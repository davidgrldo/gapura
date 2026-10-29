//! Delivery to export sinks: one bounded queue per sink, filled by the request path and drained
//! in batches by one worker per sink.
//!
//! Kong's shape (`kong/tools/queue.lua`): an entry waits up to [`COALESCE`] for others to share
//! its batch of at most [`MAX_BATCH`]; a batch that fails is sent again after a delay that doubles
//! from [`FIRST_RETRY`] up to [`MAX_RETRY_DELAY`], until [`MAX_RETRY_TIME`] has passed; a full
//! queue drops its oldest entry for the new one and warns once it is 80% full. Unlike
//! gravitee-node's reporter fan-out, every record lost is counted, in
//! `gapura_log_dropped_total{sink, reason}`.

use std::collections::VecDeque;
use std::future::Future;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use pingora::server::ShutdownWatch;
use prometheus::IntCounter;
use tokio::sync::Notify;
use tokio::time::Instant;

use super::METRICS;

/// Entries a sink holds before it drops the oldest.
pub const CAPACITY: usize = 10_000;
/// Entries in one batch at most.
const MAX_BATCH: usize = 500;
/// How long the first entry of a batch waits for others to join it.
const COALESCE: Duration = Duration::from_secs(1);
/// The delay before the first resend of a failed batch; it doubles with each resend.
const FIRST_RETRY: Duration = Duration::from_millis(10);
/// The longest delay between two sends of one batch.
const MAX_RETRY_DELAY: Duration = Duration::from_secs(60);
/// How long a batch is retried before it is dropped.
const MAX_RETRY_TIME: Duration = Duration::from_secs(60);
/// How long a batch is retried once the process is shutting down: the grace period is all the
/// time left for every queued record, and one dead collector must not spend it.
const STOPPING_RETRY_TIME: Duration = Duration::from_secs(5);

/// One sink's queue.
pub struct Queue<T> {
    /// The `sink` label of its metrics and log lines.
    sink: &'static str,
    capacity: usize,
    inner: Mutex<Inner<T>>,
    /// Woken by every push, so the worker can wait for an entry without polling.
    ready: Notify,
    queue_full: IntCounter,
    send_failed: IntCounter,
}

struct Inner<T> {
    items: VecDeque<T>,
    /// Set once the queue has warned that it is 80% full; cleared when it next empties.
    warned: bool,
}

impl<T> Queue<T> {
    pub fn new(sink: &'static str, capacity: usize) -> Self {
        let dropped = |reason: &str| METRICS.log_dropped_total.with_label_values(&[sink, reason]);
        Queue {
            sink,
            capacity,
            inner: Mutex::new(Inner {
                items: VecDeque::new(),
                warned: false,
            }),
            ready: Notify::new(),
            queue_full: dropped("queue_full"),
            send_failed: dropped("send_failed"),
        }
    }

    /// Queue `item`, dropping the oldest entry when the queue is full. Never waits: this is the
    /// request path's side of a sink, and a sink that cannot keep up costs records, not latency.
    pub fn push(&self, item: T) {
        let mut inner = self.lock();
        if inner.items.len() >= self.capacity {
            inner.items.pop_front();
            self.queue_full.inc();
        }
        inner.items.push_back(item);
        if !inner.warned && inner.items.len() * 5 >= self.capacity * 4 {
            inner.warned = true;
            tracing::warn!(
                sink = self.sink,
                capacity = self.capacity,
                "export queue 80% full: the sink is not keeping up, and records will be dropped once it is full"
            );
        }
        drop(inner);
        self.ready.notify_one();
    }

    fn len(&self) -> usize {
        self.lock().items.len()
    }

    /// Up to `max` entries off the front. Taking the last one re-arms the 80% warning.
    fn take(&self, max: usize) -> Vec<T> {
        let mut inner = self.lock();
        let n = inner.items.len().min(max);
        let batch = inner.items.drain(..n).collect();
        if inner.items.is_empty() {
            inner.warned = false;
        }
        batch
    }

    /// Each change under the lock is a single `VecDeque` call, so a panic while it was held
    /// cannot leave the queue half-changed: a poisoned lock is used as it is.
    fn lock(&self) -> MutexGuard<'_, Inner<T>> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Drain `queue` for as long as the process runs: batch, `encode`, `post`, retry. It returns only
/// by being dropped, when Pingora tears its runtime down at the end of the grace period, by which
/// time every request that could still push a record has finished.
///
/// Once `shutdown` fires, a batch no longer waits to fill and a failing one is retried for
/// [`STOPPING_RETRY_TIME`] rather than [`MAX_RETRY_TIME`]: what is queued goes out as soon as it
/// can, and the records of the requests that finish during the grace period still go out after it.
pub async fn run<T, Fut>(
    queue: &Queue<T>,
    mut shutdown: ShutdownWatch,
    encode: impl Fn(&[T]) -> Bytes,
    post: impl Fn(Bytes) -> Fut,
) where
    Fut: Future<Output = Result<(), String>>,
{
    loop {
        let stopping = is_stopping(&shutdown);
        if queue.len() == 0 {
            tokio::select! {
                _ = queue.ready.notified() => {}
                _ = stopped(&mut shutdown), if !stopping => {}
            }
            continue;
        }
        if !stopping {
            // Let the batch fill for up to COALESCE, unless it fills first or shutdown begins.
            let deadline = Instant::now() + COALESCE;
            while queue.len() < MAX_BATCH {
                tokio::select! {
                    _ = tokio::time::sleep_until(deadline) => break,
                    _ = queue.ready.notified() => {}
                    _ = stopped(&mut shutdown) => break,
                }
            }
        }
        let batch = queue.take(MAX_BATCH);
        deliver(queue, batch.len(), encode(&batch), &post, &mut shutdown).await;
    }
}

/// Send one batch of `n` records until `post` takes it, or count them dropped once retrying it
/// has taken [`MAX_RETRY_TIME`] ([`STOPPING_RETRY_TIME`] while shutting down).
async fn deliver<T, Fut>(
    queue: &Queue<T>,
    n: usize,
    body: Bytes,
    post: &impl Fn(Bytes) -> Fut,
    shutdown: &mut ShutdownWatch,
) where
    Fut: Future<Output = Result<(), String>>,
{
    let started = Instant::now();
    let mut delay = FIRST_RETRY;
    loop {
        let error = match post(body.clone()).await {
            Ok(()) => return,
            Err(error) => error,
        };
        let stopping = is_stopping(shutdown);
        let budget = if stopping {
            STOPPING_RETRY_TIME
        } else {
            MAX_RETRY_TIME
        };
        if started.elapsed() + delay > budget {
            queue.send_failed.inc_by(n as u64);
            tracing::warn!(sink = queue.sink, records = n, %error, "export batch dropped after retrying");
            return;
        }
        tracing::debug!(sink = queue.sink, %error, ?delay, "export batch not delivered, retrying");
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            // Shutdown cuts a long wait short; the next failure is then held to the shorter budget.
            _ = stopped(shutdown), if !stopping => {}
        }
        delay = next_delay(delay);
    }
}

/// The delay after `delay`: twice as long, up to [`MAX_RETRY_DELAY`].
fn next_delay(delay: Duration) -> Duration {
    (delay * 2).min(MAX_RETRY_DELAY)
}

/// Whether shutdown has begun. A watch whose sender is gone counts: nothing will ever say
/// otherwise, and waiting on it would return at once, forever.
fn is_stopping(shutdown: &ShutdownWatch) -> bool {
    *shutdown.borrow() || shutdown.has_changed().is_err()
}

/// Resolves once shutdown has begun, at once if it already has.
async fn stopped(shutdown: &mut ShutdownWatch) {
    let _ = shutdown.wait_for(|stop| *stop).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    use std::sync::Arc;

    #[test]
    fn a_full_queue_drops_its_oldest_and_counts_it() {
        let q = Queue::new("test_drop_oldest", 3);
        for n in 1..=5 {
            q.push(n);
        }
        assert_eq!(q.take(10), vec![3, 4, 5]);
        assert_eq!(q.queue_full.get(), 2);
        assert_eq!(q.send_failed.get(), 0);
    }

    #[test]
    fn the_80_percent_warning_fires_once_until_the_queue_empties() {
        let q = Queue::new("test_warning", 5);
        for n in 0..3 {
            q.push(n);
        }
        assert!(!q.lock().warned, "3 of 5 is under 80%");
        q.push(3);
        assert!(q.lock().warned, "4 of 5 is 80%");
        q.take(1);
        assert!(q.lock().warned, "not re-armed while entries remain");
        q.take(10);
        assert!(!q.lock().warned, "re-armed once empty");
    }
    /// What a fake sink was sent: when, and the batch, decoded.
    type Sent = Arc<Mutex<Vec<(Instant, Vec<u32>)>>>;

    fn encode(batch: &[u32]) -> Bytes {
        Bytes::from(serde_json::to_vec(batch).unwrap())
    }

    /// A sink that records every send and fails the first `fail_first`.
    fn sink(
        fail_first: usize,
    ) -> (
        Sent,
        impl Fn(Bytes) -> std::future::Ready<Result<(), String>>,
    ) {
        let sent: Sent = Arc::default();
        let sends = AtomicUsize::new(0);
        let record = Arc::clone(&sent);
        let post = move |body: Bytes| {
            let batch = serde_json::from_slice(&body).unwrap();
            record.lock().unwrap().push((Instant::now(), batch));
            let fail = sends.fetch_add(1, SeqCst) < fail_first;
            std::future::ready(if fail {
                Err("collector down".to_string())
            } else {
                Ok(())
            })
        };
        (sent, post)
    }

    /// A worker on `queue`; sending `true` on the returned sender starts shutdown.
    fn worker(
        queue: &Arc<Queue<u32>>,
        post: impl Fn(Bytes) -> std::future::Ready<Result<(), String>> + Send + Sync + 'static,
    ) -> tokio::sync::watch::Sender<bool> {
        let (tx, rx) = tokio::sync::watch::channel(false);
        let queue = Arc::clone(queue);
        tokio::spawn(async move { run(&queue, rx, encode, post).await });
        tx
    }

    #[tokio::test(start_paused = true)]
    async fn a_batch_waits_for_the_deadline_unless_it_fills() {
        let q = Arc::new(Queue::new("test_coalesce", CAPACITY));
        let (sent, post) = sink(0);
        let _tx = worker(&q, post);
        for n in 0..3 {
            q.push(n);
        }
        tokio::time::sleep(COALESCE - Duration::from_millis(1)).await;
        assert!(
            sent.lock().unwrap().is_empty(),
            "nothing before the deadline"
        );
        tokio::time::sleep(Duration::from_millis(2)).await;
        let batches: Vec<Vec<u32>> = sent
            .lock()
            .unwrap()
            .iter()
            .map(|(_, b)| b.clone())
            .collect();
        assert_eq!(batches, vec![vec![0, 1, 2]]);

        for n in 0..=(MAX_BATCH as u32) {
            q.push(n);
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
        let sent = sent.lock().unwrap();
        assert_eq!(sent.len(), 2);
        assert_eq!(
            sent[1].1.len(),
            MAX_BATCH,
            "a full batch, the extra entry left behind"
        );
        assert!(
            sent[1].0 - sent[0].0 <= Duration::from_millis(1),
            "a full batch goes at once, not after another {COALESCE:?}"
        );
    }

    #[test]
    fn the_retry_delay_doubles_up_to_its_cap() {
        let mut delays = vec![FIRST_RETRY];
        for _ in 0..15 {
            delays.push(next_delay(*delays.last().unwrap()));
        }
        assert_eq!(delays[..4], [10, 20, 40, 80].map(Duration::from_millis));
        assert_eq!(*delays.last().unwrap(), MAX_RETRY_DELAY);
        assert!(delays.iter().all(|d| *d <= MAX_RETRY_DELAY));
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_batch_is_resent_after_each_delay() {
        let q = Arc::new(Queue::new("test_retry", CAPACITY));
        let (sent, post) = sink(3);
        let _tx = worker(&q, post);
        q.push(7);
        tokio::time::sleep(COALESCE + Duration::from_secs(1)).await;
        let sent = sent.lock().unwrap();
        let gaps: Vec<Duration> = sent.windows(2).map(|w| w[1].0 - w[0].0).collect();
        assert_eq!(gaps, [10, 20, 40].map(Duration::from_millis));
        assert!(
            sent.iter().all(|(_, b)| *b == [7]),
            "the same batch each time"
        );
        assert_eq!(q.send_failed.get(), 0, "delivered on the fourth send");
    }

    #[tokio::test(start_paused = true)]
    async fn a_batch_failing_past_the_retry_time_is_dropped_and_counted() {
        let q = Arc::new(Queue::new("test_give_up", CAPACITY));
        let (sent, post) = sink(usize::MAX);
        let _tx = worker(&q, post);
        q.push(1);
        q.push(2);
        tokio::time::sleep(COALESCE + MAX_RETRY_TIME + Duration::from_secs(1)).await;
        assert_eq!(q.send_failed.get(), 2);
        let tries = sent.lock().unwrap().len();
        q.push(3);
        tokio::time::sleep(COALESCE + Duration::from_millis(1)).await;
        assert_eq!(
            sent.lock().unwrap().len(),
            tries + 1,
            "a dropped batch does not stop the worker"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn once_shutting_down_a_batch_goes_at_once_and_is_retried_briefly() {
        let q = Arc::new(Queue::new("test_shutdown", CAPACITY));
        let (sent, post) = sink(usize::MAX);
        let tx = worker(&q, post);
        tx.send(true).unwrap();
        q.push(1);
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert_eq!(
            sent.lock().unwrap().len(),
            1,
            "sent without waiting to fill"
        );
        tokio::time::sleep(STOPPING_RETRY_TIME).await;
        assert_eq!(
            q.send_failed.get(),
            1,
            "dropped after the shorter retry time"
        );
    }
}
