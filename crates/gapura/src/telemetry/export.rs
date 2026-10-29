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
use std::sync::{Mutex, MutexGuard, PoisonError};

use prometheus::IntCounter;
use tokio::sync::Notify;

use super::METRICS;

/// Entries a sink holds before it drops the oldest.
pub const CAPACITY: usize = 10_000;

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
