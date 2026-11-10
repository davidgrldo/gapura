//! The `redis` scope's count: one fixed window per (window name, client), as the local table
//! keeps, but held in Redis, so every replica connected to it -- every data plane, every
//! Gateway -- draws on one count. Windows are aligned to the epoch, as the local table's are,
//! so replicas agree on where a window starts as closely as their clocks do.
//!
//! Redis is in the request path only for a limit that asks for it, and never decides whether a
//! request is served: when it cannot answer within `--redis-timeout-ms`, answers with an error,
//! or is not connected, the request is counted as a `split` limit would count it, on this
//! replica, and the failure is counted in `gapura_rate_limit_redis_fallbacks_total{reason}`.
//! After a failure Redis is not tried again for a second, then twice as long each time it fails
//! again, up to 30 s, so an outage costs requests one timeout per backoff, not one each.
//!
//! A key per (window name, client, window): `gapura:rl:<first 16 bytes of a SHA-256, hex>:
//! <window ms>:<window number>`, which expires 5 s after its window ends. A limit that counts by
//! a header's value therefore holds one key per value per window in Redis, which the data plane's
//! own cap on header windows does not bound: Redis's `maxmemory` does.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwapOption;
use async_trait::async_trait;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use sha2::{Digest, Sha256};

use crate::proxy::rate_limit::{canonical, now_ms, Client, Outcome};

/// Increment, and set the expiry on the increment that created the key, in one script: no crash
/// between the two can leave a key that never expires.
const COUNT: &str = r"
local n = redis.call('INCR', KEYS[1])
if n == 1 then redis.call('PEXPIREAT', KEYS[1], ARGV[1]) end
return n
";

/// How long a window's key outlives the window, so that a replica whose clock runs a little
/// behind the one that created it still counts into it rather than into a fresh one.
const KEY_SLACK_MS: u64 = 5_000;

/// The first and the longest wait before Redis is tried again after a failure.
const MIN_BACKOFF_MS: u64 = 1_000;
const MAX_BACKOFF_MS: u64 = 30_000;

/// The default for `--redis-timeout-ms`.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(50);

/// Why a `redis` limit was counted as `split` instead, the `reason` label of
/// `gapura_rate_limit_redis_fallbacks_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fallback {
    /// Redis did not answer within the timeout.
    Timeout,
    /// Redis answered with an error, or the connection failed.
    Error,
    /// No connection to try: none configured, not yet made, or backing off after a failure.
    Unavailable,
}

impl Fallback {
    pub fn label(self) -> &'static str {
        match self {
            Fallback::Timeout => "timeout",
            Fallback::Error => "error",
            Fallback::Unavailable => "unavailable",
        }
    }
}

pub struct SharedLimiter {
    /// `None` without `--redis-url`, and until [`Connect`] has made the connection manager,
    /// which then reconnects by itself.
    conn: ArcSwapOption<ConnectionManager>,
    timeout: Duration,
    /// Epoch milliseconds before which Redis is not tried, after a failure.
    retry_at_ms: AtomicU64,
    /// The wait the last failure set; `0` while Redis answers.
    backoff_ms: AtomicU64,
    script: redis::Script,
    /// Whether `--redis-url` was given; without it a `redis` limit is a configuration this
    /// replica cannot follow, which it says once.
    configured: bool,
    warned: AtomicBool,
}

impl Default for SharedLimiter {
    /// No Redis: every `redis` limit counts as `split`.
    fn default() -> Self {
        Self::new(DEFAULT_TIMEOUT, false)
    }
}

impl SharedLimiter {
    /// `configured` is whether `--redis-url` was given, and [`Connect`] will make a connection.
    pub fn new(timeout: Duration, configured: bool) -> Self {
        Self {
            conn: ArcSwapOption::empty(),
            timeout,
            retry_at_ms: AtomicU64::new(0),
            backoff_ms: AtomicU64::new(0),
            script: redis::Script::new(COUNT),
            configured,
            warned: AtomicBool::new(false),
        }
    }

    /// Counts one request of `client` under the window name `window`, in windows of
    /// `window_ms`, allowing `allowance` of them in each across every replica sharing this
    /// Redis. `Err` says why it could not, and the caller counts the request locally instead.
    pub async fn check(
        &self,
        window: &str,
        client: &Client,
        window_ms: u64,
        allowance: u32,
    ) -> Result<Outcome, Fallback> {
        let now = now_ms();
        if now < self.retry_at_ms.load(Ordering::Relaxed) {
            return Err(Fallback::Unavailable);
        }
        let Some(conn) = self.conn.load_full() else {
            if !self.configured && !self.warned.swap(true, Ordering::Relaxed) {
                tracing::warn!(
                    "a request limit counts in redis, but this replica has no --redis-url; it counts as split"
                );
            }
            return Err(Fallback::Unavailable);
        };
        let mut conn = ConnectionManager::clone(&conn);
        let window_ms = window_ms.max(1);
        let bucket = now / window_ms;
        let ends_ms = (bucket + 1) * window_ms;
        let mut invocation = self.script.key(key(window, client, window_ms, bucket));
        invocation.arg(ends_ms + KEY_SLACK_MS);
        let count: u64 =
            match tokio::time::timeout(self.timeout, invocation.invoke_async(&mut conn)).await {
                Ok(Ok(count)) => count,
                Ok(Err(e)) => {
                    let why = if e.is_timeout() {
                        Fallback::Timeout
                    } else {
                        Fallback::Error
                    };
                    return Err(self.failed(now, why, Some(&e)));
                }
                Err(_) => return Err(self.failed(now, Fallback::Timeout, None)),
            };
        if self.backoff_ms.swap(0, Ordering::Relaxed) != 0 {
            tracing::info!("redis answers again; redis request limits count there");
        }
        Ok(if count > u64::from(allowance) {
            Outcome::Limited {
                retry_after_secs: (ends_ms.saturating_sub(now) / 1000).max(1),
            }
        } else {
            Outcome::Allowed
        })
    }

    /// Backs off after a failure at `now`: a second the first time, twice the last wait each
    /// time after, up to `MAX_BACKOFF_MS`. Warns on the first failure after Redis last
    /// answered, not on every one, which an outage would otherwise repeat per request.
    fn failed(&self, now: u64, why: Fallback, error: Option<&redis::RedisError>) -> Fallback {
        let last = self.backoff_ms.load(Ordering::Relaxed);
        let wait = (last * 2).clamp(MIN_BACKOFF_MS, MAX_BACKOFF_MS);
        self.backoff_ms.store(wait, Ordering::Relaxed);
        self.retry_at_ms.store(now + wait, Ordering::Relaxed);
        if last == 0 {
            tracing::warn!(
                reason = why.label(),
                error = error.map(tracing::field::display),
                "redis did not answer a request limit; redis limits count as split until it does"
            );
        }
        why
    }
}

/// The key a window is counted under. Hashed, because a window name carries a route and maybe a
/// consumer, and a client an address or a consumer: Redis is often shared, and its keys are
/// listed by whoever operates it. The kind of client is hashed in, so a consumer named like an
/// address never shares that address's count, as in the local table.
fn key(window: &str, client: &Client, window_ms: u64, bucket: u64) -> String {
    let mut hash = Sha256::new();
    hash.update(window.as_bytes());
    hash.update([0]);
    match canonical(client.clone()) {
        Client::Ip(addr) => {
            hash.update(b"ip:");
            hash.update(addr.to_string().as_bytes());
        }
        Client::Consumer(name) => {
            hash.update(b"consumer:");
            hash.update(name.as_bytes());
        }
        Client::Header(digest) => {
            hash.update(b"header:");
            hash.update(digest);
        }
    }
    let digest = hash.finalize();
    let hex: String = digest[..16].iter().map(|b| format!("{b:02x}")).collect();
    format!("gapura:rl:{hex}:{window_ms}:{bucket}")
}

/// Makes the connection at startup, on a runtime of its own: the connection manager's tasks run
/// where it was first used, and a request's worker is not where they belong. Says once whether
/// Redis answers, so a wrong URL is in the log before the first limited request.
pub struct Connect {
    pub limiter: Arc<SharedLimiter>,
    pub client: redis::Client,
}

#[async_trait]
impl BackgroundService for Connect {
    async fn start(&self, _shutdown: ShutdownWatch) {
        let config = ConnectionManagerConfig::new()
            .set_connection_timeout(Some(self.limiter.timeout.max(Duration::from_millis(500))))
            .set_response_timeout(Some(self.limiter.timeout))
            .set_max_delay(Duration::from_millis(MAX_BACKOFF_MS));
        let manager = match ConnectionManager::new_lazy_with_config(self.client.clone(), config) {
            Ok(manager) => manager,
            Err(e) => {
                tracing::error!(error = %e, "cannot set up the redis connection; redis request limits count as split");
                return;
            }
        };
        let mut probe = manager.clone();
        match redis::cmd("PING").query_async::<String>(&mut probe).await {
            Ok(_) => tracing::info!("redis answers; redis request limits count there"),
            Err(e) => tracing::warn!(
                error = %e,
                "redis does not answer yet; redis request limits count as split until it does"
            ),
        }
        self.limiter.conn.store(Some(Arc::new(manager)));
    }
}

/// The client `--redis-url` names, with the password `--redis-password-file` holds and the CA
/// `--redis-ca` trusts for `rediss://`, on top of the system's roots.
pub fn client(
    url: &str,
    password: Option<&str>,
    ca_pem: Option<Vec<u8>>,
) -> redis::RedisResult<redis::Client> {
    use redis::IntoConnectionInfo;
    let mut info = url.into_connection_info()?;
    if let Some(password) = password {
        let settings = info.redis_settings().clone().set_password(password);
        info = info.set_redis_settings(settings);
    }
    match ca_pem {
        Some(root_cert) => redis::Client::build_with_tls(
            info,
            redis::TlsCertificates {
                client_tls: None,
                root_cert: Some(root_cert),
            },
        ),
        None => redis::Client::open(info),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn a_key_names_the_window_the_client_and_the_window_number() {
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        let k = key("default/orders#0", &Client::Ip(ip), 60_000, 7);
        assert!(k.starts_with("gapura:rl:"), "{k}");
        assert!(k.ends_with(":60000:7"), "{k}");
        assert_eq!(k.len(), "gapura:rl:".len() + 32 + ":60000:7".len());
        assert!(
            !k.contains("orders") && !k.contains("198.51"),
            "hashed: {k}"
        );
        assert_eq!(k, key("default/orders#0", &Client::Ip(ip), 60_000, 7));
        assert_ne!(k, key("default/orders#1", &Client::Ip(ip), 60_000, 7));
        assert_ne!(k, key("default/orders#0", &Client::Ip(ip), 60_000, 8));
        assert_ne!(
            k,
            key(
                "default/orders#0",
                &Client::Consumer("198.51.100.1".into()),
                60_000,
                7
            ),
            "a consumer named like an address is not that address"
        );
    }

    /// Two addresses of one IPv6 /64 are one client, as they are in the local table.
    #[test]
    fn a_key_groups_an_ipv6_address_by_its_64() {
        let a: IpAddr = "2001:db8::1".parse().unwrap();
        let b: IpAddr = "2001:db8::2".parse().unwrap();
        assert_eq!(
            key("r", &Client::Ip(a), 1_000, 1),
            key("r", &Client::Ip(b), 1_000, 1)
        );
    }

    #[tokio::test]
    async fn without_a_connection_a_limit_falls_back() {
        let limiter = SharedLimiter::default();
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        assert_eq!(
            limiter.check("r", &Client::Ip(ip), 1_000, 1).await.err(),
            Some(Fallback::Unavailable)
        );
    }

    #[test]
    fn failures_back_off_doubling_to_a_ceiling_and_an_answer_resets_it() {
        let limiter = SharedLimiter::default();
        limiter.failed(10_000, Fallback::Error, None);
        assert_eq!(limiter.retry_at_ms.load(Ordering::Relaxed), 11_000);
        limiter.failed(11_000, Fallback::Timeout, None);
        assert_eq!(limiter.retry_at_ms.load(Ordering::Relaxed), 13_000);
        for _ in 0..10 {
            limiter.failed(13_000, Fallback::Timeout, None);
        }
        assert_eq!(limiter.backoff_ms.load(Ordering::Relaxed), MAX_BACKOFF_MS);
    }

    /// Against a real Redis when `GAPURA_TEST_REDIS_URL` names one (CI runs one, and refuses to
    /// skip it); skipped otherwise, like the store tests without a database:
    /// `docker run -d --rm -p 6379:6379 redis:7-alpine` and
    /// `GAPURA_TEST_REDIS_URL=redis://localhost:6379`. Two limiters on one Redis are two
    /// replicas: they share one count.
    #[tokio::test]
    async fn two_replicas_on_one_redis_share_one_count() {
        let Ok(url) = std::env::var("GAPURA_TEST_REDIS_URL") else {
            // Optional locally, mandatory in CI, as the store tests' database is.
            assert!(
                std::env::var_os("CI").is_none(),
                "GAPURA_TEST_REDIS_URL must be set in CI"
            );
            eprintln!("GAPURA_TEST_REDIS_URL is unset: skipping");
            return;
        };
        let replicas: Vec<Arc<SharedLimiter>> = (0..2)
            .map(|_| Arc::new(SharedLimiter::new(Duration::from_secs(2), true)))
            .collect();
        for limiter in &replicas {
            Connect {
                limiter: limiter.clone(),
                client: client(&url, None, None).unwrap(),
            }
            .start(tokio::sync::watch::channel(false).1)
            .await;
        }
        // A window name of its own, so a rerun within the hour does not find this run's count.
        let window = format!("test/{}", now_ms());
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        let client = Client::Ip(ip);
        let mut allowed = 0;
        for n in 0..6 {
            match replicas[n % 2]
                .check(&window, &client, 3_600_000, 4)
                .await
                .expect("redis answers")
            {
                Outcome::Allowed => allowed += 1,
                Outcome::Limited { .. } => {}
            }
        }
        assert_eq!(allowed, 4, "four between them, not four each");
    }
}
