//! Per-replica request limits for rules whose backend Service carries
//! `gapura.dev/rate-limit`. One fixed window per (route, client IP), aligned to the epoch so
//! every replica and every restart slices time identically. The project has no database, so
//! counts are per replica: with N replicas the effective allowance is N x limit, which is the
//! documented semantics, not a bug to fix with state.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use gapura_core::config::RateLimit;

/// What `check` decided for one request.
#[derive(Debug)]
pub enum Outcome {
    Allowed,
    Limited { limit: u32, retry_after_secs: u64 },
}

struct Window {
    bucket: u64,
    count: u32,
}

pub struct RateLimiter {
    windows: Mutex<HashMap<(String, IpAddr), Window>>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
        }
    }
}

impl RateLimiter {
    pub fn check(&self, route: &str, ip: IpAddr, rl: &RateLimit) -> Outcome {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        self.check_at(route, ip, rl, now_ms)
    }

    fn check_at(&self, route: &str, ip: IpAddr, rl: &RateLimit, now_ms: u64) -> Outcome {
        let bucket = now_ms / rl.window_ms.max(1);
        let mut windows = self.windows.lock().unwrap();
        // Unique keys are bounded by unique client IPs; stale windows of clients that went away
        // are dropped whenever the map outgrows a hard ceiling, so a scanning crowd cannot grow
        // the table forever.
        if windows.len() > 65_536 {
            windows.retain(|_, w| w.bucket == bucket);
        }
        let w = windows
            .entry((route.to_string(), ip))
            .or_insert(Window { bucket, count: 0 });
        if w.bucket != bucket {
            *w = Window { bucket, count: 0 };
        }
        if w.count >= rl.limit {
            let next_bucket_ms = (bucket + 1) * rl.window_ms.max(1);
            Outcome::Limited {
                limit: rl.limit,
                retry_after_secs: ((next_bucket_ms.saturating_sub(now_ms)) / 1000).max(1),
            }
        } else {
            w.count += 1;
            Outcome::Allowed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rl(limit: u32, window_ms: u64) -> RateLimit {
        RateLimit { limit, window_ms }
    }

    #[test]
    fn the_limit_trips_within_a_window_and_resets_in_the_next() {
        let l = RateLimiter::default();
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        for _ in 0..3 {
            assert!(matches!(
                l.check_at("r", ip, &rl(3, 60_000), 1_000),
                Outcome::Allowed
            ));
        }
        match l.check_at("r", ip, &rl(3, 60_000), 2_000) {
            Outcome::Limited {
                limit,
                retry_after_secs,
            } => {
                assert_eq!(limit, 3);
                assert_eq!(retry_after_secs, 58, "the rest of this minute's window");
            }
            o => panic!("expected Limited, got {o:?}"),
        }
        // The next window is a clean slate.
        assert!(matches!(
            l.check_at("r", ip, &rl(3, 60_000), 61_000),
            Outcome::Allowed
        ));
    }

    #[test]
    fn clients_are_counted_separately_and_so_are_routes() {
        let l = RateLimiter::default();
        let a: IpAddr = "198.51.100.1".parse().unwrap();
        let b: IpAddr = "198.51.100.2".parse().unwrap();
        for _ in 0..2 {
            assert!(matches!(
                l.check_at("r", a, &rl(2, 60_000), 1_000),
                Outcome::Allowed
            ));
        }
        assert!(matches!(
            l.check_at("r", b, &rl(2, 60_000), 1_000),
            Outcome::Allowed
        ));
        assert!(matches!(
            l.check_at("other", a, &rl(2, 60_000), 1_000),
            Outcome::Allowed
        ));
        assert!(matches!(
            l.check_at("r", a, &rl(2, 60_000), 1_000),
            Outcome::Limited { .. }
        ));
    }
}
