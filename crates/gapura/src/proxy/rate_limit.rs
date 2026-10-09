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

/// A table this small is never swept: below it, stale windows cost less than looking for them.
const SWEEP_FLOOR: usize = 65_536;

struct Window {
    /// When this window ends, in epoch milliseconds: `(bucket + 1) * window_ms` for the rule
    /// that created it. Kept per window rather than recomputed from the rule at hand, because
    /// routes have different window lengths and so bucket numbers on different scales: only a
    /// window's own end says whether it is still live.
    ends_ms: u64,
    count: u32,
}

struct Table {
    windows: HashMap<(String, IpAddr), Window>,
    /// The size at which the next sweep runs. Reset after each sweep to twice what survived,
    /// so a sweep that frees little is not repeated on the very next request.
    sweep_at: usize,
}

pub struct RateLimiter {
    table: Mutex<Table>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self {
            table: Mutex::new(Table {
                windows: HashMap::new(),
                sweep_at: SWEEP_FLOOR,
            }),
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
        let window_ms = rl.window_ms.max(1);
        let ends_ms = (now_ms / window_ms + 1) * window_ms;
        let mut table = self.table.lock().unwrap();
        // Unique keys are bounded by unique (route, client IP) pairs seen within a window.
        // Only windows that have ended are dropped: a live one holds a count that a reset would
        // hand back to its client, which is the bypass. The sweep is a full scan under the one
        // lock every worker shares, so it runs only once the table has doubled since the last
        // one (and never below the floor): each sweep is paid for by as many inserts as it
        // scans, and the table never holds more than twice its live windows.
        if table.windows.len() > table.sweep_at {
            table.windows.retain(|_, w| w.ends_ms > now_ms);
            table.sweep_at = (table.windows.len() * 2).max(SWEEP_FLOOR);
        }
        let w = table
            .windows
            .entry((route.to_string(), ip))
            .or_insert(Window { ends_ms, count: 0 });
        // A window that ended, or one created under a different window length (the rule
        // changed on a reload), starts over in the current window.
        if w.ends_ms != ends_ms {
            *w = Window { ends_ms, count: 0 };
        }
        if w.count >= rl.limit {
            Outcome::Limited {
                limit: rl.limit,
                retry_after_secs: ((ends_ms.saturating_sub(now_ms)) / 1000).max(1),
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

    /// The distinct address `n` of a flood, as from one IPv6 /64.
    fn flood_ip(n: u32) -> IpAddr {
        IpAddr::V6(std::net::Ipv6Addr::new(
            0x2001,
            0xdb8,
            0,
            0,
            0,
            0,
            (n >> 16) as u16,
            n as u16,
        ))
    }

    #[test]
    fn a_flood_on_one_route_does_not_reset_another_routes_live_window() {
        // #159: eviction compared every window against the bucket number of the rule at hand,
        // and buckets of different window lengths are on different scales, so a flood on a
        // per-second route wiped an exhausted per-hour counter.
        let l = RateLimiter::default();
        let victim: IpAddr = "198.51.100.1".parse().unwrap();
        let login = rl(5, 3_600_000);
        let now = 1_000;
        for _ in 0..5 {
            assert!(matches!(
                l.check_at("login", victim, &login, now),
                Outcome::Allowed
            ));
        }
        assert!(matches!(
            l.check_at("login", victim, &login, now),
            Outcome::Limited { .. }
        ));
        let other = rl(1_000, 1_000);
        for n in 0..=(SWEEP_FLOOR as u32 + 1) {
            l.check_at("other", flood_ip(n), &other, now);
        }
        assert!(
            l.table.lock().unwrap().sweep_at > SWEEP_FLOOR,
            "the flood must have triggered a sweep"
        );
        match l.check_at("login", victim, &login, now) {
            Outcome::Limited {
                limit,
                retry_after_secs,
            } => {
                assert_eq!(limit, 5);
                assert_eq!(retry_after_secs, 3_599);
            }
            o => panic!("the login window must survive the sweep, got {o:?}"),
        }
    }

    #[test]
    fn ended_windows_are_evicted_and_live_ones_kept() {
        let l = RateLimiter::default();
        let short = rl(10, 1_000);
        let long = rl(10, 3_600_000);
        let survivor: IpAddr = "198.51.100.1".parse().unwrap();
        l.check_at("long", survivor, &long, 500);
        for n in 0..SWEEP_FLOOR as u32 {
            l.check_at("short", flood_ip(n), &short, 500);
        }
        // Past the floor, in the next second: every `short` window has ended.
        l.check_at("short", flood_ip(u32::MAX), &short, 1_500);
        let table = l.table.lock().unwrap();
        assert_eq!(
            table.windows.len(),
            2,
            "only the hour window and the new one remain"
        );
        assert!(table.windows.contains_key(&("long".to_string(), survivor)));
        assert_eq!(table.sweep_at, SWEEP_FLOOR);
    }

    #[test]
    fn a_table_of_live_windows_is_not_rescanned_on_every_request() {
        // While every window is live a sweep frees nothing; the next one waits until the table
        // has doubled, rather than scanning the whole map under the lock on every request.
        let l = RateLimiter::default();
        let hour = rl(10, 3_600_000);
        for n in 0..=(SWEEP_FLOOR as u32 + 1) {
            l.check_at("r", flood_ip(n), &hour, 0);
        }
        let after_first = l.table.lock().unwrap().sweep_at;
        assert_eq!(after_first, 2 * (SWEEP_FLOOR + 1));
        for n in 0..1_000 {
            l.check_at("r", flood_ip(SWEEP_FLOOR as u32 + 2 + n), &hour, 0);
        }
        assert_eq!(
            l.table.lock().unwrap().sweep_at,
            after_first,
            "no sweep until the table doubles"
        );
    }
}
