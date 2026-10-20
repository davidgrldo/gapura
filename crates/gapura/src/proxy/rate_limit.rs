//! Per-replica request limits. One fixed window per (rule, client), aligned to the epoch so
//! every replica and every restart slices time identically; the client is what the limit counts
//! by -- an address, a consumer or a header's value, see [`Client`]. The project has no database,
//! so counts are per replica: with N replicas the effective allowance is N x limit, which is the
//! documented semantics, not a bug to fix with state.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use gapura_core::config::{LimitBy, RateLimit};
use sha2::{Digest, Sha256};

/// What `check` decided for one request.
#[derive(Debug)]
pub enum Outcome {
    Allowed,
    Limited { limit: u32, retry_after_secs: u64 },
}

/// Who one window counts: what the rule's [`LimitBy`] names, for one request. An enum rather
/// than a string, so a consumer called `198.51.100.1` and a header carrying it never share a
/// window with that address. A header's value is held as the first 16 bytes of its SHA-256:
/// the value is the client's to choose, and a window must not cost whatever it chose to send.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Client {
    Ip(IpAddr),
    Consumer(String),
    Header([u8; 16]),
}

impl Client {
    /// The client a header's `value` names. Raw bytes rather than text, so a value that is not
    /// ASCII -- a tenant id a proxy set in UTF-8 -- is a client of its own and is not mistaken
    /// for a request that carried no header.
    pub fn header(value: &[u8]) -> Client {
        let digest = Sha256::digest(value);
        let mut short = [0; 16];
        short.copy_from_slice(&digest[..16]);
        Client::Header(short)
    }
}

impl From<IpAddr> for Client {
    fn from(ip: IpAddr) -> Self {
        Client::Ip(ip)
    }
}

/// The client a request counts as under `by`: its consumer or its value of the header when it
/// has one, else its address. `None` when the address is what is needed and it is unknown,
/// which is no limit, as it was before a limit could count anything else.
///
/// A header counts only when the request carries exactly one non-empty line of it. A front
/// proxy that appends its own line rather than replacing the client's leaves the client's line
/// first, so counting the first of several would let the client choose its own window; the
/// request counts by address instead, the rule one `Authorization` (#190, #212) and one `Host`
/// line already follow, and an empty value names no one, so it does the same.
pub fn client(
    by: &LimitBy,
    ip: Option<IpAddr>,
    consumer: Option<&str>,
    headers: &http::HeaderMap,
) -> Option<Client> {
    let named = match by {
        LimitBy::Ip => None,
        LimitBy::Consumer => consumer.map(|c| Client::Consumer(c.to_string())),
        LimitBy::Header(name) => {
            let mut lines = headers.get_all(name.as_str()).iter();
            match (lines.next(), lines.next()) {
                (Some(line), None) if !line.as_bytes().is_empty() => {
                    Some(Client::header(line.as_bytes()))
                }
                _ => None,
            }
        }
    };
    named.or_else(|| ip.map(Client::Ip))
}

/// A table this small is never swept: below it, stale windows cost less than looking for them.
const SWEEP_FLOOR: usize = 65_536;

/// The most header windows one window name holds at once, on one replica. A client choosing the
/// header's value can open a window per request, which the sweep frees only once it has ended,
/// so without a cap one limit could grow the table at its request rate; past this a new value
/// counts by the request's address instead, as a request without the header does. Windows
/// still held are what count, ended ones not yet swept included, which is why a request that
/// meets the cap sweeps (see `CAPPED_SWEEP_MS`). The cap is per name -- the `route` a window is
/// counted under -- so a limit whose clients choose the value fills only its own allowance,
/// never another limit's. Memory is therefore bounded by the number of window names that count
/// by a header, times this: a rule's name comes from configuration, and a consumer's own limit
/// counts under a name of its own, which a request reaches only by presenting that consumer's
/// valid key, so a client needs a key for every name it would add to the bound. The documented
/// figure on [`LimitBy::Header`] is this one.
const HEADER_WINDOWS: usize = 65_536;

/// How often a request that meets `HEADER_WINDOWS` may sweep, in milliseconds. Without it,
/// header windows that ended would wait for the table to double, which falling back to the
/// address may never let it do; with it, the full scan under the lock runs at most once a second.
const CAPPED_SWEEP_MS: u64 = 1_000;

struct Window {
    /// When this window ends, in epoch milliseconds: `(bucket + 1) * window_ms` for the rule
    /// that created it. Kept per window rather than recomputed from the rule at hand, because
    /// routes have different window lengths and so bucket numbers on different scales: only a
    /// window's own end says whether it is still live.
    ends_ms: u64,
    count: u32,
}

struct Table {
    windows: HashMap<(String, Client), Window>,
    /// The size at which the next sweep runs. Reset after each sweep to twice what survived,
    /// so a sweep that frees little is not repeated on the very next request.
    sweep_at: usize,
    /// How many of `windows` count a header's value, per window name, which `HEADER_WINDOWS`
    /// caps for each name separately. A name with none is absent.
    header_windows: HashMap<String, usize>,
    /// When the last sweep ran, in epoch milliseconds.
    swept_ms: u64,
}

impl Table {
    /// How many header windows `route` holds, ended ones not yet swept included.
    fn held(&self, route: &str) -> usize {
        self.header_windows.get(route).copied().unwrap_or(0)
    }

    /// Drops every window that has ended -- a live one holds a count that a reset would hand
    /// back to its client, which is the bypass -- and counts the header windows that are left.
    fn sweep(&mut self, now_ms: u64) {
        self.windows.retain(|_, w| w.ends_ms > now_ms);
        self.header_windows.clear();
        for (route, client) in self.windows.keys() {
            if matches!(client, Client::Header(_)) {
                add_header_window(&mut self.header_windows, route);
            }
        }
        self.sweep_at = (self.windows.len() * 2).max(SWEEP_FLOOR);
        self.swept_ms = now_ms;
    }
}

/// Counts one more header window under `route`. The name is copied only the first time it is
/// seen, so a flood of new values does not allocate a name per window.
fn add_header_window(counts: &mut HashMap<String, usize>, route: &str) {
    match counts.get_mut(route) {
        Some(n) => *n += 1,
        None => {
            counts.insert(route.to_string(), 1);
        }
    }
}

/// The address a limit counts a client by. An IPv6 /64 is the granularity an address limit
/// works at: without this, a client rotating source addresses inside one /64 gets a fresh
/// window per address (#189), which makes the limit effectively off for IPv6 and fills the map
/// with windows the sweep cannot reclaim until they expire.
fn grouped(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            octets[8..].fill(0);
            IpAddr::from(octets)
        }
        v4 => v4,
    }
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
                header_windows: HashMap::new(),
                swept_ms: 0,
            }),
        }
    }
}

impl RateLimiter {
    /// Counts one request of `client` against `rl` under the window name `route`. `ip` is the
    /// request's own address, which only the header cap needs: past `HEADER_WINDOWS` a new
    /// header value counts by it instead of opening one more window.
    pub fn check(
        &self,
        route: &str,
        client: impl Into<Client>,
        ip: Option<IpAddr>,
        rl: &RateLimit,
    ) -> Outcome {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        self.check_at(route, client, ip, rl, now_ms)
    }

    fn check_at(
        &self,
        route: &str,
        client: impl Into<Client>,
        ip: Option<IpAddr>,
        rl: &RateLimit,
        now_ms: u64,
    ) -> Outcome {
        let window_ms = rl.window_ms.max(1);
        let ends_ms = (now_ms / window_ms + 1) * window_ms;
        // The key is built once, before the lock every worker shares is taken.
        let client = match client.into() {
            Client::Ip(addr) => Client::Ip(grouped(addr)),
            named => named,
        };
        let mut key = (route.to_string(), client);
        // Set when this call swept because `route`'s header windows were full and found them
        // still full. Logged after the lock is released: a subscriber that blocks on its
        // output must not hold up every worker's limit check.
        let mut cap_still_full = false;
        let outcome = 'counted: {
            let mut table = self.table.lock().unwrap();
            // Unique keys are bounded by the unique (rule, client) pairs seen within a window,
            // and header clients further by `HEADER_WINDOWS` for each window name. The sweep is
            // a full scan under the one lock every worker shares, so it runs only once the table
            // has doubled since the last one (and never below the floor): each sweep is paid
            // for by as many inserts as it scans, and the table never holds more than twice its
            // live windows. The one other sweep is a full header cap's, below, at most once a
            // second.
            if table.windows.len() > table.sweep_at {
                table.sweep(now_ms);
            }
            if matches!(key.1, Client::Header(_)) && !table.windows.contains_key(&key) {
                // A clock that stepped back is taken as a second gone by, or the sweep would
                // wait for it to catch up with the one that ran before the step.
                let due = now_ms < table.swept_ms
                    || now_ms >= table.swept_ms.saturating_add(CAPPED_SWEEP_MS);
                if table.held(route) >= HEADER_WINDOWS && due {
                    table.sweep(now_ms);
                    cap_still_full = table.held(route) >= HEADER_WINDOWS;
                }
                if table.held(route) >= HEADER_WINDOWS {
                    // Counted by address, as a request without the header is; with no address
                    // there is nothing to count by, and an unaddressed request never was.
                    match ip {
                        Some(addr) => key.1 = Client::Ip(grouped(addr)),
                        None => break 'counted Outcome::Allowed,
                    }
                } else {
                    add_header_window(&mut table.header_windows, route);
                }
            }
            let w = table
                .windows
                .entry(key)
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
        };
        if cap_still_full {
            tracing::warn!(
                route,
                "this limit's header windows are full: a new header value now counts by address, or not at all without an address"
            );
        }
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rl(limit: u32, window_ms: u64) -> RateLimit {
        RateLimit {
            limit,
            window_ms,
            by: gapura_core::config::LimitBy::Ip,
        }
    }

    #[test]
    fn the_limit_trips_within_a_window_and_resets_in_the_next() {
        let l = RateLimiter::default();
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        for _ in 0..3 {
            assert!(matches!(
                l.check_at("r", ip, None, &rl(3, 60_000), 1_000),
                Outcome::Allowed
            ));
        }
        match l.check_at("r", ip, None, &rl(3, 60_000), 2_000) {
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
            l.check_at("r", ip, None, &rl(3, 60_000), 61_000),
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
                l.check_at("r", a, None, &rl(2, 60_000), 1_000),
                Outcome::Allowed
            ));
        }
        assert!(matches!(
            l.check_at("r", b, None, &rl(2, 60_000), 1_000),
            Outcome::Allowed
        ));
        assert!(matches!(
            l.check_at("other", a, None, &rl(2, 60_000), 1_000),
            Outcome::Allowed
        ));
        assert!(matches!(
            l.check_at("r", a, None, &rl(2, 60_000), 1_000),
            Outcome::Limited { .. }
        ));
    }

    /// The distinct address `n` of a flood, as from one IPv6 /64.
    fn flood_ip(n: u32) -> IpAddr {
        // The varying bits live in the /64 prefix, because the limiter keys on the
        // prefix now: varying the low bits would collapse to one bucket after the
        // normalization #189 added, and the flood would fill nothing.
        IpAddr::V6(std::net::Ipv6Addr::new(
            0x2001,
            0xdb8,
            (n >> 16) as u16,
            n as u16,
            0,
            0,
            0,
            0,
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
                l.check_at("login", victim, None, &login, now),
                Outcome::Allowed
            ));
        }
        assert!(matches!(
            l.check_at("login", victim, None, &login, now),
            Outcome::Limited { .. }
        ));
        let other = rl(1_000, 1_000);
        for n in 0..=(SWEEP_FLOOR as u32 + 1) {
            l.check_at("other", flood_ip(n), None, &other, now);
        }
        assert!(
            l.table.lock().unwrap().sweep_at > SWEEP_FLOOR,
            "the flood must have triggered a sweep"
        );
        match l.check_at("login", victim, None, &login, now) {
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
        l.check_at("long", survivor, None, &long, 500);
        for n in 0..SWEEP_FLOOR as u32 {
            l.check_at("short", flood_ip(n), None, &short, 500);
        }
        // Past the floor, in the next second: every `short` window has ended.
        l.check_at("short", flood_ip(u32::MAX), None, &short, 1_500);
        let table = l.table.lock().unwrap();
        assert_eq!(
            table.windows.len(),
            2,
            "only the hour window and the new one remain"
        );
        assert!(table
            .windows
            .contains_key(&("long".to_string(), Client::Ip(survivor))));
        assert_eq!(table.sweep_at, SWEEP_FLOOR);
    }

    #[test]
    fn a_table_of_live_windows_is_not_rescanned_on_every_request() {
        // While every window is live a sweep frees nothing; the next one waits until the table
        // has doubled, rather than scanning the whole map under the lock on every request.
        let l = RateLimiter::default();
        let hour = rl(10, 3_600_000);
        for n in 0..=(SWEEP_FLOOR as u32 + 1) {
            l.check_at("r", flood_ip(n), None, &hour, 0);
        }
        let after_first = l.table.lock().unwrap().sweep_at;
        assert_eq!(after_first, 2 * (SWEEP_FLOOR + 1));
        for n in 0..1_000 {
            l.check_at("r", flood_ip(SWEEP_FLOOR as u32 + 2 + n), None, &hour, 0);
        }
        assert_eq!(
            l.table.lock().unwrap().sweep_at,
            after_first,
            "no sweep until the table doubles"
        );
    }

    /// A consumer named like an address, or a header carrying one, is not that address: each
    /// kind of client counts in windows of its own.
    #[test]
    fn a_consumer_a_header_and_an_address_never_share_a_window() {
        let l = RateLimiter::default();
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        let one = rl(1, 60_000);
        let named = || Client::Consumer("198.51.100.1".into());
        assert!(matches!(
            l.check_at("r", named(), None, &one, 1_000),
            Outcome::Allowed
        ));
        assert!(matches!(
            l.check_at("r", Client::header(b"198.51.100.1"), None, &one, 1_000),
            Outcome::Allowed
        ));
        assert!(matches!(
            l.check_at("r", ip, None, &one, 1_000),
            Outcome::Allowed
        ));
        assert!(matches!(
            l.check_at("r", named(), None, &one, 1_000),
            Outcome::Limited { .. }
        ));
    }

    #[test]
    fn a_limit_counts_by_what_it_names_and_by_address_without_it() {
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert("x-tenant", "acme".parse().unwrap());
        let none = http::HeaderMap::new();
        let tenant = LimitBy::Header("x-tenant".into());
        let mobile = || Client::Consumer("shop/mobile".into());
        assert_eq!(
            client(&LimitBy::Ip, Some(ip), Some("shop/mobile"), &headers),
            Some(Client::Ip(ip))
        );
        assert_eq!(
            client(&LimitBy::Consumer, Some(ip), Some("shop/mobile"), &none),
            Some(mobile())
        );
        assert_eq!(
            client(&LimitBy::Consumer, Some(ip), None, &none),
            Some(Client::Ip(ip)),
            "no consumer identified"
        );
        assert_eq!(
            client(&tenant, Some(ip), None, &headers),
            Some(Client::header(b"acme"))
        );
        assert_ne!(Client::header(b"acme"), Client::header(b"acme2"));
        assert_eq!(
            client(&tenant, Some(ip), None, &none),
            Some(Client::Ip(ip)),
            "no such header"
        );
        // The address is needed and unknown: no limit, as before limits counted anything else.
        assert_eq!(client(&tenant, None, None, &none), None);
        // A consumer needs no address.
        assert_eq!(
            client(&LimitBy::Consumer, None, Some("shop/mobile"), &none),
            Some(mobile())
        );
    }

    /// Past `HEADER_WINDOWS` live header windows a new value counts by the request's address
    /// rather than opening one more window; a value counted before keeps its own; with no
    /// address a new value is not counted at all, as an unaddressed request never was; and once
    /// the windows end, a request that meets the cap sweeps them and gets a window again.
    #[test]
    fn past_the_cap_a_new_header_value_counts_by_address() {
        let l = RateLimiter::default();
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        let hour = rl(1, 3_600_000);
        for n in 0..HEADER_WINDOWS {
            l.check_at(
                "r",
                Client::header(n.to_string().as_bytes()),
                Some(ip),
                &hour,
                0,
            );
        }
        assert_eq!(l.table.lock().unwrap().header_windows["r"], HEADER_WINDOWS);
        // The address's own window is untouched so far: the first new value spends it ...
        assert!(matches!(
            l.check_at("r", Client::header(b"new-1"), Some(ip), &hour, 0),
            Outcome::Allowed
        ));
        // ... and the second new value finds it spent.
        assert!(matches!(
            l.check_at("r", Client::header(b"new-2"), Some(ip), &hour, 0),
            Outcome::Limited { .. }
        ));
        // A value counted before the cap keeps its window, which the loop spent.
        assert!(matches!(
            l.check_at("r", Client::header(b"0"), Some(ip), &hour, 0),
            Outcome::Limited { .. }
        ));
        assert!(matches!(
            l.check_at("r", Client::header(b"new-3"), None, &hour, 0),
            Outcome::Allowed
        ));
        assert_eq!(l.table.lock().unwrap().header_windows["r"], HEADER_WINDOWS);
        // The hour is over: meeting the cap sweeps, and the new value gets a window of its own.
        let later = 3_600_000 + 1;
        assert!(matches!(
            l.check_at("r", Client::header(b"new-4"), Some(ip), &hour, later),
            Outcome::Allowed
        ));
        assert!(matches!(
            l.check_at("r", Client::header(b"new-4"), Some(ip), &hour, later),
            Outcome::Limited { .. }
        ));
        assert_eq!(l.table.lock().unwrap().header_windows["r"], 1);
    }

    /// A rule whose clients choose the header's value fills its own allowance and no one else's:
    /// at the cap on "a", a new value on "b" still opens a window of its own.
    #[test]
    fn a_full_rule_leaves_another_rules_header_windows_alone() {
        let l = RateLimiter::default();
        let hour = rl(1, 3_600_000);
        for n in 0..HEADER_WINDOWS {
            l.check_at(
                "a",
                Client::header(n.to_string().as_bytes()),
                None,
                &hour,
                0,
            );
        }
        let new = || Client::header(b"new");
        // "a" is full, and with no address a new value there is not counted at all.
        assert!(matches!(
            l.check_at("a", new(), None, &hour, 0),
            Outcome::Allowed
        ));
        assert!(matches!(
            l.check_at("b", new(), None, &hour, 0),
            Outcome::Allowed
        ));
        let table = l.table.lock().unwrap();
        assert!(!table.windows.contains_key(&("a".to_string(), new())));
        assert!(table.windows.contains_key(&("b".to_string(), new())));
        assert_eq!(table.header_windows["a"], HEADER_WINDOWS);
        assert_eq!(table.header_windows["b"], 1);
    }

    /// The header counts only as a single, non-empty line, whatever a proxy in front did to it;
    /// a value that is not ASCII is still a value.
    #[test]
    fn only_a_single_non_empty_header_line_counts_by_the_header() {
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        let tenant = LimitBy::Header("x-tenant".into());
        let by = |headers: &http::HeaderMap| client(&tenant, Some(ip), None, headers);

        // A proxy that appends leaves the client's own line first: neither line is believed.
        let mut two = http::HeaderMap::new();
        two.append("x-tenant", "client-chosen".parse().unwrap());
        two.append("x-tenant", "acme".parse().unwrap());
        assert_eq!(by(&two), Some(Client::Ip(ip)), "two lines");

        let mut same = http::HeaderMap::new();
        same.append("x-tenant", "acme".parse().unwrap());
        same.append("x-tenant", "acme".parse().unwrap());
        assert_eq!(by(&same), Some(Client::Ip(ip)), "the same line twice");

        let mut empty = http::HeaderMap::new();
        empty.insert("x-tenant", http::HeaderValue::from_static(""));
        assert_eq!(by(&empty), Some(Client::Ip(ip)), "an empty value");

        let mut utf8 = http::HeaderMap::new();
        utf8.insert(
            "x-tenant",
            http::HeaderValue::from_bytes(b"caf\xc3\xa9").unwrap(),
        );
        assert_eq!(by(&utf8), Some(Client::header(b"caf\xc3\xa9")));
        assert_ne!(by(&utf8), Some(Client::header(b"cafe")));
    }

    /// A request that meets a full cap may sweep, but at most once a second: the scan is under
    /// the lock every worker shares, and a flood of new values would otherwise repeat it on
    /// every request. Rule "r" throughout, and no address, so that nothing falls back to an
    /// address window, which would push the table past its doubling sweep and confuse this.
    #[test]
    fn a_full_cap_sweeps_at_most_once_a_second() {
        let l = RateLimiter::default();
        let hour = rl(1, 3_600_000);
        let second = rl(1, 1_000);
        let has = |value: &[u8]| {
            l.table
                .lock()
                .unwrap()
                .windows
                .contains_key(&("r".to_string(), Client::header(value)))
        };
        for n in 0..HEADER_WINDOWS - 1 {
            l.check_at(
                "r",
                Client::header(n.to_string().as_bytes()),
                None,
                &hour,
                0,
            );
        }
        // One more, in a window that ends at 2000: "r" is now full.
        l.check_at("r", Client::header(b"short"), None, &second, 1_500);
        assert_eq!(l.table.lock().unwrap().header_windows["r"], HEADER_WINDOWS);
        // The first request to meet the cap sweeps; nothing has ended, so nothing is freed and
        // the new value is not counted.
        assert!(matches!(
            l.check_at("r", Client::header(b"early"), None, &hour, 1_600),
            Outcome::Allowed
        ));
        assert!(!has(b"early"));
        // The short window has ended, but the last sweep was half a second ago: not again yet.
        assert!(matches!(
            l.check_at("r", Client::header(b"late"), None, &hour, 2_100),
            Outcome::Allowed
        ));
        assert!(!has(b"late"), "no second sweep within the second");
        // A second after that sweep, the ended window is freed and the value gets its own.
        assert!(matches!(
            l.check_at("r", Client::header(b"late"), None, &hour, 2_600),
            Outcome::Allowed
        ));
        assert!(has(b"late"));
        assert_eq!(l.table.lock().unwrap().header_windows["r"], HEADER_WINDOWS);
    }
}
