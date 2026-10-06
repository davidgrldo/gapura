//! Limits on failed sign-ins.
//!
//! Two counters, both of failures only, so that an office signing in from one address is never
//! slowed by its own successes:
//!
//! - **A username at an address.** Five failures for one name from one address lock that pair
//!   for fifteen minutes. Every other address can go on trying that name, and that address can
//!   go on trying others: locking the account itself would hand anyone who knows a username a
//!   way to keep it locked, and the account that hurts most is the local one kept for the day
//!   the identity provider is down. Names are compared without case and counted whether or not
//!   an account has them, so a lock proves nothing about the name.
//! - **An address.** Ten failures from one address in a minute refuse its sign-ins until the
//!   minute is out, whatever names they try. A provider's refusal on the callback counts here,
//!   naming no account.
//!
//! The address is the peer's, or the nearest untrusted one in `X-Forwarded-For` when the peer
//! is a proxy named in `--trusted-proxies`. Behind an ingress without that flag every request
//! comes from the ingress, and a locked pair would lock that name for everyone.
//!
//! ponytail: counted in this process. Each console replica keeps its own counts, so N replicas
//! allow N times the attempts; a table in the store is the upgrade if that matters. argon2id's
//! cost is the brake that holds either way.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use gapura_core::client_ip::{client_ip, Cidr};

struct Rule {
    limit: u32,
    window: Duration,
    lock: Duration,
}

const PAIR: Rule = Rule {
    limit: 5,
    window: Duration::from_secs(15 * 60),
    lock: Duration::from_secs(15 * 60),
};

const ADDRESS: Rule = Rule {
    limit: 10,
    window: Duration::from_secs(60),
    lock: Duration::from_secs(60),
};

/// Entries kept at most. Expired ones are dropped first when it is reached; a flood from more
/// addresses than this leaves its newest ones uncounted rather than growing without bound.
const CAPACITY: usize = 100_000;

#[derive(Clone, PartialEq, Eq, Hash)]
enum Key {
    Pair(String, IpAddr),
    Address(IpAddr),
}

impl Key {
    fn rule(&self) -> &'static Rule {
        match self {
            Key::Pair(..) => &PAIR,
            Key::Address(_) => &ADDRESS,
        }
    }
}

struct Counter {
    failures: u32,
    since: Instant,
    locked_until: Option<Instant>,
}

impl Counter {
    fn locked(&self, now: Instant) -> Option<Duration> {
        self.locked_until
            .filter(|until| *until > now)
            .map(|until| until - now)
    }

    fn expired(&self, rule: &Rule, now: Instant) -> bool {
        self.locked(now).is_none() && now >= self.since + rule.window
    }
}

#[derive(Default)]
pub struct Throttle {
    trusted_proxies: Vec<Cidr>,
    counters: Mutex<HashMap<Key, Counter>>,
}

impl Throttle {
    pub fn new(trusted_proxies: Vec<Cidr>) -> Self {
        Self {
            trusted_proxies,
            counters: Mutex::default(),
        }
    }

    /// The address a sign-in is counted against.
    pub fn client(&self, peer: Option<IpAddr>, forwarded_for: Option<&str>) -> IpAddr {
        // No peer only where no listener supplied one, which is a test; one shared address
        // there is the conservative reading.
        let peer = peer.unwrap_or(IpAddr::from([0, 0, 0, 0]));
        client_ip(peer, forwarded_for, &self.trusted_proxies, None)
    }

    /// How long a sign-in as `name` from `addr` must wait, if it must. `None` for `name` asks
    /// only about the address.
    pub fn wait(&self, name: Option<&str>, addr: IpAddr) -> Option<Duration> {
        self.wait_at(name, addr, Instant::now())
    }

    /// Counts a failed sign-in. `None` for `name` counts it against the address only.
    pub fn failed(&self, name: Option<&str>, addr: IpAddr) {
        self.failed_at(name, addr, Instant::now())
    }

    /// A sign-in that succeeded clears its pair, so the person who finally typed it right is not
    /// still a strike from a lock. The address keeps its count: it is about the address.
    pub fn succeeded(&self, name: &str, addr: IpAddr) {
        self.lock().remove(&Key::Pair(name.to_lowercase(), addr));
    }

    fn wait_at(&self, name: Option<&str>, addr: IpAddr, now: Instant) -> Option<Duration> {
        let counters = self.lock();
        let keys = name
            .map(|n| Key::Pair(n.to_lowercase(), addr))
            .into_iter()
            .chain([Key::Address(addr)]);
        keys.filter_map(|k| counters.get(&k).and_then(|c| c.locked(now)))
            .max()
    }

    fn failed_at(&self, name: Option<&str>, addr: IpAddr, now: Instant) {
        let mut counters = self.lock();
        let keys = name
            .map(|n| Key::Pair(n.to_lowercase(), addr))
            .into_iter()
            .chain([Key::Address(addr)]);
        for key in keys {
            let rule = key.rule();
            if !counters.contains_key(&key) && counters.len() >= CAPACITY {
                counters.retain(|k, c| !c.expired(k.rule(), now));
                if counters.len() >= CAPACITY {
                    tracing::warn!("the sign-in limits are full; a failure went uncounted");
                    continue;
                }
            }
            let counter = counters.entry(key).or_insert(Counter {
                failures: 0,
                since: now,
                locked_until: None,
            });
            if counter.expired(rule, now) {
                *counter = Counter {
                    failures: 0,
                    since: now,
                    locked_until: None,
                };
            }
            counter.failures += 1;
            if counter.failures >= rule.limit && counter.locked(now).is_none() {
                counter.locked_until = Some(now + rule.lock);
            }
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<Key, Counter>> {
        // A panic while holding it leaves counts, never a half-made decision about a password.
        self.counters.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// What a refused sign-in is told: the same for a locked pair and a busy address, and for any
/// name, so it says nothing about which accounts exist.
pub fn wait_message(wait: Duration) -> String {
    let minutes = wait.as_secs().div_ceil(60).max(1);
    let unit = if minutes == 1 { "minute" } else { "minutes" };
    format!("Too many failed attempts. Try again in {minutes} {unit}.")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn five_failures_lock_the_name_at_that_address_and_nowhere_else() {
        let t = Throttle::default();
        let now = Instant::now();
        let (here, there) = (ip("203.0.113.1"), ip("203.0.113.2"));
        for _ in 0..4 {
            t.failed_at(Some("Maya"), here, now);
        }
        assert_eq!(t.wait_at(Some("maya"), here, now), None);
        t.failed_at(Some("MAYA"), here, now);
        assert_eq!(
            t.wait_at(Some("maya"), here, now),
            Some(Duration::from_secs(15 * 60)),
            "compared without case"
        );
        assert_eq!(t.wait_at(Some("maya"), there, now), None, "another address");
        assert_eq!(t.wait_at(Some("ivan"), here, now), None, "another name");
        let later = now + Duration::from_secs(15 * 60);
        assert_eq!(t.wait_at(Some("maya"), here, later), None, "and it ends");
    }

    #[test]
    fn ten_failures_from_an_address_refuse_every_name_until_the_minute_is_out() {
        let t = Throttle::default();
        let now = Instant::now();
        let here = ip("198.51.100.7");
        for i in 0..10 {
            t.failed_at(Some(&format!("user{i}")), here, now);
        }
        assert!(t.wait_at(Some("someone-new"), here, now).is_some());
        assert!(t.wait_at(None, here, now).is_some());
        assert_eq!(t.wait_at(None, here, now + Duration::from_secs(60)), None);
    }

    #[test]
    fn failures_spread_beyond_the_window_never_lock() {
        let t = Throttle::default();
        let mut now = Instant::now();
        let here = ip("192.0.2.9");
        for _ in 0..20 {
            t.failed_at(Some("maya"), here, now);
            now += Duration::from_secs(16 * 60 / 4);
        }
        assert_eq!(t.wait_at(Some("maya"), here, now), None);
    }

    #[test]
    fn a_success_clears_the_pair_but_not_the_address() {
        let t = Throttle::default();
        let now = Instant::now();
        let here = ip("192.0.2.10");
        for _ in 0..4 {
            t.failed_at(Some("maya"), here, now);
        }
        t.succeeded("Maya", here);
        t.failed_at(Some("maya"), here, now);
        assert_eq!(t.wait_at(Some("maya"), here, now), None);
    }

    #[test]
    fn behind_a_trusted_proxy_the_forwarded_address_is_counted() {
        let t = Throttle::new(vec!["10.0.0.0/8".parse().unwrap()]);
        assert_eq!(
            t.client(Some(ip("10.1.2.3")), Some("203.0.113.5, 10.9.9.9")),
            ip("203.0.113.5")
        );
        // Not from a trusted proxy: the header is the caller's word, and is ignored.
        assert_eq!(
            t.client(Some(ip("198.51.100.1")), Some("203.0.113.5")),
            ip("198.51.100.1")
        );
    }

    #[test]
    fn the_message_rounds_up_to_whole_minutes() {
        assert_eq!(
            wait_message(Duration::from_secs(61)),
            "Too many failed attempts. Try again in 2 minutes."
        );
        assert_eq!(
            wait_message(Duration::from_secs(5)),
            "Too many failed attempts. Try again in 1 minute."
        );
    }
}
