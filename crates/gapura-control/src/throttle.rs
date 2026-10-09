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
//!   an account has them, so a lock proves nothing about the name. A name is kept only as a
//!   SHA-256 digest of its lowercased form: a fixed 32 bytes however long the name posted was,
//!   so a flood of unique, long names costs the counters no more than one of short ones.
//! - **An address.** Ten failures from one address in a minute refuse its sign-ins until the
//!   minute is out, whatever names they try. A provider's refusal on the callback counts here,
//!   naming no account.
//!
//! An attempt is counted from the moment it is let through, not from when its password has been
//! verified: `begin` reserves it against both counters as a failure in waiting, and its outcome
//! settles it. So a burst sent at once gets as far as a sequence would, and no further.
//!
//! The address is the peer's, or the nearest untrusted one in `X-Forwarded-For` when the peer
//! is a proxy named in `--trusted-proxies`. Behind an ingress without that flag every request
//! comes from the ingress, and a locked pair would lock that name for everyone.
//!
//! Sign-ups (`SignUps`) are held by the same counters under a policy of their own: every attempt
//! from an address counts, successful or not, against two windows, five in ten minutes and
//! twenty in a day. Creating accounts is what is being limited, not guessing passwords, so a
//! success is no reason to forgive one, and neither is a client hanging up: an attempt dropped
//! unsettled counts. An IPv6 address is counted by its /64, which one host is commonly handed
//! whole, and when the counters are full a sign-up is refused rather than let through uncounted.
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

/// Sign-ups from one address in a burst: five in ten minutes.
const SIGN_UP_BURST: Rule = Rule {
    limit: 5,
    window: Duration::from_secs(10 * 60),
    lock: Duration::from_secs(10 * 60),
};

/// Sign-ups from one address in a day: twenty.
const SIGN_UP_DAY: Rule = Rule {
    limit: 20,
    window: Duration::from_secs(24 * 60 * 60),
    lock: Duration::from_secs(24 * 60 * 60),
};

/// Which counters an attempt is held to: a name at an address, when there is a rule for that,
/// and the address, under each of its rules.
#[derive(Clone, Copy)]
struct Policy {
    pair: Option<&'static Rule>,
    address: &'static [Rule],
    /// Full counters refuse an attempt rather than let it through uncounted.
    fail_closed: bool,
    /// What an attempt dropped unsettled is taken as.
    on_drop: Outcome,
}

impl Policy {
    fn rule(&self, key: &Key) -> &'static Rule {
        match key {
            Key::Pair(..) => self.pair.expect("a pair is counted only under a pair rule"),
            Key::Address(_, window) => &self.address[usize::from(*window)],
        }
    }
}

/// A sign-in fails open when the counters are full: refusing would lock everyone out, the
/// break-glass account included, and argon2id's cost still brakes guessing. Dropped, an attempt
/// is given back: it said nothing about the password.
const SIGN_IN: Policy = Policy {
    pair: Some(&PAIR),
    address: &[ADDRESS],
    fail_closed: false,
    on_drop: Outcome::Refunded,
};

/// A sign-up fails closed: what it makes is an account, and nobody is locked out of anything
/// they had by waiting. Dropped, an attempt counts: a client that hangs up once its password is
/// being hashed has already cost the hash.
const SIGN_UP: Policy = Policy {
    pair: None,
    address: &[SIGN_UP_BURST, SIGN_UP_DAY],
    fail_closed: true,
    on_drop: Outcome::Failed,
};

/// Entries kept at most. Expired ones are dropped first when it is reached; a flood from more
/// addresses than this leaves its newest ones uncounted rather than growing without bound.
const CAPACITY: usize = 100_000;

/// What a counter counts. `Copy`, so it owns nothing on the heap: an entry costs the same
/// whatever name it was made from.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Key {
    /// The digest of a lowercased name, and an address.
    Pair([u8; 32], IpAddr),
    /// An address, under the policy's address rule at this index.
    Address(IpAddr, u8),
}

impl Key {
    /// The pair `name` at `addr`. Lowercased a character at a time straight into the digest,
    /// so a long name is never copied, only read once.
    fn pair(name: &str, addr: IpAddr) -> Self {
        use sha2::{Digest, Sha256};
        let mut digest = Sha256::new();
        let mut buf = [0u8; 4];
        for c in name.chars().flat_map(char::to_lowercase) {
            digest.update(c.encode_utf8(&mut buf).as_bytes());
        }
        Key::Pair(digest.finalize().into(), addr)
    }
}

struct Counter {
    failures: u32,
    /// Attempts let through and not yet settled. Each counts as a failure until it is one or
    /// is not, so a burst sent all at once is held to the limit a sequence would be.
    pending: u32,
    since: Instant,
    locked_until: Option<Instant>,
}

impl Counter {
    fn fresh(now: Instant) -> Self {
        Counter {
            failures: 0,
            pending: 0,
            since: now,
            locked_until: None,
        }
    }

    fn locked(&self, now: Instant) -> Option<Duration> {
        self.locked_until
            .filter(|until| *until > now)
            .map(|until| until - now)
    }

    /// Unlocked and past its window: the failures it holds no longer count.
    fn lapsed(&self, rule: &Rule, now: Instant) -> bool {
        self.locked(now).is_none() && now >= self.since + rule.window
    }

    /// Nothing left worth keeping: lapsed, and no attempt in flight to settle against it.
    fn expired(&self, rule: &Rule, now: Instant) -> bool {
        self.pending == 0 && self.lapsed(rule, now)
    }

    /// How long another attempt must wait. A lock says so itself; short of one, the attempts in
    /// flight are counted as the failures they may yet be, and if those would reach the limit
    /// the answer is the lock they would make, the longest the caller could have to wait.
    fn wait(&self, rule: &Rule, now: Instant) -> Option<Duration> {
        if let Some(wait) = self.locked(now) {
            return Some(wait);
        }
        let failures = if self.lapsed(rule, now) {
            0
        } else {
            self.failures
        };
        (failures + self.pending >= rule.limit).then_some(rule.lock)
    }
}

pub struct Throttle {
    trusted_proxies: Vec<Cidr>,
    policy: Policy,
    /// `CAPACITY`, but for tests.
    capacity: usize,
    counters: Mutex<HashMap<Key, Counter>>,
}

/// Why an attempt was not let through.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    /// The counters it is held to are spent for this long.
    Wait(Duration),
    /// The counters are full, and the policy refuses what it cannot count.
    Full,
}

/// The sign-in limits, trusting no proxy.
impl Default for Throttle {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

/// How an attempt ended, as far as the counters care.
#[derive(Clone, Copy)]
enum Outcome {
    Failed,
    Succeeded,
    /// It said nothing about the password, such as the store being down: given back.
    Refunded,
}

/// A sign-in let through by `Throttle::begin`, reserved against its counters until it is
/// settled: `failed`, `succeeded`, `refund`ed, or dropped, which gives the reservation back for a
/// sign-in and counts it for a sign-up (see the policies). Dropping is also what a request does
/// when its client hangs up mid-check, so no outcome leaks a slot.
#[must_use = "an attempt is settled by `failed`, `succeeded` or `refund`"]
pub struct Attempt<'a> {
    throttle: &'a Throttle,
    /// The keys it is counted against, each with whether it holds a reservation there: one is
    /// not made when the counters are full, as a failure there went uncounted before.
    keys: Vec<(Key, bool)>,
}

impl Attempt<'_> {
    /// The password was wrong, or the provider refused: counted as a failure.
    pub fn failed(mut self) {
        let keys = std::mem::take(&mut self.keys);
        self.throttle.settle(keys, Outcome::Failed, Instant::now());
    }

    /// The sign-in succeeded. Its pair is cleared, so the person who finally typed it right is
    /// not still a strike from a lock. The address keeps its count: it is about the address.
    pub fn succeeded(mut self) {
        let keys = std::mem::take(&mut self.keys);
        self.throttle
            .settle(keys, Outcome::Succeeded, Instant::now());
    }

    /// It said nothing, such as the store being down: given back, whatever the policy does with
    /// an attempt dropped unsettled.
    pub fn refund(mut self) {
        let keys = std::mem::take(&mut self.keys);
        self.throttle
            .settle(keys, Outcome::Refunded, Instant::now());
    }

    #[cfg(test)]
    fn failed_at(mut self, now: Instant) {
        let keys = std::mem::take(&mut self.keys);
        self.throttle.settle(keys, Outcome::Failed, now);
    }
}

impl Drop for Attempt<'_> {
    fn drop(&mut self) {
        if !self.keys.is_empty() {
            let keys = std::mem::take(&mut self.keys);
            let outcome = self.throttle.policy.on_drop;
            self.throttle.settle(keys, outcome, Instant::now());
        }
    }
}

impl Throttle {
    /// The sign-in limits: a name at an address, and an address.
    pub fn new(trusted_proxies: Vec<Cidr>) -> Self {
        Self::with_policy(trusted_proxies, SIGN_IN)
    }

    fn with_policy(trusted_proxies: Vec<Cidr>, policy: Policy) -> Self {
        Self {
            trusted_proxies,
            policy,
            capacity: CAPACITY,
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

    /// Lets a sign-in as `name` from `addr` through and reserves it against the counters, or
    /// says how long it must wait. `None` for `name` counts it against the address only.
    ///
    /// The check and the reservation are one step under one lock. Checking alone and counting
    /// the failure once the password had been verified let every attempt of a burst through
    /// before the first of them was counted (#157).
    pub fn begin(&self, name: Option<&str>, addr: IpAddr) -> Result<Attempt<'_>, Duration> {
        self.begin_at(name, addr, Instant::now())
    }

    fn begin_at(
        &self,
        name: Option<&str>,
        addr: IpAddr,
        now: Instant,
    ) -> Result<Attempt<'_>, Duration> {
        self.reserve_at(name, addr, now)
            .map_err(|refused| match refused {
                Refused::Wait(wait) => wait,
                // Not produced under a policy that fails open, as the sign-in one does; were it ever,
                // the address rule's lock is the wait it would be told.
                Refused::Full => ADDRESS.lock,
            })
    }

    fn reserve_at(
        &self,
        name: Option<&str>,
        addr: IpAddr,
        now: Instant,
    ) -> Result<Attempt<'_>, Refused> {
        let policy = self.policy;
        let mut counters = self.lock();
        let windows = (0..policy.address.len()).filter_map(|i| u8::try_from(i).ok());
        let keys: Vec<Key> = name
            .filter(|_| policy.pair.is_some())
            .map(|n| Key::pair(n, addr))
            .into_iter()
            .chain(windows.map(|i| Key::Address(addr, i)))
            .collect();
        if let Some(wait) = keys
            .iter()
            .filter_map(|k| counters.get(k).and_then(|c| c.wait(policy.rule(k), now)))
            .max()
        {
            return Err(Refused::Wait(wait));
        }
        let mut reserved = Vec::with_capacity(keys.len());
        for key in keys {
            match counter(&mut counters, policy, self.capacity, key, now) {
                Some(counter) => {
                    counter.pending += 1;
                    reserved.push((key, true));
                }
                None if policy.fail_closed => {
                    // What was reserved before the full one is given back, under the same lock.
                    self.settle_in(&mut counters, reserved, Outcome::Refunded, now);
                    return Err(Refused::Full);
                }
                None => reserved.push((key, false)),
            }
        }
        Ok(Attempt {
            throttle: self,
            keys: reserved,
        })
    }

    fn settle(&self, keys: Vec<(Key, bool)>, outcome: Outcome, now: Instant) {
        let mut counters = self.lock();
        self.settle_in(&mut counters, keys, outcome, now);
    }

    fn settle_in(
        &self,
        counters: &mut HashMap<Key, Counter>,
        keys: Vec<(Key, bool)>,
        outcome: Outcome,
        now: Instant,
    ) {
        let policy = self.policy;
        for (key, reserved) in keys {
            let rule = policy.rule(&key);
            if reserved {
                if let Some(counter) = counters.get_mut(&key) {
                    counter.pending = counter.pending.saturating_sub(1);
                }
            }
            match (outcome, key) {
                (Outcome::Failed, _) => {
                    if let Some(counter) = counter(counters, policy, self.capacity, key, now) {
                        counter.failures += 1;
                        if counter.failures >= rule.limit && counter.locked(now).is_none() {
                            counter.locked_until = Some(now + rule.lock);
                        }
                    }
                }
                (Outcome::Succeeded, Key::Pair(..)) => {
                    if let Some(counter) = counters.get_mut(&key) {
                        counter.failures = 0;
                        counter.locked_until = None;
                    }
                }
                (Outcome::Succeeded, Key::Address(..)) | (Outcome::Refunded, _) => {}
            }
            // A reservation makes an entry for every attempt, the ones that never fail
            // included; one left holding nothing goes now rather than waiting for the cap.
            if counters
                .get(&key)
                .is_some_and(|c| c.pending == 0 && c.failures == 0 && c.locked_until.is_none())
            {
                counters.remove(&key);
            }
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<Key, Counter>> {
        // A panic while holding it leaves counts, never a half-made decision about a password.
        self.counters.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The counter for `key`, made if there is none and restarted if its window has lapsed, or
/// `None` when the counters are full even of entries still worth keeping.
fn counter(
    counters: &mut HashMap<Key, Counter>,
    policy: Policy,
    capacity: usize,
    key: Key,
    now: Instant,
) -> Option<&mut Counter> {
    if !counters.contains_key(&key) && counters.len() >= capacity {
        counters.retain(|k, c| !c.expired(policy.rule(k), now));
        if counters.len() >= capacity {
            tracing::warn!(
                fail_closed = policy.fail_closed,
                "the attempt limits are full; an attempt was not counted"
            );
            return None;
        }
    }
    let rule = policy.rule(&key);
    let counter = counters.entry(key).or_insert_with(|| Counter::fresh(now));
    if counter.lapsed(rule, now) {
        // Attempts in flight stay counted; only the failures of a window that is over go.
        *counter = Counter {
            pending: counter.pending,
            ..Counter::fresh(now)
        };
    }
    Some(counter)
}

/// What a refused sign-in is told: the same for a locked pair and a busy address, and for any
/// name, so it says nothing about which accounts exist.
pub fn wait_message(wait: Duration) -> String {
    format!("Too many failed attempts. {}", try_again_in(wait))
}

/// What a sign-up refused for its address's count is told.
pub fn sign_up_wait_message(wait: Duration) -> String {
    format!(
        "Too many sign-ups from this address. {}",
        try_again_in(wait)
    )
}

/// "Try again in" `wait`, rounded up to whole minutes, or past two hours, which only the sign-up
/// day reaches, to whole hours.
fn try_again_in(wait: Duration) -> String {
    let minutes = wait.as_secs().div_ceil(60).max(1);
    let (count, unit) = if minutes > 120 {
        (minutes.div_ceil(60), "hours")
    } else if minutes == 1 {
        (1, "minute")
    } else {
        (minutes, "minutes")
    };
    format!("Try again in {count} {unit}.")
}

/// Sign-ups, counted per address: every attempt that reaches the form's checks, whether it
/// creates an account or not, under `SIGN_UP_BURST` and `SIGN_UP_DAY`. The address is resolved
/// as a sign-in's is, by `login::client_addr`, so this keeps no proxies of its own; an IPv6 one
/// is then counted by its /64.
pub struct SignUps(Throttle);

/// The bucket `addr` is counted in: an IPv4 address as it is, an IPv6 one by its /64. A host is
/// commonly given a whole /64, so counting single IPv6 addresses would give it 2^64 buckets. An
/// IPv4 address written as IPv6 (`::ffff:a.b.c.d`) is the IPv4 address.
fn bucket(addr: IpAddr) -> IpAddr {
    match addr.to_canonical() {
        IpAddr::V6(v6) => {
            let mut octets = v6.octets();
            octets[8..].fill(0);
            IpAddr::from(octets)
        }
        v4 => v4,
    }
}

impl Default for SignUps {
    fn default() -> Self {
        Self(Throttle::with_policy(Vec::new(), SIGN_UP))
    }
}

impl SignUps {
    /// Lets a sign-up from `addr` through and reserves it, or says why not. The attempt counts
    /// however it ends, settled with `failed` or dropped, unless it is given back with `refund`,
    /// which is for an answer that said nothing, such as the store being down.
    pub fn begin(&self, addr: IpAddr) -> Result<Attempt<'_>, Refused> {
        self.begin_at(addr, Instant::now())
    }

    fn begin_at(&self, addr: IpAddr, now: Instant) -> Result<Attempt<'_>, Refused> {
        self.0.reserve_at(None, bucket(addr), now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    impl Throttle {
        /// An attempt that is let through and fails, as the tests below count them.
        fn failed_at(&self, name: Option<&str>, addr: IpAddr, now: Instant) {
            self.begin_at(name, addr, now)
                .unwrap_or_else(|_| panic!("refused"))
                .failed_at(now);
        }

        /// How long an attempt now would wait; one let through is refunded at once.
        fn wait_at(&self, name: Option<&str>, addr: IpAddr, now: Instant) -> Option<Duration> {
            self.begin_at(name, addr, now).err()
        }
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
        t.begin_at(Some("Maya"), here, now).unwrap().succeeded();
        t.failed_at(Some("maya"), here, now);
        assert_eq!(t.wait_at(Some("maya"), here, now), None);
    }

    #[test]
    fn attempts_in_flight_count_against_the_limits_until_they_settle() {
        // #157: a burst for one name from one address is let through only as far as the limit,
        // before any of it has failed.
        let t = Throttle::default();
        let now = Instant::now();
        let here = ip("192.0.2.11");
        let held: Vec<_> = (0..5)
            .map(|_| {
                t.begin_at(Some("maya"), here, now)
                    .expect("within the limit")
            })
            .collect();
        assert_eq!(
            t.begin_at(Some("maya"), here, now).err(),
            Some(Duration::from_secs(15 * 60)),
            "the sixth waits for the lock the five would make"
        );
        // Given back, they count for nothing: neither failures nor a lock remain.
        drop(held);
        assert_eq!(t.wait_at(Some("maya"), here, now), None);
        assert_eq!(t.lock().len(), 0, "no entry is left holding nothing");

        // The address is held the same way, across names.
        let held: Vec<_> = (0..10)
            .map(|i| t.begin_at(Some(&format!("user{i}")), here, now).unwrap())
            .collect();
        assert!(t.wait_at(Some("someone-new"), here, now).is_some());
        assert!(t.wait_at(None, here, now).is_some());
        for attempt in held {
            attempt.failed_at(now);
        }
        assert_eq!(
            t.wait_at(None, here, now),
            Some(Duration::from_secs(60)),
            "and settled as failures, they lock it"
        );
    }

    #[test]
    fn a_success_settles_its_own_reservation_and_leaves_the_others() {
        let t = Throttle::default();
        let now = Instant::now();
        let here = ip("192.0.2.12");
        let others: Vec<_> = (0..4)
            .map(|_| t.begin_at(Some("maya"), here, now).unwrap())
            .collect();
        t.begin_at(Some("maya"), here, now).unwrap().succeeded();
        // Four still in flight: one more is let through, a second is not.
        let fifth = t.begin_at(Some("maya"), here, now).unwrap();
        assert!(t.wait_at(Some("maya"), here, now).is_some());
        drop((others, fifth));
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
    fn a_long_name_costs_a_counter_no_more_than_a_short_one() {
        // #158: the pair used to keep the whole lowercased name, so unique megabyte names each
        // held megabytes until the map filled. A key is now a fixed size and owns no heap.
        fn owns_no_heap<T: Copy>() {}
        owns_no_heap::<Key>();
        assert!(std::mem::size_of::<Key>() <= 64);
        let here = ip("203.0.113.3");
        let long = "M".repeat(1 << 20);
        assert!(Key::pair(&long, here) == Key::pair(&long.to_lowercase(), here));
        assert!(Key::pair(&long, here) != Key::pair(&long[1..], here));
        // And it is still counted, against the pair and the address.
        let t = Throttle::default();
        let now = Instant::now();
        for _ in 0..5 {
            t.failed_at(Some(&long), here, now);
        }
        assert!(t.wait_at(Some(&long.to_lowercase()), here, now).is_some());
        assert_eq!(t.lock().len(), 2, "one pair and one address");
    }

    #[test]
    fn five_sign_ups_from_an_address_wait_ten_minutes_and_twenty_wait_a_day() {
        let s = SignUps::default();
        let mut now = Instant::now();
        let (here, there) = (ip("203.0.113.20"), ip("203.0.113.21"));
        let sign_up = |now: Instant| s.begin_at(here, now).map(|a| a.failed_at(now));
        for _ in 0..5 {
            sign_up(now).expect("within the burst");
        }
        assert_eq!(
            sign_up(now),
            Err(Refused::Wait(Duration::from_secs(10 * 60)))
        );
        // Three more bursts of five, ten minutes apart, reach twenty.
        for _ in 0..3 {
            now += Duration::from_secs(10 * 60);
            for _ in 0..5 {
                sign_up(now).expect("a new burst");
            }
        }
        now += Duration::from_secs(10 * 60);
        let Err(Refused::Wait(wait)) = sign_up(now) else {
            panic!("twenty in a day");
        };
        assert!(wait > Duration::from_secs(23 * 60 * 60), "{wait:?}");
        assert!(s.begin_at(there, now).is_ok(), "another address");
        assert_eq!(
            sign_up_wait_message(wait),
            "Too many sign-ups from this address. Try again in 24 hours."
        );
    }

    #[test]
    fn a_sign_up_counts_unless_it_is_given_back() {
        let s = SignUps::default();
        let now = Instant::now();
        let here = ip("203.0.113.22");
        for _ in 0..10 {
            s.begin_at(here, now).unwrap().refund();
        }
        s.begin_at(here, now).expect("nothing counted").refund();
        assert_eq!(s.0.lock().len(), 0, "no entry is left holding nothing");
        // Dropped unsettled, as when a client hangs up mid-hash: counted.
        // A drop settles at the clock's own now, a little after `now`, so the lock it makes
        // runs a little past ten minutes from `now`.
        for _ in 0..5 {
            drop(s.begin_at(here, now).unwrap());
        }
        let refused = s.begin_at(here, now).err();
        assert!(
            matches!(refused, Some(Refused::Wait(w)) if w >= Duration::from_secs(10 * 60)),
            "{refused:?}"
        );
    }

    #[test]
    fn an_ipv6_sign_up_is_counted_by_its_64() {
        let s = SignUps::default();
        let now = Instant::now();
        for host in 1..=5 {
            let addr = ip(&format!("2001:db8:1:2::{host:x}"));
            s.begin_at(addr, now).unwrap().failed_at(now);
        }
        assert!(
            s.begin_at(ip("2001:db8:1:2:ffff:ffff:ffff:ffff"), now)
                .is_err(),
            "anywhere in the /64"
        );
        assert!(
            s.begin_at(ip("2001:db8:1:3::1"), now).is_ok(),
            "the next /64"
        );
        assert_eq!(bucket(ip("::ffff:192.0.2.1")), ip("192.0.2.1"));
        assert_eq!(bucket(ip("192.0.2.1")), ip("192.0.2.1"));
        // A sign-in still counts the address itself.
        let t = Throttle::default();
        for _ in 0..10 {
            t.failed_at(None, ip("2001:db8:1:2::1"), now);
        }
        assert_eq!(t.wait_at(None, ip("2001:db8:1:2::2"), now), None);
    }

    #[test]
    fn full_counters_refuse_a_sign_up_and_let_a_sign_in_through() {
        let mut s = SignUps::default();
        s.0.capacity = 3;
        let now = Instant::now();
        // Two windows per address: the first address fills two entries, the second one more and
        // then finds no room for its day window.
        s.begin_at(ip("192.0.2.1"), now).unwrap().failed_at(now);
        assert_eq!(s.begin_at(ip("192.0.2.2"), now).err(), Some(Refused::Full));
        assert_eq!(
            s.0.lock().len(),
            2,
            "the half-made reservation was given back"
        );
        assert!(
            s.begin_at(ip("192.0.2.1"), now).is_ok(),
            "one already counted"
        );

        let t = Throttle {
            capacity: 1,
            ..Throttle::default()
        };
        t.failed_at(None, ip("192.0.2.1"), now);
        let through = t.begin_at(Some("maya"), ip("192.0.2.2"), now);
        assert!(through.is_ok(), "a sign-in fails open");
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
        assert_eq!(
            sign_up_wait_message(Duration::from_secs(599)),
            "Too many sign-ups from this address. Try again in 10 minutes."
        );
    }
}
