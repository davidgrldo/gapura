//! Passive outlier detection: endpoints that keep failing are taken out of rotation for a while.
//!
//! Each attempt's outcome is recorded against its endpoint's [`Health`]. Enough consecutive
//! failures eject it for `base × n` (n = times ejected, capped); after that it is back on
//! probation, where one failure ejects it again and enough successes clear its history.
//! Selection only asks [`Health::is_ejected`], which takes no lock.
//!
//! Records are keyed by address and held by the [`Registry`] the `Store` owns, outside any one
//! configuration generation: a swap neither resets them nor keeps them for addresses it dropped.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use gapura_core::config::OutlierDetection;
use gapura_core::Config;

use crate::proxy::select::endpoint_addr;

/// What one attempt against an endpoint came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Success,
    Failure,
}

#[derive(Default)]
struct Counts {
    failures: u32,
    successes: u32,
    ejections: u32,
}

/// One endpoint's record.
#[derive(Default)]
pub struct Health {
    // ponytail: one small mutex per endpoint, taken once per attempt; atomics if a single
    // endpoint's request rate ever makes it contend.
    counts: Mutex<Counts>,
    /// The [`now_ms`] until which the endpoint is out. Written under `counts`, read without it.
    ejected_until: AtomicU64,
}

impl Health {
    pub fn is_ejected(&self, now_ms: u64) -> bool {
        self.ejected_until.load(Ordering::Relaxed) > now_ms
    }

    /// Count one outcome. `Some(how long)` when it is the one that ejected the endpoint.
    pub fn record(&self, outcome: Outcome, now_ms: u64, p: &OutlierDetection) -> Option<Duration> {
        if p.consecutive_failures == 0 {
            return None;
        }
        let mut c = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        // Answers to requests already in flight when it was ejected say nothing about the
        // endpoint after its time out, and must neither extend nor end it.
        if self.is_ejected(now_ms) {
            return None;
        }
        match outcome {
            Outcome::Success => {
                c.failures = 0;
                if c.ejections > 0 {
                    c.successes += 1;
                    if c.successes >= p.successes_to_recover {
                        *c = Counts::default();
                    }
                }
                None
            }
            Outcome::Failure => {
                c.successes = 0;
                c.failures = c.failures.saturating_add(1);
                // On probation one failure is enough: it has already shown what it does.
                let threshold = if c.ejections > 0 {
                    1
                } else {
                    p.consecutive_failures
                };
                if c.failures < threshold {
                    return None;
                }
                c.failures = 0;
                c.ejections = c.ejections.saturating_add(1);
                let ms = p
                    .base_ejection_ms
                    .saturating_mul(u64::from(c.ejections))
                    .min(p.max_ejection_ms);
                self.ejected_until
                    .store(now_ms.saturating_add(ms), Ordering::Relaxed);
                Some(Duration::from_millis(ms))
            }
        }
    }
}

static EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Milliseconds on a process-local monotonic clock, the one ejections are measured on.
pub fn now_ms() -> u64 {
    EPOCH.elapsed().as_millis() as u64
}

/// Per cluster key, one record per entry of `Cluster::endpoints`, in order; `None` where the
/// address does not parse (selection never picks those).
pub type ClusterHealth = HashMap<String, Vec<Option<Arc<Health>>>>;

/// Every configured endpoint's record, by address.
#[derive(Default)]
pub struct Registry(Mutex<HashMap<SocketAddr, Arc<Health>>>);

impl Registry {
    /// Records for `config`'s endpoints, sharing those of addresses seen before. An address
    /// `config` does not name is forgotten, so one that comes back starts over, as a new endpoint
    /// would.
    pub fn sync(&self, config: &Config) -> ClusterHealth {
        let mut known = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let named: HashSet<SocketAddr> = config
            .clusters
            .values()
            .flat_map(|c| c.endpoints.iter().filter_map(endpoint_addr))
            .collect();
        known.retain(|addr, _| named.contains(addr));
        let mut out = ClusterHealth::new();
        for (key, cluster) in &config.clusters {
            let records = cluster
                .endpoints
                .iter()
                .map(|e| endpoint_addr(e).map(|a| Arc::clone(known.entry(a).or_default())))
                .collect();
            out.insert(key.clone(), records);
        }
        out
    }
}

/// `pick_endpoint`'s question about the endpoint at an index, answered from `records`.
pub fn ejected_at(records: &[Option<Arc<Health>>], now_ms: u64) -> impl Fn(usize) -> bool + '_ {
    move |i| {
        records
            .get(i)
            .and_then(Option::as_ref)
            .is_some_and(|h| h.is_ejected(now_ms))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const F: Outcome = Outcome::Failure;
    const S: Outcome = Outcome::Success;

    /// Fail `h` until it is ejected; how long for.
    fn eject(h: &Health, now: u64, p: &OutlierDetection) -> Option<Duration> {
        (0..p.consecutive_failures)
            .filter_map(|_| h.record(F, now, p))
            .last()
    }

    #[test]
    fn five_consecutive_failures_eject_for_thirty_seconds() {
        let (h, p) = (Health::default(), OutlierDetection::default());
        for _ in 0..4 {
            assert_eq!(h.record(F, 0, &p), None);
        }
        assert_eq!(h.record(F, 0, &p), Some(Duration::from_secs(30)));
        assert!(h.is_ejected(29_999));
        assert!(!h.is_ejected(30_000));
    }

    #[test]
    fn a_success_resets_the_failure_count() {
        let (h, p) = (Health::default(), OutlierDetection::default());
        for _ in 0..4 {
            h.record(F, 0, &p);
        }
        h.record(S, 0, &p);
        for _ in 0..4 {
            assert_eq!(h.record(F, 0, &p), None);
        }
        assert!(h.record(F, 0, &p).is_some());
    }

    #[test]
    fn on_probation_one_failure_ejects_for_base_times_n_up_to_the_cap() {
        let (h, p) = (Health::default(), OutlierDetection::default());
        let mut now = eject(&h, 0, &p).unwrap().as_millis() as u64;
        for n in 2..=12u64 {
            let d = h
                .record(F, now, &p)
                .expect("one failure on probation ejects");
            assert_eq!(
                d.as_millis() as u64,
                (30_000 * n).min(300_000),
                "ejection {n}"
            );
            now += d.as_millis() as u64;
        }
    }

    #[test]
    fn outcomes_while_ejected_are_ignored() {
        let (h, p) = (Health::default(), OutlierDetection::default());
        eject(&h, 0, &p);
        assert_eq!(h.record(S, 10_000, &p), None);
        assert_eq!(h.record(F, 10_000, &p), None);
        assert!(
            !h.is_ejected(30_000),
            "neither result moved the end of the ejection"
        );
        assert_eq!(
            h.record(F, 30_000, &p),
            Some(Duration::from_secs(60)),
            "the success that arrived while ejected did not count towards recovery"
        );
    }

    #[test]
    fn enough_successes_on_probation_clear_the_history() {
        let (h, p) = (Health::default(), OutlierDetection::default());
        eject(&h, 0, &p);
        for _ in 0..5 {
            h.record(S, 30_000, &p);
        }
        for _ in 0..4 {
            assert_eq!(h.record(F, 30_000, &p), None, "back to five failures");
        }
        assert_eq!(
            h.record(F, 30_000, &p),
            Some(Duration::from_secs(30)),
            "and n back to 1"
        );
    }

    #[test]
    fn too_few_successes_leave_it_on_probation() {
        let (h, p) = (Health::default(), OutlierDetection::default());
        eject(&h, 0, &p);
        for _ in 0..4 {
            h.record(S, 30_000, &p);
        }
        assert_eq!(h.record(F, 30_000, &p), Some(Duration::from_secs(60)));
    }

    fn config(clusters: &[(&str, &[&str])]) -> Config {
        let mut c = Config::default();
        for (key, addrs) in clusters {
            c.clusters.insert(
                key.to_string(),
                gapura_core::config::Cluster {
                    endpoints: addrs
                        .iter()
                        .map(|a| gapura_core::config::Endpoint {
                            address: a.to_string(),
                            port: 80,
                        })
                        .collect(),
                    ..Default::default()
                },
            );
        }
        c
    }

    #[test]
    fn the_registry_keeps_records_across_syncs_and_forgets_dropped_addresses() {
        let reg = Registry::default();
        let both = config(&[
            ("a", &["10.0.0.1", "10.0.0.2"]),
            ("b", &["10.0.0.1", "nope"]),
        ]);
        let h = reg.sync(&both);
        let first = h["a"][0].clone().unwrap();
        assert!(
            Arc::ptr_eq(&first, h["b"][0].as_ref().unwrap()),
            "one record per address, whichever clusters name it"
        );
        assert!(
            h["b"][1].is_none(),
            "an address that does not parse has no record"
        );
        eject(&first, 0, &OutlierDetection::default());

        let again = reg.sync(&both);
        assert!(Arc::ptr_eq(&first, again["a"][0].as_ref().unwrap()));
        assert!(again["a"][0].as_ref().unwrap().is_ejected(0));

        reg.sync(&config(&[("a", &["10.0.0.2"])]));
        let back = reg.sync(&both);
        assert!(
            !back["a"][0].as_ref().unwrap().is_ejected(0),
            "an address that left the configuration starts over when it returns"
        );
    }

    #[test]
    fn zero_consecutive_failures_disables_detection() {
        let h = Health::default();
        let p = OutlierDetection {
            consecutive_failures: 0,
            ..OutlierDetection::default()
        };
        for _ in 0..100 {
            assert_eq!(h.record(F, 0, &p), None);
        }
        assert!(!h.is_ejected(0));
    }
}
