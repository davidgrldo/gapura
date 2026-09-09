//! Hot-swappable runtime state derived from a `Config`.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use arc_swap::{ArcSwap, Guard};
use gapura_core::Config;
use pingora::tls::pkey::{PKey, Private};
use pingora::tls::x509::X509;

use crate::telemetry::{now_secs, METRICS};

/// A parsed TLS bundle: leaf certificate, optional chain, private key.
pub struct ParsedCert {
    #[allow(dead_code)] // used from Task 9 (TLS SNI resolver)
    pub leaf: X509,
    #[allow(dead_code)] // used from Task 9 (TLS SNI resolver)
    pub chain: Vec<X509>,
    #[allow(dead_code)] // used from Task 9 (TLS SNI resolver)
    pub key: PKey<Private>,
}

/// Immutable per-generation state read by every request without locks.
pub struct Runtime {
    pub config: Config,
    #[allow(dead_code)]
    // not read by production code anywhere in the plan text; kept for parity with the Store-level generation counter
    pub generation: u64,
    rr: HashMap<String, AtomicUsize>,
    #[allow(dead_code)] // read via Runtime::cert, used from Task 9
    certs: HashMap<String, Arc<ParsedCert>>,
}

impl Runtime {
    pub fn new(config: Config, generation: u64) -> Self {
        let rr = config
            .clusters
            .keys()
            .map(|k| (k.clone(), AtomicUsize::new(0)))
            .collect();
        let mut certs: HashMap<String, Arc<ParsedCert>> = HashMap::new();
        let mut attempted: HashSet<String> = HashSet::new();
        for listener in &config.listeners {
            let Some(tls) = &listener.tls else { continue };
            if !attempted.insert(tls.secret.clone()) {
                continue;
            }
            match parse_bundle(&tls.cert_pem, &tls.key_pem) {
                Ok(parsed) => {
                    certs.insert(tls.secret.clone(), Arc::new(parsed));
                }
                Err(e) => {
                    tracing::error!(secret = %tls.secret, listener = %listener.id, error = %e, "TLS secret unusable, handshakes for this listener will fail");
                    METRICS
                        .tls_cert_parse_errors_total
                        .with_label_values(&[&tls.secret])
                        .inc();
                }
            }
        }
        Self {
            config,
            generation,
            rr,
            certs,
        }
    }

    /// Monotonic round-robin cursor for a cluster; `None` for unknown clusters.
    pub fn next_index(&self, cluster: &str) -> Option<usize> {
        self.rr
            .get(cluster)
            .map(|c| c.fetch_add(1, Ordering::Relaxed))
    }

    #[allow(dead_code)] // used from Task 9 (TLS SNI resolver)
    pub fn cert(&self, secret: &str) -> Option<&Arc<ParsedCert>> {
        self.certs.get(secret)
    }
}

fn parse_bundle(cert_pem: &str, key_pem: &str) -> Result<ParsedCert, String> {
    let mut stack =
        X509::stack_from_pem(cert_pem.as_bytes()).map_err(|e| format!("tls.crt: {e}"))?;
    if stack.is_empty() {
        return Err("tls.crt: no CERTIFICATE block".to_string());
    }
    // kubernetes.io/tls convention (cert-manager, kubectl create secret tls): leaf first, then intermediates.
    let leaf = stack.remove(0);
    let key =
        PKey::private_key_from_pem(key_pem.as_bytes()).map_err(|e| format!("tls.key: {e}"))?;
    Ok(ParsedCert {
        leaf,
        chain: stack,
        key,
    })
}

/// The single shared handle: swap is atomic, readers never block, in-flight requests keep their Arc.
pub struct Store {
    current: ArcSwap<Runtime>,
    ready: AtomicBool,
    generation: AtomicU64,
}

impl Store {
    #[allow(dead_code)] // used from Task 10 (main.rs constructs the Store)
    pub fn empty() -> Self {
        Self {
            current: ArcSwap::from_pointee(Runtime::new(Config::default(), 0)),
            ready: AtomicBool::new(false),
            generation: AtomicU64::new(0),
        }
    }

    #[allow(dead_code)] // not called by production code anywhere in the plan text; load_full is used instead from Task 8/9/10
    pub fn load(&self) -> Guard<Arc<Runtime>> {
        self.current.load()
    }

    pub fn load_full(&self) -> Arc<Runtime> {
        self.current.load_full()
    }

    /// Install a new Config. Marks the store ready.
    /// Call from a single writer (the config source); concurrent swaps could publish generations out of order.
    pub fn swap(&self, config: Config) {
        let generation = self.generation.fetch_add(1, Ordering::Relaxed) + 1;
        self.current
            .store(Arc::new(Runtime::new(config, generation)));
        self.ready.store(true, Ordering::Release);
        METRICS.config_last_reload_timestamp_seconds.set(now_secs());
    }

    #[allow(dead_code)] // used from Task 10 (admin /readyz)
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    /// Generation of the last swap (0 before the first).
    #[allow(dead_code)] // not called by production code anywhere in the plan text; kept as a public accessor for the generation counter
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use gapura_core::config::{Cluster, Endpoint, ListenerConfig, Protocol, TlsBundle};

    use super::*;

    fn listener(tls: Option<TlsBundle>) -> ListenerConfig {
        ListenerConfig {
            id: "infra/main/https".into(),
            port: 443,
            protocol: Protocol::Https,
            hostname: None,
            tls,
            rules: vec![],
            table: vec![],
        }
    }

    #[test]
    fn round_robin_cursor_advances_per_cluster() {
        let mut clusters = BTreeMap::new();
        clusters.insert(
            "apps/echo:80".to_string(),
            Cluster {
                endpoints: vec![Endpoint {
                    address: "10.0.0.1".into(),
                    port: 8080,
                }],
            },
        );
        let rt = Runtime::new(
            Config {
                listeners: vec![],
                clusters,
            },
            1,
        );
        assert_eq!(rt.next_index("apps/echo:80"), Some(0));
        assert_eq!(rt.next_index("apps/echo:80"), Some(1));
        assert_eq!(rt.next_index("nope"), None);
    }

    #[test]
    fn swap_marks_ready_and_bumps_generation() {
        let store = Store::empty();
        assert!(!store.is_ready());
        assert_eq!(store.load().generation, 0);
        assert_eq!(store.generation(), 0);
        store.swap(Config::default());
        assert!(store.is_ready());
        assert_eq!(store.load().generation, 1);
        assert_eq!(store.generation(), 1);
        store.swap(Config::default());
        assert_eq!(store.load_full().generation, 2);
        assert_eq!(store.generation(), 2);
    }

    #[test]
    fn bad_pem_is_tolerated_and_good_pem_is_parsed() {
        let bad = TlsBundle {
            secret: "infra/bad".into(),
            cert_pem: "-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n".into(),
            key_pem: "-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----\n".into(),
        };
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["a.example.com".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let good = TlsBundle {
            secret: "infra/good".into(),
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        };
        let rt = Runtime::new(
            Config {
                listeners: vec![listener(Some(bad)), listener(Some(good))],
                clusters: BTreeMap::new(),
            },
            1,
        );
        assert!(rt.cert("infra/bad").is_none());
        let parsed = rt.cert("infra/good").expect("parsed");
        assert!(parsed.chain.is_empty());
        let sans = parsed.leaf.subject_alt_names().expect("SANs");
        assert!(sans
            .iter()
            .any(|san| san.dnsname() == Some("a.example.com")));
    }

    #[test]
    fn shared_bad_secret_is_counted_once() {
        let bad = TlsBundle {
            secret: "infra/bad2".into(),
            cert_pem: "-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n".into(),
            key_pem: "-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----\n".into(),
        };
        let before = METRICS
            .tls_cert_parse_errors_total
            .with_label_values(&["infra/bad2"])
            .get();
        let rt = Runtime::new(
            Config {
                listeners: vec![listener(Some(bad.clone())), listener(Some(bad))],
                clusters: BTreeMap::new(),
            },
            1,
        );
        let after = METRICS
            .tls_cert_parse_errors_total
            .with_label_values(&["infra/bad2"])
            .get();
        assert_eq!(after - before, 1);
        assert!(rt.cert("infra/bad2").is_none());
    }

    #[test]
    fn leaf_and_intermediate_split() {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf_params = rcgen::CertificateParams::new(vec!["x.example.com".to_string()]).unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();

        let cert_pem = format!("{}{}", leaf_cert.pem(), ca_cert.pem());
        let key_pem = leaf_key.serialize_pem();

        let bundle = TlsBundle {
            secret: "infra/chain".into(),
            cert_pem,
            key_pem,
        };
        let rt = Runtime::new(
            Config {
                listeners: vec![listener(Some(bundle))],
                clusters: BTreeMap::new(),
            },
            1,
        );
        let parsed = rt.cert("infra/chain").expect("parsed");
        assert_eq!(parsed.chain.len(), 1);
        let sans = parsed.leaf.subject_alt_names().expect("SANs");
        assert!(sans
            .iter()
            .any(|san| san.dnsname() == Some("x.example.com")));
    }
}
