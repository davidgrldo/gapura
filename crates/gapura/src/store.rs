//! Hot-swappable runtime state derived from a `Config`.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use arc_swap::{ArcSwap, Guard};
use gapura_core::matcher::{compile_regexes, RegexMap};
use gapura_core::status::StatusPatch;
use gapura_core::Config;
use pingora::tls::pkey::{PKey, Private};
use pingora::tls::x509::X509;

use crate::telemetry::{now_secs, METRICS};

/// A parsed TLS bundle: leaf certificate, optional chain, private key.
pub struct ParsedCert {
    pub leaf: X509,
    pub chain: Vec<X509>,
    pub key: PKey<Private>,
}

/// Immutable per-generation state read by every request without locks.
pub struct Runtime {
    pub config: Config,
    pub generation: u64,
    /// The status patches this generation's translation produced -- what a Kubernetes cluster
    /// would show as conditions, kept so the admin port can serve them where no API server
    /// exists to hold them (file mode; see /debug/status).
    pub status: Vec<StatusPatch>,
    rr: HashMap<String, AtomicUsize>,
    certs: HashMap<String, Arc<ParsedCert>>,
    /// Upstream CA bundles by cluster key, for `PeerOptions::ca`.
    upstream_cas: HashMap<String, Arc<Box<[X509]>>>,
    /// Compiled `PathMatch::Regex` patterns, like the cursors and certs compiled once per
    /// generation instead of per request.
    regexes: RegexMap,
    /// Decoding keys per JWKS document, for the same reason: a policy's keys cannot change
    /// between swaps, so parsing them per request would be work nothing asked for.
    jwt_keys: HashMap<String, crate::proxy::jwt::JwtKeys>,
}

impl Runtime {
    pub fn new(config: Config, generation: u64, status: Vec<StatusPatch>) -> Self {
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
        let mut upstream_cas: HashMap<String, Arc<Box<[X509]>>> = HashMap::new();
        for (key, cluster) in &config.clusters {
            let Some(pem) = cluster.tls.as_ref().and_then(|t| t.ca_pem.as_deref()) else {
                continue;
            };
            match X509::stack_from_pem(pem.as_bytes()) {
                Ok(stack) if !stack.is_empty() => {
                    upstream_cas.insert(key.clone(), Arc::new(stack.into_boxed_slice()));
                }
                Ok(_) | Err(_) => {
                    tracing::error!(cluster = %key, "upstream CA bundle unusable, TLS to this backend will fail verification");
                    METRICS
                        .tls_cert_parse_errors_total
                        .with_label_values(&[&format!("upstream-ca/{key}")])
                        .inc();
                }
            }
        }
        let (jwt_keys, unusable) = crate::proxy::jwt::compile(&config);
        if unusable > 0 {
            // Once per swap rather than once per request. A policy whose keys did not load
            // refuses everything, which is the safe direction and a loud one.
            tracing::warn!(
                keys = unusable,
                "JWKS keys that could not be used; policies relying on them will refuse every request"
            );
        }
        let (regexes, skipped) = compile_regexes(&config);
        for pattern in &skipped {
            tracing::warn!(
                pattern = %pattern,
                "path match regex does not compile, it matches nothing; translate should have rejected it"
            );
        }
        Self {
            config,
            generation,
            status,
            rr,
            certs,
            upstream_cas,
            regexes,
            jwt_keys,
        }
    }

    /// Decoding keys for a policy's JWKS document, compiled with this generation.
    pub fn jwt_keys(&self, jwks: &str) -> Option<&crate::proxy::jwt::JwtKeys> {
        self.jwt_keys.get(jwks)
    }

    /// Compiled regex path match patterns of this generation, for `match_port_with`.
    pub fn regexes(&self) -> &RegexMap {
        &self.regexes
    }

    /// Monotonic round-robin cursor for a cluster; `None` for unknown clusters.
    pub fn next_index(&self, cluster: &str) -> Option<usize> {
        self.rr
            .get(cluster)
            .map(|c| c.fetch_add(1, Ordering::Relaxed))
    }

    pub fn cert(&self, secret: &str) -> Option<&Arc<ParsedCert>> {
        self.certs.get(secret)
    }

    /// CA bundle of a cluster with `ca_pem`; `None` for system roots or an unparsable bundle.
    pub fn upstream_ca(&self, cluster: &str) -> Option<Arc<Box<[X509]>>> {
        self.upstream_cas.get(cluster).cloned()
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
    pub fn empty() -> Self {
        Self {
            current: ArcSwap::from_pointee(Runtime::new(Config::default(), 0, Vec::new())),
            ready: AtomicBool::new(false),
            generation: AtomicU64::new(0),
        }
    }

    /// Borrow the current runtime for a short, non-async read (e.g. `/readyz`).
    pub fn load(&self) -> Guard<Arc<Runtime>> {
        self.current.load()
    }

    pub fn load_full(&self) -> Arc<Runtime> {
        self.current.load_full()
    }

    /// Install a new Config. Marks the store ready.
    /// Call from a single writer (the config source); concurrent swaps could publish generations out of order.
    pub fn swap(&self, config: Config, status: Vec<StatusPatch>) {
        let generation = self.generation.fetch_add(1, Ordering::Relaxed) + 1;
        self.current
            .store(Arc::new(Runtime::new(config, generation, status)));
        self.ready.store(true, Ordering::Release);
        METRICS.config_last_reload_timestamp_seconds.set(now_secs());
        METRICS.config_from_cache.set(0);
    }

    /// Install a configuration read back from the disk cache at startup.
    ///
    /// Deliberately not `swap`: that sets `config_last_reload_timestamp_seconds`, and a cache
    /// load is not a reload. Letting it say otherwise would turn every alert built on "this
    /// gateway has not reloaded recently" green on a gateway serving a week-old cache, which is
    /// the one situation those alerts exist to reveal. What this does set is
    /// `gapura_config_from_cache`, so the state is visible rather than disguised.
    pub fn swap_from_cache(&self, config: Config) {
        let generation = self.generation.fetch_add(1, Ordering::Relaxed) + 1;
        self.current
            .store(Arc::new(Runtime::new(config, generation, Vec::new())));
        self.ready.store(true, Ordering::Release);
        METRICS.config_from_cache.set(1);
    }

    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
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
            client_port: None,
            protocol: Protocol::Https,
            hostname: None,
            tls,
            rules: vec![],
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
                tls: None,
                resolve: None,
            },
        );
        let rt = Runtime::new(
            Config {
                listeners: vec![],
                ports: BTreeMap::new(),
                clusters,
            },
            1,
            Vec::new(),
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
        store.swap(Config::default(), Vec::new());
        assert!(store.is_ready());
        assert_eq!(store.load().generation, 1);
        store.swap(Config::default(), Vec::new());
        assert_eq!(store.load_full().generation, 2);
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
                ports: BTreeMap::new(),
                clusters: BTreeMap::new(),
            },
            1,
            Vec::new(),
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
                ports: BTreeMap::new(),
                clusters: BTreeMap::new(),
            },
            1,
            Vec::new(),
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
                ports: BTreeMap::new(),
                clusters: BTreeMap::new(),
            },
            1,
            Vec::new(),
        );
        let parsed = rt.cert("infra/chain").expect("parsed");
        assert_eq!(parsed.chain.len(), 1);
        let sans = parsed.leaf.subject_alt_names().expect("SANs");
        assert!(sans
            .iter()
            .any(|san| san.dnsname() == Some("x.example.com")));
    }

    #[test]
    fn regexes_are_compiled_once_per_generation() {
        use gapura_core::config::{PathMatch, PortEntry, RouteMatch, RouteRule, Timeouts};
        let match_ = RouteMatch {
            path: PathMatch::Regex("^/api/v[0-9]+/".into()),
            headers: vec![],
            query: vec![],
            method: None,
        };
        let rules = vec![RouteRule {
            route: "apps/r".into(),
            rule_index: 0,
            creation_timestamp: "2026-01-01T00:00:00Z".into(),
            matches: vec![match_.clone()],
            filters: Default::default(),
            backends: vec![],
            timeouts: Timeouts::default(),
            rate_limit: None,
            plugins: vec![],
        }];
        let rt = Runtime::new(
            Config {
                listeners: vec![ListenerConfig {
                    id: "infra/main/http".into(),
                    port: 80,
                    client_port: None,
                    protocol: Protocol::Http,
                    hostname: None,
                    tls: None,
                    rules,
                }],
                ports: BTreeMap::from([(
                    80u16,
                    vec![PortEntry {
                        listener: 0,
                        hostname: None,
                        matcher: match_,
                        rule: 0,
                    }],
                )]),
                clusters: BTreeMap::new(),
            },
            1,
            Vec::new(),
        );
        assert!(
            rt.regexes().contains_key("^/api/v[0-9]+/"),
            "the runtime carries compiled patterns for the data plane"
        );
    }

    #[test]
    fn upstream_ca_is_parsed_per_cluster_and_garbage_is_skipped() {
        use gapura_core::config::ClusterTls;
        let key = rcgen::KeyPair::generate().unwrap();
        let ca = rcgen::CertificateParams::new(Vec::<String>::new())
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let tls = |pem: &str| {
            Some(ClusterTls {
                sni: "echo.apps.svc".into(),
                ca_pem: Some(pem.to_string()),
                insecure: false,
            })
        };
        let mut config = Config::default();
        config.clusters.insert(
            "apps/good:443".into(),
            Cluster {
                endpoints: vec![],
                tls: tls(&ca.pem()),
                resolve: None,
            },
        );
        config.clusters.insert(
            "apps/bad:443".into(),
            Cluster {
                endpoints: vec![],
                tls: tls("not a certificate"),
                resolve: None,
            },
        );
        config.clusters.insert(
            "apps/system:443".into(),
            Cluster {
                endpoints: vec![],
                tls: Some(ClusterTls {
                    sni: "x".into(),
                    ca_pem: None,
                    insecure: false,
                }),
                resolve: None,
            },
        );
        let rt = Runtime::new(config, 1, Vec::new());
        assert_eq!(rt.upstream_ca("apps/good:443").map(|c| c.len()), Some(1));
        assert!(
            rt.upstream_ca("apps/bad:443").is_none(),
            "unparsable bundle is logged and skipped"
        );
        assert!(
            rt.upstream_ca("apps/system:443").is_none(),
            "System roots need no bundle"
        );
    }
}
