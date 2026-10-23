//! Keys for JWT policies that name a `jwks_uri`: fetched beside the configuration poll, never on
//! the request path, and written into each policy's `jwks` before the configuration is swapped in,
//! so verifying reads them exactly as it reads a pasted document.
//!
//! Modelled on Kong's mlcache "resurrect". Once a URI has loaded, a failed fetch keeps the last
//! good document verifying for as long as the failures last, across restarts too (the control
//! source keeps the documents in its disk cache). One that has never loaded leaves the document
//! empty, and an empty document refuses every token. An IdP outage then costs key rotation, not
//! traffic -- the bargain the configuration cache makes for the control plane.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::time::{Duration, Instant};

use gapura_core::config::{Config, Plugin};
use gapura_core::jwt::MAX_JWKS_BYTES;
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

use crate::telemetry::{now_secs, METRICS};

/// How long a document is used when the IdP sends no `max-age`: Envoy's `remote_jwks` default.
const DEFAULT_TTL: Duration = Duration::from_secs(600);
/// The shortest `max-age` honoured, so an IdP answering `max-age=0` is not fetched every tick.
const MIN_TTL: Duration = Duration::from_secs(60);
/// The longest: a key removed at the IdP stops verifying within this.
const MAX_TTL: Duration = Duration::from_secs(3600);
/// The next try after a failed fetch.
const RETRY: Duration = Duration::from_secs(30);
/// The least time between two fetches an unknown `kid` asks for, Kong's `rediscovery_lifetime`:
/// tokens naming keys that exist nowhere cost the IdP at most one fetch per this, on top of the
/// schedule. Counted apart from scheduled fetches, so a key the IdP starts signing with just after
/// one is not held back by it.
const KID_MISS_GAP: Duration = Duration::from_secs(30);
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Where one key set comes from: the URI, and the CA that replaces the bundled roots for it. Two
/// policies naming one URI with different CAs are two sources.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Source {
    pub uri: String,
    pub ca_pem: Option<String>,
}

/// One fetched document, as the disk cache holds it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Fetched {
    pub uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_pem: Option<String>,
    pub document: String,
    /// Unix seconds of the fetch, so the age gauge tells the truth after a restart.
    pub fetched_at: i64,
}

/// A 200 from the IdP: the body, and the `max-age` it was sent with.
pub struct Answer {
    pub document: String,
    pub max_age: Option<Duration>,
}

struct State {
    /// The last good document and when it was fetched.
    document: Option<(String, i64)>,
    due: Instant,
    /// When an unknown `kid` last caused a fetch.
    kid_refresh: Option<Instant>,
    /// A fetch still running from an earlier tick.
    task: Option<JoinHandle<Result<Answer, String>>>,
}

impl State {
    fn new(now: Instant) -> Self {
        Self {
            document: None,
            due: now,
            kid_refresh: None,
            task: None,
        }
    }
}

/// Every key source the configuration names, carried across ticks by the control source.
#[derive(Default)]
pub struct KeySources {
    states: BTreeMap<Source, State>,
}

impl KeySources {
    /// Start from what the disk cache held. Each is fetched again on the first tick: the cache is
    /// what to verify with until then, not a promise that it is current.
    pub fn seed(&mut self, cached: Vec<Fetched>, now: Instant) {
        for f in cached {
            METRICS
                .jwks_last_success_timestamp_seconds
                .with_label_values(&[&f.uri])
                .set(f.fetched_at);
            let state = State {
                document: Some((f.document, f.fetched_at)),
                ..State::new(now)
            };
            self.states.insert(
                Source {
                    uri: f.uri,
                    ca_pem: f.ca_pem,
                },
                state,
            );
        }
    }

    /// The documents held, for the disk cache.
    pub fn held(&self) -> Vec<Fetched> {
        self.states
            .iter()
            .filter_map(|(source, state)| {
                let (document, fetched_at) = state.document.clone()?;
                Some(Fetched {
                    uri: source.uri.clone(),
                    ca_pem: source.ca_pem.clone(),
                    document,
                    fetched_at,
                })
            })
            .collect()
    }

    /// One tick: forget sources `config` no longer names, start a fetch for each that is due --
    /// or that an unknown `kid` asked for, at most once per `KID_MISS_GAP` -- and read every
    /// running fetch that finishes within `wait`. One that does not is read by a later tick, so an
    /// IdP that hangs holds back a configuration poll by `wait` at most. Returns whether a fetch
    /// succeeded, for the caller to rewrite its cache.
    pub async fn refresh<F, Fut>(
        &mut self,
        config: &Config,
        now: Instant,
        kid_miss: bool,
        fetch: F,
        wait: Duration,
    ) -> bool
    where
        F: Fn(Source) -> Fut,
        Fut: Future<Output = Result<Answer, String>> + Send + 'static,
    {
        let wanted = sources(config);
        let gone: Vec<String> = self
            .states
            .keys()
            .filter(|s| !wanted.contains(*s))
            .map(|s| s.uri.clone())
            .collect();
        // Dropping a running fetch's handle detaches it; it ends at its own timeout.
        self.states.retain(|s, _| wanted.contains(s));
        for uri in gone {
            // A URI no longer configured must not sit at 0 or age forever for an alert to find.
            if !self.states.keys().any(|s| s.uri == uri) {
                let _ = METRICS
                    .jwks_last_success_timestamp_seconds
                    .remove_label_values(&[&uri]);
            }
        }

        for source in wanted {
            let state = self.states.entry(source.clone()).or_insert_with(|| {
                METRICS
                    .jwks_last_success_timestamp_seconds
                    .with_label_values(&[&source.uri])
                    .set(0);
                State::new(now)
            });
            if state.task.is_some() {
                continue;
            }
            let asked = kid_miss
                && state
                    .kid_refresh
                    .is_none_or(|at| now.duration_since(at) >= KID_MISS_GAP);
            if asked {
                state.kid_refresh = Some(now);
            }
            if asked || now >= state.due {
                state.task = Some(tokio::spawn(fetch(source)));
            }
        }

        let outcomes = futures::future::join_all(self.states.iter_mut().filter_map(
            |(source, state)| {
                let task = state.task.as_mut()?;
                Some(async move {
                    let outcome = match tokio::time::timeout(wait, task).await {
                        Err(_) => None,
                        Ok(Ok(result)) => Some(result),
                        Ok(Err(e)) => Some(Err(format!("the fetch task failed: {e}"))),
                    };
                    (source.clone(), outcome)
                })
            },
        ))
        .await;

        let mut fetched = false;
        for (source, outcome) in outcomes {
            let Some(result) = outcome else {
                continue;
            };
            let state = self.states.get_mut(&source).expect("still named");
            state.task = None;
            match result.and_then(usable) {
                Ok(answer) => {
                    let at = now_secs();
                    METRICS
                        .jwks_last_success_timestamp_seconds
                        .with_label_values(&[&source.uri])
                        .set(at);
                    state.document = Some((answer.document, at));
                    state.due = now + ttl(answer.max_age);
                    fetched = true;
                }
                Err(e) => {
                    METRICS
                        .jwks_fetch_errors_total
                        .with_label_values(&[&source.uri])
                        .inc();
                    tracing::warn!(
                        uri = %source.uri,
                        error = %e,
                        loaded = state.document.is_some(),
                        "fetching a JWKS failed; keeping the keys already held, if any"
                    );
                    state.due = now + RETRY;
                }
            }
        }
        fetched
    }

    /// Write each `jwks_uri` policy's document into `config`: the last good one, or "" for a URI
    /// that has never loaded, which refuses every token.
    pub fn fill(&self, config: &mut Config) {
        for listener in &mut config.listeners {
            for rule in &mut listener.rules {
                for plugin in &mut rule.plugins {
                    let Plugin::Jwt(policy) = plugin else {
                        continue;
                    };
                    let Some(uri) = &policy.jwks_uri else {
                        continue;
                    };
                    let source = Source {
                        uri: uri.clone(),
                        ca_pem: policy.jwks_ca_pem.clone(),
                    };
                    policy.jwks = self
                        .states
                        .get(&source)
                        .and_then(|s| s.document.as_ref())
                        .map(|(document, _)| document.clone())
                        .unwrap_or_default();
                }
            }
        }
    }
}

/// Every distinct source the configuration's JWT policies name.
fn sources(config: &Config) -> BTreeSet<Source> {
    config
        .listeners
        .iter()
        .flat_map(|l| &l.rules)
        .flat_map(|r| &r.plugins)
        .filter_map(|p| match p {
            Plugin::Jwt(policy) => policy.jwks_uri.as_ref().map(|uri| Source {
                uri: uri.clone(),
                ca_pem: policy.jwks_ca_pem.clone(),
            }),
            _ => None,
        })
        .collect()
}

/// A fetched document the verifier may use: no secret, and at least one usable key. One that
/// fails is a failed fetch, and the last good document stays.
fn usable(answer: Answer) -> Result<Answer, String> {
    if gapura_core::jwt::holds_a_secret(&answer.document) {
        return Err("the document holds an oct key or a private key, which is refused".into());
    }
    gapura_core::jwt::keys(&answer.document).map_err(|e| e.to_string())?;
    Ok(answer)
}

/// `max-age` from a `Cache-Control` value; `None` when it has none that parses.
fn max_age(cache_control: Option<&str>) -> Option<Duration> {
    cache_control?.split(',').find_map(|directive| {
        let (name, value) = directive.split_once('=')?;
        if !name.trim().eq_ignore_ascii_case("max-age") {
            return None;
        }
        value
            .trim()
            .trim_matches('"')
            .parse()
            .ok()
            .map(Duration::from_secs)
    })
}

/// How long a document is used before it is fetched again.
fn ttl(max_age: Option<Duration>) -> Duration {
    max_age.unwrap_or(DEFAULT_TTL).clamp(MIN_TTL, MAX_TTL)
}

/// GET `source.uri`: https only, no redirects, verified by the bundled public roots or by
/// `source.ca_pem` alone, at most `MAX_JWKS_BYTES` read.
///
/// ponytail: a client per fetch. Fetches are at most one per source per 30 s, so building the TLS
/// configuration each time costs nothing measurable; keep one per CA if that ever changes.
pub async fn fetch(source: Source) -> Result<Answer, String> {
    use reqwest::header::{ACCEPT, CACHE_CONTROL, LOCATION};
    let mut builder = reqwest::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .https_only(true)
        // A jwks_uri is the address the IdP publishes. A redirect could lead to plain http or to
        // another host, so it is a failure that names where it pointed.
        .redirect(reqwest::redirect::Policy::none());
    if let Some(pem) = &source.ca_pem {
        // The control plane checked it parses; failing here means a row written by hand.
        let certs = reqwest::Certificate::from_pem_bundle(pem.as_bytes())
            .map_err(|e| format!("the CA does not parse: {}", chain(&e)))?;
        if certs.is_empty() {
            return Err("the CA holds no certificate".into());
        }
        builder = builder.tls_built_in_root_certs(false);
        for cert in certs {
            builder = builder.add_root_certificate(cert);
        }
    }
    let client = builder.build().map_err(|e| chain(&e))?;
    let mut res = client
        .get(&source.uri)
        .header(ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| chain(&e))?;
    if res.status() != reqwest::StatusCode::OK {
        let to = res
            .headers()
            .get(LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(|to| format!(" (to {to})"))
            .unwrap_or_default();
        return Err(format!("the IdP answered {}{to}", res.status()));
    }
    let max_age = max_age(
        res.headers()
            .get(CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
    );
    let mut body = Vec::new();
    while let Some(chunk) = res.chunk().await.map_err(|e| chain(&e))? {
        body.extend_from_slice(&chunk);
        if body.len() > MAX_JWKS_BYTES {
            return Err(format!("the document is over {} KiB", MAX_JWKS_BYTES / 1024));
        }
    }
    let document =
        String::from_utf8(body).map_err(|_| "the document is not UTF-8".to_string())?;
    Ok(Answer { document, max_age })
}

/// An error and its causes on one line. reqwest's own message is "error sending request for url";
/// the connect or certificate cause an operator needs is in its sources.
fn chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut cause = e.source();
    while let Some(c) = cause {
        out.push_str(": ");
        out.push_str(&c.to_string());
        cause = c.source();
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// RFC 7517's example P-256 public key, as `k1` and as `k2`.
    pub(crate) const TEST_JWKS: &str = r#"{"keys":[{"kty":"EC","crv":"P-256","alg":"ES256","kid":"k1","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}]}"#;
    const ROTATED: &str = r#"{"keys":[{"kty":"EC","crv":"P-256","alg":"ES256","kid":"k2","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}]}"#;

    /// A store configuration with one route per URI, each guarded by a JWT policy naming it.
    pub(crate) fn config_naming(uris: &[&str]) -> Config {
        use gapura_core::config::{JwtPolicy, PathMatch, Protocol};
        use gapura_core::store::{
            StorePlugin, StoreRoute, StoreService, StoreSettings, StoreSnapshot,
        };
        let snapshot = StoreSnapshot {
            services: vec![StoreService {
                workspace: String::new(),
                name: "echo".into(),
                protocol: Protocol::Http,
                host: "127.0.0.1".into(),
                port: 8080,
                connect_timeout_ms: None,
                read_timeout_ms: None,
                tls_verify: true,
                tls_ca_pem: None,
                tls_sni: None,
            }],
            routes: (0..uris.len())
                .map(|i| StoreRoute {
                    workspace: String::new(),
                    name: format!("r{i}"),
                    service: "echo".into(),
                    hosts: vec![],
                    paths: vec![PathMatch::Prefix(format!("/r{i}"))],
                    methods: vec![],
                    headers: vec![],
                    strip_path: false,
                    priority: 0,
                })
                .collect(),
            plugins: uris
                .iter()
                .enumerate()
                .map(|(i, uri)| StorePlugin {
                    workspace: String::new(),
                    route: Some(format!("r{i}")),
                    service: None,
                    plugin: Plugin::Jwt(JwtPolicy {
                        issuer: Some("https://idp.test".into()),
                        jwks_uri: Some(uri.to_string()),
                        ..JwtPolicy::default()
                    }),
                })
                .collect(),
            ..StoreSnapshot::default()
        };
        gapura_core::store::compile(
            &snapshot,
            &StoreSettings {
                http_ports: vec![80],
            },
        )
    }

    /// Every JWT policy's document, in rule order.
    pub(crate) fn documents(config: &Config) -> Vec<String> {
        config
            .listeners
            .iter()
            .flat_map(|l| &l.rules)
            .flat_map(|r| &r.plugins)
            .filter_map(|p| match p {
                Plugin::Jwt(policy) => Some(policy.jwks.clone()),
                _ => None,
            })
            .collect()
    }

    fn filled(keys: &KeySources, config: &Config) -> Vec<String> {
        let mut config = config.clone();
        keys.fill(&mut config);
        documents(&config)
    }

    /// A fetch that answers `result` at once and counts its calls.
    fn answering(
        calls: &Arc<AtomicUsize>,
        result: Result<&'static str, &'static str>,
    ) -> impl Fn(Source) -> std::future::Ready<Result<Answer, String>> {
        let calls = Arc::clone(calls);
        move |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            std::future::ready(
                result
                    .map(|document| Answer {
                        document: document.into(),
                        max_age: None,
                    })
                    .map_err(str::to_string),
            )
        }
    }

    const WAIT: Duration = Duration::from_secs(1);

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn max_age_is_honoured_within_its_bounds() {
        assert_eq!(max_age(None), None);
        assert_eq!(max_age(Some("no-store")), None);
        assert_eq!(max_age(Some("public, max-age=300")), Some(secs(300)));
        assert_eq!(
            max_age(Some("MAX-AGE=\"120\", must-revalidate")),
            Some(secs(120))
        );
        assert_eq!(max_age(Some("max-age=soon")), None);
        assert_eq!(
            ttl(None),
            secs(600),
            "Envoy's default when the IdP says nothing"
        );
        assert_eq!(ttl(Some(secs(0))), secs(60), "never every tick");
        assert_eq!(ttl(Some(secs(30))), secs(60));
        assert_eq!(ttl(Some(secs(300))), secs(300));
        assert_eq!(
            ttl(Some(secs(7200))),
            secs(3600),
            "a removed key stops within an hour"
        );
    }

    #[tokio::test]
    async fn a_first_fetch_fills_every_policy_naming_the_uri() {
        let uri = "https://idp.test/first";
        let config = config_naming(&[uri, uri]);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut keys = KeySources::default();
        assert!(
            keys.refresh(
                &config,
                Instant::now(),
                false,
                answering(&calls, Ok(TEST_JWKS)),
                WAIT
            )
            .await
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "one fetch per distinct URI"
        );
        assert_eq!(filled(&keys, &config), [TEST_JWKS, TEST_JWKS]);
        let held = keys.held();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].uri, uri);
        assert!(
            METRICS
                .jwks_last_success_timestamp_seconds
                .with_label_values(&[uri])
                .get()
                > 0
        );
    }

    #[tokio::test]
    async fn nothing_is_fetched_again_before_it_is_due() {
        let config = config_naming(&["https://idp.test/due"]);
        let calls = Arc::new(AtomicUsize::new(0));
        let fetch = answering(&calls, Ok(TEST_JWKS));
        let mut keys = KeySources::default();
        let t0 = Instant::now();
        keys.refresh(&config, t0, false, &fetch, WAIT).await;
        keys.refresh(&config, t0 + secs(599), false, &fetch, WAIT)
            .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        keys.refresh(&config, t0 + secs(600), false, &fetch, WAIT)
            .await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_failure_after_a_load_keeps_the_keys_and_is_counted() {
        let uri = "https://idp.test/stale";
        let config = config_naming(&[uri]);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut keys = KeySources::default();
        let t0 = Instant::now();
        keys.refresh(&config, t0, false, answering(&calls, Ok(TEST_JWKS)), WAIT)
            .await;
        let errors = || {
            METRICS
                .jwks_fetch_errors_total
                .with_label_values(&[uri])
                .get()
        };
        let before = errors();
        assert!(
            !keys
                .refresh(
                    &config,
                    t0 + secs(600),
                    false,
                    answering(&calls, Err("connect refused")),
                    WAIT
                )
                .await,
            "nothing new to cache"
        );
        assert_eq!(
            filled(&keys, &config),
            [TEST_JWKS],
            "the last good keys keep verifying"
        );
        assert_eq!(errors(), before + 1);
    }

    #[tokio::test]
    async fn a_failed_fetch_is_retried_after_30_s() {
        let config = config_naming(&["https://idp.test/retry"]);
        let calls = Arc::new(AtomicUsize::new(0));
        let fetch = answering(&calls, Err("timed out"));
        let mut keys = KeySources::default();
        let t0 = Instant::now();
        keys.refresh(&config, t0, false, &fetch, WAIT).await;
        keys.refresh(&config, t0 + secs(29), false, &fetch, WAIT)
            .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        keys.refresh(&config, t0 + secs(30), false, &fetch, WAIT)
            .await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn never_loaded_leaves_the_document_empty_and_the_policy_refuses() {
        let uri = "https://idp.test/never";
        let config = config_naming(&[uri]);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut keys = KeySources::default();
        keys.refresh(
            &config,
            Instant::now(),
            false,
            answering(&calls, Err("refused")),
            WAIT,
        )
        .await;
        let mut served = config.clone();
        keys.fill(&mut served);
        assert_eq!(documents(&served), [""]);
        assert_eq!(
            METRICS
                .jwks_last_success_timestamp_seconds
                .with_label_values(&[uri])
                .get(),
            0,
            "an alert can tell never loaded from stale"
        );
        let (compiled, unusable) = crate::proxy::jwt::compile(&served);
        assert_eq!(
            unusable, 0,
            "a pending first fetch is not misreported as bad keys"
        );
        assert!(
            !compiled.contains_key(""),
            "no keys, so the request path refuses"
        );
    }

    #[tokio::test]
    async fn a_kid_miss_refetches_at_most_once_per_30_s() {
        let config = config_naming(&["https://idp.test/kid"]);
        let calls = Arc::new(AtomicUsize::new(0));
        let fetch = answering(&calls, Ok(TEST_JWKS));
        let mut keys = KeySources::default();
        let t0 = Instant::now();
        keys.refresh(&config, t0, false, &fetch, WAIT).await;
        keys.refresh(&config, t0 + secs(1), true, &fetch, WAIT)
            .await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "a key rotated just after a fetch is looked for"
        );
        keys.refresh(&config, t0 + secs(5), true, &fetch, WAIT)
            .await;
        assert_eq!(calls.load(Ordering::SeqCst), 2, "but not again within 30 s");
        keys.refresh(&config, t0 + secs(31), true, &fetch, WAIT)
            .await;
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn a_rotated_document_replaces_the_old_one() {
        let config = config_naming(&["https://idp.test/rotate"]);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut keys = KeySources::default();
        let t0 = Instant::now();
        keys.refresh(&config, t0, false, answering(&calls, Ok(TEST_JWKS)), WAIT)
            .await;
        keys.refresh(
            &config,
            t0 + secs(1),
            true,
            answering(&calls, Ok(ROTATED)),
            WAIT,
        )
        .await;
        assert_eq!(filled(&keys, &config), [ROTATED]);
    }

    #[tokio::test]
    async fn a_document_holding_a_secret_is_a_failed_fetch() {
        let config = config_naming(&["https://idp.test/secret"]);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut keys = KeySources::default();
        let oct = r#"{"keys":[{"kty":"oct","alg":"HS256","kid":"s","k":"c2VjcmV0"}]}"#;
        assert!(
            !keys
                .refresh(
                    &config,
                    Instant::now(),
                    false,
                    answering(&calls, Ok(oct)),
                    WAIT
                )
                .await
        );
        assert_eq!(filled(&keys, &config), [""]);
    }

    #[tokio::test]
    async fn a_document_with_no_usable_key_is_a_failed_fetch() {
        let config = config_naming(&["https://idp.test/unusable"]);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut keys = KeySources::default();
        let t0 = Instant::now();
        keys.refresh(&config, t0, false, answering(&calls, Ok(TEST_JWKS)), WAIT)
            .await;
        keys.refresh(
            &config,
            t0 + secs(600),
            false,
            answering(&calls, Ok(r#"{"keys":[]}"#)),
            WAIT,
        )
        .await;
        assert_eq!(
            filled(&keys, &config),
            [TEST_JWKS],
            "an emptied key set is not a rotation"
        );
    }

    #[tokio::test]
    async fn a_slow_fetch_is_read_on_a_later_tick_not_started_again() {
        let config = config_naming(&["https://idp.test/slow"]);
        let mut keys = KeySources::default();
        let slow = |_: Source| async {
            tokio::time::sleep(Duration::from_millis(200)).await;
            Ok::<_, String>(Answer {
                document: TEST_JWKS.into(),
                max_age: None,
            })
        };
        let t0 = Instant::now();
        assert!(
            !keys
                .refresh(&config, t0, false, slow, Duration::from_millis(10))
                .await
        );
        assert_eq!(filled(&keys, &config), [""]);
        let calls = Arc::new(AtomicUsize::new(0));
        assert!(
            keys.refresh(
                &config,
                t0 + secs(1),
                false,
                answering(&calls, Err("x")),
                WAIT
            )
            .await
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "the running fetch was waited for"
        );
        assert_eq!(filled(&keys, &config), [TEST_JWKS]);
    }

    #[tokio::test]
    async fn a_uri_no_longer_named_is_forgotten() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut keys = KeySources::default();
        let t0 = Instant::now();
        keys.refresh(
            &config_naming(&["https://idp.test/gone"]),
            t0,
            false,
            answering(&calls, Ok(TEST_JWKS)),
            WAIT,
        )
        .await;
        keys.refresh(
            &config_naming(&[]),
            t0 + secs(1),
            false,
            answering(&calls, Ok(TEST_JWKS)),
            WAIT,
        )
        .await;
        assert!(
            keys.held().is_empty(),
            "the disk cache keeps only what is named"
        );
    }

    #[test]
    fn a_seeded_document_is_served_and_dated() {
        let uri = "https://idp.test/seeded";
        let mut keys = KeySources::default();
        keys.seed(
            vec![Fetched {
                uri: uri.into(),
                ca_pem: None,
                document: TEST_JWKS.into(),
                fetched_at: 7,
            }],
            Instant::now(),
        );
        assert_eq!(filled(&keys, &config_naming(&[uri])), [TEST_JWKS]);
        assert_eq!(
            METRICS
                .jwks_last_success_timestamp_seconds
                .with_label_values(&[uri])
                .get(),
            7
        );
    }
}
