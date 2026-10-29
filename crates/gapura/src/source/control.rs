//! Configuration from `gapura-control`, which owns it and hands it out only when asked.
//!
//! The data plane calls carrying the version it holds and the features it reads, and gets
//! "nothing has changed", the configuration that replaces it, or a refusal naming what it lacks
//! to read that configuration. The call is also the liveness signal: there is no second
//! heartbeat reporting a fact this one already carries.

use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use gapura_core::config::{Config, Endpoint};
use serde::{Deserialize, Serialize};

use async_trait::async_trait;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;

use crate::source::jwks::{self, KeySources};
use crate::store::Store;

/// This build's version as the release stamps it, the tag it is published under, else the
/// crate's, which every prerelease of one version shares. Said to the control plane on each
/// poll for the console to show; it decides nothing.
///
/// Empty counts as unset: the Dockerfile declares the ARG for every build, release or not.
const VERSION: &str = match option_env!("GAPURA_VERSION") {
    Some(v) if !v.is_empty() => v,
    _ => env!("CARGO_PKG_VERSION"),
};

/// What one poll learned.
enum Polled {
    /// The version held is the one served.
    Unchanged,
    /// A new version, and the configuration it is.
    Changed(String, Config),
    /// The control plane will not send what it serves now: this build lacks these features.
    Incompatible(Vec<String>),
}

/// What the cache file holds. The version and the configuration together in one file, because
/// two files can disagree with each other and one cannot.
#[derive(Serialize, Deserialize)]
struct Cached {
    version: String,
    config: Config,
    /// The last good document of each `jwks_uri` the configuration names, so a restart with the
    /// IdP down still verifies. Beside `config` rather than in it: `config` stays what the
    /// control plane sent. Absent from a cache written before `jwks_uri`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    jwks: Vec<jwks::Fetched>,
}

pub struct ControlSource {
    pub url: String,
    pub token: String,
    /// PEM bundle to trust for the control plane's certificate, on top of the public roots. An
    /// in-cluster control plane almost always presents a certificate from a private CA.
    pub ca_pem: Option<Vec<u8>>,
    pub cache_path: Option<PathBuf>,
    pub interval: Duration,
    pub store: Arc<Store>,
}

impl ControlSource {
    /// Read the cache and start serving from it, before the control plane has been reached.
    ///
    /// This is the whole reason the cache exists. Without it a control plane that is down at
    /// startup means `/readyz` never passes, the pod never joins its Service, and a gateway
    /// holding a perfectly good configuration on disk refuses to serve with it. Readiness here
    /// means "I can route", not "I have spoken to the control plane".
    ///
    /// A cache that will not parse is logged and ignored rather than fatal: a damaged file
    /// should not take a gateway down harder than never having had one.
    ///
    /// Returns the cached version *and* the cached configuration, unresolved. The configuration
    /// matters as much as the version: `run` re-resolves backends from it on every tick, and a
    /// start whose first poll is a 304 receives no configuration to resolve from otherwise --
    /// that start used to keep whatever one resolution at boot produced, forever.
    ///
    /// `in_flight` is the set `run` carries across its ticks, so a lookup that outlives this
    /// first resolution is waited for by the next one rather than started a second time.
    ///
    /// Each `jwks_uri` policy is filled with the document the cache kept for it, and `keys` is
    /// seeded with them, so the first tick refetches them rather than starting from nothing.
    pub async fn prime(
        &self,
        in_flight: &mut InFlight,
        keys: &mut KeySources,
    ) -> Option<(String, Config)> {
        let path = self.cache_path.as_ref()?;
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
            Err(e) => {
                tracing::warn!(error = %e, path = %path.display(), "reading the configuration cache");
                return None;
            }
        };
        match serde_json::from_slice::<Cached>(&bytes) {
            Ok(cached) => {
                keys.seed(cached.jwks, Instant::now());
                let served = self.store.load().config.clone();
                let mut config = resolve(
                    cached.config.clone(),
                    &served,
                    lookup,
                    LOOKUP_TIMEOUT,
                    in_flight,
                )
                .await;
                keys.fill(&mut config);
                self.store.swap_from_cache(config);
                tracing::info!(
                    version = %cached.version,
                    "serving a configuration from the cache while the control plane is unconfirmed"
                );
                Some((cached.version, cached.config))
            }
            Err(e) => {
                tracing::warn!(error = %e, path = %path.display(), "the configuration cache is unreadable and is being ignored");
                None
            }
        }
    }

    /// Written only after a configuration has been swapped in, never before. A cache written
    /// first is a cache that can hold something this binary could not actually use -- and the
    /// next start would load it, fail the same way, and have nothing older to fall back to.
    fn write_cache(&self, version: &str, config: &Config, jwks: Vec<jwks::Fetched>) {
        let Some(path) = &self.cache_path else { return };
        if let Err(e) = write_atomic(
            path,
            &Cached {
                version: version.to_string(),
                config: config.clone(),
                jwks,
            },
        ) {
            // A cache that cannot be written costs resilience at the next start, not traffic now.
            tracing::warn!(error = %e, path = %path.display(), "writing the configuration cache");
        }
    }

    /// One poll. `held` is the version we have, if any. Each poll names the features this build
    /// reads, so the control plane refuses one it could not use rather than send it.
    async fn poll(&self, client: &reqwest::Client, held: Option<&str>) -> anyhow::Result<Polled> {
        let mut req = client
            .get(format!("{}/v1/config", self.url.trim_end_matches('/')))
            .bearer_auth(&self.token)
            .header(
                "x-gapura-features",
                gapura_core::features::FEATURES.join(","),
            );
        if let Some(v) = held {
            req = req.header(reqwest::header::IF_NONE_MATCH, v);
        }
        let res = req.send().await?;
        if res.status() == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(Polled::Unchanged);
        }
        if res.status() == reqwest::StatusCode::CONFLICT {
            #[derive(Deserialize)]
            struct Refusal {
                missing: Vec<String>,
            }
            return Ok(Polled::Incompatible(res.json::<Refusal>().await?.missing));
        }
        if !res.status().is_success() {
            anyhow::bail!("the control plane answered {}", res.status());
        }
        let version = res
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        Ok(Polled::Changed(version, res.json().await?))
    }

    async fn run(&self, mut shutdown: ShutdownWatch) {
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent(format!("gapura/{}", VERSION.trim_start_matches('v')));
        if let Some(pem) = &self.ca_pem {
            match reqwest::Certificate::from_pem_bundle(pem) {
                Ok(certs) => {
                    for c in certs {
                        builder = builder.add_root_certificate(c);
                    }
                }
                // main.rs read the file and checked it parses before starting; reaching here
                // means it changed shape between the two, which is not worth a second policy.
                Err(e) => tracing::error!(error = %e, "the control plane CA bundle does not parse"),
            }
        }
        let client = builder.build().expect("a reqwest client");
        let mut in_flight = InFlight::new();
        let mut keys = KeySources::default();
        let (mut held, mut latest) = match self.prime(&mut in_flight, &mut keys).await {
            Some((version, config)) => (Some(version), Some(config)),
            None => (None, None),
        };

        let mut refused: Vec<String> = Vec::new();
        loop {
            let mut changed = false;
            match self.poll(&client, held.as_deref()).await {
                Ok(Polled::Changed(version, config)) => {
                    tracing::info!(version = %version, "new configuration");
                    held = Some(version);
                    latest = Some(config);
                    changed = true;
                    crate::telemetry::METRICS.config_incompatible.set(0);
                    refused.clear();
                }
                // The control plane just confirmed the version we hold: whatever we serve is no
                // longer an unconfirmed cache, and the gauge that says "running blind" must stop
                // saying it. `swap` would clear it too, but a 304 on a quiet cluster never swaps.
                Ok(Polled::Unchanged) => {
                    crate::telemetry::METRICS.config_from_cache.set(0);
                    crate::telemetry::METRICS.config_incompatible.set(0);
                    refused.clear();
                }
                // Kept serving, as after any failed poll. Said once per change of what is
                // missing rather than every poll: it lasts until this data plane is upgraded.
                Ok(Polled::Incompatible(missing)) => {
                    crate::telemetry::METRICS.config_incompatible.set(1);
                    if missing != refused {
                        tracing::warn!(
                            missing = %missing.join(","),
                            "the control plane serves a configuration this build cannot read; \
                             serving the last one until this data plane is upgraded"
                        );
                        refused = missing;
                    }
                }
                Err(e) => {
                    // Keep serving. The cache is here precisely so that losing the
                    // control plane costs new configuration and not traffic.
                    tracing::warn!(error = %e, "asking the control plane for configuration");
                }
            }

            // Every tick, not only when the configuration changed: a backend's addresses move
            // when pods do, which has nothing to do with the version. Swapped only when the
            // result differs, so a quiet cluster does not churn the runtime.
            if let Some(config) = &latest {
                let fetched = keys
                    .refresh(
                        config,
                        Instant::now(),
                        self.store.take_jwks_refresh(),
                        jwks::fetch,
                        LOOKUP_TIMEOUT,
                    )
                    .await;
                // Cached before resolution, so the file holds what the control plane sent rather
                // than one data plane's view of DNS at one moment; after the keys, so it holds the
                // documents this configuration's URIs last gave.
                if changed || fetched {
                    self.write_cache(held.as_deref().unwrap_or_default(), config, keys.held());
                }
                let served = self.store.load().config.clone();
                let mut resolved = resolve(
                    config.clone(),
                    &served,
                    lookup,
                    LOOKUP_TIMEOUT,
                    &mut in_flight,
                )
                .await;
                keys.fill(&mut resolved);
                if served != resolved {
                    self.store.swap(resolved, Vec::new());
                }
            }

            tokio::select! {
                _ = tokio::time::sleep(self.interval) => {}
                _ = shutdown.changed() => return,
            }
        }
    }
}

/// How long one backend name may take to resolve before it counts as a resolver error.
///
/// Resolution runs on the same tick as the configuration poll, so a name whose authoritative DNS
/// stops answering would otherwise hold back every poll behind it -- and with them a revoked key
/// or a removed route -- for as long as glibc's retries take, which `ndots:5` and a search list
/// multiply into tens of seconds. A few seconds is far longer than a healthy in-cluster or
/// upstream lookup needs, and short beside the default poll interval.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(3);

/// Lookups that outlived their tick's timeout and are still running, by `host:port`.
///
/// A timeout drops the future, not the lookup (#251): `tokio::net::lookup_host` runs
/// `getaddrinfo` on the blocking pool, and that call runs on to glibc's own limit -- tens of
/// seconds with `ndots:5` and a search list -- whatever happens to the future. With every name
/// looked up on every tick, a black-holed DNS server then started one more blocking call per
/// name per tick, each outliving several ticks, until the pool reached its thread cap and its
/// queue grew for as long as the outage lasted. So each lookup runs as its own task, a tick that
/// gives up on one keeps its handle here, and the next tick waits on that handle instead of
/// starting another. That bounds the blocking calls at one per distinct name, whatever the
/// outage costs, which is what the configuration already asks for on a healthy tick. A semaphore
/// would bound them too, but it would still let names queue behind the ones that hang, and it
/// adds a number to choose; this needs none.
pub type InFlight = HashMap<String, tokio::task::JoinHandle<std::io::Result<Vec<SocketAddr>>>>;

/// Fill in `Cluster::endpoints` for every cluster that names a host instead.
///
/// Only the data plane can do this. Data planes in another network are deliberately supported,
/// where a name answers differently or not at all, so the control plane sends the name and each
/// data plane asks its own resolver. A name that resolves to nothing leaves the cluster empty,
/// which is 503 -- the same answer as a backend with no ready addresses, and correct for the
/// same reason: there is nowhere to send the request.
///
/// A resolver *error* is different, and keeps the addresses `served` holds for that cluster.
/// `config` cannot supply them: it is the control plane's configuration, whose resolve clusters
/// are always empty by construction, so leaving them alone on error -- what this used to do --
/// swapped in an empty cluster and turned a CoreDNS restart into a 503 for every such backend.
/// A lookup that outlasts `timeout` is a resolver error too; it is left running in `in_flight`
/// and its answer, when it comes, is the one a later tick uses.
///
/// Every name is looked up at once, so one name that hangs costs a tick at most `timeout`,
/// not `timeout` for each name behind it. Clusters naming the same `host:port` share a lookup.
async fn resolve<F, Fut>(
    mut config: Config,
    served: &Config,
    lookup: F,
    timeout: Duration,
    in_flight: &mut InFlight,
) -> Config
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<Vec<SocketAddr>>> + Send + 'static,
{
    let targets: BTreeSet<String> = config
        .clusters
        .values()
        .filter_map(|c| c.resolve.as_ref())
        .map(|t| format!("{}:{}", t.host, t.port))
        .collect();
    // What is left in `previous` afterwards is for names no longer configured. Dropping those
    // handles detaches their tasks, which end with their blocking calls.
    let mut previous = std::mem::take(in_flight);
    let lookups = targets.into_iter().map(|target| {
        let mut handle = previous
            .remove(&target)
            .unwrap_or_else(|| tokio::spawn(lookup(target.clone())));
        async move {
            let outcome = tokio::time::timeout(timeout, &mut handle).await;
            (target, handle, outcome)
        }
    });
    let mut answers = HashMap::new();
    for (target, handle, outcome) in futures::future::join_all(lookups).await {
        let answer = match outcome {
            Ok(Ok(result)) => result.map_err(|e| e.to_string()),
            Ok(Err(e)) => Err(format!("the lookup task failed: {e}")),
            Err(_) => {
                in_flight.insert(target.clone(), handle);
                Err(format!("no answer within {timeout:?}"))
            }
        };
        answers.insert(target, answer);
    }

    for (key, cluster) in config.clusters.iter_mut() {
        let Some(target) = &cluster.resolve else {
            continue;
        };
        let Some(answer) = answers.get(&format!("{}:{}", target.host, target.port)) else {
            continue;
        };
        match answer {
            Ok(addrs) => {
                let mut endpoints: Vec<Endpoint> = addrs
                    .iter()
                    .map(|a| Endpoint {
                        address: a.ip().to_string(),
                        port: a.port(),
                    })
                    .collect();
                endpoints.sort();
                endpoints.dedup();
                if endpoints.is_empty() {
                    tracing::warn!(cluster = %key, host = %target.host, "resolved to no addresses");
                }
                cluster.endpoints = endpoints;
            }
            Err(e) => {
                let kept = served
                    .clusters
                    .get(key)
                    .filter(|c| c.resolve == cluster.resolve)
                    .map(|c| c.endpoints.clone())
                    .unwrap_or_default();
                tracing::warn!(
                    cluster = %key,
                    host = %target.host,
                    error = %e,
                    kept = kept.len(),
                    "resolving a backend failed; keeping the addresses already served"
                );
                cluster.endpoints = kept;
            }
        }
    }
    config
}

/// The system resolver, for `resolve`. A function rather than a closure at each call site so
/// the tests can hand `resolve` a resolver that fails on demand.
async fn lookup(target: String) -> std::io::Result<Vec<SocketAddr>> {
    Ok(tokio::net::lookup_host(target).await?.collect())
}

fn write_atomic(path: &Path, cached: &Cached) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir)?;
    let tmp = path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        // The file holds a private key for every certificate the gateway serves. admin.rs
        // refuses to show key material even on the admin port; a world-readable file here would
        // undo that with a permission.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        f.write_all(&serde_json::to_vec(cached)?)?;
        f.sync_all()?;
    }
    // Atomic within a directory, so a crash leaves either the old file or the new one and never
    // half of one -- which would arrive precisely when the control plane is unreachable.
    std::fs::rename(&tmp, path)
}

#[async_trait]
impl BackgroundService for ControlSource {
    async fn start(&self, shutdown: ShutdownWatch) {
        self.run(shutdown).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(dir: &std::path::Path) -> ControlSource {
        ControlSource {
            url: "http://unused".into(),
            token: "unused".into(),
            ca_pem: None,
            cache_path: Some(dir.join("cache.json")),
            interval: Duration::from_secs(1),
            store: Arc::new(Store::empty()),
        }
    }

    fn tempdir() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("gapura-cache-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[tokio::test]
    async fn a_cache_written_is_a_cache_that_serves() {
        let dir = tempdir();
        let s = source(&dir);
        assert!(!s.store.is_ready(), "nothing to serve yet");

        s.write_cache("\"7\"", &Config::default(), Vec::new());
        assert_eq!(
            s.prime(&mut InFlight::new(), &mut KeySources::default())
                .await
                .map(|(v, _)| v)
                .as_deref(),
            Some("\"7\"")
        );
        assert!(
            s.store.is_ready(),
            "priming from cache must make the gateway ready, or the pod never joins its Service"
        );
    }

    /// A damaged cache must not take a gateway down harder than never having had one.
    #[tokio::test]
    async fn a_truncated_cache_is_ignored_rather_than_fatal() {
        let dir = tempdir();
        let s = source(&dir);
        s.write_cache("\"7\"", &Config::default(), Vec::new());
        let path = s.cache_path.clone().unwrap();
        let half = std::fs::read(&path).unwrap();
        std::fs::write(&path, &half[..half.len() / 2]).unwrap();

        assert_eq!(
            s.prime(&mut InFlight::new(), &mut KeySources::default())
                .await,
            None
        );
        assert!(
            !s.store.is_ready(),
            "and it starts unready, not serving nothing as if it were something"
        );
    }

    #[tokio::test]
    async fn a_missing_cache_is_not_an_error() {
        let dir = tempdir();
        assert_eq!(
            source(&dir)
                .prime(&mut InFlight::new(), &mut KeySources::default())
                .await,
            None
        );
    }

    /// The file holds a private key for every certificate the gateway serves.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_cache_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir();
        let s = source(&dir);
        s.write_cache("\"1\"", &Config::default(), Vec::new());
        let mode = std::fs::metadata(s.cache_path.as_ref().unwrap())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o077,
            0,
            "group and other must have nothing, got {mode:o}"
        );
    }

    /// The rename is what makes a crash mid-write survivable. A leftover temp file from a crash
    /// that never got to the rename must leave the previous cache loadable.
    #[tokio::test]
    async fn a_leftover_temp_file_does_not_disturb_the_good_one() {
        let dir = tempdir();
        let s = source(&dir);
        s.write_cache("\"7\"", &Config::default(), Vec::new());
        std::fs::write(dir.join("cache.tmp"), b"{ half a docum").unwrap();
        assert_eq!(
            s.prime(&mut InFlight::new(), &mut KeySources::default())
                .await
                .map(|(v, _)| v)
                .as_deref(),
            Some("\"7\"")
        );
    }

    #[tokio::test]
    async fn the_cache_keeps_fetched_keys_and_a_restart_verifies_with_them() {
        use crate::source::jwks::tests::{config_naming, documents, TEST_JWKS};
        let dir = tempdir();
        let s = source(&dir);
        let uri = "https://idp.test/cached";
        let fetched = jwks::Fetched {
            uri: uri.into(),
            ca_pem: None,
            document: TEST_JWKS.into(),
            fetched_at: 7,
        };
        s.write_cache("\"7\"", &config_naming(&[uri]), vec![fetched.clone()]);
        let mut keys = KeySources::default();
        assert!(s.prime(&mut InFlight::new(), &mut keys).await.is_some());
        assert_eq!(
            documents(&s.store.load().config),
            [TEST_JWKS],
            "verifying with the cached keys before the IdP has been asked"
        );
        assert_eq!(keys.held(), [fetched]);
    }

    #[tokio::test]
    async fn a_cache_written_before_jwks_uri_still_serves() {
        let dir = tempdir();
        let s = source(&dir);
        let old = serde_json::json!({"version": "\"7\"", "config": Config::default()});
        std::fs::write(dir.join("cache.json"), serde_json::to_vec(&old).unwrap()).unwrap();
        let mut keys = KeySources::default();
        assert_eq!(
            s.prime(&mut InFlight::new(), &mut keys)
                .await
                .map(|(v, _)| v)
                .as_deref(),
            Some("\"7\"")
        );
        assert!(keys.held().is_empty());
    }

    fn resolve_config(host: &str, endpoints: Vec<Endpoint>) -> Config {
        use gapura_core::config::{Cluster, ResolveTarget};
        let mut c = Config::default();
        c.clusters.insert(
            "store/orders".into(),
            Cluster {
                endpoints,
                tls: None,
                resolve: Some(ResolveTarget {
                    host: host.into(),
                    port: 8080,
                }),
                outlier: None,
            },
        );
        c
    }

    fn ep(address: &str) -> Endpoint {
        Endpoint {
            address: address.into(),
            port: 8080,
        }
    }

    async fn resolves_to(
        _: String,
        addrs: &'static [&'static str],
    ) -> std::io::Result<Vec<std::net::SocketAddr>> {
        Ok(addrs
            .iter()
            .map(|a| format!("{a}:8080").parse().unwrap())
            .collect())
    }

    async fn resolver_down(_: String) -> std::io::Result<Vec<std::net::SocketAddr>> {
        Err(std::io::Error::other("SERVFAIL"))
    }

    #[tokio::test]
    async fn a_successful_resolution_replaces_the_addresses() {
        let from_control_plane = resolve_config("orders.apps", vec![]);
        let served = resolve_config("orders.apps", vec![ep("10.0.0.1")]);
        let got = resolve(
            from_control_plane,
            &served,
            |t| resolves_to(t, &["10.0.0.9"]),
            LOOKUP_TIMEOUT,
            &mut InFlight::new(),
        )
        .await;
        assert_eq!(got.clusters["store/orders"].endpoints, vec![ep("10.0.0.9")]);
    }

    #[tokio::test]
    async fn a_resolver_error_keeps_the_addresses_already_served() {
        // The control plane's config always carries empty endpoints for a resolve cluster, so
        // "leave them alone" on error is not enough: it would swap in an empty cluster and turn
        // a resolver hiccup into a 503 for every request to this backend.
        let from_control_plane = resolve_config("orders.apps", vec![]);
        let served = resolve_config("orders.apps", vec![ep("10.0.0.5")]);
        let got = resolve(
            from_control_plane,
            &served,
            resolver_down,
            LOOKUP_TIMEOUT,
            &mut InFlight::new(),
        )
        .await;
        assert_eq!(got.clusters["store/orders"].endpoints, vec![ep("10.0.0.5")]);
    }

    #[tokio::test]
    async fn a_resolver_error_does_not_borrow_addresses_from_a_different_target() {
        // Same cluster key, but the service now points somewhere else: the old addresses
        // belong to the old host and must not be sent the new host's traffic.
        let from_control_plane = resolve_config("orders-v2.apps", vec![]);
        let served = resolve_config("orders.apps", vec![ep("10.0.0.5")]);
        let got = resolve(
            from_control_plane,
            &served,
            resolver_down,
            LOOKUP_TIMEOUT,
            &mut InFlight::new(),
        )
        .await;
        assert!(got.clusters["store/orders"].endpoints.is_empty());
    }

    async fn resolver_hangs(_: String) -> std::io::Result<Vec<std::net::SocketAddr>> {
        std::future::pending().await
    }

    #[tokio::test]
    async fn a_lookup_that_never_answers_is_a_resolver_error() {
        // An authoritative server that stops answering must cost one tick a bounded wait, and
        // the backend its addresses already served, not hold every later poll behind it.
        let from_control_plane = resolve_config("orders.apps", vec![]);
        let served = resolve_config("orders.apps", vec![ep("10.0.0.5")]);
        let got = tokio::time::timeout(
            Duration::from_secs(10),
            resolve(
                from_control_plane,
                &served,
                resolver_hangs,
                Duration::from_millis(50),
                &mut InFlight::new(),
            ),
        )
        .await
        .expect("resolve must give up on a lookup that never answers");
        assert_eq!(got.clusters["store/orders"].endpoints, vec![ep("10.0.0.5")]);
    }

    #[tokio::test]
    async fn clusters_are_looked_up_at_once_not_one_after_another() {
        use gapura_core::config::{Cluster, ResolveTarget};
        // Each lookup answers only once every lookup has started. Run one after another, the
        // first would wait for the second forever and every cluster would time out instead.
        let mut config = Config::default();
        for name in ["a", "b", "c"] {
            config.clusters.insert(
                format!("store/{name}"),
                Cluster {
                    endpoints: vec![],
                    tls: None,
                    resolve: Some(ResolveTarget {
                        host: format!("{name}.apps"),
                        port: 8080,
                    }),
                    outlier: None,
                },
            );
        }
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let got = resolve(
            config,
            &Config::default(),
            |t| {
                let barrier = barrier.clone();
                async move {
                    barrier.wait().await;
                    resolves_to(t, &["10.0.0.9"]).await
                }
            },
            Duration::from_secs(5),
            &mut InFlight::new(),
        )
        .await;
        for name in ["a", "b", "c"] {
            assert_eq!(
                got.clusters[&format!("store/{name}")].endpoints,
                vec![ep("10.0.0.9")],
                "{name}"
            );
        }
    }

    #[tokio::test]
    async fn priming_hands_back_the_configuration_not_only_its_version() {
        // `run` needs the configuration to re-resolve from on every tick; a start whose first
        // poll is a 304 gets nothing else to resolve from.
        let dir = tempdir();
        let s = source(&dir);
        let cached = resolve_config("orders.apps", vec![]);
        s.write_cache("\"3\"", &cached, Vec::new());
        let (version, config) = s
            .prime(&mut InFlight::new(), &mut KeySources::default())
            .await
            .expect("primed");
        assert_eq!(version, "\"3\"");
        assert_eq!(
            config, cached,
            "unresolved, exactly as the control plane sent it"
        );
    }

    #[tokio::test]
    async fn a_lookup_still_running_is_waited_for_not_started_again() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        // #251: a timeout drops the future, but `getaddrinfo` keeps its blocking thread. Started
        // afresh on every tick, a black-holed resolver piled up one more per name per tick.
        let started = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let slow = |t: String| {
            started.fetch_add(1, Ordering::SeqCst);
            let gate = gate.clone();
            async move {
                // Each answer takes a permit for good, so every lookup waits for its own.
                gate.acquire().await.unwrap().forget();
                resolves_to(t, &["10.0.0.9"]).await
            }
        };
        // Two clusters naming one host share a lookup.
        let mut from_control_plane = resolve_config("orders.apps", vec![]);
        let twin = from_control_plane.clusters["store/orders"].clone();
        from_control_plane
            .clusters
            .insert("store/orders-twin".into(), twin);
        let mut served = resolve_config("orders.apps", vec![ep("10.0.0.5")]);
        let twin = served.clusters["store/orders"].clone();
        served.clusters.insert("store/orders-twin".into(), twin);
        let tick = Duration::from_millis(50);
        let mut in_flight = InFlight::new();

        for _ in 0..3 {
            let got = resolve(
                from_control_plane.clone(),
                &served,
                &slow,
                tick,
                &mut in_flight,
            )
            .await;
            assert_eq!(got.clusters["store/orders"].endpoints, vec![ep("10.0.0.5")]);
            assert_eq!(
                got.clusters["store/orders-twin"].endpoints,
                vec![ep("10.0.0.5")]
            );
        }
        assert_eq!(
            started.load(Ordering::SeqCst),
            1,
            "one lookup, however many ticks it outlives"
        );
        assert_eq!(in_flight.len(), 1);

        // The answer that finally comes is the one the next tick uses.
        gate.add_permits(1);
        let got = resolve(
            from_control_plane.clone(),
            &served,
            &slow,
            tick,
            &mut in_flight,
        )
        .await;
        assert_eq!(got.clusters["store/orders"].endpoints, vec![ep("10.0.0.9")]);
        assert_eq!(
            got.clusters["store/orders-twin"].endpoints,
            vec![ep("10.0.0.9")]
        );
        assert_eq!(started.load(Ordering::SeqCst), 1);
        assert!(in_flight.is_empty());

        // Once it has answered, the next tick asks again.
        resolve(
            from_control_plane.clone(),
            &served,
            &slow,
            tick,
            &mut in_flight,
        )
        .await;
        assert_eq!(started.load(Ordering::SeqCst), 2);
        assert_eq!(in_flight.len(), 1);

        // A name no longer configured is not held on to.
        resolve(Config::default(), &served, &slow, tick, &mut in_flight).await;
        assert!(in_flight.is_empty());
    }
}
