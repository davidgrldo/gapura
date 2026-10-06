//! Configuration from `gapura-control`, which owns it and hands it out only when asked.
//!
//! The data plane calls carrying the version it holds and gets either "nothing has changed" or
//! the configuration that replaces it. The call is also the liveness signal: there is no second
//! heartbeat reporting a fact this one already carries.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use gapura_core::config::{Config, Endpoint};
use serde::{Deserialize, Serialize};

use async_trait::async_trait;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;

use crate::store::Store;

/// What the cache file holds. The version and the configuration together in one file, because
/// two files can disagree with each other and one cannot.
#[derive(Serialize, Deserialize)]
struct Cached {
    version: String,
    config: Config,
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
    pub async fn prime(&self) -> Option<(String, Config)> {
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
                let served = self.store.load().config.clone();
                let config = resolve(cached.config.clone(), &served, lookup).await;
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
    fn write_cache(&self, version: &str, config: &Config) {
        let Some(path) = &self.cache_path else { return };
        if let Err(e) = write_atomic(
            path,
            &Cached {
                version: version.to_string(),
                config: config.clone(),
            },
        ) {
            // A cache that cannot be written costs resilience at the next start, not traffic now.
            tracing::warn!(error = %e, path = %path.display(), "writing the configuration cache");
        }
    }

    /// One poll. `held` is the version we have, if any.
    async fn poll(
        &self,
        client: &reqwest::Client,
        held: Option<&str>,
    ) -> anyhow::Result<Option<(String, Config)>> {
        let mut req = client
            .get(format!("{}/v1/config", self.url.trim_end_matches('/')))
            .bearer_auth(&self.token);
        if let Some(v) = held {
            req = req.header(reqwest::header::IF_NONE_MATCH, v);
        }
        let res = req.send().await?;
        if res.status() == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(None);
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
        Ok(Some((version, res.json().await?)))
    }

    async fn run(&self, mut shutdown: ShutdownWatch) {
        let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(15));
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
        let (mut held, mut latest) = match self.prime().await {
            Some((version, config)) => (Some(version), Some(config)),
            None => (None, None),
        };

        loop {
            match self.poll(&client, held.as_deref()).await {
                Ok(Some((version, config))) => {
                    tracing::info!(version = %version, "new configuration");
                    held = Some(version.clone());
                    latest = Some(config);
                    // Cached before resolution, so the file holds what the control plane sent
                    // rather than one data plane's view of DNS at one moment.
                    if let Some(c) = &latest {
                        self.write_cache(&version, c);
                    }
                }
                // The control plane just confirmed the version we hold: whatever we serve is no
                // longer an unconfirmed cache, and the gauge that says "running blind" must stop
                // saying it. `swap` would clear it too, but a 304 on a quiet cluster never swaps.
                Ok(None) => crate::telemetry::METRICS.config_from_cache.set(0),
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
                let served = self.store.load().config.clone();
                let resolved = resolve(config.clone(), &served, lookup).await;
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
async fn resolve<F, Fut>(mut config: Config, served: &Config, lookup: F) -> Config
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = std::io::Result<Vec<std::net::SocketAddr>>>,
{
    for (key, cluster) in config.clusters.iter_mut() {
        let Some(target) = cluster.resolve.clone() else {
            continue;
        };
        match lookup(format!("{}:{}", target.host, target.port)).await {
            Ok(addrs) => {
                let mut endpoints: Vec<Endpoint> = addrs
                    .into_iter()
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
async fn lookup(target: String) -> std::io::Result<Vec<std::net::SocketAddr>> {
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

        s.write_cache("\"7\"", &Config::default());
        assert_eq!(s.prime().await.map(|(v, _)| v).as_deref(), Some("\"7\""));
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
        s.write_cache("\"7\"", &Config::default());
        let path = s.cache_path.clone().unwrap();
        let half = std::fs::read(&path).unwrap();
        std::fs::write(&path, &half[..half.len() / 2]).unwrap();

        assert_eq!(s.prime().await, None);
        assert!(
            !s.store.is_ready(),
            "and it starts unready, not serving nothing as if it were something"
        );
    }

    #[tokio::test]
    async fn a_missing_cache_is_not_an_error() {
        let dir = tempdir();
        assert_eq!(source(&dir).prime().await, None);
    }

    /// The file holds a private key for every certificate the gateway serves.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_cache_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir();
        let s = source(&dir);
        s.write_cache("\"1\"", &Config::default());
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
        s.write_cache("\"7\"", &Config::default());
        std::fs::write(dir.join("cache.tmp"), b"{ half a docum").unwrap();
        assert_eq!(s.prime().await.map(|(v, _)| v).as_deref(), Some("\"7\""));
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
        let got = resolve(from_control_plane, &served, |t| {
            resolves_to(t, &["10.0.0.9"])
        })
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
        let got = resolve(from_control_plane, &served, resolver_down).await;
        assert_eq!(got.clusters["store/orders"].endpoints, vec![ep("10.0.0.5")]);
    }

    #[tokio::test]
    async fn a_resolver_error_does_not_borrow_addresses_from_a_different_target() {
        // Same cluster key, but the service now points somewhere else: the old addresses
        // belong to the old host and must not be sent the new host's traffic.
        let from_control_plane = resolve_config("orders-v2.apps", vec![]);
        let served = resolve_config("orders.apps", vec![ep("10.0.0.5")]);
        let got = resolve(from_control_plane, &served, resolver_down).await;
        assert!(got.clusters["store/orders"].endpoints.is_empty());
    }

    #[tokio::test]
    async fn priming_hands_back_the_configuration_not_only_its_version() {
        // `run` needs the configuration to re-resolve from on every tick; a start whose first
        // poll is a 304 gets nothing else to resolve from.
        let dir = tempdir();
        let s = source(&dir);
        let cached = resolve_config("orders.apps", vec![]);
        s.write_cache("\"3\"", &cached);
        let (version, config) = s.prime().await.expect("primed");
        assert_eq!(version, "\"3\"");
        assert_eq!(
            config, cached,
            "unresolved, exactly as the control plane sent it"
        );
    }
}
