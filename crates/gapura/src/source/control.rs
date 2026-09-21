//! Configuration from `gapura-control`, which ADR 2 made its owner and ADR 3 said we ask for.
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
    pub async fn prime(&self) -> Option<String> {
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
                let config = resolve(cached.config).await;
                self.store.swap_from_cache(config);
                tracing::info!(
                    version = %cached.version,
                    "serving a configuration from the cache while the control plane is unconfirmed"
                );
                Some(cached.version)
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
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .expect("a reqwest client");
        let mut held = self.prime().await;
        let mut latest: Option<Config> = None;

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
                Ok(None) => {}
                Err(e) => {
                    // Keep serving. ADR 2 put the cache here precisely so that losing the
                    // control plane costs new configuration and not traffic.
                    tracing::warn!(error = %e, "asking the control plane for configuration");
                }
            }

            // Every tick, not only when the configuration changed: a backend's addresses move
            // when pods do, which has nothing to do with the version. Swapped only when the
            // result differs, so a quiet cluster does not churn the runtime.
            if let Some(config) = &latest {
                let resolved = resolve(config.clone()).await;
                if self.store.load().config != resolved {
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
/// Only the data plane can do this. ADR 3 deliberately supports data planes in another network,
/// where a name answers differently or not at all, so the control plane sends the name and each
/// data plane asks its own resolver. A name that does not resolve leaves the cluster empty,
/// which is 503 -- the same answer as a backend with no ready addresses, and correct for the
/// same reason: there is nowhere to send the request.
async fn resolve(mut config: Config) -> Config {
    for (key, cluster) in config.clusters.iter_mut() {
        let Some(target) = cluster.resolve.clone() else {
            continue;
        };
        match tokio::net::lookup_host(format!("{}:{}", target.host, target.port)).await {
            Ok(addrs) => {
                let mut endpoints: Vec<Endpoint> = addrs
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
                tracing::warn!(cluster = %key, host = %target.host, error = %e, "resolving a backend");
                // Deliberately nothing: `endpoints` keeps whatever the last successful
                // resolution put there. Stale addresses are a better answer than none while
                // DNS is unhappy, and clearing them would turn a resolver hiccup into an
                // outage.
            }
        }
    }
    config
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
        assert_eq!(s.prime().await.as_deref(), Some("\"7\""));
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
        assert_eq!(s.prime().await.as_deref(), Some("\"7\""));
    }
}
