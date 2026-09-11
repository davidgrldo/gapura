//! Kubernetes config source: watch ten kinds, fold them into a Snapshot, translate, swap, and
//! hand status to the leader's writer. Runs as a Pingora background service.
//!
//! Failure policy (spec 5.4): the process never exits because of the API server. Connection or
//! discovery failures are retried every `RETRY`; a watch failure restarts that watch with backoff
//! while the last good Config keeps serving; a translator panic keeps the previous Config.

pub mod kinds;
pub mod leader;
pub mod reconcile;
pub mod status;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use async_trait::async_trait;
use futures::StreamExt;
use gapura_core::status::StatusPatch;
use gapura_core::{ObjectRef, Settings};
use kube::api::{Api, ApiResource, DynamicObject, ListParams};
use kube::runtime::{watcher, WatchStreamExt};
use kube::Client;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;
use tokio::sync::{mpsc, watch};

use self::kinds::{Kind, KINDS};
use self::leader::LeaderOpts;
use self::reconcile::{Change, State};
use crate::store::Store;
use crate::telemetry::METRICS;

pub const DEBOUNCE: Duration = Duration::from_millis(200);
const RETRY: Duration = Duration::from_secs(10);
/// How often an absent optional kind is looked for again.
const RECHECK: Duration = Duration::from_secs(60);

pub struct KubeSource {
    pub settings: Settings,
    pub store: Arc<Store>,
    pub publish_service: Option<ObjectRef>,
    pub leader: LeaderOpts,
    /// Skip status writes and the Lease entirely (`--no-status`).
    pub read_only: bool,
}

/// Why `run` returned without failing. Both are expected; neither is an error.
enum Stopped {
    /// The process is shutting down, so nothing restarts.
    Shutdown,
    /// An optional kind is served and listable now: rebuild the source to watch it.
    KindAppeared(&'static str),
}

#[async_trait]
impl BackgroundService for KubeSource {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        loop {
            let outcome = tokio::select! {
                r = self.run(shutdown.clone()) => r,
                _ = shutdown.changed() => return,
            };
            match outcome {
                Ok(Stopped::Shutdown) => return,
                // A planned restart: error level is reserved for bugs and the unexpected
                // (spec 5.4), and installing a CRD must not page anyone.
                Ok(Stopped::KindAppeared(kind)) => {
                    tracing::info!(
                        kind,
                        restart_secs = RETRY.as_secs(),
                        "optional kind is served now, restarting the source to watch it"
                    );
                    tokio::select! {
                        _ = tokio::time::sleep(RETRY) => {}
                        _ = shutdown.changed() => return,
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, retry_secs = RETRY.as_secs(), "kubernetes source failed, retrying");
                    tokio::select! {
                        _ = tokio::time::sleep(RETRY) => {}
                        _ = shutdown.changed() => return,
                    }
                }
            }
        }
    }
}

impl KubeSource {
    async fn run(&self, mut shutdown: ShutdownWatch) -> anyhow::Result<Stopped> {
        let client = Client::try_default()
            .await
            .context("connecting to the API server")?;

        // 1. Discovery: which version serves each kind.
        let mut resolved: Vec<(&'static Kind, ApiResource)> = Vec::new();
        for kind in KINDS.iter() {
            match kind
                .resolve(&client)
                .await
                .with_context(|| format!("discovering {}", kind.name))?
            {
                Some(ar) => resolved.push((kind, ar)),
                None if kind.optional => tracing::warn!(
                    kind = kind.name,
                    "not served by the API server, feature disabled"
                ),
                None => anyhow::bail!(
                    "{} is not served by the API server; install the Gateway API CRDs",
                    kind.name
                ),
            }
        }
        let watched: Vec<&str> = resolved.iter().map(|(k, _)| k.name).collect();
        // Each task reports what it was, so an unexpected end can name itself.
        let mut aux: tokio::task::JoinSet<&'static str> = tokio::task::JoinSet::new();
        let missing = kinds::missing_optional(&watched);
        for kind in KINDS.iter() {
            let absent = missing.iter().any(|m| m.name == kind.name);
            METRICS
                .discovery_missing
                .with_label_values(&[kind.name])
                .set(i64::from(absent));
        }
        // An optional CRD installed after we started would otherwise stay invisible until a
        // restart. Recheck on a timer and ask `run` to rebuild everything once one appears.
        // This is a planned restart, not a failure, so it travels on its own channel and lives
        // in its own JoinSet: nothing joins it, and dropping the set when `run` returns aborts it.
        let (found_tx, mut found_rx) = mpsc::channel::<&'static str>(1);
        let mut rediscovery = tokio::task::JoinSet::new();
        if !missing.is_empty() {
            let client = client.clone();
            let names: Vec<&'static str> = missing.iter().map(|k| k.name).collect();
            let found_tx = found_tx.clone();
            rediscovery.spawn(async move {
                // No immediate first tick: discovery decided these kinds were absent a moment
                // ago. Asking again straight away is not just redundant -- an API server whose
                // replicas disagree about a freshly created CRD (discovery hits one that says
                // absent, the tick one that says present) would restart us every `RETRY`
                // instead of every `RECHECK`.
                let mut tick =
                    tokio::time::interval_at(tokio::time::Instant::now() + RECHECK, RECHECK);
                loop {
                    tick.tick().await;
                    for kind in &missing {
                        let Ok(Some(ar)) = kind.resolve(&client).await else {
                            continue;
                        };
                        // Served is not the same as usable. If listing the kind is forbidden,
                        // its watcher retries its initial list forever, that kind never syncs,
                        // and `synced_all` then blocks *every* Gateway and HTTPRoute change.
                        // A bounded list proves the RBAC is in place before we restart on it.
                        let api = Api::<DynamicObject>::all_with(client.clone(), &ar);
                        match api.list(&ListParams::default().limit(1)).await {
                            Ok(_) => {
                                let _ = found_tx.send(kind.name).await;
                                return;
                            }
                            Err(e) => tracing::warn!(
                                kind = kind.name,
                                error = %e,
                                "kind is served but cannot be listed, not restarting; check RBAC"
                            ),
                        }
                    }
                }
            });
            tracing::warn!(
                ?names,
                recheck_secs = RECHECK.as_secs(),
                "optional kinds absent, rechecking"
            );
        }
        // Without a rediscovery task the channel closes here, which disables its select arm.
        drop(found_tx);

        // 2. One watcher per kind, all feeding one channel.
        let (tx, mut rx) = mpsc::channel::<Change>(1024);
        let mut tasks = tokio::task::JoinSet::new();
        for &(kind, ref ar) in &resolved {
            let api = Api::<DynamicObject>::all_with(client.clone(), ar);
            // keep ListWatch: kube-runtime 4.2 emits `Init` only for ListWatch, and
            // `reconcile::State` relies on it to reset the relist buffer
            let mut cfg = watcher::Config::default();
            if let Some(fields) = kind.field_selector {
                cfg = cfg.fields(fields);
            }
            let tx = tx.clone();
            tasks.spawn(async move {
                let mut stream = watcher(api, cfg).default_backoff().boxed();
                while let Some(item) = stream.next().await {
                    match item {
                        Ok(event) => {
                            if tx.send(reconcile::change_of(kind, event)).await.is_err() {
                                return;
                            }
                        }
                        Err(e) => {
                            METRICS
                                .watch_disconnects_total
                                .with_label_values(&[kind.name])
                                .inc();
                            tracing::warn!(kind = kind.name, error = %e, "watch failed, backing off and restarting");
                        }
                    }
                }
            });
        }
        drop(tx);

        // 3. Leader election and the status writer, joining `aux`.
        // Leader and writer end only at shutdown; watchers never end on their own, so a finished
        // watcher task is a failure that restarts the source.
        let (status_tx, status_rx) = watch::channel::<Vec<StatusPatch>>(Vec::new());
        if !self.read_only {
            let (leadership_tx, leadership_rx) = watch::channel(false);
            aux.spawn({
                let (client, opts, shutdown) =
                    (client.clone(), self.leader.clone(), shutdown.clone());
                async move {
                    leader::run(client, opts, leadership_tx, shutdown).await;
                    "leader election"
                }
            });
            let resources: HashMap<&'static str, ApiResource> = resolved
                .iter()
                .filter(|(k, _)| matches!(k.name, "GatewayClass" | "Gateway" | "HTTPRoute"))
                .map(|(k, ar)| (k.name, ar.clone()))
                .collect();
            let writer = status::Writer::new(
                client.clone(),
                resources,
                self.settings.controller_name.clone(),
                leadership_rx,
            );
            aux.spawn({
                let shutdown = shutdown.clone();
                async move {
                    writer.run(status_rx, shutdown).await;
                    "status writer"
                }
            });
        }

        // 4. Reconcile: debounce, translate, swap, publish status.
        let mut state = State::new(self.publish_service.clone());
        loop {
            let first = tokio::select! {
                c = rx.recv() => c,
                Some(ended) = tasks.join_next() => anyhow::bail!("a watcher task ended: {ended:?}"),
                Some(kind) = found_rx.recv() => return Ok(Stopped::KindAppeared(kind)),
                Some(ended) = aux.join_next() => {
                    // The leader and the writer end at shutdown too, and that can win the race
                    // against the arm below, so a clean stop must not be reported as a failure.
                    if *shutdown.borrow() {
                        return Ok(Stopped::Shutdown);
                    }
                    match ended {
                        Ok(name) => anyhow::bail!("the {name} task ended unexpectedly"),
                        Err(e) => anyhow::bail!("a support task panicked: {e}"),
                    }
                }
                _ = shutdown.changed() => return Ok(Stopped::Shutdown),
            };
            let Some(first) = first else {
                anyhow::bail!("all watchers stopped")
            };
            let mut dirty = state.apply(first);
            tokio::time::sleep(DEBOUNCE).await;
            while let Ok(c) = rx.try_recv() {
                dirty |= state.apply(c);
            }
            if !dirty || !state.synced_all(&watched) {
                continue;
            }
            let mut settings = self.settings.clone();
            settings
                .gateway_addresses
                .extend(state.addresses.iter().cloned());
            settings.gateway_addresses.sort();
            settings.gateway_addresses.dedup();
            let started = Instant::now();
            match reconcile::translate_guarded(&state.snapshot, &settings) {
                Ok(t) => {
                    let listeners = t.config.listeners.len();
                    let rules: usize = t.config.listeners.iter().map(|l| l.rules.len()).sum();
                    let clusters = t.config.clusters.len();
                    self.store.swap(t.config);
                    METRICS
                        .config_reloads_total
                        .with_label_values(&["success"])
                        .inc();
                    tracing::info!(
                        listeners,
                        rules,
                        clusters,
                        status = t.status.len(),
                        took_ms = started.elapsed().as_millis() as u64,
                        "config reloaded"
                    );
                    if !self.read_only {
                        let _ = status_tx.send(t.status);
                    }
                }
                Err(panic) => {
                    METRICS
                        .config_reloads_total
                        .with_label_values(&["failure"])
                        .inc();
                    tracing::error!(panic = %panic, "translator panicked, keeping the previous config");
                }
            }
        }
    }
}
