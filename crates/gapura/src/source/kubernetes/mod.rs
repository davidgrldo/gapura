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
use kube::api::{Api, ApiResource, DynamicObject};
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

pub struct KubeSource {
    pub settings: Settings,
    pub store: Arc<Store>,
    pub publish_service: Option<ObjectRef>,
    pub leader: LeaderOpts,
    /// Skip status writes and the Lease entirely (`--no-status`).
    pub read_only: bool,
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
                Ok(()) => return,
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
    async fn run(&self, mut shutdown: ShutdownWatch) -> anyhow::Result<()> {
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

        // 3. Leader election and the status writer.
        // Leader and writer end only at shutdown; watchers never end on their own, so a finished
        // watcher task is a failure that restarts the source.
        let mut aux = tokio::task::JoinSet::new();
        let (status_tx, status_rx) = watch::channel::<Vec<StatusPatch>>(Vec::new());
        if !self.read_only {
            let (leadership_tx, leadership_rx) = watch::channel(false);
            aux.spawn(leader::run(
                client.clone(),
                self.leader.clone(),
                leadership_tx,
                shutdown.clone(),
            ));
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
            aux.spawn(writer.run(status_rx, shutdown.clone()));
        }

        // 4. Reconcile: debounce, translate, swap, publish status.
        let mut state = State::new(self.publish_service.clone());
        loop {
            let first = tokio::select! {
                c = rx.recv() => c,
                Some(ended) = tasks.join_next() => anyhow::bail!("a watcher task ended: {ended:?}"),
                _ = shutdown.changed() => return Ok(()),
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
