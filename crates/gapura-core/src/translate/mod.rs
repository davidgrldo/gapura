//! `translate(&Snapshot, &Settings) -> Translation`: the pure heart of Gapura.
//! Steps: accept GatewayClasses -> build listeners -> attach routes -> assemble Config + Gateway status.

mod gateway_class;
mod grants;
mod listeners;

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::config::{Cluster, Config, ListenerConfig};
use crate::snapshot::{Settings, Snapshot};
use crate::status::{reasons, types, Condition, ConditionStatus, ListenerStatus, StatusPatch};
use listeners::GatewayBuild;

/// Result of one translation pass. Status order: GatewayClass, Gateway, HTTPRoute.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Translation {
    pub config: Config,
    pub status: Vec<StatusPatch>,
}

pub fn translate(snap: &Snapshot, settings: &Settings) -> Translation {
    let mut status = Vec::new();
    let classes = gateway_class::accept(snap, settings, &mut status);
    let gateways = listeners::build(snap, settings, &classes);
    let clusters: BTreeMap<String, Cluster> = BTreeMap::new(); // filled once routes are attached (Task 8)
    let config = assemble(gateways, clusters, settings, &mut status);
    Translation { config, status }
}

/// Turn listener builds into `ListenerConfig`s (programmed ones only) and Gateway status patches.
/// Clusters not referenced by any programmed rule are dropped.
fn assemble(
    gateways: Vec<GatewayBuild>,
    clusters: BTreeMap<String, Cluster>,
    settings: &Settings,
    status: &mut Vec<StatusPatch>,
) -> Config {
    let mut listeners_cfg = Vec::new();
    let mut used = BTreeSet::new();
    for gw in gateways {
        let generation = gw.generation;
        let mut listener_status = Vec::new();
        let mut any_programmed = false;
        let mut all_valid = true;
        for mut l in gw.listeners {
            let programmed = l.programmed();
            if programmed {
                any_programmed = true;
            } else {
                all_valid = false;
            }
            listener_status.push(ListenerStatus {
                name: l.name.clone(),
                supported_kinds: l.supported_kinds.clone(),
                attached_routes: l.attached_routes,
                conditions: l.conditions(generation),
            });
            if !programmed {
                continue;
            }
            for rule in &l.rules {
                for backend in &rule.backends {
                    if let Some(cluster) = &backend.cluster {
                        used.insert(cluster.clone());
                    }
                }
            }
            listeners_cfg.push(ListenerConfig {
                id: format!("{}/{}/{}", gw.r#ref.namespace, gw.r#ref.name, l.name),
                port: l.port,
                protocol: l
                    .protocol
                    .expect("a programmed listener has a supported protocol"),
                hostname: l.hostname.clone(),
                tls: l.tls.take(),
                rules: std::mem::take(&mut l.rules),
                table: std::mem::take(&mut l.table),
            });
        }
        let accepted = if all_valid {
            Condition::new(
                types::ACCEPTED,
                ConditionStatus::True,
                reasons::ACCEPTED,
                "Gateway is accepted",
                generation,
            )
        } else if any_programmed {
            Condition::new(
                types::ACCEPTED,
                ConditionStatus::True,
                reasons::LISTENERS_NOT_VALID,
                "Some listeners are not valid",
                generation,
            )
        } else {
            Condition::new(
                types::ACCEPTED,
                ConditionStatus::False,
                reasons::LISTENERS_NOT_VALID,
                "No listener is valid",
                generation,
            )
        };
        let programmed = if any_programmed {
            Condition::new(
                types::PROGRAMMED,
                ConditionStatus::True,
                reasons::PROGRAMMED,
                "Gateway is programmed",
                generation,
            )
        } else {
            Condition::new(
                types::PROGRAMMED,
                ConditionStatus::False,
                reasons::INVALID,
                "No listener is programmed",
                generation,
            )
        };
        status.push(StatusPatch::Gateway {
            namespace: gw.r#ref.namespace.clone(),
            name: gw.r#ref.name.clone(),
            addresses: settings.gateway_addresses.clone(),
            conditions: vec![accepted, programmed],
            listeners: listener_status,
        });
    }
    let clusters = clusters
        .into_iter()
        .filter(|(key, _)| used.contains(key))
        .collect();
    Config {
        listeners: listeners_cfg,
        clusters,
    }
}
