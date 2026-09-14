//! `translate(&Snapshot, &Settings) -> Translation`: the pure heart of Gapura.
//! Steps: accept GatewayClasses -> build listeners -> attach routes -> assemble Config + Gateway status.

mod allowed;
mod backend_tls;
mod backends;
mod gateway_class;
mod grants;
mod listeners;
mod precedence;
mod routes;
mod rules;

/// The per-port sort, exposed so the matcher's unit tests build their index exactly as
/// `assemble` does. Not part of the public API.
#[cfg(test)]
pub(crate) fn sort_port_table_for_tests(
    entries: &mut [crate::config::PortEntry],
    listeners: &[crate::config::ListenerConfig],
) {
    precedence::sort_port_table(entries, listeners);
}

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::config::{Cluster, Config, ListenerConfig, MatchEntry, PortEntry};
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
    let mut gateways = listeners::build(snap, settings, &classes);
    let mut clusters: BTreeMap<String, Cluster> = BTreeMap::new();
    let mut route_status = Vec::new();
    routes::attach(
        snap,
        settings,
        &mut gateways,
        &mut clusters,
        &mut route_status,
    );
    let config = assemble(gateways, clusters, settings, &mut status);
    status.extend(route_status);
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
    let mut tables: Vec<Vec<MatchEntry>> = Vec::new();
    let mut used = BTreeSet::new();
    for gw in gateways {
        let generation = gw.generation;
        let gateway_ok = gw.rejected.is_none();
        let mut listener_status = Vec::new();
        let mut any_programmed = false;
        let mut all_programmed = true;
        for mut l in gw.listeners {
            let programmed = gateway_ok && l.programmed();
            if programmed {
                any_programmed = true;
            } else {
                all_programmed = false;
            }
            listener_status.push(ListenerStatus {
                name: l.name.clone(),
                supported_kinds: l.supported_kinds.clone(),
                attached_routes: l.attached_routes,
                conditions: l.conditions(generation, gateway_ok),
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
                // A mirror-only cluster has no entry in rule.backends; without this the prune
                // below would silently drop it and the mirror would have nowhere to go.
                if let Some(mirror) = &rule.filters.mirror {
                    used.insert(mirror.cluster.clone());
                }
            }
            tables.push(std::mem::take(&mut l.table));
            listeners_cfg.push(ListenerConfig {
                id: format!("{}/{}/{}", gw.r#ref.namespace, gw.r#ref.name, l.name),
                port: l.port,
                protocol: l
                    .protocol
                    .expect("a programmed listener has a supported protocol"),
                hostname: l.hostname.clone(),
                tls: l.tls.take(),
                rules: std::mem::take(&mut l.rules),
            });
        }
        let accepted = match &gw.rejected {
            Some((reason, message)) => Condition::new(
                types::ACCEPTED,
                ConditionStatus::False,
                reason,
                message.clone(),
                generation,
            ),
            None if all_programmed => Condition::new(
                types::ACCEPTED,
                ConditionStatus::True,
                reasons::ACCEPTED,
                "Gateway is accepted",
                generation,
            ),
            None if any_programmed => Condition::new(
                types::ACCEPTED,
                ConditionStatus::True,
                reasons::LISTENERS_NOT_VALID,
                "Some listeners are not valid",
                generation,
            ),
            None => Condition::new(
                types::ACCEPTED,
                ConditionStatus::False,
                reasons::LISTENERS_NOT_VALID,
                "No listener is valid",
                generation,
            ),
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
    // One table per port over every programmed listener: the data plane matches on the port the
    // request arrived on, not on a single listener chosen up front.
    let mut ports: BTreeMap<u16, Vec<PortEntry>> = BTreeMap::new();
    for (index, entries) in tables.into_iter().enumerate() {
        let port = listeners_cfg[index].port;
        let bucket = ports.entry(port).or_default();
        for e in entries {
            bucket.push(PortEntry {
                listener: index,
                hostname: e.hostname,
                matcher: e.matcher,
                rule: e.rule,
            });
        }
    }
    for entries in ports.values_mut() {
        precedence::sort_port_table(entries, &listeners_cfg);
    }
    let clusters = clusters
        .into_iter()
        .filter(|(key, _)| used.contains(key))
        .collect();
    Config {
        listeners: listeners_cfg,
        ports,
        clusters,
    }
}
