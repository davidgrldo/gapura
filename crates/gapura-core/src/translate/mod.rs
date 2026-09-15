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

/// Addresses of one Gateway: its per-Gateway override when it has one, the global publish list
/// otherwise.
fn addresses_for(settings: &Settings, r#ref: &crate::snapshot::ObjectRef) -> Vec<String> {
    let key = format!("{}/{}", r#ref.namespace, r#ref.name);
    settings
        .gateway_address_overrides
        .get(&key)
        .cloned()
        .unwrap_or_else(|| settings.gateway_addresses.clone())
}

/// An address per Gateway, part 1: the destination port must tell two Gateways apart when
/// nothing else does (the `HTTPRouteMultipleGateways` case — two routes matching `PathPrefix /`
/// with no hostname on two Gateways sharing a port). Only a Gateway the operator gave **its own
/// address** (`--gateway-address`) is touched: that override is the declaration that this
/// Gateway is reachable at its own destination, so its listeners move to the next free **bound**
/// port of their protocol — address and destination port stay consistent, whatever else shares
/// the declared port today. Every other Gateway keeps its declared port and the shared address
/// exactly as before; nothing about a deployment without overrides changes at all.
///
/// The proxy binds exactly the `--listen-http`/`--listen-https` sockets at startup, so a remap
/// target must come from that set: an operator who wants addressable Gateways binds a second
/// port (e.g. `--listen-http 0.0.0.0:10000`) and points a Service at it. With no free bound
/// port the listener keeps its declared port — and the operator's Service must map the shared
/// port instead, or that Gateway is unreachable at its override address.
///
/// The allocation is deterministic (translation order is the sorted snapshot order, the pools
/// are sorted), which is what lets a deployment map a Service port to the remapped target port
/// by hand. The port a parentRef declares is matched in the route-attach step, before this
/// runs, so a remap never breaks attachment.
fn remap_overridden_listeners(
    listeners: &mut [ListenerConfig],
    settings: &Settings,
    overridden: &[bool],
) {
    let mut taken: BTreeSet<u16> = listeners.iter().map(|l| l.port).collect();
    for i in 0..listeners.len() {
        if !overridden[i] {
            continue;
        }
        let pool = match listeners[i].protocol {
            crate::config::Protocol::Http => &settings.http_ports,
            crate::config::Protocol::Https => &settings.https_ports,
        };
        if let Some(p) = pool.iter().copied().find(|p| !taken.contains(p)) {
            listeners[i].client_port = Some(listeners[i].port);
            listeners[i].port = p;
            taken.insert(p);
        }
    }
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
    // Whether each programmed listener's Gateway carries a `--gateway-address` override: only
    // those Gateways are individually addressable, so only they may be remapped.
    let mut overridden = Vec::new();
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
            overridden.push(
                settings
                    .gateway_address_overrides
                    .contains_key(&format!("{}/{}", gw.r#ref.namespace, gw.r#ref.name)),
            );
            tables.push(std::mem::take(&mut l.table));
            listeners_cfg.push(ListenerConfig {
                id: format!("{}/{}/{}", gw.r#ref.namespace, gw.r#ref.name, l.name),
                port: l.port,
                client_port: None,
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
            addresses: addresses_for(settings, &gw.r#ref),
            conditions: vec![accepted, programmed],
            listeners: listener_status,
        });
    }
    remap_overridden_listeners(&mut listeners_cfg, settings, &overridden);
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

#[cfg(test)]
mod remap_tests {
    use super::*;
    use crate::snapshot::Settings;

    fn listener(port: u16, name: &str) -> ListenerConfig {
        ListenerConfig {
            id: format!("ns/gw/{name}"),
            port,
            client_port: None,
            protocol: crate::config::Protocol::Http,
            hostname: None,
            tls: None,
            rules: Vec::new(),
        }
    }

    fn settings(bound_http: &[u16]) -> Settings {
        Settings {
            http_ports: bound_http.to_vec(),
            ..Settings::default()
        }
    }

    fn overridden_settings(bound_http: &[u16], gateways: &[&str]) -> Settings {
        let mut s = settings(bound_http);
        for g in gateways {
            s.gateway_address_overrides
                .insert(g.to_string(), vec!["203.0.113.9".to_string()]);
        }
        s
    }

    #[test]
    fn an_overridden_gateway_takes_a_free_bound_port() {
        let mut ls = vec![listener(80, "http"), listener(80, "http")];
        let overridden = vec![false, true];
        remap_overridden_listeners(
            &mut ls,
            &overridden_settings(&[80, 10000], &["ns/gw"]),
            &overridden,
        );
        assert_eq!(ls[0].port, 80, "the shared-address Gateway is untouched");
        assert_eq!(
            ls[1].port, 10000,
            "the overridden Gateway gets its own port"
        );
    }

    #[test]
    fn a_gateway_without_its_own_address_is_never_remapped() {
        // No override, free bound port or not: the shared address keeps serving exactly the
        // listeners it always served. (Every conformance test that dials the shared address
        // depends on this.)
        let mut ls = vec![listener(80, "a"), listener(80, "b"), listener(80, "c")];
        let overridden = vec![false, false, false];
        remap_overridden_listeners(&mut ls, &settings(&[80, 10000, 10001]), &overridden);
        assert!(ls.iter().all(|l| l.port == 80));
    }

    #[test]
    fn every_listener_of_an_overridden_gateway_moves() {
        let mut ls = vec![
            listener(80, "http"),
            listener(80, "http"),
            listener(8080, "http"),
        ];
        let overridden = vec![true, true, true];
        remap_overridden_listeners(
            &mut ls,
            &overridden_settings(&[80, 8080, 10000, 10001], &["ns/gw"]),
            &overridden,
        );
        assert_eq!(
            ls.iter().map(|l| l.port).collect::<Vec<_>>(),
            vec![10000, 10001, 8080],
            "the first two fill free pool ports in order; the third keeps its own declared port"
        );
    }

    #[test]
    fn pool_exhaustion_leaves_the_declared_port() {
        // One bound port: the override cannot move anywhere, so the listener keeps the declared
        // port and the operator must map the shared port to this Gateway's address.
        let mut ls = vec![listener(80, "http")];
        let overridden = vec![true];
        remap_overridden_listeners(&mut ls, &settings(&[80]), &overridden);
        assert_eq!(ls[0].port, 80);
    }

    #[test]
    fn the_remap_never_lands_on_another_declared_port() {
        let mut ls = vec![listener(80, "a"), listener(80, "b"), listener(10000, "c")];
        let overridden = vec![false, true, false];
        remap_overridden_listeners(
            &mut ls,
            &overridden_settings(&[80, 10000], &["ns/gw"]),
            &overridden,
        );
        assert_eq!(ls[1].port, 80, "10000 is taken by a declared listener");
    }

    #[test]
    fn https_overrides_take_from_the_https_pool() {
        let mut ls = vec![ListenerConfig {
            protocol: crate::config::Protocol::Https,
            ..listener(443, "https")
        }];
        let overridden = vec![true];
        let s = Settings {
            https_ports: vec![443, 8443],
            ..Settings::default()
        };
        remap_overridden_listeners(&mut ls, &s, &overridden);
        assert_eq!(ls[0].port, 8443, "the https pool, not the http one");
    }
}
