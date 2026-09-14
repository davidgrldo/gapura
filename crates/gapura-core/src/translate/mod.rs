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
/// address** (`--gateway-address`) is remapped: that override is the declaration that this
/// Gateway is reachable at its own destination, so its listener must have a destination port of
/// its own too. Every other Gateway keeps sharing the shared address's port exactly as before —
/// the suite's many single-address tests depend on that. The first listener in translation
/// order keeps its declared port; a later listener moves to the next free **bound** port of its
/// protocol when one of its table entries has *equal hostname specificity* to an entry of an
/// earlier listener on the same port **from a different route** — both catch-alls, the same
/// exact name, or wildcards over the same parent — because precedence cannot decide between
/// those, so one of the two routes is unreachable through this port no matter what. The proxy
/// binds exactly the `--listen-http`/`--listen-https` sockets at startup, so a remap target
/// must come from that set; an operator who wants addressable Gateways binds a second port
/// (e.g. `--listen-http 0.0.0.0:10000`) and maps a Service to it. With no free bound port the
/// listener keeps sharing the table — the pre-existing behavior. An equal-class pair from the
/// *same* route is unobservable (either way the same rule serves) and always shares — one route
/// attached to both an exact and a wildcard listener of one Gateway is the SNI-cert case. A
/// pair where one side is strictly more specific (`second.test` against a catch-all,
/// `a.example.com` against `*.example.com`) also shares: precedence always resolves it the
/// same way. Listeners on distinct ports are untouched, so existing charts keep working
/// verbatim. The port a parentRef declares is matched in the route-attach step, before this
/// runs, so a remap never breaks attachment.
///
/// The allocation is deterministic (translation order is the sorted snapshot order, the pools
/// are sorted), which is what lets a deployment map a Service port to the remapped target port
/// by hand.
fn remap_colliding_ports(
    listeners: &mut [ListenerConfig],
    tables: &[Vec<MatchEntry>],
    settings: &Settings,
    overridden: &[bool],
) {
    let declared: Vec<u16> = listeners.iter().map(|l| l.port).collect();
    let mut taken: BTreeSet<u16> = declared.iter().copied().collect();
    for i in 0..listeners.len() {
        if !overridden[i] {
            continue;
        }
        let conflict = (0..i).any(|j| {
            declared[j] == declared[i]
                && tables[i].iter().any(|a| {
                    tables[j].iter().any(|b| {
                        hostname_class(a.hostname.as_deref())
                            == hostname_class(b.hostname.as_deref())
                            && listeners[i].rules[a.rule].route != listeners[j].rules[b.rule].route
                    })
                })
        });
        if conflict {
            let pool = match listeners[i].protocol {
                crate::config::Protocol::Http => &settings.http_ports,
                crate::config::Protocol::Https => &settings.https_ports,
            };
            let target = pool.iter().copied().find(|p| !taken.contains(p));
            if let Some(p) = target {
                listeners[i].port = p;
                taken.insert(p);
            }
        }
    }
}

/// The specificity class of one table entry's hostname: entries in the same class can claim the
/// same request and only a tie-break could tell them apart, so they count as a conflict.
/// Lowercased: hostnames are case-insensitive.
#[derive(Debug, PartialEq, Eq)]
enum HostnameClass {
    CatchAll,
    Exact(String),
    Wildcard(String),
}

fn hostname_class(hostname: Option<&str>) -> HostnameClass {
    match hostname {
        None => HostnameClass::CatchAll,
        Some(h) => match h.to_ascii_lowercase().strip_prefix("*.") {
            Some(parent) => HostnameClass::Wildcard(parent.to_string()),
            None => HostnameClass::Exact(h.to_ascii_lowercase()),
        },
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
    remap_colliding_ports(&mut listeners_cfg, &tables, settings, &overridden);
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
    use crate::config::{PathMatch, RouteMatch, RouteRule};
    use crate::snapshot::Settings;

    fn listener(port: u16, route: &str) -> ListenerConfig {
        ListenerConfig {
            id: format!("ns/gw/{port}"),
            port,
            protocol: crate::config::Protocol::Http,
            hostname: None,
            tls: None,
            rules: vec![RouteRule {
                route: route.to_string(),
                rule_index: 0,
                creation_timestamp: "2026-09-10T00:00:00Z".into(),
                matches: vec![RouteMatch {
                    path: PathMatch::Prefix("/".into()),
                    headers: vec![],
                    query: vec![],
                    method: None,
                }],
                filters: Default::default(),
                backends: vec![],
                timeouts: Default::default(),
            }],
        }
    }

    fn entry(hostname: Option<&str>) -> MatchEntry {
        MatchEntry {
            hostname: hostname.map(str::to_string),
            matcher: RouteMatch {
                path: PathMatch::Prefix("/".into()),
                headers: vec![],
                query: vec![],
                method: None,
            },
            rule: 0,
        }
    }

    fn table(hostnames: &[Option<&str>]) -> Vec<MatchEntry> {
        hostnames.iter().map(|h| entry(*h)).collect()
    }

    fn settings(bound_http: &[u16]) -> Settings {
        Settings {
            http_ports: bound_http.to_vec(),
            ..Settings::default()
        }
    }

    /// Settings whose one Gateway (`ns/gw`) carries its own address: the declaration that
    /// makes the remap eligible.
    fn overridden_settings(bound_http: &[u16]) -> Settings {
        let mut s = settings(bound_http);
        s.gateway_address_overrides
            .insert("ns/gw".to_string(), vec!["203.0.113.9".to_string()]);
        s
    }

    #[test]
    fn two_routes_that_both_match_everything_split_by_port() {
        // The HTTPRouteMultipleGateways shape: two catch-all routes on two Gateways sharing a
        // port. Precedence would tie them to one route; the address per Gateway needs a
        // destination port per Gateway, and the operator bound room for one.
        let mut ls = vec![listener(80, "apps/a"), listener(80, "apps/b")];
        let tables = vec![table(&[None]), table(&[None])];
        let overridden = vec![true, true];
        remap_colliding_ports(
            &mut ls,
            &tables,
            &overridden_settings(&[80, 10000]),
            &overridden,
        );
        assert_eq!(ls[0].port, 80, "first in order keeps its declared port");
        assert_eq!(
            ls[1].port, 10000,
            "the equally-specific listener moves to the free bound port"
        );
    }

    #[test]
    fn three_way_collisions_chain_the_free_bound_ports() {
        let mut ls = vec![
            listener(80, "apps/a"),
            listener(80, "apps/b"),
            listener(80, "apps/c"),
        ];
        let tables = vec![table(&[None]), table(&[None]), table(&[None])];
        let overridden = vec![true, true, true];
        remap_colliding_ports(
            &mut ls,
            &tables,
            &overridden_settings(&[80, 10000, 10001]),
            &overridden,
        );
        assert_eq!(
            ls.iter().map(|l| l.port).collect::<Vec<_>>(),
            vec![80, 10000, 10001]
        );
    }

    #[test]
    fn no_free_bound_port_keeps_the_old_shared_behavior() {
        // One bound port: there is nothing to remap onto, so the listeners keep sharing the
        // table exactly as before this feature existed.
        let mut ls = vec![listener(80, "apps/a"), listener(80, "apps/b")];
        let tables = vec![table(&[None]), table(&[None])];
        let overridden = vec![true, true];
        remap_colliding_ports(&mut ls, &tables, &settings(&[80]), &overridden);
        assert!(ls.iter().all(|l| l.port == 80));
    }

    #[test]
    fn a_gateway_without_its_own_address_is_never_remapped() {
        // The override IS the declaration of individual addressability. Without it a Gateway
        // expects to be reachable on the shared address's port, exactly as before this feature
        // existed — even when a free bound port is sitting right there. (The conformance
        // suite's many single-address tests depend on this.)
        let mut ls = vec![listener(80, "apps/a"), listener(80, "apps/b")];
        let tables = vec![table(&[None]), table(&[None])];
        let overridden = vec![false, false];
        remap_colliding_ports(&mut ls, &tables, &settings(&[80, 10000]), &overridden);
        assert!(ls.iter().all(|l| l.port == 80));
    }

    #[test]
    fn equal_specificity_for_the_same_route_keeps_sharing() {
        // One route attached to both an exact and a wildcard listener of one Gateway — the SNI
        // certificate shape. Whichever listener wins the tie, the same rule serves, so there is
        // nothing an address per Gateway could disambiguate.
        let mut ls = vec![listener(443, "apps/all"), listener(443, "apps/all")];
        let tables = vec![
            table(&[Some("a.gw.test")]),
            table(&[Some("a.gw.test"), Some("*.gw.test")]),
        ];
        let overridden = vec![true, true];
        remap_colliding_ports(
            &mut ls,
            &tables,
            &overridden_settings(&[443, 8443]),
            &overridden,
        );
        assert!(ls.iter().all(|l| l.port == 443));
    }

    #[test]
    fn strictly_more_specific_hostnames_keep_sharing_the_port() {
        // A catch-all and a route scoped to second.test are resolved by precedence the same way
        // for every request; sharing one port is a working setup (the e2e pins it).
        let mut ls = vec![listener(80, "apps/echo"), listener(80, "apps/second")];
        let tables = vec![table(&[None]), table(&[Some("second.test")])];
        let overridden = vec![true, true];
        remap_colliding_ports(
            &mut ls,
            &tables,
            &overridden_settings(&[80, 10000]),
            &overridden,
        );
        assert!(ls.iter().all(|l| l.port == 80));
        // Disjoint exact names too.
        let mut ls = vec![listener(80, "apps/first"), listener(80, "apps/second")];
        let tables = vec![
            table(&[Some("first.example.com")]),
            table(&[Some("second.example.com")]),
        ];
        let overridden = vec![true, true];
        remap_colliding_ports(
            &mut ls,
            &tables,
            &overridden_settings(&[80, 10000]),
            &overridden,
        );
        assert!(ls.iter().all(|l| l.port == 80));
    }

    #[test]
    fn equal_exact_names_on_different_routes_conflict() {
        let mut ls = vec![listener(80, "apps/a"), listener(80, "apps/b")];
        let tables = vec![
            table(&[Some("app.example.com")]),
            table(&[Some("APP.example.com")]),
        ];
        let overridden = vec![true, true];
        remap_colliding_ports(
            &mut ls,
            &tables,
            &overridden_settings(&[80, 10000]),
            &overridden,
        );
        assert_eq!(ls[1].port, 10000, "hostnames are case-insensitive");

        let mut ls = vec![listener(80, "apps/a"), listener(80, "apps/b")];
        let tables = vec![
            table(&[Some("*.example.com")]),
            table(&[Some("*.example.com")]),
        ];
        let overridden = vec![true, true];
        remap_colliding_ports(
            &mut ls,
            &tables,
            &overridden_settings(&[80, 10000]),
            &overridden,
        );
        assert_eq!(ls[1].port, 10000);
    }

    #[test]
    fn a_remapped_port_never_lands_on_another_declared_port() {
        let mut ls = vec![
            listener(80, "apps/a"),
            listener(80, "apps/b"),
            listener(10000, "apps/c"),
        ];
        let tables = vec![table(&[None]), table(&[None]), table(&[None])];
        let overridden = vec![true, true, true];
        remap_colliding_ports(
            &mut ls,
            &tables,
            &overridden_settings(&[80, 10000]),
            &overridden,
        );
        assert_eq!(
            ls.iter().map(|l| l.port).collect::<Vec<_>>(),
            vec![80, 80, 10000],
            "10000 is taken by a declared listener and the pool has nothing else, so b shares"
        );
    }

    #[test]
    fn hostname_classes() {
        use HostnameClass::{CatchAll, Exact, Wildcard};
        assert_eq!(hostname_class(None), CatchAll);
        assert_eq!(hostname_class(Some("A.com")), Exact("a.com".into()));
        assert_eq!(
            hostname_class(Some("*.Example.com")),
            Wildcard("example.com".into())
        );
        assert_eq!(
            hostname_class(Some("*.Example.com")),
            hostname_class(Some("*.example.com"))
        );
        assert_ne!(
            hostname_class(Some("a.com")),
            hostname_class(Some("*.a.com"))
        );
        assert_ne!(hostname_class(Some("a.com")), hostname_class(Some("b.com")));
        assert_ne!(
            hostname_class(Some("*.a.com")),
            hostname_class(Some("*.b.com"))
        );
        assert_ne!(hostname_class(None), hostname_class(Some("x.com")));
    }
}
