//! Compiling a store-shaped configuration into the [`Config`] the data plane serves.
//!
//! [`translate()`](crate::translate()) does this from Gateway API resources. This does it from the
//! objects ADR 2 put in Postgres: Kong's shape, where a route names a service and a service names
//! an upstream. Same output type, same purity -- no I/O, no clock, no async -- so both paths are
//! covered by fixtures rather than by a running cluster.
//!
//! What this deliberately does not do is talk to a database. The rows come in as plain data, so
//! `gapura-core` keeps no dependency on sqlx and these tests need no Postgres.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::config::{
    Cluster, Config, Filters, ListenerConfig, PathMatch, Plugin, PortEntry, Protocol,
    ResolveTarget, RouteMatch, RouteRule, Timeouts, WeightedBackend,
};

/// Where traffic goes. `host` is resolved by the data plane, not here; see [`Cluster::resolve`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoreService {
    pub name: String,
    pub protocol: Protocol,
    pub host: String,
    pub port: u16,
}

/// What traffic goes there. Kong's semantics: a request matches when it matches any of the
/// hosts, any of the paths and any of the methods, and an empty list means "any".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoreRoute {
    pub name: String,
    /// [`StoreService::name`]. A route naming a service that does not exist is dropped.
    pub service: String,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub paths: Vec<PathMatch>,
    #[serde(default)]
    pub methods: Vec<String>,
    /// Higher wins. Explicit rather than derived from match specificity, so an operator can see
    /// and set the order; ties break on name so the output never depends on row order.
    #[serde(default)]
    pub priority: i32,
}

/// A policy row, attached to exactly one of a route or a service, or to neither -- which means
/// every route in the workspace. The schema enforces the "exactly one" with a check constraint,
/// because it is a rule that has to hold for every write path that will ever exist.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StorePlugin {
    /// [`StoreRoute::name`], when this is attached to one route.
    #[serde(default)]
    pub route: Option<String>,
    /// [`StoreService::name`], when this is attached to every route using one service.
    #[serde(default)]
    pub service: Option<String>,
    pub plugin: Plugin,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct StoreSnapshot {
    pub services: Vec<StoreService>,
    pub routes: Vec<StoreRoute>,
    #[serde(default)]
    pub plugins: Vec<StorePlugin>,
}

/// Runtime settings that are the data plane's, not the store's: which ports this process bound.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoreSettings {
    pub http_ports: Vec<u16>,
}

impl Default for StoreSettings {
    fn default() -> Self {
        Self {
            http_ports: vec![80],
        }
    }
}

/// One listener per bound port, every route on all of them.
///
/// Unlike the Gateway API path there is nothing here to attach a route to a particular listener:
/// the store has no Gateway object yet, so a route is reachable on every port the process bound.
/// When Gateways become store objects this is where that changes.
pub fn compile(snap: &StoreSnapshot, settings: &StoreSettings) -> Config {
    let services: BTreeMap<&str, &StoreService> =
        snap.services.iter().map(|s| (s.name.as_str(), s)).collect();

    // A route naming a service that is not there is dropped. This is load-bearing rather than
    // tidy: the lookup below indexes `services` directly, so without this filter a dangling
    // reference panics the compile and takes the control plane's endpoint down with it. A
    // foreign key should make it unreachable and the console should refuse it first; this is
    // what stands between those two being wrong and a crash.
    let mut routes: Vec<&StoreRoute> = snap
        .routes
        .iter()
        .filter(|r| services.contains_key(r.service.as_str()))
        .collect();
    // Highest priority first, then by name, so the table is a function of the rows and not of
    // the order a query happened to return them.
    routes.sort_by(|a, b| {
        b.priority
            .cmp(&a.priority)
            .then_with(|| a.name.cmp(&b.name))
    });

    let mut clusters = BTreeMap::new();
    let mut rules = Vec::with_capacity(routes.len());
    // Built once against rule indices, then cloned per listener: every listener carries every
    // route, so the table is identical and only the listener index differs.
    let mut table: Vec<(Option<String>, RouteMatch, usize)> = Vec::new();

    for route in &routes {
        let service = services[route.service.as_str()];
        let key = cluster_key(service);
        clusters.entry(key.clone()).or_insert_with(|| Cluster {
            // Nothing is resolved yet, which is why this is empty and not an error. The data
            // plane fills it, and until it does these requests get 503.
            endpoints: Vec::new(),
            tls: None,
            resolve: Some(ResolveTarget {
                host: service.host.clone(),
                port: service.port,
            }),
        });

        let matches = expand(route);
        let rule_index = rules.len();
        let plugins = plugins_for(&snap.plugins, route);
        rules.push(RouteRule {
            route: route.name.clone(),
            rule_index,
            // Gateway API breaks precedence ties on creation time. The store breaks them on an
            // explicit priority, so there is nothing to put here and nothing that reads it.
            creation_timestamp: String::new(),
            matches: matches.clone(),
            filters: Filters::default(),
            backends: vec![WeightedBackend {
                cluster: Some(key),
                weight: 1,
            }],
            timeouts: Timeouts::default(),
            rate_limit: None,
            plugins,
        });

        for m in matches {
            if route.hosts.is_empty() {
                table.push((None, m, rule_index));
            } else {
                for host in &route.hosts {
                    table.push((Some(host.clone()), m.clone(), rule_index));
                }
            }
        }
    }

    let listeners: Vec<ListenerConfig> = settings
        .http_ports
        .iter()
        .map(|port| ListenerConfig {
            id: format!("store/http:{port}"),
            port: *port,
            client_port: None,
            protocol: Protocol::Http,
            hostname: None,
            tls: None,
            rules: rules.clone(),
        })
        .collect();

    let ports = listeners
        .iter()
        .enumerate()
        .map(|(index, listener)| {
            let entries = table
                .iter()
                .map(|(hostname, matcher, rule)| PortEntry {
                    listener: index,
                    hostname: hostname.clone(),
                    matcher: matcher.clone(),
                    rule: *rule,
                })
                .collect();
            (listener.port, entries)
        })
        .collect();

    Config {
        listeners,
        ports,
        clusters,
    }
}

/// The policies that apply to one route, most specific wins.
///
/// A policy on the route beats one on its service, which beats one attached to neither and so to
/// the whole workspace -- the same precedence Kong settled on, and the one an operator expects
/// when they attach something narrow to override something broad. "Most specific" is per kind:
/// a route-level JWT policy replaces a workspace-level JWT policy and leaves everything else
/// alone, because the alternative is that attaching one narrow policy silently drops every
/// broad one.
fn plugins_for(all: &[StorePlugin], route: &StoreRoute) -> Vec<Plugin> {
    let mut chosen: Vec<(u8, &Plugin)> = Vec::new();
    for p in all {
        let rank = match (&p.route, &p.service) {
            (Some(r), _) if *r == route.name => 2,
            (Some(_), _) => continue,
            (None, Some(s)) if *s == route.service => 1,
            (None, Some(_)) => continue,
            (None, None) => 0,
        };
        match chosen.iter_mut().find(|(_, c)| same_kind(c, &p.plugin)) {
            Some(slot) if slot.0 < rank => *slot = (rank, &p.plugin),
            Some(_) => {}
            None => chosen.push((rank, &p.plugin)),
        }
    }
    chosen.into_iter().map(|(_, p)| p.clone()).collect()
}

/// Two policies of the same kind compete; two of different kinds both run.
fn same_kind(a: &Plugin, b: &Plugin) -> bool {
    matches!((a, b), (Plugin::Jwt(_), Plugin::Jwt(_)))
}

/// `host:port` rather than the service name: two services pointing at one upstream share a
/// cluster, and the key says what it is instead of which row first named it.
fn cluster_key(service: &StoreService) -> String {
    format!("{}:{}", service.host, service.port)
}

/// Kong's OR-of-each-list into Gateway API's list-of-AND-matches: one entry per combination.
fn expand(route: &StoreRoute) -> Vec<RouteMatch> {
    let paths = if route.paths.is_empty() {
        vec![PathMatch::Prefix("/".to_string())]
    } else {
        route.paths.clone()
    };
    let methods: Vec<Option<String>> = if route.methods.is_empty() {
        vec![None]
    } else {
        route.methods.iter().map(|m| Some(m.clone())).collect()
    };
    let mut out = Vec::with_capacity(paths.len() * methods.len());
    for path in &paths {
        for method in &methods {
            out.push(RouteMatch {
                path: path.clone(),
                headers: Vec::new(),
                query: Vec::new(),
                method: method.clone(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::{RegexMap, RequestAttrs};

    fn svc(name: &str, host: &str, port: u16) -> StoreService {
        StoreService {
            name: name.into(),
            protocol: Protocol::Http,
            host: host.into(),
            port,
        }
    }

    fn route(name: &str, service: &str, path: &str, priority: i32) -> StoreRoute {
        StoreRoute {
            name: name.into(),
            service: service.into(),
            hosts: Vec::new(),
            paths: vec![PathMatch::Prefix(path.into())],
            methods: Vec::new(),
            priority,
        }
    }

    fn hit<'a>(
        cfg: &'a Config,
        port: u16,
        host: &str,
        path: &str,
        method: &str,
    ) -> Option<&'a str> {
        let headers: Vec<(String, String)> = Vec::new();
        let query: Vec<(String, String)> = Vec::new();
        cfg.match_port_with(
            port,
            &RequestAttrs {
                host,
                path,
                method,
                headers: &headers,
                query: &query,
            },
            &RegexMap::default(),
        )
        .map(|m| m.rule.route.as_str())
    }

    /// The whole point: what comes out of `compile` has to be routable, not merely well shaped.
    /// Asserting on the struct alone would pass for a table that matches nothing.
    #[test]
    fn a_compiled_config_actually_routes() {
        let snap = StoreSnapshot {
            plugins: Vec::new(),
            services: vec![svc("orders", "orders.internal", 8080)],
            routes: vec![route("orders-api", "orders", "/orders", 0)],
        };
        let cfg = compile(&snap, &StoreSettings::default());
        assert_eq!(
            hit(&cfg, 80, "any.example", "/orders/42", "GET"),
            Some("orders-api")
        );
        assert_eq!(hit(&cfg, 80, "any.example", "/other", "GET"), None);
    }

    /// The data plane resolves the name; the control plane cannot. Empty endpoints here is the
    /// correct starting state and yields 503 until resolution fills it.
    #[test]
    fn a_service_becomes_a_cluster_the_data_plane_must_resolve() {
        let snap = StoreSnapshot {
            plugins: Vec::new(),
            services: vec![svc("orders", "orders.internal", 8080)],
            routes: vec![route("orders-api", "orders", "/", 0)],
        };
        let cfg = compile(&snap, &StoreSettings::default());
        let cluster = &cfg.clusters["orders.internal:8080"];
        assert!(
            cluster.endpoints.is_empty(),
            "nothing is resolved at compile time"
        );
        assert_eq!(
            cluster.resolve,
            Some(ResolveTarget {
                host: "orders.internal".into(),
                port: 8080
            })
        );
    }

    /// Two routes that both match: the higher priority has to win, or the explicit ordering the
    /// schema chose over Gateway API's derived precedence buys nothing.
    #[test]
    fn higher_priority_wins_over_a_route_that_also_matches() {
        let snap = StoreSnapshot {
            plugins: Vec::new(),
            services: vec![svc("v1", "v1.internal", 80), svc("v2", "v2.internal", 80)],
            routes: vec![
                route("catch-all", "v1", "/", 0),
                route("specific", "v2", "/", 10),
            ],
        };
        let cfg = compile(&snap, &StoreSettings::default());
        assert_eq!(hit(&cfg, 80, "any", "/anything", "GET"), Some("specific"));
    }

    /// Row order must not reach the output, or two replicas querying the same rows could serve
    /// different orderings and the same request would go to different places.
    #[test]
    fn equal_priority_is_broken_by_name_not_by_row_order() {
        let services = vec![svc("a", "a.internal", 80), svc("b", "b.internal", 80)];
        let forwards = StoreSnapshot {
            plugins: Vec::new(),
            services: services.clone(),
            routes: vec![route("aaa", "a", "/", 5), route("bbb", "b", "/", 5)],
        };
        let backwards = StoreSnapshot {
            plugins: Vec::new(),
            services,
            routes: vec![route("bbb", "b", "/", 5), route("aaa", "a", "/", 5)],
        };
        let settings = StoreSettings::default();
        assert_eq!(
            compile(&forwards, &settings),
            compile(&backwards, &settings)
        );
        assert_eq!(
            hit(&compile(&forwards, &settings), 80, "any", "/x", "GET"),
            Some("aaa")
        );
    }

    /// A rule whose backend cannot exist can only 500. Dropping it is the backstop for a console
    /// that should have refused the write.
    #[test]
    fn a_route_naming_a_missing_service_is_dropped() {
        let snap = StoreSnapshot {
            plugins: Vec::new(),
            services: vec![svc("orders", "orders.internal", 80)],
            routes: vec![route("ghost", "does-not-exist", "/", 0)],
        };
        let cfg = compile(&snap, &StoreSettings::default());
        assert!(cfg.clusters.is_empty());
        assert_eq!(hit(&cfg, 80, "any", "/", "GET"), None);
    }

    /// Kong's lists are ORs and Gateway API's matches are ANDs, so the compile has to expand the
    /// combinations. Two hosts, two paths and two methods is eight entries, and every one of
    /// them has to match.
    #[test]
    fn hosts_paths_and_methods_expand_into_every_combination() {
        let snap = StoreSnapshot {
            plugins: Vec::new(),
            services: vec![svc("orders", "orders.internal", 80)],
            routes: vec![StoreRoute {
                name: "api".into(),
                service: "orders".into(),
                hosts: vec!["a.example".into(), "b.example".into()],
                paths: vec![
                    PathMatch::Prefix("/v1".into()),
                    PathMatch::Exact("/health".into()),
                ],
                methods: vec!["GET".into(), "POST".into()],
                priority: 0,
            }],
        };
        let cfg = compile(&snap, &StoreSettings::default());
        assert_eq!(cfg.ports[&80].len(), 8);
        assert_eq!(hit(&cfg, 80, "a.example", "/v1/x", "GET"), Some("api"));
        assert_eq!(hit(&cfg, 80, "b.example", "/health", "POST"), Some("api"));
        // The host list is a filter, not decoration.
        assert_eq!(hit(&cfg, 80, "c.example", "/v1/x", "GET"), None);
        // So is the method list.
        assert_eq!(hit(&cfg, 80, "a.example", "/v1/x", "DELETE"), None);
    }

    fn jwt(issuer: &str) -> Plugin {
        Plugin::Jwt(crate::config::JwtPolicy {
            issuer: Some(issuer.into()),
            audience: None,
            jwks: "{}".into(),
        })
    }

    fn issuers(cfg: &Config) -> Vec<String> {
        cfg.listeners[0].rules[0]
            .plugins
            .iter()
            .map(|p| {
                let Plugin::Jwt(j) = p;
                j.issuer.clone().unwrap_or_default()
            })
            .collect()
    }

    /// Narrow beats broad, the precedence Kong settled on and the one an operator expects when
    /// they attach something to a route to override something attached to everything.
    #[test]
    fn a_policy_on_the_route_wins_over_one_on_its_service_and_one_on_everything() {
        let snap = StoreSnapshot {
            services: vec![svc("orders", "orders.internal", 80)],
            routes: vec![route("api", "orders", "/", 0)],
            plugins: vec![
                StorePlugin {
                    route: None,
                    service: None,
                    plugin: jwt("global"),
                },
                StorePlugin {
                    route: None,
                    service: Some("orders".into()),
                    plugin: jwt("service"),
                },
                StorePlugin {
                    route: Some("api".into()),
                    service: None,
                    plugin: jwt("route"),
                },
            ],
        };
        assert_eq!(
            issuers(&compile(&snap, &StoreSettings::default())),
            ["route"]
        );
    }

    #[test]
    fn a_service_policy_wins_over_a_global_one_when_the_route_has_none() {
        let snap = StoreSnapshot {
            services: vec![svc("orders", "orders.internal", 80)],
            routes: vec![route("api", "orders", "/", 0)],
            plugins: vec![
                StorePlugin {
                    route: None,
                    service: None,
                    plugin: jwt("global"),
                },
                StorePlugin {
                    route: None,
                    service: Some("orders".into()),
                    plugin: jwt("service"),
                },
            ],
        };
        assert_eq!(
            issuers(&compile(&snap, &StoreSettings::default())),
            ["service"]
        );
    }

    /// A policy attached to another route or another service must not leak onto this one.
    #[test]
    fn a_policy_attached_elsewhere_does_not_apply_here() {
        let snap = StoreSnapshot {
            services: vec![svc("orders", "a", 80), svc("billing", "b", 80)],
            routes: vec![route("api", "orders", "/", 0)],
            plugins: vec![
                StorePlugin {
                    route: Some("other".into()),
                    service: None,
                    plugin: jwt("wrong-route"),
                },
                StorePlugin {
                    route: None,
                    service: Some("billing".into()),
                    plugin: jwt("wrong-service"),
                },
            ],
        };
        assert!(issuers(&compile(&snap, &StoreSettings::default())).is_empty());
    }

    /// "Most specific wins" is per kind. Overriding one policy must not silently drop the others,
    /// which is the failure that turns a narrow tweak into an open route.
    #[test]
    fn overriding_one_kind_leaves_other_kinds_alone() {
        // Only one kind exists today, so this pins the shape rather than the behaviour: two
        // global policies of the same kind collapse to one, and the count is what a second kind
        // would change.
        let snap = StoreSnapshot {
            services: vec![svc("orders", "orders.internal", 80)],
            routes: vec![route("api", "orders", "/", 0)],
            plugins: vec![
                StorePlugin {
                    route: None,
                    service: None,
                    plugin: jwt("first"),
                },
                StorePlugin {
                    route: None,
                    service: None,
                    plugin: jwt("second"),
                },
            ],
        };
        let got = issuers(&compile(&snap, &StoreSettings::default()));
        assert_eq!(got.len(), 1, "two of one kind compete rather than stacking");
    }

    /// Every bound port carries every route, and each listener's table indexes its own listener.
    #[test]
    fn every_bound_port_gets_the_same_routes() {
        let snap = StoreSnapshot {
            plugins: Vec::new(),
            services: vec![svc("orders", "orders.internal", 80)],
            routes: vec![route("api", "orders", "/", 0)],
        };
        let cfg = compile(
            &snap,
            &StoreSettings {
                http_ports: vec![80, 8080],
            },
        );
        assert_eq!(cfg.listeners.len(), 2);
        assert_eq!(hit(&cfg, 80, "any", "/", "GET"), Some("api"));
        assert_eq!(hit(&cfg, 8080, "any", "/", "GET"), Some("api"));
        assert_eq!(
            cfg.ports[&8080][0].listener, 1,
            "an entry must index its own listener"
        );
    }
}
