//! Compiling a store-shaped configuration into the [`Config`] the data plane serves.
//!
//! [`translate()`](crate::translate()) does this from Gateway API resources. This does it from the
//! objects stored in Postgres: Kong's shape, where a route names a service and a service names
//! an upstream. Same output type, same purity -- no I/O, no clock, no async -- so both paths are
//! covered by fixtures rather than by a running cluster.
//!
//! What this deliberately does not do is talk to a database. The rows come in as plain data, so
//! `gapura-core` keeps no dependency on sqlx and these tests need no Postgres.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::{
    Cluster, ClusterTls, Config, Filters, KeyAuthPolicy, KvMatch, ListenerConfig, PathMatch,
    Plugin, PortEntry, Protocol, RateLimit, ResolveTarget, Rewrite, RouteMatch, RouteRule,
    Timeouts, WeightedBackend,
};

/// Where traffic goes. `host` is resolved by the data plane, not here; see [`Cluster::resolve`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoreService {
    /// The workspace this row belongs to. Names are unique only within a workspace, so every
    /// lookup in [`compile`] is by workspace and name together. Empty for a snapshot that has no
    /// workspaces, which is then one workspace.
    #[serde(default)]
    pub workspace: String,
    pub name: String,
    pub protocol: Protocol,
    pub host: String,
    pub port: u16,
    /// Milliseconds. `None` keeps the data plane's default.
    #[serde(default)]
    pub connect_timeout_ms: Option<u32>,
    /// Milliseconds, the upstream read and write timeout. `None` keeps the data plane's default.
    #[serde(default)]
    pub read_timeout_ms: Option<u32>,
    /// `https` only: whether the upstream's certificate and name are checked. `false` encrypts
    /// without verifying, as the `gapura.dev/backend-tls: insecure` annotation does.
    #[serde(default = "verify_by_default")]
    pub tls_verify: bool,
    /// `https` only: PEM CA certificates to verify the upstream against; `None` = the process
    /// trust store.
    #[serde(default)]
    pub tls_ca_pem: Option<String>,
    /// `https` only: the name sent as SNI and checked against the certificate; `None` = `host`.
    #[serde(default)]
    pub tls_sni: Option<String>,
}

fn verify_by_default() -> bool {
    true
}

/// What traffic goes there. Kong's semantics: a request matches when it matches any of the
/// hosts, any of the paths and any of the methods, and an empty list means "any".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoreRoute {
    /// The workspace this row belongs to. Names are unique only within a workspace, so every
    /// lookup in [`compile`] is by workspace and name together. Empty for a snapshot that has no
    /// workspaces, which is then one workspace.
    #[serde(default)]
    pub workspace: String,
    pub name: String,
    /// [`StoreService::name`]. A route naming a service that does not exist is dropped.
    pub service: String,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub paths: Vec<PathMatch>,
    #[serde(default)]
    pub methods: Vec<String>,
    /// Request headers that must all be present with exactly these values -- an AND, unlike the
    /// lists above, and on every host, path and method combination. Names are matched ignoring
    /// case and compiled lowercase; values are compared exactly. Empty means any headers.
    #[serde(default)]
    pub headers: Vec<KvMatch>,
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
    /// The workspace this policy belongs to; it applies to routes of that workspace only.
    #[serde(default)]
    pub workspace: String,
    /// [`StoreRoute::name`], when this is attached to one route.
    #[serde(default)]
    pub route: Option<String>,
    /// [`StoreService::name`], when this is attached to every route using one service.
    #[serde(default)]
    pub service: Option<String>,
    pub plugin: Plugin,
}

/// A request limit, attached as a [`StorePlugin`] is: to one route, to every route of one service,
/// or to neither and so to every route in the workspace, the most specific winning.
///
/// Not a [`Plugin`]: the data plane enforces [`RouteRule::rate_limit`], the field the Kubernetes
/// `gapura.dev/rate-limit` annotation sets, rather than running something from the plugin list.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoreRateLimit {
    /// The workspace this limit belongs to; it applies to routes of that workspace only.
    #[serde(default)]
    pub workspace: String,
    /// [`StoreRoute::name`], when this is attached to one route.
    #[serde(default)]
    pub route: Option<String>,
    /// [`StoreService::name`], when this is attached to every route using one service.
    #[serde(default)]
    pub service: Option<String>,
    pub limit: RateLimit,
}

/// One issued API key. The hash, never the key: the console shows a key once when it mints it
/// and stores only this, so nothing downstream -- including the data plane's disk cache -- ever
/// holds something that could be presented.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoreCredential {
    /// SHA-256 of the key, hex.
    pub key_hash: String,
    /// The consumer's username, which is what an upstream is told. There is no consumer
    /// type here: the store has the rows, and all the data plane needs is the name.
    pub consumer: String,
    /// The consumer's workspace. A key opens `key_auth` routes of this workspace only.
    #[serde(default)]
    pub workspace: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct StoreSnapshot {
    pub services: Vec<StoreService>,
    pub routes: Vec<StoreRoute>,
    #[serde(default)]
    pub plugins: Vec<StorePlugin>,
    #[serde(default)]
    pub credentials: Vec<StoreCredential>,
    #[serde(default)]
    pub rate_limits: Vec<StoreRateLimit>,
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
    // Keyed by workspace and name together: names are unique only within a workspace, and keyed
    // by name alone two workspaces' `orders` services collapsed into one -- whichever row came
    // last -- so a route in one workspace could be sent to the other's upstream.
    let services: BTreeMap<(&str, &str), &StoreService> = snap
        .services
        .iter()
        .map(|s| ((s.workspace.as_str(), s.name.as_str()), s))
        .collect();

    // A route naming a service that is not there is dropped. This is load-bearing rather than
    // tidy: the lookup below indexes `services` directly, so without this filter a dangling
    // reference panics the compile and takes the control plane's endpoint down with it. A
    // foreign key should make it unreachable and the console should refuse it first; this is
    // what stands between those two being wrong and a crash.
    let mut routes: Vec<&StoreRoute> = snap
        .routes
        .iter()
        .filter(|r| services.contains_key(&(r.workspace.as_str(), r.service.as_str())))
        .collect();
    // Highest priority first, then by name, so the table is a function of the rows and not of
    // the order a query happened to return them.
    routes.sort_by(|a, b| {
        b.priority
            .cmp(&a.priority)
            .then_with(|| a.workspace.cmp(&b.workspace))
            .then_with(|| a.name.cmp(&b.name))
    });

    let mut clusters = BTreeMap::new();
    let mut rules = Vec::with_capacity(routes.len());
    // Built once against rule indices, then cloned per listener: every listener carries every
    // route, so the table is identical and only the listener index differs.
    let mut table: Vec<(Option<String>, RouteMatch, usize)> = Vec::new();

    for route in &routes {
        let service = services[&(route.workspace.as_str(), route.service.as_str())];
        let key = cluster_key(service);
        clusters.entry(key.clone()).or_insert_with(|| Cluster {
            // Nothing is resolved yet, which is why this is empty and not an error. The data
            // plane fills it, and until it does these requests get 503.
            endpoints: Vec::new(),
            // By default verified against the process trust store with the host as SNI, as a
            // `BackendTLSPolicy` naming the system CAs is: an `https` service that answered with
            // any certificate at all would be no different from plain HTTP to anyone on the
            // path. A service may name its own CAs and SNI, or opt out of verifying, and
            // `cluster_key` covers each of those, since clusters are shared first-wins.
            tls: (service.protocol == Protocol::Https).then(|| ClusterTls {
                sni: sni(service).to_string(),
                ca_pem: ca_pem(service).map(str::to_string),
                insecure: !service.tls_verify,
            }),
            resolve: Some(ResolveTarget {
                host: service.host.clone(),
                port: service.port,
            }),
        });

        let matches = expand(route);
        let rule_index = rules.len();
        let plugins = plugins_for(&snap.plugins, route);
        rules.push(RouteRule {
            route: route_id(route),
            rule_index,
            // Gateway API breaks precedence ties on creation time. The store breaks them on an
            // explicit priority, so there is nothing to put here and nothing that reads it.
            creation_timestamp: String::new(),
            matches: matches.clone(),
            // Kong's default (`preserve_host = false`): the upstream is addressed by the
            // service's own host, not by whatever name the client used to reach the gateway.
            filters: Filters {
                rewrite: Some(Rewrite {
                    hostname: Some(upstream_authority(service)),
                    path: None,
                }),
                ..Filters::default()
            },
            backends: vec![WeightedBackend {
                cluster: Some(key),
                weight: 1,
            }],
            timeouts: Timeouts {
                connect_ms: service.connect_timeout_ms.map(u64::from),
                backend_request_ms: service.read_timeout_ms.map(u64::from),
                request_ms: None,
            },
            rate_limit: rate_limit_for(&snap.rate_limits, route),
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
        credentials: snap
            .credentials
            .iter()
            .map(|c| (c.key_hash.clone(), c.consumer.clone()))
            .collect(),
        credential_workspaces: snap
            .credentials
            .iter()
            .filter(|c| !c.workspace.is_empty())
            .map(|c| (c.key_hash.clone(), c.workspace.clone()))
            .collect(),
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
        let Some(rank) = rank(
            &p.workspace,
            p.route.as_deref(),
            p.service.as_deref(),
            route,
        ) else {
            continue;
        };
        match chosen.iter_mut().find(|(_, c)| same_kind(c, &p.plugin)) {
            Some(slot) if slot.0 < rank => *slot = (rank, &p.plugin),
            Some(_) => {}
            None => chosen.push((rank, &p.plugin)),
        }
    }
    chosen
        .into_iter()
        .map(|(_, p)| match p {
            // A key opens the routes of its consumer's workspace and no other's: the policy
            // carries the workspace it was written in, and the data plane checks the key's.
            Plugin::KeyAuth(policy) if !route.workspace.is_empty() => {
                Plugin::KeyAuth(KeyAuthPolicy {
                    workspace: Some(route.workspace.clone()),
                    ..policy.clone()
                })
            }
            other => other.clone(),
        })
        .collect()
}

/// The request limit that applies to one route: the most specific, as [`plugins_for`] picks a
/// policy of one kind, and the first of two equally specific ones. `None` when there is none,
/// which is no limit.
fn rate_limit_for(all: &[StoreRateLimit], route: &StoreRoute) -> Option<RateLimit> {
    let mut chosen: Option<(u8, &RateLimit)> = None;
    for l in all {
        let Some(rank) = rank(
            &l.workspace,
            l.route.as_deref(),
            l.service.as_deref(),
            route,
        ) else {
            continue;
        };
        if chosen.is_none_or(|(best, _)| best < rank) {
            chosen = Some((rank, &l.limit));
        }
    }
    chosen.map(|(_, limit)| limit.clone())
}

/// How specifically a policy attached to `on_route` or `on_service` in `workspace` applies to
/// `route`: 2 on the route itself, 1 on its service, 0 on the whole workspace, `None` when it
/// does not apply at all.
fn rank(
    workspace: &str,
    on_route: Option<&str>,
    on_service: Option<&str>,
    route: &StoreRoute,
) -> Option<u8> {
    // A policy belongs to one workspace. Without this a policy attached to neither a route nor a
    // service -- "every route in the workspace" -- applied to every route in every workspace, and
    // a route-level one applied to a same-named route anywhere.
    if workspace != route.workspace {
        return None;
    }
    match (on_route, on_service) {
        (Some(r), _) => (r == route.name).then_some(2),
        (None, Some(s)) => (s == route.service).then_some(1),
        (None, None) => Some(0),
    }
}

/// Two policies of the same kind compete; two of different kinds both run.
fn same_kind(a: &Plugin, b: &Plugin) -> bool {
    matches!(
        (a, b),
        (Plugin::Jwt(_), Plugin::Jwt(_)) | (Plugin::KeyAuth(_), Plugin::KeyAuth(_))
    )
}

/// The cluster a service's traffic goes to. Plain HTTP keeps the `host:port` key it always had;
/// HTTPS is keyed apart, so a TLS pool and a plain one to the same address are never one pool.
/// Keyed by address rather than service name: two services pointing at one upstream share a
/// cluster, and the key says what it is instead of which row first named it.
///
/// Clusters are shared first-wins, so an `https` key also carries every TLS setting that is not
/// the default -- `?sni=…&ca=…&insecure`, only the parts that differ -- and two services that
/// differ in any of them never share a pool. The defaults keep the bare `https://host:port`, so
/// configurations written before these settings existed keep their keys and their ETags. The CA
/// bundle is named by the first 16 hex digits of its SHA-256 rather than spelled out.
fn cluster_key(service: &StoreService) -> String {
    let address = format!("{}:{}", service.host, service.port);
    if service.protocol == Protocol::Http {
        return address;
    }
    let mut settings = Vec::new();
    let sni = sni(service);
    if sni != service.host {
        settings.push(format!("sni={sni}"));
    }
    if let Some(pem) = ca_pem(service) {
        let digest = Sha256::digest(pem.as_bytes());
        let short: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
        settings.push(format!("ca={short}"));
    }
    if !service.tls_verify {
        settings.push("insecure".to_string());
    }
    if settings.is_empty() {
        format!("https://{address}")
    } else {
        format!("https://{address}?{}", settings.join("&"))
    }
}

/// The name an `https` service's upstream is reached and checked by: its own SNI, else its host.
fn sni(service: &StoreService) -> &str {
    match service.tls_sni.as_deref() {
        Some(sni) if !sni.is_empty() => sni,
        _ => &service.host,
    }
}

/// An `https` service's own CA bundle; an empty one is none, which is the process trust store.
fn ca_pem(service: &StoreService) -> Option<&str> {
    service.tls_ca_pem.as_deref().filter(|pem| !pem.is_empty())
}

/// The `Host` an upstream is sent: the service's host, with the port only when it is not the
/// protocol's default, as a browser would write it.
fn upstream_authority(service: &StoreService) -> String {
    let default_port = match service.protocol {
        Protocol::Https => 443,
        Protocol::Http => 80,
    };
    if service.port == default_port {
        service.host.clone()
    } else {
        format!("{}:{}", service.host, service.port)
    }
}

/// What a rule is called in the served configuration, its metrics and its access log:
/// `workspace/name`, as the Kubernetes path says `namespace/name`, so two workspaces' `orders`
/// routes are told apart. A snapshot without workspaces keeps the bare name.
fn route_id(route: &StoreRoute) -> String {
    if route.workspace.is_empty() {
        route.name.clone()
    } else {
        format!("{}/{}", route.workspace, route.name)
    }
}

/// Kong's OR-of-each-list into Gateway API's list-of-AND-matches: one entry per combination.
/// The header matches are already an AND, so every combination carries all of them.
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
    // Lowercase, as `RouteMatch` documents and the Gateway API path writes them: the data plane
    // compares names ignoring case either way, but one spelling keeps equal routes equal bytes.
    let headers: Vec<KvMatch> = route
        .headers
        .iter()
        .map(|h| KvMatch {
            name: h.name.to_ascii_lowercase(),
            value: h.value.clone(),
        })
        .collect();
    let mut out = Vec::with_capacity(paths.len() * methods.len());
    for path in &paths {
        for method in &methods {
            out.push(RouteMatch {
                path: path.clone(),
                headers: headers.clone(),
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
            workspace: String::new(),
            name: name.into(),
            protocol: Protocol::Http,
            host: host.into(),
            port,
            connect_timeout_ms: None,
            read_timeout_ms: None,
            tls_verify: true,
            tls_ca_pem: None,
            tls_sni: None,
        }
    }

    fn route(name: &str, service: &str, path: &str, priority: i32) -> StoreRoute {
        StoreRoute {
            workspace: String::new(),
            name: name.into(),
            service: service.into(),
            hosts: Vec::new(),
            paths: vec![PathMatch::Prefix(path.into())],
            methods: Vec::new(),
            headers: Vec::new(),
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

    fn in_ws<T>(ws: &str, mut row: T, set: impl FnOnce(&mut T, String)) -> T {
        set(&mut row, ws.to_string());
        row
    }

    fn ws_svc(ws: &str, name: &str, host: &str) -> StoreService {
        in_ws(ws, svc(name, host, 8080), |s, w| s.workspace = w)
    }

    fn ws_route(ws: &str, name: &str, service: &str, host: &str) -> StoreRoute {
        let mut r = in_ws(ws, route(name, service, "/", 0), |r, w| r.workspace = w);
        r.hosts = vec![host.into()];
        r
    }

    fn key_auth(ws: &str, route: Option<&str>) -> StorePlugin {
        StorePlugin {
            workspace: ws.into(),
            route: route.map(str::to_string),
            service: None,
            plugin: Plugin::KeyAuth(crate::config::KeyAuthPolicy::default()),
        }
    }

    fn plugins_on<'a>(cfg: &'a Config, route_id: &str) -> &'a [Plugin] {
        cfg.listeners[0]
            .rules
            .iter()
            .find(|r| r.route == route_id)
            .map(|r| r.plugins.as_slice())
            .unwrap_or_else(|| panic!("no rule {route_id}"))
    }

    #[test]
    fn timeouts_of_a_service_reach_every_rule_of_its_routes() {
        let mut orders = svc("orders", "orders.internal", 8080);
        orders.connect_timeout_ms = Some(2000);
        orders.read_timeout_ms = Some(15000);
        let snap = StoreSnapshot {
            services: vec![orders],
            routes: vec![route("a", "orders", "/a", 0), route("b", "orders", "/b", 0)],
            ..Default::default()
        };
        let cfg = compile(&snap, &StoreSettings::default());
        assert_eq!(cfg.listeners[0].rules.len(), 2);
        for rule in &cfg.listeners[0].rules {
            assert_eq!(rule.timeouts.connect_ms, Some(2000));
            assert_eq!(rule.timeouts.backend_request_ms, Some(15000));
            assert_eq!(rule.timeouts.request_ms, None);
        }
    }

    #[test]
    fn the_upstream_is_sent_the_service_s_host_with_a_port_only_when_it_is_not_the_default() {
        let orders = svc("orders", "orders.internal", 8080);
        let mut secure = svc("secure", "api.internal", 443);
        secure.protocol = Protocol::Https;
        let snap = StoreSnapshot {
            services: vec![orders, secure],
            routes: vec![route("o", "orders", "/o", 0), route("s", "secure", "/s", 0)],
            ..Default::default()
        };
        let cfg = compile(&snap, &StoreSettings::default());
        let host_of = |id: &str| {
            let rule = cfg.listeners[0].rules.iter().find(|r| r.route == id);
            let rewrite = rule.expect("rule").filters.rewrite.as_ref();
            let rewrite = rewrite.expect("a rewrite");
            assert!(rewrite.path.is_none());
            rewrite.hostname.clone()
        };
        assert_eq!(host_of("o").as_deref(), Some("orders.internal:8080"));
        assert_eq!(host_of("s").as_deref(), Some("api.internal"));
    }

    #[test]
    fn an_https_service_is_reached_over_verified_tls_in_a_pool_of_its_own() {
        let mut secure = svc("secure", "api.internal", 443);
        secure.protocol = Protocol::Https;
        let plain = svc("plain", "api.internal", 443);
        let snap = StoreSnapshot {
            services: vec![secure, plain],
            routes: vec![route("s", "secure", "/s", 0), route("p", "plain", "/p", 0)],
            ..Default::default()
        };
        let cfg = compile(&snap, &StoreSettings::default());
        let tls = cfg.clusters["https://api.internal:443"]
            .tls
            .as_ref()
            .expect("tls");
        assert_eq!(tls.sni, "api.internal");
        assert!(!tls.insecure);
        assert!(tls.ca_pem.is_none());
        assert!(cfg.clusters["api.internal:443"].tls.is_none());
    }

    const CA_A: &str = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    const CA_B: &str = "-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n";

    fn https(name: &str, set: impl FnOnce(&mut StoreService)) -> StoreService {
        let mut s = svc(name, "api.internal", 443);
        s.protocol = Protocol::Https;
        set(&mut s);
        s
    }

    /// The one cluster `service` compiles to, and its key.
    fn cluster_of(service: StoreService) -> (String, Cluster) {
        let snap = StoreSnapshot {
            routes: vec![route("r", &service.name, "/", 0)],
            services: vec![service],
            ..Default::default()
        };
        let cfg = compile(&snap, &StoreSettings::default());
        assert_eq!(cfg.clusters.len(), 1);
        cfg.clusters.into_iter().next().expect("a cluster")
    }

    #[test]
    fn each_tls_setting_of_a_service_reaches_its_cluster() {
        let (_, c) = cluster_of(https("s", |s| s.tls_sni = Some("origin.example".into())));
        let tls = c.tls.expect("tls");
        assert_eq!(
            (tls.sni.as_str(), tls.ca_pem.as_deref(), tls.insecure),
            ("origin.example", None, false)
        );
        // The address is still the service's host: SNI changes the name, not where to connect.
        let resolve = c.resolve.expect("resolve");
        assert_eq!((resolve.host.as_str(), resolve.port), ("api.internal", 443));

        let (_, c) = cluster_of(https("s", |s| s.tls_ca_pem = Some(CA_A.into())));
        let tls = c.tls.expect("tls");
        assert_eq!(
            (tls.sni.as_str(), tls.ca_pem.as_deref(), tls.insecure),
            ("api.internal", Some(CA_A), false)
        );

        let (_, c) = cluster_of(https("s", |s| s.tls_verify = false));
        let tls = c.tls.expect("tls");
        assert_eq!(
            (tls.sni.as_str(), tls.ca_pem.as_deref(), tls.insecure),
            ("api.internal", None, true)
        );

        // Empty is none, as the API reads it.
        let (key, c) = cluster_of(https("s", |s| {
            s.tls_sni = Some(String::new());
            s.tls_ca_pem = Some(String::new());
        }));
        let tls = c.tls.expect("tls");
        assert_eq!(
            (tls.sni.as_str(), tls.ca_pem.as_deref()),
            ("api.internal", None)
        );
        assert_eq!(key, "https://api.internal:443");
    }

    #[test]
    fn the_cluster_key_names_the_settings_that_are_not_the_default_and_only_those() {
        let key = |set: fn(&mut StoreService)| cluster_of(https("s", set)).0;
        let ca_a = {
            let digest = Sha256::digest(CA_A.as_bytes());
            digest[..8]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        assert_eq!(
            key(|_| {}),
            "https://api.internal:443",
            "unchanged for the defaults"
        );
        assert_eq!(
            key(|s| s.tls_sni = Some("api.internal".into())),
            "https://api.internal:443",
            "an SNI that is the host is the default"
        );
        assert_eq!(
            key(|s| s.tls_sni = Some("origin.example".into())),
            "https://api.internal:443?sni=origin.example"
        );
        assert_eq!(
            key(|s| s.tls_ca_pem = Some(CA_A.into())),
            format!("https://api.internal:443?ca={ca_a}")
        );
        assert_eq!(ca_a.len(), 16);
        assert_eq!(
            key(|s| s.tls_verify = false),
            "https://api.internal:443?insecure"
        );
        assert_eq!(
            key(|s| {
                s.tls_sni = Some("origin.example".into());
                s.tls_ca_pem = Some(CA_A.into());
                s.tls_verify = false;
            }),
            format!("https://api.internal:443?sni=origin.example&ca={ca_a}&insecure")
        );
        // Plain HTTP has no TLS, whatever the columns say.
        let mut plain = svc("p", "api.internal", 443);
        plain.tls_verify = false;
        plain.tls_sni = Some("origin.example".into());
        assert_eq!(cluster_of(plain).0, "api.internal:443");
    }

    #[test]
    fn two_services_that_differ_only_in_their_ca_get_a_cluster_each() {
        let snap = StoreSnapshot {
            services: vec![
                https("a", |s| s.tls_ca_pem = Some(CA_A.into())),
                https("b", |s| s.tls_ca_pem = Some(CA_B.into())),
                https("system", |_| {}),
            ],
            routes: vec![
                route("ra", "a", "/a", 0),
                route("rb", "b", "/b", 0),
                route("rs", "system", "/s", 0),
            ],
            ..Default::default()
        };
        let cfg = compile(&snap, &StoreSettings::default());
        assert_eq!(cfg.clusters.len(), 3);
        let ca_of = |rule: &str| {
            let rule = cfg.listeners[0].rules.iter().find(|r| r.route == rule);
            let key = rule.expect("rule").backends[0].cluster.as_deref();
            let tls = cfg.clusters[key.expect("a cluster")].tls.as_ref();
            tls.expect("tls").ca_pem.clone()
        };
        assert_eq!(ca_of("ra").as_deref(), Some(CA_A));
        assert_eq!(ca_of("rb").as_deref(), Some(CA_B));
        assert_eq!(ca_of("rs"), None);
    }

    #[test]
    fn a_service_without_tls_settings_reads_as_verified_against_the_trust_store() {
        let service: StoreService = serde_json::from_value(serde_json::json!({
            "name": "s", "protocol": "Https", "host": "api.internal", "port": 443
        }))
        .expect("an older snapshot's service still reads");
        assert!(service.tls_verify);
        assert_eq!((service.tls_ca_pem, service.tls_sni), (None, None));
    }

    #[test]
    fn a_key_auth_policy_carries_its_workspace_and_each_key_its_own() {
        let snap = StoreSnapshot {
            services: vec![ws_svc("team-a", "orders", "orders.a.internal")],
            routes: vec![ws_route("team-a", "api", "orders", "a.example")],
            plugins: vec![key_auth("team-a", None)],
            credentials: vec![
                StoreCredential {
                    key_hash: "hash-a".into(),
                    consumer: "mobile".into(),
                    workspace: "team-a".into(),
                },
                StoreCredential {
                    key_hash: "hash-b".into(),
                    consumer: "mobile".into(),
                    workspace: "team-b".into(),
                },
            ],
            rate_limits: Vec::new(),
        };
        let cfg = compile(&snap, &StoreSettings::default());
        let [Plugin::KeyAuth(policy)] = plugins_on(&cfg, "team-a/api") else {
            panic!("one key_auth policy");
        };
        assert_eq!(policy.workspace.as_deref(), Some("team-a"));
        assert_eq!(cfg.credential_workspaces["hash-a"], "team-a");
        assert_eq!(cfg.credential_workspaces["hash-b"], "team-b");
        // The upstream is still told the bare name: within a workspace it is unique.
        assert_eq!(cfg.credentials["hash-b"], "mobile");
    }

    /// Names are unique per workspace, so two workspaces may both have an `orders` service. Keyed
    /// by name alone they collapsed into whichever row came last, and one workspace's route was
    /// sent to the other's upstream.
    #[test]
    fn two_workspaces_with_the_same_service_name_keep_their_own_upstreams() {
        let snap = StoreSnapshot {
            services: vec![
                ws_svc("team-a", "orders", "orders.a.internal"),
                ws_svc("team-b", "orders", "orders.b.internal"),
            ],
            routes: vec![
                ws_route("team-a", "api", "orders", "a.example"),
                ws_route("team-b", "api", "orders", "b.example"),
            ],
            ..Default::default()
        };
        let cfg = compile(&snap, &StoreSettings::default());
        let backend_of = |id: &str| {
            cfg.listeners[0]
                .rules
                .iter()
                .find(|r| r.route == id)
                .and_then(|r| r.backends[0].cluster.clone())
        };
        assert_eq!(
            backend_of("team-a/api").as_deref(),
            Some("orders.a.internal:8080")
        );
        assert_eq!(
            backend_of("team-b/api").as_deref(),
            Some("orders.b.internal:8080")
        );
        assert_eq!(hit(&cfg, 80, "a.example", "/", "GET"), Some("team-a/api"));
        assert_eq!(hit(&cfg, 80, "b.example", "/", "GET"), Some("team-b/api"));
    }

    /// A route cannot use another workspace's service, even one with the name it asked for.
    #[test]
    fn a_route_does_not_reach_a_service_of_another_workspace() {
        let snap = StoreSnapshot {
            services: vec![ws_svc("team-b", "orders", "orders.b.internal")],
            routes: vec![ws_route("team-a", "api", "orders", "a.example")],
            ..Default::default()
        };
        let cfg = compile(&snap, &StoreSettings::default());
        assert_eq!(hit(&cfg, 80, "a.example", "/", "GET"), None);
    }

    /// A policy attached to neither a route nor a service means every route in its workspace.
    /// It used to mean every route in every workspace, and a route-level one applied to a
    /// same-named route anywhere.
    #[test]
    fn a_policy_applies_only_inside_its_workspace() {
        let snap = StoreSnapshot {
            services: vec![
                ws_svc("team-a", "orders", "orders.a.internal"),
                ws_svc("team-b", "orders", "orders.b.internal"),
            ],
            routes: vec![
                ws_route("team-a", "api", "orders", "a.example"),
                ws_route("team-b", "api", "orders", "b.example"),
            ],
            plugins: vec![key_auth("team-a", None)],
            ..Default::default()
        };
        let cfg = compile(&snap, &StoreSettings::default());
        assert_eq!(plugins_on(&cfg, "team-a/api").len(), 1);
        assert!(
            plugins_on(&cfg, "team-b/api").is_empty(),
            "team-a's policy leaked"
        );

        let snap = StoreSnapshot {
            plugins: vec![key_auth("team-b", Some("api"))],
            ..snap
        };
        let cfg = compile(&snap, &StoreSettings::default());
        assert!(
            plugins_on(&cfg, "team-a/api").is_empty(),
            "matched by route name alone"
        );
        assert_eq!(plugins_on(&cfg, "team-b/api").len(), 1);
    }

    /// The whole point: what comes out of `compile` has to be routable, not merely well shaped.
    /// Asserting on the struct alone would pass for a table that matches nothing.
    #[test]
    fn a_compiled_config_actually_routes() {
        let snap = StoreSnapshot {
            credentials: Vec::new(),
            rate_limits: Vec::new(),
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
            credentials: Vec::new(),
            rate_limits: Vec::new(),
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
            credentials: Vec::new(),
            rate_limits: Vec::new(),
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
            credentials: Vec::new(),
            rate_limits: Vec::new(),
            plugins: Vec::new(),
            services: services.clone(),
            routes: vec![route("aaa", "a", "/", 5), route("bbb", "b", "/", 5)],
        };
        let backwards = StoreSnapshot {
            credentials: Vec::new(),
            rate_limits: Vec::new(),
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
            credentials: Vec::new(),
            rate_limits: Vec::new(),
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
            credentials: Vec::new(),
            rate_limits: Vec::new(),
            plugins: Vec::new(),
            services: vec![svc("orders", "orders.internal", 80)],
            routes: vec![StoreRoute {
                workspace: String::new(),
                name: "api".into(),
                service: "orders".into(),
                hosts: vec!["a.example".into(), "b.example".into()],
                paths: vec![
                    PathMatch::Prefix("/v1".into()),
                    PathMatch::Exact("/health".into()),
                ],
                methods: vec!["GET".into(), "POST".into()],
                headers: Vec::new(),
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

    fn hit_with<'a>(cfg: &'a Config, path: &str, headers: &[(&str, &str)]) -> Option<&'a str> {
        let headers: Vec<(String, String)> = headers
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect();
        let query: Vec<(String, String)> = Vec::new();
        cfg.match_port_with(
            80,
            &RequestAttrs {
                host: "any",
                path,
                method: "GET",
                headers: &headers,
                query: &query,
            },
            &RegexMap::default(),
        )
        .map(|m| m.rule.route.as_str())
    }

    fn kv(name: &str, value: &str) -> KvMatch {
        KvMatch {
            name: name.into(),
            value: value.into(),
        }
    }

    /// The header list is an AND, so it is not one more axis of the expansion: every host, path
    /// and method combination carries all of it, with the names lowercased as `RouteMatch` keeps
    /// them.
    #[test]
    fn a_route_s_headers_reach_every_match_it_expands_to_with_lowercase_names() {
        let mut beta = route("beta", "orders", "/v1", 0);
        beta.hosts = vec!["a.example".into(), "b.example".into()];
        beta.paths.push(PathMatch::Exact("/health".into()));
        beta.methods = vec!["GET".into(), "POST".into()];
        beta.headers = vec![kv("X-Version", "2"), kv("x-Env", "Beta")];
        let snap = StoreSnapshot {
            services: vec![svc("orders", "orders.internal", 80)],
            routes: vec![beta],
            ..Default::default()
        };
        let cfg = compile(&snap, &StoreSettings::default());
        let want = vec![kv("x-version", "2"), kv("x-env", "Beta")];
        assert_eq!(cfg.ports[&80].len(), 8);
        for entry in &cfg.ports[&80] {
            assert_eq!(entry.matcher.headers, want);
        }
        let rule = &cfg.listeners[0].rules[0];
        assert_eq!(rule.matches.len(), 4);
        for m in &rule.matches {
            assert_eq!(m.headers, want);
        }
    }

    #[test]
    fn a_route_with_headers_matches_only_requests_that_carry_every_one_exactly() {
        let mut beta = route("beta", "orders", "/", 0);
        beta.headers = vec![kv("X-Version", "2"), kv("x-env", "Beta")];
        let snap = StoreSnapshot {
            services: vec![svc("orders", "orders.internal", 80)],
            routes: vec![beta, route("stable", "orders", "/", 0)],
            ..Default::default()
        };
        let cfg = compile(&snap, &StoreSettings::default());
        // The beta route sorts first on name; a request without its headers falls through.
        assert_eq!(
            hit_with(&cfg, "/x", &[("x-version", "2"), ("X-Env", "Beta")]),
            Some("beta")
        );
        assert_eq!(hit_with(&cfg, "/x", &[("x-version", "2")]), Some("stable"));
        // The value is compared exactly, case and all.
        assert_eq!(
            hit_with(&cfg, "/x", &[("x-version", "2"), ("x-env", "beta")]),
            Some("stable")
        );
        assert_eq!(hit_with(&cfg, "/x", &[]), Some("stable"));
    }

    /// The ETag is the digest of the compiled bytes, so a route without headers must compile to
    /// exactly what it did before routes had them -- including a route read from a snapshot
    /// written before the field existed -- or every data plane refetches on upgrade for nothing.
    #[test]
    fn a_route_without_headers_compiles_exactly_as_before() {
        let older: StoreRoute = serde_json::from_value(serde_json::json!({
            "name": "api", "service": "orders",
            "paths": [{"Prefix": "/v1"}], "methods": ["GET"], "priority": 0
        }))
        .expect("an older snapshot's route still reads");
        assert!(older.headers.is_empty());
        let snap = StoreSnapshot {
            services: vec![svc("orders", "orders.internal", 8080)],
            routes: vec![older],
            ..Default::default()
        };
        let body = serde_json::to_vec(&compile(&snap, &StoreSettings::default())).unwrap();
        let digest: String = Sha256::digest(&body)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            digest,
            PRE_HEADERS_DIGEST,
            "{}",
            String::from_utf8_lossy(&body)
        );
    }

    /// What the compiler made of that snapshot before routes had headers, computed at the time.
    const PRE_HEADERS_DIGEST: &str =
        "1081010dd85af1cc25660773d6f1f352c96ed5e32b59d29b43415a255b8cf4b2";

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
            .filter_map(|p| match p {
                Plugin::Jwt(j) => Some(j.issuer.clone().unwrap_or_default()),
                Plugin::KeyAuth(_) => None,
            })
            .collect()
    }

    /// Narrow beats broad, the precedence Kong settled on and the one an operator expects when
    /// they attach something to a route to override something attached to everything.
    #[test]
    fn a_policy_on_the_route_wins_over_one_on_its_service_and_one_on_everything() {
        let snap = StoreSnapshot {
            credentials: Vec::new(),
            rate_limits: Vec::new(),
            services: vec![svc("orders", "orders.internal", 80)],
            routes: vec![route("api", "orders", "/", 0)],
            plugins: vec![
                StorePlugin {
                    workspace: String::new(),
                    route: None,
                    service: None,
                    plugin: jwt("global"),
                },
                StorePlugin {
                    workspace: String::new(),
                    route: None,
                    service: Some("orders".into()),
                    plugin: jwt("service"),
                },
                StorePlugin {
                    workspace: String::new(),
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
            credentials: Vec::new(),
            rate_limits: Vec::new(),
            services: vec![svc("orders", "orders.internal", 80)],
            routes: vec![route("api", "orders", "/", 0)],
            plugins: vec![
                StorePlugin {
                    workspace: String::new(),
                    route: None,
                    service: None,
                    plugin: jwt("global"),
                },
                StorePlugin {
                    workspace: String::new(),
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
            credentials: Vec::new(),
            rate_limits: Vec::new(),
            services: vec![svc("orders", "a", 80), svc("billing", "b", 80)],
            routes: vec![route("api", "orders", "/", 0)],
            plugins: vec![
                StorePlugin {
                    workspace: String::new(),
                    route: Some("other".into()),
                    service: None,
                    plugin: jwt("wrong-route"),
                },
                StorePlugin {
                    workspace: String::new(),
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
            credentials: Vec::new(),
            rate_limits: Vec::new(),
            services: vec![svc("orders", "orders.internal", 80)],
            routes: vec![route("api", "orders", "/", 0)],
            plugins: vec![
                StorePlugin {
                    workspace: String::new(),
                    route: None,
                    service: None,
                    plugin: jwt("first"),
                },
                StorePlugin {
                    workspace: String::new(),
                    route: None,
                    service: None,
                    plugin: jwt("second"),
                },
            ],
        };
        let got = issuers(&compile(&snap, &StoreSettings::default()));
        assert_eq!(got.len(), 1, "two of one kind compete rather than stacking");
    }

    fn limit(limit: u32, window_ms: u64) -> RateLimit {
        RateLimit { limit, window_ms }
    }

    fn rate_limit(
        ws: &str,
        route: Option<&str>,
        service: Option<&str>,
        per_minute: u32,
    ) -> StoreRateLimit {
        StoreRateLimit {
            workspace: ws.into(),
            route: route.map(str::to_string),
            service: service.map(str::to_string),
            limit: limit(per_minute, 60_000),
        }
    }

    fn rate_limit_on(cfg: &Config, route_id: &str) -> Option<RateLimit> {
        cfg.listeners[0]
            .rules
            .iter()
            .find(|r| r.route == route_id)
            .unwrap_or_else(|| panic!("no rule {route_id}"))
            .rate_limit
            .clone()
    }

    /// A limit on the workspace reaches every rule of that workspace, on every listener, and no
    /// rule of another; it is the rule's field, not a plugin.
    #[test]
    fn a_stored_rate_limit_reaches_the_rules_it_covers() {
        let snap = StoreSnapshot {
            services: vec![
                ws_svc("a", "orders", "a.internal"),
                ws_svc("b", "orders", "b.internal"),
            ],
            routes: vec![
                ws_route("a", "api", "orders", "a.example"),
                ws_route("a", "web", "orders", "w.example"),
                ws_route("b", "api", "orders", "b.example"),
            ],
            rate_limits: vec![StoreRateLimit {
                limit: limit(5, 1_000),
                ..rate_limit("a", None, None, 0)
            }],
            ..Default::default()
        };
        let cfg = compile(
            &snap,
            &StoreSettings {
                http_ports: vec![80, 8080],
            },
        );
        for listener in &cfg.listeners {
            for rule in &listener.rules {
                let want = rule.route.starts_with("a/").then(|| limit(5, 1_000));
                assert_eq!(rule.rate_limit, want, "{}", rule.route);
                assert!(rule.plugins.is_empty(), "{}", rule.route);
            }
        }
    }

    /// Route over service over workspace, as for every policy, and a limit attached to another
    /// route, another service or the same names in another workspace does not apply.
    #[test]
    fn the_most_specific_rate_limit_applies() {
        let routes = vec![
            ws_route("a", "api", "orders", "a.example"),
            ws_route("a", "web", "orders", "w.example"),
            ws_route("a", "pay", "billing", "p.example"),
        ];
        let services = vec![
            ws_svc("a", "orders", "o.internal"),
            ws_svc("a", "billing", "b.internal"),
        ];
        let snap = StoreSnapshot {
            services: services.clone(),
            routes: routes.clone(),
            rate_limits: vec![
                rate_limit("a", None, None, 10),
                rate_limit("a", None, Some("orders"), 20),
                rate_limit("a", Some("api"), None, 30),
                // Elsewhere: another workspace's same names, and a route that is not here.
                rate_limit("b", Some("pay"), None, 99),
                rate_limit("b", None, Some("billing"), 99),
                rate_limit("a", Some("other"), None, 99),
            ],
            ..Default::default()
        };
        let cfg = compile(&snap, &StoreSettings::default());
        assert_eq!(rate_limit_on(&cfg, "a/api"), Some(limit(30, 60_000)));
        assert_eq!(rate_limit_on(&cfg, "a/web"), Some(limit(20, 60_000)));
        assert_eq!(rate_limit_on(&cfg, "a/pay"), Some(limit(10, 60_000)));

        // Row order decides nothing between different specificities.
        let mut reversed = snap.clone();
        reversed.rate_limits.reverse();
        assert_eq!(compile(&reversed, &StoreSettings::default()), cfg);

        // Only the elsewhere ones: no limit at all.
        let elsewhere = StoreSnapshot {
            services,
            routes,
            rate_limits: snap.rate_limits[3..].to_vec(),
            ..Default::default()
        };
        let cfg = compile(&elsewhere, &StoreSettings::default());
        for route in ["a/api", "a/web", "a/pay"] {
            assert_eq!(rate_limit_on(&cfg, route), None, "{route}");
        }
    }

    /// A limit and a policy are independent: a route-level limit leaves a workspace-level policy
    /// in place, and a policy leaves the limit alone.
    #[test]
    fn a_rate_limit_and_a_policy_both_apply() {
        let snap = StoreSnapshot {
            services: vec![svc("orders", "orders.internal", 80)],
            routes: vec![route("api", "orders", "/", 0)],
            plugins: vec![key_auth("", None)],
            rate_limits: vec![rate_limit("", Some("api"), None, 7)],
            ..Default::default()
        };
        let cfg = compile(&snap, &StoreSettings::default());
        assert_eq!(rate_limit_on(&cfg, "api"), Some(limit(7, 60_000)));
        assert!(matches!(plugins_on(&cfg, "api"), [Plugin::KeyAuth(_)]));
    }

    /// A snapshot written before limits existed still reads, and compiles to no limit.
    #[test]
    fn a_snapshot_without_rate_limits_reads_as_none() {
        let older: StoreSnapshot = serde_json::from_value(serde_json::json!({
            "services": [], "routes": [], "plugins": [], "credentials": []
        }))
        .expect("an older snapshot still reads");
        assert!(older.rate_limits.is_empty());
        let snap = StoreSnapshot {
            services: vec![svc("orders", "orders.internal", 80)],
            routes: vec![route("api", "orders", "/", 0)],
            ..older
        };
        let cfg = compile(&snap, &StoreSettings::default());
        assert_eq!(rate_limit_on(&cfg, "api"), None);
        let body = serde_json::to_string(&cfg).unwrap();
        assert!(!body.contains("rate_limit"), "{body}");
    }

    /// Every bound port carries every route, and each listener's table indexes its own listener.
    #[test]
    fn every_bound_port_gets_the_same_routes() {
        let snap = StoreSnapshot {
            credentials: Vec::new(),
            rate_limits: Vec::new(),
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
