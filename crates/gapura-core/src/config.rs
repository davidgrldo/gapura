//! Output of translation: exactly what the data plane needs to route a request. Plain data, serializable.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

// `serde(default)` here and deliberately not on the types below. ADR 2 gives the data plane a
// disk cache, so after an upgrade a new binary reads a configuration an older one wrote, and any
// field added since would otherwise be a missing field that fails the whole load. At the top
// level a missing field sensibly means "none of those". Inside an `Endpoint` it does not: an
// address defaulting to the empty string is a silent hole where failing loudly is correct.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub listeners: Vec<ListenerConfig>,
    /// Match table per listen port, over every programmed listener on that port, sorted once by
    /// Gateway API precedence. The data plane does first-match over the table of the port the
    /// request arrived on; this is what lets two Gateways share a port.
    pub ports: BTreeMap<u16, Vec<PortEntry>>,
    /// Key: `namespace/service:port`.
    pub clusters: BTreeMap<String, Cluster>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ListenerConfig {
    /// `namespace/gateway/listener`.
    pub id: String,
    pub port: u16,
    /// The port the client dialed, when it differs from `port`. `port` is the bound socket; a
    /// listener remapped for an address-per-Gateway Gateway is dialed through a Service that
    /// maps this client-facing port onto it, so anything client-facing (redirect Locations)
    /// must name this one, never `port`. Absent when the two are the same.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_port: Option<u16>,
    pub protocol: Protocol,
    pub hostname: Option<String>,
    pub tls: Option<TlsBundle>,
    pub rules: Vec<RouteRule>,
}

/// One match of one listener inside a port-wide table.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PortEntry {
    /// Index into `Config::listeners`.
    pub listener: usize,
    /// `None` = any host. Already the intersection of the listener hostname and the route
    /// hostnames, so matching this is enough: the listener hostname needs no separate check.
    pub hostname: Option<String>,
    pub matcher: RouteMatch,
    /// Index into `Config::listeners[listener].rules`.
    pub rule: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Http,
    Https,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TlsBundle {
    /// `namespace/name` of the Secret, for logs and status.
    pub secret: String,
    pub cert_pem: String,
    pub key_pem: String,
}

/// Build-time entry: what `translate` collects per listener before the per-port index is built.
/// The data plane matches on `PortEntry`, not on this.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MatchEntry {
    /// `None` = any host.
    pub hostname: Option<String>,
    pub matcher: RouteMatch,
    /// Index into `ListenerConfig::rules`.
    pub rule: usize,
}

/// A per-rule request limit, from the backend Service's `gapura.dev/rate-limit` annotation
/// ("20/min"; seconds, minutes or hours). Enforced by the data plane per replica and keyed by
/// client IP: with N replicas the effective allowance is N x limit, which is the honest shape
/// for a gateway with no database, and `gapura.dev/rate-limit-by: ip` is the only keying.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimit {
    pub limit: u32,
    pub window_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RouteRule {
    /// `namespace/name` of the HTTPRoute.
    pub route: String,
    pub rule_index: usize,
    /// RFC 3339 creationTimestamp of the route, for precedence.
    pub creation_timestamp: String,
    pub matches: Vec<RouteMatch>,
    pub filters: Filters,
    pub backends: Vec<WeightedBackend>,
    pub timeouts: Timeouts,
    /// None means unlimited. Carried per rule so the data plane can enforce at the point the
    /// rule matched, before any upstream work is done.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimit>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RouteMatch {
    pub path: PathMatch,
    /// Header names are stored lowercase.
    pub headers: Vec<KvMatch>,
    /// Query names are case-sensitive.
    pub query: Vec<KvMatch>,
    pub method: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PathMatch {
    Exact(String),
    /// Normalized without trailing slash, except `/` itself.
    Prefix(String),
    /// Pattern string as written in the HTTPRoute; compiled into a side map by the data plane
    /// (see `matcher::compile_regexes`), so this stays plain serializable data.
    Regex(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KvMatch {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Filters {
    pub request_headers: HeaderOps,
    pub response_headers: HeaderOps,
    pub redirect: Option<Redirect>,
    pub rewrite: Option<Rewrite>,
    /// Fire-and-forget copy of the request. Plain data like the rest: the resolved cluster key,
    /// with the endpoint picked by the data plane at fire time.
    pub mirror: Option<Mirror>,
}

/// Where mirrored requests go: a cluster key into `Config::clusters`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Mirror {
    pub cluster: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct HeaderOps {
    pub set: Vec<(String, String)>,
    pub add: Vec<(String, String)>,
    pub remove: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Redirect {
    pub scheme: Option<String>,
    pub hostname: Option<String>,
    pub port: Option<u16>,
    pub status: u16,
    pub path: Option<PathRewrite>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rewrite {
    pub hostname: Option<String>,
    pub path: Option<PathRewrite>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PathRewrite {
    ReplaceFullPath(String),
    ReplacePrefixMatch(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WeightedBackend {
    /// `None` = invalid backendRef. Traffic weighted here gets HTTP 500 (Gateway API spec).
    pub cluster: Option<String>,
    pub weight: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Timeouts {
    pub request_ms: Option<u64>,
    pub backend_request_ms: Option<u64>,
}

/// TLS towards the backend. `None` on the cluster means plain HTTP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterTls {
    /// SNI and, unless `insecure`, the name the server certificate must match.
    pub sni: String,
    /// PEM bundle of CA certificates to verify against; `None` = the process trust store.
    pub ca_pem: Option<String>,
    /// Skip certificate and hostname verification: per-Service opt-in via the
    /// `gapura.dev/backend-tls: insecure` annotation.
    pub insecure: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Cluster {
    /// Sorted, unique. Empty is valid config and yields 503 at runtime.
    pub endpoints: Vec<Endpoint>,
    pub tls: Option<ClusterTls>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Endpoint {
    pub address: String,
    pub port: u16,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_round_trips_through_json() {
        let cfg = Config {
            listeners: vec![ListenerConfig {
                id: "infra/main/http".into(),
                port: 80,
                client_port: None,
                protocol: Protocol::Http,
                hostname: None,
                tls: None,
                rules: vec![RouteRule {
                    route: "apps/echo".into(),
                    rule_index: 0,
                    creation_timestamp: "2026-09-01T10:00:00Z".into(),
                    matches: vec![RouteMatch {
                        path: PathMatch::Prefix("/api".into()),
                        headers: vec![],
                        query: vec![],
                        method: None,
                    }],
                    filters: Filters::default(),
                    backends: vec![WeightedBackend {
                        cluster: Some("apps/echo:80".into()),
                        weight: 1,
                    }],
                    timeouts: Timeouts::default(),
                    rate_limit: None,
                }],
            }],
            ports: BTreeMap::from([(
                80u16,
                vec![PortEntry {
                    listener: 0,
                    hostname: Some("echo.example.com".into()),
                    matcher: RouteMatch {
                        path: PathMatch::Prefix("/api".into()),
                        headers: vec![],
                        query: vec![],
                        method: None,
                    },
                    rule: 0,
                }],
            )]),
            clusters: BTreeMap::from([(
                "apps/echo:80".to_string(),
                Cluster {
                    endpoints: vec![Endpoint {
                        address: "10.1.0.5".into(),
                        port: 8080,
                    }],
                    tls: None,
                },
            )]),
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cfg);
    }

    /// ADR 2 requires an old data plane to keep talking to a new control plane across a
    /// rolling upgrade, and the configuration protocol carries `Config` itself. That promise
    /// is either pinned here or discovered by an operator mid-upgrade.
    #[test]
    fn a_new_control_planes_extra_fields_do_not_break_an_old_data_plane() {
        let cfg = Config::default();
        let mut v = serde_json::to_value(&cfg).unwrap();
        // What a newer control plane would add: a field this binary has never heard of.
        v.as_object_mut()
            .unwrap()
            .insert("something_added_later".into(), serde_json::json!({"a": 1}));
        v["listeners"] = serde_json::json!([]);
        let back: Config = serde_json::from_value(v).expect("unknown fields must be ignored");
        assert_eq!(back, cfg);
    }

    /// The other direction, which is easy to miss: ADR 2 gives the data plane a disk cache, so
    /// after an upgrade a NEW binary reads a config an OLD one wrote. Every field a future
    /// version adds has to be able to be absent, which is what `#[serde(default)]` on the
    /// struct buys. If this fails, the cache stops loading across exactly one upgrade.
    #[test]
    fn a_config_written_by_an_older_binary_still_loads() {
        let empty = serde_json::json!({});
        let back: Config = serde_json::from_value(empty)
            .expect("a Config missing every field must load as the default");
        assert_eq!(back, Config::default());
    }
}
