//! Output of translation: exactly what the data plane needs to route a request. Plain data, serializable.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

// `serde(default)` here and deliberately not on the types below. The data plane keeps a
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
    /// API key credentials: SHA-256 of the key, hex, to the consumer it was issued to.
    ///
    /// Held once for the whole configuration rather than per rule, because a key belongs to a
    /// consumer and not to a route, and duplicating them per rule would multiply the one part of
    /// the configuration that scales with how many callers there are.
    ///
    /// Hashes, never keys: a configuration is written to the data plane's disk cache and read by
    /// whoever can read that file, and a stolen cache should not yield working credentials.
    /// Keyed by the hash directly, with no prefix index -- SHA-256 is deterministic, so the
    /// presented key hashes to exactly the map key. The `key_prefix` column in the store exists
    /// for the SQL side and for showing an operator which key is which; neither is needed here.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub credentials: BTreeMap<String, String>,
    /// The workspace each credential's consumer belongs to, keyed like `credentials`. A
    /// `key_auth` policy that names a workspace accepts only keys listed here under that name.
    ///
    /// A map beside `credentials` rather than a change to its values, so either side can run a
    /// release behind the other: a data plane that predates it ignores it, and a control plane
    /// that predates it sends none, while the policies that would read it name no workspace.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub credential_workspaces: BTreeMap<String, String>,
    /// Request limits that are a consumer's own, keyed `workspace/username` -- the bare username
    /// in a configuration without workspaces -- the form [`RouteRule::route`] names routes in.
    /// Picked by [`Config::rate_limit_for`] once a `key_auth` policy has identified the caller.
    ///
    /// A table beside the rules rather than a variant in each, for the reason `credentials` is
    /// held once: a limit attached to a consumer alone covers every route of its workspace, and
    /// copied into every rule it would multiply by consumers, routes and listeners.
    ///
    /// Absent on the wire while empty, like the two maps above, so a configuration that gives no
    /// consumer a limit of its own serialises byte-for-byte as before and its ETag does not move.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub consumer_rate_limits: BTreeMap<String, ConsumerRateLimits>,
}

/// One consumer's own request limits, which replace a rule's [`RouteRule::rate_limit`] for that
/// consumer: Kong's order, a consumer's limit before any limit on everyone.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsumerRateLimits {
    /// By [`RouteRule::route`]: the consumer's limit on that route, else on that route's
    /// service. The store resolves the two, so the data plane looks up one key.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub routes: BTreeMap<String, RateLimit>,
    /// The consumer's limit on no route or service: every route of its workspace not in
    /// `routes`. No workspace check is needed when it is read, because a consumer is only ever
    /// identified on a route of its own workspace -- a `key_auth` policy accepts that
    /// workspace's keys only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub any: Option<RateLimit>,
}

impl Config {
    /// The request limit for a request `rule` matched, and whether it is the consumer's own:
    /// the consumer's limit on the route, else on its service -- both resolved into
    /// [`ConsumerRateLimits::routes`] -- else on the consumer alone, else the rule's own. That is
    /// Kong's precedence (`plugins_iterator.lua`) restricted to the attachments the store has: a
    /// store route has exactly one service, so Kong's route+service is our route.
    ///
    /// `consumer` is the key [`Config::consumer_rate_limits`] is keyed by, and is known only once
    /// a `key_auth` policy accepted a key. That is why a limit is the only thing that can be a
    /// consumer's own: the policies are what find the consumer out, so none of them can depend
    /// on it, and an anonymous caller never reaches a consumer's limit.
    pub fn rate_limit_for<'a>(
        &'a self,
        rule: &'a RouteRule,
        consumer: Option<&str>,
    ) -> Option<(&'a RateLimit, bool)> {
        let own = consumer
            .and_then(|c| self.consumer_rate_limits.get(c))
            .and_then(|c| c.routes.get(&rule.route).or(c.any.as_ref()));
        match own {
            Some(limit) => Some((limit, true)),
            None => rule.rate_limit.as_ref().map(|limit| (limit, false)),
        }
    }
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

/// A per-rule request limit: from the backend Service's `gapura.dev/rate-limit` annotation
/// ("20/min"; seconds, minutes or hours), or from a store `rate_limit` policy. Enforced by the
/// data plane per replica: with N replicas the effective allowance is N x limit, which is the
/// honest shape for a gateway whose replicas share no counter. The annotation path counts by
/// client IP only (`gapura.dev/rate-limit-by: ip`); a store policy may also count by consumer
/// or by a header, see [`LimitBy`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimit {
    pub limit: u32,
    pub window_ms: u64,
    /// Absent on the wire when it is [`LimitBy::Ip`], so a limit that counts by address
    /// serialises exactly as one written before this field existed.
    #[serde(default, skip_serializing_if = "LimitBy::is_ip")]
    pub by: LimitBy,
}

/// What a [`RateLimit`] counts by: one window per client address, per consumer, or per value of
/// one request header.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitBy {
    /// Each client address, as the access log names it; an IPv6 /64 counts as one.
    #[default]
    Ip,
    /// Each consumer a `key_auth` policy identified. A request no policy identified counts by
    /// address instead, so a route that lets anonymous callers through still limits them.
    Consumer,
    /// Each value of this request header, named in lowercase -- the control plane stores it so,
    /// because it validates the name on write -- and a request without it counts by address.
    /// Only as honest as whoever sets the header: a client that sets it itself picks a fresh
    /// window per value, so this belongs behind a proxy that overwrites it.
    Header(String),
}

impl LimitBy {
    /// Whether this is the default, which [`RateLimit::by`] leaves off the wire (its
    /// `skip_serializing_if`). Public because the crates that build a limit from a store row
    /// decide the same thing when they write one out.
    pub fn is_ip(&self) -> bool {
        matches!(self, LimitBy::Ip)
    }
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
    /// Run in order, after the rule matched and before anything upstream is touched. Empty for
    /// every rule the Kubernetes path produces today: policies arrive from the store.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub plugins: Vec<Plugin>,
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

/// A named policy attached to a rule.
///
/// A typed enum rather than a name and a JSON blob. The spec's SP2 asked for "one policy with
/// typed sections" for the same reason: adding a policy should make the compiler name every
/// place that has to handle it, and a blob makes every one of those places a runtime `match` on
/// a string that can be wrong in production instead of at build time.
///
/// JWT came first deliberately. Two separate things were unproven -- the extension
/// mechanism itself, and the seam that looks a credential up -- and checking a signature needs
/// nothing looked up and nothing stored, so it exercises the first and touches none of the
/// second. Taking both bets in one plugin would have left a failure ambiguous.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Plugin {
    Jwt(JwtPolicy),
    KeyAuth(KeyAuthPolicy),
}

/// Reject a request unless it carries an API key issued to a consumer.
///
/// This came after JWT on purpose: JWT proves the extension mechanism without touching the
/// credential seam, and this is the seam. What it needs that JWT did not is somewhere to look a
/// presented key up -- see [`Config::credentials`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyAuthPolicy {
    /// Where to read the key from. Named rather than fixed because deployments migrating from
    /// another gateway arrive with a header their callers already send.
    pub header: String,
    /// Set by the store from the policy's own workspace: only keys issued to that workspace's
    /// consumers are accepted. `None` accepts any key in the configuration, which is what a
    /// configuration without workspaces means.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<String>,
}

impl Default for KeyAuthPolicy {
    fn default() -> Self {
        Self {
            header: "x-api-key".to_string(),
            workspace: None,
        }
    }
}

/// Reject a request unless it carries a JWT this policy accepts.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct JwtPolicy {
    /// Required `iss`. `None` accepts any issuer, which is almost always a mistake and is
    /// therefore something an operator has to write rather than get by leaving a field out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Required `aud`. `None` accepts any audience.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// A JWKS document, verbatim. Carried rather than fetched so that verification needs no
    /// network at request time and no key material is invented by this crate; a `jwks_uri` that
    /// the data plane refreshes is the next step and replaces only where this string comes from.
    pub jwks: String,
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
    /// How long connecting to an upstream may take, per attempt. For a TLS cluster Pingora applies
    /// the same value separately to the TCP connect and to the TLS handshake, so connecting can
    /// take up to about twice this. Set from a store service; Gateway API has no such field, so Kubernetes mode
    /// leaves it `None`, which keeps the data plane's default. Omitted from the wire when unset, so
    /// a configuration without it serialises byte-for-byte as before and its ETag does not change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_ms: Option<u64>,
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
    /// Store mode only: the name whose resolution fills `endpoints`. `None` under Kubernetes,
    /// where EndpointSlice has already resolved them, and under `--config-dir`.
    ///
    /// The control plane cannot resolve this on a data plane's behalf, because a data plane may
    /// be in another network where the name answers differently or not at all, so the
    /// configuration carries the name and each data plane resolves it for itself. Until it has,
    /// `endpoints` is empty and requests get 503 -- which is the same answer as a backend with
    /// no ready addresses, and correctly so: in both cases there is nowhere to send the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolve: Option<ResolveTarget>,
    /// Passive outlier detection; `None` is `OutlierDetection::default()`. Nothing sets it yet:
    /// it is where a per-service setting will go.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outlier: Option<OutlierDetection>,
}

/// A name for the data plane to resolve into `Cluster::endpoints`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ResolveTarget {
    pub host: String,
    pub port: u16,
}

/// Passive outlier detection for one cluster's endpoints: how many consecutive failures take one
/// out of rotation, for how long, and how much of the cluster may be out before that is ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OutlierDetection {
    /// Consecutive failures (connect error, timeout, 502/503/504) that eject an endpoint. `0`
    /// turns detection off for the cluster.
    pub consecutive_failures: u32,
    /// Consecutive successes after an ejection that clear its history. Until then one failure
    /// ejects it again, for longer.
    pub successes_to_recover: u32,
    /// The nth ejection lasts n times this, up to `max_ejection_ms`.
    pub base_ejection_ms: u64,
    pub max_ejection_ms: u64,
    /// With more than this share of the cluster ejected, ejection is ignored and every endpoint
    /// takes traffic (Envoy's healthy panic): detection that has taken out most of a cluster is
    /// more likely wrong than right, and what is left would take the whole load.
    pub max_ejected_percent: u8,
}

impl Default for OutlierDetection {
    fn default() -> Self {
        Self {
            consecutive_failures: 5,
            successes_to_recover: 5,
            base_ejection_ms: 30_000,
            max_ejection_ms: 300_000,
            max_ejected_percent: 50,
        }
    }
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
                    plugins: vec![],
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
                    resolve: None,
                    outlier: Some(OutlierDetection {
                        consecutive_failures: 3,
                        ..OutlierDetection::default()
                    }),
                },
            )]),
            credentials: BTreeMap::from([("abc123".to_string(), "team-orders".to_string())]),
            credential_workspaces: Default::default(),
            consumer_rate_limits: Default::default(),
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cfg);
    }

    /// An old data plane has to keep talking to a new control plane across a
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

    /// `resolve` is the first field added since the compatibility tests above were written,
    /// so it is the first real exercise of the promise rather than a hypothetical one: a
    /// cluster serialised before it existed must still load.
    #[test]
    fn a_cluster_from_before_resolve_existed_still_loads() {
        let old = serde_json::json!({"endpoints": [], "tls": null});
        let c: Cluster = serde_json::from_value(old).expect("a missing `resolve` must mean None");
        assert_eq!(c.resolve, None);
    }

    /// The same for `outlier`, and the ETag point below: a cluster that leaves it unset must
    /// serialise as before, and one that sets some of it gets the defaults for the rest.
    #[test]
    fn an_unset_outlier_is_absent_on_the_wire_and_a_partial_one_fills_in() {
        let wire = serde_json::to_value(Cluster::default()).unwrap();
        assert!(wire.get("outlier").is_none(), "{wire}");
        let partial = serde_json::json!({"endpoints": [], "tls": null, "outlier": {"consecutive_failures": 3}});
        let c: Cluster = serde_json::from_value(partial).unwrap();
        assert_eq!(
            c.outlier,
            Some(OutlierDetection {
                consecutive_failures: 3,
                ..OutlierDetection::default()
            })
        );
    }

    /// `connect_ms` must stay invisible on the wire while unset: a configuration that does not use
    /// it has to serialise byte-for-byte as before, or its ETag changes for no reason.
    #[test]
    fn an_unset_connect_ms_is_absent_on_the_wire_and_reads_as_none() {
        let old = serde_json::json!({"request_ms": null, "backend_request_ms": null});
        let t: Timeouts =
            serde_json::from_value(old).expect("a missing `connect_ms` must mean None");
        assert_eq!(t.connect_ms, None);
        let wire = serde_json::to_value(Timeouts::default()).unwrap();
        assert!(
            wire.get("connect_ms").is_none(),
            "an unset connect_ms must not be serialised: {wire}"
        );
    }

    /// The other direction, which is easy to miss: the data plane keeps a disk cache, so
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

    fn per_ip(limit: u32) -> RateLimit {
        RateLimit {
            limit,
            window_ms: 60_000,
            by: LimitBy::Ip,
        }
    }

    fn rule(route: &str, limit: Option<RateLimit>) -> RouteRule {
        RouteRule {
            route: route.into(),
            rule_index: 0,
            creation_timestamp: String::new(),
            matches: vec![],
            filters: Filters::default(),
            backends: vec![],
            timeouts: Timeouts::default(),
            rate_limit: limit,
            plugins: vec![],
        }
    }

    /// The consumer's limit on the route, else its limit anywhere, else the rule's own: and the
    /// rule's own for anyone with nothing of their own, or with no consumer identified at all.
    #[test]
    fn a_consumer_s_own_limit_replaces_the_rule_s_and_anyone_else_gets_the_rule_s() {
        let cfg = Config {
            consumer_rate_limits: BTreeMap::from([
                (
                    "shop/mobile".to_string(),
                    ConsumerRateLimits {
                        routes: BTreeMap::from([("shop/api".to_string(), per_ip(9))]),
                        any: Some(per_ip(8)),
                    },
                ),
                ("shop/batch".to_string(), ConsumerRateLimits::default()),
            ]),
            ..Config::default()
        };
        let api = rule("shop/api", Some(per_ip(1)));
        let web = rule("shop/web", Some(per_ip(1)));
        let open = rule("shop/open", None);
        let got = |rule: &RouteRule, consumer: Option<&str>| {
            cfg.rate_limit_for(rule, consumer)
                .map(|(l, own)| (l.limit, own))
        };
        assert_eq!(
            got(&api, Some("shop/mobile")),
            Some((9, true)),
            "on the route"
        );
        assert_eq!(
            got(&web, Some("shop/mobile")),
            Some((8, true)),
            "anywhere else"
        );
        assert_eq!(
            got(&open, Some("shop/mobile")),
            Some((8, true)),
            "even where no one else is limited"
        );
        assert_eq!(
            got(&api, Some("shop/batch")),
            Some((1, false)),
            "nothing of its own"
        );
        assert_eq!(got(&api, Some("shop/unknown")), Some((1, false)));
        assert_eq!(got(&api, None), Some((1, false)), "no consumer identified");
        assert_eq!(got(&open, None), None);
    }

    /// Counting by address is what every limit did before `by` existed, so it must stay absent
    /// on the wire: a configuration that does not use the others serialises byte-for-byte as
    /// before, and its ETag does not change. The other two round-trip as written, and the address
    /// spelt out reads as the address while a name nobody knows does not read at all.
    #[test]
    fn what_a_limit_counts_by_is_absent_on_the_wire_when_it_is_the_address() {
        let wire = serde_json::to_value(per_ip(5)).unwrap();
        assert_eq!(wire, serde_json::json!({"limit": 5, "window_ms": 60_000}));
        let old: RateLimit =
            serde_json::from_value(wire).expect("a limit from before `by` still reads");
        assert_eq!(old.by, LimitBy::Ip);
        for (by, json) in [
            (LimitBy::Consumer, serde_json::json!("consumer")),
            (
                LimitBy::Header("x-tenant".into()),
                serde_json::json!({"header": "x-tenant"}),
            ),
        ] {
            let limit = RateLimit {
                by: by.clone(),
                ..per_ip(5)
            };
            let wire = serde_json::to_value(&limit).unwrap();
            assert_eq!(wire["by"], json);
            assert_eq!(serde_json::from_value::<RateLimit>(wire).unwrap(), limit);
        }
        // Writing the default out by hand is harmless and reads as the default; a name this
        // binary does not know is an error, not the default. A limit that fell back to counting
        // by address on a misspelt (or newer) `by` would silently be a different limit from the
        // one that was written, so it has to fail the load, as an unknown variant does anywhere.
        let explicit: RateLimit =
            serde_json::from_str(r#"{"limit":5,"window_ms":60000,"by":"ip"}"#)
                .expect("`ip` is spelt out by hand as often as it is left off");
        assert_eq!(explicit.by, LimitBy::Ip);
        let unknown =
            serde_json::from_str::<RateLimit>(r#"{"limit":5,"window_ms":60000,"by":"tenant"}"#);
        assert!(
            unknown.is_err(),
            "an unknown `by` must not fall back to the address: {unknown:?}"
        );
    }
}
