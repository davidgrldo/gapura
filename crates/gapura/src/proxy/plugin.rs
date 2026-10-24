//! The plugin contract: what a step returns ([`Flow`]), what it knows of the request
//! ([`RequestCtx`]), and the lists each rule's plugins are compiled into, one per [`Phase`],
//! once per configuration generation.
//!
//! Shaped against gravitee-gateway-api 7.0.0, whose contract a policy can get wrong without a
//! word: hooks that default to doing nothing, so a policy in a phase it does not implement is
//! silently skipped; an interrupt that is an exception, and takes effect only if the policy
//! returns it; attributes in a map keyed by strings. Here each phase has a step type of its own,
//! so a step is only ever dispatched where it has a handler and no handler has a default arm; a
//! rule whose plugins cannot all run is compiled to refuse; every step says what happens next by
//! value; and what steps learn about a request is typed.

use std::net::IpAddr;

use gapura_core::config::{
    Body, IpRestrictionPolicy, JwtPolicy, KeyAuthPolicy, Phase, Plugin, RouteRule,
};
use gapura_core::credentials;
use pingora::http::{RequestHeader, ResponseHeader};

use crate::proxy::failure::ErrorKey;
use crate::proxy::{client_ip_of, jwt, jwt_refusal, rate_limit, GapuraProxy};
use crate::store::Runtime;
use crate::telemetry::METRICS;

/// What a step decided.
pub enum Flow {
    /// Go on: to the next step, and after the last to whatever the rule invokes.
    Continue,
    /// Answer with this head and no body, and invoke nothing.
    Respond(Box<ResponseHeader>),
    /// Refuse the request.
    Fail(Failure),
}

/// Why a step refused a request: the key the answer names, and what that kind of answer adds --
/// the challenge on a 401, the limit's headers on a 429.
pub struct Failure {
    pub key: ErrorKey,
    pub headers: Vec<(&'static str, String)>,
}

/// What answers a request.
#[derive(Default)]
pub enum Invoke {
    /// The upstream: the request is proxied to this cluster.
    Upstream(String),
    /// The gateway, without refusing it: a redirect, a [`Flow::Respond`].
    Serve,
    /// Nothing: the request was refused, or matched no rule.
    #[default]
    Skip,
}

/// The caller a key_auth policy identified.
pub struct Consumer {
    /// What the upstream is told, in `x-consumer-username`: unique within a workspace only.
    pub name: String,
    /// `workspace/username`, unique everywhere: what picks the consumer's own request limit and
    /// what a limit counts by consumer.
    pub id: String,
}

/// What the plugins of one request know about it.
#[derive(Default)]
pub struct RequestCtx {
    /// The `(listener, rule)` the request is attributed to, indices into its generation's
    /// configuration. Set once it is proxied or refused, so metrics and the access log name the
    /// route; a redirect, or a request with nowhere to go, is not attributed and is logged as `-`.
    pub route: Option<(usize, usize)>,
    /// Carried here rather than written straight onto the request: the upstream header can only
    /// be set after the inbound one is removed, and that happens later.
    pub consumer: Option<Consumer>,
    pub invoke: Invoke,
    /// The request body's bytes so far, as the RequestBody steps count them.
    body_bytes: u64,
    terminated: bool,
}

impl RequestCtx {
    /// The cluster the request is proxied to, once it is.
    pub fn cluster(&self) -> Option<&str> {
        match &self.invoke {
            Invoke::Upstream(cluster) => Some(cluster),
            Invoke::Serve | Invoke::Skip => None,
        }
    }

    /// Start the body count again for a new upstream attempt. A retry replays what was read of
    /// the body so far, from Pingora's retry buffer, through the RequestBody steps before it reads
    /// on; a count carried over from the failed attempt would count those bytes twice and refuse
    /// a body within its limit. The count after the replay is exact only because a retry is made
    /// while that buffer still holds the whole body read so far: `error_while_proxy` in
    /// `proxy/mod.rs` refuses one once `retry_buffer_truncated()`. Without that guard a replay
    /// would resend part of the body and the count would start short of what had been read.
    pub fn new_attempt(&mut self) {
        self.body_bytes = 0;
    }

    /// Run `chain`'s Terminate steps -- the rule's, for a request attributed to one -- once,
    /// whatever answered it: a refused request too.
    #[expect(
        clippy::never_loop,
        reason = "there is no Terminate step yet; this expectation fails once there is one"
    )]
    pub fn terminate(&mut self, chain: Option<&Chain>) {
        if std::mem::replace(&mut self.terminated, true) {
            return;
        }
        if let Some(chain) = chain {
            for step in &chain.terminate {
                match *step {}
            }
        }
    }
}

/// One rule's plugins, compiled once per configuration generation into a list per phase.
#[derive(Default)]
pub struct Chain {
    access: Vec<Access>,
    upstream_request: Vec<UpstreamRequest>,
    request_body: Vec<RequestBody>,
    terminate: Vec<Terminate>,
}

/// A step of [`Phase::Access`].
enum Access {
    Jwt(JwtPolicy),
    KeyAuth(KeyAuthPolicy),
    IpRestriction(IpRestrictionPolicy),
    /// A request_size_limit policy's cap, judged against the declared `Content-Length`.
    SizeLimit(u64),
    /// The rule's request limit, or the consumer's own. Not a plugin on the wire, but the last
    /// step of every chain; see [`Chain::compile`].
    RateLimit,
}

/// A step of [`Phase::UpstreamRequest`].
enum UpstreamRequest {
    /// A key_auth policy's key header: the key is the gateway's to check, not the upstream's to
    /// see, so it is removed before forwarding.
    RemoveHeader(String),
}

/// A step of [`Phase::RequestBody`].
enum RequestBody {
    /// A request_size_limit policy's cap, counted over every chunk.
    SizeLimit(u64),
}

/// A step of [`Phase::Terminate`]. There is none yet; quota reconciliation is the first.
enum Terminate {}

/// Why a rule's plugins cannot all run. Such a rule refuses every request.
#[derive(Debug, PartialEq)]
pub struct Misplaced {
    /// The plugin's [`Plugin::kind`].
    pub plugin: &'static str,
    pub why: &'static str,
}

/// The phases a request that matches `rule` passes through. A redirect is answered as soon as
/// the rule matched and is attributed to no rule, so it reaches none.
fn reachable(rule: &RouteRule) -> &'static [Phase] {
    if rule.filters.redirect.is_some() {
        &[]
    } else {
        &[
            Phase::Access,
            Phase::UpstreamRequest,
            Phase::RequestBody,
            Phase::Terminate,
        ]
    }
}

/// Why a plugin that runs in `phases` and reads a body as `body` cannot run where only
/// `reachable` is reached, if it cannot.
fn misplaced(phases: &[Phase], body: Body, reachable: &[Phase]) -> Option<&'static str> {
    if phases.iter().any(|p| !reachable.contains(p)) {
        return Some("the rule never reaches a phase it runs in");
    }
    // A streamed body is fed in RequestBody, which the check above found reachable if the plugin
    // runs there; one that does not would wait for a stream that never comes. A buffered one has
    // no phase that feeds it yet.
    match body {
        Body::None => None,
        Body::Stream if phases.contains(&Phase::RequestBody) => None,
        Body::Stream => Some("it reads a body as it streams, and does not run where one is fed"),
        Body::Buffered { .. } => Some("it reads a body whole, and no phase feeds one yet"),
    }
}

impl Chain {
    /// Compile `rule`'s plugins into the list of each phase they run in, with the request limit
    /// after them. The Access steps run in [`Access::rank`] order, not the order the policies
    /// arrive in. `Err` when a plugin cannot run on this rule: a rule whose policies cannot all
    /// run must not serve, or an auth policy that never runs would let every request through.
    ///
    /// The limit is not checked. It is not a plugin, and a Kubernetes redirect rule can carry one
    /// from its backend's annotation and has to keep redirecting.
    pub fn compile(rule: &RouteRule) -> Result<Chain, Misplaced> {
        let reachable = reachable(rule);
        let mut chain = Chain::default();
        for plugin in &rule.plugins {
            if let Some(why) = misplaced(plugin.phases(), plugin.body(), reachable) {
                return Err(Misplaced {
                    plugin: plugin.kind(),
                    why,
                });
            }
            match plugin {
                Plugin::Jwt(policy) => chain.access.push(Access::Jwt(policy.clone())),
                Plugin::KeyAuth(policy) => {
                    chain.access.push(Access::KeyAuth(policy.clone()));
                    chain
                        .upstream_request
                        .push(UpstreamRequest::RemoveHeader(policy.header.clone()));
                }
                Plugin::IpRestriction(policy) => {
                    chain.access.push(Access::IpRestriction(policy.clone()))
                }
                Plugin::RequestSizeLimit(policy) => {
                    chain.access.push(Access::SizeLimit(policy.max_bytes));
                    chain
                        .request_body
                        .push(RequestBody::SizeLimit(policy.max_bytes));
                }
            }
        }
        // Stable, so policies of one rank keep the order they arrived in.
        chain.access.sort_by_key(Access::rank);
        // Last, because the limit may be the consumer's own and may count per consumer, and the
        // consumer is not known until a policy has checked its credential.
        chain.access.push(Access::RateLimit);
        Ok(chain)
    }

    /// Run the Access steps in order, up to the first that does not continue. `peer` is the
    /// connection's address, from which the client's is worked out only if a limit or an
    /// ip_restriction step needs it.
    pub fn access(
        &self,
        proxy: &GapuraProxy,
        rt: &Runtime,
        rule: &RouteRule,
        req: &RequestHeader,
        peer: Option<IpAddr>,
        cx: &mut RequestCtx,
    ) -> Flow {
        for step in &self.access {
            let flow = step.run(proxy, rt, rule, req, peer, cx);
            if !matches!(flow, Flow::Continue) {
                return flow;
            }
        }
        Flow::Continue
    }

    /// Run the UpstreamRequest steps on the request about to be sent.
    pub fn upstream_request(&self, upstream: &mut RequestHeader) {
        for step in &self.upstream_request {
            match step {
                UpstreamRequest::RemoveHeader(name) => {
                    upstream.remove_header(name.as_str());
                }
            }
        }
    }

    /// Run `rule`'s RequestBody steps on a chunk of `len` bytes, and the key to refuse with when
    /// one refuses. The step that refuses counts its refusal in `policy_refused_total`, by its
    /// own kind and reason, as an Access step does through [`refuse`]: the caller only answers
    /// the key. Nothing is counted once the connection is `upgraded`: what follows a 101 is a
    /// tunnel, not a request body, and a cap on it would cut a WebSocket after so many bytes.
    pub fn request_body(
        &self,
        rule: &RouteRule,
        cx: &mut RequestCtx,
        len: usize,
        upgraded: bool,
    ) -> Option<ErrorKey> {
        if upgraded || self.request_body.is_empty() {
            return None;
        }
        cx.body_bytes = cx.body_bytes.saturating_add(len as u64);
        for step in &self.request_body {
            match step {
                RequestBody::SizeLimit(max) if cx.body_bytes > *max => {
                    count_refusal(rule, "request_size_limit", "streamed");
                    return Some(ErrorKey::RequestTooLarge);
                }
                RequestBody::SizeLimit(_) => {}
            }
        }
        None
    }
}

impl Access {
    /// Where the step runs among the Access steps, lowest first, whatever order the policies
    /// arrive in. The address is judged before any credential is read, so a denied address
    /// cannot tell a good key from a bad one by its answer. The credential checks keep the
    /// order they arrive in among themselves. The declared length is judged after them, as Kong
    /// judges it after authentication, so a caller without a credential is told 401 whatever it
    /// sends; and before the limit, so a body refused for its declared length does not spend a
    /// caller's allowance. One refused as it streams does: the count runs in RequestBody, after
    /// the limit has counted the request. The limit is last: it may be the consumer's own and may
    /// count per consumer, and the consumer is not known until a credential is checked.
    fn rank(&self) -> u8 {
        match self {
            Access::IpRestriction(_) => 1,
            Access::Jwt(_) | Access::KeyAuth(_) => 2,
            Access::SizeLimit(_) => 3,
            Access::RateLimit => 4,
        }
    }

    fn run(
        &self,
        proxy: &GapuraProxy,
        rt: &Runtime,
        rule: &RouteRule,
        req: &RequestHeader,
        peer: Option<IpAddr>,
        cx: &mut RequestCtx,
    ) -> Flow {
        match self {
            Access::Jwt(policy) => {
                // No keys for this document means it did not parse at swap time, or its
                // `jwks_uri` has never loaded. Refusing is the safe direction: the alternative is
                // passing traffic through unverified because verification was impossible.
                let empty = jwt::Keys::default();
                let keys = rt.jwt_keys(&policy.jwks).unwrap_or(&empty);
                match jwt_refusal(req, policy, keys) {
                    None => Flow::Continue,
                    Some((key, reason, challenge)) => {
                        // A key the policy does not hold may be one its IdP has just started
                        // signing with. This request is refused either way; the control source
                        // refetches on its next tick, at most once per 30 s.
                        if policy.jwks_uri.is_some()
                            && reason == gapura_core::jwt::Refusal::UnknownKey.as_str()
                        {
                            proxy.store.want_jwks_refresh();
                        }
                        refuse(
                            rule,
                            "jwt",
                            reason,
                            key,
                            vec![("WWW-Authenticate", challenge.to_string())],
                        )
                    }
                }
            }
            Access::KeyAuth(policy) => {
                let presented = req
                    .headers
                    .get(&policy.header)
                    .and_then(|v| v.to_str().ok());
                match credentials::identify(&rt.config, presented, policy.workspace.as_deref()) {
                    Ok(name) => {
                        cx.consumer = Some(Consumer {
                            id: credentials::consumer_id(
                                policy.workspace.as_deref().unwrap_or_default(),
                                name,
                            ),
                            name: name.to_string(),
                        });
                        Flow::Continue
                    }
                    Err(r) => refuse(
                        rule,
                        "key_auth",
                        r.as_str(),
                        ErrorKey::from(&r),
                        vec![(
                            "WWW-Authenticate",
                            format!("Key realm=\"{}\"", policy.header),
                        )],
                    ),
                }
            }
            Access::IpRestriction(policy) => match policy.refusal(client_of(proxy, req, peer)) {
                None => Flow::Continue,
                Some(reason) => refuse(
                    rule,
                    "ip_restriction",
                    reason,
                    ErrorKey::IpForbidden,
                    Vec::new(),
                ),
            },
            // Pingora refuses a request whose `Content-Length` is not a number before any filter
            // runs, so one that does not parse here is absent, and left to the count. The parse
            // agrees with Pingora's, which reads the value as a signed number and so takes a
            // leading `+`. A declared length is not always what frames the body: when
            // `Transfer-Encoding` is also present Pingora frames it by its chunks (and on HTTP/1
            // drops the length before any filter runs), so a body may outgrow a length it
            // declared. The RequestBody count runs on every body, and covers that.
            Access::SizeLimit(max) => {
                let declared = req
                    .headers
                    .get(http::header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.trim().parse::<u64>().ok());
                match declared {
                    Some(len) if len > *max => refuse(
                        rule,
                        "request_size_limit",
                        "content_length",
                        ErrorKey::RequestTooLarge,
                        Vec::new(),
                    ),
                    _ => Flow::Continue,
                }
            }
            Access::RateLimit => limit(proxy, rt, rule, req, peer, cx),
        }
    }
}

/// Count a policy's refusal and say how to answer it, with what that kind of answer adds: the
/// challenge on a 401, nothing on a 403. Missing or invalid is all an auth key says: which check
/// failed is an operator's business (the metric's reason), and telling a caller narrows the
/// search for whoever is guessing.
fn refuse(
    rule: &RouteRule,
    kind: &str,
    reason: &str,
    key: ErrorKey,
    headers: Vec<(&'static str, String)>,
) -> Flow {
    count_refusal(rule, kind, reason);
    Flow::Fail(Failure { key, headers })
}

/// Count one refusal by a `kind` policy on `rule` in `policy_refused_total`, with why. Each step
/// counts its own, whatever phase it runs in, since only the step knows its kind and reason.
fn count_refusal(rule: &RouteRule, kind: &str, reason: &str) {
    METRICS
        .policy_refused_total
        .with_label_values(&[rule.route.as_str(), kind, reason])
        .inc();
}

/// The client address the access log names: the connection's, or behind a trusted proxy the one
/// it forwarded. `None` when the connection has no IP address.
fn client_of(proxy: &GapuraProxy, req: &RequestHeader, peer: Option<IpAddr>) -> Option<IpAddr> {
    peer.map(|peer| {
        client_ip_of(
            req,
            peer,
            &proxy.trusted_proxies,
            &proxy.trusted_client_headers,
        )
    })
}

/// The request limit: after the match (the route is known) and the policies (the consumer is
/// known, and its own limit replaces the rule's), before any upstream work (the limit must not
/// cost the backend anything). When the limit counts by address, the address is the same answer
/// the access log records, so a limited request names the same client a served one would; a
/// limit that counts by consumer or by a header's value counts that instead, which the log does
/// not name.
fn limit(
    proxy: &GapuraProxy,
    rt: &Runtime,
    rule: &RouteRule,
    req: &RequestHeader,
    peer: Option<IpAddr>,
    cx: &RequestCtx,
) -> Flow {
    let consumer = cx.consumer.as_ref().map(|c| c.id.as_str());
    let Some((rl, own)) = rt.config.rate_limit_for(rule, consumer) else {
        return Flow::Continue;
    };
    // Keyed per rule, not per route (#185): one HTTPRoute can carry rules with different limits
    // (/login at 5/h, / at 100/s), and a shared route key means the rules reset each other's
    // windows, so the tighter limit never trips.
    let route = format!("{}#{}", rule.route, rule.rule_index);
    // A consumer's own limit counts apart from the rule's: one window for two limits would let
    // each spend the other's allowance. The metric keeps the rule's label, since a label per
    // consumer grows without bound.
    let window = match (own, consumer) {
        (true, Some(consumer)) => format!("{route}@{consumer}"),
        _ => route.clone(),
    };
    let ip = client_of(proxy, req, peer);
    let Some(client) = rate_limit::client(&rl.by, ip, consumer, &req.headers) else {
        return Flow::Continue;
    };
    match proxy.limiter.check(&window, client, ip, rl) {
        rate_limit::Outcome::Allowed => Flow::Continue,
        rate_limit::Outcome::Limited {
            limit,
            retry_after_secs,
        } => {
            METRICS
                .rate_limited_total
                .with_label_values(&[&route])
                .inc();
            Flow::Fail(Failure {
                key: ErrorKey::RateLimited,
                headers: vec![
                    ("Retry-After", retry_after_secs.to_string()),
                    ("X-RateLimit-Limit", limit.to_string()),
                    ("X-RateLimit-Remaining", "0".to_string()),
                ],
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use gapura_core::config::{
        Config, ConsumerRateLimits, Filters, LimitBy, RateLimit, Redirect, Timeouts,
    };
    use sha2::{Digest, Sha256};

    use crate::store::Store;

    const ALL: [Phase; 4] = [
        Phase::Access,
        Phase::UpstreamRequest,
        Phase::RequestBody,
        Phase::Terminate,
    ];

    fn rule(plugins: Vec<Plugin>) -> RouteRule {
        RouteRule {
            route: "shop/api".into(),
            rule_index: 0,
            creation_timestamp: String::new(),
            matches: vec![],
            filters: Filters::default(),
            backends: vec![],
            timeouts: Timeouts::default(),
            rate_limit: None,
            plugins,
        }
    }

    fn redirect() -> Option<Redirect> {
        Some(Redirect {
            scheme: Some("https".into()),
            hostname: None,
            port: None,
            status: 301,
            path: None,
        })
    }

    /// What a variant declares and where `compile` puts it are written in two places; this is
    /// what keeps them one answer.
    #[test]
    fn each_plugin_runs_in_exactly_the_phases_it_declares() {
        for plugin in [
            Plugin::Jwt(JwtPolicy::default()),
            Plugin::KeyAuth(KeyAuthPolicy::default()),
            ip_restriction(&["10.0.0.0/8"], &[]),
            size_limit(10),
        ] {
            let chain = Chain::compile(&rule(vec![plugin.clone()])).unwrap();
            // The request limit closes every chain and is not the plugin's.
            let access = chain
                .access
                .iter()
                .filter(|s| !matches!(s, Access::RateLimit))
                .count();
            let found: Vec<Phase> = [
                (Phase::Access, access),
                (Phase::UpstreamRequest, chain.upstream_request.len()),
                (Phase::RequestBody, chain.request_body.len()),
                (Phase::Terminate, chain.terminate.len()),
            ]
            .into_iter()
            .filter(|&(_, steps)| steps > 0)
            .map(|(phase, _)| phase)
            .collect();
            assert_eq!(found, plugin.phases(), "{}", plugin.kind());
        }
    }

    #[test]
    fn a_plugin_on_a_redirect_rule_refuses_the_rule_and_a_limit_there_does_not() {
        let mut with_policy = rule(vec![Plugin::KeyAuth(KeyAuthPolicy::default())]);
        with_policy.filters.redirect = redirect();
        assert_eq!(
            Chain::compile(&with_policy).err(),
            Some(Misplaced {
                plugin: "key_auth",
                why: "the rule never reaches a phase it runs in",
            })
        );
        // A Kubernetes rule takes its limit from the backend Service's annotation, redirect or
        // not, and has to keep redirecting: the limit is not a plugin.
        let mut with_limit = rule(vec![]);
        with_limit.filters.redirect = redirect();
        with_limit.rate_limit = Some(RateLimit {
            limit: 1,
            window_ms: 60_000,
            by: LimitBy::Ip,
        });
        assert!(Chain::compile(&with_limit).is_ok());
    }

    fn proxy() -> GapuraProxy {
        GapuraProxy {
            store: Arc::new(Store::empty()),
            trusted_proxies: vec![],
            trusted_client_headers: vec![],
            limiter: Default::default(),
            access_log_query: false,
        }
    }

    fn key_auth(workspace: Option<&str>) -> Plugin {
        Plugin::KeyAuth(KeyAuthPolicy {
            header: "x-api-key".into(),
            workspace: workspace.map(str::to_string),
        })
    }

    fn ip_restriction(allow: &[&str], deny: &[&str]) -> Plugin {
        let nets = |list: &[&str]| list.iter().map(|s| s.parse().unwrap()).collect();
        Plugin::IpRestriction(IpRestrictionPolicy {
            allow: nets(allow),
            deny: nets(deny),
        })
    }

    fn size_limit(max_bytes: u64) -> Plugin {
        Plugin::RequestSizeLimit(gapura_core::config::RequestSizeLimitPolicy { max_bytes })
    }

    fn get() -> RequestHeader {
        RequestHeader::build("GET", b"/", None).unwrap()
    }

    fn with_length(len: u64) -> RequestHeader {
        let mut req = RequestHeader::build("POST", b"/", None).unwrap();
        req.insert_header("content-length", len.to_string())
            .unwrap();
        req
    }

    /// A configuration holding the key `k-1`, issued to `shop/mobile`.
    fn with_key(config: Config) -> Runtime {
        let hash = format!("{:x}", Sha256::digest(b"k-1"));
        let config = Config {
            credentials: BTreeMap::from([(hash.clone(), "mobile".to_string())]),
            credential_workspaces: BTreeMap::from([(hash, "shop".to_string())]),
            ..config
        };
        Runtime::new(config, 1, Vec::new())
    }

    fn refused(flow: Flow) -> Failure {
        match flow {
            Flow::Fail(failure) => failure,
            Flow::Continue | Flow::Respond(_) => panic!("admitted"),
        }
    }

    #[test]
    fn access_runs_in_order_and_stops_at_the_first_refusal() {
        let rt = Runtime::new(Config::default(), 1, Vec::new());
        let jwt = Plugin::Jwt(JwtPolicy::default());
        for (plugins, first) in [
            (vec![key_auth(None), jwt.clone()], ErrorKey::AuthKeyMissing),
            (vec![jwt.clone(), key_auth(None)], ErrorKey::AuthJwtMissing),
        ] {
            let r = rule(plugins);
            let chain = Chain::compile(&r).unwrap();
            let flow = chain.access(&proxy(), &rt, &r, &get(), None, &mut RequestCtx::default());
            assert_eq!(refused(flow).key, first);
        }
    }

    /// Listed after key_auth and run before it: a denied address is refused without its key
    /// being read, so it never learns whether the key is good. An address the policy admits
    /// goes on to the key check.
    #[test]
    fn an_address_is_refused_before_any_credential_is_read() {
        let rt = Runtime::new(Config::default(), 1, Vec::new());
        let r = rule(vec![key_auth(None), ip_restriction(&[], &["192.0.2.0/24"])]);
        let chain = Chain::compile(&r).unwrap();
        let from = |ip: &str| {
            chain.access(
                &proxy(),
                &rt,
                &r,
                &get(),
                Some(ip.parse().unwrap()),
                &mut RequestCtx::default(),
            )
        };
        let failure = refused(from("192.0.2.9"));
        assert_eq!(failure.key, ErrorKey::IpForbidden);
        assert!(failure.headers.is_empty(), "a 403 carries no challenge");
        assert_eq!(refused(from("198.51.100.1")).key, ErrorKey::AuthKeyMissing);
    }

    /// No connection address, no client address: refused, never admitted.
    #[test]
    fn an_unknown_address_is_refused() {
        let rt = Runtime::new(Config::default(), 1, Vec::new());
        let r = rule(vec![ip_restriction(&["10.0.0.0/8"], &[])]);
        let chain = Chain::compile(&r).unwrap();
        let flow = chain.access(&proxy(), &rt, &r, &get(), None, &mut RequestCtx::default());
        assert_eq!(refused(flow).key, ErrorKey::IpForbidden);
    }

    #[test]
    fn a_key_names_its_consumer_and_is_not_sent_upstream() {
        let rt = with_key(Config::default());
        let r = rule(vec![key_auth(Some("shop"))]);
        let chain = Chain::compile(&r).unwrap();
        let mut req = get();
        req.insert_header("x-api-key", "k-1").unwrap();
        let mut cx = RequestCtx::default();
        let flow = chain.access(&proxy(), &rt, &r, &req, None, &mut cx);
        assert!(matches!(flow, Flow::Continue));
        let consumer = cx.consumer.expect("identified");
        assert_eq!(
            (consumer.name.as_str(), consumer.id.as_str()),
            ("mobile", "shop/mobile")
        );
        chain.upstream_request(&mut req);
        assert!(req.headers.get("x-api-key").is_none());
    }

    #[test]
    fn the_limit_runs_last_and_counts_a_consumer_s_own_window() {
        let rt = with_key(Config {
            consumer_rate_limits: BTreeMap::from([(
                "shop/mobile".to_string(),
                ConsumerRateLimits {
                    routes: BTreeMap::new(),
                    any: Some(RateLimit {
                        limit: 1,
                        window_ms: 60_000,
                        by: LimitBy::Consumer,
                    }),
                },
            )]),
            ..Config::default()
        });
        let r = rule(vec![key_auth(Some("shop"))]);
        let chain = Chain::compile(&r).unwrap();
        let proxy = proxy();
        let mut req = get();
        req.insert_header("x-api-key", "k-1").unwrap();
        let run = || {
            let mut cx = RequestCtx::default();
            chain.access(&proxy, &rt, &r, &req, None, &mut cx)
        };
        assert!(matches!(run(), Flow::Continue));
        let failure = refused(run());
        assert_eq!(failure.key, ErrorKey::RateLimited);
        let names: Vec<&str> = failure.headers.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            names,
            ["Retry-After", "X-RateLimit-Limit", "X-RateLimit-Remaining"]
        );
        assert_eq!(failure.headers[1].1, "1");
        assert_eq!(failure.headers[2].1, "0");
    }

    #[test]
    fn terminate_runs_once_whatever_answered() {
        let chain = Chain::compile(&rule(vec![])).unwrap();
        let mut cx = RequestCtx::default();
        cx.terminate(Some(&chain));
        assert!(cx.terminated);
        // Pingora calls `logging` once; were it ever called twice, the steps would not run again.
        cx.terminate(Some(&chain));
        cx.terminate(None);
        assert!(cx.terminated);
    }

    /// A streaming plugin runs where the body phase is reached and it declares that phase; one
    /// that does not declare it would never be fed. A buffering one runs nowhere yet.
    #[test]
    fn a_streaming_plugin_runs_where_the_body_phase_is_reached_and_a_buffering_one_nowhere_yet() {
        let streams = [Phase::Access, Phase::RequestBody];
        assert_eq!(misplaced(&[Phase::Access], Body::None, &ALL), None);
        assert_eq!(misplaced(&streams, Body::Stream, &ALL), None);
        assert!(misplaced(&streams, Body::Stream, &[]).is_some());
        assert!(misplaced(&[Phase::Access], Body::Stream, &ALL).is_some());
        assert!(misplaced(&[Phase::Access], Body::Buffered { max: 1 << 20 }, &ALL).is_some());
    }

    /// A declared length over the limit is refused before anything upstream, read as Pingora
    /// reads it; one at the limit, and a request with no length at all, are left to the count.
    #[test]
    fn a_declared_length_over_the_limit_is_413_up_front() {
        let rt = Runtime::new(Config::default(), 1, Vec::new());
        let r = rule(vec![size_limit(10)]);
        let chain = Chain::compile(&r).unwrap();
        let run = |req: &RequestHeader| {
            chain.access(&proxy(), &rt, &r, req, None, &mut RequestCtx::default())
        };
        let failure = refused(run(&with_length(11)));
        assert_eq!(failure.key, ErrorKey::RequestTooLarge);
        assert!(failure.headers.is_empty());
        assert!(matches!(run(&with_length(10)), Flow::Continue));
        assert!(matches!(run(&get()), Flow::Continue));
        // Pingora reads `+11` as 11 and frames the body by it, so the limit must read it so too.
        let mut plus = RequestHeader::build("POST", b"/", None).unwrap();
        plus.insert_header("content-length", "+11").unwrap();
        assert_eq!(refused(run(&plus)).key, ErrorKey::RequestTooLarge);
    }

    /// The count runs over every chunk, holds none of them, refuses the chunk that crosses the
    /// limit, counts that refusal itself, and stops once the connection is upgraded.
    #[test]
    fn streamed_bytes_are_counted_up_to_the_limit() {
        // A route of its own, so the metric is this test's alone: the registry is shared.
        let r = RouteRule {
            route: "shop/streamed".into(),
            ..rule(vec![size_limit(10)])
        };
        let refusals = || {
            METRICS
                .policy_refused_total
                .with_label_values(&["shop/streamed", "request_size_limit", "streamed"])
                .get()
        };
        let chain = Chain::compile(&r).unwrap();
        let mut cx = RequestCtx::default();
        assert_eq!(chain.request_body(&r, &mut cx, 6, false), None);
        assert_eq!(
            chain.request_body(&r, &mut cx, 4, false),
            None,
            "10 is at the limit"
        );
        assert_eq!(refusals(), 0);
        assert_eq!(
            chain.request_body(&r, &mut cx, 1, false),
            Some(ErrorKey::RequestTooLarge)
        );
        assert_eq!(refusals(), 1);
        let mut upgraded = RequestCtx::default();
        assert_eq!(chain.request_body(&r, &mut upgraded, 1 << 30, true), None);
    }

    /// A retry replays the body read so far before it reads on, so each attempt counts from
    /// nothing: the replayed bytes are counted once, and the limit still holds after them.
    #[test]
    fn a_retry_counts_the_replayed_body_once() {
        let r = rule(vec![size_limit(10)]);
        let chain = Chain::compile(&r).unwrap();
        let mut cx = RequestCtx::default();
        cx.new_attempt();
        assert_eq!(chain.request_body(&r, &mut cx, 8, false), None);
        cx.new_attempt();
        assert_eq!(
            chain.request_body(&r, &mut cx, 8, false),
            None,
            "the replay"
        );
        assert_eq!(
            chain.request_body(&r, &mut cx, 3, false),
            Some(ErrorKey::RequestTooLarge)
        );
    }

    /// The length is judged after the credentials, as Kong does, and before the request limit,
    /// so a body refused for its declared length does not spend a caller's allowance. One
    /// refused as it streams does, since the limit has counted the request by then.
    #[test]
    fn the_length_is_judged_after_the_credentials() {
        let rt = Runtime::new(Config::default(), 1, Vec::new());
        let r = rule(vec![size_limit(10), key_auth(None)]);
        let chain = Chain::compile(&r).unwrap();
        let flow = chain.access(
            &proxy(),
            &rt,
            &r,
            &with_length(11),
            None,
            &mut RequestCtx::default(),
        );
        assert_eq!(refused(flow).key, ErrorKey::AuthKeyMissing);

        let mut limited = rule(vec![size_limit(10)]);
        limited.rate_limit = Some(RateLimit {
            limit: 1,
            window_ms: 60_000,
            by: LimitBy::Ip,
        });
        let chain = Chain::compile(&limited).unwrap();
        let proxy = proxy();
        let run = |req: &RequestHeader| {
            let peer = Some("192.0.2.1".parse().unwrap());
            chain.access(&proxy, &rt, &limited, req, peer, &mut RequestCtx::default())
        };
        for _ in 0..2 {
            assert_eq!(
                refused(run(&with_length(11))).key,
                ErrorKey::RequestTooLarge
            );
        }
        assert!(
            matches!(run(&with_length(10)), Flow::Continue),
            "allowance unspent"
        );
        assert_eq!(refused(run(&with_length(10))).key, ErrorKey::RateLimited);
    }
}
