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
    Body, CorsPolicy, HeaderEdits, IpRestrictionPolicy, JwtPolicy, KeyAuthPolicy, Phase, Plugin,
    RequestTransformerPolicy, RouteRule,
};
use gapura_core::credentials;
use pingora::http::{RequestHeader, ResponseHeader};

use crate::proxy::failure::ErrorKey;
use crate::proxy::transform::{edit_headers, edit_query, writable};
use crate::proxy::{client_ip_of, is_final, jwt, jwt_verdict, rate_limit, GapuraProxy};
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

/// The caller a credential policy identified, or the one an auth policy names for a request
/// that presented no credential.
#[derive(Clone)]
pub struct Consumer {
    /// What the upstream is told, in `x-consumer-username`: unique within a workspace only.
    pub name: String,
    /// `workspace/username`, unique everywhere: what picks the consumer's own request limit and
    /// what a limit counts by consumer.
    pub id: String,
    /// The auth policy's anonymous consumer: the request presented no credential.
    #[expect(
        dead_code,
        reason = "set by the auth chain and read by the upstream headers, which come next"
    )]
    pub anonymous: bool,
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
    /// What a cors policy's Access step decided, for its Response step.
    cors: Option<Cors>,
    terminated: bool,
}

/// What a cors policy's Access step decided of a request.
enum Cors {
    /// It answered a preflight itself, and its answer is left as it built it.
    Answered,
    /// Anything else: the `Access-Control-Allow-Origin` to send, when the request named an origin
    /// the policy allows, and whether this is a preflight passed to the upstream, whose answer
    /// keeps the methods, headers and max-age it gives.
    Pass {
        allow: Option<String>,
        preflight: bool,
    },
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
    response: Vec<Response>,
    terminate: Vec<Terminate>,
}

/// A step of [`Phase::Access`].
enum Access {
    /// A cors policy: answers a preflight, and judges the origin of everything else.
    Cors(CorsPolicy),
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
    /// A request_transformer policy's edits: the headers, then the query string. Boxed, as ten
    /// lists would make every step of this phase that size.
    Transform(Box<RequestTransformerPolicy>),
}

/// A step of [`Phase::RequestBody`].
enum RequestBody {
    /// A request_size_limit policy's cap, counted over every chunk.
    SizeLimit(u64),
}

/// A step of [`Phase::Response`].
enum Response {
    /// A cors policy's headers, as its Access step decided them.
    Cors(CorsPolicy),
    /// A response_transformer policy's header edits.
    Transform(HeaderEdits),
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
            Phase::Response,
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

/// `Err` when a `plugin`'s header `edits` cannot all be made: a name or a value the header map
/// would refuse. Such a rule refuses every request, as one whose plugin cannot run does. The
/// edits are what the operator asked the upstream or the client to be told, and an answer
/// without some of them is not that.
fn writable_edits(plugin: &Plugin, edits: &HeaderEdits) -> Result<(), Misplaced> {
    if writable(edits) {
        Ok(())
    } else {
        Err(Misplaced {
            plugin: plugin.kind(),
            why: "it writes a header name or value HTTP does not allow",
        })
    }
}

impl Chain {
    /// Compile `rule`'s plugins into the list of each phase they run in, with the request limit
    /// after them. The Access steps run in [`Access::rank`] order, and the UpstreamRequest steps
    /// in [`UpstreamRequest::rank`] order -- a key_auth policy's key removed before any
    /// request_transformer edits -- not the order the policies arrive in. `Err` when a plugin
    /// cannot run on this rule: a rule whose policies cannot all run must not serve, or an auth
    /// policy that never runs would let every request through.
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
                Plugin::RequestTransformer(policy) => {
                    writable_edits(plugin, &policy.headers)?;
                    chain
                        .upstream_request
                        .push(UpstreamRequest::Transform(Box::new(policy.clone())));
                }
                Plugin::ResponseTransformer(policy) => {
                    writable_edits(plugin, &policy.headers)?;
                    chain
                        .response
                        .push(Response::Transform(policy.headers.clone()));
                }
                Plugin::Cors(policy) => {
                    let lists = [&policy.methods, &policy.headers, &policy.expose_headers];
                    if !lists
                        .iter()
                        .all(|list| http::HeaderValue::from_str(&list.join(", ")).is_ok())
                    {
                        return Err(Misplaced {
                            plugin: plugin.kind(),
                            why: "it writes a header name or value HTTP does not allow",
                        });
                    }
                    chain.access.push(Access::Cors(policy.clone()));
                    chain.response.push(Response::Cors(policy.clone()));
                }
                // Temporary: the chain that runs them is the next change, and nothing sends a
                // configuration that holds either until the control plane learns the kinds.
                Plugin::Auth(_) | Plugin::Acl(_) => {}
            }
        }
        // Stable, so policies of one rank keep the order they arrived in.
        chain.access.sort_by_key(Access::rank);
        chain.upstream_request.sort_by_key(UpstreamRequest::rank);
        chain.response.sort_by_key(Response::rank);
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
                UpstreamRequest::Transform(policy) => {
                    edit_headers(upstream, &policy.headers);
                    if let Some(uri) = edit_query(&upstream.uri, &policy.query) {
                        upstream.set_uri(uri);
                    }
                }
            }
        }
    }

    /// Run the Response steps on a head about to be written to the client: the upstream's, or
    /// the gateway's own. An interim head is not the answer and is left alone: a relayed `100
    /// Continue` is followed by the final head, which the steps edit, and they run once per
    /// answer. A 101 is final, and edited like any other.
    pub fn response(&self, cx: &RequestCtx, resp: &mut ResponseHeader) {
        if !is_final(resp.status) {
            return;
        }
        for step in &self.response {
            match step {
                Response::Cors(policy) => match &cx.cors {
                    Some(Cors::Answered) => {}
                    Some(Cors::Pass { allow, preflight }) => {
                        cors_headers(resp, policy, allow.as_deref(), *preflight)
                    }
                    // The Access step runs first on every request the rule answers, so this is
                    // never so; were it, the request is one with no origin the policy allows.
                    None => cors_headers(resp, policy, None, false),
                },
                Response::Transform(edits) => edit_headers(resp, edits),
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

impl UpstreamRequest {
    /// Where the step runs among the UpstreamRequest steps, lowest first, whatever order the
    /// policies arrive in. The client's key goes first, as Kong's `hide_credentials` removes it
    /// before its request-transformer runs: a transform that renamed the key's header would
    /// otherwise move the key out of the removal's reach, and hand the upstream, under the new
    /// name, the key the gateway checks so that the upstream never sees it. The order the
    /// policies arrive in, by name, happens to agree today; nothing holds it there.
    fn rank(&self) -> u8 {
        match self {
            UpstreamRequest::RemoveHeader(_) => 1,
            UpstreamRequest::Transform(_) => 2,
        }
    }
}

impl Response {
    /// Where the step runs among the Response steps, lowest first, whatever order the policies
    /// arrive in: cors before any transform, as Kong runs its cors (priority 2000) before its
    /// response-transformer (800), so that the operator's transform has the last word.
    fn rank(&self) -> u8 {
        match self {
            Response::Cors(_) => 0,
            Response::Transform(_) => 1,
        }
    }
}

/// Why a credential policy refused a request, not yet counted: in a chain, a refusal because the
/// credential is not there means only "not mine", and is counted only if no policy accepts.
struct Refused {
    key: ErrorKey,
    reason: &'static str,
    headers: Vec<(&'static str, String)>,
}

/// A jwt policy's verdict: the consumer its `consumer_claim` names, or nobody without one.
fn check_jwt(
    proxy: &GapuraProxy,
    rt: &Runtime,
    req: &RequestHeader,
    policy: &JwtPolicy,
) -> Result<Option<Consumer>, Refused> {
    // No keys for this document means it did not parse at swap time, or its `jwks_uri` has never
    // loaded; `jwt_verdict` answers a token there `AUTH_UNAVAILABLE`.
    let empty = jwt::Keys::default();
    let keys = rt.jwt_keys(&policy.jwks).unwrap_or(&empty);
    let claims = jwt_verdict(req, policy, keys).map_err(|(key, reason, challenge)| {
        // A key the policy does not hold may be one its IdP has just started signing with. This
        // request is refused either way; the control source refetches on its next tick, at most
        // once per 30 s.
        if policy.jwks_uri.is_some() && reason == gapura_core::jwt::Refusal::UnknownKey.as_str() {
            proxy.store.want_jwks_refresh();
        }
        // A 503 asks the caller to come back, as the control source retries a failed fetch in
        // 30 s; it challenges for nothing, since the token may be good.
        let headers = match key {
            ErrorKey::AuthUnavailable => vec![("Retry-After", "30".to_string())],
            _ => vec![("WWW-Authenticate", challenge.to_string())],
        };
        Refused {
            key,
            reason,
            headers,
        }
    })?;
    let Some(claim) = &policy.consumer_claim else {
        return Ok(None);
    };
    let workspace = policy.workspace.as_deref().unwrap_or_default();
    claims
        .get(claim)
        .and_then(serde_json::Value::as_str)
        .map(|name| Consumer {
            id: credentials::consumer_id(workspace, name),
            name: name.to_string(),
            anonymous: false,
        })
        .filter(|c| rt.config.consumers.contains_key(&c.id))
        .map(Some)
        // The same answer as a bad token: a caller learns nothing of which consumers exist.
        .ok_or(Refused {
            key: ErrorKey::AuthJwtInvalid,
            reason: "unknown_consumer",
            headers: vec![("WWW-Authenticate", "Bearer".to_string())],
        })
}

/// A key_auth policy's verdict: the consumer its key was issued to.
fn check_key(
    rt: &Runtime,
    req: &RequestHeader,
    policy: &KeyAuthPolicy,
) -> Result<Option<Consumer>, Refused> {
    let presented = req
        .headers
        .get(&policy.header)
        .and_then(|v| v.to_str().ok());
    let workspace = policy.workspace.as_deref();
    match credentials::identify(&rt.config, presented, workspace) {
        Ok(name) => Ok(Some(Consumer {
            id: credentials::consumer_id(workspace.unwrap_or_default(), name),
            name: name.to_string(),
            anonymous: false,
        })),
        Err(r) => Err(Refused {
            key: ErrorKey::from(&r),
            reason: r.as_str(),
            headers: vec![(
                "WWW-Authenticate",
                format!("Key realm=\"{}\"", policy.header),
            )],
        }),
    }
}

/// Go on with the consumer `verdict` identified -- a later policy's replacing an earlier one's,
/// which under AND is key_auth's over jwt's -- or refuse, counted against `kind`.
fn admit(
    rule: &RouteRule,
    kind: &str,
    verdict: Result<Option<Consumer>, Refused>,
    cx: &mut RequestCtx,
) -> Flow {
    match verdict {
        Ok(None) => Flow::Continue,
        Ok(consumer) => {
            cx.consumer = consumer;
            Flow::Continue
        }
        Err(r) => refuse(rule, kind, r.reason, r.key, r.headers),
    }
}

impl Access {
    /// Where the step runs among the Access steps, lowest first, whatever order the policies
    /// arrive in. A CORS preflight is answered first, since a browser sends it without
    /// credentials: an auth policy before it would refuse every preflight, and a browser would
    /// never send the request it asked about. Answering it before the address is judged tells a
    /// denied address no more than the policy's own CORS configuration, as Kong's cors (priority
    /// 2000) runs before its ip-restriction (990). The address is judged before any credential is
    /// read, so a denied address cannot tell a good key from a bad one by its answer. jwt runs
    /// before key_auth, the order an auth policy's chain tries them in (Gravitee's JWT 0 and API
    /// key 500), so the two modes never disagree about which is asked first. The declared length
    /// is judged after them, as Kong judges it after authentication, so a caller without a
    /// credential is told 401 whatever it sends; and before the limit, so a body refused for its
    /// declared length does not spend a caller's allowance. One refused as it streams does: the
    /// count runs in RequestBody, after the limit has counted the request. The limit is last: it
    /// may be the consumer's own and may count per consumer, and the consumer is not known until a
    /// credential is checked.
    fn rank(&self) -> u8 {
        match self {
            Access::Cors(_) => 0,
            Access::IpRestriction(_) => 1,
            Access::Jwt(_) => 2,
            Access::KeyAuth(_) => 3,
            Access::SizeLimit(_) => 5,
            Access::RateLimit => 6,
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
            Access::Cors(policy) => cors(rule, policy, req, cx),
            Access::Jwt(policy) => admit(rule, "jwt", check_jwt(proxy, rt, req, policy), cx),
            Access::KeyAuth(policy) => admit(rule, "key_auth", check_key(rt, req, policy), cx),
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

/// A cors policy's Access step. A preflight -- `OPTIONS` with `Origin` and
/// `Access-Control-Request-Method` -- is answered here unless the policy passes it on: 204 to an
/// origin it allows, 403 to any other. Everything else goes on, with the origin the policy allows
/// recorded for the Response step; a request from one it does not is never refused for it, since
/// CORS is the browser's to enforce and a caller that is not a browser may send `Origin` too.
fn cors(rule: &RouteRule, policy: &CorsPolicy, req: &RequestHeader, cx: &mut RequestCtx) -> Flow {
    // Two `Origin` lines are no origin a browser sends, and none of them is allowed.
    let mut origins = req.headers.get_all(http::header::ORIGIN).iter();
    let allow = match (origins.next(), origins.next()) {
        (Some(origin), None) => origin
            .to_str()
            .ok()
            .and_then(|o| policy.allowed(&o.to_ascii_lowercase())),
        _ => None,
    };
    let preflight = req.method == http::Method::OPTIONS
        && req.headers.contains_key(http::header::ORIGIN)
        && req
            .headers
            .contains_key(http::header::ACCESS_CONTROL_REQUEST_METHOD);
    if !preflight || policy.preflight_continue {
        cx.cors = Some(Cors::Pass { allow, preflight });
        return Flow::Continue;
    }
    let Some(allow) = allow else {
        cx.cors = Some(Cors::Pass {
            allow: None,
            preflight: false,
        });
        return refuse(
            rule,
            "cors",
            "origin",
            ErrorKey::CorsOriginForbidden,
            Vec::new(),
        );
    };
    cx.cors = Some(Cors::Answered);
    // Built whole here and left alone by the Response step; `X-Request-Id` is added where every
    // answer a step builds is written.
    let mut resp = ResponseHeader::build(204, Some(7)).expect("204 is a status");
    let _ = resp.insert_header("Access-Control-Allow-Origin", allow);
    if policy.credentials {
        let _ = resp.insert_header("Access-Control-Allow-Credentials", "true");
    }
    if !policy.methods.is_empty() {
        let _ = resp.insert_header("Access-Control-Allow-Methods", policy.methods.join(", "));
    }
    let vary = if policy.headers.is_empty() {
        // No list of its own: whatever the preflight asks for, so the answer varies by that too,
        // whether or not this one asked for any -- a cache must not hand an answer that allows no
        // headers to a preflight that asks for some.
        for asked in req
            .headers
            .get_all(http::header::ACCESS_CONTROL_REQUEST_HEADERS)
        {
            let _ = resp.append_header("Access-Control-Allow-Headers", asked.clone());
        }
        "Origin, Access-Control-Request-Headers"
    } else {
        let _ = resp.insert_header("Access-Control-Allow-Headers", policy.headers.join(", "));
        "Origin"
    };
    if let Some(max_age) = policy.max_age {
        let _ = resp.insert_header("Access-Control-Max-Age", max_age.to_string());
    }
    let _ = resp.insert_header("Vary", vary);
    Flow::Respond(Box::new(resp))
}

/// A cors policy's headers on an answer other than its own preflight 204, `allow` being the
/// `Access-Control-Allow-Origin` to send, if any. The upstream's own go first: the policy owns
/// CORS on its routes, so an upstream's `*` cannot widen it. A preflight the policy passed to the
/// upstream keeps the methods, headers and max-age the upstream answered it with.
///
/// No write here can fail: `Chain::compile` refuses a policy whose lists are no header value, and
/// `allow` is `*` or an `Origin` value the request carried.
fn cors_headers(
    resp: &mut ResponseHeader,
    policy: &CorsPolicy,
    allow: Option<&str>,
    preflight: bool,
) {
    let mut owned = vec![
        "access-control-allow-origin",
        "access-control-allow-credentials",
        "access-control-expose-headers",
    ];
    if !preflight {
        owned.extend([
            "access-control-allow-methods",
            "access-control-allow-headers",
            "access-control-max-age",
        ]);
    }
    for name in owned {
        resp.remove_header(name);
    }
    if let Some(allow) = allow {
        let _ = resp.insert_header("Access-Control-Allow-Origin", allow);
        if policy.credentials {
            let _ = resp.insert_header("Access-Control-Allow-Credentials", "true");
        }
        if !policy.expose_headers.is_empty() {
            let _ = resp.insert_header(
                "Access-Control-Expose-Headers",
                policy.expose_headers.join(", "),
            );
        }
    }
    vary_origin(resp);
}

/// Make `resp`'s `Vary` name `Origin`: the answer differs by it, and a cache that kept one
/// origin's answer would hand it to the next. Added as a line of its own beside any already there,
/// and not at all when one already names it or is `*`, which says the answer varies by everything.
fn vary_origin(resp: &mut ResponseHeader) {
    let named = resp
        .headers
        .get_all(http::header::VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .any(|v| v == "*" || v.eq_ignore_ascii_case("origin"));
    if !named {
        let _ = resp.append_header("Vary", "Origin");
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
        Config, ConsumerRateLimits, Filters, LimitBy, RateLimit, Redirect,
        ResponseTransformerPolicy, Timeouts,
    };
    use sha2::{Digest, Sha256};

    use crate::store::Store;

    const ALL: [Phase; 5] = [
        Phase::Access,
        Phase::UpstreamRequest,
        Phase::RequestBody,
        Phase::Response,
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
            Plugin::RequestTransformer(RequestTransformerPolicy::default()),
            Plugin::ResponseTransformer(ResponseTransformerPolicy::default()),
            cors(|_| {}),
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
                (Phase::Response, chain.response.len()),
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
            sinks: Default::default(),
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

    /// jwt runs before key_auth whatever order the policies arrive in, as the chain tries them,
    /// so the two modes never disagree about which is asked first.
    #[test]
    fn jwt_runs_before_key_auth_whatever_order_they_arrive_in() {
        let rt = Runtime::new(Config::default(), 1, Vec::new());
        let jwt = Plugin::Jwt(JwtPolicy::default());
        for plugins in [
            vec![key_auth(None), jwt.clone()],
            vec![jwt.clone(), key_auth(None)],
        ] {
            let r = rule(plugins);
            let chain = Chain::compile(&r).unwrap();
            let flow = chain.access(&proxy(), &rt, &r, &get(), None, &mut RequestCtx::default());
            assert_eq!(refused(flow).key, ErrorKey::AuthJwtMissing);
        }
    }

    const SECRET: &[u8] = b"a-secret-long-enough-for-hs256-to-be-happy";

    /// A jwt policy on `shop` that trusts `SECRET`, naming its consumer by `sub` when `claim`.
    fn jwt_policy(claim: bool) -> JwtPolicy {
        use base64::Engine;
        let k = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(SECRET);
        JwtPolicy {
            jwks:
                serde_json::json!({"keys": [{"kty": "oct", "alg": "HS256", "kid": "k1", "k": k}]})
                    .to_string(),
            consumer_claim: claim.then(|| "sub".to_string()),
            workspace: claim.then(|| "shop".to_string()),
            ..JwtPolicy::default()
        }
    }

    fn bearer(sub: serde_json::Value) -> RequestHeader {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some("k1".into());
        let claims = serde_json::json!({"sub": sub, "exp": 4102444800u64});
        let token = encode(&header, &claims, &EncodingKey::from_secret(SECRET)).unwrap();
        let mut req = get();
        req.insert_header("authorization", format!("Bearer {token}"))
            .unwrap();
        req
    }

    fn listener_with(rule: RouteRule) -> gapura_core::config::ListenerConfig {
        gapura_core::config::ListenerConfig {
            id: "store/http:80".into(),
            port: 80,
            client_port: None,
            protocol: gapura_core::config::Protocol::Http,
            hostname: None,
            tls: None,
            rules: vec![rule],
        }
    }

    /// The key `k-1` issued to `shop/mobile`, who is in `staff`; `shop/guest`, in no group; and
    /// `rule` in a listener, so `Runtime::new` compiles its JWKS.
    fn people(rule: &RouteRule) -> Runtime {
        let hash = format!("{:x}", Sha256::digest(b"k-1"));
        let config = Config {
            credentials: BTreeMap::from([(hash.clone(), "mobile".to_string())]),
            credential_workspaces: BTreeMap::from([(hash, "shop".to_string())]),
            consumers: BTreeMap::from([
                ("shop/mobile".to_string(), vec!["staff".to_string()]),
                ("shop/guest".to_string(), vec![]),
            ]),
            listeners: vec![listener_with(rule.clone())],
            ..Config::default()
        };
        Runtime::new(config, 1, Vec::new())
    }

    #[test]
    fn a_consumer_claim_names_a_consumer_and_a_name_that_is_none_is_refused() {
        let r = rule(vec![Plugin::Jwt(jwt_policy(true))]);
        let rt = people(&r);
        let chain = Chain::compile(&r).unwrap();
        let mut cx = RequestCtx::default();
        let flow = chain.access(&proxy(), &rt, &r, &bearer("mobile".into()), None, &mut cx);
        assert!(matches!(flow, Flow::Continue));
        assert_eq!(
            cx.consumer.as_ref().map(|c| c.id.as_str()),
            Some("shop/mobile")
        );
        for sub in [serde_json::json!("nobody"), serde_json::json!(7)] {
            let flow = chain.access(
                &proxy(),
                &rt,
                &r,
                &bearer(sub),
                None,
                &mut RequestCtx::default(),
            );
            assert_eq!(refused(flow).key, ErrorKey::AuthJwtInvalid);
        }
    }

    #[test]
    fn a_jwt_policy_without_a_claim_identifies_nobody() {
        let r = rule(vec![Plugin::Jwt(jwt_policy(false))]);
        let rt = people(&r);
        let mut cx = RequestCtx::default();
        let flow = Chain::compile(&r).unwrap().access(
            &proxy(),
            &rt,
            &r,
            &bearer("mobile".into()),
            None,
            &mut cx,
        );
        assert!(matches!(flow, Flow::Continue));
        assert!(cx.consumer.is_none());
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

    fn pair(name: &str, value: &str) -> (String, String) {
        (name.to_string(), value.to_string())
    }

    /// The request's edits run as one step: its headers, then its query string, on the URI the
    /// step is given.
    #[test]
    fn a_request_transform_edits_the_headers_and_the_query() {
        let r = rule(vec![Plugin::RequestTransformer(RequestTransformerPolicy {
            headers: HeaderEdits {
                remove: vec!["x-debug".into()],
                add: vec![pair("x-team", "core")],
                ..HeaderEdits::default()
            },
            query: HeaderEdits {
                remove: vec!["secret".into()],
                add: vec![pair("v", "2")],
                ..HeaderEdits::default()
            },
        })]);
        let chain = Chain::compile(&r).unwrap();
        let mut req = RequestHeader::build("GET", b"/t?secret=s&keep=1", None).unwrap();
        req.insert_header("x-debug", "1").unwrap();
        chain.upstream_request(&mut req);
        assert!(req.headers.get("x-debug").is_none());
        assert_eq!(req.headers.get("x-team").unwrap(), "core");
        assert_eq!(req.uri.to_string(), "/t?keep=1&v=2");
    }

    /// The key comes off before any transform runs, whatever order the policies arrive in: a
    /// transform listed first that renames the key's header finds nothing to move, so the key
    /// reaches the upstream under neither name.
    #[test]
    fn the_key_is_removed_before_a_transform_can_move_it() {
        let r = rule(vec![
            Plugin::RequestTransformer(RequestTransformerPolicy {
                headers: HeaderEdits {
                    rename: vec![pair("apikey", "x-key")],
                    ..HeaderEdits::default()
                },
                query: HeaderEdits::default(),
            }),
            Plugin::KeyAuth(KeyAuthPolicy {
                header: "apikey".into(),
                workspace: None,
            }),
        ]);
        let chain = Chain::compile(&r).unwrap();
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("apikey", "k").unwrap();
        chain.upstream_request(&mut req);
        assert!(req.headers.get("apikey").is_none(), "{:?}", req.headers);
        assert!(req.headers.get("x-key").is_none(), "{:?}", req.headers);
    }

    fn served_by() -> Plugin {
        Plugin::ResponseTransformer(ResponseTransformerPolicy {
            headers: HeaderEdits {
                append: vec![pair("x-served-by", "gapura")],
                ..HeaderEdits::default()
            },
        })
    }

    /// An interim head is not the answer, so it is not edited: the final head that follows it
    /// is, once. A 101 is final.
    #[test]
    fn the_response_steps_skip_an_interim_head() {
        let chain = Chain::compile(&rule(vec![served_by()])).unwrap();
        for (status, edited) in [
            (100, false),
            (103, false),
            (101, true),
            (200, true),
            (401, true),
        ] {
            let mut resp = ResponseHeader::build(status, None).unwrap();
            chain.response(&RequestCtx::default(), &mut resp);
            let got = resp.headers.get_all("x-served-by").iter().count();
            assert_eq!(got, usize::from(edited), "{status}");
        }
    }

    /// A transform that would write what the header map refuses cannot run as written, so the
    /// rule refuses every request, as one whose plugin never runs does.
    #[test]
    fn a_transform_the_header_map_would_refuse_refuses_the_rule() {
        let bad = Plugin::ResponseTransformer(ResponseTransformerPolicy {
            headers: HeaderEdits {
                add: vec![pair("x-a", "one\r\nx-injected: 1")],
                ..HeaderEdits::default()
            },
        });
        assert_eq!(
            Chain::compile(&rule(vec![bad])).err(),
            Some(Misplaced {
                plugin: "response_transformer",
                why: "it writes a header name or value HTTP does not allow",
            })
        );
        let mut on_redirect = rule(vec![served_by()]);
        on_redirect.filters.redirect = redirect();
        assert!(
            Chain::compile(&on_redirect).is_err(),
            "a redirect reaches no Response step"
        );
    }

    /// Allows `https://app.example` and one label under `example.org`, with its other fields as
    /// `edit` leaves them.
    fn cors(edit: impl FnOnce(&mut CorsPolicy)) -> Plugin {
        let mut policy = CorsPolicy {
            origins: vec!["https://app.example".into(), "https://*.example.org".into()],
            methods: vec!["GET".into(), "POST".into()],
            ..CorsPolicy::default()
        };
        edit(&mut policy);
        Plugin::Cors(policy)
    }

    fn preflight(origin: &str) -> RequestHeader {
        let mut req = RequestHeader::build("OPTIONS", b"/", None).unwrap();
        req.insert_header("origin", origin).unwrap();
        req.insert_header("access-control-request-method", "POST")
            .unwrap();
        req
    }

    fn header<'a>(resp: &'a ResponseHeader, name: &str) -> Option<&'a str> {
        resp.headers.get(name).map(|v| v.to_str().unwrap())
    }

    /// Listed after key_auth and run before it, with no key: a browser sends a preflight without
    /// credentials. The answer is built whole, and the Response step leaves it as it is.
    #[test]
    fn a_preflight_is_answered_before_any_credential_is_read() {
        let rt = Runtime::new(Config::default(), 1, Vec::new());
        let r = rule(vec![
            key_auth(None),
            ip_restriction(&["10.0.0.0/8"], &[]),
            cors(|p| {
                p.credentials = true;
                p.max_age = Some(600);
            }),
        ]);
        let chain = Chain::compile(&r).unwrap();
        let mut req = preflight("https://App.Example");
        req.insert_header("access-control-request-headers", "x-a, content-type")
            .unwrap();
        let mut cx = RequestCtx::default();
        let Flow::Respond(mut resp) = chain.access(&proxy(), &rt, &r, &req, None, &mut cx) else {
            panic!("not answered");
        };
        chain.response(&cx, &mut resp);
        assert_eq!(resp.status, 204);
        for (name, value) in [
            ("access-control-allow-origin", "https://app.example"),
            ("access-control-allow-credentials", "true"),
            ("access-control-allow-methods", "GET, POST"),
            ("access-control-allow-headers", "x-a, content-type"),
            ("access-control-max-age", "600"),
            ("vary", "Origin, Access-Control-Request-Headers"),
        ] {
            assert_eq!(header(&resp, name), Some(value), "{name}");
        }
        assert_eq!(resp.headers.get_all("vary").iter().count(), 1);

        // A list of its own is sent as it is, and the answer no longer varies by what was asked.
        let r = rule(vec![cors(|p| p.headers = vec!["x-b".into()])]);
        let chain = Chain::compile(&r).unwrap();
        let mut cx = RequestCtx::default();
        let Flow::Respond(resp) = chain.access(&proxy(), &rt, &r, &req, None, &mut cx) else {
            panic!("not answered");
        };
        assert_eq!(header(&resp, "access-control-allow-headers"), Some("x-b"));
        assert_eq!(header(&resp, "vary"), Some("Origin"));
        assert_eq!(header(&resp, "access-control-allow-credentials"), None);
        assert_eq!(header(&resp, "access-control-max-age"), None);

        // Echoing, the answer varies by what was asked even when nothing was, so a cache does not
        // hand this one to a preflight that asks for headers.
        let r = rule(vec![cors(|_| {})]);
        let chain = Chain::compile(&r).unwrap();
        let mut cx = RequestCtx::default();
        let flow = chain.access(
            &proxy(),
            &rt,
            &r,
            &preflight("https://app.example"),
            None,
            &mut cx,
        );
        let Flow::Respond(resp) = flow else {
            panic!("not answered");
        };
        assert_eq!(header(&resp, "access-control-allow-headers"), None);
        assert_eq!(
            header(&resp, "vary"),
            Some("Origin, Access-Control-Request-Headers")
        );
    }

    /// A preflight from an origin the policy does not allow is refused before anything else
    /// runs; one from two origins at once is no origin it allows.
    #[test]
    fn a_preflight_from_an_origin_not_allowed_is_refused() {
        let rt = Runtime::new(Config::default(), 1, Vec::new());
        let r = rule(vec![key_auth(None), cors(|_| {})]);
        let chain = Chain::compile(&r).unwrap();
        let mut two = preflight("https://app.example");
        two.append_header("origin", "https://app.example").unwrap();
        for req in [
            preflight("https://evil.example"),
            preflight("null"),
            preflight("https://a.b.example.org"),
            two,
        ] {
            let mut cx = RequestCtx::default();
            let failure = refused(chain.access(&proxy(), &rt, &r, &req, None, &mut cx));
            assert_eq!(failure.key, ErrorKey::CorsOriginForbidden);
            assert!(failure.headers.is_empty());
            // The 403 says it varies by origin, and allows none.
            let mut resp = ResponseHeader::build(403, None).unwrap();
            chain.response(&cx, &mut resp);
            assert_eq!(header(&resp, "access-control-allow-origin"), None);
            assert_eq!(header(&resp, "vary"), Some("Origin"));
        }
    }

    /// Passed on, a preflight goes through the rest of the chain, and the upstream's answer keeps
    /// the methods it gives, with the policy's origin in place of the upstream's.
    #[test]
    fn a_preflight_passed_on_runs_the_rest_of_the_chain() {
        let rt = Runtime::new(Config::default(), 1, Vec::new());
        let r = rule(vec![key_auth(None), cors(|p| p.preflight_continue = true)]);
        let chain = Chain::compile(&r).unwrap();
        let mut cx = RequestCtx::default();
        let req = preflight("https://app.example");
        let flow = chain.access(&proxy(), &rt, &r, &req, None, &mut cx);
        assert_eq!(refused(flow).key, ErrorKey::AuthKeyMissing);

        let mut resp = ResponseHeader::build(200, None).unwrap();
        resp.insert_header("access-control-allow-origin", "*")
            .unwrap();
        resp.insert_header("access-control-allow-methods", "PUT")
            .unwrap();
        chain.response(&cx, &mut resp);
        assert_eq!(
            header(&resp, "access-control-allow-origin"),
            Some("https://app.example")
        );
        assert_eq!(header(&resp, "access-control-allow-methods"), Some("PUT"));
    }

    /// The request a preflight asked about goes on, whatever its origin, and the answer carries
    /// the policy's headers in place of the upstream's: the origin for one it allows, nothing for
    /// one it does not, and `Vary: Origin` either way.
    #[test]
    fn an_actual_request_gets_the_policy_s_headers_in_place_of_the_upstream_s() {
        let rt = Runtime::new(Config::default(), 1, Vec::new());
        let r = rule(vec![cors(|p| {
            p.credentials = true;
            p.expose_headers = vec!["x-gapura-error".into(), "x-request-id".into()];
        })]);
        let chain = Chain::compile(&r).unwrap();
        let answer = |origin: Option<&str>| {
            let mut req = get();
            if let Some(origin) = origin {
                req.insert_header("origin", origin).unwrap();
            }
            let mut cx = RequestCtx::default();
            let flow = chain.access(&proxy(), &rt, &r, &req, None, &mut cx);
            assert!(matches!(flow, Flow::Continue), "{origin:?}");
            let mut resp = ResponseHeader::build(200, None).unwrap();
            for (name, value) in [
                ("access-control-allow-origin", "*"),
                ("access-control-allow-methods", "DELETE"),
                ("access-control-max-age", "86400"),
                ("access-control-expose-headers", "x-secret"),
                ("vary", "Accept"),
            ] {
                resp.insert_header(name, value).unwrap();
            }
            chain.response(&cx, &mut resp);
            resp
        };
        // Credentials and a `*.` entry: the origin itself, never `*`.
        let resp = answer(Some("https://web.example.org"));
        assert_eq!(
            header(&resp, "access-control-allow-origin"),
            Some("https://web.example.org")
        );
        assert_eq!(
            header(&resp, "access-control-allow-credentials"),
            Some("true")
        );
        assert_eq!(
            header(&resp, "access-control-expose-headers"),
            Some("x-gapura-error, x-request-id")
        );
        for resp in [resp, answer(Some("https://evil.example")), answer(None)] {
            assert_eq!(header(&resp, "access-control-allow-methods"), None);
            assert_eq!(header(&resp, "access-control-max-age"), None);
            let vary: Vec<&str> = resp
                .headers
                .get_all("vary")
                .iter()
                .map(|v| v.to_str().unwrap())
                .collect();
            assert_eq!(vary, ["Accept", "Origin"]);
        }
        let resp = answer(Some("https://evil.example"));
        for name in [
            "access-control-allow-origin",
            "access-control-allow-credentials",
            "access-control-expose-headers",
        ] {
            assert_eq!(header(&resp, name), None, "{name}");
        }
    }

    /// The transform runs after the policy, whatever order they arrive in, so the operator's
    /// edit has the last word.
    #[test]
    fn a_transform_edits_after_the_cors_policy() {
        let rt = Runtime::new(Config::default(), 1, Vec::new());
        let remove = Plugin::ResponseTransformer(ResponseTransformerPolicy {
            headers: HeaderEdits {
                remove: vec!["access-control-allow-origin".into()],
                ..HeaderEdits::default()
            },
        });
        let r = rule(vec![remove, cors(|_| {})]);
        let chain = Chain::compile(&r).unwrap();
        let mut req = get();
        req.insert_header("origin", "https://app.example").unwrap();
        let mut cx = RequestCtx::default();
        chain.access(&proxy(), &rt, &r, &req, None, &mut cx);
        let mut resp = ResponseHeader::build(200, None).unwrap();
        chain.response(&cx, &mut resp);
        assert_eq!(header(&resp, "access-control-allow-origin"), None);
        assert_eq!(header(&resp, "vary"), Some("Origin"));
    }

    #[test]
    fn vary_names_origin_once() {
        for (before, after) in [
            (&[][..], &["Origin"][..]),
            (&["Accept"], &["Accept", "Origin"]),
            (&["*"], &["*"]),
            (&["origin"], &["origin"]),
            (
                &["Accept", "Accept-Encoding, ORIGIN"],
                &["Accept", "Accept-Encoding, ORIGIN"],
            ),
        ] {
            let mut resp = ResponseHeader::build(200, None).unwrap();
            for v in before {
                resp.append_header("vary", *v).unwrap();
            }
            vary_origin(&mut resp);
            let got: Vec<&str> = resp
                .headers
                .get_all("vary")
                .iter()
                .map(|v| v.to_str().unwrap())
                .collect();
            assert_eq!(got, after, "{before:?}");
        }
    }

    #[test]
    fn a_cors_list_that_is_no_header_value_refuses_the_rule() {
        let bad = cors(|p| p.expose_headers = vec!["x-a\r\nx-injected: 1".into()]);
        assert_eq!(
            Chain::compile(&rule(vec![bad])).err(),
            Some(Misplaced {
                plugin: "cors",
                why: "it writes a header name or value HTTP does not allow",
            })
        );
    }
}
