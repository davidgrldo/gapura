//! The Pingora data plane: request attributes, routing decisions, the ProxyHttp implementation, TLS.
//!
//! One request, top to bottom: `request_filter` (match, the rule's Access steps, answer locally
//! or pick a cluster), `upstream_peer` (pick an endpoint), `upstream_request_filter` (rewrite,
//! headers, the UpstreamRequest steps), `upstream_response_filter` (the endpoint's outcome),
//! `response_filter` (response headers), `fail_to_connect` (retry once), `fail_to_proxy` (the
//! error key and its status, from `failure::classify`), `logging` (access log + metrics, the
//! Terminate steps). The steps are each rule's plugins, compiled per generation (`plugin`).
//! Outcomes feed passive outlier detection (`outlier`).

pub mod attrs;
// Shared with the console, which has to answer the same question for its sign-in limits.
pub use gapura_core::client_ip as client;
pub mod failure;
pub mod jwt;
pub mod outlier;
pub mod plugin;
pub mod rate_limit;
pub mod select;
pub mod tls;

use std::net::SocketAddr;
use std::sync::{Arc, LazyLock, OnceLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use gapura_core::config::{HeaderOps, Mirror, PathMatch, Protocol, RouteRule, Timeouts};
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::proxy::{FailToProxy, ProxyHttp, Session};
use pingora::upstreams::peer::HttpPeer;
use pingora::{Error, ErrorSource, ErrorType, Result};
use tokio::sync::Semaphore;

use crate::proxy::attrs::Extracted;
use crate::proxy::failure::ErrorKey;
use crate::proxy::outlier::Outcome;
use crate::proxy::plugin::{Failure, Flow, Invoke, RequestCtx};
use crate::proxy::select::{
    pick_backend, pick_endpoint, random_roll, redirect_location, rewrite_path, Local,
};
use crate::store::{Runtime, Store};
use crate::telemetry::{
    now_millis, request_id, trace_id_of, traceparent, write_access_log, AccessLog, METRICS,
};

pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const DEFAULT_UPSTREAM_TIMEOUT: Duration = Duration::from_secs(60);
/// Attempts per request: the first try plus one retry on connect failure.
const MAX_ATTEMPTS: usize = 2;
/// In-flight mirrors across all routes; beyond this they are dropped and counted as overflow.
/// ponytail: one global bound; per-route bounds if a route ever needs its own.
const MIRROR_INFLIGHT: usize = 1024;
/// A mirror may never hold resources for long: one bounded attempt, no retries.
const MIRROR_TIMEOUT: Duration = Duration::from_secs(3);
/// ponytail: one shared client, HTTP-only mirrors; TLS mirrors and body tee-ing are a follow-up.
static MIRROR_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
/// ponytail: global bound, per-route if it ever matters.
static MIRROR_PERMITS: LazyLock<Semaphore> = LazyLock::new(|| Semaphore::new(MIRROR_INFLIGHT));

pub struct GapuraProxy {
    pub store: Arc<Store>,
    /// Networks whose `X-Forwarded-For` the access log believes. Empty means none.
    pub trusted_proxies: Vec<client::Cidr>,
    /// Header names (e.g. CF-Connecting-IP) believed for the client address when no
    /// X-Forwarded-For chain exists and the peer is a trusted proxy (`--trusted-client-header`).
    pub trusted_client_headers: Vec<String>,
    /// Per-replica request limits, shared by every worker thread.
    pub limiter: rate_limit::RateLimiter,
    /// Whether the access log carries the request's query string (`--access-log-query`).
    pub access_log_query: bool,
}

/// Per-request state. Indices point into `runtime.config`; holding the Arc keeps that
/// configuration generation alive for the whole request even if a reload happens meanwhile.
pub struct Ctx {
    runtime: Option<Arc<Runtime>>,
    /// What the rule's plugins know of the request: the route, the consumer, what invokes it.
    req: RequestCtx,
    matched: Option<PathMatch>,
    tried: Vec<SocketAddr>,
    upstream: Option<SocketAddr>,
    /// The outlier record of the endpoint this attempt went to.
    health: Option<Arc<outlier::Health>>,
    extracted: Option<Extracted>,
    request_id: String,
    traceparent: String,
    scheme: &'static str,
    port: u16,
    local_status: Option<u16>,
    /// Why the gateway answered this request itself, when it did; the access log's `error_key`.
    error_key: Option<ErrorKey>,
    /// Whether the one retry after a failure on a reused upstream connection has been spent.
    reuse_retried: bool,
    started: Instant,
    upstream_started: Option<Instant>,
    client_abort: bool,
    mirrored: bool,
}

impl Ctx {
    fn rule(&self) -> Option<&RouteRule> {
        let rt = self.runtime.as_ref()?;
        let (listener, rule) = self.req.route?;
        rt.config.listeners.get(listener)?.rules.get(rule)
    }

    /// Count this attempt's outcome against the endpoint it went to.
    fn record(&self, outcome: Outcome) {
        let (Some(health), Some(rt), Some(key)) = (&self.health, &self.runtime, self.req.cluster())
        else {
            return;
        };
        let p = rt
            .config
            .clusters
            .get(key)
            .and_then(|c| c.outlier)
            .unwrap_or_default();
        if let Some(out_for) = health.record(outcome, outlier::now_ms(), &p) {
            METRICS
                .upstream_ejections_total
                .with_label_values(&[key])
                .inc();
            tracing::warn!(
                cluster = %key,
                endpoint = ?self.upstream,
                seconds = out_for.as_secs(),
                "ejecting an endpoint after consecutive failures"
            );
        }
    }

    fn route_label(&self) -> &str {
        self.rule().map(|r| r.route.as_str()).unwrap_or("-")
    }

    fn listener_label(&self) -> &str {
        match (&self.runtime, self.req.route) {
            (Some(rt), Some((i, _))) => rt
                .config
                .listeners
                .get(i)
                .map(|l| l.id.as_str())
                .unwrap_or("-"),
            _ => "-",
        }
    }
}

/// What `request_filter` decided.
enum Decision {
    NotFound,
    /// The rule's plugins cannot all run on it (see `Runtime::build`'s warning), so it refuses.
    Misplaced {
        listener: usize,
        rule: usize,
    },
    Local(Local),
    Redirect {
        status: u16,
        location: String,
    },
    Proxy {
        listener: usize,
        rule: usize,
        matched: PathMatch,
        cluster: String,
    },
}

/// Gateway API timeouts to Pingora's per-attempt read/write timeout.
///
/// Pingora 0.8 applies this to each socket read and write of an attempt, not to the attempt
/// as a whole: it is an idle bound, and a backend that keeps trickling bytes is not cut off by
/// it. Pingora has no hook that could end an exchange that is waiting on a read, so a true total
/// deadline is not available here (#217). What is enforced instead:
///
/// - The per-read bound is the smaller of `backendRequest` and `request`; setting
///   `backendRequest` no longer makes `request` ignored. `0` (Gateway API: "0s", no timeout)
///   drops that field from the choice, and only when neither field bounds anything is the
///   timeout disabled. With neither field set the default applies.
/// - `request` is also a budget for the whole request, retries included, counted from when the
///   request was read: see [`request_budget_left`], which caps each attempt's connect and read
///   timeouts to what is left of it and refuses an attempt once it is spent.
pub fn effective_timeout(t: &Timeouts) -> Option<Duration> {
    if t.backend_request_ms.is_none() && t.request_ms.is_none() {
        return Some(DEFAULT_UPSTREAM_TIMEOUT);
    }
    [t.backend_request_ms, t.request_ms]
        .into_iter()
        .flatten()
        .filter(|&ms| ms > 0)
        .min()
        .map(Duration::from_millis)
}

/// What is left of the rule's `request` timeout `elapsed` into the request, or `None` when it
/// sets none (unset or "0s"). `Some(Duration::ZERO)` means it is spent.
pub fn request_budget_left(t: &Timeouts, elapsed: Duration) -> Option<Duration> {
    t.request_ms
        .filter(|&ms| ms > 0)
        .map(|ms| Duration::from_millis(ms).saturating_sub(elapsed))
}

/// The connect timeout for `t`'s rule: its own, where 0 or unset means the default.
pub fn connect_timeout(t: &Timeouts) -> Duration {
    t.connect_ms
        .filter(|&ms| ms > 0)
        .map(Duration::from_millis)
        .unwrap_or(DEFAULT_CONNECT_TIMEOUT)
}

/// RFC 9110 section 9.2.2: sending these twice has the effect of sending them once.
fn idempotent(method: &http::Method) -> bool {
    use http::Method;
    [
        Method::GET,
        Method::HEAD,
        Method::OPTIONS,
        Method::TRACE,
        Method::PUT,
        Method::DELETE,
    ]
    .contains(method)
}

/// Small header-op adapter so the same `HeaderOps` apply to requests and responses.
trait HeaderTarget {
    fn set(&mut self, name: &str, value: &str) -> Result<()>;
    fn add(&mut self, name: &str, value: &str) -> Result<()>;
    fn del(&mut self, name: &str);
}

impl HeaderTarget for RequestHeader {
    fn set(&mut self, name: &str, value: &str) -> Result<()> {
        self.insert_header(name.to_string(), value)
    }
    fn add(&mut self, name: &str, value: &str) -> Result<()> {
        self.append_header(name.to_string(), value).map(|_| ())
    }
    fn del(&mut self, name: &str) {
        self.remove_header(name);
    }
}

impl HeaderTarget for ResponseHeader {
    fn set(&mut self, name: &str, value: &str) -> Result<()> {
        self.insert_header(name.to_string(), value)
    }
    fn add(&mut self, name: &str, value: &str) -> Result<()> {
        self.append_header(name.to_string(), value).map(|_| ())
    }
    fn del(&mut self, name: &str) {
        self.remove_header(name);
    }
}

/// Gateway API order: set, then add, then remove.
fn apply_header_ops(target: &mut impl HeaderTarget, ops: &HeaderOps) -> Result<()> {
    for (name, value) in &ops.set {
        target.set(name, value)?;
    }
    for (name, value) in &ops.add {
        target.add(name, value)?;
    }
    for name in &ops.remove {
        target.del(name);
    }
    Ok(())
}

/// The head and body of a locally generated error answer: the key in `X-Gapura-Error` and in
/// the body, plain text unless the caller prefers JSON, the request id, and never any internal
/// detail. `extra` carries what one kind of answer adds: the challenge on a 401, the limit
/// headers on a 429. `Content-Length` is always explicit: without it the body is
/// close-delimited, and the connection closes after every error while pingora announces
/// keep-alive.
fn error_response(
    key: ErrorKey,
    request_id: &str,
    json: bool,
    extra: &[(&'static str, String)],
) -> Result<(ResponseHeader, Bytes)> {
    let (content_type, body) = failure::render(key, request_id, json);
    let mut resp = ResponseHeader::build(key.status(), Some(5 + extra.len()))?;
    resp.insert_header("Content-Type", content_type)?;
    resp.insert_header("Content-Length", body.len().to_string())?;
    resp.insert_header("Cache-Control", "no-store")?;
    resp.insert_header("X-Request-Id", request_id)?;
    resp.insert_header(failure::HEADER, key.as_str())?;
    for (name, value) in extra {
        resp.insert_header(*name, value.as_str())?;
    }
    Ok((resp, Bytes::from(body)))
}

/// Answer the request with `key`, and record it for the access log.
async fn write_error(
    session: &mut Session,
    ctx: &mut Ctx,
    key: ErrorKey,
    extra: &[(&'static str, String)],
) -> Result<()> {
    ctx.local_status = Some(key.status());
    ctx.error_key = Some(key);
    // Every Accept line, joined: RFC 9110 section 5.3 makes them one list.
    let accept: Vec<&str> = session
        .req_header()
        .headers
        .get_all(http::header::ACCEPT)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    let json = failure::wants_json(&accept.join(","));
    let (resp, body) = error_response(key, &ctx.request_id, json, extra)?;
    session.write_response_header(Box::new(resp), false).await?;
    session.write_response_body(Some(body), true).await
}

/// Answer the request as a step, or the router, decided; `Continue` answers nothing. Whether
/// the request was answered is what `request_filter` returns.
async fn answer(session: &mut Session, ctx: &mut Ctx, flow: Flow) -> Result<bool> {
    match flow {
        Flow::Continue => Ok(false),
        Flow::Respond(resp) => {
            let status = resp.status.as_u16();
            session.write_response_header(resp, true).await?;
            ctx.local_status = Some(status);
            ctx.req.invoke = Invoke::Serve;
            Ok(true)
        }
        Flow::Fail(failure) => {
            write_error(session, ctx, failure.key, &failure.headers).await?;
            Ok(true)
        }
    }
}

/// Whether `ex` would match a different rule once its `;params` are stripped, the way a servlet
/// container reads the path (#213). `/admin;x/secret` misses an `/admin` prefix (the byte after
/// it is `;`, not `/`) and falls through to a catch-all, while Tomcat serves it as
/// `/admin/secret`: the `/admin` policy never ran. Refusing every `;` would break matrix
/// parameters and `;jsessionid=` URLs that route the same either way, so only a request whose
/// two readings disagree is refused. Paths without a `;` cost nothing.
fn path_params_change_the_route(rt: &Runtime, port: u16, ex: &Extracted) -> bool {
    let Some(stripped) = attrs::without_path_params(&ex.path) else {
        return false;
    };
    let rule_for = |path: &str| {
        let mut req = ex.attrs();
        req.path = path;
        rt.config
            .match_port_with(port, &req, rt.regexes())
            .map(|hit| (hit.listener_index, hit.entry.rule))
    };
    rule_for(&ex.path) != rule_for(&stripped)
}

/// Why a JWT policy refuses `req` -- its key, the metric's reason, and the challenge to answer
/// with; `None` admits it.
///
/// Every Authorization line is forwarded upstream, so the check must cover every line, not just
/// the first (#190). Lines are counted raw (#212): counting only those that parse as UTF-8 and as
/// `Bearer <token>` let `Bearer\t<forged>`, or a line carrying obs-text, through unverified beside
/// a valid one, and a backend that splits on any whitespace or keeps the first duplicate then read
/// the forged token. So one Authorization line per request, whatever its shape; a single line that
/// is not UTF-8 or not a bearer presents no token and is refused as a missing one.
fn jwt_refusal(
    req: &RequestHeader,
    policy: &gapura_core::config::JwtPolicy,
    keys: &jwt::Keys,
) -> Option<(ErrorKey, &'static str, &'static str)> {
    let mut lines = req.headers.get_all(http::header::AUTHORIZATION).iter();
    let first = lines.next();
    if lines.next().is_some() {
        return Some((
            ErrorKey::AuthJwtInvalid,
            "multiple_bearer",
            // RFC 6750 section 3.1: more than one credential is a malformed request.
            "Bearer error=\"invalid_request\"",
        ));
    }
    let presented = jwt::bearer(first.and_then(|v| v.to_str().ok()));
    jwt::verify(policy, keys, presented)
        .err()
        .map(|r| (ErrorKey::from(&r), r.as_str(), "Bearer"))
}

/// The client address after the trusted-proxy walk, the same answer the access log records:
/// one computation so limiting and logging can never disagree about who the client is.
/// `trusted_client_headers` names the single-IP headers (e.g. CF-Connecting-IP) consulted when
/// no XFF chain exists; the walk decides whether any of it may be believed.
fn effective_client_ip(
    session: &Session,
    trusted: &[client::Cidr],
    trusted_client_headers: &[String],
) -> Option<std::net::IpAddr> {
    session.client_addr().and_then(|a| a.as_inet()).map(|a| {
        client_ip_of(
            session.req_header(),
            a.ip(),
            trusted,
            trusted_client_headers,
        )
    })
}

/// [`effective_client_ip`] for a peer already known, apart from the session so it is testable.
fn client_ip_of(
    req: &RequestHeader,
    peer: std::net::IpAddr,
    trusted: &[client::Cidr],
    trusted_client_headers: &[String],
) -> std::net::IpAddr {
    let forwarded_for = forwarded_for(req);
    // First configured single-IP header present on the request, in flag order.
    let named = trusted_client_headers
        .iter()
        .find_map(|name| header_str(req, name.as_str()));
    client::client_ip(peer, forwarded_for.as_deref(), trusted, named)
}

/// Every `X-Forwarded-For` field line, in order, as the one comma-joined list RFC 9110 section
/// 5.3 says they are. Reading only the first line trusted the client: a proxy that adds its own
/// line rather than appending to the client's (HAProxy's `option forwardfor`) leaves the first
/// line entirely client-written, and the right-to-left walk then started inside it. A line that
/// is not valid UTF-8 is kept, lossily, rather than dropped, so it stays in its place in the
/// chain as a hop the walk cannot parse and skips -- dropping it could move a client-written
/// line into the place of a proxy's.
fn forwarded_for(req: &RequestHeader) -> Option<String> {
    let mut lines = req.headers.get_all("x-forwarded-for").iter();
    let first = lines.next()?;
    let mut joined = String::from_utf8_lossy(first.as_bytes()).into_owned();
    for line in lines {
        joined.push_str(", ");
        joined.push_str(&String::from_utf8_lossy(line.as_bytes()));
    }
    Some(joined)
}

/// The `X-Forwarded-For` value to send upstream: every inbound line, joined, then the peer.
/// Rebuilding from the first line alone dropped the hops on the others, the real one included,
/// from what upstreams see. The peer is canonical (#252): on a dual-stack `[::]` listener an
/// IPv4 client arrives as `::ffff:203.0.113.9`, and a backend that allowlists or geolocates the
/// last hop must see `203.0.113.9`, as the access log and the rate limiter already do.
fn forwarded_for_with_hop(req: &RequestHeader, peer: std::net::IpAddr) -> String {
    let hop = peer.to_canonical();
    match forwarded_for(req) {
        Some(existing) => format!("{existing}, {hop}"),
        None => hop.to_string(),
    }
}

fn header_str<'a>(req: &'a RequestHeader, name: &str) -> Option<&'a str> {
    req.headers.get(name).and_then(|v| v.to_str().ok())
}

/// URL and headers for a headers-only mirror of the outbound request: the rewritten path and
/// query with the final header set, minus the framing headers that would promise a body we do
/// not send. Pure, so the shape is unit-tested without a network.
fn mirror_parts(upstream: &RequestHeader, endpoint: SocketAddr) -> (String, http::HeaderMap) {
    let path_and_query = upstream
        .uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let url = format!("http://{endpoint}{path_and_query}");
    let mut headers = upstream.headers.clone();
    headers.remove(http::header::CONTENT_LENGTH);
    headers.remove(http::header::TRANSFER_ENCODING);
    (url, headers)
}

/// Fire a headers-only mirror of the outbound request, fire-and-forget.
///
/// `try_acquire` means the primary is NEVER blocked or delayed by mirroring: no permit, no
/// mirror (counted as `overflow`). The task owns only cloned data -- an `Arc` snapshot of the
/// config generation, the route label, and the fully-built request -- so no failure on the
/// mirror path can touch the primary's decision or its response. Responses from the mirror are
/// ignored per the Gateway API definition.
fn fire_mirror(rt: &Arc<Runtime>, mirror: &Mirror, upstream: &RequestHeader, ctx: &mut Ctx) {
    // Same selection as a primary: round-robin cursor over the mirror cluster's endpoints,
    // ejected ones skipped. A mirror's own outcome is not recorded: nothing reads its answer.
    // A cluster that vanished between translate and now, or has no endpoints, is an error like
    // any other mirror failure: counted, never felt by the primary.
    let endpoint = rt.config.clusters.get(&mirror.cluster).and_then(|cluster| {
        let cursor = rt.next_index(&mirror.cluster).unwrap_or(0);
        let ejected = outlier::ejected_at(rt.health(&mirror.cluster), outlier::now_ms());
        let max_out = cluster.outlier.unwrap_or_default().max_ejected_percent;
        pick_endpoint(cluster, cursor, &[], ejected, max_out)
            .ok()
            .map(|(_, addr)| addr)
    });
    let Some(endpoint) = endpoint else {
        METRICS
            .mirror_requests_total
            .with_label_values(&[ctx.route_label(), "error"])
            .inc();
        return;
    };
    let Ok(permit) = MIRROR_PERMITS.try_acquire() else {
        METRICS
            .mirror_requests_total
            .with_label_values(&[ctx.route_label(), "overflow"])
            .inc();
        return;
    };
    let rt = Arc::clone(rt);
    let route = ctx.route_label().to_string();
    let method = upstream.method.clone();
    let (url, headers) = mirror_parts(upstream, endpoint);
    // No redirects: a mirror is fire-and-forget, and following a 3xx would send a copy of the
    // request wherever the mirror backend's Location pointed, from the gateway's own network.
    let client = MIRROR_CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("a client with no TLS settings builds, as reqwest::Client::new assumes")
    });
    let request = client.request(method, url).headers(headers);
    ctx.mirrored = true;
    tokio::spawn(async move {
        // The permit is held for the whole task: in-flight mirrors stay bounded end to end.
        let _permit = permit;
        let result = match tokio::time::timeout(MIRROR_TIMEOUT, request.send()).await {
            Ok(Ok(_)) => "sent",
            Ok(Err(_)) => "error",
            Err(_) => "timeout",
        };
        METRICS
            .mirror_requests_total
            .with_label_values(&[&route, result])
            .inc();
        // Holding `rt` keeps the config generation this mirror was computed against alive
        // until the request is done, so a reload cannot tear it.
        drop(rt);
    });
}

#[async_trait]
impl ProxyHttp for GapuraProxy {
    type CTX = Ctx;

    fn new_ctx(&self) -> Ctx {
        Ctx {
            runtime: None,
            req: RequestCtx::default(),
            matched: None,
            tried: Vec::new(),
            upstream: None,
            health: None,
            extracted: None,
            request_id: String::new(),
            traceparent: String::new(),
            scheme: "http",
            port: 0,
            local_status: None,
            error_key: None,
            reuse_retried: false,
            started: Instant::now(),
            upstream_started: None,
            client_abort: false,
            mirrored: false,
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Ctx) -> Result<bool> {
        let rt = self.store.load_full();
        ctx.port = session
            .server_addr()
            .and_then(|a| a.as_inet())
            .map(|a| a.port())
            .unwrap_or(0);
        {
            let req = session.req_header();
            ctx.request_id = header_str(req, "x-request-id")
                .filter(|v| {
                    !v.is_empty() && v.len() <= 128 && v.chars().all(|c| c.is_ascii_graphic())
                })
                .map(str::to_string)
                .unwrap_or_else(request_id);
            ctx.traceparent = traceparent(header_str(req, "traceparent"));
        }
        match Extracted::from_request(session.req_header()) {
            Ok(ex) => ctx.extracted = Some(ex),
            Err(why) => {
                // No route is consulted: a target that cannot be normalised has no path a
                // policy could be attached to, and guessing one is the bypass this refuses.
                // The same holds for a host the backend may read differently from the one we
                // would match (two Host lines, or one that disagrees with the authority).
                tracing::debug!(reason = why, "refusing a request target");
                write_error(session, ctx, ErrorKey::InvalidRequestTarget, &[]).await?;
                return Ok(true);
            }
        }

        if path_params_change_the_route(&rt, ctx.port, ctx.extracted.as_ref().expect("set above")) {
            tracing::debug!(
                reason = "path parameters change the route",
                "refusing a request target"
            );
            write_error(session, ctx, ErrorKey::InvalidRequestTarget, &[]).await?;
            return Ok(true);
        }

        let decision = {
            let ex = ctx.extracted.as_ref().expect("set above");
            match rt
                .config
                .match_port_with(ctx.port, &ex.attrs(), rt.regexes())
            {
                None => Decision::NotFound,
                Some(hit) => {
                    // The scheme comes from the listener that actually won the match, and feeds
                    // both the redirect Location and X-Forwarded-Proto.
                    ctx.scheme = match hit.listener.protocol {
                        Protocol::Https => "https",
                        Protocol::Http => "http",
                    };
                    if !matches!(rt.chain(hit.listener_index, hit.entry.rule), Some(Ok(_))) {
                        // Before the redirect, which is how a rule comes to reach none of its
                        // plugins' phases: such a rule must not answer as though they had run.
                        Decision::Misplaced {
                            listener: hit.listener_index,
                            rule: hit.entry.rule,
                        }
                    } else if let Some(redirect) = &hit.rule.filters.redirect {
                        // A remapped listener is dialed through a Service that maps the
                        // client-facing port onto the bound one: the Location must name the
                        // port the client used, never the internal socket.
                        let client_port = hit.listener.client_port.unwrap_or(ctx.port);
                        let location = redirect_location(
                            redirect,
                            ctx.scheme,
                            &ex.host,
                            client_port,
                            &ex.path,
                            ex.query_string.as_deref(),
                            &hit.entry.matcher.path,
                        );
                        Decision::Redirect {
                            status: redirect.status,
                            location,
                        }
                    } else {
                        match pick_backend(&hit.rule.backends, random_roll) {
                            Err(local) => Decision::Local(local),
                            Ok(key) => match rt.config.clusters.get(key) {
                                None => Decision::Local(Local::NoBackend),
                                Some(cluster) if cluster.endpoints.is_empty() => {
                                    Decision::Local(Local::NoEndpoints)
                                }
                                Some(_) => Decision::Proxy {
                                    listener: hit.listener_index,
                                    rule: hit.entry.rule,
                                    matched: hit.entry.matcher.path.clone(),
                                    cluster: key.to_string(),
                                },
                            },
                        }
                    }
                }
            }
        };

        ctx.runtime = Some(rt);
        match decision {
            Decision::Proxy {
                listener,
                rule,
                matched,
                cluster,
            } => {
                // The rule's Access steps -- its policies, then its limit -- run after the match and
                // before anything upstream is touched: a refused request must cost the backend
                // nothing. A clone of the Arc, not a borrow of the context: answering needs
                // `&mut ctx`.
                let rt = Arc::clone(ctx.runtime.as_ref().expect("set above"));
                let r = &rt.config.listeners[listener].rules[rule];
                let peer = session
                    .client_addr()
                    .and_then(|a| a.as_inet())
                    .map(|a| a.ip());
                let flow = match rt.chain(listener, rule) {
                    Some(Ok(chain)) => {
                        chain.access(self, &rt, r, session.req_header(), peer, &mut ctx.req)
                    }
                    // Answered as `Decision::Misplaced` before it got here.
                    _ => Flow::Fail(Failure {
                        key: ErrorKey::InternalError,
                        headers: Vec::new(),
                    }),
                };
                // Attributed before answering: metrics, the duration histogram and the access log
                // read it, and a refusal that records route="-" tells an operator nothing.
                ctx.req.route = Some((listener, rule));
                if !matches!(flow, Flow::Continue) {
                    return answer(session, ctx, flow).await;
                }
                ctx.matched = Some(matched);
                ctx.req.invoke = Invoke::Upstream(cluster);
                Ok(false)
            }
            Decision::Redirect { status, location } => {
                let mut resp = ResponseHeader::build(status, Some(3))?;
                resp.insert_header("Location", location)?;
                resp.insert_header("Content-Length", "0")?;
                resp.insert_header("X-Request-Id", ctx.request_id.clone())?;
                answer(session, ctx, Flow::Respond(Box::new(resp))).await
            }
            Decision::Misplaced { listener, rule } => {
                ctx.req.route = Some((listener, rule));
                write_error(session, ctx, ErrorKey::InternalError, &[]).await?;
                Ok(true)
            }
            Decision::Local(local) => {
                write_error(session, ctx, local.key(), &[]).await?;
                Ok(true)
            }
            Decision::NotFound => {
                write_error(session, ctx, ErrorKey::NoRoute, &[]).await?;
                Ok(true)
            }
        }
    }

    async fn upstream_peer(&self, _session: &mut Session, ctx: &mut Ctx) -> Result<Box<HttpPeer>> {
        let rt = ctx.runtime.clone().ok_or_else(|| {
            Error::explain(
                ErrorType::InternalError,
                "upstream_peer before request_filter",
            )
        })?;
        let key = ctx.req.cluster().map(str::to_string).ok_or_else(|| {
            Error::explain(ErrorType::InternalError, "upstream_peer without a cluster")
        })?;
        let cluster = rt.config.clusters.get(&key).ok_or_else(|| {
            Error::explain(ErrorType::InternalError, "cluster missing from config")
        })?;
        let cursor = rt.next_index(&key).unwrap_or(0);
        let records = rt.health(&key);
        let max_out = cluster.outlier.unwrap_or_default().max_ejected_percent;
        let (index, addr) = pick_endpoint(
            cluster,
            cursor,
            &ctx.tried,
            outlier::ejected_at(records, outlier::now_ms()),
            max_out,
        )
        .map_err(|_| Error::explain(ErrorType::HTTPStatus(503), "no endpoint left to try"))?;
        ctx.upstream = Some(addr);
        ctx.health = records.get(index).cloned().flatten();
        let mut peer = match &cluster.tls {
            None => HttpPeer::new(addr, false, String::new()),
            Some(tls) => {
                let mut peer = HttpPeer::new(addr, true, tls.sni.clone());
                if tls.insecure {
                    // Opt-in per Service (gapura.dev/backend-tls: insecure): encrypt, do not verify.
                    peer.options.verify_cert = false;
                    peer.options.verify_hostname = false;
                } else if tls.ca_pem.is_some() {
                    // None here means the bundle failed to parse at load time; verification then
                    // runs against the system store and fails loudly instead of silently trusting.
                    peer.options.ca = rt.upstream_ca(&key);
                }
                // Pooled connections are keyed by address, SNI and verify flags, not by CA bundle:
                // one pool per cluster so a connection verified under one trust anchor is never
                // reused by another cluster.
                peer.group_key = {
                    let mut h = std::hash::DefaultHasher::new();
                    std::hash::Hash::hash(&key, &mut h);
                    std::hash::Hasher::finish(&h)
                };
                peer
            }
        };
        // A retry starts with whatever is left of the request's budget, not a fresh one (#217).
        let left = ctx
            .rule()
            .and_then(|r| request_budget_left(&r.timeouts, ctx.started.elapsed()));
        if left == Some(Duration::ZERO) {
            return Err(Error::explain(
                ErrorType::HTTPStatus(504),
                "the request timeout was spent before this attempt",
            ));
        }
        let within_budget = |d: Duration| left.map_or(d, |left| d.min(left));
        let timeout = ctx
            .rule()
            .map(|r| effective_timeout(&r.timeouts))
            .unwrap_or(Some(DEFAULT_UPSTREAM_TIMEOUT))
            .map(within_budget);
        peer.options.connection_timeout = Some(within_budget(
            ctx.rule()
                .map_or(DEFAULT_CONNECT_TIMEOUT, |r| connect_timeout(&r.timeouts)),
        ));
        peer.options.read_timeout = timeout;
        peer.options.write_timeout = timeout;
        ctx.upstream_started = Some(Instant::now());
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream: &mut RequestHeader,
        ctx: &mut Ctx,
    ) -> Result<()> {
        let Some(rt) = ctx.runtime.clone() else {
            return Ok(());
        };
        let Some((li, ri)) = ctx.req.route else {
            return Ok(());
        };
        let rule = &rt.config.listeners[li].rules[ri];

        // Removed unconditionally, before anything is set. This header is the gateway's word
        // about who called; a client that sends it themselves must not be believed, and an
        // upstream cannot tell the two apart. Stripping only when a policy ran would leave every
        // route without one forwarding whatever a caller claimed.
        upstream.remove_header(gapura_core::credentials::CONSUMER_HEADER);
        if let Some(consumer) = &ctx.req.consumer {
            upstream.insert_header(
                gapura_core::credentials::CONSUMER_HEADER,
                consumer.name.as_str(),
            )?;
        }
        if let Some(Ok(chain)) = rt.chain(li, ri) {
            chain.upstream_request(upstream);
        }

        // Forward the path that was matched. Without this a normalised request would match one
        // string and reach the backend as another, which is exactly the disagreement
        // normalisation exists to remove. A URLRewrite below replaces it again, from `ex.path`.
        if let Some(ex) = ctx.extracted.as_ref().filter(|ex| ex.path_normalized) {
            let target = match &ex.query_string {
                Some(q) => format!("{}?{q}", ex.path),
                None => ex.path.clone(),
            };
            match target.parse::<http::Uri>() {
                Ok(uri) => upstream.set_uri(uri),
                Err(e) => {
                    tracing::warn!(error = %e, "the normalised path is not a valid URI, keeping the original")
                }
            }
        }

        if let Some(rewrite) = &rule.filters.rewrite {
            if let (Some(modifier), Some(matched), Some(ex)) =
                (&rewrite.path, &ctx.matched, &ctx.extracted)
            {
                let new_path = rewrite_path(modifier, &ex.path, matched);
                let target = match &ex.query_string {
                    Some(q) => format!("{new_path}?{q}"),
                    None => new_path,
                };
                match target.parse::<http::Uri>() {
                    Ok(uri) => upstream.set_uri(uri),
                    Err(e) => {
                        tracing::warn!(target, error = %e, "rewritten path is not a valid URI, keeping the original")
                    }
                }
            }
            if let Some(host) = &rewrite.hostname {
                upstream.insert_header("Host", host.as_str())?;
            }
        }

        apply_header_ops(upstream, &rule.filters.request_headers)?;

        if let Some(ex) = &ctx.extracted {
            if !ex.host.is_empty() {
                upstream.insert_header("X-Forwarded-Host", ex.host.as_str())?;
            }
        }
        upstream.insert_header("X-Forwarded-Proto", ctx.scheme)?;
        if let Some(peer) = session.client_addr().and_then(|a| a.as_inet()) {
            let value = forwarded_for_with_hop(upstream, peer.ip());
            upstream.insert_header("X-Forwarded-For", value)?;
        }
        upstream.insert_header("X-Request-Id", ctx.request_id.clone())?;
        upstream.insert_header("traceparent", ctx.traceparent.clone())?;

        // The mirror fires only on requests that reached an upstream -- redirects answered in
        // request_filter never get here -- and after every header mutation above, so it copies
        // the final rewritten, modified header set. Once per request: pingora runs this filter
        // on every attempt, and a retry after a reused connection failed must not send the
        // mirror backend a second copy.
        if let Some(mirror) = &rule.filters.mirror {
            if !ctx.mirrored {
                fire_mirror(&rt, mirror, upstream, ctx);
            }
        }
        Ok(())
    }

    async fn upstream_response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Ctx,
    ) -> Result<()> {
        // The gateway failures, as Envoy counts them: the endpoint answered, but the way a broken
        // proxy or an overloaded instance does. A 500 is the application's, usually the request's.
        ctx.record(match upstream_response.status.as_u16() {
            502..=504 => Outcome::Failure,
            _ => Outcome::Success,
        });
        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Ctx,
    ) -> Result<()> {
        if let Some(rule) = ctx.rule() {
            apply_header_ops(upstream_response, &rule.filters.response_headers)?;
        }
        if upstream_response.headers.get("x-request-id").is_none() {
            upstream_response.insert_header("X-Request-Id", ctx.request_id.clone())?;
        }
        Ok(())
    }

    /// A failure after the upstream connection was established or reused. Pingora's default
    /// retries any request that failed on a reused connection, up to its `max_retries` (16),
    /// whatever the method, replaying the buffered body. A pooled connection the backend already
    /// closed is the common case and worth one retry; a `POST` the backend may have processed
    /// before the connection died is not something to send again. So: one retry, idempotent
    /// methods only, and never once the body no longer fits the retry buffer.
    fn error_while_proxy(
        &self,
        peer: &HttpPeer,
        session: &mut Session,
        e: Box<Error>,
        ctx: &mut Ctx,
        client_reused: bool,
    ) -> Box<Error> {
        let mut e = e.more_context(format!("Peer: {peer}"));
        let retry = client_reused
            && !ctx.reuse_retried
            && idempotent(&session.req_header().method)
            && !session.as_ref().retry_buffer_truncated();
        if retry {
            ctx.reuse_retried = true;
        }
        e.retry.decide_reuse(retry);
        e
    }

    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut Ctx,
        mut e: Box<Error>,
    ) -> Box<Error> {
        let cluster = ctx.req.cluster().unwrap_or("-").to_string();
        METRICS
            .upstream_errors_total
            .with_label_values(&[&cluster, "connect"])
            .inc();
        ctx.record(Outcome::Failure);
        if let Some(addr) = ctx.upstream {
            ctx.tried.push(addr);
        }
        let more_endpoints = ctx
            .runtime
            .as_ref()
            .and_then(|rt| rt.config.clusters.get(&cluster))
            .is_some_and(|c| c.endpoints.len() > ctx.tried.len());
        if ctx.tried.len() < MAX_ATTEMPTS && more_endpoints {
            e.set_retry(true);
        }
        e
    }

    async fn fail_to_proxy(&self, session: &mut Session, e: &Error, ctx: &mut Ctx) -> FailToProxy {
        let upstream = matches!(e.esource(), ErrorSource::Upstream);
        // Mark it above the status mapping so that every path through this function reaches it: a
        // downstream failure yields no key and an abort mid-body has already written a response,
        // so neither reaches the error-response branch below. What the flag means then rests on
        // `failure::classify` returning `None` for a downstream failure -- no key is what keeps
        // an abort from being answered and logged as an error of ours.
        if matches!(e.esource(), ErrorSource::Downstream) {
            ctx.client_abort = true;
        }
        let key = failure::classify(e);
        let code = key.map_or(0, ErrorKey::status);
        if upstream {
            let kind = match e.etype() {
                ErrorType::ReadTimedout | ErrorType::WriteTimedout => "timeout",
                ErrorType::ConnectTimedout
                | ErrorType::ConnectRefused
                | ErrorType::ConnectNoRoute
                | ErrorType::ConnectError
                | ErrorType::TLSHandshakeFailure
                | ErrorType::TLSHandshakeTimedout
                | ErrorType::InvalidCert => "connect",
                ErrorType::ReadError | ErrorType::WriteError | ErrorType::ConnectionClosed => {
                    "read"
                }
                _ => "other",
            };
            // A connect failure was counted, and recorded against its endpoint, in fail_to_connect.
            // A read error is most often a pooled connection the backend had already closed,
            // which says nothing about the endpoint; a timeout does.
            if kind == "timeout" {
                ctx.record(Outcome::Failure);
            }
            if kind != "connect" {
                METRICS
                    .upstream_errors_total
                    .with_label_values(&[ctx.req.cluster().unwrap_or("-"), kind])
                    .inc();
            }
        }
        // Only answer when nothing has been sent yet: a failure mid-body must not append an error
        // text to the streamed response. Pingora drops the downstream connection after this, so
        // say so in the header instead of advertising keep-alive.
        if let Some(key) = key.filter(|_| session.response_written().is_none()) {
            session.set_keepalive(None);
            if let Err(write_err) = write_error(session, ctx, key, &[]).await {
                tracing::debug!(error = %write_err, "could not write error response, client likely gone");
            }
        }
        FailToProxy {
            error_code: code,
            can_reuse_downstream: false,
        }
    }

    async fn logging(&self, session: &mut Session, e: Option<&Error>, ctx: &mut Ctx) {
        let status = session
            .response_written()
            .map(|r| r.status.as_u16())
            .or(ctx.local_status)
            .unwrap_or(0);
        let route = ctx.route_label().to_string();
        let listener = ctx.listener_label().to_string();
        METRICS
            .requests_total
            .with_label_values(&[&route, &status.to_string()])
            .inc();
        METRICS
            .request_duration_seconds
            .with_label_values(&[&route])
            .observe(ctx.started.elapsed().as_secs_f64());

        let upstream = ctx.upstream.map(|a| a.to_string());
        let client_ip =
            effective_client_ip(session, &self.trusted_proxies, &self.trusted_client_headers)
                .map(|ip| ip.to_string());
        let user_agent = header_str(session.req_header(), "user-agent").map(str::to_string);
        // Read off the raw URI, not the extracted path: extraction strips the query, and this
        // field is the one place the deployment may ask to keep it.
        let query = self
            .access_log_query
            .then(|| session.req_header().uri.query())
            .flatten();
        let (host, path, method) = match &ctx.extracted {
            Some(ex) => (ex.host.as_str(), ex.path.as_str(), ex.method.as_str()),
            None => (
                "",
                session.req_header().uri.path(),
                session.req_header().method.as_str(),
            ),
        };
        write_access_log(&AccessLog {
            ts_ms: now_millis(),
            request_id: &ctx.request_id,
            trace_id: trace_id_of(&ctx.traceparent),
            method,
            host,
            path,
            query,
            status,
            bytes: session.body_bytes_sent(),
            duration_ms: ctx.started.elapsed().as_millis() as u64,
            upstream_duration_ms: ctx.upstream_started.map(|t| t.elapsed().as_millis() as u64),
            client_abort: ctx.client_abort,
            mirrored: ctx.mirrored,
            listener: &listener,
            route: &route,
            upstream: upstream.as_deref(),
            client_ip: client_ip.as_deref(),
            user_agent: user_agent.as_deref(),
            error: e.map(|e| e.to_string()),
            error_key: ctx.error_key.map(ErrorKey::as_str),
        });
        // Once the answer is out, whatever it was: a request refused in Access gets here too, and
        // so a step can settle what it counted for one.
        let chain = ctx
            .req
            .route
            .and_then(|(l, r)| ctx.runtime.as_ref()?.chain(l, r)?.as_ref().ok());
        ctx.req.terminate(chain);
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn only_idempotent_methods_may_be_replayed() {
        use http::Method;
        for m in [
            Method::GET,
            Method::HEAD,
            Method::OPTIONS,
            Method::PUT,
            Method::DELETE,
        ] {
            assert!(idempotent(&m), "{m}");
        }
        for m in [Method::POST, Method::PATCH, Method::CONNECT] {
            assert!(!idempotent(&m), "{m}");
        }
    }

    use super::*;

    #[test]
    fn connect_timeout_is_the_rules_own_or_the_default() {
        assert_eq!(
            connect_timeout(&Timeouts::default()),
            DEFAULT_CONNECT_TIMEOUT
        );
        assert_eq!(
            connect_timeout(&Timeouts {
                connect_ms: Some(250),
                ..Timeouts::default()
            }),
            Duration::from_millis(250)
        );
        assert_eq!(
            connect_timeout(&Timeouts {
                connect_ms: Some(0),
                ..Timeouts::default()
            }),
            DEFAULT_CONNECT_TIMEOUT
        );
    }

    #[test]
    fn effective_timeout_follows_gateway_api_zero_means_disabled() {
        assert_eq!(
            effective_timeout(&Timeouts::default()),
            Some(DEFAULT_UPSTREAM_TIMEOUT)
        );
        assert_eq!(
            effective_timeout(&Timeouts {
                request_ms: Some(1500),
                backend_request_ms: None,
                ..Timeouts::default()
            }),
            Some(Duration::from_millis(1500))
        );
        assert_eq!(
            effective_timeout(&Timeouts {
                request_ms: Some(1500),
                backend_request_ms: Some(500),
                ..Timeouts::default()
            }),
            Some(Duration::from_millis(500))
        );
        assert_eq!(
            effective_timeout(&Timeouts {
                request_ms: Some(0),
                backend_request_ms: None,
                ..Timeouts::default()
            }),
            None
        );
        // #217: `request` is no longer ignored when `backendRequest` is set; the smaller wins,
        // and "0s" on one of them leaves the other in force.
        assert_eq!(
            effective_timeout(&Timeouts {
                request_ms: Some(300),
                backend_request_ms: Some(500),
                ..Timeouts::default()
            }),
            Some(Duration::from_millis(300))
        );
        assert_eq!(
            effective_timeout(&Timeouts {
                request_ms: Some(1500),
                backend_request_ms: Some(0),
                ..Timeouts::default()
            }),
            Some(Duration::from_millis(1500))
        );
        assert_eq!(
            effective_timeout(&Timeouts {
                request_ms: Some(0),
                backend_request_ms: Some(500),
                ..Timeouts::default()
            }),
            Some(Duration::from_millis(500))
        );
        assert_eq!(
            effective_timeout(&Timeouts {
                request_ms: None,
                backend_request_ms: Some(0),
                ..Timeouts::default()
            }),
            None
        );
        assert_eq!(
            effective_timeout(&Timeouts {
                request_ms: Some(0),
                backend_request_ms: Some(0),
                ..Timeouts::default()
            }),
            None
        );
    }

    #[test]
    fn the_request_timeout_is_a_budget_retries_draw_from() {
        let t = Timeouts {
            request_ms: Some(5000),
            backend_request_ms: Some(3000),
            ..Timeouts::default()
        };
        assert_eq!(
            request_budget_left(&t, Duration::from_millis(3200)),
            Some(Duration::from_millis(1800))
        );
        assert_eq!(
            request_budget_left(&t, Duration::from_secs(6)),
            Some(Duration::ZERO)
        );
        // No `request` timeout, or "0s", is no budget at all.
        for request_ms in [None, Some(0)] {
            let t = Timeouts {
                request_ms,
                backend_request_ms: Some(3000),
                ..Timeouts::default()
            };
            assert_eq!(request_budget_left(&t, Duration::from_secs(60)), None);
        }
    }

    #[test]
    fn header_ops_apply_set_add_remove_in_order() {
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("X-Old", "1").unwrap();
        req.insert_header("X-Set", "old").unwrap();
        let ops = HeaderOps {
            set: vec![("X-Set".into(), "new".into())],
            add: vec![("X-Add".into(), "a".into()), ("X-Add".into(), "b".into())],
            remove: vec!["X-Old".into()],
        };
        apply_header_ops(&mut req, &ops).unwrap();
        assert_eq!(req.headers.get("x-set").unwrap(), "new");
        assert_eq!(req.headers.get_all("x-add").iter().count(), 2);
        assert!(req.headers.get("x-old").is_none());
    }

    #[test]
    fn mirror_parts_strips_framing_headers_and_keeps_path_and_query() {
        let mut req = RequestHeader::build("GET", b"/orig?q=1", None).unwrap();
        req.insert_header("Content-Length", "42").unwrap();
        req.insert_header("Transfer-Encoding", "chunked").unwrap();
        req.insert_header("X-Keep", "yes").unwrap();
        let (url, headers) = mirror_parts(&req, "127.0.0.1:9".parse().unwrap());
        assert_eq!(url, "http://127.0.0.1:9/orig?q=1");
        assert!(
            headers.get("content-length").is_none(),
            "a headers-only mirror must not promise a body"
        );
        assert!(headers.get("transfer-encoding").is_none());
        assert_eq!(headers.get("x-keep").unwrap(), "yes");
    }

    #[test]
    fn every_local_error_answer_carries_the_same_framing() {
        // An explicit length so the connection is not close-delimited (pingora would still say
        // keep-alive and then close), no-store so no cache keeps an error, the request id where
        // every other answer carries it, and the key.
        let challenge = [("WWW-Authenticate", "Bearer".to_string())];
        let (resp, body) =
            error_response(ErrorKey::AuthJwtMissing, "req-1", false, &challenge).unwrap();
        assert_eq!(resp.status.as_u16(), 401);
        assert_eq!(resp.headers.get("www-authenticate").unwrap(), "Bearer");
        assert_eq!(
            resp.headers.get("x-gapura-error").unwrap(),
            "AUTH_JWT_MISSING"
        );
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            resp.headers.get("content-length").unwrap(),
            body.len().to_string().as_str(),
            "the body must not be close-delimited"
        );
        assert_eq!(resp.headers.get("cache-control").unwrap(), "no-store");
        assert_eq!(resp.headers.get("x-request-id").unwrap(), "req-1");
        assert_eq!(&body[..], b"401 unauthorized\n");

        let (resp, body) = error_response(ErrorKey::NoRoute, "req-2", true, &[]).unwrap();
        assert_eq!(resp.status.as_u16(), 404);
        assert_eq!(
            resp.headers.get("content-type").unwrap(),
            "application/json"
        );
        assert_eq!(
            resp.headers.get("content-length").unwrap(),
            body.len().to_string().as_str()
        );
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["error"]["key"], "NO_ROUTE");
        assert_eq!(v["error"]["request_id"], "req-2");
    }

    #[test]
    fn every_forwarded_for_line_is_read_in_order() {
        // #160: behind a proxy that adds its own line instead of appending, the first line is
        // the client's. Reading it alone named whatever address the client wrote.
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.append_header("X-Forwarded-For", "6.6.6.6").unwrap();
        req.append_header("X-Forwarded-For", "203.0.113.7").unwrap();
        assert_eq!(forwarded_for(&req).as_deref(), Some("6.6.6.6, 203.0.113.7"));
        let proxy: std::net::IpAddr = "10.0.0.2".parse().unwrap();
        let trusted = vec!["10.0.0.0/8".parse::<client::Cidr>().unwrap()];
        assert_eq!(
            client_ip_of(&req, proxy, &trusted, &[]),
            "203.0.113.7".parse::<std::net::IpAddr>().unwrap(),
            "the proxy's line names the client; the client's own line is never reached"
        );
        // One line behaves as before, and no line at all falls back to the peer.
        let mut one = RequestHeader::build("GET", b"/", None).unwrap();
        one.insert_header("X-Forwarded-For", "6.6.6.6, 203.0.113.7")
            .unwrap();
        assert_eq!(
            client_ip_of(&one, proxy, &trusted, &[]),
            client_ip_of(&req, proxy, &trusted, &[])
        );
        let none = RequestHeader::build("GET", b"/", None).unwrap();
        assert_eq!(forwarded_for(&none), None);
        assert_eq!(client_ip_of(&none, proxy, &trusted, &[]), proxy);
    }

    #[test]
    fn the_forwarded_for_hop_is_the_canonical_peer() {
        // #252: an IPv4 client on a dual-stack `[::]` listener is `::ffff:203.0.113.9` to the
        // socket; the backend must see the IPv4 address the access log records.
        let mapped: std::net::IpAddr = "::ffff:203.0.113.9".parse().unwrap();
        let none = RequestHeader::build("GET", b"/", None).unwrap();
        assert_eq!(forwarded_for_with_hop(&none, mapped), "203.0.113.9");
        let mut two = RequestHeader::build("GET", b"/", None).unwrap();
        two.append_header("X-Forwarded-For", "6.6.6.6").unwrap();
        two.append_header("X-Forwarded-For", "10.0.0.2").unwrap();
        assert_eq!(
            forwarded_for_with_hop(&two, mapped),
            "6.6.6.6, 10.0.0.2, 203.0.113.9"
        );
        // Real IPv6 peers are left as they are.
        let v6: std::net::IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(forwarded_for_with_hop(&none, v6), "2001:db8::1");
    }

    mod jwt_lines {
        use super::super::*;
        use base64::Engine;
        use gapura_core::config::JwtPolicy;
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

        const SECRET: &[u8] = b"a test secret that is long enough";

        fn policy() -> (JwtPolicy, jwt::Keys) {
            let k = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(SECRET);
            let jwks = serde_json::json!({"keys": [
                {"kty": "oct", "k": k, "alg": "HS256", "kid": "k1"}
            ]})
            .to_string();
            let keys = jwt::Keys::default();
            let keys = gapura_core::jwt::keys(&jwks).unwrap_or(keys);
            let policy = JwtPolicy {
                issuer: None,
                audience: None,
                jwks,
                ..JwtPolicy::default()
            };
            (policy, keys)
        }

        fn token(secret: &[u8], sub: &str) -> String {
            let mut header = Header::new(Algorithm::HS256);
            header.kid = Some("k1".into());
            let claims = serde_json::json!({"sub": sub, "exp": 4102444800u64});
            encode(&header, &claims, &EncodingKey::from_secret(secret)).unwrap()
        }

        fn with_lines(lines: &[&[u8]]) -> RequestHeader {
            let mut req = RequestHeader::build("GET", b"/", None).unwrap();
            for line in lines {
                let value = http::HeaderValue::from_bytes(line).unwrap();
                req.append_header(http::header::AUTHORIZATION, value)
                    .unwrap();
            }
            req
        }

        #[test]
        fn one_valid_bearer_is_admitted() {
            let (policy, keys) = policy();
            let good = format!("Bearer {}", token(SECRET, "me"));
            assert_eq!(
                jwt_refusal(&with_lines(&[good.as_bytes()]), &policy, &keys),
                None
            );
        }

        #[test]
        fn a_tab_separated_line_beside_a_valid_one_is_refused() {
            // #212: `bearer()` splits on a space, so the tab line was neither counted nor
            // verified, yet it was forwarded, and a backend splitting on any whitespace read it.
            let (policy, keys) = policy();
            let forged = format!(
                "Bearer\t{}",
                token(b"not the secret at all, forged", "admin")
            );
            let good = format!("Bearer {}", token(SECRET, "me"));
            for lines in [
                [forged.as_bytes(), good.as_bytes()],
                [good.as_bytes(), forged.as_bytes()],
            ] {
                let refusal = jwt_refusal(&with_lines(&lines), &policy, &keys);
                assert_eq!(refusal.map(|r| r.1), Some("multiple_bearer"));
                assert_eq!(refusal.map(|r| r.0), Some(ErrorKey::AuthJwtInvalid));
            }
        }

        #[test]
        fn two_authorization_lines_are_challenged_as_an_invalid_request() {
            // RFC 6750 section 3.1: a request carrying more than one credential is
            // `invalid_request`. The challenge must parse as one (RFC 9110 section 11.6.1): the
            // prose this used to send read as an auth scheme named "one".
            let (policy, keys) = policy();
            let good = format!("Bearer {}", token(SECRET, "me"));
            let refusal = jwt_refusal(
                &with_lines(&[good.as_bytes(), good.as_bytes()]),
                &policy,
                &keys,
            );
            assert_eq!(
                refusal.map(|r| r.2),
                Some("Bearer error=\"invalid_request\"")
            );
        }

        #[test]
        fn a_non_utf8_line_beside_a_valid_one_is_refused() {
            // #212: `to_str()` fails on obs-text, so the line was dropped from the count.
            let (policy, keys) = policy();
            let mut forged = format!("Bearer {}", token(b"forged", "admin")).into_bytes();
            forged.push(0x80);
            let good = format!("Bearer {}", token(SECRET, "me"));
            assert_eq!(
                jwt_refusal(&with_lines(&[&forged, good.as_bytes()]), &policy, &keys).map(|r| r.1),
                Some("multiple_bearer")
            );
        }

        #[test]
        fn a_single_line_that_is_not_a_bearer_presents_no_token() {
            let (policy, keys) = policy();
            let tab = format!("Bearer\t{}", token(SECRET, "me"));
            let mut non_utf8 = format!("Bearer {}", token(SECRET, "me")).into_bytes();
            non_utf8.push(0x80);
            for line in [tab.as_bytes(), &non_utf8, b"Basic dXNlcjpwYXNz"] {
                assert_eq!(
                    jwt_refusal(&with_lines(&[line]), &policy, &keys),
                    Some((ErrorKey::AuthJwtMissing, "missing", "Bearer"))
                );
            }
            assert_eq!(
                jwt_refusal(&with_lines(&[]), &policy, &keys),
                Some((ErrorKey::AuthJwtMissing, "missing", "Bearer"))
            );
        }
    }

    #[test]
    fn path_parameters_that_change_the_route_are_caught() {
        // #213: `/admin;x/secret` misses the `/admin` prefix and falls to the catch-all, while
        // Tomcat serves it as `/admin/secret`.
        let yaml = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata: { name: gapura }
spec: { controllerName: gapura.dev/controller }
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: { name: main, namespace: infra, generation: 1 }
spec:
  gatewayClassName: gapura
  listeners:
  - { name: http, port: 80, protocol: HTTP, allowedRoutes: { namespaces: { from: All } } }
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: r, namespace: apps, generation: 1, creationTimestamp: "2026-09-10T00:00:00Z" }
spec:
  parentRefs: [{ name: main, namespace: infra }]
  rules:
  - matches: [{ path: { type: PathPrefix, value: /admin } }]
    backendRefs: [{ name: echo, port: 80 }]
  - matches: [{ path: { type: PathPrefix, value: /shop } }]
    backendRefs: [{ name: echo, port: 80 }]
  - matches: [{ path: { type: PathPrefix, value: / } }]
    backendRefs: [{ name: echo, port: 80 }]
"#;
        let snap = gapura_core::Snapshot::from_yaml_docs(yaml).unwrap();
        let translation = gapura_core::translate(&snap, &gapura_core::Settings::default());
        let rt = Runtime::new(translation.config, 1, Vec::new());
        let changes = |path: &str| {
            let r = RequestHeader::build("GET", path.as_bytes(), None).unwrap();
            path_params_change_the_route(&rt, 80, &Extracted::from_request(&r).unwrap())
        };
        // The catch-all is what a miss falls to, so the test only means something if it is
        // there and `/admin` really is a different rule.
        let rule_of = |path: &str| {
            let r = RequestHeader::build("GET", path.as_bytes(), None).unwrap();
            let ex = Extracted::from_request(&r).unwrap();
            rt.config
                .match_port_with(80, &ex.attrs(), rt.regexes())
                .map(|hit| hit.entry.rule)
        };
        assert!(rule_of("/admin/secret").is_some());
        assert!(rule_of("/elsewhere").is_some());
        assert_ne!(rule_of("/admin/secret"), rule_of("/elsewhere"));
        assert!(!changes("/admin/secret"));
        assert!(!changes("/elsewhere"));
        assert!(changes("/admin;x/secret"));
        assert!(changes("/admin;"));
        assert!(changes("/;x/admin/secret"));
        // Parameters that route the same either way are left alone.
        assert!(!changes("/shop/cart;jsessionid=1"));
        assert!(!changes("/admin/secret;v=2"));
        assert!(!changes("/elsewhere;x/y"));
    }

    #[test]
    fn a_rule_naming_path_parameters_is_still_refused_at_the_data_plane() {
        // #247: no check here can make such a rule safe. With `Exact /api;v=2` beside `Exact
        // /api`, `GET /api;v=2` would run the first rule's policies while a servlet backend
        // serves `/api`, whose rule may carry others. So the console, the store compiler and the
        // translator refuse a `;` in an Exact or PathPrefix value, and a row that slipped past
        // them is still refused here: the stripped reading never matches the rule as sent.
        let yaml = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata: { name: gapura }
spec: { controllerName: gapura.dev/controller }
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: { name: main, namespace: infra, generation: 1 }
spec:
  gatewayClassName: gapura
  listeners:
  - { name: http, port: 80, protocol: HTTP, allowedRoutes: { namespaces: { from: All } } }
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: r, namespace: apps, generation: 1, creationTimestamp: "2026-09-10T00:00:00Z" }
spec:
  parentRefs: [{ name: main, namespace: infra }]
  rules:
  - matches: [{ path: { type: Exact, value: /api-v-2 } }]
    backendRefs: [{ name: echo, port: 80 }]
  - matches: [{ path: { type: PathPrefix, value: /items-type-book } }]
    backendRefs: [{ name: echo, port: 80 }]
  - matches: [{ path: { type: Exact, value: /api } }]
    backendRefs: [{ name: echo, port: 80 }]
  - matches: [{ path: { type: PathPrefix, value: / } }]
    backendRefs: [{ name: echo, port: 80 }]
"#;
        let snap = gapura_core::Snapshot::from_yaml_docs(yaml).unwrap();
        let mut config = gapura_core::translate(&snap, &gapura_core::Settings::default()).config;
        // The translator refuses these values, so they are written into the served
        // configuration directly, the way a row that slipped through would arrive.
        for entry in config.ports.get_mut(&80).unwrap() {
            entry.matcher.path = match &entry.matcher.path {
                PathMatch::Exact(p) if p == "/api-v-2" => PathMatch::Exact("/api;v=2".into()),
                PathMatch::Prefix(p) if p == "/items-type-book" => {
                    PathMatch::Prefix("/items;type=book".into())
                }
                other => other.clone(),
            };
        }
        let rt = Runtime::new(config, 1, Vec::new());
        let with = |path: &str| {
            let r = RequestHeader::build("GET", path.as_bytes(), None).unwrap();
            Extracted::from_request(&r).unwrap()
        };
        // The test only means something if these requests do match the `;` rules as sent.
        let path_of = |path: &str| {
            rt.config
                .match_port_with(80, &with(path).attrs(), rt.regexes())
                .map(|hit| hit.entry.matcher.path.clone())
        };
        assert_eq!(
            path_of("/api;v=2"),
            Some(PathMatch::Exact("/api;v=2".into()))
        );
        assert_eq!(
            path_of("/items;type=book/42"),
            Some(PathMatch::Prefix("/items;type=book".into()))
        );
        for path in ["/api;v=2", "/items;type=book", "/items;type=book/42"] {
            assert!(
                path_params_change_the_route(&rt, 80, &with(path)),
                "{path} must be refused"
            );
        }
    }
}
