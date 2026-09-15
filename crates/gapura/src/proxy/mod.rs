//! The Pingora data plane: request attributes, routing decisions, the ProxyHttp implementation, TLS.
//!
//! One request, top to bottom: `request_filter` (match, answer locally or pick a cluster),
//! `upstream_peer` (pick an endpoint), `upstream_request_filter` (rewrite, headers),
//! `response_filter` (response headers), `fail_to_connect` (retry once), `fail_to_proxy`
//! (502/504 mapping), `logging` (access log + metrics).

pub mod attrs;
pub mod client;
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
    listener: Option<usize>,
    rule: Option<usize>,
    matched: Option<PathMatch>,
    cluster: Option<String>,
    tried: Vec<SocketAddr>,
    upstream: Option<SocketAddr>,
    extracted: Option<Extracted>,
    request_id: String,
    traceparent: String,
    scheme: &'static str,
    port: u16,
    local_status: Option<u16>,
    started: Instant,
    upstream_started: Option<Instant>,
    client_abort: bool,
    mirrored: bool,
}

impl Ctx {
    fn rule(&self) -> Option<&RouteRule> {
        let rt = self.runtime.as_ref()?;
        rt.config
            .listeners
            .get(self.listener?)?
            .rules
            .get(self.rule?)
    }

    fn route_label(&self) -> &str {
        self.rule().map(|r| r.route.as_str()).unwrap_or("-")
    }

    fn listener_label(&self) -> &str {
        match (&self.runtime, self.listener) {
            (Some(rt), Some(i)) => rt
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
/// `Some(0)` disables the timeout (Gateway API: "0s" means no timeout); `None` uses the default.
/// `backendRequest` is the per-attempt bound and wins over `request` when both are set.
pub fn effective_timeout(t: &Timeouts) -> Option<Duration> {
    match t.backend_request_ms.or(t.request_ms) {
        Some(0) => None,
        Some(ms) => Some(Duration::from_millis(ms)),
        None => Some(DEFAULT_UPSTREAM_TIMEOUT),
    }
}

fn reason_phrase(code: u16) -> &'static str {
    match code {
        404 => "no route",
        500 => "no valid backend",
        502 => "bad gateway",
        503 => "no ready endpoints",
        504 => "gateway timeout",
        _ => "error",
    }
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

/// A locally generated error response: plain text, request id, never any internal detail.
/// The rate-limit answer: like `write_local`, plus the three headers a throttled client reads.
async fn write_429(
    session: &mut Session,
    limit: u32,
    retry_after_secs: u64,
    request_id: &str,
) -> Result<()> {
    let body = "429 too many requests\n";
    let mut resp = ResponseHeader::build(429u16, Some(6))?;
    resp.insert_header("Content-Type", "text/plain; charset=utf-8")?;
    resp.insert_header("Content-Length", body.len().to_string())?;
    resp.insert_header("Cache-Control", "no-store")?;
    resp.insert_header("Retry-After", retry_after_secs.to_string())?;
    resp.insert_header("X-RateLimit-Limit", limit.to_string())?;
    resp.insert_header("X-RateLimit-Remaining", "0")?;
    resp.insert_header("X-Request-Id", request_id.to_string())?;
    session.write_response_header(Box::new(resp), false).await?;
    session
        .write_response_body(Some(Bytes::from(body)), true)
        .await
}

async fn write_local(session: &mut Session, code: u16, request_id: &str) -> Result<()> {
    let body = format!("{code} {}\n", reason_phrase(code));
    let mut resp = ResponseHeader::build(code, Some(4))?;
    resp.insert_header("Content-Type", "text/plain; charset=utf-8")?;
    resp.insert_header("Content-Length", body.len().to_string())?;
    resp.insert_header("Cache-Control", "no-store")?;
    resp.insert_header("X-Request-Id", request_id.to_string())?;
    session.write_response_header(Box::new(resp), false).await?;
    session
        .write_response_body(Some(Bytes::from(body)), true)
        .await
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
        let forwarded_for = header_str(session.req_header(), "x-forwarded-for");
        // First configured single-IP header present on the request, in flag order.
        let named = trusted_client_headers
            .iter()
            .find_map(|name| header_str(session.req_header(), name.as_str()));
        client::client_ip(a.ip(), forwarded_for, trusted, named)
    })
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
    // Same selection as a primary: round-robin cursor over the mirror cluster's endpoints.
    // A cluster that vanished between translate and now, or has no endpoints, is an error like
    // any other mirror failure: counted, never felt by the primary.
    let endpoint = rt.config.clusters.get(&mirror.cluster).and_then(|cluster| {
        let cursor = rt.next_index(&mirror.cluster).unwrap_or(0);
        pick_endpoint(cluster, cursor, &[]).ok()
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
    let client = MIRROR_CLIENT.get_or_init(reqwest::Client::new);
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
            listener: None,
            rule: None,
            matched: None,
            cluster: None,
            tried: Vec::new(),
            upstream: None,
            extracted: None,
            request_id: String::new(),
            traceparent: String::new(),
            scheme: "http",
            port: 0,
            local_status: None,
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
            ctx.extracted = Some(Extracted::from_request(req));
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
                    if let Some(redirect) = &hit.rule.filters.redirect {
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
                // The rule's limit, if its backend Service asked for one, is enforced here:
                // after the match (the route is known), before any upstream work (the limit
                // must not cost the backend anything). Same client answer the access log
                // records, so a limited request names the same client a served one would.
                let rt = ctx.runtime.as_ref().expect("set above");
                if let Some(rl) = &rt.config.listeners[listener].rules[rule].rate_limit {
                    let route = rt.config.listeners[listener].rules[rule].route.clone();
                    if let Some(ip) = effective_client_ip(
                        session,
                        &self.trusted_proxies,
                        &self.trusted_client_headers,
                    ) {
                        if let rate_limit::Outcome::Limited {
                            limit,
                            retry_after_secs,
                        } = self.limiter.check(&route, ip, rl)
                        {
                            METRICS
                                .rate_limited_total
                                .with_label_values(&[&route])
                                .inc();
                            ctx.listener = Some(listener);
                            ctx.rule = Some(rule);
                            ctx.local_status = Some(429);
                            write_429(session, limit, retry_after_secs, &ctx.request_id).await?;
                            return Ok(true);
                        }
                    }
                }
                ctx.listener = Some(listener);
                ctx.rule = Some(rule);
                ctx.matched = Some(matched);
                ctx.cluster = Some(cluster);
                Ok(false)
            }
            Decision::Redirect { status, location } => {
                let mut resp = ResponseHeader::build(status, Some(3))?;
                resp.insert_header("Location", location)?;
                resp.insert_header("Content-Length", "0")?;
                resp.insert_header("X-Request-Id", ctx.request_id.clone())?;
                session.write_response_header(Box::new(resp), true).await?;
                ctx.local_status = Some(status);
                Ok(true)
            }
            Decision::Local(local) => {
                ctx.local_status = Some(local.status());
                write_local(session, local.status(), &ctx.request_id).await?;
                Ok(true)
            }
            Decision::NotFound => {
                ctx.local_status = Some(404);
                write_local(session, 404, &ctx.request_id).await?;
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
        let key = ctx.cluster.clone().ok_or_else(|| {
            Error::explain(ErrorType::InternalError, "upstream_peer without a cluster")
        })?;
        let cluster = rt.config.clusters.get(&key).ok_or_else(|| {
            Error::explain(ErrorType::InternalError, "cluster missing from config")
        })?;
        let cursor = rt.next_index(&key).unwrap_or(0);
        let addr = pick_endpoint(cluster, cursor, &ctx.tried)
            .map_err(|_| Error::explain(ErrorType::HTTPStatus(503), "no endpoint left to try"))?;
        ctx.upstream = Some(addr);
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
        let timeout = ctx
            .rule()
            .map(|r| effective_timeout(&r.timeouts))
            .unwrap_or(Some(DEFAULT_UPSTREAM_TIMEOUT));
        peer.options.connection_timeout = Some(DEFAULT_CONNECT_TIMEOUT);
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
        let (Some(li), Some(ri)) = (ctx.listener, ctx.rule) else {
            return Ok(());
        };
        let rule = &rt.config.listeners[li].rules[ri];

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
        if let Some(ip) = session
            .client_addr()
            .and_then(|a| a.as_inet())
            .map(|a| a.ip().to_string())
        {
            let value = match header_str(upstream, "x-forwarded-for") {
                Some(existing) => format!("{existing}, {ip}"),
                None => ip,
            };
            upstream.insert_header("X-Forwarded-For", value)?;
        }
        upstream.insert_header("X-Request-Id", ctx.request_id.clone())?;
        upstream.insert_header("traceparent", ctx.traceparent.clone())?;

        // The mirror fires only on requests that reached an upstream -- redirects answered in
        // request_filter never get here -- and after every header mutation above, so it copies
        // the final rewritten, modified header set.
        if let Some(mirror) = &rule.filters.mirror {
            fire_mirror(&rt, mirror, upstream, ctx);
        }
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

    fn fail_to_connect(
        &self,
        _session: &mut Session,
        _peer: &HttpPeer,
        ctx: &mut Ctx,
        mut e: Box<Error>,
    ) -> Box<Error> {
        let cluster = ctx.cluster.clone().unwrap_or_else(|| "-".to_string());
        METRICS
            .upstream_errors_total
            .with_label_values(&[&cluster, "connect"])
            .inc();
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
        // downstream failure yields code 0 and an abort mid-body has already written a response,
        // so neither reaches the error-response branch below. What the flag means then rests on
        // the `ErrorSource::Downstream => 0` arm a few lines down -- code 0 is what keeps an abort
        // from being answered and logged as an error of ours.
        if matches!(e.esource(), ErrorSource::Downstream) {
            ctx.client_abort = true;
        }
        let code = match e.etype() {
            ErrorType::HTTPStatus(code) => *code,
            ErrorType::ConnectTimedout | ErrorType::ReadTimedout | ErrorType::WriteTimedout
                if upstream =>
            {
                504
            }
            _ => match e.esource() {
                ErrorSource::Upstream => 502,
                ErrorSource::Downstream => 0,
                ErrorSource::Internal | ErrorSource::Unset => 500,
            },
        };
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
            // connect failures were already counted in fail_to_connect
            if kind != "connect" {
                METRICS
                    .upstream_errors_total
                    .with_label_values(&[ctx.cluster.as_deref().unwrap_or("-"), kind])
                    .inc();
            }
        }
        // Only answer when nothing has been sent yet: a failure mid-body must not append an error
        // text to the streamed response. Pingora drops the downstream connection after this, so
        // say so in the header instead of advertising keep-alive.
        if code > 0 && session.response_written().is_none() {
            session.set_keepalive(None);
            if let Err(write_err) = write_local(session, code, &ctx.request_id).await {
                tracing::debug!(error = %write_err, "could not write error response, client likely gone");
            }
            ctx.local_status = Some(code);
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
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_timeout_follows_gateway_api_zero_means_disabled() {
        assert_eq!(
            effective_timeout(&Timeouts::default()),
            Some(DEFAULT_UPSTREAM_TIMEOUT)
        );
        assert_eq!(
            effective_timeout(&Timeouts {
                request_ms: Some(1500),
                backend_request_ms: None
            }),
            Some(Duration::from_millis(1500))
        );
        assert_eq!(
            effective_timeout(&Timeouts {
                request_ms: Some(1500),
                backend_request_ms: Some(500)
            }),
            Some(Duration::from_millis(500))
        );
        assert_eq!(
            effective_timeout(&Timeouts {
                request_ms: Some(0),
                backend_request_ms: None
            }),
            None
        );
        assert_eq!(
            effective_timeout(&Timeouts {
                request_ms: Some(1500),
                backend_request_ms: Some(0)
            }),
            None
        );
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
    fn reason_phrases_never_leak_internals() {
        for code in [404u16, 500, 502, 503, 504, 418] {
            let phrase = reason_phrase(code);
            assert!(!phrase.is_empty());
            assert!(!phrase.contains("pingora"));
        }
    }
}
