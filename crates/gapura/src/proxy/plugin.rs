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

use gapura_core::config::{Body, JwtPolicy, KeyAuthPolicy, Phase, Plugin, RouteRule};
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

    /// Run `chain`'s Terminate steps -- the rule's, for a request attributed to one -- once,
    /// whatever answered it: a refused request too.
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
    terminate: Vec<Terminate>,
}

/// A step of [`Phase::Access`].
enum Access {
    Jwt(JwtPolicy),
    KeyAuth(KeyAuthPolicy),
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
        &[Phase::Access, Phase::UpstreamRequest, Phase::Terminate]
    }
}

/// Why a plugin that runs in `phases` and reads a body as `body` cannot run where only
/// `reachable` is reached, if it cannot.
fn misplaced(phases: &[Phase], body: Body, reachable: &[Phase]) -> Option<&'static str> {
    if phases.iter().any(|p| !reachable.contains(p)) {
        return Some("the rule never reaches a phase it runs in");
    }
    // No phase feeds a plugin a body yet: one that needs it would run without it.
    (body != Body::None).then_some("it reads a body, and no phase feeds one yet")
}

impl Chain {
    /// Compile `rule`'s plugins, in order, into the list of each phase they run in, with the
    /// request limit after them. `Err` when a plugin cannot run on this rule: a rule whose
    /// policies cannot all run must not serve, or an auth policy that never runs would let every
    /// request through.
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
            }
        }
        // Last, because the limit may be the consumer's own and may count per consumer, and the
        // consumer is not known until a policy has checked its credential.
        chain.access.push(Access::RateLimit);
        Ok(chain)
    }

    /// Run the Access steps in order, up to the first that does not continue. `peer` is the
    /// connection's address, from which the client's is worked out only if a limit needs it.
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
}

impl Access {
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
                // No keys for this document means it did not parse at swap time. Refusing is the
                // safe direction: the alternative is passing traffic through unverified because a
                // configuration error made verification impossible.
                let empty = jwt::Keys::default();
                let keys = rt.jwt_keys(&policy.jwks).unwrap_or(&empty);
                match jwt_refusal(req, policy, keys) {
                    None => Flow::Continue,
                    Some((key, reason, challenge)) => {
                        refuse(rule, "jwt", reason, key, challenge.to_string())
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
                        format!("Key realm=\"{}\"", policy.header),
                    ),
                }
            }
            Access::RateLimit => limit(proxy, rt, rule, req, peer, cx),
        }
    }
}

/// Count a policy's refusal and say how to answer it. Missing or invalid is all the key says:
/// which check failed is an operator's business (the metric's reason), and telling a caller
/// narrows the search for whoever is guessing.
fn refuse(rule: &RouteRule, kind: &str, reason: &str, key: ErrorKey, challenge: String) -> Flow {
    METRICS
        .policy_refused_total
        .with_label_values(&[rule.route.as_str(), kind, reason])
        .inc();
    Flow::Fail(Failure {
        key,
        headers: vec![("WWW-Authenticate", challenge)],
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
    let ip = peer.map(|peer| {
        client_ip_of(
            req,
            peer,
            &proxy.trusted_proxies,
            &proxy.trusted_client_headers,
        )
    });
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

    const ALL: [Phase; 3] = [Phase::Access, Phase::UpstreamRequest, Phase::Terminate];

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

    fn get() -> RequestHeader {
        RequestHeader::build("GET", b"/", None).unwrap()
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

    #[test]
    fn a_plugin_that_reads_a_body_cannot_run_anywhere_yet() {
        assert_eq!(misplaced(&[Phase::Access], Body::None, &ALL), None);
        for body in [Body::Stream, Body::Buffered { max: 1 << 20 }] {
            assert!(
                misplaced(&[Phase::Access], body, &ALL).is_some(),
                "{body:?}"
            );
        }
        assert!(misplaced(&[Phase::Access], Body::None, &[]).is_some());
    }
}
