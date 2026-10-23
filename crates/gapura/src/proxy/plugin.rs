//! The plugin contract: the lists each rule's plugins are compiled into, one per [`Phase`], once
//! per configuration generation.
//!
//! Shaped against gravitee-gateway-api 7.0.0, whose contract a policy can get wrong without a
//! word: hooks that default to doing nothing, so a policy in a phase it does not implement is
//! silently skipped. Here each phase has a step type of its own, so a step is only ever
//! dispatched where it has a handler and no handler has a default arm, and a rule whose plugins
//! cannot all run is compiled to refuse.

use gapura_core::config::{Body, JwtPolicy, KeyAuthPolicy, Phase, Plugin, RouteRule};

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use gapura_core::config::{Filters, LimitBy, RateLimit, Redirect, Timeouts};

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
