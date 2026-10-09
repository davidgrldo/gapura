//! Step 3 of translation: attach HTTPRoutes to listeners through parentRefs and produce route status.

use std::collections::{BTreeMap, BTreeSet};

use crate::config::Cluster;
use crate::hostname;
use crate::input::{HttpRoute, ParentReference};
use crate::snapshot::{ObjectRef, Settings, Snapshot};
use crate::status::{reasons, types, Condition, ConditionStatus, RouteParentStatus, StatusPatch};
use crate::translate::listeners::{GatewayBuild, GATEWAY_GROUP};
use crate::translate::{allowed, rules};

pub(crate) fn attach(
    snap: &Snapshot,
    settings: &Settings,
    gateways: &mut [GatewayBuild],
    clusters: &mut BTreeMap<String, Cluster>,
    status: &mut Vec<StatusPatch>,
) {
    for (rref, route) in &snap.http_routes {
        // Compile only a route that names one of our Gateways. Any namespace may hold
        // HTTPRoutes, and compiling one costs its regex paths; a route for another controller
        // (or for no Gateway at all) gets no status from us either, so compiling it would only
        // let an object we were never asked to serve stall every translation (#156).
        let ours = route
            .spec
            .parent_refs
            .iter()
            .any(|pref| our_gateway(gateways, pref, rref).is_some());
        if !ours {
            continue;
        }
        let compiled = rules::compile(route, rref, snap, clusters);
        let generation = route.metadata.generation;
        let mut parents = Vec::new();
        let mut attached: BTreeSet<String> = BTreeSet::new();
        for pref in &route.spec.parent_refs {
            let Some(i) = our_gateway(gateways, pref, rref) else {
                continue; // not ours (or absent): the spec says stay silent
            };
            let gw = &mut gateways[i];
            let outcome = attach_to_gateway(
                gw,
                pref,
                route,
                rref,
                snap,
                compiled.as_ref().ok(),
                &mut attached,
            );
            parents.push(RouteParentStatus {
                parent_ref: pref.clone(),
                controller_name: settings.controller_name.clone(),
                conditions: vec![
                    accepted_condition(&outcome, &compiled, generation),
                    resolved_condition(&compiled, generation),
                ],
            });
        }
        if !parents.is_empty() {
            status.push(StatusPatch::HttpRoute {
                namespace: rref.namespace.clone(),
                name: rref.name.clone(),
                uid: route.metadata.uid.clone(),
                parents,
            });
        }
    }
}

/// The index of the Gateway of ours a parentRef names, if any. A parentRef of another kind, or
/// one naming a Gateway we do not build (another controller's, or absent), resolves to `None`.
/// Both the "is this route ours" check and the attach loop go through here so they cannot
/// disagree about which routes are compiled.
fn our_gateway(
    gateways: &[GatewayBuild],
    pref: &ParentReference,
    rref: &ObjectRef,
) -> Option<usize> {
    let is_gateway = pref.group.as_deref().unwrap_or(GATEWAY_GROUP) == GATEWAY_GROUP
        && pref.kind.as_deref().unwrap_or("Gateway") == "Gateway";
    if !is_gateway {
        return None;
    }
    let gw_ns = pref.namespace.as_deref().unwrap_or(&rref.namespace);
    gateways
        .iter()
        .position(|g| g.r#ref.namespace == gw_ns && g.r#ref.name == pref.name)
}

/// Counts used to pick the Accepted reason.
struct Outcome {
    matching_listeners: usize,
    allowed: usize,
    hostname_ok: usize,
}

fn attach_to_gateway(
    gw: &mut GatewayBuild,
    pref: &ParentReference,
    route: &HttpRoute,
    rref: &ObjectRef,
    snap: &Snapshot,
    compiled: Option<&rules::Compiled>,
    attached: &mut BTreeSet<String>,
) -> Outcome {
    let mut outcome = Outcome {
        matching_listeners: 0,
        allowed: 0,
        hostname_ok: 0,
    };
    let gw_ns = gw.r#ref.namespace.clone();
    let gw_id = gw.r#ref.to_string();
    for l in gw.listeners.iter_mut() {
        if pref.section_name.as_deref().is_some_and(|s| s != l.name)
            || pref.port.is_some_and(|p| p != l.port)
        {
            continue;
        }
        outcome.matching_listeners += 1;
        if !allowed::namespace_ok(l.allowed.as_ref(), &gw_ns, rref, snap)
            || !allowed::kind_ok(l.allowed.as_ref())
        {
            continue;
        }
        outcome.allowed += 1;
        let Some(hosts) = hostname::intersect(l.hostname.as_deref(), &route.spec.hostnames) else {
            continue; // no hostname intersection
        };
        outcome.hostname_ok += 1;
        // Counted whether or not the route compiled: the spec has attachedRoutes count every
        // attached route, including one whose own Accepted condition is False. Only a route that
        // compiled contributes rules.
        let key = format!("{gw_id}/{}", l.name);
        if attached.insert(key) {
            l.attached_routes += 1;
            if let Some(c) = compiled.filter(|_| l.programmed()) {
                l.add_route(&c.rules, &hosts);
            }
        }
    }
    outcome
}

fn accepted_condition(
    o: &Outcome,
    compiled: &Result<rules::Compiled, rules::Unsupported>,
    generation: Option<i64>,
) -> Condition {
    let (status, reason, message) = if let Err(rules::Unsupported(msg)) = compiled {
        (
            ConditionStatus::False,
            reasons::UNSUPPORTED_VALUE,
            msg.clone(),
        )
    } else if o.hostname_ok > 0 {
        (
            ConditionStatus::True,
            reasons::ACCEPTED,
            "Route is accepted".to_string(),
        )
    } else if o.matching_listeners == 0 {
        (
            ConditionStatus::False,
            reasons::NO_MATCHING_PARENT,
            "No listener matches the parentRef sectionName/port".to_string(),
        )
    } else if o.allowed == 0 {
        (
            ConditionStatus::False,
            reasons::NOT_ALLOWED_BY_LISTENERS,
            "Route is not allowed by any matching listener (namespace or kind)".to_string(),
        )
    } else {
        (
            ConditionStatus::False,
            reasons::NO_MATCHING_LISTENER_HOSTNAME,
            "No listener hostname intersects the route hostnames".to_string(),
        )
    };
    Condition::new(types::ACCEPTED, status, reason, message, generation)
}

fn resolved_condition(
    compiled: &Result<rules::Compiled, rules::Unsupported>,
    generation: Option<i64>,
) -> Condition {
    match compiled {
        Ok(c) => c.resolved_refs.clone(),
        Err(_) => Condition::new(
            types::RESOLVED_REFS,
            ConditionStatus::True,
            reasons::RESOLVED_REFS,
            "References not evaluated because the route was rejected",
            generation,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::StatusPatch;
    use crate::translate::{gateway_class, listeners};

    const BASE: &str = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata: { name: gapura }
spec: { controllerName: gapura.dev/controller }
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: { name: main, namespace: infra }
spec:
  gatewayClassName: gapura
  listeners:
  - { name: http, port: 80, protocol: HTTP, allowedRoutes: { namespaces: { from: All } } }
---
apiVersion: v1
kind: Service
metadata: { name: echo, namespace: apps }
spec: { ports: [{ name: http, port: 80, targetPort: 8080 }] }
"#;

    /// An HTTPRoute with the given parentRefs (a YAML flow list): a plain rule with a backend
    /// first, then two rules of 64 RegularExpression matches each shaped like `/<n>\w{100}`,
    /// every one over `PATH_REGEX_SIZE_LIMIT` -- the route of #156.
    fn heavy_route(parent_refs: &str) -> String {
        let mut rules =
            "  - matches: [{ path: { type: PathPrefix, value: /ok } }]\n    backendRefs: [{ name: echo, port: 80 }]\n".to_string();
        for r in 0..2 {
            rules.push_str("  - matches:\n");
            for m in 0..64 {
                let n = r * 64 + m;
                rules.push_str(&format!(
                    "    - {{ path: {{ type: RegularExpression, value: '/{n}\\w{{100}}' }} }}\n"
                ));
            }
        }
        format!(
            "{BASE}---\napiVersion: gateway.networking.k8s.io/v1\nkind: HTTPRoute\n\
             metadata: {{ name: heavy, namespace: apps }}\n\
             spec:\n  parentRefs: {parent_refs}\n  rules:\n{rules}"
        )
    }

    /// Runs the attach step alone, so the clusters `rules::compile` records are visible before
    /// `assemble` prunes the unused ones: an empty map means no route was compiled.
    fn attach_only(yaml: &str) -> (BTreeMap<String, Cluster>, Vec<StatusPatch>) {
        let snap = Snapshot::from_yaml_docs(yaml).unwrap();
        let settings = Settings::default();
        let mut class_status = Vec::new();
        let classes = gateway_class::accept(&snap, &settings, &mut class_status);
        let mut gateways = listeners::build(&snap, &settings, &classes);
        let mut clusters = BTreeMap::new();
        let mut status = Vec::new();
        attach(&snap, &settings, &mut gateways, &mut clusters, &mut status);
        (clusters, status)
    }

    fn route_parents(status: &[StatusPatch]) -> &[RouteParentStatus] {
        match status {
            [StatusPatch::HttpRoute { parents, .. }] => parents,
            other => panic!("expected one HTTPRoute patch, got {other:?}"),
        }
    }

    #[test]
    fn a_route_without_a_parent_of_ours_is_not_compiled() {
        // Absent Gateway, a Gateway in another namespace, and a parentRef of another kind: none
        // resolves to one of ours, so the route is neither compiled nor given a status.
        let yaml = heavy_route(
            "[{ name: absent, namespace: infra }, { name: main }, \
             { kind: Service, group: '', name: main, namespace: infra }]",
        );
        let started = std::time::Instant::now();
        let (clusters, status) = attach_only(&yaml);
        assert!(
            clusters.is_empty(),
            "compiling the route would have recorded its backend: {clusters:?}"
        );
        assert!(
            status.is_empty(),
            "a route not ours stays silent: {status:?}"
        );
        // Compiling its 128 patterns takes seconds even under the size limit; skipping it is
        // microseconds. The bound is loose so only the regression itself can trip it.
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "attach took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn an_attached_route_with_an_over_limit_regex_is_refused_with_a_condition() {
        let (_, status) = attach_only(&heavy_route("[{ name: main, namespace: infra }]"));
        let parents = route_parents(&status);
        assert_eq!(parents.len(), 1);
        let accepted = &parents[0].conditions[0];
        assert_eq!(accepted.type_, types::ACCEPTED);
        assert_eq!(accepted.status, ConditionStatus::False);
        assert_eq!(accepted.reason, reasons::UNSUPPORTED_VALUE);
        assert!(
            accepted.message.contains("RegularExpression")
                && accepted.message.contains("size limit"),
            "{}",
            accepted.message
        );
    }

    #[test]
    fn a_route_with_one_parent_of_ours_is_compiled_and_reports_only_that_parent() {
        let yaml = format!(
            "{BASE}---\napiVersion: gateway.networking.k8s.io/v1\nkind: HTTPRoute\n\
             metadata: {{ name: mixed, namespace: apps }}\n\
             spec:\n  parentRefs: [{{ name: absent, namespace: infra }}, {{ name: main, namespace: infra }}]\n  \
             rules:\n  - matches: [{{ path: {{ type: RegularExpression, value: '/api/v[0-9]+/.*' }} }}]\n    \
             backendRefs: [{{ name: echo, port: 80 }}]\n"
        );
        let (clusters, status) = attach_only(&yaml);
        assert_eq!(clusters.len(), 1, "the route was compiled: {clusters:?}");
        let parents = route_parents(&status);
        assert_eq!(parents.len(), 1, "the absent parent stays silent");
        assert_eq!(parents[0].parent_ref.name, "main");
        assert_eq!(parents[0].conditions[0].reason, reasons::ACCEPTED);
    }
}
