//! Step 3 of translation: attach HTTPRoutes to listeners through parentRefs and produce route status.

use std::collections::BTreeMap;

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
        let compiled = rules::compile(route, rref, snap, clusters);
        let generation = route.metadata.generation;
        let mut parents = Vec::new();
        for pref in &route.spec.parent_refs {
            let is_gateway = pref.group.as_deref().unwrap_or(GATEWAY_GROUP) == GATEWAY_GROUP
                && pref.kind.as_deref().unwrap_or("Gateway") == "Gateway";
            if !is_gateway {
                continue;
            }
            let gw_ns = pref
                .namespace
                .clone()
                .unwrap_or_else(|| rref.namespace.clone());
            let Some(gw) = gateways
                .iter_mut()
                .find(|g| g.r#ref.namespace == gw_ns && g.r#ref.name == pref.name)
            else {
                continue; // not ours (or absent): the spec says stay silent
            };
            let outcome = attach_to_gateway(gw, pref, route, rref, snap, compiled.as_ref().ok());
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
                parents,
            });
        }
    }
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
) -> Outcome {
    let mut outcome = Outcome {
        matching_listeners: 0,
        allowed: 0,
        hostname_ok: 0,
    };
    let gw_ns = gw.r#ref.namespace.clone();
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
        if let Some(c) = compiled {
            l.attached_routes += 1;
            if l.programmed() {
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
