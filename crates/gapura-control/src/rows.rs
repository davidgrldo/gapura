//! Declared and served, joined into the rows the routes screen shows.

use crate::declared::{Acceptance, DeclaredParent, DeclaredRoute};
use crate::served::Served;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// Declared, accepted, and present in what the gateway serves.
    Served,
    /// Declared and refused. `reason` says why.
    Refused,
    /// Declared, and the gateway has not ruled on it yet. Not a fault: nobody has looked.
    Pending,
    /// Declared and accepted, but absent from what the gateway serves.
    Missing,
    /// The gateway could not be reached, so the served side is unknown.
    Unknown,
    /// The Gateways this route attaches to do not agree; `parents` says who said what.
    Mixed,
}

/// One attachment of the route, and how it is faring on that Gateway alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ParentRow {
    /// The Gateway attached to, as `namespace/name`.
    pub gateway: String,
    pub state: State,
    /// Why, when this Gateway did not accept it. It belongs here rather than on the row:
    /// a route refused on two Gateways for two causes has no single reason, and picking
    /// one to stand for the route presents an answer that is false of the other.
    pub reason: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Row {
    pub id: String,
    pub namespace: String,
    /// What the parents add up to, for a list that is read a row at a time.
    pub state: State,
    pub parents: Vec<ParentRow>,
}

/// What the row says when it has room for one state. Parents that agree speak for the
/// route; parents that disagree have no common answer, and `Mixed` says so instead of
/// electing one of them. A route no Gateway of ours has claimed is pending: nothing has
/// ruled on it, which is the same thing an unreconciled route means.
fn summarise(parents: &[ParentRow]) -> State {
    let Some(first) = parents.first() else {
        return State::Pending;
    };
    if parents.iter().all(|p| p.state == first.state) {
        first.state
    } else {
        State::Mixed
    }
}

/// Whether this Gateway is serving the route, judged only against the listeners that
/// belong to it. A rule under some other Gateway's listener is another attachment being
/// served, and counting it would report a route as up on a Gateway that never took it.
fn is_served_by(served: &Served, parent: &DeclaredParent, route: &str) -> bool {
    served
        .listeners
        .iter()
        .filter(|listener| match &parent.section {
            // The route asked for one listener by name, so only that listener can serve
            // this attachment: a sibling listener carrying the route serves some other
            // attachment, and the one that was asked for is still empty.
            Some(section) => listener.id == format!("{}/{}", parent.gateway, section),
            // Attaching to the whole Gateway asks every listener of it to take the route.
            // The trailing slash is what keeps `infra/main` off `infra/mainline`.
            None => listener.id.starts_with(&format!("{}/", parent.gateway)),
        })
        .any(|listener| listener.rules.iter().any(|r| r.route == route))
}

/// `served` is `None` when the gateway could not be reached.
pub fn join(mut declared: Vec<DeclaredRoute>, served: Option<&Served>) -> Vec<Row> {
    // Sorted by id so the screen renders the same order every poll instead of
    // shuffling rows whenever Kubernetes returns the list in a different order.
    declared.sort_by(|a, b| a.id.cmp(&b.id));
    declared
        .into_iter()
        .map(|route| {
            let DeclaredRoute {
                id,
                namespace,
                parents,
            } = route;
            let parents: Vec<ParentRow> = parents
                .into_iter()
                .map(|parent| {
                    // Order matters here. An unreachable gateway wins over everything else
                    // (we truly don't know). A parent with no verdict comes next, because
                    // until that Gateway has spoken its presence in the served config is
                    // evidence of nothing either way. A refused parent must never fall
                    // through to the presence check, because the Gateway already explained
                    // why it is absent — that is not the same fault as an accepted route
                    // going missing.
                    let state = match (served, parent.acceptance) {
                        (None, _) => State::Unknown,
                        (_, Acceptance::Pending) => State::Pending,
                        (_, Acceptance::Refused) => State::Refused,
                        (Some(s), Acceptance::Accepted) if is_served_by(s, &parent, &id) => {
                            State::Served
                        }
                        (Some(_), Acceptance::Accepted) => State::Missing,
                    };
                    ParentRow {
                        gateway: parent.gateway,
                        state,
                        reason: parent.reason,
                        message: parent.message,
                    }
                })
                .collect();
            Row {
                id,
                namespace,
                state: summarise(&parents),
                parents,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::declared::DeclaredParent;
    use crate::served::{ServedListener, ServedRule};

    fn parent(gateway: &str, acceptance: Acceptance, reason: Option<&str>) -> DeclaredParent {
        DeclaredParent {
            gateway: gateway.to_string(),
            section: None,
            acceptance,
            reason: reason.map(str::to_string),
            message: reason.map(|r| format!("{r} happened")),
        }
    }

    /// The ordinary case the console mostly shows: one route on one Gateway.
    fn declared(id: &str, acceptance: Acceptance, reason: Option<&str>) -> DeclaredRoute {
        on_gateways(id, vec![parent("infra/main", acceptance, reason)])
    }

    fn on_gateways(id: &str, parents: Vec<DeclaredParent>) -> DeclaredRoute {
        DeclaredRoute {
            id: id.to_string(),
            namespace: id.split('/').next().unwrap().to_string(),
            parents,
        }
    }

    /// Rules served under `infra/main/http`, the listener the `declared` helper attaches to.
    fn served(ids: &[&str]) -> Served {
        listeners(&[("infra/main/http", ids)])
    }

    fn listeners(listeners: &[(&str, &[&str])]) -> Served {
        Served {
            listeners: listeners
                .iter()
                .map(|(id, routes)| ServedListener {
                    id: id.to_string(),
                    rules: routes
                        .iter()
                        .map(|route| ServedRule {
                            route: route.to_string(),
                            cluster: None,
                        })
                        .collect(),
                })
                .collect(),
        }
    }

    #[test]
    fn accepted_and_present_is_served() {
        let rows = join(
            vec![declared("apps/checkout", Acceptance::Accepted, None)],
            Some(&served(&["apps/checkout"])),
        );
        assert_eq!(rows[0].parents[0].state, State::Served);
    }

    #[test]
    fn refused_keeps_the_reason_and_is_never_called_missing() {
        let rows = join(
            vec![declared(
                "apps/billing",
                Acceptance::Refused,
                Some("UnsupportedValue"),
            )],
            Some(&served(&[])),
        );
        assert_eq!(rows[0].parents[0].state, State::Refused);
        assert_eq!(
            rows[0].parents[0].reason.as_deref(),
            Some("UnsupportedValue")
        );
    }

    #[test]
    fn accepted_but_absent_is_missing_which_is_a_fault_worth_showing() {
        // The gateway said yes and is not serving it. Nothing explains this, which is
        // exactly why it must not be quietly rendered as served.
        let rows = join(
            vec![declared("apps/checkout", Acceptance::Accepted, None)],
            Some(&served(&[])),
        );
        assert_eq!(rows[0].parents[0].state, State::Missing);
    }

    #[test]
    fn an_unreachable_gateway_makes_every_row_unknown_not_missing() {
        let rows = join(
            vec![
                declared("apps/checkout", Acceptance::Accepted, None),
                declared(
                    "apps/billing",
                    Acceptance::Refused,
                    Some("UnsupportedValue"),
                ),
            ],
            None,
        );
        assert!(rows.iter().all(|r| r.state == State::Unknown));
        assert!(rows
            .iter()
            .flat_map(|r| &r.parents)
            .all(|p| p.state == State::Unknown));
    }

    #[test]
    fn an_unreachable_gateway_still_reports_the_reason_it_already_knew() {
        let rows = join(
            vec![declared(
                "apps/billing",
                Acceptance::Refused,
                Some("UnsupportedValue"),
            )],
            None,
        );
        assert_eq!(
            rows[0].parents[0].reason.as_deref(),
            Some("UnsupportedValue")
        );
    }

    #[test]
    fn an_unreachable_gateway_makes_every_parent_unknown_and_keeps_both_reasons() {
        // Not knowing what is served says nothing about what each Gateway already ruled,
        // and those rulings are the only thing left to show while the gateway is down.
        let rows = join(
            vec![on_gateways(
                "apps/search",
                vec![
                    parent("infra/main", Acceptance::Refused, Some("UnsupportedValue")),
                    parent(
                        "infra/second",
                        Acceptance::Refused,
                        Some("NoMatchingListenerHostname"),
                    ),
                ],
            )],
            None,
        );
        assert_eq!(rows[0].state, State::Unknown);
        assert!(rows[0].parents.iter().all(|p| p.state == State::Unknown));
        assert_eq!(
            rows[0].parents[0].reason.as_deref(),
            Some("UnsupportedValue")
        );
        assert_eq!(
            rows[0].parents[1].reason.as_deref(),
            Some("NoMatchingListenerHostname")
        );
    }

    #[test]
    fn rows_come_back_in_a_stable_order() {
        let rows = join(
            vec![
                declared("shop/catalog", Acceptance::Accepted, None),
                declared("apps/checkout", Acceptance::Accepted, None),
            ],
            Some(&served(&["shop/catalog", "apps/checkout"])),
        );
        assert_eq!(
            rows[0].id, "apps/checkout",
            "sorted, so the screen does not shuffle between polls"
        );
    }

    #[test]
    fn a_route_nobody_has_reconciled_yet_is_pending_not_refused() {
        // Straight from the parsed resource, because the distinction this proves was the
        // one the parse layer already made and the join then threw away: an HTTPRoute with
        // no `.status` has had no verdict written, and calling that a refusal tells the
        // user the gateway rejected their route when nobody has looked at it yet.
        let declared = crate::declared::routes_from_list(
            r#"{"items":[{"metadata":{"name":"fresh","namespace":"apps"}}]}"#,
            "gapura.dev/controller",
        )
        .unwrap();
        let rows = join(declared, Some(&served(&[])));
        assert_eq!(rows[0].state, State::Pending);
        assert!(rows[0].parents.is_empty());
    }

    #[test]
    fn a_pending_route_that_happens_to_be_served_is_still_pending() {
        // Presence in the served config is not a verdict: the gateway may be serving an
        // older generation of this route while the current one waits to be reconciled.
        let rows = join(
            vec![declared("apps/checkout", Acceptance::Pending, None)],
            Some(&served(&["apps/checkout"])),
        );
        assert_eq!(rows[0].parents[0].state, State::Pending);
    }

    #[test]
    fn accepted_on_one_gateway_and_refused_on_another_is_mixed() {
        // The bug this shape exists to fix. Whichever verdict a single state picked would
        // be false about the other Gateway, and the two refusals have different causes, so
        // there is no one reason either. Both have to survive, attributed.
        let rows = join(
            vec![on_gateways(
                "apps/search",
                vec![
                    parent("infra/main", Acceptance::Accepted, None),
                    parent(
                        "infra/second",
                        Acceptance::Refused,
                        Some("NoMatchingListenerHostname"),
                    ),
                ],
            )],
            Some(&listeners(&[("infra/main/http", &["apps/search"])])),
        );
        assert_eq!(rows[0].state, State::Mixed);
        assert_eq!(rows[0].parents.len(), 2);
        assert_eq!(rows[0].parents[0].gateway, "infra/main");
        assert_eq!(rows[0].parents[0].state, State::Served);
        assert_eq!(rows[0].parents[1].gateway, "infra/second");
        assert_eq!(rows[0].parents[1].state, State::Refused);
        assert_eq!(
            rows[0].parents[1].reason.as_deref(),
            Some("NoMatchingListenerHostname")
        );
    }

    #[test]
    fn a_route_on_one_gateway_summarises_as_that_gateways_state() {
        // The ordinary case must not pay for the exception: one attachment has one verdict
        // and mixed would be nonsense.
        let rows = join(
            vec![declared(
                "apps/billing",
                Acceptance::Refused,
                Some("UnsupportedValue"),
            )],
            Some(&served(&[])),
        );
        assert_eq!(rows[0].state, State::Refused);
    }

    #[test]
    fn gateways_that_agree_summarise_as_what_they_agree_on() {
        // Mixed means the Gateways disagree. Two of them saying the same thing is not a
        // disagreement, however many of them there are.
        let rows = join(
            vec![on_gateways(
                "apps/search",
                vec![
                    parent("infra/main", Acceptance::Accepted, None),
                    parent("infra/second", Acceptance::Accepted, None),
                ],
            )],
            Some(&listeners(&[
                ("infra/main/http", &["apps/search"]),
                ("infra/second/http", &["apps/search"]),
            ])),
        );
        assert_eq!(rows[0].state, State::Served);
    }

    #[test]
    fn a_route_no_parent_attributes_to_this_controller_is_pending_with_no_parents() {
        // Another controller's Gateway took this route; gapura never did. Summarising
        // someone else's yes would claim a verdict this console cannot account for.
        let declared = crate::declared::routes_from_list(
            r#"{"items":[{"metadata":{"name":"theirs","namespace":"apps"},
                "status":{"parents":[{"parentRef":{"name":"edge","namespace":"infra"},
                  "controllerName":"k8s.io/ingress-nginx","conditions":[
                  {"type":"Accepted","status":"True","reason":"Accepted","message":"ok"}]}]}}]}"#,
            "gapura.dev/controller",
        )
        .unwrap();
        let rows = join(declared, Some(&served(&["apps/theirs"])));
        assert_eq!(rows[0].state, State::Pending);
        assert!(rows[0].parents.is_empty());
    }

    #[test]
    fn a_parent_that_named_a_listener_is_not_served_by_a_different_one() {
        // The route attached to one listener of the Gateway. A rule under a sibling
        // listener serves some other attachment of some other route, and counting it would
        // report this attachment up while the listener it asked for carries nothing.
        let mut only_http = parent("infra/main", Acceptance::Accepted, None);
        only_http.section = Some("http".to_string());
        let rows = join(
            vec![on_gateways("apps/checkout", vec![only_http])],
            Some(&listeners(&[("infra/main/https", &["apps/checkout"])])),
        );
        assert_eq!(rows[0].parents[0].state, State::Missing);
    }

    #[test]
    fn a_parent_that_named_no_listener_is_served_by_any_listener_of_its_gateway() {
        // Attaching to the whole Gateway asks every listener of it to take the route, so
        // serving it on one of them is the Gateway serving it.
        let rows = join(
            vec![declared("apps/checkout", Acceptance::Accepted, None)],
            Some(&listeners(&[("infra/main/https", &["apps/checkout"])])),
        );
        assert_eq!(rows[0].parents[0].state, State::Served);
    }

    #[test]
    fn another_gateways_listener_does_not_serve_this_parent() {
        // Presence has to be judged against the Gateway the parent names, or the console
        // reports a route as up on a Gateway that has never heard of it. The second case
        // guards the boundary: `infra/main` must not match the Gateway `infra/mainline`.
        let rows = join(
            vec![
                on_gateways(
                    "apps/search",
                    vec![parent("infra/second", Acceptance::Accepted, None)],
                ),
                on_gateways(
                    "apps/checkout",
                    vec![parent("infra/main", Acceptance::Accepted, None)],
                ),
            ],
            Some(&listeners(&[
                ("infra/main/http", &["apps/search"]),
                ("infra/mainline/http", &["apps/checkout"]),
            ])),
        );
        assert_eq!(rows[0].id, "apps/checkout");
        assert_eq!(rows[0].parents[0].state, State::Missing);
        assert_eq!(rows[1].id, "apps/search");
        assert_eq!(rows[1].parents[0].state, State::Missing);
    }

    #[test]
    fn a_parent_ref_without_a_namespace_resolves_to_the_routes_own() {
        // End to end, because the resolution happens in the parse and only the join can
        // show that it named the Gateway the served side actually calls that.
        let declared = crate::declared::routes_from_list(
            r#"{"items":[{"metadata":{"name":"local","namespace":"apps"},
                "status":{"parents":[{"parentRef":{"name":"main"},
                  "controllerName":"gapura.dev/controller","conditions":[
                  {"type":"Accepted","status":"True","reason":"Accepted","message":"ok"}]}]}}]}"#,
            "gapura.dev/controller",
        )
        .unwrap();
        let rows = join(
            declared,
            Some(&listeners(&[("apps/main/http", &["apps/local"])])),
        );
        assert_eq!(rows[0].parents[0].gateway, "apps/main");
        assert_eq!(rows[0].parents[0].state, State::Served);
    }
}
