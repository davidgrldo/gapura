//! Declared and served, joined into the rows the routes screen shows.

use crate::declared::{Acceptance, DeclaredParent, DeclaredRoute};
use crate::served::Served;
use serde::Serialize;
use std::collections::HashMap;

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
    /// Declared, accepted and installed, but a reference it names did not resolve, so the
    /// rule the gateway is serving cannot reach a backend. Presence in the served config
    /// does not redeem this: the route answers, with an error, on every request.
    Unresolved,
    /// Declared, accepted, and its references resolved — but the gateway could not be
    /// reached, so whether it is actually serving the route is unknown. Nothing else
    /// carries this state: everything short of that question is decided by Kubernetes
    /// alone, and an unreachable gateway does not unknow it.
    Unknown,
    /// The Gateways this route attaches to do not agree; `parents` says who said what.
    Mixed,
}

/// One attachment of the route, and how it is faring on that Gateway alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ParentRow {
    /// The Gateway attached to, as `namespace/name`.
    pub gateway: String,
    /// The listener named by `sectionName`, when the attachment named one. Two attachments
    /// to the same Gateway are only tellable apart by this.
    pub section: Option<String>,
    pub state: State,
    /// Why this attachment is in the state it is in, taken from whichever condition
    /// accounts for that state — the `ResolvedRefs` one when the references did not
    /// resolve, the `Accepted` one otherwise. It belongs here rather than on the row:
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

/// The served rules indexed for the question `join` asks once per attachment: is this route
/// carried by a listener that belongs to this Gateway? Two maps built in one pass, so the
/// answer is a lookup rather than a scan of every rule under every listener per route --
/// which was O(declared x rules) with a string compare inside, and grew with the cluster.
struct ServedIndex<'a> {
    /// Listener id -> the routes it carries.
    by_listener: HashMap<&'a str, std::collections::HashSet<&'a str>>,
    /// Gateway id (the listener id up to its last `/`) -> every route any of its listeners
    /// carries. The trailing slash in the key construction keeps `infra/main` off
    /// `infra/mainline`, exactly as the prefix match it replaces did.
    by_gateway: HashMap<&'a str, std::collections::HashSet<&'a str>>,
}

impl<'a> ServedIndex<'a> {
    fn build(served: &'a Served) -> Self {
        let mut by_listener: HashMap<&str, std::collections::HashSet<&str>> = HashMap::new();
        let mut by_gateway: HashMap<&str, std::collections::HashSet<&str>> = HashMap::new();
        for listener in &served.listeners {
            let gateway = listener.id.rsplit_once('/').map(|(g, _)| g).unwrap_or("");
            for rule in &listener.rules {
                by_listener
                    .entry(listener.id.as_str())
                    .or_default()
                    .insert(rule.route.as_str());
                by_gateway
                    .entry(gateway)
                    .or_default()
                    .insert(rule.route.as_str());
            }
        }
        Self {
            by_listener,
            by_gateway,
        }
    }

    /// Whether this Gateway is serving the route, judged only against the listeners that
    /// belong to it. A rule under some other Gateway's listener is another attachment being
    /// served, and counting it would report a route as up on a Gateway that never took it.
    fn serves(&self, parent: &DeclaredParent, route: &str) -> bool {
        match &parent.section {
            // The route asked for one listener by name, so only that listener can serve
            // this attachment: a sibling listener carrying the route serves some other
            // attachment, and the one that was asked for is still empty.
            Some(section) => {
                let listener_id = format!("{}/{}", parent.gateway, section);
                self.by_listener
                    .get(listener_id.as_str())
                    .is_some_and(|routes| routes.contains(route))
            }
            None => self
                .by_gateway
                .get(parent.gateway.as_str())
                .is_some_and(|routes| routes.contains(route)),
        }
    }
}

/// `served` is `None` when the gateway could not be reached.
pub fn join(mut declared: Vec<DeclaredRoute>, served: Option<&Served>) -> Vec<Row> {
    // Sorted by id so the screen renders the same order every poll instead of
    // shuffling rows whenever Kubernetes returns the list in a different order.
    declared.sort_by(|a, b| a.id.cmp(&b.id));
    let index = served.map(ServedIndex::build);
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
                    // Order matters here, and only the fourth arm ever looks at the served
                    // side. `Unknown` means one specific thing — we cannot tell whether this
                    // route is being served — and that question only makes sense once a
                    // route has been accepted and its references have resolved; everything
                    // above it is decided by Kubernetes alone, and an unreachable gateway
                    // does not unknow any of it. A parent with no verdict is still unruled.
                    // A refused parent is still refused, with the reason the Gateway already
                    // gave — that verdict was written before the gateway went dark, so the
                    // outage does not retract it. A parent whose references did not resolve
                    // still has a missing backend, because that fact came from the Service
                    // list, not from the gateway, and an outage on one side does not make a
                    // Service reappear on the other. Only once acceptance and reference
                    // resolution are both settled does "is it actually being served" become
                    // the open question, and only then can not reaching the gateway leave it
                    // open rather than answered.
                    let state = match (parent.acceptance, index.as_ref()) {
                        (Acceptance::Pending, _) => State::Pending,
                        (Acceptance::Refused, _) => State::Refused,
                        (Acceptance::Accepted, _) if !parent.refs_resolved => State::Unresolved,
                        (Acceptance::Accepted, None) => State::Unknown,
                        (Acceptance::Accepted, Some(index)) if index.serves(&parent, &id) => {
                            State::Served
                        }
                        (Acceptance::Accepted, Some(_)) => State::Missing,
                    };
                    // Which condition explains the parent, rather than which one the state
                    // was read from: an accepted route with a dangling reference is
                    // explained by `ResolvedRefs`, matching the `Unresolved` state that
                    // condition now always produces, gateway reachable or not. Reporting the
                    // acceptance instead would put `Accepted / Route is accepted` beside a
                    // broken route, which is true, useless, and reads as reassurance.
                    let refs_explain =
                        parent.acceptance == Acceptance::Accepted && !parent.refs_resolved;
                    let (reason, message) = if refs_explain {
                        (parent.refs_reason, parent.refs_message)
                    } else {
                        (parent.reason, parent.message)
                    };
                    ParentRow {
                        gateway: parent.gateway,
                        section: parent.section,
                        state,
                        reason,
                        message,
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

    const LIST: &str = include_str!("../tests/fixtures/httproutes.json");
    /// The default of gapura's own `--controller-name` flag.
    const CONTROLLER: &str = "gapura.dev/controller";

    /// The row for one route id, for the fixture-driven tests that care about a single one.
    fn row_for<'a>(rows: &'a [Row], id: &str) -> &'a Row {
        rows.iter().find(|r| r.id == id).expect("a row per route")
    }

    fn parent(gateway: &str, acceptance: Acceptance, reason: Option<&str>) -> DeclaredParent {
        DeclaredParent {
            gateway: gateway.to_string(),
            section: None,
            acceptance,
            reason: reason.map(str::to_string),
            message: reason.map(|r| format!("{r} happened")),
            refs_resolved: true,
            refs_reason: None,
            refs_message: None,
        }
    }

    /// The same attachment, with a reference that did not resolve. The Gateway accepted the
    /// route and installed its rules either way; it is only the backend behind them that is
    /// not there, which is why this is never a substitute for a refusal.
    fn with_unresolved_refs(mut parent: DeclaredParent, reason: &str) -> DeclaredParent {
        parent.refs_resolved = false;
        parent.refs_reason = Some(reason.to_string());
        parent.refs_message = Some(format!("{reason} happened"));
        parent
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
                    // Irrelevant to what these tests claim: they are about which rules stay
                    // attributed to which listener, never about a listener's own port or
                    // protocol.
                    port: 0,
                    client_port: None,
                    protocol: String::new(),
                    hostname: None,
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
    fn an_unreachable_gateway_still_unknows_an_accepted_route_with_resolved_refs() {
        // Unchanged. This is the one case `Unknown` exists for: the route was accepted,
        // its references resolved, and the only open question left is whether the gateway
        // is actually serving it — an answer only the gateway itself can give.
        let rows = join(
            vec![declared("apps/checkout", Acceptance::Accepted, None)],
            None,
        );
        assert_eq!(rows[0].state, State::Unknown);
        assert_eq!(rows[0].parents[0].state, State::Unknown);
    }

    #[test]
    fn an_unreachable_gateway_still_refuses_a_refused_route_not_unknown() {
        // The refusal is a verdict Kubernetes already wrote down; a gateway outage does
        // not unwrite it. Reading it back as `Unknown` would bury a fault that is already
        // fully explained behind the one thing that actually is unknown right now, which
        // is whether the gateway is reachable.
        let rows = join(
            vec![declared(
                "apps/billing",
                Acceptance::Refused,
                Some("UnsupportedValue"),
            )],
            None,
        );
        assert_eq!(rows[0].parents[0].state, State::Refused);
        assert_eq!(
            rows[0].parents[0].reason.as_deref(),
            Some("UnsupportedValue")
        );
    }

    #[test]
    fn an_unreachable_gateway_still_refuses_every_parent_and_keeps_both_reasons() {
        // Not knowing what is served says nothing about what each Gateway already ruled,
        // and those rulings are the only thing left to show while the gateway is down —
        // so the state should say exactly that, not `Unknown`.
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
        assert_eq!(rows[0].state, State::Refused);
        assert!(rows[0].parents.iter().all(|p| p.state == State::Refused));
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
    fn an_unreachable_gateway_leaves_a_pending_route_pending_not_unknown() {
        // Nobody has ruled on this route yet, and that is a fact Kubernetes already
        // recorded by writing no verdict at all. A gateway outage supplies no new
        // information about it, so it must not manufacture `Unknown` where the honest
        // answer is still just "nobody has looked".
        let rows = join(
            vec![declared("apps/checkout", Acceptance::Pending, None)],
            None,
        );
        assert_eq!(rows[0].parents[0].state, State::Pending);
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
    fn two_attachments_to_the_same_gateway_are_tellable_apart_by_section() {
        // A route may name the same Gateway twice, once per listener, and the two
        // attachments can legitimately disagree: served on the listener that carries the
        // route, missing on the one that does not. Without `section` on `ParentRow` these
        // two parents are identical, and a reader of a `Mixed` row has no way to tell which
        // verdict belongs to which listener — the exact confusion #47 removed one level up.
        let mut http = parent("infra/main", Acceptance::Accepted, None);
        http.section = Some("http".to_string());
        let mut https = parent("infra/main", Acceptance::Accepted, None);
        https.section = Some("https".to_string());
        let rows = join(
            vec![on_gateways("apps/checkout", vec![http, https])],
            Some(&listeners(&[("infra/main/http", &["apps/checkout"])])),
        );
        assert_eq!(rows[0].state, State::Mixed);
        assert_eq!(rows[0].parents.len(), 2);
        let served = rows[0]
            .parents
            .iter()
            .find(|p| p.section.as_deref() == Some("http"))
            .expect("the http attachment");
        assert_eq!(served.state, State::Served);
        let missing = rows[0]
            .parents
            .iter()
            .find(|p| p.section.as_deref() == Some("https"))
            .expect("the https attachment");
        assert_eq!(missing.state, State::Missing);
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

    #[test]
    fn a_route_whose_refs_did_not_resolve_is_unresolved_even_though_it_is_served() {
        // The bug. gapura compiles and installs the rule whether or not the backendRef
        // resolved, so the route is in /debug/config and answers every request with
        // `500 no valid backend`. Presence therefore proves nothing about this route, and
        // reading it as served paints the console green over the one route that is
        // certainly broken — the opposite of what someone opens this screen to find out.
        let declared = crate::declared::routes_from_list(LIST, CONTROLLER).unwrap();
        let rows = join(declared, Some(&served(&["apps/payments"])));
        let payments = row_for(&rows, "apps/payments");
        assert_eq!(payments.parents[0].state, State::Unresolved);
        assert_eq!(payments.state, State::Unresolved);
    }

    #[test]
    fn an_unresolved_parent_reports_why_its_refs_failed_not_why_it_was_accepted() {
        // Two conditions, two different facts. `Accepted / Route is accepted` is true and
        // useless here: it restates the state the row is not in. The only sentence that
        // sends the reader anywhere is the one naming the backend that is not there.
        let declared = crate::declared::routes_from_list(LIST, CONTROLLER).unwrap();
        let rows = join(declared, Some(&served(&["apps/payments"])));
        let parent = &row_for(&rows, "apps/payments").parents[0];
        assert_eq!(parent.reason.as_deref(), Some("BackendNotFound"));
        assert_eq!(
            parent.message.as_deref(),
            Some("backendRef apps/ledger not found")
        );
    }

    #[test]
    fn a_route_with_no_resolved_refs_condition_at_all_is_unaffected() {
        // Absence of a complaint is not a complaint. A gateway that has written `Accepted`
        // and nothing else has not said a reference failed, and inventing the failure would
        // flag every healthy route the moment it talked to an implementation that writes
        // fewer conditions than gapura does.
        let declared = crate::declared::routes_from_list(
            r#"{"items":[{"metadata":{"name":"checkout","namespace":"apps"},
                "status":{"parents":[{"parentRef":{"name":"main","namespace":"infra"},
                  "controllerName":"gapura.dev/controller","conditions":[
                  {"type":"Accepted","status":"True","reason":"Accepted","message":"ok"}]}]}}]}"#,
            CONTROLLER,
        )
        .unwrap();
        let rows = join(declared, Some(&served(&["apps/checkout"])));
        assert_eq!(rows[0].parents[0].state, State::Served);
    }

    #[test]
    fn resolved_refs_still_reading_unknown_is_not_a_failure() {
        // Only an explicit `False` is the gateway saying a reference did not resolve.
        // `Unknown` is it saying it has not finished looking, and a console that reads
        // "still checking" as "broken" cries wolf on every route mid-reconcile.
        let declared = crate::declared::routes_from_list(
            r#"{"items":[{"metadata":{"name":"checkout","namespace":"apps"},
                "status":{"parents":[{"parentRef":{"name":"main","namespace":"infra"},
                  "controllerName":"gapura.dev/controller","conditions":[
                  {"type":"Accepted","status":"True","reason":"Accepted","message":"ok"},
                  {"type":"ResolvedRefs","status":"Unknown","reason":"Pending",
                   "message":"still resolving"}]}]}}]}"#,
            CONTROLLER,
        )
        .unwrap();
        let rows = join(declared, Some(&served(&["apps/checkout"])));
        assert_eq!(rows[0].parents[0].state, State::Served);
    }

    #[test]
    fn a_refused_parent_is_refused_even_when_its_refs_did_not_resolve() {
        // The Gateway never installed this route, so its dangling backendRef is a fault in
        // a rule that does not exist. Reporting the reference would send the reader off to
        // create a Service that would still change nothing until the refusal is fixed.
        let rows = join(
            vec![on_gateways(
                "apps/billing",
                vec![with_unresolved_refs(
                    parent("infra/main", Acceptance::Refused, Some("UnsupportedValue")),
                    "BackendNotFound",
                )],
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
    fn an_unreachable_gateway_still_reports_unresolved_refs_not_unknown() {
        // Only one side went dark. The unresolved reference was read from Kubernetes, not
        // from the gateway, so it survives the outage untouched — an outage on the gateway
        // side does not make the missing Service reappear, and it must not demote a fault
        // Kubernetes already reported down to a mere "can't tell".
        let rows = join(
            vec![on_gateways(
                "apps/payments",
                vec![with_unresolved_refs(
                    parent("infra/main", Acceptance::Accepted, None),
                    "BackendNotFound",
                )],
            )],
            None,
        );
        assert_eq!(rows[0].parents[0].state, State::Unresolved);
        assert_eq!(
            rows[0].parents[0].reason.as_deref(),
            Some("BackendNotFound")
        );
    }

    #[test]
    fn served_on_one_gateway_and_unresolved_on_another_is_mixed() {
        // `Unresolved` summarises like any other state. gapura writes one ResolvedRefs for
        // every parent of a route, so this split comes from the Gateway API's per-parent
        // status shape rather than from gapura; the console reads what is written to the
        // resource instead of what it assumes the writer would have written.
        let rows = join(
            vec![on_gateways(
                "apps/payments",
                vec![
                    parent("infra/main", Acceptance::Accepted, None),
                    with_unresolved_refs(
                        parent("infra/second", Acceptance::Accepted, None),
                        "BackendNotFound",
                    ),
                ],
            )],
            Some(&listeners(&[
                ("infra/main/http", &["apps/payments"]),
                ("infra/second/http", &["apps/payments"]),
            ])),
        );
        assert_eq!(rows[0].state, State::Mixed);
        assert_eq!(rows[0].parents[0].state, State::Served);
        assert_eq!(rows[0].parents[1].state, State::Unresolved);
        assert_eq!(
            rows[0].parents[1].reason.as_deref(),
            Some("BackendNotFound")
        );
    }

    #[test]
    fn refused_on_one_gateway_and_unresolved_on_another_is_mixed() {
        // The split that is reachable against gapura itself: one ResolvedRefs failure for
        // the whole route, and an Accepted that differs per Gateway. The two parents need
        // different sentences — fix the hostname here, create the Service there — and a
        // single state for the row could only carry one of them.
        let rows = join(
            vec![on_gateways(
                "apps/payments",
                vec![
                    with_unresolved_refs(
                        parent("infra/main", Acceptance::Accepted, None),
                        "BackendNotFound",
                    ),
                    with_unresolved_refs(
                        parent(
                            "infra/second",
                            Acceptance::Refused,
                            Some("NoMatchingListenerHostname"),
                        ),
                        "BackendNotFound",
                    ),
                ],
            )],
            Some(&listeners(&[("infra/main/http", &["apps/payments"])])),
        );
        assert_eq!(rows[0].state, State::Mixed);
        assert_eq!(rows[0].parents[0].state, State::Unresolved);
        assert_eq!(
            rows[0].parents[0].reason.as_deref(),
            Some("BackendNotFound")
        );
        assert_eq!(rows[0].parents[1].state, State::Refused);
        assert_eq!(
            rows[0].parents[1].reason.as_deref(),
            Some("NoMatchingListenerHostname")
        );
    }
}
