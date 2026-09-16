//! Declared and served, joined into the rows the routes screen shows.

use crate::declared::{Acceptance, DeclaredRoute};
use crate::served::Served;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Row {
    pub id: String,
    pub namespace: String,
    pub state: State,
    pub reason: Option<String>,
    pub message: Option<String>,
}

/// `served` is `None` when the gateway could not be reached.
pub fn join(mut declared: Vec<DeclaredRoute>, served: Option<&Served>) -> Vec<Row> {
    // Sorted by id so the screen renders the same order every poll instead of
    // shuffling rows whenever Kubernetes returns the list in a different order.
    declared.sort_by(|a, b| a.id.cmp(&b.id));
    declared
        .into_iter()
        .map(|route| {
            // Order matters here. An unreachable gateway wins over everything else (we
            // truly don't know). A route with no verdict comes next, because until the
            // gateway has spoken its presence in the served config is evidence of nothing
            // either way. A refused route must never fall through to the presence check,
            // because the gateway already explained why it is absent — that is not the
            // same fault as an accepted route going missing.
            let state = match (served, route.acceptance) {
                (None, _) => State::Unknown,
                (_, Acceptance::Pending) => State::Pending,
                (_, Acceptance::Refused) => State::Refused,
                (Some(s), Acceptance::Accepted) if s.rules.iter().any(|r| r.route == route.id) => {
                    State::Served
                }
                (Some(_), Acceptance::Accepted) => State::Missing,
            };
            Row {
                id: route.id,
                namespace: route.namespace,
                state,
                reason: route.reason,
                message: route.message,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::served::ServedRule;

    fn declared(id: &str, acceptance: Acceptance, reason: Option<&str>) -> DeclaredRoute {
        DeclaredRoute {
            id: id.to_string(),
            namespace: id.split('/').next().unwrap().to_string(),
            acceptance,
            reason: reason.map(str::to_string),
            message: reason.map(|r| format!("{r} happened")),
        }
    }
    fn served(ids: &[&str]) -> Served {
        Served {
            rules: ids
                .iter()
                .map(|id| ServedRule {
                    route: id.to_string(),
                    cluster: None,
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
        assert_eq!(rows[0].state, State::Served);
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
        assert_eq!(rows[0].state, State::Refused);
        assert_eq!(rows[0].reason.as_deref(), Some("UnsupportedValue"));
    }

    #[test]
    fn accepted_but_absent_is_missing_which_is_a_fault_worth_showing() {
        // The gateway said yes and is not serving it. Nothing explains this, which is
        // exactly why it must not be quietly rendered as served.
        let rows = join(
            vec![declared("apps/checkout", Acceptance::Accepted, None)],
            Some(&served(&[])),
        );
        assert_eq!(rows[0].state, State::Missing);
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
        assert_eq!(rows[0].reason.as_deref(), Some("UnsupportedValue"));
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
        )
        .unwrap();
        let rows = join(declared, Some(&served(&[])));
        assert_eq!(rows[0].state, State::Pending);
        assert_eq!(rows[0].reason, None);
    }

    #[test]
    fn a_pending_route_that_happens_to_be_served_is_still_pending() {
        // Presence in the served config is not a verdict: the gateway may be serving an
        // older generation of this route while the current one waits to be reconciled.
        let rows = join(
            vec![declared("apps/checkout", Acceptance::Pending, None)],
            Some(&served(&["apps/checkout"])),
        );
        assert_eq!(rows[0].state, State::Pending);
    }
}
