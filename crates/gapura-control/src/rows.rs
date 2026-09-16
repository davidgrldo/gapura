//! Declared and served, joined into the rows the routes screen shows.

use crate::declared::DeclaredRoute;
use crate::served::Served;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// Declared, accepted, and present in what the gateway serves.
    Served,
    /// Declared and refused. `reason` says why.
    Refused,
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
            // Order matters here: an unreachable gateway must win over everything else
            // (we truly don't know), and a refused route must never fall through to the
            // presence check below it, because the gateway already explained why it is
            // absent — that is not the same fault as an accepted route going missing.
            let state = match served {
                None => State::Unknown,
                Some(_) if !route.accepted => State::Refused,
                Some(s) if s.rules.iter().any(|r| r.route == route.id) => State::Served,
                Some(_) => State::Missing,
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

    fn declared(id: &str, accepted: bool, reason: Option<&str>) -> DeclaredRoute {
        DeclaredRoute {
            id: id.to_string(),
            namespace: id.split('/').next().unwrap().to_string(),
            accepted,
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
            vec![declared("apps/checkout", true, None)],
            Some(&served(&["apps/checkout"])),
        );
        assert_eq!(rows[0].state, State::Served);
    }

    #[test]
    fn refused_keeps_the_reason_and_is_never_called_missing() {
        let rows = join(
            vec![declared("apps/billing", false, Some("UnsupportedValue"))],
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
            vec![declared("apps/checkout", true, None)],
            Some(&served(&[])),
        );
        assert_eq!(rows[0].state, State::Missing);
    }

    #[test]
    fn an_unreachable_gateway_makes_every_row_unknown_not_missing() {
        let rows = join(
            vec![
                declared("apps/checkout", true, None),
                declared("apps/billing", false, Some("UnsupportedValue")),
            ],
            None,
        );
        assert!(rows.iter().all(|r| r.state == State::Unknown));
    }

    #[test]
    fn an_unreachable_gateway_still_reports_the_reason_it_already_knew() {
        let rows = join(
            vec![declared("apps/billing", false, Some("UnsupportedValue"))],
            None,
        );
        assert_eq!(rows[0].reason.as_deref(), Some("UnsupportedValue"));
    }

    #[test]
    fn rows_come_back_in_a_stable_order() {
        let rows = join(
            vec![
                declared("shop/catalog", true, None),
                declared("apps/checkout", true, None),
            ],
            Some(&served(&["shop/catalog", "apps/checkout"])),
        );
        assert_eq!(
            rows[0].id, "apps/checkout",
            "sorted, so the screen does not shuffle between polls"
        );
    }
}
