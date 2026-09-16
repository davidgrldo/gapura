//! What was declared, and what the gateway said about it.

use serde::Deserialize;

/// A Kubernetes condition is `True`, `False` or `Unknown`, and may not be written at all,
/// so a bool cannot hold one: it would fold "not reconciled yet" into "refused".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acceptance {
    Accepted,
    Refused,
    /// No verdict yet: no status, or a condition still reading `Unknown`.
    Pending,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredRoute {
    /// `namespace/name`.
    pub id: String,
    pub namespace: String,
    pub acceptance: Acceptance,
    /// Why, when it was not accepted.
    pub reason: Option<String>,
    pub message: Option<String>,
}

/// Parse a Kubernetes list response into the fields the console shows.
pub fn routes_from_list(json: &str) -> anyhow::Result<Vec<DeclaredRoute>> {
    #[derive(Deserialize)]
    struct List {
        items: Vec<Item>,
    }
    #[derive(Deserialize)]
    struct Item {
        metadata: Metadata,
        #[serde(default)]
        status: Option<Status>,
    }
    #[derive(Deserialize)]
    struct Metadata {
        name: String,
        namespace: String,
    }
    #[derive(Deserialize)]
    struct Status {
        #[serde(default)]
        parents: Vec<Parent>,
    }
    #[derive(Deserialize)]
    struct Parent {
        #[serde(default)]
        conditions: Vec<Condition>,
    }
    #[derive(Deserialize)]
    struct Condition {
        #[serde(rename = "type")]
        kind: String,
        status: String,
        reason: Option<String>,
        message: Option<String>,
    }

    let list: List = serde_json::from_str(json)?;
    Ok(list
        .items
        .into_iter()
        .map(|item| {
            let accepted_condition = item
                .status
                .iter()
                .flat_map(|s| s.parents.iter())
                .flat_map(|p| p.conditions.iter())
                .find(|c| c.kind == "Accepted");
            let acceptance = match accepted_condition.map(|c| c.status.as_str()) {
                Some("True") => Acceptance::Accepted,
                Some("False") => Acceptance::Refused,
                // `Unknown`, an absent condition, or a status this version does not know:
                // none of them is a verdict, so none of them may be read as one.
                _ => Acceptance::Pending,
            };
            // An accepted route's reason says only that it was accepted, which the state
            // already says; every other case is one the console has to explain.
            let unexplained = accepted_condition.filter(|_| acceptance != Acceptance::Accepted);
            DeclaredRoute {
                id: format!("{}/{}", item.metadata.namespace, item.metadata.name),
                namespace: item.metadata.namespace,
                acceptance,
                reason: unexplained.and_then(|c| c.reason.clone()),
                message: unexplained.and_then(|c| c.message.clone()),
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIST: &str = include_str!("../tests/fixtures/httproutes.json");

    #[test]
    fn every_route_in_the_list_is_read() {
        let got = routes_from_list(LIST).unwrap();
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].id, "apps/checkout");
        assert_eq!(got[2].namespace, "shop");
    }

    #[test]
    fn a_refused_route_carries_the_reason_it_was_refused() {
        let got = routes_from_list(LIST).unwrap();
        let billing = got.iter().find(|r| r.id == "apps/billing").unwrap();
        assert_eq!(billing.acceptance, Acceptance::Refused);
        assert_eq!(billing.reason.as_deref(), Some("UnsupportedValue"));
        assert_eq!(
            billing.message.as_deref(),
            Some("filter type ExtensionRef is not supported")
        );
    }

    #[test]
    fn an_accepted_route_carries_no_reason() {
        let got = routes_from_list(LIST).unwrap();
        let checkout = got.iter().find(|r| r.id == "apps/checkout").unwrap();
        assert_eq!(checkout.acceptance, Acceptance::Accepted);
        assert_eq!(checkout.reason, None);
    }

    #[test]
    fn a_route_with_no_status_yet_is_pending_not_refused() {
        // A resource the controller has not reached. Unknown is not the same as refused,
        // and the console must be able to tell them apart.
        let got =
            routes_from_list(r#"{"items":[{"metadata":{"name":"fresh","namespace":"apps"}}]}"#)
                .unwrap();
        assert_eq!(got[0].acceptance, Acceptance::Pending);
        assert_eq!(got[0].reason, None);
    }

    #[test]
    fn a_condition_still_reading_unknown_is_pending_and_keeps_what_it_said() {
        // The controller has started on this one but has not concluded; whatever it said
        // while undecided is the only thing the console can show.
        let got = routes_from_list(
            r#"{"items":[{"metadata":{"name":"slow","namespace":"apps"},
                "status":{"parents":[{"conditions":[
                  {"type":"Accepted","status":"Unknown","reason":"Pending",
                   "message":"waiting for the backend to resolve"}]}]}}]}"#,
        )
        .unwrap();
        assert_eq!(got[0].acceptance, Acceptance::Pending);
        assert_eq!(got[0].reason.as_deref(), Some("Pending"));
    }
}
