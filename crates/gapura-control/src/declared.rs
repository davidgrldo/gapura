//! What was declared, and what the gateway said about it.

use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredRoute {
    /// `namespace/name`.
    pub id: String,
    pub namespace: String,
    pub accepted: bool,
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
            let accepted = accepted_condition.is_some_and(|c| c.status == "True");
            DeclaredRoute {
                id: format!("{}/{}", item.metadata.namespace, item.metadata.name),
                namespace: item.metadata.namespace,
                accepted,
                reason: accepted_condition
                    .filter(|_| !accepted)
                    .and_then(|c| c.reason.clone()),
                message: accepted_condition
                    .filter(|_| !accepted)
                    .and_then(|c| c.message.clone()),
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
        assert!(!billing.accepted);
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
        assert!(checkout.accepted);
        assert_eq!(checkout.reason, None);
    }

    #[test]
    fn a_route_with_no_status_yet_is_not_accepted_and_says_nothing() {
        // A resource the controller has not reached. Unknown is not the same as refused,
        // and the console must be able to tell them apart later.
        let got =
            routes_from_list(r#"{"items":[{"metadata":{"name":"fresh","namespace":"apps"}}]}"#)
                .unwrap();
        assert!(!got[0].accepted);
        assert_eq!(got[0].reason, None);
    }
}
