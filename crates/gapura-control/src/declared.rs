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

/// One attachment of a route to one of our Gateways, and that Gateway's verdict on it. A
/// route may attach to several, and they answer independently: one Gateway accepting a
/// route says nothing about whether another did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredParent {
    /// `namespace/name` of the Gateway. A `parentRef` with no namespace means the route's own.
    pub gateway: String,
    /// The listener named by `sectionName`, when the route named one.
    pub section: Option<String>,
    pub acceptance: Acceptance,
    /// Why, when this Gateway did not accept it.
    pub reason: Option<String>,
    pub message: Option<String>,
    /// The `ResolvedRefs` condition: false when a reference the route names did not
    /// resolve. It is a separate fact from acceptance, not a milder form of it — gapura
    /// accepts such a route and installs its rules, which then answer with an error — so
    /// it carries its own reason and message rather than sharing the acceptance's.
    pub refs_resolved: bool,
    pub refs_reason: Option<String>,
    pub refs_message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredRoute {
    /// `namespace/name`.
    pub id: String,
    pub namespace: String,
    /// Only the attachments to Gateways this controller runs; empty when it runs none of
    /// them, because then there is no verdict of ours to report.
    pub parents: Vec<DeclaredParent>,
}

/// The next page's token, when a list response says there is one. Kubernetes paginates list
/// responses; a `continue` token means the list was cut short and the rest follows on request
/// carrying it. Empty string counts as none.
pub fn continue_token(json: &str) -> anyhow::Result<Option<String>> {
    #[derive(Deserialize)]
    struct List {
        #[serde(default)]
        metadata: Metadata,
    }
    #[derive(Deserialize, Default)]
    struct Metadata {
        #[serde(rename = "continue", default)]
        continue_: String,
    }
    let parsed: List = serde_json::from_str(json)?;
    let token = parsed.metadata.continue_;
    Ok(if token.is_empty() { None } else { Some(token) })
}

/// Parse a Kubernetes list response into the fields the console shows. `controller` is the
/// GatewayClass controllerName whose verdict to read: a route may be attached to several
/// controllers, and only the one we are the console for can say why *we* are not serving it.
pub fn routes_from_list(json: &str, controller: &str) -> anyhow::Result<Vec<DeclaredRoute>> {
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
        // Required by the Gateway API on every status entry, and deliberately not optional
        // here: a verdict that names no Gateway cannot be attributed to one, and inventing
        // the attachment would be exactly the guess this crate exists to avoid.
        #[serde(rename = "parentRef")]
        parent_ref: ParentRef,
        #[serde(rename = "controllerName")]
        controller_name: Option<String>,
        #[serde(default)]
        conditions: Vec<Condition>,
    }
    #[derive(Deserialize)]
    struct ParentRef {
        name: String,
        namespace: Option<String>,
        #[serde(rename = "sectionName")]
        section_name: Option<String>,
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
            let namespace = item.metadata.namespace;
            let parents = item
                .status
                .iter()
                .flat_map(|s| s.parents.iter())
                .filter(|p| p.controller_name.as_deref() == Some(controller))
                .map(|p| {
                    let accepted_condition = p.conditions.iter().find(|c| c.kind == "Accepted");
                    let acceptance = match accepted_condition.map(|c| c.status.as_str()) {
                        Some("True") => Acceptance::Accepted,
                        Some("False") => Acceptance::Refused,
                        // `Unknown`, an absent condition, or a status this version does not
                        // know: none of them is a verdict, so none may be read as one.
                        _ => Acceptance::Pending,
                    };
                    // An accepted route's reason says only that it was accepted, which the
                    // state already says; every other case is one the console has to explain.
                    let unexplained =
                        accepted_condition.filter(|_| acceptance != Acceptance::Accepted);
                    // Only an explicit `False` is the gateway reporting that a reference did
                    // not resolve. An absent condition is an implementation that writes
                    // fewer of them, and `Unknown` is one that has not finished looking:
                    // neither is a complaint, and reading a complaint into silence would
                    // flag healthy routes as broken.
                    let failed_refs = p
                        .conditions
                        .iter()
                        .find(|c| c.kind == "ResolvedRefs" && c.status == "False");
                    DeclaredParent {
                        // Gateway API omits the namespace when the Gateway sits beside the
                        // route, so the route's own is the only thing it can mean.
                        gateway: format!(
                            "{}/{}",
                            p.parent_ref.namespace.as_deref().unwrap_or(&namespace),
                            p.parent_ref.name
                        ),
                        section: p.parent_ref.section_name.clone(),
                        acceptance,
                        reason: unexplained.and_then(|c| c.reason.clone()),
                        message: unexplained.and_then(|c| c.message.clone()),
                        refs_resolved: failed_refs.is_none(),
                        refs_reason: failed_refs.and_then(|c| c.reason.clone()),
                        refs_message: failed_refs.and_then(|c| c.message.clone()),
                    }
                })
                .collect();
            DeclaredRoute {
                id: format!("{}/{}", namespace, item.metadata.name),
                namespace,
                parents,
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIST: &str = include_str!("../tests/fixtures/httproutes.json");
    /// The default of gapura's own `--controller-name` flag.
    const CONTROLLER: &str = "gapura.dev/controller";

    /// The one parent a route in the fixture has, for the routes that have exactly one.
    fn only_parent(routes: &[DeclaredRoute], id: &str) -> DeclaredParent {
        let route = routes
            .iter()
            .find(|r| r.id == id)
            .expect("a route in the fixture");
        assert_eq!(
            route.parents.len(),
            1,
            "{id} was expected to have one parent"
        );
        route.parents[0].clone()
    }

    #[test]
    fn every_route_in_the_list_is_read() {
        let got = routes_from_list(LIST, CONTROLLER).unwrap();
        assert_eq!(got.len(), 6);
        assert_eq!(got[0].id, "apps/checkout");
        assert_eq!(got[2].namespace, "shop");
    }

    #[test]
    fn a_refused_route_carries_the_reason_it_was_refused() {
        let got = routes_from_list(LIST, CONTROLLER).unwrap();
        let billing = only_parent(&got, "apps/billing");
        assert_eq!(billing.acceptance, Acceptance::Refused);
        assert_eq!(billing.reason.as_deref(), Some("UnsupportedValue"));
        assert_eq!(
            billing.message.as_deref(),
            Some("filter type ExtensionRef is not supported")
        );
    }

    #[test]
    fn an_accepted_route_carries_no_reason() {
        let got = routes_from_list(LIST, CONTROLLER).unwrap();
        let checkout = only_parent(&got, "apps/checkout");
        assert_eq!(checkout.acceptance, Acceptance::Accepted);
        assert_eq!(checkout.reason, None);
    }

    #[test]
    fn a_route_with_no_status_yet_declares_no_parent_at_all() {
        // A resource the controller has not reached. Nothing has claimed it, so there is no
        // attachment to report a verdict against — which the summary reads as pending,
        // never as a refusal.
        let got = routes_from_list(
            r#"{"items":[{"metadata":{"name":"fresh","namespace":"apps"}}]}"#,
            CONTROLLER,
        )
        .unwrap();
        assert!(got[0].parents.is_empty());
    }

    #[test]
    fn a_condition_still_reading_unknown_is_pending_and_keeps_what_it_said() {
        // The controller has started on this one but has not concluded; whatever it said
        // while undecided is the only thing the console can show.
        let got = routes_from_list(
            r#"{"items":[{"metadata":{"name":"slow","namespace":"apps"},
                "status":{"parents":[{"parentRef":{"name":"main","namespace":"infra"},
                  "controllerName":"gapura.dev/controller","conditions":[
                  {"type":"Accepted","status":"Unknown","reason":"Pending",
                   "message":"waiting for the backend to resolve"}]}]}}]}"#,
            CONTROLLER,
        )
        .unwrap();
        let slow = only_parent(&got, "apps/slow");
        assert_eq!(slow.acceptance, Acceptance::Pending);
        assert_eq!(slow.reason.as_deref(), Some("Pending"));
    }

    #[test]
    fn another_controllers_verdict_is_not_read_as_this_ones() {
        // A route attached to both ingress-nginx and gapura. nginx accepted it and gapura
        // refused it; reporting nginx's yes would draw the route as accepted-but-absent and
        // hide the refusal that actually explains why gapura is not serving it.
        let got = routes_from_list(LIST, CONTROLLER).unwrap();
        let storefront = only_parent(&got, "shop/storefront");
        assert_eq!(storefront.acceptance, Acceptance::Refused);
        assert_eq!(storefront.reason.as_deref(), Some("UnsupportedValue"));
        assert_eq!(storefront.gateway, "infra/main");
    }

    #[test]
    fn a_route_no_parent_attributes_to_this_controller_declares_no_parent() {
        // gapura has not claimed this route, so it has no verdict to report on it. Reading
        // the other controller's yes would promise the console can explain a route it is
        // not even responsible for.
        let got = routes_from_list(
            r#"{"items":[{"metadata":{"name":"theirs","namespace":"apps"},
                "status":{"parents":[{"parentRef":{"name":"edge","namespace":"infra"},
                  "controllerName":"k8s.io/ingress-nginx","conditions":[
                  {"type":"Accepted","status":"True","reason":"Accepted","message":"ok"}]}]}}]}"#,
            CONTROLLER,
        )
        .unwrap();
        assert!(got[0].parents.is_empty());
    }

    #[test]
    fn a_route_on_two_gateways_keeps_a_verdict_for_each_of_them() {
        // The case the per-parent shape exists for: one Gateway took the route and another
        // refused it, for a cause that is only true of that Gateway. Either verdict alone
        // is a lie about the other.
        let got = routes_from_list(LIST, CONTROLLER).unwrap();
        let search = got.iter().find(|r| r.id == "apps/search").unwrap();
        assert_eq!(search.parents.len(), 2);
        assert_eq!(search.parents[0].gateway, "infra/main");
        assert_eq!(search.parents[0].acceptance, Acceptance::Accepted);
        assert_eq!(search.parents[1].gateway, "infra/second");
        assert_eq!(search.parents[1].acceptance, Acceptance::Refused);
        assert_eq!(
            search.parents[1].reason.as_deref(),
            Some("NoMatchingListenerHostname")
        );
    }

    #[test]
    fn the_listener_a_route_named_is_kept() {
        // A route may attach to one named listener of a Gateway rather than to the whole
        // Gateway, and then only that listener can serve it.
        let got = routes_from_list(LIST, CONTROLLER).unwrap();
        assert_eq!(
            only_parent(&got, "shop/catalog").section.as_deref(),
            Some("http")
        );
        assert_eq!(only_parent(&got, "apps/checkout").section, None);
    }

    #[test]
    fn a_parent_ref_with_no_namespace_means_the_routes_own() {
        // Gateway API leaves `parentRef.namespace` out when the Gateway sits beside the
        // route; resolving it to anything else would name a Gateway that does not exist.
        let got = routes_from_list(
            r#"{"items":[{"metadata":{"name":"local","namespace":"apps"},
                "status":{"parents":[{"parentRef":{"name":"main"},
                  "controllerName":"gapura.dev/controller","conditions":[
                  {"type":"Accepted","status":"True","reason":"Accepted","message":"ok"}]}]}}]}"#,
            CONTROLLER,
        )
        .unwrap();
        assert_eq!(only_parent(&got, "apps/local").gateway, "apps/main");
    }

    #[test]
    fn a_route_whose_refs_did_not_resolve_says_so_with_its_own_reason() {
        // The commonest way a route fails, and the condition it is reported on. `Accepted`
        // is still True — gapura installs the rule regardless — so nothing in the
        // acceptance explains it, and the two conditions have to be kept apart.
        let got = routes_from_list(LIST, CONTROLLER).unwrap();
        let payments = only_parent(&got, "apps/payments");
        assert_eq!(payments.acceptance, Acceptance::Accepted);
        assert!(!payments.refs_resolved);
        assert_eq!(payments.refs_reason.as_deref(), Some("BackendNotFound"));
        assert_eq!(
            payments.refs_message.as_deref(),
            Some("backendRef apps/ledger not found")
        );
        assert_eq!(
            payments.reason, None,
            "the acceptance explains nothing here and must not borrow the refs' words"
        );
    }

    #[test]
    fn a_route_whose_refs_resolved_carries_no_refs_reason() {
        // `ResolvedRefs=True` says only that references resolved, which `refs_resolved`
        // already says; repeating it as a reason would put a sentence on screen beside a
        // route that has nothing wrong with it.
        let got = routes_from_list(LIST, CONTROLLER).unwrap();
        let checkout = only_parent(&got, "apps/checkout");
        assert!(checkout.refs_resolved);
        assert_eq!(checkout.refs_reason, None);
        assert_eq!(checkout.refs_message, None);
    }

    #[test]
    fn a_route_with_no_resolved_refs_condition_is_read_as_resolved() {
        // Absence of a complaint is not a complaint. This fixture route carries only
        // `Accepted`, as an implementation that writes fewer conditions would leave it.
        let got = routes_from_list(LIST, CONTROLLER).unwrap();
        assert!(only_parent(&got, "shop/catalog").refs_resolved);
    }

    #[test]
    fn resolved_refs_still_reading_unknown_is_read_as_resolved() {
        // Only an explicit `False` is the gateway reporting that a reference did not
        // resolve. `Unknown` is it still looking, and folding the two together would call
        // every route broken for as long as its reconcile takes.
        let got = routes_from_list(
            r#"{"items":[{"metadata":{"name":"slow","namespace":"apps"},
                "status":{"parents":[{"parentRef":{"name":"main","namespace":"infra"},
                  "controllerName":"gapura.dev/controller","conditions":[
                  {"type":"Accepted","status":"True","reason":"Accepted","message":"ok"},
                  {"type":"ResolvedRefs","status":"Unknown","reason":"Pending",
                   "message":"still resolving"}]}]}}]}"#,
            CONTROLLER,
        )
        .unwrap();
        let slow = only_parent(&got, "apps/slow");
        assert!(slow.refs_resolved);
        assert_eq!(slow.refs_reason, None);
    }
}
