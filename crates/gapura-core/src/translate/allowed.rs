//! allowedRoutes evaluation: which namespaces and route kinds a listener admits.

use std::collections::BTreeMap;

use crate::input::{AllowedRoutes, LabelSelector};
use crate::snapshot::{ObjectRef, Snapshot};

/// `from: Same` (default) | `All` | `Selector` (label selector over the route's Namespace object).
pub(crate) fn namespace_ok(
    allowed: Option<&AllowedRoutes>,
    gateway_namespace: &str,
    route: &ObjectRef,
    snap: &Snapshot,
) -> bool {
    let namespaces = allowed.and_then(|a| a.namespaces.as_ref());
    match namespaces.and_then(|n| n.from.as_deref()).unwrap_or("Same") {
        "All" => true,
        "Same" => route.namespace == gateway_namespace,
        "Selector" => {
            let Some(selector) = namespaces.and_then(|n| n.selector.as_ref()) else {
                return false;
            };
            let Some(ns) = snap.namespaces.get(&route.namespace) else {
                return false;
            };
            selector_matches(selector, &ns.metadata.labels)
        }
        _ => false,
    }
}

/// HTTPRoute is admitted unless `kinds` is set and does not list it.
pub(crate) fn kind_ok(allowed: Option<&AllowedRoutes>) -> bool {
    match allowed.map(|a| a.kinds.as_slice()) {
        None | Some([]) => true,
        Some(kinds) => kinds.iter().any(|k| {
            k.kind == "HTTPRoute"
                && k.group
                    .as_deref()
                    .is_none_or(|g| g == "gateway.networking.k8s.io")
        }),
    }
}

fn selector_matches(sel: &LabelSelector, labels: &BTreeMap<String, String>) -> bool {
    if !sel
        .match_labels
        .iter()
        .all(|(k, v)| labels.get(k) == Some(v))
    {
        return false;
    }
    sel.match_expressions
        .iter()
        .all(|e| match e.operator.as_str() {
            "In" => labels.get(&e.key).is_some_and(|v| e.values.contains(v)),
            "NotIn" => labels.get(&e.key).is_none_or(|v| !e.values.contains(v)),
            "Exists" => labels.contains_key(&e.key),
            "DoesNotExist" => !labels.contains_key(&e.key),
            _ => false,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::{LabelSelectorRequirement, RouteGroupKind, RouteNamespaces};

    fn snap() -> Snapshot {
        Snapshot::from_yaml_docs(
            "apiVersion: v1\nkind: Namespace\nmetadata: { name: apps, labels: { team: platform, tier: web } }\n",
        )
        .unwrap()
    }

    fn allowed(from: &str, selector: Option<LabelSelector>) -> AllowedRoutes {
        AllowedRoutes {
            namespaces: Some(RouteNamespaces {
                from: Some(from.into()),
                selector,
            }),
            kinds: vec![],
        }
    }

    #[test]
    fn same_all_and_selector() {
        let s = snap();
        let apps = ObjectRef::new("apps", "r");
        let other = ObjectRef::new("other", "r");
        assert!(namespace_ok(None, "apps", &apps, &s));
        assert!(!namespace_ok(None, "infra", &apps, &s));
        assert!(namespace_ok(
            Some(&allowed("All", None)),
            "infra",
            &other,
            &s
        ));
        let sel = LabelSelector {
            match_labels: BTreeMap::from([("team".to_string(), "platform".to_string())]),
            match_expressions: vec![],
        };
        assert!(namespace_ok(
            Some(&allowed("Selector", Some(sel.clone()))),
            "infra",
            &apps,
            &s
        ));
        assert!(!namespace_ok(
            Some(&allowed("Selector", Some(sel))),
            "infra",
            &other,
            &s
        ));
        let expr = LabelSelector {
            match_labels: BTreeMap::new(),
            match_expressions: vec![LabelSelectorRequirement {
                key: "tier".into(),
                operator: "In".into(),
                values: vec!["web".into()],
            }],
        };
        assert!(namespace_ok(
            Some(&allowed("Selector", Some(expr))),
            "infra",
            &apps,
            &s
        ));
    }

    #[test]
    fn kinds() {
        assert!(kind_ok(None));
        let http = AllowedRoutes {
            namespaces: None,
            kinds: vec![RouteGroupKind {
                group: None,
                kind: "HTTPRoute".into(),
            }],
        };
        assert!(kind_ok(Some(&http)));
        let tcp = AllowedRoutes {
            namespaces: None,
            kinds: vec![RouteGroupKind {
                group: None,
                kind: "TCPRoute".into(),
            }],
        };
        assert!(!kind_ok(Some(&tcp)));
    }
}
