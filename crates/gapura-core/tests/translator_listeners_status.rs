//! Translation regressions for listener isolation (#218), backendRef filters (#219),
//! Gateway spec.addresses (#220) and withdrawing our HTTPRoute status (#214). Inline YAML and
//! explicit assertions; the whole-Translation snapshots live in golden.rs.

use gapura_core::matcher::compile_regexes;
use gapura_core::status::{Condition, ConditionStatus, RouteParentStatus, StatusPatch};
use gapura_core::{translate, RequestAttrs, Settings, Snapshot, Translation};

const CLASS: &str = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata: { name: gapura }
spec: { controllerName: gapura.dev/controller }
"#;

fn settings() -> Settings {
    Settings {
        gateway_addresses: vec!["10.0.0.1".to_string()],
        ..Settings::default()
    }
}

fn run(yaml: &str) -> Translation {
    let snap = Snapshot::from_yaml_docs(&format!("{CLASS}---\n{yaml}")).unwrap();
    translate(&snap, &settings())
}

fn route_parents<'a>(t: &'a Translation, ns: &str, name: &str) -> &'a [RouteParentStatus] {
    t.status
        .iter()
        .find_map(|p| match p {
            StatusPatch::HttpRoute {
                namespace,
                name: n,
                parents,
                ..
            } if namespace == ns && n == name => Some(parents.as_slice()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no status patch for HTTPRoute {ns}/{name}"))
}

fn cond<'a>(conds: &'a [Condition], type_: &str) -> &'a Condition {
    conds
        .iter()
        .find(|c| c.type_ == type_)
        .unwrap_or_else(|| panic!("no {type_} in {conds:?}"))
}

/// The route (namespace/name) serving `GET host path` on port 80, if any.
fn served_by(t: &Translation, host: &str, path: &str) -> Option<String> {
    let (regexes, _) = compile_regexes(&t.config);
    let req = RequestAttrs {
        host,
        path,
        method: "GET",
        headers: &[],
        query: &[],
    };
    t.config
        .match_port_with(80, &req, &regexes)
        .map(|m| m.rule.route.clone())
}

fn attached(t: &Translation, listener: &str) -> u32 {
    t.status
        .iter()
        .find_map(|p| match p {
            StatusPatch::Gateway { listeners, .. } => listeners.iter().find(|l| l.name == listener),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no listener {listener}"))
        .attached_routes
}

// ---------- #218 ----------

/// The issue's Gateway: `admin` (exact, default allowedRoutes: Same) and `apps` (wildcard,
/// from: All) share port 80. `infra/admin` owns admin.example.com.
const ISOLATION: &str = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: { name: gw, namespace: infra }
spec:
  gatewayClassName: gapura
  listeners:
  - { name: admin, hostname: admin.example.com, port: 80, protocol: HTTP }
  - { name: apps, hostname: "*.example.com", port: 80, protocol: HTTP, allowedRoutes: { namespaces: { from: All } } }
---
apiVersion: v1
kind: Service
metadata: { name: admin, namespace: infra }
spec: { ports: [{ name: http, port: 80 }] }
---
apiVersion: v1
kind: Service
metadata: { name: evil, namespace: tenant }
spec: { ports: [{ name: http, port: 80 }] }
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: admin, namespace: infra }
spec:
  parentRefs: [{ name: gw, sectionName: admin }]
  rules:
  - matches: [{ path: { type: PathPrefix, value: / } }]
    backendRefs: [{ name: admin, port: 80 }]
"#;

fn evil(hostnames: &str) -> String {
    format!(
        "{ISOLATION}---\napiVersion: gateway.networking.k8s.io/v1\nkind: HTTPRoute\n\
         metadata: {{ name: evil, namespace: tenant }}\n\
         spec:\n  parentRefs: [{{ name: gw, namespace: infra, sectionName: apps }}]\n  \
         hostnames: {hostnames}\n  rules:\n  \
         - matches: [{{ path: {{ type: PathPrefix, value: /login }} }}]\n    \
         backendRefs: [{{ name: evil, port: 80 }}]\n"
    )
}

#[test]
fn a_wildcard_listener_route_cannot_take_over_an_exact_sibling_host() {
    let t = run(&evil("[admin.example.com]"));
    assert_eq!(
        served_by(&t, "admin.example.com", "/login").as_deref(),
        Some("infra/admin"),
        "admin.example.com belongs to the admin listener and its routes only"
    );
    let parents = route_parents(&t, "tenant", "evil");
    let accepted = cond(&parents[0].conditions, "Accepted");
    assert_eq!(accepted.status, ConditionStatus::False);
    assert_eq!(accepted.reason, "NoMatchingListenerHostname");
    assert!(
        accepted.message.contains("more specific listener"),
        "{}",
        accepted.message
    );
    assert_eq!(attached(&t, "apps"), 0, "the route did not attach to apps");
    assert_eq!(attached(&t, "admin"), 1);
}

#[test]
fn a_route_keeps_the_hostnames_no_sibling_claims() {
    let t = run(&evil("[admin.example.com, shop.example.com]"));
    assert_eq!(
        served_by(&t, "admin.example.com", "/login").as_deref(),
        Some("infra/admin")
    );
    assert_eq!(
        served_by(&t, "shop.example.com", "/login").as_deref(),
        Some("tenant/evil"),
        "the unclaimed hostname still attaches"
    );
    let parents = route_parents(&t, "tenant", "evil");
    assert_eq!(
        cond(&parents[0].conditions, "Accepted").status,
        ConditionStatus::True
    );
    assert_eq!(attached(&t, "apps"), 1);
}

#[test]
fn a_wildcard_route_hostname_covered_by_a_narrower_sibling_wildcard_is_dropped() {
    // A listener without hostname next to `*.example.com`: a route naming `*.a.example.com`
    // (narrower) or `*.example.com` (equal) on the catch-all belongs to the wildcard sibling.
    let yaml = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: { name: gw, namespace: infra }
spec:
  gatewayClassName: gapura
  listeners:
  - { name: any, port: 80, protocol: HTTP, allowedRoutes: { namespaces: { from: All } } }
  - { name: wild, hostname: "*.example.com", port: 80, protocol: HTTP }
---
apiVersion: v1
kind: Service
metadata: { name: echo, namespace: tenant }
spec: { ports: [{ name: http, port: 80 }] }
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: r, namespace: tenant }
spec:
  parentRefs: [{ name: gw, namespace: infra, sectionName: any }]
  hostnames: ["*.a.example.com", "*.example.com", other.org]
  rules:
  - backendRefs: [{ name: echo, port: 80 }]
"#;
    let t = run(yaml);
    assert_eq!(
        served_by(&t, "x.a.example.com", "/"),
        None,
        "both wildcards belong to the wild listener"
    );
    assert_eq!(served_by(&t, "b.example.com", "/"), None);
    assert_eq!(served_by(&t, "other.org", "/").as_deref(), Some("tenant/r"));
    let hosts: Vec<Option<&str>> = t.config.ports[&80]
        .iter()
        .map(|e| e.hostname.as_deref())
        .collect();
    assert_eq!(hosts, vec![Some("other.org")]);
}

#[test]
fn a_route_attached_to_both_listeners_serves_the_exact_host_from_the_exact_listener() {
    // No sectionName: the route attaches to both, and only the exact listener carries it for
    // admin.example.com. Nothing changes for the traffic, only which listener holds the entry.
    let yaml = format!(
        "{ISOLATION}---\napiVersion: gateway.networking.k8s.io/v1\nkind: HTTPRoute\n\
         metadata: {{ name: both, namespace: infra }}\n\
         spec:\n  parentRefs: [{{ name: gw }}]\n  hostnames: [admin.example.com]\n  rules:\n  \
         - matches: [{{ path: {{ type: PathPrefix, value: /both }} }}]\n    \
         backendRefs: [{{ name: admin, port: 80 }}]\n"
    );
    let t = run(&yaml);
    assert_eq!(
        served_by(&t, "admin.example.com", "/both").as_deref(),
        Some("infra/both")
    );
    let parents = route_parents(&t, "infra", "both");
    assert_eq!(
        cond(&parents[0].conditions, "Accepted").status,
        ConditionStatus::True
    );
    assert_eq!(attached(&t, "admin"), 2);
    assert_eq!(attached(&t, "apps"), 0);
}

// ---------- #219 ----------

#[test]
fn backend_ref_filters_make_the_route_unsupported() {
    let yaml = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: { name: gw, namespace: apps }
spec:
  gatewayClassName: gapura
  listeners: [{ name: http, port: 80, protocol: HTTP }]
---
apiVersion: v1
kind: Service
metadata: { name: canary, namespace: apps }
spec: { ports: [{ name: http, port: 80 }] }
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: r, namespace: apps }
spec:
  parentRefs: [{ name: gw }]
  rules:
  - backendRefs:
    - name: canary
      port: 80
      filters:
      - type: RequestHeaderModifier
        requestHeaderModifier: { remove: [Authorization] }
"#;
    let t = run(yaml);
    let accepted = cond(&route_parents(&t, "apps", "r")[0].conditions, "Accepted").clone();
    assert_eq!(accepted.status, ConditionStatus::False);
    assert_eq!(accepted.reason, "UnsupportedValue");
    assert!(
        accepted.message.contains("backendRefs[].filters"),
        "{}",
        accepted.message
    );
    assert_eq!(
        served_by(&t, "any.host", "/"),
        None,
        "the route is not served"
    );
}

// ---------- #220 ----------

fn gateway_with_addresses(addresses: &str) -> Translation {
    run(&format!(
        "apiVersion: gateway.networking.k8s.io/v1\nkind: Gateway\n\
         metadata: {{ name: gw, namespace: infra }}\n\
         spec:\n  gatewayClassName: gapura\n  addresses: {addresses}\n  \
         listeners: [{{ name: http, port: 80, protocol: HTTP }}]\n"
    ))
}

fn gateway_conditions(t: &Translation) -> &[Condition] {
    t.status
        .iter()
        .find_map(|p| match p {
            StatusPatch::Gateway { conditions, .. } => Some(conditions.as_slice()),
            _ => None,
        })
        .expect("a Gateway patch")
}

#[test]
fn an_unassigned_static_address_is_not_programmed() {
    let t = gateway_with_addresses("[{ type: IPAddress, value: 10.0.0.5 }]");
    let conds = gateway_conditions(&t);
    assert_eq!(cond(conds, "Accepted").status, ConditionStatus::True);
    let programmed = cond(conds, "Programmed");
    assert_eq!(programmed.status, ConditionStatus::False);
    assert_eq!(programmed.reason, "AddressNotAssigned");
    assert!(
        programmed.message.contains("10.0.0.5"),
        "{}",
        programmed.message
    );
}

#[test]
fn a_requested_address_that_is_published_is_programmed() {
    // `type` defaults to IPAddress.
    let t = gateway_with_addresses("[{ value: 10.0.0.1 }]");
    let programmed = cond(gateway_conditions(&t), "Programmed");
    assert_eq!(programmed.status, ConditionStatus::True);
    assert_eq!(programmed.reason, "Programmed");
}

#[test]
fn an_unsupported_address_type_rejects_the_gateway() {
    let t = gateway_with_addresses("[{ type: example.com/Named, value: pool-a }]");
    let accepted = cond(gateway_conditions(&t), "Accepted");
    assert_eq!(accepted.status, ConditionStatus::False);
    assert_eq!(accepted.reason, "UnsupportedAddress");
    assert!(
        t.config.listeners.is_empty(),
        "a refused Gateway serves nothing"
    );
}

// ---------- #214 ----------

#[test]
fn a_route_that_left_our_gateway_gets_an_empty_patch_withdrawing_our_entries() {
    let yaml = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: moved, namespace: apps, uid: u1 }
spec:
  parentRefs: [{ name: other-gw }]
status:
  parents:
  - { controllerName: gapura.dev/controller }
  - { controllerName: example.com/other }
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: never-ours, namespace: apps }
spec:
  parentRefs: [{ name: other-gw }]
status:
  parents:
  - { controllerName: example.com/other }
"#;
    let t = run(yaml);
    let routes: Vec<&StatusPatch> = t
        .status
        .iter()
        .filter(|p| matches!(p, StatusPatch::HttpRoute { .. }))
        .collect();
    assert_eq!(
        routes,
        vec![&StatusPatch::HttpRoute {
            namespace: "apps".into(),
            name: "moved".into(),
            uid: Some("u1".into()),
            parents: vec![],
        }],
        "only the route still holding our entries is patched, and with no parents of ours"
    );
}
