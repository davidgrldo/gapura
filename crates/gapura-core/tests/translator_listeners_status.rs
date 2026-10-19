//! Translation regressions for listener isolation (#218, across Gateways #248, only towards
//! programmed listeners #249), backendRef filters (#219), Gateway spec.addresses (#220),
//! withdrawing our HTTPRoute status (#214), route paths in the data plane's normal form
//! (#250) and route paths with `;` path parameters (#247). Inline YAML and explicit assertions; the whole-Translation snapshots live in
//! golden.rs.

use gapura_core::matcher::compile_regexes;
use gapura_core::path::normalize_path;
use gapura_core::status::{
    Condition, ConditionStatus, ListenerStatus, RouteParentStatus, StatusPatch,
};
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
    run_with(yaml, &settings())
}

fn run_with(yaml: &str, settings: &Settings) -> Translation {
    let snap = Snapshot::from_yaml_docs(&format!("{CLASS}---\n{yaml}")).unwrap();
    translate(&snap, settings)
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
    served_on(t, 80, host, path)
}

/// The route serving `GET host path` on `port`. The path goes through the data plane's own
/// normaliser first, as every request's does.
fn served_on(t: &Translation, port: u16, host: &str, path: &str) -> Option<String> {
    let (regexes, _) = compile_regexes(&t.config);
    let path = normalize_path(path).expect("a path the data plane accepts");
    let req = RequestAttrs {
        host,
        path: &path,
        method: "GET",
        headers: &[],
        query: &[],
    };
    t.config
        .match_port_with(port, &req, &regexes)
        .map(|m| m.rule.route.clone())
}

fn attached(t: &Translation, listener: &str) -> u32 {
    listener_status(t, None, listener).attached_routes
}

/// A listener's status, in the named Gateway or in the first one that has a listener so named.
fn listener_status<'a>(
    t: &'a Translation,
    gateway: Option<&str>,
    listener: &str,
) -> &'a ListenerStatus {
    t.status
        .iter()
        .find_map(|p| match p {
            StatusPatch::Gateway {
                name, listeners, ..
            } if gateway.is_none_or(|g| g == name) => listeners.iter().find(|l| l.name == listener),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no listener {listener} in {gateway:?}"))
}

/// The route's Accepted condition on its first parent.
fn accepted<'a>(t: &'a Translation, ns: &str, name: &str) -> &'a Condition {
    cond(&route_parents(t, ns, name)[0].conditions, "Accepted")
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

// ---------- #248 ----------

/// The issue's two Gateways on port 80: `admin-gw` owns admin.example.com (default
/// allowedRoutes: Same), `shared` takes `*.example.com` from every namespace, and `tenant/evil`
/// on `shared` names admin.example.com.
const TWO_GATEWAYS: &str = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: { name: admin-gw, namespace: infra }
spec:
  gatewayClassName: gapura
  listeners:
  - { name: admin, hostname: admin.example.com, port: 80, protocol: HTTP }
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: { name: shared, namespace: infra }
spec:
  gatewayClassName: gapura
  listeners:
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
  parentRefs: [{ name: admin-gw }]
  rules:
  - matches: [{ path: { type: PathPrefix, value: / } }]
    backendRefs: [{ name: admin, port: 80 }]
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: evil, namespace: tenant }
spec:
  parentRefs: [{ name: shared, namespace: infra }]
  hostnames: [admin.example.com]
  rules:
  - matches: [{ path: { type: PathPrefix, value: /login } }]
    backendRefs: [{ name: evil, port: 80 }]
"#;

#[test]
fn a_route_on_another_gateway_sharing_the_port_cannot_take_over_an_exact_listener_host() {
    let t = run(TWO_GATEWAYS);
    assert_eq!(
        served_by(&t, "admin.example.com", "/login").as_deref(),
        Some("infra/admin"),
        "admin.example.com belongs to admin-gw's listener, whichever Gateway the route names"
    );
    let accepted = accepted(&t, "tenant", "evil");
    assert_eq!(accepted.status, ConditionStatus::False);
    assert_eq!(accepted.reason, "NoMatchingListenerHostname");
    assert!(
        accepted.message.contains("another one sharing the port"),
        "{}",
        accepted.message
    );
    assert_eq!(
        listener_status(&t, Some("shared"), "apps").attached_routes,
        0
    );
    assert_eq!(
        listener_status(&t, Some("admin-gw"), "admin").attached_routes,
        1
    );
}

/// `--gateway-address` for `admin-gw` and the given bound HTTP ports.
fn admin_gw_addressed(http_ports: &[u16]) -> Settings {
    let mut s = Settings {
        http_ports: http_ports.to_vec(),
        ..settings()
    };
    s.gateway_address_overrides
        .insert("infra/admin-gw".to_string(), vec!["10.0.0.2".to_string()]);
    s
}

#[test]
fn a_gateway_moved_to_a_port_of_its_own_claims_nothing_on_the_shared_port() {
    // admin-gw has its own address and a free bound port, so it serves on 10000 and port 80
    // holds `shared` alone: admin.example.com on the shared address is the wildcard's.
    let t = run_with(TWO_GATEWAYS, &admin_gw_addressed(&[80, 10000]));
    assert_eq!(
        served_on(&t, 10000, "admin.example.com", "/login").as_deref(),
        Some("infra/admin")
    );
    assert_eq!(
        served_by(&t, "admin.example.com", "/login").as_deref(),
        Some("tenant/evil"),
        "no listener on port 80 is more specific than *.example.com"
    );
    assert_eq!(accepted(&t, "tenant", "evil").status, ConditionStatus::True);
}

#[test]
fn an_addressed_gateway_left_on_the_shared_port_still_claims_its_host() {
    // One bound port: the override cannot move admin-gw anywhere, so it shares port 80's table
    // with `shared` and keeps its host.
    let t = run_with(TWO_GATEWAYS, &admin_gw_addressed(&[80]));
    assert_eq!(
        served_by(&t, "admin.example.com", "/login").as_deref(),
        Some("infra/admin")
    );
    assert_eq!(
        accepted(&t, "tenant", "evil").status,
        ConditionStatus::False
    );
}

#[test]
fn a_gateway_on_another_port_claims_nothing() {
    let yaml = TWO_GATEWAYS.replacen(
        "{ name: admin, hostname: admin.example.com, port: 80,",
        "{ name: admin, hostname: admin.example.com, port: 8080,",
        1,
    );
    let t = run_with(
        &yaml,
        &Settings {
            http_ports: vec![80, 8080],
            ..settings()
        },
    );
    assert_eq!(
        served_by(&t, "admin.example.com", "/login").as_deref(),
        Some("tenant/evil")
    );
    assert_eq!(
        served_on(&t, 8080, "admin.example.com", "/login").as_deref(),
        Some("infra/admin")
    );
}

// ---------- #249 ----------

/// The #218 Gateway with the `admin` listener replaced, and `tenant/evil` on `apps` naming
/// admin.example.com at PathPrefix `/login`.
fn evil_beside(admin_listener: &str, extra: &str) -> String {
    let isolation = ISOLATION.replacen(
        "  - { name: admin, hostname: admin.example.com, port: 80, protocol: HTTP }\n",
        admin_listener,
        1,
    );
    assert_ne!(isolation, ISOLATION, "the admin listener was replaced");
    format!(
        "{isolation}---\napiVersion: gateway.networking.k8s.io/v1\nkind: HTTPRoute\n\
         metadata: {{ name: evil, namespace: tenant }}\n\
         spec:\n  parentRefs: [{{ name: gw, namespace: infra, sectionName: apps }}]\n  \
         hostnames: [admin.example.com]\n  rules:\n  \
         - matches: [{{ path: {{ type: PathPrefix, value: /login }} }}]\n    \
         backendRefs: [{{ name: evil, port: 80 }}]\n{extra}"
    )
}

fn assert_served_by_the_wildcard(t: &Translation, port: u16) {
    assert_eq!(
        served_on(t, port, "admin.example.com", "/login").as_deref(),
        Some("tenant/evil"),
        "the admin listener serves nothing, so the wildcard listener is the most specific one left"
    );
    let accepted = accepted(t, "tenant", "evil");
    assert_eq!(accepted.status, ConditionStatus::True, "{accepted:?}");
    assert_eq!(attached(t, "apps"), 1);
}

#[test]
fn a_listener_with_invalid_route_kinds_claims_no_hostname() {
    // The issue's reproduction: GRPCRoute only, so Programmed=False/InvalidRouteKinds.
    let t = run(&evil_beside(
        "  - { name: admin, hostname: admin.example.com, port: 80, protocol: HTTP, \
         allowedRoutes: { kinds: [{ kind: GRPCRoute }] } }\n",
        "",
    ));
    let admin = listener_status(&t, None, "admin");
    assert_eq!(
        cond(&admin.conditions, "Programmed").status,
        ConditionStatus::False
    );
    assert_served_by_the_wildcard(&t, 80);
}

#[test]
fn conflicted_listeners_claim_no_hostname() {
    let t = run(&evil_beside(
        "  - { name: admin, hostname: admin.example.com, port: 80, protocol: HTTP }\n  \
         - { name: admin-2, hostname: admin.example.com, port: 80, protocol: HTTP }\n",
        "",
    ));
    let admin = listener_status(&t, None, "admin");
    assert_eq!(
        cond(&admin.conditions, "Conflicted").status,
        ConditionStatus::True
    );
    assert_served_by_the_wildcard(&t, 80);
}

#[test]
fn a_listener_of_a_refused_gateway_claims_no_hostname() {
    // admin-gw is refused as a whole (an unsupported parametersRef), so it serves nothing.
    let yaml = TWO_GATEWAYS.replacen(
        "metadata: { name: admin-gw, namespace: infra }\nspec:\n  gatewayClassName: gapura\n",
        "metadata: { name: admin-gw, namespace: infra }\nspec:\n  gatewayClassName: gapura\n  \
         infrastructure: { parametersRef: { group: example.com, kind: Params, name: p } }\n",
        1,
    );
    assert_ne!(yaml, TWO_GATEWAYS);
    let t = run(&yaml);
    assert_eq!(
        served_by(&t, "admin.example.com", "/login").as_deref(),
        Some("tenant/evil")
    );
    assert_eq!(accepted(&t, "tenant", "evil").status, ConditionStatus::True);
}

/// An HTTPS Gateway on 443: `admin` as given, `apps` on `*.example.com` with a certificate.
fn https_evil_beside(admin_listener: &str) -> String {
    format!(
        r#"
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {{ name: gw, namespace: infra }}
spec:
  gatewayClassName: gapura
  listeners:
{admin_listener}
  - name: apps
    hostname: "*.example.com"
    port: 443
    protocol: HTTPS
    tls: {{ certificateRefs: [{{ name: wildcard }}] }}
    allowedRoutes: {{ namespaces: {{ from: All }} }}
---
apiVersion: v1
kind: Secret
metadata: {{ name: wildcard, namespace: infra }}
type: kubernetes.io/tls
data:
  tls.crt: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJzekNDQVZvQ0NRRGZpeHR1cmUKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=
  tls.key: LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2UUlCQURBTkJnZml4dHVyZQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg==
---
apiVersion: v1
kind: Service
metadata: {{ name: evil, namespace: tenant }}
spec: {{ ports: [{{ name: http, port: 80 }}] }}
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {{ name: evil, namespace: tenant }}
spec:
  parentRefs: [{{ name: gw, namespace: infra, sectionName: apps }}]
  hostnames: [admin.example.com]
  rules:
  - matches: [{{ path: {{ type: PathPrefix, value: /login }} }}]
    backendRefs: [{{ name: evil, port: 80 }}]
"#
    )
}

#[test]
fn an_https_listener_without_its_certificate_claims_no_hostname() {
    let t = run(&https_evil_beside(
        "  - { name: admin, hostname: admin.example.com, port: 443, protocol: HTTPS, \
         tls: { certificateRefs: [{ name: missing }] } }",
    ));
    let admin = listener_status(&t, None, "admin");
    assert_eq!(
        cond(&admin.conditions, "ResolvedRefs").reason,
        "InvalidCertificateRef"
    );
    assert_served_by_the_wildcard(&t, 443);
}

#[test]
fn a_tls_passthrough_listener_claims_no_hostname() {
    let t = run(&https_evil_beside(
        "  - { name: admin, hostname: admin.example.com, port: 443, protocol: HTTPS, \
         tls: { mode: Passthrough } }",
    ));
    let admin = listener_status(&t, None, "admin");
    assert_eq!(
        cond(&admin.conditions, "Accepted").status,
        ConditionStatus::False
    );
    assert_served_by_the_wildcard(&t, 443);
}

#[test]
fn a_programmed_https_sibling_still_claims_its_host() {
    // The control for the two above: with its certificate the exact listener keeps its host.
    let t = run(&https_evil_beside(
        "  - { name: admin, hostname: admin.example.com, port: 443, protocol: HTTPS, \
         tls: { certificateRefs: [{ name: wildcard }] } }",
    ));
    assert_eq!(served_on(&t, 443, "admin.example.com", "/login"), None);
    assert_eq!(
        accepted(&t, "tenant", "evil").status,
        ConditionStatus::False
    );
}

// ---------- #250 ----------

#[test]
fn kubernetes_route_paths_with_escapes_match_the_requests_they_name() {
    // The issue's reproduction: an Exact and a PathPrefix value written with escapes the data
    // plane rewrites, next to a catch-all that would otherwise take their requests.
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
metadata: { name: echo, namespace: apps }
spec: { ports: [{ name: http, port: 80 }] }
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: escaped, namespace: apps }
spec:
  parentRefs: [{ name: gw }]
  rules:
  - matches:
    - path: { type: PathPrefix, value: /files/a%2fb }
    - path: { type: Exact, value: /%7Ejohn }
    - path: { type: Exact, value: //api//v1 }
    backendRefs: [{ name: echo, port: 80 }]
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: catch-all, namespace: apps }
spec:
  parentRefs: [{ name: gw }]
  rules:
  - backendRefs: [{ name: echo, port: 80 }]
"#;
    let t = run(yaml);
    assert_eq!(
        accepted(&t, "apps", "escaped").status,
        ConditionStatus::True
    );
    for path in [
        "/files/a%2fb",
        "/files/a%2Fb",
        "/files/a%2fb/c",
        "/%7Ejohn",
        "/%7ejohn",
        "/~john",
        "/api/v1",
        "//api/v1",
    ] {
        assert_eq!(
            served_by(&t, "any.host", path).as_deref(),
            Some("apps/escaped"),
            "{path}"
        );
    }
    // An encoded slash is still not a path separator.
    assert_eq!(
        served_by(&t, "any.host", "/files/a/b").as_deref(),
        Some("apps/catch-all")
    );
}

#[test]
fn a_kubernetes_route_path_no_request_can_carry_is_refused() {
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
metadata: { name: echo, namespace: apps }
spec: { ports: [{ name: http, port: 80 }] }
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: dots, namespace: apps }
spec:
  parentRefs: [{ name: gw }]
  rules:
  - matches: [{ path: { type: PathPrefix, value: /public/../admin } }]
    backendRefs: [{ name: echo, port: 80 }]
"#;
    let t = run(yaml);
    let accepted = accepted(&t, "apps", "dots");
    assert_eq!(accepted.status, ConditionStatus::False);
    assert_eq!(accepted.reason, "UnsupportedValue");
    assert!(
        accepted.message.contains("/public/../admin"),
        "{}",
        accepted.message
    );
}

// ---------- #247 ----------

#[test]
fn a_route_path_with_path_parameters_is_refused_rather_than_reported_served() {
    // The issue's values next to a catch-all: `GET /api;v=2` matched the first route as sent
    // and the catch-all as `/api`, so the data plane answered every such request 400 while
    // the route said Accepted.
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
metadata: { name: echo, namespace: apps }
spec: { ports: [{ name: http, port: 80 }] }
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: exact-params, namespace: apps }
spec:
  parentRefs: [{ name: gw }]
  rules:
  - matches: [{ path: { type: Exact, value: "/api;v=2" } }]
    backendRefs: [{ name: echo, port: 80 }]
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: prefix-params, namespace: apps }
spec:
  parentRefs: [{ name: gw }]
  rules:
  - matches: [{ path: { type: PathPrefix, value: "/items;type=book" } }]
    backendRefs: [{ name: echo, port: 80 }]
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: catch-all, namespace: apps }
spec:
  parentRefs: [{ name: gw }]
  rules:
  - backendRefs: [{ name: echo, port: 80 }]
"#;
    let t = run(yaml);
    for (name, value) in [
        ("exact-params", "/api;v=2"),
        ("prefix-params", "/items;type=book"),
    ] {
        let accepted = accepted(&t, "apps", name);
        assert_eq!(accepted.status, ConditionStatus::False, "{name}");
        assert_eq!(accepted.reason, "UnsupportedValue", "{name}");
        assert!(
            accepted.message.contains(value) && accepted.message.contains("contains ;"),
            "{}",
            accepted.message
        );
    }
    assert_eq!(
        served_by(&t, "any.host", "/api;v=2").as_deref(),
        Some("apps/catch-all"),
        "nothing claims to serve the parameterised path"
    );
    assert_eq!(
        accepted(&t, "apps", "catch-all").status,
        ConditionStatus::True
    );
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
