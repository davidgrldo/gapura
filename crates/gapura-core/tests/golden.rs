#![allow(dead_code)]
//! Golden tests: one fixture directory per scenario under tests/fixtures/<case>/input/*.yaml.
//! Each test snapshots the whole Translation with insta AND asserts the key facts explicitly,
//! so a wrong snapshot cannot be accepted by accident.

use std::fs;
use std::path::Path;

use gapura_core::config::{ClusterTls, Mirror, PathMatch};
use gapura_core::status::RouteParentStatus;
use gapura_core::status::{Condition, ConditionStatus, ListenerStatus, StatusPatch};
use gapura_core::{translate, Settings, Snapshot, Translation};

fn load(case: &str) -> Snapshot {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(case)
        .join("input");
    let mut files: Vec<_> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "yaml" || x == "yml"))
        .collect();
    files.sort();
    assert!(
        !files.is_empty(),
        "fixture {case} has no *.yaml files in {}",
        dir.display()
    );
    let mut yaml = String::new();
    for f in files {
        yaml.push_str(&fs::read_to_string(&f).unwrap());
        yaml.push_str("\n---\n");
    }
    Snapshot::from_yaml_docs(&yaml).unwrap_or_else(|e| panic!("fixture {case}: {e}"))
}

fn settings() -> Settings {
    Settings {
        gateway_addresses: vec!["10.0.0.1".to_string()],
        ..Settings::default()
    }
}

fn run(case: &str) -> Translation {
    translate(&load(case), &settings())
}

/// (status, reason) of the condition with the given type. Panics when absent.
fn cond<'a>(conds: &'a [Condition], type_: &str) -> (ConditionStatus, &'a str) {
    let c = conds
        .iter()
        .find(|c| c.type_ == type_)
        .unwrap_or_else(|| panic!("no condition {type_} in {conds:?}"));
    (c.status, c.reason.as_str())
}

/// First Gateway patch: (conditions, listeners, addresses).
fn gateway_patch(t: &Translation) -> (&[Condition], &[ListenerStatus], &[String]) {
    t.status
        .iter()
        .find_map(|p| match p {
            StatusPatch::Gateway {
                conditions,
                listeners,
                addresses,
                ..
            } => Some((
                conditions.as_slice(),
                listeners.as_slice(),
                addresses.as_slice(),
            )),
            _ => None,
        })
        .expect("a Gateway status patch")
}

fn listener<'a>(listeners: &'a [ListenerStatus], name: &str) -> &'a ListenerStatus {
    listeners
        .iter()
        .find(|l| l.name == name)
        .unwrap_or_else(|| panic!("no listener status {name}"))
}

#[test]
fn other_controller_ignored() {
    let t = run("other-controller-ignored");
    assert!(
        t.status.is_empty(),
        "foreign GatewayClass must produce no status"
    );
    assert!(t.config.listeners.is_empty());
    insta::assert_yaml_snapshot!("other-controller-ignored", t);
}

#[test]
fn gatewayclass_accepted() {
    let t = run("gatewayclass-accepted");
    assert_eq!(t.status.len(), 1);
    match &t.status[0] {
        StatusPatch::GatewayClass {
            name, conditions, ..
        } => {
            assert_eq!(name, "gapura");
            assert_eq!(
                cond(conditions, "Accepted"),
                (ConditionStatus::True, "Accepted")
            );
            assert_eq!(conditions[0].observed_generation, Some(1));
        }
        other => panic!("unexpected patch {other:?}"),
    }
    insta::assert_yaml_snapshot!("gatewayclass-accepted", t);
}

#[test]
fn gatewayclass_mixed() {
    let t = run("gatewayclass-mixed");
    assert_eq!(t.status.len(), 1, "only our class gets status");
    match &t.status[0] {
        StatusPatch::GatewayClass {
            name, conditions, ..
        } => {
            assert_eq!(name, "gapura");
            assert_eq!(
                cond(conditions, "Accepted"),
                (ConditionStatus::True, "Accepted")
            );
            assert_eq!(conditions[0].observed_generation, Some(2));
        }
        other => panic!("unexpected patch {other:?}"),
    }
    insta::assert_yaml_snapshot!("gatewayclass-mixed", t);
}

#[test]
fn gateway_class_advertises_supported_features() {
    let t = run("basic-http");
    let StatusPatch::GatewayClass {
        supported_features, ..
    } = &t.status[0]
    else {
        panic!("first patch is the GatewayClass: {:?}", t.status[0])
    };
    assert_eq!(
        supported_features,
        &vec![
            "Gateway".to_string(),
            "HTTPRoute".to_string(),
            "HTTPRouteRequestMirror".to_string(),
            "PathMatchRegularExpression".to_string(),
            "ReferenceGrant".to_string()
        ],
        "the GATEWAY-HTTP core feature set plus regex path matching and request mirroring, sorted as the CRD requires"
    );
}

#[test]
fn gateway_http_listener() {
    let t = run("gateway-http-listener");
    let (gw_conds, listeners, addresses) = gateway_patch(&t);
    assert_eq!(addresses, ["10.0.0.1".to_string()]);
    assert_eq!(
        cond(gw_conds, "Accepted"),
        (ConditionStatus::True, "Accepted")
    );
    assert_eq!(
        cond(gw_conds, "Programmed"),
        (ConditionStatus::True, "Programmed")
    );
    let http = listener(listeners, "http");
    assert_eq!(http.attached_routes, 0);
    assert_eq!(http.supported_kinds.len(), 1);
    assert_eq!(http.supported_kinds[0].kind, "HTTPRoute");
    assert_eq!(
        cond(&http.conditions, "Accepted"),
        (ConditionStatus::True, "Accepted")
    );
    assert_eq!(
        cond(&http.conditions, "Programmed"),
        (ConditionStatus::True, "Programmed")
    );
    assert_eq!(
        cond(&http.conditions, "ResolvedRefs"),
        (ConditionStatus::True, "ResolvedRefs")
    );
    assert_eq!(
        cond(&http.conditions, "Conflicted"),
        (ConditionStatus::False, "NoConflicts")
    );
    assert_eq!(t.config.listeners.len(), 1);
    assert_eq!(t.config.listeners[0].id, "infra/main/http");
    assert_eq!(t.config.listeners[0].port, 80);
    assert!(t.config.listeners[0].tls.is_none());
    insta::assert_yaml_snapshot!("gateway-http-listener", t);
}

#[test]
fn unsupported_port() {
    let t = run("unsupported-port");
    let (gw_conds, listeners, _) = gateway_patch(&t);
    assert_eq!(
        cond(gw_conds, "Accepted"),
        (ConditionStatus::False, "ListenersNotValid")
    );
    assert_eq!(
        cond(gw_conds, "Programmed"),
        (ConditionStatus::False, "Invalid")
    );
    let alt = listener(listeners, "alt");
    assert_eq!(
        cond(&alt.conditions, "Accepted"),
        (ConditionStatus::False, "PortUnavailable")
    );
    assert_eq!(
        cond(&alt.conditions, "Programmed"),
        (ConditionStatus::False, "Invalid")
    );
    assert!(t.config.listeners.is_empty());
    insta::assert_yaml_snapshot!("unsupported-port", t);
}

#[test]
fn listener_port_protocol_mismatch() {
    let t = run("listener-port-protocol-mismatch");
    let (_, listeners, _) = gateway_patch(&t);
    assert_eq!(
        cond(
            &listener(listeners, "http-on-tls-port").conditions,
            "Accepted"
        ),
        (ConditionStatus::False, "PortUnavailable"),
        "HTTP on the HTTPS port is not bound for HTTP"
    );
    assert_eq!(
        cond(&listener(listeners, "http").conditions, "Accepted"),
        (ConditionStatus::True, "Accepted")
    );
    assert_eq!(
        t.config.listeners.len(),
        1,
        "only the valid listener is programmed"
    );
    insta::assert_yaml_snapshot!("listener-port-protocol-mismatch", t);
}

#[test]
fn https_tls_secret() {
    let t = run("https-tls-secret");
    let (_, listeners, _) = gateway_patch(&t);
    assert_eq!(
        cond(&listener(listeners, "https").conditions, "ResolvedRefs"),
        (ConditionStatus::True, "ResolvedRefs")
    );
    let l = &t.config.listeners[0];
    assert_eq!(l.hostname.as_deref(), Some("*.example.com"));
    let tls = l.tls.as_ref().expect("tls bundle");
    assert_eq!(tls.secret, "infra/wildcard");
    assert!(tls.cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(tls.key_pem.contains("PRIVATE KEY"));
    insta::assert_yaml_snapshot!("https-tls-secret", t);
}

#[test]
fn https_missing_secret() {
    let t = run("https-missing-secret");
    let (gw_conds, listeners, _) = gateway_patch(&t);
    let https = listener(listeners, "https");
    assert_eq!(
        cond(&https.conditions, "Accepted"),
        (ConditionStatus::True, "Accepted")
    );
    assert_eq!(
        cond(&https.conditions, "ResolvedRefs"),
        (ConditionStatus::False, "InvalidCertificateRef")
    );
    assert_eq!(
        cond(&https.conditions, "Programmed"),
        (ConditionStatus::False, "Invalid")
    );
    assert_eq!(
        cond(gw_conds, "Programmed"),
        (ConditionStatus::False, "Invalid")
    );
    assert!(t.config.listeners.is_empty());
    insta::assert_yaml_snapshot!("https-missing-secret", t);
}

#[test]
fn https_cross_ns_secret_grant() {
    let t = run("https-cross-ns-secret-grant");
    let (_, listeners, _) = gateway_patch(&t);
    assert_eq!(
        cond(&listener(listeners, "https").conditions, "ResolvedRefs"),
        (ConditionStatus::True, "ResolvedRefs")
    );
    assert_eq!(
        t.config.listeners[0].tls.as_ref().unwrap().secret,
        "certs/wildcard"
    );
    insta::assert_yaml_snapshot!("https-cross-ns-secret-grant", t);
}

#[test]
fn https_cross_ns_secret_no_grant() {
    let t = run("https-cross-ns-secret-no-grant");
    let (_, listeners, _) = gateway_patch(&t);
    assert_eq!(
        cond(&listener(listeners, "https").conditions, "ResolvedRefs"),
        (ConditionStatus::False, "RefNotPermitted")
    );
    assert!(t.config.listeners.is_empty());
    insta::assert_yaml_snapshot!("https-cross-ns-secret-no-grant", t);
}

#[test]
fn listener_conflict() {
    let t = run("listener-conflict");
    let (gw_conds, listeners, _) = gateway_patch(&t);
    for name in ["http-a", "http-b"] {
        let l = listener(listeners, name);
        assert_eq!(
            cond(&l.conditions, "Conflicted"),
            (ConditionStatus::True, "HostnameConflict")
        );
        assert_eq!(
            cond(&l.conditions, "Programmed"),
            (ConditionStatus::False, "Invalid")
        );
    }
    assert_eq!(
        cond(&listener(listeners, "https").conditions, "Programmed"),
        (ConditionStatus::True, "Programmed")
    );
    assert_eq!(
        cond(gw_conds, "Accepted"),
        (ConditionStatus::True, "ListenersNotValid")
    );
    assert_eq!(
        cond(gw_conds, "Programmed"),
        (ConditionStatus::True, "Programmed")
    );
    assert_eq!(t.config.listeners.len(), 1);
    assert_eq!(t.config.listeners[0].id, "infra/main/https");
    insta::assert_yaml_snapshot!("listener-conflict", t);
}

#[test]
fn allowed_kinds_invalid() {
    let t = run("allowed-kinds-invalid");
    let (_, listeners, _) = gateway_patch(&t);
    let l = listener(listeners, "tcp-only");
    assert_eq!(
        cond(&l.conditions, "ResolvedRefs"),
        (ConditionStatus::False, "InvalidRouteKinds")
    );
    assert!(l.supported_kinds.is_empty());
    insta::assert_yaml_snapshot!("allowed-kinds-invalid", t);
}

/// Parents of the HTTPRoute status patch `namespace/name`.
fn route_parents<'a>(t: &'a Translation, namespace: &str, name: &str) -> &'a [RouteParentStatus] {
    t.status
        .iter()
        .find_map(|p| match p {
            StatusPatch::HttpRoute {
                namespace: ns,
                name: n,
                parents,
            } if ns == namespace && n == name => Some(parents.as_slice()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no HTTPRoute status for {namespace}/{name}"))
}

#[test]
fn basic_http() {
    let t = run("basic-http");
    let (_, listeners, _) = gateway_patch(&t);
    assert_eq!(listener(listeners, "http").attached_routes, 1);
    let parents = route_parents(&t, "apps", "echo");
    assert_eq!(parents.len(), 1);
    assert_eq!(parents[0].controller_name, "gapura.dev/controller");
    assert_eq!(
        cond(&parents[0].conditions, "Accepted"),
        (ConditionStatus::True, "Accepted")
    );
    assert_eq!(
        cond(&parents[0].conditions, "ResolvedRefs"),
        (ConditionStatus::True, "ResolvedRefs")
    );
    assert_eq!(parents[0].conditions[0].observed_generation, Some(2));
    let l = &t.config.listeners[0];
    assert_eq!(l.rules.len(), 1);
    assert_eq!(l.rules[0].route, "apps/echo");
    assert_eq!(l.rules[0].matches[0].path, PathMatch::Prefix("/api".into()));
    assert_eq!(
        l.rules[0].filters.request_headers.set,
        vec![("X-Gateway".to_string(), "gapura".to_string())]
    );
    let entries = &t.config.ports[&l.port];
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].listener, 0);
    assert_eq!(entries[0].hostname.as_deref(), Some("echo.example.com"));
    assert_eq!(entries[0].rule, 0);
    let cluster = &t.config.clusters["apps/echo:80"];
    assert_eq!(cluster.endpoints.len(), 1);
    assert_eq!(cluster.endpoints[0].address, "10.1.0.5");
    assert_eq!(cluster.endpoints[0].port, 8080);
    insta::assert_yaml_snapshot!("basic-http", t);
}

#[test]
fn backend_not_found() {
    let t = run("backend-not-found");
    let parents = route_parents(&t, "apps", "echo");
    assert_eq!(
        cond(&parents[0].conditions, "Accepted"),
        (ConditionStatus::True, "Accepted")
    );
    assert_eq!(
        cond(&parents[0].conditions, "ResolvedRefs"),
        (ConditionStatus::False, "BackendNotFound")
    );
    assert_eq!(t.config.listeners[0].rules[0].backends[0].cluster, None);
    assert!(t.config.clusters.is_empty());
    insta::assert_yaml_snapshot!("backend-not-found", t);
}

#[test]
fn cross_ns_backend_grant() {
    let t = run("cross-ns-backend-grant");
    let parents = route_parents(&t, "apps", "echo");
    assert_eq!(
        cond(&parents[0].conditions, "ResolvedRefs"),
        (ConditionStatus::True, "ResolvedRefs")
    );
    assert_eq!(
        t.config.clusters["platform/shared:80"].endpoints[0].address,
        "10.2.0.9"
    );
    insta::assert_yaml_snapshot!("cross-ns-backend-grant", t);
}

#[test]
fn cross_ns_backend_no_grant() {
    let t = run("cross-ns-backend-no-grant");
    let parents = route_parents(&t, "apps", "echo");
    assert_eq!(
        cond(&parents[0].conditions, "Accepted"),
        (ConditionStatus::True, "Accepted")
    );
    assert_eq!(
        cond(&parents[0].conditions, "ResolvedRefs"),
        (ConditionStatus::False, "RefNotPermitted")
    );
    assert!(t.config.clusters.is_empty());
    insta::assert_yaml_snapshot!("cross-ns-backend-no-grant", t);
}

#[test]
fn hostname_intersection() {
    let t = run("hostname-intersection");
    assert_eq!(
        cond(&route_parents(&t, "apps", "api")[0].conditions, "Accepted"),
        (ConditionStatus::True, "Accepted")
    );
    assert_eq!(
        cond(
            &route_parents(&t, "apps", "nomatch")[0].conditions,
            "Accepted"
        ),
        (ConditionStatus::False, "NoMatchingListenerHostname")
    );
    let l = &t.config.listeners[0];
    assert_eq!(
        l.rules.len(),
        1,
        "only the intersecting route is programmed"
    );
    let entries = &t.config.ports[&l.port];
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].listener, 0);
    assert_eq!(entries[0].hostname.as_deref(), Some("api.example.com"));
    let (_, listeners, _) = gateway_patch(&t);
    assert_eq!(listener(listeners, "http").attached_routes, 1);
    insta::assert_yaml_snapshot!("hostname-intersection", t);
}

#[test]
fn allowed_routes_selector() {
    let t = run("allowed-routes-selector");
    assert_eq!(
        cond(&route_parents(&t, "apps", "ok")[0].conditions, "Accepted"),
        (ConditionStatus::True, "Accepted")
    );
    assert_eq!(
        cond(
            &route_parents(&t, "other", "denied")[0].conditions,
            "Accepted"
        ),
        (ConditionStatus::False, "NotAllowedByListeners")
    );
    assert_eq!(t.config.listeners[0].rules.len(), 1);
    assert_eq!(t.config.listeners[0].rules[0].route, "apps/ok");
    insta::assert_yaml_snapshot!("allowed-routes-selector", t);
}

#[test]
fn section_name_parent() {
    let t = run("section-name-parent");
    assert_eq!(
        cond(
            &route_parents(&t, "apps", "secure")[0].conditions,
            "Accepted"
        ),
        (ConditionStatus::True, "Accepted")
    );
    assert_eq!(
        cond(
            &route_parents(&t, "apps", "nowhere")[0].conditions,
            "Accepted"
        ),
        (ConditionStatus::False, "NoMatchingParent")
    );
    let (_, listeners, _) = gateway_patch(&t);
    assert_eq!(listener(listeners, "http").attached_routes, 0);
    assert_eq!(listener(listeners, "https").attached_routes, 1);
    let https = t
        .config
        .listeners
        .iter()
        .find(|l| l.id == "infra/main/https")
        .unwrap();
    assert_eq!(https.rules.len(), 1);
    let http = t
        .config
        .listeners
        .iter()
        .find(|l| l.id == "infra/main/http")
        .unwrap();
    assert!(http.rules.is_empty());
    insta::assert_yaml_snapshot!("section-name-parent", t);
}

#[test]
fn unsupported_filter() {
    let t = run("unsupported-filter");
    let parents = route_parents(&t, "apps", "mirror");
    assert_eq!(
        cond(&parents[0].conditions, "Accepted"),
        (ConditionStatus::False, "UnsupportedValue")
    );
    let (_, listeners, _) = gateway_patch(&t);
    assert_eq!(listener(listeners, "http").attached_routes, 0);
    assert!(t.config.listeners[0].rules.is_empty());
    assert!(
        t.config.clusters.is_empty(),
        "clusters of rejected routes are pruned"
    );
    insta::assert_yaml_snapshot!("unsupported-filter", t);
}

#[test]
fn foreign_parent_ignored() {
    let t = run("foreign-parent-ignored");
    assert!(
        !t.status
            .iter()
            .any(|p| matches!(p, StatusPatch::HttpRoute { .. })),
        "routes whose parents are not ours get no status from us"
    );
    insta::assert_yaml_snapshot!("foreign-parent-ignored", t);
}

#[test]
fn listener_protocol_conflict() {
    let t = run("listener-protocol-conflict");
    let (gw_conds, listeners, _) = gateway_patch(&t);
    // Port 80 is bound for HTTP only, so the HTTPS listener is also PortUnavailable;
    // the protocol conflict is still reported on both listeners.
    assert_eq!(
        cond(&listener(listeners, "http").conditions, "Accepted"),
        (ConditionStatus::True, "Accepted")
    );
    assert_eq!(
        cond(&listener(listeners, "https-on-80").conditions, "Accepted"),
        (ConditionStatus::False, "PortUnavailable")
    );
    for name in ["http", "https-on-80"] {
        let l = listener(listeners, name);
        assert_eq!(
            cond(&l.conditions, "Conflicted"),
            (ConditionStatus::True, "ProtocolConflict")
        );
        assert_eq!(
            cond(&l.conditions, "Programmed"),
            (ConditionStatus::False, "Invalid")
        );
    }
    assert_eq!(
        cond(gw_conds, "Accepted"),
        (ConditionStatus::False, "ListenersNotValid")
    );
    assert!(t.config.listeners.is_empty());
    insta::assert_yaml_snapshot!("listener-protocol-conflict", t);
}

#[test]
fn https_without_tls() {
    let t = run("https-without-tls");
    let (_, listeners, _) = gateway_patch(&t);
    let l = listener(listeners, "https");
    assert_eq!(
        cond(&l.conditions, "Accepted"),
        (ConditionStatus::True, "Accepted")
    );
    assert_eq!(
        cond(&l.conditions, "ResolvedRefs"),
        (ConditionStatus::False, "InvalidCertificateRef")
    );
    assert_eq!(
        cond(&l.conditions, "Programmed"),
        (ConditionStatus::False, "Invalid")
    );
    assert!(t.config.listeners.is_empty());
    insta::assert_yaml_snapshot!("https-without-tls", t);
}

#[test]
fn precedence() {
    let t = run("precedence");
    let l = &t.config.listeners[0];
    let entries = &t.config.ports[&l.port];
    assert!(
        entries.iter().all(|e| e.listener == 0),
        "this fixture has one listener, so the whole port table is its own"
    );
    let order: Vec<(Option<&str>, &str, usize)> = entries
        .iter()
        .map(|e| {
            (
                e.hostname.as_deref(),
                l.rules[e.rule].route.as_str(),
                l.rules[e.rule].rule_index,
            )
        })
        .collect();
    assert_eq!(
        order,
        vec![
            (Some("api.example.com"), "apps/c-host", 0), // hostname beats everything
            (None, "apps/b-new", 1),                     // Exact beats Prefix
            (None, "apps/b-new", 0),                     // more header matches
            (None, "apps/a-old", 0),                     // the rest
        ]
    );
    insta::assert_yaml_snapshot!("precedence", t);
}

#[test]
fn regex_path() {
    let t = run("regex-path");
    let parents = route_parents(&t, "apps", "mixed");
    assert_eq!(
        cond(&parents[0].conditions, "Accepted"),
        (ConditionStatus::True, "Accepted")
    );
    let l = &t.config.listeners[0];
    assert_eq!(
        l.rules[0].matches[0].path,
        PathMatch::Regex("^/api/.*".into())
    );
    let entries = &t.config.ports[&l.port];
    let order: Vec<usize> = entries.iter().map(|e| e.rule).collect();
    assert_eq!(
        order,
        vec![2, 1, 0],
        "Exact beats PathPrefix beats RegularExpression, reversing the spec order"
    );
    insta::assert_yaml_snapshot!("regex-path", t);
}

#[test]
fn mirror_route() {
    let t = run("mirror-route");
    let parents = route_parents(&t, "apps", "shadowed");
    assert_eq!(
        cond(&parents[0].conditions, "Accepted"),
        (ConditionStatus::True, "Accepted")
    );
    assert_eq!(
        cond(&parents[0].conditions, "ResolvedRefs"),
        (ConditionStatus::True, "ResolvedRefs")
    );
    let rule = &t.config.listeners[0].rules[0];
    assert_eq!(
        rule.filters.mirror,
        Some(Mirror {
            cluster: "apps/shadow:80".into()
        })
    );
    assert_eq!(
        rule.filters.request_headers.set,
        vec![("X-Gateway".to_string(), "gapura".to_string())]
    );
    assert_eq!(rule.backends[0].cluster.as_deref(), Some("apps/echo:80"));
    assert!(
        t.config.clusters.contains_key("apps/shadow:80"),
        "a cluster referenced only by the mirror filter must survive assemble's used-set prune"
    );
    assert_eq!(t.config.clusters["apps/shadow:80"].endpoints.len(), 1);
    insta::assert_yaml_snapshot!("mirror-route", t);
}

#[test]
fn duplicate_parent_refs_attach_once() {
    let t = run("duplicate-parent-refs");
    let (_, listeners, _) = gateway_patch(&t);
    assert_eq!(listener(listeners, "http").attached_routes, 1);
    let parents = route_parents(&t, "apps", "echo");
    assert_eq!(parents.len(), 2, "status is still reported per parentRef");
    for p in parents {
        assert_eq!(
            cond(&p.conditions, "Accepted"),
            (ConditionStatus::True, "Accepted")
        );
    }
    assert_eq!(t.config.listeners[0].rules.len(), 1);
    assert_eq!(t.config.ports[&t.config.listeners[0].port].len(), 1);
    insta::assert_yaml_snapshot!("duplicate-parent-refs", t);
}

#[test]
fn port_based_parent_ref() {
    let t = run("port-based-parent");
    let (_, listeners, _) = gateway_patch(&t);
    assert_eq!(listener(listeners, "http").attached_routes, 0);
    assert_eq!(listener(listeners, "https").attached_routes, 1);
    assert_eq!(
        cond(
            &route_parents(&t, "apps", "secure")[0].conditions,
            "Accepted"
        ),
        (ConditionStatus::True, "Accepted")
    );
    let https = t
        .config
        .listeners
        .iter()
        .find(|l| l.id == "infra/main/https")
        .unwrap();
    assert_eq!(https.rules.len(), 1);
    insta::assert_yaml_snapshot!("port-based-parent", t);
}

fn cluster_tls<'a>(t: &'a Translation, key: &str) -> &'a ClusterTls {
    t.config.clusters[key]
        .tls
        .as_ref()
        .unwrap_or_else(|| panic!("cluster {key} has no tls"))
}

#[test]
fn backend_tls_configmap() {
    let t = run("backend-tls-configmap");
    let tls = cluster_tls(&t, "apps/echo:443");
    assert_eq!(tls.sni, "echo.apps.svc");
    assert!(tls.ca_pem.as_deref().unwrap().contains("BEGIN CERTIFICATE"));
    assert!(!tls.insecure);
    let parents = route_parents(&t, "apps", "echo");
    assert_eq!(
        cond(&parents[0].conditions, "ResolvedRefs"),
        (ConditionStatus::True, "ResolvedRefs")
    );
    insta::assert_yaml_snapshot!("backend-tls-configmap", t);
}

#[test]
fn backend_tls_system() {
    let t = run("backend-tls-system");
    let tls = cluster_tls(&t, "apps/echo:443");
    assert_eq!(tls.sni, "echo.example.com");
    assert_eq!(tls.ca_pem, None, "System means the process trust store");
    assert!(!tls.insecure);
    insta::assert_yaml_snapshot!("backend-tls-system", t);
}

#[test]
fn backend_tls_insecure_annotation() {
    let t = run("backend-tls-insecure");
    let tls = cluster_tls(&t, "apps/echo:443");
    assert_eq!(
        tls,
        &ClusterTls {
            sni: "echo.apps.svc".into(),
            ca_pem: None,
            insecure: true
        }
    );
    insta::assert_yaml_snapshot!("backend-tls-insecure", t);
}

#[test]
fn backend_tls_missing_ca_invalidates_backend() {
    let t = run("backend-tls-missing-ca");
    let parents = route_parents(&t, "apps", "echo");
    assert_eq!(
        cond(&parents[0].conditions, "ResolvedRefs"),
        (ConditionStatus::False, "BackendNotFound")
    );
    assert!(parents[0].conditions[1]
        .message
        .contains("ConfigMap apps/echo-ca not found"));
    let rule = &t.config.listeners[0].rules[0];
    assert_eq!(
        rule.backends[0].cluster, None,
        "invalid backend serves 500, never plaintext"
    );
    assert!(t.config.clusters.is_empty());
    insta::assert_yaml_snapshot!("backend-tls-missing-ca", t);
}

#[test]
fn backend_tls_section_name_wins_over_service_wide_policy() {
    let t = run("backend-tls-section");
    assert_eq!(cluster_tls(&t, "apps/echo:443").sni, "https.example.com");
    insta::assert_yaml_snapshot!("backend-tls-section", t);
}

#[test]
fn backend_tls_unknown_annotation_fails_closed() {
    let t = run("backend-tls-bad-annotation");
    let parents = route_parents(&t, "apps", "echo");
    assert_eq!(
        cond(&parents[0].conditions, "ResolvedRefs"),
        (ConditionStatus::False, "UnsupportedValue")
    );
    assert!(
        t.config.clusters.is_empty(),
        "a typo in the annotation must never mean plaintext"
    );
    insta::assert_yaml_snapshot!("backend-tls-bad-annotation", t);
}

#[test]
fn backend_tls_oldest_service_wide_policy_wins() {
    let t = run("backend-tls-oldest-wins");
    assert_eq!(
        cluster_tls(&t, "apps/echo:443").sni,
        "all.example.com",
        "older policy beats the lexically smaller newer name"
    );
    insta::assert_yaml_snapshot!("backend-tls-oldest-wins", t);
}

#[test]
fn listener_mixed_route_kinds_is_not_resolved() {
    let t = run("listener-mixed-route-kinds");
    let (_, listeners, _) = gateway_patch(&t);
    let mixed = listener(listeners, "mixed");
    assert_eq!(
        cond(&mixed.conditions, "ResolvedRefs"),
        (ConditionStatus::False, "InvalidRouteKinds"),
        "one unsupported kind in the list is enough, even next to HTTPRoute"
    );
    assert_eq!(
        mixed.supported_kinds,
        vec![gapura_core::input::RouteGroupKind {
            group: Some("gateway.networking.k8s.io".into()),
            kind: "HTTPRoute".into()
        }],
        "supportedKinds still advertises what we do support"
    );
    let only_bad = listener(listeners, "only-bad");
    assert_eq!(
        cond(&only_bad.conditions, "ResolvedRefs"),
        (ConditionStatus::False, "InvalidRouteKinds")
    );
    assert!(only_bad.supported_kinds.is_empty());
    assert_eq!(
        cond(&mixed.conditions, "Programmed"),
        (ConditionStatus::True, "Programmed"),
        "the kinds we do serve keep working, so the listener is still programmed"
    );
    assert_eq!(mixed.attached_routes, 1);
    let https = listener(listeners, "https-mixed");
    assert_eq!(
        cond(&https.conditions, "ResolvedRefs"),
        (ConditionStatus::False, "InvalidRouteKinds")
    );
    assert_eq!(
        cond(&https.conditions, "Programmed"),
        (ConditionStatus::True, "Programmed"),
        "an unknown route kind must not cost the listener its certificate"
    );
    let tls_listener = t
        .config
        .listeners
        .iter()
        .find(|l| l.id == "infra/main/https-mixed")
        .expect("the HTTPS listener is programmed");
    assert!(
        tls_listener.tls.is_some(),
        "a programmed HTTPS listener always carries a resolved certificate"
    );
    let ids: Vec<&str> = t.config.listeners.iter().map(|l| l.id.as_str()).collect();
    assert_eq!(
        ids,
        vec!["infra/main/mixed", "infra/main/https-mixed"],
        "only the listener with no usable kind is dropped"
    );
    assert_eq!(
        t.config.listeners[0].rules.len(),
        1,
        "an HTTPRoute still attaches to it"
    );
    insta::assert_yaml_snapshot!("listener-mixed-route-kinds", t);
}

#[test]
fn gateway_with_parameters_ref_is_rejected() {
    let t = run("gateway-invalid-parameters-ref");
    let (conditions, listeners, _) = gateway_patch(&t);
    assert_eq!(
        cond(conditions, "Accepted"),
        (ConditionStatus::False, "InvalidParameters")
    );
    assert_eq!(
        cond(conditions, "Programmed"),
        (ConditionStatus::False, "Invalid")
    );
    assert_eq!(
        cond(&listener(listeners, "http").conditions, "Accepted"),
        (ConditionStatus::True, "Accepted"),
        "the listener itself is fine; the Gateway is what we refuse"
    );
    assert_eq!(
        cond(&listener(listeners, "http").conditions, "Programmed"),
        (ConditionStatus::False, "Invalid"),
        "a refused Gateway programs nothing, whatever its listeners look like"
    );
    let ids: Vec<&str> = t.config.listeners.iter().map(|l| l.id.as_str()).collect();
    assert_eq!(
        ids,
        vec!["infra/plain/http"],
        "the refusal is scoped to the Gateway that asked for parameters"
    );
    let plain = t
        .status
        .iter()
        .find_map(|p| match p {
            gapura_core::status::StatusPatch::Gateway {
                name, conditions, ..
            } if name == "plain" => Some(conditions),
            _ => None,
        })
        .expect("the second Gateway has a status patch");
    assert_eq!(
        cond(plain, "Accepted"),
        (ConditionStatus::True, "Accepted"),
        "infrastructure without parametersRef is fine"
    );
    insta::assert_yaml_snapshot!("gateway-invalid-parameters-ref", t);
}

#[test]
fn listener_with_unsupported_protocol_advertises_no_kinds() {
    let t = run("listener-unsupported-protocol");
    let (_, listeners, _) = gateway_patch(&t);
    let tcp = listener(listeners, "tcp");
    assert_eq!(
        cond(&tcp.conditions, "Accepted"),
        (ConditionStatus::False, "UnsupportedProtocol")
    );
    assert!(
        tcp.supported_kinds.is_empty(),
        "a protocol we do not serve carries no route kind: {:?}",
        tcp.supported_kinds
    );
    assert_eq!(
        cond(&listener(listeners, "http").conditions, "Accepted"),
        (ConditionStatus::True, "Accepted"),
        "the sibling listener is unaffected"
    );
    insta::assert_yaml_snapshot!("listener-unsupported-protocol", t);
}

#[test]
fn two_gateways_share_a_port_and_both_are_reachable() {
    let t = run("two-gateways-one-port");
    let ids: Vec<&str> = t.config.listeners.iter().map(|l| l.id.as_str()).collect();
    assert_eq!(ids, vec!["infra/first/http", "infra/second/http"]);
    let port80 = &t.config.ports[&80];
    assert_eq!(port80.len(), 2, "one entry per Gateway");
    // Both hostnames live in the same table and each points at its own Gateway. Their relative
    // order is not asserted: two disjoint exact hostnames never match the same request, so the
    // order between them carries no meaning (today the longer hostname happens to sort first,
    // because equal-kind specificity falls back to length).
    let mut pairs: Vec<(&str, &str)> = port80
        .iter()
        .map(|e| {
            (
                e.hostname
                    .as_deref()
                    .expect("both listeners have a hostname"),
                t.config.listeners[e.listener].id.as_str(),
            )
        })
        .collect();
    pairs.sort();
    assert_eq!(
        pairs,
        vec![
            ("first.example.com", "infra/first/http"),
            ("second.example.com", "infra/second/http"),
        ],
        "each Gateway's route is reachable under its own hostname"
    );
    for (i, entry) in port80.iter().enumerate() {
        let listener = &t.config.listeners[entry.listener];
        assert!(
            listener.rules.get(entry.rule).is_some(),
            "entry {i} points at a real rule"
        );
    }
    insta::assert_yaml_snapshot!("two-gateways-one-port", t);
}

#[test]
fn two_identical_listeners_are_split_by_bind_port() {
    // The deployment bound a second port (the chart's extraListenHttp) and gave beta its own
    // address via --gateway-address — the declaration that beta is individually addressable,
    // so the translator may move its listener. Alpha keeps its declared 80, beta moves to the
    // free bound port, and each published address reaches exactly its own Gateway: the shape
    // that failed HTTPRouteMultipleGateways. Alpha, without an override, stays reachable on
    // the shared address exactly as before.
    let settings = Settings {
        http_ports: vec![80, 10000],
        gateway_address_overrides: [("infra/beta".to_string(), vec!["203.0.113.9".to_string()])]
            .into_iter()
            .collect(),
        ..settings()
    };
    let t = translate(&load("two-gateways-same-hostname"), &settings);
    let by_id = |id: &str| {
        t.config
            .listeners
            .iter()
            .find(|l| l.id == id)
            .unwrap_or_else(|| panic!("{id} is programmed"))
    };
    assert_eq!(by_id("infra/alpha/http").port, 80);
    assert_eq!(by_id("infra/beta/http").port, 10000);
    assert_eq!(t.config.ports[&80].len(), 1, "only alpha serves port 80");
    assert_eq!(t.config.ports[&10000].len(), 1, "only beta serves its port");
    let beta_patch = t.status.iter().find_map(|p| match p {
        StatusPatch::Gateway {
            name, addresses, ..
        } if name == "beta" => Some(addresses),
        _ => None,
    });
    assert_eq!(
        beta_patch.map(Vec::as_slice),
        Some(["203.0.113.9".to_string()].as_slice()),
        "beta's status carries its own address"
    );
    insta::assert_yaml_snapshot!("two-gateways-same-hostname", t);
}
