#![allow(dead_code)]
//! Golden tests: one fixture directory per scenario under tests/fixtures/<case>/input/*.yaml.
//! Each test snapshots the whole Translation with insta AND asserts the key facts explicitly,
//! so a wrong snapshot cannot be accepted by accident.

use std::fs;
use std::path::Path;

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
        StatusPatch::GatewayClass { name, conditions } => {
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
        StatusPatch::GatewayClass { name, conditions } => {
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
