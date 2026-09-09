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
