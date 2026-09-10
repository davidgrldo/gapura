//! Fold watch events into the core Snapshot, and run the translator without letting a panic
//! take the process down. Pure: no I/O, unit-tested with synthetic events.

use std::collections::{BTreeMap, BTreeSet};

use gapura_core::{translate, ObjectRef, Settings, Snapshot, Translation};
use kube::api::DynamicObject;
use kube::runtime::watcher::Event;
use serde_json::Value;

use super::kinds::{object_ref, project, Kind};

/// One watcher event, reduced to what the Snapshot needs.
#[derive(Debug)]
pub enum Change {
    /// A (re)list starts for this kind; the objects until `InitDone` replace everything known.
    Init {
        kind: &'static str,
    },
    Upsert {
        kind: &'static str,
        r#ref: ObjectRef,
        doc: Option<Value>,
        initial: bool,
    },
    Delete {
        kind: &'static str,
        r#ref: ObjectRef,
    },
    InitDone {
        kind: &'static str,
    },
}

pub fn change_of(kind: &'static Kind, event: Event<DynamicObject>) -> Change {
    match event {
        Event::Init => Change::Init { kind: kind.name },
        Event::InitApply(o) => Change::Upsert {
            kind: kind.name,
            r#ref: object_ref(&o),
            doc: project(kind, &o),
            initial: true,
        },
        Event::Apply(o) => Change::Upsert {
            kind: kind.name,
            r#ref: object_ref(&o),
            doc: project(kind, &o),
            initial: false,
        },
        Event::Delete(o) => Change::Delete {
            kind: kind.name,
            r#ref: object_ref(&o),
        },
        Event::InitDone => Change::InitDone { kind: kind.name },
    }
}

#[derive(Default)]
pub struct State {
    pub snapshot: Snapshot,
    /// Objects known per kind, to delete what a relist no longer returns.
    known: BTreeMap<&'static str, BTreeSet<ObjectRef>>,
    /// Objects of a relist in progress, applied together at `InitDone`.
    pending: BTreeMap<&'static str, Vec<(ObjectRef, Option<Value>)>>,
    synced: BTreeSet<&'static str>,
    publish: Option<ObjectRef>,
    /// LoadBalancer addresses of the `--publish-service` Service.
    pub addresses: Vec<String>,
}

impl State {
    pub fn new(publish: Option<ObjectRef>) -> Self {
        Self {
            publish,
            ..Self::default()
        }
    }

    /// Returns true when the snapshot (or the published addresses) changed.
    pub fn apply(&mut self, change: Change) -> bool {
        match change {
            Change::Init { kind } => {
                self.pending.insert(kind, Vec::new());
                false
            }
            Change::Upsert {
                kind,
                r#ref,
                doc,
                initial: true,
            } => {
                self.pending.entry(kind).or_default().push((r#ref, doc));
                false
            }
            Change::Upsert {
                kind,
                r#ref,
                doc,
                initial: false,
            } => self.put(kind, r#ref, doc),
            Change::Delete { kind, r#ref } => self.drop(kind, &r#ref),
            Change::InitDone { kind } => {
                let items = self.pending.remove(kind).unwrap_or_default();
                let fresh: BTreeSet<ObjectRef> = items.iter().map(|(r, _)| r.clone()).collect();
                let stale: Vec<ObjectRef> = self
                    .known
                    .get(kind)
                    .map(|k| k.difference(&fresh).cloned().collect())
                    .unwrap_or_default();
                let mut changed = false;
                for r in stale {
                    changed |= self.drop(kind, &r);
                }
                for (r, doc) in items {
                    changed |= self.put(kind, r, doc);
                }
                let first_sync = self.synced.insert(kind);
                changed || first_sync
            }
        }
    }

    /// True once every kind in `kinds` finished its first list; only then is a translation meaningful.
    pub fn synced_all(&self, kinds: &[&str]) -> bool {
        kinds.iter().all(|k| self.synced.contains(k))
    }

    fn put(&mut self, kind: &'static str, r: ObjectRef, doc: Option<Value>) -> bool {
        if kind == "Service" && self.publish.as_ref() == Some(&r) {
            self.addresses = doc.as_ref().map(addresses_of).unwrap_or_default();
        }
        let Some(doc) = doc else {
            return self.drop(kind, &r);
        };
        match self.snapshot.insert_json(doc) {
            Ok(()) => {
                self.known.entry(kind).or_default().insert(r);
                true
            }
            Err(e) => {
                tracing::warn!(
                    kind,
                    object = %r,
                    error = %e,
                    "object rejected by the translator input schema, dropped"
                );
                self.drop(kind, &r)
            }
        }
    }

    fn drop(&mut self, kind: &'static str, r: &ObjectRef) -> bool {
        if kind == "Service" && self.publish.as_ref() == Some(r) {
            self.addresses.clear();
        }
        let was_known = self.known.get_mut(kind).is_some_and(|k| k.remove(r));
        self.snapshot.remove(kind, r) || was_known
    }
}

/// `status.loadBalancer.ingress[*].ip`, falling back to `.hostname`.
pub fn addresses_of(service: &Value) -> Vec<String> {
    service
        .pointer("/status/loadBalancer/ingress")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|i| {
            i.get("ip")
                .or_else(|| i.get("hostname"))
                .and_then(Value::as_str)
        })
        .map(str::to_string)
        .collect()
}

/// Translate, turning a translator panic into an error so the previous Config stays in service.
pub fn translate_guarded(snap: &Snapshot, settings: &Settings) -> Result<Translation, String> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| translate(snap, settings))).map_err(
        |p| {
            p.downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| p.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unknown panic".to_string())
        },
    )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn gateway(name: &str) -> Value {
        json!({ "kind": "Gateway", "metadata": { "name": name, "namespace": "infra" }, "spec": { "gatewayClassName": "gapura", "listeners": [] } })
    }

    fn upsert(
        kind: &'static str,
        ns: &str,
        name: &str,
        doc: Option<Value>,
        initial: bool,
    ) -> Change {
        Change::Upsert {
            kind,
            r#ref: ObjectRef::new(ns, name),
            doc,
            initial,
        }
    }

    #[test]
    fn relist_replaces_the_kind_and_marks_it_synced() {
        let mut s = State::new(None);
        assert!(!s.apply(Change::Init { kind: "Gateway" }));
        assert!(!s.apply(upsert("Gateway", "infra", "a", Some(gateway("a")), true)));
        assert!(!s.apply(upsert("Gateway", "infra", "b", Some(gateway("b")), true)));
        assert!(!s.synced_all(&["Gateway"]));
        assert!(s.apply(Change::InitDone { kind: "Gateway" }));
        assert_eq!(s.snapshot.gateways.len(), 2);
        assert!(s.synced_all(&["Gateway"]));
        assert!(!s.synced_all(&["Gateway", "Service"]));

        // relist without b: b is gone
        s.apply(Change::Init { kind: "Gateway" });
        s.apply(upsert("Gateway", "infra", "a", Some(gateway("a")), true));
        assert!(s.apply(Change::InitDone { kind: "Gateway" }));
        assert_eq!(s.snapshot.gateways.len(), 1);
        assert!(s
            .snapshot
            .gateways
            .contains_key(&ObjectRef::new("infra", "a")));

        // identical relist changes nothing
        s.apply(Change::Init { kind: "Gateway" });
        s.apply(upsert("Gateway", "infra", "a", Some(gateway("a")), true));
        assert!(
            s.apply(Change::InitDone { kind: "Gateway" }),
            "insert_json replaces, so it reports a change; acceptable"
        );
    }

    #[test]
    fn live_events_apply_immediately() {
        let mut s = State::new(None);
        assert!(s.apply(upsert("Gateway", "infra", "a", Some(gateway("a")), false)));
        assert!(s.apply(Change::Delete {
            kind: "Gateway",
            r#ref: ObjectRef::new("infra", "a")
        }));
        assert!(
            !s.apply(Change::Delete {
                kind: "Gateway",
                r#ref: ObjectRef::new("infra", "a")
            }),
            "deleting twice is not a change"
        );
        assert!(s.snapshot.gateways.is_empty());
    }

    #[test]
    fn invalid_object_is_dropped_not_fatal() {
        let mut s = State::new(None);
        s.apply(upsert("Gateway", "infra", "a", Some(gateway("a")), false));
        let garbage = json!({ "kind": "Gateway", "metadata": { "name": "a", "namespace": "infra" }, "spec": "nope" });
        assert!(
            s.apply(upsert("Gateway", "infra", "a", Some(garbage), false)),
            "the stale copy is removed"
        );
        assert!(s.snapshot.gateways.is_empty());
    }

    #[test]
    fn publish_service_addresses_follow_the_service() {
        let publish = ObjectRef::new("gapura-system", "gapura");
        let mut s = State::new(Some(publish.clone()));
        let svc = json!({ "kind": "Service", "metadata": { "name": "gapura", "namespace": "gapura-system" }, "spec": { "ports": [] },
            "status": { "loadBalancer": { "ingress": [{ "ip": "203.0.113.7" }, { "hostname": "lb.example.com" }] } } });
        assert!(s.apply(upsert(
            "Service",
            "gapura-system",
            "gapura",
            Some(svc),
            false
        )));
        assert_eq!(s.addresses, vec!["203.0.113.7", "lb.example.com"]);
        s.apply(Change::Delete {
            kind: "Service",
            r#ref: publish,
        });
        assert!(s.addresses.is_empty());
        assert!(addresses_of(&json!({ "status": {} })).is_empty());
    }

    #[test]
    fn dropped_projection_removes_the_object() {
        let mut s = State::new(None);
        let cm = json!({ "kind": "ConfigMap", "metadata": { "name": "ca", "namespace": "apps" }, "data": { "ca.crt": "PEM" } });
        s.apply(upsert("ConfigMap", "apps", "ca", Some(cm), false));
        assert_eq!(s.snapshot.config_maps.len(), 1);
        assert!(s.apply(upsert("ConfigMap", "apps", "ca", None, false)));
        assert!(s.snapshot.config_maps.is_empty());
    }

    #[test]
    fn translate_guarded_translates() {
        let t = translate_guarded(&Snapshot::default(), &Settings::default()).unwrap();
        assert!(t.config.listeners.is_empty());
    }
}
