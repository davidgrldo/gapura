//! Status writer: the leader turns `StatusPatch` into merge patches on the status subresource,
//! copying `lastTransitionTime` from the live object and skipping unchanged patches.

use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use gapura_core::input::ParentReference;
use gapura_core::status::{Condition, StatusPatch};
use kube::api::{Api, ApiResource, DynamicObject, Patch, PatchParams};
use kube::Client;
use pingora::server::ShutdownWatch;
use serde_json::{json, Value};
use tokio::sync::watch;

use super::kinds::GATEWAY_GROUP;
use crate::telemetry::METRICS;

/// The object a patch targets.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Target {
    pub kind: &'static str,
    pub namespace: Option<String>,
    pub name: String,
}

pub fn target_of(p: &StatusPatch) -> Target {
    match p {
        StatusPatch::GatewayClass { name, .. } => Target {
            kind: "GatewayClass",
            namespace: None,
            name: name.clone(),
        },
        StatusPatch::Gateway {
            namespace, name, ..
        } => Target {
            kind: "Gateway",
            namespace: Some(namespace.clone()),
            name: name.clone(),
        },
        StatusPatch::HttpRoute {
            namespace, name, ..
        } => Target {
            kind: "HTTPRoute",
            namespace: Some(namespace.clone()),
            name: name.clone(),
        },
    }
}

/// RFC 3339 seconds, the format metav1.Time round-trips.
pub fn now_rfc3339() -> String {
    k8s_openapi::jiff::Timestamp::now()
        .strftime("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

/// Merge-patch body `{ "status": ... }`. `live` is the object's current `status` (or Null);
/// `now` is RFC 3339.
pub fn body(p: &StatusPatch, live: &Value, controller_name: &str, now: &str) -> Value {
    match p {
        StatusPatch::GatewayClass { conditions, .. } => {
            json!({ "status": { "conditions": stamp(conditions, live.get("conditions"), now) } })
        }
        StatusPatch::Gateway {
            addresses,
            conditions,
            listeners,
            ..
        } => {
            let live_listeners = live.get("listeners").and_then(Value::as_array);
            json!({ "status": {
                "addresses": addresses.iter().map(|a| json!({
                    "type": if a.parse::<IpAddr>().is_ok() { "IPAddress" } else { "Hostname" },
                    "value": a,
                })).collect::<Vec<_>>(),
                "conditions": stamp(conditions, live.get("conditions"), now),
                "listeners": listeners.iter().map(|l| {
                    let prev = live_listeners.into_iter().flatten()
                        .find(|x| x["name"] == l.name.as_str())
                        .and_then(|x| x.get("conditions"));
                    json!({
                        "name": l.name,
                        "supportedKinds": l.supported_kinds.iter().map(|k| json!({
                            "group": k.group.clone().unwrap_or_else(|| GATEWAY_GROUP.to_string()),
                            "kind": k.kind,
                        })).collect::<Vec<_>>(),
                        "attachedRoutes": l.attached_routes,
                        "conditions": stamp(&l.conditions, prev, now),
                    })
                }).collect::<Vec<_>>(),
            } })
        }
        StatusPatch::HttpRoute { parents, .. } => {
            let live_parents: Vec<&Value> = live
                .get("parents")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .collect();
            let mut out: Vec<Value> = live_parents
                .iter()
                .filter(|x| x["controllerName"] != controller_name)
                .map(|x| (*x).clone())
                .collect();
            for parent in parents {
                let ours = parent_ref_json(&parent.parent_ref);
                let prev = live_parents
                    .iter()
                    .find(|x| {
                        x["controllerName"] == controller_name
                            && same_parent(&x["parentRef"], &ours)
                    })
                    .and_then(|x| x.get("conditions"));
                out.push(json!({
                    "parentRef": ours,
                    "controllerName": parent.controller_name,
                    "conditions": stamp(&parent.conditions, prev, now),
                }));
            }
            json!({ "status": { "parents": out } })
        }
    }
}

/// The API server defaults `group` and `kind`; compare on the fields that identify the parent.
fn same_parent(a: &Value, b: &Value) -> bool {
    ["namespace", "name", "sectionName", "port"]
        .iter()
        .all(|k| a.get(k) == b.get(k))
}

/// parentRef with explicit defaults and without null fields (a merge patch would delete them).
fn parent_ref_json(p: &ParentReference) -> Value {
    let mut m = serde_json::Map::new();
    m.insert(
        "group".into(),
        Value::String(p.group.clone().unwrap_or_else(|| GATEWAY_GROUP.to_string())),
    );
    m.insert(
        "kind".into(),
        Value::String(p.kind.clone().unwrap_or_else(|| "Gateway".to_string())),
    );
    m.insert("name".into(), Value::String(p.name.clone()));
    if let Some(ns) = &p.namespace {
        m.insert("namespace".into(), Value::String(ns.clone()));
    }
    if let Some(s) = &p.section_name {
        m.insert("sectionName".into(), Value::String(s.clone()));
    }
    if let Some(port) = p.port {
        m.insert("port".into(), Value::from(port));
    }
    Value::Object(m)
}

/// Copy `lastTransitionTime` from the live condition of the same type when its status is
/// unchanged; otherwise stamp `now`.
fn stamp(conds: &[Condition], live: Option<&Value>, now: &str) -> Vec<Value> {
    conds
        .iter()
        .map(|c| {
            let status = serde_json::to_value(c.status).unwrap_or(Value::Null);
            let ltt = live
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .find(|p| p["type"] == c.type_.as_str() && p["status"] == status)
                .and_then(|p| p["lastTransitionTime"].as_str())
                .unwrap_or(now);
            let mut cond = json!({
                "type": c.type_,
                "status": status,
                "reason": c.reason,
                "message": c.message,
                "lastTransitionTime": ltt,
            });
            if let Some(g) = c.observed_generation {
                cond["observedGeneration"] = Value::from(g);
            }
            cond
        })
        .collect()
}

fn hash_of(p: &StatusPatch) -> u64 {
    let mut h = DefaultHasher::new();
    serde_json::to_string(p).unwrap_or_default().hash(&mut h);
    h.finish()
}

/// Writes the latest translation's status while this replica is leader.
pub struct Writer {
    client: Client,
    resources: HashMap<&'static str, ApiResource>,
    controller_name: String,
    is_leader: Arc<AtomicBool>,
    written: HashMap<Target, u64>,
}

impl Writer {
    pub fn new(
        client: Client,
        resources: HashMap<&'static str, ApiResource>,
        controller_name: String,
        is_leader: Arc<AtomicBool>,
    ) -> Self {
        Self {
            client,
            resources,
            controller_name,
            is_leader,
            written: HashMap::new(),
        }
    }

    /// `latest` carries the newest status list (a `watch` channel: intermediate versions are skipped).
    /// A tick retries failures and catches leadership gained between translations.
    pub async fn run(
        mut self,
        mut latest: watch::Receiver<Vec<StatusPatch>>,
        mut shutdown: ShutdownWatch,
    ) {
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        let mut ticks: u32 = 0;
        loop {
            tokio::select! {
                changed = latest.changed() => {
                    if changed.is_err() { return; }
                }
                _ = tick.tick() => {
                    // Every 10 minutes forget what was written: an object deleted and recreated
                    // with an identical translation would otherwise never get its status back.
                    ticks += 1;
                    if ticks % 20 == 0 {
                        self.written.clear();
                    }
                }
                _ = shutdown.changed() => return,
            }
            let patches = latest.borrow_and_update().clone();
            self.flush(&patches).await;
        }
    }

    async fn flush(&mut self, patches: &[StatusPatch]) {
        if !self.is_leader.load(Ordering::Acquire) {
            // A future leader must rewrite everything, including what we wrote before.
            self.written.clear();
            return;
        }
        // Objects that left the translation are forgotten, so a recreated one is written again.
        self.written
            .retain(|t, _| patches.iter().any(|p| target_of(p) == *t));
        for p in patches {
            if !self.is_leader.load(Ordering::Acquire) {
                self.written.clear();
                return;
            }
            self.write(p).await;
        }
    }

    async fn write(&mut self, p: &StatusPatch) {
        let target = target_of(p);
        let hash = hash_of(p);
        if self.written.get(&target) == Some(&hash) {
            return;
        }
        let Some(ar) = self.resources.get(target.kind) else {
            tracing::debug!(?target, "kind not served by the API server, status skipped");
            METRICS
                .status_writes_total
                .with_label_values(&["skipped"])
                .inc();
            return;
        };
        let api: Api<DynamicObject> = match &target.namespace {
            Some(ns) => Api::namespaced_with(self.client.clone(), ns, ar),
            None => Api::all_with(self.client.clone(), ar),
        };
        let result: kube::Result<bool> = async {
            let Some(live) = api.get_opt(&target.name).await? else {
                return Ok(false);
            };
            let live_status = live.data.get("status").cloned().unwrap_or(Value::Null);
            let body = body(p, &live_status, &self.controller_name, &now_rfc3339());
            api.patch_status(&target.name, &PatchParams::default(), &Patch::Merge(body))
                .await?;
            Ok(true)
        }
        .await;
        match result {
            Ok(true) => {
                self.written.insert(target, hash);
                METRICS
                    .status_writes_total
                    .with_label_values(&["success"])
                    .inc();
            }
            Ok(false) => tracing::debug!(?target, "object gone before its status was written"),
            Err(e) => {
                tracing::warn!(?target, error = %e, "status patch failed, will retry");
                METRICS
                    .status_writes_total
                    .with_label_values(&["failure"])
                    .inc();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use gapura_core::status::{ConditionStatus, ListenerStatus, RouteParentStatus};

    use super::*;

    fn cond(type_: &str, status: ConditionStatus) -> Condition {
        Condition::new(type_, status, "R", "m", Some(3))
    }

    #[test]
    fn transition_time_is_kept_when_status_is_unchanged() {
        let live = json!({ "conditions": [
            { "type": "Accepted", "status": "True", "lastTransitionTime": "2026-01-01T00:00:00Z" },
            { "type": "Programmed", "status": "False", "lastTransitionTime": "2026-01-01T00:00:00Z" },
        ] });
        let p = StatusPatch::GatewayClass {
            name: "g".into(),
            conditions: vec![
                cond("Accepted", ConditionStatus::True),
                cond("Programmed", ConditionStatus::True),
            ],
        };
        let b = body(&p, &live, "gapura.dev/controller", "2026-09-10T00:00:00Z");
        let conds = b["status"]["conditions"].as_array().unwrap();
        assert_eq!(
            conds[0]["lastTransitionTime"], "2026-01-01T00:00:00Z",
            "same status keeps the old time"
        );
        assert_eq!(
            conds[1]["lastTransitionTime"], "2026-09-10T00:00:00Z",
            "flipped status is stamped now"
        );
        assert_eq!(conds[0]["observedGeneration"], 3);
        assert_eq!(
            target_of(&p),
            Target {
                kind: "GatewayClass",
                namespace: None,
                name: "g".into()
            }
        );
    }

    #[test]
    fn gateway_body_has_typed_addresses_and_listener_times() {
        let live = json!({ "listeners": [{ "name": "http", "conditions": [{ "type": "Accepted", "status": "True", "lastTransitionTime": "2026-01-01T00:00:00Z" }] }] });
        let p = StatusPatch::Gateway {
            namespace: "infra".into(),
            name: "main".into(),
            addresses: vec!["203.0.113.7".into(), "lb.example.com".into()],
            conditions: vec![cond("Accepted", ConditionStatus::True)],
            listeners: vec![ListenerStatus {
                name: "http".into(),
                supported_kinds: vec![gapura_core::input::RouteGroupKind {
                    group: None,
                    kind: "HTTPRoute".into(),
                }],
                attached_routes: 2,
                conditions: vec![cond("Accepted", ConditionStatus::True)],
            }],
        };
        let b = body(&p, &live, "gapura.dev/controller", "now");
        assert_eq!(b["status"]["addresses"][0]["type"], "IPAddress");
        assert_eq!(b["status"]["addresses"][1]["type"], "Hostname");
        let l = &b["status"]["listeners"][0];
        assert_eq!(l["attachedRoutes"], 2);
        assert_eq!(l["supportedKinds"][0]["group"], GATEWAY_GROUP);
        assert_eq!(
            l["conditions"][0]["lastTransitionTime"],
            "2026-01-01T00:00:00Z"
        );
        assert_eq!(target_of(&p).namespace.as_deref(), Some("infra"));
    }

    #[test]
    fn route_body_keeps_other_controllers_parents_and_replaces_ours() {
        let live = json!({ "parents": [
            { "parentRef": { "group": GATEWAY_GROUP, "kind": "Gateway", "name": "other", "namespace": "infra" }, "controllerName": "example.com/other", "conditions": [] },
            { "parentRef": { "group": GATEWAY_GROUP, "kind": "Gateway", "name": "main", "namespace": "infra" }, "controllerName": "gapura.dev/controller",
              "conditions": [{ "type": "Accepted", "status": "True", "lastTransitionTime": "2026-01-01T00:00:00Z" }] },
        ] });
        let p = StatusPatch::HttpRoute {
            namespace: "apps".into(),
            name: "echo".into(),
            parents: vec![RouteParentStatus {
                parent_ref: ParentReference {
                    name: "main".into(),
                    namespace: Some("infra".into()),
                    ..Default::default()
                },
                controller_name: "gapura.dev/controller".into(),
                conditions: vec![cond("Accepted", ConditionStatus::True)],
            }],
        };
        let b = body(&p, &live, "gapura.dev/controller", "now");
        let parents = b["status"]["parents"].as_array().unwrap();
        assert_eq!(parents.len(), 2);
        assert_eq!(parents[0]["controllerName"], "example.com/other");
        assert_eq!(
            parents[1]["parentRef"],
            json!({ "group": GATEWAY_GROUP, "kind": "Gateway", "name": "main", "namespace": "infra" })
        );
        assert_eq!(
            parents[1]["conditions"][0]["lastTransitionTime"],
            "2026-01-01T00:00:00Z"
        );
    }

    #[test]
    fn hash_changes_with_content() {
        let a = StatusPatch::GatewayClass {
            name: "g".into(),
            conditions: vec![cond("Accepted", ConditionStatus::True)],
        };
        let b = StatusPatch::GatewayClass {
            name: "g".into(),
            conditions: vec![cond("Accepted", ConditionStatus::False)],
        };
        assert_ne!(hash_of(&a), hash_of(&b));
        assert_eq!(hash_of(&a), hash_of(&a.clone()));
        assert!(now_rfc3339().ends_with('Z'));
    }
}
