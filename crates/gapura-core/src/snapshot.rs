//! The input side of translation: every watched resource, keyed for deterministic iteration.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::input::*;

/// `namespace/name`. Cluster-scoped objects use an empty namespace.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ObjectRef {
    pub namespace: String,
    pub name: String,
}

impl ObjectRef {
    pub fn new(namespace: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            name: name.into(),
        }
    }

    pub fn of(meta: &ObjectMeta) -> Self {
        Self {
            namespace: meta.namespace.clone().unwrap_or_default(),
            name: meta.name.clone(),
        }
    }
}

impl std::fmt::Display for ObjectRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.namespace, self.name)
    }
}

/// Everything the translator reads. BTreeMap so iteration order is stable (golden tests depend on it).
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub gateway_classes: BTreeMap<String, GatewayClass>,
    pub gateways: BTreeMap<ObjectRef, Gateway>,
    pub http_routes: BTreeMap<ObjectRef, HttpRoute>,
    pub reference_grants: BTreeMap<ObjectRef, ReferenceGrant>,
    pub namespaces: BTreeMap<String, Namespace>,
    pub services: BTreeMap<ObjectRef, Service>,
    pub endpoint_slices: BTreeMap<ObjectRef, EndpointSlice>,
    pub secrets: BTreeMap<ObjectRef, Secret>,
}

/// Runtime settings that influence translation but are not Kubernetes resources.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Settings {
    /// Only GatewayClasses with this `spec.controllerName` are handled.
    pub controller_name: String,
    /// Ports the process actually binds. Listeners on other ports are rejected with `PortUnavailable`.
    pub supported_ports: Vec<u16>,
    /// Addresses published into `Gateway.status.addresses` (the LoadBalancer IPs of our Service).
    pub gateway_addresses: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            controller_name: "gapura.dev/controller".to_string(),
            supported_ports: vec![80, 443],
            gateway_addresses: Vec::new(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    #[error("document has no `kind` field")]
    MissingKind,
    #[error("unsupported kind `{0}`")]
    UnsupportedKind(String),
    #[error("invalid {kind}: {source}")]
    Invalid {
        kind: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("yaml: {0}")]
    Yaml(#[from] serde_yaml_ng::Error),
}

impl Snapshot {
    /// Insert or replace one object given as JSON (what a Kubernetes watcher hands us).
    pub fn insert_json(&mut self, doc: serde_json::Value) -> Result<(), SnapshotError> {
        let kind = doc
            .get("kind")
            .and_then(|k| k.as_str())
            .ok_or(SnapshotError::MissingKind)?
            .to_string();
        macro_rules! put {
            ($map:expr, $ty:ty, $key:expr) => {{
                let obj: $ty =
                    serde_json::from_value(doc.clone()).map_err(|e| SnapshotError::Invalid {
                        kind: kind.clone(),
                        source: e,
                    })?;
                let key = ($key)(&obj);
                $map.insert(key, obj);
            }};
        }
        match kind.as_str() {
            "GatewayClass" => put!(self.gateway_classes, GatewayClass, |o: &GatewayClass| o
                .metadata
                .name
                .clone()),
            "Gateway" => put!(self.gateways, Gateway, |o: &Gateway| ObjectRef::of(
                &o.metadata
            )),
            "HTTPRoute" => put!(self.http_routes, HttpRoute, |o: &HttpRoute| ObjectRef::of(
                &o.metadata
            )),
            "ReferenceGrant" => put!(
                self.reference_grants,
                ReferenceGrant,
                |o: &ReferenceGrant| ObjectRef::of(&o.metadata)
            ),
            "Namespace" => put!(self.namespaces, Namespace, |o: &Namespace| o
                .metadata
                .name
                .clone()),
            "Service" => put!(self.services, Service, |o: &Service| ObjectRef::of(
                &o.metadata
            )),
            "EndpointSlice" => put!(self.endpoint_slices, EndpointSlice, |o: &EndpointSlice| {
                ObjectRef::of(&o.metadata)
            }),
            "Secret" => put!(self.secrets, Secret, |o: &Secret| ObjectRef::of(
                &o.metadata
            )),
            other => return Err(SnapshotError::UnsupportedKind(other.to_string())),
        }
        Ok(())
    }

    /// Remove an object. Returns true when something was removed.
    pub fn remove(&mut self, kind: &str, r: &ObjectRef) -> bool {
        match kind {
            "GatewayClass" => self.gateway_classes.remove(&r.name).is_some(),
            "Gateway" => self.gateways.remove(r).is_some(),
            "HTTPRoute" => self.http_routes.remove(r).is_some(),
            "ReferenceGrant" => self.reference_grants.remove(r).is_some(),
            "Namespace" => self.namespaces.remove(&r.name).is_some(),
            "Service" => self.services.remove(r).is_some(),
            "EndpointSlice" => self.endpoint_slices.remove(r).is_some(),
            "Secret" => self.secrets.remove(r).is_some(),
            _ => false,
        }
    }

    /// Build a snapshot from a multi-document YAML string (`---` separated). Used by fixtures and the dump example.
    pub fn from_yaml_docs(yaml: &str) -> Result<Self, SnapshotError> {
        let mut snap = Snapshot::default();
        for doc in serde_yaml_ng::Deserializer::from_str(yaml) {
            let value = serde_json::Value::deserialize(doc)?;
            if value.is_null() {
                continue;
            }
            snap.insert_json(value)?;
        }
        Ok(snap)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOCS: &str = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata: { name: gapura }
spec: { controllerName: gapura.dev/controller }
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: { name: main, namespace: infra, generation: 3 }
spec:
  gatewayClassName: gapura
  listeners:
  - { name: http, port: 80, protocol: HTTP }
---
apiVersion: v1
kind: Service
metadata: { name: echo, namespace: apps }
spec:
  ports:
  - { name: http, port: 80, targetPort: 8080 }
  - { name: named, port: 81, targetPort: web }
---
apiVersion: v1
kind: Secret
metadata: { name: tls, namespace: infra }
type: kubernetes.io/tls
data: { tls.crt: Zm9v, tls.key: YmFy }
"#;

    #[test]
    fn loads_multi_doc_yaml() {
        let s = Snapshot::from_yaml_docs(DOCS).unwrap();
        assert_eq!(s.gateway_classes.len(), 1);
        let gw = &s.gateways[&ObjectRef::new("infra", "main")];
        assert_eq!(gw.metadata.generation, Some(3));
        assert_eq!(gw.spec.listeners[0].port, 80);
        let svc = &s.services[&ObjectRef::new("apps", "echo")];
        assert_eq!(svc.spec.ports[0].target_port, Some(IntOrString::Int(8080)));
        assert_eq!(
            svc.spec.ports[1].target_port,
            Some(IntOrString::Str("web".into()))
        );
        assert_eq!(
            s.secrets[&ObjectRef::new("infra", "tls")].type_.as_deref(),
            Some("kubernetes.io/tls")
        );
    }

    #[test]
    fn rejects_unknown_kind() {
        let err = Snapshot::from_yaml_docs("kind: Pod\nmetadata: { name: x }\n").unwrap_err();
        assert!(matches!(err, SnapshotError::UnsupportedKind(k) if k == "Pod"));
    }

    #[test]
    fn rejects_missing_kind() {
        let err = Snapshot::from_yaml_docs("metadata: { name: x }\n").unwrap_err();
        assert!(matches!(err, SnapshotError::MissingKind));
    }

    #[test]
    fn remove_by_kind_and_ref() {
        let mut s = Snapshot::from_yaml_docs(DOCS).unwrap();
        assert!(s.remove("Gateway", &ObjectRef::new("infra", "main")));
        assert!(!s.remove("Gateway", &ObjectRef::new("infra", "main")));
        assert!(s.remove("GatewayClass", &ObjectRef::new("", "gapura")));
        assert!(s.gateways.is_empty() && s.gateway_classes.is_empty());
    }
}
