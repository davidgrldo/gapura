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
    pub backend_tls_policies: BTreeMap<ObjectRef, BackendTlsPolicy>,
    pub config_maps: BTreeMap<ObjectRef, ConfigMap>,
}

/// Runtime settings that influence translation but are not Kubernetes resources.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Settings {
    /// Only GatewayClasses with this `spec.controllerName` are handled.
    pub controller_name: String,
    /// Ports bound for plain HTTP. HTTP listeners on other ports get `PortUnavailable`.
    pub http_ports: Vec<u16>,
    /// Ports bound for HTTPS. HTTPS listeners on other ports get `PortUnavailable`.
    pub https_ports: Vec<u16>,
    /// Addresses published into `Gateway.status.addresses` (the LoadBalancer IPs of our Service).
    pub gateway_addresses: Vec<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            controller_name: "gapura.dev/controller".to_string(),
            http_ports: vec![80],
            https_ports: vec![443],
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
    /// The wrapped serde_json error comes from `from_value`, so its line and column are always 0; the useful part is the message.
    #[error("invalid {kind}: {source}")]
    Invalid {
        kind: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("yaml: {0}")]
    Yaml(#[from] serde_yaml_ng::Error),
    #[error("document {index}: {source}")]
    Document {
        /// 0-based position of the failing document in the multi-document input.
        index: usize,
        #[source]
        source: Box<SnapshotError>,
    },
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
            "BackendTLSPolicy" => put!(
                self.backend_tls_policies,
                BackendTlsPolicy,
                |o: &BackendTlsPolicy| { ObjectRef::of(&o.metadata) }
            ),
            "ConfigMap" => put!(self.config_maps, ConfigMap, |o: &ConfigMap| ObjectRef::of(
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
            "BackendTLSPolicy" => self.backend_tls_policies.remove(r).is_some(),
            "ConfigMap" => self.config_maps.remove(r).is_some(),
            _ => false,
        }
    }

    /// Build a snapshot from a multi-document YAML string (`---` separated). Used by fixtures and the dump example.
    pub fn from_yaml_docs(yaml: &str) -> Result<Self, SnapshotError> {
        let mut snap = Snapshot::default();
        for (index, doc) in serde_yaml_ng::Deserializer::from_str(yaml).enumerate() {
            let value =
                serde_json::Value::deserialize(doc).map_err(|e| SnapshotError::Document {
                    index,
                    source: Box::new(SnapshotError::Yaml(e)),
                })?;
            if value.is_null() {
                continue;
            }
            snap.insert_json(value)
                .map_err(|e| SnapshotError::Document {
                    index,
                    source: Box::new(e),
                })?;
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
        let SnapshotError::Document { index, source } = err else {
            panic!("expected Document, got {err:?}")
        };
        assert_eq!(index, 0);
        assert!(matches!(*source, SnapshotError::UnsupportedKind(ref k) if k == "Pod"));
    }

    #[test]
    fn rejects_missing_kind() {
        let err = Snapshot::from_yaml_docs("metadata: { name: x }\n").unwrap_err();
        let SnapshotError::Document { index, source } = err else {
            panic!("expected Document, got {err:?}")
        };
        assert_eq!(index, 0);
        assert!(matches!(*source, SnapshotError::MissingKind));
    }

    #[test]
    fn wrong_json_type_is_an_error_not_a_default() {
        let err = Snapshot::from_yaml_docs(
            "apiVersion: gateway.networking.k8s.io/v1\nkind: Gateway\nmetadata: { name: g, namespace: ns }\nspec: { gatewayClassName: c, listeners: [{ name: l, port: not-a-number, protocol: HTTP }] }\n",
        )
        .unwrap_err();
        let SnapshotError::Document { index: 0, source } = err else {
            panic!("expected Document, got {err:?}")
        };
        assert!(matches!(*source, SnapshotError::Invalid { ref kind, .. } if kind == "Gateway"));
    }

    #[test]
    fn document_index_points_at_the_failing_document() {
        let yaml = "apiVersion: v1\nkind: Namespace\nmetadata: { name: ok }\n---\nkind: Pod\nmetadata: { name: x }\n";
        let err = Snapshot::from_yaml_docs(yaml).unwrap_err();
        assert!(
            matches!(err, SnapshotError::Document { index: 1, .. }),
            "{err:?}"
        );
    }

    #[test]
    fn insert_replaces_object_with_same_key() {
        let mut s = Snapshot::default();
        let mut doc = serde_json::json!({ "kind": "Namespace", "metadata": { "name": "apps", "labels": { "team": "a" } } });
        s.insert_json(doc.clone()).unwrap();
        doc["metadata"]["labels"]["team"] = serde_json::json!("b");
        s.insert_json(doc).unwrap();
        assert_eq!(s.namespaces.len(), 1);
        assert_eq!(s.namespaces["apps"].metadata.labels["team"], "b");
    }

    #[test]
    fn remove_by_kind_and_ref() {
        let mut s = Snapshot::from_yaml_docs(DOCS).unwrap();
        assert!(s.remove("Gateway", &ObjectRef::new("infra", "main")));
        assert!(!s.remove("Gateway", &ObjectRef::new("infra", "main")));
        assert!(s.remove("GatewayClass", &ObjectRef::new("", "gapura")));
        assert!(s.gateways.is_empty() && s.gateway_classes.is_empty());
    }

    #[test]
    fn backend_tls_policy_and_configmap_round_trip() {
        let mut snap = Snapshot::default();
        snap.insert_json(serde_json::json!({
            "apiVersion": "gateway.networking.k8s.io/v1",
            "kind": "BackendTLSPolicy",
            "metadata": { "name": "echo-tls", "namespace": "apps", "creationTimestamp": "2026-09-01T00:00:00Z" },
            "spec": {
                "targetRefs": [{ "group": "", "kind": "Service", "name": "echo", "sectionName": "https" }],
                "validation": {
                    "caCertificateRefs": [{ "group": "", "kind": "ConfigMap", "name": "echo-ca" }],
                    "hostname": "echo.apps.svc"
                }
            }
        }))
        .unwrap();
        snap.insert_json(serde_json::json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": { "name": "echo-ca", "namespace": "apps", "annotations": { "a": "b" } },
            "data": { "ca.crt": "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n" }
        }))
        .unwrap();
        let pref = ObjectRef::new("apps", "echo-tls");
        let policy = &snap.backend_tls_policies[&pref];
        assert_eq!(
            policy.spec.target_refs[0].section_name.as_deref(),
            Some("https")
        );
        assert_eq!(policy.spec.validation.hostname, "echo.apps.svc");
        assert_eq!(
            policy.spec.validation.ca_certificate_refs[0].kind,
            "ConfigMap"
        );
        snap.insert_json(serde_json::json!({
            "kind": "BackendTLSPolicy",
            "metadata": { "name": "sys-tls", "namespace": "apps" },
            "spec": {
                "targetRefs": [{ "kind": "Service", "name": "echo" }],
                "validation": { "wellKnownCACertificates": "System", "hostname": "echo.example.com" }
            }
        }))
        .unwrap();
        assert_eq!(
            snap.backend_tls_policies[&ObjectRef::new("apps", "sys-tls")]
                .spec
                .validation
                .well_known_ca_certificates
                .as_deref(),
            Some("System"),
            "the CRD key is wellKnownCACertificates, not serde's wellKnownCaCertificates"
        );
        let cref = ObjectRef::new("apps", "echo-ca");
        assert!(snap.config_maps[&cref].data["ca.crt"].starts_with("-----BEGIN CERTIFICATE-----"));
        assert_eq!(snap.config_maps[&cref].metadata.annotations["a"], "b");
        assert!(snap.remove("BackendTLSPolicy", &pref));
        assert!(snap.remove("ConfigMap", &cref));
        assert!(snap.backend_tls_policies.is_empty() && snap.config_maps.is_empty());
    }
}
