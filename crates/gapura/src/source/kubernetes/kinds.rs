//! The Kubernetes kinds Gapura watches, how to find them on the API server, and how each
//! object is projected into the JSON the core Snapshot accepts.

use gapura_core::ObjectRef;
use kube::api::{ApiResource, DynamicObject, GroupVersionKind};
use kube::{Client, ResourceExt};
use serde_json::{json, Value};

pub const GATEWAY_GROUP: &str = "gateway.networking.k8s.io";

/// kubectl stores the whole applied manifest here; keeping it would double every object's
/// footprint for the life of the Snapshot.
const LAST_APPLIED_ANNOTATION: &str = "kubectl.kubernetes.io/last-applied-configuration";

pub struct Kind {
    /// The `kind` string the core Snapshot accepts.
    pub name: &'static str,
    pub group: &'static str,
    /// Preferred first; the first version the API server serves wins.
    pub versions: &'static [&'static str],
    pub plural: &'static str,
    pub field_selector: Option<&'static str>,
    /// Missing CRD is a warning, not a startup failure.
    pub optional: bool,
}

const fn kind(
    name: &'static str,
    group: &'static str,
    versions: &'static [&'static str],
    plural: &'static str,
) -> Kind {
    Kind {
        name,
        group,
        versions,
        plural,
        field_selector: None,
        optional: false,
    }
}

/// Everything the translator reads. `static` so watcher tasks can hold `&'static Kind`.
pub static KINDS: [Kind; 10] = [
    kind("GatewayClass", GATEWAY_GROUP, &["v1"], "gatewayclasses"),
    kind("Gateway", GATEWAY_GROUP, &["v1"], "gateways"),
    kind("HTTPRoute", GATEWAY_GROUP, &["v1"], "httproutes"),
    kind(
        "ReferenceGrant",
        GATEWAY_GROUP,
        &["v1", "v1beta1"],
        "referencegrants",
    ),
    Kind {
        optional: true,
        ..kind(
            "BackendTLSPolicy",
            GATEWAY_GROUP,
            &["v1", "v1alpha3"],
            "backendtlspolicies",
        )
    },
    kind("Namespace", "", &["v1"], "namespaces"),
    kind("Service", "", &["v1"], "services"),
    kind(
        "EndpointSlice",
        "discovery.k8s.io",
        &["v1"],
        "endpointslices",
    ),
    Kind {
        field_selector: Some("type=kubernetes.io/tls"),
        ..kind("Secret", "", &["v1"], "secrets")
    },
    kind("ConfigMap", "", &["v1"], "configmaps"),
];

impl Kind {
    fn api_version(&self, version: &str) -> String {
        if self.group.is_empty() {
            version.to_string()
        } else {
            format!("{}/{version}", self.group)
        }
    }

    /// Ask the API server which of our candidate versions serves this kind. `Ok(None)` when none does.
    pub async fn resolve(&self, client: &Client) -> kube::Result<Option<ApiResource>> {
        for version in self.versions {
            // The core group lives at /api/<version>; named groups at /apis/<group>/<version>.
            let listed = if self.group.is_empty() {
                client.list_core_api_resources(version).await
            } else {
                client
                    .list_api_group_resources(&self.api_version(version))
                    .await
            };
            match listed {
                Ok(list) if list.resources.iter().any(|r| r.name == self.plural) => {
                    let gvk = GroupVersionKind::gvk(self.group, version, self.name);
                    return Ok(Some(ApiResource::from_gvk_with_plural(&gvk, self.plural)));
                }
                Ok(_) => continue,
                Err(kube::Error::Api(e)) if e.code == 404 => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(None)
    }
}

pub fn object_ref(obj: &DynamicObject) -> ObjectRef {
    ObjectRef::new(obj.namespace().unwrap_or_default(), obj.name_any())
}

/// The JSON document the core receives for this object, or `None` when the object is irrelevant
/// (a ConfigMap without `ca.crt`) and must be removed from the Snapshot instead.
pub fn project(kind: &Kind, obj: &DynamicObject) -> Option<Value> {
    let mut doc = serde_json::to_value(obj).ok()?;
    // List items carry no apiVersion/kind; the core keys on `kind`.
    doc["kind"] = Value::String(kind.name.to_string());
    if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
        meta.remove("managedFields");
        if let Some(annotations) = meta.get_mut("annotations").and_then(Value::as_object_mut) {
            annotations.remove(LAST_APPLIED_ANNOTATION);
        }
    }
    // Only the publish Service's status is read (LoadBalancer addresses); the rest is dead weight.
    if kind.name != "Service" {
        if let Some(root) = doc.as_object_mut() {
            root.remove("status");
        }
    }
    match kind.name {
        "ConfigMap" => {
            let ca = doc.pointer("/data/ca.crt")?.clone();
            doc["data"] = json!({ "ca.crt": ca });
        }
        "Secret" => {
            let data = doc.get("data").cloned().unwrap_or(Value::Null);
            let mut kept = serde_json::Map::new();
            for key in ["tls.crt", "tls.key", "ca.crt"] {
                if let Some(v) = data.get(key) {
                    kept.insert(key.to_string(), v.clone());
                }
            }
            doc["data"] = Value::Object(kept);
        }
        _ => {}
    }
    Some(doc)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kind_named(name: &str) -> &'static Kind {
        KINDS.iter().find(|k| k.name == name).unwrap()
    }

    fn obj(v: Value) -> DynamicObject {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn project_sets_kind_and_strips_managed_fields() {
        let o = obj(json!({
            "metadata": {
                "name": "main",
                "namespace": "infra",
                "managedFields": [{"manager": "x"}],
                "annotations": {
                    "kubectl.kubernetes.io/last-applied-configuration": "{\"kind\":\"Gateway\"}",
                    "gapura.dev/backend-tls": "insecure"
                }
            },
            "spec": { "gatewayClassName": "gapura" }
        }));
        let doc = project(kind_named("Gateway"), &o).unwrap();
        assert_eq!(doc["kind"], "Gateway");
        assert!(doc["metadata"].get("managedFields").is_none());
        assert_eq!(
            doc["metadata"]["annotations"],
            json!({ "gapura.dev/backend-tls": "insecure" })
        );
        assert_eq!(doc["spec"]["gatewayClassName"], "gapura");
        assert_eq!(object_ref(&o), ObjectRef::new("infra", "main"));
    }

    #[test]
    fn status_is_kept_only_for_services() {
        let gw = obj(
            json!({ "metadata": { "name": "main", "namespace": "infra" }, "spec": {}, "status": { "conditions": [] } }),
        );
        assert!(project(kind_named("Gateway"), &gw)
            .unwrap()
            .get("status")
            .is_none());
        let svc = obj(
            json!({ "metadata": { "name": "lb", "namespace": "infra" }, "spec": {}, "status": { "loadBalancer": { "ingress": [{ "ip": "203.0.113.7" }] } } }),
        );
        assert_eq!(
            project(kind_named("Service"), &svc).unwrap()["status"]["loadBalancer"]["ingress"][0]
                ["ip"],
            "203.0.113.7"
        );
    }

    #[test]
    fn secret_without_data_projects_to_empty_data() {
        let s = obj(
            json!({ "metadata": { "name": "tls", "namespace": "apps" }, "type": "kubernetes.io/tls" }),
        );
        let doc = project(kind_named("Secret"), &s).unwrap();
        assert_eq!(doc["data"], json!({}), "unlike ConfigMap, an empty Secret stays so the translator reports InvalidCertificateRef");
    }

    #[test]
    fn configmap_keeps_only_ca_crt_or_is_dropped() {
        let with = obj(json!({
            "metadata": { "name": "ca", "namespace": "apps" },
            "data": { "ca.crt": "PEM", "other": "x" }
        }));
        assert_eq!(
            project(kind_named("ConfigMap"), &with).unwrap()["data"],
            json!({ "ca.crt": "PEM" })
        );
        let without = obj(json!({
            "metadata": { "name": "ca", "namespace": "apps" },
            "data": { "other": "x" }
        }));
        assert!(project(kind_named("ConfigMap"), &without).is_none());
    }

    #[test]
    fn secret_keeps_tls_keys_only() {
        let s = obj(json!({
            "metadata": { "name": "tls", "namespace": "apps" },
            "type": "kubernetes.io/tls",
            "data": { "tls.crt": "a", "tls.key": "b", "junk": "c" }
        }));
        let doc = project(kind_named("Secret"), &s).unwrap();
        assert_eq!(doc["data"], json!({ "tls.crt": "a", "tls.key": "b" }));
        assert_eq!(doc["type"], "kubernetes.io/tls");
    }

    #[test]
    fn api_versions_are_formed_per_group() {
        assert_eq!(kind_named("Secret").api_version("v1"), "v1");
        assert_eq!(
            kind_named("Gateway").api_version("v1"),
            "gateway.networking.k8s.io/v1"
        );
        assert!(kind_named("BackendTLSPolicy").optional);
        assert_eq!(
            kind_named("Secret").field_selector,
            Some("type=kubernetes.io/tls")
        );
    }
}
