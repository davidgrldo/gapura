//! Step 3b of translation: backendRef -> cluster key. Builds the Cluster from Service + EndpointSlices.

use std::collections::BTreeMap;

use crate::config::{Cluster, Endpoint};
use crate::input::HttpBackendRef;
use crate::snapshot::{ObjectRef, Snapshot};
use crate::status::reasons;
use crate::translate::grants;
use crate::translate::listeners::{Rejection, GATEWAY_GROUP};

/// Resolve one backendRef of an HTTPRoute in namespace `route.namespace`.
/// On success the cluster exists in `clusters` and its key is returned.
// used from Task 9 (routes::attach)
#[allow(dead_code)]
pub(crate) fn resolve(
    b: &HttpBackendRef,
    route: &ObjectRef,
    snap: &Snapshot,
    clusters: &mut BTreeMap<String, Cluster>,
) -> Result<String, Rejection> {
    let group = b.group.as_deref().unwrap_or("");
    let kind = b.kind.as_deref().unwrap_or("Service");
    if !group.is_empty() || kind != "Service" {
        return Err((
            reasons::INVALID_KIND,
            format!("backendRef kind {group}/{kind} is not supported, only core Service"),
        ));
    }
    let ns = b
        .namespace
        .clone()
        .unwrap_or_else(|| route.namespace.clone());
    if ns != route.namespace
        && !grants::permits(
            snap,
            GATEWAY_GROUP,
            "HTTPRoute",
            &route.namespace,
            "",
            "Service",
            &ns,
            &b.name,
        )
    {
        return Err((
            reasons::REF_NOT_PERMITTED,
            format!(
                "reference to Service {ns}/{} is not permitted by any ReferenceGrant",
                b.name
            ),
        ));
    }
    let port = b.port.ok_or((
        reasons::UNSUPPORTED_VALUE,
        format!("backendRef to Service {ns}/{} has no port", b.name),
    ))?;
    let sref = ObjectRef::new(ns.clone(), b.name.clone());
    let svc = snap.services.get(&sref).ok_or((
        reasons::BACKEND_NOT_FOUND,
        format!("Service {ns}/{} not found", b.name),
    ))?;
    let svc_port = svc.spec.ports.iter().find(|p| p.port == port).ok_or((
        reasons::BACKEND_NOT_FOUND,
        format!("Service {ns}/{} has no port {port}", b.name),
    ))?;
    let key = format!("{ns}/{}:{port}", b.name);
    if !clusters.contains_key(&key) {
        clusters.insert(
            key.clone(),
            build_cluster(svc_port.name.as_deref(), &sref, snap),
        );
    }
    Ok(key)
}

/// Ready addresses from every EndpointSlice of the Service, taken from the slice port whose
/// name equals the Service port name (unnamed ports match unnamed slice ports).
fn build_cluster(port_name: Option<&str>, svc: &ObjectRef, snap: &Snapshot) -> Cluster {
    let wanted = port_name.unwrap_or("");
    let mut endpoints = Vec::new();
    for slice in snap.endpoint_slices.values() {
        let same_ns = slice.metadata.namespace.as_deref() == Some(svc.namespace.as_str());
        let same_svc = slice.metadata.labels.get("kubernetes.io/service-name") == Some(&svc.name);
        if !same_ns || !same_svc || slice.address_type.as_deref() == Some("FQDN") {
            continue;
        }
        let Some(port) = slice
            .ports
            .iter()
            .find(|p| p.name.as_deref().unwrap_or("") == wanted)
            .and_then(|p| p.port)
        else {
            continue;
        };
        for e in &slice.endpoints {
            let ready = e.conditions.as_ref().and_then(|c| c.ready).unwrap_or(true);
            if !ready {
                continue;
            }
            for address in &e.addresses {
                endpoints.push(Endpoint {
                    address: address.clone(),
                    port,
                });
            }
        }
    }
    endpoints.sort();
    endpoints.dedup();
    Cluster { endpoints }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BACKENDS: &str = r#"
apiVersion: v1
kind: Service
metadata: { name: echo, namespace: apps }
spec:
  ports:
  - { name: http, port: 80, targetPort: 8080 }
  - { port: 9000 }
---
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata: { name: echo-a, namespace: apps, labels: { kubernetes.io/service-name: echo } }
addressType: IPv4
endpoints:
- { addresses: [10.1.0.5], conditions: { ready: true } }
- { addresses: [10.1.0.6], conditions: { ready: false } }
- { addresses: [10.1.0.7] }
ports:
- { name: http, port: 8080 }
- { port: 9000 }
---
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata: { name: echo-fqdn, namespace: apps, labels: { kubernetes.io/service-name: echo } }
addressType: FQDN
endpoints: [{ addresses: [echo.internal] }]
ports: [{ name: http, port: 8080 }]
---
apiVersion: v1
kind: Service
metadata: { name: shared, namespace: platform }
spec: { ports: [{ name: http, port: 80 }] }
---
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata: { name: allow-apps, namespace: platform }
spec:
  from: [{ group: gateway.networking.k8s.io, kind: HTTPRoute, namespace: apps }]
  to: [{ group: "", kind: Service }]
"#;

    fn route() -> ObjectRef {
        ObjectRef::new("apps", "echo")
    }

    fn bref(name: &str, ns: Option<&str>, port: Option<u16>) -> HttpBackendRef {
        HttpBackendRef {
            name: name.into(),
            namespace: ns.map(String::from),
            port,
            ..Default::default()
        }
    }

    #[test]
    fn named_port_collects_only_ready_endpoints_and_skips_fqdn() {
        let snap = Snapshot::from_yaml_docs(BACKENDS).unwrap();
        let mut clusters = BTreeMap::new();
        let key = resolve(
            &bref("echo", None, Some(80)),
            &route(),
            &snap,
            &mut clusters,
        )
        .unwrap();
        assert_eq!(key, "apps/echo:80");
        assert_eq!(
            clusters[&key].endpoints,
            vec![
                Endpoint {
                    address: "10.1.0.5".into(),
                    port: 8080
                },
                Endpoint {
                    address: "10.1.0.7".into(),
                    port: 8080
                },
            ]
        );
    }

    #[test]
    fn unnamed_port_matches_unnamed_slice_port() {
        let snap = Snapshot::from_yaml_docs(BACKENDS).unwrap();
        let mut clusters = BTreeMap::new();
        let key = resolve(
            &bref("echo", None, Some(9000)),
            &route(),
            &snap,
            &mut clusters,
        )
        .unwrap();
        assert_eq!(clusters[&key].endpoints.len(), 2);
        assert!(clusters[&key].endpoints.iter().all(|e| e.port == 9000));
    }

    #[test]
    fn missing_service_and_missing_port_are_backend_not_found() {
        let snap = Snapshot::from_yaml_docs(BACKENDS).unwrap();
        let mut clusters = BTreeMap::new();
        let (reason, _) = resolve(
            &bref("ghost", None, Some(80)),
            &route(),
            &snap,
            &mut clusters,
        )
        .unwrap_err();
        assert_eq!(reason, reasons::BACKEND_NOT_FOUND);
        let (reason, _) = resolve(
            &bref("echo", None, Some(81)),
            &route(),
            &snap,
            &mut clusters,
        )
        .unwrap_err();
        assert_eq!(reason, reasons::BACKEND_NOT_FOUND);
        let (reason, _) =
            resolve(&bref("echo", None, None), &route(), &snap, &mut clusters).unwrap_err();
        assert_eq!(reason, reasons::UNSUPPORTED_VALUE);
        assert!(clusters.is_empty());
    }

    #[test]
    fn cross_namespace_needs_a_grant() {
        let snap = Snapshot::from_yaml_docs(BACKENDS).unwrap();
        let mut clusters = BTreeMap::new();
        assert_eq!(
            resolve(
                &bref("shared", Some("platform"), Some(80)),
                &route(),
                &snap,
                &mut clusters
            )
            .unwrap(),
            "platform/shared:80"
        );
        let other_route = ObjectRef::new("other", "r");
        let (reason, _) = resolve(
            &bref("shared", Some("platform"), Some(80)),
            &other_route,
            &snap,
            &mut clusters,
        )
        .unwrap_err();
        assert_eq!(reason, reasons::REF_NOT_PERMITTED);
    }

    #[test]
    fn non_service_kind_is_invalid_kind() {
        let snap = Snapshot::from_yaml_docs(BACKENDS).unwrap();
        let mut clusters = BTreeMap::new();
        let b = HttpBackendRef {
            name: "x".into(),
            kind: Some("ConfigMap".into()),
            port: Some(80),
            ..Default::default()
        };
        let (reason, _) = resolve(&b, &route(), &snap, &mut clusters).unwrap_err();
        assert_eq!(reason, reasons::INVALID_KIND);
    }
}
