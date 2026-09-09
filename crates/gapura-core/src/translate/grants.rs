//! ReferenceGrant checks for cross-namespace references.

use crate::snapshot::Snapshot;

/// True when a ReferenceGrant in `to_namespace` lets `from_kind` objects in `from_namespace`
/// reference `to_kind` objects there (optionally restricted to one name).
#[allow(clippy::too_many_arguments)]
pub(crate) fn permits(
    snap: &Snapshot,
    from_group: &str,
    from_kind: &str,
    from_namespace: &str,
    to_group: &str,
    to_kind: &str,
    to_namespace: &str,
    to_name: &str,
) -> bool {
    snap.reference_grants
        .values()
        .filter(|g| g.metadata.namespace.as_deref() == Some(to_namespace))
        .any(|g| {
            g.spec.from.iter().any(|f| {
                f.group == from_group && f.kind == from_kind && f.namespace == from_namespace
            }) && g.spec.to.iter().any(|t| {
                t.group == to_group
                    && t.kind == to_kind
                    && t.name.as_deref().is_none_or(|n| n == to_name)
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const GRANT: &str = r#"
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata: { name: g, namespace: certs }
spec:
  from: [{ group: gateway.networking.k8s.io, kind: Gateway, namespace: infra }]
  to: [{ group: "", kind: Secret, name: only-this }]
"#;

    #[test]
    fn grant_matches_from_to_and_name() {
        let snap = Snapshot::from_yaml_docs(GRANT).unwrap();
        let g = "gateway.networking.k8s.io";
        assert!(permits(
            &snap,
            g,
            "Gateway",
            "infra",
            "",
            "Secret",
            "certs",
            "only-this"
        ));
        assert!(!permits(
            &snap, g, "Gateway", "infra", "", "Secret", "certs", "other"
        ));
        assert!(!permits(
            &snap,
            g,
            "Gateway",
            "apps",
            "",
            "Secret",
            "certs",
            "only-this"
        ));
        assert!(!permits(
            &snap,
            g,
            "HTTPRoute",
            "infra",
            "",
            "Secret",
            "certs",
            "only-this"
        ));
        assert!(!permits(
            &snap,
            g,
            "Gateway",
            "infra",
            "",
            "Secret",
            "elsewhere",
            "only-this"
        ));
    }
}
