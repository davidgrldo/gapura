//! Status written back to the API server: conditions per GatewayClass, Gateway listener, and HTTPRoute parent.
//! `lastTransitionTime` is deliberately absent: the core has no clock. The bin crate stamps it.

use serde::{Deserialize, Serialize};

use crate::input::{ParentReference, RouteGroupKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConditionStatus {
    True,
    False,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Condition {
    #[serde(rename = "type")]
    pub type_: String,
    pub status: ConditionStatus,
    pub reason: String,
    pub message: String,
    pub observed_generation: Option<i64>,
}

impl Condition {
    pub fn new(
        type_: &str,
        status: ConditionStatus,
        reason: &str,
        message: impl Into<String>,
        observed_generation: Option<i64>,
    ) -> Self {
        Self {
            type_: type_.to_string(),
            status,
            reason: reason.to_string(),
            message: message.into(),
            observed_generation,
        }
    }
}

/// Condition types (Gateway API v1).
pub mod types {
    pub const ACCEPTED: &str = "Accepted";
    pub const PROGRAMMED: &str = "Programmed";
    pub const RESOLVED_REFS: &str = "ResolvedRefs";
    pub const CONFLICTED: &str = "Conflicted";
}

/// Condition reasons (Gateway API v1).
pub mod reasons {
    pub const ACCEPTED: &str = "Accepted";
    pub const PROGRAMMED: &str = "Programmed";
    pub const RESOLVED_REFS: &str = "ResolvedRefs";
    pub const NO_CONFLICTS: &str = "NoConflicts";
    pub const INVALID: &str = "Invalid";
    pub const INVALID_PARAMETERS: &str = "InvalidParameters";
    pub const LISTENERS_NOT_VALID: &str = "ListenersNotValid";
    pub const PORT_UNAVAILABLE: &str = "PortUnavailable";
    pub const UNSUPPORTED_PROTOCOL: &str = "UnsupportedProtocol";
    pub const INVALID_CERTIFICATE_REF: &str = "InvalidCertificateRef";
    pub const INVALID_ROUTE_KINDS: &str = "InvalidRouteKinds";
    pub const REF_NOT_PERMITTED: &str = "RefNotPermitted";
    pub const HOSTNAME_CONFLICT: &str = "HostnameConflict";
    pub const PROTOCOL_CONFLICT: &str = "ProtocolConflict";
    pub const NOT_ALLOWED_BY_LISTENERS: &str = "NotAllowedByListeners";
    pub const NO_MATCHING_LISTENER_HOSTNAME: &str = "NoMatchingListenerHostname";
    pub const NO_MATCHING_PARENT: &str = "NoMatchingParent";
    pub const UNSUPPORTED_VALUE: &str = "UnsupportedValue";
    pub const BACKEND_NOT_FOUND: &str = "BackendNotFound";
    pub const INVALID_KIND: &str = "InvalidKind";
}

/// Feature names Gapura claims in `GatewayClass.status.supportedFeatures`. These are the core
/// features of the Gateway API GATEWAY-HTTP conformance profile, plus regex path matching,
/// request mirroring, and the full RequestRedirect statusCode enum. The CRD requires ascending
/// order.
pub const SUPPORTED_FEATURES: [&str; 8] = [
    "Gateway",
    "HTTPRoute",
    "HTTPRoute303RedirectStatusCode",
    "HTTPRoute307RedirectStatusCode",
    "HTTPRoute308RedirectStatusCode",
    "HTTPRouteRequestMirror",
    "PathMatchRegularExpression",
    "ReferenceGrant",
];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all_fields = "camelCase")]
pub enum StatusPatch {
    GatewayClass {
        name: String,
        conditions: Vec<Condition>,
        /// Feature names, ascending; the writer turns them into `[{name: ...}]`.
        supported_features: Vec<String>,
    },
    Gateway {
        namespace: String,
        name: String,
        addresses: Vec<String>,
        conditions: Vec<Condition>,
        listeners: Vec<ListenerStatus>,
    },
    #[serde(rename = "HTTPRoute")]
    HttpRoute {
        namespace: String,
        name: String,
        parents: Vec<RouteParentStatus>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListenerStatus {
    pub name: String,
    pub supported_kinds: Vec<RouteGroupKind>,
    pub attached_routes: u32,
    pub conditions: Vec<Condition>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteParentStatus {
    pub parent_ref: ParentReference,
    pub controller_name: String,
    pub conditions: Vec<Condition>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn condition_serializes_like_metav1() {
        let c = Condition::new(
            types::ACCEPTED,
            ConditionStatus::True,
            reasons::ACCEPTED,
            "ok",
            Some(2),
        );
        let v = serde_json::to_value(&c).unwrap();
        assert_eq!(v["type"], "Accepted");
        assert_eq!(v["status"], "True");
        assert_eq!(v["reason"], "Accepted");
        assert_eq!(v["observedGeneration"], 2);
    }

    #[test]
    fn supported_features_satisfy_the_crd_constraints() {
        // GatewayClass.status.supportedFeatures is a list-map keyed by name: ascending, unique,
        // at most 64 entries. The CRD rejects anything else.
        assert!(
            SUPPORTED_FEATURES.windows(2).all(|w| w[0] < w[1]),
            "must be sorted ascending and free of duplicates: {SUPPORTED_FEATURES:?}"
        );
        assert!(SUPPORTED_FEATURES.len() <= 64);
    }

    #[test]
    fn status_patch_is_tagged_by_kind() {
        let p = StatusPatch::HttpRoute {
            namespace: "apps".into(),
            name: "echo".into(),
            parents: vec![],
        };
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["kind"], "HTTPRoute");
        assert_eq!(v["namespace"], "apps");
        let g = StatusPatch::GatewayClass {
            name: "gapura".into(),
            conditions: vec![],
            supported_features: vec![],
        };
        assert_eq!(serde_json::to_value(&g).unwrap()["kind"], "GatewayClass");
    }
}
