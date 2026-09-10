//! Serde mirrors of the subset of Kubernetes and Gateway API schemas that Gapura reads.
//! Unknown fields are ignored on purpose so newer API versions keep deserializing.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ObjectMeta {
    pub name: String,
    pub namespace: Option<String>,
    pub generation: Option<i64>,
    /// RFC 3339 string as emitted by the API server, e.g. `2026-09-01T10:00:00Z`.
    pub creation_timestamp: Option<String>,
    pub labels: BTreeMap<String, String>,
    pub annotations: BTreeMap<String, String>,
}

// ---------- gateway.networking.k8s.io/v1 ----------

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct GatewayClass {
    pub metadata: ObjectMeta,
    pub spec: GatewayClassSpec,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct GatewayClassSpec {
    /// Empty means the field was absent (struct-level `serde(default)`), never a valid controller name.
    pub controller_name: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Gateway {
    pub metadata: ObjectMeta,
    pub spec: GatewaySpec,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct GatewaySpec {
    /// Empty means the field was absent (struct-level `serde(default)`), never a valid GatewayClass name.
    pub gateway_class_name: String,
    pub listeners: Vec<Listener>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Listener {
    pub name: String,
    pub hostname: Option<String>,
    pub port: u16,
    pub protocol: String,
    pub tls: Option<ListenerTls>,
    pub allowed_routes: Option<AllowedRoutes>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ListenerTls {
    pub mode: Option<String>,
    pub certificate_refs: Vec<SecretObjectReference>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct SecretObjectReference {
    pub group: Option<String>,
    pub kind: Option<String>,
    pub name: String,
    pub namespace: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct AllowedRoutes {
    pub namespaces: Option<RouteNamespaces>,
    pub kinds: Vec<RouteGroupKind>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct RouteNamespaces {
    /// `Same` (default), `All`, or `Selector`.
    pub from: Option<String>,
    pub selector: Option<LabelSelector>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct LabelSelector {
    pub match_labels: BTreeMap<String, String>,
    pub match_expressions: Vec<LabelSelectorRequirement>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct LabelSelectorRequirement {
    pub key: String,
    /// `In`, `NotIn`, `Exists`, `DoesNotExist`.
    pub operator: String,
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct RouteGroupKind {
    pub group: Option<String>,
    pub kind: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct HttpRoute {
    pub metadata: ObjectMeta,
    pub spec: HttpRouteSpec,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct HttpRouteSpec {
    pub parent_refs: Vec<ParentReference>,
    pub hostnames: Vec<String>,
    pub rules: Vec<HttpRouteRule>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ParentReference {
    pub group: Option<String>,
    pub kind: Option<String>,
    pub namespace: Option<String>,
    pub name: String,
    pub section_name: Option<String>,
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct HttpRouteRule {
    pub name: Option<String>,
    pub matches: Vec<HttpRouteMatch>,
    pub filters: Vec<HttpRouteFilter>,
    pub backend_refs: Vec<HttpBackendRef>,
    pub timeouts: Option<HttpRouteTimeouts>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct HttpRouteMatch {
    pub path: Option<HttpPathMatch>,
    pub headers: Vec<HttpHeaderMatch>,
    pub query_params: Vec<HttpQueryParamMatch>,
    pub method: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct HttpPathMatch {
    /// `Exact`, `PathPrefix` (default), `RegularExpression` (unsupported in v0.1).
    #[serde(rename = "type")]
    pub type_: Option<String>,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct HttpHeaderMatch {
    #[serde(rename = "type")]
    pub type_: Option<String>,
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct HttpQueryParamMatch {
    #[serde(rename = "type")]
    pub type_: Option<String>,
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct HttpRouteFilter {
    #[serde(rename = "type")]
    pub type_: String,
    pub request_header_modifier: Option<HeaderModifier>,
    pub response_header_modifier: Option<HeaderModifier>,
    pub request_redirect: Option<RequestRedirect>,
    pub url_rewrite: Option<UrlRewrite>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct HeaderModifier {
    pub set: Vec<HttpHeader>,
    pub add: Vec<HttpHeader>,
    pub remove: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct RequestRedirect {
    pub scheme: Option<String>,
    pub hostname: Option<String>,
    pub path: Option<PathModifier>,
    pub port: Option<u16>,
    pub status_code: Option<u16>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct UrlRewrite {
    pub hostname: Option<String>,
    pub path: Option<PathModifier>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct PathModifier {
    /// `ReplaceFullPath` or `ReplacePrefixMatch`.
    #[serde(rename = "type")]
    pub type_: String,
    pub replace_full_path: Option<String>,
    pub replace_prefix_match: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct HttpBackendRef {
    pub group: Option<String>,
    pub kind: Option<String>,
    pub name: String,
    pub namespace: Option<String>,
    pub port: Option<u16>,
    pub weight: Option<i32>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct HttpRouteTimeouts {
    pub request: Option<String>,
    pub backend_request: Option<String>,
}

// ---------- gateway.networking.k8s.io/v1beta1 ReferenceGrant ----------

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ReferenceGrant {
    pub metadata: ObjectMeta,
    pub spec: ReferenceGrantSpec,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ReferenceGrantSpec {
    pub from: Vec<ReferenceGrantFrom>,
    pub to: Vec<ReferenceGrantTo>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ReferenceGrantFrom {
    pub group: String,
    pub kind: String,
    pub namespace: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ReferenceGrantTo {
    pub group: String,
    pub kind: String,
    pub name: Option<String>,
}

// ---------- core/v1 and discovery.k8s.io/v1 ----------

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Namespace {
    pub metadata: ObjectMeta,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Service {
    pub metadata: ObjectMeta,
    pub spec: ServiceSpec,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ServiceSpec {
    pub ports: Vec<ServicePort>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ServicePort {
    pub name: Option<String>,
    pub port: u16,
    pub target_port: Option<IntOrString>,
    pub protocol: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum IntOrString {
    Int(u16),
    Str(String),
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct EndpointSlice {
    pub metadata: ObjectMeta,
    /// `IPv4`, `IPv6`, or `FQDN`.
    pub address_type: Option<String>,
    pub endpoints: Vec<SliceEndpoint>,
    pub ports: Vec<SlicePort>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct SliceEndpoint {
    pub addresses: Vec<String>,
    pub conditions: Option<SliceEndpointConditions>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct SliceEndpointConditions {
    /// `None` means ready (Kubernetes semantics for a nil ready condition).
    pub ready: Option<bool>,
    pub serving: Option<bool>,
    pub terminating: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct SlicePort {
    pub name: Option<String>,
    pub port: Option<u16>,
    pub protocol: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Secret {
    pub metadata: ObjectMeta,
    #[serde(rename = "type")]
    pub type_: Option<String>,
    /// Values are base64 as stored by the API server.
    pub data: BTreeMap<String, String>,
}

/// gateway.networking.k8s.io/v1 BackendTLSPolicy (v1alpha3 has the same fields).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct BackendTlsPolicy {
    pub metadata: ObjectMeta,
    pub spec: BackendTlsPolicySpec,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct BackendTlsPolicySpec {
    pub target_refs: Vec<PolicyTargetRef>,
    pub validation: BackendTlsValidation,
}

/// LocalPolicyTargetReferenceWithSectionName: same namespace as the policy; `sectionName` is a Service port name.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct PolicyTargetRef {
    pub group: Option<String>,
    pub kind: String,
    pub name: String,
    pub section_name: Option<String>,
}

/// `subjectAltNames` is deliberately not modeled in v0.1; the SNI hostname is what gets verified.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct BackendTlsValidation {
    pub ca_certificate_refs: Vec<LocalObjectReference>,
    /// `System` is the only supported value.
    pub well_known_ca_certificates: Option<String>,
    pub hostname: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct LocalObjectReference {
    pub group: Option<String>,
    pub kind: String,
    pub name: String,
}

/// core/v1 ConfigMap; the reconciler only forwards the `ca.crt` key.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct ConfigMap {
    pub metadata: ObjectMeta,
    pub data: BTreeMap<String, String>,
}
