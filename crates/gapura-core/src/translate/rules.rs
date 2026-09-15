//! Step 3a of translation: HTTPRoute rules -> RouteRule (matches, filters, backends, timeouts).
//! Any unsupported value rejects the whole route (Gateway API: Accepted=False, UnsupportedValue).

use std::collections::{BTreeMap, BTreeSet};

use crate::config::RateLimit;
use crate::config::{
    Cluster, Filters, HeaderOps, KvMatch, Mirror, PathMatch, PathRewrite, Redirect, Rewrite,
    RouteMatch, RouteRule, Timeouts, WeightedBackend,
};
use crate::duration;
use crate::input::{
    HeaderModifier, HttpBackendRef, HttpRoute, HttpRouteFilter, HttpRouteMatch, PathModifier,
    RequestRedirect, UrlRewrite,
};
use crate::snapshot::{ObjectRef, Snapshot};
use crate::status::{reasons, types, Condition, ConditionStatus};

/// Service annotations the translator reads for per-rule request limits.
pub(crate) const RATE_LIMIT_ANNOTATION: &str = "gapura.dev/rate-limit";
pub(crate) const RATE_LIMIT_BY_ANNOTATION: &str = "gapura.dev/rate-limit-by";

use crate::translate::backends;

/// Why a whole route is rejected. Always reported with reason `UnsupportedValue`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Unsupported(pub String);

pub(crate) struct Compiled {
    pub rules: Vec<RouteRule>,
    /// ResolvedRefs condition of the route; identical for every parent.
    pub resolved_refs: Condition,
}

pub(crate) fn compile(
    route: &HttpRoute,
    rref: &ObjectRef,
    snap: &Snapshot,
    clusters: &mut BTreeMap<String, Cluster>,
) -> Result<Compiled, Unsupported> {
    let generation = route.metadata.generation;
    let mut rules = Vec::new();
    let mut first_ref_error: Option<(&'static str, String)> = None;
    for (index, r) in route.spec.rules.iter().enumerate() {
        let raw_matches: Vec<HttpRouteMatch> = if r.matches.is_empty() {
            vec![HttpRouteMatch::default()]
        } else {
            r.matches.clone()
        };
        let matches = raw_matches
            .iter()
            .map(compile_match)
            .collect::<Result<Vec<_>, _>>()?;
        let regex_matched = matches
            .iter()
            .any(|m| matches!(m.path, PathMatch::Regex(_)));
        // The mirror backendRef resolves exactly like a primary one: same error mapping into
        // ResolvedRefs=False, same cluster table. A failed mirror leaves the route unmirrored
        // (the filter is dropped) instead of failing its primary traffic.
        let mirror_ref = r
            .filters
            .iter()
            .find(|f| f.type_ == "RequestMirror")
            .and_then(|f| f.request_mirror.as_ref())
            .map(|m| &m.backend_ref);
        let mirror_cluster = match mirror_ref {
            Some(b) => match backends::resolve(b, rref, snap, clusters) {
                Ok(key) => Some(key),
                Err(rejection) => {
                    first_ref_error.get_or_insert(rejection);
                    None
                }
            },
            None => None,
        };
        let filters = compile_filters(&r.filters, regex_matched, mirror_cluster)?;
        let mut backends = Vec::new();
        for b in &r.backend_refs {
            // Negative weights are rejected by the CRD schema; clamping is defense in depth, not a real path.
            let weight = b.weight.unwrap_or(1).max(0) as u32;
            match backends::resolve(b, rref, snap, clusters) {
                Ok(key) => backends.push(WeightedBackend {
                    cluster: Some(key),
                    weight,
                }),
                Err(rejection) => {
                    first_ref_error.get_or_insert(rejection);
                    backends.push(WeightedBackend {
                        cluster: None,
                        weight,
                    });
                }
            }
        }
        // Gateway API: "0s" disables a timeout, so Some(0) means disabled, never "expire now".
        // backendRequest <= request is enforced by the CRD's CEL validation upstream; not re-checked here.
        let timeouts = Timeouts {
            request_ms: parse_timeout(r.timeouts.as_ref().and_then(|t| t.request.as_deref()))?,
            backend_request_ms: parse_timeout(
                r.timeouts
                    .as_ref()
                    .and_then(|t| t.backend_request.as_deref()),
            )?,
        };
        rules.push(RouteRule {
            route: rref.to_string(),
            rule_index: index,
            creation_timestamp: route
                .metadata
                .creation_timestamp
                .clone()
                .unwrap_or_default(),
            matches,
            filters,
            backends,
            timeouts,
            rate_limit: rate_limit_of(snap, &rref.namespace, &r.backend_refs),
        });
    }
    let resolved_refs = match first_ref_error {
        None => Condition::new(
            types::RESOLVED_REFS,
            ConditionStatus::True,
            reasons::RESOLVED_REFS,
            "All references resolved",
            generation,
        ),
        Some((reason, message)) => Condition::new(
            types::RESOLVED_REFS,
            ConditionStatus::False,
            reason,
            message,
            generation,
        ),
    };
    Ok(Compiled {
        rules,
        resolved_refs,
    })
}

fn parse_timeout(value: Option<&str>) -> Result<Option<u64>, Unsupported> {
    match value {
        None => Ok(None),
        Some(s) => duration::parse_millis(s)
            .map(Some)
            .ok_or_else(|| Unsupported(format!("invalid timeout {s:?}"))),
    }
}

fn compile_match(m: &HttpRouteMatch) -> Result<RouteMatch, Unsupported> {
    let path = match &m.path {
        None => PathMatch::Prefix("/".to_string()),
        Some(p) => {
            let value = p.value.clone().unwrap_or_else(|| "/".to_string());
            match p.type_.as_deref().unwrap_or("PathPrefix") {
                "Exact" => PathMatch::Exact(value),
                "PathPrefix" => PathMatch::Prefix(normalize_prefix(value)),
                "RegularExpression" => {
                    // Validate here so an invalid pattern keeps the Unsupported path; the data
                    // plane compiles the pattern again into its per-generation side map.
                    if let Err(e) = regex::Regex::new(&value) {
                        return Err(Unsupported(format!(
                            "path match RegularExpression {value:?} does not compile: {e}"
                        )));
                    }
                    PathMatch::Regex(value)
                }
                other => {
                    return Err(Unsupported(format!(
                        "path match type {other} is not supported"
                    )))
                }
            }
        }
    };
    let mut headers = Vec::new();
    for h in &m.headers {
        if h.type_.as_deref().unwrap_or("Exact") != "Exact" {
            return Err(Unsupported(
                "header match type RegularExpression is not supported".to_string(),
            ));
        }
        headers.push(KvMatch {
            name: h.name.to_ascii_lowercase(),
            value: h.value.clone(),
        });
    }
    let mut query = Vec::new();
    for q in &m.query_params {
        if q.type_.as_deref().unwrap_or("Exact") != "Exact" {
            return Err(Unsupported(
                "query param match type RegularExpression is not supported".to_string(),
            ));
        }
        query.push(KvMatch {
            name: q.name.clone(),
            value: q.value.clone(),
        });
    }
    Ok(RouteMatch {
        path,
        headers,
        query,
        method: m.method.as_ref().map(|s| s.to_ascii_uppercase()),
    })
}

/// `/foo/` -> `/foo`; `/` stays `/`.
fn normalize_prefix(mut p: String) -> String {
    while p.len() > 1 && p.ends_with('/') {
        p.pop();
    }
    if p.is_empty() {
        "/".to_string()
    } else {
        p
    }
}

/// `regex_matched`: any match of this rule uses a RegularExpression path. Gateway API leaves the
/// replaced prefix undefined for regex matches, so a ReplacePrefixMatch modifier (URLRewrite or
/// RequestRedirect) combined with one is rejected here, before it could reach the data plane.
fn compile_filters(
    filters: &[HttpRouteFilter],
    regex_matched: bool,
    mirror_cluster: Option<String>,
) -> Result<Filters, Unsupported> {
    let mut out = Filters::default();
    let mut seen = BTreeSet::new();
    for f in filters {
        if !seen.insert(f.type_.clone()) {
            return Err(Unsupported(format!(
                "filter {} may only appear once per rule",
                f.type_
            )));
        }
        match f.type_.as_str() {
            "RequestHeaderModifier" => {
                out.request_headers = header_ops(f.request_header_modifier.as_ref())
            }
            "ResponseHeaderModifier" => {
                out.response_headers = header_ops(f.response_header_modifier.as_ref())
            }
            "RequestRedirect" => out.redirect = Some(redirect(f.request_redirect.as_ref())?),
            "URLRewrite" => out.rewrite = Some(rewrite(f.url_rewrite.as_ref())?),
            "RequestMirror" => {
                let m = f.request_mirror.as_ref().ok_or_else(|| {
                    Unsupported("RequestMirror filter without requestMirror body".to_string())
                })?;
                // The CRD schema allows weight on any backendRef; for a mirror it is meaningless
                // (every request is copied in full), so only the default weight is accepted.
                if m.backend_ref.weight.is_some_and(|w| w != 1) {
                    return Err(Unsupported(
                        "RequestMirror backendRef weight is not supported: every request is mirrored"
                            .to_string(),
                    ));
                }
                out.mirror = mirror_cluster.clone().map(|cluster| Mirror { cluster });
            }
            other => return Err(Unsupported(format!("filter type {other} is not supported"))),
        }
    }
    if out.redirect.is_some() && out.rewrite.is_some() {
        return Err(Unsupported(
            "RequestRedirect and URLRewrite cannot be combined in one rule".to_string(),
        ));
    }
    if regex_matched {
        let prefix_rewrite = [
            out.rewrite.as_ref().and_then(|w| w.path.as_ref()),
            out.redirect.as_ref().and_then(|d| d.path.as_ref()),
        ]
        .into_iter()
        .flatten()
        .any(|p| matches!(p, PathRewrite::ReplacePrefixMatch(_)));
        if prefix_rewrite {
            return Err(Unsupported(
                "ReplacePrefixMatch cannot be combined with a RegularExpression path match: \
                 the prefix to replace is undefined"
                    .to_string(),
            ));
        }
    }
    Ok(out)
}

fn header_ops(m: Option<&HeaderModifier>) -> HeaderOps {
    let Some(m) = m else {
        return HeaderOps::default();
    };
    HeaderOps {
        set: m
            .set
            .iter()
            .map(|h| (h.name.clone(), h.value.clone()))
            .collect(),
        add: m
            .add
            .iter()
            .map(|h| (h.name.clone(), h.value.clone()))
            .collect(),
        remove: m.remove.clone(),
    }
}

fn redirect(r: Option<&RequestRedirect>) -> Result<Redirect, Unsupported> {
    let r = r.ok_or_else(|| {
        Unsupported("RequestRedirect filter without requestRedirect body".to_string())
    })?;
    let status = r.status_code.unwrap_or(302);
    // The full statusCode enum the RequestRedirect CRD allows; 306 and friends stay Unsupported.
    if !matches!(status, 301 | 302 | 303 | 307 | 308) {
        return Err(Unsupported(format!(
            "redirect statusCode {status} is not supported, use one of 301, 302, 303, 307, 308"
        )));
    }
    Ok(Redirect {
        scheme: r.scheme.clone(),
        hostname: r.hostname.clone(),
        port: r.port,
        status,
        path: path_rewrite(r.path.as_ref())?,
    })
}

fn rewrite(r: Option<&UrlRewrite>) -> Result<Rewrite, Unsupported> {
    let r =
        r.ok_or_else(|| Unsupported("URLRewrite filter without urlRewrite body".to_string()))?;
    Ok(Rewrite {
        hostname: r.hostname.clone(),
        path: path_rewrite(r.path.as_ref())?,
    })
}

fn path_rewrite(p: Option<&PathModifier>) -> Result<Option<PathRewrite>, Unsupported> {
    let Some(p) = p else { return Ok(None) };
    match p.type_.as_str() {
        "ReplaceFullPath" => Ok(Some(PathRewrite::ReplaceFullPath(
            p.replace_full_path
                .clone()
                .unwrap_or_else(|| "/".to_string()),
        ))),
        "ReplacePrefixMatch" => Ok(Some(PathRewrite::ReplacePrefixMatch(
            p.replace_prefix_match
                .clone()
                .unwrap_or_else(|| "/".to_string()),
        ))),
        other => Err(Unsupported(format!(
            "path modifier type {other} is not supported"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Endpoint;

    const DOCS: &str = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: echo, namespace: apps, generation: 2, creationTimestamp: "2026-09-01T10:00:00Z" }
spec:
  rules:
  - matches:
    - path: { type: PathPrefix, value: /api/ }
      headers: [{ name: X-Env, value: prod }]
      method: get
    filters:
    - type: RequestHeaderModifier
      requestHeaderModifier: { set: [{ name: X-Gateway, value: gapura }], remove: [Cookie] }
    backendRefs: [{ name: echo, port: 80, weight: 3 }]
    timeouts: { request: 10s }
  - filters:
    - type: RequestRedirect
      requestRedirect: { scheme: https, statusCode: 301 }
---
apiVersion: v1
kind: Service
metadata: { name: echo, namespace: apps }
spec: { ports: [{ name: http, port: 80, targetPort: 8080 }] }
---
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata: { name: echo-abc, namespace: apps, labels: { kubernetes.io/service-name: echo } }
addressType: IPv4
endpoints:
- { addresses: [10.1.0.5], conditions: { ready: true } }
- { addresses: [10.1.0.6], conditions: { ready: false } }
ports: [{ name: http, port: 8080, protocol: TCP }]
"#;

    fn compile_first(yaml: &str) -> (Result<Compiled, Unsupported>, BTreeMap<String, Cluster>) {
        let snap = Snapshot::from_yaml_docs(yaml).unwrap();
        let (rref, route) = snap.http_routes.iter().next().unwrap();
        let mut clusters = BTreeMap::new();
        let result = compile(route, rref, &snap, &mut clusters);
        (result, clusters)
    }

    #[test]
    fn compiles_matches_filters_backends_timeouts() {
        let (result, clusters) = compile_first(DOCS);
        let c = result.unwrap();
        assert_eq!(c.rules.len(), 2);
        let r0 = &c.rules[0];
        assert_eq!(r0.matches[0].path, PathMatch::Prefix("/api".into()));
        assert_eq!(r0.matches[0].headers[0].name, "x-env");
        assert_eq!(r0.matches[0].method.as_deref(), Some("GET"));
        assert_eq!(
            r0.filters.request_headers.set,
            vec![("X-Gateway".to_string(), "gapura".to_string())]
        );
        assert_eq!(
            r0.filters.request_headers.remove,
            vec!["Cookie".to_string()]
        );
        assert_eq!(
            r0.backends,
            vec![WeightedBackend {
                cluster: Some("apps/echo:80".into()),
                weight: 3
            }]
        );
        assert_eq!(r0.timeouts.request_ms, Some(10_000));
        assert_eq!(r0.creation_timestamp, "2026-09-01T10:00:00Z");
        let r1 = &c.rules[1];
        assert_eq!(r1.matches[0].path, PathMatch::Prefix("/".into()));
        assert_eq!(r1.filters.redirect.as_ref().unwrap().status, 301);
        assert!(r1.backends.is_empty());
        assert_eq!(c.resolved_refs.status, ConditionStatus::True);
        assert_eq!(
            clusters["apps/echo:80"].endpoints,
            vec![Endpoint {
                address: "10.1.0.5".into(),
                port: 8080
            }]
        );
    }

    #[test]
    fn regex_match_compiles_into_path_match() {
        let yaml = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: r, namespace: apps }
spec:
  rules:
  - matches: [{ path: { type: RegularExpression, value: "/a.*" } }]
"#;
        let (result, _) = compile_first(yaml);
        let c = result.unwrap();
        assert_eq!(c.rules[0].matches[0].path, PathMatch::Regex("/a.*".into()));
    }

    #[test]
    fn invalid_regex_pattern_rejects_route() {
        let yaml = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: r, namespace: apps }
spec:
  rules:
  - matches: [{ path: { type: RegularExpression, value: "[unclosed" } }]
"#;
        let (result, _) = compile_first(yaml);
        assert!(
            matches!(result, Err(Unsupported(m)) if m.contains("[unclosed")),
            "an uncompilable pattern must keep the Unsupported path"
        );
    }

    #[test]
    fn replace_prefix_match_with_regex_path_rejects_route() {
        let rewrite = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: r, namespace: apps }
spec:
  rules:
  - matches: [{ path: { type: RegularExpression, value: "/a.*" } }]
    filters:
    - type: URLRewrite
      urlRewrite: { path: { type: ReplacePrefixMatch, replacePrefixMatch: /new } }
"#;
        assert!(matches!(
            compile_first(rewrite).0,
            Err(Unsupported(m)) if m.contains("ReplacePrefixMatch")
        ));
        let redirect = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: r, namespace: apps }
spec:
  rules:
  - matches: [{ path: { type: RegularExpression, value: "/a.*" } }]
    filters:
    - type: RequestRedirect
      requestRedirect: { path: { type: ReplacePrefixMatch, replacePrefixMatch: /new } }
"#;
        assert!(
            matches!(compile_first(redirect).0, Err(Unsupported(ref m)) if m.contains("ReplacePrefixMatch")),
            "the redirect path modifier shares rewrite_path, so the same guard applies"
        );
        // The mixed case: one Exact match and one Regex match in the same rule is still rejected,
        // because the regex match leaves the prefix-to-replace undefined.
        let mixed = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: r, namespace: apps }
spec:
  rules:
  - matches:
    - { path: { type: Exact, value: /a } }
    - { path: { type: RegularExpression, value: "/b.*" } }
    filters:
    - type: URLRewrite
      urlRewrite: { path: { type: ReplacePrefixMatch, replacePrefixMatch: /new } }
"#;
        assert!(compile_first(mixed).0.is_err());
    }

    #[test]
    fn mirror_filter_compiles_with_resolved_cluster() {
        let yaml = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: r, namespace: apps, generation: 1 }
spec:
  rules:
  - matches: [{ path: { type: PathPrefix, value: /mirror } }]
    filters:
    - type: RequestMirror
      requestMirror: { backendRef: { name: shadow, port: 80 } }
    - type: RequestHeaderModifier
      requestHeaderModifier: { set: [{ name: X-Gateway, value: gapura }] }
    backendRefs: [{ name: echo, port: 80 }]
---
apiVersion: v1
kind: Service
metadata: { name: echo, namespace: apps }
spec: { ports: [{ name: http, port: 80 }] }
---
apiVersion: v1
kind: Service
metadata: { name: shadow, namespace: apps }
spec: { ports: [{ name: http, port: 80 }] }
"#;
        let (result, clusters) = compile_first(yaml);
        let c = result.unwrap();
        assert_eq!(
            c.rules[0].filters.mirror,
            Some(Mirror {
                cluster: "apps/shadow:80".into()
            })
        );
        assert_eq!(
            c.rules[0].filters.request_headers.set,
            vec![("X-Gateway".to_string(), "gapura".to_string())],
            "the header modifier coexists with the mirror"
        );
        assert_eq!(c.resolved_refs.status, ConditionStatus::True);
        assert!(clusters.contains_key("apps/shadow:80"));
    }

    #[test]
    fn second_mirror_on_a_rule_rejects_route() {
        let yaml = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: r, namespace: apps }
spec:
  rules:
  - filters:
    - { type: RequestMirror, requestMirror: { backendRef: { name: a, port: 80 } } }
    - { type: RequestMirror, requestMirror: { backendRef: { name: b, port: 80 } } }
---
apiVersion: v1
kind: Service
metadata: { name: a, namespace: apps }
spec: { ports: [{ name: http, port: 80 }] }
---
apiVersion: v1
kind: Service
metadata: { name: b, namespace: apps }
spec: { ports: [{ name: http, port: 80 }] }
"#;
        assert!(
            matches!(compile_first(yaml).0, Err(Unsupported(m)) if m.contains("once per rule")),
            "the CRD allows multiple mirrors but excuses implementations that cannot; we say so"
        );
    }

    #[test]
    fn mirror_backend_resolution_failure_flags_resolved_refs() {
        let yaml = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: r, namespace: apps, generation: 1 }
spec:
  rules:
  - matches: [{ path: { type: PathPrefix, value: /mirror } }]
    filters:
    - type: RequestMirror
      requestMirror: { backendRef: { name: ghost, port: 80 } }
    backendRefs: [{ name: echo, port: 80 }]
---
apiVersion: v1
kind: Service
metadata: { name: echo, namespace: apps }
spec: { ports: [{ name: http, port: 80 }] }
"#;
        let (result, _) = compile_first(yaml);
        let c = result.unwrap();
        assert_eq!(
            c.rules[0].filters.mirror, None,
            "the mirror is not configured"
        );
        assert_eq!(
            c.rules[0].backends[0].cluster,
            Some("apps/echo:80".into()),
            "the primary keeps serving"
        );
        assert_eq!(c.resolved_refs.status, ConditionStatus::False);
        assert_eq!(c.resolved_refs.reason, reasons::BACKEND_NOT_FOUND);
    }

    #[test]
    fn mirror_backend_weight_is_rejected() {
        let yaml = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: r, namespace: apps }
spec:
  rules:
  - filters:
    - type: RequestMirror
      requestMirror: { backendRef: { name: shadow, port: 80, weight: 5 } }
---
apiVersion: v1
kind: Service
metadata: { name: shadow, namespace: apps }
spec: { ports: [{ name: http, port: 80 }] }
"#;
        assert!(
            matches!(compile_first(yaml).0, Err(Unsupported(m)) if m.contains("weight")),
            "a weighted mirror is meaningless: all traffic is mirrored"
        );
    }

    #[test]
    fn redirect_status_codes_match_the_crd_enum() {
        for code in [301u16, 302, 303, 307, 308] {
            let yaml = format!(
                r#"
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {{ name: r, namespace: apps }}
spec:
  rules:
  - filters:
    - type: RequestRedirect
      requestRedirect: {{ statusCode: {code} }}
"#
            );
            let (result, _) = compile_first(&yaml);
            let c = result.unwrap();
            assert_eq!(c.rules[0].filters.redirect.as_ref().unwrap().status, code);
        }
        // The new codes compose with hostname and path modifiers exactly like 301 does.
        let yaml = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: r, namespace: apps }
spec:
  rules:
  - filters:
    - type: RequestRedirect
      requestRedirect:
        { hostname: new.test, statusCode: 307, path: { type: ReplaceFullPath, replaceFullPath: /moved } }
"#;
        let (result, _) = compile_first(yaml);
        let redirect = result.unwrap().rules[0].filters.redirect.clone().unwrap();
        assert_eq!(redirect.status, 307);
        assert_eq!(redirect.hostname.as_deref(), Some("new.test"));
        assert_eq!(
            redirect.path,
            Some(PathRewrite::ReplaceFullPath("/moved".into()))
        );
    }

    #[test]
    fn off_enum_redirect_status_code_rejects_route() {
        let yaml = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: r, namespace: apps }
spec:
  rules:
  - filters:
    - type: RequestRedirect
      requestRedirect: { statusCode: 306 }
"#;
        assert!(
            matches!(compile_first(yaml).0, Err(Unsupported(m)) if m.contains("306")),
            "a code outside the CRD enum must keep the Unsupported path"
        );
    }

    #[test]
    fn duplicate_filter_and_unknown_filter_reject_route() {
        let dup = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: r, namespace: apps }
spec:
  rules:
  - filters:
    - { type: RequestHeaderModifier, requestHeaderModifier: { set: [{ name: a, value: b }] } }
    - { type: RequestHeaderModifier, requestHeaderModifier: { set: [{ name: c, value: d }] } }
"#;
        assert!(compile_first(dup).0.is_err());
        let mirror = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: r, namespace: apps }
spec:
  rules:
  - filters: [{ type: RequestMirror }]
"#;
        assert!(
            matches!(compile_first(mirror).0, Err(Unsupported(m)) if m.contains("RequestMirror"))
        );
    }

    #[test]
    fn missing_backend_marks_rule_invalid_but_keeps_route() {
        let yaml = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: r, namespace: apps, generation: 1 }
spec:
  rules:
  - backendRefs: [{ name: ghost, port: 80 }]
"#;
        let (result, clusters) = compile_first(yaml);
        let c = result.unwrap();
        assert_eq!(
            c.rules[0].backends,
            vec![WeightedBackend {
                cluster: None,
                weight: 1
            }]
        );
        assert_eq!(c.resolved_refs.status, ConditionStatus::False);
        assert_eq!(c.resolved_refs.reason, reasons::BACKEND_NOT_FOUND);
        assert!(clusters.is_empty());
    }

    #[test]
    fn invalid_timeout_rejects_route() {
        let yaml = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: r, namespace: apps }
spec:
  rules:
  - timeouts: { request: "10" }
"#;
        assert!(compile_first(yaml).0.is_err());
    }

    #[test]
    fn mixed_valid_and_invalid_backends_keep_weights_and_report_first_error() {
        let yaml = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: r, namespace: apps, generation: 1 }
spec:
  rules:
  - backendRefs:
    - { name: echo, port: 80, weight: 9 }
    - { name: ghost, port: 80, weight: 1 }
---
apiVersion: v1
kind: Service
metadata: { name: echo, namespace: apps }
spec: { ports: [{ name: http, port: 80 }] }
"#;
        let (result, clusters) = compile_first(yaml);
        let c = result.unwrap();
        assert_eq!(
            c.rules[0].backends,
            vec![
                WeightedBackend {
                    cluster: Some("apps/echo:80".into()),
                    weight: 9
                },
                WeightedBackend {
                    cluster: None,
                    weight: 1
                },
            ]
        );
        assert_eq!(c.resolved_refs.status, ConditionStatus::False);
        assert_eq!(c.resolved_refs.reason, reasons::BACKEND_NOT_FOUND);
        assert!(
            clusters["apps/echo:80"].endpoints.is_empty(),
            "no EndpointSlice -> empty cluster, 503 at runtime"
        );
    }

    #[test]
    fn url_rewrite_compiles_prefix_and_full_path_variants() {
        let yaml = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: r, namespace: apps }
spec:
  rules:
  - matches: [{ path: { type: PathPrefix, value: /old } }]
    filters:
    - type: URLRewrite
      urlRewrite: { hostname: internal.svc, path: { type: ReplacePrefixMatch, replacePrefixMatch: /new } }
  - filters:
    - type: URLRewrite
      urlRewrite: { path: { type: ReplaceFullPath, replaceFullPath: /index.html } }
"#;
        let (result, _) = compile_first(yaml);
        let c = result.unwrap();
        assert_eq!(
            c.rules[0].filters.rewrite,
            Some(Rewrite {
                hostname: Some("internal.svc".into()),
                path: Some(PathRewrite::ReplacePrefixMatch("/new".into()))
            })
        );
        assert_eq!(
            c.rules[1].filters.rewrite,
            Some(Rewrite {
                hostname: None,
                path: Some(PathRewrite::ReplaceFullPath("/index.html".into()))
            })
        );
        assert!(c.rules[0].filters.redirect.is_none());
    }
}

/// The request limit a rule's backend Service asks for, from `gapura.dev/rate-limit` ("20/min";
/// seconds, minutes or hours). The first backend Service carrying the annotation wins, in
/// backendRef order -- a rule with several annotated backends is a config mistake, and one
/// answer beats several. `gapura.dev/rate-limit-by` accepts only `ip`, the client address after
/// the trusted-proxy walk; any other value disables the pair with a warning rather than
/// silently keying by something unreviewed.
fn rate_limit_of(snap: &Snapshot, route_ns: &str, refs: &[HttpBackendRef]) -> Option<RateLimit> {
    for b in refs {
        let ns = b.namespace.as_deref().unwrap_or(route_ns);
        let Some(svc) = snap.services.get(&ObjectRef::new(ns, &b.name)) else {
            continue;
        };
        let Some(value) = svc.metadata.annotations.get(RATE_LIMIT_ANNOTATION) else {
            continue;
        };
        // An unsupported by-key or an unparseable value disables the pair: the route keeps
        // serving, unlimited. core has no logging -- the translator's failure channel is
        // conditions, and a mispriced limit is not a routing failure -- so this is silent
        // here and stated plainly in the docs.
        if let Some(by) = svc.metadata.annotations.get(RATE_LIMIT_BY_ANNOTATION) {
            if by != "ip" {
                return None;
            }
        }
        return parse_rate_limit(value);
    }
    None
}

fn parse_rate_limit(value: &str) -> Option<RateLimit> {
    let (count, unit) = value.split_once('/')?;
    let limit = count.trim().parse::<u32>().ok().filter(|l| *l > 0)?;
    let window_ms = match unit.trim() {
        "s" => 1_000,
        "min" => 60_000,
        "h" => 3_600_000,
        _ => return None,
    };
    Some(RateLimit { limit, window_ms })
}

#[cfg(test)]
mod rate_limit_tests {
    use super::*;

    #[test]
    fn units_parse_and_zero_or_garbage_do_not() {
        assert_eq!(
            parse_rate_limit("20/min"),
            Some(RateLimit {
                limit: 20,
                window_ms: 60_000
            })
        );
        assert_eq!(
            parse_rate_limit("1/s"),
            Some(RateLimit {
                limit: 1,
                window_ms: 1_000
            })
        );
        assert_eq!(
            parse_rate_limit("5/h"),
            Some(RateLimit {
                limit: 5,
                window_ms: 3_600_000
            })
        );
        assert_eq!(parse_rate_limit("0/min"), None);
        assert_eq!(parse_rate_limit("20"), None);
        assert_eq!(parse_rate_limit("soon"), None);
        assert_eq!(parse_rate_limit("20/fortnight"), None);
    }
}
