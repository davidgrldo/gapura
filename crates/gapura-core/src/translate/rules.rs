//! Step 3a of translation: HTTPRoute rules -> RouteRule (matches, filters, backends, timeouts).
//! Any unsupported value rejects the whole route (Gateway API: Accepted=False, UnsupportedValue).

use std::collections::{BTreeMap, BTreeSet};

use crate::config::{
    Cluster, Filters, HeaderOps, KvMatch, PathMatch, PathRewrite, Redirect, Rewrite, RouteMatch,
    RouteRule, Timeouts, WeightedBackend,
};
use crate::duration;
use crate::input::{
    HeaderModifier, HttpRoute, HttpRouteFilter, HttpRouteMatch, PathModifier, RequestRedirect,
    UrlRewrite,
};
use crate::snapshot::{ObjectRef, Snapshot};
use crate::status::{reasons, types, Condition, ConditionStatus};
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
        let filters = compile_filters(&r.filters)?;
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

fn compile_filters(filters: &[HttpRouteFilter]) -> Result<Filters, Unsupported> {
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
            other => return Err(Unsupported(format!("filter type {other} is not supported"))),
        }
    }
    if out.redirect.is_some() && out.rewrite.is_some() {
        return Err(Unsupported(
            "RequestRedirect and URLRewrite cannot be combined in one rule".to_string(),
        ));
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
    if status != 301 && status != 302 {
        return Err(Unsupported(format!(
            "redirect statusCode {status} is not supported, use 301 or 302"
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
    fn regex_match_rejects_route() {
        let yaml = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: r, namespace: apps }
spec:
  rules:
  - matches: [{ path: { type: RegularExpression, value: "/a.*" } }]
"#;
        let (result, _) = compile_first(yaml);
        assert!(matches!(result, Err(Unsupported(m)) if m.contains("RegularExpression")));
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
