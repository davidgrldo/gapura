//! Request matching over a translated Config: pick the listener, pick the TLS cert, find the rule.

use crate::config::{Config, ListenerConfig, PathMatch, RouteMatch, RouteRule, TlsBundle};
use crate::hostname;

/// What the proxy extracts from a request before matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestAttrs<'a> {
    /// Host without port, any case.
    pub host: &'a str,
    /// Path only, no query string.
    pub path: &'a str,
    pub method: &'a str,
    /// Header names in any case, compared case-insensitively. First occurrence of a name wins.
    pub headers: &'a [(String, String)],
    /// Query parameters in request order. First occurrence of a name wins.
    pub query: &'a [(String, String)],
}

impl Config {
    /// The listener serving `port` for `host`: hostname must match (or be absent); the most specific wins.
    pub fn select_listener(&self, port: u16, host: &str) -> Option<&ListenerConfig> {
        self.listeners
            .iter()
            .filter(|l| {
                l.port == port
                    && l.hostname
                        .as_deref()
                        .is_none_or(|h| hostname::matches(h, host))
            })
            .max_by_key(|l| hostname::specificity(l.hostname.as_deref()))
    }

    /// Certificate for a TLS handshake on `port` with the given SNI: the most specific matching listener
    /// hostname, else a listener without hostname, else the first certificate on the port.
    pub fn tls_for(&self, port: u16, sni: Option<&str>) -> Option<&TlsBundle> {
        let on_port = || {
            self.listeners
                .iter()
                .filter(move |l| l.port == port && l.tls.is_some())
        };
        if let Some(name) = sni {
            let best = on_port()
                .filter(|l| {
                    l.hostname
                        .as_deref()
                        .is_some_and(|h| hostname::matches(h, name))
                })
                .max_by_key(|l| hostname::specificity(l.hostname.as_deref()));
            if let Some(l) = best {
                return l.tls.as_ref();
            }
        }
        on_port()
            .find(|l| l.hostname.is_none())
            .or_else(|| on_port().next())
            .and_then(|l| l.tls.as_ref())
    }
}

impl ListenerConfig {
    /// First entry of the precedence-sorted table that matches the request.
    pub fn match_request(&self, req: &RequestAttrs<'_>) -> Option<&RouteRule> {
        self.table
            .iter()
            .find(|e| {
                e.hostname
                    .as_deref()
                    .is_none_or(|h| hostname::matches(h, req.host))
                    && matches(&e.matcher, req)
            })
            .map(|e| &self.rules[e.rule])
    }
}

/// PathPrefix matches on `/` boundaries: `/api` matches `/api` and `/api/x`, not `/apix`.
fn matches(m: &RouteMatch, req: &RequestAttrs<'_>) -> bool {
    let path_ok = match &m.path {
        PathMatch::Exact(p) => req.path == p,
        PathMatch::Prefix(p) => {
            p == "/"
                || req.path == p
                || (req.path.starts_with(p.as_str())
                    && req.path.as_bytes().get(p.len()) == Some(&b'/'))
        }
    };
    path_ok
        && m.method
            .as_deref()
            .is_none_or(|method| method.eq_ignore_ascii_case(req.method))
        && m.headers.iter().all(|h| {
            req.headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(&h.name))
                .is_some_and(|(_, v)| *v == h.value)
        })
        && m.query.iter().all(|q| {
            req.query
                .iter()
                .find(|(n, _)| *n == q.name)
                .is_some_and(|(_, v)| *v == q.value)
        })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::config::{Filters, KvMatch, MatchEntry, Protocol, Timeouts};

    fn rule(route: &str, m: RouteMatch) -> RouteRule {
        RouteRule {
            route: route.into(),
            rule_index: 0,
            creation_timestamp: String::new(),
            matches: vec![m],
            filters: Filters::default(),
            backends: vec![],
            timeouts: Timeouts::default(),
        }
    }

    fn m(path: PathMatch) -> RouteMatch {
        RouteMatch {
            path,
            headers: vec![],
            query: vec![],
            method: None,
        }
    }

    fn listener(
        id: &str,
        port: u16,
        hostname: Option<&str>,
        tls: bool,
        rules: Vec<RouteRule>,
    ) -> ListenerConfig {
        let table = rules
            .iter()
            .enumerate()
            .map(|(i, r)| MatchEntry {
                hostname: None,
                matcher: r.matches[0].clone(),
                rule: i,
            })
            .collect();
        ListenerConfig {
            id: id.into(),
            port,
            protocol: if tls { Protocol::Https } else { Protocol::Http },
            hostname: hostname.map(String::from),
            tls: tls.then(|| TlsBundle {
                secret: format!("s/{id}"),
                cert_pem: "c".into(),
                key_pem: "k".into(),
            }),
            rules,
            table,
        }
    }

    /// Table already in precedence order (Task 10 guarantees this in real configs).
    fn config() -> Config {
        let exact = rule("apps/a", m(PathMatch::Exact("/api/v1".into())));
        let prefix_hdr = rule(
            "apps/b",
            RouteMatch {
                path: PathMatch::Prefix("/api".into()),
                headers: vec![KvMatch {
                    name: "x-version".into(),
                    value: "2".into(),
                }],
                query: vec![],
                method: None,
            },
        );
        let prefix = rule("apps/c", m(PathMatch::Prefix("/api".into())));
        Config {
            listeners: vec![
                listener(
                    "infra/gw/http",
                    80,
                    None,
                    false,
                    vec![exact, prefix_hdr, prefix],
                ),
                listener("infra/gw/wild", 443, Some("*.example.com"), true, vec![]),
                listener("infra/gw/exact", 443, Some("api.example.com"), true, vec![]),
                listener("infra/gw/any", 443, None, true, vec![]),
            ],
            clusters: BTreeMap::new(),
        }
    }

    fn req<'a>(path: &'a str, headers: &'a [(String, String)]) -> RequestAttrs<'a> {
        RequestAttrs {
            host: "echo.example.com",
            path,
            method: "GET",
            headers,
            query: &[],
        }
    }

    #[test]
    fn select_listener_prefers_most_specific_hostname() {
        let c = config();
        assert_eq!(
            c.select_listener(443, "api.example.com").unwrap().id,
            "infra/gw/exact"
        );
        assert_eq!(
            c.select_listener(443, "foo.example.com").unwrap().id,
            "infra/gw/wild"
        );
        assert_eq!(
            c.select_listener(443, "other.org").unwrap().id,
            "infra/gw/any"
        );
        assert!(c.select_listener(8443, "api.example.com").is_none());
    }

    #[test]
    fn tls_for_sni_then_fallbacks() {
        let c = config();
        assert_eq!(
            c.tls_for(443, Some("api.example.com")).unwrap().secret,
            "s/infra/gw/exact"
        );
        assert_eq!(
            c.tls_for(443, Some("x.example.com")).unwrap().secret,
            "s/infra/gw/wild"
        );
        assert_eq!(
            c.tls_for(443, Some("nomatch.org")).unwrap().secret,
            "s/infra/gw/any"
        );
        assert_eq!(c.tls_for(443, None).unwrap().secret, "s/infra/gw/any");
        assert!(c.tls_for(80, None).is_none());
    }

    #[test]
    fn match_request_first_match_and_prefix_boundaries() {
        let c = config();
        let l = c.select_listener(80, "echo.example.com").unwrap();
        assert_eq!(
            l.match_request(&req("/api/v1", &[])).unwrap().route,
            "apps/a"
        );
        let hdr = [("X-Version".to_string(), "2".to_string())];
        assert_eq!(
            l.match_request(&req("/api/v2", &hdr)).unwrap().route,
            "apps/b"
        );
        assert_eq!(
            l.match_request(&req("/api/v2", &[])).unwrap().route,
            "apps/c"
        );
        assert_eq!(l.match_request(&req("/api", &[])).unwrap().route, "apps/c");
        assert!(l.match_request(&req("/apiv2", &[])).is_none());
        assert!(l.match_request(&req("/", &[])).is_none());
    }

    #[test]
    fn method_and_query_matching() {
        let r = RouteMatch {
            path: PathMatch::Prefix("/".into()),
            headers: vec![],
            query: vec![KvMatch {
                name: "v".into(),
                value: "1".into(),
            }],
            method: Some("POST".into()),
        };
        let q = [
            ("v".to_string(), "1".to_string()),
            ("v".to_string(), "2".to_string()),
        ];
        let ok = RequestAttrs {
            host: "h",
            path: "/x",
            method: "post",
            headers: &[],
            query: &q,
        };
        assert!(matches(&r, &ok));
        assert!(!matches(
            &r,
            &RequestAttrs {
                method: "GET",
                ..ok.clone()
            }
        ));
        let q2 = [
            ("v".to_string(), "2".to_string()),
            ("v".to_string(), "1".to_string()),
        ];
        assert!(
            !matches(
                &r,
                &RequestAttrs {
                    query: &q2,
                    ..ok.clone()
                }
            ),
            "only the first occurrence of a query name counts"
        );
    }

    proptest::proptest! {
        #[test]
        fn matching_never_panics(host in "[a-z0-9.*-]{0,24}", path in "[a-zA-Z0-9/._%-]{0,40}", method in "[A-Z]{0,7}") {
            let c = config();
            for port in [80u16, 443] {
                if let Some(l) = c.select_listener(port, &host) {
                    let _ = l.match_request(&RequestAttrs { host: &host, path: &path, method: &method, headers: &[], query: &[] });
                }
                let _ = c.tls_for(port, Some(&host));
            }
        }
    }
}
