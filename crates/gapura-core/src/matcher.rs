//! Request matching over a translated Config: match the port's table, pick the TLS cert, find the rule.

use std::collections::HashMap;
use std::sync::Arc;

use crate::config::{
    Config, ListenerConfig, PathMatch, PortEntry, RouteMatch, RouteRule, TlsBundle,
};
use crate::hostname;

/// Compiled `PathMatch::Regex` patterns of one Config, keyed by pattern string so identical
/// patterns are compiled once. Built per generation by the data plane (see `compile_regexes`),
/// next to the round-robin cursors and parsed TLS certs.
pub type RegexMap = HashMap<String, Arc<regex::Regex>>;

/// Compile every `PathMatch::Regex` pattern of the port tables into a side map, and report the
/// patterns that could not be compiled (deduped like the map).
///
/// Translation validates each pattern before it reaches a Config, so a non-empty Vec means that
/// invariant regressed; the caller that owns logging should say so. The pattern matches nothing
/// either way, mirroring how the matcher treats a map miss.
pub fn compile_regexes(config: &Config) -> (RegexMap, Vec<String>) {
    let mut out = RegexMap::new();
    let mut skipped = Vec::new();
    for entries in config.ports.values() {
        for e in entries {
            let PathMatch::Regex(pattern) = &e.matcher.path else {
                continue;
            };
            if out.contains_key(pattern) || skipped.iter().any(|s| s == pattern) {
                continue;
            }
            match regex::Regex::new(pattern) {
                Ok(re) => {
                    out.insert(pattern.clone(), Arc::new(re));
                }
                Err(_) => skipped.push(pattern.clone()),
            }
        }
    }
    (out, skipped)
}

/// What the proxy extracts from a request before matching.
///
/// Borrowed `(name, value)` slices keep this type simple; the planned proxy (Plan 2) is expected to
/// collect headers and query pairs into `Vec`s per request. If that shows up in profiles, a later revision can borrow
/// straight from the server's header map instead of changing the matching logic.
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

/// The winning entry on a port, with the listener it belongs to and the rule it points at.
#[derive(Debug)]
pub struct PortMatch<'a> {
    /// Index into `Config::listeners`, for the proxy's per-request state.
    pub listener_index: usize,
    pub listener: &'a ListenerConfig,
    pub entry: &'a PortEntry,
    pub rule: &'a RouteRule,
}

impl Config {
    /// First entry of the port's precedence-sorted table that matches this request.
    ///
    /// The table spans every programmed listener on the port, so a request is served by the most
    /// specific listener hostname first and then by normal route precedence, whichever Gateway the
    /// route came from. Two identical entries from two Gateways are ordered by listener id, which
    /// is arbitrary but stable: no single-address data plane can tell those two requests apart.
    pub fn match_port_with(
        &self,
        port: u16,
        req: &RequestAttrs<'_>,
        regexes: &RegexMap,
    ) -> Option<PortMatch<'_>> {
        let entry = self.ports.get(&port)?.iter().find(|e| {
            e.hostname
                .as_deref()
                .is_none_or(|h| hostname::matches(h, req.host))
                && matches(&e.matcher, req, regexes)
        })?;
        let listener = self.listeners.get(entry.listener)?;
        let rule = listener.rules.get(entry.rule)?;
        Some(PortMatch {
            listener_index: entry.listener,
            listener,
            entry,
            rule,
        })
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

/// PathPrefix matches on `/` boundaries: `/api` matches `/api` and `/api/x`, not `/apix`.
/// RegularExpression matches the RAW request path, no percent-decoding, like Exact/Prefix.
fn matches(m: &RouteMatch, req: &RequestAttrs<'_>, regexes: &RegexMap) -> bool {
    let path_ok = match &m.path {
        PathMatch::Exact(p) => req.path == p,
        PathMatch::Prefix(p) => {
            p == "/"
                || req.path == p
                || (req.path.starts_with(p.as_str())
                    && req.path.as_bytes().get(p.len()) == Some(&b'/'))
        }
        // A pattern missing from the map could not be compiled (see `compile_regexes`); the
        // data plane treats it as a no-match instead of panicking on a request.
        PathMatch::Regex(p) => regexes.get(p).is_some_and(|re| re.is_match(req.path)),
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
    use super::*;
    use crate::config::{
        Cluster, Filters, KvMatch, ListenerConfig, PortEntry, Protocol, RouteRule, Timeouts,
        WeightedBackend,
    };
    use std::collections::BTreeMap;

    fn rule(route: &str, m: RouteMatch) -> RouteRule {
        RouteRule {
            route: route.to_string(),
            rule_index: 0,
            creation_timestamp: "2026-01-01T00:00:00Z".to_string(),
            matches: vec![m],
            filters: Filters::default(),
            backends: vec![WeightedBackend {
                cluster: Some("apps/echo:80".to_string()),
                weight: 1,
            }],
            timeouts: Timeouts::default(),
        }
    }

    fn m(path: &str) -> RouteMatch {
        RouteMatch {
            path: PathMatch::Prefix(path.to_string()),
            headers: vec![],
            query: vec![],
            method: None,
        }
    }

    fn listener(
        id: &str,
        port: u16,
        hostname: Option<&str>,
        rules: Vec<RouteRule>,
    ) -> ListenerConfig {
        ListenerConfig {
            id: id.to_string(),
            port,
            protocol: if port == 443 {
                Protocol::Https
            } else {
                Protocol::Http
            },
            hostname: hostname.map(str::to_string),
            tls: None,
            rules,
        }
    }

    /// Build the per-port index the way `translate::assemble` does: one entry per (listener, rule,
    /// match), hostname taken from the listener because these fixtures have no route hostnames.
    fn index(listeners: &[ListenerConfig]) -> BTreeMap<u16, Vec<PortEntry>> {
        let mut ports: BTreeMap<u16, Vec<PortEntry>> = BTreeMap::new();
        for (i, l) in listeners.iter().enumerate() {
            for (r, rule) in l.rules.iter().enumerate() {
                for matcher in &rule.matches {
                    ports.entry(l.port).or_default().push(PortEntry {
                        listener: i,
                        hostname: l.hostname.clone(),
                        matcher: matcher.clone(),
                        rule: r,
                    });
                }
            }
        }
        for entries in ports.values_mut() {
            crate::translate::sort_port_table_for_tests(entries, listeners);
        }
        ports
    }

    fn config() -> Config {
        let listeners = vec![
            listener("infra/gw/http", 80, None, vec![rule("apps/any", m("/"))]),
            listener(
                "infra/gw/wild",
                443,
                Some("*.example.com"),
                vec![rule("apps/wild", m("/"))],
            ),
            listener(
                "infra/gw/exact",
                443,
                Some("api.example.com"),
                vec![rule("apps/exact", m("/"))],
            ),
            listener(
                "infra/gw/any",
                443,
                None,
                vec![rule("apps/fallback", m("/"))],
            ),
        ];
        Config {
            ports: index(&listeners),
            listeners,
            clusters: BTreeMap::from([("apps/echo:80".to_string(), Cluster::default())]),
        }
    }

    fn req<'a>(path: &'a str, headers: &'a [(String, String)]) -> RequestAttrs<'a> {
        RequestAttrs {
            host: "api.example.com",
            path,
            method: "GET",
            headers,
            query: &[],
        }
    }

    #[test]
    fn most_specific_listener_hostname_wins_on_a_shared_port() {
        let c = config();
        let (re, _) = compile_regexes(&c);
        let hit = c
            .match_port_with(443, &req("/", &[]), &re)
            .expect("a listener matches");
        assert_eq!(hit.listener.id, "infra/gw/exact");
        assert_eq!(hit.rule.route, "apps/exact");

        let other = RequestAttrs {
            host: "shop.example.com",
            ..req("/", &[])
        };
        assert_eq!(
            c.match_port_with(443, &other, &re)
                .expect("wildcard matches")
                .listener
                .id,
            "infra/gw/wild"
        );

        let unrelated = RequestAttrs {
            host: "nope.test",
            ..req("/", &[])
        };
        assert_eq!(
            c.match_port_with(443, &unrelated, &re)
                .expect("hostname-less listener catches the rest")
                .listener
                .id,
            "infra/gw/any"
        );
    }

    #[test]
    fn a_port_with_no_listener_matches_nothing() {
        let c = config();
        let (re, _) = compile_regexes(&c);
        assert!(c.match_port_with(8080, &req("/", &[]), &re).is_none());
    }

    #[test]
    fn routes_of_every_listener_on_the_port_are_reachable() {
        // Two Gateways, neither with a hostname, distinct paths: both must be served. This is the
        // case `select_listener` used to lose, and the reason this index exists.
        let listeners = vec![
            listener("a/gw/http", 80, None, vec![rule("apps/first", m("/first"))]),
            listener(
                "b/gw/http",
                80,
                None,
                vec![rule("apps/second", m("/second"))],
            ),
        ];
        let c = Config {
            ports: index(&listeners),
            listeners,
            clusters: BTreeMap::new(),
        };
        let (re, _) = compile_regexes(&c);
        let first = c.match_port_with(
            80,
            &RequestAttrs {
                host: "any.test",
                path: "/first",
                method: "GET",
                headers: &[],
                query: &[],
            },
            &re,
        );
        assert_eq!(first.expect("first is reachable").rule.route, "apps/first");
        let second = c.match_port_with(
            80,
            &RequestAttrs {
                host: "any.test",
                path: "/second",
                method: "GET",
                headers: &[],
                query: &[],
            },
            &re,
        );
        assert_eq!(
            second.expect("second is reachable").rule.route,
            "apps/second"
        );
    }

    #[test]
    fn first_match_and_prefix_boundaries() {
        let listeners = vec![listener(
            "infra/gw/http",
            80,
            None,
            vec![rule("apps/api", m("/api")), rule("apps/root", m("/"))],
        )];
        let c = Config {
            ports: index(&listeners),
            listeners,
            clusters: BTreeMap::new(),
        };
        let (re, _) = compile_regexes(&c);
        let at = |p: &str| {
            c.match_port_with(
                80,
                &RequestAttrs {
                    host: "any.test",
                    path: p,
                    method: "GET",
                    headers: &[],
                    query: &[],
                },
                &re,
            )
            .map(|h| h.rule.route.clone())
        };
        assert_eq!(at("/api").as_deref(), Some("apps/api"));
        assert_eq!(at("/api/x").as_deref(), Some("apps/api"));
        assert_eq!(
            at("/apix").as_deref(),
            Some("apps/root"),
            "a prefix only matches on / boundaries"
        );
        assert_eq!(at("/other").as_deref(), Some("apps/root"));
    }

    #[test]
    fn header_matching_is_case_insensitive_on_the_name_and_exact_on_the_value() {
        let mut with_header = m("/");
        with_header.headers = vec![KvMatch {
            name: "x-version".into(),
            value: "2".into(),
        }];
        let listeners = vec![listener(
            "infra/gw/http",
            80,
            None,
            vec![rule("apps/v2", with_header), rule("apps/any", m("/"))],
        )];
        let c = Config {
            ports: index(&listeners),
            listeners,
            clusters: BTreeMap::new(),
        };
        let (re, _) = compile_regexes(&c);
        let at = |headers: &[(String, String)]| {
            c.match_port_with(
                80,
                &RequestAttrs {
                    host: "any.test",
                    path: "/",
                    method: "GET",
                    headers,
                    query: &[],
                },
                &re,
            )
            .map(|h| h.rule.route.clone())
        };
        assert_eq!(
            at(&[("X-Version".to_string(), "2".to_string())]).as_deref(),
            Some("apps/v2"),
            "the header name compares case-insensitively"
        );
        assert_eq!(
            at(&[("x-version".to_string(), "3".to_string())]).as_deref(),
            Some("apps/any"),
            "the value compares exactly"
        );
        assert_eq!(at(&[]).as_deref(), Some("apps/any"));
    }

    #[test]
    fn a_populated_port_can_still_match_nothing() {
        let listeners = vec![listener(
            "infra/gw/http",
            80,
            Some("only.example.com"),
            vec![rule("apps/only", m("/api"))],
        )];
        let c = Config {
            ports: index(&listeners),
            listeners,
            clusters: BTreeMap::new(),
        };
        let (re, _) = compile_regexes(&c);
        let miss = |host: &str, path: &str| {
            c.match_port_with(
                80,
                &RequestAttrs {
                    host,
                    path,
                    method: "GET",
                    headers: &[],
                    query: &[],
                },
                &re,
            )
            .is_none()
        };
        assert!(miss("other.example.com", "/api"), "the hostname must match");
        assert!(miss("only.example.com", "/other"), "the path must match");
        assert!(!miss("only.example.com", "/api"));
    }

    #[test]
    fn method_and_query_matching() {
        let mut with_method = m("/");
        with_method.method = Some("POST".to_string());
        with_method.query = vec![KvMatch {
            name: "v".into(),
            value: "2".into(),
        }];
        let listeners = vec![listener(
            "infra/gw/http",
            80,
            None,
            vec![rule("apps/post", with_method), rule("apps/any", m("/"))],
        )];
        let c = Config {
            ports: index(&listeners),
            listeners,
            clusters: BTreeMap::new(),
        };
        let (re, _) = compile_regexes(&c);
        let post = RequestAttrs {
            host: "any.test",
            path: "/",
            method: "post",
            headers: &[],
            query: &[("v".to_string(), "2".to_string())],
        };
        assert_eq!(
            c.match_port_with(80, &post, &re).unwrap().rule.route,
            "apps/post",
            "method compares case-insensitively"
        );
        let get = RequestAttrs {
            method: "GET",
            ..post.clone()
        };
        assert_eq!(
            c.match_port_with(80, &get, &re).unwrap().rule.route,
            "apps/any"
        );
    }

    #[test]
    fn tls_for_sni_then_fallbacks() {
        // Unchanged behaviour, kept because the SNI resolver depends on it.
        let mut listeners = vec![
            listener("infra/gw/wild", 443, Some("*.example.com"), vec![]),
            listener("infra/gw/exact", 443, Some("api.example.com"), vec![]),
            listener("infra/gw/any", 443, None, vec![]),
        ];
        for (i, l) in listeners.iter_mut().enumerate() {
            l.tls = Some(crate::config::TlsBundle {
                secret: format!("infra/secret-{i}"),
                cert_pem: "CERT".into(),
                key_pem: "KEY".into(),
            });
        }
        let c = Config {
            ports: index(&listeners),
            listeners,
            clusters: BTreeMap::new(),
        };
        assert_eq!(
            c.tls_for(443, Some("api.example.com")).unwrap().secret,
            "infra/secret-1"
        );
        assert_eq!(
            c.tls_for(443, Some("shop.example.com")).unwrap().secret,
            "infra/secret-0"
        );
        assert_eq!(
            c.tls_for(443, Some("nope.test")).unwrap().secret,
            "infra/secret-2"
        );
        assert_eq!(c.tls_for(443, None).unwrap().secret, "infra/secret-2");
        assert!(c.tls_for(80, None).is_none());
    }

    #[test]
    fn regex_match_hits_and_misses_against_the_raw_path() {
        let mut rx = m("/static");
        rx.path = PathMatch::Regex("^/api/v[0-9]+/".to_string());
        let listeners = vec![listener(
            "infra/gw/http",
            80,
            None,
            vec![rule("apps/regex", rx), rule("apps/static", m("/static"))],
        )];
        let c = Config {
            ports: index(&listeners),
            listeners,
            clusters: BTreeMap::new(),
        };
        let (regexes, _) = compile_regexes(&c);
        let at = |p: &str| {
            c.match_port_with(
                80,
                &RequestAttrs {
                    host: "any.test",
                    path: p,
                    method: "GET",
                    headers: &[],
                    query: &[],
                },
                &regexes,
            )
            .map(|h| h.rule.route.clone())
        };
        assert_eq!(at("/api/v1/x").as_deref(), Some("apps/regex"));
        assert_eq!(at("/api/v42/").as_deref(), Some("apps/regex"));
        assert_eq!(
            at("/api/vx/1").as_deref(),
            None,
            "the pattern does not match, so nothing else catches it"
        );
        assert_eq!(at("/static/x").as_deref(), Some("apps/static"));
        assert_eq!(
            at("/api%2Fv1/x").as_deref(),
            None,
            "matching runs on the raw path, no percent-decoding"
        );
    }

    #[test]
    fn regex_loses_to_exact_and_prefix_no_matter_the_pattern_length() {
        let mut rx_long = m("/");
        rx_long.path = PathMatch::Regex("^/api/v[0-9]+/very/long/pattern".to_string());
        let mut rx_short = m("/");
        rx_short.path = PathMatch::Regex("^/api".to_string());
        let listeners = vec![listener(
            "infra/gw/http",
            80,
            None,
            vec![
                rule("apps/regex-long", rx_long),
                rule("apps/regex-short", rx_short),
                rule("apps/prefix", m("/api")),
                rule("apps/exact", {
                    let mut e = m("/");
                    e.path = PathMatch::Exact("/api/v1".to_string());
                    e
                }),
            ],
        )];
        let c = Config {
            ports: index(&listeners),
            listeners,
            clusters: BTreeMap::new(),
        };
        let (regexes, _) = compile_regexes(&c);
        let hit = c
            .match_port_with(
                80,
                &RequestAttrs {
                    host: "any.test",
                    path: "/api/v1",
                    method: "GET",
                    headers: &[],
                    query: &[],
                },
                &regexes,
            )
            .expect("several entries match");
        assert_eq!(
            hit.rule.route, "apps/exact",
            "Exact wins even though both regex patterns also match"
        );
        // Without the exact rule, the prefix beats both regexes.
        let mut trimmed = c.clone();
        trimmed.ports.get_mut(&80).unwrap().retain(|e| e.rule != 3);
        let hit = trimmed
            .match_port_with(
                80,
                &RequestAttrs {
                    host: "any.test",
                    path: "/api/v1",
                    method: "GET",
                    headers: &[],
                    query: &[],
                },
                &regexes,
            )
            .expect("prefix and regexes match");
        assert_eq!(hit.rule.route, "apps/prefix");
    }

    #[test]
    fn compile_regexes_walks_the_port_tables_and_dedupes() {
        let mut rx = m("/");
        rx.path = PathMatch::Regex("^/dup".to_string());
        let mut bad = m("/");
        bad.path = PathMatch::Regex("[unclosed".to_string());
        let listeners = vec![listener(
            "infra/gw/http",
            80,
            None,
            vec![
                rule("apps/a", rx.clone()),
                rule("apps/b", rx),
                rule("apps/c", bad.clone()),
                rule("apps/d", bad),
            ],
        )];
        let c = Config {
            ports: index(&listeners),
            listeners,
            clusters: BTreeMap::new(),
        };
        let (regexes, skipped) = compile_regexes(&c);
        assert_eq!(regexes.len(), 1, "identical patterns share one entry");
        assert!(regexes.contains_key("^/dup"));
        assert_eq!(
            skipped,
            vec!["[unclosed".to_string()],
            "the uncompilable pattern is named once, deduped like the map"
        );
    }

    proptest::proptest! {
        #[test]
        fn matching_never_panics(host in "[a-z0-9.*-]{0,24}", path in "[a-zA-Z0-9/._%-]{0,40}", method in "[A-Z]{0,7}") {
            let c = config();
            let (re, _) = compile_regexes(&c);
            for port in [80u16, 443] {
                let _ = c.match_port_with(port, &RequestAttrs { host: &host, path: &path, method: &method, headers: &[], query: &[] }, &re);
                let _ = c.tls_for(port, Some(&host));
            }
        }

        #[test]
        fn matching_with_headers_and_query_never_panics(
            host in "[a-z0-9.*-]{0,24}",
            path in "[a-zA-Z0-9/._%-]{0,40}",
            headers in proptest::collection::vec(("[a-z-]{1,8}", "[a-zA-Z0-9]{0,8}"), 0..=3),
            query in proptest::collection::vec(("[a-z-]{1,8}", "[a-zA-Z0-9]{0,8}"), 0..=3),
        ) {
            let c = config();
            let (re, _) = compile_regexes(&c);
            for port in [80u16, 443] {
                let _ = c.match_port_with(port, &RequestAttrs { host: &host, path: &path, method: "GET", headers: &headers, query: &query }, &re);
            }
        }
    }
}
