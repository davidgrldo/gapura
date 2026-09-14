//! Gateway API match precedence, used to sort each port's match table once after translation.
//! Order: hostname specificity (exact > wildcard, more labels first) > path Exact > longer PathPrefix >
//! longer RegularExpression pattern (the least specific path type) > has method > more header matches >
//! more query matches > older route > namespace/name > rule index >
//! listener id. The last key only decides between two Gateways that attached the same route to the
//! same port, where nothing in the request can tell them apart; it keeps the order stable instead of
//! leaving it to hash or iteration order.
//! Routes without creationTimestamp sort as the oldest (empty string); real clusters always stamp it.

use std::cmp::Reverse;

use crate::config::{ListenerConfig, PathMatch, PortEntry, RouteMatch, RouteRule};
use crate::hostname;

type Key = (
    Reverse<(u8, usize)>,
    Reverse<u8>,
    Reverse<usize>,
    Reverse<u8>,
    Reverse<usize>,
    Reverse<usize>,
    String,
    String,
    usize,
    String,
);

fn key(hostname_: Option<&str>, matcher: &RouteMatch, rule: &RouteRule, listener_id: &str) -> Key {
    let (path_kind, path_len) = match &matcher.path {
        PathMatch::Exact(p) => (2u8, p.len()),
        PathMatch::Prefix(p) => (1u8, p.len()),
        // Gateway API precedence: a regex is the least specific path match type.
        PathMatch::Regex(p) => (0u8, p.len()),
    };
    (
        Reverse(hostname::specificity(hostname_)),
        Reverse(path_kind),
        Reverse(path_len),
        Reverse(u8::from(matcher.method.is_some())),
        Reverse(matcher.headers.len()),
        Reverse(matcher.query.len()),
        rule.creation_timestamp.clone(),
        rule.route.clone(),
        rule.rule_index,
        listener_id.to_string(),
    )
}

/// Sort one port's table in place so the first matching entry is the winner.
pub(crate) fn sort_port_table(entries: &mut [PortEntry], listeners: &[ListenerConfig]) {
    entries.sort_by_cached_key(|e| {
        let l = &listeners[e.listener];
        key(e.hostname.as_deref(), &e.matcher, &l.rules[e.rule], &l.id)
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Filters, KvMatch, Protocol, Timeouts};

    fn rule(
        route: &str,
        created: &str,
        path: PathMatch,
        headers: usize,
        method: bool,
    ) -> RouteRule {
        rule_with_query(route, created, path, headers, method, 0)
    }

    fn rule_with_query(
        route: &str,
        created: &str,
        path: PathMatch,
        headers: usize,
        method: bool,
        query: usize,
    ) -> RouteRule {
        RouteRule {
            route: route.into(),
            rule_index: 0,
            creation_timestamp: created.into(),
            matches: vec![RouteMatch {
                path,
                headers: (0..headers)
                    .map(|i| KvMatch {
                        name: format!("h{i}"),
                        value: "v".into(),
                    })
                    .collect(),
                query: (0..query)
                    .map(|i| KvMatch {
                        name: format!("q{i}"),
                        value: "v".into(),
                    })
                    .collect(),
                method: method.then(|| "GET".to_string()),
            }],
            filters: Filters::default(),
            backends: vec![],
            timeouts: Timeouts::default(),
        }
    }

    fn m(path: &str) -> RouteMatch {
        RouteMatch {
            path: PathMatch::Prefix(path.into()),
            headers: vec![],
            query: vec![],
            method: None,
        }
    }

    /// The tables these tests sort belong to one listener on one port, so its id never decides
    /// anything; `the_listener_id_breaks_a_tie_between_two_gateways` covers the case where it does.
    fn one_listener(rules: Vec<RouteRule>) -> Vec<ListenerConfig> {
        vec![ListenerConfig {
            id: "infra/gw/http".into(),
            port: 80,
            client_port: None,
            protocol: Protocol::Http,
            hostname: None,
            tls: None,
            rules,
        }]
    }

    fn entries_for(rules: &[RouteRule]) -> Vec<PortEntry> {
        rules
            .iter()
            .enumerate()
            .map(|(i, r)| PortEntry {
                listener: 0,
                hostname: None,
                matcher: r.matches[0].clone(),
                rule: i,
            })
            .collect()
    }

    #[test]
    fn sorts_by_spec_order() {
        let rules = vec![
            rule(
                "z/prefix-short",
                "2026-01-01T00:00:00Z",
                PathMatch::Prefix("/a".into()),
                0,
                false,
            ),
            rule(
                "z/prefix-long",
                "2026-01-01T00:00:00Z",
                PathMatch::Prefix("/a/b".into()),
                0,
                false,
            ),
            rule(
                "z/exact",
                "2026-01-01T00:00:00Z",
                PathMatch::Exact("/a".into()),
                0,
                false,
            ),
            rule(
                "z/method",
                "2026-01-01T00:00:00Z",
                PathMatch::Prefix("/a".into()),
                0,
                true,
            ),
            rule(
                "z/headers",
                "2026-01-01T00:00:00Z",
                PathMatch::Prefix("/a".into()),
                2,
                false,
            ),
            rule(
                "a/older-same",
                "2025-01-01T00:00:00Z",
                PathMatch::Prefix("/a".into()),
                0,
                false,
            ),
        ];
        let mut entries = entries_for(&rules);
        entries.push(PortEntry {
            listener: 0,
            hostname: Some("*.x.com".into()),
            matcher: rules[0].matches[0].clone(),
            rule: 0,
        });
        entries.push(PortEntry {
            listener: 0,
            hostname: Some("a.x.com".into()),
            matcher: rules[0].matches[0].clone(),
            rule: 0,
        });
        let listeners = one_listener(rules.clone());
        sort_port_table(&mut entries, &listeners);
        let order: Vec<String> = entries
            .iter()
            .map(|e| {
                format!(
                    "{}:{}",
                    e.hostname.clone().unwrap_or_else(|| "-".into()),
                    rules[e.rule].route
                )
            })
            .collect();
        assert_eq!(
            order,
            vec![
                "a.x.com:z/prefix-short",
                "*.x.com:z/prefix-short",
                "-:z/exact",
                "-:z/prefix-long",
                "-:z/method",
                "-:z/headers",
                "-:a/older-same",
                "-:z/prefix-short",
            ]
        );
    }

    #[test]
    fn exact_beats_prefix_beats_regex_with_length_ties_inside_regex() {
        let rules = vec![
            rule(
                "z/regex-long",
                "2026-01-01T00:00:00Z",
                PathMatch::Regex("^/a/.*$".into()),
                0,
                false,
            ),
            rule(
                "z/regex-short",
                "2026-01-01T00:00:00Z",
                PathMatch::Regex("^/a$".into()),
                0,
                false,
            ),
            rule(
                "z/prefix-long",
                "2026-01-01T00:00:00Z",
                PathMatch::Prefix("/a/b/c".into()),
                0,
                false,
            ),
            rule(
                "z/prefix-short",
                "2026-01-01T00:00:00Z",
                PathMatch::Prefix("/a".into()),
                0,
                false,
            ),
            rule(
                "z/exact",
                "2026-01-01T00:00:00Z",
                PathMatch::Exact("/a".into()),
                0,
                false,
            ),
        ];
        let mut entries = entries_for(&rules);
        let listeners = one_listener(rules.clone());
        sort_port_table(&mut entries, &listeners);
        let order: Vec<&str> = entries
            .iter()
            .map(|e| rules[e.rule].route.as_str())
            .collect();
        assert_eq!(
            order,
            vec![
                "z/exact",
                "z/prefix-long",
                "z/prefix-short",
                // A regex is the least specific path type no matter how long its pattern is.
                "z/regex-long",
                "z/regex-short",
            ]
        );
    }

    #[test]
    fn query_count_breaks_ties() {
        let rules = vec![
            rule_with_query(
                "z/no-query",
                "2026-01-01T00:00:00Z",
                PathMatch::Prefix("/a".into()),
                0,
                false,
                0,
            ),
            rule_with_query(
                "z/one-query",
                "2026-01-01T00:00:00Z",
                PathMatch::Prefix("/a".into()),
                0,
                false,
                1,
            ),
        ];
        let mut entries = entries_for(&rules);
        let listeners = one_listener(rules.clone());
        sort_port_table(&mut entries, &listeners);
        let order: Vec<&str> = entries
            .iter()
            .map(|e| rules[e.rule].route.as_str())
            .collect();
        assert_eq!(order, vec!["z/one-query", "z/no-query"]);
    }

    #[test]
    fn the_listener_id_breaks_a_tie_between_two_gateways() {
        // The same route attached to two Gateways on one port: identical in every key but the
        // listener, so the order must still be deterministic.
        let shared = rule(
            "apps/shared",
            "2026-01-01T00:00:00Z",
            PathMatch::Prefix("/".into()),
            0,
            false,
        );
        let listeners = vec![
            ListenerConfig {
                id: "b/gw/http".into(),
                port: 80,
                client_port: None,
                protocol: Protocol::Http,
                hostname: None,
                tls: None,
                rules: vec![shared.clone()],
            },
            ListenerConfig {
                id: "a/gw/http".into(),
                port: 80,
                client_port: None,
                protocol: Protocol::Http,
                hostname: None,
                tls: None,
                rules: vec![shared],
            },
        ];
        let mut entries = vec![
            PortEntry {
                listener: 0,
                hostname: None,
                matcher: m("/"),
                rule: 0,
            },
            PortEntry {
                listener: 1,
                hostname: None,
                matcher: m("/"),
                rule: 0,
            },
        ];
        sort_port_table(&mut entries, &listeners);
        assert_eq!(entries[0].listener, 1, "a/gw/http sorts before b/gw/http");
    }
}
