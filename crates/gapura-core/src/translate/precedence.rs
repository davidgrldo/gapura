//! Gateway API match precedence, used to sort each listener's match table once after translation.
//! Order: hostname specificity (exact > wildcard, more labels first) > path Exact > longer PathPrefix >
//! has method > more header matches > more query matches > older route > namespace/name > rule index.
//! Routes without creationTimestamp sort as the oldest (empty string); real clusters always stamp it.

use std::cmp::Reverse;

use crate::config::{MatchEntry, PathMatch, RouteRule};
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
);

fn key(entry: &MatchEntry, rule: &RouteRule) -> Key {
    let (path_kind, path_len) = match &entry.matcher.path {
        PathMatch::Exact(p) => (1u8, p.len()),
        PathMatch::Prefix(p) => (0u8, p.len()),
    };
    (
        Reverse(hostname::specificity(entry.hostname.as_deref())),
        Reverse(path_kind),
        Reverse(path_len),
        Reverse(u8::from(entry.matcher.method.is_some())),
        Reverse(entry.matcher.headers.len()),
        Reverse(entry.matcher.query.len()),
        rule.creation_timestamp.clone(),
        rule.route.clone(),
        rule.rule_index,
    )
}

/// Sort a listener's table in place so the first matching entry is the winner.
pub(crate) fn sort_table(table: &mut [MatchEntry], rules: &[RouteRule]) {
    table.sort_by_cached_key(|e| key(e, &rules[e.rule]));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Filters, KvMatch, RouteMatch, Timeouts};

    fn rule(
        route: &str,
        created: &str,
        path: PathMatch,
        headers: usize,
        method: bool,
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
                query: vec![],
                method: method.then(|| "GET".to_string()),
            }],
            filters: Filters::default(),
            backends: vec![],
            timeouts: Timeouts::default(),
        }
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
        let mut table: Vec<MatchEntry> = rules
            .iter()
            .enumerate()
            .map(|(i, r)| MatchEntry {
                hostname: None,
                matcher: r.matches[0].clone(),
                rule: i,
            })
            .collect();
        table.push(MatchEntry {
            hostname: Some("*.x.com".into()),
            matcher: rules[0].matches[0].clone(),
            rule: 0,
        });
        table.push(MatchEntry {
            hostname: Some("a.x.com".into()),
            matcher: rules[0].matches[0].clone(),
            rule: 0,
        });
        sort_table(&mut table, &rules);
        let order: Vec<String> = table
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
}
