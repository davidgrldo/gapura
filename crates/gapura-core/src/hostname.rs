//! Hostname matching, intersection, and specificity per Gateway API rules.
//!
//! Matching is allocation-free and case-insensitive; callers must pass hosts already
//! normalized by the request layer (the proxy), with the port and any trailing dot
//! stripped, before calling into this module.

/// True when `pattern` (exact or `*.` wildcard) matches `host`. Case-insensitive.
/// A wildcard `*.example.com` matches one or more leading labels (`a.example.com`,
/// `b.a.example.com`), never `example.com`. A host whose first label is a literal `*`
/// is treated as an ordinary label; `intersect` relies on this to intersect two wildcards.
/// Callers must pass an already normalized host: lowercase is not required, but the port
/// and any trailing dot must be stripped by the request layer (the proxy) before matching.
pub fn matches(pattern: &str, host: &str) -> bool {
    let (p, h) = (pattern.as_bytes(), host.as_bytes());
    match p.strip_prefix(b"*.") {
        Some(suffix) => {
            h.len() > suffix.len() + 1
                && h[h.len() - suffix.len() - 1] == b'.'
                && h[h.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
        }
        None => p.eq_ignore_ascii_case(h),
    }
}

/// Effective hostnames for a route attached to a listener, per the Gateway API table.
/// `None` = no intersection (the caller must reject the attachment).
/// `Some(vec![])` = any host (neither side constrains the hostname).
/// `Some(hosts)` = the effective hostnames, lowercased, sorted, deduplicated.
/// When one side is a wildcard containing the other, the narrower hostname is kept.
pub fn intersect(listener: Option<&str>, route: &[String]) -> Option<Vec<String>> {
    let mut out: Vec<String> = match (listener, route.is_empty()) {
        (None, true) => return Some(Vec::new()),
        (None, false) => route.iter().map(|r| r.to_ascii_lowercase()).collect(),
        (Some(l), true) => vec![l.to_ascii_lowercase()],
        (Some(l), false) => {
            let mut out = Vec::new();
            for r in route {
                if matches(l, r) {
                    out.push(r.to_ascii_lowercase()); // r is narrower or equal
                } else if matches(r, l) {
                    out.push(l.to_ascii_lowercase()); // l is narrower
                }
            }
            if out.is_empty() {
                return None;
            }
            out
        }
    };
    out.sort();
    out.dedup();
    Some(out)
}

/// Higher is more specific, following Gateway API precedence: exact beats wildcard beats
/// none, then the longer hostname (in characters) wins. Returns (kind, length) with
/// kind 2 = exact, 1 = wildcard, 0 = none.
pub fn specificity(hostname: Option<&str>) -> (u8, usize) {
    match hostname {
        None => (0, 0),
        Some(h) => (if h.starts_with("*.") { 1 } else { 2 }, h.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn exact_match_is_case_insensitive() {
        assert!(matches("api.example.com", "API.Example.COM"));
        assert!(!matches("api.example.com", "www.example.com"));
    }

    #[test]
    fn wildcard_matches_one_or_more_labels_case_insensitively() {
        assert!(matches("*.example.com", "a.example.com"));
        assert!(matches("*.example.com", "b.a.example.com"));
        assert!(matches("*.Example.COM", "A.example.com"));
        assert!(!matches("*.example.com", "example.com"));
        assert!(!matches("*.example.com", "aexample.com"));
        assert!(!matches("*.example.com", ".example.com"));
    }

    #[test]
    fn wildcard_pattern_matches_narrower_wildcard_host() {
        assert!(matches("*.ex.com", "*.a.ex.com"));
        assert!(!matches("*.a.ex.com", "*.ex.com"));
    }

    #[test]
    fn intersect_follows_gateway_api_table() {
        assert_eq!(intersect(None, &r(&[])), Some(vec![]));
        assert_eq!(
            intersect(None, &r(&["A.com", "a.com", "b.com"])),
            Some(r(&["a.com", "b.com"]))
        );
        assert_eq!(intersect(Some("L.com"), &r(&[])), Some(r(&["l.com"])));
        assert_eq!(
            intersect(Some("l.com"), &r(&["l.com", "x.com"])),
            Some(r(&["l.com"]))
        );
        assert_eq!(
            intersect(Some("*.ex.com"), &r(&["a.ex.com", "ex.com", "*.a.ex.com"])),
            Some(r(&["*.a.ex.com", "a.ex.com"]))
        );
        assert_eq!(
            intersect(Some("a.ex.com"), &r(&["*.ex.com"])),
            Some(r(&["a.ex.com"]))
        );
        assert_eq!(
            intersect(Some("*.ex.com"), &r(&["*.ex.com"])),
            Some(r(&["*.ex.com"]))
        );
        assert_eq!(
            intersect(Some("*.a.ex.com"), &r(&["*.ex.com"])),
            Some(r(&["*.a.ex.com"]))
        );
        assert_eq!(intersect(Some("a.ex.com"), &r(&["b.ex.com"])), None);
        assert_eq!(intersect(Some("*.a.com"), &r(&["*.b.com"])), None);
    }

    #[test]
    fn specificity_orders_exact_over_wildcard_over_none_then_longer() {
        assert!(specificity(Some("a.b.c")) > specificity(Some("*.b.c")));
        assert!(specificity(Some("*.b.c")) > specificity(None));
        assert!(specificity(Some("*.a.b.c")) > specificity(Some("*.b.c")));
        assert!(specificity(Some("*.example.com")) > specificity(Some("*.ex.com")));
        assert_eq!(specificity(Some("a.b.c")), (2, 5));
    }
}
