//! Hostname matching, intersection, and specificity per Gateway API rules.

/// True when `pattern` (exact or `*.` wildcard) matches `host`. Case-insensitive.
pub fn matches(pattern: &str, host: &str) -> bool {
    let p = pattern.to_ascii_lowercase();
    let h = host.to_ascii_lowercase();
    match p.strip_prefix("*.") {
        Some(suffix) => {
            h.len() > suffix.len() + 1
                && h.ends_with(suffix)
                && h.as_bytes()[h.len() - suffix.len() - 1] == b'.'
        }
        None => p == h,
    }
}

/// Effective hostnames for a route attached to a listener.
/// Empty result with `listener == None` and empty `route` means "any host".
/// Empty result otherwise means "no intersection" (the caller rejects the attachment).
pub fn intersect(listener: Option<&str>, route: &[String]) -> Vec<String> {
    match (listener, route.is_empty()) {
        (None, true) => Vec::new(),
        (None, false) => route.to_vec(),
        (Some(l), true) => vec![l.to_string()],
        (Some(l), false) => {
            let mut out: Vec<String> = Vec::new();
            for r in route {
                if l.eq_ignore_ascii_case(r) || (l.starts_with("*.") && matches(l, r)) {
                    out.push(r.to_ascii_lowercase());
                } else if r.starts_with("*.") && matches(r, l) {
                    out.push(l.to_ascii_lowercase());
                }
            }
            out.sort();
            out.dedup();
            out
        }
    }
}

/// Higher is more specific: (kind, label count). kind: 2 exact, 1 wildcard, 0 none.
pub fn specificity(hostname: Option<&str>) -> (u8, usize) {
    match hostname {
        None => (0, 0),
        Some(h) if h.starts_with("*.") => (1, h.matches('.').count()),
        Some(h) => (2, h.matches('.').count()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match_is_case_insensitive() {
        assert!(matches("api.example.com", "API.Example.COM"));
        assert!(!matches("api.example.com", "www.example.com"));
    }

    #[test]
    fn wildcard_matches_one_or_more_labels() {
        assert!(matches("*.example.com", "a.example.com"));
        assert!(matches("*.example.com", "b.a.example.com"));
        assert!(!matches("*.example.com", "example.com"));
        assert!(!matches("*.example.com", "aexample.com"));
    }

    #[test]
    fn intersect_follows_gateway_api_table() {
        let r = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(intersect(None, &r(&[])), Vec::<String>::new());
        assert_eq!(intersect(None, &r(&["a.com"])), r(&["a.com"]));
        assert_eq!(intersect(Some("l.com"), &r(&[])), r(&["l.com"]));
        assert_eq!(
            intersect(Some("l.com"), &r(&["l.com", "x.com"])),
            r(&["l.com"])
        );
        assert_eq!(
            intersect(Some("*.ex.com"), &r(&["a.ex.com", "ex.com", "*.a.ex.com"])),
            r(&["*.a.ex.com", "a.ex.com"])
        );
        assert_eq!(
            intersect(Some("a.ex.com"), &r(&["*.ex.com"])),
            r(&["a.ex.com"])
        );
        assert_eq!(
            intersect(Some("a.ex.com"), &r(&["b.ex.com"])),
            Vec::<String>::new()
        );
    }

    #[test]
    fn specificity_orders_exact_over_wildcard_over_none() {
        assert!(specificity(Some("a.b.c")) > specificity(Some("*.b.c")));
        assert!(specificity(Some("*.b.c")) > specificity(None));
        assert!(specificity(Some("*.a.b.c")) > specificity(Some("*.b.c")));
    }
}
