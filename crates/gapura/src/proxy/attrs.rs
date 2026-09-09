//! Turn a Pingora request header into the inputs the core matcher needs. Pure, unit-tested.

use gapura_core::RequestAttrs;
use pingora::http::RequestHeader;

/// Owned copy of what matching needs; borrow it as `RequestAttrs` via `attrs()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extracted {
    /// Normalized host, or empty when the request has no usable host
    /// (then only hostname-less listeners can match).
    pub host: String,
    pub path: String,
    pub query_string: Option<String>,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub query: Vec<(String, String)>,
}

impl Extracted {
    pub fn from_request(req: &RequestHeader) -> Self {
        let host = host_of(req).unwrap_or_default();
        let path = if req.uri.path().is_empty() {
            "/".to_string()
        } else {
            req.uri.path().to_string()
        };
        let query_string = req.uri.query().map(str::to_string);
        let query = query_string.as_deref().map(parse_query).unwrap_or_default();
        let headers = req
            .headers
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_string(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect();
        Self {
            host,
            path,
            query_string,
            method: req.method.as_str().to_string(),
            headers,
            query,
        }
    }

    pub fn attrs(&self) -> RequestAttrs<'_> {
        RequestAttrs {
            host: &self.host,
            path: &self.path,
            method: &self.method,
            headers: &self.headers,
            query: &self.query,
        }
    }
}

/// Host from the request target (absolute-form) or the Host header, normalized.
pub fn host_of(req: &RequestHeader) -> Option<String> {
    let raw = match req.uri.host() {
        Some(h) => h.to_string(),
        None => req
            .headers
            .get(http::header::HOST)?
            .to_str()
            .ok()?
            .to_string(),
    };
    normalize_host(&raw)
}

/// Lowercase, strip `:port` and one trailing dot. Reject empty hosts, hosts containing `*`,
/// and hosts with empty labels; an IPv6 literal is validated with `std::net::Ipv6Addr` and
/// re-emitted bracketed in canonical form.
pub fn normalize_host(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if let Some(rest) = trimmed.strip_prefix('[') {
        // IPv6 literal: "[addr]" or "[addr]:port", nothing else after ']'.
        let (inner, after) = rest.split_once(']')?;
        let port = after.strip_prefix(':').unwrap_or(after);
        if !after.is_empty() && !port.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let addr: std::net::Ipv6Addr = inner.parse().ok()?;
        return Some(format!("[{addr}]"));
    }
    let without_port = match trimmed.rsplit_once(':') {
        // `port = *DIGIT` per RFC 9110, so a bare trailing colon is a valid empty port.
        Some((h, port)) if port.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => trimmed,
    };
    let host = without_port
        .strip_suffix('.')
        .unwrap_or(without_port)
        .to_ascii_lowercase();
    if host.is_empty() || host.contains('*') || host.split('.').any(str::is_empty) {
        return None;
    }
    Some(host)
}

/// `a=1&b=2&a=3` -> [(a,1),(b,2),(a,3)], request order kept, values raw (no percent-decoding in v0.1).
pub fn parse_query(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| match kv.split_once('=') {
            Some((k, v)) => (k.to_string(), v.to_string()),
            None => (kv.to_string(), String::new()),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(path: &str, host: Option<&str>) -> RequestHeader {
        let mut r = RequestHeader::build("GET", path.as_bytes(), None).unwrap();
        if let Some(h) = host {
            r.insert_header("Host", h).unwrap();
        }
        r.insert_header("X-Version", "2").unwrap();
        r
    }

    #[test]
    fn normalizes_host() {
        assert_eq!(
            normalize_host("App.Example.COM:8080"),
            Some("app.example.com".into())
        );
        assert_eq!(
            normalize_host("app.example.com."),
            Some("app.example.com".into())
        );
        assert_eq!(normalize_host("[::1]:8443"), Some("[::1]".into()));
        assert_eq!(normalize_host("localhost"), Some("localhost".into()));
        assert_eq!(normalize_host(""), None);
        assert_eq!(normalize_host("*.example.com"), None);
        assert_eq!(normalize_host("a..b"), None);
        assert_eq!(normalize_host("a.b:notaport"), Some("a.b:notaport".into()));
        assert_eq!(normalize_host("host:"), Some("host".into()));
        assert_eq!(normalize_host("[0:0:0:0:0:0:0:1]"), Some("[::1]".into()));
        assert_eq!(normalize_host("[::1]:"), Some("[::1]".into()));
        assert_eq!(normalize_host("[*]"), None);
        assert_eq!(normalize_host("[]"), None);
        assert_eq!(normalize_host("[::1"), None);
        assert_eq!(normalize_host("[::1]junk"), None);
        assert_eq!(normalize_host("[::1]:abc"), None);
        assert_eq!(normalize_host("example.com.."), None);
        assert_eq!(normalize_host("."), None);
        assert_eq!(normalize_host(":80"), None);
    }

    #[test]
    fn extracts_path_query_headers_method() {
        let e = Extracted::from_request(&req(
            "/api/v1?b=2&a=1&a=3&flag",
            Some("Echo.Example.com:80"),
        ));
        assert_eq!(e.host, "echo.example.com");
        assert_eq!(e.path, "/api/v1");
        assert_eq!(e.query_string.as_deref(), Some("b=2&a=1&a=3&flag"));
        assert_eq!(e.method, "GET");
        assert_eq!(
            e.query,
            vec![
                ("b".into(), "2".into()),
                ("a".into(), "1".into()),
                ("a".into(), "3".into()),
                ("flag".into(), String::new())
            ]
        );
        assert!(
            e.headers
                .contains(&("x-version".to_string(), "2".to_string())),
            "{:?}",
            e.headers
        );
        let attrs = e.attrs();
        assert_eq!(attrs.host, "echo.example.com");
    }

    #[test]
    fn missing_or_bad_host_becomes_empty() {
        assert_eq!(Extracted::from_request(&req("/", None)).host, "");
        assert_eq!(
            Extracted::from_request(&req("/", Some("*.example.com"))).host,
            ""
        );
        assert_eq!(Extracted::from_request(&req("", None)).path, "/");
        let r = RequestHeader::build("OPTIONS", b"*", None).unwrap();
        assert_eq!(Extracted::from_request(&r).path, "*");
    }
}
