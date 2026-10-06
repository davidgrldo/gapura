//! Turn a Pingora request header into the inputs the core matcher needs. Pure, unit-tested.

use gapura_core::RequestAttrs;
use pingora::http::RequestHeader;

/// Owned copy of what matching needs; borrow it as `RequestAttrs` via `attrs()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extracted {
    /// Normalized host, or empty when the request has no usable host
    /// (then only hostname-less listeners can match).
    pub host: String,
    /// The path as matched and as forwarded: see [`normalize_path`].
    pub path: String,
    /// The path the client sent differs from `path`, so the upstream request must carry `path`
    /// rather than the original. Matching one string and forwarding another is the bypass.
    pub path_normalized: bool,
    pub query_string: Option<String>,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub query: Vec<(String, String)>,
}

impl Extracted {
    /// `Err` carries why the request target cannot be routed at all; the caller answers 400.
    pub fn from_request(req: &RequestHeader) -> Result<Self, &'static str> {
        let host = host_of(req).unwrap_or_default();
        let raw = req.uri.path();
        let path = normalize_path(raw)?;
        let path_normalized = path != raw;
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
        Ok(Self {
            host,
            path,
            path_normalized,
            query_string,
            method: req.method.as_str().to_string(),
            headers,
            query,
        })
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

/// The path a route is matched against, which is also the path forwarded upstream.
///
/// A backend normalises what it receives; a gateway that matches the raw string and forwards it
/// unchanged lets the two disagree, and the disagreement is a policy bypass. `/public/../admin`
/// matches a `/public` rule that carries no policy and is served as `/admin` by the backend;
/// `/%61dmin` and `//admin` miss a `/admin` rule and fall through to a catch-all. So:
///
/// - The target must be an absolute path. An absolute-form target (`GET http://x/admin`) does
///   not start with `/`, matches only a catch-all, and most backends serve it as `/admin`.
/// - Percent-encoded unreserved characters (`A-Z a-z 0-9 - . _ ~`) are decoded, as RFC 3986
///   section 6.2.2.2 says they are equivalent to the character. Anything else stays encoded,
///   `%2F` included: an encoded slash is data some APIs carry on purpose, and Envoy's default
///   is likewise to leave it.
/// - Repeated slashes are merged.
/// - A `.` or `..` segment, after decoding, is refused rather than resolved: a browser never
///   sends one, and resolving it is the backend's semantics to guess at.
pub fn normalize_path(raw: &str) -> Result<String, &'static str> {
    if raw.is_empty() {
        return Ok("/".to_string());
    }
    if !raw.starts_with('/') {
        return Err("the request target is not an absolute path");
    }
    let bytes = raw.as_bytes();
    let mut decoded = String::with_capacity(raw.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = raw.get(i + 1..i + 3).ok_or("a truncated percent escape")?;
            let v = u8::from_str_radix(hex, 16).map_err(|_| "an invalid percent escape")?;
            if v.is_ascii_alphanumeric() || matches!(v, b'-' | b'.' | b'_' | b'~') {
                decoded.push(v as char);
            } else {
                decoded.push('%');
                decoded.push_str(&hex.to_ascii_uppercase());
            }
            i += 3;
        } else {
            decoded.push(bytes[i] as char);
            i += 1;
        }
    }
    let mut out = String::with_capacity(decoded.len());
    for c in decoded.chars() {
        if c == '/' && out.ends_with('/') {
            continue;
        }
        out.push(c);
    }
    if out.split('/').any(|seg| seg == "." || seg == "..") {
        return Err("a dot segment in the path");
    }
    Ok(out)
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
        ))
        .unwrap();
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
        assert_eq!(Extracted::from_request(&req("/", None)).unwrap().host, "");
        assert_eq!(
            Extracted::from_request(&req("/", Some("*.example.com")))
                .unwrap()
                .host,
            ""
        );
        assert_eq!(Extracted::from_request(&req("", None)).unwrap().path, "/");
        // `OPTIONS *` names no resource to route; it used to match only a `/` catch-all.
        let r = RequestHeader::build("OPTIONS", b"*", None).unwrap();
        assert!(Extracted::from_request(&r).is_err());
    }

    #[test]
    fn an_absolute_form_target_is_matched_on_its_path_or_refused() {
        // However the request line was parsed, `http://x/admin` must never be matched as a path
        // that misses `/admin` and falls through to a catch-all.
        // A parsed absolute-form target arrives with the authority in the URI and the path
        // apart from it, and is matched on that path. One that reaches us unparsed, as a path
        // that does not start with `/`, is refused by `normalize_path` (see path_tests).
        let mut r = RequestHeader::build("GET", b"/", None).unwrap();
        r.set_uri("http://x/admin".parse().unwrap());
        assert_eq!(Extracted::from_request(&r).unwrap().path, "/admin");
    }

    #[test]
    fn the_normalised_path_is_flagged_for_forwarding() {
        let e = Extracted::from_request(&req("//api/%61", None)).unwrap();
        assert_eq!(e.path, "/api/a");
        assert!(e.path_normalized);
        assert!(
            !Extracted::from_request(&req("/api/a", None))
                .unwrap()
                .path_normalized
        );
    }
}

#[cfg(test)]
mod path_tests {
    use super::normalize_path;

    #[test]
    fn ordinary_paths_pass_unchanged() {
        for p in [
            "/",
            "/api",
            "/api/v1/users",
            "/a-b_c.d~e",
            "/x%20y",
            "/files/a%2Fb",
        ] {
            assert_eq!(normalize_path(p).unwrap(), p, "{p}");
        }
        assert_eq!(normalize_path("").unwrap(), "/");
    }

    #[test]
    fn encoded_unreserved_characters_are_decoded() {
        assert_eq!(normalize_path("/%61dmin").unwrap(), "/admin");
        assert_eq!(normalize_path("/%7Euser").unwrap(), "/~user");
        // Reserved and other characters stay encoded, with the hex canonicalised.
        assert_eq!(normalize_path("/a%2fb").unwrap(), "/a%2Fb");
        assert_eq!(normalize_path("/a%3f").unwrap(), "/a%3F");
    }

    #[test]
    fn repeated_slashes_are_merged() {
        assert_eq!(normalize_path("//admin").unwrap(), "/admin");
        assert_eq!(
            normalize_path("/api//v1///users/").unwrap(),
            "/api/v1/users/"
        );
    }

    #[test]
    fn dot_segments_are_refused_encoded_or_not() {
        for p in [
            "/public/../admin",
            "/public/./admin",
            "/..",
            "/public/%2e%2e/admin",
            "/public/%2E%2E/admin",
            "/public/.%2e/admin",
            "/public/%2e/admin",
        ] {
            assert!(normalize_path(p).is_err(), "{p}");
        }
        // Dots inside a segment are just characters.
        assert_eq!(normalize_path("/v1.2/..x/x..").unwrap(), "/v1.2/..x/x..");
    }

    #[test]
    fn non_origin_targets_and_bad_escapes_are_refused() {
        for p in ["http://x/admin", "*", "admin", "/a%2", "/a%zz"] {
            assert!(normalize_path(p).is_err(), "{p}");
        }
    }
}
