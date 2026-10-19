//! The path a request is matched on. One normaliser, shared by the data plane, which matches
//! and forwards every request path through it, and the translator, which writes Exact and
//! PathPrefix route values in the same form so they can match at all (#250).

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
///   is likewise to leave it. Raw non-ASCII bytes pass through unchanged, so a path the client
///   sent as UTF-8 is matched and forwarded as the same UTF-8.
/// - Repeated slashes are merged.
/// - A `.` or `..` segment, after decoding, is refused rather than resolved: a browser never
///   sends one, and resolving it is the backend's semantics to guess at. So is one that carries
///   path parameters (`..;x`, `.;`): servlet containers strip `;params` from each segment before
///   resolving dot segments, so Tomcat serves `/public/..;/admin` as `/admin` (#213).
pub fn normalize_path(raw: &str) -> Result<String, &'static str> {
    if raw.is_empty() {
        return Ok("/".to_string());
    }
    if !raw.starts_with('/') {
        return Err("the request target is not an absolute path");
    }
    let bytes = raw.as_bytes();
    // Decoded bytes, not chars: the target may carry raw non-ASCII UTF-8 (httparse accepts
    // bytes 0x80-0xFF there), and casting each byte to char re-encoded every byte of a
    // multi-byte sequence as its own Latin-1 character — `/café` became `/cafÃ©`, which missed
    // the route for `/café` and was forwarded upstream double-encoded. Bytes >= 0x80 pass
    // through untouched; the percent branch below only ever writes ASCII.
    let mut decoded: Vec<u8> = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = raw.get(i + 1..i + 3).ok_or("a truncated percent escape")?;
            // from_str_radix alone accepts a sign, so `%+1` would pass as an escape.
            if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("an invalid percent escape");
            }
            let v = u8::from_str_radix(hex, 16).map_err(|_| "an invalid percent escape")?;
            if v.is_ascii_alphanumeric() || matches!(v, b'-' | b'.' | b'_' | b'~') {
                decoded.push(v);
            } else {
                decoded.push(b'%');
                decoded.extend_from_slice(hex.to_ascii_uppercase().as_bytes());
            }
            i += 3;
        } else {
            decoded.push(bytes[i]);
            i += 1;
        }
    }
    let decoded = std::str::from_utf8(&decoded)
        .expect("only ASCII bytes were replaced, so the target is still UTF-8");
    let mut out = String::with_capacity(decoded.len());
    for c in decoded.chars() {
        if c == '/' && out.ends_with('/') {
            continue;
        }
        out.push(c);
    }
    if out
        .split('/')
        .map(without_params)
        .any(|seg| seg == "." || seg == "..")
    {
        return Err("a dot segment in the path");
    }
    Ok(out)
}

/// A path segment without its `;params`, the way a servlet container reads it.
fn without_params(segment: &str) -> &str {
    segment.split_once(';').map_or(segment, |(name, _)| name)
}

/// `path` with every segment's `;params` removed and the slashes merged again, or `None` when
/// it carries no `;` at all. This is the path a servlet container resolves `path` to: Tomcat
/// serves `/admin;x/secret` as `/admin/secret`. The caller matches routes on it as well, and
/// refuses a request whose two matches disagree (#213) -- otherwise `/admin;x/secret` misses an
/// `/admin` rule, falls through to a catch-all, and is served as `/admin/secret` unchecked.
pub fn without_path_params(path: &str) -> Option<String> {
    if !path.contains(';') {
        return None;
    }
    let mut out = String::with_capacity(path.len());
    for (i, segment) in path.split('/').map(without_params).enumerate() {
        if i > 0 {
            if out.ends_with('/') {
                // An empty segment, `/;x/`, collapses like a repeated slash.
                if !segment.is_empty() {
                    out.push_str(segment);
                }
                continue;
            }
            out.push('/');
        }
        out.push_str(segment);
    }
    Some(out)
}

#[cfg(test)]
mod path_tests {
    use super::{normalize_path, without_path_params};

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
    fn dot_segments_with_path_parameters_are_refused() {
        // #213: Tomcat and Jetty strip `;params` before resolving dot segments, so they serve
        // `/public/..;/admin/secret` as `/admin/secret` while we matched it as `/public`.
        for p in [
            "/public/..;/admin/secret",
            "/public/..;x=1/admin",
            "/public/.;/admin",
            "/public/%2e%2e;/admin",
            "/public/.%2E;jsessionid=1/admin",
            "/..;",
        ] {
            assert!(normalize_path(p).is_err(), "{p}");
        }
        // Parameters on an ordinary segment, and dots after the `;`, are just characters.
        for p in ["/shop;jsessionid=1/cart", "/a;..", "/a/x..;y", "/a/;/b"] {
            assert_eq!(normalize_path(p).unwrap(), p, "{p}");
        }
    }

    #[test]
    fn path_parameters_are_stripped_the_way_a_servlet_container_does() {
        assert_eq!(without_path_params("/admin/secret"), None);
        assert_eq!(
            without_path_params("/admin;x/secret").as_deref(),
            Some("/admin/secret")
        );
        assert_eq!(
            without_path_params("/shop;jsessionid=1").as_deref(),
            Some("/shop")
        );
        assert_eq!(
            without_path_params("/;x/admin;y=1;z/").as_deref(),
            Some("/admin/")
        );
        assert_eq!(without_path_params("/;").as_deref(), Some("/"));
    }

    #[test]
    fn non_origin_targets_and_bad_escapes_are_refused() {
        for p in [
            "http://x/admin",
            "*",
            "admin",
            "/a%2",
            "/a%zz",
            "/a%+1",
            "/a%-1",
        ] {
            assert!(normalize_path(p).is_err(), "{p}");
        }
    }
}
