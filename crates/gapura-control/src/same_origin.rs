//! Refuses the requests another site's page makes a browser send.
//!
//! The session is a cookie, and a browser attaches it to requests to this origin wherever they
//! start. `SameSite=Lax` already keeps it off a POST from another site, but not off one from a
//! sibling subdomain, which browsers count as the same site. It does nothing for a sign-in
//! either: that sets a cookie rather than sending one, so another site could sign a browser in
//! as an account of its own choosing. So every request that is not a `GET` or a `HEAD`, under
//! `/api/` and `/auth/`, has to show that this origin's own pages sent it:
//!
//! - `Sec-Fetch-Site`, which current browsers send to an HTTPS origin and no page can set, must
//!   say `same-origin`. `same-site`, a sibling subdomain, is refused like `cross-site`.
//! - Without it, `Origin` must name this host and port. That covers Safari before 16.4, which
//!   does not send `Sec-Fetch-Site`, and so it relies on a proxy in front of the console keeping
//!   `Host` as the browser sent it. `Origin: null`, which a sandboxed frame or a redirect from
//!   another site sends, is refused.
//! - With neither, it came from no browser released since 2019, and is treated as a client that
//!   chose its own cookies, so it passes.
//!
//! Writes under `/api/` must also be JSON. A page on another site cannot send that without a
//! CORS preflight, which this server never answers, so it is a second wall behind the first.
//!
//! Not covered here: `GET /auth/callback`, where an identity provider returns the browser. It
//! is a `GET` by the protocol's design, and tying its `state` to the browser that began the
//! sign-in is the callback's own work.

use axum::extract::Request;
use axum::http::{header, HeaderMap, Method, StatusCode, Uri};
use axum::middleware::Next;
use axum::response::Response;

/// What the rules make of one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    /// 403: another site's page sent it.
    CrossSite,
    /// 415: a write to the API that is not JSON.
    NotJson,
}

/// The rules above, over the three parts of a request they read.
pub fn verdict(method: &Method, uri: &Uri, headers: &HeaderMap) -> Verdict {
    if *method == Method::GET || *method == Method::HEAD {
        return Verdict::Pass;
    }
    // Lowered, as the fallback compares paths, so `/API/...` is held to the same rules on its
    // way to a 404 rather than slipping past them.
    let path = uri.path().to_ascii_lowercase();
    let api = path.starts_with("/api/");
    if !api && !path.starts_with("/auth/") {
        return Verdict::Pass;
    }
    if !from_this_origin(uri, headers) {
        return Verdict::CrossSite;
    }
    if api && !is_json(headers) {
        return Verdict::NotJson;
    }
    Verdict::Pass
}

/// Whether a request shows it came from this origin's own pages, or from no browser at all.
fn from_this_origin(uri: &Uri, headers: &HeaderMap) -> bool {
    if let Some(site) = headers.get("sec-fetch-site") {
        return site.as_bytes() == b"same-origin";
    }
    let Some(origin) = headers.get(header::ORIGIN) else {
        return true;
    };
    // HTTP/1.1 carries the host in `Host`, and HTTP/2 in the request's authority. A proxy that
    // rewrites `Host` breaks this comparison, but only for a browser that sends no
    // `Sec-Fetch-Site`. The scheme is not compared: behind a proxy that ends TLS, this server
    // cannot tell which one the browser used.
    let host = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .or_else(|| uri.authority().map(|a| a.as_str()));
    // `null` has no `://`, so it falls out here with anything else that is not an origin.
    let named = origin
        .to_str()
        .ok()
        .and_then(|o| o.split_once("://"))
        .map(|(_, authority)| authority);
    matches!((named, host), (Some(named), Some(host)) if named.eq_ignore_ascii_case(host))
}

/// `application/json`, with or without parameters such as a charset, in any case.
fn is_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|essence| essence.trim().eq_ignore_ascii_case("application/json"))
}

/// The layer `api::router_with` puts in front of every route.
pub async fn guard(request: Request, next: Next) -> Response {
    match verdict(request.method(), request.uri(), request.headers()) {
        Verdict::Pass => next.run(request).await,
        Verdict::CrossSite => crate::api::refuse(
            StatusCode::FORBIDDEN,
            "This request came from another site, so it was refused.",
        ),
        Verdict::NotJson => crate::api::refuse(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Send this request as JSON, with Content-Type: application/json.",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: (&str, &str) = ("host", "console.example.test");

    fn judge(method: Method, path: &str, pairs: &[(&str, &str)]) -> Verdict {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(
                header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        verdict(&method, &path.parse().unwrap(), &headers)
    }

    #[test]
    fn only_same_origin_passes_when_the_browser_says_where_it_came_from() {
        for site in ["cross-site", "same-site", "none"] {
            assert_eq!(
                judge(Method::POST, "/auth/logout", &[("sec-fetch-site", site)]),
                Verdict::CrossSite,
                "{site}"
            );
        }
        assert_eq!(
            judge(
                Method::POST,
                "/auth/logout",
                &[("sec-fetch-site", "same-origin")]
            ),
            Verdict::Pass
        );
    }

    #[test]
    fn every_method_but_get_and_head_is_held_to_the_rules() {
        for method in [
            Method::OPTIONS,
            Method::TRACE,
            Method::from_bytes(b"FOO").unwrap(),
        ] {
            assert_eq!(
                judge(
                    method.clone(),
                    "/api/users",
                    &[("sec-fetch-site", "cross-site")]
                ),
                Verdict::CrossSite,
                "{method}"
            );
        }
        assert_eq!(
            judge(
                Method::HEAD,
                "/api/users",
                &[("sec-fetch-site", "cross-site")]
            ),
            Verdict::Pass
        );
    }

    #[test]
    fn sec_fetch_site_is_believed_over_origin() {
        // A browser that sends both is judged by the header no page can set.
        assert_eq!(
            judge(
                Method::POST,
                "/auth/logout",
                &[
                    ("sec-fetch-site", "cross-site"),
                    ("origin", "https://console.example.test"),
                    HOST
                ]
            ),
            Verdict::CrossSite
        );
    }

    #[test]
    fn without_it_the_origin_must_name_this_host_and_port() {
        assert_eq!(
            judge(
                Method::POST,
                "/auth/login",
                &[("origin", "https://console.example.test"), HOST]
            ),
            Verdict::Pass
        );
        assert_eq!(
            judge(
                Method::POST,
                "/auth/login",
                &[("origin", "https://CONSOLE.example.test"), HOST]
            ),
            Verdict::Pass,
            "host names ignore case"
        );
        for origin in [
            "https://evil.example",
            "https://console.example.test:8443",
            "https://console.example.test.evil.example",
            "null",
            "console.example.test",
        ] {
            assert_eq!(
                judge(Method::POST, "/auth/login", &[("origin", origin), HOST]),
                Verdict::CrossSite,
                "{origin}"
            );
        }
        assert_eq!(
            judge(
                Method::POST,
                "/auth/login",
                &[("origin", "https://console.example.test")]
            ),
            Verdict::CrossSite,
            "with no host to compare it with, an origin proves nothing"
        );
    }

    #[test]
    fn with_neither_header_the_request_is_not_from_a_browser_and_passes() {
        assert_eq!(judge(Method::POST, "/auth/logout", &[]), Verdict::Pass);
        assert_eq!(
            judge(
                Method::PATCH,
                "/api/users/x/roles",
                &[("content-type", "application/json")]
            ),
            Verdict::Pass
        );
    }

    #[test]
    fn reading_is_never_refused() {
        for method in [Method::GET, Method::HEAD] {
            assert_eq!(
                judge(method, "/api/users", &[("sec-fetch-site", "cross-site")]),
                Verdict::Pass
            );
        }
    }

    #[test]
    fn only_the_api_and_sign_in_paths_are_guarded() {
        assert_eq!(
            judge(Method::POST, "/", &[("sec-fetch-site", "cross-site")]),
            Verdict::Pass
        );
        assert_eq!(
            judge(
                Method::POST,
                "/API/users",
                &[("sec-fetch-site", "cross-site")]
            ),
            Verdict::CrossSite,
            "case does not dodge it"
        );
    }

    #[test]
    fn a_write_to_the_api_must_be_json_and_a_sign_in_need_not_be() {
        for content_type in [
            "application/json",
            "application/json; charset=utf-8",
            "Application/JSON",
        ] {
            assert_eq!(
                judge(
                    Method::PUT,
                    "/api/group-mappings",
                    &[("content-type", content_type)]
                ),
                Verdict::Pass,
                "{content_type}"
            );
        }
        for content_type in [
            "text/plain",
            "application/x-www-form-urlencoded",
            "multipart/form-data; boundary=x",
            "application/jsonp",
        ] {
            assert_eq!(
                judge(
                    Method::PUT,
                    "/api/group-mappings",
                    &[("content-type", content_type)]
                ),
                Verdict::NotJson,
                "{content_type}"
            );
        }
        assert_eq!(
            judge(Method::DELETE, "/api/group-mappings", &[]),
            Verdict::NotJson,
            "a write with no body still says what it is"
        );
        assert_eq!(
            judge(
                Method::POST,
                "/auth/login",
                &[("content-type", "application/x-www-form-urlencoded")]
            ),
            Verdict::Pass,
            "the sign-in form posts a form"
        );
    }

    #[test]
    fn a_cross_site_write_is_refused_as_cross_site_before_its_type_is_looked_at() {
        assert_eq!(
            judge(
                Method::PATCH,
                "/api/users/x/roles",
                &[("sec-fetch-site", "cross-site")]
            ),
            Verdict::CrossSite
        );
    }
}
