//! Why the gateway answered a request itself.
//!
//! Every answer the gateway writes on its own -- not an upstream's response, not a redirect --
//! names its cause with one key from a closed set: in the `X-Gapura-Error` header, in the body,
//! and in the access log's `error_key`. Modelled on Gravitee's `ExecutionFailure` (status, key,
//! message) and its connection-failure classifier. Callers may match on these strings, so a key
//! is never renamed or given a second meaning; a new cause gets a new key.

use gapura_core::{credentials, jwt};
use pingora::{Error, ErrorSource, ErrorType};

/// The header that carries the key on every locally generated error answer.
pub const HEADER: &str = "X-Gapura-Error";

/// Why the gateway answered a request itself. Each key has one status, so the key alone says
/// what the caller got.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKey {
    /// The request target cannot be normalised, its host is ambiguous, or its `;` parameters
    /// would route it elsewhere (#213).
    InvalidRequestTarget,
    /// No rule matches.
    NoRoute,
    /// The rule has no valid backend (Gateway API: 500).
    NoBackend,
    /// The backend has no ready endpoint, or none left to try.
    NoEndpoints,
    /// A key_auth policy found no key.
    AuthKeyMissing,
    /// A key_auth policy found a key it does not accept.
    AuthKeyInvalid,
    /// A JWT policy found no bearer token.
    AuthJwtMissing,
    /// A JWT policy found a token it does not accept. Which check failed is not said.
    AuthJwtInvalid,
    /// The rule's rate limit is spent for this client.
    RateLimited,
    /// Connecting to the upstream timed out.
    UpstreamConnectTimeout,
    /// The upstream went quiet past the rule's timeout, or the request's budget ran out.
    UpstreamTimeout,
    /// The upstream refused the connection, or could not be reached.
    UpstreamConnectError,
    /// The TLS handshake with the upstream failed.
    UpstreamTlsError,
    /// The exchange with the upstream failed after it connected.
    UpstreamError,
    /// The gateway failed on its own account.
    InternalError,
}

impl ErrorKey {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequestTarget => "INVALID_REQUEST_TARGET",
            Self::NoRoute => "NO_ROUTE",
            Self::NoBackend => "NO_BACKEND",
            Self::NoEndpoints => "NO_ENDPOINTS",
            Self::AuthKeyMissing => "AUTH_KEY_MISSING",
            Self::AuthKeyInvalid => "AUTH_KEY_INVALID",
            Self::AuthJwtMissing => "AUTH_JWT_MISSING",
            Self::AuthJwtInvalid => "AUTH_JWT_INVALID",
            Self::RateLimited => "RATE_LIMITED",
            Self::UpstreamConnectTimeout => "UPSTREAM_CONNECT_TIMEOUT",
            Self::UpstreamTimeout => "UPSTREAM_TIMEOUT",
            Self::UpstreamConnectError => "UPSTREAM_CONNECT_ERROR",
            Self::UpstreamTlsError => "UPSTREAM_TLS_ERROR",
            Self::UpstreamError => "UPSTREAM_ERROR",
            Self::InternalError => "INTERNAL_ERROR",
        }
    }

    pub fn status(self) -> u16 {
        match self {
            Self::InvalidRequestTarget => 400,
            Self::AuthKeyMissing
            | Self::AuthKeyInvalid
            | Self::AuthJwtMissing
            | Self::AuthJwtInvalid => 401,
            Self::NoRoute => 404,
            Self::RateLimited => 429,
            Self::NoBackend | Self::InternalError => 500,
            Self::UpstreamConnectError | Self::UpstreamTlsError | Self::UpstreamError => 502,
            Self::NoEndpoints => 503,
            Self::UpstreamConnectTimeout | Self::UpstreamTimeout => 504,
        }
    }

    /// What the body says beside the key. Never more than the key does: no error text, no
    /// address, nothing an operator's log has that a caller should not.
    pub fn message(self) -> &'static str {
        match self {
            Self::InvalidRequestTarget => "bad request target",
            Self::NoRoute => "no route",
            Self::NoBackend => "no valid backend",
            Self::NoEndpoints => "no ready endpoints",
            Self::AuthKeyMissing
            | Self::AuthKeyInvalid
            | Self::AuthJwtMissing
            | Self::AuthJwtInvalid => "unauthorized",
            Self::RateLimited => "too many requests",
            Self::UpstreamConnectTimeout | Self::UpstreamTimeout => "gateway timeout",
            Self::UpstreamConnectError | Self::UpstreamTlsError | Self::UpstreamError => {
                "bad gateway"
            }
            Self::InternalError => "internal error",
        }
    }
}

/// Whether a token was presented, never which check it failed.
impl From<&jwt::Refusal> for ErrorKey {
    fn from(r: &jwt::Refusal) -> Self {
        match r {
            jwt::Refusal::Missing => Self::AuthJwtMissing,
            jwt::Refusal::Malformed
            | jwt::Refusal::UnknownKey
            | jwt::Refusal::BadSignature
            | jwt::Refusal::Claims => Self::AuthJwtInvalid,
        }
    }
}

/// Whether a key was presented, never whether it exists in another workspace.
impl From<&credentials::Refusal> for ErrorKey {
    fn from(r: &credentials::Refusal) -> Self {
        match r {
            credentials::Refusal::Missing => Self::AuthKeyMissing,
            credentials::Refusal::Unknown => Self::AuthKeyInvalid,
        }
    }
}

/// The key for an error `fail_to_proxy` is handed, or `None` when the client is what failed --
/// nearly always one that went away. That is not answered, and not counted as an error of ours.
///
/// The statuses are the ones Gapura answered before keys existed: a timeout is 504 only when the
/// upstream is the side that timed out, and the `HTTPStatus` errors this crate raises, 503 and
/// 504, keep their code. Any other `HTTPStatus` (none is raised today) is a 500.
pub fn classify(e: &Error) -> Option<ErrorKey> {
    let upstream = matches!(e.esource(), ErrorSource::Upstream);
    Some(match e.etype() {
        ErrorType::HTTPStatus(503) => ErrorKey::NoEndpoints,
        ErrorType::HTTPStatus(504) => ErrorKey::UpstreamTimeout,
        ErrorType::HTTPStatus(_) => ErrorKey::InternalError,
        _ if matches!(e.esource(), ErrorSource::Downstream) => return None,
        _ if !upstream => ErrorKey::InternalError,
        ErrorType::ConnectTimedout => ErrorKey::UpstreamConnectTimeout,
        ErrorType::ReadTimedout | ErrorType::WriteTimedout => ErrorKey::UpstreamTimeout,
        ErrorType::ConnectRefused | ErrorType::ConnectNoRoute | ErrorType::ConnectError => {
            ErrorKey::UpstreamConnectError
        }
        ErrorType::TLSHandshakeFailure
        | ErrorType::TLSHandshakeTimedout
        | ErrorType::InvalidCert => ErrorKey::UpstreamTlsError,
        _ => ErrorKey::UpstreamError,
    })
}

/// Whether an `Accept` value prefers JSON to plain text. Only a caller that names JSON gets it
/// -- `application/json` or `application/*` -- and only at a quality no lower than plain text
/// gets, so a missing Accept, `*/*` and a browser's `text/html,...,*/*;q=0.8` keep the plain
/// answer. The most specific range present decides each side (RFC 9110 section 12.5.1).
pub fn wants_json(accept: &str) -> bool {
    let ranges: Vec<(String, f32)> = accept
        .split(',')
        .map(|range| {
            let mut parts = range.split(';');
            let media = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
            let q = parts
                .find_map(|p| {
                    let (name, value) = p.split_once('=')?;
                    if name.trim().eq_ignore_ascii_case("q") {
                        value.trim().parse::<f32>().ok()
                    } else {
                        None
                    }
                })
                .unwrap_or(1.0);
            (media, q)
        })
        .collect();
    let q = |names: &[&str]| {
        names
            .iter()
            .find_map(|n| {
                ranges
                    .iter()
                    .find(|(m, _)| m.as_str() == *n)
                    .map(|&(_, q)| q)
            })
            .unwrap_or(0.0)
    };
    let json = q(&["application/json", "application/*"]);
    json > 0.0 && json >= q(&["text/plain", "text/*", "*/*"])
}

/// The body of the answer for `key`, with its content type: JSON when the caller prefers it,
/// otherwise the plain `"<status> <message>\n"` every local answer has always carried.
///
/// ponytail: one rendering for every route. Per-service response templates (Gravitee's) replace
/// this lookup when they land, chosen by the rule the request matched.
pub fn render(key: ErrorKey, request_id: &str, json: bool) -> (&'static str, String) {
    if json {
        let body = serde_json::json!({
            "error": { "key": key.as_str(), "message": key.message(), "request_id": request_id }
        });
        ("application/json", body.to_string())
    } else {
        (
            "text/plain; charset=utf-8",
            format!("{} {}\n", key.status(), key.message()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [ErrorKey; 15] = [
        ErrorKey::InvalidRequestTarget,
        ErrorKey::NoRoute,
        ErrorKey::NoBackend,
        ErrorKey::NoEndpoints,
        ErrorKey::AuthKeyMissing,
        ErrorKey::AuthKeyInvalid,
        ErrorKey::AuthJwtMissing,
        ErrorKey::AuthJwtInvalid,
        ErrorKey::RateLimited,
        ErrorKey::UpstreamConnectTimeout,
        ErrorKey::UpstreamTimeout,
        ErrorKey::UpstreamConnectError,
        ErrorKey::UpstreamTlsError,
        ErrorKey::UpstreamError,
        ErrorKey::InternalError,
    ];

    #[test]
    fn keys_are_distinct_and_say_nothing_internal() {
        let mut seen = std::collections::HashSet::new();
        for key in ALL {
            let s = key.as_str();
            assert!(seen.insert(s), "{s} twice");
            assert!(s.chars().all(|c| c.is_ascii_uppercase() || c == '_'), "{s}");
            assert!((400..600).contains(&key.status()), "{s}");
            let m = key.message();
            assert!(!m.is_empty() && !m.contains("pingora"), "{s}: {m}");
        }
    }

    #[test]
    fn plain_text_is_the_status_and_message() {
        let (ct, body) = render(ErrorKey::NoRoute, "r1", false);
        assert_eq!(ct, "text/plain; charset=utf-8");
        assert_eq!(body, "404 no route\n");
        assert_eq!(
            render(ErrorKey::AuthJwtInvalid, "r1", false).1,
            "401 unauthorized\n"
        );
        assert_eq!(
            render(ErrorKey::InternalError, "r1", false).1,
            "500 internal error\n"
        );
    }

    #[test]
    fn json_names_the_key_the_message_and_the_request_id() {
        let (ct, body) = render(ErrorKey::RateLimited, "req-\"7", true);
        assert_eq!(ct, "application/json");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"error": {"key": "RATE_LIMITED", "message": "too many requests", "request_id": "req-\"7"}})
        );
    }

    #[test]
    fn json_only_when_the_caller_names_it_at_no_lower_quality() {
        for accept in [
            "application/json",
            "application/*",
            "APPLICATION/JSON",
            "application/json;charset=utf-8",
            "application/json, text/plain",
            "text/plain;q=0.5, application/json",
            "application/json, */*;q=0.1",
        ] {
            assert!(wants_json(accept), "{accept:?}");
        }
        for accept in [
            "",
            "*/*",
            "text/plain",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "application/json;q=0",
            "application/json;q=0.5, text/plain",
            "application/json;q=0, application/*",
            "text/*, application/json;q=0.9",
        ] {
            assert!(!wants_json(accept), "{accept:?}");
        }
    }

    #[test]
    fn failures_keep_their_status_and_name_their_cause() {
        let cases: [(Box<Error>, Option<ErrorKey>); 17] = [
            (
                Error::new_up(ErrorType::ConnectTimedout),
                Some(ErrorKey::UpstreamConnectTimeout),
            ),
            (
                Error::new_up(ErrorType::ReadTimedout),
                Some(ErrorKey::UpstreamTimeout),
            ),
            (
                Error::new_up(ErrorType::WriteTimedout),
                Some(ErrorKey::UpstreamTimeout),
            ),
            (
                Error::new_up(ErrorType::ConnectRefused),
                Some(ErrorKey::UpstreamConnectError),
            ),
            (
                Error::new_up(ErrorType::ConnectNoRoute),
                Some(ErrorKey::UpstreamConnectError),
            ),
            (
                Error::new_up(ErrorType::ConnectError),
                Some(ErrorKey::UpstreamConnectError),
            ),
            (
                Error::new_up(ErrorType::TLSHandshakeFailure),
                Some(ErrorKey::UpstreamTlsError),
            ),
            (
                Error::new_up(ErrorType::TLSHandshakeTimedout),
                Some(ErrorKey::UpstreamTlsError),
            ),
            (
                Error::new_up(ErrorType::InvalidCert),
                Some(ErrorKey::UpstreamTlsError),
            ),
            (
                Error::new_up(ErrorType::ConnectionClosed),
                Some(ErrorKey::UpstreamError),
            ),
            (
                Error::new_up(ErrorType::ReadError),
                Some(ErrorKey::UpstreamError),
            ),
            (
                Error::explain(ErrorType::HTTPStatus(503), "x"),
                Some(ErrorKey::NoEndpoints),
            ),
            (
                Error::explain(ErrorType::HTTPStatus(504), "x"),
                Some(ErrorKey::UpstreamTimeout),
            ),
            (Error::new_down(ErrorType::ReadError), None),
            (
                Error::new_in(ErrorType::InternalError),
                Some(ErrorKey::InternalError),
            ),
            // A timeout that is not the upstream's was a 500 before keys existed, and stays one.
            (
                Error::new_in(ErrorType::ReadTimedout),
                Some(ErrorKey::InternalError),
            ),
            (
                Error::new(ErrorType::ConnectRefused),
                Some(ErrorKey::InternalError),
            ),
        ];
        for (e, want) in cases {
            assert_eq!(classify(&e), want, "{e}");
        }
        assert_eq!(ErrorKey::UpstreamConnectTimeout.status(), 504);
        assert_eq!(ErrorKey::UpstreamTlsError.status(), 502);
    }

    #[test]
    fn a_refusal_says_missing_or_invalid_and_nothing_more() {
        use gapura_core::credentials::Refusal as Key;
        use gapura_core::jwt::Refusal as Jwt;
        assert_eq!(ErrorKey::from(&Jwt::Missing), ErrorKey::AuthJwtMissing);
        for r in [
            Jwt::Malformed,
            Jwt::UnknownKey,
            Jwt::BadSignature,
            Jwt::Claims,
        ] {
            assert_eq!(ErrorKey::from(&r), ErrorKey::AuthJwtInvalid);
        }
        assert_eq!(ErrorKey::from(&Key::Missing), ErrorKey::AuthKeyMissing);
        assert_eq!(ErrorKey::from(&Key::Unknown), ErrorKey::AuthKeyInvalid);
    }
}
