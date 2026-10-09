//! Consumers, their API keys, and the key_auth requirement: what a request may contain.
//!
//! Pure, like `configuration`, whose permission rule it shares: a viewer reads, an editor creates
//! consumers, issues keys and switches key_auth on and off, an admin deletes consumers and revokes
//! keys.

use crate::configuration::{self, FieldError};
use k8s_openapi::jiff::Timestamp;
use serde::{Deserialize, Serialize};

/// The header a key is read from when the console names none.
pub const DEFAULT_HEADER: &str = "x-api-key";
pub const MAX_HEADER_CHARS: usize = 64;

fn field(field: &str, sentence: impl Into<String>) -> FieldError {
    FieldError {
        field: field.into(),
        sentence: sentence.into(),
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumerInput {
    pub name: String,
}

/// A consumer's name: the services and routes rule, since it is what an upstream is told.
pub fn consumer(input: ConsumerInput) -> Result<String, FieldError> {
    configuration::name(&input.name, "name")
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyInput {
    #[serde(default)]
    pub expires_at: Option<String>,
}

/// When a new key stops working: absent, or an RFC 3339 time after `now`. Returned in the same
/// RFC 3339 form, which Postgres reads as `timestamptz`.
pub fn expiry(input: &KeyInput, now: Timestamp) -> Result<Option<String>, FieldError> {
    let Some(text) = input
        .expires_at
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
    else {
        return Ok(None);
    };
    let at: Timestamp = text.parse().map_err(|_| {
        field(
            "expires_at",
            "Use a date and time such as 2026-12-31T00:00:00Z.",
        )
    })?;
    if at <= now {
        return Err(field(
            "expires_at",
            "Pick a time in the future, or leave it empty.",
        ));
    }
    Ok(Some(at.to_string()))
}

/// A key_auth target: the whole workspace, or one named service or route of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    Workspace,
    Service(String),
    Route(String),
}

impl Target {
    pub fn parse(text: &str) -> Result<Target, FieldError> {
        let bad = || field("target", "Name workspace, service:<name> or route:<name>.");
        match text.split_once(':') {
            None if text == "workspace" => Ok(Target::Workspace),
            Some(("service", name)) => configuration::name(name, "target")
                .map(Target::Service)
                .map_err(|_| bad()),
            Some(("route", name)) => configuration::name(name, "target")
                .map(Target::Route)
                .map_err(|_| bad()),
            _ => Err(bad()),
        }
    }

    pub fn as_text(&self) -> String {
        match self {
            Target::Workspace => "workspace".into(),
            Target::Service(n) => format!("service:{n}"),
            Target::Route(n) => format!("route:{n}"),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyAuthInput {
    pub target: String,
    #[serde(default)]
    pub header: Option<String>,
}

/// Names a key cannot be read from: the connection's own, which a proxy owns, and the one the
/// data plane writes for the upstream (`gapura_core::credentials::CONSUMER_HEADER`, set in
/// `upstream_request_filter` after it removes the inbound one). `authorization` is not here:
/// people send keys in it.
const RESERVED_HEADERS: &[&str] = &[
    gapura_core::credentials::CONSUMER_HEADER,
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "te",
    "upgrade",
];

/// An HTTP header name (RFC 9110 token characters), lowercased; `x-api-key` when absent.
pub fn header(value: Option<&str>) -> Result<String, FieldError> {
    let value = value
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .unwrap_or(DEFAULT_HEADER);
    if value.len() > MAX_HEADER_CHARS || !configuration::header_token(value) {
        return Err(field(
            "header",
            format!(
                "Use a header name of 1 to {MAX_HEADER_CHARS} letters, digits and - _ . ! # $ % & ' * + ^ ` | ~, with no spaces or colons."
            ),
        ));
    }
    let value = value.to_ascii_lowercase();
    if RESERVED_HEADERS.contains(&value.as_str()) {
        return Err(field(
            "header",
            format!(
                "The {value} header is set by the connection or the gateway. Pick another name."
            ),
        ));
    }
    Ok(value)
}

/// A key as a list shows it: never the key, never its hash.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct KeyView {
    pub prefix: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub expired: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConsumerView {
    pub name: String,
    pub keys: Vec<KeyView>,
}

/// What issuing answers with, the only time the key itself is shown.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct IssuedKey {
    pub key: String,
    pub prefix: String,
    pub expires_at: Option<String>,
}

/// By hand, so that a `{:?}` in a log or a failed assertion never prints the key.
impl std::fmt::Debug for IssuedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedKey")
            .field("key", &"<redacted>")
            .field("prefix", &self.prefix)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PolicyView {
    pub target: String,
    pub header: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> Timestamp {
        "2026-10-08T00:00:00Z".parse().unwrap()
    }

    #[test]
    fn a_consumer_name_follows_the_configuration_rule() {
        assert_eq!(
            consumer(ConsumerInput {
                name: "mobile-app".into()
            })
            .unwrap(),
            "mobile-app"
        );
        assert_eq!(
            consumer(ConsumerInput { name: "..".into() })
                .unwrap_err()
                .field,
            "name"
        );
    }

    #[test]
    fn an_expiry_is_absent_or_in_the_future() {
        let at = |s: &str| KeyInput {
            expires_at: Some(s.into()),
        };
        assert_eq!(expiry(&KeyInput::default(), now()).unwrap(), None);
        assert_eq!(expiry(&at(""), now()).unwrap(), None);
        assert!(expiry(&at("2026-12-31T00:00:00Z"), now())
            .unwrap()
            .is_some());
        assert_eq!(
            expiry(&at("2026-01-01T00:00:00Z"), now())
                .unwrap_err()
                .field,
            "expires_at"
        );
        assert_eq!(
            expiry(&at("tomorrow"), now()).unwrap_err().field,
            "expires_at"
        );
        // An offset is kept as the instant it names, in UTC.
        assert_eq!(
            expiry(&at("2030-01-01T07:00:00+07:00"), now()).unwrap(),
            Some("2030-01-01T00:00:00Z".to_string())
        );
    }

    #[test]
    fn targets_parse_and_print_back() {
        for text in ["workspace", "service:orders", "route:orders-api"] {
            assert_eq!(Target::parse(text).unwrap().as_text(), text);
        }
        for bad in [
            "",
            "route",
            "route:",
            "route:..",
            "consumer:x",
            "service:a b",
        ] {
            assert_eq!(Target::parse(bad).unwrap_err().field, "target", "{bad:?}");
        }
    }

    #[test]
    fn a_header_is_a_token_lowercased_with_a_default() {
        assert_eq!(header(None).unwrap(), "x-api-key");
        assert_eq!(header(Some("X-Token")).unwrap(), "x-token");
        assert_eq!(header(Some("  ")).unwrap(), "x-api-key");
        for bad in ["x token", "x:y", "é"] {
            assert_eq!(header(Some(bad)).unwrap_err().field, "header");
        }
        assert!(header(Some(&"a".repeat(65))).is_err());
    }

    #[test]
    fn a_header_the_connection_or_the_gateway_owns_is_refused() {
        for bad in [
            "x-consumer-username",
            "X-Consumer-Username",
            "Host",
            "content-length",
            "Transfer-Encoding",
            "connection",
            "TE",
            "upgrade",
        ] {
            let e = header(Some(bad)).unwrap_err();
            assert_eq!(e.field, "header", "{bad}");
            assert!(e.sentence.contains("Pick another"), "{bad}");
        }
        assert_eq!(header(Some("Authorization")).unwrap(), "authorization");
    }

    #[test]
    fn an_issued_key_is_not_printed() {
        let issued = IssuedKey {
            key: "gpak_secret".into(),
            prefix: "gpak_abcd".into(),
            expires_at: None,
        };
        let shown = format!("{issued:?}");
        assert!(!shown.contains("gpak_secret"), "{shown}");
        assert!(shown.contains("gpak_abcd"), "{shown}");
    }
}
