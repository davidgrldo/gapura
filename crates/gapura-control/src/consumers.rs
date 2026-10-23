//! Consumers, their API keys, the key_auth and JWT requirements, and request limits: what a
//! request may contain, and how many may come.
//!
//! Pure, like `configuration`, whose permission rule it shares: a viewer reads, an editor creates
//! consumers, issues keys and switches key_auth, JWT and rate_limit policies on and off, an admin
//! deletes consumers and revokes keys.

use crate::configuration::{self, FieldError};
use gapura_core::config::{JwtPolicy, LimitBy, RateLimit};
use gapura_core::jwt::JwksError;
use k8s_openapi::jiff::Timestamp;
use serde::{Deserialize, Serialize};

/// The header a key is read from when the console names none.
pub const DEFAULT_HEADER: &str = "x-api-key";
pub const MAX_HEADER_CHARS: usize = 64;
/// The longest issuer or audience a JWT requirement may name.
pub const MAX_CLAIM_CHARS: usize = 512;
/// The largest JWKS document a JWT requirement may carry, shared with the data plane's fetch.
pub use gapura_core::jwt::MAX_JWKS_BYTES;
/// The longest `jwks_uri` a JWT requirement may name.
pub const MAX_JWKS_URI_CHARS: usize = 2048;

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
    /// The policy row's `updated_at` as this caller last read it, which a `PUT` replacing an
    /// existing requirement must send; a missing or different one answers 409 (#197, #223), and so
    /// does one sent when there is no requirement to replace.
    #[serde(default)]
    pub seen_updated_at: Option<String>,
}

/// Names a key cannot be read from: the connection's own, which a proxy owns, and the one the
/// data plane writes for the upstream (`gapura_core::credentials::CONSUMER_HEADER`, set in
/// `upstream_request_filter` after it removes the inbound one). `authorization` is not here:
/// people send keys in it.
///
/// The list binds what is already stored, not only what is written next: `Limit::from_config`
/// reads a stored limit's `by` header back through `header`, so a name added here later makes
/// every stored limit counting by that header fail the snapshot, and no data plane gets new
/// configuration until those rows are gone. A migration has to move such rows off the name before
/// a binary with the longer list ships.
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

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwtInput {
    pub target: String,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default)]
    pub jwks: Option<String>,
    /// Where the issuer publishes its JWKS, for each data plane to fetch: instead of `jwks`,
    /// never beside it.
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// PEM CA certificates that verify `jwks_uri` in place of the public roots.
    #[serde(default)]
    pub jwks_ca_pem: Option<String>,
    /// The policy row's `updated_at` as this caller last read it, which a `PUT` replacing an
    /// existing requirement must send; a missing or different one answers 409 (#197, #223), and so
    /// does one sent when there is no requirement to replace.
    #[serde(default)]
    pub seen_updated_at: Option<String>,
}

/// `value` trimmed, when it is 1 to `MAX_CLAIM_CHARS` characters with no control characters;
/// `None` when it is absent or empty.
fn claim(value: Option<&str>, at: &str, sentence: &str) -> Result<Option<String>, FieldError> {
    let Some(value) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    if value.chars().count() > MAX_CLAIM_CHARS || value.chars().any(char::is_control) {
        return Err(field(at, sentence));
    }
    Ok(Some(value.to_string()))
}

/// A JWT requirement: an issuer, which is required, since a policy without one accepts tokens
/// from any issuer whose key it lists; an audience, which is not; and its keys, either a JWKS
/// document that `gapura_core::jwt` finds at least one usable key in -- the reading the data plane
/// gives it, so a document the data plane would verify nothing with is refused here rather than
/// there -- or the https URL the issuer publishes them at, which each data plane fetches. Never
/// both. The control plane does not fetch the URL: it may sit in another network from the IdP,
/// and a fetch here would make the console a probe whose errors say what is reachable. A pasted
/// document holds public keys only: viewers read it back, so it must hold no secret.
pub fn jwt(input: &JwtInput) -> Result<JwtPolicy, FieldError> {
    let issuer_rule = format!(
        "Name the issuer tokens must carry as iss, in 1 to {MAX_CLAIM_CHARS} characters with no control characters."
    );
    let issuer = claim(input.issuer.as_deref(), "issuer", &issuer_rule)?
        .ok_or_else(|| field("issuer", &issuer_rule))?;
    let audience = claim(
        input.audience.as_deref(),
        "audience",
        &format!(
            "Leave the audience empty, or use 1 to {MAX_CLAIM_CHARS} characters with no control characters."
        ),
    )?;
    let jwks = input.jwks.as_deref().filter(|d| !d.trim().is_empty());
    let jwks_uri = input
        .jwks_uri
        .as_deref()
        .map(str::trim)
        .filter(|u| !u.is_empty());
    let jwks_ca_pem = input
        .jwks_ca_pem
        .clone()
        .filter(|pem| !pem.trim().is_empty());
    match (jwks, jwks_uri) {
        (Some(_), Some(_)) => Err(field(
            "jwks",
            "Give the keys or the URL they are published at, not both.",
        )),
        (None, None) => Err(field(
            "jwks",
            "Paste a JWKS document, or give the URL the issuer publishes its keys at.",
        )),
        (Some(document), None) => {
            if jwks_ca_pem.is_some() {
                return Err(field(
                    "jwks_ca_pem",
                    "A CA verifies the URL keys are fetched from; pasted keys need none.",
                ));
            }
            pasted(document)?;
            Ok(JwtPolicy {
                issuer: Some(issuer),
                audience,
                jwks: document.to_string(),
                ..JwtPolicy::default()
            })
        }
        (None, Some(uri)) => Ok(JwtPolicy {
            issuer: Some(issuer),
            audience,
            jwks: String::new(),
            jwks_uri: Some(key_url(uri)?),
            jwks_ca_pem: configuration::ca_pem(jwks_ca_pem, "jwks_ca_pem")?,
        }),
    }
}

/// A pasted JWKS document the data plane can verify with: at most `MAX_JWKS_BYTES`, readable,
/// no secret, at least one usable key.
fn pasted(jwks: &str) -> Result<(), FieldError> {
    if jwks.len() > MAX_JWKS_BYTES {
        return Err(field("jwks", "Paste at most 64 KiB of keys."));
    }
    let refused = match gapura_core::jwt::keys(jwks) {
        Err(JwksError::Unreadable) => {
            Some("Paste a JWKS document: a JSON object with a keys array.")
        }
        // Before whether any key is usable: an oct key is refused even beside public ones.
        _ if gapura_core::jwt::holds_a_secret(jwks) => Some(
            "Use public keys only: an oct key is a shared secret, and anyone who can read this workspace could read it.",
        ),
        Err(JwksError::NoUsableKey { .. }) => Some(
            "None of these keys can verify a token. Each needs an alg and key material the gateway reads.",
        ),
        Ok(_) => None,
    };
    match refused {
        Some(sentence) => Err(field("jwks", sentence)),
        None => Ok(()),
    }
}

/// An https URL with a host and no credentials, fragment or control character: where an issuer
/// publishes its keys. Kept as written; the data plane parses it again.
fn key_url(uri: &str) -> Result<String, FieldError> {
    let readable = uri.chars().count() <= MAX_JWKS_URI_CHARS
        // `Url::parse` drops tabs and newlines silently, so they are refused before it sees them.
        && !uri.chars().any(char::is_control)
        && reqwest::Url::parse(uri).is_ok_and(|url| {
            url.scheme() == "https"
                && url.host_str().is_some_and(|host| !host.is_empty())
                && url.username().is_empty()
                && url.password().is_none()
                && url.fragment().is_none()
        });
    if readable {
        Ok(uri.to_string())
    } else {
        Err(field(
            "jwks_uri",
            format!(
                "Use the https URL the issuer publishes its keys at, with no user name, password or #fragment, in at most {MAX_JWKS_URI_CHARS} characters."
            ),
        ))
    }
}

/// How many keys a stored JWKS holds that a token can be verified with; none for a document
/// only SQL written by hand could store.
pub fn usable_keys(jwks: &str) -> usize {
    gapura_core::jwt::keys(jwks).map_or(0, |k| k.usable())
}

/// A JWT requirement as a list shows it: never the JWKS, which is public but large.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct JwtView {
    pub target: String,
    pub issuer: Option<String>,
    pub audience: Option<String>,
    /// Usable keys in a pasted JWKS; 0 for keys fetched from `jwks_uri`, which the control plane
    /// never reads.
    pub keys: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
}

/// One target's JWT requirement with its JWKS or the URL it is fetched from, which the console
/// edits.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct JwtDocument {
    pub target: String,
    pub issuer: Option<String>,
    pub audience: Option<String>,
    pub jwks: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_ca_pem: Option<String>,
    /// The policy row's stamp, which a `PUT` replacing it sends back as `seen_updated_at`.
    pub updated_at: String,
}

/// The most requests a limit may allow per window.
pub const MAX_RATE_LIMIT: u32 = 1_000_000;

/// The window a request limit counts in, as the API names it; the `gapura.dev/rate-limit`
/// annotation's `s`, `min` and `h`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Per {
    Second,
    Minute,
    Hour,
}

impl Per {
    pub fn window_ms(self) -> u64 {
        match self {
            Per::Second => 1_000,
            Per::Minute => 60_000,
            Per::Hour => 3_600_000,
        }
    }

    fn of_window(window_ms: u64) -> Option<Per> {
        [Per::Second, Per::Minute, Per::Hour]
            .into_iter()
            .find(|p| p.window_ms() == window_ms)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitInput {
    pub target: String,
    #[serde(default)]
    pub limit: Option<serde_json::Value>,
    #[serde(default)]
    pub per: Option<serde_json::Value>,
    /// The consumer whose own limit this is; absent for a limit on everyone.
    #[serde(default)]
    pub consumer: Option<String>,
    /// What the limit counts by: `ip` (the default when absent or null), `consumer` or
    /// `header:<name>`.
    #[serde(default)]
    pub by: Option<serde_json::Value>,
    /// The policy row's `updated_at` as this caller last read it, which a `PUT` replacing an
    /// existing requirement must send; a missing or different one answers 409 (#197, #223), and so
    /// does one sent when there is no requirement to replace.
    #[serde(default)]
    pub seen_updated_at: Option<String>,
}

/// A request limit: at most `limit` requests per `per` from each client, as `by` tells them
/// apart -- by address, by consumer or by a header's value -- counted by each data plane replica
/// separately.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limit {
    pub limit: u32,
    pub per: Per,
    pub by: LimitBy,
}

/// The configuration a `rate_limit` row stores, and nothing else: an unknown field is a shape this
/// binary does not know, not one to ignore. `by` is absent for the address, so a row written
/// before it existed reads as it always did.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredLimit {
    limit: u32,
    window_ms: u64,
    #[serde(default, skip_serializing_if = "LimitBy::is_ip")]
    by: LimitBy,
}

impl Limit {
    /// What the row stores: `{"limit": n, "window_ms": ms}`, with `by` when it is not `ip`.
    pub fn config(&self) -> serde_json::Value {
        serde_json::to_value(StoredLimit {
            limit: self.limit,
            window_ms: self.per.window_ms(),
            by: self.by.clone(),
        })
        .expect("two numbers and a name always serialise")
    }

    /// A stored configuration read back, when it is one the API could have written: a limit of
    /// 1 to `MAX_RATE_LIMIT`, a window of a second, a minute or an hour, and a header to count by
    /// that `header` accepts as it is stored, lowercase. Anything else is `None`, and the
    /// compiler refuses it rather than serve a limit the console cannot show.
    pub fn from_config(config: serde_json::Value) -> Option<Limit> {
        let stored: StoredLimit = serde_json::from_value(config).ok()?;
        if !(1..=MAX_RATE_LIMIT).contains(&stored.limit) {
            return None;
        }
        if let LimitBy::Header(name) = &stored.by {
            if header(Some(name)).ok().as_ref() != Some(name) {
                return None;
            }
        }
        Some(Limit {
            limit: stored.limit,
            per: Per::of_window(stored.window_ms)?,
            by: stored.by,
        })
    }

    /// What the data plane enforces.
    pub fn rate_limit(&self) -> RateLimit {
        RateLimit {
            limit: self.limit,
            window_ms: self.per.window_ms(),
            by: self.by.clone(),
        }
    }
}

/// What a limit counts by, as a request sends it: `ip`, also when absent or null; `consumer`; or
/// `header:<name>`, with a name `header` accepts, stored lowercase.
fn limit_by(value: Option<&serde_json::Value>) -> Result<LimitBy, FieldError> {
    let Some(value) = value.filter(|v| !v.is_null()) else {
        return Ok(LimitBy::Ip);
    };
    let refused = || field("by", "Use ip, consumer or header:<name>.");
    match value.as_str().ok_or_else(refused)? {
        "ip" => Ok(LimitBy::Ip),
        "consumer" => Ok(LimitBy::Consumer),
        text => match text.strip_prefix("header:").map(str::trim) {
            Some(name) if !name.is_empty() => header(Some(name))
                .map(LimitBy::Header)
                .map_err(|e| field("by", e.sentence)),
            _ => Err(refused()),
        },
    }
}

/// `by` as the API spells it: `ip`, `consumer` or `header:<name>`.
pub fn by_text(by: &LimitBy) -> String {
    match by {
        LimitBy::Ip => "ip".to_string(),
        LimitBy::Consumer => "consumer".to_string(),
        LimitBy::Header(name) => format!("header:{name}"),
    }
}

/// `by` as a list or an audit row shows it: absent for the address, which every limit counted
/// by before `by` existed, so those rows read as they did.
pub fn shown_by(by: &LimitBy) -> Option<String> {
    (!by.is_ip()).then(|| by_text(by))
}

/// The consumer a request names a limit for, by the rule a consumer is created with; `None`
/// for a limit on everyone.
pub fn consumer_named(name: Option<&str>) -> Result<Option<String>, FieldError> {
    name.map(|n| configuration::name(n, "consumer")).transpose()
}

/// A request limit as a request sends it: `limit` a whole number from 1 to `MAX_RATE_LIMIT`,
/// `per` one of `second`, `minute` and `hour`, and `by` what it counts by, which `limit_by` reads.
pub fn rate_limit(input: &RateLimitInput) -> Result<Limit, FieldError> {
    let limit = input
        .limit
        .as_ref()
        .and_then(serde_json::Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .filter(|n| (1..=MAX_RATE_LIMIT).contains(n))
        .ok_or_else(|| {
            field(
                "limit",
                format!("Use a whole number of requests from 1 to {MAX_RATE_LIMIT}."),
            )
        })?;
    let per = match input.per.as_ref().and_then(serde_json::Value::as_str) {
        Some("second") => Per::Second,
        Some("minute") => Per::Minute,
        Some("hour") => Per::Hour,
        _ => return Err(field("per", "Use second, minute or hour.")),
    };
    let by = limit_by(input.by.as_ref())?;
    Ok(Limit { limit, per, by })
}

/// A request limit as the list shows it. `consumer` and `by` are absent for a limit on everyone
/// counted by address, so such a row reads as it did before either existed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RateLimitView {
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumer: Option<String>,
    pub limit: u32,
    pub per: Per,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    /// The policy row's stamp, which a `PUT` replacing it sends back as `seen_updated_at`.
    pub updated_at: String,
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
    /// The policy row's stamp, which a `PUT` replacing it sends back as `seen_updated_at`.
    pub updated_at: String,
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

    fn jwt_input(issuer: Option<&str>, audience: Option<&str>, jwks: &str) -> JwtInput {
        JwtInput {
            target: "workspace".into(),
            issuer: issuer.map(str::to_string),
            audience: audience.map(str::to_string),
            jwks: Some(jwks.into()),
            jwks_uri: None,
            jwks_ca_pem: None,
            seen_updated_at: None,
        }
    }

    /// RFC 7517's example P-256 public key.
    const JWKS: &str = r#"{"keys":[{"kty":"EC","crv":"P-256","alg":"ES256","kid":"k1","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}]}"#;
    const OCT: &str = r#"{"kty":"oct","alg":"HS256","kid":"k2","k":"c2VjcmV0"}"#;

    #[test]
    fn a_jwt_requirement_names_an_issuer_and_a_usable_key() {
        let ok = jwt(&jwt_input(Some(" https://id.example "), Some(""), JWKS)).unwrap();
        assert_eq!(ok.issuer.as_deref(), Some("https://id.example"));
        assert_eq!(ok.audience, None);
        assert_eq!(ok.jwks, JWKS, "kept as sent");
        assert_eq!(usable_keys(&ok.jwks), 1);

        let long = "a".repeat(MAX_CLAIM_CHARS + 1);
        for (input, at) in [
            (jwt_input(None, None, JWKS), "issuer"),
            (jwt_input(Some("  "), None, JWKS), "issuer"),
            (jwt_input(Some("a\nb"), None, JWKS), "issuer"),
            (jwt_input(Some(&long), None, JWKS), "issuer"),
            (jwt_input(Some("i"), Some("a\u{7f}"), JWKS), "audience"),
            (jwt_input(Some("i"), Some(&long), JWKS), "audience"),
            (jwt_input(Some("i"), None, "not json"), "jwks"),
            (jwt_input(Some("i"), None, r#"{"keys":[]}"#), "jwks"),
            (
                jwt_input(
                    Some("i"),
                    None,
                    r#"{"keys":[{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}]}"#,
                ),
                "jwks",
            ),
            (
                jwt_input(Some("i"), None, &" ".repeat(MAX_JWKS_BYTES + 1)),
                "jwks",
            ),
        ] {
            assert_eq!(jwt(&input).unwrap_err().field, at, "{input:?}");
        }
        let missing = JwtInput {
            jwks: None,
            ..jwt_input(Some("i"), None, "")
        };
        assert_eq!(jwt(&missing).unwrap_err().field, "jwks");
        // A shared secret is refused alone or beside a public key, and says why.
        let public = &JWKS[JWKS.find('[').unwrap() + 1..JWKS.rfind(']').unwrap()];
        for keys in [OCT.to_string(), format!("{public},{OCT}")] {
            let e = jwt(&jwt_input(
                Some("i"),
                None,
                &format!(r#"{{"keys":[{keys}]}}"#),
            ))
            .unwrap_err();
            assert_eq!(e.field, "jwks", "{keys}");
            assert!(e.sentence.starts_with("Use public keys only"), "{keys}");
        }
        // Exactly at the limit is a length, not a refusal.
        assert!(jwt(&jwt_input(Some(&"a".repeat(MAX_CLAIM_CHARS)), None, JWKS)).is_ok());
    }

    fn uri_input(uri: &str, ca: Option<&str>) -> JwtInput {
        JwtInput {
            jwks: None,
            jwks_uri: Some(uri.into()),
            jwks_ca_pem: ca.map(str::to_string),
            ..jwt_input(Some("i"), None, "")
        }
    }

    #[test]
    fn a_jwt_requirement_can_take_its_keys_from_a_url_instead() {
        let ok = jwt(&uri_input(
            " https://idp.example/.well-known/jwks.json ",
            None,
        ))
        .unwrap();
        assert_eq!(
            ok.jwks_uri.as_deref(),
            Some("https://idp.example/.well-known/jwks.json")
        );
        assert_eq!(
            (ok.jwks.as_str(), ok.jwks_ca_pem),
            ("", None),
            "fetched by the data plane"
        );

        let long = format!("https://idp.example/{}", "a".repeat(MAX_JWKS_URI_CHARS));
        for bad in [
            "http://idp.example/jwks",
            "https://user:pw@idp.example/jwks",
            "https://idp.example/jwks#k",
            "idp.example/jwks",
            "https://idp.exa\nmple/jwks",
            long.as_str(),
        ] {
            assert_eq!(
                jwt(&uri_input(bad, None)).unwrap_err().field,
                "jwks_uri",
                "{bad:?}"
            );
        }

        let both = JwtInput {
            jwks: Some(JWKS.into()),
            ..uri_input("https://idp.example/jwks", None)
        };
        assert_eq!(jwt(&both).unwrap_err().field, "jwks");

        let ca = rcgen::generate_simple_self_signed(vec!["idp.internal".into()])
            .unwrap()
            .cert
            .pem();
        let pasted_with_ca = JwtInput {
            jwks_ca_pem: Some(ca.clone()),
            ..jwt_input(Some("i"), None, JWKS)
        };
        assert_eq!(jwt(&pasted_with_ca).unwrap_err().field, "jwks_ca_pem");
        assert_eq!(
            jwt(&uri_input("https://idp.example/jwks", Some("not pem")))
                .unwrap_err()
                .field,
            "jwks_ca_pem"
        );
        let pinned = jwt(&uri_input("https://idp.internal/jwks", Some(&ca))).unwrap();
        assert_eq!(pinned.jwks_ca_pem.as_deref(), Some(ca.as_str()));
        assert_eq!(
            jwt(&uri_input("https://idp.example/jwks", Some("  ")))
                .unwrap()
                .jwks_ca_pem,
            None,
            "an empty CA is none"
        );
    }

    fn limit_input(limit: serde_json::Value, per: serde_json::Value) -> RateLimitInput {
        RateLimitInput {
            target: "workspace".into(),
            limit: Some(limit),
            per: Some(per),
            consumer: None,
            by: None,
            seen_updated_at: None,
        }
    }

    #[test]
    fn a_rate_limit_is_a_count_from_one_to_a_million_per_second_minute_or_hour() {
        use serde_json::json;
        for (limit, per, window_ms) in [
            (1, "second", 1_000),
            (120, "minute", 60_000),
            (1_000_000, "hour", 3_600_000),
        ] {
            let got = rate_limit(&limit_input(json!(limit), json!(per))).unwrap();
            assert_eq!(got.limit, limit);
            assert_eq!(
                got.rate_limit(),
                RateLimit {
                    limit,
                    window_ms,
                    by: gapura_core::config::LimitBy::Ip,
                },
                "{limit}/{per}"
            );
            assert_eq!(
                got.config(),
                json!({"limit": limit, "window_ms": window_ms})
            );
            assert_eq!(Limit::from_config(got.config()), Some(got), "read back");
        }
        for bad in [
            json!(0),
            json!(-1),
            json!(1_000_001),
            json!(1.5),
            json!("10"),
            json!(null),
            json!(u64::MAX),
        ] {
            assert_eq!(
                rate_limit(&limit_input(bad.clone(), json!("minute")))
                    .unwrap_err()
                    .field,
                "limit",
                "{bad}"
            );
        }
        for bad in [
            json!("min"),
            json!("s"),
            json!("day"),
            json!("Minute"),
            json!(60),
        ] {
            assert_eq!(
                rate_limit(&limit_input(json!(10), bad.clone()))
                    .unwrap_err()
                    .field,
                "per",
                "{bad}"
            );
        }
        let missing = RateLimitInput {
            target: "workspace".into(),
            limit: None,
            per: None,
            consumer: None,
            by: None,
            seen_updated_at: None,
        };
        assert_eq!(rate_limit(&missing).unwrap_err().field, "limit");
    }

    #[test]
    fn a_limit_counts_by_the_address_unless_it_names_a_consumer_or_a_header() {
        use serde_json::json;
        let with_by = |by: serde_json::Value| RateLimitInput {
            by: Some(by),
            ..limit_input(json!(10), json!("minute"))
        };
        assert_eq!(
            rate_limit(&limit_input(json!(10), json!("minute")))
                .unwrap()
                .by,
            LimitBy::Ip
        );
        for (by, want) in [
            (json!(null), LimitBy::Ip),
            (json!("ip"), LimitBy::Ip),
            (json!("consumer"), LimitBy::Consumer),
            (json!("header:X-Tenant"), LimitBy::Header("x-tenant".into())),
            (
                json!("header: x-tenant "),
                LimitBy::Header("x-tenant".into()),
            ),
        ] {
            let got = rate_limit(&with_by(by.clone())).unwrap();
            assert_eq!(got.by, want, "{by}");
            assert_eq!(
                Limit::from_config(got.config()),
                Some(got.clone()),
                "read back {by}"
            );
            assert_eq!(got.rate_limit().by, want, "what the data plane counts by");
        }
        for bad in [
            json!("everyone"),
            json!("header:"),
            json!("header:host"),
            json!("header:a b"),
            json!("Consumer"),
            json!(7),
        ] {
            assert_eq!(
                rate_limit(&with_by(bad.clone())).unwrap_err().field,
                "by",
                "{bad}"
            );
        }
        assert_eq!(
            by_text(&LimitBy::Header("x-tenant".into())),
            "header:x-tenant"
        );
        assert_eq!(shown_by(&LimitBy::Ip), None);
        assert_eq!(shown_by(&LimitBy::Consumer).as_deref(), Some("consumer"));
    }

    #[test]
    fn a_consumer_is_named_as_a_consumer_is_created() {
        assert_eq!(consumer_named(None).unwrap(), None);
        assert_eq!(
            consumer_named(Some("mobile")).unwrap().as_deref(),
            Some("mobile")
        );
        for bad in ["", "a b", ".."] {
            assert_eq!(
                consumer_named(Some(bad)).unwrap_err().field,
                "consumer",
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_stored_rate_limit_reads_back_only_in_the_shape_the_api_writes() {
        use serde_json::json;
        for bad in [
            json!({"limit": 10, "window_ms": 5_000}),
            json!({"limit": 0, "window_ms": 1_000}),
            json!({"limit": 1_000_001, "window_ms": 1_000}),
            json!({"limit": 10}),
            json!({"window_ms": 1_000}),
            json!({"limit": "10", "window_ms": 1_000}),
            json!({"limit": 10, "window_ms": 1_000, "by": "header"}),
            json!({"limit": 10, "window_ms": 1_000, "by": "everyone"}),
            json!({"limit": 10, "window_ms": 1_000, "by": {"header": ""}}),
            json!({"limit": 10, "window_ms": 1_000, "by": {"header": "Host"}}),
            json!({"limit": 10, "window_ms": 1_000, "by": {"header": "X-Tenant"}}),
            json!(null),
        ] {
            assert_eq!(Limit::from_config(bad.clone()), None, "{bad}");
        }
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
