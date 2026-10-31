//! The policies kept through `/api/workspaces/{ws}/policies/{kind}`: one endpoint for every kind
//! whose stored configuration is the policy itself, checked here and stored in the form the data
//! plane reads. key_auth, jwt and rate_limit keep the endpoints they had.
//!
//! Pure, like `consumers`: the same check reads a request's body and a stored row, so a row only
//! SQL written by hand could make fails the snapshot as a request carrying it would be refused.

use crate::configuration::{self, FieldError, METHODS};
use gapura_core::client_ip::Cidr;
use gapura_core::config::{
    AclPolicy, AuthPolicy, CorsPolicy, HeaderEdits, IpRestrictionPolicy, Plugin,
    RequestSizeLimitPolicy, RequestTransformerPolicy, ResponseTransformerPolicy,
};
use gapura_core::credentials::{ANONYMOUS_HEADER, CONSUMER_HEADER, GATEWAY_HEADERS, GROUPS_HEADER};
use serde::{Deserialize, Serialize};

/// The kinds this endpoint keeps, as [`Plugin::kind`] names them.
pub const KINDS: &[&str] = &[
    "ip_restriction",
    "request_size_limit",
    "request_transformer",
    "response_transformer",
    "cors",
    "auth",
    "acl",
];

/// The most addresses and networks an ip_restriction policy lists, allow and deny together:
/// 1000 of the longest IPv6 networks still fit in the 64 KiB a request body may carry.
pub const MAX_NETWORKS: usize = 1000;

/// The largest body limit a policy may set, 1 GiB: past it a limit is no limit.
pub const MAX_BODY_BYTES: u64 = 1 << 30;

/// The most edits a transformer policy lists, headers and query together, as
/// [`HeaderEdits::len`] counts them. Each one is a pass over the head on every request the rule
/// answers, so this bounds what a policy adds to every request; 64 is more than a route's
/// transform needs.
pub const MAX_EDITS: usize = 64;

/// The longest value a transformer writes, in characters. A bearer token or a signed cookie for
/// the upstream fits; a header much longer would meet the 8 KiB many servers allow a whole head
/// before it met anything else.
pub const MAX_VALUE_CHARS: usize = 4096;

/// The longest header name or query parameter name a transformer names, in characters: far past
/// any name in use, so it refuses only a mistake, and bounds what one edit adds to a head.
const MAX_NAME_CHARS: usize = 256;

/// The most origins a cors policy lists: more than a route has callers, and a bound on the list
/// the data plane walks for every request that names an origin.
pub const MAX_ORIGINS: usize = 100;

/// The most header names a cors policy lists in `headers`, and again in `expose_headers`.
pub const MAX_CORS_HEADERS: usize = 64;

/// The longest a browser may keep a cors policy's preflight answer, a day: Firefox keeps one no
/// longer, and Chromium no longer than two hours.
pub const MAX_AGE_SECS: u64 = 86_400;

/// The most groups an acl policy lists in `allow`, and again in `deny`: the data plane checks the
/// caller's groups against both lists on every request the rule answers.
pub const MAX_ACL_GROUPS: usize = 100;

/// What a cors policy tells a preflight when it names no methods: Kong's default, less `OPTIONS`,
/// which is the preflight's own.
const CORS_METHODS: [&str; 6] = ["GET", "HEAD", "PUT", "PATCH", "POST", "DELETE"];

/// The header names no transformer writes, removes or renames: what says how HTTP frames a
/// message, where it goes, and what the connection carrying it does. A transform that removed
/// `content-length` or added a `transfer-encoding` would have the upstream read the body
/// differently from the gateway -- request smuggling, by configuration; one that wrote
/// `connection` or `upgrade` would steer the connection the gateway keeps to the upstream, and
/// one that wrote `host` would send the request to a virtual host the route never named. The data
/// plane does not refuse these itself, so this is the only guard.
const FRAMING: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
    "proxy-connection",
];

fn field(field: &str, sentence: impl Into<String>) -> FieldError {
    FieldError {
        field: field.into(),
        sentence: sentence.into(),
    }
}

/// A `PUT` body.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyInput {
    pub target: String,
    /// The policy, in the shape its kind reads.
    pub config: serde_json::Value,
    /// The policy row's `updated_at` as this caller last read it, which a `PUT` replacing a
    /// policy must send; a missing or different one answers 409 (#197, #223), and so does one
    /// sent when there is none to replace.
    #[serde(default)]
    pub seen_updated_at: Option<String>,
}

/// `config` as a policy of `kind`, or the field that is wrong with it.
pub fn parse(kind: &str, config: serde_json::Value) -> Result<Plugin, FieldError> {
    match kind {
        "ip_restriction" => ip_restriction(config).map(Plugin::IpRestriction),
        "request_size_limit" => request_size_limit(config).map(Plugin::RequestSizeLimit),
        "request_transformer" => request_transformer(config).map(Plugin::RequestTransformer),
        "response_transformer" => response_transformer(config).map(Plugin::ResponseTransformer),
        "cors" => cors(config).map(Plugin::Cors),
        "auth" => auth(config).map(Plugin::Auth),
        "acl" => acl(config).map(Plugin::Acl),
        _ => Err(field("kind", "There is no such policy kind.")),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IpRestrictionInput {
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    deny: Vec<String>,
}

fn ip_restriction(config: serde_json::Value) -> Result<IpRestrictionPolicy, FieldError> {
    let input: IpRestrictionInput = serde_json::from_value(config).map_err(|_| {
        field(
            "config",
            "Send allow and deny, each a list of addresses or networks such as 10.0.0.0/8.",
        )
    })?;
    // Nothing listed restricts nothing: a policy that looks like it guards a route and admits
    // everyone.
    if input.allow.is_empty() && input.deny.is_empty() {
        return Err(field(
            "allow",
            "List at least one address or network to allow or to deny.",
        ));
    }
    if input.allow.len() + input.deny.len() > MAX_NETWORKS {
        return Err(field(
            "allow",
            format!("List at most {MAX_NETWORKS} addresses and networks, allow and deny together."),
        ));
    }
    let networks = |name: &str, list: &[String]| -> Result<Vec<Cidr>, FieldError> {
        list.iter()
            .map(|text| {
                text.parse::<Cidr>().map_err(|e| {
                    field(
                        name,
                        format!(
                            "{e}. Write an address such as 203.0.113.7 or a network such as \
                             10.0.0.0/8."
                        ),
                    )
                })
            })
            .collect()
    };
    Ok(IpRestrictionPolicy {
        allow: networks("allow", &input.allow)?,
        deny: networks("deny", &input.deny)?,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AclInput {
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    deny: Vec<String>,
}

/// An acl policy: the groups it admits and the groups it refuses, each named as a consumer's
/// group is (`consumers::group`), so a list can only name groups a consumer could be in.
fn acl(config: serde_json::Value) -> Result<AclPolicy, FieldError> {
    let input: AclInput = serde_json::from_value(config)
        .map_err(|_| field("config", "Send allow and deny, each a list of group names."))?;
    // Nothing listed refuses nothing but callers without a consumer, which reads like a policy
    // that guards a route by group and does not.
    if input.allow.is_empty() && input.deny.is_empty() {
        return Err(field(
            "allow",
            "List at least one group to allow or to deny.",
        ));
    }
    let groups = |at: &str, list: Vec<String>| -> Result<Vec<String>, FieldError> {
        if list.len() > MAX_ACL_GROUPS {
            return Err(field(at, format!("List at most {MAX_ACL_GROUPS} groups.")));
        }
        list.iter()
            .map(|g| crate::consumers::group(g).map_err(|e| field(at, e.sentence)))
            .collect()
    };
    Ok(AclPolicy {
        allow: groups("allow", input.allow)?,
        deny: groups("deny", input.deny)?,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthInput {
    #[serde(default)]
    anonymous: Option<String>,
}

/// An auth policy: who a caller without a credential is, by a consumer's name, or nobody. That
/// the consumer exists is the store's to check, in the write. The workspace the data plane looks
/// the consumer up in is stamped by the compiler, so a request that sends one is refused rather
/// than believed.
fn auth(config: serde_json::Value) -> Result<AuthPolicy, FieldError> {
    let input: AuthInput = serde_json::from_value(config)
        .map_err(|_| field("config", "Send anonymous, a consumer's name, or nothing."))?;
    let anonymous = input
        .anonymous
        .filter(|n| !n.trim().is_empty())
        .map(|n| configuration::name(&n, "anonymous"))
        .transpose()?;
    Ok(AuthPolicy {
        anonymous,
        workspace: None,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestSizeLimitInput {
    /// Read as any JSON value and judged below, so that a string, a negative number or a
    /// fraction is named as `max_bytes` rather than as the whole configuration.
    max_bytes: serde_json::Value,
}

fn request_size_limit(config: serde_json::Value) -> Result<RequestSizeLimitPolicy, FieldError> {
    let input: RequestSizeLimitInput = serde_json::from_value(config)
        .map_err(|_| field("config", "Send max_bytes, the largest body in bytes."))?;
    // Zero refuses every request with a body, a route switched off in the guise of a limit; past
    // MAX_BODY_BYTES a limit no longer limits anything a gateway should pass.
    input
        .max_bytes
        .as_u64()
        .filter(|n| (1..=MAX_BODY_BYTES).contains(n))
        .map(|max_bytes| RequestSizeLimitPolicy { max_bytes })
        .ok_or_else(|| {
            field(
                "max_bytes",
                format!("Use a whole number of bytes from 1 to {MAX_BODY_BYTES}."),
            )
        })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestTransformerInput {
    /// Each read as any JSON value and judged by [`edits`], so that a list in the wrong shape is
    /// named by its dotted field, `headers.add`, rather than as the whole configuration.
    #[serde(default)]
    headers: serde_json::Value,
    #[serde(default)]
    query: serde_json::Value,
}

/// A response has no query string, so `query` here is an unknown field, refused as the
/// configuration rather than stored and never applied.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseTransformerInput {
    #[serde(default)]
    headers: serde_json::Value,
}

fn request_transformer(config: serde_json::Value) -> Result<RequestTransformerPolicy, FieldError> {
    let input: RequestTransformerInput = object(
        "config",
        config,
        "Send headers and query, each with any of remove, rename, replace, add and append.",
    )?;
    // The request transform runs after the gateway has set the headers about the caller from the
    // credential it checked, so a transform that wrote one would name whichever consumer, groups
    // or anonymous caller the policy said.
    let refused: Vec<&str> = FRAMING.iter().copied().chain(GATEWAY_HEADERS).collect();
    let policy = RequestTransformerPolicy {
        headers: edits("headers", &input.headers, true, &refused)?,
        query: edits("query", &input.query, false, &[])?,
    };
    counted(&[("headers", &policy.headers), ("query", &policy.query)])?;
    Ok(policy)
}

fn response_transformer(
    config: serde_json::Value,
) -> Result<ResponseTransformerPolicy, FieldError> {
    let input: ResponseTransformerInput = object(
        "config",
        config,
        "Send headers, with any of remove, rename, replace, add and append.",
    )?;
    let policy = ResponseTransformerPolicy {
        headers: edits("headers", &input.headers, true, FRAMING)?,
    };
    counted(&[("headers", &policy.headers)])?;
    Ok(policy)
}

/// Each read as any JSON value and judged in [`cors`], so that a field in the wrong shape is
/// named by itself rather than as the whole configuration.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CorsInput {
    #[serde(default)]
    origins: serde_json::Value,
    #[serde(default)]
    methods: serde_json::Value,
    #[serde(default)]
    headers: serde_json::Value,
    #[serde(default)]
    expose_headers: serde_json::Value,
    #[serde(default)]
    credentials: serde_json::Value,
    #[serde(default)]
    max_age: serde_json::Value,
    #[serde(default)]
    preflight_continue: serde_json::Value,
}

/// A cors policy, stored with every default filled in, so the data plane reads it as it is:
/// origins lowercased with the scheme's own port left off, as a browser writes `Origin`; methods
/// uppercased, [`CORS_METHODS`] when none are named; header names lowercased.
fn cors(config: serde_json::Value) -> Result<CorsPolicy, FieldError> {
    let input: CorsInput = object(
        "config",
        config,
        "Send origins, and any of methods, headers, expose_headers, credentials, max_age and \
         preflight_continue.",
    )?;
    let credentials = flag("credentials", input.credentials)?;
    let origins = texts("origins", input.origins, r#"["https://app.example.com"]"#)?;
    if origins.is_empty() {
        return Err(field(
            "origins",
            "List at least one origin, such as https://app.example.com.",
        ));
    }
    if origins.len() > MAX_ORIGINS {
        return Err(field(
            "origins",
            format!("List at most {MAX_ORIGINS} origins."),
        ));
    }
    let origins = origins
        .iter()
        .map(|text| origin(text))
        .collect::<Result<Vec<_>, _>>()?;
    if origins.iter().any(|o| o == "*") {
        // A browser refuses `*` with credentials, and echoing every origin instead would let any
        // page read a signed-in user's answers.
        if credentials {
            return Err(field(
                "origins",
                "An origin of * cannot be sent with credentials: list the origins instead.",
            ));
        }
        if origins.len() > 1 {
            return Err(field(
                "origins",
                "List * alone: it already allows every origin.",
            ));
        }
    }
    let methods = texts("methods", input.methods, r#"["GET", "POST"]"#)?;
    let methods = if methods.is_empty() {
        CORS_METHODS.map(String::from).to_vec()
    } else {
        methods
            .into_iter()
            .map(|m| {
                let m = m.to_ascii_uppercase();
                if METHODS.contains(&m.as_str()) {
                    Ok(m)
                } else {
                    Err(field(
                        "methods",
                        format!("Use methods from {}.", METHODS.join(", ")),
                    ))
                }
            })
            .collect::<Result<_, _>>()?
    };
    let max_age = if input.max_age.is_null() {
        None
    } else {
        let secs = input
            .max_age
            .as_u64()
            .filter(|n| *n <= MAX_AGE_SECS)
            .ok_or_else(|| {
                field(
                    "max_age",
                    format!("Use a whole number of seconds from 0 to {MAX_AGE_SECS}."),
                )
            })?;
        Some(secs as u32)
    };
    Ok(CorsPolicy {
        origins,
        methods,
        headers: header_names("headers", input.headers)?,
        expose_headers: header_names("expose_headers", input.expose_headers)?,
        credentials,
        max_age,
        preflight_continue: flag("preflight_continue", input.preflight_continue)?,
    })
}

/// One origin entry in the form the data plane matches, or why it is not one: `*`;
/// `scheme://host[:port]`; or `scheme://*.suffix[:port]`, the `*` standing for one label. The
/// scheme is http or https, the host is letters, digits, hyphens and dots (an international name
/// in its `xn--` form), and nothing follows the port.
fn origin(text: &str) -> Result<String, FieldError> {
    let lower = text.to_ascii_lowercase();
    if lower == "*" {
        return Ok(lower);
    }
    if lower == "null" {
        return Err(field(
            "origins",
            "null is the origin of a sandboxed page or a local file, which any page can claim, so \
             it cannot be allowed.",
        ));
    }
    let shape = || {
        field(
            "origins",
            format!(
                "{text} is not an origin. Write scheme://host or scheme://host:port, such as \
                 https://app.example.com or https://*.example.com, with no path."
            ),
        )
    };
    let (scheme, rest) = lower.split_once("://").ok_or_else(shape)?;
    if scheme != "http" && scheme != "https" {
        return Err(shape());
    }
    let (host, port) = match rest.split_once(':') {
        Some((host, port)) => {
            let n = port
                .bytes()
                .all(|b| b.is_ascii_digit())
                .then(|| port.parse::<u16>().ok())
                .flatten()
                .filter(|n| *n > 0)
                .ok_or_else(shape)?;
            (host, Some(n))
        }
        None => (rest, None),
    };
    let (wildcard, name) = match host.strip_prefix("*.") {
        Some(name) => (true, name),
        None => (false, host),
    };
    let label = |l: &str| {
        (1..=63).contains(&l.len())
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    if name.len() > 253 || !name.split('.').all(label) {
        return Err(shape());
    }
    if wildcard && !name.contains('.') {
        return Err(field(
            "origins",
            format!(
                "{text} would allow every name under {name}. Put *. before a name with a dot in \
                 it, such as https://*.example.com."
            ),
        ));
    }
    // A browser leaves the scheme's own port out of `Origin`, so an entry that named it would
    // never match.
    let port = match (scheme, port) {
        ("http", Some(80)) | ("https", Some(443)) | (_, None) => String::new(),
        (_, Some(n)) => format!(":{n}"),
    };
    Ok(format!("{scheme}://{host}{port}"))
}

/// A list of text at `at`, empty when absent.
fn texts(at: &str, value: serde_json::Value, example: &str) -> Result<Vec<String>, FieldError> {
    if value.is_null() {
        return Ok(Vec::new());
    }
    serde_json::from_value(value).map_err(|_| field(at, format!("List text, such as {example}.")))
}

/// `true` or `false` at `at`, `false` when absent.
fn flag(at: &str, value: serde_json::Value) -> Result<bool, FieldError> {
    match value {
        serde_json::Value::Null => Ok(false),
        serde_json::Value::Bool(b) => Ok(b),
        _ => Err(field(at, "Use true or false.")),
    }
}

/// A cors policy's list of header names at `at`, lowercased: at most [`MAX_CORS_HEADERS`], each an
/// RFC 9110 token of 1 to 256 characters.
fn header_names(at: &str, value: serde_json::Value) -> Result<Vec<String>, FieldError> {
    let names = texts(at, value, r#"["x-request-id"]"#)?;
    if names.len() > MAX_CORS_HEADERS {
        return Err(field(
            at,
            format!("List at most {MAX_CORS_HEADERS} header names."),
        ));
    }
    names
        .into_iter()
        .map(|name| {
            if name.bytes().all(is_token) && (1..=MAX_NAME_CHARS).contains(&name.len()) {
                Ok(name.to_ascii_lowercase())
            } else {
                Err(field(
                    at,
                    format!(
                        "Use header names of 1 to {MAX_NAME_CHARS} letters, digits and \
                         !#$%&'*+-.^_`|~."
                    ),
                ))
            }
        })
        .collect()
}

/// `value` read as `T` when it is a JSON object, or `sentence` at `at`. Only an object: serde
/// reads a struct from an array too, by position, so `["x-debug"]` would otherwise be taken for a
/// `remove` the sender never wrote.
fn object<T: serde::de::DeserializeOwned>(
    at: &str,
    value: serde_json::Value,
    sentence: &str,
) -> Result<T, FieldError> {
    if !value.is_object() {
        return Err(field(at, sentence));
    }
    serde_json::from_value(value).map_err(|_| field(at, sentence))
}

/// A transformer's edits, counted over every list of each of its `sections`. One with none edits
/// nothing, a policy that looks like it changes a route and changes nothing; past [`MAX_EDITS`]
/// it costs every request more than any route's transform should. A section over the bound on
/// its own is named; one where only the sections together are over names `config`, since
/// shortening either would do and naming one would send the console to the wrong list.
fn counted(sections: &[(&str, &HeaderEdits)]) -> Result<(), FieldError> {
    let total: usize = sections.iter().map(|(_, edits)| edits.len()).sum();
    if total == 0 {
        return Err(field("headers", "List at least one edit."));
    }
    if let Some((section, _)) = sections.iter().find(|(_, edits)| edits.len() > MAX_EDITS) {
        return Err(field(
            section,
            format!("List at most {MAX_EDITS} edits in one policy."),
        ));
    }
    if total > MAX_EDITS {
        return Err(field(
            "config",
            format!("List at most {MAX_EDITS} edits in one policy, headers and query together."),
        ));
    }
    Ok(())
}

/// The five lists of one [`HeaderEdits`], each read as any JSON value and judged by [`edits`].
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EditsInput {
    #[serde(default)]
    remove: serde_json::Value,
    #[serde(default)]
    rename: serde_json::Value,
    #[serde(default)]
    replace: serde_json::Value,
    #[serde(default)]
    add: serde_json::Value,
    #[serde(default)]
    append: serde_json::Value,
}

/// `config` as the edits of `section`, `headers` or `query`, or the dotted field that is wrong
/// with them: `headers.add`, `query.remove`. Absent, the section edits nothing.
///
/// A header name is an RFC 9110 token of 1 to 256 characters, stored lowercase so that what the
/// list shows is what the header map matches; none of `refused` may be named. A header value is
/// visible ASCII, spaces and tabs, so no edit can end a header line and begin another. A query
/// name is any text of 1 to 256 characters and a value any text, matched exactly once decoded and
/// encoded on the way out, so neither can break the query apart.
fn edits(
    section: &str,
    config: &serde_json::Value,
    header: bool,
    refused: &[&str],
) -> Result<HeaderEdits, FieldError> {
    if config.is_null() {
        return Ok(HeaderEdits::default());
    }
    let input: EditsInput = object(
        section,
        config.clone(),
        "Send any of remove, rename, replace, add and append.",
    )?;
    let at = |op: &str| format!("{section}.{op}");
    // What a list in the wrong shape is shown, in the words of the section it is in.
    let (removed, renamed, set) = if header {
        (
            r#"["x-debug"]"#,
            r#"[["x-old", "x-new"]]"#,
            r#"[["x-team", "core"]]"#,
        )
    } else {
        (
            r#"["debug"]"#,
            r#"[["old", "new"]]"#,
            r#"[["version", "2"]]"#,
        )
    };
    let names = |op: &str, list: serde_json::Value| -> Result<Vec<String>, FieldError> {
        if list.is_null() {
            return Ok(Vec::new());
        }
        serde_json::from_value(list)
            .map_err(|_| field(&at(op), format!("List names, such as {removed}.")))
    };
    let pairs = |op: &str, list: serde_json::Value| -> Result<Vec<(String, String)>, FieldError> {
        if list.is_null() {
            return Ok(Vec::new());
        }
        let shape = if op == "rename" {
            format!("List pairs of the old name and the new, such as {renamed}.")
        } else {
            format!("List pairs of a name and its value, such as {set}.")
        };
        serde_json::from_value(list).map_err(|_| field(&at(op), shape))
    };
    let name = |op: &str, name: String| -> Result<String, FieldError> {
        let name = if header {
            if !(1..=MAX_NAME_CHARS).contains(&name.chars().count()) {
                return Err(field(
                    &at(op),
                    format!("Use header names of 1 to {MAX_NAME_CHARS} characters."),
                ));
            }
            if !name.bytes().all(is_token) {
                return Err(field(
                    &at(op),
                    "Use header names made of letters, digits and !#$%&'*+-.^_`|~.",
                ));
            }
            name.to_ascii_lowercase()
        } else {
            if !(1..=MAX_NAME_CHARS).contains(&name.chars().count()) {
                return Err(field(
                    &at(op),
                    format!("Use parameter names of 1 to {MAX_NAME_CHARS} characters."),
                ));
            }
            name
        };
        match refused.iter().find(|r| **r == name) {
            Some(r) => Err(field(&at(op), refusal(r))),
            None => Ok(name),
        }
    };
    let value = |op: &str, value: String| -> Result<String, FieldError> {
        if value.chars().count() > MAX_VALUE_CHARS {
            return Err(field(
                &at(op),
                format!("Use values of at most {MAX_VALUE_CHARS} characters."),
            ));
        }
        if header
            && !value
                .bytes()
                .all(|b| b == b'\t' || (b' '..=b'~').contains(&b))
        {
            return Err(field(
                &at(op),
                "Use header values of visible ASCII, spaces and tabs: no line breaks, other \
                 control characters or characters past ASCII.",
            ));
        }
        Ok(value)
    };
    let written =
        |op: &str, list: serde_json::Value| -> Result<Vec<(String, String)>, FieldError> {
            pairs(op, list)?
                .into_iter()
                .map(|(n, v)| Ok((name(op, n)?, value(op, v)?)))
                .collect()
        };
    Ok(HeaderEdits {
        remove: names("remove", input.remove)?
            .into_iter()
            .map(|n| name("remove", n))
            .collect::<Result<_, _>>()?,
        rename: pairs("rename", input.rename)?
            .into_iter()
            .map(|(from, to)| Ok((name("rename", from)?, name("rename", to)?)))
            .collect::<Result<_, _>>()?,
        replace: written("replace", input.replace)?,
        add: written("add", input.add)?,
        append: written("append", input.append)?,
    })
}

/// Whether `b` may be in a header name: an RFC 9110 `tchar`.
fn is_token(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Why a transform cannot touch the refused header `name`.
fn refusal(name: &str) -> String {
    match name {
        CONSUMER_HEADER => format!(
            "{CONSUMER_HEADER} is set by the gateway from the consumer a key names, so a \
             transform cannot write it."
        ),
        GROUPS_HEADER => format!(
            "{GROUPS_HEADER} is set by the gateway from the groups of the consumer a credential \
             names, so a transform cannot write it."
        ),
        ANONYMOUS_HEADER => format!(
            "{ANONYMOUS_HEADER} is set by the gateway when a caller without a credential is an \
             auth policy's anonymous consumer, so a transform cannot write it."
        ),
        _ => format!(
            "{name} says how HTTP frames, routes or carries a message, which the gateway keeps \
             for itself, so a transform cannot write it."
        ),
    }
}

/// What a stored row holds of `plugin`: the policy without its `kind` tag, which the row's name
/// already says. Also what the list shows, so a reader sees the form the data plane reads: a
/// bare address as the network of one it is.
pub fn config(plugin: &Plugin) -> serde_json::Value {
    let mut value = serde_json::to_value(plugin).expect("a policy serialises");
    value
        .as_object_mut()
        .expect("a policy is an object")
        .remove("kind");
    value
}

/// What the audit log records of `plugin`, and what the list shows a caller who may only read the
/// workspace: [`config`], except that a transformer keeps the names it edits and none of the
/// values it writes.
///
/// A transformer may carry a credential for the upstream -- an `authorization` it adds, an API
/// key in the query -- and the audit log is kept long after the policy has changed, and read by
/// everyone with a role in the workspace, those who join later included, while the names alone
/// still say what each change did. (The JWT audit also leaves its keys out, recording how many
/// there are, but not for secrecy: a JWKS holds public keys only, as
/// [`jwt::holds_a_secret`](gapura_core::jwt::holds_a_secret) refuses any other.) The list shows a
/// reader this form too, for the same reason; a caller who may change the workspace reads the
/// whole [`config`] there, because the console edits a policy from it. `remove` stays as it is,
/// `rename` as its `[from, to]` pairs, and `replace`, `add` and `append` as the names they write.
pub fn audited(plugin: &Plugin) -> serde_json::Value {
    fn names(edits: &HeaderEdits) -> serde_json::Value {
        let mut out = serde_json::Map::new();
        if !edits.remove.is_empty() {
            out.insert("remove".into(), serde_json::json!(edits.remove));
        }
        if !edits.rename.is_empty() {
            out.insert("rename".into(), serde_json::json!(edits.rename));
        }
        for (op, list) in [
            ("replace", &edits.replace),
            ("add", &edits.add),
            ("append", &edits.append),
        ] {
            if !list.is_empty() {
                let written: Vec<&str> = list.iter().map(|(name, _)| name.as_str()).collect();
                out.insert(op.into(), serde_json::json!(written));
            }
        }
        serde_json::Value::Object(out)
    }
    // Sections with no edits are left out, as the stored form leaves them out.
    let sections = |list: &[(&str, &HeaderEdits)]| {
        let out: serde_json::Map<String, serde_json::Value> = list
            .iter()
            .filter(|(_, edits)| !edits.is_empty())
            .map(|(section, edits)| (section.to_string(), names(edits)))
            .collect();
        serde_json::Value::Object(out)
    };
    match plugin {
        Plugin::RequestTransformer(p) => sections(&[("headers", &p.headers), ("query", &p.query)]),
        Plugin::ResponseTransformer(p) => sections(&[("headers", &p.headers)]),
        other => config(other),
    }
}

/// A policy of one kind as the list shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct KindPolicyView {
    pub target: String,
    pub config: serde_json::Value,
    /// The policy row's stamp, which a `PUT` replacing it sends back as `seen_updated_at`.
    pub updated_at: String,
}

/// Where a route or a service gets a policy of one kind from, as its list row shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PolicyFromView {
    /// `"route"`, `"service"` or `"workspace"`.
    pub from: &'static str,
    /// The policy row's own stamp.
    pub updated_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn an_ip_restriction_is_stored_in_the_form_the_data_plane_reads() {
        let plugin = parse(
            "ip_restriction",
            json!({"allow": ["203.0.113.7", "10.0.0.0/8"]}),
        )
        .unwrap();
        assert_eq!(
            config(&plugin),
            json!({"allow": ["203.0.113.7/32", "10.0.0.0/8"]})
        );
        assert_eq!(parse("ip_restriction", config(&plugin)).unwrap(), plugin);
    }

    /// The store writes a row under `plugin.kind()` and reads it back under the path's kind, so
    /// the two must be one name for every kind this endpoint keeps.
    #[test]
    fn each_kind_parses_to_a_plugin_of_that_kind() {
        let minimal = |kind: &str| match kind {
            "ip_restriction" => json!({"deny": ["10.0.0.0/8"]}),
            "request_size_limit" => json!({"max_bytes": 1024}),
            "request_transformer" => json!({"query": {"remove": ["debug"]}}),
            "response_transformer" => json!({"headers": {"add": [["x-served-by", "gapura"]]}}),
            "cors" => json!({"origins": ["https://app.example"]}),
            "auth" => json!({"anonymous": "guest"}),
            "acl" => json!({"allow": ["staff"]}),
            other => panic!("no minimal configuration for {other}: add one here"),
        };
        for kind in KINDS {
            let plugin = parse(kind, minimal(kind)).unwrap();
            assert_eq!(plugin.kind(), *kind);
            assert_eq!(parse(kind, config(&plugin)).unwrap(), plugin);
        }
    }

    #[test]
    fn a_bad_ip_restriction_names_its_field() {
        let refused = |config: serde_json::Value| parse("ip_restriction", config).unwrap_err();
        assert_eq!(refused(json!({})).field, "allow");
        assert_eq!(refused(json!({"allow": [], "deny": []})).field, "allow");
        assert_eq!(refused(json!({"allow": ["10.0.0.0/33"]})).field, "allow");
        assert_eq!(refused(json!({"deny": ["nope"]})).field, "deny");
        assert_eq!(refused(json!({"deny": "10.0.0.0/8"})).field, "config");
        assert_eq!(
            refused(json!({"allow": ["10.0.0.0/8"], "mode": "x"})).field,
            "config"
        );
        let many: Vec<String> = (0..=MAX_NETWORKS)
            .map(|i| format!("10.0.{}.{}", i / 256, i % 256))
            .collect();
        assert_eq!(refused(json!({"deny": many})).field, "allow");
        assert_eq!(parse("oauth2", json!({})).unwrap_err().field, "kind");
    }

    #[test]
    fn a_request_size_limit_is_stored_as_its_byte_count() {
        let plugin = parse("request_size_limit", json!({"max_bytes": 1024})).unwrap();
        assert_eq!(
            plugin,
            Plugin::RequestSizeLimit(RequestSizeLimitPolicy { max_bytes: 1024 })
        );
        assert_eq!(config(&plugin), json!({"max_bytes": 1024}));
        let largest = json!({ "max_bytes": MAX_BODY_BYTES });
        assert!(parse("request_size_limit", largest).is_ok());
    }

    /// A missing or misspelt field names the configuration; a count out of range or not a whole
    /// number names `max_bytes`.
    #[test]
    fn a_bad_request_size_limit_names_its_field() {
        let refused = |config: serde_json::Value| parse("request_size_limit", config).unwrap_err();
        assert_eq!(refused(json!({})).field, "config");
        assert_eq!(
            refused(json!({"max_bytes": 1, "unit": "kb"})).field,
            "config"
        );
        assert_eq!(refused(json!({"max_bytes": 0})).field, "max_bytes");
        assert_eq!(
            refused(json!({ "max_bytes": MAX_BODY_BYTES + 1 })).field,
            "max_bytes"
        );
        assert_eq!(refused(json!({"max_bytes": -1})).field, "max_bytes");
        assert_eq!(refused(json!({"max_bytes": 1.5})).field, "max_bytes");
        assert_eq!(refused(json!({"max_bytes": "1k"})).field, "max_bytes");
        assert_eq!(refused(json!({"max_bytes": null})).field, "max_bytes");
    }

    fn refused(kind: &str, config: serde_json::Value) -> FieldError {
        parse(kind, config.clone()).expect_err(&config.to_string())
    }

    /// Both kinds are stored in the form they were sent in, a header name lowercased so that the
    /// list shows what the header map matches; a query name keeps its case, as it is matched
    /// exactly.
    #[test]
    fn a_transformer_is_stored_with_its_header_names_lowercased() {
        let sent = json!({
            "headers": {
                "remove": ["X-Debug"],
                "rename": [["X-Old", "X-New"]],
                "replace": [["X-Env", "prod"]],
                "add": [["X-Team", "Core Team\t1"]],
                "append": [["X-Tag", "gw"]],
            },
            "query": {"remove": ["Secret"], "add": [["V", "a b&c"]]},
        });
        let plugin = parse("request_transformer", sent).unwrap();
        let stored = json!({
            "headers": {
                "remove": ["x-debug"],
                "rename": [["x-old", "x-new"]],
                "replace": [["x-env", "prod"]],
                "add": [["x-team", "Core Team\t1"]],
                "append": [["x-tag", "gw"]],
            },
            "query": {"remove": ["Secret"], "add": [["V", "a b&c"]]},
        });
        assert_eq!(config(&plugin), stored);
        assert_eq!(parse("request_transformer", stored).unwrap(), plugin);

        let plugin = parse(
            "response_transformer",
            json!({"headers": {"remove": ["X-Request-Id"]}}),
        )
        .unwrap();
        assert_eq!(
            config(&plugin),
            json!({"headers": {"remove": ["x-request-id"]}})
        );
    }

    /// A list in the wrong shape, a name or a value that is not one, is named by its dotted field;
    /// a configuration that is not one, or that names a list the kind has not, names `config`.
    #[test]
    fn a_bad_transformer_names_its_dotted_field() {
        let long = "v".repeat(MAX_VALUE_CHARS + 1);
        let long_name = "n".repeat(257);
        for (config, at) in [
            (json!({"headers": {"remove": "x-a"}}), "headers.remove"),
            (json!({"headers": {"remove": [1]}}), "headers.remove"),
            (json!({"headers": {"remove": ["x a"]}}), "headers.remove"),
            (json!({"headers": {"remove": [""]}}), "headers.remove"),
            (
                json!({"headers": {"remove": [long_name]}}),
                "headers.remove",
            ),
            (
                json!({"headers": {"rename": [[long_name, "x-a"]]}}),
                "headers.rename",
            ),
            (
                json!({"headers": {"add": [[long_name, "v"]]}}),
                "headers.add",
            ),
            (json!({"headers": {"rename": [["x-a"]]}}), "headers.rename"),
            (
                json!({"headers": {"rename": [["x-a", "x:b"]]}}),
                "headers.rename",
            ),
            (
                json!({"headers": {"replace": [["x-a", "b", "c"]]}}),
                "headers.replace",
            ),
            (
                json!({"headers": {"replace": [["é", "b"]]}}),
                "headers.replace",
            ),
            (
                json!({"headers": {"add": [["x-a", "one\r\nx-b: 1"]]}}),
                "headers.add",
            ),
            (
                json!({"headers": {"add": [["x-a", "caf\u{e9}"]]}}),
                "headers.add",
            ),
            (
                json!({"headers": {"add": [["x-a", "\u{7f}"]]}}),
                "headers.add",
            ),
            (
                json!({"headers": {"append": [["x-a", long]]}}),
                "headers.append",
            ),
            (json!({"headers": {"append": ["x-a"]}}), "headers.append"),
            (json!({"headers": {"prepend": [["x-a", "b"]]}}), "headers"),
            (json!({"headers": ["x-a"]}), "headers"),
            (json!({"query": {"remove": [""]}}), "query.remove"),
            (
                json!({"query": {"rename": [["a", long_name]]}}),
                "query.rename",
            ),
            (json!({"query": {"add": [["a", long]]}}), "query.add"),
            (json!({"query": {"append": "a"}}), "query.append"),
            (json!({"query": {"set": [["a", "b"]]}}), "query"),
            (json!({"body": {"remove": ["a"]}}), "config"),
            (json!(["x-a"]), "config"),
        ] {
            assert_eq!(
                refused("request_transformer", config.clone()).field,
                at,
                "{config}"
            );
        }
        // A response has no query string.
        assert_eq!(
            refused("response_transformer", json!({"query": {"remove": ["a"]}})).field,
            "config"
        );
        // The longest of each is taken.
        let longest = json!({
            "headers": {
                "add": [["x-a", "v".repeat(MAX_VALUE_CHARS)]],
                "remove": ["h".repeat(MAX_NAME_CHARS)],
            },
            "query": {"add": [["n".repeat(MAX_NAME_CHARS), "é".repeat(MAX_VALUE_CHARS)]]},
        });
        assert!(parse("request_transformer", longest).is_ok());
        // A header name too long says so, rather than calling its characters wrong.
        let e = refused(
            "response_transformer",
            json!({"headers": {"remove": [long_name]}}),
        );
        assert_eq!(e.sentence, "Use header names of 1 to 256 characters.");
    }

    /// The names that frame and route a message are refused in every list of both kinds, in any
    /// case; the headers the gateway sets about the caller only in a request transform's headers,
    /// since the response's are the upstream's to send and a query parameter of one of those names
    /// is no header.
    #[test]
    fn the_framing_headers_and_the_consumer_headers_are_refused() {
        for name in FRAMING.iter().copied().chain(["Content-Length", "HOST"]) {
            for (op, list) in [
                ("remove", json!([name])),
                ("rename", json!([[name, "x-a"]])),
                ("rename", json!([["x-a", name]])),
                ("replace", json!([[name, "1"]])),
                ("add", json!([[name, "1"]])),
                ("append", json!([[name, "1"]])),
            ] {
                for kind in ["request_transformer", "response_transformer"] {
                    let e = refused(kind, json!({"headers": {op: list}}));
                    assert_eq!(e.field, format!("headers.{op}"), "{kind} {name}");
                    assert!(e.sentence.contains("cannot write it"), "{}", e.sentence);
                }
            }
        }

        let consumer = json!({"headers": {"add": [[CONSUMER_HEADER, "alice"]]}});
        let e = refused("request_transformer", consumer.clone());
        assert_eq!(e.field, "headers.add");
        assert_eq!(
            e.sentence,
            "x-consumer-username is set by the gateway from the consumer a key names, so a \
             transform cannot write it."
        );
        // Every list refuses each header the gateway sets about the caller, in any case, a removal
        // and a rename away from it too: the gateway sets them just before the transform runs, so
        // either would take the consumer, its groups or its being anonymous from the upstream.
        for name in GATEWAY_HEADERS {
            let shouted = name.to_ascii_uppercase();
            for (op, list) in [
                ("remove", json!([shouted])),
                ("rename", json!([["x-user", shouted]])),
                ("rename", json!([[name, "x-user"]])),
                ("replace", json!([[name, "alice"]])),
                ("add", json!([[shouted, "alice"]])),
                ("append", json!([[name, "alice"]])),
            ] {
                let e = refused("request_transformer", json!({"headers": {op: list}}));
                assert_eq!(e.field, format!("headers.{op}"), "{list}");
                assert!(e.sentence.starts_with(name), "{}", e.sentence);
                assert!(e.sentence.ends_with("cannot write it."), "{}", e.sentence);
            }
            // A response's are the upstream's to send, and a query parameter of the name is no
            // header.
            let response = json!({"headers": {"add": [[name, "alice"]]}});
            assert!(parse("response_transformer", response).is_ok(), "{name}");
            let parameter = json!({"query": {"add": [[name, "alice"], ["host", "h"]]}});
            assert!(parse("request_transformer", parameter).is_ok(), "{name}");
        }
        assert!(parse("response_transformer", consumer).is_ok());
    }

    /// A transformer with nothing to do is refused, and so is one past [`MAX_EDITS`], headers and
    /// query counted together. A section over on its own is named; a policy over only once both
    /// are counted names `config`.
    #[test]
    fn a_transformer_lists_one_edit_and_at_most_max_edits() {
        for kind in ["request_transformer", "response_transformer"] {
            for empty in [
                json!({}),
                json!({"headers": {}}),
                json!({"headers": {"remove": [], "add": []}}),
            ] {
                let e = refused(kind, empty);
                assert_eq!(
                    (e.field.as_str(), e.sentence.as_str()),
                    ("headers", "List at least one edit.")
                );
            }
        }
        assert_eq!(
            refused("request_transformer", json!({"query": {}})).sentence,
            "List at least one edit."
        );

        let headers = |n: usize| (0..n).map(|i| format!("x-{i}")).collect::<Vec<_>>();
        let half = MAX_EDITS / 2;
        let full = json!({
            "headers": {"remove": headers(half)},
            "query": {"remove": headers(MAX_EDITS - half)},
        });
        assert!(parse("request_transformer", full).is_ok());
        let over = json!({
            "headers": {"remove": headers(half)},
            "query": {"remove": headers(MAX_EDITS - half + 1)},
        });
        let e = refused("request_transformer", over);
        assert_eq!(
            (e.field.as_str(), e.sentence.as_str()),
            (
                "config",
                "List at most 64 edits in one policy, headers and query together."
            )
        );
        for (section, kind) in [
            ("headers", "request_transformer"),
            ("query", "request_transformer"),
            ("headers", "response_transformer"),
        ] {
            let over = json!({ section: {"remove": headers(MAX_EDITS + 1)} });
            let e = refused(kind, over);
            assert_eq!(
                (e.field.as_str(), e.sentence.as_str()),
                (section, "List at most 64 edits in one policy."),
                "{kind}"
            );
        }
        // Over in one section, the other's edits besides: still the section's fault.
        let over = json!({
            "headers": {"remove": ["x-a"]},
            "query": {"remove": headers(MAX_EDITS + 1)},
        });
        assert_eq!(refused("request_transformer", over).field, "query");
    }

    /// The audit form keeps every name a transformer edits and none of the values it writes, so a
    /// credential added for the upstream never reaches the audit log; other kinds are audited as
    /// they are stored.
    #[test]
    fn a_transformer_is_audited_by_its_names_without_values() {
        let plugin = parse(
            "request_transformer",
            json!({
                "headers": {
                    "remove": ["x-debug"],
                    "rename": [["x-old", "x-new"]],
                    "replace": [["x-env", "replaced-secret"]],
                    "add": [["Authorization", "Bearer s3cret"]],
                    "append": [["x-tag", "appended-secret"]],
                },
                "query": {"add": [["api_key", "query-secret"]]},
            }),
        )
        .unwrap();
        let audit = audited(&plugin);
        assert_eq!(
            audit,
            json!({
                "headers": {
                    "remove": ["x-debug"],
                    "rename": [["x-old", "x-new"]],
                    "replace": ["x-env"],
                    "add": ["authorization"],
                    "append": ["x-tag"],
                },
                "query": {"add": ["api_key"]},
            })
        );
        let text = audit.to_string();
        for value in [
            "s3cret",
            "replaced-secret",
            "appended-secret",
            "query-secret",
        ] {
            assert!(!text.contains(value), "{value} is in {text}");
        }

        let plugin = parse(
            "response_transformer",
            json!({"headers": {"add": [["set-cookie", "session=s3cret"]]}}),
        )
        .unwrap();
        assert_eq!(
            audited(&plugin),
            json!({"headers": {"add": ["set-cookie"]}})
        );

        let plugin = parse("ip_restriction", json!({"deny": ["10.0.0.0/8"]})).unwrap();
        assert_eq!(audited(&plugin), config(&plugin));
        let plugin = parse("request_size_limit", json!({"max_bytes": 1024})).unwrap();
        assert_eq!(audited(&plugin), config(&plugin));
        let plugin = parse("cors", json!({"origins": ["https://app.example"]})).unwrap();
        assert_eq!(audited(&plugin), config(&plugin));
        let plugin = parse("auth", json!({"anonymous": "guest"})).unwrap();
        assert_eq!(audited(&plugin), json!({"anonymous": "guest"}));
        let plugin = parse("acl", json!({"allow": ["staff"], "deny": ["suspended"]})).unwrap();
        assert_eq!(audited(&plugin), config(&plugin));
    }

    #[test]
    fn an_acl_lists_groups_and_at_least_one() {
        assert_eq!(
            parse("acl", json!({"allow": ["staff"], "deny": ["suspended"]})),
            Ok(Plugin::Acl(AclPolicy {
                allow: vec!["staff".into()],
                deny: vec!["suspended".into()]
            }))
        );
        assert_eq!(
            config(&parse("acl", json!({"deny": ["suspended"]})).unwrap()),
            json!({"deny": ["suspended"]}),
            "an empty list is left out, as the data plane reads it"
        );
        assert_eq!(refused("acl", json!({})).field, "allow");
        assert_eq!(
            refused("acl", json!({"allow": [], "deny": []})).field,
            "allow"
        );
        assert_eq!(refused("acl", json!({"deny": ["two words"]})).field, "deny");
        assert_eq!(refused("acl", json!({"allow": ["a,b"]})).field, "allow");
        assert_eq!(
            refused("acl", json!({"allow": ["staff"], "mode": "x"})).field,
            "config"
        );
        assert_eq!(refused("acl", json!({"allow": "staff"})).field, "config");
        let many: Vec<String> = (0..=MAX_ACL_GROUPS).map(|i| format!("g{i}")).collect();
        assert_eq!(refused("acl", json!({ "deny": many })).field, "deny");
        let most: Vec<String> = (0..MAX_ACL_GROUPS).map(|i| format!("g{i}")).collect();
        assert!(parse("acl", json!({ "allow": most, "deny": most })).is_ok());
    }

    #[test]
    fn an_auth_policy_names_an_anonymous_consumer_or_nobody() {
        assert_eq!(
            parse("auth", json!({})),
            Ok(Plugin::Auth(AuthPolicy::default()))
        );
        assert_eq!(
            parse("auth", json!({"anonymous": "guest"})),
            Ok(Plugin::Auth(AuthPolicy {
                anonymous: Some("guest".into()),
                workspace: None
            }))
        );
        assert_eq!(
            parse("auth", json!({"anonymous": "  "})),
            Ok(Plugin::Auth(AuthPolicy::default())),
            "an empty name is nobody"
        );
        assert_eq!(
            refused("auth", json!({"anonymous": "no such name!"})).field,
            "anonymous"
        );
        // The store stamps the workspace; a request that sends one is refused.
        assert_eq!(refused("auth", json!({"workspace": "x"})).field, "config");
        assert_eq!(refused("auth", json!({"anonymous": 7})).field, "config");
    }

    /// Stored as the data plane matches it: origins lowercased with the scheme's own port left
    /// off, as a browser writes `Origin`; the default methods filled in; header names lowercased.
    #[test]
    fn a_cors_policy_is_stored_with_its_defaults_filled_in() {
        let plugin = parse(
            "cors",
            json!({
                "origins": ["HTTPS://App.Example:443", "https://*.Example.org:8443", "http://localhost:80"],
                "headers": ["X-Requested-With"],
                "expose_headers": ["X-Gapura-Error"],
                "max_age": 0,
            }),
        )
        .unwrap();
        let stored = json!({
            "origins": ["https://app.example", "https://*.example.org:8443", "http://localhost"],
            "methods": ["GET", "HEAD", "PUT", "PATCH", "POST", "DELETE"],
            "headers": ["x-requested-with"],
            "expose_headers": ["x-gapura-error"],
            "max_age": 0,
        });
        assert_eq!(config(&plugin), stored);
        assert_eq!(parse("cors", stored).unwrap(), plugin);

        let plugin = parse(
            "cors",
            json!({"origins": ["*"], "methods": ["get", "OPTIONS"], "preflight_continue": true}),
        )
        .unwrap();
        assert_eq!(
            config(&plugin),
            json!({"origins": ["*"], "methods": ["GET", "OPTIONS"], "preflight_continue": true})
        );
        let largest = json!({"origins": ["https://a.example"], "max_age": MAX_AGE_SECS});
        assert!(parse("cors", largest).is_ok());
    }

    /// `*` never goes with credentials: a browser refuses it, and an echo of every origin would
    /// let any page read a signed-in user's answers.
    #[test]
    fn a_star_origin_is_refused_with_credentials_and_beside_others() {
        let e = refused("cors", json!({"origins": ["*"], "credentials": true}));
        assert_eq!(
            (e.field.as_str(), e.sentence.as_str()),
            (
                "origins",
                "An origin of * cannot be sent with credentials: list the origins instead."
            )
        );
        let e = refused("cors", json!({"origins": ["*", "https://a.example"]}));
        assert_eq!(e.field, "origins");
        assert!(
            parse(
                "cors",
                json!({"origins": ["https://*.example.com"], "credentials": true})
            )
            .is_ok(),
            "a wildcard entry echoes only the origins under it"
        );
    }

    #[test]
    fn a_bad_cors_policy_names_its_field() {
        let many: Vec<String> = (0..=MAX_ORIGINS)
            .map(|i| format!("https://a{i}.example"))
            .collect();
        let headers: Vec<String> = (0..=MAX_CORS_HEADERS).map(|i| format!("x-{i}")).collect();
        let one = |origin: &str| json!({ "origins": [origin] });
        for (config, at) in [
            (json!({}), "origins"),
            (json!({"origins": []}), "origins"),
            (json!({"origins": "https://a.example"}), "origins"),
            (json!({ "origins": many }), "origins"),
            (one("null"), "origins"),
            (one("NULL"), "origins"),
            (one("app.example"), "origins"),
            (one("ftp://app.example"), "origins"),
            (one("https://app.example/"), "origins"),
            (one("https://app.example/path"), "origins"),
            (one("https://app.example?q"), "origins"),
            (one("https://app.example#f"), "origins"),
            (one("https://u@app.example"), "origins"),
            (one("https://app.example."), "origins"),
            (one("https://app..example"), "origins"),
            (one("https://bücher.example"), "origins"),
            (one("https://app.example:0"), "origins"),
            (one("https://app.example:65536"), "origins"),
            (one("https://app.example:+80"), "origins"),
            (one("https://app.example:"), "origins"),
            (one("https://*.com"), "origins"),
            (one("https://*"), "origins"),
            (one("https://a.*.example"), "origins"),
            (one("https://*.*.example"), "origins"),
            (one("https://[::1]:3000"), "origins"),
            (
                json!({"origins": ["https://a.example"], "methods": ["FETCH"]}),
                "methods",
            ),
            (
                json!({"origins": ["https://a.example"], "methods": "GET"}),
                "methods",
            ),
            (
                json!({"origins": ["https://a.example"], "headers": ["x a"]}),
                "headers",
            ),
            (
                json!({"origins": ["https://a.example"], "headers": [""]}),
                "headers",
            ),
            (
                json!({"origins": ["https://a.example"], "expose_headers": headers}),
                "expose_headers",
            ),
            (
                json!({"origins": ["https://a.example"], "max_age": MAX_AGE_SECS + 1}),
                "max_age",
            ),
            (
                json!({"origins": ["https://a.example"], "max_age": -1}),
                "max_age",
            ),
            (
                json!({"origins": ["https://a.example"], "max_age": "600"}),
                "max_age",
            ),
            (
                json!({"origins": ["https://a.example"], "credentials": "yes"}),
                "credentials",
            ),
            (
                json!({"origins": ["https://a.example"], "preflight_continue": 1}),
                "preflight_continue",
            ),
            (
                json!({"origins": ["https://a.example"], "allow_origins": ["*"]}),
                "config",
            ),
            (json!(["https://a.example"]), "config"),
        ] {
            assert_eq!(refused("cors", config.clone()).field, at, "{config}");
        }
        let e = refused("cors", json!({"origins": ["https://*.com"]}));
        assert!(
            e.sentence.contains("*. before a name with a dot"),
            "{}",
            e.sentence
        );
    }
}
