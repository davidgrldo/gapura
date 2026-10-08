//! Services and routes in the store: what a request may contain, and who may make it.
//!
//! Pure, so every rule is tested without a database. The handlers ask `allowed` first, over the
//! rows they read anyway, to refuse cheaply; the store asks it again inside the transaction that
//! writes, over rows it has locked, and that answer is the one that counts. The validation here
//! is the compiler's and the data plane's own rules, so nothing accepted can fail the snapshot
//! later.

use crate::access::{Role, Rows, User};
use crate::grants::Refusal;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const MAX_NAME_CHARS: usize = 63;
pub const MAX_HOSTS: usize = 32;
pub const MAX_PATHS: usize = 32;
/// The most host, path and method combinations one route may expand to. An empty list counts as
/// one, since it means any.
pub const MAX_COMBINATIONS: usize = 1024;
pub const MAX_PATH_CHARS: usize = 1024;
pub const MAX_TIMEOUT_MS: i32 = 3_600_000;
/// The methods a route may name. `web/check.mjs` reads this list, so the console offers exactly
/// these.
pub const METHODS: [&str; 9] = [
    "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE",
];
/// The path match types, in the store's spelling. `web/check.mjs` reads this list too.
pub const PATH_TYPES: [&str; 3] = ["prefix", "exact", "regex"];

/// What a request wants to do to a workspace's services or routes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Read,
    Write,
    Delete,
}

impl Action {
    fn needs(self) -> Role {
        match self {
            Action::Read => Role::Viewer,
            Action::Write => Role::Editor,
            Action::Delete => Role::Admin,
        }
    }
}

/// The one answer for a workspace the caller holds no role in and for one that does not exist,
/// so a request cannot be used to learn which exist.
pub fn no_role() -> Refusal {
    Refusal::Forbidden("You hold no role in that workspace.".into())
}

/// The caller's role in `workspace`, when it is enough for `action`.
pub fn allowed(
    rows: &Rows,
    caller: &User,
    workspace: Uuid,
    action: Action,
) -> Result<Role, Refusal> {
    let Some(access) = rows.effective(caller, workspace) else {
        return Err(no_role());
    };
    if access.role >= action.needs() {
        return Ok(access.role);
    }
    let verb = match action {
        Action::Read => "Reading",
        Action::Write => "Changing",
        Action::Delete => "Deleting",
    };
    let needs = action.needs().as_str();
    Err(Refusal::Forbidden(format!(
        "{verb} services and routes needs the {needs} role in this workspace."
    )))
}

/// A refusal of one field, which the console shows beside it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldError {
    pub field: String,
    pub sentence: String,
}

fn field(field: impl Into<String>, sentence: impl Into<String>) -> FieldError {
    FieldError {
        field: field.into(),
        sentence: sentence.into(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Http,
    Https,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Http => "http",
            Protocol::Https => "https",
        }
    }
}

/// A service as a request sends it.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceInput {
    pub name: String,
    pub protocol: String,
    pub host: String,
    pub port: i64,
    #[serde(default)]
    pub connect_timeout_ms: Option<i64>,
    #[serde(default)]
    pub read_timeout_ms: Option<i64>,
    /// Required on `PUT`, the value last read; refused on `POST`.
    #[serde(default)]
    pub updated_at: Option<String>,
}

/// A service that passed validation, as the store writes it and the audit log records it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Service {
    pub name: String,
    pub protocol: Protocol,
    pub host: String,
    pub port: i32,
    pub connect_timeout_ms: Option<i32>,
    pub read_timeout_ms: Option<i32>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathInput {
    #[serde(rename = "type")]
    pub kind: String,
    pub value: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteInput {
    pub name: String,
    pub service: String,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub paths: Vec<PathInput>,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub updated_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathMatch {
    #[serde(rename = "type")]
    pub kind: String,
    pub value: String,
}

/// A route that passed validation. `paths` is stored as JSON in exactly this shape, which is the
/// shape the snapshot already reads.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Route {
    pub name: String,
    pub service: String,
    pub hosts: Vec<String>,
    pub paths: Vec<PathMatch>,
    pub methods: Vec<String>,
    pub priority: i32,
}

/// What the list endpoints answer with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ServiceView {
    #[serde(flatten)]
    pub service: Service,
    /// How many routes use it.
    pub routes: i64,
    pub updated_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RouteView {
    #[serde(flatten)]
    pub route: Route,
    pub updated_at: String,
}

/// Whether this is a create or a replace, which decides what `updated_at` must be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Write {
    Create,
    Replace,
}

/// What a replace without `updated_at` is told.
pub(crate) const UNSEEN: &str =
    "Send the updated_at you last read, so a change made meanwhile is not overwritten.";

fn updated_at(kind: Write, value: Option<String>) -> Result<Option<String>, FieldError> {
    match (kind, value) {
        (Write::Create, None) => Ok(None),
        (Write::Create, Some(_)) => {
            Err(field("updated_at", "A new row has no updated_at to send."))
        }
        (Write::Replace, Some(v)) => Ok(Some(v)),
        (Write::Replace, None) => Err(field("updated_at", UNSEEN)),
    }
}

/// Letters, digits and `. _ ~ -`, 1 to 63 of them, starting with a letter or a digit. A name is
/// a URL path segment, so `.` and `..` would be normalised away and the row could never be
/// addressed again.
pub fn name(value: &str, at: &str) -> Result<String, FieldError> {
    let ok = value
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric())
        && value.chars().count() <= MAX_NAME_CHARS
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '~' | '-'));
    if ok {
        Ok(value.to_string())
    } else {
        Err(field(
            at,
            format!(
                "Use 1 to {MAX_NAME_CHARS} letters, digits, dots, underscores, tildes or hyphens, \
                 starting with a letter or a digit."
            ),
        ))
    }
}

/// A DNS name: labels of letters, digits and hyphens, 1 to 63 long, not starting or ending with a
/// hyphen, 253 characters in all, whose last label starts with a letter. That last rule keeps
/// anything that resolvers read as an IPv4 address in some spelling (`1.2.3`, `2130706433`,
/// `0x7f.1`) from passing as a name.
fn dns_name(value: &str) -> bool {
    value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
        && value
            .rsplit('.')
            .next()
            .is_some_and(|last| last.starts_with(|c: char| c.is_ascii_alphabetic()))
}

/// A DNS name or an IPv4 address. The data plane joins `host:port` without brackets, so an IPv6
/// literal would be ambiguous and is refused.
fn upstream_host(value: &str) -> Result<String, FieldError> {
    let lowered = value.to_ascii_lowercase();
    if value.parse::<std::net::Ipv4Addr>().is_ok() || dns_name(&lowered) {
        Ok(lowered)
    } else {
        Err(field(
            "host",
            "Use a host name or an IPv4 address, without a scheme, port or path.",
        ))
    }
}

fn timeout(value: Option<i64>, at: &str) -> Result<Option<i32>, FieldError> {
    match value {
        None => Ok(None),
        Some(ms) if (1..=i64::from(MAX_TIMEOUT_MS)).contains(&ms) => Ok(Some(ms as i32)),
        Some(_) => Err(field(
            at,
            format!("Use a number of milliseconds from 1 to {MAX_TIMEOUT_MS}, or leave it empty."),
        )),
    }
}

/// A service request, checked, and the `updated_at` it carried.
pub fn service(input: ServiceInput, kind: Write) -> Result<(Service, Option<String>), FieldError> {
    let service_name = name(&input.name, "name")?;
    let protocol = match input.protocol.as_str() {
        "http" => Protocol::Http,
        "https" => Protocol::Https,
        _ => return Err(field("protocol", "Use http or https.")),
    };
    let port = if (1..=i64::from(u16::MAX)).contains(&input.port) {
        input.port as i32
    } else {
        return Err(field("port", format!("Use a port from 1 to {}.", u16::MAX)));
    };
    let host = upstream_host(&input.host)?;
    if protocol == Protocol::Https && host.parse::<std::net::IpAddr>().is_ok() {
        return Err(field(
            "host",
            "An https service needs a host name: its certificate is checked against names, not addresses.",
        ));
    }
    let service = Service {
        name: service_name,
        protocol,
        host,
        port,
        connect_timeout_ms: timeout(input.connect_timeout_ms, "connect_timeout_ms")?,
        read_timeout_ms: timeout(input.read_timeout_ms, "read_timeout_ms")?,
    };
    Ok((service, updated_at(kind, input.updated_at)?))
}

/// The regular expression's own reason, one line, at most 200 characters.
fn regex_reason(error: &impl std::fmt::Display) -> String {
    let text = error.to_string();
    let last = text
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("");
    let reason = last.strip_prefix("error: ").unwrap_or(last).trim();
    reason.chars().take(200).collect()
}

/// The most a console regex may compile to, in bytes. Generous, since Unicode classes such as
/// `\w` are large, and well under what `a{1000}{1000}` costs. It applies to what the console
/// writes only: the shared `compile_path_regex` stays as every reader of a snapshot has it.
const REGEX_SIZE_LIMIT: usize = 4 * 1024 * 1024;

/// A console regex: it must pass the data plane's own rules, and also fit `REGEX_SIZE_LIMIT`.
fn console_regex(value: &str) -> Result<(), String> {
    gapura_core::matcher::compile_path_regex(value).map_err(|e| regex_reason(&e))?;
    regex::RegexBuilder::new(&format!("^(?:{value})$"))
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map(drop)
        .map_err(|e| regex_reason(&e))
}

/// A route host that names every name under a single label, such as `*.com`, takes more than one
/// workspace's share of the data plane's ports. Only a superuser may route one; a wildcard needs
/// at least two labels after `*.`. The store asks this for each host of a route.
pub fn may_claim_wildcard(caller: &User, host: &str) -> Result<(), Refusal> {
    let Some(suffix) = host.strip_prefix("*.") else {
        return Ok(());
    };
    if caller.superuser || suffix.contains('.') {
        return Ok(());
    }
    Err(Refusal::Forbidden(format!(
        "{host} would claim every name under one label for this workspace; only a superuser may route it."
    )))
}

/// One prefix or exact path value: visible ASCII, no query string or fragment, starting with `/`.
/// A prefix loses its trailing slashes, as the data plane's own prefix rule does, because that
/// rule only matches at a `/` boundary.
fn plain_path(kind: &str, value: &str, at: String) -> Result<String, FieldError> {
    if !value.starts_with('/') {
        return Err(field(at, "A prefix or exact path starts with /."));
    }
    if !value.chars().all(|c| ('\u{21}'..='\u{7e}').contains(&c)) {
        return Err(field(
            at,
            "Percent-encode characters outside visible ASCII, as clients send them.",
        ));
    }
    if value.contains(['?', '#']) {
        return Err(field(at, "A path has no query string or fragment."));
    }
    // The data plane normalises a request's path before matching it (`normalize_path` in the
    // gateway's proxy): it collapses `//`, refuses `.` and `..` segments, and decodes an escaped
    // letter, digit or `- . _ ~`. A route path written any of those ways could never match.
    if value.contains("//") {
        return Err(field(
            at,
            "A path has no empty segments: the gateway collapses // in requests.",
        ));
    }
    if value
        .split('/')
        .any(|segment| segment == "." || segment == "..")
    {
        return Err(field(
            at,
            "A path has no . or .. segments: the gateway refuses requests that do.",
        ));
    }
    let bytes = value.as_bytes();
    for (i, _) in value.match_indices('%') {
        let escape = bytes
            .get(i + 1..i + 3)
            .and_then(|hex| u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok());
        match escape {
            None => {
                return Err(field(at, "A % starts an escape of two hexadecimal digits."));
            }
            Some(b) if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') => {
                return Err(field(
                    at,
                    "Write letters, digits and - . _ ~ as they are: the gateway decodes them before matching.",
                ));
            }
            Some(_) => {}
        }
    }
    let mut value = value.to_string();
    if kind == "prefix" {
        while value.len() > 1 && value.ends_with('/') {
            value.pop();
        }
    }
    Ok(value)
}

/// Whether two route hosts, normalised (lowercase, with an optional leading `*.`), can name the
/// same request host. A host is claimed by the first workspace that routes it; another
/// workspace's route may not name an overlapping host, because every workspace's routes share
/// the data plane's ports.
///
/// Overlap is the data plane's own matching, either way round: a wildcard `*.x` matches one or
/// more extra labels, never the bare `x`, and a wildcard overlaps a narrower wildcard that ends
/// in its suffix.
pub fn hosts_overlap(a: &str, b: &str) -> bool {
    a == b || gapura_core::hostname::matches(a, b) || gapura_core::hostname::matches(b, a)
}

/// A route with no hosts takes every host on the data plane's ports, so only a superuser may
/// write one. The store asks this when a route's hosts are empty.
pub fn may_route_any_host(caller: &User) -> Result<(), Refusal> {
    if caller.superuser {
        Ok(())
    } else {
        Err(Refusal::Forbidden(
            "Only a superuser may create a route for any host: it would take other workspaces' traffic. Name at least one host."
                .into(),
        ))
    }
}

/// A route request, checked, and the `updated_at` it carried. Hosts are lowercased and methods
/// uppercased; a value given twice is kept once.
pub fn route(input: RouteInput, kind: Write) -> Result<(Route, Option<String>), FieldError> {
    let route_name = name(&input.name, "name")?;
    let service_name = name(&input.service, "service")?;
    if input.hosts.len() > MAX_HOSTS {
        return Err(field(
            "hosts",
            format!("A route takes at most {MAX_HOSTS} hosts."),
        ));
    }
    let mut hosts: Vec<String> = Vec::new();
    for (i, host) in input.hosts.iter().enumerate() {
        let lowered = host.to_ascii_lowercase();
        let bare = lowered.strip_prefix("*.").unwrap_or(&lowered);
        if !dns_name(bare) {
            return Err(field(
                format!("hosts[{i}]"),
                "Use a host name, optionally starting with *. for its subdomains.",
            ));
        }
        if !hosts.contains(&lowered) {
            hosts.push(lowered);
        }
    }
    if input.paths.len() > MAX_PATHS {
        return Err(field(
            "paths",
            format!("A route takes at most {MAX_PATHS} paths."),
        ));
    }
    let mut paths: Vec<PathMatch> = Vec::new();
    for (i, path) in input.paths.into_iter().enumerate() {
        if !PATH_TYPES.contains(&path.kind.as_str()) {
            return Err(field(
                format!("paths[{i}].type"),
                "Use prefix, exact or regex.",
            ));
        }
        let at = format!("paths[{i}].value");
        if path.value.is_empty() || path.value.chars().count() > MAX_PATH_CHARS {
            return Err(field(
                at,
                format!("Use a path of 1 to {MAX_PATH_CHARS} characters."),
            ));
        }
        let value = if path.kind == "regex" {
            if let Err(reason) = console_regex(&path.value) {
                return Err(field(
                    at,
                    format!("This regular expression does not compile: {reason}"),
                ));
            }
            path.value
        } else {
            plain_path(&path.kind, &path.value, at)?
        };
        let entry = PathMatch {
            kind: path.kind,
            value,
        };
        if !paths.contains(&entry) {
            paths.push(entry);
        }
    }
    let mut methods: Vec<String> = Vec::new();
    for (i, method) in input.methods.iter().enumerate() {
        let upper = method.to_ascii_uppercase();
        if !METHODS.contains(&upper.as_str()) {
            return Err(field(
                format!("methods[{i}]"),
                "Use an HTTP method such as GET or POST.",
            ));
        }
        if !methods.contains(&upper) {
            methods.push(upper);
        }
    }
    let combinations = hosts.len().max(1) * paths.len().max(1) * methods.len().max(1);
    if combinations > MAX_COMBINATIONS {
        return Err(field(
            "paths",
            format!(
                "This route expands to more than {MAX_COMBINATIONS} host, path and method \
                 combinations; split it into several routes."
            ),
        ));
    }
    let route = Route {
        name: route_name,
        service: service_name,
        hosts,
        paths,
        methods,
        priority: input.priority,
    };
    Ok((route, updated_at(kind, input.updated_at)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::{Grant, Method, Workspace};

    /// A way to break a valid input, and the field the refusal must name.
    type Case<T> = (fn(&mut T), &'static str);

    fn person(id: u128, superuser: bool) -> User {
        User {
            id: Uuid::from_u128(id),
            name: format!("u{id}"),
            method: Method::Local,
            superuser,
            disabled: false,
            groups: vec![],
            last_sign_in: None,
        }
    }

    fn rows(role: Option<Role>) -> (Rows, User, Uuid) {
        let ws = Uuid::from_u128(100);
        let me = person(1, false);
        let rows = Rows {
            users: vec![me.clone()],
            workspaces: vec![Workspace {
                id: ws,
                name: "default".into(),
            }],
            grants: role
                .map(|role| Grant {
                    user: me.id,
                    workspace: ws,
                    role,
                })
                .into_iter()
                .collect(),
            group_grants: vec![],
        };
        (rows, me, ws)
    }

    #[test]
    fn each_role_may_do_its_own_and_less() {
        use Action::*;
        let table = [
            (Some(Role::Viewer), [true, false, false]),
            (Some(Role::Editor), [true, true, false]),
            (Some(Role::Admin), [true, true, true]),
            (None, [false, false, false]),
        ];
        for (role, expected) in table {
            let (rows, me, ws) = rows(role);
            for (action, ok) in [Read, Write, Delete].into_iter().zip(expected) {
                assert_eq!(
                    allowed(&rows, &me, ws, action).is_ok(),
                    ok,
                    "{role:?} {action:?}"
                );
            }
        }
    }

    #[test]
    fn a_superuser_is_admin_everywhere_and_an_unknown_workspace_reads_like_no_role() {
        let (mut rows, _, ws) = rows(None);
        let root = person(2, true);
        rows.users.push(root.clone());
        assert!(allowed(&rows, &root, ws, Action::Delete).is_ok());
        let (rows, me, _) = self::rows(Some(Role::Admin));
        assert_eq!(
            allowed(&rows, &me, Uuid::from_u128(999), Action::Read),
            Err(no_role())
        );
    }

    fn service_input() -> ServiceInput {
        ServiceInput {
            name: "orders".into(),
            protocol: "http".into(),
            host: "Orders.Internal".into(),
            port: 8080,
            connect_timeout_ms: Some(2000),
            read_timeout_ms: None,
            updated_at: None,
        }
    }

    #[test]
    fn a_valid_service_is_normalised() {
        let (s, at) = service(service_input(), Write::Create).unwrap();
        assert_eq!(s.host, "orders.internal");
        assert_eq!(s.connect_timeout_ms, Some(2000));
        assert_eq!(at, None);
    }

    #[test]
    fn each_bad_service_field_is_named() {
        let cases: Vec<Case<ServiceInput>> = vec![
            (|i| i.name = "has space".into(), "name"),
            (|i| i.name = "x".repeat(64), "name"),
            (|i| i.protocol = "ftp".into(), "protocol"),
            (|i| i.host = "http://orders".into(), "host"),
            (|i| i.host = "orders:8080".into(), "host"),
            (|i| i.port = 0, "port"),
            (|i| i.port = 65536, "port"),
            (|i| i.connect_timeout_ms = Some(0), "connect_timeout_ms"),
            (|i| i.read_timeout_ms = Some(3_600_001), "read_timeout_ms"),
            (|i| i.updated_at = Some("x".into()), "updated_at"),
        ];
        for (break_it, expected) in cases {
            let mut input = service_input();
            break_it(&mut input);
            assert_eq!(service(input, Write::Create).unwrap_err().field, expected);
        }
        assert_eq!(
            service(service_input(), Write::Replace).unwrap_err().field,
            "updated_at",
            "a replace must say what it last read"
        );
    }

    #[test]
    fn an_ipv4_address_is_a_host() {
        let mut input = service_input();
        input.host = "10.0.0.7".into();
        assert!(service(input, Write::Create).is_ok());
    }

    #[test]
    fn an_https_service_needs_a_name_not_an_address() {
        let mut input = service_input();
        input.host = "10.0.0.7".into();
        input.protocol = "https".into();
        assert_eq!(service(input, Write::Create).unwrap_err().field, "host");
    }

    #[test]
    fn an_ipv6_address_is_refused() {
        let mut input = service_input();
        input.host = "::1".into();
        assert_eq!(service(input, Write::Create).unwrap_err().field, "host");
    }

    fn route_input() -> RouteInput {
        RouteInput {
            name: "orders-api".into(),
            service: "orders".into(),
            hosts: vec![
                "API.example.com".into(),
                "*.example.org".into(),
                "api.example.com".into(),
            ],
            paths: vec![
                PathInput {
                    kind: "prefix".into(),
                    value: "/orders".into(),
                },
                PathInput {
                    kind: "regex".into(),
                    value: "/v[0-9]+/.*".into(),
                },
            ],
            methods: vec!["get".into(), "POST".into(), "GET".into()],
            priority: 5,
            updated_at: Some("2026-10-07T03:00:00.000000Z".into()),
        }
    }

    #[test]
    fn a_valid_route_is_normalised_and_deduplicated() {
        let (r, at) = route(route_input(), Write::Replace).unwrap();
        assert_eq!(r.hosts, ["api.example.com", "*.example.org"]);
        assert_eq!(r.methods, ["GET", "POST"]);
        assert_eq!(at.as_deref(), Some("2026-10-07T03:00:00.000000Z"));
    }

    #[test]
    fn each_bad_route_field_is_named() {
        let cases: Vec<Case<RouteInput>> = vec![
            (|i| i.hosts = vec!["bad host".into()], "hosts[0]"),
            (|i| i.hosts = vec!["*.".into()], "hosts[0]"),
            (|i| i.paths[0].kind = "glob".into(), "paths[0].type"),
            (|i| i.paths[0].value = "orders".into(), "paths[0].value"),
            (|i| i.paths[1].value = "[unclosed".into(), "paths[1].value"),
            (|i| i.paths[1].value = "a)|(b".into(), "paths[1].value"),
            (|i| i.methods = vec!["FETCH".into()], "methods[0]"),
            (|i| i.service = "".into(), "service"),
        ];
        for (break_it, expected) in cases {
            let mut input = route_input();
            break_it(&mut input);
            assert_eq!(route(input, Write::Replace).unwrap_err().field, expected);
        }
        let mut input = route_input();
        input.paths = (0..33)
            .map(|i| PathInput {
                kind: "exact".into(),
                value: format!("/{i}"),
            })
            .collect();
        assert_eq!(route(input, Write::Replace).unwrap_err().field, "paths");
    }

    #[test]
    fn empty_lists_mean_any() {
        let mut input = route_input();
        input.hosts.clear();
        input.paths.clear();
        input.methods.clear();
        let (r, _) = route(input, Write::Replace).unwrap();
        assert!(r.hosts.is_empty() && r.paths.is_empty() && r.methods.is_empty());
    }

    fn path(kind: &str, value: &str) -> PathInput {
        PathInput {
            kind: kind.into(),
            value: value.into(),
        }
    }

    fn route_with_paths(paths: Vec<PathInput>) -> RouteInput {
        RouteInput {
            paths,
            ..route_input()
        }
    }

    #[test]
    fn a_prefix_loses_its_trailing_slash_and_an_exact_path_keeps_it() {
        let input = route_with_paths(vec![
            path("prefix", "/api/"),
            path("prefix", "/"),
            path("exact", "/api/"),
        ]);
        let (r, _) = route(input, Write::Replace).unwrap();
        let values: Vec<_> = r
            .paths
            .iter()
            .map(|p| (p.kind.as_str(), p.value.as_str()))
            .collect();
        assert_eq!(
            values,
            [("prefix", "/api"), ("prefix", "/"), ("exact", "/api/")]
        );
    }

    #[test]
    fn a_path_given_twice_after_normalising_is_kept_once() {
        let input = route_with_paths(vec![
            path("prefix", "/api"),
            path("prefix", "/api/"),
            path("exact", "/api"),
        ]);
        let (r, _) = route(input, Write::Replace).unwrap();
        assert_eq!(
            r.paths.len(),
            2,
            "the same value of another type is a different match"
        );
    }

    #[test]
    fn a_path_is_visible_ascii_without_query_or_fragment() {
        let cases = [
            (
                "/a b",
                "Percent-encode characters outside visible ASCII, as clients send them.",
            ),
            (
                "/caf\u{e9}",
                "Percent-encode characters outside visible ASCII, as clients send them.",
            ),
            (
                "/a\tb",
                "Percent-encode characters outside visible ASCII, as clients send them.",
            ),
            ("/orders?x=1", "A path has no query string or fragment."),
            ("/a#b", "A path has no query string or fragment."),
            (
                "//orders",
                "A path has no empty segments: the gateway collapses // in requests.",
            ),
            (
                "/a/../b",
                "A path has no . or .. segments: the gateway refuses requests that do.",
            ),
            ("/a/.", "A path has no . or .. segments: the gateway refuses requests that do."),
            ("/a%2", "A % starts an escape of two hexadecimal digits."),
            ("/a%zz", "A % starts an escape of two hexadecimal digits."),
            (
                "/%41pi",
                "Write letters, digits and - . _ ~ as they are: the gateway decodes them before matching.",
            ),
        ];
        for kind in ["prefix", "exact"] {
            for (value, sentence) in cases {
                let err =
                    route(route_with_paths(vec![path(kind, value)]), Write::Replace).unwrap_err();
                assert_eq!(err.field, "paths[0].value", "{kind} {value:?}");
                assert_eq!(err.sentence, sentence, "{kind} {value:?}");
            }
        }
        // A regex is the author's own pattern and may use any of these.
        assert!(route(
            route_with_paths(vec![path("regex", "/a b|/c#")]),
            Write::Replace
        )
        .is_ok());
    }

    #[test]
    fn a_regex_refusal_carries_the_compilers_reason_on_one_line() {
        let err = route(
            route_with_paths(vec![path("regex", "[unclosed")]),
            Write::Replace,
        )
        .unwrap_err();
        assert_eq!(
            err.sentence,
            "This regular expression does not compile: unclosed character class"
        );
        let err = route(
            route_with_paths(vec![path("regex", "a{1000}{1000}")]),
            Write::Replace,
        )
        .unwrap_err();
        assert_eq!(err.field, "paths[0].value");
        assert!(err.sentence.contains("size limit"), "{}", err.sentence);
        assert!(!err.sentence.contains('\n') && err.sentence.chars().count() < 260);
    }

    #[test]
    fn a_route_takes_at_most_32_hosts() {
        let hosts = |n: usize| {
            (0..n)
                .map(|i| format!("h{i}.example.com"))
                .collect::<Vec<_>>()
        };
        let input = RouteInput {
            hosts: hosts(32),
            paths: vec![],
            methods: vec![],
            ..route_input()
        };
        assert!(route(input, Write::Replace).is_ok());
        let input = RouteInput {
            hosts: hosts(33),
            ..route_input()
        };
        let err = route(input, Write::Replace).unwrap_err();
        assert_eq!(err.field, "hosts");
        assert_eq!(err.sentence, "A route takes at most 32 hosts.");
    }

    #[test]
    fn a_route_may_not_expand_past_1024_combinations() {
        let hosts = |n: usize| {
            (0..n)
                .map(|i| format!("h{i}.example.com"))
                .collect::<Vec<_>>()
        };
        let paths = (0..32)
            .map(|i| path("exact", &format!("/{i}")))
            .collect::<Vec<_>>();
        // 32 hosts x 32 paths x any method is exactly the limit.
        let at_limit = RouteInput {
            hosts: hosts(32),
            paths: paths.clone(),
            methods: vec![],
            ..route_input()
        };
        assert!(route(at_limit, Write::Replace).is_ok());
        // 11 x 32 x 3 is 1056.
        let over = RouteInput {
            hosts: hosts(11),
            paths,
            methods: vec!["GET".into(), "POST".into(), "PUT".into()],
            ..route_input()
        };
        let err = route(over, Write::Replace).unwrap_err();
        assert_eq!(err.field, "paths");
        assert_eq!(
            err.sentence,
            "This route expands to more than 1024 host, path and method combinations; split it into several routes."
        );
    }

    #[test]
    fn a_host_that_a_resolver_reads_as_an_address_is_not_a_name() {
        for host in [
            "1.2.3",
            "2130706433",
            "010.0.0.1",
            "0x7f.1",
            "1.2.3.4.5",
            "orders.1",
        ] {
            let mut input = service_input();
            input.host = host.into();
            assert_eq!(
                service(input, Write::Create).unwrap_err().field,
                "host",
                "{host}"
            );
        }
        for host in [
            "10.0.0.1",
            "*.10.0.0.1",
            "1.2.3",
            "2130706433",
            "0x7f.1",
            "*.0x7f.1",
        ] {
            let input = RouteInput {
                hosts: vec![host.into()],
                ..route_input()
            };
            assert_eq!(
                route(input, Write::Replace).unwrap_err().field,
                "hosts[0]",
                "{host}"
            );
        }
        for host in ["orders", "orders-1.internal", "a.b.c1x", "x1"] {
            let mut input = service_input();
            input.host = host.into();
            assert!(service(input, Write::Create).is_ok(), "{host}");
        }
    }

    #[test]
    fn a_name_starts_with_a_letter_or_a_digit() {
        for bad in [".", "..", "-x", "_x", "~x", ".hidden"] {
            let mut input = service_input();
            input.name = bad.into();
            assert_eq!(
                service(input, Write::Create).unwrap_err().field,
                "name",
                "{bad}"
            );
            let input = RouteInput {
                name: bad.into(),
                ..route_input()
            };
            assert_eq!(
                route(input, Write::Replace).unwrap_err().field,
                "name",
                "{bad}"
            );
            let input = RouteInput {
                service: bad.into(),
                ..route_input()
            };
            assert_eq!(
                route(input, Write::Replace).unwrap_err().field,
                "service",
                "{bad}"
            );
        }
        for good in ["a", "7", "a.b_c~d-e", "9lives"] {
            assert!(name(good, "name").is_ok(), "{good}");
        }
    }

    #[test]
    fn the_name_is_checked_before_anything_else() {
        let mut input = service_input();
        input.name = "..".into();
        input.protocol = "ftp".into();
        input.port = 0;
        assert_eq!(service(input, Write::Create).unwrap_err().field, "name");
        let input = RouteInput {
            name: "..".into(),
            hosts: vec!["bad host".into()],
            methods: vec!["FETCH".into()],
            ..route_input()
        };
        assert_eq!(route(input, Write::Replace).unwrap_err().field, "name");
    }

    #[test]
    fn the_limits_themselves_are_accepted() {
        let mut input = service_input();
        input.name = "n".repeat(63);
        input.port = 1;
        input.connect_timeout_ms = Some(1);
        input.read_timeout_ms = Some(3_600_000);
        assert!(service(input.clone(), Write::Create).is_ok());
        input.port = 65535;
        assert!(service(input.clone(), Write::Create).is_ok());
        // Four labels of 63, 63, 63 and 61 characters, and three dots: 253.
        input.host = [63, 63, 63, 61].map(|n| "a".repeat(n)).join(".");
        assert_eq!(input.host.len(), 253);
        assert!(service(input.clone(), Write::Create).is_ok());
        input.host.push('a');
        assert_eq!(service(input, Write::Create).unwrap_err().field, "host");

        let long = format!("/{}", "a".repeat(1023));
        let input = route_with_paths(vec![path("exact", &long)]);
        assert!(route(input, Write::Replace).is_ok());
        let input = route_with_paths(vec![path("exact", &format!("{long}a"))]);
        assert_eq!(
            route(input, Write::Replace).unwrap_err().field,
            "paths[0].value"
        );
    }

    #[test]
    fn a_refusal_for_too_little_role_names_the_role_needed() {
        let (rows, me, ws) = rows(Some(Role::Viewer));
        assert_eq!(
            allowed(&rows, &me, ws, Action::Write),
            Err(Refusal::Forbidden(
                "Changing services and routes needs the editor role in this workspace.".into()
            ))
        );
        assert_eq!(
            allowed(&rows, &me, ws, Action::Delete),
            Err(Refusal::Forbidden(
                "Deleting services and routes needs the admin role in this workspace.".into()
            ))
        );
    }

    #[test]
    fn equal_hosts_overlap_and_different_names_do_not() {
        assert!(hosts_overlap("api.example.com", "api.example.com"));
        assert!(hosts_overlap("*.example.com", "*.example.com"));
        assert!(!hosts_overlap("api.example.com", "www.example.com"));
        assert!(!hosts_overlap("example.com", "example.org"));
    }

    #[test]
    fn a_wildcard_overlaps_what_it_matches_and_not_its_bare_suffix() {
        for (a, b) in [
            ("*.example.com", "api.example.com"),
            ("*.example.com", "a.b.example.com"),
        ] {
            assert!(hosts_overlap(a, b), "{a} {b}");
            assert!(hosts_overlap(b, a), "{b} {a}");
        }
        assert!(!hosts_overlap("*.example.com", "example.com"));
        assert!(!hosts_overlap("example.com", "*.example.com"));
        assert!(!hosts_overlap("*.example.com", "notexample.com"));
    }

    #[test]
    fn wildcards_overlap_when_one_suffix_ends_with_the_other() {
        assert!(hosts_overlap("*.example.com", "*.api.example.com"));
        assert!(hosts_overlap("*.api.example.com", "*.example.com"));
        assert!(!hosts_overlap("*.a.com", "*.b.com"));
        assert!(!hosts_overlap("*.xexample.com", "*.example.com"));
    }

    #[test]
    fn only_a_superuser_may_route_any_host() {
        assert!(may_route_any_host(&person(1, true)).is_ok());
        assert_eq!(
            may_route_any_host(&person(2, false)),
            Err(Refusal::Forbidden(
                "Only a superuser may create a route for any host: it would take other workspaces' traffic. Name at least one host.".into()
            ))
        );
    }

    #[test]
    fn ordinary_unicode_patterns_are_accepted_and_a_huge_one_is_not() {
        for ok in [r"/users/[\w-]{1,64}", "/[^/]{1,255}"] {
            let r = route(route_with_paths(vec![path("regex", ok)]), Write::Replace);
            assert!(r.is_ok(), "{ok}: {:?}", r.err());
        }
        let err = route(
            route_with_paths(vec![path("regex", "a{1000}{1000}")]),
            Write::Replace,
        )
        .unwrap_err();
        assert_eq!(err.field, "paths[0].value");
        assert!(err.sentence.contains("size limit"), "{}", err.sentence);
    }

    #[test]
    fn a_wildcard_needs_two_labels_unless_a_superuser_routes_it() {
        let editor = person(2, false);
        let root = person(1, true);
        for host in [
            "*.example.com",
            "*.a.example.com",
            "example.com",
            "api.example.com",
        ] {
            assert!(may_claim_wildcard(&editor, host).is_ok(), "{host}");
        }
        assert_eq!(
            may_claim_wildcard(&editor, "*.com"),
            Err(Refusal::Forbidden(
                "*.com would claim every name under one label for this workspace; only a superuser may route it.".into()
            ))
        );
        assert!(may_claim_wildcard(&root, "*.com").is_ok());
    }
}
