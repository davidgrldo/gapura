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
pub const MAX_PATHS: usize = 32;
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
    Err(Refusal::Forbidden(
        match action {
            Action::Read => unreachable!("every role reads"),
            Action::Write => {
                "Changing services and routes needs the editor role in this workspace."
            }
            Action::Delete => {
                "Deleting services and routes needs the admin role in this workspace."
            }
        }
        .into(),
    ))
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

fn updated_at(kind: Write, value: Option<String>) -> Result<Option<String>, FieldError> {
    match (kind, value) {
        (Write::Create, None) => Ok(None),
        (Write::Create, Some(_)) => {
            Err(field("updated_at", "A new row has no updated_at to send."))
        }
        (Write::Replace, Some(v)) => Ok(Some(v)),
        (Write::Replace, None) => Err(field(
            "updated_at",
            "Send the updated_at you last read, so a change made meanwhile is not overwritten.",
        )),
    }
}

/// Letters, digits and `. _ ~ -`, 1 to 63 of them.
pub fn name(value: &str, at: &str) -> Result<String, FieldError> {
    let ok = !value.is_empty()
        && value.chars().count() <= MAX_NAME_CHARS
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '~' | '-'));
    if ok {
        Ok(value.to_string())
    } else {
        Err(field(
            at,
            "Use 1 to 63 letters, digits, dots, underscores, tildes or hyphens.",
        ))
    }
}

/// A DNS name: labels of letters, digits and hyphens, 1 to 63 long, not starting or ending with a
/// hyphen, 253 characters in all.
fn dns_name(value: &str) -> bool {
    value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

/// A DNS name or an IPv4 address. The data plane joins `host:port` without brackets, so an IPv6
/// literal would be ambiguous and is refused.
fn upstream_host(value: &str) -> Result<String, FieldError> {
    let lowered = value.to_ascii_lowercase();
    let ipv4 = value.parse::<std::net::Ipv4Addr>().is_ok();
    if ipv4 || (value.parse::<std::net::IpAddr>().is_err() && dns_name(&lowered)) {
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
            "Use a number of milliseconds from 1 to 3600000, or leave it empty.",
        )),
    }
}

/// A service request, checked, and the `updated_at` it carried.
pub fn service(input: ServiceInput, kind: Write) -> Result<(Service, Option<String>), FieldError> {
    let protocol = match input.protocol.as_str() {
        "http" => Protocol::Http,
        "https" => Protocol::Https,
        _ => return Err(field("protocol", "Use http or https.")),
    };
    let port = if (1..=65535).contains(&input.port) {
        input.port as i32
    } else {
        return Err(field("port", "Use a port from 1 to 65535."));
    };
    let host = upstream_host(&input.host)?;
    if protocol == Protocol::Https && host.parse::<std::net::IpAddr>().is_ok() {
        return Err(field(
            "host",
            "An https service needs a host name: its certificate is checked against names, not addresses.",
        ));
    }
    let service = Service {
        name: name(&input.name, "name")?,
        protocol,
        host,
        port,
        connect_timeout_ms: timeout(input.connect_timeout_ms, "connect_timeout_ms")?,
        read_timeout_ms: timeout(input.read_timeout_ms, "read_timeout_ms")?,
    };
    Ok((service, updated_at(kind, input.updated_at)?))
}

/// A route request, checked, and the `updated_at` it carried. Hosts are lowercased and methods
/// uppercased; a value given twice is kept once.
pub fn route(input: RouteInput, kind: Write) -> Result<(Route, Option<String>), FieldError> {
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
        return Err(field("paths", "A route takes at most 32 paths."));
    }
    let mut paths = Vec::new();
    for (i, path) in input.paths.into_iter().enumerate() {
        if !PATH_TYPES.contains(&path.kind.as_str()) {
            return Err(field(
                format!("paths[{i}].type"),
                "Use prefix, exact or regex.",
            ));
        }
        let at = format!("paths[{i}].value");
        if path.value.is_empty() || path.value.chars().count() > MAX_PATH_CHARS {
            return Err(field(at, "Use a path of 1 to 1024 characters."));
        }
        if path.kind == "regex" {
            if gapura_core::matcher::compile_path_regex(&path.value).is_err() {
                return Err(field(at, "This regular expression does not compile."));
            }
        } else if !path.value.starts_with('/') {
            return Err(field(at, "A prefix or exact path starts with /."));
        }
        paths.push(PathMatch {
            kind: path.kind,
            value: path.value,
        });
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
    let route = Route {
        name: name(&input.name, "name")?,
        service: name(&input.service, "service")?,
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
}
