//! The audit log: who may read which of its entries, and what a request for a page of them may
//! ask. Pure; `store::audit` reads the page these describe.
//!
//! ADR 5 rule 5: anyone with a role in at least one workspace reads the log, a superuser all of
//! it. Anyone else sees the entries of the workspaces they hold a role in, any role. An entry with
//! no workspace (about an account itself, a workspace, a data plane, or one whose workspace has
//! since been deleted) is a superuser's alone. Nothing secret reaches the log, so an entry is
//! shown as recorded.

use crate::access::{Rows, User};
use crate::configuration::FieldError;
use crate::grants::Refusal;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

/// Every `object_kind` the store writes, and where. A write that records a new kind adds it
/// here, or the log cannot be filtered by it; `the_known_kinds_are_the_ones_written` checks.
pub const KINDS: &[&str] = &[
    // store/accounts.rs `entry`: an account created, changed, its password reset or deleted;
    // store/grants.rs `try_set_direct_roles`: an account's direct grant in one workspace.
    "user",
    // store/grants.rs `try_write_group_mapping`.
    "group_mapping",
    // store/workspaces.rs `entry`.
    "workspace",
    // store/configuration.rs, the service writes.
    "service",
    // store/configuration.rs, the route writes.
    "route",
    // store/consumers.rs, creating and deleting a consumer.
    "consumer",
    // store/consumers.rs, issuing and revoking a consumer's key.
    "consumer_key",
    // store/consumers.rs, putting and removing key-auth.
    "policy",
    // store/data_planes.rs, registering and deleting a data plane.
    "data_plane",
    // store/data_planes.rs, issuing and revoking a data plane's token.
    "data_plane_token",
];

/// The fewest and the most entries one page holds, and how many when the request does not say.
pub const MIN_LIMIT: i64 = 1;
pub const MAX_LIMIT: i64 = 200;
pub const DEFAULT_LIMIT: i64 = 50;

/// What `workspace=` asks for in the query that means entries with no workspace.
pub const NO_WORKSPACE: &str = "-";

/// The query as sent, each value as text, so that one which cannot be read is refused beside its
/// own field rather than as a query axum could not read.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct QueryInput {
    pub before: Option<String>,
    pub limit: Option<String>,
    pub workspace: Option<String>,
    pub kind: Option<String>,
}

/// Which workspace's entries a page holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkspaceFilter {
    /// Every one the caller may see, and, to a superuser, the entries with none.
    Any,
    /// The entries with no workspace: `workspace=-`.
    NoWorkspace,
    /// The entries of the workspace of this name. One that does not exist, or that the caller
    /// holds no role in, gives an empty page rather than a refusal, so the filter does not tell
    /// whether a name exists.
    Named(String),
}

/// A request for one page, read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Query {
    /// Only entries older than this one: the `next` of the page before.
    pub before: Option<i64>,
    pub limit: i64,
    pub workspace: WorkspaceFilter,
    /// One of `KINDS`.
    pub kind: Option<&'static str>,
}

fn field(field: &str, sentence: impl Into<String>) -> FieldError {
    FieldError {
        field: field.into(),
        sentence: sentence.into(),
    }
}

/// A value that was sent empty is one that was not sent: the console's filters send `kind=` for
/// "every kind".
fn given(value: Option<String>) -> Option<String> {
    value.filter(|v| !v.is_empty())
}

/// The query read and checked: a value that cannot be read, a limit outside 1 to 200 or a kind
/// the log does not use is refused beside its field.
pub fn query(input: QueryInput) -> Result<Query, FieldError> {
    let before = match given(input.before) {
        None => None,
        Some(v) => match v.parse::<i64>() {
            Ok(id) if id >= 1 => Some(id),
            _ => {
                return Err(field(
                    "before",
                    "Use the id of an entry, as the page before gave it.",
                ))
            }
        },
    };
    let limit = match given(input.limit) {
        None => DEFAULT_LIMIT,
        Some(v) => match v.parse::<i64>() {
            Ok(n) if (MIN_LIMIT..=MAX_LIMIT).contains(&n) => n,
            _ => {
                return Err(field(
                    "limit",
                    format!("Ask for {MIN_LIMIT} to {MAX_LIMIT} entries."),
                ))
            }
        },
    };
    let workspace = match given(input.workspace) {
        None => WorkspaceFilter::Any,
        Some(v) if v == NO_WORKSPACE => WorkspaceFilter::NoWorkspace,
        Some(v) => WorkspaceFilter::Named(v),
    };
    let kind = match given(input.kind) {
        None => None,
        Some(v) => match KINDS.iter().find(|k| **k == v) {
            Some(k) => Some(*k),
            None => return Err(field("kind", format!("Use one of {}.", KINDS.join(", ")))),
        },
    };
    Ok(Query {
        before,
        limit,
        workspace,
        kind,
    })
}

/// Which entries a caller may read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Visible {
    /// A superuser's: every entry, those with no workspace among them.
    Everything,
    /// The entries of these workspaces, the ones the caller holds any role in. Never empty.
    Workspaces(BTreeSet<Uuid>),
}

/// What `caller` may read of the log. Someone with no role anywhere, and not a superuser, reads
/// none of it, and is refused rather than shown an empty log.
pub fn visible(rows: &Rows, caller: &User) -> Result<Visible, Refusal> {
    if caller.superuser && !caller.disabled {
        return Ok(Visible::Everything);
    }
    let reached: BTreeSet<Uuid> = rows
        .workspaces
        .iter()
        .filter(|w| rows.effective(caller, w.id).is_some())
        .map(|w| w.id)
        .collect();
    if reached.is_empty() {
        return Err(Refusal::Forbidden(
            "You hold no role in any workspace, so there is no audit log for you to read.".into(),
        ));
    }
    Ok(Visible::Workspaces(reached))
}

impl Query {
    /// Whether the page is empty whatever the log holds, so the store need not be asked: the
    /// entries with no workspace, to anyone but a superuser, or a workspace by a name that can be
    /// no workspace's (one the database would refuse to compare, a NUL byte, among them).
    pub fn matches_nothing(&self, visible: &Visible) -> bool {
        match &self.workspace {
            WorkspaceFilter::Any => false,
            WorkspaceFilter::NoWorkspace => *visible != Visible::Everything,
            WorkspaceFilter::Named(name) => crate::configuration::name(name, "workspace").is_err(),
        }
    }
}

/// One entry, as the console shows it. `object_id` is left out: `before` and `after` carry the
/// names a person reads.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct EntryView {
    pub id: i64,
    /// UTC, to the microsecond, as `updated_at` is everywhere else.
    pub at: String,
    pub actor: String,
    /// `local` or `oidc`; `null` for an entry with no person behind it.
    pub actor_method: Option<String>,
    pub action: String,
    pub object_kind: String,
    /// The workspace's name now; `null` for an entry with none, or whose workspace is gone.
    pub workspace: Option<String>,
    pub before: Option<serde_json::Value>,
    pub after: Option<serde_json::Value>,
}

/// One page, newest first. `next` is what to send as `before` for the page after it, and `null`
/// on the last page.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct AuditPage {
    pub entries: Vec<EntryView>,
    pub next: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::{Grant, GroupGrant, Method, Role, Workspace};

    fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn user(n: u128, superuser: bool, groups: &[&str]) -> User {
        User {
            id: id(n),
            name: format!("user-{n}"),
            method: Method::Local,
            superuser,
            disabled: false,
            groups: groups.iter().map(|g| g.to_string()).collect(),
            last_sign_in: None,
            must_change_password: false,
            sessions_valid_after: None,
        }
    }

    /// Workspaces 100, 200 and 300; user 2 a viewer of 100, user 3 an editor of 200 through the
    /// group `devs`.
    fn rows() -> Rows {
        Rows {
            users: vec![],
            workspaces: [100, 200, 300]
                .into_iter()
                .map(|n| Workspace {
                    id: id(n),
                    name: format!("w{n}"),
                })
                .collect(),
            grants: vec![Grant {
                user: id(2),
                workspace: id(100),
                role: Role::Viewer,
            }],
            group_grants: vec![GroupGrant {
                group: "devs".into(),
                workspace: id(200),
                role: Role::Editor,
            }],
        }
    }

    fn input(pairs: &[(&str, &str)]) -> QueryInput {
        let mut q = QueryInput::default();
        for (k, v) in pairs {
            let v = Some(v.to_string());
            match *k {
                "before" => q.before = v,
                "limit" => q.limit = v,
                "workspace" => q.workspace = v,
                "kind" => q.kind = v,
                other => panic!("{other}"),
            }
        }
        q
    }

    fn refused(pairs: &[(&str, &str)]) -> String {
        query(input(pairs)).unwrap_err().field
    }

    #[test]
    fn nothing_asked_is_the_newest_fifty_of_everything() {
        assert_eq!(
            query(QueryInput::default()).unwrap(),
            Query {
                before: None,
                limit: 50,
                workspace: WorkspaceFilter::Any,
                kind: None,
            }
        );
        // The console sends an empty filter for "all".
        assert_eq!(
            query(input(&[
                ("workspace", ""),
                ("kind", ""),
                ("before", ""),
                ("limit", "")
            ]))
            .unwrap(),
            query(QueryInput::default()).unwrap()
        );
    }

    #[test]
    fn each_value_is_read() {
        assert_eq!(
            query(input(&[
                ("before", "98"),
                ("limit", "200"),
                ("workspace", "payments"),
                ("kind", "consumer_key"),
            ]))
            .unwrap(),
            Query {
                before: Some(98),
                limit: 200,
                workspace: WorkspaceFilter::Named("payments".into()),
                kind: Some("consumer_key"),
            }
        );
        assert_eq!(
            query(input(&[("workspace", "-"), ("limit", "1")])).unwrap(),
            Query {
                before: None,
                limit: 1,
                workspace: WorkspaceFilter::NoWorkspace,
                kind: None,
            }
        );
    }

    #[test]
    fn a_limit_outside_one_to_two_hundred_is_refused_not_clamped() {
        for bad in ["0", "201", "-1", "ten", "1.5", "99999999999999999999"] {
            assert_eq!(refused(&[("limit", bad)]), "limit", "{bad}");
        }
    }

    #[test]
    fn a_before_that_is_no_id_is_refused() {
        for bad in ["0", "-3", "abc", "1e3"] {
            assert_eq!(refused(&[("before", bad)]), "before", "{bad}");
        }
    }

    #[test]
    fn a_kind_the_log_does_not_use_is_refused() {
        for bad in ["users", "Service", "certificate", " route"] {
            assert_eq!(refused(&[("kind", bad)]), "kind", "{bad}");
        }
        for kind in KINDS {
            assert_eq!(query(input(&[("kind", kind)])).unwrap().kind, Some(*kind));
        }
    }

    /// Every `object_kind: "…"` in the store's sources, read at compile time. The store writes
    /// entries only through `grants::Entry`, so this is every kind it can record.
    #[test]
    fn the_known_kinds_are_the_ones_written() {
        let sources = [
            include_str!("store/accounts.rs"),
            include_str!("store/configuration.rs"),
            include_str!("store/consumers.rs"),
            include_str!("store/data_planes.rs"),
            include_str!("store/grants.rs"),
            include_str!("store/identity.rs"),
            include_str!("store/mod.rs"),
            include_str!("store/workspaces.rs"),
        ];
        let mut written = BTreeSet::new();
        for source in sources {
            for (i, m) in source.match_indices("object_kind: \"") {
                let rest = &source[i + m.len()..];
                written.insert(&rest[..rest.find('"').unwrap()]);
            }
        }
        let known: BTreeSet<&str> = KINDS.iter().copied().collect();
        assert_eq!(written, known);
        assert_eq!(known.len(), KINDS.len(), "a kind is listed twice");
    }

    #[test]
    fn a_superuser_sees_everything() {
        assert_eq!(
            visible(&rows(), &user(1, true, &[])).unwrap(),
            Visible::Everything
        );
    }

    #[test]
    fn anyone_else_sees_the_workspaces_they_hold_any_role_in() {
        let rows = rows();
        assert_eq!(
            visible(&rows, &user(2, false, &[])).unwrap(),
            Visible::Workspaces(BTreeSet::from([id(100)]))
        );
        assert_eq!(
            visible(&rows, &user(3, false, &["devs"])).unwrap(),
            Visible::Workspaces(BTreeSet::from([id(200)])),
            "a role through a group counts"
        );
    }

    #[test]
    fn no_role_anywhere_is_refused() {
        let rows = rows();
        let refusal = visible(&rows, &user(4, false, &["strangers"])).unwrap_err();
        assert_eq!(refusal.status(), axum::http::StatusCode::FORBIDDEN);
        let mut disabled = user(1, true, &[]);
        disabled.disabled = true;
        assert!(visible(&rows, &disabled).is_err(), "a disabled superuser");
        let mut viewer = user(2, false, &[]);
        viewer.disabled = true;
        assert!(visible(&rows, &viewer).is_err(), "a disabled viewer");
    }

    #[test]
    fn what_matches_nothing_is_not_asked_for() {
        let mine = Visible::Workspaces(BTreeSet::from([id(100)]));
        let no_workspace = query(input(&[("workspace", "-")])).unwrap();
        assert!(no_workspace.matches_nothing(&mine));
        assert!(!no_workspace.matches_nothing(&Visible::Everything));
        let any = query(QueryInput::default()).unwrap();
        assert!(!any.matches_nothing(&mine));
        let named = query(input(&[("workspace", "payments")])).unwrap();
        assert!(!named.matches_nothing(&mine));
        for impossible in ["a\0b", "../x", "-x", "has space"] {
            let q = query(input(&[("workspace", impossible)])).unwrap();
            assert!(q.matches_nothing(&Visible::Everything), "{impossible:?}");
        }
    }
}
