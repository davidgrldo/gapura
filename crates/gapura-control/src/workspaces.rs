//! Workspaces: who may see and change them, and what keeps one from being deleted. Pure; the
//! store applies these over rows it has locked.
//!
//! ADR 5 rule 2: creating, renaming and deleting a workspace are a superuser's. A workspace admin
//! sees the workspaces they administer; nobody else sees the list. A workspace is deleted only
//! when it is empty, because every table that belongs to one cascades on its delete: a populated
//! workspace would take its whole configuration, and the traffic it routes, with it. The last
//! workspace is never deleted, since the console's pickers assume there is one.

use crate::access::{Rows, User};
use crate::configuration::{self, FieldError};
use crate::grants::Refusal;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

/// What a superuser sends to create or rename a workspace.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceInput {
    pub name: String,
}

/// A workspace's name follows the services' rule, and case matters as it does for them.
pub fn name(input: WorkspaceInput) -> Result<String, FieldError> {
    configuration::name(&input.name, "name")
}

/// Which workspaces `caller` sees on the list: `None` for every one, to a superuser; otherwise
/// the ones they administer. Someone who administers none is refused.
pub fn may_list(rows: &Rows, caller: &User) -> Result<Option<BTreeSet<Uuid>>, Refusal> {
    if caller.superuser && !caller.disabled {
        return Ok(None);
    }
    let administered = rows.grantable(caller);
    if administered.is_empty() {
        return Err(Refusal::Forbidden(
            "You do not administer any workspace.".into(),
        ));
    }
    Ok(Some(administered))
}

/// A superuser's, and an enabled one's: the store reads the caller again inside each write
/// without refusing a disabled account, so this is where one disabled since sign-in is stopped.
pub fn may_write(caller: &User) -> Result<(), Refusal> {
    if caller.superuser && !caller.disabled {
        return Ok(());
    }
    Err(Refusal::Forbidden(
        "Workspaces are a superuser's to change.".into(),
    ))
}

/// What a workspace holds that its delete would take with it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Contents {
    pub services: i64,
    pub routes: i64,
    pub consumers: i64,
    pub policies: i64,
    pub certificates: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WorkspaceView {
    pub name: String,
    pub created_at: String,
    #[serde(flatten)]
    pub contents: Contents,
    /// Direct grants there plus group mappings into it.
    pub members: i64,
}

/// `count` of a thing, with the right plural.
fn counted(count: i64, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

/// Whether the workspace `name`, holding `contents`, may be deleted: only when it holds nothing.
/// The refusal names what is left, so whoever reads it knows what to remove.
pub fn emptiness(name: &str, contents: &Contents) -> Result<(), Refusal> {
    let left: Vec<String> = [
        (contents.services, "service", "services"),
        (contents.routes, "route", "routes"),
        (contents.consumers, "consumer", "consumers"),
        (contents.policies, "policy", "policies"),
        (contents.certificates, "certificate", "certificates"),
    ]
    .into_iter()
    .filter(|(count, _, _)| *count > 0)
    .map(|(count, one, many)| counted(count, one, many))
    .collect();
    let Some((last, rest)) = left.split_last() else {
        return Ok(());
    };
    let list = if rest.is_empty() {
        last.clone()
    } else {
        format!("{} and {last}", rest.join(", "))
    };
    let total: i64 = [
        contents.services,
        contents.routes,
        contents.consumers,
        contents.policies,
        contents.certificates,
    ]
    .iter()
    .sum();
    let them = if total == 1 { "it" } else { "them" };
    Err(Refusal::Conflict(format!(
        "{name} still has {list}. Remove {them} first."
    )))
}

/// Whether the workspace `name` may be deleted when `workspaces` exist in all, it among them:
/// never the last one.
pub fn not_the_last(name: &str, workspaces: usize) -> Result<(), Refusal> {
    if workspaces > 1 {
        return Ok(());
    }
    Err(Refusal::Conflict(format!(
        "{name} is the only workspace, and the console needs one. Create another first."
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::{Grant, Method, Role, Workspace};

    fn user(n: u128, superuser: bool) -> User {
        User {
            id: Uuid::from_u128(n),
            name: format!("u{n}"),
            method: Method::Local,
            superuser,
            disabled: false,
            groups: Vec::new(),
            last_sign_in: None,
            must_change_password: false,
            sessions_valid_after: None,
            signup_note: None,
        }
    }

    fn conflict(result: Result<(), Refusal>) -> String {
        match result {
            Err(Refusal::Conflict(sentence)) => sentence,
            other => panic!("not a conflict: {other:?}"),
        }
    }

    /// Two workspaces; `u2` administers `a`, `u3` views it.
    fn rows() -> Rows {
        let a = Uuid::from_u128(100);
        Rows {
            users: vec![user(1, true), user(2, false), user(3, false)],
            workspaces: vec![
                Workspace {
                    id: a,
                    name: "a".into(),
                },
                Workspace {
                    id: Uuid::from_u128(101),
                    name: "b".into(),
                },
            ],
            grants: vec![
                Grant {
                    user: Uuid::from_u128(2),
                    workspace: a,
                    role: Role::Admin,
                },
                Grant {
                    user: Uuid::from_u128(3),
                    workspace: a,
                    role: Role::Viewer,
                },
            ],
            group_grants: Vec::new(),
        }
    }

    #[test]
    fn a_name_follows_the_configuration_rule() {
        let named = |text: &str| {
            name(WorkspaceInput {
                name: text.to_string(),
            })
        };
        assert_eq!(named("payments").unwrap(), "payments");
        assert_eq!(named("Team-2").unwrap(), "Team-2");
        for bad in ["", "..", "-a", "a b", "a/b"] {
            assert_eq!(named(bad).unwrap_err().field, "name", "{bad:?}");
        }
    }

    #[test]
    fn a_superuser_lists_every_workspace_an_admin_only_theirs() {
        let rows = rows();
        assert_eq!(may_list(&rows, &user(1, true)), Ok(None));
        assert_eq!(
            may_list(&rows, &user(2, false)),
            Ok(Some(BTreeSet::from([Uuid::from_u128(100)])))
        );
        for caller in [user(3, false), user(4, false)] {
            assert_eq!(
                may_list(&rows, &caller),
                Err(Refusal::Forbidden(
                    "You do not administer any workspace.".into()
                ))
            );
        }
        let mut disabled = user(1, true);
        disabled.disabled = true;
        assert!(may_list(&rows, &disabled).is_err());
    }

    #[test]
    fn only_an_enabled_superuser_may_write() {
        let mut caller = user(1, true);
        assert!(may_write(&caller).is_ok());
        caller.disabled = true;
        assert!(
            may_write(&caller).is_err(),
            "a disabled superuser holds nothing"
        );
        caller.disabled = false;
        caller.superuser = false;
        assert_eq!(
            may_write(&caller),
            Err(Refusal::Forbidden(
                "Workspaces are a superuser's to change.".into()
            ))
        );
    }

    #[test]
    fn an_empty_workspace_may_go() {
        assert!(emptiness("a", &Contents::default()).is_ok());
    }

    #[test]
    fn what_is_left_is_named_with_its_plurals() {
        let left = |contents: Contents| conflict(emptiness("payments", &contents));
        assert_eq!(
            left(Contents {
                services: 2,
                consumers: 1,
                ..Contents::default()
            }),
            "payments still has 2 services and 1 consumer. Remove them first."
        );
        assert_eq!(
            left(Contents {
                routes: 1,
                ..Contents::default()
            }),
            "payments still has 1 route. Remove it first."
        );
        assert_eq!(
            left(Contents {
                policies: 3,
                ..Contents::default()
            }),
            "payments still has 3 policies. Remove them first."
        );
        assert_eq!(
            left(Contents {
                services: 1,
                routes: 2,
                consumers: 3,
                policies: 1,
                certificates: 1,
            }),
            "payments still has 1 service, 2 routes, 3 consumers, 1 policy and 1 certificate. \
             Remove them first."
        );
    }

    #[test]
    fn the_last_workspace_stays() {
        assert!(not_the_last("a", 2).is_ok());
        assert_eq!(
            conflict(not_the_last("default", 1)),
            "default is the only workspace, and the console needs one. Create another first."
        );
    }
}
