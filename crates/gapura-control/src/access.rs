//! Who may see what in store mode, as pure functions over rows.
//!
//! The rules: a person's role in a workspace is the highest that any of their grants gives
//! them, and nothing subtracts; a superuser is admin everywhere; a disabled account holds
//! nothing; and someone who administers a workspace sees roles only in the workspaces they
//! administer. They live here, apart from the store and the handlers, so each one is tested
//! without a database and there is one place to read them.

use serde::Serialize;
use std::collections::BTreeSet;
use uuid::Uuid;

/// A role in one workspace, in rising order: each can do everything the one before it can.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Viewer,
    Editor,
    Admin,
}

impl Role {
    /// The store's `role_name` spelling.
    pub fn parse(name: &str) -> Option<Role> {
        match name {
            "viewer" => Some(Role::Viewer),
            "editor" => Some(Role::Editor),
            "admin" => Some(Role::Admin),
            _ => None,
        }
    }
}

/// Why someone holds a role in a workspace.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "kind", content = "name", rename_all = "lowercase")]
pub enum Source {
    Superuser,
    Direct,
    Group(String),
}

/// How an account signs in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Method {
    Local,
    Oidc,
}

#[derive(Clone, Debug, PartialEq)]
pub struct User {
    pub id: Uuid,
    /// The username of a local account; the provider's name for an OIDC one.
    pub name: String,
    pub method: Method,
    pub superuser: bool,
    pub disabled: bool,
    /// An OIDC account's groups as of its last sign-in; always empty for a local account.
    pub groups: Vec<String>,
    /// Unix seconds.
    pub last_sign_in: Option<i64>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Workspace {
    pub id: Uuid,
    pub name: String,
}

/// A role given to one account directly.
#[derive(Clone, Debug, PartialEq)]
pub struct Grant {
    pub user: Uuid,
    pub workspace: Uuid,
    pub role: Role,
}

/// A role given to everyone whose identity provider puts them in a group.
#[derive(Clone, Debug, PartialEq)]
pub struct GroupGrant {
    pub group: String,
    pub workspace: Uuid,
    pub role: Role,
}

/// Everything access is computed from, as one consistent read of the store.
#[derive(Clone, Debug, Default)]
pub struct Rows {
    pub users: Vec<User>,
    pub workspaces: Vec<Workspace>,
    pub grants: Vec<Grant>,
    pub group_grants: Vec<GroupGrant>,
}

/// A role held in one workspace, and every grant that gives a role there.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Access {
    pub role: Role,
    pub sources: Vec<Source>,
}

impl Rows {
    /// The highest role `user` holds in `workspace`, with every source of a role there,
    /// whatever its level: the direct viewer grant underneath a group's editor role is what an
    /// admin needs to see before removing either.
    pub fn effective(&self, user: &User, workspace: Uuid) -> Option<Access> {
        if user.disabled {
            return None;
        }
        let mut held: Vec<(Role, Source)> = Vec::new();
        if user.superuser {
            held.push((Role::Admin, Source::Superuser));
        }
        held.extend(
            self.grants
                .iter()
                .filter(|g| g.user == user.id && g.workspace == workspace)
                .map(|g| (g.role, Source::Direct)),
        );
        held.extend(
            self.group_grants
                .iter()
                .filter(|g| g.workspace == workspace && user.groups.contains(&g.group))
                .map(|g| (g.role, Source::Group(g.group.clone()))),
        );
        let role = held.iter().map(|(role, _)| *role).max()?;
        let mut sources: Vec<Source> = held.into_iter().map(|(_, source)| source).collect();
        sources.sort();
        sources.dedup();
        Some(Access { role, sources })
    }

    /// The workspaces where `caller` is admin. A superuser is admin everywhere, so for them this
    /// is every workspace; it is also exactly where the caller may see other people's roles.
    pub fn grantable(&self, caller: &User) -> BTreeSet<Uuid> {
        self.workspaces
            .iter()
            .filter(|w| {
                self.effective(caller, w.id)
                    .is_some_and(|a| a.role == Role::Admin)
            })
            .map(|w| w.id)
            .collect()
    }

    /// Signed in, enabled, and reaching nothing: the account exists, but nobody has granted it
    /// anything yet. Derived rather than stored, so a grant ends the wait by itself.
    pub fn waiting(&self, user: &User) -> bool {
        !user.disabled
            && !user.superuser
            && self
                .workspaces
                .iter()
                .all(|w| self.effective(user, w.id).is_none())
    }

    /// `user`'s access in `within` only, in workspace order. This is the trim: a workspace
    /// outside `within` is never computed, so it cannot be returned by mistake.
    pub fn access_in(&self, user: &User, within: &BTreeSet<Uuid>) -> Vec<(&Workspace, Access)> {
        self.workspaces
            .iter()
            .filter(|w| within.contains(&w.id))
            .filter_map(|w| self.effective(user, w.id).map(|a| (w, a)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn user(n: u128, superuser: bool, groups: &[&str]) -> User {
        User {
            id: id(n),
            name: format!("user-{n}"),
            method: if groups.is_empty() {
                Method::Local
            } else {
                Method::Oidc
            },
            superuser,
            disabled: false,
            groups: groups.iter().map(|g| g.to_string()).collect(),
            last_sign_in: None,
        }
    }

    /// Two workspaces, 100 and 200, and:
    /// - 1: a superuser;
    /// - 2: a direct admin of 100;
    /// - 3: a direct viewer of 100, also in `devs`, who are editors of 100;
    /// - 4: nothing at all;
    /// - 5: a direct viewer of 200, disabled.
    fn rows() -> Rows {
        let mut disabled = user(5, false, &[]);
        disabled.disabled = true;
        Rows {
            users: vec![
                user(1, true, &[]),
                user(2, false, &[]),
                user(3, false, &["devs"]),
                user(4, false, &[]),
                disabled,
            ],
            workspaces: vec![
                Workspace {
                    id: id(100),
                    name: "payments".into(),
                },
                Workspace {
                    id: id(200),
                    name: "storefront".into(),
                },
            ],
            grants: vec![
                Grant {
                    user: id(2),
                    workspace: id(100),
                    role: Role::Admin,
                },
                Grant {
                    user: id(3),
                    workspace: id(100),
                    role: Role::Viewer,
                },
                Grant {
                    user: id(5),
                    workspace: id(200),
                    role: Role::Viewer,
                },
            ],
            group_grants: vec![GroupGrant {
                group: "devs".into(),
                workspace: id(100),
                role: Role::Editor,
            }],
        }
    }

    #[test]
    fn the_highest_grant_wins_and_every_source_is_named() {
        let rows = rows();
        assert_eq!(
            rows.effective(&rows.users[2], id(100)),
            Some(Access {
                role: Role::Editor,
                sources: vec![Source::Direct, Source::Group("devs".into())],
            })
        );
    }

    #[test]
    fn a_superuser_is_admin_in_every_workspace() {
        let rows = rows();
        for workspace in [id(100), id(200)] {
            assert_eq!(
                rows.effective(&rows.users[0], workspace),
                Some(Access {
                    role: Role::Admin,
                    sources: vec![Source::Superuser]
                })
            );
        }
    }

    #[test]
    fn nothing_granted_is_nothing_held_and_a_disabled_account_holds_nothing() {
        let rows = rows();
        assert_eq!(rows.effective(&rows.users[3], id(100)), None);
        assert_eq!(rows.effective(&rows.users[4], id(200)), None);
    }

    #[test]
    fn grantable_is_where_the_caller_is_admin() {
        let rows = rows();
        assert_eq!(rows.grantable(&rows.users[0]), [id(100), id(200)].into());
        assert_eq!(rows.grantable(&rows.users[1]), [id(100)].into());
        assert!(
            rows.grantable(&rows.users[2]).is_empty(),
            "an editor grants nothing"
        );
    }

    #[test]
    fn waiting_is_enabled_with_no_role_anywhere() {
        let rows = rows();
        assert!(rows.waiting(&rows.users[3]));
        assert!(!rows.waiting(&rows.users[2]));
        assert!(!rows.waiting(&rows.users[0]), "a superuser never waits");
        assert!(!rows.waiting(&rows.users[4]), "disabled is its own status");
    }

    #[test]
    fn access_in_returns_nothing_outside_the_workspaces_it_is_given() {
        let rows = rows();
        let within = rows.grantable(&rows.users[1]);
        let seen: Vec<&str> = rows
            .access_in(&rows.users[0], &within)
            .iter()
            .map(|(w, _)| w.name.as_str())
            .collect();
        assert_eq!(
            seen,
            ["payments"],
            "storefront is outside what user 2 administers"
        );
    }
}
