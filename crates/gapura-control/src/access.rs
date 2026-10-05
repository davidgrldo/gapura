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

/// Why someone holds a role in a workspace, and the role that one grant gives. Sources are
/// listed in this declaration order, and groups by name, which is the order a reader sees them
/// in.
///
/// Each carries its own role because the highest is not the only one that matters. The form
/// that edits an account's access holds its direct grant even where a group gives more, and
/// someone deciding what to remove needs to see what is left underneath.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Source {
    Superuser { role: Role },
    Direct { role: Role },
    Group { name: String, role: Role },
}

impl Source {
    /// The role this one grant gives, whatever the others give.
    pub fn role(&self) -> Role {
        match self {
            Source::Superuser { role } | Source::Direct { role } | Source::Group { role, .. } => {
                *role
            }
        }
    }
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
    /// The highest role `user` holds in `workspace`, and every grant that gives them a role there,
    /// whatever its level: a direct grant underneath a group's higher role is what an admin needs
    /// to see before removing either. Other people's roles reach a caller only through
    /// `access_in`, which keeps them inside the caller's `grantable` set.
    pub fn effective(&self, user: &User, workspace: Uuid) -> Option<Access> {
        if user.disabled {
            return None;
        }
        let mut sources: Vec<Source> = Vec::new();
        if user.superuser {
            sources.push(Source::Superuser { role: Role::Admin });
        }
        sources.extend(
            self.grants
                .iter()
                .filter(|g| g.user == user.id && g.workspace == workspace)
                .map(|g| Source::Direct { role: g.role }),
        );
        sources.extend(
            self.group_grants
                .iter()
                .filter(|g| g.workspace == workspace && user.groups.contains(&g.group))
                .map(|g| Source::Group {
                    name: g.group.clone(),
                    role: g.role,
                }),
        );
        let role = sources.iter().map(Source::role).max()?;
        // Each binding table's primary key keeps a grant from appearing twice, and a group named
        // twice in the claim still matches its one binding once, so rows read from the store
        // never repeat a source. The dedup guards rows built by hand.
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

    /// Enabled, not a superuser, and reaching nothing: the account exists, but nobody has granted
    /// it anything yet. Derived rather than stored, so a grant ends the wait by itself.
    pub fn waiting(&self, user: &User) -> bool {
        // `!user.superuser` is not redundant: with no workspaces at all, `all` over nothing is
        // true, and a superuser would read as waiting for access to a console they run.
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
    /// - 2: a direct admin of 100, also in `readers`, who are viewers of 100;
    /// - 3: a direct viewer of 100, also in `devs` (editors of 100) and `auditors` (viewers of
    ///   100), listed after `devs` so that the sources' order has to be sorted, not inherited;
    /// - 4: nothing at all;
    /// - 5: a direct viewer of 200, disabled.
    fn rows() -> Rows {
        let mut disabled = user(5, false, &[]);
        disabled.disabled = true;
        Rows {
            users: vec![
                user(1, true, &[]),
                user(2, false, &["readers"]),
                user(3, false, &["devs", "auditors"]),
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
            group_grants: vec![
                GroupGrant {
                    group: "devs".into(),
                    workspace: id(100),
                    role: Role::Editor,
                },
                GroupGrant {
                    group: "readers".into(),
                    workspace: id(100),
                    role: Role::Viewer,
                },
                GroupGrant {
                    group: "auditors".into(),
                    workspace: id(100),
                    role: Role::Viewer,
                },
            ],
        }
    }

    #[test]
    fn the_highest_grant_wins_and_every_source_is_named() {
        let rows = rows();
        assert_eq!(
            rows.effective(&rows.users[2], id(100)),
            Some(Access {
                role: Role::Editor,
                // The direct grant keeps its own role underneath the group's higher one.
                sources: vec![
                    Source::Direct { role: Role::Viewer },
                    Source::Group {
                        name: "auditors".into(),
                        role: Role::Viewer
                    },
                    Source::Group {
                        name: "devs".into(),
                        role: Role::Editor
                    },
                ],
            })
        );
        // A group's role stays in its own workspace.
        assert_eq!(
            rows.effective(&rows.users[2], id(200)),
            None,
            "devs and auditors hold roles in payments only"
        );
        // And a direct grant above a group's keeps the group's lower role beneath it.
        assert_eq!(
            rows.effective(&rows.users[1], id(100)),
            Some(Access {
                role: Role::Admin,
                sources: vec![
                    Source::Direct { role: Role::Admin },
                    Source::Group {
                        name: "readers".into(),
                        role: Role::Viewer
                    },
                ],
            })
        );
    }

    #[test]
    fn a_superuser_with_a_direct_grant_lists_both_superuser_first() {
        let mut rows = rows();
        rows.grants.push(Grant {
            user: rows.users[0].id,
            workspace: id(100),
            role: Role::Viewer,
        });
        assert_eq!(
            rows.effective(&rows.users[0], id(100)),
            Some(Access {
                role: Role::Admin,
                sources: vec![
                    Source::Superuser { role: Role::Admin },
                    Source::Direct { role: Role::Viewer },
                ],
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
                    sources: vec![Source::Superuser { role: Role::Admin }]
                })
            );
        }
    }

    #[test]
    fn nothing_granted_is_nothing_held_and_a_disabled_account_holds_nothing() {
        let rows = rows();
        assert_eq!(rows.effective(&rows.users[3], id(100)), None);
        assert_eq!(rows.effective(&rows.users[4], id(200)), None);
        let mut fallen = rows.users[0].clone();
        fallen.disabled = true;
        assert_eq!(
            rows.effective(&fallen, id(100)),
            None,
            "a disabled superuser holds nothing"
        );
        assert!(rows.grantable(&fallen).is_empty());
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
        let no_workspaces = Rows {
            users: rows.users.clone(),
            ..Rows::default()
        };
        assert!(
            !no_workspaces.waiting(&rows.users[0]),
            "a superuser does not wait, even with no workspaces"
        );
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

    #[test]
    fn every_source_says_the_role_it_gives_in_the_shape_the_console_reads() {
        let shapes = [
            (
                Source::Superuser { role: Role::Admin },
                serde_json::json!({"kind": "superuser", "role": "admin"}),
            ),
            (
                Source::Direct { role: Role::Viewer },
                serde_json::json!({"kind": "direct", "role": "viewer"}),
            ),
            (
                Source::Group {
                    name: "/platform".into(),
                    role: Role::Admin,
                },
                serde_json::json!({"kind": "group", "name": "/platform", "role": "admin"}),
            ),
        ];
        for (source, shape) in shapes {
            assert_eq!(serde_json::to_value(&source).unwrap(), shape);
        }
    }
}
