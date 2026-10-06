//! The rules for changing who holds what, as pure functions over the rows `access` reads.
//!
//! A workspace admin gives, changes and removes direct grants in the workspaces they
//! administer, and the group mappings that point at them, up to and including admin; a
//! superuser does the same everywhere. A request that names one workspace outside that set
//! changes nothing. A workspace that does not exist is refused in the same words, so a request
//! cannot be used to learn which ids exist.
//!
//! The handlers ask these first, over the rows they already read, which is only a way to refuse
//! cheaply. The store asks them again inside the transaction that writes, over rows it has
//! locked, and that answer is the one that counts. Kept apart from both so every rule is tested
//! without a database.

use crate::access::{Role, Rows, User};
use axum::http::StatusCode;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

/// The longest group name a mapping may hold, in characters. Identity providers send paths such
/// as `/engineering/platform/on-call`; 256 leaves room for those and still refuses an essay.
pub const MAX_GROUP_CHARS: usize = 256;

/// A change to one account's direct grants: by workspace, the role to hold there, or `None`
/// for none.
pub type RoleChanges = BTreeMap<Uuid, Option<Role>>;

/// Why a write was refused. Each carries the sentence the console shows as it is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The request is malformed. Who sent it was never considered.
    Invalid(String),
    /// The caller may not make this change, or named a workspace that does not exist.
    Forbidden(String),
    /// The account or the mapping the request names does not exist. Only ever said after the
    /// caller was found to administer the workspaces concerned, so a refused request says
    /// nothing about what exists.
    NotFound(String),
}

impl Refusal {
    /// The status the API answers with.
    pub fn status(&self) -> StatusCode {
        match self {
            Refusal::Invalid(_) => StatusCode::BAD_REQUEST,
            Refusal::Forbidden(_) => StatusCode::FORBIDDEN,
            Refusal::NotFound(_) => StatusCode::NOT_FOUND,
        }
    }

    /// The sentence the console shows.
    pub fn sentence(&self) -> &str {
        match self {
            Refusal::Invalid(s) | Refusal::Forbidden(s) | Refusal::NotFound(s) => s,
        }
    }

    /// The one answer for a workspace the caller does not administer and for one that does not
    /// exist.
    pub fn outside_your_workspaces() -> Refusal {
        Refusal::Forbidden(
            "You can only change roles in workspaces you administer, so nothing was changed."
                .into(),
        )
    }
}

/// Whether `caller` may change grants and mappings in every one of `workspaces`, decided over
/// `rows`.
///
/// The set is `access`'s own `grantable`, so the rule for who may grant is the rule for who may
/// see, written once. A workspace missing from `rows` is in nobody's grantable set, which is
/// what makes an unknown id read exactly like a forbidden one. An empty request asks for
/// nothing, and is allowed, except to a disabled caller: that refusal comes first, so even a
/// request that names no workspace learns nothing from a disabled account.
pub fn authorise(rows: &Rows, caller: &User, workspaces: &BTreeSet<Uuid>) -> Result<(), Refusal> {
    if caller.disabled {
        return Err(Refusal::outside_your_workspaces());
    }
    let grantable = rows.grantable(caller);
    if workspaces.is_subset(&grantable) {
        Ok(())
    } else {
        Err(Refusal::outside_your_workspaces())
    }
}

/// One binding before and after a write, where the two differ. `None` is no binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Change {
    pub before: Option<Role>,
    pub after: Option<Role>,
}

impl Change {
    /// The change from `before` to `after`, or `None` when they are the same. Asking for the
    /// value already held writes nothing, so it leaves no audit entry saying something happened.
    pub fn between(before: Option<Role>, after: Option<Role>) -> Option<Change> {
        (before != after).then_some(Change { before, after })
    }

    /// The audit action for a group mapping: created, changed or removed. A direct grant is
    /// always recorded as an update to its account, whichever of the three it is.
    pub fn mapping_action(&self) -> &'static str {
        match (self.before, self.after) {
            (None, _) => "create",
            (_, None) => "delete",
            _ => "update",
        }
    }
}

/// The direct-grant changes `wanted` makes to an account holding `held`, in workspace-id order,
/// the order the store locks rows in. A
/// workspace where the account already holds what is asked for is left out.
pub fn direct_changes(held: &BTreeMap<Uuid, Role>, wanted: &RoleChanges) -> Vec<(Uuid, Change)> {
    wanted
        .iter()
        .filter_map(|(workspace, after)| {
            Change::between(held.get(workspace).copied(), *after).map(|change| (*workspace, change))
        })
        .collect()
}

/// A direct grant as an audit entry records it. Always an object, with `role` null on the side
/// where the account held, or will hold, nothing in that workspace.
pub fn direct_audit(workspace: &str, role: Option<Role>) -> serde_json::Value {
    serde_json::json!({ "workspace": workspace, "role": role })
}

/// A group mapping as an audit entry records it, or nothing on the side where it does not
/// exist.
pub fn mapping_audit(
    group: &str,
    workspace: &str,
    role: Option<Role>,
) -> Option<serde_json::Value> {
    role.map(|role| serde_json::json!({ "group": group, "workspace": workspace, "role": role }))
}

/// Whether `name` may be a mapping's group.
///
/// It is compared with the groups claim exactly, so it is never trimmed or folded. What it
/// refuses is a name no identity provider sends, which would only look like one on screen:
/// nothing at all, more than `MAX_GROUP_CHARS`, a control character, a character that draws
/// nothing or turns the text around it, or space at either end. Spaces inside are allowed,
/// because Keycloak and Azure send group names that contain them.
pub fn check_group_name(name: &str) -> Result<(), String> {
    let chars = name.chars().count();
    if chars == 0 {
        return Err("A group name cannot be empty.".into());
    }
    if chars > MAX_GROUP_CHARS {
        return Err(format!(
            "A group name is at most {MAX_GROUP_CHARS} characters; this one has {chars}."
        ));
    }
    if name.chars().any(char::is_control) {
        return Err("A group name cannot contain control characters.".into());
    }
    if name.chars().any(invisible) {
        return Err(
            "A group name cannot contain characters that show nothing or reverse the text \
             around them."
                .into(),
        );
    }
    if name.starts_with(char::is_whitespace) || name.ends_with(char::is_whitespace) {
        return Err(
            "A group name cannot start or end with a space: it has to equal the groups claim \
             exactly."
                .into(),
        );
    }
    Ok(())
}

/// Characters `char::is_control` lets through that still make a name look, on screen and in the
/// audit trail, like another: zero-width and formatting characters, which draw nothing, and the
/// bidirectional controls, which reorder the text around them.
fn invisible(c: char) -> bool {
    matches!(
        c,
        '\u{AD}'
            | '\u{61C}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
    )
}

/// The group of a mapping to remove. It is not held to `check_group_name`, so a mapping made by
/// hand, or before those rules, stays removable; it is refused only where it could never name a
/// stored mapping: empty, or holding NUL, which Postgres cannot keep in `text` and would answer
/// with an error that reads like an outage.
pub fn group_to_remove(name: &str) -> Result<(), Refusal> {
    if name.is_empty() || name.contains('\0') {
        return Err(Refusal::Invalid(
            "Name the group of the mapping to remove.".into(),
        ));
    }
    Ok(())
}

/// A workspace id from a request.
pub fn workspace_id(text: &str) -> Result<Uuid, Refusal> {
    text.parse()
        .map_err(|_| Refusal::Invalid(format!("{text:?} is not a workspace id.")))
}

/// A role from a request, in the store's spelling.
fn role_named(name: &str) -> Result<Role, Refusal> {
    Role::parse(name).ok_or_else(|| {
        Refusal::Invalid(format!(
            "{name:?} is not a role: a role is viewer, editor or admin."
        ))
    })
}

/// The direct grants a `PATCH /api/users/{id}/roles` body asks for: an object of workspace ids,
/// each with a role name or `null` for none. Only the workspaces it names change.
///
/// Two spellings of one id, say upper and lower case, are refused rather than one silently
/// winning. The same key written twice is not seen here: the JSON reader keeps its last value.
pub fn parse_role_changes(body: &[u8]) -> Result<RoleChanges, Refusal> {
    let object: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(body).map_err(|_| {
            Refusal::Invalid(
                "Send a JSON object of workspace ids, each with a role or null.".into(),
            )
        })?;
    let mut changes = RoleChanges::new();
    for (key, value) in object {
        let workspace = workspace_id(&key)?;
        let role = match value {
            serde_json::Value::Null => None,
            serde_json::Value::String(name) => Some(role_named(&name)?),
            _ => {
                return Err(Refusal::Invalid(format!(
                    "The role for workspace {workspace} must be a role name or null."
                )))
            }
        };
        if changes.insert(workspace, role).is_some() {
            return Err(Refusal::Invalid(format!(
                "The request names workspace {workspace} twice."
            )));
        }
    }
    Ok(changes)
}

/// A group mapping a `PUT /api/group-mappings` body asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupMapping {
    pub workspace: Uuid,
    pub group: String,
    pub role: Role,
}

/// The mapping a `PUT /api/group-mappings` body asks for: `workspace_id`, `group` and `role`,
/// and nothing else, so a misspelt field is refused rather than silently ignored.
pub fn parse_mapping(body: &[u8]) -> Result<GroupMapping, Refusal> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Body {
        workspace_id: String,
        group: String,
        role: String,
    }
    let body: Body = serde_json::from_slice(body).map_err(|_| {
        Refusal::Invalid("Send a JSON object with workspace_id, group and role.".into())
    })?;
    let workspace = workspace_id(&body.workspace_id)?;
    check_group_name(&body.group).map_err(Refusal::Invalid)?;
    let role = role_named(&body.role)?;
    Ok(GroupMapping {
        workspace,
        group: body.group,
        role,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::{Grant, GroupGrant, Method, Workspace};

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

    /// Workspaces 100 and 200, and:
    /// - 1: a superuser;
    /// - 2: a direct admin of 100, and a direct viewer of 200;
    /// - 3: an admin of 200 through the group `b-admins`, holding nothing directly.
    fn rows() -> Rows {
        Rows {
            users: vec![
                user(1, true, &[]),
                user(2, false, &[]),
                user(3, false, &["b-admins"]),
            ],
            workspaces: vec![
                Workspace {
                    id: id(100),
                    name: "a".into(),
                },
                Workspace {
                    id: id(200),
                    name: "b".into(),
                },
            ],
            grants: vec![
                Grant {
                    user: id(2),
                    workspace: id(100),
                    role: Role::Admin,
                },
                Grant {
                    user: id(2),
                    workspace: id(200),
                    role: Role::Viewer,
                },
            ],
            group_grants: vec![GroupGrant {
                group: "b-admins".into(),
                workspace: id(200),
                role: Role::Admin,
            }],
        }
    }

    fn set(ids: &[u128]) -> BTreeSet<Uuid> {
        ids.iter().map(|n| id(*n)).collect()
    }

    #[test]
    fn an_admin_changes_roles_where_they_administer_and_nowhere_else() {
        let rows = rows();
        let admin = &rows.users[1];
        assert_eq!(authorise(&rows, admin, &set(&[100])), Ok(()));
        assert_eq!(
            authorise(&rows, admin, &set(&[200])),
            Err(Refusal::outside_your_workspaces()),
            "a viewer of 200 grants nothing there"
        );
        assert_eq!(
            authorise(&rows, admin, &set(&[100, 200])),
            Err(Refusal::outside_your_workspaces()),
            "one workspace outside refuses the whole request"
        );
    }

    #[test]
    fn an_admin_through_a_group_grants_like_a_direct_one() {
        let rows = rows();
        let admin = &rows.users[2];
        assert_eq!(authorise(&rows, admin, &set(&[200])), Ok(()));
        assert_eq!(
            authorise(&rows, admin, &set(&[100])),
            Err(Refusal::outside_your_workspaces())
        );
    }

    #[test]
    fn a_superuser_changes_roles_anywhere() {
        let rows = rows();
        assert_eq!(authorise(&rows, &rows.users[0], &set(&[100, 200])), Ok(()));
    }

    #[test]
    fn an_unknown_workspace_is_refused_like_one_the_caller_cannot_reach() {
        let rows = rows();
        let unknown = authorise(&rows, &rows.users[0], &set(&[999]));
        assert_eq!(
            unknown,
            Err(Refusal::outside_your_workspaces()),
            "not even a superuser grants in a workspace that does not exist"
        );
        assert_eq!(
            unknown,
            authorise(&rows, &rows.users[1], &set(&[200])),
            "the two answers cannot be told apart"
        );
    }

    #[test]
    fn a_disabled_caller_changes_nothing() {
        let mut rows = rows();
        rows.users[0].disabled = true;
        assert_eq!(
            authorise(&rows, &rows.users[0], &set(&[100])),
            Err(Refusal::outside_your_workspaces())
        );
        assert_eq!(
            authorise(&rows, &rows.users[0], &set(&[])),
            Err(Refusal::outside_your_workspaces()),
            "not even a request that names no workspace"
        );
    }

    #[test]
    fn an_empty_request_is_allowed_to_anyone_enabled() {
        let rows = rows();
        assert_eq!(authorise(&rows, &rows.users[1], &set(&[])), Ok(()));
    }

    #[test]
    fn asking_for_what_is_already_held_changes_nothing() {
        let held = BTreeMap::from([(id(100), Role::Viewer), (id(200), Role::Admin)]);
        let wanted = BTreeMap::from([
            (id(100), Some(Role::Viewer)), // the same: skipped
            (id(200), None),               // removed
            (id(300), Some(Role::Editor)), // given
            (id(400), None),               // nothing there to remove: skipped
        ]);
        assert_eq!(
            direct_changes(&held, &wanted),
            [
                (
                    id(200),
                    Change {
                        before: Some(Role::Admin),
                        after: None
                    }
                ),
                (
                    id(300),
                    Change {
                        before: None,
                        after: Some(Role::Editor)
                    }
                ),
            ]
        );
        assert!(direct_changes(&held, &BTreeMap::new()).is_empty());
    }

    #[test]
    fn a_mapping_is_created_changed_or_removed() {
        let action = |before: Option<Role>, after: Option<Role>| {
            Change::between(before, after).map(|c| c.mapping_action())
        };
        assert_eq!(action(None, Some(Role::Viewer)), Some("create"));
        assert_eq!(
            action(Some(Role::Viewer), Some(Role::Admin)),
            Some("update")
        );
        assert_eq!(action(Some(Role::Admin), None), Some("delete"));
        assert_eq!(
            action(Some(Role::Admin), Some(Role::Admin)),
            None,
            "putting the role a mapping already has writes nothing"
        );
    }

    #[test]
    fn group_names_keep_their_inner_spaces_and_refuse_what_no_claim_sends() {
        let longest = "g".repeat(MAX_GROUP_CHARS);
        let too_long = "g".repeat(MAX_GROUP_CHARS + 1);
        // Two bytes each, so a check that counted bytes would refuse the first and the length
        // tests would still pass on ASCII alone.
        let longest_accented = "é".repeat(MAX_GROUP_CHARS);
        let too_long_accented = "é".repeat(MAX_GROUP_CHARS + 1);
        for good in [
            "/platform-team",
            "Platform Engineers",
            "a",
            longest.as_str(),
            longest_accented.as_str(),
        ] {
            assert_eq!(check_group_name(good), Ok(()), "{good:?}");
        }
        for bad in [
            "",
            too_long.as_str(),
            too_long_accented.as_str(),
            "ops\nadmins",
            "ops\u{0}",
            "ops\u{7f}",
            "ops\u{85}",
            " platform",
            "platform ",
            "\u{a0}platform",
            "platform-admins\u{200b}",
            "ops\u{202e}snimda",
            "\u{feff}ops",
            "ops\u{2028}admins",
        ] {
            assert!(check_group_name(bad).is_err(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn a_mapping_to_remove_needs_a_group_postgres_could_hold() {
        assert_eq!(group_to_remove(" made by hand "), Ok(()));
        for bad in ["", "ops\u{0}"] {
            assert!(
                matches!(group_to_remove(bad), Err(Refusal::Invalid(_))),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_role_change_names_workspaces_and_roles_or_null() {
        let body = format!(r#"{{"{}": "editor", "{}": null}}"#, id(100), id(200));
        assert_eq!(
            parse_role_changes(body.as_bytes()),
            Ok(BTreeMap::from([
                (id(100), Some(Role::Editor)),
                (id(200), None)
            ]))
        );
        assert_eq!(
            parse_role_changes(b"{}"),
            Ok(BTreeMap::new()),
            "no changes is a request that changes nothing"
        );
        for bad in [
            "not json".to_string(),
            "[]".to_string(),
            r#"{"payments": "editor"}"#.to_string(),
            format!(r#"{{"{}": "owner"}}"#, id(100)),
            format!(r#"{{"{}": 3}}"#, id(100)),
            // One workspace in two spellings: neither silently wins.
            format!(
                r#"{{"{}": "admin", "{}": "viewer"}}"#,
                id(0xabc),
                id(0xabc).to_string().to_uppercase()
            ),
        ] {
            assert!(
                matches!(parse_role_changes(bad.as_bytes()), Err(Refusal::Invalid(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_mapping_names_a_workspace_a_group_and_a_role_and_nothing_else() {
        let body = format!(
            r#"{{"workspace_id": "{}", "group": "/platform team", "role": "admin"}}"#,
            id(100)
        );
        assert_eq!(
            parse_mapping(body.as_bytes()),
            Ok(GroupMapping {
                workspace: id(100),
                group: "/platform team".into(),
                role: Role::Admin,
            })
        );
        for bad in [
            format!(
                r#"{{"workspace_id": "{}", "group": " lead", "role": "admin"}}"#,
                id(100)
            ),
            format!(
                r#"{{"workspace_id": "{}", "group": "lead", "role": "owner"}}"#,
                id(100)
            ),
            format!(r#"{{"workspace_id": "{}", "group": "lead"}}"#, id(100)),
            format!(
                r#"{{"workspace_id": "{}", "group": "lead", "role": "admin", "note": "x"}}"#,
                id(100)
            ),
            r#"{"workspace_id": "payments", "group": "lead", "role": "admin"}"#.to_string(),
        ] {
            assert!(
                matches!(parse_mapping(bad.as_bytes()), Err(Refusal::Invalid(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn audit_entries_have_the_shapes_the_trail_promises() {
        assert_eq!(
            direct_audit("payments", None),
            serde_json::json!({"workspace": "payments", "role": null})
        );
        assert_eq!(
            direct_audit("payments", Some(Role::Viewer)),
            serde_json::json!({"workspace": "payments", "role": "viewer"})
        );
        assert_eq!(
            mapping_audit("/platform", "payments", Some(Role::Editor)),
            Some(
                serde_json::json!({"group": "/platform", "workspace": "payments", "role": "editor"})
            )
        );
        assert_eq!(mapping_audit("/platform", "payments", None), None);
    }
}
