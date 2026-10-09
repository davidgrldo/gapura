//! The console's writes to who holds what: direct grants and group mappings.
//!
//! Each write is one transaction that does three things in order:
//!
//! 1. It reads again, `FOR SHARE`, everything the caller's right to make it rests on: their own
//!    row, the workspaces concerned, their direct grants there, and the group mappings there
//!    that their groups match. A change to any of those that another transaction has made but
//!    not committed makes this one wait; one that has been committed is what it reads. A row
//!    another transaction has inserted, or moved into the caller's set, but not yet committed is
//!    not seen, because there is nothing to wait for on a row that is not yet visible. Nothing
//!    subtracts from a role, so a grant the write does not see can only make it refuse, never
//!    allow it. Then it decides with `grants::authorise`, the function the handler already asked
//!    over the rows it read before the transaction began. This decision is the one that counts.
//! 2. It reads the binding it changes `FOR UPDATE`, and inserts, updates or deletes it.
//! 3. It writes one `audit_log` row for each binding that changed.
//!
//! So a demotion of the caller and the caller's own write are ordered by Postgres rather than
//! interleaved: whichever commits first wins, and the other sees its result.

use super::Store;
use crate::access::{Grant, GroupGrant, Method, Role, Rows, User, Workspace};
use crate::grants::{self, Change, Refusal, RoleChanges};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use tokio_postgres::error::SqlState;
use tokio_postgres::Transaction;
use uuid::Uuid;

/// Why a write did not happen. Either way, nothing was written.
#[derive(Debug)]
pub enum WriteError {
    /// The rules refused it, deciding inside the transaction.
    Refused(Refusal),
    /// One field of the request was refused, deciding inside the transaction because the
    /// decision needs what is stored: a password change's current password is checked against
    /// the hash. Answered as a refused field, beside which the console shows it.
    Field(crate::configuration::FieldError),
    /// The store could not be read or written.
    Store(anyhow::Error),
    /// Too many password checks and hashes were already waiting, so the one this write needed
    /// was not made. Says nothing about the request; it may simply be tried again.
    Busy,
}

impl From<Refusal> for WriteError {
    fn from(refusal: Refusal) -> Self {
        WriteError::Refused(refusal)
    }
}

impl From<tokio_postgres::Error> for WriteError {
    fn from(error: tokio_postgres::Error) -> Self {
        WriteError::Store(error.into())
    }
}

impl From<deadpool_postgres::PoolError> for WriteError {
    fn from(error: deadpool_postgres::PoolError) -> Self {
        WriteError::Store(error.into())
    }
}

/// How many times a write is tried in all before its error is the answer.
const ATTEMPTS: u32 = 3;

/// Runs `attempt` again when Postgres aborted it for a reason that running it again settles.
///
/// - A deadlock. Each write share-locks the grants its caller's right rests on, then
///   update-locks the binding it changes, so two admins demoting each other at the same moment
///   each hold what the other is waiting for. Two saves of one change to the caller's own grant
///   meet the same way. Postgres aborts one. Run again, it reads what the other committed: a
///   caller demoted meanwhile is refused, which is the ordering the rules promise, not an
///   outage.
/// - A unique violation. Two writes gave one account a grant in one workspace, or made one
///   mapping, when neither existed yet, and the second insert lost. Run again, it reads the
///   first one's row as what it is changing, and its audit entry says so. Renaming a service or
///   route meets the same way when another write takes the new name at the same moment: run
///   again, the rename sees the name taken and is refused as a conflict. Issuing an API key
///   meets it when the new key's prefix is one already stored: run again, it draws another key.
pub(super) async fn retrying<T, F, Fut>(mut attempt: F) -> Result<T, WriteError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, WriteError>>,
{
    let mut tried = 1;
    loop {
        match attempt().await {
            Err(WriteError::Store(error)) if tried < ATTEMPTS && settled_by_retrying(&error) => {
                // A database error's own text is only "db error", with the reason behind it as
                // its source, so the log names both the chain and the SQLSTATE, which tells a
                // deadlock from a duplicate at a glance.
                tracing::info!(
                    error = format!("{error:#}"),
                    sqlstate = sqlstate(&error).map(SqlState::code),
                    "a write met another at the same moment; trying it again"
                );
                tried += 1;
            }
            done => return done,
        }
    }
}

/// The SQLSTATE Postgres answered with, when `error` is one it answered. The handlers log it
/// beside the error, and `grants_api` words its answer by it.
pub(crate) fn sqlstate(error: &anyhow::Error) -> Option<&SqlState> {
    error
        .downcast_ref::<tokio_postgres::Error>()
        .and_then(tokio_postgres::Error::code)
}

fn settled_by_retrying(error: &anyhow::Error) -> bool {
    sqlstate(error).is_some_and(|code| {
        *code == SqlState::T_R_DEADLOCK_DETECTED || *code == SqlState::UNIQUE_VIOLATION
    })
}

/// Whether an enabled account other than a superuser is an admin of the workspace `$1`,
/// directly or through a group it signed in with last.
const AN_ADMIN_IS_LEFT: &str = "select exists (
    select 1 from users u
     where u.disabled_at is null and not u.superuser
       and (exists (select 1 from role_bindings b
                     where b.user_id = u.id and b.workspace_id = $1 and b.role = 'admin')
            or exists (select 1 from group_bindings g
                        where g.workspace_id = $1 and g.role = 'admin'
                          and g.group_name = any(u.oidc_groups))))";

/// Step 4, for a caller who is not a superuser: refuse a write that leaves any workspace it
/// touched with no admin. Only a superuser could give that workspace one back, and the caller,
/// who was an admin there a moment ago, is the one person who certainly did not mean to need
/// that. The console warns before such a save; this is the rule, for a save from a stale tab or
/// from curl. A superuser is trusted to leave a workspace to superusers, and is not counted as
/// its admin, or the bootstrap account would make this never refuse.
///
/// Two admins demoting themselves at once would each still see the other and both commit. The
/// lock orders them: the second waits for the first to finish, then counts what it committed.
/// It is taken after the changes and in workspace order, and nothing else takes it, so it
/// cannot close a cycle with the row locks above.
async fn keeps_an_admin<'a>(
    tx: &Transaction<'_>,
    actor: &User,
    workspaces: impl IntoIterator<Item = &'a Uuid>,
) -> Result<(), WriteError> {
    if actor.superuser {
        return Ok(());
    }
    for workspace in workspaces {
        tx.execute(
            "select pg_advisory_xact_lock(hashtextextended(($1::uuid)::text, 0))",
            &[workspace],
        )
        .await?;
        let left: bool = tx.query_one(AN_ADMIN_IS_LEFT, &[workspace]).await?.get(0);
        if !left {
            return Err(Refusal::Conflict(
                "This would leave the workspace with no admin, and only a superuser could \
                 give it one back. Make someone else an admin first."
                    .into(),
            )
            .into());
        }
    }
    Ok(())
}

/// The caller as their row stands inside the transaction, and the names of the workspaces the
/// write concerns, which the audit entries carry.
struct Authorised {
    actor: User,
    workspaces: BTreeMap<Uuid, String>,
}

/// What `caller`'s rights in `concerned` rest on, read again inside `tx` and locked `FOR SHARE`:
/// their own row, the workspaces, their direct grants there and the group mappings their groups
/// match. Each write decides over these with its own rule. A caller whose row is gone is refused
/// in the words a workspace outside their reach gets. It does not refuse a disabled caller:
/// `actor.disabled` is for the caller's rule to check, as `grants::authorise` and
/// `Rows::effective` do.
///
/// A workspace that does not exist is simply missing from what is read, so a rule sees it as one
/// the caller holds nothing in. Rows come back in a fixed order, so two writes that lock the same
/// rows take them the same way round.
pub(super) async fn rights(
    tx: &Transaction<'_>,
    caller: Uuid,
    concerned: &BTreeSet<Uuid>,
) -> Result<(User, Rows), WriteError> {
    // This bounds each wait for a lock, not the whole write: a write queued behind a transaction
    // that never ends answers with an error after ten seconds instead of holding its connection,
    // and the request, for as long as that one runs. A write that waits at several rows, or is
    // run again, can take longer than that in all.
    tx.batch_execute("set local lock_timeout = '10s'").await?;
    let Some(row) = tx
        .query_opt(
            "select id,
                    coalesce(username, display_name, oidc_subject) as name,
                    password_hash is not null as local,
                    superuser,
                    disabled_at is not null as disabled,
                    oidc_groups
               from users where id = $1 for share",
            &[&caller],
        )
        .await?
    else {
        return Err(Refusal::outside_your_workspaces().into());
    };
    let actor = User {
        id: row.get("id"),
        name: row.get("name"),
        method: if row.get::<_, bool>("local") {
            Method::Local
        } else {
            Method::Oidc
        },
        superuser: row.get("superuser"),
        disabled: row.get("disabled"),
        groups: row.get("oidc_groups"),
        last_sign_in: None,
        must_change_password: false,
        sessions_valid_after: None,
    };
    let ids: Vec<Uuid> = concerned.iter().copied().collect();
    let workspaces: Vec<Workspace> = tx
        .query(
            "select id, name from workspaces where id = any($1) order by id for share",
            &[&ids],
        )
        .await?
        .into_iter()
        .map(|r| Workspace {
            id: r.get("id"),
            name: r.get("name"),
        })
        .collect();
    // A role this binary does not know is left out, so it grants less, as `access_rows` does.
    let direct: Vec<Grant> = tx
        .query(
            "select workspace_id, role::text as role from role_bindings
              where user_id = $1 and workspace_id = any($2)
              order by workspace_id for share",
            &[&caller, &ids],
        )
        .await?
        .into_iter()
        .filter_map(|r| {
            Some(Grant {
                user: caller,
                workspace: r.get("workspace_id"),
                role: Role::parse(r.get::<_, &str>("role"))?,
            })
        })
        .collect();
    let mapped: Vec<GroupGrant> = tx
        .query(
            "select group_name, workspace_id, role::text as role from group_bindings
              where workspace_id = any($1) and group_name = any($2)
              order by group_name, workspace_id for share",
            &[&ids, &actor.groups],
        )
        .await?
        .into_iter()
        .filter_map(|r| {
            Some(GroupGrant {
                group: r.get("group_name"),
                workspace: r.get("workspace_id"),
                role: Role::parse(r.get::<_, &str>("role"))?,
            })
        })
        .collect();
    let rows = Rows {
        users: vec![actor.clone()],
        workspaces,
        grants: direct,
        group_grants: mapped,
    };
    Ok((actor, rows))
}

/// Step 1: read again, locked, what `caller`'s right to write in `concerned` rests on, with
/// `rights`, and decide with the function the handler used, `grants::authorise`.
///
/// A caller whose row is gone, or disabled since their session was read, administers nothing.
/// A workspace that does not exist is refused like one the caller does not administer.
async fn authorise_again(
    tx: &Transaction<'_>,
    caller: Uuid,
    concerned: &BTreeSet<Uuid>,
) -> Result<Authorised, WriteError> {
    let (actor, rows) = rights(tx, caller, concerned).await?;
    grants::authorise(&rows, &actor, concerned)?;
    Ok(Authorised {
        workspaces: rows
            .workspaces
            .into_iter()
            .map(|w| (w.id, w.name))
            .collect(),
        actor,
    })
}

/// The role a binding about to be changed holds. Unlike the reads that decide, which leave out
/// a role this binary does not know and so grant less, this one cannot guess, because it is
/// the `before` of an audit entry. It fails the write and says why, which can only happen
/// mid-way through a rolling upgrade that adds a role.
fn known(name: &str) -> Result<Role, WriteError> {
    Role::parse(name).ok_or_else(|| {
        WriteError::Store(anyhow::anyhow!(
            "a binding holds the role {name:?}, which this binary does not know"
        ))
    })
}

/// One `audit_log` row.
pub(super) struct Entry {
    pub(super) action: &'static str,
    pub(super) object_kind: &'static str,
    pub(super) object_id: Option<Uuid>,
    pub(super) workspace: Option<Uuid>,
    pub(super) before: Option<serde_json::Value>,
    pub(super) after: Option<serde_json::Value>,
}

/// Step 3: the audit entry for one binding that changed, naming who changed it and how they
/// signed in. In store mode an account signs in one way only, so its method is the session's.
pub(super) async fn audit(
    tx: &Transaction<'_>,
    actor: &User,
    entry: Entry,
) -> Result<(), WriteError> {
    tx.execute(
        "insert into audit_log (actor_user_id, actor_name, actor_method, action, object_kind,
                                object_id, workspace_id, before, after)
         values ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        &[
            &actor.id,
            &actor.name,
            &actor.method.as_str(),
            &entry.action,
            &entry.object_kind,
            &entry.object_id,
            &entry.workspace,
            &entry.before,
            &entry.after,
        ],
    )
    .await?;
    Ok(())
}

impl Store {
    /// Gives, changes and removes `target`'s direct grants as `wanted` says, as `caller`. All of
    /// it, or, refused, none of it.
    pub async fn set_direct_roles(
        &self,
        caller: Uuid,
        target: Uuid,
        wanted: &RoleChanges,
    ) -> Result<(), WriteError> {
        retrying(move || self.try_set_direct_roles(caller, target, wanted)).await
    }

    async fn try_set_direct_roles(
        &self,
        caller: Uuid,
        target: Uuid,
        wanted: &RoleChanges,
    ) -> Result<(), WriteError> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let concerned: BTreeSet<Uuid> = wanted.keys().copied().collect();
        let allowed = authorise_again(&tx, caller, &concerned).await?;
        // Only now, so a refused request says nothing about whether the account exists.
        if tx
            .query_opt(
                "select 1 from users where id = $1 for key share",
                &[&target],
            )
            .await?
            .is_none()
        {
            return Err(Refusal::NotFound("There is no such account.".into()).into());
        }
        let ids: Vec<Uuid> = concerned.into_iter().collect();
        let mut held = BTreeMap::new();
        for row in tx
            .query(
                "select workspace_id, role::text as role from role_bindings
                  where user_id = $1 and workspace_id = any($2)
                  order by workspace_id for update",
                &[&target, &ids],
            )
            .await?
        {
            held.insert(row.get::<_, Uuid>("workspace_id"), known(row.get("role"))?);
        }
        for (workspace, change) in grants::direct_changes(&held, wanted) {
            match change.after {
                Some(role) if change.before.is_some() => {
                    tx.execute(
                        "update role_bindings set role = $3::text::role_name
                          where user_id = $1 and workspace_id = $2",
                        &[&target, &workspace, &role.as_str()],
                    )
                    .await?
                }
                Some(role) => {
                    tx.execute(
                        "insert into role_bindings (user_id, workspace_id, role)
                         values ($1, $2, $3::text::role_name)",
                        &[&target, &workspace, &role.as_str()],
                    )
                    .await?
                }
                None => {
                    tx.execute(
                        "delete from role_bindings where user_id = $1 and workspace_id = $2",
                        &[&target, &workspace],
                    )
                    .await?
                }
            };
            // Present: `authorise_again` refuses any workspace it did not read.
            let name = &allowed.workspaces[&workspace];
            audit(
                &tx,
                &allowed.actor,
                Entry {
                    action: "update",
                    object_kind: "user",
                    object_id: Some(target),
                    workspace: Some(workspace),
                    before: Some(grants::direct_audit(name, change.before)),
                    after: Some(grants::direct_audit(name, change.after)),
                },
            )
            .await?;
        }
        keeps_an_admin(&tx, &allowed.actor, allowed.workspaces.keys()).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Maps `group` to `role` in `workspace`, creating the mapping or changing its role, as
    /// `caller`. Putting the role it already has writes nothing.
    pub async fn put_group_mapping(
        &self,
        caller: Uuid,
        workspace: Uuid,
        group: &str,
        role: Role,
    ) -> Result<(), WriteError> {
        retrying(move || self.try_write_group_mapping(caller, workspace, group, Some(role))).await
    }

    /// Removes the mapping of `group` in `workspace`, as `caller`.
    pub async fn delete_group_mapping(
        &self,
        caller: Uuid,
        workspace: Uuid,
        group: &str,
    ) -> Result<(), WriteError> {
        retrying(move || self.try_write_group_mapping(caller, workspace, group, None)).await
    }

    /// Both of the above: `Some` puts the mapping at that role, `None` removes it.
    async fn try_write_group_mapping(
        &self,
        caller: Uuid,
        workspace: Uuid,
        group: &str,
        after: Option<Role>,
    ) -> Result<(), WriteError> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let allowed = authorise_again(&tx, caller, &BTreeSet::from([workspace])).await?;
        let before = match tx
            .query_opt(
                "select role::text as role from group_bindings
                  where group_name = $1 and workspace_id = $2 for update",
                &[&group, &workspace],
            )
            .await?
        {
            Some(row) => Some(known(row.get("role"))?),
            None => None,
        };
        if before.is_none() && after.is_none() {
            return Err(Refusal::NotFound("There is no such group mapping.".into()).into());
        }
        let Some(change) = Change::between(before, after) else {
            // The role it already has: nothing to write, and nothing to record.
            return Ok(());
        };
        match (change.before, change.after) {
            (None, Some(role)) => {
                tx.execute(
                    "insert into group_bindings (group_name, workspace_id, role)
                     values ($1, $2, $3::text::role_name)",
                    &[&group, &workspace, &role.as_str()],
                )
                .await?
            }
            (Some(_), Some(role)) => {
                tx.execute(
                    "update group_bindings set role = $3::text::role_name
                      where group_name = $1 and workspace_id = $2",
                    &[&group, &workspace, &role.as_str()],
                )
                .await?
            }
            (_, None) => {
                tx.execute(
                    "delete from group_bindings where group_name = $1 and workspace_id = $2",
                    &[&group, &workspace],
                )
                .await?
            }
        };
        // Present: `authorise_again` refuses any workspace it did not read.
        let name = &allowed.workspaces[&workspace];
        audit(
            &tx,
            &allowed.actor,
            Entry {
                action: change.mapping_action(),
                object_kind: "group_mapping",
                object_id: None,
                workspace: Some(workspace),
                before: grants::mapping_audit(group, name, change.before),
                after: grants::mapping_audit(group, name, change.after),
            },
        )
        .await?;
        keeps_an_admin(&tx, &allowed.actor, [&workspace]).await?;
        tx.commit().await?;
        Ok(())
    }
}
