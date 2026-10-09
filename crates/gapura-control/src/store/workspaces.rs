//! Workspaces as a superuser creates, renames and deletes them.
//!
//! Each write is one transaction, with one audit row that concerns no workspace (its object is
//! one), and takes its locks in one order:
//!
//! 1. the caller, read again by `rights` (`FOR SHARE`) and decided by `workspaces::may_write`;
//! 2. on a delete, the advisory lock that deletes take one at a time;
//! 3. on a rename or a delete, the workspace `FOR UPDATE`;
//! 4. the write; on a rename, `config_state`; the audit row.
//!
//! Every write to what a workspace holds (services, routes, consumers, policies, grants and
//! mappings) reads that workspace `FOR SHARE` through `rights` before it writes anything there.
//! So under a delete's `FOR UPDATE` none of them can add a row to the workspace: one that got its
//! share first finishes first, and the delete's counts, read by statements that begin only once
//! its lock is granted, see what it committed; one that comes after waits, then finds the
//! workspace gone and is refused. The emptiness the delete decides on is the emptiness it
//! deletes. Nothing in this binary writes certificates; one written by hand meanwhile would go
//! with the workspace, as anything it holds goes by `on delete cascade`.
//!
//! The last workspace is kept by the advisory lock rather than by locking every workspace row,
//! which would hold up writes into every other workspace for as long as a delete runs. Deletes
//! take it one at a time, and only they make fewer workspaces, so the count a delete reads after
//! taking it cannot fall before it commits: two deleting the last two at once queue there, and the
//! second, once the first has committed, counts one. A create meanwhile is not held up, and can
//! only make one more.
//!
//! The writes into a workspace update-lock no workspace, so they and a delete or rename queue at
//! the workspace's row rather than cross; nothing else takes the advisory lock. The caller's row
//! comes first here, unlike in the accounts' writes, because nothing that holds a workspace's row
//! waits for a user's row `FOR UPDATE`: the accounts' writes, which take users that way, lock no
//! workspace.

use super::configuration::updated_at;
use super::grants::{audit, retrying, rights, Entry};
use super::{Store, WriteError};
use crate::access::User;
use crate::grants::Refusal;
use crate::workspaces::{self, Contents, WorkspaceView};
use anyhow::Result;
use std::collections::BTreeSet;
use tokio_postgres::Transaction;
use uuid::Uuid;

/// Step 1 of every write: the caller read again inside `tx`, locked, and refused unless they may
/// change workspaces.
async fn decide(tx: &Transaction<'_>, caller: Uuid) -> Result<User, WriteError> {
    let actor = match rights(tx, caller, &BTreeSet::new()).await {
        Ok((actor, _)) => actor,
        // `rights` words a caller whose row is gone for a change to roles; deleted by a superuser
        // since their session was read, they are told so instead.
        Err(WriteError::Refused(r)) if r == Refusal::outside_your_workspaces() => {
            return Err(Refusal::Forbidden("Your account no longer exists.".into()).into())
        }
        Err(e) => return Err(e),
    };
    workspaces::may_write(&actor)?;
    Ok(actor)
}

/// The advisory lock deletes take one at a time: see the module's comment.
const DELETES_LOCK: &str = "select pg_advisory_xact_lock(hashtext('gapura workspace delete'))";

fn no_such(name: &str) -> WriteError {
    Refusal::NotFound(format!("There is no workspace named {name}.")).into()
}

/// An audit entry about the workspace `id`.
fn entry(
    action: &'static str,
    id: Uuid,
    before: Option<serde_json::Value>,
    after: Option<serde_json::Value>,
) -> Entry {
    Entry {
        action,
        object_kind: "workspace",
        object_id: Some(id),
        workspace: None,
        before,
        after,
    }
}

/// What the workspace `w.id` holds, as the columns of a query over `workspaces w`.
const CONTENTS: &str = "(select count(*) from services where workspace_id = w.id) as services,
     (select count(*) from routes where workspace_id = w.id) as routes,
     (select count(*) from consumers where workspace_id = w.id) as consumers,
     (select count(*) from plugins where workspace_id = w.id) as policies,
     (select count(*) from certificates where workspace_id = w.id) as certificates";

fn contents(row: &tokio_postgres::Row) -> Contents {
    Contents {
        services: row.get("services"),
        routes: row.get("routes"),
        consumers: row.get("consumers"),
        policies: row.get("policies"),
        certificates: row.get("certificates"),
    }
}

impl Store {
    /// The workspaces by name, every one when `only` is `None`, with what each holds and how many
    /// grants and mappings reach into it.
    pub async fn workspaces(&self, only: Option<&BTreeSet<Uuid>>) -> Result<Vec<WorkspaceView>> {
        let only: Option<Vec<Uuid>> = only.map(|ids| ids.iter().copied().collect());
        let client = self.pool.get().await?;
        let rows = client
            .query(
                &format!(
                    "select w.name, {} as created_at, {CONTENTS},
                            (select count(*) from role_bindings where workspace_id = w.id)
                          + (select count(*) from group_bindings where workspace_id = w.id)
                            as members
                       from workspaces w
                      where $1::uuid[] is null or w.id = any($1)
                      order by w.name collate \"C\"",
                    updated_at("w.created_at"),
                ),
                &[&only],
            )
            .await?;
        Ok(rows
            .iter()
            .map(|row| WorkspaceView {
                name: row.get("name"),
                created_at: row.get("created_at"),
                contents: contents(row),
                members: row.get("members"),
            })
            .collect())
    }

    /// Creates an empty workspace called `name`, which the handler has checked with
    /// `workspaces::name`, as `caller`, who must be a superuser. Nobody but superusers holds a
    /// role there until one is granted.
    pub async fn create_workspace(&self, caller: Uuid, name: &str) -> Result<(), WriteError> {
        retrying(move || self.try_create_workspace(caller, name)).await
    }

    async fn try_create_workspace(&self, caller: Uuid, name: &str) -> Result<(), WriteError> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let actor = decide(&tx, caller).await?;
        // Two creating one name at once meet here: the second waits for the first, then inserts
        // nothing and is refused.
        let Some(row) = tx
            .query_opt(
                "insert into workspaces (name) values ($1)
                 on conflict (name) do nothing returning id",
                &[&name],
            )
            .await?
        else {
            return Err(
                Refusal::Conflict(format!("A workspace named {name} already exists.")).into(),
            );
        };
        audit(
            &tx,
            &actor,
            entry(
                "create",
                row.get("id"),
                None,
                Some(serde_json::json!({ "name": name })),
            ),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Renames the workspace called `from` to `to`, as a superuser. Its id stays, so what it
    /// holds, the grants into it and its audit entries follow it. Renaming it to the name it has
    /// writes nothing.
    pub async fn rename_workspace(
        &self,
        caller: Uuid,
        from: &str,
        to: &str,
    ) -> Result<(), WriteError> {
        retrying(move || self.try_rename_workspace(caller, from, to)).await
    }

    async fn try_rename_workspace(
        &self,
        caller: Uuid,
        from: &str,
        to: &str,
    ) -> Result<(), WriteError> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let actor = decide(&tx, caller).await?;
        let Some(row) = tx
            .query_opt(
                "select id from workspaces where name = $1 for update",
                &[&from],
            )
            .await?
        else {
            return Err(no_such(from));
        };
        if from == to {
            return Ok(());
        }
        let id: Uuid = row.get("id");
        // A create or another rename taking `to` after this read loses to the unique index
        // instead, and `retrying` runs this again, which then reads the name as taken.
        if tx
            .query_opt("select 1 from workspaces where name = $1", &[&to])
            .await?
            .is_some()
        {
            return Err(
                Refusal::Conflict(format!("A workspace named {to} already exists.")).into(),
            );
        }
        tx.execute("update workspaces set name = $2 where id = $1", &[&id, &to])
            .await?;
        // The compiled configuration names each workspace, so a rename changes what the data
        // planes are served. The trigger that moves the version watches only the tables a
        // workspace holds, so the version is moved here, as that trigger moves it.
        tx.execute(
            "update config_state set version = version + 1, changed_at = now()",
            &[],
        )
        .await?;
        audit(
            &tx,
            &actor,
            entry(
                "update",
                id,
                Some(serde_json::json!({ "name": from })),
                Some(serde_json::json!({ "name": to })),
            ),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Deletes the workspace called `name`, as a superuser: only an empty one, and never the last.
    /// The grants and group mappings into it go with it, and the audit entry lists them.
    pub async fn delete_workspace(&self, caller: Uuid, name: &str) -> Result<(), WriteError> {
        retrying(move || self.try_delete_workspace(caller, name)).await
    }

    async fn try_delete_workspace(&self, caller: Uuid, name: &str) -> Result<(), WriteError> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let actor = decide(&tx, caller).await?;
        tx.execute(DELETES_LOCK, &[]).await?;
        let Some(row) = tx
            .query_opt(
                "select id from workspaces where name = $1 for update",
                &[&name],
            )
            .await?
        else {
            return Err(no_such(name));
        };
        let id: Uuid = row.get("id");
        // A plain count: no other delete can run until this one commits, so none of these rows
        // can go meanwhile.
        let workspaces: i64 = tx
            .query_one("select count(*) from workspaces", &[])
            .await?
            .get(0);
        workspaces::not_the_last(name, usize::try_from(workspaces).unwrap_or(0))?;
        // Read under the row's lock: see the module's comment. So are the grants and mappings,
        // whose writes share-lock the workspace too, so the audit entry lists what went.
        let row = tx
            .query_one(
                &format!(
                    "select {CONTENTS},
                            (select coalesce(jsonb_agg(jsonb_build_object(
                                        'user', coalesce(u.username, u.display_name, u.oidc_subject),
                                        'role', b.role::text)
                                    order by coalesce(u.username, u.display_name, u.oidc_subject)
                                             collate \"C\", u.id), '[]')
                               from role_bindings b join users u on u.id = b.user_id
                              where b.workspace_id = w.id) as role_grants,
                            (select coalesce(jsonb_agg(jsonb_build_object(
                                        'group', g.group_name, 'role', g.role::text)
                                    order by g.group_name collate \"C\"), '[]')
                               from group_bindings g where g.workspace_id = w.id)
                            as group_mappings
                       from workspaces w where w.id = $1"
                ),
                &[&id],
            )
            .await?;
        workspaces::emptiness(name, &contents(&row))?;
        let role_grants: serde_json::Value = row.get("role_grants");
        let group_mappings: serde_json::Value = row.get("group_mappings");
        // The grants and mappings go with it by `on delete cascade`, and its audit entries keep
        // their rows with no workspace.
        tx.execute("delete from workspaces where id = $1", &[&id])
            .await?;
        audit(
            &tx,
            &actor,
            entry(
                "delete",
                id,
                Some(serde_json::json!({
                    "name": name,
                    "role_grants": role_grants,
                    "group_mappings": group_mappings,
                })),
                None,
            ),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
}
