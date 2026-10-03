//! The console's accounts and grants: read whole for `access`, written at sign-in.

use super::Store;
use crate::access::{Grant, GroupGrant, Method, Role, Rows, User, Workspace};
use anyhow::Result;
use uuid::Uuid;

/// A local account, as sign-in needs it.
pub struct LocalAccount {
    pub id: Uuid,
    pub password_hash: String,
    pub disabled: bool,
}

/// An OIDC account after its sign-in was recorded.
pub struct OidcAccount {
    pub id: Uuid,
    pub disabled: bool,
}

impl Store {
    /// Accounts, workspaces, grants and group mappings, read in one transaction so the four
    /// agree: read apart, a grant written in between could name an account the read missed.
    ///
    /// Whole tables, because the console's are small and `access` reasons over sets. A
    /// deployment where that stops being true is a reason to measure, not to guess now.
    pub async fn access_rows(&self) -> Result<Rows> {
        let mut client = self.pool.get().await?;
        let tx = client
            .build_transaction()
            .read_only(true)
            .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
            .start()
            .await?;
        let users = tx
            .query(
                "select id,
                        coalesce(username, display_name, oidc_subject) as name,
                        password_hash is not null as local,
                        superuser,
                        disabled_at is not null as disabled,
                        oidc_groups,
                        extract(epoch from last_sign_in_at)::bigint as last_sign_in
                   from users
                  order by lower(coalesce(username, display_name, oidc_subject))",
                &[],
            )
            .await?
            .into_iter()
            .map(|r| User {
                id: r.get("id"),
                name: r.get("name"),
                method: if r.get::<_, bool>("local") {
                    Method::Local
                } else {
                    Method::Oidc
                },
                superuser: r.get("superuser"),
                disabled: r.get("disabled"),
                groups: r.get("oidc_groups"),
                last_sign_in: r.get("last_sign_in"),
            })
            .collect();
        let workspaces = tx
            .query("select id, name from workspaces order by name", &[])
            .await?
            .into_iter()
            .map(|r| Workspace {
                id: r.get("id"),
                name: r.get("name"),
            })
            .collect();
        // `role` is a Postgres enum, read as text and parsed: the enum is what keeps an
        // unknown name out of the table, so `parse` failing here would mean the binary is older
        // than the schema, and such a row is left out rather than guessed at.
        let grants = tx
            .query(
                "select user_id, workspace_id, role::text as role from role_bindings",
                &[],
            )
            .await?
            .into_iter()
            .filter_map(|r| {
                Some(Grant {
                    user: r.get("user_id"),
                    workspace: r.get("workspace_id"),
                    role: Role::parse(r.get("role"))?,
                })
            })
            .collect();
        let group_grants = tx
            .query(
                "select group_name, workspace_id, role::text as role from group_bindings",
                &[],
            )
            .await?
            .into_iter()
            .filter_map(|r| {
                Some(GroupGrant {
                    group: r.get("group_name"),
                    workspace: r.get("workspace_id"),
                    role: Role::parse(r.get("role"))?,
                })
            })
            .collect();
        tx.commit().await?;
        Ok(Rows {
            users,
            workspaces,
            grants,
            group_grants,
        })
    }

    /// The local account `username` names, matched ignoring case the way the unique index
    /// lowers it, so the index serves the lookup.
    pub async fn local_user(&self, username: &str) -> Result<Option<LocalAccount>> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                "select id, password_hash, disabled_at is not null as disabled
                   from users where lower(username collate \"C\") = lower($1::text collate \"C\")",
                &[&username],
            )
            .await?;
        Ok(row.map(|r| LocalAccount {
            id: r.get("id"),
            password_hash: r.get("password_hash"),
            disabled: r.get("disabled"),
        }))
    }

    pub async fn record_sign_in(&self, id: Uuid) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                "update users set last_sign_in_at = now() where id = $1",
                &[&id],
            )
            .await?;
        Ok(())
    }

    /// Records an OIDC sign-in: the row for (issuer, subject), created the first time, with
    /// the name and groups the provider gave this time. A disabled account keeps its last
    /// recorded sign-in, because this one is about to be refused.
    pub async fn upsert_oidc_user(
        &self,
        issuer: &str,
        subject: &str,
        display_name: &str,
        groups: &[String],
    ) -> Result<OidcAccount> {
        let client = self.pool.get().await?;
        let row = client
            .query_one(
                "insert into users (oidc_issuer, oidc_subject, display_name, oidc_groups, last_sign_in_at)
                 values ($1, $2, $3, $4, now())
                 on conflict (oidc_issuer, oidc_subject) do update
                    set display_name = excluded.display_name,
                        oidc_groups = excluded.oidc_groups,
                        last_sign_in_at = case when users.disabled_at is null
                                               then now() else users.last_sign_in_at end
                 returning id, disabled_at is not null as disabled",
                &[&issuer, &subject, &display_name, &groups],
            )
            .await?;
        Ok(OidcAccount {
            id: row.get("id"),
            disabled: row.get("disabled"),
        })
    }

    /// Creates the first superuser, but only into an empty table, and says whether it did.
    ///
    /// The lock is what makes "only into an empty table" true when two replicas start at once:
    /// without it both count zero rows and both insert.
    pub async fn bootstrap_superuser(&self, username: &str, password_hash: &str) -> Result<bool> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        tx.batch_execute("lock table users in share row exclusive mode")
            .await?;
        let existing: i64 = tx
            .query_one("select count(*) from users", &[])
            .await?
            .get(0);
        if existing > 0 {
            tx.rollback().await?;
            return Ok(false);
        }
        tx.execute(
            "insert into users (username, password_hash, superuser) values ($1, $2, true)",
            &[&username, &password_hash],
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }

    pub async fn user_count(&self) -> Result<i64> {
        let client = self.pool.get().await?;
        Ok(client
            .query_one("select count(*) from users", &[])
            .await?
            .get(0))
    }
}
