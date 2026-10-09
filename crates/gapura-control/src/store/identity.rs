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
    /// The database's clock as the sign-in was recorded, in Unix milliseconds: see
    /// `record_sign_in`.
    pub signed_in_at: i64,
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
        // The cut-off is floored to the millisecond: rounded, one late in its millisecond would
        // read as the next, and refuse a session issued within the same one.
        let users = tx
            .query(
                "select id,
                        coalesce(username, display_name, oidc_subject) as name,
                        password_hash is not null as local,
                        superuser,
                        disabled_at is not null as disabled,
                        oidc_groups,
                        floor(extract(epoch from last_sign_in_at))::bigint as last_sign_in,
                        must_change_password,
                        floor(extract(epoch from sessions_valid_after) * 1000)::bigint
                            as sessions_valid_after
                   from users
                  order by lower(coalesce(username, display_name, oidc_subject)), id",
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
                must_change_password: r.get("must_change_password"),
                sessions_valid_after: r.get("sessions_valid_after"),
            })
            .collect();
        let workspaces = tx
            // collate "C", so every deployment lists workspaces in one order, the one Rust's own
            // sorting of names elsewhere in the console agrees with.
            .query(
                "select id, name from workspaces order by name collate \"C\"",
                &[],
            )
            .await?
            .into_iter()
            .map(|r| Workspace {
                id: r.get("id"),
                name: r.get("name"),
            })
            .collect();
        // `role` is a Postgres enum, read as text and parsed: the enum is what keeps an
        // unknown name out of the table, so `parse` failing here means the binary is older than
        // the schema -- a rolling upgrade, mid-way. Such a row is left out rather than guessed at,
        // and said so, or an operator seeing a grant honoured by some replicas and not others
        // would have nothing to go on.
        let grants = tx
            .query(
                "select user_id, workspace_id, role::text as role from role_bindings",
                &[],
            )
            .await?
            .into_iter()
            .filter_map(|r| {
                let user: Uuid = r.get("user_id");
                let workspace: Uuid = r.get("workspace_id");
                let name: &str = r.get("role");
                let Some(role) = Role::parse(name) else {
                    tracing::warn!(role = %name, %user, %workspace, "a role this binary does not know; the grant is ignored");
                    return None;
                };
                Some(Grant {
                    user,
                    workspace,
                    role,
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
                let group: String = r.get("group_name");
                let workspace: Uuid = r.get("workspace_id");
                let name: &str = r.get("role");
                let Some(role) = Role::parse(name) else {
                    tracing::warn!(role = %name, %group, %workspace, "a role this binary does not know; the group mapping is ignored");
                    return None;
                };
                Some(GroupGrant {
                    group,
                    workspace,
                    role,
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

    /// Stamps a local account's sign-in, if `verified` -- the hash its password was checked
    /// against -- is still the account's, and says when by the database's clock, in Unix
    /// milliseconds. None when it is not: a reset or a password change committed between the
    /// read and now, so the password that signed in no longer opens the account, and the
    /// sign-in must be refused. An OIDC sign-in is stamped by `upsert_oidc_user`, in the
    /// statement that records it.
    ///
    /// The time is what the session is issued at, so it and a cut-off come from one clock.
    pub async fn record_sign_in(&self, id: Uuid, verified: &str) -> Result<Option<i64>> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                "update users set last_sign_in_at = now() where id = $1 and password_hash = $2
                 returning floor(extract(epoch from clock_timestamp()) * 1000)::bigint",
                &[&id, &verified],
            )
            .await?;
        Ok(row.map(|r| r.get(0)))
    }

    /// Records an OIDC sign-in: the row for (issuer, subject), created the first time, with
    /// the name and groups the provider gave this time. An empty name is stored as none, so the
    /// account is shown by its subject rather than as a blank. A disabled account keeps its
    /// last recorded sign-in, because this one is about to be refused.
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
                 values ($1, $2, nullif($3::text, ''), $4, now())
                 on conflict (oidc_issuer, oidc_subject) do update
                    set display_name = excluded.display_name,
                        oidc_groups = excluded.oidc_groups,
                        last_sign_in_at = case when users.disabled_at is null
                                               then now() else users.last_sign_in_at end
                 returning id, disabled_at is not null as disabled,
                           floor(extract(epoch from clock_timestamp()) * 1000)::bigint as signed_in_at",
                &[&issuer, &subject, &display_name, &groups],
            )
            .await?;
        Ok(OidcAccount {
            id: row.get("id"),
            disabled: row.get("disabled"),
            signed_in_at: row.get("signed_in_at"),
        })
    }

    /// Creates the first superuser, but only into an empty table, and says whether it did.
    ///
    /// The lock is what makes "only into an empty table" true when two replicas start at once:
    /// without it both count zero rows and both insert. SHARE ROW EXCLUSIVE is the weakest mode
    /// that conflicts with itself and with the writes sign-ins make, so the two take turns and a
    /// first OIDC sign-in cannot land between the count and the insert; SHARE would let both
    /// count zero and then deadlock on their inserts.
    pub async fn bootstrap_superuser(&self, username: &str, password_hash: &str) -> Result<bool> {
        // Every start after the first answers here, without touching the lock.
        if self.user_count().await? > 0 {
            return Ok(false);
        }
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        // Bounded, so a start-up queued behind a long write on `users` fails with a reason
        // instead of hanging, and stops holding up the sign-ins queued behind it.
        tx.batch_execute(
            "set local lock_timeout = '10s'; lock table users in share row exclusive mode",
        )
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

    /// How many accounts exist, disabled ones included: what decides whether the bootstrap
    /// variables apply.
    pub async fn user_count(&self) -> Result<i64> {
        let client = self.pool.get().await?;
        Ok(client
            .query_one("select count(*) from users", &[])
            .await?
            .get(0))
    }
}
