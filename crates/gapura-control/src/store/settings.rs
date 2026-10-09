//! The console's one setting, whether sign-up is open, and the sign-up it allows.
//!
//! The switch is the single row of `console_settings`. A sign-up takes it `FOR UPDATE` in the
//! transaction that inserts the account, and so does a change of the switch, so the two are
//! ordered by Postgres: a sign-up that read "open" holds the row until it commits, and closing
//! waits for it; a sign-up that starts while closing is in flight waits, then reads "closed".
//! Once the request that closes sign-up has been answered, no account is created by sign-up.
//! Sign-ups take turns on the row too, which is what keeps the count of waiting accounts each
//! one reads, and so `MAX_WAITING_SIGN_UPS`, exact. The password is hashed before, so a turn is
//! a few statements long.
//!
//! Lock order: a change of the switch takes its caller's row (`rights`, `FOR SHARE`) and then
//! the settings row; a sign-up takes the settings row and then inserts its own new row, which
//! no other transaction can hold. Neither waits for what the other holds second.

use super::accounts::caller_rights;
use super::grants::{audit, retrying, Entry};
use super::{Store, WriteError};
use crate::access::{Method, User};
use anyhow::Result;
use std::collections::HashMap;
use uuid::Uuid;

/// How many accounts made by sign-up may be waiting for access at once: enabled, no superuser,
/// and holding no role binding (a local account has no groups, so no group mapping reaches it).
/// Past it sign-up refuses until someone grants, declines or disables some of them. The rate
/// limit is per address, and an attacker has many; this bounds what all of them together leave
/// for someone to look through, at a size a person can still read through in one sitting.
pub const MAX_WAITING_SIGN_UPS: i64 = 500;

/// An account that signed itself up, and when, by the database's clock in Unix milliseconds:
/// what its first session is issued at, as `record_sign_in` says for a sign-in.
#[derive(Debug)]
pub struct SignedUp {
    pub id: Uuid,
    pub signed_in_at: i64,
}

/// What a sign-up came to, short of the store failing.
#[derive(Debug)]
pub enum SignUp {
    Created(SignedUp),
    /// Sign-up is closed.
    Closed,
    /// An account has the name already, ignoring case.
    Taken,
    /// `MAX_WAITING_SIGN_UPS` accounts made by sign-up are waiting.
    Full,
}

impl Store {
    /// Whether anyone may create an account for themselves now.
    pub async fn sign_up_open(&self) -> Result<bool> {
        Ok(self
            .pool
            .get()
            .await?
            .query_one("select sign_up_open from console_settings", &[])
            .await?
            .get(0))
    }

    /// Opens or closes sign-up, as `caller`, who must be a superuser. Already as asked, nothing
    /// is written and nothing audited.
    pub async fn set_sign_up_open(&self, caller: Uuid, open: bool) -> Result<(), WriteError> {
        retrying(|| self.try_set_sign_up_open(caller, open)).await
    }

    async fn try_set_sign_up_open(&self, caller: Uuid, open: bool) -> Result<(), WriteError> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let actor = caller_rights(&tx, caller).await?;
        crate::accounts::may_change_settings(&actor)?;
        let was: bool = tx
            .query_one("select sign_up_open from console_settings for update", &[])
            .await?
            .get(0);
        if was == open {
            return Ok(());
        }
        tx.execute("update console_settings set sign_up_open = $1", &[&open])
            .await?;
        audit(
            &tx,
            &actor,
            Entry {
                action: "update",
                object_kind: "setting",
                object_id: None,
                workspace: None,
                before: Some(serde_json::json!({ "sign_up_open": was })),
                after: Some(serde_json::json!({ "sign_up_open": open })),
            },
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Creates the local account `username`, with `password_hash` and the note its owner wrote,
    /// if sign-up is open and fewer than `MAX_WAITING_SIGN_UPS` of its accounts are waiting, and
    /// stamps it signed in. It holds no role. `username` and the note have been checked by the
    /// caller; the hash is made before this is called, since hashing is slow and a retry reuses
    /// it.
    ///
    /// The insert names no conflict target, so the one that applies to a name taken ignoring case
    /// is `users_username_lower`. Its audit entry names the new account as the actor, since
    /// nobody else made it, and says whether a note was written, not what it says.
    pub async fn sign_up(
        &self,
        username: &str,
        password_hash: &str,
        note: Option<&str>,
    ) -> Result<SignUp, WriteError> {
        retrying(|| self.try_sign_up(username, password_hash, note)).await
    }

    async fn try_sign_up(
        &self,
        username: &str,
        password_hash: &str,
        note: Option<&str>,
    ) -> Result<SignUp, WriteError> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        tx.batch_execute("set local lock_timeout = '10s'").await?;
        let open: bool = tx
            .query_one("select sign_up_open from console_settings for update", &[])
            .await?
            .get(0);
        if !open {
            return Ok(SignUp::Closed);
        }
        let waiting: i64 = tx
            .query_one(
                "select count(*) from users u
                  where u.signed_up_at is not null and u.disabled_at is null and not u.superuser
                    and not exists (select 1 from role_bindings b where b.user_id = u.id)",
                &[],
            )
            .await?
            .get(0);
        if waiting >= MAX_WAITING_SIGN_UPS {
            return Ok(SignUp::Full);
        }
        let Some(row) = tx
            .query_opt(
                "insert into users (username, password_hash, signup_note, signed_up_at,
                                    last_sign_in_at)
                 values ($1, $2, $3, now(), now())
                 on conflict do nothing
                 returning id, floor(extract(epoch from clock_timestamp()) * 1000)::bigint",
                &[&username, &password_hash, &note],
            )
            .await?
        else {
            return Ok(SignUp::Taken);
        };
        let id: Uuid = row.get(0);
        let signed_in_at: i64 = row.get(1);
        let actor = User {
            id,
            name: username.to_string(),
            method: Method::Local,
            superuser: false,
            disabled: false,
            groups: Vec::new(),
            last_sign_in: None,
            must_change_password: false,
            sessions_valid_after: None,
        };
        audit(
            &tx,
            &actor,
            Entry {
                action: "create",
                object_kind: "user",
                object_id: Some(id),
                workspace: None,
                before: None,
                after: Some(serde_json::json!({
                    "username": username,
                    "signed_up": true,
                    "note": note.is_some(),
                })),
            },
        )
        .await?;
        tx.commit().await?;
        Ok(SignUp::Created(SignedUp { id, signed_in_at }))
    }

    /// The notes accounts wrote when they signed up, by account. Read apart from `access_rows`,
    /// which every request reads, for the one page that shows them.
    pub async fn signup_notes(&self) -> Result<HashMap<Uuid, String>> {
        Ok(self
            .pool
            .get()
            .await?
            .query(
                "select id, signup_note from users where signup_note is not null",
                &[],
            )
            .await?
            .into_iter()
            .map(|row| (row.get(0), row.get(1)))
            .collect())
    }
}
