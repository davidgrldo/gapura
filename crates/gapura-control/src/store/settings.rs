//! The console's one setting, whether sign-up is open, and the sign-up it allows.
//!
//! The switch is the single row of `console_settings`. A sign-up reads it `FOR SHARE` in the
//! transaction that inserts the account, and the switch is changed `FOR UPDATE`, so the two are
//! ordered by Postgres: a sign-up that read "open" holds the row until it commits, and closing
//! waits for it; a sign-up that starts while closing is in flight waits, then reads "closed".
//! Once the request that closes sign-up has been answered, no account is created by sign-up.
//!
//! Lock order: a change of the switch takes its caller's row (`rights`, `FOR SHARE`) and then
//! the settings row; a sign-up takes the settings row and then inserts its own new row, which
//! no other transaction can hold. Neither waits for what the other holds second.

use super::accounts::caller_rights;
use super::grants::{audit, retrying, Entry};
use super::{Store, WriteError};
use crate::access::{Method, User};
use crate::grants::Refusal;
use anyhow::Result;
use uuid::Uuid;

/// An account that signed itself up, and when, by the database's clock in Unix milliseconds:
/// what its first session is issued at, as `record_sign_in` says for a sign-in.
#[derive(Debug)]
pub struct SignedUp {
    pub id: Uuid,
    pub signed_in_at: i64,
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
    /// if sign-up is open, and stamps it signed in. It holds no role. `username` and the note
    /// have been checked by the caller; the hash is made before this is called, since hashing is
    /// slow and a retry reuses it.
    ///
    /// Refused with `Refusal::Forbidden` while sign-up is closed, and with `Refusal::Conflict`
    /// when the name is taken, ignoring case: the insert names no conflict target, so the one
    /// that applies is `users_username_lower`. Its audit entry names the new account as the
    /// actor, since nobody else made it, and says whether a note was written, not what it says.
    pub async fn sign_up(
        &self,
        username: &str,
        password_hash: &str,
        note: Option<&str>,
    ) -> Result<SignedUp, WriteError> {
        retrying(|| self.try_sign_up(username, password_hash, note)).await
    }

    async fn try_sign_up(
        &self,
        username: &str,
        password_hash: &str,
        note: Option<&str>,
    ) -> Result<SignedUp, WriteError> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        tx.batch_execute("set local lock_timeout = '10s'").await?;
        let open: bool = tx
            .query_one("select sign_up_open from console_settings for share", &[])
            .await?
            .get(0);
        if !open {
            return Err(Refusal::Forbidden("Sign-up is closed.".into()).into());
        }
        let Some(row) = tx
            .query_opt(
                "insert into users (username, password_hash, signup_note, last_sign_in_at)
                 values ($1, $2, $3, now())
                 on conflict do nothing
                 returning id, floor(extract(epoch from clock_timestamp()) * 1000)::bigint",
                &[&username, &password_hash, &note],
            )
            .await?
        else {
            return Err(Refusal::Conflict("That username is taken.".into()).into());
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
            signup_note: None,
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
        Ok(SignedUp { id, signed_in_at })
    }
}
