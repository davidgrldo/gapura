//! Accounts as a superuser changes them, and a password as its owner changes it.
//!
//! Each write is one transaction, decided over rows it has locked, with one audit row that
//! concerns no workspace and never holds a password or a hash. A superuser's change to an
//! account takes its locks in one order:
//!
//! 1. every enabled superuser, `FOR UPDATE`, in id order, and counts them;
//! 2. the caller, read again by `rights` (`FOR SHARE`) and decided by `accounts::may_administer`;
//! 3. the account it changes, `FOR UPDATE`, decided by `accounts::guard` over the count;
//! 4. the write, and the audit row.
//!
//! The superusers come first, before `rights`, because the caller is one of them. Taken the other
//! way round, two superusers changing accounts at once would each share-lock their own row, then
//! each wait to update-lock the other's: a deadlock every time two such writes overlapped, which
//! Postgres would break after its `deadlock_timeout` and `retrying` would run again. In this
//! order each such write waits at the first superuser row the other holds, so the second starts
//! only once the first has committed, and then reads what it committed. Two superusers demoting
//! each other end with one demoted and the other's write refused, because by then its caller is
//! no superuser; the last superuser cannot be lost between a count and a write. `rights`'s own
//! `FOR SHARE` on a row this transaction already holds `FOR UPDATE` waits for nothing. A caller
//! who is no superuser takes the same locks for a moment before being refused; the handler
//! refuses them before any transaction, so only one demoted meanwhile gets that far.
//!
//! Waits can still form a cycle with a write elsewhere that holds a superuser's row `FOR SHARE`
//! (`rights`, for a grant) and then wants the account this write already holds, such as a grant
//! to a superuser being deleted while another superuser grants them a role. Postgres aborts one
//! and `retrying` runs it again; that is rare, and run again it is ordered like any other.
//!
//! Creating an account changes no one who exists, so it takes only step 2. A password change by
//! its owner locks only the owner's row, by its update before `rights` shares it, for the same
//! reason as above: two saves of one person's password would otherwise deadlock each other.
//!
//! Every cut-off is `clock_timestamp()`, the moment the statement runs, not `now()`, which is
//! when the transaction began: the lock waits above lie between the two, and a session issued in
//! that gap would otherwise postdate the cut-off meant to end it.

use super::grants::{audit, retrying, rights, Entry};
use super::{Store, WriteError};
use crate::access::{Method, User};
use crate::accounts::{self, Change, PasswordChange};
use crate::grants::Refusal;
use std::collections::BTreeSet;
use tokio_postgres::Transaction;
use uuid::Uuid;

/// As `rights` sets it, here too because the locks below are taken before `rights` is called.
async fn bound_lock_waits(tx: &Transaction<'_>) -> Result<(), WriteError> {
    tx.batch_execute("set local lock_timeout = '10s'").await?;
    Ok(())
}

/// The PHC string for `password`, made off the async workers and under the bound and queue
/// sign-ins are checked under: argon2 takes 19 MiB and about 20 ms each time. `Busy` when the
/// queue is full.
async fn hashed(password: String) -> Result<String, WriteError> {
    match crate::password::hash_or_busy(password).await {
        Ok(hashed) => hashed.map_err(WriteError::Store),
        Err(crate::password::Busy) => Err(WriteError::Busy),
    }
}

/// The refusal of a caller whose own account is gone: deleted by a superuser after their
/// session was read.
fn gone() -> Refusal {
    Refusal::Forbidden("Your account no longer exists.".into())
}

/// The caller, read again by `rights`. Its one refusal is of a caller whose row is gone, worded
/// for a change to roles; an account write says it about the account instead.
pub(super) async fn caller_rights(tx: &Transaction<'_>, caller: Uuid) -> Result<User, WriteError> {
    match rights(tx, caller, &BTreeSet::new()).await {
        Ok((actor, _)) => Ok(actor),
        Err(WriteError::Refused(r)) if r == Refusal::outside_your_workspaces() => {
            Err(gone().into())
        }
        Err(e) => Err(e),
    }
}

/// Steps 1 to 3: the superusers locked and counted, the caller decided, and `target` locked and
/// guarded for `change`. The answer is the caller and the account as they stand now.
async fn decide(
    tx: &Transaction<'_>,
    caller: Uuid,
    target: Uuid,
    change: Change,
) -> Result<(User, User), WriteError> {
    bound_lock_waits(tx).await?;
    let enabled_superusers = tx
        .query(
            "select id from users where superuser and disabled_at is null
              order by id for update",
            &[],
        )
        .await?
        .len();
    let actor = caller_rights(tx, caller).await?;
    accounts::may_administer(&actor)?;
    // Only now, so a refused request says nothing about whether the account exists.
    let Some(row) = tx
        .query_opt(
            "select id,
                    coalesce(username, display_name, oidc_subject) as name,
                    password_hash is not null as local,
                    superuser,
                    disabled_at is not null as disabled
               from users where id = $1 for update",
            &[&target],
        )
        .await?
    else {
        return Err(Refusal::NotFound("There is no such account.".into()).into());
    };
    let target = User {
        id: row.get("id"),
        name: row.get("name"),
        method: if row.get::<_, bool>("local") {
            Method::Local
        } else {
            Method::Oidc
        },
        superuser: row.get("superuser"),
        disabled: row.get("disabled"),
        groups: Vec::new(),
        last_sign_in: None,
        must_change_password: false,
        sessions_valid_after: None,
    };
    accounts::guard(&actor, &target, &change, enabled_superusers)?;
    Ok((actor, target))
}

/// An audit entry about the account `id`.
fn entry(
    action: &'static str,
    id: Uuid,
    before: Option<serde_json::Value>,
    after: Option<serde_json::Value>,
) -> Entry {
    Entry {
        action,
        object_kind: "user",
        object_id: Some(id),
        workspace: None,
        before,
        after,
    }
}

impl Store {
    /// Creates a local account called `username`, which the handler has checked with
    /// `accounts::username`, as `caller`, who must be a superuser. It holds no role, and its
    /// password is a temporary one it must replace at its first sign-in. The answer is its id and
    /// that password, which appears nowhere else.
    pub async fn create_account(
        &self,
        caller: Uuid,
        username: &str,
        superuser: bool,
    ) -> Result<(Uuid, String), WriteError> {
        // Hashed once, before the transaction: hashing is slow, and a retry reuses it.
        let password = accounts::temporary_password(username);
        let hash = hashed(password.clone()).await?;
        let id = retrying(|| self.try_create_account(caller, username, superuser, &hash)).await?;
        Ok((id, password))
    }

    async fn try_create_account(
        &self,
        caller: Uuid,
        username: &str,
        superuser: bool,
        hash: &str,
    ) -> Result<Uuid, WriteError> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let actor = caller_rights(&tx, caller).await?;
        accounts::may_administer(&actor)?;
        // No conflict target: the one that matters is `users_username_lower`, an expression
        // index, so `Maya` meets `maya` here. Two creating one name at once meet here too: the
        // second waits for the first, then inserts nothing and is refused.
        let Some(row) = tx
            .query_opt(
                "insert into users (username, password_hash, superuser, must_change_password)
                 values ($1, $2, $3, true)
                 on conflict do nothing returning id",
                &[&username, &hash, &superuser],
            )
            .await?
        else {
            return Err(
                Refusal::Conflict(format!("An account named {username} already exists.")).into(),
            );
        };
        let id: Uuid = row.get("id");
        audit(
            &tx,
            &actor,
            entry(
                "create",
                id,
                None,
                Some(serde_json::json!({ "username": username, "superuser": superuser })),
            ),
        )
        .await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Gives the local account `id` a new temporary password, as a superuser, and signs it out
    /// everywhere. The answer is the password, which appears nowhere else.
    pub async fn reset_password(&self, caller: Uuid, id: Uuid) -> Result<String, WriteError> {
        // The password is drawn for the account's username, which it must not contain, and
        // hashed before the transaction. Usernames never change, so the one read here is the
        // one the transaction finds; an account with none is refused there.
        let username: Option<String> = self
            .pool
            .get()
            .await?
            .query_opt("select username from users where id = $1", &[&id])
            .await?
            .and_then(|row| row.get("username"));
        let password = accounts::temporary_password(username.as_deref().unwrap_or(""));
        let hash = hashed(password.clone()).await?;
        retrying(|| self.try_reset_password(caller, id, &hash)).await?;
        Ok(password)
    }

    async fn try_reset_password(
        &self,
        caller: Uuid,
        id: Uuid,
        hash: &str,
    ) -> Result<(), WriteError> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let (actor, target) = decide(&tx, caller, id, Change::Reset).await?;
        tx.execute(
            "update users set password_hash = $2, must_change_password = true,
                              sessions_valid_after = clock_timestamp()
              where id = $1",
            &[&target.id, &hash],
        )
        .await?;
        audit(
            &tx,
            &actor,
            entry(
                "update",
                target.id,
                None,
                Some(serde_json::json!({ "password": "reset" })),
            ),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Disables or enables the account `id`, as a superuser. Either signs it out everywhere. An
    /// account already as asked is left alone, with no audit entry.
    pub async fn set_disabled(
        &self,
        caller: Uuid,
        id: Uuid,
        disabled: bool,
    ) -> Result<(), WriteError> {
        retrying(|| self.try_set_disabled(caller, id, disabled)).await
    }

    async fn try_set_disabled(
        &self,
        caller: Uuid,
        id: Uuid,
        disabled: bool,
    ) -> Result<(), WriteError> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let change = if disabled {
            Change::Disable
        } else {
            Change::Enable
        };
        let (actor, target) = decide(&tx, caller, id, change).await?;
        if target.disabled == disabled {
            return Ok(());
        }
        // Enabling cuts off too: a sign-in that verified just before the disable can still have
        // issued its session after the disable's cut-off, and enabling must not bring it back.
        tx.execute(
            "update users set
                    disabled_at = case when $2 then now() end,
                    sessions_valid_after = clock_timestamp()
              where id = $1",
            &[&target.id, &disabled],
        )
        .await?;
        audit(
            &tx,
            &actor,
            entry(
                "update",
                target.id,
                Some(serde_json::json!({ "disabled": target.disabled })),
                Some(serde_json::json!({ "disabled": disabled })),
            ),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Makes the account `id` a superuser or not, as a superuser. Removing it signs the account
    /// out everywhere. An account already as asked is left alone, with no audit entry.
    pub async fn set_superuser(
        &self,
        caller: Uuid,
        id: Uuid,
        superuser: bool,
    ) -> Result<(), WriteError> {
        retrying(|| self.try_set_superuser(caller, id, superuser)).await
    }

    async fn try_set_superuser(
        &self,
        caller: Uuid,
        id: Uuid,
        superuser: bool,
    ) -> Result<(), WriteError> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let (actor, target) = decide(&tx, caller, id, Change::Superuser(superuser)).await?;
        if target.superuser == superuser {
            return Ok(());
        }
        tx.execute(
            "update users set
                    superuser = $2,
                    sessions_valid_after =
                        case when $2 then sessions_valid_after else clock_timestamp() end
              where id = $1",
            &[&target.id, &superuser],
        )
        .await?;
        audit(
            &tx,
            &actor,
            entry(
                "update",
                target.id,
                Some(serde_json::json!({ "superuser": target.superuser })),
                Some(serde_json::json!({ "superuser": superuser })),
            ),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Deletes the local account `id`, as a superuser. Its role bindings go with it; the audit
    /// entries it wrote keep its name, and lose its id by the foreign key.
    pub async fn delete_account(&self, caller: Uuid, id: Uuid) -> Result<(), WriteError> {
        retrying(|| self.try_delete_account(caller, id)).await
    }

    async fn try_delete_account(&self, caller: Uuid, id: Uuid) -> Result<(), WriteError> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let (actor, target) = decide(&tx, caller, id, Change::Delete).await?;
        tx.execute("delete from users where id = $1", &[&target.id])
            .await?;
        audit(
            &tx,
            &actor,
            entry(
                "delete",
                target.id,
                Some(serde_json::json!({ "username": target.name })),
                None,
            ),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Replaces `caller`'s own password, given the current one, and signs them out everywhere,
    /// which is the caller's to follow with a new session. Ends what a temporary password
    /// allows. A wrong current password is refused as a `WriteError::Field` on
    /// `accounts::CURRENT`, which the handler counts as a failed attempt; a new password the
    /// rules refuse is a `WriteError::Field` on `new`.
    ///
    /// The current password is verified, and the new one hashed, before any transaction: argon2
    /// waits its turn under the bound sign-ins share, and no row lock is held while it does. The
    /// write then replaces only the hash that was verified, so a password changed or reset in
    /// between is not overwritten by one checked against the old.
    ///
    /// The answer is the cut-off it set, in Unix milliseconds, read as `access_rows` reads it.
    /// It comes from the database's clock, and the new session from the console's: a session
    /// issued no earlier than this stands whatever the difference between the two.
    pub async fn change_own_password(
        &self,
        caller: Uuid,
        current: &str,
        new: &str,
    ) -> Result<i64, WriteError> {
        let change = PasswordChange {
            current: current.to_string(),
            new: new.to_string(),
        };
        let Some(row) = self
            .pool
            .get()
            .await?
            .query_opt(
                "select username, password_hash from users where id = $1",
                &[&caller],
            )
            .await?
        else {
            return Err(gone().into());
        };
        let (Some(username), Some(verified)) = (
            row.get::<_, Option<String>>("username"),
            row.get::<_, Option<String>>("password_hash"),
        ) else {
            return Err(Refusal::Conflict(
                "Your account signs in through the identity provider; its password is not kept \
                 here."
                    .into(),
            )
            .into());
        };
        match crate::password::verify_or_dummy(change.current.clone(), Some(verified.clone())).await
        {
            Ok(true) => {}
            Ok(false) => return Err(WriteError::Field(accounts::wrong_current())),
            // Not a verdict on the password: a 503 the caller can retry, given back to the
            // sign-in throttle.
            Err(crate::password::Busy) => return Err(WriteError::Busy),
        }
        accounts::new_password(&username, &change).map_err(WriteError::Field)?;
        let hash = hashed(change.new.clone()).await?;
        retrying(|| self.try_change_own_password(caller, &verified, &hash)).await
    }

    async fn try_change_own_password(
        &self,
        caller: Uuid,
        verified: &str,
        hash: &str,
    ) -> Result<i64, WriteError> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        bound_lock_waits(&tx).await?;
        // The update locks the row before `rights` shares it: see the module's comment.
        let Some(row) = tx
            .query_opt(
                "update users set password_hash = $3, must_change_password = false,
                                  sessions_valid_after = clock_timestamp()
                  where id = $1 and password_hash = $2
              returning floor(extract(epoch from sessions_valid_after) * 1000)::bigint",
                &[&caller, &verified, &hash],
            )
            .await?
        else {
            // The password changed after it was verified: the one given is not current now.
            return Err(WriteError::Field(accounts::wrong_current()));
        };
        let cut_off: i64 = row.get(0);
        let actor = caller_rights(&tx, caller).await?;
        if actor.disabled {
            return Err(Refusal::Forbidden("This account is disabled.".into()).into());
        }
        audit(
            &tx,
            &actor,
            entry(
                "update",
                caller,
                None,
                Some(serde_json::json!({ "password": "changed" })),
            ),
        )
        .await?;
        tx.commit().await?;
        Ok(cut_off)
    }
}
