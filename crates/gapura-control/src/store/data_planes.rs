//! Data planes and their tokens as the console reads and writes them.
//!
//! Each write is one transaction in the consumers' order: the caller's row re-read locked and
//! decided by `data_planes::may_write`, so a demotion and a write are ordered by Postgres; the
//! changed row locked; one audit row, which concerns no workspace. A token is stored as its
//! SHA-256 and a 13-character prefix, as `seed_token` stores one; the token itself leaves this
//! module only in the answer to registering or issuing, and the audit row records its prefix.

use super::configuration::updated_at;
use super::grants::{audit, retrying, rights, Entry};
use super::{hash, hex, Store, WriteError, PREFIX_LEN};
use crate::data_planes::{self, DataPlaneView, IssuedToken, TokenView, CONNECTED_WITHIN_SECS};
use crate::grants::Refusal;
use anyhow::Result;
use std::collections::BTreeSet;
use tokio_postgres::Transaction;
use uuid::Uuid;

/// A new token and its prefix. Drawn inside each attempt, so a retry after a prefix that is
/// already stored draws another.
fn draw() -> (String, String) {
    let raw: [u8; 32] = rand::random();
    let token = format!("gpdp_{}", hex(&raw));
    let prefix = token[..PREFIX_LEN].to_string();
    (token, prefix)
}

/// Step 1 of every write: the caller read again inside `tx`, locked, and refused unless they may
/// write data planes.
async fn decide(tx: &Transaction<'_>, caller: Uuid) -> Result<crate::access::User, WriteError> {
    let (actor, _) = rights(tx, caller, &BTreeSet::new()).await?;
    data_planes::may_write(&actor)?;
    Ok(actor)
}

/// Stores `token` for the data plane `id`, returning the token row's id.
async fn insert_token(
    tx: &Transaction<'_>,
    id: Uuid,
    token: &str,
    prefix: &str,
) -> Result<Uuid, WriteError> {
    Ok(tx
        .query_one(
            "insert into data_plane_tokens (data_plane_id, token_prefix, token_hash)
             values ($1, $2, $3) returning id",
            &[&id, &prefix, &hash(token)],
        )
        .await?
        .get("id"))
}

/// The status column's text as the view's `&'static str`.
fn status(text: &str) -> Result<&'static str> {
    match text {
        "connected" => Ok("connected"),
        "not_seen" => Ok("not_seen"),
        "never" => Ok("never"),
        other => Err(anyhow::anyhow!("a data plane's status read as {other:?}")),
    }
}

impl Store {
    /// Every data plane by name, each with its tokens, newest first, and whether it holds what
    /// is served now, whose tag is `current_etag`. No token or hash is read.
    pub async fn data_planes(&self, current_etag: &str) -> Result<Vec<DataPlaneView>> {
        let client = self.pool.get().await?;
        let rows = client
            .query(
                &format!(
                    "select d.name, {} as created_at, {} as last_seen_at,
                            host(d.last_seen_address) as last_seen_address,
                            case when d.last_seen_at is null then 'never'
                                 when d.last_seen_at > now() - make_interval(secs => $1)
                                     then 'connected'
                                 else 'not_seen' end as status,
                            d.last_seen_etag,
                            t.token_prefix, {} as token_created_at, {} as token_last_used_at
                       from data_planes d left join data_plane_tokens t on t.data_plane_id = d.id
                      order by d.name, t.created_at desc, t.token_prefix",
                    updated_at("d.created_at"),
                    updated_at("d.last_seen_at"),
                    updated_at("t.created_at"),
                    updated_at("t.last_used_at"),
                ),
                &[&(CONNECTED_WITHIN_SECS as f64)],
            )
            .await?;
        // Rows come grouped by data plane, whose name is unique.
        let mut out: Vec<DataPlaneView> = Vec::new();
        for row in rows {
            let name: String = row.get("name");
            if out.last().is_none_or(|d| d.name != name) {
                out.push(DataPlaneView {
                    name,
                    created_at: row.get("created_at"),
                    last_seen_at: row.get("last_seen_at"),
                    last_seen_address: row.get("last_seen_address"),
                    status: status(row.get("status"))?,
                    in_sync: data_planes::in_sync(row.get("last_seen_etag"), current_etag),
                    tokens: Vec::new(),
                });
            }
            if let Some(prefix) = row.get::<_, Option<String>>("token_prefix") {
                out.last_mut()
                    .expect("pushed above")
                    .tokens
                    .push(TokenView {
                        prefix,
                        created_at: row.get("token_created_at"),
                        last_used_at: row.get("token_last_used_at"),
                    });
            }
        }
        Ok(out)
    }

    /// Registers a data plane called `name` with its first token, as `caller`, who must be a
    /// superuser. The answer is the only place the token ever appears.
    pub async fn register_data_plane(
        &self,
        caller: Uuid,
        name: &str,
    ) -> Result<IssuedToken, WriteError> {
        retrying(move || self.try_register_data_plane(caller, name)).await
    }

    async fn try_register_data_plane(
        &self,
        caller: Uuid,
        name: &str,
    ) -> Result<IssuedToken, WriteError> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let actor = decide(&tx, caller).await?;
        // Two registering one name at once meet here: the second waits for the first, then
        // inserts nothing and is refused.
        let Some(row) = tx
            .query_opt(
                "insert into data_planes (name) values ($1)
                 on conflict (name) do nothing returning id",
                &[&name],
            )
            .await?
        else {
            return Err(
                Refusal::Conflict(format!("A data plane named {name} already exists.")).into(),
            );
        };
        let id: Uuid = row.get("id");
        let (token, prefix) = draw();
        insert_token(&tx, id, &token, &prefix).await?;
        audit(
            &tx,
            &actor,
            Entry {
                action: "create",
                object_kind: "data_plane",
                object_id: Some(id),
                workspace: None,
                before: None,
                after: Some(serde_json::json!({ "name": name, "tokens": [&prefix] })),
            },
        )
        .await?;
        tx.commit().await?;
        Ok(IssuedToken {
            name: name.to_string(),
            token,
            prefix,
        })
    }

    /// Issues another token to the data plane called `name`, as a superuser: the first half of
    /// rotating one. The answer is the only place the token ever appears.
    pub async fn issue_data_plane_token(
        &self,
        caller: Uuid,
        name: &str,
    ) -> Result<IssuedToken, WriteError> {
        retrying(move || self.try_issue_data_plane_token(caller, name)).await
    }

    async fn try_issue_data_plane_token(
        &self,
        caller: Uuid,
        name: &str,
    ) -> Result<IssuedToken, WriteError> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let actor = decide(&tx, caller).await?;
        // `for share`, so the data plane cannot be deleted between this read and the insert, and
        // a delete's list of the tokens that went with it is complete.
        let Some(row) = tx
            .query_opt(
                "select id from data_planes where name = $1 for share",
                &[&name],
            )
            .await?
        else {
            return Err(Refusal::NotFound(format!("There is no data plane named {name}.")).into());
        };
        let (token, prefix) = draw();
        let token_id = insert_token(&tx, row.get("id"), &token, &prefix).await?;
        audit(
            &tx,
            &actor,
            Entry {
                action: "create",
                object_kind: "data_plane_token",
                object_id: Some(token_id),
                workspace: None,
                before: None,
                after: Some(serde_json::json!({ "data_plane": name, "prefix": prefix })),
            },
        )
        .await?;
        tx.commit().await?;
        Ok(IssuedToken {
            name: name.to_string(),
            token,
            prefix,
        })
    }

    /// Revokes the token of the data plane called `name` that begins `prefix`, as a superuser. A
    /// data plane presenting it is refused from its next call.
    pub async fn revoke_data_plane_token(
        &self,
        caller: Uuid,
        name: &str,
        prefix: &str,
    ) -> Result<(), WriteError> {
        retrying(move || self.try_revoke_data_plane_token(caller, name, prefix)).await
    }

    async fn try_revoke_data_plane_token(
        &self,
        caller: Uuid,
        name: &str,
        prefix: &str,
    ) -> Result<(), WriteError> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let actor = decide(&tx, caller).await?;
        let Some(row) = tx
            .query_opt(
                "select t.id from data_plane_tokens t join data_planes d on d.id = t.data_plane_id
                  where d.name = $1 and t.token_prefix = $2
                    for update of t",
                &[&name, &prefix],
            )
            .await?
        else {
            return Err(
                Refusal::NotFound(format!("There is no token {prefix} for {name}.")).into(),
            );
        };
        let id: Uuid = row.get("id");
        tx.execute("delete from data_plane_tokens where id = $1", &[&id])
            .await?;
        audit(
            &tx,
            &actor,
            Entry {
                action: "delete",
                object_kind: "data_plane_token",
                object_id: Some(id),
                workspace: None,
                before: Some(serde_json::json!({ "data_plane": name, "prefix": prefix })),
                after: None,
            },
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Deletes the data plane called `name` and its tokens, as a superuser. The audit entry lists
    /// the prefixes of the tokens that went with it.
    pub async fn delete_data_plane(&self, caller: Uuid, name: &str) -> Result<(), WriteError> {
        retrying(move || self.try_delete_data_plane(caller, name)).await
    }

    async fn try_delete_data_plane(&self, caller: Uuid, name: &str) -> Result<(), WriteError> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let actor = decide(&tx, caller).await?;
        let Some(row) = tx
            .query_opt(
                "select id from data_planes where name = $1 for update",
                &[&name],
            )
            .await?
        else {
            return Err(Refusal::NotFound(format!("There is no data plane named {name}.")).into());
        };
        let id: Uuid = row.get("id");
        // Issuing holds the data plane `for share`, so no token can be added between this read
        // and the delete: the `for update` above waits for it, and it for this.
        let tokens: Vec<String> = tx
            .query(
                "select token_prefix from data_plane_tokens where data_plane_id = $1
                  order by created_at, token_prefix",
                &[&id],
            )
            .await?
            .iter()
            .map(|r| r.get(0))
            .collect();
        // The tokens go with it by `on delete cascade`.
        tx.execute("delete from data_planes where id = $1", &[&id])
            .await?;
        audit(
            &tx,
            &actor,
            Entry {
                action: "delete",
                object_kind: "data_plane",
                object_id: Some(id),
                workspace: None,
                before: Some(serde_json::json!({ "name": name, "tokens": tokens })),
                after: None,
            },
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
}
