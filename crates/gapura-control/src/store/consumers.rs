//! Consumers, their keys and key_auth policies as the console reads and writes them.
//!
//! Each write is one transaction in the services slice's order: rights re-read locked and
//! decided by `configuration::allowed`; the changed row locked; one audit row. A key is stored as
//! its SHA-256 and a 13-character prefix; the key itself leaves this module only in the issue
//! answer, and the audit row records its prefix and expiry.
//!
//! A policy write takes its locks in one order: the caller's grant rows `FOR SHARE`; the service
//! or route it targets `FOR SHARE`, so the target cannot be deleted under it; the policy row
//! `FOR UPDATE`; `config_state`, through the trigger. Only an enabled `key_auth` row with no
//! consumer is a policy here, as it is to the compiler; a disabled one, which only SQL written by
//! hand can make, reads as none, and switching key_auth on takes it over.

use super::configuration::{decide, json, updated_at};
use super::grants::{audit, retrying, Entry};
use super::{hash, hex, Store, WriteError, PREFIX_LEN};
use crate::configuration::Action;
use crate::consumers::{ConsumerView, IssuedKey, KeyView, PolicyView, Target};
use crate::grants::Refusal;
use anyhow::Result;
use tokio_postgres::Transaction;
use uuid::Uuid;

/// The service or route `target` names in `workspace`, read `FOR SHARE`, as the `plugins` column
/// that points at it and its id; `None` for the whole workspace.
async fn target_row(
    tx: &Transaction<'_>,
    workspace: Uuid,
    target: &Target,
) -> Result<Option<(&'static str, Uuid)>, WriteError> {
    let (table, column, name) = match target {
        Target::Workspace => return Ok(None),
        Target::Service(name) => ("service", "service_id", name),
        Target::Route(name) => ("route", "route_id", name),
    };
    let Some(row) = tx
        .query_opt(
            &format!("select id from {table}s where workspace_id = $1 and name = $2 for share"),
            &[&workspace, name],
        )
        .await?
    else {
        return Err(Refusal::NotFound(format!(
            "There is no {table} named {name} in this workspace."
        ))
        .into());
    };
    Ok(Some((column, row.get("id"))))
}

/// The `key_auth` row on a target `target_row` resolved, read `FOR UPDATE`: its id, its header
/// and whether it is enabled. A row with no header reads as `None`, which no header equals.
async fn policy_row(
    tx: &Transaction<'_>,
    workspace: Uuid,
    resolved: Option<(&str, Uuid)>,
) -> Result<Option<(Uuid, Option<String>, bool)>, WriteError> {
    let row = match resolved {
        None => {
            tx.query_opt(
                "select id, config->>'header' as header, enabled from plugins
                  where workspace_id = $1 and name = 'key_auth' and service_id is null
                    and route_id is null and consumer_id is null
                    for update",
                &[&workspace],
            )
            .await?
        }
        Some((column, id)) => {
            tx.query_opt(
                &format!(
                    "select id, config->>'header' as header, enabled from plugins
                      where {column} = $1 and name = 'key_auth' for update"
                ),
                &[&id],
            )
            .await?
        }
    };
    Ok(row.map(|r| (r.get("id"), r.get("header"), r.get("enabled"))))
}

impl Store {
    /// A workspace's consumers by name, each with its keys, newest first.
    pub async fn consumers(&self, workspace: Uuid) -> Result<Vec<ConsumerView>> {
        let client = self.pool.get().await?;
        let rows = client
            .query(
                &format!(
                    "select c.username as name, k.key_prefix, {} as created_at, {} as expires_at,
                            coalesce(k.expires_at <= now(), false) as expired
                       from consumers c left join consumer_keys k on k.consumer_id = c.id
                      where c.workspace_id = $1
                      order by c.username, k.created_at desc",
                    updated_at("k.created_at"),
                    updated_at("k.expires_at")
                ),
                &[&workspace],
            )
            .await?;
        // `consumers.username` is the column; the API calls it name. Rows come grouped by consumer.
        let mut out: Vec<ConsumerView> = Vec::new();
        for row in rows {
            let name: String = row.get("name");
            if out.last().is_none_or(|c| c.name != name) {
                out.push(ConsumerView {
                    name,
                    keys: Vec::new(),
                });
            }
            if let Some(prefix) = row.get::<_, Option<String>>("key_prefix") {
                out.last_mut().expect("pushed above").keys.push(KeyView {
                    prefix,
                    created_at: row.get("created_at"),
                    expires_at: row.get("expires_at"),
                    expired: row.get("expired"),
                });
            }
        }
        Ok(out)
    }

    /// Creates a consumer called `name` in `workspace` as `caller`, who needs the editor role
    /// there.
    pub async fn create_consumer(
        &self,
        caller: Uuid,
        workspace: Uuid,
        name: &str,
    ) -> Result<(), WriteError> {
        retrying(move || self.try_create_consumer(caller, workspace, name)).await
    }

    async fn try_create_consumer(
        &self,
        caller: Uuid,
        workspace: Uuid,
        name: &str,
    ) -> Result<(), WriteError> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let actor = decide(&tx, caller, workspace, Action::Write).await?;
        let Some(row) = tx
            .query_opt(
                "insert into consumers (workspace_id, username) values ($1, $2)
                 on conflict (workspace_id, username) do nothing returning id",
                &[&workspace, &name],
            )
            .await?
        else {
            return Err(Refusal::Conflict(format!(
                "A consumer named {name} already exists in this workspace."
            ))
            .into());
        };
        audit(
            &tx,
            &actor,
            Entry {
                action: "create",
                object_kind: "consumer",
                object_id: Some(row.get("id")),
                workspace,
                before: None,
                after: Some(serde_json::json!({ "name": name })),
            },
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Deletes the consumer called `name` and its keys, which needs the admin role. The audit
    /// entry lists the prefixes of the keys that went with it.
    pub async fn delete_consumer(
        &self,
        caller: Uuid,
        workspace: Uuid,
        name: &str,
    ) -> Result<(), WriteError> {
        retrying(move || self.try_delete_consumer(caller, workspace, name)).await
    }

    async fn try_delete_consumer(
        &self,
        caller: Uuid,
        workspace: Uuid,
        name: &str,
    ) -> Result<(), WriteError> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let actor = decide(&tx, caller, workspace, Action::Delete).await?;
        let Some(row) = tx
            .query_opt(
                "select id from consumers where workspace_id = $1 and username = $2 for update",
                &[&workspace, &name],
            )
            .await?
        else {
            return Err(Refusal::NotFound(format!(
                "There is no consumer named {name} in this workspace."
            ))
            .into());
        };
        let id: Uuid = row.get("id");
        // Issuing holds the consumer `for share`, so no key can be added between this read and
        // the delete: the `for update` above waits for it, and it for this.
        let keys: Vec<String> = tx
            .query(
                "select key_prefix from consumer_keys where consumer_id = $1 order by created_at",
                &[&id],
            )
            .await?
            .iter()
            .map(|r| r.get(0))
            .collect();
        // The keys go with it by `on delete cascade`.
        tx.execute("delete from consumers where id = $1", &[&id])
            .await?;
        audit(
            &tx,
            &actor,
            Entry {
                action: "delete",
                object_kind: "consumer",
                object_id: Some(id),
                workspace,
                before: Some(serde_json::json!({ "name": name, "keys": keys })),
                after: None,
            },
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Issues a key to the consumer called `name`, which needs the editor role, working until
    /// `expires_at` (RFC 3339) or for good. The answer is the only place the key ever appears.
    pub async fn issue_key(
        &self,
        caller: Uuid,
        workspace: Uuid,
        name: &str,
        expires_at: Option<&str>,
    ) -> Result<IssuedKey, WriteError> {
        retrying(move || self.try_issue_key(caller, workspace, name, expires_at)).await
    }

    async fn try_issue_key(
        &self,
        caller: Uuid,
        workspace: Uuid,
        name: &str,
        expires_at: Option<&str>,
    ) -> Result<IssuedKey, WriteError> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let actor = decide(&tx, caller, workspace, Action::Write).await?;
        let Some(consumer) = tx
            .query_opt(
                "select id from consumers where workspace_id = $1 and username = $2 for share",
                &[&workspace, &name],
            )
            .await?
        else {
            return Err(Refusal::NotFound(format!(
                "There is no consumer named {name} in this workspace."
            ))
            .into());
        };
        // Drawn in the attempt, so a retry after a prefix that is already stored draws another.
        let raw: [u8; 32] = rand::random();
        let key = format!("gpak_{}", hex(&raw));
        let prefix = key[..PREFIX_LEN].to_string();
        // The expiry is read back in the form the list shows, not echoed as sent.
        let row = tx
            .query_one(
                &format!(
                    "insert into consumer_keys (consumer_id, key_prefix, key_hash, expires_at)
                     values ($1, $2, $3, $4::text::timestamptz)
                     returning id, {} as expires_at",
                    updated_at("expires_at")
                ),
                &[
                    &consumer.get::<_, Uuid>("id"),
                    &prefix,
                    &hash(&key),
                    &expires_at,
                ],
            )
            .await?;
        let expires_at: Option<String> = row.get("expires_at");
        audit(
            &tx,
            &actor,
            Entry {
                action: "create",
                object_kind: "consumer_key",
                object_id: Some(row.get("id")),
                workspace,
                before: None,
                after: Some(serde_json::json!({
                    "consumer": name,
                    "prefix": prefix,
                    "expires_at": expires_at,
                })),
            },
        )
        .await?;
        tx.commit().await?;
        Ok(IssuedKey {
            key,
            prefix,
            expires_at,
        })
    }

    /// Revokes the key of the consumer called `name` that begins `prefix`, which needs the admin
    /// role. A request carrying it is refused once the data planes have the next configuration.
    pub async fn revoke_key(
        &self,
        caller: Uuid,
        workspace: Uuid,
        name: &str,
        prefix: &str,
    ) -> Result<(), WriteError> {
        retrying(move || self.try_revoke_key(caller, workspace, name, prefix)).await
    }

    async fn try_revoke_key(
        &self,
        caller: Uuid,
        workspace: Uuid,
        name: &str,
        prefix: &str,
    ) -> Result<(), WriteError> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let actor = decide(&tx, caller, workspace, Action::Delete).await?;
        let Some(row) = tx
            .query_opt(
                &format!(
                    "select k.id, {} as expires_at
                       from consumer_keys k join consumers c on c.id = k.consumer_id
                      where c.workspace_id = $1 and c.username = $2 and k.key_prefix = $3
                        for update of k",
                    updated_at("k.expires_at")
                ),
                &[&workspace, &name, &prefix],
            )
            .await?
        else {
            return Err(Refusal::NotFound(format!("There is no key {prefix} for {name}.")).into());
        };
        let id: Uuid = row.get("id");
        tx.execute("delete from consumer_keys where id = $1", &[&id])
            .await?;
        audit(
            &tx,
            &actor,
            Entry {
                action: "delete",
                object_kind: "consumer_key",
                object_id: Some(id),
                workspace,
                before: Some(serde_json::json!({
                    "consumer": name,
                    "prefix": prefix,
                    "expires_at": row.get::<_, Option<String>>("expires_at"),
                })),
                after: None,
            },
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// A workspace's key requirements: the workspace's own first, then its services', then its
    /// routes', each by name.
    pub async fn policies(&self, workspace: Uuid) -> Result<Vec<PolicyView>> {
        let client = self.pool.get().await?;
        let rows = client
            .query(
                "select p.config->>'header' as header, s.name as service, r.name as route
                   from plugins p
                   left join services s on s.id = p.service_id
                   left join routes r on r.id = p.route_id
                  where p.workspace_id = $1 and p.name = 'key_auth' and p.consumer_id is null
                    and p.enabled
                  order by case when p.service_id is not null then 1
                                when p.route_id is not null then 2
                                else 0 end,
                           coalesce(s.name, r.name)",
                &[&workspace],
            )
            .await?;
        rows.iter()
            .map(|row| {
                let target = match (row.get("service"), row.get("route")) {
                    (Some(service), _) => Target::Service(service),
                    (None, Some(route)) => Target::Route(route),
                    (None, None) => Target::Workspace,
                };
                // The compiler refuses such a row too, so it is an error here, not a policy
                // listed with no header.
                let header: Option<String> = row.get("header");
                let header = header.ok_or_else(|| {
                    anyhow::anyhow!("the key_auth policy on {} has no header", target.as_text())
                })?;
                Ok(PolicyView {
                    target: target.as_text(),
                    header,
                })
            })
            .collect()
    }

    /// Requires a key on `target`, read from `header`, which needs the editor role. Switching
    /// a requirement on again with the header it already reads writes nothing.
    pub async fn put_key_auth(
        &self,
        caller: Uuid,
        workspace: Uuid,
        target: &Target,
        header: &str,
    ) -> Result<(), WriteError> {
        retrying(move || self.try_put_key_auth(caller, workspace, target, header)).await
    }

    async fn try_put_key_auth(
        &self,
        caller: Uuid,
        workspace: Uuid,
        target: &Target,
        header: &str,
    ) -> Result<(), WriteError> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let actor = decide(&tx, caller, workspace, Action::Write).await?;
        let resolved = target_row(&tx, workspace, target).await?;
        let after = PolicyView {
            target: target.as_text(),
            header: header.to_string(),
        };
        let (action, id, before) = match policy_row(&tx, workspace, resolved).await? {
            // Nothing to write, so nothing to audit and nothing for the data planes to reload.
            Some((_, Some(current), true)) if current == header => return Ok(()),
            // Another header, or a disabled row: that is no requirement, so taking it over is
            // audited as creating one.
            Some((id, current, enabled)) => {
                tx.execute(
                    "update plugins set config = jsonb_build_object('header', $2::text),
                            enabled = true, updated_at = now()
                      where id = $1",
                    &[&id, &header],
                )
                .await?;
                let before = enabled
                    .then(|| serde_json::json!({ "target": target.as_text(), "header": current }));
                (if enabled { "update" } else { "create" }, id, before)
            }
            // Two writers switching it on at once meet at the unique index: the second's insert
            // fails, and `retrying` runs it again to find the first's row.
            None => {
                let (service, route) = match resolved {
                    Some(("service_id", id)) => (Some(id), None),
                    Some((_, id)) => (None, Some(id)),
                    None => (None, None),
                };
                let row = tx
                    .query_one(
                        "insert into plugins (workspace_id, name, config, service_id, route_id)
                         values ($1, 'key_auth', jsonb_build_object('header', $2::text), $3, $4)
                         returning id",
                        &[&workspace, &header, &service, &route],
                    )
                    .await?;
                ("create", row.get("id"), None)
            }
        };
        audit(
            &tx,
            &actor,
            Entry {
                action,
                object_kind: "policy",
                object_id: Some(id),
                workspace,
                before,
                after: Some(json(&after)),
            },
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Stops requiring a key on `target`, which needs the editor role, like switching it on.
    pub async fn delete_key_auth(
        &self,
        caller: Uuid,
        workspace: Uuid,
        target: &Target,
    ) -> Result<(), WriteError> {
        retrying(move || self.try_delete_key_auth(caller, workspace, target)).await
    }

    async fn try_delete_key_auth(
        &self,
        caller: Uuid,
        workspace: Uuid,
        target: &Target,
    ) -> Result<(), WriteError> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let actor = decide(&tx, caller, workspace, Action::Write).await?;
        let resolved = target_row(&tx, workspace, target).await?;
        let Some((id, header, true)) = policy_row(&tx, workspace, resolved).await? else {
            return Err(
                Refusal::NotFound(format!("{} has no key requirement.", target.as_text())).into(),
            );
        };
        tx.execute("delete from plugins where id = $1", &[&id])
            .await?;
        audit(
            &tx,
            &actor,
            Entry {
                action: "delete",
                object_kind: "policy",
                object_id: Some(id),
                workspace,
                before: Some(serde_json::json!({ "target": target.as_text(), "header": header })),
                after: None,
            },
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
}
