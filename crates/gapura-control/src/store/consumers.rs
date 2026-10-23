//! Consumers, their keys, and key_auth, JWT and rate_limit policies as the console reads and
//! writes them.
//!
//! Each write is one transaction in the services slice's order: rights re-read locked and
//! decided by `configuration::allowed`; the changed row locked; one audit row. A key is stored as
//! its SHA-256 and a 13-character prefix; the key itself leaves this module only in the issue
//! answer, and the audit row records its prefix and expiry.
//!
//! A policy write takes its locks in one order: the caller's grant rows `FOR SHARE`; the service
//! or route it targets `FOR SHARE`, so the target cannot be deleted under it; the consumer it is
//! for, `FOR SHARE`, likewise; the policy row `FOR UPDATE`; `config_state`, through the trigger.
//! Only an enabled `key_auth`, `jwt` or `rate_limit` row is a policy here, as it is to the
//! compiler, and only a `rate_limit` row may be a consumer's own; a disabled one, which only SQL
//! written by hand can make, reads as none, and switching the requirement on takes it over.

use super::configuration::{decide, json, updated_at};
use super::grants::{audit, retrying, Entry};
use super::{hash, hex, Store, WriteError, PREFIX_LEN, RATE_LIMIT};
use crate::configuration::Action;
use crate::consumers::{
    shown_by, usable_keys, ConsumerView, IssuedKey, JwtDocument, JwtView, KeyView, Limit,
    PolicyView, RateLimitView, Target,
};
use crate::grants::Refusal;
use anyhow::{Context, Result};
use gapura_core::config::JwtPolicy;
use tokio_postgres::Transaction;
use uuid::Uuid;

/// The service or route `target` names in `workspace`, read `FOR SHARE`, as the `plugins` column
/// that points at it and its id; `None` for the whole workspace.
pub(super) async fn target_row(
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

/// The `name` policy row on a target `target_row` resolved, for the consumer `consumer_row`
/// resolved or for none, read `FOR UPDATE`: its id, its configuration, whether it is enabled,
/// and its `updated_at` as the API shows it. A consumer's own row and the row on everyone are two
/// rows on one target, and each write reads only its own -- `is not distinct from` matches a
/// null consumer to the row with none.
pub(super) async fn plugin_row(
    tx: &Transaction<'_>,
    workspace: Uuid,
    resolved: Option<(&str, Uuid)>,
    consumer: Option<Uuid>,
    name: &str,
) -> Result<Option<(Uuid, serde_json::Value, bool, String)>, WriteError> {
    let row = match resolved {
        None => {
            tx.query_opt(
                &format!(
                    "select id, config, enabled, {} as updated_at from plugins
                      where workspace_id = $1 and name = $2 and service_id is null
                        and route_id is null and consumer_id is not distinct from $3
                        for update",
                    updated_at("updated_at")
                ),
                &[&workspace, &name, &consumer],
            )
            .await?
        }
        Some((column, id)) => {
            tx.query_opt(
                &format!(
                    "select id, config, enabled, {} as updated_at from plugins
                      where {column} = $1 and name = $2 and consumer_id is not distinct from $3
                        for update",
                    updated_at("updated_at")
                ),
                &[&id, &name, &consumer],
            )
            .await?
        }
    };
    Ok(row.map(|r| {
        (
            r.get("id"),
            r.get("config"),
            r.get("enabled"),
            r.get("updated_at"),
        )
    }))
}

/// The consumer `name` names in `workspace`, read `FOR SHARE` so it cannot be deleted under the
/// write, as `target_row` holds the route or service; `None` for a policy on everyone.
async fn consumer_row(
    tx: &Transaction<'_>,
    workspace: Uuid,
    name: Option<&str>,
) -> Result<Option<Uuid>, WriteError> {
    let Some(name) = name else {
        return Ok(None);
    };
    let Some(row) = tx
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
    Ok(Some(row.get("id")))
}

/// Whether a policy write was made from a fresh read (#197, #223): `shown` is the `updated_at` a
/// read shows of the requirement set on the target, and `seen` the one the caller sent. A `PUT`
/// creates or replaces, so a caller that sends no stamp says it saw no requirement there:
/// replacing one it never saw is as stale as replacing one it saw older, and so is sending a
/// stamp for one that has gone since.
///
/// `shown` is `None` where no read shows a stamp: no row, a disabled one, which reads as none, or
/// one whose configuration does not fit, which fails every read. Such a row can only be replaced
/// with no stamp, so a write can still put right what SQL by hand broke, and nothing a reader saw
/// is lost by it.
pub(super) fn fresh(shown: Option<&str>, seen: Option<&str>) -> Result<(), WriteError> {
    if shown == seen {
        Ok(())
    } else {
        Err(WriteError::Stale)
    }
}

/// The `key_auth` row on a target `target_row` resolved, read `FOR UPDATE`: its id, its header
/// and whether it is enabled. A row with no header reads as `None`, which no header equals.
async fn policy_row(
    tx: &Transaction<'_>,
    workspace: Uuid,
    resolved: Option<(&str, Uuid)>,
) -> Result<Option<(Uuid, Option<String>, bool, String)>, WriteError> {
    let row = plugin_row(tx, workspace, resolved, None, "key_auth").await?;
    Ok(row.map(|(id, config, enabled, updated_at)| {
        let header = config
            .get("header")
            .and_then(|h| h.as_str())
            .map(str::to_string);
        (id, header, enabled, updated_at)
    }))
}

/// The `{target, kind, issuer, audience, keys}` an audit row records of a JWT requirement, and its
/// `jwks_uri` when it has one: what it asks for, never the keys themselves.
fn jwt_audit(target: &Target, policy: &JwtPolicy) -> serde_json::Value {
    let mut audit = serde_json::json!({
        "target": target.as_text(),
        "kind": "jwt",
        "issuer": policy.issuer,
        "audience": policy.audience,
        "keys": usable_keys(&policy.jwks),
    });
    if let Some(uri) = &policy.jwks_uri {
        audit["jwks_uri"] = serde_json::json!(uri);
    }
    audit
}

/// A stored `jwt` configuration as the policy the compiler reads it as. One that does not fit
/// fails the compiler too, so it is an error here, not a requirement shown as none.
fn stored_jwt(config: serde_json::Value) -> anyhow::Result<JwtPolicy> {
    serde_json::from_value(config).context("a jwt policy does not fit its shape")
}

/// The `{target, kind, limit, per}` an audit row records of a request limit, with `consumer` when
/// it is a consumer's own and `by` when it counts by something other than the address, so a row
/// on everyone counted by address reads as it did before either existed.
fn rate_limit_audit(target: &Target, consumer: Option<&str>, limit: &Limit) -> serde_json::Value {
    let mut entry = serde_json::json!({
        "target": target.as_text(),
        "kind": "rate_limit",
        "limit": limit.limit,
        "per": limit.per,
    });
    if let Some(consumer) = consumer {
        entry["consumer"] = consumer.into();
    }
    if let Some(by) = shown_by(&limit.by) {
        entry["by"] = by.into();
    }
    entry
}

/// The `{target, limit, per, by}` the audit entry of a deleted consumer records of a limit of its
/// own that went with it: what `rate_limit_audit` records, without the kind and the consumer,
/// which the entry already says, and `by` only when it counts by something other than the
/// address. A row the compiler could not read is recorded by its target alone.
fn own_limit_audit(target: &Target, config: serde_json::Value) -> serde_json::Value {
    let mut entry = serde_json::json!({ "target": target.as_text() });
    if let Some(limit) = Limit::from_config(config) {
        entry["limit"] = limit.limit.into();
        entry["per"] = serde_json::json!(limit.per);
        if let Some(by) = shown_by(&limit.by) {
            entry["by"] = by.into();
        }
    }
    entry
}

/// A stored `rate_limit` configuration as the limit the compiler reads it as. One that does not
/// fit fails the compiler too, so it is an error here, not a limit shown as none.
fn stored_rate_limit(config: serde_json::Value) -> anyhow::Result<Limit> {
    Limit::from_config(config).context("a rate_limit policy does not fit its shape")
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
                workspace: Some(workspace),
                before: None,
                after: Some(serde_json::json!({ "name": name })),
            },
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Deletes the consumer called `name`, its keys and its own request limits, which needs the
    /// admin role. The audit entry lists the prefixes of the keys that went with it and, under
    /// `limits`, each limit of its own that did -- its target, limit and window, and what it
    /// counted by when that was not the address -- in the order `rate_limits` lists them, since
    /// no policy entry records their going. A consumer with no limits of its own has no `limits`
    /// in its entry, which so reads as it did before a consumer could have any.
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
        // Its own limits go with it by `on delete cascade` too, unseen unless this entry records
        // them. A limit write holds the consumer `for share`, as issuing does, so none can change
        // between this read and the delete. Only this workspace's rows are read, and their
        // service or route is joined by this workspace too, so the entry never names another
        // workspace's: a row on one, which only SQL written by hand can make, is left out rather
        // than recorded as a limit on this whole workspace.
        let limits: Vec<serde_json::Value> = tx
            .query(
                "select p.config, s.name as service, r.name as route
                   from plugins p
                   left join services s
                          on s.id = p.service_id and s.workspace_id = p.workspace_id
                   left join routes r on r.id = p.route_id and r.workspace_id = p.workspace_id
                  where p.consumer_id = $1 and p.workspace_id = $2 and p.name = $3 and p.enabled
                    and (p.service_id is null) = (s.id is null)
                    and (p.route_id is null) = (r.id is null)
                  order by case when p.service_id is not null then 1
                                when p.route_id is not null then 2
                                else 0 end,
                           coalesce(s.name, r.name)",
                &[&id, &workspace, &RATE_LIMIT],
            )
            .await?
            .iter()
            .map(|r| {
                own_limit_audit(
                    &target_of(r.get("service"), r.get("route")),
                    r.get("config"),
                )
            })
            .collect();
        let mut before = serde_json::json!({ "name": name, "keys": keys });
        if !limits.is_empty() {
            before["limits"] = limits.into();
        }
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
                workspace: Some(workspace),
                before: Some(before),
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
                workspace: Some(workspace),
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
                workspace: Some(workspace),
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
                &format!(
                    "select p.config->>'header' as header, s.name as service, r.name as route,
                            {} as updated_at
                       from plugins p
                       left join services s on s.id = p.service_id
                       left join routes r on r.id = p.route_id
                      where p.workspace_id = $1 and p.name = 'key_auth' and p.consumer_id is null
                        and p.enabled
                      order by case when p.service_id is not null then 1
                                    when p.route_id is not null then 2
                                    else 0 end,
                               coalesce(s.name, r.name)",
                    updated_at("p.updated_at")
                ),
                &[&workspace],
            )
            .await?;
        rows.iter()
            .map(|row| {
                let target = target_of(row.get("service"), row.get("route"));
                // The compiler refuses such a row too, so it is an error here, not a policy
                // listed with no header.
                let header: Option<String> = row.get("header");
                let header = header.ok_or_else(|| {
                    anyhow::anyhow!("the key_auth policy on {} has no header", target.as_text())
                })?;
                Ok(PolicyView {
                    target: target.as_text(),
                    header,
                    updated_at: row.get("updated_at"),
                })
            })
            .collect()
    }

    /// Requires a key on `target`, read from `header`, which needs the editor role, when the
    /// caller saw no requirement set there: one set meanwhile is not replaced, but answered as
    /// `replace_key_auth` answers a stale stamp.
    pub async fn put_key_auth(
        &self,
        caller: Uuid,
        workspace: Uuid,
        target: &Target,
        header: &str,
    ) -> Result<(), WriteError> {
        retrying(move || self.try_put_key_auth(caller, workspace, target, header, None)).await
    }

    /// Requires a key on `target`, read from `header`, in place of the requirement set there,
    /// when `seen_updated_at` is its stamp as last read. Switching a requirement on again with
    /// the header it already reads writes nothing.
    pub async fn replace_key_auth(
        &self,
        caller: Uuid,
        workspace: Uuid,
        target: &Target,
        header: &str,
        seen_updated_at: &str,
    ) -> Result<(), WriteError> {
        retrying(move || {
            self.try_put_key_auth(caller, workspace, target, header, Some(seen_updated_at))
        })
        .await
    }

    async fn try_put_key_auth(
        &self,
        caller: Uuid,
        workspace: Uuid,
        target: &Target,
        header: &str,
        seen_updated_at: Option<&str>,
    ) -> Result<(), WriteError> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let actor = decide(&tx, caller, workspace, Action::Write).await?;
        let resolved = target_row(&tx, workspace, target).await?;
        let after = serde_json::json!({ "target": target.as_text(), "header": header });
        let row = policy_row(&tx, workspace, resolved).await?;
        let shown = row.as_ref().filter(|r| r.2 && r.1.is_some());
        fresh(shown.map(|r| r.3.as_str()), seen_updated_at)?;
        let (action, id, before) = match row {
            // Nothing to write, so nothing to audit and nothing for the data planes to reload.
            Some((_, Some(current), true, _)) if current == header => return Ok(()),
            // Another header, or a disabled row: that is no requirement, so taking it over is
            // audited as creating one.
            Some((id, current, enabled, _)) => {
                tx.execute(
                    "update plugins set config = config || jsonb_build_object('header', $2::text),
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
                workspace: Some(workspace),
                before,
                after: Some(after),
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
        let Some((id, header, true, _)) = policy_row(&tx, workspace, resolved).await? else {
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
                workspace: Some(workspace),
                before: Some(serde_json::json!({ "target": target.as_text(), "header": header })),
                after: None,
            },
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// A workspace's JWT requirements, in the order `policies` lists key requirements, each with
    /// how many usable keys its JWKS holds.
    pub async fn jwt_policies(&self, workspace: Uuid) -> Result<Vec<JwtView>> {
        let client = self.pool.get().await?;
        let rows = client
            .query(
                "select p.config, s.name as service, r.name as route
                   from plugins p
                   left join services s on s.id = p.service_id
                   left join routes r on r.id = p.route_id
                  where p.workspace_id = $1 and p.name = 'jwt' and p.consumer_id is null
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
                let target = target_of(row.get("service"), row.get("route"));
                let policy = stored_jwt(row.get("config"))?;
                Ok(JwtView {
                    target: target.as_text(),
                    keys: usable_keys(&policy.jwks),
                    issuer: policy.issuer,
                    audience: policy.audience,
                    jwks_uri: policy.jwks_uri,
                })
            })
            .collect()
    }

    /// The JWT requirement on `target` itself, with its JWKS; `None` when it has none of its own.
    pub async fn jwt_policy(
        &self,
        workspace: Uuid,
        target: &Target,
    ) -> Result<Option<JwtDocument>> {
        let client = self.pool.get().await?;
        let (join, filter, name) = match target {
            Target::Workspace => (
                "",
                "p.service_id is null and p.route_id is null and $2::text is null",
                None,
            ),
            Target::Service(name) => (
                "join services t on t.id = p.service_id",
                "t.name = $2",
                Some(name.as_str()),
            ),
            Target::Route(name) => (
                "join routes t on t.id = p.route_id",
                "t.name = $2",
                Some(name.as_str()),
            ),
        };
        let row = client
            .query_opt(
                &format!(
                    "select p.config, {} as updated_at from plugins p {join}
                      where p.workspace_id = $1 and p.name = 'jwt' and p.consumer_id is null
                        and p.enabled and {filter}",
                    updated_at("p.updated_at")
                ),
                &[&workspace, &name],
            )
            .await?;
        row.map(|row| {
            let policy = stored_jwt(row.get("config"))?;
            Ok(JwtDocument {
                target: target.as_text(),
                issuer: policy.issuer,
                audience: policy.audience,
                jwks: policy.jwks,
                jwks_uri: policy.jwks_uri,
                jwks_ca_pem: policy.jwks_ca_pem,
                updated_at: row.get("updated_at"),
            })
        })
        .transpose()
    }

    /// Requires a JWT on `target` that `policy` accepts, which needs the editor role, when
    /// `seen_updated_at` is the stamp of the requirement set there as last read, or `None` when
    /// none was. The same requirement again writes nothing.
    pub async fn put_jwt(
        &self,
        caller: Uuid,
        workspace: Uuid,
        target: &Target,
        policy: &JwtPolicy,
        seen_updated_at: Option<&str>,
    ) -> Result<(), WriteError> {
        // seen is moved into the closure (owned, not borrowed), because the Future must
        // outlive the function. The other arguments stay borrowed from &self.
        let seen = seen_updated_at.map(str::to_string);
        retrying(move || {
            let seen = seen.clone();
            async move {
                self.try_put_jwt(caller, workspace, target, policy, seen.as_deref())
                    .await
            }
        })
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn try_put_jwt(
        &self,
        caller: Uuid,
        workspace: Uuid,
        target: &Target,
        policy: &JwtPolicy,
        seen_updated_at: Option<&str>,
    ) -> Result<(), WriteError> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let actor = decide(&tx, caller, workspace, Action::Write).await?;
        let resolved = target_row(&tx, workspace, target).await?;
        let config = json(policy);
        let row = plugin_row(&tx, workspace, resolved, None, "jwt").await?;
        // #197: otherwise a second editor's rotation is undone silently by a stale sheet.
        let shown = row
            .as_ref()
            .filter(|r| r.2 && stored_jwt(r.1.clone()).is_ok());
        fresh(shown.map(|r| r.3.as_str()), seen_updated_at)?;
        let (action, id, before) = match row {
            Some((id, current, enabled, _)) => {
                let current = stored_jwt(current).ok();
                // Nothing to write, so nothing to audit and nothing for the data planes to reload.
                if enabled && current.as_ref() == Some(policy) {
                    return Ok(());
                }
                tx.execute(
                    "update plugins set config = $2, enabled = true, updated_at = now()
                      where id = $1",
                    &[&id, &config],
                )
                .await?;
                // A disabled row is no requirement, so taking it over is audited as creating one.
                let before = if enabled {
                    current.map(|c| jwt_audit(target, &c))
                } else {
                    None
                };
                (if enabled { "update" } else { "create" }, id, before)
            }
            // Two writers meet at the unique index, as switching key_auth on does.
            None => {
                let (service, route) = match resolved {
                    Some(("service_id", id)) => (Some(id), None),
                    Some((_, id)) => (None, Some(id)),
                    None => (None, None),
                };
                let row = tx
                    .query_one(
                        "insert into plugins (workspace_id, name, config, service_id, route_id)
                         values ($1, 'jwt', $2, $3, $4)
                         returning id",
                        &[&workspace, &config, &service, &route],
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
                workspace: Some(workspace),
                before,
                after: Some(jwt_audit(target, policy)),
            },
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Stops requiring a JWT on `target`, which needs the editor role, like requiring one.
    pub async fn delete_jwt(
        &self,
        caller: Uuid,
        workspace: Uuid,
        target: &Target,
    ) -> Result<(), WriteError> {
        retrying(move || self.try_delete_jwt(caller, workspace, target)).await
    }

    async fn try_delete_jwt(
        &self,
        caller: Uuid,
        workspace: Uuid,
        target: &Target,
    ) -> Result<(), WriteError> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let actor = decide(&tx, caller, workspace, Action::Write).await?;
        let resolved = target_row(&tx, workspace, target).await?;
        let Some((id, config, true, _)) = plugin_row(&tx, workspace, resolved, None, "jwt").await?
        else {
            return Err(
                Refusal::NotFound(format!("{} has no JWT requirement.", target.as_text())).into(),
            );
        };
        tx.execute("delete from plugins where id = $1", &[&id])
            .await?;
        // A row the compiler could not read is recorded by what it was, as far as it goes.
        let before = match stored_jwt(config) {
            Ok(policy) => jwt_audit(target, &policy),
            Err(_) => serde_json::json!({ "target": target.as_text(), "kind": "jwt" }),
        };
        audit(
            &tx,
            &actor,
            Entry {
                action: "delete",
                object_kind: "policy",
                object_id: Some(id),
                workspace: Some(workspace),
                before: Some(before),
                after: None,
            },
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// A workspace's request limits: those on everyone first, in the order `policies` lists key
    /// requirements, then each consumer's own by consumer, in the same order. A consumer is
    /// joined by its workspace as well as its id, so a limit for a consumer of another workspace,
    /// which only SQL written by hand can attach, never shows that workspace's username: the
    /// compiler refuses such a row, so it is an error here, not a limit listed as one on everyone.
    pub async fn rate_limits(&self, workspace: Uuid) -> Result<Vec<RateLimitView>> {
        let client = self.pool.get().await?;
        let rows = client
            .query(
                &format!(
                    "select p.config, s.name as service, r.name as route, c.username as consumer,
                            p.consumer_id is not null as owned, {} as updated_at
                       from plugins p
                       left join services s on s.id = p.service_id
                       left join routes r on r.id = p.route_id
                       left join consumers c
                              on c.id = p.consumer_id and c.workspace_id = p.workspace_id
                      where p.workspace_id = $1 and p.name = $2 and p.enabled
                      order by c.username nulls first,
                               case when p.service_id is not null then 1
                                    when p.route_id is not null then 2
                                    else 0 end,
                               coalesce(s.name, r.name)",
                    updated_at("p.updated_at")
                ),
                &[&workspace, &RATE_LIMIT],
            )
            .await?;
        rows.iter()
            .map(|row| {
                let target = target_of(row.get("service"), row.get("route"));
                let consumer: Option<String> = row.get("consumer");
                if row.get::<_, bool>("owned") && consumer.is_none() {
                    anyhow::bail!(
                        "the rate_limit policy on {} is for a consumer of another workspace",
                        target.as_text()
                    );
                }
                let limit = stored_rate_limit(row.get("config"))?;
                Ok(RateLimitView {
                    target: target.as_text(),
                    consumer,
                    limit: limit.limit,
                    per: limit.per,
                    by: shown_by(&limit.by),
                    updated_at: row.get("updated_at"),
                })
            })
            .collect()
    }

    /// Limits requests on `target`, for `consumer` alone when one is named, to `limit`, which
    /// needs the editor role, when `seen_updated_at` is the stamp of the limit this write
    /// replaces as last read -- the consumer's own there when one is named, else the one on
    /// everyone -- or `None` when none was. The two are separate rows with stamps of their own,
    /// so a stamp read off one never answers for the other. The same limit again writes nothing.
    pub async fn put_rate_limit(
        &self,
        caller: Uuid,
        workspace: Uuid,
        target: &Target,
        consumer: Option<&str>,
        limit: Limit,
        seen_updated_at: Option<&str>,
    ) -> Result<(), WriteError> {
        retrying(move || {
            self.try_put_rate_limit(
                caller,
                workspace,
                target,
                consumer,
                limit.clone(),
                seen_updated_at,
            )
        })
        .await
    }

    async fn try_put_rate_limit(
        &self,
        caller: Uuid,
        workspace: Uuid,
        target: &Target,
        consumer: Option<&str>,
        limit: Limit,
        seen_updated_at: Option<&str>,
    ) -> Result<(), WriteError> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let actor = decide(&tx, caller, workspace, Action::Write).await?;
        let resolved = target_row(&tx, workspace, target).await?;
        let owner = consumer_row(&tx, workspace, consumer).await?;
        let config = limit.config();
        let row = plugin_row(&tx, workspace, resolved, owner, RATE_LIMIT).await?;
        let shown = row
            .as_ref()
            .filter(|r| r.2 && Limit::from_config(r.1.clone()).is_some());
        fresh(shown.map(|r| r.3.as_str()), seen_updated_at)?;
        let (action, id, before) = match row {
            Some((id, current, enabled, _)) => {
                let current = Limit::from_config(current);
                // Nothing to write, so nothing to audit and nothing for the data planes to reload.
                if enabled && current.as_ref() == Some(&limit) {
                    return Ok(());
                }
                tx.execute(
                    "update plugins set config = $2, enabled = true, updated_at = now()
                      where id = $1",
                    &[&id, &config],
                )
                .await?;
                // A disabled row is no limit, so taking it over is audited as creating one.
                let before = if enabled {
                    current.map(|c| rate_limit_audit(target, consumer, &c))
                } else {
                    None
                };
                (if enabled { "update" } else { "create" }, id, before)
            }
            // Two writers meet at the unique index, as switching key_auth on does: the one on
            // everyone or the consumer's own, whichever this write is.
            None => {
                let (service, route) = match resolved {
                    Some(("service_id", id)) => (Some(id), None),
                    Some((_, id)) => (None, Some(id)),
                    None => (None, None),
                };
                let row = tx
                    .query_one(
                        "insert into plugins
                                (workspace_id, name, config, service_id, route_id, consumer_id)
                         values ($1, $2, $3, $4, $5, $6)
                         returning id",
                        &[&workspace, &RATE_LIMIT, &config, &service, &route, &owner],
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
                workspace: Some(workspace),
                before,
                after: Some(rate_limit_audit(target, consumer, &limit)),
            },
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Stops limiting requests on `target`, for `consumer` alone when one is named, which needs
    /// the editor role, like limiting them. Only that one limit goes: the consumer's own leaves
    /// the one on everyone in place, and the other way round.
    pub async fn delete_rate_limit(
        &self,
        caller: Uuid,
        workspace: Uuid,
        target: &Target,
        consumer: Option<&str>,
    ) -> Result<(), WriteError> {
        retrying(move || self.try_delete_rate_limit(caller, workspace, target, consumer)).await
    }

    async fn try_delete_rate_limit(
        &self,
        caller: Uuid,
        workspace: Uuid,
        target: &Target,
        consumer: Option<&str>,
    ) -> Result<(), WriteError> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let actor = decide(&tx, caller, workspace, Action::Write).await?;
        let resolved = target_row(&tx, workspace, target).await?;
        let owner = consumer_row(&tx, workspace, consumer).await?;
        let Some((id, config, true, _)) =
            plugin_row(&tx, workspace, resolved, owner, RATE_LIMIT).await?
        else {
            let whose = consumer.map(|c| format!(" for {c}")).unwrap_or_default();
            return Err(Refusal::NotFound(format!(
                "{} has no request limit{whose}.",
                target.as_text()
            ))
            .into());
        };
        tx.execute("delete from plugins where id = $1", &[&id])
            .await?;
        // A row the compiler could not read is recorded by what it was, as far as it goes: its
        // target, its kind and, when it is a consumer's own, whose it was.
        let before = match Limit::from_config(config) {
            Some(limit) => rate_limit_audit(target, consumer, &limit),
            None => {
                let mut entry =
                    serde_json::json!({ "target": target.as_text(), "kind": "rate_limit" });
                if let Some(consumer) = consumer {
                    entry["consumer"] = consumer.into();
                }
                entry
            }
        };
        audit(
            &tx,
            &actor,
            Entry {
                action: "delete",
                object_kind: "policy",
                object_id: Some(id),
                workspace: Some(workspace),
                before: Some(before),
                after: None,
            },
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
}

/// The target a policy row is attached to, from the names of its service and route.
pub(super) fn target_of(service: Option<String>, route: Option<String>) -> Target {
    match (service, route) {
        (Some(service), _) => Target::Service(service),
        (None, Some(route)) => Target::Route(route),
        (None, None) => Target::Workspace,
    }
}
