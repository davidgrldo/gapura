//! The policies `/api/workspaces/{ws}/policies/{kind}` keeps, as the console reads and writes
//! them. Each write is one transaction in the order `consumers`' policy writes take: rights
//! re-read and decided; the service or route it targets `FOR SHARE`; the policy row `FOR
//! UPDATE`; one audit row. None of these kinds is ever a consumer's own.

use super::configuration::{decide, updated_at};
use super::consumers::{fresh, plugin_row, target_of, target_row};
use super::grants::{audit, retrying, Entry};
use super::{Store, WriteError};
use crate::configuration::Action;
use crate::consumers::Target;
use crate::grants::Refusal;
use crate::policies::{self, KindPolicyView};
use anyhow::Result;
use gapura_core::config::Plugin;
use uuid::Uuid;

/// The `{target, kind, config}` an audit row records of a policy.
fn audited(target: &Target, kind: &str, config: serde_json::Value) -> serde_json::Value {
    serde_json::json!({ "target": target.as_text(), "kind": kind, "config": config })
}

impl Store {
    /// A workspace's policies of `kind`: the one on the whole workspace first, then those on
    /// services, then those on routes, each by name. A row whose configuration this kind does not
    /// read is an error, as it is to the compiler, never a policy listed as none.
    pub async fn policies_of(&self, workspace: Uuid, kind: &str) -> Result<Vec<KindPolicyView>> {
        let client = self.pool.get().await?;
        let rows = client
            .query(
                &format!(
                    "select p.config, s.name as service, r.name as route, {} as updated_at
                       from plugins p
                       left join services s on s.id = p.service_id
                       left join routes r on r.id = p.route_id
                      where p.workspace_id = $1 and p.name = $2 and p.enabled
                        and p.consumer_id is null
                      order by case when p.service_id is not null then 1
                                    when p.route_id is not null then 2
                                    else 0 end,
                               coalesce(s.name, r.name)",
                    updated_at("p.updated_at")
                ),
                &[&workspace, &kind],
            )
            .await?;
        rows.iter()
            .map(|row| {
                let target = target_of(row.get("service"), row.get("route"));
                let plugin = policies::parse(kind, row.get("config")).map_err(|e| {
                    anyhow::anyhow!(
                        "the {kind} policy on {} does not fit its shape: {}",
                        target.as_text(),
                        e.sentence
                    )
                })?;
                Ok(KindPolicyView {
                    target: target.as_text(),
                    config: policies::config(&plugin),
                    updated_at: row.get("updated_at"),
                })
            })
            .collect()
    }

    /// Sets `plugin` on `target`, which needs the editor role, when `seen_updated_at` is the
    /// stamp of the policy of its kind this write replaces as last read, or `None` when there was
    /// none. The same policy again writes nothing.
    pub async fn put_policy(
        &self,
        caller: Uuid,
        workspace: Uuid,
        target: &Target,
        plugin: &Plugin,
        seen_updated_at: Option<&str>,
    ) -> Result<(), WriteError> {
        retrying(move || self.try_put_policy(caller, workspace, target, plugin, seen_updated_at))
            .await
    }

    async fn try_put_policy(
        &self,
        caller: Uuid,
        workspace: Uuid,
        target: &Target,
        plugin: &Plugin,
        seen_updated_at: Option<&str>,
    ) -> Result<(), WriteError> {
        let kind = plugin.kind();
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let actor = decide(&tx, caller, workspace, Action::Write).await?;
        let resolved = target_row(&tx, workspace, target).await?;
        let config = policies::config(plugin);
        let row = plugin_row(&tx, workspace, resolved, None, kind).await?;
        // What a read shows of the row: an enabled one this kind reads. A disabled row, or one
        // only SQL by hand could make, shows no stamp, and is replaced without one.
        let current = row
            .as_ref()
            .filter(|r| r.2)
            .and_then(|r| policies::parse(kind, r.1.clone()).ok());
        let shown = row
            .as_ref()
            .filter(|_| current.is_some())
            .map(|r| r.3.as_str());
        fresh(shown, seen_updated_at)?;
        let (action, id, before) = match row {
            Some((id, _, enabled, _)) => {
                // Nothing to write, so nothing to audit and nothing for the data planes to reload.
                if current.as_ref() == Some(plugin) {
                    return Ok(());
                }
                tx.execute(
                    "update plugins set config = $2, enabled = true, updated_at = now()
                      where id = $1",
                    &[&id, &config],
                )
                .await?;
                let before = current.map(|c| audited(target, kind, policies::config(&c)));
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
                         values ($1, $2, $3, $4, $5)
                         returning id",
                        &[&workspace, &kind, &config, &service, &route],
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
                after: Some(audited(target, kind, config)),
            },
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Removes the policy of `kind` from `target`, which needs the editor role, like setting it.
    pub async fn delete_policy(
        &self,
        caller: Uuid,
        workspace: Uuid,
        target: &Target,
        kind: &str,
    ) -> Result<(), WriteError> {
        retrying(move || self.try_delete_policy(caller, workspace, target, kind)).await
    }

    async fn try_delete_policy(
        &self,
        caller: Uuid,
        workspace: Uuid,
        target: &Target,
        kind: &str,
    ) -> Result<(), WriteError> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let actor = decide(&tx, caller, workspace, Action::Write).await?;
        let resolved = target_row(&tx, workspace, target).await?;
        let Some((id, config, true, _)) = plugin_row(&tx, workspace, resolved, None, kind).await?
        else {
            return Err(
                Refusal::NotFound(format!("{} has no {kind} policy.", target.as_text())).into(),
            );
        };
        tx.execute("delete from plugins where id = $1", &[&id])
            .await?;
        // A row the compiler could not read is recorded by its target and kind alone.
        let before = match policies::parse(kind, config) {
            Ok(plugin) => audited(target, kind, policies::config(&plugin)),
            Err(_) => serde_json::json!({ "target": target.as_text(), "kind": kind }),
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
