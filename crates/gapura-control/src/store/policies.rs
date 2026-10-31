//! The policies `/api/workspaces/{ws}/policies/{kind}` keeps, as the console reads and writes
//! them. Each write is one transaction in the order `consumers`' policy writes take: rights
//! re-read and decided; the service or route it targets `FOR SHARE`; an auth policy's anonymous
//! consumer `FOR SHARE`; the policy row `FOR UPDATE`; one audit row. None of these kinds is ever
//! a consumer's own.

use super::configuration::{decide, updated_at};
use super::consumers::{fresh, plugin_row, target_of, target_row};
use super::grants::{audit, retrying, Entry};
use super::{Store, WriteError};
use crate::configuration::{Action, FieldError};
use crate::consumers::Target;
use crate::grants::Refusal;
use crate::policies::{self, KindPolicyView};
use anyhow::Result;
use gapura_core::config::{AuthPolicy, Plugin};
use uuid::Uuid;

/// The `{target, kind, config}` an audit row records of `plugin`, its `config` in the form
/// [`policies::audited`] gives: a transformer's names without the values it writes.
fn recorded(target: &Target, plugin: &Plugin) -> serde_json::Value {
    serde_json::json!({
        "target": target.as_text(),
        "kind": plugin.kind(),
        "config": policies::audited(plugin),
    })
}

impl Store {
    /// A workspace's policies of `kind`: the one on the whole workspace first, then those on
    /// services, then those on routes, each by name. A row whose configuration this kind does not
    /// read is an error, as it is to the compiler, never a policy listed as none.
    ///
    /// With `values`, for a caller who may change the workspace, each configuration is the
    /// stored one ([`policies::config`]), which the console edits from; without, for one who may
    /// only read it, the form the audit log records ([`policies::audited`]), so a credential a
    /// transformer writes for the upstream reaches no reader by either.
    pub async fn policies_of(
        &self,
        workspace: Uuid,
        kind: &str,
        values: bool,
    ) -> Result<Vec<KindPolicyView>> {
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
                    config: if values {
                        policies::config(&plugin)
                    } else {
                        policies::audited(&plugin)
                    },
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
        // An anonymous consumer the workspace does not have would be dropped when compiled, and
        // every caller without a credential refused, with nothing said where it was written. It is
        // held `for share`, as a consumer's own limit holds its consumer, so it cannot be deleted
        // between this read and the commit; deleted afterwards, the compiler drops it.
        if let Plugin::Auth(AuthPolicy {
            anonymous: Some(name),
            ..
        }) = plugin
        {
            let exists = tx
                .query_opt(
                    "select 1 from consumers where workspace_id = $1 and username = $2 for share",
                    &[&workspace, name],
                )
                .await?
                .is_some();
            if !exists {
                return Err(WriteError::Field(FieldError {
                    field: "anonymous".into(),
                    sentence: format!(
                        "There is no consumer named {name} in this workspace. Create it first, \
                         or name another."
                    ),
                }));
            }
        }
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
                let before = current.map(|c| recorded(target, &c));
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
                after: Some(recorded(target, plugin)),
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
            Ok(plugin) => recorded(target, &plugin),
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
