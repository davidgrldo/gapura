//! The audit log, read a page at a time, newest first.
//!
//! One statement, so no transaction: a page is what was committed when it ran. Pages are keyed by
//! id rather than counted by offset, so an entry written while someone reads older pages neither
//! shifts them nor shows up twice. Ids come from one sequence, so a larger id is a later write,
//! except between two writes committing at the same moment, whose order does not matter here.

use super::configuration::updated_at;
use super::Store;
use crate::audit::{AuditPage, EntryView, Query, Visible, WorkspaceFilter};
use anyhow::Result;
use uuid::Uuid;

impl Store {
    /// The page `q` asks for, of the entries `visible` lets its caller read.
    pub async fn audit(&self, visible: Visible, q: &Query) -> Result<AuditPage> {
        if q.matches_nothing(&visible) {
            return Ok(AuditPage {
                entries: Vec::new(),
                next: None,
            });
        }
        // `None` for a superuser, who reads every workspace's entries and those with none.
        let within: Option<Vec<Uuid>> = match visible {
            Visible::Everything => None,
            Visible::Workspaces(ids) => Some(ids.into_iter().collect()),
        };
        let no_workspace = q.workspace == WorkspaceFilter::NoWorkspace;
        let named = match &q.workspace {
            WorkspaceFilter::Named(name) => Some(name.as_str()),
            _ => None,
        };
        // One more than the page holds, to tell whether there is a page after it.
        let fetch = q.limit + 1;
        let client = self.pool.get().await?;
        let rows = client
            .query(
                &format!(
                    "select a.id, {} as at, a.actor_name, a.actor_method, a.action,
                            a.object_kind, w.name as workspace, a.before, a.after
                       from audit_log a
                       left join workspaces w on w.id = a.workspace_id
                      where ($1::bigint is null or a.id < $1)
                        and ($2::text is null or a.object_kind = $2)
                        and ($3::uuid[] is null or a.workspace_id = any($3))
                        and (not $4 or a.workspace_id is null)
                        and ($5::text is null or w.name = $5)
                      order by a.id desc
                      limit $6",
                    updated_at("a.at"),
                ),
                &[&q.before, &q.kind, &within, &no_workspace, &named, &fetch],
            )
            .await?;
        let mut entries: Vec<EntryView> = rows
            .iter()
            .map(|row| EntryView {
                id: row.get("id"),
                at: row.get("at"),
                actor: row.get("actor_name"),
                actor_method: row.get("actor_method"),
                action: row.get("action"),
                object_kind: row.get("object_kind"),
                workspace: row.get("workspace"),
                before: row.get("before"),
                after: row.get("after"),
            })
            .collect();
        let more = entries.len() as i64 > q.limit;
        entries.truncate(q.limit as usize);
        let next = if more {
            entries.last().map(|e| e.id)
        } else {
            None
        };
        Ok(AuditPage { entries, next })
    }
}
