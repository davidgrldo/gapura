-- Deleting a workspace sets `audit_log.workspace_id` to null on every entry about it, and without
-- an index that is a scan of the whole trail, under the workspace's row lock, which writes into
-- that workspace wait on. Partial, because most entries name no workspace.
create index audit_log_workspace on audit_log (workspace_id) where workspace_id is not null;
