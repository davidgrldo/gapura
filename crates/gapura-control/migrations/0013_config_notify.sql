-- Wakes the data planes' held polls (`Prefer: wait`) when the configuration may have changed,
-- instead of one poll interval later. Postgres delivers a notification on commit, so a woken
-- poll never reads before the write is visible, and folds repeats within one transaction into
-- one. The payload is empty: the poll re-reads and compares tags, which a version number would
-- not spare it.
create or replace function bump_config_version() returns trigger language plpgsql as $$
begin
    update config_state set version = version + 1, changed_at = now();
    perform pg_notify('gapura_config', '');
    return null;
end $$;
