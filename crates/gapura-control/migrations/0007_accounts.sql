-- A temporary password opens nothing but the screen that replaces it, and a password change
-- signs out every session issued before it. Sessions are signed cookies with no server state, so
-- the cut-off is a time each request compares with the session's own issue time.
alter table users add column must_change_password boolean not null default false;
alter table users add column sessions_valid_after timestamptz;
