-- Which way the person behind an audit entry signed in: with a password kept here, or through
-- the identity provider. The trail has to record how a session arrived, and until now it had
-- nowhere to put it. In store mode an account signs in one way only, so the method recorded is
-- the account's. Nullable, because an entry may have no person behind it at all.
alter table audit_log
    add column actor_method text
    constraint audit_log_actor_method check (actor_method in ('local', 'oidc'));
