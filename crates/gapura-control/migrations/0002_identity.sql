-- Identity moves into the store. A local account signs in against its row here; an account
-- that arrives through OIDC becomes a row the first time it signs in, keyed by the issuer and
-- subject the identity provider vouched for, so that it can be listed and granted roles like any
-- other. Its display name and groups are kept as of that last sign-in.

-- An OIDC row has no username: the name it is known by belongs to the provider, and it can
-- change there without this row having to.
alter table users alter column username drop not null;

-- Unique ignoring case, so `Maya` and `maya` cannot be two accounts that sign in as each other
-- depending on how the name was typed.
alter table users drop constraint users_username_key;
create unique index users_username_lower on users (lower(username));

alter table users
    add column oidc_issuer     text,
    add column oidc_subject    text,
    add column display_name    text,
    add column oidc_groups     text[] not null default '{}',
    add column last_sign_in_at timestamptz;

alter table users add constraint users_oidc_identity unique (oidc_issuer, oidc_subject);

-- Exactly one of the two shapes. Adding the check validates the rows already here, so a row
-- written by hand that fits neither stops this migration instead of passing it silently.
alter table users add constraint users_local_or_oidc check (
       (username is not null and password_hash is not null
        and oidc_issuer is null and oidc_subject is null)
    or (username is null and password_hash is null
        and oidc_issuer is not null and oidc_subject is not null)
);
