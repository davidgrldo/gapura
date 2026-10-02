-- One unit of tenancy. Everything configuration-shaped is scoped to one.
create table workspaces (
    id         uuid primary key default gen_random_uuid(),
    name       text not null unique,
    created_at timestamptz not null default now()
);
insert into workspaces (name) values ('default');

-- The console's two ways in, a local password or OIDC. password_hash is null for
-- people who only ever arrive through OIDC: there is no local credential to store
-- and none should be invented.
create table users (
    id            uuid primary key default gen_random_uuid(),
    username      text not null unique,
    password_hash text,
    superuser     boolean not null default false,
    disabled_at   timestamptz,
    created_at    timestamptz not null default now()
);

create type role_name as enum ('viewer', 'editor', 'admin');

create table role_bindings (
    user_id      uuid not null references users(id) on delete cascade,
    workspace_id uuid not null references workspaces(id) on delete cascade,
    role         role_name not null,
    primary key (user_id, workspace_id)
);

-- OIDC users are not rows. Sign-in maps their groups claim, so authorisation for them
-- is a binding on a group name that no local user ever has to exist for.
create table group_bindings (
    group_name   text not null,
    workspace_id uuid not null references workspaces(id) on delete cascade,
    role         role_name not null,
    primary key (group_name, workspace_id)
);

-- An upstream. host is a name the DATA PLANE resolves; see section 1.
create table services (
    id                 uuid primary key default gen_random_uuid(),
    workspace_id       uuid not null references workspaces(id) on delete cascade,
    name               text not null,
    protocol           text not null check (protocol in ('http', 'https')),
    host               text not null,
    port               integer not null check (port between 1 and 65535),
    path               text,
    connect_timeout_ms integer check (connect_timeout_ms > 0),
    read_timeout_ms    integer check (read_timeout_ms > 0),
    retries            smallint not null default 1 check (retries >= 0),
    tls_verify         boolean not null default true,
    tls_ca_pem         text,
    tls_sni            text,
    created_at         timestamptz not null default now(),
    updated_at         timestamptz not null default now(),
    unique (workspace_id, name)
);

-- Matching. priority is explicit rather than derived from match specificity and a
-- creation timestamp the way Gateway API does it: the store is Kong-shaped, an
-- operator here can see and set the order, and a tie broken by a timestamp is a
-- tie an operator cannot see.
create table routes (
    id           uuid primary key default gen_random_uuid(),
    workspace_id uuid not null references workspaces(id) on delete cascade,
    service_id   uuid references services(id) on delete restrict,
    name         text not null,
    hosts        text[] not null default '{}',
    methods      text[] not null default '{}',
    -- [{"type":"prefix|exact|regex","value":"/v1"}]
    paths        jsonb  not null default '[]',
    -- [{"name":"x-env","value":"prod"}]
    headers      jsonb  not null default '[]',
    priority     integer not null default 0,
    created_at   timestamptz not null default now(),
    updated_at   timestamptz not null default now(),
    unique (workspace_id, name)
);

-- An API caller's identity. Not a user: users administer, consumers call.
create table consumers (
    id           uuid primary key default gen_random_uuid(),
    workspace_id uuid not null references workspaces(id) on delete cascade,
    username     text not null,
    created_at   timestamptz not null default now(),
    unique (workspace_id, username)
);

-- The key is shown once and stored hashed. prefix exists because a salted hash
-- cannot be indexed: a lookup finds the row by prefix, then verifies the secret
-- against that row's hash. The data plane does the same in memory, since keys
-- ride the configuration rather than being asked for per request.
create table consumer_keys (
    id          uuid primary key default gen_random_uuid(),
    consumer_id uuid not null references consumers(id) on delete cascade,
    key_prefix  text not null unique,
    key_hash    text not null,
    created_at  timestamptz not null default now(),
    expires_at  timestamptz
);

-- Attached to exactly one of a service, a route or a consumer -- or to none,
-- which means the whole workspace. The check is here rather than in the console
-- because it is the kind of rule that is enforced everywhere or nowhere.
create table plugins (
    id           uuid primary key default gen_random_uuid(),
    workspace_id uuid not null references workspaces(id) on delete cascade,
    name         text not null,
    config       jsonb not null default '{}',
    enabled      boolean not null default true,
    service_id   uuid references services(id)  on delete cascade,
    route_id     uuid references routes(id)    on delete cascade,
    consumer_id  uuid references consumers(id) on delete cascade,
    created_at   timestamptz not null default now(),
    updated_at   timestamptz not null default now(),
    check (num_nonnulls(service_id, route_id, consumer_id) <= 1)
);

-- key_pem is a private key sitting in a database. See section 5.
create table certificates (
    id           uuid primary key default gen_random_uuid(),
    workspace_id uuid not null references workspaces(id) on delete cascade,
    name         text not null,
    cert_pem     text not null,
    key_pem      text not null,
    snis         text[] not null default '{}',
    created_at   timestamptz not null default now(),
    unique (workspace_id, name)
);

-- Registered data planes. last_seen_at and last_seen_version are their liveness:
-- they are set by the configuration call itself, because a data plane that asked a
-- second ago is alive and a second mechanism saying so again is a thing to keep
-- consistent.
create table data_planes (
    id                uuid primary key default gen_random_uuid(),
    name              text not null unique,
    created_at        timestamptz not null default now(),
    last_seen_at      timestamptz,
    last_seen_version bigint,
    last_seen_address inet
);

-- Two live rows per data plane is how a token rotates: issue, accept both, update
-- the data plane, delete the first. Same prefix-then-verify shape as API keys.
create table data_plane_tokens (
    id            uuid primary key default gen_random_uuid(),
    data_plane_id uuid not null references data_planes(id) on delete cascade,
    token_prefix  text not null unique,
    token_hash    text not null,
    created_at    timestamptz not null default now(),
    expires_at    timestamptz
);

-- The data plane sends the version it holds, so there must be ONE
-- comparable number for the whole configuration. Per-table timestamps cannot
-- answer "has anything changed", which is the only question the protocol asks.
create table config_state (
    only_row boolean primary key default true check (only_row),
    version  bigint not null default 0,
    changed_at timestamptz not null default now()
);
insert into config_state default values;

create function bump_config_version() returns trigger language plpgsql as $$
begin
    update config_state set version = version + 1, changed_at = now();
    return null;
end $$;

-- A trigger rather than the application bumping it, because the one place this
-- can go wrong is somebody adding a write path and forgetting.
create trigger t_bump after insert or update or delete
    on services for each statement execute function bump_config_version();
create trigger t_bump after insert or update or delete
    on routes for each statement execute function bump_config_version();
create trigger t_bump after insert or update or delete
    on plugins for each statement execute function bump_config_version();
create trigger t_bump after insert or update or delete
    on consumers for each statement execute function bump_config_version();
create trigger t_bump after insert or update or delete
    on consumer_keys for each statement execute function bump_config_version();
create trigger t_bump after insert or update or delete
    on certificates for each statement execute function bump_config_version();

-- The console's audit trail. actor_name is denormalised on purpose: deleting a user
-- must not quietly erase who did what.
create table audit_log (
    id           bigserial primary key,
    at           timestamptz not null default now(),
    actor_user_id uuid references users(id) on delete set null,
    actor_name   text not null,
    action       text not null check (action in ('create', 'update', 'delete')),
    object_kind  text not null,
    object_id    uuid,
    workspace_id uuid references workspaces(id) on delete set null,
    before       jsonb,
    after        jsonb
);
create index on audit_log (at desc);
create index on audit_log (object_kind, object_id);
