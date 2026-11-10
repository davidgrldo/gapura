-- The replicas of each data plane, by the name each one sends as X-Gapura-Instance (its pod's
-- name, or --identity), and when it last called. A poll records its caller here and is answered
-- with how many replicas of its data plane called recently (X-Gapura-Replicas), which a `split`
-- request limit divides by. A poll also deletes its data plane's rows unseen for ten minutes, so
-- the table holds about what is running; a data plane's rows go with it.
create table data_plane_instances (
    data_plane_id uuid not null references data_planes(id) on delete cascade,
    instance text not null,
    last_seen_at timestamptz not null default now(),
    primary key (data_plane_id, instance)
);
