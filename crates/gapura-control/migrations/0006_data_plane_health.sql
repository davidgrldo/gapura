-- What a data plane holds and which token it used, recorded by the call it makes anyway.
-- last_seen_etag is the If-None-Match it sent, not the tag it was answered with: a data plane
-- that was sent a configuration and could not apply it keeps sending its old tag.
alter table data_planes add column last_seen_etag text;
alter table data_plane_tokens add column last_used_at timestamptz;
