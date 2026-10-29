-- What a data plane said of itself on its last call: the build it runs (User-Agent) and the
-- features it reads (X-Gapura-Features). Null when it said nothing, or more than the endpoint
-- accepts. What it lacks is not stored: the console works it out against the configuration
-- served now, so it cannot go stale when that configuration changes.
alter table data_planes
    add column last_seen_build text,
    add column last_seen_features text[];
