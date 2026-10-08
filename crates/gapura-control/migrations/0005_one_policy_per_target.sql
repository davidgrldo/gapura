-- At most one policy of a name on each target, so "switch key_auth on" is a fact the database
-- keeps rather than one every writer has to remember. A target is a route, a service, a consumer,
-- or none of them, which is the whole workspace. Two writers switching the same policy on at
-- once now meet here: the second's insert is a unique violation, which the store retries and
-- then finds the first's row.
create unique index plugins_one_per_route on plugins (route_id, name) where route_id is not null;
create unique index plugins_one_per_service on plugins (service_id, name) where service_id is not null;
create unique index plugins_one_per_consumer on plugins (consumer_id, name) where consumer_id is not null;
create unique index plugins_one_per_workspace on plugins (workspace_id, name)
    where route_id is null and service_id is null and consumer_id is null;
