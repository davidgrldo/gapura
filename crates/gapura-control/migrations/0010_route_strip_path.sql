-- Kong's `strip_path`: whether the upstream gets the request's path without the part the route
-- matched. Off by default, unlike Kong's, so every route stored before it is served as it was.
alter table routes add column strip_path boolean not null default false;
