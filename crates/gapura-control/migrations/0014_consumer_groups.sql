-- The groups an acl policy judges a consumer by, and an upstream is told in x-consumer-groups:
-- Kong's acls, as a column rather than a table, because a group is a name a consumer carries and
-- nothing refers to one. Names are checked by the API (letters, digits and . _ : -, which an
-- HTTP header and a URL path carry as they are), not here, as a consumer's username is. The
-- statement trigger on consumers already bumps the configuration version, so a change in a
-- consumer's groups reaches the data planes like any other.
alter table consumers add column groups text[] not null default '{}';
