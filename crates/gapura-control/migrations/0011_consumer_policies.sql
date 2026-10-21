-- A policy may be a consumer's own and, besides, attached to one route or one service: a
-- consumer's own request limit on one route, say. 0001 allowed at most one of the three, so a row
-- could name a route or a service or a consumer and never a consumer on a route. The consumer is
-- now a dimension of its own, and only the route and the service exclude each other: a policy
-- that named both would apply to the route and to the service at once, and which of them it
-- meant is a question no reader of the row could answer. The check 0001 wrote was unnamed, so
-- Postgres named it plugins_check; the one that replaces it is named, so the next migration that
-- touches it need not guess.
alter table plugins drop constraint plugins_check;
alter table plugins add constraint plugins_one_target
    check (num_nonnulls(service_id, route_id) <= 1);

-- One policy of a name per target, as 0005 has it, where a target is now a route, a service, a
-- consumer, a consumer on a route or a consumer on a service -- or none of them, which is the
-- whole workspace and keeps 0005's index as it is. The indexes for a route and for a service
-- were partial on the route or the service alone, and would now count a consumer's own policy on
-- a route against the one for everyone on that route; they are rebuilt to stand for "on
-- everyone" only, and the consumer's own get indexes of their own. The consumer-alone index
-- gains the two nulls for the same reason, so a consumer's policy on a route is not also counted
-- as the consumer's policy everywhere.
--
-- No row stored before this migration can break an index below: every one of them named at most
-- one of the three, so each sits in the same index it sat in before and none in the new ones.
drop index plugins_one_per_route;
drop index plugins_one_per_service;
drop index plugins_one_per_consumer;
create unique index plugins_one_per_route on plugins (route_id, name)
    where route_id is not null and consumer_id is null;
create unique index plugins_one_per_service on plugins (service_id, name)
    where service_id is not null and consumer_id is null;
create unique index plugins_one_per_consumer on plugins (consumer_id, name)
    where consumer_id is not null and route_id is null and service_id is null;
create unique index plugins_one_per_route_consumer on plugins (route_id, consumer_id, name)
    where route_id is not null and consumer_id is not null;
create unique index plugins_one_per_service_consumer on plugins (service_id, consumer_id, name)
    where service_id is not null and consumer_id is not null;
