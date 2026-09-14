# 1. A control plane for users who have no cluster

Status: Proposed -- 2026-09-14

## Context

Gapura's configuration is Gateway API resources and its only write path is the
Kubernetes API. For a platform team that is the right model and a cheap one: its
members already have a cluster identity, and RBAC, the audit log and namespace
boundaries come for free with it.

It does not serve the people the console now being discussed is meant for. Those
are API teams with no cluster access at all -- no kubeconfig, no ServiceAccount,
no name the cluster would recognise. Kubernetes RBAC cannot authorise someone the
cluster has never heard of, so "authenticate the human against the cluster and
act as them" is not available for this audience.

A console for them needs its own accounts and its own roles, and those have to be
kept somewhere. That is a database. The only open question is where it is allowed
to live.

## Decision

Split the two, the way Kong did after shipping a gateway that wanted a database
behind every node.

- **`gapura`**, the data plane, is unchanged: one binary, no database,
  configuration from `--config-dir` or `--kubernetes`. Nothing here touches it.
- **`gapura-control`**, new, owns Postgres, the admin API, the console, and the
  accounts and roles that go with them.

`gapura-control` stores identity, authorisation and an audit trail. It does not
store routing configuration. When a console user saves a route, the control plane
checks the request against its own roles and then writes Gateway API resources to
Kubernetes under its own credentials. Kubernetes stays the single source of truth
for what the gateway actually serves.

## Consequences

- The first line of the README -- one binary, no database -- stays true of the
  thing operators run in the request path, which is how that sentence is read.
- Postgres going away costs the console, not the gateway. The data plane has
  never heard of it and keeps serving the configuration it already has.
- Kubernetes mode is untouched, so conformance stays where it is, and CRDs remain
  a first-class way in for teams that do hold cluster identities.
- The schema is small: users, roles, sessions, audit. Routing configuration is
  what would have made migrations painful over the years, and it is not in here.
- The control plane's own credentials become powerful, because it writes on
  behalf of everyone. Its roles are the only thing between an API team and every
  namespace it is allowed to reach. That is the security surface this decision
  creates, and it has to be treated as the main one.
- GitOps and the console write the same resources and will fight over any
  namespace driven by both. Picking one per namespace is an operational rule to
  be stated in the docs; it cannot be resolved in code.

## Alternatives

**Kubernetes RBAC with impersonation.** Turned down for this audience only, not
on merit. It remains the better model wherever users have cluster identities, and
is what a platform team should keep using.

**Postgres as the configuration store, with data planes pulling from the control
plane -- Kong's database mode.** Not chosen now. It is what running gapura with a
console and no Kubernetes at all would require, and this decision is arranged so
that it stays reachable: the control plane would already exist and already hold
Postgres, and would gain a configuration schema and a push path rather than being
built from nothing.

## Open questions

- Consumer identity on the data path, meaning API keys and JWT, is not settled
  here. Delegating to an external IdP keeps credentials out of our database
  entirely and is the current preference.
- Rate limit counters need state shared across replicas and belong in Redis, not
  in this database. Postgres is a poor counter store and Kong's own guidance says
  as much about its equivalent.
- Whether one deployment may run the Kubernetes source and the control plane at
  the same time, or whether the two have to be mutually exclusive.
