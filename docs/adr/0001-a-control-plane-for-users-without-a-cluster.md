# 1. A control plane for users who have no cluster

Status: Proposed -- 2026-09-14

## Context

Gapura's configuration is Gateway API resources and its only write path is the
Kubernetes API. For a platform team that is the right model and a cheap one: its
members already hold a cluster identity, and RBAC, the audit log and namespace
boundaries come with it for free.

It does not serve the people the console is meant for. Those are API teams with
no cluster access at all -- no kubeconfig, no ServiceAccount, no name the cluster
would recognise. Kubernetes RBAC cannot authorise someone the cluster has never
heard of, so authenticating the human against the cluster and acting as them is
not available for this audience. A console for them needs accounts and roles of
its own, and those have to be kept somewhere.

The same teams need API keys, which means a notion of a consumer that gapura does
not have today. How many consumers there will be is not known. Today it would be
tens. It may stay there, or it may grow if the project attracts deployments
larger than this one. That number decides where credentials should live, and we
do not have it yet.

## Decision

Split the control plane from the data plane, the way Kong arrived at after
shipping a gateway that wanted a database behind every node.

- **`gapura`**, the data plane, is unchanged: one binary, no database,
  configuration from `--config-dir` or `--kubernetes`.
- **`gapura-control`**, new, owns Postgres, the admin API, the console, and the
  accounts and roles that go with them.

Because the control plane writes Gateway API resources, it is a client of the
Kubernetes API rather than a configuration source of its own, and a deployment
that runs it is a deployment in `--kubernetes` mode. There is no combination of
the two to arbitrate: the data plane still reads from exactly one source.

What Postgres holds is authorisation and an audit trail. It does not hold
routing configuration, and for now it does not hold consumers either. It does not
hold passwords: the console federates to an identity provider the organisation
already runs, so a person is a subject claim we recognise, not a row we secure.

Consumers and their credentials are configuration, and stay where the rest of the
configuration is: a CRD under Kubernetes, a YAML document under `--config-dir`.
The console creates them for a team after checking its own roles, so an API team
still never touches kubectl.

Because that store may have to move later, the data plane looks credentials up
through one interface rather than reading a CRD directly. The plugin asks whether
a key is valid and whose it is; what answers sits behind the seam. This is not a
speculative abstraction. It has two implementations on the first day, one per
configuration source, because Docker deployments need API keys too.

## Consequences

- The first line of the README, one binary and no database, stays true of the
  thing that sits in the request path, which is how that sentence is read.
- Postgres going away costs the console. The data plane has never heard of it,
  keeps serving, and keeps receiving configuration from Kubernetes.
- There is no control-plane-to-data-plane protocol, so there is none to version
  or keep compatible across a rolling upgrade. Kubernetes already carries
  configuration down and that path is conformance-tested.
- The schema stays small: users, roles, sessions, audit. What makes migrations
  painful over years is configuration, and it is not in there.
- Credential lookup is fast by construction. Keys are already in memory from the
  watch, so it is a hash map read, and an API key carries enough entropy to be
  stored under SHA-256 rather than a deliberately slow password hash.
- etcd becomes a credential store, which it was not built to be. Every key
  written is a watch event and a reload. That is the cost this decision accepts,
  and the reason the seam above exists.
- `gapura-control` ships in the existing chart, disabled by default, so a
  deployment that only wants the gateway is unchanged by its arrival. Postgres is
  required to be external rather than bundled: a database shipped inside a chart
  is one nobody backs up.
- The control plane's own credentials become powerful, because it writes on
  behalf of everyone. Its roles are the only thing between an API team and every
  namespace it can reach. That is the security surface this creates.
- GitOps and the console write the same resources and will fight over any
  namespace driven by both. A rule that lives only in documentation gets broken,
  so the console refuses to write to a namespace carrying
  `gapura.dev/managed-by: gitops` and says why, rather than leaving an operator
  to work the conflict out from a reconciliation loop.

## When the credential store should move

Not on a guess about growth. `config_reloads_total` is already exported. When
creating keys starts driving that counter, or reload duration begins to track the
number of consumers rather than the number of routes, etcd is being used as a
credential database and it is time. Until a measurement says so, the cost is not
justified.

At that point `gapura-control` gains a Postgres-backed implementation of the same
interface and a channel to push credentials down. Routing configuration does not
have to move with it.

## The order the plugins land

JWT and OIDC first, then API keys, then rate limiting with counters held locally,
and a shared counter store only if somebody asks for one.

This is about splitting risk, not ranking features. Two separate things are
unproven: the extension mechanism itself, meaning `ExtensionRef`, the filter
wiring and the route status an unsupported value produces; and the credential
seam above. JWT exercises the first and touches none of the second, because
checking a signature against a JWKS needs nothing looked up and nothing stored.
Taking both bets inside one plugin would leave a failure ambiguous.

It pays twice over. Every team that authenticates with JWT is a consumer that
never reaches etcd, which pushes the ceiling in the previous section further out;
and for those teams gapura holds no credential of theirs at all.

## State that is not configuration

Rate limit counters have to be shared across replicas to mean anything, which
sounds like it contradicts the claim this record has spent its length defending.
It does not. What is worth defending in "no database" is a source of truth that
must be backed up, migrated, and never lost. A counter is none of those. Losing
one resets a limit; it does not corrupt a gateway.

A shared counter store is therefore allowed, on three conditions. It stays
optional, the feature degrading rather than disappearing without it. It stays
disposable, with nothing to back up and no schema to migrate. And it stays out of
the startup path, so a gateway comes up and serves whether or not it is there.

Counters start local to each replica regardless, which is the honest
zero-dependency answer for as long as the documentation says plainly that a limit
of R across N replicas admits something closer to R times N. Redis arrives later
as an opt-in strategy for deployments that need the arithmetic exact. Shipping
rate limiting does not wait on any of this.

## What the console authorises

Three roles, named as Kong names them: superuser, admin, viewer. What each may do
is a matrix of create, read, update and delete against each kind of resource, so
the roles are defined by ticking boxes rather than by writing code.

A role is granted **per namespace**, not globally. That one extra column is what
makes the console multi-tenant, and multi-tenancy is the reason it exists: the
teams it serves must not be able to reach each other's routes. Namespaces are
already the boundary gapura writes into, so the scope costs nothing to invent and
nothing to enforce -- the control plane simply declines to write outside it.
Superuser is the exception that spans all namespaces, and exists mainly to grant
the others.

Because identity is federated, there is no first account to log in as. The first
superuser comes from naming an identity provider group in configuration, which
also means losing the database does not lock anybody out permanently.

## Alternatives

**Kubernetes RBAC with impersonation.** Turned down for this audience only, not
on merit. It stays the better model wherever users hold cluster identities.

**Postgres as the configuration store with data planes pulling from the control
plane, which is Kong's database mode.** Not chosen. It would mean building and
versioning a control-plane-to-data-plane protocol, a disk cache in the data plane
so it outlives the control plane, and a migration path for a configuration schema
that can never break. It also puts the control plane in the path of every
configuration change, where an outage stops updates instead of merely closing the
console. Nothing here forecloses it: the control plane would already exist and
already hold Postgres.

**Consumers pushed from the control plane while configuration stays in
Kubernetes.** Rejected as a starting point, because it pays the largest cost, the
channel, before anything has shown it is needed. It is the shape the step above
takes if the measurement ever arrives.

## Open questions

- Whether the CRUD matrix is per kind of resource or something finer, which only
  matters once there are more kinds than HTTPRoute and the consumer.
- What the console does when the identity provider is unreachable. Refusing every
  login is correct and also means an outage there closes the console entirely.
