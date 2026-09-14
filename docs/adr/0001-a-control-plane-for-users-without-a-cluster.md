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

What Postgres holds is identity, authorisation and an audit trail. It does not
hold routing configuration, and for now it does not hold consumers either.

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
- The control plane's own credentials become powerful, because it writes on
  behalf of everyone. Its roles are the only thing between an API team and every
  namespace it can reach. That is the security surface this creates.
- GitOps and the console write the same resources and will fight over any
  namespace driven by both. One or the other per namespace is an operational rule
  to document; code cannot settle it.

## When the credential store should move

Not on a guess about growth. `config_reloads_total` is already exported. When
creating keys starts driving that counter, or reload duration begins to track the
number of consumers rather than the number of routes, etcd is being used as a
credential database and it is time. Until a measurement says so, the cost is not
justified.

At that point `gapura-control` gains a Postgres-backed implementation of the same
interface and a channel to push credentials down. Routing configuration does not
have to move with it.

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

- Whether one deployment may run the Kubernetes source and the control plane at
  the same time, or whether the two have to be mutually exclusive.
- Rate limit counters need state shared across replicas and belong in Redis
  rather than here. How that sits with the no-database claim is not settled.
- Whether JWT and OIDC, which need no credential store at all, should land before
  API keys and reduce how much that store has to carry.
