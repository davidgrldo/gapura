# 2. Postgres owns the configuration

Status: Accepted -- 2026-09-16

Supersedes [1. A control plane for users who have no cluster](0001-a-control-plane-for-users-without-a-cluster.md).

## Context

ADR 1 gave the console accounts of its own and left routing configuration in
Kubernetes: the console would check a person's roles and then write Gateway API
resources on their behalf. That holds as long as every deployment worth a console
runs under Kubernetes.

It does not. Gapura already runs from `--config-dir` with no cluster at all, and a
console for those deployments has nowhere to write. Writing YAML into a directory
the gateway watches sounds like the answer until it is asked which machine's disk,
what happens with more than one replica, and what two people editing at once are
supposed to do. There are no transactions there and nothing to lock.

The ambition behind the console is also Kong-shaped -- services, routes, plugins,
consumers, managed from one place by teams who do not hold a cluster identity. A
store that exists only under Kubernetes cannot carry that.

## Decision

Postgres holds the configuration: services, routes, plugins and consumers, along
with the roles and audit trail ADR 1 already put there.

Data planes do not read it. `gapura-control` sends each of them the configuration
over an authenticated channel, and each keeps the last it received on disk, so a
gateway that loses the control plane keeps serving what it already has rather than
waking up empty. Nothing in the request path opens a database connection, which is
the part of "no database" worth defending.

**The Kubernetes source stays, and the two are mutually exclusive.** A deployment
reads its configuration from Gateway API resources or from the control plane, never
both. This is what Kong settled on after the same question, and it keeps the
conformance work standing: the CRD path remains a first-class way to run gapura and
remains what the suite exercises.

**The console writes only to Postgres.** A deployment in Kubernetes mode gets a
read-only console, which is again where Kong landed, and is worth having on its own
-- the reading half is most of the daily value.

`gapura-control` and the console live in this workspace, as `crates/gapura-control`
and `web/`. The channel between control plane and data plane has to keep old data
planes talking to new control planes across a rolling upgrade, and that is far
likelier to hold when both ends are built and tested together than when they are
matched by release notes.

## Consequences

- There is now a protocol to design, version, and keep compatible, and a disk cache
  in the data plane to keep correct. This is the largest thing this decision buys
  and the largest thing it costs.
- Schema migrations become permanent work. Every release needs a path from the one
  before it, and that path can never break. This is what ADR 1 was avoiding by
  keeping configuration out of the database, and the avoidance is over.
- Two configuration paths are maintained for good: the Kubernetes source and the
  store. Deleting either is a later decision, not this one.
- Conformance is unaffected, because the path it measures is untouched.
- A deployment that wants a writable console moves off Gateway API resources. After
  that `kubectl get httproute` no longer describes what the gateway serves, and
  GitOps has no part in that namespace. That is a real loss and the reason the two
  modes are exclusive rather than blended: a deployment should have one answer to
  "where does this come from".
- Losing Postgres stops configuration changes and closes the console. It does not
  stop traffic.

## What ADR 1 still decides

Its identity and authorisation model is unchanged and is not restated here: the
three namespace-scoped roles with fixed permissions, superuser above them, the two
ways in, and what storing local passwords obliges. The plugin order it set --
JWT and OIDC before API keys -- also stands, for the same reason: it separates
proving the extension mechanism from proving the credential path.

What it no longer decides is where configuration lives. Its staging of consumers,
and the measured trigger for moving them, go with it: consumers are configuration,
so they live in the store from the start.

## Alternatives

**Leave ADR 1 alone and keep the console to Kubernetes.** The smallest thing that
could work, and rejected only because the goal is a console for deployments that
have no cluster. Worth revisiting if that goal narrows.

**Let the console write YAML files in file mode.** Rejected on the three questions
in the context above, none of which has an answer that survives a second replica.

**Read Gateway API resources into the store, so both are ways in to one place.**
Rejected because it needs a rule for what happens when the console edits a route and
a GitOps controller reapplies the resource behind it. Every available rule is
arbitrary, and the one thing worse than choosing a source is having two that
disagree quietly.
