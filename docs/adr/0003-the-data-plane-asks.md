# 3. The data plane asks

Status: Accepted -- 2026-09-16

Refines [2. Postgres owns the configuration](0002-postgres-owns-the-configuration.md), which decided that data planes receive their configuration over an authenticated channel and recorded that channel as the largest thing that decision costs. This one decides its shape.

## Context

Two shapes are in front of us, and both are in production elsewhere.

Kong's hybrid mode has each data plane dial the control plane and hold a connection open, over mTLS. Configuration is pushed down the moment it changes, and the connection itself is the liveness signal.

Gravitee has gateways report to the management API on an interval. The console reads that list rather than discovering anything.

ADR 2's own wording — "`gapura-control` sends each of them the configuration" — leans toward the first without having thought about it.

## Decision

The data plane asks. It calls the control plane carrying the configuration version it currently holds, and the answer is either "nothing has changed" or the configuration that replaces it.

**Liveness and configuration are the same request.** The control plane learns a data plane is alive because it called; there is no second heartbeat mechanism reporting a fact the first one already carries.

Propagation is bounded by the interval. When that becomes the thing anyone complains about, the fix is to hold the request open until something changes or a timeout expires, rather than to invert the direction — near-instant delivery without a connection lifecycle to own.

ADR 2's sentence should be read as "the data plane obtains the configuration from `gapura-control`", not as a push.

## Consequences

- **Discovery disappears.** The control plane knows every data plane because they call it. Nothing has to enumerate pods, resolve a headless service, or be told an address. This also removes the requirement that the control plane can reach a data plane at all, so data planes in another network or another cluster work with nothing added.
- **The protocol is an endpoint with a version number, not a connection lifecycle.** No reconnection, no backoff, no thundering herd when the control plane restarts, no long-lived connections dying quietly behind a load balancer's idle timeout. This is the largest cost ADR 2 recorded, and this shape is what makes it small.
- **A control plane restart is a non-event.** The next call succeeds. Under a persistent channel, every data plane is disconnected at once and has to come back in a stampede.
- **It can be debugged with `curl`.** For one maintainer, that is not a small property.
- **More requests while nothing is happening**, which is the honest cost. It is bounded and cheap, and it buys the four points above.
- The disk cache ADR 2 requires still carries a data plane through a control-plane outage. Nothing here changes that; a failed call is simply a call that gets retried.

## Alternatives

**A persistent bidirectional channel, as Kong hybrid has.** Instant propagation and exact liveness, and the right choice for a vendor with a team to maintain it and customers pushing configuration to thousands of nodes at once. Both halves of that sentence are the reason it is not the right choice here: the cost is real and continuous, and the problem it solves is one this project does not have. Copying the decision without the circumstances copies only the bill.

**A heartbeat separate from configuration fetching, as Gravitee has.** Rejected for being two mechanisms carrying one fact. A data plane that asked for configuration a second ago is alive, and a separate endpoint saying so again is a thing to build, version, and keep consistent with the first.

**The control plane pushing to data planes it discovered.** Rejected: it needs a way to find them and a network path to reach them, both of which stop working the moment a data plane is somewhere the control plane is not.

## Open

- How a data plane authenticates to the control plane. mTLS is the obvious candidate and brings a certificate lifecycle with it; a bearer token from a Secret is cheaper and weaker. This wants deciding before the endpoint is built, not after.
- Whether holding the request open lands with the first version or once someone asks for it. The interval is a value in a config file either way, so nothing about this decision has to be revisited to change it.
