# Changelog

Notable changes, newest first. v0.1.0 is the first release: nothing was tagged before it, so
everyone running Gapura until now has been running a checkout of this repository, and "upgrading"
to v0.1.0 means `helm upgrade` from that checkout to the published chart. From v0.1.0 onward it
means what it usually does, moving from one version below to a later one. Release procedure:
[docs/RELEASING.md](docs/RELEASING.md).

## Unreleased

- An address per Gateway: `--gateway-address namespace/name=ip-or-host` (repeatable) publishes
  per-Gateway status addresses instead of one shared list, and the translator remaps the listener of a Gateway that carries such an override —
  the declaration that it is individually addressable — onto the next free bound port of its
  protocol whenever it would tie with another Gateway — the proxy
  only ever binds the `--listen-http`/`--listen-https` sockets, so a deployment that wants
  addressable Gateways binds a second port (chart value `extraListenHttp`) and points a Service
  at it. The allocation is deterministic, so the Service mapping is stable. Listeners whose
  requests precedence can already tell apart — disjoint or strictly-more-specific hostnames, or
  one route attached to both — keep sharing the port, and with a single bound port nothing
  changes at all. This is what the `HTTPRouteMultipleGateways` conformance test needed: the
  GATEWAY-HTTP profile now passes 37 of 37 core plus 1 of 1 extended, the chart's `gatewayAddresses`
  value carries the per-Gateway addresses, and `hack/conformance.sh` runs with an empty
  `EXPECTED_FAILURES` — any failure fails the run.
- The release workflow can no longer publish a release whose notes say nothing. The check meant
  to catch that ran over the finished file, which by then already carried the `## Packages` list
  the same step writes, so both of its conditions were satisfied by its own output and it passed
  for every version -- including ones with no section in this file at all. It now reads the
  section before anything else is added and stops there when it is empty. A dispatch of the
  workflow also stops trying to create a release: it builds a branch and makes no tag, so there
  is nothing to hang one on, and the image and chart it publishes are the point of that path.
- `RequestMirror` fires a bounded, fire-and-forget copy of the request. Headers-only: the mirror
  never promises a body it does not send (content-length and transfer-encoding are stripped), and
  body tee-ing is a follow-up. The mirror also dials plaintext HTTP regardless of the cluster's
  TLS policy: a TLS-only shadow backend shows up as counted `error`s, a dual listener receives
  the copy unencrypted, and honoring `BackendTLSPolicy` for mirrors is the same follow-up. A global 1024 in-flight bound drops mirrors past it, counted as
  `overflow` on `gapura_mirror_requests_total{route, result}` (`sent|error|timeout|overflow`); each
  mirror is one 3s attempt with no retries, and the primary's access-log line gains a `mirrored`
  field. The mirror's backendRef resolves like any other — ReferenceGrant included — and a mirror
  that cannot resolve sets `ResolvedRefs=False` while the route keeps serving unmirrored. Claiming
  the extended `HTTPRouteRequestMirror` adds the one extended test that gates on it: the report now
  carries an extended section, 1 of 1 passing, core still 36 of 37.
- The access log can name the client again. `client_ip` was read straight off the connection, so
  anywhere an ingress, a mesh or a CDN sits in front, every line recorded that proxy and the
  visitor appeared nowhere -- and anything later keyed on the client address would have read the
  proxy too. `--trusted-proxy` takes a CIDR or a bare address and is repeatable (`trustedProxies`
  in the chart); with at least one set, a connection arriving from one of those networks has its
  `X-Forwarded-For` read from the right until an address no listed network vouches for, and that
  is the client. Anything a caller wrote into the header itself sits further left and is never
  reached, and a connection from outside those networks is taken at face value however it filled
  the header in. Nothing is listed by default, which is the old behaviour: the header ignored,
  the peer logged. What gapura sends upstream does not change.
- `path.type: RegularExpression` is matched, not rejected. Patterns compile once per config
  generation into a side map next to the round-robin cursors, match the raw request path, and
  rank below `Exact` and `PathPrefix` in the precedence chain, the pattern length breaking ties
  inside the type. A pattern that does not compile, or a `ReplacePrefixMatch` rewrite on a regex
  match, still rejects the route as `Unsupported`. `PathMatchRegularExpression` is now claimed in
  `GatewayClass.status.supportedFeatures` and passed to the suite; v1.6.2's standard channel has
  no core regex cases, so the conformance counts stand at 36 of 37.
- `helm test` on a release now proves it routes: the chart ships a throwaway Gateway, HTTPRoute
  and echo backend as `helm.sh/hook: test` resources, plus a curl pod that drives one request
  through the data plane and checks the answer. Nothing exists at install time; `helm test`
  creates it, waits, and cleans up after itself (gated by `tests.smoke.enabled`, on by default).
- New `quickstart` workflow: the README quickstart, verbatim, on a fresh kind cluster, with no
  ghcr credentials anywhere. Automates the anonymous check of RELEASING 5.3 and all of 5.5 —
  red while a package is private, the tripwire for every release after that.
- The release workflow now publishes a GitHub Release from the tag: the CHANGELOG section for
  the version as notes, the conformance report attached as an asset.
- The chart's NOTES now cover NodePort installs: they print the exact `curl`, NodePort included,
  because a Gateway's published address never carries a port and that is the trap every NodePort
  install hits.
- The controller now diagnoses absent or stale Gateway API CRDs out loud. A missing optional
  kind logs what stops working (a `loses` field: absent `BackendTLSPolicy` means TLS to
  backends is off), the aggregate warning names the expected channel (`v1.6.2`) and says the
  fix needs no restart, a missing required kind says the same at startup, and one info line
  summarizes every watched kind with its apiVersion. Verified live: CRD deleted at startup,
  pod warned and degraded; CRD reinstalled, the 60s recheck picked it up and rebuilt the watch
  list, traffic uninterrupted. Chart NOTES say which channel the build is made for.
- k3s gets a first-class seat: a `k3s` workflow runs `hack/k3s-deploy.sh` — build, import into a
  k3d cluster with traefik deliberately left on, NodePort install, one request through the
  gateway — on every PR and push to main. The README quickstart documents the stock-k3s case
  (traefik holds 80/443 through ServiceLB, so the default LoadBalancer Service hangs rather than
  fails) with the NodePort install for it.
- The chart can pin the image by digest (`image.digest`, taking precedence over the tag), for
  operators who want the release to run byte-for-byte what CI pushed; `externalTrafficPolicy`'s
  Local default now says what it costs on a multi-node cluster.
- Release images now carry `provenance: mode=max` and an SBOM per platform, and the digest-join
  is asserted to keep them: `hack/release-dry-run.sh` fails if the manifest list arrives without
  its attestations. A project with no edition to buy should not need one to verify what it runs.
- RELEASING gains section 8, the post-public listings (Gateway API implementations page,
  upstream report submission once the profile allows it, Artifact Hub, README badge), and 5.3
  now points at the quickstart workflow as the standing private-package detector.

## 0.1.0 — 2026-09-11

The first release, and the first time any of this installs without a checkout. What ships: the
Gateway API core objects — `Gateway`, `HTTPRoute` and `ReferenceGrant` — served by one binary that
watches the API server and translates them into a routing table, at 36 of 37 GATEWAY-HTTP core
conformance tests. TLS terminates from a `Secret` on the listener, and is re-established to
backends through `BackendTLSPolicy`. Observability is open formats only: Prometheus metrics on the
admin port next to `/healthz` and `/readyz`, one JSON access log line per request on stdout, and
W3C `traceparent` plus `X-Request-Id` propagated upstream, created when the client sent neither.
It is delivered as a `linux/amd64` and `linux/arm64` image and the Helm chart in
[charts/gapura](charts/gapura).

### Read this before upgrading

**1. HTTPRoutes that were shadowed before now serve traffic.**

Gapura used to pick a single winning listener per port and hostname, and every other Gateway's
routes on that port were unreachable. It now builds one match table per port, over every listener
on it, so all of those routes match. A Gateway and HTTPRoute that have been sitting dead in your
cluster will start answering requests the moment you upgrade.

Audit what is attached to your shared ports before upgrading:

```bash
kubectl get httproute -A -o custom-columns=\
NS:.metadata.namespace,NAME:.metadata.name,PARENTS:.spec.parentRefs[*].name,HOSTS:.spec.hostnames
```

**2. A data-plane port that cannot be bound is now fatal.**

Before, Pingora's bind failure was swallowed by the panic hook: the pod stayed Ready and served
nothing. Gapura now tries every `--listen-http`, `--listen-https` and `--admin` address before
starting, logs `cannot bind a listen address`, and exits 1. The pod goes into CrashLoopBackOff
instead of lying about its health. If a gateway that used to come up now crash-loops, read the
first log line: something else on the node already holds the port.

**3. The liveness probe moved to the data-plane port.**

It was an HTTP GET on `/healthz` on the admin port; it is now a TCP probe on the http port, so a
dead data-plane listener is visible from outside. The trade-off is that a hung admin thread is no
longer caught by liveness. Set `livenessPort: admin` to restore the old behaviour.

### Also in this release

- Gapura refuses to start when one address is repeated across `--listen-http`, `--listen-https`
  and `--admin`. Both services used to bind it (Pingora sets `SO_REUSEPORT`) and the kernel split
  connections between them, silently. The chart rejects a values file whose `ports.http`,
  `ports.https` and `ports.admin` are not all distinct.
- Gateway API GATEWAY-HTTP conformance is at 36 of 37 core tests; the report and the reason for the
  remaining failure are in [conformance/](conformance/).
- Access log gained two fields: `client_abort` (the downstream client went away mid-request, not an
  error on our side) and `upstream_duration_ms` (null when no peer was ever picked).
- New metric `gapura_discovery_missing{kind}`, 1 while an optional kind is not served by the API
  server.
- An optional CRD (BackendTLSPolicy) that is absent at startup is rechecked every 60 seconds, and
  the source rebuilds itself once the CRD appears and can be listed. Installing it no longer needs
  a pod restart.
- Example Prometheus alerts ship as a PrometheusRule with `metrics.prometheusRule.enabled=true`
  (needs the Prometheus Operator CRDs).
- Status writes go out concurrently, in batches, and a demoted leader stops patching immediately
  instead of finishing its batch.
