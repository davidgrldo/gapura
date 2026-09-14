# Gateway API conformance reports

| API channel | Implementation version | Mode | Report |
|---|---|---|---|
| standard | v0.1.0 | default | [standard-v0.1.0-default-report.yaml](reports/v1.6/davidgrldo-gapura/standard-v0.1.0-default-report.yaml) |

Profile GATEWAY-HTTP against Gateway API v1.6.2. Features claimed, and advertised in
`GatewayClass.status.supportedFeatures`: core `Gateway`, `HTTPRoute`,
`PathMatchRegularExpression`, `ReferenceGrant`, and the extended `HTTPRouteRequestMirror`. The
regex claim leaves the counts below untouched: v1.6.2's standard channel carries no core regex
path-match cases to unlock, so the feature is claimed for the channels and versions that gate on
it, not for what this run measures. The mirror claim is what extended runs are for: it adds the
one extended test that gates on it, and the report now carries an extended section.

## Result

37 of 37 core tests pass, 0 fail, 0 are skipped; the extended section is 1 of 1, the
RequestMirror test. The report result is `success`, and the folder is submittable upstream with
the next release run.

The one failure this profile carried for a long time was architectural, not a bug:
`HTTPRouteMultipleGateways` attaches two routes that both match `PathPrefix /` with no hostname to
two different Gateways and expects different backends from the same address. One Deployment with one
published address cannot distinguish those two requests, whatever the precedence rules say; the
per-port match table orders them deterministically by the Gateway API precedence chain instead of
leaving it to name order. Closing it took an address per Gateway:

- `--gateway-address namespace/name=ip-or-host` (repeatable) publishes per-Gateway status
  addresses; a Gateway without an override keeps the global `--publish-address` list.
- The translator maps a listener whose table would tie with another Gateway's onto the next free
  **bound** port of its protocol — the proxy binds exactly the `--listen-http`/`--listen-https`
  sockets at startup, so an operator who wants addressable Gateways binds a second port (the
  chart's `extraListenHttp`) and points a Service at it. The allocation is deterministic
  (sorted snapshot order), so the Service mapping is stable. Listeners whose requests precedence
  can already tell apart — disjoint or strictly-more-specific hostnames, or one route attached to
  both — keep sharing the port, and a deployment with a single bound port behaves exactly as
  before.

The three earlier failures were two different problems wearing one face. `HTTPRouteCrossNamespace`
and `HTTPRouteHostnameIntersection` failed because `Config::select_listener` picked exactly one
listener per port-and-host pair -- a different hostname could select a different listener, but for
any one request only that listener's routes existed, so the routes attached to every other Gateway
matching the same host on that port were never served at all; one match table per port fixes that
and both now pass. `HTTPRouteMultipleGateways` was the other problem, and merging cannot fix it.
Two identical listeners whose routes both match `/` are distinguishable only by which address the
client dialled, and Gapura published one address for every Gateway of its class. Ordering made the
outcome deterministic and documented rather than a name-order lottery, but one of the two backends
stayed unreachable by construction — the same reason a shared ingress controller cannot pass this
test. The address per Gateway above is what removed the construction.

The folder `reports/v1.6/davidgrldo-gapura/` already carries the `README.md` upstream requires, so a
submission there is a folder copy rather than a rewrite; the counts above are what it submits.

The nightly `conformance` workflow runs the same script. `EXPECTED_FAILURES` at the top of
`hack/conformance.sh` is now empty — any failure fails the run — but the check itself is unchanged:
an equality, still red both on a regression and on a surprise pass that would make the counts on
this page wrong. None of that weakens the run: the suite
is still invoked with no `--skip-tests` and no `--exempt-features`, and the committed report records
whatever actually happened.

Local note: the two kind port mappings on host port 80 (`127.0.0.1:80` and `127.0.0.2:80`) need a
docker provider that binds per address — Docker on Linux and Docker Desktop do; OrbStack collapses
both published ports into one listener and breaks every host-port-80 path, so on an OrbStack host
run the suite on CI instead.

## Reproduce

<!-- REMOVE WHEN PUBLIC: delete this paragraph once github.com/davidgrldo/gapura is public and v0.1.0 is tagged. -->
The clone URL below does not resolve yet: the repository is published with the first release.

```bash
git clone https://github.com/davidgrldo/gapura.git && cd gapura
./hack/conformance.sh
```

`hack/conformance.sh` creates a kind cluster from `hack/kind-config.yaml` (host port 443 mapped to
the chart's NodePort, and port 80 mapped twice — `127.0.0.1` to the chart's NodePort and `127.0.0.2`
to the second Gateway's), installs the Gateway API standard channel v1.6.2, builds the image
and loads it into the cluster, installs `charts/gapura` with `charts/gapura/tests/values-kind.yaml`
(which binds the extra port and overrides the one Gateway's address), applies the second Gateway's
Service (`hack/kind-second-service.yaml`), then runs the upstream suite from a v1.6.2 checkout with
`--supported-features=Gateway,ReferenceGrant,HTTPRoute,HTTPRouteRequestMirror,PathMatchRegularExpression
--conformance-profiles=GATEWAY-HTTP`. Requires docker, kind, kubectl, helm and Go 1.26.
