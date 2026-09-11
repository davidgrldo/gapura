# Gateway API conformance reports

| API channel | Implementation version | Mode | Report |
|---|---|---|---|
| standard | v0.1.0 | default | [standard-v0.1.0-default-report.yaml](reports/v1.6/davidgrldo-gapura/standard-v0.1.0-default-report.yaml) |

Profile GATEWAY-HTTP against Gateway API v1.6.2. Core features claimed, and advertised in
`GatewayClass.status.supportedFeatures`: `Gateway`, `HTTPRoute`, `ReferenceGrant`.

## Result

36 of 37 core tests pass, 1 fails, 0 are skipped. The report result is therefore still `failure`, so
it is not submittable upstream yet. The remaining failure is architectural, not a bug:
`HTTPRouteMultipleGateways` attaches two routes that both match `PathPrefix /` with no hostname to
two different Gateways and expects different backends from the same address. One Deployment with one
published address cannot distinguish those two requests, whatever the precedence rules say; the
per-port table introduced in Plan 5 orders them deterministically by the Gateway API precedence
chain instead of leaving it to name order. Passing it needs an address per Gateway, which spec
section 5.1 defers to SP4.

| Test | Why it fails |
|---|---|
| `HTTPRouteMultipleGateways` | `same-namespace-dedicated-route` and `all-namespaces-dedicated-route` are the same match, `PathPrefix /` with no hostname, on the same port, attached to two different Gateways, and they want different backends. Nothing in the request tells them apart, so the port table has to pick one: the two routes share a creation timestamp, the tie falls through to `namespace/name`, `all-namespaces-dedicated-route` sorts first, and `/` answers from `infra-backend-v3`. The `Gateway_same-namespace` subtest asks for `infra-backend-v2` at that same URL and gets `infra-backend-v3`. |

The three earlier failures were two different problems wearing one face. `HTTPRouteCrossNamespace`
and `HTTPRouteHostnameIntersection` failed because `Config::select_listener` picked exactly one
listener per port-and-host pair -- a different hostname could select a different listener, but for
any one request only that listener's routes existed, so the routes attached to every other Gateway
matching the same host on that port were never served at all; one match table per port fixes that
and both now pass. `HTTPRouteMultipleGateways` is the other problem, and merging cannot fix it. Two identical listeners whose routes both match `/` are
distinguishable only by which address the client dialled, and Gapura publishes one address for every
Gateway of its class. Ordering makes the outcome deterministic and documented rather than a
name-order lottery, but one of the two backends is still unreachable by construction. Closing it
needs a listening address per Gateway, or a Deployment per Gateway; spec section 5.1 defers
per-Gateway isolation to SP4 and beyond, so this is a known trade-off rather than a surprise. It is
the same reason a shared ingress controller cannot pass this test.

The folder `reports/v1.6/davidgrldo-gapura/` already carries the `README.md` upstream requires, so a
submission there is a folder copy rather than a rewrite; sending it waits for 37 of 37.

## Reproduce

```bash
git clone https://github.com/davidgrldo/gapura.git && cd gapura
./hack/conformance.sh
```

`hack/conformance.sh` creates a kind cluster from `hack/kind-config.yaml` (host ports 80 and 443
mapped to the chart's NodePorts), installs the Gateway API standard channel v1.6.2, builds the image
and loads it into the cluster, installs `charts/gapura` with `charts/gapura/tests/values-kind.yaml`,
then runs the upstream suite from a v1.6.2 checkout with
`--supported-features=Gateway,ReferenceGrant,HTTPRoute --conformance-profiles=GATEWAY-HTTP`.
Requires docker, kind, kubectl, helm and Go 1.26.
