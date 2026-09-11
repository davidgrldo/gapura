# Gateway API conformance reports

| API channel | Implementation version | Mode | Report |
|---|---|---|---|
| standard | v0.1.0 | default | [standard-v0.1.0-default-report.yaml](reports/v1.6/gapura-gapura/standard-v0.1.0-default-report.yaml) |

Profile GATEWAY-HTTP against Gateway API v1.6.2. Core features claimed, and advertised in
`GatewayClass.status.supportedFeatures`: `Gateway`, `HTTPRoute`, `ReferenceGrant`.

## Result

34 of 37 core tests pass, 3 fail, 0 are skipped. The report result is therefore `failure`, so it is
not submittable upstream yet.

All three failures have the same cause, and it is the architecture SP1 chose, not three separate
bugs. One Gapura Deployment serves every Gateway of its class and publishes one address for all of
them. The conformance manifests define several Gateways whose HTTP listener is byte-identical:
`same-namespace`, `all-namespaces` and `backend-namespaces` all listen on port 80 with no hostname,
and the hostname-intersection test adds a fourth. `Config::select_listener` picks exactly one
listener per port and hostname, so only one of those Gateways is reachable at the shared address and
the routes attached to the others are never served. Which one wins is decided by name order, which
is arbitrary: `same-namespace` happens to sort last, and that is the only reason the other 34 tests
pass.

| Test | Why it fails |
|---|---|
| `HTTPRouteCrossNamespace` | Its route attaches to the `backend-namespaces` Gateway, which loses the port-80 selection. |
| `HTTPRouteHostnameIntersection` | Its own Gateway loses the same selection, so none of its hostnames are reachable. |
| `HTTPRouteMultipleGateways` | Two Gateways expect `/` with no Host header to reach different backends at the same address, which no single-address data plane can distinguish. |

Two changes would close this, both out of scope for SP1 and recorded for the next plan:

1. Merge the route tables of every Gateway that shares a port instead of selecting one listener.
   That fixes `HTTPRouteCrossNamespace` and `HTTPRouteHostnameIntersection`, and removes the
   name-order lottery.
2. Give each Gateway its own address, or its own Deployment. `HTTPRouteMultipleGateways` needs this;
   merging cannot disambiguate two identical listeners whose routes both match `/`.

Spec section 5.1 already defers per-Gateway isolation to SP4 and beyond, so this is a known
trade-off rather than a surprise. It is the same reason a shared ingress controller cannot pass
these tests.

## Reproduce

```bash
git clone https://github.com/gapura-dev/gapura.git && cd gapura
./hack/conformance.sh
```

`hack/conformance.sh` creates a kind cluster from `hack/kind-config.yaml` (host ports 80 and 443
mapped to the chart's NodePorts), installs the Gateway API standard channel v1.6.2, builds the image
and loads it into the cluster, installs `charts/gapura` with `charts/gapura/tests/values-kind.yaml`,
then runs the upstream suite from a v1.6.2 checkout with
`--supported-features=Gateway,ReferenceGrant,HTTPRoute --conformance-profiles=GATEWAY-HTTP`.
Requires docker, kind, kubectl, helm and Go 1.26.

The organization, URLs and contact in the report are placeholders until the project has a public
repository, which is why this report has not been submitted to kubernetes-sigs/gateway-api.
