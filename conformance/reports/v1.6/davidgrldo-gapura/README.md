# gapura

Gapura is a Kubernetes Gateway API gateway built on Pingora. One binary, no database: each replica
watches the API server, translates Gateway API resources into a routing table, and serves traffic
from it. Source and issues: <!-- markdown-link-check-disable --> https://github.com/davidgrldo/gapura <!-- markdown-link-check-enable -->

## Table of contents

| API channel | Implementation version | Mode | Report |
|-------------|------------------------|------|--------|
| standard | <!-- markdown-link-check-disable --> [v0.1.0](https://github.com/davidgrldo/gapura/releases/tag/v0.1.0) <!-- markdown-link-check-enable --> | default | [v0.1.0 report](./standard-v0.1.0-default-report.yaml) |

<!-- REMOVE WHEN PUBLIC: delete this paragraph, and the markdown-link-check-disable/enable comments above, once github.com/davidgrldo/gapura is public and v0.1.0 is tagged. -->
No GitHub URL here resolves yet: neither link above, nor the clone URL under Reproduce below. The
repository has not been published and no `v0.1.0` tag exists. Both arrive with the first release,
and every URL here is written in its final form so that this folder can be copied upstream
unchanged.

## Not yet submitted

This report is **not** eligible for submission to kubernetes-sigs/gateway-api. The reports rules
require every profile's `result` to be `success` or `partial`; this one is `failure`, because one
core test fails:

- `HTTPRouteMultipleGateways` attaches two routes that both match `PathPrefix /` with no hostname,
  to two different Gateways, and expects a different backend from each. Gapura serves every Gateway
  of its class from one Deployment with one published address, so nothing in the request
  distinguishes the two. The port table orders them deterministically by the Gateway API precedence
  chain, which makes the outcome documented rather than a name-order lottery, but one of the two
  backends stays unreachable by construction.

`partial` is not a way out: it covers tests that were **skipped**, or a run that needed steps the
suite did not expect, never a test that failed. Skipping a test we know fails would be claiming
conformance we do not have. Submission waits for an address per Gateway, which takes the profile to
37 of 37.

The extended section records the one extended feature claimed, `HTTPRouteRequestMirror`, passing
1 of 1: a fire-and-forget, headers-only copy with a bounded in-flight count, never able to delay
or fail the request it shadows.

## Reproduce

```bash
git clone https://github.com/davidgrldo/gapura.git && cd gapura && git checkout tags/v0.1.0
./hack/conformance.sh
```

`hack/conformance.sh` creates a kind cluster from `hack/kind-config.yaml` (host ports 80 and 443
mapped to the chart's NodePorts), installs the Gateway API standard channel v1.6.2, builds the
image and loads it into the cluster, installs `charts/gapura` with
`charts/gapura/tests/values-kind.yaml`, then runs the upstream suite from a v1.6.2 checkout with
`--supported-features=Gateway,ReferenceGrant,HTTPRoute,HTTPRouteRequestMirror,PathMatchRegularExpression
--conformance-profiles=GATEWAY-HTTP`, no
`--skip-tests` and no `--exempt-features`. Requires docker, kind, kubectl, helm and Go 1.26.
