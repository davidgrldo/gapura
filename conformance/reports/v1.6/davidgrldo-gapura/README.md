# gapura

Gapura is a Kubernetes Gateway API gateway built on Pingora. One binary, no database: each replica
watches the API server, translates Gateway API resources into a routing table, and serves traffic
from it. Source and issues: https://github.com/davidgrldo/gapura

## Table of contents

| API channel | Implementation version | Mode | Report |
|-------------|------------------------|------|--------|
| standard | [v0.1.0](https://github.com/davidgrldo/gapura/releases/tag/v0.1.0) | default | [v0.1.0 report](./standard-v0.1.0-default-report.yaml) |

## Submission

The reports rules require every profile's `result` to be `success` or `partial`, and this profile
is now `success`: 37 of 37 core tests, and the extended section 1 of 1.

The core profile reached 37 of 37 when Gapura grew an address per Gateway: `--gateway-address`
publishes per-Gateway status addresses, and the translator maps a listener that would tie with
another Gateway onto the next free bound port, so two Gateways whose routes overlap become two
distinct destinations. `partial` was never a way out: it covers tests that were **skipped**, or a
run that needed steps the suite did not expect, never a test that failed.

The extended section records the four extended features claimed, all passing:
`HTTPRouteRequestMirror` — a fire-and-forget, headers-only, plaintext-only copy with a bounded
in-flight count, never able to delay or fail the request it shadows — and the redirect status
codes 303, 307 and 308.

## Reproduce

```bash
git clone https://github.com/davidgrldo/gapura.git && cd gapura && git checkout tags/v0.1.0
./hack/conformance.sh
```

`hack/conformance.sh` creates a kind cluster from `hack/kind-config.yaml` (host ports 80 and 443
mapped to the chart's NodePorts), installs the Gateway API standard channel v1.6.2, builds the
image and loads it into the cluster, installs `charts/gapura` with
`charts/gapura/tests/values-kind.yaml`, then runs the upstream suite from a v1.6.2 checkout with
`--supported-features=Gateway,ReferenceGrant,HTTPRoute,HTTPRoute303RedirectStatusCode,HTTPRoute307RedirectStatusCode,HTTPRoute308RedirectStatusCode,HTTPRouteRequestMirror,PathMatchRegularExpression
--conformance-profiles=GATEWAY-HTTP`, no
`--skip-tests` and no `--exempt-features`. Requires docker, kind, kubectl, helm and Go 1.26.
