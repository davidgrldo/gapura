# Gapura

The Rust API gateway. Kubernetes Gateway API-native, one binary, no database, no enterprise edition. Built on [Pingora](https://github.com/cloudflare/pingora).

Status: SP1 v0.1 is code-complete: the data plane, the Kubernetes controller (`--kubernetes`) with status writes and leader election, TLS to backends via BackendTLSPolicy, the Helm chart in [charts/gapura](charts/gapura), the multi-arch image, and CI. The Gateway API GATEWAY-HTTP conformance suite passes 36 of 37 core tests; the report and the reason for the one remaining failure are in [conformance/](conformance/).

- Release notes, and what changes for operators on upgrade: [CHANGELOG.md](CHANGELOG.md)
- Contributing, security policy, and code of conduct: [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- Design spec (Indonesian): [docs/superpowers/specs/2026-09-09-gapura-sp1-design.md](docs/superpowers/specs/2026-09-09-gapura-sp1-design.md)
- Diagrams: [docs/diagrams/](docs/diagrams/) (open the HTML files in a browser)
- Market research and gap analysis: [docs/superpowers/specs/research/](docs/superpowers/specs/research/)

## Quickstart

```bash
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.6.2/standard-install.yaml
helm install gapura oci://ghcr.io/davidgrldo/charts/gapura --namespace gapura-system --create-namespace
```

The `oci://ghcr.io/davidgrldo/charts/gapura` reference above, and the `home` and `sources` URLs in
[charts/gapura/Chart.yaml](charts/gapura/Chart.yaml), are placeholders for a public repository that
does not exist yet: nothing has been pushed to GHCR, so that install command and those links do not
work. Until the first release, build the image yourself and install from the checkout. `./hack/kind-deploy.sh`
does all of it for a local kind cluster; against any other cluster, build and push the image to a
registry your nodes can read, then:

```bash
helm install gapura ./charts/gapura --namespace gapura-system --create-namespace \
  --set image.repository=<your-registry>/gapura --set image.tag=0.1.0
```

Without those two values the chart points at the placeholder registry and the pods sit in
`ImagePullBackOff`.

Then point a Gateway at the `gapura` class:

```bash
kubectl apply -f - <<'EOF'
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: { name: main }
spec:
  gatewayClassName: gapura
  listeners: [{ name: http, port: 80, protocol: HTTP }]
EOF
kubectl get gateway main -o jsonpath='{.status.conditions[?(@.type=="Programmed")].status}{"\n"}'
```

Chart values, RBAC, and the admin endpoints are documented in [charts/gapura/values.yaml](charts/gapura/values.yaml).
The Grafana dashboard is [deploy/grafana/gapura-overview.json](deploy/grafana/gapura-overview.json); `--set metrics.dashboard.enabled=true` ships it as a ConfigMap for the Grafana sidecar.
Example alerts are in [deploy/prometheus-rule.yaml](deploy/prometheus-rule.yaml); `--set metrics.prometheusRule.enabled=true` ships them as a PrometheusRule (needs the Prometheus Operator CRDs).
The conformance report is in [conformance/](conformance/). To reproduce everything locally:

```bash
./hack/kind-deploy.sh      # image + chart in kind, one request through the gateway
./hack/conformance.sh      # Gateway API GATEWAY-HTTP suite (needs Go 1.26)
```

`hack/conformance.sh` defaults `FIXTURE=0`, so it deploys the chart without the e2e fixture from
`hack/kind-deploy.sh`: the suite brings its own Gateways on port 80 and the fixture would compete
for that address. Pass `FIXTURE=1 ./hack/conformance.sh` to keep the fixture as well.

## Development

```bash
cargo test -p gapura-core                 # unit + golden tests (< 60 s)
cargo install cargo-insta                 # once; needed for the review command below
cargo insta review                        # review changed golden snapshots
cargo run -p gapura-core --example dump -- crates/gapura-core/tests/fixtures/basic-http/input
./hack/chart-render.sh                    # helm lint plus rendered output vs the golden files
cargo deny check all                      # licenses and advisories
```

### Running the data plane locally

`cargo build -p gapura` compiles a vendored OpenSSL the first time (a few minutes). Then follow
[crates/gapura/examples/dev/README.md](crates/gapura/examples/dev/README.md) to run Gapura against a
local backend with the file-based config source. End-to-end tests (`cargo test -p gapura`) start the
real binary against generated configs and a mock upstream.

### Running against a Kubernetes cluster

```bash
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.6.2/standard-install.yaml
kubectl apply -f deploy/rbac.yaml
cargo run -p gapura -- --kubernetes --listen-http 127.0.0.1:8080 --listen-https 127.0.0.1:8443 --admin 127.0.0.1:9090 --lease-namespace gapura-system
```

The controller watches GatewayClass, Gateway, HTTPRoute, ReferenceGrant, BackendTLSPolicy,
Namespace, Service, EndpointSlice, TLS Secrets, and ConfigMaps (`ca.crt` only), writes status as
the holder of the `gapura-leader` Lease, and publishes `--publish-address` values and the
LoadBalancer addresses of `--publish-service namespace/name` into Gateway status.
`hack/kind-e2e.sh` runs the control-plane e2e against a local kind cluster.

TLS to backends: attach a `BackendTLSPolicy` (CA from a ConfigMap `ca.crt`, or
`wellKnownCACertificates: System`) to a Service, or annotate the Service with
`gapura.dev/backend-tls: insecure` to encrypt without verification.

`gapura-core` is the pure translation library (Gateway API resources in, routing Config and status out). The Kubernetes controller lives in the `gapura` binary, packaged by the Dockerfile and the chart in [charts/gapura](charts/gapura).

License: Apache-2.0.
