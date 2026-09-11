# Gapura

The Rust API gateway. Kubernetes Gateway API-native, one binary, no database, no enterprise edition. Built on [Pingora](https://github.com/cloudflare/pingora).

Status: SP1 v0.1 is code-complete: the data plane, the Kubernetes controller (`--kubernetes`) with status writes and leader election, TLS to backends via BackendTLSPolicy, the Helm chart in [charts/gapura](charts/gapura), the multi-arch image, and CI. The Gateway API GATEWAY-HTTP conformance suite passes 36 of 37 core tests; the report and the reason for the one remaining failure are in [conformance/](conformance/).

- Release notes, and what changes for operators on upgrade: [CHANGELOG.md](CHANGELOG.md)
- Contributing, security policy, and code of conduct: [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- Design spec (Indonesian): [docs/superpowers/specs/2026-09-09-gapura-sp1-design.md](docs/superpowers/specs/2026-09-09-gapura-sp1-design.md)
- Diagrams: [docs/diagrams/](docs/diagrams/) (open the HTML files in a browser)
- Market research and gap analysis: [docs/superpowers/specs/research/](docs/superpowers/specs/research/)

## Quickstart

You need a cluster (Kubernetes 1.29 or newer), `kubectl`, and Helm 3.8 or newer. Steps 1 to 4 are
meant to be pasted in order and end with a request that goes through the gateway to a backend.

> **Step 2 does not work yet.** Nothing has been published to `ghcr.io/davidgrldo`, so
> `helm install ... oci://ghcr.io/...` fails until the `v0.1.0` tag is pushed; the `home` and
> `sources` URLs in [charts/gapura/Chart.yaml](charts/gapura/Chart.yaml) point at the same
> repository and are equally unpublished. Until the tag exists, install from a checkout instead:
> `./hack/kind-deploy.sh` does all of this on a local kind cluster, and against any other cluster
> build the image, push it somewhere your nodes can read, and replace step 2 with
> `helm install gapura ./charts/gapura --namespace gapura-system --create-namespace --wait --set
> image.repository=<your-registry>/gapura --set image.tag=0.1.0`, adding the no-LoadBalancer flags
> step 2 lists if your cluster needs them. Steps 1, 3 and 4 are unchanged.

No cluster? kind will do. It has no LoadBalancer, so give the node a host port that reaches the
NodePort step 2 will ask for:

```bash
kind create cluster --config - <<'EOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraPortMappings: [{ containerPort: 30080, hostPort: 80, protocol: TCP }]
EOF
```

**1. Gateway API CRDs** (standard channel, v1.6.2):

```bash
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.6.2/standard-install.yaml
kubectl wait --for=condition=Established --timeout=60s \
  crd/gatewayclasses.gateway.networking.k8s.io \
  crd/gateways.gateway.networking.k8s.io \
  crd/httproutes.gateway.networking.k8s.io
```

**2. Gapura:**

```bash
helm install gapura oci://ghcr.io/davidgrldo/charts/gapura --version 0.1.0 \
  --namespace gapura-system --create-namespace --wait
```

The chart's Service is a `LoadBalancer`, and its address is what lands in Gateway status. On a
cluster without a LoadBalancer -- kind, or minikube without `minikube tunnel` -- publish a fixed
address and a NodePort instead:

```bash
helm install gapura oci://ghcr.io/davidgrldo/charts/gapura --version 0.1.0 \
  --namespace gapura-system --create-namespace --wait \
  --set service.type=NodePort --set service.nodePorts.http=30080 \
  --set publishService=false --set 'publishAddresses={127.0.0.1}'
```

**3. A Gateway, a route, and something to route to.** The echo backend is the one
[deploy/kind/fixture.yaml](deploy/kind/fixture.yaml) uses:

```bash
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: Namespace
metadata: { name: gapura-demo }
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: { name: main, namespace: gapura-demo }
spec:
  gatewayClassName: gapura
  listeners:
  - name: http
    port: 80
    protocol: HTTP
    allowedRoutes: { namespaces: { from: Same } }
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: { name: echo, namespace: gapura-demo }
spec:
  parentRefs: [{ name: main }]
  hostnames: [echo.example]
  rules:
  - backendRefs: [{ name: echo, port: 80 }]
---
apiVersion: v1
kind: Service
metadata: { name: echo, namespace: gapura-demo }
spec:
  selector: { app: echo }
  ports: [{ name: http, port: 80, targetPort: 8080 }]
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: echo, namespace: gapura-demo }
spec:
  replicas: 1
  selector: { matchLabels: { app: echo } }
  template:
    metadata: { labels: { app: echo } }
    spec:
      containers:
      - name: echo
        image: registry.k8s.io/e2e-test-images/agnhost:2.53
        args: [netexec, --http-port=8080]
        ports: [{ containerPort: 8080, name: http }]
EOF
kubectl -n gapura-demo rollout status deploy/echo --timeout=120s
kubectl -n gapura-demo wait --for=condition=Programmed --timeout=120s gateway/main
```

The listener is on port 80 because that is the port the container binds (`ports.http` in the
chart's values). A listener on any other port is rejected with `Accepted=False`, reason
`PortUnavailable`.

**4. One request through it:**

```bash
GW=$(kubectl -n gapura-demo get gateway main -o jsonpath='{.status.addresses[0].value}')
curl -sS -H 'Host: echo.example' "http://${GW}/echo?msg=it-works"
```

That prints `it-works`: the request reached Gapura on the address in Gateway status, matched the
HTTPRoute by its `Host` header, and came back from the echo pod. Tear the demo down with
`kubectl delete ns gapura-demo`.

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
