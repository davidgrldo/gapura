# Gapura

The Rust API gateway. Kubernetes Gateway API-native, one binary, no database, no enterprise edition. Built on [Pingora](https://github.com/cloudflare/pingora).

Status: Plan 3 done: the binary runs as a Kubernetes controller (`--kubernetes`) with status writes and leader election and speaks TLS to backends via BackendTLSPolicy; the Helm chart and the conformance suite follow in Plan 4.

- Design spec (Indonesian): [docs/superpowers/specs/2026-09-09-gapura-sp1-design.md](docs/superpowers/specs/2026-09-09-gapura-sp1-design.md)
- Diagrams: [docs/diagrams/](docs/diagrams/) (open the HTML files in a browser)
- Market research and gap analysis: [docs/superpowers/specs/research/](docs/superpowers/specs/research/)

## Development

```bash
cargo test -p gapura-core                 # unit + golden tests (< 60 s)
cargo install cargo-insta                 # once; needed for the review command below
cargo insta review                        # review changed golden snapshots
cargo run -p gapura-core --example dump -- crates/gapura-core/tests/fixtures/basic-http/input
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
the holder of the `gapura-leader` Lease, and publishes `--publish-address` values or the
LoadBalancer addresses of `--publish-service namespace/name` into Gateway status.
`hack/kind-e2e.sh` runs the control-plane e2e against a local kind cluster.

TLS to backends: attach a `BackendTLSPolicy` (CA from a ConfigMap `ca.crt`, or
`wellKnownCACertificates: System`) to a Service, or annotate the Service with
`gapura.dev/backend-tls: insecure` to encrypt without verification.

`gapura-core` is the pure translation library (Gateway API resources in, routing Config and status out). The Kubernetes controller lives in the `gapura` binary; the Helm chart follows in Plan 4.

License: Apache-2.0.
