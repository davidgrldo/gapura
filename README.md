<h1>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo/gapura-lockup-reversed.svg">
    <img alt="Gapura" src="assets/logo/gapura-lockup.svg" width="280">
  </picture>
</h1>

The Rust API gateway. Kubernetes Gateway API-native, one binary, nothing in the request path touches a database, no enterprise edition. Built on [Pingora](https://github.com/cloudflare/pingora).

Status: v0.1.0 is the latest published release: the data plane, the Kubernetes controller (`--kubernetes`) with status writes and leader election, TLS to backends via BackendTLSPolicy, the Helm chart in [charts/gapura](charts/gapura), the multi-arch image, and CI, everything the quickstart below installs. The tree is ahead of that release, the console, consumer API keys, and JWT policies among it, none of it in a stable release yet; [CHANGELOG.md](CHANGELOG.md) lists what changed. The Gateway API GATEWAY-HTTP conformance suite passes all 37 core tests plus the four extended tests it claims; the report is in [conformance/](conformance/).

- Release notes, and what changes for operators on upgrade: [CHANGELOG.md](CHANGELOG.md)
- Contributing, security policy, and code of conduct: [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- Diagrams of the data plane and its Kubernetes controller: [docs/diagrams/](docs/diagrams/) (open the HTML files in a browser)
- The mark, its variants, and how to use them: [assets/logo/](assets/logo/)

## What it does

Gateway API core, served out of one binary. Nothing in the request path touches a database, and
a separate control plane is optional rather than required:

- **Routing** on hostname, path (`Exact`, `PathPrefix` and `RegularExpression`), header, query
  parameter and method. A `RegularExpression` path must match the whole path, as in Envoy and
  Istio, so a pattern meant as a prefix ends in `.*`.
- **Filters**: request and response header modification, `RequestRedirect`, `RequestMirror` (every request, headers only; a partial mirror is refused), and
  `URLRewrite`.
- **TLS**: termination with the certificate chosen per SNI, and TLS to backends via
  `BackendTLSPolicy`, including a per-Service annotation to encrypt without verifying.
- **Traffic**: per-rule request and backend timeouts, one retry against a second endpoint when a
  connection fails, and per-route rate limits from a Service annotation, counted per replica.
  Passive outlier detection takes an endpoint out of rotation after five consecutive connect
  errors, timeouts or 502/503/504 answers, for 30 s and longer each time it happens again (up to
  5 min); it is ignored while more than half of a backend's endpoints are out, so it never leaves
  a request with nowhere to go. Counted in `gapura_upstream_ejections_total{cluster}` and
  `gapura_upstream_ejected_endpoints{cluster}`.
- **Consumer credentials**: a rule can require an API key or a JWT. The key travels through the
  configuration only as its SHA-256 hash, so a stolen config cache yields nothing to replay, and
  the presented key maps straight to the consumer it was issued to; a token that does not verify
  is refused with `401` and a `WWW-Authenticate` challenge before the request goes upstream.
  A JWT requirement takes its keys pasted as a JWKS or from the `jwks_uri` its issuer publishes
  them at, which each data plane fetches in the background and keeps through an IdP outage and
  across a restart; `gapura_jwks_fetch_errors_total{uri}` and
  `gapura_jwks_last_success_timestamp_seconds{uri}` say when it last could.
  In store mode a request limit can also be a consumer's own -- everywhere, or on one route or
  service -- and can count per consumer or per value of a header as well as per address; a
  consumer's own limit comes before any limit on everyone, in Kong's order.
- **Operations**: Prometheus metrics, a JSON access log carrying trace context and the client
  address as seen behind trusted proxies, export of that log to an HTTP endpoint and of a span per
  request to an OTLP collector, per-request debug timing behind a token ([Debug
  timing](#debug-timing)), a Grafana dashboard and example alerts, status written only by the
  replica holding the Lease, an address per Gateway when one shared address is not enough
  (`gatewayAddresses`), hot reload by atomic config swap so in-flight requests finish on the
  config they started with, and a drain on SIGTERM ([Shutdown](#shutdown)).
- **Console**: off by default. `console.enabled` deploys `gapura-control` in its own Deployment
  and Service with read-only RBAC: sign-in from a local users file or OIDC, and routes scoped to
  the namespaces each group is granted. The stock install stays one binary with no database;
  store mode (`console.store`) keeps what the console owns -- accounts, roles, the audit trail,
  and the configuration it serves to data planes running in `--control-plane` mode -- in a
  Postgres you bring. The chart never ships one, and the data plane never opens a connection to
  it: it polls `gapura-control` and keeps a disk cache. `sslmode=require` in the database URL
  turns on TLS to it, always verified; `console.store.ca` takes the CA bundle of a service that
  signs with its own, such as RDS or Cloud SQL.

### Error keys

Every answer the gateway gives on its own -- not an upstream's response, not a redirect -- names
its cause with a stable key, in an `X-Gapura-Error` header and in the access log's `error_key`
(`null` on every other line). The body is plain text, `404 no route`, unless the request's
`Accept` prefers `application/json` (names it at a quality no lower than plain text gets); then
it is `{"error":{"key":"NO_ROUTE","message":"no route","request_id":"..."}}`. The set is closed
and a key never changes meaning, so a client can match on it:

| Key | Status | Cause |
|---|---|---|
| `INVALID_REQUEST_TARGET` | 400 | the path cannot be normalised, the host is ambiguous, `;` parameters would route it elsewhere, or `Connection` names `Host` or an `X-Forwarded-*` header |
| `NO_ROUTE` | 404 | no rule matches |
| `NO_BACKEND` | 500 | the rule has no valid backend |
| `NO_ENDPOINTS` | 503 | the backend has no ready endpoint, or none left to try |
| `AUTH_KEY_MISSING` | 401 | an API key policy found no key |
| `AUTH_KEY_INVALID` | 401 | an API key policy found a key it does not accept |
| `AUTH_JWT_MISSING` | 401 | a JWT policy found no bearer token |
| `AUTH_JWT_INVALID` | 401 | a JWT policy found a token it does not accept |
| `RATE_LIMITED` | 429 | the rule's rate limit is spent for this client |
| `IP_FORBIDDEN` | 403 | an ip_restriction policy refused the client address |
| `REQUEST_TOO_LARGE` | 413 | a request_size_limit policy refused the body, by its length or as it streamed |
| `CORS_ORIGIN_FORBIDDEN` | 403 | a cors policy refused a preflight from an origin it does not allow |
| `UPSTREAM_CONNECT_TIMEOUT` | 504 | connecting to the upstream timed out |
| `UPSTREAM_TIMEOUT` | 504 | the upstream went quiet past the rule's timeout, or the request's budget ran out |
| `UPSTREAM_CONNECT_ERROR` | 502 | the upstream refused the connection or could not be reached |
| `UPSTREAM_TLS_ERROR` | 502 | the TLS handshake with the upstream failed |
| `UPSTREAM_ERROR` | 502 | the exchange with the upstream failed after it connected |
| `INTERNAL_ERROR` | 500 | the gateway failed on its own account |

A `response_transformer` on a route can remove or replace `X-Gapura-Error` like any other
response header, so a route with such a transform answers as its operator configured.

The 401 keys say whether a credential was presented, never why it was refused: that stays with
the operator, in the `reason` label of `gapura_policy_refused_total`.

A request Pingora cannot read as a well-formed one never reaches the gateway: two `Host` lines, a
`Host` that differs from the request target's authority, userinfo in either, or an unparseable
request line is answered with Pingora's own empty 400, which carries no key and leaves no access
log line.

### Shutdown

On SIGTERM, Pingora closes the listeners at once (the admin port's too), waits a 30 s grace
period for requests in flight, then gives the rest up to 30 s more. `--drain-seconds N` (the
chart's `preStopDelaySeconds`, 15 by default) puts N seconds before that, during which `/readyz`
answers `503 not ready: draining` and every listener keeps accepting, so a load balancer health
checking `/readyz` stops sending here before connections are refused. Pick N from its
deregistration time, and give the orchestrator's kill timeout room for N + 60 s (`docker stop`
waits 10 s by default; `--time` raises it). A second SIGTERM ends the drain early; SIGINT stops at
once.

### Log and trace export

Each replica can send what it logs and traces to collectors of its own. These are flags (the
chart's `telemetry` values), not per-route policies, so a Kubernetes-mode gateway exports exactly
as a `--control-plane` one does:

- `--http-log-url URL` POSTs every access-log line -- the same JSON as stdout -- in batches, as a
  JSON array. `--http-log-headers-file FILE` adds `Name: value` lines as headers to each POST, for
  a token that should never be an argument; a `Content-Type` line there is ignored, since a body
  is always `application/json`.
- `--otlp-traces-url URL` sends a span per sampled request to an OTLP/HTTP traces endpoint,
  JSON-encoded (`http://otel-collector:4318/v1/traces`); `--otlp-headers-file` as above. The span
  is SERVER kind, named `GET <route>` (the method alone when no route matched), with
  `http.request.method`, `http.response.status_code`, `url.scheme`, `url.path`, `server.address`,
  `client.address`, and `gapura.route` (the route's name, not a path template), `gapura.service`,
  `gapura.consumer`, `gapura.error_key` and `gapura.listener` when the request has them; a 5xx
  marks it an error. A method outside the nine standard ones is reported as `_OTHER`, and its
  span is named `HTTP <route>`. With it on the gateway is a hop of the trace, and the upstream's
  `traceparent` names the gateway's span as its parent. A request that arrives with a
  `traceparent` keeps its caller's sampling decision; a trace that starts at the gateway is
  sampled at `--otlp-sample-ratio` (0 to 1, default 1).

No request waits on a sink. Each sink has one queue per replica, bounded at 10 000 records and
16 MiB: when either is reached it drops its oldest record for the new one, and it warns once it
is 80% full. A batch holds up to 500 records and is sent at most a second after the first one
queued. A batch that fails is sent again after 10 ms, then twice as long each time up to a minute
apart, for a minute before it is dropped. Every record lost is counted in
`gapura_log_dropped_total{sink, reason}`: `sink` is `http_log` or `otlp_traces`, `reason` is
`queue_full` or `send_failed`. Once shutdown begins a batch no longer waits to fill and is retried
for 5 s, so the requests that finish during the grace period are exported too.

A sink verifies an `https://` endpoint's certificate against the public roots (there is no
private-CA flag yet) and follows no redirect: a 3xx answer is a failed send, retried like any
other.

Nothing exported carries a request header, so `Authorization`, `Proxy-Authorization`, `Cookie` and
an API key header never leave the gateway this way. An access-log line names the consumer a
key_auth policy identified, in `consumer`. It carries the query string only with
`--access-log-query`, and then -- on stdout too -- the value of a parameter named (in any case,
once decoded) `api_key`, `apikey`, `api-key`, `x-api-key`, `key`, `token`, `access_token`,
`id_token`, `refresh_token`, `client_secret`, `password`, `secret`, `signature`, `sig`, `code`, or
a presigned URL's `x-amz-security-token`, `x-amz-signature`, `x-amz-credential`,
`x-goog-signature` or `x-goog-credential`, or like the header a route's key_auth policy reads, is
written `<redacted>`. A span carries no query at all.

### Debug timing

`--debug-token-file FILE` (the chart's `telemetry.debugTiming`, a Secret) turns on request debug
timing. A request whose `X-Gapura-Debug-Token` header carries that token is answered with a
`Server-Timing` header, in milliseconds, which browser devtools show under Timing:

```
Server-Timing: route;dur=0.034, access.rate_limit;dur=0.001, connect;dur=0.158,
  upstream_request;dur=0.000, ttfb;dur=0.441, response;dur=0.000, total;dur=0.815
```

`route` is the route match; `access.<policy>` each Access step in the order it ran
(`access.cors`, `access.ip_restriction`, `access.jwt`, `access.key_auth`,
`access.request_size_limit`, and `access.rate_limit`, which every rule has); `upstream_request`
and `response` those phases' steps (header edits) taken whole; `connect` the upstream connect
(`connect.reused` for a pooled connection); `ttfb` from the request handed upstream to its
response head; `total` from the request read to the answer's head. A retry repeats `connect`,
`upstream_request` and `ttfb`. An answer the gateway gives itself, a 401 or a 404, carries what
ran before it.

The token is compared as a SHA-256 digest, in constant time, and the header is removed from every
request while a token is configured, so no upstream sees it. A request without the token, or with
another value, is not timed and gets no header; loopback is no exception. Without the flag nothing
is timed at all. The header goes on after the Response steps, so a response transformer cannot
remove it. The request body's streamed steps and anything after the head are not in it.

## The name

A *gapura* is the gate of a Javanese or Balinese temple. The one the mark is
drawn from is a *candi bentar*: a stepped tower split down the middle and pulled
apart, leaving a gap with no door in it. Nothing is kept out. What the gate does
is mark where one place ends and another begins, and make everything crossing
that line take one known path.

That is the whole job of this program. It does not hold your traffic, it does
not store it, and there is nothing behind the wall for it to guard: nothing in
the request path touches a database, the control plane is optional, and there is
no edition you have to buy. It stands where
the cluster meets everything else and gives what arrives a single legible way
in. The mark sets that gate inside the hexagon Kubernetes tooling is drawn in,
in a rust that is both the language and the colour of temple brick.

## Quickstart

You need a cluster (Kubernetes 1.29 or newer), `kubectl`, and Helm 3.8 or newer. Steps 1 to 4 are
meant to be pasted in order and end with a request that goes through the gateway to a backend.

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

**2. Gapura.** Two commands, and the choice between them is worth making before you paste either
one. The chart's Service is a `LoadBalancer`, its address is what lands in Gateway status, and
`--wait` blocks until that address exists -- so on a cluster where nothing assigns LoadBalancer
addresses the first command does not fail, it hangs for Helm's five-minute default and then times
out, which is the entire quickstart budget spent on the wrong command. Use it when something does
assign them: a managed cluster, or minikube with `minikube tunnel` running in another terminal.

```bash
helm install gapura oci://ghcr.io/davidgrldo/charts/gapura --version 0.1.0 \
  --namespace gapura-system --create-namespace --wait
```

Without a LoadBalancer -- a kind cluster, or anything else where a `LoadBalancer` Service stays
`<pending>` -- publish a fixed address and a NodePort instead:

```bash
helm install gapura oci://ghcr.io/davidgrldo/charts/gapura --version 0.1.0 \
  --namespace gapura-system --create-namespace --wait \
  --set service.type=NodePort --set service.nodePorts.http=30080 \
  --set publishService=false --set 'publishAddresses={127.0.0.1}'
```

**That `127.0.0.1` assumes your node maps host port 80 to the NodePort.** Skip this and nothing
upstream looks wrong: the Gateway reports `Programmed=True`, and step 4 answers
`curl: (7) Failed to connect to 127.0.0.1 port 80`.

<details>
<summary>Why, what to do if your cluster has no such mapping, and why minikube is not on that list</summary>

Gapura reads the address out of Gateway status and dials it; a Gateway address carries no port,
so step 4 goes to `127.0.0.1:80` while the Service above is on NodePort 30080. The
`kind create cluster` block above bridges the two with `extraPortMappings`; a cluster you already
had almost certainly does not. If
yours does not, either recreate it with that mapping, or find the host port that does reach 30080
and put it into step 4's `curl` by hand -- `http://127.0.0.1:<hostPort>/echo?msg=it-works` -- since
the published address stays `127.0.0.1` with no port to carry it.

minikube is deliberately not on that list. Its NodePort answers at `$(minikube ip):30080`, and
nothing listens on `127.0.0.1:80` by default, so `publishAddresses={127.0.0.1}` publishes an address
that was never going to answer. Run `minikube tunnel` in another terminal and use the LoadBalancer
command above: the tunnel is what gives the `LoadBalancer` Service a reachable address, on port 80,
which is exactly what step 4 expects.

</details>

**Stock k3s is the third case, and the commonest.** It *does* have a LoadBalancer implementation
(klipper ServiceLB), but k3s ships traefik, and traefik already holds host ports 80 and 443 through
it. A second `LoadBalancer` Service on those ports can never bind: nothing errors, the Service
stays `<pending>` and the first command above does not fail, it hangs on `--wait` until Helm's
timeout. Publish a NodePort and the node's address instead:

```bash
NODE=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].value}')
helm install gapura oci://ghcr.io/davidgrldo/charts/gapura --version 0.1.0 \
  --namespace gapura-system --create-namespace --wait \
  --set service.type=NodePort --set service.nodePorts.http=30080 --set service.nodePorts.https=30443 \
  --set publishService=false --set "publishAddresses={${NODE}}"
```

The published address carries no port, so step 4 needs the NodePort in its URL by hand -- the same
trap the details block above explains -- and the port is one the node already listens on, no host
port mapping required:

```bash
GW=$(kubectl -n gapura-demo get gateway main -o jsonpath='{.status.addresses[0].value}')
curl -sS -H 'Host: echo.example' "http://${GW}:30080/echo?msg=it-works"
```

Traefik keeps running untouched: it is an ingress of its own kind, so it neither competes with
Gapura nor notices it. Against a local k3d cluster, `./hack/k3s-deploy.sh` does all of the above in
one go, and it is also the CI leg that keeps this path working.

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

### Serving console routes

The gateway above serves HTTPRoutes. Routes created in the console (store mode) are served by a
second Deployment, `<fullname>-data-plane`, which polls the console's configuration endpoint
instead of reading the cluster. For a release `gapura` in `gapura-system`:

1. Run the console in store mode (`console.store.existingSecret`) and publish its configuration
   endpoint: `console.store.config.service.create: true` creates the ClusterIP Service
   `gapura-control-config`.
2. Give the endpoint TLS: a data plane refuses an `http://` control plane. With cert-manager, a
   self-signed CA and a certificate from it for the Service's name:

   ```yaml
   apiVersion: cert-manager.io/v1
   kind: Issuer
   metadata: { name: selfsigned, namespace: gapura-system }
   spec: { selfSigned: {} }
   ---
   apiVersion: cert-manager.io/v1
   kind: Certificate
   metadata: { name: gapura-config-ca, namespace: gapura-system }
   spec:
     isCA: true
     commonName: gapura-config-ca
     secretName: gapura-config-ca
     privateKey: { algorithm: ECDSA, size: 256 }
     issuerRef: { name: selfsigned, kind: Issuer }
   ---
   apiVersion: cert-manager.io/v1
   kind: Issuer
   metadata: { name: gapura-config-ca, namespace: gapura-system }
   spec: { ca: { secretName: gapura-config-ca } }
   ---
   apiVersion: cert-manager.io/v1
   kind: Certificate
   metadata: { name: gapura-control-config, namespace: gapura-system }
   spec:
     secretName: gapura-control-config-tls
     dnsNames: [gapura-control-config.gapura-system.svc]
     issuerRef: { name: gapura-config-ca, kind: Issuer }
   ```

   Set `console.store.config.tls.existingSecret: gapura-control-config-tls`. The same Secret's
   `ca.crt` is the CA the data plane trusts. The console reads the certificate at startup, so
   restart it after a renewal.
3. Sign in as a superuser, open Data planes and register one. Its token is shown once; store it:

   ```bash
   kubectl -n gapura-system create secret generic gapura-data-plane-token --from-file=token=/dev/stdin
   ```

   (paste the token, then Ctrl-D).
4. Enable the data plane:

   ```yaml
   dataPlane:
     enabled: true
     controlPlane:
       token: { existingSecret: gapura-data-plane-token }
       ca: { existingSecret: gapura-control-config-tls }
   ```

   With `dataPlane.controlPlane.url` empty it polls `https://gapura-control-config.gapura-system.svc:8081`,
   and the chart tells the console which port it binds for plain HTTP (`dataPlane.ports.http`).
   Its Service, `gapura-data-plane`, is ClusterIP by default (`dataPlane.service.type`):

   ```bash
   kubectl -n gapura-system port-forward svc/gapura-data-plane 8080:80
   curl -sS localhost:8080/your-route
   ```

## Development

```bash
cargo test -p gapura-core                 # unit + golden tests (< 60 s)
cargo test -p gapura-control              # console; the Postgres test skips without GAPURA_TEST_DATABASE_URL
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
`hack/kind-e2e.sh` runs the Kubernetes controller's end-to-end test against a local kind cluster.

A third config source exists besides files (`--config-dir`, above) and the cluster: `--control-plane`
polls the configuration endpoint `gapura-control` serves and keeps a disk cache, so a control-plane
outage costs new configuration, not traffic. The chart runs one with `dataPlane.enabled` (see
[Serving console routes](#serving-console-routes)). The URL must be
`https://`: every configuration carries the private key of each certificate the gateway serves.
Start `gapura-control` with `--config-tls-cert` and `--config-tls-key` to serve that endpoint over
TLS, and pass the CA that signed the certificate to the gateway with `--control-plane-ca`.
`--control-plane-insecure-http` exists only for a control plane on loopback or behind a TLS
sidecar in the same pod.

TLS to backends: attach a `BackendTLSPolicy` (CA from a ConfigMap `ca.crt`, or
`wellKnownCACertificates: System`) to a Service, or annotate the Service with
`gapura.dev/backend-tls: insecure` to encrypt without verification.

Per-route request limits come from the backend Service too: `gapura.dev/rate-limit: "20/min"`
(supported units `s`, `min`, `h`) caps each client's requests per rule at `limit` per window,
answered past the cap with `429`, `Retry-After`, `X-RateLimit-Limit` and
`X-RateLimit-Remaining: 0`. `gapura.dev/rate-limit-by: ip` is the only keying (the default;
any other value disables the pair), the counter is per replica — with N replicas the effective
allowance is N × the limit, the honest shape when replicas share no store — and rejections are
counted in `gapura_rate_limited_total{route}`.

`gapura-core` is the pure translation library (Gateway API resources in, routing Config and status out). The Kubernetes controller lives in the `gapura` binary, packaged by the Dockerfile and the chart in [charts/gapura](charts/gapura).

License: Apache-2.0.
