# Changelog

Notable changes, newest first. Gapura has not had a tagged release yet: v0.1.0 is still
unreleased, so "upgrading" below means `helm upgrade` from an older checkout of this repository.

## Unreleased

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
