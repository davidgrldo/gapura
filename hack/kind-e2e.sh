#!/usr/bin/env bash
# Control-plane e2e against a local kind cluster: CRDs, RBAC, fixture, then the gapura binary
# runs on the host with --kubernetes and the test asserts status and hot reload.
# Needs: kind, kubectl, docker. hack/kind-up.sh brings up the kind cluster and the Gateway API
# CRDs if missing, and never deletes the cluster. It runs with REQUIRE_PORTS=0 because this path,
# unlike the deploy path, never dials a Gateway through a host port: the gateway runs here on the
# host and binds its own.
# Stands the chart's in-cluster gapura down for the run if one is installed, and puts it back.
set -euo pipefail
cd "$(dirname "$0")/.."

REQUIRE_PORTS=0 ./hack/kind-up.sh

# The chart may already be installed here. That gapura binds :80, wins the leader lease, and
# publishes Gateway status from its own ports, so the host-run gateway below never gets to and the
# fixture's 8080 listener is reported PortUnavailable -- the test then just times out waiting for
# Programmed=True with no hint why. Stand it down for the run, and put it back however we exit.
REPLICAS=$(kubectl -n gapura-system get deploy gapura -o jsonpath='{.spec.replicas}' 2>/dev/null || true)
if [ -n "$REPLICAS" ] && [ "$REPLICAS" != 0 ]; then
  echo "in-cluster gapura found: scaling to 0 for this run, back to $REPLICAS on exit"
  trap 'kubectl -n gapura-system scale deploy gapura --replicas='"$REPLICAS" EXIT
  kubectl -n gapura-system scale deploy gapura --replicas=0
  kubectl -n gapura-system wait --for=delete pod -l app.kubernetes.io/name=gapura --timeout=90s
fi

kubectl apply -f deploy/rbac.yaml
kubectl apply -f deploy/kind/fixture.yaml
kubectl -n gapura-e2e rollout status deploy/echo --timeout=120s
cargo build -p gapura
GAPURA_KIND=1 cargo test -p gapura --test kind_e2e -- --ignored --nocapture
