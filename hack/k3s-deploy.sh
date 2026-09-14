#!/usr/bin/env bash
# Build the image, import it into a k3d cluster, install the chart with the values a stock k3s
# cluster needs, and prove a request goes through the gateway. Needs: docker, k3d, kubectl, helm.
#
# Why this exists next to hack/kind-deploy.sh: kind is vanilla Kubernetes with no LoadBalancer at
# all, and k3s is where a lot of Gateway API gateways actually run. k3d is real k3s in docker, and
# traefik is deliberately left enabled: traefik holds host ports 80/443 through k3s's own
# ServiceLB, so the chart's default LoadBalancer Service can never bind on it -- nothing fails,
# --wait just hangs -- which is exactly what happens on a stock single-node k3s box. The install
# below is therefore the NodePort one the README documents for k3s, and this script is the CI leg
# that keeps that path honest.
set -euo pipefail
cd "$(dirname "$0")/.."

CLUSTER=${CLUSTER:-gapura-k3s}
IMAGE=${IMAGE:-gapura:dev}
NS=${NS:-gapura-system}
HTTP_PORT=${HTTP_PORT:-30080}
GWAPI=${GWAPI:-v1.6.2}
CONTEXT="k3d-$CLUSTER"

if ! k3d cluster get "$CLUSTER" >/dev/null 2>&1; then
  # One host-port mapping: the runner (or a laptop) reaches the NodePort through it. Traefik and
  # its ServiceLB stay on -- they are the reason this cluster is not a kind cluster.
  k3d cluster create "$CLUSTER" \
    --kubeconfig-update-default \
    -p "${HTTP_PORT}:${HTTP_PORT}@server:0" \
    --wait
fi
kubectl config use-context "$CONTEXT"

# k3s ships no Gateway API CRDs (its traefik is not Gateway API).
kubectl apply -f "https://github.com/kubernetes-sigs/gateway-api/releases/download/${GWAPI}/standard-install.yaml"
kubectl wait --for=condition=Established --timeout=60s \
  crd/gatewayclasses.gateway.networking.k8s.io \
  crd/gateways.gateway.networking.k8s.io \
  crd/httproutes.gateway.networking.k8s.io \
  crd/backendtlspolicies.gateway.networking.k8s.io

docker build -t "$IMAGE" .
k3d image import "$IMAGE" --cluster "$CLUSTER"

helm upgrade --install gapura charts/gapura \
  --namespace "$NS" --create-namespace \
  --set "image.repository=${IMAGE%%:*}" --set "image.tag=${IMAGE##*:}" \
  --set service.type=NodePort \
  --set "service.nodePorts.http=${HTTP_PORT}" --set service.nodePorts.https=30443 \
  --set publishService=false --set 'publishAddresses={127.0.0.1}' \
  --wait --timeout 3m

# The tag never changes, so helm sees no diff and the pods keep the image they started with.
# Force them onto the one just imported, or every run tests the previous build.
kubectl -n "$NS" rollout restart deploy/gapura
kubectl -n "$NS" rollout status deploy/gapura --timeout=3m

# The e2e fixture: one Gateway, one route, one echo Deployment, in gapura-e2e.
kubectl apply -f deploy/kind/fixture.yaml
kubectl -n gapura-e2e rollout status deploy/echo --timeout=120s

# The fixture Gateway listens on 8080, which this chart does not bind; give it one on 80.
kubectl -n gapura-e2e patch gateway main --type=merge -p \
  '{"spec":{"listeners":[{"name":"http","port":80,"protocol":"HTTP","allowedRoutes":{"namespaces":{"from":"Same"}}}]}}'

echo "==> waiting for Programmed=True"
for _ in $(seq 60); do
  [ "$(kubectl -n gapura-e2e get gateway main -o jsonpath='{.status.conditions[?(@.type=="Programmed")].status}')" = "True" ] && break
  sleep 2
done
kubectl -n gapura-e2e get gateway main -o wide
kubectl -n gapura-e2e get httproute echo -o jsonpath='{.status.parents[0].conditions[*].type}={.status.parents[0].conditions[*].status}{"\n"}'

echo "==> request through the gateway (host port -> NodePort ${HTTP_PORT})"
# Right after a rollout the NodePort can still hand a connection to the terminating pod, so give
# the first request a few tries before calling it a failure.
for attempt in $(seq 10); do
  if body=$(curl -sS --fail-with-body -H 'Host: echo.e2e' "http://127.0.0.1:${HTTP_PORT}/" 2>&1); then
    printf '%s\n' "$body" | head -5
    break
  fi
  if [ "$attempt" = 10 ]; then
    echo "no answer through the gateway after 10 tries: $body" >&2
    exit 1
  fi
  sleep 2
done

echo "==> admin endpoints"
kubectl -n "$NS" port-forward "svc/gapura-admin" 19090:9090 >/tmp/gapura-k3s-pf.log 2>&1 &
pf=$!
trap 'kill $pf 2>/dev/null || true' EXIT
# The forward needs a moment, and just after a rollout it can attach to the pod that is going away.
for attempt in $(seq 15); do
  if curl -sf -o /dev/null --max-time 2 http://127.0.0.1:19090/healthz; then break; fi
  if [ "$attempt" = 15 ]; then
    echo "admin port never answered; port-forward log:" >&2
    cat /tmp/gapura-k3s-pf.log >&2
    exit 1
  fi
  sleep 2
done
curl -sS http://127.0.0.1:19090/readyz
curl -s http://127.0.0.1:19090/metrics | grep -E '^gapura_(requests_total|leader|config_reloads_total)' | head -5
echo "==> done"
