#!/usr/bin/env bash
# Build the image, load it into kind, install the chart, and prove a request goes through the
# gateway to a backend. Needs: docker, kind, kubectl, helm.
# The cluster must have hack/kind-config.yaml's port mappings; the script creates it when missing
# and tells you to delete it when it exists without them.
set -euo pipefail
cd "$(dirname "$0")/.."

CLUSTER=${CLUSTER:-gapura}
GWAPI=${GWAPI:-v1.6.2}
IMAGE=${IMAGE:-gapura:dev}
NS=${NS:-gapura-system}

if kind get clusters | grep -qx "$CLUSTER"; then
  if ! docker port "${CLUSTER}-control-plane" | grep -q '^30080/tcp'; then
    cat >&2 <<EOF
Cluster "$CLUSTER" exists without the port mappings this script needs.
Delete it and rerun (it only ever holds test fixtures):
    kind delete cluster --name $CLUSTER
EOF
    exit 1
  fi
else
  kind create cluster --name "$CLUSTER" --config hack/kind-config.yaml --wait 120s
fi
kubectl config use-context "kind-$CLUSTER"

kubectl apply -f "https://github.com/kubernetes-sigs/gateway-api/releases/download/${GWAPI}/standard-install.yaml"
kubectl wait --for=condition=Established --timeout=60s \
  crd/gatewayclasses.gateway.networking.k8s.io \
  crd/gateways.gateway.networking.k8s.io \
  crd/httproutes.gateway.networking.k8s.io \
  crd/backendtlspolicies.gateway.networking.k8s.io

docker build -t "$IMAGE" .
kind load docker-image "$IMAGE" --name "$CLUSTER"

helm upgrade --install gapura charts/gapura \
  --namespace "$NS" --create-namespace \
  --values charts/gapura/tests/values-kind.yaml \
  --set "image.repository=${IMAGE%%:*}" --set "image.tag=${IMAGE##*:}" \
  --wait --timeout 3m

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

echo "==> request through the gateway"
curl -sS --fail-with-body -H 'Host: echo.e2e' http://127.0.0.1/ | head -5
echo "==> admin endpoints"
kubectl -n "$NS" port-forward "svc/gapura-admin" 19090:9090 >/tmp/gapura-pf.log 2>&1 &
pf=$!
trap 'kill $pf 2>/dev/null || true' EXIT
sleep 2
curl -sS http://127.0.0.1:19090/readyz
curl -s http://127.0.0.1:19090/metrics | grep -E '^gapura_(requests_total|leader|config_reloads_total)' | head -5
echo "==> done"
