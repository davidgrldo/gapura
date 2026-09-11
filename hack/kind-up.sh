#!/usr/bin/env bash
# Bring up the kind cluster and the Gateway API CRDs. The only place either happens, so the
# version installed can never differ between the deploy path and the e2e path.
#
# Exports nothing and leaves the kubectl context pointed at the cluster. Safe to run repeatedly.
#
# REQUIRE_PORTS=0 skips the check that an *existing* cluster maps host 80/443 to the chart's
# NodePorts. hack/kind-e2e.sh is the one caller that sets it: that test runs the gateway on the
# host, binds 127.0.0.1:8080 itself, and asserts status, the Lease and hot reload through the API
# server rather than proxied traffic, so it is happy on a cluster without the mappings and used to
# run on one. hack/kind-deploy.sh (and hack/conformance.sh through it) leave it at 1, because both
# dial a Gateway listener through host port 80. A cluster *created* here always gets the mappings
# either way, since hack/kind-config.yaml is the only config we ever create one from.
set -euo pipefail
cd "$(dirname "$0")/.."

CLUSTER=${CLUSTER:-gapura}
GWAPI=${GWAPI:-v1.6.2}
REQUIRE_PORTS=${REQUIRE_PORTS:-1}

if kind get clusters | grep -qx "$CLUSTER"; then
  if [ "$REQUIRE_PORTS" != 0 ] && ! docker port "${CLUSTER}-control-plane" | grep -q '^30080/tcp'; then
    cat >&2 <<EOF
Cluster "$CLUSTER" exists without the port mappings this repo needs.
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
