#!/usr/bin/env bash
# Control-plane e2e against a local kind cluster: CRDs, RBAC, fixture, then the gapura binary
# runs on the host with --kubernetes and the test asserts status and hot reload.
# Needs: kind, kubectl, docker. Creates cluster "$CLUSTER" if missing; never deletes it.
set -euo pipefail
cd "$(dirname "$0")/.."
CLUSTER=${CLUSTER:-gapura}
GWAPI=${GWAPI:-v1.6.2}

kind get clusters | grep -qx "$CLUSTER" || kind create cluster --name "$CLUSTER" --config hack/kind-config.yaml --wait 120s
kubectl config use-context "kind-$CLUSTER"
kubectl apply -f "https://github.com/kubernetes-sigs/gateway-api/releases/download/${GWAPI}/standard-install.yaml"
kubectl wait --for=condition=Established crd/gateways.gateway.networking.k8s.io crd/httproutes.gateway.networking.k8s.io --timeout=60s
kubectl apply -f deploy/rbac.yaml
kubectl apply -f deploy/kind/fixture.yaml
kubectl -n gapura-e2e rollout status deploy/echo --timeout=120s
cargo build -p gapura
GAPURA_KIND=1 cargo test -p gapura --test kind_e2e -- --ignored --nocapture
