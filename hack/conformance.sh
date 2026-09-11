#!/usr/bin/env bash
# Run the Gateway API conformance suite (GATEWAY-HTTP profile) against Gapura in kind.
# Needs: docker, kind, kubectl, helm, go >= 1.26, git.
#
# The suite dials Gateway.status.addresses at the listener port, so the cluster must map host
# ports 80 and 443 to the chart's NodePorts (hack/kind-config.yaml) and Gapura must publish
# 127.0.0.1 (charts/gapura/tests/values-kind.yaml).
set -euo pipefail
cd "$(dirname "$0")/.."
REPO_ROOT=$(pwd)

GWAPI=${GWAPI:-v1.6.2}
CHECKOUT=${CHECKOUT:-/tmp/gateway-api-$GWAPI}
ORG=${ORG:-gapura}
PROJECT=${PROJECT:-gapura}
URL=${URL:-https://github.com/gapura-dev/gapura}
VERSION=${VERSION:-v0.1.0}
CONTACT=${CONTACT:-https://github.com/gapura-dev/gapura/issues}
PROFILE=${PROFILE:-GATEWAY-HTTP}
REPORT_DIR="$REPO_ROOT/conformance/reports/v1.6/${ORG}-${PROJECT}"
REPORT="$REPORT_DIR/standard-${VERSION}-default-report.yaml"

echo "==> cluster and chart"
./hack/kind-deploy.sh

echo "==> gateway-api $GWAPI checkout"
if [ ! -d "$CHECKOUT" ]; then
  git clone --depth 1 --branch "$GWAPI" https://github.com/kubernetes-sigs/gateway-api.git "$CHECKOUT"
fi

mkdir -p "$REPORT_DIR"
echo "==> running $PROFILE conformance, this takes 10 to 40 minutes"
cd "$CHECKOUT/conformance"
# --supported-features is passed explicitly: without it the suite infers the set from
# GatewayClass.status.supportedFeatures and skips everything if that is empty.
# The package selector is "." and not "./...": TestConformance lives only in the root
# conformance package, and every other package in the module is an echo-server helper binary
# or a harness unit test that -run TestConformance would not execute anyway. Building them
# links a dozen extra test binaries and needs about 1.5 GB more disk for no added coverage.
# `.` not `./...`: TestConformance lives only in the root conformance package, and linking the
# echo-server helper binaries alongside it costs disk for nothing.
go test -timeout 60m . -run TestConformance -args \
  --gateway-class=gapura \
  --supported-features=Gateway,ReferenceGrant,HTTPRoute \
  --conformance-profiles="$PROFILE" \
  --organization="$ORG" \
  --project="$PROJECT" \
  --url="$URL" \
  --version="$VERSION" \
  --contact="$CONTACT" \
  --report-output="$REPORT" \
  --cleanup-base-resources=true

echo "==> report at $REPORT"
grep -A6 '^profiles:' "$REPORT" || true
