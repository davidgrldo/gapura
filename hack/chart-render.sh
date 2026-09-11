#!/usr/bin/env bash
# Render the chart with every values permutation under charts/gapura/tests and compare against the
# committed golden output. `hack/chart-render.sh --update` rewrites the golden files.
# Needs: helm.
set -euo pipefail
cd "$(dirname "$0")/.."

CHART=charts/gapura
GOLDEN="$CHART/tests/golden"
UPDATE=${1:-}
mkdir -p "$GOLDEN"
status=0

helm lint "$CHART"

for values in "$CHART"/tests/values-*.yaml; do
  case=$(basename "$values" .yaml)
  case=${case#values-}
  out=$(helm template gapura "$CHART" --namespace gapura-system --values "$values" --kube-version 1.34)
  if [ "$UPDATE" = "--update" ]; then
    printf '%s\n' "$out" > "$GOLDEN/$case.yaml"
    echo "updated $GOLDEN/$case.yaml"
  elif ! printf '%s\n' "$out" | diff -u "$GOLDEN/$case.yaml" - > /tmp/chart-$case.diff; then
    echo "FAIL $case: rendered output differs from $GOLDEN/$case.yaml" >&2
    head -40 /tmp/chart-$case.diff >&2
    status=1
  else
    echo "ok $case"
  fi
done

exit $status
