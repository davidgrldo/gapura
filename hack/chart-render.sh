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

if ! diff -q deploy/grafana/gapura-overview.json charts/gapura/dashboards/gapura-overview.json; then
  echo "FAIL dashboards differ: cp deploy/grafana/gapura-overview.json charts/gapura/dashboards/" >&2
  exit 1
fi

if ! diff -q deploy/prometheus-rule.yaml charts/gapura/prometheus-rule.yaml; then
  echo "FAIL prometheus rules differ: cp deploy/prometheus-rule.yaml charts/gapura/" >&2
  exit 1
fi

helm lint "$CHART"

# An ignore rule in .helmignore matches template paths as helm loads the chart: a template under
# a swallowed path renders as nothing, installs nothing, and fails nowhere -- templates/tests/
# under the tests/ entry once cost a whole debugging session. Fail here instead: every template
# file must contribute at least one rendered document in at least one values permutation, since
# conditional templates (metrics, dashboards) legitimately render nothing under defaults.
# NOTES.txt renders no documents by design and is exempt.
tmp_sources=$(mktemp)
trap 'rm -f "$tmp_sources"' EXIT
for values in "$CHART"/tests/values-*.yaml; do
  helm template gapura "$CHART" --namespace gapura-system --values "$values" --kube-version 1.34 \
    | grep '^# Source: gapura/templates/' >> "$tmp_sources" || true
done
sources=$(sort -u "$tmp_sources" | wc -l)
files=$(find "$CHART/templates" -type f -name '*.yaml' ! -name 'NOTES.txt' | wc -l)
if [ "$sources" -ne "$files" ]; then
  echo "FAIL: $files template files, only $sources rendered -- a .helmignore pattern swallowing one?" >&2
  diff <(find "$CHART/templates" -type f -name '*.yaml' ! -name 'NOTES.txt' -printf '%P\n' | sort) \
       <(sort -u "$tmp_sources" | sed 's|^# Source: gapura/templates/||') \
    | grep '^<' | sed 's/^</  swallowed: /' >&2
  exit 1
fi

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
