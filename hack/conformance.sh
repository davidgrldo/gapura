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

# Exported so hack/kind-up.sh installs the CRDs for the same release this script checks out.
# Left unexported the two would agree only by both spelling the same literal, and bumping one
# would leave the cluster on the old CRDs with nothing to say why the suite started failing.
export GWAPI=${GWAPI:-v1.6.2}
CHECKOUT=${CHECKOUT:-/tmp/gateway-api-$GWAPI}
ORG=${ORG:-davidgrldo}
PROJECT=${PROJECT:-gapura}
# Derived, not repeated: the report folder is already ${ORG}-${PROJECT}, so a fork running with
# its own ORG would otherwise file a report under its own name while still stamping this repo's
# URL and issue tracker inside it. A report may not be hand-edited, so that mistake costs a whole
# rerun to undo.
URL=${URL:-https://github.com/$ORG/$PROJECT}
VERSION=${VERSION:-v0.1.0}
CONTACT=${CONTACT:-https://github.com/$ORG/$PROJECT/issues}
PROFILE=${PROFILE:-GATEWAY-HTTP}
REPORT_DIR="$REPO_ROOT/conformance/reports/v1.6/${ORG}-${PROJECT}"
REPORT="$REPORT_DIR/standard-${VERSION}-default-report.yaml"

# The tests that fail by construction today, and therefore the only failures a run is allowed to
# have. This changes nothing about the suite: it still runs at full strength below, with no
# --skip-tests and no --exempt-features, and the report still records whatever actually happened.
# All this list decides is the exit status of *this script*, so that the nightly job in
# .github/workflows/conformance.yml is a signal rather than a light that is red every night for
# something already known, documented, and indistinguishable from a real regression.
#
# The list is empty: HTTPRouteMultipleGateways used to fail by construction (one published
# address for every Gateway of the class), and an address per Gateway -- --gateway-address plus
# the translator's bind-port remap of colliding listeners, wired up in kind by kind-config.yaml,
# kind-second-service.yaml and values-kind.yaml -- closed it. 37 of 37 now.
#
# The comparison at the end of this script is an equality, not a subset: a test that fails and is
# not on this list is a regression and fails the run, and a test on this list that starts passing
# also fails the run -- that is good news, but it makes the counts in the docs and in the
# committed report wrong, so it must not pass silently. Keep the list non-empty, or rework that
# comparison. With the list empty, ANY failure fails the run, which is the point.
EXPECTED_FAILURES=()

# The suite brings its own Gateways on port 80; the e2e fixture would put a second one there
# and change what is being measured. Default it off here so a plain run reproduces the
# recorded report, while FIXTURE=1 still works for anyone who wants both.
export FIXTURE=${FIXTURE:-0}

echo "==> cluster and chart"
./hack/kind-deploy.sh

echo "==> gateway-api $GWAPI checkout"
if [ ! -d "$CHECKOUT" ]; then
  git clone --depth 1 --branch "$GWAPI" https://github.com/kubernetes-sigs/gateway-api.git "$CHECKOUT"
fi

mkdir -p "$REPORT_DIR"
# A suite that panics, fails to build, or is killed by the -timeout never writes a report, and the
# committed one from the last good run is still sitting there. Without something to date the run
# against, that stale file would read as a clean result for a run that measured nothing.
STAMP=$(mktemp)
trap 'rm -f "$STAMP"' EXIT

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
# `go test` exits non-zero whenever a test fails, and the known failure above makes that the normal
# outcome, so its status is captured rather than left to `set -e`. Nothing is decided here: the
# verdict is the expected-failure comparison at the bottom.
set +e
go test -timeout 60m . -run TestConformance -args \
  --gateway-class=gapura \
  --supported-features=Gateway,ReferenceGrant,HTTPRoute,HTTPRoute303RedirectStatusCode,HTTPRoute307RedirectStatusCode,HTTPRoute308RedirectStatusCode,HTTPRouteRequestMirror,PathMatchRegularExpression \
  --conformance-profiles="$PROFILE" \
  --organization="$ORG" \
  --project="$PROJECT" \
  --url="$URL" \
  --version="$VERSION" \
  --contact="$CONTACT" \
  --report-output="$REPORT" \
  --cleanup-base-resources=true
GO_RC=$?
set -e

if [ ! "$REPORT" -nt "$STAMP" ]; then
  echo "" >&2
  echo "FAIL go test exited $GO_RC without writing $REPORT." >&2
  echo "     Nothing was measured, so there is no result to compare: that is a broken run, not a" >&2
  echo "     test outcome. The go test output above says why." >&2
  exit 1
fi

echo "==> report at $REPORT"
grep -A6 '^profiles:' "$REPORT" || true

# The report's own failedTests list, rather than a scrape of go test's output: it is what the suite
# recorded, what the committed report shows, and what a reader of either one sees. Every
# failedTests block in the file is collected, so a failure under any profile counts.
ACTUAL=$(awk '
  /^[[:space:]]*failedTests:[[:space:]]*$/ { collecting = 1; next }
  collecting && /^[[:space:]]*-[[:space:]]+/ {
    sub(/^[[:space:]]*-[[:space:]]+/, ""); gsub(/^"|"$/, ""); print; next
  }
  { collecting = 0 }
' "$REPORT" | sort -u)
EXPECTED=$(printf '%s\n' ${EXPECTED_FAILURES[@]-} | sort -u | grep -v '^$' || true)

if [ "$ACTUAL" = "$EXPECTED" ]; then
  echo "==> the failures are exactly the expected set, so this run passes (go test exited $GO_RC):"
  if [ "${#EXPECTED_FAILURES[@]}" -gt 0 ]; then
    printf '    %s\n' "${EXPECTED_FAILURES[@]}"
  else
    echo "    (none — the suite passed clean)"
  fi
  exit 0
fi

echo "" >&2
echo "FAIL the set of failing tests changed. Expected on the left, this run on the right:" >&2
diff <(printf '%s\n' "$EXPECTED" | grep -v '^$') \
     <(printf '%s\n' "$ACTUAL" | grep -v '^$') >&2 || true
echo "" >&2
echo "     A '>' line is a test that failed and was not expected to: a regression. Fix the code." >&2
echo "     A '<' line is an expected failure that now passes: drop it from EXPECTED_FAILURES at the" >&2
echo "     top of this script, and correct the pass counts quoted in conformance/README.md," >&2
echo "     README.md and conformance/reports/v1.6/${ORG}-${PROJECT}/README.md." >&2
exit 1
