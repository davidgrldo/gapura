#!/usr/bin/env bash
# Load-test a running Gapura listener. Starts nothing: point it at a live gateway.
#   bench/run.sh [URL] [DURATION] [CONNECTIONS]
# Indicative numbers only; never a CI gate.
set -euo pipefail
cd "$(dirname "$0")/.."

URL=${1:-${GAPURA_BENCH_URL:-http://127.0.0.1/}}
DURATION=${2:-30s}
CONNS=${3:-50}
HOST_HEADER=${GAPURA_BENCH_HOST:-echo.e2e}
ADMIN=${GAPURA_BENCH_ADMIN:-http://127.0.0.1:19090}

snapshot() {
  curl -s "$ADMIN/metrics" 2>/dev/null \
    | grep -E '^gapura_(requests_total|upstream_errors_total)' | head -10 || true
}

echo "== metrics before"; snapshot
if command -v oha >/dev/null 2>&1; then
  echo "== oha: $CONNS connections for $DURATION against $URL (Host: $HOST_HEADER)"
  oha -z "$DURATION" -c "$CONNS" --no-tui -H "Host: ${HOST_HEADER}" "$URL" || true
elif command -v hey >/dev/null 2>&1; then
  echo "== hey (oha not found): $CONNS connections for $DURATION against $URL"
  hey -z "$DURATION" -c "$CONNS" -host "$HOST_HEADER" "$URL" || true
else
  cat >&2 <<'EOF'
No HTTP load generator found. Install one:
    cargo install oha      # preferred: percentiles, HTTP/2
    brew install hey
Then rerun: bench/run.sh [URL] [DURATION] [CONNECTIONS]
EOF
  exit 127
fi
echo "== metrics after"; snapshot
