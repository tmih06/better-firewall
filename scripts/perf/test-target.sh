#!/usr/bin/env bash
# Probe a remote bfw test server from this machine without changing its firewall.
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 TARGET_IP" >&2
    exit 2
fi
TARGET_IP="$1"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

if ! python3 - "$TARGET_IP" <<'PY'
import ipaddress
import sys
try:
    ipaddress.ip_address(sys.argv[1])
except ValueError:
    raise SystemExit(1)
PY
then
    echo "Error: TARGET_IP must be an IPv4 or IPv6 address" >&2
    exit 2
fi
if ! command -v k6 >/dev/null 2>&1; then
    echo "Error: k6 is required (https://grafana.com/docs/k6/latest/set-up/install-k6/)" >&2
    exit 2
fi

if [[ "$TARGET_IP" == *:* ]]; then
    HOST="[$TARGET_IP]"
else
    HOST="$TARGET_IP"
fi
HTTP_PORT="${PERF_HTTP_PORT:-8080}"
DENIED_PORT="${PERF_DENIED_PORT:-8081}"

printf '[probe] Checking allowed service at http://%s:%s/ (expects HTTP 200)\n' "$HOST" "$HTTP_PORT"
k6 run --quiet -e "TARGET_URL=http://${HOST}:${HTTP_PORT}/" \
    "$REPO_ROOT/scripts/perf/probe.js"
printf '[probe] Checking denied service at http://%s:%s/ (expects blocked connection)\n' "$HOST" "$DENIED_PORT"
k6 run --quiet -e "MODE=blocked" -e "TARGET_URL=http://${HOST}:${DENIED_PORT}/" \
    "$REPO_ROOT/scripts/perf/probe.js"
