#!/usr/bin/env bash
# Run the network-visible firewall showcase against a prepared bfw laptop.
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
SOURCE_PORT="${PERF_SOURCE_PORT:-8082}"
LOGGED_PORT="${PERF_LOGGED_PORT:-8083}"
HTTP_MODE="${PERF_HTTP_MODE:-allowed}"

if [[ "$HTTP_MODE" != "allowed" && "$HTTP_MODE" != "blocked" ]]; then
    echo "Error: PERF_HTTP_MODE must be 'allowed' or 'blocked'" >&2
    exit 2
fi

probe() {
    local mode="$1" port="$2"
    printf '[showcase] %-7s http://%s:%s/\n' "$mode" "$HOST" "$port"
    k6 run --quiet -e "MODE=$mode" -e "TARGET_URL=http://${HOST}:${port}/" \
        "$REPO_ROOT/scripts/perf/probe.js"
}

probe "$HTTP_MODE" "$HTTP_PORT"
probe blocked "$DENIED_PORT"
probe allowed "$SOURCE_PORT"
probe allowed "$LOGGED_PORT"
