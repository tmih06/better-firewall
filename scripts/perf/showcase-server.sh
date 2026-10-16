#!/usr/bin/env bash
# Start local HTTP listeners used by the two-laptop firewall showcase.
set -euo pipefail

ports=("${PERF_HTTP_PORT:-8080}" "${PERF_DENIED_PORT:-8081}" "${PERF_SOURCE_PORT:-8082}" "${PERF_LOGGED_PORT:-8083}")
pids=()
cleanup() {
    for pid in "${pids[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
}
trap cleanup EXIT INT TERM

for port in "${ports[@]}"; do
    python3 -m http.server "$port" --bind 0.0.0.0 &
    pids+=("$!")
    printf '[showcase-server] listening on 0.0.0.0:%s (PID %s)\n' "$port" "${pids[-1]}"
done

wait
