#!/usr/bin/env bash
# scripts/perf/run.sh - Run k6 from an attacker container against a defended
# bfw server container, retaining the bfw/ufw comparison and CI report.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

# Docker firewall benchmarks are permitted only on disposable GitHub-hosted
# runners. Containers use an internal-only bridge with no host-published ports.
if [ "${CI:-}" != "true" ] || [ "${GITHUB_ACTIONS:-}" != "true" ] ||
    [ "${BFW_PERF_RUNNER_ENV:-}" != "github-hosted" ]; then
    echo "FATAL: Container performance benchmarks run only on GitHub-hosted CI." >&2
    exit 1
fi

for cmd in docker python3; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "FATAL: Required tool '$cmd' is not installed or not in PATH." >&2
        exit 1
    fi
done
if ! docker compose version >/dev/null 2>&1; then
    echo "FATAL: Docker Compose v2 is required." >&2
    exit 1
fi
if [ ! -x "$REPO_ROOT/bfw" ]; then
    echo "FATAL: Expected executable bfw artifact at $REPO_ROOT/bfw." >&2
    exit 1
fi

echo "[perf] Running comparison engine pre-flight test suite..."
python3 "$REPO_ROOT/scripts/perf/compare_test.py"

export K6_VERSION="${K6_VERSION:-2.3.0}"
PERF_UID="$(id -u)"
PERF_GID="$(id -g)"
export PERF_UID PERF_GID
COMPOSE_PROJECT="bfw-perf-$$"
COMPOSE_FILE="$REPO_ROOT/scripts/perf/compose.yaml"

compose() {
    docker compose --project-name "$COMPOSE_PROJECT" --file "$COMPOSE_FILE" "$@"
}

server_exec() {
    compose exec --no-TTY server "$@"
}

attacker_exec() {
    compose exec --no-TTY attacker "$@"
}

probe() {
    local mode="$1"
    local port="$2"
    attacker_exec k6 run -q \
        -e MODE="$mode" \
        -e TARGET_URL="http://server:${port}/" \
        /scripts/probe.js
}

PERF_CARDINALITIES="${PERF_CARDINALITIES:-10 100 500 1000}"
read -r -a CARDINALITIES <<< "$PERF_CARDINALITIES"
if [ "${#CARDINALITIES[@]}" -eq 0 ]; then
    echo "FATAL: PERF_CARDINALITIES must include at least one rule count." >&2
    exit 1
fi
PERF_DURATION="${PERF_DURATION:-10s}"
PERF_WARMUP_DURATION="${PERF_WARMUP_DURATION:-2s}"
PERF_VUS="${PERF_VUS:-10}"
PERF_CHURN_RPS="${PERF_CHURN_RPS:-200}"
PERF_PEAK_VUS="${PERF_PEAK_VUS:-50}"
PERF_MIXED_STAGES="${PERF_MIXED_STAGES:-4s:0,6s:${PERF_PEAK_VUS},10s:${PERF_PEAK_VUS},5s:0}"
PERF_REPEATS="${PERF_REPEATS:-3}"
PERF_RESOURCE_SAMPLE_INTERVAL="${PERF_RESOURCE_SAMPLE_INTERVAL:-1}"
PERF_PROFILES="${PERF_PROFILES:-keepalive churn mixed}"
read -r -a PROFILES <<< "$PERF_PROFILES"
if [ "${#PROFILES[@]}" -eq 0 ]; then
    echo "FATAL: PERF_PROFILES must include at least one traffic profile." >&2
    exit 1
fi

HTTP_PORT=8080
DENIED_PORT=8081
ARTIFACTS_DIR="$REPO_ROOT/artifacts/performance"
RAW_DIR="$ARTIFACTS_DIR/raw"
mkdir -p "$RAW_DIR"
rm -f "$RAW_DIR"/*.json

APPLY_TIMES_FILE="$RAW_DIR/apply_times.json"
METADATA_FILE="$RAW_DIR/metadata.json"

cleanup() {
    echo "[perf] Removing benchmark containers and internal network..."
    compose down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

# The compose network is internal and publishes no container port on the
# runner. NET_ADMIN is granted only to the defender; k6 remains unprivileged.
echo "[perf] Building the bfw server and starting attacker/server containers..."
if ! compose up --build --detach; then
    compose logs --no-color >&2 || true
    exit 1
fi
SERVER_CONTAINER_ID="$(compose ps -q server)"
ATTACKER_CONTAINER_ID="$(compose ps -q attacker)"
if [[ -z "$SERVER_CONTAINER_ID" || -z "$ATTACKER_CONTAINER_ID" ]]; then
    echo "FATAL: Could not resolve benchmark container IDs for resource sampling." >&2
    exit 1
fi
BFW_BINARY_SIZE_BYTES="$(server_exec stat -c '%s' /usr/local/bin/bfw)"
UFW_LAUNCHER_PATH="$(server_exec sh -c 'command -v ufw')"
UFW_LAUNCHER_SIZE_BYTES="$(server_exec stat -c '%s' "$UFW_LAUNCHER_PATH")"
UFW_PACKAGE_INSTALLED_KIB="$(server_exec dpkg-query -W -f="\${Installed-Size}" ufw)"
echo "[perf] bfw executable: ${BFW_BINARY_SIZE_BYTES} bytes; ufw launcher: ${UFW_LAUNCHER_SIZE_BYTES} bytes; ufw package: ${UFW_PACKAGE_INSTALLED_KIB} KiB."
K6_VER="$(attacker_exec k6 version | head -n 1)"
echo "[perf] Using ${K6_VER}; k6 attacker and firewall server are on the private Docker network."

# ==============================================================================
# SECURITY CONTROLS: baseline, permitted traffic, and denied traffic
# ==============================================================================
echo "[perf] Verifying baseline reachability before enabling the firewall..."
BASELINE_CONTROL_PASSED=0
if probe allowed "$HTTP_PORT" && probe allowed "$DENIED_PORT"; then
    BASELINE_CONTROL_PASSED=1
else
    echo "FATAL: Both server ports must return HTTP 200 before firewall setup." >&2
    exit 1
fi

reset_firewalls() {
    server_exec sh -c \
        'bfw disable >/dev/null 2>&1 || true; bfw --force reset >/dev/null 2>&1 || true; ufw disable >/dev/null 2>&1 || true; ufw --force reset >/dev/null 2>&1 || true'
}

reset_firewalls
server_exec bfw default deny incoming >/dev/null
server_exec bfw allow "${HTTP_PORT}/tcp" >/dev/null
server_exec bfw --force enable >/dev/null

POS_CONTROL_PASSED=0
if probe allowed "$HTTP_PORT"; then
    POS_CONTROL_PASSED=1
fi

NEG_CONTROL_PASSED=0
if probe blocked "$DENIED_PORT"; then
    NEG_CONTROL_PASSED=1
fi

echo "[perf] Controls: baseline=${BASELINE_CONTROL_PASSED}, permitted=${POS_CONTROL_PASSED}, denied=${NEG_CONTROL_PASSED}"
if [ "$POS_CONTROL_PASSED" -ne 1 ] || [ "$NEG_CONTROL_PASSED" -ne 1 ]; then
    echo "FATAL: bfw did not allow port ${HTTP_PORT} and block port ${DENIED_PORT}." >&2
    exit 1
fi

BENCH_CONTROLS_PASSED=0
reset_firewalls

# Apply timings and process resources; each list has one sample per repeat.
# {"bfw": {"10": {"rule_add_seconds": [...], "rule_add_cpu_seconds": [...],
#                 "rule_add_peak_rss_kib": [...], ...}}, "ufw": {...}}
python3 - "$APPLY_TIMES_FILE" <<'PY'
import json
import sys

with open(sys.argv[1], "w", encoding="utf-8") as output:
    json.dump({"bfw": {}, "ufw": {}}, output)
PY

record_apply_time() {
    local engine="$1"
    local cardinality="$2"
    local timing_json="$3"
    python3 - "$APPLY_TIMES_FILE" "$engine" "$cardinality" "$timing_json" <<'PY'
import json
import math
import sys

path, engine, cardinality, timing_json = sys.argv[1:]
try:
    timing = json.loads(timing_json)
    if timing.get("engine") != engine or timing.get("rule_count") != int(cardinality):
        raise SystemExit(f"FATAL: apply timing identity mismatch for {engine}/{cardinality}")
    measurements = {
        field: float(timing[field])
        for field in (
            "rule_add_seconds",
            "enable_seconds",
            "total_seconds",
            "rule_add_cpu_seconds",
            "enable_cpu_seconds",
            "rule_add_peak_rss_kib",
            "enable_peak_rss_kib",
        )
    }
    if any(not math.isfinite(value) or value < 0 for value in measurements.values()):
        raise SystemExit(f"FATAL: invalid apply timing for {engine}/{cardinality}")
except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
    raise SystemExit(f"FATAL: malformed apply timing for {engine}/{cardinality}: {exc}")

with open(path, "r", encoding="utf-8") as source:
    results = json.load(source)
bucket = results.setdefault(engine, {}).setdefault(
    cardinality, {field: [] for field in measurements}
)
for field, value in measurements.items():
    bucket[field].append(value)
with open(path, "w", encoding="utf-8") as output:
    json.dump(results, output, indent=2)
PY
}

apply_rules() {
    local engine="$1"
    local count="$2"
    reset_firewalls
    server_exec python3 /usr/local/lib/bfw-perf/apply_rules.py "$engine" "$count" "$HTTP_PORT"
}

verify_benchmark_controls() {
    local scenario="$1"
    if probe allowed "$HTTP_PORT" && probe blocked "$DENIED_PORT"; then
        BENCH_CONTROLS_PASSED=$((BENCH_CONTROLS_PASSED + 1))
        echo "[perf] Controls verified for ${scenario}: port ${HTTP_PORT}=HTTP 200, port ${DENIED_PORT}=blocked."
        return 0
    fi

    echo "FATAL: ${scenario} did not both allow ${HTTP_PORT} and block ${DENIED_PORT}." >&2
    exit 1
}

execute_k6_run() {
    local scenario="$1"
    local profile="$2"
    local repeat="$3"
    local output_file="/results/${scenario}_${profile}_r${repeat}.json"

    # Warmup metrics are discarded; keep the script's summary out of the repo.
    attacker_exec k6 run -q \
        -e PROFILE="$profile" \
        -e VUS=5 \
        -e CHURN_RPS=50 \
        -e DURATION="$PERF_WARMUP_DURATION" \
        -e MIXED_STAGES="1s:5,1s:0" \
        -e TARGET_URL="http://server:${HTTP_PORT}/" \
        -e SUMMARY_PATH=/tmp/warmup.json \
        /scripts/firewall.js >/dev/null 2>&1 || true

    echo "[perf] Executing k6 ${profile} run for ${scenario} (repeat ${repeat}/${PERF_REPEATS})..."
    python3 "$REPO_ROOT/scripts/perf/measure_resources.py" \
        --summary "$RAW_DIR/${scenario}_${profile}_r${repeat}.json" \
        --sample-interval "$PERF_RESOURCE_SAMPLE_INTERVAL" \
        --container server "$SERVER_CONTAINER_ID" \
        --container attacker "$ATTACKER_CONTAINER_ID" \
        -- \
        docker compose --project-name "$COMPOSE_PROJECT" --file "$COMPOSE_FILE" \
        exec --no-TTY attacker k6 run \
        -e PROFILE="$profile" \
        -e VUS="$PERF_VUS" \
        -e CHURN_RPS="$PERF_CHURN_RPS" \
        -e DURATION="$PERF_DURATION" \
        -e MIXED_STAGES="$PERF_MIXED_STAGES" \
        -e TARGET_URL="http://server:${HTTP_PORT}/" \
        -e SUMMARY_PATH="$output_file" \
        /scripts/firewall.js
}

# =============================================================================
# EXECUTION MATRIX: profiles x rule scales x repeats, alternating engine order
# Raw files: <engine>_<rules>_<profile>_r<repeat>.json (baseline uses 0 rules).
# =============================================================================
for ((repeat = 1; repeat <= PERF_REPEATS; repeat++)); do
    echo "===================================================================="
    echo "[perf] Starting benchmark repeat ${repeat}/${PERF_REPEATS}"
    echo "===================================================================="

    for profile in "${PROFILES[@]}"; do
        reset_firewalls
        execute_k6_run baseline_0 "$profile" "$repeat"
    done

    if (( repeat % 2 == 1 )); then
        FIRST_ENGINE=bfw
        SECOND_ENGINE=ufw
    else
        FIRST_ENGINE=ufw
        SECOND_ENGINE=bfw
    fi

    for cardinality in "${CARDINALITIES[@]}"; do
        for engine in "$FIRST_ENGINE" "$SECOND_ENGINE"; do
            echo "[perf] Repeat ${repeat}: applying ${engine} with ${cardinality} rules..."
            apply_timing="$(apply_rules "$engine" "$cardinality")"
            record_apply_time "$engine" "$cardinality" "$apply_timing"
            verify_benchmark_controls "${engine}_${cardinality} (repeat ${repeat})"
            for profile in "${PROFILES[@]}"; do
                execute_k6_run "${engine}_${cardinality}" "$profile" "$repeat"
            done
        done
    done
done

reset_firewalls

# =============================================================================
# Metadata and report generation
# =============================================================================
BFW_VER="$(server_exec bfw --version 2>&1 | head -n 1 || echo 'bfw version unavailable')"
UFW_VER="$(server_exec ufw --version 2>&1 | head -n 1 || echo 'ufw version unavailable')"
python3 - "$METADATA_FILE" \
    "$(uname -srm)" "$(uname -m)" "$BFW_VER" "$UFW_VER" "$K6_VER" \
    "$BFW_BINARY_SIZE_BYTES" "$UFW_LAUNCHER_SIZE_BYTES" "$UFW_LAUNCHER_PATH" \
    "$UFW_PACKAGE_INSTALLED_KIB" "$PERF_RESOURCE_SAMPLE_INTERVAL" \
    "$PERF_VUS" "$PERF_PEAK_VUS" "$PERF_CHURN_RPS" "$PERF_DURATION" "$PERF_WARMUP_DURATION" \
    "$PERF_REPEATS" "$PERF_CARDINALITIES" "$PERF_PROFILES" "$PERF_MIXED_STAGES" \
    "$BASELINE_CONTROL_PASSED" "$POS_CONTROL_PASSED" \
    "$NEG_CONTROL_PASSED" "$BENCH_CONTROLS_PASSED" <<'PY'
import json
import sys

(
    path,
    kernel,
    arch,
    bfw_version,
    ufw_version,
    k6_version,
    bfw_binary_size_bytes,
    ufw_launcher_size_bytes,
    ufw_launcher_path,
    ufw_package_installed_kib,
    resource_sample_interval,
    vus,
    peak_vus,
    churn_rps,
    duration,
    warmup_duration,
    repeats,
    cardinalities,
    profiles,
    mixed_stages,
    baseline,
    positive,
    negative,
    benchmark_controls,
) = sys.argv[1:]
metadata = {
    "metadata": {
        "kernel": kernel,
        "arch": arch,
        "bfw_version": bfw_version,
        "ufw_version": ufw_version,
        "bfw_binary_size_bytes": int(bfw_binary_size_bytes),
        "ufw_launcher_size_bytes": int(ufw_launcher_size_bytes),
        "ufw_launcher_path": ufw_launcher_path,
        "ufw_package_installed_kib": int(ufw_package_installed_kib),
        "resource_sample_interval_seconds": float(resource_sample_interval),
        "k6_version": k6_version,
        "vus": vus,
        "peak_vus": peak_vus,
        "churn_rps": churn_rps,
        "duration": duration,
        "warmup_duration": warmup_duration,
        "repeats": repeats,
        "cardinalities": cardinalities,
        "profiles": profiles,
        "mixed_stages": mixed_stages,
        "isolation": "Internal-only Docker network; separate k6 attacker and firewall server containers",
    },
    "controls": {
        "baseline_unfiltered": baseline == "1",
        "positive_permitted": positive == "1",
        "negative_denied": negative == "1",
        "benchmark_rulesets_verified": int(benchmark_controls),
    },
}
with open(path, "w", encoding="utf-8") as output:
    json.dump(metadata, output, indent=2)
PY

echo "[perf] Generating performance comparison reports..."
python3 "$REPO_ROOT/scripts/perf/compare.py" \
    --results-dir "$RAW_DIR" \
    --apply-times "$APPLY_TIMES_FILE" \
    --meta-file "$METADATA_FILE" \
    --output-json "$ARTIFACTS_DIR/summary.json" \
    --output-md "$ARTIFACTS_DIR/summary.md" \
    --max-error-rate 0.01 \
    --max-p95-latency-ms 500.0

echo "[perf] Benchmark complete. Artifacts written to $ARTIFACTS_DIR/."
