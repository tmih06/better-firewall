#!/usr/bin/env bash
# scripts/perf/run.sh - Orchestrate firewall performance comparison (bfw vs ufw).
# Executes genuine traversed HTTP filtering benchmarks inside isolated net/mount
# namespaces using k6, private veth client/server namespaces, baseline + positive/negative
# controls (fail-closed), representative rule cardinalities, warmup/repeats, and alternate
# execution order.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

# ==============================================================================
# 1. FAIL-CLOSED ISOLATION & NAMESPACE GUARDS
# ==============================================================================

# Guard A: Root privileges required for namespace operations
if [ "$(id -u)" -ne 0 ]; then
    if [ "${CI:-}" = "true" ] || [ "${GITHUB_ACTIONS:-}" = "true" ]; then
        ISOLATE_SH="$REPO_ROOT/scripts/ci/isolate.sh"
        if [ -x "$ISOLATE_SH" ]; then
            echo "[perf] Re-executing via sudo scripts/ci/isolate.sh..."
            exec sudo -E "$ISOLATE_SH" "$0" "$@"
        fi
    fi
    echo "FATAL: scripts/perf/run.sh requires root privileges inside an isolated container/namespace." >&2
    exit 1
fi

# Guard B: Fail-closed isolation attestation
if [ "${BFW_ISOLATED:-0}" != "1" ]; then
    if [ "${CI:-}" = "true" ] || [ "${GITHUB_ACTIONS:-}" = "true" ]; then
        ISOLATE_SH="$REPO_ROOT/scripts/ci/isolate.sh"
        if [ -x "$ISOLATE_SH" ]; then
            echo "[perf] Re-executing via scripts/ci/isolate.sh..."
            exec "$ISOLATE_SH" "$0" "$@"
        fi
    fi
    echo "FATAL: scripts/perf/run.sh requires isolated namespaces via scripts/ci/isolate.sh." >&2
    echo "Refusing unisolated execution on host system." >&2
    exit 1
fi

# Guard C: Actual Network Namespace Proof (Cannot be bypassed with any flag)
if [ ! -e /proc/self/ns/net ]; then
    echo "FATAL: /proc/self/ns/net not found; cannot verify network namespace." >&2
    exit 1
fi

CURR_NET="$(readlink /proc/self/ns/net 2>/dev/null || true)"
if [ -z "$CURR_NET" ]; then
    echo "FATAL: Cannot determine current network namespace identity." >&2
    exit 1
fi

# Original-netns comparison: when isolate.sh exported the pre-unshare netns,
# we MUST still differ from it.
if [ -n "${BFW_ORIGINAL_NET_NS:-}" ] && [ "$CURR_NET" = "$BFW_ORIGINAL_NET_NS" ]; then
    echo "FATAL: Current network namespace ($CURR_NET) matches host network namespace ($BFW_ORIGINAL_NET_NS)." >&2
    echo "Refusing to touch host network." >&2
    exit 1
fi

# PID 1 namespace proof — ALWAYS enforced, never skipped on env values.
# isolate.sh unshares a PID namespace without remounting /proc, so /proc/1/ns/net
# still resolves to the outer (host) network namespace. Requiring it readable AND
# different from CURR_NET defeats forged BFW_ORIGINAL_NET_NS/BFW_ISOLATED values.
if [ ! -r /proc/1/ns/net ]; then
    echo "FATAL: /proc/1/ns/net is not readable; cannot prove network namespace isolation." >&2
    exit 1
fi
P1_NET="$(readlink /proc/1/ns/net 2>/dev/null || true)"
if [ -z "$P1_NET" ]; then
    echo "FATAL: Cannot resolve /proc/1/ns/net; cannot prove network namespace isolation." >&2
    exit 1
fi
if [ "$CURR_NET" = "$P1_NET" ]; then
    echo "FATAL: Current network namespace ($CURR_NET) matches /proc/1/ns/net (host netns)." >&2
    echo "Refusing to touch host network." >&2
    exit 1
fi

# ==============================================================================
# 2. DEPENDENCY & PRE-FLIGHT CHECKS
# ==============================================================================

# Locate or build bfw binary
BFW_BIN="${BFW_BIN:-}"
if [ -z "$BFW_BIN" ]; then
    if [ -x "$REPO_ROOT/bfw" ]; then
        BFW_BIN="$REPO_ROOT/bfw"
    elif command -v go >/dev/null 2>&1; then
        echo "[perf] Building bfw binary..."
        go build -o "$REPO_ROOT/bfw" "$REPO_ROOT/cmd/bfw"
        BFW_BIN="$REPO_ROOT/bfw"
    else
        echo "FATAL: bfw binary not found and go compiler unavailable." >&2
        exit 1
    fi
fi

if [ ! -x "$BFW_BIN" ]; then
    echo "FATAL: bfw binary '$BFW_BIN' is not executable." >&2
    exit 1
fi

# Check required binaries
for cmd in python3 k6 ufw ip; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "FATAL: Required tool '$cmd' is not installed or not in PATH." >&2
        exit 1
    fi
done

# Run unit tests on comparison engine before creating namespaces
echo "[perf] Running comparison engine pre-flight test suite..."
python3 "$REPO_ROOT/scripts/perf/compare_test.py"

# ==============================================================================
# 3. BENCHMARK PARAMETERS & CONFIGURATION
# ==============================================================================

PERF_CARDINALITIES="${PERF_CARDINALITIES:-10 100 500}"
PERF_DURATION="${PERF_DURATION:-3s}"
PERF_WARMUP_DURATION="${PERF_WARMUP_DURATION:-1s}"
PERF_VUS="${PERF_VUS:-10}"
PERF_REPEATS="${PERF_REPEATS:-2}"

CLIENT_NS="perf_c_$$"
SERVER_NS="perf_s_$$"
VETH_C="veth_c"
VETH_S="veth_s"
CLIENT_IP="10.200.1.2"
SERVER_IP="10.200.1.1"
HTTP_PORT=8080
DENIED_PORT=8081

ARTIFACTS_DIR="$REPO_ROOT/artifacts/performance"
RAW_DIR="$ARTIFACTS_DIR/raw"
mkdir -p "$RAW_DIR"
rm -f "$RAW_DIR"/*.json

APPLY_TIMES_FILE="$RAW_DIR/apply_times.json"
METADATA_FILE="$RAW_DIR/metadata.json"

# ==============================================================================
# 4. NAMESPACE LIFECYCLE & CLEANUP
# ==============================================================================

SERVER_PID=""

cleanup() {
    echo "[perf] Cleaning up benchmark resources..."
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill -TERM "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    ip netns del "$CLIENT_NS" 2>/dev/null || true
    ip netns del "$SERVER_NS" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Create isolated client and server network namespaces connected by veth
mkdir -p /run/netns /var/run/netns
ip netns add "$CLIENT_NS"
ip netns add "$SERVER_NS"

ip link add "$VETH_C" type veth peer name "$VETH_S"
ip link set "$VETH_C" netns "$CLIENT_NS"
ip link set "$VETH_S" netns "$SERVER_NS"

# Configure client namespace
ip -n "$CLIENT_NS" link set lo up
ip -n "$CLIENT_NS" addr add "${CLIENT_IP}/24" dev "$VETH_C"
ip -n "$CLIENT_NS" link set "$VETH_C" up

# Configure server namespace
ip -n "$SERVER_NS" link set lo up
ip -n "$SERVER_NS" addr add "${SERVER_IP}/24" dev "$VETH_S"
ip -n "$SERVER_NS" link set "$VETH_S" up

# Start HTTP target server in server namespace
echo "[perf] Starting benchmark HTTP server in $SERVER_NS..."
ip netns exec "$SERVER_NS" python3 "$REPO_ROOT/scripts/perf/server.py" \
    --host "$SERVER_IP" \
    --port "$HTTP_PORT" \
    --denied-port "$DENIED_PORT" &
SERVER_PID=$!

# Wait for server readiness from client namespace; BOTH the permitted port and
# the denied-port listener must return HTTP 200 before any firewall is enabled.
READY=0
for _ in $(seq 1 30); do
    if ip netns exec "$CLIENT_NS" python3 -c "
import urllib.request

def http_200(url):
    try:
        with urllib.request.urlopen(url, timeout=1) as resp:
            return resp.status == 200
    except Exception:
        return False

exit(0 if http_200('http://${SERVER_IP}:${HTTP_PORT}/') and http_200('http://${SERVER_IP}:${DENIED_PORT}/') else 1)
" 2>/dev/null; then
        READY=1
        break
    fi
    sleep 0.1
done

if [ "$READY" -ne 1 ]; then
    echo "FATAL: Benchmark server failed to start or is unreachable across veth pair (ports ${HTTP_PORT} and ${DENIED_PORT})." >&2
    exit 1
fi
echo "[perf] Target server confirmed reachable at http://${SERVER_IP}:${HTTP_PORT}/ and http://${SERVER_IP}:${DENIED_PORT}/."

# ==============================================================================
# 5. SECURITY CONTROLS PROOF (POSITIVE & NEGATIVE CONTROLS)
# ==============================================================================
echo "[perf] Executing positive and negative security controls to verify active packet filtering..."

# Reset server firewall state
ip netns exec "$SERVER_NS" "$BFW_BIN" disable >/dev/null 2>&1 || true
ip netns exec "$SERVER_NS" "$BFW_BIN" --force reset >/dev/null 2>&1 || true
ip netns exec "$SERVER_NS" ufw disable >/dev/null 2>&1 || true
ip netns exec "$SERVER_NS" ufw --force reset >/dev/null 2>&1 || true

# Baseline control (unfiltered): with no firewall enabled, BOTH ports MUST
# return HTTP 200. This establishes that the denied-port listener is genuinely
# reachable, so a later port-8081 denial is attributable to the firewall ruleset
# (drop/timeout/refuse) and NOT to an absent listener. Fail closed.
BASELINE_CONTROL_PASSED=0
if ip netns exec "$CLIENT_NS" python3 -c "
import urllib.request

def http_200(url):
    try:
        with urllib.request.urlopen(url, timeout=1) as resp:
            return resp.status == 200
    except Exception:
        return False

exit(0 if http_200('http://${SERVER_IP}:${HTTP_PORT}/') and http_200('http://${SERVER_IP}:${DENIED_PORT}/') else 1)
" 2>/dev/null; then
    BASELINE_CONTROL_PASSED=1
fi

if [ "$BASELINE_CONTROL_PASSED" -ne 1 ]; then
    echo "FATAL: Baseline control failed - unfiltered port ${DENIED_PORT} did not return HTTP 200." >&2
    echo "Cannot attribute port ${DENIED_PORT} denials to firewall filtering; refusing to benchmark." >&2
    exit 1
fi

# Configure bfw with default deny incoming and allow only HTTP_PORT (8080)
ip netns exec "$SERVER_NS" "$BFW_BIN" default deny incoming >/dev/null 2>&1
ip netns exec "$SERVER_NS" "$BFW_BIN" allow "${HTTP_PORT}/tcp" >/dev/null 2>&1
ip netns exec "$SERVER_NS" "$BFW_BIN" --force enable >/dev/null 2>&1

# Positive control: Traffic to permitted port 8080 must return HTTP 200
POS_CONTROL_PASSED=0
if ip netns exec "$CLIENT_NS" python3 -c "
import urllib.request
try:
    with urllib.request.urlopen('http://${SERVER_IP}:${HTTP_PORT}/', timeout=2) as resp:
        if resp.status == 200:
            exit(0)
except Exception:
    exit(1)
" 2>/dev/null; then
    POS_CONTROL_PASSED=1
fi

# Negative control: Traffic to non-permitted port 8081 must be BLOCKED by the
# firewall (timeout or refusal). Combined with the baseline control above,
# unreachable here proves active filtering rather than a dead listener.
NEG_CONTROL_PASSED=0
if ! ip netns exec "$CLIENT_NS" python3 -c "
import urllib.request
try:
    with urllib.request.urlopen('http://${SERVER_IP}:${DENIED_PORT}/', timeout=2) as resp:
        exit(0)  # Reached -> failed negative control
except Exception:
    exit(1)  # Blocked/refused -> passed negative control
" 2>/dev/null; then
    NEG_CONTROL_PASSED=1
fi

echo "[perf] Controls Proof: Baseline (unfiltered)=${BASELINE_CONTROL_PASSED}, Positive (Port ${HTTP_PORT} permitted)=${POS_CONTROL_PASSED}, Negative (Port ${DENIED_PORT} blocked)=${NEG_CONTROL_PASSED}"

# Fail closed: benchmark results are meaningless without proven filtering.
if [ "$POS_CONTROL_PASSED" -ne 1 ] || [ "$NEG_CONTROL_PASSED" -ne 1 ]; then
    echo "FATAL: Security controls proof failed; refusing to run benchmarks against unverified filtering." >&2
    exit 1
fi

# Per-ruleset benchmark control counter (incremented by verify_benchmark_controls).
BENCH_CONTROLS_PASSED=0

# Clean firewall state after controls proof
ip netns exec "$SERVER_NS" "$BFW_BIN" disable >/dev/null 2>&1 || true
ip netns exec "$SERVER_NS" "$BFW_BIN" --force reset >/dev/null 2>&1 || true

# Initialize apply times storage
python3 -c "
import json
with open('${APPLY_TIMES_FILE}', 'w') as f:
    json.dump({'bfw': {}, 'ufw': {}}, f)
"

record_apply_time() {
    local engine="$1"
    local card="$2"
    local timing="$3"
    python3 -c "
import json, sys
file_path, eng, crd, tm = sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4])
with open(file_path, 'r', encoding='utf-8') as f:
    d = json.load(f)
d.setdefault(eng, {}).setdefault(crd, []).append(tm)
with open(file_path, 'w', encoding='utf-8') as f:
    json.dump(d, f, indent=2)
" "${APPLY_TIMES_FILE}" "$engine" "$card" "$timing"
}

# ==============================================================================
# 6. RULE APPLICATION & BENCHMARK HELPERS
# ==============================================================================

reset_firewalls() {
    ip netns exec "$SERVER_NS" "$BFW_BIN" disable >/dev/null 2>&1 || true
    ip netns exec "$SERVER_NS" "$BFW_BIN" --force reset >/dev/null 2>&1 || true
    ip netns exec "$SERVER_NS" ufw disable >/dev/null 2>&1 || true
    ip netns exec "$SERVER_NS" ufw --force reset >/dev/null 2>&1 || true
}

apply_rules_bfw() {
    local count="$1"
    reset_firewalls
    ip netns exec "$SERVER_NS" "$BFW_BIN" default deny incoming >/dev/null 2>&1

    local t_start
    t_start="$(python3 -c 'import time; print(time.time())')"

    # Apply count-1 dummy rules plus 1 target rule
    for port in $(seq 10001 $((10000 + count - 1))); do
        ip netns exec "$SERVER_NS" "$BFW_BIN" allow "${port}/tcp" >/dev/null 2>&1
    done
    ip netns exec "$SERVER_NS" "$BFW_BIN" allow "${HTTP_PORT}/tcp" >/dev/null 2>&1
    ip netns exec "$SERVER_NS" "$BFW_BIN" --force enable >/dev/null 2>&1

    local t_end
    t_end="$(python3 -c 'import time; print(time.time())')"
    python3 -c "print(round($t_end - $t_start, 4))"
}

apply_rules_ufw() {
    local count="$1"
    reset_firewalls
    ip netns exec "$SERVER_NS" ufw default deny incoming >/dev/null 2>&1

    local t_start
    t_start="$(python3 -c 'import time; print(time.time())')"

    # Apply count-1 dummy rules plus 1 target rule
    for port in $(seq 10001 $((10000 + count - 1))); do
        ip netns exec "$SERVER_NS" ufw allow "${port}/tcp" >/dev/null 2>&1
    done
    ip netns exec "$SERVER_NS" ufw allow "${HTTP_PORT}/tcp" >/dev/null 2>&1
    ip netns exec "$SERVER_NS" ufw --force enable >/dev/null 2>&1

    local t_end
    t_end="$(python3 -c 'import time; print(time.time())')"
    python3 -c "print(round($t_end - $t_start, 4))"
}

# Verify active filtering after a benchmark ruleset is applied: the permitted
# port must still return HTTP 200 and the denied port must be blocked (timeout
# or refusal within ~1s). Runs AFTER the apply timer closes and BEFORE k6
# measurement. Fails closed (exits) on any anomaly.
verify_benchmark_controls() {
    local scenario="$1"

    # Permitted port must return HTTP 200 under the applied ruleset.
    if ! ip netns exec "$CLIENT_NS" python3 -c "
import urllib.request
try:
    with urllib.request.urlopen('http://${SERVER_IP}:${HTTP_PORT}/', timeout=2) as resp:
        exit(0 if resp.status == 200 else 1)
except Exception:
    exit(1)
" 2>/dev/null; then
        echo "FATAL: [${scenario}] permitted port ${HTTP_PORT} unreachable or non-200 under applied ruleset." >&2
        exit 1
    fi

    # Denied port must be blocked (drop/timeout or refusal). Reachable = leak.
    if ! ip netns exec "$CLIENT_NS" python3 -c "
import urllib.request
try:
    with urllib.request.urlopen('http://${SERVER_IP}:${DENIED_PORT}/', timeout=1) as resp:
        exit(0)  # Leaked through the firewall -> control failure
except Exception:
    exit(1)  # Blocked/refused -> expected under filtering
" 2>/dev/null; then
        BENCH_CONTROLS_PASSED=$((BENCH_CONTROLS_PASSED + 1))
        echo "[perf] Controls verified for ${scenario}: port ${HTTP_PORT}=HTTP 200, port ${DENIED_PORT}=blocked."
        return 0
    fi

    echo "FATAL: [${scenario}] denied port ${DENIED_PORT} leaked through the applied ruleset." >&2
    exit 1
}

execute_k6_run() {
    local scenario="$1"
    local repeat="$2"
    local out_json="${RAW_DIR}/${scenario}_r${repeat}.json"

    # Warmup phase: results are discarded, so point SUMMARY_PATH at /dev/null to
    # prevent handleSummary from writing a stray summary.json into the repo root.
    ip netns exec "$CLIENT_NS" k6 run -q \
        -e VUS=5 \
        -e DURATION="$PERF_WARMUP_DURATION" \
        -e TARGET_URL="http://${SERVER_IP}:${HTTP_PORT}/" \
        -e SUMMARY_PATH=/dev/null \
        "$REPO_ROOT/scripts/perf/firewall.js" >/dev/null 2>&1 || true

    # Measurement phase
    echo "[perf] Executing k6 run for ${scenario} (repeat ${repeat}/${PERF_REPEATS})..."
    ip netns exec "$CLIENT_NS" k6 run \
        -e VUS="$PERF_VUS" \
        -e DURATION="$PERF_DURATION" \
        -e TARGET_URL="http://${SERVER_IP}:${HTTP_PORT}/" \
        -e SUMMARY_PATH="$out_json" \
        "$REPO_ROOT/scripts/perf/firewall.js"
}

# ==============================================================================
# 7. EXECUTION MATRIX WITH WARMUP, REPEATS, AND ALTERNATE ORDER
# ==============================================================================

for r in $(seq 1 "$PERF_REPEATS"); do
    echo "===================================================================="
    echo "[perf] Starting Benchmark Repeat $r / $PERF_REPEATS"
    echo "===================================================================="

    # Baseline: No firewall loaded
    reset_firewalls
    execute_k6_run "baseline" "$r"

    if [ $((r % 2)) -eq 1 ]; then
        # Alternate Order A: bfw first, then ufw
        for card in $PERF_CARDINALITIES; do
            echo "[perf] Repeat $r: Applying bfw with $card rules..."
            t_bfw="$(apply_rules_bfw "$card")"
            record_apply_time "bfw" "$card" "$t_bfw"
            verify_benchmark_controls "bfw_${card} (repeat $r)"
            execute_k6_run "bfw_${card}" "$r"

            echo "[perf] Repeat $r: Applying ufw with $card rules..."
            t_ufw="$(apply_rules_ufw "$card")"
            record_apply_time "ufw" "$card" "$t_ufw"
            verify_benchmark_controls "ufw_${card} (repeat $r)"
            execute_k6_run "ufw_${card}" "$r"
        done
    else
        # Alternate Order B: ufw first, then bfw
        for card in $PERF_CARDINALITIES; do
            echo "[perf] Repeat $r (alternate order): Applying ufw with $card rules..."
            t_ufw="$(apply_rules_ufw "$card")"
            record_apply_time "ufw" "$card" "$t_ufw"
            verify_benchmark_controls "ufw_${card} (repeat $r)"
            execute_k6_run "ufw_${card}" "$r"

            echo "[perf] Repeat $r (alternate order): Applying bfw with $card rules..."
            t_bfw="$(apply_rules_bfw "$card")"
            record_apply_time "bfw" "$card" "$t_bfw"
            verify_benchmark_controls "bfw_${card} (repeat $r)"
            execute_k6_run "bfw_${card}" "$r"
        done
    fi
done

# Reset firewalls after benchmark runs
reset_firewalls

# ==============================================================================
# 8. METADATA & REPORT GENERATION
# ==============================================================================

BFW_VER="$("$BFW_BIN" --version 2>&1 | head -n 1 || echo 'bfw 0.1.0')"
UFW_VER="$(ufw --version 2>&1 | head -n 1 || echo 'ufw 0.36.2')"

python3 -c "
import json, sys
meta = {
    'metadata': {
        'kernel': sys.argv[1],
        'arch': sys.argv[2],
        'bfw_version': sys.argv[3],
        'ufw_version': sys.argv[4],
        'vus': sys.argv[5],
        'duration': sys.argv[6],
        'warmup_duration': sys.argv[7],
        'repeats': sys.argv[8],
        'cardinalities': sys.argv[9],
    },
    'controls': {
        'baseline_unfiltered': sys.argv[10] == '1',
        'positive_permitted': sys.argv[11] == '1',
        'negative_denied': sys.argv[12] == '1',
        'benchmark_rulesets_verified': int(sys.argv[13]),
    }
}
with open(sys.argv[14], 'w', encoding='utf-8') as f:
    json.dump(meta, f, indent=2)
" "$(uname -srm)" "$(uname -m)" "${BFW_VER}" "${UFW_VER}" "${PERF_VUS}" "${PERF_DURATION}" "${PERF_WARMUP_DURATION}" "${PERF_REPEATS}" "${PERF_CARDINALITIES}" "${BASELINE_CONTROL_PASSED}" "${POS_CONTROL_PASSED}" "${NEG_CONTROL_PASSED}" "${BENCH_CONTROLS_PASSED}" "${METADATA_FILE}"

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
