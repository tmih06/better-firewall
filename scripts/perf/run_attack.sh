#!/usr/bin/env bash
# scripts/perf/run_attack.sh - Attack-and-defend comparison: nmap recon, SYN
# floods, and a TCP connect flood against an HTTP service defended by bfw and
# by ufw, plus a no-firewall baseline. Legitimate keep-alive HTTP traffic runs
# concurrently with each attack to measure service availability.
#
# Same isolation model as run.sh: two containers on an internal-only Docker
# bridge, no published ports, NET_ADMIN confined to the defender's own network
# namespace (so nftables changes never touch the runner's firewall state).
#
# Permitted only on disposable GitHub-hosted runners.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

if [ "${CI:-}" != "true" ] || [ "${GITHUB_ACTIONS:-}" != "true" ] ||
   [ "${BFW_PERF_RUNNER_ENV:-}" != "github-hosted" ]; then
    echo "error: the attack comparison is restricted to disposable GitHub-hosted CI runners" >&2
    echo "       (containers use an internal-only bridge; firewall state is confined to a" >&2
    echo "       container network namespace, but this job is not meant for workstations)" >&2
    exit 2
fi

for cmd in docker python3; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "error: required command not found: $cmd" >&2
        exit 2
    fi
done
if ! docker compose version >/dev/null 2>&1; then
    echo "error: docker compose plugin not available" >&2
    exit 2
fi
if [ ! -x "$REPO_ROOT/bfw" ]; then
    echo "error: ./bfw binary missing; run 'go build -o bfw ./cmd/bfw' first" >&2
    exit 2
fi

COMPOSE_FILE="$REPO_ROOT/scripts/perf/compose.attack.yaml"
COMPOSE_PROJECT="bfw-attack-$$"

compose() { docker compose --project-name "$COMPOSE_PROJECT" --file "$COMPOSE_FILE" "$@"; }
sx() { compose exec --no-TTY server "$@"; }
ax() { compose exec --no-TTY attacker "$@"; }

HTTP_PORT=8080
DENIED_PORT=8081
# Runs on every push: keep the lab short. Rule scaling is already covered by
# the k6 performance shards; here a small ruleset is enough to exercise the
# real rule path during attacks. ufw rule-adds dominate wall time, so RULES
# stays low by default (override with PERF_ATTACK_RULES for deeper runs).
RULES="${PERF_ATTACK_RULES:-10}"
FLOOD_S="${PERF_ATTACK_FLOOD_SECONDS:-6}"
CALM_S=4
DRIVERS=/lab/attack_drivers.py

ARTIFACTS_DIR="$REPO_ROOT/artifacts/attack"
RAW_DIR="$ARTIFACTS_DIR/raw"
mkdir -p "$RAW_DIR"
rm -f "$RAW_DIR"/* 2>/dev/null || true

cleanup() {
    compose down --volumes --remove-orphans --timeout 5 >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_up() {
    for _ in $(seq 1 30); do
        if ax python3 "$DRIVERS" probe server "$HTTP_PORT" 2>/dev/null | grep -q 1; then
            return 0
        fi
        sleep 1
    done
    echo "error: defended server never became reachable" >&2
    return 1
}

reset_firewalls() {
    sx bfw --force disable >/dev/null 2>&1 || true
    sx ufw --force disable >/dev/null 2>&1 || true
    sx nft flush ruleset >/dev/null 2>&1 || true
}

# add_rules <engine>: deny incoming, allow 10001..(10000+N)/tcp plus the
# service port, enable. Mirrors run.sh's rule shape so comparisons line up.
add_rules() {
    local engine=$1
    sx "$engine" default deny incoming >/dev/null
    sx "$engine" default allow outgoing >/dev/null 2>&1 || true
    for p in $(seq 10001 $((10000 + RULES))); do
        sx "$engine" allow "$p/tcp" >/dev/null
    done
    sx "$engine" allow "$HTTP_PORT/tcp" >/dev/null
    sx "$engine" --force enable >/dev/null
}

legit() { # seconds -> json stats on stdout
    ax python3 "$DRIVERS" legit server "$HTTP_PORT" "$1" 8
}

server_cpu() {
    docker stats --no-stream --format '{{.CPUPerc}}' "$(compose ps -q server)" | tr -d '%'
}

# run_attack <name> <attacker-cmd...>: start legit traffic, run the attack for
# FLOOD_S seconds in parallel, sample defender CPU mid-attack.
run_attack() {
    local name=$1; shift
    legit $((FLOOD_S + 4)) > "$RAW_DIR/legit_during_${name}.json" &
    local legit_pid=$!
    sleep 2
    ax "$@" > "$RAW_DIR/attack_${name}.txt" 2>&1 &
    local attack_pid=$!
    sleep $((FLOOD_S / 2))
    echo "{\"server_cpu\": $(server_cpu)}" > "$RAW_DIR/cpu_${name}.json"
    wait "$attack_pid" || true
    wait "$legit_pid" || true
}

echo "[attack] Building attacker/server images..."
compose up --build --detach >/dev/null
wait_up

META="$RAW_DIR/metadata.json"
{
    echo "{"
    echo "  \"kernel\": \"$(uname -srm)\","
    echo "  \"rules\": $RULES,"
    echo "  \"flood_seconds\": $FLOOD_S,"
    echo "  \"bfw_version\": \"$(sx bfw --version 2>&1 | head -n1 || echo unknown)\","
    echo "  \"ufw_version\": \"$(sx ufw --version 2>&1 | head -n1 || echo unknown)\","
    echo "  \"hping3_version\": \"$(ax hping3 -v 2>&1 | head -n1 || echo unknown)\","
    echo "  \"nmap_version\": \"$(ax nmap --version 2>&1 | head -n1 || echo unknown)\""
    echo "}"
} > "$META"

for ENGINE in none bfw ufw; do
    echo "[attack] === engine: $ENGINE (${RULES} rules) ==="
    reset_firewalls
    if [ "$ENGINE" != none ]; then
        T0=$(date +%s.%N)
        add_rules "$ENGINE"
        T1=$(date +%s.%N)
        awk -v a="$T0" -v b="$T1" -v e="$ENGINE" -v r="$RULES" \
            'BEGIN{printf "{\"engine\":\"%s\",\"rules\":%d,\"setup_s\":%.3f}\n", e, r, b-a}' \
            > "$RAW_DIR/setup_${ENGINE}.json"
    else
        echo '{"engine":"none","rules":0,"setup_s":0}' > "$RAW_DIR/setup_${ENGINE}.json"
    fi

    # Reachability controls: service port must answer; denied port must not.
    OPEN_OK=$(ax python3 "$DRIVERS" probe server "$HTTP_PORT" | tail -1)
    DENIED_OK=$(ax python3 "$DRIVERS" probe server "$DENIED_PORT" | tail -1)
    echo "{\"engine\":\"$ENGINE\",\"open_${HTTP_PORT}\":${OPEN_OK:-0},\"open_${DENIED_PORT}\":${DENIED_OK:-0}}" \
        > "$RAW_DIR/reach_${ENGINE}.json"

    # Recon: nmap connect scan over ports 1-2000 (drop policy slows it down),
    # plus a windowed scan covering the real service/denied ports to show
    # exactly which ports each engine exposes to an attacker.
    ax nmap -Pn -p 1-2000 --max-retries 1 -T4 server \
        > "$RAW_DIR/nmap_${ENGINE}.txt" 2>&1 || true
    ax nmap -Pn -p 8070-8110 --max-retries 1 -T4 server \
        > "$RAW_DIR/nmap_window_${ENGINE}.txt" 2>&1 || true

    # Calm baseline for this engine's steady-state rule path.
    legit "$CALM_S" > "$RAW_DIR/legit_calm_${ENGINE}.json"

    # Attack 1: SYN flood against the DENIED port (firewall should absorb it).
    run_attack "synflood_denied_${ENGINE}" \
        timeout "$FLOOD_S" hping3 -S -p "$DENIED_PORT" --flood -q server

    # Attack 2: SYN flood against the ALLOWED port (worst case: attack and
    # legit traffic hit the same rule path).
    run_attack "synflood_allowed_${ENGINE}" \
        timeout "$FLOOD_S" hping3 -S -p "$HTTP_PORT" --flood -q server

    # Attack 3: TCP connect() flood against the allowed port.
    run_attack "connectflood_${ENGINE}" \
        python3 "$DRIVERS" connectflood server "$HTTP_PORT" "$FLOOD_S" 64
done

reset_firewalls

echo "[attack] Generating comparison report..."
python3 "$REPO_ROOT/scripts/perf/attack_report.py" \
    --raw-dir "$RAW_DIR" \
    --output-json "$ARTIFACTS_DIR/attack-summary.json" \
    --output-md "$ARTIFACTS_DIR/attack-summary.md"
echo "[attack] Done. Artifacts in $ARTIFACTS_DIR/"
