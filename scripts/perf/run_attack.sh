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
    sx "$engine" allow "22/tcp" >/dev/null
    sx "$engine" --force enable >/dev/null
}

lx() { compose exec --no-TTY legit "$@"; }

resolve_ip() {
    sx getent hosts "$1" | awk '{print $1; exit}'
}

legit() { # seconds -> json stats on stdout
    lx python3 "$DRIVERS" legit server "$HTTP_PORT" "$1" 8
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

# --- dynamic smart banning ---------------------------------------------------

ATTACKER_IP=""

# threat_bans <ip> -> 1 if ip is in the bfw threat-ban set.
threat_bans() {
    sx nft list set inet better-firewall bfw_threat_bans 2>/dev/null | grep -q "$1"
}

# start_sshd: run a real OpenSSH daemon inside the defender; sshd -E logs to
# the file the journalctl shim tails and converts to journald JSON records.
start_sshd() {
    sx sh -c '/usr/sbin/sshd -E /var/log/bfw-attack-auth.log >/dev/null 2>&1 || true'
}

# start_protect <lapi-url-or-empty>: write protect.json + key, launch the
# fake LAPI when configured, then start `bfw protect` in the background.
start_protect() {
    sx sh -c 'mkdir -p /etc/better-firewall && printf "lab-bouncer-key-0123456789abcdef" > /etc/better-firewall/bouncer.key && chmod 600 /etc/better-firewall/bouncer.key'
    if [ -n "${1:-}" ]; then
        sx sh -c 'cat > /etc/better-firewall/protect.json <<EOF
{"jails":[{"name":"ssh","identifiers":["sshd"],"patterns":["(?i)failed password for (?:invalid user )?\\\\S+ from (?P<ip>[a-f0-9:.]+) port [0-9]+"],"max_retries":5,"find_time":"10m","ban_time":"10m","ignore_ips":["127.0.0.0/8","::1/128"]}],
 "crowdsec":{"url":"'$1'","api_key_file":"/etc/better-firewall/bouncer.key","poll_interval":"2s"}}
EOF'
        compose exec --no-TTY --detach server python3 /usr/local/lib/bfw-perf/fake_lapi.py
    else
        sx sh -c 'cat > /etc/better-firewall/protect.json <<EOF
{"jails":[{"name":"ssh","identifiers":["sshd"],"patterns":["(?i)failed password for (?:invalid user )?\\\\S+ from (?P<ip>[a-f0-9:.]+) port [0-9]+"],"max_retries":5,"find_time":"10m","ban_time":"10m","ignore_ips":["127.0.0.0/8","::1/128"]}]}
EOF'
    fi
    # Sanity: the generated protect.json must be valid JSON on the defender.
    sx python3 -c 'import json; json.load(open("/etc/better-firewall/protect.json"))' \
        > "$RAW_DIR/protect_config_check.txt" 2>&1 || echo "protect.json invalid" > "$RAW_DIR/protect_config_check.txt"
    compose exec --no-TTY --detach server bfw protect
}

# wait_ban <ip> <timeout_s>: poll the threat set; prints seconds-to-ban or -1.
wait_ban() {
    local ip=$1 limit=$2 t0 now
    t0=$(date +%s.%N)
    while true; do
        if threat_bans "$ip"; then
            date +%s.%N | awk -v a="$t0" '{printf "%.3f", $1-a}'
            return 0
        fi
        now=$(date +%s.%N)
        if awk -v a="$now" -v b="$t0" -v l="$limit" 'BEGIN{exit !((a-b) > l)}'; then
            echo "-1"
            return 1
        fi
        sleep 0.3
    done
}

# lapi_push / lapi_unban <ip>
lapi_push() { sx curl -sS -X POST -d "{\"value\":\"$1\",\"duration\":\"10m\"}" http://127.0.0.1:8085/__push; }
lapi_unban() { sx curl -sS -X POST -d "{\"value\":\"$1\"}" http://127.0.0.1:8085/__unban; }

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

# Trace the engine loop: compose-exec chatter is the only way to see which
# remote command failed when a phase exits non-zero under set -e.
set -x

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
    # --- dynamic smart banning -------------------------------------------
    ATTACKER_IP=$(resolve_ip attacker)

    if [ "$ENGINE" = bfw ]; then
        # Phase A: CrowdSec-style LAPI ban mid-traffic, then dynamic unban.
        # The fake LAPI runs on the defender's loopback (plain HTTP is only
        # permitted to loopback LAPIs by the bouncer client).
        start_protect "http://127.0.0.1:8085"
        sleep 3  # let protect reconcile the startup snapshot

        legit 14 > "$RAW_DIR/legit_during_lapiban_bfw.json" &
        LAPI_PID=$!
        sleep 2
        lapi_push "$ATTACKER_IP" >/dev/null
        BAN_S=$(wait_ban "$ATTACKER_IP" 15)
        ATK_AFTER=$(ax python3 "$DRIVERS" probe server "$HTTP_PORT" | tail -1)
        LGT_AFTER=$(lx python3 "$DRIVERS" probe server "$HTTP_PORT" | tail -1)
        lapi_unban "$ATTACKER_IP" >/dev/null
        T0=$(date +%s.%N); UNBAN_S=-1
        for _ in $(seq 1 50); do
            threat_bans "$ATTACKER_IP" || { UNBAN_S=$(date +%s.%N | awk -v a="$T0" '{printf "%.3f", $1-a}'); break; }
            sleep 0.4
        done
        wait $LAPI_PID || true
        echo "{\"lapi_ban_s\":$BAN_S,\"lapi_unban_s\":$UNBAN_S,\"attacker_after_ban\":${ATK_AFTER:-9},\"legit_after_ban\":${LGT_AFTER:-9}}" \
            > "$RAW_DIR/dynamic_lapi_bfw.json"

        # Phase B: real SSH brute-force -> journal jail ban.
        start_sshd
        sleep 1
        SSH_PRE=$(ax python3 "$DRIVERS" probe server 22 | tail -1)
        legit 20 > "$RAW_DIR/legit_during_sshjail_bfw.json" &
        LAPI_PID=$!
        sleep 1
        ax sh -c 'for i in $(seq 1 12); do timeout 4 sshpass -p wrongpw ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@server true 2>/dev/null; done' \
            > "$RAW_DIR/attack_sshbrute_bfw.txt" 2>&1
        BAN_S=$(wait_ban "$ATTACKER_IP" 15)
        SSH_POST=$(ax python3 "$DRIVERS" probe server 22 | tail -1)
        HTTP_POST=$(ax python3 "$DRIVERS" probe server "$HTTP_PORT" | tail -1)
        LGT_AFTER=$(lx python3 "$DRIVERS" probe server "$HTTP_PORT" | tail -1)
        wait $LAPI_PID || true
        echo "{\"ssh_before\":${SSH_PRE:-9},\"ssh_after\":${SSH_POST:-9},\"http_after\":${HTTP_POST:-9},\"legit_after\":${LGT_AFTER:-9},\"jail_ban_s\":$BAN_S}" \
            > "$RAW_DIR/dynamic_jail_bfw.json"
        sx pkill -f 'bfw protect' >/dev/null 2>&1 || true
        sx pkill -f fake_lapi >/dev/null 2>&1 || true
    else
        # Reference behavior: no protect mechanism exists for ufw/none, so the
        # same brute-force leaves the attacker unbanned.
        start_sshd
        sleep 1
        SSH_PRE=$(ax python3 "$DRIVERS" probe server 22 | tail -1)
        ax sh -c 'for i in $(seq 1 12); do timeout 4 sshpass -p wrongpw ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@server true 2>/dev/null; done' \
            > "$RAW_DIR/attack_sshbrute_${ENGINE}.txt" 2>&1
        SSH_POST=$(ax python3 "$DRIVERS" probe server 22 | tail -1)
        echo "{\"ssh_before\":${SSH_PRE:-9},\"ssh_after\":${SSH_POST:-9},\"mechanism\":\"none\"}" \
            > "$RAW_DIR/dynamic_jail_${ENGINE}.json"
        echo "{\"mechanism\":\"none\"}" > "$RAW_DIR/dynamic_lapi_${ENGINE}.json"
        sx pkill -x sshd >/dev/null 2>&1 || true
    fi
done

reset_firewalls

echo "[attack] Generating comparison report..."
python3 "$REPO_ROOT/scripts/perf/attack_report.py" \
    --raw-dir "$RAW_DIR" \
    --output-json "$ARTIFACTS_DIR/attack-summary.json" \
    --output-md "$ARTIFACTS_DIR/attack-summary.md"
echo "[attack] Done. Artifacts in $ARTIFACTS_DIR/"
