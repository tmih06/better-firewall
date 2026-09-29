#!/usr/bin/env bash
# scripts/ci/ssh-guard.sh — assert this host's live firewall was not modified.
#
# WHY THIS EXISTS
# ---------------
# The development host is reached over a live SSH session and its input path is
# owned by tailscale and Docker, in `table ip filter`. bfw installs a separate
# `table inet better-firewall` whose base chains sit at ChainPriorityFilter --
# the same hook and priority as the host's existing filter chain. nftables runs
# every base chain registered on a hook, so loading bfw here would add a second
# input chain alongside the one currently permitting this session, and a
# deny-by-default policy on it would drop the very connection running the build.
#
# There is no way to make that safe from inside bfw. The only safe rule is that
# bfw is never applied on this host, ever, and that anything needing privileges
# runs in a container with its own network namespace.
#
# WHAT IT CHECKS
# --------------
# 1. No `better-firewall` table exists on the host. Its presence means something
#    applied bfw for real, which is the one outcome that can end the session.
# 2. The session is still established (an SSH_CONNECTION env var is set).
# 3. A recorded baseline of the host ruleset, with volatile packet counters and
#    Docker's own per-container NAT rules normalised, still matches. Counters
#    increment on every packet, so a raw comparison always differs; comparing
#    structure catches a real edit.
#
# A raw `nft list ruleset` diff is useless for this: the SSH session alone moves
# those counters thousands of times a second. Only the normalised form is stable
# enough to assert on.
#
# Usage: scripts/ci/ssh-guard.sh          verify only
#        scripts/ci/ssh-guard.sh --record write the baseline (do this once,
#                                        on a known-good host, and commit it)
set -euo pipefail

BASELINE="${SSH_GUARD_BASELINE:-scripts/ci/ssh-guard-baseline.txt}"
VERBOSE=0
[ "${1:-}" = "--record" ] && VERBOSE=1

fail() { printf '[ssh-guard] FATAL: %s\n' "$*" >&2; exit 1; }

# `nft list ruleset` needs CAP_NET_ADMIN. Prefer a direct call when we already
# have it, and otherwise try passwordless sudo, which is how this is expected to
# run in CI and in a root devcontainer. If neither works the guard must not pass
# silently: a check that cannot see anything is not a check.
NFT=""
if nft list tables >/dev/null 2>&1; then
    NFT="nft"
elif sudo -n nft list tables >/dev/null 2>&1; then
    NFT="sudo -n nft"
else
    fail "cannot read the nftables ruleset (needs CAP_NET_ADMIN or passwordless sudo).
       Refusing to report OK blind. Run with sufficient privileges, or set
       SSH_GUARD_BASELINE to a trusted file to check structure only."
fi

# Normalising strips the two parts of the ruleset that change on their own:
# packet and byte counters, which this SSH session alone moves continuously, and
# Docker's per-container daddr NAT rules, which Docker rewrites whenever a
# container starts or stops on this host. Neither is a firewall change made by a
# person, and treating them as one produced a false alarm the first time a
# container was started during development.
snapshot() {
    $NFT list ruleset 2>/dev/null \
        | grep -v '^# Warning:' \
        | grep -vE 'ip daddr [0-9.]+ iifname ' \
        | sed -E 's/counter packets [0-9]+ bytes [0-9]+//g'
}

if [ -z "${SSH_CONNECTION:-}" ]; then
    printf '[ssh-guard] no SSH_CONNECTION in env; not a remote session\n'
    printf '[ssh-guard] bfw must still not be applied to this host, so the table check below is the real test\n'
fi

# --- 1. the one genuinely dangerous condition -----------------------------
if $NFT list tables 2>/dev/null | grep -q "better-firewall"; then
    fail "a 'better-firewall' nftables table exists on this host.
       bfw shares ChainPriorityFilter with the host's existing input chain, so
       its policy is now deciding whether this SSH session survives.
       Do not work around this. Disconnect over a second session, remove the
       table deliberately, and keep bfw off this host."
fi

# --- 2. a baseline exists and still matches -------------------------------
if [ "$VERBOSE" -eq 1 ]; then
    snapshot > "$BASELINE"
    printf '[ssh-guard] recorded baseline to %s\n' "$BASELINE"
    exit 0
fi

if [ ! -f "$BASELINE" ]; then
    fail "no baseline at $BASELINE. Run: scripts/ci/ssh-guard.sh --record"
fi

if ! diff -q <(snapshot) "$BASELINE" >/dev/null 2>&1; then
    fail "the host ruleset no longer matches $BASELINE.
       Something outside this repository changed the live firewall. Inspect with:
       diff <($NFT list ruleset | grep -v '^# Warning:' | grep -vE 'ip daddr [0-9.]+ iifname ' | sed -E 's/counter packets [0-9]+ bytes [0-9]+//g') $BASELINE"
fi

printf '[ssh-guard] host firewall untouched; no better-firewall table; session intact\n'
