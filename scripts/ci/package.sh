#!/usr/bin/env bash
# scripts/ci/package.sh — verify packaging: build the binary and perform a
# fully staged `make install DESTDIR=<tmpdir>`, assert the installed file
# layout, smoke `bfw --version` under BFW_PREFIX=<stage> (cli.Run writes
# store defaults before flag handling — the prefix keeps even privileged
# runs off the host FS), validate the systemd units with `systemd-analyze
# verify` rooted at the stage, then run `make uninstall DESTDIR=<tmpdir>`
# and assert the binary and units are gone (the stage's applications.d dir
# stays behind, matching the documented uninstall). Safe: never touches the
# host filesystem; a PATH stub stands in for systemctl and fails the run if
# anything invokes it (the Makefile must skip systemctl when DESTDIR is
# set); never needs root.
#
# Usage: scripts/ci/package.sh   (no arguments; used by the `package` CI job
# and safe to run locally)
set -euo pipefail

cd "$(dirname "$0")/../.."

log() { printf '[package] %s\n' "$*"; }
die() { printf '[package] FATAL: %s\n' "$*" >&2; exit 1; }
if [ "$(id -u)" -eq 0 ]; then
    die "must run unprivileged; the packaging check refuses root"
fi

STAGE="$(mktemp -d "${TMPDIR:-/tmp}/bfw-package.XXXXXX")"
STUBBIN="$(mktemp -d "${TMPDIR:-/tmp}/bfw-package-bin.XXXXXX")"
trap 'rm -rf "$STAGE" ${STUBBIN:+"$STUBBIN"}' EXIT
[ -d "$STAGE" ] || die "stage dir missing"
case "$STAGE" in
    "${TMPDIR:-/tmp}"/bfw-package.*) : ;;
    *) die "refusing non-tmp stage dir: $STAGE" ;;
esac
[ -d "$STUBBIN" ] || die "stub bin dir missing"
# Shadow systemctl with a fail-loud marker stub. The Makefile must skip
# systemctl whenever DESTDIR is set; if a regression ever drops that guard,
# the stub is what runs — never the real systemctl, never the host systemd.
cat > "$STUBBIN/systemctl" <<EOF
#!/bin/sh
echo "[package] FATAL: systemctl invoked (args: \$*)" >&2
: > "$STUBBIN/called"
exit 1
EOF
chmod +x "$STUBBIN/systemctl"
PATH="$STUBBIN:$PATH"; export PATH

# ---------------------------------------------------------------- build+stage
log "make install DESTDIR=$STAGE"
# Snapshot host paths first so we can prove afterwards that the staged
# install wrote nothing outside $STAGE (e.g. a Makefile regression dropping
# DESTDIR would otherwise clobber a real system silently).
host_paths=(/usr/sbin/bfw /etc/systemd/system/bfirewall.service \
    /etc/systemd/system/bfirewall-sweep.service \
    /etc/systemd/system/bfirewall-sweep.timer /etc/bfirewall)
declare -A pre=()
for p in "${host_paths[@]}"; do
    if [ -e "$p" ]; then pre["$p"]=1; fi
done
make install DESTDIR="$STAGE" BFW_BIN="$STAGE/.bfw-build" >/dev/null
rm -f "$STAGE/.bfw-build"
for p in "${host_paths[@]}"; do
    if [ -e "$p" ] && [ -z "${pre[$p]:-}" ]; then
        die "staged install created host file $p — DESTDIR isolation broken"
    fi
done


BIN="$STAGE/usr/sbin/bfw"
UNITDIR_STAGED="$STAGE/etc/systemd/system"

# ------------------------------------------------------------- file layout
log "asserting installed layout"
[ -f "$BIN" ] || die "missing $BIN"
[ -x "$BIN" ] || die "$BIN is not executable"
[ -d "$STAGE/etc/bfirewall/applications.d" ] || die "missing applications.d staging dir"
for u in bfirewall.service bfirewall-sweep.service bfirewall-sweep.timer; do
    [ -f "$UNITDIR_STAGED/$u" ] || die "missing staged unit $u"
    [ ! -x "$UNITDIR_STAGED/$u" ] || die "unit $u must not be executable"
done

# Inventory: the stage must contain exactly the paths we expect — a Makefile
# regression that drops files (or dirs) anywhere else fails here.
log "checking for unexpected staged files"
expected="$(printf '%s\n' \
    "$STAGE/usr" "$STAGE/usr/sbin" "$BIN" \
    "$STAGE/etc" "$STAGE/etc/systemd" "$UNITDIR_STAGED" \
    "$UNITDIR_STAGED/bfirewall.service" \
    "$UNITDIR_STAGED/bfirewall-sweep.service" \
    "$UNITDIR_STAGED/bfirewall-sweep.timer" \
    "$STAGE/etc/bfirewall" "$STAGE/etc/bfirewall/applications.d" \
    | sort)"
actual="$(find "$STAGE" -mindepth 1 | sort)"
unexpected="$(comm -13 <(printf '%s\n' "$expected") <(printf '%s\n' "$actual"))"
if [ -n "$unexpected" ]; then
    printf '[package] unexpected paths in stage:\n%s\n' "$unexpected" >&2
    exit 1
fi
missing="$(comm -23 <(printf '%s\n' "$expected") <(printf '%s\n' "$actual"))"
if [ -n "$missing" ]; then
    printf '[package] expected paths missing from stage:\n%s\n' "$missing" >&2
    exit 1
fi

# -------------------------------------------------------- binary smoke test
# cli.Run() materializes store defaults via Store.EnsureDefaults *before*
# flag handling, so plain `bfw --version` would try to write under
# /etc/bfirewall on the host. BFW_PREFIX redirects that state root into the
# stage — this both keeps the "never touches host FS" promise airtight (even
# when run privileged) and exercises the staged etc/bfirewall/ for real.
log "smoke: staged bfw --version (BFW_PREFIX=$STAGE)"
BFW_PREFIX="$STAGE" "$BIN" --version >/dev/null || die "staged bfw --version failed"
# Snapshot the stage after the smoke so the post-uninstall inventory can
# allow exactly the materialized default files EnsureDefaults added.
post_smoke="$(find "$STAGE" -mindepth 1 | sort)"

# --------------------------------------------------------- systemd verify
if command -v systemd-analyze >/dev/null 2>&1; then
    # Seed minimal stub targets so verify can resolve WantedBy=/After=
    # dependencies without a full systemd tree.
    for t in sysinit.target local-fs.target network-pre.target multi-user.target timers.target; do
        printf '[Unit]\nDescription=%s stub (packaging test)\n' "$t" > "$UNITDIR_STAGED/$t"
    done
    log "systemd-analyze verify --root=$STAGE"
    systemd-analyze verify --root="$STAGE" \
        "$UNITDIR_STAGED/bfirewall.service" \
        "$UNITDIR_STAGED/bfirewall-sweep.service" \
        "$UNITDIR_STAGED/bfirewall-sweep.timer" \
        || die "systemd-analyze verify failed"
    rm -f "$UNITDIR_STAGED"/*.target
    # Referenced units' ExecStart binary exists inside the stage:
    grep -q 'ExecStart=/usr/sbin/bfw boot-load' "$UNITDIR_STAGED/bfirewall.service" \
        || die "bfirewall.service ExecStart drifted from /usr/sbin/bfw boot-load"
elif [ "${CI:-}" = "true" ]; then
    die "systemd-analyze not found on CI runner (install systemd package)"
else
    log "systemd-analyze not found; skipping unit verification (fine locally)"
fi

# ------------------------------------------------------ staged uninstall
# `make uninstall` documents the removal path; with DESTDIR set it must
# delete the staged binary + units, skip every systemctl call, and leave the
# applications.d directory in place (it holds user-managed app profiles).
# Expected post-uninstall state = post-smoke snapshot minus exactly the
# binary and the three units.
log "make uninstall DESTDIR=$STAGE"
make uninstall DESTDIR="$STAGE" >/dev/null
if [ -e "$BIN" ] || [ -L "$BIN" ]; then
    die "staged binary still present after uninstall"
fi
for u in bfirewall.service bfirewall-sweep.service bfirewall-sweep.timer; do
    { [ ! -e "$UNITDIR_STAGED/$u" ] && [ ! -L "$UNITDIR_STAGED/$u" ]; } \
        || die "staged unit $u still present after uninstall"
done
[ -d "$STAGE/etc/bfirewall/applications.d" ] \
    || die "applications.d staging dir must survive uninstall"
[ ! -e "$STUBBIN/called" ] || die "systemctl was invoked despite DESTDIR"
removed="$(printf '%s\n' \
    "$BIN" \
    "$UNITDIR_STAGED/bfirewall.service" \
    "$UNITDIR_STAGED/bfirewall-sweep.service" \
    "$UNITDIR_STAGED/bfirewall-sweep.timer" \
    | sort)"
expected_leftover="$(comm -23 <(printf '%s\n' "$post_smoke") <(printf '%s\n' "$removed"))"
leftover="$(find "$STAGE" -mindepth 1 | sort)"
unexpected="$(comm -13 <(printf '%s\n' "$expected_leftover") <(printf '%s\n' "$leftover"))"
if [ -n "$unexpected" ]; then
    printf '[package] unexpected paths left in stage after uninstall:\n%s\n' "$unexpected" >&2
    exit 1
fi
gone="$(comm -23 <(printf '%s\n' "$expected_leftover") <(printf '%s\n' "$leftover"))"
if [ -n "$gone" ]; then
    printf '[package] paths unexpectedly removed by uninstall:\n%s\n' "$gone" >&2
    exit 1
fi
# Prove the host-path snapshot is unchanged — a Makefile regression that
# dropped DESTDIR would have just run `rm -f /usr/sbin/bfw` for real.
for p in "${host_paths[@]}"; do
    if [ -e "$p" ] && [ -z "${pre[$p]:-}" ]; then
        die "staged uninstall created host file $p — DESTDIR isolation broken"
    fi
    if [ ! -e "$p" ] && [ -n "${pre[$p]:-}" ]; then
        die "staged uninstall removed host file $p — DESTDIR isolation broken"
    fi
done


log "packaging check passed — staged install, unit verify, uninstall (stage: $STAGE, removed on exit)"
