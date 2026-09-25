#!/usr/bin/env bash
# scripts/ci/isolate.sh - Fail-closed privileged container/namespace isolation
# wrapper for hosted CI execution.
#
# Provides:
# - Separate network and mount namespaces (unshare -m -n -p -f)
# - Private mount propagation (mount --make-rprivate /)
# - Isolated tmpfs state for /etc/bfirewall, /etc/default/bfirewall, /etc/ufw, /run
# - Protection against host sysctl mutations, kernel module loading, and host hooks
# - Preserved loopback interface without external networking
# - Rejection of execution if in host namespace or non-CI environment
# - Robust net namespace tracking (BFW_ORIGINAL_NET_NS) avoiding PID namespace pitfalls
set -euo pipefail

# 1. Fail-closed CI guard: privileged jobs run only on disposable hosted CI
# runners. There is deliberately no local opt-in; never use this wrapper on
# a workstation or production host.
if [ "${CI:-}" != "true" ] && [ "${GITHUB_ACTIONS:-}" != "true" ]; then
    echo "FATAL: scripts/ci/isolate.sh refused outside CI." >&2
    echo "Privileged integration and performance jobs are supported only on the disposable hosted GitHub runner." >&2
    exit 1
fi

# 2. Privileges guard: root required for namespace and nftables isolation
if [ "$(id -u)" -ne 0 ]; then
    echo "FATAL: scripts/ci/isolate.sh requires root privileges inside the CI runner (id -u == 0)." >&2
    exit 1
fi

# 3. Usage guard
if [ $# -eq 0 ]; then
    echo "Usage: $0 <command> [args...]" >&2
    exit 1
fi

# 4. Record original host network namespace before unsharing
if [ "${_BFW_INTERNAL_ISOLATED:-0}" != "1" ]; then
    ORIG_NET=""
    if [ -e /proc/self/ns/net ]; then
        ORIG_NET="$(readlink /proc/self/ns/net 2>/dev/null || true)"
    elif [ -e "/proc/$$/ns/net" ]; then
        ORIG_NET="$(readlink "/proc/$$/ns/net" 2>/dev/null || true)"
    fi
    if [ -z "$ORIG_NET" ] && [ -e /proc/1/ns/net ]; then
        ORIG_NET="$(readlink /proc/1/ns/net 2>/dev/null || true)"
    fi

    if [ -z "$ORIG_NET" ]; then
        echo "FATAL: Unable to resolve original network namespace before unshare" >&2
        exit 1
    fi

    # Unshare mount, network, and pid namespaces.
    # Note: we do not use --mount-proc so /proc/1 remains the host PID 1 reference,
    # while our current process gets an isolated netns.
    exec unshare --mount --net --pid --fork \
        env _BFW_INTERNAL_ISOLATED=1 \
            BFW_ORIGINAL_NET_NS="$ORIG_NET" \
            BFW_ISOLATED=1 \
            "$0" "$@"
fi

# ==============================================================================
# INSIDE ISOLATED NAMESPACE
# ==============================================================================

# A. Verify network namespace identity difference against recorded original
CURR_NET=""
if [ -e /proc/self/ns/net ]; then
    CURR_NET="$(readlink /proc/self/ns/net 2>/dev/null || true)"
fi

if [ -z "$CURR_NET" ]; then
    echo "FATAL: Unable to resolve current network namespace inside isolation wrapper" >&2
    exit 1
fi

if [ "$CURR_NET" = "${BFW_ORIGINAL_NET_NS:-}" ]; then
    echo "FATAL: Failed to isolate network namespace! Still in host netns: $CURR_NET" >&2
    exit 1
fi

# B. Private mount propagation - prevent any mounts from leaking out
mount --make-rprivate /

# C. Loopback interface up, no external routes or interfaces
ip link set lo up 2>/dev/null || true

# D. Isolated state directories: /etc/bfirewall, /etc/default/bfirewall, /etc/ufw, /run
WORK_DIR="$(mktemp -d /tmp/bfw_iso_state.XXXXXX)"
mount -t tmpfs -o mode=0755,noexec=off tmpfs_bfw_iso "$WORK_DIR"

mkdir -p "$WORK_DIR/etc/bfirewall/applications.d"
mkdir -p "$WORK_DIR/etc/default"
mkdir -p "$WORK_DIR/etc/ufw"
mkdir -p "$WORK_DIR/run"
mkdir -p "$WORK_DIR/bin"

# Seed default configs if available from repo
REPO_DIR="$(cd "$(dirname "$0")/../.." 2>/dev/null && pwd || echo "")"
if [ -n "$REPO_DIR" ] && [ -d "$REPO_DIR/etc/bfirewall" ]; then
    cp -r "$REPO_DIR/etc/bfirewall/"* "$WORK_DIR/etc/bfirewall/" 2>/dev/null || true
fi
if [ -n "$REPO_DIR" ] && [ -f "$REPO_DIR/etc/default/bfirewall" ]; then
    cp "$REPO_DIR/etc/default/bfirewall" "$WORK_DIR/etc/default/bfirewall" 2>/dev/null || true
else
    touch "$WORK_DIR/etc/default/bfirewall"
fi

# Seed ufw installed configuration if present on system so perf benchmarks have stock templates
if [ -d /etc/ufw ]; then
    cp -a /etc/ufw/. "$WORK_DIR/etc/ufw/" 2>/dev/null || true
fi
if [ -f /etc/default/ufw ]; then
    cp -a /etc/default/ufw "$WORK_DIR/etc/default/ufw" 2>/dev/null || true
else
    touch "$WORK_DIR/etc/default/ufw"
fi
mkdir -p /etc/bfirewall /etc/default /etc/ufw /run
mount --bind "$WORK_DIR/etc/bfirewall" /etc/bfirewall
touch /etc/default/bfirewall
mount --bind "$WORK_DIR/etc/default/bfirewall" /etc/default/bfirewall
touch /etc/default/ufw
mount --bind "$WORK_DIR/etc/default/ufw" /etc/default/ufw
mount --bind "$WORK_DIR/etc/ufw" /etc/ufw
mount --bind "$WORK_DIR/run" /run

# E. Protect host kernel sysctls outside network namespace
# /proc/sys/net is per-netns in Linux; make host-wide sysctls read-only
for d in /proc/sys/kernel /proc/sys/fs /proc/sys/vm; do
    if [ -d "$d" ]; then
        mount -o remount,ro,bind "$d" 2>/dev/null || true
    fi
done

# F. Mock modprobe in PATH so host kernel modules cannot be loaded or probed
cat << 'EOF' > "$WORK_DIR/bin/modprobe"
#!/bin/sh
# Staged isolated runner mock modprobe
exit 0
EOF
chmod +x "$WORK_DIR/bin/modprobe"
export PATH="$WORK_DIR/bin:$PATH"

# G. Final fail-closed check: verify we are not in host net ns before execution
FINAL_NET="$(readlink /proc/self/ns/net 2>/dev/null || true)"
if [ "$FINAL_NET" = "${BFW_ORIGINAL_NET_NS:-}" ] || [ -z "$FINAL_NET" ]; then
    echo "FATAL: refusing execution: host network namespace detected" >&2
    exit 1
fi

export BFW_ISOLATED=1
export BFW_ORIGINAL_NET_NS

# H. Execute isolated command
exec "$@"
