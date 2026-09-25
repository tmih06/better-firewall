//go:build integration

// Package tests contains root-requiring integration tests that exercise the
// real nftables backend. Run only inside isolated namespaces via scripts/ci/isolate.sh.
package tests

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var bfwBin string

func TestMain(m *testing.M) {
	// Fail-closed isolation validation:
	// 1. Must be root (CAP_NET_ADMIN required for nftables operations)
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "FATAL: integration tests require root privileges inside an isolated runner (os.Geteuid() == 0)")
		os.Exit(1)
	}

	// 2. Explicit isolation attestation required
	if os.Getenv("BFW_ISOLATED") != "1" {
		fmt.Fprintln(os.Stderr, "FATAL: integration tests require BFW_ISOLATED=1 attestation via scripts/ci/isolate.sh")
		os.Exit(1)
	}

	// 3. Recorded original network namespace must be present
	origNet := os.Getenv("BFW_ORIGINAL_NET_NS")
	if origNet == "" {
		fmt.Fprintln(os.Stderr, "FATAL: integration tests require BFW_ORIGINAL_NET_NS environment variable")
		os.Exit(1)
	}

	// 4. Current network namespace must differ from host's recorded original
	selfNet, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: cannot read /proc/self/ns/net: %v\n", err)
		os.Exit(1)
	}
	if selfNet == "" || selfNet == origNet {
		fmt.Fprintf(os.Stderr, "FATAL: /proc/self/ns/net (%s) is identical to original host net ns (%s); refusing unisolated execution\n", selfNet, origNet)
		os.Exit(1)
	}

	// 5. Kernel-state cross-check against PID 1's network namespace.
	// BFW_ISOLATED and BFW_ORIGINAL_NET_NS are forgeable environment
	// attestation: any caller can set BFW_ISOLATED=1 plus a fabricated
	// original namespace and the env checks above would pass on the host.
	// isolate.sh uses `unshare --pid --fork` WITHOUT --mount-proc, so the
	// inner /proc still describes the outer PID namespace: /proc/1 is the
	// host init and /proc/1/ns/net is the host network namespace. Requiring
	// it to be readable and different from our own net ns proves isolation
	// independently of any env var; fail closed if same or unreadable.
	pid1Net, err := os.Readlink("/proc/1/ns/net")
	if err != nil || pid1Net == "" {
		fmt.Fprintf(os.Stderr, "FATAL: cannot read /proc/1/ns/net (%v); refusing unverified execution\n", err)
		os.Exit(1)
	}
	if pid1Net == selfNet {
		fmt.Fprintf(os.Stderr, "FATAL: /proc/1/ns/net (%s) equals self net ns; unisolated host execution refused\n", pid1Net)
		os.Exit(1)
	}

	// Build the bfw binary into a temporary directory
	buildDir, err := os.MkdirTemp("", "bfw-build-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: failed to create temporary build directory: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(buildDir)

	bfwBin = filepath.Join(buildDir, "bfw")
	out, err := exec.Command("go", "build", "-o", bfwBin, "../cmd/bfw").CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: failed to build bfw: %v\n%s\n", err, out)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

// testEnv manages per-test isolated filesystem state and kernel table cleanup.
type testEnv struct {
	t   *testing.T
	dir string
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	env := &testEnv{t: t, dir: dir}

	// Seed directory structure under BFW_PREFIX
	if err := os.MkdirAll(filepath.Join(dir, "etc", "bfirewall", "applications.d"), 0755); err != nil {
		t.Fatalf("failed to create app profile dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "etc", "default"), 0755); err != nil {
		t.Fatalf("failed to create etc default dir: %v", err)
	}

	// Ensure clean slate before and after test
	env.cleanupKernel()
	t.Cleanup(func() {
		env.cleanupKernel()
	})

	return env
}

func (e *testEnv) run(args ...string) (string, string, int) {
	e.t.Helper()
	cmd := exec.Command(bfwBin, args...)
	cmd.Env = append(os.Environ(),
		"BFW_PREFIX="+e.dir,
	)
	var so, se strings.Builder
	cmd.Stdout = &so
	cmd.Stderr = &se
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		e.t.Fatalf("failed to execute bfw %v: %v", args, err)
	}
	return so.String(), se.String(), code
}

func (e *testEnv) runOK(args ...string) string {
	e.t.Helper()
	so, se, code := e.run(args...)
	if code != 0 {
		e.t.Fatalf("runOK %v failed with code %d:\nSTDOUT: %s\nSTDERR: %s", args, code, so, se)
	}
	return so
}

func (e *testEnv) runErr(args ...string) (string, string) {
	e.t.Helper()
	so, se, code := e.run(args...)
	if code == 0 {
		e.t.Fatalf("runErr %v unexpectedly succeeded with code 0:\nSTDOUT: %s\nSTDERR: %s", args, so, se)
	}
	return so, se
}

func (e *testEnv) nft(args ...string) (string, error) {
	e.t.Helper()
	cmd := exec.Command("nft", args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (e *testEnv) cleanupKernel() {
	// Idempotently flush/remove managed tables from kernel
	_ = exec.Command("nft", "delete", "table", "inet", "bfirewall").Run()
	_ = exec.Command("nft", "delete", "table", "ip", "bfirewall-nat").Run()
	_ = exec.Command("nft", "delete", "table", "ip6", "bfirewall-nat").Run()
}

// -----------------------------------------------------------------------------
// Lifecycle: enable, disable, reload, reset, boot-load, boot-unload
// -----------------------------------------------------------------------------

func TestLifecycleEnableDisableReloadReset(t *testing.T) {
	env := newTestEnv(t)

	// 1. Initial status when disabled
	out := env.runOK("status")
	if !strings.Contains(out, "Status: inactive") {
		t.Fatalf("expected inactive status, got: %q", out)
	}

	// 2. Enable
	out = env.runOK("--force", "enable")
	if !strings.Contains(out, "Firewall is active and enabled on system startup") {
		t.Fatalf("unexpected enable output: %q", out)
	}

	// Verify live kernel ruleset has inet bfirewall table and core chains
	nftOut, err := env.nft("list", "table", "inet", "bfirewall")
	if err != nil {
		t.Fatalf("nft list table inet bfirewall failed: %v\n%s", err, nftOut)
	}
	for _, expectedChain := range []string{"chain input", "chain output", "chain forward", "chain bfw-user-input"} {
		if !strings.Contains(nftOut, expectedChain) {
			t.Fatalf("expected chain %q in kernel table:\n%s", expectedChain, nftOut)
		}
	}

	// Verify enable idempotence ("Firewall already started, use 'reload'")
	out = env.runOK("--force", "enable")
	if !strings.Contains(out, "Firewall already started, use 'reload'") {
		t.Fatalf("expected already started message on re-enable, got: %q", out)
	}

	// 3. Reload
	out = env.runOK("reload")
	if !strings.Contains(out, "Firewall reloaded") {
		t.Fatalf("unexpected reload output: %q", out)
	}

	// 4. Disable
	out = env.runOK("disable")
	if !strings.Contains(out, "Firewall stopped and disabled on system startup") {
		t.Fatalf("unexpected disable output: %q", out)
	}

	// Verify table flushed from kernel
	nftOut, err = env.nft("list", "table", "inet", "bfirewall")
	if err == nil && !strings.Contains(nftOut, "Error") && len(nftOut) > 0 {
		t.Fatalf("table still present in kernel after disable:\n%s", nftOut)
	}

	// Reload when disabled should skip
	out = env.runOK("reload")
	if !strings.Contains(out, "Firewall not enabled (skipping reload)") {
		t.Fatalf("expected skipping reload message when disabled, got: %q", out)
	}

	// 5. Reset with force
	env.runOK("--force", "enable")
	env.runOK("allow", "80/tcp")
	out = env.runOK("--force", "reset")
	if !strings.Contains(out, "Backing up") {
		t.Fatalf("expected backup notice on reset, got: %q", out)
	}

	// Verify state reset to inactive and table removed
	out = env.runOK("status")
	if !strings.Contains(out, "Status: inactive") {
		t.Fatalf("status should be inactive after reset, got: %q", out)
	}

	// 6. Boot-load and Boot-unload
	env.runOK("--force", "enable")
	env.runOK("boot-unload")
	nftOut, _ = env.nft("list", "table", "inet", "bfirewall")
	if !strings.Contains(nftOut, "Error") && len(nftOut) > 0 {
		t.Fatalf("table still present after boot-unload:\n%s", nftOut)
	}

	env.runOK("boot-load")
	nftOut, err = env.nft("list", "table", "inet", "bfirewall")
	if err != nil {
		t.Fatalf("boot-load failed to load table: %v\n%s", err, nftOut)
	}
	if !strings.Contains(nftOut, "chain input") {
		t.Fatalf("boot-load table missing chains:\n%s", nftOut)
	}
}

// -----------------------------------------------------------------------------
// Rule Grammar: allow, deny, reject, limit, duplicate handling
// -----------------------------------------------------------------------------

func TestRuleGrammarAllowDenyRejectLimit(t *testing.T) {
	env := newTestEnv(t)
	env.runOK("--force", "enable")

	// Allow 80/tcp
	out := env.runOK("allow", "80/tcp")
	if !strings.Contains(out, "Rule added") {
		t.Fatalf("allow output: %q", out)
	}

	// Deny 23/tcp
	out = env.runOK("deny", "23/tcp")
	if !strings.Contains(out, "Rule added") {
		t.Fatalf("deny output: %q", out)
	}

	// Reject 25/tcp
	out = env.runOK("reject", "25/tcp")
	if !strings.Contains(out, "Rule added") {
		t.Fatalf("reject output: %q", out)
	}

	// Limit ssh/tcp
	out = env.runOK("limit", "ssh/tcp")
	if !strings.Contains(out, "Rule added") {
		t.Fatalf("limit output: %q", out)
	}

	// Duplicate rule addition should be skipped
	out = env.runOK("allow", "80/tcp")
	if !strings.Contains(out, "Skipping adding existing rule") {
		t.Fatalf("expected skipping duplicate add, got: %q", out)
	}

	// Check kernel nftables ruleset
	nftOut, err := env.nft("list", "table", "inet", "bfirewall")
	if err != nil {
		t.Fatalf("nft list failed: %v", err)
	}

	// 80/tcp accept
	if !strings.Contains(nftOut, "tcp dport 80") || !strings.Contains(nftOut, "accept") {
		t.Fatalf("kernel table missing allow 80/tcp:\n%s", nftOut)
	}
	// 23/tcp drop
	if !strings.Contains(nftOut, "tcp dport 23") || !strings.Contains(nftOut, "drop") {
		t.Fatalf("kernel table missing deny 23/tcp:\n%s", nftOut)
	}
	// 25/tcp reject
	if !strings.Contains(nftOut, "tcp dport 25") || !strings.Contains(nftOut, "reject") {
		t.Fatalf("kernel table missing reject 25/tcp:\n%s", nftOut)
	}
	// Limit dynamic meter
	if !strings.Contains(nftOut, "bfw_limit_") || !strings.Contains(nftOut, "dynamic") {
		t.Fatalf("kernel table missing dynamic limit meter:\n%s", nftOut)
	}
}

// -----------------------------------------------------------------------------
// Rule Manipulation: insert, prepend, delete by rule and by number
// -----------------------------------------------------------------------------

func TestRuleInsertPrependDelete(t *testing.T) {
	env := newTestEnv(t)
	env.runOK("--force", "enable")

	// Add base rules
	env.runOK("allow", "8080/tcp")
	env.runOK("allow", "8081/tcp")

	// Insert at position 1
	out := env.runOK("insert", "1", "allow", "8000/tcp")
	if !strings.Contains(out, "Rule inserted") {
		t.Fatalf("expected Rule inserted, got: %q", out)
	}

	// Status numbered should show 8000/tcp at index 1
	out = env.runOK("status", "numbered")
	if !strings.Contains(out, "[ 1] 8000/tcp") {
		t.Fatalf("expected [ 1] 8000/tcp, got status:\n%s", out)
	}

	// Prepend rule (inserts at beginning)
	out = env.runOK("prepend", "allow", "7000/tcp")
	if !strings.Contains(out, "Rule inserted") && !strings.Contains(out, "Rule added") {
		t.Fatalf("expected Rule inserted on prepend, got: %q", out)
	}
	out = env.runOK("status", "numbered")
	if !strings.Contains(out, "[ 1] 7000/tcp") {
		t.Fatalf("expected [ 1] 7000/tcp after prepend, got:\n%s", out)
	}

	// Delete by rule syntax
	out = env.runOK("delete", "allow", "8080/tcp")
	if !strings.Contains(out, "Rule deleted") {
		t.Fatalf("expected Rule deleted, got: %q", out)
	}

	// Delete by rule number with force
	out = env.runOK("--force", "delete", "1")
	if !strings.Contains(out, "Rule deleted") {
		t.Fatalf("expected Rule deleted by number, got: %q", out)
	}

	// Delete non-existent rule should fail
	so, se := env.runErr("--force", "delete", "999")
	if !strings.Contains(se, "Could not find rule '999'") && !strings.Contains(so, "Could not find rule '999'") {
		t.Fatalf("expected 'Could not find rule' error, got stdout=%q stderr=%q", so, se)
	}

	// Delete non-existent rule syntax should report error or not found
	out = env.runOK("delete", "allow", "65432/tcp")
	if !strings.Contains(out, "Could not delete non-existent rule") {
		t.Fatalf("expected 'Could not delete non-existent rule', got: %q", out)
	}
}

// -----------------------------------------------------------------------------
// Route / Forwarding rules
// -----------------------------------------------------------------------------

func TestRuleRouteForwarding(t *testing.T) {
	env := newTestEnv(t)
	env.runOK("--force", "enable")

	// Add routed rule
	out := env.runOK("route", "allow", "in", "on", "eth0", "out", "on", "eth1", "to", "10.0.0.1", "port", "80", "proto", "tcp")
	if !strings.Contains(out, "Rule added") {
		t.Fatalf("expected route rule added, got: %q", out)
	}

	// Verify rule lands in bfw-user-forward chain in kernel
	nftOut, err := env.nft("list", "chain", "inet", "bfirewall", "bfw-user-forward")
	if err != nil {
		t.Fatalf("failed to list bfw-user-forward chain: %v\n%s", err, nftOut)
	}
	if !strings.Contains(nftOut, "iifname \"eth0\"") || !strings.Contains(nftOut, "oifname \"eth1\"") || !strings.Contains(nftOut, "ip daddr 10.0.0.1") {
		t.Fatalf("route rule missing expected expressions:\n%s", nftOut)
	}
}

// -----------------------------------------------------------------------------
// Dual-Stack and Single-Family Isolation
// -----------------------------------------------------------------------------

func TestDualStackAndFamilyIsolation(t *testing.T) {
	env := newTestEnv(t)
	env.runOK("--force", "enable")

	// 1. Dual-stack rule produces both v4 and v6 halves
	out := env.runOK("allow", "443/tcp")
	if !strings.Contains(out, "Rule added") || !strings.Contains(out, "Rule added (v6)") {
		t.Fatalf("expected both v4 and v6 output for dualstack allow, got: %q", out)
	}

	// Verify both v4 and v6 rules exist in bfw-user-input
	nftOut, err := env.nft("list", "chain", "inet", "bfirewall", "bfw-user-input")
	if err != nil {
		t.Fatalf("failed to list bfw-user-input chain: %v\n%s", err, nftOut)
	}
	if !strings.Contains(nftOut, "tcp dport 443") {
		t.Fatalf("expected port 443 in kernel chain:\n%s", nftOut)
	}

	// 2. IPv4-only rule
	out = env.runOK("allow", "from", "192.168.10.0/24", "to", "any", "port", "3306", "proto", "tcp")
	if !strings.Contains(out, "Rule added") || strings.Contains(out, "Rule added (v6)") {
		t.Fatalf("expected only v4 Rule added, got: %q", out)
	}

	// 3. IPv6-only rule
	out = env.runOK("allow", "from", "2001:db8::/32", "to", "any", "port", "3306", "proto", "tcp")
	if !strings.Contains(out, "Rule added (v6)") {
		t.Fatalf("expected v6 Rule added, got: %q", out)
	}

	// Verify kernel chain contains both specific address matches
	nftOut, _ = env.nft("list", "chain", "inet", "bfirewall", "bfw-user-input")
	if !strings.Contains(nftOut, "192.168.10.0/24") {
		t.Fatalf("expected IPv4 CIDR in bfw-user-input:\n%s", nftOut)
	}
	if !strings.Contains(nftOut, "2001:db8::/32") {
		t.Fatalf("expected IPv6 prefix in bfw-user-input:\n%s", nftOut)
	}
}

// -----------------------------------------------------------------------------
// Policies (default command) & Logging levels
// -----------------------------------------------------------------------------

func TestPolicyAndLoggingLevels(t *testing.T) {
	env := newTestEnv(t)
	env.runOK("--force", "enable")

	// 1. Changing default incoming policy to reject
	out := env.runOK("default", "reject", "incoming")
	if !strings.Contains(out, "Default incoming policy changed to 'reject'") {
		t.Fatalf("unexpected default policy output: %q", out)
	}

	// Check kernel input base chain or jump to bfw-reject-input
	nftOut, _ := env.nft("list", "table", "inet", "bfirewall")
	if !strings.Contains(nftOut, "bfw-reject-input") {
		t.Fatalf("expected bfw-reject-input in kernel table after default reject:\n%s", nftOut)
	}

	// Changing default outgoing policy to deny
	out = env.runOK("default", "deny", "outgoing")
	if !strings.Contains(out, "Default outgoing policy changed to 'deny'") {
		t.Fatalf("unexpected default outgoing output: %q", out)
	}

	// Changing default routed policy to allow
	out = env.runOK("default", "allow", "routed")
	if !strings.Contains(out, "Default routed policy changed to 'allow'") {
		t.Fatalf("unexpected default routed output: %q", out)
	}

	// Invalid policy rejection
	_, se := env.runErr("default", "invalid_policy", "incoming")

	// Invalid direction rejection
	_, se = env.runErr("default", "allow", "bad_direction")
	if !strings.Contains(se, "Invalid direction") {
		t.Fatalf("expected Invalid direction error, got: %s", se)
	}

	// 2. Logging levels
	out = env.runOK("logging", "medium")
	if !strings.Contains(out, "Logging enabled") {
		t.Fatalf("expected Logging enabled, got: %q", out)
	}

	nftOut, _ = env.nft("list", "table", "inet", "bfirewall")
	if !strings.Contains(nftOut, "bfw-before-logging-input") && !strings.Contains(nftOut, "log") {
		t.Fatalf("expected logging chains/rules in kernel table:\n%s", nftOut)
	}

	out = env.runOK("logging", "off")
	if !strings.Contains(out, "Logging disabled") {
		t.Fatalf("expected Logging disabled, got: %q", out)
	}

	// Invalid log level
	env.runErr("logging", "superhigh")
}
