//go:build integration

// Package tests contains real kernel behavioral coverage for better-firewall extensions:
// named sets CRUD/toggle/expiry, NAT v4/v6, status/check/diff/panic, application profiles,
// import/export/import-ufw migration, and fragments/hooks atomic failure.
package tests

import (
	"encoding/json"
	"github.com/tmih06/better-firewall/internal/store"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// -----------------------------------------------------------------------------
// Named IP Sets CRUD, Element Manipulation, and Rule References
// -----------------------------------------------------------------------------

func TestNamedIPSetsCRUDAndReferences(t *testing.T) {
	env := newTestEnv(t)
	env.runOK("--force", "enable")

	// 1. Create named set
	out := env.runOK("set", "create", "blocklist")
	if !strings.Contains(out, "Set 'blocklist' created") {
		t.Fatalf("unexpected set create output: %q", out)
	}

	// Verify set exists in kernel table
	nftOut, err := env.nft("list", "set", "inet", "better-firewall", "bfw_set_blocklist")
	if err != nil {
		t.Fatalf("expected set bfw_set_blocklist in kernel: %v\n%s", err, nftOut)
	}

	// 2. Add elements (multiple IP/CIDR)
	out = env.runOK("set", "add", "blocklist", "192.0.2.1,192.0.2.2,198.51.100.0/24")
	if !strings.Contains(out, "added 3 element(s) to 'blocklist'") {
		t.Fatalf("unexpected set add output: %q", out)
	}

	// Verify elements in live kernel set
	nftOut, _ = env.nft("list", "set", "inet", "better-firewall", "bfw_set_blocklist")
	for _, el := range []string{"192.0.2.1", "192.0.2.2", "198.51.100.0/24"} {
		if !strings.Contains(nftOut, el) {
			t.Fatalf("expected element %q in kernel set:\n%s", el, nftOut)
		}
	}

	// 3. List set
	out = env.runOK("set", "list", "blocklist")
	if !strings.Contains(out, "Set 'blocklist' (inet):") || !strings.Contains(out, "192.0.2.1") {
		t.Fatalf("unexpected set list output:\n%s", out)
	}

	// 4. Delete element
	out = env.runOK("set", "del", "blocklist", "192.0.2.2")
	if !strings.Contains(out, "removed '192.0.2.2' from 'blocklist'") {
		t.Fatalf("unexpected set del output: %q", out)
	}

	nftOut, _ = env.nft("list", "set", "inet", "better-firewall", "bfw_set_blocklist")
	if strings.Contains(nftOut, "192.0.2.2") {
		t.Fatalf("element 192.0.2.2 still present in kernel set after deletion:\n%s", nftOut)
	}

	// 5. Reference set from rule
	out = env.runOK("deny", "from", "set", "blocklist", "to", "any")
	if !strings.Contains(out, "Rule added") {
		t.Fatalf("deny from set output: %q", out)
	}

	// Kernel rule should reference @bfw_set_blocklist
	nftOut, _ = env.nft("list", "chain", "inet", "better-firewall", "bfw-user-input")
	if !strings.Contains(nftOut, "@bfw_set_blocklist") {
		t.Fatalf("expected rule referencing @bfw_set_blocklist in kernel:\n%s", nftOut)
	}

	// 6. Destroy set guarded: refuses without --force when referenced
	so, se := env.runErr("set", "destroy", "blocklist")
	if !strings.Contains(se, "is referenced by 1 rule(s)") && !strings.Contains(so, "is referenced by 1 rule(s)") {
		t.Fatalf("expected reference error on set destroy, got so=%q se=%q", so, se)
	}

	// 7. Destroy set with --force: strips referencing rules and removes set
	out = env.runOK("--force", "set", "destroy", "blocklist")
	if !strings.Contains(out, "Set 'blocklist' destroyed") {
		t.Fatalf("expected set destroyed output, got: %q", out)
	}

	nftOut, _ = env.nft("list", "table", "inet", "better-firewall")
	if strings.Contains(nftOut, "bfw_set_blocklist") {
		t.Fatalf("destroyed set still present in kernel table:\n%s", nftOut)
	}

	// 8. Negative validations
	env.runErr("set", "create", "invalid name with spaces")
	env.runErr("set", "add", "nonexistent_set", "1.2.3.4")
	env.runErr("set", "add", "blocklist", "invalid.ip.string")
}

func TestThreatBansLoadAsKernelSetsBeforeEstablishedAcceptance(t *testing.T) {
	env := newTestEnv(t)
	now := time.Now().Unix()
	st := store.Defaults()
	st.Bans = []store.ThreatBan{
		{Address: "198.51.100.19", Source: "ssh:ssh", ExpiresAt: now + 3600},
		{Address: "2001:db8::19/128", Source: "crowdsec", Reason: "integration", DecisionID: 19, ExpiresAt: now + 3600},
	}
	data, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	rulesPath := filepath.Join(env.dir, "etc", "better-firewall", "rules.json")
	if err := os.WriteFile(rulesPath, data, 0600); err != nil {
		t.Fatalf("write state: %v", err)
	}
	env.runOK("--force", "enable")

	v4, err := env.nft("list", "set", "inet", "better-firewall", "bfw_threat_bans")
	if err != nil || !strings.Contains(v4, "198.51.100.19") {
		t.Fatalf("IPv4 threat set output=%q err=%v", v4, err)
	}
	v6, err := env.nft("list", "set", "inet", "better-firewall", "bfw_threat_bans6")
	if err != nil || !strings.Contains(v6, "2001:db8::19") {
		t.Fatalf("IPv6 threat set output=%q err=%v", v6, err)
	}
	input, err := env.nft("list", "chain", "inet", "better-firewall", "bfw-before-input")
	if err != nil {
		t.Fatalf("list input chain: %v", err)
	}
	banAt := strings.Index(input, "ip saddr @bfw_threat_bans")
	establishedAt := strings.Index(input, "ct state established,related")
	if banAt < 0 || establishedAt < 0 || banAt > establishedAt {
		t.Fatalf("kernel chain does not drop threat sources before established acceptance:\n%s", input)
	}
}

// -----------------------------------------------------------------------------
// Rule Toggling and Expiry Sweeps
// -----------------------------------------------------------------------------

func TestRuleToggleAndExpirySweep(t *testing.T) {
	env := newTestEnv(t)
	env.runOK("--force", "enable")

	// 1. Rule Toggle
	env.runOK("allow", "5000/tcp")
	nftOut, _ := env.nft("list", "chain", "inet", "better-firewall", "bfw-user-input")
	if !strings.Contains(nftOut, "tcp dport 5000") {
		t.Fatalf("rule 5000/tcp not found in kernel before toggle:\n%s", nftOut)
	}

	// Disable rule 1
	out := env.runOK("rule", "disable", "1")
	if !strings.Contains(out, "Rule disabled") {
		t.Fatalf("expected Rule disabled, got: %q", out)
	}

	nftOut, _ = env.nft("list", "chain", "inet", "better-firewall", "bfw-user-input")
	if strings.Contains(nftOut, "tcp dport 5000") {
		t.Fatalf("disabled rule still present in active kernel chain:\n%s", nftOut)
	}

	// Enable rule 1
	out = env.runOK("rule", "enable", "1")
	if !strings.Contains(out, "Rule enabled") {
		t.Fatalf("expected Rule enabled, got: %q", out)
	}

	nftOut, _ = env.nft("list", "chain", "inet", "better-firewall", "bfw-user-input")
	if !strings.Contains(nftOut, "tcp dport 5000") {
		t.Fatalf("re-enabled rule not restored in kernel chain:\n%s", nftOut)
	}

	// Toggle invalid rule number
	env.runErr("rule", "disable", "99")

	// 2. Expiring Rules and Sweep
	out = env.runOK("allow", "5001/tcp", "expires", "1s")
	if !strings.Contains(out, "Rule added") {
		t.Fatalf("expected expiring rule added, got: %q", out)
	}

	// Sleep for rule to expire
	time.Sleep(1200 * time.Millisecond)

	out = env.runOK("sweep")
	if !strings.Contains(out, "Removed") || strings.Contains(out, "Removed 0 expired") {
		t.Fatalf("expected sweep to remove expired rule, got: %q", out)
	}

	nftOut, _ = env.nft("list", "chain", "inet", "better-firewall", "bfw-user-input")
	if strings.Contains(nftOut, "tcp dport 5001") {
		t.Fatalf("expired rule still present in kernel after sweep:\n%s", nftOut)
	}
}

// -----------------------------------------------------------------------------
// NAT Rules v4/v6 and Validation
// -----------------------------------------------------------------------------

func TestNATRulesV4V6AndValidation(t *testing.T) {
	env := newTestEnv(t)
	env.runOK("--force", "enable")

	// 1. Masquerade rule
	out := env.runOK("nat", "add", "masquerade", "out", "on", "eth0", "from", "10.10.0.0/16")
	if !strings.Contains(out, "NAT rule added") {
		t.Fatalf("expected NAT rule added, got: %q", out)
	}

	// Verify kernel table ip better-firewall-nat postrouting
	nftOut, err := env.nft("list", "table", "ip", "better-firewall-nat")
	if err != nil {
		t.Fatalf("failed to list nat table in kernel: %v\n%s", err, nftOut)
	}
	if !strings.Contains(nftOut, "oifname \"eth0\"") || !strings.Contains(nftOut, "masquerade") {
		t.Fatalf("masquerade rule missing in kernel nat table:\n%s", nftOut)
	}

	// 2. DNAT rule
	out = env.runOK("nat", "add", "dnat", "proto", "tcp", "in", "on", "eth0", "to", "198.51.100.1", "port", "80", "to-destination", "10.10.0.5:8080")
	if !strings.Contains(out, "NAT rule added") {
		t.Fatalf("expected DNAT rule added, got: %q", out)
	}

	nftOut, _ = env.nft("list", "table", "ip", "better-firewall-nat")
	if !strings.Contains(nftOut, "dnat to 10.10.0.5:8080") {
		t.Fatalf("dnat rule missing in kernel nat table:\n%s", nftOut)
	}

	// 3. NAT list
	out = env.runOK("nat", "list")
	if !strings.Contains(out, "masquerade out on eth0") || !strings.Contains(out, "dnat proto tcp") {
		t.Fatalf("nat list missing rules:\n%s", out)
	}

	// 4. NAT delete
	out = env.runOK("nat", "delete", "1")
	if !strings.Contains(out, "NAT rule deleted") {
		t.Fatalf("expected NAT rule deleted, got: %q", out)
	}

	// 5. Validation errors
	env.runErr("nat", "add", "dnat", "proto", "icmp", "to", "1.2.3.4", "port", "80", "to-destination", "1.2.3.5")
	env.runErr("nat", "add", "dnat", "proto", "tcp", "to", "1.2.3.4", "port", "70000", "to-destination", "1.2.3.5")
	env.runErr("nat", "add", "dnat", "proto", "tcp", "to", "1.2.3.4", "port", "80", "to-destination", "[2001:db8::1]:80")
	env.runErr("nat", "delete", "99")
}

// -----------------------------------------------------------------------------
// Status, Check, Diff, and Panic Restore
// -----------------------------------------------------------------------------

func TestStatusCheckDiffPanicRestore(t *testing.T) {
	env := newTestEnv(t)
	env.runOK("--force", "enable")
	env.runOK("allow", "22/tcp")

	// 1. Status verbose
	out := env.runOK("status", "verbose")
	if !strings.Contains(out, "Status: active") || !strings.Contains(out, "Logging: on (low)") || !strings.Contains(out, "Default:") {
		t.Fatalf("status verbose missing key fields:\n%s", out)
	}

	// 2. Status numbered
	out = env.runOK("status", "numbered")
	if !strings.Contains(out, "[ 1] 22/tcp") {
		t.Fatalf("status numbered missing rule entry:\n%s", out)
	}

	// 3. Status JSON
	out = env.runOK("--json", "status")
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("failed to parse --json status output: %v\n%s", err, out)
	}
	if doc["status"] != "active" {
		t.Fatalf("expected status active in JSON, got: %v", doc["status"])
	}

	// 4. Check command
	out = env.runOK("check")
	if !strings.Contains(out, "No issues found") {
		t.Fatalf("expected clean check, got: %q", out)
	}

	// Shadowed rule detection
	env.runOK("allow", "from", "192.168.1.100", "to", "any", "port", "22", "proto", "tcp")
	out = env.runOK("check")
	if !strings.Contains(out, "WARN: rule 2 shadowed by rule 1") {
		t.Fatalf("expected shadowed rule warning in check, got: %q", out)
	}

	// 5. Diff command
	out = env.runOK("diff")
	if !strings.Contains(out, "Ruleset matches stored state") {
		t.Fatalf("expected matching diff, got: %q", out)
	}

	nftOut, err := env.nft("add", "rule", "inet", "better-firewall", "bfw-user-input",
		"tcp", "dport", "9999", "accept")
	if err != nil {
		t.Fatalf("failed to inject kernel drift: %v\n%s", err, nftOut)
	}
	so, _ := env.runErr("diff")
	if !strings.Contains(so, "--- stored") || !strings.Contains(so, "+++ kernel") {
		t.Fatalf("expected diff output after manual drift injection, got:\n%s", so)
	}

	// Reload fixes drift
	env.runOK("reload")
	out = env.runOK("diff")
	if !strings.Contains(out, "Ruleset matches stored state") {
		t.Fatalf("diff should match after reload, got: %q", out)
	}

	// 6. Panic Mode and Restore
	out = env.runOK("--force", "panic")
	if !strings.Contains(out, "Panic mode ON: all traffic dropped") {
		t.Fatalf("expected Panic mode ON, got: %q", out)
	}

	// Kernel base chains must all be policy drop
	nftOut, _ = env.nft("list", "table", "inet", "better-firewall")
	if !strings.Contains(nftOut, "policy drop") {
		t.Fatalf("panic did not install drop policies:\n%s", nftOut)
	}

	// Re-panic reports already on
	out = env.runOK("--force", "panic")
	if !strings.Contains(out, "Already in panic mode") {
		t.Fatalf("expected Already in panic mode, got: %q", out)
	}

	// Panic off restores policies
	out = env.runOK("panic", "off")
	if !strings.Contains(out, "Panic mode OFF") {
		t.Fatalf("expected Panic mode OFF, got: %q", out)
	}

	nftOut, _ = env.nft("list", "table", "inet", "better-firewall")
	if !strings.Contains(nftOut, "policy accept") {
		t.Fatalf("panic off did not restore output accept policy:\n%s", nftOut)
	}
}

// -----------------------------------------------------------------------------
// Application Profiles
// -----------------------------------------------------------------------------

func TestApplicationProfiles(t *testing.T) {
	env := newTestEnv(t)
	env.runOK("--force", "enable")

	// 1. Built-in profiles list
	out := env.runOK("app", "list")
	if !strings.Contains(out, "Available applications:") || !strings.Contains(out, "OpenSSH") {
		t.Fatalf("app list missing OpenSSH:\n%s", out)
	}

	// 2. Built-in profile info
	out = env.runOK("app", "info", "OpenSSH")
	if !strings.Contains(out, "Profile: OpenSSH") || !strings.Contains(out, "22/tcp") {
		t.Fatalf("app info OpenSSH missing port details:\n%s", out)
	}

	// 3. Allow built-in profile
	out = env.runOK("allow", "OpenSSH")
	if !strings.Contains(out, "Rule added") {
		t.Fatalf("allow OpenSSH output: %q", out)
	}

	nftOut, _ := env.nft("list", "chain", "inet", "better-firewall", "bfw-user-input")
	if !strings.Contains(nftOut, "tcp dport 22") {
		t.Fatalf("kernel chain missing port 22 for OpenSSH:\n%s", nftOut)
	}

	// 4. Custom INI application profile
	customProf := `[CustomApp]
title=Custom Test App
description=Test custom application profile
ports=9100,9200/tcp
`
	profPath := filepath.Join(env.dir, "etc", "better-firewall", "applications.d", "custom.ini")
	if err := os.WriteFile(profPath, []byte(customProf), 0644); err != nil {
		t.Fatalf("failed to write custom app profile: %v", err)
	}

	out = env.runOK("app", "info", "CustomApp")
	if !strings.Contains(out, "9100,9200/tcp") {
		t.Fatalf("app info CustomApp failed to parse ports:\n%s", out)
	}

	out = env.runOK("allow", "CustomApp")
	if !strings.Contains(out, "Rule added") {
		t.Fatalf("allow CustomApp failed: %q", out)
	}

	nftOut, _ = env.nft("list", "chain", "inet", "better-firewall", "bfw-user-input")
	if strings.Count(nftOut, "tcp dport { 9100, 9200 }") != 2 {
		t.Fatalf("expected custom app port set in both address families:\n%s", nftOut)
	}
}

// -----------------------------------------------------------------------------
// Import / Export and import-ufw Migration
// -----------------------------------------------------------------------------

func TestImportExportAndImportUFW(t *testing.T) {
	env := newTestEnv(t)
	env.runOK("--force", "enable")

	env.runOK("allow", "1234/tcp")
	env.runOK("allow", "5678/udp")

	// 1. Export state
	expFile := filepath.Join(env.dir, "export.json")
	env.runOK("export", expFile)
	data, err := os.ReadFile(expFile)
	if err != nil || len(data) == 0 {
		t.Fatalf("export file missing or empty: %v", err)
	}

	// 2. Export to stdout
	out := env.runOK("export", "-")
	if !strings.Contains(out, "1234") || !strings.Contains(out, "5678") {
		t.Fatalf("export stdout missing rule data:\n%s", out)
	}

	// 3. Reset and Import
	env.runOK("--force", "reset")
	out = env.runOK("import", expFile)

	// Re-enable and verify live kernel has imported rules
	env.runOK("--force", "enable")
	nftOut, _ := env.nft("list", "chain", "inet", "better-firewall", "bfw-user-input")
	if !strings.Contains(nftOut, "tcp dport 1234") || !strings.Contains(nftOut, "udp dport 5678") {
		t.Fatalf("imported rules missing in kernel after enable:\n%s", nftOut)
	}

	// 4. import-ufw migration
	ufwDir := filepath.Join(env.dir, "mock-ufw")
	if err := os.MkdirAll(ufwDir, 0755); err != nil {
		t.Fatalf("failed to create mock ufw dir: %v", err)
	}

	userRules := `*filter
:ufw-user-input - [0:0]
### tuple ### allow tcp 7777 0.0.0.0/0 any 0.0.0.0/0 in
COMMIT
`
	if err := os.WriteFile(filepath.Join(ufwDir, "user.rules"), []byte(userRules), 0644); err != nil {
		t.Fatalf("failed to write user.rules: %v", err)
	}
	ufwConf := `ENABLED=yes
LOGLEVEL=low
`
	if err := os.WriteFile(filepath.Join(ufwDir, "ufw.conf"), []byte(ufwConf), 0644); err != nil {
		t.Fatalf("failed to write ufw.conf: %v", err)
	}

	out = env.runOK("import-ufw", "--dir", ufwDir)

	nftOut, _ = env.nft("list", "chain", "inet", "better-firewall", "bfw-user-input")
	if !strings.Contains(nftOut, "tcp dport 7777") {
		t.Fatalf("migrated ufw rule 7777/tcp missing in kernel:\n%s", nftOut)
	}
}

// -----------------------------------------------------------------------------
// Fragments & Init Hooks Atomic Failure
// -----------------------------------------------------------------------------

func TestFragmentsAndInitHooksAtomicFailure(t *testing.T) {
	env := newTestEnv(t)

	// 1. Valid before.rules fragment
	validFrag := `table inet better-firewall {
    chain bfw-before-input {
        tcp dport 4444 accept
    }
}
`
	fragPath := filepath.Join(env.dir, "etc", "better-firewall", "before.rules")
	if err := os.WriteFile(fragPath, []byte(validFrag), 0644); err != nil {
		t.Fatalf("failed to write valid fragment: %v", err)
	}

	env.runOK("--force", "enable")
	nftOut, _ := env.nft("list", "chain", "inet", "better-firewall", "bfw-before-input")
	if !strings.Contains(nftOut, "tcp dport 4444") {
		t.Fatalf("valid fragment rule not applied in kernel:\n%s", nftOut)
	}

	// 2. Broken before.rules fragment -> atomic failure and rollback
	brokenFrag := `table inet better-firewall {
    chain bfw-before-input {
        this is completely broken syntax !!!
    }
}
`
	if err := os.WriteFile(fragPath, []byte(brokenFrag), 0644); err != nil {
		t.Fatalf("failed to write broken fragment: %v", err)
	}

	so, se := env.runErr("reload")
	if !strings.Contains(se, "Failed to apply firewall fragments") && !strings.Contains(so, "Failed to apply firewall fragments") {
		t.Fatalf("expected fragment failure error message, got so=%q se=%q", so, se)
	}

	// Verify rollback flushed the broken table from kernel
	nftOut, _ = env.nft("list", "table", "inet", "better-firewall")
	if !strings.Contains(nftOut, "Error") && len(nftOut) > 0 {
		t.Fatalf("expected core table to be rolled back/flushed after fragment failure:\n%s", nftOut)
	}

	// Clean up fragment for next subtest
	_ = os.Remove(fragPath)

	// 3. Failing before.init hook -> aborts enable
	failingHook := `#!/bin/sh
exit 1
`
	hookPath := filepath.Join(env.dir, "etc", "better-firewall", "before.init")
	if err := os.WriteFile(hookPath, []byte(failingHook), 0755); err != nil {
		t.Fatalf("failed to write hook: %v", err)
	}

	so, se = env.runErr("--force", "enable")
	if !strings.Contains(se, "before.init failed; aborting enable") && !strings.Contains(so, "before.init failed; aborting enable") {
		t.Fatalf("expected before.init abort message, got so=%q se=%q", so, se)
	}

	// Verify firewall was not started
	out := env.runOK("status")
	if !strings.Contains(out, "Status: inactive") {
		t.Fatalf("status should be inactive after aborted enable, got: %q", out)
	}

	// 4. Working before.init hook
	workingHook := `#!/bin/sh
exit 0
`
	if err := os.WriteFile(hookPath, []byte(workingHook), 0755); err != nil {
		t.Fatalf("failed to write working hook: %v", err)
	}

	out = env.runOK("--force", "enable")
	if !strings.Contains(out, "Firewall is active and enabled on system startup") {
		t.Fatalf("expected successful enable with working hook, got: %q", out)
	}
}
