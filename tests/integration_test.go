//go:build integration

// Package tests contains root-requiring integration tests that exercise the
// real nftables backend. Run: go test -tags=integration ./tests/...
package tests

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var bfw string

func TestMain(m *testing.M) {
	if os.Geteuid() != 0 {
		// Not root: skip everything rather than fail.
		os.Exit(0)
	}
	dir, err := os.MkdirTemp("", "bfw-int-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	bfw = filepath.Join(dir, "bfw")
	out, err := exec.Command("go", "build", "-o", bfw, "../cmd/bfw").CombinedOutput()
	if err != nil {
		panic(string(out))
	}
	os.Setenv("BFW_PREFIX", dir)
	os.Exit(m.Run())
}

func run(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(bfw, args...)
	var so, se strings.Builder
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run %v: %v", args, err)
	}
	return so.String(), se.String(), code
}

func nft(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("nft", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("nft %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func TestEnableStatusDisable(t *testing.T) {
	so, _, code := run(t, "allow", "22/tcp")
	if code != 0 || !strings.Contains(so, "Rule added") {
		t.Fatalf("allow: code=%d out=%q", code, so)
	}
	so, _, code = run(t, "--force", "enable")
	if code != 0 || !strings.Contains(so, "Firewall is active and enabled on system startup") {
		t.Fatalf("enable: code=%d out=%q", code, so)
	}
	table := nft(t, "list", "table", "inet", "bfirewall")
	if !strings.Contains(table, "chain input") || !strings.Contains(table, "bfw-user-input") {
		t.Fatalf("table missing chains:\n%s", table)
	}
	so, _, _ = run(t, "status")
	if !strings.Contains(so, "Status: active") || !strings.Contains(so, "22/tcp") {
		t.Fatalf("status: %q", so)
	}
	so, _, _ = run(t, "disable")
	if !strings.Contains(so, "Firewall stopped and disabled") {
		t.Fatalf("disable: %q", so)
	}
	out, _ := exec.Command("nft", "list", "table", "inet", "bfirewall").CombinedOutput()
	if !strings.Contains(string(out), "Error") && len(out) != 0 {
		t.Fatalf("table still present after disable:\n%s", out)
	}
}

func TestLimitRule(t *testing.T) {
	run(t, "limit", "ssh/tcp")
	run(t, "--force", "enable")
	defer run(t, "disable")
	table := nft(t, "list", "table", "inet", "bfirewall")
	if !strings.Contains(table, "bfw_limit_") || !strings.Contains(table, "dynamic") {
		t.Fatalf("no dynamic limit set:\n%s", table)
	}
}

func TestSetAndExpiry(t *testing.T) {
	run(t, "set", "create", "badguys")
	so, _, _ := run(t, "set", "add", "badguys", "203.0.113.0/24")
	if !strings.Contains(so, "badguys") {
		t.Fatalf("set add: %q", so)
	}
	run(t, "deny", "from", "set", "badguys")
	run(t, "--force", "enable")
	defer run(t, "disable")
	set := nft(t, "list", "set", "inet", "bfirewall", "bfw_set_badguys")
	if !strings.Contains(set, "203.0.113.0/24") {
		t.Fatalf("set element missing:\n%s", set)
	}
}

func TestPanic(t *testing.T) {
	run(t, "--force", "enable")
	defer run(t, "disable")
	so, _, _ := run(t, "--force", "panic")
	if !strings.Contains(so, "Panic mode ON") {
		t.Fatalf("panic: %q", so)
	}
	table := nft(t, "list", "table", "inet", "bfirewall")
	if !strings.Contains(table, "policy drop") {
		t.Fatalf("panic did not set drop policies:\n%s", table)
	}
	run(t, "panic", "off")
}
