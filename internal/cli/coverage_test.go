package cli

// Coverage for the documented CLI surface not exercised by the
// parser/lifecycle/status/ext suites: global flags and the version command
// through Run(), dry-run behavior, --json outputs, rule-op persistence,
// set/nat storage commands, app profile commands (including the ufw-compat
// applications.d fallback), logs fallback wiring, check/diff/show reports,
// and export/import/import-ufw migration. Everything runs against a temp
// BFW_PREFIX-style store and stubbed backends/hooks — no host mutation.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"

	"github.com/tmih06/better-firewall/internal/backend"
	nftbe "github.com/tmih06/better-firewall/internal/backend/nft"
	"github.com/tmih06/better-firewall/internal/rule"
	"github.com/tmih06/better-firewall/internal/store"
)

// snapBackend lets a test control what ReadBack reports (foreign chains).
type snapBackend struct {
	fakeBackend
	snap *backend.Snapshot
}

func (s *snapBackend) ReadBack() (*backend.Snapshot, error) { return s.snap, nil }

// fragFailBackend fails ApplyFragments for a named fragment path.
type fragFailBackend struct {
	fakeBackend
	failOn string
}

func (f *fragFailBackend) ApplyFragments(path string) error {
	if f.failOn != "" && strings.Contains(path, f.failOn) {
		return errors.New("fragment compile failed")
	}
	f.fragments = append(f.fragments, path)
	return nil
}

// writeProfile installs an INI app profile into the env's store.
func writeProfile(t *testing.T, e *Env, name, ini string) {
	t.Helper()
	dir := e.Store.AppDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".ini"), []byte(ini), 0644); err != nil {
		t.Fatal(err)
	}
}

func loadState(t *testing.T, e *Env) *store.State {
	t.Helper()
	st, err := e.Store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	markFamilies(st)
	return st
}

// ---- Run(): global flags ------------------------------------------------

func runCLI(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	prefix := t.TempDir()
	t.Setenv("BFW_PREFIX", prefix)
	out, errOut := &strings.Builder{}, &strings.Builder{}
	rc := Run("bfw", "0.0.0-test", args, strings.NewReader(""), out, errOut)
	return out.String(), errOut.String(), rc
}

func TestRunVersionAndHelpFlags(t *testing.T) {
	out, _, rc := runCLI(t, "--version")
	if rc != 0 || !strings.Contains(out, "bfw 0.0.0-test") {
		t.Fatalf("--version: rc=%d out=%q", rc, out)
	}

	out, _, rc = runCLI(t, "--help")
	if rc != 0 || !strings.HasPrefix(out, "Usage: bfw COMMAND") {
		t.Fatalf("--help: rc=%d out=%.80q", rc, out)
	}

	// Drop-in argv[0]: usage text tracks the invoked program name.
	prefix := t.TempDir()
	t.Setenv("BFW_PREFIX", prefix)
	var ufwOut strings.Builder
	rc2 := Run("ufw", "0.0.0-test", []string{"--help"}, strings.NewReader(""), &ufwOut, &strings.Builder{})
	if rc2 != 0 || !strings.HasPrefix(ufwOut.String(), "Usage: ufw COMMAND") {
		t.Fatalf("ufw --help: rc=%d out=%.80q", rc2, ufwOut.String())
	}
}

func TestRunVersionCommand(t *testing.T) {
	// `bfw version` is a dispatchable command (ufw parity), not a flag:
	// it must print "<prog> <version>" and exit 0.
	out, errOut, rc := runCLI(t, "version")
	if rc != 0 {
		t.Fatalf("version: rc=%d err=%q", rc, errOut)
	}
	if strings.TrimSpace(out) != "bfw 0.0.0-test" {
		t.Fatalf("version stdout = %q, want %q", out, "bfw 0.0.0-test")
	}

	// Drop-in argv[0]: the command name tracks the invoked program name.
	prefix := t.TempDir()
	t.Setenv("BFW_PREFIX", prefix)
	var ufwOut, ufwErr strings.Builder
	rc = Run("ufw", "0.0.0-test", []string{"version"}, strings.NewReader(""), &ufwOut, &ufwErr)
	if rc != 0 || strings.TrimSpace(ufwOut.String()) != "ufw 0.0.0-test" {
		t.Fatalf("ufw version: rc=%d out=%q", rc, ufwOut.String())
	}
}

func TestRunNoArgsAndUnknownCommand(t *testing.T) {
	out, _, rc := runCLI(t)
	if rc != 1 || !strings.HasPrefix(out, "Usage:") {
		t.Fatalf("no args: rc=%d out=%.40q", rc, out)
	}
	out, _, rc = runCLI(t, "frobnicate")
	if rc != 1 || !strings.HasPrefix(out, "Usage:") {
		t.Fatalf("unknown cmd: rc=%d out=%.40q", rc, out)
	}
}

func TestRunEnsureDefaultsMaterializes(t *testing.T) {
	// Run() materializes the bundled app profiles under BFW_PREFIX.
	prefix := t.TempDir()
	t.Setenv("BFW_PREFIX", prefix)
	var so strings.Builder
	rc := Run("bfw", "t", []string{"app", "list"}, strings.NewReader(""), &so, &strings.Builder{})
	if rc != 0 {
		t.Fatalf("app list rc=%d", rc)
	}
	if !strings.Contains(so.String(), "OpenSSH") {
		t.Fatalf("app list missing bundled OpenSSH profile:\n%s", so.String())
	}
	if _, err := os.Stat(filepath.Join(prefix, "etc", "better-firewall", "applications.d", "openssh.ini")); err != nil {
		t.Errorf("openssh.ini not materialized: %v", err)
	}
	if _, err := os.Stat(filepath.Join(prefix, "etc", "better-firewall", "protect.json")); err != nil {
		t.Errorf("protect.json not materialized: %v", err)
	}
}

// ---- dry-run ------------------------------------------------------------

func TestDryRunEnableRendersWithoutSideEffects(t *testing.T) {
	e, fb, out, _ := lifecycleEnv(t, "")
	e.DryRun = true

	// A sysctl file whose content should be *printed*, never applied: the
	// fixture is comment-only, so even a stray apply would be a no-op; the
	// assertion pins the documented dry-run surface.
	if err := os.MkdirAll(e.Store.Dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.Store.SysctlPath(), []byte("# forwarded tunable\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// Executable before.init that must NOT run under dry-run.
	hookRan := false
	hookRunCmd = func(string, ...string) error { hookRan = true; return nil }
	if err := os.WriteFile(e.Store.InitPath("before"), []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}

	if rc := e.cmdEnable(nil); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	got := out.String()
	if !strings.Contains(got, "table inet better-firewall") {
		t.Errorf("dry-run missing rendered ruleset:\n%s", got)
	}
	if !strings.Contains(got, "### sysctl ###") || !strings.Contains(got, "# forwarded tunable") {
		t.Errorf("dry-run missing sysctl section:\n%s", got)
	}
	if fb.applies != 0 {
		t.Errorf("dry-run applied %d times", fb.applies)
	}
	if hookRan {
		t.Error("dry-run executed init hook")
	}
	conf, _ := e.Store.LoadConf()
	if conf.Enabled {
		t.Error("dry-run persisted ENABLED=yes")
	}
}

func TestDryRunRuleOpDoesNotSave(t *testing.T) {
	e, fb, out, _ := lifecycleEnv(t, "")
	e.DryRun = true
	if rc := e.cmdRuleOp([]string{"allow", "22"}); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	if !strings.Contains(out.String(), "Rules updated") ||
		!strings.Contains(out.String(), "table inet better-firewall") {
		t.Fatalf("stdout = %q", out.String())
	}
	if fb.applies != 0 {
		t.Error("dry-run applied ruleset")
	}
	st := loadState(t, e)
	if len(st.Rules4)+len(st.Rules6) != 0 {
		t.Fatalf("dry-run persisted rules: %+v", st)
	}
}

func TestDryRunDisableDoesNotFlushOrPersist(t *testing.T) {
	e, fb, out, _ := lifecycleEnv(t, "")
	e.DryRun = true
	if err := e.Store.SaveConf(&store.Conf{Enabled: true, LogLevel: "low"}); err != nil {
		t.Fatal(err)
	}
	if rc := e.cmdDisable(nil); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	if !strings.Contains(out.String(), "flushing") {
		t.Fatalf("stdout = %q", out.String())
	}
	if fb.flushes != 0 {
		t.Error("dry-run flushed")
	}
	conf, _ := e.Store.LoadConf()
	if !conf.Enabled {
		t.Error("dry-run persisted ENABLED=no")
	}
}

func TestDryRunMutationsDoNotPersist(t *testing.T) {
	e, _, out, _ := lifecycleEnv(t, "")
	e.DryRun = true

	if rc := e.cmdDefault([]string{"reject", "outgoing"}); rc != 0 {
		t.Fatalf("default rc = %d", rc)
	}
	if !strings.Contains(out.String(), "Default outgoing policy changed to 'reject'") {
		t.Fatalf("stdout = %q", out.String())
	}
	st := loadState(t, e)
	if st.Policies.Output != "allow" {
		t.Errorf("dry-run default persisted: %+v", st.Policies)
	}

	e2, _, out2, _ := lifecycleEnv(t, "")
	e2.DryRun = true
	if rc := e2.cmdLogging([]string{"full"}); rc != 0 {
		t.Fatalf("logging rc = %d", rc)
	}
	if !strings.Contains(out2.String(), "Logging enabled") {
		t.Fatalf("stdout = %q", out2.String())
	}
	st2, _ := e2.Store.Load()
	if st2.Logging != "low" {
		t.Errorf("dry-run logging persisted: %q", st2.Logging)
	}
}

// ---- status extras + --json ----------------------------------------------

func TestStatusArgumentValidation(t *testing.T) {
	e, _, out, _ := lifecycleEnv(t, "")
	if rc := e.cmdStatus([]string{"bogus"}); rc != 1 || !strings.HasPrefix(out.String(), "Usage:") {
		t.Fatalf("status bogus: rc=%d out=%.40q", rc, out.String())
	}
	e, _, out, _ = lifecycleEnv(t, "")
	if rc := e.cmdStatus([]string{"verbose", "numbered"}); rc != 1 {
		t.Fatalf("status verbose numbered: rc=%d, want 1", rc)
	}
	if !strings.HasPrefix(out.String(), "Usage:") {
		t.Fatalf("stdout = %.40q", out.String())
	}
}

func TestStatusJSON(t *testing.T) {
	e, fb, out, _ := lifecycleEnv(t, "")
	e.JSON = true
	st := store.Defaults()
	st.Logging = "medium"
	r := mkExtRule("allow", "in", "tcp", "any", "any", ports(22, "tcp"))
	st.Rules4 = []rule.Rule{*r}
	if err := e.Store.Save(st); err != nil {
		t.Fatal(err)
	}
	// Enabled but not loaded in kernel → still reported inactive.
	if err := e.Store.SaveConf(&store.Conf{Enabled: true, LogLevel: "medium"}); err != nil {
		t.Fatal(err)
	}
	fb.loaded = false
	if rc := e.cmdStatus(nil); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	var doc struct {
		Status  string `json:"status"`
		Logging string `json:"logging"`
		Default struct {
			Incoming string `json:"incoming"`
		} `json:"default"`
		Rules []struct {
			Num int    `json:"num"`
			To  string `json:"to"`
			V6  bool   `json:"v6"`
		} `json:"rules"`
	}
	if err := json.Unmarshal([]byte(out.String()), &doc); err != nil {
		t.Fatalf("invalid JSON %q: %v", out.String(), err)
	}
	if doc.Status != "inactive" || doc.Logging != "medium" || doc.Default.Incoming != "deny" {
		t.Fatalf("doc = %+v", doc)
	}
	if len(doc.Rules) != 1 || doc.Rules[0].Num != 1 || doc.Rules[0].V6 {
		t.Fatalf("rules = %+v", doc.Rules)
	}
}

// ---- rule ops end-to-end -------------------------------------------------

func TestRuleOpAddDeleteRoundTrip(t *testing.T) {
	e, fb, out, _ := lifecycleEnv(t, "")

	// add: disabled firewall → stored, "Rules updated" (ufw reports the
	// live wording only when enabled).
	if rc := e.cmdRuleOp([]string{"allow", "22"}); rc != 0 {
		t.Fatalf("allow rc = %d", rc)
	}
	if !strings.Contains(out.String(), "Rules updated") {
		t.Fatalf("stdout = %q", out.String())
	}
	st := loadState(t, e)
	if len(st.Rules4) != 1 || len(st.Rules6) != 1 {
		t.Fatalf("rules4=%d rules6=%d, want 1/1 (dual family)", len(st.Rules4), len(st.Rules6))
	}
	p := st.Rules4[0].Dst.Ports[0]
	if p.Lo != 22 || p.Hi != 22 {
		t.Errorf("stored ports = %+v, want 22:22", p)
	}
	if st.Rules4[0].Proto != "any" {
		t.Errorf("proto = %q, want any (no proto clause given)", st.Rules4[0].Proto)
	}
	if fb.applies != 0 {
		t.Error("disabled firewall applied to kernel")
	}

	// Exact duplicate add → skipped, list unchanged.
	out.Reset()
	if rc := e.cmdRuleOp([]string{"allow", "22"}); rc != 0 {
		t.Fatalf("dup rc = %d", rc)
	}
	if !strings.Contains(out.String(), "Skipping adding existing rule") {
		t.Fatalf("stdout = %q", out.String())
	}
	st = loadState(t, e)
	if len(st.Rules4) != 1 {
		t.Fatalf("dup added: rules4=%d", len(st.Rules4))
	}
	// Delete by text removes both halves.
	out.Reset()
	if rc := e.cmdRuleOp([]string{"delete", "allow", "22"}); rc != 0 {
		t.Fatalf("delete rc = %d", rc)
	}
	st = loadState(t, e)
	if len(st.Rules4)+len(st.Rules6) != 0 {
		t.Fatalf("rules remain after delete: %+v", st)
	}
}

func TestRuleOpDeleteByNumberPrompt(t *testing.T) {
	e, fb, out, errOut := lifecycleEnv(t, "n\n")
	st := store.Defaults()
	st.Rules4 = []rule.Rule{*mkExtRule("allow", "in", "tcp", "any", "any", ports(53, "tcp"))}
	if err := e.Store.Save(st); err != nil {
		t.Fatal(err)
	}

	// "n" aborts without touching the store.
	if rc := e.cmdRuleOp([]string{"delete", "1"}); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	if !strings.Contains(out.String(), "Aborted") {
		t.Fatalf("stdout = %q", out.String())
	}
	st = loadState(t, e)
	if len(st.Rules4) != 1 {
		t.Fatal("rule deleted despite abort")
	}

	// Out-of-range number → error.
	errOut.Reset()
	if rc := e.cmdRuleOp([]string{"delete", "9"}); rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	if !strings.Contains(errOut.String(), "Could not find rule") {
		t.Fatalf("stderr = %q", errOut.String())
	}

	// Forced delete skips the prompt.
	e.Force = true
	errOut.Reset()
	if rc := e.cmdRuleOp([]string{"delete", "1"}); rc != 0 {
		t.Fatalf("forced delete rc = %d", rc)
	}
	st = loadState(t, e)
	if len(st.Rules4) != 0 {
		t.Fatalf("rules4 = %+v", st.Rules4)
	}
	if fb.applies != 0 {
		t.Error("disabled firewall applied")
	}
}

func TestRuleOpInsert(t *testing.T) {
	e, _, _, _ := lifecycleEnv(t, "")
	st := store.Defaults()
	st.Rules4 = []rule.Rule{
		*mkExtRule("allow", "in", "tcp", "any", "any", ports(80, "tcp")),
		*mkExtRule("allow", "in", "tcp", "any", "any", ports(443, "tcp")),
	}
	if err := e.Store.Save(st); err != nil {
		t.Fatal(err)
	}
	if rc := e.cmdRuleOp([]string{"insert", "2", "allow", "from", "10.0.0.1", "to", "any", "port", "25", "proto", "tcp"}); rc != 0 {
		t.Fatalf("insert rc = %d", rc)
	}
	st = loadState(t, e)
	if len(st.Rules4) != 3 {
		t.Fatalf("rules4 = %d, want 3", len(st.Rules4))
	}
	got := st.Rules4[1].Dst.Ports[0].Lo
	if got != 25 || st.Rules4[1].Src.IP != "10.0.0.1" {
		t.Errorf("position 2 = %+v, want the new 25/tcp rule", st.Rules4[1])
	}

	// Invalid position → error.
	if rc := e.cmdRuleOp([]string{"insert", "99", "allow", "53"}); rc != 1 {
		t.Fatalf("insert 99 rc = %d, want 1", rc)
	}
}

func TestRuleOpSyntaxVsError(t *testing.T) {
	e, _, out, errOut := lifecycleEnv(t, "")
	// ErrSyntax → full help on stdout, no "ERROR:". ("allow in on" parses
	// as a deferred interface, so use an unknown action and a bare verb.)
	for _, args := range [][]string{{"frobnicate", "22"}, {"allow"}} {
		out.Reset()
		if rc := e.cmdRuleOp(args); rc != 1 {
			t.Fatalf("%v: rc = %d", args, rc)
		}
		if !strings.HasPrefix(out.String(), "Usage:") {
			t.Fatalf("%v: stdout = %.60q", args, out.String())
		}
	}
	// Semantic error → "ERROR:" on stderr.
	out.Reset()
	if rc := e.cmdRuleOp([]string{"allow", "99999"}); rc != 1 {
		t.Fatalf("rc = %d", rc)
	}
	if !strings.HasPrefix(errOut.String(), "ERROR:") {
		t.Fatalf("stderr = %q", errOut.String())
	}
	if out.String() != "" {
		t.Fatalf("stdout = %q, want empty for ERROR path", out.String())
	}
}

// ---- enable-side hooks and fragments -------------------------------------

func TestEnableBeforeInitFailureAborts(t *testing.T) {
	e, fb, _, errOut := lifecycleEnv(t, "")
	if err := os.MkdirAll(e.Store.Dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.Store.InitPath("before"), []byte("#!/bin/sh\nexit 1\n"), 0755); err != nil {
		t.Fatal(err)
	}
	hookRunCmd = func(string, ...string) error { return errors.New("boom") }
	if rc := e.cmdEnable(nil); rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	if fb.applies != 0 {
		t.Error("applied after before.init failure")
	}
	if !strings.Contains(errOut.String(), "before.init failed") {
		t.Fatalf("stderr = %q", errOut.String())
	}
}

func TestEnableFragmentFailureRollsBack(t *testing.T) {
	e, _, _, errOut := lifecycleEnv(t, "")
	fb := &fragFailBackend{failOn: "after.rules"}
	e.Backend = fb
	if err := os.MkdirAll(e.Store.Dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.Store.FragmentPath("after"), []byte("bad fragment\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if rc := e.cmdEnable(nil); rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	if fb.applies != 1 {
		t.Fatalf("applies = %d, want 1", fb.applies)
	}
	if fb.flushes != 1 {
		t.Errorf("flushes = %d, want 1 (core rolled back)", fb.flushes)
	}
	if !strings.Contains(errOut.String(), "Failed to apply firewall fragments") {
		t.Fatalf("stderr = %q", errOut.String())
	}
}

func TestDisableRunsStopHooks(t *testing.T) {
	e, fb, _, _ := lifecycleEnv(t, "")
	if err := os.MkdirAll(e.Store.Dir, 0755); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"before", "after"} {
		if err := os.WriteFile(e.Store.InitPath(n), []byte("#!/bin/sh\n"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	var calls []string
	hookRunCmd = func(name string, args ...string) error {
		calls = append(calls, filepath.Base(name)+" "+strings.Join(args, " "))
		return nil
	}
	if rc := e.cmdDisable(nil); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	want := []string{"before.init stop", "after.init stop"}
	if fmt.Sprint(calls) != fmt.Sprint(want) {
		t.Fatalf("hook calls = %v, want %v", calls, want)
	}
	if fb.flushes != 1 {
		t.Errorf("flushes = %d, want 1", fb.flushes)
	}
}

// ---- panic ----------------------------------------------------------------

func TestPanicModes(t *testing.T) {
	// Engage: applies a drop-all copy even while disabled; stored policies
	// untouched.
	e, fb, out, _ := lifecycleEnv(t, "")
	if rc := e.cmdPanic(nil); rc != 0 {
		t.Fatalf("panic rc = %d", rc)
	}
	if !strings.Contains(out.String(), "Panic mode ON") {
		t.Fatalf("stdout = %q", out.String())
	}
	if fb.applies != 1 {
		t.Fatalf("applies = %d, want 1 (emergency apply while disabled)", fb.applies)
	}
	st := loadState(t, e)
	if !st.Panic {
		t.Fatal("state not marked panicked")
	}
	if st.Policies.Input != "deny" || st.Policies.Output != "allow" {
		t.Errorf("stored policies clobbered: %+v", st.Policies)
	}

	// Already panicked → idempotent message, no second apply.
	out.Reset()
	if rc := e.cmdPanic(nil); rc != 0 {
		t.Fatalf("second panic rc = %d", rc)
	}
	if !strings.Contains(out.String(), "Already in panic mode") || fb.applies != 1 {
		t.Fatalf("stdout=%q applies=%d", out.String(), fb.applies)
	}

	// panic off restores: saves panic=false and re-applies only if live;
	// disabled → Flush to drop the panic table.
	out.Reset()
	if rc := e.cmdPanic([]string{"off"}); rc != 0 {
		t.Fatalf("panic off rc = %d", rc)
	}
	if !strings.Contains(out.String(), "Panic mode OFF") {
		t.Fatalf("stdout = %q", out.String())
	}
	st = loadState(t, e)
	if st.Panic {
		t.Error("panic flag still set")
	}
	if fb.flushes != 1 {
		t.Errorf("flushes = %d, want 1", fb.flushes)
	}

	// panic off when not panicked.
	out.Reset()
	if rc := e.cmdPanic([]string{"off"}); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	if !strings.Contains(out.String(), "Not in panic mode") {
		t.Fatalf("stdout = %q", out.String())
	}
}

func TestPanicRefusesOverSSH(t *testing.T) {
	e, fb, _, errOut := lifecycleEnv(t, "")
	hookUnderSSH = func() bool { return true }
	if rc := e.cmdPanic(nil); rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	if fb.applies != 0 {
		t.Error("panic applied over ssh")
	}
	if !strings.Contains(errOut.String(), "refusing to panic over ssh") {
		t.Fatalf("stderr = %q", errOut.String())
	}

	// --force overrides.
	e.Force = true
	if rc := e.cmdPanic(nil); rc != 0 {
		t.Fatalf("forced panic rc = %d", rc)
	}
	if fb.applies != 1 {
		t.Error("forced panic not applied")
	}
}

func TestPanicDryRun(t *testing.T) {
	e, fb, out, _ := lifecycleEnv(t, "")
	e.DryRun = true
	if rc := e.cmdPanic(nil); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	if !strings.Contains(out.String(), "Panic mode ON") {
		t.Fatalf("stdout = %q", out.String())
	}
	st := loadState(t, e)
	if st.Panic || fb.applies != 0 {
		t.Errorf("dry-run mutated state=%v applies=%d", st.Panic, fb.applies)
	}
}

// ---- rule enable/disable --------------------------------------------------

func TestRuleToggle(t *testing.T) {
	e, _, _, errOut := lifecycleEnv(t, "")
	st := store.Defaults()
	st.Rules4 = []rule.Rule{
		*mkExtRule("allow", "in", "tcp", "any", "any", ports(22, "tcp")),
		*mkExtRule("deny", "in", "tcp", "any", "any", ports(23, "tcp")),
	}
	if err := e.Store.Save(st); err != nil {
		t.Fatal(err)
	}

	if rc := e.cmdRule([]string{"disable", "1"}); rc != 0 {
		t.Fatalf("rule disable rc = %d", rc)
	}
	st = loadState(t, e)
	if !st.Rules4[0].Disabled || st.Rules4[1].Disabled {
		t.Fatalf("disabled flags = %v/%v", st.Rules4[0].Disabled, st.Rules4[1].Disabled)
	}

	if rc := e.cmdRule([]string{"enable", "1"}); rc != 0 {
		t.Fatalf("rule enable rc = %d", rc)
	}
	st = loadState(t, e)
	if st.Rules4[0].Disabled {
		t.Error("rule still disabled")
	}

	// Numbering is the displayed (deduped) index; out-of-range and junk
	// numbers error out.
	for _, arg := range []string{"0", "99", "bogus"} {
		errOut.Reset()
		if rc := e.cmdRule([]string{"disable", arg}); rc != 1 {
			t.Errorf("rule disable %q: rc = %d, want 1", arg, rc)
		}
		if !strings.Contains(errOut.String(), "Could not find rule") {
			t.Errorf("stderr = %q", errOut.String())
		}
	}

	// Malformed invocation → help.
	e2, _, out2, _ := lifecycleEnv(t, "")
	if rc := e2.cmdRule([]string{"frobnicate", "1"}); rc != 1 || !strings.HasPrefix(out2.String(), "Usage:") {
		t.Errorf("rule frobnicate: rc=%d out=%.40q", rc, out2.String())
	}
}

// ---- set ------------------------------------------------------------------

func TestSetLifecycle(t *testing.T) {
	e, _, out, errOut := lifecycleEnv(t, "")

	if rc := e.cmdSet([]string{"create", "blocklist"}); rc != 0 {
		t.Fatalf("set create rc = %d", rc)
	}
	st := loadState(t, e)
	if len(st.Sets) != 1 || st.Sets[0].Name != "blocklist" || st.Sets[0].Family != "inet" {
		t.Fatalf("sets = %+v", st.Sets)
	}

	// Duplicate create → error.
	if rc := e.cmdSet([]string{"create", "blocklist"}); rc != 1 ||
		!strings.Contains(errOut.String(), "already exists") {
		t.Fatalf("dup create: rc=%d err=%q", rc, errOut.String())
	}
	errOut.Reset()

	// v6 twin naming collision.
	if rc := e.cmdSet([]string{"create", "blocklist6"}); rc != 1 ||
		!strings.Contains(errOut.String(), "collides") {
		t.Fatalf("twin create: rc=%d err=%q", rc, errOut.String())
	}
	errOut.Reset()

	// Invalid names rejected before touching state.
	if rc := e.cmdSet([]string{"create", "bad name!"}); rc != 1 ||
		!strings.Contains(errOut.String(), "Invalid set name") {
		t.Fatalf("bad name: rc=%d err=%q", rc, errOut.String())
	}
	errOut.Reset()
	if rc := e.cmdSet([]string{"add", "blocklist", "10.0.0.0/8", "192.168.1.1,10.0.0.0/8"}); rc != 0 {
		t.Fatalf("set add rc = %d", rc)
	}
	st = loadState(t, e)
	elems := st.Sets[0].Elements
	// canonSetElem keeps bare IPs bare and canonicalizes CIDRs.
	if len(elems) != 2 || elems[0] != "10.0.0.0/8" || elems[1] != "192.168.1.1" {
		t.Fatalf("elements = %v, want [10.0.0.0/8 192.168.1.1]", elems)
	}
	if !strings.Contains(out.String(), "added 2 element(s)") {
		t.Fatalf("stdout = %q", out.String())
	}

	// Bad element / missing set errors.
	if rc := e.cmdSet([]string{"add", "blocklist", "nonsense"}); rc != 1 ||
		!strings.Contains(errOut.String(), "Bad IP address") {
		t.Fatalf("bad elem: rc=%d err=%q", rc, errOut.String())
	}
	errOut.Reset()
	if rc := e.cmdSet([]string{"add", "nosuch", "10.0.0.1"}); rc != 1 ||
		!strings.Contains(errOut.String(), "does not exist") {
		t.Fatalf("missing set: rc=%d err=%q", rc, errOut.String())
	}
	errOut.Reset()

	// Del removes a canonicalized element; absent element errors.
	if rc := e.cmdSet([]string{"del", "blocklist", "192.168.1.1"}); rc != 0 {
		t.Fatalf("set del rc = %d", rc)
	}
	st = loadState(t, e)
	if len(st.Sets[0].Elements) != 1 {
		t.Fatalf("elements = %v", st.Sets[0].Elements)
	}
	if rc := e.cmdSet([]string{"del", "blocklist", "192.168.1.1"}); rc != 1 ||
		!strings.Contains(errOut.String(), "is not in set") {
		t.Fatalf("absent del: rc=%d err=%q", rc, errOut.String())
	}
	errOut.Reset()

	// Destroy: unreferenced → gone.
	if rc := e.cmdSet([]string{"destroy", "blocklist"}); rc != 0 {
		t.Fatalf("destroy rc = %d", rc)
	}
	st = loadState(t, e)
	if len(st.Sets) != 0 {
		t.Fatalf("sets = %+v", st.Sets)
	}
	if rc := e.cmdSet([]string{"destroy", "blocklist"}); rc != 1 ||
		!strings.Contains(errOut.String(), "does not exist") {
		t.Fatalf("double destroy: rc=%d err=%q", rc, errOut.String())
	}
}

func TestSetListAndJSON(t *testing.T) {
	e, _, out, _ := lifecycleEnv(t, "")
	st := store.Defaults()
	st.Sets = []store.IPSet{
		{Name: "a", Family: "inet", Elements: []string{"10.0.0.0/8"}},
		{Name: "b", Family: "inet"},
	}
	if err := e.Store.Save(st); err != nil {
		t.Fatal(err)
	}
	if rc := e.cmdSet([]string{"list"}); rc != 0 {
		t.Fatalf("set list rc = %d", rc)
	}
	got := out.String()
	if !strings.Contains(got, "Set 'a' (inet):") || !strings.Contains(got, "  10.0.0.0/8") ||
		!strings.Contains(got, "Set 'b'") {
		t.Fatalf("stdout = %q", got)
	}

	// Named lookup; unknown name errors.
	out.Reset()
	if rc := e.cmdSet([]string{"list", "a"}); rc != 0 || !strings.Contains(out.String(), "10.0.0.0/8") {
		t.Fatalf("set list a: rc=%d out=%q", rc, out.String())
	}
	e2, _, _, errOut2 := lifecycleEnv(t, "")
	_ = e2.Store.Save(store.Defaults())
	if rc := e2.cmdSet([]string{"list", "nosuch"}); rc != 1 ||
		!strings.Contains(errOut2.String(), "does not exist") {
		t.Fatalf("set list nosuch: rc=%d err=%q", rc, errOut2.String())
	}

	// JSON shape.
	e.JSON = true
	out.Reset()
	if rc := e.cmdSet([]string{"list"}); rc != 0 {
		t.Fatalf("json list rc = %d", rc)
	}
	var doc struct {
		Sets []store.IPSet `json:"sets"`
	}
	if err := json.Unmarshal([]byte(out.String()), &doc); err != nil || len(doc.Sets) != 2 {
		t.Fatalf("json = %q err=%v", out.String(), err)
	}
}

func TestSetDestroyReferenced(t *testing.T) {
	e, _, _, errOut := lifecycleEnv(t, "")
	st := store.Defaults()
	st.Sets = []store.IPSet{{Name: "blocklist", Family: "inet", Elements: []string{"10.0.0.0/8"}}}
	r := mkExtRule("deny", "in", "any", "any", "any")
	r.Src.Set = "blocklist"
	st.Rules4 = []rule.Rule{*r}
	if err := e.Store.Save(st); err != nil {
		t.Fatal(err)
	}

	// Without --force: refused, set and rule preserved.
	if rc := e.cmdSet([]string{"destroy", "blocklist"}); rc != 1 ||
		!strings.Contains(errOut.String(), "referenced by 1 rule(s)") {
		t.Fatalf("destroy rc=%d err=%q", rc, errOut.String())
	}
	st = loadState(t, e)
	if len(st.Sets) != 1 || len(st.Rules4) != 1 {
		t.Fatal("referenced destroy mutated state")
	}

	// --force: set gone AND referencing rules stripped (dangling refs
	// would wedge every later apply).
	e.Force = true
	if rc := e.cmdSet([]string{"destroy", "blocklist"}); rc != 0 {
		t.Fatalf("forced destroy rc = %d", rc)
	}
	st = loadState(t, e)
	if len(st.Sets) != 0 {
		t.Error("set survives forced destroy")
	}
	if len(st.Rules4) != 0 {
		t.Errorf("referencing rule kept: %+v", st.Rules4)
	}
}

// ---- nat ------------------------------------------------------------------

func TestNatAddListDelete(t *testing.T) {
	e, _, out, errOut := lifecycleEnv(t, "")

	if rc := e.cmdNat([]string{"add", "masquerade", "out", "on", "eth0", "from", "10.9.0.0/24"}); rc != 0 {
		t.Fatalf("nat add masq rc = %d", rc)
	}
	if rc := e.cmdNat([]string{"add", "dnat", "proto", "tcp", "in", "on", "wan0",
		"to", "203.0.113.5", "port", "8080", "to-destination", "10.0.0.8:80"}); rc != 0 {
		t.Fatalf("nat add dnat rc = %d", rc)
	}
	st := loadState(t, e)
	if len(st.NAT) != 2 {
		t.Fatalf("nat = %+v", st.NAT)
	}
	if st.NAT[0].Kind != "masquerade" || st.NAT[0].IfaceOut != "eth0" || st.NAT[0].Src != "10.9.0.0/24" {
		t.Errorf("masq = %+v", st.NAT[0])
	}
	d := st.NAT[1]
	if d.Kind != "dnat" || d.Proto != "tcp" || d.IfaceIn != "wan0" ||
		d.Dst != "203.0.113.5" || d.Dport != 8080 || d.ToDest != "10.0.0.8:80" {
		t.Errorf("dnat = %+v", d)
	}

	out.Reset()
	if rc := e.cmdNat([]string{"list"}); rc != 0 {
		t.Fatalf("nat list rc = %d", rc)
	}
	got := out.String()
	if !strings.Contains(got, "masquerade out on eth0 from 10.9.0.0/24") ||
		!strings.Contains(got, "dnat proto tcp in on wan0 to 203.0.113.5 port 8080 to-destination 10.0.0.8:80") {
		t.Fatalf("stdout = %q", got)
	}

	// Delete entry 1; out-of-range and non-numeric rejected.
	if rc := e.cmdNat([]string{"delete", "1"}); rc != 0 {
		t.Fatalf("nat delete rc = %d", rc)
	}
	st = loadState(t, e)
	if len(st.NAT) != 1 || st.NAT[0].Kind != "dnat" {
		t.Fatalf("nat = %+v", st.NAT)
	}
	for _, arg := range []string{"0", "5", "x"} {
		if rc := e.cmdNat([]string{"delete", arg}); rc != 1 ||
			!strings.Contains(errOut.String(), "Could not find rule") {
			t.Fatalf("nat del %q: rc=%d err=%q", arg, rc, errOut.String())
		}
		errOut.Reset()
	}
}

func TestNatAddValidation(t *testing.T) {
	e, _, _, errOut := lifecycleEnv(t, "")
	bad := [][]string{
		{"add", "bogus"},
		{"add", "masquerade", "out", "on", "eth0", "from", "not-an-ip"},
		{"add", "dnat", "proto", "sctp", "to", "1.2.3.4", "port", "80", "to-destination", "10.0.0.1"},
		{"add", "dnat", "proto", "tcp", "to", "1.2.3.4", "port", "0", "to-destination", "10.0.0.1"},
		{"add", "dnat", "proto", "tcp", "to", "1.2.3.4", "port", "80", "to-destination", "10.0.0.1:99999"},
		{"add", "dnat", "proto", "tcp", "to", "1.2.3.4", "port", "80", "to-destination", "::1"}, // family mismatch
	}
	for i, args := range bad {
		if rc := e.cmdNat(args); rc != 1 {
			t.Errorf("case %d %v: rc = %d, want 1", i, args, rc)
		}
		errOut.Reset()
	}
	st := loadState(t, e)
	if len(st.NAT) != 0 {
		t.Errorf("invalid adds persisted: %+v", st.NAT)
	}
}

// ---- check ----------------------------------------------------------------

func TestCheckReports(t *testing.T) {
	// Clean state → "No issues found".
	e, _, out, _ := lifecycleEnv(t, "")
	if rc := e.cmdCheck(nil); rc != 0 {
		t.Fatalf("check rc = %d", rc)
	}
	if !strings.Contains(out.String(), "No issues found") {
		t.Fatalf("stdout = %q", out.String())
	}

	// ssh lockout risk: deny-in policy + under ssh + no ssh allow.
	e, _, out, _ = lifecycleEnv(t, "")
	hookUnderSSH = func() bool { return true }
	if rc := e.cmdCheck(nil); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	if !strings.Contains(out.String(), "ssh lockout risk") {
		t.Fatalf("stdout = %q", out.String())
	}

	// Same policy but with an ssh allow → no lockout warning.
	e, _, out, _ = lifecycleEnv(t, "")
	hookUnderSSH = func() bool { return true }
	st := store.Defaults()
	st.Rules4 = []rule.Rule{*mkExtRule("allow", "in", "tcp", "any", "any", ports(22, "tcp"))}
	if err := e.Store.Save(st); err != nil {
		t.Fatal(err)
	}
	if rc := e.cmdCheck(nil); rc != 0 || strings.Contains(out.String(), "lockout") {
		t.Fatalf("rc=%d out=%q", rc, out.String())
	}

	// Enabled but not loaded in the kernel.
	e, _, out, _ = lifecycleEnv(t, "")
	if err := e.Store.SaveConf(&store.Conf{Enabled: true, LogLevel: "low"}); err != nil {
		t.Fatal(err)
	}
	if rc := e.cmdCheck(nil); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	if !strings.Contains(out.String(), "enabled but not loaded") {
		t.Fatalf("stdout = %q", out.String())
	}

	// Expired and shadowed rules.
	e, _, out, _ = lifecycleEnv(t, "")
	st = store.Defaults()
	expired := mkExtRule("allow", "in", "udp", "any", "any", ports(67, "udp"))
	expired.ExpiresAt = 1 // long past
	shadowee := mkExtRule("allow", "in", "tcp", "10.0.0.1", "10.0.0.2", ports(22, "tcp"))
	shadowed := mkExtRule("allow", "in", "tcp", "any", "any", ports(22, "tcp"))
	st.Rules4 = []rule.Rule{*expired, *shadowee, *shadowed}
	if err := e.Store.Save(st); err != nil {
		t.Fatal(err)
	}
	if rc := e.cmdCheck(nil); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	got := out.String()
	if !strings.Contains(got, "rule 1 expired") {
		t.Errorf("missing expiry warning: %q", got)
	}
	// rule2 (specific) is shadowed by rule3? No — rule3 comes after rule2;
	// shadow = earlier rule covers later one. Reorder mentally: all[1] is
	// shadowed only if an earlier rule supersedes it. Put the broad rule
	// first to trigger.
	st2 := store.Defaults()
	st2.Rules4 = []rule.Rule{*shadowed, *shadowee}
	e2, _, out2, _ := lifecycleEnv(t, "")
	if err := e2.Store.Save(st2); err != nil {
		t.Fatal(err)
	}
	if rc := e2.cmdCheck(nil); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	if !strings.Contains(out2.String(), "rule 2 shadowed by rule 1") {
		t.Errorf("missing shadow warning: %q", out2.String())
	}

	// Foreign ufw chains in the kernel.
	e, _, out, _ = lifecycleEnv(t, "")
	e.Backend = &snapBackend{snap: &backend.Snapshot{
		Chains: []*nftables.Chain{{Name: "ufw-user-input"}, {Name: "bfw-user-input"}},
	}}
	if rc := e.cmdCheck(nil); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	got = out.String()
	if !strings.Contains(got, "ufw chains detected") || !strings.Contains(got, "ufw-user-input") {
		t.Errorf("stdout = %q", got)
	}
	if strings.Contains(got, "bfw-user-input detected") ||
		strings.Contains(got, "bfw-user-input\n") {
		t.Errorf("own chains mislabeled foreign: %q", got)
	}
}

// ---- diff -----------------------------------------------------------------

func TestDiffAgainstEmptyKernel(t *testing.T) {
	e, _, out, _ := lifecycleEnv(t, "")
	// Hide nft: every `nft list table` call fails → kernel side is empty →
	// stored ruleset must show up as a diff and exit 1.
	t.Setenv("PATH", t.TempDir())
	st := store.Defaults()
	st.Rules4 = []rule.Rule{*mkExtRule("allow", "in", "tcp", "any", "any", ports(22, "tcp"))}
	if err := e.Store.Save(st); err != nil {
		t.Fatal(err)
	}
	if rc := e.cmdDiff(nil); rc != 1 {
		t.Fatalf("diff rc = %d, want 1", rc)
	}
	got := out.String()
	if !strings.Contains(got, "--- stored") || !strings.Contains(got, "+++ kernel") {
		t.Fatalf("stdout = %q", got)
	}
	if !strings.Contains(got, "-") || !strings.Contains(got, "better-firewall") {
		t.Errorf("diff body missing stored rules:\n%s", got)
	}
}

func TestDiffMatch(t *testing.T) {
	e, _, out, _ := lifecycleEnv(t, "")
	st := store.Defaults()
	if err := e.Store.Save(st); err != nil {
		t.Fatal(err)
	}
	etc, err := e.Store.EtcDefaults()
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := nftbe.RenderText(st, etc)
	if err != nil {
		t.Fatalf("RenderText: %v", err)
	}
	// Stub `nft` to echo the stored rendering only for the inet table so
	// normalizeNft(stored) == normalizeNft(kernel) → match, rc 0.
	// argv: nft -nn list table <family> <name> → family is $4.
	bin := t.TempDir()
	stub := filepath.Join(bin, "nft")
	script := "#!/bin/sh\nif [ \"$4\" = \"inet\" ]; then cat " +
		writeFixture(t, "ruleset.nft", rendered) + "; fi\n"
	if err := os.WriteFile(stub, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH")) // stub first; real cat/sh still resolve
	if rc := e.cmdDiff(nil); rc != 0 {
		t.Fatalf("diff rc = %d, want 0; out = %q", rc, out.String())
	}
	if !strings.Contains(out.String(), "Ruleset matches stored state") {
		t.Fatalf("stdout = %q", out.String())
	}
}

func writeFixture(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

// ---- show ------------------------------------------------------------------

func TestShowFragmentsAndChains(t *testing.T) {
	e, _, out, _ := lifecycleEnv(t, "")
	if err := os.MkdirAll(e.Store.Dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.Store.FragmentPath("before"), []byte("# user before rules\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if rc := e.cmdShow([]string{"before-rules"}); rc != 0 {
		t.Fatalf("show before-rules rc = %d", rc)
	}
	if !strings.Contains(out.String(), "# user before rules") {
		t.Fatalf("stdout = %q", out.String())
	}

	// Missing fragments → empty output, still rc 0.
	out.Reset()
	if rc := e.cmdShow([]string{"after-rules"}); rc != 0 {
		t.Fatalf("show after-rules rc = %d", rc)
	}

	// Rendered chain reports include the managed chains.
	out.Reset()
	if rc := e.cmdShow([]string{"builtins"}); rc != 0 {
		t.Fatalf("show builtins rc = %d", rc)
	}
	if !strings.Contains(out.String(), "chain input") {
		t.Fatalf("builtins missing chain input:\n%s", out.String())
	}
	out.Reset()
	if rc := e.cmdShow([]string{"user-rules"}); rc != 0 {
		t.Fatalf("show user-rules rc = %d", rc)
	}
	if !strings.Contains(out.String(), "bfw-user-input") {
		t.Fatalf("user-rules missing bfw-user-input:\n%s", out.String())
	}
	out.Reset()
	if rc := e.cmdShow([]string{"logging-rules"}); rc != 0 {
		t.Fatalf("logging-rules rc = %d", rc)
	}
	if !strings.Contains(out.String(), "bfw-user-logging-input") {
		t.Fatalf("logging-rules missing logging chains:\n%s", out.String())
	}
}

func TestShowAdded(t *testing.T) {
	e, _, out, _ := lifecycleEnv(t, "")

	// Empty → (None).
	if rc := e.cmdShow([]string{"added"}); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	if !strings.Contains(out.String(), "(None)") {
		t.Fatalf("stdout = %q", out.String())
	}

	st := store.Defaults()
	st.Rules4 = []rule.Rule{*mkExtRule("allow", "in", "tcp", "any", "any", ports(22, "tcp"))}
	st.Rules6 = []rule.Rule{*st.Rules4[0].Clone()}
	if err := e.Store.Save(st); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if rc := e.cmdShow([]string{"added"}); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	got := out.String()
	// Identical v4/v6 commands are echoed once (deduped).
	if strings.Count(got, "bfw allow 22/tcp") != 1 {
		t.Fatalf("stdout = %q", got)
	}

	// --json emits the command list.
	e.JSON = true
	out.Reset()
	if rc := e.cmdShow([]string{"added"}); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	var doc struct {
		Added []string `json:"added"`
	}
	if err := json.Unmarshal([]byte(out.String()), &doc); err != nil || len(doc.Added) != 1 {
		t.Fatalf("json = %q err=%v", out.String(), err)
	}
}

func TestShowValidationAndRaw(t *testing.T) {
	e, _, out, _ := lifecycleEnv(t, "")
	for _, args := range [][]string{{}, {"bogus"}, {"raw", "extra"}} {
		out.Reset()
		if rc := e.cmdShow(args); rc != 1 || !strings.HasPrefix(out.String(), "Usage:") {
			t.Errorf("show %v: rc=%d out=%.40q", args, rc, out.String())
		}
	}

	// show raw falls back to the rendered stored model when nft fails.
	e2, _, out2, _ := lifecycleEnv(t, "")
	t.Setenv("PATH", t.TempDir())
	if rc := e2.cmdShow([]string{"raw"}); rc != 0 {
		t.Fatalf("show raw rc = %d", rc)
	}
	if !strings.Contains(out2.String(), "table inet better-firewall") {
		t.Fatalf("stdout = %q", out2.String())
	}

	// With an nft stub the kernel view wins verbatim.
	e3, _, out3, _ := lifecycleEnv(t, "")
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "nft"), []byte("#!/bin/sh\necho KERNEL-VIEW\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	if rc := e3.cmdShow([]string{"raw"}); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	if strings.TrimSpace(out3.String()) != "KERNEL-VIEW" {
		t.Fatalf("stdout = %q", out3.String())
	}
}

// ---- app ------------------------------------------------------------------

const testProfileINI = `[ZzTestApp]
title=Test app
description=Coverage test profile
ports=8080/tcp
`

func TestAppList(t *testing.T) {
	e, _, out, _ := lifecycleEnv(t, "")
	writeProfile(t, e, "zztestapp", testProfileINI)
	if rc := e.cmdApp([]string{"list"}); rc != 0 {
		t.Fatalf("app list rc = %d", rc)
	}
	got := out.String()
	if !strings.Contains(got, "Available applications:") || !strings.Contains(got, "ZzTestApp") {
		t.Fatalf("stdout = %q", got)
	}

	e.JSON = true
	out.Reset()
	if rc := e.cmdApp([]string{"list"}); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	var doc struct {
		Applications []string `json:"applications"`
	}
	if err := json.Unmarshal([]byte(out.String()), &doc); err != nil {
		t.Fatalf("json = %q: %v", out.String(), err)
	}
	found := false
	for _, n := range doc.Applications {
		if n == "ZzTestApp" {
			found = true
		}
	}
	if !found {
		t.Errorf("ZzTestApp missing from %v", doc.Applications)
	}
}

func TestAppInfo(t *testing.T) {
	e, _, out, errOut := lifecycleEnv(t, "")
	writeProfile(t, e, "zztestapp", testProfileINI)

	if rc := e.cmdApp([]string{"info", "ZzTestApp"}); rc != 0 {
		t.Fatalf("app info rc = %d", rc)
	}
	got := out.String()
	for _, want := range []string{"Profile: ZzTestApp", "Title: Test app", "Coverage test profile", "8080/tcp"} {
		if !strings.Contains(got, want) {
			t.Errorf("app info missing %q:\n%s", want, got)
		}
	}
	if !strings.Contains(got, "Port:") {
		t.Errorf("single-item profile should use 'Port:' header:\n%s", got)
	}

	// Unknown and invalid names.
	out.Reset()
	if rc := e.cmdApp([]string{"info", "NoSuchApp"}); rc != 1 ||
		!strings.Contains(errOut.String(), "Could not find profile") {
		t.Fatalf("unknown: rc=%d err=%q", rc, errOut.String())
	}
	errOut.Reset()
	if rc := e.cmdApp([]string{"info", "9bad;name"}); rc != 1 ||
		!strings.Contains(errOut.String(), "Invalid profile name") {
		t.Fatalf("invalid: rc=%d err=%q", rc, errOut.String())
	}
	errOut.Reset()
	// Reserved "all" is rejected by validProfileName for single-info but
	// accepted as the all-profiles query.
	out.Reset()
	if rc := e.cmdApp([]string{"info", "all"}); rc != 0 {
		t.Fatalf("info all rc = %d", rc)
	}
	if !strings.Contains(out.String(), "Profile:") {
		t.Fatalf("info all output = %q", out.String())
	}
}

func TestAppDefault(t *testing.T) {
	e, _, out, _ := lifecycleEnv(t, "")
	if rc := e.cmdApp([]string{"default", "deny"}); rc != 0 {
		t.Fatalf("app default rc = %d", rc)
	}
	if !strings.Contains(out.String(), "Default application policy changed to 'deny'") {
		t.Fatalf("stdout = %q", out.String())
	}
	m, err := e.Store.EtcDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if m["DEFAULT_APPLICATION_POLICY"] != "DROP" {
		t.Errorf("DEFAULT_APPLICATION_POLICY = %q, want DROP", m["DEFAULT_APPLICATION_POLICY"])
	}
	st := loadState(t, e)
	if st.AppPolicy != "deny" {
		t.Errorf("AppPolicy = %q, want deny", st.AppPolicy)
	}

	// Invalid policy → help, exit 1; nothing written.
	e2, _, out2, _ := lifecycleEnv(t, "")
	if rc := e2.cmdApp([]string{"default", "bogus"}); rc != 1 || !strings.HasPrefix(out2.String(), "Usage:") {
		t.Fatalf("bogus policy: rc=%d out=%.40q", rc, out2.String())
	}
	if _, err := os.Stat(e2.Store.EtcFile); !os.IsNotExist(err) {
		t.Error("invalid policy wrote /etc/default file")
	}
}

func TestAppUpdate(t *testing.T) {
	e, _, out, errOut := lifecycleEnv(t, "")
	writeProfile(t, e, "zztestapp", testProfileINI)

	// Stored app rule referencing the profile.
	st := store.Defaults()
	r := mkExtRule("allow", "in", "tcp", "any", "any", ports(8080, "tcp"))
	r.Dapp = "ZzTestApp"
	st.Rules4 = []rule.Rule{*r}
	if err := e.Store.Save(st); err != nil {
		t.Fatal(err)
	}

	// Profile changes → stored rule regenerated from the new ports.
	writeProfile(t, e, "zztestapp", strings.ReplaceAll(testProfileINI, "8080/tcp", "9090/tcp"))
	if rc := e.cmdApp([]string{"update", "ZzTestApp"}); rc != 0 {
		t.Fatalf("app update rc = %d", rc)
	}
	if !strings.Contains(out.String(), "Rules updated for profile 'ZzTestApp'") {
		t.Fatalf("stdout = %q", out.String())
	}
	st = loadState(t, e)
	if len(st.Rules4) != 1 || st.Rules4[0].Dst.Ports[0].Lo != 9090 {
		t.Fatalf("rules4 = %+v, want port 9090", st.Rules4)
	}
	if st.Rules4[0].Dapp != "ZzTestApp" {
		t.Errorf("app tuple lost: %+v", st.Rules4[0])
	}

	// Unknown profile: ufw errors "Could not find a profile matching '<name>'".
	out.Reset()
	if rc := e.cmdApp([]string{"update", "NoSuchProfile"}); rc != 1 {
		t.Fatalf("update missing rc = %d, want 1", rc)
	}
	if !strings.Contains(errOut.String(), "Could not find a profile matching 'NoSuchProfile'") {
		t.Fatalf("stderr = %q, want ufw's profile-miss error", errOut.String())
	}
	st = loadState(t, e)
	if len(st.Rules4) != 1 || st.Rules4[0].Dst.Ports[0].Lo != 9090 {
		t.Error("unknown profile update mutated state")
	}
}

func TestAppUpdateAddNew(t *testing.T) {
	e, _, _, errOut := lifecycleEnv(t, "")
	// The parser-side profile lookup honors BFW_PREFIX; point it at the
	// env's prefix so `applicationAdd` can expand the profile.
	prefix := filepath.Dir(filepath.Dir(e.Store.Dir))
	t.Setenv("BFW_PREFIX", prefix)
	writeProfile(t, e, "zztestapp", testProfileINI)

	st := store.Defaults()
	st.AppPolicy = "allow"
	if err := e.Store.Save(st); err != nil {
		t.Fatal(err)
	}
	if rc := e.cmdApp([]string{"update", "--add-new", "ZzTestApp"}); rc != 0 {
		t.Fatalf("rc = %d, err=%q", rc, errOut.String())
	}
	st = loadState(t, e)
	found := false
	for _, r := range st.Rules4 {
		if r.Dapp == "ZzTestApp" && r.Action == "allow" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no allow rule added for profile: %+v", st.Rules4)
	}

	// 'all' is rejected with --add-new.
	if rc := e.cmdApp([]string{"update", "--add-new", "all"}); rc != 1 {
		t.Fatalf("add-new all: rc=%d, want 1", rc)
	}

	// skip policy → no rule added.
	e2, _, _, _ := lifecycleEnv(t, "")
	st2 := store.Defaults() // AppPolicy "skip"
	if err := e2.Store.Save(st2); err != nil {
		t.Fatal(err)
	}
	if rc := e2.cmdApp([]string{"update", "--add-new", "ZzTestApp"}); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	st2 = loadState(t, e2)
	if len(st2.Rules4) != 0 {
		t.Errorf("skip policy added rules: %+v", st2.Rules4)
	}

	// skip policy + --add-new on a profile that exists nowhere: the
	// tested skip shortcut must still return 0 rather than the
	// missing-profile error, and must not add rules.
	e3, _, _, _ := lifecycleEnv(t, "")
	st3 := store.Defaults() // AppPolicy "skip"
	if err := e3.Store.Save(st3); err != nil {
		t.Fatal(err)
	}
	if rc := e3.cmdApp([]string{"update", "--add-new", "NoSuchProfile"}); rc != 0 {
		t.Fatalf("skip add-new missing profile: rc=%d, want 0", rc)
	}
	st3 = loadState(t, e3)
	if len(st3.Rules4) != 0 || len(st3.Rules6) != 0 {
		t.Errorf("skip add-new added rules for missing profile: %+v", st3.Rules4)
	}

	// Non-skip policy + --add-new on a missing profile stays an error.
	e4, _, _, errOut4 := lifecycleEnv(t, "")
	st4 := store.Defaults()
	st4.AppPolicy = "allow"
	if err := e4.Store.Save(st4); err != nil {
		t.Fatal(err)
	}
	if rc := e4.cmdApp([]string{"update", "--add-new", "NoSuchProfile"}); rc != 1 {
		t.Fatalf("allow add-new missing profile: rc=%d, want 1", rc)
	}
	if !strings.Contains(errOut4.String(), "Could not find a profile matching 'NoSuchProfile'") {
		t.Fatalf("stderr = %q", errOut4.String())
	}
}

func TestAppProfilesFallbackDir(t *testing.T) {
	// Profiles are also resolved from the ufw-compat fallback
	// <prefix>/etc/ufw/applications.d, derived from the store dir (never a
	// hardcoded /etc path), so BFW_PREFIX trees and import-ufw staging
	// areas see the same profiles. Everything lives under t.TempDir().
	e, _, out, _ := lifecycleEnv(t, "")
	ufwApps := filepath.Join(filepath.Dir(e.Store.Dir), "ufw", "applications.d")
	if err := os.MkdirAll(ufwApps, 0755); err != nil {
		t.Fatal(err)
	}
	ini := "[UfwOnlyApp]\ntitle=Ufw-only app\ndescription=Profile in ufw fallback dir\nports=5150/tcp\n"
	if err := os.WriteFile(filepath.Join(ufwApps, "ufwonlyapp.ini"), []byte(ini), 0644); err != nil {
		t.Fatal(err)
	}

	// Direct check: loadProfiles surfaces the fallback-dir profile even
	// though the store's own applications.d does not exist.
	profiles := e.loadProfiles()
	found := false
	for _, p := range profiles {
		if p.Name == "UfwOnlyApp" {
			found = true
		}
	}
	if !found {
		names := make([]string, 0, len(profiles))
		for _, p := range profiles {
			names = append(names, p.Name)
		}
		t.Fatalf("loadProfiles = %v, want UfwOnlyApp from fallback dir", names)
	}

	// Command surface: `app list`/`app info` resolve the same profile.
	if rc := e.cmdApp([]string{"list"}); rc != 0 {
		t.Fatalf("app list rc = %d", rc)
	}
	if !strings.Contains(out.String(), "UfwOnlyApp") {
		t.Fatalf("app list missing fallback profile:\n%s", out.String())
	}
	out.Reset()
	if rc := e.cmdApp([]string{"info", "UfwOnlyApp"}); rc != 0 {
		t.Fatalf("app info rc = %d", rc)
	}
	if !strings.Contains(out.String(), "Profile: UfwOnlyApp") ||
		!strings.Contains(out.String(), "5150/tcp") {
		t.Fatalf("app info output = %q", out.String())
	}
}

// ---- logs -----------------------------------------------------------------

func TestLineFilter(t *testing.T) {
	var out bytes.Buffer
	f := &lineFilter{w: &out, substr: []byte("BFW")}
	in := "kern info\nkernel: BFW-IN blocked tcp 22\nplain line\nBFW-AUDIT\npartial BFW no newline"
	n, err := f.Write([]byte(in))
	if err != nil || n != len(in) {
		t.Fatalf("Write = %d, %v", n, err)
	}
	got := out.String()
	if !strings.Contains(got, "BFW-IN blocked tcp 22") || !strings.Contains(got, "BFW-AUDIT") {
		t.Errorf("filtered output missing BFW lines: %q", got)
	}
	if strings.Contains(got, "kern info") || strings.Contains(got, "plain line") {
		t.Errorf("unfiltered lines leaked: %q", got)
	}
	// A trailing unterminated line is buffered, not flushed.
	if strings.Contains(got, "partial BFW") {
		t.Errorf("partial line emitted early: %q", got)
	}
	if _, err := f.Write([]byte(" done\n")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "partial BFW no newline done") {
		t.Errorf("buffered line not flushed on newline: %q", out.String())
	}
}

func TestLogsJournalctlHook(t *testing.T) {
	e, _, out, errOut := lifecycleEnv(t, "")
	bin := t.TempDir()
	argvFile := filepath.Join(bin, "argv")
	stub := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + argvFile + "\necho LOGDATA\n"
	if err := os.WriteFile(filepath.Join(bin, "journalctl"), []byte(stub), 0755); err != nil {
		t.Fatal(err)
	}
	hookLookPath = func(name string) (string, error) {
		if name == "journalctl" {
			return filepath.Join(bin, "journalctl"), nil
		}
		return "", os.ErrNotExist
	}
	if rc := e.cmdLogs(nil); rc != 0 {
		t.Fatalf("logs rc = %d, err=%q", rc, errOut.String())
	}
	if !strings.Contains(out.String(), "LOGDATA") {
		t.Errorf("journalctl output not forwarded: %q", out.String())
	}
	argv, _ := os.ReadFile(argvFile)
	if !strings.Contains(string(argv), "-g\nBFW") {
		t.Errorf("journalctl args = %q, want -g BFW", argv)
	}
}

func TestLogsExitCodes(t *testing.T) {
	e, _, out, _ := lifecycleEnv(t, "")
	bin := t.TempDir()
	// Exit 7 → mapped to that code.
	if err := os.WriteFile(filepath.Join(bin, "journalctl"), []byte("#!/bin/sh\nexit 7\n"), 0755); err != nil {
		t.Fatal(err)
	}
	hookLookPath = func(string) (string, error) { return filepath.Join(bin, "journalctl"), nil }
	if rc := e.cmdLogs(nil); rc != 7 {
		t.Fatalf("exit 7 → rc %d", rc)
	}
	// Killed by signal (e.g. Ctrl-C on -f) → rc 0.
	if err := os.WriteFile(filepath.Join(bin, "journalctl"), []byte("#!/bin/sh\nkill -TERM $$\n"), 0755); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if rc := e.cmdLogs(nil); rc != 0 {
		t.Fatalf("signal exit → rc %d, want 0", rc)
	}
}

func TestLogsArgValidation(t *testing.T) {
	e, _, out, _ := lifecycleEnv(t, "")
	if rc := e.cmdLogs([]string{"extra"}); rc != 1 || !strings.HasPrefix(out.String(), "Usage:") {
		t.Fatalf("logs extra: rc=%d out=%.40q", rc, out.String())
	}
}

// ---- export/import/import-ufw ----------------------------------------------

func TestExportImportRoundTrip(t *testing.T) {
	e, _, out, _ := lifecycleEnv(t, "")
	st := store.Defaults()
	st.Logging = "full"
	st.Rules4 = []rule.Rule{*mkExtRule("allow", "in", "tcp", "any", "any", ports(443, "tcp"))}
	st.Bans = []store.ThreatBan{{
		Address: "203.0.113.9", Source: "crowdsec", Reason: "decision",
		DecisionID: 1, ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}}
	if err := e.Store.Save(st); err != nil {
		t.Fatal(err)
	}
	if rc := e.cmdExport(nil); rc != 0 {
		t.Fatalf("export rc = %d", rc)
	}
	doc := out.String()
	var m map[string]any
	if err := json.Unmarshal([]byte(doc), &m); err != nil || m["version"] != float64(1) {
		t.Fatalf("export = %q: %v", doc, err)
	}

	// Import into a fresh store merges the rule and scalars.
	e2, _, out2, _ := lifecycleEnv(t, doc)
	if rc := e2.cmdImport([]string{"-"}); rc != 0 {
		t.Fatalf("import rc = %d", rc)
	}
	if !strings.Contains(out2.String(), "Imported 1 rule(s)") {
		t.Fatalf("stdout = %q", out2.String())
	}
	st2 := loadState(t, e2)
	if st2.Logging != "full" || len(st2.Rules4) != 1 || len(st2.Bans) != 1 || st2.Bans[0].DecisionID != 1 {
		t.Fatalf("imported state = %+v", st2)
	}

	// Re-import is a no-op for identical rules.
	out2.Reset()
	e2.Stdin = strings.NewReader(doc)
	if rc := e2.cmdImport([]string{"-"}); rc != 0 {
		t.Fatalf("reimport rc = %d", rc)
	}
	st2 = loadState(t, e2)
	if len(st2.Rules4) != 1 {
		t.Errorf("reimport duplicated: %d rules", len(st2.Rules4))
	}
	if len(st2.Bans) != 1 {
		t.Errorf("reimport duplicated threat bans: %d", len(st2.Bans))
	}
}

func TestImportValidationAndDryRun(t *testing.T) {
	e, _, out, _ := lifecycleEnv(t, `{"version":1,"rules4":[],"rules6":[]}`)
	e.DryRun = true
	if rc := e.cmdImport([]string{"-"}); rc != 0 {
		t.Fatalf("dry-run import rc = %d", rc)
	}
	if !strings.Contains(out.String(), "Would import") {
		t.Fatalf("stdout = %q", out.String())
	}
	st := loadState(t, e)
	if len(st.Rules4) != 0 || st.Logging != "low" {
		t.Error("dry-run import persisted")
	}

	e2, _, _, errOut2 := lifecycleEnv(t, "not json")
	if rc := e2.cmdImport([]string{"-"}); rc != 1 {
		t.Fatalf("bad json rc = %d", rc)
	}
	if !strings.HasPrefix(errOut2.String(), "ERROR:") {
		t.Fatalf("stderr = %q", errOut2.String())
	}

	// Missing file argument → usage error.
	e3, _, _, _ := lifecycleEnv(t, "")
	if rc := e3.cmdImport(nil); rc != 1 {
		t.Fatalf("no file rc = %d", rc)
	}
}

func TestImportUFWMigration(t *testing.T) {
	e, _, out, errOut := lifecycleEnv(t, "")
	// Deterministic snapshot: no foreign chains.
	e.Backend = &snapBackend{snap: &backend.Snapshot{}}

	ufwDir := filepath.Join(filepath.Dir(e.Store.Dir), "ufw")
	if err := os.MkdirAll(ufwDir, 0755); err != nil {
		t.Fatal(err)
	}
	user := `*filter
:ufw-user-input - [0:0]
### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in
### tuple ### bogus tcp 1 0.0.0.0/0 any 0.0.0.0/0 in
### END RULES ###
COMMIT
`
	if err := os.WriteFile(filepath.Join(ufwDir, "user.rules"), []byte(user), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ufwDir, "ufw.conf"), []byte("ENABLED=yes\nLOGLEVEL=high\n"), 0644); err != nil {
		t.Fatal(err)
	}
	etcFile := filepath.Join(filepath.Dir(ufwDir), "default", "ufw")
	if err := os.MkdirAll(filepath.Dir(etcFile), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(etcFile, []byte("DEFAULT_FORWARD_POLICY=\"REJECT\"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Dry-run: rules described, nothing saved.
	e.DryRun = true
	if rc := e.cmdImportUFW(nil); rc != 0 {
		t.Fatalf("dry-run rc = %d", rc)
	}
	if !strings.Contains(out.String(), "Would import 1 ufw rule(s)") {
		t.Fatalf("stdout = %q", out.String())
	}
	st := loadState(t, e)
	if len(st.Rules4) != 0 {
		t.Error("dry-run import-ufw persisted")
	}

	// Real import: merges rules + ufw.conf policies, warns about bad tuple
	// and ENABLED=yes.
	e.DryRun = false
	out.Reset()
	if rc := e.cmdImportUFW(nil); rc != 0 {
		t.Fatalf("import-ufw rc = %d, err=%q", rc, errOut.String())
	}
	if !strings.Contains(out.String(), "Imported 1 ufw rule(s)") {
		t.Fatalf("stdout = %q", out.String())
	}
	st = loadState(t, e)
	if len(st.Rules4) != 1 || st.Rules4[0].Dst.Ports[0].Lo != 22 {
		t.Fatalf("rules = %+v", st.Rules4)
	}
	if st.Policies.Forward != "reject" || st.Logging != "high" {
		t.Errorf("policies/logging not migrated: %+v log=%q", st.Policies, st.Logging)
	}
	if !strings.Contains(errOut.String(), "bad action") ||
		!strings.Contains(errOut.String(), "ufw was enabled") {
		t.Errorf("stderr = %q, want malformed-tuple and enabled warnings", errOut.String())
	}
}

func TestImportUFWRefusesWithUfwChains(t *testing.T) {
	e, _, _, errOut := lifecycleEnv(t, "")
	e.Backend = &snapBackend{snap: &backend.Snapshot{
		Chains: []*nftables.Chain{{Name: "ufw-user-input"}},
	}}
	if rc := e.cmdImportUFW(nil); rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	if !strings.Contains(errOut.String(), "ufw chains are loaded") {
		t.Fatalf("stderr = %q", errOut.String())
	}
}

func TestImportUFWToleratesNilSnapshot(t *testing.T) {
	// A backend that cannot snapshot the kernel (ReadBack → nil, nil)
	// must not crash the foreign-chain check and must not block the
	// migration. fakeBackend.ReadBack already returns nil, nil.
	e, _, out, errOut := lifecycleEnv(t, "")

	ufwDir := filepath.Join(filepath.Dir(e.Store.Dir), "ufw")
	if err := os.MkdirAll(ufwDir, 0755); err != nil {
		t.Fatal(err)
	}
	user := `*filter
:ufw-user-input - [0:0]
### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in
### END RULES ###
COMMIT
`
	if err := os.WriteFile(filepath.Join(ufwDir, "user.rules"), []byte(user), 0644); err != nil {
		t.Fatal(err)
	}

	if rc := e.cmdImportUFW(nil); rc != 0 {
		t.Fatalf("import-ufw with nil ReadBack rc = %d, err=%q", rc, errOut.String())
	}
	if !strings.Contains(out.String(), "Imported 1 ufw rule(s)") {
		t.Fatalf("stdout = %q", out.String())
	}
	st := loadState(t, e)
	if len(st.Rules4) != 1 || st.Rules4[0].Dst.Ports[0].Lo != 22 {
		t.Fatalf("rules4 = %+v, want the imported 22/tcp rule", st.Rules4)
	}
}

// ---- sweep + commitState expiry --------------------------------------------

func TestSweep(t *testing.T) {
	e, _, out, _ := lifecycleEnv(t, "")
	exp := mkExtRule("allow", "in", "tcp", "any", "any", ports(22, "tcp"))
	exp.ExpiresAt = 1
	st := store.Defaults()
	st.Rules4 = []rule.Rule{*exp, *mkExtRule("deny", "in", "udp", "any", "any", ports(53, "udp"))}
	st.Bans = []store.ThreatBan{
		{Address: "203.0.113.1", Source: "crowdsec", ExpiresAt: 1},
		{Address: "203.0.113.2", Source: "crowdsec", ExpiresAt: time.Now().Add(time.Hour).Unix()},
	}
	if err := e.Store.Save(st); err != nil {
		t.Fatal(err)
	}
	if rc := e.cmdSweep(nil); rc != 0 {
		t.Fatalf("sweep rc = %d", rc)
	}
	if !strings.Contains(out.String(), "Removed 1 expired rule(s)") {
		t.Fatalf("stdout = %q", out.String())
	}
	st = loadState(t, e)
	if len(st.Rules4) != 1 || st.Rules4[0].Action != "deny" {
		t.Fatalf("rules4 = %+v", st.Rules4)
	}
	if !strings.Contains(out.String(), "1 expired threat ban(s)") {
		t.Fatalf("stdout = %q, want expired threat-ban count", out.String())
	}
	if len(st.Bans) != 1 || st.Bans[0].Address != "203.0.113.2" {
		t.Fatalf("threat bans after sweep = %+v, want only active address", st.Bans)
	}

	// Idempotent second run.
	out.Reset()
	if rc := e.cmdSweep(nil); rc != 0 || !strings.Contains(out.String(), "Removed 0 expired rule(s)") {
		t.Fatalf("rc=%d out=%q", rc, out.String())
	}
}
