package cli

import (
	"errors"
	"github.com/tmih06/better-firewall/internal/rule"
	"github.com/tmih06/better-firewall/internal/store"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigrateImportsUFWAndKeepsSourceActiveByDefault(t *testing.T) {
	e, _, out, _ := lifecycleEnv(t, "")
	etcDir := filepath.Join(t.TempDir(), "etc")
	e.Store.Dir = filepath.Join(etcDir, "better-firewall")
	e.Store.EtcFile = filepath.Join(etcDir, "default", "better-firewall")
	ufwDir := filepath.Join(etcDir, "ufw")
	if err := os.MkdirAll(ufwDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ufwDir, "user.rules"), []byte("### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if rc := e.cmdMigrate([]string{"--from", "ufw", "--replace"}); rc != 0 {
		t.Fatalf("migrate rc = %d, stderr = %q", rc, e.Stderr.(*strings.Builder).String())
	}
	st, err := e.Store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Rules4) != 1 || st.Rules4[0].Action != "allow" || len(st.Rules4[0].Dst.Ports) != 1 || st.Rules4[0].Dst.Ports[0].Lo != 22 {
		t.Fatalf("imported rules = %+v, want one allow-22 rule", st.Rules4)
	}
	if !strings.Contains(out.String(), "source firewall remains active") {
		t.Fatalf("output should make the non-takeover behavior explicit: %q", out.String())
	}
}

func TestMigrateDryRunDoesNotPersist(t *testing.T) {
	e, _, out, _ := lifecycleEnv(t, "")
	e.DryRun = true
	etcDir := filepath.Join(t.TempDir(), "etc")
	e.Store.Dir = filepath.Join(etcDir, "better-firewall")
	e.Store.EtcFile = filepath.Join(etcDir, "default", "better-firewall")
	ufwDir := filepath.Join(etcDir, "ufw")
	if err := os.MkdirAll(ufwDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ufwDir, "user.rules"), []byte("### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if rc := e.cmdMigrate([]string{"--from", "ufw", "--replace"}); rc != 0 {
		t.Fatalf("dry-run rc = %d, stderr = %q", rc, e.Stderr.(*strings.Builder).String())
	}
	if _, err := os.Stat(e.Store.RulesPath()); !os.IsNotExist(err) {
		t.Fatalf("dry-run created state file: stat err = %v", err)
	}
	if !strings.Contains(out.String(), "Would import 1 rule(s) from ufw") {
		t.Fatalf("preview missing imported rule count: %q", out.String())
	}
}

func TestMigrateTakeoverRestoresUFWWhenBfwApplyFails(t *testing.T) {
	e, fb, _, errOut := lifecycleEnv(t, "")
	fb.applyErr = errors.New("synthetic backend failure")
	e.Force = true
	etcDir := filepath.Join(t.TempDir(), "etc")
	e.Store.Dir = filepath.Join(etcDir, "better-firewall")
	e.Store.EtcFile = filepath.Join(etcDir, "default", "better-firewall")
	prior := store.Defaults()
	prior.Rules4 = []rule.Rule{{
		ID: "prior", Action: rule.ActionAllow, Direction: rule.DirIn, Proto: "tcp",
		Src: rule.AddrSpec{IP: "any"},
		Dst: rule.AddrSpec{IP: "any", Ports: []rule.PortRange{{Lo: 443, Hi: 443, Proto: "tcp"}}},
	}}
	if err := e.Store.Save(prior); err != nil {
		t.Fatal(err)
	}
	ufwDir := filepath.Join(etcDir, "ufw")
	if err := os.MkdirAll(ufwDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ufwDir, "user.rules"), []byte("### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ufwDir, "ufw.conf"), []byte("ENABLED=yes\n"), 0644); err != nil {
		t.Fatal(err)
	}
	oldOutput := hookOutputCommand
	hookOutputCommand = func(string, ...string) ([]byte, error) { return nil, os.ErrNotExist }
	t.Cleanup(func() { hookOutputCommand = oldOutput })
	var commands []string
	hookRunCmd = func(name string, args ...string) error {
		commands = append(commands, name+" "+strings.Join(args, " "))
		return nil
	}

	if rc := e.cmdMigrate([]string{"--from", "ufw", "--replace", "--takeover"}); rc == 0 {
		t.Fatal("migrate succeeded despite bfw apply failure")
	}
	if len(commands) != 2 || commands[0] != "ufw --force disable" || commands[1] != "ufw --force enable" {
		t.Fatalf("source service commands = %v, want disable then restore", commands)
	}
	if !strings.Contains(errOut.String(), "synthetic backend failure") {
		t.Fatalf("stderr does not report bfw failure: %q", errOut.String())
	}
	restored, err := e.Store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(restored.Rules4) != 1 || restored.Rules4[0].ID != "prior" || restored.Rules4[0].Dst.Ports[0].Lo != 443 {
		t.Fatalf("failed takeover did not restore previous bfw state: %+v", restored.Rules4)
	}
	conf, err := e.Store.LoadConf()
	if err != nil {
		t.Fatal(err)
	}
	if conf.Enabled {
		t.Fatal("failed bfw apply persisted ENABLED=yes")
	}
}

func TestMigrateTakeoverEnablesBfwAfterStoppingUFW(t *testing.T) {
	e, fb, out, _ := lifecycleEnv(t, "")
	e.Force = true
	etcDir := filepath.Join(t.TempDir(), "etc")
	e.Store.Dir = filepath.Join(etcDir, "better-firewall")
	e.Store.EtcFile = filepath.Join(etcDir, "default", "better-firewall")
	ufwDir := filepath.Join(etcDir, "ufw")
	if err := os.MkdirAll(ufwDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ufwDir, "user.rules"), []byte("### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ufwDir, "ufw.conf"), []byte("ENABLED=yes\n"), 0644); err != nil {
		t.Fatal(err)
	}
	oldOutput := hookOutputCommand
	hookOutputCommand = func(string, ...string) ([]byte, error) { return nil, os.ErrNotExist }
	t.Cleanup(func() { hookOutputCommand = oldOutput })
	hookLookPath = func(string) (string, error) { return "/fake/systemctl", nil }
	var commands []string
	hookRunCmd = func(name string, args ...string) error {
		commands = append(commands, name+" "+strings.Join(args, " "))
		return nil
	}

	if rc := e.cmdMigrate([]string{"--from", "ufw", "--replace", "--takeover"}); rc != 0 {
		t.Fatalf("migrate rc = %d, stderr = %q", rc, e.Stderr.(*strings.Builder).String())
	}
	if fb.applies != 1 {
		t.Fatalf("bfw applied %d times, want one apply", fb.applies)
	}
	if len(commands) != 2 || commands[0] != "ufw --force disable" || commands[1] != "systemctl enable better-firewall.service" {
		t.Fatalf("handoff commands = %v", commands)
	}
	conf, err := e.Store.LoadConf()
	if err != nil {
		t.Fatal(err)
	}
	if !conf.Enabled {
		t.Fatal("successful takeover did not persist ENABLED=yes")
	}
	if !strings.Contains(out.String(), "bfw is enabled and the source manager is disabled") {
		t.Fatalf("success output does not confirm handoff: %q", out.String())
	}
}
func TestMigrateTakeoverRejectsMultipleActiveManagers(t *testing.T) {
	e, _, _, errOut := lifecycleEnv(t, "")
	etcDir := filepath.Join(t.TempDir(), "etc")
	e.Store.Dir = filepath.Join(etcDir, "better-firewall")
	ufwDir := filepath.Join(etcDir, "ufw")
	if err := os.MkdirAll(ufwDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ufwDir, "ufw.conf"), []byte("ENABLED=yes\n"), 0644); err != nil {
		t.Fatal(err)
	}
	oldOutput := hookOutputCommand
	hookOutputCommand = func(_ string, args ...string) ([]byte, error) {
		if args[len(args)-1] == "firewalld.service" {
			return nil, nil
		}
		return nil, os.ErrNotExist
	}
	t.Cleanup(func() { hookOutputCommand = oldOutput })
	var commands []string
	hookRunCmd = func(name string, args ...string) error {
		commands = append(commands, name+" "+strings.Join(args, " "))
		return nil
	}

	if rc := e.cmdMigrate([]string{"--from", "ufw", "--takeover"}); rc == 0 {
		t.Fatal("takeover proceeded with multiple active managers")
	}
	if !strings.Contains(errOut.String(), "multiple firewall managers") {
		t.Fatalf("stderr does not identify ambiguous managers: %q", errOut.String())
	}
	if len(commands) != 0 {
		t.Fatalf("takeover changed services before resolving ambiguity: %v", commands)
	}
	if _, err := os.Stat(e.Store.RulesPath()); !os.IsNotExist(err) {
		t.Fatalf("ambiguous takeover persisted state: stat err = %v", err)
	}
}
func TestMigrateTakeoverRechecksSourceAfterLock(t *testing.T) {
	e, _, _, errOut := lifecycleEnv(t, "")
	etcDir := filepath.Join(t.TempDir(), "etc")
	e.Store.Dir = filepath.Join(etcDir, "better-firewall")
	ufwDir := filepath.Join(etcDir, "ufw")
	if err := os.MkdirAll(ufwDir, 0755); err != nil {
		t.Fatal(err)
	}
	confPath := filepath.Join(ufwDir, "ufw.conf")
	if err := os.WriteFile(confPath, []byte("ENABLED=yes\n"), 0644); err != nil {
		t.Fatal(err)
	}
	oldOutput := hookOutputCommand
	hookOutputCommand = func(string, ...string) ([]byte, error) { return nil, os.ErrNotExist }
	t.Cleanup(func() { hookOutputCommand = oldOutput })
	hookLockFile = func(string) (*os.File, error) {
		if err := os.WriteFile(confPath, []byte("ENABLED=no\n"), 0644); err != nil {
			return nil, err
		}
		return os.CreateTemp(t.TempDir(), "lock")
	}
	var commands []string
	hookRunCmd = func(name string, args ...string) error {
		commands = append(commands, name+" "+strings.Join(args, " "))
		return nil
	}

	if rc := e.cmdMigrate([]string{"--from", "ufw", "--takeover"}); rc == 0 {
		t.Fatal("takeover proceeded after UFW became inactive")
	}
	if !strings.Contains(errOut.String(), "no active supported firewall manager") {
		t.Fatalf("stderr does not report changed source state: %q", errOut.String())
	}
	if len(commands) != 0 {
		t.Fatalf("takeover ran manager commands after source changed: %v", commands)
	}
	if _, err := os.Stat(e.Store.RulesPath()); !os.IsNotExist(err) {
		t.Fatalf("changed-source takeover persisted state: stat err = %v", err)
	}
}

func TestMigrateReportsWarningsWhenImportFails(t *testing.T) {
	e, _, _, errOut := lifecycleEnv(t, "")
	etcDir := filepath.Join(t.TempDir(), "etc")
	e.Store.Dir = filepath.Join(etcDir, "better-firewall")
	ufwDir := filepath.Join(etcDir, "ufw")
	if err := os.MkdirAll(ufwDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ufwDir, "user.rules"),
		[]byte("### tuple ### bogus tcp 22 0.0.0.0/0 any 0.0.0.0/0 in\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if rc := e.cmdMigrate([]string{"--from", "ufw"}); rc == 0 {
		t.Fatal("migration succeeded without any parseable rules")
	}
	if !strings.Contains(errOut.String(), "bad action") {
		t.Fatalf("stderr omits malformed tuple warning: %q", errOut.String())
	}
	if !strings.Contains(errOut.String(), "no ufw rules found") {
		t.Fatalf("stderr omits import error: %q", errOut.String())
	}
	if _, err := os.Stat(e.Store.RulesPath()); !os.IsNotExist(err) {
		t.Fatalf("failed import persisted state: stat err = %v", err)
	}
}

func TestParseMigrationOptions(t *testing.T) {
	opts, err := parseMigrationOptions([]string{"--from", "FIREWALLD", "--dir=/tmp/firewall data", "--replace", "--takeover"}, "bfw")
	if err != nil {
		t.Fatal(err)
	}
	if opts.source != "firewalld" || opts.dir != "/tmp/firewall data" || !opts.replace || !opts.takeover {
		t.Fatalf("parsed options = %+v", opts)
	}
	if _, err := parseMigrationOptions([]string{"--from", "unsupported"}, "bfw"); err == nil {
		t.Fatal("unsupported source was accepted")
	}
}
