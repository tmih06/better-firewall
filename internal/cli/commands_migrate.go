package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/tmih06/better-firewall/internal/impexp"
	"github.com/tmih06/better-firewall/internal/rule"
	"github.com/tmih06/better-firewall/internal/store"
)

var hookOutputCommand = func(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).Output()
}

type migrationOptions struct {
	source   string
	dir      string
	replace  bool
	takeover bool
}

// cmdMigrate imports one supported system firewall configuration into bfw's
// canonical state. It never stops the source manager unless --takeover is set.
func (e *Env) cmdMigrate(args []string) int {
	opts, err := parseMigrationOptions(args, e.Prog)
	if err != nil {
		return e.Errorf("%s", err)
	}
	sourceWasAuto := opts.source == "" || opts.source == "auto"
	if sourceWasAuto {
		opts.source, err = e.detectMigrationSource()
		if err != nil {
			return e.Errorf("%s", err)
		}
	}
	if opts.takeover && !sourceWasAuto {
		active, err := e.detectMigrationSource()
		if err != nil {
			return e.Errorf("%s", err)
		}
		if active != opts.source {
			return e.Errorf("refusing takeover of %s while %s is the only detected active manager", opts.source, active)
		}
	}

	var release func()
	if !e.DryRun {
		if !e.checkRoot() {
			return 1
		}
		var code int
		release, code = e.acquireLock()
		if code != 0 {
			return code
		}
		defer func() {
			if release != nil {
				release()
			}
		}()
	}
	if opts.takeover && !e.DryRun {
		active, err := e.detectMigrationSource()
		if err != nil {
			return e.Errorf("%s", err)
		}
		if active != opts.source {
			return e.Errorf("refusing takeover because detected active manager changed from %s to %s", opts.source, active)
		}
	}

	previous, err := e.Store.Load()
	if err != nil {
		return e.Errorf("%s", err)
	}
	base := cloneMigrationState(previous)
	var previousState *store.State
	var stateFileExists bool
	if opts.takeover {
		previousState = cloneMigrationState(previous)
		if !e.DryRun {
			if _, err := os.Stat(e.Store.RulesPath()); err == nil {
				stateFileExists = true
			} else if !os.IsNotExist(err) {
				return e.Errorf("%s", err)
			}
		}
	}
	if opts.replace {
		base = store.Defaults()
	}

	merged, count, warnings, err := e.importSystemFirewall(opts.source, opts.dir, base)
	for _, warning := range warnings {
		e.Warnf("%s", warning)
	}
	if err != nil {
		return e.Errorf("%s", err)
	}

	if e.DryRun {
		e.Msg("Would import %d rule(s) from %s", count, opts.source)
		for i := range merged.Rules4 {
			e.Msg("%s", impexpDescribeRule(&merged.Rules4[i], false))
		}
		for i := range merged.Rules6 {
			e.Msg("%s", impexpDescribeRule(&merged.Rules6[i], true))
		}
		if opts.takeover {
			e.Msg("Dry run: would stop and disable %s, then enable bfw", opts.source)
		} else {
			e.Msg("Dry run: the source firewall remains unchanged")
		}
		return 0
	}

	if opts.takeover && !e.Force && !e.Prompt("This will stop and disable %s, then enable bfw; networking may be interrupted. Proceed (y/n)? ", opts.source) {
		e.Msg("Aborted")
		return 0
	}
	if err := e.Store.Save(merged); err != nil {
		return e.Errorf("%s", err)
	}
	if opts.takeover {
		if err := stopMigrationSource(opts.source); err != nil {
			if restoreErr := restoreMigrationSource(opts.source); restoreErr != nil {
				e.Warnf("could not restore %s after stop failed: %v", opts.source, restoreErr)
			}
			e.restoreMigrationState(previousState, stateFileExists)
			return e.Errorf("could not stop %s: %v; bfw state was restored", opts.source, err)
		}
		if rc := e.enableMigratedFirewall(); rc != 0 {
			if err := restoreMigrationSource(opts.source); err != nil {
				e.Warnf("could not restore %s after bfw enable failed: %v", opts.source, err)
			}
			e.restoreMigrationState(previousState, stateFileExists)
			return rc
		}
		e.Msg("Imported %d rule(s) from %s; bfw is enabled and the source manager is disabled", count, opts.source)
		return 0
	}

	if rc := e.applyImportedState(merged); rc != 0 {
		return rc
	}
	e.Msg("Imported %d rule(s) from %s", count, opts.source)
	e.Msg("The source firewall remains active; review the migration, then use --takeover for a prompted service handoff")
	return 0
}

func parseMigrationOptions(args []string, prog string) (migrationOptions, error) {
	var opts migrationOptions
	skipNext := false
	for i := range args {
		if skipNext {
			skipNext = false
			continue
		}
		arg := args[i]
		switch {
		case arg == "--replace":
			opts.replace = true
		case arg == "--takeover":
			opts.takeover = true
		case arg == "--from" || arg == "--dir":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("%s requires a value", arg)
			}
			skipNext = true
			if arg == "--from" {
				opts.source = strings.ToLower(args[i+1])
			} else {
				opts.dir = args[i+1]
			}
		case strings.HasPrefix(arg, "--from="):
			opts.source = strings.ToLower(strings.TrimPrefix(arg, "--from="))
		case strings.HasPrefix(arg, "--dir="):
			opts.dir = strings.TrimPrefix(arg, "--dir=")
		default:
			return opts, fmt.Errorf("usage: %s migrate [--from auto|ufw|firewalld|iptables|nftables] [--dir DIR] [--replace] [--takeover]", prog)
		}
	}
	if opts.source != "" && opts.source != "auto" && opts.source != "ufw" && opts.source != "firewalld" && opts.source != "iptables" && opts.source != "nftables" {
		return opts, fmt.Errorf("unknown migration source %q (choose auto, ufw, firewalld, iptables, or nftables)", opts.source)
	}
	if opts.source == "nftables" && opts.dir != "" {
		return opts, fmt.Errorf("--dir is not supported for nftables; bfw reads the live ruleset using 'nft -j list ruleset'")
	}
	return opts, nil
}

// cloneMigrationState isolates the import candidate from the previous state so
// a failed takeover can restore the exact rules, policies, sets, and NAT data.
func cloneMigrationState(st *store.State) *store.State {
	out := *st
	out.Rules4 = cloneMigrationRules(st.Rules4)
	out.Rules6 = cloneMigrationRules(st.Rules6)
	out.Sets = append([]store.IPSet(nil), st.Sets...)
	for i := range out.Sets {
		out.Sets[i].Elements = append([]string(nil), st.Sets[i].Elements...)
	}
	out.NAT = append([]store.NATRule(nil), st.NAT...)
	out.Bans = append([]store.ThreatBan(nil), st.Bans...)
	return &out
}

func cloneMigrationRules(src []rule.Rule) []rule.Rule {
	if src == nil {
		return nil
	}
	out := append([]rule.Rule(nil), src...)
	for i := range out {
		out[i].Src.Ports = append([]rule.PortRange(nil), src[i].Src.Ports...)
		out[i].Dst.Ports = append([]rule.PortRange(nil), src[i].Dst.Ports...)
	}
	return out
}
func (e *Env) importSystemFirewall(source, dir string, base *store.State) (*store.State, int, []string, error) {
	etcDir := filepath.Dir(e.Store.Dir)
	switch source {
	case "ufw":
		if dir == "" {
			dir = filepath.Join(etcDir, "ufw")
		}
		return impexp.ImportUFW(dir, filepath.Join(filepath.Dir(dir), "default", "ufw"), base)
	case "firewalld":
		if dir == "" {
			dir = filepath.Join(etcDir, "firewalld")
		}
		return impexp.ImportFirewalld(dir, base)
	case "iptables":
		if dir == "" {
			dir = filepath.Join(etcDir, "iptables")
		}
		v4, err := optionalMigrationFile(filepath.Join(dir, "rules.v4"))
		if err != nil {
			return nil, 0, nil, err
		}
		v6, err := optionalMigrationFile(filepath.Join(dir, "rules.v6"))
		if err != nil {
			return nil, 0, nil, err
		}
		if v4 == nil && v6 == nil {
			return nil, 0, nil, fmt.Errorf("no iptables-persistent rules.v4 or rules.v6 files found in %s", dir)
		}
		return impexp.ImportIPTables(v4, v6, base)
	case "nftables":
		data, err := hookOutputCommand("nft", "-j", "list", "ruleset")
		if err != nil {
			return nil, 0, nil, fmt.Errorf("read live nftables ruleset: %w", err)
		}
		return impexp.ImportNFTables(bytes.NewReader(data), base)
	default:
		return nil, 0, nil, fmt.Errorf("unsupported migration source %q", source)
	}
}

func optionalMigrationFile(path string) (io.Reader, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return bytes.NewReader(data), nil
}

func (e *Env) detectMigrationSource() (string, error) {
	etcDir := filepath.Dir(e.Store.Dir)
	var active []string
	if ufwEnabled(filepath.Join(etcDir, "ufw", "ufw.conf")) {
		active = append(active, "ufw")
	}
	for _, candidate := range []struct{ source, unit string }{
		{"firewalld", "firewalld.service"},
		{"iptables", "netfilter-persistent.service"},
		{"nftables", "nftables.service"},
	} {
		if _, err := hookOutputCommand("systemctl", "is-active", "--quiet", candidate.unit); err == nil {
			active = append(active, candidate.source)
		}
	}
	switch len(active) {
	case 0:
		return "", fmt.Errorf("no active supported firewall manager detected; pass --from to import a saved configuration explicitly")
	case 1:
		return active[0], nil
	default:
		return "", fmt.Errorf("multiple firewall managers appear active (%s); pass --from to choose one, and check for conflicting rules", strings.Join(active, ", "))
	}
}

func ufwEnabled(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && strings.EqualFold(strings.TrimSpace(key), "ENABLED") && strings.EqualFold(strings.Trim(strings.TrimSpace(value), `"'`), "yes") {
			return true
		}
	}
	return false
}

func stopMigrationSource(source string) error {
	switch source {
	case "ufw":
		return hookRunCmd("ufw", "--force", "disable")
	case "firewalld":
		return hookRunCmd("systemctl", "disable", "--now", "firewalld.service")
	case "iptables":
		return hookRunCmd("systemctl", "disable", "--now", "netfilter-persistent.service")
	case "nftables":
		return hookRunCmd("systemctl", "disable", "--now", "nftables.service")
	default:
		return fmt.Errorf("unsupported migration source %q", source)
	}
}

func (e *Env) restoreMigrationState(previous *store.State, existed bool) {
	if existed {
		if err := e.Store.Save(previous); err != nil {
			e.Warnf("could not restore previous bfw state: %v", err)
		}
		return
	}
	if err := os.Remove(e.Store.RulesPath()); err != nil && !os.IsNotExist(err) {
		e.Warnf("could not remove failed migration state: %v", err)
	}
}

func restoreMigrationSource(source string) error {
	switch source {
	case "ufw":
		return hookRunCmd("ufw", "--force", "enable")
	case "firewalld":
		return hookRunCmd("systemctl", "enable", "--now", "firewalld.service")
	case "iptables":
		return hookRunCmd("systemctl", "enable", "--now", "netfilter-persistent.service")
	case "nftables":
		return hookRunCmd("systemctl", "enable", "--now", "nftables.service")
	default:
		return fmt.Errorf("unsupported migration source %q", source)
	}
}

func (e *Env) enableMigratedFirewall() int {
	if code := e.startFirewall(); code != 0 {
		return code
	}
	if code := e.persistEnabled(true); code != 0 {
		if stopCode := e.stopFirewall(); stopCode != 0 {
			e.Warnf("failed to remove bfw rules after persistence error")
		}
		return code
	}
	e.Msg("Firewall is active and enabled on system startup")
	return 0
}
