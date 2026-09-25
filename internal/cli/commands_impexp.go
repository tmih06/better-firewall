package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/tmih06/better-firewall/internal/impexp"
	"github.com/tmih06/better-firewall/internal/rule"
	"github.com/tmih06/better-firewall/internal/store"
)

// cmdExport implements `export [FILE]` — JSON state document to FILE or
// stdout (default, also "-").
func (e *Env) cmdExport(args []string) int {
	if len(args) > 1 {
		return e.Errorf("usage: %s export [FILE]", e.Prog)
	}
	st, err := e.Store.Load()
	if err != nil {
		return e.Errorf("%s", err)
	}
	if len(args) == 0 || args[0] == "-" {
		if err := impexp.Export(st, e.Stdout); err != nil {
			return e.Errorf("%s", err)
		}
		return 0
	}
	f, err := os.Create(args[0])
	if err != nil {
		return e.Errorf("%s", err)
	}
	if err := impexp.Export(st, f); err != nil {
		f.Close()
		return e.Errorf("%s", err)
	}
	if err := f.Close(); err != nil {
		return e.Errorf("%s", err)
	}
	return 0
}

// cmdImport implements `import [--replace] FILE` — merges an export
// document into the stored state ("-" reads stdin).
func (e *Env) cmdImport(args []string) int {
	replace := false
	var file string
	for _, a := range args {
		if a == "--replace" {
			replace = true
		} else if file == "" {
			file = a
		} else {
			return e.Errorf("usage: %s import [--replace] FILE", e.Prog)
		}
	}
	if file == "" {
		return e.Errorf("usage: %s import [--replace] FILE", e.Prog)
	}
	if !e.checkRoot() {
		return 1
	}
	unlock, code := e.acquireLock()
	if code != 0 {
		return code
	}
	defer unlock()

	var data []byte
	var err error
	if file == "-" {
		data, err = io.ReadAll(e.Stdin)
	} else {
		data, err = os.ReadFile(file)
	}
	if err != nil {
		return e.Errorf("%s", err)
	}

	st, err := e.Store.Load()
	if err != nil {
		return e.Errorf("%s", err)
	}
	merged, n, err := impexp.Import(bytes.NewReader(data), st, replace)
	if err != nil {
		return e.Errorf("%s", err)
	}
	if e.DryRun {
		e.Msg("Would import %d rule(s)", n)
		return 0
	}
	if err := e.Store.Save(merged); err != nil {
		return e.Errorf("%s", err)
	}
	e.Msg("Imported %d rule(s)", n)
	return e.applyImportedState(merged)
}

// cmdImportUFW implements `import-ufw [--dir DIR]` — migrates a ufw
// installation's user.rules/user6.rules, /etc/default/ufw policies, and
// ufw.conf into the better-firewall state.
func (e *Env) cmdImportUFW(args []string) int {
	dir := ""
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--dir" && i+1 < len(args):
			i++
			dir = args[i]
		case strings.HasPrefix(args[i], "--dir="):
			dir = strings.TrimPrefix(args[i], "--dir=")
		default:
			return e.Errorf("usage: %s import-ufw [--dir DIR]", e.Prog)
		}
	}
	if dir == "" {
		// Derive <prefix>/etc/ufw from the store dir (<prefix>/etc/better-firewall)
		// so BFW_PREFIX-rooted test trees work too.
		dir = filepath.Join(filepath.Dir(e.Store.Dir), "ufw")
	}
	etcFile := filepath.Join(filepath.Dir(dir), "default", "ufw")
	if !e.checkRoot() {
		return 1
	}
	unlock, code := e.acquireLock()
	if code != 0 {
		return code
	}
	defer unlock()

	// Refuse while ufw chains are loaded in the kernel.
	b, err := e.backend()
	if err != nil {
		return e.Errorf("%s", err)
	}
	snap, err := b.ReadBack()
	if err != nil {
		return e.Errorf("%s", err)
	}
	if snap != nil {
		if fc := snap.ForeignChains("ufw-"); len(fc) > 0 {
			return e.Errorf("ufw chains are loaded; run 'ufw disable' first")
		}
	}

	if e.DryRun {
		merged, _, warnings, err := impexp.ImportUFW(dir, etcFile, store.Defaults())
		if err != nil {
			return e.Errorf("%s", err)
		}
		for _, r := range merged.Rules4 {
			e.Msg("%s", impexpDescribeRule(&r, false))
		}
		for _, r := range merged.Rules6 {
			e.Msg("%s", impexpDescribeRule(&r, true))
		}
		e.Msg("Would import %d ufw rule(s)", len(merged.Rules4)+len(merged.Rules6))
		for _, w := range warnings {
			e.Warnf("%s", w)
		}
		return 0
	}

	st, err := e.Store.Load()
	if err != nil {
		return e.Errorf("%s", err)
	}
	merged, n, warnings, err := impexp.ImportUFW(dir, etcFile, st)
	if err != nil {
		return e.Errorf("%s", err)
	}
	for _, w := range warnings {
		e.Warnf("%s", w)
	}
	if err := e.Store.Save(merged); err != nil {
		return e.Errorf("%s", err)
	}
	e.Msg("Imported %d ufw rule(s)", n)
	return e.applyImportedState(merged)
}

// applyImportedState reapplies the kernel ruleset when the firewall is
// enabled; a no-op (exit 0) otherwise.
func (e *Env) applyImportedState(st *store.State) int {
	conf, err := e.Store.LoadConf()
	if err != nil {
		return e.Errorf("%s", err)
	}
	if !conf.Enabled {
		return 0
	}
	etc, err := e.Store.EtcDefaults()
	if err != nil {
		e.Warnf("%s", err)
	}
	return e.applyRuleset(st, etc)
}

// impexpDescribeRule renders a parsed rule for dry-run output.
func impexpDescribeRule(r *rule.Rule, v6 bool) string {
	fam := "v4"
	if v6 {
		fam = "v6"
	}
	s := fmt.Sprintf("[%s] %s %s", fam, r.Action, r.Direction)
	if r.IfaceIn != "" {
		s += " in on " + r.IfaceIn
	}
	if r.IfaceOut != "" {
		s += " out on " + r.IfaceOut
	}
	if r.Log != "" {
		s += " " + r.Log
	}
	s += fmt.Sprintf(" proto %s from %s to %s", r.Proto, impexpDescribeAddr(&r.Src), impexpDescribeAddr(&r.Dst))
	if r.Dapp != "" {
		s += " dapp " + r.Dapp
	}
	if r.Sapp != "" {
		s += " sapp " + r.Sapp
	}
	if r.Comment != "" {
		s += " comment '" + r.Comment + "'"
	}
	return s
}

func impexpDescribeAddr(a *rule.AddrSpec) string {
	s := a.IP
	if s == "" {
		s = "any"
	}
	var ps []string
	for _, p := range a.Ports {
		ps = append(ps, p.String())
	}
	if len(ps) > 0 {
		s += " " + strings.Join(ps, ",")
	}
	return s
}
