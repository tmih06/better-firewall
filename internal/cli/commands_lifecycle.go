// Lifecycle commands: enable, disable, reload, reset, default, logging,
// plus the hidden boot-load/boot-unload used by the systemd unit.
// Semantics mirror ufw 0.36.2 (frontend.py / backend_iptables.py /
// ufw-init-functions); deviations are noted inline.
package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	nftbe "bfirewall/internal/backend/nft"
	"bfirewall/internal/store"
	"bfirewall/internal/sysstate"
)

// Indirections so tests can stub the process/system boundary.
var (
	hookGeteuid  = os.Geteuid
	hookUnderSSH = sysstate.UnderSSH
	hookLockFile = sysstate.LockFile
	hookLookPath = exec.LookPath
	hookRunCmd   = func(name string, args ...string) error {
		return exec.Command(name, args...).Run()
	}
)

// checkRoot enforces ufw's "You need to be root to run this script".
func (e *Env) checkRoot() bool {
	if hookGeteuid() != 0 {
		e.Errorf("You need to be root to run this script")
		return false
	}
	return true
}

// acquireLock takes the mutating-command flock: /run/bfw.lock, falling back
// to <state dir>/bfw.lock when /run is not writable (ufw falls back for
// non-root/TESTSTATE; we probe writability instead).
func (e *Env) acquireLock() (func(), int) {
	path := "/run/bfw.lock"
	if !dirWritable("/run") {
		path = filepath.Join(e.Store.Dir, "bfw.lock")
	}
	f, err := hookLockFile(path)
	if err != nil {
		return nil, e.Errorf("Could not acquire lock '%s': %v", path, err)
	}
	return func() { f.Close() }, 0
}

func dirWritable(dir string) bool {
	f, err := os.CreateTemp(dir, ".bfw-wtest")
	if err != nil {
		return false
	}
	f.Close()
	os.Remove(f.Name())
	return true
}

// runInitHook executes <dir>/<name>.init <arg> when present and executable
// (ufw before.init/after.init parity). Failures warn, never abort.
func (e *Env) runInitHook(name, arg string) {
	p := e.Store.InitPath(name)
	fi, err := os.Stat(p)
	if err != nil || fi.IsDir() || fi.Mode()&0111 == 0 {
		return
	}
	if err := hookRunCmd(p, arg); err != nil {
		e.Warnf("'%s %s' exited with error", p, arg)
	}
}

// applyRuleset performs the enable-time apply sequence (ufw-init start):
// compile+apply core ruleset, then before*/after* fragments, sysctl file,
// kernel modules. In dry-run mode it prints the rendered ruleset and the
// sysctl/module notes without touching the kernel.
func (e *Env) applyRuleset(st *store.State, etc map[string]string) int {
	b, err := e.backend()
	if err != nil {
		return e.Errorf("%v", err)
	}

	if e.DryRun {
		txt, err := nftbe.RenderText(st, etc)
		if err != nil {
			return e.Errorf("%v", err)
		}
		e.Msg("%s", strings.TrimRight(txt, "\n"))
		e.Msg("### sysctl ###")
		if p := etc["IPT_SYSCTL"]; p != "" {
			if data, err := os.ReadFile(p); err == nil {
				e.Msg("%s", strings.TrimRight(string(data), "\n"))
			}
		}
		if m := strings.TrimSpace(etc["IPT_MODULES"]); m != "" {
			e.Msg("### modprobe %s ###", m)
		}
		return 0
	}

	e.runInitHook("before", "start")

	if err := b.Apply(st, etc); err != nil {
		return e.Errorf("%v", err)
	}

	// Fragments apply in a second transaction (nft -c checked inside the
	// backend). On failure, roll back the core ruleset like ufw's abort.
	for _, name := range []string{"before", "before6", "after", "after6"} {
		p := e.Store.FragmentPath(name)
		if _, err := os.Stat(p); err != nil {
			continue
		}
		if err := b.ApplyFragments(p); err != nil {
			e.Warnf("applying '%s' failed: %v", p, err)
			b.Flush()
			return e.Errorf("Failed to apply firewall fragments")
		}
	}

	// sysctl -e -q -p $IPT_SYSCTL: errors are ignored by ufw; warn on ours.
	if p := etc["IPT_SYSCTL"]; p != "" {
		if fi, err := os.Stat(p); err == nil && fi.Size() > 0 {
			if err := sysstate.ApplySysctlFile(p); err != nil {
				e.Warnf("applying sysctl file '%s': %v", p, err)
			}
		}
	}

	// modprobe each IPT_MODULES entry; failures warn, never abort.
	for _, err := range sysstate.Modprobe(etc["IPT_MODULES"]) {
		e.Warnf("%v", err)
	}

	e.runInitHook("after", "start")
	return 0
}

// startFirewall is the shared enable path (cmdEnable, cmdReload,
// cmdBootLoad): apply the stored ruleset. It does not print the final
// success message and does not prompt.
func (e *Env) startFirewall() int {
	st, err := e.Store.Load()
	if err != nil {
		return e.Errorf("%v", err)
	}
	etc, err := e.Store.EtcDefaults()
	if err != nil {
		return e.Errorf("%v", err)
	}
	return e.applyRuleset(st, etc)
}

// stopFirewall is the shared flush path (cmdDisable, cmdReload, cmdReset,
// cmdBootUnload): init hooks + Flush. No conf/systemctl changes.
func (e *Env) stopFirewall() int {
	b, err := e.backend()
	if err != nil {
		return e.Errorf("%v", err)
	}

	if e.DryRun {
		e.Msg("> flushing firewall tables")
		return 0
	}

	e.runInitHook("before", "stop")

	if err := b.Flush(); err != nil {
		return e.Errorf("%v", err)
	}

	e.runInitHook("after", "stop")
	return 0
}

// persistEnabled writes ENABLED=yes/no to bfw.conf and enables/disables the
// systemd unit. Boot persistence failures warn, never abort.
func (e *Env) persistEnabled(enabled bool) int {
	conf, err := e.Store.LoadConf()
	if err != nil {
		return e.Errorf("%v", err)
	}
	conf.Enabled = enabled
	if enabled && !validLogLevel(conf.LogLevel) {
		conf.LogLevel = "low"
	}
	if err := e.Store.SaveConf(conf); err != nil {
		return e.Errorf("%v", err)
	}

	if _, err := hookLookPath("systemctl"); err != nil {
		if enabled {
			e.Warnf("systemctl not found; firewall is active but boot persistence needs init integration")
		}
		return 0
	}
	verb := "disable"
	if enabled {
		verb = "enable"
	}
	if err := hookRunCmd("systemctl", verb, "bfirewall.service"); err != nil && enabled {
		e.Warnf("could not enable bfirewall.service; firewall will not persist across reboot")
	}
	return 0
}

func (e *Env) cmdEnable(args []string) int {
	if len(args) != 0 {
		e.Msg("%s", HelpText(e.Prog))
		return 1
	}
	if !e.checkRoot() {
		return 1
	}
	release, rc := e.acquireLock()
	if release == nil {
		return rc
	}
	defer release()

	b, err := e.backend()
	if err != nil {
		return e.Errorf("%v", err)
	}
	loaded, err := b.Loaded()
	if err != nil {
		return e.Errorf("%v", err)
	}
	if loaded {
		e.Msg("Firewall already started, use 'force-reload'")
		return 0
	}

	if !e.Force && hookUnderSSH() {
		if !e.Prompt("Command may disrupt existing ssh connections. Proceed with operation (y|n)? ") {
			e.Msg("Aborted")
			return 0
		}
	}

	if rc := e.startFirewall(); rc != 0 {
		return rc
	}
	if !e.DryRun {
		if rc := e.persistEnabled(true); rc != 0 {
			return rc
		}
	}
	e.Msg("Firewall is active and enabled on system startup")
	return 0
}

func (e *Env) cmdDisable(args []string) int {
	if len(args) != 0 {
		e.Msg("%s", HelpText(e.Prog))
		return 1
	}
	if !e.checkRoot() {
		return 1
	}
	release, rc := e.acquireLock()
	if release == nil {
		return rc
	}
	defer release()

	if rc := e.stopFirewall(); rc != 0 {
		return rc
	}
	if !e.DryRun {
		if rc := e.persistEnabled(false); rc != 0 {
			return rc
		}
	}
	e.Msg("Firewall stopped and disabled on system startup")
	return 0
}

func (e *Env) cmdReload(args []string) int {
	if len(args) != 0 {
		e.Msg("%s", HelpText(e.Prog))
		return 1
	}
	if !e.checkRoot() {
		return 1
	}
	release, rc := e.acquireLock()
	if release == nil {
		return rc
	}
	defer release()

	conf, err := e.Store.LoadConf()
	if err != nil {
		return e.Errorf("%v", err)
	}
	if !conf.Enabled {
		e.Msg("Firewall not enabled (skipping reload)")
		return 0
	}
	if rc := e.stopFirewall(); rc != 0 {
		return rc
	}
	if rc := e.startFirewall(); rc != 0 {
		return rc
	}
	if !e.DryRun {
		if rc := e.persistEnabled(true); rc != 0 {
			return rc
		}
	}
	e.Msg("Firewall reloaded")
	return 0
}

func (e *Env) cmdReset(args []string) int {
	if len(args) != 0 {
		e.Msg("%s", HelpText(e.Prog))
		return 1
	}
	if !e.checkRoot() {
		return 1
	}
	release, rc := e.acquireLock()
	if release == nil {
		return rc
	}
	defer release()

	if !e.Force {
		prompt := "Resetting all rules to installed defaults. Proceed with operation (y|n)? "
		if hookUnderSSH() {
			prompt = "Resetting all rules to installed defaults. This may disrupt existing ssh connections. Proceed with operation (y|n)? "
		}
		if !e.Prompt("%s", prompt) {
			e.Msg("Aborted")
			return 0
		}
	}

	conf, err := e.Store.LoadConf()
	if err != nil {
		return e.Errorf("%v", err)
	}
	if conf.Enabled && !e.DryRun {
		if rc := e.stopFirewall(); rc != 0 {
			return rc
		}
	}

	// Back up rules.json and every existing *.rules fragment to
	// <file>.<YYYYMMDD_HHMMSS> (ufw reset parity: refuse if a backup name
	// already exists).
	ext := time.Now().Format("20060102_150405")
	var files []string
	if _, err := os.Stat(e.Store.RulesPath()); err == nil {
		files = append(files, e.Store.RulesPath())
	}
	for _, name := range []string{"before", "before6", "after", "after6"} {
		p := e.Store.FragmentPath(name)
		if _, err := os.Stat(p); err == nil {
			files = append(files, p)
		}
	}
	for _, f := range files {
		if _, err := os.Stat(f + "." + ext); err == nil {
			return e.Errorf("'%s' already exists. Aborting", f+"."+ext)
		}
	}
	for _, f := range files {
		dst := f + "." + ext
		e.Msg("Backing up '%s' to '%s'", filepath.Base(f), dst)
		if !e.DryRun {
			if err := os.Rename(f, dst); err != nil {
				return e.Errorf("%v", err)
			}
		}
	}

	if !e.DryRun {
		if err := e.Store.Save(store.Defaults()); err != nil {
			return e.Errorf("%v", err)
		}
		conf.Enabled = false
		if err := e.Store.SaveConf(conf); err != nil {
			return e.Errorf("%v", err)
		}
	}
	return 0
}

func (e *Env) cmdDefault(args []string) int {
	if len(args) < 1 {
		e.Msg("%s", HelpText(e.Prog))
		return 1
	}
	policy := strings.ToLower(args[0])
	if policy != "allow" && policy != "deny" && policy != "reject" {
		e.Msg("%s", HelpText(e.Prog))
		return 1
	}
	dir := ""
	if len(args) > 1 {
		dir = strings.ToLower(args[1])
	}
	var chain string
	switch dir {
	case "incoming", "input":
		dir, chain = "incoming", "INPUT"
	case "outgoing", "output":
		dir, chain = "outgoing", "OUTPUT"
	case "routed", "forward":
		dir, chain = "routed", "FORWARD"
	default:
		// ufw requires the direction; missing → "Invalid direction ''".
		return e.Errorf("Invalid direction '%s'", dir)
	}
	if len(args) > 2 {
		e.Msg("%s", HelpText(e.Prog))
		return 1
	}
	if !e.checkRoot() {
		return 1
	}
	release, rc := e.acquireLock()
	if release == nil {
		return rc
	}
	defer release()

	if !e.DryRun {
		st, err := e.Store.Load()
		if err != nil {
			return e.Errorf("%v", err)
		}
		switch chain {
		case "INPUT":
			st.Policies.Input = policy
		case "OUTPUT":
			st.Policies.Output = policy
		case "FORWARD":
			st.Policies.Forward = policy
		}
		if err := e.Store.Save(st); err != nil {
			return e.Errorf("%v", err)
		}
		if err := e.Store.WriteEtcDefault("DEFAULT_"+chain+"_POLICY", policyTarget(policy)); err != nil {
			return e.Errorf("%v", err)
		}

		conf, err := e.Store.LoadConf()
		if err != nil {
			return e.Errorf("%v", err)
		}
		if conf.Enabled {
			etc, err := e.Store.EtcDefaults()
			if err != nil {
				return e.Errorf("%v", err)
			}
			if rc := e.applyRuleset(st, etc); rc != 0 {
				return rc
			}
		}
	}

	e.Msg("Default %s policy changed to '%s'\n(be sure to update your rules accordingly)", dir, policy)
	return 0
}

// policyTarget maps a CLI policy word to the /etc/default value ufw writes
// (iptables target names).
func policyTarget(policy string) string {
	switch policy {
	case "allow":
		return "ACCEPT"
	case "deny":
		return "DROP"
	case "reject":
		return "REJECT"
	}
	return strings.ToUpper(policy)
}

func validLogLevel(l string) bool {
	switch l {
	case "off", "low", "medium", "high", "full":
		return true
	}
	return false
}
func (e *Env) cmdLogging(args []string) int {
	if len(args) != 1 {
		e.Msg("%s", HelpText(e.Prog))
		return 1
	}
	level := strings.ToLower(args[0])
	if level != "on" && !validLogLevel(level) {
		e.Msg("%s", HelpText(e.Prog))
		return 1
	}
	if !e.checkRoot() {
		return 1
	}
	release, rc := e.acquireLock()
	if release == nil {
		return rc
	}
	defer release()

	conf, err := e.Store.LoadConf()
	if err != nil {
		return e.Errorf("%v", err)
	}

	st, err := e.Store.Load()
	if err != nil {
		return e.Errorf("%v", err)
	}

	// 'on' keeps the current level unless logging is off/unset (ufw
	// set_loglevel parity).
	newLevel := level
	if level == "on" {
		newLevel = "low"
		if validLogLevel(st.Logging) && st.Logging != "off" {
			newLevel = st.Logging
		} else if validLogLevel(conf.LogLevel) && conf.LogLevel != "off" {
			newLevel = conf.LogLevel
		}
	}

	if !e.DryRun {
		st.Logging = newLevel
		if err := e.Store.Save(st); err != nil {
			return e.Errorf("%v", err)
		}
		conf.LogLevel = newLevel
		if err := e.Store.SaveConf(conf); err != nil {
			return e.Errorf("%v", err)
		}
		if conf.Enabled {
			etc, err := e.Store.EtcDefaults()
			if err != nil {
				return e.Errorf("%v", err)
			}
			if rc := e.applyRuleset(st, etc); rc != 0 {
				return rc
			}
		}
	}

	if newLevel == "off" {
		e.Msg("Logging disabled")
	} else {
		e.Msg("Logging enabled")
	}
	return 0
}

// cmdBootLoad applies the stored ruleset when the firewall is enabled.
// Used by the systemd unit: no ENABLED flip, no prompt, no systemctl.
func (e *Env) cmdBootLoad(args []string) int {
	if len(args) != 0 {
		e.Msg("%s", HelpText(e.Prog))
		return 1
	}
	if !e.checkRoot() {
		return 1
	}
	release, rc := e.acquireLock()
	if release == nil {
		return rc
	}
	defer release()

	conf, err := e.Store.LoadConf()
	if err != nil {
		return e.Errorf("%v", err)
	}
	if !conf.Enabled {
		return 0
	}
	return e.startFirewall()
}

// cmdBootUnload flushes the managed tables (systemd ExecStop).
func (e *Env) cmdBootUnload(args []string) int {
	if len(args) != 0 {
		e.Msg("%s", HelpText(e.Prog))
		return 1
	}
	if !e.checkRoot() {
		return 1
	}
	release, rc := e.acquireLock()
	if release == nil {
		return rc
	}
	defer release()

	return e.stopFirewall()
}
