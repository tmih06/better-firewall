package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"bfirewall/internal/backend"
	"bfirewall/internal/store"
)

// fakeBackend records lifecycle calls; Apply/Flush/Loaded are the only
// methods the lifecycle commands exercise.
type fakeBackend struct {
	loaded    bool
	loadErr   error
	applyErr  error
	applies   int
	flushes   int
	fragments []string
}

func (f *fakeBackend) Apply(st *store.State, etc map[string]string) error {
	f.applies++
	return f.applyErr
}
func (f *fakeBackend) Flush() error { f.flushes++; return nil }
func (f *fakeBackend) Loaded() (bool, error) {
	return f.loaded, f.loadErr
}
func (f *fakeBackend) ReadBack() (*backend.Snapshot, error) { return nil, nil }
func (f *fakeBackend) ApplyFragments(path string) error {
	f.fragments = append(f.fragments, path)
	return nil
}

// lifecycleEnv builds an Env rooted at a temp BFW_PREFIX-style store with
// all system hooks stubbed. opts may set fields on the returned Env.
func lifecycleEnv(t *testing.T, stdin string) (*Env, *fakeBackend, *strings.Builder, *strings.Builder) {
	t.Helper()

	dir := t.TempDir()
	st := &store.Store{
		Dir:     filepath.Join(dir, "etc", "bfirewall"),
		EtcFile: filepath.Join(dir, "etc", "default", "bfirewall"),
	}
	fb := &fakeBackend{}
	out, errOut := &strings.Builder{}, &strings.Builder{}
	e := &Env{
		Prog:    "bfw",
		Stdin:   strings.NewReader(stdin),
		Stdout:  out,
		Stderr:  errOut,
		Store:   st,
		Backend: fb,
	}

	oldGeteuid, oldSSH, oldLock := hookGeteuid, hookUnderSSH, hookLockFile
	oldLook, oldRun := hookLookPath, hookRunCmd
	t.Cleanup(func() {
		hookGeteuid, hookUnderSSH, hookLockFile = oldGeteuid, oldSSH, oldLock
		hookLookPath, hookRunCmd = oldLook, oldRun
	})

	hookGeteuid = func() int { return 0 }
	hookUnderSSH = func() bool { return false }
	hookLockFile = func(path string) (*os.File, error) {
		return os.CreateTemp(t.TempDir(), "lock")
	}
	hookLookPath = func(string) (string, error) { return "", os.ErrNotExist }
	hookRunCmd = func(string, ...string) error { return nil }

	return e, fb, out, errOut
}

func TestEnableAlreadyLoaded(t *testing.T) {
	e, fb, out, _ := lifecycleEnv(t, "")
	fb.loaded = true
	if rc := e.cmdEnable(nil); rc != 0 {
		t.Fatalf("rc = %d, want 0", rc)
	}
	if got := out.String(); got != "Firewall already started, use 'force-reload'\n" {
		t.Fatalf("stdout = %q", got)
	}
	if fb.applies != 0 {
		t.Fatalf("Apply called %d times, want 0", fb.applies)
	}
}

func TestEnableSSHPrompt(t *testing.T) {
	// Non-y answer aborts without applying.
	e, fb, out, _ := lifecycleEnv(t, "n\n")
	hookUnderSSH = func() bool { return true }
	if rc := e.cmdEnable(nil); rc != 0 {
		t.Fatalf("rc = %d, want 0", rc)
	}
	if !strings.Contains(out.String(), "Command may disrupt existing ssh connections.") ||
		!strings.HasSuffix(out.String(), "Aborted\n") {
		t.Fatalf("stdout = %q", out.String())
	}
	if fb.applies != 0 {
		t.Fatal("Apply called after abort")
	}

	// y proceeds.
	e, fb, _, _ = lifecycleEnv(t, "yes\n")
	hookUnderSSH = func() bool { return true }
	if rc := e.cmdEnable(nil); rc != 0 {
		t.Fatalf("rc = %d, want 0", rc)
	}
	if fb.applies != 1 {
		t.Fatalf("applies = %d, want 1", fb.applies)
	}

	// --force skips the prompt entirely (no stdin).
	e, fb, _, _ = lifecycleEnv(t, "")
	e.Force = true
	hookUnderSSH = func() bool { return true }
	if rc := e.cmdEnable(nil); rc != 0 {
		t.Fatalf("rc = %d, want 0", rc)
	}
	if fb.applies != 1 {
		t.Fatalf("applies = %d, want 1", fb.applies)
	}
}

func TestEnableSuccess(t *testing.T) {
	e, fb, out, _ := lifecycleEnv(t, "")
	if rc := e.cmdEnable(nil); rc != 0 {
		t.Fatalf("rc = %d, want 0", rc)
	}
	if got := out.String(); got != "Firewall is active and enabled on system startup\n" {
		t.Fatalf("stdout = %q", got)
	}
	conf, err := e.Store.LoadConf()
	if err != nil || !conf.Enabled {
		t.Fatalf("conf = %+v, err = %v", conf, err)
	}
	if fb.applies != 1 {
		t.Fatalf("applies = %d, want 1", fb.applies)
	}
}

func TestEnableNonRoot(t *testing.T) {
	e, _, _, errOut := lifecycleEnv(t, "")
	hookGeteuid = func() int { return 1000 }
	if rc := e.cmdEnable(nil); rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	if got := errOut.String(); got != "ERROR: You need to be root to run this script\n" {
		t.Fatalf("stderr = %q", got)
	}
}

func TestDisable(t *testing.T) {
	e, fb, out, _ := lifecycleEnv(t, "")
	if err := e.Store.SaveConf(&store.Conf{Enabled: true, LogLevel: "low"}); err != nil {
		t.Fatal(err)
	}
	if rc := e.cmdDisable(nil); rc != 0 {
		t.Fatalf("rc = %d, want 0", rc)
	}
	if got := out.String(); got != "Firewall stopped and disabled on system startup\n" {
		t.Fatalf("stdout = %q", got)
	}
	if fb.flushes != 1 {
		t.Fatalf("flushes = %d, want 1", fb.flushes)
	}
	conf, _ := e.Store.LoadConf()
	if conf.Enabled {
		t.Fatal("ENABLED still yes after disable")
	}
}

func TestReload(t *testing.T) {
	// Disabled → skip message, no backend calls.
	e, fb, out, _ := lifecycleEnv(t, "")
	if rc := e.cmdReload(nil); rc != 0 {
		t.Fatalf("rc = %d, want 0", rc)
	}
	if got := out.String(); got != "Firewall not enabled (skipping reload)\n" {
		t.Fatalf("stdout = %q", got)
	}
	if fb.flushes != 0 || fb.applies != 0 {
		t.Fatalf("backend touched: flushes=%d applies=%d", fb.flushes, fb.applies)
	}

	// Enabled → disable+enable cycle.
	e, fb, out, _ = lifecycleEnv(t, "")
	if err := e.Store.SaveConf(&store.Conf{Enabled: true, LogLevel: "low"}); err != nil {
		t.Fatal(err)
	}
	if rc := e.cmdReload(nil); rc != 0 {
		t.Fatalf("rc = %d, want 0", rc)
	}
	if got := out.String(); got != "Firewall reloaded\n" {
		t.Fatalf("stdout = %q", got)
	}
	if fb.flushes != 1 || fb.applies != 1 {
		t.Fatalf("flushes=%d applies=%d, want 1/1", fb.flushes, fb.applies)
	}
}

func TestReset(t *testing.T) {
	// Abort on non-y.
	e, _, out, _ := lifecycleEnv(t, "no\n")
	if rc := e.cmdReset(nil); rc != 0 {
		t.Fatalf("rc = %d, want 0", rc)
	}
	if got := out.String(); !strings.HasPrefix(got, "Resetting all rules to installed defaults.") ||
		!strings.HasSuffix(got, "Aborted\n") {
		t.Fatalf("stdout = %q", got)
	}

	// Under ssh the prompt gains the ssh warning.
	e, _, out, _ = lifecycleEnv(t, "n\n")
	hookUnderSSH = func() bool { return true }
	e.cmdReset(nil)
	if !strings.Contains(out.String(), "This may disrupt existing ssh connections.") {
		t.Fatalf("ssh prompt missing warning: %q", out.String())
	}

	// Forced reset: enabled firewall disabled, files backed up, defaults
	// written, conf disabled.
	e, fb, out, _ := lifecycleEnv(t, "")
	e.Force = true
	if err := e.Store.SaveConf(&store.Conf{Enabled: true, LogLevel: "medium"}); err != nil {
		t.Fatal(err)
	}
	st := store.Defaults()
	st.Logging = "high"
	if err := e.Store.Save(st); err != nil {
		t.Fatal(err)
	}
	frag := e.Store.FragmentPath("before")
	if err := os.MkdirAll(e.Store.Dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(frag, []byte("# frag\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if rc := e.cmdReset(nil); rc != 0 {
		t.Fatalf("rc = %d, want 0", rc)
	}
	if fb.flushes != 1 {
		t.Fatalf("flushes = %d, want 1 (enabled reset disables first)", fb.flushes)
	}
	if !strings.Contains(out.String(), "Backing up 'rules.json' to '") ||
		!strings.Contains(out.String(), "Backing up 'before.rules' to '") {
		t.Fatalf("stdout = %q", out.String())
	}
	// Originals moved away, defaults written.
	if _, err := os.Stat(e.Store.RulesPath()); err != nil {
		t.Fatal("rules.json not rewritten")
	}
	got, err := e.Store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.Logging != "low" || len(got.Rules4) != 0 {
		t.Fatalf("state = %+v, want defaults", got)
	}
	conf, _ := e.Store.LoadConf()
	if conf.Enabled {
		t.Fatal("ENABLED still yes after reset")
	}
	matches, _ := filepath.Glob(e.Store.RulesPath() + ".*")
	if len(matches) != 1 {
		t.Fatalf("backups = %v, want 1", matches)
	}
}

func TestDefaultPolicy(t *testing.T) {
	// Missing direction → Invalid direction ''.
	e, _, _, errOut := lifecycleEnv(t, "")
	if rc := e.cmdDefault([]string{"allow"}); rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	if got := errOut.String(); got != "ERROR: Invalid direction ''\n" {
		t.Fatalf("stderr = %q", got)
	}

	// Invalid policy → help, exit 1.
	e, _, out, _ := lifecycleEnv(t, "")
	if rc := e.cmdDefault([]string{"bogus", "incoming"}); rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	if !strings.HasPrefix(out.String(), "Usage:") {
		t.Fatalf("stdout = %q", out.String())
	}

	// Valid: state + /etc/default updated, ufw message printed.
	e, fb, out, _ := lifecycleEnv(t, "")
	if rc := e.cmdDefault([]string{"allow", "incoming"}); rc != 0 {
		t.Fatalf("rc = %d, want 0", rc)
	}
	want := "Default incoming policy changed to 'allow'\n(be sure to update your rules accordingly)\n"
	if got := out.String(); got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
	st, err := e.Store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if st.Policies.Input != "allow" {
		t.Fatalf("input policy = %q", st.Policies.Input)
	}
	etc, err := e.Store.EtcDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if etc["DEFAULT_INPUT_POLICY"] != "ACCEPT" {
		t.Fatalf("DEFAULT_INPUT_POLICY = %q", etc["DEFAULT_INPUT_POLICY"])
	}
	if fb.applies != 0 {
		t.Fatal("re-applied while disabled")
	}

	// Enabled → re-apply happens.
	e, fb, _, _ = lifecycleEnv(t, "")
	if err := e.Store.SaveConf(&store.Conf{Enabled: true, LogLevel: "low"}); err != nil {
		t.Fatal(err)
	}
	if rc := e.cmdDefault([]string{"reject", "routed"}); rc != 0 {
		t.Fatalf("rc = %d, want 0", rc)
	}
	if fb.applies != 1 {
		t.Fatalf("applies = %d, want 1", fb.applies)
	}
	st, _ = e.Store.Load()
	if st.Policies.Forward != "reject" {
		t.Fatalf("forward policy = %q", st.Policies.Forward)
	}
	etc, _ = e.Store.EtcDefaults()
	if etc["DEFAULT_FORWARD_POLICY"] != "REJECT" {
		t.Fatalf("DEFAULT_FORWARD_POLICY = %q", etc["DEFAULT_FORWARD_POLICY"])
	}
}

func TestLogging(t *testing.T) {
	// Invalid level → help, exit 1.
	e, _, out, _ := lifecycleEnv(t, "")
	if rc := e.cmdLogging([]string{"bogus"}); rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	if !strings.HasPrefix(out.String(), "Usage:") {
		t.Fatalf("stdout = %q", out.String())
	}

	// off → disabled message, persisted.
	e, _, out, _ = lifecycleEnv(t, "")
	if rc := e.cmdLogging([]string{"off"}); rc != 0 {
		t.Fatalf("rc = %d, want 0", rc)
	}
	if got := out.String(); got != "Logging disabled\n" {
		t.Fatalf("stdout = %q", got)
	}
	conf, _ := e.Store.LoadConf()
	if conf.LogLevel != "off" {
		t.Fatalf("LOGLEVEL = %q", conf.LogLevel)
	}
	st, _ := e.Store.Load()
	if st.Logging != "off" {
		t.Fatalf("state logging = %q", st.Logging)
	}

	// on while off → low.
	e, _, out, _ = lifecycleEnv(t, "")
	st = store.Defaults()
	st.Logging = "off"
	if err := e.Store.Save(st); err != nil {
		t.Fatal(err)
	}
	if err := e.Store.SaveConf(&store.Conf{LogLevel: "off"}); err != nil {
		t.Fatal(err)
	}
	if rc := e.cmdLogging([]string{"on"}); rc != 0 {
		t.Fatalf("rc = %d, want 0", rc)
	}
	if got := out.String(); got != "Logging enabled\n" {
		t.Fatalf("stdout = %q", got)
	}
	conf, _ = e.Store.LoadConf()
	if conf.LogLevel != "low" {
		t.Fatalf("LOGLEVEL = %q, want low", conf.LogLevel)
	}

	// on while medium → keeps medium.
	e, _, _, _ = lifecycleEnv(t, "")
	st = store.Defaults()
	st.Logging = "medium"
	if err := e.Store.Save(st); err != nil {
		t.Fatal(err)
	}
	if err := e.Store.SaveConf(&store.Conf{LogLevel: "medium"}); err != nil {
		t.Fatal(err)
	}
	e.cmdLogging([]string{"on"})
	conf, _ = e.Store.LoadConf()
	if conf.LogLevel != "medium" {
		t.Fatalf("LOGLEVEL = %q, want medium", conf.LogLevel)
	}

	// Enabled → re-apply.
	e, fb, _, _ := lifecycleEnv(t, "")
	if err := e.Store.SaveConf(&store.Conf{Enabled: true, LogLevel: "low"}); err != nil {
		t.Fatal(err)
	}
	if rc := e.cmdLogging([]string{"high"}); rc != 0 {
		t.Fatalf("rc = %d, want 0", rc)
	}
	if fb.applies != 1 {
		t.Fatalf("applies = %d, want 1", fb.applies)
	}
}
func TestBootLoadUnload(t *testing.T) {
	// Disabled → boot-load is a silent no-op.
	e, fb, out, _ := lifecycleEnv(t, "")
	if rc := e.cmdBootLoad(nil); rc != 0 {
		t.Fatalf("rc = %d, want 0", rc)
	}
	if fb.applies != 0 || out.String() != "" {
		t.Fatalf("applies=%d stdout=%q", fb.applies, out.String())
	}

	// Enabled → applies without touching ENABLED or messaging.
	e, fb, out, _ = lifecycleEnv(t, "")
	if err := e.Store.SaveConf(&store.Conf{Enabled: true, LogLevel: "low"}); err != nil {
		t.Fatal(err)
	}
	if rc := e.cmdBootLoad(nil); rc != 0 {
		t.Fatalf("rc = %d, want 0", rc)
	}
	if fb.applies != 1 || out.String() != "" {
		t.Fatalf("applies=%d stdout=%q", fb.applies, out.String())
	}

	// boot-unload flushes.
	e, fb, _, _ = lifecycleEnv(t, "")
	if rc := e.cmdBootUnload(nil); rc != 0 {
		t.Fatalf("rc = %d, want 0", rc)
	}
	if fb.flushes != 1 {
		t.Fatalf("flushes = %d, want 1", fb.flushes)
	}
}

func TestLockFailure(t *testing.T) {
	e, _, _, errOut := lifecycleEnv(t, "")
	hookLockFile = func(path string) (*os.File, error) {
		return nil, errors.New("locked")
	}
	if rc := e.cmdEnable(nil); rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	if !strings.HasPrefix(errOut.String(), "ERROR: Could not acquire lock") {
		t.Fatalf("stderr = %q", errOut.String())
	}
}
