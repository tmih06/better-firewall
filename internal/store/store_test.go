package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tmih06/better-firewall/internal/rule"
)

// tmpStore builds a Store rooted at t.TempDir(), shaped like a BFW_PREFIX
// installation (<dir>/etc/better-firewall + <dir>/etc/default/better-firewall).
func tmpStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	return &Store{
		Dir:     filepath.Join(dir, "etc", "better-firewall"),
		EtcFile: filepath.Join(dir, "etc", "default", "better-firewall"),
	}
}

func TestStorePaths(t *testing.T) {
	s := &Store{Dir: "/x/etc/better-firewall", EtcFile: "/x/etc/default/better-firewall"}
	cases := map[string]string{
		s.RulesPath():             "/x/etc/better-firewall/rules.json",
		s.ConfPath():              "/x/etc/better-firewall/better-firewall.conf",
		s.SysctlPath():            "/x/etc/better-firewall/sysctl.conf",
		s.AppDir():                "/x/etc/better-firewall/applications.d",
		s.FragmentPath("before"):  "/x/etc/better-firewall/before.rules",
		s.FragmentPath("before6"): "/x/etc/better-firewall/before6.rules",
		s.FragmentPath("after"):   "/x/etc/better-firewall/after.rules",
		s.InitPath("before"):      "/x/etc/better-firewall/before.init",
		s.InitPath("after"):       "/x/etc/better-firewall/after.init",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("path = %q, want %q", got, want)
		}
	}
}

func TestDefaultStoreHonorsBFWPrefix(t *testing.T) {
	prefix := t.TempDir()
	t.Setenv("BFW_PREFIX", prefix)
	s := Default()
	if want := filepath.Join(prefix, "etc", "better-firewall"); s.Dir != want {
		t.Errorf("Dir = %q, want %q", s.Dir, want)
	}
	if want := filepath.Join(prefix, "etc", "default", "better-firewall"); s.EtcFile != want {
		t.Errorf("EtcFile = %q, want %q", s.EtcFile, want)
	}
}

func TestLoadMissingFileReturnsInstallDefaults(t *testing.T) {
	s := tmpStore(t)
	st, err := s.Load()
	if err != nil {
		t.Fatalf("Load on missing rules.json: %v", err)
	}
	want := Defaults()
	if st.Logging != want.Logging || st.IPv6 != want.IPv6 || st.AppPolicy != want.AppPolicy ||
		st.Policies != want.Policies {
		t.Fatalf("Load() = %+v, want install defaults %+v", st, want)
	}
	if st.Rules4 != nil || st.Rules6 != nil {
		t.Fatalf("expected no rules, got %d/%d", len(st.Rules4), len(st.Rules6))
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	s := tmpStore(t)
	st := Defaults()
	st.Logging = "high"
	st.Panic = true
	st.Policies = Policies{Input: "reject", Output: "deny", Forward: "allow"}
	st.Rules4 = []rule.Rule{{ID: "r4", Action: "allow", Direction: "in",
		Proto: "tcp", Dst: rule.AddrSpec{IP: "any", Ports: []rule.PortRange{{Lo: 22, Hi: 22, Proto: "tcp"}}}}}
	st.Rules6 = []rule.Rule{{ID: "r6", Action: "deny", Direction: "out", Proto: "any"}}
	st.Sets = []IPSet{{Name: "blocklist", Family: "inet", Elements: []string{"10.0.0.0/8", "192.168.0.0/16"}}}
	st.NAT = []NATRule{{Kind: "masquerade", IfaceOut: "eth0", Src: "10.9.0.0/24"},
		{Kind: "dnat", Proto: "tcp", Dst: "203.0.113.5", Dport: 8080, ToDest: "10.0.0.8:80"}}

	if err := s.Save(st); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := s.Load()
	if err != nil {
		t.Fatalf("Load after Save: %v", err)
	}
	wantJSON, _ := json.Marshal(st)
	gotJSON, _ := json.Marshal(got)
	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("round trip mismatch:\n got: %s\nwant: %s", gotJSON, wantJSON)
	}

	// List membership drives the transient family flag.
	if got.Rules4[0].V6() {
		t.Error("Rules4[0].V6() = true after load, want false")
	}
	if !got.Rules6[0].V6() {
		t.Error("Rules6[0].V6() = false after load, want true")
	}
}

func TestSaveWrites0600AndNoLeftoverTmp(t *testing.T) {
	s := tmpStore(t)
	if err := s.Save(Defaults()); err != nil {
		t.Fatalf("Save: %v", err)
	}
	fi, err := os.Stat(s.RulesPath())
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("rules.json perm = %o, want 600", perm)
	}
	if _, err := os.Stat(s.RulesPath() + ".tmp"); !os.IsNotExist(err) {
		t.Error("rules.json.tmp left behind after successful Save")
	}
}

func TestLoadPartialJSONKeepsDefaults(t *testing.T) {
	// A state file missing scalar fields must keep install defaults for
	// them rather than zeroing (json.Unmarshal over Defaults()).
	s := tmpStore(t)
	if err := os.MkdirAll(s.Dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.RulesPath(), []byte(`{"rules4":[],"rules6":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	st, err := s.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if st.Logging != "low" || !st.IPv6 || st.AppPolicy != "skip" ||
		st.Policies.Input != "deny" || st.Policies.Output != "allow" {
		t.Fatalf("defaults not preserved: %+v", st)
	}
}

func TestLoadErrorPaths(t *testing.T) {
	s := tmpStore(t)
	if err := os.MkdirAll(s.Dir, 0755); err != nil {
		t.Fatal(err)
	}

	// Corrupt JSON → error naming the file.
	if err := os.WriteFile(s.RulesPath(), []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); err == nil || !strings.Contains(err.Error(), "rules.json") {
		t.Fatalf("corrupt file: err = %v, want parse error naming rules.json", err)
	}

	// A directory where rules.json belongs → read error, not defaults.
	os.Remove(s.RulesPath())
	if err := os.Mkdir(s.RulesPath(), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); err == nil {
		t.Fatal("Load with rules.json as dir: got nil error")
	}
}

func TestSaveErrorWhenDirIsFile(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	s := &Store{Dir: filepath.Join(blocker, "etc", "better-firewall"), EtcFile: filepath.Join(dir, "etc-default")}
	if err := s.Save(Defaults()); err == nil {
		t.Fatal("Save with non-directory Dir: got nil error")
	}
	// The staged tmp file must be cleaned up (or never created) — no
	// leftover either way.
	if _, err := os.Stat(filepath.Join(s.Dir, "rules.json.tmp")); err == nil {
		t.Error("temp file left behind after failed Save")
	}
}

func TestSaveFailureLeavesDestinationUntouched(t *testing.T) {
	// rules.json as a directory: the tmp write succeeds but rename cannot
	// replace a non-empty directory → Save errors and the destination is
	// left as-is (no partial content at the final path).
	s := tmpStore(t)
	if err := os.MkdirAll(s.RulesPath(), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.RulesPath(), "keep"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(Defaults()); err == nil {
		t.Fatal("Save onto a directory: got nil error")
	}
	if fi, err := os.Stat(s.RulesPath()); err != nil || !fi.IsDir() {
		t.Error("destination path was clobbered by failed Save")
	}
	if _, err := os.Stat(filepath.Join(s.RulesPath(), "keep")); err != nil {
		t.Error("existing content under destination lost")
	}
	// The staged rules.json.tmp must be removed on rename failure.
	if _, err := os.Stat(s.RulesPath() + ".tmp"); !os.IsNotExist(err) {
		t.Error("rules.json.tmp leaked after failed rename")
	}
}

func TestLoadConfDefaultsAndParsing(t *testing.T) {
	s := tmpStore(t)

	// Missing file → disabled, log level low (ufw defaults).
	c, err := s.LoadConf()
	if err != nil || c.Enabled || c.LogLevel != "low" {
		t.Fatalf("missing conf = %+v, err %v; want disabled/low", c, err)
	}

	if err := os.MkdirAll(s.Dir, 0755); err != nil {
		t.Fatal(err)
	}
	conf := `# comment
ENABLED = YES
bogus line without equals
LOGLEVEL=high
UNKNOWN_KEY=ignored
`
	if err := os.WriteFile(s.ConfPath(), []byte(conf), 0644); err != nil {
		t.Fatal(err)
	}
	c, err = s.LoadConf()
	if err != nil {
		t.Fatalf("LoadConf: %v", err)
	}
	if !c.Enabled {
		t.Error("ENABLED = YES not honored")
	}
	if c.LogLevel != "high" {
		t.Errorf("LogLevel = %q, want high", c.LogLevel)
	}

	// Read errors propagate (conf path is a directory).
	if err := os.Remove(s.ConfPath()); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(s.ConfPath(), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadConf(); err == nil {
		t.Fatal("LoadConf on directory: got nil error")
	}
}

func TestSaveConfRoundTrip(t *testing.T) {
	s := tmpStore(t)
	for _, c := range []*Conf{{Enabled: true, LogLevel: "full"}, {Enabled: false, LogLevel: "off"}} {
		if err := s.SaveConf(c); err != nil {
			t.Fatalf("SaveConf(%+v): %v", c, err)
		}
		got, err := s.LoadConf()
		if err != nil {
			t.Fatalf("LoadConf: %v", err)
		}
		if got.Enabled != c.Enabled || got.LogLevel != c.LogLevel {
			t.Fatalf("round trip = %+v, want %+v", got, c)
		}
	}
	// Enabled forms are the ufw spellings.
	if err := s.SaveConf(&Conf{Enabled: true, LogLevel: "low"}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(s.ConfPath())
	if !strings.Contains(string(data), "ENABLED=yes\n") {
		t.Fatalf("better-firewall.conf missing ENABLED=yes:\n%s", data)
	}
}

func TestEtcDefaultsBaselineAndOverrides(t *testing.T) {
	s := tmpStore(t)

	// Missing file → ufw-equivalent baseline map.
	m, err := s.EtcDefaults()
	if err != nil {
		t.Fatalf("EtcDefaults: %v", err)
	}
	for k, want := range map[string]string{
		"IPV6": "yes", "DEFAULT_INPUT_POLICY": "DROP",
		"DEFAULT_OUTPUT_POLICY": "ACCEPT", "DEFAULT_FORWARD_POLICY": "DROP",
		"DEFAULT_APPLICATION_POLICY": "SKIP", "MANAGE_BUILTINS": "no",
		"IPT_SYSCTL": s.SysctlPath(),
	} {
		if m[k] != want {
			t.Errorf("default %s = %q, want %q", k, m[k], want)
		}
	}

	body := `# ufw-style overrides
IPV6="no"
DEFAULT_INPUT_POLICY='ACCEPT'
IPT_MODULES="nf_conntrack_ftp nf_nat_ftp"
LINES_WITHOUT_EQUALS
CUSTOM_KEY=kept
`
	if err := os.MkdirAll(filepath.Dir(s.EtcFile), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.EtcFile, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	m, err = s.EtcDefaults()
	if err != nil {
		t.Fatalf("EtcDefaults: %v", err)
	}
	if m["IPV6"] != "no" {
		t.Errorf("IPV6 = %q, want no (quotes stripped)", m["IPV6"])
	}
	if m["DEFAULT_INPUT_POLICY"] != "ACCEPT" {
		t.Errorf("DEFAULT_INPUT_POLICY = %q, want ACCEPT (single quotes stripped)", m["DEFAULT_INPUT_POLICY"])
	}
	if m["IPT_MODULES"] != "nf_conntrack_ftp nf_nat_ftp" {
		t.Errorf("IPT_MODULES = %q", m["IPT_MODULES"])
	}
	if m["CUSTOM_KEY"] != "kept" {
		t.Errorf("CUSTOM_KEY = %q", m["CUSTOM_KEY"])
	}
	// Baseline keys not overridden remain.
	if m["DEFAULT_OUTPUT_POLICY"] != "ACCEPT" {
		t.Errorf("DEFAULT_OUTPUT_POLICY = %q, want baseline ACCEPT", m["DEFAULT_OUTPUT_POLICY"])
	}
}

func TestWriteEtcDefaultPreservesFile(t *testing.T) {
	s := tmpStore(t)
	orig := `# header comment
IPV6=yes
IPT_MODULES=""
DEFAULT_INPUT_POLICY="DROP"
`
	if err := os.MkdirAll(filepath.Dir(s.EtcFile), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.EtcFile, []byte(orig), 0644); err != nil {
		t.Fatal(err)
	}

	// Update an existing key: other lines and comments preserved.
	if err := s.WriteEtcDefault("IPV6", "no"); err != nil {
		t.Fatalf("WriteEtcDefault: %v", err)
	}
	data, _ := os.ReadFile(s.EtcFile)
	got := string(data)
	if !strings.Contains(got, "# header comment") || !strings.Contains(got, `IPT_MODULES=""`) {
		t.Fatalf("unrelated lines lost:\n%s", got)
	}
	if !strings.Contains(got, `IPV6="no"`) {
		t.Fatalf("updated line missing:\n%s", got)
	}
	// Prefix safety: writing IPT_MODULES must not rewrite IPV6 etc.
	if err := s.WriteEtcDefault("IPT_MODULES", "nf_conntrack"); err != nil {
		t.Fatalf("WriteEtcDefault: %v", err)
	}
	data, _ = os.ReadFile(s.EtcFile)
	got = string(data)
	if !strings.Contains(got, `IPT_MODULES="nf_conntrack"`) ||
		!strings.Contains(got, `IPV6="no"`) {
		t.Fatalf("key-prefix collision mangled file:\n%s", got)
	}

	// New key on a missing file → file created with just that key.
	s2 := tmpStore(t)
	if err := s2.WriteEtcDefault("DEFAULT_INPUT_POLICY", "REJECT"); err != nil {
		t.Fatalf("WriteEtcDefault on missing file: %v", err)
	}
	m, err := s2.EtcDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if m["DEFAULT_INPUT_POLICY"] != "REJECT" {
		t.Errorf("DEFAULT_INPUT_POLICY = %q, want REJECT", m["DEFAULT_INPUT_POLICY"])
	}
}

func TestEnsureDefaults(t *testing.T) {
	s := tmpStore(t)

	// Missing EtcFile → materialized alongside the store dir files.
	if err := s.EnsureDefaults(); err != nil {
		t.Fatalf("EnsureDefaults: %v", err)
	}
	for _, p := range []string{s.SysctlPath(), filepath.Join(s.AppDir(), "openssh.ini"), s.EtcFile} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected %s to exist: %v", p, err)
		}
	}

	// User-edited files are never overwritten.
	custom := []byte("IPV6=no\n")
	if err := os.WriteFile(s.EtcFile, custom, 0644); err != nil {
		t.Fatal(err)
	}
	customSysctl := []byte("# my tunables\n")
	if err := os.WriteFile(s.SysctlPath(), customSysctl, 0644); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureDefaults(); err != nil {
		t.Fatalf("second EnsureDefaults: %v", err)
	}
	if data, _ := os.ReadFile(s.EtcFile); string(data) != string(custom) {
		t.Error("EnsureDefaults overwrote user /etc/default/better-firewall")
	}
	if data, _ := os.ReadFile(s.SysctlPath()); string(data) != string(customSysctl) {
		t.Error("EnsureDefaults overwrote user sysctl.conf")
	}
}
