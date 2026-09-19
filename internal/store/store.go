// Package store owns all persistent state under /etc/bfirewall (overridable
// via BFW_PREFIX for tests): rules.json, bfw.conf, sysctl.conf,
// applications.d/, before/after.rules fragments, and /etc/default/bfirewall.
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"bfirewall/internal/rule"
)

// State is the complete persistent firewall configuration.
type State struct {
	Rules4    []rule.Rule `json:"rules4"`
	Rules6    []rule.Rule `json:"rules6"`
	Policies  Policies    `json:"policies"`
	Logging   string      `json:"logging"` // off|low|medium|high|full
	IPv6      bool        `json:"ipv6"`
	AppPolicy string      `json:"app_policy"` // skip|allow|deny|reject
	Panic     bool        `json:"panic,omitempty"`
	Sets      []IPSet     `json:"sets,omitempty"`
	NAT       []NATRule   `json:"nat,omitempty"`
}

// Policies are the default chain policies (allow|deny|reject).
type Policies struct {
	Input   string `json:"input"`
	Output  string `json:"output"`
	Forward string `json:"forward"`
}

// IPSet is a named set of addresses usable from rules (`from set NAME`).
type IPSet struct {
	Name     string   `json:"name"`
	Family   string   `json:"family"` // ip|ip6|inet
	Elements []string `json:"elements"`
}

// NATRule is a stored NAT rule (bfw extension).
type NATRule struct {
	Kind     string `json:"kind"` // masquerade|dnat
	IfaceIn  string `json:"iface_in,omitempty"`
	IfaceOut string `json:"iface_out,omitempty"`
	Proto    string `json:"proto,omitempty"`
	Src      string `json:"src,omitempty"`
	Dst      string `json:"dst,omitempty"`
	Dport    uint16 `json:"dport,omitempty"`
	ToDest   string `json:"to_dest,omitempty"` // dnat target ip[:port]
}

// Defaults returns the install-default state (mirrors ufw defaults).
func Defaults() *State {
	return &State{
		Policies:  Policies{Input: "deny", Output: "allow", Forward: "deny"},
		Logging:   "low",
		IPv6:      true,
		AppPolicy: "skip",
	}
}

// Store binds a State to its on-disk location.
type Store struct {
	Dir     string // e.g. /etc/bfirewall
	EtcFile string // e.g. /etc/default/bfirewall
}

// Default returns the production store rooted at BFW_PREFIX or /.
func Default() *Store {
	prefix := os.Getenv("BFW_PREFIX")
	return &Store{
		Dir:     filepath.Join(prefix, "etc", "bfirewall"),
		EtcFile: filepath.Join(prefix, "etc", "default", "bfirewall"),
	}
}

// RulesPath is the canonical rules file.
func (s *Store) RulesPath() string { return filepath.Join(s.Dir, "rules.json") }

// ConfPath is the ENABLED/LOGLEVEL file (mirrors ufw.conf).
func (s *Store) ConfPath() string { return filepath.Join(s.Dir, "bfw.conf") }

// SysctlPath is the kernel-tunables file applied on enable.
func (s *Store) SysctlPath() string { return filepath.Join(s.Dir, "sysctl.conf") }

// AppDir holds INI application profiles.
func (s *Store) AppDir() string { return filepath.Join(s.Dir, "applications.d") }

// FragmentPath returns the path of a before/after fragment ("before",
// "before6", "after", "after6").
func (s *Store) FragmentPath(name string) string {
	return filepath.Join(s.Dir, name+".rules")
}

// InitPath returns the path of an init hook ("before", "after").
func (s *Store) InitPath(name string) string {
	return filepath.Join(s.Dir, name+".init")
}

// Load reads rules.json; missing file → Defaults() (not an error).
func (s *Store) Load() (*State, error) {
	data, err := os.ReadFile(s.RulesPath())
	if os.IsNotExist(err) {
		return Defaults(), nil
	}
	if err != nil {
		return nil, err
	}
	st := Defaults()
	if err := json.Unmarshal(data, st); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", s.RulesPath(), err)
	}
	for i := range st.Rules4 {
		st.Rules4[i].SetV6(false)
	}
	for i := range st.Rules6 {
		st.Rules6[i].SetV6(true)
	}
	return st, nil
}

// Save writes rules.json atomically (tmp + rename, 0600).
func (s *Store) Save(st *State) error {
	if err := os.MkdirAll(s.Dir, 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.RulesPath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.RulesPath())
}

// Conf holds bfw.conf values.
type Conf struct {
	Enabled  bool
	LogLevel string
}

// LoadConf reads bfw.conf; missing → disabled/low.
func (s *Store) LoadConf() (*Conf, error) {
	c := &Conf{LogLevel: "low"}
	data, err := os.ReadFile(s.ConfPath())
	if os.IsNotExist(err) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		kv := strings.SplitN(strings.TrimSpace(line), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch strings.TrimSpace(kv[0]) {
		case "ENABLED":
			c.Enabled = strings.TrimSpace(kv[1]) == "yes"
		case "LOGLEVEL":
			c.LogLevel = strings.TrimSpace(kv[1])
		}
	}
	return c, nil
}

// SaveConf writes bfw.conf.
func (s *Store) SaveConf(c *Conf) error {
	if err := os.MkdirAll(s.Dir, 0755); err != nil {
		return err
	}
	en := "no"
	if c.Enabled {
		en = "yes"
	}
	body := fmt.Sprintf("# /etc/bfirewall/bfw.conf\n\nENABLED=%s\nLOGLEVEL=%s\n", en, c.LogLevel)
	return os.WriteFile(s.ConfPath(), []byte(body), 0644)
}

// EtcDefaults parses /etc/default/bfirewall KEY=VALUE pairs (ufw key names).
func (s *Store) EtcDefaults() (map[string]string, error) {
	out := map[string]string{
		"IPV6":                       "yes",
		"DEFAULT_INPUT_POLICY":       "DROP",
		"DEFAULT_OUTPUT_POLICY":      "ACCEPT",
		"DEFAULT_FORWARD_POLICY":     "DROP",
		"DEFAULT_APPLICATION_POLICY": "SKIP",
		"MANAGE_BUILTINS":            "no",
		"LOGGING_BACKEND":            "kernel",
		"KERNEL_SYSLOG_LEVEL":        "",
		"IPT_SYSCTL":                 s.SysctlPath(),
		"IPT_MODULES":                "",
	}
	data, err := os.ReadFile(s.EtcFile)
	if os.IsNotExist(err) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			continue
		}
		out[strings.TrimSpace(kv[0])] = strings.Trim(strings.TrimSpace(kv[1]), `"'`)
	}
	return out, nil
}

// WriteEtcDefault updates one key in /etc/default/bfirewall, preserving the
// file's other lines (creates the file if missing).
func (s *Store) WriteEtcDefault(key, value string) error {
	if err := os.MkdirAll(filepath.Dir(s.EtcFile), 0755); err != nil {
		return err
	}
	data, _ := os.ReadFile(s.EtcFile)
	lines := strings.Split(string(data), "\n")
	found := false
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), key+"=") {
			lines[i] = fmt.Sprintf("%s=\"%s\"", key, value)
			found = true
		}
	}
	if !found {
		lines = append(lines, fmt.Sprintf("%s=\"%s\"", key, value))
	}
	return os.WriteFile(s.EtcFile, []byte(strings.Join(lines, "\n")), 0644)
}
