package impexp

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tmih06/better-firewall/internal/rule"
	"github.com/tmih06/better-firewall/internal/store"
)

func TestParseTupleLine(t *testing.T) {
	tests := []struct {
		name string
		line string
		want rule.Rule
	}{
		{
			name: "7-field allow with ifaces",
			line: "### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in",
			want: rule.Rule{
				Action: rule.ActionAllow, Direction: rule.DirIn, Proto: "tcp",
				Dst: rule.AddrSpec{IP: "any", Ports: []rule.PortRange{{Lo: 22, Hi: 22, Proto: "tcp"}}},
				Src: rule.AddrSpec{IP: "any"},
			},
		},
		{
			name: "9-field with apps and iface",
			line: "### tuple ### deny udp 53 192.168.1.0/24 any 10.0.0.5 - - in_eth0",
			want: rule.Rule{
				Action: rule.ActionDeny, Direction: rule.DirIn, Proto: "udp", IfaceIn: "eth0",
				Dst: rule.AddrSpec{IP: "192.168.1.0/24", Ports: []rule.PortRange{{Lo: 53, Hi: 53, Proto: "udp"}}},
				Src: rule.AddrSpec{IP: "10.0.0.5"},
			},
		},
		{
			name: "route prefix with both ifaces",
			line: "### tuple ### route:allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in_eth0!out_eth1",
			want: rule.Rule{
				Action: rule.ActionAllow, Direction: rule.DirRouted, Proto: "tcp",
				IfaceIn: "eth0", IfaceOut: "eth1",
				Dst: rule.AddrSpec{IP: "any", Ports: []rule.PortRange{{Lo: 80, Hi: 80, Proto: "tcp"}}},
				Src: rule.AddrSpec{IP: "any"},
			},
		},
		{
			name: "log suffix",
			line: "### tuple ### limit_log tcp 22 0.0.0.0/0 any 0.0.0.0/0 in",
			want: rule.Rule{
				Action: rule.ActionLimit, Direction: rule.DirIn, Proto: "tcp", Log: rule.LogNew,
				Dst: rule.AddrSpec{IP: "any", Ports: []rule.PortRange{{Lo: 22, Hi: 22, Proto: "tcp"}}},
				Src: rule.AddrSpec{IP: "any"},
			},
		},
		{
			name: "log-all suffix",
			line: "### tuple ### reject_log-all tcp 23 0.0.0.0/0 any 0.0.0.0/0 in",
			want: rule.Rule{
				Action: rule.ActionReject, Direction: rule.DirIn, Proto: "tcp", Log: rule.LogAll,
				Dst: rule.AddrSpec{IP: "any", Ports: []rule.PortRange{{Lo: 23, Hi: 23, Proto: "tcp"}}},
				Src: rule.AddrSpec{IP: "any"},
			},
		},
		{
			name: "out direction with iface",
			line: "### tuple ### allow tcp 443 0.0.0.0/0 any 0.0.0.0/0 out_eth0",
			want: rule.Rule{
				Action: rule.ActionAllow, Direction: rule.DirOut, Proto: "tcp", IfaceOut: "eth0",
				Dst: rule.AddrSpec{IP: "any", Ports: []rule.PortRange{{Lo: 443, Hi: 443, Proto: "tcp"}}},
				Src: rule.AddrSpec{IP: "any"},
			},
		},
		{
			name: "comment",
			line: "### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in comment=ssh access",
			want: rule.Rule{
				Action: rule.ActionAllow, Direction: rule.DirIn, Proto: "tcp", Comment: "ssh access",
				Dst: rule.AddrSpec{IP: "any", Ports: []rule.PortRange{{Lo: 22, Hi: 22, Proto: "tcp"}}},
				Src: rule.AddrSpec{IP: "any"},
			},
		},
		{
			name: "legacy 6-field",
			line: "### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0",
			want: rule.Rule{
				Action: rule.ActionAllow, Direction: rule.DirIn, Proto: "tcp",
				Dst: rule.AddrSpec{IP: "any", Ports: []rule.PortRange{{Lo: 22, Hi: 22, Proto: "tcp"}}},
				Src: rule.AddrSpec{IP: "any"},
			},
		},
		{
			name: "legacy 8-field with apps",
			line: "### tuple ### allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 Nginx%20Full -",
			want: rule.Rule{
				Action: rule.ActionAllow, Direction: rule.DirIn, Proto: "tcp", Dapp: "Nginx Full",
				Dst: rule.AddrSpec{IP: "any", Ports: []rule.PortRange{{Lo: 80, Hi: 80, Proto: "tcp"}}},
				Src: rule.AddrSpec{IP: "any"},
			},
		},
		{
			name: "multiport list",
			line: "### tuple ### allow tcp 80,443,8080:8090 0.0.0.0/0 any 0.0.0.0/0 in",
			want: rule.Rule{
				Action: rule.ActionAllow, Direction: rule.DirIn, Proto: "tcp",
				Dst: rule.AddrSpec{IP: "any", Ports: []rule.PortRange{
					{Lo: 80, Hi: 80, Proto: "tcp"},
					{Lo: 443, Hi: 443, Proto: "tcp"},
					{Lo: 8080, Hi: 8090, Proto: "tcp"},
				}},
				Src: rule.AddrSpec{IP: "any"},
			},
		},
		{
			name: "v6 wildcard",
			line: "### tuple ### allow tcp 22 ::/0 any ::/0 in",
			want: rule.Rule{
				Action: rule.ActionAllow, Direction: rule.DirIn, Proto: "tcp",
				Dst: rule.AddrSpec{IP: "any", Ports: []rule.PortRange{{Lo: 22, Hi: 22, Proto: "tcp"}}},
				Src: rule.AddrSpec{IP: "any"},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseTupleLine(tc.line)
			if err != nil {
				t.Fatalf("ParseTupleLine: %v", err)
			}
			got.ID = ""
			if !rulesEqual(got, &tc.want) {
				t.Fatalf("got %+v, want %+v", got, &tc.want)
			}
		})
	}
}

func TestParseTupleLineMalformed(t *testing.T) {
	for _, line := range []string{
		"### tuple ### frobnicate tcp 22 0.0.0.0/0 any 0.0.0.0/0 in",            // bad action
		"### tuple ### allow tcp 22 0.0.0.0/0",                                  // too few fields
		"### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in extra junk more", // too many
		"### tuple ### allow tcp 99999 0.0.0.0/0 any 0.0.0.0/0 in",              // bad port
		"### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 sideways",           // bad ifaces
	} {
		if _, err := ParseTupleLine(line); err == nil {
			t.Errorf("expected error for %q", line)
		}
	}
}

// rulesEqual compares all fields except ID and the transient v6 flag.
func rulesEqual(a, b *rule.Rule) bool {
	return a.Action == b.Action &&
		a.Direction == b.Direction &&
		a.IfaceIn == b.IfaceIn &&
		a.IfaceOut == b.IfaceOut &&
		a.Proto == b.Proto &&
		addrEqual(a.Src, b.Src) &&
		addrEqual(a.Dst, b.Dst) &&
		a.Dapp == b.Dapp &&
		a.Sapp == b.Sapp &&
		a.Log == b.Log &&
		a.Comment == b.Comment &&
		a.ExpiresAt == b.ExpiresAt &&
		a.Disabled == b.Disabled
}

func addrEqual(a, b rule.AddrSpec) bool {
	if a.IP != b.IP || a.Set != b.Set || len(a.Ports) != len(b.Ports) {
		return false
	}
	for i := range a.Ports {
		if a.Ports[i] != b.Ports[i] {
			return false
		}
	}
	return true
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestImportUFW(t *testing.T) {
	dir := t.TempDir()
	ufwDir := filepath.Join(dir, "etc", "ufw")
	writeFile(t, filepath.Join(ufwDir, "user.rules"), `*filter
:ufw-user-input - [0:0]
### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in
### tuple ### deny udp 53 192.168.1.0/24 any 10.0.0.5 - - in_eth0
### tuple ### route:allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in_eth0!out_eth1
### tuple ### limit_log tcp 2222 0.0.0.0/0 any 0.0.0.0/0 in
### tuple ### bogus tcp 1 0.0.0.0/0 any 0.0.0.0/0 in
### END RULES ###
-A ufw-user-input -j ACCEPT
COMMIT
`)
	writeFile(t, filepath.Join(ufwDir, "user6.rules"), `*filter
### tuple ### allow tcp 22 ::/0 any ::/0 in
### END RULES ###
COMMIT
`)
	writeFile(t, filepath.Join(ufwDir, "ufw.conf"), "ENABLED=yes\nLOGLEVEL=medium\n")
	etcFile := filepath.Join(dir, "etc", "default", "ufw")
	writeFile(t, etcFile, `IPV6=yes
DEFAULT_INPUT_POLICY="DROP"
DEFAULT_OUTPUT_POLICY="ACCEPT"
DEFAULT_FORWARD_POLICY="REJECT"
`)

	st := store.Defaults()
	merged, n, warnings, err := ImportUFW(ufwDir, etcFile, st)
	if err != nil {
		t.Fatalf("ImportUFW: %v", err)
	}
	if n != 5 {
		t.Fatalf("added = %d, want 5 (4 v4 + 1 v6)", n)
	}
	if len(merged.Rules4) != 4 {
		t.Fatalf("Rules4 = %d, want 4", len(merged.Rules4))
	}
	if len(merged.Rules6) != 1 {
		t.Fatalf("Rules6 = %d, want 1", len(merged.Rules6))
	}
	// Identical tuple in both files → dual rule sharing one ID.
	if merged.Rules4[0].ID != merged.Rules6[0].ID {
		t.Errorf("dual rule IDs differ: %q vs %q", merged.Rules4[0].ID, merged.Rules6[0].ID)
	}
	// Malformed tuple skipped with a warning; ENABLED=yes warns too.
	var sawMalformed, sawEnabled bool
	for _, w := range warnings {
		if strings.Contains(w, "bad action") {
			sawMalformed = true
		}
		if strings.Contains(w, "ufw was enabled") {
			sawEnabled = true
		}
	}
	if !sawMalformed {
		t.Errorf("missing malformed-tuple warning in %v", warnings)
	}
	if !sawEnabled {
		t.Errorf("missing enabled warning in %v", warnings)
	}
	// Policies + logging from ufw files.
	if merged.Policies.Input != "deny" || merged.Policies.Output != "allow" || merged.Policies.Forward != "reject" {
		t.Errorf("policies = %+v", merged.Policies)
	}
	if merged.Logging != "medium" {
		t.Errorf("logging = %q, want medium", merged.Logging)
	}
	if !merged.IPv6 {
		t.Error("ipv6 = false, want true")
	}
}

func TestImportUFWMissingDir(t *testing.T) {
	st := store.Defaults()
	if _, _, _, err := ImportUFW(t.TempDir(), "/nonexistent", st); err == nil {
		t.Fatal("expected error for missing ufw dir")
	}
}

func TestExportImportRoundTrip(t *testing.T) {
	st := store.Defaults()
	r4 := rule.Rule{
		ID: "aaa", Action: rule.ActionAllow, Direction: rule.DirIn, Proto: "tcp",
		Dst: rule.AddrSpec{IP: "any", Ports: []rule.PortRange{{Lo: 22, Hi: 22, Proto: "tcp"}}},
		Src: rule.AddrSpec{IP: "any"}, Comment: "ssh",
	}
	r6 := r4
	r6.SetV6(true)
	st.Rules4 = []rule.Rule{r4}
	st.Rules6 = []rule.Rule{r6}
	st.Logging = "high"
	st.Policies.Forward = "reject"
	st.Sets = []store.IPSet{{Name: "bad", Family: "ip", Elements: []string{"10.0.0.1"}}}
	st.NAT = []store.NATRule{{Kind: "masquerade", IfaceOut: "eth0"}}

	var buf bytes.Buffer
	if err := Export(st, &buf); err != nil {
		t.Fatalf("Export: %v", err)
	}
	if !strings.Contains(buf.String(), `"version": 1`) {
		t.Fatalf("export missing version: %s", buf.String())
	}

	// Replace round-trip preserves everything.
	back, n, err := Import(bytes.NewReader(buf.Bytes()), store.Defaults(), true)
	if err != nil {
		t.Fatalf("Import replace: %v", err)
	}
	if n != 2 {
		t.Fatalf("replace count = %d, want 2", n)
	}
	if len(back.Rules4) != 1 || len(back.Rules6) != 1 {
		t.Fatalf("rules = %d/%d", len(back.Rules4), len(back.Rules6))
	}
	if !rulesEqual(&back.Rules4[0], &r4) || back.Rules4[0].ID != "aaa" {
		t.Errorf("v4 rule mismatch: %+v", back.Rules4[0])
	}
	if back.Logging != "high" || back.Policies.Forward != "reject" {
		t.Errorf("scalars not preserved: %+v", back)
	}
	if len(back.Sets) != 1 || len(back.NAT) != 1 {
		t.Errorf("sets/nat not preserved: %+v", back)
	}

	// Merge into a state already holding the same rule → dedup, count 0.
	existing := store.Defaults()
	dup := r4
	dup.ID = "bbb"
	existing.Rules4 = []rule.Rule{dup}
	merged, n, err := Import(bytes.NewReader(buf.Bytes()), existing, false)
	if err != nil {
		t.Fatalf("Import merge: %v", err)
	}
	if n != 1 { // v6 half is new; v4 half dedups
		t.Fatalf("merge count = %d, want 1", n)
	}
	if len(merged.Rules4) != 1 {
		t.Fatalf("Rules4 grew: %d", len(merged.Rules4))
	}
	if merged.Rules4[0].ID != "bbb" {
		t.Errorf("existing rule ID clobbered: %q", merged.Rules4[0].ID)
	}
	if len(merged.Rules6) != 1 {
		t.Fatalf("Rules6 = %d, want 1", len(merged.Rules6))
	}
	// Sets merged by name (union), NAT deduped.
	if len(merged.Sets) != 1 || len(merged.NAT) != 1 {
		t.Errorf("sets/nat merge wrong: %+v", merged)
	}
}

func TestImportBadInput(t *testing.T) {
	st := store.Defaults()
	if _, _, err := Import(strings.NewReader("not json"), st, false); err == nil {
		t.Error("expected error for non-JSON")
	}
	if _, _, err := Import(strings.NewReader(`{"version":2}`), st, false); err == nil {
		t.Error("expected error for version 2")
	}
}
