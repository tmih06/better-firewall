package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/tmih06/better-firewall/internal/rule"
	"github.com/tmih06/better-firewall/internal/store"
)

func mkExtRule(action, dir, proto, src, dst string, dports ...rule.PortRange) *rule.Rule {
	return &rule.Rule{
		ID:        rule.NewID(),
		Action:    action,
		Direction: dir,
		Proto:     proto,
		Src:       rule.AddrSpec{IP: src},
		Dst:       rule.AddrSpec{IP: dst, Ports: dports},
	}
}

func TestValidSetName(t *testing.T) {
	for _, ok := range []string{"badguys", "net_1", "A-B_c", "x"} {
		if !validSetName(ok) {
			t.Errorf("validSetName(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"", "a b", "a.b", "a/b", "a;b", "set!", "na me", "-x y"} {
		if validSetName(bad) {
			t.Errorf("validSetName(%q) = true, want false", bad)
		}
	}
}

func TestCanonSetElem(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4":       "1.2.3.4",
		"10.0.0.0/8":    "10.0.0.0/8",
		"10.1.2.3/8":    "10.0.0.0/8", // host bits masked
		"::1":           "::1",
		"2001:db8::/32": "2001:db8::/32",
		"1.2.3.4/32":    "1.2.3.4/32",
	}
	for in, want := range cases {
		got, ok := canonSetElem(in)
		if !ok || got != want {
			t.Errorf("canonSetElem(%q) = %q,%v want %q,true", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "abc", "1.2.3.4/33", "999.1.1.1", "10.0.0.0/-1", "1.2.3.4/"} {
		if got, ok := canonSetElem(bad); ok {
			t.Errorf("canonSetElem(%q) = %q,true want '',false", bad, got)
		}
	}
}

func TestRuleSuperset(t *testing.T) {
	tcp22 := rule.PortRange{Lo: 22, Hi: 22, Proto: "tcp"}
	tcpAll := rule.PortRange{Lo: 1, Hi: 65535, Proto: "tcp"}

	cases := []struct {
		name string
		a, b *rule.Rule
		want bool
	}{
		{
			"identical tuples shadow",
			mkExtRule("deny", "in", "tcp", "any", "any", tcp22),
			mkExtRule("allow", "in", "tcp", "any", "any", tcp22),
			true,
		},
		{
			"any-proto covers tcp",
			mkExtRule("allow", "in", "tcp", "any", "any", tcp22),
			mkExtRule("deny", "in", "any", "any", "any"),
			true,
		},
		{
			"tcp does not cover any",
			mkExtRule("allow", "in", "any", "any", "any"),
			mkExtRule("deny", "in", "tcp", "any", "any", tcp22),
			false,
		},
		{
			"cidr covers member ip",
			mkExtRule("allow", "in", "any", "10.1.2.3", "any"),
			mkExtRule("deny", "in", "any", "10.0.0.0/8", "any"),
			true,
		},
		{
			"member ip does not cover cidr",
			mkExtRule("allow", "in", "any", "10.0.0.0/8", "any"),
			mkExtRule("deny", "in", "any", "10.1.2.3", "any"),
			false,
		},
		{
			"port range covers single port",
			mkExtRule("allow", "in", "tcp", "any", "any", tcp22),
			mkExtRule("deny", "in", "tcp", "any", "any", tcpAll),
			true,
		},
		{
			"single port does not cover range",
			mkExtRule("allow", "in", "tcp", "any", "any", tcpAll),
			mkExtRule("deny", "in", "tcp", "any", "any", tcp22),
			false,
		},
		{
			"no-iface covers iface",
			mkExtRule("allow", "in", "any", "any", "any"),
			func() *rule.Rule { r := mkExtRule("deny", "in", "any", "any", "any"); r.IfaceIn = "eth0"; return r }(),
			false, // b restricted to eth0 does NOT cover unrestricted a
		},
		{
			"unrestricted covers iface-restricted",
			func() *rule.Rule { r := mkExtRule("allow", "in", "any", "any", "any"); r.IfaceIn = "eth0"; return r }(),
			mkExtRule("deny", "in", "any", "any", "any"),
			true,
		},
		{
			"different direction never shadows",
			mkExtRule("allow", "out", "any", "any", "any"),
			mkExtRule("deny", "in", "any", "any", "any"),
			false,
		},
		{
			"different family never shadows",
			func() *rule.Rule { r := mkExtRule("allow", "in", "any", "any", "any"); r.SetV6(true); return r }(),
			mkExtRule("deny", "in", "any", "any", "any"),
			false,
		},
		{
			"udp port not covered by tcp port",
			mkExtRule("allow", "in", "udp", "any", "any", rule.PortRange{Lo: 53, Hi: 53, Proto: "udp"}),
			mkExtRule("deny", "in", "any", "any", "any", tcp22),
			false,
		},
		{
			"any-proto port covers tcp port",
			mkExtRule("allow", "in", "tcp", "any", "any", tcp22),
			mkExtRule("deny", "in", "any", "any", "any", rule.PortRange{Lo: 22, Hi: 22, Proto: "any"}),
			true,
		},
	}
	for _, c := range cases {
		if got := ruleSuperset(c.a, c.b); got != c.want {
			t.Errorf("%s: ruleSuperset = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestExpiredCount(t *testing.T) {
	now := time.Now().Unix()
	st := &store.State{
		Rules4: []rule.Rule{
			{ID: "keep1", Action: "allow"},
			{ID: "gone1", Action: "deny", ExpiresAt: now - 10},
			{ID: "keep2", Action: "allow", ExpiresAt: now + 3600},
		},
		Rules6: []rule.Rule{
			{ID: "gone2", Action: "deny", ExpiresAt: now - 1},
			{ID: "gone1", Action: "deny", ExpiresAt: now - 10}, // dual half
		},
	}
	if n := expiredCount(st, now); n != 3 {
		t.Fatalf("expiredCount = %d, want 3", n)
	}
	// Boundary: ExpiresAt == now counts as expired.
	st.Rules4[0].ExpiresAt = now
	if n := expiredCount(st, now); n != 4 {
		t.Fatalf("expiredCount at boundary = %d, want 4", n)
	}
	if n := expiredCount(&store.State{}, now); n != 0 {
		t.Fatalf("expiredCount on empty state = %d, want 0", n)
	}
}

func TestSSHAllowsPort(t *testing.T) {
	now := time.Now().Unix()
	tcp22 := rule.PortRange{Lo: 22, Hi: 22, Proto: "tcp"}
	cases := []struct {
		name string
		r    *rule.Rule
		want bool
	}{
		{"allow 22/tcp", mkExtRule("allow", "in", "tcp", "any", "any", tcp22), true},
		{"allow all ports", mkExtRule("allow", "in", "any", "any", "any"), true},
		{"limit 22/tcp counts", mkExtRule("limit", "in", "tcp", "any", "any", tcp22), true},
		{"deny 22/tcp", mkExtRule("deny", "in", "tcp", "any", "any", tcp22), false},
		{"allow 22 out", mkExtRule("allow", "out", "tcp", "any", "any", tcp22), false},
		{"allow 80/tcp only", mkExtRule("allow", "in", "tcp", "any", "any", rule.PortRange{Lo: 80, Hi: 80, Proto: "tcp"}), false},
		{"allow 20:25/tcp covers", mkExtRule("allow", "in", "tcp", "any", "any", rule.PortRange{Lo: 20, Hi: 25, Proto: "tcp"}), true},
		{"udp 22 does not count", mkExtRule("allow", "in", "udp", "any", "any", rule.PortRange{Lo: 22, Hi: 22, Proto: "udp"}), false},
		{"disabled rule ignored", func() *rule.Rule {
			r := mkExtRule("allow", "in", "tcp", "any", "any", tcp22)
			r.Disabled = true
			return r
		}(), false},
		{"expired rule ignored", func() *rule.Rule {
			r := mkExtRule("allow", "in", "tcp", "any", "any", tcp22)
			r.ExpiresAt = now - 1
			return r
		}(), false},
	}
	for _, c := range cases {
		if got := sshAllowsPort(c.r, now); got != c.want {
			t.Errorf("%s: sshAllowsPort = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestNormalizeNft(t *testing.T) {
	in := "table inet better-firewall {\n" +
		"\tchain input {\n" +
		"\t\ttcp dport 22 counter packets 5 bytes 300 accept # handle 12\n" +
		"\t}\n" +
		"}\n"
	got := normalizeNft(in)
	want := []string{
		"table inet better-firewall {",
		"chain input {",
		"tcp dport 22 accept",
		"}",
		"}",
	}
	if len(got) != len(want) {
		t.Fatalf("normalizeNft = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("normalizeNft[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestUnifiedDiff(t *testing.T) {
	a := []string{"l1", "l2", "l3", "l4", "l5"}
	b := []string{"l1", "l2", "lX", "l4", "l5", "l6"}
	out := unifiedDiff("stored", "kernel", a, b)
	for _, frag := range []string{"--- stored", "+++ kernel", "@@ ", "-l3", "+lX", "+l6"} {
		if !strings.Contains(out, frag) {
			t.Errorf("diff missing %q:\n%s", frag, out)
		}
	}
	if unifiedDiff("a", "b", a, a) != "--- a\n+++ b\n" {
		t.Errorf("identical inputs should produce header-only diff")
	}
}

func TestSetReferenced(t *testing.T) {
	st := &store.State{
		Rules4: []rule.Rule{
			{ID: "r1", Src: rule.AddrSpec{Set: "badguys"}},
			{ID: "r2", Dst: rule.AddrSpec{Set: "other"}},
		},
		Rules6: []rule.Rule{
			{ID: "r1", Src: rule.AddrSpec{Set: "badguys"}}, // dual half: same ID
		},
	}
	if n := setReferenced(st, "badguys"); n != 1 {
		t.Errorf("setReferenced(badguys) = %d, want 1 (dual halves share ID)", n)
	}
	if n := setReferenced(st, "other"); n != 1 {
		t.Errorf("setReferenced(other) = %d, want 1", n)
	}
	if n := setReferenced(st, "missing"); n != 0 {
		t.Errorf("setReferenced(missing) = %d, want 0", n)
	}
}
