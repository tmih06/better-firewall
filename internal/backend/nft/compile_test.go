package nft

import (
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"

	"bfirewall/internal/rule"
	"bfirewall/internal/store"
)

func fixtureState() *store.State {
	st := store.Defaults()
	mk := func(id, action, dir, proto string, src, dst rule.AddrSpec) rule.Rule {
		return rule.Rule{ID: id, Action: action, Direction: dir, Proto: proto, Src: src, Dst: dst}
	}
	any := rule.AddrSpec{IP: "any"}
	st.Rules4 = []rule.Rule{
		mk("r1", "allow", "in", "tcp", any, rule.AddrSpec{IP: "any", Ports: []rule.PortRange{{Lo: 22, Hi: 22, Proto: "tcp"}}}),
		mk("r2", "deny", "in", "any", rule.AddrSpec{IP: "10.0.0.0/8"}, any),
		mk("r3", "limit", "in", "tcp", any, rule.AddrSpec{IP: "any", Ports: []rule.PortRange{{Lo: 22, Hi: 22, Proto: "tcp"}}}),
		mk("r4", "reject", "out", "tcp", any, rule.AddrSpec{IP: "any", Ports: []rule.PortRange{{Lo: 25, Hi: 25, Proto: "tcp"}}}),
		mk("r5", "allow", "routed", "udp", rule.AddrSpec{IP: "192.168.0.0/16"}, rule.AddrSpec{IP: "any", Ports: []rule.PortRange{{Lo: 80, Hi: 80, Proto: "udp"}, {Lo: 443, Hi: 443, Proto: "udp"}, {Lo: 8000, Hi: 8100, Proto: "udp"}}}),
		{ID: "r6", Action: "allow", Direction: "in", Proto: "tcp", Log: "log",
			Src: rule.AddrSpec{IP: "any"}, Dst: rule.AddrSpec{IP: "any", Ports: []rule.PortRange{{Lo: 80, Hi: 80, Proto: "tcp"}}}},
		{ID: "r7", Action: "deny", Direction: "in", Proto: "any",
			Src: rule.AddrSpec{IP: "any", Set: "badguys"}, Dst: rule.AddrSpec{IP: "any"}},
	}
	st.Rules6 = []rule.Rule{
		mk("r1", "allow", "in", "tcp", any, rule.AddrSpec{IP: "any", Ports: []rule.PortRange{{Lo: 22, Hi: 22, Proto: "tcp"}}}),
		mk("r8", "allow", "in", "tcp", rule.AddrSpec{IP: "fe80::/10"}, any),
	}
	st.Sets = []store.IPSet{
		{Name: "badguys", Family: "inet", Elements: []string{"203.0.113.0/24", "198.51.100.7", "2001:db8::/32"}},
	}
	st.NAT = []store.NATRule{
		{Kind: "masquerade", IfaceOut: "eth0", Src: "10.0.0.0/8"},
		{Kind: "dnat", Proto: "tcp", Dport: 8080, ToDest: "10.0.0.5:80"},
	}
	return st
}

func chainNames(c *compiled) map[string]bool {
	m := map[string]bool{}
	for _, ch := range c.chains {
		m[ch.Name] = true
	}
	return m
}

func rulesIn(c *compiled, chain string) []*nftables.Rule {
	var out []*nftables.Rule
	ch := c.chainIndex[chain]
	for _, r := range c.rules {
		if r.Chain == ch {
			out = append(out, r)
		}
	}
	return out
}

func TestCompileStructure(t *testing.T) {
	c, err := compile(fixtureState(), nil)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	names := chainNames(c)

	// base chains with hooks and policies
	for _, base := range []string{"input", "output", "forward"} {
		ch := c.chainIndex[base]
		if ch == nil {
			t.Fatalf("missing base chain %s", base)
		}
		if ch.Hooknum == nil || ch.Priority == nil || ch.Type != nftables.ChainTypeFilter {
			t.Fatalf("base chain %s missing hook/priority/type", base)
		}
	}
	// defaults: input deny→drop, output allow→accept, forward deny→drop
	if *c.chainIndex["input"].Policy != nftables.ChainPolicyDrop {
		t.Error("input policy should be drop")
	}
	if *c.chainIndex["output"].Policy != nftables.ChainPolicyAccept {
		t.Error("output policy should be accept")
	}
	if *c.chainIndex["forward"].Policy != nftables.ChainPolicyDrop {
		t.Error("forward policy should be drop")
	}

	// ufw chain layout
	for _, want := range []string{
		"bfw-before-input", "bfw-before-output", "bfw-before-forward",
		"bfw-user-input", "bfw-user-output", "bfw-user-forward",
		"bfw-after-input", "bfw-after-output", "bfw-after-forward",
		"bfw-before-logging-input", "bfw-before-logging-output", "bfw-before-logging-forward",
		"bfw-after-logging-input", "bfw-after-logging-output", "bfw-after-logging-forward",
		"bfw-user-logging-input", "bfw-user-logging-output", "bfw-user-logging-forward",
		"bfw-reject-input", "bfw-reject-output", "bfw-reject-forward",
		"bfw-track-input", "bfw-track-output", "bfw-track-forward",
		"bfw-skip-to-policy-input", "bfw-skip-to-policy-output", "bfw-skip-to-policy-forward",
		chNotLocal, chLogDeny, chLogAllow, chUserLimit, chUserLimitA, chUserEgress,
	} {
		if !names[want] {
			t.Errorf("missing chain %s", want)
		}
	}

	// base chain jump order: before-logging, before, user, after,
	// after-logging, reject, track (user jump moved to base chain so
	// before.rules fragments run before user rules).
	in := rulesIn(c, "input")
	if len(in) != 7 {
		t.Fatalf("input base chain has %d rules, want 7 jumps", len(in))
	}
	wantJumps := []string{
		"bfw-before-logging-input", "bfw-before-input", "bfw-user-input",
		"bfw-after-input", "bfw-after-logging-input", "bfw-reject-input", "bfw-track-input",
	}
	for i, w := range wantJumps {
		v, ok := in[i].Exprs[len(in[i].Exprs)-1].(*expr.Verdict)
		if !ok || v.Kind != expr.VerdictJump || v.Chain != w {
			t.Errorf("input rule %d: last expr = %+v, want jump %s", i, in[i].Exprs[len(in[i].Exprs)-1], w)
		}
	}

	// user-input rules: r1 allow, r2 deny, r3 limit pair, r6 log jump+allow, r7 set deny
	user := rulesIn(c, "bfw-user-input")
	if len(user) == 0 {
		t.Fatal("no user-input rules")
	}

	// limit rule produced a dynamic set
	var dynset *nftables.Set
	for _, s := range c.sets {
		if s.Name == "bfw_limit_r3" {
			dynset = s
		}
	}
	if dynset == nil {
		t.Fatal("missing bfw_limit_r3 dynamic set")
	}
	if !dynset.Dynamic || !dynset.HasTimeout || !dynset.Concatenation {
		t.Error("limit set missing dynamic/timeout/concat flags")
	}

	// named sets: v4 + v6 always created
	var s4, s6 *nftables.Set
	for _, s := range c.sets {
		if s.Name == "bfw_set_badguys" {
			s4 = s
		}
		if s.Name == "bfw_set_badguys6" {
			s6 = s
		}
	}
	if s4 == nil || s6 == nil {
		t.Fatal("missing named sets")
	}
	if got := len(c.elems[s4]); got != 4 { // 2 elements × (start,end) pairs
		t.Errorf("v4 set has %d elements, want 4", got)
	}
	if got := len(c.elems[s6]); got != 2 {
		t.Errorf("v6 set has %d elements, want 2", got)
	}

	// multiport rule produced an anonymous interval set
	var anon *nftables.Set
	for _, s := range c.sets {
		if s.Anonymous {
			anon = s
		}
	}
	if anon == nil || !anon.Interval {
		t.Fatal("missing anonymous interval set for multiport")
	}
	if anon.ID == 0 || anon.Name == "" {
		t.Error("anonymous set missing pre-assigned ID/name")
	}

	// NAT tables
	if len(c.natTables) != 2 {
		t.Fatalf("natTables = %d, want 2", len(c.natTables))
	}
	var masq, dnat bool
	for _, r := range c.rules {
		for _, e := range r.Exprs {
			if _, ok := e.(*expr.Masq); ok {
				masq = true
			}
			if n, ok := e.(*expr.NAT); ok && n.Type == expr.NATTypeDestNAT {
				dnat = true
			}
		}
	}
	if !masq || !dnat {
		t.Errorf("nat rules missing: masq=%v dnat=%v", masq, dnat)
	}

	// every rule carries a counter except pure log/limit exprs — check
	// verdict-bearing rules have a counter somewhere
	for _, r := range c.rules {
		hasVerdict := false
		hasCounter := false
		for _, e := range r.Exprs {
			switch e.(type) {
			case *expr.Verdict:
				hasVerdict = true
			case *expr.Counter:
				hasCounter = true
			}
		}
		if hasVerdict && !hasCounter {
			t.Errorf("rule in %s has verdict but no counter", r.Chain.Name)
		}
	}
}

func TestCompileIPv6Disabled(t *testing.T) {
	st := store.Defaults()
	st.IPv6 = false
	c, err := compile(st, nil)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	in := rulesIn(c, "input")
	// first rules: nfproto ipv6 iifname lo accept; nfproto ipv6 drop
	if len(in) < 8 {
		t.Fatalf("input has %d rules, want v6-drop + 6 jumps", len(in))
	}
	found := false
	for _, r := range in {
		for _, e := range r.Exprs {
			if v, ok := e.(*expr.Verdict); ok && v.Kind == expr.VerdictDrop {
				found = true
			}
		}
	}
	if !found {
		t.Error("no v6 drop rule in input base chain")
	}
}

func TestCompileLoggingOff(t *testing.T) {
	st := store.Defaults()
	st.Logging = "off"
	c, err := compile(st, nil)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// user-logging chains get a RETURN at top
	rs := rulesIn(c, "bfw-user-logging-input")
	if len(rs) == 0 {
		t.Fatal("no rules in bfw-user-logging-input with logging off")
	}
	v, ok := rs[0].Exprs[len(rs[0].Exprs)-1].(*expr.Verdict)
	if !ok || v.Kind != expr.VerdictReturn {
		t.Error("first user-logging rule should be RETURN when logging off")
	}
	// after-logging chains stay empty
	if n := len(rulesIn(c, "bfw-after-logging-input")); n != 0 {
		t.Errorf("after-logging-input has %d rules with logging off", n)
	}
}

func TestCompileRejectPolicy(t *testing.T) {
	st := store.Defaults()
	st.Policies.Input = "reject"
	c, err := compile(st, nil)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	rs := rulesIn(c, "bfw-reject-input")
	if len(rs) != 1 {
		t.Fatalf("bfw-reject-input has %d rules, want 1", len(rs))
	}
	if _, ok := rs[0].Exprs[len(rs[0].Exprs)-1].(*expr.Reject); !ok {
		t.Error("reject chain missing terminal reject expr")
	}
	if *c.chainIndex["input"].Policy != nftables.ChainPolicyDrop {
		t.Error("reject policy should still map base chain to drop")
	}
}

func TestRenderTextDeterministic(t *testing.T) {
	st := fixtureState()
	a, err := RenderText(st, nil)
	if err != nil {
		t.Fatalf("RenderText: %v", err)
	}
	b, err := RenderText(st, nil)
	if err != nil {
		t.Fatalf("RenderText: %v", err)
	}
	if a != b {
		t.Error("RenderText not deterministic")
	}
	for _, want := range []string{
		"table inet bfirewall {",
		"chain input {",
		"type filter hook input priority 0; policy drop;",
		"set bfw_set_badguys {",
		"set bfw_limit_r3 {",
		"table ip bfirewall-nat {",
		"masquerade",
		"dnat to 10.0.0.5:80",
		"jump bfw-user-input",
		"ct state established,related",
		"fib daddr type local",
		"log prefix \"[BFW BLOCK] \"",
	} {
		if !strings.Contains(a, want) {
			t.Errorf("rendered text missing %q", want)
		}
	}
}
