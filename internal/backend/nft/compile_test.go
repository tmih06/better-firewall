package nft

import (
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"github.com/tmih06/better-firewall/internal/rule"
	"github.com/tmih06/better-firewall/internal/store"
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

func TestUserChainMapping(t *testing.T) {
	cases := []struct {
		direction string
		user      string
		logging   string
	}{
		{direction: rule.DirIn, user: "bfw-user-input", logging: "bfw-user-logging-input"},
		{direction: rule.DirOut, user: "bfw-user-output", logging: "bfw-user-logging-output"},
		{direction: rule.DirRouted, user: "bfw-user-forward", logging: "bfw-user-logging-forward"},
		{direction: "unexpected", user: "bfw-user-input", logging: "bfw-user-logging-input"},
	}
	for _, tc := range cases {
		t.Run(tc.direction, func(t *testing.T) {
			if got := userChainFor(tc.direction); got != tc.user {
				t.Errorf("userChainFor(%q) = %q, want %q", tc.direction, got, tc.user)
			}
			if got := userLoggingChainFor(tc.direction); got != tc.logging {
				t.Errorf("userLoggingChainFor(%q) = %q, want %q", tc.direction, got, tc.logging)
			}
		})
	}
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
	if c.setIndex[anon.ID] != anon {
		t.Error("anonymous set ID index does not point to the compiled set")
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

func TestOverridePolicyPreservesUnknownValues(t *testing.T) {
	for _, tc := range []struct {
		raw, want string
	}{
		{raw: "ACCEPT", want: "allow"},
		{raw: "allow", want: "allow"},
		{raw: "DROP", want: "deny"},
		{raw: "deny", want: "deny"},
		{raw: "REJECT", want: "reject"},
		{raw: "unexpected", want: "original"},
		{raw: "", want: "original"},
	} {
		if got := overridePolicy("original", tc.raw); got != tc.want {
			t.Errorf("overridePolicy(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestCompileICMPType(t *testing.T) {
	st := store.Defaults()
	st.IPv6 = true
	st.Rules6 = []rule.Rule{{
		ID: "nd", Action: rule.ActionAllow, Direction: rule.DirIn,
		Proto: "icmpv6", ICMPType: "135",
		Src: rule.AddrSpec{IP: "any"}, Dst: rule.AddrSpec{IP: "any"},
	}}
	text, err := RenderText(st, nil)
	if err != nil {
		t.Fatalf("RenderText: %v", err)
	}
	if !strings.Contains(text, "icmpv6 type neighbour-solicitation counter accept") {
		t.Fatalf("rendered ruleset omitted exact ICMPv6 type match:\n%s", text)
	}

	st.Rules4 = []rule.Rule{{
		ID: "bad-family", Action: rule.ActionAllow, Direction: rule.DirIn,
		Proto: "icmpv6", ICMPType: "135",
		Src: rule.AddrSpec{IP: "any"}, Dst: rule.AddrSpec{IP: "any"},
	}}
	if _, err := RenderText(st, nil); err == nil {
		t.Fatal("RenderText accepted an IPv6-only ICMP type in Rules4")
	}

	st.Rules4 = nil
	st.Rules6[0].Proto = "tcp"
	if _, err := RenderText(st, nil); err == nil {
		t.Fatal("RenderText accepted an ICMP type with TCP")
	}
	st.Rules6[0].Proto = "icmpv6"
	st.Rules6[0].Dst.Ports = []rule.PortRange{{Lo: 80, Hi: 80, Proto: "tcp"}}
	if _, err := RenderText(st, nil); err == nil {
		t.Fatal("RenderText accepted ports on an ICMP rule")
	}
}

func TestCompileThreatBansUseMergedAddressSetsBeforeEstablishedTraffic(t *testing.T) {
	now := time.Now().Unix()
	st := store.Defaults()
	st.Bans = []store.ThreatBan{
		{Address: "203.0.113.9", Source: "crowdsec", ExpiresAt: now + 3600},
		{Address: "203.0.113.9", Source: "ssh:sshd", ExpiresAt: now + 7200},
		{Address: "198.51.100.0/24", Source: "crowdsec", ExpiresAt: now + 3600},
		{Address: "198.51.100.9", Source: "ssh:sshd", ExpiresAt: now + 7200},
		{Address: "192.0.2.77", Source: "crowdsec", ExpiresAt: now},
		{Address: "2001:db8::7", Source: "crowdsec", ExpiresAt: now + 3600},
	}
	c, err := compile(st, nil)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	sets := map[string]*nftables.Set{}
	for _, set := range c.sets {
		sets[set.Name] = set
	}
	for _, name := range []string{"bfw_threat_bans", "bfw_threat_bans6"} {
		if sets[name] == nil || !sets[name].Interval || sets[name].HasTimeout {
			t.Fatalf("missing static interval set %q", name)
		}
	}
	if got := len(c.elems[sets["bfw_threat_bans"]]); got != 4 {
		t.Fatalf("IPv4 threat elements = %d, want two merged address intervals", got)
	}
	if got := len(c.elems[sets["bfw_threat_bans6"]]); got != 2 {
		t.Fatalf("IPv6 threat elements = %d, want one address interval", got)
	}

	text, err := RenderText(st, nil)
	if err != nil {
		t.Fatalf("RenderText: %v", err)
	}
	for _, want := range []string{"ip saddr @bfw_threat_bans", "ip6 saddr @bfw_threat_bans6", "flags interval"} {
		if !strings.Contains(text, want) {
			t.Fatalf("rendered ruleset omitted %q:\n%s", want, text)
		}
	}
	banAt := strings.Index(text, "ip saddr @bfw_threat_bans")
	establishedAt := strings.Index(text, "ct state established,related")
	if banAt < 0 || establishedAt < 0 || banAt > establishedAt {
		t.Fatalf("threat ban must precede established-flow acceptance:\n%s", text)
	}
	if strings.Contains(text, "192.0.2.77") {
		t.Fatalf("expired threat address was compiled:\n%s", text)
	}
}

func TestCompileLimitUsesFamilySpecificRegisters(t *testing.T) {
	st := store.Defaults()
	st.Rules4 = []rule.Rule{{
		ID: "four", Action: rule.ActionLimit, Direction: rule.DirIn, Proto: "tcp",
		Src: rule.AddrSpec{IP: "any"},
		Dst: rule.AddrSpec{IP: "any", Ports: []rule.PortRange{{Lo: 443, Hi: 443, Proto: "tcp"}}},
	}}
	st.Rules6 = []rule.Rule{{
		ID: "six", Action: rule.ActionLimit, Direction: rule.DirIn, Proto: "tcp",
		Src: rule.AddrSpec{IP: "any"},
		Dst: rule.AddrSpec{IP: "any", Ports: []rule.PortRange{{Lo: 443, Hi: 443, Proto: "tcp"}}},
	}}
	c, err := compile(st, nil)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	want := map[string]struct {
		sreg, preg     uint32
		offset, length uint32
	}{
		"bfw_limit_four": {sreg: unix.NFT_REG32_00, preg: unix.NFT_REG32_01, offset: 12, length: 4},
		"bfw_limit_six6": {sreg: unix.NFT_REG_1, preg: unix.NFT_REG_2, offset: 8, length: 16},
	}
	found := map[string]bool{}
	for _, compiledRule := range c.rules {
		if compiledRule.Chain.Name != "bfw-user-input" {
			continue
		}
		for _, raw := range compiledRule.Exprs {
			dyn, ok := raw.(*expr.Dynset)
			if !ok {
				continue
			}
			w, ok := want[dyn.SetName]
			if !ok {
				t.Fatalf("unexpected limit set %q", dyn.SetName)
			}
			if dyn.SrcRegKey != w.sreg {
				t.Errorf("%s source register = %d, want %d", dyn.SetName, dyn.SrcRegKey, w.sreg)
			}
			hasAddress, hasPort := false, false
			for _, expression := range compiledRule.Exprs {
				p, ok := expression.(*expr.Payload)
				if !ok {
					continue
				}
				if p.Base == expr.PayloadBaseNetworkHeader && p.Offset == w.offset && p.Len == w.length && p.DestRegister == w.sreg {
					hasAddress = true
				}
				if p.Base == expr.PayloadBaseTransportHeader && p.Offset == 2 && p.Len == 2 && p.DestRegister == w.preg {
					hasPort = true
				}
			}
			if !hasAddress || !hasPort {
				t.Errorf("%s missing family-specific key payloads: address=%v port=%v", dyn.SetName, hasAddress, hasPort)
			}
			found[dyn.SetName] = true
		}
	}
	for name := range want {
		if !found[name] {
			t.Errorf("missing compiled limit set %q", name)
		}
	}
}

func TestRuleArenaKeepsPointersStableAcrossChunks(t *testing.T) {
	table := &nftables.Table{Name: "arena"}
	chain := &nftables.Chain{Name: "input", Table: table}
	c := &compiled{
		table:   table,
		rules:   make([]*nftables.Rule, 0, 128),
		ruleCap: 2,
	}
	for i := 0; i < 100; i++ {
		c.addRuleObject(table, chain, []expr.Any{&expr.Counter{}})
	}
	if len(c.ruleArenas) < 2 {
		t.Fatalf("rule arena did not exercise chunk rollover: got %d chunks", len(c.ruleArenas))
	}
	for i, r := range c.rules {
		if r.Table != table || r.Chain != chain {
			t.Errorf("rule %d points at the wrong table or chain", i)
		}
		if len(r.Exprs) != 1 {
			t.Errorf("rule %d expression count = %d, want 1", i, len(r.Exprs))
		}
	}
}

func TestExprArenaKeepsSlicesDisjointAcrossChunks(t *testing.T) {
	c := &compiled{}
	first := c.exprSlice(2)
	first = append(first, &expr.Counter{}, &expr.Verdict{Kind: expr.VerdictAccept})
	second := c.exprSlice(2)
	second = append(second, &expr.Counter{}, &expr.Verdict{Kind: expr.VerdictDrop})
	if len(c.exprArenas) != 1 {
		t.Fatalf("expr arena count = %d, want one chunk", len(c.exprArenas))
	}
	if first[0] == second[0] || first[1] == second[1] {
		t.Fatal("expression slices unexpectedly alias")
	}
	if first[1].(*expr.Verdict).Kind != expr.VerdictAccept {
		t.Fatal("first expression slice was overwritten")
	}
	if second[1].(*expr.Verdict).Kind != expr.VerdictDrop {
		t.Fatal("second expression slice was not retained")
	}

	// Force a new chunk and verify the first chunk remains address-stable.
	old := &first[0]
	_ = c.exprSlice(4096)
	if old != &first[0] {
		t.Fatal("expression arena moved a retained slice")
	}
}

func TestPortDataUsesBigEndianEncoding(t *testing.T) {
	for _, tc := range []struct {
		port uint16
		want []byte
	}{
		{0, []byte{0, 0}},
		{1, []byte{0, 1}},
		{0x1234, []byte{0x12, 0x34}},
		{0xffff, []byte{0xff, 0xff}},
	} {
		got := portData(tc.port)
		if len(got) != len(tc.want) || got[0] != tc.want[0] || got[1] != tc.want[1] {
			t.Errorf("portData(%d) = %v, want %v", tc.port, got, tc.want)
		}
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

func TestCompileLoggedRuleKeepsIndependentTerminalRules(t *testing.T) {
	st := store.Defaults()
	st.Rules4 = []rule.Rule{{
		ID: "logged", Action: rule.ActionAllow, Direction: rule.DirIn,
		Proto: "tcp", Log: rule.LogAll,
		Src: rule.AddrSpec{IP: "any"},
		Dst: rule.AddrSpec{IP: "any", Ports: []rule.PortRange{{Lo: 443, Hi: 443, Proto: "tcp"}}},
	}}
	c, err := compile(st, nil)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	logging := rulesIn(c, "bfw-user-logging-input")
	if len(logging) != 2 {
		t.Fatalf("logged chain has %d rules, want log + return", len(logging))
	}
	last := func(r *nftables.Rule) expr.Any {
		return r.Exprs[len(r.Exprs)-1]
	}
	if _, ok := last(logging[0]).(*expr.Log); !ok {
		t.Fatalf("first logged rule was overwritten: last expression is %T", last(logging[0]))
	}
	if v, ok := last(logging[1]).(*expr.Verdict); !ok || v.Kind != expr.VerdictReturn {
		t.Fatalf("logged return rule = %T %+v, want return verdict", last(logging[1]), last(logging[1]))
	}

	user := rulesIn(c, "bfw-user-input")
	if len(user) < 2 {
		t.Fatalf("user chain has %d rules, want logging jump + accept", len(user))
	}
	if v, ok := last(user[len(user)-2]).(*expr.Verdict); !ok || v.Kind != expr.VerdictJump || v.Chain != "bfw-user-logging-input" {
		t.Fatalf("logging jump missing: %T %+v", last(user[len(user)-2]), last(user[len(user)-2]))
	}
	if v, ok := last(user[len(user)-1]).(*expr.Verdict); !ok || v.Kind != expr.VerdictAccept {
		t.Fatalf("terminal accept missing: %T %+v", last(user[len(user)-1]), last(user[len(user)-1]))
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
		"table inet better-firewall {",
		"chain input {",
		"type filter hook input priority 0; policy drop;",
		"set bfw_set_badguys {",
		"set bfw_limit_r3 {",
		"table ip better-firewall-nat {",
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

func TestCompileAnyPortsExpandToMatchingTransports(t *testing.T) {
	tests := []struct {
		name  string
		ports []rule.PortRange
		want  []byte
	}{
		{
			name:  "tcp only",
			ports: []rule.PortRange{{Lo: 80, Hi: 80, Proto: "tcp"}},
			want:  []byte{6},
		},
		{
			name:  "udp only",
			ports: []rule.PortRange{{Lo: 53, Hi: 53, Proto: "udp"}},
			want:  []byte{17},
		},
		{
			name:  "unspecified transport expands to tcp and udp",
			ports: []rule.PortRange{{Lo: 80, Hi: 80, Proto: "any"}},
			want:  []byte{6, 17},
		},
		{
			name: "no ports stays protocol agnostic",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := store.Defaults()
			st.Rules4 = []rule.Rule{{
				ID: "r1", Action: rule.ActionAllow, Direction: rule.DirIn, Proto: "any",
				Src: rule.AddrSpec{IP: "any"},
				Dst: rule.AddrSpec{IP: "any", Ports: tt.ports},
			}}
			c, err := compile(st, nil)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}

			compiledRules := rulesIn(c, "bfw-user-input")
			var got []byte
			for _, compiledRule := range compiledRules {
				for _, expression := range compiledRule.Exprs {
					cmp, ok := expression.(*expr.Cmp)
					if ok && len(cmp.Data) == 1 && (cmp.Data[0] == 6 || cmp.Data[0] == 17) {
						got = append(got, cmp.Data[0])
						break
					}
				}
			}
			if len(got) != len(tt.want) {
				t.Fatalf("compiled transports = %v, want %v", got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Fatalf("compiled transports = %v, want %v", got, tt.want)
				}
			}
		})
	}
}
