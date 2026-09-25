package impexp

import (
	"io"
	"strings"
	"testing"

	"github.com/tmih06/better-firewall/internal/rule"
	"github.com/tmih06/better-firewall/internal/store"
)

func iptImport(t *testing.T, st *store.State, v4, v6 string) (*store.State, int, []string) {
	t.Helper()
	var in4, in6 io.Reader
	if v4 != "" {
		in4 = strings.NewReader(v4)
	}
	if v6 != "" {
		in6 = strings.NewReader(v6)
	}
	out, n, warnings, err := ImportIPTables(in4, in6, st)
	if err != nil {
		t.Fatalf("ImportIPTables: %v", err)
	}
	return out, n, warnings
}

func iptImportErr(t *testing.T, st *store.State, v4, v6 string) error {
	t.Helper()
	var in4, in6 io.Reader
	if v4 != "" {
		in4 = strings.NewReader(v4)
	}
	if v6 != "" {
		in6 = strings.NewReader(v6)
	}
	_, _, _, err := ImportIPTables(in4, in6, st)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	return err
}

func onePort(t *testing.T, ports []rule.PortRange, lo, hi uint16, proto string) {
	t.Helper()
	if len(ports) != 1 || ports[0].Lo != lo || ports[0].Hi != hi || ports[0].Proto != proto {
		t.Fatalf("ports = %+v, want exactly {%d:%d %s}", ports, lo, hi, proto)
	}
}

func TestImportIPTablesBasicV4(t *testing.T) {
	out, n, warnings := iptImport(t, store.Defaults(), `# comment
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 22 -m comment --comment "ssh access" -j ACCEPT
-A INPUT -s 192.168.1.0/24 -p udp --dport 53 -j DROP
-A INPUT -j REJECT --reject-with icmp-port-unreachable
-A FORWARD -i eth0 -o eth1 -j ACCEPT
-A OUTPUT -d 10.0.0.1 -p tcp --dport 443 -j ACCEPT
-A INPUT -p tcp --dport 80
COMMIT
`, "")

	if n != 5 {
		t.Fatalf("added = %d, want 5", n)
	}
	if len(out.Rules4) != 5 {
		t.Fatalf("Rules4 = %d, want 5", len(out.Rules4))
	}
	if len(out.Rules6) != 0 {
		t.Fatalf("Rules6 = %d, want 0", len(out.Rules6))
	}
	if out.Policies.Input != "deny" || out.Policies.Output != "allow" || out.Policies.Forward != "deny" {
		t.Fatalf("policies = %+v", out.Policies)
	}

	// Order is preserved: ssh, udp-53 drop, reject, forward, output-443.
	rs := out.Rules4
	if rs[0].Action != "allow" || rs[0].Direction != "in" || rs[0].Proto != "tcp" {
		t.Fatalf("rule 0 = %+v", rs[0])
	}
	onePort(t, rs[0].Dst.Ports, 22, 22, "tcp")
	if rs[0].Comment != "ssh access" {
		t.Fatalf("rule 0 comment = %q", rs[0].Comment)
	}
	if rs[1].Action != "deny" || rs[1].Src.IP != "192.168.1.0/24" || rs[1].Proto != "udp" {
		t.Fatalf("rule 1 = %+v", rs[1])
	}
	onePort(t, rs[1].Dst.Ports, 53, 53, "udp")
	if rs[2].Action != "reject" || rs[2].Direction != "in" {
		t.Fatalf("rule 2 = %+v", rs[2])
	}
	if rs[3].Direction != "routed" || rs[3].IfaceIn != "eth0" || rs[3].IfaceOut != "eth1" {
		t.Fatalf("rule 3 = %+v", rs[3])
	}
	if rs[4].Direction != "out" || rs[4].Dst.IP != "10.0.0.1" {
		t.Fatalf("rule 4 = %+v", rs[4])
	}
	onePort(t, rs[4].Dst.Ports, 443, 443, "tcp")

	// The accounting-only --dport 80 rule warns and is not imported.
	sawAcct := false
	for _, w := range warnings {
		if strings.Contains(w, "accounting-only") {
			sawAcct = true
		}
	}
	if !sawAcct {
		t.Errorf("missing accounting-only warning in %v", warnings)
	}
}

func TestImportIPTablesV6(t *testing.T) {
	out, n, _ := iptImport(t, store.Defaults(), "", `*filter
:INPUT DROP [0:0]
:FORWARD - [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p icmpv6 -j ACCEPT
-A INPUT -s 2001:db8::/32 -p tcp --dport 80 -j ACCEPT
COMMIT
`)
	if n != 2 || len(out.Rules6) != 2 {
		t.Fatalf("added = %d, Rules6 = %d; want 2", n, len(out.Rules6))
	}
	if len(out.Rules4) != 0 {
		t.Fatalf("Rules4 = %d, want 0", len(out.Rules4))
	}
	if !out.IPv6 {
		t.Error("IPv6 flag not set by v6 import")
	}
	if out.Rules6[0].Proto != "icmpv6" || out.Rules6[0].Action != "allow" {
		t.Fatalf("v6 rule 0 = %+v", out.Rules6[0])
	}
	if out.Rules6[1].Src.IP != "2001:db8::/32" {
		t.Fatalf("v6 rule 1 src = %q", out.Rules6[1].Src.IP)
	}
	if !out.Rules6[0].V6() || !out.Rules6[1].V6() {
		t.Error("v6 rules not marked v6")
	}
	// INPUT policy applied; "-" forward and absent stream leave defaults.
	if out.Policies.Input != "deny" || out.Policies.Output != "allow" || out.Policies.Forward != "deny" {
		t.Fatalf("policies = %+v", out.Policies)
	}
}

func TestImportIPTablesDualFamilySharedID(t *testing.T) {
	v4 := `*filter
:INPUT DROP [0:0]
-A INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
`
	v6 := `*filter
:INPUT DROP [0:0]
-A INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
`
	out, n, _ := iptImport(t, store.Defaults(), v4, v6)
	if n != 2 || len(out.Rules4) != 1 || len(out.Rules6) != 1 {
		t.Fatalf("added = %d, Rules4 = %d, Rules6 = %d", n, len(out.Rules4), len(out.Rules6))
	}
	if out.Rules4[0].ID != out.Rules6[0].ID {
		t.Errorf("dual rule IDs differ: %q vs %q", out.Rules4[0].ID, out.Rules6[0].ID)
	}
}

func TestImportIPTablesOrderAndInsert(t *testing.T) {
	st := store.Defaults()
	st.IPv6 = false // v4-only stream; keep the run free of policy catchalls
	out, _, _ := iptImport(t, st, `*filter
:INPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 80 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT
-I INPUT 2 -p tcp --dport 81 -j ACCEPT
-I INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
`, "")
	rs := out.Rules4
	want := []uint16{22, 80, 81, 443} // -I 1 prepends, -I 2 lands between
	if len(rs) != len(want) {
		t.Fatalf("Rules4 = %d, want %d", len(rs), len(want))
	}
	for i, w := range want {
		if len(rs[i].Dst.Ports) != 1 || rs[i].Dst.Ports[0].Lo != w {
			t.Fatalf("rule %d ports = %+v, want %d", i, rs[i].Dst.Ports, w)
		}
	}
}

func TestImportIPTablesMatches(t *testing.T) {
	st := store.Defaults()
	st.IPv6 = false
	out, _, _ := iptImport(t, st, `*filter
:INPUT ACCEPT [0:0]
-A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT
-A INPUT -p udp --sport 1024:65535 -j ACCEPT
-A INPUT -p tcp --dport :1024 -j DROP
-A INPUT -s 10.0.0.0/255.255.0.0 -j DROP
-A INPUT -s 0.0.0.0/0 -j DROP
-A INPUT -p tcp -m tcp --dport 8080 -j ACCEPT
-A INPUT -p udp -m udp --dport 5353 -j ACCEPT
COMMIT
`, "")
	rs := out.Rules4
	if len(rs) != 7 {
		t.Fatalf("Rules4 = %d, want 7", len(rs))
	}
	if len(rs[0].Dst.Ports) != 2 || rs[0].Dst.Ports[0].Lo != 80 || rs[0].Dst.Ports[1].Lo != 443 {
		t.Fatalf("multiport = %+v", rs[0].Dst.Ports)
	}
	onePort(t, rs[1].Src.Ports, 1024, 65535, "udp")
	onePort(t, rs[2].Dst.Ports, 0, 1024, "tcp")
	if rs[3].Src.IP != "10.0.0.0/16" {
		t.Fatalf("dotted netmask = %q, want 10.0.0.0/16", rs[3].Src.IP)
	}
	if rs[4].Src.IP != "any" && rs[4].Src.IP != "0.0.0.0/0" {
		t.Fatalf("wildcard src = %q", rs[4].Src.IP)
	}
	// -p tcp -m tcp agree and bind the destination-port match to tcp.
	if rs[5].Proto != "tcp" {
		t.Fatalf("-m tcp rule proto = %q, want tcp", rs[5].Proto)
	}
	onePort(t, rs[5].Dst.Ports, 8080, 8080, "tcp")
	// -p udp -m udp agree → udp.
	if rs[6].Proto != "udp" {
		t.Fatalf("-p udp -m udp proto = %q, want udp", rs[6].Proto)
	}
	onePort(t, rs[6].Dst.Ports, 5353, 5353, "udp")
}

func TestImportIPTablesMergeDeduplicates(t *testing.T) {
	dump := `*filter
:INPUT DROP [0:0]
-A INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
`
	st := store.Defaults()
	out1, n1, _, err := ImportIPTables(strings.NewReader(dump), nil, st)
	if err != nil {
		t.Fatalf("first import: %v", err)
	}
	if n1 != 1 || len(out1.Rules4) != 1 {
		t.Fatalf("first import added = %d", n1)
	}
	// Re-importing the identical dump deduplicates.
	out2, n2, _, err := ImportIPTables(strings.NewReader(dump), nil, out1)
	if err != nil {
		t.Fatalf("second import: %v", err)
	}
	if n2 != 0 || len(out2.Rules4) != 1 {
		t.Fatalf("second import added = %d, Rules4 = %d", n2, len(out2.Rules4))
	}
}

func TestImportIPTablesLeavesInputUnchanged(t *testing.T) {
	st := store.Defaults()
	st.Policies.Input = "reject"
	bad := `*filter
:INPUT DROP [0:0]
-A INPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT
COMMIT
`
	if _, _, _, err := ImportIPTables(strings.NewReader(bad), nil, st); err == nil {
		t.Fatal("expected error")
	}
	if len(st.Rules4) != 0 || st.Policies.Input != "reject" {
		t.Fatalf("input state mutated on error: %+v", st)
	}
	// A successful import must not mutate st either. st.Input=reject is
	// laxer than the dump's deny on the strictness ladder (deny > reject >
	// allow), so out takes deny and the v6 side keeps reject via a
	// catchall — n counts the rule plus that catchall.
	good := `*filter
:INPUT DROP [0:0]
-A INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
`
	out, n, _, err := ImportIPTables(strings.NewReader(good), nil, st)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if n != 2 || len(st.Rules4) != 0 || st.Policies.Input != "reject" || out.Policies.Input != "deny" {
		t.Fatalf("st mutated or merge wrong: st=%+v out policies=%+v n=%d", st, out.Policies, n)
	}
	c := iptCatchall(t, out.Rules6, "in")
	if c == nil || c.Action != "reject" {
		t.Fatalf("v6 input reject catchall missing: %+v", out.Rules6)
	}
}

func TestImportIPTablesUnreachableChainWarns(t *testing.T) {
	st := store.Defaults()
	st.IPv6 = false
	out, n, warnings := iptImport(t, st, `*filter
:INPUT ACCEPT [0:0]
:MYDROP - [0:0]
-A MYDROP -j DROP
-A INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
`, "")
	if n != 1 || len(out.Rules4) != 1 {
		t.Fatalf("added = %d, want 1", n)
	}
	saw := false
	for _, w := range warnings {
		if strings.Contains(w, "unreachable") && strings.Contains(w, "MYDROP") {
			saw = true
		}
	}
	if !saw {
		t.Errorf("missing unreachable-chain warning in %v", warnings)
	}
}

func TestImportIPTablesReturnTail(t *testing.T) {
	// Unconditional RETURN as the last rule is a no-op; rules after it are
	// dead in the source and dropped with a warning.
	out, n, warnings := iptImport(t, store.Defaults(), `*filter
:INPUT DROP [0:0]
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -j RETURN
-A INPUT -p tcp --dport 25 -j ACCEPT
COMMIT
`, "")
	if n != 1 || len(out.Rules4) != 1 {
		t.Fatalf("added = %d, want 1 (RETURN tail + dead rule skipped)", n)
	}
	saw := false
	for _, w := range warnings {
		if strings.Contains(w, "unreachable") {
			saw = true
		}
	}
	if !saw {
		t.Errorf("missing dead-after-RETURN warning in %v", warnings)
	}
}

func TestImportIPTablesRejections(t *testing.T) {
	cases := []struct {
		name string
		v4   string
		v6   string
		want string
	}{
		{"nat table with rule",
			`*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -o eth0 -j MASQUERADE
COMMIT
*filter
:INPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
`, "", "table nat"},
		{"nat table non-accept policy",
			`*nat
:POSTROUTING DROP [0:0]
COMMIT
*filter
:INPUT ACCEPT [0:0]
-A INPUT -j ACCEPT
COMMIT
`, "", "table nat"},
		{"conntrack non-idiom state",
			`*filter
:INPUT ACCEPT [0:0]
-A INPUT -m conntrack --ctstate NEW -j ACCEPT
COMMIT
`, "", "conntrack"},
		{"conntrack state with extra match",
			`*filter
:INPUT ACCEPT [0:0]
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -s 10.0.0.1 -j ACCEPT
COMMIT
`, "", "conntrack"},
		{"conntrack accept mid-chain",
			`*filter
:INPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 22 -j DROP
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
COMMIT
`, "", "mid-chain"},
		{"conntrack with non-accept verdict",
			`*filter
:INPUT ACCEPT [0:0]
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j DROP
COMMIT
`, "", "conntrack"},
		{"state match",
			`*filter
:INPUT ACCEPT [0:0]
-A INPUT -m state --state NEW -j ACCEPT
COMMIT
`, "", "conntrack"},
		{"ctstate without module",
			`*filter
:INPUT ACCEPT [0:0]
-A INPUT --ctstate RELATED,ESTABLISHED -j ACCEPT
COMMIT
`, "", "requires -m"},
		{"protocol number 0",
			`*filter
:INPUT ACCEPT [0:0]
-A INPUT -p 0 -j ACCEPT
COMMIT
`, "", "protocol number 0"},
		{"icmp type with code qualifier",
			`*filter
:INPUT ACCEPT [0:0]
-A INPUT -p icmp --icmp-type 3/1 -j ACCEPT
COMMIT
`, "", "code qualifier"},
		{"icmp type on wrong proto",
			`*filter
:INPUT ACCEPT [0:0]
-A INPUT -p tcp --icmp-type 8 -j ACCEPT
COMMIT
`, "", "requires -p icmp"},
		{"icmpv6 type on v4 proto",
			`*filter
:INPUT ACCEPT [0:0]
-A INPUT -p icmp --icmpv6-type 128 -j ACCEPT
COMMIT
`, "", "requires -p icmpv6"},
		{"protocol module without -p",
			`*filter
:INPUT ACCEPT [0:0]
-A INPUT -m tcp -j ACCEPT
COMMIT
`, "", "requires -p tcp"},
		{"icmp type module without -p",
			`*filter
:INPUT ACCEPT [0:0]
-A INPUT -m icmp --icmp-type 8 -j ACCEPT
COMMIT
`, "", "requires -p icmp"},
		{"bare icmp type",
			`*filter
:INPUT ACCEPT [0:0]
-A INPUT --icmp-type 8 -j ACCEPT
COMMIT
`, "", "requires -p icmp"},
		{"icmp type contradicts -m udp",
			`*filter
:INPUT ACCEPT [0:0]
-A INPUT -p icmp -m udp --icmp-type 8 -j ACCEPT
COMMIT
`, "", "contradicts"},
		{"duplicate icmp type",
			`*filter
:INPUT ACCEPT [0:0]
-A INPUT -p icmp --icmp-type 8 --icmp-type 0 -j ACCEPT
COMMIT
`, "", "duplicate"},
		{"negated source",
			`*filter
:INPUT ACCEPT [0:0]
-A INPUT ! -s 10.0.0.1 -j ACCEPT
COMMIT
`, "", "negation"},
		{"negated source glued",
			`*filter
:INPUT ACCEPT [0:0]
-A INPUT -s ! 10.0.0.1 -j ACCEPT
COMMIT
`, "", "negated"},
		{"LOG target",
			`*filter
:INPUT ACCEPT [0:0]
-A INPUT -j LOG --log-prefix "drop: "
COMMIT
`, "", "LOG"},
		{"jump to user chain",
			`*filter
:INPUT ACCEPT [0:0]
:FOO - [0:0]
-A INPUT -j FOO
COMMIT
`, "", "user chain"},
		{"goto",
			`*filter
:INPUT ACCEPT [0:0]
:FOO - [0:0]
-A INPUT -g FOO
COMMIT
`, "", "goto"},
		{"conditional RETURN",
			`*filter
:INPUT ACCEPT [0:0]
-A INPUT -p tcp -j RETURN
COMMIT
`, "", "conditional RETURN"},
		{"reject-with unsupported",
			`*filter
:INPUT ACCEPT [0:0]
-A INPUT -p tcp -j REJECT --reject-with tcp-reset
COMMIT
`, "", "reject-with"},
		{"service-name port",
			`*filter
:INPUT ACCEPT [0:0]
-A INPUT -p tcp --dport ssh -j ACCEPT
COMMIT
`, "", "port"},
		{"port without proto",
			`*filter
:INPUT ACCEPT [0:0]
-A INPUT --dport 80 -j ACCEPT
COMMIT
`, "", "requires -p"},
		{"port with icmp proto",
			`*filter
:INPUT ACCEPT [0:0]
-A INPUT -p icmp --dport 8 -j ACCEPT
COMMIT
`, "", "requires -p"},
		{"unsupported proto",
			`*filter
:INPUT ACCEPT [0:0]
-A INPUT -p sctp -j ACCEPT
COMMIT
`, "", "sctp"},
		{"missing COMMIT",
			`*filter
:INPUT ACCEPT [0:0]
-A INPUT -j ACCEPT
`, "", "COMMIT"},
		{"unsupported directive",
			`*filter
:INPUT ACCEPT [0:0]
-N FOO
COMMIT
`, "", "directive"},
		{"v4 addr in v6 stream",
			"", `*filter
:INPUT ACCEPT [0:0]
-A INPUT -s 10.0.0.1 -j ACCEPT
COMMIT
`, "IPv6"},
		{"rule outside table",
			`-A INPUT -j ACCEPT
`, "", "outside a table"},
		{"no filter content",
			`*nat
:PREROUTING ACCEPT [0:0]
COMMIT
`, "", "no filter-table"},
		{"multiport --ports OR semantics",
			`*filter
:INPUT ACCEPT [0:0]
-A INPUT -p tcp -m multiport --ports 80,443 -j ACCEPT
COMMIT
`, "", "--ports"},
		{"duplicate -p",
			`*filter
:INPUT ACCEPT [0:0]
-A INPUT -p tcp -p udp -j ACCEPT
COMMIT
`, "", "duplicate -p"},
		{"duplicate -i",
			`*filter
:INPUT ACCEPT [0:0]
-A INPUT -i eth0 -i eth1 -j ACCEPT
COMMIT
`, "", "duplicate -i"},
		{"duplicate -o",
			`*filter
:OUTPUT ACCEPT [0:0]
-A OUTPUT -o eth0 -o eth1 -j ACCEPT
COMMIT
`, "", "duplicate -o"},
		{"duplicate -m tcp",
			`*filter
:INPUT ACCEPT [0:0]
-A INPUT -m tcp -m tcp --dport 22 -j ACCEPT
COMMIT
`, "", "duplicate -m"},
		{"conflicting -m tcp -m udp",
			`*filter
:INPUT ACCEPT [0:0]
-A INPUT -m tcp -m udp --dport 53 -j ACCEPT
COMMIT
`, "", "conflicting match modules"},
		{"-p contradicts -m",
			`*filter
:INPUT ACCEPT [0:0]
-A INPUT -p udp -m tcp --dport 53 -j ACCEPT
COMMIT
`, "", "contradicts"},
		{"-p all with -m tcp ports",
			`*filter
:INPUT ACCEPT [0:0]
-A INPUT -p all -m tcp --dport 80 -j ACCEPT
COMMIT
`, "", "contradicts"},
		{"multiport without proto",
			`*filter
:INPUT ACCEPT [0:0]
-A INPUT -m multiport --dports 80,443 -j ACCEPT
COMMIT
`, "", "requires -p"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := iptImportErr(t, store.Defaults(), tc.v4, tc.v6)
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

func TestImportIPTablesBothNil(t *testing.T) {
	if _, _, _, err := ImportIPTables(nil, nil, store.Defaults()); err == nil {
		t.Fatal("expected error for nil readers")
	}
}

// iptCatchall finds the trailing unconditional policy catchall for dir.
func iptCatchall(t *testing.T, rules []rule.Rule, dir string) *rule.Rule {
	t.Helper()
	for i := len(rules) - 1; i >= 0; i-- {
		r := &rules[i]
		if r.Direction != dir {
			continue
		}
		if strings.HasPrefix(r.Comment, "iptables-persistent") && r.Src.Any() && r.Dst.Any() {
			return r
		}
		return nil // last rule for dir is not a catchall
	}
	return nil
}

func TestImportIPTablesPolicyEmulation(t *testing.T) {
	t.Run("matching policies apply directly", func(t *testing.T) {
		v4 := `*filter
:INPUT DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
`
		v6 := `*filter
:INPUT DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
`
		out, n, _ := iptImport(t, store.Defaults(), v4, v6)
		if out.Policies.Input != "deny" || out.Policies.Output != "allow" {
			t.Fatalf("policies = %+v", out.Policies)
		}
		if len(out.Rules4) != 1 || len(out.Rules6) != 1 || n != 2 {
			t.Fatalf("no catchall expected: Rules4=%d Rules6=%d n=%d", len(out.Rules4), len(out.Rules6), n)
		}
	})

	t.Run("divergent policies emulate via catchall", func(t *testing.T) {
		v4 := `*filter
:INPUT ACCEPT [0:0]
-A INPUT -j ACCEPT
COMMIT
`
		v6 := `*filter
:INPUT DROP [0:0]
-A INPUT -j ACCEPT
COMMIT
`
		out, n, warnings := iptImport(t, store.Defaults(), v4, v6)
		// Baseline deny globally; v4 keeps ACCEPT via a trailing allow.
		if out.Policies.Input != "deny" {
			t.Fatalf("global input policy = %q, want deny", out.Policies.Input)
		}
		c := iptCatchall(t, out.Rules4, "in")
		if c == nil || c.Action != "allow" {
			t.Fatalf("no v4 input allow catchall: %+v", out.Rules4)
		}
		if iptCatchall(t, out.Rules6, "in") != nil {
			t.Fatal("unexpected v6 catchall (v6 is the baseline)")
		}
		saw := false
		for _, w := range warnings {
			if strings.Contains(w, "catchall") {
				saw = true
			}
		}
		if !saw {
			t.Errorf("missing catchall warning in %v", warnings)
		}
		if n < 3 {
			t.Fatalf("added = %d, want >= 3 (rules + catchall)", n)
		}
	})

	t.Run("unprovided family keeps its policy via catchall", func(t *testing.T) {
		// v4-only dump tightens INPUT to DROP; st has IPv6 enabled with an
		// allow input policy, which would silently become deny without a
		// preserving catchall on the v6 list.
		v4 := `*filter
:INPUT DROP [0:0]
-A INPUT -j ACCEPT
COMMIT
`
		st := store.Defaults()
		st.IPv6 = true
		st.Policies.Input = "allow"
		out, _, _ := iptImport(t, st, v4, "")
		if out.Policies.Input != "deny" {
			t.Fatalf("global input = %q, want deny", out.Policies.Input)
		}
		c := iptCatchall(t, out.Rules6, "in")
		if c == nil || c.Action != "allow" || c.Comment == "" {
			t.Fatalf("v6 input allow catchall missing/wrong: %+v", out.Rules6)
		}
	})

	t.Run("single stream onto disabled v6 applies directly", func(t *testing.T) {
		v4 := `*filter
:INPUT DROP [0:0]
-A INPUT -p tcp --dport 22 -j ACCEPT
COMMIT
`
		st := store.Defaults()
		st.IPv6 = false
		out, n, _ := iptImport(t, st, v4, "")
		if out.Policies.Input != "deny" {
			t.Fatalf("input policy = %q", out.Policies.Input)
		}
		if len(out.Rules6) != 0 {
			t.Fatalf("unexpected v6 catchall: %+v", out.Rules6)
		}
		if n != 1 {
			t.Fatalf("added = %d, want 1", n)
		}
	})

	t.Run("undeclared chain preserves current policy", func(t *testing.T) {
		// v4 omits FORWARD and v6 declares "-" — neither is authoritative,
		// so st's deny survives unchanged.
		v4 := `*filter
:INPUT DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -j ACCEPT
COMMIT
`
		v6 := `*filter
:INPUT DROP [0:0]
:FORWARD - [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -j ACCEPT
COMMIT
`
		out, _, _ := iptImport(t, store.Defaults(), v4, v6)
		if out.Policies.Forward != "deny" {
			t.Fatalf("forward policy = %q, want deny (unchanged)", out.Policies.Forward)
		}
		if iptCatchall(t, out.Rules4, "routed") != nil {
			t.Fatalf("unexpected v4 forward catchall: %+v", out.Rules4)
		}
	})

	t.Run("no catchall duplication on reimport", func(t *testing.T) {
		v4 := `*filter
:INPUT ACCEPT [0:0]
-A INPUT -j ACCEPT
COMMIT
`
		v6 := `*filter
:INPUT DROP [0:0]
-A INPUT -j ACCEPT
COMMIT
`
		st := store.Defaults()
		out1, _, _, err := ImportIPTables(strings.NewReader(v4), strings.NewReader(v6), st)
		if err != nil {
			t.Fatalf("first import: %v", err)
		}
		n4 := len(out1.Rules4)
		out2, _, _, err := ImportIPTables(strings.NewReader(v4), strings.NewReader(v6), out1)
		if err != nil {
			t.Fatalf("reimport: %v", err)
		}
		if len(out2.Rules4) != n4 {
			t.Fatalf("reimport grew Rules4: %d -> %d", n4, len(out2.Rules4))
		}
	})
}

func TestImportIPTablesICMPType(t *testing.T) {
	st := store.Defaults()
	st.IPv6 = false // exercise each family separately below
	out, n, _ := iptImport(t, st, `*filter
:INPUT ACCEPT [0:0]
-A INPUT -p icmp --icmp-type echo-request -j ACCEPT
-A INPUT -p icmp --icmp-type 3 -j DROP
-A INPUT -p icmp -m icmp --icmp-type timestamp-request -j ACCEPT
COMMIT
`, "")
	if n != 3 || len(out.Rules4) != 3 {
		t.Fatalf("added = %d, want 3", n)
	}
	got := []struct{ proto, typ string }{
		{out.Rules4[0].Proto, out.Rules4[0].ICMPType},
		{out.Rules4[1].Proto, out.Rules4[1].ICMPType},
		{out.Rules4[2].Proto, out.Rules4[2].ICMPType},
	}
	want := []struct{ proto, typ string }{
		{"icmp", "8"}, {"icmp", "3"}, {"icmp", "13"},
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("rule %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	if out.Rules4[0].Action != "allow" || out.Rules4[1].Action != "deny" {
		t.Fatalf("actions: %+v", out.Rules4)
	}

	// IPv6: protocol aliases and the `icmp6` extension alias use the
	// explicit -p protocol; all symbolic types canonicalize to decimals.
	out6, n6, _ := iptImport(t, store.Defaults(), "", `*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p icmpv6 --icmpv6-type echo-request -j ACCEPT
-A INPUT -p ipv6-icmp --icmpv6-type 1 -j DROP
-A INPUT -p ipv6-icmp -m icmp6 --icmp6-type router-advertisement -j ACCEPT
COMMIT
`)
	if n6 != 3 || len(out6.Rules6) != 3 {
		t.Fatalf("v6 added = %d, want 3", n6)
	}
	wantV6 := []string{"128", "1", "134"}
	for i, w := range wantV6 {
		if out6.Rules6[i].Proto != "icmpv6" || out6.Rules6[i].ICMPType != w {
			t.Fatalf("v6 rule %d = %s/%s, want icmpv6/%s", i,
				out6.Rules6[i].Proto, out6.Rules6[i].ICMPType, w)
		}
	}
	if !out6.Rules6[0].V6() {
		t.Fatal("v6 rule not marked V6")
	}
}
