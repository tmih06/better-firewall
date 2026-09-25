package impexp

import (
	"strings"
	"testing"

	"github.com/tmih06/better-firewall/internal/rule"
	"github.com/tmih06/better-firewall/internal/store"
)

// nftDoc wraps object JSON fragments in the `nft -j list ruleset` envelope.
func nftDoc(objs ...string) string {
	return `{"nftables": [` + strings.Join(objs, ",") + `]}`
}

// nftChainObj builds one filter base-chain object in table "filter";
// policy "" omits the key (nft's implicit accept).
func nftChainObj(family, hook, policy string) string {
	return nftChainTable(family, "filter", strings.ToUpper(hook), hook, policy)
}

// nftChainTable builds one chain object with an explicit table and name.
func nftChainTable(family, table, name, hook, policy string) string {
	s := `{"chain":{"family":"` + family + `","table":"` + table + `","name":"` + name +
		`","handle":1,"type":"filter","hook":"` + hook + `","prio":0`
	if policy != "" {
		s += `,"policy":"` + policy + `"`
	}
	return s + `}}`
}

// nftRuleObj builds one rule object bound to family/table filter/<hook>.
func nftRuleObj(family, hook string, exprs ...string) string {
	return `{"rule":{"family":"` + family + `","table":"filter","chain":"` +
		strings.ToUpper(hook) + `","handle":9,"expr":[` + strings.Join(exprs, ",") + `]}}`
}

func nftTableObj(family string) string {
	return `{"table":{"family":"` + family + `","name":"filter","handle":1}}`
}

// nftFullBase returns a complete-coverage scaffold: one ip and one ip6
// filter base chain on every hook, all sharing policy pol.
func nftFullBase(pol string) []string {
	var objs []string
	for _, f := range []string{"ip", "ip6"} {
		objs = append(objs, nftTableObj(f))
		for _, h := range []string{"input", "output", "forward"} {
			objs = append(objs, nftChainObj(f, h, pol))
		}
	}
	return objs
}

func TestImportNFTables(t *testing.T) {
	doc := nftDoc(
		`{"metainfo":{"version":"1.0.9","release_name":"X","json_schema_version":1}}`,
		// Mixed coverage: inet alone covers input; ip+ip6 pairs cover
		// output and forward.
		nftTableObj("inet"),
		nftChainObj("inet", "input", "drop"),
		// ssh accept: dual rule (no family restriction) with dport +
		// counter + log + comment.
		nftRuleObj("inet", "input",
			`{"match":{"left":{"payload":{"protocol":"tcp","field":"dport"}},"op":"==","right":22}}`,
			`{"counter":{"packets":7,"bytes":512}}`,
			`{"log":{"prefix":"IN "}}`,
			`{"comment":"ssh"}`,
			`{"accept":null}`),
		// inet v4-only: nfproto guard + string-form meta + numeric proto +
		// saddr prefix + a non-default reject code (dropped with warning).
		nftRuleObj("inet", "input",
			`{"match":{"left":{"meta":"nfproto"},"op":"==","right":"ipv4"}}`,
			`{"match":{"left":{"payload":{"protocol":"ip","field":"protocol"}},"op":"==","right":6}}`,
			`{"match":{"left":{"payload":{"protocol":"ip","field":"saddr"}},"op":"==","right":{"prefix":{"addr":"192.168.1.0","len":24}}}}`,
			`{"match":{"left":{"meta":"iifname"},"op":"==","right":"eth0"}}`,
			`{"reject":{"type":"icmpx","expr":"host-unreachable"}}`),
		// inet v6-only via protocol narrowing (icmpv6 ⇒ IPv6 only).
		nftRuleObj("inet", "input",
			`{"match":{"left":{"meta":{"key":"l4proto"}},"op":"==","right":"ipv6-icmp"}}`,
			`{"accept":null}`),
		// Named counter object: accounting only → counted for the warning.
		`{"counter":{"family":"inet","table":"filter","name":"ctr","handle":7,"packets":0,"bytes":0}}`,
		nftTableObj("ip"),
		nftChainObj("ip", "output", "drop"),
		nftChainObj("ip", "forward", ""),
		// Forward drop: host saddr + udp sport range.
		nftRuleObj("ip", "forward",
			`{"match":{"left":{"payload":{"protocol":"ip","field":"saddr"}},"op":"==","right":"10.0.0.5"}}`,
			`{"match":{"left":{"payload":{"protocol":"udp","field":"sport"}},"op":"==","right":{"range":[5353,5354]}}}`,
			`{"drop":null}`),
		nftTableObj("ip6"),
		nftChainObj("ip6", "output", "drop"),
		nftChainObj("ip6", "forward", ""),
		nftRuleObj("ip6", "forward",
			`{"match":{"left":{"payload":{"protocol":"ip6","field":"daddr"}},"op":"==","right":{"prefix":{"addr":"2001:db8::","len":48}}}}`,
			`{"drop":null}`),
	)

	st := store.Defaults()
	st.IPv6 = false // imported ruleset covers v6 → merged state must enable it
	merged, n, warnings, err := ImportNFTables(strings.NewReader(doc), st)
	if err != nil {
		t.Fatalf("ImportNFTables: %v", err)
	}
	if n != 6 {
		t.Fatalf("added = %d, want 6", n)
	}
	// Input state untouched.
	if len(st.Rules4) != 0 || len(st.Rules6) != 0 || st.IPv6 {
		t.Fatal("input state mutated")
	}
	if !merged.IPv6 {
		t.Error("merged IPv6 = false, want true (ruleset covers IPv6)")
	}
	if len(merged.Rules4) != 3 {
		t.Fatalf("Rules4 = %d, want 3", len(merged.Rules4))
	}
	if len(merged.Rules6) != 3 {
		t.Fatalf("Rules6 = %d, want 3", len(merged.Rules6))
	}

	want4 := []rule.Rule{
		{Action: "allow", Direction: "in", Proto: "tcp",
			Src: rule.AddrSpec{IP: "any"},
			Dst: rule.AddrSpec{IP: "any", Ports: []rule.PortRange{{Lo: 22, Hi: 22, Proto: "tcp"}}},
			Log: "log-all", Comment: "ssh"},
		{Action: "reject", Direction: "in", IfaceIn: "eth0", Proto: "tcp",
			Src: rule.AddrSpec{IP: "192.168.1.0/24"}, Dst: rule.AddrSpec{IP: "any"}},
		{Action: "deny", Direction: "routed", Proto: "udp",
			Src: rule.AddrSpec{IP: "10.0.0.5", Ports: []rule.PortRange{{Lo: 5353, Hi: 5354, Proto: "udp"}}},
			Dst: rule.AddrSpec{IP: "any"}},
	}
	for i, want := range want4 {
		if !rulesEqual(&merged.Rules4[i], &want) {
			t.Errorf("Rules4[%d] = %+v, want %+v", i, merged.Rules4[i], want)
		}
	}
	want6 := []rule.Rule{
		{Action: "allow", Direction: "in", Proto: "tcp",
			Src: rule.AddrSpec{IP: "any"},
			Dst: rule.AddrSpec{IP: "any", Ports: []rule.PortRange{{Lo: 22, Hi: 22, Proto: "tcp"}}},
			Log: "log-all", Comment: "ssh"},
		{Action: "allow", Direction: "in", Proto: "icmpv6",
			Src: rule.AddrSpec{IP: "any"}, Dst: rule.AddrSpec{IP: "any"}},
		{Action: "deny", Direction: "routed", Proto: "any",
			Src: rule.AddrSpec{IP: "any"}, Dst: rule.AddrSpec{IP: "2001:db8::/48"}},
	}
	for i, want := range want6 {
		if !rulesEqual(&merged.Rules6[i], &want) {
			t.Errorf("Rules6[%d] = %+v, want %+v", i, merged.Rules6[i], want)
		}
	}
	// The unrestricted inet rule is dual: same ID in both lists.
	if merged.Rules4[0].ID != merged.Rules6[0].ID {
		t.Errorf("dual rule IDs differ: %q vs %q", merged.Rules4[0].ID, merged.Rules6[0].ID)
	}

	// input/output dropped; forward covered by ip+ip6 chains with omitted
	// policies → nft implicit accept → allow.
	if merged.Policies.Input != "deny" || merged.Policies.Output != "deny" || merged.Policies.Forward != "allow" {
		t.Errorf("policies = %+v", merged.Policies)
	}
	// Three warnings: skipped counters (1 object + 1 expr), dropped log
	// prefix, non-default reject code.
	var sawCtr, sawLog, sawRej bool
	for _, w := range warnings {
		sawCtr = sawCtr || strings.Contains(w, "2 counter(s)")
		sawLog = sawLog || strings.Contains(w, "log options")
		sawRej = sawRej || strings.Contains(w, "reject type/expr")
	}
	if !sawCtr || !sawLog || !sawRej {
		t.Errorf("warnings = %v, want counter+log+reject warnings", warnings)
	}
}

func TestImportNFTablesICMPType(t *testing.T) {
	// inet rules narrow to a single family through icmp/icmpv6 payload
	// matches; family tables get the same via ip protocol / ip6 nexthdr.
	// Repeated identical type constraints (echo-request == 8) coalesce.
	doc := nftDoc(
		nftTableObj("inet"),
		nftChainObj("inet", "input", "drop"),
		nftRuleObj("inet", "input",
			`{"match":{"left":{"payload":{"protocol":"icmp","field":"type"}},"op":"==","right":8}}`,
			`{"match":{"left":{"payload":{"protocol":"icmp","field":"type"}},"op":"==","right":"echo-request"}}`,
			`{"drop":null}`),
		nftRuleObj("inet", "input",
			`{"match":{"left":{"payload":{"protocol":"icmpv6","field":"type"}},"op":"==","right":"destination-unreachable"}}`,
			`{"accept":null}`),
		nftTableObj("ip"),
		nftChainObj("ip", "output", "drop"),
		nftRuleObj("ip", "output",
			`{"match":{"left":{"payload":{"protocol":"ip","field":"protocol"}},"op":"==","right":"icmp"}}`,
			`{"match":{"left":{"payload":{"protocol":"icmp","field":"type"}},"op":"==","right":0}}`,
			`{"drop":null}`),
		nftTableObj("ip6"),
		nftChainObj("ip6", "output", "drop"),
		nftRuleObj("ip6", "output",
			`{"match":{"left":{"payload":{"protocol":"ip6","field":"nexthdr"}},"op":"==","right":58}}`,
			`{"match":{"left":{"payload":{"protocol":"icmpv6","field":"type"}},"op":"==","right":128}}`,
			`{"accept":null}`),
	)
	merged, n, _, err := ImportNFTables(strings.NewReader(doc), store.Defaults())
	if err != nil {
		t.Fatalf("ImportNFTables: %v", err)
	}
	if n != 4 {
		t.Fatalf("added = %d, want 4", n)
	}
	if len(merged.Rules4) != 2 || len(merged.Rules6) != 2 {
		t.Fatalf("Rules4=%d Rules6=%d, want 2 each", len(merged.Rules4), len(merged.Rules6))
	}
	// icmp ⇒ IPv4 only, icmpv6 ⇒ IPv6 only; no dead half in the other list.
	want4 := []rule.Rule{
		{Action: "deny", Direction: "in", Proto: "icmp", ICMPType: "8",
			Src: rule.AddrSpec{IP: "any"}, Dst: rule.AddrSpec{IP: "any"}},
		{Action: "deny", Direction: "out", Proto: "icmp", ICMPType: "0",
			Src: rule.AddrSpec{IP: "any"}, Dst: rule.AddrSpec{IP: "any"}},
	}
	want6 := []rule.Rule{
		{Action: "allow", Direction: "in", Proto: "icmpv6", ICMPType: "1",
			Src: rule.AddrSpec{IP: "any"}, Dst: rule.AddrSpec{IP: "any"}},
		{Action: "allow", Direction: "out", Proto: "icmpv6", ICMPType: "128",
			Src: rule.AddrSpec{IP: "any"}, Dst: rule.AddrSpec{IP: "any"}},
	}
	for i, want := range want4 {
		if !rulesEqual(&merged.Rules4[i], &want) || merged.Rules4[i].ICMPType != want.ICMPType {
			t.Errorf("Rules4[%d] = %+v, want %+v", i, merged.Rules4[i], want)
		}
	}
	for i, want := range want6 {
		if !rulesEqual(&merged.Rules6[i], &want) || merged.Rules6[i].ICMPType != want.ICMPType {
			t.Errorf("Rules6[%d] = %+v, want %+v", i, merged.Rules6[i], want)
		}
	}
}

func TestImportNFTablesAbsentHooks(t *testing.T) {
	// Directions with no base chain are nft's implicit accept: imported as
	// "allow" with no rules, which is exact. A common input-only ruleset.
	doc := nftDoc(
		nftTableObj("ip"), nftTableObj("ip6"),
		nftChainObj("ip", "input", "drop"),
		nftChainObj("ip6", "input", "drop"),
		nftRuleObj("ip6", "input",
			`{"match":{"left":{"payload":{"protocol":"tcp","field":"dport"}},"op":"==","right":22}}`,
			`{"drop":null}`),
	)
	st := store.Defaults()
	merged, n, _, err := ImportNFTables(strings.NewReader(doc), st)
	if err != nil {
		t.Fatalf("ImportNFTables: %v", err)
	}
	if n != 1 {
		t.Fatalf("added = %d, want 1", n)
	}
	if merged.Policies.Input != "deny" || merged.Policies.Output != "allow" || merged.Policies.Forward != "allow" {
		t.Errorf("policies = %+v, want deny/allow/allow", merged.Policies)
	}
	if len(merged.Rules6) != 1 || merged.Rules6[0].Action != "deny" {
		t.Errorf("Rules6 = %+v, want one deny rule", merged.Rules6)
	}
}

func TestImportNFTablesPartialAcceptCoverage(t *testing.T) {
	// An ip-only input chain with accept policy is faithful: the absent
	// ip6 family's implicit accept unifies with it. The v4 rules still
	// filter before the policy.
	doc := nftDoc(
		nftTableObj("ip"),
		nftChainObj("ip", "input", "accept"),
		nftRuleObj("ip", "input",
			`{"match":{"left":{"payload":{"protocol":"tcp","field":"dport"}},"op":"==","right":23}}`,
			`{"drop":null}`),
	)
	st := store.Defaults()
	merged, n, _, err := ImportNFTables(strings.NewReader(doc), st)
	if err != nil {
		t.Fatalf("ImportNFTables: %v", err)
	}
	if n != 1 {
		t.Fatalf("added = %d, want 1", n)
	}
	if merged.Policies.Input != "allow" || merged.Policies.Output != "allow" || merged.Policies.Forward != "allow" {
		t.Errorf("policies = %+v, want all allow", merged.Policies)
	}
	if len(merged.Rules4) != 1 || merged.Rules4[0].Action != "deny" {
		t.Errorf("Rules4 = %+v, want one deny rule", merged.Rules4)
	}
	if len(merged.Rules6) != 0 {
		t.Errorf("Rules6 = %+v, want none (absent family = implicit accept)", merged.Rules6)
	}
}

func TestImportNFTablesImplicitPolicy(t *testing.T) {
	// All chains omit policy: nft treats that as accept for every hook, so
	// all three model policies become "allow" regardless of prior state.
	doc := nftDoc(
		nftTableObj("inet"),
		nftChainObj("inet", "input", ""),
		nftChainObj("inet", "output", ""),
		nftChainObj("inet", "forward", ""),
	)
	st := store.Defaults() // deny / allow / deny
	merged, n, _, err := ImportNFTables(strings.NewReader(doc), st)
	if err != nil {
		t.Fatalf("ImportNFTables: %v", err)
	}
	if n != 0 {
		t.Fatalf("added = %d, want 0", n)
	}
	if merged.Policies.Input != "allow" || merged.Policies.Output != "allow" || merged.Policies.Forward != "allow" {
		t.Errorf("policies = %+v, want all allow (nft implicit accept)", merged.Policies)
	}
	if st.Policies != store.Defaults().Policies {
		t.Error("input state mutated")
	}
}

func TestImportNFTablesMerge(t *testing.T) {
	st := store.Defaults()
	st.Rules4 = []rule.Rule{{
		ID: "existing1", Action: "allow", Direction: "in", Proto: "tcp",
		Src:      rule.AddrSpec{IP: "any"},
		Dst:      rule.AddrSpec{IP: "any", Ports: []rule.PortRange{{Lo: 22, Hi: 22, Proto: "tcp"}}},
		Comment:  "old",
		Disabled: true,
	}}
	doc := nftDoc(append(nftFullBase("drop"),
		nftRuleObj("ip", "input",
			`{"match":{"left":{"payload":{"protocol":"tcp","field":"dport"}},"op":"==","right":22}}`,
			`{"comment":"new"}`,
			`{"accept":null}`))...)
	merged, n, _, err := ImportNFTables(strings.NewReader(doc), st)
	if err != nil {
		t.Fatalf("ImportNFTables: %v", err)
	}
	if n != 1 {
		t.Fatalf("added = %d, want 1 (in-place update)", n)
	}
	if len(merged.Rules4) != 1 {
		t.Fatalf("Rules4 = %d, want 1", len(merged.Rules4))
	}
	got := merged.Rules4[0]
	if got.ID != "existing1" {
		t.Errorf("in-place merge lost ID: %q", got.ID)
	}
	if !got.Disabled {
		t.Error("in-place merge lost Disabled flag")
	}
	if got.Comment != "new" {
		t.Errorf("comment = %q, want new", got.Comment)
	}
	if len(st.Rules4) != 1 || st.Rules4[0].Comment != "old" {
		t.Error("input state mutated")
	}
}

func TestImportNFTablesRejections(t *testing.T) {
	// mkRule appends a rule to a fully covered scaffold so rule-conversion
	// errors are reached (coverage validation precedes conversion).
	mkRule := func(exprs ...string) string {
		return nftDoc(append(nftFullBase("drop"),
			nftRuleObj("ip", "input", exprs...))...)
	}
	tcpdport := `{"match":{"left":{"payload":{"protocol":"tcp","field":"dport"}},"op":"==","right":22}}`

	cases := []struct {
		name string
		doc  string
		want string
	}{
		{"not json", `{"nftables": [`, "parsing nftables JSON"},
		{"missing array", `{"foo": []}`, "missing \"nftables\" array"},
		{"missing v6 coverage", nftDoc(nftTableObj("ip"),
			nftChainObj("ip", "input", "drop"),
			nftChainObj("ip", "output", "drop"),
			nftChainObj("ip", "forward", "drop")),
			"incomplete coverage"},
		{"overlap inet+ip", nftDoc(nftTableObj("inet"),
			nftChainObj("inet", "input", "drop"),
			nftChainObj("inet", "output", "drop"),
			nftChainObj("inet", "forward", "drop"),
			nftTableObj("ip"), nftChainObj("ip", "input", "drop")),
			"overlapping base chains"},
		{"foreign family objects", nftDoc(
			`{"table":{"family":"arp","name":"filter","handle":8}}`,
			nftChainTable("arp", "filter", "INPUT", "input", "accept")),
			"unsupported family"},
		{"foreign family rule", nftDoc(nftTableObj("ip"),
			`{"rule":{"family":"netdev","table":"f","chain":"X","handle":1,"expr":[{"accept":null}]}}`),
			"unsupported family"},
		{"nat chain", nftDoc(nftTableObj("ip"),
			`{"chain":{"family":"ip","table":"nat","name":"PREROUTING","handle":1,"type":"nat","hook":"prerouting","prio":-100,"policy":"accept"}}`),
			"unsupported type/hook"},
		{"non-filter hook", nftDoc(nftTableObj("ip"),
			`{"chain":{"family":"ip","table":"filter","name":"POST","handle":1,"type":"filter","hook":"postrouting","prio":0,"policy":"accept"}}`),
			"unsupported type/hook"},
		{"regular chain", nftDoc(nftTableObj("ip"),
			`{"chain":{"family":"ip","table":"filter","name":"custom","handle":4}}`),
			"regular (non-base) chains"},
		{"duplicate hook", nftDoc(nftTableObj("ip"), nftChainObj("ip", "input", "drop"),
			`{"table":{"family":"ip","name":"mangle","handle":2}}`,
			nftChainTable("ip", "mangle", "IN", "input", "drop")),
			"multiple base chains"},
		{"policy conflict", nftDoc(nftTableObj("ip"), nftChainObj("ip", "input", "drop"),
			nftTableObj("inet"), nftChainObj("inet", "input", "accept")),
			"conflicts with"},
		{"bad policy value", nftDoc(nftTableObj("ip"),
			nftChainTable("ip", "filter", "INPUT", "input", "reject")),
			"unsupported policy"},
		{"set object", nftDoc(nftTableObj("ip"),
			`{"set":{"family":"ip","table":"filter","name":"block","handle":5,"type":"ipv4_addr","flags":["interval"],"elem":["10.0.0.1"]}}`),
			"named sets/maps"},
		{"map object", nftDoc(nftTableObj("ip"),
			`{"map":{"family":"ip","table":"filter","name":"m","handle":6,"type":"ipv4_addr","map":"verdict"}}`),
			"named sets/maps"},
		{"quota object", nftDoc(nftTableObj("ip"),
			`{"quota":{"family":"ip","table":"filter","name":"q","handle":9,"limit":1048576}}`),
			"quota"},
		{"quota expr", mkRule(tcpdport, `{"quota":{"limit":1024}}`, `{"accept":null}`),
			"quota"},
		{"log nflog group", mkRule(tcpdport, `{"log":{"group":5}}`, `{"accept":null}`),
			"NFLOG"},
		{"conflict ports", mkRule(tcpdport,
			`{"match":{"left":{"payload":{"protocol":"tcp","field":"dport"}},"op":"==","right":80}}`,
			`{"accept":null}`), "conflicting port constraints"},
		{"rule in unknown chain", nftDoc(append(nftFullBase("drop"),
			`{"rule":{"family":"ip","table":"filter","chain":"MISSING","handle":7,"expr":[{"accept":null}]}}`)...),
			"not an imported filter base chain"},
		{"jump verdict", mkRule(tcpdport, `{"jump":"other-chain"}`), "jump"},
		{"goto verdict", mkRule(`{"goto":"other-chain"}`), "goto"},
		{"no verdict", mkRule(tcpdport), "no terminal verdict"},
		{"expr after verdict", mkRule(`{"accept":null}`, `{"counter":{"packets":1,"bytes":1}}`),
			"after terminal verdict"},
		{"neq operator", mkRule(
			`{"match":{"left":{"payload":{"protocol":"tcp","field":"dport"}},"op":"!=","right":22}}`,
			`{"accept":null}`), "not representable"},
		{"set membership", mkRule(
			`{"match":{"left":{"payload":{"protocol":"tcp","field":"dport"}},"op":"in","right":{"set":[80,443]}}}`,
			`{"accept":null}`), "set matches"},
		{"named set ref", mkRule(
			`{"match":{"left":{"payload":{"protocol":"ip","field":"saddr"}},"op":"==","right":{"set":"@block"}}}`,
			`{"accept":null}`), "set matches"},
		{"ct state", mkRule(
			`{"match":{"left":{"ct":{"key":"state"}},"op":"==","right":"established"}}`,
			`{"accept":null}`), "ct expression"},
		{"fib", mkRule(
			`{"match":{"left":{"fib":{"flags":["saddr"],"result":"oif"}},"op":"==","right":"eth0"}}`,
			`{"accept":null}`), "fib expression"},
		{"icmp code", mkRule(
			`{"match":{"left":{"payload":{"protocol":"icmp","field":"code"}},"op":"==","right":0}}`,
			`{"accept":null}`), "not representable"},
		{"icmpv6 code", mkRule(
			`{"match":{"left":{"payload":{"protocol":"icmpv6","field":"code"}},"op":"==","right":0}}`,
			`{"accept":null}`), "not representable"},
		{"icmp type range", mkRule(
			`{"match":{"left":{"payload":{"protocol":"icmp","field":"type"}},"op":"==","right":{"range":[8,9]}}}`,
			`{"accept":null}`), "icmp type"},
		{"icmp type set", mkRule(
			`{"match":{"left":{"payload":{"protocol":"icmp","field":"type"}},"op":"in","right":{"set":["echo-request","echo-reply"]}}}`,
			`{"accept":null}`), "set"},
		{"icmp type bogus name", mkRule(
			`{"match":{"left":{"payload":{"protocol":"icmp","field":"type"}},"op":"==","right":"not-a-type"}}`,
			`{"accept":null}`), "icmp type"},
		{"icmp conflicting types", mkRule(
			`{"match":{"left":{"payload":{"protocol":"icmp","field":"type"}},"op":"==","right":8}}`,
			`{"match":{"left":{"payload":{"protocol":"icmp","field":"type"}},"op":"==","right":0}}`,
			`{"accept":null}`), "conflicting types"},
		{"icmp type contradicts proto", mkRule(
			`{"match":{"left":{"payload":{"protocol":"ip","field":"protocol"}},"op":"==","right":"tcp"}}`,
			`{"match":{"left":{"payload":{"protocol":"icmp","field":"type"}},"op":"==","right":8}}`,
			`{"accept":null}`), "conflicting protocols"},
		{"icmp type with port", mkRule(tcpdport,
			`{"match":{"left":{"payload":{"protocol":"icmp","field":"type"}},"op":"==","right":8}}`,
			`{"accept":null}`), "conflicting protocols"},
		{"icmp and icmpv6 types", mkRule(
			`{"match":{"left":{"payload":{"protocol":"icmp","field":"type"}},"op":"==","right":8}}`,
			`{"match":{"left":{"payload":{"protocol":"icmpv6","field":"type"}},"op":"==","right":128}}`,
			`{"accept":null}`), "conflicting protocols"},
		{"icmpv6 type in v4 chain", mkRule(
			`{"match":{"left":{"payload":{"protocol":"icmpv6","field":"type"}},"op":"==","right":128}}`,
			`{"accept":null}`), "conflicting address families"},
		{"icmp type in v6 chain", nftDoc(append(nftFullBase("drop"),
			nftRuleObj("ip6", "input",
				`{"match":{"left":{"payload":{"protocol":"icmp","field":"type"}},"op":"==","right":8}}`,
				`{"accept":null}`))...),
			"conflicting address families"},
		{"tcp option", mkRule(
			`{"match":{"left":{"exthdr":{"name":"tcp option","field":"mss"}},"op":"==","right":1460}}`,
			`{"accept":null}`), "exthdr"},
		{"conflict protos", mkRule(tcpdport,
			`{"match":{"left":{"payload":{"protocol":"udp","field":"dport"}},"op":"==","right":53}}`,
			`{"accept":null}`), "conflicting protocols"},
		{"conflict families", mkRule(
			`{"match":{"left":{"meta":"nfproto"},"op":"==","right":"ipv4"}}`,
			`{"match":{"left":{"payload":{"protocol":"ip6","field":"saddr"}},"op":"==","right":"::1"}}`,
			`{"accept":null}`), "conflicting address families"},
		{"icmpv6 in v4 chain", nftDoc(append(nftFullBase("drop"),
			nftRuleObj("ip", "input",
				`{"match":{"left":{"meta":"l4proto"},"op":"==","right":"ipv6-icmp"}}`,
				`{"accept":null}`))...),
			"conflicting address families"},
		{"named port", mkRule(
			`{"match":{"left":{"payload":{"protocol":"tcp","field":"dport"}},"op":"==","right":"ssh"}}`,
			`{"accept":null}`), "unsupported port"},
		{"bad prefix len", mkRule(
			`{"match":{"left":{"payload":{"protocol":"ip","field":"saddr"}},"op":"==","right":{"prefix":{"addr":"10.0.0.0","len":99}}}}`,
			`{"accept":null}`), "invalid prefix"},
		{"unsupported proto", mkRule(
			`{"match":{"left":{"payload":{"protocol":"ip","field":"protocol"}},"op":"==","right":"sctp"}}`,
			`{"accept":null}`), "unsupported protocol"},
		{"meta mark", mkRule(
			`{"match":{"left":{"meta":"mark"},"op":"==","right":7}}`,
			`{"accept":null}`), "not representable"},
		{"unsupported stmt", mkRule(tcpdport, `{"masquerade":null}`), "unsupported expression"},
		{"elem object", nftDoc(nftTableObj("ip"),
			`{"elem":{"family":"ip","table":"filter","name":"s","elem":"1.2.3.4"}}`),
			"unsupported object type"},
		{"flowtable", nftDoc(nftTableObj("ip"),
			`{"flowtable":{"family":"ip","table":"filter","name":"f","handle":1,"hook":"ingress","prio":0,"dev":"eth0"}}`),
			"flowtables"},
	}
	for _, tc := range cases {
		st := store.Defaults()
		out, _, _, err := ImportNFTables(strings.NewReader(tc.doc), st)
		if err == nil {
			t.Errorf("%s: expected error, got none", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %q does not contain %q", tc.name, err, tc.want)
		}
		if out != nil {
			t.Errorf("%s: expected nil state on error", tc.name)
		}
		if len(st.Rules4) != 0 || len(st.Rules6) != 0 || st.Policies != store.Defaults().Policies {
			t.Errorf("%s: input state mutated on error", tc.name)
		}
	}
}

func TestImportNFTablesNilState(t *testing.T) {
	doc := nftDoc(nftTableObj("inet"),
		nftChainObj("inet", "input", "drop"),
		nftChainObj("inet", "output", ""),
		nftChainObj("inet", "forward", ""))
	out, n, _, err := ImportNFTables(strings.NewReader(doc), nil)
	if err == nil {
		t.Fatal("expected error for nil state")
	}
	if !strings.Contains(err.Error(), "non-nil state") {
		t.Errorf("error %q does not mention nil state", err)
	}
	if out != nil || n != 0 {
		t.Errorf("got (%v, %d), want (nil, 0)", out, n)
	}
}
