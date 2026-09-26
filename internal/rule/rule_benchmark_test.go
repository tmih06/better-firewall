package rule

import "testing"

func benchmarkRules1000() []Rule {
	list := make([]Rule, 1000)
	for i := range list {
		list[i] = Rule{
			Action: ActionAllow, Direction: DirIn, Proto: "tcp",
			Src: AddrSpec{IP: "any"},
			Dst: AddrSpec{IP: "any", Ports: []PortRange{{Lo: uint16(1000 + i), Hi: uint16(1000 + i), Proto: "tcp"}}},
		}
	}
	return list
}

// BenchmarkRuleMatch1000 covers the linear duplicate/update scan used by the
// CLI rule engine when a policy contains 1,000 rules.
func BenchmarkRuleMatch1000(b *testing.B) {
	list := benchmarkRules1000()
	want := list[len(list)-1].Clone()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := range list {
			_ = list[j].Match(want)
		}
	}
}

// BenchmarkTupleKey1000 covers the canonical key path used by import/export
// indexing and cross-family rule reconciliation.
func BenchmarkTupleKey1000(b *testing.B) {
	list := benchmarkRules1000()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := range list {
			_ = list[j].TupleKey()
		}
	}
}

// BenchmarkAppTuple1000 covers the application-profile grouping path used by
// status and app-rule mutation commands.
func BenchmarkAppTuple1000(b *testing.B) {
	list := benchmarkRules1000()
	for i := range list {
		list[i].Dapp = "OpenSSH"
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := range list {
			_ = list[j].AppTuple()
		}
	}
}
