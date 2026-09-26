package rule

import "testing"

// BenchmarkRuleMatch1000 covers the linear duplicate/update scan used by the
// CLI rule engine when a policy contains 1,000 rules.
func BenchmarkRuleMatch1000(b *testing.B) {
	list := make([]Rule, 1000)
	for i := range list {
		list[i] = Rule{
			Action: ActionAllow, Direction: DirIn, Proto: "tcp",
			Src: AddrSpec{IP: "any"},
			Dst: AddrSpec{IP: "any", Ports: []PortRange{{Lo: uint16(1000 + i), Hi: uint16(1000 + i), Proto: "tcp"}}},
		}
	}
	want := list[len(list)-1].Clone()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := range list {
			_ = list[j].Match(want)
		}
	}
}
