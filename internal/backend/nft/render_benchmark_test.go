package nft

import (
	"strconv"
	"strings"
	"testing"

	"github.com/tmih06/better-firewall/internal/rule"
	"github.com/tmih06/better-firewall/internal/store"
)

// BenchmarkRulesetRender measures canonical diff/dry-run rendering separately
// from compilation, including the anonymous-set lookup path used by rules
// with multiple ports.
func BenchmarkRulesetRender(b *testing.B) {
	for _, count := range []int{100, 1000} {
		b.Run(strconv.Itoa(count), func(b *testing.B) {
			st := store.Defaults()
			st.Rules4 = make([]rule.Rule, count)
			for i := range st.Rules4 {
				port := uint16(10001 + i)
				st.Rules4[i] = rule.Rule{
					ID: "r" + strconv.Itoa(i+1), Action: rule.ActionAllow,
					Direction: rule.DirIn, Proto: "tcp",
					Src: rule.AddrSpec{IP: "any"},
					Dst: rule.AddrSpec{IP: "any", Ports: []rule.PortRange{
						{Lo: port, Hi: port, Proto: "tcp"},
						{Lo: port + 1, Hi: port + 1, Proto: "tcp"},
					}},
				}
			}
			c, err := compile(st, nil)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var out strings.Builder
				renderTable(&out, c)
				for _, t := range c.natTables {
					renderNATTable(&out, c, t)
				}
				if out.Len() == 0 {
					b.Fatal("empty ruleset")
				}
			}
		})
	}
}

// BenchmarkLimitRulesetRender measures the dynamic-set meter text path used
// by `bfw diff` for limit rules, including the nested rate expression.
func BenchmarkLimitRulesetRender(b *testing.B) {
	for _, count := range []int{100, 1000} {
		b.Run(strconv.Itoa(count), func(b *testing.B) {
			st := store.Defaults()
			st.Rules4 = make([]rule.Rule, count)
			for i := range st.Rules4 {
				port := uint16(10001 + i)
				st.Rules4[i] = rule.Rule{
					ID: "limit" + strconv.Itoa(i+1), Action: rule.ActionLimit,
					Direction: rule.DirIn, Proto: "tcp",
					Src: rule.AddrSpec{IP: "any"},
					Dst: rule.AddrSpec{IP: "any", Ports: []rule.PortRange{{Lo: port, Hi: port, Proto: "tcp"}}},
				}
			}
			c, err := compile(st, nil)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var out strings.Builder
				renderTable(&out, c)
				for _, t := range c.natTables {
					renderNATTable(&out, c, t)
				}
				if out.Len() == 0 {
					b.Fatal("empty ruleset")
				}
			}
		})
	}
}
