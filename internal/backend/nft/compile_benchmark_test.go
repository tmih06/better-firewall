package nft

import (
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/tmih06/better-firewall/internal/rule"
	"github.com/tmih06/better-firewall/internal/store"
)

func BenchmarkThreatBanSetCompile(b *testing.B) {
	for _, count := range []int{100, 1000, 10000} {
		b.Run(strconv.Itoa(count), func(b *testing.B) {
			st := store.Defaults()
			st.Bans = make([]store.ThreatBan, count)
			expires := time.Now().Add(24 * time.Hour).Unix()
			for i := range st.Bans {
				address := netip.AddrFrom4([4]byte{198, 18, byte((i * 2) >> 8), byte(i * 2)})
				st.Bans[i] = store.ThreatBan{
					Address: address.String(), Source: "crowdsec",
					DecisionID: int64(i + 1), ExpiresAt: expires,
				}
			}
			b.ReportAllocs()
			b.ReportMetric(float64(count), "bans/op")
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := compile(st, nil); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkRulesetCompile measures the full compiler path for ordinary
// user rules at the same cardinalities used by the hosted firewall benchmark.
func BenchmarkRulesetCompile(b *testing.B) {
	for _, count := range []int{10, 100, 500, 1000} {
		b.Run(strconv.Itoa(count), func(b *testing.B) {
			st := store.Defaults()
			st.Rules4 = make([]rule.Rule, count)
			for i := range st.Rules4 {
				port := uint16(10001 + i)
				st.Rules4[i] = rule.Rule{
					ID:        "r" + strconv.Itoa(i+1),
					Action:    rule.ActionAllow,
					Direction: rule.DirIn,
					Proto:     "tcp",
					Src:       rule.AddrSpec{IP: "any"},
					Dst: rule.AddrSpec{
						IP:    "any",
						Ports: []rule.PortRange{{Lo: port, Hi: port, Proto: "tcp"}},
					},
				}
			}
			b.ReportAllocs()
			b.ReportMetric(float64(count), "rules/op")
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := compile(st, nil); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkLimitRulesetCompile exercises the dynamic-set lookup path. Limit
// rules used to scan every previously-created set, making a large policy
// needlessly quadratic during apply.
func BenchmarkLimitRulesetCompile(b *testing.B) {
	for _, count := range []int{100, 1000} {
		b.Run(strconv.Itoa(count), func(b *testing.B) {
			st := store.Defaults()
			st.Rules4 = make([]rule.Rule, count)
			for i := range st.Rules4 {
				st.Rules4[i] = rule.Rule{
					ID: "limit" + strconv.Itoa(i+1), Action: rule.ActionLimit,
					Direction: rule.DirIn, Proto: "tcp",
					Src: rule.AddrSpec{IP: "any"},
					Dst: rule.AddrSpec{IP: "any", Ports: []rule.PortRange{{Lo: uint16(10000 + i%50000), Hi: uint16(10000 + i%50000), Proto: "tcp"}}},
				}
			}
			b.ReportAllocs()
			b.ReportMetric(float64(count), "rules/op")
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := compile(st, nil); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
