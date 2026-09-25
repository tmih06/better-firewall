package nft

import (
	"net/netip"
	"strconv"
	"testing"
	"time"

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
