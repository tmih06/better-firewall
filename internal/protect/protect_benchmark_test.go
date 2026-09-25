package protect

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func BenchmarkJournalFailureDetection(b *testing.B) {
	cfg := DefaultConfig()
	detector, err := NewDetector(cfg)
	if err != nil {
		b.Fatal(err)
	}
	message := "Failed password for invalid user scanner from 203.0.113.27 port 52222 ssh2"
	start := time.Unix(1_800_000_000, 0)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector.Observe("sshd", message, start.Add(time.Duration(i)*time.Millisecond))
	}
}

func BenchmarkCrowdSecDecisionDecode(b *testing.B) {
	decisions := make([]CrowdSecDecision, 100)
	for i := range decisions {
		decisions[i] = CrowdSecDecision{
			ID: int64(i + 1), Type: "ban", Scope: "Ip",
			Value:    fmt.Sprintf("198.51.%d.%d", i/256, i%256),
			Duration: "3h59m57.64s", Scenario: "crowdsecurity/http-probing",
		}
	}
	payload, err := json.Marshal(CrowdSecResponse{New: decisions})
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var response CrowdSecResponse
		if err := json.Unmarshal(payload, &response); err != nil {
			b.Fatal(err)
		}
	}
}
