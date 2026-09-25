package backend

import (
	"slices"
	"testing"

	"github.com/google/nftables"
)

// TestSnapshotForeignChains covers the live-ruleset prefix scan used by
// check/import-ufw: inclusion of matching chains, exclusion of unrelated and
// near-miss names, empty input, and preservation of ruleset order.
func TestSnapshotForeignChains(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		chains []string
		want   []string
	}{
		{
			name:   "nil chains",
			prefix: "ufw-",
			chains: nil,
			want:   nil,
		},
		{
			name:   "empty chains",
			prefix: "ufw-",
			chains: []string{},
			want:   nil,
		},
		{
			name:   "single exact prefix match",
			prefix: "ufw-",
			chains: []string{"ufw-before-input"},
			want:   []string{"ufw-before-input"},
		},
		{
			name:   "unrelated chains excluded",
			prefix: "ufw-",
			chains: []string{"INPUT", "FORWARD", "bfw-input", "DOCKER-USER"},
			want:   nil,
		},
		{
			name:   "similar names without exact prefix excluded",
			prefix: "ufw-",
			chains: []string{"ufw", "ufwother", "ufwX-input", "ufw2-logging", "UFW-input", ""},
			want:   nil,
		},
		{
			name:   "near-miss names alongside real match",
			prefix: "ufw-",
			chains: []string{"ufwother", "ufw-track", "INPUT"},
			want:   []string{"ufw-track"},
		},
		{
			name:   "longer prefix distinguishes ufw subfamilies",
			prefix: "ufw-user-",
			chains: []string{"ufw-other", "ufw-user-input", "ufw-user-output"},
			want:   []string{"ufw-user-input", "ufw-user-output"},
		},
		{
			name:   "chain names shorter than prefix never match",
			prefix: "ufw-other",
			chains: []string{"ufw", "ufw-", "u"},
			want:   nil,
		},
		{
			name:   "multiple matches preserve ruleset order",
			prefix: "ufw-",
			chains: []string{"INPUT", "ufw-skip-to-policy-input", "ufw-after-input", "DOCKER", "ufw-before-input", "ufw"},
			want:   []string{"ufw-skip-to-policy-input", "ufw-after-input", "ufw-before-input"},
		},
		{
			name:   "empty prefix matches every chain",
			prefix: "",
			chains: []string{"INPUT", "ufw-before-input"},
			want:   []string{"INPUT", "ufw-before-input"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &Snapshot{}
			for _, n := range tc.chains {
				s.Chains = append(s.Chains, &nftables.Chain{Name: n})
			}
			if got := s.ForeignChains(tc.prefix); !slices.Equal(got, tc.want) {
				t.Errorf("ForeignChains(%q) = %v, want %v", tc.prefix, got, tc.want)
			}
		})
	}
}
