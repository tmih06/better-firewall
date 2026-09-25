package protect

import "github.com/tmih06/better-firewall/internal/store"

// CrowdSecConfig configures the optional CrowdSec local-API bouncer.
type CrowdSecConfig struct {
	URL          string `json:"url,omitempty"`
	APIKeyFile   string `json:"api_key_file,omitempty"`
	PollInterval string `json:"poll_interval,omitempty"`
}

// CrowdSecDecision is the bouncer-facing subset of a LAPI decision.
type CrowdSecDecision struct {
	ID       int64  `json:"id"`
	Type     string `json:"type"`
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	Duration string `json:"duration"`
	Scenario string `json:"scenario"`
}

// CrowdSecResponse carries one full startup snapshot or one server-side delta.
type CrowdSecResponse struct {
	New     []CrowdSecDecision `json:"new"`
	Deleted []CrowdSecDecision `json:"deleted"`
}

// Update applies one local ban or one CrowdSec stream batch atomically.
type Update struct {
	Snapshot  bool
	Add       []store.ThreatBan
	DeleteIDs []int64
}
