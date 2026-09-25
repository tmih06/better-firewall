package cli

import (
	"reflect"
	"testing"
	"time"

	"github.com/tmih06/better-firewall/internal/protect"
	"github.com/tmih06/better-firewall/internal/store"
)

func TestCrowdSecUpdateNormalizesActiveIPAndRangeDecisions(t *testing.T) {
	now := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	response := protect.CrowdSecResponse{
		New: []protect.CrowdSecDecision{
			{ID: 10, Type: "ban", Scope: "Ip", Value: "203.0.113.8/32", Duration: "1h", Scenario: "ssh-bf"},
			{ID: 11, Type: "ban", Scope: "Range", Value: "198.51.100.17/24", Duration: "2h", Scenario: "range-ban"},
			{ID: 12, Type: "captcha", Scope: "Ip", Value: "192.0.2.4", Duration: "5m"},
		},
		Deleted: []protect.CrowdSecDecision{{ID: 9}},
	}
	update, err := crowdSecUpdate(response, true, now)
	if err != nil {
		t.Fatalf("crowdSecUpdate: %v", err)
	}
	if !update.Snapshot || len(update.Add) != 2 || len(update.DeleteIDs) != 0 {
		t.Fatalf("startup update = %+v", update)
	}
	if update.Add[0].Address != "203.0.113.8/32" || update.Add[0].DecisionID != 10 || update.Add[0].ExpiresAt != now.Add(time.Hour).Unix() {
		t.Fatalf("host decision = %+v", update.Add[0])
	}
	if update.Add[1].Address != "198.51.100.0/24" || update.Add[1].DecisionID != 11 {
		t.Fatalf("range decision = %+v", update.Add[1])
	}
}

func TestCrowdSecDeltaCarriesDeletionsAndRejectsMalformedBanAtomically(t *testing.T) {
	now := time.Now()
	response := protect.CrowdSecResponse{
		New:     []protect.CrowdSecDecision{{ID: 2, Type: "ban", Scope: "ip", Value: "2001:db8::1", Duration: "30m"}},
		Deleted: []protect.CrowdSecDecision{{ID: 1, Type: "ban"}},
	}
	update, err := crowdSecUpdate(response, false, now)
	if err != nil {
		t.Fatalf("crowdSecUpdate: %v", err)
	}
	if update.Snapshot || len(update.Add) != 1 || !reflect.DeepEqual(update.DeleteIDs, []int64{1}) {
		t.Fatalf("delta update = %+v", update)
	}
	response.New = append(response.New, protect.CrowdSecDecision{ID: 3, Type: "ban", Scope: "country", Value: "ZZ", Duration: "1h"})
	if _, err := crowdSecUpdate(response, false, now); err == nil {
		t.Fatal("crowdSecUpdate accepted an unsupported ban scope")
	}
}

func TestThreatSnapshotReconcilesProviderOnlyAndDeltaDeletesAfterAdds(t *testing.T) {
	now := time.Now().Unix()
	st := store.Defaults()
	st.Bans = []store.ThreatBan{
		{Address: "192.0.2.7", Source: "ssh:ssh", ExpiresAt: now + 3600},
		{Address: "198.51.100.1", Source: "crowdsec", DecisionID: 1, ExpiresAt: now + 600},
		{Address: "198.51.100.2", Source: "crowdsec", DecisionID: 2, ExpiresAt: now + 600},
	}
	local := st.Bans[0]
	active := store.ThreatBan{Address: "203.0.113.9", Source: "crowdsec", DecisionID: 3, ExpiresAt: now + 1800}
	changed, err := applyThreatUpdateToState(st, protect.Update{Snapshot: true, Add: []store.ThreatBan{active}}, now)
	if err != nil || !changed {
		t.Fatalf("snapshot update changed=%v err=%v", changed, err)
	}
	if len(st.Bans) != 2 || st.Bans[0] != local || st.Bans[1] != active {
		t.Fatalf("snapshot bans = %+v, want local plus current CrowdSec snapshot", st.Bans)
	}

	replacement := active
	replacement.Address = "203.0.113.10"
	replacement.ExpiresAt = now + 2400
	changed, err = applyThreatUpdateToState(st, protect.Update{Add: []store.ThreatBan{replacement}, DeleteIDs: []int64{3}}, now)
	if err != nil || !changed {
		t.Fatalf("delta update changed=%v err=%v", changed, err)
	}
	if len(st.Bans) != 1 || st.Bans[0] != local {
		t.Fatalf("delta bans = %+v, want local ban after add-then-delete", st.Bans)
	}
}

func TestThreatUpdateExtendsLocalBanAndRejectsInvalidBatchWithoutMutation(t *testing.T) {
	now := time.Now().Unix()
	st := store.Defaults()
	old := store.ThreatBan{Address: "203.0.113.1", Source: "ssh:ssh", ExpiresAt: now + 60}
	st.Bans = []store.ThreatBan{old}
	newBan := old
	newBan.ExpiresAt = now + 3600
	changed, err := applyThreatUpdateToState(st, protect.Update{Add: []store.ThreatBan{newBan}}, now)
	if err != nil || !changed || len(st.Bans) != 1 || st.Bans[0].ExpiresAt != now+3600 {
		t.Fatalf("local re-ban state=%+v changed=%v err=%v", st.Bans, changed, err)
	}
	before := append([]store.ThreatBan(nil), st.Bans...)
	_, err = applyThreatUpdateToState(st, protect.Update{Add: []store.ThreatBan{
		{Address: "198.51.100.1", Source: "crowdsec", DecisionID: 9, ExpiresAt: now + 3600},
		{Address: "not-an-ip", Source: "crowdsec", DecisionID: 10, ExpiresAt: now + 3600},
	}}, now)
	if err == nil {
		t.Fatal("invalid ban batch was accepted")
	}
	if !reflect.DeepEqual(st.Bans, before) {
		t.Fatalf("invalid batch partially mutated state: %+v", st.Bans)
	}
}

func TestJournalctlArgsDeduplicatesConfiguredIdentifiers(t *testing.T) {
	cfg := protect.Config{Jails: []protect.Jail{
		{Identifiers: []string{"sshd", "pam_unix"}},
		{Identifiers: []string{"sshd", "dovecot"}},
	}}
	got := journalctlArgs(cfg)
	want := []string{"--follow", "--lines=0", "--output=json", "--no-pager", "--identifier=sshd", "--identifier=pam_unix", "--identifier=dovecot"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("journalctlArgs = %v, want %v", got, want)
	}
}
