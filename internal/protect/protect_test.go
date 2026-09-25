package protect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tmih06/better-firewall/internal/defaults"
	"github.com/tmih06/better-firewall/internal/store"
)

func testJailConfig() Config {
	return Config{Jails: []Jail{{
		Name: "ssh", Identifiers: []string{"sshd"},
		Patterns:   []string{`(?i)failed password for (?:invalid user )?\S+ from (?P<ip>[a-f0-9:.]+) port [0-9]+`},
		MaxRetries: 2, FindTime: "10m", BanTime: "1h",
	}}}
}

func TestConfigDefaultSSHJailIsValid(t *testing.T) {
	if err := DefaultConfig().Validate(); err != nil {
		t.Fatalf("default protection config is invalid: %v", err)
	}
}

func TestEmbeddedProtectionDefaultMatchesRuntimeConfig(t *testing.T) {
	data, err := defaults.Read("protect.json")
	if err != nil {
		t.Fatalf("read embedded protection config: %v", err)
	}
	var embedded Config
	if err := json.Unmarshal(data, &embedded); err != nil {
		t.Fatalf("decode embedded protection config: %v", err)
	}
	if err := embedded.Validate(); err != nil {
		t.Fatalf("embedded protection config is invalid: %v", err)
	}
	if !reflect.DeepEqual(embedded, DefaultConfig()) {
		t.Fatalf("embedded protection config differs from DefaultConfig:\nembedded=%+v\ncode=%+v", embedded, DefaultConfig())
	}
	path := filepath.Join(t.TempDir(), "protect.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	loaded, err := LoadConfig(path)
	if err != nil || !reflect.DeepEqual(loaded, DefaultConfig()) {
		t.Fatalf("LoadConfig = %+v, err=%v", loaded, err)
	}
	if err := os.WriteFile(path, []byte(`{"jails":[],"unexpected":true}`), 0600); err != nil {
		t.Fatalf("write invalid config: %v", err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("LoadConfig accepted an unknown configuration field")
	}
}

func TestDefaultDetectorIgnoresLoopbackSources(t *testing.T) {
	d, err := NewDetector(DefaultConfig())
	if err != nil {
		t.Fatalf("NewDetector: %v", err)
	}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, ip := range []string{"127.0.0.1", "::1"} {
		message := "Failed password for root from " + ip + " port 22 ssh2"
		for i := 0; i < 10; i++ {
			if got := d.Observe("sshd", message, now.Add(time.Duration(i)*time.Second)); len(got) != 0 {
				t.Fatalf("loopback %s produced bans: %+v", ip, got)
			}
		}
	}
}

func TestDetectorBansAtRetryThreshold(t *testing.T) {
	d, err := NewDetector(testJailConfig())
	if err != nil {
		t.Fatalf("NewDetector: %v", err)
	}
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	message := "Failed password for root from 203.0.113.9 port 22 ssh2"
	if got := d.Observe("sshd", message, start); len(got) != 0 {
		t.Fatalf("first failed login produced bans: %+v", got)
	}
	bans := d.Observe("sshd", message, start.Add(9*time.Minute))
	if len(bans) != 1 {
		t.Fatalf("second failed login produced %d bans, want one", len(bans))
	}
	ban := bans[0]
	if ban.Address != "203.0.113.9" || ban.Source != "ssh:ssh" || ban.ExpiresAt != start.Add(69*time.Minute).Unix() {
		t.Fatalf("ban = %+v, want source-IP ban expiring one hour after threshold", ban)
	}
}

func TestDetectorFindTimeAndIgnoreNetworks(t *testing.T) {
	cfg := testJailConfig()
	cfg.Jails[0].IgnoreIPs = []string{"203.0.113.0/24"}
	d, err := NewDetector(cfg)
	if err != nil {
		t.Fatalf("NewDetector: %v", err)
	}
	start := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	message := "Failed password for root from 198.51.100.8 port 22 ssh2"
	if got := d.Observe("other", message, start); len(got) != 0 {
		t.Fatalf("unconfigured identifier produced bans: %+v", got)
	}
	if got := d.Observe("sshd", "Failed password for root from 203.0.113.8 port 22 ssh2", start); len(got) != 0 {
		t.Fatalf("ignored network produced bans: %+v", got)
	}
	if got := d.Observe("sshd", message, start); len(got) != 0 {
		t.Fatalf("first failure produced bans: %+v", got)
	}
	if got := d.Observe("sshd", message, start.Add(11*time.Minute)); len(got) != 0 {
		t.Fatalf("failure outside findtime produced bans: %+v", got)
	}
	bans := d.Observe("sshd", message, start.Add(12*time.Minute))
	if len(bans) != 1 || bans[0].Address != "198.51.100.8" {
		t.Fatalf("failure inside rolling findtime produced %+v, want one ban", bans)
	}
}

func TestDetectorRejectsInvalidPatternAndDurations(t *testing.T) {
	cfg := testJailConfig()
	cfg.Jails[0].Patterns = []string{`Failed password from [0-9.]+`}
	if err := cfg.Validate(); err == nil {
		t.Fatal("config accepted pattern without named ip capture")
	}
	cfg = testJailConfig()
	cfg.Jails[0].BanTime = "0s"
	if err := cfg.Validate(); err == nil {
		t.Fatal("config accepted a zero-length ban")
	}
}

func TestParseJournalLine(t *testing.T) {
	event, err := ParseJournalLine([]byte(`{"SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Failed password for root from 203.0.113.9 port 22 ssh2"}`))
	if err != nil {
		t.Fatalf("ParseJournalLine: %v", err)
	}
	if event.Identifier != "sshd" || event.Message != "Failed password for root from 203.0.113.9 port 22 ssh2" {
		t.Fatalf("journal event = %+v", event)
	}
	if _, err := ParseJournalLine([]byte("not json")); err == nil {
		t.Fatal("ParseJournalLine accepted malformed JSON")
	}
}

func TestScanJournalAppliesThresholdBanAndContinuesMalformedRecords(t *testing.T) {
	detector, err := NewDetector(testJailConfig())
	if err != nil {
		t.Fatalf("NewDetector: %v", err)
	}
	record := `{"SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Failed password for root from 203.0.113.9 port 22 ssh2"}`
	input := strings.NewReader(record + "\nnot-json\n" + record + "\n")
	var applied []store.ThreatBan
	warnings := 0
	err = ScanJournal(input, detector, func(ban store.ThreatBan) error {
		applied = append(applied, ban)
		return nil
	}, func(string, ...any) {
		warnings++
	})
	if err != nil {
		t.Fatalf("ScanJournal: %v", err)
	}
	if len(applied) != 1 || applied[0].Address != "203.0.113.9" || applied[0].Source != "ssh:ssh" {
		t.Fatalf("applied bans = %+v, want one threshold ban", applied)
	}
	if warnings != 1 {
		t.Fatalf("warnings = %d, want one malformed-record warning", warnings)
	}
}
