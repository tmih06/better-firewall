package protect

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/tmih06/better-firewall/internal/store"
)

// JournalEvent is the systemd journal data consumed by configured jails.
type JournalEvent struct {
	Identifier string
	Message    string
}

type journalRecord struct {
	Identifier string `json:"SYSLOG_IDENTIFIER"`
	Message    string `json:"MESSAGE"`
}

// ParseJournalLine decodes one journalctl --output=json record.
func ParseJournalLine(line []byte) (JournalEvent, error) {
	var record journalRecord
	if err := json.Unmarshal(line, &record); err != nil {
		return JournalEvent{}, fmt.Errorf("decode journal JSON: %w", err)
	}
	return JournalEvent(record), nil
}

// ScanJournal applies bans from a journalctl JSON stream. Malformed records and
// failed state updates are reported and skipped; a reader error is returned so
// systemd can restart a failed journal follower.
func ScanJournal(r io.Reader, detector *Detector, apply func(store.ThreatBan) error, warnf func(string, ...any)) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		event, err := ParseJournalLine(scanner.Bytes())
		if err != nil {
			if warnf != nil {
				warnf("ignoring malformed journal record: %v", err)
			}
			continue
		}
		for _, ban := range detector.Observe(event.Identifier, event.Message, time.Now()) {
			if err := apply(ban); err != nil && warnf != nil {
				warnf("could not apply %s ban for %s: %v", ban.Source, ban.Address, err)
			}
		}
	}
	return scanner.Err()
}
