package protect

import (
	"regexp"
	"time"

	"net/netip"

	"github.com/tmih06/better-firewall/internal/store"
)

type compiledPattern struct {
	re    *regexp.Regexp
	ipIdx int
}

type compiledJail struct {
	name        string
	identifiers map[string]struct{}
	patterns    []compiledPattern
	maxRetries  int
	findTime    time.Duration
	banTime     time.Duration
	ignoreIPs   []netip.Prefix
}

type failureKey struct {
	jail string
	ip   netip.Addr
}

// Detector keeps in-memory failure windows for one running protection service.
type Detector struct {
	jails     []compiledJail
	failures  map[failureKey][]time.Time
	nextPrune time.Time
}

// NewDetector compiles the validated jail configuration.
func NewDetector(cfg Config) (*Detector, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	d := &Detector{failures: map[failureKey][]time.Time{}}
	for _, source := range cfg.Jails {
		jail := compiledJail{
			name:        source.Name,
			identifiers: make(map[string]struct{}, len(source.Identifiers)),
			maxRetries:  source.MaxRetries,
		}
		for _, id := range source.Identifiers {
			jail.identifiers[id] = struct{}{}
		}
		jail.findTime, _ = time.ParseDuration(source.FindTime)
		jail.banTime, _ = time.ParseDuration(source.BanTime)
		for _, raw := range source.Patterns {
			re := regexp.MustCompile(raw)
			jail.patterns = append(jail.patterns, compiledPattern{re: re, ipIdx: re.SubexpIndex("ip")})
		}
		for _, raw := range source.IgnoreIPs {
			prefix, _ := parsePrefix(raw)
			jail.ignoreIPs = append(jail.ignoreIPs, prefix)
		}
		d.jails = append(d.jails, jail)
	}
	return d, nil
}

// Observe records one journal message and returns any bans reached at this
// event. It is intended for a single journal-reader goroutine.
func (d *Detector) Observe(identifier, message string, now time.Time) []store.ThreatBan {
	d.prune(now)
	var bans []store.ThreatBan
	for i := range d.jails {
		jail := &d.jails[i]
		if _, ok := jail.identifiers[identifier]; !ok {
			continue
		}
		ip, ok := matchingIP(jail.patterns, message)
		if !ok || ignored(ip, jail.ignoreIPs) {
			continue
		}
		key := failureKey{jail: jail.name, ip: ip}
		cutoff := now.Add(-jail.findTime)
		failures := d.failures[key]
		kept := failures[:0]
		for _, at := range failures {
			if !at.Before(cutoff) {
				kept = append(kept, at)
			}
		}
		failures = append(kept, now)
		if len(failures) < jail.maxRetries {
			d.failures[key] = failures
			continue
		}
		delete(d.failures, key)
		bans = append(bans, store.ThreatBan{
			Address:   ip.String(),
			Source:    "ssh:" + jail.name,
			Reason:    "failed authentication",
			ExpiresAt: now.Add(jail.banTime).Unix(),
		})
	}
	return bans
}

func (d *Detector) prune(now time.Time) {
	if !d.nextPrune.IsZero() && now.Before(d.nextPrune) {
		return
	}
	findTimes := make(map[string]time.Duration, len(d.jails))
	for _, jail := range d.jails {
		findTimes[jail.name] = jail.findTime
	}
	for key, failures := range d.failures {
		cutoff := now.Add(-findTimes[key.jail])
		kept := failures[:0]
		for _, at := range failures {
			if !at.Before(cutoff) {
				kept = append(kept, at)
			}
		}
		if len(kept) == 0 {
			delete(d.failures, key)
		} else {
			d.failures[key] = kept
		}
	}
	d.nextPrune = now.Add(time.Minute)
}

func matchingIP(patterns []compiledPattern, message string) (netip.Addr, bool) {
	for _, pattern := range patterns {
		match := pattern.re.FindStringSubmatch(message)
		if match == nil || pattern.ipIdx >= len(match) {
			continue
		}
		ip, err := netip.ParseAddr(match[pattern.ipIdx])
		if err == nil {
			return ip.WithZone("").Unmap(), true
		}
	}
	return netip.Addr{}, false
}

func ignored(ip netip.Addr, prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}
