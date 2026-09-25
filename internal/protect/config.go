package protect

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"time"
)

// Config selects the local journal jails and optional CrowdSec bouncer.
type Config struct {
	Jails    []Jail         `json:"jails"`
	CrowdSec CrowdSecConfig `json:"crowdsec,omitempty"`
}

// Jail counts matching journal messages from configured systemd identifiers.
type Jail struct {
	Name        string   `json:"name"`
	Identifiers []string `json:"identifiers"`
	Patterns    []string `json:"patterns"` // each expression captures source address in named group ip
	MaxRetries  int      `json:"max_retries"`
	FindTime    string   `json:"find_time"`
	BanTime     string   `json:"ban_time"`
	IgnoreIPs   []string `json:"ignore_ips,omitempty"`
}

var jailNameRE = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// DefaultConfig enables a conservative SSH failed-password jail. Operators can
// add service identifiers and patterns without changing firewall ownership.
func DefaultConfig() Config {
	return Config{Jails: []Jail{{
		Name:        "ssh",
		Identifiers: []string{"sshd"},
		Patterns:    []string{`(?i)failed password for (?:invalid user )?\S+ from (?P<ip>[a-f0-9:.]+) port [0-9]+`},
		MaxRetries:  5,
		FindTime:    "10m",
		BanTime:     "1h",
		IgnoreIPs:   []string{"127.0.0.0/8", "::1/128"},
	}}}
}

// LoadConfig reads and validates the protection JSON file.
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parsing %s: %w", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Config{}, fmt.Errorf("parsing %s: multiple JSON values", path)
		}
		return Config{}, fmt.Errorf("parsing %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("invalid protection config %s: %w", path, err)
	}
	return cfg, nil
}

// Validate rejects incomplete jails and malformed threat-source settings.
func (cfg Config) Validate() error {
	if len(cfg.Jails) == 0 && cfg.CrowdSec.URL == "" {
		return fmt.Errorf("enable at least one journal jail or configure CrowdSec")
	}
	if (cfg.CrowdSec.URL == "") != (cfg.CrowdSec.APIKeyFile == "") {
		return fmt.Errorf("CrowdSec url and api_key_file must be configured together")
	}
	if cfg.CrowdSec.PollInterval != "" {
		d, err := time.ParseDuration(cfg.CrowdSec.PollInterval)
		if err != nil || d <= 0 {
			return fmt.Errorf("CrowdSec poll_interval must be a positive duration")
		}
	}
	seenNames := map[string]bool{}
	for _, jail := range cfg.Jails {
		if !jailNameRE.MatchString(jail.Name) {
			return fmt.Errorf("jail name %q must contain only letters, digits, _ or -", jail.Name)
		}
		if seenNames[jail.Name] {
			return fmt.Errorf("duplicate jail name %q", jail.Name)
		}
		seenNames[jail.Name] = true
		if len(jail.Identifiers) == 0 {
			return fmt.Errorf("jail %s has no journal identifiers", jail.Name)
		}
		for _, id := range jail.Identifiers {
			if strings.TrimSpace(id) == "" || strings.ContainsAny(id, "\x00\r\n") {
				return fmt.Errorf("jail %s has an invalid journal identifier", jail.Name)
			}
		}
		if jail.MaxRetries < 1 {
			return fmt.Errorf("jail %s max_retries must be positive", jail.Name)
		}
		findTime, err := time.ParseDuration(jail.FindTime)
		if err != nil || findTime <= 0 {
			return fmt.Errorf("jail %s find_time must be a positive duration", jail.Name)
		}
		banTime, err := time.ParseDuration(jail.BanTime)
		if err != nil || banTime <= 0 {
			return fmt.Errorf("jail %s ban_time must be a positive duration", jail.Name)
		}
		if banTime < time.Second {
			return fmt.Errorf("jail %s ban_time must be at least one second", jail.Name)
		}
		if len(jail.Patterns) == 0 {
			return fmt.Errorf("jail %s has no failure patterns", jail.Name)
		}
		for _, pattern := range jail.Patterns {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("jail %s pattern: %w", jail.Name, err)
			}
			if re.SubexpIndex("ip") < 0 {
				return fmt.Errorf("jail %s pattern must capture the source address as (?P<ip>...)", jail.Name)
			}
		}
		for _, raw := range jail.IgnoreIPs {
			if _, err := parsePrefix(raw); err != nil {
				return fmt.Errorf("jail %s ignore_ips %q: %w", jail.Name, raw, err)
			}
		}
	}
	return nil
}

func parsePrefix(raw string) (netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(raw); err == nil {
		prefix = prefix.Masked()
		if prefix.Addr().Is4In6() {
			if prefix.Bits() < 96 {
				return netip.Prefix{}, fmt.Errorf("IPv4-mapped prefix %q is broader than an IPv4 address", raw)
			}
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96).Masked()
		}
		return prefix, nil
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("must be an IP address or CIDR prefix")
	}
	addr = addr.WithZone("").Unmap()
	bits := 128
	if addr.Is4() {
		bits = 32
	}
	return netip.PrefixFrom(addr, bits), nil
}

// PollIntervalDuration returns the configured CrowdSec polling interval.
func (cfg CrowdSecConfig) PollIntervalDuration() (time.Duration, error) {
	if cfg.PollInterval == "" {
		return 30 * time.Second, nil
	}
	d, err := time.ParseDuration(cfg.PollInterval)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("CrowdSec poll_interval must be a positive duration")
	}
	return d, nil
}
