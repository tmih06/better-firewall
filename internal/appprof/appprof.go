// Package appprof parses ufw-compatible application profiles: INI files
// with one [section] per profile carrying title, description, and a
// '|'-separated ports list of port[/proto] items.
//
// Semantics mirror ufw's applications.py: profile names must match
// ^[a-zA-Z0-9][a-zA-Z0-9 _\-\.+]*$ (≤64 chars, not "all", not an integer);
// profiles colliding with /etc/services names are skipped; port lists and
// ranges require an explicit protocol.
package appprof

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/tmih06/better-firewall/internal/services"
)

// PortSpec is one '|'-separated item of a profile's ports field.
type PortSpec struct {
	// Ports is the raw port expression: a single port ("80"), comma list
	// ("80,443"), range ("8080:8090"), or "any".
	Ports string
	// Proto is "tcp", "udp", or "any" (both).
	Proto string
}

// Profile is one parsed application profile.
type Profile struct {
	Name        string
	Title       string
	Description string
	Ports       []PortSpec
}

// Expand returns the profile's parsed port items.
func (p *Profile) Expand() []PortSpec {
	out := make([]PortSpec, len(p.Ports))
	copy(out, p.Ports)
	return out
}

// Find returns the profile named name, matched case-insensitively like
// ufw's find_application_name, or nil.
func Find(profiles []*Profile, name string) *Profile {
	for _, p := range profiles {
		if strings.EqualFold(p.Name, name) {
			return p
		}
	}
	return nil
}

var nameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9 _\-\.+]*$`)

// ValidName reports whether name is a legal profile name (ufw
// valid_profile_name): the regex above, ≤64 chars, not "all", not an
// integer (so profile names can never collide with port numbers).
func ValidName(name string) bool {
	if name == "all" || len(name) > 64 {
		return false
	}
	if _, err := strconv.Atoi(name); err == nil {
		return false
	}
	return nameRe.MatchString(name)
}

// Load scans the given directories for *.ini profiles and returns all
// valid profiles. Earlier directories win on name collisions. Profiles
// whose names collide with /etc/services are dropped silently; use LoadAll
// to observe them.
func Load(dirs ...string) ([]*Profile, error) {
	profiles, _, err := LoadAll(dirs...)
	return profiles, err
}

// LoadAll is Load plus the names of profiles skipped because they collide
// with /etc/services (caller warns "Skipping '<name>': also in
// /etc/services"). Malformed files and invalid profiles are skipped
// silently, mirroring ufw's warn-and-continue behavior.
func LoadAll(dirs ...string) (profiles []*Profile, skipped []string, err error) {
	seen := make(map[string]bool)
	collided := make(map[string]bool)
	for _, dir := range dirs {
		ents, derr := os.ReadDir(dir)
		if derr != nil {
			continue // missing/unreadable dir: no profiles, not an error
		}
		names := make([]string, 0, len(ents))
		for _, e := range ents {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".ini") {
				continue
			}
			names = append(names, e.Name())
		}
		sort.Strings(names)
		for _, fn := range names {
			sects, perr := parseFile(filepath.Join(dir, fn))
			if perr != nil {
				continue // ufw: "Skipping '<file>': couldn't process"
			}
			for _, s := range sects {
				if !ValidName(s.name) {
					continue
				}
				if services.Exists(s.name) {
					if !collided[s.name] {
						collided[s.name] = true
						skipped = append(skipped, s.name)
					}
					continue
				}
				if seen[s.name] {
					continue // first dir wins
				}
				p, verr := buildProfile(s)
				if verr != nil {
					continue
				}
				seen[s.name] = true
				profiles = append(profiles, p)
			}
		}
	}
	return profiles, skipped, nil
}

// section is a raw parsed INI section.
type section struct {
	name   string
	fields map[string]string
}

// parseFile parses one INI file into its sections, in file order. Keys are
// lowercased (configparser parity); values keep their case. '#' and ';'
// start comments; indented lines continue the previous value.
func parseFile(path string) ([]section, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []section
	cur := -1
	lastKey := ""
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		// Continuation: indented line extends the previous value.
		if cur >= 0 && lastKey != "" && len(raw) > 0 && (raw[0] == ' ' || raw[0] == '\t') {
			out[cur].fields[lastKey] += " " + line
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return nil, fmt.Errorf("malformed section header %q", line)
			}
			name := strings.TrimSpace(line[1 : len(line)-1])
			for _, s := range out {
				if s.name == name {
					return nil, fmt.Errorf("duplicate section %q", name)
				}
			}
			out = append(out, section{name: name, fields: make(map[string]string)})
			cur = len(out) - 1
			lastKey = ""
			continue
		}
		i := strings.IndexAny(line, "=:")
		if i < 0 || cur < 0 {
			return nil, fmt.Errorf("malformed line %q", line)
		}
		key := strings.ToLower(strings.TrimSpace(line[:i]))
		val := strings.TrimSpace(line[i+1:])
		out[cur].fields[key] = val
		lastKey = key
	}
	return out, nil
}

var (
	rangeRe   = regexp.MustCompile(`^\d+:\d+$`)
	singleRe  = regexp.MustCompile(`^\d+$`)
	svcNameRe = regexp.MustCompile(`^\w[\w\-]+`)
)

// buildProfile validates one section into a Profile (ufw verify_profile).
func buildProfile(s section) (*Profile, error) {
	title := s.fields["title"]
	desc := s.fields["description"]
	ports := s.fields["ports"]
	if title == "" || desc == "" || ports == "" {
		return nil, fmt.Errorf("profile '%s' missing required field", s.name)
	}
	for k, v := range s.fields {
		if len(k) > 64 || len(v) > 1024 {
			return nil, fmt.Errorf("profile '%s' field too long", s.name)
		}
	}
	p := &Profile{Name: s.name, Title: title, Description: desc}
	for _, item := range strings.Split(ports, "|") {
		spec, err := parsePortItem(item)
		if err != nil {
			return nil, fmt.Errorf("Invalid ports in profile '%s'", s.name)
		}
		p.Ports = append(p.Ports, spec)
	}
	return p, nil
}

// parsePortItem parses one "port[/proto]" item (ufw parse_port_proto +
// set_port validation). Lists and ranges require an explicit proto.
func parsePortItem(item string) (PortSpec, error) {
	var spec PortSpec
	parts := strings.Split(item, "/")
	switch len(parts) {
	case 1:
		spec.Ports, spec.Proto = parts[0], "any"
	case 2:
		spec.Ports, spec.Proto = parts[0], parts[1]
		if services.PortlessProtocol(spec.Proto) {
			return spec, fmt.Errorf("Invalid port with protocol '%s'", spec.Proto)
		}
	default:
		return spec, fmt.Errorf("Bad port")
	}
	if spec.Proto != "any" && !services.SupportedProtocol(spec.Proto) {
		return spec, fmt.Errorf("Unsupported protocol '%s'", spec.Proto)
	}
	if spec.Proto == "any" && (strings.ContainsAny(spec.Ports, ":,")) {
		return spec, fmt.Errorf("list or range requires explicit proto")
	}
	if err := validPortList(spec.Ports); err != nil {
		return spec, err
	}
	return spec, nil
}

// validPortList mirrors UFWRule.set_port validation for a port expression:
// "any", or a comma list of single ports and lo:hi ranges (≤14 separators,
// no leading/trailing separators, bounds 1-65535, lo<hi), or a service
// name resolvable via /etc/services.
func validPortList(ports string) error {
	bad := fmt.Errorf("Bad port '%s'", ports)
	if ports == "any" {
		return nil
	}
	if strings.HasPrefix(ports, ",") || strings.HasPrefix(ports, ":") ||
		strings.HasSuffix(ports, ",") || strings.HasSuffix(ports, ":") {
		return bad
	}
	if strings.Count(ports, ",")+strings.Count(ports, ":") > 14 {
		return bad
	}
	for _, p := range strings.Split(ports, ",") {
		switch {
		case rangeRe.MatchString(p):
			ran := strings.SplitN(p, ":", 2)
			lo, _ := strconv.Atoi(ran[0])
			hi, _ := strconv.Atoi(ran[1])
			if lo < 1 || lo > 65535 || hi < 1 || hi > 65535 || lo >= hi {
				return bad
			}
		case singleRe.MatchString(p):
			n, _ := strconv.Atoi(p)
			if n < 1 || n > 65535 {
				return bad
			}
		case svcNameRe.MatchString(p):
			if _, _, err := services.Proto(p); err != nil {
				return bad
			}
		default:
			return bad
		}
	}
	return nil
}
