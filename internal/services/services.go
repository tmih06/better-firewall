// Package services resolves service names to port/protocol via
// /etc/services (mirroring ufw's getservbyname usage), with an embedded
// fallback table used when the file is unreadable.
//
// The file is parsed once and cached; the cache is keyed on the resolved
// path so tests can divert it via BFW_PREFIX.
package services

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// entry records the port and protocols a service name resolves to.
type entry struct {
	port     int
	tcp, udp bool
	other    bool // registered only for a non-tcp/udp protocol
}

var (
	mu         sync.Mutex
	loaded     bool
	loadedPath string
	table      map[string]*entry
)

// path is the services database location; BFW_PREFIX diverts it (tests and
// alternate-root installs), matching store.Default's prefix handling.
func path() string {
	if p := os.Getenv("BFW_PREFIX"); p != "" {
		return filepath.Join(p, "etc", "services")
	}
	return "/etc/services"
}

// fallback is used when the services file cannot be read. Protocols mirror
// the standard IANA assignments ufw users rely on.
var fallback = map[string]entry{
	"ssh":    {port: 22, tcp: true},
	"http":   {port: 80, tcp: true},
	"https":  {port: 443, tcp: true},
	"smtp":   {port: 25, tcp: true},
	"domain": {port: 53, tcp: true, udp: true},
	"dns":    {port: 53, tcp: true, udp: true},
	"ntp":    {port: 123, udp: true},
	"ftp":    {port: 21, tcp: true},
	"tftp":   {port: 69, udp: true},
	"imap":   {port: 143, tcp: true},
	"pop3":   {port: 110, tcp: true},
	"snmp":   {port: 161, udp: true},
	"ldap":   {port: 389, tcp: true, udp: true},
	"syslog": {port: 514, udp: true},
}

func load() {
	p := path()
	mu.Lock()
	defer mu.Unlock()
	if loaded && p == loadedPath {
		return
	}
	table = make(map[string]*entry)
	f, err := os.Open(p)
	if err != nil {
		for name, e := range fallback {
			c := e
			table[name] = &c
		}
		loaded, loadedPath = true, p
		return
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pp := strings.SplitN(fields[1], "/", 2)
		if len(pp) != 2 {
			continue
		}
		port, err := strconv.Atoi(pp[0])
		if err != nil {
			continue
		}
		proto := strings.ToLower(pp[1])
		// fields[0] is the official name; the rest are aliases.
		for _, name := range append([]string{fields[0]}, fields[2:]...) {
			e := table[name]
			if e == nil {
				e = &entry{port: port}
				table[name] = e
			}
			switch proto {
			case "tcp":
				e.tcp = true
			case "udp":
				e.udp = true
			default:
				e.other = true
			}
		}
	}
	loaded, loadedPath = true, p
}

// Proto resolves a service name to its port and protocol: "tcp" when only
// tcp is registered, "udp" when only udp, "any" when both, and "" when the
// name exists but for neither (mirroring getservbyname behavior). Lookup is
// case-sensitive like glibc getservbyname. Error when the name is unknown.
func Proto(name string) (port int, proto string, err error) {
	load()
	mu.Lock()
	defer mu.Unlock()
	e := table[name]
	if e == nil {
		return 0, "", fmt.Errorf("unknown service '%s'", name)
	}
	switch {
	case e.tcp && e.udp:
		proto = "any"
	case e.tcp:
		proto = "tcp"
	case e.udp:
		proto = "udp"
	}
	return e.port, proto, nil
}

// Exists reports whether the name appears in the services database at all
// (any protocol). Used for app-profile name-collision checks, mirroring
// ufw's bare getservbyname(name) probe.
func Exists(name string) bool {
	load()
	mu.Lock()
	defer mu.Unlock()
	_, ok := table[name]
	return ok
}

// SupportedProtocol reports whether p is a protocol ufw accepts in rules.
func SupportedProtocol(p string) bool {
	switch p {
	case "tcp", "udp", "ipv6", "esp", "ah", "igmp", "gre", "vrrp":
		return true
	}
	return false
}

// PortlessProtocol reports whether p forbids port numbers (ufw
// portless_protocols).
func PortlessProtocol(p string) bool {
	switch p {
	case "ipv6", "esp", "ah", "igmp", "gre", "vrrp":
		return true
	}
	return false
}

// IPv4OnlyProtocol reports whether p is restricted to IPv4 rules (ufw
// ipv4_only_protocols).
func IPv4OnlyProtocol(p string) bool {
	return p == "ipv6" || p == "igmp"
}
