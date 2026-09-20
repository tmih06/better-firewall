package services

import (
	"os"
	"path/filepath"
	"testing"
)

// writeServices installs a fixture services database under a BFW_PREFIX
// temp dir and points the resolver at it.
func writeServices(t *testing.T, content string) {
	t.Helper()
	dir := t.TempDir()
	if content != "" {
		etc := filepath.Join(dir, "etc")
		if err := os.MkdirAll(etc, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(etc, "services"), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("BFW_PREFIX", dir)
}

const fixture = `# comment line
ssh		22/tcp
smtp		25/tcp		mail
auth		113/tcp		authentication tap ident
domain		53/tcp
domain		53/udp
http		80/tcp		www
ntp		123/udp
syslog		514/udp
multi		99/tcp		alias1 alias2
`

func TestProtoTCPOnly(t *testing.T) {
	writeServices(t, fixture)
	port, proto, err := Proto("smtp")
	if err != nil {
		t.Fatalf("Proto(smtp): %v", err)
	}
	if port != 25 || proto != "tcp" {
		t.Fatalf("Proto(smtp) = %d, %q; want 25, tcp", port, proto)
	}
}

func TestProtoBothIsAny(t *testing.T) {
	writeServices(t, fixture)
	port, proto, err := Proto("domain")
	if err != nil {
		t.Fatalf("Proto(domain): %v", err)
	}
	if port != 53 || proto != "any" {
		t.Fatalf("Proto(domain) = %d, %q; want 53, any", port, proto)
	}
}

func TestProtoUDPOnly(t *testing.T) {
	writeServices(t, fixture)
	port, proto, err := Proto("ntp")
	if err != nil {
		t.Fatalf("Proto(ntp): %v", err)
	}
	if port != 123 || proto != "udp" {
		t.Fatalf("Proto(ntp) = %d, %q; want 123, udp", port, proto)
	}
}

func TestProtoAlias(t *testing.T) {
	writeServices(t, fixture)
	port, proto, err := Proto("alias2")
	if err != nil {
		t.Fatalf("Proto(alias2): %v", err)
	}
	if port != 99 || proto != "tcp" {
		t.Fatalf("Proto(alias2) = %d, %q; want 99, tcp", port, proto)
	}
}

func TestProtoUnknown(t *testing.T) {
	writeServices(t, fixture)
	if _, _, err := Proto("nosuchservice"); err == nil {
		t.Fatal("Proto(nosuchservice): want error")
	}
}

func TestExists(t *testing.T) {
	writeServices(t, fixture)
	if !Exists("smtp") {
		t.Fatal("Exists(smtp) = false")
	}
	if !Exists("alias1") {
		t.Fatal("Exists(alias1) = false")
	}
	if Exists("nosuchservice") {
		t.Fatal("Exists(nosuchservice) = true")
	}
}

func TestFallbackTable(t *testing.T) {
	// BFW_PREFIX with no etc/services → embedded fallback.
	writeServices(t, "")
	cases := []struct {
		name  string
		port  int
		proto string
	}{
		{"ssh", 22, "tcp"},
		{"http", 80, "tcp"},
		{"https", 443, "tcp"},
		{"smtp", 25, "tcp"},
		{"domain", 53, "any"},
		{"dns", 53, "any"},
		{"ntp", 123, "udp"},
		{"ftp", 21, "tcp"},
		{"tftp", 69, "udp"},
		{"imap", 143, "tcp"},
		{"pop3", 110, "tcp"},
		{"snmp", 161, "udp"},
		{"ldap", 389, "any"},
		{"syslog", 514, "udp"},
	}
	for _, c := range cases {
		port, proto, err := Proto(c.name)
		if err != nil {
			t.Fatalf("Proto(%s): %v", c.name, err)
		}
		if port != c.port || proto != c.proto {
			t.Fatalf("Proto(%s) = %d, %q; want %d, %q", c.name, port, proto, c.port, c.proto)
		}
	}
	if Exists("ssh") != true {
		t.Fatal("Exists(ssh) = false with fallback")
	}
	if Exists("nosuchservice") {
		t.Fatal("Exists(nosuchservice) = true with fallback")
	}
}

func TestProtocolHelpers(t *testing.T) {
	for _, p := range []string{"tcp", "udp", "ipv6", "esp", "ah", "igmp", "gre", "vrrp"} {
		if !SupportedProtocol(p) {
			t.Fatalf("SupportedProtocol(%s) = false", p)
		}
	}
	if SupportedProtocol("icmp") || SupportedProtocol("bogus") {
		t.Fatal("SupportedProtocol accepted unsupported protocol")
	}
	for _, p := range []string{"ipv6", "esp", "ah", "igmp", "gre", "vrrp"} {
		if !PortlessProtocol(p) {
			t.Fatalf("PortlessProtocol(%s) = false", p)
		}
	}
	if PortlessProtocol("tcp") {
		t.Fatal("PortlessProtocol(tcp) = true")
	}
	if !IPv4OnlyProtocol("ipv6") || !IPv4OnlyProtocol("igmp") {
		t.Fatal("IPv4OnlyProtocol rejected ipv6/igmp")
	}
	if IPv4OnlyProtocol("esp") {
		t.Fatal("IPv4OnlyProtocol(esp) = true")
	}
}
