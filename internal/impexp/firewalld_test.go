package impexp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tmih06/better-firewall/internal/rule"
	"github.com/tmih06/better-firewall/internal/store"
)

// emptyVendor returns a directory with no firewalld files so tests do
// not depend on the host's /usr/lib/firewalld.
func emptyVendor(t *testing.T) string {
	t.Helper()
	return t.TempDir()
}

// fwFixture builds an interface-bound default zone plus a dead zone.
// Source-bound zones live in separate tests because interface and
// source bindings cannot coexist across zones (unrepresentable
// precedence) — see checkZoneOverlap.
func fwFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "firewalld.conf"), "DefaultZone=public\nLogDenied=off\n")
	writeFile(t, filepath.Join(dir, "zones", "public.xml"), `<?xml version="1.0" encoding="utf-8"?>
<zone>
  <short>Public</short>
  <description>public zone</description>
  <interface name="eth0"/>
  <service name="mysvc"/>
  <port port="22" protocol="tcp"/>
  <protocol value="ah"/>
  <rule family="ipv4">
    <source address="10.1.0.0/16"/>
    <port port="8080" protocol="tcp"/>
    <log prefix="pre "/>
    <accept/>
  </rule>
  <rule family="ipv6">
    <destination address="2001:db8::1"/>
    <reject/>
  </rule>
</zone>
`)
	writeFile(t, filepath.Join(dir, "zones", "dead.xml"), `<zone>
  <port port="9999" protocol="tcp"/>
</zone>
`)
	writeFile(t, filepath.Join(dir, "services", "mysvc.xml"), `<service>
  <short>My</short>
  <port port="8080-8090" protocol="tcp"/>
  <port port="53" protocol="udp"/>
</service>
`)
	return dir
}

func findRule(rules []rule.Rule, match func(*rule.Rule) bool) *rule.Rule {
	for i := range rules {
		if match(&rules[i]) {
			return &rules[i]
		}
	}
	return nil
}

func hasPort(a rule.AddrSpec, lo, hi uint16, proto string) bool {
	for _, p := range a.Ports {
		if p.Lo == lo && p.Hi == hi && p.Proto == proto {
			return true
		}
	}
	return false
}

func TestImportFirewalld(t *testing.T) {
	dir := fwFixture(t)
	st := store.Defaults()
	merged, n, warnings, err := importFirewalld(dir, emptyVendor(t), st)
	if err != nil {
		t.Fatalf("ImportFirewalld: %v", err)
	}

	// public (iface eth0): service mysvc dual, port 22 dual,
	// proto ah dual, rich accept v4, rich reject v6 → 4+4.
	// dead: skipped (unbound, not default).
	want4, want6 := 4, 4
	if len(merged.Rules4) != want4 {
		t.Fatalf("Rules4 = %d, want %d\n%v", len(merged.Rules4), want4, merged.Rules4)
	}
	if len(merged.Rules6) != want6 {
		t.Fatalf("Rules6 = %d, want %d\n%v", len(merged.Rules6), want6, merged.Rules6)
	}
	if n != want4+want6 {
		t.Fatalf("added = %d, want %d", n, want4+want6)
	}
	if len(st.Rules4) != 0 || len(st.Rules6) != 0 {
		t.Fatalf("input state mutated: %d/%d rules", len(st.Rules4), len(st.Rules6))
	}

	r4 := findRule(merged.Rules4, func(r *rule.Rule) bool {
		return r.IfaceIn == "eth0" && hasPort(r.Dst, 22, 22, "tcp")
	})
	if r4 == nil {
		t.Fatal("missing v4 eth0 tcp/22 rule")
	}
	r6 := findRule(merged.Rules6, func(r *rule.Rule) bool {
		return r.IfaceIn == "eth0" && hasPort(r.Dst, 22, 22, "tcp")
	})
	if r6 == nil || r6.ID != r4.ID {
		t.Fatalf("dual rule mismatch: v4 %+v, v6 %+v", r4, r6)
	}
	if r4.Action != rule.ActionAllow || r4.Direction != rule.DirIn || r4.Proto != "tcp" {
		t.Errorf("port rule fields wrong: %+v", r4)
	}
	if !strings.Contains(r4.Comment, "public") {
		t.Errorf("expected provenance comment, got %q", r4.Comment)
	}

	svc := findRule(merged.Rules4, func(r *rule.Rule) bool {
		return hasPort(r.Dst, 8080, 8090, "tcp")
	})
	if svc == nil || !hasPort(svc.Dst, 53, 53, "udp") {
		t.Fatalf("service rule missing port range: %+v", merged.Rules4)
	}

	ar := findRule(merged.Rules4, func(r *rule.Rule) bool {
		return r.Src.IP == "10.1.0.0/16" && hasPort(r.Dst, 8080, 8080, "tcp")
	})
	if ar == nil || ar.Action != rule.ActionAllow || ar.Log != rule.LogAll {
		t.Fatalf("rich accept rule wrong: %+v", ar)
	}
	rr := findRule(merged.Rules6, func(r *rule.Rule) bool {
		return r.Dst.IP == "2001:db8::1"
	})
	if rr == nil || rr.Action != rule.ActionReject {
		t.Fatalf("rich reject rule wrong: %+v", rr)
	}

	var sawDead, sawPrefix bool
	for _, w := range warnings {
		if strings.Contains(w, "dead") && strings.Contains(w, "skipped") {
			sawDead = true
		}
		if strings.Contains(w, "log prefix") {
			sawPrefix = true
		}
	}
	if !sawDead {
		t.Errorf("missing dead-zone warning in %v", warnings)
	}
	if !sawPrefix {
		t.Errorf("missing log-prefix warning in %v", warnings)
	}
}

// Source-bound zones only: disjoint v4 ranges plus a v6 zone may
// coexist (no shared family => no cross-zone dispatch ambiguity).
func TestImportFirewalldSourceBindings(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "firewalld.conf"), "DefaultZone=a\n")
	writeFile(t, filepath.Join(dir, "zones", "a.xml"), `<zone>
  <source address="10.0.0.0/8"/>
  <service name="mysvc"/>
</zone>
`)
	writeFile(t, filepath.Join(dir, "zones", "b.xml"), `<zone>
  <source address="172.16.0.0/12"/>
  <port port="9090" protocol="tcp"/>
</zone>
`)
	writeFile(t, filepath.Join(dir, "zones", "v6.xml"), `<zone>
  <source address="2001:db8::/32"/>
  <service name="v6svc"/>
</zone>
`)
	writeFile(t, filepath.Join(dir, "services", "mysvc.xml"), `<service>
  <port port="8080-8090" protocol="tcp"/>
  <port port="53" protocol="udp"/>
</service>
`)
	writeFile(t, filepath.Join(dir, "services", "v6svc.xml"), `<service>
  <port port="2222" protocol="tcp"/>
</service>
`)

	merged, n, _, err := importFirewalld(dir, emptyVendor(t), store.Defaults())
	if err != nil {
		t.Fatalf("ImportFirewalld: %v", err)
	}
	// a: svc dual-shape but bound v4 → 1 v4; b: 1 v4; v6: 1 v6.
	if len(merged.Rules4) != 2 || len(merged.Rules6) != 1 || n != 3 {
		t.Fatalf("rules %d/%d n=%d, want 2/1/3", len(merged.Rules4), len(merged.Rules6), n)
	}
	sb := findRule(merged.Rules4, func(r *rule.Rule) bool {
		return r.Src.IP == "10.0.0.0/8" && hasPort(r.Dst, 53, 53, "udp")
	})
	if sb == nil {
		t.Fatalf("missing source-bound rule: %+v", merged.Rules4)
	}
	if findRule(merged.Rules4, func(r *rule.Rule) bool {
		return r.Src.IP == "172.16.0.0/12" && hasPort(r.Dst, 9090, 9090, "tcp")
	}) == nil {
		t.Error("missing disjoint source-bound rule")
	}
	v6 := findRule(merged.Rules6, func(r *rule.Rule) bool {
		return r.Src.IP == "2001:db8::/32" && hasPort(r.Dst, 2222, 2222, "tcp")
	})
	if v6 == nil {
		t.Fatal("missing v6 source-bound rule")
	}
}

func TestImportFirewalldIPSetBinding(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "firewalld.conf"), "DefaultZone=z\n")
	writeFile(t, filepath.Join(dir, "zones", "z.xml"), `<zone>
  <source ipset="allowlist"/>
  <port port="443" protocol="tcp"/>
</zone>
`)
	writeFile(t, filepath.Join(dir, "ipsets", "allowlist.xml"), `<ipset type="hash:ip">
  <option name="family" value="inet"/>
  <entry>192.0.2.10</entry>
  <entry>198.51.100.20</entry>
</ipset>
`)
	merged, _, _, err := importFirewalld(dir, emptyVendor(t), store.Defaults())
	if err != nil {
		t.Fatalf("ImportFirewalld: %v", err)
	}
	is := findRule(merged.Rules4, func(r *rule.Rule) bool {
		return r.Src.Set == "allowlist"
	})
	if is == nil || !hasPort(is.Dst, 443, 443, "tcp") {
		t.Fatalf("missing ipset-bound rule: %+v", merged.Rules4)
	}
	if len(merged.Rules6) != 0 {
		t.Error("v4 ipset leaked into Rules6")
	}
	var ipset *store.IPSet
	for i := range merged.Sets {
		if merged.Sets[i].Name == "allowlist" {
			ipset = &merged.Sets[i]
		}
	}
	if ipset == nil || len(ipset.Elements) != 2 || ipset.Family != "ip" {
		t.Fatalf("ipset not imported: %+v", merged.Sets)
	}
}

// The vendor tree supplies stock definitions; the configuration dir
// overrides per basename.
func TestImportFirewalldVendorOverlay(t *testing.T) {
	vendor := t.TempDir()
	writeFile(t, filepath.Join(vendor, "zones", "public.xml"), `<zone>
  <interface name="eth0"/>
  <service name="stocksvc"/>
  <port port="5353" protocol="udp"/>
</zone>
`)
	writeFile(t, filepath.Join(vendor, "services", "stocksvc.xml"), `<service>
  <port port="100" protocol="tcp"/>
</service>
`)

	// No config zones at all → vendor zone imported.
	dir := t.TempDir()
	merged, n, _, err := importFirewalld(dir, vendor, store.Defaults())
	if err != nil {
		t.Fatalf("vendor import: %v", err)
	}
	if n != 4 { // service rule + port rule, both dual
		t.Fatalf("added = %d, want 4", n)
	}
	if findRule(merged.Rules4, func(r *rule.Rule) bool {
		return hasPort(r.Dst, 5353, 5353, "udp")
	}) == nil {
		t.Fatal("vendor zone not imported")
	}

	// Same-name service in the config dir overrides the vendor file.
	writeFile(t, filepath.Join(dir, "zones", "public.xml"), `<zone>
  <interface name="eth1"/>
  <service name="stocksvc"/>
</zone>
`)
	writeFile(t, filepath.Join(dir, "services", "stocksvc.xml"), `<service>
  <port port="200" protocol="tcp"/>
</service>
`)
	merged, _, _, err = importFirewalld(dir, vendor, store.Defaults())
	if err != nil {
		t.Fatalf("overlay import: %v", err)
	}
	if len(merged.Rules4) != 1 {
		t.Fatalf("Rules4 = %d, want 1 (config zone wins)", len(merged.Rules4))
	}
	if !hasPort(merged.Rules4[0].Dst, 200, 200, "tcp") || merged.Rules4[0].IfaceIn != "eth1" {
		t.Fatalf("config dir did not override vendor: %+v", merged.Rules4[0])
	}

	// Overridden vendor ipset: only the config-dir elements survive.
	writeFile(t, filepath.Join(vendor, "ipsets", "allowlist.xml"), `<ipset type="hash:ip">
  <entry>192.0.2.10</entry>
</ipset>
`)
	writeFile(t, filepath.Join(dir, "ipsets", "allowlist.xml"), `<ipset type="hash:ip">
  <entry>203.0.113.7</entry>
</ipset>
`)
	merged, _, _, err = importFirewalld(dir, vendor, store.Defaults())
	if err != nil {
		t.Fatalf("ipset overlay import: %v", err)
	}
	if len(merged.Sets) != 1 || len(merged.Sets[0].Elements) != 1 || merged.Sets[0].Elements[0] != "203.0.113.7" {
		t.Fatalf("vendor ipset elements leaked past /etc override: %+v", merged.Sets)
	}

	// Overridden vendor policy: the config-dir replacement must
	// neutralize the unrepresentable vendor policy; the stock-shape
	// override imports its own rules instead.
	writeFile(t, filepath.Join(vendor, "policies", "p.xml"), `<policy target="ACCEPT">
  <ingress-zone name="HOST"/>
  <egress-zone name="ANY"/>
</policy>
`)
	if _, _, _, err := importFirewalld(dir, vendor, store.Defaults()); err == nil {
		t.Fatal("unoverridden vendor policy should error")
	}
	writeFile(t, filepath.Join(dir, "policies", "p.xml"), `<policy target="CONTINUE" priority="-15000">
  <ingress-zone name="ANY"/>
  <egress-zone name="HOST"/>
  <rule family="ipv6"><icmp-type name="router-solicitation"/><accept/></rule>
</policy>
`)
	merged, _, _, err = importFirewalld(dir, vendor, store.Defaults())
	if err != nil {
		t.Fatalf("overridden vendor policy must not error: %v", err)
	}
	pr := findRule(merged.Rules6, func(r *rule.Rule) bool {
		return r.Proto == "icmpv6" && r.ICMPType == "133"
	})
	if pr == nil {
		t.Fatalf("config-dir policy override not imported: %+v", merged.Rules6)
	}
}

// Imported v6 rules must not be inert: st.IPv6=false becomes true.
func TestImportFirewalldEnablesIPv6(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "zones", "public.xml"), `<zone>
  <interface name="eth0"/>
  <port port="22" protocol="tcp"/>
</zone>
`)
	st := store.Defaults()
	st.IPv6 = false
	merged, _, warnings, err := importFirewalld(dir, emptyVendor(t), st)
	if err != nil {
		t.Fatalf("ImportFirewalld: %v", err)
	}
	if !merged.IPv6 {
		t.Fatal("IPv6 not enabled despite v6 rules")
	}
	var sawIPv6 bool
	for _, w := range warnings {
		if strings.Contains(w, "IPv6") {
			sawIPv6 = true
		}
	}
	if !sawIPv6 {
		t.Errorf("missing IPv6 warning in %v", warnings)
	}
	if st.IPv6 {
		t.Error("input state IPv6 flag mutated")
	}

	// v4-only rules still enable IPv6: firewalld's default-zone policy
	// governs both families regardless of explicit rule families.
	dir2 := t.TempDir()
	writeFile(t, filepath.Join(dir2, "zones", "public.xml"), `<zone>
  <interface name="eth0"/>
  <rule family="ipv4"><port port="22" protocol="tcp"/><accept/></rule>
</zone>
`)
	st2 := store.Defaults()
	st2.IPv6 = false
	merged2, _, _, err := importFirewalld(dir2, emptyVendor(t), st2)
	if err != nil {
		t.Fatalf("v4-only import: %v", err)
	}
	if len(merged2.Rules6) != 0 {
		t.Fatalf("unexpected v6 rules: %+v", merged2.Rules6)
	}
	if !merged2.IPv6 {
		t.Error("IPv6 not enabled for v4-only firewalld config")
	}
}

func TestImportFirewalldServiceInclude(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "zones", "public.xml"), `<zone>
  <interface name="eth0"/>
  <service name="parent"/>
</zone>
`)
	writeFile(t, filepath.Join(dir, "services", "parent.xml"), `<service>
  <include service="child"/>
  <port port="9001" protocol="tcp"/>
  <module name="nf_conntrack_netbios_ns"/>
</service>
`)
	writeFile(t, filepath.Join(dir, "services", "child.xml"), `<service>
  <port port="9000" protocol="udp"/>
</service>
`)
	writeFile(t, filepath.Join(dir, "zones", "zyzzyva.xml"), `<zone>
  <interface name="eth1"/>
  <service name="cyc"/>
</zone>
`)
	writeFile(t, filepath.Join(dir, "services", "cyc.xml"), `<service>
  <include service="cyc"/>
</service>
`)

	st := store.Defaults()
	_, _, _, err := importFirewalld(dir, emptyVendor(t), st)
	if err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("expected include-cycle error, got %v", err)
	}

	if err := os.Remove(filepath.Join(dir, "zones", "zyzzyva.xml")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "services", "cyc.xml")); err != nil {
		t.Fatal(err)
	}
	merged, n, warnings, err := importFirewalld(dir, emptyVendor(t), st)
	if err != nil {
		t.Fatalf("ImportFirewalld: %v", err)
	}
	if n != 2 { // one dual-family rule carrying both ports
		t.Fatalf("added = %d, want 2 (v4+v6)", n)
	}
	r := findRule(merged.Rules4, func(r *rule.Rule) bool {
		return hasPort(r.Dst, 9001, 9001, "tcp")
	})
	if r == nil || !hasPort(r.Dst, 9000, 9000, "udp") {
		t.Fatalf("included service ports missing: %+v", merged.Rules4)
	}
	var sawModule bool
	for _, w := range warnings {
		if strings.Contains(w, "module") {
			sawModule = true
		}
	}
	if !sawModule {
		t.Errorf("missing module warning in %v", warnings)
	}
}

// Service <destination> splits families; an include's destination is
// adopted when the parent does not set one.
func TestImportFirewalldServiceDestination(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "zones", "public.xml"), `<zone>
  <interface name="eth0"/>
  <service name="v4only"/>
  <service name="parent2"/>
</zone>
`)
	writeFile(t, filepath.Join(dir, "services", "v4only.xml"), `<service>
  <port port="100" protocol="tcp"/>
  <destination ipv4="192.0.2.0/24"/>
</service>
`)
	writeFile(t, filepath.Join(dir, "services", "parent2.xml"), `<service>
  <include service="child2"/>
</service>
`)
	writeFile(t, filepath.Join(dir, "services", "child2.xml"), `<service>
  <port port="300" protocol="tcp"/>
  <destination ipv6="2001:db8::5"/>
</service>
`)
	merged, n, _, err := importFirewalld(dir, emptyVendor(t), store.Defaults())
	if err != nil {
		t.Fatalf("ImportFirewalld: %v", err)
	}
	if len(merged.Rules4) != 1 || len(merged.Rules6) != 1 || n != 2 {
		t.Fatalf("rules %d/%d n=%d, want 1/1/2", len(merged.Rules4), len(merged.Rules6), n)
	}
	if merged.Rules4[0].Dst.IP != "192.0.2.0/24" {
		t.Errorf("dst = %q, want 192.0.2.0/24", merged.Rules4[0].Dst.IP)
	}
	if merged.Rules6[0].Dst.IP != "2001:db8::5" {
		t.Errorf("included dst = %q, want 2001:db8::5", merged.Rules6[0].Dst.IP)
	}
}

func TestImportFirewalldEtcServicesFallback(t *testing.T) {
	t.Setenv("BFW_PREFIX", t.TempDir()) // force embedded services table
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "zones", "public.xml"), `<zone>
  <interface name="eth0"/>
  <service name="ssh"/>
</zone>
`)
	merged, _, _, err := importFirewalld(dir, emptyVendor(t), store.Defaults())
	if err != nil {
		t.Fatalf("ImportFirewalld: %v", err)
	}
	if findRule(merged.Rules4, func(r *rule.Rule) bool {
		return hasPort(r.Dst, 22, 22, "tcp")
	}) == nil {
		t.Fatalf("ssh did not resolve via services fallback: %+v", merged.Rules4)
	}
}

func TestImportFirewalldErrors(t *testing.T) {
	cases := []struct {
		name    string
		files   map[string]string // path under dir → content
		wantErr string
	}{
		{"zone target DROP", map[string]string{
			"zones/public.xml": `<zone target="DROP"><port port="22" protocol="tcp"/></zone>`,
		}, "target"},
		{"masquerade", map[string]string{
			"zones/public.xml": `<zone><masquerade/></zone>`,
		}, "NAT"},
		{"forward-port", map[string]string{
			"zones/public.xml": `<zone><forward-port port="80" protocol="tcp" to-port="8080"/></zone>`,
		}, "NAT"},
		{"forward", map[string]string{
			"zones/public.xml": `<zone><forward/></zone>`,
		}, "forward"},
		{"icmp-block", map[string]string{
			"zones/public.xml": `<zone><icmp-block value="echo-request"/></zone>`,
		}, "ICMP"},
		{"unknown zone element", map[string]string{
			"zones/public.xml": `<zone><frobnicate/></zone>`,
		}, "unsupported"},
		{"invert source binding", map[string]string{
			"zones/public.xml": `<zone><source address="1.2.3.4" invert="yes"/></zone>`,
		}, "invert"},
		{"missing source attrs", map[string]string{
			"zones/public.xml": `<zone><source/></zone>`,
		}, "address"},
		{"missing ipset", map[string]string{
			"zones/public.xml": `<zone><source ipset="nosuch"/><port port="1" protocol="tcp"/></zone>`,
		}, "ipset"},
		{"missing port attr", map[string]string{
			"zones/public.xml": `<zone><port protocol="tcp"/></zone>`,
		}, "missing port"},
		{"bad port", map[string]string{
			"zones/public.xml": `<zone><port port="bogus" protocol="tcp"/></zone>`,
		}, "port"},
		{"bad proto", map[string]string{
			"zones/public.xml": `<zone><port port="80" protocol="sctp"/></zone>`,
		}, "protocol"},
		{"unknown service", map[string]string{
			"zones/public.xml": `<zone><service name="nosuchsvc"/></zone>`,
		}, "service"},
		{"rich mark", map[string]string{
			"zones/public.xml": `<zone><rule><port port="1" protocol="tcp"/><mark set="0x1"/></rule></zone>`,
		}, "mark"},
		{"rich no verdict", map[string]string{
			"zones/public.xml": `<zone><rule><port port="1" protocol="tcp"/><log/></rule></zone>`,
		}, "verdict"},
		{"rich two verdicts", map[string]string{
			"zones/public.xml": `<zone><rule><accept/><drop/></rule></zone>`,
		}, "multiple verdicts"},
		{"rich invert", map[string]string{
			"zones/public.xml": `<zone><rule><source address="1.2.3.4" invert="yes"/><accept/></rule></zone>`,
		}, "invert"},
		{"rich icmp-type no family", map[string]string{
			"zones/public.xml": `<zone><rule><icmp-type name="echo-request"/><accept/></rule></zone>`,
		}, "cannot resolve"},
		{"rich icmp-type unknown name", map[string]string{
			"zones/public.xml": `<zone><rule family="ipv6"><icmp-type name="bogus"/><accept/></rule></zone>`,
		}, "icmp-type"},
		{"rich icmp-type v6 v4 name", map[string]string{
			"zones/public.xml": `<zone><rule family="ipv6"><icmp-type name="source-quench"/><accept/></rule></zone>`,
		}, "unknown"},
		{"rich icmp-type plus port", map[string]string{
			"zones/public.xml": `<zone><rule family="ipv4"><icmp-type name="echo-request"/><port port="1" protocol="tcp"/><accept/></rule></zone>`,
		}, "more than one"},
		{"rich two match elements", map[string]string{
			"zones/public.xml": `<zone><rule><port port="1" protocol="tcp"/><service name="x"/><accept/></rule></zone>`,
		}, "more than one"},
		{"rich v4 family v6 src", map[string]string{
			"zones/public.xml": `<zone><rule family="ipv4"><source address="2001:db8::1"/><accept/></rule></zone>`,
		}, "famil"},
		{"accept rate limit", map[string]string{
			"zones/public.xml": `<zone><rule><port port="1" protocol="tcp"/><accept><limit value="5/m"/></accept></rule></zone>`,
		}, "rate limit"},
		{"log rate limit", map[string]string{
			"zones/public.xml": `<zone><rule><port port="1" protocol="tcp"/><log><limit value="5/m"/></log><accept/></rule></zone>`,
		}, "rate limit"},
		{"reject rate limit", map[string]string{
			"zones/public.xml": `<zone><rule><port port="1" protocol="tcp"/><reject><limit value="5/m"/></reject></rule></zone>`,
		}, "rate limit"},
		{"audit with limit", map[string]string{
			"zones/public.xml": `<zone><rule><port port="1" protocol="tcp"/><audit><limit value="5/m"/></audit><accept/></rule></zone>`,
		}, "audit"},
		{"unbound default plus bound zone", map[string]string{
			"zones/public.xml": `<zone><port port="1" protocol="tcp"/></zone>`,
			"zones/other.xml":  `<zone><interface name="eth1"/><port port="2" protocol="tcp"/></zone>`,
		}, "unbound default"},
		{"duplicate interface", map[string]string{
			"firewalld.conf": "DefaultZone=a\n",
			"zones/a.xml":    `<zone><interface name="eth0"/><port port="1" protocol="tcp"/></zone>`,
			"zones/b.xml":    `<zone><interface name="eth0"/><port port="2" protocol="tcp"/></zone>`,
		}, "interface"},
		{"iface zone vs source zone", map[string]string{
			"firewalld.conf": "DefaultZone=a\n",
			"zones/a.xml":    `<zone><interface name="eth0"/><port port="1" protocol="tcp"/></zone>`,
			"zones/b.xml":    `<zone><source address="10.0.0.0/8"/><port port="2" protocol="tcp"/></zone>`,
		}, "mix interface and source"},
		{"overlapping sources", map[string]string{
			"firewalld.conf": "DefaultZone=a\n",
			"zones/a.xml":    `<zone><source address="10.0.0.0/8"/><port port="1" protocol="tcp"/></zone>`,
			"zones/b.xml":    `<zone><source address="10.1.0.0/16"/><port port="2" protocol="tcp"/></zone>`,
		}, "overlapping"},
		{"same ipset two zones", map[string]string{
			"firewalld.conf": "DefaultZone=a\n",
			"zones/a.xml":    `<zone><source ipset="s"/><port port="1" protocol="tcp"/></zone>`,
			"zones/b.xml":    `<zone><source ipset="s"/><port port="2" protocol="tcp"/></zone>`,
			"ipsets/s.xml":   `<ipset type="hash:ip"><entry>1.2.3.4</entry></ipset>`,
		}, "ipset"},
		{"ipset vs addr bindings", map[string]string{
			"firewalld.conf": "DefaultZone=a\n",
			"zones/a.xml":    `<zone><source ipset="s"/><port port="1" protocol="tcp"/></zone>`,
			"zones/b.xml":    `<zone><source address="10.0.0.0/8"/><port port="2" protocol="tcp"/></zone>`,
			"ipsets/s.xml":   `<ipset type="hash:ip"><entry>1.2.3.4</entry></ipset>`,
		}, "overlap"},
		{"missing default zone", map[string]string{
			"firewalld.conf": "DefaultZone=nosuchzone\n",
			"zones/a.xml":    `<zone><interface name="eth0"/><port port="1" protocol="tcp"/></zone>`,
		}, "default zone"},
		{"zone src vs rule src", map[string]string{
			"zones/public.xml": `<zone><source address="10.0.0.0/8"/><rule><source address="10.9.9.9"/><accept/></rule></zone>`,
		}, ""}, // narrower rule src inside binding: must NOT error
		{"malformed xml", map[string]string{
			"zones/public.xml": `<zone><port`,
		}, "XML"},
		{"service helper", map[string]string{
			"zones/public.xml": `<zone><service name="h"/></zone>`,
			"services/h.xml":   `<service><helper name="tftp"/></service>`,
		}, "helper"},
		{"service missing port attr", map[string]string{
			"zones/public.xml": `<zone><service name="h"/></zone>`,
			"services/h.xml":   `<service><port protocol="tcp"/></service>`,
		}, "missing port"},
		{"service dst conflict", map[string]string{
			"zones/public.xml": `<zone><service name="p"/></zone>`,
			"services/p.xml":   `<service><include service="c"/><destination ipv4="192.0.2.0/24"/></service>`,
			"services/c.xml":   `<service><port port="1" protocol="tcp"/><destination ipv4="10.0.0.0/8"/></service>`,
		}, "conflicting"},
		{"ipset bad type", map[string]string{
			"zones/public.xml": `<zone><source ipset="m"/><port port="1" protocol="tcp"/></zone>`,
			"ipsets/m.xml":     `<ipset type="hash:mac"><entry>aa:bb</entry></ipset>`,
		}, "type"},
		{"ipset v6 entry default inet", map[string]string{
			"zones/public.xml": `<zone><source ipset="m"/><port port="1" protocol="tcp"/></zone>`,
			"ipsets/m.xml":     `<ipset type="hash:ip"><entry>2001:db8::1</entry></ipset>`,
		}, "family"},
		{"direct rules", map[string]string{
			"zones/public.xml": `<zone/>`,
			"direct.xml":       `<direct><rule ipv="ipv4" table="filter" chain="INPUT" priority="0">-j ACCEPT</rule></direct>`,
		}, "direct"},
		{"policy object", map[string]string{
			"zones/public.xml": `<zone/>`,
			"policies/p.xml":   `<policy target="CONTINUE" priority="-15000"><ingress-zone name="ANY"/><egress-zone name="HOST"/><service name="ssh"/></policy>`,
		}, "policy element <service>"},
		{"policy target", map[string]string{
			"zones/public.xml": `<zone/>`,
			"policies/p.xml":   `<policy target="ACCEPT"/>`,
		}, "target <ACCEPT>"},
		{"policy wrong priority", map[string]string{
			"zones/public.xml": `<zone/>`,
			"policies/p.xml":   `<policy target="CONTINUE" priority="0"><ingress-zone name="ANY"/><egress-zone name="HOST"/></policy>`,
		}, "priority"},
		{"policy missing priority", map[string]string{
			"zones/public.xml": `<zone/>`,
			"policies/p.xml":   `<policy target="CONTINUE"><ingress-zone name="ANY"/><egress-zone name="HOST"/></policy>`,
		}, "priority"},
		{"policy wrong egress", map[string]string{
			"zones/public.xml": `<zone/>`,
			"policies/p.xml":   `<policy target="CONTINUE" priority="-15000"><ingress-zone name="ANY"/><egress-zone name="ANY"/></policy>`,
		}, "egress-zone"},
		{"policy zone as text", map[string]string{
			"zones/public.xml": `<zone/>`,
			"policies/p.xml":   `<policy priority="-15000"><ingress-zone>ANY</ingress-zone><egress-zone>HOST</egress-zone></policy>`,
		}, "ingress-zone"},
		{"policy wrong root", map[string]string{
			"zones/public.xml": `<zone/>`,
			"policies/p.xml":   `<notpolicy/>`,
		}, "root element"},
		{"policy malformed xml", map[string]string{
			"zones/public.xml": `<zone/>`,
			"policies/p.xml":   `<policy target="CONTINUE"`,
		}, "policy"},
		{"policy rule not ipv6", map[string]string{
			"zones/public.xml": `<zone/>`,
			"policies/p.xml":   `<policy priority="-15000"><ingress-zone name="ANY"/><egress-zone name="HOST"/><rule family="ipv4"><icmp-type name="echo-request"/><accept/></rule></policy>`,
		}, "family"},
		{"policy rule extra match", map[string]string{
			"zones/public.xml": `<zone/>`,
			"policies/p.xml":   `<policy priority="-15000"><ingress-zone name="ANY"/><egress-zone name="HOST"/><rule family="ipv6"><icmp-type name="echo-request"/><port port="1" protocol="tcp"/><accept/></rule></policy>`,
		}, "<port>"},
		{"policy rule drop", map[string]string{
			"zones/public.xml": `<zone/>`,
			"policies/p.xml":   `<policy priority="-15000"><ingress-zone name="ANY"/><egress-zone name="HOST"/><rule family="ipv6"><icmp-type name="echo-request"/><drop/></rule></policy>`,
		}, "<drop>"},
		{"policy unknown icmp type", map[string]string{
			"zones/public.xml": `<zone/>`,
			"policies/p.xml":   `<policy priority="-15000"><ingress-zone name="ANY"/><egress-zone name="HOST"/><rule family="ipv6"><icmp-type name="bogus-type"/><accept/></rule></policy>`,
		}, "icmp-type"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for p, c := range tc.files {
				writeFile(t, filepath.Join(dir, p), c)
			}
			st := store.Defaults()
			st.Rules4 = []rule.Rule{{ID: "keep", Action: rule.ActionAllow, Direction: rule.DirIn, Proto: "any",
				Src: rule.AddrSpec{IP: "any"}, Dst: rule.AddrSpec{IP: "any"}}}
			out, _, _, err := importFirewalld(dir, emptyVendor(t), st)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected %q error, got nil (out=%+v)", tc.wantErr, out)
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.wantErr)) {
				t.Fatalf("error %q does not mention %q", err, tc.wantErr)
			}
			if len(st.Rules4) != 1 || st.Rules4[0].ID != "keep" {
				t.Fatal("input state mutated on error")
			}
		})
	}
}

func TestImportFirewalldMissingDir(t *testing.T) {
	if _, _, _, err := importFirewalld(t.TempDir(), emptyVendor(t), store.Defaults()); err == nil {
		t.Fatal("expected error for missing zones dir")
	}
}

func TestImportFirewalldRichRuleWarnings(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "zones", "public.xml"), `<zone>
  <interface name="eth0"/>
  <rule><port port="1" protocol="tcp"/><log/><audit/><accept/></rule>
  <rule><port port="2" protocol="tcp"/><reject type="icmp-host-prohibited"/></rule>
</zone>
`)
	merged, _, warnings, err := importFirewalld(dir, emptyVendor(t), store.Defaults())
	if err != nil {
		t.Fatalf("ImportFirewalld: %v", err)
	}
	lr := findRule(merged.Rules4, func(r *rule.Rule) bool { return hasPort(r.Dst, 1, 1, "tcp") })
	if lr == nil || lr.Action != rule.ActionAllow || lr.Log != rule.LogAll {
		t.Fatalf("logged accept rule wrong: %+v", lr)
	}
	var sawAudit, sawRejectType bool
	for _, w := range warnings {
		if strings.Contains(w, "audit") {
			sawAudit = true
		}
		if strings.Contains(w, "reject type") {
			sawRejectType = true
		}
	}
	if !sawAudit || !sawRejectType {
		t.Errorf("missing warnings audit=%v reject=%v in %v", sawAudit, sawRejectType, warnings)
	}
}

func TestImportFirewalldNilState(t *testing.T) {
	dir := fwFixture(t)
	if _, _, _, err := importFirewalld(dir, emptyVendor(t), nil); err == nil {
		t.Fatal("expected error for nil state")
	}
}

// The stock allow-host-ipv6 policy (/usr/lib/firewalld/policies) imports
// as exact icmp-type-scoped v6 accepts, ordered ahead of zone rules
// because it runs at priority -15000.
func TestImportFirewalldAllowHostIPv6(t *testing.T) {
	vendor := t.TempDir()
	writeFile(t, filepath.Join(vendor, "policies", "allow-host-ipv6.xml"), `<?xml version="1.0" encoding="utf-8"?>
<policy target="CONTINUE" priority="-15000">
  <short>Allow host IPv6</short>
  <description>Allows basic IPv6 functionality for the host running firewalld.</description>
  <ingress-zone name="ANY"/>
  <egress-zone name="HOST"/>
  <rule family="ipv6"><icmp-type name="neighbour-advertisement"/><accept/></rule>
  <rule family="ipv6"><icmp-type name="neighbour-solicitation"/><accept/></rule>
  <rule family="ipv6"><icmp-type name="router-advertisement"/><accept/></rule>
  <rule family="ipv6"><icmp-type name="redirect"/><accept/></rule>
  <rule family="ipv6"><icmp-type name="mld-listener-done"/><accept/></rule>
  <rule family="ipv6"><icmp-type name="mld-listener-query"/><accept/></rule>
  <rule family="ipv6"><icmp-type name="mld-listener-report"/><accept/></rule>
  <rule family="ipv6"><icmp-type name="mld2-listener-report"/><accept/></rule>
</policy>
`)

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "zones", "public.xml"), `<zone>
  <interface name="eth0"/>
  <port port="22" protocol="tcp"/>
</zone>
`)

	merged, n, _, err := importFirewalld(dir, vendor, store.Defaults())
	if err != nil {
		t.Fatalf("ImportFirewalld: %v", err)
	}
	// 8 policy accepts + 1 zone port rule in v6; the zone's dual port
	// rule also lands in v4.
	if len(merged.Rules6) != 9 {
		t.Fatalf("Rules6 = %d, want 9\n%v", len(merged.Rules6), merged.Rules6)
	}
	if len(merged.Rules4) != 1 || n != 10 {
		t.Fatalf("Rules4 = %d, added = %d; want 1/10", len(merged.Rules4), n)
	}
	wantTypes := []string{"136", "135", "134", "137", "132", "130", "131", "143"}
	for i, want := range wantTypes {
		r := merged.Rules6[i]
		if r.Proto != "icmpv6" || r.ICMPType != want {
			t.Fatalf("policy rule %d: proto=%q type=%q, want icmpv6/%s", i, r.Proto, r.ICMPType, want)
		}
		if r.Action != rule.ActionAllow || r.Direction != rule.DirIn {
			t.Fatalf("policy rule %d not an input accept: %+v", i, r)
		}
		if r.Src.IP != "any" || r.Dst.IP != "any" || len(r.Src.Ports) != 0 || len(r.Dst.Ports) != 0 {
			t.Fatalf("policy rule %d is broader than the icmp-type match: %+v", i, r)
		}
		if r.IfaceIn != "" {
			t.Fatalf("policy rule %d unexpectedly bound to interface: %+v", i, r)
		}
	}
	// Priority -15000 runs before zone dispatch: all eight policy
	// accepts precede the zone's tcp/22 rule in Rules6.
	if !hasPort(merged.Rules6[8].Dst, 22, 22, "tcp") || merged.Rules6[8].IfaceIn != "eth0" {
		t.Fatalf("zone rule not ordered after policy rules: %+v", merged.Rules6[8])
	}
}

// Rich rules accept a single family-scoped <icmp-type> match; the
// family attr (or endpoint families) picks icmp vs icmpv6.
func TestImportFirewalldRichICMPType(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "zones", "public.xml"), `<zone>
  <interface name="eth0"/>
  <rule family="ipv6"><icmp-type name="router-advertisement"/><accept/></rule>
  <rule family="ipv4"><icmp-type name="echo-request"/><accept/></rule>
  <rule><destination address="2001:db8::7"/><icmp-type name="2"/><accept/></rule>
</zone>
`)
	merged, _, _, err := importFirewalld(dir, emptyVendor(t), store.Defaults())
	if err != nil {
		t.Fatalf("ImportFirewalld: %v", err)
	}
	if len(merged.Rules4) != 1 || len(merged.Rules6) != 2 {
		t.Fatalf("rules %d/%d, want 1/2\n%v\n%v", len(merged.Rules4), len(merged.Rules6), merged.Rules4, merged.Rules6)
	}
	r6 := merged.Rules6[0]
	if r6.Proto != "icmpv6" || r6.ICMPType != "134" || r6.Action != rule.ActionAllow || r6.IfaceIn != "eth0" {
		t.Fatalf("v6 icmp-type rule wrong: %+v", r6)
	}
	r4 := merged.Rules4[0]
	if r4.Proto != "icmp" || r4.ICMPType != "8" || r4.Action != rule.ActionAllow {
		t.Fatalf("v4 icmp-type rule wrong: %+v", r4)
	}
	// A single-family destination pins the family without the attr.
	byDst := merged.Rules6[1]
	if byDst.Proto != "icmpv6" || byDst.ICMPType != "2" || byDst.Dst.IP != "2001:db8::7" {
		t.Fatalf("endpoint-scoped icmp-type rule wrong: %+v", byDst)
	}
}

// Every built-in icmpv6 type name resolves through
// rule.ICMPTypeNumber to its canonical number in imported rules.
func TestImportFirewalldPolicyICMPv6Names(t *testing.T) {
	cases := map[string]string{
		"echo-request":            "128",
		"echo-reply":              "129",
		"destination-unreachable": "1",
		"packet-too-big":          "2",
		"time-exceeded":           "3",
		"parameter-problem":       "4",
		"router-solicitation":     "133",
		"mld-listener-done":       "132",
		"mld2-listener-report":    "143",
		"128":                     "128", // numeric tokens pass through canonicalized
	}
	for name, want := range cases {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "zones", "public.xml"), `<zone><interface name="eth0"/></zone>`)
		writeFile(t, filepath.Join(dir, "policies", "allow-host-ipv6.xml"), `<policy target="CONTINUE" priority="-15000">
  <ingress-zone name="ANY"/>
  <egress-zone name="HOST"/>
  <rule family="ipv6"><icmp-type name="`+name+`"/><accept/></rule>
</policy>
`)
		merged, _, _, err := importFirewalld(dir, emptyVendor(t), store.Defaults())
		if err != nil {
			t.Fatalf("type %q: %v", name, err)
		}
		if len(merged.Rules6) != 1 || merged.Rules6[0].ICMPType != want || merged.Rules6[0].Proto != "icmpv6" {
			t.Fatalf("type %q: got %+v, want icmpv6/%s", name, merged.Rules6, want)
		}
	}
}
