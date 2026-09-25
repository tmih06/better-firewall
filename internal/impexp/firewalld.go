// firewalld.go implements the firewalld permanent-configuration importer.
// It reads the XML trees rooted at a /etc/firewalld-equivalent directory
// overlaid on the vendor tree (default /usr/lib/firewalld) —
// firewalld.conf, zones/*.xml, services/*.xml, ipsets/*.xml — without
// shelling out, and converts supported inbound filtering semantics into
// rule.Rule entries merged into bfw state. The configuration tree wins
// over the vendor tree per file basename, mirroring firewalld's own
// precedence.
//
// Supported: zone interface and source (address or hash:ip/hash:net
// ipset) bindings, <service>, <port>, <source-port>, <protocol>, a
// subset of rich rules (source/destination address-or-ipset, one match
// element — port, source-port, service, protocol, or a family-scoped
// icmp-type — plus optional log, audit-with-warning, accept/drop/reject),
// and the stock allow-host-ipv6 policy shape: a CONTINUE policy at
// priority -15000 from ingress ANY to egress HOST whose rules are each
// one ipv6 <icmp-type> match plus <accept/>. Its rules import as v6
// input accepts ordered ahead of zone rules because -15000 runs before
// zone dispatch. Service definitions resolve from services/*.xml (with
// <include> recursion) falling back to /etc/services.
//
// Only inbound filtering is representable in bfw, so active semantics
// with no model — zone targets other than "default", icmp-block,
// masquerade, forward-port, forward, marks, inverted matches,
// rate limits, other policies/*.xml objects, direct.xml rules — are
// rejected with an actionable error instead of being silently dropped
// or broadened. Metadata-only skips (short/description, modules, audit,
// lockdown whitelist) produce warnings.
//
// Zone bindings are OR-ed: a bound zone's rules expand per interface and
// per source binding. Zone dispatch itself is not representable: two
// zones whose bindings can capture the same packet (duplicate
// interfaces, overlapping or unverifiably-overlapping sources, an
// interface zone mixed with a source zone — firewalld resolves these by
// internal precedence, bfw cannot) are rejected. A zone with no
// bindings imports only when it is the default zone and nothing else is
// bound (its rules then apply globally, matching firewalld); an unbound
// default zone alongside bound zones is rejected, and an unbound
// non-default zone is skipped with a warning (it never receives
// traffic).
//
// Dual-family elements emit one rule into Rules4 and one into Rules6
// sharing an ID (mirroring ImportUFW). All output is staged, then merged
// into a clone of st, so a failed import leaves st untouched.
package impexp

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/tmih06/better-firewall/internal/rule"
	"github.com/tmih06/better-firewall/internal/services"
	"github.com/tmih06/better-firewall/internal/store"
)

// fwVendorDir is firewalld's stock definition tree; the configuration
// dir (the /etc/firewalld equivalent) overrides it per basename.
const fwVendorDir = "/usr/lib/firewalld"

// ImportFirewalld migrates a firewalld permanent configuration rooted at
// dir (typically /etc/firewalld), overlaid on fwVendorDir stock
// definitions. Returns the merged state, the number of rules added or
// updated, non-fatal warnings, and an error aborting the import (input
// st is never modified on error).
func ImportFirewalld(dir string, st *store.State) (*store.State, int, []string, error) {
	return importFirewalld(dir, fwVendorDir, st)
}

// importFirewalld is the testable core: vendor is the stock-definition
// tree dir overrides.
func importFirewalld(dir, vendor string, st *store.State) (*store.State, int, []string, error) {
	if st == nil {
		return nil, 0, nil, fmt.Errorf("importFirewalld: nil state")
	}
	f := &fwLoader{dir: dir, vendor: vendor}
	if err := f.load(); err != nil {
		return nil, 0, f.warnings, err
	}
	out := fwCloneState(st)
	added := mergeRules(&out.Rules4, f.rules4)
	added += mergeRules(&out.Rules6, f.rules6)
	mergeSets(out, f.sets)
	if !out.IPv6 {
		// firewalld is dual-family: its default-zone/base-chain policy
		// governs IPv6 even when every imported element is v4-only.
		out.IPv6 = true
		f.warn("enabled IPv6 because firewalld manages both address families")
	}
	return out, added, f.warnings, nil
}

// fwLoader accumulates parsed zones and resolution tables for one import.
type fwLoader struct {
	dir         string
	vendor      string
	warnings    []string
	rules4      []rule.Rule
	rules6      []rule.Rule
	sets        []store.IPSet
	svcFiles    map[string]*fwSvcFile
	setFiles    map[string]*fwSetFile
	defaultZone string
}

func (f *fwLoader) warn(format string, args ...interface{}) {
	f.warnings = append(f.warnings, fmt.Sprintf(format, args...))
}

func (f *fwLoader) load() error {
	if err := f.loadConf(); err != nil {
		return err
	}
	if err := f.checkUnsupportedFiles(); err != nil {
		return err
	}
	// Policies emit before zones so imported policy rules precede zone
	// rules in f.rules6, matching firewalld's dispatch order (the stock
	// allow-host-ipv6 policy runs at priority -15000).
	if err := f.emitPolicies(); err != nil {
		return err
	}
	if err := f.loadServices(); err != nil {
		return err
	}
	if err := f.loadIPSets(); err != nil {
		return err
	}
	// Effective zone tree: vendor first, configuration dir wins by
	// basename (firewalld overlay semantics).
	zoneFiles := map[string]string{}
	for _, base := range []string{f.vendor, f.dir} {
		if base == "" {
			continue
		}
		files, err := filepath.Glob(filepath.Join(base, "zones", "*.xml"))
		if err != nil {
			return err
		}
		for _, zf := range files {
			zoneFiles[filepath.Base(zf)] = zf
		}
	}
	if len(zoneFiles) == 0 {
		return fmt.Errorf("no firewalld zones found in %s", filepath.Join(f.dir, "zones"))
	}
	names := make([]string, 0, len(zoneFiles))
	for n := range zoneFiles {
		names = append(names, n)
	}
	sort.Strings(names)
	var zones []*fwZone
	foundDefault := false
	for _, n := range names {
		z, err := f.parseZone(zoneFiles[n])
		if err != nil {
			return err
		}
		if z.name == f.defaultZone {
			foundDefault = true
		}
		zones = append(zones, z)
	}
	if !foundDefault {
		return fmt.Errorf("default zone %q has no zone file under %s or %s "+
			"(fix DefaultZone in firewalld.conf or add zones/%s.xml)",
			f.defaultZone, f.dir, f.vendor, f.defaultZone)
	}
	if err := f.emitZones(zones); err != nil {
		return err
	}
	if len(f.rules4)+len(f.rules6) == 0 {
		f.warn("no importable rules found in %s", f.dir)
	}
	return nil
}

// loadConf reads firewalld.conf for DefaultZone; other keys are
// daemon/backend settings with no bfw equivalent.
func (f *fwLoader) loadConf() error {
	kv, err := parseKVFile(filepath.Join(f.dir, "firewalld.conf"))
	if err != nil {
		return fmt.Errorf("firewalld.conf: %w", err)
	}
	f.defaultZone = "public"
	if v := kv["DefaultZone"]; v != "" {
		f.defaultZone = v
	}
	if v := kv["LogDenied"]; v != "" && !strings.EqualFold(v, "off") {
		f.warn("firewalld.conf: LogDenied=%s is not representable and was skipped", v)
	}
	return nil
}

// checkUnsupportedFiles rejects rule-bearing config that cannot be
// represented: direct.xml rules/chains. policies/*.xml is handled by
// emitPolicies; lockdown-whitelist.xml is access-control metadata.
func (f *fwLoader) checkUnsupportedFiles() error {
	dp := filepath.Join(f.dir, "direct.xml")
	if data, err := os.ReadFile(dp); err == nil {
		root, perr := fwParseXML(data)
		if perr != nil {
			return fmt.Errorf("%s: %v (direct rules cannot be imported)", dp, perr)
		}
		for _, k := range root.kids {
			switch k.name {
			case "rule", "chain", "passthrough":
				return fmt.Errorf("%s: direct <%s> entries are not supported by bfw; convert them manually", dp, k.name)
			}
		}
		f.warn("%s: contains no direct rules, skipped", dp)
	} else if !os.IsNotExist(err) {
		return err
	}
	if _, err := os.Stat(filepath.Join(f.dir, "lockdown-whitelist.xml")); err == nil {
		f.warn("lockdown-whitelist.xml: lockdown is daemon access control, not firewall rules; skipped")
	}
	return nil
}

// ---------------------------------------------------------------------
// policies

// emitPolicies imports firewalld's stock allow-host-ipv6 policy and
// rejects every other policy. It runs before zone emission so imported
// rules precede zone rules: the stock policy runs at priority -15000,
// ahead of zone dispatch. Policies overlay vendor by basename like
// zones: an overridden vendor policy is not active and is not parsed.
func (f *fwLoader) emitPolicies() error {
	polByName := map[string]string{}
	for _, base := range []string{f.vendor, f.dir} {
		if base == "" {
			continue
		}
		g, err := filepath.Glob(filepath.Join(base, "policies", "*.xml"))
		if err != nil {
			return err
		}
		for _, p := range g {
			polByName[filepath.Base(p)] = p
		}
	}
	var pols []string
	for _, p := range polByName {
		pols = append(pols, p)
	}
	sort.Strings(pols)
	for _, p := range pols {
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		root, perr := fwParseXML(data)
		if perr != nil {
			return fmt.Errorf("%s: %v", p, perr)
		}
		if err := f.emitPolicy(p, root); err != nil {
			return err
		}
	}
	return nil
}

// emitPolicy validates one policy file. Only the stock allow-host-ipv6
// semantics are representable in bfw: target CONTINUE (the default when
// the attribute is omitted), priority -15000, exactly one ingress-zone
// ANY and one egress-zone HOST, and <rule> children that are each one
// ipv6 <icmp-type> match plus <accept/>. Any deviation — a forwarding or
// filtered target, a different priority, other zones, or rule elements
// with broader matches or verdicts — aborts the import: emitting or
// skipping it would silently alter the packet policy.
func (f *fwLoader) emitPolicy(path string, root *fwElem) error {
	if root.name != "policy" {
		return fmt.Errorf("%s: root element <%s>, want <policy>", path, root.name)
	}
	if err := fwCheckAttrs(root, path, "version", "target", "priority"); err != nil {
		return err
	}
	if t := root.attr("target"); t != "" && t != "CONTINUE" {
		return fmt.Errorf("%s: policy target <%s> is not representable in bfw "+
			"(only the stock allow-host-ipv6 CONTINUE policy is supported)", path, t)
	}
	prio, err := strconv.Atoi(root.attr("priority"))
	if err != nil || prio != -15000 {
		return fmt.Errorf("%s: policy priority %q is not representable in bfw "+
			"(only the stock allow-host-ipv6 priority -15000 is supported)", path, root.attr("priority"))
	}
	var ingress, egress, rules int
	for _, k := range root.kids {
		switch k.name {
		case "short", "description":
		case "ingress-zone":
			ingress++
			if err := fwPolicyZone(k, path, "ANY"); err != nil {
				return err
			}
		case "egress-zone":
			egress++
			if err := fwPolicyZone(k, path, "HOST"); err != nil {
				return err
			}
		case "rule":
			rules++
			if err := f.fwPolicyRule(path, k); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%s: policy element <%s> is not representable in bfw", path, k.name)
		}
	}
	if ingress != 1 || egress != 1 {
		return fmt.Errorf("%s: policy needs exactly one ingress-zone and one egress-zone", path)
	}
	if rules == 0 {
		f.warn("%s: policy matches the allow-host-ipv6 shape but defines no rules", path)
	}
	return nil
}

// fwPolicyZone checks one ingress-zone/egress-zone element carries
// exactly want ("ANY"/"HOST") as its name attribute — other values or
// nested elements are not part of the stock policy grammar.
func fwPolicyZone(e *fwElem, path, want string) error {
	where := fmt.Sprintf("%s <%s>", path, e.name)
	if err := fwCheckAttrs(e, where, "name"); err != nil {
		return err
	}
	if len(e.kids) != 0 {
		return fmt.Errorf("%s: unexpected element <%s>", where, e.kids[0].name)
	}
	if v := e.attr("name"); v != want {
		return fmt.Errorf("%s: name %q is not representable in bfw (only %q is)", where, v, want)
	}
	return nil
}

// fwPolicyRule converts one allow-host-ipv6 <rule> into a v6 input
// accept. The stock grammar is exactly <rule family="ipv6"><icmp-type
// name="..."/><accept/></rule>: one icmp-type match, one accept verdict,
// nothing else.
func (f *fwLoader) fwPolicyRule(path string, e *fwElem) error {
	where := fmt.Sprintf("%s <rule>", path)
	if err := fwCheckAttrs(e, where, "family"); err != nil {
		return err
	}
	if fam := e.attr("family"); fam != "ipv6" {
		return fmt.Errorf("%s: family %q is not representable in bfw (allow-host-ipv6 rules are ipv6)", where, fam)
	}
	typ, seenType, seenAccept := "", false, false
	for _, k := range e.kids {
		kw := fmt.Sprintf("%s <%s>", where, k.name)
		switch k.name {
		case "icmp-type":
			if seenType {
				return fmt.Errorf("%s: multiple icmp-type matches are not representable in one rule", kw)
			}
			seenType = true
			if err := fwCheckAttrs(k, kw, "name"); err != nil {
				return err
			}
			if len(k.kids) != 0 {
				return fmt.Errorf("%s: unexpected element <%s>", kw, k.kids[0].name)
			}
			name := k.attr("name")
			if name == "" {
				return fmt.Errorf("%s: missing name attribute", kw)
			}
			num, err := rule.ICMPTypeNumber("icmpv6", name)
			if err != nil {
				return fmt.Errorf("%s: %v", kw, err)
			}
			typ = num
		case "accept":
			if seenAccept {
				return fmt.Errorf("%s: policy rule has multiple verdicts", where)
			}
			seenAccept = true
			if err := fwCheckAttrs(k, kw); err != nil {
				return err
			}
			if len(k.kids) != 0 {
				return fmt.Errorf("%s: unexpected element <%s>", kw, k.kids[0].name)
			}
		default:
			return fmt.Errorf("%s: policy rule element <%s> is not representable in bfw", where, k.name)
		}
	}
	if !seenType || !seenAccept {
		return fmt.Errorf("%s: policy rule requires exactly one <icmp-type> match and one <accept> verdict", where)
	}
	r := rule.Rule{
		ID:        rule.NewID(),
		Action:    rule.ActionAllow,
		Direction: rule.DirIn,
		Proto:     "icmpv6",
		ICMPType:  typ,
		Src:       rule.AddrSpec{IP: "any"},
		Dst:       rule.AddrSpec{IP: "any"},
		Comment:   "firewalld policy " + strings.TrimSuffix(filepath.Base(path), ".xml"),
	}
	r.Normalize()
	r.SetV6(true)
	f.rules6 = append(f.rules6, r)
	return nil
}

// ---------------------------------------------------------------------
// generic XML decoding

// fwElem is a generic XML element. Decoding into a tree (rather than
// tagged structs) lets the importer reject unknown elements and
// attributes explicitly instead of silently dropping them.
type fwElem struct {
	name  string
	attrs map[string]string
	kids  []*fwElem
	text  string
}

func (e *fwElem) attr(name string) string { return e.attrs[name] }

func fwParseXML(data []byte) (*fwElem, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	var root *fwElem
	var stack []*fwElem
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			e := &fwElem{name: t.Name.Local, attrs: map[string]string{}}
			for _, a := range t.Attr {
				e.attrs[a.Name.Local] = a.Value
			}
			if len(stack) > 0 {
				p := stack[len(stack)-1]
				p.kids = append(p.kids, e)
			} else if root == nil {
				root = e
			} else {
				return nil, fmt.Errorf("multiple root elements")
			}
			stack = append(stack, e)
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, fmt.Errorf("unexpected </%s>", t.Name.Local)
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) > 0 {
				stack[len(stack)-1].text += string(t)
			}
		}
	}
	if len(stack) != 0 {
		return nil, fmt.Errorf("unclosed <%s>", stack[len(stack)-1].name)
	}
	if root == nil {
		return nil, fmt.Errorf("empty document")
	}
	return root, nil
}

// fwCheckAttrs errors when e carries an attribute outside the allowed
// set, so newer firewalld knobs surface as errors rather than being
// ignored.
func fwCheckAttrs(e *fwElem, where string, allowed ...string) error {
	for a := range e.attrs {
		ok := false
		for _, w := range allowed {
			if a == w {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("%s: unsupported attribute %q on <%s>", where, a, e.name)
		}
	}
	return nil
}

// fwBool parses firewalld's yes/no style booleans.
func fwBool(v string) (bool, error) {
	switch strings.ToLower(v) {
	case "", "no", "false":
		return false, nil
	case "yes", "true":
		return true, nil
	}
	return false, fmt.Errorf("bad boolean %q", v)
}

// fwInvertError is the shared rejection for inverted matches, which the
// rule model cannot express.
func fwInvertError(where, what string) error {
	return fmt.Errorf("%s: inverted %s match is not representable in bfw", where, what)
}

// ---------------------------------------------------------------------
// primitives: ports, protocols, addresses

// fwParsePortAttr parses a firewalld port attribute: a single port or a
// "lo-hi" (also "lo:hi") inclusive range.
func fwParsePortAttr(s, where string) (uint16, uint16, error) {
	lo, hi, err := parsePortRange(strings.ReplaceAll(s, "-", ":"))
	if err != nil {
		return 0, 0, fmt.Errorf("%s: bad port %q", where, s)
	}
	return lo, hi, nil
}

// fwPortElem validates a <port>/<source-port> element and returns its
// range and protocol. The port attribute is required: a port-less
// element would silently broaden to all ports of the protocol, which
// firewalld itself rejects.
func fwPortElem(e *fwElem, where string) (lo, hi uint16, proto string, err error) {
	if err = fwCheckAttrs(e, where, "port", "protocol"); err != nil {
		return
	}
	proto = e.attr("protocol")
	if proto != "tcp" && proto != "udp" {
		err = fmt.Errorf("%s: port protocol %q not supported (only tcp/udp)", where, proto)
		return
	}
	p := e.attr("port")
	if p == "" {
		err = fmt.Errorf("%s: missing port attribute", where)
		return
	}
	lo, hi, err = fwParsePortAttr(p, where)
	return
}

// fwNormProto validates a <protocol value> against the rule model and
// reports the address families it can fire in.
func fwNormProto(v, where string) (proto string, v4, v6 bool, err error) {
	switch v {
	case "tcp", "udp", "ah", "esp", "gre", "vrrp":
		return v, true, true, nil
	case "igmp", "icmp":
		return v, true, false, nil
	case "icmpv6", "ipv6-icmp", "ipv6-icmpv6":
		return "icmpv6", false, true, nil
	default:
		return "", false, false, fmt.Errorf("%s: protocol %q is not representable in bfw", where, v)
	}
}

// fwCanonAddr validates and canonicalizes an IP/CIDR string.
func fwCanonAddr(s, where string) (string, error) {
	if ip := net.ParseIP(s); ip != nil {
		return ip.String(), nil
	}
	if _, n, err := net.ParseCIDR(s); err == nil {
		return n.String(), nil
	}
	return "", fmt.Errorf("%s: bad address %q", where, s)
}

// fwAddrFamily reports which families an address belongs to.
func fwAddrFamily(ip string) (v4, v6 bool) {
	if ip == "" || ip == "any" {
		return true, true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		if _, n, err := net.ParseCIDR(ip); err == nil {
			parsed = n.IP
		}
	}
	if parsed == nil {
		return false, false
	}
	if parsed.To4() != nil {
		return true, false
	}
	return false, true
}

// fwNetOf parses a canonical address into a network for containment
// checks (bare IPs become host prefixes).
func fwNetOf(s string) *net.IPNet {
	if _, n, err := net.ParseCIDR(s); err == nil {
		return n
	}
	if ip := net.ParseIP(s); ip != nil {
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
	}
	return nil
}

// fwNetContains reports whether n1 fully contains n2 (same family and
// equal-or-wider prefix).
func fwNetContains(n1, n2 *net.IPNet) bool {
	o1, b1 := n1.Mask.Size()
	o2, b2 := n2.Mask.Size()
	return b1 == b2 && o1 <= o2 && n1.Contains(n2.IP)
}

// ---------------------------------------------------------------------
// service definitions

// fwSvcDef is a parsed service: ports plus bare protocol matches plus
// optional per-family destination addresses and includes.
type fwSvcDef struct {
	ports    []fwSvcPort
	protos   []string
	dst4     string
	dst6     string
	modules  []string
	includes []string
}

type fwSvcPort struct {
	lo, hi uint16
	proto  string // tcp|udp
}

// fwSvcFile records a parsed services/*.xml or the reason it is unusable
// (reported only when the service is actually referenced).
type fwSvcFile struct {
	def *fwSvcDef
	err error
}

func (f *fwLoader) loadServices() error {
	f.svcFiles = map[string]*fwSvcFile{}
	// Vendor services first; configuration dir overrides by basename.
	for _, base := range []string{f.vendor, f.dir} {
		if base == "" {
			continue
		}
		files, err := filepath.Glob(filepath.Join(base, "services", "*.xml"))
		if err != nil {
			return err
		}
		for _, p := range files {
			name := strings.TrimSuffix(filepath.Base(p), ".xml")
			def, perr := fwParseServiceFile(p)
			if perr != nil {
				f.warn("%s: %v", p, perr)
			}
			f.svcFiles[name] = &fwSvcFile{def: def, err: perr}
		}
	}
	return nil
}

func fwParseServiceFile(path string) (*fwSvcDef, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	root, err := fwParseXML(data)
	if err != nil {
		return nil, err
	}
	if root.name != "service" {
		return nil, fmt.Errorf("root element <%s>, want <service>", root.name)
	}
	if err := fwCheckAttrs(root, path, "version"); err != nil {
		return nil, err
	}
	def := &fwSvcDef{}
	for _, k := range root.kids {
		where := path + " <" + k.name + ">"
		switch k.name {
		case "short", "description":
		case "port":
			lo, hi, proto, err := fwPortElem(k, where)
			if err != nil {
				return nil, err
			}
			def.ports = append(def.ports, fwSvcPort{lo: lo, hi: hi, proto: proto})
		case "protocol":
			if err := fwCheckAttrs(k, where, "value"); err != nil {
				return nil, err
			}
			proto, _, _, err := fwNormProto(k.attr("value"), where)
			if err != nil {
				return nil, err
			}
			def.protos = append(def.protos, proto)
		case "destination":
			if err := fwCheckAttrs(k, where, "ipv4", "ipv6"); err != nil {
				return nil, err
			}
			if v := k.attr("ipv4"); v != "" {
				c, err := fwCanonAddr(v, where)
				if err != nil {
					return nil, err
				}
				def.dst4 = c
			}
			if v := k.attr("ipv6"); v != "" {
				c, err := fwCanonAddr(v, where)
				if err != nil {
					return nil, err
				}
				def.dst6 = c
			}
		case "include":
			if err := fwCheckAttrs(k, where, "service"); err != nil {
				return nil, err
			}
			if k.attr("service") == "" {
				return nil, fmt.Errorf("%s: <include> missing service attribute", where)
			}
			def.includes = append(def.includes, k.attr("service"))
		case "module":
			if err := fwCheckAttrs(k, where, "name"); err != nil {
				return nil, err
			}
			def.modules = append(def.modules, k.attr("name"))
		case "source-port":
			return nil, fmt.Errorf("%s: <source-port> inside a service is not supported", where)
		case "helper":
			return nil, fmt.Errorf("%s: conntrack helper %q is not representable in bfw", where, k.attr("name"))
		default:
			return nil, fmt.Errorf("%s: unsupported service element <%s>", path, k.name)
		}
	}
	return def, nil
}

// resolveService flattens a service (includes merged recursively, cycle
// checked) into ports/protos/destinations. Resolution order: parsed
// services/*.xml, then /etc/services via services.Proto.
func (f *fwLoader) resolveService(name string, stack map[string]bool) (*fwSvcDef, error) {
	if stack[name] {
		return nil, fmt.Errorf("service include cycle involving %q", name)
	}
	stack[name] = true
	defer delete(stack, name)

	base, err := f.serviceDef(name)
	if err != nil {
		return nil, err
	}
	out := &fwSvcDef{
		ports:   append([]fwSvcPort(nil), base.ports...),
		protos:  append([]string(nil), base.protos...),
		dst4:    base.dst4,
		dst6:    base.dst6,
		modules: append([]string(nil), base.modules...),
	}
	for _, inc := range base.includes {
		sub, err := f.resolveService(inc, stack)
		if err != nil {
			return nil, err
		}
		out.ports = append(out.ports, sub.ports...)
		out.protos = append(out.protos, sub.protos...)
		out.modules = append(out.modules, sub.modules...)
		for _, d := range []struct {
			name     string
			out, sub *string
		}{{"ipv4", &out.dst4, &sub.dst4}, {"ipv6", &out.dst6, &sub.dst6}} {
			switch {
			case *d.sub == "":
				// Include carries no restriction; parent's stands.
			case *d.out == "":
				*d.out = *d.sub // parent unspecified: adopt include's.
			case *d.out != *d.sub:
				return nil, fmt.Errorf("service %q: conflicting %s destination %q vs included %q", name, d.name, *d.out, *d.sub)
			}
		}
	}
	return out, nil
}

// serviceDef returns the definition for one name: the parsed file, its
// deferred error, or an /etc/services fallback definition.
func (f *fwLoader) serviceDef(name string) (*fwSvcDef, error) {
	if sf, ok := f.svcFiles[name]; ok {
		if sf.err != nil {
			return nil, fmt.Errorf("service %q: %v", name, sf.err)
		}
		return sf.def, nil
	}
	port, proto, err := services.Proto(name)
	if err != nil {
		return nil, fmt.Errorf("undefined service %q (no services/%s.xml and not in /etc/services)", name, name)
	}
	def := &fwSvcDef{}
	if proto == "any" || proto == "tcp" {
		def.ports = append(def.ports, fwSvcPort{lo: uint16(port), hi: uint16(port), proto: "tcp"})
	}
	if proto == "any" || proto == "udp" {
		def.ports = append(def.ports, fwSvcPort{lo: uint16(port), hi: uint16(port), proto: "udp"})
	}
	if len(def.ports) == 0 {
		return nil, fmt.Errorf("service %q resolves to no tcp/udp port in /etc/services", name)
	}
	return def, nil
}

// ---------------------------------------------------------------------
// ipsets

// fwSetDef is a parsed ipsets/*.xml (hash:ip/hash:net only).
type fwSetDef struct {
	family   string // ip|ip6 (store.IPSet naming)
	elements []string
}

type fwSetFile struct {
	def *fwSetDef
	err error
}

func (f *fwLoader) loadIPSets() error {
	f.setFiles = map[string]*fwSetFile{}
	// Vendor ipsets first; configuration dir overrides by basename.
	// f.sets is filled only from the effective (winning) definitions —
	// appending inside the loop would union overridden vendor elements
	// into the imported set and broaden rules.
	for _, base := range []string{f.vendor, f.dir} {
		if base == "" {
			continue
		}
		files, err := filepath.Glob(filepath.Join(base, "ipsets", "*.xml"))
		if err != nil {
			return err
		}
		for _, p := range files {
			name := strings.TrimSuffix(filepath.Base(p), ".xml")
			def, perr := fwParseIPSetFile(p)
			if perr != nil {
				f.warn("%s: %v", p, perr)
			}
			f.setFiles[name] = &fwSetFile{def: def, err: perr}
		}
	}
	names := make([]string, 0, len(f.setFiles))
	for n := range f.setFiles {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if sf := f.setFiles[n]; sf.err == nil {
			f.sets = append(f.sets, store.IPSet{Name: n, Family: sf.def.family, Elements: sf.def.elements})
		}
	}
	return nil
}

func fwParseIPSetFile(path string) (*fwSetDef, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	root, err := fwParseXML(data)
	if err != nil {
		return nil, err
	}
	if root.name != "ipset" {
		return nil, fmt.Errorf("root element <%s>, want <ipset>", root.name)
	}
	if err := fwCheckAttrs(root, path, "version", "type"); err != nil {
		return nil, err
	}
	typ := root.attr("type")
	isNet := false
	switch typ {
	case "hash:ip":
	case "hash:net":
		isNet = true
	case "":
		return nil, fmt.Errorf("%s: <ipset> missing type attribute", path)
	default:
		return nil, fmt.Errorf("%s: ipset type %q not supported (only hash:ip/hash:net)", path, typ)
	}
	// firewalld's implicit ipset family is "inet" (IPv4); entries are
	// validated against it rather than used to infer a wider family.
	fam := "ip"
	var raw []string
	for _, k := range root.kids {
		where := path + " <" + k.name + ">"
		switch k.name {
		case "short", "description":
		case "option":
			if err := fwCheckAttrs(k, where, "name", "value"); err != nil {
				return nil, err
			}
			switch k.attr("name") {
			case "family":
				switch k.attr("value") {
				case "inet":
					fam = "ip"
				case "inet6":
					fam = "ip6"
				default:
					return nil, fmt.Errorf("%s: bad ipset family %q", where, k.attr("value"))
				}
			default:
				return nil, fmt.Errorf("%s: ipset option %q is not representable in bfw", where, k.attr("name"))
			}
		case "entry":
			if err := fwCheckAttrs(k, where); err != nil {
				return nil, err
			}
			raw = append(raw, strings.TrimSpace(k.text))
		default:
			return nil, fmt.Errorf("%s: unsupported ipset element <%s>", path, k.name)
		}
	}
	var elems []string
	for _, txt := range raw {
		where := path + " <entry>"
		c, err := fwCanonAddr(txt, where)
		if err != nil {
			return nil, err
		}
		if !isNet && strings.Contains(c, "/") {
			return nil, fmt.Errorf("%s: CIDR entry %q in hash:ip set", where, txt)
		}
		v4, _ := fwAddrFamily(c)
		if fam == "ip" && !v4 {
			return nil, fmt.Errorf("%s: IPv6 entry %q contradicts ipset family inet", where, txt)
		}
		if fam == "ip6" && v4 {
			return nil, fmt.Errorf("%s: IPv4 entry %q contradicts ipset family inet6", where, txt)
		}
		elems = append(elems, c)
	}
	return &fwSetDef{family: fam, elements: elems}, nil
}

// setFamily resolves a referenced ipset to its rule-model families.
func (f *fwLoader) setFamily(name, where string) (v4, v6 bool, err error) {
	sf, ok := f.setFiles[name]
	if !ok {
		return false, false, fmt.Errorf("%s: ipset %q is not defined under %s", where, name, filepath.Join(f.dir, "ipsets"))
	}
	if sf.err != nil {
		return false, false, fmt.Errorf("%s: ipset %q: %v", where, name, sf.err)
	}
	if sf.def.family == "ip6" {
		return false, true, nil
	}
	return true, false, nil
}

// ---------------------------------------------------------------------
// zones

// fwBinding is one zone membership condition (interface or source); zone
// bindings are OR-ed, so each binding expands rules separately.
type fwBinding struct {
	iface   string
	ip      string // canonical address/CIDR
	set     string // ipset name
	v4, v6  bool
	isIface bool
}

// fwZone is a parsed zone ready for element expansion.
type fwZone struct {
	name     string
	path     string
	bindings []fwBinding
	elems    []*fwElem
}

// parseZone reads one zone file into bindings and rule-bearing elements.
func (f *fwLoader) parseZone(path string) (*fwZone, error) {
	zname := strings.TrimSuffix(filepath.Base(path), ".xml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	root, err := fwParseXML(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	if root.name != "zone" {
		return nil, fmt.Errorf("%s: root element <%s>, want <zone>", path, root.name)
	}
	if err := fwCheckAttrs(root, path, "version", "target"); err != nil {
		return nil, err
	}
	switch t := root.attr("target"); t {
	case "", "default":
	default:
		return nil, fmt.Errorf("%s: zone target %q is not representable in bfw (only the implicit default is supported)", path, t)
	}
	z := &fwZone{name: zname, path: path}
	for _, k := range root.kids {
		switch k.name {
		case "short", "description":
		case "interface":
			where := fmt.Sprintf("%s (zone %s)", path, zname)
			if err := fwCheckAttrs(k, where, "name"); err != nil {
				return nil, err
			}
			iface := k.attr("name")
			if iface == "" {
				return nil, fmt.Errorf("%s: <interface> missing name attribute", where)
			}
			z.bindings = append(z.bindings, fwBinding{iface: iface, isIface: true, v4: true, v6: true})
		case "source":
			b, err := f.zoneSource(path, zname, k)
			if err != nil {
				return nil, err
			}
			z.bindings = append(z.bindings, b)
		default:
			z.elems = append(z.elems, k)
		}
	}
	return z, nil
}

// emitZones decides per zone whether its elements become rules, then
// rejects binding layouts whose packet→zone assignment is not
// faithfully representable before expanding elements.
func (f *fwLoader) emitZones(zones []*fwZone) error {
	bound := 0
	for _, z := range zones {
		if len(z.bindings) > 0 {
			bound++
		}
	}
	var active []*fwZone
	for _, z := range zones {
		if len(z.bindings) == 0 {
			if z.name != f.defaultZone {
				f.warn("zone %s has no interface/source bindings and is not the default zone; "+
					"its %d rule element(s) would never match in firewalld and were skipped", z.name, len(z.elems))
				continue
			}
			if bound > 0 {
				return fmt.Errorf("%s (zone %s): an unbound default zone alongside bound zones is not representable in bfw "+
					"(its rules would leak onto interfaces/sources claimed by other zones)", z.path, z.name)
			}
			// Nothing is bound anywhere: the default zone sees all
			// traffic, so a wildcard binding is exact, not approximate.
			z.bindings = []fwBinding{{v4: true, v6: true}}
		}
		active = append(active, z)
	}
	if err := f.checkZoneOverlap(active); err != nil {
		return err
	}
	for _, z := range active {
		for _, e := range z.elems {
			if err := f.zoneElem(z, e); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkZoneOverlap rejects cross-zone binding overlaps. firewalld
// assigns a packet to exactly one zone via interface-over-source
// precedence and single-dispatch order; bfw's flat model ORs everything,
// so bindings that could capture the same packet in different zones are
// unrepresentable.
func (f *fwLoader) checkZoneOverlap(active []*fwZone) error {
	for i := range active {
		for j := i + 1; j < len(active); j++ {
			a, b := active[i], active[j]
			for _, ba := range a.bindings {
				for _, bb := range b.bindings {
					if err := f.bindingsOverlap(a, ba, b, bb); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func (f *fwLoader) bindingsOverlap(a *fwZone, ba fwBinding, b *fwZone, bb fwBinding) error {
	switch {
	case ba.isIface && bb.isIface:
		if ba.iface == bb.iface {
			return fmt.Errorf("zones %s and %s both bind interface %s; firewalld assigns an interface to one "+
				"zone only, so this is not representable", a.name, b.name, ba.iface)
		}
	case ba.isIface != bb.isIface:
		// An interface-bound zone and a source-bound zone overlap on
		// packets matching both; firewalld resolves that by precedence,
		// which a flat ruleset cannot express.
		return fmt.Errorf("zones %s and %s mix interface and source bindings; firewalld's interface-over-source "+
			"precedence is not representable in bfw", a.name, b.name)
	default:
		// Source-vs-source: only same-family pairs can overlap.
		v4, v6 := ba.v4 && bb.v4, ba.v6 && bb.v6
		if !v4 && !v6 {
			return nil
		}
		switch {
		case ba.ip != "" && bb.ip != "":
			an, bn := fwNetOf(ba.ip), fwNetOf(bb.ip)
			if an != nil && bn != nil && (fwNetContains(an, bn) || fwNetContains(bn, an)) {
				return fmt.Errorf("zones %s and %s have overlapping source ranges %s/%s; firewalld's zone "+
					"dispatch order is not representable in bfw", a.name, b.name, ba.ip, bb.ip)
			}
		case ba.set != "" && bb.set != "" && ba.set == bb.set:
			return fmt.Errorf("zones %s and %s both bind ipset %s", a.name, b.name, ba.set)
		default:
			// Address-vs-ipset or two different ipsets: overlap cannot
			// be verified, so reject rather than broaden.
			return fmt.Errorf("zones %s and %s have unverifiably-overlapping source bindings (%s vs %s); "+
				"zone dispatch precedence is not representable in bfw",
				a.name, b.name, fwBindingDesc(ba), fwBindingDesc(bb))
		}
	}
	return nil
}

func fwBindingDesc(b fwBinding) string {
	if b.isIface {
		return "interface " + b.iface
	}
	if b.set != "" {
		return "ipset " + b.set
	}
	return b.ip
}

// zoneSource parses a zone <source> binding (address or ipset).
func (f *fwLoader) zoneSource(path, zname string, e *fwElem) (fwBinding, error) {
	where := fmt.Sprintf("%s (zone %s) <source>", path, zname)
	if err := fwCheckAttrs(e, where, "address", "ipset", "invert"); err != nil {
		return fwBinding{}, err
	}
	inv, err := fwBool(e.attr("invert"))
	if err != nil {
		return fwBinding{}, fmt.Errorf("%s: %v", where, err)
	}
	if inv {
		return fwBinding{}, fwInvertError(where, "source")
	}
	addr, set := e.attr("address"), e.attr("ipset")
	if (addr == "") == (set == "") {
		return fwBinding{}, fmt.Errorf("%s: exactly one of address/ipset is required", where)
	}
	if set != "" {
		v4, v6, err := f.setFamily(set, where)
		if err != nil {
			return fwBinding{}, err
		}
		return fwBinding{set: set, v4: v4, v6: v6}, nil
	}
	c, err := fwCanonAddr(addr, where)
	if err != nil {
		return fwBinding{}, err
	}
	v4, v6 := fwAddrFamily(c)
	return fwBinding{ip: c, v4: v4, v6: v6}, nil
}

// ---------------------------------------------------------------------
// rule templates and emission

// fwTmpl is a zone-element rule before binding/family expansion.
type fwTmpl struct {
	action   string
	log      string
	proto    string // "" → "any"
	icmpType string // canonical ICMP type number; requires proto icmp/icmpv6
	dports   []rule.PortRange
	sports   []rule.PortRange
	srcIP    string
	srcSet   string
	dstIP    string
	dstSet   string
	v4, v6   bool
	comment  string
}

// emit expands a template across zone bindings and families into staged
// rule lists. Source bindings AND-combine with the element's own source
// via CIDR containment (disjoint = dead rule, partial = impossible for
// CIDRs, ipset+address mixes are rejected).
func (f *fwLoader) emit(z *fwZone, t fwTmpl) error {
	proto := t.proto
	if proto == "" {
		proto = "any"
	}
	for _, b := range z.bindings {
		srcIP, srcSet := t.srcIP, t.srcSet
		v4, v6 := t.v4 && b.v4, t.v6 && b.v6
		dead := false
		switch {
		case b.ip == "" && b.set == "":
			// Wildcard/interface binding: the rule's own source stands.
		case b.ip != "":
			switch {
			case srcIP == "" && srcSet == "":
				srcIP = b.ip
			case srcSet != "":
				return fmt.Errorf("%s (zone %s): cannot combine zone source address %s with rule source ipset %s",
					z.path, z.name, b.ip, srcSet)
			default:
				// Element source AND-ed with the zone binding: CIDRs
				// either contain one another or are disjoint.
				bn, sn := fwNetOf(b.ip), fwNetOf(srcIP)
				switch {
				case bn != nil && sn != nil && fwNetContains(bn, sn):
					// Rule source is narrower (or equal): it stands.
				case bn != nil && sn != nil && fwNetContains(sn, bn):
					srcIP = b.ip // binding is narrower
				case bn != nil && sn != nil:
					dead = true // disjoint: cannot ever match
					f.warn("zone %s: rule source %s never matches zone source binding %s, skipped for that binding",
						z.name, srcIP, b.ip)
				default:
					return fmt.Errorf("%s (zone %s): cannot intersect source addresses", z.path, z.name)
				}
			}
		case b.set != "":
			switch {
			case srcIP == "" && srcSet == "":
				srcSet = b.set
			case srcSet == b.set:
				// Same set on binding and rule: it stands.
			default:
				return fmt.Errorf("%s (zone %s): cannot combine zone source ipset %s with rule source",
					z.path, z.name, b.set)
			}
		}
		if dead {
			continue
		}
		if !v4 && !v6 {
			return fmt.Errorf("%s (zone %s): rule families conflict with zone bindings", z.path, z.name)
		}
		r := rule.Rule{
			ID:        rule.NewID(),
			Action:    t.action,
			Direction: rule.DirIn,
			IfaceIn:   b.iface,
			Proto:     proto,
			ICMPType:  t.icmpType,
			Src:       rule.AddrSpec{IP: srcIP, Set: srcSet, Ports: t.sports},
			Dst:       rule.AddrSpec{IP: t.dstIP, Set: t.dstSet, Ports: t.dports},
			Log:       t.log,
			Comment:   t.comment,
		}
		if r.Src.IP == "" {
			r.Src.IP = "any"
		}
		if r.Dst.IP == "" {
			r.Dst.IP = "any"
		}
		r.Normalize()
		if r.Src.IP == "0.0.0.0/0" || r.Src.IP == "::/0" {
			r.Src.IP = "any"
		}
		if r.Dst.IP == "0.0.0.0/0" || r.Dst.IP == "::/0" {
			r.Dst.IP = "any"
		}
		if v4 {
			f.rules4 = append(f.rules4, r)
		}
		if v6 {
			r6 := r
			r6.SetV6(true)
			f.rules6 = append(f.rules6, r6)
		}
	}
	return nil
}

// zoneElem converts one zone child element into emitted rules.
func (f *fwLoader) zoneElem(z *fwZone, e *fwElem) error {
	where := fmt.Sprintf("%s (zone %s) <%s>", z.path, z.name, e.name)
	switch e.name {
	case "service":
		if err := fwCheckAttrs(e, where, "name"); err != nil {
			return err
		}
		name := e.attr("name")
		if name == "" {
			return fmt.Errorf("%s: missing name attribute", where)
		}
		def, err := f.resolveService(name, map[string]bool{})
		if err != nil {
			return fmt.Errorf("%s: %v", where, err)
		}
		return f.emitService(z, name, def)
	case "port":
		lo, hi, proto, err := fwPortElem(e, where)
		if err != nil {
			return err
		}
		t := fwTmpl{action: rule.ActionAllow, proto: proto, v4: true, v6: true,
			dports:  []rule.PortRange{{Lo: lo, Hi: hi, Proto: proto}},
			comment: fmt.Sprintf("firewalld zone %s port", z.name)}
		return f.emit(z, t)
	case "source-port":
		lo, hi, proto, err := fwPortElem(e, where)
		if err != nil {
			return err
		}
		t := fwTmpl{action: rule.ActionAllow, proto: proto, v4: true, v6: true,
			sports:  []rule.PortRange{{Lo: lo, Hi: hi, Proto: proto}},
			comment: fmt.Sprintf("firewalld zone %s source-port", z.name)}
		return f.emit(z, t)
	case "protocol":
		if err := fwCheckAttrs(e, where, "value"); err != nil {
			return err
		}
		proto, v4, v6, err := fwNormProto(e.attr("value"), where)
		if err != nil {
			return err
		}
		return f.emit(z, fwTmpl{action: rule.ActionAllow, proto: proto, v4: v4, v6: v6,
			comment: fmt.Sprintf("firewalld zone %s protocol %s", z.name, proto)})
	case "rule":
		return f.richRule(z, e)
	case "icmp-block", "icmp-block-inversion":
		return fmt.Errorf("%s: zone ICMP blocking is not representable in bfw", where)
	case "icmp-type":
		return fmt.Errorf("%s: icmp-type is only representable inside a family-scoped <rule>", where)
	case "masquerade", "forward-port":
		return fmt.Errorf("%s: NAT semantics are not supported by the firewalld importer", where)
	case "forward":
		return fmt.Errorf("%s: intra-zone forwarding is not representable in bfw", where)
	case "tcp-mss-clamp":
		return fmt.Errorf("%s: TCP MSS clamping is not representable in bfw", where)
	default:
		return fmt.Errorf("%s: unsupported zone element", where)
	}
}

// emitService expands a resolved service into allow rules: one rule
// carrying all port ranges (protocol bound per range) plus one rule per
// bare protocol match, split by destination families when present.
func (f *fwLoader) emitService(z *fwZone, name string, def *fwSvcDef) error {
	comment := fmt.Sprintf("firewalld zone %s service %s", z.name, name)
	if len(def.ports) == 0 && len(def.protos) == 0 {
		return fmt.Errorf("%s (zone %s): service %q defines no ports or protocols", z.path, z.name, name)
	}
	if len(def.ports) > 0 {
		var prs []rule.PortRange
		protos := map[string]bool{}
		for _, p := range def.ports {
			prs = append(prs, rule.PortRange{Lo: p.lo, Hi: p.hi, Proto: p.proto})
			protos[p.proto] = true
		}
		t := fwTmpl{action: rule.ActionAllow, dports: prs, v4: true, v6: true, comment: comment}
		if len(protos) == 1 {
			for p := range protos {
				t.proto = p
			}
		}
		if err := f.emitWithDst(z, t, def); err != nil {
			return err
		}
	}
	for _, pv := range def.protos {
		proto, v4, v6, err := fwNormProto(pv, z.path)
		if err != nil {
			return err
		}
		if err := f.emitWithDst(z, fwTmpl{action: rule.ActionAllow, proto: proto, v4: v4, v6: v6, comment: comment}, def); err != nil {
			return err
		}
	}
	for _, m := range def.modules {
		f.warn("service %s: conntrack module %q is not imported (no bfw equivalent)", name, m)
	}
	return nil
}

// emitWithDst splits a template by the service's destination addresses
// (per-family) or emits it dual-family.
func (f *fwLoader) emitWithDst(z *fwZone, t fwTmpl, def *fwSvcDef) error {
	if def.dst4 == "" && def.dst6 == "" {
		return f.emit(z, t)
	}
	if def.dst4 != "" {
		t4 := t
		t4.dstIP = def.dst4
		t4.v6 = false
		if err := f.emit(z, t4); err != nil {
			return err
		}
	}
	if def.dst6 != "" {
		t6 := t
		t6.dstIP = def.dst6
		t6.v4 = false
		return f.emit(z, t6)
	}
	return nil
}

// richRule converts a zone <rule> element. Grammar supported: optional
// family attr; optional source/destination (address|ipset); at most one
// match element (port, source-port, service, protocol, or icmp-type —
// firewalld allows only one element anyway); optional log/audit;
// exactly one verdict (accept [+limit], drop, reject). An icmp-type
// match resolves its name only when the rule is pinned to one address
// family by the family attribute or the source/destination addresses.
func (f *fwLoader) richRule(z *fwZone, e *fwElem) error {
	where := fmt.Sprintf("%s (zone %s) <rule>", z.path, z.name)
	t := fwTmpl{v4: true, v6: true,
		comment: fmt.Sprintf("firewalld zone %s rich rule", z.name)}
	if err := fwCheckAttrs(e, where, "family"); err != nil {
		return err
	}
	switch fam := e.attr("family"); fam {
	case "":
	case "ipv4":
		t.v6 = false
	case "ipv6":
		t.v4 = false
	default:
		return fmt.Errorf("%s: bad family %q", where, fam)
	}
	elems := 0
	markElem := func() error {
		elems++
		if elems > 1 {
			return fmt.Errorf("%s: rich rule has more than one match element", where)
		}
		return nil
	}
	// icmpName defers <icmp-type> name→number resolution until the whole
	// rule is parsed: element order inside <rule> is not significant in
	// firewalld, so the family (attr or endpoint addresses) must be
	// complete before a proto can be chosen.
	icmpName := ""
	for _, k := range e.kids {
		kw := fmt.Sprintf("%s <%s>", where, k.name)
		switch k.name {
		case "source", "destination":
			isSrc := k.name == "source"
			ip, set, v4, v6, err := f.ruleEnd(k, kw)
			if err != nil {
				return err
			}
			if isSrc {
				if t.srcIP != "" || t.srcSet != "" {
					return fmt.Errorf("%s: duplicate <source>", kw)
				}
				t.srcIP, t.srcSet = ip, set
			} else {
				if t.dstIP != "" || t.dstSet != "" {
					return fmt.Errorf("%s: duplicate <destination>", kw)
				}
				t.dstIP, t.dstSet = ip, set
			}
			t.v4 = t.v4 && v4
			t.v6 = t.v6 && v6
		case "port":
			if err := markElem(); err != nil {
				return err
			}
			lo, hi, proto, err := fwPortElem(k, kw)
			if err != nil {
				return err
			}
			t.dports = []rule.PortRange{{Lo: lo, Hi: hi, Proto: proto}}
			t.proto = proto
		case "source-port":
			if err := markElem(); err != nil {
				return err
			}
			lo, hi, proto, err := fwPortElem(k, kw)
			if err != nil {
				return err
			}
			t.sports = []rule.PortRange{{Lo: lo, Hi: hi, Proto: proto}}
			t.proto = proto
		case "service":
			if err := markElem(); err != nil {
				return err
			}
			if err := fwCheckAttrs(k, kw, "name"); err != nil {
				return err
			}
			name := k.attr("name")
			def, err := f.resolveService(name, map[string]bool{})
			if err != nil {
				return fmt.Errorf("%s: %v", kw, err)
			}
			if err := f.richService(&t, def, kw); err != nil {
				return err
			}
			for _, m := range def.modules {
				f.warn("service %s: conntrack module %q is not imported (no bfw equivalent)", name, m)
			}
		case "protocol":
			if err := markElem(); err != nil {
				return err
			}
			if err := fwCheckAttrs(k, kw, "value"); err != nil {
				return err
			}
			proto, v4, v6, err := fwNormProto(k.attr("value"), kw)
			if err != nil {
				return err
			}
			t.proto = proto
			t.v4 = t.v4 && v4
			t.v6 = t.v6 && v6
		case "icmp-type":
			if err := markElem(); err != nil {
				return err
			}
			if err := fwCheckAttrs(k, kw, "name"); err != nil {
				return err
			}
			if len(k.kids) != 0 {
				return fmt.Errorf("%s: unexpected element <%s>", kw, k.kids[0].name)
			}
			icmpName = k.attr("name")
			if icmpName == "" {
				return fmt.Errorf("%s: missing name attribute", kw)
			}
		case "masquerade", "forward-port":
			return fmt.Errorf("%s: NAT semantics are not supported by the firewalld importer", kw)
		case "log":
			if err := fwCheckAttrs(k, kw, "prefix", "level"); err != nil {
				return err
			}
			if k.attr("prefix") != "" || k.attr("level") != "" {
				f.warn("%s: log prefix/level is not representable and was dropped", kw)
			}
			for _, c := range k.kids {
				if c.name == "limit" {
					return fmt.Errorf("%s: log rate limits are not representable in bfw", kw)
				}
				return fmt.Errorf("%s: unsupported log element <%s>", kw, c.name)
			}
			t.log = rule.LogAll
		case "audit":
			if len(k.kids) != 0 {
				return fmt.Errorf("%s: audit options are not representable in bfw", kw)
			}
			f.warn("%s: audit logging is not representable and was skipped", kw)
		case "accept":
			if t.action != "" {
				return fmt.Errorf("%s: rich rule has multiple verdicts", where)
			}
			if err := fwCheckAttrs(k, kw); err != nil {
				return err
			}
			t.action = rule.ActionAllow
			for _, c := range k.kids {
				if c.name == "limit" {
					return fmt.Errorf("%s: rate limits are not representable in bfw "+
						"(bfw's limit action is a fixed rate, not the source rate)", kw)
				}
				return fmt.Errorf("%s: unsupported accept element <%s>", kw, c.name)
			}
		case "drop":
			if t.action != "" {
				return fmt.Errorf("%s: rich rule has multiple verdicts", where)
			}
			if err := fwCheckAttrs(k, kw); err != nil {
				return err
			}
			if len(k.kids) != 0 {
				return fmt.Errorf("%s: unexpected elements inside <drop>", kw)
			}
			t.action = rule.ActionDeny
		case "reject":
			if t.action != "" {
				return fmt.Errorf("%s: rich rule has multiple verdicts", where)
			}
			if err := fwCheckAttrs(k, kw, "type"); err != nil {
				return err
			}
			for _, c := range k.kids {
				if c.name == "limit" {
					return fmt.Errorf("%s: rate limits are not representable in bfw", kw)
				}
				return fmt.Errorf("%s: unsupported reject element <%s>", kw, c.name)
			}
			if v := k.attr("type"); v != "" {
				f.warn("%s: reject type %q is not representable; imported as generic reject", kw, v)
			}
			t.action = rule.ActionReject
		case "mark":
			return fmt.Errorf("%s: packet marking is not representable in bfw", kw)
		default:
			return fmt.Errorf("%s: unsupported rule element <%s>", where, k.name)
		}
	}
	if t.action == "" {
		return fmt.Errorf("%s: rich rule has no verdict (accept/drop/reject)", where)
	}
	if icmpName != "" {
		var proto string
		switch {
		case t.v4 && !t.v6:
			proto = "icmp"
		case t.v6 && !t.v4:
			proto = "icmpv6"
		default:
			return fmt.Errorf("%s <icmp-type>: cannot resolve the ICMP family "+
				"(set family=\"ipv4\"/\"ipv6\" or single-family addresses)", where)
		}
		num, err := rule.ICMPTypeNumber(proto, icmpName)
		if err != nil {
			return fmt.Errorf("%s <icmp-type>: %v", where, err)
		}
		t.proto = proto
		t.icmpType = num
	}
	return f.emit(z, t)
}

// richService folds a resolved service into a rich-rule template: ports
// become dports; a single bare protocol sets proto; anything richer is
// not representable inside one rule.
func (f *fwLoader) richService(t *fwTmpl, def *fwSvcDef, where string) error {
	if len(def.ports) == 0 && len(def.protos) == 0 {
		return fmt.Errorf("%s: service defines no ports or protocols", where)
	}
	if len(def.protos) > 1 || (len(def.protos) > 0 && len(def.ports) > 0) {
		return fmt.Errorf("%s: service mixing ports with bare protocols is not representable in one rule", where)
	}
	for _, p := range def.ports {
		t.dports = append(t.dports, rule.PortRange{Lo: p.lo, Hi: p.hi, Proto: p.proto})
	}
	if len(def.protos) == 1 {
		proto, v4, v6, err := fwNormProto(def.protos[0], where)
		if err != nil {
			return err
		}
		t.proto = proto
		t.v4 = t.v4 && v4
		t.v6 = t.v6 && v6
	}
	if def.dst4 != "" || def.dst6 != "" {
		return fmt.Errorf("%s: service destination restrictions are not representable inside a rich rule", where)
	}
	return nil
}

// ruleEnd parses a rich-rule <source>/<destination>: address or ipset,
// no inversion. Returns the endpoint plus the families it can fire in.
func (f *fwLoader) ruleEnd(e *fwElem, where string) (ip, set string, v4, v6 bool, err error) {
	if err = fwCheckAttrs(e, where, "address", "ipset", "invert"); err != nil {
		return
	}
	var inv bool
	if inv, err = fwBool(e.attr("invert")); err != nil {
		err = fmt.Errorf("%s: %v", where, err)
		return
	}
	if inv {
		err = fwInvertError(where, e.name)
		return
	}
	addr, setName := e.attr("address"), e.attr("ipset")
	if (addr == "") == (setName == "") {
		err = fmt.Errorf("%s: exactly one of address/ipset is required", where)
		return
	}
	if setName != "" {
		v4, v6, err = f.setFamily(setName, where)
		set = setName
		return
	}
	if ip, err = fwCanonAddr(addr, where); err != nil {
		return
	}
	v4, v6 = fwAddrFamily(ip)
	return
}

// fwCloneState deep-copies st enough that mergeRules/mergeSets cannot
// mutate the caller's state (fresh rule and set-element slices).
func fwCloneState(st *store.State) *store.State {
	out := *st
	out.Rules4 = append([]rule.Rule(nil), st.Rules4...)
	out.Rules6 = append([]rule.Rule(nil), st.Rules6...)
	out.NAT = append([]store.NATRule(nil), st.NAT...)
	out.Sets = append([]store.IPSet(nil), st.Sets...)
	for i := range out.Sets {
		out.Sets[i].Elements = append([]string(nil), out.Sets[i].Elements...)
	}
	out.Bans = append([]store.ThreatBan(nil), st.Bans...)
	return &out
}
