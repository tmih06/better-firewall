// Package impexp implements bfw export/import (JSON state documents) and
// the ufw migration importer that parses /etc/ufw/user.rules + user6.rules
// "### tuple ###" lines, /etc/default/ufw policies, and ufw.conf.
package impexp

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/tmih06/better-firewall/internal/rule"
	"github.com/tmih06/better-firewall/internal/store"
)

// document is the on-disk JSON shape produced by Export and consumed by
// Import. Scalar fields are pointers so Import can tell "absent" from an
// explicit zero value.
type document struct {
	Version   int             `json:"version"`
	Rules4    []rule.Rule     `json:"rules4"`
	Rules6    []rule.Rule     `json:"rules6"`
	Policies  *store.Policies `json:"policies,omitempty"`
	Logging   *string         `json:"logging,omitempty"`
	IPv6      *bool           `json:"ipv6,omitempty"`
	AppPolicy *string         `json:"app_policy,omitempty"`
	Panic     *bool           `json:"panic,omitempty"`
	Sets      []store.IPSet   `json:"sets,omitempty"`
	NAT       []store.NATRule `json:"nat,omitempty"`
}

// Export writes st as a versioned JSON document to w.
func Export(st *store.State, w io.Writer) error {
	pol := st.Policies
	logging := st.Logging
	ipv6 := st.IPv6
	appPolicy := st.AppPolicy
	panicMode := st.Panic
	doc := document{
		Version:   1,
		Rules4:    st.Rules4,
		Rules6:    st.Rules6,
		Policies:  &pol,
		Logging:   &logging,
		IPv6:      &ipv6,
		AppPolicy: &appPolicy,
		Panic:     &panicMode,
		Sets:      st.Sets,
		NAT:       st.NAT,
	}
	if doc.Rules4 == nil {
		doc.Rules4 = []rule.Rule{}
	}
	if doc.Rules6 == nil {
		doc.Rules6 = []rule.Rule{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// Import reads an export document from r and merges it into st. With
// replace=false, rules are deduplicated per ufw match semantics (exact
// duplicates skipped, comment/action diffs update in place) and scalar
// fields present in the document overwrite st's. With replace=true the
// document becomes the state wholesale (absent fields fall back to
// install defaults). Returns the merged state and the number of rules
// added or updated.
func Import(r io.Reader, st *store.State, replace bool) (*store.State, int, error) {
	var doc document
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, 0, fmt.Errorf("invalid import file: %w", err)
	}
	if doc.Version != 1 {
		return nil, 0, fmt.Errorf("unsupported export version %d", doc.Version)
	}

	var out *store.State
	if replace {
		out = store.Defaults()
	} else {
		out = st
	}

	if doc.Policies != nil {
		out.Policies = *doc.Policies
	}
	if doc.Logging != nil {
		out.Logging = *doc.Logging
	}
	if doc.IPv6 != nil {
		out.IPv6 = *doc.IPv6
	}
	if doc.AppPolicy != nil {
		out.AppPolicy = *doc.AppPolicy
	}
	if doc.Panic != nil {
		out.Panic = *doc.Panic
	}

	for i := range doc.Rules4 {
		doc.Rules4[i].SetV6(false)
		doc.Rules4[i].Normalize()
	}
	for i := range doc.Rules6 {
		doc.Rules6[i].SetV6(true)
		doc.Rules6[i].Normalize()
	}

	if replace {
		out.Rules4 = doc.Rules4
		out.Rules6 = doc.Rules6
		out.Sets = doc.Sets
		out.NAT = doc.NAT
		return out, len(doc.Rules4) + len(doc.Rules6), nil
	}

	added := mergeRules(&out.Rules4, doc.Rules4)
	added += mergeRules(&out.Rules6, doc.Rules6)
	mergeSets(out, doc.Sets)
	mergeNAT(out, doc.NAT)
	return out, added, nil
}

// mergeRules merges src into dst per ufw dedup semantics: exact duplicates
// are skipped, comment/action/log diffs replace the existing rule in place,
// everything else appends. Returns the number of rules added or updated.
func mergeRules(dst *[]rule.Rule, src []rule.Rule) int {
	added := 0
	for i := range src {
		nr := &src[i]
		merged := false
		for j := range *dst {
			switch nr.Match(&(*dst)[j]) {
			case rule.MatchExact:
				merged = true
			case rule.MatchComment, rule.MatchAction:
				// In-place replace keeps the stored rule's ID and bfw
				// extensions (disabled/expires) that the import lacks.
				id := (*dst)[j].ID
				dis, exp := (*dst)[j].Disabled, (*dst)[j].ExpiresAt
				(*dst)[j] = *nr
				(*dst)[j].ID = id
				(*dst)[j].Disabled = dis
				(*dst)[j].ExpiresAt = exp
				added++
				merged = true
			}
			if merged {
				break
			}
		}
		if merged {
			continue
		}
		if nr.ID == "" || idUsed(*dst, nr.ID) {
			nr.ID = rule.NewID()
		}
		*dst = append(*dst, *nr)
		added++
	}
	return added
}

func idUsed(rules []rule.Rule, id string) bool {
	for i := range rules {
		if rules[i].ID == id {
			return true
		}
	}
	return false
}

// mergeSets unions imported sets into st by name (elements deduplicated).
func mergeSets(st *store.State, sets []store.IPSet) {
	for _, s := range sets {
		found := false
		for j := range st.Sets {
			if st.Sets[j].Name == s.Name {
				have := map[string]bool{}
				for _, el := range st.Sets[j].Elements {
					have[el] = true
				}
				for _, el := range s.Elements {
					if !have[el] {
						st.Sets[j].Elements = append(st.Sets[j].Elements, el)
					}
				}
				found = true
				break
			}
		}
		if !found {
			st.Sets = append(st.Sets, s)
		}
	}
}

// mergeNAT appends imported NAT rules not already present.
func mergeNAT(st *store.State, nat []store.NATRule) {
	for _, n := range nat {
		dup := false
		for _, e := range st.NAT {
			if e == n {
				dup = true
				break
			}
		}
		if !dup {
			st.NAT = append(st.NAT, n)
		}
	}
}

// ImportUFW migrates a ufw installation rooted at dir (typically /etc/ufw):
// it parses <dir>/user.rules (IPv4) and <dir>/user6.rules (IPv6)
// "### tuple ###" lines, applies policies from etcFile (typically
// /etc/default/ufw) and ENABLED/LOGLEVEL from <dir>/ufw.conf, then merges
// the parsed rules into st. Identical tuples present in both files become
// dual-family rules sharing one ID. Malformed tuples are skipped and
// reported in the returned warnings slice.
func ImportUFW(dir string, etcFile string, st *store.State) (*store.State, int, []string, error) {
	var warnings []string

	v4rules, w, err := parseUserRules(filepath.Join(dir, "user.rules"), false)
	warnings = append(warnings, w...)
	if err != nil {
		return nil, 0, warnings, err
	}
	v6rules, w, err := parseUserRules(filepath.Join(dir, "user6.rules"), true)
	warnings = append(warnings, w...)
	if err != nil {
		return nil, 0, warnings, err
	}
	if v4rules == nil && v6rules == nil {
		return nil, 0, warnings, fmt.Errorf("no ufw rules found in %s", dir)
	}

	// Identical tuples in both files → dual rule sharing the v4 ID.
	v4byKey := map[string]string{}
	for i := range v4rules {
		// TupleKey includes the family flag; compute both keys with v6
		// cleared so identical tuples in the two files compare equal.
		v4byKey[v4rules[i].TupleKey()] = v4rules[i].ID
	}
	for i := range v6rules {
		v6rules[i].SetV6(false)
		key := v6rules[i].TupleKey()
		v6rules[i].SetV6(true)
		if id, ok := v4byKey[key]; ok {
			v6rules[i].ID = id
		}
	}

	out := st
	added := mergeRules(&out.Rules4, v4rules)
	added += mergeRules(&out.Rules6, v6rules)

	warnings = append(warnings, applyUfwDefaults(out, etcFile)...)
	warnings = append(warnings, applyUfwConf(out, filepath.Join(dir, "ufw.conf"))...)

	return out, added, warnings, nil
}

// parseUserRules extracts "### tuple ###" lines from a ufw user.rules file.
// A missing file yields nil rules and no error. v6 marks the parsed rules
// as belonging to the IPv6 family.
func parseUserRules(path string, v6 bool) ([]rule.Rule, []string, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var rules []rule.Rule
	var warnings []string
	for ln, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "### tuple ###") {
			continue
		}
		r, err := ParseTupleLine(line)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s:%d: %v", path, ln+1, err))
			continue
		}
		r.SetV6(v6)
		rules = append(rules, *r)
	}
	return rules, warnings, nil
}

// ParseTupleLine parses one ufw "### tuple ###" line:
//
//	### tuple ### <action> <proto> <dport> <dst> <sport> <src>
//	    [<dapp> <sapp>] <ifaces>[ comment=<text>]
//
// action = allow|deny|reject|limit with optional "route:" prefix and
// "_log"/"_log-all" suffix; ifaces = in|out or in_<if>/out_<if>/
// in_<if>!out_<if>; dapp/sapp = "-" or a %20-escaped name. Legacy 6- and
// 8-field tuples (no ifaces field) default to direction in.
func ParseTupleLine(line string) (*rule.Rule, error) {
	rest := strings.TrimSpace(strings.TrimPrefix(line, "### tuple ###"))
	comment := ""
	if i := strings.Index(rest, " comment="); i >= 0 {
		comment = rest[i+len(" comment="):]
		rest = rest[:i]
	} else if strings.HasPrefix(rest, "comment=") {
		comment = strings.TrimPrefix(rest, "comment=")
		rest = ""
	}

	f := strings.Fields(rest)
	var ifaces string
	var dapp, sapp string
	switch len(f) {
	case 6: // legacy: no apps, no ifaces
	case 7:
		ifaces = f[6]
	case 8: // legacy: apps, no ifaces
		dapp, sapp = f[6], f[7]
	case 9:
		dapp, sapp = f[6], f[7]
		ifaces = f[8]
	default:
		return nil, fmt.Errorf("malformed tuple (%d fields): %s", len(f), line)
	}

	r := &rule.Rule{
		ID:        rule.NewID(),
		Direction: rule.DirIn,
		Comment:   comment,
	}

	// Action: optional route: prefix, optional _log/_log-all suffix.
	action := f[0]
	routed := false
	if strings.HasPrefix(action, "route:") {
		routed = true
		action = strings.TrimPrefix(action, "route:")
	}
	switch {
	case strings.HasSuffix(action, "_log-all"):
		r.Log = rule.LogAll
		action = strings.TrimSuffix(action, "_log-all")
	case strings.HasSuffix(action, "_log"):
		r.Log = rule.LogNew
		action = strings.TrimSuffix(action, "_log")
	}
	switch action {
	case rule.ActionAllow, rule.ActionDeny, rule.ActionReject, rule.ActionLimit:
		r.Action = action
	default:
		return nil, fmt.Errorf("bad action %q in tuple: %s", f[0], line)
	}
	if routed {
		r.Direction = rule.DirRouted
	}

	// Proto.
	proto := f[1]
	if proto == "" {
		return nil, fmt.Errorf("empty proto in tuple: %s", line)
	}
	r.Proto = proto

	// Ports and addresses.
	dports, err := parsePortList(f[2], proto)
	if err != nil {
		return nil, fmt.Errorf("bad dport %q in tuple: %s", f[2], line)
	}
	sports, err := parsePortList(f[4], proto)
	if err != nil {
		return nil, fmt.Errorf("bad sport %q in tuple: %s", f[4], line)
	}
	r.Dst = rule.AddrSpec{IP: f[3], Ports: dports}
	r.Src = rule.AddrSpec{IP: f[5], Ports: sports}

	// Apps ("-" = none; %20 escapes spaces).
	if dapp != "" && dapp != "-" {
		r.Dapp = unescapeApp(dapp)
	}
	if sapp != "" && sapp != "-" {
		r.Sapp = unescapeApp(sapp)
	}

	// Interfaces / direction.
	if ifaces != "" && ifaces != "-" {
		dirSet := false
		for _, part := range strings.Split(ifaces, "!") {
			switch {
			case part == "in":
				if !dirSet {
					r.Direction = rule.DirIn
					dirSet = true
				}
			case part == "out":
				if !dirSet {
					r.Direction = rule.DirOut
					dirSet = true
				}
			case strings.HasPrefix(part, "in_"):
				r.IfaceIn = part[3:]
				if !dirSet {
					r.Direction = rule.DirIn
					dirSet = true
				}
			case strings.HasPrefix(part, "out_"):
				r.IfaceOut = part[4:]
				if !dirSet {
					r.Direction = rule.DirOut
					dirSet = true
				}
			default:
				return nil, fmt.Errorf("bad ifaces %q in tuple: %s", ifaces, line)
			}
		}
	}
	if routed {
		r.Direction = rule.DirRouted
	}

	r.Normalize()
	// ufw writes wildcards as 0.0.0.0/0 and ::/0; canonicalize so
	// identical tuples in user.rules/user6.rules merge to dual rules.
	if r.Src.IP == "0.0.0.0/0" || r.Src.IP == "::/0" {
		r.Src.IP = "any"
	}
	if r.Dst.IP == "0.0.0.0/0" || r.Dst.IP == "::/0" {
		r.Dst.IP = "any"
	}
	return r, nil
}

// parsePortList parses a ufw tuple port field: "any", a single port, a
// range lo:hi, or a comma-separated list of those. proto is the rule's
// protocol, bound onto each range.
func parsePortList(s, proto string) ([]rule.PortRange, error) {
	if s == "" || s == "any" || s == "-" {
		return nil, nil
	}
	p := proto
	if p != "tcp" && p != "udp" {
		p = "any"
	}
	var out []rule.PortRange
	for _, item := range strings.Split(s, ",") {
		if item == "" {
			return nil, fmt.Errorf("empty port item")
		}
		lo, hi, err := parsePortRange(item)
		if err != nil {
			return nil, err
		}
		out = append(out, rule.PortRange{Lo: lo, Hi: hi, Proto: p})
	}
	return out, nil
}

func parsePortRange(item string) (uint16, uint16, error) {
	lo, hi, found := strings.Cut(item, ":")
	l, err := parsePort(lo)
	if err != nil {
		return 0, 0, err
	}
	if !found {
		return l, l, nil
	}
	h, err := parsePort(hi)
	if err != nil {
		return 0, 0, err
	}
	if h <= l {
		return 0, 0, fmt.Errorf("bad port range %q", item)
	}
	return l, h, nil
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("bad port %q", s)
	}
	return uint16(n), nil
}

func unescapeApp(s string) string {
	return strings.ReplaceAll(s, "%20", " ")
}

// applyUfwDefaults maps /etc/default/ufw policy keys onto st.
func applyUfwDefaults(st *store.State, etcFile string) []string {
	var warnings []string
	kv, err := parseKVFile(etcFile)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("%s: %v", etcFile, err))
		return warnings
	}
	if kv == nil {
		return nil
	}
	pol := func(key string, dst *string) {
		v, ok := kv[key]
		if !ok {
			return
		}
		switch strings.ToLower(v) {
		case "accept", "allow":
			*dst = "allow"
		case "drop", "deny":
			*dst = "deny"
		case "reject":
			*dst = "reject"
		default:
			warnings = append(warnings, fmt.Sprintf("%s: unknown policy %q for %s", etcFile, v, key))
		}
	}
	pol("DEFAULT_INPUT_POLICY", &st.Policies.Input)
	pol("DEFAULT_OUTPUT_POLICY", &st.Policies.Output)
	pol("DEFAULT_FORWARD_POLICY", &st.Policies.Forward)
	if v, ok := kv["IPV6"]; ok {
		st.IPv6 = strings.EqualFold(v, "yes")
	}
	if v, ok := kv["DEFAULT_APPLICATION_POLICY"]; ok {
		// ufw stores iptables targets (ACCEPT/DROP/REJECT/SKIP); map to
		// the better-firewall policy words (allow/deny/reject/skip).
		switch strings.ToLower(v) {
		case "accept", "allow":
			st.AppPolicy = "allow"
		case "drop", "deny":
			st.AppPolicy = "deny"
		case "reject":
			st.AppPolicy = "reject"
		case "skip":
			st.AppPolicy = "skip"
		default:
			warnings = append(warnings, fmt.Sprintf("%s: unknown application policy %q", etcFile, v))
		}
	}
	return warnings
}

// applyUfwConf maps ufw.conf LOGLEVEL onto st.Logging; ENABLED=yes produces
// a warning since bfw enablement is a separate step.
func applyUfwConf(st *store.State, confPath string) []string {
	var warnings []string
	kv, err := parseKVFile(confPath)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("%s: %v", confPath, err))
		return warnings
	}
	if kv == nil {
		return nil
	}
	if v, ok := kv["LOGLEVEL"]; ok {
		switch strings.ToLower(v) {
		case "off", "low", "medium", "high", "full":
			st.Logging = strings.ToLower(v)
		default:
			warnings = append(warnings, fmt.Sprintf("%s: unknown LOGLEVEL %q", confPath, v))
		}
	}
	if strings.EqualFold(kv["ENABLED"], "yes") {
		warnings = append(warnings, "ufw was enabled; run 'bfw enable' to activate the imported ruleset")
	}
	return warnings
}

// parseKVFile reads a KEY=VALUE file (ufw.conf, /etc/default/ufw style):
// comments and blanks skipped, values may be single- or double-quoted.
// A missing file yields nil map and nil error.
func parseKVFile(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	kv := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 {
			if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
				v = v[1 : len(v)-1]
			}
		}
		kv[strings.TrimSpace(k)] = v
	}
	return kv, nil
}
