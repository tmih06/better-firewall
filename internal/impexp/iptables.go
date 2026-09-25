package impexp

// iptables.go imports iptables-save/ip6tables-save output (the
// iptables-persistent format written to rules.v4/rules.v6): filter-table
// chain policies and ordered -A/-I rules. Anything not exactly
// representable by the rule model — non-filter tables with rules or
// non-ACCEPT policies on those tables, user chains reachable from builtins,
// unmapped match modules, negation, and non-verdict targets — abort the import
// with an actionable error rather than silently dropping or broadening semantics.

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/tmih06/better-firewall/internal/rule"
	"github.com/tmih06/better-firewall/internal/store"
)

// ImportIPTables merges iptables-save (v4) and ip6tables-save (v6) dumps
// into a clone of st; a nil reader means that family is not imported. Only
// the filter table is representable: INPUT rules become direction in,
// OUTPUT direction out, FORWARD direction routed, and builtin chain
// policies map onto st.Policies. Supported rule flags: -p, -s/-d (numeric addresses
// and CIDRs), -i/-o, --sport/--dport and -m multiport lists/ranges,
// matching -m tcp/udp/icmp/icmp6/icmpv6 modules with explicit -p, --icmp-type and
// --icmpv6-type (type only — no codes or negation), -m comment --comment,
// and -j ACCEPT/DROP/REJECT (an unconditional trailing RETURN is a no-op).
// Returns the merged state, the number of rules added or updated, and
// warnings for skipped non-semantic content.
//
// Policies are global in the model and bfw compiles one family-inet
// table, so per-family policy divergence is emulated exactly: the global
// policy takes the stricter value and each laxer family gets an
// unconditional catchall appended at the end of its rule list (the same
// position iptables applies a chain policy). Only explicit policy
// declarations are authoritative: a builtin chain absent from a provided
// table, declared "-" (iptables-save output for an unmodified chain), or
// in a family whose stream is nil keeps st's effective policy via such a
// catchall when a stricter imported policy would otherwise govern it —
// nothing is widened or narrowed for the undeclared side.
func ImportIPTables(v4, v6 io.Reader, st *store.State) (*store.State, int, []string, error) {
	if st == nil {
		return nil, 0, nil, errors.New("impexp: nil state")
	}
	if v4 == nil && v6 == nil {
		return nil, 0, nil, errors.New("impexp: no iptables input (both readers nil)")
	}
	var warnings []string

	var res4, res6 *iptParsed
	if v4 != nil {
		p, err := iptImportStream(v4, false)
		if err != nil {
			return nil, 0, warnings, err
		}
		res4 = p
		warnings = append(warnings, res4.warnings...)
	}
	if v6 != nil {
		p, err := iptImportStream(v6, true)
		if err != nil {
			return nil, 0, warnings, err
		}
		res6 = p
		warnings = append(warnings, res6.warnings...)
	}

	empty := func(res *iptParsed) bool {
		return res == nil || (len(res.rules) == 0 && len(res.policies) == 0)
	}
	if empty(res4) && empty(res6) {
		return nil, 0, warnings, errors.New("impexp: no filter-table rules or policies found in iptables-save input")
	}

	out := iptCloneState(st)
	added := 0
	if res4 != nil {
		added += mergeRules(&out.Rules4, res4.rules)
	}
	if res6 != nil {
		// Identical tuples in both dumps become dual-family rules sharing
		// one ID (same convention as ImportUFW).
		var v4byKey map[string]string
		if res4 != nil {
			v4byKey = make(map[string]string, len(res4.rules))
			for i := range res4.rules {
				v4byKey[res4.rules[i].TupleKey()] = res4.rules[i].ID
			}
		}
		for i := range res6.rules {
			res6.rules[i].SetV6(false)
			key := res6.rules[i].TupleKey()
			res6.rules[i].SetV6(true)
			if id, ok := v4byKey[key]; ok {
				res6.rules[i].ID = id
			}
		}
		added += mergeRules(&out.Rules6, res6.rules)
		out.IPv6 = true
	}

	// Per-family chain policies onto one global policy + per-family
	// catchall rules. The model compiles one inet table, so the global
	// policy must be a value both families reduce to; take the stricter
	// (deny > reject > allow) and append an unconditional catchall at the
	// end of the laxer family's builtin list — the position where iptables
	// applies the chain policy. A family that stays enabled but was not
	// provided keeps st's effective policy via such a catchall, so the
	// import never widens or narrows the missing side.
	v6Enabled := out.IPv6
	var pol4, pol6 map[string]string
	cov4 := res4 != nil && res4.hasFilter
	cov6 := res6 != nil && res6.hasFilter
	if res4 != nil {
		pol4 = res4.policies
	}
	if res6 != nil {
		pol6 = res6.policies
	}
	if cov6 && !v6Enabled {
		warnings = append(warnings,
			"IPv6 filter policies are ignored: state disables IPv6 (IPV6=no); rules are still imported")
	}
	for _, ch := range []struct {
		name string
		dst  *string
	}{
		{"INPUT", &out.Policies.Input},
		{"OUTPUT", &out.Policies.Output},
		{"FORWARD", &out.Policies.Forward},
	} {
		// Effective policy per enabled family: the declared one where a
		// provided stream sets it, st's current value otherwise. (A covered
		// family that left the chain undeclared/"-" preserves status quo
		// exactly like an unprovided one.)
		p4, ok4 := pol4[ch.name]
		p6, ok6 := pol6[ch.name]
		eff4 := iptEffPol(*ch.dst)
		if cov4 && ok4 {
			eff4 = p4
		}
		eff6 := ""
		if v6Enabled {
			eff6 = iptEffPol(*ch.dst)
			if cov6 && ok6 {
				eff6 = p6
			}
		}
		base := eff4
		if eff6 != "" && iptPolicyRank(eff6) > iptPolicyRank(base) {
			base = eff6
		}
		if eff4 != base {
			if iptAppendPolicyCatchall(&out.Rules4, false, ch.name, eff4) {
				added++
				warnings = append(warnings, fmt.Sprintf(
					"IPv4 %s policy %s differs from global %s; installed a trailing %s catchall rule", ch.name, eff4, base, eff4))
			}
		}
		if eff6 != "" && eff6 != base {
			if iptAppendPolicyCatchall(&out.Rules6, true, ch.name, eff6) {
				added++
				warnings = append(warnings, fmt.Sprintf(
					"IPv6 %s policy %s differs from global %s; installed a trailing %s catchall rule", ch.name, eff6, base, eff6))
			}
		}
		*ch.dst = base
	}
	return out, added, warnings, nil
}

// ---- save-file structure --------------------------------------------------

type iptChain struct {
	policy   string // ACCEPT|DROP|REJECT, "-" (unspecified), or "" (implicit)
	declared bool   // created by a ":" declaration, not implicitly by -A/-I
	rules    []iptRuleRef
}

type iptRuleRef struct {
	spec []string // tokens after "-A CHAIN" / "-I CHAIN [pos]"
	line int
}

type iptTable struct {
	name   string
	chains map[string]*iptChain
	order  []string
}

func (t *iptTable) chain(name string) *iptChain {
	if c, ok := t.chains[name]; ok {
		return c
	}
	c := &iptChain{}
	t.chains[name] = c
	t.order = append(t.order, name)
	return c
}

type iptSaveFile struct {
	tables []*iptTable
	byName map[string]*iptTable
}

// iptErrs accumulates per-rule errors so one bad rule does not hide the
// rest; the import still fails atomically.
type iptErrs []error

func (e *iptErrs) add(format string, args ...any) {
	if len(*e) < 20 {
		*e = append(*e, fmt.Errorf(format, args...))
	}
}

func (e iptErrs) err() error {
	return errors.Join(e...)
}

// iptParseSave parses the structural skeleton of one dump: *table,
// :chain policy [counters], -A/-I rules, COMMIT. Everything else is an
// unsupported restore directive and fails the import.
func iptParseSave(r io.Reader) (*iptSaveFile, error) {
	f := &iptSaveFile{byName: map[string]*iptTable{}}
	var cur *iptTable
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	ln := 0
	for sc.Scan() {
		ln++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case strings.HasPrefix(line, "*"):
			if cur != nil {
				return nil, fmt.Errorf("line %d: table %q opened before COMMIT of table %q", ln, line[1:], cur.name)
			}
			name := strings.TrimSpace(line[1:])
			if name == "" || strings.ContainsAny(name, " \t") {
				return nil, fmt.Errorf("line %d: malformed table declaration %q", ln, line)
			}
			if _, dup := f.byName[name]; dup {
				return nil, fmt.Errorf("line %d: duplicate table %q", ln, name)
			}
			cur = &iptTable{name: name, chains: map[string]*iptChain{}}
			f.tables = append(f.tables, cur)
			f.byName[name] = cur
		case strings.HasPrefix(line, ":"):
			if cur == nil {
				return nil, fmt.Errorf("line %d: chain declaration outside a table", ln)
			}
			fields := strings.Fields(line[1:])
			if len(fields) < 2 {
				return nil, fmt.Errorf("line %d: malformed chain declaration %q", ln, line)
			}
			if len(fields) > 2 && !iptCounterTok(fields[2]) {
				return nil, fmt.Errorf("line %d: malformed chain counters %q", ln, fields[2])
			}
			c := cur.chain(fields[0])
			if c.declared {
				return nil, fmt.Errorf("line %d: duplicate chain declaration %q", ln, fields[0])
			}
			c.declared = true
			c.policy = fields[1]
		case strings.HasPrefix(line, "-"):
			if cur == nil {
				return nil, fmt.Errorf("line %d: rule outside a table", ln)
			}
			toks, err := iptFields(line)
			if err != nil {
				return nil, fmt.Errorf("line %d: %v", ln, err)
			}
			if len(toks) < 2 {
				return nil, fmt.Errorf("line %d: %s requires a chain name", ln, toks[0])
			}
			insert := false
			switch toks[0] {
			case "-A", "--append":
			case "-I", "--insert":
				insert = true
			default:
				return nil, fmt.Errorf("line %d: unsupported iptables-restore directive %q", ln, toks[0])
			}
			spec := toks[2:]
			c := cur.chain(toks[1])
			pos := len(c.rules) + 1 // -A appends (1-based slot past the end)
			if insert {
				// -I CHAIN [rulenum] spec — rulenum defaults to 1.
				pos = 1
				if len(spec) > 0 {
					if n, e := strconv.Atoi(spec[0]); e == nil {
						pos = n
						spec = spec[1:]
					}
				}
				if pos <= 0 || pos > len(c.rules)+1 {
					return nil, fmt.Errorf("line %d: insert position %d out of range for chain %s", ln, pos, toks[1])
				}
			}
			c.rules = append(c.rules, iptRuleRef{})
			copy(c.rules[pos:], c.rules[pos-1:])
			c.rules[pos-1] = iptRuleRef{spec: spec, line: ln}
		case line == "COMMIT":
			if cur == nil {
				return nil, fmt.Errorf("line %d: COMMIT outside a table", ln)
			}
			cur = nil
		default:
			return nil, fmt.Errorf("line %d: unsupported iptables-restore directive %q", ln, line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if cur != nil {
		return nil, fmt.Errorf("table %q not closed by COMMIT", cur.name)
	}
	return f, nil
}

// iptFields splits a rule line on whitespace, honoring double and single
// quotes and backslash escapes (iptables-save quotes arguments containing
// spaces, e.g. --comment "two words").
func iptFields(s string) ([]string, error) {
	var out []string
	var b strings.Builder
	var quote byte // 0 = outside, '"' or '\'' inside
	esc := false
	inTok := false
	flush := func() {
		out = append(out, b.String())
		b.Reset()
		inTok = false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case esc:
			b.WriteByte(c)
			esc = false
		case c == '\\' && quote != '\'':
			esc = true
			inTok = true
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				b.WriteByte(c)
			}
		case c == '"' || c == '\'':
			quote = c
			inTok = true
		case c == ' ' || c == '\t':
			if inTok {
				flush()
			}
		default:
			b.WriteByte(c)
			inTok = true
		}
	}
	if esc {
		b.WriteByte('\\') // trailing backslash is literal
	}
	if quote != 0 {
		return nil, errors.New("unterminated quote")
	}
	if inTok {
		flush()
	}
	return out, nil
}

// iptCounterTok reports whether s looks like a "[pkts:bytes]" chain
// counter field.
func iptCounterTok(s string) bool {
	if len(s) < 5 || s[0] != '[' || s[len(s)-1] != ']' {
		return false
	}
	a, b, ok := strings.Cut(s[1:len(s)-1], ":")
	if !ok {
		return false
	}
	_, ea := strconv.ParseUint(a, 10, 64)
	_, eb := strconv.ParseUint(b, 10, 64)
	return ea == nil && eb == nil
}

// ---- semantic conversion --------------------------------------------------

type iptParsed struct {
	rules     []rule.Rule
	policies  map[string]string // INPUT|OUTPUT|FORWARD -> allow|deny|reject
	hasFilter bool              // the dump declared a *filter table
	warnings  []string
}

var iptBuiltinDir = map[string]string{
	"INPUT":   rule.DirIn,
	"OUTPUT":  rule.DirOut,
	"FORWARD": rule.DirRouted,
}

// iptImportStream parses one save stream into model rules and policies.
// v6 marks the parsed rules as belonging to the IPv6 family.
func iptImportStream(r io.Reader, v6 bool) (*iptParsed, error) {
	label := "IPv4"
	if v6 {
		label = "IPv6"
	}
	f, err := iptParseSave(r)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	res := &iptParsed{policies: map[string]string{}}
	var errs iptErrs
	var filt *iptTable
	for _, t := range f.tables {
		if t.name == "filter" {
			filt = t
			continue
		}
		// A non-filter table is harmless only when empty: no rules, and
		// every builtin policy ACCEPT or unspecified.
		bad := false
		for _, name := range t.order {
			c := t.chains[name]
			if len(c.rules) > 0 ||
				(iptBuiltinChain(t.name, name) && c.policy != "" && c.policy != "-" && c.policy != "ACCEPT") {
				bad = true
				break
			}
		}
		if bad {
			errs.add("%s: table %s carries rules or non-ACCEPT policies, which are not representable (nat/mangle/raw/security are not imported)", label, t.name)
		}
	}
	if filt == nil {
		return res, errs.err()
	}
	res.hasFilter = true

	// Reachability from builtins: jumps to user chains are unsupported, so
	// any referenced chain aborts via the jump-site error in iptParseSpec.
	// Chains unreachable from INPUT/OUTPUT/FORWARD never ran in the source
	// either — they are dropped with a warning, not an error.
	reachable := map[string]bool{}
	queue := []string{"INPUT", "OUTPUT", "FORWARD"}
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		if reachable[name] {
			continue
		}
		reachable[name] = true
		c := filt.chains[name]
		if c == nil {
			continue
		}
		for _, rr := range c.rules {
			if tgt := iptJumpTarget(rr.spec); tgt != "" {
				if _, builtin := iptBuiltinDir[tgt]; !builtin && filt.chains[tgt] != nil {
					queue = append(queue, tgt)
				}
			}
		}
	}
	for _, name := range filt.order {
		if _, builtin := iptBuiltinDir[name]; builtin {
			continue
		}
		if !reachable[name] {
			res.warnings = append(res.warnings, fmt.Sprintf(
				"%s: chain %s unreachable from INPUT/OUTPUT/FORWARD; dropped %d rules",
				label, name, len(filt.chains[name].rules)))
		}
	}

	// Emit builtin rules in the dump's chain declaration order; within a
	// chain, rule order is preserved. Chains absent from the dump keep st's
	// rules and policy.
	for _, name := range filt.order {
		if _, builtin := iptBuiltinDir[name]; !builtin {
			continue
		}
		c := filt.chains[name]
		switch c.policy {
		case "", "-": // unspecified: keep the existing state policy
		case "ACCEPT":
			res.policies[name] = "allow"
		case "DROP":
			res.policies[name] = "deny"
		case "REJECT":
			res.policies[name] = "reject"
		default:
			errs.add("%s: bad policy %q on chain %s", label, c.policy, name)
		}
		truncated := false
		emitted := 0
		for i, rr := range c.rules {
			if truncated {
				continue
			}
			r, ret, warn, err := iptParseSpec(name, rr.spec, filt, v6, emitted == 0)
			if err != nil {
				errs.add("%s: line %d: %v", label, rr.line, err)
				continue
			}
			if ret {
				// Unconditional RETURN. Only meaningful as the last rule;
				// anything after it is dead in the source too — drop it
				// with one warning.
				if i+1 < len(c.rules) {
					res.warnings = append(res.warnings, fmt.Sprintf(
						"%s: chain %s: dropped %d unreachable rules after unconditional RETURN",
						label, name, len(c.rules)-i-1))
					truncated = true
				}
				continue
			}
			if warn != "" {
				res.warnings = append(res.warnings, fmt.Sprintf("%s: line %d: %s", label, rr.line, warn))
			}
			if r != nil {
				r.SetV6(v6)
				res.rules = append(res.rules, *r)
				emitted++
			}
		}
	}
	if err := errs.err(); err != nil {
		return nil, err
	}
	// Only explicit policy declarations are recorded; a chain absent (or
	// declared "-") keeps st's effective policy — the merge layer
	// preserves it with a catchall when a stricter policy lands.
	return res, nil
}

// iptBuiltinChain reports whether name is a builtin chain of the given
// table (used to decide whether a non-filter table is empty).
func iptBuiltinChain(table, name string) bool {
	switch name {
	case "INPUT", "OUTPUT", "FORWARD":
		return table == "filter" || table == "mangle"
	case "PREROUTING", "POSTROUTING":
		return table == "nat" || table == "mangle" || table == "raw" || table == "security"
	}
	return false
}

// iptJumpTarget returns the argument of a -j/--jump/-g/--goto token, or ""
// when the spec has none. Best-effort scan used only for reachability.
func iptJumpTarget(spec []string) string {
	for i, tok := range spec {
		if (tok == "-j" || tok == "--jump" || tok == "-g" || tok == "--goto") && i+1 < len(spec) {
			return spec[i+1]
		}
	}
	return ""
}

// iptParseSpec converts one -A/-I rule body into a rule.Rule. It returns
// (nil, true, "", nil) for an unconditional RETURN (a chain-terminating
// no-op the caller handles), (nil, false, warning, nil) for representable
// no-ops like accounting-only rules and the redundant established/related
// accept bfw already emits, and an error for anything unrepresentable.
// first reports whether no rule has been emitted for this chain yet —
// the conntrack preamble idiom is only redundant in that position.
func iptParseSpec(chainName string, spec []string, t *iptTable, v6, first bool) (r *rule.Rule, ret bool, warning string, err error) {
	r = &rule.Rule{ID: rule.NewID(), Proto: "any"}
	r.Direction = iptBuiltinDir[chainName]
	var sport, dport []iptPortSpan
	var rejectWith, target string
	var sportSet, dportSet, sSet, dSet, commentSet, jSet, matched bool
	var pSet, iSet, oSet bool
	var modProto string          // "tcp"|"udp"|"icmp"|"icmpv6" set by the protocol modules
	var icmpTok string           // --icmp-type/--icmpv6-type token (canonicalized at end)
	var icmpV6 bool              // true when icmpTok came from the v6 flag
	var ctSeen, ctOK, ctMod bool // -m conntrack/-m state seen; RELATED,ESTABLISHED value ok

	take := func(i *int) (string, error) {
		if *i+1 >= len(spec) {
			return "", fmt.Errorf("option %s requires an argument", spec[*i])
		}
		*i++
		a := spec[*i]
		if a == "!" || strings.HasPrefix(a, "!") {
			return "", fmt.Errorf("negated argument %q for %s is not representable", a, spec[*i-1])
		}
		return a, nil
	}

	for i := 0; i < len(spec); i++ {
		tok := spec[i]
		switch tok {
		case "!":
			return nil, false, "", errors.New("negation (!) is not representable in the rule model")
		case "-p", "--protocol":
			if pSet {
				return nil, false, "", errors.New("duplicate -p")
			}
			pSet, matched = true, true
			a, e := take(&i)
			if e != nil {
				return nil, false, "", e
			}
			p, e := iptProto(a)
			if e != nil {
				return nil, false, "", e
			}
			r.Proto = p
		case "-s", "--source":
			if sSet {
				return nil, false, "", errors.New("duplicate -s")
			}
			sSet, matched = true, true
			a, e := take(&i)
			if e != nil {
				return nil, false, "", e
			}
			ip, e := iptAddr(a, v6)
			if e != nil {
				return nil, false, "", e
			}
			r.Src.IP = ip
		case "-d", "--destination":
			if dSet {
				return nil, false, "", errors.New("duplicate -d")
			}
			dSet, matched = true, true
			a, e := take(&i)
			if e != nil {
				return nil, false, "", e
			}
			ip, e := iptAddr(a, v6)
			if e != nil {
				return nil, false, "", e
			}
			r.Dst.IP = ip
		case "-i", "--in-interface":
			if iSet {
				return nil, false, "", errors.New("duplicate -i")
			}
			iSet, matched = true, true
			a, e := take(&i)
			if e != nil {
				return nil, false, "", e
			}
			r.IfaceIn = iptIface(a)
		case "-o", "--out-interface":
			if oSet {
				return nil, false, "", errors.New("duplicate -o")
			}
			oSet, matched = true, true
			a, e := take(&i)
			if e != nil {
				return nil, false, "", e
			}
			r.IfaceOut = iptIface(a)
		case "--sport", "--source-port":
			a, e := take(&i)
			if e != nil {
				return nil, false, "", e
			}
			if sportSet {
				return nil, false, "", errors.New("multiple source-port options are not representable (iptables conjoins them; the model unions)")
			}
			sportSet, matched = true, true
			sport, e = iptPortList(a, false)
			if e != nil {
				return nil, false, "", e
			}
		case "--dport", "--destination-port":
			a, e := take(&i)
			if e != nil {
				return nil, false, "", e
			}
			if dportSet {
				return nil, false, "", errors.New("multiple destination-port options are not representable (iptables conjoins them; the model unions)")
			}
			dportSet, matched = true, true
			dport, e = iptPortList(a, false)
			if e != nil {
				return nil, false, "", e
			}
		case "--sports", "--source-ports":
			a, e := take(&i)
			if e != nil {
				return nil, false, "", e
			}
			if sportSet {
				return nil, false, "", errors.New("multiple source-port options are not representable (iptables conjoins them; the model unions)")
			}
			sportSet, matched = true, true
			sport, e = iptPortList(a, true)
			if e != nil {
				return nil, false, "", e
			}
		case "--dports", "--destination-ports":
			a, e := take(&i)
			if e != nil {
				return nil, false, "", e
			}
			if dportSet {
				return nil, false, "", errors.New("multiple destination-port options are not representable (iptables conjoins them; the model unions)")
			}
			dportSet, matched = true, true
			dport, e = iptPortList(a, true)
			if e != nil {
				return nil, false, "", e
			}
		case "--ports":
			// multiport --ports matches when EITHER port matches; the
			// model conjoins Src.Ports and Dst.Ports, so it cannot be
			// represented faithfully.
			return nil, false, "", errors.New("multiport --ports is not representable (it ORs source and destination ports; the model conjoins them)")
		case "-m", "--match":
			a, e := take(&i)
			if e != nil {
				return nil, false, "", e
			}
			module := strings.ToLower(a)
			if module == "icmp6" {
				module = "icmpv6"
			}
			switch module {
			case "tcp", "udp", "icmp", "icmpv6":
				// Protocol modules require and are checked against an
				// explicit -p declaration after parsing the complete rule.
				if modProto != "" && modProto != module {
					return nil, false, "", fmt.Errorf("conflicting match modules -m %s and -m %s", modProto, module)
				}
				if modProto == module {
					return nil, false, "", fmt.Errorf("duplicate -m %s", module)
				}
				modProto = module
			case "conntrack", "state":
				if ctMod {
					return nil, false, "", fmt.Errorf("duplicate -m %s", a)
				}
				ctMod = true
			case "comment", "multiport":
				// Non-protocol modules: allowed; their representable
				// options are the flags handled here.
			default:
				return nil, false, "", fmt.Errorf("match module %q is not representable (limit, mark, set, addrtype and others are unsupported)", a)
			}
		case "--ctstate", "--state":
			if ctSeen {
				return nil, false, "", errors.New("duplicate --ctstate/--state")
			}
			ctSeen = true
			a, e := take(&i)
			if e != nil {
				return nil, false, "", e
			}
			// The only representable value is the related+established
			// accept bfw emits unconditionally — checked at the end.
			ctOK = iptCtEstRel(a)
		case "--icmp-type", "--icmpv6-type", "--icmp6-type":
			if icmpTok != "" {
				return nil, false, "", fmt.Errorf("duplicate %s", tok)
			}
			icmpV6 = tok != "--icmp-type"
			a, e := take(&i)
			if e != nil {
				return nil, false, "", e
			}
			if strings.Contains(a, "/") {
				return nil, false, "", fmt.Errorf("%s with a code qualifier (%q) is not representable", tok, a)
			}
			icmpTok = a
			matched = true
		case "--comment":
			if commentSet {
				return nil, false, "", errors.New("duplicate --comment")
			}
			commentSet = true
			a, e := take(&i)
			if e != nil {
				return nil, false, "", e
			}
			r.Comment = a
		case "-j", "--jump":
			if jSet {
				return nil, false, "", errors.New("duplicate -j")
			}
			jSet = true
			a, e := take(&i)
			if e != nil {
				return nil, false, "", e
			}
			// Anything past a verdict is a target-extension flag we don't
			// model; reject non-verdict targets up front so their flags
			// can't slip through as "unsupported option" noise.
			switch a {
			case "ACCEPT", "DROP", "REJECT", "RETURN":
				target = a
			case "LOG", "NFLOG", "ULOG":
				return nil, false, "", fmt.Errorf("target %s is not representable (log-and-continue; the model logs only attached to a verdict)", a)
			default:
				if _, builtin := iptBuiltinDir[a]; builtin {
					return nil, false, "", fmt.Errorf("jump to builtin chain %s is not representable", a)
				}
				if t.chains[a] != nil {
					return nil, false, "", fmt.Errorf("jump to user chain %q is not representable (the rule model has no user chains)", a)
				}
				return nil, false, "", fmt.Errorf("target %q is not representable (only ACCEPT, DROP, REJECT are)", a)
			}
		case "-g", "--goto":
			return nil, false, "", errors.New("goto is not representable (the rule model has no user chains)")
		case "-c", "--set-counters":
			// Packet/byte counters from iptables-save -c: non-semantic.
			if i+2 >= len(spec) {
				return nil, false, "", errors.New("option -c requires two arguments")
			}
			i += 2
		case "-n", "-x", "-v", "--exact", "--numeric", "--verbose", "--line-numbers":
			// Restore-time no-ops.
		case "--reject-with":
			a, e := take(&i)
			if e != nil {
				return nil, false, "", e
			}
			rejectWith = a
		default:
			if strings.HasPrefix(tok, "-") {
				return nil, false, "", fmt.Errorf("unsupported option %q (not representable in the rule model)", tok)
			}
			return nil, false, "", fmt.Errorf("unexpected argument %q", tok)
		}
	}

	// Protocol-specific match modules require the matching explicit -p
	// protocol in iptables-save; module names alone are not a protocol
	// predicate in the rule model.
	if modProto != "" && !pSet {
		return nil, false, "", fmt.Errorf("-m %s requires -p %s", modProto, modProto)
	}
	if modProto != "" && r.Proto != modProto {
		return nil, false, "", fmt.Errorf("-m %s contradicts -p %s", modProto, r.Proto)
	}
	// ICMP type flags require the corresponding explicit protocol. Codes
	// were rejected above because Rule stores only a type.
	if icmpTok != "" {
		want, flag := "icmp", "--icmp-type"
		if icmpV6 {
			want, flag = "icmpv6", "--icmpv6-type"
		}
		if !pSet {
			return nil, false, "", fmt.Errorf("%s requires -p %s", flag, want)
		}
		if r.Proto != want {
			return nil, false, "", fmt.Errorf("%s requires -p %s, got %q", flag, want, r.Proto)
		}
		num, e := rule.ICMPTypeNumber(want, icmpTok)
		if e != nil {
			return nil, false, "", fmt.Errorf("%s %q: %v", flag, icmpTok, e)
		}
		r.ICMPType = num
	}
	// Port options require an explicit -p tcp or -p udp. A `-m tcp`/`-m
	// udp` extension is valid only alongside that protocol and cannot
	// safely be inferred as a substitute in a save file.
	if len(sport) > 0 || len(dport) > 0 {
		if !pSet || (r.Proto != "tcp" && r.Proto != "udp") {
			return nil, false, "", fmt.Errorf("port match requires -p tcp or -p udp, got proto %q", r.Proto)
		}
	}
	for _, p := range sport {
		r.Src.Ports = append(r.Src.Ports, rule.PortRange{Lo: p.lo, Hi: p.hi, Proto: r.Proto})
	}
	for _, p := range dport {
		r.Dst.Ports = append(r.Dst.Ports, rule.PortRange{Lo: p.lo, Hi: p.hi, Proto: r.Proto})
	}

	// -m conntrack/-m state: only the ubiquitous preamble
	//   -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
	// is representable — bfw emits exactly that accept unconditionally at
	// the head of every builtin chain. The rule must be the first emitted
	// one in its chain: a preceding match would reorder the fast path.
	if ctSeen {
		switch {
		case !ctMod:
			return nil, false, "", errors.New("--ctstate/--state requires -m conntrack or -m state")
		case ctOK && target == "ACCEPT" && !matched:
			if !first {
				return nil, false, "", errors.New("established/related accept is not representable mid-chain (bfw always emits it first)")
			}
			return nil, false, "redundant established/related accept; bfw emits it unconditionally", nil
		default:
			return nil, false, "", errors.New("conntrack/state matching is not representable (only the unconditional RELATED,ESTABLISHED accept preamble is)")
		}
	}

	if rejectWith != "" && target != "REJECT" {
		return nil, false, "", errors.New("--reject-with requires -j REJECT")
	}
	switch target {
	case "":
		// Accounting-only rule: matches plus counters, no verdict.
		return nil, false, "accounting-only rule (no -j target); skipped", nil
	case "ACCEPT":
		r.Action = rule.ActionAllow
	case "DROP":
		r.Action = rule.ActionDeny
	case "REJECT":
		switch strings.ToLower(rejectWith) {
		case "", "icmp-port-unreachable", "icmp6-port-unreachable", "port-unreachable":
		default:
			return nil, false, "", fmt.Errorf("--reject-with %q is not representable (only port-unreachable is)", rejectWith)
		}
		r.Action = rule.ActionReject
	case "RETURN":
		if matched {
			return nil, false, "", errors.New("conditional RETURN is not representable (the rule model has no early-exit)")
		}
		return nil, true, "", nil
	}

	r.Normalize()
	// Canonicalize wildcards like the ufw importer so identical v4/v6
	// tuples merge into dual rules.
	if r.Src.IP == "0.0.0.0/0" || r.Src.IP == "::/0" {
		r.Src.IP = "any"
	}
	if r.Dst.IP == "0.0.0.0/0" || r.Dst.IP == "::/0" {
		r.Dst.IP = "any"
	}
	return r, false, "", nil
}

type iptPortSpan struct{ lo, hi uint16 }

// iptPortList parses a port spec: a single port, a lo:hi range (open ends
// allowed: :80, 1000:), or — only when multi is true — a comma-separated
// list of those (multiport --dports/--sports/--ports).
func iptPortList(s string, multi bool) ([]iptPortSpan, error) {
	if s == "" {
		return nil, errors.New("empty port spec")
	}
	items := []string{s}
	if multi {
		items = strings.Split(s, ",")
	} else if strings.Contains(s, ",") {
		return nil, fmt.Errorf("port list %q requires -m multiport (--dports/--sports/--ports)", s)
	}
	var out []iptPortSpan
	for _, item := range items {
		if item == "" {
			return nil, fmt.Errorf("empty port in %q", s)
		}
		lo, hi, err := iptPortRange(item)
		if err != nil {
			return nil, err
		}
		out = append(out, iptPortSpan{lo, hi})
	}
	return out, nil
}

func iptPortRange(item string) (uint16, uint16, error) {
	lo, hi, found := strings.Cut(item, ":")
	if !found {
		p, err := iptPort(item)
		return p, p, err
	}
	l, h := uint16(0), uint16(65535)
	if lo != "" {
		p, err := iptPort(lo)
		if err != nil {
			return 0, 0, err
		}
		l = p
	}
	if hi != "" {
		p, err := iptPort(hi)
		if err != nil {
			return 0, 0, err
		}
		h = p
	}
	if h < l {
		return 0, 0, fmt.Errorf("inverted port range %q", item)
	}
	return l, h, nil
}

func iptPort(s string) (uint16, error) {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("unsupported port %q (service names are not resolved; use numbers)", s)
	}
	return uint16(n), nil
}

// iptAddr validates and canonicalizes an address token for the family
// (v6 is the stream family). The caller already rejected negation.
func iptAddr(s string, v6 bool) (string, error) {
	if s == "" {
		return "", errors.New("empty address")
	}
	if s == "any" || s == "all" {
		return "any", nil
	}
	if strings.HasPrefix(s, "+") || strings.HasPrefix(s, "!") {
		return "", fmt.Errorf("address %q is not representable", s)
	}
	var ip net.IP
	var ipnet *net.IPNet
	if strings.Contains(s, "/") {
		p, n, err := net.ParseCIDR(s)
		if err != nil {
			// iptables also accepts a dotted netmask (1.2.3.0/255.255.255.0).
			addr, mask, ok := strings.Cut(s, "/")
			p = net.ParseIP(addr)
			m := net.ParseIP(mask)
			if !ok || p == nil || m == nil || p.To4() == nil || m.To4() == nil {
				return "", fmt.Errorf("bad address %q", s)
			}
			m4 := m.To4() // Size() needs the 4-byte form; a 16-byte mapped mask reports non-contiguous
			ones, bits := net.IPMask(m4).Size()
			if bits == 0 {
				return "", fmt.Errorf("non-contiguous netmask in %q", s)
			}
			n = &net.IPNet{IP: p.To4().Mask(net.IPMask(m4)), Mask: net.CIDRMask(ones, bits)}
			if n.IP == nil {
				return "", fmt.Errorf("bad address %q", s)
			}
		}
		ip, ipnet = p, n

	} else {
		ip = net.ParseIP(s)
		if ip == nil {
			return "", fmt.Errorf("bad address %q", s)
		}
	}
	if (ip.To4() == nil) != v6 {
		fam := "IPv4"
		if v6 {
			fam = "IPv6"
		}
		return "", fmt.Errorf("address %q is not %s", s, fam)
	}
	if ipnet != nil {
		return ipnet.String(), nil
	}
	return ip.String(), nil
}

// iptProto maps an iptables -p argument onto a model protocol. Names not
// in the model (sctp, dccp, udplite, ...) are rejected rather than
// broadened to "any". Numeric 0 is rejected: iptables-save serializes
// wildcards as "all", so -p 0 means protocol number 0 (HOPOPT), which
// the model cannot express.
func iptProto(s string) (string, error) {
	v := strings.ToLower(s)
	if v == "all" {
		return "any", nil
	}
	switch v {
	case "tcp", "udp", "ah", "esp", "gre", "vrrp", "igmp", "icmp", "ipv6":
		return v, nil
	case "ipv6-icmp", "icmp6", "icmpv6":
		return "icmpv6", nil
	}
	if n, err := strconv.Atoi(v); err == nil {
		switch n {
		case 1:
			return "icmp", nil
		case 2:
			return "igmp", nil
		case 6:
			return "tcp", nil
		case 17:
			return "udp", nil
		case 41:
			return "ipv6", nil
		case 47:
			return "gre", nil
		case 50:
			return "esp", nil
		case 51:
			return "ah", nil
		case 58:
			return "icmpv6", nil
		case 112:
			return "vrrp", nil
		}
		return "", fmt.Errorf("protocol number %d is not representable", n)
	}
	return "", fmt.Errorf("protocol %q is not representable", s)
}

func iptIface(s string) string {
	if s == "+" {
		return "" // bare "+" is iptables' any-interface wildcard
	}
	return s
}

// iptCloneState deep-copies st so parse/merge failures leave the input
// untouched.
func iptCloneState(st *store.State) *store.State {
	out := *st
	out.Rules4 = iptCloneRules(st.Rules4)
	out.Rules6 = iptCloneRules(st.Rules6)
	if st.Sets != nil {
		out.Sets = make([]store.IPSet, len(st.Sets))
		for i, s := range st.Sets {
			out.Sets[i] = s
			out.Sets[i].Elements = append([]string(nil), s.Elements...)
		}
	}
	if st.NAT != nil {
		out.NAT = append([]store.NATRule(nil), st.NAT...)
	}
	return &out
}

func iptCloneRules(rs []rule.Rule) []rule.Rule {
	out := make([]rule.Rule, len(rs))
	for i := range rs {
		out[i] = *rs[i].Clone()
	}
	return out
}

// iptPolicyRank orders policies by strictness: deny > reject > allow.
// The stricter value is the safe global baseline; the laxer family gets
// a catchall rule preserving its own policy.
func iptPolicyRank(p string) int {
	switch p {
	case "deny":
		return 3
	case "reject":
		return 2
	default:
		return 1
	}
}

// iptEffPol normalizes a stored policy word ("" or unknown values mean
// "not allow" for ranking — the compiler maps anything but allow to a
// drop chain policy).
func iptEffPol(p string) string {
	switch p {
	case "allow", "deny", "reject":
		return p
	default:
		return "deny"
	}
}

// iptAppendPolicyCatchall appends an unconditional <action> rule for
// direction dir to the family list, emulating a per-family chain policy
// that differs from the global baseline. Returns false (no append) when
// the last rule for that direction already is an identical catchall —
// keeps re-imports idempotent.
func iptAppendPolicyCatchall(rules *[]rule.Rule, v6 bool, chain, policy string) bool {
	dir := iptBuiltinDir[chain]
	action := map[string]string{
		"allow":  rule.ActionAllow,
		"deny":   rule.ActionDeny,
		"reject": rule.ActionReject,
	}[policy]
	nr := rule.Rule{
		Action:    action,
		Direction: dir,
		Proto:     "any",
		Comment:   "iptables-persistent " + chain + " chain policy " + policy,
	}
	nr.Src.IP, nr.Dst.IP = "any", "any"
	nr.SetV6(v6)
	// Dedup against the last rule for this direction only — a catchall
	// anywhere earlier would not be in policy position anyway.
	for i := len(*rules) - 1; i >= 0; i-- {
		if (*rules)[i].Direction != dir {
			continue
		}
		if (*rules)[i].Match(&nr) == rule.MatchExact {
			return false
		}
		break
	}
	nr.ID = rule.NewID()
	*rules = append(*rules, nr)
	return true
}

// iptCtEstRel reports whether a --ctstate/--state value is exactly
// RELATED,ESTABLISHED (either order, case-insensitive) — the accept bfw
// emits unconditionally in every builtin chain.
func iptCtEstRel(s string) bool {
	var seen [2]bool
	for _, part := range strings.Split(s, ",") {
		switch strings.ToLower(strings.TrimSpace(part)) {
		case "established":
			seen[0] = true
		case "related":
			seen[1] = true
		default:
			return false
		}
	}
	return seen[0] && seen[1]
}
