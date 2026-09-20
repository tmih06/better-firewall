// Rule mutation commands: allow|deny|reject|limit plus the delete,
// insert NUM and prepend prefixes. The engine replicates ufw 0.36.2
// frontend.py::set_rule + backend_iptables.py::set_rule: per-family
// processing, match() dedup, app-group expansion, position mapping and
// the exact result strings.
package cli

import (
	"errors"
	"strconv"
	"os"
	"strings"
	"time"

	"bfirewall/internal/appprof"
	"bfirewall/internal/rule"
	"bfirewall/internal/store"
)

// ruleOutcome mirrors the result of one backend.set_rule call.
type ruleOutcome int

const (
	outAdded ruleOutcome = iota
	outDeleted
	outUpdated    // replaced in place (action/logtype/comment diff)
	outInserted   // inserted at a position
	outSkipAdd    // exact dup on add
	outSkipInsert // any dup on insert/prepend
	outNotFound   // delete matched nothing
)

// cmdRuleOp handles allow|deny|reject|limit|delete|insert|prepend|route.
func (e *Env) cmdRuleOp(args []string) int {
	if !e.checkRoot() {
		return 1
	}
	op, err := ParseRuleArgs(args)
	if err != nil {
		if errors.Is(err, ErrSyntax) {
			e.Msg("%s", HelpText(e.Prog))
			return 1
		}
		return e.Errorf("%s", err)
	}
	if op == nil {
		e.Msg("%s", HelpText(e.Prog))
		return 1
	}
	if op.Kind == OpDelete && op.Rule == nil {
		return e.deleteByNumber(op.Num)
	}
	return e.runRuleOp(op)
}

// deleteByNumber implements `ufw delete NUM`: deletes only the family
// half at that displayed position.
func (e *Env) deleteByNumber(n int) int {
	st, err := e.Store.Load()
	if err != nil {
		return e.Errorf("%s", err)
	}
	markFamilies(st)
	total := len(st.Rules4) + len(st.Rules6)
	if n <= 0 || n > total {
		return e.Errorf("Could not find rule '%d'", n)
	}
	idx, v6, ok := ruleByNumber(st, n)
	if !ok {
		return e.Errorf("Could not find rule '%d'", n)
	}
	var r *rule.Rule
	if v6 {
		r = &st.Rules6[idx]
	} else {
		r = &st.Rules4[idx]
	}

	if !e.Force {
		if !e.Prompt("Deleting:\n %s\nProceed with operation (y|n)? ", GetCommand(r)) {
			e.Msg("Aborted")
			return 0
		}
	}

	unlock, code := e.acquireLock()
	if code != 0 {
		return code
	}
	defer unlock()

	// App rules: delete every member of the tuple in this family, like
	// ufw's get_app_rules_from_system expansion (frontend.delete_rule).
	if r.Dapp != "" || r.Sapp != "" {
		tupl := r.AppTuple()
		list := st.Rules4
		if v6 {
			list = st.Rules6
		}
		var kept []rule.Rule
		for i := range list {
			if list[i].AppTuple() != tupl {
				kept = append(kept, list[i])
			}
		}
		if v6 {
			st.Rules6 = kept
		} else {
			st.Rules4 = kept
		}
	} else if v6 {
		st.Rules6 = append(st.Rules6[:idx], st.Rules6[idx+1:]...)
	} else {
		st.Rules4 = append(st.Rules4[:idx], st.Rules4[idx+1:]...)
	}
	return e.commitState(st, outcomeString(outDeleted, v6, e.live()))
}

// runRuleOp applies a parsed add/delete/insert/prepend to the state.
func (e *Env) runRuleOp(op *ParsedRuleOp) int {
	st, err := e.Store.Load()
	if err != nil {
		return e.Errorf("%s", err)
	}
	markFamilies(st)

	// App rules expand to one rule per profile port item (ufw stores
	// separate rules per `|` item, sharing the app tuple). Deletes keep
	// the single parsed rule — applyHalf expands it against stored rules.
	// For positional inserts ufw reverses the group so it lands in order.
	rules := []*rule.Rule{op.Rule}
	if op.Kind != OpDelete && (op.Rule.Dapp != "" || op.Rule.Sapp != "") {
		if expanded := expandAppRules(op.Rule); len(expanded) > 0 {
			if op.Kind == OpInsert || op.Kind == OpPrepend {
				for i, j := 0, len(expanded)-1; i < j; i, j = i+1, j-1 {
					expanded[i], expanded[j] = expanded[j], expanded[i]
				}
			}
			rules = expanded
		}
	}

	numV4 := dedupedCount(st.Rules4)
	numV6 := dedupedCount(st.Rules6)

	unlock, code := e.acquireLock()
	if code != 0 {
		return code
	}
	defer unlock()

	var last string
	var warned bool
	for i, nr := range rules {
		count := i
		pos := op.Num
		if op.Kind == OpPrepend {
			pos = -1
		}
		if op.Kind == OpInsert && pos > numV4+numV6 {
			return e.Errorf("Invalid position '%d'", pos)
		}

		if !warned && op.Normalized {
			e.Warnf("Rule changed after normalization")
			warned = true
		}

		var res string
		switch op.IPType {
		case "v4":
			p, err2 := v4Position(pos, count, numV4)
			if err2 != "" {
				return e.Errorf("%s%d'", err2, pos)
			}
			res = e.applyHalf(st, nr, p, false, op.Kind)
		case "v6":
		if !st.IPv6 {
			return e.Errorf("IPv6 support not enabled")
		}
		if !ipv6Available() {
			return e.Errorf("IPv6 support not enabled") // kernel lacks ipv6
		}
			p, err2 := v6Position(pos, count, numV4, numV6)
			if err2 != "" {
				return e.Errorf("%s%d'", err2, pos)
			}
			res = e.applyHalf(st, nr, p, true, op.Kind)
		case "both":
			if st.IPv6 {
				res = e.applyDual(st, nr, pos, count, &numV4, numV6, op.Kind)
			} else {
				p, err2 := v4Position(pos, count, numV4)
				if err2 != "" {
					return e.Errorf("%s%d'", err2, pos)
				}
				res = e.applyHalf(st, nr, p, false, op.Kind)
			}
		default:
			return e.Errorf("Invalid IP version '%s'", op.IPType)
		}
		if res == "" {
			// applyHalf reported an error already.
			return 1
		}
		last = res
	}

	return e.commitState(st, last)
}

// v4Position maps a user position for a v4 rule (frontend.set_rule).
// Returns the backend position (0 append, -1 prepend marker resolved
// here, N insert) or an error prefix.
func v4Position(pos, count, numV4 int) (int, string) {
	if pos == -1 { // prepend
		if count == 0 && numV4 == 0 {
			return 0, ""
		}
		return 1, ""
	}
	if pos > numV4 {
		return 0, "Invalid position '"
	}
	return pos, ""
}

// v6Position maps a user position for a v6 rule.
func v6Position(pos, count, numV4, numV6 int) (int, string) {
	if pos == -1 { // prepend
		if count == 0 && numV6 == 0 {
			return 0, ""
		}
		return 1, ""
	}
	if pos > numV4 {
		return pos - numV4, ""
	}
	if pos != 0 && pos <= numV4 {
		return 0, "Invalid position '"
	}
	return pos, ""
}

// applyDual replicates the ip_version="both" branch of frontend.set_rule:
// the v4 half goes first, then the v6 half is placed relative to the
// displaced rule's family twin.
func (e *Env) applyDual(st *store.State, nr *rule.Rule, userPos, count int, numV4 *int, numV6 int, kind OpKind) string {
	remove := kind == OpDelete
	pos4 := userPos
	if userPos == -1 { // prepend
		if count == 0 && *numV4 == 0 {
			pos4 = 0
		} else {
			pos4 = 1
		}
	} else if !remove && userPos > *numV4 {
		// User specified a v6 position: find the matching v4 position.
		p := findOtherPosition(st, userPos-*numV4+count, true)
		if p > 0 {
			pos4 = p
		} else {
			pos4 = 0
		}
	}
	res := e.applyHalf(st, nr, pos4, false, kind)
	if res == "" {
		return ""
	}

	// Readjust: the number of v4 rules may have increased.
	pos6 := pos4
	if !remove && userPos > 0 {
		*numV4 = dedupedCount(st.Rules4)
		pos6 = userPos + 1
	}
	if userPos == -1 { // prepend
		if count == 0 && numV6 == 0 {
			pos6 = 0
		} else {
			pos6 = 1
		}
	} else if !remove && pos6 > 0 && pos6 <= *numV4 {
		// User specified a v4 rule: find the matching v6 position.
		p := findOtherPosition(st, pos6, false)
		if p > 0 {
			pos6 = p - count
		} else {
			pos6 = 0
		}
	}
	if !remove && pos6 > *numV4 && userPos != -1 {
		pos6 -= *numV4
	}
	res2 := e.applyHalf(st, nr, pos6, true, kind)
	if res2 == "" {
		return ""
	}
	return res + "\n" + res2
}

// applyHalf runs one rule through the set_rule engine for one family
// list. For app-rule deletes it first expands the command against the
// stored rules sharing the app tuple (ufw get_app_rules_from_system).
// Returns the result line ("" on error, already reported).
func (e *Env) applyHalf(st *store.State, nr *rule.Rule, pos int, v6 bool, kind OpKind) string {
	remove := kind == OpDelete
	list := st.Rules4
	if v6 {
		list = st.Rules6
	}
	if pos < 0 || pos > len(list) {
		e.Errorf("Invalid position '%d'", pos)
		return ""
	}
	if pos > 0 && remove {
		e.Errorf("Cannot specify insert and delete")
		return ""
	}

	nr = nr.Clone()
	nr.SetV6(v6)

	// Build the target list: for app deletes, every stored rule sharing
	// the app tuple, re-stamped with the command's action/logtype.
	targets := []*rule.Rule{nr}
	if remove && (nr.Dapp != "" || nr.Sapp != "") {
		tupl := nr.AppTuple()
		targets = nil
		for i := range list {
			if list[i].AppTuple() == tupl {
				t := list[i].Clone()
				t.Action = nr.Action
				t.Log = nr.Log
				targets = append(targets, t)
			}
		}
		if len(targets) == 0 {
			return outcomeString(outNotFound, v6, e.live())
		}
	}

	last := ""
	for _, t := range targets {
		var oc ruleOutcome
		list, oc = setRuleEngine(list, t, pos, remove)
		if oc == outNotFound || oc == outSkipAdd || oc == outSkipInsert {
			return outcomeString(oc, v6, e.live())
		}
		if v6 {
			st.Rules6 = list
		} else {
			st.Rules4 = list
		}
		last = outcomeString(oc, v6, e.live())
	}
	return last
}

// setRuleEngine is the per-family core of ufw's backend.set_rule: it
// walks the list once, handling insert-position sliding, dedup matching,
// in-place update and removal. Returns the new list and the outcome.
func setRuleEngine(list []rule.Rule, nr *rule.Rule, pos int, remove bool) ([]rule.Rule, ruleOutcome) {
	newrules := make([]rule.Rule, 0, len(list)+1)
	found := false
	modified := false
	inserted := false
	matches := 0
	count := 1
	var last [4]string
	v6 := nr.V6()
	for i := range list {
		r := &list[i]
		current := [4]string{canonAddr(r.Dst, v6), canonAddr(r.Src, v6), r.Dapp, r.Sapp}
		if count == pos {
			// Insert unless the previous rule shares this rule's app
			// tuple (app groups are never split).
			if (last[2] == "" && last[3] == "" && count > 1) ||
				(current[2] == "" && current[3] == "") ||
				last != current {
				inserted = true
				newrules = append(newrules, *nr)
				last = [4]string{}
			} else {
				pos++
			}
		}
		last = current
		count++

		ret := r.Match(nr)
		if ret < rule.MatchNone {
			matches++
		}
		switch {
		case ret == rule.MatchExact && !found && !inserted:
			found = true
			if !remove {
				newrules = append(newrules, *nr)
			}
		case ret == rule.MatchComment && remove && nr.Comment == "":
			// Deleting without a comment matches a commented rule.
			found = true
		case ret < rule.MatchExact && !remove && !inserted:
			found = true
			modified = true
			newrules = append(newrules, *nr)
		default:
			newrules = append(newrules, *r)
		}
	}

	if inserted {
		if matches > 0 {
			return list, outSkipInsert
		}
		return newrules, outInserted
	}
	if !found && !remove {
		newrules = append(newrules, *nr)
	}
	switch {
	case !found && remove:
		return list, outNotFound
	case found && !remove && !modified:
		return list, outSkipAdd
	case remove:
		return newrules, outDeleted
	case modified:
		return newrules, outUpdated
	default:
		return newrules, outAdded
	}
}

// outcomeString maps an outcome to ufw's result line. When the firewall
// is not live (disabled or dry-run) ufw reports "Rules updated" for any
// state-changing operation.
func outcomeString(oc ruleOutcome, v6, live bool) string {
	suffix := ""
	if v6 {
		suffix = " (v6)"
	}
	switch oc {
	case outSkipAdd:
		return "Skipping adding existing rule" + suffix
	case outSkipInsert:
		return "Skipping inserting existing rule" + suffix
	case outNotFound:
		// ufw gates the not-found message on `not self.dryrun`; a dry-run
		// delete of a missing rule still reports "Rules updated".
		if !live {
			return "Rules updated" + suffix
		}
		return "Could not delete non-existent rule" + suffix
	}
	if !live {
		return "Rules updated" + suffix
	}
	switch oc {
	case outAdded:
		return "Rule added" + suffix
	case outDeleted:
		return "Rule deleted" + suffix
	case outInserted:
		return "Rule inserted" + suffix
	case outUpdated:
		return "Rule updated" + suffix
	}
	return "Rules updated" + suffix
}

// live reports whether mutations should hit the kernel (enabled and not
// a dry run).
func (e *Env) live() bool {
	conf, err := e.Store.LoadConf()
	if err != nil {
		return false
	}
	return conf.Enabled && !e.DryRun
}

// commitState persists the mutated state, applies it when live, and
// prints the result lines. Dry-run renders the would-be ruleset via
// applyRuleset instead of saving.
func (e *Env) commitState(st *store.State, precomputed ...string) int {
	sweepExpired(st)
	if e.DryRun {
		e.Msg("%s", strings.Join(precomputed, "\n"))
		etc, err := e.Store.EtcDefaults()
		if err != nil {
			return e.Errorf("%s", err)
		}
		return e.applyRuleset(st, etc)
	}
	// Apply before saving when live: a compile/apply error must not leave
	// rules.json ahead of the kernel (that wedges every later mutation).
	if e.live() {
		etc, err := e.Store.EtcDefaults()
		if err != nil {
			return e.Errorf("%s", err)
		}
		// Mutations reload only the ruleset; init hooks/sysctl/modprobe run
		// once at enable, not per rule change (ufw _reload_user_rules).
		if code := e.reloadRuleset(st, etc); code != 0 {
			return code
		}
	}
	if err := e.Store.Save(st); err != nil {
		return e.Errorf("%s", err)
	}
	e.Msg("%s", strings.Join(precomputed, "\n"))
	return 0
}

// sweepExpired drops expired rules (lazy expiry enforcement on every
// mutation, per the expiry design).
func sweepExpired(st *store.State) {
	now := time.Now().Unix()
	keep := func(rules []rule.Rule) []rule.Rule {
		out := rules[:0]
		for _, r := range rules {
			if !r.Expired(now) {
				out = append(out, r)
			}
		}
		return out
	}
	st.Rules4 = keep(st.Rules4)
	st.Rules6 = keep(st.Rules6)
}

// findOtherPosition replicates backend.find_other_position: returns the
// position in the OTHER family list of the rule occupying `position` in
// the `v6`-selected list, accounting for app-tuple grouping. 0 = no twin.
func findOtherPosition(st *store.State, position int, v6 bool) int {
	src := st.Rules4
	other := st.Rules6
	if v6 {
		src = st.Rules6
		other = st.Rules4
	}
	if position < 1 || position > len(src) {
		return 0
	}
	// Count app-tuple duplicates leading up to position.
	seen := map[string]bool{}
	offset := 0
	for i := range src {
		if i >= position {
			break
		}
		r := &src[i]
		if r.Dapp != "" || r.Sapp != "" {
			t := r.AppTuple()
			if seen[t] {
				offset++
			} else {
				seen[t] = true
			}
		}
	}
	idx := position - 1 + offset
	if idx < 0 || idx >= len(src) {
		return 0
	}
	match := src[idx].Clone()
	match.SetV6(!v6)
	count := 1
	for i := range other {
		if other[i].Match(match) == rule.MatchExact {
			return count
		}
		count++
	}
	return 0
}

// profilePorts flattens a profile's port items into PortRanges, matching
// the parser's setApp expansion: "any" items wildcard the endpoint.
func profilePorts(p *appprof.Profile) []rule.PortRange {
	var ranges []rule.PortRange
	for _, spec := range p.Expand() {
		if spec.Ports == "any" {
			return nil
		}
		for _, item := range strings.Split(spec.Ports, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			lo, hi := item, item
			if i := strings.Index(item, ":"); i >= 0 {
				lo, hi = item[:i], item[i+1:]
			}
			l, err1 := strconv.Atoi(lo)
			h, err2 := strconv.Atoi(hi)
			if err1 != nil || err2 != nil || l < 1 || h > 65535 || l > h {
				continue
			}
			ranges = append(ranges, rule.PortRange{
				Lo: uint16(l), Hi: uint16(h), Proto: spec.Proto,
			})
		}
	}
	return ranges
}

// expandAppRules regenerates the per-item rule list for an app-rule add:
// the parser flattened the profile's ports onto the rule, so rebuild from
// the profile's Expand() items (one rule per dapp item, cross-product with
// sapp items). Returns nil when the profile is gone — caller keeps the
// single parsed rule.
func expandAppRules(nr *rule.Rule) []*rule.Rule {
	profiles := loadProfiles()
	var dspecs, sspecs []appprof.PortSpec
	if nr.Dapp != "" {
		p := appprof.Find(profiles, nr.Dapp)
		if p == nil {
			return nil
		}
		dspecs = p.Expand()
	}
	if nr.Sapp != "" {
		p := appprof.Find(profiles, nr.Sapp)
		if p == nil {
			return nil
		}
		sspecs = p.Expand()
	}
	out := appRulesFromSpecs(nr, dspecs, sspecs)
	for _, r := range out {
		r.ID = rule.NewID()
	}
	return out
}

// ipv6Available reports whether the kernel has IPv6 (ufw's use_ipv6 check).
func ipv6Available() bool {
	_, err := os.Stat("/proc/sys/net/ipv6")
	return err == nil
}
