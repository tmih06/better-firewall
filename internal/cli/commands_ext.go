package cli

// Extension commands (Phase 4): set, nat, check, diff, panic, sweep,
// rule enable/disable, logs. Export/import live in commands_impexp.go.
// Mutations go through commitState (shared save+apply+dry-run path).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	nftbe "github.com/tmih06/better-firewall/internal/backend/nft"
	"github.com/tmih06/better-firewall/internal/rule"
	"github.com/tmih06/better-firewall/internal/store"
)

// ---------------------------------------------------------------- set

var setNameRe = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// validSetName reports whether name is usable as an nftables set suffix.
func validSetName(name string) bool { return setNameRe.MatchString(name) }

// canonSetElem validates and canonicalizes one set element (IP or CIDR).
func canonSetElem(s string) (string, bool) {
	if ip := net.ParseIP(s); ip != nil {
		return ip.String(), true
	}
	if _, ipnet, err := net.ParseCIDR(s); err == nil {
		return ipnet.String(), true
	}
	return "", false
}

func findSet(st *store.State, name string) *store.IPSet {
	for i := range st.Sets {
		if st.Sets[i].Name == name {
			return &st.Sets[i]
		}
	}
	return nil
}

// setReferenced counts distinct rule IDs referencing the named set.
func setReferenced(st *store.State, name string) int {
	ids := map[string]bool{}
	for _, list := range [][]rule.Rule{st.Rules4, st.Rules6} {
		for i := range list {
			r := &list[i]
			if r.Src.Set == name || r.Dst.Set == name {
				ids[r.ID] = true
			}
		}
	}
	return len(ids)
}

func (e *Env) cmdSet(args []string) int {
	if len(args) == 0 {
		e.Msg("%s", HelpText(e.Prog))
		return 1
	}
	switch args[0] {
	case "create":
		return e.setCreate(args[1:])
	case "add":
		return e.setAdd(args[1:])
	case "del", "delete":
		return e.setDel(args[1:])
	case "list":
		return e.setList(args[1:])
	case "destroy":
		return e.setDestroy(args[1:])
	default:
		e.Msg("%s", HelpText(e.Prog))
		return 1
	}
}

func (e *Env) setCreate(args []string) int {
	if len(args) != 1 {
		e.Msg("%s", HelpText(e.Prog))
		return 1
	}
	name := args[0]
	if !validSetName(name) {
		return e.Errorf("Invalid set name '%s'", name)
	}
	if !e.checkRoot() {
		return 1
	}
	release, rc := e.acquireLock()
	if release == nil {
		return rc
	}
	defer release()
	st, err := e.Store.Load()
	if err != nil {
		return e.Errorf("%v", err)
	}
	if findSet(st, name) != nil {
		return e.Errorf("Set '%s' already exists", name)
	}
	// The compiler derives the v6 set as bfw_set_<name>6, so `name` collides
	// with an existing set `o` when name+"6"==o or name==o+"6".
	for _, o := range st.Sets {
		if name+"6" == o.Name || name == o.Name+"6" {
			return e.Errorf("Set '%s' collides with '%s' (v6 twin naming)", name, o.Name)
		}
	}
	st.Sets = append(st.Sets, store.IPSet{Name: name, Family: "inet"})
	return e.commitState(st, fmt.Sprintf("Set '%s' created", name))
}

func (e *Env) setAdd(args []string) int {
	if len(args) < 2 {
		e.Msg("%s", HelpText(e.Prog))
		return 1
	}
	name := args[0]
	var elems []string
	for _, arg := range args[1:] {
		for _, piece := range strings.Split(arg, ",") {
			piece = strings.TrimSpace(piece)
			c, ok := canonSetElem(piece)
			if !ok {
				return e.Errorf("Bad IP address '%s'", piece)
			}
			elems = append(elems, c)
		}
	}
	if len(elems) == 0 {
		return e.Errorf("no elements specified")
	}
	if !e.checkRoot() {
		return 1
	}
	release, rc := e.acquireLock()
	if release == nil {
		return rc
	}
	defer release()
	st, err := e.Store.Load()
	if err != nil {
		return e.Errorf("%v", err)
	}
	s := findSet(st, name)
	if s == nil {
		return e.Errorf("Set '%s' does not exist", name)
	}
	added := 0
	for _, el := range elems {
		dup := false
		for _, ex := range s.Elements {
			if ex == el {
				dup = true
				break
			}
		}
		if !dup {
			s.Elements = append(s.Elements, el)
			added++
		}
	}
	return e.commitState(st, fmt.Sprintf("added %d element(s) to '%s'", added, name))
}

func (e *Env) setDel(args []string) int {
	if len(args) < 2 {
		e.Msg("%s", HelpText(e.Prog))
		return 1
	}
	name := args[0]
	var elems []string
	for _, arg := range args[1:] {
		for _, piece := range strings.Split(arg, ",") {
			piece = strings.TrimSpace(piece)
			c, ok := canonSetElem(piece)
			if !ok {
				return e.Errorf("Bad IP address '%s'", piece)
			}
			elems = append(elems, c)
		}
	}
	if !e.checkRoot() {
		return 1
	}
	release, rc := e.acquireLock()
	if release == nil {
		return rc
	}
	defer release()
	st, err := e.Store.Load()
	if err != nil {
		return e.Errorf("%v", err)
	}
	s := findSet(st, name)
	if s == nil {
		return e.Errorf("Set '%s' does not exist", name)
	}
	var removed []string
	for _, c := range elems {
		found := false
		for i, ex := range s.Elements {
			if ex == c {
				s.Elements = append(s.Elements[:i], s.Elements[i+1:]...)
				found = true
				break
			}
		}
		if !found {
			return e.Errorf("'%s' is not in set '%s'", c, name)
		}
		removed = append(removed, fmt.Sprintf("removed '%s' from '%s'", c, name))
	}
	return e.commitState(st, removed...)
}

func (e *Env) setList(args []string) int {
	if len(args) > 1 {
		e.Msg("%s", HelpText(e.Prog))
		return 1
	}
	if !e.checkRoot() {
		return 1
	}
	st, err := e.Store.Load()
	if err != nil {
		return e.Errorf("%v", err)
	}
	var sets []store.IPSet
	if len(args) == 1 {
		s := findSet(st, args[0])
		if s == nil {
			return e.Errorf("Set '%s' does not exist", args[0])
		}
		sets = []store.IPSet{*s}
	} else {
		sets = st.Sets
	}
	if e.JSON {
		if sets == nil {
			sets = []store.IPSet{}
		}
		out, _ := json.MarshalIndent(map[string]any{"sets": sets}, "", "  ")
		e.Msg("%s", out)
		return 0
	}
	for _, s := range sets {
		e.Msg("Set '%s' (%s):", s.Name, s.Family)
		for _, el := range s.Elements {
			e.Msg("  %s", el)
		}
	}
	return 0
}

func (e *Env) setDestroy(args []string) int {
	if len(args) != 1 {
		e.Msg("%s", HelpText(e.Prog))
		return 1
	}
	name := args[0]
	if !e.checkRoot() {
		return 1
	}
	release, rc := e.acquireLock()
	if release == nil {
		return rc
	}
	defer release()
	st, err := e.Store.Load()
	if err != nil {
		return e.Errorf("%v", err)
	}
	if findSet(st, name) == nil {
		return e.Errorf("Set '%s' does not exist", name)
	}
	if n := setReferenced(st, name); n > 0 {
		if !e.Force {
			return e.Errorf("Set '%s' is referenced by %d rule(s) (use --force to destroy anyway)", name, n)
		}
		// A destroyed set leaves dangling Lookup refs that fail every later
		// apply. Strip the references so the ruleset stays loadable.
		e.Warnf("destroying set '%s'; removing %d referencing rule(s)", name, n)
		st.Rules4 = dropSetRefs(st.Rules4, name)
		st.Rules6 = dropSetRefs(st.Rules6, name)
	}
	for i := range st.Sets {
		if st.Sets[i].Name == name {
			st.Sets = append(st.Sets[:i], st.Sets[i+1:]...)
			break
		}
	}
	return e.commitState(st, fmt.Sprintf("Set '%s' destroyed", name))
}

// ---------------------------------------------------------------- nat

func (e *Env) cmdNat(args []string) int {
	if len(args) == 0 {
		e.Msg("%s", HelpText(e.Prog))
		return 1
	}
	switch args[0] {
	case "add":
		return e.natAdd(args[1:])
	case "list":
		return e.natList(args[1:])
	case "del", "delete":
		return e.natDelete(args[1:])
	default:
		e.Msg("%s", HelpText(e.Prog))
		return 1
	}
}

func (e *Env) natAdd(args []string) int {
	if len(args) == 0 {
		e.Msg("%s", HelpText(e.Prog))
		return 1
	}
	var nr store.NATRule
	switch args[0] {
	case "masquerade":
		// nat add masquerade out on IFACE [from CIDR]
		if len(args) < 4 || args[1] != "out" || args[2] != "on" {
			e.Msg("%s", HelpText(e.Prog))
			return 1
		}
		nr.Kind = "masquerade"
		nr.IfaceOut = args[3]
		if len(args) > 4 {
			if len(args) != 6 || args[4] != "from" {
				e.Msg("%s", HelpText(e.Prog))
				return 1
			}
			c, ok := canonSetElem(args[5])
			if !ok {
				return e.Errorf("Bad IP address '%s'", args[5])
			}
			nr.Src = c
		}
	case "dnat":
		// nat add dnat proto tcp [in on IFACE] to IP port N to-destination IP[:PORT]
		if len(args) < 3 || args[1] != "proto" {
			e.Msg("%s", HelpText(e.Prog))
			return 1
		}
		nr.Kind = "dnat"
		nr.Proto = args[2]
		if nr.Proto != "tcp" && nr.Proto != "udp" {
			return e.Errorf("Bad protocol '%s'", nr.Proto)
		}
		i := 3
		if i+1 < len(args) && args[i] == "in" && args[i+1] == "on" {
			if i+2 >= len(args) {
				e.Msg("%s", HelpText(e.Prog))
				return 1
			}
			nr.IfaceIn = args[i+2]
			i += 3
		}
		if i+3 >= len(args) || args[i] != "to" || args[i+2] != "port" {
			e.Msg("%s", HelpText(e.Prog))
			return 1
		}
		if net.ParseIP(args[i+1]) == nil {
			return e.Errorf("Bad IP address '%s'", args[i+1])
		}
		nr.Dst = args[i+1]
		p, err := strconv.Atoi(args[i+3])
		if err != nil || p < 1 || p > 65535 {
			return e.Errorf("Bad port '%s'", args[i+3])
		}
		nr.Dport = uint16(p)
		i += 4
		if i+1 >= len(args) || args[i] != "to-destination" {
			e.Msg("%s", HelpText(e.Prog))
			return 1
		}
		// Validate now so a bad value can't wedge every later apply.
		if !validToDest(args[i+1]) {
			return e.Errorf("Bad to-destination '%s'", args[i+1])
		}
		// The `to` address and to-destination must share a family — mixing
		// v4 dst with a v6 target compiles to a nonsensical ip6 match.
		if dstIP := net.ParseIP(nr.Dst); dstIP != nil {
			if tdHost, _ := splitToDestCLI(args[i+1]); tdHost != "" {
				if tdIP := net.ParseIP(tdHost); tdIP != nil &&
					(dstIP.To4() == nil) != (tdIP.To4() == nil) {
					return e.Errorf("to-destination family mismatch with 'to %s'", nr.Dst)
				}
			}
		}
		nr.ToDest = args[i+1]
		i += 2
		if i != len(args) {
			e.Msg("%s", HelpText(e.Prog))
			return 1
		}
	default:
		e.Msg("%s", HelpText(e.Prog))
		return 1
	}
	if !e.checkRoot() {
		return 1
	}
	release, rc := e.acquireLock()
	if release == nil {
		return rc
	}
	defer release()
	st, err := e.Store.Load()
	if err != nil {
		return e.Errorf("%v", err)
	}
	st.NAT = append(st.NAT, nr)
	return e.commitState(st, "NAT rule added")
}

// natDesc renders a stored NAT rule for `nat list`.
func natDesc(nr *store.NATRule) string {
	switch nr.Kind {
	case "masquerade":
		s := "masquerade out on " + nr.IfaceOut
		if nr.Src != "" {
			s += " from " + nr.Src
		}
		return s
	case "dnat":
		s := "dnat proto " + nr.Proto
		if nr.IfaceIn != "" {
			s += " in on " + nr.IfaceIn
		}
		s += fmt.Sprintf(" to %s port %d to-destination %s", nr.Dst, nr.Dport, nr.ToDest)
		return s
	}
	return nr.Kind
}

func (e *Env) natList(args []string) int {
	if len(args) != 0 {
		e.Msg("%s", HelpText(e.Prog))
		return 1
	}
	if !e.checkRoot() {
		return 1
	}
	st, err := e.Store.Load()
	if err != nil {
		return e.Errorf("%v", err)
	}
	for i := range st.NAT {
		e.Msg("[%2d] %s", i+1, natDesc(&st.NAT[i]))
	}
	return 0
}

func (e *Env) natDelete(args []string) int {
	if len(args) != 1 {
		e.Msg("%s", HelpText(e.Prog))
		return 1
	}
	n, err := strconv.Atoi(args[0])
	if err != nil {
		return e.Errorf("Could not find rule")
	}
	if !e.checkRoot() {
		return 1
	}
	release, rc := e.acquireLock()
	if release == nil {
		return rc
	}
	defer release()
	st, err := e.Store.Load()
	if err != nil {
		return e.Errorf("%v", err)
	}
	if n < 1 || n > len(st.NAT) {
		return e.Errorf("Could not find rule")
	}
	st.NAT = append(st.NAT[:n-1], st.NAT[n:]...)
	return e.commitState(st, "NAT rule deleted")
}

// ---------------------------------------------------------------- check

// sshAllowsPort reports whether r is an effective allow/limit rule covering
// the ssh service port (22/tcp) on incoming traffic.
func sshAllowsPort(r *rule.Rule, now int64) bool {
	if r.Disabled || r.Expired(now) {
		return false
	}
	if r.Action != rule.ActionAllow && r.Action != rule.ActionLimit {
		return false
	}
	if r.Direction != rule.DirIn {
		return false
	}
	if r.Proto != "tcp" && r.Proto != "any" && r.Proto != "" {
		return false
	}
	if len(r.Dst.Ports) == 0 {
		return true // all ports
	}
	for _, p := range r.Dst.Ports {
		if (p.Proto == "tcp" || p.Proto == "any" || p.Proto == "") && p.Lo <= 22 && 22 <= p.Hi {
			return true
		}
	}
	return false
}

// prefixContains reports whether prefix b covers all of a.
func prefixContains(a, b netip.Prefix) bool {
	if a.Addr().Is4() != b.Addr().Is4() {
		return false
	}
	return b.Contains(a.Addr()) && b.Bits() <= a.Bits()
}

// addrSuperset reports whether endpoint b covers every packet endpoint a
// matches (b's address space ⊇ a's and b's ports ⊇ a's).
func addrSuperset(a, b rule.AddrSpec) bool {
	if b.Set != "" || a.Set != "" {
		return a.Set == b.Set
	}
	if !b.Any() {
		if a.Any() {
			return false
		}
		toPrefix := func(s string) (netip.Prefix, bool) {
			if p, err := netip.ParsePrefix(s); err == nil {
				return p, true
			}
			if ip, err := netip.ParseAddr(s); err == nil {
				return netip.PrefixFrom(ip, ip.BitLen()), true
			}
			return netip.Prefix{}, false
		}
		pa, oka := toPrefix(a.IP)
		pb, okb := toPrefix(b.IP)
		if !oka || !okb || !prefixContains(pa, pb) {
			return false
		}
	}
	if len(b.Ports) == 0 {
		return true // b matches all ports
	}
	if len(a.Ports) == 0 {
		return false // a matches all ports, b only some
	}
	for _, pa := range a.Ports {
		covered := false
		for _, pb := range b.Ports {
			if portProtoCovers(pa.Proto, pb.Proto) && pb.Lo <= pa.Lo && pa.Hi <= pb.Hi {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

// portProtoCovers reports whether a port-range with protocol pb covers one
// with protocol pa ("any" covers tcp and udp).
func portProtoCovers(pa, pb string) bool {
	if pa == pb {
		return true
	}
	if pb == "any" || pb == "" {
		return pa == "tcp" || pa == "udp" || pa == "any" || pa == ""
	}
	return false
}

// ruleSuperset reports whether rule b matches a superset of the packets
// rule a matches, making a unreachable when b precedes it.
func ruleSuperset(a, b *rule.Rule) bool {
	if a.V6() != b.V6() {
		return false
	}
	if a.Direction != b.Direction {
		return false
	}
	if b.IfaceIn != "" && b.IfaceIn != a.IfaceIn {
		return false
	}
	if b.IfaceOut != "" && b.IfaceOut != a.IfaceOut {
		return false
	}
	if b.Proto != "" && b.Proto != "any" && b.Proto != a.Proto {
		return false
	}
	if b.ICMPType != "" && b.ICMPType != a.ICMPType {
		return false
	}
	if b.Dapp != "" && b.Dapp != a.Dapp {
		return false
	}
	if b.Sapp != "" && b.Sapp != a.Sapp {
		return false
	}
	return addrSuperset(a.Src, b.Src) && addrSuperset(a.Dst, b.Dst)
}

func (e *Env) cmdCheck(args []string) int {
	if len(args) != 0 {
		e.Msg("%s", HelpText(e.Prog))
		return 1
	}
	if !e.checkRoot() {
		return 1
	}
	st, err := e.Store.Load()
	if err != nil {
		return e.Errorf("%v", err)
	}
	now := time.Now().Unix()
	warned := false
	warn := func(format string, a ...any) {
		fmt.Fprintf(e.Stdout, "WARN: "+format+"\n", a...)
		warned = true
	}

	// (a) ssh lockout risk: deny OR reject incoming policy, or panic mode
	// (effective deny-all), with no ssh allow → lockout.
	lockout := st.Policies.Input == "deny" || st.Policies.Input == "reject" || st.Panic
	if hookUnderSSH() && lockout {
		allowed := false
		for _, r := range combined(st) {
			if sshAllowsPort(r, now) {
				allowed = true
				break
			}
		}
		if !allowed {
			warn("ssh lockout risk: incoming policy is '%s' and no rule allows ssh (port 22/tcp)", st.Policies.Input)
		}
	}

	// (a2) enabled but not loaded: the most basic drift.
	conf, _ := e.Store.LoadConf()
	if conf != nil && conf.Enabled {
		if b, err := e.backend(); err == nil {
			if loaded, _ := b.Loaded(); !loaded {
				warn("firewall is enabled but not loaded in the kernel")
			}
		}
	}

	// (b) shadowed + (c) expired rules, over the combined displayed list
	all := combined(st)
	for j, rj := range all {
		if rj.Expired(now) {
			warn("rule %d expired", j+1)
		}
		if rj.Disabled {
			continue
		}
		for i := 0; i < j; i++ {
			ri := all[i]
			if ri.Disabled || ri.Expired(now) {
				continue
			}
			if ruleSuperset(rj, ri) {
				warn("rule %d shadowed by rule %d", j+1, i+1)
				break
			}
		}
	}

	// (d) foreign (ufw) chains in the kernel
	if b, err := e.backend(); err == nil {
		if snap, err := b.ReadBack(); err == nil && snap != nil {
			if names := snap.ForeignChains("ufw-"); len(names) > 0 {
				sort.Strings(names)
				warn("ufw chains detected in kernel: %s", strings.Join(names, ", "))
			}
		}
	}

	if !warned {
		e.Msg("No issues found")
	}
	return 0
}

// ---------------------------------------------------------------- diff

var (
	nftCounterRe = regexp.MustCompile(`counter packets \d+ bytes \d+`)
	nftHandleRe  = regexp.MustCompile(`# handle \d+`)
	nftBareCtrRe = regexp.MustCompile(`\bcounter\b`)
)

// normalizeNft strips volatile nft output (counters, handles, whitespace)
// and canonicalizes the symbolic-vs-numeric divergence between RenderText
// and `nft -nn`: the kernel folds `meta nfproto`/`meta l4proto` into the
// protocol match and prints numeric ct-states/icmp-types, so both sides are
// reduced to the kernel's folded numeric form.
func normalizeNft(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = nftCounterRe.ReplaceAllString(line, "")
		line = nftHandleRe.ReplaceAllString(line, "")
		line = nftBareCtrRe.ReplaceAllString(line, "")
		line = canonNftLine(line)
		line = strings.Join(strings.Fields(line), " ")
		if line != "" {
			out = append(out, line)
		}
	}
	// Set blocks are unordered in the kernel; collect them all, sort by
	// name, and emit them back in the positions set blocks occupied.
	return sortSetBlocks(out)
}

// sortSetBlocks gathers every `set X { … }` block, sorts them by the set
// header line, and writes them back into the slots set blocks occupied —
// so creation-order differences between stored and kernel don't diff.
func sortSetBlocks(lines []string) []string {
	var blocks [][]string
	var slots []int // index in `lines` where each block starts
	for i := 0; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "set ") {
			var block []string
			slots = append(slots, i)
			for i < len(lines) && !strings.HasPrefix(lines[i], "}") {
				block = append(block, lines[i])
				i++
			}
			if i < len(lines) {
				block = append(block, lines[i])
			}
			blocks = append(blocks, block)
		}
	}
	if len(blocks) == 0 {
		return lines
	}
	sort.Slice(blocks, func(i, j int) bool { return blocks[i][0] < blocks[j][0] })
	// Rebuild: walk lines, substituting sorted blocks at each slot.
	slotSet := map[int]bool{}
	for _, s := range slots {
		slotSet[s] = true
	}
	var out []string
	bi := 0
	for i := 0; i < len(lines); i++ {
		if slotSet[i] {
			out = append(out, blocks[bi]...)
			bi++
			// skip to just past this block's closing brace
			for i < len(lines) && !strings.HasPrefix(lines[i], "}") {
				i++
			}
			continue
		}
		out = append(out, lines[i])
	}
	return out
}

// canonNftLine reduces one nft rule line to the kernel's folded numeric
// form: drops `meta nfproto`/`meta l4proto` qualifiers (the kernel folds
// them into the proto match) and maps symbolic names to numbers.
func canonNftLine(line string) string {
	f := strings.Fields(line)
	var out []string
	for i := 0; i < len(f); i++ {
		// Drop "meta nfproto <f>" and "meta l4proto <p>" — the kernel folds
		// both into the following protocol/address match.
		if f[i] == "meta" && i+2 < len(f) && (f[i+1] == "nfproto" || f[i+1] == "l4proto") {
			i += 2
			continue
		}
		// The kernel appends "burst N packets" to meter limits; RenderText
		// omits the default burst. Drop it from the kernel side.
		if f[i] == "burst" && i+2 < len(f) && f[i+2] == "packets" {
			i += 2
			continue
		}
		// "fib daddr type X" — kernel prints the addrtype number.
		if i > 0 && f[i-1] == "type" && i > 2 && f[i-3] == "fib" {
			out = append(out, mapFibType(f[i]))
			continue
		}
		// symbolic names with different numbers — key on the proto token.
		if i > 0 && f[i-1] == "state" {
			out = append(out, mapNftValue(f[i]))
			continue
		}
		if i > 1 && f[i-1] == "type" {
			out = append(out, mapIcmpType(f[i-2], f[i]))
			continue
		}
		out = append(out, f[i])
	}
	return strings.Join(out, " ")
}

// mapNftValue maps a symbolic value token (ct-state list, icmp type) to the
// numeric form `nft -nn` prints.
func mapNftValue(t string) string {
	if n, ok := nftSymToNum[t]; ok {
		return n
	}
	// comma-separated ct-state list: map each element.
	if strings.Contains(t, ",") {
		parts := strings.Split(t, ",")
		for i, p := range parts {
			if n, ok := nftSymToNum[p]; ok {
				parts[i] = n
			}
		}
		return strings.Join(parts, ",")
	}
	return t
}

// mapIcmpType maps a symbolic icmp/icmpv6 type name to its number, keyed on
// the preceding proto token ("icmp" or "icmpv6").
func mapIcmpType(proto, name string) string {
	if n, err := rule.ICMPTypeNumber(proto, name); err == nil {
		return n
	}
	return name
}

// nftSymToNum maps symbolic ct-state tokens to the numeric form `nft -nn`
// prints.
var nftSymToNum = map[string]string{
	"invalid": "0x1", "established": "0x2", "related": "0x4", "new": "0x8",
}

// unifiedDiff renders a unified diff of a vs b with 3 lines of context.
func unifiedDiff(nameA, nameB string, a, b []string) string {
	// LCS dynamic program.
	n, m := len(a), len(b)
	d := make([][]int, n+1)
	for i := range d {
		d[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				d[i][j] = d[i+1][j+1] + 1
			} else if d[i+1][j] >= d[i][j+1] {
				d[i][j] = d[i+1][j]
			} else {
				d[i][j] = d[i][j+1]
			}
		}
	}
	type op struct {
		kind byte // ' ', '-', '+'
		line string
	}
	var ops []op
	i, j := 0, 0
	for i < n && j < m {
		if a[i] == b[j] {
			ops = append(ops, op{' ', a[i]})
			i++
			j++
		} else if d[i+1][j] >= d[i][j+1] {
			ops = append(ops, op{'-', a[i]})
			i++
		} else {
			ops = append(ops, op{'+', b[j]})
			j++
		}
	}
	for ; i < n; i++ {
		ops = append(ops, op{'-', a[i]})
	}
	for ; j < m; j++ {
		ops = append(ops, op{'+', b[j]})
	}

	const ctx = 3
	var sb strings.Builder
	fmt.Fprintf(&sb, "--- %s\n+++ %s\n", nameA, nameB)
	for k := 0; k < len(ops); {
		if ops[k].kind == ' ' {
			k++
			continue
		}
		start := k - ctx
		if start < 0 {
			start = 0
		}
		end := k
		for end < len(ops) {
			if ops[end].kind != ' ' {
				end++
				continue
			}
			// extend through a run of context only if another change follows
			p := end
			for p < len(ops) && ops[p].kind == ' ' {
				p++
			}
			if p-end <= 2*ctx && p < len(ops) {
				end = p
				continue
			}
			break
		}
		if end+ctx < len(ops) {
			end += ctx
		} else {
			end = len(ops)
		}
		aStart, bStart, aCount, bCount := 0, 0, 0, 0
		for _, o := range ops[:start] {
			if o.kind != '+' {
				aStart++
			}
			if o.kind != '-' {
				bStart++
			}
		}
		for _, o := range ops[start:end] {
			if o.kind != '+' {
				aCount++
			}
			if o.kind != '-' {
				bCount++
			}
		}
		aDisp, bDisp := aStart+1, bStart+1
		if aCount == 0 {
			aDisp = aStart
		}
		if bCount == 0 {
			bDisp = bStart
		}
		fmt.Fprintf(&sb, "@@ -%d,%d +%d,%d @@\n", aDisp, aCount, bDisp, bCount)
		for _, o := range ops[start:end] {
			sb.WriteByte(o.kind)
			sb.WriteString(o.line)
			sb.WriteByte('\n')
		}
		k = end
	}
	return sb.String()
}

func (e *Env) cmdDiff(args []string) int {
	if len(args) != 0 {
		e.Msg("%s", HelpText(e.Prog))
		return 1
	}
	if !e.checkRoot() {
		return 1
	}
	st, err := e.Store.Load()
	if err != nil {
		return e.Errorf("%v", err)
	}
	etc, err := e.Store.EtcDefaults()
	if err != nil {
		return e.Errorf("%v", err)
	}
	want, err := nftbe.RenderText(st, etc)
	if err != nil {
		return e.Errorf("%v", err)
	}
	// Read-only shell-out; a missing table or nft binary diffs against empty.
	// Include the NAT tables so NAT rules don't show as spurious diffs.
	var have []byte
	for _, spec := range [][2]string{
		{"inet", nftbe.TableName},
		{"ip", nftbe.NATTableName},
		{"ip6", nftbe.NATTableName},
	} {
		out, _ := exec.Command("nft", "-nn", "list", "table", spec[0], spec[1]).Output()
		have = append(have, out...)
	}
	a := normalizeNft(want)
	b := normalizeNft(string(have))
	if len(a) == len(b) {
		same := true
		for i := range a {
			if a[i] != b[i] {
				same = false
				break
			}
		}
		if same {
			e.Msg("Ruleset matches stored state")
			return 0
		}
	}
	e.Msg("%s", unifiedDiff("stored", "kernel", a, b))
	return 1
}

// ---------------------------------------------------------------- panic

func (e *Env) cmdPanic(args []string) int {
	off := false
	switch {
	case len(args) == 0:
	case len(args) == 1 && args[0] == "off":
		off = true
	default:
		e.Msg("%s", HelpText(e.Prog))
		return 1
	}
	if !e.checkRoot() {
		return 1
	}
	release, rc := e.acquireLock()
	if release == nil {
		return rc
	}
	defer release()
	st, err := e.Store.Load()
	if err != nil {
		return e.Errorf("%v", err)
	}
	if !off {
		if st.Panic {
			e.Msg("Already in panic mode")
			return 0
		}
		if hookUnderSSH() && !e.Force {
			return e.Errorf("refusing to panic over ssh without --force")
		}
		if !e.DryRun {
			// Apply a drop-all copy; stored policies stay untouched so
			// `panic off` restores them. Applies even when disabled:
			// panic is an emergency measure.
			pst := *st
			pst.Panic = true // bare drop-all chains; also bypasses etc overrides
			pst.Policies = store.Policies{Input: "deny", Output: "deny", Forward: "deny"}
			etc, err := e.Store.EtcDefaults()
			if err != nil {
				return e.Errorf("%v", err)
			}
			if rc := e.applyRuleset(&pst, etc); rc != 0 {
				return rc
			}
			st.Panic = true
			if err := e.Store.Save(st); err != nil {
				return e.Errorf("%v", err)
			}
		}
		e.Msg("Panic mode ON: all traffic dropped")
		return 0
	}
	if !st.Panic {
		e.Msg("Not in panic mode")
		return 0
	}
	if !e.DryRun {
		st.Panic = false
		if err := e.Store.Save(st); err != nil {
			return e.Errorf("%v", err)
		}
		if e.live() {
			etc, err := e.Store.EtcDefaults()
			if err != nil {
				return e.Errorf("%v", err)
			}
			if rc := e.applyRuleset(st, etc); rc != 0 {
				return rc
			}
		} else if b, err := e.backend(); err == nil {
			// Panic may have created the table while disabled; remove it.
			_ = b.Flush()
		}
	}
	e.Msg("Panic mode OFF")
	return 0
}

// ---------------------------------------------------------------- sweep

// expiredCount returns the number of expired rules across both lists.
func expiredCount(st *store.State, now int64) int {
	n := 0
	for _, list := range [][]rule.Rule{st.Rules4, st.Rules6} {
		for i := range list {
			if list[i].Expired(now) {
				n++
			}
		}
	}
	return n
}

func (e *Env) cmdSweep(args []string) int {
	if len(args) != 0 {
		e.Msg("%s", HelpText(e.Prog))
		return 1
	}
	if !e.checkRoot() {
		return 1
	}
	release, rc := e.acquireLock()
	if release == nil {
		return rc
	}
	defer release()
	st, err := e.Store.Load()
	if err != nil {
		return e.Errorf("%v", err)
	}
	n := expiredCount(st, time.Now().Unix())
	if n == 0 {
		e.Msg("Removed 0 expired rule(s)")
		return 0
	}
	// commitState sweeps the expired rules, saves, and applies when live.
	return e.commitState(st, fmt.Sprintf("Removed %d expired rule(s)", n))
}

// ---------------------------------------------------------------- rule

func (e *Env) cmdRule(args []string) int {
	if len(args) != 2 || (args[0] != "enable" && args[0] != "disable") {
		e.Msg("%s", HelpText(e.Prog))
		return 1
	}
	n, err := strconv.Atoi(args[1])
	if err != nil {
		return e.Errorf("Could not find rule")
	}
	if !e.checkRoot() {
		return 1
	}
	release, rc := e.acquireLock()
	if release == nil {
		return rc
	}
	defer release()
	st, err := e.Store.Load()
	if err != nil {
		return e.Errorf("%v", err)
	}
	// NUM is the displayed line; ruleByNumber maps it like status numbered.
	idx, v6, ok := ruleByNumber(st, n)
	if !ok {
		return e.Errorf("Could not find rule")
	}
	// App rules expand to one member per port item, each with a fresh ID;
	// toggling by ID hits only one member. Match the whole app tuple like
	// ufw's get_app_rules_from_system expansion.
	target := st.Rules4[idx]
	if v6 {
		target = st.Rules6[idx]
	}
	tuple := target.AppTuple()
	isApp := target.Dapp != "" || target.Sapp != ""
	disabled := args[0] == "disable"
	for _, lp := range []*[]rule.Rule{&st.Rules4, &st.Rules6} {
		for i := range *lp {
			r := &(*lp)[i]
			if isApp && r.AppTuple() == tuple {
				r.Disabled = disabled
			} else if !isApp && r.ID == target.ID {
				r.Disabled = disabled
			}
		}
	}
	if disabled {
		return e.commitState(st, "Rule disabled")
	}
	return e.commitState(st, "Rule enabled")
}

// ---------------------------------------------------------------- logs

// lineFilter copies only lines containing substr.
type lineFilter struct {
	w      io.Writer
	substr []byte
	buf    []byte
}

func (f *lineFilter) Write(p []byte) (int, error) {
	f.buf = append(f.buf, p...)
	for {
		i := bytes.IndexByte(f.buf, '\n')
		if i < 0 {
			break
		}
		line := f.buf[:i+1]
		f.buf = f.buf[i+1:]
		if bytes.Contains(line, f.substr) {
			if _, err := f.w.Write(line); err != nil {
				return 0, err
			}
		}
	}
	return len(p), nil
}

func (e *Env) cmdLogs(args []string) int {
	if len(args) != 0 {
		e.Msg("%s", HelpText(e.Prog))
		return 1
	}
	if !e.checkRoot() {
		return 1
	}
	var cmd *exec.Cmd
	if path, err := hookLookPath("journalctl"); err == nil {
		cmd = exec.Command(path, "-kf", "-g", "BFW")
		cmd.Stdout = e.Stdout
	} else {
		var logfile string
		for _, p := range []string{"/var/log/kern.log", "/var/log/syslog"} {
			if _, err := os.Stat(p); err == nil {
				logfile = p
				break
			}
		}
		if logfile == "" {
			return e.Errorf("no log source found")
		}
		cmd = exec.Command("tail", "-F", logfile)
		cmd.Stdout = &lineFilter{w: e.Stdout, substr: []byte("BFW")}
	}
	cmd.Stderr = e.Stderr
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			if code := ee.ExitCode(); code > 0 {
				return code
			}
			return 0 // killed by signal (e.g. Ctrl-C on -f)
		}
		return e.Errorf("%v", err)
	}
	return 0
}

// validToDest validates a dnat to-destination: bare IP, [v6]:port, or
// v4 host:port. Rejects anything the compiler can't express.
func validToDest(s string) bool {
	if net.ParseIP(s) != nil {
		return true // bare v4 or v6
	}
	if strings.HasPrefix(s, "[") {
		h, rest, ok := strings.Cut(s[1:], "]")
		if !ok || net.ParseIP(h) == nil {
			return false
		}
		if rest == "" {
			return true
		}
		if !strings.HasPrefix(rest, ":") {
			return false
		}
		p, err := strconv.Atoi(rest[1:])
		return err == nil && p >= 1 && p <= 65535
	}
	// v4 host:port
	h, p, ok := strings.Cut(s, ":")
	if !ok || net.ParseIP(h) == nil || net.ParseIP(h).To4() == nil {
		return false
	}
	pn, err := strconv.Atoi(p)
	return err == nil && pn >= 1 && pn <= 65535
}

// dropSetRefs removes rules whose src or dst references the named set.
func dropSetRefs(rules []rule.Rule, name string) []rule.Rule {
	out := rules[:0]
	for _, r := range rules {
		if r.Src.Set == name || r.Dst.Set == name {
			continue
		}
		out = append(out, r)
	}
	return out
}

// mapFibType maps a fib addrtype name to the number `nft -nn` prints.
func mapFibType(t string) string {
	switch t {
	case "unspec":
		return "0"
	case "unicast":
		return "1"
	case "local":
		return "2"
	case "broadcast":
		return "3"
	case "anycast":
		return "4"
	case "multicast":
		return "5"
	}
	return t
}

// splitToDestCLI splits a to-destination into host and optional port for
// CLI-side family validation (mirrors the backend's splitToDest).
func splitToDestCLI(s string) (host, port string) {
	if strings.HasPrefix(s, "[") {
		if h, rest, ok := strings.Cut(s[1:], "]"); ok {
			if strings.HasPrefix(rest, ":") {
				return h, rest[1:]
			}
			return h, ""
		}
	}
	if strings.Count(s, ":") > 1 {
		return s, "" // bare v6
	}
	if h, p, ok := strings.Cut(s, ":"); ok {
		return h, p
	}
	return s, ""
}
