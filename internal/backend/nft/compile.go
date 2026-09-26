// compile.go translates the persistent firewall model (store.State) into
// nftables objects for `table inet better-firewall` plus optional per-family NAT
// tables. The chain layout mirrors ufw's iptables layout (ufw-* → bfw-*):
//
//	base chain input/output/forward (policy = configured)
//	  → bfw-before-logging-<dir>   (audit logging, medium+)
//	  → bfw-before-<dir>           (ufw before.rules defaults, then
//	                              jump bfw-user-<dir>)
//	  → bfw-after-<dir>            (empty; after.rules fragments land here)
//	  → bfw-after-logging-<dir>    (policy-mismatch logging, low+)
//	  → bfw-reject-<dir>           (terminal reject when policy=reject)
//	  → bfw-track-<dir>            (ct new tcp/udp accept when policy=accept)
//
// Verified against ufw 0.36.2 ufw-init-functions + conf/before{,6}.rules +
// backend_iptables.py (_get_logging_rules, _get_rules_from_formatted).
package nft

import (
	"bytes"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"github.com/tmih06/better-firewall/internal/rule"
	"github.com/tmih06/better-firewall/internal/store"
)

// Chain names (ufw-* equivalents).
const (
	chNotLocal   = "bfw-not-local"
	chLogDeny    = "bfw-logging-deny"
	chLogAllow   = "bfw-logging-allow"
	chUserLimit  = "bfw-user-limit"
	chUserLimitA = "bfw-user-limit-accept"
	chUserEgress = "bfw-user-egress"
)

var directions = []struct {
	dir  string // model direction
	base string // base chain name
	hook *nftables.ChainHook
}{
	{"in", "input", nftables.ChainHookInput},
	{"out", "output", nftables.ChainHookOutput},
	{"routed", "forward", nftables.ChainHookForward},
}

func baseFor(dir string) string {
	switch dir {
	case "out":
		return "output"
	case "routed":
		return "forward"
	default:
		return "input"
	}
}

// compiled is the full object graph for one Apply batch.
type compiled struct {
	table       *nftables.Table
	chains      []*nftables.Chain
	chainIndex  map[string]*nftables.Chain
	sets        []*nftables.Set
	elems       map[*nftables.Set][]nftables.SetElement
	rules       []*nftables.Rule
	natTables   []*nftables.Table
	setID       uint32
	threatBans4 *nftables.Set
	threatBans6 *nftables.Set
}

// newSetID pre-assigns kernel set IDs at compile time so Lookup/Dynset
// expressions (which capture SetID/SetName by value) reference the same
// IDs AddSet later sends in the batch.
func (c *compiled) newSetID() uint32 {
	c.setID++
	return c.setID
}

func (c *compiled) chain(name string) *nftables.Chain {
	if ch, ok := c.chainIndex[name]; ok {
		return ch
	}
	ch := &nftables.Chain{Name: name, Table: c.table}
	c.chains = append(c.chains, ch)
	c.chainIndex[name] = ch
	return ch
}

func (c *compiled) addRule(chain string, exprs ...expr.Any) {
	c.rules = append(c.rules, &nftables.Rule{
		Table: c.table, Chain: c.chain(chain), Exprs: exprs,
	})
}

// compile builds the complete ruleset for st. etc carries /etc/default
// values; IPV6 there overrides st.IPv6 when present (same precedence ufw
// gives /etc/default/ufw).
func compile(st *store.State, etc map[string]string) (*compiled, error) {
	c := &compiled{
		table:      &nftables.Table{Family: nftables.TableFamilyINet, Name: TableName},
		chainIndex: map[string]*nftables.Chain{},
		elems:      map[*nftables.Set][]nftables.SetElement{},
	}

	pol := st.Policies
	if st.Panic {
		pol = store.Policies{Input: "deny", Output: "deny", Forward: "deny"}
	}
	// /etc/default/better-firewall DEFAULT_*_POLICY keys override stored policies
	// (ufw reads them from /etc/default/ufw at apply time) — but never
	// override panic's forced deny-all.
	if !st.Panic {
		for k, dst := range map[string]*string{
			"DEFAULT_INPUT_POLICY":   &pol.Input,
			"DEFAULT_OUTPUT_POLICY":  &pol.Output,
			"DEFAULT_FORWARD_POLICY": &pol.Forward,
		} {
			if v, ok := etc[k]; ok {
				switch strings.ToLower(v) {
				case "accept", "allow":
					*dst = "allow"
				case "drop", "deny":
					*dst = "deny"
				case "reject":
					*dst = "reject"
				}
			}
		}
	}
	ipv6 := st.IPv6
	if v, ok := etc["IPV6"]; ok {
		ipv6 = strings.EqualFold(v, "yes")
	}
	level := st.Logging
	if level == "" {
		level = "low"
	}
	now := time.Now().Unix()

	// Panic mode: bare drop-policy base chains, nothing else. No user
	// rules, no established-accept, no NAT — panic must drop ALL traffic.
	if st.Panic {
		for _, d := range directions {
			cp := nftables.ChainPolicyDrop
			c.chains = append(c.chains, &nftables.Chain{
				Name: d.base, Table: c.table, Hooknum: d.hook,
				Priority: nftables.ChainPriorityFilter,
				Type:     nftables.ChainTypeFilter, Policy: &cp,
			})
		}
		return c, nil
	}

	// ---- base chains -----------------------------------------------------
	policies := map[string]string{"in": pol.Input, "out": pol.Output, "routed": pol.Forward}
	for _, d := range directions {
		p := policies[d.dir]
		cp := nftables.ChainPolicyAccept
		if p != "allow" {
			cp = nftables.ChainPolicyDrop // deny and reject both map to drop
		}
		base := &nftables.Chain{
			Name:     d.base,
			Table:    c.table,
			Hooknum:  d.hook,
			Priority: nftables.ChainPriorityFilter,
			Type:     nftables.ChainTypeFilter,
			Policy:   &cp,
		}
		c.chains = append(c.chains, base)
		c.chainIndex[d.base] = base

		if !ipv6 {
			// ufw IPV6=no: drop all v6 except loopback.
			switch d.dir {
			case "in":
				c.addRule(d.base, join(nfproto(true), iif("lo"), ex(counter(), verdict(expr.VerdictAccept)))...)
			case "out":
				c.addRule(d.base, join(nfproto(true), oif("lo"), ex(counter(), verdict(expr.VerdictAccept)))...)
			}
			c.addRule(d.base, join(nfproto(true), ex(counter(), verdict(expr.VerdictDrop)))...)
		}

		// ufw-init-functions jump order. The user jump lives in the base
		// chain (not inside bfw-before-*) so before.rules fragments appended
		// later still run before user rules, and a fragment `flush chain`
		// can't delete the user jump.
		for _, suffix := range []string{"before-logging-", "before-", "user-", "after-", "after-logging-", "reject-", "track-"} {
			c.addRule(d.base, counter(), jump("bfw-"+suffix+d.base))
		}
	}
	// Pre-create every regular chain (ufw creates them all even when
	// empty) in ufw's declaration order.
	for _, prefix := range []string{
		"bfw-before-logging-", "bfw-before-", "bfw-user-", "bfw-after-",
		"bfw-after-logging-", "bfw-user-logging-", "bfw-reject-",
		"bfw-track-", "bfw-skip-to-policy-",
	} {
		for _, d := range directions {
			c.chain(prefix + d.base)
		}
	}
	for _, name := range []string{chNotLocal, chLogDeny, chLogAllow, chUserLimit, chUserLimitA, chUserEgress} {
		c.chain(name)
	}
	// ---- before-* chains: ufw before.rules + before6.rules defaults ------
	if err := c.compileThreatBans(st, now); err != nil {
		return nil, err
	}
	c.compileBefore()
	// ---- after-* chains: ufw after.rules + after6.rules defaults --------
	c.compileAfter()
	// bfw extension: dedicated egress chain after user-output.
	c.addRule("bfw-before-output", counter(), jump(chUserEgress))

	// ---- reject / track / skip-to-policy / limit / logging chains --------
	for _, d := range directions {
		if policies[d.dir] == "reject" {
			c.addRule("bfw-reject-"+d.base, counter(), rejectExpr())
		}
		if policies[d.dir] == "allow" {
			// ufw track chains: statefully accept new tcp/udp so the
			// accept policy is conntrack-aware.
			for _, proto := range []byte{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
				c.addRule("bfw-track-"+d.base,
					join(l4proto(proto), ctState(expr.CtStateBitNEW),
						ex(counter(), verdict(expr.VerdictAccept)))...)
			}
		}
		// skip-to-policy chains exist so after.rules fragments can jump
		// noisy traffic straight to the policy verdict (ufw parity).
		c.addRule("bfw-skip-to-policy-"+d.base, counter(), policyVerdict(policies[d.dir]))
	}
	c.addRule(chUserLimitA, counter(), verdict(expr.VerdictAccept))
	if level != "off" {
		// ufw_user_limit_log is --limit 3/minute with iptables' default
		// burst 5 (not the shared burst-10 limit3).
		c.addRule(chUserLimit,
			&expr.Limit{Type: expr.LimitTypePkts, Rate: 3, Unit: expr.LimitTimeMinute, Burst: 5},
			logExpr("[BFW LIMIT BLOCK] "))
	}
	c.addRule(chUserLimit, counter(), rejectExpr())

	c.compileLoggingChains(level, policies)

	// ---- named sets (bfw extension) --------------------------------------
	if err := c.compileNamedSets(st); err != nil {
		return nil, err
	}

	// ---- user rules --------------------------------------------------------
	for i := range st.Rules4 {
		if err := c.compileRule(&st.Rules4[i], false, now); err != nil {
			return nil, err
		}
	}
	for i := range st.Rules6 {
		if err := c.compileRule(&st.Rules6[i], true, now); err != nil {
			return nil, err
		}
	}

	// ---- NAT ---------------------------------------------------------------
	if err := c.compileNAT(st); err != nil {
		return nil, err
	}

	return c, nil
}

func (c *compiled) addThreatBanRules(chain string) {
	for _, family := range []struct {
		set *nftables.Set
		v6  bool
	}{{c.threatBans4, false}, {c.threatBans6, true}} {
		if family.set == nil {
			continue
		}
		offset, length := uint32(12), uint32(4)
		if family.v6 {
			offset, length = 8, 16
		}
		match := join(nfproto(family.v6), ex(
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: length},
			&expr.Lookup{SourceRegister: 1, SetName: family.set.Name, SetID: family.set.ID},
		), ex(counter(), verdict(expr.VerdictDrop)))
		c.addRule(chain, match...)
	}
}

// compileBefore emits the ufw before.rules/before6.rules equivalent rules.
// The inet table handles both families in one chain, so v6 rules carry a
// `meta nfproto ipv6` guard and v4 rules `meta nfproto ipv4`.
func (c *compiled) compileBefore() {
	in, out, fwd := "bfw-before-input", "bfw-before-output", "bfw-before-forward"

	// loopback
	c.addRule(in, join(iif("lo"), ex(counter(), verdict(expr.VerdictAccept)))...)
	c.addRule(out, join(oif("lo"), ex(counter(), verdict(expr.VerdictAccept)))...)

	// RH0 drop (v6): rt type 0 = exthdr routing-header type byte (offset 2)
	for _, ch := range []string{in, out, fwd} {
		c.addRule(ch, join(nfproto(true), rhType(0), ex(counter(), verdict(expr.VerdictDrop)))...)
	}

	c.addThreatBanRules(in)
	c.addThreatBanRules(fwd)

	// established/related fast path
	for _, ch := range []string{in, out, fwd} {
		c.addRule(ch, join(ctState(expr.CtStateBitESTABLISHED|expr.CtStateBitRELATED),
			ex(counter(), verdict(expr.VerdictAccept)))...)
	}

	// v6 multicast ping replies arrive without conntrack state (rfc4890)
	c.addRule(in, join(nfproto(true), l4proto(unix.IPPROTO_ICMPV6), icmpType(129),
		ex(counter(), verdict(expr.VerdictAccept)))...)

	// INVALID → logging-deny then drop (ufw logs INVALID at medium+)
	c.addRule(in, join(ctState(expr.CtStateBitINVALID), ex(counter(), jump(chLogDeny)))...)
	c.addRule(in, join(ctState(expr.CtStateBitINVALID), ex(counter(), verdict(expr.VerdictDrop)))...)

	// ICMPv4 accepts (before.rules): destination-unreachable, time-exceeded,
	// parameter-problem, echo-request. (ufw dropped source-quench in 0.36.)
	for _, ch := range []string{in, fwd} {
		for _, t := range []byte{3, 11, 12, 8} {
			c.addRule(ch, join(nfproto(false), l4proto(unix.IPPROTO_ICMP), icmpType(t),
				ex(counter(), verdict(expr.VerdictAccept)))...)
		}
	}

	// ICMPv6 accepts (before6.rules, rfc4890). hl = hop limit @ nh+1.
	type ic6 struct {
		typ     byte
		hl      int // -1 = no hop-limit match
		srcCIDR string
	}
	v6rules := []ic6{
		{1, -1, ""}, {2, -1, ""}, {3, -1, ""}, {4, -1, ""}, {128, -1, ""},
		{133, 255, ""}, {134, 255, ""}, {135, 255, ""}, {136, 255, ""},
		{141, 255, ""}, {142, 255, ""},
		{130, -1, "fe80::/10"}, {131, -1, "fe80::/10"}, {132, -1, "fe80::/10"}, {143, -1, "fe80::/10"},
		{148, 255, ""}, {149, 255, ""},
		{151, 1, "fe80::/10"}, {152, 1, "fe80::/10"}, {153, 1, "fe80::/10"},
	}
	emit6 := func(ch string, list []ic6) {
		for _, r := range list {
			ex := join(nfproto(true), l4proto(unix.IPPROTO_ICMPV6), icmpType(r.typ))
			if r.srcCIDR != "" {
				ex = append(ex, addrMatch("saddr", r.srcCIDR, true)...)
			}
			if r.hl >= 0 {
				ex = append(ex, hopLimit(byte(r.hl))...)
			}
			ex = append(ex, counter(), verdict(expr.VerdictAccept))
			c.addRule(ch, ex...)
		}
	}
	emit6(in, v6rules)
	// output adds echo-reply after echo-request
	out6 := append([]ic6{}, v6rules[:5]...)
	out6 = append(out6, ic6{129, -1, ""})
	out6 = append(out6, v6rules[5:]...)
	emit6(out, out6)
	// forward: base set + echo-reply only (rfc4890 4.3.1)
	emit6(fwd, []ic6{{1, -1, ""}, {2, -1, ""}, {3, -1, ""}, {4, -1, ""}, {128, -1, ""}, {129, -1, ""}})
	// HAAD/MPS/MPA (before6.rules places these on input)
	for _, t := range []byte{144, 145, 146, 147} {
		c.addRule(in, join(nfproto(true), l4proto(unix.IPPROTO_ICMPV6), icmpType(t),
			ex(counter(), verdict(expr.VerdictAccept)))...)
	}

	// DHCP client: v4 udp 67→68; v6 link-local 547→546
	c.addRule(in, join(nfproto(false), l4proto(unix.IPPROTO_UDP),
		portEq("sport", 67), portEq("dport", 68),
		ex(counter(), verdict(expr.VerdictAccept)))...)
	c.addRule(in, join(nfproto(true), l4proto(unix.IPPROTO_UDP),
		addrMatch("saddr", "fe80::/10", true), portEq("sport", 547),
		addrMatch("daddr", "fe80::/10", true), portEq("dport", 546),
		ex(counter(), verdict(expr.VerdictAccept)))...)

	// non-local drop (v4 only in ufw: before6.rules has no not-local chain)
	c.addRule(in, join(nfproto(false), ex(counter(), jump(chNotLocal)))...)
	for _, t := range []uint32{unix.RTN_LOCAL, unix.RTN_MULTICAST, unix.RTN_BROADCAST} {
		c.addRule(chNotLocal, join(fibAddrType(t), ex(counter(), verdict(expr.VerdictReturn)))...)
	}
	c.addRule(chNotLocal, limit3(), counter(), jump(chLogDeny))
	c.addRule(chNotLocal, counter(), verdict(expr.VerdictDrop))

	// mDNS + UPnP multicast
	c.addRule(in, join(nfproto(false), l4proto(unix.IPPROTO_UDP),
		addrMatch("daddr", "224.0.0.251", false), portEq("dport", 5353),
		ex(counter(), verdict(expr.VerdictAccept)))...)
	c.addRule(in, join(nfproto(true), l4proto(unix.IPPROTO_UDP),
		addrMatch("daddr", "ff02::fb", true), portEq("dport", 5353),
		ex(counter(), verdict(expr.VerdictAccept)))...)
	c.addRule(in, join(nfproto(false), l4proto(unix.IPPROTO_UDP),
		addrMatch("daddr", "239.255.255.250", false), portEq("dport", 1900),
		ex(counter(), verdict(expr.VerdictAccept)))...)
	c.addRule(in, join(nfproto(true), l4proto(unix.IPPROTO_UDP),
		addrMatch("daddr", "ff02::f", true), portEq("dport", 1900),
		ex(counter(), verdict(expr.VerdictAccept)))...)
}

// compileAfter emits ufw's after.rules/after6.rules defaults: noisy
// broadcast/NetBIOS/DHCP traffic is jumped to skip-to-policy so it takes
// the policy verdict without logging (suppresses log spam).
func (c *compiled) compileAfter() {
	in := "bfw-after-input"
	skip := "bfw-skip-to-policy-input"

	// v4: broadcast dest, NetBIOS/SMB, DHCP server+client ports.
	c.addRule(in, join(nfproto(false), fibAddrType(unix.RTN_BROADCAST),
		ex(counter(), jump(skip)))...)
	for _, p := range []uint16{137, 138} {
		c.addRule(in, join(nfproto(false), l4proto(unix.IPPROTO_UDP), portEq("dport", p),
			ex(counter(), jump(skip)))...)
	}
	for _, p := range []uint16{139, 445} {
		c.addRule(in, join(nfproto(false), l4proto(unix.IPPROTO_TCP), portEq("dport", p),
			ex(counter(), jump(skip)))...)
	}
	c.addRule(in, join(nfproto(false), l4proto(unix.IPPROTO_UDP),
		portEq("sport", 67), portEq("dport", 68),
		ex(counter(), jump(skip)))...)

	// v6: DHCPv6 server+client ports (after6.rules).
	for _, p := range []uint16{546, 547} {
		c.addRule(in, join(nfproto(true), l4proto(unix.IPPROTO_UDP), portEq("dport", p),
			ex(counter(), jump(skip)))...)
	}
}

// compileLoggingChains emits the level-dependent contents of the logging
// chains, mirroring backend_iptables.py _get_logging_rules.
func (c *compiled) compileLoggingChains(level string, policies map[string]string) {
	userLogging := []string{}
	for _, d := range directions {
		userLogging = append(userLogging, "bfw-user-logging-"+d.base)
	}

	if level == "off" {
		// RETURN at top of user-logging chains preserves the log rules
		// beneath while disabling them (ufw parity).
		for _, ch := range userLogging {
			c.addRule(ch, counter(), verdict(expr.VerdictReturn))
		}
		return
	}

	limited := level != "high" && level != "full"
	limitExpr := func() []expr.Any {
		if limited {
			return []expr.Any{limit3()}
		}
		return nil
	}

	// low+: after-logging logs packets about to hit a deny/reject policy;
	// medium+ also logs packets about to hit an accept policy.
	for _, d := range directions {
		ch := "bfw-after-logging-" + d.base
		p := policies[d.dir]
		switch {
		case p == "deny" || p == "reject":
			ex := append(limitExpr(), logExpr("[BFW BLOCK] "))
			c.addRule(ch, ex...)
		case level != "low": // medium+
			ex := append(limitExpr(), logExpr("[BFW ALLOW] "))
			c.addRule(ch, ex...)
		}
	}

	// misc chains: logging-deny / logging-allow.
	for _, ch := range []string{chLogDeny, chLogAllow} {
		prefix := "[BFW ALLOW] "
		if ch == chLogDeny {
			prefix = "[BFW BLOCK] "
			if level == "low" {
				// ufw rate-limits the INVALID RETURN (limit_args appended):
				// beyond 3/min INVALIDs fall through to the BLOCK log.
				c.addRule(ch, join(ctState(expr.CtStateBitINVALID), limitExpr(),
					ex(counter(), verdict(expr.VerdictReturn)))...)
			} else {
				ex := ctState(expr.CtStateBitINVALID)
				ex = append(ex, limitExpr()...)
				ex = append(ex, logExpr("[BFW AUDIT INVALID] "))
				c.addRule(ch, ex...)
			}
		}
		ex := limitExpr()
		ex = append(ex, logExpr(prefix))
		c.addRule(ch, ex...)
	}

	// medium+: before-logging audit chains.
	if level != "low" {
		for _, d := range directions {
			ch := "bfw-before-logging-" + d.base
			var ex []expr.Any
			switch level {
			case "medium": // new connections only, rate-limited
				ex = append(ctState(expr.CtStateBitNEW), limit3())
			case "high": // all packets, rate-limited
				ex = []expr.Any{limit3()}
			case "full": // all packets, unlimited
				ex = nil
			}
			ex = append(ex, logExpr("[BFW AUDIT] "))
			c.addRule(ch, ex...)
		}
	}
}

// compileNamedSets turns st.Sets into interval sets. Both address families
// are always created so rule lookups never reference a missing set.
func (c *compiled) compileNamedSets(st *store.State) error {
	for _, s := range st.Sets {
		if _, _, err := c.compileAddressSet(
			"bfw_set_"+s.Name, "bfw_set_"+s.Name+"6", "set "+s.Name, s.Elements,
		); err != nil {
			return err
		}
	}
	return nil
}

func (c *compiled) compileThreatBans(st *store.State, now int64) error {
	addresses := make([]string, 0, len(st.Bans))
	for _, ban := range st.Bans {
		if ban.ExpiresAt > now {
			addresses = append(addresses, ban.Address)
		}
	}
	var err error
	c.threatBans4, c.threatBans6, err = c.compileAddressSet(
		"bfw_threat_bans", "bfw_threat_bans6", "threat ban", addresses,
	)
	return err
}

func (c *compiled) compileAddressSet(name4, name6, source string, elements []string) (*nftables.Set, *nftables.Set, error) {
	v4 := &nftables.Set{
		Table: c.table, Name: name4, ID: c.newSetID(),
		KeyType: nftables.TypeIPAddr, Interval: true,
	}
	v6 := &nftables.Set{
		Table: c.table, Name: name6, ID: c.newSetID(),
		KeyType: nftables.TypeIP6Addr, Interval: true,
	}
	c.sets = append(c.sets, v4, v6)
	var iv4, iv6 [][2][]byte // [start, endExclusive)
	for _, element := range elements {
		_, ipnet, err := net.ParseCIDR(element)
		if err != nil {
			ip := net.ParseIP(element)
			if ip == nil {
				return nil, nil, fmt.Errorf("%s: bad element %q", source, element)
			}
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
		}
		start := canonIP(ipnet.IP.Mask(ipnet.Mask))
		end := addOne(canonIP(lastAddr(ipnet)))
		if len(start) == 16 {
			iv6 = append(iv6, [2][]byte{start, end})
		} else {
			iv4 = append(iv4, [2][]byte{start, end})
		}
	}
	// Overlapping intervals make the kernel reject the whole batch
	// (__nft_rbtree_insert ENOTEMPTY); merge like nft does.
	for set, intervals := range map[*nftables.Set][][2][]byte{v4: iv4, v6: iv6} {
		for _, interval := range mergeIntervals(intervals) {
			c.elems[set] = append(c.elems[set],
				nftables.SetElement{Key: interval[0]},
				nftables.SetElement{Key: interval[1], IntervalEnd: true})
		}
	}
	return v4, v6, nil
}

// mergeIntervals sorts and coalesces overlapping/adjacent [start,end)
// intervals so the kernel accepts them in one batch.
func mergeIntervals(ivs [][2][]byte) [][2][]byte {
	if len(ivs) == 0 {
		return nil
	}
	sort.Slice(ivs, func(i, j int) bool {
		return bytes.Compare(ivs[i][0], ivs[j][0]) < 0
	})
	out := [][2][]byte{ivs[0]}
	for _, iv := range ivs[1:] {
		last := &out[len(out)-1]
		// iv.start <= last.end → overlap or adjacency: extend end.
		if bytes.Compare(iv[0], last[1]) <= 0 {
			if bytes.Compare(iv[1], last[1]) > 0 {
				last[1] = iv[1]
			}
			continue
		}
		out = append(out, iv)
	}
	return out
}

// compileRule emits the nft rules for one model rule into the appropriate
// bfw-user-* chain (and bfw-user-logging-* when logged).
func (c *compiled) compileRule(r *rule.Rule, v6 bool, now int64) error {
	if r.Disabled || r.Expired(now) {
		return nil
	}
	base := baseFor(r.Direction)
	userChain := "bfw-user-" + base
	logChain := "bfw-user-logging-" + base

	variants, variantCount := protoVariants(r)
	for _, proto := range variants[:variantCount] {
		match, err := c.ruleMatch(r, proto, v6)
		if err != nil {
			return err
		}
		if r.Log != rule.LogNone {
			// logged rules jump the user-logging chain first (ufw parity):
			// the chain holds [limit? log prefix, return] per rule. The
			// RETURN must carry the same match — an unconditional return
			// would shadow every later logged rule in the chain.
			lm := append([]expr.Any{}, match...)
			if r.Log == rule.LogNew {
				lm = append(lm, ctState(expr.CtStateBitNEW)...)
			}
			lm = append(lm, limit3(), logExpr(logPrefix(r.Action)))
			c.addRule(logChain, lm...)
			rm := append([]expr.Any{}, match...)
			if r.Log == rule.LogNew {
				rm = append(rm, ctState(expr.CtStateBitNEW)...)
			}
			c.addRule(logChain, append(rm, counter(), verdict(expr.VerdictReturn))...)
			c.addRule(userChain, append(append([]expr.Any{}, match...), counter(), jump(logChain))...)
		}
		switch r.Action {
		case rule.ActionAllow:
			c.addRule(userChain, append(append([]expr.Any{}, match...), counter(), verdict(expr.VerdictAccept))...)
		case rule.ActionDeny:
			c.addRule(userChain, append(append([]expr.Any{}, match...), counter(), verdict(expr.VerdictDrop))...)
		case rule.ActionReject:
			c.addRule(userChain, append(append([]expr.Any{}, match...), counter(), rejectExpr())...)
		case rule.ActionLimit:
			if err := c.compileLimit(r, proto, v6, match, userChain); err != nil {
				return err
			}
		default:
			return fmt.Errorf("rule %s: unknown action %q", r.ID, r.Action)
		}
	}
	return nil
}

// compileLimit emits the meter idiom for a limit rule: a dynamic set
// bfw_limit_<id> keyed on saddr.dport; packets over 6/minute jump
// bfw-user-limit (log+reject), the rest fall through to
// bfw-user-limit-accept. Approximates ufw's recent --seconds 30 --hitcount 6.
func (c *compiled) compileLimit(r *rule.Rule, proto string, v6 bool, match []expr.Any, userChain string) error {
	addrType := nftables.TypeIPAddr
	if v6 {
		addrType = nftables.TypeIP6Addr
	}
	name := "bfw_limit_" + r.ID
	if v6 {
		name += "6" // dual v4/v6 rules share r.ID; qualify the set name
	}
	// Reuse an existing dynset of the same name: a proto-any limit rule
	// expands to tcp+udp variants that share r.ID, and emitting the set
	// twice would double it in render/diff (the kernel dedups by name).
	var set *nftables.Set
	for _, s := range c.sets {
		if s.Name == name {
			set = s
			break
		}
	}
	if set == nil {
		set = &nftables.Set{
			Table:         c.table,
			Name:          name,
			ID:            c.newSetID(),
			KeyType:       nftables.MustConcatSetType(addrType, nftables.TypeInetService),
			Concatenation: true,
			Dynamic:       true,
			HasTimeout:    true,
			Timeout:       30 * time.Second,
			// size 0 makes the kernel refuse the first element add
			// (atomic_add_unless nelems vs size) → the meter never fires and
			// the rule fails open. nft defaults meter sets to 65535.
			Size: 65535,
		}
		c.sets = append(c.sets, set)
	}

	// Key registers: saddr then dport, contiguous in the kernel's reg32
	// space. v4: NFT_REG32_00 (data[4]) + NFT_REG32_01 (data[5]).
	// v6: NFT_REG_1 (data[4..7]) + NFT_REG_2 (data[8..11]).
	sreg, preg := uint32(unix.NFT_REG32_00), uint32(unix.NFT_REG32_01)
	saddrOff, saddrLen := uint32(12), uint32(4)
	if v6 {
		sreg, preg = unix.NFT_REG_1, unix.NFT_REG_2
		saddrOff, saddrLen = 8, 16
	}

	ex := append([]expr.Any{}, match...)
	ex = append(ex,
		ctState(expr.CtStateBitNEW)...,
	)
	ex = append(ex,
		&expr.Payload{DestRegister: sreg, Base: expr.PayloadBaseNetworkHeader, Offset: saddrOff, Len: saddrLen},
	)
	if proto == "tcp" || proto == "udp" {
		ex = append(ex, &expr.Payload{DestRegister: preg, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2})
	} else {
		ex = append(ex, &expr.Immediate{Register: preg, Data: []byte{0, 0}})
	}
	ex = append(ex,
		&expr.Dynset{
			SrcRegKey: sreg,
			SetName:   set.Name,
			SetID:     set.ID,
			Operation: unix.NFT_DYNSET_OP_UPDATE,
			Timeout:   30 * time.Second,
			Exprs: []expr.Any{&expr.Limit{
				Type: expr.LimitTypePkts, Rate: 6, Over: true, Unit: expr.LimitTimeMinute,
			}},
		},
		counter(),
		jump(chUserLimit),
	)
	c.addRule(userChain, ex...)
	c.addRule(userChain, append(append([]expr.Any{}, match...), counter(), jump(chUserLimitA))...)
	return nil
}

// ruleMatch builds the match expression list (everything before the
// counter/verdict) for one rule+proto variant.
func (c *compiled) ruleMatch(r *rule.Rule, proto string, v6 bool) ([]expr.Any, error) {
	if proto == "icmp" && v6 {
		return nil, fmt.Errorf("rule %s: proto icmp is IPv4-only", r.ID)
	}
	if proto == "icmpv6" && !v6 {
		return nil, fmt.Errorf("rule %s: proto icmpv6 is IPv6-only", r.ID)
	}
	if (proto == "icmp" || proto == "icmpv6") &&
		(len(r.Src.Ports) != 0 || len(r.Dst.Ports) != 0) {
		return nil, fmt.Errorf("rule %s: ICMP rules cannot include ports", r.ID)
	}
	ex := nfproto(v6)
	if r.IfaceIn != "" {
		ex = append(ex, iif(r.IfaceIn)...)
	}
	if r.IfaceOut != "" {
		ex = append(ex, oif(r.IfaceOut)...)
	}
	if proto != "any" {
		num, err := protoNum(proto)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", r.ID, err)
		}
		ex = append(ex, l4proto(num)...)
	}
	if r.ICMPType != "" {
		if proto != "icmp" && proto != "icmpv6" {
			return nil, fmt.Errorf("rule %s: ICMP type requires proto icmp or icmpv6", r.ID)
		}
		typ, err := rule.ICMPTypeNumber(proto, r.ICMPType)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", r.ID, err)
		}
		n, _ := strconv.ParseUint(typ, 10, 8)
		ex = append(ex, icmpType(byte(n))...)
	}
	ex = append(ex, c.endpointAddr(&r.Src, "saddr", v6)...)
	ex = append(ex, c.endpointAddr(&r.Dst, "daddr", v6)...)
	// ports (only meaningful for tcp/udp)
	if proto == "tcp" || proto == "udp" {
		ex = append(ex, c.portExprs(r.Src.Ports, "sport", proto)...)
		ex = append(ex, c.portExprs(r.Dst.Ports, "dport", proto)...)
	}
	return ex, nil
}

// endpointAddr emits the address match for one endpoint: set lookup, CIDR
// bitwise, host cmp, or nothing for "any".
func (c *compiled) endpointAddr(a *rule.AddrSpec, which string, v6 bool) []expr.Any {
	if a.Set != "" {
		name := "bfw_set_" + a.Set
		if v6 {
			name += "6"
		}
		off := uint32(12)
		if which == "daddr" {
			off = 16
		}
		if v6 {
			off = 8
			if which == "daddr" {
				off = 24
			}
		}
		return []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: off, Len: addrLen(v6)},
			&expr.Lookup{SourceRegister: 1, SetName: name},
		}
	}
	if a.Any() {
		return nil
	}
	return addrMatch(which, a.IP, v6)
}

// portExprs emits sport/dport matches for the ranges of one proto.
// Single port → cmp; lo:hi → range; multiple → anonymous set lookup.
func (c *compiled) portExprs(ports []rule.PortRange, which, proto string) []expr.Any {
	var first rule.PortRange
	matched := 0
	for _, p := range ports {
		if p.Proto == "" || p.Proto == "any" || p.Proto == proto {
			matched++
			if matched == 1 {
				first = p
			}
		}
	}
	if matched == 0 {
		return nil
	}
	offset := uint32(0)
	if which == "dport" {
		offset = 2
	}
	load := &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: offset, Len: 2}
	if matched == 1 {
		if first.Lo == first.Hi {
			return []expr.Any{load, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(first.Lo)}}
		}
		return []expr.Any{load, &expr.Range{
			Op: expr.CmpOpEq, Register: 1,
			FromData: binaryutil.BigEndian.PutUint16(first.Lo),
			ToData:   binaryutil.BigEndian.PutUint16(first.Hi),
		}}
	}

	// Multiport rules alone need a retained filtered list for set creation.
	rs := make([]rule.PortRange, 0, matched)
	interval := false
	for _, p := range ports {
		if p.Proto != "" && p.Proto != "any" && p.Proto != proto {
			continue
		}
		rs = append(rs, p)
		if p.Multi() {
			interval = true
		}
	}
	set := &nftables.Set{
		Table: c.table, Anonymous: true, Constant: true,
		ID:      c.newSetID(),
		KeyType: nftables.TypeInetService, Interval: interval,
	}
	set.Name = fmt.Sprintf("__set%d", set.ID)
	var elems []nftables.SetElement
	for _, p := range rs {
		if interval {
			elems = append(elems, portIntervalElems(p.Lo, p.Hi)...)
		} else {
			elems = append(elems, nftables.SetElement{Key: binaryutil.BigEndian.PutUint16(p.Lo)})
		}
	}
	c.sets = append(c.sets, set)
	c.elems[set] = elems
	return []expr.Any{load, &expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID}}
}

// compileNAT builds table ip/ip6 better-firewall-nat when st.NAT is non-empty.
func (c *compiled) compileNAT(st *store.State) error {
	if len(st.NAT) == 0 {
		return nil
	}
	t4 := &nftables.Table{Family: nftables.TableFamilyIPv4, Name: NATTableName}
	t6 := &nftables.Table{Family: nftables.TableFamilyIPv6, Name: NATTableName}
	c.natTables = []*nftables.Table{t4, t6}

	pre := map[*nftables.Table]*nftables.Chain{}
	post := map[*nftables.Table]*nftables.Chain{}
	for _, t := range c.natTables {
		// NAT base chains carry an explicit accept policy (nft prints
		// `policy accept`); set it so render/diff match the kernel.
		accept := nftables.ChainPolicyAccept
		pre[t] = &nftables.Chain{
			Name: "prerouting", Table: t, Type: nftables.ChainTypeNAT,
			Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityNATDest,
			Policy: &accept,
		}
		post[t] = &nftables.Chain{
			Name: "postrouting", Table: t, Type: nftables.ChainTypeNAT,
			Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityNATSource,
			Policy: &accept,
		}
		c.chains = append(c.chains, pre[t], post[t])
	}

	for i := range st.NAT {
		nr := &st.NAT[i]
		v6 := natRuleV6(nr)
		t := t4
		if v6 {
			t = t6
		}
		var ex []expr.Any
		if nr.IfaceIn != "" {
			ex = append(ex, iif(nr.IfaceIn)...)
		}
		if nr.IfaceOut != "" {
			ex = append(ex, oif(nr.IfaceOut)...)
		}
		if nr.Proto != "" && nr.Proto != "any" {
			num, err := protoNum(nr.Proto)
			if err != nil {
				return fmt.Errorf("nat rule %d: %w", i, err)
			}
			ex = append(ex, l4proto(num)...)
		}
		if nr.Src != "" && nr.Src != "any" {
			ex = append(ex, addrMatch("saddr", nr.Src, v6)...)
		}
		if nr.Dst != "" && nr.Dst != "any" {
			ex = append(ex, addrMatch("daddr", nr.Dst, v6)...)
		}
		if nr.Dport != 0 {
			ex = append(ex, portEq("dport", nr.Dport)...)
		}
		ex = append(ex, counter())

		switch nr.Kind {
		case "masquerade":
			ex = append(ex, &expr.Masq{})
			c.rules = append(c.rules, &nftables.Rule{Table: t, Chain: post[t], Exprs: ex})
		case "dnat":
			host, portStr := splitToDest(nr.ToDest)
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("nat rule %d: bad to-destination %q", i, nr.ToDest)
			}
			if (ip.To4() == nil) != v6 {
				return fmt.Errorf("nat rule %d: to-destination family mismatch", i)
			}
			nat := &expr.NAT{Type: expr.NATTypeDestNAT, Family: natFamily(v6), RegAddrMin: unix.NFT_REG_1}
			ex = append(ex, &expr.Immediate{Register: unix.NFT_REG_1, Data: canonIP(ip)})
			if portStr != "" {
				p, err := strconv.ParseUint(portStr, 10, 16)
				if err != nil {
					return fmt.Errorf("nat rule %d: bad to-destination port %q", i, portStr)
				}
				nat.RegProtoMin = unix.NFT_REG_2
				ex = append(ex, &expr.Immediate{Register: unix.NFT_REG_2, Data: binaryutil.BigEndian.PutUint16(uint16(p))})
			}
			ex = append(ex, nat)
			c.rules = append(c.rules, &nftables.Rule{Table: t, Chain: pre[t], Exprs: ex})
		default:
			return fmt.Errorf("nat rule %d: unknown kind %q", i, nr.Kind)
		}
	}
	return nil
}

// ---- expression helpers --------------------------------------------------
// Helpers return []expr.Any for compound matches (load+cmp); single-expr
// helpers return expr.Any. join/ex flatten for addRule.

func ex(exprs ...expr.Any) []expr.Any { return exprs }

func join(lists ...[]expr.Any) []expr.Any {
	var out []expr.Any
	for _, l := range lists {
		out = append(out, l...)
	}
	return out
}

func nfproto(v6 bool) []expr.Any {
	b := byte(unix.NFPROTO_IPV4)
	if v6 {
		b = unix.NFPROTO_IPV6
	}
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{b}},
	}
}

func l4proto(num byte) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{num}},
	}
}

func protoNum(p string) (byte, error) {
	switch p {
	case "tcp":
		return unix.IPPROTO_TCP, nil
	case "udp":
		return unix.IPPROTO_UDP, nil
	case "icmp":
		return unix.IPPROTO_ICMP, nil
	case "icmpv6":
		return unix.IPPROTO_ICMPV6, nil
	case "ah":
		return unix.IPPROTO_AH, nil
	case "esp":
		return unix.IPPROTO_ESP, nil
	case "gre":
		return unix.IPPROTO_GRE, nil
	case "igmp":
		return unix.IPPROTO_IGMP, nil
	case "ipv6":
		return unix.IPPROTO_IPV6, nil
	case "vrrp":
		return 112, nil
	default:
		return 0, fmt.Errorf("unknown proto %q", p)
	}
}

// protoVariants expands a rule into per-proto compile passes. proto "any"
// with port specs expands to the referenced protos (ufw expands bare ports
// to tcp+udp); without ports it stays a single proto-less match.
func protoVariants(r *rule.Rule) ([2]string, int) {
	var out [2]string
	if r.Proto != "any" && r.Proto != "" {
		out[0] = r.Proto
		return out, 1
	}

	hasTCP, hasUDP := false, false
	for _, p := range r.Src.Ports {
		switch p.Proto {
		case "tcp":
			hasTCP = true
		case "udp":
			hasUDP = true
		default:
			hasTCP, hasUDP = true, true
		}
	}
	for _, p := range r.Dst.Ports {
		switch p.Proto {
		case "tcp":
			hasTCP = true
		case "udp":
			hasUDP = true
		default:
			hasTCP, hasUDP = true, true
		}
	}
	if !hasTCP && !hasUDP {
		out[0] = "any"
		return out, 1
	}

	count := 0
	if hasTCP {
		out[count] = "tcp"
		count++
	}
	if hasUDP {
		out[count] = "udp"
		count++
	}
	return out, count
}

func iif(name string) []expr.Any { return ifaceMatch(expr.MetaKeyIIFNAME, name) }
func oif(name string) []expr.Any { return ifaceMatch(expr.MetaKeyOIFNAME, name) }

func ifaceMatch(key expr.MetaKey, name string) []expr.Any {
	// Trailing '+' is a prefix wildcard (iptables -i eth+ / nft iifname
	// "eth*"): match only the prefix bytes via a bitwise mask.
	if strings.HasSuffix(name, "+") {
		prefix := name[:len(name)-1]
		b := make([]byte, 16)
		copy(b, prefix)
		mask := make([]byte, 16)
		for i := range prefix {
			mask[i] = 0xff
		}
		return []expr.Any{
			&expr.Meta{Key: key, Register: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 16, Mask: mask, Xor: make([]byte, 16)},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: b},
		}
	}
	b := make([]byte, 16)
	copy(b, name)
	return []expr.Any{
		&expr.Meta{Key: key, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: b},
	}
}

func addrLen(v6 bool) uint32 {
	if v6 {
		return 16
	}
	return 4
}

// addrMatch emits payload+bitwise+cmp (CIDR) or payload+cmp (host) for
// saddr/daddr. which is "saddr" or "daddr". Returns nil on unparseable
// input (callers validate upstream).
func addrMatch(which, cidr string, v6 bool) []expr.Any {
	off := uint32(12)
	if which == "daddr" {
		off = 16
	}
	if v6 {
		off = 8
		if which == "daddr" {
			off = 24
		}
	}
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		ip := net.ParseIP(cidr)
		if ip == nil {
			// Fail closed: two contradictory cmps on reg 1 can never both
			// hold, so the rule matches nothing rather than everything.
			return []expr.Any{
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0}},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1}},
			}
		}
		bits := 128
		if ip.To4() != nil {
			bits = 32
		}
		ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
	}
	addr := canonIP(ipnet.IP.Mask(ipnet.Mask))
	// Family mismatch (v4 addr in a v6 rule or vice versa) would emit a
	// wrong-length payload load — fail closed instead of a garbage match.
	if (len(addr) == 16) != v6 {
		return []expr.Any{
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0}},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1}},
		}
	}
	load := &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: off, Len: uint32(len(addr))}
	ones, bits := ipnet.Mask.Size()
	if ones == bits {
		return []expr.Any{load, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: addr}}
	}
	return []expr.Any{
		load,
		&expr.Bitwise{
			SourceRegister: 1, DestRegister: 1, Len: uint32(len(addr)),
			Mask: []byte(ipnet.Mask), Xor: make([]byte, len(addr)),
		},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: addr},
	}
}

func canonIP(ip net.IP) []byte {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip.To16()
}

func lastAddr(ipnet *net.IPNet) net.IP {
	ip := canonIP(ipnet.IP.Mask(ipnet.Mask))
	mask := ipnet.Mask
	// canonIP may shrink a v4-mapped-v6 IP to 4 bytes while the mask stays
	// 16; take the mask's last len(ip) bytes so lengths always match.
	if len(mask) != len(ip) {
		if len(mask) > len(ip) {
			mask = mask[len(mask)-len(ip):]
		} else {
			mask = canonIP(net.IP(mask))
		}
	}
	out := make(net.IP, len(ip))
	for i := range ip {
		out[i] = ip[i] | ^mask[i]
	}
	return out
}

func addOne(ip net.IP) net.IP {
	out := make(net.IP, len(ip))
	copy(out, ip)
	for i := len(out) - 1; i >= 0; i-- {
		out[i]++
		if out[i] != 0 {
			break
		}
	}
	return out
}

// portIntervalElems encodes [lo,hi] as an interval-set element pair
// (start, end-exclusive) with the 65535 overflow handled via a 0 end
// marker, matching kernel interval semantics.
func portIntervalElems(lo, hi uint16) []nftables.SetElement {
	start := nftables.SetElement{Key: binaryutil.BigEndian.PutUint16(lo)}
	if hi == 0xffff {
		return []nftables.SetElement{start, {Key: []byte{0, 0}, IntervalEnd: true}}
	}
	return []nftables.SetElement{start, {Key: binaryutil.BigEndian.PutUint16(hi + 1), IntervalEnd: true}}
}

func portEq(which string, p uint16) []expr.Any {
	off := uint32(0)
	if which == "dport" {
		off = 2
	}
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: off, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(p)},
	}
}

func icmpType(t byte) []expr.Any {
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{t}},
	}
}

func hopLimit(hl byte) []expr.Any {
	// IPv6 Hop Limit is byte 7 of the header (nft encodes `ip6 hoplimit`
	// as @nh,56,8). Offset 1 is Traffic Class/Flow Label — never matches.
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 7, Len: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{hl}},
	}
}

// rhType matches the routing-header type field (exthdr type 43, offset 2).
func rhType(t byte) []expr.Any {
	return []expr.Any{
		&expr.Exthdr{DestRegister: 1, Type: 43, Offset: 2, Len: 1, Op: expr.ExthdrOpIpv6},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{t}},
	}
}

// ctState matches any of the given state bits (nft's `ct state { ... }`
// encoding: load, mask, neq 0).
// ctState matches when the conntrack state has any of `bits` set. The ct
// state register is host-order, so the bitwise mask is native-endian
// (big-endian here would read as bits 25/26 — the ENOBUFS-era bug).
func ctState(bits uint32) []expr.Any {
	return []expr.Any{
		&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
		&expr.Bitwise{
			SourceRegister: 1, DestRegister: 1, Len: 4,
			Mask: binaryutil.NativeEndian.PutUint32(bits),
			Xor:  binaryutil.NativeEndian.PutUint32(0),
		},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(0)},
	}
}

// fibAddrType matches the destination address type (local/broadcast/…).
// The fib result register is host-order → native-endian compare.
func fibAddrType(rtn uint32) []expr.Any {
	return []expr.Any{
		&expr.Fib{Register: 1, ResultADDRTYPE: true, FlagDADDR: true},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(rtn)},
	}
}

func counter() expr.Any { return &expr.Counter{} }

func verdict(k expr.VerdictKind) expr.Any { return &expr.Verdict{Kind: k} }

func jump(chain string) expr.Any {
	return &expr.Verdict{Kind: expr.VerdictJump, Chain: chain}
}

func rejectExpr() expr.Any {
	return &expr.Reject{Type: unix.NFT_REJECT_ICMPX_UNREACH, Code: unix.NFT_REJECT_ICMPX_PORT_UNREACH}
}

func policyVerdict(policy string) expr.Any {
	switch policy {
	case "allow":
		return verdict(expr.VerdictAccept)
	case "reject":
		return rejectExpr()
	default:
		return verdict(expr.VerdictDrop)
	}
}

// limit3 is ufw's shared log rate limit: limit rate 3/minute burst 10.
func limit3() expr.Any {
	return &expr.Limit{Type: expr.LimitTypePkts, Rate: 3, Unit: expr.LimitTimeMinute, Burst: 10}
}

func logExpr(prefix string) expr.Any {
	return &expr.Log{Key: 1 << unix.NFTA_LOG_PREFIX, Data: []byte(prefix)}
}

func logPrefix(action string) string {
	switch action {
	case "allow":
		return "[BFW ALLOW] "
	case "limit":
		return "[BFW LIMIT] "
	default:
		return "[BFW BLOCK] "
	}
}

func natRuleV6(nr *store.NATRule) bool {
	for _, s := range []string{nr.Src, nr.Dst, nr.ToDest} {
		if s == "" || s == "any" {
			continue
		}
		if ip := natHostIP(s); ip != nil && ip.To4() == nil {
			return true
		}
	}
	return false
}

// natHostIP extracts the IP from a NAT field that may be a bare IP, a CIDR,
// a v4 host:port, or a [v6]:port. Returns nil when unparseable.
func natHostIP(s string) net.IP {
	if ip, _, err := net.ParseCIDR(s); err == nil {
		return ip
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip // bare v4 or v6
	}
	// host:port — strip a bracketed v6 host or split on the last colon.
	if strings.HasPrefix(s, "[") {
		if h, _, ok := strings.Cut(s[1:], "]"); ok {
			return net.ParseIP(h)
		}
	}
	if i := strings.LastIndex(s, ":"); i > 0 {
		return net.ParseIP(s[:i])
	}
	return nil
}

func natFamily(v6 bool) uint32 {
	if v6 {
		return unix.NFPROTO_IPV6
	}
	return unix.NFPROTO_IPV4
}

// splitToDest splits a to-destination into host and optional port.
// Handles bare IP, v4 host:port, and [v6]:port.
func splitToDest(s string) (host, port string) {
	if strings.HasPrefix(s, "[") {
		if h, rest, ok := strings.Cut(s[1:], "]"); ok {
			if strings.HasPrefix(rest, ":") {
				return h, rest[1:]
			}
			return h, ""
		}
	}
	// Bare v6 (multiple colons, no brackets) has no port.
	if strings.Count(s, ":") > 1 {
		return s, ""
	}
	if h, p, ok := strings.Cut(s, ":"); ok {
		return h, p
	}
	return s, ""
}
