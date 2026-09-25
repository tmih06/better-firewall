// render.go renders the compiled ruleset as deterministic `nft -f`-style
// text (numeric form, matching `nft -nn list`) for `bfw diff` and
// `--dry-run`. It walks the same compiled object graph Apply sends to the
// kernel, so the text is authoritative.
package nft

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"bfirewall/internal/store"
)

// RenderText returns the canonical nft -f-style text of the ruleset
// compile(st, etc) produces. Output is deterministic: object order is
// compile order, and all values render numerically (nft -nn style).
func RenderText(st *store.State, etc map[string]string) (string, error) {
	c, err := compile(st, etc)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	renderTable(&b, c)
	for _, t := range c.natTables {
		renderNATTable(&b, c, t)
	}
	return b.String(), nil
}

func renderTable(b *strings.Builder, c *compiled) {
	fmt.Fprintf(b, "table inet %s {\n", c.table.Name)

	// named sets first (nft -f style), deterministic by name
	named := []*nftables.Set{}
	for _, s := range c.sets {
		if !s.Anonymous {
			named = append(named, s)
		}
	}
	sort.Slice(named, func(i, j int) bool { return named[i].Name < named[j].Name })
	for _, s := range named {
		renderSet(b, c, s)
	}

	for _, ch := range c.chains {
		if ch.Table != c.table {
			continue
		}
		renderChain(b, c, ch)
	}
	b.WriteString("}\n")
}

func renderNATTable(b *strings.Builder, c *compiled, t *nftables.Table) {
	fam := "ip"
	if t.Family == nftables.TableFamilyIPv6 {
		fam = "ip6"
	}
	fmt.Fprintf(b, "table %s %s {\n", fam, t.Name)
	for _, ch := range c.chains {
		if ch.Table != t {
			continue
		}
		renderChain(b, c, ch)
	}
	b.WriteString("}\n")
}

func renderSet(b *strings.Builder, c *compiled, s *nftables.Set) {
	fmt.Fprintf(b, "\tset %s {\n", s.Name)
	fmt.Fprintf(b, "\t\ttype %s\n", renderSetType(s.KeyType))
	// nft prints `size N` (before flags) for sets with an explicit size.
	if s.Size != 0 {
		fmt.Fprintf(b, "\t\tsize %d\n", s.Size)
	}
	var flags []string
	if s.Interval {
		flags = append(flags, "interval")
	}
	if s.Dynamic {
		flags = append(flags, "dynamic")
	}
	if s.HasTimeout {
		flags = append(flags, "timeout")
	}
	if len(flags) > 0 {
		fmt.Fprintf(b, "\t\tflags %s\n", strings.Join(flags, ","))
	}
	if s.HasTimeout && s.Timeout != 0 {
		fmt.Fprintf(b, "\t\ttimeout %s\n", renderDuration(s.Timeout))
	}
	if elems := c.elems[s]; len(elems) > 0 {
		fmt.Fprintf(b, "\t\telements = { %s }\n", renderElements(s, elems))
	}
	b.WriteString("\t}\n")
}

func renderChain(b *strings.Builder, c *compiled, ch *nftables.Chain) {
	fmt.Fprintf(b, "\tchain %s {\n", ch.Name)
	if ch.Hooknum != nil {
		hook := hookName(*ch.Hooknum)
		prio := 0
		if ch.Priority != nil {
			prio = int(*ch.Priority)
		}
		// `nft -nn` prints numeric priority; match it for diff parity.
		fmt.Fprintf(b, "\t\ttype %s hook %s priority %d;", ch.Type, hook, prio)
		if ch.Policy != nil {
			pol := "accept"
			if *ch.Policy == nftables.ChainPolicyDrop {
				pol = "drop"
			}
			fmt.Fprintf(b, " policy %s;", pol)
		}
		b.WriteString("\n")
	}
	for _, r := range c.rules {
		if r.Chain == ch {
			fmt.Fprintf(b, "\t\t%s\n", renderRule(c, r))
		}
	}
	b.WriteString("\t}\n")
}

func hookName(h nftables.ChainHook) string {
	switch h {
	case *nftables.ChainHookPrerouting:
		return "prerouting"
	case *nftables.ChainHookInput:
		return "input"
	case *nftables.ChainHookForward:
		return "forward"
	case *nftables.ChainHookOutput:
		return "output"
	case *nftables.ChainHookPostrouting:
		return "postrouting"
	default:
		return "unknown"
	}
}

func renderSetType(t nftables.SetDatatype) string {
	parts := nftables.ConcatSetTypeElements(t)
	if len(parts) == 0 {
		return t.Name
	}
	names := make([]string, len(parts))
	for i, p := range parts {
		names[i] = p.Name
	}
	return strings.Join(names, " . ")
}

func renderDuration(d interface{ String() string }) string { return d.String() }

// renderElements formats set elements; interval sets are stored as
// (start, end-exclusive IntervalEnd) pairs.
func renderElements(s *nftables.Set, elems []nftables.SetElement) string {
	var parts []string
	for i := 0; i < len(elems); i++ {
		e := elems[i]
		if i+1 < len(elems) && elems[i+1].IntervalEnd {
			parts = append(parts, renderRangeElem(s, e.Key, elems[i+1].Key))
			i++
			continue
		}
		parts = append(parts, renderKey(s, e.Key))
	}
	return strings.Join(parts, ", ")
}

func renderKey(s *nftables.Set, key []byte) string {
	switch s.KeyType {
	case nftables.TypeIPAddr, nftables.TypeIP6Addr:
		return net.IP(key).String()
	case nftables.TypeInetService:
		if len(key) == 2 {
			return strconv.Itoa(int(binaryutil.BigEndian.Uint16(key)))
		}
	}
	return fmt.Sprintf("0x%x", key)
}

// renderRangeElem renders start..endExclusive as CIDR when the span is a
// power-of-two prefix, else as a range.
func renderRangeElem(s *nftables.Set, start, endEx []byte) string {
	if s.KeyType == nftables.TypeIPAddr || s.KeyType == nftables.TypeIP6Addr {
		if ones, ok := prefixLen(start, endEx); ok {
			return fmt.Sprintf("%s/%d", net.IP(start).String(), ones)
		}
		end := decIP(endEx)
		return fmt.Sprintf("%s-%s", net.IP(start).String(), net.IP(end).String())
	}
	if s.KeyType == nftables.TypeInetService && len(start) == 2 && len(endEx) == 2 {
		lo := binaryutil.BigEndian.Uint16(start)
		// End marker {0,0} means the interval ran to 65535 (wrapped).
		var hi uint32
		if endEx[0] == 0 && endEx[1] == 0 {
			hi = 0xffff
		} else {
			hi = uint32(binaryutil.BigEndian.Uint16(endEx)) - 1
		}
		if uint32(lo) == hi {
			return strconv.Itoa(int(lo))
		}
		return fmt.Sprintf("%d-%d", lo, hi)
	}
	return fmt.Sprintf("0x%x-0x%x", start, endEx)
}

// prefixLen reports the CIDR length when [start, endEx) is exactly one
// prefix block.
func prefixLen(start, endEx []byte) (int, bool) {
	n := len(start)
	if len(endEx) != n {
		return 0, false
	}
	// span = endEx - start must be a power of two and start aligned
	span := make([]byte, n)
	borrow := 0
	for i := n - 1; i >= 0; i-- {
		d := int(endEx[i]) - int(start[i]) - borrow
		if d < 0 {
			d += 256
			borrow = 1
		} else {
			borrow = 0
		}
		span[i] = byte(d)
	}
	// span must be a power of two: exactly one bit set. The set bit sits at
	// left-position i*8+b; a /p prefix has its lowest span bit at p-1, so
	// p = i*8+b+1.
	bits := 0
	seen := false
	for i := 0; i < n; i++ {
		for b := 0; b < 8; b++ {
			if span[i]&(1<<uint(7-b)) != 0 {
				if seen {
					return 0, false
				}
				seen = true
				bits = i*8 + b + 1
			}
		}
	}
	if !seen {
		return 0, false
	}
	// start must be aligned to the prefix
	mask := net.CIDRMask(bits, n*8)
	for i := 0; i < n; i++ {
		if start[i]&^mask[i] != 0 {
			return 0, false
		}
	}
	return bits, true
}

func decIP(ip []byte) []byte {
	out := make([]byte, len(ip))
	copy(out, ip)
	for i := len(out) - 1; i >= 0; i-- {
		if out[i] > 0 {
			out[i]--
			break
		}
		out[i] = 0xff
	}
	return out
}

// ---- rule rendering --------------------------------------------------------

// pend describes what a register currently holds, for rendering the next
// comparison.
type pend struct {
	text string // e.g. "ip saddr", "tcp dport", "meta nfproto"
	mask []byte // non-nil when a bitwise masked the value (CIDR match)
	imm  []byte // non-nil for Immediate loads (raw value)
}

func renderRule(c *compiled, r *nftables.Rule) string {
	regs := map[uint32]pend{}
	var toks []string
	lastL4 := byte(0)

	for _, e := range r.Exprs {
		switch x := e.(type) {
		case *expr.Meta:
			regs[x.Register] = pend{text: metaText(x.Key)}
		case *expr.Payload:
			regs[x.DestRegister] = pend{text: payloadText(x, lastL4)}
		case *expr.Bitwise:
			p := regs[x.DestRegister]
			p.mask = x.Mask
			regs[x.DestRegister] = p
		case *expr.Immediate:
			regs[x.Register] = pend{text: "imm", imm: x.Data}
		case *expr.Cmp:
			p := regs[x.Register]
			toks = append(toks, renderCmp(p, x))
		case *expr.Range:
			p := regs[x.Register]
			toks = append(toks, fmt.Sprintf("%s %d-%d", p.text,
				binaryutil.BigEndian.Uint16(x.FromData),
				binaryutil.BigEndian.Uint16(x.ToData)))
		case *expr.Lookup:
			p := regs[x.SourceRegister]
			toks = append(toks, renderLookup(c, p, x))
		case *expr.Ct:
			regs[x.Register] = pend{text: "ct state"}
		case *expr.Fib:
			regs[x.Register] = pend{text: fibText(x)}
		case *expr.Exthdr:
			regs[x.DestRegister] = pend{text: exthdrText(x)}
		case *expr.Dynset:
			toks = append(toks, renderDynset(regs, x, lastL4))
		case *expr.Limit:
			toks = append(toks, renderLimit(x))
		case *expr.Log:
			toks = append(toks, fmt.Sprintf("log prefix %q", string(x.Data)))
		case *expr.Counter:
			toks = append(toks, "counter")
		case *expr.Verdict:
			toks = append(toks, renderVerdict(x))
		case *expr.Reject:
			toks = append(toks, "reject")
		case *expr.Masq:
			toks = append(toks, "masquerade")
		case *expr.NAT:
			toks = append(toks, renderNAT(regs, x))
		case *expr.Notrack:
			toks = append(toks, "notrack")
		default:
			toks = append(toks, fmt.Sprintf("# unsupported expr %T", e))
		}
		// track last l4proto for payload naming
		if cmp, ok := e.(*expr.Cmp); ok {
			if p, ok2 := regs[cmp.Register]; ok2 && p.text == "meta l4proto" && len(cmp.Data) == 1 {
				lastL4 = cmp.Data[0]
			}
		}
	}
	return strings.Join(toks, " ")
}

func metaText(k expr.MetaKey) string {
	switch k {
	case expr.MetaKeyNFPROTO:
		return "meta nfproto"
	case expr.MetaKeyL4PROTO:
		return "meta l4proto"
	case expr.MetaKeyIIFNAME:
		return "iifname"
	case expr.MetaKeyOIFNAME:
		return "oifname"
	case expr.MetaKeyIIF:
		return "iif"
	case expr.MetaKeyOIF:
		return "oif"
	case expr.MetaKeyMARK:
		return "meta mark"
	default:
		return fmt.Sprintf("meta key%d", k)
	}
}

func payloadText(p *expr.Payload, lastL4 byte) string {
	if p.Base == expr.PayloadBaseNetworkHeader {
		if p.Len == 4 {
			switch p.Offset {
			case 12:
				return "ip saddr"
			case 16:
				return "ip daddr"
			}
		}
		if p.Len == 16 {
			switch p.Offset {
			case 8:
				return "ip6 saddr"
			case 24:
				return "ip6 daddr"
			}
		}
		if p.Len == 1 && p.Offset == 7 {
			return "ip6 hoplimit"
		}
		return fmt.Sprintf("@nh,%d,%d", p.Offset*8, p.Len*8)
	}
	if p.Base == expr.PayloadBaseTransportHeader {
		proto := l4Name(lastL4)
		if proto == "" {
			proto = "@th"
		}
		if p.Len == 2 {
			switch p.Offset {
			case 0:
				return proto + " sport"
			case 2:
				return proto + " dport"
			}
		}
		if p.Len == 1 && p.Offset == 0 {
			if lastL4 == unix.IPPROTO_ICMP {
				return "icmp type"
			}
			if lastL4 == unix.IPPROTO_ICMPV6 {
				return "icmpv6 type"
			}
		}
		return fmt.Sprintf("@th,%d,%d", p.Offset*8, p.Len*8)
	}
	return fmt.Sprintf("@%d,%d,%d", p.Base, p.Offset*8, p.Len*8)
}

func l4Name(num byte) string {
	switch num {
	case unix.IPPROTO_TCP:
		return "tcp"
	case unix.IPPROTO_UDP:
		return "udp"
	case unix.IPPROTO_ICMP:
		return "icmp"
	case unix.IPPROTO_ICMPV6:
		return "icmpv6"
	case unix.IPPROTO_AH:
		return "ah"
	case unix.IPPROTO_ESP:
		return "esp"
	case unix.IPPROTO_GRE:
		return "gre"
	case unix.IPPROTO_IGMP:
		return "igmp"
	case unix.IPPROTO_IPV6:
		return "ipv6"
	case 112:
		return "vrrp"
	default:
		return ""
	}
}

func renderCmp(p pend, x *expr.Cmp) string {
	op := " "
	if x.Op == expr.CmpOpNeq {
		op = " != "
		// bitwise-mask idiom (mask + neq 0) renders as a plain match
		if p.mask != nil && isZero(x.Data) {
			op = " "
		}
	}
	return p.text + op + cmpValue(p, x.Data)
}

func isZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func cmpValue(p pend, data []byte) string {
	switch p.text {
	case "meta nfproto":
		if len(data) == 1 && data[0] == unix.NFPROTO_IPV4 {
			return "ipv4"
		}
		if len(data) == 1 && data[0] == unix.NFPROTO_IPV6 {
			return "ipv6"
		}
	case "meta l4proto":
		if len(data) == 1 {
			if n := l4Name(data[0]); n != "" {
				return n
			}
			return strconv.Itoa(int(data[0]))
		}
	case "iifname", "oifname":
		return strconv.Quote(strings.TrimRight(string(data), "\x00"))
	case "ct state":
		// ct state matches encode as bitwise mask + cmp neq 0; the state
		// bits live in the mask, not the cmp data. Host-order register →
		// native-endian decode.
		if len(p.mask) == 4 {
			return ctStateName(binaryutil.NativeEndian.Uint32(p.mask))
		}
		if len(data) == 4 {
			return ctStateName(binaryutil.NativeEndian.Uint32(data))
		}
	case "fib daddr type":
		if len(data) == 4 {
			return addrTypeName(binaryutil.NativeEndian.Uint32(data))
		}
	case "icmp type":
		if len(data) == 1 {
			return icmpTypeName(data[0])
		}
	case "icmpv6 type":
		if len(data) == 1 {
			return icmpv6TypeName(data[0])
		}
	case "rt type":
		if len(data) == 1 {
			return strconv.Itoa(int(data[0]))
		}
	case "ip saddr", "ip daddr", "ip6 saddr", "ip6 daddr":
		if p.mask != nil {
			if ones, ok := maskPrefix(p.mask); ok {
				return fmt.Sprintf("%s/%d", net.IP(data).String(), ones)
			}
			return fmt.Sprintf("%s & %s", net.IP(data).String(), net.IP(p.mask).String())
		}
		return net.IP(data).String()
	default:
		if strings.HasSuffix(p.text, "sport") || strings.HasSuffix(p.text, "dport") {
			if len(data) == 2 {
				return strconv.Itoa(int(binaryutil.BigEndian.Uint16(data)))
			}
		}
		if p.text == "ip6 hoplimit" && len(data) == 1 {
			return strconv.Itoa(int(data[0]))
		}
	}
	return fmt.Sprintf("0x%x", data)
}

func ctStateName(bits uint32) string {
	var names []string
	for _, s := range []struct {
		bit  uint32
		name string
	}{
		{expr.CtStateBitINVALID, "invalid"},
		{expr.CtStateBitESTABLISHED, "established"},
		{expr.CtStateBitRELATED, "related"},
		{expr.CtStateBitNEW, "new"},
		{expr.CtStateBitUNTRACKED, "untracked"},
	} {
		if bits&s.bit != 0 {
			names = append(names, s.name)
		}
	}
	return strings.Join(names, ",")
}

func addrTypeName(rtn uint32) string {
	switch rtn {
	case unix.RTN_LOCAL:
		return "local"
	case unix.RTN_BROADCAST:
		return "broadcast"
	case unix.RTN_MULTICAST:
		return "multicast"
	case unix.RTN_ANYCAST:
		return "anycast"
	default:
		return strconv.Itoa(int(rtn))
	}
}

func icmpTypeName(t byte) string {
	switch t {
	case 0:
		return "echo-reply"
	case 3:
		return "destination-unreachable"
	case 4:
		return "source-quench"
	case 5:
		return "redirect"
	case 8:
		return "echo-request"
	case 11:
		return "time-exceeded"
	case 12:
		return "parameter-problem"
	default:
		return strconv.Itoa(int(t))
	}
}

func icmpv6TypeName(t byte) string {
	switch t {
	case 1:
		return "destination-unreachable"
	case 2:
		return "packet-too-big"
	case 3:
		return "time-exceeded"
	case 4:
		return "parameter-problem"
	case 128:
		return "echo-request"
	case 129:
		return "echo-reply"
	case 133:
		return "router-solicitation"
	case 134:
		return "router-advertisement"
	case 135:
		return "neighbour-solicitation"
	case 136:
		return "neighbour-advertisement"
	default:
		return strconv.Itoa(int(t))
	}
}

func maskPrefix(mask []byte) (int, bool) {
	ones := 0
	zeroSeen := false
	for _, b := range mask {
		for i := 7; i >= 0; i-- {
			if b&(1<<uint(i)) != 0 {
				if zeroSeen {
					return 0, false
				}
				ones++
			} else {
				zeroSeen = true
			}
		}
	}
	return ones, true
}

func renderLookup(c *compiled, p pend, x *expr.Lookup) string {
	name := x.SetName
	if strings.HasPrefix(name, "__set") {
		// anonymous set: render elements inline
		for _, s := range c.sets {
			if s.ID == x.SetID {
				return fmt.Sprintf("%s { %s }", p.text, renderElements(s, c.elems[s]))
			}
		}
	}
	inv := ""
	if x.Invert {
		inv = "!= "
	}
	return fmt.Sprintf("%s %s@%s", p.text, inv, name)
}

func fibText(x *expr.Fib) string {
	if x.ResultADDRTYPE {
		if x.FlagDADDR {
			return "fib daddr type"
		}
		if x.FlagSADDR {
			return "fib saddr type"
		}
	}
	return "fib"
}

func exthdrText(x *expr.Exthdr) string {
	if x.Type == 43 && x.Offset == 2 && x.Len == 1 {
		return "rt type"
	}
	return fmt.Sprintf("exthdr %d @ %d", x.Type, x.Offset)
}

func renderDynset(regs map[uint32]pend, x *expr.Dynset, lastL4 byte) string {
	key := regs[x.SrcRegKey].text
	// find the port register: the next reg32 slot after the addr
	portText := ""
	for reg, p := range regs {
		if reg != x.SrcRegKey && p.text != "" && (strings.HasSuffix(p.text, "dport") || p.text == "imm") {
			if p.text == "imm" && len(p.imm) == 2 {
				portText = strconv.Itoa(int(binaryutil.BigEndian.Uint16(p.imm)))
			} else {
				portText = p.text
			}
		}
	}
	if portText == "" {
		portText = l4Name(lastL4) + " dport"
	}
	var inner strings.Builder
	fmt.Fprintf(&inner, "%s . %s", key, portText)
	if x.Timeout != 0 {
		fmt.Fprintf(&inner, " timeout %s", x.Timeout)
	}
	for _, e := range x.Exprs {
		if l, ok := e.(*expr.Limit); ok {
			fmt.Fprintf(&inner, " %s", renderLimit(l))
		}
	}
	op := "add"
	if x.Operation == unix.NFT_DYNSET_OP_UPDATE {
		op = "update"
	}
	return fmt.Sprintf("%s @%s { %s }", op, x.SetName, inner.String())
}

func renderLimit(l *expr.Limit) string {
	unit := "second"
	switch l.Unit {
	case expr.LimitTimeMinute:
		unit = "minute"
	case expr.LimitTimeHour:
		unit = "hour"
	case expr.LimitTimeDay:
		unit = "day"
	case expr.LimitTimeWeek:
		unit = "week"
	}
	over := ""
	if l.Over {
		over = "over "
	}
	s := fmt.Sprintf("limit rate %s%d/%s", over, l.Rate, unit)
	if l.Burst != 0 {
		s += fmt.Sprintf(" burst %d packets", l.Burst)
	}
	return s
}

func renderVerdict(v *expr.Verdict) string {
	switch v.Kind {
	case expr.VerdictAccept:
		return "accept"
	case expr.VerdictDrop:
		return "drop"
	case expr.VerdictReturn:
		return "return"
	case expr.VerdictJump:
		return "jump " + v.Chain
	case expr.VerdictGoto:
		return "goto " + v.Chain
	case expr.VerdictContinue:
		return "continue"
	default:
		return fmt.Sprintf("verdict %d", v.Kind)
	}
}

func renderNAT(regs map[uint32]pend, x *expr.NAT) string {
	addr := ""
	if p, ok := regs[x.RegAddrMin]; ok && len(p.imm) > 0 {
		addr = net.IP(p.imm).String()
	}
	port := ""
	if x.RegProtoMin != 0 {
		if p, ok := regs[x.RegProtoMin]; ok && len(p.imm) == 2 {
			port = ":" + strconv.Itoa(int(binaryutil.BigEndian.Uint16(p.imm)))
		}
	}
	// nft brackets a v6 address when a port follows: dnat to [::1]:8080.
	if port != "" && strings.Contains(addr, ":") {
		addr = "[" + addr + "]"
	}
	if x.Type == expr.NATTypeDestNAT {
		return fmt.Sprintf("dnat to %s%s", addr, port)
	}
	return fmt.Sprintf("snat to %s%s", addr, port)
}
