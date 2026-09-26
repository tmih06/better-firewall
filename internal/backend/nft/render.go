// render.go renders the compiled ruleset as deterministic `nft -f`-style
// text (numeric form, matching `nft -nn list`) for `bfw diff` and
// `--dry-run`. It walks the same compiled object graph Apply sends to the
// kernel, so the text is authoritative.
package nft

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"github.com/tmih06/better-firewall/internal/store"
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
	var named []*nftables.Set
	for _, s := range c.sets {
		if !s.Anonymous {
			named = append(named, s)
		}
	}
	if len(named) > 1 {
		sort.Slice(named, func(i, j int) bool { return named[i].Name < named[j].Name })
	}
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
	b.WriteString("\tset ")
	b.WriteString(s.Name)
	b.WriteString(" {\n")
	b.WriteString("\t\ttype ")
	b.WriteString(renderSetType(s.KeyType))
	b.WriteString("\n")
	// nft prints `size N` (before flags) for sets with an explicit size.
	if s.Size != 0 {
		b.WriteString("\t\tsize ")
		writeUint(b, uint64(s.Size))
		b.WriteString("\n")
	}
	if s.Interval || s.Dynamic || s.HasTimeout {
		b.WriteString("\t\tflags ")
		firstFlag := true
		writeFlag := func(name string) {
			if !firstFlag {
				b.WriteByte(',')
			}
			b.WriteString(name)
			firstFlag = false
		}
		if s.Interval {
			writeFlag("interval")
		}
		if s.Dynamic {
			writeFlag("dynamic")
		}
		if s.HasTimeout {
			writeFlag("timeout")
		}
		b.WriteByte('\n')
	}
	if s.HasTimeout && s.Timeout != 0 {
		b.WriteString("\t\ttimeout ")
		b.WriteString(renderDuration(s.Timeout))
		b.WriteByte('\n')
	}
	if elems := c.elems[s]; len(elems) > 0 {
		b.WriteString("\t\telements = { ")
		writeElements(b, s, elems)
		b.WriteString(" }\n")
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
			b.WriteString("\t\t")
			renderRule(b, c, r)
			b.WriteByte('\n')
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
	// SetDatatype.Name is already the canonical nft spelling, including
	// concatenation separators. Avoid decomposing it through the nftables
	// helper, which allocates a slice and joins it again for every set.
	if t.Name != "" {
		return t.Name
	}
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

// writeElements formats set elements; interval sets are stored as
// (start, end-exclusive IntervalEnd) pairs.
func writeElements(b *strings.Builder, s *nftables.Set, elems []nftables.SetElement) {
	first := true
	for i := 0; i < len(elems); i++ {
		e := elems[i]
		if !first {
			b.WriteString(", ")
		}
		first = false
		if i+1 < len(elems) && elems[i+1].IntervalEnd {
			writeRangeElem(b, s, e.Key, elems[i+1].Key)
			i++
			continue
		}
		writeKey(b, s, e.Key)
	}
}

func writeKey(b *strings.Builder, s *nftables.Set, key []byte) {
	switch s.KeyType {
	case nftables.TypeIPAddr, nftables.TypeIP6Addr:
		if writeIP(b, key) {
			return
		}
	case nftables.TypeInetService:
		if len(key) == 2 {
			writeUint(b, uint64(binaryutil.BigEndian.Uint16(key)))
			return
		}
	}
	fmt.Fprintf(b, "0x%x", key)
}

// writeRangeElem renders start..endExclusive as CIDR when the span is a
// power-of-two prefix, else as a range.
func writeRangeElem(b *strings.Builder, s *nftables.Set, start, endEx []byte) {
	if s.KeyType == nftables.TypeIPAddr || s.KeyType == nftables.TypeIP6Addr {
		if ones, ok := prefixLen(start, endEx); ok {
			if !writeIP(b, start) {
				b.WriteString(net.IP(start).String())
			}
			b.WriteByte('/')
			writeUint(b, uint64(ones))
			return
		}
		end := decIP(endEx)
		if !writeIP(b, start) {
			b.WriteString(net.IP(start).String())
		}
		b.WriteByte('-')
		if !writeIP(b, end) {
			b.WriteString(net.IP(end).String())
		}
		return
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
			writeUint(b, uint64(lo))
			return
		}
		writeUint(b, uint64(lo))
		b.WriteByte('-')
		writeUint(b, uint64(hi))
		return
	}
	fmt.Fprintf(b, "0x%x-0x%x", start, endEx)
}

// writeIP appends the canonical nft address spelling without creating the
// temporary string returned by net.IP.String. Unmap preserves net.IP's
// historical dotted-decimal rendering for IPv4-mapped IPv6 values.
func writeIP(b *strings.Builder, data []byte) bool {
	ip, ok := netip.AddrFromSlice(data)
	if !ok {
		return false
	}
	var buf [39]byte
	b.Write(ip.Unmap().AppendTo(buf[:0]))
	return true
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

// renderRegs mirrors nftables' data registers without allocating a map for
// every rule. The array covers both the verdict/128-bit registers
// (NFT_REG_1..NFT_REG_MAX) and the reg32 aliases (NFT_REG32_00..NFT_REG32_15,
// IDs 8-23) that limit dynsets use for their saddr/dport keys. The overflow
// map is created only for malformed or future expressions using an ID outside
// that span, preserving the renderer's previous behavior for those inputs.
type renderRegs struct {
	values [int(unix.NFT_REG32_15) + 1]pend
	extra  map[uint32]pend
}

func (r *renderRegs) set(register uint32, value pend) {
	if register < uint32(len(r.values)) {
		r.values[register] = value
		return
	}
	if r.extra == nil {
		r.extra = make(map[uint32]pend)
	}
	r.extra[register] = value
}

func (r *renderRegs) get(register uint32) pend {
	if register < uint32(len(r.values)) {
		return r.values[register]
	}
	if r.extra != nil {
		return r.extra[register]
	}
	return pend{}
}

func renderRule(out *strings.Builder, c *compiled, r *nftables.Rule) {
	var regs renderRegs
	first := true
	lastL4 := byte(0)
	addToken := func(token string) {
		if !first {
			out.WriteByte(' ')
		}
		out.WriteString(token)
		first = false
	}

	for _, e := range r.Exprs {
		switch x := e.(type) {
		case *expr.Meta:
			regs.set(x.Register, pend{text: metaText(x.Key)})
		case *expr.Payload:
			regs.set(x.DestRegister, pend{text: payloadText(x, lastL4)})
		case *expr.Bitwise:
			p := regs.get(x.DestRegister)
			p.mask = x.Mask
			regs.set(x.DestRegister, p)
		case *expr.Immediate:
			regs.set(x.Register, pend{text: "imm", imm: x.Data})
		case *expr.Cmp:
			p := regs.get(x.Register)
			tokenPrefix(out, &first)
			writeCmp(out, p, x)
		case *expr.Range:
			p := regs.get(x.Register)
			tokenPrefix(out, &first)
			out.WriteString(p.text)
			out.WriteByte(' ')
			writeUint(out, uint64(binaryutil.BigEndian.Uint16(x.FromData)))
			out.WriteByte('-')
			writeUint(out, uint64(binaryutil.BigEndian.Uint16(x.ToData)))
		case *expr.Lookup:
			p := regs.get(x.SourceRegister)
			tokenPrefix(out, &first)
			writeLookup(out, c, p, x)
		case *expr.Ct:
			regs.set(x.Register, pend{text: "ct state"})
		case *expr.Fib:
			regs.set(x.Register, pend{text: fibText(x)})
		case *expr.Exthdr:
			regs.set(x.DestRegister, pend{text: exthdrText(x)})
		case *expr.Dynset:
			tokenPrefix(out, &first)
			writeDynset(out, &regs, x, lastL4)
		case *expr.Limit:
			tokenPrefix(out, &first)
			writeLimit(out, x)
		case *expr.Log:
			tokenPrefix(out, &first)
			out.WriteString("log prefix ")
			out.WriteString(strconv.Quote(string(x.Data)))
		case *expr.Counter:
			addToken("counter")
		case *expr.Verdict:
			tokenPrefix(out, &first)
			writeVerdict(out, x)
		case *expr.Reject:
			addToken("reject")
		case *expr.Masq:
			addToken("masquerade")
		case *expr.NAT:
			tokenPrefix(out, &first)
			writeNAT(out, &regs, x)
		case *expr.Notrack:
			addToken("notrack")
		default:
			addToken(fmt.Sprintf("# unsupported expr %T", e))
		}
		// track last l4proto for payload naming
		if cmp, ok := e.(*expr.Cmp); ok {
			if p := regs.get(cmp.Register); p.text == "meta l4proto" && len(cmp.Data) == 1 {
				lastL4 = cmp.Data[0]
			}
		}
	}
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
		if p.Len == 2 {
			switch p.Offset {
			case 0:
				return l4PortName(lastL4, "sport")
			case 2:
				return l4PortName(lastL4, "dport")
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

func l4PortName(proto byte, port string) string {
	switch proto {
	case unix.IPPROTO_TCP:
		if port == "sport" {
			return "tcp sport"
		}
		return "tcp dport"
	case unix.IPPROTO_UDP:
		if port == "sport" {
			return "udp sport"
		}
		return "udp dport"
	default:
		if name := l4Name(proto); name != "" {
			return name + " " + port
		}
		return "@th " + port
	}
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

func tokenPrefix(out *strings.Builder, first *bool) {
	if !*first {
		out.WriteByte(' ')
	}
	*first = false
}

func writeCmp(out *strings.Builder, p pend, x *expr.Cmp) {
	op := " "
	if x.Op == expr.CmpOpNeq {
		op = " != "
		// bitwise-mask idiom (mask + neq 0) renders as a plain match
		if p.mask != nil && isZero(x.Data) {
			op = " "
		}
	}
	out.WriteString(p.text)
	out.WriteString(op)
	writeCmpValue(out, p, x.Data)
}

func isZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func writeCmpValue(out *strings.Builder, p pend, data []byte) {
	switch p.text {
	case "meta nfproto":
		if len(data) == 1 && data[0] == unix.NFPROTO_IPV4 {
			out.WriteString("ipv4")
			return
		}
		if len(data) == 1 && data[0] == unix.NFPROTO_IPV6 {
			out.WriteString("ipv6")
			return
		}
	case "meta l4proto":
		if len(data) == 1 {
			if n := l4Name(data[0]); n != "" {
				out.WriteString(n)
				return
			}
			writeUint(out, uint64(data[0]))
			return
		}
	case "iifname", "oifname":
		writeQuotedBytes(out, data)
		return
	case "ct state":
		// ct state matches encode as bitwise mask + cmp neq 0; the state
		// bits live in the mask, not the cmp data. Host-order register →
		// native-endian decode.
		if len(p.mask) == 4 {
			writeCtStateName(out, binaryutil.NativeEndian.Uint32(p.mask))
			return
		}
		if len(data) == 4 {
			writeCtStateName(out, binaryutil.NativeEndian.Uint32(data))
			return
		}
	case "fib daddr type":
		if len(data) == 4 {
			writeAddrTypeName(out, binaryutil.NativeEndian.Uint32(data))
			return
		}
	case "icmp type":
		if len(data) == 1 {
			writeICMPTypeName(out, data[0])
			return
		}
	case "icmpv6 type":
		if len(data) == 1 {
			writeICMPv6TypeName(out, data[0])
			return
		}
	case "rt type":
		if len(data) == 1 {
			writeUint(out, uint64(data[0]))
			return
		}
	case "ip saddr", "ip daddr", "ip6 saddr", "ip6 daddr":
		if p.mask != nil {
			if ones, ok := maskPrefix(p.mask); ok {
				if !writeIP(out, data) {
					out.WriteString(net.IP(data).String())
				}
				out.WriteByte('/')
				writeUint(out, uint64(ones))
				return
			}
			if !writeIP(out, data) {
				out.WriteString(net.IP(data).String())
			}
			out.WriteString(" & ")
			if !writeIP(out, p.mask) {
				out.WriteString(net.IP(p.mask).String())
			}
			return
		}
		if !writeIP(out, data) {
			out.WriteString(net.IP(data).String())
		}
		return
	default:
		if strings.HasSuffix(p.text, "sport") || strings.HasSuffix(p.text, "dport") {
			if len(data) == 2 {
				writeUint(out, uint64(binaryutil.BigEndian.Uint16(data)))
				return
			}
		}
		if p.text == "ip6 hoplimit" && len(data) == 1 {
			writeUint(out, uint64(data[0]))
			return
		}
	}
	fmt.Fprintf(out, "0x%x", data)
}

// writeQuotedBytes is the allocation-free fast path for nft interface names.
// Kernel metadata is normally short printable ASCII; the fallback retains
// strconv.Quote's exact handling for invalid UTF-8 and non-printable Unicode.
func writeQuotedBytes(out *strings.Builder, data []byte) {
	for len(data) > 0 && data[len(data)-1] == 0 {
		data = data[:len(data)-1]
	}
	for i := 0; i < len(data); {
		r, width := utf8.DecodeRune(data[i:])
		if width == 1 && r == utf8.RuneError && data[i] >= utf8.RuneSelf {
			var quoted [64]byte
			out.Write(strconv.AppendQuote(quoted[:0], string(data)))
			return
		}
		if r >= utf8.RuneSelf && !strconv.IsPrint(r) {
			var quoted [64]byte
			out.Write(strconv.AppendQuote(quoted[:0], string(data)))
			return
		}
		i += width
	}

	const hex = "0123456789abcdef"
	out.WriteByte('"')
	for i := 0; i < len(data); {
		r, width := utf8.DecodeRune(data[i:])
		switch r {
		case '"', '\\':
			out.WriteByte('\\')
			out.WriteByte(byte(r))
		case '\a':
			out.WriteString(`\a`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		case '\v':
			out.WriteString(`\v`)
		default:
			if r < ' ' || r == 0x7f {
				out.WriteString(`\x`)
				out.WriteByte(hex[byte(r)>>4])
				out.WriteByte(hex[byte(r)&0xf])
			} else {
				out.Write(data[i : i+width])
			}
		}
		i += width
	}
	out.WriteByte('"')
}

func writeUint(out *strings.Builder, n uint64) {
	var buf [20]byte
	out.Write(strconv.AppendUint(buf[:0], n, 10))
}

func writeInt(out *strings.Builder, n int64) {
	var buf [20]byte
	out.Write(strconv.AppendInt(buf[:0], n, 10))
}

func writeCtStateName(out *strings.Builder, bits uint32) {
	first := true
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
			if !first {
				out.WriteByte(',')
			}
			out.WriteString(s.name)
			first = false
		}
	}
}

func writeAddrTypeName(out *strings.Builder, rtn uint32) {
	switch rtn {
	case unix.RTN_LOCAL:
		out.WriteString("local")
	case unix.RTN_BROADCAST:
		out.WriteString("broadcast")
	case unix.RTN_MULTICAST:
		out.WriteString("multicast")
	case unix.RTN_ANYCAST:
		out.WriteString("anycast")
	default:
		writeUint(out, uint64(rtn))
	}
}

func writeICMPTypeName(out *strings.Builder, t byte) {
	switch t {
	case 0:
		out.WriteString("echo-reply")
	case 3:
		out.WriteString("destination-unreachable")
	case 4:
		out.WriteString("source-quench")
	case 5:
		out.WriteString("redirect")
	case 8:
		out.WriteString("echo-request")
	case 11:
		out.WriteString("time-exceeded")
	case 12:
		out.WriteString("parameter-problem")
	default:
		writeUint(out, uint64(t))
	}
}

func writeICMPv6TypeName(out *strings.Builder, t byte) {
	switch t {
	case 1:
		out.WriteString("destination-unreachable")
	case 2:
		out.WriteString("packet-too-big")
	case 3:
		out.WriteString("time-exceeded")
	case 4:
		out.WriteString("parameter-problem")
	case 128:
		out.WriteString("echo-request")
	case 129:
		out.WriteString("echo-reply")
	case 133:
		out.WriteString("router-solicitation")
	case 134:
		out.WriteString("router-advertisement")
	case 135:
		out.WriteString("neighbour-solicitation")
	case 136:
		out.WriteString("neighbour-advertisement")
	default:
		writeUint(out, uint64(t))
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

func writeLookup(out *strings.Builder, c *compiled, p pend, x *expr.Lookup) {
	name := x.SetName
	if strings.HasPrefix(name, "__set") {
		// anonymous set: render elements inline
		if s := c.setIndex[x.SetID]; s != nil {
			out.WriteString(p.text)
			out.WriteString(" { ")
			writeElements(out, s, c.elems[s])
			out.WriteString(" }")
			return
		}
	}
	out.WriteString(p.text)
	out.WriteByte(' ')
	if x.Invert {
		out.WriteString("!= ")
	}
	out.WriteByte('@')
	out.WriteString(name)
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

func writeDynset(out *strings.Builder, regs *renderRegs, x *expr.Dynset, lastL4 byte) {
	key := regs.get(x.SrcRegKey).text
	// find the port register: the next reg32 slot after the addr
	var port pend
	setPort := func(reg uint32, p pend) {
		if port.text != "" || reg == x.SrcRegKey || p.text == "" ||
			(!strings.HasSuffix(p.text, "dport") && p.text != "imm") {
			return
		}
		port = p
	}
	for reg := uint32(1); reg < uint32(len(regs.values)); reg++ {
		setPort(reg, regs.get(reg))
	}
	for reg, p := range regs.extra {
		setPort(reg, p)
	}
	if port.text == "" {
		// Keep the legacy rendering for a dynset without an observed L4
		// protocol; normal limit rules always carry tcp/udp here.
		if name := l4Name(lastL4); name != "" {
			port.text = name + " dport"
		} else {
			port.text = " dport"
		}
	}
	op := "add"
	if x.Operation == unix.NFT_DYNSET_OP_UPDATE {
		op = "update"
	}
	out.WriteString(op)
	out.WriteString(" @")
	out.WriteString(x.SetName)
	out.WriteString(" { ")
	out.WriteString(key)
	out.WriteString(" . ")
	if port.text == "imm" && len(port.imm) == 2 {
		writeUint(out, uint64(binaryutil.BigEndian.Uint16(port.imm)))
	} else {
		out.WriteString(port.text)
	}
	if x.Timeout != 0 {
		out.WriteString(" timeout ")
		out.WriteString(x.Timeout.String())
	}
	for _, e := range x.Exprs {
		if l, ok := e.(*expr.Limit); ok {
			out.WriteByte(' ')
			writeLimit(out, l)
		}
	}
	out.WriteString(" }")
}

func writeLimit(out *strings.Builder, l *expr.Limit) {
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
	if l.Over {
		out.WriteString("limit rate over ")
	} else {
		out.WriteString("limit rate ")
	}
	writeUint(out, uint64(l.Rate))
	out.WriteByte('/')
	out.WriteString(unit)
	if l.Burst != 0 {
		out.WriteString(" burst ")
		writeUint(out, uint64(l.Burst))
		out.WriteString(" packets")
	}
}

func writeVerdict(out *strings.Builder, v *expr.Verdict) {
	switch v.Kind {
	case expr.VerdictAccept:
		out.WriteString("accept")
	case expr.VerdictDrop:
		out.WriteString("drop")
	case expr.VerdictReturn:
		out.WriteString("return")
	case expr.VerdictJump:
		out.WriteString("jump ")
		out.WriteString(v.Chain)
	case expr.VerdictGoto:
		out.WriteString("goto ")
		out.WriteString(v.Chain)
	case expr.VerdictContinue:
		out.WriteString("continue")
	default:
		out.WriteString("verdict ")
		writeInt(out, int64(v.Kind))
	}
}

func writeNAT(out *strings.Builder, regs *renderRegs, x *expr.NAT) {
	var addr []byte
	var addrBuf [39]byte
	addrV6 := false
	if p := regs.get(x.RegAddrMin); len(p.imm) > 0 {
		if ip, ok := netip.AddrFromSlice(p.imm); ok {
			ip = ip.Unmap()
			addrV6 = ip.Is6()
			addr = ip.AppendTo(addrBuf[:0])
		} else {
			addr = []byte(net.IP(p.imm).String())
		}
	}
	var port uint16
	hasPort := false
	if x.RegProtoMin != 0 {
		if p := regs.get(x.RegProtoMin); len(p.imm) == 2 {
			port = binaryutil.BigEndian.Uint16(p.imm)
			hasPort = true
		}
	}
	// nft brackets a v6 address when a port follows: dnat to [::1]:8080.
	if hasPort && addrV6 {
		out.WriteByte('[')
	}
	if x.Type == expr.NATTypeDestNAT {
		out.WriteString("dnat to ")
	} else {
		out.WriteString("snat to ")
	}
	out.Write(addr)
	if hasPort && addrV6 {
		out.WriteByte(']')
	}
	if hasPort {
		out.WriteByte(':')
		writeUint(out, uint64(port))
	}
}
