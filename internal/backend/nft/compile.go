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
	"fmt"
	"net/netip"
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

// These names are emitted for every compile. Keeping them as immutable
// literals avoids rebuilding the same chain strings for each ruleset while
// preserving ufw's declaration and jump order (input, output, forward).
var baseJumpChains = [3][7]string{
	{"bfw-before-logging-input", "bfw-before-input", "bfw-user-input", "bfw-after-input", "bfw-after-logging-input", "bfw-reject-input", "bfw-track-input"},
	{"bfw-before-logging-output", "bfw-before-output", "bfw-user-output", "bfw-after-output", "bfw-after-logging-output", "bfw-reject-output", "bfw-track-output"},
	{"bfw-before-logging-forward", "bfw-before-forward", "bfw-user-forward", "bfw-after-forward", "bfw-after-logging-forward", "bfw-reject-forward", "bfw-track-forward"},
}

var regularChainNames = [...]string{
	"bfw-before-logging-input", "bfw-before-logging-output", "bfw-before-logging-forward",
	"bfw-before-input", "bfw-before-output", "bfw-before-forward",
	"bfw-user-input", "bfw-user-output", "bfw-user-forward",
	"bfw-after-input", "bfw-after-output", "bfw-after-forward",
	"bfw-after-logging-input", "bfw-after-logging-output", "bfw-after-logging-forward",
	"bfw-user-logging-input", "bfw-user-logging-output", "bfw-user-logging-forward",
	"bfw-reject-input", "bfw-reject-output", "bfw-reject-forward",
	"bfw-track-input", "bfw-track-output", "bfw-track-forward",
	"bfw-skip-to-policy-input", "bfw-skip-to-policy-output", "bfw-skip-to-policy-forward",
}

type icmpv6BeforeRule struct {
	typ     byte
	hl      int // -1 = no hop-limit match
	srcCIDR string
}

var beforeICMPv6Rules = []icmpv6BeforeRule{
	{1, -1, ""}, {2, -1, ""}, {3, -1, ""}, {4, -1, ""}, {128, -1, ""},
	{133, 255, ""}, {134, 255, ""}, {135, 255, ""}, {136, 255, ""},
	{141, 255, ""}, {142, 255, ""},
	{130, -1, "fe80::/10"}, {131, -1, "fe80::/10"}, {132, -1, "fe80::/10"}, {143, -1, "fe80::/10"},
	{148, 255, ""}, {149, 255, ""},
	{151, 1, "fe80::/10"}, {152, 1, "fe80::/10"}, {153, 1, "fe80::/10"},
}

var beforeICMPv6OutputRules = func() []icmpv6BeforeRule {
	out := make([]icmpv6BeforeRule, 0, len(beforeICMPv6Rules)+1)
	out = append(out, beforeICMPv6Rules[:5]...)
	out = append(out, icmpv6BeforeRule{129, -1, ""})
	out = append(out, beforeICMPv6Rules[5:]...)
	return out
}()

var beforeICMPv6ForwardRules = []icmpv6BeforeRule{
	{1, -1, ""}, {2, -1, ""}, {3, -1, ""},
	{4, -1, ""}, {128, -1, ""}, {129, -1, ""},
}

// Common protocol matches are immutable after construction. Rules receive a
// fresh expression slice, but sharing these read-only expression objects avoids
// allocating the same meta/cmp pair for every ordinary rule during a compile.
var cachedNFProto = [2][]expr.Any{
	appendNFProto(nil, false),
	appendNFProto(nil, true),
}

var cachedL4Proto = func() [256][]expr.Any {
	var out [256][]expr.Any
	for _, num := range []byte{
		unix.IPPROTO_TCP, unix.IPPROTO_UDP, unix.IPPROTO_ICMP,
		unix.IPPROTO_ICMPV6, unix.IPPROTO_AH, unix.IPPROTO_ESP,
		unix.IPPROTO_GRE, unix.IPPROTO_IGMP, unix.IPPROTO_IPV6, 112,
	} {
		out[num] = appendL4Proto(nil, num)
	}
	return out
}()

// ICMP type matches are also immutable; indexing all byte values avoids
// rebuilding the payload/cmp pair for the built-in before-rules on every
// compile and for repeated user rules.
var cachedICMPType = func() [256][]expr.Any {
	var out [256][]expr.Any
	for i := range out {
		out[i] = []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(i)}},
		}
	}
	return out
}()

// IPv6 hop limit is byte 7 of the network header (nft's @nh,56,8 form).
var cachedHopLimit = func() [256][]expr.Any {
	var out [256][]expr.Any
	for i := range out {
		out[i] = []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 7, Len: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(i)}},
		}
	}
	return out
}()

var cachedRHType = func() [256][]expr.Any {
	var out [256][]expr.Any
	for i := range out {
		out[i] = []expr.Any{
			&expr.Exthdr{DestRegister: 1, Type: 43, Offset: 2, Len: 1, Op: expr.ExthdrOpIpv6},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{byte(i)}},
		}
	}
	return out
}()

var cachedFibAddrType = func() [256][]expr.Any {
	var out [256][]expr.Any
	for i := range out {
		out[i] = []expr.Any{
			&expr.Fib{Register: 1, ResultADDRTYPE: true, FlagDADDR: true},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(uint32(i))},
		}
	}
	return out
}()

// Limit expressions have the same shape for every rule. The set name/ID and
// protocol-family registers remain per-rule, while these zero-state matches
// are safe to share because nftables only reads them while marshalling.
var cachedCtState = func() [32][]expr.Any {
	var out [32][]expr.Any
	for i := range out {
		out[i] = newCtState(uint32(i))
	}
	return out
}()
var cachedLimitStateNew = cachedCtState[expr.CtStateBitNEW]
var cachedLimitOver = &expr.Limit{
	Type: expr.LimitTypePkts, Rate: 6, Over: true, Unit: expr.LimitTimeMinute,
}
var cachedLimitOverExprs = []expr.Any{cachedLimitOver}

// These expressions contain no per-rule state. nftables serializes each
// expression occurrence independently, so sharing the immutable Go objects
// does not merge kernel counters or otherwise change rule behavior.
var cachedCounter expr.Any = &expr.Counter{}
var cachedAcceptVerdict expr.Any = &expr.Verdict{Kind: expr.VerdictAccept}
var cachedDropVerdict expr.Any = &expr.Verdict{Kind: expr.VerdictDrop}
var cachedReturnVerdict expr.Any = &expr.Verdict{Kind: expr.VerdictReturn}
var cachedReject expr.Any = &expr.Reject{
	Type: unix.NFT_REJECT_ICMPX_UNREACH, Code: unix.NFT_REJECT_ICMPX_PORT_UNREACH,
}
var cachedLimitCounter expr.Any = cachedCounter
var cachedLimitJump expr.Any = &expr.Verdict{Kind: expr.VerdictJump, Chain: chUserLimit}
var cachedLimitAcceptJump expr.Any = &expr.Verdict{Kind: expr.VerdictJump, Chain: chUserLimitA}
var cachedLimitKeyTypes = [2]nftables.SetDatatype{
	nftables.MustConcatSetType(nftables.TypeIPAddr, nftables.TypeInetService),
	nftables.MustConcatSetType(nftables.TypeIP6Addr, nftables.TypeInetService),
}
var cachedLimitAddrPayload = [2]expr.Any{
	&expr.Payload{DestRegister: unix.NFT_REG32_00, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
	&expr.Payload{DestRegister: unix.NFT_REG_1, Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 16},
}
var cachedLimitPortPayload = [2]expr.Any{
	&expr.Payload{DestRegister: unix.NFT_REG32_01, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
	&expr.Payload{DestRegister: unix.NFT_REG_2, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
}
var cachedLimitPortImmediate = [2]expr.Any{
	&expr.Immediate{Register: unix.NFT_REG32_01, Data: []byte{0, 0}},
	&expr.Immediate{Register: unix.NFT_REG_2, Data: []byte{0, 0}},
}

// Transport-header loads are identical for every user rule. The endpoint
// index is zero for sport and one for dport; the payload register is local to
// each compiled rule and is therefore safe to reuse as an immutable value.
var cachedPortPayload = [2]*expr.Payload{
	{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2},
	{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
}

// Port values are always two-byte big-endian keys. Keeping the encodings in
// one immutable table avoids a tiny heap allocation for every comparison and
// interval element while retaining the exact binaryutil representation.
var cachedPortData = func() [1 << 16][2]byte {
	var data [1 << 16][2]byte
	for i := range data {
		data[i][0] = byte(i >> 8)
		data[i][1] = byte(i)
	}
	return data
}()

type portEqCacheKey struct {
	which string
	port  uint16
}

var cachedStaticPortEq = func() map[portEqCacheKey][]expr.Any {
	keys := []portEqCacheKey{
		{which: "sport", port: 67}, {which: "dport", port: 68},
		{which: "sport", port: 547}, {which: "dport", port: 546},
		{which: "dport", port: 5353}, {which: "dport", port: 1900},
		{which: "dport", port: 137}, {which: "dport", port: 138},
		{which: "dport", port: 139}, {which: "dport", port: 445},
		{which: "dport", port: 547},
	}
	out := make(map[portEqCacheKey][]expr.Any, len(keys))
	for _, key := range keys {
		out[key] = makePortEq(key.which, key.port)
	}
	return out
}()

// Address payloads differ only by family and endpoint. Named-set lookups and
// literal address matches use the same network-header load shape.
var cachedAddrPayload = [2][2]*expr.Payload{
	{
		{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
		{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
	},
	{
		{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 8, Len: 16},
		{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 24, Len: 16},
	},
}

var cachedLoopbackIIF = appendIfaceMatch(nil, expr.MetaKeyIIFNAME, "lo")
var cachedLoopbackOIF = appendIfaceMatch(nil, expr.MetaKeyOIFNAME, "lo")

type addrMatchCacheKey struct {
	which string
	cidr  string
	v6    bool
}

// These addresses are emitted repeatedly by the immutable before-rules. Keep
// their parsed expression graphs once per process; arbitrary user and NAT
// addresses still take the validating path below.
var cachedStaticAddrMatches = func() map[addrMatchCacheKey][]expr.Any {
	keys := []addrMatchCacheKey{
		{which: "saddr", cidr: "fe80::/10", v6: true},
		{which: "daddr", cidr: "fe80::/10", v6: true},
		{which: "daddr", cidr: "224.0.0.251", v6: false},
		{which: "daddr", cidr: "ff02::fb", v6: true},
		{which: "daddr", cidr: "239.255.255.250", v6: false},
		{which: "daddr", cidr: "ff02::f", v6: true},
	}
	out := make(map[addrMatchCacheKey][]expr.Any, len(keys))
	for _, key := range keys {
		out[key] = appendAddrMatch(nil, key.which, key.cidr, key.v6)
	}
	return out
}()

var cachedJumps = func() map[string]expr.Any {
	chains := make(map[string]expr.Any, 32)
	add := func(name string) { chains[name] = &expr.Verdict{Kind: expr.VerdictJump, Chain: name} }
	for _, d := range directions {
		for _, prefix := range []string{
			"bfw-before-logging-", "bfw-before-", "bfw-user-", "bfw-after-",
			"bfw-after-logging-", "bfw-user-logging-", "bfw-reject-", "bfw-track-",
			"bfw-skip-to-policy-",
		} {
			add(prefix + d.base)
		}
	}
	for _, name := range []string{
		chNotLocal, chLogDeny, chLogAllow, chUserLimit, chUserLimitA, chUserEgress,
	} {
		add(name)
	}
	return chains
}()

var cachedLimit3 expr.Any = &expr.Limit{
	Type: expr.LimitTypePkts, Rate: 3, Unit: expr.LimitTimeMinute, Burst: 10,
}
var cachedLimit3Exprs = []expr.Any{cachedLimit3}

// Built-in logging prefixes are immutable and recur on every compile.
var cachedLogExpressions = map[string]expr.Any{
	"[BFW ALLOW] ":         &expr.Log{Key: 1 << unix.NFTA_LOG_PREFIX, Data: []byte("[BFW ALLOW] ")},
	"[BFW BLOCK] ":         &expr.Log{Key: 1 << unix.NFTA_LOG_PREFIX, Data: []byte("[BFW BLOCK] ")},
	"[BFW LIMIT] ":         &expr.Log{Key: 1 << unix.NFTA_LOG_PREFIX, Data: []byte("[BFW LIMIT] ")},
	"[BFW AUDIT] ":         &expr.Log{Key: 1 << unix.NFTA_LOG_PREFIX, Data: []byte("[BFW AUDIT] ")},
	"[BFW AUDIT INVALID] ": &expr.Log{Key: 1 << unix.NFTA_LOG_PREFIX, Data: []byte("[BFW AUDIT INVALID] ")},
	"[BFW LIMIT BLOCK] ":   &expr.Log{Key: 1 << unix.NFTA_LOG_PREFIX, Data: []byte("[BFW LIMIT BLOCK] ")},
}

// userChainFor returns the canonical user chain without constructing a new
// string for every compiled rule. Unknown directions retain the existing
// fail-closed mapping to the input chain.
func userChainFor(dir string) string {
	switch dir {
	case "out":
		return "bfw-user-output"
	case "routed":
		return "bfw-user-forward"
	default:
		return "bfw-user-input"
	}
}

func userLoggingChainFor(dir string) string {
	switch dir {
	case "out":
		return "bfw-user-logging-output"
	case "routed":
		return "bfw-user-logging-forward"
	default:
		return "bfw-user-logging-input"
	}
}

func afterLoggingChainFor(dir string) string {
	switch dir {
	case "out":
		return "bfw-after-logging-output"
	case "routed":
		return "bfw-after-logging-forward"
	default:
		return "bfw-after-logging-input"
	}
}

func policyFor(p store.Policies, dir string) string {
	switch dir {
	case "out":
		return p.Output
	case "routed":
		return p.Forward
	default:
		return p.Input
	}
}

func overridePolicy(current, raw string) string {
	switch strings.ToLower(raw) {
	case "accept", "allow":
		return "allow"
	case "drop", "deny":
		return "deny"
	case "reject":
		return "reject"
	default:
		return current
	}
}

// compiled is the full object graph for one Apply batch.
type compiled struct {
	table       *nftables.Table
	chains      []*nftables.Chain
	chainArenas [][]nftables.Chain
	chainIndex  map[string]*nftables.Chain
	sets        []*nftables.Set
	setArenas   [][]nftables.Set
	elems       map[*nftables.Set][]nftables.SetElement
	setIndex    map[uint32]*nftables.Set
	limitSets   map[string]*nftables.Set
	rules       []*nftables.Rule
	ruleArenas  [][]nftables.Rule
	ruleCap     int
	exprArenas  []exprArena
	cmpArenas   [][]expr.Cmp
	rangeArenas [][]expr.Range
	dynArenas   [][]expr.Dynset
	byteArenas  [][]byte
	natTables   []*nftables.Table
	setID       uint32
	threatBans4 *nftables.Set
	threatBans6 *nftables.Set
}

// exprArena owns disjoint capacity windows for match slices. Each returned
// slice is capped at its reserved window so later rules cannot append over a
// previous rule's expressions. The backing arrays remain stable for the life
// of the compiled ruleset.
type exprArena struct {
	values []expr.Any
	used   int
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
	if len(c.chainArenas) == 0 || len(c.chainArenas[len(c.chainArenas)-1]) == cap(c.chainArenas[len(c.chainArenas)-1]) {
		c.chainArenas = append(c.chainArenas, make([]nftables.Chain, 0, 64))
	}
	arena := &c.chainArenas[len(c.chainArenas)-1]
	*arena = append(*arena, nftables.Chain{Name: name, Table: c.table})
	ch := &(*arena)[len(*arena)-1]
	c.chains = append(c.chains, ch)
	c.chainIndex[name] = ch
	return ch
}

func (c *compiled) addRule(chain string, exprs ...expr.Any) {
	c.addRuleObject(c.table, c.chain(chain), exprs)
}

func (c *compiled) exprSlice(capHint int) []expr.Any {
	return c.exprSliceWithChunk(capHint, 4096)
}

func (c *compiled) exprSliceWithChunk(capHint, chunkCap int) []expr.Any {
	if capHint <= 0 {
		return nil
	}
	if len(c.exprArenas) == 0 || len(c.exprArenas[len(c.exprArenas)-1].values)-c.exprArenas[len(c.exprArenas)-1].used < capHint {
		arenaCap := chunkCap
		if capHint > arenaCap {
			arenaCap = capHint
		}
		c.exprArenas = append(c.exprArenas, exprArena{values: make([]expr.Any, arenaCap)})
	}
	arena := &c.exprArenas[len(c.exprArenas)-1]
	start := arena.used
	arena.used += capHint
	return arena.values[start : start : start+capHint]
}

// addRuleObject stores rule values in stable chunks before retaining pointers
// to them. A single large ruleset otherwise allocates one nftables.Rule object
// per rule; chunked storage keeps pointers stable without requiring a costly
// exact count for every optional logging, limit, and NAT branch.
func (c *compiled) addRuleObject(table *nftables.Table, chain *nftables.Chain, exprs []expr.Any) {
	if len(c.ruleArenas) == 0 || len(c.ruleArenas[len(c.ruleArenas)-1]) == cap(c.ruleArenas[len(c.ruleArenas)-1]) {
		capHint := c.ruleCap
		if capHint == 0 || len(c.ruleArenas) != 0 {
			capHint = 256
		}
		c.ruleArenas = append(c.ruleArenas, make([]nftables.Rule, 0, capHint))
	}
	arena := &c.ruleArenas[len(c.ruleArenas)-1]
	*arena = append(*arena, nftables.Rule{Table: table, Chain: chain, Exprs: exprs})
	r := &(*arena)[len(*arena)-1]
	c.rules = append(c.rules, r)
}

// cmpEq allocates rule-specific port comparisons from stable chunks. The
// comparison data is immutable after construction and points either to the
// shared port table or to address bytes owned by the compiled expression.
func (c *compiled) cmpEq(data []byte) *expr.Cmp {
	if len(c.cmpArenas) == 0 || len(c.cmpArenas[len(c.cmpArenas)-1]) == cap(c.cmpArenas[len(c.cmpArenas)-1]) {
		c.cmpArenas = append(c.cmpArenas, make([]expr.Cmp, 0, 256))
	}
	arena := &c.cmpArenas[len(c.cmpArenas)-1]
	*arena = append(*arena, expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: data})
	return &(*arena)[len(*arena)-1]
}

// portRange stores a rule-specific range expression in stable chunks so the
// returned pointer remains valid until the compiled ruleset is discarded.
func (c *compiled) portRange(from, to []byte) *expr.Range {
	if len(c.rangeArenas) == 0 || len(c.rangeArenas[len(c.rangeArenas)-1]) == cap(c.rangeArenas[len(c.rangeArenas)-1]) {
		c.rangeArenas = append(c.rangeArenas, make([]expr.Range, 0, 128))
	}
	arena := &c.rangeArenas[len(c.rangeArenas)-1]
	*arena = append(*arena, expr.Range{Op: expr.CmpOpEq, Register: 1, FromData: from, ToData: to})
	return &(*arena)[len(*arena)-1]
}

// newSet stores limit and anonymous port sets in stable chunks for the same
// reason addRuleObject chunks rules: sets are retained by pointer for the
// life of the compiled ruleset.
func (c *compiled) newSet() *nftables.Set {
	if len(c.setArenas) == 0 || len(c.setArenas[len(c.setArenas)-1]) == cap(c.setArenas[len(c.setArenas)-1]) {
		c.setArenas = append(c.setArenas, make([]nftables.Set, 0, 64))
	}
	arena := &c.setArenas[len(c.setArenas)-1]
	*arena = append(*arena, nftables.Set{})
	return &(*arena)[len(*arena)-1]
}

// arenaBytes reserves n zeroed bytes in a chunk-owned slice so data retained
// by compiled objects stays valid without one heap allocation per use.
func (c *compiled) arenaBytes(n int) []byte {
	if len(c.byteArenas) == 0 || len(c.byteArenas[len(c.byteArenas)-1])+n > cap(c.byteArenas[len(c.byteArenas)-1]) {
		c.byteArenas = append(c.byteArenas, make([]byte, 0, 4096))
	}
	arena := &c.byteArenas[len(c.byteArenas)-1]
	off := len(*arena)
	*arena = append(*arena, make([]byte, n)...)
	return (*arena)[off : off+n]
}

// addrBytes copies an address into a chunk-owned byte slice so set-element
// keys stay valid for the life of the compiled ruleset without one heap
// allocation per interval bound.
func (c *compiled) addrBytes(addr netip.Addr, v6 bool) []byte {
	n := 4
	if v6 {
		n = 16
	}
	out := c.arenaBytes(n)
	if v6 {
		b := addr.As16()
		copy(out, b[:])
	} else {
		b := addr.As4()
		copy(out, b[:])
	}
	return out
}

// addrEndBytes encodes the end-exclusive bound. An invalid Addr (the range
// ran past the family maximum) is emitted as all-zeros, the same convention
// the kernel and nft use for an interval ending at the top of the space.
func (c *compiled) addrEndBytes(end netip.Addr, v6 bool) []byte {
	if end.IsValid() {
		return c.addrBytes(end, v6)
	}
	n := 4
	if v6 {
		n = 16
	}
	return c.arenaBytes(n)
}

// newDynset stores per-rule dynset expressions in stable chunks. The kernel
// operation fields differ per rule only in set name/ID, but each limit rule
// still needs its own object.
func (c *compiled) newDynset() *expr.Dynset {
	if len(c.dynArenas) == 0 || len(c.dynArenas[len(c.dynArenas)-1]) == cap(c.dynArenas[len(c.dynArenas)-1]) {
		c.dynArenas = append(c.dynArenas, make([]expr.Dynset, 0, 256))
	}
	arena := &c.dynArenas[len(c.dynArenas)-1]
	*arena = append(*arena, expr.Dynset{})
	return &(*arena)[len(*arena)-1]
}

// addSet records a set in compile order and indexes anonymous sets by their
// pre-assigned kernel ID for constant-time rendering. Set IDs are unique
// within one batch; retaining the slice order keeps netlink and diff output
// stable.
func (c *compiled) addSet(s *nftables.Set, elems []nftables.SetElement) {
	c.sets = append(c.sets, s)
	if s.Anonymous && s.ID != 0 {
		c.setIndex[s.ID] = s
	}
	if elems != nil {
		c.elems[s] = elems
	}
}

// limitSetsMap allocates the limit-set index only when the ruleset actually
// contains limit rules; plain policies skip the map entirely.
func limitSetsMap(limitCount int) map[string]*nftables.Set {
	if limitCount == 0 {
		return nil
	}
	return make(map[string]*nftables.Set, limitCount)
}

// compile builds the complete ruleset for st. etc carries /etc/default
// values; IPV6 there overrides st.IPv6 when present (same precedence ufw
// gives /etc/default/ufw).
func compile(st *store.State, etc map[string]string) (*compiled, error) {
	limitCount := 0
	for _, r := range st.Rules4 {
		if r.Action == rule.ActionLimit {
			limitCount++
		}
	}
	for _, r := range st.Rules6 {
		if r.Action == rule.ActionLimit {
			limitCount++
		}
	}
	ruleReserve, setReserve, anonymousSetReserve := 128, 2+2*len(st.Sets)+limitCount, 0
	reserveRules := func(rules []rule.Rule) {
		for _, r := range rules {
			variants := 1
			if (r.Proto == "" || r.Proto == "any") && (len(r.Src.Ports) != 0 || len(r.Dst.Ports) != 0) {
				variants = 2 // bare ports expand to tcp and udp
			}
			ruleReserve += variants
			if r.Log != rule.LogNone {
				ruleReserve += 3 * variants // log, return, and user-chain jump
			}
			if r.Action == rule.ActionLimit {
				ruleReserve += variants // over-limit and under-limit branches
			}
			if len(r.Src.Ports) > 1 {
				setReserve += variants
				anonymousSetReserve += variants
			}
			if len(r.Dst.Ports) > 1 {
				setReserve += variants
				anonymousSetReserve += variants
			}
		}
	}
	reserveRules(st.Rules4)
	reserveRules(st.Rules6)
	c := &compiled{
		table: &nftables.Table{Family: nftables.TableFamilyINet, Name: TableName},
		// Reserve the object graph once. Apply sends every object in one
		// batch, so repeated slice growth here only copies pointers while the
		// ruleset is being built. The rule estimate deliberately errs high for
		// logged/limited rules; the small pointer reserve is cheaper than the
		// repeated growth and copying on the common large-ruleset path.
		chains:     make([]*nftables.Chain, 0, 48),
		rules:      make([]*nftables.Rule, 0, ruleReserve+128+2*len(st.NAT)),
		ruleCap:    ruleReserve + 128 + 2*len(st.NAT),
		sets:       make([]*nftables.Set, 0, setReserve),
		chainIndex: make(map[string]*nftables.Chain, 48),
		elems:      make(map[*nftables.Set][]nftables.SetElement, setReserve),
		setIndex:   make(map[uint32]*nftables.Set, anonymousSetReserve),
		limitSets:  limitSetsMap(limitCount),
	}

	pol := st.Policies
	if st.Panic {
		pol = store.Policies{Input: "deny", Output: "deny", Forward: "deny"}
	}
	// /etc/default/better-firewall DEFAULT_*_POLICY keys override stored policies
	// (ufw reads them from /etc/default/ufw at apply time) — but never
	// override panic's forced deny-all.
	if !st.Panic {
		if v, ok := etc["DEFAULT_INPUT_POLICY"]; ok {
			pol.Input = overridePolicy(pol.Input, v)
		}
		if v, ok := etc["DEFAULT_OUTPUT_POLICY"]; ok {
			pol.Output = overridePolicy(pol.Output, v)
		}
		if v, ok := etc["DEFAULT_FORWARD_POLICY"]; ok {
			pol.Forward = overridePolicy(pol.Forward, v)
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
	for i, d := range directions {
		p := policyFor(pol, d.dir)
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
				c.addRule(d.base, c.join(nfproto(true), iif("lo"), ex(counter(), verdict(expr.VerdictAccept)))...)
			case "out":
				c.addRule(d.base, c.join(nfproto(true), oif("lo"), ex(counter(), verdict(expr.VerdictAccept)))...)
			}
			c.addRule(d.base, c.join(nfproto(true), ex(counter(), verdict(expr.VerdictDrop)))...)
		}

		// ufw-init-functions jump order. The user jump lives in the base
		// chain (not inside bfw-before-*) so before.rules fragments appended
		// later still run before user rules, and a fragment `flush chain`
		// can't delete the user jump.
		for _, target := range baseJumpChains[i] {
			c.addRule(d.base, counter(), jump(target))
		}
	}
	// Pre-create every regular chain (ufw creates them all even when
	// empty) in ufw's declaration order.
	for _, name := range regularChainNames {
		c.chain(name)
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
		p := policyFor(pol, d.dir)
		if p == "reject" {
			c.addRule("bfw-reject-"+d.base, counter(), rejectExpr())
		}
		if p == "allow" {
			// ufw track chains: statefully accept new tcp/udp so the
			// accept policy is conntrack-aware.
			for _, proto := range []byte{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
				c.addRule("bfw-track-"+d.base,
					c.join(l4proto(proto), ctState(expr.CtStateBitNEW),
						ex(counter(), verdict(expr.VerdictAccept)))...)
			}
		}
		// skip-to-policy chains exist so after.rules fragments can jump
		// noisy traffic straight to the policy verdict (ufw parity).
		c.addRule("bfw-skip-to-policy-"+d.base, counter(), policyVerdict(p))
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

	c.compileLoggingChains(level, pol)

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
		match := c.join(nfproto(family.v6), ex(
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
	c.addRule(in, c.join(iif("lo"), ex(counter(), verdict(expr.VerdictAccept)))...)
	c.addRule(out, c.join(oif("lo"), ex(counter(), verdict(expr.VerdictAccept)))...)

	// RH0 drop (v6): rt type 0 = exthdr routing-header type byte (offset 2)
	for _, ch := range []string{in, out, fwd} {
		c.addRule(ch, c.join(nfproto(true), rhType(0), ex(counter(), verdict(expr.VerdictDrop)))...)
	}

	c.addThreatBanRules(in)
	c.addThreatBanRules(fwd)

	// established/related fast path
	for _, ch := range []string{in, out, fwd} {
		c.addRule(ch, c.join(ctState(expr.CtStateBitESTABLISHED|expr.CtStateBitRELATED),
			ex(counter(), verdict(expr.VerdictAccept)))...)
	}

	// v6 multicast ping replies arrive without conntrack state (rfc4890)
	c.addRule(in, c.join(nfproto(true), l4proto(unix.IPPROTO_ICMPV6), icmpType(129),
		ex(counter(), verdict(expr.VerdictAccept)))...)

	// INVALID → logging-deny then drop (ufw logs INVALID at medium+)
	c.addRule(in, c.join(ctState(expr.CtStateBitINVALID), ex(counter(), jump(chLogDeny)))...)
	c.addRule(in, c.join(ctState(expr.CtStateBitINVALID), ex(counter(), verdict(expr.VerdictDrop)))...)

	// ICMPv4 accepts (before.rules): destination-unreachable, time-exceeded,
	// parameter-problem, echo-request. (ufw dropped source-quench in 0.36.)
	for _, ch := range []string{in, fwd} {
		for _, t := range []byte{3, 11, 12, 8} {
			c.addRule(ch, c.join(nfproto(false), l4proto(unix.IPPROTO_ICMP), icmpType(t),
				ex(counter(), verdict(expr.VerdictAccept)))...)
		}
	}

	// ICMPv6 accepts (before6.rules, rfc4890). hl = hop limit @ nh+1.
	emit6 := func(ch string, list []icmpv6BeforeRule) {
		for _, r := range list {
			var srcMatch, hopMatch []expr.Any
			if r.srcCIDR != "" {
				srcMatch = addrMatch("saddr", r.srcCIDR, true)
			}
			if r.hl >= 0 {
				hopMatch = hopLimit(byte(r.hl))
			}
			ex := c.join(nfproto(true), l4proto(unix.IPPROTO_ICMPV6), icmpType(r.typ),
				srcMatch, hopMatch, ex(counter(), verdict(expr.VerdictAccept)))
			c.addRule(ch, ex...)
		}
	}
	emit6(in, beforeICMPv6Rules)
	// output adds echo-reply after echo-request
	emit6(out, beforeICMPv6OutputRules)
	// forward: base set + echo-reply only (rfc4890 4.3.1)
	emit6(fwd, beforeICMPv6ForwardRules)
	// HAAD/MPS/MPA (before6.rules places these on input)
	for _, t := range []byte{144, 145, 146, 147} {
		c.addRule(in, c.join(nfproto(true), l4proto(unix.IPPROTO_ICMPV6), icmpType(t),
			ex(counter(), verdict(expr.VerdictAccept)))...)
	}

	// DHCP client: v4 udp 67→68; v6 link-local 547→546
	c.addRule(in, c.join(nfproto(false), l4proto(unix.IPPROTO_UDP),
		portEq("sport", 67), portEq("dport", 68),
		ex(counter(), verdict(expr.VerdictAccept)))...)
	c.addRule(in, c.join(nfproto(true), l4proto(unix.IPPROTO_UDP),
		addrMatch("saddr", "fe80::/10", true), portEq("sport", 547),
		addrMatch("daddr", "fe80::/10", true), portEq("dport", 546),
		ex(counter(), verdict(expr.VerdictAccept)))...)

	// non-local drop (v4 only in ufw: before6.rules has no not-local chain)
	c.addRule(in, c.join(nfproto(false), ex(counter(), jump(chNotLocal)))...)
	for _, t := range []uint32{unix.RTN_LOCAL, unix.RTN_MULTICAST, unix.RTN_BROADCAST} {
		c.addRule(chNotLocal, c.join(fibAddrType(t), ex(counter(), verdict(expr.VerdictReturn)))...)
	}
	c.addRule(chNotLocal, limit3(), counter(), jump(chLogDeny))
	c.addRule(chNotLocal, counter(), verdict(expr.VerdictDrop))

	// mDNS + UPnP multicast
	c.addRule(in, c.join(nfproto(false), l4proto(unix.IPPROTO_UDP),
		addrMatch("daddr", "224.0.0.251", false), portEq("dport", 5353),
		ex(counter(), verdict(expr.VerdictAccept)))...)
	c.addRule(in, c.join(nfproto(true), l4proto(unix.IPPROTO_UDP),
		addrMatch("daddr", "ff02::fb", true), portEq("dport", 5353),
		ex(counter(), verdict(expr.VerdictAccept)))...)
	c.addRule(in, c.join(nfproto(false), l4proto(unix.IPPROTO_UDP),
		addrMatch("daddr", "239.255.255.250", false), portEq("dport", 1900),
		ex(counter(), verdict(expr.VerdictAccept)))...)
	c.addRule(in, c.join(nfproto(true), l4proto(unix.IPPROTO_UDP),
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
	c.addRule(in, c.join(nfproto(false), fibAddrType(unix.RTN_BROADCAST),
		ex(counter(), jump(skip)))...)
	for _, p := range []uint16{137, 138} {
		c.addRule(in, c.join(nfproto(false), l4proto(unix.IPPROTO_UDP), portEq("dport", p),
			ex(counter(), jump(skip)))...)
	}
	for _, p := range []uint16{139, 445} {
		c.addRule(in, c.join(nfproto(false), l4proto(unix.IPPROTO_TCP), portEq("dport", p),
			ex(counter(), jump(skip)))...)
	}
	c.addRule(in, c.join(nfproto(false), l4proto(unix.IPPROTO_UDP),
		portEq("sport", 67), portEq("dport", 68),
		ex(counter(), jump(skip)))...)

	// v6: DHCPv6 server+client ports (after6.rules).
	for _, p := range []uint16{546, 547} {
		c.addRule(in, c.join(nfproto(true), l4proto(unix.IPPROTO_UDP), portEq("dport", p),
			ex(counter(), jump(skip)))...)
	}
}

// compileLoggingChains emits the level-dependent contents of the logging
// chains, mirroring backend_iptables.py _get_logging_rules.
func (c *compiled) compileLoggingChains(level string, policies store.Policies) {
	userLogging := [3]string{}
	for i, d := range directions {
		userLogging[i] = userLoggingChainFor(d.dir)
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

	// low+: after-logging logs packets about to hit a deny/reject policy;
	// medium+ also logs packets about to hit an accept policy.
	for _, d := range directions {
		ch := afterLoggingChainFor(d.dir)
		p := policyFor(policies, d.dir)
		switch {
		case p == "deny" || p == "reject":
			if limited {
				c.addRule(ch, limit3(), logExpr("[BFW BLOCK] "))
			} else {
				c.addRule(ch, logExpr("[BFW BLOCK] "))
			}
		case level != "low": // medium+
			if limited {
				c.addRule(ch, limit3(), logExpr("[BFW ALLOW] "))
			} else {
				c.addRule(ch, logExpr("[BFW ALLOW] "))
			}
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
				c.addRule(ch, c.join(ctState(expr.CtStateBitINVALID), cachedLimit3Exprs,
					ex(counter(), verdict(expr.VerdictReturn)))...)
			} else {
				if limited {
					c.addRule(ch, c.join(ctState(expr.CtStateBitINVALID), ex(limit3(), logExpr("[BFW AUDIT INVALID] ")))...)
				} else {
					c.addRule(ch, c.join(ctState(expr.CtStateBitINVALID), ex(logExpr("[BFW AUDIT INVALID] ")))...)
				}
			}
		}
		if limited {
			c.addRule(ch, limit3(), logExpr(prefix))
		} else {
			c.addRule(ch, logExpr(prefix))
		}
	}

	// medium+: before-logging audit chains.
	if level != "low" {
		for _, d := range directions {
			ch := "bfw-before-logging-" + d.base
			switch level {
			case "medium": // new connections only, rate-limited
				c.addRule(ch, c.join(ctState(expr.CtStateBitNEW), ex(limit3(), logExpr("[BFW AUDIT] ")))...)
			case "high": // all packets, rate-limited
				c.addRule(ch, limit3(), logExpr("[BFW AUDIT] "))
			case "full": // all packets, unlimited
				c.addRule(ch, logExpr("[BFW AUDIT] "))
			default:
				c.addRule(ch, logExpr("[BFW AUDIT] "))
			}
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
	c.addSet(v4, nil)
	c.addSet(v6, nil)
	// Reserve family-specific input cardinalities. Address text contains a
	// colon for IPv6, so this avoids an unused full-size backing array for the
	// common all-IPv4 ban list while keeping mixed-family sets growth-free.
	v4Cap, v6Cap := 0, 0
	for _, element := range elements {
		if strings.IndexByte(element, ':') >= 0 {
			v6Cap++
		} else {
			v4Cap++
		}
	}
	iv4 := make([]addrInterval, 0, v4Cap) // [start, endExclusive)
	iv6 := make([]addrInterval, 0, v6Cap)
	for _, element := range elements {
		addr, bits, err := parseAddrOrPrefix(element)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: bad element %q", source, element)
		}
		prefix := netip.PrefixFrom(addr, bits).Masked()
		end := intervalEnd(prefix.Addr(), bits) // invalid Addr = past family max
		if addr.Is4() {
			iv4 = append(iv4, addrInterval{prefix.Addr(), end})
		} else {
			iv6 = append(iv6, addrInterval{prefix.Addr(), end})
		}
	}
	// Overlapping intervals make the kernel reject the whole batch
	// (__nft_rbtree_insert ENOTEMPTY); merge like nft does. Build the final
	// element slices with their exact size so large ban lists do not repeatedly
	// grow and copy the map values.
	setIntervals := func(set *nftables.Set, intervals []addrInterval, v6 bool) {
		merged := mergeAddrIntervals(intervals)
		if len(merged) == 0 {
			return
		}
		elems := make([]nftables.SetElement, 0, len(merged)*2)
		for _, interval := range merged {
			elems = append(elems,
				nftables.SetElement{Key: c.addrBytes(interval.start, v6)},
				nftables.SetElement{Key: c.addrEndBytes(interval.end, v6), IntervalEnd: true})
		}
		c.elems[set] = elems
	}
	setIntervals(v4, iv4, false)
	setIntervals(v6, iv6, true)
	return v4, v6, nil
}

// addrInterval is a [start, endExclusive) address range. An invalid end Addr
// means the range runs past the family maximum (the end-exclusive marker is
// emitted as all-zeros, matching nft's interval convention).
type addrInterval struct {
	start netip.Addr
	end   netip.Addr
}

// parseAddrOrPrefix accepts a CIDR or bare IP and returns the address and its
// prefix length in bits. IPv4-mapped IPv6 inputs are unmapped to keep the
// v4/v6 split consistent with element text. The '/' pre-check avoids
// ParsePrefix's quoted error string on the common bare-IP path.
func parseAddrOrPrefix(s string) (netip.Addr, int, error) {
	if strings.IndexByte(s, '/') >= 0 {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Addr{}, 0, err
		}
		addr := p.Addr()
		bits := p.Bits()
		if addr.Is4In6() && bits >= 96 {
			// A 4in6 prefix whose bits cover only the mapped tail is a v4
			// network: net.ParseCIDR produced a 4-byte result for these.
			return addr.Unmap(), bits - 96, nil
		}
		return addr, bits, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	addr = addr.Unmap()
	bits := 128
	if addr.Is4() {
		bits = 32
	}
	return addr, bits, nil
}

// intervalEnd returns the end-exclusive bound of a prefix: its masked last
// address plus one. A prefix ending at the family maximum overflows Addr and
// returns the invalid Addr, which mergeAddrIntervals treats as +∞.
func intervalEnd(addr netip.Addr, bits int) netip.Addr {
	n := 16
	if addr.Is4() {
		n = 4
	}
	var b [16]byte
	if addr.Is4() {
		b4 := addr.As4()
		copy(b[:4], b4[:])
	} else {
		b = addr.As16()
	}
	for i := bits; i < 8*n; i++ {
		b[i/8] |= 1 << (7 - uint(i%8))
	}
	if addr.Is4() {
		return netip.AddrFrom4([4]byte(b[:4])).Next()
	}
	return netip.AddrFrom16(b).Next()
}

// mergeAddrIntervals sorts and coalesces overlapping/adjacent
// [start,endExclusive) intervals so the kernel accepts them in one batch.
func mergeAddrIntervals(ivs []addrInterval) []addrInterval {
	if len(ivs) == 0 {
		return nil
	}
	sort.Slice(ivs, func(i, j int) bool {
		return ivs[i].start.Compare(ivs[j].start) < 0
	})
	// Compact in the caller-owned interval backing array. The range below
	// reads each source element before any append can overwrite that same
	// position, so no second interval slice is needed.
	out := ivs[:1]
	for _, iv := range ivs[1:] {
		last := &out[len(out)-1]
		// iv.start <= last.end → overlap or adjacency: extend end. An
		// invalid end is +∞ within the family.
		if last.end.IsValid() && iv.start.Compare(last.end) > 0 {
			out = append(out, iv)
			continue
		}
		if !last.end.IsValid() || !iv.end.IsValid() || iv.end.Compare(last.end) > 0 {
			last.end = iv.end
		}
	}
	return out
}

// compileRule emits the nft rules for one model rule into the appropriate
// bfw-user-* chain (and bfw-user-logging-* when logged).
func (c *compiled) compileRule(r *rule.Rule, v6 bool, now int64) error {
	if r.Disabled || r.Expired(now) {
		return nil
	}
	userChain := userChainFor(r.Direction)
	logChain := userLoggingChainFor(r.Direction)

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
			// Keep the match slice for the other rule variants. Appending to
			// it is safe because ruleMatch returns a fresh slice for every
			// variant; only the slice header is changed here.
			lm := match
			if r.Log == rule.LogNew {
				lm = append(lm, ctState(expr.CtStateBitNEW)...)
			}
			lm = append(lm, limit3(), logExpr(logPrefix(r.Action)))
			c.addRule(logChain, lm...)
			rm := append([]expr.Any(nil), match...)
			if r.Log == rule.LogNew {
				rm = append(rm, ctState(expr.CtStateBitNEW)...)
			}
			c.addRule(logChain, append(rm, counter(), verdict(expr.VerdictReturn))...)
			c.addRule(userChain, append(append([]expr.Any(nil), match...), counter(), jump(logChain))...)
		}
		actionMatch := match
		if r.Log != rule.LogNone && r.Action != rule.ActionLimit {
			// The logged rule above owns match's backing array after its
			// append. Clone before adding the terminal action so the two
			// compiled nft rules cannot alias and overwrite one another.
			actionMatch = append([]expr.Any(nil), match...)
		}
		switch r.Action {
		case rule.ActionAllow:
			c.addRule(userChain, append(actionMatch, counter(), verdict(expr.VerdictAccept))...)
		case rule.ActionDeny:
			c.addRule(userChain, append(actionMatch, counter(), verdict(expr.VerdictDrop))...)
		case rule.ActionReject:
			c.addRule(userChain, append(actionMatch, counter(), rejectExpr())...)
		case rule.ActionLimit:
			limitMatch := match
			if r.Log != rule.LogNone {
				// The logging rule owns match's backing array; limit's two
				// branches must be built from an independent prefix.
				limitMatch = append([]expr.Any(nil), match...)
			}
			if err := c.compileLimit(r, proto, v6, limitMatch, userChain); err != nil {
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
	family := 0
	if v6 {
		family = 1
	}
	name := "bfw_limit_" + r.ID
	if v6 {
		name += "6" // dual v4/v6 rules share r.ID; qualify the set name
	}
	// Reuse an existing dynset of the same name: a proto-any limit rule
	// expands to tcp+udp variants that share r.ID, and emitting the set
	// twice would double it in render/diff (the kernel dedups by name).
	set := c.limitSets[name]
	if set == nil {
		set = c.newSet()
		*set = nftables.Set{
			Table:         c.table,
			Name:          name,
			ID:            c.newSetID(),
			KeyType:       cachedLimitKeyTypes[family],
			Concatenation: true,
			Dynamic:       true,
			HasTimeout:    true,
			Timeout:       30 * time.Second,
			// size 0 makes the kernel refuse the first element add
			// (atomic_add_unless nelems vs size) → the meter never fires and
			// the rule fails open. nft defaults meter sets to 65535.
			Size: 65535,
		}
		c.addSet(set, nil)
		c.limitSets[name] = set
	}

	// Key registers: saddr then dport, contiguous in the kernel's reg32
	// space. v4: NFT_REG32_00 (data[4]) + NFT_REG32_01 (data[5]).
	// v6: NFT_REG_1 (data[4..7]) + NFT_REG_2 (data[8..11]).
	sreg := uint32(unix.NFT_REG32_00)
	if v6 {
		sreg = unix.NFT_REG_1
	}

	// The first limit branch consumes match's backing array. The caller does
	// not retain it after this function, so avoid a full copy for the common
	// path; the second branch clones only the original match prefix below.
	baseLen := len(match)
	ex := match
	ex = append(ex, cachedLimitStateNew...)
	ex = append(ex, cachedLimitAddrPayload[family])
	if proto == "tcp" || proto == "udp" {
		ex = append(ex, cachedLimitPortPayload[family])
	} else {
		ex = append(ex, cachedLimitPortImmediate[family])
	}
	dyn := c.newDynset()
	*dyn = expr.Dynset{
		SrcRegKey: sreg,
		SetName:   set.Name,
		SetID:     set.ID,
		Operation: unix.NFT_DYNSET_OP_UPDATE,
		Timeout:   30 * time.Second,
		Exprs:     cachedLimitOverExprs,
	}
	ex = append(ex, dyn, cachedLimitCounter, cachedLimitJump)
	c.addRule(userChain, ex...)
	acceptMatch := append(c.exprSlice(baseLen+2), match[:baseLen]...)
	c.addRule(userChain, append(acceptMatch, cachedLimitCounter, cachedLimitAcceptJump)...)
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
	capHint := 4 // family match plus the common counter/verdict suffix
	if r.IfaceIn != "" {
		capHint += 3 // meta + optional prefix mask + cmp
	}
	if r.IfaceOut != "" {
		capHint += 3
	}
	if proto != "any" {
		capHint += 2 // l4 protocol meta + cmp
	}
	if r.ICMPType != "" {
		capHint += 2
	}
	if !r.Src.Any() {
		capHint += 3 // payload + optional CIDR bitwise + cmp
	}
	if !r.Dst.Any() {
		capHint += 3
	}
	if proto == "tcp" || proto == "udp" {
		if len(r.Src.Ports) != 0 {
			capHint += 2 // payload + cmp/range/anonymous-set lookup
		}
		if len(r.Dst.Ports) != 0 {
			capHint += 2
		}
	}
	if r.Action == rule.ActionLimit {
		capHint += 8 // state, key loads, dynset, counter, and jump
	}
	if r.Log != rule.LogNone {
		capHint += 5 // rate limit, log, and the logging-rule suffix
		if r.Log == rule.LogNew {
			capHint += 3 // ct state NEW
		}
	}
	ex := c.exprSlice(capHint)
	if v6 {
		ex = append(ex, cachedNFProto[1]...)
	} else {
		ex = append(ex, cachedNFProto[0]...)
	}
	if r.IfaceIn != "" {
		ex = appendIfaceMatch(ex, expr.MetaKeyIIFNAME, r.IfaceIn)
	}
	if r.IfaceOut != "" {
		ex = appendIfaceMatch(ex, expr.MetaKeyOIFNAME, r.IfaceOut)
	}
	if proto != "any" {
		num, err := protoNum(proto)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", r.ID, err)
		}
		ex = append(ex, cachedL4Proto[num]...)
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
		ex = appendICMPType(ex, byte(n))
	}
	ex = c.appendEndpointAddr(ex, &r.Src, "saddr", v6)
	ex = c.appendEndpointAddr(ex, &r.Dst, "daddr", v6)
	// ports (only meaningful for tcp/udp)
	if proto == "tcp" || proto == "udp" {
		ex = c.appendPortExprs(ex, r.Src.Ports, "sport", proto)
		ex = c.appendPortExprs(ex, r.Dst.Ports, "dport", proto)
	}
	return ex, nil
}

// appendEndpointAddr emits the address match for one endpoint directly into
// dst: set lookup, CIDR bitwise, host cmp, or nothing for "any".
func (c *compiled) appendEndpointAddr(dst []expr.Any, a *rule.AddrSpec, which string, v6 bool) []expr.Any {
	if a.Set != "" {
		name := "bfw_set_" + a.Set
		if v6 {
			name += "6"
		}
		family := 0
		if v6 {
			family = 1
		}
		endpoint := 0
		if which == "daddr" {
			endpoint = 1
		}
		return append(dst,
			cachedAddrPayload[family][endpoint],
			&expr.Lookup{SourceRegister: 1, SetName: name},
		)
	}
	if a.Any() {
		return dst
	}
	return c.appendAddrMatch(dst, which, a.IP, v6)
}

// appendPortExprs emits sport/dport matches for the ranges of one proto
// directly into dst. Single port → cmp; lo:hi → range; multiple → anonymous set lookup.
func (c *compiled) appendPortExprs(dst []expr.Any, ports []rule.PortRange, which, proto string) []expr.Any {
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
		return dst
	}
	load := cachedPortPayload[0]
	if which == "dport" {
		load = cachedPortPayload[1]
	}
	if matched == 1 {
		if first.Lo == first.Hi {
			return append(dst, load, c.cmpEq(portData(first.Lo)))
		}
		return append(dst, load, c.portRange(portData(first.Lo), portData(first.Hi)))
	}

	// Multiport rules need an anonymous set. Build its elements directly from
	// the filtered input so no second temporary port slice is required.
	interval := false
	for _, p := range ports {
		if p.Proto != "" && p.Proto != "any" && p.Proto != proto {
			continue
		}
		if p.Multi() {
			interval = true
		}
	}
	set := c.newSet()
	*set = nftables.Set{
		Table: c.table, Anonymous: true, Constant: true,
		ID:      c.newSetID(),
		KeyType: nftables.TypeInetService, Interval: interval,
	}
	set.Name = fmt.Sprintf("__set%d", set.ID)
	var elems []nftables.SetElement
	for _, p := range ports {
		if p.Proto != "" && p.Proto != "any" && p.Proto != proto {
			continue
		}
		if interval {
			elems = append(elems, portIntervalElems(p.Lo, p.Hi)...)
		} else {
			elems = append(elems, nftables.SetElement{Key: portData(p.Lo)})
		}
	}
	c.addSet(set, elems)
	return append(dst, load, &expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID})
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
			c.addRuleObject(t, post[t], ex)
		case "dnat":
			host, portStr := splitToDest(nr.ToDest)
			ip, err := netip.ParseAddr(host)
			if err != nil || ip.Zone() != "" {
				return fmt.Errorf("nat rule %d: bad to-destination %q", i, nr.ToDest)
			}
			ip = ip.Unmap()
			if ip.Is4() == v6 {
				return fmt.Errorf("nat rule %d: to-destination family mismatch", i)
			}
			nat := &expr.NAT{Type: expr.NATTypeDestNAT, Family: natFamily(v6), RegAddrMin: unix.NFT_REG_1}
			ex = append(ex, &expr.Immediate{Register: unix.NFT_REG_1, Data: c.addrBytes(ip, v6)})
			if portStr != "" {
				p, err := strconv.ParseUint(portStr, 10, 16)
				if err != nil {
					return fmt.Errorf("nat rule %d: bad to-destination port %q", i, portStr)
				}
				nat.RegProtoMin = unix.NFT_REG_2
				ex = append(ex, &expr.Immediate{Register: unix.NFT_REG_2, Data: portData(uint16(p))})
			}
			ex = append(ex, nat)
			c.addRuleObject(t, pre[t], ex)
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

func (c *compiled) join(lists ...[]expr.Any) []expr.Any {
	n := 0
	for _, list := range lists {
		n += len(list)
	}
	if n == 0 {
		return nil
	}
	out := c.exprSliceWithChunk(n, 128)
	for _, l := range lists {
		out = append(out, l...)
	}
	return out
}

func nfproto(v6 bool) []expr.Any {
	if v6 {
		return cachedNFProto[1]
	}
	return cachedNFProto[0]
}

func appendNFProto(dst []expr.Any, v6 bool) []expr.Any {
	b := byte(unix.NFPROTO_IPV4)
	if v6 {
		b = unix.NFPROTO_IPV6
	}
	return append(dst,
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{b}},
	)
}

func l4proto(num byte) []expr.Any {
	return cachedL4Proto[num]
}

func appendL4Proto(dst []expr.Any, num byte) []expr.Any {
	return append(dst,
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{num}},
	)
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

func iif(name string) []expr.Any {
	if name == "lo" {
		return cachedLoopbackIIF
	}
	return ifaceMatch(expr.MetaKeyIIFNAME, name)
}

func oif(name string) []expr.Any {
	if name == "lo" {
		return cachedLoopbackOIF
	}
	return ifaceMatch(expr.MetaKeyOIFNAME, name)
}

func ifaceMatch(key expr.MetaKey, name string) []expr.Any {
	return appendIfaceMatch(nil, key, name)
}

func appendIfaceMatch(dst []expr.Any, key expr.MetaKey, name string) []expr.Any {
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
		return append(dst,
			&expr.Meta{Key: key, Register: 1},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 16, Mask: mask, Xor: make([]byte, 16)},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: b},
		)
	}
	b := make([]byte, 16)
	copy(b, name)
	return append(dst,
		&expr.Meta{Key: key, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: b},
	)
}

// addrMatch emits payload+bitwise+cmp (CIDR) or payload+cmp (host) for
// saddr/daddr. which is "saddr" or "daddr". Returns nil on unparseable
// input (callers validate upstream).
func addrMatch(which, cidr string, v6 bool) []expr.Any {
	if cached, ok := cachedStaticAddrMatches[addrMatchCacheKey{which: which, cidr: cidr, v6: v6}]; ok {
		return cached
	}
	return appendAddrMatch(nil, which, cidr, v6)
}

// appendAddrMatch is the allocation-conscious form used while compiling user
// rules. It appends directly to dst while retaining addrMatch's fail-closed
// behavior for malformed or family-mismatched addresses.
func appendAddrMatch(dst []expr.Any, which, cidr string, v6 bool) []expr.Any {
	return appendAddrMatchTo(dst, which, cidr, v6, nil)
}

func (c *compiled) appendAddrMatch(dst []expr.Any, which, cidr string, v6 bool) []expr.Any {
	return appendAddrMatchTo(dst, which, cidr, v6, c)
}

func appendAddrMatchTo(dst []expr.Any, which, cidr string, v6 bool, c *compiled) []expr.Any {
	failClosed := func() []expr.Any {
		// Two contradictory cmps on reg 1 can never both hold, so the rule
		// matches nothing rather than everything.
		if c != nil {
			cmp := c.cmpEq([]byte{0})
			return append(dst, cmp, c.cmpEq([]byte{1}))
		}
		return append(dst,
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0}},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1}},
		)
	}
	addr, bits, err := parseAddrOrPrefix(cidr)
	if err != nil || addr.Zone() != "" {
		// Unparseable input: callers validate upstream, but fail closed.
		return failClosed()
	}
	addr = netip.PrefixFrom(addr, bits).Masked().Addr()
	// Family mismatch (v4 addr in a v6 rule or vice versa) would emit a
	// wrong-length payload load — fail closed instead of a garbage match.
	if addr.Is4() == v6 {
		return failClosed()
	}
	n := 4
	family := 0
	if v6 {
		n = 16
		family = 1
	}
	endpoint := 0
	if which == "daddr" {
		endpoint = 1
	}
	load := cachedAddrPayload[family][endpoint]
	var data []byte
	if c != nil {
		data = c.addrBytes(addr, v6)
	} else if v6 {
		b := addr.As16()
		data = b[:]
	} else {
		b := addr.As4()
		data = b[:]
	}
	if bits == 8*n {
		// Host route: payload + cmp only.
		if c != nil {
			return append(dst, load, c.cmpEq(data))
		}
		return append(dst, load, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: data})
	}
	mask := cidrMaskBytes(c, bits, n)
	xor := zeroBytes(c, n)
	var cmp expr.Any = &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: data}
	if c != nil {
		cmp = c.cmpEq(data)
	}
	return append(dst,
		load,
		&expr.Bitwise{
			SourceRegister: 1, DestRegister: 1, Len: uint32(n),
			Mask: mask, Xor: xor,
		},
		cmp,
	)
}

// cidrMaskBytes returns the n-byte big-endian mask for a prefix of ones bits.
func cidrMaskBytes(c *compiled, ones, n int) []byte {
	if c != nil {
		mask := c.arenaBytes(n)
		for i := range n {
			switch {
			case 8*i+8 <= ones:
				mask[i] = 0xff
			case 8*i >= ones:
				mask[i] = 0
			default:
				mask[i] = 0xff << (8 - uint(ones%8))
			}
		}
		return mask
	}
	mask := make([]byte, n)
	for i := range n {
		switch {
		case 8*i+8 <= ones:
			mask[i] = 0xff
		case 8*i >= ones:
			mask[i] = 0
		default:
			mask[i] = 0xff << (8 - uint(ones%8))
		}
	}
	return mask
}

// zeroBytes returns n zero bytes, arena-backed when c is present.
func zeroBytes(c *compiled, n int) []byte {
	if c == nil {
		return make([]byte, n)
	}
	return c.arenaBytes(n)
}

// portIntervalElems encodes [lo,hi] as an interval-set element pair
// (start, end-exclusive) with the 65535 overflow handled via a 0 end
// marker, matching kernel interval semantics.
func portIntervalElems(lo, hi uint16) []nftables.SetElement {
	start := nftables.SetElement{Key: portData(lo)}
	if hi == 0xffff {
		return []nftables.SetElement{start, {Key: portData(0), IntervalEnd: true}}
	}
	return []nftables.SetElement{start, {Key: portData(hi + 1), IntervalEnd: true}}
}

func makePortEq(which string, p uint16) []expr.Any {
	load := cachedPortPayload[0]
	if which == "dport" {
		load = cachedPortPayload[1]
	}
	return []expr.Any{
		load,
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: portData(p)},
	}
}

func portEq(which string, p uint16) []expr.Any {
	if cached, ok := cachedStaticPortEq[portEqCacheKey{which: which, port: p}]; ok {
		return cached
	}
	return makePortEq(which, p)
}

func portData(port uint16) []byte { return cachedPortData[port][:] }

func icmpType(t byte) []expr.Any {
	return cachedICMPType[t]
}

func appendICMPType(dst []expr.Any, t byte) []expr.Any {
	return append(dst, cachedICMPType[t]...)
}

func hopLimit(hl byte) []expr.Any {
	return cachedHopLimit[hl]
}

// rhType matches the routing-header type field (exthdr type 43, offset 2).
func rhType(t byte) []expr.Any {
	return cachedRHType[t]
}

// ctState matches any of the given state bits (nft's `ct state { ... }`
// encoding: load, mask, neq 0).
// ctState matches when the conntrack state has any of `bits` set. The ct
// state register is host-order, so the bitwise mask is native-endian
// (big-endian here would read as bits 25/26 — the ENOBUFS-era bug).
func ctState(bits uint32) []expr.Any {
	if bits < uint32(len(cachedCtState)) {
		return cachedCtState[bits]
	}
	return newCtState(bits)
}

func newCtState(bits uint32) []expr.Any {
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
	if rtn < uint32(len(cachedFibAddrType)) {
		return cachedFibAddrType[rtn]
	}
	return []expr.Any{
		&expr.Fib{Register: 1, ResultADDRTYPE: true, FlagDADDR: true},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(rtn)},
	}
}

func counter() expr.Any { return cachedCounter }

func verdict(k expr.VerdictKind) expr.Any {
	switch k {
	case expr.VerdictAccept:
		return cachedAcceptVerdict
	case expr.VerdictDrop:
		return cachedDropVerdict
	case expr.VerdictReturn:
		return cachedReturnVerdict
	default:
		return &expr.Verdict{Kind: k}
	}
}

func jump(chain string) expr.Any {
	if cached, ok := cachedJumps[chain]; ok {
		return cached
	}
	return &expr.Verdict{Kind: expr.VerdictJump, Chain: chain}
}

func rejectExpr() expr.Any {
	return cachedReject
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
	return cachedLimit3
}

func logExpr(prefix string) expr.Any {
	if cached, ok := cachedLogExpressions[prefix]; ok {
		return cached
	}
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
		if ip := natHostIP(s); ip.IsValid() && !ip.Is4() {
			return true
		}
	}
	return false
}

// natHostIP extracts the IP from a NAT field that may be a bare IP, a CIDR,
// a v4 host:port, or a [v6]:port. Returns the invalid Addr when unparseable.
func natHostIP(s string) netip.Addr {
	if strings.IndexByte(s, '/') >= 0 {
		if p, err := netip.ParsePrefix(s); err == nil {
			return p.Addr().Unmap()
		}
	}
	if ip, err := netip.ParseAddr(s); err == nil {
		return ip.Unmap() // bare v4 or v6
	}
	// host:port — strip a bracketed v6 host or split on the last colon.
	if strings.HasPrefix(s, "[") {
		if h, _, ok := strings.Cut(s[1:], "]"); ok {
			if ip, err := netip.ParseAddr(h); err == nil {
				return ip.Unmap()
			}
			return netip.Addr{}
		}
	}
	if i := strings.LastIndex(s, ":"); i > 0 {
		if ip, err := netip.ParseAddr(s[:i]); err == nil {
			return ip.Unmap()
		}
	}
	return netip.Addr{}
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
