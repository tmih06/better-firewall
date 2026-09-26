// Package rule defines the canonical firewall rule model shared by the
// parser, store, status renderer, and nftables compiler.
//
// The model mirrors ufw's two-list design: Rules4 and Rules6 are separate
// ordered lists; a dual-family rule is one entry in each list sharing the
// same ID. Display order is all Rules4 lines then all Rules6 lines, and
// `status numbered` N is the index into Rules4++Rules6.
package rule

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// Action values.
const (
	ActionAllow  = "allow"
	ActionDeny   = "deny"
	ActionReject = "reject"
	ActionLimit  = "limit"
)

// Direction values.
const (
	DirIn     = "in"
	DirOut    = "out"
	DirRouted = "routed"
)

// LogType values.
const (
	LogNone = ""
	LogNew  = "log"
	LogAll  = "log-all"
)

// PortRange is an inclusive port range bound to a protocol ("tcp", "udp",
// or "any" meaning both).
type PortRange struct {
	Lo    uint16 `json:"lo"`
	Hi    uint16 `json:"hi"`
	Proto string `json:"proto"` // tcp|udp|any
}

func (p PortRange) String() string {
	s := strconv.Itoa(int(p.Lo))
	if p.Hi != p.Lo {
		s += ":" + strconv.Itoa(int(p.Hi))
	}
	if p.Proto != "" && p.Proto != "any" {
		s += "/" + p.Proto
	}
	return s
}

// Multi reports whether the range spans more than one port.
func (p PortRange) Multi() bool { return p.Hi != p.Lo }

// AddrSpec is one endpoint of a rule: an address plus optional ports.
// IP is canonical: "any" (wildcard), an IP, or CIDR. App names ride on the
// rule (Dapp/Sapp), not here.
type AddrSpec struct {
	IP    string      `json:"ip"` // "any" | ip | cidr
	Ports []PortRange `json:"ports,omitempty"`
	Set   string      `json:"set,omitempty"` // bfw extension: named set reference
}

// Any reports whether the endpoint is the wildcard address.
func (a AddrSpec) Any() bool { return a.IP == "" || a.IP == "any" }

// Rule is one firewall rule in one address family list.
type Rule struct {
	ID        string   `json:"id"` // shared by v4/v6 halves of a dual rule
	Action    string   `json:"action"`
	Direction string   `json:"direction"`           // in|out|routed
	RouteDir  string   `json:"route_dir,omitempty"` // in|out for routed rules (ufw keeps direction alongside forward)
	IfaceIn   string   `json:"iface_in,omitempty"`
	IfaceOut  string   `json:"iface_out,omitempty"`
	Proto     string   `json:"proto"`               // tcp|udp|ah|esp|gre|vrrp|ipv6|igmp|icmp|icmpv6|any
	ICMPType  string   `json:"icmp_type,omitempty"` // decimal ICMP type; empty means any type
	Src       AddrSpec `json:"src"`
	Dst       AddrSpec `json:"dst"`
	Dapp      string   `json:"dapp,omitempty"`
	Sapp      string   `json:"sapp,omitempty"`
	Log       string   `json:"log,omitempty"`
	Comment   string   `json:"comment,omitempty"`
	ExpiresAt int64    `json:"expires_at,omitempty"` // unix ts; 0 = never
	Disabled  bool     `json:"disabled,omitempty"`

	v6 bool // transient: set by store/frontend, not serialized
}

// NewID returns a random short rule ID.
func NewID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// V6 reports whether this rule instance lives in the v6 list. Set by the
// store when loading; not serialized (list membership encodes family).
func (r *Rule) V6() bool { return r.v6 }

// SetV6 marks family membership (called by store/frontend, not persisted).
func (r *Rule) SetV6(v6 bool) { r.v6 = v6 }

// Forward reports whether the rule applies to routed traffic.
func (r *Rule) Forward() bool { return r.Direction == DirRouted }

// Clone returns a deep copy.
func (r *Rule) Clone() *Rule {
	c := *r
	c.Src.Ports = append([]PortRange(nil), r.Src.Ports...)
	c.Dst.Ports = append([]PortRange(nil), r.Dst.Ports...)
	return &c
}

// TupleKey returns the identity used by ufw's match(): all match fields
// except action, logtype, and comment (and bfw extensions expires/disabled).
func (r *Rule) TupleKey() string {
	var b strings.Builder
	// ufw's match() compares direction (in/out) not the forward flag; for
	// routed rules RouteDir carries that direction so in/out swaps match.
	dir := r.Direction
	if r.Forward() && r.RouteDir != "" {
		dir = r.RouteDir
	}
	fmt.Fprintf(&b, "dir=%s fwd=%v proto=%s icmp_type=%s ifin=%s ifout=%s v6=%v\n",
		dir, r.Forward(), r.Proto, r.ICMPType, r.IfaceIn, r.IfaceOut, r.v6)
	fmt.Fprintf(&b, "src=%s|%s dapp=%s sapp=%s\n", addrKey(r.Src), addrKey(r.Dst), r.Dapp, r.Sapp)
	return b.String()
}

func addrKey(a AddrSpec) string {
	var ps []string
	for _, p := range a.Ports {
		ps = append(ps, p.String())
	}
	return a.IP + "/" + a.Set + "{" + strings.Join(ps, ",") + "}"
}

// MatchCode mirrors ufw UFWRule.match return codes.
type MatchCode int

const (
	MatchNone    MatchCode = 1  // different tuple
	MatchExact   MatchCode = 0  // identical incl. action/log/comment
	MatchComment MatchCode = -2 // same tuple, different comment
	MatchAction  MatchCode = -1 // same tuple, different action/logtype
)

// Match compares two rules per ufw semantics.
func (r *Rule) Match(o *Rule) MatchCode {
	if !sameTuple(r, o) {
		return MatchNone
	}
	if r.Action == o.Action && r.Log == o.Log && r.Comment == o.Comment {
		return MatchExact
	}
	if r.Action == o.Action && r.Log == o.Log {
		return MatchComment
	}
	return MatchAction
}

// sameTuple compares the fields represented by TupleKey without constructing
// either formatted key. Keep the normalization rules in sync with addrKey and
// TupleKey: an empty or explicit "any" port protocol has no serialized suffix
// and therefore compares equal.
func sameTuple(r, o *Rule) bool {
	routeDir := r.Direction
	if r.Forward() && r.RouteDir != "" {
		routeDir = r.RouteDir
	}
	oRouteDir := o.Direction
	if o.Forward() && o.RouteDir != "" {
		oRouteDir = o.RouteDir
	}
	if routeDir != oRouteDir || r.Forward() != o.Forward() ||
		r.Proto != o.Proto || r.ICMPType != o.ICMPType ||
		r.IfaceIn != o.IfaceIn || r.IfaceOut != o.IfaceOut || r.v6 != o.v6 ||
		r.Dapp != o.Dapp || r.Sapp != o.Sapp {
		return false
	}
	return sameAddrTuple(r.Src, o.Src) && sameAddrTuple(r.Dst, o.Dst)
}

func sameAddrTuple(a, b AddrSpec) bool {
	if a.IP != b.IP || a.Set != b.Set || len(a.Ports) != len(b.Ports) {
		return false
	}
	for i := range a.Ports {
		left, right := a.Ports[i], b.Ports[i]
		if left.Lo != right.Lo || left.Hi != right.Hi ||
			normalizedPortProto(left.Proto) != normalizedPortProto(right.Proto) {
			return false
		}
	}
	return true
}

func normalizedPortProto(proto string) string {
	if proto == "" || proto == "any" {
		return ""
	}
	return proto
}

// AppTuple groups rules expanded from one app-profile application; ufw
// keeps these groups unsplittable on insert. Mirrors ufw get_app_tuple:
// the app name is substituted by the port when that side has no app, and
// addresses are family-canonical ("0.0.0.0/0" vs "::/0") so a dual rule's
// v4 and v6 halves never share a tuple.
func (r *Rule) AppTuple() string {
	if r.Dapp == "" && r.Sapp == "" {
		return ""
	}
	dst := canonWild(r.Dst.IP, r.v6)
	src := canonWild(r.Src.IP, r.v6)
	dside := r.Dapp
	if dside == "" {
		dside = portListStr(r.Dst.Ports)
	}
	sside := r.Sapp
	if sside == "" {
		sside = portListStr(r.Src.Ports)
	}
	tupl := fmt.Sprintf("%s %s %s %s", dside, dst, sside, src)
	if r.IfaceIn == "" && r.IfaceOut == "" {
		tupl += " " + r.Direction
	} else {
		if r.IfaceIn != "" {
			tupl += " in_" + r.IfaceIn
		}
		if r.IfaceOut != "" {
			tupl += " out_" + r.IfaceOut
		}
	}
	return tupl
}

// canonWild maps a stored endpoint to the family-canonical wildcard so
// tuples differ across families even when both store "any".
func canonWild(ip string, v6 bool) string {
	if ip == "any" || ip == "" {
		if v6 {
			return "::/0"
		}
		return "0.0.0.0/0"
	}
	return ip
}

// portListStr renders a port list the way ufw's dport/sport strings look
// ("any", "80", "80,443", "8080:8090").
func portListStr(ports []PortRange) string {
	if len(ports) == 0 {
		return "any"
	}
	var ps []string
	for _, p := range ports {
		ps = append(ps, p.String())
	}
	return strings.Join(ps, ",")
}

// Normalize canonicalizes addresses and port lists in place, returning true
// if anything changed (caller warns "Rule changed after normalization").
func (r *Rule) Normalize() bool {
	changed := false
	if n := normalizeAddr(&r.Src); n {
		changed = true
	}
	if n := normalizeAddr(&r.Dst); n {
		changed = true
	}
	for _, ports := range [][]PortRange{r.Src.Ports, r.Dst.Ports} {
		// Record whether the in-place sort changes list order as part of the
		// Normalize contract; address-only changes are not the only mutation.
		for i := 1; i < len(ports); i++ {
			prev, current := ports[i-1], ports[i]
			if current.Lo < prev.Lo || (current.Lo == prev.Lo && current.Proto < prev.Proto) {
				changed = true
				break
			}
		}
		sort.SliceStable(ports, func(i, j int) bool {
			if ports[i].Lo != ports[j].Lo {
				return ports[i].Lo < ports[j].Lo
			}
			return ports[i].Proto < ports[j].Proto
		})
	}
	return changed
}

// normalizeAddr canonicalizes one endpoint: "any"→"any", strips host masks,
// dotted netmask→CIDR, host-with-mask→network, inet_ntop round-trip.
func normalizeAddr(a *AddrSpec) bool {
	if a.IP == "" {
		a.IP = "any"
		return true
	}
	if a.IP == "any" || a.Set != "" {
		return false
	}
	orig := a.IP
	ip, ipnet, err := net.ParseCIDR(a.IP)
	if err != nil {
		// Bare IP: canonicalize via inet_ntop round-trip (ufw
		// normalize_address always does this — collapses 2001:0DB8::1
		// to 2001:db8::1 so delete matches).
		if p := net.ParseIP(a.IP); p != nil {
			a.IP = p.String()
			return a.IP != orig
		}
		return false // leave for validator
	}
	ones, bits := ipnet.Mask.Size()
	if bits == 32 && ones == 32 {
		a.IP = ip.String()
	} else if bits == 128 && ones == 128 {
		a.IP = ip.String()
	} else {
		a.IP = ipnet.String() // host-with-mask → network
	}
	return a.IP != orig
}

// Expired reports whether the rule has passed its expiry time.
func (r *Rule) Expired(now int64) bool {
	return r.ExpiresAt != 0 && now >= r.ExpiresAt
}
