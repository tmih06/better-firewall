package rule

import (
	"encoding/hex"
	"math"
	"reflect"
	"strings"
	"testing"
)

func TestPortRangeString(t *testing.T) {
	cases := []struct {
		name string
		p    PortRange
		want string
	}{
		{"single port", PortRange{Lo: 80, Hi: 80, Proto: "tcp"}, "80/tcp"},
		{"minimal range", PortRange{Lo: 80, Hi: 81, Proto: "tcp"}, "80:81/tcp"},
		{"wide range", PortRange{Lo: 8080, Hi: 8090, Proto: "udp"}, "8080:8090/udp"},
		{"any proto omitted", PortRange{Lo: 53, Hi: 53, Proto: "any"}, "53"},
		{"empty proto omitted", PortRange{Lo: 22, Hi: 22}, "22"},
		{"proto only no range", PortRange{Lo: 443, Hi: 443, Proto: "udp"}, "443/udp"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.p.String(); got != c.want {
				t.Errorf("PortRange%+v.String() = %q, want %q", c.p, got, c.want)
			}
		})
	}
}

func TestPortRangeMulti(t *testing.T) {
	if (PortRange{Lo: 80, Hi: 80}).Multi() {
		t.Error("single-port range reported Multi")
	}
	if !(PortRange{Lo: 80, Hi: 81}).Multi() {
		t.Error("two-port range not reported Multi")
	}
}

func TestAddrSpecAny(t *testing.T) {
	wild := []string{"", "any"}
	for _, ip := range wild {
		if !(AddrSpec{IP: ip}).Any() {
			t.Errorf("AddrSpec{IP:%q}.Any() = false, want true", ip)
		}
	}
	// Canonical-but-not-literal wildcards and real addresses are not "any":
	// Any() is a stored-field check, not a semantic one.
	other := []string{"0.0.0.0/0", "::/0", "ANY", "192.168.1.1", "10.0.0.0/8"}
	for _, ip := range other {
		if (AddrSpec{IP: ip}).Any() {
			t.Errorf("AddrSpec{IP:%q}.Any() = true, want false", ip)
		}
	}
}

// matchBase is a fully populated rule every TupleKey/Match test mutates.
func matchBase() *Rule {
	return &Rule{
		ID:        "0123456789abcdef",
		Action:    ActionAllow,
		Direction: DirIn,
		IfaceIn:   "eth0",
		Proto:     "tcp",
		Src:       AddrSpec{IP: "10.0.0.0/8", Ports: []PortRange{{Lo: 1000, Hi: 2000, Proto: "tcp"}}},
		Dst:       AddrSpec{IP: "192.168.1.1", Ports: []PortRange{{Lo: 80, Hi: 80, Proto: "tcp"}}},
		Log:       LogNew,
		Comment:   "web",
		ExpiresAt: 1700000000,
	}
}

func TestCloneDeepCopiesPorts(t *testing.T) {
	orig := matchBase()
	c := orig.Clone()

	if c == orig {
		t.Fatal("Clone returned the same pointer")
	}
	if !reflect.DeepEqual(orig, c) {
		t.Fatalf("Clone changed contents:\norig %+v\nclon %+v", orig, c)
	}

	// Mutating the clone's port slices must not reach the original.
	c.Src.Ports[0].Lo = 1
	c.Dst.Ports[0].Hi = 65535
	if orig.Src.Ports[0].Lo != 1000 || orig.Dst.Ports[0].Hi != 80 {
		t.Errorf("mutating clone leaked into original: %+v / %+v", orig.Src.Ports, orig.Dst.Ports)
	}

	// Mutating the original must not reach the clone either.
	orig.Dst.Ports[0].Proto = "udp"
	if c.Dst.Ports[0].Proto != "tcp" {
		t.Errorf("mutating original leaked into clone: %+v", c.Dst.Ports)
	}
}

func TestCloneNilPortsAndV6(t *testing.T) {
	r := &Rule{Action: ActionDeny, Direction: DirOut, Proto: "any"}
	r.SetV6(true)
	c := r.Clone()
	if c.Src.Ports != nil || c.Dst.Ports != nil {
		t.Errorf("clone of nil ports got %+v / %+v", c.Src.Ports, c.Dst.Ports)
	}
	if !c.V6() {
		t.Error("clone lost v6 family flag")
	}
}

func TestTupleKeyDistinguishesMatchFields(t *testing.T) {
	base := matchBase()
	baseKey := base.TupleKey()

	mutations := []struct {
		name string
		mut  func(*Rule)
	}{
		{"direction", func(r *Rule) { r.Direction = DirOut }},
		{"routed", func(r *Rule) { r.Direction = DirRouted }},
		{"proto", func(r *Rule) { r.Proto = "udp" }},
		{"icmp type", func(r *Rule) { r.ICMPType = "135" }},
		{"iface in", func(r *Rule) { r.IfaceIn = "eth1" }},
		{"iface out", func(r *Rule) { r.IfaceOut = "eth0" }},
		{"src ip", func(r *Rule) { r.Src.IP = "10.0.0.0/16" }},
		{"dst ip", func(r *Rule) { r.Dst.IP = "192.168.1.2" }},
		{"src ports", func(r *Rule) { r.Src.Ports[0].Hi = 3000 }},
		{"dst ports", func(r *Rule) { r.Dst.Ports = append(r.Dst.Ports, PortRange{Lo: 443, Hi: 443, Proto: "tcp"}) }},
		{"dst set", func(r *Rule) { r.Dst.Set = "baddies" }},
		{"dapp", func(r *Rule) { r.Dapp = "OpenSSH" }},
		{"sapp", func(r *Rule) { r.Sapp = "DNS" }},
	}
	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			c := base.Clone()
			m.mut(c)
			if c.TupleKey() == baseKey {
				t.Errorf("TupleKey unchanged after %s mutation:\n%s", m.name, c.TupleKey())
			}
		})
	}
}

func TestTupleKeyCanonicalFormat(t *testing.T) {
	want := "dir=in fwd=false proto=tcp icmp_type= ifin=eth0 ifout= v6=false\n" +
		"src=10.0.0.0/8/{1000:2000/tcp}|192.168.1.1/{80/tcp} dapp= sapp=\n"
	if got := matchBase().TupleKey(); got != want {
		t.Fatalf("TupleKey = %q, want %q", got, want)
	}
}

func TestTupleKeyDistinguishesFamily(t *testing.T) {
	base := matchBase()
	v6 := base.Clone()
	v6.SetV6(true)
	if base.TupleKey() == v6.TupleKey() {
		t.Error("TupleKey identical for v4 and v6 halves of a dual rule")
	}
}

func TestTupleKeyIgnoresNonMatchFields(t *testing.T) {
	base := matchBase()
	baseKey := base.TupleKey()

	mutations := []struct {
		name string
		mut  func(*Rule)
	}{
		{"action", func(r *Rule) { r.Action = ActionDeny }},
		{"log", func(r *Rule) { r.Log = LogAll }},
		{"comment", func(r *Rule) { r.Comment = "different" }},
		{"id", func(r *Rule) { r.ID = "ffffffffffffffff" }},
		{"expires", func(r *Rule) { r.ExpiresAt = 1 }},
		{"disabled", func(r *Rule) { r.Disabled = true }},
		// RouteDir only participates via dir= for routed rules; on a
		// plain in/out rule it is inert metadata.
		{"route dir on non-routed", func(r *Rule) { r.RouteDir = DirOut }},
	}
	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			c := base.Clone()
			m.mut(c)
			if c.TupleKey() != baseKey {
				t.Errorf("TupleKey changed after %s mutation:\nbase %q\ngot  %q", m.name, baseKey, c.TupleKey())
			}
		})
	}
}

func TestTupleKeyRoutedUsesRouteDir(t *testing.T) {
	rin := matchBase()
	rin.Direction = DirRouted
	rin.RouteDir = DirIn
	rout := rin.Clone()
	rout.RouteDir = DirOut
	if rin.TupleKey() == rout.TupleKey() {
		t.Error("routed in/out rules share a TupleKey; RouteDir not honored")
	}
	// A routed rule never matches a non-routed rule even with equal dir.
	plain := rin.Clone()
	plain.Direction = DirIn
	plain.RouteDir = ""
	if rin.TupleKey() == plain.TupleKey() {
		t.Error("routed rule shares TupleKey with non-routed rule")
	}
}

func TestMatch(t *testing.T) {
	base := matchBase()

	same := base.Clone()
	if got := base.Match(same); got != MatchExact {
		t.Errorf("identical rules: got %v, want MatchExact", got)
	}

	// bfw extension fields are outside the match tuple entirely.
	ext := base.Clone()
	ext.ExpiresAt = 5
	ext.Disabled = true
	ext.ID = "ffffffffffffffff"
	if got := base.Match(ext); got != MatchExact {
		t.Errorf("expires/disabled/id differences: got %v, want MatchExact", got)
	}

	comment := base.Clone()
	comment.Comment = "other"
	if got := base.Match(comment); got != MatchComment {
		t.Errorf("comment-only difference: got %v, want MatchComment", got)
	}

	action := base.Clone()
	action.Action = ActionDeny
	if got := base.Match(action); got != MatchAction {
		t.Errorf("action difference: got %v, want MatchAction", got)
	}

	log := base.Clone()
	log.Log = LogAll
	if got := base.Match(log); got != MatchAction {
		t.Errorf("log-type difference: got %v, want MatchAction", got)
	}

	// Action divergence wins over comment divergence.
	both := base.Clone()
	both.Action = ActionDeny
	both.Comment = "other"
	if got := base.Match(both); got != MatchAction {
		t.Errorf("action+comment difference: got %v, want MatchAction", got)
	}

	tuple := base.Clone()
	tuple.Proto = "udp"
	if got := base.Match(tuple); got != MatchNone {
		t.Errorf("tuple difference: got %v, want MatchNone", got)
	}
}

func TestMatchNormalizesPortProtocolAliases(t *testing.T) {
	base := matchBase()
	base.Src.Ports = []PortRange{{Lo: 22, Hi: 22, Proto: ""}}
	other := base.Clone()
	other.Src.Ports[0].Proto = "any"
	if got := base.Match(other); got != MatchExact {
		t.Fatalf("empty and any port protocols: got %v, want MatchExact", got)
	}
}

func TestAppTupleEmptyWithoutApps(t *testing.T) {
	r := matchBase()
	if got := r.AppTuple(); got != "" {
		t.Errorf("rule without apps: AppTuple() = %q, want \"\"", got)
	}
}

func TestAppTupleFamilyCanonicalWildcard(t *testing.T) {
	mk := func(v6 bool) *Rule {
		r := &Rule{
			Action:    ActionAllow,
			Direction: DirIn,
			Dapp:      "OpenSSH",
			Src:       AddrSpec{IP: "any"},
			Dst:       AddrSpec{IP: "any"},
		}
		r.SetV6(v6)
		return r
	}
	v4, v6 := mk(false), mk(true)
	if v4.AppTuple() == v6.AppTuple() {
		t.Errorf("v4 and v6 halves share AppTuple %q", v4.AppTuple())
	}
	if !strings.Contains(v4.AppTuple(), "0.0.0.0/0") {
		t.Errorf("v4 tuple missing 0.0.0.0/0: %q", v4.AppTuple())
	}
	if !strings.Contains(v6.AppTuple(), "::/0") {
		t.Errorf("v6 tuple missing ::/0: %q", v6.AppTuple())
	}
}

func TestAppTuplePortFallbackAndAppPrecedence(t *testing.T) {
	// Only a source app: destination side falls back to its port list.
	r := &Rule{
		Direction: DirIn,
		Sapp:      "DNS",
		Src:       AddrSpec{IP: "10.0.0.1"},
		Dst: AddrSpec{IP: "any", Ports: []PortRange{
			{Lo: 53, Hi: 53, Proto: "tcp"},
			{Lo: 5353, Hi: 5353, Proto: "udp"},
		}},
	}
	got := r.AppTuple()
	want := "53/tcp,5353/udp 0.0.0.0/0 DNS 10.0.0.1 in"
	if got != want {
		t.Errorf("port fallback tuple = %q, want %q", got, want)
	}

	// A bare side with neither app nor ports renders "any".
	r2 := &Rule{Direction: DirOut, Dapp: "OpenSSH"}
	got = r2.AppTuple()
	want = "OpenSSH 0.0.0.0/0 any 0.0.0.0/0 out"
	if got != want {
		t.Errorf("portless app-less tuple = %q, want %q", got, want)
	}

	// App name wins over ports on the same side.
	r3 := &Rule{
		Direction: DirIn,
		Dapp:      "Nginx",
		Dst:       AddrSpec{IP: "any", Ports: []PortRange{{Lo: 80, Hi: 80, Proto: "tcp"}}},
	}
	got = r3.AppTuple()
	want = "Nginx 0.0.0.0/0 any 0.0.0.0/0 in"
	if got != want {
		t.Errorf("app precedence tuple = %q, want %q", got, want)
	}
}

func TestAppTupleInterfaceSuppressesDirection(t *testing.T) {
	r := &Rule{
		Direction: DirIn,
		IfaceIn:   "eth0",
		IfaceOut:  "eth1",
		Dapp:      "OpenSSH",
	}
	got := r.AppTuple()
	want := "OpenSSH 0.0.0.0/0 any 0.0.0.0/0 in_eth0 out_eth1"
	if got != want {
		t.Errorf("interface tuple = %q, want %q", got, want)
	}
}

func TestNormalizeAddrs(t *testing.T) {
	r := &Rule{
		Src: AddrSpec{IP: ""},
		Dst: AddrSpec{IP: "192.168.1.7/32"},
	}
	if !r.Normalize() {
		t.Fatal("first Normalize() = false, want true")
	}
	if r.Src.IP != "any" {
		t.Errorf("empty src IP normalized to %q, want any", r.Src.IP)
	}
	if r.Dst.IP != "192.168.1.7" {
		t.Errorf("host /32 normalized to %q, want bare 192.168.1.7", r.Dst.IP)
	}
	if r.Normalize() {
		t.Error("second Normalize() = true, want false (not idempotent)")
	}
}

func TestNormalizeHostMaskAndIPv6(t *testing.T) {
	r := &Rule{
		Src: AddrSpec{IP: "2001:0DB8::1"},
		Dst: AddrSpec{IP: "10.1.2.3/24"},
	}
	if !r.Normalize() {
		t.Fatal("Normalize() = false, want true")
	}
	if r.Src.IP != "2001:db8::1" {
		t.Errorf("bare IPv6 normalized to %q, want inet_ntop form 2001:db8::1", r.Src.IP)
	}
	if r.Dst.IP != "10.1.2.0/24" {
		t.Errorf("host-with-mask normalized to %q, want network 10.1.2.0/24", r.Dst.IP)
	}
}

func TestNormalizeSortsPortsStably(t *testing.T) {
	r := &Rule{
		Src: AddrSpec{IP: "any"},
		Dst: AddrSpec{IP: "any", Ports: []PortRange{
			{Lo: 443, Hi: 443, Proto: "tcp"},
			{Lo: 80, Hi: 8080, Proto: "tcp"}, // equal Lo+Proto to next; stable order must hold
			{Lo: 80, Hi: 80, Proto: "tcp"},
			{Lo: 80, Hi: 80, Proto: "any"}, // proto tiebreak: "any" < "tcp"
		}},
	}
	// Addresses are already canonical; only the ports need sorting.
	// Normalize's contract is "true if anything changed", so a port
	// reorder must report changed.
	if !r.Normalize() {
		t.Error("Normalize() = false on unsorted ports, want true")
	}
	got := r.Dst.Ports
	want := []PortRange{
		{Lo: 80, Hi: 80, Proto: "any"},
		{Lo: 80, Hi: 8080, Proto: "tcp"},
		{Lo: 80, Hi: 80, Proto: "tcp"},
		{Lo: 443, Hi: 443, Proto: "tcp"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ports = %+v, want stable-sorted %+v", got, want)
	}
	// With ports now sorted, a second pass must report no change.
	if r.Normalize() {
		t.Error("second Normalize() = true on sorted ports, want false")
	}
}

func TestNormalizeUntouchedInputs(t *testing.T) {
	r := &Rule{
		Src: AddrSpec{IP: "not-an-ip"},
		Dst: AddrSpec{IP: "10.0.0.0/8", Set: "allowed"},
	}
	if r.Normalize() {
		t.Error("Normalize() = true, want false for invalid/set endpoints")
	}
	if r.Src.IP != "not-an-ip" {
		t.Errorf("invalid IP rewritten to %q; should be left for validator", r.Src.IP)
	}
	if r.Dst.IP != "10.0.0.0/8" {
		t.Errorf("set-referencing endpoint rewritten to %q", r.Dst.IP)
	}
}

func TestForwardAndV6(t *testing.T) {
	r := &Rule{Direction: DirIn}
	if r.Forward() {
		t.Error("in rule reported Forward")
	}
	if r.V6() {
		t.Error("zero-value rule reported V6")
	}
	r.Direction = DirRouted
	if !r.Forward() {
		t.Error("routed rule not reported Forward")
	}
	r.SetV6(true)
	if !r.V6() {
		t.Error("SetV6(true) not reflected by V6()")
	}
	r.SetV6(false)
	if r.V6() {
		t.Error("SetV6(false) not reflected by V6()")
	}
}

func TestExpired(t *testing.T) {
	r := &Rule{}
	for _, now := range []int64{0, 1, math.MaxInt64} {
		if r.Expired(now) {
			t.Errorf("ExpiresAt=0 (never) reported expired at now=%d", now)
		}
	}

	r.ExpiresAt = 100
	if r.Expired(99) {
		t.Error("expired before ExpiresAt")
	}
	if !r.Expired(100) {
		t.Error("not expired at ExpiresAt boundary (boundary is inclusive)")
	}
	if !r.Expired(101) {
		t.Error("not expired after ExpiresAt")
	}
}

func TestNewIDFormat(t *testing.T) {
	id := NewID()
	if len(id) != 16 {
		t.Fatalf("NewID length = %d, want 16", len(id))
	}
	if _, err := hex.DecodeString(id); err != nil {
		t.Errorf("NewID %q is not lowercase hex: %v", id, err)
	}
}
func TestICMPTypeNumber(t *testing.T) {
	cases := []struct {
		proto, token, want string
	}{
		{"icmp", "echo-request", "8"},
		{"icmp", "008", "8"},
		{"icmpv6", "neighbour-solicitation", "135"},
		{"icmpv6", "neighbor-advertisement", "136"},
		{"icmpv6", "mld2-listener-report", "143"},
	}
	for _, c := range cases {
		got, err := ICMPTypeNumber(c.proto, c.token)
		if err != nil || got != c.want {
			t.Errorf("ICMPTypeNumber(%q, %q) = %q, %v; want %q", c.proto, c.token, got, err, c.want)
		}
	}
	for _, c := range []struct{ proto, token string }{
		{"tcp", "80"}, {"icmp", "256"}, {"icmpv6", "unknown"},
	} {
		if _, err := ICMPTypeNumber(c.proto, c.token); err == nil {
			t.Errorf("ICMPTypeNumber(%q, %q) unexpectedly succeeded", c.proto, c.token)
		}
	}
}
