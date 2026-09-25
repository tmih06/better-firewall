// nftjson.go implements the native nftables importer: it parses the JSON
// document produced by `nft -j list ruleset` and merges filter base-chain
// rules and policies into the canonical state.
//
// Supported input, deliberately narrow so nothing is broadened or dropped:
//   - tables in the ip, ip6, and inet families;
//   - type "filter" base chains on the input/output/forward hooks only,
//     at most one per family+hook. Coverage per direction: a direction
//     with no base chain is nft's implicit accept and imports as policy
//     "allow" with no rules; a fully covered direction is exactly one
//     inet chain or one ip plus one ip6 chain; partial coverage is
//     faithful only when the imported side's policy is accept (unifying
//     with the absent family's implicit accept) and otherwise rejected.
//     Overlapping chains (inet alongside ip/ip6 on one hook) are rejected
//     — flattening would interleave chain evaluation order;
//   - chain policies accept/drop mapped to allow/deny; an omitted policy
//     is nft's implicit accept and imports as "allow". Families serving
//     one hook must agree — conflicting policies are fatal (per-family
//     baselines cannot be encoded in one global direction policy);
//   - rules whose expressions are simple equality matches on l4 protocol
//     (meta l4proto / ip protocol / ip6 nexthdr), interface names
//     (iifname/oifname), IPv4/IPv6 saddr/daddr (host or CIDR), tcp/udp
//     sport/dport (one constraint per field — nft conjuncts repeated
//     matches but the model's port list is a union), a single icmp or
//     icmpv6 type equality (numeric or symbolic, stored as the canonical
//     decimal — the match pins the protocol and with it the family:
//     icmp is IPv4-only, icmpv6 IPv6-only; repeated identical types
//     coalesce while differing ones are contradictory and rejected),
//     an optional log
//     statement (mapped to LogAll; presentational options like prefix are
//     dropped with a warning, group/queue-threshold are fatal since they
//     retarget to NFLOG), an optional comment, and a terminal
//     accept/drop/reject verdict (non-default reject type/expr is dropped
//     with a warning — the compiler always emits icmpx port-unreachable).
//
// Everything else is rejected with an error naming the construct rather
// than silently dropped: other families (arp, bridge, netdev, …) whose
// enforcement would otherwise be lost, nat/other chain types or hooks,
// regular chains, set/map/flowtable objects, quota objects and
// expressions (quotas gate verdicts), jump/goto/return/set-lookup
// expressions, negations, icmp fields other than type (code, …),
// ct/rt/th/fib/socket exprs, and verdict-less
// rules. metainfo is decorative; counters are accounting-only — skipped
// counters are reported in a single warning.
//
// inet-family rules are dual: a rule with no family restriction is
// appended to both lists sharing one ID (mirroring the ufw importer);
// rules guarded by `meta nfproto` or family-typed payload matches land in
// the matching list only.
package impexp

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/tmih06/better-firewall/internal/rule"
	"github.com/tmih06/better-firewall/internal/store"
)

// ---- nft JSON document shapes ----------------------------------------------

type nftRuleset struct {
	NFT []map[string]json.RawMessage `json:"nftables"`
}

type nftChain struct {
	Family string `json:"family"`
	Table  string `json:"table"`
	Name   string `json:"name"`
	Handle int    `json:"handle"`
	Type   string `json:"type"`
	Hook   string `json:"hook"`
	Prio   int    `json:"prio"`
	Policy string `json:"policy"`
}

type nftRule struct {
	Family  string            `json:"family"`
	Table   string            `json:"table"`
	Chain   string            `json:"chain"`
	Handle  int               `json:"handle"`
	Comment string            `json:"comment"`
	Expr    []json.RawMessage `json:"expr"`
}

// nftMatch is a {"match": {...}} expression.
type nftMatch struct {
	Op    string          `json:"op"`
	Left  json.RawMessage `json:"left"`
	Right json.RawMessage `json:"right"`
}

// nftPrefix is the {"prefix": {"addr": ..., "len": ...}} RHS form.
type nftPrefix struct {
	Addr string `json:"addr"`
	Len  int    `json:"len"`
}

// nftSet is the {"set": [...]} or {"set": "@name"} RHS form; present only
// so matches can detect and reject set operands explicitly.
type nftSet struct {
	Set json.RawMessage `json:"set"`
}

// nftRange is the {"range": [lo, hi]} RHS form.
type nftRange struct {
	Range [2]json.RawMessage `json:"range"`
}

// nftKeyVal is the single-key payload/meta/ct LHS form: either a bare
// string ("l4proto") or {"key": "l4proto", ...} in newer nft versions.
type nftKeyVal struct {
	Key      string `json:"key"`
	Field    string `json:"field"`
	Protocol string `json:"protocol"`
}

// nftProto maps nft protocol names and numbers onto model Proto values.
var nftProto = map[string]string{
	"tcp": "tcp", "udp": "udp", "icmp": "icmp", "icmpv6": "icmpv6",
	"ipv6-icmp": "icmpv6", "ah": "ah", "esp": "esp", "gre": "gre",
	"vrrp": "vrrp", "igmp": "igmp", "ipv6": "ipv6",
}

var nftProtoNum = map[int]string{
	1: "icmp", 2: "igmp", 6: "tcp", 17: "udp", 41: "ipv6",
	47: "gre", 50: "esp", 51: "ah", 58: "icmpv6", 112: "vrrp",
}

// nftHookDir maps nft base-chain hooks onto model directions.
var nftHookDir = map[string]string{
	"input":   rule.DirIn,
	"output":  rule.DirOut,
	"forward": rule.DirRouted,
}

var nftFamilies = map[string]bool{"ip": true, "ip6": true, "inet": true}

// ImportNFTables merges an `nft -j list ruleset` document read from r into
// st. The import is fail-closed: the first pass validates every object
// (families, chain kinds, duplicate hooks, policy conflicts, named
// objects) before any state is touched, so errors leave st untouched.
// Returns the merged state, the number of rules added/updated, warnings
// for skipped non-semantic objects, and any fatal error.
func ImportNFTables(r io.Reader, st *store.State) (*store.State, int, []string, error) {
	if st == nil {
		return nil, 0, nil, fmt.Errorf("nftables import requires a non-nil state to merge into")
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("reading nftables JSON: %w", err)
	}
	var doc nftRuleset
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, 0, nil, fmt.Errorf("parsing nftables JSON: %w", err)
	}
	if doc.NFT == nil {
		return nil, 0, nil, fmt.Errorf("parsing nftables JSON: missing \"nftables\" array")
	}

	// First pass: validate and catalog. Every ruleset object except
	// metainfo carries a family field; decode it generically up front.
	chains := map[string]*nftChain{}    // family/table/name → chain
	hookChain := map[string]*nftChain{} // family/hook → first base chain
	hookFams := map[string][]string{}   // hook → families with base chains
	hookPolicy := map[string]string{}   // hook → mapped allow|deny
	hookPolicier := map[string]string{} // hook → chain that set the policy
	counters := 0                       // skipped counters (objects + exprs)
	logOpts, rejOpts := 0, 0            // dropped log/reject options
	for i, obj := range doc.NFT {
		if len(obj) != 1 {
			return nil, 0, nil, fmt.Errorf("nftables object %d: expected one key, got %d", i, len(obj))
		}
		for kind, raw := range obj {
			var head struct {
				Family string `json:"family"`
			}
			_ = json.Unmarshal(raw, &head)
			if head.Family != "" && !nftFamilies[head.Family] {
				return nil, 0, nil, fmt.Errorf("nftables object %d: unsupported family %q (only ip, ip6, inet are imported); refusing to silently drop its enforcement", i, head.Family)
			}
			switch kind {
			case "metainfo":
				// Decorative version/release info: ignored.
			case "table":
				// Existence only; nothing to enforce by itself.
			case "chain":
				var c nftChain
				if err := json.Unmarshal(raw, &c); err != nil {
					return nil, 0, nil, fmt.Errorf("chain object %d: %w", i, err)
				}
				if c.Type == "" {
					return nil, 0, nil, fmt.Errorf("chain %s: regular (non-base) chains are not supported; inline its rules or remove it", nftChainID(&c))
				}
				if c.Type != "filter" || nftHookDir[c.Hook] == "" {
					return nil, 0, nil, fmt.Errorf("chain %s: unsupported type/hook %s/%s (only filter input|output|forward)", nftChainID(&c), c.Type, c.Hook)
				}
				if first := hookChain[c.Family+"/"+c.Hook]; first != nil {
					return nil, 0, nil, fmt.Errorf("chain %s: multiple base chains for %s %s (already have %s); flattening would lose chain priority/order", nftChainID(&c), c.Family, c.Hook, nftChainID(first))
				}
				hookChain[c.Family+"/"+c.Hook] = &c
				chains[c.Family+"/"+c.Table+"/"+c.Name] = &c
				hookFams[c.Hook] = append(hookFams[c.Hook], c.Family)
				p := nftPolicyMap(c.Policy)
				if p == "" {
					return nil, 0, nil, fmt.Errorf("chain %s: unsupported policy %q", nftChainID(&c), c.Policy)
				}
				if prev, ok := hookPolicy[c.Hook]; ok {
					if prev != p {
						return nil, 0, nil, fmt.Errorf("chain %s: policy %q conflicts with %q from %s on the %s hook; the model stores one policy per hook", nftChainID(&c), p, prev, hookPolicier[c.Hook], c.Hook)
					}
				} else {
					hookPolicy[c.Hook] = p
					hookPolicier[c.Hook] = nftChainID(&c)
				}
			case "set", "map", "flowtable":
				return nil, 0, nil, fmt.Errorf("%s object %d: named sets/maps/flowtables are not supported", kind, i)
			case "quota":
				return nil, 0, nil, fmt.Errorf("quota object %d: quotas gate verdicts and are not representable", i)
			case "counter":
				counters++ // accounting only; reported once below
			case "rule":
				// Bound to its chain and converted in the second pass.
			default:
				return nil, 0, nil, fmt.Errorf("nftables object %d: unsupported object type %q", i, kind)
			}
		}
	}

	// Per-hook coverage: the model has one global policy per direction and
	// one ordered rule list per family, so each direction needs either a
	// single inet chain (covers both families) or one ip plus one ip6
	// chain. A direction with no base chain is nft's implicit accept —
	// exactly representable as policy "allow" with no rules. Partial
	// coverage is faithful only when the imported side's policy is accept
	// (accept + implicit accept unify); otherwise the missing family's
	// implicit-accept could not coexist with the imported family's real
	// policy in one global direction policy. Overlapping inet+ip/ip6
	// chains interleave evaluation order the model cannot keep.
	for _, hook := range []string{"input", "output", "forward"} {
		fams := hookFams[hook]
		has := map[string]bool{}
		for _, f := range fams {
			has[f] = true
		}
		switch {
		case len(fams) == 0:
			hookPolicy[hook] = "allow"
		case has["inet"] && len(fams) > 1:
			return nil, 0, nil, fmt.Errorf("overlapping base chains on the %s hook (%s): nft evaluates all of them, but the model flattens to one chain per direction; keep exactly one of inet or ip+ip6", hook, strings.Join(fams, " + "))
		case !has["inet"] && !has["ip"], !has["inet"] && !has["ip6"]:
			if hookPolicy[hook] == "allow" {
				break // accept policy + absent family's implicit accept unify
			}
			missing := "IPv6 (ip6 or inet)"
			if !has["ip"] && !has["inet"] {
				missing = "IPv4 (ip or inet)"
			}
			return nil, 0, nil, fmt.Errorf("incomplete coverage on the %s hook: chains for %s only — the %s family is left on nft's implicit accept, which a single per-direction policy cannot express alongside a drop policy; set the chain policy to accept or add the missing family's chain", hook, strings.Join(fams, "+"), missing)
		}
	}

	// Second pass: apply the resolved per-hook policies, then convert and
	// merge rules.
	out := nftCloneState(st)
	// IPv6 is covered for every direction — explicitly or via nft's
	// implicit accept — so the merged state must enable it regardless of
	// the caller's prior flag (otherwise imported Rules6 stay inactive).
	out.IPv6 = true
	for hook, p := range hookPolicy {
		switch nftHookDir[hook] {
		case rule.DirIn:
			out.Policies.Input = p
		case rule.DirOut:
			out.Policies.Output = p
		case rule.DirRouted:
			out.Policies.Forward = p
		}
	}
	added := 0
	for i, obj := range doc.NFT {
		for kind, raw := range obj {
			if kind != "rule" {
				continue
			}
			var nr nftRule
			if err := json.Unmarshal(raw, &nr); err != nil {
				return nil, 0, nil, fmt.Errorf("rule object %d: %w", i, err)
			}
			c := chains[nr.Family+"/"+nr.Table+"/"+nr.Chain]
			if c == nil {
				return nil, 0, nil, fmt.Errorf("rule in %s/%s/%s: chain is not an imported filter base chain", nr.Family, nr.Table, nr.Chain)
			}
			rules, err := nftConvertRule(&nr, c)
			if err != nil {
				return nil, 0, nil, fmt.Errorf("rule in %s: %w", nftChainID(c), err)
			}
			counters += rules.counters
			logOpts += rules.logOpts
			rejOpts += rules.rejOpts
			added += mergeRules(&out.Rules4, rules.v4)
			added += mergeRules(&out.Rules6, rules.v6)
		}
	}
	var warnings []string
	if counters > 0 {
		warnings = append(warnings, fmt.Sprintf("skipped %d counter(s) (accounting only)", counters))
	}
	if logOpts > 0 {
		warnings = append(warnings, fmt.Sprintf("%d rule(s) had log options not preserved (prefix/level/flags map to kernel-log defaults)", logOpts))
	}
	if rejOpts > 0 {
		warnings = append(warnings, fmt.Sprintf("%d rule(s) had non-default reject type/expr not preserved (mapped to icmpx port-unreachable)", rejOpts))
	}
	return out, added, warnings, nil
}

func nftChainID(c *nftChain) string {
	return fmt.Sprintf("%s %s %s", c.Family, c.Table, c.Name)
}

// nftPolicyMap maps an nft base-chain policy onto a model policy. An empty
// policy field is nft's implicit accept, imported as "allow" rather than
// inheriting whatever the input state happened to hold. Anything else is
// unrepresentable ("" → the caller errors).
func nftPolicyMap(policy string) string {
	switch policy {
	case "", "accept":
		return "allow"
	case "drop":
		return "deny"
	}
	return ""
}

// nftPair is one converted rule's per-family instances; an inet rule with
// no family restriction populates both with a shared ID. The counters
// tally skipped/dropped options for the caller's warnings.
type nftPair struct {
	v4       []rule.Rule
	v6       []rule.Rule
	counters int // skipped counter exprs
	logOpts  int // log statements whose options were not preserved
	rejOpts  int // reject verdicts with non-default type/expr
}

// nftConv accumulates the match state of one nft rule being converted.
type nftConv struct {
	r        rule.Rule
	famBits  int // 1 = restricted to v4, 2 = restricted to v6, 0 = either
	l4Set    bool
	verdict  bool
	comment  string
	counters int
	logOpts  int
	rejOpts  int
}

func (c *nftConv) restrict(bit int, what string) error {
	if c.famBits != 0 && c.famBits != bit {
		return fmt.Errorf("%s: conflicting address families", what)
	}
	c.famBits = bit
	return nil
}

func (c *nftConv) setProto(p, what string) error {
	if c.r.Proto != "" && c.r.Proto != "any" && c.r.Proto != p {
		return fmt.Errorf("%s: conflicting protocols %q and %q", what, c.r.Proto, p)
	}
	if c.l4Set && (p != "tcp" && p != "udp") {
		return fmt.Errorf("%s: port match requires tcp or udp, got %q", what, p)
	}
	// icmp/icmpv6 exist in exactly one family; narrowing here keeps an
	// inet rule from emitting a dead half in the other family's list.
	switch p {
	case "icmp":
		if err := c.restrict(1, what); err != nil {
			return err
		}
	case "icmpv6":
		if err := c.restrict(2, what); err != nil {
			return err
		}
	}
	c.r.Proto = p
	return nil
}

// nftConvertRule converts one nft rule object into model rules split by
// family. dir comes from the chain hook.
func nftConvertRule(nr *nftRule, c *nftChain) (*nftPair, error) {
	cv := &nftConv{}
	cv.r.Direction = nftHookDir[c.Hook]
	cv.r.Src.IP, cv.r.Dst.IP = "any", "any"
	cv.comment = nr.Comment
	// Chain family seeds the restriction; nfproto guards and family-typed
	// payloads can only narrow an inet rule further.
	switch c.Family {
	case "ip":
		cv.famBits = 1
	case "ip6":
		cv.famBits = 2
	}

	for _, raw := range nr.Expr {
		var expr map[string]json.RawMessage
		if err := json.Unmarshal(raw, &expr); err != nil {
			return nil, fmt.Errorf("expression: %w", err)
		}
		if len(expr) != 1 {
			return nil, fmt.Errorf("expression: expected one key, got %d", len(expr))
		}
		for kind, val := range expr {
			if cv.verdict {
				return nil, fmt.Errorf("expression %q after terminal verdict", kind)
			}
			if err := cv.expr(kind, val); err != nil {
				return nil, err
			}
		}
	}
	if !cv.verdict {
		return nil, fmt.Errorf("no terminal verdict")
	}
	if cv.comment != "" {
		cv.r.Comment = cv.comment
	}
	if cv.r.Proto == "" {
		cv.r.Proto = "any"
	}
	cv.r.ID = rule.NewID()
	cv.r.Normalize()

	out := &nftPair{counters: cv.counters, logOpts: cv.logOpts, rejOpts: cv.rejOpts}
	if cv.famBits != 2 { // unrestricted (0) or v4-only (1)
		out.v4 = append(out.v4, cv.r)
	}
	if cv.famBits != 1 { // unrestricted (0) or v6-only (2)
		r6 := cv.r
		r6.SetV6(true)
		out.v6 = append(out.v6, r6)
	}
	return out, nil
}

// expr dispatches one {"kind": value} expression.
func (c *nftConv) expr(kind string, val json.RawMessage) error {
	switch kind {
	case "match":
		var m nftMatch
		if err := json.Unmarshal(val, &m); err != nil {
			return fmt.Errorf("match: %w", err)
		}
		return c.match(&m)
	case "counter":
		c.counters++
		return nil // accounting metadata
	case "log":
		// val is null or an options object. group/queue-threshold retarget
		// the statement to NFLOG — a different sink than the model's kernel
		// log, so those are fatal; the rest are presentational detail the
		// model drops with a warning.
		if len(val) > 0 && string(val) != "null" {
			var opts map[string]json.RawMessage
			if err := json.Unmarshal(val, &opts); err != nil {
				return fmt.Errorf("log: %w", err)
			}
			for _, k := range []string{"group", "queue-threshold"} {
				if _, ok := opts[k]; ok {
					return fmt.Errorf("log option %q targets NFLOG, which the model cannot express", k)
				}
			}
			if len(opts) > 0 {
				c.logOpts++
			}
		}
		c.r.Log = rule.LogAll
		return nil
	case "comment":
		var s string
		if err := json.Unmarshal(val, &s); err != nil {
			return fmt.Errorf("comment: %w", err)
		}
		c.comment = s
		return nil
	case "accept":
		c.r.Action = rule.ActionAllow
		c.verdict = true
		return nil
	case "drop":
		c.r.Action = rule.ActionDeny
		c.verdict = true
		return nil
	case "reject":
		// The compiler always emits icmpx port-unreachable (nft's own
		// default); any other type/expr is dropped and warned about.
		if len(val) > 0 && string(val) != "null" {
			var opts struct {
				Type string `json:"type"`
				Expr string `json:"expr"`
			}
			if err := json.Unmarshal(val, &opts); err != nil {
				return fmt.Errorf("reject: %w", err)
			}
			if (opts.Type != "" && opts.Type != "icmpx") ||
				(opts.Expr != "" && opts.Expr != "port-unreachable") {
				c.rejOpts++
			}
		}
		c.r.Action = rule.ActionReject
		c.verdict = true
		return nil
	case "jump", "goto", "return", "continue":
		return fmt.Errorf("%s verdict is not representable (no user chains)", kind)
	default:
		return fmt.Errorf("unsupported expression %q", kind)
	}
}

// match handles one {"match": {"op": ..., "left": ..., "right": ...}}.
func (c *nftConv) match(m *nftMatch) error {
	op := m.Op
	if op == "" {
		op = "=="
	}
	if op != "==" && op != "in" {
		return fmt.Errorf("match operator %q is not representable (equality only)", op)
	}
	// Negations and set RHS need left info to report accurately; decode
	// left first.
	left, err := nftLeft(m.Left)
	if err != nil {
		return err
	}
	var probe nftSet
	if err := json.Unmarshal(m.Right, &probe); err == nil && probe.Set != nil {
		return fmt.Errorf("%s: set matches are not supported", left.desc)
	}
	if op == "in" {
		return fmt.Errorf("%s: set membership matches are not supported", left.desc)
	}
	return c.eq(left, m.Right)
}

// nftOperand is a decoded LHS: a named meta key or a payload field.
type nftOperand struct {
	kind  string // "meta" | "payload"
	desc  string // human-readable, for errors
	key   string // meta key or payload protocol
	field string // payload field ("" for meta)
}

// nftLeft decodes the left operand of a match: {"meta": key-or-obj} or
// {"payload": {"protocol": p, "field": f}}.
func nftLeft(raw json.RawMessage) (*nftOperand, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("match left: %w", err)
	}
	if len(obj) != 1 {
		return nil, fmt.Errorf("match left: expected one key, got %d", len(obj))
	}
	for kind, v := range obj {
		switch kind {
		case "meta":
			key, err := nftKey(v)
			if err != nil {
				return nil, fmt.Errorf("meta: %w", err)
			}
			return &nftOperand{kind: "meta", desc: "meta " + key, key: key}, nil
		case "payload":
			var kv nftKeyVal
			if err := json.Unmarshal(v, &kv); err != nil {
				return nil, fmt.Errorf("payload: %w", err)
			}
			return &nftOperand{kind: "payload", desc: kv.Protocol + " " + kv.Field, key: kv.Protocol, field: kv.Field}, nil
		case "ct", "rt", "th", "fib", "socket", "osf", "exthdr":
			return nil, fmt.Errorf("%s expression is not representable", kind)
		default:
			return nil, fmt.Errorf("unsupported match left %q", kind)
		}
	}
	return nil, fmt.Errorf("match left: empty")
}

// nftKey accepts both meta/ct encodings: "l4proto" and {"key": "l4proto"}.
func nftKey(v json.RawMessage) (string, error) {
	var s string
	if err := json.Unmarshal(v, &s); err == nil {
		return s, nil
	}
	var kv nftKeyVal
	if err := json.Unmarshal(v, &kv); err != nil {
		return "", fmt.Errorf("expected key string or object: %w", err)
	}
	return kv.Key, nil
}

// eq applies an equality match: o == right.
func (c *nftConv) eq(o *nftOperand, right json.RawMessage) error {
	if o.kind == "meta" {
		return c.metaEq(o, right)
	}
	return c.payloadEq(o, right)
}

func (c *nftConv) metaEq(o *nftOperand, right json.RawMessage) error {
	switch o.key {
	case "l4proto":
		p, err := nftProtoVal(right)
		if err != nil {
			return fmt.Errorf("meta l4proto: %w", err)
		}
		return c.setProto(p, "meta l4proto")
	case "nfproto":
		var s string
		if err := json.Unmarshal(right, &s); err != nil {
			return fmt.Errorf("meta nfproto: %w", err)
		}
		switch s {
		case "ipv4":
			return c.restrict(1, "meta nfproto")
		case "ipv6":
			return c.restrict(2, "meta nfproto")
		default:
			return fmt.Errorf("meta nfproto: unsupported protocol family %q", s)
		}
	case "iifname":
		return c.iface(&c.r.IfaceIn, right, "iifname")
	case "oifname":
		return c.iface(&c.r.IfaceOut, right, "oifname")
	case "mark", "iif", "oif", "skuid", "skgid", "length", "priority", "protocol", "cpu", "iifgroup", "oifgroup", "cgclassid", "ibriport", "obriport", "pkttype", "ipsec", "time", "day", "hour", "secmark":
		return fmt.Errorf("meta %s is not representable", o.key)
	default:
		return fmt.Errorf("unsupported meta key %q", o.key)
	}
}

func (c *nftConv) iface(dst *string, right json.RawMessage, what string) error {
	var s string
	if err := json.Unmarshal(right, &s); err != nil {
		return fmt.Errorf("meta %s: %w", what, err)
	}
	if s == "" {
		return fmt.Errorf("meta %s: empty interface name", what)
	}
	if *dst != "" && *dst != s {
		return fmt.Errorf("meta %s: conflicting interface names %q and %q", what, *dst, s)
	}
	*dst = s
	return nil
}

func (c *nftConv) payloadEq(o *nftOperand, right json.RawMessage) error {
	switch o.key {
	case "ip":
		if err := c.restrict(1, "ip payload"); err != nil {
			return err
		}
	case "ip6":
		if err := c.restrict(2, "ip6 payload"); err != nil {
			return err
		}
	}
	switch o.key + "." + o.field {
	case "ip.protocol":
		p, err := nftProtoVal(right)
		if err != nil {
			return fmt.Errorf("ip protocol: %w", err)
		}
		return c.setProto(p, "ip protocol")
	case "ip6.nexthdr":
		p, err := nftProtoVal(right)
		if err != nil {
			return fmt.Errorf("ip6 nexthdr: %w", err)
		}
		return c.setProto(p, "ip6 nexthdr")
	case "icmp.type", "icmpv6.type":
		return c.icmpType(o.key, right)
	case "ip.saddr":
		return c.addr(&c.r.Src, right, false, "ip saddr")
	case "ip.daddr":
		return c.addr(&c.r.Dst, right, false, "ip daddr")
	case "ip6.saddr":
		return c.addr(&c.r.Src, right, true, "ip6 saddr")
	case "ip6.daddr":
		return c.addr(&c.r.Dst, right, true, "ip6 daddr")
	case "tcp.sport":
		return c.port(&c.r.Src, right, "tcp", "sport")
	case "tcp.dport":
		return c.port(&c.r.Dst, right, "tcp", "dport")
	case "udp.sport":
		return c.port(&c.r.Src, right, "udp", "sport")
	case "udp.dport":
		return c.port(&c.r.Dst, right, "udp", "dport")
	default:
		return fmt.Errorf("%s %s is not representable", o.key, o.field)
	}
}

// nftProtoVal decodes a protocol RHS: name string or ip protocol number.
func nftProtoVal(right json.RawMessage) (string, error) {
	var s string
	if err := json.Unmarshal(right, &s); err == nil {
		if p, ok := nftProto[s]; ok {
			return p, nil
		}
		return "", fmt.Errorf("unsupported protocol %q", s)
	}
	var n int
	if err := json.Unmarshal(right, &n); err != nil {
		return "", fmt.Errorf("expected protocol name or number: %w", err)
	}
	if p, ok := nftProtoNum[n]; ok {
		return p, nil
	}
	return "", fmt.Errorf("unsupported protocol number %d", n)
}

// addr applies an IP equality match: bare host string or
// {"prefix": {...}} CIDR. "any" wildcards and host masks normalize via
// r.Normalize() after conversion.
func (c *nftConv) addr(a *rule.AddrSpec, right json.RawMessage, v6 bool, what string) error {
	var s string
	if err := json.Unmarshal(right, &s); err == nil {
		if !a.Any() && a.IP != s {
			return fmt.Errorf("%s: conflicting addresses %q and %q", what, a.IP, s)
		}
		a.IP = s
		return nil
	}
	var w struct {
		Prefix *nftPrefix `json:"prefix"`
	}
	if err := json.Unmarshal(right, &w); err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if w.Prefix == nil {
		return fmt.Errorf("%s: unsupported address operand (want host or prefix)", what)
	}
	p := w.Prefix
	if p.Addr == "" {
		return fmt.Errorf("%s: empty prefix address", what)
	}
	ip := net.ParseIP(p.Addr)
	if ip == nil {
		return fmt.Errorf("%s: invalid address %q", what, p.Addr)
	}
	bits := 32
	if v6 {
		bits = 128
	}
	if p.Len < 0 || p.Len > bits {
		return fmt.Errorf("%s: invalid prefix length %d", what, p.Len)
	}
	a.IP = fmt.Sprintf("%s/%d", ip.String(), p.Len)
	return nil
}

// port applies a port equality match: number, digit string, or
// {"range": [lo, hi]}.
func (c *nftConv) port(a *rule.AddrSpec, right json.RawMessage, proto, what string) error {
	if err := c.setProto(proto, proto+" "+what); err != nil {
		return err
	}
	c.l4Set = true
	lo, hi, err := nftPortVal(right)
	if err != nil {
		return fmt.Errorf("%s %s: %w", proto, what, err)
	}
	pr := rule.PortRange{Lo: lo, Hi: hi, Proto: proto}
	if len(a.Ports) != 0 {
		ex := a.Ports[0]
		if ex.Proto != proto {
			return fmt.Errorf("%s: mixed port protocols %q and %q", what, ex.Proto, proto)
		}
		if ex == pr {
			return nil // duplicate match, harmless
		}
		// nft conjuncts repeated matches on one field; PortRange slices
		// compile as a union, so a differing second constraint would be
		// broadened — reject instead.
		return fmt.Errorf("%s: conflicting port constraints %s and %s (nft conjuncts them, the model would union them)", proto+" "+what, ex.String(), pr.String())
	}
	a.Ports = append(a.Ports, pr)
	return nil
}

// nftPortVal decodes a port RHS: number, decimal string, or
// {"range": [lo, hi]}. Named ports (strings) are rejected.
func nftPortVal(right json.RawMessage) (uint16, uint16, error) {
	one := func(raw json.RawMessage) (uint16, error) {
		var n int
		if err := json.Unmarshal(raw, &n); err == nil {
			if n < 0 || n > 65535 {
				return 0, fmt.Errorf("port %d out of range", n)
			}
			return uint16(n), nil
		}
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return 0, fmt.Errorf("expected port number")
		}
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 || n > 65535 {
			return 0, fmt.Errorf("unsupported port %q (names and non-numeric values are not representable)", s)
		}
		return uint16(n), nil
	}
	var rng nftRange
	if err := json.Unmarshal(right, &rng); err == nil && rng.Range[0] != nil {
		lo, err := one(rng.Range[0])
		if err != nil {
			return 0, 0, err
		}
		hi, err := one(rng.Range[1])
		if err != nil {
			return 0, 0, err
		}
		if hi < lo {
			return 0, 0, fmt.Errorf("port range %d-%d is inverted", lo, hi)
		}
		return lo, hi, nil
	}
	p, err := one(right)
	if err != nil {
		return 0, 0, err
	}
	return p, p, nil
}

// icmpType applies an icmp.type / icmpv6.type equality match. The RHS is a
// number or symbolic name normalized to the canonical decimal string by
// rule.ICMPTypeNumber; ranges, sets, and anything else are rejected. The
// match pins the l4 protocol (icmp ⇒ IPv4, icmpv6 ⇒ IPv6 — setProto
// narrows the family and rejects contradicting protocol/port matches).
// nft conjuncts repeated type matches but the model stores one type, so
// identical constraints coalesce and differing ones are rejected.
func (c *nftConv) icmpType(proto string, right json.RawMessage) error {
	if err := c.setProto(proto, proto+" type"); err != nil {
		return err
	}
	var token string
	var s string
	if err := json.Unmarshal(right, &s); err == nil {
		token = s
	} else {
		var n int
		if err := json.Unmarshal(right, &n); err != nil {
			return fmt.Errorf("%s type: expected type name or number", proto)
		}
		token = strconv.Itoa(n)
	}
	typ, err := rule.ICMPTypeNumber(proto, token)
	if err != nil {
		return fmt.Errorf("%s type: %w", proto, err)
	}
	if c.r.ICMPType != "" && c.r.ICMPType != typ {
		return fmt.Errorf("%s type: conflicting types %q and %q (nft conjuncts them, the model stores one)", proto, c.r.ICMPType, typ)
	}
	c.r.ICMPType = typ
	return nil
}

// nftCloneState deep-copies st so failed imports leave the input untouched
// (mergeRules mutates list elements in place).
func nftCloneState(st *store.State) *store.State {
	out := *st
	out.Rules4 = append([]rule.Rule(nil), st.Rules4...)
	out.Rules6 = append([]rule.Rule(nil), st.Rules6...)
	out.Sets = append([]store.IPSet(nil), st.Sets...)
	for i := range out.Sets {
		out.Sets[i].Elements = append([]string(nil), st.Sets[i].Elements...)
	}
	out.NAT = append([]store.NATRule(nil), st.NAT...)
	out.Bans = append([]store.ThreatBan(nil), st.Bans...)
	return &out
}
