// parser.go implements the full ufw rule grammar, ported from ufw 0.36.2
// parser.py (UFWCommandRule.parse + UFWCommandRouteRule.parse) with bfw
// extensions: `expires DUR`, `from|to set NAME`, and the short form
// `ACTION in|out on IFACE PORT[/PROTO]|APPNAME`.
//
// Error strings mirror ufw's UFWError messages verbatim (the caller adds
// the "ERROR: " prefix). ErrSyntax marks malformed input; the caller maps
// it to ufw's syntax-error behavior (full help on stdout, exit 1).
package cli

import (
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"bfirewall/internal/appprof"
	"bfirewall/internal/rule"
	"bfirewall/internal/services"
	"bfirewall/internal/store"
)

// ErrSyntax reports malformed command lines. ufw raises ValueError for
// these and prints the full help text; callers should do the same.
var ErrSyntax = errors.New("invalid syntax")

var (
	numListRe   = regexp.MustCompile(`^\d([0-9,:]*\d+)*$`)
	portRangeRe = regexp.MustCompile(`^\d+:\d+$`)
	portNumRe   = regexp.MustCompile(`^\d+$`)
	portSvcRe   = regexp.MustCompile(`^\w[\w\-]+`)
	ifaceRe     = regexp.MustCompile(`^[a-zA-Z0-9_\-\.\+,=%@]+$`)
	insertNumRe = regexp.MustCompile(`^[0-9]+$`)
	expiryRe    = regexp.MustCompile(`^(\d+)([smhd])$`)
	appInOutRe  = regexp.MustCompile(` app (in|out) `)
	dottedRe    = regexp.MustCompile(`^[0-9.]+$`)
)

func countTok(argv []string, tok string) int {
	n := 0
	for _, a := range argv {
		if a == tok {
			n++
		}
	}
	return n
}

func indexTok(argv []string, tok string) int {
	for i, a := range argv {
		if a == tok {
			return i
		}
	}
	return -1
}

func hasAnyTok(argv []string, toks ...string) bool {
	for _, a := range argv {
		for _, t := range toks {
			if a == t {
				return true
			}
		}
	}
	return false
}

func isDirTok(s string) bool {
	l := strings.ToLower(s)
	return l == "in" || l == "out"
}

// parseRuleArgs parses the complete ufw rule grammar. See ParseRuleArgs.
func parseRuleArgs(args []string) (*ParsedRuleOp, error) {
	argv := append([]string(nil), args...)

	// ufw UFWCommandRouteRule.parse: 'route' is stripped first and the
	// remainder re-parsed as a rule (so 'route rule …' works). Mirror
	// that: strip 'route', then the optional 'rule' keyword.
	routed := false
	deferredDir, deferredIface := "", ""
	if len(argv) > 0 && strings.ToLower(argv[0]) == "route" {
		routed = true
		argv = argv[1:]
	}
	if len(argv) > 0 && strings.ToLower(argv[0]) == "rule" {
		argv = argv[1:]
	}
	if routed {

		// 'ufw delete NUM' is the correct usage, not 'ufw route delete NUM'.
		for i, a := range argv {
			if a == "delete" && i+1 < len(argv) {
				if _, err := strconv.Atoi(argv[i+1]); err == nil {
					return nil, errors.New("'route delete NUM' unsupported. Use 'delete NUM' instead.")
				}
			}
		}

		// Route rules support both 'in on IF' and 'out on IF'; the base
		// parser only accepts the interface clause first, so strip the
		// second one and apply it afterwards (ufw UFWCommandRouteRule).
		s := strings.Join(argv, " ")
		inOn := strings.Contains(s, " in on ")
		outOn := strings.Contains(s, " out on ")
		switch {
		case inOn && outOn:
			strip := "out"
			if indexTok(argv, "in") > indexTok(argv, "out") {
				strip = "in"
			}
			i := indexTok(argv, strip)
			if i >= 0 && i+2 < len(argv) {
				deferredDir, deferredIface = strip, argv[i+2]
				argv = append(argv[:i:i], argv[i+3:]...)
			} else {
				// "in on"/"out on" only inside a comment or app name —
				// no real interface clause. ufw: argv.index() ValueError
				// → Invalid syntax.
				return nil, ErrSyntax
			}
		case !inOn && !outOn && !appInOutRe.MatchString(s) &&
			(strings.Contains(s, " in ") || strings.Contains(s, " out ")):
			// A direction without an interface makes no sense for route
			// rules (app names may be 'in'/'out', hence the regex guard).
			return nil, errors.New("Invalid interface clause for route rule")
		}
	}

	var (
		action       string
		fromType     = "any"
		toType       = "any"
		fromService  string
		toService    string
		insertPosStr string
		insertPos    int
		prepend      bool
		logtype      string
		remove       bool
	)

	if len(argv) > 0 {
		switch strings.ToLower(argv[0]) {
		case "delete":
			if len(argv) > 1 {
				remove = true
				argv = argv[1:]
				if n, err := strconv.Atoi(argv[0]); err == nil {
					// Deleting by rule number.
					return &ParsedRuleOp{Kind: OpDelete, Num: n, Routed: routed}, nil
				}
				action = argv[0]
			}
		case "insert":
			if len(argv) < 4 {
				return nil, ErrSyntax
			}
			insertPosStr = argv[1]
			// ufw set_position: unanchored ^[0-9]+ on the string, then
			// int(). "00"→0 (append); negatives/non-numeric → invalid.
			if !insertNumRe.MatchString(insertPosStr) {
				return nil, fmt.Errorf("Insert position '%s' is not a valid position", insertPosStr)
			}
			if n, err := strconv.Atoi(insertPosStr); err == nil {
				insertPos = n
			} else {
				// Overflow: keep a huge sentinel so position checks reject.
				insertPos = int(^uint(0) >> 1)
			}
			argv = argv[2:]
			action = argv[0]
		case "prepend":
			prepend = true
			argv = argv[1:]
			if len(argv) == 0 {
				return nil, ErrSyntax
			}
			action = argv[0]
		default:
			action = argv[0]
		}
	}

	switch action {
	case rule.ActionAllow, rule.ActionDeny, rule.ActionReject, rule.ActionLimit:
	default:
		return nil, ErrSyntax
	}

	nargs := len(argv)
	if nargs < 2 {
		return nil, ErrSyntax
	}

	// Direction: 'in' is the default; a bare in/out token is stripped
	// unless it introduces an interface clause ('in on IFACE').
	direction := rule.DirIn
	if nargs > 1 && isDirTok(argv[1]) {
		direction = strings.ToLower(argv[1])
	}
	if nargs > 2 && argv[2] != "on" && isDirTok(argv[1]) {
		direction = strings.ToLower(argv[1])
		argv = append(argv[:1], argv[2:]...)
		nargs = len(argv)
	}

	// Interface clause: 'allow in on eth0 ...' — strip the 'on'.
	hasIface := false
	if nargs > 1 && (countTok(argv, "in") > 0 || countTok(argv, "out") > 0) {
		errMsg := errors.New("Invalid interface clause")
		if !isDirTok(argv[1]) {
			return nil, errMsg
		}
		if nargs < 3 || strings.ToLower(argv[2]) != "on" {
			return nil, errMsg
		}
		argv = append(argv[:2], argv[3:]...)
		nargs = len(argv)
		hasIface = true
	}

	// log|log-all must directly follow the action or interface clause.
	logIdx := 0
	if hasIface && nargs > 3 && isLogTok(argv[3]) {
		logIdx = 3
	} else if nargs > 2 && isLogTok(argv[1]) {
		logIdx = 1
	}
	if logIdx > 0 {
		logtype = strings.ToLower(argv[logIdx])
		argv = append(argv[:logIdx], argv[logIdx+1:]...)
		nargs = len(argv)
	}
	if indexTok(argv, "log") >= 0 {
		return nil, errors.New("Option 'log' not allowed here")
	}
	if indexTok(argv, "log-all") >= 0 {
		return nil, errors.New("Option 'log-all' not allowed here")
	}

	// Comment clause.
	comment := ""
	if i := indexTok(argv, "comment"); i >= 0 {
		if i == len(argv)-1 {
			return nil, errors.New("Option 'comment' missing required argument")
		}
		comment = argv[i+1]
		if strings.Contains(comment, "'") {
			// ufw raises ValueError here → syntax error.
			return nil, ErrSyntax
		}
		argv = append(argv[:i], argv[i+2:]...)
		nargs = len(argv)
	}

	// bfw extension: expires clause.
	var expiresAt int64
	if i := indexTok(argv, "expires"); i >= 0 {
		if i == len(argv)-1 {
			return nil, errors.New("Option 'expires' missing required argument")
		}
		d, err := parseExpiry(argv[i+1])
		if err != nil {
			return nil, err
		}
		expiresAt = time.Now().Unix() + d
		argv = append(argv[:i], argv[i+2:]...)
		nargs = len(argv)
	}

	// bfw extension: 'from set NAME' / 'to set NAME' — fold the set name
	// into the address token so the key/value parity checks still hold.
	for i := 0; i+1 < len(argv); i++ {
		if (argv[i] == "from" || argv[i] == "to") && argv[i+1] == "set" {
			if i+2 >= len(argv) {
				return nil, fmt.Errorf("Missing set name in '%s' clause", argv[i])
			}
			argv[i+1] = "set:" + argv[i+2]
			argv = append(argv[:i+2], argv[i+3:]...)
		}
	}
	nargs = len(argv)

	if nargs < 2 || nargs > 13 {
		return nil, ErrSyntax
	}

	r := &rule.Rule{
		ID:        rule.NewID(),
		Action:    action,
		Direction: direction,
		Proto:     "any",
		Log:       logtype,
		Comment:   comment,
		ExpiresAt: expiresAt,
	}
	r.Src.IP = "any"
	r.Dst.IP = "any"

	// insertPos was already validated and parsed in the dispatch above;
	// the regex gate there is authoritative. Nothing more to do here.

	ipType := ""
	switch {
	case nargs == 2:
		// Short form: ACTION PORT[/PROTO] | ACTION APPNAME.
		var err error
		toService, err = shortToken(r, argv[1], remove)
		if err != nil {
			return nil, err
		}
		ipType = "both"
	case hasIface && nargs == 4:
		// bfw extension: ACTION in|out on IFACE PORT[/PROTO]|APPNAME.
		if err := setIface(r, strings.ToLower(argv[1]), argv[2]); err != nil {
			return nil, err
		}
		var err error
		toService, err = shortToken(r, argv[3], remove)
		if err != nil {
			return nil, err
		}
		ipType = "both"
	case (nargs+1)%2 != 0:
		return nil, errors.New("Wrong number of arguments")
	case !hasAnyTok(argv, "from", "to", "in", "out"):
		return nil, errors.New("Need 'to' or 'from' clause")
	default:
		// Full form with PF-style key/value clauses.
		if countTok(argv, "to") > 1 || countTok(argv, "from") > 1 ||
			countTok(argv, "proto") > 1 || countTok(argv, "port") > 2 ||
			countTok(argv, "in") > 1 || countTok(argv, "out") > 1 ||
			countTok(argv, "app") > 2 ||
			(countTok(argv, "app") > 0 && countTok(argv, "proto") > 0) {
			return nil, errors.New("Improper rule syntax")
		}

		keys := map[string]bool{
			"proto": true, "from": true, "to": true, "port": true,
			"app": true, "in": true, "out": true,
		}
		loc := ""
		for i := 0; i < nargs; i++ {
			arg := argv[i]
			if i%2 != 0 && !keys[arg] {
				return nil, fmt.Errorf("Invalid token '%s'", arg)
			}
			switch arg {
			case "proto":
				if i+1 >= nargs {
					return nil, errors.New("Invalid 'proto' clause")
				}
				if err := setProto(r, argv[i+1]); err != nil {
					return nil, err
				}
			case "in", "out":
				if i+1 >= nargs {
					return nil, fmt.Errorf("Invalid '%s' clause", arg)
				}
				if err := setIface(r, arg, argv[i+1]); err != nil {
					return nil, err
				}
			case "from", "to":
				if i+1 >= nargs {
					return nil, fmt.Errorf("Invalid '%s' clause", arg)
				}
				ip, set, typ, err := parseAddr(argv[i+1])
				if err != nil {
					if arg == "from" {
						return nil, errors.New("Bad source address")
					}
					return nil, errors.New("Bad destination address")
				}
				if arg == "from" {
					fromType = typ
					r.Src.IP, r.Src.Set = ip, set
					loc = "src"
				} else {
					toType = typ
					r.Dst.IP, r.Dst.Set = ip, set
					loc = "dst"
				}
			case "port", "app":
				if i+1 >= nargs {
					return nil, errors.New("Invalid 'port' clause")
				}
				if loc == "" {
					return nil, fmt.Errorf("Need 'from' or 'to' with '%s'", arg)
				}
				tmp := argv[i+1]
				if arg == "app" {
					err := setApp(r, loc, tmp, remove,
						fmt.Sprintf("Could not find a profile matching '%s'", tmp))
					if err != nil {
						return nil, err
					}
				} else {
					if !numListRe.MatchString(tmp) {
						if strings.ContainsAny(tmp, ",:") {
							return nil, errors.New("Port ranges must be numeric")
						}
						if loc == "src" {
							fromService = tmp
						} else {
							toService = tmp
						}
					}
					if err := setPort(r, loc, tmp); err != nil {
						return nil, err
					}
				}
			}
		}

		// Figure out whether this is an IPv4, IPv6, or dual rule.
		switch {
		case fromType == "any" && toType == "any":
			ipType = "both"
		case fromType != "any" && toType != "any" && fromType != toType:
			return nil, errors.New("Mixed IP versions for 'from' and 'to'")
		case fromType != "any":
			ipType = fromType
		default:
			ipType = toType
		}
	}

	// Adjust the rule protocol from any service names used as ports.
	if toService != "" || fromService != "" {
		proto := ""
		if toService != "" {
			_, p, err := services.Proto(toService)
			if err != nil {
				return nil, errors.New("Could not find protocol")
			}
			proto = p
		}
		if fromService != "" {
			if proto == "any" || proto == "" {
				_, p, err := services.Proto(fromService)
				if err != nil {
					return nil, errors.New("Could not find protocol")
				}
				proto = p
			} else {
				_, tmp, err := services.Proto(fromService)
				if err != nil {
					return nil, errors.New("Could not find protocol")
				}
				if proto == "any" || proto == tmp {
					proto = tmp
				} else if tmp != "any" {
					return nil, errors.New("Protocol mismatch (from/to)")
				}
			}
		}
		if r.Proto == "any" {
			if err := setProto(r, proto); err != nil {
				return nil, err
			}
		} else if proto != "any" && r.Proto != proto {
			return nil, fmt.Errorf("Protocol mismatch with specified protocol %s", r.Proto)
		}
	}

	// ipv6/igmp are IPv4-only protocols.
	if services.IPv4OnlyProtocol(r.Proto) && ipType == "both" {
		ipType = "v4"
	}

	// verify() — ufw common.py.
	if r.Proto != "any" && (r.Sapp != "" || r.Dapp != "") {
		return nil, fmt.Errorf("Improper rule syntax ('%s' specified with app rule)", r.Proto)
	}
	if services.IPv4OnlyProtocol(r.Proto) && ipType == "v6" {
		return nil, fmt.Errorf("Invalid IPv6 address with protocol '%s'", r.Proto)
	}
	if services.PortlessProtocol(r.Proto) &&
		(len(r.Dst.Ports) > 0 || len(r.Src.Ports) > 0) {
		return nil, fmt.Errorf("Invalid port with protocol '%s'", r.Proto)
	}
	// ufw backend check: multiport requires tcp or udp. App rules carry
	// per-item protos and are exempt (validated by profile parsing).
	if r.Dapp == "" && r.Sapp == "" &&
		(multiPorts(r.Src.Ports) || multiPorts(r.Dst.Ports)) &&
		r.Proto != "tcp" && r.Proto != "udp" {
		return nil, errors.New("Must specify 'tcp' or 'udp' with multiple ports")
	}

	// Stamp the rule protocol onto port ranges that don't carry their own
	// (app-profile items already have per-item protocols).
	stampProto(r.Src.Ports, r.Proto)
	stampProto(r.Dst.Ports, r.Proto)

	if routed {
		// ufw keeps direction (in/out) alongside forward=True; preserve it
		// in RouteDir so status can show "(out)" and match() stays symmetric.
		r.RouteDir = r.Direction
		r.Direction = rule.DirRouted
		if deferredIface != "" {
			if err := setIface(r, deferredDir, deferredIface); err != nil {
				return nil, err
			}
		}
	}

	normalized := r.Normalize()

	op := &ParsedRuleOp{
		Kind:       OpAdd,
		Action:     action,
		Rule:       r,
		Routed:     routed,
		IPType:     ipType,
		Normalized: normalized,
	}
	switch {
	case remove:
		op.Kind = OpDelete
	case prepend:
		op.Kind = OpPrepend
	case insertPosStr != "":
		op.Kind = OpInsert
		op.Num = insertPos
	}
	return op, nil
}

func isLogTok(s string) bool {
	l := strings.ToLower(s)
	return l == "log" || l == "log-all"
}

// shortToken handles the short-form argument: an app profile name, a
// PORT[/PROTO] expression, or a service name. Returns the service name
// when the token resolved to one ("" otherwise).
func shortToken(r *rule.Rule, tok string, remove bool) (toService string, err error) {
	if appprof.ValidName(tok) {
		// /etc/services wins over app profiles on name collision. ufw sets
		// dapp unconditionally and the frontend reports the profile lookup
		// failure — use its message, not "Bad port".
		if _, _, serr := services.Proto(tok); serr != nil {
			err := setApp(r, "dst", tok, remove,
				fmt.Sprintf("Could not find a profile matching '%s'", tok))
			return "", err
		}
	}
	port, proto, err := parsePortProto(tok)
	if err != nil {
		return "", err
	}
	if !numListRe.MatchString(port) {
		if strings.ContainsAny(port, ",:") {
			return "", errors.New("Port ranges must be numeric")
		}
		toService = port
	}
	if err := setProto(r, proto); err != nil {
		return "", errors.New("Bad port")
	}
	if err := setPort(r, "dst", port); err != nil {
		return "", errors.New("Bad port")
	}
	return toService, nil
}

// parsePortProto splits PORT[/PROTO] (ufw parse_port_proto).
func parsePortProto(s string) (port, proto string, err error) {
	tmp := strings.Split(s, "/")
	switch len(tmp) {
	case 1:
		return tmp[0], "any", nil
	case 2:
		if services.PortlessProtocol(tmp[1]) {
			return "", "", fmt.Errorf("Invalid port with protocol '%s'", tmp[1])
		}
		return tmp[0], tmp[1], nil
	default:
		return "", "", errors.New("Bad port")
	}
}

// setProto sets the rule protocol (ufw set_protocol).
func setProto(r *rule.Rule, p string) error {
	if p == "any" || services.SupportedProtocol(p) {
		r.Proto = p
		return nil
	}
	return fmt.Errorf("Unsupported protocol '%s'", p)
}

// setPort validates and stores a port expression on one endpoint (ufw
// set_port). "any" leaves the endpoint wildcard.
func setPort(r *rule.Rule, loc, port string) error {
	if port == "any" {
		setPorts(r, loc, nil)
		return nil
	}
	ranges, err := parsePortRanges(port)
	if err != nil {
		return err
	}
	setPorts(r, loc, ranges)
	return nil
}

func setPorts(r *rule.Rule, loc string, ranges []rule.PortRange) {
	if loc == "src" {
		r.Src.Ports = ranges
	} else {
		r.Dst.Ports = ranges
	}
}

// parsePortRanges converts a numeric port expression into ranges,
// mirroring UFWRule.set_port validation: no leading/trailing separators,
// at most 14 ',' and ':' combined, bounds 1-65535, ranges strictly
// increasing. A single service name resolves via /etc/services.
func parsePortRanges(port string) ([]rule.PortRange, error) {
	bad := fmt.Errorf("Bad port '%s'", port)
	if strings.HasPrefix(port, ",") || strings.HasPrefix(port, ":") ||
		strings.HasSuffix(port, ",") || strings.HasSuffix(port, ":") {
		return nil, bad
	}
	if strings.Count(port, ",")+strings.Count(port, ":") > 14 {
		return nil, bad
	}
	var ranges []rule.PortRange
	for _, p := range strings.Split(port, ",") {
		switch {
		case portRangeRe.MatchString(p):
			ran := strings.SplitN(p, ":", 2)
			lo, _ := strconv.Atoi(ran[0])
			hi, _ := strconv.Atoi(ran[1])
			if lo < 1 || lo > 65535 || hi < 1 || hi > 65535 || lo >= hi {
				return nil, bad
			}
			ranges = append(ranges, rule.PortRange{Lo: uint16(lo), Hi: uint16(hi)})
		case portNumRe.MatchString(p):
			n, _ := strconv.Atoi(p)
			if n < 1 || n > 65535 {
				return nil, bad
			}
			ranges = append(ranges, rule.PortRange{Lo: uint16(n), Hi: uint16(n)})
		case portSvcRe.MatchString(p):
			n, _, err := services.Proto(p)
			if err != nil {
				return nil, bad
			}
			ranges = append(ranges, rule.PortRange{Lo: uint16(n), Hi: uint16(n)})
		default:
			return nil, bad
		}
	}
	return ranges, nil
}

// setApp attaches an application profile to one endpoint: the canonical
// profile name goes on Dapp/Sapp and the profile's port items expand into
// the endpoint's port ranges (one PortRange per list element, carrying the
// item's protocol). On delete, a missing profile is tolerated so rules for
// removed profiles can still be matched (ufw LP: #407810).
func setApp(r *rule.Rule, loc, name string, remove bool, notFound string) error {
	p := appprof.Find(loadProfiles(), name)
	if p == nil {
		if !remove {
			return errors.New(notFound)
		}
		if loc == "src" {
			r.Sapp = name
		} else {
			r.Dapp = name
		}
		return nil
	}
	var ranges []rule.PortRange
	wildcard := false
	for _, spec := range p.Expand() {
		if spec.Ports == "any" {
			wildcard = true
			break
		}
		prs, err := parsePortRanges(spec.Ports)
		if err != nil {
			return err
		}
		for _, pr := range prs {
			pr.Proto = spec.Proto
			ranges = append(ranges, pr)
		}
	}
	if wildcard {
		ranges = nil
	}
	if loc == "src" {
		r.Sapp = p.Name
		r.Src.Ports = ranges
	} else {
		r.Dapp = p.Name
		r.Dst.Ports = ranges
	}
	return nil
}

// loadProfiles loads app profiles from the bfirewall store dir plus the
// ufw compatibility dir (both under BFW_PREFIX when set).
func loadProfiles() []*appprof.Profile {
	ufwDir := "/etc/ufw/applications.d"
	if prefix := os.Getenv("BFW_PREFIX"); prefix != "" {
		ufwDir = filepath.Join(prefix, "etc", "ufw", "applications.d")
	}
	st := store.Default()
	_ = st.EnsureDefaults()
	profs, _, _ := appprof.LoadAll(st.AppDir(), ufwDir)
	return profs
}

// parseAddr validates a from/to address token: "any", an IP or CIDR (v4
// dotted netmasks canonicalized to CIDR when contiguous), or a "set:NAME"
// reference. Returns the canonical address, set name, and address type
// ("v4", "v6", or "any").
func parseAddr(tok string) (ip, set, typ string, err error) {
	if strings.HasPrefix(tok, "set:") {
		name := tok[len("set:"):]
		if name == "" {
			return "", "", "", errors.New("missing set name")
		}
		return "", name, "any", nil
	}
	a := strings.ToLower(tok)
	if a == "any" {
		return "any", "", "any", nil
	}
	if !validAddress(a) {
		return "", "", "", errors.New("invalid address")
	}
	a = canonicalAddr(a)
	if strings.Contains(a, ":") {
		return a, "", "v6", nil
	}
	return a, "", "v4", nil
}

// validAddress mirrors ufw.util.valid_address: IPv4 (dotted quads, CIDR or
// dotted netmask) or IPv6 (CIDR mask only).
func validAddress(a string) bool {
	host, mask, hasMask := strings.Cut(a, "/")
	if strings.Contains(host, ":") {
		// ufw valid_address6 rejects '%' (zone IDs) and addrs >43 chars.
		if strings.Contains(host, "%") || len(host) > 43 {
			return false
		}
		if net.ParseIP(host) == nil {
			return false
		}
		if !hasMask {
			return true
		}
		n, err := strconv.Atoi(mask)
		return err == nil && n >= 0 && n <= 128
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil {
		return false
	}
	if !hasMask {
		return true
	}
	if n, err := strconv.Atoi(mask); err == nil {
		return n >= 0 && n <= 32
	}
	// Dotted-quad netmask.
	if !dottedRe.MatchString(mask) {
		return false
	}
	for _, o := range strings.Split(mask, ".") {
		n, err := strconv.Atoi(o)
		if err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return len(strings.Split(mask, ".")) == 4
}

// canonicalAddr rewrites a contiguous IPv4 dotted netmask to CIDR so the
// model and compiler only ever see CIDR form (non-contiguous masks are
// left as-is, matching ufw which keeps them).
func canonicalAddr(a string) string {
	host, mask, hasMask := strings.Cut(a, "/")
	if !hasMask || strings.Contains(host, ":") {
		return a
	}
	if _, err := strconv.Atoi(mask); err == nil {
		return a // already CIDR
	}
	m := net.ParseIP(mask)
	if m == nil || m.To4() == nil {
		return a
	}
	ones, bits := net.IPMask(m.To4()).Size()
	if bits == 0 {
		return a // non-contiguous: keep dotted form
	}
	return host + "/" + strconv.Itoa(ones)
}

// setIface validates and sets an interface name (ufw set_interface).
func setIface(r *rule.Rule, dir, name string) error {
	switch {
	case strings.Contains(name, "!"):
		return errors.New("Bad interface name: reserved character: '!'")
	case strings.Contains(name, ":"):
		return errors.New("Bad interface name: can't use interface aliases")
	case name == "." || name == "..":
		return errors.New("Bad interface name: can't use '.' or '..'")
	case name == "":
		return errors.New("Bad interface name: interface name is empty")
	case len(name) > 15:
		return errors.New("Bad interface name: interface name too long")
	case !ifaceRe.MatchString(name):
		return errors.New("Bad interface name")
	}
	if dir == "in" {
		r.IfaceIn = name
	} else {
		r.IfaceOut = name
	}
	return nil
}

// multiPorts reports whether one endpoint's port list is a ufw "multi"
// (more than one port, or a range).
func multiPorts(ports []rule.PortRange) bool {
	if len(ports) > 1 {
		return true
	}
	return len(ports) == 1 && ports[0].Multi()
}

// stampProto fills empty per-range protocols with the rule protocol.
func stampProto(ports []rule.PortRange, proto string) {
	for i := range ports {
		if ports[i].Proto == "" {
			ports[i].Proto = proto
		}
	}
}

// parseExpiry parses the bfw `expires` duration: Ns|Nm|Nh|Nd.
func parseExpiry(s string) (int64, error) {
	m := expiryRe.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("Invalid expires value '%s'", s)
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("Invalid expires value '%s'", s)
	}
	var mult int64
	switch m[2] {
	case "m":
		mult = 60
	case "h":
		mult = 3600
	case "d":
		mult = 86400
	default:
		mult = 1
	}
	if n > math.MaxInt64/mult {
		return 0, fmt.Errorf("Invalid expires value '%s'", s)
	}
	return n * mult, nil
}
