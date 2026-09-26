// Status rendering: canonical rule echo (ufw get_command), the
// To/Action/From table, and combined v4+v6 numbering. The algorithms here
// replicate ufw 0.36.2 backend_iptables.py::get_status and
// parser.py::UFWCommandRule.get_command exactly.
package cli

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/tmih06/better-firewall/internal/rule"
	"github.com/tmih06/better-firewall/internal/store"
	"github.com/tmih06/better-firewall/internal/sysstate"
)

// combined returns all rules in display order (v4 then v6) with family
// flags set, as pointers into the state's slices.
func combined(st *store.State) []*rule.Rule {
	out := make([]*rule.Rule, 0, len(st.Rules4)+len(st.Rules6))
	for i := range st.Rules4 {
		st.Rules4[i].SetV6(false)
		out = append(out, &st.Rules4[i])
	}
	for i := range st.Rules6 {
		st.Rules6[i].SetV6(true)
		out = append(out, &st.Rules6[i])
	}
	return out
}

// markFamilies sets transient v6 flags after Load.
func markFamilies(st *store.State) {
	for i := range st.Rules4 {
		st.Rules4[i].SetV6(false)
	}
	for i := range st.Rules6 {
		st.Rules6[i].SetV6(true)
	}
}

// canonAddr maps a stored endpoint to ufw's normalized address string
// ("0.0.0.0/0" / "::/0" for the wildcard).
func canonAddr(a rule.AddrSpec, v6 bool) string {
	if a.Set != "" {
		return "set " + a.Set
	}
	if a.Any() {
		if v6 {
			return "::/0"
		}
		return "0.0.0.0/0"
	}
	return a.IP
}

// portStr renders a port list the way ufw renders dport/sport ("any",
// "80", "80,443", "8080:8090"). The protocol is appended by the caller
// from r.Proto, mirroring ufw.
func portStr(ports []rule.PortRange) string {
	if len(ports) == 0 {
		return "any"
	}
	var b strings.Builder
	b.Grow(len(ports) * 12)
	for i, p := range ports {
		if i != 0 {
			b.WriteByte(',')
		}
		var digits [5]byte
		b.Write(strconv.AppendUint(digits[:0], uint64(p.Lo), 10))
		if p.Hi != p.Lo {
			b.WriteByte(':')
			b.Write(strconv.AppendUint(digits[:0], uint64(p.Hi), 10))
		}
	}
	return b.String()
}

// portsEqual compares port lists the way ufw does: by rendered string,
// ignoring per-item protocol (ufw compares r.dport == r.sport strings).
func portsEqual(a, b []rule.PortRange) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Lo != b[i].Lo || a[i].Hi != b[i].Hi {
			return false
		}
	}
	return true
}

// dedupedCount counts rules the way ufw's get_rules_count does: app-rule
// groups sharing an app tuple count once.
func dedupedCount(rules []rule.Rule) int {
	seen := map[string]bool{}
	n := 0
	for i := range rules {
		r := &rules[i]
		if r.Dapp != "" || r.Sapp != "" {
			t := r.AppTuple()
			if seen[t] {
				continue
			}
			seen[t] = true
		}
		n++
	}
	return n
}

// ruleByNumber maps a `status numbered` number to a rule index within its
// family list, deduplicating app tuples like ufw's get_rule_by_number.
func ruleByNumber(st *store.State, num int) (idx int, v6 bool, ok bool) {
	seen := map[string]bool{}
	count := 1
	for fam := 0; fam < 2; fam++ {
		rules := st.Rules4
		if fam == 1 {
			rules = st.Rules6
		}
		for i := range rules {
			r := &rules[i]
			if r.Dapp != "" || r.Sapp != "" {
				t := r.AppTuple()
				if seen[t] {
					continue
				}
				seen[t] = true
			}
			if count == num {
				return i, fam == 1, true
			}
			count++
		}
	}
	return 0, false, false
}

// GetCommand renders the canonical command for a rule, replicating ufw's
// UFWCommandRule.get_command: short form only when src/dst are wildcard,
// sport is any, no apps/interfaces and dport is set; otherwise the full
// PF-style form. Route rules are prefixed with "route ".
func GetCommand(r *rule.Rule) string {
	res := r.Action
	dst := canonAddr(r.Dst, r.V6())
	src := canonAddr(r.Src, r.V6())
	dstWild := dst == "0.0.0.0/0" || dst == "::/0"
	srcWild := src == "0.0.0.0/0" || src == "::/0"
	dport := portStr(r.Dst.Ports)
	sport := portStr(r.Src.Ports)

	if dstWild && srcWild && sport == "any" && r.Sapp == "" &&
		r.IfaceIn == "" && r.IfaceOut == "" && dport != "any" {
		// Short syntax.
		if r.Direction == rule.DirOut {
			res += " out"
		}
		if r.Log != "" {
			res += " " + r.Log
		}
		if r.Dapp != "" {
			if strings.Contains(r.Dapp, " ") {
				res += " '" + r.Dapp + "'"
			} else {
				res += " " + r.Dapp
			}
		} else {
			res += " " + dport
			if r.Proto != "" && r.Proto != "any" {
				res += "/" + r.Proto
			}
		}
		if r.Comment != "" {
			res += " comment '" + r.Comment + "'"
		}
	} else {
		// Full syntax.
		if r.IfaceIn != "" {
			res += " in on " + r.IfaceIn
		}
		if r.IfaceOut != "" {
			res += " out on " + r.IfaceOut
		} else if r.Direction == rule.DirOut {
			res += " out"
		}
		if r.Log != "" {
			res += " " + r.Log
		}
		sides := []struct {
			loc, port, app, dir string
		}{
			{src, sport, r.Sapp, "from"},
			{dst, dport, r.Dapp, "to"},
		}
		for _, s := range sides {
			loc := s.loc
			if loc == "0.0.0.0/0" || loc == "::/0" {
				loc = "any"
			}
			if loc != "any" || s.port != "any" || s.app != "" {
				res += " " + s.dir + " " + loc
				if s.app != "" {
					if strings.Contains(s.app, " ") {
						res += " app '" + s.app + "'"
					} else {
						res += " app " + s.app
					}
				} else if s.port != "any" {
					res += " port " + s.port
				}
			}
		}
		// A fully generic rule gets ' to any' to force extended form.
		if !strings.Contains(res, " to ") && !strings.Contains(res, " from ") &&
			r.IfaceIn == "" && r.IfaceOut == "" {
			res += " to any"
		}
		if r.Proto != "" && r.Proto != "any" && r.Dapp == "" && r.Sapp == "" {
			res += " proto " + r.Proto
		}
		if r.ICMPType != "" {
			res += " type " + r.ICMPType
		}
		if r.Comment != "" {
			res += " comment '" + r.Comment + "'"
		}
	}
	if r.Forward() {
		res = "route " + res
	}
	return res
}

// RuleLine renders one rule's To/Action/From columns plus the attribute
// suffix (" (log)", " (out)", " (log, out)"), replicating the per-rule
// logic of ufw's get_status. verbose enables verbose rendering; numbered
// selects the numbered action/attrib variants (ufw treats show_count like
// verbose for the action column).
func RuleLine(r *rule.Rule, verbose, numbered bool) (to, action, from, attribs string) {
	showProto := verbose || (r.Dapp == "" && r.Sapp == "")
	dst := canonAddr(r.Dst, r.V6())
	src := canonAddr(r.Src, r.V6())
	srcWild := src == "0.0.0.0/0" || src == "::/0"
	dstWild := dst == "0.0.0.0/0" || dst == "::/0"

	var loc [2]string // 0 = dst (To), 1 = src (From)
	for i := 0; i < 2; i++ {
		var tmp, port, app string
		if i == 0 {
			tmp = dst
			port = portStr(r.Dst.Ports)
			app = r.Dapp
		} else {
			tmp = src
			port = portStr(r.Src.Ports)
			app = r.Sapp
		}
		if !verbose && app != "" {
			port = app
			if r.V6() && tmp == "::/0" {
				port += " (v6)"
			}
		}

		if tmp != "0.0.0.0/0" && tmp != "::/0" {
			loc[i] = tmp
		}

		if port != "any" {
			if loc[i] == "" {
				loc[i] = port
			} else {
				loc[i] += " " + port
			}
			if showProto && r.Proto != "" && r.Proto != "any" {
				loc[i] += "/" + r.Proto
			}
			if verbose && app != "" {
				loc[i] += " (" + app
				if r.V6() && tmp == "::/0" {
					loc[i] += " (v6)"
				}
				loc[i] += ")"
			}
		}

		if port == "any" {
			if tmp == "0.0.0.0/0" || tmp == "::/0" {
				loc[i] = "Anywhere"
				// Show the protocol if Anywhere to Anywhere with a
				// protocol and both ports any.
				if showProto && r.Proto != "" && r.Proto != "any" &&
					dst == src && portsEqual(r.Dst.Ports, r.Src.Ports) {
					loc[i] += "/" + r.Proto
				}
				if tmp == "::/0" {
					loc[i] += " (v6)"
				}
			} else {
				// Show the protocol if set and both ports are any.
				if showProto && r.Proto != "" && r.Proto != "any" &&
					portsEqual(r.Dst.Ports, r.Src.Ports) {
					loc[i] += "/" + r.Proto
				}
			}
		} else if r.V6() && srcWild && dstWild && !strings.Contains(loc[i], " (v6)") {
			// v6 rule with ports but wildcard addresses: mark it so it
			// doesn't look like a duplicate of the v4 rule.
			loc[i] += " (v6)"
		}

		// Interface placement: route rules report interfaces relative to
		// packet flow (in under From, out under To); other rules relative
		// to the firewall (in under To, out under From).
		if r.Forward() {
			if i == 1 && r.IfaceIn != "" {
				loc[i] += " on " + r.IfaceIn
			}
			if i == 0 && r.IfaceOut != "" {
				loc[i] += " on " + r.IfaceOut
			}
		} else {
			if i == 0 && r.IfaceIn != "" {
				loc[i] += " on " + r.IfaceIn
			}
			if i == 1 && r.IfaceOut != "" {
				loc[i] += " on " + r.IfaceOut
			}
		}
	}
	if r.ICMPType != "" {
		loc[0] += " type " + r.ICMPType
	}

	var attrs []string
	// ufw shows "(out)" for routed rules whose direction is out; RouteDir
	// preserves the in/out that Direction=routed would otherwise hide.
	outDir := r.Direction == rule.DirOut || (r.Forward() && r.RouteDir == rule.DirOut)
	if r.Log != "" || outDir {
		if r.Log != "" {
			attrs = append(attrs, r.Log)
		}
		if numbered && outDir {
			attrs = append(attrs, "out")
		}
	}
	if len(attrs) > 0 {
		attribs = " (" + strings.Join(attrs, ", ") + ")"
	}

	dir := strings.ToUpper(r.Direction)
	if r.Forward() {
		dir = "FWD"
	}
	if r.Direction == rule.DirIn && !r.Forward() && !verbose && !numbered {
		dir = ""
	}
	action = strings.ToUpper(r.Action) + " " + dir

	return loc[0], action, loc[1], attribs
}

// statusLine formats one table row with ufw's exact column widths.
func statusLine(to, action, from, attribs, suffix string) string {
	return formatStatusLine(0, false, to, action, from, attribs, suffix)
}

func numberedStatusLine(number int, to, action, from, attribs, suffix string) string {
	return formatStatusLine(number, true, to, action, from, attribs, suffix)
}

func formatStatusLine(number int, numbered bool, to, action, from, attribs, suffix string) string {
	digits, divisor := 0, 1
	if numbered {
		digits = 1
		for n := number; n >= 10; n /= 10 {
			digits++
			divisor *= 10
		}
	}
	var b strings.Builder
	// The three columns occupy 26 + 1 + 12 + 26 bytes when their values fit
	// the ufw widths. Reserve that fixed part plus the variable suffix; long
	// or multibyte values are allowed to grow naturally below.
	reserve := 65 + len(attribs) + len(suffix)
	if numbered {
		if digits < 2 {
			digits = 2
		}
		reserve += digits + 3 // brackets and trailing space.
	}
	b.Grow(reserve)
	if numbered {
		b.WriteByte('[')
		if number < 10 {
			b.WriteByte(' ')
		}
		for divisor > 0 {
			b.WriteByte(byte('0' + number/divisor%10))
			divisor /= 10
		}
		b.WriteString("] ")
	}
	writeStatusField(&b, to, 26)
	b.WriteByte(' ')
	writeStatusField(&b, action, 12)
	writeStatusField(&b, from, 26)
	b.WriteString(attribs)
	b.WriteString(suffix)
	return b.String()
}

func writeStatusField(b *strings.Builder, value string, width int) {
	b.WriteString(value)
	if padding := width - utf8.RuneCountInString(value); padding > 0 {
		for i := 0; i < padding; i++ {
			b.WriteByte(' ')
		}
	}
}

// StatusLines renders the full `status` body (without the leading
// "Status: active" line) as lines, replicating ufw's get_status layout:
// verbose prepends Logging/Default/New profiles; the table is split into
// incoming/outgoing/routed sections unless numbered.
func StatusLines(st *store.State, numbered, verbose bool) []string {
	var b strings.Builder
	if verbose {
		b.WriteString("Status: active\n")
		b.WriteString(loggingStatusLine(st) + "\n")
		b.WriteString(defaultStatusLine(st) + "\n")
		b.WriteString("New profiles: " + st.AppPolicy)
	} else {
		b.WriteString("Status: active")
	}

	var inLines, outLines, rteLines, allLines []string
	seen := map[string]bool{}
	count := 1
	for family := 0; family < 2; family++ {
		rules := st.Rules4
		v6 := false
		if family == 1 {
			rules = st.Rules6
			v6 = true
		}
		for i := range rules {
			rules[i].SetV6(v6)
			r := &rules[i]
			if !verbose && (r.Dapp != "" || r.Sapp != "") {
				t := r.AppTuple()
				if seen[t] {
					continue
				}
				seen[t] = true
			}
			to, action, from, attribs := RuleLine(r, verbose, numbered)
			suffix := ""
			if r.Comment != "" {
				suffix = " # " + r.Comment
			}
			if r.Disabled {
				suffix += " (disabled)"
			}
			line := ""
			if numbered {
				line = numberedStatusLine(count, to, action, from, attribs, suffix)
			} else {
				line = statusLine(to, action, from, attribs, suffix)
			}
			if numbered {
				allLines = append(allLines, line)
			} else {
				switch {
				case r.Forward():
					rteLines = append(rteLines, line)
				case r.Direction == rule.DirOut:
					outLines = append(outLines, line)
				default:
					inLines = append(inLines, line)
				}
			}
			count++
		}
	}

	s := strings.Join(inLines, "\n")
	strOut := strings.Join(outLines, "\n")
	strRte := strings.Join(rteLines, "\n")
	if numbered {
		s = strings.Join(allLines, "\n")
		strOut, strRte = "", ""
	}

	if s != "" || strOut != "" || strRte != "" {
		b.WriteString("\n\n")
		if numbered {
			b.WriteString("     ")
		}
		b.WriteString(fmt.Sprintf("%-26s %-12s%s\n", "To", "Action", "From"))
		if numbered {
			b.WriteString("     ")
		}
		b.WriteString(fmt.Sprintf("%-26s %-12s%s\n", "--", "------", "----"))
		b.WriteString(s)
		if s != "" && strOut != "" {
			b.WriteString("\n\n")
		}
		if strOut != "" {
			b.WriteString(strOut)
		}
		if s != "" && strRte != "" {
			b.WriteString("\n\n")
		}
		if strRte != "" {
			b.WriteString(strRte)
		}
	}

	// ufw appends this hint when IPv6 is configured off.
	if !st.IPv6 {
		b.WriteString("\n\nIPv6 is not enabled")
	}

	return strings.Split(b.String(), "\n")
}

// loggingStatusLine renders ufw's "Logging: ..." verbose line.
func loggingStatusLine(st *store.State) string {
	switch st.Logging {
	case "off":
		return "Logging: off"
	case "low", "medium", "high", "full":
		return "Logging: on (" + st.Logging + ")"
	default:
		return "Logging: unknown"
	}
}

// defaultStatusLine renders ufw's "Default: ..." verbose line; routed is
// "disabled" when kernel forwarding is off.
func defaultStatusLine(st *store.State) string {
	routed := st.Policies.Forward
	v4, v6 := sysstate.IPForwardEnabled()
	fwd := v4 || (st.IPv6 && v6)
	if !fwd {
		routed = "disabled"
	}
	return fmt.Sprintf("Default: %s (incoming), %s (outgoing), %s (routed)",
		st.Policies.Input, st.Policies.Output, routed)
}
