// `show raw|builtins|before-rules|user-rules|after-rules|logging-rules|
// listening|added` — ufw report parity. Raw/builtins/user/logging render
// the compiled ruleset (nft format, documented deviation from ufw's
// iptables format); before/after print the fragment files; listening
// replicates frontend.get_show_listening; added echoes get_command.
package cli

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	nftbe "bfirewall/internal/backend/nft"
	"bfirewall/internal/report"
	"bfirewall/internal/rule"
)

// cmdShow implements `bfw show <report>`.
func (e *Env) cmdShow(args []string) int {
	if len(args) != 1 {
		e.Msg("%s", HelpText(e.Prog))
		return 1
	}
	switch args[0] {
	case "raw":
		return e.showRaw()
	case "builtins":
		return e.showChains("builtins", baseChainNames())
	case "before-rules":
		return e.showFragments("before", "before6")
	case "after-rules":
		return e.showFragments("after", "after6")
	case "user-rules":
		return e.showChains("user", userChainNames())
	case "logging-rules":
		return e.showChains("logging", loggingChainNames())
	case "listening":
		return e.showListening()
	case "added":
		return e.showAdded()
	default:
		e.Msg("%s", HelpText(e.Prog))
		return 1
	}
}

// showRaw prints the live ruleset. Prefers `nft list ruleset` (the
// truthful kernel view); falls back to rendering the stored model.
func (e *Env) showRaw() int {
	out, err := exec.Command("nft", "-nn", "list", "ruleset").Output()
	if err == nil {
		e.Msg("%s", strings.TrimRight(string(out), "\n"))
		return 0
	}
	// nft unavailable or failed: render the stored model instead.
	st, err := e.Store.Load()
	if err != nil {
		return e.Errorf("%s", err)
	}
	etc, err := e.Store.EtcDefaults()
	if err != nil {
		return e.Errorf("%s", err)
	}
	text, err := nftbe.RenderText(st, etc)
	if err != nil {
		return e.Errorf("%s", err)
	}
	e.Msg("%s", text)
	return 0
}

// showFragments prints the before/after nft fragment files.
func (e *Env) showFragments(names ...string) int {
	var b strings.Builder
	for _, n := range names {
		data, err := os.ReadFile(e.Store.FragmentPath(n))
		if err != nil {
			continue
		}
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		b.Write(data)
	}
	e.Msg("%s", strings.TrimRight(b.String(), "\n"))
	return 0
}

// chain-name groups mirroring ufw's get_running_raw categories.
func baseChainNames() map[string]bool {
	return map[string]bool{
		"input": true, "output": true, "forward": true,
		"prerouting": true, "postrouting": true,
	}
}

func userChainNames() map[string]bool {
	return map[string]bool{
		"bfw-user-input": true, "bfw-user-output": true, "bfw-user-forward": true,
		"bfw-user-limit": true, "bfw-user-limit-accept": true,
		"bfw-user-egress": true,
	}
}

func loggingChainNames() map[string]bool {
	return map[string]bool{
		"bfw-before-logging-input": true, "bfw-before-logging-output": true,
		"bfw-before-logging-forward": true,
		"bfw-user-logging-input":     true, "bfw-user-logging-output": true,
		"bfw-user-logging-forward": true,
		"bfw-after-logging-input":  true, "bfw-after-logging-output": true,
		"bfw-after-logging-forward": true,
		"bfw-logging-allow":         true, "bfw-logging-deny": true,
	}
}

// showChains renders the stored model and extracts the requested chain
// blocks (ufw's builtins/user/logging reports).
func (e *Env) showChains(kind string, names map[string]bool) int {
	st, err := e.Store.Load()
	if err != nil {
		return e.Errorf("%s", err)
	}
	etc, err := e.Store.EtcDefaults()
	if err != nil {
		return e.Errorf("%s", err)
	}
	text, err := nftbe.RenderText(st, etc)
	if err != nil {
		return e.Errorf("%s", err)
	}
	blocks := extractChains(text, names)
	if len(blocks) == 0 {
		e.Msg("%s", "")
		return 0
	}
	e.Msg("%s", strings.Join(blocks, "\n\n"))
	return 0
}

// extractChains pulls `chain <name> { ... }` blocks out of rendered
// nftables text.
func extractChains(text string, names map[string]bool) []string {
	var blocks []string
	lines := strings.Split(text, "\n")
	for i := 0; i < len(lines); i++ {
		f := strings.Fields(lines[i])
		if len(f) >= 3 && f[0] == "chain" && names[f[1]] {
			start := i
			depth := 0
			for ; i < len(lines); i++ {
				depth += strings.Count(lines[i], "{")
				depth -= strings.Count(lines[i], "}")
				if depth <= 0 && strings.Contains(lines[i], "}") {
					break
				}
			}
			blocks = append(blocks, strings.Join(lines[start:i+1], "\n"))
		}
	}
	return blocks
}

// showAdded echoes the canonical command for each stored rule
// (frontend.get_show_added).
func (e *Env) showAdded() int {
	st, err := e.Store.Load()
	if err != nil {
		return e.Errorf("%s", err)
	}
	markFamilies(st)

	var cmds []string
	seen := map[string]bool{}
	for _, r := range combined(st) {
		c := GetCommand(r)
		if seen[c] {
			continue
		}
		seen[c] = true
		cmds = append(cmds, c)
	}
	if e.JSON {
		out, err := json.MarshalIndent(map[string]any{"added": cmds}, "", "  ")
		if err != nil {
			return e.Errorf("%s", err)
		}
		e.Msg("%s", out)
		return 0
	}
	e.Msg("Added user rules (see '%s status' for running firewall):", e.Prog)
	if len(cmds) == 0 {
		e.Msg("(None)")
		return 0
	}
	for _, c := range cmds {
		e.Msg("%s %s", e.Prog, c)
	}
	return 0
}

// showListening lists listening sockets and the incoming rules matching
// each (frontend.get_show_listening + backend.get_matching).
func (e *Env) showListening() int {
	listeners, err := report.Listening()
	if err != nil {
		return e.Errorf("Could not get listening status")
	}
	st, err := e.Store.Load()
	if err != nil {
		return e.Errorf("%s", err)
	}
	markFamilies(st)
	rules := combined(st)

	// Group by protocol, sorted; ports sorted numerically.
	byProto := map[string]map[int][]report.Listener{}
	for _, l := range listeners {
		proto := l.Proto
		v6 := strings.HasSuffix(proto, "6") || strings.Contains(l.Addr, ":")
		if v6 && !st.IPv6 {
			continue
		}
		if byProto[proto] == nil {
			byProto[proto] = map[int][]report.Listener{}
		}
		byProto[proto][l.Port] = append(byProto[proto][l.Port], l)
	}

	var b strings.Builder
	protos := make([]string, 0, len(byProto))
	for p := range byProto {
		protos = append(protos, p)
	}
	sort.Strings(protos)
	for _, proto := range protos {
		fmt.Fprintf(&b, "%s:\n", proto)
		ports := make([]int, 0, len(byProto[proto]))
		for p := range byProto[proto] {
			ports = append(ports, p)
		}
		sort.Ints(ports)
		for _, port := range ports {
			for _, l := range byProto[proto][port] {
				addr := l.Addr
				if strings.HasPrefix(addr, "127.") || strings.HasPrefix(addr, "::1") {
					continue
				}
				v6 := strings.HasSuffix(proto, "6") || strings.Contains(addr, ":")
				ifname := ""
				fmt.Fprintf(&b, "  %d ", port)
				if addr == "0.0.0.0" || addr == "::" {
					b.WriteString("* ")
					addr += "/0"
				} else {
					fmt.Fprintf(&b, "%s ", addr)
					ifname = getIfFromIP(addr)
				}
				fmt.Fprintf(&b, "(%s)", filepath.Base(l.Exe))

				// Build an incoming rule for the listener and find
				// stored rules that would match it.
				x := &rule.Rule{
					Action:    rule.ActionAllow,
					Direction: rule.DirIn,
					Proto:     strings.TrimSuffix(proto, "6"),
					Dst: rule.AddrSpec{
						IP:    addr,
						Ports: []rule.PortRange{{Lo: uint16(port), Hi: uint16(port), Proto: strings.TrimSuffix(proto, "6")}},
					},
					Src: rule.AddrSpec{IP: "any"},
				}
				x.SetV6(v6)
				if ifname != "" {
					x.IfaceIn = ifname
				}
				x.Normalize()

				var matching []int
				for i, y := range rules {
					if fuzzyDstMatch(x, y) < 1 {
						matching = append(matching, i+1)
					}
				}
				if len(matching) > 0 {
					b.WriteString("\n")
					for _, i := range matching {
						fmt.Fprintf(&b, "   [%2d] %s\n", i, GetCommand(rules[i-1]))
					}
				}
				b.WriteString("\n")
			}
		}
	}
	e.Msg("%s", strings.TrimRight(b.String(), "\n"))
	return 0
}

// fuzzyDstMatch replicates UFWRule.fuzzy_dst_match: 0 exact, 1 no match,
// -1 fuzzy (x more specific than y). Only incoming rules are considered.
func fuzzyDstMatch(x, y *rule.Rule) int {
	if x.Match(y) == rule.MatchExact {
		return 0
	}
	if y.Direction != rule.DirIn || y.Forward() {
		return 1
	}
	if x.Proto != y.Proto && y.Proto != "any" {
		return 1
	}
	if len(y.Dst.Ports) > 0 && !matchPorts(x.Dst.Ports, y.Dst.Ports) {
		return 1
	}
	xdst := canonAddr(x.Dst, x.V6())
	ydst := canonAddr(y.Dst, y.V6())
	if y.IfaceIn == "" {
		// No interface on the rule: dst must match or contain x's dst.
		if x.IfaceIn == "" && isAnywhere(xdst) {
			// ok
		} else if xdst != ydst && !strings.Contains(ydst, "/") {
			return 1
		} else if xdst != ydst && strings.Contains(ydst, "/") &&
			x.V6() == y.V6() && !inNetwork(xdst, ydst) {
			return 1
		}
	} else {
		// Interface on the rule: x's interface must match, or the
		// interface's IP must match/be contained in y's dst.
		if x.IfaceIn != "" && x.IfaceIn != y.IfaceIn {
			return 1
		}
		ifIP, err := getIPFromIf(y.IfaceIn, y.V6())
		if err != nil {
			return 1
		}
		if ydst != ifIP && !strings.Contains(ydst, "/") {
			return 1
		}
		if ydst != ifIP && strings.Contains(ydst, "/") &&
			x.V6() == y.V6() && !inNetwork(ifIP, ydst) {
			return 1
		}
	}
	if x.V6() != y.V6() {
		return 1
	}
	return -1
}

func isAnywhere(addr string) bool {
	return addr == "::/0" || addr == "0.0.0.0/0"
}

// matchPorts reports whether every test port is covered by the rule's
// port list (ufw _match_ports).
func matchPorts(test, against []rule.PortRange) bool {
	if len(test) == 0 {
		return true
	}
	for _, tp := range test {
		ok := false
		for _, ap := range against {
			if tp.Lo >= ap.Lo && tp.Hi <= ap.Hi {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// inNetwork reports whether addr (ip or cidr) is contained in cidr.
func inNetwork(addr, cidr string) bool {
	ip := net.ParseIP(strings.SplitN(addr, "/", 2)[0])
	_, n, err := net.ParseCIDR(cidr)
	if ip == nil || err != nil {
		return false
	}
	return n.Contains(ip)
}

// getIPFromIf returns the first address of iface for the family.
func getIPFromIf(name string, v6 bool) (string, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return "", err
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return "", err
	}
	for _, a := range addrs {
		ip, _, err := net.ParseCIDR(a.String())
		if err != nil {
			continue
		}
		if (ip.To4() == nil) == v6 {
			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("no address for %s", name)
}

// getIfFromIP returns the interface name owning addr, or "".
func getIfFromIP(addr string) string {
	target := net.ParseIP(strings.SplitN(addr, "/", 2)[0])
	if target == nil {
		return ""
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifi := range ifaces {
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ip, _, err := net.ParseCIDR(a.String())
			if err == nil && ip.Equal(target) {
				return ifi.Name
			}
		}
	}
	return ""
}
