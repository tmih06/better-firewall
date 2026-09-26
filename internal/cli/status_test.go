package cli

import (
	"fmt"
	"strings"
	"testing"

	"github.com/tmih06/better-firewall/internal/rule"
	"github.com/tmih06/better-firewall/internal/store"
)

func ports(p uint16, proto string) rule.PortRange {
	return rule.PortRange{Lo: p, Hi: p, Proto: proto}
}

// Golden status lines from the plan fixtures (ufw 0.36.2 output).
func TestStatusLinesGolden(t *testing.T) {
	st := store.Defaults()
	r4 := mkExtRule("allow", "in", "any", "any", "any", ports(53, "any"))
	r6 := r4.Clone()
	st.Rules4 = []rule.Rule{*r4}
	st.Rules6 = []rule.Rule{*r6}
	markFamilies(st)

	got := strings.Join(StatusLines(st, false, false), "\n")
	want := "Status: active\n\n" +
		"To                         Action      From\n" +
		"--                         ------      ----\n" +
		"53                         ALLOW       Anywhere                  \n" +
		"53 (v6)                    ALLOW       Anywhere (v6)             "
	if got != want {
		t.Errorf("status plain:\n got: %q\nwant: %q", got, want)
	}
}

func TestStatusNumbered(t *testing.T) {
	st := store.Defaults()
	r := mkExtRule("deny", "in", "tcp", "10.0.0.0/8", "192.168.0.1", ports(25, "tcp"))
	st.Rules4 = []rule.Rule{*r}
	markFamilies(st)

	got := strings.Join(StatusLines(st, true, false), "\n")
	want := "Status: active\n\n" +
		"     To                         Action      From\n" +
		"     --                         ------      ----\n" +
		"[ 1] 192.168.0.1 25/tcp         DENY IN     10.0.0.0/8                "
	if got != want {
		t.Errorf("status numbered:\n got: %q\nwant: %q", got, want)
	}
}

func TestStatusLineFormattingMatchesFmt(t *testing.T) {
	cases := []struct {
		name                    string
		to, action, from, attrs string
		suffix                  string
	}{
		{name: "empty", to: "", action: "", from: "", attrs: "", suffix: ""},
		{name: "ordinary", to: "80/tcp", action: "ALLOW IN", from: "Anywhere", attrs: " (log)", suffix: " # web"},
		{name: "unicode", to: "界", action: "拒否", from: "источник", attrs: "", suffix: ""},
		{name: "invalid utf8", to: string([]byte{0xff, 'x'}), action: "ALLOW", from: "", attrs: "", suffix: ""},
		{name: "wide", to: strings.Repeat("x", 30), action: "ALLOW", from: strings.Repeat("y", 31), attrs: "", suffix: " (disabled)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := fmt.Sprintf("%-26s %-12s%-26s%s%s", tc.to, tc.action, tc.from, tc.attrs, tc.suffix)
			if got := statusLine(tc.to, tc.action, tc.from, tc.attrs, tc.suffix); got != want {
				t.Errorf("statusLine = %q, want %q", got, want)
			}
		})
	}
	for _, number := range []int{1, 9, 10, 99, 100, 1000} {
		want := fmt.Sprintf("[%2d] %-26s %-12s%-26s%s%s", number, "80/tcp", "ALLOW IN", "Anywhere", "", "")
		if got := numberedStatusLine(number, "80/tcp", "ALLOW IN", "Anywhere", "", ""); got != want {
			t.Errorf("number %d: numberedStatusLine = %q, want %q", number, got, want)
		}
	}
}

func TestPortStrFormatting(t *testing.T) {
	cases := []struct {
		name  string
		ports []rule.PortRange
		want  string
	}{
		{name: "any", want: "any"},
		{name: "single", ports: []rule.PortRange{{Lo: 22, Hi: 22}}, want: "22"},
		{name: "range", ports: []rule.PortRange{{Lo: 8080, Hi: 8090}}, want: "8080:8090"},
		{name: "mixed", ports: []rule.PortRange{{Lo: 80, Hi: 80}, {Lo: 443, Hi: 443}, {Lo: 1000, Hi: 1002}}, want: "80,443,1000:1002"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := portStr(tc.ports); got != tc.want {
				t.Errorf("portStr = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestStatusVerboseAction(t *testing.T) {
	st := store.Defaults()
	st.Logging = "low"
	st.Rules4 = []rule.Rule{*mkExtRule("allow", "in", "tcp", "any", "any", ports(80, "tcp"))}
	markFamilies(st)

	got := strings.Join(StatusLines(st, false, true), "\n")
	if !strings.Contains(got, "ALLOW IN") {
		t.Errorf("verbose should suffix direction: %q", got)
	}
	if !strings.Contains(got, "Logging: on (low)") {
		t.Errorf("missing logging line: %q", got)
	}
	if !strings.Contains(got, "New profiles: skip") {
		t.Errorf("missing profiles line: %q", got)
	}
}

func TestStatusAppRule(t *testing.T) {
	st := store.Defaults()
	r := mkExtRule("allow", "in", "tcp", "any", "any", ports(80, "tcp"))
	r.Dapp = "Apache"
	st.Rules4 = []rule.Rule{*r}
	markFamilies(st)

	to, action, from, _ := RuleLine(&st.Rules4[0], true, false)
	if to != "80/tcp (Apache)" || strings.TrimSpace(action) != "ALLOW IN" || from != "Anywhere" {
		t.Errorf("verbose app rule = %q %q %q", to, action, from)
	}
	// Non-verbose collapses to the app name.
	to, _, _, _ = RuleLine(&st.Rules4[0], false, false)
	if to != "Apache" {
		t.Errorf("plain app rule To = %q, want Apache", to)
	}
}

func TestGetCommand(t *testing.T) {
	// Short form.
	r := mkExtRule("allow", "in", "tcp", "any", "any", ports(22, "tcp"))
	if got := GetCommand(r); got != "allow 22/tcp" {
		t.Errorf("short form = %q", got)
	}
	// proto any → no /proto suffix.
	r2 := mkExtRule("allow", "in", "any", "any", "any", ports(53, "any"))
	if got := GetCommand(r2); got != "allow 53" {
		t.Errorf("any proto = %q", got)
	}
	// Out rule short form.
	r3 := mkExtRule("allow", "out", "tcp", "any", "any", ports(25, "tcp"))
	if got := GetCommand(r3); got != "allow out 25/tcp" {
		t.Errorf("out short form = %q", got)
	}
	// Extended form.
	r4 := mkExtRule("deny", "in", "tcp", "10.0.0.0/8", "192.168.0.1", ports(25, "tcp"))
	if got := GetCommand(r4); got != "deny from 10.0.0.0/8 to 192.168.0.1 port 25 proto tcp" {
		t.Errorf("extended form = %q", got)
	}
	// Fully generic rule gets ' to any'.
	r5 := mkExtRule("allow", "in", "any", "any", "any")
	if got := GetCommand(r5); got != "allow to any" {
		t.Errorf("generic = %q", got)
	}
	// Route prefix (interfaces set → no ' to any').
	r6 := mkExtRule("allow", "routed", "any", "any", "any")
	r6.IfaceIn = "eth0"
	r6.IfaceOut = "eth1"
	if got := GetCommand(r6); got != "route allow in on eth0 out on eth1" {
		t.Errorf("route = %q", got)
	}
	r7 := mkExtRule("allow", "in", "icmpv6", "any", "any")
	r7.ICMPType = "135"
	if got := GetCommand(r7); got != "allow to any proto icmpv6 type 135" {
		t.Errorf("ICMP command = %q", got)
	}
	r7.SetV6(true)
	to, _, _, _ := RuleLine(r7, false, false)
	if !strings.Contains(to, "type 135") {
		t.Errorf("status omitted ICMP type: To=%q", to)
	}
}
