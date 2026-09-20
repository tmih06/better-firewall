package cli

import (
	"testing"
)

func parse(t *testing.T, args ...string) *ParsedRuleOp {
	t.Helper()
	op, err := parseRuleArgs(args)
	if err != nil {
		t.Fatalf("parse %v: %v", args, err)
	}
	return op
}

func parseErr(t *testing.T, args ...string) error {
	t.Helper()
	_, err := parseRuleArgs(args)
	if err == nil {
		t.Fatalf("parse %v: expected error", args)
	}
	return err
}

func TestSimplePort(t *testing.T) {
	op := parse(t, "allow", "53")
	if op.Action != "allow" || op.IPType != "both" {
		t.Fatalf("got %+v", op)
	}
	if len(op.Rule.Dst.Ports) != 1 || op.Rule.Dst.Ports[0].Lo != 53 {
		t.Fatalf("ports: %+v", op.Rule.Dst.Ports)
	}
	if op.Rule.Proto != "any" {
		t.Fatalf("proto: %q", op.Rule.Proto)
	}
}

func TestSimplePortProto(t *testing.T) {
	op := parse(t, "allow", "25/tcp")
	if op.Rule.Proto != "tcp" || op.Rule.Dst.Ports[0].Lo != 25 {
		t.Fatalf("got %+v", op.Rule)
	}
}

func TestServiceName(t *testing.T) {
	op := parse(t, "allow", "smtp")
	if op.Rule.Dst.Ports[0].Lo != 25 {
		t.Fatalf("smtp → %+v", op.Rule.Dst.Ports)
	}
}

func TestDirection(t *testing.T) {
	op := parse(t, "reject", "out", "smtp")
	if op.Rule.Direction != "out" {
		t.Fatalf("dir: %q", op.Rule.Direction)
	}
	op = parse(t, "allow", "in", "http")
	if op.Rule.Direction != "in" || op.Rule.Dst.Ports[0].Lo != 80 {
		t.Fatalf("got %+v", op.Rule)
	}
}

func TestExtended(t *testing.T) {
	op := parse(t, "deny", "proto", "tcp", "to", "any", "port", "80")
	if op.Rule.Proto != "tcp" || op.Rule.Dst.Ports[0].Lo != 80 || !op.Rule.Dst.Any() {
		t.Fatalf("got %+v", op.Rule)
	}
	op = parse(t, "deny", "proto", "tcp", "from", "10.0.0.0/8", "to", "192.168.0.1", "port", "25")
	if op.Rule.Src.IP != "10.0.0.0/8" || op.Rule.Dst.IP != "192.168.0.1" || op.Rule.Dst.Ports[0].Lo != 25 {
		t.Fatalf("got %+v", op.Rule)
	}
	if op.IPType != "v4" {
		t.Fatalf("iptype: %q", op.IPType)
	}
}

func TestIPv6(t *testing.T) {
	op := parse(t, "deny", "proto", "tcp", "from", "2001:db8::/32", "to", "any", "port", "25")
	if op.IPType != "v6" {
		t.Fatalf("iptype: %q", op.IPType)
	}
}

func TestInterface(t *testing.T) {
	op := parse(t, "deny", "in", "on", "eth0", "to", "224.0.0.1", "proto", "igmp")
	if op.Rule.IfaceIn != "eth0" || op.Rule.Proto != "igmp" {
		t.Fatalf("got %+v", op.Rule)
	}
	op = parse(t, "allow", "in", "on", "eth0", "to", "192.168.0.1", "proto", "gre")
	if op.Rule.Proto != "gre" || op.Rule.IfaceIn != "eth0" {
		t.Fatalf("got %+v", op.Rule)
	}
}

func TestMultiport(t *testing.T) {
	op := parse(t, "allow", "proto", "tcp", "from", "any", "to", "any", "port", "80,443,8080:8090", "comment", "web app")
	if len(op.Rule.Dst.Ports) != 3 {
		t.Fatalf("ports: %+v", op.Rule.Dst.Ports)
	}
	if op.Rule.Dst.Ports[2].Lo != 8080 || op.Rule.Dst.Ports[2].Hi != 8090 {
		t.Fatalf("range: %+v", op.Rule.Dst.Ports[2])
	}
	if op.Rule.Comment != "web app" {
		t.Fatalf("comment: %q", op.Rule.Comment)
	}
}

func TestRoute(t *testing.T) {
	op := parse(t, "route", "allow", "in", "on", "eth1", "out", "on", "eth2")
	if !op.Routed || op.Rule.Direction != "routed" || op.Rule.IfaceIn != "eth1" || op.Rule.IfaceOut != "eth2" {
		t.Fatalf("got %+v", op)
	}
	op = parse(t, "route", "allow", "in", "on", "eth0", "out", "on", "eth1", "to", "12.34.45.67", "port", "80", "proto", "tcp")
	if op.Rule.Dst.IP != "12.34.45.67" || op.Rule.Dst.Ports[0].Lo != 80 {
		t.Fatalf("got %+v", op.Rule)
	}
}

func TestLimit(t *testing.T) {
	op := parse(t, "limit", "ssh/tcp")
	if op.Action != "limit" || op.Rule.Dst.Ports[0].Lo != 22 {
		t.Fatalf("got %+v", op.Rule)
	}
}

func TestInsertPrependDelete(t *testing.T) {
	op := parse(t, "insert", "3", "deny", "to", "any", "port", "22", "from", "10.0.0.135", "proto", "tcp")
	if op.Kind != OpInsert || op.Num != 3 || op.Rule.Src.IP != "10.0.0.135" {
		t.Fatalf("got %+v", op)
	}
	op = parse(t, "prepend", "deny", "from", "1.2.3.4")
	if op.Kind != OpPrepend || op.Rule.Src.IP != "1.2.3.4" {
		t.Fatalf("got %+v", op)
	}
	op = parse(t, "delete", "deny", "80/tcp")
	if op.Kind != OpDelete || op.Action != "deny" || op.Rule.Dst.Ports[0].Lo != 80 {
		t.Fatalf("got %+v", op)
	}
	op = parse(t, "delete", "3")
	if op.Kind != OpDelete || op.Num != 3 || op.Rule != nil {
		t.Fatalf("got %+v", op)
	}
}

func TestLog(t *testing.T) {
	op := parse(t, "allow", "log", "22/tcp")
	if op.Rule.Log != "log" {
		t.Fatalf("log: %q", op.Rule.Log)
	}
	op = parse(t, "allow", "log-all", "22/tcp")
	if op.Rule.Log != "log-all" {
		t.Fatalf("log: %q", op.Rule.Log)
	}
}

func TestProtoRestrictions(t *testing.T) {
	for _, p := range []string{"esp", "ah", "vrrp", "gre"} {
		op := parse(t, "allow", "to", "10.0.0.1", "proto", p)
		if op.Rule.Proto != p {
			t.Fatalf("proto %s: %+v", p, op.Rule)
		}
	}
	parseErr(t, "allow", "to", "10.0.0.1", "proto", "esp", "port", "80")
}

func TestErrors(t *testing.T) {
	parseErr(t, "insert", "0", "deny", "80/tcp")
	parseErr(t, "allow", "badportname123")
	parseErr(t, "allow", "80:80/tcp")
	parseErr(t, "allow", "proto", "tcp", "to", "any", "port", "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16")
}

func TestExpires(t *testing.T) {
	op := parse(t, "allow", "22/tcp", "expires", "30m")
	if op.Rule.ExpiresAt == 0 {
		t.Fatalf("expires not set: %+v", op.Rule)
	}
}

func TestSetRef(t *testing.T) {
	op := parse(t, "deny", "from", "set", "badguys")
	if op.Rule.Src.Set != "badguys" {
		t.Fatalf("set: %+v", op.Rule.Src)
	}
}

func TestAppProfile(t *testing.T) {
	op := parse(t, "allow", "OpenSSH")
	if op.Rule.Dapp == "" && len(op.Rule.Dst.Ports) == 0 {
		t.Fatalf("app rule: %+v", op.Rule)
	}
}
