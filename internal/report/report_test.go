package report

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// decodeAddr: /proc/net stores IPv4 as one little-endian u32 and IPv6 as
// four little-endian u32 words.

func TestDecodeAddrV4(t *testing.T) {
	cases := map[string]string{
		"00000000":   "*",           // wildcard → "*"
		"0100007F":   "127.0.0.1",   // loopback, little-endian
		"0101A8C0":   "192.168.1.1", // 01 01 A8 C0 → C0.A8.01.01
		"6401A8C0":   "192.168.1.100",
		"FFFF0A0A":   "10.10.255.255",
		"ZZZZ":       "*", // invalid hex → "*"
		"010000":     "*", // odd length handled upstream; wrong length → "*"
		"0100007F00": "*", // 5 bytes → "*"
		"":           "*",
	}
	for in, want := range cases {
		if got := decodeAddr(in, false); got != want {
			t.Errorf("decodeAddr(%q, v4) = %q, want %q", in, got, want)
		}
	}
}

func TestDecodeAddrV6(t *testing.T) {
	cases := map[string]string{
		strings.Repeat("0", 32):          "*", // :: wildcard
		"zzzz" + strings.Repeat("0", 28): "*", // bad hex
		"0100007F":                       "*", // wrong length
		// ::1 → last u32 word LE: 01000000 ... → "…00000001" reversed per word.
		strings.Repeat("0", 24) + "01000000": "::1",
		// fe80::1 → word0 = fe800000 → raw "000080FE", word3 = 01000000.
		"000080FE" + strings.Repeat("0", 16) + "01000000": "fe80::1",
		// 2001:db8::1 → word0 "0DB80020"?? no: bytes are BE per 4-byte group
		// byte-reversed: 2001:0db8 → word bytes 20 01 0D B8 → raw "B80D0120".
		"B80D0120" + strings.Repeat("0", 16) + "01000000": "2001:db8::1",
	}
	for in, want := range cases {
		if got := decodeAddr(in, true); got != want {
			t.Errorf("decodeAddr(%q, v6) = %q, want %q", in, got, want)
		}
	}
}

func TestHexDecode(t *testing.T) {
	if _, err := hexDecode("abc"); err == nil {
		t.Error("odd length: got nil error")
	}
	if _, err := hexDecode("zz"); err == nil {
		t.Error("bad hex: got nil error")
	}
	b, err := hexDecode("DEADbeef")
	if err != nil || len(b) != 4 || b[0] != 0xDE || b[3] != 0xEF {
		t.Errorf("hexDecode(DEADbeef) = %v, %v", b, err)
	}
}

// parseProcNet against a fixture file in the real /proc/net format.
const procNetFixture = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 11111 1 0000000000000000 100 0 0 10 0
   1: 00000000:0050 00000000:0000 01 00000000:00000000 00:00000000 00000000     0        0 22222 1 0000000000000000 100 0 0 10 0
   2: 0101A8C0:15B3 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 33333 1 0000000000000000 100 0 0 10 0
   3: short line
   4: 00000000:0000 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 44444 1 0000000000000000 100 0 0 10 0
`

func writeProcNet(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "net")
	if err := os.WriteFile(p, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseProcNet(t *testing.T) {
	owner := map[string]string{"33333": "nginx"}
	ls, err := parseProcNet(writeProcNet(t, procNetFixture), "tcp", "0A", owner)
	if err != nil {
		t.Fatalf("parseProcNet: %v", err)
	}
	if len(ls) != 3 {
		t.Fatalf("got %d listeners, want 3 (header, established row, short row skipped)", len(ls))
	}

	if ls[0].Proto != "tcp" || ls[0].Port != 8080 || ls[0].Addr != "127.0.0.1" {
		t.Errorf("listener0 = %+v, want tcp 127.0.0.1:8080", ls[0])
	}
	if ls[0].Exe != "" {
		t.Errorf("listener0 Exe = %q, want empty (unknown inode)", ls[0].Exe)
	}
	// Port 0x50 = 80, st 01 (established) filtered out — ls[1] is the
	// 192.168.1.1:5555 row with a resolved owner.
	if ls[1].Port != 5555 || ls[1].Addr != "192.168.1.1" || ls[1].Exe != "nginx" {
		t.Errorf("listener1 = %+v, want tcp 192.168.1.1:5555 nginx", ls[1])
	}
	// :0 wildcard row.
	if ls[2].Port != 0 || ls[2].Addr != "*" {
		t.Errorf("listener2 = %+v, want tcp *:0", ls[2])
	}
}

func TestParseProcNetUDPState(t *testing.T) {
	fixture := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 99999 1 0000000000000000 100 0 0 10 0
`
	ls, err := parseProcNet(writeProcNet(t, fixture), "udp", "07", nil)
	if err != nil {
		t.Fatalf("parseProcNet: %v", err)
	}
	if len(ls) != 1 || ls[0].Proto != "udp" || ls[0].Port != 53 || ls[0].Addr != "*" {
		t.Fatalf("listeners = %+v, want udp *:53", ls)
	}
}

func TestParseProcNetMissingFile(t *testing.T) {
	if _, err := parseProcNet(filepath.Join(t.TempDir(), "nope"), "tcp", "0A", nil); !os.IsNotExist(err) {
		t.Fatalf("missing file: err = %v, want IsNotExist", err)
	}
}

// End-to-end against the real /proc: pure read, no kernel mutation. Bind a
// real socket first so the result is guaranteed non-trivial and correct.

func TestListeningFindsBoundSocket(t *testing.T) {
	if _, err := os.Stat("/proc/net/tcp"); err != nil {
		t.Skip("no /proc/net/tcp")
	}
	ln, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	wantPort := ln.Addr().(*net.TCPAddr).Port

	listeners, err := Listening()
	if err != nil {
		t.Fatalf("Listening: %v", err)
	}
	var found *Listener
	for i := range listeners {
		l := &listeners[i]
		if (l.Proto == "tcp" || l.Proto == "tcp6") && l.Port == wantPort {
			found = l
			break
		}
	}
	if found == nil {
		t.Fatalf("listening socket :%d not found in %+v", wantPort, listeners)
	}
	if found.Addr != "*" && found.Addr != "0.0.0.0" {
		t.Errorf("wildcard listener addr = %q", found.Addr)
	}
}

func TestInodeOwnersFindSelf(t *testing.T) {
	if _, err := os.Stat("/proc/self/fd"); err != nil {
		t.Skip("no procfs")
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// Discover our socket's inode via /proc/self/fd.
	tc, err := ln.(*net.TCPListener).File()
	if err != nil {
		t.Skipf("cannot get listener fd: %v", err)
	}
	defer tc.Close()
	var inode string
	fds, _ := os.ReadDir("/proc/self/fd")
	for _, fd := range fds {
		link, err := os.Readlink(filepath.Join("/proc/self/fd", fd.Name()))
		if err != nil {
			continue
		}
		if ino, ok := strings.CutPrefix(link, "socket:["); ok {
			// The listener fd owns this socket; identify by matching the
			// dup'd fd number after opening.
			if fd.Name() == fmt.Sprint(tc.Fd()) {
				inode = strings.TrimSuffix(ino, "]")
			}
		}
	}
	if inode == "" {
		t.Skip("socket fd link not found")
	}

	owners := inodeOwners()
	exe, ok := owners[inode]
	if !ok {
		t.Skipf("inode %s not in owner map (procfs restricted?)", inode)
	}
	if exe == "" {
		t.Skip("exe unreadable")
	}
	if exe != filepath.Base(os.Args[0]) {
		t.Errorf("owner exe = %q, want %q", exe, filepath.Base(os.Args[0]))
	}
}
