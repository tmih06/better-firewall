package sysstate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// procStat is the pure /proc parser behind UnderSSH; exercise it on our own
// process plus error paths. UnderSSH itself walks the real process tree —
// nothing here writes host or kernel state.

func TestProcStatSelf(t *testing.T) {
	comm, ppid, err := procStat(os.Getpid())
	if err != nil {
		t.Fatalf("procStat(self): %v", err)
	}
	if ppid != os.Getppid() {
		t.Errorf("ppid = %d, want %d", ppid, os.Getppid())
	}
	if !strings.HasPrefix(comm, "(") || !strings.HasSuffix(comm, ")") {
		t.Errorf("comm = %q, want parenthesized", comm)
	}
	if comm == "()" {
		t.Error("comm is empty")
	}
	// PID 1 exists on every Linux host; its ppid is 0.
	comm1, ppid1, err := procStat(1)
	if err != nil {
		t.Fatalf("procStat(1): %v", err)
	}
	if comm1 == "()" || ppid1 != 0 {
		t.Errorf("pid1 = %q ppid %d, want comm set and ppid 0", comm1, ppid1)
	}
}

func TestProcStatBadPID(t *testing.T) {
	for _, pid := range []int{-1, 1 << 30} {
		if _, _, err := procStat(pid); err == nil {
			t.Errorf("procStat(%d): got nil error", pid)
		}
	}
}

func TestUnderSSHReturnsBool(t *testing.T) {
	// Value depends on the caller's ancestry — only assert it terminates
	// and is stable between calls (ppid chain doesn't change mid-test).
	a, b := UnderSSH(), UnderSSH()
	if a != b {
		t.Errorf("UnderSSH unstable: %v then %v", a, b)
	}
}

func TestLockFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bfw.lock")

	f1, err := LockFile(path)
	if err != nil {
		t.Fatalf("LockFile: %v", err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("lock file mode = %v, err %v; want 0600", fi, err)
	}

	// Second non-blocking flock on a different open file description must
	// fail while f1 is held (flock is per-OFD, per-process holds don't
	// collapse it).
	f2, err := LockFile(path)
	if err == nil {
		f2.Close()
		t.Fatal("second LockFile succeeded while first lock held")
	}
	if !strings.Contains(err.Error(), "could not lock") {
		t.Errorf("lock error = %v, want 'could not lock' prefix", err)
	}

	// Releasing allows re-locking.
	if err := f1.Close(); err != nil {
		t.Fatal(err)
	}
	f3, err := LockFile(path)
	if err != nil {
		t.Fatalf("re-lock after release: %v", err)
	}
	f3.Close()
}

func TestLockFileUnwritablePath(t *testing.T) {
	if _, err := LockFile(filepath.Join(t.TempDir(), "no", "such", "dir", "lock")); err == nil {
		t.Fatal("LockFile in missing dir: got nil error")
	}
}

// ApplySysctlFile: only assert behavior that never reaches a real
// /proc/sys write — parsing errors, unsafe keys, and nonexistent keys all
// fail without mutating kernel state. On this design the target path is
// always /proc/sys/<key>, so fixtures use guaranteed-nonexistent keys.

func TestApplySysctlFileMissing(t *testing.T) {
	if err := ApplySysctlFile(filepath.Join(t.TempDir(), "nope.conf")); err == nil {
		t.Fatal("missing file: got nil error")
	}
}

func TestApplySysctlFileEmptyAndCommentsOnly(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sysctl.conf")
	if err := os.WriteFile(p, []byte("# shipped defaults\n\n   \n#net/ipv4/ip_forward=1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := ApplySysctlFile(p); err != nil {
		t.Fatalf("comment-only file: %v", err)
	}
}

func TestApplySysctlFileMalformed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sysctl.conf")
	if err := os.WriteFile(p, []byte("no equals sign here\n= novalue\nkey_only=\n"), 0644); err != nil {
		t.Fatal(err)
	}
	err := ApplySysctlFile(p)
	if err == nil {
		t.Fatal("malformed lines: got nil error")
	}
	if got := err.Error(); !strings.Contains(got, "malformed") {
		t.Errorf("err = %v, want 'malformed'", got)
	}
	// Three malformed lines → three joined errors.
	if n := strings.Count(err.Error(), "malformed"); n != 3 {
		t.Errorf("joined error count = %d, want 3 (%v)", n, err)
	}
}

func TestValidSysctlKey(t *testing.T) {
	valid := []string{
		"net.ipv4.ip_forward", "net/ipv4/ip_forward", "kernel.hostname",
		"net.ipv4.conf.all.forwarding", "vm.swappiness", "a-b_c",
	}
	for _, k := range valid {
		if !validSysctlKey(k) {
			t.Errorf("validSysctlKey(%q) = false, want true", k)
		}
	}
	unsafe := []string{
		"", "net/../x", "..x/y", "net..x", "net.ipv4..x",
		"/abs/key", ".net/x", "net.", "net/",
		// Adjacent separators: each rewrites to "net///x"-style paths
		// that filepath.Join would clean to the different key "net/x".
		"net/./x", "net//x", "net./x", "net/.x",
		"net ipv4.x", "net;rm", "net$(x)", "net`x`", "a|b", "a:b",
	}
	for _, k := range unsafe {
		if validSysctlKey(k) {
			t.Errorf("validSysctlKey(%q) = true, want false", k)
		}
	}
}

func TestApplySysctlFileUnsafeKeysRejected(t *testing.T) {
	for _, key := range []string{
		"../x=1", "net/../x=1", "..x/y=1", "net..x=1", "net.ipv4..x=1",
		"/abs/key=1", ".hidden/x=1", "net.ipv4.x;rm=1", "net $(x)=1",
		"a|b=1", "trail.=1",
		// Adjacent separators collapse through filepath.Join to "net/x".
		"net/./x=1", "net//x=1", "net./x=1", "net/.x=1",
	} {
		p := filepath.Join(t.TempDir(), "sysctl.conf")
		if err := os.WriteFile(p, []byte(key+"\n"), 0644); err != nil {
			t.Fatal(err)
		}
		err := ApplySysctlFile(p)
		if err == nil || !strings.Contains(err.Error(), "unsafe") {
			t.Errorf("key %q: err = %v, want 'unsafe'", key, err)
		}
	}
}

func TestApplySysctlFileMissingKeyReportsError(t *testing.T) {
	// A key that cannot exist under /proc/sys exercises the write-error
	// path without touching real tunables. Line 2 must also be attempted:
	// failures are joined, never short-circuit.
	p := filepath.Join(t.TempDir(), "sysctl.conf")
	if err := os.WriteFile(p, []byte("bfw.no_such_tunable_a = \"7\" # comment\nnet.ipv4.bfw_no_such_key=0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	err := ApplySysctlFile(p)
	if err == nil {
		t.Fatal("nonexistent keys: got nil error")
	}
	if !strings.Contains(err.Error(), "bfw.no_such_tunable_a") ||
		!strings.Contains(err.Error(), "net.ipv4.bfw_no_such_key") {
		t.Errorf("err = %v, want both keys reported (quotes/comments stripped)", err)
	}
}

func TestModprobeEmpty(t *testing.T) {
	// Empty and whitespace-only module lists must not invoke modprobe at
	// all — that would be a host kernel mutation.
	for _, in := range []string{"", "   ", "\t\n "} {
		if errs := Modprobe(in); len(errs) != 0 {
			t.Errorf("Modprobe(%q) = %v, want none", in, errs)
		}
	}
}

func TestReadSysctlFlag(t *testing.T) {
	dir := t.TempDir()
	if readSysctlFlag(filepath.Join(dir, "absent")) {
		t.Error("missing file reported enabled")
	}
	on := filepath.Join(dir, "on")
	if err := os.WriteFile(on, []byte("1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if !readSysctlFlag(on) {
		t.Error("'1\\n' not reported enabled")
	}
	for _, v := range []string{"0\n", "2", "1x", ""} {
		p := filepath.Join(dir, fmt.Sprintf("v%d", len(v))+".flag")
		if err := os.WriteFile(p, []byte(v), 0644); err != nil {
			t.Fatal(err)
		}
		if readSysctlFlag(p) {
			t.Errorf("value %q reported enabled", v)
		}
	}
}

func TestIPForwardEnabledMatchesKernelFiles(t *testing.T) {
	// Read-only: compare against the real sysctl files the function reads.
	// This pins the file→flag contract (TrimSpace == "1") on the live
	// kernel view rather than re-asserting an assumed value.
	v4, v6 := IPForwardEnabled()
	if want := strings.TrimSpace(readFile("/proc/sys/net/ipv4/ip_forward")) == "1"; v4 != want {
		t.Errorf("v4 = %v, want %v", v4, want)
	}
	all := strings.TrimSpace(readFile("/proc/sys/net/ipv6/conf/all/forwarding")) == "1"
	def := strings.TrimSpace(readFile("/proc/sys/net/ipv6/conf/default/forwarding")) == "1"
	if v6 != (all || def) {
		t.Errorf("v6 = %v, want %v (all=%v default=%v)", v6, all || def, all, def)
	}
}

func readFile(p string) string {
	b, _ := os.ReadFile(p)
	return string(b)
}
