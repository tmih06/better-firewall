// Package sysstate interfaces with kernel/system state: sysctl writes,
// module loading, ssh-session detection, and the mutating-command lock.
package sysstate

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// UnderSSH reports whether the current process descends from an sshd
// process, mirroring ufw's util.under_ssh: walk the ppid chain via
// /proc/<pid>/stat looking for comm "(sshd)".
func UnderSSH() bool {
	pid := os.Getpid()
	for depth := 0; depth < 64 && pid > 1; depth++ {
		comm, ppid, err := procStat(pid)
		if err != nil {
			return false
		}
		if comm == "(sshd)" {
			return true
		}
		pid = ppid
	}
	return false
}

// procStat returns the parenthesized comm and ppid from /proc/<pid>/stat.
// comm may itself contain spaces or parens, so split at the last ')'.
func procStat(pid int) (comm string, ppid int, err error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", 0, err
	}
	s := string(b)
	open := strings.IndexByte(s, '(')
	close := strings.LastIndexByte(s, ')')
	if open < 0 || close < 0 || close < open {
		return "", 0, fmt.Errorf("malformed stat for pid %d", pid)
	}
	comm = s[open : close+1]
	// Fields after ')' are: state ppid pgrp ...
	rest := strings.Fields(s[close+1:])
	if len(rest) < 2 {
		return "", 0, fmt.Errorf("malformed stat for pid %d", pid)
	}
	ppid, err = strconv.Atoi(rest[1])
	if err != nil {
		return "", 0, fmt.Errorf("bad ppid for pid %d: %w", pid, err)
	}
	return comm, ppid, nil
}

// ApplySysctlFile applies a sysctl.conf-style file by writing each
// "key=value" pair to /proc/sys/<key> where key may use '/' or '.'
// separators (ufw ships "net/ipv4/ip_forward=1"). Blank lines and '#'
// comments are skipped. All entries are attempted; failures are joined.
func ApplySysctlFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var errs []error
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			errs = append(errs, fmt.Errorf("sysctl: malformed line %q", line))
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		// Strip inline comment and surrounding quotes.
		if i := strings.IndexByte(val, '#'); i >= 0 {
			val = strings.TrimSpace(val[:i])
		}
		val = strings.Trim(val, `"'`)
		if key == "" || val == "" {
			errs = append(errs, fmt.Errorf("sysctl: malformed line %q", line))
			continue
		}
		// Validate the key BEFORE the dot→slash rewrite: after ReplaceAll
		// a ".." element is indistinguishable from a "net..x" collapse, and
		// "net/../x" would otherwise resolve to a different sysctl path.
		if !validSysctlKey(key) {
			errs = append(errs, fmt.Errorf("sysctl: unsafe key %q", key))
			continue
		}
		rel := strings.ReplaceAll(key, ".", "/")
		if strings.Contains(rel, "..") || strings.HasPrefix(rel, "/") {
			errs = append(errs, fmt.Errorf("sysctl: unsafe key %q", key))
			continue
		}
		target := filepath.Join("/proc/sys", rel)
		if err := os.WriteFile(target, []byte(val+"\n"), 0); err != nil {
			errs = append(errs, fmt.Errorf("sysctl %s: %w", key, err))
		}
	}
	return errors.Join(errs...)
}

// validSysctlKey reports whether key is safe to map under /proc/sys:
// a dot- or slash-separated path of [A-Za-z0-9_-] elements — no ".."
// traversal, no leading/trailing/adjacent separators, no whitespace or
// shell metachars. Rejects "net/../x" (resolves to /proc/sys/x) and
// "a..b", "net//x", "net/./x" (each gains an empty element after the
// dot→slash rewrite, which filepath.Join would clean to another key).
func validSysctlKey(key string) bool {
	if key == "" ||
		strings.HasPrefix(key, ".") || strings.HasPrefix(key, "/") ||
		strings.HasSuffix(key, ".") || strings.HasSuffix(key, "/") {
		return false
	}
	prevSep := false
	for _, c := range key {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '_' || c == '-':
			prevSep = false
		case c == '.' || c == '/':
			// Adjacent separators ("..", "//", "./", "/.") produce an
			// empty path element after the dot→slash rewrite.
			if prevSep {
				return false
			}
			prevSep = true
		default:
			return false
		}
	}
	return true
}

// Modprobe loads each space-separated module in modules, mirroring ufw's
// IPT_MODULES handling: failures are collected, never fatal.
func Modprobe(modules string) []error {
	var errs []error
	for _, m := range strings.Fields(modules) {
		if err := exec.Command("modprobe", m).Run(); err != nil {
			errs = append(errs, fmt.Errorf("modprobe %s: %w", m, err))
		}
	}
	return errs
}

// LockFile takes a non-blocking exclusive flock on path (creating the file
// if needed), mirroring ufw's /run/ufw.lock. The returned file must be
// closed by the caller to release the lock.
func LockFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("could not lock %s: %w", path, err)
	}
	return f, nil
}

// IPForwardEnabled reads the kernel forwarding sysctls. ufw ORs
// ip_forward, conf/default/forwarding, and conf/all/forwarding for v6.
func IPForwardEnabled() (v4, v6 bool) {
	v4 = readSysctlFlag("/proc/sys/net/ipv4/ip_forward")
	v6 = readSysctlFlag("/proc/sys/net/ipv6/conf/all/forwarding") ||
		readSysctlFlag("/proc/sys/net/ipv6/conf/default/forwarding")
	return v4, v6
}

func readSysctlFlag(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(b)) == "1"
}
