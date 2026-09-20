// Package report implements `bfw show listening`: parse /proc/net
// sockets and map them back to owning processes.
package report

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Listener is one listening socket with its owning process (when known).
type Listener struct {
	Proto string // tcp|tcp6|udp|udp6
	Addr  string // local address, "*" for wildcard
	Port  int
	Exe   string // basename of /proc/<pid>/exe, "" when unknown
}

// Listening returns all listening TCP (state 0A) and UDP (state 07)
// sockets from /proc/net/{tcp,tcp6,udp,udp6}, resolving each socket's
// inode to a process via /proc/<pid>/fd symlinks.
func Listening() ([]Listener, error) {
	owner := inodeOwners()
	var out []Listener
	for _, f := range []struct {
		path, proto, state string
	}{
		{"/proc/net/tcp", "tcp", "0A"},
		{"/proc/net/tcp6", "tcp6", "0A"},
		{"/proc/net/udp", "udp", "07"},
		{"/proc/net/udp6", "udp6", "07"},
	} {
		ls, err := parseProcNet(f.path, f.proto, f.state, owner)
		if err != nil {
			if os.IsNotExist(err) {
				continue // e.g. no ipv6
			}
			return nil, err
		}
		out = append(out, ls...)
	}
	return out, nil
}

// inodeOwners maps socket inode → exe basename by scanning /proc/<pid>/fd.
// Entries we cannot read (other users' processes) are skipped.
func inodeOwners() map[string]string {
	owners := map[string]string{}
	pids, err := filepath.Glob("/proc/[0-9]*/fd")
	if err != nil {
		return owners
	}
	for _, fdDir := range pids {
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		var exe string
		exeSet := false
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			inode, ok := strings.CutPrefix(link, "socket:[")
			if !ok {
				continue
			}
			inode = strings.TrimSuffix(inode, "]")
			if _, seen := owners[inode]; seen {
				continue
			}
			if !exeSet {
				pid := filepath.Base(filepath.Dir(fdDir))
				if target, err := os.Readlink(filepath.Join("/proc", pid, "exe")); err == nil {
					exe = filepath.Base(target)
				}
				exeSet = true
			}
			owners[inode] = exe
		}
	}
	return owners
}

// parseProcNet parses one /proc/net/<proto> file, keeping rows whose st
// column equals state.
func parseProcNet(path, proto, state string, owner map[string]string) ([]Listener, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Listener
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if first {
			first = false
			continue // header
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		if fields[3] != state {
			continue
		}
		hostHex, portHex, ok := strings.Cut(fields[1], ":")
		if !ok {
			continue
		}
		port, err := strconv.ParseUint(portHex, 16, 16)
		if err != nil {
			continue
		}
		addr := decodeAddr(hostHex, strings.HasSuffix(proto, "6"))
		l := Listener{Proto: proto, Addr: addr, Port: int(port)}
		if exe, ok := owner[fields[9]]; ok {
			l.Exe = exe
		}
		out = append(out, l)
	}
	return out, sc.Err()
}

// decodeAddr converts the /proc/net hex address to a display string.
// IPv4 is a single little-endian u32; IPv6 is four little-endian u32
// words (each word byte-reversed, words in order).
func decodeAddr(hexStr string, v6 bool) string {
	raw, err := hexDecode(hexStr)
	if err != nil {
		return "*"
	}
	if !v6 {
		if len(raw) != 4 {
			return "*"
		}
		ip := net.IPv4(raw[3], raw[2], raw[1], raw[0])
		if ip.IsUnspecified() {
			return "*"
		}
		return ip.String()
	}
	if len(raw) != 16 {
		return "*"
	}
	ip := make(net.IP, 16)
	for w := 0; w < 4; w++ {
		ip[w*4+0] = raw[w*4+3]
		ip[w*4+1] = raw[w*4+2]
		ip[w*4+2] = raw[w*4+1]
		ip[w*4+3] = raw[w*4+0]
	}
	if ip.IsUnspecified() {
		return "*"
	}
	return ip.String()
}

func hexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd hex length")
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		v, err := strconv.ParseUint(s[i*2:i*2+2], 16, 8)
		if err != nil {
			return nil, err
		}
		out[i] = byte(v)
	}
	return out, nil
}
