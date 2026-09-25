//go:build integration

package nft

import (
	"os"
	"testing"
)

// TestApplySmoke exercises the real netlink path; requires root (CAP_NET_ADMIN)
// within an isolated network namespace (BFW_ISOLATED=1 and net ns identity difference).
// Protected by the 'integration' build tag and fail-closed isolation checks so that
// running `sudo go test ./...` on a host can never mutate host firewall rules.
func TestApplySmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	if os.Geteuid() != 0 {
		t.Skip("root required (CAP_NET_ADMIN)")
	}
	if os.Getenv("BFW_ISOLATED") != "1" {
		t.Skip("requires BFW_ISOLATED=1 isolation wrapper")
	}
	origNet := os.Getenv("BFW_ORIGINAL_NET_NS")
	if origNet == "" {
		t.Skip("requires BFW_ORIGINAL_NET_NS attestation")
	}
	selfNet, err := os.Readlink("/proc/self/ns/net")
	if err != nil || selfNet == "" || selfNet == origNet {
		t.Skip("requires separate network namespace; host network namespace detected")
	}
	// Kernel-state cross-check against PID 1's network namespace.
	// The env vars above are forgeable attestation: a caller can set
	// BFW_ISOLATED=1 plus a fabricated BFW_ORIGINAL_NET_NS and the checks
	// above would pass on the host. isolate.sh uses `unshare --pid --fork`
	// WITHOUT --mount-proc, so /proc still describes the outer PID
	// namespace: /proc/1 is the host init and /proc/1/ns/net is the host
	// network namespace. Unreadable or equal to self means we cannot prove
	// isolation, so skip before any Apply can touch host firewall state.
	pid1Net, err := os.Readlink("/proc/1/ns/net")
	if err != nil || pid1Net == "" || pid1Net == selfNet {
		t.Skip("requires /proc/1/ns/net to differ from self net ns; unisolated host execution refused")
	}

	b, err := New()
	if err != nil {
		t.Fatal(err)
	}
	st := fixtureState()
	if err := b.Apply(st, nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	loaded, err := b.Loaded()
	if err != nil || !loaded {
		t.Fatalf("Loaded: %v %v", loaded, err)
	}
	if err := b.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
}
