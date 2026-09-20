package nft

import (
	"os"
	"testing"
)

// TestApplySmoke exercises the real netlink path; requires root
// (CAP_NET_ADMIN). Skips otherwise — the integration suite under
// tests/ covers this as root.
func TestApplySmoke(t *testing.T) {
	if testing.Short() || os.Geteuid() != 0 {
		t.Skip("root smoke")
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
