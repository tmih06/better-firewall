// Package backend defines the interface between the firewall model and the
// kernel ruleset. The nftables implementation lives in backend/nft.
package backend

import (
	"github.com/google/nftables"

	"github.com/tmih06/better-firewall/internal/store"
)

// Backend applies the compiled ruleset to the kernel and reads it back.
type Backend interface {
	// Apply atomically replaces the managed tables with the compiled
	// ruleset for st. Exactly one netlink batch; never partial.
	Apply(st *store.State, etc map[string]string) error
	// Flush removes all managed tables (disable path).
	Flush() error
	// Loaded reports whether the managed table exists in the kernel.
	Loaded() (bool, error)
	// ReadBack returns the live ruleset objects for reports/diff.
	ReadBack() (*Snapshot, error)
	// ApplyFragments applies a before/after nft fragment in a second
	// transaction (post-core-apply; not atomic with core).
	ApplyFragments(path string) error
}

// Snapshot is the live kernel state relevant to better-firewall.
type Snapshot struct {
	Tables []*nftables.Table
	Chains []*nftables.Chain
	Rules  []*nftables.Rule
	Sets   []*nftables.Set
	Elems  map[*nftables.Set][]nftables.SetElement
}

// ForeignChains returns names of chains in the live ruleset belonging to
// another firewall manager (e.g. ufw-*) — used by check/import-ufw.
func (s *Snapshot) ForeignChains(prefix string) []string {
	var out []string
	for _, c := range s.Chains {
		if len(c.Name) >= len(prefix) && c.Name[:len(prefix)] == prefix {
			out = append(out, c.Name)
		}
	}
	return out
}
