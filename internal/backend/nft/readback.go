// readback.go implements Backend.ReadBack: live kernel ruleset objects for
// `show raw` and `bfw diff`.
package nft

import (
	"fmt"

	"github.com/google/nftables"

	"github.com/tmih06/better-firewall/internal/backend"
)

// ReadBack returns the live ruleset objects for the managed tables
// (inet better-firewall plus ip/ip6 better-firewall-nat when present). Tables and
// chains are returned unfiltered so foreign chains (e.g. ufw-*) remain
// visible to Snapshot.ForeignChains; rules and sets are limited to the
// managed tables.
func (b *be) ReadBack() (*backend.Snapshot, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("netlink: %w", err)
	}
	snap := &backend.Snapshot{Elems: map[*nftables.Set][]nftables.SetElement{}}

	tables, err := conn.ListTables()
	if err != nil {
		return nil, fmt.Errorf("netlink list tables: %w", err)
	}
	snap.Tables = tables

	managed := map[*nftables.Table]bool{}
	for _, t := range tables {
		if t.Name == TableName || t.Name == NATTableName {
			managed[t] = true
		}
	}

	chains, err := conn.ListChains()
	if err != nil {
		return nil, fmt.Errorf("netlink list chains: %w", err)
	}
	snap.Chains = chains

	for _, ch := range chains {
		if ch.Table == nil || !managed[ch.Table] {
			continue
		}
		rules, err := conn.GetRules(ch.Table, ch)
		if err != nil {
			return nil, fmt.Errorf("netlink get rules %s: %w", ch.Name, err)
		}
		snap.Rules = append(snap.Rules, rules...)
	}

	for t := range managed {
		sets, err := conn.GetSets(t)
		if err != nil {
			return nil, fmt.Errorf("netlink get sets: %w", err)
		}
		for _, s := range sets {
			snap.Sets = append(snap.Sets, s)
			elems, err := conn.GetSetElements(s)
			if err != nil {
				return nil, fmt.Errorf("netlink get set elements %s: %w", s.Name, err)
			}
			snap.Elems[s] = elems
		}
	}
	return snap, nil
}
