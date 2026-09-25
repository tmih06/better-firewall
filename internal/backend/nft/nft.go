// Package nft implements backend.Backend over nftables netlink via
// github.com/google/nftables. The managed tables are `inet better-firewall`
// (filter) plus `ip better-firewall-nat` / `ip6 better-firewall-nat` (created only when
// NAT rules exist). Apply is a single netlink batch = atomic replace.
package nft

import (
	"github.com/tmih06/better-firewall/internal/backend"
)

// TableName is the managed inet table.
const TableName = "better-firewall"

// NATTableName is the managed nat table (per-family: ip/ip6).
const NATTableName = "better-firewall-nat"

// New returns a Backend bound to a fresh netlink connection.
func New() (backend.Backend, error) {
	return &be{}, nil
}

type be struct{}

var _ backend.Backend = (*be)(nil)
