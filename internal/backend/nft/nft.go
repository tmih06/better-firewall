// Package nft implements backend.Backend over nftables netlink via
// github.com/google/nftables. The managed tables are `inet bfirewall`
// (filter) plus `ip bfirewall-nat` / `ip6 bfirewall-nat` (created only when
// NAT rules exist). Apply is a single netlink batch = atomic replace.
package nft

import (
	"bfirewall/internal/backend"
)

// TableName is the managed inet table.
const TableName = "bfirewall"

// NATTableName is the managed nat table (per-family: ip/ip6).
const NATTableName = "bfirewall-nat"

// New returns a Backend bound to a fresh netlink connection.
func New() (backend.Backend, error) {
	return &be{}, nil
}

type be struct{}

var _ backend.Backend = (*be)(nil)
