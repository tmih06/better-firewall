// apply.go implements the Backend interface: atomic single-batch apply,
// flush, loaded-check, and fragment application via nft(8).
package nft

import (
	"fmt"
	"os/exec"

	"github.com/google/nftables"

	"bfirewall/internal/store"
)

// Apply atomically replaces the managed tables with the compiled ruleset:
// one netlink batch containing DelTable (for each managed table that
// exists) + AddTable + chains + sets + elements + rules, committed by a
// single Flush(). Never partial.
func (b *be) Apply(st *store.State, etc map[string]string) error {
	c, err := compile(st, etc)
	if err != nil {
		return err
	}
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("netlink: %w", err)
	}

	// Delete only managed tables that currently exist; DelTable on a
	// missing table would fail the whole batch.
	existing, err := conn.ListTables()
	if err != nil {
		return fmt.Errorf("netlink list tables: %w", err)
	}
	managed := map[*nftables.Table]bool{c.table: true}
	for _, t := range c.natTables {
		managed[t] = true
	}
	for _, t := range existing {
		for m := range managed {
			if t.Name == m.Name && t.Family == m.Family {
				conn.DelTable(t)
			}
		}
	}

	conn.AddTable(c.table)
	for _, t := range c.natTables {
		conn.AddTable(t)
	}
	for _, ch := range c.chains {
		conn.AddChain(ch)
	}
	for _, s := range c.sets {
		if err := conn.AddSet(s, c.elems[s]); err != nil {
			return fmt.Errorf("set %s: %w", s.Name, err)
		}
	}
	for _, r := range c.rules {
		conn.AddRule(r)
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("apply ruleset: %w", err)
	}
	return nil
}

// Flush removes all managed tables (disable path). Missing tables are
// skipped so Flush is idempotent.
func (b *be) Flush() error {
	conn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("netlink: %w", err)
	}
	existing, err := conn.ListTables()
	if err != nil {
		return fmt.Errorf("netlink list tables: %w", err)
	}
	n := 0
	for _, t := range existing {
		if t.Name == TableName || t.Name == NATTableName {
			conn.DelTable(t)
			n++
		}
	}
	if n == 0 {
		return nil
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("flush ruleset: %w", err)
	}
	return nil
}

// Loaded reports whether the managed inet table exists in the kernel.
func (b *be) Loaded() (bool, error) {
	conn, err := nftables.New()
	if err != nil {
		return false, fmt.Errorf("netlink: %w", err)
	}
	t, err := conn.ListTableOfFamily(TableName, nftables.TableFamilyINet)
	if err != nil {
		return false, nil // ENOENT-style failure = not loaded
	}
	return t != nil, nil
}

// ApplyFragments applies a before/after nft fragment in a second
// transaction (post-core-apply; not atomic with core). The fragment is
// validated with `nft -c` first; this is the only shell-out in the
// backend, per design.
func (b *be) ApplyFragments(path string) error {
	if out, err := exec.Command("nft", "-c", "-f", path).CombinedOutput(); err != nil {
		return fmt.Errorf("fragment %s failed check: %v: %s", path, err, out)
	}
	if out, err := exec.Command("nft", "-f", path).CombinedOutput(); err != nil {
		return fmt.Errorf("fragment %s failed apply: %v: %s", path, err, out)
	}
	return nil
}
