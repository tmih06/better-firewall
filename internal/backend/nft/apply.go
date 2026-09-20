// apply.go implements the Backend interface: atomic single-batch apply,
// flush, loaded-check, and fragment application via nft(8).
package nft

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"

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
	conn, err := nftables.New(nftables.WithSockOptions(func(c *netlink.Conn) error {
		// Large batches (full ruleset replace) can overflow the default
		// netlink receive buffer while reading ACKs → ENOBUFS. Bump it.
		if err := c.SetReadBuffer(8 * 1024 * 1024); err != nil {
			return err
		}
		return c.SetWriteBuffer(8 * 1024 * 1024)
	}))
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
	if os.Getenv("BFW_DEBUG_DUMP") != "" {
		return b.debugDump(c)
	}
	if os.Getenv("BFW_DEBUG_APPLY") != "" {
		return b.debugApply(conn, c)
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

// debugApply flushes the batch in two stages to isolate which object
// fails: (1) tables+chains+sets, (2) rules incrementally. Enabled by
// BFW_DEBUG_APPLY=1.
func (b *be) debugApply(conn *nftables.Conn, c *compiled) error {
	for _, ch := range c.chains {
		conn.AddChain(ch)
	}
	for _, s := range c.sets {
		if err := conn.AddSet(s, c.elems[s]); err != nil {
			return fmt.Errorf("set %s: %w", s.Name, err)
		}
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("stage tables+chains+sets: %w", err)
	}
	fmt.Printf("stage1 OK: %d chains %d sets\n", len(c.chains), len(c.sets))
	for i, r := range c.rules {
		conn.AddRule(r)
		if err := conn.Flush(); err != nil {
			return fmt.Errorf("stage rule[%d] chain=%s: %w", i, r.Chain.Name, err)
		}
	}
	fmt.Printf("stage2 OK: %d rules\n", len(c.rules))
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

// debugDump prints every object in the batch (names + flags) without
// sending it. Enabled by BFW_DEBUG_DUMP=1.
func (b *be) debugDump(c *compiled) error {
	fmt.Printf("table: %s family=%d\n", c.table.Name, c.table.Family)
	for _, t := range c.natTables {
		fmt.Printf("nat table: %s family=%d\n", t.Name, t.Family)
	}
	seen := map[string]int{}
	for _, ch := range c.chains {
		k := ch.Name
		seen[k]++
		mark := ""
		if seen[k] > 1 {
			mark = "  <<DUP>>"
		}
		fmt.Printf("chain %q base=%v%s\n", ch.Name, ch.Hooknum != nil, mark)
	}
	for _, s := range c.sets {
		fmt.Printf("set %q anon=%v const=%v dyn=%v concat=%v id=%d elems=%d\n",
			s.Name, s.Anonymous, s.Constant, s.Dynamic, s.Concatenation, s.ID, len(c.elems[s]))
	}
	fmt.Printf("rules: %d\n", len(c.rules))
	return nil
}
