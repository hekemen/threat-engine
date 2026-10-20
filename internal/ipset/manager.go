// Package ipset owns the kernel hash tables that hold blocked and allowed
// addresses.
//
// Updates are atomic: entries are loaded into a "_tmp" buffer set, then
// swapped into the live set in a single operation. A live set is never
// flushed, so packets are never evaluated against a partially-populated
// table (see AGENTS.md rule 2).
package ipset

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"

	"github.com/hekemen/thread-engine/internal/runner"
)

// Manager reconciles the host's ipset tables.
type Manager struct {
	HostileSetName   string
	WhitelistSetName string
	// Whitelist holds every prefix that must never be blocked.
	Whitelist []netip.Prefix
	// Exec runs external commands; inject a fake in tests.
	Exec runner.Runner
}

// Sync replaces the contents of both sets with the given hostile entries plus
// the configured whitelist, using a single `ipset restore` transaction.
func (m *Manager) Sync(ctx context.Context, entries []string) error {
	var buf bytes.Buffer

	// 1. Production sets
	buf.WriteString(fmt.Sprintf("create %s hash:net maxelem 300000 -exist\n", m.HostileSetName))
	buf.WriteString(fmt.Sprintf("create %s hash:net maxelem 50000 -exist\n", m.WhitelistSetName))

	// 2. Refresh Whitelist
	tmpWhitelist := fmt.Sprintf("%s_tmp", m.WhitelistSetName)
	buf.WriteString(fmt.Sprintf("create %s hash:net maxelem 50000 -exist\n", tmpWhitelist))
	buf.WriteString(fmt.Sprintf("flush %s\n", tmpWhitelist))
	for _, p := range m.Whitelist {
		buf.WriteString(fmt.Sprintf("add %s %s -exist\n", tmpWhitelist, p.String()))
	}
	buf.WriteString(fmt.Sprintf("swap %s %s\n", tmpWhitelist, m.WhitelistSetName))
	buf.WriteString(fmt.Sprintf("destroy %s\n", tmpWhitelist))

	// 3. Atomically Swap Hostile Set
	tmpHostile := fmt.Sprintf("%s_tmp", m.HostileSetName)
	buf.WriteString(fmt.Sprintf("create %s hash:net maxelem 300000 -exist\n", tmpHostile))
	buf.WriteString(fmt.Sprintf("flush %s\n", tmpHostile))
	for _, entry := range entries {
		buf.WriteString(fmt.Sprintf("add %s %s -exist\n", tmpHostile, entry))
	}
	buf.WriteString(fmt.Sprintf("swap %s %s\n", tmpHostile, m.HostileSetName))
	buf.WriteString(fmt.Sprintf("destroy %s\n", tmpHostile))

	out, err := m.Exec(ctx, &buf, "ipset", "restore")
	if err != nil {
		return fmt.Errorf("ipset restore failed: %v: %s", err, out)
	}
	return nil
}

// Contains reports whether addr is a member of setName. It mirrors
// `ipset test` exit-code semantics: a clean exit means present.
func (m *Manager) Contains(ctx context.Context, setName string, addr netip.Addr) bool {
	_, err := m.Exec(ctx, nil, "ipset", "test", setName, addr.String())
	return err == nil
}
