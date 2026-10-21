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
	"log"
	"net/netip"
	"strings"

	"github.com/hekemen/threat-engine/internal/runner"
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
//
// Every set is created with `family inet`. Without an explicit family,
// `hash:net` silently defaults to IPv4, which is the same effective choice but
// fails at `add` time with an inscrutable "is out of range 0-32" error if an
// IPv6 member ever appears. Being explicit documents the constraint, and the
// IPv6 members are filtered here as well so a caller that forgets cannot take
// down the whole scan.
func (m *Manager) Sync(ctx context.Context, entries []string) error {
	var buf bytes.Buffer

	// 1. Production sets. The daemon enforces with IPv4 iptables only, so the
	// tables are IPv4-only by design; see the README on IPv6 scope.
	buf.WriteString(fmt.Sprintf("create %s hash:net family inet maxelem 300000 -exist\n", m.HostileSetName))
	buf.WriteString(fmt.Sprintf("create %s hash:net family inet maxelem 50000 -exist\n", m.WhitelistSetName))

	// 2. Refresh Whitelist
	tmpWhitelist := fmt.Sprintf("%s_tmp", m.WhitelistSetName)
	buf.WriteString(fmt.Sprintf("create %s hash:net family inet maxelem 50000 -exist\n", tmpWhitelist))
	buf.WriteString(fmt.Sprintf("flush %s\n", tmpWhitelist))
	for _, p := range m.Whitelist {
		if !p.Addr().Is4() {
			continue
		}
		buf.WriteString(fmt.Sprintf("add %s %s -exist\n", tmpWhitelist, p.String()))
	}
	buf.WriteString(fmt.Sprintf("swap %s %s\n", tmpWhitelist, m.WhitelistSetName))
	buf.WriteString(fmt.Sprintf("destroy %s\n", tmpWhitelist))

	// 3. Atomically Swap Hostile Set
	tmpHostile := fmt.Sprintf("%s_tmp", m.HostileSetName)
	buf.WriteString(fmt.Sprintf("create %s hash:net family inet maxelem 300000 -exist\n", tmpHostile))
	buf.WriteString(fmt.Sprintf("flush %s\n", tmpHostile))
	for _, entry := range entries {
		if !isIPv4Member(entry) {
			continue
		}
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

// EnsureSets creates both kernel sets if they are not already there, leaving
// their contents untouched. It exists because the enforcement rules reference
// these sets: `iptables -A ... --match-set threat_engine_hostile_ips` fails outright
// while the set is missing ("Set threat_engine_hostile_ips doesn't exist"), and on a
// cold start nothing has created them yet.
//
// Sync also creates them, but Sync runs behind the scan's change guard, so the
// engine cannot depend on it having run before it attaches. This is the
// cheap, idempotent way to state the prerequisite: `create ... -exist` is a
// no-op once the set exists, and it never flushes or swaps, so a populated set
// survives a restart untouched.
func (m *Manager) EnsureSets(ctx context.Context) error {
	var buf bytes.Buffer
	buf.WriteString(fmt.Sprintf("create %s hash:net family inet maxelem 300000 -exist\n", m.HostileSetName))
	buf.WriteString(fmt.Sprintf("create %s hash:net family inet maxelem 50000 -exist\n", m.WhitelistSetName))

	out, err := m.Exec(ctx, &buf, "ipset", "restore")
	if err != nil {
		return fmt.Errorf("ipset ensure failed: %v: %s", err, out)
	}
	return nil
}

// Destroy removes both kernel sets. It is the graceful-shutdown counterpart to
// Sync: stopping the daemon restores the host rather than leaving a frozen
// blocklist behind.
//
// An absent set is not an error, so a first-run shutdown, or a repeated one,
// still succeeds. A genuine failure (the set is still referenced by a rule)
// is reported so the operator learns the host was not fully restored.
func (m *Manager) Destroy(ctx context.Context) error {
	var firstErr error
	for _, name := range []string{m.HostileSetName, m.WhitelistSetName} {
		out, err := m.Exec(ctx, nil, "ipset", "destroy", name)
		if err != nil && !isAbsentSetError(out, err) {
			log.Printf("[Cleanup] failed to destroy ipset %s: %v: %s", name, err, out)
			if firstErr == nil {
				firstErr = fmt.Errorf("destroy %s: %v: %s", name, err, out)
			}
		}
	}
	return firstErr
}

// isAbsentSetError reports whether the failure is only "there is nothing to
// destroy". ipset writes that message on stdout/stderr and exits non-zero, so
// the text is the only signal available.
func isAbsentSetError(out string, err error) bool {
	text := strings.ToLower(out + " " + err.Error())
	return strings.Contains(text, "does not exist") || strings.Contains(text, "no such")
}

// isIPv4Member guards the kernel boundary: `ipset add` into a `family inet` set
// rejects any IPv6 member and aborts the entire restore transaction. An
// unparseable entry is also dropped rather than written, since it could only
// fail the same way.
func isIPv4Member(entry string) bool {
	if strings.Contains(entry, "/") {
		p, err := netip.ParsePrefix(entry)
		return err == nil && p.Addr().Is4() && !p.Addr().Is4In6()
	}
	a, err := netip.ParseAddr(entry)
	return err == nil && a.Is4() && !a.Is4In6()
}

// Contains reports whether addr is a member of setName. It mirrors
// `ipset test` exit-code semantics: a clean exit means present.
func (m *Manager) Contains(ctx context.Context, setName string, addr netip.Addr) bool {
	_, err := m.Exec(ctx, nil, "ipset", "test", setName, addr.String())
	return err == nil
}
