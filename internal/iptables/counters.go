package iptables

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// Counters holds the packet and byte counters of a single iptables rule.
type Counters struct {
	Packets uint64
	Bytes   uint64
}

// DropCounters reads the kernel's per-rule counters for the chain's hostile
// DROP rule and its whitelist RETURN rule.
//
// The counters come from `iptables -L -v -n -x`. The -x flag is mandatory:
// without it iptables abbreviates large values ("1.2k") and the numbers cannot
// be parsed.
//
// A missing chain is not an error: it means enforcement is off, and the caller
// gets zeroed counters. Every other failure (no CAP_NET_ADMIN, a wedged
// kernel) is returned so the caller can log it and keep serving the last
// known totals.
func (e *Enforcer) DropCounters(ctx context.Context) (hostile, whitelist Counters, err error) {
	out, execErr := e.Exec(ctx, nil, "iptables", "-t", "raw", "-L", ChainName, "-v", "-n", "-x")
	if execErr != nil {
		if isAbsentChain(out) {
			return Counters{}, Counters{}, nil
		}
		return Counters{}, Counters{}, fmt.Errorf("failed listing chain %s: %v: %s", ChainName, execErr, out)
	}
	return parseChainCounters(out, e.HostileSetName, e.WhitelistSetName)
}

// isAbsentChain reports whether a failed listing was only "there is no such
// chain". iptables says so on stderr and exits non-zero, so the message is
// the only signal available.
func isAbsentChain(out string) bool {
	return strings.Contains(out, "No chain/target/match by that name")
}

// parseChainCounters extracts the per-rule counters from `iptables -L -v -n -x`
// output.
//
// Rules are matched by the trailing "match-set <name> src" suffix rather than
// by position, so a reordered chain cannot misattribute a counter.
func parseChainCounters(out, hostileSet, whitelistSet string) (hostile, whitelist Counters, err error) {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		// The chain header and the column header both fail this parse, so
		// they are skipped without a special case.
		pkts, perr := strconv.ParseUint(fields[0], 10, 64)
		if perr != nil {
			continue
		}
		bytes, berr := strconv.ParseUint(fields[1], 10, 64)
		if berr != nil {
			continue
		}
		c := Counters{Packets: pkts, Bytes: bytes}
		switch matchSetName(fields) {
		case hostileSet:
			hostile = c
		case whitelistSet:
			whitelist = c
		}
	}
	return hostile, whitelist, nil
}

// matchSetName returns the set name from a rule line ending in
// "match-set <name> src", or "" when the line is not a set match.
func matchSetName(fields []string) string {
	n := len(fields)
	if n < 3 {
		return ""
	}
	if fields[n-3] != "match-set" || fields[n-1] != "src" {
		return ""
	}
	return fields[n-2]
}
