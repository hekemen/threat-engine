// Package iptables installs the packet-drop rules.
//
// Rules live in the raw table's PREROUTING chain so they run before
// connection tracking and before K3s/Docker NAT. A rule in filter:INPUT would
// be bypassed entirely by ServiceLB and kube-proxy forwarding (see AGENTS.md
// rule 3).
package iptables

import (
	"context"
	"fmt"
	"strings"

	"github.com/hekemen/thread-engine/internal/runner"
)

// ChainName is the custom chain this daemon owns in the raw table.
const ChainName = "K3S_THREAT_FILTER"

// Enforcer reconciles the daemon's iptables chain.
type Enforcer struct {
	HostileSetName   string
	WhitelistSetName string
	// Exec runs external commands; inject a fake in tests.
	Exec runner.Runner
}

// Attach makes the raw-table chain match the desired state: it exists, is
// reachable from PREROUTING, whitelisted sources return early, and hostile
// sources are dropped. It is idempotent and safe to call on every reconcile.
func (e *Enforcer) Attach(ctx context.Context) error {
	// Create the chain; failure just means it already exists.
	_, _ = e.Exec(ctx, nil, "iptables", "-t", "raw", "-N", ChainName)

	// Link it into PREROUTING only if the jump is not already present.
	if _, err := e.Exec(ctx, nil, "iptables", "-t", "raw", "-C", "PREROUTING", "-j", ChainName); err != nil {
		if _, err := e.Exec(ctx, nil, "iptables", "-t", "raw", "-I", "PREROUTING", "1", "-j", ChainName); err != nil {
			return fmt.Errorf("failed linking chain to PREROUTING: %v", err)
		}
	}

	// Rebuild the chain body. Order matters: the whitelist RETURN must be
	// reachable before the hostile DROP.
	cmds := [][]string{
		{"-t", "raw", "-F", ChainName},
		{"-t", "raw", "-A", ChainName, "-m", "set", "--match-set", e.WhitelistSetName, "src", "-j", "RETURN"},
		{"-t", "raw", "-A", ChainName, "-m", "set", "--match-set", e.HostileSetName, "src", "-j", "DROP"},
	}

	for _, args := range cmds {
		if out, err := e.Exec(ctx, nil, "iptables", args...); err != nil {
			return fmt.Errorf("rule error [%s]: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	return nil
}

// IsAttached reports whether the chain is currently hooked into PREROUTING,
// using `iptables -C` exit-code semantics: a clean exit means attached.
func (e *Enforcer) IsAttached(ctx context.Context) bool {
	_, err := e.Exec(ctx, nil, "iptables", "-t", "raw", "-C", "PREROUTING", "-j", ChainName)
	return err == nil
}

// Detach removes the chain and its PREROUTING jump, returning the host's
// netfilter state to what it was before Attach. It never touches the ipset
// tables, which stay populated so /check and the blocklist metrics keep
// working while enforcement is off.
//
// An already-absent chain is success: the goal is a torn-down state, so
// Detach returns nil even when individual rules do not exist.
func (e *Enforcer) Detach(ctx context.Context) error {
	// Probe before deleting: `iptables -D` on a jump that is not present
	// would itself fail, so only delete what we know is there.
	if e.IsAttached(ctx) {
		if _, err := e.Exec(ctx, nil, "iptables", "-t", "raw", "-D", "PREROUTING", "-j", ChainName); err != nil {
			return fmt.Errorf("failed unlinking chain from PREROUTING: %v", err)
		}
	}

	// The chain can outlive its jump, so always attempt to flush and delete
	// it. Errors are ignored: the chain may legitimately not exist, and a
	// torn-down state is the goal either way.
	_, _ = e.Exec(ctx, nil, "iptables", "-t", "raw", "-F", ChainName)
	_, _ = e.Exec(ctx, nil, "iptables", "-t", "raw", "-X", ChainName)

	return nil
}
