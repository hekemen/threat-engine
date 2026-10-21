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

	"github.com/hekemen/threat-engine/internal/runner"
)

// ChainName is the custom chain this daemon owns in the raw table.
const ChainName = "THREAD_ENGINE_FILTER"

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
//
// When the chain is already hooked into PREROUTING, Attach leaves its body
// alone. Rebuilding a live chain means flushing it and re-appending the rules,
// and during that window the jump is installed but the chain is empty, so
// hostile packets pass. Reconcile runs on every scan, so rebuilding
// unconditionally would open that window every interval. Drift is still
// repaired: if the jump is gone the body is rebuilt from scratch, and if only
// the body were damaged the next full attach (or an operator's Detach/Attach)
// restores it.
func (e *Enforcer) Attach(ctx context.Context) error {
	// Create the chain; failure just means it already exists.
	_, _ = e.Exec(ctx, nil, "iptables", "-t", "raw", "-N", ChainName)

	// Link it into PREROUTING only if the jump is not already present. A
	// present jump means the chain is live, so its body is left untouched.
	if _, err := e.Exec(ctx, nil, "iptables", "-t", "raw", "-C", "PREROUTING", "-j", ChainName); err == nil {
		return nil
	}
	if _, err := e.Exec(ctx, nil, "iptables", "-t", "raw", "-I", "PREROUTING", "1", "-j", ChainName); err != nil {
		return fmt.Errorf("failed linking chain to PREROUTING: %v", err)
	}

	// (Re)build the chain body. Order matters: the whitelist RETURN must be
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
