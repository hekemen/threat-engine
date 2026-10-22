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

// maxUnlinkAttempts bounds the unlink loop. It exists so a jump that
// survives its own deletion cannot spin forever: the bound turns that into
// a reported failure instead of a hung scan.
const maxUnlinkAttempts = 16

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
// The order of operations is load-bearing. The chain body is built and
// verified BEFORE the PREROUTING jump is installed, and a chain whose body
// turns out to be damaged is unlinked before it is rebuilt.
//
// The reason is the one state this daemon must never be in: a chain that is
// reachable from PREROUTING but carries no rules. Under a default `policy
// ACCEPT` such a chain drops nothing, while the daemon reports enforcement as
// on — a silent fail-open that no metric would reveal. Linking first and
// filling afterwards produces exactly that state whenever a rule fails to
// install, which is not hypothetical: `iptables` refuses a `--match-set` rule
// outright while the referenced ipset does not exist yet.
//
// Building the body first makes the bad state unreachable. Until the jump is
// inserted nothing routes into the chain, so a rule that fails leaves an
// unreachable — and therefore inert — chain, and IsAttached keeps telling the
// truth about what is enforced.
//
// A chain whose body is already intact is left completely alone. Rebuilding it
// means flushing it, and since Reconcile runs on every scan, rebuilding
// unconditionally would open the same empty-chain window on every interval.
func (e *Enforcer) Attach(ctx context.Context) error {
	// Create the chain; failure just means it already exists.
	_, _ = e.Exec(ctx, nil, "iptables", "-t", "raw", "-N", ChainName)

	attached := e.IsAttached(ctx)
	if attached && e.bodyIntact(ctx) {
		// Live and correct: nothing to do. Rebuilding here would flush the
		// live chain and open a window where hostile packets pass.
		return nil
	}

	// Unlink before rebuilding. A damaged chain is already not doing its job,
	// and unlinking first means a rebuild that fails leaves an inert chain
	// rather than a reachable empty one.
	//
	// Every jump is removed, not just the first one: `-D` deletes a single
	// matching rule, so a survivor would keep the chain reachable and would
	// be missed by a later teardown that deletes one rule at a time.
	if attached {
		if err := e.unlinkAll(ctx); err != nil {
			return err
		}
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

	// The body is complete; only now make it reachable.
	if _, err := e.Exec(ctx, nil, "iptables", "-t", "raw", "-I", "PREROUTING", "1", "-j", ChainName); err != nil {
		return fmt.Errorf("failed linking chain to PREROUTING: %v", err)
	}
	return nil
}

// bodyIntact reports whether the chain carries both rules the daemon needs:
// the whitelist RETURN and the hostile DROP. Either one missing means the body
// is damaged — a missing RETURN would drop whitelisted traffic, and a missing
// DROP would drop nothing at all.
//
// This is what turns "the jump is present" into "the jump is present and does
// something". Without it, a chain that was hooked before its rules could be
// installed would look healthy forever, because the jump is there and the
// early-return path would never rebuild the body.
func (e *Enforcer) bodyIntact(ctx context.Context) bool {
	rules := [][]string{
		{"-t", "raw", "-C", ChainName, "-m", "set", "--match-set", e.WhitelistSetName, "src", "-j", "RETURN"},
		{"-t", "raw", "-C", ChainName, "-m", "set", "--match-set", e.HostileSetName, "src", "-j", "DROP"},
	}
	for _, args := range rules {
		if _, err := e.Exec(ctx, nil, "iptables", args...); err != nil {
			return false
		}
	}
	return true
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
//
// Detach removes EVERY jump, not just the first one. `iptables -D` deletes a
// single matching rule, so a leftover second jump keeps the chain reachable:
// the daemon would report enforcement as off while packets still entered the
// chain, and the chain's body may still have been dropping them.
//
// The teardown is verified rather than assumed. If the chain is still hooked
// afterwards, Detach reports it instead of claiming success — a silent
// failure here is exactly how a "disabled" daemon keeps filtering.
func (e *Enforcer) Detach(ctx context.Context) error {
	// Unlink first: the chain cannot be deleted while a rule still points
	// at it.
	unlinkErr := e.unlinkAll(ctx)

	// The chain can outlive its jump, so always attempt to flush and delete
	// it. Errors are ignored: the chain may legitimately not exist, and a
	// torn-down state is the goal either way. A chain that is still
	// referenced stays in place, but empty and therefore inert.
	_, _ = e.Exec(ctx, nil, "iptables", "-t", "raw", "-F", ChainName)
	_, _ = e.Exec(ctx, nil, "iptables", "-t", "raw", "-X", ChainName)

	if unlinkErr != nil {
		return unlinkErr
	}

	// Verify the outcome. The probe is the same one Attach uses to decide
	// whether the chain is live, so this asks the kernel, not the flag.
	if e.IsAttached(ctx) {
		return fmt.Errorf("chain %s is still hooked into PREROUTING after detach", ChainName)
	}
	return nil
}

// unlinkAll removes every PREROUTING jump that points at the chain.
//
// `iptables -D` removes one matching rule per call, so the loop keeps
// deleting until the jump is gone. The attempt count is bounded: a rule that
// survives its own deletion would otherwise spin forever, and the bound
// turns that into a reported failure.
func (e *Enforcer) unlinkAll(ctx context.Context) error {
	for i := 0; i < maxUnlinkAttempts; i++ {
		if !e.IsAttached(ctx) {
			return nil
		}
		if _, err := e.Exec(ctx, nil, "iptables", "-t", "raw", "-D", "PREROUTING", "-j", ChainName); err != nil {
			return fmt.Errorf("failed unlinking chain from PREROUTING: %v", err)
		}
	}
	return fmt.Errorf("chain %s is still hooked into PREROUTING after %d unlink attempts", ChainName, maxUnlinkAttempts)
}
