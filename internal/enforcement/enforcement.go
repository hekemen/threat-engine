// Package enforcement owns the daemon's enforcement flag and reconciles the
// kernel to match it.
//
// The contract is declarative in both directions: every scan asserts that the
// desired state is the actual state, so enabled means the chain is present and
// hooked, and disabled means the chain is absent. Nothing else is allowed to
// touch the rules. That is what makes the flag trustworthy — the scheduler can
// neither silently re-enable enforcement after an operator turns it off, nor
// leave a stale chain behind after a manual flush.
//
// The ipset tables are deliberately out of scope here: they are populated in
// both modes so /check and the blocklist metrics keep working while enforcement
// is off.
package enforcement

import (
	"context"
	"errors"
	"sync"

	"github.com/hekemen/threat-engine/internal/iptables"
)

var ErrLocked = errors.New("enforcement is locked by environment variable")

// Controller holds the enforcement flag and applies it to the kernel.
type Controller struct {
	Enforcer *iptables.Enforcer

	mu      sync.RWMutex
	enabled bool
	locked  bool
}

// New returns a controller in the given initial state. It performs no kernel
// work; the first Reconcile applies the state.
func New(enforcer *iptables.Enforcer, enabled bool) *Controller {
	return &Controller{Enforcer: enforcer, enabled: enabled}
}

// NewLocked returns a controller locked by environment configuration.
// Runtime toggles are rejected while locked.
func NewLocked(enforcer *iptables.Enforcer, enabled bool) *Controller {
	return &Controller{Enforcer: enforcer, enabled: enabled, locked: true}
}

// Enabled reports whether enforcement is currently on.
func (c *Controller) Enabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.enabled
}

// Locked reports whether enforcement changes are disallowed.
func (c *Controller) Locked() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.locked
}

// Set updates the flag without touching the kernel. Pair it with Reconcile
// (or use SetAndReconcile) to make the change take effect.
func (c *Controller) Set(enabled bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.locked {
		return ErrLocked
	}
	c.enabled = enabled
	return nil
}

// Reconcile applies the current flag to the kernel. It is idempotent and is
// called on every scan, so it also repairs drift such as a manual `iptables -F`
// while enabled.
func (c *Controller) Reconcile(ctx context.Context) error {
	// Read the flag under the lock, then release it: exec can block, and
	// holding the lock across it would serialise every scan behind the admin
	// endpoint.
	c.mu.RLock()
	enabled := c.enabled
	c.mu.RUnlock()

	if enabled {
		return c.Enforcer.Attach(ctx)
	}
	return c.Enforcer.Detach(ctx)
}

// SetAndReconcile flips the flag and applies it in one call, so a toggle takes
// effect within one round-trip rather than at the next scan tick.
func (c *Controller) SetAndReconcile(ctx context.Context, enabled bool) error {
	if err := c.Set(enabled); err != nil {
		return err
	}
	return c.Reconcile(ctx)
}

// Shutdown tears the enforcement rules down on the way out. It clears the flag
// first and then reconciles, so the kernel ends in the disabled state even if
// the iptables call fails: reporting the error to the caller is what matters,
// and holding the process open over a wedged kernel call would be worse.
//
// This exists because a bare `return` on SIGTERM left the chain attached with
// a stale blocklist, still dropping packets long after the daemon was gone.
func (c *Controller) Shutdown(ctx context.Context) error {
	c.mu.Lock()
	c.enabled = false
	c.mu.Unlock()
	return c.Reconcile(ctx)
}
