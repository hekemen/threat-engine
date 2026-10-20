package enforcement_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/hekemen/thread-engine/internal/enforcement"
	"github.com/hekemen/thread-engine/internal/iptables"
)

var errNotAttached = errors.New("exit status 1")

type recorder struct {
	mu    sync.Mutex
	calls []string
	// jumpPresent models the kernel's PREROUTING state. It starts false (a
	// fresh host) and flips true once an -I installs the jump, so `-C` behaves
	// the way iptables does.
	jumpPresent bool
	// failDelete makes the `-D PREROUTING` unlink fail, modelling a kernel
	// that is reachable enough to report the jump but cannot remove it.
	failDelete bool
}

func (r *recorder) exec(ctx context.Context, stdin io.Reader, name string, args ...string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	line := strings.Join(args, " ")
	r.calls = append(r.calls, line)

	if r.failDelete && strings.Contains(line, "-t raw -D PREROUTING") {
		return "simulated failure", errNotAttached
	}

	if strings.Contains(line, "-t raw -C PREROUTING -j THREAD_ENGINE_FILTER") && !r.jumpPresent {
		return "no such rule", errNotAttached
	}
	if strings.Contains(line, "-t raw -I PREROUTING") {
		r.jumpPresent = true
	}
	if strings.Contains(line, "-t raw -D PREROUTING") {
		r.jumpPresent = false
	}
	return "", nil
}

func (r *recorder) joined() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return strings.Join(r.calls, "\n")
}

func (r *recorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = nil
}

func newController(enabled bool) (*enforcement.Controller, *recorder) {
	rec := &recorder{}
	e := &iptables.Enforcer{HostileSetName: "h", WhitelistSetName: "w", Exec: rec.exec}
	return enforcement.New(e, enabled), rec
}

func TestNewTakesInitialState(t *testing.T) {
	c, _ := newController(true)
	if !c.Enabled() {
		t.Fatal("New(true) must start enabled")
	}
	c2, _ := newController(false)
	if c2.Enabled() {
		t.Fatal("New(false) must start disabled")
	}
}

func TestSetPerformsNoKernelWork(t *testing.T) {
	c, rec := newController(false)
	c.Set(true)
	if !c.Enabled() {
		t.Fatal("Set(true) must update Enabled")
	}
	if rec.joined() != "" {
		t.Fatalf("Set must not touch the kernel, got:\n%s", rec.joined())
	}
}

func TestReconcileAttachesWhenEnabled(t *testing.T) {
	c, rec := newController(true)
	if err := c.Reconcile(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := rec.joined()
	if !strings.Contains(got, "-t raw -A THREAD_ENGINE_FILTER -m set --match-set h src -j DROP") {
		t.Fatalf("enabled reconcile must install the DROP rule, got:\n%s", got)
	}
}

func TestReconcileDisablesAndStaysDisabled(t *testing.T) {
	c, rec := newController(false)
	if err := c.Reconcile(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := c.Reconcile(context.Background()); err != nil {
			t.Fatalf("reconcile %d: %v", i, err)
		}
	}
	got := rec.joined()
	if strings.Contains(got, "-A THREAD_ENGINE_FILTER -m set --match-set h src -j DROP") {
		t.Fatalf("disabled reconcile must never install a DROP rule, got:\n%s", got)
	}
	if !strings.Contains(got, "-X THREAD_ENGINE_FILTER") {
		t.Fatalf("disabled reconcile must tear the chain down, got:\n%s", got)
	}
}

func TestSetAndReconcileAppliesImmediately(t *testing.T) {
	c, rec := newController(false)
	if err := c.SetAndReconcile(context.Background(), true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !c.Enabled() || !strings.Contains(rec.joined(), "-A THREAD_ENGINE_FILTER -m set --match-set h src -j DROP") {
		t.Fatalf("SetAndReconcile(true) must attach within the call, got:\n%s", rec.joined())
	}
	rec.reset()
	if err := c.SetAndReconcile(context.Background(), false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Enabled() || !strings.Contains(rec.joined(), "-X THREAD_ENGINE_FILTER") {
		t.Fatalf("SetAndReconcile(false) must detach within the call, got:\n%s", rec.joined())
	}
}

func TestShutdownCleanupDetachesAndReportsNoError(t *testing.T) {
	// Graceful shutdown must assert the disabled state so the chain is
	// removed. Enabled -> shutdown must not leave the chain attached.
	c, rec := newController(false)
	if err := c.SetAndReconcile(context.Background(), true); err != nil {
		t.Fatalf("setup attach: %v", err)
	}
	if !c.Enabled() {
		t.Fatal("setup: expected enabled")
	}
	rec.reset()

	if err := c.Shutdown(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Enabled() {
		t.Fatal("Shutdown must leave the flag disabled")
	}
	got := rec.joined()
	if strings.Contains(got, "-A THREAD_ENGINE_FILTER -m set --match-set h src -j DROP") {
		t.Fatalf("Shutdown must not install a DROP rule, got:\n%s", got)
	}
	if !strings.Contains(got, "-X THREAD_ENGINE_FILTER") {
		t.Fatalf("Shutdown must tear the chain down, got:\n%s", got)
	}
}

func TestShutdownToleratesKernelFailure(t *testing.T) {
	// A wedged or unavailable iptables must not prevent the process from
	// exiting. The error is reported, and the flag is still cleared so a
	// later Reconcile cannot resurrect the rules.
	r := &recorder{jumpPresent: true, failDelete: true}
	e := &iptables.Enforcer{HostileSetName: "h", WhitelistSetName: "w", Exec: r.exec}
	c := enforcement.New(e, true)
	if err := c.Shutdown(context.Background()); err == nil {
		t.Fatal("a kernel failure during shutdown must be reported")
	}
	if c.Enabled() {
		t.Fatal("the flag must be cleared even when the kernel call fails")
	}
}

func TestEnabledIsRaceFree(t *testing.T) {
	c, _ := newController(false)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func(n int) { defer wg.Done(); c.Set(n%2 == 0) }(i)
		go func() { defer wg.Done(); _ = c.Enabled() }()
	}
	wg.Wait()
}
