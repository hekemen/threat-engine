package iptables_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/hekemen/threat-engine/internal/iptables"
	"github.com/hekemen/threat-engine/internal/runner"
)

type call struct {
	name string
	args []string
}

func scriptedExec(calls *[]call, fail map[string]bool) runner.RunnerFn {
	return func(ctx context.Context, stdin io.Reader, name string, args ...string) (string, error) {
		*calls = append(*calls, call{name, args})
		key := strings.Join(args, " ")
		if fail[key] {
			return "simulated failure", errors.New("exit status 1")
		}
		return "", nil
	}
}

func callLines(calls []call) []string {
	out := make([]string, 0, len(calls))
	for _, c := range calls {
		out = append(out, c.name+" "+strings.Join(c.args, " "))
	}
	return out
}

// fakeTable models an iptables table whose jump rules can actually be
// deleted: -C reports the jump present while at least one remains, and -D
// removes exactly one.
//
// scriptedExec cannot express that, and the difference is the whole point of
// these tests: `-D` deletes a single matching rule, so a survivor keeps the
// chain reachable while the daemon believes enforcement is off.
type fakeTable struct {
	// jumps is the number of PREROUTING rules pointing at the chain.
	jumps int
	// deleteFails makes every -D fail, the way a permission error would.
	deleteFails bool
	// stuckJumps makes a deleted jump reappear, the way a kernel or a
	// concurrent writer could keep the rule alive.
	stuckJumps bool
	// bodyDamaged makes the hostile DROP probe fail, so the chain looks
	// damaged and Attach rebuilds it.
	bodyDamaged bool
}

func (f *fakeTable) exec(calls *[]call) runner.RunnerFn {
	return func(ctx context.Context, stdin io.Reader, name string, args ...string) (string, error) {
		*calls = append(*calls, call{name, args})
		line := strings.Join(args, " ")

		switch {
		case strings.Contains(line, "-C PREROUTING"):
			if f.jumps > 0 {
				return "", nil
			}
			return "iptables: Bad rule (does a matching rule exist in that chain?).", errors.New("exit status 1")

		case strings.Contains(line, "-D PREROUTING"):
			if f.deleteFails {
				return "iptables: Permission denied (you must be root).", errors.New("exit status 1")
			}
			if f.jumps == 0 {
				return "iptables: Bad rule (does a matching rule exist in that chain?).", errors.New("exit status 1")
			}
			f.jumps--
			if f.stuckJumps {
				f.jumps++ // the rule survives the delete
			}
			return "", nil

		case strings.Contains(line, "-I PREROUTING"):
			f.jumps++
			return "", nil

		case strings.Contains(line, "-C ") && strings.Contains(line, "--match-set"):
			if f.bodyDamaged && strings.Contains(line, "src -j DROP") {
				return "iptables: Bad rule (does a matching rule exist in that chain?).", errors.New("exit status 1")
			}
			return "", nil
		}
		return "", nil
	}
}

func TestChainNameIsThreadEngineFilter(t *testing.T) {
	if iptables.ChainName != "THREAD_ENGINE_FILTER" {
		t.Fatalf("ChainName = %q, want THREAD_ENGINE_FILTER", iptables.ChainName)
	}
}

func TestEnsureChainExactSequence(t *testing.T) {
	var calls []call
	e := &iptables.Enforcer{
		HostileSetName:   "threat_engine_hostile_ips",
		WhitelistSetName: "threat_engine_whitelist_ips",
		Exec: scriptedExec(&calls, map[string]bool{
			"-t raw -N THREAD_ENGINE_FILTER":               true, // chain already exists
			"-t raw -C PREROUTING -j THREAD_ENGINE_FILTER": true, // jump missing → insert
		}),
	}
	if err := e.Attach(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The body is built BEFORE the jump is installed. Linking first would
	// leave a reachable but empty chain whenever a rule fails to install,
	// which drops nothing while the daemon reports enforcement as on.
	want := []string{
		"iptables -t raw -N THREAD_ENGINE_FILTER",
		"iptables -t raw -C PREROUTING -j THREAD_ENGINE_FILTER",
		"iptables -t raw -F THREAD_ENGINE_FILTER",
		"iptables -t raw -A THREAD_ENGINE_FILTER -m set --match-set threat_engine_whitelist_ips src -j RETURN",
		"iptables -t raw -A THREAD_ENGINE_FILTER -m set --match-set threat_engine_hostile_ips src -j DROP",
		"iptables -t raw -I PREROUTING 1 -j THREAD_ENGINE_FILTER",
	}
	if len(calls) != len(want) {
		t.Fatalf("got %d calls: %+v", len(calls), calls)
	}
	for i, c := range calls {
		got := c.name + " " + strings.Join(c.args, " ")
		if got != want[i] {
			t.Fatalf("call %d = %q, want %q", i, got, want[i])
		}
	}
}

// The jump must be the LAST thing installed. A rule that fails to install
// (here: the ipset does not exist yet) must leave the chain unreachable, so
// nothing is dropped and nothing claims to be enforced.
func TestAttachRuleFailureLeavesChainUnlinked(t *testing.T) {
	var calls []call
	e := &iptables.Enforcer{
		HostileSetName: "h", WhitelistSetName: "w",
		Exec: scriptedExec(&calls, map[string]bool{
			"-t raw -C PREROUTING -j THREAD_ENGINE_FILTER":                      true, // jump missing
			"-t raw -A THREAD_ENGINE_FILTER -m set --match-set w src -j RETURN": true, // set missing
		}),
	}
	err := e.Attach(context.Background())
	if err == nil || !strings.Contains(err.Error(), "rule error") {
		t.Fatalf("want rule error, got %v", err)
	}
	joined := strings.Join(callLines(calls), "\n")
	if strings.Contains(joined, "-I PREROUTING") {
		t.Fatalf("the jump must not be installed when the body failed:\n%s", joined)
	}
}

// A chain that is hooked but whose body is damaged must be repaired: the
// daemon would otherwise report enforcement as on while dropping nothing,
// forever, because the jump is present so the body is never rebuilt.
func TestAttachRepairsDamagedChain(t *testing.T) {
	var calls []call
	table := &fakeTable{jumps: 1, bodyDamaged: true}
	e := &iptables.Enforcer{
		HostileSetName: "h", WhitelistSetName: "w",
		Exec: table.exec(&calls),
	}
	if err := e.Attach(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	joined := strings.Join(callLines(calls), "\n")
	for _, want := range []string{
		"-t raw -D PREROUTING -j THREAD_ENGINE_FILTER", // unlink the damaged chain first
		"-t raw -F THREAD_ENGINE_FILTER",               // rebuild the body
		"-t raw -A THREAD_ENGINE_FILTER -m set --match-set h src -j DROP",
		"-t raw -I PREROUTING 1 -j THREAD_ENGINE_FILTER", // and only then relink it
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("Attach missing %q, got:\n%s", want, joined)
		}
	}
	// The unlink must precede the rebuild, and the relink must come last.
	unlink := strings.Index(joined, "-D PREROUTING")
	flush := strings.Index(joined, "-F THREAD_ENGINE_FILTER")
	relink := strings.Index(joined, "-I PREROUTING")
	if !(unlink < flush && flush < relink) {
		t.Fatalf("expected unlink → rebuild → relink order, got:\n%s", joined)
	}
}

// Attach must not leave duplicate jumps behind. Every survivor is another
// path into the chain, and Detach only has to miss one of them to leave the
// chain reachable while the daemon reports enforcement as off.
func TestAttachRemovesDuplicateJumpsBeforeRelinking(t *testing.T) {
	var calls []call
	table := &fakeTable{jumps: 2, bodyDamaged: true}
	e := &iptables.Enforcer{
		HostileSetName: "h", WhitelistSetName: "w",
		Exec: table.exec(&calls),
	}
	if err := e.Attach(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if table.jumps != 1 {
		t.Fatalf("expected exactly 1 jump after Attach, got %d", table.jumps)
	}
}

// A chain whose body is intact must not be rebuilt: flushing a live chain
// opens a window in which hostile packets pass, and it would recur on every
// scan.
func TestAttachDoesNotRebuildIntactChain(t *testing.T) {
	var calls []call
	e := &iptables.Enforcer{
		HostileSetName: "h", WhitelistSetName: "w",
		Exec: scriptedExec(&calls, nil), // every probe succeeds ⇒ body is intact
	}
	if err := e.Attach(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	joined := strings.Join(callLines(calls), "\n")
	for _, forbidden := range []string{"-F THREAD_ENGINE_FILTER", "-A THREAD_ENGINE_FILTER", "-I PREROUTING", "-D PREROUTING"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("Attach must not touch an intact chain (saw %q):\n%s", forbidden, joined)
		}
	}
	// It must have verified the jump and both rules.
	for _, want := range []string{
		"-t raw -C PREROUTING -j THREAD_ENGINE_FILTER",
		"-t raw -C THREAD_ENGINE_FILTER -m set --match-set w src -j RETURN",
		"-t raw -C THREAD_ENGINE_FILTER -m set --match-set h src -j DROP",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("Attach missing probe %q, got:\n%s", want, joined)
		}
	}
}

func TestAttachDoesNotFlushWhenAlreadyAttached(t *testing.T) {
	// The jump is present (scriptedExec default: everything succeeds), which
	// means the chain is already installed. Rebuilding it would create a
	// window in which the live chain is empty and hostile packets pass, and
	// that window would recur on every scan. Attach must be a no-op then.
	var calls []call
	e := &iptables.Enforcer{
		HostileSetName: "threat_engine_hostile_ips", WhitelistSetName: "threat_engine_whitelist_ips",
		Exec: scriptedExec(&calls, nil),
	}
	if err := e.Attach(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	joined := strings.Join(callLines(calls), "\n")
	for _, forbidden := range []string{"-F THREAD_ENGINE_FILTER", "-A THREAD_ENGINE_FILTER"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("Attach must not rebuild an already-attached chain (saw %q):\n%s", forbidden, joined)
		}
	}
	// It must still have confirmed the jump is present.
	if !strings.Contains(joined, "-t raw -C PREROUTING -j THREAD_ENGINE_FILTER") {
		t.Fatalf("Attach must probe the jump even when nothing needs doing:\n%s", joined)
	}
}

func TestEnsureChainSkipsInsertWhenJumpExists(t *testing.T) {
	var calls []call
	e := &iptables.Enforcer{
		HostileSetName: "h", WhitelistSetName: "w",
		Exec: scriptedExec(&calls, map[string]bool{"-t raw -N THREAD_ENGINE_FILTER": true}),
	}
	if err := e.Attach(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, c := range calls {
		if strings.Join(c.args, " ") == "-t raw -I PREROUTING 1 -j THREAD_ENGINE_FILTER" {
			t.Fatal("insert must be skipped when -C succeeds")
		}
	}
}

func TestEnsureChainInsertFailureIsFatal(t *testing.T) {
	var calls []call
	e := &iptables.Enforcer{
		HostileSetName: "h", WhitelistSetName: "w",
		Exec: scriptedExec(&calls, map[string]bool{
			"-t raw -C PREROUTING -j THREAD_ENGINE_FILTER":   true,
			"-t raw -I PREROUTING 1 -j THREAD_ENGINE_FILTER": true,
		}),
	}
	err := e.Attach(context.Background())
	if err == nil || !strings.Contains(err.Error(), "failed linking chain to PREROUTING") {
		t.Fatalf("want linking error, got %v", err)
	}
}

func TestEnsureChainRuleErrorFatal(t *testing.T) {
	var calls []call
	e := &iptables.Enforcer{
		HostileSetName: "h", WhitelistSetName: "w",
		Exec: scriptedExec(&calls, map[string]bool{
			// The jump must be missing for the body to be rebuilt at all.
			"-t raw -C PREROUTING -j THREAD_ENGINE_FILTER":                      true,
			"-t raw -A THREAD_ENGINE_FILTER -m set --match-set w src -j RETURN": true,
		}),
	}
	err := e.Attach(context.Background())
	if err == nil || !strings.Contains(err.Error(), "rule error") {
		t.Fatalf("want rule error, got %v", err)
	}
}

func TestDetachRemovesJumpAndChain(t *testing.T) {
	var calls []call
	table := &fakeTable{jumps: 1}
	e := &iptables.Enforcer{
		HostileSetName: "threat_engine_hostile_ips", WhitelistSetName: "threat_engine_whitelist_ips",
		Exec: table.exec(&calls),
	}
	if err := e.Detach(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	joined := strings.Join(callLines(calls), "\n")
	// With the jump present, it must be deleted, and the chain must be removed.
	for _, want := range []string{
		"-t raw -C PREROUTING -j THREAD_ENGINE_FILTER",
		"-t raw -D PREROUTING -j THREAD_ENGINE_FILTER",
		"-t raw -F THREAD_ENGINE_FILTER",
		"-t raw -X THREAD_ENGINE_FILTER",
	} {
		if !strings.Contains(joined, "iptables "+want) {
			t.Fatalf("Detach missing %q, got:\n%s", want, joined)
		}
	}
	// -D must never precede the -C that authorizes it.
	if strings.Index(joined, "-D PREROUTING") < strings.Index(joined, "-C PREROUTING") {
		t.Fatalf("Detach must probe with -C before deleting with -D, got:\n%s", joined)
	}
	// Detach must never touch the ipset tables.
	for _, c := range calls {
		if line := strings.Join(c.args, " "); strings.Contains(line, "threat_engine_hostile_ips") || strings.Contains(line, "threat_engine_whitelist_ips") {
			t.Fatalf("Detach must not touch ipset tables, got %q", line)
		}
	}
}

// Detach must remove EVERY jump, not just the first one. `-D` deletes a
// single matching rule, so a survivor keeps the chain reachable: the daemon
// would report enforcement as off while packets still entered the chain, and
// the chain's body may still drop them.
func TestDetachRemovesEveryJump(t *testing.T) {
	var calls []call
	table := &fakeTable{jumps: 3}
	e := &iptables.Enforcer{
		HostileSetName: "threat_engine_hostile_ips", WhitelistSetName: "threat_engine_whitelist_ips",
		Exec: table.exec(&calls),
	}
	if err := e.Detach(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if table.jumps != 0 {
		t.Fatalf("Detach left %d jump(s) behind; the chain stays reachable", table.jumps)
	}
	deletes := 0
	for _, c := range calls {
		if strings.Contains(strings.Join(c.args, " "), "-D PREROUTING") {
			deletes++
		}
	}
	if deletes != 3 {
		t.Fatalf("expected 3 deletions (one per jump), got %d:\n%s", deletes, strings.Join(callLines(calls), "\n"))
	}
}

// A jump that cannot be removed must be reported, not swallowed: the chain
// is still reachable and may still be dropping packets while the daemon
// claims enforcement is off.
func TestDetachReportsFailureWhenTheJumpCannotBeRemoved(t *testing.T) {
	var calls []call
	table := &fakeTable{jumps: 1, deleteFails: true}
	e := &iptables.Enforcer{
		HostileSetName: "threat_engine_hostile_ips", WhitelistSetName: "threat_engine_whitelist_ips",
		Exec: table.exec(&calls),
	}
	err := e.Detach(context.Background())
	if err == nil {
		t.Fatal("a jump that cannot be removed must be reported")
	}
	if !strings.Contains(err.Error(), "unlink") {
		t.Fatalf("error should name the unlink failure, got: %v", err)
	}
}

// The teardown must be verified, not assumed. A chain that is still hooked
// after Detach means the daemon reports enforcement as off while its rules
// are still in the path of every packet.
func TestDetachReportsFailureWhenTheChainStaysReachable(t *testing.T) {
	var calls []call
	table := &fakeTable{jumps: 1, stuckJumps: true}
	e := &iptables.Enforcer{
		HostileSetName: "threat_engine_hostile_ips", WhitelistSetName: "threat_engine_whitelist_ips",
		Exec: table.exec(&calls),
	}
	err := e.Detach(context.Background())
	if err == nil {
		t.Fatal("a chain that stays reachable must be reported")
	}
	if !strings.Contains(err.Error(), "still hooked") {
		t.Fatalf("error should say the chain is still hooked, got: %v", err)
	}
}

func TestDetachIsNoOpWhenNothingAttached(t *testing.T) {
	var calls []call
	e := &iptables.Enforcer{
		HostileSetName: "h", WhitelistSetName: "w",
		Exec: scriptedExec(&calls, map[string]bool{
			"-t raw -C PREROUTING -j THREAD_ENGINE_FILTER": true, // jump absent
			"-t raw -F THREAD_ENGINE_FILTER":               true, // chain absent
			"-t raw -X THREAD_ENGINE_FILTER":               true,
		}),
	}
	if err := e.Detach(context.Background()); err != nil {
		t.Fatalf("Detach must tolerate an absent chain/jump, got %v", err)
	}
	joined := strings.Join(callLines(calls), "\n")
	if strings.Contains(joined, "-D PREROUTING") {
		t.Fatalf("must not delete a jump that is not present:\n%s", joined)
	}
	// The chain can exist while the jump is gone, so teardown must still try
	// to remove it even when the probe fails.
	for _, want := range []string{"-t raw -F THREAD_ENGINE_FILTER", "-t raw -X THREAD_ENGINE_FILTER"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("Detach must still attempt %q, got:\n%s", want, joined)
		}
	}
}

func TestIsAttachedExitCodeSemantics(t *testing.T) {
	var calls []call
	e := &iptables.Enforcer{HostileSetName: "h", WhitelistSetName: "w", Exec: scriptedExec(&calls, nil)}
	if !e.IsAttached(context.Background()) {
		t.Fatal("clean exit must mean attached")
	}
	e.Exec = scriptedExec(&calls, map[string]bool{"-t raw -C PREROUTING -j THREAD_ENGINE_FILTER": true})
	if e.IsAttached(context.Background()) {
		t.Fatal("non-zero exit must mean not attached")
	}
	// Both probes share the calls slice: each must have been exactly
	// `iptables -t raw -C PREROUTING -j THREAD_ENGINE_FILTER`.
	if len(calls) != 2 {
		t.Fatalf("expected 2 probes, got %+v", calls)
	}
	for i, c := range calls {
		if got := c.name + " " + strings.Join(c.args, " "); got != "iptables -t raw -C PREROUTING -j THREAD_ENGINE_FILTER" {
			t.Fatalf("probe %d = %q, want the -C PREROUTING jump test", i, got)
		}
	}
}
