package iptables_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/hekemen/thread-engine/internal/iptables"
	"github.com/hekemen/thread-engine/internal/runner"
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

func TestEnsureChainExactSequence(t *testing.T) {
	var calls []call
	e := &iptables.Enforcer{
		HostileSetName:   "k3s_hostile_ips",
		WhitelistSetName: "k3s_whitelist_ips",
		Exec: scriptedExec(&calls, map[string]bool{
			"-t raw -N K3S_THREAT_FILTER":               true, // chain already exists
			"-t raw -C PREROUTING -j K3S_THREAT_FILTER": true, // jump missing → insert
		}),
	}
	if err := e.Attach(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{
		"iptables -t raw -N K3S_THREAT_FILTER",
		"iptables -t raw -C PREROUTING -j K3S_THREAT_FILTER",
		"iptables -t raw -I PREROUTING 1 -j K3S_THREAT_FILTER",
		"iptables -t raw -F K3S_THREAT_FILTER",
		"iptables -t raw -A K3S_THREAT_FILTER -m set --match-set k3s_whitelist_ips src -j RETURN",
		"iptables -t raw -A K3S_THREAT_FILTER -m set --match-set k3s_hostile_ips src -j DROP",
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

func TestAttachDoesNotFlushWhenAlreadyAttached(t *testing.T) {
	// The jump is present (scriptedExec default: everything succeeds), which
	// means the chain is already installed. Rebuilding it would create a
	// window in which the live chain is empty and hostile packets pass, and
	// that window would recur on every scan. Attach must be a no-op then.
	var calls []call
	e := &iptables.Enforcer{
		HostileSetName: "k3s_hostile_ips", WhitelistSetName: "k3s_whitelist_ips",
		Exec: scriptedExec(&calls, nil),
	}
	if err := e.Attach(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	joined := strings.Join(callLines(calls), "\n")
	for _, forbidden := range []string{"-F K3S_THREAT_FILTER", "-A K3S_THREAT_FILTER"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("Attach must not rebuild an already-attached chain (saw %q):\n%s", forbidden, joined)
		}
	}
	// It must still have confirmed the jump is present.
	if !strings.Contains(joined, "-t raw -C PREROUTING -j K3S_THREAT_FILTER") {
		t.Fatalf("Attach must probe the jump even when nothing needs doing:\n%s", joined)
	}
}

func TestEnsureChainSkipsInsertWhenJumpExists(t *testing.T) {
	var calls []call
	e := &iptables.Enforcer{
		HostileSetName: "h", WhitelistSetName: "w",
		Exec: scriptedExec(&calls, map[string]bool{"-t raw -N K3S_THREAT_FILTER": true}),
	}
	if err := e.Attach(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, c := range calls {
		if strings.Join(c.args, " ") == "-t raw -I PREROUTING 1 -j K3S_THREAT_FILTER" {
			t.Fatal("insert must be skipped when -C succeeds")
		}
	}
}

func TestEnsureChainInsertFailureIsFatal(t *testing.T) {
	var calls []call
	e := &iptables.Enforcer{
		HostileSetName: "h", WhitelistSetName: "w",
		Exec: scriptedExec(&calls, map[string]bool{
			"-t raw -C PREROUTING -j K3S_THREAT_FILTER":   true,
			"-t raw -I PREROUTING 1 -j K3S_THREAT_FILTER": true,
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
			"-t raw -C PREROUTING -j K3S_THREAT_FILTER":                      true,
			"-t raw -A K3S_THREAT_FILTER -m set --match-set w src -j RETURN": true,
		}),
	}
	err := e.Attach(context.Background())
	if err == nil || !strings.Contains(err.Error(), "rule error") {
		t.Fatalf("want rule error, got %v", err)
	}
}

func TestDetachRemovesJumpAndChain(t *testing.T) {
	var calls []call
	e := &iptables.Enforcer{
		HostileSetName: "k3s_hostile_ips", WhitelistSetName: "k3s_whitelist_ips",
		Exec: scriptedExec(&calls, nil), // everything succeeds ⇒ -C reports the jump IS present
	}
	if err := e.Detach(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	joined := strings.Join(callLines(calls), "\n")
	// With the jump present, it must be deleted, and the chain must be removed.
	for _, want := range []string{
		"-t raw -C PREROUTING -j K3S_THREAT_FILTER",
		"-t raw -D PREROUTING -j K3S_THREAT_FILTER",
		"-t raw -F K3S_THREAT_FILTER",
		"-t raw -X K3S_THREAT_FILTER",
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
		if line := strings.Join(c.args, " "); strings.Contains(line, "k3s_hostile_ips") || strings.Contains(line, "k3s_whitelist_ips") {
			t.Fatalf("Detach must not touch ipset tables, got %q", line)
		}
	}
}

func TestDetachIsNoOpWhenNothingAttached(t *testing.T) {
	var calls []call
	e := &iptables.Enforcer{
		HostileSetName: "h", WhitelistSetName: "w",
		Exec: scriptedExec(&calls, map[string]bool{
			"-t raw -C PREROUTING -j K3S_THREAT_FILTER": true, // jump absent
			"-t raw -F K3S_THREAT_FILTER":               true, // chain absent
			"-t raw -X K3S_THREAT_FILTER":               true,
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
	for _, want := range []string{"-t raw -F K3S_THREAT_FILTER", "-t raw -X K3S_THREAT_FILTER"} {
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
	e.Exec = scriptedExec(&calls, map[string]bool{"-t raw -C PREROUTING -j K3S_THREAT_FILTER": true})
	if e.IsAttached(context.Background()) {
		t.Fatal("non-zero exit must mean not attached")
	}
	// Both probes share the calls slice: each must have been exactly
	// `iptables -t raw -C PREROUTING -j K3S_THREAT_FILTER`.
	if len(calls) != 2 {
		t.Fatalf("expected 2 probes, got %+v", calls)
	}
	for i, c := range calls {
		if got := c.name + " " + strings.Join(c.args, " "); got != "iptables -t raw -C PREROUTING -j K3S_THREAT_FILTER" {
			t.Fatalf("probe %d = %q, want the -C PREROUTING jump test", i, got)
		}
	}
}
