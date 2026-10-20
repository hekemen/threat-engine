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
	if err := e.EnsureChain(context.Background()); err != nil {
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

func TestEnsureChainSkipsInsertWhenJumpExists(t *testing.T) {
	var calls []call
	e := &iptables.Enforcer{
		HostileSetName: "h", WhitelistSetName: "w",
		Exec: scriptedExec(&calls, map[string]bool{"-t raw -N K3S_THREAT_FILTER": true}),
	}
	if err := e.EnsureChain(context.Background()); err != nil {
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
	err := e.EnsureChain(context.Background())
	if err == nil || !strings.Contains(err.Error(), "failed linking chain to PREROUTING") {
		t.Fatalf("want linking error, got %v", err)
	}
}

func TestEnsureChainRuleErrorFatal(t *testing.T) {
	var calls []call
	e := &iptables.Enforcer{
		HostileSetName: "h", WhitelistSetName: "w",
		Exec: scriptedExec(&calls, map[string]bool{
			"-t raw -A K3S_THREAT_FILTER -m set --match-set w src -j RETURN": true,
		}),
	}
	err := e.EnsureChain(context.Background())
	if err == nil || !strings.Contains(err.Error(), "rule error") {
		t.Fatalf("want rule error, got %v", err)
	}
}
