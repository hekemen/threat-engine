package iptables_test

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/hekemen/threat-engine/internal/iptables"
)

// listOutput mirrors the exact shape of `iptables -t raw -L THREAD_ENGINE_FILTER
// -v -n -x`: a chain header, the column header, and one line per rule.
const listOutput = `Chain THREAD_ENGINE_FILTER (0 references)
    pkts      bytes target     prot opt in     out     source               destination
      12     1440 RETURN     all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set threat_engine_whitelist_ips src
     345    45678 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set threat_engine_hostile_ips src
`

// counterEnforcer returns an Enforcer whose exec produces the given output.
func counterEnforcer(out string, err error) *iptables.Enforcer {
	return &iptables.Enforcer{
		HostileSetName:   "threat_engine_hostile_ips",
		WhitelistSetName: "threat_engine_whitelist_ips",
		Exec: func(ctx context.Context, stdin io.Reader, name string, args ...string) (string, error) {
			return out, err
		},
	}
}

func TestDropCountersParsesHostileAndWhitelist(t *testing.T) {
	e := counterEnforcer(listOutput, nil)

	hostile, whitelist, err := e.DropCounters(context.Background())
	if err != nil {
		t.Fatalf("DropCounters: %v", err)
	}
	if hostile.Packets != 345 || hostile.Bytes != 45678 {
		t.Fatalf("hostile counters = %+v, want {345 45678}", hostile)
	}
	if whitelist.Packets != 12 || whitelist.Bytes != 1440 {
		t.Fatalf("whitelist counters = %+v, want {12 1440}", whitelist)
	}
}

// The rules must be identified by the set they match, not by their position in
// the chain: an operator may reorder the chain, and a positional read would
// then attribute the DROP counter to the whitelist.
func TestDropCountersIdentifiesRulesBySetNotPosition(t *testing.T) {
	reordered := `Chain THREAD_ENGINE_FILTER (0 references)
    pkts      bytes target     prot opt in     out     source               destination
       7      700 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set threat_engine_hostile_ips src
       9      900 RETURN     all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set threat_engine_whitelist_ips src
`
	e := counterEnforcer(reordered, nil)

	hostile, whitelist, err := e.DropCounters(context.Background())
	if err != nil {
		t.Fatalf("DropCounters: %v", err)
	}
	if hostile.Packets != 7 || hostile.Bytes != 700 {
		t.Fatalf("hostile counters = %+v, want {7 700}", hostile)
	}
	if whitelist.Packets != 9 || whitelist.Bytes != 900 {
		t.Fatalf("whitelist counters = %+v, want {9 900}", whitelist)
	}
}

// -x is mandatory: without it iptables abbreviates large values ("1.2k") and
// the numbers cannot be parsed.
func TestDropCountersUsesExactListing(t *testing.T) {
	var got string
	e := &iptables.Enforcer{
		HostileSetName:   "h",
		WhitelistSetName: "w",
		Exec: func(ctx context.Context, stdin io.Reader, name string, args ...string) (string, error) {
			got = name + " " + strings.Join(args, " ")
			return listOutput, nil
		},
	}

	if _, _, err := e.DropCounters(context.Background()); err != nil {
		t.Fatalf("DropCounters: %v", err)
	}
	want := "iptables -t raw -L THREAD_ENGINE_FILTER -v -n -x"
	if got != want {
		t.Fatalf("command = %q, want %q", got, want)
	}
}

// A missing chain means enforcement is off. That is not an error: it must not
// spam the log every poll, and it must not look like a failure.
func TestDropCountersAbsentChainIsNotAnError(t *testing.T) {
	e := counterEnforcer("iptables: No chain/target/match by that name.\n", errors.New("exit status 1"))

	hostile, whitelist, err := e.DropCounters(context.Background())
	if err != nil {
		t.Fatalf("absent chain must not be an error, got %v", err)
	}
	if hostile.Packets != 0 || hostile.Bytes != 0 {
		t.Fatalf("hostile counters = %+v, want zeros", hostile)
	}
	if whitelist.Packets != 0 || whitelist.Bytes != 0 {
		t.Fatalf("whitelist counters = %+v, want zeros", whitelist)
	}
}

// Any other failure (no CAP_NET_ADMIN, a wedged kernel) must surface so the
// caller can log it and keep serving the last known totals.
func TestDropCountersReportsRealFailures(t *testing.T) {
	e := counterEnforcer("iptables v1.8.11 (nf_tables): can't initialize ipset.\n", errors.New("exit status 1"))

	if _, _, err := e.DropCounters(context.Background()); err == nil {
		t.Fatal("a real failure must be reported")
	}
}

// A chain that exists but holds no set rules yields zero counters.
func TestDropCountersEmptyChain(t *testing.T) {
	e := counterEnforcer("Chain THREAD_ENGINE_FILTER (0 references)\n", nil)

	hostile, whitelist, err := e.DropCounters(context.Background())
	if err != nil {
		t.Fatalf("DropCounters: %v", err)
	}
	if hostile.Packets != 0 || whitelist.Packets != 0 {
		t.Fatalf("want zero counters, got hostile=%+v whitelist=%+v", hostile, whitelist)
	}
}
