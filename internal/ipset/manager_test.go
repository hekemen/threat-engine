package ipset_test

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"

	"github.com/hekemen/threat-engine/internal/ipset"
	"github.com/hekemen/threat-engine/internal/runner"
)

type recordedCall struct {
	name  string
	args  []string
	stdin string
}

func fakeExec(calls *[]recordedCall, err error) runner.RunnerFn {
	return func(ctx context.Context, stdin io.Reader, name string, args ...string) (string, error) {
		body := ""
		if stdin != nil {
			b, _ := io.ReadAll(stdin)
			body = string(b)
		}
		*calls = append(*calls, recordedCall{name, args, body})
		return "", err
	}
}

func TestSyncBuildsAtomicSwapScript(t *testing.T) {
	var calls []recordedCall
	m := &ipset.Manager{
		HostileSetName:   "threat_engine_hostile_ips",
		WhitelistSetName: "threat_engine_whitelist_ips",
		Whitelist:        []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		Exec:             fakeExec(&calls, nil),
	}
	if err := m.Sync(context.Background(), []string{"1.2.3.4", "5.6.7.0/24"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(calls) != 1 || calls[0].name != "ipset" || len(calls[0].args) != 1 || calls[0].args[0] != "restore" {
		t.Fatalf("expected single 'ipset restore' call, got %+v", calls)
	}
	want := strings.Join([]string{
		"create threat_engine_hostile_ips hash:net family inet maxelem 300000 -exist",
		"create threat_engine_whitelist_ips hash:net family inet maxelem 50000 -exist",
		"create threat_engine_whitelist_ips_tmp hash:net family inet maxelem 50000 -exist",
		"flush threat_engine_whitelist_ips_tmp",
		"add threat_engine_whitelist_ips_tmp 10.0.0.0/8 -exist",
		"swap threat_engine_whitelist_ips_tmp threat_engine_whitelist_ips",
		"destroy threat_engine_whitelist_ips_tmp",
		"create threat_engine_hostile_ips_tmp hash:net family inet maxelem 300000 -exist",
		"flush threat_engine_hostile_ips_tmp",
		"add threat_engine_hostile_ips_tmp 1.2.3.4 -exist",
		"add threat_engine_hostile_ips_tmp 5.6.7.0/24 -exist",
		"swap threat_engine_hostile_ips_tmp threat_engine_hostile_ips",
		"destroy threat_engine_hostile_ips_tmp",
		"",
	}, "\n")
	if calls[0].stdin != want {
		t.Fatalf("restore script mismatch:\ngot:\n%s\nwant:\n%s", calls[0].stdin, want)
	}
}

func TestSyncErrorPropagates(t *testing.T) {
	var calls []recordedCall
	m := &ipset.Manager{
		HostileSetName: "h", WhitelistSetName: "w", Exec: fakeExec(&calls, errors.New("denied")),
	}
	err := m.Sync(context.Background(), []string{"1.2.3.4"})
	if err == nil || !strings.Contains(err.Error(), "ipset restore failed") || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("want wrapped restore error, got %v", err)
	}
}

func TestSyncWithEmptyEntriesStillSwaps(t *testing.T) {
	var calls []recordedCall
	m := &ipset.Manager{
		HostileSetName: "h", WhitelistSetName: "w", Exec: fakeExec(&calls, nil),
	}
	if err := m.Sync(context.Background(), nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	script := calls[0].stdin
	if strings.Contains(script, "flush h\n") || strings.Contains(script, "flush w\n") {
		t.Fatalf("live sets must never be flushed:\n%s", script)
	}
	if !strings.Contains(script, "swap h_tmp h") || !strings.Contains(script, "swap w_tmp w") {
		t.Fatalf("empty entry list must still swap both sets:\n%s", script)
	}
}

func TestSyncNeverEmitsIPv6IntoIPv4Sets(t *testing.T) {
	// Regression: the default whitelist always contains ::1/128, fc00::/7 and
	// fe80::/10, and blocklist.de returns real IPv6 addresses. A hash:net set
	// with no family is IPv4-only, so `add <set> ::1/128` aborts the whole
	// restore with "128 is out of range 0-32" and the blocklist never loads.
	// Sync must therefore filter IPv6 out of both the whitelist and the hostile
	// entries, and every create must pin family inet.
	var calls []recordedCall
	m := &ipset.Manager{
		HostileSetName:   "h",
		WhitelistSetName: "w",
		Whitelist: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("::1/128"),
			netip.MustParsePrefix("fc00::/7"),
			netip.MustParsePrefix("fe80::/10"),
		},
		Exec: fakeExec(&calls, nil),
	}
	entries := []string{
		"1.2.3.4",
		"5.6.7.0/24",
		"2001:1308:a5cc:6600:e157:76a6:16c8:37df",
		"2001:db8::/32",
	}
	if err := m.Sync(context.Background(), entries); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	script := calls[0].stdin

	// No IPv6 literal or prefix may appear in any add line.
	for _, line := range strings.Split(script, "\n") {
		if !strings.HasPrefix(line, "add ") {
			continue
		}
		fields := strings.Fields(line) // add, set, member, -exist
		if len(fields) < 3 {
			continue
		}
		addr, err := netip.ParseAddr(strings.Split(fields[2], "/")[0])
		if err != nil {
			t.Fatalf("add line has unparseable member %q: %q", fields[2], line)
		}
		if !addr.Is4() {
			t.Fatalf("IPv6 member %q must not be added to an IPv4 set: %q", fields[2], line)
		}
	}

	// The IPv4 whitelist and hostile entries must still be present.
	if !strings.Contains(script, "add w_tmp 10.0.0.0/8 -exist") {
		t.Fatalf("IPv4 whitelist entry was dropped:\n%s", script)
	}
	if !strings.Contains(script, "add h_tmp 1.2.3.4 -exist") || !strings.Contains(script, "add h_tmp 5.6.7.0/24 -exist") {
		t.Fatalf("IPv4 hostile entries were dropped:\n%s", script)
	}

	// Every create must be explicit about the family.
	for _, line := range strings.Split(script, "\n") {
		if strings.HasPrefix(line, "create ") && !strings.Contains(line, "family inet ") {
			t.Fatalf("create without 'family inet' defaults to IPv4 silently: %q", line)
		}
	}
}

func TestEnsureSetsCreatesBothSetsWithoutTouchingContents(t *testing.T) {
	// The enforcement rules name these sets, so they must exist before the
	// attach. EnsureSets is the minimal way to assert that: create both, with
	// the same family constraint Sync uses, and never flush or swap — a
	// populated set must survive a restart untouched.
	var calls []recordedCall
	m := &ipset.Manager{HostileSetName: "h", WhitelistSetName: "w", Exec: fakeExec(&calls, nil)}
	if err := m.EnsureSets(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(calls) != 1 || calls[0].name != "ipset" || strings.Join(calls[0].args, " ") != "restore" {
		t.Fatalf("want a single `ipset restore`, got %+v", calls)
	}
	body := calls[0].stdin
	for _, want := range []string{
		"create h hash:net family inet maxelem 300000 -exist",
		"create w hash:net family inet maxelem 50000 -exist",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in restore script:\n%s", want, body)
		}
	}
	for _, forbidden := range []string{"flush", "swap", "destroy", "add "} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("EnsureSets must not touch set contents (saw %q):\n%s", forbidden, body)
		}
	}
}

func TestEnsureSetsReportsFailure(t *testing.T) {
	var calls []recordedCall
	m := &ipset.Manager{
		HostileSetName: "h", WhitelistSetName: "w",
		Exec: fakeExec(&calls, errors.New("exit status 1: ipset v7.22: Permission denied")),
	}
	if err := m.EnsureSets(context.Background()); err == nil {
		t.Fatal("a failed ensure must be reported, not swallowed")
	}
}

func TestDestroyRemovesBothSets(t *testing.T) {
	// Graceful shutdown destroys the kernel tables so stopping the daemon
	// restores the host instead of leaving a frozen blocklist behind.
	var calls []recordedCall
	m := &ipset.Manager{HostileSetName: "h", WhitelistSetName: "w", Exec: fakeExec(&calls, nil)}
	if err := m.Destroy(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"ipset destroy h", "ipset destroy w"}
	if len(calls) != len(want) {
		t.Fatalf("got %d calls, want %d: %+v", len(calls), len(want), calls)
	}
	for i, w := range want {
		got := calls[i].name + " " + strings.Join(calls[i].args, " ")
		if got != w {
			t.Fatalf("call %d = %q, want %q", i, got, w)
		}
	}
}

func TestDestroyIgnoresAbsentSet(t *testing.T) {
	// Destroy must be idempotent: a first-run shutdown, or a repeated
	// shutdown, must not fail because the set was never created.
	var calls []recordedCall
	m := &ipset.Manager{
		HostileSetName: "h", WhitelistSetName: "w",
		Exec: fakeExec(&calls, errors.New("exit status 1: ipset v7.22: The set with the given name does not exist")),
	}
	if err := m.Destroy(context.Background()); err != nil {
		t.Fatalf("an absent set must not be an error, got: %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("both sets must still be attempted, got %+v", calls)
	}
}

func TestDestroyReportsRealFailure(t *testing.T) {
	// A genuine failure (e.g. the set is still referenced by an iptables
	// rule) must surface, so the operator learns the host was not restored.
	var calls []recordedCall
	m := &ipset.Manager{
		HostileSetName: "h", WhitelistSetName: "w",
		Exec: fakeExec(&calls, errors.New("exit status 1: ipset v7.22: Set cannot be destroyed: it is in use by a kernel component")),
	}
	if err := m.Destroy(context.Background()); err == nil {
		t.Fatal("a set that cannot be destroyed must be reported")
	}
}

func TestContainsExitCodeSemantics(t *testing.T) {
	var calls []recordedCall
	m := &ipset.Manager{HostileSetName: "h", WhitelistSetName: "w", Exec: fakeExec(&calls, nil)}
	if !m.Contains(context.Background(), "w", netip.MustParseAddr("1.2.3.4")) {
		t.Fatal("nil error must mean contained")
	}
	m.Exec = fakeExec(&calls, errors.New("exit status 1"))
	if m.Contains(context.Background(), "w", netip.MustParseAddr("1.2.3.4")) {
		t.Fatal("non-nil error must mean not contained")
	}
	if len(calls) != 2 || calls[0].name != "ipset" || calls[0].args[0] != "test" || calls[0].args[1] != "w" || calls[0].args[2] != "1.2.3.4" {
		t.Fatalf("expected 'ipset test w 1.2.3.4', got %+v", calls)
	}
}
