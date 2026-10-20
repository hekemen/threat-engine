package ipset_test

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"

	"github.com/hekemen/thread-engine/internal/ipset"
	"github.com/hekemen/thread-engine/internal/runner"
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
		HostileSetName:   "k3s_hostile_ips",
		WhitelistSetName: "k3s_whitelist_ips",
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
		"create k3s_hostile_ips hash:net family inet maxelem 300000 -exist",
		"create k3s_whitelist_ips hash:net family inet maxelem 50000 -exist",
		"create k3s_whitelist_ips_tmp hash:net family inet maxelem 50000 -exist",
		"flush k3s_whitelist_ips_tmp",
		"add k3s_whitelist_ips_tmp 10.0.0.0/8 -exist",
		"swap k3s_whitelist_ips_tmp k3s_whitelist_ips",
		"destroy k3s_whitelist_ips_tmp",
		"create k3s_hostile_ips_tmp hash:net family inet maxelem 300000 -exist",
		"flush k3s_hostile_ips_tmp",
		"add k3s_hostile_ips_tmp 1.2.3.4 -exist",
		"add k3s_hostile_ips_tmp 5.6.7.0/24 -exist",
		"swap k3s_hostile_ips_tmp k3s_hostile_ips",
		"destroy k3s_hostile_ips_tmp",
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
