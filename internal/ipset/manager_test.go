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
		"create k3s_hostile_ips hash:net maxelem 300000 -exist",
		"create k3s_whitelist_ips hash:net maxelem 50000 -exist",
		"create k3s_whitelist_ips_tmp hash:net maxelem 50000 -exist",
		"flush k3s_whitelist_ips_tmp",
		"add k3s_whitelist_ips_tmp 10.0.0.0/8 -exist",
		"swap k3s_whitelist_ips_tmp k3s_whitelist_ips",
		"destroy k3s_whitelist_ips_tmp",
		"create k3s_hostile_ips_tmp hash:net maxelem 300000 -exist",
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
