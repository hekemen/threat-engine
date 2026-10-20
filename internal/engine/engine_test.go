package engine_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/hekemen/thread-engine/internal/adapters"
	"github.com/hekemen/thread-engine/internal/enforcement"
	"github.com/hekemen/thread-engine/internal/engine"
	"github.com/hekemen/thread-engine/internal/ipset"
	"github.com/hekemen/thread-engine/internal/iptables"
	"github.com/hekemen/thread-engine/internal/metrics"
	"github.com/hekemen/thread-engine/internal/runner"
)

type fakeAdapter struct {
	name    string
	entries []string
	err     error
}

func (f *fakeAdapter) Name() string { return f.name }
func (f *fakeAdapter) Fetch(ctx context.Context, client *http.Client) ([]string, error) {
	return f.entries, f.err
}

type kernelCall struct{ stdin, raw string }

func countingExec(calls *[]kernelCall, err error) runner.RunnerFn {
	return func(ctx context.Context, stdin io.Reader, name string, args ...string) (string, error) {
		body := ""
		if stdin != nil {
			b, _ := io.ReadAll(stdin)
			body = string(b)
		}
		*calls = append(*calls, kernelCall{stdin: body, raw: name + " " + strings.Join(args, " ")})
		return "", err
	}
}

func callArgs(calls []kernelCall) []string {
	out := make([]string, 0, len(calls))
	for _, c := range calls {
		out = append(out, c.raw)
	}
	return out
}

func newEngine(m *metrics.Metrics, entries []string, exec runner.RunnerFn) *engine.Engine {
	whitelist := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	return &engine.Engine{
		Adapters:    []adapters.FeedAdapter{&fakeAdapter{name: "fake", entries: entries}},
		Whitelist:   whitelist,
		IPSet:       &ipset.Manager{HostileSetName: "k3s_hostile_ips", WhitelistSetName: "k3s_whitelist_ips", Whitelist: whitelist, Exec: exec},
		Enforcement: enforcement.New(&iptables.Enforcer{HostileSetName: "k3s_hostile_ips", WhitelistSetName: "k3s_whitelist_ips", Exec: exec}, false),
		Metrics:     m,
		HTTPClient:  &http.Client{},
	}
}

func TestFingerprintVector(t *testing.T) {
	got := engine.Fingerprint([]string{"1.2.3.4", "5.6.7.0/24"})
	const want = "a7c3dc18825d2d37d05ccd6beda643e7eb935c1941ad4958b3aead01f321409c"
	if got != want {
		t.Fatalf("Fingerprint = %s, want %s", got, want)
	}
}

func TestAggregateFiltersWhitelistAndDedupes(t *testing.T) {
	e := newEngine(metrics.New(), []string{"1.2.3.4", "10.0.0.5", "1.2.3.4", "not-an-ip", "  9.9.9.9  ", "10.0.0.0/8"}, nil)
	got, err := e.Aggregate(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"1.2.3.4", "9.9.9.9"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("Aggregate = %v, want %v", got, want)
	}
}

func TestAggregateSkipsFailedAdapter(t *testing.T) {
	e := newEngine(metrics.New(), []string{"1.2.3.4"}, nil)
	e.Adapters = []adapters.FeedAdapter{
		&fakeAdapter{name: "broken", err: errors.New("network down")},
		&fakeAdapter{name: "good", entries: []string{"1.2.3.4"}},
	}
	got, err := e.Aggregate(context.Background())
	if err != nil {
		t.Fatalf("aggregate must not fail when one adapter fails: %v", err)
	}
	if len(got) != 1 || got[0] != "1.2.3.4" {
		t.Fatalf("Aggregate = %v, want [1.2.3.4]", got)
	}
}

func TestAggregateSortsEntries(t *testing.T) {
	e := newEngine(metrics.New(), []string{"9.9.9.9", "1.2.3.4", "5.6.7.8"}, nil)
	got, _ := e.Aggregate(context.Background())
	for i := 1; i < len(got); i++ {
		if got[i-1] > got[i] {
			t.Fatalf("entries not sorted: %v", got)
		}
	}
}

func TestScanAndReconcileSkipsKernelOnUnchangedFingerprint(t *testing.T) {
	entries := []string{"1.2.3.4", "5.6.7.0/24"}
	var calls []kernelCall
	m := metrics.New()
	e := newEngine(m, entries, countingExec(&calls, nil))
	e.ScanAndReconcile(context.Background()) // first scan: applies

	// Enforcement is disabled in newEngine. The disabled reconcile runs its
	// Detach probe first, so the ipset restore is no longer call[0] — assert
	// that it happened, and that no rules were installed.
	joined := strings.Join(callArgs(calls), "\n")
	var sawIpsetRestore bool
	for _, c := range calls {
		if strings.Contains(c.stdin, "swap k3s_hostile_ips_tmp k3s_hostile_ips") {
			sawIpsetRestore = true
		}
	}
	if !sawIpsetRestore {
		t.Fatalf("first scan must sync the ipsets, got calls:\n%s", joined)
	}
	if strings.Contains(joined, "-A K3S_THREAT_FILTER") {
		t.Fatalf("enforcement is disabled, so no rules may be installed, got:\n%s", joined)
	}

	calls = nil
	e.ScanAndReconcile(context.Background()) // second scan: identical hash
	if len(calls) != 0 {
		// Enforcement is still reconciled every scan, so with it disabled the
		// second scan issues only the Detach teardown — never an ipset sync.
		for _, c := range calls {
			if c.raw == "ipset restore" {
				t.Fatalf("unchanged fingerprint must not re-sync ipsets, got %q", c.raw)
			}
		}
	}
	if m.Snapshot().ScanSuccessTotal != 2 {
		t.Fatalf("both scans must count as success: %+v", m.Snapshot())
	}
}

func TestScanPopulatesIpsetsButSkipsIptablesWhenDisabled(t *testing.T) {
	var calls []kernelCall
	m := metrics.New()
	exec := countingExec(&calls, nil)
	e := newEngine(m, []string{"1.2.3.4"}, exec) // newEngine constructs the controller with enforcement disabled
	e.ScanAndReconcile(context.Background())

	// The ipset restore must happen even though enforcement is off. It is no
	// longer necessarily the first call: the disabled reconcile runs a Detach
	// probe first.
	var sawIpsetRestore bool
	for _, c := range calls {
		if strings.Contains(c.stdin, "swap k3s_hostile_ips_tmp k3s_hostile_ips") {
			sawIpsetRestore = true
		}
	}
	if !sawIpsetRestore {
		t.Fatalf("ipsets must be synced even when enforcement is off; calls were %+v", calls)
	}
	for _, c := range calls {
		if strings.Contains(c.raw, "-A K3S_THREAT_FILTER") {
			t.Fatalf("disabled enforcement must not install rules, saw %q", c.raw)
		}
	}
}

func TestScanAttachesWhenEnforcementEnabled(t *testing.T) {
	var calls []kernelCall
	exec := countingExec(&calls, nil)
	e := newEngine(metrics.New(), []string{"1.2.3.4"}, exec)
	e.Enforcement.Set(true)
	e.ScanAndReconcile(context.Background())
	if !strings.Contains(strings.Join(callArgs(calls), "\n"), "-A K3S_THREAT_FILTER -m set --match-set k3s_hostile_ips src -j DROP") {
		t.Fatalf("enabled enforcement must attach the chain, got:\n%s", strings.Join(callArgs(calls), "\n"))
	}
}

func TestScanDetachesWhenEnforcementDisabled(t *testing.T) {
	var calls []kernelCall
	exec := countingExec(&calls, nil)
	e := newEngine(metrics.New(), []string{"1.2.3.4"}, exec)
	e.Enforcement.Set(true)
	e.ScanAndReconcile(context.Background())
	e.Enforcement.Set(false)
	calls = nil
	e.ScanAndReconcile(context.Background()) // fingerprint unchanged, but enforcement must still reconcile
	joined := strings.Join(callArgs(calls), "\n")
	if !strings.Contains(joined, "-X K3S_THREAT_FILTER") {
		t.Fatalf("disabling must tear down the chain even on an unchanged fingerprint, got:\n%s", joined)
	}
}

func TestScanAndReconcileRecordsUpdateOnChange(t *testing.T) {
	m := metrics.New()
	e := newEngine(m, []string{"1.2.3.4"}, countingExec(&[]kernelCall{}, nil))
	e.ScanAndReconcile(context.Background())
	if m.Snapshot().UpdatesAppliedTotal != 1 || m.Snapshot().BlockedIPsCount != 1 {
		t.Fatalf("unexpected snapshot: %+v", m.Snapshot())
	}
	if m.Fingerprint() != engine.Fingerprint([]string{"1.2.3.4"}) {
		t.Fatalf("fingerprint not recorded: %q", m.Fingerprint())
	}
}

func TestScanAndReconcileDoesNotRecordUpdateOnSyncFailure(t *testing.T) {
	m := metrics.New()
	var calls []kernelCall
	e := newEngine(m, []string{"1.2.3.4"}, countingExec(&calls, errors.New("denied")))
	e.ScanAndReconcile(context.Background())
	if m.Fingerprint() != "" || m.Snapshot().UpdatesAppliedTotal != 0 {
		t.Fatal("failed sync must not update fingerprint or counters")
	}
	if m.Snapshot().ScanSuccessTotal != 1 {
		t.Fatalf("scan itself succeeded, so success counter must increment: %+v", m.Snapshot())
	}
}

func TestIsWhitelisted(t *testing.T) {
	e := newEngine(metrics.New(), nil, nil)
	if !e.IsWhitelisted(netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("private address must be whitelisted")
	}
	if e.IsWhitelisted(netip.MustParseAddr("1.2.3.4")) {
		t.Fatal("public address must not be whitelisted")
	}
}
