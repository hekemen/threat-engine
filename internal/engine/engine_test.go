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

type kernelCall struct{ stdin string }

func countingExec(calls *[]kernelCall, err error) runner.RunnerFn {
	return func(ctx context.Context, stdin io.Reader, name string, args ...string) (string, error) {
		body := ""
		if stdin != nil {
			b, _ := io.ReadAll(stdin)
			body = string(b)
		}
		*calls = append(*calls, kernelCall{body})
		return "", err
	}
}

func newEngine(m *metrics.Metrics, entries []string, exec runner.RunnerFn) *engine.Engine {
	whitelist := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	return &engine.Engine{
		Adapters:   []adapters.FeedAdapter{&fakeAdapter{name: "fake", entries: entries}},
		Whitelist:  whitelist,
		IPSet:      &ipset.Manager{HostileSetName: "k3s_hostile_ips", WhitelistSetName: "k3s_whitelist_ips", Whitelist: whitelist, Exec: exec},
		Firewall:   &iptables.Enforcer{HostileSetName: "k3s_hostile_ips", WhitelistSetName: "k3s_whitelist_ips", Exec: exec},
		Metrics:    m,
		HTTPClient: &http.Client{},
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
	// 1 ipset restore + 5 iptables calls (-N, -C, -F, -A RETURN, -A DROP; no insert since -C succeeds)
	if len(calls) != 6 {
		t.Fatalf("first scan: got %d kernel calls, want 6: %+v", len(calls), calls)
	}
	if !strings.Contains(calls[0].stdin, "swap k3s_hostile_ips_tmp k3s_hostile_ips") {
		t.Fatalf("first kernel call must be the ipset restore script, got stdin %q", calls[0].stdin)
	}
	calls = nil
	e.ScanAndReconcile(context.Background()) // second scan: identical hash
	if len(calls) != 0 {
		t.Fatalf("unchanged fingerprint must skip kernel work, got %d calls", len(calls))
	}
	if m.Snapshot().ScanSuccessTotal != 2 {
		t.Fatalf("both scans must count as success: %+v", m.Snapshot())
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
