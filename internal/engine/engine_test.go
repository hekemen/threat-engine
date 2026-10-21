package engine_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/hekemen/threat-engine/internal/adapters"
	"github.com/hekemen/threat-engine/internal/enforcement"
	"github.com/hekemen/threat-engine/internal/engine"
	"github.com/hekemen/threat-engine/internal/ipset"
	"github.com/hekemen/threat-engine/internal/iptables"
	"github.com/hekemen/threat-engine/internal/metrics"
	"github.com/hekemen/threat-engine/internal/runner"
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

// errKernel stands in for a failing `iptables`/`ipset` invocation.
var errKernel = errors.New("exit status 1")

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

// countingExecWithKernel is countingExec with a PREROUTING state machine, so
// `iptables -C PREROUTING` answers like a real kernel instead of always
// succeeding. Use it for tests about attach/detach transitions.
func countingExecWithKernel(calls *[]kernelCall, err error) runner.RunnerFn {
	jumpPresent := false
	return func(ctx context.Context, stdin io.Reader, name string, args ...string) (string, error) {
		body := ""
		if stdin != nil {
			b, _ := io.ReadAll(stdin)
			body = string(b)
		}
		line := strings.Join(args, " ")
		*calls = append(*calls, kernelCall{stdin: body, raw: name + " " + line})

		if strings.Contains(line, "-t raw -C PREROUTING -j THREAD_ENGINE_FILTER") && !jumpPresent {
			return "no such rule", errKernel
		}
		if strings.Contains(line, "-t raw -I PREROUTING") {
			jumpPresent = true
		}
		if strings.Contains(line, "-t raw -D PREROUTING") {
			jumpPresent = false
		}
		return "", err
	}
}

// kernelWithSets models the real dependency between the two subsystems: an
// `iptables` rule that names an ipset fails while that set does not exist, and
// `ipset restore` (whose script contains `create ... -exist`) is what brings
// the sets into being. Without this, a fake happily accepts an attach against
// sets that were never created, which hides the cold-start ordering bug.
func kernelWithSets(calls *[]kernelCall) runner.RunnerFn {
	jumpPresent := false
	sets := map[string]bool{}
	return func(ctx context.Context, stdin io.Reader, name string, args ...string) (string, error) {
		body := ""
		if stdin != nil {
			b, _ := io.ReadAll(stdin)
			body = string(b)
		}
		line := strings.Join(args, " ")
		*calls = append(*calls, kernelCall{stdin: body, raw: name + " " + line})

		if name == "ipset" && strings.Contains(body, "create") {
			for _, f := range strings.Fields(body) {
				if strings.HasPrefix(f, "threat_engine_") && !strings.HasSuffix(f, "_tmp") {
					sets[f] = true
				}
			}
			return "", nil
		}

		if strings.Contains(line, "-t raw -C PREROUTING -j THREAD_ENGINE_FILTER") && !jumpPresent {
			return "no such rule", errKernel
		}
		if strings.Contains(line, "-t raw -I PREROUTING") {
			jumpPresent = true
		}
		if strings.Contains(line, "-t raw -D PREROUTING") {
			jumpPresent = false
		}

		// Any rule referring to a set that was never created is rejected, the
		// way the kernel rejects it: "Set <name> doesn't exist."
		if strings.Contains(line, "--match-set") {
			fields := strings.Fields(line)
			for i, f := range fields {
				if f == "--match-set" && i+1 < len(fields) {
					if !sets[fields[i+1]] {
						return "iptables: Set " + fields[i+1] + " doesn't exist.", errKernel
					}
				}
			}
		}
		return "", nil
	}
}

func newEngine(m *metrics.Metrics, entries []string, exec runner.RunnerFn) *engine.Engine {
	whitelist := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	return &engine.Engine{
		Adapters:    []adapters.FeedAdapter{&fakeAdapter{name: "fake", entries: entries}},
		Whitelist:   whitelist,
		IPSet:       &ipset.Manager{HostileSetName: "threat_engine_hostile_ips", WhitelistSetName: "threat_engine_whitelist_ips", Whitelist: whitelist, Exec: exec},
		Enforcement: enforcement.New(&iptables.Enforcer{HostileSetName: "threat_engine_hostile_ips", WhitelistSetName: "threat_engine_whitelist_ips", Exec: exec}, false),
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
		if strings.Contains(c.stdin, "swap threat_engine_hostile_ips_tmp threat_engine_hostile_ips") {
			sawIpsetRestore = true
		}
	}
	if !sawIpsetRestore {
		t.Fatalf("first scan must sync the ipsets, got calls:\n%s", joined)
	}
	// Disabled means nothing attaches: no chain creation, no jump insert, no
	// rules appended. Checking only -A would miss a chain created empty.
	for _, forbidden := range []string{"-N THREAD_ENGINE_FILTER", "-A THREAD_ENGINE_FILTER"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("enforcement is disabled, so %q must not happen, got:\n%s", forbidden, joined)
		}
	}
	if strings.Contains(joined, "-I PREROUTING") {
		t.Fatalf("disabled enforcement must not hook PREROUTING, got:\n%s", joined)
	}

	calls = nil
	e.ScanAndReconcile(context.Background()) // second scan: identical hash
	// Enforcement is still reconciled every scan, so with it disabled the
	// second scan issues only the Detach teardown — never an ipset sync.
	for _, c := range calls {
		if c.raw == "ipset restore" {
			t.Fatalf("unchanged fingerprint must not re-sync ipsets, got %q", c.raw)
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
		if strings.Contains(c.stdin, "swap threat_engine_hostile_ips_tmp threat_engine_hostile_ips") {
			sawIpsetRestore = true
		}
	}
	if !sawIpsetRestore {
		t.Fatalf("ipsets must be synced even when enforcement is off; calls were %+v", calls)
	}
	for _, c := range calls {
		// Detach legitimately runs -F/-X as teardown. What must never happen
		// while disabled is attachment: creating the chain, hooking PREROUTING,
		// or appending rules.
		for _, forbidden := range []string{"-A THREAD_ENGINE_FILTER", "-N THREAD_ENGINE_FILTER", "-I PREROUTING"} {
			if strings.Contains(c.raw, forbidden) {
				t.Fatalf("disabled enforcement must not attach (saw %q in %q)", forbidden, c.raw)
			}
		}
	}
}

func TestScanAttachesWhenEnforcementEnabled(t *testing.T) {
	var calls []kernelCall
	exec := countingExecWithKernel(&calls, nil)
	e := newEngine(metrics.New(), []string{"1.2.3.4"}, exec)
	e.Enforcement.Set(true)
	e.ScanAndReconcile(context.Background())
	if !strings.Contains(strings.Join(callArgs(calls), "\n"), "-A THREAD_ENGINE_FILTER -m set --match-set threat_engine_hostile_ips src -j DROP") {
		t.Fatalf("enabled enforcement must attach the chain, got:\n%s", strings.Join(callArgs(calls), "\n"))
	}
}

func TestScanDetachesWhenEnforcementDisabled(t *testing.T) {
	var calls []kernelCall
	exec := countingExecWithKernel(&calls, nil)
	e := newEngine(metrics.New(), []string{"1.2.3.4"}, exec)
	e.Enforcement.Set(true)
	e.ScanAndReconcile(context.Background())
	e.Enforcement.Set(false)
	calls = nil
	e.ScanAndReconcile(context.Background()) // fingerprint unchanged, but enforcement must still reconcile
	joined := strings.Join(callArgs(calls), "\n")
	if !strings.Contains(joined, "-X THREAD_ENGINE_FILTER") {
		t.Fatalf("disabling must tear down the chain even on an unchanged fingerprint, got:\n%s", joined)
	}
}

// When enforcement is enabled and the kernel refuses to attach, the scan must
// report the failure rather than pretending to succeed. The ipset sync is
// deliberately skipped: the plan pins enforcement-failure as fatal for the
// cycle so the next tick retries with the fingerprint still dirty.
func TestScanReportsEnforcementFailure(t *testing.T) {
	var calls []kernelCall
	rec := &calls
	e := newEngine(metrics.New(), []string{"1.2.3.4"}, countingExec(&calls, nil))
	e.Enforcement = enforcement.New(&iptables.Enforcer{
		HostileSetName: "threat_engine_hostile_ips", WhitelistSetName: "threat_engine_whitelist_ips",
		Exec: func(ctx context.Context, stdin io.Reader, name string, args ...string) (string, error) {
			*rec = append(*rec, kernelCall{raw: name + " " + strings.Join(args, " ")})
			// The chain cannot be linked: this is the missing-capability case.
			return "iptables: Permission denied", errKernel
		},
	}, true)

	e.ScanAndReconcile(context.Background())

	// The update must not be recorded, so the next scan retries.
	if got := e.Metrics.Snapshot().UpdatesAppliedTotal; got != 0 {
		t.Fatalf("a failed enforcement reconcile must not record an update, got %d", got)
	}
	if got := e.Metrics.Snapshot().ScanSuccessTotal; got != 1 {
		t.Fatalf("the scan itself completed; want 1 success, got %d", got)
	}
}

// Once the chain is hooked, a later enabled scan must not flush and rebuild it:
// the flush window leaves the live chain empty, and Reconcile runs every scan.
func TestScanDoesNotRebuildAnAlreadyAttachedChain(t *testing.T) {
	var calls []kernelCall
	exec := countingExecWithKernel(&calls, nil)
	e := newEngine(metrics.New(), []string{"1.2.3.4"}, exec)
	e.Enforcement.Set(true)
	e.ScanAndReconcile(context.Background()) // first scan attaches

	calls = nil
	e.ScanAndReconcile(context.Background()) // second scan: however the fingerprint fares, enforcement is already on

	joined := strings.Join(callArgs(calls), "\n")
	if strings.Contains(joined, "-F THREAD_ENGINE_FILTER") {
		t.Fatalf("a repeat scan must not flush the live chain, got:\n%s", joined)
	}
	if !strings.Contains(joined, "-t raw -C PREROUTING -j THREAD_ENGINE_FILTER") {
		t.Fatalf("a repeat scan must still verify the jump is present, got:\n%s", joined)
	}
}

// A cold start has no ipsets yet. The enforcement rules name those sets, so
// reconciling before they exist leaves the chain created and hooked but with
// no RETURN/DROP rules in it: enforcement silently does nothing until the next
// scan. The engine must guarantee the sets exist before it attaches.
func TestScanCreatesSetsBeforeAttachingOnColdStart(t *testing.T) {
	var calls []kernelCall
	e := newEngine(metrics.New(), []string{"1.2.3.4"}, kernelWithSets(&calls))
	e.Enforcement.Set(true)

	e.ScanAndReconcile(context.Background())

	joined := strings.Join(callArgs(calls), "\n")
	for _, want := range []string{
		"-A THREAD_ENGINE_FILTER -m set --match-set threat_engine_whitelist_ips src -j RETURN",
		"-A THREAD_ENGINE_FILTER -m set --match-set threat_engine_hostile_ips src -j DROP",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("cold start must populate the chain, missing %q in:\n%s", want, joined)
		}
	}
	if !strings.Contains(joined, "-t raw -I PREROUTING 1 -j THREAD_ENGINE_FILTER") {
		t.Fatalf("chain must be hooked, got:\n%s", joined)
	}
}

// EnsureSets states a prerequisite, not a per-scan obligation. Once the sets
// exist, repeating the call every tick would be pure kernel churn.
func TestScanEnsuresSetsOnlyOnce(t *testing.T) {
	var calls []kernelCall
	e := newEngine(metrics.New(), []string{"1.2.3.4"}, kernelWithSets(&calls))

	countEnsure := func() int {
		n := 0
		for _, c := range calls {
			if strings.Contains(c.stdin, "create threat_engine_hostile_ips hash:net") &&
				!strings.Contains(c.stdin, "flush") {
				n++
			}
		}
		return n
	}

	e.ScanAndReconcile(context.Background())
	if got := countEnsure(); got != 1 {
		t.Fatalf("first scan must ensure the sets exactly once, got %d", got)
	}
	calls = nil
	e.ScanAndReconcile(context.Background())
	if got := countEnsure(); got != 0 {
		t.Fatalf("later scans must not re-ensure the sets, got %d", got)
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

// IPv6 targets must be dropped during aggregation. The kernel sets and the
// iptables enforcement are IPv4-only, so a v6 literal would abort the restore
// with "128 is out of range 0-32" and also could not be enforced.
func TestAggregateDropsIPv6(t *testing.T) {
	var calls []kernelCall
	e := newEngine(metrics.New(), []string{
		"1.2.3.4",
		"2001:1308:a5cc:6600:e157:76a6:16c8:37df",
		"2001:db8::/32",
		"5.6.7.0/24",
	}, countingExec(&calls, nil))

	entries, err := e.Aggregate(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, entry := range entries {
		addr, err := netip.ParseAddr(strings.Split(entry, "/")[0])
		if err != nil {
			t.Fatalf("unparseable aggregated entry %q", entry)
		}
		if !addr.Is4() {
			t.Fatalf("IPv6 entry %q must be filtered out", entry)
		}
	}
	if len(entries) != 2 {
		t.Fatalf("want the two IPv4 entries, got %v", entries)
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
