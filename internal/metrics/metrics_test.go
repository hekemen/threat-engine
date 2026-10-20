package metrics_test

import (
	"sync"
	"testing"

	"github.com/hekemen/thread-engine/internal/metrics"
)

func TestRecordScanSuccessAndFailure(t *testing.T) {
	m := metrics.New()
	m.RecordScanFailure()
	m.RecordScanSuccess(8)
	m.RecordScanSuccess(8)
	s := m.Snapshot()
	if s.ScanFailureTotal != 1 || s.ScanSuccessTotal != 2 || s.WhitelistCount != 8 {
		t.Fatalf("unexpected snapshot: %+v", s)
	}
	if s.LastScanUnix == 0 {
		t.Fatal("LastScanUnix not set by RecordScanSuccess")
	}
}

func TestFingerprintLifecycle(t *testing.T) {
	m := metrics.New()
	if m.Fingerprint() != "" {
		t.Fatalf("fresh metrics fingerprint = %q, want empty", m.Fingerprint())
	}
	m.RecordUpdate("abc123", 1234)
	if m.Fingerprint() != "abc123" {
		t.Fatalf("fingerprint = %q, want abc123", m.Fingerprint())
	}
	s := m.Snapshot()
	if s.BlockedIPsCount != 1234 || s.UpdatesAppliedTotal != 1 || s.LastChangeUnix == 0 {
		t.Fatalf("unexpected snapshot: %+v", s)
	}
}

func TestConcurrentUpdates(t *testing.T) {
	m := metrics.New()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); m.RecordScanSuccess(1) }()
	}
	wg.Wait()
	if m.Snapshot().ScanSuccessTotal != 50 {
		t.Fatalf("lost updates: %d", m.Snapshot().ScanSuccessTotal)
	}
}
