package metrics_test

import (
	"testing"

	"github.com/hekemen/threat-engine/internal/metrics"
)

// The kernel resets a rule's counters whenever the chain is rebuilt, so the
// daemon accumulates deltas instead of exposing the raw value. The totals
// must never go down: a Prometheus counter that decreases is a bug.
func TestRecordDropCountersAccumulatesDeltas(t *testing.T) {
	m := metrics.New()

	m.RecordDropCounters(metrics.DropCounters{
		HostilePackets: 100, HostileBytes: 1000,
		WhitelistPackets: 10, WhitelistBytes: 100,
	})
	m.RecordDropCounters(metrics.DropCounters{
		HostilePackets: 150, HostileBytes: 2500,
		WhitelistPackets: 25, WhitelistBytes: 400,
	})

	s := m.Snapshot()
	if s.DroppedPacketsTotal != 150 {
		t.Fatalf("DroppedPacketsTotal = %d, want 150", s.DroppedPacketsTotal)
	}
	if s.DroppedBytesTotal != 2500 {
		t.Fatalf("DroppedBytesTotal = %d, want 2500", s.DroppedBytesTotal)
	}
	if s.WhitelistBypassedPacketsTotal != 25 {
		t.Fatalf("WhitelistBypassedPacketsTotal = %d, want 25", s.WhitelistBypassedPacketsTotal)
	}
	if s.WhitelistBypassedBytesTotal != 400 {
		t.Fatalf("WhitelistBypassedBytesTotal = %d, want 400", s.WhitelistBypassedBytesTotal)
	}
}

// A chain rebuild resets the kernel counters to zero. The reading after the
// rebuild therefore counts only the drops that happened since, and all of it
// is new. The total must not lose the drops counted before the rebuild.
func TestRecordDropCountersHandlesKernelReset(t *testing.T) {
	m := metrics.New()

	m.RecordDropCounters(metrics.DropCounters{HostilePackets: 100, HostileBytes: 1000})
	// The chain was rebuilt: the kernel counter restarted from zero.
	m.RecordDropCounters(metrics.DropCounters{HostilePackets: 30, HostileBytes: 400})

	s := m.Snapshot()
	if s.DroppedPacketsTotal != 130 {
		t.Fatalf("DroppedPacketsTotal = %d, want 130", s.DroppedPacketsTotal)
	}
	if s.DroppedBytesTotal != 1400 {
		t.Fatalf("DroppedBytesTotal = %d, want 1400", s.DroppedBytesTotal)
	}
}

// A reset to exactly zero, then a rise, must not lose the earlier total.
func TestRecordDropCountersHandlesResetToZero(t *testing.T) {
	m := metrics.New()

	m.RecordDropCounters(metrics.DropCounters{HostilePackets: 100, HostileBytes: 1000})
	m.RecordDropCounters(metrics.DropCounters{}) // chain gone / rebuilt
	m.RecordDropCounters(metrics.DropCounters{HostilePackets: 5, HostileBytes: 60})

	s := m.Snapshot()
	if s.DroppedPacketsTotal != 105 {
		t.Fatalf("DroppedPacketsTotal = %d, want 105", s.DroppedPacketsTotal)
	}
	if s.DroppedBytesTotal != 1060 {
		t.Fatalf("DroppedBytesTotal = %d, want 1060", s.DroppedBytesTotal)
	}
}

// Polling repeatedly while nothing is dropped must not inflate the totals.
func TestRecordDropCountersRepeatedReadingAddsNothing(t *testing.T) {
	m := metrics.New()

	for i := 0; i < 5; i++ {
		m.RecordDropCounters(metrics.DropCounters{HostilePackets: 42, HostileBytes: 420})
	}

	s := m.Snapshot()
	if s.DroppedPacketsTotal != 42 || s.DroppedBytesTotal != 420 {
		t.Fatalf("repeated readings inflated the totals: %+v", s)
	}
}

// The hostile DROP rule and the whitelist RETURN rule are separate counters
// and must not be mixed up.
func TestRecordDropCountersKeepsHostileAndWhitelistSeparate(t *testing.T) {
	m := metrics.New()

	m.RecordDropCounters(metrics.DropCounters{
		HostilePackets: 11, HostileBytes: 1100,
		WhitelistPackets: 22, WhitelistBytes: 2200,
	})

	s := m.Snapshot()
	if s.DroppedPacketsTotal != 11 || s.DroppedBytesTotal != 1100 {
		t.Fatalf("hostile counters wrong: %+v", s)
	}
	if s.WhitelistBypassedPacketsTotal != 22 || s.WhitelistBypassedBytesTotal != 2200 {
		t.Fatalf("whitelist counters wrong: %+v", s)
	}
}
