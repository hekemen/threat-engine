// Package metrics holds the daemon's runtime counters behind a mutex so the
// HTTP handlers, the scanner, and the scheduler can share them safely.
package metrics

import (
	"sync"
	"time"
)

// Snapshot is a plain copy of the counters, safe to render without holding
// the lock.
type Snapshot struct {
	BlockedIPsCount     int
	WhitelistCount      int
	LastScanUnix        int64
	LastChangeUnix      int64
	ScanSuccessTotal    int64
	ScanFailureTotal    int64
	UpdatesAppliedTotal int64
	// DroppedPacketsTotal and DroppedBytesTotal count the packets and bytes
	// the kernel actually dropped for hostile sources.
	DroppedPacketsTotal uint64
	DroppedBytesTotal   uint64
	// WhitelistBypassedPacketsTotal and WhitelistBypassedBytesTotal count the
	// packets and bytes that matched the whitelist and returned early.
	WhitelistBypassedPacketsTotal uint64
	WhitelistBypassedBytesTotal   uint64
}

// DropCounters carries one reading of the kernel's rule counters.
type DropCounters struct {
	// HostilePackets and HostileBytes are the counters of the DROP rule that
	// matches the hostile set.
	HostilePackets uint64
	HostileBytes   uint64
	// WhitelistPackets and WhitelistBytes are the counters of the RETURN rule
	// that matches the whitelist set.
	WhitelistPackets uint64
	WhitelistBytes   uint64
}

// Metrics is the mutex-guarded counter set.
type Metrics struct {
	mu                  sync.RWMutex
	blockedIPsCount     int
	whitelistCount      int
	lastScanUnix        int64
	lastChangeUnix      int64
	scanSuccessTotal    int64
	scanFailureTotal    int64
	updatesAppliedTotal int64
	lastHash            string

	// Accumulated drop totals and the kernel readings they were derived
	// from. The totals are what /metrics exposes; the last readings are the
	// baseline the next delta is computed against.
	droppedPacketsTotal           uint64
	droppedBytesTotal             uint64
	whitelistBypassedPacketsTotal uint64
	whitelistBypassedBytesTotal   uint64
	lastHostilePackets            uint64
	lastHostileBytes              uint64
	lastWhitelistPackets          uint64
	lastWhitelistBytes            uint64
}

// New returns an empty counter set.
func New() *Metrics { return &Metrics{} }

// RecordScanFailure counts a scan that could not complete.
func (m *Metrics) RecordScanFailure() {
	m.mu.Lock()
	m.scanFailureTotal++
	m.mu.Unlock()
}

// RecordScanSuccess counts a completed scan and stamps its time. The
// whitelist count is only known at scan time, so it is set here too.
func (m *Metrics) RecordScanSuccess(whitelistCount int) {
	m.mu.Lock()
	m.lastScanUnix = time.Now().Unix()
	m.scanSuccessTotal++
	m.whitelistCount = whitelistCount
	m.mu.Unlock()
}

// Fingerprint returns the hash of the rule set currently applied, or "" when
// nothing has been applied yet.
func (m *Metrics) Fingerprint() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastHash
}

// RecordUpdate records a successful kernel update. Callers only invoke this
// after the ipset swap and iptables reconciliation both succeeded, so the
// stored fingerprint always describes what the kernel is actually running.
func (m *Metrics) RecordUpdate(fingerprint string, blockedCount int) {
	m.mu.Lock()
	m.lastHash = fingerprint
	m.blockedIPsCount = blockedCount
	m.lastChangeUnix = time.Now().Unix()
	m.updatesAppliedTotal++
	m.mu.Unlock()
}

// Snapshot copies the counters under a read lock.
func (m *Metrics) Snapshot() Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return Snapshot{
		BlockedIPsCount:               m.blockedIPsCount,
		WhitelistCount:                m.whitelistCount,
		LastScanUnix:                  m.lastScanUnix,
		LastChangeUnix:                m.lastChangeUnix,
		ScanSuccessTotal:              m.scanSuccessTotal,
		ScanFailureTotal:              m.scanFailureTotal,
		UpdatesAppliedTotal:           m.updatesAppliedTotal,
		DroppedPacketsTotal:           m.droppedPacketsTotal,
		DroppedBytesTotal:             m.droppedBytesTotal,
		WhitelistBypassedPacketsTotal: m.whitelistBypassedPacketsTotal,
		WhitelistBypassedBytesTotal:   m.whitelistBypassedBytesTotal,
	}
}

// RecordDropCounters folds a fresh kernel reading into the monotonic totals.
//
// The kernel zeroes a rule's counters whenever the chain is rebuilt, so the
// raw value cannot be exposed as a counter: it can go down, and Prometheus
// would read that as a reset. The increase against the previous reading is
// added to the total instead, and a decrease is treated as a reset, in which
// case the whole new value counts as drops that happened after the reset.
//
// One case cannot be told apart from the outside: a reset followed by enough
// drops to surpass the previous total reads as a normal increase, so those
// drops are undercounted. The totals stay monotonic either way, which is what
// a counter must do.
func (m *Metrics) RecordDropCounters(c DropCounters) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.droppedPacketsTotal += delta(m.lastHostilePackets, c.HostilePackets)
	m.droppedBytesTotal += delta(m.lastHostileBytes, c.HostileBytes)
	m.whitelistBypassedPacketsTotal += delta(m.lastWhitelistPackets, c.WhitelistPackets)
	m.whitelistBypassedBytesTotal += delta(m.lastWhitelistBytes, c.WhitelistBytes)
	m.lastHostilePackets = c.HostilePackets
	m.lastHostileBytes = c.HostileBytes
	m.lastWhitelistPackets = c.WhitelistPackets
	m.lastWhitelistBytes = c.WhitelistBytes
}

// delta returns the increase since the previous reading. A decrease means the
// kernel counter was reset, so everything counted now is new.
func delta(previous, current uint64) uint64 {
	if current < previous {
		return current
	}
	return current - previous
}
