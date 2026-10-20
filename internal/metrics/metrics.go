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
		BlockedIPsCount:     m.blockedIPsCount,
		WhitelistCount:      m.whitelistCount,
		LastScanUnix:        m.lastScanUnix,
		LastChangeUnix:      m.lastChangeUnix,
		ScanSuccessTotal:    m.scanSuccessTotal,
		ScanFailureTotal:    m.scanFailureTotal,
		UpdatesAppliedTotal: m.updatesAppliedTotal,
	}
}
