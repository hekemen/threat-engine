// Package kernelstats samples the kernel's drop counters and publishes them
// as monotonic Prometheus counters.
//
// The kernel's own counters cannot be exposed directly: they are reset to
// zero whenever the chain is rebuilt, so the raw value can go down and
// Prometheus would read that as a counter reset. The monitor therefore keeps
// the last reading, adds the increase to a total, and treats a decrease as a
// reset. The published counter therefore only ever grows.
package kernelstats

import (
	"context"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/hekemen/threat-engine/internal/iptables"
	"github.com/hekemen/threat-engine/internal/metrics"
)

// DefaultInterval is the poll interval used when none is configured.
const DefaultInterval = 10 * time.Second

// Reader reads the kernel's per-rule counters.
type Reader interface {
	DropCounters(ctx context.Context) (hostile, whitelist iptables.Counters, err error)
}

// Monitor polls the kernel's rule counters and folds them into the metrics.
type Monitor struct {
	// Reader reads the counters; the iptables enforcer satisfies it.
	Reader Reader
	// Metrics receives the accumulated totals.
	Metrics *metrics.Metrics
	// Interval is the poll period. A non-positive value falls back to
	// DefaultInterval, which keeps the ticker from panicking.
	Interval time.Duration
	// Logger receives the poll failures. A nil Logger falls back to the
	// package-level logger, which is what production uses.
	Logger *zerolog.Logger
}

// warn builds a warning event on the configured logger, falling back to the
// package-level logger when the monitor was not given one.
//
// The fallback is resolved per event rather than once per Run, so a logger
// installed after the monitor started is still picked up.
func (m *Monitor) warn() *zerolog.Event {
	if m.Logger != nil {
		return m.Logger.Warn()
	}
	return log.Warn()
}

// Run polls until ctx is cancelled.
//
// A failed read is logged once and then suppressed while it keeps failing, so
// a broken kernel path cannot flood the log at the poll rate. The totals are
// left untouched by a failure: the last known numbers keep being served.
func (m *Monitor) Run(ctx context.Context) {
	interval := m.Interval
	if interval <= 0 {
		interval = DefaultInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// The error message of the last failure, so the same failure is only
	// logged once. An empty string means "no failure outstanding".
	lastErr := ""

	poll := func() {
		hostile, whitelist, err := m.Reader.DropCounters(ctx)
		if err != nil {
			if ctx.Err() != nil {
				// Shutting down; the cancellation is not a kernel problem.
				return
			}
			if err.Error() != lastErr {
				m.warn().Err(err).Msg("KernelStats: drop counter poll failed")
				lastErr = err.Error()
			}
			return
		}
		lastErr = ""
		m.Metrics.RecordDropCounters(metrics.DropCounters{
			HostilePackets:   hostile.Packets,
			HostileBytes:     hostile.Bytes,
			WhitelistPackets: whitelist.Packets,
			WhitelistBytes:   whitelist.Bytes,
		})
	}

	// Read once up front so the first scrape already carries numbers.
	poll()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			poll()
		}
	}
}
