package kernelstats_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/hekemen/threat-engine/internal/iptables"
	"github.com/hekemen/threat-engine/internal/kernelstats"
	"github.com/hekemen/threat-engine/internal/metrics"
)

// fakeReader is a scripted kernel reader.
type fakeReader struct {
	mu        sync.Mutex
	calls     int
	hostile   iptables.Counters
	whitelist iptables.Counters
	err       error
	// called is signalled on every read so tests can wait for a poll.
	called chan struct{}
}

func newFakeReader() *fakeReader {
	return &fakeReader{called: make(chan struct{}, 64)}
}

func (f *fakeReader) DropCounters(ctx context.Context) (iptables.Counters, iptables.Counters, error) {
	f.mu.Lock()
	f.calls++
	hostile, whitelist, err := f.hostile, f.whitelist, f.err
	f.mu.Unlock()

	select {
	case f.called <- struct{}{}:
	default:
	}
	return hostile, whitelist, err
}

func (f *fakeReader) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// syncBuffer is a concurrency-safe log sink. The monitor logs from its own
// goroutine while the test reads the captured output.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// captureLogger returns a logger writing into a thread-safe buffer.
//
// The logger is injected into the monitor rather than installed globally:
// swapping the package-level logger would race with any goroutine that is
// still logging, and a monitor goroutine from an earlier test outlives the
// test that started it.
func captureLogger() (*zerolog.Logger, *syncBuffer) {
	buf := &syncBuffer{}
	logger := zerolog.New(buf)
	return &logger, buf
}

// startMonitor runs the monitor in the background and returns a stop function
// that cancels the context and waits for the goroutine to finish.
//
// Waiting matters: a monitor that outlives its test keeps logging into the
// next test's buffer and races with it.
func startMonitor(t *testing.T, mon *kernelstats.Monitor) (cancel context.CancelFunc, wait func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		mon.Run(ctx)
	}()
	return cancel, func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("monitor did not stop after the context was cancelled")
		}
	}
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestMonitorRecordsKernelCounters(t *testing.T) {
	reader := newFakeReader()
	reader.hostile = iptables.Counters{Packets: 100, Bytes: 1000}
	reader.whitelist = iptables.Counters{Packets: 10, Bytes: 100}

	m := metrics.New()
	mon := &kernelstats.Monitor{Reader: reader, Metrics: m, Interval: 10 * time.Millisecond}

	cancel, wait := startMonitor(t, mon)
	defer wait()
	defer cancel()

	waitFor(t, "the first poll", func() bool { return reader.count() > 0 })
	waitFor(t, "the counters to be recorded", func() bool {
		s := m.Snapshot()
		return s.DroppedPacketsTotal == 100 && s.DroppedBytesTotal == 1000 &&
			s.WhitelistBypassedPacketsTotal == 10 && s.WhitelistBypassedBytesTotal == 100
	})
}

// Repeated polls with an unchanged kernel reading must not inflate the totals.
func TestMonitorRepeatedPollsDoNotInflateTotals(t *testing.T) {
	reader := newFakeReader()
	reader.hostile = iptables.Counters{Packets: 100, Bytes: 1000}

	m := metrics.New()
	mon := &kernelstats.Monitor{Reader: reader, Metrics: m, Interval: 5 * time.Millisecond}

	cancel, wait := startMonitor(t, mon)
	defer wait()
	defer cancel()

	waitFor(t, "several polls", func() bool { return reader.count() >= 5 })
	cancel()
	wait()

	s := m.Snapshot()
	if s.DroppedPacketsTotal != 100 || s.DroppedBytesTotal != 1000 {
		t.Fatalf("totals inflated by repeated polls: %+v", s)
	}
}

// A failing read must not wipe the totals: the last known numbers keep being
// served until the kernel answers again.
func TestMonitorKeepsLastTotalOnError(t *testing.T) {
	reader := newFakeReader()
	reader.hostile = iptables.Counters{Packets: 100, Bytes: 1000}

	m := metrics.New()
	mon := &kernelstats.Monitor{Reader: reader, Metrics: m, Interval: 5 * time.Millisecond}

	cancel, wait := startMonitor(t, mon)
	defer wait()
	defer cancel()

	waitFor(t, "the first successful poll", func() bool { return m.Snapshot().DroppedPacketsTotal == 100 })

	reader.mu.Lock()
	reader.err = errors.New("iptables: Permission denied")
	reader.mu.Unlock()

	time.Sleep(50 * time.Millisecond)
	cancel()
	wait()

	if s := m.Snapshot(); s.DroppedPacketsTotal != 100 {
		t.Fatalf("error lost the total: %+v", s)
	}
}

// A persistent failure must be logged once, not once per poll.
func TestMonitorLogsErrorOnce(t *testing.T) {
	logger, buf := captureLogger()

	reader := newFakeReader()
	reader.err = errors.New("iptables: Permission denied")

	mon := &kernelstats.Monitor{
		Reader:   reader,
		Metrics:  metrics.New(),
		Interval: 5 * time.Millisecond,
		Logger:   logger,
	}

	cancel, wait := startMonitor(t, mon)
	defer wait()
	defer cancel()

	waitFor(t, "several polls", func() bool { return reader.count() >= 5 })
	cancel()
	wait()

	if n := strings.Count(buf.String(), "Permission denied"); n != 1 {
		t.Fatalf("error logged %d times, want exactly 1:\n%s", n, buf.String())
	}
}

// The monitor must stop when its context is cancelled.
func TestMonitorStopsOnContextCancel(t *testing.T) {
	reader := newFakeReader()
	mon := &kernelstats.Monitor{Reader: reader, Metrics: metrics.New(), Interval: 5 * time.Millisecond}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		mon.Run(ctx)
		close(done)
	}()

	waitFor(t, "the first poll", func() bool { return reader.count() > 0 })
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after the context was cancelled")
	}
}

// A zero interval must not panic the ticker.
func TestMonitorZeroIntervalDoesNotPanic(t *testing.T) {
	reader := newFakeReader()
	mon := &kernelstats.Monitor{Reader: reader, Metrics: metrics.New()}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		mon.Run(ctx)
		close(done)
	}()

	waitFor(t, "the first poll", func() bool { return reader.count() > 0 })
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after the context was cancelled")
	}
}
