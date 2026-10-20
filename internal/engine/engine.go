// Package engine orchestrates one scan cycle: poll every adapter, normalize
// and filter the results, and reconcile the kernel only when the resulting
// set actually changed.
package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"github.com/hekemen/thread-engine/internal/adapters"
	"github.com/hekemen/thread-engine/internal/ipset"
	"github.com/hekemen/thread-engine/internal/iptables"
	"github.com/hekemen/thread-engine/internal/metrics"
)

// Engine owns the scan-reconcile pipeline. Every collaborator is injected so
// the pipeline can be driven in tests without network or kernel access.
type Engine struct {
	Adapters  []adapters.FeedAdapter
	Whitelist []netip.Prefix
	IPSet     *ipset.Manager
	Firewall  *iptables.Enforcer
	Metrics   *metrics.Metrics
	// HTTPClient is shared by all adapters for one scan.
	HTTPClient *http.Client
}

// IsWhitelisted reports whether addr falls inside any configured whitelist
// prefix. Whitelisted addresses are dropped during aggregation, so they never
// reach the hostile set.
func (e *Engine) IsWhitelisted(addr netip.Addr) bool {
	for _, p := range e.Whitelist {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// Aggregate polls every adapter concurrently and returns the deduplicated,
// whitelist-filtered, sorted set of targets. A failing adapter is logged and
// skipped; the scan proceeds with whatever the healthy sources returned.
func (e *Engine) Aggregate(ctx context.Context) ([]string, error) {
	var wg sync.WaitGroup
	resultsChan := make(chan []string, len(e.Adapters))

	for _, adapter := range e.Adapters {
		wg.Add(1)
		go func(a adapters.FeedAdapter) {
			defer wg.Done()
			entries, err := a.Fetch(ctx, e.HTTPClient)
			if err != nil {
				log.Printf("[%s Adapter] Fetch failed: %v", a.Name(), err)
				return
			}
			log.Printf("[%s Adapter] Retrieved %d candidate entries", a.Name(), len(entries))
			resultsChan <- entries
		}(adapter)
	}

	wg.Wait()
	close(resultsChan)

	uniqueEntries := make(map[string]struct{})
	for batch := range resultsChan {
		for _, raw := range batch {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}

			// Validate CIDR or Single IP
			if strings.Contains(raw, "/") {
				prefix, err := netip.ParsePrefix(raw)
				if err != nil || e.IsWhitelisted(prefix.Addr()) {
					continue
				}
				uniqueEntries[prefix.String()] = struct{}{}
			} else {
				addr, err := netip.ParseAddr(raw)
				if err != nil || e.IsWhitelisted(addr) {
					continue
				}
				uniqueEntries[addr.String()] = struct{}{}
			}
		}
	}

	sorted := make([]string, 0, len(uniqueEntries))
	for entry := range uniqueEntries {
		sorted = append(sorted, entry)
	}
	sort.Strings(sorted)

	return sorted, nil
}

// Fingerprint hashes a sorted entry list. It is the change-detection key: an
// identical fingerprint means the kernel set is already correct.
func Fingerprint(entries []string) string {
	h := sha256.New()
	for _, entry := range entries {
		h.Write([]byte(entry))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ScanAndReconcile runs one full cycle. The fingerprint is recorded only after
// both kernel steps succeed, so a partial failure leaves the previous
// fingerprint in place and the next tick retries.
func (e *Engine) ScanAndReconcile(ctx context.Context) {
	log.Printf("[Scanner] Starting feed poll across %d adapters...", len(e.Adapters))

	entries, err := e.Aggregate(ctx)
	if err != nil {
		log.Printf("[Scanner Error] Aggregation encountered issues: %v", err)
		e.Metrics.RecordScanFailure()
		return
	}

	fingerprint := Fingerprint(entries)

	e.Metrics.RecordScanSuccess(len(e.Whitelist))

	// Change Detection Guard
	if fingerprint == e.Metrics.Fingerprint() {
		log.Printf("[Scanner] SHA-256 fingerprint matches (%s). Zero changes detected; skipping kernel update.", fingerprint[:12])
		return
	}

	log.Printf("[Scanner] Change detected! New fingerprint: %s. Reconciling %d unique targets...", fingerprint[:12], len(entries))

	if err := e.IPSet.Sync(ctx, entries); err != nil {
		log.Printf("[Kernel Error] ipset swap failure: %v", err)
		return
	}

	if err := e.Firewall.EnsureChain(ctx); err != nil {
		log.Printf("[Kernel Error] iptables chain configuration failed: %v", err)
		return
	}

	e.Metrics.RecordUpdate(fingerprint, len(entries))

	log.Printf("[Scanner Complete] Successfully applied updated rules. Blocklist entries: %d", len(entries))
}
