// Package api exposes the daemon's HTTP surface: a readiness probe, an
// on-demand membership check against the live kernel sets, and Prometheus
// metrics.
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/hekemen/thread-engine/internal/ipset"
	"github.com/hekemen/thread-engine/internal/metrics"
)

// Server holds the dependencies the handlers read from.
type Server struct {
	Metrics *metrics.Metrics
	IPSet   *ipset.Manager
	Port    string
}

// Handler builds the routing table.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/check", s.handleCheck)
	mux.HandleFunc("/metrics", s.handleMetrics)

	return mux
}

// HTTPServer wraps Handler in a server listening on the configured port.
func (s *Server) HTTPServer() *http.Server {
	return &http.Server{Addr: ":" + s.Port, Handler: s.Handler()}
}

// handleHealthz reports ready only once a first scan has completed, so
// orchestrators do not route traffic to a daemon with no rules loaded.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if s.Metrics.Snapshot().LastScanUnix == 0 {
		http.Error(w, "Initializing", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok\n"))
}

// handleCheck answers whether an address is currently blocked, whitelisted, or
// unlisted, by testing the live kernel sets.
func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if ip == "" {
		http.Error(w, `{"error":"ip parameter required"}`, http.StatusBadRequest)
		return
	}

	addr, err := netip.ParseAddr(ip)
	if err != nil {
		http.Error(w, `{"error":"invalid ip"}`, http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	isBlocked := s.IPSet.Contains(ctx, s.IPSet.HostileSetName, addr)
	isWhitelisted := s.IPSet.Contains(ctx, s.IPSet.WhitelistSetName, addr)

	status := "allowed"
	if isWhitelisted {
		status = "whitelisted"
	} else if isBlocked {
		status = "blocked"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ip":             addr.String(),
		"status":         status,
		"is_blocked":     isBlocked,
		"is_whitelisted": isWhitelisted,
		"timestamp":      time.Now().UTC().Format(time.RFC3339),
	})
}

// handleMetrics renders the Prometheus exposition format by hand; the daemon
// carries no metrics dependency.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	snap := s.Metrics.Snapshot()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintf(w, "# HELP threat_engine_blocked_targets_total Number of hostile IPs/CIDRs currently blocked in kernel\n")
	fmt.Fprintf(w, "# TYPE threat_engine_blocked_targets_total gauge\n")
	fmt.Fprintf(w, "threat_engine_blocked_targets_total %d\n\n", snap.BlockedIPsCount)

	fmt.Fprintf(w, "# HELP threat_engine_whitelist_entries_total Active whitelist subnets\n")
	fmt.Fprintf(w, "# TYPE threat_engine_whitelist_entries_total gauge\n")
	fmt.Fprintf(w, "threat_engine_whitelist_entries_total %d\n\n", snap.WhitelistCount)

	fmt.Fprintf(w, "# HELP threat_engine_scans_total Total scheduled scan attempts\n")
	fmt.Fprintf(w, "# TYPE threat_engine_scans_total counter\n")
	fmt.Fprintf(w, "threat_engine_scans_total{status=\"success\"} %d\n", snap.ScanSuccessTotal)
	fmt.Fprintf(w, "threat_engine_scans_total{status=\"failure\"} %d\n\n", snap.ScanFailureTotal)

	fmt.Fprintf(w, "# HELP threat_engine_updates_applied_total Times a change triggered an ipset swap\n")
	fmt.Fprintf(w, "# TYPE threat_engine_updates_applied_total counter\n")
	fmt.Fprintf(w, "threat_engine_updates_applied_total %d\n\n", snap.UpdatesAppliedTotal)

	fmt.Fprintf(w, "# HELP threat_engine_last_scan_timestamp Unix timestamp of latest scan execution\n")
	fmt.Fprintf(w, "# TYPE threat_engine_last_scan_timestamp gauge\n")
	fmt.Fprintf(w, "threat_engine_last_scan_timestamp %d\n\n", snap.LastScanUnix)

	fmt.Fprintf(w, "# HELP threat_engine_last_change_timestamp Unix timestamp when rules were last updated\n")
	fmt.Fprintf(w, "# TYPE threat_engine_last_change_timestamp gauge\n")
	fmt.Fprintf(w, "threat_engine_last_change_timestamp %d\n", snap.LastChangeUnix)
}
