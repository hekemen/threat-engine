// Package api exposes the daemon's HTTP surface: a readiness probe, an
// on-demand membership check against the live kernel sets, and Prometheus
// metrics.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/hekemen/threat-engine/internal/enforcement"
	"github.com/hekemen/threat-engine/internal/ipset"
	"github.com/hekemen/threat-engine/internal/metrics"
)

// Server holds the dependencies the handlers read from.
type Server struct {
	Metrics *metrics.Metrics
	IPSet   *ipset.Manager
	Port    string
	// Enforcement gates whether the kernel drop rules are attached. A nil
	// controller means enforcement is not configured, which reads as disabled.
	Enforcement *enforcement.Controller
	// AdminPort is the loopback-only admin listener's port.
	AdminPort string
}

// enforcementEnabled reports the current enforcement state. A nil controller
// (Server built without one) means enforcement is not configured, which reads
// the same as disabled.
func (s *Server) enforcementEnabled() bool {
	return s.Enforcement != nil && s.Enforcement.Enabled()
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

// AdminHandler builds the mutating routing table. It is deliberately separate
// from Handler: the public listener stays read-only, so the only way to change
// enforcement is over the loopback-bound admin listener.
func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/enforcement", s.handleEnforcement)
	return mux
}

// AdminHTTPServer binds the admin surface to loopback only. Off-host callers
// and other pods cannot reach it; on Kubernetes use kubectl port-forward or
// kubectl exec.
func (s *Server) AdminHTTPServer() *http.Server {
	return &http.Server{Addr: "127.0.0.1:" + s.AdminPort, Handler: s.AdminHandler()}
}

// parseBoolArg accepts the same spellings as the ENFORCEMENT_ENABLED env var.
func parseBoolArg(raw string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "1", "yes":
		return true, true
	case "false", "0", "no":
		return false, true
	default:
		return false, false
	}
}

// handleEnforcement reads or flips the enforcement flag. GET reports the
// current state; POST applies a new one and reconciles the kernel immediately.
func (s *Server) handleEnforcement(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		json.NewEncoder(w).Encode(map[string]interface{}{
			"enforcement_enabled": s.enforcementEnabled(),
		})
	case http.MethodPost:
		enabled, ok := parseBoolArg(r.URL.Query().Get("enabled"))
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"enabled parameter must be true or false"}`))
			return
		}
		if s.Enforcement == nil {
			// A Server without a controller cannot change anything. Reporting
			// success here would tell an operator their firewall changed when
			// nothing happened, so refuse instead.
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"enforcement is not configured on this server"}`))
			return
		}
		if err := s.Enforcement.SetAndReconcile(r.Context(), enabled); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error()})
			return
		}
		log.Printf("[Enforcement] toggled via admin API: enabled=%v", enabled)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"enforcement_enabled": s.enforcementEnabled(),
		})
	default:
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
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

	// Deliberately not r.Context(): the baseline ran `ipset test` uncancellably,
	// and Contains maps any error to "not a member". A client that aborts
	// mid-request would otherwise have a blocked address classified as allowed.
	ctx := context.Background()
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
		"ip":                  addr.String(),
		"status":              status,
		"is_blocked":          isBlocked,
		"is_whitelisted":      isWhitelisted,
		"enforcement_enabled": s.enforcementEnabled(),
		"timestamp":           time.Now().UTC().Format(time.RFC3339),
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

	fmt.Fprintf(w, "# HELP threat_engine_enforcement_enabled Whether hostile DROP rules are attached to PREROUTING (1) or inert (0)\n")
	fmt.Fprintf(w, "# TYPE threat_engine_enforcement_enabled gauge\n")
	enabled := 0
	if s.enforcementEnabled() {
		enabled = 1
	}
	fmt.Fprintf(w, "threat_engine_enforcement_enabled %d\n\n", enabled)

	fmt.Fprintf(w, "# HELP threat_engine_last_scan_timestamp Unix timestamp of latest scan execution\n")
	fmt.Fprintf(w, "# TYPE threat_engine_last_scan_timestamp gauge\n")
	fmt.Fprintf(w, "threat_engine_last_scan_timestamp %d\n\n", snap.LastScanUnix)

	fmt.Fprintf(w, "# HELP threat_engine_last_change_timestamp Unix timestamp when rules were last updated\n")
	fmt.Fprintf(w, "# TYPE threat_engine_last_change_timestamp gauge\n")
	fmt.Fprintf(w, "threat_engine_last_change_timestamp %d\n", snap.LastChangeUnix)
}
