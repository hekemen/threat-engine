// Package api exposes the daemon's HTTP surface: a readiness probe, an
// on-demand membership check against the live kernel sets, and Prometheus
// metrics.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rs/zerolog/log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
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
	// AdminSocket is the unix domain socket path for admin control.
	AdminSocket string
	// EnforcementLocked prevents runtime changes when true.
	EnforcementLocked bool
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

// AdminSocketServer listens on a unix domain socket for admin control.
// On Linux, socket permissions can be used to restrict access.
func (s *Server) AdminSocketServer() *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/enforcement", s.handleEnforcement)
	return &http.Server{Handler: mux}
}

// ListenAdminSocket creates and listens on the admin unix socket.
func (s *Server) ListenAdminSocket() (net.Listener, error) {
	if s.AdminSocket == "" {
		return nil, nil
	}
	if err := os.Remove(s.AdminSocket); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(s.AdminSocket), 0755); err != nil {
		return nil, err
	}
	ln, err := net.Listen("unix", s.AdminSocket)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(s.AdminSocket, 0660)
	return ln, nil
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
		if s.EnforcementLocked || (s.Enforcement != nil && s.Enforcement.Locked()) {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"enforcement is locked by environment variable"}`))
			return
		}
		enabled, ok := parseBoolArg(r.URL.Query().Get("enabled"))
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"enabled parameter must be true or false"}`))
			return
		}
		if s.Enforcement == nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"enforcement is not configured on this server"}`))
			return
		}
		// The chain's rules reference the kernel sets by name, and iptables
		// refuses to install a `--match-set` rule while the set does not exist
		// ("Set threat_engine_whitelist_ips doesn't exist"). The sets are
		// normally created by the first scan, so an operator toggling
		// enforcement before that scan finished would hit that error and end
		// up with no rules at all.
		//
		// EnsureSets states the prerequisite explicitly. It is idempotent
		// (`create ... -exist`) and never flushes or swaps, so a populated set
		// survives untouched.
		if enabled && s.IPSet != nil {
			if err := s.IPSet.EnsureSets(r.Context()); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error()})
				return
			}
		}
		if err := s.Enforcement.SetAndReconcile(r.Context(), enabled); err != nil {
			if errors.Is(err, enforcement.ErrLocked) {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"error":"enforcement is locked by environment variable"}`))
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error()})
			return
		}
		log.Info().Bool("enabled", enabled).Msg("Enforcement toggled via admin API")
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
//
// The drop counters are read from memory: the scrape path never shells out,
// so a scrape cannot block on the kernel.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	snap := s.Metrics.Snapshot()

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	fmt.Fprintf(w, "# HELP threat_engine_blocked_targets Number of hostile IPs/CIDRs currently blocked in kernel\n")
	fmt.Fprintf(w, "# TYPE threat_engine_blocked_targets gauge\n")
	fmt.Fprintf(w, "threat_engine_blocked_targets %d\n\n", snap.BlockedIPsCount)

	// Deprecated aliases. The `_total` suffix is reserved for counters, so a
	// gauge wearing it is a lint violation. The old names are kept for one
	// release cycle so existing dashboards do not silently go blank.
	fmt.Fprintf(w, "# HELP threat_engine_blocked_targets_total DEPRECATED: use threat_engine_blocked_targets instead. Number of hostile IPs/CIDRs currently blocked in kernel\n")
	fmt.Fprintf(w, "# TYPE threat_engine_blocked_targets_total gauge\n")
	fmt.Fprintf(w, "threat_engine_blocked_targets_total %d\n\n", snap.BlockedIPsCount)

	fmt.Fprintf(w, "# HELP threat_engine_whitelist_entries Active whitelist subnets\n")
	fmt.Fprintf(w, "# TYPE threat_engine_whitelist_entries gauge\n")
	fmt.Fprintf(w, "threat_engine_whitelist_entries %d\n\n", snap.WhitelistCount)

	fmt.Fprintf(w, "# HELP threat_engine_whitelist_entries_total DEPRECATED: use threat_engine_whitelist_entries instead. Active whitelist subnets\n")
	fmt.Fprintf(w, "# TYPE threat_engine_whitelist_entries_total gauge\n")
	fmt.Fprintf(w, "threat_engine_whitelist_entries_total %d\n\n", snap.WhitelistCount)

	fmt.Fprintf(w, "# HELP threat_engine_scans_total Total scheduled scan attempts\n")
	fmt.Fprintf(w, "# TYPE threat_engine_scans_total counter\n")
	fmt.Fprintf(w, "threat_engine_scans_total{status=\"success\"} %d\n", snap.ScanSuccessTotal)
	fmt.Fprintf(w, "threat_engine_scans_total{status=\"failure\"} %d\n\n", snap.ScanFailureTotal)

	fmt.Fprintf(w, "# HELP threat_engine_updates_applied_total Times a change triggered an ipset swap\n")
	fmt.Fprintf(w, "# TYPE threat_engine_updates_applied_total counter\n")
	fmt.Fprintf(w, "threat_engine_updates_applied_total %d\n\n", snap.UpdatesAppliedTotal)

	fmt.Fprintf(w, "# HELP threat_engine_dropped_packets_total Packets dropped by the kernel for hostile sources\n")
	fmt.Fprintf(w, "# TYPE threat_engine_dropped_packets_total counter\n")
	fmt.Fprintf(w, "threat_engine_dropped_packets_total %d\n\n", snap.DroppedPacketsTotal)

	fmt.Fprintf(w, "# HELP threat_engine_dropped_bytes_total Bytes dropped by the kernel for hostile sources\n")
	fmt.Fprintf(w, "# TYPE threat_engine_dropped_bytes_total counter\n")
	fmt.Fprintf(w, "threat_engine_dropped_bytes_total %d\n\n", snap.DroppedBytesTotal)

	fmt.Fprintf(w, "# HELP threat_engine_whitelist_bypassed_packets_total Packets let through by the whitelist bypass\n")
	fmt.Fprintf(w, "# TYPE threat_engine_whitelist_bypassed_packets_total counter\n")
	fmt.Fprintf(w, "threat_engine_whitelist_bypassed_packets_total %d\n\n", snap.WhitelistBypassedPacketsTotal)

	fmt.Fprintf(w, "# HELP threat_engine_whitelist_bypassed_bytes_total Bytes let through by the whitelist bypass\n")
	fmt.Fprintf(w, "# TYPE threat_engine_whitelist_bypassed_bytes_total counter\n")
	fmt.Fprintf(w, "threat_engine_whitelist_bypassed_bytes_total %d\n\n", snap.WhitelistBypassedBytesTotal)

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
