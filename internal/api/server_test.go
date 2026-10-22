package api_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/hekemen/threat-engine/internal/api"
	"github.com/hekemen/threat-engine/internal/enforcement"
	"github.com/hekemen/threat-engine/internal/ipset"
	"github.com/hekemen/threat-engine/internal/iptables"
	"github.com/hekemen/threat-engine/internal/metrics"
)

func adminServer(enabled bool) (*api.Server, *enforcement.Controller) {
	return adminServerWith(metrics.New(), enabled)
}

func adminServerWith(m *metrics.Metrics, enabled bool) (*api.Server, *enforcement.Controller) {
	exec := kernelExec()
	ctl := enforcement.New(&iptables.Enforcer{HostileSetName: "h", WhitelistSetName: "w", Exec: exec}, enabled)
	s := &api.Server{
		Metrics:     m,
		IPSet:       &ipset.Manager{HostileSetName: "h", WhitelistSetName: "w", Exec: exec},
		Port:        "0",
		Enforcement: ctl,
		AdminPort:   "0",
	}
	return s, ctl
}

// kernelExec models the PREROUTING jump the way the kernel does: `-C`
// reports the jump only while it exists, `-D` removes it, and `-I` creates
// it.
//
// A fake where every probe succeeds models an impossible kernel — one where
// a deleted jump stays alive forever. The detach path deletes the jump in a
// loop until the probe reports it gone, so the probe has to tell the truth.
func kernelExec() func(ctx context.Context, stdin io.Reader, name string, args ...string) (string, error) {
	jumpPresent := false
	return func(ctx context.Context, stdin io.Reader, name string, args ...string) (string, error) {
		line := strings.Join(args, " ")
		switch {
		case strings.Contains(line, "-C PREROUTING"):
			if !jumpPresent {
				return "iptables: Bad rule (does a matching rule exist in that chain?).", errors.New("exit status 1")
			}
		case strings.Contains(line, "-D PREROUTING"):
			jumpPresent = false
		case strings.Contains(line, "-I PREROUTING"):
			jumpPresent = true
		}
		return "", nil
	}
}

// isAttached asserts the JSON response body reports the given enforcement state.
func isAttached(t *testing.T, body string, want bool) {
	t.Helper()
	field := `"enforcement_enabled":false`
	if want {
		field = `"enforcement_enabled":true`
	}
	if !strings.Contains(body, field) {
		t.Fatalf("body %q missing %s", body, field)
	}
}

// The toggle path must create the kernel sets before it installs the rules
// that reference them. `iptables` refuses a `--match-set` rule outright while
// the set does not exist, so an operator toggling enforcement before the first
// scan finishes would otherwise end up with no rules at all.
func TestAdminPostEnsuresSetsBeforeAttaching(t *testing.T) {
	var mu sync.Mutex
	var calls []string
	exec := func(ctx context.Context, stdin io.Reader, name string, args ...string) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		line := name + " " + strings.Join(args, " ")
		calls = append(calls, line)
		// A fresh host: the jump is absent and the chain has no rules yet.
		if strings.Contains(line, "-C PREROUTING") || strings.Contains(line, "-C THREAD_ENGINE_FILTER") {
			return "no such rule", errors.New("exit status 1")
		}
		return "", nil
	}
	ctl := enforcement.New(&iptables.Enforcer{HostileSetName: "h", WhitelistSetName: "w", Exec: exec}, false)
	s := &api.Server{
		Metrics:     metrics.New(),
		IPSet:       &ipset.Manager{HostileSetName: "h", WhitelistSetName: "w", Exec: exec},
		Port:        "0",
		Enforcement: ctl,
		AdminPort:   "0",
	}

	rec := httptest.NewRecorder()
	s.AdminHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/enforcement?enabled=true", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST = %d %q", rec.Code, rec.Body.String())
	}

	joined := strings.Join(calls, "\n")
	restore := strings.Index(joined, "ipset restore")
	rule := strings.Index(joined, "-A THREAD_ENGINE_FILTER")
	if restore < 0 {
		t.Fatalf("the toggle must ensure the kernel sets exist, got:\n%s", joined)
	}
	if rule < 0 {
		t.Fatalf("the toggle must install the rules, got:\n%s", joined)
	}
	if restore > rule {
		t.Fatalf("the sets must be created before the rules that name them:\n%s", joined)
	}
}

// If the sets cannot be created, the toggle must fail cleanly and leave the
// flag untouched. Reporting "enabled" while nothing was installed would be the
// same silent fail-open the ordering fix exists to prevent.
func TestAdminPostFailsWhenSetsCannotBeEnsured(t *testing.T) {
	exec := func(ctx context.Context, stdin io.Reader, name string, args ...string) (string, error) {
		if name == "ipset" {
			return "Operation not permitted", errors.New("exit status 1")
		}
		return "", nil
	}
	ctl := enforcement.New(&iptables.Enforcer{HostileSetName: "h", WhitelistSetName: "w", Exec: exec}, false)
	s := &api.Server{
		Metrics:     metrics.New(),
		IPSet:       &ipset.Manager{HostileSetName: "h", WhitelistSetName: "w", Exec: exec},
		Port:        "0",
		Enforcement: ctl,
		AdminPort:   "0",
	}

	rec := httptest.NewRecorder()
	s.AdminHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/enforcement?enabled=true", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("POST = %d %q, want 500", rec.Code, rec.Body.String())
	}
	if ctl.Enabled() {
		t.Fatal("a failed toggle must not change the flag")
	}
}

func TestAdminGetEnforcement(t *testing.T) {
	s, _ := adminServer(false)
	rec := httptest.NewRecorder()
	s.AdminHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/enforcement", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"enforcement_enabled":false`) {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
}

func TestAdminPostEnforcementToggles(t *testing.T) {
	s, ctl := adminServer(false)
	rec := httptest.NewRecorder()
	s.AdminHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/enforcement?enabled=true", nil))
	if rec.Code != http.StatusOK || !ctl.Enabled() {
		t.Fatalf("POST enabled=true → %d, Enabled=%v", rec.Code, ctl.Enabled())
	}
	isAttached(t, rec.Body.String(), true)

	rec = httptest.NewRecorder()
	s.AdminHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/enforcement?enabled=false", nil))
	if rec.Code != http.StatusOK || ctl.Enabled() {
		t.Fatalf("POST enabled=false → %d, Enabled=%v", rec.Code, ctl.Enabled())
	}
	isAttached(t, rec.Body.String(), false)
}

// A toggle against a Server with no controller cannot do anything; reporting
// success would tell an operator their firewall changed when it did not.
func TestAdminPostEnforcementWithoutControllerFails(t *testing.T) {
	s := &api.Server{
		Metrics: metrics.New(),
		IPSet: &ipset.Manager{HostileSetName: "h", WhitelistSetName: "w", Exec: func(ctx context.Context, stdin io.Reader, name string, args ...string) (string, error) {
			return "", nil
		}},
		Port:      "0",
		AdminPort: "0",
	}
	rec := httptest.NewRecorder()
	s.AdminHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/enforcement?enabled=true", nil))
	if rec.Code != http.StatusInternalServerError && rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("a no-op toggle must not report success, got %d %q", rec.Code, rec.Body.String())
	}
}

func TestAdminPostEnforcementRejectsBadValue(t *testing.T) {
	s, ctl := adminServer(false)
	rec := httptest.NewRecorder()
	s.AdminHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/enforcement?enabled=maybe", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad value → %d, want 400", rec.Code)
	}
	if ctl.Enabled() {
		t.Fatal("a rejected value must not change state")
	}
}

// A locked enforcement controller must reject runtime toggles with 403 while
// GET keeps reporting the current state. This is the Kubernetes ConfigMap
// case: the env var owns the flag.
func TestAdminPostEnforcementForbiddenWhenLocked(t *testing.T) {
	exec := func(ctx context.Context, stdin io.Reader, name string, args ...string) (string, error) {
		return "", nil
	}
	ctl := enforcement.NewLocked(&iptables.Enforcer{HostileSetName: "h", WhitelistSetName: "w", Exec: exec}, false)
	s := &api.Server{
		Metrics:           metrics.New(),
		IPSet:             &ipset.Manager{HostileSetName: "h", WhitelistSetName: "w", Exec: exec},
		Port:              "0",
		Enforcement:       ctl,
		AdminPort:         "0",
		EnforcementLocked: true,
	}

	rec := httptest.NewRecorder()
	s.AdminHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/enforcement?enabled=true", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("locked POST = %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "locked") {
		t.Fatalf("403 body should explain the lock, got %q", rec.Body.String())
	}
	if ctl.Enabled() {
		t.Fatal("a locked POST must not change the flag")
	}

	// GET still works: the operator needs to see the state even when they
	// cannot change it.
	rec = httptest.NewRecorder()
	s.AdminHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/enforcement", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"enforcement_enabled":false`) {
		t.Fatalf("locked GET = %d %q, want 200 with state", rec.Code, rec.Body.String())
	}
}

// The socket server must expose the same handler as the TCP admin listener,
// so a toggle over the socket behaves identically.
func TestAdminSocketServesEnforcement(t *testing.T) {
	s, ctl := adminServer(false)
	srv := s.AdminSocketServer()

	rec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/enforcement?enabled=true", nil))
	if rec.Code != http.StatusOK || !ctl.Enabled() {
		t.Fatalf("socket POST = %d, Enabled=%v", rec.Code, ctl.Enabled())
	}
}

// The socket listener must bind, serve, and clean up a stale socket file left
// behind by a crashed process.
func TestListenAdminSocketBindsAndServes(t *testing.T) {
	s, ctl := adminServer(false)
	s.AdminSocket = filepath.Join(t.TempDir(), "threat-engine", "admin.sock")

	ln, err := s.ListenAdminSocket()
	if err != nil {
		t.Fatalf("ListenAdminSocket: %v", err)
	}
	if ln == nil {
		t.Fatal("ListenAdminSocket returned no listener")
	}
	defer ln.Close()

	if _, err := os.Stat(s.AdminSocket); err != nil {
		t.Fatalf("socket file missing: %v", err)
	}

	go s.AdminSocketServer().Serve(ln)

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", s.AdminSocket)
		},
	}}

	resp, err := client.Post("http://unix/enforcement?enabled=true", "text/plain", nil)
	if err != nil {
		t.Fatalf("POST over socket: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !ctl.Enabled() {
		t.Fatalf("socket POST = %d, Enabled=%v", resp.StatusCode, ctl.Enabled())
	}
}

// A leftover socket file from a crashed daemon must not block startup.
func TestListenAdminSocketReplacesStaleSocket(t *testing.T) {
	s, _ := adminServer(false)
	dir := t.TempDir()
	s.AdminSocket = filepath.Join(dir, "admin.sock")

	if err := os.WriteFile(s.AdminSocket, []byte("stale"), 0600); err != nil {
		t.Fatalf("seed stale socket: %v", err)
	}

	ln, err := s.ListenAdminSocket()
	if err != nil {
		t.Fatalf("ListenAdminSocket over a stale file: %v", err)
	}
	defer ln.Close()
}

func TestAdminListenerBindsLoopbackOnly(t *testing.T) {
	s, _ := adminServer(false)
	addr := s.AdminHTTPServer().Addr
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Fatalf("admin listener Addr = %q, must be loopback-only", addr)
	}
}

func TestCheckIncludesEnforcementState(t *testing.T) {
	m := metrics.New()
	exec := func(ctx context.Context, stdin io.Reader, name string, args ...string) (string, error) {
		return "", errors.New("exit status 1")
	}
	s, _ := adminServerWith(m, false)
	s.IPSet = &ipset.Manager{HostileSetName: "h", WhitelistSetName: "w", Exec: exec}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/check?ip=1.2.3.4", nil))
	if !strings.Contains(rec.Body.String(), `"enforcement_enabled":false`) {
		t.Fatalf("/check must expose enforcement state, got %s", rec.Body.String())
	}
}

func TestMetricsIncludesEnforcementGauge(t *testing.T) {
	m := metrics.New()
	for _, enabled := range []bool{false, true} {
		s, _ := adminServerWith(m, enabled)
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		want := "threat_engine_enforcement_enabled 0"
		if enabled {
			want = "threat_engine_enforcement_enabled 1"
		}
		if !strings.Contains(rec.Body.String(), want) {
			t.Fatalf("enabled=%v: missing %q", enabled, want)
		}
		if !strings.Contains(rec.Body.String(), "# TYPE threat_engine_enforcement_enabled gauge") {
			t.Fatalf("enabled=%v: missing HELP/TYPE lines", enabled)
		}
	}
}

// A Server built without an Enforcement controller must not panic; it reads as
// disabled. Guards the six pre-existing construction sites.
func TestServerWithoutEnforcementControllerIsNilSafe(t *testing.T) {
	s := &api.Server{
		Metrics: metrics.New(),
		IPSet: &ipset.Manager{HostileSetName: "h", WhitelistSetName: "w", Exec: func(ctx context.Context, stdin io.Reader, name string, args ...string) (string, error) {
			return "", errors.New("exit status 1")
		}},
		Port: "0",
	}

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/check?ip=1.2.3.4", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/check with nil Enforcement = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"enforcement_enabled":false`) {
		t.Fatalf("nil controller must report disabled, got %s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics with nil Enforcement = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "threat_engine_enforcement_enabled 0") {
		t.Fatalf("nil controller must render as disabled, got:\n%s", rec.Body.String())
	}
}

func TestHealthzTransition(t *testing.T) {
	m := metrics.New()
	s := &api.Server{Metrics: m, IPSet: &ipset.Manager{}, Port: "0"}
	h := s.Handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("pre-scan /healthz = %d, want 503", rec.Code)
	}

	m.RecordScanSuccess(0)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "ok\n" {
		t.Fatalf("post-scan /healthz = %d %q", rec.Code, rec.Body.String())
	}
}

func TestCheckValidation(t *testing.T) {
	s := &api.Server{Metrics: metrics.New(), IPSet: &ipset.Manager{}, Port: "0"}
	h := s.Handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/check", nil))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "ip parameter required") {
		t.Fatalf("missing ip: %d %q", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/check?ip=999.1.1.1", nil))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid ip") {
		t.Fatalf("bad ip: %d %q", rec.Code, rec.Body.String())
	}
}

func TestCheckStatusPrecedence(t *testing.T) {
	cases := []struct {
		name      string
		blocked   bool
		whitelist bool
		want      string
	}{
		{"both→whitelisted", true, true, "whitelisted"},
		{"blocked only", true, false, "blocked"},
		{"clean", false, false, "allowed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := metrics.New()
			exec := func(ctx context.Context, stdin io.Reader, name string, args ...string) (string, error) {
				set := args[1] // ipset test <set> <addr>
				if set == "h" && tc.blocked {
					return "", nil
				}
				if set == "w" && tc.whitelist {
					return "", nil
				}
				return "", errors.New("exit status 1")
			}
			s := &api.Server{
				Metrics: m,
				IPSet:   &ipset.Manager{HostileSetName: "h", WhitelistSetName: "w", Exec: exec},
				Port:    "0",
			}
			rec := httptest.NewRecorder()
			s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/check?ip=1.2.3.4", nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("code %d", rec.Code)
			}
			body := rec.Body.String()
			for _, want := range []string{`"ip":"1.2.3.4"`, `"status":"` + tc.want + `"`, `"is_blocked"`, `"is_whitelisted"`, `"timestamp"`} {
				if !strings.Contains(body, want) {
					t.Fatalf("body %q missing %q", body, want)
				}
			}
		})
	}
}

func TestCheckWhitelistedBlockedAddressReportsWhitelisted(t *testing.T) {
	exec := func(ctx context.Context, stdin io.Reader, name string, args ...string) (string, error) {
		return "", nil // present in every set
	}
	s := &api.Server{
		Metrics: metrics.New(),
		IPSet:   &ipset.Manager{HostileSetName: "h", WhitelistSetName: "w", Exec: exec},
		Port:    "0",
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/check?ip=10.0.0.5", nil))
	if !strings.Contains(rec.Body.String(), `"is_blocked":true`) || !strings.Contains(rec.Body.String(), `"status":"whitelisted"`) {
		t.Fatalf("whitelist must win over block status: %s", rec.Body.String())
	}
}

func TestCheckUsesUncancellableContext(t *testing.T) {
	var ctxErr error
	exec := func(ctx context.Context, stdin io.Reader, name string, args ...string) (string, error) {
		ctxErr = ctx.Err() // must be nil: a cancelled lookup would misreport a blocked IP as allowed
		if args[1] == "h" {
			return "", nil
		}
		return "", errors.New("exit status 1")
	}
	s := &api.Server{
		Metrics: metrics.New(),
		IPSet:   &ipset.Manager{HostileSetName: "h", WhitelistSetName: "w", Exec: exec},
		Port:    "0",
	}
	req := httptest.NewRequest(http.MethodGet, "/check?ip=1.2.3.4", nil)
	cancelled, cancel := context.WithCancel(req.Context())
	cancel()
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req.WithContext(cancelled))
	if ctxErr != nil {
		t.Fatalf("kernel lookup must not be cancellable, got ctx err %v", ctxErr)
	}
	if !strings.Contains(rec.Body.String(), `"status":"blocked"`) {
		t.Fatalf("blocked address misreported: %s", rec.Body.String())
	}
}

func TestMetricsBodyGolden(t *testing.T) {
	m := metrics.New()
	m.RecordScanSuccess(3)
	m.RecordUpdate("abc", 7)
	m.RecordDropCounters(metrics.DropCounters{
		HostilePackets:   345,
		HostileBytes:     45678,
		WhitelistPackets: 12,
		WhitelistBytes:   1440,
	})
	s := &api.Server{Metrics: m, IPSet: &ipset.Manager{}, Port: "0"}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	want := "# HELP threat_engine_blocked_targets Number of hostile IPs/CIDRs currently blocked in kernel\n" +
		"# TYPE threat_engine_blocked_targets gauge\n" +
		"threat_engine_blocked_targets 7\n\n" +
		"# HELP threat_engine_blocked_targets_total DEPRECATED: use threat_engine_blocked_targets instead. Number of hostile IPs/CIDRs currently blocked in kernel\n" +
		"# TYPE threat_engine_blocked_targets_total gauge\n" +
		"threat_engine_blocked_targets_total 7\n\n" +
		"# HELP threat_engine_whitelist_entries Active whitelist subnets\n" +
		"# TYPE threat_engine_whitelist_entries gauge\n" +
		"threat_engine_whitelist_entries 3\n\n" +
		"# HELP threat_engine_whitelist_entries_total DEPRECATED: use threat_engine_whitelist_entries instead. Active whitelist subnets\n" +
		"# TYPE threat_engine_whitelist_entries_total gauge\n" +
		"threat_engine_whitelist_entries_total 3\n\n" +
		"# HELP threat_engine_scans_total Total scheduled scan attempts\n" +
		"# TYPE threat_engine_scans_total counter\n" +
		"threat_engine_scans_total{status=\"success\"} 1\n" +
		"threat_engine_scans_total{status=\"failure\"} 0\n\n" +
		"# HELP threat_engine_updates_applied_total Times a change triggered an ipset swap\n" +
		"# TYPE threat_engine_updates_applied_total counter\n" +
		"threat_engine_updates_applied_total 1\n\n" +
		"# HELP threat_engine_dropped_packets_total Packets dropped by the kernel for hostile sources\n" +
		"# TYPE threat_engine_dropped_packets_total counter\n" +
		"threat_engine_dropped_packets_total 345\n\n" +
		"# HELP threat_engine_dropped_bytes_total Bytes dropped by the kernel for hostile sources\n" +
		"# TYPE threat_engine_dropped_bytes_total counter\n" +
		"threat_engine_dropped_bytes_total 45678\n\n" +
		"# HELP threat_engine_whitelist_bypassed_packets_total Packets let through by the whitelist bypass\n" +
		"# TYPE threat_engine_whitelist_bypassed_packets_total counter\n" +
		"threat_engine_whitelist_bypassed_packets_total 12\n\n" +
		"# HELP threat_engine_whitelist_bypassed_bytes_total Bytes let through by the whitelist bypass\n" +
		"# TYPE threat_engine_whitelist_bypassed_bytes_total counter\n" +
		"threat_engine_whitelist_bypassed_bytes_total 1440\n\n" +
		"# HELP threat_engine_enforcement_enabled Whether hostile DROP rules are attached to PREROUTING (1) or inert (0)\n" +
		"# TYPE threat_engine_enforcement_enabled gauge\n" +
		"threat_engine_enforcement_enabled 0\n\n" +
		"# HELP threat_engine_last_scan_timestamp Unix timestamp of latest scan execution\n" +
		"# TYPE threat_engine_last_scan_timestamp gauge\n" +
		"threat_engine_last_scan_timestamp " + strconv.FormatInt(m.Snapshot().LastScanUnix, 10) + "\n\n" +
		"# HELP threat_engine_last_change_timestamp Unix timestamp when rules were last updated\n" +
		"# TYPE threat_engine_last_change_timestamp gauge\n" +
		"threat_engine_last_change_timestamp " + strconv.FormatInt(m.Snapshot().LastChangeUnix, 10) + "\n"

	if rec.Body.String() != want {
		t.Fatalf("/metrics body drift:\ngot:\n%s\nwant:\n%s", rec.Body.String(), want)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; version=0.0.4; charset=utf-8" {
		t.Fatalf("Content-Type = %q", ct)
	}
}

func TestMetricsFamilies(t *testing.T) {
	m := metrics.New()
	m.RecordScanSuccess(3)
	m.RecordUpdate("abc", 7)
	m.RecordDropCounters(metrics.DropCounters{
		HostilePackets:   345,
		HostileBytes:     45678,
		WhitelistPackets: 12,
		WhitelistBytes:   1440,
	})
	s := &api.Server{Metrics: m, IPSet: &ipset.Manager{}, Port: "0"}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	for _, fam := range []string{
		"threat_engine_blocked_targets 7",
		"threat_engine_blocked_targets_total 7",
		"threat_engine_whitelist_entries 3",
		"threat_engine_whitelist_entries_total 3",
		`threat_engine_scans_total{status="success"} 1`,
		`threat_engine_scans_total{status="failure"} 0`,
		"threat_engine_updates_applied_total 1",
		"threat_engine_dropped_packets_total 345",
		"threat_engine_dropped_bytes_total 45678",
		"threat_engine_whitelist_bypassed_packets_total 12",
		"threat_engine_whitelist_bypassed_bytes_total 1440",
		"threat_engine_enforcement_enabled 0",
		"threat_engine_last_scan_timestamp",
		"threat_engine_last_change_timestamp",
	} {
		if !strings.Contains(body, fam) {
			t.Fatalf("/metrics missing %q:\n%s", fam, body)
		}
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Fatalf("Content-Type = %q", ct)
	}
}

// The drop counters are counters, not gauges: they must be typed as such so
// Prometheus applies rate() and increase() correctly.
func TestMetricsDropCountersAreTypedAsCounters(t *testing.T) {
	m := metrics.New()
	s := &api.Server{Metrics: m, IPSet: &ipset.Manager{}, Port: "0"}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	for _, fam := range []string{
		"threat_engine_dropped_packets_total",
		"threat_engine_dropped_bytes_total",
		"threat_engine_whitelist_bypassed_packets_total",
		"threat_engine_whitelist_bypassed_bytes_total",
	} {
		if !strings.Contains(body, "# TYPE "+fam+" counter") {
			t.Fatalf("%s must be typed as a counter:\n%s", fam, body)
		}
	}
}
