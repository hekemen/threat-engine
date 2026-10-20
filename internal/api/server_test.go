package api_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/hekemen/thread-engine/internal/api"
	"github.com/hekemen/thread-engine/internal/enforcement"
	"github.com/hekemen/thread-engine/internal/ipset"
	"github.com/hekemen/thread-engine/internal/iptables"
	"github.com/hekemen/thread-engine/internal/metrics"
)

func adminServer(enabled bool) (*api.Server, *enforcement.Controller) {
	return adminServerWith(metrics.New(), enabled)
}

func adminServerWith(m *metrics.Metrics, enabled bool) (*api.Server, *enforcement.Controller) {
	exec := func(ctx context.Context, stdin io.Reader, name string, args ...string) (string, error) {
		return "", nil // every kernel probe succeeds
	}
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
	s := &api.Server{Metrics: m, IPSet: &ipset.Manager{}, Port: "0"}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	want := "# HELP threat_engine_blocked_targets_total Number of hostile IPs/CIDRs currently blocked in kernel\n" +
		"# TYPE threat_engine_blocked_targets_total gauge\n" +
		"threat_engine_blocked_targets_total 7\n\n" +
		"# HELP threat_engine_whitelist_entries_total Active whitelist subnets\n" +
		"# TYPE threat_engine_whitelist_entries_total gauge\n" +
		"threat_engine_whitelist_entries_total 3\n\n" +
		"# HELP threat_engine_scans_total Total scheduled scan attempts\n" +
		"# TYPE threat_engine_scans_total counter\n" +
		"threat_engine_scans_total{status=\"success\"} 1\n" +
		"threat_engine_scans_total{status=\"failure\"} 0\n\n" +
		"# HELP threat_engine_updates_applied_total Times a change triggered an ipset swap\n" +
		"# TYPE threat_engine_updates_applied_total counter\n" +
		"threat_engine_updates_applied_total 1\n\n" +
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
	s := &api.Server{Metrics: m, IPSet: &ipset.Manager{}, Port: "0"}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	for _, fam := range []string{
		"threat_engine_blocked_targets_total 7",
		"threat_engine_whitelist_entries_total 3",
		`threat_engine_scans_total{status="success"} 1`,
		`threat_engine_scans_total{status="failure"} 0`,
		"threat_engine_updates_applied_total 1",
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
