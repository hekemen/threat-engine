package api_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hekemen/thread-engine/internal/api"
	"github.com/hekemen/thread-engine/internal/ipset"
	"github.com/hekemen/thread-engine/internal/metrics"
)

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
