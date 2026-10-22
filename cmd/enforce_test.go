package main

import (
	"bytes"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// serveAdmin starts an HTTP server on a unix socket and returns its path.
func serveAdmin(t *testing.T, handler http.Handler) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "admin.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	srv := &http.Server{Handler: handler}
	go srv.Serve(ln)
	t.Cleanup(func() {
		srv.Close()
		os.Remove(sock)
	})
	return sock
}

func TestEnforceStatus(t *testing.T) {
	sock := serveAdmin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("status must issue a GET, got %s", r.Method)
		}
		w.Write([]byte(`{"enforcement_enabled":true}`))
	}))

	var out, errOut bytes.Buffer
	code, err := enforceCommand(&out, &errOut, []string{"status"}, sock)
	if err != nil {
		t.Fatalf("enforceCommand: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out.String(), `"enforcement_enabled":true`) {
		t.Fatalf("stdout = %q, want the daemon's JSON body", out.String())
	}
}

func TestEnforceOnAndOff(t *testing.T) {
	var lastQuery string
	sock := serveAdmin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("toggle must issue a POST, got %s", r.Method)
		}
		lastQuery = r.URL.RawQuery
		w.Write([]byte(`{"enforcement_enabled":true}`))
	}))

	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"on"}, "enabled=true"},
		{[]string{"off"}, "enabled=false"},
		{[]string{"enable"}, "enabled=true"},
		{[]string{"disable"}, "enabled=false"},
	} {
		var out, errOut bytes.Buffer
		code, err := enforceCommand(&out, &errOut, tc.args, sock)
		if err != nil {
			t.Fatalf("%v: %v", tc.args, err)
		}
		if code != 0 {
			t.Fatalf("%v: exit code = %d, want 0", tc.args, code)
		}
		if lastQuery != tc.want {
			t.Fatalf("%v: query = %q, want %q", tc.args, lastQuery, tc.want)
		}
	}
}

// A locked daemon answers 403. The CLI must surface that as a failure and
// still print the reason, rather than reporting a successful toggle.
func TestEnforceReportsLockedDaemonAsFailure(t *testing.T) {
	sock := serveAdmin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"enforcement is locked by environment variable"}`))
	}))

	var out, errOut bytes.Buffer
	code, err := enforceCommand(&out, &errOut, []string{"on"}, sock)
	if err == nil {
		t.Fatal("a 403 must be reported as an error")
	}
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(out.String(), "locked") {
		t.Fatalf("stdout = %q, want the daemon's explanation", out.String())
	}
}

func TestEnforceUnknownSubcommand(t *testing.T) {
	var out, errOut bytes.Buffer
	code, err := enforceCommand(&out, &errOut, []string{"maybe"}, "/nonexistent.sock")
	if err != nil {
		t.Fatalf("a usage error must not be reported as a transport error: %v", err)
	}
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "unknown subcommand") {
		t.Fatalf("stderr = %q", errOut.String())
	}
}

// A missing socket must fail with a clear message, not a stack trace.
func TestEnforceReportsUnreachableSocket(t *testing.T) {
	var out, errOut bytes.Buffer
	code, err := enforceCommand(&out, &errOut, []string{"status"}, filepath.Join(t.TempDir(), "missing.sock"))
	if err == nil {
		t.Fatal("an unreachable socket must be reported as an error")
	}
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(err.Error(), "admin socket") {
		t.Fatalf("error = %v, want it to name the socket", err)
	}
}

func TestAdminSocketPathDefault(t *testing.T) {
	t.Setenv(adminSocketEnv, "")
	if got := adminSocketPath(); got != defaultAdminSocket {
		t.Fatalf("adminSocketPath() = %q, want %q", got, defaultAdminSocket)
	}
	t.Setenv(adminSocketEnv, "/tmp/custom.sock")
	if got := adminSocketPath(); got != "/tmp/custom.sock" {
		t.Fatalf("adminSocketPath() = %q, want /tmp/custom.sock", got)
	}
}

// A daemon that accepts the connection but closes it without answering must
// fail cleanly rather than hanging or reporting success.
func TestEnforceHandlesDroppedConnection(t *testing.T) {
	ln, err := net.Listen("unix", filepath.Join(t.TempDir(), "admin.sock"))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	done := make(chan struct{})
	var code int
	go func() {
		defer close(done)
		var out, errOut bytes.Buffer
		code, _ = enforceCommand(&out, &errOut, []string{"status"}, ln.Addr().String())
	}()
	<-done
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
}

// The CLI is reachable as `threat-engine enforce <args>` and, in the image,
// as `enforce <args>` through the alias symlink. Anything else is the daemon.
func TestEnforceInvocation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		argv     []string
		wantArgs []string
		wantName string
		wantOK   bool
	}{
		{
			name:     "subcommand form",
			argv:     []string{"threat-engine", "enforce", "off"},
			wantArgs: []string{"off"},
			wantName: "threat-engine enforce",
			wantOK:   true,
		},
		{
			name:     "subcommand form without a subcommand",
			argv:     []string{"threat-engine", "enforce"},
			wantArgs: []string{},
			wantName: "threat-engine enforce",
			wantOK:   true,
		},
		{
			name:     "alias",
			argv:     []string{"enforce", "off"},
			wantArgs: []string{"off"},
			wantName: "enforce",
			wantOK:   true,
		},
		{
			name:     "alias by absolute path",
			argv:     []string{"/usr/local/bin/enforce", "status"},
			wantArgs: []string{"status"},
			wantName: "enforce",
			wantOK:   true,
		},
		{
			name:     "alias without a subcommand",
			argv:     []string{"enforce"},
			wantArgs: []string{},
			wantName: "enforce",
			wantOK:   true,
		},
		{
			name: "bare binary is the daemon",
			argv: []string{"threat-engine"},
		},
		{
			name: "unknown argument is the daemon",
			argv: []string{"threat-engine", "serve"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			call, ok := enforceInvocation(tc.argv)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (call = %+v)", ok, tc.wantOK, call)
			}
			if !tc.wantOK {
				return
			}
			if len(call.Args) != len(tc.wantArgs) {
				t.Fatalf("args = %v, want %v", call.Args, tc.wantArgs)
			}
			for i := range tc.wantArgs {
				if call.Args[i] != tc.wantArgs[i] {
					t.Fatalf("args = %v, want %v", call.Args, tc.wantArgs)
				}
			}
			if call.Name != tc.wantName {
				t.Fatalf("name = %q, want %q", call.Name, tc.wantName)
			}
		})
	}
}

// The alias must reach the same behaviour as the subcommand form: the same
// request, the same exit code.
func TestEnforceAliasReachesTheAdminSocket(t *testing.T) {
	var lastQuery string
	sock := serveAdmin(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastQuery = r.URL.RawQuery
		w.Write([]byte(`{"enforcement_enabled":false}`))
	}))

	call, ok := enforceInvocation([]string{"enforce", "off"})
	if !ok {
		t.Fatal("the alias must be recognised as an enforcement call")
	}

	var out, errOut bytes.Buffer
	code, err := enforceCommand(&out, &errOut, call.Args, sock)
	if err != nil {
		t.Fatalf("enforceCommand: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if lastQuery != "enabled=false" {
		t.Fatalf("query = %q, want %q", lastQuery, "enabled=false")
	}
}
