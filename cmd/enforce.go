package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// adminSocketEnv is the environment variable the CLI reads to locate the
// admin unix socket. It is deliberately separate from ADMIN_SOCKET (the
// daemon's own variable) so that a client can point at a different socket
// than the one the daemon it is talking to was started with.
const adminSocketEnv = "THREAT_ENGINE_ADMIN_SOCKET"

// defaultAdminSocket is the daemon's default socket path.
const defaultAdminSocket = "/var/run/threat-engine/admin.sock"

// enforceAlias is the name the container image installs this binary under,
// so that `docker exec threat-engine enforce off` reads naturally instead of
// repeating the binary name.
const enforceAlias = "enforce"

// enforceCall describes an invocation of the enforcement CLI.
type enforceCall struct {
	// Args are the subcommand arguments: on, off, or status.
	Args []string
	// Name is how the command was invoked. It is used in the usage line so
	// the message matches what the operator typed.
	Name string
}

// enforceInvocation reports whether the process was asked to act as the
// enforcement CLI, and with which arguments.
//
// Two shapes are accepted:
//
//   - `threat-engine enforce <args>` — the documented subcommand form.
//   - `enforce <args>` — invoked through the alias symlink the image
//     installs, so argv[1] is already the subcommand.
//
// The alias is checked first: under that name argv[1] is the subcommand and
// must not be mistaken for one.
func enforceInvocation(args []string) (enforceCall, bool) {
	if len(args) > 0 && filepath.Base(args[0]) == enforceAlias {
		return enforceCall{Args: args[1:], Name: enforceAlias}, true
	}
	if len(args) > 1 && args[1] == "enforce" {
		return enforceCall{Args: args[2:], Name: "threat-engine enforce"}, true
	}
	return enforceCall{}, false
}

// runEnforce is the enforcement CLI entry point. It parses the subcommand,
// performs the request, and maps the outcome to an exit code.
func runEnforce(call enforceCall) {
	if len(call.Args) == 0 {
		fmt.Fprintf(os.Stderr, "usage: %s <on|off|status>\n", call.Name)
		os.Exit(2)
	}

	code, err := enforceCommand(os.Stdout, os.Stderr, call.Args, adminSocketPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
	}
	os.Exit(code)
}

// adminSocketPath resolves the socket path the CLI dials.
func adminSocketPath() string {
	if p := strings.TrimSpace(os.Getenv(adminSocketEnv)); p != "" {
		return p
	}
	return defaultAdminSocket
}

// enforceCommand performs one enforce subcommand and returns the process exit
// code. It is separated from runEnforce so it can be tested without exiting
// the test binary.
//
// Exit codes: 0 success, 1 request/transport failure or an error response
// from the daemon, 2 usage error.
func enforceCommand(stdout, stderr io.Writer, args []string, sock string) (int, error) {
	cmd := strings.ToLower(strings.TrimSpace(args[0]))
	switch cmd {
	case "status":
		return enforceRequest(stdout, stderr, sock, http.MethodGet, "/enforcement")
	case "on", "enable", "true":
		return enforceRequest(stdout, stderr, sock, http.MethodPost, "/enforcement?enabled=true")
	case "off", "disable", "false":
		return enforceRequest(stdout, stderr, sock, http.MethodPost, "/enforcement?enabled=false")
	default:
		fmt.Fprintf(stderr, "unknown subcommand %q: want on, off, or status\n", args[0])
		return 2, nil
	}
}

// enforceRequest performs the HTTP call over the unix socket and prints the
// result. The daemon's JSON body is echoed verbatim so the operator sees the
// same state the daemon reports.
func enforceRequest(stdout, stderr io.Writer, sock string, method, path string) (int, error) {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		},
		Timeout: 5 * time.Second,
	}
	defer client.CloseIdleConnections()

	req, err := http.NewRequest(method, "http://unix"+path, nil)
	if err != nil {
		return 1, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return 1, fmt.Errorf("cannot reach the admin socket at %s: %w", sock, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 1, err
	}

	// Echo the body as-is. The daemon returns JSON on both success and
	// failure (e.g. the 403 when enforcement is locked by the environment),
	// and reformatting it would hide the reason.
	trimmed := strings.TrimSpace(string(body))
	if trimmed != "" {
		fmt.Fprintln(stdout, trimmed)
	}

	if resp.StatusCode >= 400 {
		return 1, fmt.Errorf("admin request failed: %s", resp.Status)
	}
	return 0, nil
}
