// Package runner is the only place in the project that shells out. Every
// kernel-touching package (ipset, iptables) takes a Runner so unit tests can
// assert the exact commands without root or a live kernel.
package runner

import (
	"context"
	"fmt"
	"io"
	"os/exec"
)

// Runner executes an external command with optional stdin and returns its
// combined stdout+stderr. A non-nil error means the command failed.
type Runner func(ctx context.Context, stdin io.Reader, name string, args ...string) (string, error)

// RunnerFn is an alias for Runner, kept so test fakes read naturally.
type RunnerFn = Runner

// OS returns a Runner backed by os/exec. Output is collected with
// CombinedOutput so stderr text lands in the returned error message.
func OS() Runner {
	return func(ctx context.Context, stdin io.Reader, name string, args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Stdin = stdin
		out, err := cmd.CombinedOutput()
		if err != nil {
			return string(out), fmt.Errorf("%s %v: %w: %s", name, args, err, out)
		}
		return string(out), nil
	}
}
