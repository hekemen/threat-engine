package runner_test

import (
	"context"
	"strings"
	"testing"

	"github.com/hekemen/thread-engine/internal/runner"
)

func TestOSPassesStdinAndReturnsCombinedOutput(t *testing.T) {
	out, err := runner.OS()(context.Background(), strings.NewReader("hello"), "cat")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != "hello" {
		t.Fatalf("got %q, want %q", out, "hello")
	}
}

func TestOSFoldsOutputIntoError(t *testing.T) {
	_, err := runner.OS()(context.Background(), nil, "sh", "-c", "echo boom >&2; exit 1")
	if err == nil {
		t.Fatal("expected error for nonzero exit")
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Fatalf("error %q does not contain command output %q", err.Error(), "boom")
	}
}
