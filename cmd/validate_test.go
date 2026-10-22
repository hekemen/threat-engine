package main

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/hekemen/threat-engine/internal/netns"
	"github.com/hekemen/threat-engine/internal/runner"
)

// probeRunner records the command it was asked to run and replays a scripted
// answer.
type probeRunner struct {
	calls [][]string
	out   string
	err   error
}

func (p *probeRunner) run(ctx context.Context, stdin io.Reader, name string, args ...string) (string, error) {
	call := append([]string{name}, args...)
	p.calls = append(p.calls, call)
	return p.out, p.err
}

// The probe lists a set that does not exist, so ipset is expected to fail.
// That failure is the success signal and must not be reported as an error.
func TestProbeIPSetAcceptsAbsentProbeSet(t *testing.T) {
	p := &probeRunner{
		out: "ipset v7.22: The set with the given name does not exist",
		err: errors.New("exit status 1"),
	}

	if err := probeIPSet(context.Background(), p.run); err != nil {
		t.Fatalf("an absent probe set must be a success, got: %v", err)
	}
}

// The probe must ask for a set name that cannot collide with a real one.
func TestProbeIPSetUsesDedicatedProbeSetName(t *testing.T) {
	p := &probeRunner{
		out: "ipset v7.22: The set with the given name does not exist",
		err: errors.New("exit status 1"),
	}

	if err := probeIPSet(context.Background(), p.run); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{"ipset", "list", ipsetProbeSet}
	if len(p.calls) != 1 {
		t.Fatalf("expected exactly one command, got %v", p.calls)
	}
	for i, arg := range want {
		if p.calls[0][i] != arg {
			t.Fatalf("command %v does not contain %q", p.calls[0], arg)
		}
	}
}

// A privileged failure means the daemon cannot manage its sets at all, and
// the message has to say which capability to grant.
func TestProbeIPSetRejectsPermissionDenied(t *testing.T) {
	p := &probeRunner{
		out: "ipset v7.22: Unable to create a temporary set: Operation not permitted",
		err: errors.New("exit status 1"),
	}

	err := probeIPSet(context.Background(), p.run)
	if err == nil {
		t.Fatal("a permission failure must not be reported as success")
	}
	for _, want := range []string{"CAP_NET_ADMIN", "--cap-add=NET_ADMIN", "--net=host"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error should mention %q, got: %v", want, err)
		}
	}
}

// Some ipset builds probe the kernel even for --version, so a failing version
// check can be a missing capability rather than a broken binary.
func TestCheckBinaryVersionFailsOnPermissionDenied(t *testing.T) {
	p := &probeRunner{
		out: "ipset v7.22: Kernel error received: Operation not permitted",
		err: errors.New("exit status 1"),
	}

	err := checkBinaryVersion(context.Background(), p.run, "ipset")
	if err == nil {
		t.Fatal("a version probe that needs privileges must fail")
	}
	for _, want := range []string{"CAP_NET_ADMIN", "--cap-add=NET_ADMIN", "--cap-add=NET_RAW", "--net=host"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error should mention %q, got: %v", want, err)
		}
	}
}

// A version check that fails for another reason is not fatal: the binary may
// only print its version differently.
func TestCheckBinaryVersionToleratesOtherFailures(t *testing.T) {
	p := &probeRunner{
		out: "ipset v7.22, protocol version: 7",
		err: errors.New("exit status 1"),
	}

	if err := checkBinaryVersion(context.Background(), p.run, "ipset"); err != nil {
		t.Fatalf("an unusual version failure must not be fatal, got: %v", err)
	}
}

// A missing kernel module is a different failure and must say so.
func TestProbeIPSetRejectsMissingModules(t *testing.T) {
	p := &probeRunner{
		out: "ipset v7.22: Cannot open netlink socket: ipset kernel module is not loaded",
		err: errors.New("exit status 1"),
	}

	err := probeIPSet(context.Background(), p.run)
	if err == nil {
		t.Fatal("a missing kernel module must not be reported as success")
	}
	if !strings.Contains(err.Error(), "netfilter modules missing") {
		t.Fatalf("error should mention the missing modules, got: %v", err)
	}
}

// Anything the probe did not expect is a real problem: it used to be logged as
// "ipset reachable", which hid a broken kernel path.
func TestProbeIPSetRejectsUnexpectedFailure(t *testing.T) {
	p := &probeRunner{
		out: "ipset v7.22: something entirely unexpected",
		err: errors.New("exit status 1"),
	}

	if err := probeIPSet(context.Background(), p.run); err == nil {
		t.Fatal("an unexpected probe failure must not be reported as success")
	}
}

// The probe set existing at all means the probe proves nothing.
func TestProbeIPSetRejectsExistingProbeSet(t *testing.T) {
	p := &probeRunner{out: "Name: " + ipsetProbeSet}

	if err := probeIPSet(context.Background(), p.run); err == nil {
		t.Fatal("an existing probe set must not be reported as success")
	}
}

// Reading the raw table must succeed; it needs the privileges the daemon
// requires to install its rules.
func TestProbeIPTablesRequiresReadableRawTable(t *testing.T) {
	p := &probeRunner{
		out: "iptables v1.8.11 (nf_tables): can't initialize ip tables: Permission denied",
		err: errors.New("exit status 1"),
	}

	err := probeIPTables(context.Background(), p.run)
	if err == nil {
		t.Fatal("an unreadable raw table must not be reported as success")
	}
	for _, want := range []string{"CAP_NET_ADMIN", "CAP_NET_RAW", "--cap-add=NET_ADMIN", "--cap-add=NET_RAW", "--net=host"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error should mention %q, got: %v", want, err)
		}
	}
}

func TestProbeIPTablesAcceptsReadableRawTable(t *testing.T) {
	p := &probeRunner{out: "Chain PREROUTING (policy ACCEPT)"}

	if err := probeIPTables(context.Background(), p.run); err != nil {
		t.Fatalf("a readable raw table must be a success, got: %v", err)
	}
}

// A daemon outside the host's network namespace populates its own ipsets and
// enforces nothing on the host, so the namespace must be verified.
func TestValidateNetworkNamespaceRejectsANonHostNamespace(t *testing.T) {
	fake := func() (netns.Namespace, error) {
		return netns.Namespace{Link: "net:[4026534517]", Ino: 4026534517}, nil
	}

	err := validateNetworkNamespace(fake)
	if err == nil {
		t.Fatal("a non-host network namespace must not be accepted")
	}

	// The message has to tell the operator which knob to turn, per runtime.
	for _, want := range []string{
		"network_mode: host", // Docker Compose
		"--net=host",         // docker run
		"hostNetwork: true",  // Kubernetes
		"not to the host",    // what goes wrong
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error should mention %q, got: %v", want, err)
		}
	}
}

// An unreadable namespace cannot be vouched for, so it fails closed.
func TestValidateNetworkNamespaceRejectsAnUnreadableNamespace(t *testing.T) {
	fake := func() (netns.Namespace, error) {
		return netns.Namespace{}, errors.New("no /proc")
	}

	if err := validateNetworkNamespace(fake); err == nil {
		t.Fatal("an unreadable network namespace must not be accepted")
	}
}

func TestValidateNetworkNamespaceAcceptsTheInitialNamespace(t *testing.T) {
	fake := func() (netns.Namespace, error) {
		return netns.Namespace{Link: "net:[4026531833]", Ino: netns.InitialIno}, nil
	}

	if err := validateNetworkNamespace(fake); err != nil {
		t.Fatalf("the initial namespace must be accepted, got: %v", err)
	}
}

// The namespace check must run before the ipset and iptables probes: in the
// wrong namespace those probes still succeed, against the wrong tables.
func TestValidateKernelRejectsANonHostNamespaceBeforeAnythingElse(t *testing.T) {
	fake := func() (netns.Namespace, error) {
		return netns.Namespace{Link: "net:[4026534517]", Ino: 4026534517}, nil
	}

	run := runner.RunnerFn(func(ctx context.Context, stdin io.Reader, name string, args ...string) (string, error) {
		t.Errorf("no kernel command may run when the namespace is wrong (ran %s)", name)
		return "", nil
	})

	err := validateKernel(context.Background(), run, fake)
	if err == nil {
		t.Fatal("validateKernel must reject a non-host network namespace")
	}
	if !strings.Contains(err.Error(), "network_mode: host") {
		t.Fatalf("error should name the Docker setting to enable, got: %v", err)
	}
}
