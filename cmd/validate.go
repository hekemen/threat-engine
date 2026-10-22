package main

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/hekemen/threat-engine/internal/netns"
	"github.com/hekemen/threat-engine/internal/runner"
)

// ipsetProbeSet is the set name used to probe ipset. It must not exist: the
// probe expects ipset to fail with "does not exist", and that failure is the
// proof that ipset reached the kernel.
const ipsetProbeSet = "threat_engine_probe_nonexistent"

// validateKernel checks that ipset and iptables are available and executable,
// and that the process appears to have sufficient privileges for netfilter.
// The daemon requires CAP_NET_ADMIN/CAP_NET_RAW and host networking to enforce.
//
// It returns an error describing the first problem it finds. The caller must
// abort startup: a daemon that starts cleanly but cannot write the kernel
// tables looks healthy while filtering nothing.
//
// currentNetns reports the network namespace of the process. It is a
// parameter so tests can substitute it.
func validateKernel(ctx context.Context, run runner.Runner, currentNetns func() (netns.Namespace, error)) error {
	// The daemon edits the *host's* netfilter tables, so it has to share the
	// host's network namespace. This is checked first: in the wrong namespace
	// the ipset and iptables probes below still succeed, but they succeed
	// against the container's tables, not the host's.
	if err := validateNetworkNamespace(currentNetns); err != nil {
		return err
	}

	// Check binaries exist and are runnable.
	for _, bin := range []string{"ipset", "iptables"} {
		if _, err := exec.LookPath(bin); err != nil {
			return fmt.Errorf("Required binary %q not found in PATH: %w", bin, err)
		}
		if err := checkBinaryVersion(ctx, run, bin); err != nil {
			return err
		}
	}

	if err := probeIPSet(ctx, run); err != nil {
		return err
	}

	if err := probeIPTables(ctx, run); err != nil {
		return err
	}

	log.Info().Msg("KernelCheck: kernel management commands are available")
	return nil
}

// capabilityHint spells out how to grant the privileges the daemon needs. It
// is repeated in every permission failure because that message is what an
// operator reads while the container crash-loops.
const capabilityHint = "The daemon requires CAP_NET_ADMIN (docker: --cap-add=NET_ADMIN) and " +
	"CAP_NET_RAW (docker: --cap-add=NET_RAW), and host networking " +
	"(docker-compose: network_mode: host, docker run: --net=host)."

// checkBinaryVersion runs "<bin> --version" and reports what it found.
//
// Some ipset builds probe the kernel even for --version, so a failing check
// can be a missing capability rather than a broken binary. Reporting that as
// a version problem would send the operator looking in the wrong place, so a
// permission failure is fatal and names the capabilities to grant.
func checkBinaryVersion(ctx context.Context, run runner.Runner, bin string) error {
	out, err := run(ctx, nil, bin, "--version")
	if err == nil {
		log.Info().Str("check", strings.TrimSpace(out)).Msg("KernelCheck")
		return nil
	}

	if isPermissionDenied(out, err) {
		return fmt.Errorf("Cannot run %s: permission denied. %s", bin, capabilityHint)
	}

	// Some builds print the version differently; the binary is callable, which
	// is all this check is really after.
	log.Warn().Str("binary", bin).Str("output", strings.TrimSpace(out)).Msg("KernelCheck: version check failed")
	return nil
}

// isPermissionDenied reports whether a command failed because the process
// lacks the privileges to talk to the kernel.
func isPermissionDenied(out string, err error) bool {
	msg := strings.ToLower(out + " " + err.Error())
	return strings.Contains(msg, "permission") || strings.Contains(msg, "operation not permitted")
}

// validateNetworkNamespace checks that the process shares the host's network
// namespace.
//
// The daemon installs its rules in raw:PREROUTING and populates its ipsets.
// In a container's own network namespace both happen to the container, so the
// host keeps forwarding packets the daemon believes it is blocking. That is
// the same silent no-op as a daemon without privileges, so it fails fast here.
//
// There is no escape hatch: an operator who cannot manage the host's
// netfilter tables has no business running this daemon.
func validateNetworkNamespace(currentNetns func() (netns.Namespace, error)) error {
	ns, err := currentNetns()
	if err != nil {
		return fmt.Errorf("Cannot determine the network namespace: %w", err)
	}

	if !ns.IsInitial() {
		return fmt.Errorf("Not sharing the host network namespace (%s, expected the initial namespace net:[%d]): "+
			"the daemon's ipset and iptables rules would apply to this container only, not to the host, "+
			"so it would filter nothing while looking healthy. "+
			"If you are running in Docker, `network_mode: host` must be enabled (in docker-compose.yaml), "+
			"or pass `--net=host` to docker run. "+
			"If you are running in Kubernetes, set `hostNetwork: true` on the pod.",
			ns.Link, netns.InitialIno)
	}

	log.Info().Str("netns", ns.Link).Msg("KernelCheck: host network namespace confirmed")
	return nil
}

// probeIPSet verifies that ipset can talk to the kernel.
//
// The probe lists a set that does not exist, so ipset is expected to fail.
// That failure is the success signal: it proves the ipset kernel interface
// answered. Its wording is therefore never surfaced as if something were
// wrong — the expected outcome is reported as such, and the raw error text is
// only attached when the probe fails for a reason it should not have.
func probeIPSet(ctx context.Context, run runner.Runner) error {
	out, err := run(ctx, nil, "ipset", "list", ipsetProbeSet)
	if err == nil {
		return fmt.Errorf("ipset probe set %q exists; remove it before starting the daemon", ipsetProbeSet)
	}

	msg := strings.ToLower(out + " " + err.Error())
	switch {
	case isPermissionDenied(out, err):
		return fmt.Errorf("Cannot access ipset: permission denied. %s", capabilityHint)
	case strings.Contains(msg, "module") || strings.Contains(msg, "unknown"):
		return fmt.Errorf("Cannot access ipset: netfilter modules missing or ipset unsupported in this kernel (%s)", strings.TrimSpace(out))
	case ipsetSetAbsent(msg):
		log.Info().Str("probe_set", ipsetProbeSet).Msg("KernelCheck: ipset reachable (probe set absent, as expected)")
		return nil
	default:
		return fmt.Errorf("Cannot access ipset: unexpected probe failure (%s): %w", strings.TrimSpace(out), err)
	}
}

// ipsetSetAbsent reports whether the probe output says the set does not
// exist. The wording differs slightly between ipset releases, so a few
// spellings are accepted.
func ipsetSetAbsent(msg string) bool {
	for _, phrase := range []string{"does not exist", "doesn't exist", "no such set", "cannot find"} {
		if strings.Contains(msg, phrase) {
			return true
		}
	}
	return false
}

// probeIPTables verifies that the raw table can be read, which needs the same
// privileges the daemon requires to install its rules.
func probeIPTables(ctx context.Context, run runner.Runner) error {
	out, err := run(ctx, nil, "iptables", "-t", "raw", "-L", "-n")
	if err != nil {
		if isPermissionDenied(out, err) {
			return fmt.Errorf("Cannot access iptables: permission denied. %s", capabilityHint)
		}
		return fmt.Errorf("Cannot access iptables raw table (%s): %w", strings.TrimSpace(out), err)
	}
	log.Info().Msg("KernelCheck: iptables raw table accessible")
	return nil
}
