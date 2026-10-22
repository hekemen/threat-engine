// Command threat-engine is an autonomous threat-intelligence daemon that
// polls multi-source IP blocklists, fingerprints them with SHA-256, and
// enforces changes directly in the Linux kernel via ipset and iptables.
//
// Rules are installed in the raw table's PREROUTING chain, before connection
// tracking and K3s/Docker NAT, so container service traffic cannot bypass
// them. This file is wiring only; the logic lives under internal/.
package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/hekemen/threat-engine/internal/adapters"
	"github.com/hekemen/threat-engine/internal/api"
	"github.com/hekemen/threat-engine/internal/config"
	"github.com/hekemen/threat-engine/internal/enforcement"
	"github.com/hekemen/threat-engine/internal/engine"
	"github.com/hekemen/threat-engine/internal/ipset"
	"github.com/hekemen/threat-engine/internal/iptables"
	"github.com/hekemen/threat-engine/internal/kernelstats"
	"github.com/hekemen/threat-engine/internal/metrics"
	"github.com/hekemen/threat-engine/internal/netns"
	"github.com/hekemen/threat-engine/internal/runner"
)

// enforcementStartupMessage returns the startup line for the enforcement
// state.
//
// The wording has to match what the daemon will actually accept:
//
//   - The disabled variant names the endpoint to call. An earlier version
//     referred to it by its log field ("POST to admin_url"), which rendered
//     as an unsubstituted template: "POST to admin_url
//     admin_url=http://127.0.0.1:9091/...".
//   - A locked daemon refuses runtime toggles with 403, so it must not
//     advertise one. The environment owns the flag; the operator changes it
//     there and restarts.
func enforcementStartupMessage(enabled, locked bool, adminPort string) string {
	switch {
	case enabled && locked:
		return "Enforcement: ENABLED — hostile DROP rules will be attached to raw:PREROUTING. " +
			"The flag is locked by the environment, so runtime toggles are refused."
	case enabled:
		return "Enforcement: ENABLED — hostile DROP rules will be attached to raw:PREROUTING. " +
			"Disable with `threat-engine enforce off`."
	case locked:
		return "Enforcement: DISABLED (dry-run; ipsets populated, no kernel rules) — " +
			"the flag is locked by the environment, so runtime toggles are refused. " +
			"Change ENFORCEMENT_ENABLED in the environment and restart to enable it."
	default:
		return "Enforcement: DISABLED (dry-run; ipsets populated, no kernel rules) — " +
			"enable with `threat-engine enforce on`, or POST to http://127.0.0.1:" + adminPort +
			"/enforcement?enabled=true"
	}
}

// main is the daemon entry point.
func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	// The enforcement CLI. It answers to two shapes: the documented
	// subcommand (`threat-engine enforce on`) and the `enforce` alias the
	// image installs (`docker exec threat-engine enforce on`).
	if call, ok := enforceInvocation(os.Args); ok {
		runEnforce(call)
		return
	}

	cfg := config.Load()
	feeds := adapters.Default()
	log.Info().Dur("scan_interval", cfg.ScanInterval).Dur("counter_interval", cfg.CounterInterval).Int("adapters", len(feeds)).Msg("Starting Threat Engine")

	m := metrics.New()
	exec := runner.OS()

	setManager := &ipset.Manager{
		HostileSetName:   cfg.HostileSetName,
		WhitelistSetName: cfg.WhitelistSetName,
		Whitelist:        cfg.CustomWhitelist,
		Exec:             exec,
	}
	firewall := &iptables.Enforcer{
		HostileSetName:   cfg.HostileSetName,
		WhitelistSetName: cfg.WhitelistSetName,
		Exec:             exec,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Validate that we can execute kernel management commands in this environment.
	// If not (missing binaries, missing privileges, wrong network namespace),
	// fail fast with a clear error.
	if err := validateKernel(ctx, exec, netns.Current); err != nil {
		log.Fatal().Err(err).Msg("Startup validation failed")
	}

	var ctl *enforcement.Controller
	if cfg.EnforcementLocked {
		ctl = enforcement.NewLocked(firewall, cfg.EnforcementEnabled)
	} else {
		ctl = enforcement.New(firewall, cfg.EnforcementEnabled)
	}

	if cfg.EnforcementEnabled {
		log.Info().Msg(enforcementStartupMessage(true, cfg.EnforcementLocked, cfg.AdminPort))
	} else {
		log.Info().
			Str("admin_port", cfg.AdminPort).
			Msg(enforcementStartupMessage(false, cfg.EnforcementLocked, cfg.AdminPort))
	}

	eng := &engine.Engine{
		Adapters:    feeds,
		Whitelist:   cfg.CustomWhitelist,
		IPSet:       setManager,
		Enforcement: ctl,
		Metrics:     m,
		HTTPClient:  &http.Client{Timeout: 35 * time.Second},
	}

	apiServer := &api.Server{
		Metrics:           m,
		IPSet:             setManager,
		Port:              cfg.HTTPPort,
		Enforcement:       ctl,
		AdminPort:         cfg.AdminPort,
		AdminSocket:       cfg.AdminSocket,
		EnforcementLocked: cfg.EnforcementLocked,
	}

	// The public listener is the daemon's lifeline: if it cannot bind, the
	// process is misconfigured and exits.
	server := apiServer.HTTPServer()
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("HTTP server failure")
		}
	}()

	// Admin control: prefer a unix domain socket (e.g. mounted in K8s) over TCP.
	// If ENFORCEMENT_ENABLED was explicitly set in the environment, runtime
	// changes via the socket/TCP admin are disallowed.
	if ln, err := apiServer.ListenAdminSocket(); err != nil {
		log.Fatal().Err(err).Msg("Admin socket failure")
	} else if ln != nil {
		log.Info().Str("socket", cfg.AdminSocket).Msg("Admin control listening on unix socket")
		go func() {
			if err := apiServer.AdminSocketServer().Serve(ln); err != nil && err != http.ErrServerClosed {
				log.Warn().Err(err).Msg("Admin socket serve failed")
			}
		}()
	}

	// The admin listener is a separate, loopback-bound server. Keeping it off
	// the public listener is the whole access-control story: the toggle is
	// reachable only from the host/pod itself.
	//
	// A bind failure here must NOT kill the daemon: the admin surface is the
	// convenience path, and runtime toggling is also available via the unix
	// socket above.
	adminServer := apiServer.AdminHTTPServer()
	go func() {
		if err := adminServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Warn().Err(err).Str("addr", adminServer.Addr).Msg("Admin listener failed — runtime toggling is unavailable until restart")
		}
	}()

	// The kernel's drop counters are sampled on their own, much shorter,
	// schedule: the scan interval is minutes, but the counters are what an
	// operator actually watches. The monitor reads the counters out of band
	// and folds them into the metrics the API already serves.
	counterMonitor := &kernelstats.Monitor{
		Reader:   firewall,
		Metrics:  m,
		Interval: cfg.CounterInterval,
	}
	go counterMonitor.Run(ctx)

	// Initial scan upon startup. It populates the ipsets, so the blocklist is
	// live within seconds of boot instead of after a full scan interval, and
	// it establishes the kernel sets that the enforcement rules name.
	eng.ScanAndReconcile(ctx)

	// Scheduled scan ticker
	ticker := time.NewTicker(cfg.ScanInterval)
	defer ticker.Stop()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	for {
		select {
		case <-ticker.C:
			eng.ScanAndReconcile(ctx)
		case sig := <-sigChan:
			log.Info().Str("signal", sig.String()).Msg("Received signal, cleaning up")

			// Stop the counter monitor before the kernel is torn down, so it
			// cannot read a half-deleted chain.
			cancel()

			server.Shutdown(context.Background())
			adminServer.Shutdown(context.Background())

			// Tear the kernel back down before exiting. Without this the chain
			// and its DROP rule survived the process, leaving the host
			// filtering against a blocklist nothing was refreshing.
			//
			// Bounded: a wedged iptables must not keep the container alive
			// until the runtime's own kill timeout.
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()

			if err := ctl.Shutdown(shutdownCtx); err != nil {
				log.Warn().Err(err).Msg("Enforcement teardown failed — the chain may still be attached")
			}
			if err := setManager.Destroy(shutdownCtx); err != nil {
				log.Warn().Err(err).Msg("Ipset destroy failed — kernel sets may remain")
			}
			log.Info().Msg("Enforcement detached and kernel sets removed")
			return
		}
	}
}
