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
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hekemen/threat-engine/internal/adapters"
	"github.com/hekemen/threat-engine/internal/api"
	"github.com/hekemen/threat-engine/internal/config"
	"github.com/hekemen/threat-engine/internal/enforcement"
	"github.com/hekemen/threat-engine/internal/engine"
	"github.com/hekemen/threat-engine/internal/ipset"
	"github.com/hekemen/threat-engine/internal/iptables"
	"github.com/hekemen/threat-engine/internal/metrics"
	"github.com/hekemen/threat-engine/internal/runner"
)

func main() {
	cfg := config.Load()
	feeds := adapters.Default()
	log.Printf("Starting Threat Engine (Scan Interval: %v, Adapters: %d)",
		cfg.ScanInterval, len(feeds))

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
	ctl := enforcement.New(firewall, cfg.EnforcementEnabled)

	if cfg.EnforcementEnabled {
		log.Printf("Enforcement: ENABLED — hostile DROP rules will be attached to raw:PREROUTING.")
	} else {
		log.Printf("Enforcement: DISABLED (dry-run; ipsets populated, no kernel rules) — enable with POST http://127.0.0.1:%s/enforcement?enabled=true", cfg.AdminPort)
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
		Metrics:     m,
		IPSet:       setManager,
		Port:        cfg.HTTPPort,
		Enforcement: ctl,
		AdminPort:   cfg.AdminPort,
	}

	// The public listener is the daemon's lifeline: if it cannot bind, the
	// process is misconfigured and exits.
	server := apiServer.HTTPServer()
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server failure: %v", err)
		}
	}()

	// The admin listener is a separate, loopback-bound server. Keeping it off
	// the public listener is the whole access-control story: the toggle is
	// reachable only from the host/pod itself.
	//
	// A bind failure here must NOT kill the daemon: the admin surface is the
	// convenience path, and taking down enforcement (and the blocklist refresh)
	// because a port was busy is the wrong blast radius. Log loudly and keep
	// running; ENFORCEMENT_ENABLED and the per-scan reconcile still work.
	adminServer := apiServer.AdminHTTPServer()
	go func() {
		if err := adminServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[Admin Warning] admin listener on %s failed: %v — runtime toggling is unavailable until restart", adminServer.Addr, err)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initial scan upon startup
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
			log.Printf("Received signal %v. Cleaning up...", sig)
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
				log.Printf("[Cleanup] enforcement teardown failed: %v — the chain may still be attached", err)
			}
			if err := setManager.Destroy(shutdownCtx); err != nil {
				log.Printf("[Cleanup] ipset destroy failed: %v — kernel sets may remain", err)
			}
			log.Printf("[Cleanup] enforcement detached and kernel sets removed.")
			return
		}
	}
}
