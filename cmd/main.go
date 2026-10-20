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

	"github.com/hekemen/thread-engine/internal/adapters"
	"github.com/hekemen/thread-engine/internal/api"
	"github.com/hekemen/thread-engine/internal/config"
	"github.com/hekemen/thread-engine/internal/engine"
	"github.com/hekemen/thread-engine/internal/ipset"
	"github.com/hekemen/thread-engine/internal/iptables"
	"github.com/hekemen/thread-engine/internal/metrics"
	"github.com/hekemen/thread-engine/internal/runner"
)

func main() {
	cfg := config.Load()
	feeds := adapters.Default()
	log.Printf("Starting K3s Multi-Source Threat Engine (Scan Interval: %v, Adapters: %d)",
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
	eng := &engine.Engine{
		Adapters:   feeds,
		Whitelist:  cfg.CustomWhitelist,
		IPSet:      setManager,
		Firewall:   firewall,
		Metrics:    m,
		HTTPClient: &http.Client{Timeout: 35 * time.Second},
	}

	server := (&api.Server{Metrics: m, IPSet: setManager, Port: cfg.HTTPPort}).HTTPServer()
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server failure: %v", err)
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
			return
		}
	}
}
