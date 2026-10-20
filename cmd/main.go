package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ==========================================
// 1. DATA SOURCE ADAPTER INTERFACE & IMPLEMENTATIONS
// ==========================================

type FeedAdapter interface {
	Name() string
	Fetch(ctx context.Context, client *http.Client) ([]string, error)
}

// IPsumAdapter handles scored IPs (<IP>\t<Score>)
type IPsumAdapter struct {
	URL          string
	MinThreshold int
}

func (a *IPsumAdapter) Name() string { return "IPsum" }
func (a *IPsumAdapter) Fetch(ctx context.Context, client *http.Client) ([]string, error) {
	lines, err := fetchLines(ctx, client, a.URL)
	if err != nil {
		return nil, err
	}
	var ips []string
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			if score, err := strconv.Atoi(parts[1]); err == nil && score >= a.MinThreshold {
				ips = append(ips, parts[0])
			}
		}
	}
	return ips, nil
}

// SpamhausDropAdapter parses CIDRs separated by semicolons
type SpamhausDropAdapter struct {
	URL string
}

func (a *SpamhausDropAdapter) Name() string { return "Spamhaus-DROP" }
func (a *SpamhausDropAdapter) Fetch(ctx context.Context, client *http.Client) ([]string, error) {
	lines, err := fetchLines(ctx, client, a.URL)
	if err != nil {
		return nil, err
	}
	var cidrs []string
	for _, line := range lines {
		parts := strings.Split(line, ";")
		cidr := strings.TrimSpace(parts[0])
		if cidr != "" {
			cidrs = append(cidrs, cidr)
		}
	}
	return cidrs, nil
}

// LineDelimitedAdapter parses feeds with one IP or CIDR per line (FireHOL, Blocklist.de, Feodo)
type LineDelimitedAdapter struct {
	FeedName string
	URL      string
}

func (a *LineDelimitedAdapter) Name() string { return a.FeedName }
func (a *LineDelimitedAdapter) Fetch(ctx context.Context, client *http.Client) ([]string, error) {
	return fetchLines(ctx, client, a.URL)
}

func fetchLines(ctx context.Context, client *http.Client, url string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "k3s-threat-engine/2.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	var results []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		results = append(results, line)
	}
	return results, scanner.Err()
}

// ==========================================
// 2. CONFIGURATION & STATE ENGINE
// ==========================================

type Config struct {
	HostileSetName   string
	WhitelistSetName string
	HTTPPort         string
	ScanInterval     time.Duration
	CustomWhitelist  []netip.Prefix
	Adapters         []FeedAdapter
}

type Metrics struct {
	mu                  sync.RWMutex
	BlockedIPsCount     int
	WhitelistCount      int
	LastScanUnix        int64
	LastChangeUnix      int64
	UpdatesAppliedTotal int64
	ScanSuccessTotal    int64
	ScanFailureTotal    int64
	LastHash            string
}

var (
	metrics = &Metrics{}
	cfg     Config
)

func defaultPrivateSubnets() []netip.Prefix {
	cidrs := []string{
		"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12",
		"192.168.0.0/16", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
	}
	var list []netip.Prefix
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(c); err == nil {
			list = append(list, p)
		}
	}
	return list
}

func loadConfig() Config {
	hostileSet := getEnv("HOSTILE_SET_NAME", "k3s_hostile_ips")
	whitelistSet := getEnv("WHITELIST_SET_NAME", "k3s_whitelist_ips")
	port := getEnv("HTTP_PORT", "9090")

	// Scan interval: default 5 minutes
	intervalMin := 5
	if val := os.Getenv("INTERVAL_MINUTES"); val != "" {
		if i, err := strconv.Atoi(val); err == nil && i > 0 {
			intervalMin = i
		}
	}

	// Build Whitelist
	combinedWhitelist := defaultPrivateSubnets()
	if raw := os.Getenv("WHITELIST"); raw != "" {
		for _, item := range strings.Split(raw, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			if strings.Contains(item, "/") {
				if p, err := netip.ParsePrefix(item); err == nil {
					combinedWhitelist = append(combinedWhitelist, p)
				}
			} else if addr, err := netip.ParseAddr(item); err == nil {
				bits := 32
				if addr.Is6() {
					bits = 128
				}
				combinedWhitelist = append(combinedWhitelist, netip.PrefixFrom(addr, bits))
			}
		}
	}

	// Register Data Source Adapters
	adapters := []FeedAdapter{
		&IPsumAdapter{
			URL:          "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
			MinThreshold: 3,
		},
		&SpamhausDropAdapter{
			URL: "https://www.spamhaus.org/drop/drop.txt",
		},
		&LineDelimitedAdapter{
			FeedName: "FireHOL-Level1",
			URL:      "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
		},
		&LineDelimitedAdapter{
			FeedName: "Blocklist.de-All",
			URL:      "https://lists.blocklist.de/lists/all.txt",
		},
		&LineDelimitedAdapter{
			FeedName: "Feodo-Tracker",
			URL:      "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
		},
	}

	return Config{
		HostileSetName:   hostileSet,
		WhitelistSetName: whitelistSet,
		HTTPPort:         port,
		ScanInterval:     time.Duration(intervalMin) * time.Minute,
		CustomWhitelist:  combinedWhitelist,
		Adapters:         adapters,
	}
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

// ==========================================
// 3. AGGREGATION, CHANGE DETECTION & FIREWALL
// ==========================================

func isWhitelisted(addr netip.Addr) bool {
	for _, p := range cfg.CustomWhitelist {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func aggregateFeeds(ctx context.Context) ([]string, error) {
	client := &http.Client{Timeout: 35 * time.Second}
	var wg sync.WaitGroup
	resultsChan := make(chan []string, len(cfg.Adapters))

	for _, adapter := range cfg.Adapters {
		wg.Add(1)
		go func(a FeedAdapter) {
			defer wg.Done()
			entries, err := a.Fetch(ctx, client)
			if err != nil {
				log.Printf("[%s Adapter] Fetch failed: %v", a.Name(), err)
				return
			}
			log.Printf("[%s Adapter] Retrieved %d candidate entries", a.Name(), len(entries))
			resultsChan <- entries
		}(adapter)
	}

	wg.Wait()
	close(resultsChan)

	uniqueEntries := make(map[string]struct{})
	for batch := range resultsChan {
		for _, raw := range batch {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}

			// Validate CIDR or Single IP
			if strings.Contains(raw, "/") {
				prefix, err := netip.ParsePrefix(raw)
				if err != nil || isWhitelisted(prefix.Addr()) {
					continue
				}
				uniqueEntries[prefix.String()] = struct{}{}
			} else {
				addr, err := netip.ParseAddr(raw)
				if err != nil || isWhitelisted(addr) {
					continue
				}
				uniqueEntries[addr.String()] = struct{}{}
			}
		}
	}

	sorted := make([]string, 0, len(uniqueEntries))
	for entry := range uniqueEntries {
		sorted = append(sorted, entry)
	}
	sort.Strings(sorted)

	return sorted, nil
}

func computeFingerprint(entries []string) string {
	h := sha256.New()
	for _, e := range entries {
		h.Write([]byte(e))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func syncIpset(entries []string) error {
	var buf bytes.Buffer

	// 1. Production sets
	buf.WriteString(fmt.Sprintf("create %s hash:net maxelem 300000 -exist\n", cfg.HostileSetName))
	buf.WriteString(fmt.Sprintf("create %s hash:net maxelem 50000 -exist\n", cfg.WhitelistSetName))

	// 2. Refresh Whitelist
	tmpWhitelist := fmt.Sprintf("%s_tmp", cfg.WhitelistSetName)
	buf.WriteString(fmt.Sprintf("create %s hash:net maxelem 50000 -exist\n", tmpWhitelist))
	buf.WriteString(fmt.Sprintf("flush %s\n", tmpWhitelist))
	for _, p := range cfg.CustomWhitelist {
		buf.WriteString(fmt.Sprintf("add %s %s -exist\n", tmpWhitelist, p.String()))
	}
	buf.WriteString(fmt.Sprintf("swap %s %s\n", tmpWhitelist, cfg.WhitelistSetName))
	buf.WriteString(fmt.Sprintf("destroy %s\n", tmpWhitelist))

	// 3. Atomically Swap Hostile Set
	tmpHostile := fmt.Sprintf("%s_tmp", cfg.HostileSetName)
	buf.WriteString(fmt.Sprintf("create %s hash:net maxelem 300000 -exist\n", tmpHostile))
	buf.WriteString(fmt.Sprintf("flush %s\n", tmpHostile))
	for _, entry := range entries {
		buf.WriteString(fmt.Sprintf("add %s %s -exist\n", tmpHostile, entry))
	}
	buf.WriteString(fmt.Sprintf("swap %s %s\n", tmpHostile, cfg.HostileSetName))
	buf.WriteString(fmt.Sprintf("destroy %s\n", tmpHostile))

	cmd := exec.Command("ipset", "restore")
	cmd.Stdin = &buf
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ipset restore failed: %v: %s", err, stderr.String())
	}
	return nil
}

func setupFirewallChains() error {
	chain := "K3S_THREAT_FILTER"
	exec.Command("iptables", "-t", "raw", "-N", chain).Run()

	chk := exec.Command("iptables", "-t", "raw", "-C", "PREROUTING", "-j", chain)
	if chk.Run() != nil {
		if err := exec.Command("iptables", "-t", "raw", "-I", "PREROUTING", "1", "-j", chain).Run(); err != nil {
			return fmt.Errorf("failed linking chain to PREROUTING: %v", err)
		}
	}

	cmds := [][]string{
		{"-t", "raw", "-F", chain},
		{"-t", "raw", "-A", chain, "-m", "set", "--match-set", cfg.WhitelistSetName, "src", "-j", "RETURN"},
		{"-t", "raw", "-A", chain, "-m", "set", "--match-set", cfg.HostileSetName, "src", "-j", "DROP"},
	}

	for _, args := range cmds {
		cmd := exec.Command("iptables", args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("rule error [%s]: %v: %s", strings.Join(args, " "), err, string(out))
		}
	}
	return nil
}

func scanAndReconcile(ctx context.Context) {
	log.Printf("[Scanner] Starting feed poll across %d adapters...", len(cfg.Adapters))

	entries, err := aggregateFeeds(ctx)
	if err != nil {
		log.Printf("[Scanner Error] Aggregation encountered issues: %v", err)
		metrics.mu.Lock()
		metrics.ScanFailureTotal++
		metrics.mu.Unlock()
		return
	}

	fingerprint := computeFingerprint(entries)

	metrics.mu.Lock()
	metrics.LastScanUnix = time.Now().Unix()
	metrics.ScanSuccessTotal++
	metrics.WhitelistCount = len(cfg.CustomWhitelist)

	// Change Detection Guard
	if fingerprint == metrics.LastHash {
		metrics.mu.Unlock()
		log.Printf("[Scanner] SHA-256 fingerprint matches (%s). Zero changes detected; skipping kernel update.", fingerprint[:12])
		return
	}
	metrics.mu.Unlock()

	log.Printf("[Scanner] Change detected! New fingerprint: %s. Reconciling %d unique targets...", fingerprint[:12], len(entries))

	if err := syncIpset(entries); err != nil {
		log.Printf("[Kernel Error] ipset swap failure: %v", err)
		return
	}

	if err := setupFirewallChains(); err != nil {
		log.Printf("[Kernel Error] iptables chain configuration failed: %v", err)
		return
	}

	metrics.mu.Lock()
	metrics.LastHash = fingerprint
	metrics.BlockedIPsCount = len(entries)
	metrics.LastChangeUnix = time.Now().Unix()
	metrics.UpdatesAppliedTotal++
	metrics.mu.Unlock()

	log.Printf("[Scanner Complete] Successfully applied updated rules. Blocklist entries: %d", len(entries))
}

// ==========================================
// 4. HTTP API & MONITORING
// ==========================================

func setupHTTPServer() *http.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		metrics.mu.RLock()
		lastScan := metrics.LastScanUnix
		metrics.mu.RUnlock()

		if lastScan == 0 {
			http.Error(w, "Initializing", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok\n"))
	})

	mux.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		ip := strings.TrimSpace(r.URL.Query().Get("ip"))
		if ip == "" {
			http.Error(w, `{"error":"ip parameter required"}`, http.StatusBadRequest)
			return
		}

		addr, err := netip.ParseAddr(ip)
		if err != nil {
			http.Error(w, `{"error":"invalid ip"}`, http.StatusBadRequest)
			return
		}

		isBlocked := exec.Command("ipset", "test", cfg.HostileSetName, addr.String()).Run() == nil
		isWhitelisted := exec.Command("ipset", "test", cfg.WhitelistSetName, addr.String()).Run() == nil

		status := "allowed"
		if isWhitelisted {
			status = "whitelisted"
		} else if isBlocked {
			status = "blocked"
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ip":             addr.String(),
			"status":         status,
			"is_blocked":     isBlocked,
			"is_whitelisted": isWhitelisted,
			"timestamp":      time.Now().UTC().Format(time.RFC3339),
		})
	})

	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		metrics.mu.RLock()
		defer metrics.mu.RUnlock()

		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		fmt.Fprintf(w, "# HELP threat_engine_blocked_targets_total Number of hostile IPs/CIDRs currently blocked in kernel\n")
		fmt.Fprintf(w, "# TYPE threat_engine_blocked_targets_total gauge\n")
		fmt.Fprintf(w, "threat_engine_blocked_targets_total %d\n\n", metrics.BlockedIPsCount)

		fmt.Fprintf(w, "# HELP threat_engine_whitelist_entries_total Active whitelist subnets\n")
		fmt.Fprintf(w, "# TYPE threat_engine_whitelist_entries_total gauge\n")
		fmt.Fprintf(w, "threat_engine_whitelist_entries_total %d\n\n", metrics.WhitelistCount)

		fmt.Fprintf(w, "# HELP threat_engine_scans_total Total scheduled scan attempts\n")
		fmt.Fprintf(w, "# TYPE threat_engine_scans_total counter\n")
		fmt.Fprintf(w, "threat_engine_scans_total{status=\"success\"} %d\n", metrics.ScanSuccessTotal)
		fmt.Fprintf(w, "threat_engine_scans_total{status=\"failure\"} %d\n\n", metrics.ScanFailureTotal)

		fmt.Fprintf(w, "# HELP threat_engine_updates_applied_total Times a change triggered an ipset swap\n")
		fmt.Fprintf(w, "# TYPE threat_engine_updates_applied_total counter\n")
		fmt.Fprintf(w, "threat_engine_updates_applied_total %d\n\n", metrics.UpdatesAppliedTotal)

		fmt.Fprintf(w, "# HELP threat_engine_last_scan_timestamp Unix timestamp of latest scan execution\n")
		fmt.Fprintf(w, "# TYPE threat_engine_last_scan_timestamp gauge\n")
		fmt.Fprintf(w, "threat_engine_last_scan_timestamp %d\n\n", metrics.LastScanUnix)

		fmt.Fprintf(w, "# HELP threat_engine_last_change_timestamp Unix timestamp when rules were last updated\n")
		fmt.Fprintf(w, "# TYPE threat_engine_last_change_timestamp gauge\n")
		fmt.Fprintf(w, "threat_engine_last_change_timestamp %d\n", metrics.LastChangeUnix)
	})

	return &http.Server{Addr: ":" + cfg.HTTPPort, Handler: mux}
}

// ==========================================
// 5. LIFECYCLE & SCHEDULER
// ==========================================

func main() {
	cfg = loadConfig()
	log.Printf("Starting K3s Multi-Source Threat Engine (Scan Interval: %v, Adapters: %d)",
		cfg.ScanInterval, len(cfg.Adapters))

	server := setupHTTPServer()
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server failure: %v", err)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initial scan upon startup
	scanAndReconcile(ctx)

	// Scheduled 5-minute ticker
	ticker := time.NewTicker(cfg.ScanInterval)
	defer ticker.Stop()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	for {
		select {
		case <-ticker.C:
			scanAndReconcile(ctx)
		case sig := <-sigChan:
			log.Printf("Received signal %v. Cleaning up...", sig)
			server.Shutdown(context.Background())
			return
		}
	}
}