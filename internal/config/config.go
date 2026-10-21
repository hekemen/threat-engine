// Package config loads the daemon's settings from the environment.
//
// Environment variables:
//
//	INTERVAL_MINUTES     scan interval in minutes (default 5; invalid/zero falls back)
//	HTTP_PORT            HTTP listen port (default 9090)
//	ADMIN_PORT           loopback-only admin listen port (default 9091)
//	HOSTILE_SET_NAME     kernel ipset name for blocked targets (default threat_engine_hostile_ips)
//	WHITELIST_SET_NAME   kernel ipset name for allowed targets (default threat_engine_whitelist_ips)
//	WHITELIST            comma-separated custom IPs/CIDRs to never block
//	ENFORCEMENT_ENABLED  attach the kernel drop rules (default false; unparseable falls back to false)
//
// Feed registration lives in internal/adapters, not here: config knows about
// sets and intervals, adapters know about sources.
package config

import (
	"log"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the resolved runtime configuration.
type Config struct {
	HostileSetName   string
	WhitelistSetName string
	HTTPPort         string
	AdminPort        string
	ScanInterval     time.Duration
	CustomWhitelist  []netip.Prefix
	// EnforcementEnabled controls whether the kernel drop rules are attached.
	// It defaults to false so that installing the daemon can never silently
	// drop traffic; the ipset tables are populated either way.
	EnforcementEnabled bool
}

// defaultPrivateSubnets returns the ranges that must never enter the hostile
// set: RFC 1918, RFC 3927 link-local, and loopback (see AGENTS.md rule 1).
//
// Only IPv4 is listed. The kernel sets are `family inet` and enforcement is
// IPv4 iptables, so IPv6 ranges cannot be added to the whitelist set and would
// abort the whole restore. IPv6 targets are filtered during aggregation
// instead.
func defaultPrivateSubnets() []netip.Prefix {
	cidrs := []string{
		"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12",
		"192.168.0.0/16", "169.254.0.0/16",
	}
	var list []netip.Prefix
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(c); err == nil {
			list = append(list, p)
		}
	}
	return list
}

// Load reads the environment and returns the effective configuration.
func Load() Config {
	hostileSet := getEnv("HOSTILE_SET_NAME", "threat_engine_hostile_ips")
	whitelistSet := getEnv("WHITELIST_SET_NAME", "threat_engine_whitelist_ips")
	port := getEnv("HTTP_PORT", "9090")
	adminPort := getEnv("ADMIN_PORT", "9091")

	// Scan interval: default 5 minutes
	intervalMin := 5
	if val := os.Getenv("INTERVAL_MINUTES"); val != "" {
		if i, err := strconv.Atoi(val); err == nil && i > 0 {
			intervalMin = i
		}
	}

	// Build Whitelist: private ranges plus any operator-supplied entries.
	// IPv6 entries are ignored with a warning: the sets are IPv4-only, so
	// carrying one through would abort every restore.
	combinedWhitelist := defaultPrivateSubnets()
	if raw := os.Getenv("WHITELIST"); raw != "" {
		for _, item := range strings.Split(raw, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			if strings.Contains(item, "/") {
				p, err := netip.ParsePrefix(item)
				if err != nil {
					continue
				}
				if !p.Addr().Is4() {
					log.Printf("[Config] ignoring IPv6 whitelist entry %q: enforcement is IPv4-only", item)
					continue
				}
				combinedWhitelist = append(combinedWhitelist, p)
			} else {
				addr, err := netip.ParseAddr(item)
				if err != nil {
					continue
				}
				if !addr.Is4() {
					log.Printf("[Config] ignoring IPv6 whitelist entry %q: enforcement is IPv4-only", item)
					continue
				}
				combinedWhitelist = append(combinedWhitelist, netip.PrefixFrom(addr, 32))
			}
		}
	}

	return Config{
		HostileSetName:     hostileSet,
		WhitelistSetName:   whitelistSet,
		HTTPPort:           port,
		AdminPort:          adminPort,
		ScanInterval:       time.Duration(intervalMin) * time.Minute,
		CustomWhitelist:    combinedWhitelist,
		EnforcementEnabled: parseBool(os.Getenv("ENFORCEMENT_ENABLED"), false),
	}
}

// parseBool resolves a boolean environment value. Anything unrecognized
// returns the fallback, so a typo can never enable enforcement.
func parseBool(raw string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "1", "yes":
		return true
	case "false", "0", "no":
		return false
	default:
		return fallback
	}
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}
