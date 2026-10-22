// Package config loads the daemon's settings from the environment.
//
// Environment variables:
//
//	INTERVAL_MINUTES     scan interval in minutes (default 5; invalid/zero falls back)
//	COUNTER_INTERVAL_SECONDS  kernel drop-counter poll interval in seconds (default 10; floor 1)
//	HTTP_PORT            HTTP listen port (default 9090)
//	ADMIN_PORT           loopback-only admin listen port (default 9091)
//	ADMIN_SOCKET         unix domain socket path for admin control (default /var/run/threat-engine/admin.sock)
//	HOSTILE_SET_NAME     kernel ipset name for blocked targets (default threat_engine_hostile_ips)
//	WHITELIST_SET_NAME   kernel ipset name for allowed targets (default threat_engine_whitelist_ips)
//	WHITELIST            comma-separated custom IPs/CIDRs to never block
//	ENFORCEMENT_ENABLED  attach the kernel drop rules (default false; unparseable falls back to false).
//	                     If set at all, enforcement cannot be changed at runtime via the admin socket.
//	ENFORCEMENT_LOCK     explicitly lock (true) or unlock (false) runtime enforcement changes.
//	                     Unset means: locked whenever ENFORCEMENT_ENABLED is present in the environment.

package config

import (
	"github.com/rs/zerolog/log"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// DefaultCounterInterval is the kernel drop-counter poll interval used when
// COUNTER_INTERVAL_SECONDS is unset or unparseable.
const DefaultCounterInterval = 10 * time.Second

// MinCounterInterval is the floor for the poll interval. Reading the kernel
// counters costs one iptables call, so a tighter loop only adds load.
const MinCounterInterval = time.Second

// Config is the resolved runtime configuration.
type Config struct {
	HostileSetName   string
	WhitelistSetName string
	HTTPPort         string
	AdminPort        string
	// AdminSocket is the path to the unix domain socket used for runtime
	// enforcement control. When empty, the TCP admin listener is used.
	AdminSocket string
	// EnforcementLocked records whether ENFORCEMENT_ENABLED was explicitly set
	// in the environment. When true, the admin socket cannot change
	// enforcement (useful for Kubernetes ConfigMap-mounted env vars).
	EnforcementLocked bool
	ScanInterval      time.Duration
	// CounterInterval is how often the kernel's drop counters are sampled.
	CounterInterval time.Duration
	CustomWhitelist []netip.Prefix
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
	adminSock := getEnv("ADMIN_SOCKET", "/var/run/threat-engine/admin.sock")
	enfRaw, enfSet := os.LookupEnv("ENFORCEMENT_ENABLED")

	// Enforcement is locked when ENFORCEMENT_ENABLED is present in the
	// environment: the env var owns the flag, which is what a Kubernetes
	// ConfigMap-bound deployment wants.
	//
	// ENFORCEMENT_LOCK is the explicit override. It exists because a
	// deployment may want the env var to set the *initial* state while still
	// allowing runtime toggles over the admin socket — a plain env var alone
	// cannot express "start enabled, but let the operator change it later".
	// An unparseable value keeps the lock: failing open here would let an
	// operator's typo silently unlock a ConfigMap-owned setting.
	enfLocked := enfSet
	if lockRaw, lockSet := os.LookupEnv("ENFORCEMENT_LOCK"); lockSet {
		enfLocked = parseBool(lockRaw, true)
	}

	// Scan interval: default 5 minutes
	intervalMin := 5
	if val := os.Getenv("INTERVAL_MINUTES"); val != "" {
		if i, err := strconv.Atoi(val); err == nil && i > 0 {
			intervalMin = i
		}
	}

	// Kernel drop-counter poll interval: default 10 seconds, floor 1 second.
	counterInterval := DefaultCounterInterval
	if val := os.Getenv("COUNTER_INTERVAL_SECONDS"); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			switch {
			case i < 1:
				counterInterval = MinCounterInterval
			default:
				counterInterval = time.Duration(i) * time.Second
			}
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
					log.Warn().Str("entry", item).Msg("Config: ignoring IPv6 whitelist entry (enforcement is IPv4-only)")
					continue
				}
				combinedWhitelist = append(combinedWhitelist, p)
			} else {
				addr, err := netip.ParseAddr(item)
				if err != nil {
					continue
				}
				if !addr.Is4() {
					log.Warn().Str("entry", item).Msg("Config: ignoring IPv6 whitelist entry (enforcement is IPv4-only)")
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
		AdminSocket:        adminSock,
		EnforcementLocked:  enfLocked,
		ScanInterval:       time.Duration(intervalMin) * time.Minute,
		CounterInterval:    counterInterval,
		CustomWhitelist:    combinedWhitelist,
		EnforcementEnabled: parseBool(enfRaw, false),
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
