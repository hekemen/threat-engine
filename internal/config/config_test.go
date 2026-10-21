package config_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/hekemen/threat-engine/internal/config"
)

func prefixSet(list []netip.Prefix) map[netip.Prefix]bool {
	m := map[netip.Prefix]bool{}
	for _, p := range list {
		m[p] = true
	}
	return m
}

func TestLoadDefaults(t *testing.T) {
	c := config.Load()
	if c.HostileSetName != "threat_engine_hostile_ips" || c.WhitelistSetName != "threat_engine_whitelist_ips" {
		t.Fatalf("set names wrong: %+v", c)
	}
	if c.HTTPPort != "9090" || c.ScanInterval != 5*time.Minute {
		t.Fatalf("port/interval wrong: %+v", c)
	}
	set := prefixSet(c.CustomWhitelist)
	for _, want := range []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"} {
		p := netip.MustParsePrefix(want)
		if !set[p] {
			t.Fatalf("default whitelist missing %s: %v", want, c.CustomWhitelist)
		}
	}
	// IPv6 must not appear: the ipset tables are family inet, so a v6 member
	// aborts the restore with "128 is out of range 0-32".
	for _, p := range c.CustomWhitelist {
		if !p.Addr().Is4() {
			t.Fatalf("default whitelist must be IPv4-only, found %s", p)
		}
	}
}

func TestLoadOverrides(t *testing.T) {
	t.Setenv("HOSTILE_SET_NAME", "evil_set")
	t.Setenv("WHITELIST_SET_NAME", "nice_set")
	t.Setenv("HTTP_PORT", "8080")
	t.Setenv("INTERVAL_MINUTES", "10")
	c := config.Load()
	if c.HostileSetName != "evil_set" || c.WhitelistSetName != "nice_set" ||
		c.HTTPPort != "8080" || c.ScanInterval != 10*time.Minute {
		t.Fatalf("overrides not applied: %+v", c)
	}
}

func TestLoadInvalidIntervalFallsBack(t *testing.T) {
	t.Setenv("INTERVAL_MINUTES", "abc")
	if config.Load().ScanInterval != 5*time.Minute {
		t.Fatal("invalid interval should fall back to 5m")
	}
	t.Setenv("INTERVAL_MINUTES", "0")
	if config.Load().ScanInterval != 5*time.Minute {
		t.Fatal("zero interval should fall back to 5m")
	}
}

func TestLoadEnforcementFailSafe(t *testing.T) {
	if config.Load().EnforcementEnabled {
		t.Fatal("enforcement must default to disabled")
	}
	for _, raw := range []string{"", "flase", "TRUE!", "maybe", "enabled"} {
		t.Setenv("ENFORCEMENT_ENABLED", raw)
		if config.Load().EnforcementEnabled {
			t.Fatalf("ENFORCEMENT_ENABLED=%q must fail safe to false", raw)
		}
	}
}

func TestLoadEnforcementTruthy(t *testing.T) {
	for _, raw := range []string{"true", "TRUE", "1", "yes", "Yes"} {
		t.Setenv("ENFORCEMENT_ENABLED", raw)
		if !config.Load().EnforcementEnabled {
			t.Fatalf("ENFORCEMENT_ENABLED=%q must enable enforcement", raw)
		}
	}
}

func TestLoadEnforcementFalsy(t *testing.T) {
	for _, raw := range []string{"false", "FALSE", "0", "no"} {
		t.Setenv("ENFORCEMENT_ENABLED", raw)
		if config.Load().EnforcementEnabled {
			t.Fatalf("ENFORCEMENT_ENABLED=%q must disable enforcement", raw)
		}
	}
}

func TestLoadAdminPort(t *testing.T) {
	if got := config.Load().AdminPort; got != "9091" {
		t.Fatalf("default AdminPort = %q, want 9091", got)
	}
	t.Setenv("ADMIN_PORT", "9191")
	if got := config.Load().AdminPort; got != "9191" {
		t.Fatalf("AdminPort = %q, want 9191", got)
	}
}

func TestLoadWhitelistParsing(t *testing.T) {
	t.Setenv("WHITELIST", "203.0.113.10, 198.51.100.0/24, fd00::1, bogus")
	c := config.Load()
	set := prefixSet(c.CustomWhitelist)
	if !set[netip.MustParsePrefix("203.0.113.10/32")] {
		t.Fatal("bare IPv4 not expanded to /32")
	}
	if !set[netip.MustParsePrefix("198.51.100.0/24")] {
		t.Fatal("CIDR not parsed")
	}
	// IPv6 entries are rejected outright: they cannot be represented in a
	// family inet set and would abort the restore transaction.
	if set[netip.MustParsePrefix("fd00::1/128")] {
		t.Fatal("IPv6 whitelist entry must be ignored, not expanded")
	}
	for _, p := range c.CustomWhitelist {
		if p.String() == "bogus" {
			t.Fatal("invalid entry must be skipped")
		}
		if !p.Addr().Is4() {
			t.Fatalf("whitelist must stay IPv4-only, found %s", p)
		}
	}
}
