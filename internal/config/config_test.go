package config_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/hekemen/thread-engine/internal/config"
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
	if c.HostileSetName != "k3s_hostile_ips" || c.WhitelistSetName != "k3s_whitelist_ips" {
		t.Fatalf("set names wrong: %+v", c)
	}
	if c.HTTPPort != "9090" || c.ScanInterval != 5*time.Minute {
		t.Fatalf("port/interval wrong: %+v", c)
	}
	set := prefixSet(c.CustomWhitelist)
	for _, want := range []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10"} {
		p := netip.MustParsePrefix(want)
		if !set[p] {
			t.Fatalf("default whitelist missing %s: %v", want, c.CustomWhitelist)
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
	if !set[netip.MustParsePrefix("fd00::1/128")] {
		t.Fatal("bare IPv6 not expanded to /128")
	}
	if len(c.CustomWhitelist) != 8+3 {
		t.Fatalf("invalid entry must be skipped: got %d prefixes: %v", len(c.CustomWhitelist), c.CustomWhitelist)
	}
}
