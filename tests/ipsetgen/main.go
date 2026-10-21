// Command ipsetgen prints the exact `ipset restore` script that
// ipset.Manager.Sync would pipe to the kernel, so a container harness can
// apply it against a real ipset.
//
// It lives inside the module because Sync is an internal package. Keep it a
// plain `package main` with no tests: it is a test fixture, not shipped code.
package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"

	"github.com/hekemen/threat-engine/internal/ipset"
)

// capture is an Exec that records the stdin Sync would hand to `ipset`.
func capture(out *bytes.Buffer) func(context.Context, io.Reader, string, ...string) (string, error) {
	return func(_ context.Context, stdin io.Reader, name string, args ...string) (string, error) {
		if stdin != nil {
			b, _ := io.ReadAll(stdin)
			out.Write(b)
		}
		return "", nil
	}
}

func main() {
	var buf bytes.Buffer

	// The real default whitelist (which used to carry IPv6 and abort every
	// scan) plus hostile entries covering IPv4, IPv4 CIDR, IPv6, and an IPv6
	// prefix. The IPv6 entries must not appear in the output at all.
	m := &ipset.Manager{
		HostileSetName:   "threat_engine_hostile_ips",
		WhitelistSetName: "threat_engine_whitelist_ips",
		Whitelist: []netip.Prefix{
			netip.MustParsePrefix("127.0.0.0/8"),
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("172.16.0.0/12"),
			netip.MustParsePrefix("192.168.0.0/16"),
			netip.MustParsePrefix("169.254.0.0/16"),
			netip.MustParsePrefix("::1/128"),
			netip.MustParsePrefix("fc00::/7"),
			netip.MustParsePrefix("fe80::/10"),
		},
		Exec: capture(&buf),
	}

	entries := []string{
		"1.2.3.4",
		"5.6.7.0/24",
		"2001:1308:a5cc:6600:e157:76a6:16c8:37df",
		"2001:db8::/32",
	}

	if err := m.Sync(context.Background(), entries); err != nil {
		fmt.Fprintln(os.Stderr, "Sync failed:", err)
		os.Exit(1)
	}

	fmt.Print(buf.String())
}
