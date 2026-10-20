package adapters

import (
	"context"
	"net/http"
	"strings"
)

// SpamhausDropAdapter parses the DROP list, whose lines are
// "<CIDR>; <SBL-ID>". Only the first field is a network, so the rest is
// discarded.
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
