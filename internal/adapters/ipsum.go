package adapters

import (
	"context"
	"net/http"
	"strconv"
	"strings"
)

// IPsumAdapter handles the score-weighted IPsum list, whose lines are
// "<IP>\t<Score>". Only entries at or above MinThreshold are kept, which is
// what makes this feed usable despite its long tail of one-off reports.
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
