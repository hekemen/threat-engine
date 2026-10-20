package adapters

import (
	"context"
	"net/http"
)

// LineDelimitedAdapter handles feeds with one IP or CIDR per line (FireHOL,
// Blocklist.de, Feodo Tracker). FeedName is the label used in logs.
type LineDelimitedAdapter struct {
	FeedName string
	URL      string
}

func (a *LineDelimitedAdapter) Name() string { return a.FeedName }

func (a *LineDelimitedAdapter) Fetch(ctx context.Context, client *http.Client) ([]string, error) {
	return fetchLines(ctx, client, a.URL)
}
