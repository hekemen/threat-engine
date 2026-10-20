// Package adapters normalizes heterogeneous threat feeds into plain slices of
// IP or CIDR strings. Adding a source means implementing FeedAdapter and
// registering it in Default(); syntax validation, de-duplication, and
// whitelist filtering happen downstream in the engine.
package adapters

import (
	"context"
	"net/http"
)

// FeedAdapter is the contract every threat source implements. Fetch returns
// raw IP or CIDR tokens; validation is not the adapter's job.
type FeedAdapter interface {
	Name() string
	Fetch(ctx context.Context, client *http.Client) ([]string, error)
}

// Default returns the standard feed set, in the order they are polled.
func Default() []FeedAdapter {
	return []FeedAdapter{
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
}
