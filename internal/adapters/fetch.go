package adapters

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"strings"
)

// fetchLines downloads a feed and returns its non-comment, non-blank lines,
// trimmed. Comment conventions ("#" and "//") are common to every source we
// consume and are stripped here so parsers see only data.
func fetchLines(ctx context.Context, client *http.Client, url string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "threat-engine/2.0")

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
