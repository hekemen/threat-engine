package adapters_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hekemen/threat-engine/internal/adapters"
)

func newClient() *http.Client { return &http.Client{} }

func serve(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestIPsumThreshold(t *testing.T) {
	srv := serve(t, "1.2.3.4\t5\n2.3.4.5\t1\n3.4.5.6\tx\n# comment line\n")
	got, err := (&adapters.IPsumAdapter{URL: srv.URL, MinThreshold: 3}).Fetch(context.Background(), newClient())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0] != "1.2.3.4" {
		t.Fatalf("got %v, want [1.2.3.4]", got)
	}
}

func TestSpamhausSemicolonSplit(t *testing.T) {
	srv := serve(t, "1.2.3.0/24; SBL123\n\n4.5.6.0/24;SBL456\n// skipme\n")
	got, err := (&adapters.SpamhausDropAdapter{URL: srv.URL}).Fetch(context.Background(), newClient())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 || got[0] != "1.2.3.0/24" || got[1] != "4.5.6.0/24" {
		t.Fatalf("got %v", got)
	}
}

func TestLineDelimitedSkipsCommentsAndBlanks(t *testing.T) {
	srv := serve(t, "# c\n// c\n\n1.2.3.4\n\n5.6.7.8\n")
	got, err := (&adapters.LineDelimitedAdapter{FeedName: "x", URL: srv.URL}).Fetch(context.Background(), newClient())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 || got[0] != "1.2.3.4" || got[1] != "5.6.7.8" {
		t.Fatalf("got %v", got)
	}
}

func TestFetchNon200ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	_, err := (&adapters.LineDelimitedAdapter{FeedName: "x", URL: srv.URL}).Fetch(context.Background(), newClient())
	if err == nil || !strings.Contains(err.Error(), "HTTP 500") {
		t.Fatalf("want HTTP 500 error, got %v", err)
	}
}

func TestFetchSendsUserAgent(t *testing.T) {
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		w.Write([]byte("1.2.3.4\n"))
	}))
	t.Cleanup(srv.Close)
	if _, err := (&adapters.LineDelimitedAdapter{FeedName: "x", URL: srv.URL}).Fetch(context.Background(), newClient()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotUA != "threat-engine/2.0" {
		t.Fatalf("User-Agent = %q", gotUA)
	}
}

func TestDefaultRegistersFiveFeeds(t *testing.T) {
	feeds := adapters.Default()
	if len(feeds) != 5 {
		t.Fatalf("got %d feeds", len(feeds))
	}
	want := []string{"IPsum", "Spamhaus-DROP", "FireHOL-Level1", "Blocklist.de-All", "Feodo-Tracker"}
	for i, f := range feeds {
		if f.Name() != want[i] {
			t.Fatalf("feed %d = %q, want %q", i, f.Name(), want[i])
		}
	}
}
