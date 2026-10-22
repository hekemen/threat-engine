package netns_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hekemen/threat-engine/internal/netns"
)

// The kernel writes network namespace links as "net:[<inode>]".
func TestParseReadsTheInodeNumber(t *testing.T) {
	ino, err := netns.Parse("net:[4026531833]")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ino != 4026531833 {
		t.Fatalf("inode = %d, want 4026531833", ino)
	}
}

func TestParseRejectsMalformedLinks(t *testing.T) {
	for _, link := range []string{
		"",
		"net:",
		"net:[]",
		"net:[abc]",
		"4026531833",
		"net:[4026531833",
		"net:[4026531833]extra",
	} {
		if _, err := netns.Parse(link); err == nil {
			t.Fatalf("Parse(%q) must fail", link)
		}
	}
}

// The initial namespace is the one the host itself lives in.
func TestIsInitialRecognisesTheInitialNamespace(t *testing.T) {
	initial := netns.Namespace{Ino: netns.InitialIno}
	if !initial.IsInitial() {
		t.Fatal("the initial inode must be recognised as the initial namespace")
	}

	other := netns.Namespace{Ino: netns.InitialIno + 1}
	if other.IsInitial() {
		t.Fatal("a different inode must not be recognised as the initial namespace")
	}
}

// Current must agree with what the kernel reports for this process.
func TestCurrentReportsTheRunningProcessNamespace(t *testing.T) {
	ns, err := netns.Current()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	link, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Skipf("cannot read /proc/self/ns/net: %v", err)
	}
	if ns.Link != link {
		t.Fatalf("link = %q, want %q", ns.Link, link)
	}

	ino, err := netns.Parse(link)
	if err != nil {
		t.Fatalf("the kernel link %q must be parsable: %v", link, err)
	}
	if ns.Ino != ino {
		t.Fatalf("inode = %d, want %d", ns.Ino, ino)
	}
}

// The namespace file lives under /proc; the path is a constant so the test
// does not depend on how the process was started.
func TestCurrentReadsTheProcNamespaceLink(t *testing.T) {
	if _, err := os.Stat("/proc/self/ns/net"); err != nil {
		t.Skipf("/proc/self/ns/net is not available: %v", err)
	}
	ns, err := netns.Current()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(ns.Link, "net:[") {
		t.Fatalf("link = %q, want a net:[...] form", ns.Link)
	}
	if filepath.Base(ns.Link) == "" {
		t.Fatal("the link must not be empty")
	}
}
