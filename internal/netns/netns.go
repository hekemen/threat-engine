// Package netns identifies the network namespace a process runs in.
//
// The daemon edits the host's netfilter tables, so it has to run in the host's
// network namespace. The kernel assigns the initial namespace a fixed inode
// number (INIT_NETNS_INO in include/linux/net_namespace.h) that it never
// reuses, so comparing the process's namespace inode against that constant
// tells us whether we share the host's namespace — without shelling out and
// without depending on the container runtime.
package netns

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// InitialIno is the inode number of the initial (host) network namespace.
//
// The kernel hard-codes it in include/linux/net_namespace.h as
// INIT_NETNS_INO (0xEFFFFFF9). Every other namespace is given an inode from
// the same counter, so the value is unique and is never recycled.
const InitialIno uint64 = 0xEFFFFFF9

// procNetNS is the procfs entry naming the caller's network namespace.
const procNetNS = "/proc/self/ns/net"

// linkPrefix and linkSuffix are the brackets the kernel wraps a namespace
// inode in: "net:[4026531833]".
const (
	linkPrefix = "net:["
	linkSuffix = "]"
)

// Namespace identifies a network namespace.
type Namespace struct {
	// Link is the raw procfs link target, e.g. "net:[4026531833]".
	Link string
	// Ino is the inode number parsed from Link.
	Ino uint64
}

// IsInitial reports whether ns is the initial network namespace, i.e. the
// one the host itself lives in.
func (ns Namespace) IsInitial() bool {
	return ns.Ino == InitialIno
}

// Current returns the network namespace of the calling process.
func Current() (Namespace, error) {
	link, err := os.Readlink(procNetNS)
	if err != nil {
		return Namespace{}, fmt.Errorf("cannot read %s: %w", procNetNS, err)
	}

	ino, err := Parse(link)
	if err != nil {
		return Namespace{}, fmt.Errorf("cannot parse the %s link %q: %w", procNetNS, link, err)
	}

	return Namespace{Link: link, Ino: ino}, nil
}

// Parse extracts the inode number from a procfs namespace link, which the
// kernel writes as "net:[<inode>]".
func Parse(link string) (uint64, error) {
	if !strings.HasPrefix(link, linkPrefix) || !strings.HasSuffix(link, linkSuffix) {
		return 0, fmt.Errorf("unexpected namespace link format: %q", link)
	}

	digits := strings.TrimSuffix(strings.TrimPrefix(link, linkPrefix), linkSuffix)
	if digits == "" {
		return 0, fmt.Errorf("namespace link %q carries no inode number", link)
	}

	ino, err := strconv.ParseUint(digits, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("namespace link %q carries an invalid inode number: %w", link, err)
	}

	return ino, nil
}
