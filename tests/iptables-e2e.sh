#!/bin/sh
# iptables-e2e.sh — prove that the raw:PREROUTING rules really filter.
#
# The ipset tables and the iptables rules can both look perfect while the
# filtering does nothing: a rule that never matches, a jump that points at an
# empty chain, a set the kernel does not consult. This script sends real
# packets through the node's PREROUTING path and watches what happens.
#
# How it works
#   A packet is only judged by a `--match-set ... src` rule if it *arrives*
#   at the node. Locally generated traffic leaves through OUTPUT and never
#   touches PREROUTING, so a plain `ping <node>` proves nothing. The script
#   therefore assigns a test address to `lo` and sends from it: the packet is
#   looped back through the ingress path, so it traverses PREROUTING with the
#   test address as its source.
#
#   Phase 1 (blocked)      the source is in the hostile set      -> no reply
#   Phase 2 (whitelisted)  the source is in both sets            -> reply
#
#   Phase 2 is the one that matters. The chain's whitelist RETURN comes
#   first, so a whitelisted source must get through even while it is also
#   listed as hostile. A reply proves the RETURN fired.
#
# Usage
#   sudo ./tests/iptables-e2e.sh                 # on the node
#   kubectl exec -i -n <ns> daemonset/threat-engine -- sh < tests/iptables-e2e.sh
#
#   --src IP        source address to use (default: an address no feed covers)
#   --dst IP        destination address (default: the node's own primary IP)
#   --hostile NAME  hostile ipset name     (default: threat_engine_hostile_ips)
#   --whitelist NAME  whitelist ipset name (default: threat_engine_whitelist_ips)
#   --count N       packets per phase (default: 3)
#
# Requirements
#   root with CAP_NET_ADMIN, and the threat-engine chain attached
#   (enforcement on). The script refuses to run against a detached chain,
#   because every packet would then pass and phase 1 would "fail" for the
#   wrong reason.
#
# Notes
#   The script adds and removes its own ipset entries. A daemon scan that
#   syncs the sets (every INTERVAL_MINUTES) can drop them mid-run, which
#   shows up as a phase that unexpectedly succeeds. The script re-adds the
#   entries before each phase, so a full run takes well under a second.
#
#   The script zeroes the chain counters to get a clean measurement window.
#   The daemon's own drop counters are totals, and it treats a decrease as a
#   kernel counter reset, so nothing is lost.

set -eu

CHAIN=THREAD_ENGINE_FILTER
HOSTILE_SET=threat_engine_hostile_ips
WHITELIST_SET=threat_engine_whitelist_ips
COUNT=3
SRC=""
DST=""
PING="ping"

# Addresses to try as the test source. Most "documentation" ranges are not
# safe: several feeds list 192.0.2.0/24, 198.51.100.0/24, 198.18.0.0/15 or
# even 203.0.0.0/8, so a source taken from those ranges is already hostile
# and the whitelist phase would be meaningless. The script picks a candidate
# that ipset reports as being in neither set.
CANDIDATES="192.88.99.1 192.31.196.1 198.19.255.1 100.127.255.1 192.0.0.9 198.18.0.1"

PASS=0
FAIL=0

ok() {
	PASS=$((PASS + 1))
	printf '  PASS  %s\n' "$1"
}

bad() {
	FAIL=$((FAIL + 1))
	printf '  FAIL  %s\n' "$1"
}

info() {
	printf '        %s\n' "$1"
}

die() {
	printf 'error: %s\n' "$1" >&2
	exit 2
}

usage() {
	sed -n '2,60p' "$0" | sed 's/^# \{0,1\}//'
	exit "${1:-0}"
}

while [ $# -gt 0 ]; do
	case "$1" in
	--src)
		SRC="${2:-}"
		shift 2
		;;
	--dst)
		DST="${2:-}"
		shift 2
		;;
	--hostile)
		HOSTILE_SET="${2:-}"
		shift 2
		;;
	--whitelist)
		WHITELIST_SET="${2:-}"
		shift 2
		;;
	--count)
		COUNT="${2:-}"
		shift 2
		;;
	-h | --help)
		usage 0
		;;
	*)
		die "unknown argument: $1 (try --help)"
		;;
	esac
done

# ── Preflight ───────────────────────────────────────────────────────────────
command -v iptables >/dev/null 2>&1 || die "iptables not found"
command -v ipset >/dev/null 2>&1 || die "ipset not found"
command -v "$PING" >/dev/null 2>&1 || die "ping not found"
ipset list "$HOSTILE_SET" >/dev/null 2>&1 || die "ipset '$HOSTILE_SET' does not exist"
ipset list "$WHITELIST_SET" >/dev/null 2>&1 || die "ipset '$WHITELIST_SET' does not exist"

in_set() {
	# in_set <set> <ip> -> 0 when the address is in the set
	ipset test "$1" "$2" 2>&1 | grep -q "is in set"
}

# The chain has to be attached, or phase 1 passes for the wrong reason.
JUMPS=$(iptables -t raw -S PREROUTING 2>/dev/null | grep -c "$CHAIN" || true)
if [ "$JUMPS" -eq 0 ]; then
	die "the $CHAIN chain is not attached to raw:PREROUTING (enforcement is off).
       Turn it on first:  threat-engine enforce on"
fi

# ── Structure ───────────────────────────────────────────────────────────────
printf '\nStructure\n'

if [ "$JUMPS" -eq 1 ]; then
	ok "exactly one raw:PREROUTING jump into $CHAIN"
else
	bad "$JUMPS raw:PREROUTING jumps into $CHAIN — a duplicate jump makes the chain run twice"
fi

BODY=$(iptables -t raw -S "$CHAIN" 2>/dev/null || true)
RET_LINE=$(printf '%s\n' "$BODY" | grep -n -- "-j RETURN" | head -1 | cut -d: -f1 || true)
DROP_LINE=$(printf '%s\n' "$BODY" | grep -n -- "-j DROP" | head -1 | cut -d: -f1 || true)

if [ -z "$RET_LINE" ] || [ -z "$DROP_LINE" ]; then
	bad "the chain body is missing the whitelist RETURN or the hostile DROP"
	printf '%s\n' "$BODY" | sed 's/^/        /'
elif [ "$RET_LINE" -lt "$DROP_LINE" ]; then
	ok "the whitelist RETURN comes before the hostile DROP"
else
	bad "the hostile DROP comes before the whitelist RETURN — the whitelist would not win"
fi

# ── Addresses ───────────────────────────────────────────────────────────────
if [ -z "$SRC" ]; then
	for candidate in $CANDIDATES; do
		if in_set "$HOSTILE_SET" "$candidate" || in_set "$WHITELIST_SET" "$candidate"; then
			continue
		fi
		SRC="$candidate"
		break
	done
	[ -n "$SRC" ] || die "every candidate source address is already listed in a set; pass --src"
fi

if [ -z "$DST" ]; then
	DST=$(ip -4 addr show scope global 2>/dev/null |
		awk '/inet /{split($2,a,"/"); print a[1]; exit}')
	[ -n "$DST" ] || die "could not determine the node's own address; pass --dst"
fi

# The destination must not be hostile: otherwise the *reply* is dropped too and
# a whitelisted request still looks like a loss.
if in_set "$HOSTILE_SET" "$DST"; then
	die "the destination $DST is in the hostile set, so its reply would be dropped as well.
       Pass --dst with an address that ipset reports as NOT in '$HOSTILE_SET'."
fi

info "source $SRC   destination $DST"

# ── Setup ───────────────────────────────────────────────────────────────────
CLEANED=0

cleanup() {
	[ "$CLEANED" -eq 0 ] || return 0
	CLEANED=1
	ipset del "$WHITELIST_SET" "$SRC" >/dev/null 2>&1 || true
	ipset del "$HOSTILE_SET" "$SRC" >/dev/null 2>&1 || true
	ip addr del "$SRC"/32 dev lo >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

ip addr add "$SRC"/32 dev lo >/dev/null 2>&1 || true
ipset add "$HOSTILE_SET" "$SRC" >/dev/null 2>&1 || true

# ── Phase 1: blocked ────────────────────────────────────────────────────────
printf '\nPhase 1 — the source is hostile\n'

ipset del "$WHITELIST_SET" "$SRC" >/dev/null 2>&1 || true
ipset add "$HOSTILE_SET" "$SRC" >/dev/null 2>&1 || true
iptables -t raw -Z "$CHAIN" >/dev/null 2>&1 || true

if "$PING" -c "$COUNT" -W 1 -I "$SRC" "$DST" >/dev/null 2>&1; then
	bad "the packet got a reply — a hostile source is not being dropped"
else
	ok "no reply: the hostile source is dropped"
fi

# The -L output lists the target in the third column ("DROP"), not "-j DROP".
DROPPED=$(iptables -t raw -L "$CHAIN" -v -n -x 2>/dev/null |
	awk '$3 == "DROP" {print $1; exit}')
if [ "${DROPPED:-0}" -gt 0 ]; then
	ok "the DROP rule counted $DROPPED packet(s)"
else
	bad "the DROP rule counted nothing"
fi

# ── Phase 2: whitelisted ────────────────────────────────────────────────────
printf '\nPhase 2 — the same source, whitelisted\n'

ipset add "$WHITELIST_SET" "$SRC" >/dev/null 2>&1 || true
ipset add "$HOSTILE_SET" "$SRC" >/dev/null 2>&1 || true
iptables -t raw -Z "$CHAIN" >/dev/null 2>&1 || true

if "$PING" -c "$COUNT" -W 1 -I "$SRC" "$DST" >/dev/null 2>&1; then
	ok "the packet got a reply — the whitelist RETURN wins over the hostile DROP"
else
	bad "no reply — the whitelist did not override the hostile entry"
fi

RETURNED=$(iptables -t raw -L "$CHAIN" -v -n -x 2>/dev/null |
	awk '$3 == "RETURN" {print $1; exit}')
if [ "${RETURNED:-0}" -gt 0 ]; then
	ok "the RETURN rule counted $RETURNED packet(s)"
else
	bad "the RETURN rule counted nothing"
fi

cleanup

# ── Summary ─────────────────────────────────────────────────────────────────
printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
