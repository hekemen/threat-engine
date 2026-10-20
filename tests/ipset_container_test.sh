#!/usr/bin/env bash
#
# Validate the generated `ipset restore` script against a REAL kernel ipset,
# inside a privileged container.
#
# Why this exists: the unit tests assert the script's text, but only a real
# ipset can tell us whether the kernel accepts it. A hash:net set with no
# family defaults to IPv4, and adding an IPv6 member aborts the whole
# transaction with "128 is out of range 0-32" -- a failure the text assertions
# happily pass. This harness catches exactly that class of bug.
#
# Usage:
#   tests/ipset_container_test.sh
#
# Requires: docker, and permission to run a --privileged container (the ipset
# netlink interface is not namespaced, so CAP_NET_ADMIN alone is not enough on
# all hosts; --privileged is used for portability).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${IPSET_TEST_IMAGE:-alpine:3.21}"
GENERATOR_DIR="$REPO_ROOT/tests/ipsetgen"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

echo "==> Generating the restore script from the real Manager.Sync"
SCRIPT_FILE="$WORKDIR/restore.script"
(cd "$GENERATOR_DIR" && go run .) > "$SCRIPT_FILE"

echo "==> Generated script:"
sed 's/^/    /' "$SCRIPT_FILE"

echo
echo "==> Applying it with a real ipset in a privileged container"
docker run --rm --privileged -v "$WORKDIR:/work:ro" "$IMAGE" sh -eu -c '
  apk add --no-cache ipset >/dev/null

  echo "--- ipset version ---"
  ipset --version

  echo "--- applying restore script ---"
  ipset restore < /work/restore.script
  echo "restore exit=$? (0 = kernel accepted the whole transaction)"

  echo "--- hostile set must exist and be IPv4-only ---"
  ipset list k3s_hostile_ips | sed -n "1,12p"

  echo "--- membership checks ---"
  ipset test k3s_hostile_ips 1.2.3.4   && echo "  1.2.3.4       blocked (expected)"
  ipset test k3s_hostile_ips 5.6.7.9   && echo "  5.6.7.9       in 5.6.7.0/24 (expected)"
  if ipset test k3s_hostile_ips 9.9.9.9 2>/dev/null; then
    echo "  9.9.9.9       UNEXPECTEDLY blocked"; exit 1
  else
    echo "  9.9.9.9       not blocked (expected)"
  fi

  echo "--- whitelist set ---"
  ipset test k3s_whitelist_ips 10.1.2.3 && echo "  10.1.2.3      whitelisted (expected)"

  echo "--- no IPv6 may have leaked into either set ---"
  for s in k3s_hostile_ips k3s_whitelist_ips; do
    # Only the MEMBERS matter. The header lines legitimately contain colons
    # ("Type: hash:net", "Header: family inet ..."), so grep the members
    # section that follows "Members:".
    members=$(ipset list "$s" | sed -n "/^Members:/,\$p" | tail -n +2)
    if printf "%s\n" "$members" | grep -qE ":"; then
      echo "  FAIL: IPv6 member found in $s:"; printf "    %s\n" "$members"; exit 1
    fi
    count=$(printf "%s\n" "$members" | grep -c . || true)
    echo "  $s is IPv4-only ($count member(s))"
  done

  echo
  echo "ALL CONTAINER CHECKS PASSED"
'

echo
echo "==> Verifying the harness actually catches the original bug"
docker run --rm --privileged "$IMAGE" sh -eu -c '
  apk add --no-cache ipset >/dev/null
  # The pre-fix shape: hash:net with no family, plus an IPv6 whitelist member.
  if printf "create bug hash:net maxelem 50000 -exist\nflush bug\nadd bug ::1/128 -exist\n" | ipset restore 2>/dev/null; then
    echo "  FAIL: expected the unfixed form to be rejected"; exit 1
  fi
  echo "  Confirmed: hash:net without a family rejects ::1/128"
'
