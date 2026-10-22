#!/usr/bin/env bash
# verify.sh — check that a threat-engine DaemonSet deployment is healthy.
#
# Usage:
#   deploy/helm/threat-engine/verify.sh [-n <namespace>] [-r <release>] [--toggle]
#
#   -n, --namespace   namespace of the release      (default: threat-engine)
#   -r, --release     release name                  (default: threat-engine)
#       --toggle      also exercise the enforcement on/off path. This really
#                     attaches and detaches the rules in the node's raw table,
#                     so packets from hostile IPs are dropped while it is on.
#                     Off by default because the checks are read-only.
#
# The script inspects the node's kernel state through the pod (which shares the
# node's network namespace and holds NET_ADMIN), so it needs no root on the
# node — only permission to exec into the pod.
#
# Exit status: 0 when every check passed, 1 otherwise.

set -uo pipefail

NS=threat-engine
RELEASE=threat-engine
TOGGLE=0

while [ $# -gt 0 ]; do
	case "$1" in
	-n | --namespace)
		NS="${2:-}"
		shift 2
		;;
	-r | --release)
		RELEASE="${2:-}"
		shift 2
		;;
	--toggle)
		TOGGLE=1
		shift
		;;
	-h | --help)
		sed -n '2,20p' "$0"
		exit 0
		;;
	*)
		echo "unknown argument: $1" >&2
		exit 2
		;;
	esac
done

PASS=0
FAIL=0

ok() {
	PASS=$((PASS + 1))
	printf '  \033[32mPASS\033[0m  %s\n' "$1"
}

bad() {
	FAIL=$((FAIL + 1))
	printf '  \033[31mFAIL\033[0m  %s\n' "$1"
}

check() {
	# check <description> <expected> <actual>
	if [ "$2" = "$3" ]; then
		ok "$1 ($3)"
	else
		bad "$1 — expected $2, got $3"
	fi
}

section() {
	printf '\n\033[1m%s\033[0m\n' "$1"
}

if ! command -v kubectl >/dev/null 2>&1; then
	echo "kubectl not found" >&2
	exit 2
fi

# ── Workload ────────────────────────────────────────────────────────────────
section "Workload"

DS=$(kubectl get daemonset -n "$NS" -l "app.kubernetes.io/instance=$RELEASE" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [ -z "$DS" ]; then
	bad "no DaemonSet for release '$RELEASE' in namespace '$NS'"
	echo
	echo "Nothing to verify."
	exit 1
fi
ok "DaemonSet '$DS'"

DESIRED=$(kubectl get daemonset "$DS" -n "$NS" -o jsonpath='{.status.desiredNumberScheduled}')
READY=$(kubectl get daemonset "$DS" -n "$NS" -o jsonpath='{.status.numberReady}')
check "pods ready" "$DESIRED" "$READY"

POD=$(kubectl get pods -n "$NS" -l "app.kubernetes.io/instance=$RELEASE" -o jsonpath='{.items[0].metadata.name}')
RESTARTS=$(kubectl get pod "$POD" -n "$NS" -o jsonpath='{.status.containerStatuses[0].restartCount}')
check "restarts" "0" "$RESTARTS"

# ── Startup validation ──────────────────────────────────────────────────────
section "Startup validation"

LOGS=$(kubectl logs -n "$NS" "$POD" 2>&1)
for probe in "host network namespace confirmed" "ipset reachable" "iptables raw table accessible"; do
	if printf '%s' "$LOGS" | grep -q "$probe"; then
		ok "$probe"
	else
		bad "$probe — not in the pod log"
	fi
done

# ── Kernel state ───────────────────────────────────────────────────────────
section "Kernel state"

HOSTILE=$(kubectl get daemonset "$DS" -n "$NS" -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="HOSTILE_SET_NAME")].value}')
WHITELIST=$(kubectl get daemonset "$DS" -n "$NS" -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="WHITELIST_SET_NAME")].value}')
HOSTILE=${HOSTILE:-threat_engine_hostile_ips}
WHITELIST=${WHITELIST:-threat_engine_whitelist_ips}

HOSTILE_ENTRIES=$(kubectl exec -n "$NS" "$POD" -- ipset list "$HOSTILE" 2>/dev/null | awk '/Number of entries/ {print $NF}')
if [ -n "${HOSTILE_ENTRIES:-}" ] && [ "$HOSTILE_ENTRIES" -gt 0 ] 2>/dev/null; then
	ok "hostile set '$HOSTILE' is populated ($HOSTILE_ENTRIES entries)"
else
	bad "hostile set '$HOSTILE' is empty or missing"
fi

WHITELIST_ENTRIES=$(kubectl exec -n "$NS" "$POD" -- ipset list "$WHITELIST" 2>/dev/null | awk '/Number of entries/ {print $NF}')
if [ -n "${WHITELIST_ENTRIES:-}" ] && [ "$WHITELIST_ENTRIES" -gt 0 ] 2>/dev/null; then
	ok "whitelist set '$WHITELIST' is populated ($WHITELIST_ENTRIES entries)"
else
	bad "whitelist set '$WHITELIST' is empty or missing"
fi

CHAIN_REFS=$(kubectl exec -n "$NS" "$POD" -- iptables -t raw -S 2>/dev/null | grep -c THREAD_ENGINE_FILTER)
JUMPS=$(kubectl exec -n "$NS" "$POD" -- iptables -t raw -S PREROUTING 2>/dev/null | grep -c THREAD_ENGINE_FILTER)

ENABLED=$(kubectl exec -n "$NS" "$POD" -- wget -qO- http://127.0.0.1:9090/metrics 2>/dev/null | awk '/^threat_engine_enforcement_enabled/ {print $2}')

if [ "$ENABLED" = "0" ]; then
	check "no chain while enforcement is off" "0" "$CHAIN_REFS"
	check "no jump while enforcement is off" "0" "$JUMPS"
else
	check "chain present while enforcement is on" "4" "$CHAIN_REFS"
	check "exactly one jump while enforcement is on" "1" "$JUMPS"
fi

# ── HTTP surface ───────────────────────────────────────────────────────────
section "HTTP surface"

if kubectl exec -n "$NS" "$POD" -- wget -qO- http://127.0.0.1:9090/healthz 2>/dev/null | grep -q ok; then
	ok "/healthz reports ok"
else
	bad "/healthz did not report ok"
fi

METRICS=$(kubectl exec -n "$NS" "$POD" -- wget -qO- http://127.0.0.1:9090/metrics 2>/dev/null)
if printf '%s' "$METRICS" | grep -q '^threat_engine_enforcement_enabled'; then
	ok "/metrics exposes threat_engine_enforcement_enabled"
else
	bad "/metrics does not expose threat_engine_enforcement_enabled"
fi

if printf '%s' "$METRICS" | grep -q '^threat_engine_scans_total{status="success"}'; then
	ok "/metrics shows successful scans"
else
	bad "/metrics shows no successful scans"
fi

CHECK=$(kubectl exec -n "$NS" "$POD" -- wget -qO- "http://127.0.0.1:9090/check?ip=1.2.3.4" 2>/dev/null)
if printf '%s' "$CHECK" | grep -q '"status":'; then
	ok "/check answers with a status"
else
	bad "/check did not answer with a status"
fi

# The public listener is read-only: it must not serve the toggle.
if kubectl exec -n "$NS" "$POD" -- wget -qO- http://127.0.0.1:9090/enforcement >/dev/null 2>&1; then
	bad "the public listener served /enforcement — it must return 404"
else
	ok "the public listener refuses /enforcement (404)"
fi

# The admin listener binds 127.0.0.1, so it must not answer on the node's
# own address — that is what keeps it off every other pod and off-host.
NODE_IP=$(kubectl get pod "$POD" -n "$NS" -o jsonpath='{.status.hostIP}')
if kubectl exec -n "$NS" "$POD" -- wget -q -T 3 -O - "http://$NODE_IP:9091/enforcement" >/dev/null 2>&1; then
	bad "the admin listener answered on $NODE_IP:9091 — it must bind 127.0.0.1 only"
else
	ok "the admin listener is unreachable on $NODE_IP:9091 (loopback only)"
fi

# ── Enforcement toggle ─────────────────────────────────────────────────────
if [ "$TOGGLE" -eq 1 ]; then
	section "Enforcement toggle"

	kubectl exec -n "$NS" "$POD" -- enforce on >/dev/null 2>&1
	JUMPS=$(kubectl exec -n "$NS" "$POD" -- iptables -t raw -S PREROUTING 2>/dev/null | grep -c THREAD_ENGINE_FILTER)
	check "one jump after enforce on" "1" "$JUMPS"

	BODY=$(kubectl exec -n "$NS" "$POD" -- iptables -t raw -S THREAD_ENGINE_FILTER 2>/dev/null)
	if printf '%s' "$BODY" | grep -q 'threat_engine_whitelist_ips src -j RETURN' &&
	printf '%s' "$BODY" | grep -q 'threat_engine_hostile_ips src -j DROP'; then
		ok "the chain carries the whitelist RETURN and the hostile DROP"
	else
		bad "the chain body is wrong: $BODY"
	fi

	ENABLED=$(kubectl exec -n "$NS" "$POD" -- wget -qO- http://127.0.0.1:9090/metrics 2>/dev/null | awk '/^threat_engine_enforcement_enabled/ {print $2}')
	check "the metric follows the toggle" "1" "$ENABLED"

	kubectl exec -n "$NS" "$POD" -- enforce off >/dev/null 2>&1
	JUMPS=$(kubectl exec -n "$NS" "$POD" -- iptables -t raw -S PREROUTING 2>/dev/null | grep -c THREAD_ENGINE_FILTER)
	CHAIN_REFS=$(kubectl exec -n "$NS" "$POD" -- iptables -t raw -S 2>/dev/null | grep -c THREAD_ENGINE_FILTER)
	check "no jump after enforce off" "0" "$JUMPS"
	check "no chain after enforce off" "0" "$CHAIN_REFS"
fi

# ── Summary ─────────────────────────────────────────────────────────────────
printf '\n\033[1m%d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
