# thread-engine

An autonomous threat-intelligence daemon that polls multi-source IP blocklists,
detects changes with SHA-256 fingerprinting, and enforces sub-millisecond packet
drops in the Linux kernel via `ipset` and `iptables` `raw` PREROUTING.

It exists because standard host firewalls miss container traffic. UFW and
friends write to `filter: INPUT`, but K3s and Docker rewrite destinations in
`nat: PREROUTING` and forward to pods through `filter: FORWARD`, so a
`filter: INPUT` deny rule never sees the packet. This daemon injects rules into
`raw: PREROUTING`, which is evaluated **before** connection tracking and before
container NAT translation, so there is no path around it.

## Enforcement is off by default

**Installing this daemon does not drop any traffic.** The default is a
dry-run-style mode:

- The `ipset` tables are created and populated exactly as normal, so the
  blocklist metrics, `/check`, and `/metrics` all report real data.
- **No `iptables` chain exists and `raw:PREROUTING` is never touched.** Not a
  zero-length chain, not an empty jump — nothing at all.

That makes it safe to deploy, observe against production traffic, and only then
switch on. Enforcement is enabled two ways:

1. **At startup**, with `ENFORCEMENT_ENABLED=true`.
2. **At runtime**, by POSTing to a loopback-only admin endpoint:

   ```bash
   curl -s 'http://127.0.0.1:9091/enforcement'                       # read state
   curl -s -X POST 'http://127.0.0.1:9091/enforcement?enabled=true'  # attach rules
   curl -s -X POST 'http://127.0.0.1:9091/enforcement?enabled=false' # detach rules
   ```

   The toggle attaches or detaches the chain synchronously — no restart, no wait
   for the next scan.

The admin listener binds `127.0.0.1` only. It is reachable from the host (or
from inside the container/pod with `kubectl exec` / `kubectl port-forward`), and
never from another machine or another pod. **Note that this also means any
process on the node can toggle enforcement**; see [Security model](#security-model).

The enforcement state is reconciled declaratively on **every** scan. If someone
turns enforcement off, it stays off — a later scan cannot silently re-enable it,
and a manual `iptables -F` while enabled is repaired on the next tick.

### Verifying enforcement

```bash
# 1 when the drop rules are attached, 0 when they are inert
curl -s http://127.0.0.1:9090/metrics | grep threat_engine_enforcement_enabled

# Live membership test against the kernel table
curl -s 'http://127.0.0.1:9090/check?ip=92.118.39.229'
# → {"ip":"...","is_blocked":true,"is_whitelisted":false,"status":"blocked",
#    "enforcement_enabled":true,"timestamp":"..."}

# Blocklist size, regardless of enforcement mode
sudo ipset list k3s_hostile_ips -terse

# The chain and jump exist ONLY while enforcement is on
sudo iptables -t raw -S | grep K3S_THREAT_FILTER
sudo iptables -t raw -L K3S_THREAT_FILTER -v -n   # whitelist RETURN before hostile DROP
```

## Deployment

Every path below needs the same three things: a Linux host, host networking, and
the `CAP_NET_ADMIN` + `CAP_NET_RAW` capabilities. The netfilter set kernel
modules must also be loaded:

```bash
sudo modprobe ip_set ip_set_hash_net xt_set
```

### 1. Direct binary

```bash
go install github.com/hekemen/thread-engine/cmd@latest
```

> **Caveat:** `go install` requires the module to be published and fetchable at
> that path. If `github.com/hekemen/thread-engine` is not yet available publicly
> (or the requested version is not tagged), this command fails with a
> "module ... not found" error. This is the expected failure, not a broken
> command.

**The always-works fallback** — clone and build:

```bash
git clone https://github.com/hekemen/thread-engine.git
cd thread-engine
CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o threat-engine ./cmd
sudo install -m 0755 threat-engine /usr/local/bin/threat-engine
```

Then run it (needs root for `ipset`/`iptables`):

```bash
sudo /usr/local/bin/threat-engine
```

### 2. Docker / Compose

The image is a static Go binary on Alpine.

```bash
docker build -t k3s-threat-engine:local .

docker run -d \
  --name k3s-threat-engine \
  --restart unless-stopped \
  --net=host \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  -e INTERVAL_MINUTES=5 \
  -e ENFORCEMENT_ENABLED=false \
  -e WHITELIST="203.0.113.10" \
  k3s-threat-engine:local
```

Or with the included [`docker-compose.yaml`](docker-compose.yaml):

```bash
docker compose up -d
```

`--net=host` is required: the daemon must edit the **host's** netfilter tables,
not a container-local namespace.

### 3. Kubernetes / Helm

See [`deploy/helm/thread-engine`](deploy/helm/thread-engine) for the DaemonSet
chart (`enforcement.enabled` defaults to `false`):

```bash
helm install thread-engine ./deploy/helm/thread-engine
helm install thread-engine ./deploy/helm/thread-engine --set enforcement.enabled=true
```

The chart sets `hostNetwork: true`, `dnsPolicy: ClusterFirstWithHostNet`, and the
two capabilities. See its [README](deploy/helm/thread-engine/README.md) for the
full value list and the runtime toggle instructions.

### 4. systemd

See [`deploy/systemd`](deploy/systemd) for a hardened unit and environment file:

```bash
sudo install -m 0644 deploy/systemd/thread-engine.service /etc/systemd/system/
sudo install -d /etc/thread-engine
sudo install -m 0644 deploy/systemd/thread-engine.env.example /etc/thread-engine/thread-engine.env
sudo systemctl daemon-reload && sudo systemctl enable --now thread-engine
```

The unit deliberately omits `ProtectKernelModules`, which would block the
required `xt_set` load. See its [README](deploy/systemd/README.md).

## Configuration

All settings are environment variables.

| Variable | Default | Description |
| :--- | :--- | :--- |
| `ENFORCEMENT_ENABLED` | `false` | Attach the hostile DROP rules to `raw:PREROUTING`. Accepts `true/1/yes` and `false/0/no`; **anything unparseable falls back to `false`**, so a typo cannot enable enforcement. |
| `INTERVAL_MINUTES` | `5` | Feed polling frequency. |
| `HTTP_PORT` | `9090` | Read-only listener for `/healthz`, `/check`, `/metrics`. |
| `ADMIN_PORT` | `9091` | Loopback-only (`127.0.0.1`) toggle listener. |
| `HOSTILE_SET_NAME` | `k3s_hostile_ips` | Kernel `ipset` name for blocked IPs/CIDRs. |
| `WHITELIST_SET_NAME` | `k3s_whitelist_ips` | Kernel `ipset` name for allowed IPs/CIDRs. |
| `WHITELIST` | `""` | Comma-separated extra IPs/CIDRs to never block, e.g. `203.0.113.10,198.51.100.0/24`. |
| `CONFIDENCE_THRESHOLD` | `3` | Minimum score for confidence-weighted feeds such as IPsum. |

RFC 1918 private ranges, link-local, and loopback addresses are always excluded
and can never reach the hostile set.

### IPv4 only

Enforcement is **IPv4-only**. The `ipset` tables are created with
`family inet`, the `iptables` rules live in the `raw` table (not `ip6tables`),
and IPv6 targets from the feeds are filtered out during aggregation with a
logged count (`Ignored N IPv6 target(s)`). This is deliberate, not an
oversight: a `hash:net` set with no family defaults to IPv4, and adding an
IPv6 member aborts the entire `ipset restore` transaction, so a single IPv6
feed entry would otherwise leave the blocklist empty. Adding IPv6 enforcement
means a parallel `family inet6` set plus an `ip6tables` chain.

### Threat feeds

Fingerprint (SHA-256) over the deduplicated, sorted, whitelist-filtered set.
When the fingerprint is unchanged, no disk or kernel write happens.

| Adapter | Source |
| :--- | :--- |
| IPsum | confidence-scored aggregate, filtered by `CONFIDENCE_THRESHOLD` |
| Spamhaus DROP | CIDR-delimited |
| FireHOL Level 1 | netset |
| blocklist.de | all |
| Feodo Tracker | abuse.ch blocklist |

## HTTP endpoints

### Public listener (`HTTP_PORT`, default 9090)

Read-only. The admin path deliberately does **not** exist here (it returns 404).

| Endpoint | Description |
| :--- | :--- |
| `GET /healthz` | `200 OK` once the first sync cycle completes; `503` during boot. |
| `GET /check?ip=<IP>` | Live `ipset` membership test. Returns `is_blocked`, `is_whitelisted`, `status`, `enforcement_enabled`, `timestamp`. Status precedence: `whitelisted` > `blocked` > `allowed`. |
| `GET /metrics` | Prometheus exposition format. |

### Admin listener (`ADMIN_PORT`, default 9091, `127.0.0.1` only)

| Endpoint | Description |
| :--- | :--- |
| `GET /enforcement` | Current enforcement state as JSON. |
| `POST /enforcement?enabled=true\|false` | Apply immediately and return the new state. `400` on an unparseable value, `405` on other methods, `500` if the kernel call fails. |

## Metrics

| Metric | Type | Description |
| :--- | :--- | :--- |
| `threat_engine_blocked_targets_total` | gauge | Active IPs/subnets in the drop set. |
| `threat_engine_whitelist_entries_total` | gauge | Subnets in the whitelist. |
| `threat_engine_enforcement_enabled` | gauge | `1` when the DROP rules are attached, `0` when inert. |
| `threat_engine_scans_total{status="success\|failure"}` | counter | Scan executions. |
| `threat_engine_updates_applied_total` | counter | Times a change triggered a kernel swap. |
| `threat_engine_last_scan_timestamp` | gauge | Unix timestamp of the latest scan. |
| `threat_engine_last_change_timestamp` | gauge | Unix timestamp of the latest kernel update. |

`threat_engine_enforcement_enabled` reports the **desired** state. A toggle that
fails to reach the kernel returns HTTP 500 and the metric still reflects the
requested state until the next scan retries — treat a 500 as a failure and
re-read the metric after the following scan interval.

## Security model

- **Failure to enable is fail-safe.** An unset, empty, or misspelled
  `ENFORCEMENT_ENABLED` means "do not filter", never "filter".
- **The admin toggle is protected by network reachability only** — it binds to
  loopback. There is no bearer token. Any process on the node (or anything that
  can reach the pod's network namespace) can disable the firewall. If that is
  not an acceptable trust boundary for your host, front it with a token or an
  authorization proxy, or leave `ENFORCEMENT_ENABLED` controlled solely by the
  startup environment variable and treat the runtime toggle as a break-glass
  tool.
- **Whitelist filtering is never optional.** Private and link-local ranges are
  excluded during parsing and enforced with an explicit `RETURN` rule at the top
  of the chain. Nothing may put RFC 1918 space into the hostile set — that would
  break pod-to-pod traffic, cluster DNS, and node heartbeats.
- **Updates are atomic.** The daemon populates a `<set>_tmp` buffer and calls
  `ipset swap`; it never flushes a live set, so there is no window where the
  blocklist is empty or the kernel locks.

## Troubleshooting

**Rules missing / traffic not dropped.** Check the enforcement flag first:

```bash
curl -s http://127.0.0.1:9090/metrics | grep threat_engine_enforcement_enabled
curl -s http://127.0.0.1:9091/enforcement
```

If it reads `0`, enforcement is off and that is the designed default. Turn it on
with `ENFORCEMENT_ENABLED=true` or the POST above.

**`iptables: Could not fetch rule set generation id: Permission denied`** (in the
log, or a 500 from the toggle). The process lacks `CAP_NET_ADMIN`/root, or is
running without host networking. Verify with `capsh --print` inside the
container, or check the `--cap-add` flags / Helm securityContext.

**`exec: "ipset": executable file not found in $PATH`.** The `ipset` userland
tool is not installed in the image/container. Install the `ipset` package, or
use the published image which includes it.

**Rules never appear even with `ENFORCEMENT_ENABLED=true`.** The kernel modules
are missing:

```bash
sudo modprobe ip_set ip_set_hash_net xt_set
ipset --version   # ensure the userland tool is present too
```

**Blocklist stays at 0.** The feed poll failed — check the log for adapter
errors and confirm the host can reach the feed URLs. `/healthz` returns 503
until the first cycle completes.

## Development

```bash
gofmt -l .                    # must print nothing
go vet ./...
go test ./...                 # all packages, no root required
go test -race ./...           # concurrency check for engine + metrics
go build -o threat-engine ./cmd
```

`os/exec` is confined to `internal/runner`; every other package takes an
injectable runner so the pipeline is testable without root or kernel access.

### Validating ipset commands in a container

The unit tests assert the *text* of the generated restore script. Only a real
`ipset` can confirm the kernel accepts it, so there is a harness that applies
the real script inside a privileged container:

```bash
tests/ipset_container_test.sh
```

It generates the script from the actual `Manager.Sync`, applies it with a real
`ipset`, checks the set's family and membership, and then deliberately
reproduces the pre-fix form to prove the harness can still detect the bug. Run
it after any change to `internal/ipset` or `internal/config`'s whitelist.

## License

See the repository for license information.
