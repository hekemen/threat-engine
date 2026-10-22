# threat-engine

Autonomous threat-intelligence daemon. It polls multi-source IP blocklists,
detects changes with SHA-256 fingerprinting, and drops hostile traffic in the
Linux kernel through `ipset` and `iptables` `raw:PREROUTING`.

Standard host firewalls write to `filter: INPUT`, but Docker and K3s rewrite
destinations in `nat: PREROUTING` and forward pod traffic through
`filter: FORWARD` — the deny rule never sees the packet. `raw: PREROUTING` is
evaluated before connection tracking and before container NAT, so there is no
path around it.

## Enforcement is off by default

Populating the blocklist and dropping packets are separate switches. Out of the
box both `ipset` tables are created and filled, so `/check` and `/metrics`
report real data, and **no `iptables` chain exists at all** — not an empty one,
none.

```bash
ENFORCEMENT_ENABLED=true threat-engine          # at startup
threat-engine enforce on | off | status         # at runtime, over the unix socket
curl -s -X POST 'http://127.0.0.1:9091/enforcement?enabled=true'   # loopback only
```

`enforce` is also installed as an alias in the image, so
`docker exec threat-engine enforce off` reads as one word. If
`ENFORCEMENT_ENABLED` is present in the environment the flag is locked and
runtime toggles are refused with `403`, which lets a ConfigMap own it.

## Quick start

Docker:

```bash
docker build -t threat-engine:local .
docker run -d --name threat-engine --restart unless-stopped \
  --net=host --cap-add=NET_ADMIN --cap-add=NET_RAW \
  -v /var/run/threat-engine:/var/run/threat-engine \
  threat-engine:local
```

Kubernetes:

```bash
helm install threat-engine ./deploy/helm/threat-engine
deploy/helm/threat-engine/verify.sh --toggle
```

Requirements: Linux, host networking (`--net=host` / `hostNetwork: true`), the
`CAP_NET_ADMIN` and `CAP_NET_RAW` capabilities, and
`modprobe ip_set ip_set_hash_net xt_set`. **One daemon per host** — every
deployment path edits the same kernel tables, chain, and ports `9090`/`9091`.
The daemon verifies all of this at startup and exits non-zero rather than
running while filtering nothing.

## Configuration

| Variable | Default | Description |
| :--- | :--- | :--- |
| `ENFORCEMENT_ENABLED` | `false` | Attach the drop rules. Anything unparseable falls back to `false`. |
| `INTERVAL_MINUTES` | `5` | Feed polling frequency. |
| `COUNTER_INTERVAL_SECONDS` | `10` | How often the kernel drop counters are sampled. |
| `HTTP_PORT` | `9090` | Read-only listener. |
| `ADMIN_PORT` | `9091` | Loopback-only toggle listener. |
| `ADMIN_SOCKET` | `/var/run/threat-engine/admin.sock` | Same handler as the admin port. |
| `WHITELIST` | `""` | Extra IPs/CIDRs to never block, comma-separated. |
| `CONFIDENCE_THRESHOLD` | `3` | Minimum score for confidence-weighted feeds (IPsum). |

RFC 1918, link-local, and loopback ranges are always excluded and can never
reach the hostile set. Enforcement is IPv4-only by design.

## Endpoints

| Port | Endpoint | Purpose |
| :--- | :--- | :--- |
| `9090` | `GET /healthz` | `200` once the first sync cycle completes, `503` during boot. |
| `9090` | `GET /check?ip=<IP>` | Live kernel membership test: `blocked`, `whitelisted`, or `allowed`. |
| `9090` | `GET /metrics` | Prometheus exposition. |
| `9091` | `GET /enforcement` | Current state (also on the unix socket). |
| `9091` | `POST /enforcement?enabled=…` | Apply immediately. `403` when locked, `500` if the kernel call fails. |

The public listener is read-only; `/enforcement` returns `404` on it.

## Verify it works

```bash
curl -s http://127.0.0.1:9090/metrics | grep threat_engine_enforcement_enabled
sudo ipset list threat_engine_hostile_ips -terse
sudo iptables -t raw -S | grep THREAD_ENGINE_FILTER   # empty while enforcement is off

sudo ./tests/iptables-e2e.sh                          # real packets: hostile dropped, whitelisted allowed
```

A graceful stop removes the chain, its jump, and both sets, restoring the host.
After a `SIGKILL` or power loss the rules survive; the teardown commands are in
[docs/operations.md](docs/operations.md).

## Security model

- **Failure to enable is fail-safe.** Unset, empty, or misspelled
  `ENFORCEMENT_ENABLED` means "do not filter", never "filter".
- **The toggle is protected by reachability only.** It binds loopback and has
  no token, so any process on the node can disable enforcement. Use the unix
  socket's filesystem permissions, or lock the flag to the environment.
- **Updates are atomic.** A `<set>_tmp` buffer is populated and swapped in, so
  the blocklist is never empty and the kernel never locks.

## Development

```bash
gofmt -l .        # must print nothing
go vet ./...
go test ./...     # every package, no root required
go test -race ./...
go build -o threat-engine ./cmd
```

`os/exec` is confined to `internal/runner`; every other package takes an
injectable runner, so the pipeline is testable without root or kernel access.

## Documentation

- [docs/operations.md](docs/operations.md) — full operator guide: deployment
  paths, the enforcement model, metrics reference, startup validation,
  troubleshooting, upgrades from pre-rename builds.
- [deploy/helm/threat-engine/README.md](deploy/helm/threat-engine/README.md) —
  chart values, the ConfigMap lock, `verify.sh`.
- [deploy/systemd/README.md](deploy/systemd/README.md) — hardened unit.
- [AGENTS.md](AGENTS.md) — invariants an agent must not break.
