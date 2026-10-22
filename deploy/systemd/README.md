# Running threat-engine as a systemd service

For a single host (or any node you manage directly) the daemon can run under
systemd instead of Kubernetes. It needs root-equivalent network administration
to create `ipset` tables and edit `iptables` rules, so the unit uses
capabilities rather than running an unrestricted privileged process.

## Prerequisites

Load the netfilter set modules on the host:

```bash
sudo modprobe ip_set ip_set_hash_net xt_set
```

To make that survive a reboot, add them to `/etc/modules-load.d/`:

```bash
printf 'ip_set\nip_set_hash_net\nxt_set\n' | sudo tee /etc/modules-load.d/threat-engine.conf
```

## Install

1. Build or install the binary. See
   [docs/operations.md](../../docs/operations.md) for the `go install` route and
   the local-build fallback. The unit expects it at
   `/usr/local/bin/threat-engine`; if you put it elsewhere, edit `ExecStart`.

   ```bash
   CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o threat-engine ./cmd
   sudo install -m 0755 threat-engine /usr/local/bin/threat-engine
   ```

2. Install the unit and environment file:

   ```bash
   sudo install -m 0644 deploy/systemd/threat-engine.service /etc/systemd/system/threat-engine.service
   sudo install -d -m 0755 /etc/threat-engine
   sudo install -m 0644 deploy/systemd/threat-engine.env.example /etc/threat-engine/threat-engine.env
   ```

3. Edit `/etc/threat-engine/threat-engine.env`. Enforcement is `false` by
   default, so the service starts safely without filtering anything.

4. Start it:

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now threat-engine
   ```

## Verify

```bash
systemctl status threat-engine
journalctl -u threat-engine -n 50 --no-pager
```

The startup log states the enforcement mode explicitly, e.g.
`Enforcement: DISABLED (dry-run; ipsets populated, no kernel rules)`.

Check the listeners and the blocklist:

```bash
curl -s http://127.0.0.1:9090/healthz
curl -s http://127.0.0.1:9090/metrics | grep threat_engine_
curl -s 'http://127.0.0.1:9090/check?ip=1.2.3.4'
```

Inspect the kernel state:

```bash
sudo ipset list threat_engine_hostile_ips -terse
sudo iptables -t raw -L THREAD_ENGINE_FILTER -v -n
```

The chain only exists while enforcement is on.

## Toggle enforcement

The admin listener binds `127.0.0.1:9091` only, so the toggle is not reachable
from off-host. From the host itself:

```bash
curl -s 'http://127.0.0.1:9091/enforcement'                        # read state
curl -s -X POST 'http://127.0.0.1:9091/enforcement?enabled=true'   # attach rules
curl -s -X POST 'http://127.0.0.1:9091/enforcement?enabled=false'  # detach rules
```

Changes apply immediately; no restart is needed. To change the startup default
instead, set `ENFORCEMENT_ENABLED=true` in the env file and
`systemctl restart threat-engine`.

## Uninstall

```bash
sudo systemctl disable --now threat-engine
sudo rm /etc/systemd/system/threat-engine.service
sudo rm -rf /etc/threat-engine
sudo systemctl daemon-reload
```

Removing the service does **not** clean up the kernel state. If enforcement was
on, remove the rules and tables:

```bash
sudo iptables -t raw -D PREROUTING -j THREAD_ENGINE_FILTER
sudo iptables -t raw -F THREAD_ENGINE_FILTER
sudo iptables -t raw -X THREAD_ENGINE_FILTER
sudo ipset destroy threat_engine_hostile_ips
sudo ipset destroy threat_engine_whitelist_ips
```
