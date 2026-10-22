# threat-engine Helm chart

Deploys [threat-engine](../../../README.md) as a DaemonSet: one pod per node,
polling multi-source threat feeds, populating kernel `ipset` tables, and
optionally dropping hostile packets in `raw:PREROUTING`.

**Enforcement is off by default.** Installing this chart populates the blocklist
but attaches no iptables rules, so it cannot affect existing traffic.

## Requirements

- A Linux node kernel with `ip_set`, `ip_set_hash_net`, and `xt_set` loaded.
- The DaemonSet runs with `hostNetwork: true` and `CAP_NET_ADMIN`/`CAP_NET_RAW`.
- Pod Security Admission: the namespace must permit privileged host networking.
  In clusters enforcing the `restricted` profile, apply the `baseline` profile
  or an equivalent exemption to this namespace.
- **One daemon per node.** The chart uses host networking, so it shares the
  node's `ipset` tables, its `raw:PREROUTING` chain, and its ports `9090`/`9091`
  with anything else that manages this daemon — including a `docker compose up`
  of the same image on that node. The second daemon crash-loops with
  `listen tcp :9090: bind: address already in use`, and the two overwrite each
  other's ipset contents and fight over the same chain on every scan.

## Install

```bash
helm install threat-engine ./deploy/helm/threat-engine
```

Enforcement stays disabled. To enable it for every node from the start:

```bash
helm install threat-engine ./deploy/helm/threat-engine --set enforcement.enabled=true
```

### The image

The chart pulls `ghcr.io/hekemen/threat-engine:<appVersion>` by default, and
`image.tag` falls back to the chart's `appVersion`. Until that image is
published, point the chart at a registry you control:

```bash
helm install threat-engine ./deploy/helm/threat-engine \
  --set image.repository=localhost:5000/threat-engine \
  --set image.tag=0.1.0 \
  --set image.pullPolicy=Always
```

The node must be allowed to pull from that registry. For a plain-HTTP registry
such as `localhost:5000`, k3s needs it declared as insecure in
`/etc/rancher/k3s/registries.yaml` (note the file name k3s actually ships):

```yaml
configs:
  localhost:5000:
    insecure: true
```

`image.pullPolicy` defaults to `IfNotPresent`, so a tag that is re-pushed with
the same name is not re-pulled. Use `Always` while iterating on a tag.

## Key values

| Value | Default | Description |
| :--- | :--- | :--- |
| `enforcement.enabled` | `false` | Attach the hostile DROP rules to `raw:PREROUTING`. |
| `sets.hostileName` | `threat_engine_hostile_ips` | Kernel ipset name for blocked targets. |
| `sets.whitelistName` | `threat_engine_whitelist_ips` | Kernel ipset name for allowed targets. |
| `scan.intervalMinutes` | `5` | Feed polling frequency. |
| `scan.confidenceThreshold` | `3` | Minimum score for confidence-weighted feeds. |
| `whitelist` | `[]` | Extra IPs/CIDRs to never block. |
| `http.port` | `9090` | Read-only health/metrics/check listener. |
| `admin.port` | `9091` | Loopback-only toggle listener. |
| `admin.socketPath` | `/var/run/threat-engine/admin.sock` | Admin unix domain socket, served by the same handler as `admin.port`. |
| `admin.socketDir` | `/var/run/threat-engine` | Directory the socket is placed in. |
| `admin.socketHostPath` | `""` | When set, a `hostPath` backing `admin.socketDir`, so `threat-engine enforce` works from the node itself. Empty keeps the socket inside the pod. |
| `admin.enforcementLocked` | `false` | Source `ENFORCEMENT_ENABLED` from a ConfigMap and refuse runtime toggles (`403`). |
| `admin.enforcementConfigMap` | `""` | Existing ConfigMap holding the `ENFORCEMENT_ENABLED` key. Created by the chart when empty. |
| `serviceMonitor.enabled` | `false` | Render a Prometheus Operator `ServiceMonitor`. |
| `rbac.create` | `false` | Render a `Role`/`RoleBinding` (empty rules). |
| `tolerations` | `[{operator: Exists}]` | Schedule on every node, including tainted ones. |

See [`values.yaml`](values.yaml) for the full list.

## Enabling and disabling at runtime

The admin listener binds `127.0.0.1` on each node, so it is reachable from the
node or from inside the pod — never from another pod or off-host.

The preferred control surface is the admin unix socket, through the bundled CLI:

```bash
kubectl exec -n <ns> daemonset/threat-engine -- threat-engine enforce status
kubectl exec -n <ns> daemonset/threat-engine -- threat-engine enforce on
kubectl exec -n <ns> daemonset/threat-engine -- threat-engine enforce off
```

The DaemonSet is named after the release: `threat-engine` for
`helm install threat-engine`, `<release>-threat-engine` for any other release
name. Check with `kubectl get ds -n <ns>`.

The same handler is also available over the loopback TCP listener:

```bash
kubectl port-forward daemonset/threat-engine 19091:9091

curl -s 'http://127.0.0.1:19091/enforcement'                       # check
curl -s -X POST 'http://127.0.0.1:19091/enforcement?enabled=true'  # enable
curl -s -X POST 'http://127.0.0.1:19091/enforcement?enabled=false' # disable
```

Use a **different local port** than the container port. The pod shares the
node's network namespace, so the daemon already holds `127.0.0.1:9091` on that
node; forwarding `9091:9091` from the node itself fails with
`address already in use`. The same applies to the read-only port — forward it
as `19090:9090`.

The toggle reconciles the kernel synchronously — no restart and no wait for the
next scan. It is per-node: repeat on, or `kubectl exec` into, each node you want
to change. `kubectl port-forward` to a DaemonSet is not well supported in older
kubectl versions; `kubectl exec` into a specific pod is the reliable path.

## Letting a ConfigMap own enforcement

Set `admin.enforcementLocked=true` to make the environment the single source of
truth. The chart creates a ConfigMap, mounts its `ENFORCEMENT_ENABLED` key as an
env var, and the daemon then **refuses runtime toggles** with `403`:

```bash
helm upgrade threat-engine ./deploy/helm/threat-engine \
  --set enforcement.enabled=true \
  --set admin.enforcementLocked=true
```

To change it, edit the ConfigMap and roll the DaemonSet:

```bash
kubectl edit configmap threat-engine-enforcement -n <ns>
kubectl rollout restart daemonset/threat-engine -n <ns>
```

`GET /enforcement` keeps working while locked, so an operator can still see the
current state. Use an existing ConfigMap instead of the generated one with
`--set admin.enforcementConfigMap=<name>`.

## Validating the deployment

[`verify.sh`](verify.sh) checks that a running release is healthy. It needs
`kubectl` and permission to exec into the pod — not root on the node, because it
inspects the kernel through the pod, which shares the node's network namespace
and holds `NET_ADMIN`.

```bash
deploy/helm/threat-engine/verify.sh                       # defaults: -n threat-engine -r threat-engine
deploy/helm/threat-engine/verify.sh -n <ns> -r <release>
deploy/helm/threat-engine/verify.sh --toggle              # also exercise the on/off path
```

The read-only checks cover the workload (pods ready, no restarts), the startup
probes in the pod log (host network namespace, `ipset`, `iptables` raw table),
the kernel state (both ipset tables populated, and — while enforcement is off —
no chain and no jump), the HTTP surface (`/healthz`, `/metrics`, `/check`), and
two access-control boundaries: the public listener must refuse `/enforcement`
with `404`, and the admin listener must not answer on the node's own address,
because it binds `127.0.0.1` only.

`--toggle` additionally runs `enforce on` and `enforce off` and checks the
resulting kernel state: exactly one `PREROUTING` jump and a chain carrying both
the whitelist `RETURN` and the hostile `DROP` while on, and neither afterwards.
It really filters traffic on the node while enforcement is on, so it is opt-in.

The same checks by hand, if you would rather not run the script:

```bash
kubectl get pods -n <ns> -l app.kubernetes.io/instance=<release>
kubectl logs  -n <ns> daemonset/threat-engine | grep -E "host network namespace|ipset reachable|iptables raw table"
kubectl exec -n <ns> daemonset/threat-engine -- ipset list threat_engine_hostile_ips | grep "Number of entries"
kubectl exec -n <ns> daemonset/threat-engine -- iptables -t raw -S | grep THREAD_ENGINE_FILTER   # empty while off
kubectl exec -n <ns> daemonset/threat-engine -- wget -qO- http://127.0.0.1:9090/healthz
kubectl exec -n <ns> daemonset/threat-engine -- wget -qO- http://127.0.0.1:9090/metrics | grep enforcement_enabled
```

`verify.sh` checks the tables and the rules. To prove the rules really
*filter* — real packets through the node's `PREROUTING` path, a hostile source
dropped, and the same source whitelisted getting through — use the end-to-end
script from the repository root:

```bash
kubectl exec -i -n <ns> daemonset/threat-engine -- sh < tests/iptables-e2e.sh
```

It needs enforcement on (it refuses to run against a detached chain) and
cleans up after itself.

## Verifying enforcement

The gauge reads `1` when the drop rules are attached and `0` when they are inert:

```bash
curl -s http://127.0.0.1:9090/metrics | grep threat_engine_enforcement_enabled
```

The same scrape also reports the kernel's own packet and byte counters:
`threat_engine_dropped_packets_total`, `threat_engine_dropped_bytes_total`,
`threat_engine_whitelist_bypassed_packets_total`, and
`threat_engine_whitelist_bypassed_bytes_total`. These are sampled out of band
(`COUNTER_INTERVAL_SECONDS`, default `10`) so a scrape never blocks on the
kernel.

On a node, inspect the kernel directly:

```bash
sudo ipset list threat_engine_hostile_ips -terse
sudo iptables -t raw -L THREAD_ENGINE_FILTER -v -n -x
sudo iptables -t raw -C PREROUTING -j THREAD_ENGINE_FILTER   # exit 0 when attached
```

## Monitoring

Set `serviceMonitor.enabled=true` to scrape every node's metrics. The Service is
ClusterIP and exposes only the read-only port; each pod reports per-node numbers,
so prefer scraping all pods rather than aggregating through one Service endpoint.

## Uninstall

```bash
helm uninstall threat-engine
```

Uninstalling deletes the pods, and the daemon tears the kernel state down on its
way out: on `SIGTERM` it detaches the `raw:PREROUTING` jump, deletes the chain,
and destroys the ipset tables. A node that hosted a pod is left as it was found
— no chain, no jump, no sets.

The manual cleanup below is only needed after an **unclean** stop (`SIGKILL`,
OOM, power loss), which leaves the rules behind. Run it on every affected node:

```bash
sudo iptables -t raw -D PREROUTING -j THREAD_ENGINE_FILTER
sudo iptables -t raw -F THREAD_ENGINE_FILTER
sudo iptables -t raw -X THREAD_ENGINE_FILTER
sudo ipset destroy threat_engine_hostile_ips
sudo ipset destroy threat_engine_whitelist_ips
```

Verify with `sudo iptables -t raw -S | grep THREAD_ENGINE_FILTER` and
`sudo ipset list -n | grep threat_engine` — both should print nothing.
