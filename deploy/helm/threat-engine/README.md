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

## Install

```bash
helm install threat-engine ./deploy/helm/threat-engine
```

Enforcement stays disabled. To enable it for every node from the start:

```bash
helm install threat-engine ./deploy/helm/threat-engine --set enforcement.enabled=true
```

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
| `serviceMonitor.enabled` | `false` | Render a Prometheus Operator `ServiceMonitor`. |
| `rbac.create` | `false` | Render a `Role`/`RoleBinding` (empty rules). |
| `tolerations` | `[{operator: Exists}]` | Schedule on every node, including tainted ones. |

See [`values.yaml`](values.yaml) for the full list.

## Enabling and disabling at runtime

The admin listener binds `127.0.0.1` on each node, so it is reachable from the
node or from inside the pod — never from another pod or off-host. Reach it with
`kubectl port-forward` (or `kubectl exec`):

```bash
kubectl port-forward daemonset/threat-engine-threat-engine 9091:9091

# enable
curl -s -X POST 'http://127.0.0.1:9091/enforcement?enabled=true'

# check
curl -s 'http://127.0.0.1:9091/enforcement'

# disable
curl -s -X POST 'http://127.0.0.1:9091/enforcement?enabled=false'
```

The toggle reconciles the kernel synchronously — no restart and no wait for the
next scan. It is per-node: repeat on, or `kubectl exec` into, each node you want
to change. `kubectl port-forward` to a DaemonSet is not well supported in older
kubectl versions; `kubectl exec` into a specific pod is the reliable path.

## Verifying enforcement

The gauge reads `1` when the drop rules are attached and `0` when they are inert:

```bash
curl -s http://127.0.0.1:9090/metrics | grep threat_engine_enforcement_enabled
```

On a node, inspect the kernel directly:

```bash
sudo ipset list threat_engine_hostile_ips -terse
sudo iptables -t raw -L THREAD_ENGINE_FILTER -v -n
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

Uninstalling removes the pods but **leaves the kernel state behind**, because
`ipset`/`iptables` objects are not Kubernetes resources. Clean up a node with:

```bash
sudo iptables -t raw -D PREROUTING -j THREAD_ENGINE_FILTER
sudo iptables -t raw -F THREAD_ENGINE_FILTER
sudo iptables -t raw -X THREAD_ENGINE_FILTER
sudo ipset destroy threat_engine_hostile_ips
sudo ipset destroy threat_engine_whitelist_ips
```

Run those on every node that hosted a pod.
