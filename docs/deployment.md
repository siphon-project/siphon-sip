# Deployment & operations

Concrete topologies, configs, and the operational runbook for running SIPhon in
production. Read [scaling-and-redundancy.md](scaling-and-redundancy.md) first for
*why* these are the shapes — this doc is the *how*.

The golden rule from that document, restated: **one node does the work; you add
nodes for redundancy, and you get redundancy with a front LB + DNS SRV, not a
cluster.**

- [Scenario 1: single node](#scenario-1-single-node)
- [Scenario 2: redundant pair, N nodes (front LB + DNS SRV)](#scenario-2-redundant-pair-n-nodes)
- [Scenario 3: IMS core](#scenario-3-ims-core)
- [Operations runbook](#operations-runbook)
- [Kubernetes (kept deliberately light)](#kubernetes-kept-deliberately-light)

A runnable, self-contained version of Scenario 2 lives in
[`deploy/ha-demo/`](https://github.com/siphon-project/siphon-sip/tree/main/deploy/ha-demo/); the Kubernetes manifests are in
[`deploy/k8s/`](https://github.com/siphon-project/siphon-sip/tree/main/deploy/k8s/).

---

## Scenario 1: single node

The default, and the right answer for most deployments. One process, optionally a
Redis backend so a restart comes back whole.

```yaml
# siphon.yaml
listen:
  udp: ["0.0.0.0:5060"]
  tcp: ["0.0.0.0:5060"]
domain:
  local: ["example.com"]
script:
  path: "scripts/proxy_default.py"

registrar:
  backend: redis            # durability: a restart reloads the full snapshot
  redis:
    url: "redis://127.0.0.1:6379"

server:
  instance_id: "${HOSTNAME}"
  drain_secs: 30            # graceful drain on SIGTERM (see runbook)

metrics:
  prometheus:
    listen: "0.0.0.0:9090"  # /metrics — Prometheus scrape

admin:
  listen: "0.0.0.0:9091"    # /admin/health + /admin/ready probes, registrations
```

That's a production-shaped single node. A "warm spare" is just a second box with the
same config, kept ready; promote it by moving traffic (DNS/VIP) when you need to.

---

## Scenario 2: redundant pair, N nodes

Survive a node failure and do zero-downtime upgrades. Three ingredients, none of
which require the nodes to share live call state:

1. **DNS SRV** so clients/upstreams fail new calls over automatically.
2. **A front-facing SIP load balancer** spreading new transactions across backends.
3. **A shared Redis registrar backend** so a restarted/replacement node is whole.

### DNS SRV (the primary failover mechanism)

Publish every node as an SRV target. Equal priority + weight = load spread; lower
priority = standby.

```dns
;; Active/active across two nodes
_sip._udp.example.com. 3600 IN SRV 10 50 5060 node1.example.com.
_sip._udp.example.com. 3600 IN SRV 10 50 5060 node2.example.com.

;; Or active/standby: node2 only used if node1 is unreachable
_sip._udp.example.com. 3600 IN SRV 10 100 5060 node1.example.com.
_sip._udp.example.com. 3600 IN SRV 20 100 5060 node2.example.com.
```

SIPhon resolves SRV/NAPTR natively for its own outbound routing (RFC 3263), so this
works in both directions.

### The front LB (SIPhon fronting SIPhon)

You can use any SIP-aware load balancer you already trust. The self-contained way —
and what [`deploy/ha-demo/`](https://github.com/siphon-project/siphon-sip/tree/main/deploy/ha-demo/) demonstrates — is a thin SIPhon
proxy whose only job is to spread traffic over a `gateway` group of backends:

```yaml
# frontend siphon.yaml — the load balancer
listen:
  udp: ["0.0.0.0:5060"]
domain:
  local: ["example.com"]
script:
  path: "lb.py"
gateway:
  groups:
    - name: "backends"
      algorithm: hash       # consistent hash => subscriber affinity (see below)
      probe:
        enabled: true
        interval_secs: 5
        failure_threshold: 3
      destinations:
        - { uri: "sip:node1.example.com:5060", address: "10.0.0.1:5060" }
        - { uri: "sip:node2.example.com:5060", address: "10.0.0.2:5060" }
```

```python
# lb.py — spread new requests over the backend group; keep dialogs sticky
from siphon import proxy, gateway, log

@proxy.on_request
def route(request):
    if request.in_dialog:
        if request.loose_route():
            request.relay()
        else:
            request.reply(404, "Not Here")
        return

    # Affinity: hash on the AoR so a subscriber's REGISTER and the terminating
    # calls to them land on the SAME backend (which is the node that then holds
    # their binding in its local registrar).
    destination = gateway.select("backends", key=str(request.to_uri))
    if not destination:
        request.reply(503, "Service Unavailable")
        return
    request.record_route()
    request.relay(destination.uri)
```

### Why the affinity hash matters

Registrar lookups are node-local (see
[scaling-and-redundancy.md](scaling-and-redundancy.md#what-the-redis-registrar-backend-actually-buys-you)).
A subscriber can only be *reached for a terminating call* on the node holding their
binding. Hashing **both** the REGISTER and the terminating INVITE on the AoR sends
both to the same backend, so terminating delivery always works — with no shared live
state. If you don't need any-node terminating delivery (e.g. pure outbound trunk /
PSTN breakout), drop the affinity and use `algorithm: weighted`.

### Backends

Each backend is a Scenario-1 node pointed at the **same** Redis, with a distinct
`instance_id`:

```yaml
registrar:
  backend: redis
  redis:
    url: "redis://redis.internal:6379"
server:
  instance_id: "node1"     # node2, node3, ... — distinct per node
  drain_secs: 30
```

### Optional: a VIP instead of (or with) the front LB

For a classic active/standby pair, put a virtual IP (keepalived/VRRP) in front. The
standby boots with the registrar snapshot and converges as UEs re-REGISTER; new
calls ride DNS SRV during the swing. This is simpler than the front-LB approach but
gives you active/standby rather than active/active.

---

## Scenario 3: IMS core

In IMS, **SIPhon does not need to share location state at all**, because the
**HSS is the location authority**:

- The **I-CSCF** does a Cx LIR to the HSS to find the subscriber's serving
  **S-CSCF**, then routes there. Terminating routing never depends on any single
  SIPhon node's local registrar.
- **S-CSCF** instances persist registrar bindings and iFC profiles in Redis, so an
  S-CSCF restart doesn't trigger an HSS re-fetch storm.
- **P-CSCF** is edge state (IPsec SAs, Path) and scales horizontally behind the
  Gm reference point.

So an IMS core scales to many nodes per role using exactly the mechanisms above plus
the HSS — no `clusterer`/DMQ equivalent required. See the
[`examples/ims_*`](https://github.com/siphon-project/siphon-sip/tree/main/examples/) configs for per-role starting points.

---

## Operations runbook

### Graceful drain & rolling upgrades

On `SIGTERM`/`SIGINT`, SIPhon **stops accepting new INVITEs** and waits up to
`server.drain_secs` (default **30s**) for in-flight transactions and B2BUA calls to
finish before exiting. Set `drain_secs: 0` to exit immediately.

A rolling upgrade is therefore:

1. Remove the node from the LB / DNS rotation (or let the LB's health probe do it).
2. `SIGTERM` the process; it drains in-flight work.
3. Replace the binary / image; start it. With a Redis backend it reloads the full
   registrar snapshot on boot.
4. Re-add to rotation. Repeat per node.

In Kubernetes, wire this to the pod lifecycle (below): a `preStop` hook plus a
`terminationGracePeriodSeconds` **≥ `drain_secs`** lets the drain complete before the
kubelet sends `SIGKILL`.

### Health checks & probes

Enable the **admin API** and point your probes at it:

```yaml
admin:
  listen: "0.0.0.0:9091"   # serves /admin/health, /admin/ready, /admin/*, /metrics
```

- **Liveness:** `GET http://<node>:9091/admin/health` → `200` for as long as the
  process is alive. It does **not** flip during drain — a liveness probe failing
  mid-drain would make the orchestrator kill the node before it finished draining.
- **Readiness:** `GET http://<node>:9091/admin/ready` → `200` normally, **`503`
  while draining** (after `SIGTERM`) so a load balancer / Kubernetes pulls the node
  from rotation before it stops accepting new INVITEs.

The admin port also serves `/admin/stats`, `/admin/registrations[/{aor}]` (inspect
or force-unregister bindings), and `/metrics`. If you'd rather not enable it, a
`GET /metrics` returning `200` is a serviceable liveness signal and a SIP `OPTIONS`
ping to the SIP port works for readiness (the default proxy scripts answer local
`OPTIONS` with `200`).

### Metrics & alerting

Scrape `/metrics`. The handful that matter operationally:

| Signal | Alert when | Why |
|---|---|---|
| `siphon_memory_allocated_bytes` | `rate(...[30m]) > 0` while call rate is flat | A real leak. The per-structure gauges (`siphon_proxy_dialog_sessions`, `siphon_uac_pending_requests`) localize it. |
| `siphon_pyexec_jobs_shed_total` | sustained `rate() > 0` | Handler pool saturated + queue full → SIP retransmits. Raise `sync_pool_max` or speed up handlers. |
| `siphon_pyexec_pool_size` vs `_pool_max` | `pool_size == pool_max` **and** `inflight == pool_size` for minutes | Pool fully grown and saturated, approaching the liveness watchdog. |
| `siphon_proxy_dialog_sessions` | grows unbounded under flat completed-call load | Dialog state not draining — a leak signature. |

See [handler-execution-model.md](handler-execution-model.md) for the pool internals
and the blocking-handler contract that drives these.

### Capacity planning

- **Throughput:** ~28–30k cps per node on commodity hardware (the README baseline);
  free-threaded CPython 3.14t is required to reach it (the container image ships it).
- **Memory:** dominated by the handler pool — roughly
  `sync_pool_max × ~2 MB` at peak. Lower `script.sync_pool_max` on
  memory-constrained nodes; prefer `auth.http.cache_ttl_secs` so an auth storm never
  needs the pool to grow in the first place.
- **Stability over heroics:** if a node is unstable under load, fix the instability —
  don't paper over it with more nodes. The liveness watchdog
  (`script.handler_stall_abort_secs`) converts a hang into a fast supervised restart
  rather than an indefinite outage.

### State backup & DR

The only durable state SIPhon owns lives in your **Redis / PostgreSQL** registrar
backend (bindings, service-routes, P-Associated-URIs, iFC profiles). Back that up
with its native tooling (Redis RDB/AOF, `pg_dump`). Everything else is either
ephemeral (transactions, dialogs — not meaningful to back up) or reconstructed from
re-registration. There is no SIPhon-specific snapshot format to manage.

---

## Kubernetes (kept deliberately light)

People expect to see K8s, so here's a clean shape to copy — **not** a platform.
Manifests are in [`deploy/k8s/`](https://github.com/siphon-project/siphon-sip/tree/main/deploy/k8s/). The load-bearing details:

- **`StatefulSet`** (not Deployment) so each pod has a stable identity. Wire
  `server.instance_id` from the pod name via the downward API:

  ```yaml
  env:
    - name: POD_NAME
      valueFrom: { fieldRef: { fieldPath: metadata.name } }
  # siphon.yaml: server.instance_id: "${POD_NAME}"
  ```

- **Graceful drain:** let the SIGTERM drain finish before SIGKILL.

  ```yaml
  terminationGracePeriodSeconds: 40        # >= server.drain_secs
  # (SIGTERM is sent on pod termination; siphon drains for drain_secs.)
  ```

- **Probes on the admin API** (`admin.listen`) — liveness that survives drain,
  readiness that fails closed during drain:

  ```yaml
  livenessProbe:
    httpGet: { path: /admin/health, port: 9091 }
    initialDelaySeconds: 5
    periodSeconds: 10
  readinessProbe:
    httpGet: { path: /admin/ready, port: 9091 }   # 503 while draining
    periodSeconds: 5
  ```

- **Networking:** SIP is sensitive to NAT rewriting of `Via`/`Contact`. Prefer
  `hostNetwork: true` (or a properly configured `LoadBalancer`/`externalTrafficPolicy:
  Local` so source IPs and ports survive) and set `advertised_address` to what peers
  should see.
- **Redis** as a normal dependency (a `Deployment` + `Service`, or a managed Redis).
  All siphon pods share it for registrar durability.
- **Config** via a `ConfigMap` (siphon.yaml + the script), mounted read-only.

That's enough to run a redundant SIPhon `StatefulSet` behind a `Service`. Scale with
`replicas`; pair it with subscriber-affinity at your ingress if you need any-pod
terminating delivery. Anything fancier (HPA on cps, per-pod SRV, Diameter SCTP) is a
deployment-specific exercise, not something to bake into a starter manifest.
