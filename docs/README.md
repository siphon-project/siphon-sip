# SIPhon

**A high-performance SIP proxy, B2BUA, and IMS platform — a Kamailio/OpenSIPS-class
protocol engine, scripted in Python instead of a config DSL.**

SIPhon is written in Rust — the transports, the RFC 3261 transaction and dialog state
machines, the registrar — and scripted in free-threaded Python, which decides policy.
You get the parts that are genuinely hard to get right as a fast, memory-safe core,
and you drive them with real code:

- **Python, not a config language** — real functions, imports, a debugger, and
  `pytest` (with a mock SDK) instead of `$avp` expansions and `failure_route` chains.
- **One YAML file** for config — documented inline, no `modparam`.
- **Hot-reload** — edit a script, save, done. No restart.
- **The B2BUA is first-class** — two independent dialogs, topology hiding, media
  anchoring, header policies, forking — in ~50 lines of readable Python.
- **Fast** — tens of thousands of calls per second per node (~28–30k cps on commodity
  hardware), so you usually add nodes for *redundancy*, not throughput.

```python
from siphon import b2bua, gateway

@b2bua.on_invite
def on_invite(call):
    call.media.anchor(engine="rtpengine")      # hide the media path
    call.remove_headers_matching("^X-")         # strip internal headers
    call.dial(gateway.select("carriers").uri)   # bridge to a trunk
```

That's a topology-hiding SBC with media anchoring. More like it in the Cookbook.

## New here? Start with the Cookbook

The **[Cookbook](cookbook/index.md)** has complete, working starting points for the
common roles — each with the config, a real script, and how to test it:

[Registrar](cookbook/registrar.md) ·
[Stateful proxy](cookbook/proxy.md) ·
[Load balancer](cookbook/load-balancer.md) ·
[SBC (B2BUA)](cookbook/sbc.md) ·
[Media & RTP profiles](cookbook/media-rtp.md) ·
[Hardening & security](cookbook/security.md) ·
[Monitoring](cookbook/monitoring.md)

## Running it in production

- **[Scaling, clustering & redundancy](scaling-and-redundancy.md)** — how to run more
  than one node, what shared state actually means here, what the Redis backend buys
  you (durability + boot snapshot, **not** live cross-node sync), and why SIPhon
  ships no `clusterer`/DMQ-style replication engine. **Start here** if you're asking
  "how does SIPhon cluster?"
- **[Deployment & operations](deployment.md)** — concrete topologies (single node,
  redundant pair / N nodes, IMS), the ops runbook (graceful drain, health/readiness
  probes, metrics & alerting, capacity planning, backup/DR), and a light Kubernetes
  shape.
- **[Supply chain & SBOM](supply-chain.md)** — what every release publishes (SPDX +
  CycloneDX SBOM), how to feed it to your own scanners, how dependency advisories are
  audited, and how to report a vulnerability.
- **[Migrating from Kamailio / OpenSIPS](migrating-from-kamailio-opensips.md)** — a
  concept map for porting routes and modules, and how to translate `clusterer` /
  `dmq_usrloc` topologies to SIPhon's model.

## Internals

- **[Handler execution model](handler-execution-model.md)** — how Python handlers
  run, the blocking contract, and the elasticity / backpressure / liveness
  guarantees of the handler pool.
- **[Feature readiness matrix](feature-readiness-matrix.md)** — per-feature maturity
  (Production / Implemented / Planned) with config keys and validation notes.

## Runnable deployments

Reference deployment artifacts — a front-LB + 2-backend demo with a failover-proof
script, plus Kubernetes manifests — live in **[deploy/](https://github.com/siphon-project/siphon-sip/tree/main/deploy/)**.

## Commercial support & sponsorship

Running SIPhon in production and want a hand — or want to fund a feature? Commercial
support and feature sponsorship are available from
**[Real Time Telecom B.V.](https://realtime-telecom.nl)**, run by SIPhon's maintainer.
See **[Commercial support](support.md)**.

## Platform Partner

<p align="center">
  <a href="https://www.arnacon.com/"><img src="assets/partners/arnacon.png" alt="Arnacon by Cellact — Platform Partner" width="300"></a>
</p>

Development is backed by **[Cellact](https://www.cellact.com/)** and its Web3 telecom
project **[Arnacon](https://www.arnacon.com/)** as a Platform Partner. Their support helps
drive the SIPhon roadmap forward.

## Also

- The main **[README](https://github.com/siphon-project/siphon-sip/blob/main/README.md)** — overview, install, full scripting API, performance baseline.
- **[siphon.yaml](https://github.com/siphon-project/siphon-sip/blob/main/siphon.yaml)** — the annotated reference configuration.
- **[sdk/](https://github.com/siphon-project/siphon-sip/tree/main/sdk/)** — the `siphon-sip` mock library for testing scripts.
