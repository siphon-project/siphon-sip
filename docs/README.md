# SIPhon documentation

Operator and developer documentation for SIPhon. (GitHub renders this page when you
browse the `docs/` folder.)

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
script, plus Kubernetes manifests — live in **[../deploy/](https://github.com/siphon-project/siphon-sip/tree/main/deploy/)**.

## Also

- The main **[README](https://github.com/siphon-project/siphon-sip/blob/main/README.md)** — overview, install, scripting API, performance.
- **[siphon.yaml](https://github.com/siphon-project/siphon-sip/blob/main/siphon.yaml)** — the annotated reference configuration.
- **[sdk/](https://github.com/siphon-project/siphon-sip/tree/main/sdk/)** — the `siphon-sip` mock library for testing scripts.
