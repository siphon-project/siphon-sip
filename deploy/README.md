# Deploying SIPhon

Reference deployment artifacts for the topologies described in
[`docs/deployment.md`](../docs/deployment.md). Start with the docs for the *why*;
this directory is the *how*.

> **The thesis:** one SIPhon node handles tens of thousands of cps, so you run more
> than one node for **redundancy**, and you get redundancy with a **front LB + DNS
> SRV + a shared Redis registrar** — not a clustering engine. See
> [`docs/scaling-and-redundancy.md`](../docs/scaling-and-redundancy.md).

## Layout

| Path | What it is |
|---|---|
| [`ha-demo/`](ha-demo/) | The "front LB + 2 backends + shared Redis" pattern, runnable two ways |
| [`k8s/`](k8s/) | A light Kubernetes shape: `StatefulSet` + `Service` + Redis + `ConfigMap` |

## `ha-demo/` — two ways to run it

**1. Quick failover proof (host binary, no image build):**

```bash
# needs a built siphon binary (redis-backend feature), docker, curl, python3
cargo build --release --features redis-backend          # PYO3_PYTHON=python3
SIPHON_BIN=target/release/siphon deploy/ha-demo/validate.sh
```

`validate.sh` starts a throwaway Redis + two backend nodes + a front LB on the host
(isolated ports, own Redis — it can't collide with anything else), then asserts:

- **Phase A** — a REGISTER and a terminating INVITE routed through the LB succeed
  (the front-LB + node-local-registrar pattern works end to end).
- **Phase B** — a binding is persisted to Redis, is **not** visible on a sibling node
  (the honest "no live cross-node sync" boundary), and is **recovered from Redis**
  when its node is killed and restarted — proving the one durability claim the docs
  make. It prints `ALL N ASSERTIONS PASSED`.

**2. Containerised reference (the shape you'd actually deploy):**

```bash
cd deploy/ha-demo
docker compose -p siphon-hademo -f docker-compose.ha.yaml up --build
# SIP ingress on udp/5060, /metrics on 9090
```

This builds the image from the repo `Dockerfile` and runs `redis` + `backend1` +
`backend2` + `frontend`. Swap the `build:` blocks for a published
`image:` once you have one.

### Files

| File | Role |
|---|---|
| `siphon-backend.yaml` | a backend node (Redis-backed registrar) |
| `siphon-frontend.yaml` | the front LB (a `gateway` group over the backends) |
| `proxy.py` | backend routing (REGISTER→save, INVITE→lookup+relay) |
| `lb.py` | front-LB routing (hash on AoR → affinity → relay) |
| `sipcli.py` | a tiny self-contained SIP/UDP probe (no sipp dependency) |
| `validate.sh` | the host-binary failover proof |
| `docker-compose.ha.yaml` | the containerised reference topology |

All configs are parametrised with `${VAR:-default}`, so the same files back both the
compose and the host-binary runs.

## `k8s/`

A deliberately minimal Kubernetes shape — a starting point to copy, not a platform.

```bash
kubectl apply -f deploy/k8s/
```

| File | Role |
|---|---|
| `configmap.yaml` | `siphon.yaml` + the routing script |
| `redis.yaml` | shared Redis (Deployment + Service) |
| `statefulset.yaml` | SIPhon pods with stable identity, drain-aware termination, `/metrics` probes |
| `service.yaml` | headless Service (per-pod DNS / SRV) + a `LoadBalancer` ingress |

Scale with `replicas`. For any-pod terminating-call delivery, add subscriber affinity
at your ingress (consistent hash on the AoR) — see
[`docs/deployment.md`](../docs/deployment.md#kubernetes-kept-deliberately-light).
