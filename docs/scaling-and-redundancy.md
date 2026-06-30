# Scaling, clustering & redundancy

How to run more than one SIPhon node, what shared state actually means here, and
why SIPhon deliberately does **not** ship a clustering/replication engine.

---

## TL;DR

- **One node is a lot.** A single SIPhon process handles tens of thousands of calls
  per second — the documented baseline runs to roughly **28–30k cps** on one
  commodity box (see the [README baseline](https://github.com/siphon-project/siphon-sip/blob/main/README.md#current-baseline)). Most
  deployments never outgrow a single active node.
- **You run more than one node for _redundancy_, not throughput.** And you get
  redundancy the boring, proven SIP way: a **front-facing load balancer + DNS SRV
  records** (RFC 3263), not a bespoke cluster.
- **Redis gives you _durability_, not a live shared brain.** The Redis (or
  PostgreSQL) registrar backend persists bindings so a node recovers its full state
  on restart. It is **not** real-time location replication between running nodes.
- **In-flight calls are node-local.** Transactions, dialogs and B2BUA calls live in
  one process and are lost if that process dies — exactly like every other SIP stack
  that isn't running an explicit state-replication module. The right answer to "what
  if a node crashes" is usually *don't crash*, plus DNS SRV failover for new calls.

If that's all you needed, jump to [deployment.md](deployment.md) for the concrete
topologies and configs.

---

## Start here: do you even need to scale?

Before reaching for multiple nodes, be honest about the load. The single-node
baseline is high enough that **capacity is rarely the reason to add nodes**:

| You have | You probably need |
|---|---|
| Up to ~tens of thousands of cps, can tolerate a maintenance window | **One node** (optionally with a warm spare) |
| The same, but need to survive a node failure / do zero-downtime upgrades | **Two nodes behind a front LB + DNS SRV** |
| Genuinely beyond one box, or want N+1 spare capacity | **N nodes behind a front LB**, Redis-backed registrar |
| A full IMS core (millions of subscribers) | **IMS topology** — P/I/S-CSCF, with the **HSS** as the location authority |

The rest of this document explains *why* those are the answers, and what to watch
out for.

---

## What state lives where

A SIP engine holds several kinds of state. The only honest way to reason about
redundancy is to know, for each kind, **(a)** whether it is shared between running
nodes and **(b)** whether it survives a process restart.

| State | Where it lives | Shared between running nodes? | Survives restart? |
|---|---|---|---|
| **Registrar bindings** | local in-memory map + optional Redis/PostgreSQL | **Snapshot only** (loaded at boot — see below) | **Yes**, with a backend (UDP contacts) |
| **iFC profiles** (S-CSCF) | in-memory + optional Redis | Snapshot at boot | Yes, with Redis (avoids an HSS re-fetch storm) |
| **Named `cache`** | local LRU + optional Redis | **Yes — live**, read-through Redis | Yes, with Redis |
| **`subscribe_state` dialogs** | local map + optional cache | **Yes — live**, read-through | Yes, with Redis |
| **Transactions** (RFC 3261 §17) | local in-memory | No | No |
| **Dialogs / proxy sessions / B2BUA calls** | local in-memory / actors | No | No |
| **Presence** (PIDF, subscriptions) | local in-memory | No | No |
| **Gateway health** | local atomics, per-node probing | No (each node probes independently) | No (resets to healthy) |
| **Outbound registrations** (`registrant`) | local in-memory | No | No |

Two clean categories fall out of that table:

- **Live-shared via Redis:** the named `cache` and `subscribe_state`. These are
  true read-through L1/L2 caches — a write on one node is visible to a read on
  another. Point every node at the same Redis and they genuinely share this data.
- **Everything else is node-local at runtime.** The registrar is the interesting
  middle case, so it gets its own section.

---

## What the Redis registrar backend actually buys you

This is the part that surprises people, so it's worth being precise.

When you set `registrar.backend: redis` (or `postgres`):

- **Every REGISTER is written through to the backend** for durability.
- **At startup, a node loads the _entire_ registrar snapshot from the backend** —
  all AoRs, their contacts, service-routes, P-Associated-URIs, and iFC profiles.
- **At runtime, lookups read the local in-memory map only.** `registrar.lookup()`,
  `is_registered()` and friends never query the backend on the hot path. The only
  call that consults the backend live is `registrar.aor_count()` (so a cluster-wide
  count is authoritative).

The consequence, stated plainly:

> The Redis backend is **restart/crash durability + a boot-time snapshot**. It is
> **not** live cross-node location replication. A REGISTER that lands on node A is
> **not** visible to a lookup on node B until B is restarted (and reloads the
> snapshot) or the subscriber re-registers on B.

That sounds like a limitation, and it is — but it almost never bites, because of how
you deploy (next section). It also means the backend's job is exactly the one you
want it to do: **a node that dies and comes back is immediately whole again**, with
no HSS storm and no cold registrar.

### One restart caveat: UDP survives, connections don't

Connection-oriented bindings (**TCP / TLS / WS / WSS**) are deliberately dropped
when a node restores from the backend: the original socket is gone, so the contact
is unreachable until the UE re-registers over a fresh connection. **UDP bindings
survive** a restart intact (their flow identity is derived from the address pair,
which is stable across reboots). For TCP/TLS/WS/WSS fleets, lean on the UE's normal
re-REGISTER cadence (and `registrar.liveness`) to repopulate after a restart.

---

## How you actually get redundancy: front LB + DNS SRV

You do **not** need the nodes to share live call state to build a redundant service.
The standard SIP toolkit is enough:

1. **DNS SRV / NAPTR (RFC 3263).** Publish multiple targets for your SIP domain with
   priorities and weights. Clients (and upstream proxies) fail over to the next
   target automatically when one is unreachable. This is the primary redundancy
   mechanism for SIP, and SIPhon resolves SRV/NAPTR natively on outbound routing.
2. **A front-facing proxy / load balancer.** Put one SIP-aware element in front that
   spreads new transactions across the backend nodes. SIPhon itself can be that
   element (a thin proxy using a `gateway` group over the backends), or you can use
   any SIP LB you already trust.
3. **A shared Redis registrar backend.** So that a backend node which restarts (or a
   replacement that boots) comes up with the full binding set instead of an empty
   registrar.

For **registration-heavy** services there's one wrinkle: because lookups are
node-local, a subscriber can only be *reached for a terminating call* on the node
that currently holds their binding. Two ways to handle it:

- **Subscriber affinity (simplest).** Hash REGISTER **and** terminating requests for
  a given AoR to the same backend node at the LB (consistent hash on the AoR or
  source). Then "the node that holds the binding" is always the node the call lands
  on. This is the recommended pattern and needs no shared live state.
- **Re-register convergence (good enough for many).** Run an active/standby pair on a
  VIP; the standby boots with the snapshot and converges to current state as UEs
  re-REGISTER (seconds-to-minutes, bounded by your re-REGISTER interval). New calls
  ride DNS SRV failover in the meantime.

Concrete configs for all of this are in [deployment.md](deployment.md).

---

## Why SIPhon ships no clusterer or DMQ

If you come from Kamailio or OpenSIPS you'll notice SIPhon has nothing like their
state-replication subsystems. That's a deliberate design choice, not a gap waiting
to be filled.

- **OpenSIPS `clusterer`** replicates user location across a cluster, either
  *full-sharing* (full-mesh broadcast — every node mirrors the entire dataset) or
  *federation* (each node owns a partition), coordinated with active/backup
  *sharing tags* and seed-node sync.
  ([docs](https://opensips.org/html/docs/modules/devel/clusterer.html),
  [full-sharing write-up](https://blog.opensips.org/2018/09/13/clustered-sip-user-location-the-full-sharing-topology/))
- **Kamailio DMQ** (`dmq` + `dmq_usrloc`, dialog, htable) replicates state between
  nodes over a custom `KDMQ` SIP method, with auto node-discovery — but **all nodes
  must run the same major version or the cluster can crash**.
  ([docs](https://www.kamailio.org/docs/modules/devel/modules/dmq.html),
  [dmq_usrloc](https://www.kamailio.org/w/2015/01/new-module-dmq_usrloc/))

Both subsystems exist largely *because* a single Kamailio/OpenSIPS node, while very
capable, pushed large operators into many-node fleets that then had to share a
location table. They are powerful and they are also a meaningful source of
operational complexity (mesh membership, split-brain, version lockstep, sync edge
cases).

SIPhon's per-node ceiling moves the trade-off. With ~28–30k cps on one box, the
common deployment is **one active node, or a small redundant set behind an LB** —
which is served completely by *durability (Redis) + DNS SRV + affinity*. So SIPhon
ships that, and skips the replication engine.

**When would you actually miss full replication?** Only if you need *any node to
answer a terminating call for any subscriber, with zero affinity, and zero
re-register convergence window* — e.g. a very large active-active registrar fleet.
That's a real use case for a few operators; for them, LB-level subscriber affinity
is the supported answer today. If your scale genuinely demands live N-way usrloc
replication, that's a design conversation worth having explicitly rather than
turning on by default.

---

## What's lost when a node fails (and why that's fine)

If a node dies mid-call, the state that was *only* in that node is gone:

- **In-progress transactions and dialogs** — an INVITE that was ringing, a call that
  was up. The endpoints detect the dead dialog by normal SIP means (no response to
  the next request, session timers, RTP timeout) and tear down or re-originate.
- **B2BUA calls** — both legs were owned by that process; the call drops.
- **Presence subscriptions, gateway-health verdicts, outbound trunk registrations**
  — re-established by the replacement node from scratch.

This is **the same behavior as any SIP stack not running an explicit state
replication module**, and it's why the honest advice is:

1. **Make nodes not crash.** A wedged or crashing engine is a bug to fix, not a
   condition to engineer around. SIPhon has a graceful-drain path (SIGTERM → stop new
   INVITEs, let in-flight work finish) and a liveness watchdog that turns a hang into
   a fast restart — use them (see [deployment.md](deployment.md)).
2. **Fail over _new_ calls with DNS SRV.** Existing calls on the dead node are gone;
   new calls go to a healthy node automatically.
3. **Persist what's worth persisting (registrar, iFC) in Redis** so a recovered node
   is immediately whole.

Trying to transparently survive a mid-call node death — moving live dialogs between
machines — is enormous complexity for a payoff most deployments don't need. SIPhon
intentionally doesn't attempt it.

---

## Knowing which node owns a binding

When a script genuinely needs to reason about ownership across nodes, every accepted
binding carries identity:

- **`server.instance_id`** — a stable per-node id. Set it to the pod/host name; it
  supports env expansion, e.g. `instance_id: "${POD_NAME:-${HOSTNAME}}"`. Falls back
  to `$HOSTNAME`, then `"siphon"`.
- **`instance_epoch`** — a fresh UUID generated on every boot.
- **`contact.is_local`** — true only when a binding carries *this* node's id **and**
  *this* boot's epoch. After a restart, restored bindings carry their original
  writer's identity, so `is_local` is false for them until the UE re-registers. This
  is how, for example, an S-CSCF avoids treating a snapshot-restored binding as one
  it currently owns.

These are observability/decision hooks, not a replication mechanism — they let a
script *know* the topology, not change it.

---

## Rules of thumb

- Default to **one node**. Add nodes for **redundancy and upgrades**, not reflexively
  for throughput.
- Always run a **Redis (or PostgreSQL) registrar backend** in production — it's the
  difference between a recovered node being whole vs. empty.
- Front the nodes with a **load balancer + DNS SRV**; use **subscriber affinity** if
  you need any-node terminating-call delivery without a convergence window.
- Point every node at the **same Redis** for `cache` and `subscribe_state` if your
  scripts rely on those being shared live.
- Treat **in-flight call loss on node death as expected**; invest in stability and
  fast restart, not in live call-state replication.

See [deployment.md](deployment.md) for ready-to-run topologies (single node,
redundant pair, N+1, IMS) and the operations runbook, and
[migrating-from-kamailio-opensips.md](migrating-from-kamailio-opensips.md) if you're
coming from `clusterer` / DMQ.
