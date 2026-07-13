# Migrating from Kamailio / OpenSIPS

A practical concept map for engineers coming from Kamailio or OpenSIPS, plus the one
topic that trips people up: **state sharing and clustering**.

This is not a feature-by-feature parity claim. SIPhon's protocol engine is faithful
to the same RFCs (transactions per RFC 3261 §17, registrar §10, proxy §16), so the
*concepts* map directly — what changes is the *surface*: a Python API + YAML instead
of a routing-script DSL + `modparam`.

---

## The mental-model shift

| Kamailio / OpenSIPS | SIPhon |
|---|---|
| `kamailio.cfg` / `opensips.cfg` routing-script DSL | Python handlers (`@proxy.on_request`, `@b2bua.on_invite`, …) |
| `modparam("module", "param", value)` | one `siphon.yaml`, documented inline |
| `loadmodule "x.so"` | nothing — capabilities are namespaces you `import` |
| Edit cfg → restart (or limited rtimer reloads) | Edit script → inotify hot-reload, no restart |
| `$avp(...)`, `$var(...)`, `$dlg_val(...)` | ordinary Python variables and objects |
| Test with a live instance + SIPp | Unit-test scripts with the `siphon-sip` mock SDK, plus SIPp |

The biggest day-to-day change: routing logic is **real code** — functions, imports,
a debugger, `pytest` — not an expression language.

---

## Routing & transactions

| Kamailio / OpenSIPS | SIPhon |
|---|---|
| `t_relay()` | `request.relay()` |
| `t_relay()` to a fixed target / `$du` | `request.relay("sip:next@host:port")` |
| `t_load_contacts()` + `t_next_contacts()` (serial/parallel forking) | `request.fork(targets, strategy="parallel"\|"sequential")` |
| `record_route()` | `request.record_route()` |
| `loose_route()` | `request.loose_route()` |
| `failure_route[...]` | `@proxy.on_failure` (and per-relay `on_failure=`) |
| `onreply_route[...]` | `@proxy.on_reply` |
| `sl_send_reply()` / `t_reply()` | `request.reply(code, reason)` |
| `$ru`, `$rU`, `$rd` | `request.ruri`, `request.ruri.user`, `request.ruri.host` |
| `$fU`/`$tU`, `$ft`/`$tt` | `request.from_uri`/`to_uri`, `request.from_tag`/`to_tag` |
| `is_method("INVITE")` | `@proxy.on_request("INVITE")` or `request.method == "INVITE"` |
| `has_totag()` / loose-route dialog check | `request.in_dialog` |

CANCEL handling, Max-Forwards enforcement, retransmission absorption and ACK-for-non-2xx
are done by the SIPhon transaction layer automatically — you don't write routes for
them (see the framework-handles-automatically notes in the API reference).

## Registrar / user location

| Kamailio / OpenSIPS | SIPhon |
|---|---|
| `save("location")` | `registrar.save(request)` (also sends the 200 OK) |
| `lookup("location")` | `registrar.lookup(uri)` → `list[Contact]` |
| `registered("location")` | `registrar.is_registered(uri)` |
| `usrloc` DB modes / `db_url` | `registrar.backend: memory \| redis \| postgres` |
| `nathelper` / `fix_nated_*` | `request.fix_nated_contact()` / `fix_nated_register()` / `add_contact_alias()` |

## Auth

| Kamailio / OpenSIPS | SIPhon |
|---|---|
| `www_authorize()` / `auth_check()` | `auth.require_www_digest(request, realm)` |
| `proxy_authorize()` | `auth.require_proxy_digest(request, realm)` |
| `pv_www_authenticate()` w/ AKA | `auth.require_aka_digest()` / `auth.require_ims_digest()` |

## State, data & dispatch

| Kamailio / OpenSIPS | SIPhon |
|---|---|
| `htable` (`$sht(...)`) | `cache` namespace (local LRU + optional Redis, shared live) |
| `dispatcher` module + `ds_select_dst()` | `gateway` namespace (`gateway.select(group, key=…)`) + YAML `gateway.groups` |
| `ds_is_from_list()` / `ds_is_in_list()` | `request.from_gateway(group)` / `call.from_gateway(group)` / `reply.from_gateway(group)` (source-IP membership of a `gateway` group; the `reply` form tests which trunk answered) |
| `dialog` module (`$dlg_val`, profiles) | the B2BUA call object (`@b2bua.*`, `call.*`) for true call control |
| `rtpengine_*()` | `call.media.anchor()` / the `rtpengine` namespace |
| `sqlops` / `avpops` against a DB | plain Python (use a DB client in an `async` handler, off the hot path) |

> Module state habit to unlearn: in cfg you'd stash cross-request state in `htable`.
> In SIPhon scripts, **don't** hold cross-request state in module-level Python
> dicts/lists — use the `cache` namespace (Redis-backed, survives hot-reload, shared
> across nodes). Module-level **constants** are fine.

---

## Clustering & shared state — read this carefully

This is where expectations differ most, because Kamailio and OpenSIPS both grew
explicit **state-replication subsystems** and SIPhon deliberately did not.

**What you're used to:**

- **OpenSIPS `clusterer`** — distributed user location via *full-sharing* (full-mesh
  broadcast; every node mirrors the whole location table) or *federation*
  (partitioned), with active/backup *sharing tags* and seed-node sync.
- **Kamailio `dmq` / `dmq_usrloc`** — replicate usrloc/dialog/htable between nodes
  over the `KDMQ` SIP method, with node auto-discovery (and the requirement that all
  nodes run the same major version).

**What SIPhon does instead** — and *why* — is covered in full in
[scaling-and-redundancy.md](scaling-and-redundancy.md). The short version:

- There is **no live cross-node replication engine**. Multi-node redundancy is a
  **front LB + DNS SRV + a shared Redis registrar backend**.
- The Redis backend gives **durability + a boot-time snapshot**, *not* live
  replication: a node reads its own in-memory location table at lookup time and
  reloads the full snapshot from Redis on restart. So a binding registered on node A
  is reachable for terminating calls on node A; to get any-node terminating delivery,
  hash REGISTER and INVITE for an AoR to the **same** node at the LB (subscriber
  affinity).
- The `cache` and `subscribe_state` namespaces *are* shared live via Redis (the
  closest analogue to a replicated `htable`).

### Porting your topology

| If you ran… | Port it to… |
|---|---|
| OpenSIPS `clusterer` *full-sharing* usrloc | Front LB with **subscriber affinity** (consistent hash on AoR) + shared Redis registrar. No mesh to operate. |
| OpenSIPS *federation* / partitioned usrloc | The same affinity hash *is* your partitioning — each AoR deterministically maps to one node. |
| Kamailio `dmq_usrloc` active/active pair | Active/active behind a front LB + DNS SRV, shared Redis; or active/standby on a VIP with re-register convergence. |
| Kamailio `dmq` for `htable` replication | Point all nodes at one Redis and use the `cache` namespace (already shared live). |
| `dispatcher` health-checked gateway pools | `gateway.groups` with `probe.enabled: true` (per-node probing). |

### What's intentionally different (don't expect it)

- **Live dialog/transaction replication across nodes** — not provided. A node death
  drops its in-flight calls; new calls fail over via DNS SRV. (This matches Kamailio/
  OpenSIPS *without* an active replication module.)
- **A cluster membership protocol** — there isn't one to configure, monitor, or
  debug. Redis + DNS are the only shared infrastructure.
- **Version-locked node meshes** — not applicable; nodes don't talk a replication
  protocol to each other, so they don't have to move in lockstep.

If your scale genuinely requires N-way live usrloc replication with zero affinity,
that's a deliberate design discussion — see the "when would you miss one" section of
[scaling-and-redundancy.md](scaling-and-redundancy.md#why-siphon-ships-no-clusterer-or-dmq).

---

## Where to look next

- [scaling-and-redundancy.md](scaling-and-redundancy.md) — the full state model.
- [deployment.md](deployment.md) — ready-to-run topologies and the ops runbook.
- The Python API reference and the `sdk/` mock library — for the per-method surface
  you'll port routes onto.
