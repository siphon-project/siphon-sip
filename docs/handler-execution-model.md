# Handler execution model & blocking contract

This documents how SIPhon runs Python script handlers, what may block, and the
elasticity / backpressure / liveness guarantees. It is the user-facing companion
to the source doc-comments in
[`src/script/py_executor.rs`](https://github.com/siphon-project/siphon-sip/blob/main/src/script/py_executor.rs) and
[`src/script/async_pool.rs`](https://github.com/siphon-project/siphon-sip/blob/main/src/script/async_pool.rs).

## The two handler pools

Every inbound SIP message that reaches a script handler runs on one of two pools
of OS threads, each with a persistently-attached free-threaded Python
interpreter (the persistent attach avoids per-handler mimalloc heap churn / a
heap leak):

| Pool | Runs | Size config | Default |
|------|------|-------------|---------|
| **Sync executor** (`PyExecutor`) | sync `@proxy.on_request`, `@proxy.on_reply`, `@registrar.on_change`, `@rtpengine.on_dtmf`, timers, … | `script.sync_pool_size` / `script.sync_pool_max` | core `max(8, 2×CPUs)`, max `max(32, 4×core)` |
| **Async driver pool** (`AsyncPool`) | `async def` handlers + their `asyncio.create_task` work | `script.async_pool_size` | CPUs |

### The sync pool is elastic

The sync pool starts at `sync_pool_size` (the **core**, always-on workers) and a
background grower adds workers on demand — up to `sync_pool_max` — whenever the
job queue has more work than the idle workers can take. It **never shrinks**:
workers are never reaped, which is exactly what keeps the persistent
free-threaded-CPython attach from leaking (reaping a persistently-attached
thread orphans ~2 MB of heap). Growth-on-demand restores the burst headroom that
blocking handlers need; never-reaping keeps the no-leak property.

> Why elastic: an earlier change moved inbound dispatch off tokio's elastic
> `spawn_blocking` pool (which grew threads on demand) onto a **fixed** pool to
> stop the heap leak — but that removed the burst valve. A blocking handler pins
> a worker for the whole call, so on a small box a couple of concurrent blocking
> REGISTERs exhausted the fixed pool and wedged the engine with no recovery. The
> elastic pool is the proper fix: it grows like the old `spawn_blocking` pool but
> never reaps, so it neither wedges nor leaks. The regression is locked down by
> `pool_grows_under_blocking_load` in `py_executor.rs`.

The queue feeding the pool is **bounded** (`script.executor_queue_capacity`,
default 1024): once the pool is at its thread cap *and* the queue is full, new
jobs are shed.

## The blocking contract — what script authors must know

A handler may call Rust APIs that block the worker thread on I/O:
`auth.require_digest` with the HTTP/Diameter backend,
`proxy.send_request(wait_for_response=True)`, `cache.fetch`, `diameter.*`,
RTPEngine control, DNS/TLS connect during `relay()`, etc. **While a handler
blocks, it occupies one pool worker.**

The pool grows to absorb concurrent blocking handlers up to `sync_pool_max`, so
short blocking bursts are fine. But sustained blocking beyond the cap still
queues, and the maximum sustainable rate of a blocking handler is roughly:

```
max_rate ≈ sync_pool_max / average_handler_blocking_time
```

Design accordingly:

- **Cache hot lookups.** For HTTP digest auth, set `auth.http.cache_ttl_secs` so
  a registration storm for the same subscribers reuses a cached HA1 instead of
  making a blocking fetch per REGISTER — the pool then rarely needs to grow.
- **Fire-and-forget slow side-effects.** Do contact-change notifications, CDR
  posts, webhooks, etc. with `asyncio.create_task(...)` from an `async` handler —
  don't block the SIP path on them. A `httpx.Client` is **not** safe to share
  across threads.
- **Size for your backends and your memory.** Raise `sync_pool_max` for many
  slow blocking backends; lower it on memory-constrained NFs (peak memory ≈
  `sync_pool_max × ~2 MB`).

### Blocking calls must release the interpreter (free-threaded GC safety)

On free-threaded CPython (3.14t) the cyclic GC performs a **stop-the-world**:
it pauses every thread that is *attached* to the interpreter at a safe point. A
thread that performs a blocking call (an HTTP/Diameter auth fetch, a DNS lookup,
…) **while still attached** can never reach that safe point, so for the duration
of that block every other handler that allocates cyclic garbage — which Python
does constantly — stalls behind the GC. This is verified: a thread blocking
while attached hangs a concurrent `gc.collect()` for the whole block; detached,
it returns immediately. Under blocking-heavy load (auth/Diameter storms) the
result is periodic **engine-wide latency spikes**, each lasting as long as the
blocking call — and it bites even at low concurrency (one blocked-while-attached
handler plus one GC trigger).

The worst case has been seen on `cpus ≈ 1` nodes (a single-worker runtime,
where `available_parallelism()` reports 1), where the engine wedged outright
rather than just stalling. The exact escalation from a transient stall to a
permanent wedge on such nodes is not reproduced here, so treat it as an observed
correlation; the deadlock-aware watchdog (below) is the recovery backstop for
it. Either way the fix is the same.

The fix, and the rule for any blocking Rust-side work, is to **release the
interpreter for the blocking window** — in pyo3 terms,
`Python::attach(|py| py.detach(|| block_in_place(block_on(future))))`. siphon's
built-in blocking APIs (e.g. the HTTP digest-auth backend) do this internally;
the deadlock-aware watchdog above is the backstop for any path that doesn't.

This GC hazard is specific to **Rust-side** blocking calls, which hold the attach
for their whole duration. A blocking call made **from Python** in a handler — a
synchronous `httpx`/`urllib`/`requests` request in `@registrar.on_change`, say —
does *not* stall the GC: CPython releases the interpreter around the blocking
socket syscall, so the handler is detached for the wait. It still pins a pool
worker for the duration, though, so prefer `asyncio.create_task(...)` for slow
side-effects (throughput, not safety). Both paths are exercised by
`run-tests.sh --http-auth`: one scenario drives a REGISTER storm through the
blocking HA1-fetch (Rust) path, another through a blocking `on_change` notify
(Python) path, each on a single-worker (`cpus: 0.5`) siphon; the engine must
complete the registrations.

## Backpressure & liveness guarantees

Beyond elasticity, the pool is defended on two more fronts so a misbehaving
handler degrades gracefully instead of taking the node down silently:

1. **Bounded queue + load-shed.** When the pool is at its cap and the queue is
   full, new jobs are dropped (the SIP client retransmits) rather than growing
   memory without bound. Counted by `siphon_pyexec_jobs_shed_total`.
2. **Liveness watchdog / fail-fast.** A dedicated thread (immune to any lock a
   wedged handler holds) aborts the process when there is **work pending (a
   handler in-flight *or* jobs queued) yet zero completions** for
   `script.handler_stall_abort_secs` (default 30 s; `0` disables). The trigger
   is **independent of pool fill**, so it catches a *low-concurrency deadlock*
   (a handful of handlers stuck on a lock/await while the pool sits far below
   its cap) as well as full saturation — an earlier "at the thread cap + fully
   busy" condition could never see the former, since the pool never grew to the
   cap. A healthy pool advances completions every tick; a genuinely idle pool
   has no pending work — neither trips. Aborting is deliberate: a hung-but-alive
   SIP engine never recovers on its own, so a `restart: always` / systemd policy
   never fires — the abort turns an indefinite outage into a seconds-long
   restart and leaves a core for post-mortem.

## Metrics (`/metrics`)

| Metric | Meaning |
|--------|---------|
| `siphon_pyexec_pool_size` | live worker threads (grows core→max under load) |
| `siphon_pyexec_pool_max` | configured thread ceiling |
| `siphon_pyexec_inflight` | handlers currently executing |
| `siphon_pyexec_queue_depth` | handler jobs waiting in the queue |
| `siphon_pyexec_jobs_completed_total` | completed handler jobs |
| `siphon_pyexec_jobs_shed_total` | jobs dropped because the queue was full |
| `siphon_auth_ha1_cache_hits_total` | HTTP-auth lookups served from cache |

**Alert on**: a sustained `rate(siphon_pyexec_jobs_shed_total)` > 0, or
`siphon_pyexec_pool_size == siphon_pyexec_pool_max` with
`siphon_pyexec_inflight == siphon_pyexec_pool_size` held for minutes — both mean
the pool is fully grown and saturated, approaching the watchdog's abort condition.
