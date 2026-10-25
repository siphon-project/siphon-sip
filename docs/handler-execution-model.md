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

## Which handlers run, and which decision survives

`@proxy.on_request` takes an optional method filter. A **filtered handler does
not replace the unfiltered one — both run**, in registration order, and an
unfiltered handler matches every method.

That much is ordinary middleware. The part that surprises people is what
happens to the *routing decision*.

### One action slot, last writer wins

Every handler that runs for a request shares **one request object with a single
action slot**. `reply()`, `relay()`, `fork()` and `reject()` do not send
anything — they **assign** that slot. The dispatcher executes its final value
once, after every handler has returned.

So handlers do not each act. They take turns overwriting one decision:

```python
@proxy.on_request("OPTIONS")
def probe(request):
    request.reply(200, "OK")       # ← discarded

@proxy.on_request
def route(request):
    request.relay(NEXT_HOP)        # ← this is what happens
```

The health probe is **not answered and then relayed**. It is *only relayed* —
the `reply(200)` is gone, silently, because a later handler assigned over it.
Registration order decides, which is rarely what the author meant.

Side effects are different: `set_header()`, `record_route()`, `log`, metrics and
cache writes all happen, from every handler that runs. It is only the routing
decision that is last-writer-wins.

### Keeping your decision: `stop_propagation()`

```python
@proxy.on_request("OPTIONS")
def probe(request):
    request.reply(200, "OK")
    request.stop_propagation()     # nothing may overwrite this
```

The dispatcher stops the chain and executes what this handler chose.

It is opt-in on purpose. Answering is not on its own a request to stop — a
metrics or logging handler running afterwards is legitimate, and stopping by
default would silently drop it. Idempotent, and it leaves the chosen action
alone.

The alternative, if you would rather not register two handlers at all, is to
branch inside one:

```python
@proxy.on_request
def route(request):
    if request.method == "OPTIONS" and not request.in_dialog:
        request.reply(200, "OK")
        return
    request.relay(NEXT_HOP)
```

!!! note "Coming from Kamailio or OpenSIPS?"

    There is no equivalent of this in either. Both have exactly **one**
    automatic entry point — Kamailio's `request_route`, OpenSIPS's `route{}` —
    and everything else (`route(NAME)`, `branch_route`, `failure_route`) is
    invoked or armed explicitly. You branch inside the one route with
    `if (is_method("INVITE"))`, so two blocks can never both claim a request.

    siphon's model is closer to HTTP middleware: several handlers may match, and
    `stop_propagation()` is the `next()`-style control that model needs.
    `@proxy.on_request("INVITE")` is therefore **not** a drop-in for
    `is_method("INVITE")` — the Kamailio form is an exclusive branch, the
    decorator is additive.

!!! warning "`@diameter.on_request` is the other way round"

    The Diameter decorator takes a filter of the same shape
    (`@diameter.on_request("ULR")`, `"ULR|AIR"`, `"S6a:ULR"`) but dispatches
    **one** handler per request: the most specific filter that matches wins, and
    an unfiltered `@diameter.on_request` is the lowest-specificity fallback that
    runs only when nothing more specific matched.

    The difference is deliberate rather than accidental. A Diameter request
    needs exactly **one** answer, so one handler must own it. A SIP request can
    legitimately interest several handlers at once — metrics, lawful intercept,
    authentication, routing — so they compose. Worth knowing all the same if you
    are porting a routing pattern between the two namespaces.

### What `@b2bua.on_failure` decides

A B2BUA call that could not be connected runs `@b2bua.on_failure(call, code,
reason)` once, before the caller hears anything. `code` is what the call failed
on: the best of its branches' failures (RFC 3261 §16.7), `408` for the ring
timeout, `503` when the B-leg INVITE never left or no LCR carrier was routable,
and `500` when `@b2bua.on_answer` raised or ended an answered call. The `Call`
has the same single action slot, and its final value is carried out:

| The handler leaves | What happens |
|---|---|
| nothing, or `call.terminate()` | the caller gets `code` |
| `call.reject(code, reason)` | the caller gets that response instead (3xx-6xx) |
| `call.dial()`, `call.fork()`, `call.route()` | the call is routed again, still unanswered, and the handler runs again if that fails too |
| `call.handover(app)` | the unanswered call goes to a control app |
| `call.answer()` | siphon answers the caller itself, and the call lives on |

`code` is what the caller is sent, which is not always what the far end said: a
B-leg's `503` reaches the caller (and `code`) as `500`, and an exhausted route
sequence or fork ends on the best failure of all its legs. `call.failure_response`
is that leg's own final response, read-only (`status_code`, `reason`,
`get_header(name)`, `get_headers(name)`, `body`, `content_type`), so a handler
can act on what the far end actually sent, such as a CS breakout on a `488` whose
SDP offers no audio or on a `500` whose `Reason` carries a failure cause
(TS 24.292 §10.4.7). It is `None` when siphon ended the leg itself: a ring
timeout, a B-leg INVITE that never left, a sequence that ended on carriers it
could not dial, or a refusal of the caller's own request.

```python
@b2bua.on_failure
def failed(call, code, reason):
    response = call.failure_response
    if response is None:
        return
    cause = response.get_header("Reason") or ""
    no_audio = response.status_code == 488 and b"m=audio" not in (response.body or b"")
    if no_audio or (response.status_code == 500 and "FAILURE_CAUSE;cause=2" in cause):
        call.dial(cs_breakout_uri(call))
```

Re-routes are capped at 10 per call, so a handler that keeps dialling a target
that keeps failing still ends the call. A decision that cannot apply (a
`reject()` with a 1xx or 2xx, a REFER decision, anything on a call siphon placed
itself) is logged at `warn`, and the call ends with its failure. So does a
handler that raises: a decision taken by a failing handler is not one to route a
call on.

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
- **Never `time.sleep()` in a sync handler.** Ringing before answering is a real
  thing to want — alert the caller, then decide — but a `time.sleep()` in a
  `def` handler pins a pool worker for the whole ring, on every inbound call,
  which is a worse problem than the one it solves. Use an `async def` handler
  and `await asyncio.sleep(...)`: awaiting mid-handler is the supported shape,
  and it is what the same handler already does between `rtpengine.offer` and the
  200. `call.progress()` and `call.answer()` are **imperative** — the response
  goes out where you call them — so the wait sits between them:

  ```python
  @b2bua.on_invite
  async def route(call):
      call.progress(180, "Ringing")     # on the wire here
      await asyncio.sleep(2)            # ring (a B2BUA handler holds its worker here)
      call.handover("ai-app", answer=True, profile="voice_ai")
  ```

  `handover`, `dial` and `reject` are the deferred ones: they are applied when
  the handler returns. If the wait depends on something only an out-of-process
  application knows — a queue position, an agent becoming free, a model
  finishing its load — hand the call over **un-answered** and let the controller
  ring with the control plane's `ring` verb and then connect it with an anchored
  `answer` (see [the control-plane reference](reference/control-plane.md)).

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

### Awaiting in an `async def` handler

An `async def` `@proxy.on_request` handler that awaits does **not** hold a
sync-pool worker for the wait. The worker calls the handler, hands the coroutine
to an async driver and takes the next job; once the coroutine settles, the
remaining handlers for the request and the reply/relay run as a new job on
whichever worker is free. Awaiting a slow downstream (a third-party REGISTER, a
Diameter answer, `asyncio.sleep`) costs a pending coroutine, not a thread, so
the rate of such a handler is bounded by the backend, not by `sync_pool_max`.
Its result is unchanged: the coroutine timeout still fails the request with a
500 and cancels the coroutine, a raise still answers 500, and
`stop_propagation()` called after an await still stops the handlers after it.
`siphon_async_coroutines_pending` counts the awaiting coroutines.

The same holds for the Diameter server handlers (`@diameter.on_request`,
`@diameter.on_reply`, `@diameter.on_request_completed`) and for every handler a
host extension calls through `ScriptHandle::call_handler` (the handlers an
add-on registers under its own kind: HTTP routes, GTP-C messages, peer
events). An awaiting one gives its worker back; the stage it belongs to
continues as a new job once the coroutine settles, and on the coroutine timeout
it is cancelled and fails as before (5012 for `on_request`, `TimeoutError` from
`call_handler`).

The other handler kinds (`@proxy.on_reply` / `on_failure` callbacks, B2BUA
handlers, `@diameter.on_inbound_cer`, built-in timers, SBI callbacks, RTPEngine
events) still hold their worker until the coroutine settles, so for them the
`max_rate` formula above applies to the await as well.

### Where an awaitable API finishes

An awaitable siphon API (`await diameter.cx_uar(...)`, `await cache.fetch(...)`,
`await rtpengine.offer(...)`) runs its Rust half on tokio and then needs the
interpreter once, to build its Python result and wake the coroutine. That last
step runs on two fixed threads named `siphon-await-0` and `siphon-await-1`,
which hold their Python thread state for the life of the process. It is
microseconds of work per call, so two threads carry far more than any
signalling load.

tokio's own blocking pool never runs Python. It grows a thread per concurrent
blocking wait (a peer that stops answering parks one per in-flight request, up
to tokio's ceiling of 512) and reaps them after ten idle seconds; with no
Python on those threads, each costs its stack and nothing more, and a pile-up
of waits no longer brings a Python heap per thread with it. The pile-up itself
still matters: once 512 waits are parked at once, the pool has no thread left
to hand a worker's core to and the runtime stops until some wait ends.
`siphon_blocking_waits_in_flight` is the gauge to alert on.

Extension crates should create their awaitables with
`siphon::script::blocking::awaitable`. One that calls
`pyo3_async_runtimes::tokio::future_into_py` directly still completes on the
blocking pool and sets up a Python thread state per call.

## Backpressure & liveness guarantees

Beyond elasticity, the pool is defended on three more fronts so a misbehaving
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

3. **Process liveness / fail-fast.** The pool watchdog above stays quiet while
   the pool has idle capacity, and a wedge of the *whole process* looks exactly
   like that: when every thread is parked, nothing reads the sockets and
   nothing is queued. A second watchdog judges the process instead, from
   signals that do not depend on the pool:
   - a tokio task that sleeps on a tokio timer and round-trips a loopback
     datagram, so it lands only when the scheduler, the timer driver and the
     I/O driver all turn;
   - tokio's per-worker park counters: more than half of the workers stuck in
     one poll trips, before the last one goes;
   - a thread that attaches to the interpreter and detaches every second, which
     cannot complete while a garbage collection's stop-the-world never ends;
   - the timer sweep, which drives every SIP transaction timer, stamping each
     turn of its Rust part (which never waits for the executor, so a deep
     executor queue is overload, not a wedge).

   Any of them owed for `script.process_stall_abort_secs` (default 30 s; `0`
   disables it, independently of `handler_stall_abort_secs`) writes one line
   to stderr and aborts. The probe's attach wait is published as
   `siphon_interpreter_attach_wait_ms`, so a stop-the-world held open for a
   second or two, far too short to abort over, still shows.

### Never block while attached

On free-threaded CPython a garbage collection stops the world: it waits for
every thread *attached* to the interpreter to reach a safe point. A thread that
blocks in Rust while attached (on a lock, a channel, or a tokio future via
`block_on`) never reaches one. The collection then waits for it for ever, and
every thread that attaches meanwhile parks behind the collection: the executor
workers, the asyncio drivers, and the tokio workers that complete script
awaitables. Once every tokio worker is parked, the future the blocked thread
waits on can never complete, and the process stops with no CPU in use.

siphon keeps every such wait detached:

- The work after an `async def` request handler's await (the reply or relay,
  its DNS lookup, connects, sends) runs detached, as it does on the first pass;
  only the handlers themselves run attached.
- Every blocking wait in the dispatcher and the transport goes through a helper
  that releases the interpreter when the thread holds it, and a source scan in
  the test suite fails any that does not.
- The timer sweep runs the transaction timer wheel (retransmissions, Timer
  B/F/H) on its own tokio task, where nothing attaches, and posts each expiry
  that reaches a script (`@proxy.on_failure` on Timer B/F, `@b2bua.on_failure`
  on a ring timeout, and more) to the executor as a job of its own, never
  awaited. No script handler runs on a tokio worker, one slow handler holds up
  only its own transaction, and a backlog of handlers never stops
  retransmissions or timeouts elsewhere. A branch failure that reaches no
  script is answered on the sweep's task, off the executor; the B2BUA checks
  that can reach a script run as one executor job at a time.
- `siphon_pyexec_queue_wait_ms` reads how long the job a worker last took had
  waited in the queue: under a backlog, the age of the oldest job. Past 5 s it
  is logged as overload.
- The request's action runs on a copy of the request, not under its lock, so a
  script task still holding the request never waits for that lock attached.
- The proxy session's relay callbacks are shared, so the response path copies
  them under the session lock without attaching.

## Metrics (`/metrics`)

| Metric | Meaning |
|--------|---------|
| `siphon_pyexec_pool_size` | live worker threads (grows core→max under load) |
| `siphon_pyexec_pool_max` | configured thread ceiling |
| `siphon_pyexec_inflight` | handlers currently executing |
| `siphon_pyexec_queue_depth` | handler jobs waiting in the queue |
| `siphon_pyexec_jobs_completed_total` | completed handler jobs |
| `siphon_pyexec_jobs_shed_total` | jobs dropped because the queue was full |
| `siphon_async_coroutines_pending` | `async def` handler coroutines on a driver, not yet settled |
| `siphon_interpreter_attach_wait_ms` | how long the liveness probe's last attach to the interpreter waited |
| `siphon_blocking_waits_in_flight` | threads parked right now in a blocking wait through siphon's released helpers; stuck high means a slow backend or a hang |
| `siphon_blocking_waits_total` | blocking waits started through those helpers |
| `siphon_auth_ha1_cache_hits_total` | HTTP-auth lookups served from cache |

**Alert on**: a sustained `rate(siphon_pyexec_jobs_shed_total)` > 0, or
`siphon_pyexec_pool_size == siphon_pyexec_pool_max` with
`siphon_pyexec_inflight == siphon_pyexec_pool_size` held for minutes — both mean
the pool is fully grown and saturated, approaching the watchdog's abort condition.
