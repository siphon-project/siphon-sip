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

The ceiling is never below the core. A `sync_pool_max` smaller than the core is
raised to it and logged as a startup warning: on a 6-CPU node the core is 12, so
`sync_pool_max: 8` alone still runs 12 workers. To cap the pool at 8, set
`sync_pool_size: 8` and `sync_pool_max: 8`.

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
jobs are shed. An initial request that waited in the queue past 8 s is
answered 503 without reaching the script (see
[Backpressure & liveness guarantees](#backpressure--liveness-guarantees)).

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

- **Never `select.select()`.** siphon raises its file limit far above 1024 at
  startup, so a socket a script opens can get a descriptor number past
  `FD_SETSIZE`, and `select.select()` raises `ValueError: filedescriptor out of
  range in select()` on it. Use `selectors.DefaultSelector` (epoll) or
  `asyncio`.

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

### Direct dispatch (`script.direct_dispatch`)

```yaml
script:
  direct_dispatch: on   # default: off
```

By default an `async def` handler that suspends runs as an asyncio task on a
driver, and each `await` of a siphon API goes through an asyncio future: the
Rust future finishes on tokio, a completion thread builds the value and calls
`loop.call_soon_threadsafe`, and the driver's loop resumes the task. The task
itself is created through `asyncio.run_coroutine_threadsafe` and reports back
through a `concurrent.futures.Future`.

With `direct_dispatch: on`, these handlers skip all of that while they await
only siphon's own awaitables:

- `@proxy.on_request` handlers;
- the Diameter server handlers: `@diameter.on_request`, `@diameter.on_reply`
  and `@diameter.on_request_completed`;
- a handler called through `ScriptHandle::call_handler_with` / `call_handler`
  (the handlers an extension registers under its own kind).

Each driver thread has a native runner next to its event loop.
The executor job that called the handler passes the coroutine to the runner
of the driver with the fewest handlers in flight, and from then on that one
thread owns it:

- the runner steps the coroutine, with the handler's own `contextvars`
  context entered and a task object in place as `asyncio.current_task()`;
- an awaited siphon API registers the coroutine as its waiter and the step
  ends;
- the Rust future's completion, on a tokio worker, posts a wake to that
  runner without touching the interpreter. The runner builds the Python value
  and steps the coroutine again.

No asyncio task or future is made, no completion thread is involved, and the
executor only runs the job that calls the handler and the job that finishes
the call. Continuations never wait in the executor queue.

A handler is free to use asyncio at any point. The first time it awaits
something that is not a siphon awaitable (`asyncio.sleep`, a task, a future
from another library), or asks its task for something only a real task
answers (`add_done_callback`, `result()`, being awaited), it is handed over: a
real `asyncio.Task` is created on the same thread and continues the coroutine
where it was. `asyncio.current_task()` is the same object before and after.
The handler is then remembered and starts as a task from its next call, so the
hand-over is paid once per handler, not per call. A script reload forgets.
These do not need a task and keep a handler on the runner: `asyncio.timeout`
and `asyncio.wait_for` around a siphon awaitable, `asyncio.create_task`,
`loop.call_soon` / `call_later`, `task.cancel()`, `task.get_name()` (logging).

What stays the same in both modes: return values and exceptions, context
variables, `handler_timeout_secs` (the coroutine is cancelled once,
`CancelledError` at its await, and the call fails with `TimeoutError`), and
that an awaiting handler holds no executor worker.

Two things a script can see differ while a handler is on the runner. It is
not in `asyncio.all_tasks()`, because no asyncio task exists for it. And a
reference to its task kept past the end of a handler that never became a real
task answers `done()`, `cancelled()` and `get_name()`, but has no `result()`
or `exception()` to give. Inside the handler, and for anything that asks the
task while the handler runs, the task behaves as asyncio's does.

Admission is bounded: a driver takes at most 4096 direct handlers in flight.
A call that finds every driver full is refused at once, without running the
handler, and answered as each kind sheds:

| Handler | A refused call |
|---|---|
| `@proxy.on_request` | `503 Service Unavailable` with `Retry-After: 5` |
| `@diameter.on_request` | `3004 DIAMETER_TOO_BUSY`, with the overload report a requester that advertised DOIC gets |
| `call_handler_with` | `Err`, as a call that was never dispatched |

Every refusal is counted in `siphon_runner_admission_rejected_total` and
logged at most once every five seconds. Nothing waits for room. Only new work
is refused: once a request's first handler was admitted, the handlers that
follow it (a second `@proxy.on_request` handler after the first one's await,
`@diameter.on_reply`, `@diameter.on_request_completed`) always get a place,
because the request has been accepted and has to be finished.

The work after a handler (the SIP reply or relay, the Diameter answer) runs as
one executor job per call, however many awaits the handler made.

#### Several awaits at once: `tasks.gather`

```python
from siphon import diameter, tasks

@diameter.on_request("ULR")
async def on_update_location(request):
    profile, vectors = await tasks.gather(
        load_profile(request),                    # a coroutine of the script
        diameter.send_request(vector_request()),  # a siphon awaitable
    )
    return build_answer(request, profile, vectors)
```

`asyncio.gather` wraps each coroutine in an asyncio task, so a handler that
calls it is handed to asyncio and starts as a task from then on. On a handler
that gathers on every request, that gives back all of what the switch saves.
`tasks.gather(*awaitables, return_exceptions=False)` runs its arguments on the
runner instead:

- a coroutine becomes a second entry on the same driver thread, stepped by the
  same runner, with its own task object and a copy of the handler's context;
- a siphon awaitable is waited on as it is;
- anything else `await` accepts (an asyncio future, a task) is awaited by a
  small coroutine, which is handed to an asyncio task of its own. The handler
  that gathered it stays on the runner. So does the handler of a coroutine
  argument that uses asyncio: only that coroutine becomes a task.

The result is the list of results in argument order. It differs from
`asyncio.gather` in one way, on purpose: **when an argument raises, the others
are cancelled** before the exception reaches the handler (coroutines get
`CancelledError` at their await, a siphon awaitable's request is dropped).
`asyncio.gather` leaves them running with nobody to collect them. With
`return_exceptions=True` nothing is cancelled and an exception is that
argument's result. Cancelling the handler, or its timeout, cancels every
argument still running. On the runner nothing gathered outlives its handler: a
handler that returns with arguments still running has them cancelled, and a
coroutine that ignores the cancellation is closed. The exception is an
argument that uses asyncio and so became an asyncio task: it is cancelled as a
task is, and one that ignores the cancellation runs until it ends by itself.

Where no runner steps the caller (the switch is off, the handler runs as an
asyncio task, or the caller is a task the handler created), `tasks.gather` is
`asyncio.gather` over asyncio tasks with the same cancel-on-failure rule, so a
script behaves the same in every mode. A coroutine argument then starts at the
handler's next await rather than at once. Await the gather in the handler that
made it.

A driver loop with a task factory set (`loop.set_task_factory`) starts every
handler as a task, as with the switch off.

The switch does not affect the handler kinds that hold their worker while a
coroutine runs (`@proxy.on_reply` / `on_failure` callbacks, B2BUA handlers,
`@diameter.on_inbound_cer`, timers, SBI callbacks, RTPEngine events), nor any
`def` handler: the synchronous path is the same code with the switch on or
off. At startup the server drives one handler through a direct step, an await
and a hand-over; if any of it misbehaves on the running interpreter the switch
stays off and the log says so.

## Backpressure & liveness guarantees

Beyond elasticity, the pool is defended on three more fronts so a misbehaving
handler degrades gracefully instead of taking the node down silently:

1. **Bounded queue + load-shed.** When the pool is at its cap and the queue is
   full, new jobs are dropped (the SIP client retransmits) rather than growing
   memory without bound. Counted by `siphon_pyexec_jobs_shed_total`.

   **Age-based shed.** A queue that is not full can still be too slow: when a
   worker picks up an inbound request that waited in the queue longer than
   **8 s**, siphon answers it `503 Service Unavailable` with a `Retry-After`
   and **the script never sees it**. 8 s is 16·T1, a quarter of the client's
   Timer F / Timer B (64·T1 = 32 s): a request that waited longer has too little
   of its client's transaction left for the script, the next hop and the answer
   back, so running it is work spent on an answer that arrives after the
   client gave up and retried into the same queue. The budget is fixed, not
   configurable, because the clock it races is the client's.

   - Only **dialog-initiating and out-of-dialog requests** are shed: requests
     with no To tag, i.e. initial and refresh REGISTER, an initial INVITE or
     SUBSCRIBE, OPTIONS, MESSAGE, PUBLISH. These are new work, and refusing
     them is what drains the queue.
   - **In-dialog requests always run**, however long they queued: anything
     with a To tag, and a BYE whatever it carries. They are the cheap work that
     releases dialogs, media and charging; a shed BYE would leave its dialog
     dangling.
   - **ACK is never answered** and **CANCEL is never shed** (the framework
     answers CANCEL itself, before the script).
   - **Responses, timer expiries and handler continuations are never
     age-shed.** Dropping one would strand a transaction a client is owed an
     answer on; they complete work instead of starting it.
   - The 503 goes through a server transaction like any locally answered
     request: a retransmission is answered from the cached 503 without queueing
     again, the ACK to a shed INVITE is absorbed, and on a P-CSCF the 503
     leaves over the UE's security association.
   - `Retry-After` is the queue wait in seconds (capped at 32) plus a spread of
     up to half that, derived from the Call-ID, so the clients shed together do
     not come back together.
   - Counted by `siphon_pyexec_stale_requests_shed_total{method}`, apart from
     queue-full drops, and logged at WARN at most every 10 s with the queue
     wait and the budget.
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
   - a thread that attaches to the interpreter and detaches every 10 ms, which
     cannot complete while a garbage collection's stop-the-world never ends;
   - the timer sweep, which drives every SIP transaction timer, stamping each
     turn of its Rust part (which never waits for the executor, so a deep
     executor queue is overload, not a wedge).

   Any of them owed for `script.process_stall_abort_secs` (default 30 s; `0`
   disables it, independently of `handler_stall_abort_secs`) writes one line
   to stderr and aborts. The probe's attach waits are published as the
   `siphon_interpreter_attach_wait_seconds` histogram (and the longest of the
   last second as `siphon_interpreter_attach_wait_ms`), so a stop-the-world
   held open for milliseconds, far too short to abort over, still shows. The
   probe runs with `process_stall_abort_secs: 0` as well; only the abort is
   off then.

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
  is logged as overload. `siphon_pyexec_queue_wait_seconds` is the same wait
  for every job, as a histogram.
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
| `siphon_pyexec_stale_requests_shed_total{method}` | initial requests answered 503 without the script because they queued past the 8 s budget |
| `siphon_async_coroutines_pending` | `async def` handler coroutines on a driver, not yet settled |
| `siphon_runner_admission_rejected_total` | requests and calls refused with `script.direct_dispatch: on` because every driver had its limit of handlers in flight (answered 503, 3004 or `Err`) |
| `siphon_pyexec_queue_wait_ms` | how long the job a worker last took had waited in the queue; 0 with the queue empty |
| `siphon_pyexec_queue_wait_seconds` | histogram: how long each job waited in the queue before a worker took it (buckets 100 µs to 13 s) |
| `siphon_interpreter_attach_wait_seconds` | histogram: how long each attach of the liveness probe waited; one sample every 10 ms (buckets 100 µs to 3.3 s) |
| `siphon_interpreter_attach_wait_ms` | the longest of those waits in the last completed one-second window |
| `siphon_python_gc_pause_seconds{generation}` | histogram: wall time of each Python garbage collection (buckets 100 µs to 3.3 s) |
| `siphon_python_gc_collections_total{generation}` | Python garbage collections completed |
| `siphon_python_gc_collected_total{generation}` | unreachable objects those collections freed |
| `siphon_python_gc_uncollectable_total{generation}` | unreachable objects they found and could not free; above 0 is a leak |
| `siphon_python_gc_young_objects` | `gc.get_count()[0]`, read once a second: container objects allocated minus freed since the collector last looked |
| `siphon_python_gc_frozen_objects` | objects `script.gc.freeze_after_load` took out of every later collection; set once at startup, 0 without it |
| `siphon_blocking_waits_in_flight` | threads parked right now in a blocking wait through siphon's released helpers; stuck high means a slow backend or a hang |
| `siphon_blocking_waits_total` | blocking waits started through those helpers |
| `siphon_auth_ha1_cache_hits_total` | HTTP-auth lookups served from cache |

Reading the interpreter metrics:

- **Attach wait** is what every thread that wants the interpreter waits: a
  stop-the-world of any kind on a free-threaded build, the GIL on a GIL build.
  The probe takes one sample every 10 ms, so a stall shows as a single
  observation about as long as what was left of it, among a hundred idle
  samples a second. Read the upper buckets
  (`siphon_interpreter_attach_wait_seconds_bucket{le="0.0512"}` against
  `_count`), not a quantile. A stall shorter than 10 ms can fall between two
  samples.
- **GC pause** is timed from the collector's `start` callback to its `stop`
  callback on the collecting thread. That is the whole collection: the
  stop-the-world phases, then finalizers and the freeing of the garbage, which
  run with the other threads resumed. It is an upper bound on the pause, not
  the pause. A stop-the-world that is not a collection is not in it; the
  attach wait is where that shows.
- **`generation`** is the generation the collection was asked for. A
  free-threaded interpreter scans the whole heap every time: its automatic
  collections report `0`, `gc.collect()` reports `2`.
- **Collected** is the collector's own count. With `gc.DEBUG_SAVEALL` set it
  counts objects it then keeps in `gc.garbage`. **Uncollectable** counts
  unreachable objects with a legacy finalizer, which it also keeps.
- **Collected** over **collections** is what a collection is worth. A node
  whose collections each take tens of milliseconds and free a few hundred
  objects is paying for the walk, not for the garbage: raise
  `script.gc.threshold`. Objects freed by their reference count never reach
  the collector and are in neither counter.
- **Young objects** is not the size of the heap. CPython 3.14 does not expose
  how many objects the collector tracks without a walk of the heap
  (`gc.get_objects()` builds a list of all of them), so siphon does not
  publish it. The young count goes back to 0 at every collection and, on a
  free-threaded build, every time a collection is considered and put off; a
  thread reports its allocations in batches of 512. Read it as how fast
  container objects pile up between collections. The one exact reading of the
  heap is `siphon_python_gc_frozen_objects`, with the freeze on.

## Tuning the garbage collector (`script.gc`)

On a free-threaded interpreter every collection stops every thread and walks
the whole heap, so a collection takes as long as the heap is large, whatever
it frees: about 35 ms for 2 million tracked objects on 3.14.2t. Most of those
objects were built at startup (the standard library, the script's modules, its
tables) and are never freed. Both keys default to leaving CPython alone.

```yaml
script:
  gc:
    freeze_after_load: true
    threshold: 50000
```

The line numbers below are in CPython 3.14.2, `Python/gc_free_threading.c`
unless another file is named.

**`threshold`** is `gc.set_threshold(threshold)`. It sets the first of
CPython's three thresholds and leaves the other two (`Modules/gcmodule.c` line
162); the default is 2000 (line 1588). On a free-threaded build an automatic
collection is considered when the young count exceeds the threshold (line
2091) and is at least a quarter of the unfrozen objects that survived the last
collection (line 2099). It then runs when either

- the young counts set aside since the last collection exceed 40 times the
  threshold (line 2057), or
- the process's RSS plus swap has grown since the last collection by more than
  a tenth, and by more than 128 KiB (lines 2066-2068).

Otherwise the young count is set aside and starts again from 0 (lines
2077-2079). So the threshold is the floor under which nothing is considered,
and 40 times it is what must have been set aside before a node whose memory is
steady collects anyway: 80,000 with the default, 2 million with
`threshold: 50000`. Neither is an interval. The quarter-of-survivors rule
comes first, so an unfrozen heap of 2 million objects is not considered before
500,000 are new, whatever the threshold. The cost of a higher threshold is
that cyclic garbage waits longer to be freed, so RSS between collections is
higher by what those cycles hold; the RSS rule still collects on real growth.
`0` is refused at startup (it turns automatic collection off, line 2091, and
cycles are then freed only by an explicit `gc.collect()`), and so is anything
above 53687091, where `threshold * 40` overflows a C `int`.

**`freeze_after_load`** runs one full collection and then `gc.freeze()` when
the script has loaded and the extensions have started, and logs the number of
objects frozen. A frozen object is still stepped over in the heap walk, but it
is dropped before any traversal or reference-count work (`op_from_block`,
lines 360-374), and the pass that marks everything reachable from the roots is
skipped (lines 2184-2190). Measured on 3.14.2t with 2.1 million tracked
objects, a full collection went from 35 ms to 17 ms: the walk remains, the
work per object goes. (On a GIL build the same heap went from 236 ms to under
0.1 ms, since frozen objects leave the generations altogether.)

Three things to know before turning it on:

- **A frozen cycle is never freed.** Frozen objects are not examined again, so
  objects alive at startup that later become cyclic garbage stay allocated.
  Objects freed by their reference count are freed as before.
- **The freeze happens once, not on a reload.** A reload replaces the script's
  modules; the copy frozen at startup stays allocated after the first reload,
  a one-off cost of the size of the script's own module-level objects. Modules
  built by a reload are not frozen and are collected when the next reload
  replaces them, so this does not grow per reload. Freezing again on each
  reload would strand one copy per reload and would freeze whatever calls
  were in flight.
- **Alone, it makes collections more frequent.** The quarter-of-survivors rule
  counts unfrozen objects only (line 1214). An unfrozen heap of 2 million
  objects keeps the collector quiet until 500,000 objects are new; frozen, it
  no longer does, and the threshold rules above decide alone. Churning 3
  million cyclic objects over a heap of 2.1 million on 3.14.2t took 2
  collections unfrozen, 24 with the freeze alone (shorter each, three times
  the pause in total), and 1 with the freeze and `threshold: 500000`. So set
  `threshold` with the freeze: around a quarter of
  `siphon_python_gc_frozen_objects` restores the floor the frozen heap used
  to give. siphon warns at startup when the freeze is on without a threshold.

Check the effect on `siphon_python_gc_pause_seconds` and on the upper buckets
of `siphon_interpreter_attach_wait_seconds`.

**Alert on**: a sustained `rate(siphon_pyexec_jobs_shed_total)` > 0, or
`siphon_pyexec_pool_size == siphon_pyexec_pool_max` with
`siphon_pyexec_inflight == siphon_pyexec_pool_size` held for minutes — both mean
the pool is fully grown and saturated, approaching the watchdog's abort condition.
