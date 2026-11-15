# Direct dispatch soak

A development note. It says what the dispatch soak harness
(`src/script/dispatch_soak_bench_tests.rs`) measures, how to run it, and what it
found when pointed at the direct awaitable dispatch of #864 to #866, which #870
backed out.

Nothing here is operator documentation. It is the measurement record behind a
design decision, kept next to the code so the next attempt starts from numbers.

## Why a soak and not the microbench

Direct dispatch stepped an `async def` handler that awaits only siphon's own
awaitables on the Python executor, with no asyncio task. A per-handler
microbench put it at 3 to 5 times less CPU per call. An end-to-end A/B on
CPU-limited nodes then showed the interpreter attach wait peaking 10 to 40
times higher, the executor pool full with 22 to 25 jobs in flight where it had
2 to 7, ten times the pending coroutines, and a quarter less goodput.

The microbench could not have seen that. Its awaitables mostly finished before
the handler suspended, its heap was empty, a case ran for 3 seconds, nothing
timed an attach, the handlers did no work between awaits, and it had every CPU
of the machine.

The soak changes each of those: every await suspends on a log-normal delay,
arrivals are open loop, 30 % of the load is sync handlers that block released,
the script keeps a live heap that changes, and a thread of its own times an
attach every millisecond.

## Running it

Build the test binary on free-threaded Python and run the one ignored test by
name:

```text
PYO3_PYTHON=python3.14t cargo test --release --lib --no-run
taskset -c 0-5 target/release/deps/siphon-<hash> --ignored --nocapture \
    --test-threads=1 script::dispatch_soak_bench_tests::dispatch_soak
```

Everything is set by `SOAK_*` environment variables, listed at the top of the
file. The run that matters is the one under a CPU quota:

```text
SOAK_RATE=300 SOAK_WORK=1100 SOAK_HEAP_MB=0 SOAK_SECONDS=120 \
    systemd-run --user --scope -p CPUQuota=100% taskset -c 0-5 \
    target/release/deps/siphon-<hash> --ignored --nocapture --test-threads=1 \
    script::dispatch_soak_bench_tests::dispatch_soak
```

To compare two commits, cherry-pick the harness commit onto each and build
each into its own binary. Two worktrees sharing one target directory build the
same artifact name, and cargo will hand back the first tree's binary for the
second unless the crate is touched in between, so copy each binary out before
building the next.

## What was measured

Free-threaded CPython 3.14.2, release build, 6 tokio workers, 6 asyncio
drivers, executor sized by `resolve_sizing` with a queue of 1024. "main" is
the tree after #870. "direct" is the tree at #866 with the harness
cherry-picked. One machine, shared with other work, so single figures move by
10 to 20 % between repeats. The outcomes below are not that kind of
difference.

Columns: the attach wait of the pinned 1 ms probe and of the unpinned 100 ms
probe (the one siphon's own liveness probe takes), collector pauses from
`gc.callbacks` (an upper bound, see the CPython notes), the executor's
in-flight mean and final pool size, pending coroutines, goodput (answered
within 2 s), requests shed, and CPU per answered request.

### With all six CPUs: no difference

300 MB heap, no work between awaits, the executor at 12 threads growing to 48.

| run | attach p99 ms | attach max ms | unpinned p99 ms | unpinned max ms | gc n | gc p99 ms | gc max ms | in-flight | pool | pending | goodput /s | shed | CPU us/req |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 150/s main | 0.001 | 302.3 | 0.69 | 252.3 | 4 | 532 | 532 | 1.4 | 39 | 4 | 149 | 0 | 665 |
| 150/s direct | 0.002 | 239.3 | 0.88 | 239.4 | 3 | 437 | 437 | 1.7 | 45 | 4 | 150 | 0 | 540 |
| 300/s main | 0.002 | 347.7 | 0.58 | 328.8 | 7 | 659 | 659 | 2.8 | 48 | 8 | 300 | 0 | 545 |
| 300/s direct | 0.002 | 304.8 | 0.56 | 271.0 | 7 | 557 | 557 | 3.4 | 48 | 8 | 301 | 0 | 393 |
| 600/s main | 0.000 | 262.2 | 0.59 | 234.8 | 3 | 512 | 512 | 5.2 | 48 | 15 | 599 | 0 | 267 |
| 600/s direct | 0.002 | 292.1 | 0.64 | 245.1 | 3 | 557 | 557 | 5.4 | 48 | 15 | 597 | 0 | 230 |

Here direct dispatch gives the same service for 14 to 28 % less CPU. That is
the direction the microbench showed and a small part of its 3 to 5 times:
a request here is more than its awaits. The attach wait peaks at the length of a full collection of the 300 MB
heap in both, because that is the only long stop-the-world either has.

### Under a one-CPU quota: main carries the load, direct can tip over

`CPUQuota=100%`, no heap to speak of, `SOAK_WORK=1100` (about 1.2 ms of Python
per request spread over its steps). The quota sizes the executor at 4 threads
growing to 32. Runs of 120 s; runs 3 and 4 are 90 s and the 600 per second
pair 60 s.

| run | attach p99 ms | attach max ms | unpinned p99 ms | unpinned max ms | gc n | gc p99 ms | gc max ms | in-flight | pool | pending | goodput /s | shed | CPU us/req |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 150/s main | 0.003 | 12.6 | 0.65 | 1.3 | 2 | 28 | 28 | 1.1 | 8 | 4 | 149 | 0 | 1798 |
| 150/s direct | 0.003 | 11.0 | 0.62 | 4.3 | 2 | 21 | 21 | 1.6 | 8 | 4 | 152 | 0 | 1623 |
| 300/s main | 0.001 | 19.6 | 0.61 | 9.4 | 4 | 44 | 44 | 2.6 | 12 | 8 | 300 | 0 | 1571 |
| 300/s direct | 0.004 | 2989.0 | 1.31 | 605.9 | 5 | 5820 | 5820 | 32.0 | 32 | 1166 | 131 | 744 | 3390 |
| 300/s main, run 2 | 0.003 | 16.3 | 0.62 | 2.6 | 4 | 44 | 44 | 3.1 | 16 | 8 | 300 | 0 | 1772 |
| 300/s direct, run 2 | 0.005 | 192.8 | 3.58 | 102.3 | 4 | 891 | 891 | 31.8 | 32 | 1381 | 119 | 663 | 3384 |
| 300/s main, run 3 | 0.002 | 16.7 | 0.60 | 1.5 | 3 | 45 | 45 | 2.7 | 13 | 8 | 298 | 0 | 1811 |
| 300/s direct, run 3 | 0.003 | 17.0 | 0.62 | 16.8 | 3 | 42 | 42 | 2.8 | 19 | 8 | 300 | 0 | 1976 |
| 300/s direct, run 4 | 0.002 | 14.0 | 0.61 | 5.7 | 3 | 39 | 39 | 3.0 | 14 | 8 | 299 | 0 | 1757 |
| 600/s main | 0.005 | 137.5 | 38.14 | 128.8 | 6 | 2297 | 2297 | 16.9 | 32 | 13746 | 180 | 0 | 1660 |
| 600/s direct | 0.004 | 213.1 | 3.26 | 109.4 | 3 | 1181 | 1181 | 31.8 | 32 | 1168 | 82 | 19722 | 3686 |
| 300/s main, 300 MB heap | 0.004 | 439.1 | 1.21 | 381.1 | 5 | 1011 | 1011 | 7.5 | 32 | 11232 | 89 | 0 | 3365 |
| 300/s direct, 300 MB heap | 0.005 | 238.0 | 0.30 | 228.0 | 2 | 714 | 714 | 32.0 | 32 | 1890 | 12 | 18803 | 6893 |

At 150 per second both are healthy and alike. At 300 per second main uses
about half the quota and answers everything, in every run. Direct either does
the same, or tips into a second state and stays in it: every executor thread
busy, a queue wait above a second, over a thousand coroutines pending,
requests shed, twice the CPU per request, collector pauses of seconds where
main has 44 ms, and the attach wait peaking 12 and 150 times higher on the
pinned probe in the first two pairs (39 and 64 times on the unpinned one).
The p99 of the pinned probe does not move in any run: the stalls are a
handful of long ones, not many short ones.

It tipped in the first two runs and not in the next two. Counting the control
runs of the next section, the unchanged direct tree tipped in 4 of 8 runs at
this load, and main in none. So the ratio is not a steady property of direct
dispatch. It is what the collapsed state looks like, and at this load a run
of a minute or two enters it about half the time.

At 600 per second both are past the quota, and they fail differently: main
sheds nothing and queues without bound on its drivers, direct fills the
executor queue and sheds. With a 300 MB heap under the same quota (last two
rows) the load is past what main carries too, so that pair says nothing about
the two paths.

### One variable at a time

All at 300 per second under the one-CPU quota, 90 s (the first two unchanged
runs 120 s), on the direct tree with one change each. Throwaway patches, not
in this repository. A run counts as collapsed when its mean in-flight is
above 16.

| variant | runs | collapsed | in-flight | attach max ms | goodput /s | CPU us/req |
|---|---:|---:|---:|---:|---:|---:|
| main | 3 | 0 | 2.6 to 3.1 | 16 to 20 | 298 to 300 | 1571 to 1811 |
| direct, unchanged | 8 | 4 | 2.7 to 32.0 | 14 to 2989 | 89 to 302 | 1757 to 3583 |
| 1: continuations on their own lane (4, 12 or 32 threads) | 5 | 0 | 2.5 to 3.0 | 10 to 19 | 298 to 301 | 1523 to 1997 |
| 2: each coroutine pinned to one lane thread (4 or 12) | 2 | 0 | 2.5 to 2.8 | 10 to 10 | 299 to 302 | 1384 to 1415 |
| 3: executor max 8 | 4 | 0 | 2.7 to 3.0 | 11 to 20 | 300 to 300 | 1512 to 1860 |
| 3: executor core 12 instead of 4 | 3 | 1 | 2.7 to 45.0 | 16 to 111 | 181 to 301 | 1843 to 3332 |
| 4: attached teardown | 3 | 1 | 2.9 to 31.9 | 12 to 84 | 134 to 302 | 1608 to 3343 |
| 6: no asyncio-using handler | 1 | 1 | 31.8 | 97 | 76 | 3883 |

Every run, for the detail:

| run | attach p99 ms | attach max ms | unpinned p99 ms | unpinned max ms | gc n | gc p99 ms | gc max ms | in-flight | pool | pending | goodput /s | shed | CPU us/req |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| unchanged | 0.005 | 119.5 | 2.10 | 93.2 | 4 | 4207 | 4207 | 27.2 | 32 | 1070 | 134 | 262 | 3132 |
| unchanged | 0.003 | 14.4 | 0.55 | 1.1 | 3 | 42 | 42 | 3.0 | 17 | 8 | 302 | 0 | 2068 |
| unchanged | 0.002 | 18.0 | 0.59 | 1.1 | 3 | 35 | 35 | 2.7 | 12 | 8 | 296 | 0 | 1817 |
| unchanged | 0.005 | 189.3 | 3.27 | 106.8 | 3 | 1406 | 1406 | 32.0 | 32 | 1426 | 89 | 2214 | 3583 |
| 1: lane, 4 threads | 0.001 | 10.0 | 0.83 | 5.2 | 3 | 25 | 25 | 2.8 | 12 | 8 | 301 | 0 | 1523 |
| 1: lane, 4 threads | 0.002 | 11.7 | 0.69 | 1.2 | 3 | 27 | 27 | 2.7 | 12 | 8 | 298 | 0 | 1659 |
| 1: lane, 12 threads | 0.001 | 15.8 | 0.72 | 7.7 | 3 | 27 | 27 | 2.8 | 14 | 8 | 300 | 0 | 1532 |
| 1: lane, 32 threads | 0.003 | 15.3 | 0.61 | 1.8 | 3 | 31 | 31 | 3.0 | 10 | 8 | 299 | 0 | 1895 |
| 1: lane, 32 threads | 0.002 | 19.4 | 0.62 | 1.5 | 3 | 37 | 37 | 2.5 | 10 | 8 | 299 | 0 | 1997 |
| 2: pinned, 12 threads | 0.001 | 10.0 | 0.77 | 0.9 | 3 | 28 | 28 | 2.8 | 14 | 8 | 299 | 0 | 1415 |
| 2: pinned, 4 threads | 0.001 | 10.3 | 0.65 | 2.4 | 3 | 37 | 37 | 2.5 | 10 | 8 | 302 | 0 | 1384 |
| 3: executor max 8 | 0.002 | 14.3 | 0.60 | 1.2 | 3 | 33 | 33 | 2.7 | 8 | 8 | 300 | 0 | 1512 |
| 3: executor max 8 | 0.003 | 19.7 | 0.73 | 2.1 | 3 | 34 | 34 | 2.8 | 8 | 8 | 300 | 0 | 1860 |
| 3: executor max 8 | 0.002 | 15.0 | 0.48 | 0.7 | 3 | 32 | 32 | 2.7 | 8 | 8 | 300 | 0 | 1742 |
| 3: executor max 8 | 0.002 | 11.2 | 0.62 | 2.4 | 3 | 32 | 32 | 3.0 | 8 | 8 | 300 | 0 | 1636 |
| 3: executor core 12 | 0.002 | 16.8 | 0.59 | 4.6 | 3 | 38 | 38 | 2.8 | 18 | 8 | 297 | 0 | 1866 |
| 3: executor core 12 | 0.005 | 110.7 | 2.21 | 112.0 | 3 | 4701 | 4701 | 45.0 | 48 | 1099 | 181 | 0 | 3332 |
| 3: executor core 12 | 0.002 | 16.2 | 0.60 | 3.8 | 3 | 48 | 48 | 2.7 | 13 | 8 | 301 | 0 | 1843 |
| 4: attached teardown | 0.001 | 15.2 | 0.80 | 0.9 | 3 | 26 | 26 | 2.9 | 19 | 8 | 301 | 0 | 1608 |
| 4: attached teardown | 0.001 | 12.5 | 0.61 | 7.0 | 3 | 36 | 36 | 3.2 | 14 | 8 | 302 | 0 | 1647 |
| 4: attached teardown | 0.004 | 83.9 | 0.62 | 16.6 | 3 | 116 | 116 | 31.9 | 32 | 1026 | 134 | 99 | 3343 |
| 5: asyncio-only handlers, main | 0.000 | 11.4 | 0.61 | 0.8 | 3 | 29 | 29 | 2.6 | 13 | 7 | 297 | 0 | 1098 |
| 5: asyncio-only handlers, direct | 0.001 | 13.8 | 0.62 | 1.3 | 3 | 36 | 36 | 2.7 | 11 | 7 | 301 | 0 | 1303 |
| 5: asyncio-only handlers, direct, stock loop class | 0.001 | 13.0 | 0.65 | 2.2 | 3 | 33 | 33 | 2.9 | 16 | 7 | 300 | 0 | 1321 |
| 6: no asyncio-using handler | 0.005 | 96.9 | 0.64 | 81.1 | 3 | 498 | 498 | 31.8 | 32 | 803 | 76 | 4030 | 3883 |

Three more pairs away from that operating point:

| run | attach p99 ms | attach max ms | unpinned p99 ms | unpinned max ms | gc n | gc p99 ms | gc max ms | in-flight | pool | pending | goodput /s | shed | CPU us/req |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 7: 500 MB heap, 300/s, main | 0.004 | 454.0 | 0.64 | 360.9 | 3 | 1195 | 1195 | 8.1 | 32 | 9072 | 89 | 0 | 3348 |
| 7: 500 MB heap, 300/s, direct | 0.003 | 192.2 | 0.60 | 190.2 | 1 | 709 | 709 | 32.0 | 32 | 1537 | 0 | 16613 | 8551 |
| 7: 500 MB heap, 150/s, main | 0.003 | 414.5 | 0.80 | 385.0 | 3 | 1310 | 1310 | 2.1 | 32 | 110 | 123 | 0 | 4419 |
| 7: 500 MB heap, 150/s, direct | 0.004 | 400.4 | 0.62 | 362.2 | 3 | 1196 | 1196 | 26.2 | 32 | 850 | 69 | 0 | 5972 |
| no quota, executor core 4, main | 0.002 | 13.8 | 0.61 | 0.9 | 3 | 42 | 42 | 2.6 | 10 | 8 | 300 | 0 | 1802 |
| no quota, executor core 4, direct | 0.003 | 20.3 | 0.63 | 1.4 | 3 | 32 | 32 | 2.7 | 12 | 8 | 295 | 0 | 1872 |

## Reading it

With half the unchanged runs healthy, one healthy run of a variant says
little. What follows leans on the counts: if a change did nothing, 7 healthy
runs in a row would turn up about once in a hundred tries, and 4 about once
in sixteen.

**Continuations in the shared executor queue are what lets it tip.** With
continuations on threads of their own, direct dispatch did not collapse in 7
runs out of 7, whether the lane had 4, 12 or 32 threads and whether or not a
coroutine kept to one of them. In the shared queue a continuation waits
behind sync handlers that hold a worker for 5 to 50 ms and behind new
arrivals, on a pool that starts at 4 threads. On main a continuation never
enters that queue: it runs on an asyncio driver.

**The pool growing far past the CPUs is what keeps it down.** With the
executor capped at 8 threads and the queue still shared, it did not collapse
in 4 runs out of 4. Starting the pool at 12 instead of 4 did not prevent it
(1 of 3 collapsed, at 45 in flight of 48), because the pool can still grow.
The executor adds threads while there is a backlog and never takes one away,
so one bad moment leaves 32 threads running handler Python on one CPU's worth
of quota, and from there the CPU per request doubles and the backlog cannot
drain. main cannot get there: a suspended handler's Python runs on the
asyncio drivers, and there are only `script.async_pool_size` of those.

Why that many runnable attached threads is so costly was measured apart from
siphon, in plain free-threaded Python on six CPUs: one stop-the-world took
about 30 microseconds with 2 busy threads, between 0.03 and 0.7 ms with 6,
and 13 to 28 ms with 24. A stop-the-world has to wait for every attached
thread to reach a safe point, and a thread that is runnable but not running
reaches none. Under a quota a throttled thread is exactly that, for up to a
period. The collector pauses above say the same thing: 44 ms on main, 0.1 to
5.8 s on collapsed direct, for the same small heap.

**Thread hopping and teardown: no effect shown.** Pinning each coroutine's
continuations to one thread did no better than a shared lane, which already
did not collapse. Letting go of a finished coroutine's Python objects
attached, on the thread that ran its last step, instead of from a released
thread through pyo3's deferred-decref pool, collapsed in 1 run of 3. That is
not distinguishable from the unchanged tree.

**A stop-the-world that is not the collector's was not needed.** Without any
asyncio-using handler direct dispatch collapsed the same way. The
cross-thread task stop-the-world is real (next section), but with a handler
remembered as an asyncio user after its first call it happens once per
handler, not once per call.

**The driver loop subclass costs nothing measurable.** With asyncio-only
handlers nothing is driven directly and all three builds are healthy. The
direct tree costs the same CPU with its loop subclass as with the stock loop
class, about a fifth more than main either way, in single runs.

**Heap size sets the floor of the attach wait, not the collapse.** Both
trees stop for a full collection, and that pause grows with the live heap:
about 10 to 20 ms with no heap, 240 to 350 ms with 300 MB on six CPUs, 400 ms
with 500 MB under the quota. With a large heap main's own peak is therefore
as high as direct's and the attach wait no longer tells them apart, while
in-flight, pending coroutines and goodput still do (the 500 MB pair at 150
per second).

**Without the quota it did not happen.** The same load with the same 4-thread
pool and all six CPUs was healthy on both trees, in one run each.

## CPython notes

Read in the 3.14.8 sources; the same code is in 3.14.2, which the runs used.

- **`gc.callbacks` brackets the whole collection.** In
  `Python/gc_free_threading.c`, `gc_collect_main` calls the callbacks with
  `"start"` before `gc_collect_internal` and with `"stop"` after it. Inside,
  the world is stopped twice (refcount merge, marking, finding the unreachable
  set, clearing weak references; then, after finalizers have run with the
  world started, resurrection handling and free lists), and the garbage is
  deleted with the world running. So a callback timing is an upper bound on
  the stop-the-world, and on a starved process it also counts the time the
  collecting thread spent waiting for a CPU.
- **A task that finishes on another thread than it was made on stops the
  world.** In `Modules/_asynciomodule.c`, `Task.__init__` records the creating
  thread, and `unregister_task` stops the world to unlink the task when the
  calling thread is a different one. `future_schedule_callbacks` calls it when
  a task finishes, and `TaskObj_dealloc` calls it again when the task is
  freed. Measured: about 1 microsecond per task finished on its own thread, 25
  to 670 microseconds on another one with 2 to 6 busy threads. Dropping the
  last reference to a finished task on another thread did not show that cost
  in the same test (0.02 to 0.03 microseconds per task). The likely reason is
  that the object is handed back to its owning thread to free, which was not
  checked in the source.
- **`_swap_current_task` takes any object.** It checks that the given loop is
  the calling thread's running loop and stores the object. Nothing requires an
  `asyncio.Task`.
- **`current_task(loop)` for another thread's loop stops the world**, to walk
  the threads. The fast path is the calling thread's own running loop.
- **When a collection starts.** The young count has to pass both the
  threshold and a quarter of the live objects at the last collection, and then
  either the process has grown by a tenth since, or 40 thresholds' worth of
  new objects have been deferred. A large live heap therefore collects
  rarely, and each collection is a full one.

## Limits of this record

- One machine, not a quiet one, and runs of a minute or two. The collapse is
  an event that a run has or does not have, so the variant counts are small
  samples. Where a row is a single run, it says so.
- The quota run sits at half of what main carries on this machine when the
  machine has cores to spare. With every core busy elsewhere (load average
  above 40) a short main run used the whole quota and fell behind too, so
  the pairs are only comparable when taken under similar load. The four
  unchanged direct runs that collapsed started at a load average of 4 to 11,
  and three of the four that stayed healthy at 25 to 51. Eight runs do not
  settle whether a busy machine makes the collapse less likely (a process
  that cannot burn its quota in a burst is throttled less), so that is an
  observation, not a finding.
- The attach wait separates only once direct dispatch has collapsed. Below
  that point the two trees have the same attach wait, and the harness shows
  no steady 10 to 40 times ratio on a healthy node.
- The quota is applied from outside (`systemd-run`). The harness prints the
  quota it runs under but does not set one.
- The session heap and the work between awaits are a model. A script that
  holds a lock or calls a blocking API between awaits will sit elsewhere on
  the same curve.
