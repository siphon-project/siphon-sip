//! What tokio's blocking pool costs the process when blocking waits pile up.
//!
//! A peer that stops answering parks a thread per in-flight wait: a wait
//! through `blocking_released` on a tokio worker hands the worker's core to a
//! fresh blocking-pool thread, which takes the next message and parks too.
//! Meanwhile awaitable script APIs keep completing (`Deferred`), and a
//! completion needs the interpreter. This drives both, on the runtime the
//! server builds (`siphon::server::build_runtime`, its real thread hooks), under
//! the allocator the server runs on, and reads what the kernel and CPython say:
//! threads and resident memory from `/proc/self/status`, live and created
//! Python thread states from the interpreter.
//!
//! Its own test binary so jemalloc governs the whole process (the lib test
//! binary runs on the system allocator), and so nothing else runs in the
//! process while it measures it.
#![allow(clippy::disallowed_methods)] // test code may block

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use pyo3::prelude::*;
use pyo3::types::{PyCFunction, PyDict, PyTuple};

siphon::install_allocator!();

/// Workers, as a small node runs: the cascade is about the blocking pool.
const WORKERS: usize = 4;
/// Short, so a churn cycle (burst, then the pool reaped) takes seconds. The
/// server uses tokio's 10 s default; what is measured is the same.
const KEEP_ALIVE: Duration = Duration::from_millis(300);

/// One `/proc/self/status` reading.
#[derive(Clone, Copy, Debug, Default)]
struct Status {
    threads: u64,
    rss_kib: u64,
}

fn status() -> Status {
    let text = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let field = |name: &str| {
        text.lines()
            .find_map(|line| line.strip_prefix(name))
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0)
    };
    Status {
        threads: field("Threads:"),
        rss_kib: field("VmRSS:"),
    }
}

/// User + system CPU time of the process, in clock ticks.
fn cpu_ticks() -> u64 {
    let text = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    // Fields after the parenthesised command name; utime and stime are the
    // 14th and 15th fields of the whole line.
    let after = text.rsplit_once(')').map_or("", |(_, rest)| rest);
    let fields: Vec<&str> = after.split_whitespace().collect();
    let parse = |index: usize| {
        fields
            .get(index)
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0)
    };
    parse(11) + parse(12)
}

/// Threads by name (`/proc/self/task/*/comm`), to say what the threads are.
fn thread_names() -> BTreeMap<String, usize> {
    let mut names = BTreeMap::new();
    if let Ok(entries) = std::fs::read_dir("/proc/self/task") {
        for entry in entries.flatten() {
            let name = std::fs::read_to_string(entry.path().join("comm")).unwrap_or_default();
            *names.entry(name.trim().to_string()).or_insert(0) += 1;
        }
    }
    names
}

/// Python thread states alive right now, and the id the next new one gets
/// (CPython numbers them in creation order, so the difference between two
/// readings is how many were created in between). Read from the test thread,
/// which holds its own thread state for the whole run.
fn python_thread_states() -> (usize, i64) {
    Python::attach(|_python| {
        // SAFETY: attached. The list is walked only while the pool is idle
        // (between bursts), so no thread state is created or destroyed
        // under the walk. The probe state is created and deleted here without
        // ever being made current.
        unsafe {
            let interpreter = pyo3::ffi::PyInterpreterState_Main();
            let mut live = 0;
            let mut state = pyo3::ffi::PyInterpreterState_ThreadHead(interpreter);
            while !state.is_null() {
                live += 1;
                state = pyo3::ffi::PyThreadState_Next(state);
            }
            let probe = pyo3::ffi::PyThreadState_New(interpreter);
            let next_id = pyo3::ffi::PyThreadState_GetID(probe);
            pyo3::ffi::PyThreadState_Clear(probe);
            pyo3::ffi::PyThreadState_Delete(probe);
            (live, next_id)
        }
    })
}

/// The highest `/proc/self/status` reading while it ran.
struct Sampler {
    stop: Arc<AtomicBool>,
    peak_threads: Arc<AtomicU64>,
    peak_rss: Arc<AtomicU64>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Sampler {
    fn start() -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let peak_threads = Arc::new(AtomicU64::new(0));
        let peak_rss = Arc::new(AtomicU64::new(0));
        let thread = {
            let (stop, peak_threads, peak_rss) =
                (stop.clone(), peak_threads.clone(), peak_rss.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let now = status();
                    peak_threads.fetch_max(now.threads, Ordering::Relaxed);
                    peak_rss.fetch_max(now.rss_kib, Ordering::Relaxed);
                    std::thread::sleep(Duration::from_millis(5));
                }
            })
        };
        Self {
            stop,
            peak_threads,
            peak_rss,
            thread: Some(thread),
        }
    }

    fn finish(mut self) -> Status {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            thread.join().expect("sampler joins");
        }
        Status {
            threads: self.peak_threads.load(Ordering::Relaxed),
            rss_kib: self.peak_rss.load(Ordering::Relaxed),
        }
    }
}

/// A gate the parked waits sleep on until the burst is released.
#[derive(Default)]
struct Gate {
    open: Mutex<bool>,
    changed: Condvar,
}

impl Gate {
    fn wait(&self) {
        let mut open = self.open.lock().expect("gate lock");
        while !*open {
            open = self.changed.wait(open).expect("gate wait");
        }
    }

    fn open(&self) {
        *self.open.lock().expect("gate lock") = true;
        self.changed.notify_all();
    }
}

/// An asyncio loop on its own thread, as the script's async drivers run one.
struct Loop {
    event_loop: Py<PyAny>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Loop {
    fn start() -> Self {
        let (sender, receiver) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            Python::attach(|python| {
                let event_loop = python
                    .import("asyncio")
                    .and_then(|asyncio| asyncio.call_method0("new_event_loop"))
                    .expect("event loop");
                sender
                    .send(event_loop.clone().unbind())
                    .expect("loop handed over");
                event_loop.call_method0("run_forever").expect("loop runs");
            });
        });
        let event_loop = receiver.recv().expect("loop starts");
        Self {
            event_loop,
            thread: Some(thread),
        }
    }

    /// Start `count` awaitables on the loop, each a future that sleeps
    /// `delay` on tokio and completes with a `Deferred` dict, as a Diameter or
    /// cache answer does. `completed` counts the conversions.
    fn start_awaitables(&self, count: usize, delay: Duration, completed: &Arc<AtomicUsize>) {
        let completed = completed.clone();
        Python::attach(|python| {
            let callback = PyCFunction::new_closure(
                python,
                None,
                None,
                move |arguments: &Bound<'_, PyTuple>, _keywords: Option<&Bound<'_, PyDict>>| {
                    let python = arguments.py();
                    for index in 0..count {
                        let completed = completed.clone();
                        // A spread of delays, so completions arrive while the
                        // burst holds the pool, not in one clump.
                        let delay = delay.mul_f64(index as f64 / count as f64);
                        siphon::script::blocking::awaitable(python, async move {
                            tokio::time::sleep(delay).await;
                            Ok(siphon::script::Deferred::new(move |python| {
                                let answer = PyDict::new(python);
                                for field in 0..32 {
                                    answer.set_item(format!("avp-{field}"), field)?;
                                }
                                completed.fetch_add(1, Ordering::Relaxed);
                                Ok(answer.into_any())
                            }))
                        })?;
                    }
                    PyResult::Ok(())
                },
            )
            .expect("callback");
            self.event_loop
                .bind(python)
                .call_method1("call_soon_threadsafe", (callback,))
                .expect("scheduled");
        });
    }

    fn stop(mut self) {
        Python::attach(|python| {
            let event_loop = self.event_loop.bind(python);
            let stop = event_loop.getattr("stop").expect("stop");
            event_loop
                .call_method1("call_soon_threadsafe", (stop,))
                .expect("stop scheduled");
        });
        if let Some(thread) = self.thread.take() {
            Python::attach(|python| python.detach(|| thread.join().expect("loop joins")));
        }
    }
}

/// Wait, released from the interpreter, until `done` holds or `limit` passes.
fn wait_until(limit: Duration, done: impl Fn() -> bool + Send + Sync) -> bool {
    Python::attach(|python| {
        python.detach(|| {
            let deadline = Instant::now() + limit;
            while !done() {
                if Instant::now() > deadline {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            true
        })
    })
}

/// What one burst did.
#[derive(Debug)]
struct Burst {
    parked_while_held: usize,
    completed_while_held: usize,
    peak: Status,
    idle: Status,
    live_states: usize,
    created_states: i64,
    cpu_ticks: u64,
}

/// `waits` blocking waits parked on tokio workers through
/// `blocking_released`, with `completions` awaitables completing while they
/// hold the pool; then the waits released and the pool left idle past its
/// keep-alive.
fn burst(
    runtime: &'static tokio::runtime::Runtime,
    event_loop: &Loop,
    waits: usize,
    completions: usize,
) -> Burst {
    let (_, first_id) = python_thread_states();
    let cpu_before = cpu_ticks();
    let sampler = Sampler::start();

    let gate = Arc::new(Gate::default());
    let parked = Arc::new(AtomicUsize::new(0));
    let finished = Arc::new(AtomicUsize::new(0));
    for _ in 0..waits {
        let (gate, parked, finished) = (gate.clone(), parked.clone(), finished.clone());
        runtime.spawn(async move {
            siphon::script::blocking::blocking_released(|| {
                parked.fetch_add(1, Ordering::Relaxed);
                gate.wait();
            });
            finished.fetch_add(1, Ordering::Relaxed);
        });
    }
    let completed = Arc::new(AtomicUsize::new(0));
    event_loop.start_awaitables(completions, Duration::from_millis(400), &completed);
    // Hold the waits while the completions arrive, as a peer that has gone
    // quiet holds them, then let them go.
    std::thread::sleep(Duration::from_millis(600));
    let completed_while_held = completed.load(Ordering::Relaxed);
    let parked_while_held = parked.load(Ordering::Relaxed);
    gate.open();
    let all_finished = wait_until(Duration::from_secs(60), || {
        finished.load(Ordering::Relaxed) == waits
    });
    let all_completed = wait_until(Duration::from_secs(60), || {
        completed.load(Ordering::Relaxed) == completions
    });
    let peak = sampler.finish();
    let cpu_ticks = cpu_ticks().saturating_sub(cpu_before);
    assert!(
        all_completed,
        "{} of {completions} awaitables completed",
        completed.load(Ordering::Relaxed)
    );
    assert!(
        all_finished,
        "{} of {waits} waits finished",
        finished.load(Ordering::Relaxed)
    );

    // Past the keep-alive, so the pool reaps what the burst grew.
    std::thread::sleep(KEEP_ALIVE * 4);
    let idle = status();
    let (live_states, next_id) = python_thread_states();
    Burst {
        parked_while_held,
        completed_while_held,
        peak,
        idle,
        live_states,
        // Minus the probe of the first reading.
        created_states: next_id - first_id - 1,
        cpu_ticks,
    }
}

#[test]
fn blocking_pool_footprint_is_bounded_and_flat() {
    Python::initialize();
    // Hold this thread's own thread state for the run, as siphon's threads do,
    // so the readings below don't each create and destroy one.
    // SAFETY: once, on this thread, before it attaches; never released (the
    // process ends with the test).
    unsafe {
        pyo3::ffi::PyGILState_Ensure();
        pyo3::ffi::PyEval_SaveThread();
    }
    let runtime = siphon::server::build_runtime(|builder| {
        builder
            .worker_threads(WORKERS)
            .thread_keep_alive(KEEP_ALIVE);
    })
    .expect("runtime builds");
    let event_loop = Loop::start();
    // Let the workers start and park once.
    std::thread::sleep(KEEP_ALIVE * 2);

    let baseline = status();
    let (baseline_states, _) = python_thread_states();
    eprintln!("baseline: {baseline:?}, {baseline_states} python thread states");
    eprintln!("baseline threads: {:?}", thread_names());

    // Warm-up: first-touch growth (jemalloc arenas, CPython caches) outside
    // the measured bursts.
    let warm = burst(runtime, &event_loop, 64, 256);
    eprintln!("warm-up: {warm:?}");

    // 1. One burst of 2000 parked waits and 2000 completions.
    const WAITS: usize = 2000;
    const COMPLETIONS: usize = 2000;
    let big = burst(runtime, &event_loop, WAITS, COMPLETIONS);
    eprintln!(
        "burst of {WAITS} waits + {COMPLETIONS} completions: {} parked and {} \
         completed while held, {big:?}",
        big.parked_while_held, big.completed_while_held
    );

    // 2. Churn: the pool grown and reaped, over and over.
    const CYCLES: usize = 20;
    const CYCLE_WAITS: usize = 200;
    const CYCLE_COMPLETIONS: usize = 1000;
    let mut cycles = Vec::with_capacity(CYCLES);
    for cycle in 0..CYCLES {
        let result = burst(runtime, &event_loop, CYCLE_WAITS, CYCLE_COMPLETIONS);
        eprintln!(
            "cycle {cycle:2}: peak {} threads / {} MiB, idle {} threads / {} MiB, \
             {} live python states, {} created, {} cpu ticks",
            result.peak.threads,
            result.peak.rss_kib / 1024,
            result.idle.threads,
            result.idle.rss_kib / 1024,
            result.live_states,
            result.created_states,
            result.cpu_ticks,
        );
        let runaway = result.idle.rss_kib > baseline.rss_kib + 4 * 1024 * 1024;
        cycles.push(result);
        // Don't take the box down measuring the leak this guards against.
        if runaway {
            break;
        }
    }
    eprintln!("idle threads after churn: {:?}", thread_names());

    // 3. A trickle: grow the pool with a burst, then keep completions coming
    // at a steady rate, as a node's background traffic does after the load.
    let trickle_growth = burst(runtime, &event_loop, 300, 16);
    let completed = Arc::new(AtomicUsize::new(0));
    let trickle_start = Instant::now();
    let mut sent = 0;
    while trickle_start.elapsed() < KEEP_ALIVE * 8 {
        event_loop.start_awaitables(1, Duration::ZERO, &completed);
        sent += 1;
        std::thread::sleep(Duration::from_millis(2));
    }
    let trickle = status();
    let trickle_names = thread_names();
    wait_until(Duration::from_secs(30), || {
        completed.load(Ordering::Relaxed) == sent
    });
    eprintln!(
        "trickle of {sent} completions over {:?} after a burst to {} threads: \
         {} threads at its end {trickle_names:?}",
        trickle_start.elapsed(),
        trickle_growth.peak.threads,
        trickle.threads
    );
    event_loop.stop();

    let first = &cycles[2.min(cycles.len() - 1)];
    let last = cycles.last().expect("a cycle ran");
    let growth_kib = last.idle.rss_kib.saturating_sub(first.idle.rss_kib);
    let created: i64 = cycles.iter().map(|cycle| cycle.created_states).sum();

    // After the warm-up: the completion threads and every first-touch cost
    // are in.
    let settled = warm.idle;
    let settled_states = warm.live_states;

    // Flat: what a churn cycle leaves behind does not accumulate.
    assert!(
        cycles.len() == CYCLES && growth_kib < 32 * 1024,
        "idle RSS grew {} MiB from cycle 2 to cycle {} under blocking-pool churn",
        growth_kib / 1024,
        cycles.len() - 1,
    );
    // Bounded: the pool's thread count is tokio's ceiling (512 blocking
    // threads plus the workers)...
    assert!(
        big.peak.threads <= settled.threads + 512 + WORKERS as u64,
        "{} threads at the peak of {WAITS} parked waits",
        big.peak.threads
    );
    // ...and 2000 parked waits cost the process what their threads cost, not a
    // Python thread state and heap each. Measured (debug build, free-threaded
    // 3.14): +57 MiB with completions on the fixed threads, +160 MiB when every
    // blocking thread was pinned and ran them.
    let burst_growth_kib = big.peak.rss_kib.saturating_sub(settled.rss_kib);
    assert!(
        burst_growth_kib < 112 * 1024,
        "{WAITS} parked waits and {COMPLETIONS} completions grew RSS by {} MiB",
        burst_growth_kib / 1024
    );
    // Back to where it settled: no thread or thread state outlives its burst.
    assert!(
        last.idle.threads <= settled.threads,
        "{} threads idle after churn, {} settled",
        last.idle.threads,
        settled.threads
    );
    assert!(
        last.live_states <= settled_states,
        "{} python thread states idle after churn, {settled_states} settled",
        last.live_states
    );
    // A trickle of completions does not hold the burst's threads alive.
    assert!(
        trickle.threads <= settled.threads,
        "{} threads after 8 keep-alives of a completion trickle, {} settled",
        trickle.threads,
        settled.threads
    );
    // No thread state per completion or per pool thread: the completions ran
    // on threads that keep theirs. What is left is a worker pinned again after
    // `block_in_place` handed its core to a fresh thread, a few per cycle
    // (measured 4-6; it was one per blocking thread the pool started, ~206 a
    // cycle, when every blocking thread was pinned).
    assert!(
        created <= (cycles.len() * WORKERS * 2) as i64,
        "{created} python thread states created over {} cycles of {CYCLE_WAITS} waits \
         and {CYCLE_COMPLETIONS} completions",
        cycles.len()
    );
}
