//! Process liveness, judged from outside the Python executor.
//!
//! The executor's own watchdog (`py_executor::run_watchdog`) only acts when the
//! pool is full and work is queued behind it, so that a node with idle capacity
//! is never aborted over one wedged handler. A wedge of the whole process
//! leaves neither: a garbage collection's stop-the-world that never completes
//! parks every thread that attaches to the interpreter, the tokio workers among
//! them, so nothing reads the sockets, nothing is queued, and the pool looks
//! idle while the node serves nothing.
//!
//! Four signals cover that, none of them dependent on the pool's size or fill:
//!
//! * **tokio**: a task spawned onto the runtime that sleeps on a tokio timer and
//!   round-trips a datagram over loopback sockets, so its landing proves the
//!   scheduler, the timer driver and the I/O driver all turn.
//! * **workers**: tokio's per-worker park/unpark counters. A worker that is
//!   neither parked nor has parked again for the whole window is stuck inside
//!   one poll; more than half of them stuck trips, before the last one goes.
//! * **interpreter**: a dedicated thread attaching to the interpreter and
//!   detaching again. It completes unless a stop-the-world never ends. How long
//!   each attach waited is published (`siphon_interpreter_attach_wait_ms`), so a
//!   stop-the-world held open for a second, too short to abort over, still
//!   shows.
//! * **critical loops**: tasks that must keep turning (the timer sweep, which
//!   drives every SIP transaction timer) stamp each turn. One that stops trips
//!   even when the rest of the runtime is fine.
//!
//! When any has been owed for `script.process_stall_abort_secs`, the process
//! writes one line to stderr and aborts so a supervisor restarts it. The
//! watchdog thread only reads atomics and tokio's metrics and spawns the tokio
//! beat; it takes no lock a stuck thread could hold and never touches Python.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use tokio::runtime::Handle as TokioHandle;

/// One heartbeat: how many beats were begun and how many finished.
#[derive(Default)]
pub(crate) struct Beat {
    begun: AtomicU64,
    done: AtomicU64,
}

impl Beat {
    fn begin(&self) {
        self.begun.fetch_add(1, Ordering::AcqRel);
    }

    fn end(&self) {
        self.done.fetch_add(1, Ordering::AcqRel);
    }

    fn done(&self) -> u64 {
        self.done.load(Ordering::Acquire)
    }

    fn outstanding(&self) -> bool {
        self.begun.load(Ordering::Acquire) > self.done()
    }
}

/// What stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stalled {
    /// The tokio beat never landed.
    Tokio,
    /// More than half of the tokio workers stuck in one poll.
    Workers { stuck: usize, workers: usize },
    /// An attach to the interpreter never returned.
    Interpreter,
    /// A critical loop stopped turning.
    Loop(&'static str),
}

/// Tracks how long one beat has been owed.
#[derive(Default)]
struct Owed {
    for_samples: u32,
    last_done: u64,
}

impl Owed {
    /// One sample. Counts while the beat is owed and nothing has finished.
    fn sample(&mut self, beat: &Beat) -> u32 {
        let done = beat.done();
        if beat.outstanding() && done == self.last_done {
            self.for_samples += 1;
        } else {
            self.for_samples = 0;
        }
        self.last_done = done;
        self.for_samples
    }
}

// ---------------------------------------------------------------------------
// Critical loops
// ---------------------------------------------------------------------------

/// How many loops can register. Fixed so registering and reading take no lock.
const LOOP_SLOTS: usize = 8;

/// Loops a watchdog requires to keep turning. Fixed slots, so registering and
/// reading take no lock.
pub(crate) struct Loops {
    slots: [OnceLock<Arc<LoopStamp>>; LOOP_SLOTS],
}

impl Loops {
    const fn new() -> Self {
        Self {
            slots: [const { OnceLock::new() }; LOOP_SLOTS],
        }
    }

    fn register(&self, name: &'static str) -> Arc<LoopStamp> {
        let stamp = Arc::new(LoopStamp {
            name,
            last_ms: AtomicU64::new(now_ms()),
        });
        for slot in &self.slots {
            if slot.set(Arc::clone(&stamp)).is_ok() {
                return stamp;
            }
        }
        tracing::warn!(
            loop_name = name,
            "liveness: no slot left to watch this loop"
        );
        stamp
    }

    fn stalled(&self, stall: Duration) -> Option<&'static str> {
        self.slots
            .iter()
            .filter_map(OnceLock::get)
            .find(|stamp| stamp.idle_for() >= stall)
            .map(|stamp| stamp.name)
    }
}

/// The process's critical loops, watched by [`start`].
static LOOPS: Loops = Loops::new();

/// Process epoch for loop stamps.
fn epoch() -> Instant {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    *EPOCH.get_or_init(Instant::now)
}

fn now_ms() -> u64 {
    u64::try_from(epoch().elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// A critical loop's last turn.
pub(crate) struct LoopStamp {
    name: &'static str,
    last_ms: AtomicU64,
}

impl LoopStamp {
    /// Record a turn.
    pub(crate) fn tick(&self) {
        self.last_ms.store(now_ms(), Ordering::Release);
    }

    fn idle_for(&self) -> Duration {
        Duration::from_millis(now_ms().saturating_sub(self.last_ms.load(Ordering::Acquire)))
    }
}

/// Register a loop the watchdog requires to keep turning. A loop must turn
/// (call [`LoopStamp::tick`]) well inside the stall window. With every slot
/// taken the stamp is still returned, just not watched.
///
/// A loop that registers more than once (a test building several dispatchers)
/// takes another slot each time, and only the first [`LOOP_SLOTS`] are watched.
pub(crate) fn register_loop(name: &'static str) -> Arc<LoopStamp> {
    LOOPS.register(name)
}

// ---------------------------------------------------------------------------
// Tokio workers
// ---------------------------------------------------------------------------

/// Per-worker park/unpark counts seen at the previous sample, and for how many
/// samples each has been unparked and unchanged.
#[derive(Default)]
struct Workers {
    last: Vec<u64>,
    unchanged: Vec<u32>,
}

impl Workers {
    /// Count the workers stuck in one poll for at least `stall_samples`.
    ///
    /// The counter is bumped on every park and every unpark, so it is odd
    /// while the worker is parked. Unchanged and even means the worker has
    /// been running the same poll since the last sample.
    fn stuck(&mut self, runtime: &TokioHandle, stall_samples: u32) -> (usize, usize) {
        let metrics = runtime.metrics();
        let workers = metrics.num_workers();
        self.last.resize(workers, u64::MAX);
        self.unchanged.resize(workers, 0);
        let mut stuck = 0;
        for worker in 0..workers {
            let count = metrics.worker_park_unpark_count(worker);
            if count.is_multiple_of(2) && count == self.last[worker] {
                self.unchanged[worker] += 1;
            } else {
                self.unchanged[worker] = 0;
            }
            self.last[worker] = count;
            if self.unchanged[worker] >= stall_samples {
                stuck += 1;
            }
        }
        (stuck, workers)
    }
}

// ---------------------------------------------------------------------------
// The watchdog
// ---------------------------------------------------------------------------

/// The tokio beat's body: a timer and a loopback datagram, so it lands only
/// when the timer driver and the I/O driver turn as well as the scheduler.
async fn beat_through_the_drivers(beat: Arc<Beat>) {
    tokio::time::sleep(Duration::from_millis(1)).await;
    let round_trip = async {
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        sender.send_to(b"beat", receiver.local_addr()?).await?;
        let mut buffer = [0u8; 4];
        receiver.recv_from(&mut buffer).await?;
        std::io::Result::Ok(())
    };
    // A host with no loopback cannot prove the I/O driver this way; the beat
    // still proves the scheduler and the timer rather than tripping falsely.
    let _ = round_trip.await;
    beat.end();
}

/// Run the liveness watchdog until `shutdown`.
///
/// Each sample (spaced by `pace`, one `sample` long) sends a tokio beat when
/// the last one has landed, and checks every signal; `on_stall` fires once one
/// has been owed for `stall_samples` consecutive samples. `interpreter` is
/// driven by [`run_interpreter_probe`] on its own thread.
#[allow(clippy::too_many_arguments)] // each is one signal or knob; a struct would only rename them
pub(crate) fn run_liveness_watchdog(
    runtime: TokioHandle,
    interpreter: Arc<Beat>,
    loops: &Loops,
    stall_samples: u32,
    sample: Duration,
    shutdown: Arc<AtomicBool>,
    on_stall: impl Fn(Stalled),
    mut pace: impl FnMut(),
) {
    let tokio_beat = Arc::new(Beat::default());
    let mut tokio_owed = Owed::default();
    let mut interpreter_owed = Owed::default();
    let mut workers = Workers::default();
    let loop_stall = sample * stall_samples;
    loop {
        if !tokio_beat.outstanding() {
            tokio_beat.begin();
            runtime.spawn(beat_through_the_drivers(Arc::clone(&tokio_beat)));
        }
        pace();
        if shutdown.load(Ordering::Relaxed) {
            return;
        }
        let tokio_samples = tokio_owed.sample(&tokio_beat);
        let interpreter_samples = interpreter_owed.sample(&interpreter);
        let (stuck, total) = workers.stuck(&runtime, stall_samples);
        let stalled = if tokio_samples >= stall_samples {
            Some(Stalled::Tokio)
        } else if total > 0 && stuck * 2 > total {
            Some(Stalled::Workers {
                stuck,
                workers: total,
            })
        } else if interpreter_samples >= stall_samples {
            Some(Stalled::Interpreter)
        } else {
            loops.stalled(loop_stall).map(Stalled::Loop)
        };
        if let Some(which) = stalled {
            on_stall(which);
            tokio_owed = Owed::default();
            interpreter_owed = Owed::default();
            workers = Workers::default();
        }
    }
}

/// Attach to the interpreter and detach again, every `interval`, beating
/// `beat` around each attach and publishing how long it waited.
pub(crate) fn run_interpreter_probe(
    beat: Arc<Beat>,
    interval: Duration,
    shutdown: Arc<AtomicBool>,
    probe: impl Fn(),
) {
    while !shutdown.load(Ordering::Relaxed) {
        beat.begin();
        let started = Instant::now();
        probe();
        let waited = started.elapsed();
        beat.end();
        if let Some(registry) = crate::metrics::try_metrics() {
            registry
                .interpreter_attach_wait_ms
                .set(i64::try_from(waited.as_millis()).unwrap_or(i64::MAX));
        }
        if waited >= Duration::from_secs(1) {
            // Off the probe's attach: this thread holds nothing here.
            tracing::warn!(
                waited_ms = waited.as_millis() as u64,
                "attaching to the Python interpreter waited on a stop-the-world: \
                 some thread blocked while attached held every other thread up"
            );
        }
        std::thread::sleep(interval);
    }
}

/// Start the watchdog and the interpreter probe for `runtime`, aborting the
/// process after `stall`. Neither thread is joined on shutdown: a wedged
/// process must not also wedge its own exit.
pub(crate) fn start(runtime: TokioHandle, stall: Duration) {
    const INTERVAL: Duration = Duration::from_secs(1);
    let shutdown = Arc::new(AtomicBool::new(false));
    let interpreter = Arc::new(Beat::default());
    let probe = {
        let interpreter = Arc::clone(&interpreter);
        let shutdown = Arc::clone(&shutdown);
        std::thread::Builder::new()
            .name("siphon-attach-probe".to_string())
            .spawn(move || {
                run_interpreter_probe(interpreter, INTERVAL, shutdown, || {
                    // `try_attach` never initialises the interpreter.
                    let _ = pyo3::Python::try_attach(|_| ());
                })
            })
    };
    let watchdog = std::thread::Builder::new()
        .name("siphon-liveness".to_string())
        .spawn(move || {
            let stall_samples = u32::try_from(stall.as_secs().max(1)).unwrap_or(u32::MAX);
            run_liveness_watchdog(
                runtime,
                interpreter,
                &LOOPS,
                stall_samples,
                INTERVAL,
                shutdown,
                |which| abort_on_stall(which, stall),
                || std::thread::sleep(INTERVAL),
            )
        });
    if let Err(error) = probe.and(watchdog) {
        // Not fatal: the node serves without it, but a whole-process wedge
        // then goes unnoticed until someone looks.
        tracing::error!(%error, "could not start the process liveness watchdog");
    }
}

/// What the process does on a stall: say so on stderr without taking any lock
/// a stuck thread could hold (no `tracing`, no buffered `Stderr`), then abort
/// for the supervisor and leave a core.
fn abort_on_stall(which: Stalled, stall: Duration) -> ! {
    let what = match which {
        Stalled::Tokio => "the tokio runtime ran no timer, socket or task".to_string(),
        Stalled::Workers { stuck, workers } => {
            format!("{stuck} of {workers} tokio workers were stuck in one poll")
        }
        Stalled::Interpreter => {
            "no thread could attach to the Python interpreter (a stop-the-world that never \
             ended)"
                .to_string()
        }
        Stalled::Loop(name) => format!("the {name} loop did not turn"),
    };
    let message = format!(
        "siphon: process wedged: {what} for {}s; aborting so a supervisor restarts the \
         process\n",
        stall.as_secs()
    );
    write_stderr_raw(message.as_bytes());
    std::process::abort()
}

#[cfg(unix)]
fn write_stderr_raw(bytes: &[u8]) {
    use std::io::Write;
    use std::os::fd::FromRawFd;
    // SAFETY: fd 2 is the process's stderr for its whole life; the `File` is
    // forgotten below so it is never closed.
    let mut stderr = unsafe { std::fs::File::from_raw_fd(2) };
    let _ = stderr.write_all(bytes);
    std::mem::forget(stderr);
}

#[cfg(not(unix))]
fn write_stderr_raw(bytes: &[u8]) {
    use std::io::Write;
    let _ = std::io::stderr().write_all(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    const SAMPLE: Duration = Duration::from_millis(20);

    /// Drive `samples` samples and return which stall fired first, if any.
    fn first_stall(
        runtime: TokioHandle,
        interpreter: Arc<Beat>,
        stall_samples: u32,
        samples: u32,
    ) -> Option<Stalled> {
        first_stall_with(runtime, interpreter, &Loops::new(), stall_samples, samples)
    }

    fn first_stall_with(
        runtime: TokioHandle,
        interpreter: Arc<Beat>,
        loops: &Loops,
        stall_samples: u32,
        samples: u32,
    ) -> Option<Stalled> {
        let fired = Arc::new(Mutex::new(None));
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut taken = 0;
        let record = Arc::clone(&fired);
        let stop = Arc::clone(&shutdown);
        run_liveness_watchdog(
            runtime,
            interpreter,
            loops,
            stall_samples,
            SAMPLE,
            Arc::clone(&shutdown),
            move |which| {
                let mut slot = record.lock().unwrap();
                if slot.is_none() {
                    *slot = Some(which);
                }
            },
            move || {
                std::thread::sleep(SAMPLE);
                taken += 1;
                if taken >= samples {
                    stop.store(true, Ordering::Relaxed);
                }
            },
        );
        let result = *fired.lock().unwrap();
        result
    }

    fn runtime(workers: usize) -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(workers)
            .enable_all()
            .build()
            .unwrap()
    }

    /// Block `count` of `runtime`'s workers inside one poll each, until the
    /// returned sender is dropped.
    fn block_workers(
        runtime: &tokio::runtime::Runtime,
        count: usize,
    ) -> Vec<std::sync::mpsc::Sender<()>> {
        let mut releases = Vec::new();
        for _ in 0..count {
            let (release, blocked) = std::sync::mpsc::channel::<()>();
            let (started_tx, started) = std::sync::mpsc::channel();
            runtime.spawn(async move {
                let _ = started_tx.send(());
                let _ = blocked.recv();
            });
            started.recv().unwrap();
            releases.push(release);
        }
        releases
    }

    #[test]
    fn a_runtime_that_runs_tasks_and_an_attachable_interpreter_never_trip() {
        let runtime = runtime(2);
        let interpreter = Arc::new(Beat::default());
        assert_eq!(
            first_stall(runtime.handle().clone(), interpreter, 5, 40),
            None
        );
    }

    /// The wedge this exists for, on the tokio side: every worker blocked, so
    /// the beat never runs.
    #[test]
    fn a_runtime_whose_workers_are_all_blocked_trips() {
        let runtime = runtime(1);
        let releases = block_workers(&runtime, 1);
        let interpreter = Arc::new(Beat::default());
        let fired = first_stall(runtime.handle().clone(), interpreter, 5, 40);
        drop(releases);
        assert!(
            matches!(fired, Some(Stalled::Tokio) | Some(Stalled::Workers { .. })),
            "got {fired:?}"
        );
    }

    /// Partial starvation: the beat still lands on the one free worker, but
    /// three of four are stuck in one poll.
    #[test]
    fn most_workers_stuck_trips_while_the_beat_still_lands() {
        let runtime = runtime(4);
        let releases = block_workers(&runtime, 3);
        let interpreter = Arc::new(Beat::default());
        let fired = first_stall(runtime.handle().clone(), interpreter, 5, 40);
        drop(releases);
        assert_eq!(
            fired,
            Some(Stalled::Workers {
                stuck: 3,
                workers: 4
            })
        );
    }

    /// The interpreter side: an attach that never returns.
    #[test]
    fn an_attach_that_never_returns_trips() {
        let runtime = runtime(1);
        let interpreter = Arc::new(Beat::default());
        let shutdown = Arc::new(AtomicBool::new(false));
        let (release, blocked) = std::sync::mpsc::channel::<()>();
        let blocked = Mutex::new(blocked);
        let probe = {
            let interpreter = Arc::clone(&interpreter);
            let shutdown = Arc::clone(&shutdown);
            std::thread::spawn(move || {
                run_interpreter_probe(interpreter, Duration::from_millis(5), shutdown, || {
                    let _ = blocked.lock().unwrap().recv();
                })
            })
        };
        let fired = first_stall(runtime.handle().clone(), Arc::clone(&interpreter), 5, 40);
        shutdown.store(true, Ordering::Relaxed);
        drop(release);
        let _ = probe.join();
        assert_eq!(fired, Some(Stalled::Interpreter));
    }

    /// One critical loop stopping trips on its own, with the runtime healthy.
    #[test]
    fn a_critical_loop_that_stops_turning_trips() {
        let runtime = runtime(2);
        let loops = Loops::new();
        let stamp = loops.register("test-loop-that-stops");
        stamp.tick();
        let interpreter = Arc::new(Beat::default());
        let fired = first_stall_with(runtime.handle().clone(), interpreter, &loops, 5, 40);
        assert_eq!(fired, Some(Stalled::Loop("test-loop-that-stops")));
    }
}
