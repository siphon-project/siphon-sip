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
//!   detaching again, every 10 ms. It completes unless a stop-the-world never
//!   ends. How long each attach waited is published
//!   (`siphon_interpreter_attach_wait_seconds`, and the longest of the last
//!   second as `siphon_interpreter_attach_wait_ms`), so a stop-the-world held
//!   open for milliseconds, far too short to abort over, still shows. This
//!   thread runs with the watchdog off as well.
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
    pub(crate) const fn new() -> Self {
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

    /// Watch an existing stamp too, for a test whose watchdog judges a loop
    /// the process registered.
    #[cfg(test)]
    pub(crate) fn watch(&self, stamp: &Arc<LoopStamp>) {
        for slot in &self.slots {
            if slot.set(Arc::clone(stamp)).is_ok() {
                return;
            }
        }
    }

    /// One watchdog sample: the first loop whose stamp has not moved for
    /// `stall_samples` consecutive samples, if any.
    ///
    /// Counted in the watchdog's own samples, never as wall-clock time since
    /// the last stamp. A suspension of the whole process (a cgroup freeze, a
    /// paused VM, SIGSTOP) stops the watchdog along with the loops, and on
    /// resume the clock shows a gap no loop could have closed; judging that gap
    /// aborted healthy processes within a second of every resume. Counting
    /// samples, the suspension is at most one sample without progress.
    fn stalled(&self, progress: &mut LoopProgress, stall_samples: u32) -> Option<&'static str> {
        let mut stalled = None;
        for (index, stamp) in self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| slot.get().map(|stamp| (index, stamp)))
        {
            let last = stamp.last_ms.load(Ordering::Acquire);
            let seen = &mut progress.seen[index];
            match seen {
                Some((previous, unchanged)) if *previous == last => *unchanged += 1,
                _ => *seen = Some((last, 0)),
            }
            if let Some((_, unchanged)) = seen {
                if *unchanged >= stall_samples && stalled.is_none() {
                    stalled = Some(stamp.name);
                }
            }
        }
        stalled
    }
}

/// Per loop slot: the stamp the watchdog last saw, and for how many samples
/// since it has not moved.
#[derive(Default)]
struct LoopProgress {
    seen: [Option<(u64, u32)>; LOOP_SLOTS],
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

    /// How long since the last turn.
    #[cfg(test)]
    pub(crate) fn idle_for(&self) -> Duration {
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
    let mut loop_progress = LoopProgress::default();
    loop {
        if !tokio_beat.outstanding() {
            tokio_beat.begin();
            runtime.spawn(beat_through_the_drivers(Arc::clone(&tokio_beat)));
        }
        let paced = Instant::now();
        pace();
        if shutdown.load(Ordering::Relaxed) {
            return;
        }
        // A sample that came far later than its period means this thread was
        // not running: the whole process was suspended, or starved of CPU.
        // Nothing could progress meanwhile, so judge from here afresh.
        if paced.elapsed() > sample * 3 {
            tokio_owed = Owed::default();
            interpreter_owed = Owed::default();
            workers = Workers::default();
            loop_progress = LoopProgress::default();
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
            loops
                .stalled(&mut loop_progress, stall_samples)
                .map(Stalled::Loop)
        };
        if let Some(which) = stalled {
            on_stall(which);
            tokio_owed = Owed::default();
            interpreter_owed = Owed::default();
            workers = Workers::default();
            loop_progress = LoopProgress::default();
        }
    }
}

/// Attach to the interpreter and detach again, every `interval`, beating
/// `beat` around each attach and publishing how long it waited.
#[allow(clippy::disallowed_methods)] // dedicated probe thread; it sleeps detached, between attaches
pub(crate) fn run_interpreter_probe(
    beat: Arc<Beat>,
    interval: Duration,
    shutdown: Arc<AtomicBool>,
    wait: Option<&AttachWait>,
    probe: impl Fn(),
) {
    let mut window = LongestWait::default();
    while !shutdown.load(Ordering::Relaxed) {
        beat.begin();
        let started = Instant::now();
        probe();
        let waited = started.elapsed();
        beat.end();
        if let Some(wait) = wait {
            wait.seconds.observe(waited.as_secs_f64());
            if let Some(longest) = window.sample(waited, Instant::now()) {
                wait.last_ms
                    .set(i64::try_from(longest.as_millis()).unwrap_or(i64::MAX));
                // Once a window, on this thread because it is the one that
                // attaches anyway. Inside a beat of its own: this attaches
                // too, and a wedge that caught it between two beats would go
                // unseen. Its attach is one more sample of the wait, so a
                // stop-the-world that began after the probe above is counted.
                beat.begin();
                let sampler_waited = super::gc_metrics::sample_young_objects();
                beat.end();
                if let Some(sampler_waited) = sampler_waited {
                    wait.seconds.observe(sampler_waited.as_secs_f64());
                    window.note(sampler_waited);
                }
            }
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

/// How often the probe attaches. One uncontended attach and detach on a thread
/// that keeps its thread state costs well under a microsecond, so 100 a second
/// is no load, and a stop-the-world of 10 ms or more is always sampled.
const PROBE_INTERVAL: Duration = Duration::from_millis(10);

/// How often `siphon_interpreter_attach_wait_ms` is refreshed, with the longest
/// wait since the last refresh. The probe once attached at this rate and set
/// the gauge each time; a gauge set every [`PROBE_INTERVAL`] would hide a stall
/// from any scrape that did not land within 10 ms of it.
const GAUGE_WINDOW: Duration = Duration::from_secs(1);

/// The longest attach wait over the current [`GAUGE_WINDOW`].
#[derive(Default)]
struct LongestWait {
    since: Option<Instant>,
    longest: Duration,
}

impl LongestWait {
    /// A wait that belongs to the current window and does not close it.
    fn note(&mut self, waited: Duration) {
        self.longest = self.longest.max(waited);
    }

    /// One sample at `now`. Returns the window's longest wait when the window
    /// closes, and starts the next.
    fn sample(&mut self, waited: Duration, now: Instant) -> Option<Duration> {
        self.longest = self.longest.max(waited);
        let since = *self.since.get_or_insert(now);
        if now.duration_since(since) < GAUGE_WINDOW {
            return None;
        }
        self.since = Some(now);
        Some(std::mem::take(&mut self.longest))
    }
}

/// The collectors the probe publishes its attach waits through.
pub(crate) struct AttachWait {
    seconds: prometheus::Histogram,
    last_ms: prometheus::IntGauge,
}

impl AttachWait {
    pub(crate) fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            seconds: prometheus::Histogram::with_opts(
                prometheus::HistogramOpts::new(
                    "siphon_interpreter_attach_wait_seconds",
                    "How long each attach of the liveness probe to the Python interpreter \
                     waited. The probe attaches every 10 ms from its own thread, so a \
                     stop-the-world (a garbage collection or any other) or a held GIL shows \
                     as one observation about as long as what was left of it; read the upper \
                     buckets, not a quantile over the many idle samples",
                )
                // 100 us to 3.3 s.
                .buckets(prometheus::exponential_buckets(0.0001, 2.0, 16)?),
            )?,
            last_ms: prometheus::IntGauge::new(
                "siphon_interpreter_attach_wait_ms",
                "The longest the liveness probe's attaches to the Python interpreter waited \
                 in the last completed one-second window (ms)",
            )?,
        })
    }

    /// How many attaches were observed.
    #[cfg(test)]
    pub(crate) fn samples(&self) -> u64 {
        self.seconds.get_sample_count()
    }
}

/// The process-wide collectors, built on first use. `None` only if the
/// hardcoded names were rejected, which would be a bug; the probe still beats.
fn attach_wait() -> Option<&'static AttachWait> {
    static ATTACH_WAIT: OnceLock<Option<AttachWait>> = OnceLock::new();
    ATTACH_WAIT.get_or_init(|| AttachWait::new().ok()).as_ref()
}

/// Add the attach-wait collectors to the metrics registry. Called from
/// `metrics::init`; the registry holds the same collectors the probe writes.
pub(crate) fn register(registry: &prometheus::Registry) -> Result<(), prometheus::Error> {
    if let Some(wait) = attach_wait() {
        registry.register(Box::new(wait.seconds.clone()))?;
        registry.register(Box::new(wait.last_ms.clone()))?;
    }
    Ok(())
}

/// The probe's attach, for the thread that runs [`run_interpreter_probe`].
///
/// A thread with no Python thread state gets one made and destroyed around
/// every attach, which on a free-threaded interpreter means a heap set up and
/// torn down each time (about 180 us an attach measured on 3.14t in a debug
/// build, against about 0.1 us pinned) and a wait that measures that as well
/// as the interpreter. So once an attach has
/// succeeded, which also proves the interpreter is initialised, the thread
/// state is pinned and every later attach only resumes it.
pub(crate) fn pinned_attach_probe() -> impl Fn() {
    let pinned = std::cell::Cell::new(false);
    move || {
        // `try_attach` never initialises the interpreter.
        let attached = pyo3::Python::try_attach(|_| ()).is_some();
        if attached && !pinned.get() {
            // SAFETY: the attach above returned, so the interpreter is
            // initialised and this thread is detached again. `PyEval_SaveThread`
            // detaches once more while the thread state stays cached against
            // this OS thread, so each later attach is a resume. Never released:
            // the probe thread lives until the process exits.
            unsafe {
                pyo3::ffi::PyGILState_Ensure();
                pyo3::ffi::PyEval_SaveThread();
            }
            pinned.set(true);
        }
    }
}

/// Start the interpreter probe, and the process liveness watchdog for the
/// current tokio runtime unless `script.process_stall_abort_secs` is 0. The
/// probe runs either way: its attach waits are a metric, not only a reason to
/// abort.
pub(crate) fn start_from_config(config: &crate::config::ScriptConfig) {
    let stall = match config.process_stall_abort_secs {
        0 => None,
        secs => Some(Duration::from_secs(secs)),
    };
    start(TokioHandle::current(), stall);
}

/// Start the interpreter probe, and with `stall` the watchdog for `runtime`
/// that aborts the process after it. Neither thread is joined on shutdown: a
/// wedged process must not also wedge its own exit.
#[allow(clippy::disallowed_methods)] // dedicated watchdog thread, never attaches
pub(crate) fn start(runtime: TokioHandle, stall: Option<Duration>) {
    const INTERVAL: Duration = Duration::from_secs(1);
    let shutdown = Arc::new(AtomicBool::new(false));
    let interpreter = Arc::new(Beat::default());
    let probe = {
        let interpreter = Arc::clone(&interpreter);
        let shutdown = Arc::clone(&shutdown);
        std::thread::Builder::new()
            .name("siphon-attach-probe".to_string())
            .spawn(move || {
                run_interpreter_probe(
                    interpreter,
                    PROBE_INTERVAL,
                    shutdown,
                    attach_wait(),
                    pinned_attach_probe(),
                )
            })
    };
    let watchdog = match stall {
        None => Ok(None),
        Some(stall) => std::thread::Builder::new()
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
            })
            .map(Some),
    };
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
                run_interpreter_probe(
                    interpreter,
                    Duration::from_millis(5),
                    shutdown,
                    None,
                    || {
                        let _ = blocked.lock().unwrap().recv();
                    },
                )
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

    /// A suspension of the whole process (a cgroup freeze, a paused VM, a
    /// SIGSTOP) stops the watchdog together with the loops it watches. On
    /// resume the loops turn again; the time they could not turn is not a
    /// stall, and the watchdog must not abort for it.
    #[test]
    fn a_suspension_of_the_whole_process_is_not_a_stall() {
        let runtime = runtime(2);
        let loops = Loops::new();
        let stamp = loops.register("test-loop-suspended");
        stamp.tick();
        // The loop turns every 10 ms, except while "suspended".
        let suspended = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let turner = {
            let stamp = Arc::clone(&stamp);
            let suspended = Arc::clone(&suspended);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    if !suspended.load(Ordering::Relaxed) {
                        stamp.tick();
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            })
        };
        let fired = Arc::new(Mutex::new(None));
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut taken = 0;
        let record = Arc::clone(&fired);
        let shut = Arc::clone(&shutdown);
        let freeze = Arc::clone(&suspended);
        run_liveness_watchdog(
            runtime.handle().clone(),
            Arc::new(Beat::default()),
            &loops,
            5,
            SAMPLE,
            Arc::clone(&shutdown),
            move |which| {
                let mut slot = record.lock().unwrap();
                slot.get_or_insert(which);
            },
            move || {
                taken += 1;
                if taken == 10 {
                    // The whole process stops for 1 s, many stall windows
                    // (5 samples of 20 ms); the watchdog's own sleep with it.
                    freeze.store(true, Ordering::Relaxed);
                    std::thread::sleep(Duration::from_secs(1));
                    freeze.store(false, Ordering::Relaxed);
                } else {
                    std::thread::sleep(SAMPLE);
                }
                if taken >= 40 {
                    shut.store(true, Ordering::Relaxed);
                }
            },
        );
        stop.store(true, Ordering::Relaxed);
        let _ = turner.join();
        let result = *fired.lock().unwrap();
        assert_eq!(result, None, "the suspension was judged a stall");
    }

    /// Observations in `histogram` above `seconds`.
    fn observed_above(wait: &AttachWait, seconds: f64) -> u64 {
        use prometheus::core::Collector;
        let families = wait.seconds.collect();
        let histogram = families[0].get_metric()[0].get_histogram();
        let within = histogram
            .get_bucket()
            .iter()
            .filter(|bucket| bucket.upper_bound() <= seconds)
            .map(|bucket| bucket.cumulative_count())
            .max()
            .unwrap_or(0);
        histogram.get_sample_count() - within
    }

    /// Run the probe with `probe` as its attach until `done` says so.
    fn probe_until(wait: &Arc<AttachWait>, probe: impl Fn() + Send + 'static, done: impl Fn()) {
        let shutdown = Arc::new(AtomicBool::new(false));
        let thread = {
            let wait = Arc::clone(wait);
            let shutdown = Arc::clone(&shutdown);
            std::thread::spawn(move || {
                run_interpreter_probe(
                    Arc::new(Beat::default()),
                    Duration::from_millis(1),
                    shutdown,
                    Some(&wait),
                    probe,
                )
            })
        };
        done();
        shutdown.store(true, Ordering::Relaxed);
        thread.join().unwrap();
    }

    #[test]
    fn every_attach_is_observed_with_how_long_it_waited() {
        let wait = Arc::new(AttachWait::new().unwrap());
        let calls = Arc::new(AtomicU64::new(0));
        let counted = Arc::clone(&calls);
        probe_until(
            &wait,
            move || {
                // The third attach waits; the rest return at once.
                if counted.fetch_add(1, Ordering::Relaxed) == 2 {
                    std::thread::sleep(Duration::from_millis(30));
                }
            },
            || {
                while calls.load(Ordering::Relaxed) < 10 {
                    std::thread::sleep(Duration::from_millis(1));
                }
            },
        );
        assert!(wait.samples() >= 10);
        assert_eq!(wait.samples(), calls.load(Ordering::Relaxed));
        assert!(observed_above(&wait, 0.02) >= 1, "the one slow attach");
        assert!(wait.seconds.get_sample_sum() >= 0.030);
    }

    #[test]
    fn the_gauge_reads_the_longest_wait_of_each_window() {
        let start = Instant::now();
        let at = |ms| start + Duration::from_millis(ms);
        let ms = Duration::from_millis;
        let mut window = LongestWait::default();
        assert_eq!(window.sample(ms(1), at(0)), None);
        assert_eq!(window.sample(ms(400), at(10)), None);
        assert_eq!(window.sample(ms(2), at(500)), None);
        // The stall of 400 ms is still what the window reports when it closes.
        assert_eq!(window.sample(ms(1), at(1000)), Some(ms(400)));
        // The next window starts empty.
        assert_eq!(window.sample(ms(3), at(1500)), None);
        assert_eq!(window.sample(ms(1), at(2000)), Some(ms(3)));
        // One attach that outlasts the window reports itself.
        assert_eq!(window.sample(ms(5000), at(7000)), Some(ms(5000)));
        // A wait noted between two samples counts in its window.
        window.note(ms(250));
        assert_eq!(window.sample(ms(1), at(7500)), None);
        assert_eq!(window.sample(ms(1), at(8000)), Some(ms(250)));
    }

    #[test]
    fn the_gauge_is_set_when_its_window_closes() {
        let wait = Arc::new(AttachWait::new().unwrap());
        let read = Arc::clone(&wait);
        probe_until(
            &wait,
            // Every attach waits, so every window's longest is at least this
            // and a slow reader cannot miss the one window that held it.
            || std::thread::sleep(Duration::from_millis(40)),
            || {
                let deadline = Instant::now() + Duration::from_secs(10);
                while read.last_ms.get() == 0 && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(10));
                }
            },
        );
        assert!(
            wait.last_ms.get() >= 40,
            "the gauge reads the window's longest attach, got {} ms",
            wait.last_ms.get()
        );
    }

    /// The pinned probe leaves the thread detached with its thread state kept.
    #[test]
    fn the_pinned_probe_keeps_its_thread_state_and_stays_detached() {
        pyo3::Python::initialize();
        let (before, state_kept, attached_after) = std::thread::spawn(|| {
            // SAFETY: both read only this thread's own thread state.
            let this_thread_state = || unsafe { pyo3::ffi::PyGILState_GetThisThreadState() };
            let before = this_thread_state().is_null();
            let probe = pinned_attach_probe();
            probe();
            let state = this_thread_state();
            for _ in 0..100 {
                probe();
            }
            let attached = unsafe { pyo3::ffi::PyGILState_Check() };
            (
                before,
                !state.is_null() && state == this_thread_state(),
                attached,
            )
        })
        .join()
        .unwrap();
        assert!(before, "a fresh thread has no thread state");
        assert!(state_kept, "the probe pins one thread state for good");
        assert_eq!(attached_after, 0, "and leaves the thread detached");
    }

    /// The real stall: a thread blocked while attached holds a collection's
    /// stop-the-world open (or the GIL), and the probe's next attach waits
    /// behind it. That wait lands in the histogram.
    #[test]
    fn a_stall_behind_an_attached_thread_shows_in_the_histogram() {
        use crate::script::stop_the_world_tests::in_child;
        use pyo3::types::PyAnyMethods;
        if !in_child(
            concat!(
                module_path!(),
                "::a_stall_behind_an_attached_thread_shows_in_the_histogram"
            ),
            Duration::from_secs(60),
        ) {
            return;
        }
        pyo3::Python::initialize();
        const DEADLINE: Duration = Duration::from_secs(20);
        // Samples unchanged for this long means one attach has waited this
        // long: the probe takes one every millisecond otherwise.
        const STUCK: Duration = Duration::from_millis(200);
        let wait = Arc::new(AttachWait::new().unwrap());
        let seen = Arc::clone(&wait);
        probe_until(&wait, pinned_attach_probe(), move || {
            // The probe pins itself and takes idle samples first.
            let started = Instant::now();
            while seen.samples() < 10 && started.elapsed() < DEADLINE {
                std::thread::sleep(Duration::from_millis(1));
            }
            // Blocked while attached until released: the fault itself.
            let (attached_tx, attached) = std::sync::mpsc::channel();
            let (release, blocked) = std::sync::mpsc::channel::<()>();
            let blocker = std::thread::spawn(move || {
                pyo3::Python::attach(|_| {
                    let _ = attached_tx.send(());
                    let _ = blocked.recv();
                })
            });
            attached.recv().unwrap();
            let collector = std::thread::spawn(|| {
                pyo3::Python::attach(|python| {
                    let _ = python
                        .import("gc")
                        .and_then(|gc| gc.call_method0("collect"));
                })
            });
            // Hold the blocker until the probe has been stuck behind it.
            let started = Instant::now();
            loop {
                let before = seen.samples();
                std::thread::sleep(STUCK);
                if seen.samples() == before || started.elapsed() > DEADLINE {
                    break;
                }
            }
            drop(release);
            blocker.join().unwrap();
            collector.join().unwrap();
        });
        assert!(wait.samples() > 10, "the probe sampled before and after");
        assert!(
            observed_above(&wait, 0.11) >= 1,
            "no attach waited behind the attached thread: {} samples, {:.3} s in all",
            wait.samples(),
            wait.seconds.get_sample_sum()
        );
    }

    /// With the watchdog off the probe still runs and publishes.
    #[test]
    fn the_probe_runs_without_the_watchdog() {
        use crate::script::stop_the_world_tests::in_child;
        if !in_child(
            concat!(module_path!(), "::the_probe_runs_without_the_watchdog"),
            Duration::from_secs(60),
        ) {
            return;
        }
        pyo3::Python::initialize();
        crate::metrics::init().unwrap();
        let runtime = runtime(1);
        let before = attach_wait().expect("collectors build").samples();
        start(runtime.handle().clone(), None);
        let deadline = Instant::now() + Duration::from_secs(10);
        while attach_wait().unwrap().samples() < before + 20 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(attach_wait().unwrap().samples() >= before + 20);
        let output = crate::metrics::encode_metrics();
        assert!(output.contains("siphon_interpreter_attach_wait_seconds_bucket"));
        assert!(output.contains("siphon_interpreter_attach_wait_ms"));
    }
}
