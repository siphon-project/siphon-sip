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
//! Two heartbeats cover that, both independent of the pool's size or fill:
//!
//! * **tokio**: a trivial task spawned onto the runtime. It lands unless every
//!   worker is stuck.
//! * **interpreter**: a dedicated thread attaching to the interpreter and
//!   detaching again. It completes unless a stop-the-world never ends.
//!
//! When either has been owed for the stall window, the process aborts so a
//! supervisor restarts it, which is what `script.handler_stall_abort_secs`
//! promises. The watchdog thread only reads atomics and spawns the tokio task;
//! it takes no lock and never touches Python, so the wedge cannot catch it.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

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

/// Which heartbeat stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stalled {
    Tokio,
    Interpreter,
}

/// Tracks how long one beat has been owed.
struct Owed {
    for_samples: u32,
    last_done: u64,
}

impl Owed {
    fn new() -> Self {
        Self {
            for_samples: 0,
            last_done: 0,
        }
    }

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

/// Run the liveness watchdog until `shutdown`.
///
/// Each sample (spaced by `pace`) sends a tokio heartbeat when the last one has
/// landed, and checks both beats; `on_stall` fires once a beat has been owed
/// for `stall_samples` consecutive samples. `interpreter` is driven by
/// [`run_interpreter_probe`] on its own thread.
pub(crate) fn run_liveness_watchdog(
    runtime: TokioHandle,
    interpreter: Arc<Beat>,
    stall_samples: u32,
    shutdown: Arc<AtomicBool>,
    on_stall: impl Fn(Stalled),
    mut pace: impl FnMut(),
) {
    let tokio_beat = Arc::new(Beat::default());
    let mut tokio_owed = Owed::new();
    let mut interpreter_owed = Owed::new();
    loop {
        if !tokio_beat.outstanding() {
            tokio_beat.begin();
            let beat = Arc::clone(&tokio_beat);
            runtime.spawn(async move { beat.end() });
        }
        pace();
        if shutdown.load(Ordering::Relaxed) {
            return;
        }
        let stalled = if tokio_owed.sample(&tokio_beat) >= stall_samples {
            Some(Stalled::Tokio)
        } else if interpreter_owed.sample(&interpreter) >= stall_samples {
            Some(Stalled::Interpreter)
        } else {
            None
        };
        if let Some(which) = stalled {
            on_stall(which);
            tokio_owed = Owed::new();
            interpreter_owed = Owed::new();
        }
    }
}

/// Attach to the interpreter and detach again, every `interval`, beating
/// `beat` around each attach.
pub(crate) fn run_interpreter_probe(
    beat: Arc<Beat>,
    interval: Duration,
    shutdown: Arc<AtomicBool>,
    probe: impl Fn(),
) {
    while !shutdown.load(Ordering::Relaxed) {
        beat.begin();
        probe();
        beat.end();
        std::thread::sleep(interval);
    }
}

/// What the process does on a stall: say so on stderr without taking any lock
/// a stuck thread could hold (no `tracing`, no buffered `Stderr`), then abort
/// for the supervisor and leave a core.
pub(crate) fn abort_on_stall(which: Stalled, stall: Duration) -> ! {
    let what = match which {
        Stalled::Tokio => "the tokio runtime has run no task",
        Stalled::Interpreter => "no thread has been able to attach to the Python interpreter",
    };
    let message = format!(
        "siphon: process wedged: {what} for {}s (a stop-the-world that never ends, or every \
         worker blocked); aborting so a supervisor restarts the process\n",
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

    /// Drive `samples` samples and return which stall fired first, if any.
    fn first_stall(
        runtime: TokioHandle,
        interpreter: Arc<Beat>,
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
            stall_samples,
            Arc::clone(&shutdown),
            move |which| {
                let mut slot = record.lock().unwrap();
                if slot.is_none() {
                    *slot = Some(which);
                }
            },
            move || {
                std::thread::sleep(Duration::from_millis(20));
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

    #[test]
    fn a_runtime_that_runs_tasks_and_an_attachable_interpreter_never_trip() {
        let runtime = runtime(1);
        let interpreter = Arc::new(Beat::default());
        assert_eq!(
            first_stall(runtime.handle().clone(), interpreter, 5, 40),
            None
        );
    }

    /// The wedge this exists for, on the tokio side: every worker blocked, so
    /// the heartbeat task never runs.
    #[test]
    fn a_runtime_whose_workers_are_all_blocked_trips() {
        let runtime = runtime(1);
        let (release, blocked) = std::sync::mpsc::channel::<()>();
        let (started_tx, started) = std::sync::mpsc::channel();
        runtime.spawn(async move {
            let _ = started_tx.send(());
            let _ = blocked.recv();
        });
        started.recv().unwrap();
        let interpreter = Arc::new(Beat::default());
        let fired = first_stall(runtime.handle().clone(), interpreter, 5, 40);
        let _ = release.send(());
        assert_eq!(fired, Some(Stalled::Tokio));
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
}
