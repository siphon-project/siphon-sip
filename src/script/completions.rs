//! Where awaitable script APIs finish: a small, fixed set of threads that
//! hold their Python thread state for the life of the process.
//!
//! An awaitable ([`super::blocking::awaitable`]) is a Rust future on tokio
//! plus a completion step that attaches to the interpreter, converts the
//! result (a [`super::Deferred`] builds it there) and hands it to the asyncio
//! loop. pyo3-async-runtimes runs that step with its runtime's
//! `spawn_blocking`, which on tokio is the **elastic blocking pool**: threads
//! started on demand, up to 512, and reaped after ten idle seconds.
//!
//! That pool is the wrong home for anything that attaches. A thread that
//! attaches keeps a free-threaded CPython thread state and the mimalloc pages
//! its allocations claimed (around 2 MB once it has done real work), and a
//! thread that exits after attaching abandons those pages, `PyGILState_Release`
//! or not. Pinned or not, then, every blocking thread that ran a completion
//! cost its heap, and every one the pool reaped leaked it: memory that scaled
//! with how many blocking waits had piled up at once (a peer that stops
//! answering parks one thread per wait), and crept on after the load ended.
//! The completions themselves kept the pool from shrinking, too: tokio wakes
//! its idle threads in turn, so a steady trickle of completions resets every
//! idle thread's keep-alive and the pool stays at its high-water mark.
//!
//! Here the completions run on [`THREADS`] threads that are started once,
//! pinned once and never reaped, so the heap they keep is bounded by the
//! thread count and a completion pays no thread-state setup or teardown. The
//! blocking pool is left to Rust waits, which never attach.

use std::future::Future;
use std::pin::Pin;
use std::sync::OnceLock;
use std::task::{Context, Poll};

use pyo3_async_runtimes::generic;
use pyo3_async_runtimes::TaskLocals;
use tracing::error;

/// How many completion threads. A completion is microseconds of work (a
/// nested, already-pinned attach, the conversion, `call_soon_threadsafe`),
/// and the attach is the only thing it ever waits on, so two threads carry
/// hundreds of thousands a second; the second is there so one stalled behind
/// a collection's stop-the-world does not hold every awaitable up alone.
pub(crate) const THREADS: usize = 2;

type Job = Box<dyn FnOnce() + Send + 'static>;

/// The queue into the pool, started on first use. `None` if no thread could
/// be started, which [`submit`] answers by falling back to tokio's pool.
fn queue() -> Option<&'static flume::Sender<Job>> {
    static QUEUE: OnceLock<Option<flume::Sender<Job>>> = OnceLock::new();
    QUEUE.get_or_init(start).as_ref()
}

fn start() -> Option<flume::Sender<Job>> {
    // Unbounded: the producer is a tokio worker finishing a future, which must
    // not block, and dropping a completion would leave a coroutine awaiting
    // forever. The queue holds what has finished and not yet been handed to
    // Python; it drains as fast as the threads run.
    let (sender, receiver) = flume::unbounded::<Job>();
    let mut started = 0;
    for index in 0..THREADS {
        let receiver = receiver.clone();
        let spawned = std::thread::Builder::new()
            .name(format!("siphon-await-{index}"))
            .spawn(move || run(&receiver));
        match spawned {
            Ok(_) => started += 1,
            Err(spawn_error) => error!(
                error = %spawn_error,
                "awaitable completion thread {index} failed to start"
            ),
        }
    }
    if started == 0 {
        error!(
            "no awaitable completion thread started: awaitables complete on \
             tokio's blocking pool, which sets up and tears down a Python thread \
             state per completion"
        );
        return None;
    }
    Some(sender)
}

/// One completion thread: pinned to the interpreter for the life of the
/// process, then running completions until the queue closes (it never does).
fn run(receiver: &flume::Receiver<Job>) {
    // SAFETY: a fresh thread with no thread state. The interpreter is
    // initialised: the first completion is only submitted by an awaitable a
    // Python caller created. `PyEval_SaveThread` detaches again while the
    // thread state stays cached against this OS thread, so each completion's
    // attach is a nested no-op. Never released: the thread never exits, and a
    // thread that did would abandon its heap anyway.
    unsafe {
        pyo3::ffi::PyGILState_Ensure();
        pyo3::ffi::PyEval_SaveThread();
    }
    while let Ok(job) = receiver.recv() {
        // pyo3-async-runtimes' completion catches nothing itself; a panic here
        // must not take a completion thread with it.
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(job)).is_err() {
            error!("an awaitable completion panicked; its coroutine never resumes");
        }
    }
}

/// Run `job` on a completion thread.
fn submit(job: Job) {
    let job = match queue() {
        Some(queue) => match queue.send(job) {
            Ok(()) => return,
            // Only if every completion thread died, which `run` prevents.
            Err(flume::SendError(job)) => job,
        },
        None => job,
    };
    // The behaviour before this pool existed, so an awaitable still completes.
    drop(tokio::task::spawn_blocking(job));
}

/// Completions waiting for a thread right now.
#[cfg(test)]
pub(crate) fn queued() -> usize {
    queue().map_or(0, flume::Sender::len)
}

/// pyo3-async-runtimes' runtime for siphon's awaitables: the futures run on
/// the runtime pyo3-async-runtimes was handed (the server's, see
/// `server::build_runtime`), exactly as `pyo3_async_runtimes::tokio` runs
/// them; only the completion moves, to the pinned threads above.
pub(crate) struct AwaitableRuntime;

/// The handle [`AwaitableRuntime`] gives back: a tokio task for a spawned
/// future, already finished for a submitted completion (pyo3-async-runtimes
/// never awaits a completion's handle).
pub(crate) enum AwaitableJoin {
    Task(tokio::task::JoinHandle<()>),
    Submitted,
}

impl Future for AwaitableJoin {
    type Output = Result<(), tokio::task::JoinError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        match self.get_mut() {
            Self::Task(handle) => Pin::new(handle).poll(context),
            Self::Submitted => Poll::Ready(Ok(())),
        }
    }
}

impl generic::Runtime for AwaitableRuntime {
    type JoinError = tokio::task::JoinError;
    type JoinHandle = AwaitableJoin;

    fn spawn<F>(future: F) -> Self::JoinHandle
    where
        F: Future<Output = ()> + Send + 'static,
    {
        AwaitableJoin::Task(pyo3_async_runtimes::tokio::get_runtime().spawn(future))
    }

    fn spawn_blocking<F>(work: F) -> Self::JoinHandle
    where
        F: FnOnce() + Send + 'static,
    {
        submit(Box::new(work));
        AwaitableJoin::Submitted
    }
}

tokio::task_local! {
    static TASK_LOCALS: TaskLocals;
}

impl generic::ContextExt for AwaitableRuntime {
    fn scope<F, R>(locals: TaskLocals, future: F) -> Pin<Box<dyn Future<Output = R> + Send>>
    where
        F: Future<Output = R> + Send + 'static,
    {
        // Only this runtime's scope: no siphon future asks
        // `pyo3_async_runtimes::tokio` for the current task's locals.
        Box::pin(TASK_LOCALS.scope(locals, future))
    }

    fn get_task_locals() -> Option<TaskLocals> {
        TASK_LOCALS.try_with(Clone::clone).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use generic::Runtime as _;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    /// Whether this thread holds a Python thread state while detached, i.e.
    /// is pinned: an unpinned, detached thread has none.
    fn holds_thread_state() -> bool {
        // SAFETY: reads this thread's own thread-state slot.
        unsafe { !pyo3::ffi::PyGILState_GetThisThreadState().is_null() }
    }

    fn on_completion_thread<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
        let (sender, receiver) = std::sync::mpsc::channel();
        submit(Box::new(move || {
            let _ = sender.send(work());
        }));
        receiver
            .recv_timeout(Duration::from_secs(10))
            .expect("the completion ran")
    }

    #[test]
    fn a_completion_runs_on_a_pinned_named_thread() {
        pyo3::Python::initialize();
        let (pinned, name) = on_completion_thread(|| {
            (
                holds_thread_state(),
                std::thread::current().name().map(str::to_owned),
            )
        });
        assert!(pinned, "the completion thread holds no thread state");
        assert!(
            name.is_some_and(|name| name.starts_with("siphon-await-")),
            "ran off the completion pool"
        );
        // Not vacuous: a thread nobody pinned holds none.
        assert!(!std::thread::spawn(holds_thread_state)
            .join()
            .expect("joins"));
    }

    #[test]
    fn completions_keep_their_thread_state_across_calls() {
        pyo3::Python::initialize();
        let id = || {
            on_completion_thread(|| {
                pyo3::Python::attach(|_python| {
                    // SAFETY: attached, so this thread has a current state.
                    let state = unsafe { pyo3::ffi::PyThreadState_Get() };
                    // SAFETY: `state` is this thread's live thread state.
                    unsafe { pyo3::ffi::PyThreadState_GetID(state) }
                })
            })
        };
        let ids: std::collections::BTreeSet<i64> = (0..64).map(|_| id()).collect();
        assert!(
            ids.len() <= THREADS,
            "64 completions saw {} thread states: one is set up per completion",
            ids.len()
        );
    }

    #[test]
    fn a_panicking_completion_leaves_the_pool_running() {
        pyo3::Python::initialize();
        for _ in 0..THREADS * 2 {
            submit(Box::new(|| panic!("completion panics")));
        }
        assert!(on_completion_thread(|| true));
    }

    /// The pool's only per-completion state is its queue entry: after a
    /// batch it is back to empty.
    #[test]
    fn the_queue_drains_after_a_batch() {
        pyo3::Python::initialize();
        const BATCH: usize = 20_000;
        let done = Arc::new(AtomicUsize::new(0));
        for _ in 0..BATCH {
            let done = Arc::clone(&done);
            submit(Box::new(move || {
                pyo3::Python::attach(|_python| {
                    done.fetch_add(1, Ordering::Relaxed);
                });
            }));
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        while done.load(Ordering::Relaxed) < BATCH && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(done.load(Ordering::Relaxed), BATCH);
        assert_eq!(queued(), 0);
    }

    #[test]
    fn a_submitted_completion_handle_is_already_finished() {
        pyo3::Python::initialize();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        let joined = runtime.block_on(AwaitableRuntime::spawn_blocking(|| {}));
        assert!(joined.is_ok());
    }

    /// Every awaitable in siphon goes through `script::blocking::awaitable`,
    /// whose completion runs here. A direct pyo3-async-runtimes tokio
    /// `future_into_py` completes on tokio's elastic blocking pool instead,
    /// setting a thread state up and tearing it down per call.
    #[test]
    fn no_awaitable_completes_on_the_blocking_pool() {
        let needle = concat!("tokio::", "future_into_py");
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut offenders = Vec::new();
        let mut directories = vec![root.join("src")];
        while let Some(directory) = directories.pop() {
            for entry in std::fs::read_dir(&directory).expect("readable") {
                let path = entry.expect("entry").path();
                if path.is_dir() {
                    directories.push(path);
                    continue;
                }
                if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                    continue;
                }
                let source = std::fs::read_to_string(&path).expect("readable");
                for (number, line) in source.lines().enumerate() {
                    let code = line.split("//").next().unwrap_or("");
                    if code.contains(needle) {
                        offenders.push(format!("{}:{}", path.display(), number + 1));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "call crate::script::awaitable instead: {offenders:?}"
        );
    }
}
