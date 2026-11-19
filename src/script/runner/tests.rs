//! The runner on a real driver loop: wake, drain order, fairness, shutdown.

use std::collections::HashMap;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pyo3::prelude::*;

use super::{Fate, Message, RunnerOwner, RunnerShared, Work, DRAIN_ITEM_BUDGET, PULL_BATCH};
use crate::script::async_pool::{test_pools_runtime, AsyncPool};
use crate::script::stop_the_world_tests::{collect_garbage_back_to_back_until, in_child};

/// A pool of its own, so a test can stop it without touching the shared one.
fn private_pool() -> AsyncPool {
    Python::initialize();
    AsyncPool::spawn(
        1,
        test_pools_runtime().handle().clone(),
        Duration::from_secs(3),
    )
}

fn runner_of(pool: &AsyncPool) -> Arc<RunnerShared> {
    Arc::clone(pool.runner(0).expect("the pool has one driver"))
}

fn post(runner: &RunnerShared, message: Message) {
    assert!(runner.post(message).is_ok(), "a live runner takes the post");
}

fn wait_until(what: &str, budget: Duration, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + budget;
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn attached() -> bool {
    // SAFETY: reads only this thread's own thread state.
    unsafe { pyo3::ffi::PyGILState_Check() == 1 }
}

fn on_a_driver_thread() -> bool {
    std::thread::current()
        .name()
        .is_some_and(|name| name.starts_with("siphon-asyncio-"))
}

/// Holds a runner's loop inside one item until released, so what is posted
/// meanwhile is all queued when the drain moves on.
struct Held {
    release: mpsc::Sender<()>,
}

impl Held {
    /// `on_loop` runs first, on the loop thread, attached.
    fn hold(
        runner: &RunnerShared,
        on_loop: impl for<'py> FnOnce(Python<'py>) + Send + 'static,
    ) -> Self {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        post(
            runner,
            Message::Start(Work::new(move |python, _fate| {
                on_loop(python);
                let _ = entered_tx.send(());
                python.detach(move || {
                    let _ = release_rx.recv_timeout(Duration::from_secs(30));
                });
            })),
        );
        entered_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the holding item ran");
        Self {
            release: release_tx,
        }
    }

    fn release(self) {
        let _ = self.release.send(());
    }
}

#[test]
fn work_runs_attached_on_its_own_driver_thread() {
    let _serial = crate::script::async_pool::pool_test_guard();
    let (_executor, pool) = crate::script::async_pool::ensure_test_pools();
    for index in 0..pool.size() {
        let runner = pool.runner(index).expect("every driver has a runner");
        let (seen_tx, seen_rx) = mpsc::channel();
        post(
            runner,
            Message::Start(Work::new(move |_python, fate| {
                let thread = std::thread::current().name().map(str::to_string);
                let _ = seen_tx.send((fate, thread, attached()));
            })),
        );
        let (fate, thread, was_attached) = seen_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the item ran");
        assert_eq!(fate, Fate::Run);
        assert_eq!(thread.as_deref(), Some(&*format!("siphon-asyncio-{index}")));
        assert!(was_attached, "an item runs attached to the interpreter");
    }
    assert!(pool.runner(pool.size()).is_none());
}

/// A post from a thread that never touches Python goes through while every
/// attach in the process is stuck: one thread sits attached and blocked, and
/// another keeps collecting, which on a free-threaded build stops the world
/// behind it and on a GIL build waits for the GIL it holds.
#[test]
fn a_post_does_not_wait_for_a_stopped_world() {
    if !in_child(
        concat!(module_path!(), "::a_post_does_not_wait_for_a_stopped_world"),
        Duration::from_secs(90),
    ) {
        return;
    }
    let pool = private_pool();
    let runner = runner_of(&pool);

    let (held_tx, held_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let holder = std::thread::spawn(move || {
        Python::attach(|_python| {
            let _ = held_tx.send(());
            let _ = release_rx.recv_timeout(Duration::from_secs(60));
        });
    });
    held_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the holder attached");
    let stop = Arc::new(AtomicBool::new(false));
    let collector = collect_garbage_back_to_back_until(Arc::clone(&stop));

    // The fixture is only worth anything if an attach really is stuck: a
    // thread that keeps attaching must stop making progress.
    let attaches = Arc::new(AtomicU64::new(0));
    let prober = {
        let attaches = Arc::clone(&attaches);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                Python::attach(|_python| ());
                attaches.fetch_add(1, Ordering::Relaxed);
            }
        })
    };
    let mut last = attaches.load(Ordering::Relaxed);
    let mut still_since = Instant::now();
    let deadline = Instant::now() + Duration::from_secs(20);
    while still_since.elapsed() < Duration::from_millis(500) {
        assert!(
            Instant::now() < deadline,
            "attaches never stopped: the world is not held"
        );
        std::thread::sleep(Duration::from_millis(10));
        let now = attaches.load(Ordering::Relaxed);
        if now != last {
            last = now;
            still_since = Instant::now();
        }
    }

    const POSTS: usize = 1000;
    let before = runner.stats();
    let ran = Arc::new(AtomicUsize::new(0));
    let (posted_tx, posted_rx) = mpsc::channel();
    {
        let runner = Arc::clone(&runner);
        let ran = Arc::clone(&ran);
        std::thread::spawn(move || {
            for _ in 0..POSTS {
                let ran = Arc::clone(&ran);
                post(
                    &runner,
                    Message::Wake(Work::new(move |_python, _fate| {
                        ran.fetch_add(1, Ordering::Relaxed);
                    })),
                );
            }
            let _ = posted_tx.send(());
        });
    }
    let posted = posted_rx.recv_timeout(Duration::from_secs(5)).is_ok();
    let during = runner.stats();
    let ran_during = ran.load(Ordering::Relaxed);

    // Let the world go whatever happened, so a failure reports, not hangs.
    stop.store(true, Ordering::Relaxed);
    let _ = release_tx.send(());
    holder.join().expect("holder thread");
    collector.join().expect("collector thread");
    prober.join().expect("prober thread");

    assert!(posted, "a post waited for the interpreter");
    assert_eq!(
        ran_during, 0,
        "the driver cannot attach, so nothing can have run yet"
    );
    assert_eq!(during.queued - before.queued, POSTS);
    assert_eq!(
        during.wake_writes - before.wake_writes,
        1,
        "every post behind the first shares its wake"
    );

    wait_until("the queued items to run", Duration::from_secs(20), || {
        ran.load(Ordering::Relaxed) == POSTS
    });
    assert_eq!(runner.stats().queued, 0);
    drop(pool);
}

/// The race a lost wakeup hides in: a post landing just as a drain finds the
/// queue empty and goes back to the selector. Each round trip posts to a
/// runner that is idle or about to be, and has to hear back.
#[test]
fn no_wake_is_lost_between_a_post_and_an_idle_drain() {
    const THREADS: usize = 8;
    const ROUND_TRIPS: usize = 2000;
    let pool = private_pool();
    let runner = runner_of(&pool);

    let threads: Vec<_> = (0..THREADS)
        .map(|_| {
            let runner = Arc::clone(&runner);
            std::thread::spawn(move || {
                let (done_tx, done_rx) = mpsc::channel();
                for round in 0..ROUND_TRIPS {
                    let done_tx = done_tx.clone();
                    post(
                        &runner,
                        Message::Wake(Work::new(move |_python, _fate| {
                            let _ = done_tx.send(());
                        })),
                    );
                    assert!(
                        done_rx.recv_timeout(Duration::from_secs(20)).is_ok(),
                        "round trip {round} was never run: its wake was lost"
                    );
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().expect("a round trip was lost");
    }
    let stats = runner.stats();
    assert_eq!(stats.queued, 0);
    assert_eq!(stats.ran, (THREADS * ROUND_TRIPS) as u64);
    assert!(stats.wake_writes <= stats.ran + stats.budget_yields);
    drop(pool);
}

/// Many threads posting flat out: everything runs, and the posts share wakes.
#[test]
fn a_flood_of_posts_all_runs() {
    const THREADS: usize = 8;
    const POSTS: usize = 5000;
    let pool = private_pool();
    let runner = runner_of(&pool);
    let ran = Arc::new(AtomicUsize::new(0));

    let threads: Vec<_> = (0..THREADS)
        .map(|thread| {
            let runner = Arc::clone(&runner);
            let ran = Arc::clone(&ran);
            std::thread::spawn(move || {
                for index in 0..POSTS {
                    let ran = Arc::clone(&ran);
                    let work = Work::new(move |_python, _fate| {
                        ran.fetch_add(1, Ordering::Relaxed);
                    });
                    post(
                        &runner,
                        match (thread + index) % 3 {
                            0 => Message::Start(work),
                            1 => Message::Wake(work),
                            _ => Message::Cancel(work),
                        },
                    );
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().expect("poster thread");
    }
    wait_until("the flood to drain", Duration::from_secs(30), || {
        ran.load(Ordering::Relaxed) == THREADS * POSTS
    });
    let stats = runner.stats();
    assert_eq!(stats.queued, 0);
    assert_eq!(stats.ran, (THREADS * POSTS) as u64);
    assert!(
        stats.wake_writes <= stats.ran + stats.budget_yields,
        "a wake byte is written by a post or a yield, once at most: {stats:?}"
    );
    drop(pool);
}

#[test]
fn posts_behind_a_busy_runner_share_one_wake() {
    let pool = private_pool();
    let runner = runner_of(&pool);
    let held = Held::hold(&runner, |_python| ());
    let before = runner.stats().wake_writes;

    let ran = Arc::new(AtomicUsize::new(0));
    for _ in 0..1000 {
        let ran = Arc::clone(&ran);
        post(
            &runner,
            Message::Wake(Work::new(move |_python, _fate| {
                ran.fetch_add(1, Ordering::Relaxed);
            })),
        );
    }
    assert_eq!(runner.stats().wake_writes - before, 1);

    held.release();
    wait_until("the items to run", Duration::from_secs(10), || {
        ran.load(Ordering::Relaxed) == 1000
    });
    drop(pool);
}

#[test]
fn cancels_run_before_wakes_and_wakes_before_starts() {
    let pool = private_pool();
    let runner = runner_of(&pool);
    let held = Held::hold(&runner, |_python| ());

    let order = Arc::new(Mutex::new(Vec::new()));
    let record = |name: &'static str| {
        let order = Arc::clone(&order);
        Work::new(move |_python, _fate| order.lock().expect("order").push(name))
    };
    // A start that itself raises a cancel: the cancel goes ahead of the
    // starts queued behind it.
    let cancelling_start = {
        let order = Arc::clone(&order);
        let runner = Arc::clone(&runner);
        let late_cancel = record("late-cancel");
        Work::new(move |_python, _fate| {
            order.lock().expect("order").push("start-1");
            post(&runner, Message::Cancel(late_cancel));
        })
    };
    post(&runner, Message::Start(cancelling_start));
    post(&runner, Message::Start(record("start-2")));
    post(&runner, Message::Wake(record("wake-1")));
    post(&runner, Message::Cancel(record("cancel-1")));
    post(&runner, Message::Wake(record("wake-2")));
    post(&runner, Message::Cancel(record("cancel-2")));

    held.release();
    wait_until("the items to run", Duration::from_secs(10), || {
        order.lock().expect("order").len() == 7
    });
    assert_eq!(
        *order.lock().expect("order"),
        [
            "cancel-1",
            "cancel-2",
            "wake-1",
            "wake-2",
            "start-1",
            "late-cancel",
            "start-2"
        ]
    );
    drop(pool);
}

/// The drain itself, called by hand with no loop behind it: what one call
/// takes in and runs is bounded whatever is queued.
#[test]
fn one_drain_call_is_bounded_in_intake_and_in_items() {
    Python::initialize();
    let owner = RunnerOwner::new().expect("a runner");
    let runner = Arc::clone(owner.shared());
    let ran = Arc::new(AtomicUsize::new(0));
    for _ in 0..1000 {
        let ran = Arc::clone(&ran);
        post(
            &runner,
            Message::Start(Work::new(move |_python, _fate| {
                ran.fetch_add(1, Ordering::Relaxed);
            })),
        );
    }
    assert_eq!(runner.stats().wake_writes, 1);

    {
        let mut local = owner.local().expect("the state is free");
        local.pull(&runner);
        assert_eq!(local.starts.len(), PULL_BATCH, "one look takes one batch");
    }

    Python::attach(|python| owner.drain(python));
    let stats = runner.stats();
    assert!(
        (1..=64).contains(&stats.ran),
        "one drain ran {} items",
        stats.ran
    );
    assert_eq!(stats.ran, ran.load(Ordering::Relaxed) as u64);
    assert_eq!(stats.queued, 1000 - stats.ran as usize);
    assert_eq!(stats.budget_yields, 1);
    assert_eq!(
        stats.wake_writes, 2,
        "a drain that stops with work left wakes itself"
    );

    // Each further call makes progress until the queue is empty.
    let mut calls = 1;
    while runner.stats().queued != 0 {
        Python::attach(|python| owner.drain(python));
        calls += 1;
        assert!(calls <= 1000, "the drain stopped making progress");
    }
    assert!(calls >= 1000 / 64);
    assert_eq!(ran.load(Ordering::Relaxed), 1000);

    // With no loop to stop, closing is all that is left: nothing is queued,
    // so nothing is abandoned.
    Python::attach(|python| owner.close(python, &python.None().into_bound(python)));
    assert_eq!(runner.stats().abandoned, 0);
    assert!(runner.is_shut_down());
}

/// Counts the items each drain ran, keyed by the drain's number.
#[derive(Default)]
struct PerDrain(Mutex<HashMap<u64, usize>>);

impl PerDrain {
    fn count(&self, runner: &RunnerShared) {
        *self
            .0
            .lock()
            .expect("tally")
            .entry(runner.stats().drains)
            .or_default() += 1;
    }

    fn largest(&self) -> usize {
        self.0
            .lock()
            .expect("tally")
            .values()
            .copied()
            .max()
            .unwrap_or(0)
    }
}

#[test]
fn one_drain_runs_at_most_its_item_budget() {
    const ITEMS: usize = 1000;
    let pool = private_pool();
    let runner = runner_of(&pool);
    let held = Held::hold(&runner, |_python| ());
    let before = runner.stats();

    let tally = Arc::new(PerDrain::default());
    let ran = Arc::new(AtomicUsize::new(0));
    for _ in 0..ITEMS {
        let tally = Arc::clone(&tally);
        let ran = Arc::clone(&ran);
        let counted = Arc::clone(&runner);
        post(
            &runner,
            Message::Start(Work::new(move |_python, _fate| {
                tally.count(&counted);
                ran.fetch_add(1, Ordering::Relaxed);
            })),
        );
    }
    held.release();
    wait_until("the items to run", Duration::from_secs(20), || {
        ran.load(Ordering::Relaxed) == ITEMS
    });

    assert!(
        tally.largest() <= DRAIN_ITEM_BUDGET,
        "a drain ran {} items",
        tally.largest()
    );
    let yields = runner.stats().budget_yields - before.budget_yields;
    assert!(
        yields >= (ITEMS / DRAIN_ITEM_BUDGET) as u64,
        "{ITEMS} items need at least {} yields, saw {yields}",
        ITEMS / DRAIN_ITEM_BUDGET
    );
    drop(pool);
}

/// A loop callback that notes how many items had run when its turn came.
#[pyclass]
struct Probe {
    items_run: Arc<AtomicUsize>,
    seen: Arc<AtomicUsize>,
}

#[pymethods]
impl Probe {
    fn __call__(&self) {
        self.seen
            .store(self.items_run.load(Ordering::Relaxed), Ordering::Relaxed);
    }
}

const NOT_RUN: usize = usize::MAX;

/// With far more queued than one drain may run, a `call_soon` callback and a
/// short timer still get their turns while items are left.
#[test]
fn the_loop_runs_callbacks_and_timers_between_drains() {
    const ITEMS: usize = 2000;
    let pool = private_pool();
    let runner = runner_of(&pool);

    let items_run = Arc::new(AtomicUsize::new(0));
    let soon_seen = Arc::new(AtomicUsize::new(NOT_RUN));
    let timer_seen = Arc::new(AtomicUsize::new(NOT_RUN));
    let probe = |seen: &Arc<AtomicUsize>| Probe {
        items_run: Arc::clone(&items_run),
        seen: Arc::clone(seen),
    };
    let (soon, timer) = (probe(&soon_seen), probe(&timer_seen));

    // Scheduled from inside a drain, with the items queued before that drain
    // moves on: a drain that ran its whole queue would starve both.
    let held = Held::hold(&runner, move |python| {
        let schedule = || -> PyResult<()> {
            let event_loop = python.import("asyncio")?.call_method0("get_running_loop")?;
            event_loop.call_method1("call_soon", (Py::new(python, soon)?,))?;
            event_loop.call_method1("call_later", (0.005, Py::new(python, timer)?))?;
            Ok(())
        };
        schedule().expect("the probes are scheduled");
    });
    for _ in 0..ITEMS {
        let items_run = Arc::clone(&items_run);
        post(
            &runner,
            Message::Start(Work::new(move |_python, _fate| {
                // Long enough that the whole queue outlasts the timer.
                let started = Instant::now();
                while started.elapsed() < Duration::from_micros(20) {
                    std::hint::spin_loop();
                }
                items_run.fetch_add(1, Ordering::Relaxed);
            })),
        );
    }
    held.release();
    wait_until("the items to run", Duration::from_secs(30), || {
        items_run.load(Ordering::Relaxed) == ITEMS
    });

    let soon_seen = soon_seen.load(Ordering::Relaxed);
    let timer_seen = timer_seen.load(Ordering::Relaxed);
    assert!(
        soon_seen <= DRAIN_ITEM_BUDGET,
        "call_soon waited for {soon_seen} items"
    );
    assert!(
        timer_seen < ITEMS,
        "the timer waited for the whole queue ({timer_seen})"
    );
    drop(pool);
}

#[test]
fn a_panicking_item_does_not_stop_the_drain() {
    let pool = private_pool();
    let runner = runner_of(&pool);
    let (done_tx, done_rx) = mpsc::channel();
    post(
        &runner,
        Message::Start(Work::new(|_python, _fate| panic!("item failure"))),
    );
    post(
        &runner,
        Message::Start(Work::new(move |_python, _fate| {
            let _ = done_tx.send(());
        })),
    );
    done_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the item behind the panic ran");
    assert_eq!(runner.stats().queued, 0);
    drop(pool);
}

fn collect(python: Python<'_>) {
    let gc = python.import("gc").expect("gc module");
    for _ in 0..3 {
        gc.call_method0("collect").expect("gc.collect");
    }
}

/// Shutdown with work queued: every item is abandoned exactly once, attached,
/// on the driver thread; the counters return to zero; what the items held is
/// freed; both ends of the wake pipe close.
#[test]
fn shutdown_abandons_what_is_queued_and_leaves_nothing_behind() {
    const ITEMS: usize = 300;
    let pool = private_pool();
    let runner = runner_of(&pool);
    let held = Held::hold(&runner, |_python| ());

    let run = Arc::new(AtomicUsize::new(0));
    let abandoned = Arc::new(AtomicUsize::new(0));
    let misplaced = Arc::new(AtomicUsize::new(0));
    let mut markers = Vec::new();
    for index in 0..ITEMS {
        // Something only the interpreter can free, to see it is let go.
        let (marker, weak) = Python::attach(|python| {
            let marker = python
                .eval(c"type('Marker', (), {})()", None, None)
                .expect("a marker object");
            let weak = python
                .import("weakref")
                .and_then(|weakref| weakref.call_method1("ref", (&marker,)))
                .expect("a weak reference");
            (marker.unbind(), weak.unbind())
        });
        markers.push(weak);
        let (run, abandoned, misplaced) = (
            Arc::clone(&run),
            Arc::clone(&abandoned),
            Arc::clone(&misplaced),
        );
        let work = Work::new(move |_python, fate| {
            if !(attached() && on_a_driver_thread()) {
                misplaced.fetch_add(1, Ordering::Relaxed);
            }
            match fate {
                Fate::Run => run.fetch_add(1, Ordering::Relaxed),
                Fate::Abandoned => abandoned.fetch_add(1, Ordering::Relaxed),
            };
            drop(marker);
        });
        post(
            &runner,
            match index % 3 {
                0 => Message::Start(work),
                1 => Message::Wake(work),
                _ => Message::Cancel(work),
            },
        );
    }
    assert_eq!(runner.stats().queued, ITEMS);

    // Queued behind the items; the drain sees it before it runs any of them.
    runner.shutdown();
    let mut probe = runner.wake_probe();
    held.release();
    drop(pool);

    assert!(runner.is_shut_down());
    assert_eq!(
        run.load(Ordering::Relaxed),
        0,
        "nothing runs after shutdown"
    );
    assert_eq!(abandoned.load(Ordering::Relaxed), ITEMS);
    assert_eq!(misplaced.load(Ordering::Relaxed), 0);
    let stats = runner.stats();
    assert_eq!(stats.queued, 0);
    assert_eq!(stats.abandoned, ITEMS as u64);

    // A post now is handed back, uninvoked.
    let invoked = Arc::new(AtomicBool::new(false));
    let late = {
        let invoked = Arc::clone(&invoked);
        Work::new(move |_python, _fate| invoked.store(true, Ordering::Relaxed))
    };
    assert!(matches!(
        runner.post(Message::Start(late)),
        Err(Message::Start(_))
    ));
    assert!(!invoked.load(Ordering::Relaxed));
    assert_eq!(runner.stats().queued, 0);

    // The read end is closed: a write on the other end has no peer.
    // (A child process another test is starting holds a copy of it until it
    // execs, hence the retry.)
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match probe.write_all(&[1]) {
            Err(error) => {
                assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
                break;
            }
            Ok(()) => {
                assert!(Instant::now() < deadline, "the read end is still open");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    // The write end goes with the last handle on the runner. The loop's
    // callback held one; a collection lets go of it if the loop had not.
    let weak_runner = Arc::downgrade(&runner);
    drop(runner);
    let deadline = Instant::now() + Duration::from_secs(10);
    while weak_runner.strong_count() != 0 {
        assert!(Instant::now() < deadline, "the runner is still referenced");
        Python::attach(collect);
        std::thread::sleep(Duration::from_millis(10));
    }
    Python::attach(|python| {
        collect(python);
        for weak in &markers {
            let alive = !weak.bind(python).call0().expect("weakref call").is_none();
            assert!(!alive, "an abandoned item's Python object is still alive");
        }
    });
}

/// Posts racing a shutdown: each one is either refused, or invoked exactly
/// once. None is accepted and then dropped on the floor.
#[test]
fn every_accepted_post_is_invoked_once_across_a_shutdown() {
    const THREADS: usize = 6;
    for _ in 0..20 {
        let pool = private_pool();
        let runner = runner_of(&pool);
        let invoked = Arc::new(AtomicUsize::new(0));
        let accepted = Arc::new(AtomicUsize::new(0));
        let refused = Arc::new(AtomicUsize::new(0));

        let threads: Vec<_> = (0..THREADS)
            .map(|_| {
                let runner = Arc::clone(&runner);
                let (invoked, accepted, refused) = (
                    Arc::clone(&invoked),
                    Arc::clone(&accepted),
                    Arc::clone(&refused),
                );
                std::thread::spawn(move || {
                    while refused.load(Ordering::Relaxed) < THREADS {
                        let invoked = Arc::clone(&invoked);
                        let work = Work::new(move |_python, _fate| {
                            invoked.fetch_add(1, Ordering::Relaxed);
                        });
                        match runner.post(Message::Wake(work)) {
                            Ok(()) => accepted.fetch_add(1, Ordering::Relaxed),
                            Err(_returned) => {
                                refused.fetch_add(1, Ordering::Relaxed);
                                break;
                            }
                        };
                    }
                })
            })
            .collect();
        wait_until("posts to flow", Duration::from_secs(10), || {
            invoked.load(Ordering::Relaxed) > 100
        });
        drop(pool);
        for thread in threads {
            thread.join().expect("poster thread");
        }

        assert_eq!(refused.load(Ordering::Relaxed), THREADS);
        assert_eq!(
            invoked.load(Ordering::Relaxed),
            accepted.load(Ordering::Relaxed)
        );
        assert_eq!(runner.stats().queued, 0);
    }
}

#[cfg(target_os = "linux")]
fn open_fds() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .expect("the fd table")
        .count()
}

/// The fd table is back where it started after pools with busy runners come
/// and go. In a child process, where no other test opens anything meanwhile.
#[cfg(target_os = "linux")]
#[test]
fn stopped_runners_leave_no_fd_open() {
    if !in_child(
        concat!(module_path!(), "::stopped_runners_leave_no_fd_open"),
        Duration::from_secs(90),
    ) {
        return;
    }
    let cycle = || {
        let pool = private_pool();
        let runner = runner_of(&pool);
        let held = Held::hold(&runner, |_python| ());
        for _ in 0..50 {
            post(&runner, Message::Start(Work::new(|_python, _fate| ())));
        }
        held.release();
        drop(pool);
        drop(runner);
        Python::attach(collect);
    };
    // The first pool imports asyncio and starts the shared runtime.
    cycle();
    let before = open_fds();
    for _ in 0..10 {
        cycle();
    }
    assert_eq!(open_fds(), before, "a stopped runner left an fd open");
}
