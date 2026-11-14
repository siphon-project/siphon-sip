//! How long Python's garbage collections take, and how many there are.
//!
//! One callable in `gc.callbacks`, installed once for the life of the
//! interpreter. CPython calls every entry with `"start"` before a collection
//! and `"stop"` after it, both on the thread that collects, so the start time
//! is kept per thread and nothing is shared between threads but the collectors.
//!
//! What the two calls bracket (CPython 3.14.2, `gc_collect_main` in
//! `Python/gc_free_threading.c` and `_PyGC_Collect` in `Python/gc.c`): the
//! whole collection. On a free-threaded interpreter that is the first
//! stop-the-world (merging refcounts, marking, finding the unreachable), then
//! weakref callbacks and finalizers with every other thread running again, a
//! second short stop-the-world for resurrected objects, and the deallocation
//! of the garbage, again with the world running. The time recorded is
//! therefore an upper bound on how long other threads were held, not the pause
//! itself. A stop-the-world that is not a collection (`gc.freeze`,
//! `gc.get_objects`, a thread-state table growing) calls no callback and is
//! not counted here; `siphon_interpreter_attach_wait_seconds` sees those.
//!
//! The callable runs attached, between safe points, so it takes no lock: the
//! per-generation children are resolved when the collectors are built, and an
//! observation is a few atomic adds. It never raises.

use std::cell::Cell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

use prometheus::{
    exponential_buckets, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, Opts,
    Registry,
};
use pyo3::prelude::*;
use pyo3::types::PyString;

/// CPython's `NUM_GENERATIONS`: the `generation` a callback can be handed.
const GENERATIONS: [&str; 3] = ["0", "1", "2"];

/// The collectors behind the two garbage-collection metrics, with the child of
/// each generation resolved up front.
pub(crate) struct GcCollectors {
    pause_seconds: HistogramVec,
    collections_total: IntCounterVec,
    pause: [Histogram; 3],
    collections: [IntCounter; 3],
}

impl GcCollectors {
    fn new() -> Result<Self, prometheus::Error> {
        let pause_seconds = HistogramVec::new(
            HistogramOpts::new(
                "siphon_python_gc_pause_seconds",
                "Wall time of one Python garbage collection on the thread that ran it. It \
                 covers the whole collection, finalizers and deallocation included, so it is \
                 an upper bound on how long the collection held other threads; a \
                 stop-the-world that is not a collection is not counted. `generation` is the \
                 one the collection was asked for: 0 for an automatic collection on a \
                 free-threaded interpreter (which always scans the whole heap), 2 for \
                 gc.collect()",
            )
            // 100 us to 3.3 s.
            .buckets(exponential_buckets(0.0001, 2.0, 16)?),
            &["generation"],
        )?;
        let collections_total = IntCounterVec::new(
            Opts::new(
                "siphon_python_gc_collections_total",
                "Python garbage collections completed, by the generation asked for",
            ),
            &["generation"],
        )?;
        let pause = GENERATIONS.map(|generation| pause_seconds.with_label_values(&[generation]));
        let collections =
            GENERATIONS.map(|generation| collections_total.with_label_values(&[generation]));
        Ok(Self {
            pause_seconds,
            collections_total,
            pause,
            collections,
        })
    }

    /// One callback from the collector.
    fn record(&self, phase: &str, generation: Option<usize>) {
        match phase {
            "start" => set_collection_started(Some(Instant::now())),
            "stop" => {
                let started = take_collection_started();
                let Some(generation) = generation.filter(|index| *index < GENERATIONS.len()) else {
                    return;
                };
                self.collections[generation].inc();
                if let Some(started) = started {
                    self.pause[generation].observe(started.elapsed().as_secs_f64());
                }
            }
            _ => {}
        }
    }
}

thread_local! {
    /// When the collection this thread is running began. A collection starts
    /// and stops on one thread, and CPython runs one at a time. Shared by
    /// every recorder, which is why `gc.callbacks` holds only one.
    static COLLECTION_STARTED: Cell<Option<Instant>> = const { Cell::new(None) };
}

fn set_collection_started(started: Option<Instant>) {
    // A thread whose locals are already gone has nothing to time.
    let _ = COLLECTION_STARTED.try_with(|cell| cell.set(started));
}

fn take_collection_started() -> Option<Instant> {
    COLLECTION_STARTED.try_with(Cell::take).ok().flatten()
}

/// The entry in `gc.callbacks`.
#[pyclass(frozen, name = "GcPauseRecorder")]
struct GcPauseRecorder {
    collectors: &'static GcCollectors,
}

#[pymethods]
impl GcPauseRecorder {
    /// `callback(phase, info)`, as `gc.callbacks` documents it. Anything else
    /// is ignored: an exception here would be reported from inside the
    /// collector.
    fn __call__(&self, phase: &Bound<'_, PyAny>, info: &Bound<'_, PyAny>) {
        let Ok(phase) = phase.cast::<PyString>() else {
            return;
        };
        let Ok(phase) = phase.to_str() else {
            return;
        };
        let generation = info
            .get_item("generation")
            .and_then(|generation| generation.extract::<usize>())
            .ok();
        self.collectors.record(phase, generation);
    }
}

/// The process-wide collectors, built on first use. `None` only if the
/// hardcoded names were rejected, which would be a bug.
fn collectors() -> Option<&'static GcCollectors> {
    static COLLECTORS: OnceLock<Option<GcCollectors>> = OnceLock::new();
    COLLECTORS.get_or_init(|| GcCollectors::new().ok()).as_ref()
}

/// Add both collectors to the metrics registry. Called from `metrics::init`;
/// collections counted before that keep their values, because the registry
/// holds the same collectors.
pub(crate) fn register(registry: &Registry) -> Result<(), prometheus::Error> {
    if let Some(collectors) = collectors() {
        registry.register(Box::new(collectors.pause_seconds.clone()))?;
        registry.register(Box::new(collectors.collections_total.clone()))?;
    }
    Ok(())
}

/// Put the recorder in `gc.callbacks`, once per process however often it is
/// called: every script engine calls it, and a reload builds no engine.
///
/// The interpreter must be initialised.
pub(crate) fn install() {
    static INSTALLED: AtomicBool = AtomicBool::new(false);
    // Built before the attach, so the callback never initialises anything.
    let Some(collectors) = collectors() else {
        return;
    };
    if INSTALLED.swap(true, Ordering::AcqRel) {
        return;
    }
    let appended = Python::attach(|python| {
        append_recorder(python, collectors).map_err(|error| error.to_string())
    });
    if let Err(error) = appended {
        INSTALLED.store(false, Ordering::Release);
        tracing::warn!(
            %error,
            "could not install the garbage-collection callback; \
             siphon_python_gc_pause_seconds stays empty"
        );
    }
}

fn append_recorder(python: Python<'_>, collectors: &'static GcCollectors) -> PyResult<()> {
    let recorder = Py::new(python, GcPauseRecorder { collectors })?;
    python
        .import("gc")?
        .getattr("callbacks")?
        .call_method1("append", (recorder,))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::stop_the_world_tests::{collect_garbage_until, in_child};
    use std::sync::Arc;
    use std::time::Duration;

    fn leaked_collectors() -> &'static GcCollectors {
        Box::leak(Box::new(GcCollectors::new().expect("collectors build")))
    }

    /// How many recorders of the process-wide collectors `gc.callbacks` holds.
    /// Tests running beside this one add recorders of their own collectors.
    fn recorders_installed(python: Python<'_>) -> usize {
        let global = collectors().expect("collectors build");
        python
            .import("gc")
            .and_then(|gc| gc.getattr("callbacks"))
            .and_then(|callbacks| callbacks.try_iter())
            .expect("gc.callbacks")
            .filter(|entry| {
                entry
                    .as_ref()
                    .ok()
                    .and_then(|entry| entry.cast::<GcPauseRecorder>().ok())
                    .is_some_and(|recorder| std::ptr::eq(recorder.get().collectors, global))
            })
            .count()
    }

    fn collect(python: Python<'_>, generation: usize) {
        python
            .import("gc")
            .and_then(|gc| gc.call_method1("collect", (generation,)))
            .expect("gc.collect");
    }

    /// Collect `generation` until `recorded` says the recorder saw one.
    /// `gc.collect()` returns at once, with no callback, while another thread
    /// is collecting, and other tests collect beside this one.
    fn collect_until(generation: usize, recorded: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            Python::attach(|python| collect(python, generation));
            if recorded() {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "no collection of generation {generation} was recorded"
            );
        }
    }

    #[test]
    fn a_collection_is_timed_under_its_generation() {
        let collectors = GcCollectors::new().unwrap();
        collectors.record("start", Some(1));
        std::thread::sleep(Duration::from_millis(2));
        collectors.record("stop", Some(1));
        assert_eq!(collectors.collections[1].get(), 1);
        assert_eq!(collectors.pause[1].get_sample_count(), 1);
        assert!(collectors.pause[1].get_sample_sum() >= 0.002);
        for other in [0, 2] {
            assert_eq!(collectors.collections[other].get(), 0);
            assert_eq!(collectors.pause[other].get_sample_count(), 0);
        }
    }

    #[test]
    fn a_stop_without_its_start_is_counted_but_not_timed() {
        let collectors = GcCollectors::new().unwrap();
        collectors.record("stop", Some(2));
        assert_eq!(collectors.collections[2].get(), 1);
        assert_eq!(collectors.pause[2].get_sample_count(), 0);
    }

    #[test]
    fn a_start_is_not_carried_into_a_later_collection() {
        let collectors = GcCollectors::new().unwrap();
        collectors.record("start", Some(0));
        collectors.record("stop", Some(0));
        collectors.record("stop", Some(0));
        assert_eq!(collectors.collections[0].get(), 2);
        assert_eq!(collectors.pause[0].get_sample_count(), 1);
    }

    #[test]
    fn an_unknown_phase_or_generation_records_nothing() {
        let collectors = GcCollectors::new().unwrap();
        collectors.record("start", Some(0));
        collectors.record("pause", Some(0));
        collectors.record("stop", Some(3));
        collectors.record("stop", None);
        for generation in 0..GENERATIONS.len() {
            assert_eq!(collectors.collections[generation].get(), 0);
            assert_eq!(collectors.pause[generation].get_sample_count(), 0);
        }
    }

    /// Each thread times its own collection.
    #[test]
    fn the_start_time_belongs_to_the_collecting_thread() {
        let collectors = Arc::new(GcCollectors::new().unwrap());
        collectors.record("start", Some(2));
        let other = Arc::clone(&collectors);
        std::thread::spawn(move || other.record("stop", Some(2)))
            .join()
            .unwrap();
        assert_eq!(collectors.collections[2].get(), 1);
        assert_eq!(
            collectors.pause[2].get_sample_count(),
            0,
            "a stop on another thread must not use this thread's start"
        );
        collectors.record("stop", Some(2));
        assert_eq!(collectors.pause[2].get_sample_count(), 1);
    }

    /// The real thing: CPython calls the recorder around `gc.collect()`.
    #[test]
    fn gc_collect_is_recorded_with_its_generation_and_a_duration() {
        Python::initialize();
        install();
        // The process's recorder: a second one in `gc.callbacks` would share
        // the collecting thread's start time with it. Other tests collect
        // too, so only lower bounds hold.
        let global = collectors().expect("collectors build");
        let counted = |generation: usize| {
            (
                global.collections[generation].get(),
                global.pause[generation].get_sample_count(),
                global.pause[generation].get_sample_sum(),
            )
        };
        for generation in [2, 1] {
            let (collections, timed, seconds) = counted(generation);
            collect_until(generation, || {
                let (collections_after, timed_after, _) = counted(generation);
                collections_after > collections && timed_after > timed
            });
            assert!(
                counted(generation).2 > seconds,
                "a collection of generation {generation} takes time"
            );
        }
    }

    #[test]
    fn the_recorder_never_raises_whatever_it_is_called_with() {
        Python::initialize();
        let collectors = leaked_collectors();
        Python::attach(|python| {
            let recorder = Bound::new(python, GcPauseRecorder { collectors }).unwrap();
            let none = python.None();
            let info = pyo3::types::PyDict::new(python);
            info.set_item("generation", "two").unwrap();
            recorder.call1((1, 2)).expect("non-string phase");
            recorder.call1(("stop", &none)).expect("info is not a dict");
            recorder
                .call1(("stop", &info))
                .expect("generation is not a number");
            info.set_item("generation", -1).unwrap();
            recorder
                .call1(("stop", &info))
                .expect("negative generation");
            info.set_item("generation", 99).unwrap();
            recorder
                .call1(("stop", &info))
                .expect("generation out of range");
            let surrogate = python.eval(c"'\\ud800'", None, None).unwrap();
            recorder
                .call1((surrogate, &none))
                .expect("a phase that is not UTF-8");
        });
        for generation in 0..GENERATIONS.len() {
            assert_eq!(collectors.collections[generation].get(), 0);
        }
    }

    /// Engines come and go and scripts reload; the interpreter keeps one
    /// recorder, and it keeps recording.
    #[test]
    fn one_recorder_survives_engines_and_reloads() {
        Python::initialize();
        let directory = tempfile::tempdir().unwrap();
        let script = directory.path().join("gc_metrics_reload.py");
        std::fs::write(&script, "VALUE = 1\n").unwrap();
        let config = crate::config::ScriptConfig {
            path: script.to_str().unwrap().to_owned(),
            reload: crate::config::ReloadMode::Auto,
            async_pool_size: None,
            sync_pool_size: None,
            sync_pool_max: None,
            handler_stall_abort_secs: 30,
            process_stall_abort_secs: 30,
            handler_timeout_secs: None,
            executor_queue_capacity: 1024,
            include_paths: Vec::new(),
        };
        let engine = crate::script::engine::ScriptEngine::new(&config).expect("initial load");
        for round in 0..5 {
            std::fs::write(&script, format!("VALUE = {round}\n")).unwrap();
            engine.reload().expect("reload");
        }
        let _embedded =
            crate::script::engine::ScriptEngine::new_embedded("VALUE = 2\n").expect("embedded");
        let installers: Vec<_> = (0..8).map(|_| std::thread::spawn(install)).collect();
        for installer in installers {
            installer.join().unwrap();
        }
        assert_eq!(Python::attach(recorders_installed), 1);

        let global = collectors().expect("collectors build");
        let before = global.collections[2].get();
        let timed_before = global.pause[2].get_sample_count();
        collect_until(2, || {
            global.collections[2].get() > before
                && global.pause[2].get_sample_count() > timed_before
        });
    }

    #[test]
    fn the_metrics_are_exported_once_registered() {
        crate::metrics::init().unwrap();
        Python::initialize();
        install();
        Python::attach(|python| collect(python, 2));
        let output = crate::metrics::encode_metrics();
        assert!(output.contains("siphon_python_gc_pause_seconds_bucket{generation=\"2\""));
        assert!(output.contains("siphon_python_gc_collections_total{generation=\"2\"}"));
    }

    /// Collections forced from several threads while the attach probe runs:
    /// the recorder and the probe hold nothing a stop-the-world waits for.
    #[test]
    fn forced_collections_with_the_probe_running_do_not_deadlock() {
        if !in_child(
            concat!(
                module_path!(),
                "::forced_collections_with_the_probe_running_do_not_deadlock"
            ),
            Duration::from_secs(60),
        ) {
            return;
        }
        Python::initialize();
        install();
        let global = collectors().expect("collectors build");
        let collections_before: u64 = global.collections.iter().map(IntCounter::get).sum();

        let wait = Arc::new(crate::script::liveness::AttachWait::new().unwrap());
        let beat = Arc::new(crate::script::liveness::Beat::default());
        let stop = Arc::new(AtomicBool::new(false));
        let probe = {
            let (wait, beat, stop) = (Arc::clone(&wait), Arc::clone(&beat), Arc::clone(&stop));
            std::thread::spawn(move || {
                crate::script::liveness::run_interpreter_probe(
                    beat,
                    Duration::from_millis(1),
                    stop,
                    Some(&wait),
                    crate::script::liveness::pinned_attach_probe(),
                )
            })
        };
        let collectors_running: Vec<_> = (0..3)
            .map(|_| collect_garbage_until(Arc::clone(&stop)))
            .collect();
        // Threads that allocate, so automatic collections run as well.
        let allocators: Vec<_> = (0..3)
            .map(|_| {
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    let source = std::ffi::CString::new(
                        "for _ in range(2000):\n    a = [[] for _ in range(8)]\n    a.append(a)\n",
                    )
                    .unwrap();
                    while !stop.load(Ordering::Relaxed) {
                        Python::attach(|python| {
                            let _ = python.run(source.as_c_str(), None, None);
                        });
                    }
                })
            })
            .collect();

        std::thread::sleep(Duration::from_secs(2));
        stop.store(true, Ordering::Relaxed);
        for thread in collectors_running.into_iter().chain(allocators) {
            thread.join().unwrap();
        }
        probe.join().unwrap();

        let collections: u64 = global.collections.iter().map(IntCounter::get).sum();
        assert!(
            collections > collections_before,
            "collections were recorded"
        );
        // On a GIL build the probe queues for the GIL behind six busy
        // threads, so it samples far less often than every millisecond.
        assert!(wait.samples() >= 5, "the probe kept sampling");
    }
}
