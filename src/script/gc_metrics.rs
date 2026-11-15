//! How long Python's garbage collections take, how many there are and what
//! they free.
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
//! observation is a few atomic adds. It reads the `info` dict it is handed
//! with interned keys and calls nothing else in the interpreter, the `gc`
//! module least of all. It never raises.
//!
//! `"stop"` carries what the collection did (`invoke_gc_callback`, line 1842
//! of `gc_free_threading.c`): `collected`, the unreachable objects it freed,
//! and `uncollectable`, the unreachable ones it could not, which are those
//! with a legacy `tp_del` finalizer (`handle_legacy_finalizers`, line 1696).
//! With `gc.DEBUG_SAVEALL` set the collector counts an object as collected and
//! then keeps it in `gc.garbage` (`delete_garbage`, lines 1664-1670), so under
//! that debug flag `collected` is not memory given back.
//!
//! # What is not here: the number of tracked objects
//!
//! How long a collection takes follows from how many objects the collector
//! tracks, and CPython 3.14 does not say. The free-threaded collector counts
//! the survivors of each collection (`long_lived_total`, line 2224) and keeps
//! the count to itself; `gc.get_objects()` builds a list of every object under
//! a stop-the-world, and `gc.get_stats()` has no such field. What is cheap is
//! `gc.get_count()[0]` (`gc_get_count_impl`, `Modules/gcmodule.c` line 196):
//! container objects allocated minus those freed since the collector last
//! looked, published as `siphon_python_gc_young_objects`. It is an atomic
//! read and a tuple. On a free-threaded build threads report in batches of
//! 512 (`LOCAL_ALLOC_COUNT_THRESHOLD`, line 69), and the count goes back to 0
//! at every collection (line 2164) and every time one is considered and put
//! off (lines 2077-2079), so it shows how fast the heap is growing between
//! collections and never how large it is. The one exact reading of the heap is
//! `siphon_python_gc_frozen_objects`: with `script.gc.freeze_after_load` it is
//! every object tracked when startup finished.

use std::cell::Cell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use prometheus::{
    exponential_buckets, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec,
    IntGauge, Opts, Registry,
};
use pyo3::intern;
use pyo3::prelude::*;
use pyo3::types::PyString;

/// CPython's `NUM_GENERATIONS`: the `generation` a callback can be handed.
const GENERATIONS: [&str; 3] = ["0", "1", "2"];

/// The collectors behind the garbage-collection metrics, with the child of
/// each generation resolved up front.
pub(crate) struct GcCollectors {
    pause_seconds: HistogramVec,
    collections_total: IntCounterVec,
    collected_total: IntCounterVec,
    uncollectable_total: IntCounterVec,
    young_objects: IntGauge,
    frozen_objects: IntGauge,
    pause: [Histogram; 3],
    collections: [IntCounter; 3],
    collected: [IntCounter; 3],
    uncollectable: [IntCounter; 3],
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
        let collected_total = IntCounterVec::new(
            Opts::new(
                "siphon_python_gc_collected_total",
                "Unreachable objects Python's garbage collections freed, by the generation \
                 asked for, as the collector reports them. Objects freed by their reference \
                 count alone never reach the collector and are not counted",
            ),
            &["generation"],
        )?;
        let uncollectable_total = IntCounterVec::new(
            Opts::new(
                "siphon_python_gc_uncollectable_total",
                "Unreachable objects Python's garbage collections found and could not free \
                 (objects with a legacy finalizer; they are in gc.garbage), by the generation \
                 asked for. Anything above 0 is a leak",
            ),
            &["generation"],
        )?;
        let young_objects = IntGauge::new(
            "siphon_python_gc_young_objects",
            "gc.get_count()[0], read once a second: container objects allocated minus those \
             freed since the collector last looked. It returns to 0 at every collection and, \
             on a free-threaded interpreter, every time a collection is considered and put \
             off, so it is how fast the heap grows between collections, not its size: \
             CPython does not expose how many objects the collector tracks without a walk \
             of the heap",
        )?;
        let frozen_objects = IntGauge::new(
            "siphon_python_gc_frozen_objects",
            "Objects gc.freeze() took out of every later collection: all that the collector \
             tracked when startup finished. Set once, by script.gc.freeze_after_load; 0 \
             without it",
        )?;
        let pause = GENERATIONS.map(|generation| pause_seconds.with_label_values(&[generation]));
        let collections =
            GENERATIONS.map(|generation| collections_total.with_label_values(&[generation]));
        let collected =
            GENERATIONS.map(|generation| collected_total.with_label_values(&[generation]));
        let uncollectable =
            GENERATIONS.map(|generation| uncollectable_total.with_label_values(&[generation]));
        Ok(Self {
            pause_seconds,
            collections_total,
            collected_total,
            uncollectable_total,
            young_objects,
            frozen_objects,
            pause,
            collections,
            collected,
            uncollectable,
        })
    }

    /// What a collection that just stopped did. A count CPython did not give
    /// (or gave as something that is not a count) adds nothing.
    fn record_freed(
        &self,
        generation: Option<usize>,
        collected: Option<u64>,
        uncollectable: Option<u64>,
    ) {
        let Some(generation) = generation.filter(|index| *index < GENERATIONS.len()) else {
            return;
        };
        if let Some(collected) = collected {
            self.collected[generation].inc_by(collected);
        }
        if let Some(uncollectable) = uncollectable {
            self.uncollectable[generation].inc_by(uncollectable);
        }
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
        let python = info.py();
        let generation = info
            .get_item(intern!(python, "generation"))
            .and_then(|generation| generation.extract::<usize>())
            .ok();
        self.collectors.record(phase, generation);
        if phase == "stop" {
            let count = |key: &Bound<'_, PyString>| {
                info.get_item(key)
                    .and_then(|count| count.extract::<u64>())
                    .ok()
            };
            self.collectors.record_freed(
                generation,
                count(intern!(python, "collected")),
                count(intern!(python, "uncollectable")),
            );
        }
    }
}

/// The process-wide collectors, built on first use. `None` only if the
/// hardcoded names were rejected, which would be a bug.
fn collectors() -> Option<&'static GcCollectors> {
    static COLLECTORS: OnceLock<Option<GcCollectors>> = OnceLock::new();
    COLLECTORS.get_or_init(|| GcCollectors::new().ok()).as_ref()
}

/// Add the collectors to the metrics registry. Called from `metrics::init`;
/// collections counted before that keep their values, because the registry
/// holds the same collectors.
pub(crate) fn register(registry: &Registry) -> Result<(), prometheus::Error> {
    if let Some(collectors) = collectors() {
        registry.register(Box::new(collectors.pause_seconds.clone()))?;
        registry.register(Box::new(collectors.collections_total.clone()))?;
        registry.register(Box::new(collectors.collected_total.clone()))?;
        registry.register(Box::new(collectors.uncollectable_total.clone()))?;
        registry.register(Box::new(collectors.young_objects.clone()))?;
        registry.register(Box::new(collectors.frozen_objects.clone()))?;
    }
    Ok(())
}

/// Publish `gc.get_count()[0]` as `siphon_python_gc_young_objects`. Called
/// once a second from the interpreter probe's thread, outside the attach it
/// times and with nothing held. Does nothing before the interpreter exists.
///
/// Returns how long the attach waited, without the read that follows it: the
/// probe counts that as an attach wait like its own.
pub(crate) fn sample_young_objects() -> Option<Duration> {
    let collectors = collectors()?;
    let started = Instant::now();
    let (waited, young) = Python::try_attach(|python| {
        let waited = started.elapsed();
        (waited, young_objects(python).ok())
    })?;
    if let Some(young) = young {
        collectors.young_objects.set(young);
    }
    Some(waited)
}

fn young_objects(python: Python<'_>) -> PyResult<i64> {
    python
        .import(intern!(python, "gc"))?
        .call_method0(intern!(python, "get_count"))?
        .get_item(0)?
        .extract()
}

/// Publish what `gc.get_freeze_count()` returned after the startup freeze as
/// `siphon_python_gc_frozen_objects`. Counting is a stop-the-world walk of
/// the heap (`_PyGC_GetFreezeCount`), so it is done once, by the caller, and
/// never when the metrics are read.
pub(crate) fn set_frozen_objects(frozen: u64) {
    if let Some(collectors) = collectors() {
        collectors
            .frozen_objects
            .set(i64::try_from(frozen).unwrap_or(i64::MAX));
    }
}

/// What `siphon_python_gc_frozen_objects` reads.
#[cfg(test)]
pub(crate) fn frozen_objects() -> i64 {
    collectors().map_or(0, |collectors| collectors.frozen_objects.get())
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
    use crate::script::stop_the_world_tests::{collect_garbage_until, in_child, interpreter_build};
    use std::sync::Arc;

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

    #[test]
    fn what_a_collection_freed_is_counted_under_its_generation() {
        let collectors = GcCollectors::new().unwrap();
        collectors.record_freed(Some(2), Some(40), Some(2));
        collectors.record_freed(Some(2), Some(2), None);
        collectors.record_freed(Some(0), None, Some(1));
        assert_eq!(collectors.collected[2].get(), 42);
        assert_eq!(collectors.uncollectable[2].get(), 2);
        assert_eq!(collectors.collected[0].get(), 0);
        assert_eq!(collectors.uncollectable[0].get(), 1);
        assert_eq!(collectors.collected[1].get(), 0);
        assert_eq!(collectors.uncollectable[1].get(), 0);
    }

    #[test]
    fn what_was_freed_without_a_known_generation_is_not_counted() {
        let collectors = GcCollectors::new().unwrap();
        collectors.record_freed(None, Some(5), Some(5));
        collectors.record_freed(Some(3), Some(5), Some(5));
        for generation in 0..GENERATIONS.len() {
            assert_eq!(collectors.collected[generation].get(), 0);
            assert_eq!(collectors.uncollectable[generation].get(), 0);
        }
    }

    /// `"stop"` is where CPython reports what the collection freed; the
    /// counts in a `"start"` are always 0 and are not read.
    #[test]
    fn the_recorder_reads_the_counts_of_a_stop_only() {
        Python::initialize();
        let collectors = leaked_collectors();
        Python::attach(|python| {
            let recorder = Bound::new(python, GcPauseRecorder { collectors }).unwrap();
            let info = pyo3::types::PyDict::new(python);
            info.set_item("generation", 1).unwrap();
            info.set_item("collected", 7).unwrap();
            info.set_item("uncollectable", 3).unwrap();
            recorder.call1(("start", &info)).unwrap();
            assert_eq!(collectors.collected[1].get(), 0);
            assert_eq!(collectors.uncollectable[1].get(), 0);
            recorder.call1(("stop", &info)).unwrap();
            recorder.call1(("stop", &info)).unwrap();
        });
        assert_eq!(collectors.collected[1].get(), 14);
        assert_eq!(collectors.uncollectable[1].get(), 6);
        assert_eq!(collectors.collections[1].get(), 2);
    }

    /// `count` self-referential objects, all dropped: only a collection
    /// frees them. Returns a weak reference to each.
    fn drop_cycles<'py>(python: Python<'py>, count: usize) -> Bound<'py, PyAny> {
        let source = std::ffi::CString::new(concat!(
            "import weakref\n",
            "class Cycle:\n",
            "    pass\n",
            "def drop_cycles(count):\n",
            "    references = []\n",
            "    for _ in range(count):\n",
            "        cycle = Cycle()\n",
            "        cycle.itself = cycle\n",
            "        references.append(weakref.ref(cycle))\n",
            "    return references\n",
        ))
        .unwrap();
        let namespace = pyo3::types::PyDict::new(python);
        python
            .run(source.as_c_str(), Some(&namespace), None)
            .expect("the helper compiles");
        namespace
            .get_item("drop_cycles")
            .expect("lookup")
            .expect("the helper is defined")
            .call1((count,))
            .expect("the cycles are built")
    }

    /// The generations whose collection frees an object made a moment ago.
    /// On a GIL build of 3.14 `gc.collect(1)` is one increment over the old
    /// generation and never reaches a young object.
    fn generations_that_collect_the_young() -> &'static [usize] {
        if interpreter_build() == "GIL" {
            &[2, 0]
        } else {
            &[2, 1, 0]
        }
    }

    fn alive(references: &Bound<'_, PyAny>) -> usize {
        references
            .try_iter()
            .expect("a list of weak references")
            .filter(|reference| {
                let referent = reference
                    .as_ref()
                    .expect("an entry")
                    .call0()
                    .expect("a weak reference");
                !referent.is_none()
            })
            .count()
    }

    /// The real thing: a collection that frees known garbage moves the
    /// counter, and plain cycles are never uncollectable.
    #[test]
    fn freed_cycles_are_counted_and_none_is_uncollectable() {
        const CYCLES: usize = 500;
        Python::initialize();
        install();
        let global = collectors().expect("collectors build");
        // Other tests collect beside this one, into whichever generation
        // they ask for, and their collection may be the one that frees these
        // cycles; the sum over the generations sees them either way.
        let collected = || global.collected.iter().map(IntCounter::get).sum::<u64>();
        let uncollectable = || {
            global
                .uncollectable
                .iter()
                .map(IntCounter::get)
                .sum::<u64>()
        };
        for &generation in generations_that_collect_the_young() {
            let before = collected();
            let deadline = Instant::now() + Duration::from_secs(30);
            Python::attach(|python| {
                let references = drop_cycles(python, CYCLES);
                while alive(&references) > 0 {
                    collect(python, generation);
                    assert!(Instant::now() < deadline, "the cycles were never collected");
                }
            });
            assert!(
                collected() - before >= CYCLES as u64,
                "{CYCLES} cycles were freed, {} counted",
                collected() - before
            );
        }
        assert_eq!(uncollectable(), 0, "a plain cycle is collectable");
    }

    /// With nothing else collecting, the generation label is exact.
    #[test]
    fn freed_cycles_are_counted_under_the_generation_collected() {
        const CYCLES: usize = 300;
        if !in_child(
            concat!(
                module_path!(),
                "::freed_cycles_are_counted_under_the_generation_collected"
            ),
            Duration::from_secs(60),
        ) {
            return;
        }
        Python::initialize();
        install();
        let global = collectors().expect("collectors build");
        let collected = || [0, 1, 2].map(|generation: usize| global.collected[generation].get());
        Python::attach(|python| {
            // Only the collections asked for below may run.
            python
                .import("gc")
                .and_then(|gc| gc.call_method0("disable"))
                .expect("gc.disable");
            collect(python, 2);
            for &generation in generations_that_collect_the_young() {
                let before = collected();
                let references = drop_cycles(python, CYCLES);
                assert_eq!(alive(&references), CYCLES, "only a collection frees them");
                collect(python, generation);
                assert_eq!(alive(&references), 0);
                for (other, after) in collected().into_iter().enumerate() {
                    let moved = after - before[other];
                    if other == generation {
                        assert!(moved >= CYCLES as u64, "generation {generation}: {moved}");
                    } else {
                        assert_eq!(moved, 0, "generation {other} did not collect");
                    }
                }
            }
        });
        for generation in 0..GENERATIONS.len() {
            assert_eq!(global.uncollectable[generation].get(), 0);
        }
    }

    #[test]
    fn the_young_count_is_sampled_from_the_interpreter() {
        if !in_child(
            concat!(
                module_path!(),
                "::the_young_count_is_sampled_from_the_interpreter"
            ),
            Duration::from_secs(60),
        ) {
            return;
        }
        // Before the interpreter exists there is nothing to read, and the
        // sampler must not be what starts it.
        assert_eq!(sample_young_objects(), None);
        let global = collectors().expect("collectors build");
        assert_eq!(global.young_objects.get(), 0);
        assert_eq!(unsafe { pyo3::ffi::Py_IsInitialized() }, 0);

        Python::initialize();
        Python::attach(|python| {
            // No automatic collection may reset the count under the test.
            let gc = python.import("gc").unwrap();
            gc.call_method0("disable").unwrap();
            gc.call_method0("collect").unwrap();
            let kept = python
                .eval(c"[[] for _ in range(20000)]", None, None)
                .unwrap();
            let waited = python.detach(sample_young_objects);
            assert!(waited.is_some(), "the sampler attached");
            let young = global.young_objects.get();
            let expected: i64 = gc
                .call_method0("get_count")
                .unwrap()
                .get_item(0)
                .unwrap()
                .extract()
                .unwrap();
            // A free-threaded thread reports in batches of 512.
            assert!(
                young >= 19_000,
                "20000 lists are new, the gauge says {young}"
            );
            assert!(
                (expected - young).abs() < 1_000,
                "{expected} against {young}"
            );
            gc.call_method0("collect").unwrap();
            python.detach(sample_young_objects);
            assert!(
                global.young_objects.get() < 1_000,
                "a collection starts the count again, the gauge says {}",
                global.young_objects.get()
            );
            drop(kept);
        });
    }

    /// The interpreter probe is what samples in a running process.
    #[test]
    fn the_interpreter_probe_publishes_the_young_count() {
        if !in_child(
            concat!(
                module_path!(),
                "::the_interpreter_probe_publishes_the_young_count"
            ),
            Duration::from_secs(60),
        ) {
            return;
        }
        Python::initialize();
        let global = collectors().expect("collectors build");
        let _kept = Python::attach(|python| {
            let gc = python.import("gc").unwrap();
            gc.call_method0("disable").unwrap();
            gc.call_method0("collect").unwrap();
            python
                .eval(c"[[] for _ in range(20000)]", None, None)
                .unwrap()
                .unbind()
        });
        assert_eq!(global.young_objects.get(), 0, "nothing has sampled yet");

        let wait = Arc::new(crate::script::liveness::AttachWait::new().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let probe = {
            let (wait, stop) = (Arc::clone(&wait), Arc::clone(&stop));
            std::thread::spawn(move || {
                crate::script::liveness::run_interpreter_probe(
                    Arc::new(crate::script::liveness::Beat::default()),
                    Duration::from_millis(1),
                    stop,
                    Some(&wait),
                    crate::script::liveness::pinned_attach_probe(),
                )
            })
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        while global.young_objects.get() < 19_000 {
            assert!(
                Instant::now() < deadline,
                "the probe never published the young count: {}",
                global.young_objects.get()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        stop.store(true, Ordering::Relaxed);
        probe.join().unwrap();
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
            for counter in collectors.collections.iter().take(GENERATIONS.len()) {
                assert_eq!(counter.get(), 0);
            }

            // A known generation, and counts that are no counts.
            info.set_item("generation", 2).unwrap();
            recorder.call1(("stop", &info)).expect("no counts at all");
            for malformed in [
                c"None",
                c"'many'",
                c"-5",
                c"1.5",
                c"2 ** 80",
                c"[]",
                c"{'collected': 1}",
            ] {
                let malformed = python.eval(malformed, None, None).unwrap();
                info.set_item("collected", &malformed).unwrap();
                info.set_item("uncollectable", &malformed).unwrap();
                recorder
                    .call1(("stop", &info))
                    .expect("a count that is not a count");
            }
            // An `info` whose every lookup raises, and one that is a list.
            let raising = python
                .eval(
                    c"type('Raising', (), {'__getitem__': lambda self, key: 1 // 0})()",
                    None,
                    None,
                )
                .unwrap();
            recorder
                .call1(("stop", &raising))
                .expect("info raises on lookup");
            recorder
                .call1(("stop", pyo3::types::PyList::empty(python)))
                .expect("info is a list");
            assert!(
                pyo3::PyErr::take(python).is_none(),
                "nothing is left raised"
            );
        });
        // The malformed stops of generation 2 are still collections.
        assert_eq!(collectors.collections[2].get(), 8);
        assert_eq!(collectors.collections[0].get(), 0);
        assert_eq!(collectors.collections[1].get(), 0);
        for generation in 0..GENERATIONS.len() {
            assert_eq!(collectors.collected[generation].get(), 0);
            assert_eq!(collectors.uncollectable[generation].get(), 0);
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
            direct_dispatch: Default::default(),
            gc: Default::default(),
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
        assert!(output.contains("siphon_python_gc_collected_total{generation=\"2\"}"));
        assert!(output.contains("siphon_python_gc_uncollectable_total{generation=\"2\"} 0"));
        assert!(output.contains("siphon_python_gc_young_objects "));
        assert!(output.contains("siphon_python_gc_frozen_objects "));
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
