//! `script.gc`: what siphon tells Python's cyclic garbage collector, once, when
//! startup has finished.
//!
//! On a free-threaded interpreter every collection stops every thread and
//! walks the whole heap, so its length follows the number of objects the
//! collector tracks, most of which a long-running process built at startup and
//! will never free. Two settings act on that, both off unless configured (see
//! [`ScriptGcConfig`] for what each does inside CPython, with line references):
//!
//! - `threshold` is `gc.set_threshold(threshold)`: how many new container
//!   objects it takes before a collection is considered.
//! - `freeze_after_load` is one full collection followed by `gc.freeze()`:
//!   everything alive at that point is left out of every later collection.
//!
//! # Frozen once, and never again on a reload
//!
//! A frozen object is never examined again, so a reference cycle among frozen
//! objects that becomes garbage is never freed. A script reload makes garbage
//! of exactly that kind: the replaced module, its functions and their globals
//! refer to each other. Freezing after every reload would therefore strand one
//! copy of the script's modules per reload, and would also freeze whatever
//! calls happened to be in flight, cycles included. Thawing first
//! (`gc.unfreeze()`, collect, freeze) avoids the first and not the second, and
//! costs three walks of the heap and a full collection under traffic.
//!
//! So the freeze happens once. Modules a reload builds are not frozen and are
//! collected as usual when the next reload replaces them; the copy frozen at
//! startup stays allocated after the first reload, a one-off cost of the size
//! of the script's own module-level objects.
//!
//! # The freeze wants a threshold
//!
//! CPython does not start an automatic collection while fewer objects are new
//! than a quarter of those that survived the last one, and it counts only
//! unfrozen survivors (`gc_free_threading.c` lines 2099 and 1214 in 3.14.2).
//! A large unfrozen heap therefore keeps the collector quiet for a long time;
//! frozen, it no longer does. Churning 3 million cyclic objects over a heap of
//! 2.1 million took 2 collections unfrozen, 24 with the freeze alone (three
//! times the pause in total) and 1 with the freeze and a threshold of 500,000.
//! [`apply`] warns when it freezes without a threshold and names one.
//!
//! Both calls run attached and neither waits on anything but the collector
//! itself: `gc.freeze()` and `gc.get_freeze_count()` each stop the world for
//! one walk of the heap, which at startup holds nobody up.

use pyo3::intern;
use pyo3::prelude::*;
use tracing::{error, info, warn};

use crate::config::ScriptGcConfig;

/// Apply `script.gc`. Call once, when the script has loaded and the
/// extensions have started; a reload does not call it (see the module docs).
///
/// A setting the interpreter refuses is logged as an error and left as it
/// was: the process serves either way, with the collector CPython gave it.
pub(crate) fn apply(config: &ScriptGcConfig) {
    if let Some(threshold) = config.threshold {
        let set = Python::attach(|python| {
            set_threshold(python, threshold).map_err(|error| error.to_string())
        });
        match set {
            Ok(effective) => info!(
                threshold = effective,
                "python garbage collector: script.gc.threshold applied"
            ),
            Err(error) => error!(
                %error,
                threshold,
                "could not apply script.gc.threshold; the collector keeps its threshold"
            ),
        }
    }
    if config.freeze_after_load {
        let frozen = Python::attach(|python| freeze(python).map_err(|error| error.to_string()));
        match frozen {
            Ok(frozen) => {
                super::gc_metrics::set_frozen_objects(frozen);
                info!(
                    frozen_objects = frozen,
                    "python garbage collector: startup objects frozen \
                     (script.gc.freeze_after_load); a script reload does not freeze again"
                );
                if let Some(suggested) = threshold_to_go_with(config, frozen) {
                    warn!(
                        suggested_threshold = suggested,
                        "script.gc.freeze_after_load is on without script.gc.threshold: the \
                         frozen objects no longer hold automatic collections back, so they \
                         get shorter and can get far more frequent; set script.gc.threshold \
                         (a quarter of the frozen objects restores the old floor)"
                    );
                }
            }
            Err(error) => error!(
                %error,
                "could not apply script.gc.freeze_after_load; nothing is frozen"
            ),
        }
    }
}

/// The threshold to suggest when `frozen` objects were frozen and none is
/// configured: the quarter of the heap CPython stops counting once it is
/// frozen, within what the configuration accepts. `None` when a threshold is
/// set, or when so little was frozen that CPython's own 2000 is the floor
/// already.
fn threshold_to_go_with(config: &ScriptGcConfig, frozen: u64) -> Option<u32> {
    /// CPython's default first threshold.
    const DEFAULT_THRESHOLD: u64 = 2000;
    if config.threshold.is_some() {
        return None;
    }
    let quarter = frozen / 4;
    if quarter <= DEFAULT_THRESHOLD {
        return None;
    }
    Some(
        u32::try_from(quarter)
            .unwrap_or(u32::MAX)
            .min(crate::config::GC_THRESHOLD_MAX),
    )
}

/// `gc.set_threshold(threshold)`, and what `gc.get_threshold()` says after.
fn set_threshold(python: Python<'_>, threshold: u32) -> PyResult<u32> {
    let gc = python.import(intern!(python, "gc"))?;
    gc.call_method1(intern!(python, "set_threshold"), (threshold,))?;
    gc.call_method0(intern!(python, "get_threshold"))?
        .get_item(0)?
        .extract()
}

/// Collect, freeze what is left, and count it.
fn freeze(python: Python<'_>) -> PyResult<u64> {
    let gc = python.import(intern!(python, "gc"))?;
    // First, so garbage that startup left behind is freed and not frozen.
    gc.call_method0(intern!(python, "collect"))?;
    gc.call_method0(intern!(python, "freeze"))?;
    gc.call_method0(intern!(python, "get_freeze_count"))?
        .extract()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::stop_the_world_tests::in_child;
    use std::ffi::CString;
    use std::time::Duration;

    // Every test here changes the collector of the whole interpreter, so each
    // runs in a child process of its own.
    const BUDGET: Duration = Duration::from_secs(120);

    /// `make_cycles(count)` returns `count` objects that each refer to
    /// themselves, and `alive(references)` counts the weak references whose
    /// object still exists.
    fn helpers(python: Python<'_>) -> Bound<'_, pyo3::types::PyDict> {
        let source = CString::new(concat!(
            "import gc, weakref\n",
            "class Cycle:\n",
            "    pass\n",
            "def make_cycles(count):\n",
            "    cycles = []\n",
            "    for _ in range(count):\n",
            "        cycle = Cycle()\n",
            "        cycle.itself = cycle\n",
            "        cycles.append(cycle)\n",
            "    return cycles\n",
            "def weak(cycles):\n",
            "    return [weakref.ref(cycle) for cycle in cycles]\n",
            "def alive(references):\n",
            "    return sum(1 for reference in references if reference() is not None)\n",
        ))
        .unwrap();
        let namespace = pyo3::types::PyDict::new(python);
        python
            .run(source.as_c_str(), Some(&namespace), None)
            .expect("the helpers compile");
        namespace
    }

    fn call<'py>(
        namespace: &Bound<'py, pyo3::types::PyDict>,
        function: &str,
        argument: impl pyo3::IntoPyObject<'py>,
    ) -> Bound<'py, PyAny> {
        namespace
            .get_item(function)
            .expect("lookup")
            .expect("a helper")
            .call1((argument,))
            .expect("the helper runs")
    }

    fn alive(namespace: &Bound<'_, pyo3::types::PyDict>, references: &Bound<'_, PyAny>) -> usize {
        call(namespace, "alive", references).extract().unwrap()
    }

    /// `script.gc` as a whole configuration file gives it, so a test that
    /// applies the result proves the key wired from the YAML on.
    fn configured(gc: &str) -> ScriptGcConfig {
        let yaml = format!(
            concat!(
                "listen:\n  udp:\n    - \"0.0.0.0:5060\"\n",
                "domain:\n  local:\n    - \"example.com\"\n",
                "script:\n  path: \"scripts/proxy_default.py\"\n  gc:\n    {gc}\n",
            ),
            gc = gc
        );
        crate::config::Config::from_str(&yaml)
            .expect("the configuration parses")
            .script
            .gc
    }

    fn gc_call<'py>(python: Python<'py>, method: &str) -> Bound<'py, PyAny> {
        python
            .import("gc")
            .and_then(|gc| gc.call_method0(method))
            .expect("the gc call")
    }

    fn thresholds(python: Python<'_>) -> (u32, u32, u32) {
        gc_call(python, "get_threshold").extract().unwrap()
    }

    fn freeze_count(python: Python<'_>) -> u64 {
        gc_call(python, "get_freeze_count").extract().unwrap()
    }

    #[test]
    fn a_freeze_without_a_threshold_is_given_one_to_set() {
        let freeze_only = ScriptGcConfig {
            freeze_after_load: true,
            threshold: None,
        };
        assert_eq!(threshold_to_go_with(&freeze_only, 2_100_000), Some(525_000));
        assert_eq!(threshold_to_go_with(&freeze_only, 8_004), Some(2_001));
        // CPython's 2000 is already the floor for a heap this small.
        assert_eq!(threshold_to_go_with(&freeze_only, 8_000), None);
        assert_eq!(threshold_to_go_with(&freeze_only, 0), None);
        // Never more than the configuration would accept.
        assert_eq!(
            threshold_to_go_with(&freeze_only, u64::MAX),
            Some(crate::config::GC_THRESHOLD_MAX)
        );
        // A configured threshold is the operator's answer already.
        let both = ScriptGcConfig {
            freeze_after_load: true,
            threshold: Some(2000),
        };
        assert_eq!(threshold_to_go_with(&both, 2_100_000), None);
    }

    #[test]
    fn nothing_configured_changes_nothing() {
        if !in_child(
            concat!(module_path!(), "::nothing_configured_changes_nothing"),
            BUDGET,
        ) {
            return;
        }
        Python::initialize();
        let before = Python::attach(thresholds);
        apply(&ScriptGcConfig::default());
        Python::attach(|python| {
            assert_eq!(thresholds(python), before);
            assert_eq!(freeze_count(python), 0);
        });
        assert_eq!(crate::script::gc_metrics::frozen_objects(), 0);
    }

    #[test]
    fn a_configured_threshold_reaches_the_interpreter() {
        if !in_child(
            concat!(
                module_path!(),
                "::a_configured_threshold_reaches_the_interpreter"
            ),
            BUDGET,
        ) {
            return;
        }
        Python::initialize();
        let before = Python::attach(thresholds);
        assert_ne!(before.0, 54_321);
        apply(&configured("threshold: 54321"));
        Python::attach(|python| {
            // Only the first threshold is set; the others stay CPython's.
            assert_eq!(thresholds(python), (54_321, before.1, before.2));
            assert_eq!(freeze_count(python), 0);
            assert!(gc_call(python, "isenabled").extract::<bool>().unwrap());
        });

        // The largest value the config accepts is one CPython takes.
        let largest = crate::config::GC_THRESHOLD_MAX;
        apply(&ScriptGcConfig {
            freeze_after_load: false,
            threshold: Some(largest),
        });
        assert_eq!(Python::attach(thresholds).0, largest);
    }

    /// A raised threshold really holds automatic collections back, and the
    /// default really runs them: the knob changes what the collector does,
    /// not only what `gc.get_threshold()` reports.
    #[test]
    fn a_raised_threshold_holds_automatic_collections_back() {
        if !in_child(
            concat!(
                module_path!(),
                "::a_raised_threshold_holds_automatic_collections_back"
            ),
            BUDGET,
        ) {
            return;
        }
        Python::initialize();
        // 200,000 dropped cycles: far past CPython's 2000 and its forced
        // collection at 40 times that, far short of 40 times a million.
        let churn = CString::new(concat!(
            "import gc\n",
            "class Cycle:\n",
            "    pass\n",
            "def churn():\n",
            "    before = sum(stats['collections'] for stats in gc.get_stats())\n",
            "    for _ in range(200000):\n",
            "        cycle = Cycle()\n",
            "        cycle.itself = cycle\n",
            "    return sum(stats['collections'] for stats in gc.get_stats()) - before\n",
            "collections = churn()\n",
        ))
        .unwrap();
        let collections = || {
            Python::attach(|python| {
                let namespace = pyo3::types::PyDict::new(python);
                python
                    .run(churn.as_c_str(), Some(&namespace), None)
                    .unwrap();
                namespace
                    .get_item("collections")
                    .unwrap()
                    .unwrap()
                    .extract::<u64>()
                    .unwrap()
            })
        };
        assert!(
            collections() > 0,
            "CPython's own threshold collects under this churn"
        );
        apply(&ScriptGcConfig {
            freeze_after_load: false,
            threshold: Some(1_000_000),
        });
        assert_eq!(collections(), 0, "nothing is collected below the threshold");
    }

    #[test]
    fn freezing_takes_what_is_alive_out_of_later_collections() {
        if !in_child(
            concat!(
                module_path!(),
                "::freezing_takes_what_is_alive_out_of_later_collections"
            ),
            BUDGET,
        ) {
            return;
        }
        const CYCLES: usize = 200;
        Python::initialize();
        Python::attach(|python| {
            let namespace = helpers(python);
            // Alive at the freeze.
            let kept = call(&namespace, "make_cycles", CYCLES);
            let kept_references = call(&namespace, "weak", &kept);
            // Garbage at the freeze: built and dropped, never collected.
            python
                .import("gc")
                .unwrap()
                .call_method0("disable")
                .unwrap();
            let dropped = call(&namespace, "make_cycles", CYCLES);
            let dropped_references = call(&namespace, "weak", &dropped);
            drop(dropped);
            assert_eq!(alive(&namespace, &dropped_references), CYCLES);
            python.import("gc").unwrap().call_method0("enable").unwrap();
            assert_eq!(freeze_count(python), 0);

            let gc = configured("freeze_after_load: true");
            let before = thresholds(python);
            python.detach(|| apply(&gc));

            let frozen = freeze_count(python);
            assert!(frozen >= CYCLES as u64, "{frozen} objects frozen");
            assert_eq!(thresholds(python), before);
            assert_eq!(
                crate::script::gc_metrics::frozen_objects(),
                i64::try_from(frozen).unwrap()
            );
            assert_eq!(
                alive(&namespace, &dropped_references),
                0,
                "garbage is collected before the freeze, not frozen"
            );

            // The frozen cycles die, and no collection finds them.
            drop(kept);
            for generation in [0, 1, 2, 2] {
                python
                    .import("gc")
                    .unwrap()
                    .call_method1("collect", (generation,))
                    .unwrap();
            }
            assert_eq!(
                alive(&namespace, &kept_references),
                CYCLES,
                "a frozen cycle is never collected"
            );

            // What is built after the freeze is collected as ever.
            let later = call(&namespace, "make_cycles", CYCLES);
            let later_references = call(&namespace, "weak", &later);
            drop(later);
            python
                .import("gc")
                .unwrap()
                .call_method0("collect")
                .unwrap();
            assert_eq!(alive(&namespace, &later_references), 0);
            // Nothing more was frozen. Fewer may be: a frozen object whose
            // reference count reaches zero is freed like any other.
            assert!(freeze_count(python) <= frozen);
        });
    }

    /// The reload decision, proven: the startup copy of the script's module
    /// is frozen and stays; every later copy is collected when it is
    /// replaced, and nothing more is ever frozen.
    #[test]
    fn a_reload_after_the_freeze_strands_the_startup_module_only() {
        if !in_child(
            concat!(
                module_path!(),
                "::a_reload_after_the_freeze_strands_the_startup_module_only"
            ),
            BUDGET,
        ) {
            return;
        }
        const RELOADS: usize = 6;
        let directory = tempfile::tempdir().unwrap();
        let script = directory.path().join("gc_control_reload.py");
        // Each load leaves a weak reference to an object its module owns.
        // The handler keeps the module's globals alive while the script
        // runs, and is in a cycle with them, as every handler is.
        let source = |round: usize| {
            format!(
                concat!(
                    "import builtins, weakref\n",
                    "from siphon import proxy\n",
                    "ROUND = {round}\n",
                    "class Marker:\n",
                    "    pass\n",
                    "marker = Marker()\n",
                    "marker.namespace = globals()\n",
                    "@proxy.on_request\n",
                    "def route(request):\n",
                    "    return marker\n",
                    "if not hasattr(builtins, 'gc_control_markers'):\n",
                    "    builtins.gc_control_markers = []\n",
                    "builtins.gc_control_markers.append(weakref.ref(marker))\n",
                ),
                round = round
            )
        };
        std::fs::write(&script, source(0)).unwrap();
        let config = crate::config::ScriptConfig {
            path: script.to_str().unwrap().to_owned(),
            reload: crate::config::ReloadMode::Sighup,
            gc: ScriptGcConfig {
                freeze_after_load: true,
                threshold: None,
            },
            ..Default::default()
        };
        let engine = crate::script::engine::ScriptEngine::new(&config).expect("initial load");
        apply(&config.gc);
        let frozen = Python::attach(freeze_count);
        assert!(frozen > 0, "the freeze ran");

        let markers_alive = || {
            Python::attach(|python| {
                python
                    .import("gc")
                    .unwrap()
                    .call_method0("collect")
                    .unwrap();
                python
                    .eval(
                        c"[reference().namespace['ROUND'] \
                           for reference in __import__('builtins').gc_control_markers \
                           if reference() is not None]",
                        None,
                        None,
                    )
                    .unwrap()
                    .extract::<Vec<usize>>()
                    .unwrap()
            })
        };
        assert_eq!(markers_alive(), [0]);
        for round in 1..=RELOADS {
            std::fs::write(&script, source(round)).unwrap();
            engine.reload().expect("reload");
            assert_eq!(
                markers_alive(),
                [0, round],
                "the frozen startup module and the running one, nothing between"
            );
            let frozen_now = Python::attach(freeze_count);
            assert!(
                frozen_now <= frozen,
                "a reload freezes nothing: {frozen_now} frozen, {frozen} at startup"
            );
        }
        assert_eq!(
            crate::script::gc_metrics::frozen_objects(),
            i64::try_from(frozen).unwrap(),
            "the gauge keeps the count taken at the freeze"
        );
    }
}
