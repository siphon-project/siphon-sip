//! `script.direct_dispatch`: the switch and its self-test, the count of calls
//! the admission bound refused, and the memory of which handlers use asyncio.

use std::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use dashmap::DashMap;
use pyo3::intern;
use pyo3::prelude::*;
use tracing::{debug, error, info, warn};

use super::drive::{locked, start_unchecked, DriveHandle};
use super::python::helpers;
use crate::script::async_pool::AsyncPool;

// ---------------------------------------------------------------------------
// The switch.
// ---------------------------------------------------------------------------

const OFF: u8 = 0;
const ON: u8 = 1;

/// `script.direct_dispatch`, and only on once the self-test has passed on
/// this interpreter.
static MODE: AtomicU8 = AtomicU8::new(OFF);

/// Handlers in flight one runner admits before it is full.
pub const DEFAULT_ADMISSION_LIMIT: usize = 4096;

static ADMISSION_LIMIT: AtomicUsize = AtomicUsize::new(DEFAULT_ADMISSION_LIMIT);

pub(crate) fn enabled() -> bool {
    MODE.load(Ordering::Acquire) == ON
}

/// Handlers in flight one runner admits right now.
pub(super) fn admission_limit() -> usize {
    ADMISSION_LIMIT.load(Ordering::Acquire)
}

/// How long the self-test may take. It is two thread handoffs on an idle
/// process; the bound is for an interpreter on which it never finishes.
const SELF_TEST_PATIENCE: Duration = Duration::from_secs(5);

/// Apply `script.direct_dispatch`. Turning it on drives one handler through a
/// direct step, an await and a hand-over on `pool` first, and leaves it off,
/// saying so, if any of that misbehaves on this interpreter.
///
/// Call released from the interpreter.
pub fn configure(on: bool, pool: &Arc<AsyncPool>) -> bool {
    if !on {
        MODE.store(OFF, Ordering::Release);
        return false;
    }
    match self_test(pool) {
        Ok(()) => {
            MODE.store(ON, Ordering::Release);
            info!(
                "script.direct_dispatch is on: async handlers called through \
                 the script handle are stepped on their asyncio driver without \
                 a task while they await only siphon's awaitables"
            );
            true
        }
        Err(reason) => {
            MODE.store(OFF, Ordering::Release);
            error!(
                %reason,
                "script.direct_dispatch failed its self-test on this \
                 interpreter and stays off; async handlers run as asyncio tasks"
            );
            false
        }
    }
}

/// Done-callback of the self-test coroutine.
#[pyclass(frozen)]
struct SelfTestReport {
    sender: Mutex<Option<std::sync::mpsc::Sender<bool>>>,
}

#[pymethods]
impl SelfTestReport {
    fn __call__(&self, passed: bool) {
        let sender = locked(&self.sender).take();
        if let Some(sender) = sender {
            let _ = sender.send(passed);
        }
    }
}

fn self_test(pool: &Arc<AsyncPool>) -> Result<(), String> {
    let (sender, receiver) = std::sync::mpsc::channel();
    let started = Python::attach(|python| -> Result<DriveHandle, String> {
        let helpers = helpers(python).ok_or("the helpers could not be built")?;
        let text = |error: PyErr| error.to_string();
        let report = Py::new(
            python,
            SelfTestReport {
                sender: Mutex::new(Some(sender)),
            },
        )
        .map_err(text)?;
        let coroutine = helpers
            .self_test
            .bind(python)
            .call1((&helpers.self_test_awaitable, report))
            .map_err(text)?;
        match start_unchecked(pool, python, &coroutine, None) {
            Ok(Some(handle)) => Ok(handle),
            Ok(None) => {
                let _ = coroutine.call_method0(intern!(python, "close"));
                Err("the self-test handler was not taken by a runner".to_string())
            }
            Err(error) => Err(text(error)),
        }
    })?;
    // On a runtime worker the wait is handed off, so the worker's tasks (the
    // self-test's own awaitable among them) keep running.
    let on_multi_thread_runtime = tokio::runtime::Handle::try_current().is_ok_and(|handle| {
        matches!(
            handle.runtime_flavor(),
            tokio::runtime::RuntimeFlavor::MultiThread
        )
    });
    let wait = || receiver.recv_timeout(SELF_TEST_PATIENCE);
    let passed = if on_multi_thread_runtime {
        crate::script::blocking::blocking_released(wait)
    } else {
        crate::script::blocking::released(wait)
    };
    // Held until the verdict is in: dropping it is not what ends the test.
    drop(started);
    match passed {
        Ok(true) => Ok(()),
        Ok(false) => Err("a handler saw the wrong loop, task or value".into()),
        Err(_) => Err("the handler did not finish".into()),
    }
}

/// Turn direct dispatch on or off as the configuration would, without the
/// self-test deciding.
#[cfg(test)]
pub(crate) fn set_enabled_for_test(on: bool) {
    MODE.store(if on { ON } else { OFF }, Ordering::Release);
}

#[cfg(test)]
pub(crate) fn set_admission_limit_for_test(limit: usize) {
    ADMISSION_LIMIT.store(limit, Ordering::Release);
}

// ---------------------------------------------------------------------------
// Counters.
// ---------------------------------------------------------------------------

static ADMISSION_REJECTED: AtomicU64 = AtomicU64::new(0);
static DEMOTIONS: AtomicU64 = AtomicU64::new(0);

/// Calls refused because every runner was full, since the process started.
pub fn admission_rejected() -> u64 {
    ADMISSION_REJECTED.load(Ordering::Relaxed)
}

/// Handlers remembered as asyncio users since the process started.
pub fn demotions() -> u64 {
    DEMOTIONS.load(Ordering::Relaxed)
}

/// `siphon_runner_admission_rejected_total`. Built on first use; `None` only
/// if the hardcoded name were rejected, which would be a bug.
fn admission_rejected_total() -> Option<&'static prometheus::IntCounter> {
    static COUNTER: OnceLock<Option<prometheus::IntCounter>> = OnceLock::new();
    COUNTER
        .get_or_init(|| {
            prometheus::IntCounter::new(
                "siphon_runner_admission_rejected_total",
                "Async handler calls refused because every asyncio driver's runner was at \
                 its in-flight limit",
            )
            .ok()
        })
        .as_ref()
}

/// Add the runner's counters to the metrics registry.
pub(crate) fn register(registry: &prometheus::Registry) -> Result<(), prometheus::Error> {
    if let Some(counter) = admission_rejected_total() {
        registry.register(Box::new(counter.clone()))?;
    }
    Ok(())
}

/// Seconds between two "every runner is full" warnings.
const REJECTION_WARN_INTERVAL_SECS: u64 = 5;

pub(super) fn count_rejection(limit: usize) {
    ADMISSION_REJECTED.fetch_add(1, Ordering::Relaxed);
    if let Some(counter) = admission_rejected_total() {
        counter.inc();
    }
    static LAST_WARNED: AtomicU64 = AtomicU64::new(0);
    static PROCESS_START: OnceLock<std::time::Instant> = OnceLock::new();
    // Offset by one so the first rejection, at second 0, still warns.
    let now = PROCESS_START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_secs()
        + 1;
    let last = LAST_WARNED.load(Ordering::Relaxed);
    if (last == 0 || now.saturating_sub(last) >= REJECTION_WARN_INTERVAL_SECS)
        && LAST_WARNED
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        warn!(
            limit,
            rejected_total = ADMISSION_REJECTED.load(Ordering::Relaxed),
            "every asyncio driver's runner is at its in-flight limit: async \
             handler calls are being refused. Handlers are awaiting something \
             slow, or arriving faster than they finish."
        );
    }
}

// ---------------------------------------------------------------------------
// Which handlers are driven directly.
// ---------------------------------------------------------------------------

/// What a handler is remembered by: the callable it was registered as, or its
/// coroutine's code object when the caller has no callable to name. Keyed by
/// address; holding the object is what keeps the address unique.
#[derive(Clone)]
pub(super) struct DemotionKey(Arc<Py<PyAny>>);

impl DemotionKey {
    pub(super) fn new(object: Arc<Py<PyAny>>) -> Self {
        Self(object)
    }

    fn address(&self) -> usize {
        self.0.as_ptr() as usize
    }
}

static DEMOTED: OnceLock<DashMap<usize, DemotionKey>> = OnceLock::new();

fn demoted() -> &'static DashMap<usize, DemotionKey> {
    DEMOTED.get_or_init(DashMap::new)
}

/// Forget which handlers use asyncio. Called on reload, which replaces the
/// callables and code objects.
pub(crate) fn clear_demoted() {
    let Some(map) = DEMOTED.get() else { return };
    // Taken out one by one and dropped after: letting go of the last
    // reference to a callable can run Python, which must not happen under
    // one of the map's locks.
    let addresses: Vec<usize> = map.iter().map(|entry| *entry.key()).collect();
    let forgotten: Vec<DemotionKey> = addresses
        .into_iter()
        .filter_map(|address| map.remove(&address).map(|(_, key)| key))
        .collect();
    drop(forgotten);
}

/// Whether this handler used asyncio on an earlier call. Such a handler
/// starts as a task: handing it over each time would cost more than the
/// direct steps save.
pub(super) fn is_demoted(key: &DemotionKey) -> bool {
    demoted().contains_key(&key.address())
}

#[cfg(test)]
pub(crate) fn demoted_handlers() -> usize {
    DEMOTED.get().map_or(0, DashMap::len)
}

pub(super) fn demote(python: Python<'_>, key: &DemotionKey) {
    let address = key.address();
    if demoted().contains_key(&address) {
        return;
    }
    DEMOTIONS.fetch_add(1, Ordering::Relaxed);
    debug!(
        handler = %key
            .0
            .bind(python)
            .getattr(intern!(python, "__qualname__"))
            .or_else(|_| key.0.bind(python).getattr(intern!(python, "co_qualname")))
            .and_then(|name| name.extract::<String>())
            .unwrap_or_else(|_| "<unknown>".to_string()),
        "async handler uses asyncio beyond siphon's awaitables; it starts as \
         an asyncio task from now on"
    );
    demoted().insert(address, key.clone());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rejection_counter_is_registered_and_counts() {
        let registry = prometheus::Registry::new();
        register(&registry).expect("registers");
        let before = admission_rejected();
        count_rejection(DEFAULT_ADMISSION_LIMIT);
        count_rejection(DEFAULT_ADMISSION_LIMIT);
        assert_eq!(admission_rejected() - before, 2);
        let families = registry.gather();
        let family = families
            .iter()
            .find(|family| family.name() == "siphon_runner_admission_rejected_total")
            .expect("the counter is exported");
        assert!(family.get_metric()[0].get_counter().value() >= 2.0);
    }

    /// A handler is remembered by the address of the object it is keyed on,
    /// which the memory keeps alive, and forgotten on a reload.
    #[test]
    fn a_demoted_handler_is_remembered_until_cleared() {
        Python::initialize();
        let _serial = crate::script::async_pool::pool_test_guard();
        Python::attach(|python| {
            let object = Arc::new(python.eval(c"lambda: None", None, None).unwrap().unbind());
            let key = DemotionKey::new(Arc::clone(&object));
            let other = DemotionKey::new(Arc::new(
                python.eval(c"lambda: None", None, None).unwrap().unbind(),
            ));
            assert!(!is_demoted(&key));
            let before = demotions();
            demote(python, &key);
            demote(python, &key);
            assert_eq!(demotions() - before, 1, "remembered once");
            assert!(is_demoted(&key));
            assert!(is_demoted(&DemotionKey::new(object)), "by identity");
            assert!(!is_demoted(&other));
            clear_demoted();
            assert!(!is_demoted(&key));
            assert_eq!(demoted_handlers(), 0);
        });
    }

    #[test]
    fn the_switch_is_off_until_it_is_turned_on() {
        let _serial = crate::script::async_pool::pool_test_guard();
        assert!(!enabled());
        set_enabled_for_test(true);
        assert!(enabled());
        set_enabled_for_test(false);
        assert!(!enabled());
        assert_eq!(admission_limit(), DEFAULT_ADMISSION_LIMIT);
    }
}
