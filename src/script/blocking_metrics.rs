//! How many threads are parked in siphon's blocking helpers right now.
//!
//! Every wait through [`super::blocking::blocking_released`],
//! [`super::blocking::block_on_released`] and
//! [`super::blocking::detach_block_on`] holds a [`WaitGuard`] for its
//! duration. The guard raises `siphon_blocking_waits_in_flight` on entry and
//! lowers it on drop, so a wait that panics still gives its slot back, and
//! counts the wait in `siphon_blocking_waits_total`.
//!
//! Tokio's own blocking-pool metrics need `--cfg tokio_unstable`; these count
//! siphon's waits instead, which is what an operator wants to see anyway: a
//! gauge that stays high means threads are parked on a slow backend (DNS, a
//! Diameter peer, Redis) or on something that will never answer.
//!
//! Three atomic read-modify-writes per wait and no allocation: the collectors
//! are built once and shared by reference.

use std::sync::OnceLock;

use prometheus::{IntCounter, IntGauge, Registry};

/// The two collectors behind the blocking-wait metrics.
pub(crate) struct WaitCounters {
    in_flight: IntGauge,
    total: IntCounter,
}

impl WaitCounters {
    fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            in_flight: IntGauge::new(
                "siphon_blocking_waits_in_flight",
                "Threads parked right now in a blocking wait through siphon's released \
                 helpers (DNS, Diameter, Redis, relay sends reached synchronously). A value \
                 that stays high means threads are stuck waiting: a slow backend or a hang",
            )?,
            total: IntCounter::new(
                "siphon_blocking_waits_total",
                "Blocking waits started through siphon's released helpers; its rate is how \
                 often handler threads block on Rust work",
            )?,
        })
    }

    /// Start one wait: counted now, in flight until the guard drops.
    pub(crate) fn track(&self) -> WaitGuard<'_> {
        self.total.inc();
        self.in_flight.inc();
        WaitGuard {
            in_flight: &self.in_flight,
        }
    }
}

/// Holds one wait in `siphon_blocking_waits_in_flight` until dropped, unwind
/// included.
pub(crate) struct WaitGuard<'a> {
    in_flight: &'a IntGauge,
}

impl Drop for WaitGuard<'_> {
    fn drop(&mut self) {
        self.in_flight.dec();
    }
}

/// The process-wide collectors, built on first use. `None` only if the
/// hardcoded names were rejected, which would be a bug; the waits still run.
fn counters() -> Option<&'static WaitCounters> {
    static COUNTERS: OnceLock<Option<WaitCounters>> = OnceLock::new();
    COUNTERS.get_or_init(|| WaitCounters::new().ok()).as_ref()
}

/// Track one wait on the process-wide collectors.
pub(crate) fn track_wait() -> Option<WaitGuard<'static>> {
    counters().map(WaitCounters::track)
}

/// Add both collectors to the metrics registry. Called from `metrics::init`,
/// so the series exist from the first scrape; waits counted before that keep
/// their values, because the registry holds the same collectors.
pub(crate) fn register(registry: &Registry) -> Result<(), prometheus::Error> {
    if let Some(counters) = counters() {
        registry.register(Box::new(counters.in_flight.clone()))?;
        registry.register(Box::new(counters.total.clone()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    #[test]
    fn the_gauge_rises_during_a_wait_and_falls_after() {
        let counters = WaitCounters::new().unwrap();
        assert_eq!(counters.in_flight.get(), 0);
        {
            let _guard = counters.track();
            assert_eq!(counters.in_flight.get(), 1);
            let _nested = counters.track();
            assert_eq!(counters.in_flight.get(), 2);
        }
        assert_eq!(counters.in_flight.get(), 0);
    }

    #[test]
    fn a_panicking_wait_still_gives_its_slot_back() {
        let counters = WaitCounters::new().unwrap();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = counters.track();
            assert_eq!(counters.in_flight.get(), 1);
            panic!("backend exploded");
        }));
        assert!(outcome.is_err());
        assert_eq!(counters.in_flight.get(), 0);
        assert_eq!(counters.total.get(), 1);
    }

    #[test]
    fn the_counter_counts_every_wait() {
        let counters = WaitCounters::new().unwrap();
        for _ in 0..5 {
            drop(counters.track());
        }
        assert_eq!(counters.total.get(), 5);
        assert_eq!(counters.in_flight.get(), 0);
    }

    #[test]
    fn concurrent_waits_are_all_in_flight_then_all_released() {
        const THREADS: usize = 8;
        let counters = Arc::new(WaitCounters::new().unwrap());
        let inside = Arc::new(Barrier::new(THREADS + 1));
        let leave = Arc::new(Barrier::new(THREADS + 1));
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let counters = Arc::clone(&counters);
                let inside = Arc::clone(&inside);
                let leave = Arc::clone(&leave);
                std::thread::spawn(move || {
                    let _guard = counters.track();
                    inside.wait();
                    leave.wait();
                })
            })
            .collect();
        inside.wait();
        assert_eq!(counters.in_flight.get(), THREADS as i64);
        leave.wait();
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(counters.in_flight.get(), 0);
        assert_eq!(counters.total.get(), THREADS as u64);
    }

    /// Leak-style check: a batch of completed waits, some of them panicking,
    /// leaves nothing in flight.
    #[test]
    fn the_gauge_drains_to_zero_after_a_batch() {
        let counters = Arc::new(WaitCounters::new().unwrap());
        let handles: Vec<_> = (0..4)
            .map(|worker| {
                let counters = Arc::clone(&counters);
                std::thread::spawn(move || {
                    for wait in 0..2_500 {
                        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            let _guard = counters.track();
                            if (worker + wait) % 500 == 0 {
                                std::panic::resume_unwind(Box::new("simulated failure"));
                            }
                        }));
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(counters.in_flight.get(), 0);
        assert_eq!(counters.total.get(), 10_000);
    }

    /// The real helpers drive the process-wide collectors. Other tests wait
    /// through them in parallel, so only lower bounds hold here.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_released_helpers_are_tracked() {
        let global = counters().expect("collectors build");
        let before = global.total.get();
        let seen_in_flight = crate::script::blocking::blocking_released(|| global.in_flight.get());
        assert!(seen_in_flight >= 1);
        let seen_in_flight =
            crate::script::blocking::block_on_released(async { global.in_flight.get() });
        assert!(seen_in_flight >= 1);
        // One wait each: block_on_released is not counted twice.
        assert!(global.total.get() >= before + 2);

        pyo3::Python::initialize();
        let before = global.total.get();
        let seen_in_flight =
            crate::script::blocking::detach_block_on(async move { global.in_flight.get() });
        assert!(seen_in_flight >= 1);
        assert!(global.total.get() > before);

        let panicked = std::panic::catch_unwind(|| {
            crate::script::blocking::blocking_released(|| panic!("backend exploded"))
        });
        assert!(panicked.is_err());
    }

    #[test]
    fn the_metrics_are_exported_once_registered() {
        crate::metrics::init().unwrap();
        drop(track_wait());
        let output = crate::metrics::encode_metrics();
        assert!(output.contains("siphon_blocking_waits_in_flight"));
        assert!(output.contains("siphon_blocking_waits_total"));
    }
}
