//! Metrics for the script's periodic timers (`@timer.every`).

use std::sync::OnceLock;

use prometheus::{IntCounterVec, Opts, Registry};

static TIMER_METRICS: OnceLock<TimerMetrics> = OnceLock::new();

struct TimerMetrics {
    jobs_shed_total: IntCounterVec,
}

/// Create and register the timer metrics. Called once from [`super::init`].
pub(super) fn init(registry: &Registry) -> Result<(), prometheus::Error> {
    // Labelled by timer name. Names come from the script's own decorators,
    // never from a peer, so the series are bounded by what the script defines.
    let jobs_shed_total = IntCounterVec::new(
        Opts::new(
            "siphon_timer_jobs_shed_total",
            "Timer runs skipped because the Python executor queue was full, by timer name; \
             each one is a run whose work did not happen (also counted in siphon_pyexec_jobs_shed_total)",
        ),
        &["timer"],
    )?;
    registry.register(Box::new(jobs_shed_total.clone()))?;
    let _ = TIMER_METRICS.set(TimerMetrics { jobs_shed_total });
    Ok(())
}

/// Count one run of `timer` the executor shed.
pub fn record_shed(timer: &str) {
    if let Some(metrics) = TIMER_METRICS.get() {
        metrics.jobs_shed_total.with_label_values(&[timer]).inc();
    }
}

/// Runs of `timer` shed so far. `None` before [`super::init`].
pub fn shed(timer: &str) -> Option<u64> {
    TIMER_METRICS
        .get()
        .map(|metrics| metrics.jobs_shed_total.with_label_values(&[timer]).get())
}
