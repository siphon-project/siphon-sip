//! Metrics for age-based load shedding: initial requests answered 503 because
//! they waited in the script executor's queue past their budget.
//!
//! Kept apart from `siphon_pyexec_jobs_shed_total`, which counts jobs dropped
//! because the queue was full: those were never queued and never answered,
//! while these were queued, aged out and were answered 503.

use std::sync::OnceLock;

use prometheus::{IntCounterVec, Opts, Registry};

static STALE_SHED_METRICS: OnceLock<IntCounterVec> = OnceLock::new();

/// Create and register the metrics. Called once from [`super::startup::init`].
pub(super) fn init(registry: &Registry) -> Result<(), prometheus::Error> {
    // Labelled by method from the fixed `METHOD_LABELS` set (an extension
    // method counts as OTHER), so a peer cannot grow the series.
    let shed = IntCounterVec::new(
        Opts::new(
            "siphon_pyexec_stale_requests_shed_total",
            "Initial requests answered 503 with Retry-After, without running the script, \
             because they waited in the Python executor queue past their budget, by method \
             (queue-full drops are siphon_pyexec_jobs_shed_total)",
        ),
        &["method"],
    )?;
    registry.register(Box::new(shed.clone()))?;
    let _ = STALE_SHED_METRICS.set(shed);
    Ok(())
}

/// The `method` label for `method`. `get` rather than `[]`, so a future edit
/// of the label set cannot panic on the datapath.
fn label(method: &crate::sip::message::Method) -> &'static str {
    super::METHOD_LABELS
        .get(super::method_index(method))
        .copied()
        .unwrap_or("OTHER")
}

/// Count one request of `method` shed for its age.
pub fn record(method: &crate::sip::message::Method) {
    if let Some(shed) = STALE_SHED_METRICS.get() {
        shed.with_label_values(&[label(method)]).inc();
    }
}

/// Requests of `method` shed for their age so far. `None` before
/// [`super::startup::init`].
pub fn shed(method: &crate::sip::message::Method) -> Option<u64> {
    STALE_SHED_METRICS
        .get()
        .map(|shed| shed.with_label_values(&[label(method)]).get())
}
