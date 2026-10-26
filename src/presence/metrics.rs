//! Metrics for the presence notifier, registered with the process-wide
//! metrics by [`crate::metrics::init`].

use std::sync::OnceLock;

use prometheus::{IntCounterVec, Opts, Registry};

use crate::presence::NotifyFailure;

static REMOVED: OnceLock<IntCounterVec> = OnceLock::new();

/// Create and register the metrics. Called once from [`crate::metrics::init`].
pub(crate) fn init(registry: &Registry) -> Result<(), prometheus::Error> {
    // Labelled from the fixed `NotifyFailure` set, so a peer cannot grow the
    // series.
    let removed = IntCounterVec::new(
        Opts::new(
            "siphon_presence_subscriptions_removed_total",
            "Subscriptions the notifier removed because a NOTIFY failed (RFC 6665 §4.2.2), \
             by reason: notify_rejected (404, 405, 410, 416, 480-485, 489, 501 or 604) or \
             notify_timeout (no final response before Timer F, or a 408)",
        ),
        &["reason"],
    )?;
    registry.register(Box::new(removed.clone()))?;
    // Every series at zero from the start, so `rate()` and dashboards see the
    // counter before the first removal.
    for failure in NotifyFailure::ALL {
        removed.with_label_values(&[failure.label()]);
    }
    let _ = REMOVED.set(removed);
    Ok(())
}

/// Count one subscription removed for `failure`.
pub fn record_removed(failure: NotifyFailure) {
    if let Some(removed) = REMOVED.get() {
        removed.with_label_values(&[failure.label()]).inc();
    }
}

/// Subscriptions removed for `failure` so far. `None` before
/// [`crate::metrics::init`].
pub fn removed(failure: NotifyFailure) -> Option<u64> {
    REMOVED
        .get()
        .map(|removed| removed.with_label_values(&[failure.label()]).get())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_reason_series_is_exported_at_zero_before_any_removal() {
        let registry = Registry::new();
        init(&registry).expect("presence metrics register");

        let families = registry.gather();
        let family = families
            .iter()
            .find(|family| family.name() == "siphon_presence_subscriptions_removed_total")
            .expect("the counter is exported before any removal");
        let mut reasons: Vec<&str> = family
            .get_metric()
            .iter()
            .flat_map(|metric| metric.get_label().iter().map(|label| label.value()))
            .collect();
        reasons.sort_unstable();
        assert_eq!(reasons, vec!["notify_rejected", "notify_timeout"]);
        assert!(family
            .get_metric()
            .iter()
            .all(|metric| metric.get_counter().value() == 0.0));
    }
}
