//! Metrics for inbound call admission ([`crate::admission`]).
//!
//! The limits are published beside the refusals so that utilisation is one
//! division on a dashboard: `siphon_b2bua_calls_active` over
//! `siphon_b2bua_max_concurrent_calls`. A limit gauge reading `0` means the
//! ceiling is not set.

use std::sync::OnceLock;

use prometheus::{IntCounterVec, IntGauge, Opts, Registry};

use crate::admission::{InboundLimits, RefusalReason};

static ADMISSION_METRICS: OnceLock<AdmissionMetrics> = OnceLock::new();

struct AdmissionMetrics {
    refused_total: IntCounterVec,
    max_concurrent_calls: IntGauge,
    max_calls_per_second: IntGauge,
}

/// Create and register the admission metrics. Called once from
/// [`super::init`].
pub(super) fn init(registry: &Registry) -> Result<(), prometheus::Error> {
    let refused_total = IntCounterVec::new(
        Opts::new(
            "siphon_b2bua_inbound_calls_refused_total",
            "Inbound B2BUA calls refused by b2bua.inbound_limit, by the ceiling that refused them (concurrent, rate)",
        ),
        &["reason"],
    )?;
    let max_concurrent_calls = IntGauge::new(
        "siphon_b2bua_max_concurrent_calls",
        "Configured b2bua.inbound_limit.max_concurrent_calls (0 = unlimited); divide siphon_b2bua_calls_active by this for utilisation",
    )?;
    let max_calls_per_second = IntGauge::new(
        "siphon_b2bua_max_calls_per_second",
        "Configured b2bua.inbound_limit.max_calls_per_second (0 = unlimited)",
    )?;
    registry.register(Box::new(refused_total.clone()))?;
    registry.register(Box::new(max_concurrent_calls.clone()))?;
    registry.register(Box::new(max_calls_per_second.clone()))?;
    // Both series exist from the start, so a rate() over them reads zero
    // rather than "no data" on an instance that has refused nothing.
    for reason in [RefusalReason::Concurrent, RefusalReason::Rate] {
        refused_total.with_label_values(&[reason.as_str()]);
    }
    let _ = ADMISSION_METRICS.set(AdmissionMetrics {
        refused_total,
        max_concurrent_calls,
        max_calls_per_second,
    });
    Ok(())
}

/// Count one refused inbound call.
pub fn record_refusal(reason: RefusalReason) {
    if let Some(metrics) = ADMISSION_METRICS.get() {
        metrics
            .refused_total
            .with_label_values(&[reason.as_str()])
            .inc();
    }
}

/// Publish the instance-wide limits in force.
pub fn publish_limits(limits: InboundLimits) {
    if let Some(metrics) = ADMISSION_METRICS.get() {
        metrics
            .max_concurrent_calls
            .set(i64::from(limits.max_concurrent_calls));
        metrics
            .max_calls_per_second
            .set(i64::from(limits.max_calls_per_second));
    }
}

/// Refusals counted so far for `reason`. `None` before [`super::init`].
pub fn refusals(reason: RefusalReason) -> Option<u64> {
    ADMISSION_METRICS.get().map(|metrics| {
        metrics
            .refused_total
            .with_label_values(&[reason.as_str()])
            .get()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn initialised() {
        crate::metrics::init().expect("the metrics registry builds");
    }

    #[test]
    fn a_refusal_is_counted_under_its_reason() {
        initialised();
        let before = refusals(RefusalReason::Rate).expect("initialised");
        record_refusal(RefusalReason::Rate);
        // Other tests in the binary refuse calls too, so this is a floor.
        assert!(refusals(RefusalReason::Rate).expect("initialised") > before);
    }

    #[test]
    fn the_metrics_are_exposed_with_both_reasons_present() {
        initialised();
        publish_limits(InboundLimits::UNLIMITED);
        let exposition = crate::metrics::encode_metrics();
        for needle in [
            "siphon_b2bua_inbound_calls_refused_total{reason=\"concurrent\"}",
            "siphon_b2bua_inbound_calls_refused_total{reason=\"rate\"}",
            "siphon_b2bua_max_concurrent_calls",
            "siphon_b2bua_max_calls_per_second",
        ] {
            assert!(exposition.contains(needle), "missing {needle}");
        }
    }
}
