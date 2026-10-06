//! Metrics for inbound call admission ([`crate::admission`]).
//!
//! The limits are published beside the refusals so that utilisation is one
//! division on a dashboard: `siphon_b2bua_calls_active` over
//! `siphon_b2bua_max_concurrent_calls`. A limit gauge reading `0` means the
//! ceiling is not set.

use std::sync::OnceLock;

use prometheus::{IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry};

use crate::admission::{InboundLimits, Refusal, RefusalReason, RefusalScope};
use crate::gateway::InboundUsage;

static ADMISSION_METRICS: OnceLock<AdmissionMetrics> = OnceLock::new();

struct AdmissionMetrics {
    refused_total: IntCounterVec,
    max_concurrent_calls: IntGauge,
    max_calls_per_second: IntGauge,
    gateway_refused_total: IntCounterVec,
    gateway_calls_active: IntGaugeVec,
    gateway_max_concurrent_calls: IntGaugeVec,
    gateway_max_calls_per_second: IntGaugeVec,
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
    // Labelled by group name. Names come from `siphon.yaml` or the gateway
    // provisioning source, never from a peer, so the series are bounded by what
    // the operator configured.
    let gateway_refused_total = IntCounterVec::new(
        Opts::new(
            "siphon_gateway_inbound_calls_refused_total",
            "Inbound B2BUA calls refused by a gateway group's inbound_limit, by group and the ceiling that refused them (concurrent, rate)",
        ),
        &["group", "reason"],
    )?;
    let gateway_calls_active = IntGaugeVec::new(
        Opts::new(
            "siphon_gateway_inbound_calls_active",
            "Calls currently up from the sources a gateway group admits; only for groups with an inbound_limit",
        ),
        &["group"],
    )?;
    let gateway_max_concurrent_calls = IntGaugeVec::new(
        Opts::new(
            "siphon_gateway_inbound_max_concurrent_calls",
            "Configured gateway.groups[].inbound_limit.max_concurrent_calls (0 = unlimited)",
        ),
        &["group"],
    )?;
    let gateway_max_calls_per_second = IntGaugeVec::new(
        Opts::new(
            "siphon_gateway_inbound_max_calls_per_second",
            "Configured gateway.groups[].inbound_limit.max_calls_per_second (0 = unlimited)",
        ),
        &["group"],
    )?;
    registry.register(Box::new(refused_total.clone()))?;
    registry.register(Box::new(max_concurrent_calls.clone()))?;
    registry.register(Box::new(max_calls_per_second.clone()))?;
    registry.register(Box::new(gateway_refused_total.clone()))?;
    registry.register(Box::new(gateway_calls_active.clone()))?;
    registry.register(Box::new(gateway_max_concurrent_calls.clone()))?;
    registry.register(Box::new(gateway_max_calls_per_second.clone()))?;
    // Both series exist from the start, so a rate() over them reads zero
    // rather than "no data" on an instance that has refused nothing.
    for reason in [RefusalReason::Concurrent, RefusalReason::Rate] {
        refused_total.with_label_values(&[reason.as_str()]);
    }
    let _ = ADMISSION_METRICS.set(AdmissionMetrics {
        refused_total,
        max_concurrent_calls,
        max_calls_per_second,
        gateway_refused_total,
        gateway_calls_active,
        gateway_max_concurrent_calls,
        gateway_max_calls_per_second,
    });
    Ok(())
}

/// Count one refused inbound call, under the limit that refused it.
pub fn record_refusal(refusal: &Refusal) {
    let Some(metrics) = ADMISSION_METRICS.get() else {
        return;
    };
    let reason = refusal.reason.as_str();
    match &refusal.scope {
        RefusalScope::Global => metrics.refused_total.with_label_values(&[reason]).inc(),
        RefusalScope::Gateway(group) => metrics
            .gateway_refused_total
            .with_label_values(&[group, reason])
            .inc(),
    }
}

/// Publish each limited gateway group's limits and the calls it has up.
///
/// The gauges are cleared first, which is what drops the series of a group
/// that has been removed or has lost its limit since the last publish.
pub fn publish_gateway_usage(usage: &[InboundUsage]) {
    let Some(metrics) = ADMISSION_METRICS.get() else {
        return;
    };
    metrics.gateway_calls_active.reset();
    metrics.gateway_max_concurrent_calls.reset();
    metrics.gateway_max_calls_per_second.reset();
    for group in usage {
        let label = [&*group.group];
        metrics
            .gateway_calls_active
            .with_label_values(&label)
            .set(i64::from(group.active));
        metrics
            .gateway_max_concurrent_calls
            .with_label_values(&label)
            .set(i64::from(group.limits.max_concurrent_calls));
        metrics
            .gateway_max_calls_per_second
            .with_label_values(&label)
            .set(i64::from(group.limits.max_calls_per_second));
    }
}

/// Refusals counted so far for `group` and `reason`. `None` before
/// [`super::init`].
pub fn gateway_refusals(group: &str, reason: RefusalReason) -> Option<u64> {
    ADMISSION_METRICS.get().map(|metrics| {
        metrics
            .gateway_refused_total
            .with_label_values(&[group, reason.as_str()])
            .get()
    })
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

    fn refusal(scope: RefusalScope, reason: RefusalReason) -> Refusal {
        Refusal {
            scope,
            reason,
            reject_code: 503,
            retry_after_secs: 1,
        }
    }

    #[test]
    fn a_refusal_is_counted_under_its_reason() {
        initialised();
        let before = refusals(RefusalReason::Rate).expect("initialised");
        record_refusal(&refusal(RefusalScope::Global, RefusalReason::Rate));
        // Other tests in the binary refuse calls too, so this is a floor.
        assert!(refusals(RefusalReason::Rate).expect("initialised") > before);
    }

    #[test]
    fn a_gateway_refusal_is_counted_under_its_group() {
        initialised();
        // A group name no other test uses, so the count is exact.
        let group = "metrics-test-carrier";
        for _ in 0..3 {
            record_refusal(&refusal(
                RefusalScope::Gateway(group.into()),
                RefusalReason::Concurrent,
            ));
        }
        assert_eq!(gateway_refusals(group, RefusalReason::Concurrent), Some(3));
        assert_eq!(gateway_refusals(group, RefusalReason::Rate), Some(0));
    }

    #[test]
    fn gateway_usage_is_published_and_a_group_that_went_away_is_dropped() {
        initialised();
        let usage = |group: &str, active: u32| InboundUsage {
            group: group.into(),
            active,
            limits: InboundLimits {
                max_concurrent_calls: 300,
                max_calls_per_second: 30,
                ..InboundLimits::UNLIMITED
            },
        };
        let present = |exposition: &str, needle: &str| exposition.contains(needle);

        publish_gateway_usage(&[usage("usage-test-a", 7), usage("usage-test-b", 2)]);
        let exposition = crate::metrics::encode_metrics();
        for needle in [
            "siphon_gateway_inbound_calls_active{group=\"usage-test-a\"} 7",
            "siphon_gateway_inbound_calls_active{group=\"usage-test-b\"} 2",
            "siphon_gateway_inbound_max_concurrent_calls{group=\"usage-test-a\"} 300",
            "siphon_gateway_inbound_max_calls_per_second{group=\"usage-test-a\"} 30",
        ] {
            assert!(present(&exposition, needle), "missing {needle}");
        }

        publish_gateway_usage(&[usage("usage-test-a", 0)]);
        let exposition = crate::metrics::encode_metrics();
        assert!(present(
            &exposition,
            "siphon_gateway_inbound_calls_active{group=\"usage-test-a\"} 0"
        ));
        assert!(
            !present(&exposition, "group=\"usage-test-b\""),
            "a group that is gone keeps no series"
        );
        publish_gateway_usage(&[]);
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
