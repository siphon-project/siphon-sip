//! Metrics for the outbound connection pool's connect backoff
//! ([`crate::transport::pool`]).

use std::sync::OnceLock;

use prometheus::{IntCounterVec, Opts, Registry};

use crate::transport::Transport;

static POOL_CONNECT_METRICS: OnceLock<PoolConnectMetrics> = OnceLock::new();

struct PoolConnectMetrics {
    failures_total: IntCounterVec,
    suppressed_total: IntCounterVec,
}

/// Create and register the pool connect metrics. Called once from
/// [`super::init`].
pub(super) fn init(registry: &Registry) -> Result<(), prometheus::Error> {
    let failures_total = IntCounterVec::new(
        Opts::new(
            "siphon_pool_connect_failures_total",
            "Outbound pool connects that failed or timed out, each of which puts its destination in a connect backoff window",
        ),
        &["transport"],
    )?;
    let suppressed_total = IntCounterVec::new(
        Opts::new(
            "siphon_pool_connect_suppressed_total",
            "Outbound sends failed at once, without a connect, because their destination is inside its connect backoff window",
        ),
        &["transport"],
    )?;
    registry.register(Box::new(failures_total.clone()))?;
    registry.register(Box::new(suppressed_total.clone()))?;
    // A labelled counter exports no series until a label value is first used,
    // and a series that only appears after the first failure breaks dashboards
    // and `rate()` alike. Create the pooled transports' series at zero.
    for transport in [Transport::Tcp, Transport::Tls] {
        failures_total.with_label_values(&[transport.as_scheme()]);
        suppressed_total.with_label_values(&[transport.as_scheme()]);
    }
    let _ = POOL_CONNECT_METRICS.set(PoolConnectMetrics {
        failures_total,
        suppressed_total,
    });
    Ok(())
}

/// Count one failed pool connect.
pub fn record_failure(transport: Transport) {
    if let Some(metrics) = POOL_CONNECT_METRICS.get() {
        metrics
            .failures_total
            .with_label_values(&[transport.as_scheme()])
            .inc();
    }
}

/// Count one send failed fast inside a backoff window.
pub fn record_suppressed(transport: Transport) {
    if let Some(metrics) = POOL_CONNECT_METRICS.get() {
        metrics
            .suppressed_total
            .with_label_values(&[transport.as_scheme()])
            .inc();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_pooled_transport_exports_both_series_at_zero_before_any_failure() {
        let registry = Registry::new();
        init(&registry).expect("pool connect metrics register");

        let families = registry.gather();
        for name in [
            "siphon_pool_connect_failures_total",
            "siphon_pool_connect_suppressed_total",
        ] {
            let family = families
                .iter()
                .find(|family| family.name() == name)
                .unwrap_or_else(|| panic!("{name} is exported before any failure"));
            let mut transports: Vec<String> = family
                .get_metric()
                .iter()
                .map(|metric| {
                    assert_eq!(metric.get_counter().value(), 0.0, "{name} starts at zero");
                    metric.get_label()[0].value().to_string()
                })
                .collect();
            transports.sort();
            assert_eq!(transports, ["tcp", "tls"], "{name}");
        }
    }
}
