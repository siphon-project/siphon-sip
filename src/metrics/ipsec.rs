//! Metrics for the P-CSCF's IPsec SPI partition ([`crate::ipsec`]), and the
//! IMS UE registrant's protected ports ([`crate::registrant::protected`]).
//!
//! Utilisation is `siphon_ipsec_spis_in_use` over
//! `siphon_ipsec_spi_partition_size`. Each registered UE holds two SPIs, so
//! the partition is full at about half its size in UEs; past that,
//! `ipsec.allocate` fails and `siphon_ipsec_spi_allocation_failures_total`
//! counts it.

use std::sync::OnceLock;

use prometheus::{IntCounter, IntGauge, Registry};

static IPSEC_METRICS: OnceLock<IpsecMetrics> = OnceLock::new();

struct IpsecMetrics {
    spis_in_use: IntGauge,
    spi_partition_size: IntGauge,
    spi_allocation_failures_total: IntCounter,
    ue_port_bind_failures_total: IntCounter,
}

/// Create and register the IPsec metrics. Called once from [`super::init`].
pub(super) fn init(registry: &Registry) -> Result<(), prometheus::Error> {
    let spis_in_use = IntGauge::new(
        "siphon_ipsec_spis_in_use",
        "SPIs of the IPsec partition held by a live or pending SA pair, or by a kernel SA left by a restart",
    )?;
    let spi_partition_size = IntGauge::new(
        "siphon_ipsec_spi_partition_size",
        "SPIs in the configured IPsec partition (ipsec.spi_range_count); two per registered UE",
    )?;
    let spi_allocation_failures_total = IntCounter::new(
        "siphon_ipsec_spi_allocation_failures_total",
        "SPI pairs refused because every SPI of the partition was in use; each is a registration that could not be protected",
    )?;
    registry.register(Box::new(spis_in_use.clone()))?;
    registry.register(Box::new(spi_partition_size.clone()))?;
    let ue_port_bind_failures_total = IntCounter::new(
        "siphon_ipsec_ue_port_bind_failures_total",
        "Protected ports an IMS UE registration could not bind: each one either moved to another port or took its SA set out of use, so the next REGISTER went unprotected",
    )?;
    registry.register(Box::new(spi_allocation_failures_total.clone()))?;
    registry.register(Box::new(ue_port_bind_failures_total.clone()))?;
    let _ = IPSEC_METRICS.set(IpsecMetrics {
        spis_in_use,
        spi_partition_size,
        spi_allocation_failures_total,
        ue_port_bind_failures_total,
    });
    Ok(())
}

/// Publish how much of the SPI partition is in use.
pub fn publish_spi_usage(in_use: u32, partition_size: u32) {
    if let Some(metrics) = IPSEC_METRICS.get() {
        metrics.spis_in_use.set(i64::from(in_use));
        metrics.spi_partition_size.set(i64::from(partition_size));
    }
}

/// Count one SPI pair the partition could not supply.
pub fn record_spi_allocation_failure() {
    if let Some(metrics) = IPSEC_METRICS.get() {
        metrics.spi_allocation_failures_total.inc();
    }
}

/// Count one protected port an IMS UE registration could not bind.
pub fn record_ue_port_bind_failure() {
    if let Some(metrics) = IPSEC_METRICS.get() {
        metrics.ue_port_bind_failures_total.inc();
    }
}

/// UE port bind failures counted so far. `None` before [`super::init`].
pub fn ue_port_bind_failures() -> Option<u64> {
    IPSEC_METRICS
        .get()
        .map(|metrics| metrics.ue_port_bind_failures_total.get())
}

/// Allocation failures counted so far. `None` before [`super::init`].
pub fn spi_allocation_failures() -> Option<u64> {
    IPSEC_METRICS
        .get()
        .map(|metrics| metrics.spi_allocation_failures_total.get())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spi_usage_and_failures_reach_the_exposition() {
        crate::metrics::init().expect("the metrics registry builds");
        publish_spi_usage(6, 8);
        let before = spi_allocation_failures().expect("initialised");
        record_spi_allocation_failure();
        // Other tests may count failures meanwhile; this one is among them.
        assert!(spi_allocation_failures().expect("initialised") > before);
        let exposition = crate::metrics::encode_metrics();
        // The gauges are process-wide, so another test may publish over these
        // values; their presence is what this checks.
        assert!(exposition.contains("siphon_ipsec_spis_in_use "));
        assert!(exposition.contains("siphon_ipsec_spi_partition_size "));
        assert!(exposition.contains("siphon_ipsec_spi_allocation_failures_total"));
        let before = ue_port_bind_failures().expect("initialised");
        record_ue_port_bind_failure();
        assert!(ue_port_bind_failures().expect("initialised") > before);
        assert!(
            crate::metrics::encode_metrics().contains("siphon_ipsec_ue_port_bind_failures_total")
        );
    }
}
