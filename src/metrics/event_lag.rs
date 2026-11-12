//! Events a background consumer lost to a broadcast lag.
//!
//! The registrar and the registrant publish their state changes on bounded
//! `tokio::sync::broadcast` channels. A consumer that falls more than the
//! channel's capacity behind is told how many events it missed
//! (`RecvError::Lagged`) and carries on from the oldest one still held. This
//! counts what was missed, per consumer, so a storm that outran a slow
//! `@registrar.on_change` handler shows on a dashboard rather than only in a
//! log line.

use std::sync::OnceLock;

use prometheus::{IntCounterVec, Opts, Registry};

static EVENT_LAG_METRICS: OnceLock<IntCounterVec> = OnceLock::new();
static SNAPSHOT_RUNS: OnceLock<IntCounterVec> = OnceLock::new();
static SNAPSHOT_AORS: OnceLock<IntCounterVec> = OnceLock::new();

/// The consumers that read a state-change broadcast, as the `consumer` label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LaggedConsumer {
    /// `@registrar.on_change` and the control plane's `RegistrationChanged`.
    Registrar,
    /// `@registration.on_change` (outbound REGISTER state).
    Registrant,
    /// The Rf ACR-EVENT emitter for registration changes.
    RfRegister,
}

impl LaggedConsumer {
    /// The `consumer` label value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registrar => "registrar",
            Self::Registrant => "registrant",
            Self::RfRegister => "rf_register",
        }
    }
}

/// Create and register the lag counter. Called once from [`super::init`].
pub(super) fn init(registry: &Registry) -> Result<(), prometheus::Error> {
    let lagged_total = IntCounterVec::new(
        Opts::new(
            "siphon_event_consumer_lagged_total",
            "State-change events a background consumer lost because it fell further behind its broadcast channel than the channel holds, by consumer. After a lag the registrar and registrant consumers re-publish the current state of every AoR they know; the rf_register emitter cannot, since a lost ACR-EVENT is a charging record rather than state",
        ),
        &["consumer"],
    )?;
    registry.register(Box::new(lagged_total.clone()))?;
    // Every series exists from the start, so a rate() over one reads zero
    // rather than "no data" on an instance that has never lagged.
    for consumer in [
        LaggedConsumer::Registrar,
        LaggedConsumer::Registrant,
        LaggedConsumer::RfRegister,
    ] {
        lagged_total.with_label_values(&[consumer.as_str()]);
    }
    let _ = EVENT_LAG_METRICS.set(lagged_total);

    let snapshots_total = IntCounterVec::new(
        Opts::new(
            "siphon_event_consumer_snapshots_total",
            "Snapshot runs a consumer started after a broadcast lag, by consumer. A lag during a run replaces it with a fresh one",
        ),
        &["consumer"],
    )?;
    registry.register(Box::new(snapshots_total.clone()))?;
    let snapshot_aors_total = IntCounterVec::new(
        Opts::new(
            "siphon_event_consumer_snapshot_aors_total",
            "AoRs a consumer re-reported as a snapshot after a broadcast lag, by consumer",
        ),
        &["consumer"],
    )?;
    registry.register(Box::new(snapshot_aors_total.clone()))?;
    for consumer in [LaggedConsumer::Registrar, LaggedConsumer::Registrant] {
        snapshots_total.with_label_values(&[consumer.as_str()]);
        snapshot_aors_total.with_label_values(&[consumer.as_str()]);
    }
    let _ = SNAPSHOT_RUNS.set(snapshots_total);
    let _ = SNAPSHOT_AORS.set(snapshot_aors_total);
    Ok(())
}

/// Count one snapshot run `consumer` started.
pub fn record_snapshot_started(consumer: LaggedConsumer) {
    if let Some(snapshots_total) = SNAPSHOT_RUNS.get() {
        snapshots_total
            .with_label_values(&[consumer.as_str()])
            .inc();
    }
}

/// Count one AoR `consumer` re-reported as a snapshot.
pub fn record_snapshot_aor(consumer: LaggedConsumer) {
    if let Some(snapshot_aors_total) = SNAPSHOT_AORS.get() {
        snapshot_aors_total
            .with_label_values(&[consumer.as_str()])
            .inc();
    }
}

/// What the snapshot-run counter reads for `consumer`, `0` before the metrics
/// are built.
pub fn snapshots(consumer: LaggedConsumer) -> u64 {
    SNAPSHOT_RUNS
        .get()
        .map(|counter| counter.with_label_values(&[consumer.as_str()]).get())
        .unwrap_or(0)
}

/// What the re-reported-AoR counter reads for `consumer`, `0` before the
/// metrics are built.
pub fn snapshot_aors(consumer: LaggedConsumer) -> u64 {
    SNAPSHOT_AORS
        .get()
        .map(|counter| counter.with_label_values(&[consumer.as_str()]).get())
        .unwrap_or(0)
}

/// Count `skipped` events `consumer` lost to a broadcast lag.
pub fn record_lag(consumer: LaggedConsumer, skipped: u64) {
    if let Some(lagged_total) = EVENT_LAG_METRICS.get() {
        lagged_total
            .with_label_values(&[consumer.as_str()])
            .inc_by(skipped);
    }
}

/// What the counter reads for `consumer`, `0` before the metrics are built.
pub fn lagged(consumer: LaggedConsumer) -> u64 {
    EVENT_LAG_METRICS
        .get()
        .map(|lagged_total| lagged_total.with_label_values(&[consumer.as_str()]).get())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lag_is_counted_under_its_consumer_and_shows_in_the_exposition() {
        crate::metrics::init().expect("the metrics build");
        let before = lagged(LaggedConsumer::RfRegister);
        record_lag(LaggedConsumer::RfRegister, 7);
        assert_eq!(lagged(LaggedConsumer::RfRegister), before + 7);
        let exposition = crate::metrics::encode_metrics();
        assert!(exposition.contains("siphon_event_consumer_lagged_total{consumer=\"rf_register\"}"));
        assert!(exposition.contains("siphon_event_consumer_lagged_total{consumer=\"registrant\"}"));
    }

    #[test]
    fn snapshot_runs_and_aors_are_counted_under_their_consumer() {
        crate::metrics::init().expect("the metrics build");
        let runs = snapshots(LaggedConsumer::Registrant);
        let aors = snapshot_aors(LaggedConsumer::Registrant);
        record_snapshot_started(LaggedConsumer::Registrant);
        record_snapshot_aor(LaggedConsumer::Registrant);
        record_snapshot_aor(LaggedConsumer::Registrant);
        assert!(snapshots(LaggedConsumer::Registrant) > runs);
        assert!(snapshot_aors(LaggedConsumer::Registrant) >= aors + 2);
        let exposition = crate::metrics::encode_metrics();
        for consumer in ["registrar", "registrant"] {
            assert!(exposition.contains(&format!(
                "siphon_event_consumer_snapshots_total{{consumer=\"{consumer}\"}}"
            )));
            assert!(exposition.contains(&format!(
                "siphon_event_consumer_snapshot_aors_total{{consumer=\"{consumer}\"}}"
            )));
        }
    }

    #[test]
    fn labels_are_stable() {
        assert_eq!(LaggedConsumer::Registrar.as_str(), "registrar");
        assert_eq!(LaggedConsumer::Registrant.as_str(), "registrant");
        assert_eq!(LaggedConsumer::RfRegister.as_str(), "rf_register");
    }
}
