//! Building the process-wide metrics, once.

use std::sync::{Arc, Mutex, PoisonError};

use super::custom::CustomMetrics;
use super::{admission, SiphonMetrics, CUSTOM_METRICS, METRICS, STARTED_AT};

/// Initialize the global metrics. Call once at startup.
/// Returns an error if metric creation fails (should never happen with
/// valid hardcoded metric names — indicates a bug if it does).
///
/// One caller builds the metrics; a second one arriving meanwhile waits and
/// then finds them built. Without that two callers each built a registry, and
/// the admission gauges of the one could be kept beside the registry of the
/// other, where nothing that reads the exposition would ever see them.
pub fn init() -> Result<(), prometheus::Error> {
    static BUILDING: Mutex<()> = Mutex::new(());
    let _building = BUILDING.lock().unwrap_or_else(PoisonError::into_inner);
    if METRICS.get().is_some() {
        return Ok(());
    }
    let _ = STARTED_AT.set(std::time::Instant::now());
    let metrics = SiphonMetrics::new()?;
    admission::init(&metrics.registry)?;
    let custom = Arc::new(CustomMetrics::new(&metrics.registry));
    let _ = CUSTOM_METRICS.set(custom);
    let _ = METRICS.set(metrics);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callers_initialising_together_share_one_registry() {
        // Whichever thread builds, what the admission gauges are written to
        // has to be what the exposition reads.
        let callers: Vec<_> = (0..8).map(|_| std::thread::spawn(init)).collect();
        for caller in callers {
            caller
                .join()
                .expect("the caller ran")
                .expect("the metrics build");
        }
        let group = "startup-test-group";
        admission::record_refusal(&crate::admission::Refusal {
            scope: crate::admission::RefusalScope::Gateway(group.into()),
            reason: crate::admission::RefusalReason::Rate,
            reject_code: 503,
            retry_after_secs: 1,
        });
        assert!(
            super::super::encode_metrics().contains(&format!(
                "siphon_gateway_inbound_calls_refused_total{{group=\"{group}\",reason=\"rate\"}} 1"
            )),
            "a refusal counted on the admission metrics shows in the exposition"
        );
    }
}
