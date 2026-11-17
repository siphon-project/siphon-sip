//! NOTIFYs a `subscribe_state` notifier sent that did not get a 2xx.

use std::borrow::Cow;
use std::sync::OnceLock;

use prometheus::{IntCounterVec, Opts, Registry};

static FAILURES: OnceLock<IntCounterVec> = OnceLock::new();

/// The outcomes exported at zero from startup: the ones a subscriber that is
/// gone produces.
const EXPECTED: [Option<u16>; 3] = [Some(481), Some(408), None];

/// Create and register the metrics. Called once from [`super::startup::init`].
pub(super) fn init(registry: &Registry) -> Result<(), prometheus::Error> {
    let failures = IntCounterVec::new(
        Opts::new(
            "siphon_subscribe_notify_failures_total",
            "NOTIFYs sent by a subscribe_state notifier that ended without a 2xx, by code: the \
             status of the final response, or timeout when none came before Timer F. A 404, 405, \
             410, 416, 480-485, 489, 501, 604, a 408 and a timeout also remove the subscription \
             (RFC 6665 §4.2.2)",
        ),
        &["code"],
    )?;
    registry.register(Box::new(failures.clone()))?;
    for outcome in EXPECTED {
        failures.with_label_values(&[label(outcome).as_ref()]);
    }
    let _ = FAILURES.set(failures);
    Ok(())
}

/// The `code` label of `outcome`: `Some(status)` for a final response, `None`
/// for no final response before Timer F. A status outside 300-699 is not one
/// a failed request ends with, and is counted as `other`, so the label set is
/// bounded whatever a peer sends.
fn label(outcome: Option<u16>) -> Cow<'static, str> {
    match outcome {
        None => Cow::Borrowed("timeout"),
        Some(status @ 300..=699) => Cow::Owned(status.to_string()),
        Some(_) => Cow::Borrowed("other"),
    }
}

/// Count one NOTIFY that ended with `outcome`.
pub fn record_failure(outcome: Option<u16>) {
    if let Some(failures) = FAILURES.get() {
        failures.with_label_values(&[label(outcome).as_ref()]).inc();
    }
}

/// NOTIFYs that ended with `outcome` so far. `None` before
/// [`super::startup::init`].
pub fn failures(outcome: Option<u16>) -> Option<u64> {
    FAILURES
        .get()
        .map(|failures| failures.with_label_values(&[label(outcome).as_ref()]).get())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_expected_series_are_exported_at_zero_before_any_failure() {
        let registry = Registry::new();
        init(&registry).expect("subscribe notify metrics register");

        let families = registry.gather();
        let family = families
            .iter()
            .find(|family| family.name() == "siphon_subscribe_notify_failures_total")
            .expect("the counter is exported before any failure");
        let mut codes: Vec<&str> = family
            .get_metric()
            .iter()
            .flat_map(|metric| metric.get_label().iter().map(|label| label.value()))
            .collect();
        codes.sort_unstable();
        assert_eq!(codes, vec!["408", "481", "timeout"]);
        assert!(family
            .get_metric()
            .iter()
            .all(|metric| metric.get_counter().value() == 0.0));
    }

    #[test]
    fn the_code_label_is_the_status_or_timeout_and_bounded() {
        assert_eq!(label(None), "timeout");
        assert_eq!(label(Some(481)), "481");
        assert_eq!(label(Some(503)), "503");
        assert_eq!(label(Some(300)), "300");
        assert_eq!(label(Some(699)), "699");
        // Not a status a failed request ends with.
        assert_eq!(label(Some(200)), "other");
        assert_eq!(label(Some(700)), "other");
        assert_eq!(label(Some(0)), "other");
    }
}
