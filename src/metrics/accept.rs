//! Metrics for listener accept errors ([`crate::transport::accept_backoff`]).
//!
//! Pair with `process_open_fds / process_max_fds` for the warning side: the
//! ratio climbing toward 1 comes before `reason="emfile"` starts counting.

use std::sync::OnceLock;

use prometheus::{IntCounterVec, Opts, Registry};

static ACCEPT_METRICS: OnceLock<IntCounterVec> = OnceLock::new();

/// Every `reason` label value, so a listener's series exist at zero.
pub const REASONS: [&str; 5] = ["emfile", "enfile", "enobufs", "enomem", "other"];

/// Create and register the metric. Called once from [`super::startup::init`].
pub(super) fn init(registry: &Registry) -> Result<(), prometheus::Error> {
    // Labelled by transport and bound listener address: both come from
    // `siphon.yaml`, never from a peer, so the series are bounded by the
    // listeners the operator configured.
    let errors = IntCounterVec::new(
        Opts::new(
            "siphon_accept_errors_total",
            "accept() errors on a stream listener, by transport, listener address and reason \
             (emfile/enfile: out of file descriptors; enobufs/enomem: out of kernel memory; \
             other: anything else, including peers that reset before the accept)",
        ),
        &["transport", "listener", "reason"],
    )?;
    registry.register(Box::new(errors.clone()))?;
    let _ = ACCEPT_METRICS.set(errors);
    Ok(())
}

/// Create a listener's series at zero, so `rate()` reads 0 rather than no data
/// on a listener that has not failed an accept yet.
pub fn register_listener(transport: &str, listener: &str) {
    if let Some(errors) = ACCEPT_METRICS.get() {
        for reason in REASONS {
            errors.with_label_values(&[transport, listener, reason]);
        }
    }
}

/// Count one accept error.
pub fn record(transport: &str, listener: &str, reason: &str) {
    if let Some(errors) = ACCEPT_METRICS.get() {
        errors
            .with_label_values(&[transport, listener, reason])
            .inc();
    }
}

/// Accept errors counted so far. `None` before [`super::startup::init`].
pub fn errors(transport: &str, listener: &str, reason: &str) -> Option<u64> {
    ACCEPT_METRICS.get().map(|errors| {
        errors
            .with_label_values(&[transport, listener, reason])
            .get()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_are_counted_per_listener_and_reason() {
        crate::metrics::init().expect("metrics");
        let listener = "198.51.100.7:5061";
        register_listener("tls", listener);
        for reason in REASONS {
            assert_eq!(
                errors("tls", listener, reason),
                Some(0),
                "{reason} exported at zero"
            );
        }
        record("tls", listener, "emfile");
        record("tls", listener, "emfile");
        record("tls", listener, "other");
        assert_eq!(errors("tls", listener, "emfile"), Some(2));
        assert_eq!(errors("tls", listener, "other"), Some(1));
        assert_eq!(errors("tls", listener, "enfile"), Some(0));
        assert!(crate::metrics::encode_metrics().contains(&format!(
            "siphon_accept_errors_total{{listener=\"{listener}\",reason=\"emfile\",transport=\"tls\"}} 2"
        )));
    }
}
