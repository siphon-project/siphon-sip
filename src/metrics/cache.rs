//! Metrics for the Redis layer of the named caches ([`crate::cache`]).

use std::sync::OnceLock;

use prometheus::{IntCounterVec, IntGaugeVec, Opts, Registry};

static CACHE_METRICS: OnceLock<Option<CacheMetrics>> = OnceLock::new();

struct CacheMetrics {
    errors_total: IntCounterVec,
    backend_up: IntGaugeVec,
}

impl CacheMetrics {
    fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            errors_total: IntCounterVec::new(
                Opts::new(
                    "siphon_cache_errors_total",
                    "Named-cache operations that failed against the Redis backend, including those refused at once while the backend is marked unreachable",
                ),
                &["cache", "op"],
            )?,
            backend_up: IntGaugeVec::new(
                Opts::new(
                    "siphon_cache_backend_up",
                    "Whether the Redis backend of a named cache answered its last command or probe (1) or is unreachable (0)",
                ),
                &["cache"],
            )?,
        })
    }
}

/// The metrics, created on first use so that a cache built before
/// [`super::init`] (or in a process that never calls it) still counts.
fn cache_metrics() -> Option<&'static CacheMetrics> {
    CACHE_METRICS
        .get_or_init(|| CacheMetrics::new().ok())
        .as_ref()
}

/// Register the cache metrics. Called once from [`super::init`].
pub(super) fn init(registry: &Registry) -> Result<(), prometheus::Error> {
    let Some(metrics) = cache_metrics() else {
        return Ok(());
    };
    registry.register(Box::new(metrics.errors_total.clone()))?;
    registry.register(Box::new(metrics.backend_up.clone()))?;
    Ok(())
}

/// Count one failed operation (`op`: `get`, `set`, `del`, ...) on `cache`.
pub fn record_error(cache: &str, op: &str) {
    if let Some(metrics) = cache_metrics() {
        metrics.errors_total.with_label_values(&[cache, op]).inc();
    }
}

/// Publish whether the Redis backend of `cache` is reachable.
pub fn set_backend_up(cache: &str, up: bool) {
    if let Some(metrics) = cache_metrics() {
        metrics
            .backend_up
            .with_label_values(&[cache])
            .set(i64::from(up));
    }
}

/// Export the series of `cache` before anything happened to it: a series
/// that only appears with the first failure breaks dashboards and `rate()`.
/// The backend reads down until its first probe answers.
pub fn declare(cache: &str, ops: &[&str]) {
    if let Some(metrics) = cache_metrics() {
        metrics.backend_up.with_label_values(&[cache]);
        for op in ops {
            metrics.errors_total.with_label_values(&[cache, op]);
        }
    }
}

/// Failed operations counted so far for `cache` and `op`.
#[cfg(test)]
pub(crate) fn errors(cache: &str, op: &str) -> u64 {
    cache_metrics()
        .map(|metrics| metrics.errors_total.with_label_values(&[cache, op]).get())
        .unwrap_or(0)
}

/// Whether `cache` is published as up.
#[cfg(test)]
pub(crate) fn backend_up(cache: &str) -> bool {
    cache_metrics().is_some_and(|metrics| metrics.backend_up.with_label_values(&[cache]).get() == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_declared_cache_exports_its_series_at_zero_and_counts_from_there() {
        let registry = Registry::new();
        init(&registry).expect("cache metrics register");
        declare("metrics_test_declared", &["get", "set"]);

        let families = registry.gather();
        let series = |name: &str| -> Vec<Vec<String>> {
            families
                .iter()
                .find(|family| family.name() == name)
                .unwrap_or_else(|| panic!("{name} is exported"))
                .get_metric()
                .iter()
                .map(|metric| {
                    metric
                        .get_label()
                        .iter()
                        .map(|label| label.value().to_string())
                        .collect::<Vec<_>>()
                })
                .filter(|labels| labels.iter().any(|label| label == "metrics_test_declared"))
                .collect()
        };
        assert_eq!(series("siphon_cache_backend_up").len(), 1);
        assert_eq!(series("siphon_cache_errors_total").len(), 2);
        assert!(!backend_up("metrics_test_declared"));
        assert_eq!(errors("metrics_test_declared", "get"), 0);

        record_error("metrics_test_declared", "get");
        set_backend_up("metrics_test_declared", true);
        assert_eq!(errors("metrics_test_declared", "get"), 1);
        assert_eq!(errors("metrics_test_declared", "set"), 0);
        assert!(backend_up("metrics_test_declared"));
        set_backend_up("metrics_test_declared", false);
        assert!(!backend_up("metrics_test_declared"));
    }
}
