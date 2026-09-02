//! Custom Prometheus metrics registered by Python scripts.
//!
//! Scripts create counters, gauges, and histograms via `from siphon import metrics`.
//! All custom metrics are registered into the shared `prometheus::Registry` so they
//! appear alongside built-in metrics on the `/metrics` endpoint.

use std::collections::HashSet;
use std::sync::Mutex;

use dashmap::DashMap;
use prometheus::{CounterVec, GaugeVec, HistogramOpts, HistogramVec, Opts, Registry};
use regex::Regex;

/// Maximum number of distinct label-value combinations per metric.
const MAX_CARDINALITY: usize = 128;

/// Thread-safe store for script-defined Prometheus metrics.
pub struct CustomMetrics {
    registry: Registry,
    counters: DashMap<String, CounterVec>,
    gauges: DashMap<String, GaugeVec>,
    histograms: DashMap<String, HistogramVec>,
    /// Label names stored per metric (needed for `with_label_values` ordering).
    label_names: DashMap<String, Vec<String>>,
    /// Cardinality tracking: metric name → set of distinct label combos seen.
    cardinality: DashMap<String, Mutex<HashSet<Vec<String>>>>,
}

impl CustomMetrics {
    /// Create a new custom metrics store backed by the given registry.
    pub fn new(registry: &Registry) -> Self {
        Self {
            registry: registry.clone(),
            counters: DashMap::new(),
            gauges: DashMap::new(),
            histograms: DashMap::new(),
            label_names: DashMap::new(),
            cardinality: DashMap::new(),
        }
    }

    /// Register a new counter metric.
    pub fn register_counter(&self, name: &str, help: &str, labels: &[&str]) -> Result<(), String> {
        validate_metric_name(name)?;
        validate_labels(labels)?;
        if self.is_registered(name) {
            return Err(format!("metric '{name}' is already registered"));
        }

        let counter = CounterVec::new(Opts::new(name, help), labels)
            .map_err(|error| format!("failed to create counter '{name}': {error}"))?;
        self.registry
            .register(Box::new(counter.clone()))
            .map_err(|error| format!("failed to register counter '{name}': {error}"))?;

        self.counters.insert(name.to_owned(), counter);
        self.label_names.insert(
            name.to_owned(),
            labels.iter().map(|s| (*s).to_owned()).collect(),
        );
        self.cardinality
            .insert(name.to_owned(), Mutex::new(HashSet::new()));
        Ok(())
    }

    /// Register a new gauge metric.
    pub fn register_gauge(&self, name: &str, help: &str, labels: &[&str]) -> Result<(), String> {
        validate_metric_name(name)?;
        validate_labels(labels)?;
        if self.is_registered(name) {
            return Err(format!("metric '{name}' is already registered"));
        }

        let gauge = GaugeVec::new(Opts::new(name, help), labels)
            .map_err(|error| format!("failed to create gauge '{name}': {error}"))?;
        self.registry
            .register(Box::new(gauge.clone()))
            .map_err(|error| format!("failed to register gauge '{name}': {error}"))?;

        self.gauges.insert(name.to_owned(), gauge);
        self.label_names.insert(
            name.to_owned(),
            labels.iter().map(|s| (*s).to_owned()).collect(),
        );
        self.cardinality
            .insert(name.to_owned(), Mutex::new(HashSet::new()));
        Ok(())
    }

    /// Register a new histogram metric.
    pub fn register_histogram(
        &self,
        name: &str,
        help: &str,
        labels: &[&str],
        buckets: Vec<f64>,
    ) -> Result<(), String> {
        validate_metric_name(name)?;
        validate_labels(labels)?;
        if self.is_registered(name) {
            return Err(format!("metric '{name}' is already registered"));
        }

        let mut opts = HistogramOpts::new(name, help);
        if !buckets.is_empty() {
            opts = opts.buckets(buckets);
        }
        let histogram = HistogramVec::new(opts, labels)
            .map_err(|error| format!("failed to create histogram '{name}': {error}"))?;
        self.registry
            .register(Box::new(histogram.clone()))
            .map_err(|error| format!("failed to register histogram '{name}': {error}"))?;

        self.histograms.insert(name.to_owned(), histogram);
        self.label_names.insert(
            name.to_owned(),
            labels.iter().map(|s| (*s).to_owned()).collect(),
        );
        self.cardinality
            .insert(name.to_owned(), Mutex::new(HashSet::new()));
        Ok(())
    }

    /// Increment a counter.
    pub fn counter_inc(
        &self,
        name: &str,
        labels: &[(&str, &str)],
        value: f64,
    ) -> Result<(), String> {
        let counter = self
            .counters
            .get(name)
            .ok_or_else(|| format!("counter '{name}' not registered"))?;
        let label_values = self.resolve_label_values(name, labels)?;
        let refs: Vec<&str> = label_values.iter().map(|s| s.as_str()).collect();
        self.check_cardinality(name, &label_values)?;
        counter.with_label_values(&refs).inc_by(value);
        Ok(())
    }

    /// Set a gauge value.
    pub fn gauge_set(&self, name: &str, labels: &[(&str, &str)], value: f64) -> Result<(), String> {
        let gauge = self
            .gauges
            .get(name)
            .ok_or_else(|| format!("gauge '{name}' not registered"))?;
        let label_values = self.resolve_label_values(name, labels)?;
        let refs: Vec<&str> = label_values.iter().map(|s| s.as_str()).collect();
        self.check_cardinality(name, &label_values)?;
        gauge.with_label_values(&refs).set(value);
        Ok(())
    }

    /// Increment a gauge.
    pub fn gauge_inc(&self, name: &str, labels: &[(&str, &str)], value: f64) -> Result<(), String> {
        let gauge = self
            .gauges
            .get(name)
            .ok_or_else(|| format!("gauge '{name}' not registered"))?;
        let label_values = self.resolve_label_values(name, labels)?;
        let refs: Vec<&str> = label_values.iter().map(|s| s.as_str()).collect();
        self.check_cardinality(name, &label_values)?;
        gauge.with_label_values(&refs).add(value);
        Ok(())
    }

    /// Decrement a gauge.
    pub fn gauge_dec(&self, name: &str, labels: &[(&str, &str)], value: f64) -> Result<(), String> {
        let gauge = self
            .gauges
            .get(name)
            .ok_or_else(|| format!("gauge '{name}' not registered"))?;
        let label_values = self.resolve_label_values(name, labels)?;
        let refs: Vec<&str> = label_values.iter().map(|s| s.as_str()).collect();
        self.check_cardinality(name, &label_values)?;
        gauge.with_label_values(&refs).sub(value);
        Ok(())
    }

    /// Observe a histogram value.
    pub fn histogram_observe(
        &self,
        name: &str,
        labels: &[(&str, &str)],
        value: f64,
    ) -> Result<(), String> {
        let histogram = self
            .histograms
            .get(name)
            .ok_or_else(|| format!("histogram '{name}' not registered"))?;
        let label_values = self.resolve_label_values(name, labels)?;
        let refs: Vec<&str> = label_values.iter().map(|s| s.as_str()).collect();
        self.check_cardinality(name, &label_values)?;
        histogram.with_label_values(&refs).observe(value);
        Ok(())
    }

    /// Check if a metric name is already registered (any type).
    fn is_registered(&self, name: &str) -> bool {
        self.counters.contains_key(name)
            || self.gauges.contains_key(name)
            || self.histograms.contains_key(name)
    }

    /// Resolve label key-value pairs into ordered values matching the registered label names.
    fn resolve_label_values(
        &self,
        name: &str,
        labels: &[(&str, &str)],
    ) -> Result<Vec<String>, String> {
        let label_names = self
            .label_names
            .get(name)
            .ok_or_else(|| format!("metric '{name}' not registered"))?;

        if labels.is_empty() && label_names.is_empty() {
            return Ok(vec![]);
        }

        let mut values = Vec::with_capacity(label_names.len());
        for expected in label_names.iter() {
            let found = labels
                .iter()
                .find(|(key, _)| key == expected)
                .ok_or_else(|| format!("missing label '{expected}' for metric '{name}'"))?;
            values.push(found.1.to_owned());
        }
        Ok(values)
    }

    /// Check cardinality for this metric — only counts distinct label combos.
    fn check_cardinality(&self, name: &str, label_values: &[String]) -> Result<(), String> {
        if let Some(seen) = self.cardinality.get(name) {
            let mut set = seen.lock().unwrap();
            if set.contains(label_values) {
                return Ok(());
            }
            if set.len() >= MAX_CARDINALITY {
                return Err(format!(
                    "cardinality limit ({MAX_CARDINALITY}) exceeded for metric '{name}'"
                ));
            }
            set.insert(label_values.to_vec());
        }
        Ok(())
    }
}

/// Validate a Prometheus metric name.
fn validate_metric_name(name: &str) -> Result<(), String> {
    // Thread-local compiled regex for performance.
    thread_local! {
        static RE: Regex = Regex::new(r"^[a-zA-Z_:][a-zA-Z0-9_:]*$").unwrap();
    }
    RE.with(|regex| {
        if regex.is_match(name) {
            Ok(())
        } else {
            Err(format!(
                "invalid metric name '{name}': must match [a-zA-Z_:][a-zA-Z0-9_:]*"
            ))
        }
    })
}

/// Validate a set of Prometheus label names.
fn validate_labels(labels: &[&str]) -> Result<(), String> {
    thread_local! {
        static RE: Regex = Regex::new(r"^[a-zA-Z_][a-zA-Z0-9_]*$").unwrap();
    }
    for label in labels {
        if label.starts_with("__") {
            return Err(format!(
                "invalid label name '{label}': labels starting with '__' are reserved"
            ));
        }
        RE.with(|regex| {
            if !regex.is_match(label) {
                Err(format!(
                    "invalid label name '{label}': must match [a-zA-Z_][a-zA-Z0-9_]*"
                ))
            } else {
                Ok(())
            }
        })?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use prometheus::Encoder;

    use super::*;

    fn test_registry() -> (Registry, Arc<CustomMetrics>) {
        let registry = Registry::new();
        let custom = Arc::new(CustomMetrics::new(&registry));
        (registry, custom)
    }

    #[test]
    fn register_and_increment_counter() {
        let (_registry, custom) = test_registry();
        custom
            .register_counter("test_requests_total", "Total requests", &[])
            .unwrap();
        custom.counter_inc("test_requests_total", &[], 1.0).unwrap();
        custom.counter_inc("test_requests_total", &[], 1.0).unwrap();

        let counter = custom.counters.get("test_requests_total").unwrap();
        // prometheus 0.14: `with_label_values` infers its element type from the
        // slice, so an empty slice needs an explicit `&[&str]` annotation.
        assert_eq!(counter.with_label_values(&[] as &[&str]).get(), 2.0);
    }

    #[test]
    fn counter_with_labels() {
        let (_registry, custom) = test_registry();
        custom
            .register_counter("test_calls_total", "Calls", &["direction", "result"])
            .unwrap();

        custom
            .counter_inc(
                "test_calls_total",
                &[("direction", "inbound"), ("result", "ok")],
                1.0,
            )
            .unwrap();
        custom
            .counter_inc(
                "test_calls_total",
                &[("direction", "outbound"), ("result", "ok")],
                3.0,
            )
            .unwrap();

        let counter = custom.counters.get("test_calls_total").unwrap();
        assert_eq!(counter.with_label_values(&["inbound", "ok"]).get(), 1.0);
        assert_eq!(counter.with_label_values(&["outbound", "ok"]).get(), 3.0);
    }

    #[test]
    fn register_and_use_gauge() {
        let (_registry, custom) = test_registry();
        custom
            .register_gauge("test_active", "Active things", &[])
            .unwrap();

        custom.gauge_inc("test_active", &[], 1.0).unwrap();
        custom.gauge_inc("test_active", &[], 1.0).unwrap();
        custom.gauge_dec("test_active", &[], 1.0).unwrap();

        let gauge = custom.gauges.get("test_active").unwrap();
        assert_eq!(gauge.with_label_values(&[] as &[&str]).get(), 1.0);
    }

    #[test]
    fn gauge_set() {
        let (_registry, custom) = test_registry();
        custom
            .register_gauge("test_gauge", "A gauge", &["env"])
            .unwrap();

        custom
            .gauge_set("test_gauge", &[("env", "prod")], 42.0)
            .unwrap();

        let gauge = custom.gauges.get("test_gauge").unwrap();
        assert_eq!(gauge.with_label_values(&["prod"]).get(), 42.0);
    }

    #[test]
    fn register_and_observe_histogram() {
        let (_registry, custom) = test_registry();
        custom
            .register_histogram(
                "test_duration_seconds",
                "Duration",
                &[],
                vec![0.1, 0.5, 1.0],
            )
            .unwrap();

        custom
            .histogram_observe("test_duration_seconds", &[], 0.3)
            .unwrap();
        custom
            .histogram_observe("test_duration_seconds", &[], 0.8)
            .unwrap();

        let histogram = custom.histograms.get("test_duration_seconds").unwrap();
        assert_eq!(
            histogram
                .with_label_values(&[] as &[&str])
                .get_sample_count(),
            2
        );
    }

    #[test]
    fn duplicate_name_rejected() {
        let (_registry, custom) = test_registry();
        custom.register_counter("dup_total", "First", &[]).unwrap();
        let result = custom.register_counter("dup_total", "Second", &[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already registered"));
    }

    #[test]
    fn duplicate_across_types_rejected() {
        let (_registry, custom) = test_registry();
        custom
            .register_counter("cross_type", "Counter", &[])
            .unwrap();
        let result = custom.register_gauge("cross_type", "Gauge", &[]);
        assert!(result.is_err());
    }

    #[test]
    fn invalid_metric_name_rejected() {
        let (_registry, custom) = test_registry();
        let result = custom.register_counter("123_bad", "Bad", &[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid metric name"));
    }

    #[test]
    fn reserved_label_rejected() {
        let (_registry, custom) = test_registry();
        let result = custom.register_counter("ok_name", "Fine", &["__reserved"]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("reserved"));
    }

    #[test]
    fn invalid_label_name_rejected() {
        let (_registry, custom) = test_registry();
        let result = custom.register_counter("ok_name", "Fine", &["bad-label"]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid label name"));
    }

    #[test]
    fn missing_label_value_rejected() {
        let (_registry, custom) = test_registry();
        custom
            .register_counter("labeled_total", "Test", &["method"])
            .unwrap();
        let result = custom.counter_inc("labeled_total", &[], 1.0);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing label"));
    }

    #[test]
    fn unregistered_metric_rejected() {
        let (_registry, custom) = test_registry();
        let result = custom.counter_inc("nonexistent", &[], 1.0);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not registered"));
    }

    #[test]
    fn cardinality_guard() {
        let (_registry, custom) = test_registry();
        custom
            .register_gauge("cardinality_test", "Test", &["id"])
            .unwrap();

        // Fill up to the limit.
        for i in 0..MAX_CARDINALITY {
            custom
                .gauge_set("cardinality_test", &[("id", &i.to_string())], 1.0)
                .unwrap();
        }

        // Next one should fail.
        let result = custom.gauge_set("cardinality_test", &[("id", "overflow")], 1.0);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cardinality limit"));
    }

    #[test]
    fn metrics_appear_in_encode() {
        let (registry, custom) = test_registry();
        custom
            .register_counter("encode_test_total", "Test", &["method"])
            .unwrap();
        custom
            .counter_inc("encode_test_total", &[("method", "INVITE")], 5.0)
            .unwrap();

        let encoder = prometheus::TextEncoder::new();
        let families = registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&families, &mut buffer).unwrap();
        let output = String::from_utf8(buffer).unwrap();

        assert!(output.contains("encode_test_total"));
        assert!(output.contains("INVITE"));
    }
}
