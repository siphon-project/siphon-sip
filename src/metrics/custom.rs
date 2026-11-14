//! Custom Prometheus metrics registered by Python scripts.
//!
//! Scripts create counters, gauges, and histograms via `from siphon import metrics`.
//! All custom metrics are registered into the shared `prometheus::Registry` so they
//! appear alongside built-in metrics on the `/metrics` endpoint.

use std::cell::RefCell;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::OnceLock;

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use prometheus::{
    Counter, CounterVec, Gauge, GaugeVec, Histogram, HistogramOpts, HistogramVec, Opts, Registry,
};
use regex::Regex;

/// Maximum number of distinct label-value combinations per metric.
const MAX_CARDINALITY: usize = 128;

thread_local! {
    /// Scratch space the label-value lookup key is built in, so an update of a
    /// label combination already seen allocates nothing.
    static KEY_BUFFER: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// The resolved prometheus children of one metric, by label-value combination.
///
/// This is the whole per-update path: a repeat update builds its key in a
/// thread-local buffer, finds the child with one lookup and updates it, with no
/// lock and no allocation. The number of children is the metric's cardinality,
/// so a combination is admitted, once, against [`MAX_CARDINALITY`] the first
/// time it is seen. A metric's series is replaced when the metric is
/// registered anew, so no child outlives the metric it belongs to.
struct Series<T> {
    /// Label names in the order the prometheus vector was declared with.
    label_names: Box<[String]>,
    /// Keyed by every label value in declaration order, each prefixed with its
    /// length so that no two combinations encode alike.
    children: DashMap<Box<[u8]>, T>,
    /// The one child of a metric declared without labels, which has no
    /// combination to look up.
    unlabeled: OnceLock<T>,
    /// Combinations admitted so far. Reserved before a child is created, so the
    /// limit holds exactly however many threads race to pass it.
    admitted: AtomicUsize,
}

impl<T> Series<T> {
    fn new(labels: &[&str]) -> Self {
        Self {
            label_names: labels.iter().map(|label| (*label).to_owned()).collect(),
            children: DashMap::new(),
            unlabeled: OnceLock::new(),
            admitted: AtomicUsize::new(0),
        }
    }

    /// The value `labels` gives for `expected`.
    fn value_of<'a>(
        name: &str,
        expected: &str,
        labels: &[(&str, &'a str)],
    ) -> Result<&'a str, String> {
        labels
            .iter()
            .find(|(key, _)| *key == expected)
            .map(|(_, value)| *value)
            .ok_or_else(|| format!("missing label '{expected}' for metric '{name}'"))
    }

    /// Run `apply` on the child for `labels`, creating it with `create` (given
    /// the label values in declaration order) the first time the combination is
    /// seen, unless that would take the metric past [`MAX_CARDINALITY`].
    fn with<R>(
        &self,
        name: &str,
        labels: &[(&str, &str)],
        create: impl FnOnce(&[&str]) -> Result<T, String>,
        apply: impl FnOnce(&T) -> R,
    ) -> Result<R, String> {
        if self.label_names.is_empty() {
            if let Some(child) = self.unlabeled.get() {
                return Ok(apply(child));
            }
            // Two threads may both get here; the prometheus vector hands both
            // the same child, and one of them is kept.
            let child = create(&[])?;
            return Ok(apply(self.unlabeled.get_or_init(|| child)));
        }
        // Taken out of the cell, not borrowed, so nothing here can be a
        // re-entrant borrow.
        let mut key = KEY_BUFFER.with(RefCell::take);
        key.clear();
        let outcome = self.with_key(name, labels, &mut key, create, apply);
        KEY_BUFFER.with(|buffer| buffer.replace(key));
        outcome
    }

    fn with_key<R>(
        &self,
        name: &str,
        labels: &[(&str, &str)],
        key: &mut Vec<u8>,
        create: impl FnOnce(&[&str]) -> Result<T, String>,
        apply: impl FnOnce(&T) -> R,
    ) -> Result<R, String> {
        for expected in self.label_names.iter() {
            let value = Self::value_of(name, expected, labels)?;
            key.extend_from_slice(&(value.len() as u64).to_le_bytes());
            key.extend_from_slice(value.as_bytes());
        }
        if let Some(child) = self.children.get(key.as_slice()) {
            return Ok(apply(&child));
        }
        match self.children.entry(key.as_slice().into()) {
            Entry::Occupied(occupied) => Ok(apply(occupied.get())),
            Entry::Vacant(vacant) => {
                let reserved =
                    self.admitted
                        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |admitted| {
                            (admitted < MAX_CARDINALITY).then_some(admitted + 1)
                        });
                if reserved.is_err() {
                    return Err(format!(
                        "cardinality limit ({MAX_CARDINALITY}) exceeded for metric '{name}'"
                    ));
                }
                let mut values = Vec::with_capacity(self.label_names.len());
                for expected in self.label_names.iter() {
                    values.push(Self::value_of(name, expected, labels)?);
                }
                match create(&values) {
                    Ok(child) => {
                        let result = apply(&child);
                        vacant.insert(child);
                        Ok(result)
                    }
                    Err(error) => {
                        self.admitted.fetch_sub(1, Ordering::AcqRel);
                        Err(error)
                    }
                }
            }
        }
    }
}

/// The three kinds of metric a script can declare.
#[derive(Clone, Copy, Debug, PartialEq)]
enum MetricKind {
    Counter,
    Gauge,
    Histogram,
}

impl std::fmt::Display for MetricKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            MetricKind::Counter => "counter",
            MetricKind::Gauge => "gauge",
            MetricKind::Histogram => "histogram",
        })
    }
}

/// What a metric was declared as: everything about it that cannot change while
/// it stays registered.
#[derive(Clone, Debug, PartialEq)]
struct Declaration {
    kind: MetricKind,
    labels: Vec<String>,
    /// As given; empty means the default buckets. Always empty unless a histogram.
    buckets: Vec<f64>,
}

impl Declaration {
    fn new(kind: MetricKind, labels: &[&str], buckets: &[f64]) -> Self {
        Self {
            kind,
            labels: labels.iter().map(|label| (*label).to_owned()).collect(),
            buckets: buckets.to_vec(),
        }
    }
}

impl std::fmt::Display for Declaration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "a {} with labels [{}]",
            self.kind,
            self.labels.join(", ")
        )?;
        if self.kind == MetricKind::Histogram {
            if self.buckets.is_empty() {
                formatter.write_str(" and the default buckets")?;
            } else {
                write!(formatter, " and buckets {:?}", self.buckets)?;
            }
        }
        Ok(())
    }
}

/// How a declaration relates to what is already registered.
enum Claim {
    /// The name was free; it is now claimed by this script load, whose number
    /// this carries, and the caller registers the metric.
    New(u64),
    /// An earlier script load registered the same metric, and this load has
    /// taken it over as it is.
    TakenOver,
}

/// Thread-safe store for script-defined Prometheus metrics.
pub struct CustomMetrics {
    registry: Registry,
    counters: DashMap<String, CounterVec>,
    gauges: DashMap<String, GaugeVec>,
    histograms: DashMap<String, HistogramVec>,
    /// The children each metric's updates go to, by label values; they also
    /// carry the metric's label names and its cardinality count.
    counter_series: DashMap<String, Series<Counter>>,
    gauge_series: DashMap<String, Series<Gauge>>,
    histogram_series: DashMap<String, Series<Histogram>>,
    /// Every declared metric, with the script load that last declared it.
    declarations: DashMap<String, (Declaration, u64)>,
    /// The script load declarations are made by now; see [`Self::begin_script_load`].
    script_load: AtomicU64,
}

impl CustomMetrics {
    /// Create a new custom metrics store backed by the given registry.
    pub fn new(registry: &Registry) -> Self {
        Self {
            registry: registry.clone(),
            counters: DashMap::new(),
            gauges: DashMap::new(),
            histograms: DashMap::new(),
            counter_series: DashMap::new(),
            gauge_series: DashMap::new(),
            histogram_series: DashMap::new(),
            declarations: DashMap::new(),
            script_load: AtomicU64::new(0),
        }
    }

    /// Start a new script load.
    ///
    /// A script declares its metrics at its top level, and a reload runs that
    /// top level again while the metrics the replaced load declared stay
    /// registered, as do the handles its handlers hold. So a load may declare a
    /// metric an earlier load declared, and takes it over with the values it
    /// has, as long as its type, labels and buckets are unchanged; those cannot
    /// change without a restart. The metric keeps the help text it was first
    /// registered with. Declaring one name twice within one load is an error.
    pub fn begin_script_load(&self) {
        self.script_load.fetch_add(1, Ordering::Relaxed);
    }

    /// Claim `name` for `declaration` on behalf of the current script load.
    fn claim(&self, name: &str, declaration: &Declaration) -> Result<Claim, String> {
        let script_load = self.script_load.load(Ordering::Relaxed);
        match self.declarations.entry(name.to_owned()) {
            Entry::Vacant(vacant) => {
                vacant.insert((declaration.clone(), script_load));
                Ok(Claim::New(script_load))
            }
            Entry::Occupied(mut occupied) => {
                let (registered, declared_in) = occupied.get_mut();
                if *declared_in == script_load {
                    return Err(format!("metric '{name}' is already registered"));
                }
                if registered != declaration {
                    return Err(format!(
                        "metric '{name}' is already registered as {registered}; a reload \
                         cannot change a metric's type, labels or buckets, restart to change them"
                    ));
                }
                *declared_in = script_load;
                Ok(Claim::TakenOver)
            }
        }
    }

    /// Give back a new claim whose metric could not be registered after all.
    fn release(&self, name: &str, script_load: u64) {
        self.declarations
            .remove_if(name, |_, (_, declared_in)| *declared_in == script_load);
    }

    /// Register a new counter metric. See [`Self::begin_script_load`] for a
    /// reload declaring it again.
    pub fn register_counter(&self, name: &str, help: &str, labels: &[&str]) -> Result<(), String> {
        validate_metric_name(name)?;
        validate_labels(labels)?;
        let counter = CounterVec::new(Opts::new(name, help), labels)
            .map_err(|error| format!("failed to create counter '{name}': {error}"))?;

        let Claim::New(script_load) =
            self.claim(name, &Declaration::new(MetricKind::Counter, labels, &[]))?
        else {
            return Ok(());
        };
        if let Err(error) = self.registry.register(Box::new(counter.clone())) {
            self.release(name, script_load);
            return Err(format!("failed to register counter '{name}': {error}"));
        }

        // The series first: an update finds the metric by its series.
        self.counter_series
            .insert(name.to_owned(), Series::new(labels));
        self.counters.insert(name.to_owned(), counter);
        Ok(())
    }

    /// Register a new gauge metric. See [`Self::begin_script_load`] for a
    /// reload declaring it again.
    pub fn register_gauge(&self, name: &str, help: &str, labels: &[&str]) -> Result<(), String> {
        validate_metric_name(name)?;
        validate_labels(labels)?;
        let gauge = GaugeVec::new(Opts::new(name, help), labels)
            .map_err(|error| format!("failed to create gauge '{name}': {error}"))?;

        let Claim::New(script_load) =
            self.claim(name, &Declaration::new(MetricKind::Gauge, labels, &[]))?
        else {
            return Ok(());
        };
        if let Err(error) = self.registry.register(Box::new(gauge.clone())) {
            self.release(name, script_load);
            return Err(format!("failed to register gauge '{name}': {error}"));
        }

        self.gauge_series
            .insert(name.to_owned(), Series::new(labels));
        self.gauges.insert(name.to_owned(), gauge);
        Ok(())
    }

    /// Register a new histogram metric. See [`Self::begin_script_load`] for a
    /// reload declaring it again.
    pub fn register_histogram(
        &self,
        name: &str,
        help: &str,
        labels: &[&str],
        buckets: Vec<f64>,
    ) -> Result<(), String> {
        validate_metric_name(name)?;
        validate_labels(labels)?;
        let declaration = Declaration::new(MetricKind::Histogram, labels, &buckets);
        let mut opts = HistogramOpts::new(name, help);
        if !buckets.is_empty() {
            opts = opts.buckets(buckets);
        }
        let histogram = HistogramVec::new(opts, labels)
            .map_err(|error| format!("failed to create histogram '{name}': {error}"))?;

        let Claim::New(script_load) = self.claim(name, &declaration)? else {
            return Ok(());
        };
        if let Err(error) = self.registry.register(Box::new(histogram.clone())) {
            self.release(name, script_load);
            return Err(format!("failed to register histogram '{name}': {error}"));
        }

        self.histogram_series
            .insert(name.to_owned(), Series::new(labels));
        self.histograms.insert(name.to_owned(), histogram);
        Ok(())
    }

    /// Increment a counter.
    pub fn counter_inc(
        &self,
        name: &str,
        labels: &[(&str, &str)],
        value: f64,
    ) -> Result<(), String> {
        let series = self
            .counter_series
            .get(name)
            .ok_or_else(|| format!("counter '{name}' not registered"))?;
        series.with(
            name,
            labels,
            |values| {
                self.counters
                    .get(name)
                    .map(|counter| counter.with_label_values(values))
                    .ok_or_else(|| format!("counter '{name}' not registered"))
            },
            |counter| counter.inc_by(value),
        )
    }

    /// Set a gauge value.
    pub fn gauge_set(&self, name: &str, labels: &[(&str, &str)], value: f64) -> Result<(), String> {
        self.gauge_update(name, labels, |gauge| gauge.set(value))
    }

    /// Increment a gauge.
    pub fn gauge_inc(&self, name: &str, labels: &[(&str, &str)], value: f64) -> Result<(), String> {
        self.gauge_update(name, labels, |gauge| gauge.add(value))
    }

    /// Decrement a gauge.
    pub fn gauge_dec(&self, name: &str, labels: &[(&str, &str)], value: f64) -> Result<(), String> {
        self.gauge_update(name, labels, |gauge| gauge.sub(value))
    }

    fn gauge_update(
        &self,
        name: &str,
        labels: &[(&str, &str)],
        update: impl FnOnce(&Gauge),
    ) -> Result<(), String> {
        let series = self
            .gauge_series
            .get(name)
            .ok_or_else(|| format!("gauge '{name}' not registered"))?;
        series.with(
            name,
            labels,
            |values| {
                self.gauges
                    .get(name)
                    .map(|gauge| gauge.with_label_values(values))
                    .ok_or_else(|| format!("gauge '{name}' not registered"))
            },
            update,
        )
    }

    /// Observe a histogram value.
    pub fn histogram_observe(
        &self,
        name: &str,
        labels: &[(&str, &str)],
        value: f64,
    ) -> Result<(), String> {
        let series = self
            .histogram_series
            .get(name)
            .ok_or_else(|| format!("histogram '{name}' not registered"))?;
        series.with(
            name,
            labels,
            |values| {
                self.histograms
                    .get(name)
                    .map(|histogram| histogram.with_label_values(values))
                    .ok_or_else(|| format!("histogram '{name}' not registered"))
            },
            |histogram| histogram.observe(value),
        )
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

    /// A reload runs the script's declarations again: the load after it takes
    /// an identical metric over, values and all, and still may not declare one
    /// name twice itself.
    #[test]
    fn a_later_script_load_takes_over_an_identical_declaration() {
        let (registry, custom) = test_registry();
        custom
            .register_counter("reloaded_total", "Calls", &["direction"])
            .unwrap();
        custom
            .counter_inc("reloaded_total", &[("direction", "inbound")], 2.0)
            .unwrap();

        custom.begin_script_load();
        custom
            .register_counter("reloaded_total", "Calls", &["direction"])
            .expect("a later load takes over an identical declaration");
        custom
            .counter_inc("reloaded_total", &[("direction", "inbound")], 1.0)
            .unwrap();

        let counter = custom.counters.get("reloaded_total").unwrap();
        assert_eq!(
            counter.with_label_values(&["inbound"]).get(),
            3.0,
            "the metric taken over keeps its value"
        );
        assert_eq!(
            registry
                .gather()
                .iter()
                .filter(|family| family.name() == "reloaded_total")
                .count(),
            1,
            "taking a metric over registers nothing new"
        );
        let twice = custom
            .register_counter("reloaded_total", "Calls", &["direction"])
            .expect_err("one load still may not declare a name twice");
        assert!(twice.contains("already registered"), "{twice}");
    }

    /// What a registered metric is cannot change under it, so a later load
    /// that declares the name differently is refused, and says why.
    #[test]
    fn a_later_script_load_cannot_change_what_a_metric_is() {
        let (_registry, custom) = test_registry();
        custom
            .register_counter("shaped_total", "Calls", &["direction"])
            .unwrap();
        custom
            .register_histogram("shaped_seconds", "Latency", &[], vec![0.1, 1.0])
            .unwrap();

        custom.begin_script_load();
        let labels = custom
            .register_counter("shaped_total", "Calls", &["direction", "result"])
            .expect_err("different labels");
        assert!(labels.contains("labels [direction]"), "{labels}");
        let kind = custom
            .register_gauge("shaped_total", "Calls", &["direction"])
            .expect_err("a different type");
        assert!(kind.contains("a counter"), "{kind}");
        let buckets = custom
            .register_histogram("shaped_seconds", "Latency", &[], vec![0.5, 5.0])
            .expect_err("different buckets");
        assert!(buckets.contains("buckets [0.1, 1.0]"), "{buckets}");

        // A refused declaration leaves the metric to the load that has it, so a
        // later load that declares it as it was still takes it over.
        custom.begin_script_load();
        custom
            .register_counter("shaped_total", "Calls", &["direction"])
            .expect("the unchanged declaration is still taken over");
    }

    /// A claim whose metric the registry refuses is given back, so the name is
    /// not left claimed by a metric that does not exist.
    #[test]
    fn a_declaration_the_registry_refuses_leaves_the_name_free() {
        let (registry, custom) = test_registry();
        let taken = prometheus::IntCounter::new("taken_by_siphon_total", "Built in").unwrap();
        registry.register(Box::new(taken)).unwrap();

        assert!(custom
            .register_counter("taken_by_siphon_total", "Script", &[])
            .is_err());
        assert!(
            custom.declarations.get("taken_by_siphon_total").is_none(),
            "a refused registration must not stay claimed"
        );
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

    fn counter_value(registry: &Registry, name: &str, label_value: &str) -> Option<f64> {
        registry
            .gather()
            .iter()
            .find(|family| family.name() == name)?
            .get_metric()
            .iter()
            .find(|metric| {
                metric
                    .get_label()
                    .iter()
                    .any(|label| label.value() == label_value)
            })
            .map(|metric| metric.get_counter().value())
    }

    fn series_count(registry: &Registry, name: &str) -> usize {
        registry
            .gather()
            .iter()
            .find(|family| family.name() == name)
            .map_or(0, |family| family.get_metric().len())
    }

    #[test]
    fn repeat_updates_hit_the_same_series() {
        let (registry, custom) = test_registry();
        custom
            .register_counter("repeat_total", "Test", &["method", "result"])
            .unwrap();
        for _ in 0..3 {
            custom
                .counter_inc(
                    "repeat_total",
                    &[("method", "INVITE"), ("result", "ok")],
                    1.0,
                )
                .unwrap();
        }
        // Label order in the call does not matter.
        custom
            .counter_inc(
                "repeat_total",
                &[("result", "ok"), ("method", "INVITE")],
                1.0,
            )
            .unwrap();
        assert_eq!(series_count(&registry, "repeat_total"), 1);
        assert_eq!(
            counter_value(&registry, "repeat_total", "INVITE"),
            Some(4.0)
        );
    }

    #[test]
    fn label_values_that_would_concatenate_alike_stay_distinct() {
        // Tested on the series itself: the prometheus crate keys its own
        // children by a hash of the concatenated values, so it cannot show
        // whether our key told these apart.
        let series: Series<usize> = Series::new(&["first", "second"]);
        let mut created = 0;
        for (first, second) in [("a\0", "b"), ("a", "\0b"), ("ab", ""), ("a", "b")] {
            let child = series
                .with(
                    "ambiguous",
                    &[("first", first), ("second", second)],
                    |_| {
                        created += 1;
                        Ok(created)
                    },
                    |child| *child,
                )
                .unwrap();
            assert_eq!(child, created);
        }
        assert_eq!(created, 4);
        // And the same combination again finds its child instead of creating one.
        let again = series
            .with(
                "ambiguous",
                &[("first", "ab"), ("second", "")],
                |_| Ok(99),
                |c| *c,
            )
            .unwrap();
        assert_eq!(again, 3);
    }

    /// A metric without labels has one child, made once and then found without
    /// a lookup, however many updates follow and however many threads make them.
    #[test]
    fn an_unlabeled_series_creates_its_child_once() {
        let series: Series<usize> = Series::new(&[]);
        let created = AtomicUsize::new(0);
        for _ in 0..1000 {
            let child = series
                .with(
                    "plain",
                    &[],
                    |_| Ok(created.fetch_add(1, Ordering::Relaxed) + 1),
                    |child| *child,
                )
                .unwrap();
            assert_eq!(child, 1);
        }
        assert_eq!(created.load(Ordering::Relaxed), 1);
        assert_eq!(series.children.len(), 0, "no map entry for the one child");
        // Labels a metric did not declare are not part of its identity.
        let child = series
            .with("plain", &[("extra", "x")], |_| Ok(99), |child| *child)
            .unwrap();
        assert_eq!(child, 1);
    }

    #[test]
    fn an_unlabeled_series_failing_to_create_leaves_nothing_behind() {
        let series: Series<usize> = Series::new(&[]);
        assert!(series
            .with("plain", &[], |_| Err("refused".to_owned()), |child| *child)
            .is_err());
        let child = series
            .with("plain", &[], |_| Ok(7), |child| *child)
            .unwrap();
        assert_eq!(child, 7, "the next update creates it");
    }

    #[test]
    fn unlabeled_updates_from_many_threads_share_one_series() {
        let (registry, custom) = test_registry();
        custom.register_counter("plain_total", "Test", &[]).unwrap();
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let custom = Arc::clone(&custom);
                std::thread::spawn(move || {
                    for _ in 0..1000 {
                        custom.counter_inc("plain_total", &[], 1.0).unwrap();
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(series_count(&registry, "plain_total"), 1);
        let families = registry.gather();
        let family = families
            .iter()
            .find(|family| family.name() == "plain_total")
            .unwrap();
        assert_eq!(family.get_metric()[0].get_counter().value(), 8000.0);
    }

    #[test]
    fn missing_label_error_names_label_and_metric() {
        let (registry, custom) = test_registry();
        custom
            .register_counter("named_total", "Test", &["method", "result"])
            .unwrap();
        let error = custom
            .counter_inc("named_total", &[("method", "INVITE")], 1.0)
            .unwrap_err();
        assert_eq!(error, "missing label 'result' for metric 'named_total'");
        assert_eq!(
            series_count(&registry, "named_total"),
            0,
            "a refused update must not create a series"
        );
    }

    #[test]
    fn an_already_seen_combination_still_updates_at_the_limit() {
        let (registry, custom) = test_registry();
        custom
            .register_counter("limit_total", "Test", &["id"])
            .unwrap();
        for index in 0..MAX_CARDINALITY {
            custom
                .counter_inc("limit_total", &[("id", &index.to_string())], 1.0)
                .unwrap();
        }
        let error = custom
            .counter_inc("limit_total", &[("id", "overflow")], 1.0)
            .unwrap_err();
        assert_eq!(
            error,
            format!("cardinality limit ({MAX_CARDINALITY}) exceeded for metric 'limit_total'")
        );
        custom
            .counter_inc("limit_total", &[("id", "0")], 1.0)
            .expect("a combination already seen is not new cardinality");
        assert_eq!(counter_value(&registry, "limit_total", "0"), Some(2.0));
        assert_eq!(counter_value(&registry, "limit_total", "overflow"), None);
    }

    #[test]
    fn cardinality_limit_is_exact_under_concurrency() {
        let (registry, custom) = test_registry();
        custom
            .register_counter("race_total", "Test", &["id"])
            .unwrap();
        let threads = 8;
        let attempts_per_thread = 64;
        let handles: Vec<_> = (0..threads)
            .map(|thread_index| {
                let custom = Arc::clone(&custom);
                std::thread::spawn(move || {
                    let mut accepted = 0;
                    for attempt in 0..attempts_per_thread {
                        // Every thread tries distinct combinations: 512 in all.
                        let id = (thread_index * attempts_per_thread + attempt).to_string();
                        if custom
                            .counter_inc("race_total", &[("id", &id)], 1.0)
                            .is_ok()
                        {
                            accepted += 1;
                        }
                    }
                    accepted
                })
            })
            .collect();
        let accepted: usize = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .sum();
        assert_eq!(accepted, MAX_CARDINALITY);
        assert_eq!(series_count(&registry, "race_total"), MAX_CARDINALITY);
    }

    #[test]
    fn concurrent_repeat_updates_lose_nothing() {
        let (registry, custom) = test_registry();
        custom
            .register_histogram("hot_seconds", "Test", &["method"], vec![1.0])
            .unwrap();
        custom
            .register_counter("hot_total", "Test", &["method"])
            .unwrap();
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let custom = Arc::clone(&custom);
                std::thread::spawn(move || {
                    for _ in 0..1000 {
                        custom
                            .counter_inc("hot_total", &[("method", "INVITE")], 1.0)
                            .unwrap();
                        custom
                            .histogram_observe("hot_seconds", &[("method", "INVITE")], 0.5)
                            .unwrap();
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(
            counter_value(&registry, "hot_total", "INVITE"),
            Some(8000.0)
        );
        let histograms = custom.histograms.get("hot_seconds").unwrap();
        assert_eq!(
            histograms.with_label_values(&["INVITE"]).get_sample_count(),
            8000
        );
    }

    /// A claim the registry refuses leaves nothing behind that an update could
    /// reach.
    #[test]
    fn a_refused_registration_leaves_no_series_to_update() {
        let (registry, custom) = test_registry();
        let taken = prometheus::IntCounter::new("refused_total", "Built in").unwrap();
        registry.register(Box::new(taken)).unwrap();
        assert!(custom
            .register_counter("refused_total", "Script", &[])
            .is_err());
        let error = custom.counter_inc("refused_total", &[], 1.0).unwrap_err();
        assert!(error.contains("not registered"), "{error}");
    }

    /// A taken-over metric keeps counting into the series it had, and its
    /// cardinality budget carries over rather than resetting.
    #[test]
    fn a_taken_over_metric_keeps_its_series_and_cardinality_budget() {
        let (registry, custom) = test_registry();
        custom
            .register_counter("carried_total", "Test", &["id"])
            .unwrap();
        for index in 0..MAX_CARDINALITY {
            custom
                .counter_inc("carried_total", &[("id", &index.to_string())], 1.0)
                .unwrap();
        }
        custom.begin_script_load();
        custom
            .register_counter("carried_total", "Test", &["id"])
            .unwrap();
        custom
            .counter_inc("carried_total", &[("id", "3")], 1.0)
            .unwrap();
        assert_eq!(counter_value(&registry, "carried_total", "3"), Some(2.0));
        assert!(custom
            .counter_inc("carried_total", &[("id", "fresh")], 1.0)
            .is_err());
    }

    #[test]
    fn gauge_and_histogram_share_the_limit_and_label_checks() {
        let (_registry, custom) = test_registry();
        custom
            .register_gauge("shared_gauge", "Test", &["id"])
            .unwrap();
        custom
            .register_histogram("shared_seconds", "Test", &["id"], vec![])
            .unwrap();
        assert!(custom
            .gauge_inc("shared_gauge", &[], 1.0)
            .unwrap_err()
            .contains("missing label 'id'"));
        assert!(custom
            .histogram_observe("shared_seconds", &[], 1.0)
            .unwrap_err()
            .contains("missing label 'id'"));
        for index in 0..MAX_CARDINALITY {
            let id = index.to_string();
            custom
                .gauge_dec("shared_gauge", &[("id", &id)], 1.0)
                .unwrap();
            custom
                .histogram_observe("shared_seconds", &[("id", &id)], 1.0)
                .unwrap();
        }
        assert!(custom
            .gauge_dec("shared_gauge", &[("id", "x")], 1.0)
            .unwrap_err()
            .contains("cardinality limit"));
        assert!(custom
            .histogram_observe("shared_seconds", &[("id", "x")], 1.0)
            .unwrap_err()
            .contains("cardinality limit"));
    }
}
