//! Python `metrics` namespace — custom Prometheus metrics from scripts.
//!
//! Allows Python scripts to define counters, gauges, and histograms:
//! ```python
//! from siphon import metrics
//!
//! calls = metrics.counter("bgcf_calls_total", "Total calls", labels=["direction"])
//! calls.labels(direction="outbound").inc()
//! ```

use std::collections::HashMap;
use std::sync::Arc;

use pyo3::prelude::*;

use crate::metrics::custom::CustomMetrics;

// ---------------------------------------------------------------------------
// Top-level namespace: metrics.counter(), metrics.gauge(), metrics.histogram()
// ---------------------------------------------------------------------------

/// Python-facing metrics namespace.
#[pyclass(name = "MetricsNamespace")]
pub struct PyMetricsNamespace {
    custom: Arc<CustomMetrics>,
}

impl PyMetricsNamespace {
    pub fn new(custom: Arc<CustomMetrics>) -> Self {
        Self { custom }
    }
}

#[pymethods]
impl PyMetricsNamespace {
    /// Create a new counter metric.
    ///
    /// Args:
    ///     name: Metric name (e.g. "bgcf_calls_outbound_total").
    ///     help: Description string.
    ///     labels: Optional list of label names.
    ///
    /// Returns:
    ///     A Counter handle for incrementing.
    #[pyo3(signature = (name, help, labels=None))]
    fn counter(
        &self,
        name: &str,
        help: &str,
        labels: Option<Vec<String>>,
    ) -> PyResult<PyCounter> {
        let label_names = labels.unwrap_or_default();
        let label_refs: Vec<&str> = label_names.iter().map(|s| s.as_str()).collect();
        self.custom
            .register_counter(name, help, &label_refs)
            .map_err(PyErr::new::<pyo3::exceptions::PyValueError, _>)?;

        Ok(PyCounter {
            custom: Arc::clone(&self.custom),
            name: name.to_owned(),
            label_names,
        })
    }

    /// Create a new gauge metric.
    ///
    /// Args:
    ///     name: Metric name (e.g. "bgcf_calls_active").
    ///     help: Description string.
    ///     labels: Optional list of label names.
    ///
    /// Returns:
    ///     A Gauge handle.
    #[pyo3(signature = (name, help, labels=None))]
    fn gauge(
        &self,
        name: &str,
        help: &str,
        labels: Option<Vec<String>>,
    ) -> PyResult<PyGauge> {
        let label_names = labels.unwrap_or_default();
        let label_refs: Vec<&str> = label_names.iter().map(|s| s.as_str()).collect();
        self.custom
            .register_gauge(name, help, &label_refs)
            .map_err(PyErr::new::<pyo3::exceptions::PyValueError, _>)?;

        Ok(PyGauge {
            custom: Arc::clone(&self.custom),
            name: name.to_owned(),
            label_names,
        })
    }

    /// Create a new histogram metric.
    ///
    /// Args:
    ///     name: Metric name (e.g. "bgcf_call_setup_seconds").
    ///     help: Description string.
    ///     labels: Optional list of label names.
    ///     buckets: Optional list of bucket boundaries.
    ///
    /// Returns:
    ///     A Histogram handle.
    #[pyo3(signature = (name, help, labels=None, buckets=None))]
    fn histogram(
        &self,
        name: &str,
        help: &str,
        labels: Option<Vec<String>>,
        buckets: Option<Vec<f64>>,
    ) -> PyResult<PyHistogram> {
        let label_names = labels.unwrap_or_default();
        let label_refs: Vec<&str> = label_names.iter().map(|s| s.as_str()).collect();
        let bucket_values = buckets.unwrap_or_default();
        self.custom
            .register_histogram(name, help, &label_refs, bucket_values)
            .map_err(PyErr::new::<pyo3::exceptions::PyValueError, _>)?;

        Ok(PyHistogram {
            custom: Arc::clone(&self.custom),
            name: name.to_owned(),
            label_names,
        })
    }
}

// ---------------------------------------------------------------------------
// Counter
// ---------------------------------------------------------------------------

/// A Prometheus counter handle.
#[pyclass(name = "Counter")]
pub struct PyCounter {
    custom: Arc<CustomMetrics>,
    name: String,
    label_names: Vec<String>,
}

#[pymethods]
impl PyCounter {
    /// Increment the counter (no-label metrics only).
    #[pyo3(signature = (n=1.0))]
    fn inc(&self, n: f64) -> PyResult<()> {
        if !self.label_names.is_empty() {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "counter has labels — use .labels(...).inc() instead",
            ));
        }
        self.custom
            .counter_inc(&self.name, &[], n)
            .map_err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>)
    }

    /// Return a labeled child counter.
    #[pyo3(signature = (**kwargs))]
    fn labels(&self, kwargs: Option<HashMap<String, String>>) -> PyResult<PyCounterChild> {
        let label_values = resolve_kwargs(&self.label_names, kwargs.as_ref())?;
        Ok(PyCounterChild {
            custom: Arc::clone(&self.custom),
            name: self.name.clone(),
            label_values,
        })
    }
}

/// A labeled counter child.
#[pyclass(name = "CounterChild")]
pub struct PyCounterChild {
    custom: Arc<CustomMetrics>,
    name: String,
    label_values: Vec<(String, String)>,
}

#[pymethods]
impl PyCounterChild {
    /// Increment this labeled counter.
    #[pyo3(signature = (n=1.0))]
    fn inc(&self, n: f64) -> PyResult<()> {
        let pairs: Vec<(&str, &str)> = self
            .label_values
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        self.custom
            .counter_inc(&self.name, &pairs, n)
            .map_err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>)
    }
}

// ---------------------------------------------------------------------------
// Gauge
// ---------------------------------------------------------------------------

/// A Prometheus gauge handle.
#[pyclass(name = "Gauge")]
pub struct PyGauge {
    custom: Arc<CustomMetrics>,
    name: String,
    label_names: Vec<String>,
}

#[pymethods]
impl PyGauge {
    /// Increment the gauge (no-label metrics only).
    #[pyo3(signature = (n=1.0))]
    fn inc(&self, n: f64) -> PyResult<()> {
        if !self.label_names.is_empty() {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "gauge has labels — use .labels(...).inc() instead",
            ));
        }
        self.custom
            .gauge_inc(&self.name, &[], n)
            .map_err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>)
    }

    /// Decrement the gauge (no-label metrics only).
    #[pyo3(signature = (n=1.0))]
    fn dec(&self, n: f64) -> PyResult<()> {
        if !self.label_names.is_empty() {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "gauge has labels — use .labels(...).dec() instead",
            ));
        }
        self.custom
            .gauge_dec(&self.name, &[], n)
            .map_err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>)
    }

    /// Set the gauge value (no-label metrics only).
    fn set(&self, value: f64) -> PyResult<()> {
        if !self.label_names.is_empty() {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "gauge has labels — use .labels(...).set() instead",
            ));
        }
        self.custom
            .gauge_set(&self.name, &[], value)
            .map_err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>)
    }

    /// Return a labeled child gauge.
    #[pyo3(signature = (**kwargs))]
    fn labels(&self, kwargs: Option<HashMap<String, String>>) -> PyResult<PyGaugeChild> {
        let label_values = resolve_kwargs(&self.label_names, kwargs.as_ref())?;
        Ok(PyGaugeChild {
            custom: Arc::clone(&self.custom),
            name: self.name.clone(),
            label_values,
        })
    }
}

/// A labeled gauge child.
#[pyclass(name = "GaugeChild")]
pub struct PyGaugeChild {
    custom: Arc<CustomMetrics>,
    name: String,
    label_values: Vec<(String, String)>,
}

#[pymethods]
impl PyGaugeChild {
    /// Increment this labeled gauge.
    #[pyo3(signature = (n=1.0))]
    fn inc(&self, n: f64) -> PyResult<()> {
        let pairs: Vec<(&str, &str)> = self
            .label_values
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        self.custom
            .gauge_inc(&self.name, &pairs, n)
            .map_err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>)
    }

    /// Decrement this labeled gauge.
    #[pyo3(signature = (n=1.0))]
    fn dec(&self, n: f64) -> PyResult<()> {
        let pairs: Vec<(&str, &str)> = self
            .label_values
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        self.custom
            .gauge_dec(&self.name, &pairs, n)
            .map_err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>)
    }

    /// Set this labeled gauge value.
    fn set(&self, value: f64) -> PyResult<()> {
        let pairs: Vec<(&str, &str)> = self
            .label_values
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        self.custom
            .gauge_set(&self.name, &pairs, value)
            .map_err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>)
    }
}

// ---------------------------------------------------------------------------
// Histogram
// ---------------------------------------------------------------------------

/// A Prometheus histogram handle.
#[pyclass(name = "Histogram")]
pub struct PyHistogram {
    custom: Arc<CustomMetrics>,
    name: String,
    label_names: Vec<String>,
}

#[pymethods]
impl PyHistogram {
    /// Observe a value (no-label metrics only).
    fn observe(&self, value: f64) -> PyResult<()> {
        if !self.label_names.is_empty() {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "histogram has labels — use .labels(...).observe() instead",
            ));
        }
        self.custom
            .histogram_observe(&self.name, &[], value)
            .map_err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>)
    }

    /// Return a labeled child histogram.
    #[pyo3(signature = (**kwargs))]
    fn labels(&self, kwargs: Option<HashMap<String, String>>) -> PyResult<PyHistogramChild> {
        let label_values = resolve_kwargs(&self.label_names, kwargs.as_ref())?;
        Ok(PyHistogramChild {
            custom: Arc::clone(&self.custom),
            name: self.name.clone(),
            label_values,
        })
    }
}

/// A labeled histogram child.
#[pyclass(name = "HistogramChild")]
pub struct PyHistogramChild {
    custom: Arc<CustomMetrics>,
    name: String,
    label_values: Vec<(String, String)>,
}

#[pymethods]
impl PyHistogramChild {
    /// Observe a value on this labeled histogram.
    fn observe(&self, value: f64) -> PyResult<()> {
        let pairs: Vec<(&str, &str)> = self
            .label_values
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        self.custom
            .histogram_observe(&self.name, &pairs, value)
            .map_err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve Python **kwargs into ordered (label_name, label_value) pairs.
fn resolve_kwargs(
    label_names: &[String],
    kwargs: Option<&HashMap<String, String>>,
) -> PyResult<Vec<(String, String)>> {
    let kwargs = kwargs.ok_or_else(|| {
        PyErr::new::<pyo3::exceptions::PyValueError, _>("labels() requires keyword arguments")
    })?;

    let mut pairs = Vec::with_capacity(label_names.len());
    for name in label_names {
        let value = kwargs.get(name).ok_or_else(|| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "missing label '{name}'"
            ))
        })?;
        pairs.push((name.clone(), value.clone()));
    }
    Ok(pairs)
}
