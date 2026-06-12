//! Prometheus metrics for SIPhon.
//!
//! Exposes counters, histograms, and gauges for SIP traffic, transactions,
//! registrations, dialogs, and transport connections. Metrics are collected
//! inline (at the call site) and scraped via the HTTP admin API `/metrics`.

pub mod custom;

use std::sync::{Arc, OnceLock};

use prometheus::{
    Encoder, Gauge, GaugeVec, HistogramOpts, HistogramVec, IntCounter, IntCounterVec,
    IntGauge, IntGaugeVec, Opts, Registry, TextEncoder,
};
use tracing::error;

use self::custom::CustomMetrics;

/// Global metrics registry — initialized once at startup.
static METRICS: OnceLock<SiphonMetrics> = OnceLock::new();

/// Custom metrics registered by Python scripts.
static CUSTOM_METRICS: OnceLock<Arc<CustomMetrics>> = OnceLock::new();

/// Access the global metrics instance. Returns `None` if not initialized.
pub fn metrics() -> Option<&'static SiphonMetrics> {
    METRICS.get()
}

/// Try to access the global metrics (returns None before init).
/// Alias for `metrics()`.
pub fn try_metrics() -> Option<&'static SiphonMetrics> {
    METRICS.get()
}

/// Initialize the global metrics. Call once at startup.
/// Returns an error if metric creation fails (should never happen with
/// valid hardcoded metric names — indicates a bug if it does).
pub fn init() -> Result<(), prometheus::Error> {
    if METRICS.get().is_some() {
        return Ok(());
    }
    let metrics = SiphonMetrics::new()?;
    let custom = Arc::new(CustomMetrics::new(&metrics.registry));
    let _ = CUSTOM_METRICS.set(custom);
    let _ = METRICS.set(metrics);
    Ok(())
}

/// Access the custom metrics store (for script-defined metrics).
/// Returns `None` before `init()` is called.
pub fn custom_metrics() -> Option<&'static Arc<CustomMetrics>> {
    CUSTOM_METRICS.get()
}

/// All SIPhon metrics in one struct for easy access.
pub struct SiphonMetrics {
    pub registry: Registry,

    // --- Request counters ---
    pub requests_total: IntCounterVec,
    pub responses_total: IntCounterVec,

    // --- Transaction gauges ---
    pub transactions_active: IntGauge,

    /// In-flight UAC requests (NAT keepalive / health probe) awaiting a
    /// response.  Climbs without bound if pending entries are not swept —
    /// watch this to confirm the sweep is keeping the `UacSender` map drained.
    pub uac_pending_requests: IntGauge,

    /// Live proxy dialog-key entries (one per INVITE awaiting/within its 2xx
    /// ACK window).  Returns to ~0 when call setup is idle; a monotonic climb
    /// means completed-call dialog keys are leaking (`by_dialog_key`).
    pub proxy_dialog_sessions: IntGauge,

    /// Live SUBSCRIBE dialogs in the L1 `subscribe_state` store.  A monotonic
    /// climb under a steady subscribe/expire workload means expired dialogs
    /// are leaking (L1 has no TTL; the sweep reaps them).
    pub subscribe_dialogs: IntGauge,

    // --- Registration gauges ---
    pub registrations_active: IntGauge,

    // --- Dialog gauges ---
    pub dialogs_active: IntGauge,

    // --- Connection gauges ---
    pub connections_active: GaugeVec,

    // --- Duration histograms ---
    pub request_duration_seconds: HistogramVec,
    pub transaction_duration_seconds: HistogramVec,

    // --- Uptime ---
    pub uptime_seconds: Gauge,

    // --- Memory (jemalloc stats — the precise leak signal) ---
    /// Live bytes allocated by the application (`jemalloc stats.allocated`).
    /// Steady growth under constant load is a real leak — unlike RSS, this
    /// excludes allocator retention/fragmentation.  Alert on this.
    pub memory_allocated_bytes: IntGauge,
    /// Physical pages backing the allocator (`stats.resident`) — RSS-like.
    pub memory_resident_bytes: IntGauge,
    /// Bytes in active pages (`stats.active`).
    pub memory_active_bytes: IntGauge,
    /// Virtual memory retained by the allocator, not returned to the OS
    /// (`stats.retained`).  Explains RSS sitting above `allocated`.
    pub memory_retained_bytes: IntGauge,
    /// Total mapped bytes (`stats.mapped`).
    pub memory_mapped_bytes: IntGauge,
    /// Currently-allocated CPython memory blocks (`sys.getallocatedblocks()`).
    /// Python objects use CPython's own allocator (mimalloc on free-threaded
    /// builds), NOT jemalloc — so this is the leak signal for the *Python* side
    /// (script globals, leaked `Py<>` references) that `memory_allocated_bytes`
    /// cannot see. Steady growth at a flat, completed-call workload is a leak.
    pub python_allocated_blocks: IntGauge,

    // --- Script execution ---
    pub script_executions_total: IntCounterVec,
    pub script_errors_total: IntCounter,

    // --- Diameter ---
    pub diameter_peers_connected: IntGauge,
    pub diameter_requests_total: IntCounterVec,
    pub diameter_request_errors_total: IntCounterVec,
    pub diameter_request_duration_seconds: HistogramVec,
    pub diameter_watchdog_failures_total: IntCounter,

    // --- RTPEngine health ---
    pub rtpengine_instances_up: IntGauge,
    pub rtpengine_instances_total: IntGauge,
    pub rtpengine_instance_up: IntGaugeVec,
}

impl SiphonMetrics {
    fn new() -> Result<Self, prometheus::Error> {
        let registry = Registry::new();

        let requests_total = IntCounterVec::new(
            Opts::new("siphon_requests_total", "Total SIP requests received"),
            &["method"],
        )?;

        let responses_total = IntCounterVec::new(
            Opts::new("siphon_responses_total", "Total SIP responses sent"),
            &["code"],
        )?;

        let transactions_active = IntGauge::new(
            "siphon_transactions_active",
            "Number of active SIP transactions",
        )?;

        let uac_pending_requests = IntGauge::new(
            "siphon_uac_pending_requests",
            "In-flight UAC requests (NAT keepalive / health probe) awaiting a response",
        )?;

        let proxy_dialog_sessions = IntGauge::new(
            "siphon_proxy_dialog_sessions",
            "Live proxy dialog-key entries (INVITEs within their 2xx ACK window)",
        )?;

        let subscribe_dialogs = IntGauge::new(
            "siphon_subscribe_dialogs",
            "Live SUBSCRIBE dialogs in the L1 subscribe_state store",
        )?;

        let registrations_active = IntGauge::new(
            "siphon_registrations_active",
            "Number of active registrations (AoR bindings)",
        )?;

        let dialogs_active = IntGauge::new(
            "siphon_dialogs_active",
            "Number of active SIP dialogs",
        )?;

        let connections_active = GaugeVec::new(
            Opts::new("siphon_connections_active", "Active transport connections"),
            &["transport"],
        )?;

        let request_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "siphon_request_duration_seconds",
                "Request processing duration in seconds",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5]),
            &["method"],
        )?;

        let transaction_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "siphon_transaction_duration_seconds",
                "SIP transaction duration from creation to completion",
            )
            .buckets(vec![0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 16.0, 32.0]),
            &["method", "type"],
        )?;

        let uptime_seconds = Gauge::new(
            "siphon_uptime_seconds",
            "Time since SIPhon process started",
        )?;

        let memory_allocated_bytes = IntGauge::new(
            "siphon_memory_allocated_bytes",
            "Live bytes allocated by the application (jemalloc stats.allocated) — the leak signal",
        )?;
        let memory_resident_bytes = IntGauge::new(
            "siphon_memory_resident_bytes",
            "Physical pages backing the allocator (jemalloc stats.resident)",
        )?;
        let memory_active_bytes = IntGauge::new(
            "siphon_memory_active_bytes",
            "Bytes in active pages (jemalloc stats.active)",
        )?;
        let memory_retained_bytes = IntGauge::new(
            "siphon_memory_retained_bytes",
            "Virtual memory retained by the allocator, not returned to the OS (jemalloc stats.retained)",
        )?;
        let memory_mapped_bytes = IntGauge::new(
            "siphon_memory_mapped_bytes",
            "Total mapped bytes (jemalloc stats.mapped)",
        )?;
        let python_allocated_blocks = IntGauge::new(
            "siphon_python_allocated_blocks",
            "Currently-allocated CPython memory blocks (sys.getallocatedblocks) — the Python-side leak signal",
        )?;

        let script_executions_total = IntCounterVec::new(
            Opts::new("siphon_script_executions_total", "Total Python script handler executions"),
            &["handler"],
        )?;

        let script_errors_total = IntCounter::new(
            "siphon_script_errors_total",
            "Total Python script execution errors",
        )?;

        let diameter_peers_connected = IntGauge::new(
            "siphon_diameter_peers_connected",
            "Number of currently connected Diameter peers",
        )?;

        let diameter_requests_total = IntCounterVec::new(
            Opts::new("siphon_diameter_requests_total", "Total Diameter requests sent"),
            &["command"],
        )?;

        let diameter_request_errors_total = IntCounterVec::new(
            Opts::new(
                "siphon_diameter_request_errors_total",
                "Total Diameter request errors",
            ),
            &["error"],
        )?;

        let diameter_request_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "siphon_diameter_request_duration_seconds",
                "Diameter request round-trip duration in seconds",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0, 10.0]),
            &["command"],
        )?;

        let diameter_watchdog_failures_total = IntCounter::new(
            "siphon_diameter_watchdog_failures_total",
            "Total Diameter watchdog (DWR/DWA) failures indicating dead peers",
        )?;

        let rtpengine_instances_up = IntGauge::new(
            "siphon_rtpengine_instances_up",
            "Number of RTPEngine instances responding to ping",
        )?;

        let rtpengine_instances_total = IntGauge::new(
            "siphon_rtpengine_instances_total",
            "Total number of configured RTPEngine instances",
        )?;

        let rtpengine_instance_up = IntGaugeVec::new(
            Opts::new(
                "siphon_rtpengine_instance_up",
                "Per-instance RTPEngine health (1=responding to ping, 0=not responding)",
            ),
            &["address"],
        )?;

        // Register all metrics
        registry.register(Box::new(requests_total.clone()))?;
        registry.register(Box::new(responses_total.clone()))?;
        registry.register(Box::new(transactions_active.clone()))?;
        registry.register(Box::new(uac_pending_requests.clone()))?;
        registry.register(Box::new(proxy_dialog_sessions.clone()))?;
        registry.register(Box::new(subscribe_dialogs.clone()))?;
        registry.register(Box::new(registrations_active.clone()))?;
        registry.register(Box::new(dialogs_active.clone()))?;
        registry.register(Box::new(connections_active.clone()))?;
        registry.register(Box::new(request_duration_seconds.clone()))?;
        registry.register(Box::new(transaction_duration_seconds.clone()))?;
        registry.register(Box::new(uptime_seconds.clone()))?;
        registry.register(Box::new(memory_allocated_bytes.clone()))?;
        registry.register(Box::new(memory_resident_bytes.clone()))?;
        registry.register(Box::new(memory_active_bytes.clone()))?;
        registry.register(Box::new(memory_retained_bytes.clone()))?;
        registry.register(Box::new(memory_mapped_bytes.clone()))?;
        registry.register(Box::new(python_allocated_blocks.clone()))?;
        registry.register(Box::new(script_executions_total.clone()))?;
        registry.register(Box::new(script_errors_total.clone()))?;
        registry.register(Box::new(diameter_peers_connected.clone()))?;
        registry.register(Box::new(diameter_requests_total.clone()))?;
        registry.register(Box::new(diameter_request_errors_total.clone()))?;
        registry.register(Box::new(diameter_request_duration_seconds.clone()))?;
        registry.register(Box::new(diameter_watchdog_failures_total.clone()))?;
        registry.register(Box::new(rtpengine_instances_up.clone()))?;
        registry.register(Box::new(rtpengine_instances_total.clone()))?;
        registry.register(Box::new(rtpengine_instance_up.clone()))?;

        Ok(Self {
            registry,
            requests_total,
            responses_total,
            transactions_active,
            uac_pending_requests,
            proxy_dialog_sessions,
            subscribe_dialogs,
            registrations_active,
            dialogs_active,
            connections_active,
            request_duration_seconds,
            transaction_duration_seconds,
            uptime_seconds,
            memory_allocated_bytes,
            memory_resident_bytes,
            memory_active_bytes,
            memory_retained_bytes,
            memory_mapped_bytes,
            python_allocated_blocks,
            script_executions_total,
            script_errors_total,
            diameter_peers_connected,
            diameter_requests_total,
            diameter_request_errors_total,
            diameter_request_duration_seconds,
            diameter_watchdog_failures_total,
            rtpengine_instances_up,
            rtpengine_instances_total,
            rtpengine_instance_up,
        })
    }
}

/// Encode all metrics as Prometheus text format.
/// Returns an empty string if metrics are not initialized or encoding fails.
pub fn encode_metrics() -> String {
    let Some(metrics) = metrics() else {
        return String::new();
    };
    let encoder = TextEncoder::new();
    let metric_families = metrics.registry.gather();
    let mut buffer = Vec::new();
    if let Err(error) = encoder.encode(&metric_families, &mut buffer) {
        error!("Failed to encode metrics: {error}");
        return String::new();
    }
    String::from_utf8(buffer).unwrap_or_default()
}

/// Refresh the jemalloc memory-stat gauges from the allocator's internal
/// counters.  Call periodically (the dispatcher does so on its cleanup tick).
/// No-op when metrics aren't initialised or jemalloc isn't the allocator.
///
/// `memory_allocated_bytes` is the one to alert on: it is actual live bytes,
/// so steady growth under constant load is a real leak — independent of RSS,
/// which also moves with allocator retention and fragmentation.
#[cfg(not(target_env = "msvc"))]
pub fn update_memory_stats() {
    let Some(metrics) = metrics() else {
        return;
    };
    // jemalloc snapshots stats at epoch advance; without this the reads are
    // stale (often zero) on the first call.
    if tikv_jemalloc_ctl::epoch::advance().is_err() {
        return;
    }
    if let Ok(value) = tikv_jemalloc_ctl::stats::allocated::read() {
        metrics.memory_allocated_bytes.set(value as i64);
    }
    if let Ok(value) = tikv_jemalloc_ctl::stats::resident::read() {
        metrics.memory_resident_bytes.set(value as i64);
    }
    if let Ok(value) = tikv_jemalloc_ctl::stats::active::read() {
        metrics.memory_active_bytes.set(value as i64);
    }
    if let Ok(value) = tikv_jemalloc_ctl::stats::retained::read() {
        metrics.memory_retained_bytes.set(value as i64);
    }
    if let Ok(value) = tikv_jemalloc_ctl::stats::mapped::read() {
        metrics.memory_mapped_bytes.set(value as i64);
    }
}

/// No-op on MSVC, where jemalloc (and thus its stats) is not the allocator.
#[cfg(target_env = "msvc")]
pub fn update_memory_stats() {}

/// Refresh the Python-side allocation gauge from `sys.getallocatedblocks()`.
///
/// Python objects live in CPython's own allocator (mimalloc on free-threaded
/// builds), which jemalloc — and therefore [`update_memory_stats`] — cannot
/// see. This is the leak signal for the Python side: a script accumulating
/// objects, or a leaked `Py<>` reference. Cheap; called on the cleanup tick.
pub fn update_python_stats() {
    let Some(metrics) = metrics() else {
        return;
    };
    use pyo3::prelude::*;
    let result = pyo3::Python::attach(|python| -> PyResult<i64> {
        python.import("sys")?.call_method0("getallocatedblocks")?.extract()
    });
    if let Ok(blocks) = result {
        metrics.python_allocated_blocks.set(blocks);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_init_and_access() {
        init().unwrap();
        let metrics = metrics().unwrap();

        // Increment a counter
        metrics.requests_total.with_label_values(&["INVITE"]).inc();
        metrics.requests_total.with_label_values(&["REGISTER"]).inc();
        metrics.requests_total.with_label_values(&["INVITE"]).inc();

        assert_eq!(
            metrics.requests_total.with_label_values(&["INVITE"]).get(),
            2
        );
        assert_eq!(
            metrics.requests_total.with_label_values(&["REGISTER"]).get(),
            1
        );
    }

    #[test]
    fn metrics_encode_produces_text() {
        init().unwrap();
        // Ensure at least one label is observed so the counter appears in output
        metrics().unwrap().requests_total.with_label_values(&["OPTIONS"]).inc();
        let output = encode_metrics();
        // Gauges always appear (even at zero), counters appear after first observation
        assert!(output.contains("siphon_transactions_active"), "output: {}", &output[..output.len().min(500)]);
        assert!(output.contains("siphon_registrations_active"));
    }

    #[test]
    fn gauge_operations() {
        init().unwrap();
        let metrics = metrics().unwrap();

        metrics.transactions_active.set(5);
        assert_eq!(metrics.transactions_active.get(), 5);

        metrics.transactions_active.inc();
        assert_eq!(metrics.transactions_active.get(), 6);

        metrics.transactions_active.dec();
        assert_eq!(metrics.transactions_active.get(), 5);
    }

    #[test]
    fn connection_gauge_by_transport() {
        init().unwrap();
        let metrics = metrics().unwrap();

        metrics.connections_active.with_label_values(&["TCP"]).set(10.0);
        metrics.connections_active.with_label_values(&["UDP"]).set(0.0);
        metrics.connections_active.with_label_values(&["TLS"]).set(3.0);

        assert_eq!(
            metrics.connections_active.with_label_values(&["TCP"]).get(),
            10.0
        );
    }

    #[test]
    fn histogram_observation() {
        init().unwrap();
        let metrics = metrics().unwrap();

        metrics
            .request_duration_seconds
            .with_label_values(&["INVITE"])
            .observe(0.042);
        metrics
            .request_duration_seconds
            .with_label_values(&["REGISTER"])
            .observe(0.001);

        let output = encode_metrics();
        assert!(output.contains("siphon_request_duration_seconds"));
    }

    #[test]
    fn diameter_peers_connected_gauge() {
        init().unwrap();
        let metrics = metrics().unwrap();

        assert_eq!(metrics.diameter_peers_connected.get(), 0);
        metrics.diameter_peers_connected.inc();
        metrics.diameter_peers_connected.inc();
        assert_eq!(metrics.diameter_peers_connected.get(), 2);
        metrics.diameter_peers_connected.dec();
        assert_eq!(metrics.diameter_peers_connected.get(), 1);

        let output = encode_metrics();
        assert!(output.contains("siphon_diameter_peers_connected"));
    }

    #[test]
    fn diameter_request_counters() {
        init().unwrap();
        let metrics = metrics().unwrap();

        metrics.diameter_requests_total.with_label_values(&["UAR"]).inc();
        metrics.diameter_requests_total.with_label_values(&["UAR"]).inc();
        metrics.diameter_requests_total.with_label_values(&["SAR"]).inc();

        assert_eq!(
            metrics.diameter_requests_total.with_label_values(&["UAR"]).get(),
            2
        );
        assert_eq!(
            metrics.diameter_requests_total.with_label_values(&["SAR"]).get(),
            1
        );
    }

    #[test]
    fn diameter_error_and_watchdog_counters() {
        init().unwrap();
        let metrics = metrics().unwrap();

        metrics.diameter_request_errors_total.with_label_values(&["timeout"]).inc();
        metrics.diameter_request_errors_total.with_label_values(&["channel_dropped"]).inc();
        metrics.diameter_watchdog_failures_total.inc();

        assert_eq!(
            metrics.diameter_request_errors_total.with_label_values(&["timeout"]).get(),
            1
        );
        assert_eq!(metrics.diameter_watchdog_failures_total.get(), 1);

        let output = encode_metrics();
        assert!(output.contains("siphon_diameter_request_errors_total"));
        assert!(output.contains("siphon_diameter_watchdog_failures_total"));
    }

    #[test]
    fn diameter_request_duration_histogram() {
        init().unwrap();
        let metrics = metrics().unwrap();

        metrics.diameter_request_duration_seconds
            .with_label_values(&["MAR"])
            .observe(0.015);

        let output = encode_metrics();
        assert!(output.contains("siphon_diameter_request_duration_seconds"));
    }
}
