//! Metrics for the per-connection send queues of the connection-oriented
//! transports ([`crate::transport::send_queue`]).

use std::sync::OnceLock;

use prometheus::{IntCounterVec, IntGaugeVec, Opts, Registry};

use crate::transport::Transport;

static SEND_QUEUE_METRICS: OnceLock<SendQueueMetrics> = OnceLock::new();

struct SendQueueMetrics {
    queued_bytes: IntGaugeVec,
    refused_total: IntCounterVec,
    stalled_closes_total: IntCounterVec,
    discarded_total: IntCounterVec,
}

/// Create and register the send-queue metrics. Called once from
/// [`super::init`].
pub(super) fn init(registry: &Registry) -> Result<(), prometheus::Error> {
    let queued_bytes = IntGaugeVec::new(
        Opts::new(
            "siphon_stream_send_queue_bytes",
            "Bytes queued for connection writers and not yet written, summed over every connection of a transport",
        ),
        &["transport"],
    )?;
    let refused_total = IntCounterVec::new(
        Opts::new(
            "siphon_stream_send_queue_refused_total",
            "Outbound frames refused because their connection's send queue was at listen.stream_send_queue_bytes",
        ),
        &["transport"],
    )?;
    let stalled_closes_total = IntCounterVec::new(
        Opts::new(
            "siphon_stream_stalled_closes_total",
            "Connections closed as stuck: a write made no progress for listen.stream_write_timeout_ms",
        ),
        &["transport"],
    )?;
    let discarded_total = IntCounterVec::new(
        Opts::new(
            "siphon_stream_send_queue_discarded_total",
            "Frames still queued when their connection closed, discarded unwritten",
        ),
        &["transport"],
    )?;
    registry.register(Box::new(queued_bytes.clone()))?;
    registry.register(Box::new(refused_total.clone()))?;
    registry.register(Box::new(stalled_closes_total.clone()))?;
    registry.register(Box::new(discarded_total.clone()))?;
    let _ = SEND_QUEUE_METRICS.set(SendQueueMetrics {
        queued_bytes,
        refused_total,
        stalled_closes_total,
        discarded_total,
    });
    Ok(())
}

/// Move the queued-bytes gauge of `transport` by `delta`.
pub fn add_queued_bytes(transport: Transport, delta: i64) {
    if let Some(metrics) = SEND_QUEUE_METRICS.get() {
        metrics
            .queued_bytes
            .with_label_values(&[transport.as_scheme()])
            .add(delta);
    }
}

/// Count one frame refused at the byte bound.
pub fn record_refused(transport: Transport) {
    if let Some(metrics) = SEND_QUEUE_METRICS.get() {
        metrics
            .refused_total
            .with_label_values(&[transport.as_scheme()])
            .inc();
    }
}

/// Count one connection closed because its writer stalled.
pub fn record_stalled(transport: Transport) {
    if let Some(metrics) = SEND_QUEUE_METRICS.get() {
        metrics
            .stalled_closes_total
            .with_label_values(&[transport.as_scheme()])
            .inc();
    }
}

/// Count `frames` discarded unwritten when their connection closed.
pub fn record_discarded(transport: Transport, frames: u64) {
    if let Some(metrics) = SEND_QUEUE_METRICS.get() {
        metrics
            .discarded_total
            .with_label_values(&[transport.as_scheme()])
            .inc_by(frames);
    }
}
