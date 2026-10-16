//! Metrics for ENUM queries (`proxy.enum_query`, [`crate::dns::enum_query`]).
//!
//! `siphon_enum_queries_total{outcome}` counts every query by what it came to,
//! so "the number has no entry" (`no_such_name`, `no_records`) is told apart
//! from "the ENUM service did not answer" (`server_failure`, `timeout`), which
//! is the one to alarm on. `siphon_enum_server_up{server}` is 1 while a server
//! named in a query's `servers=` list is in use and 0 while it is held down
//! after a timeout or an error response.

use std::net::SocketAddr;
use std::sync::OnceLock;

use prometheus::{IntCounterVec, IntGaugeVec, Opts, Registry};

use crate::dns::enum_query::EnumOutcome;

static ENUM_METRICS: OnceLock<EnumMetrics> = OnceLock::new();

struct EnumMetrics {
    queries_total: IntCounterVec,
    server_up: IntGaugeVec,
}

/// Create and register the ENUM metrics. Called once from [`super::init`].
pub(super) fn init(registry: &Registry) -> Result<(), prometheus::Error> {
    let queries_total = IntCounterVec::new(
        Opts::new(
            "siphon_enum_queries_total",
            "ENUM queries (proxy.enum_query) by outcome: ok, no_such_name, no_records, no_usable_record, server_failure, timeout",
        ),
        &["outcome"],
    )?;
    // Labelled by server address. The addresses come from the script's
    // `servers=` list, never from a peer, so the series are bounded by what the
    // operator wrote.
    let server_up = IntGaugeVec::new(
        Opts::new(
            "siphon_enum_server_up",
            "1 while an ENUM server named in servers= is in use, 0 while it is held down after a timeout or an error response",
        ),
        &["server"],
    )?;
    registry.register(Box::new(queries_total.clone()))?;
    registry.register(Box::new(server_up.clone()))?;
    // Every outcome from the start, so a rate() over one reads zero rather
    // than "no data" on an instance that has not seen it.
    for outcome in EnumOutcome::ALL {
        queries_total.with_label_values(&[outcome.as_str()]);
    }
    let _ = ENUM_METRICS.set(EnumMetrics {
        queries_total,
        server_up,
    });
    Ok(())
}

/// Count one finished ENUM query.
pub fn record_query(outcome: EnumOutcome) {
    if let Some(metrics) = ENUM_METRICS.get() {
        metrics
            .queries_total
            .with_label_values(&[outcome.as_str()])
            .inc();
    }
}

/// Publish whether `server` is in use.
pub fn record_server(server: SocketAddr, up: bool) {
    if let Some(metrics) = ENUM_METRICS.get() {
        metrics
            .server_up
            .with_label_values(&[&server.to_string()])
            .set(i64::from(up));
    }
}

/// Queries counted so far with `outcome`. `None` before [`super::init`].
pub fn queries(outcome: EnumOutcome) -> Option<u64> {
    ENUM_METRICS.get().map(|metrics| {
        metrics
            .queries_total
            .with_label_values(&[outcome.as_str()])
            .get()
    })
}

/// What `siphon_enum_server_up` says for `server`. `None` before
/// [`super::init`].
pub fn server_up(server: SocketAddr) -> Option<i64> {
    ENUM_METRICS.get().map(|metrics| {
        metrics
            .server_up
            .with_label_values(&[&server.to_string()])
            .get()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queries_and_servers_are_recorded() {
        crate::metrics::init().expect("the metrics registry builds");
        let before = queries(EnumOutcome::Timeout).expect("initialised");
        record_query(EnumOutcome::Timeout);
        assert!(queries(EnumOutcome::Timeout).expect("initialised") > before);

        let server: SocketAddr = "192.0.2.53:53".parse().expect("a literal address");
        record_server(server, false);
        assert_eq!(server_up(server), Some(0));
        record_server(server, true);
        assert_eq!(server_up(server), Some(1));
    }
}
