//! Metrics for the per-source request rate limit (`security.rate_limit`).
//!
//! `siphon_rate_limited_total` (in the main registry) counts the requests a ban
//! drops. These say how many sources are banned right now and how many bans
//! were ever raised, so a ban that silences a peer is visible as a step in a
//! gauge, not only as a slope in a counter. Which source it is goes to the log
//! line raised with the ban and to `GET /admin/rate-limit/bans`, never to a
//! label: the sources are whatever addresses a scanner sends from, and a
//! label per address would be a series per scanner.

use std::sync::OnceLock;

use prometheus::{IntCounter, IntGauge, Registry};

static RATE_LIMIT_METRICS: OnceLock<RateLimitMetrics> = OnceLock::new();

struct RateLimitMetrics {
    banned_sources: IntGauge,
    bans_total: IntCounter,
}

/// Create and register the rate-limit metrics. Called once from
/// [`super::init`].
pub(super) fn init(registry: &Registry) -> Result<(), prometheus::Error> {
    let banned_sources = IntGauge::new(
        "siphon_rate_limit_banned_sources",
        "Source addresses currently banned by security.rate_limit; every request from them is dropped unanswered until the ban ends",
    )?;
    let bans_total = IntCounter::new(
        "siphon_rate_limit_bans_total",
        "Bans raised by security.rate_limit, one per source that went over max_requests in window_secs",
    )?;
    registry.register(Box::new(banned_sources.clone()))?;
    registry.register(Box::new(bans_total.clone()))?;
    let _ = RATE_LIMIT_METRICS.set(RateLimitMetrics {
        banned_sources,
        bans_total,
    });
    Ok(())
}

/// Publish how many sources are banned now.
pub fn publish_banned_sources(count: usize) {
    if let Some(metrics) = RATE_LIMIT_METRICS.get() {
        metrics
            .banned_sources
            .set(i64::try_from(count).unwrap_or(i64::MAX));
    }
}

/// Count one ban raised.
pub fn record_ban() {
    if let Some(metrics) = RATE_LIMIT_METRICS.get() {
        metrics.bans_total.inc();
    }
}
