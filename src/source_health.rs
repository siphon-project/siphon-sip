//! Whether a provisioning source is being read, and what to do when it is not.
//!
//! The gateway and registrant sources poll a controller the operator owns. Both
//! used to treat a failed poll the same way: one `warn!` and a full
//! `refresh_secs` sleep, forever. That is right for a *running* node — an
//! unreadable source is not evidence that the carriers or trunks went away, and
//! tearing the estate down over it would fail every call — and wrong for
//! everything around it:
//!
//! - **At start-up there is nothing to keep.** A node that reboots while the
//!   controller is down comes up with no carriers, routes nothing, and says so
//!   once at `warn`. [`Backoff`] is what lets the caller retry in seconds
//!   instead of sleeping out an interval, and the boot path awaits a first
//!   attempt before the listeners take traffic.
//! - **A `warn` per poll reads as normal.** At the default 30 s refresh a
//!   six-hour outage is 720 identical lines, none of them an error. A streak
//!   escalates to `error!` from its second failure and is throttled, so the
//!   volume says "still down" rather than drowning the log.
//! - **Nothing was measurable.** There was no metric for either source, so "this
//!   node has been running on a stale carrier set since 03:00" was invisible to
//!   a dashboard. [`SourceHealth`] publishes a last-success timestamp and a
//!   failure counter; an operator alerts on the age of the first and the rate of
//!   the second.

use std::time::Duration;

use tracing::{error, warn};

/// First retry delay after a failed poll.
const FIRST_RETRY: Duration = Duration::from_millis(250);

/// How long a streak of failures may go without a log line. One line a minute
/// says "still down" without hiding a recovery.
const ERROR_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// Exponential backoff between failed polls, capped at the configured refresh
/// interval.
///
/// The cap is the point: a source that stays down must not be polled harder
/// than it would be when healthy, and a source that comes back must be picked
/// up in seconds rather than at the next interval boundary.
#[derive(Debug)]
pub struct Backoff {
    ceiling: Duration,
    next: Duration,
}

impl Backoff {
    /// A backoff that never exceeds `ceiling` (the source's `refresh_secs`).
    pub fn new(ceiling: Duration) -> Self {
        Self {
            ceiling,
            next: FIRST_RETRY.min(ceiling),
        }
    }

    /// The delay before the next attempt, doubling each time it is asked.
    pub fn next_delay(&mut self) -> Duration {
        let delay = self.next.min(self.ceiling);
        self.next = (self.next * 2).min(self.ceiling);
        delay
    }

    /// Back to the first retry delay, after a poll that succeeded.
    pub fn reset(&mut self) {
        self.next = FIRST_RETRY.min(self.ceiling);
    }
}

/// Which source a [`SourceHealth`] reports for. The two are tracked separately
/// because they fail separately: a node can be routing calls over stale
/// carriers while its trunk registrations are current, or the reverse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    Gateway,
    Registrant,
}

impl SourceKind {
    fn label(self) -> &'static str {
        match self {
            SourceKind::Gateway => "gateway",
            SourceKind::Registrant => "registrant",
        }
    }
}

/// The run of failures a source is in, and the metrics that make it visible.
#[derive(Debug)]
pub struct SourceHealth {
    kind: SourceKind,
    /// Consecutive failed polls. Zero after any success.
    consecutive: u64,
    /// Failures since the last line was logged, folded into the next one so a
    /// throttled streak still reports its volume.
    suppressed: u64,
    last_logged: Option<std::time::Instant>,
}

impl SourceHealth {
    pub fn new(kind: SourceKind) -> Self {
        Self {
            kind,
            consecutive: 0,
            suppressed: 0,
            last_logged: None,
        }
    }

    /// How many polls in a row have failed. Zero when the last one succeeded.
    pub fn consecutive_failures(&self) -> u64 {
        self.consecutive
    }

    /// Record a poll that read the source, whatever the reconcile then did with
    /// it: the source is readable, which is what this tracks.
    pub fn record_success(&mut self) {
        self.consecutive = 0;
        self.suppressed = 0;
        self.last_logged = None;
        if let Some(metrics) = crate::metrics::try_metrics() {
            let gauge = match self.kind {
                SourceKind::Gateway => &metrics.gateway_source_last_success_timestamp_seconds,
                SourceKind::Registrant => &metrics.registrant_source_last_success_timestamp_seconds,
            };
            gauge.set(unix_now_secs());
        }
    }

    /// Record a poll that could not read the source, and log it at a level and
    /// a rate that match how long it has been going on.
    ///
    /// The first failure of a streak is a `warn`: a single failed poll is a
    /// blip, and a controller restart should not page anyone. From the second
    /// it is an `error`, throttled, because a source that has now missed twice
    /// is an outage and the node is serving a set nobody is maintaining.
    pub fn record_failure(&mut self, error: &str) {
        self.consecutive = self.consecutive.saturating_add(1);
        if let Some(metrics) = crate::metrics::try_metrics() {
            match self.kind {
                SourceKind::Gateway => metrics.gateway_source_failures_total.inc(),
                SourceKind::Registrant => metrics.registrant_source_failures_total.inc(),
            }
        }

        let source = self.kind.label();
        if self.consecutive == 1 {
            self.last_logged = Some(std::time::Instant::now());
            warn!(%source, %error, "provisioning source unreadable — keeping the current set");
            return;
        }

        // The second failure is the escalation and always logs: it is the line
        // that says a blip became an outage, and throttling it behind the first
        // would hide the transition for a minute — which is most of a default
        // refresh interval. From the third on, the streak is throttled.
        let due = self.consecutive == 2
            || self
                .last_logged
                .map_or(true, |at| at.elapsed() >= ERROR_LOG_INTERVAL);
        if due {
            error!(
                %source,
                %error,
                consecutive = self.consecutive,
                suppressed = self.suppressed,
                "provisioning source still unreadable — the live set is stale and nothing is \
                 maintaining it"
            );
            self.suppressed = 0;
            self.last_logged = Some(std::time::Instant::now());
        } else {
            self.suppressed = self.suppressed.saturating_add(1);
        }
    }
}

/// Seconds since the Unix epoch, for the last-success gauge. A clock before the
/// epoch reads as 0, which ages out immediately — the honest answer for a node
/// whose clock cannot be trusted.
fn unix_now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_and_stops_at_the_refresh_interval() {
        // Capped at the healthy poll interval: a source that stays down must
        // not be polled harder than one that is up.
        let mut backoff = Backoff::new(Duration::from_secs(30));
        assert_eq!(backoff.next_delay(), Duration::from_millis(250));
        assert_eq!(backoff.next_delay(), Duration::from_millis(500));
        assert_eq!(backoff.next_delay(), Duration::from_secs(1));
        for _ in 0..10 {
            backoff.next_delay();
        }
        assert_eq!(
            backoff.next_delay(),
            Duration::from_secs(30),
            "the delay never exceeds refresh_secs"
        );
    }

    #[test]
    fn backoff_starts_over_after_a_success() {
        // A controller that comes back is picked up in a quarter-second, not at
        // the next interval boundary.
        let mut backoff = Backoff::new(Duration::from_secs(30));
        for _ in 0..5 {
            backoff.next_delay();
        }
        backoff.reset();
        assert_eq!(backoff.next_delay(), Duration::from_millis(250));
    }

    #[test]
    fn a_refresh_interval_below_the_first_retry_is_the_floor_and_the_ceiling() {
        // `refresh_secs` is validated >= 1 s, but the backoff must still be
        // coherent if it ever were not: never slower than the poll it replaces.
        let mut backoff = Backoff::new(Duration::from_millis(100));
        assert_eq!(backoff.next_delay(), Duration::from_millis(100));
        assert_eq!(backoff.next_delay(), Duration::from_millis(100));
    }

    #[test]
    fn a_streak_counts_and_a_success_clears_it() {
        let mut health = SourceHealth::new(SourceKind::Gateway);
        assert_eq!(health.consecutive_failures(), 0);

        health.record_failure("connection refused");
        health.record_failure("connection refused");
        assert_eq!(health.consecutive_failures(), 2);

        health.record_success();
        assert_eq!(
            health.consecutive_failures(),
            0,
            "a readable source ends the streak"
        );
    }

    #[test]
    fn the_second_failure_of_a_streak_escalates_and_later_ones_are_throttled() {
        // The level and the rate are the point: a `warn` per poll at the default
        // 30 s refresh makes a six-hour outage 720 lines that read as normal.
        let mut health = SourceHealth::new(SourceKind::Registrant);

        health.record_failure("timeout");
        assert_eq!(health.suppressed, 0, "the first failure logs, nothing held");

        health.record_failure("timeout");
        assert_eq!(
            health.suppressed, 0,
            "the second logs too — it is the escalation"
        );

        // Everything inside the throttle window is counted, not logged.
        for _ in 0..5 {
            health.record_failure("timeout");
        }
        assert_eq!(
            health.suppressed, 5,
            "the volume is carried into the next line rather than lost"
        );
    }
}
