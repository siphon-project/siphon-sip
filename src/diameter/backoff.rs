//! Reconnect schedule of a dialled peer: exponential backoff with jitter and
//! a ceiling.
//!
//! The first retries come at the configured `reconnect_delay`, then the wait
//! doubles up to `reconnect_delay_max`. Against a peer that stays away for
//! minutes or hours that is a connection attempt a minute, not one every
//! five seconds. Each wait is drawn from the top 30 % below its nominal value,
//! so a set of nodes restarted together does not dial in step. A completed
//! capabilities exchange resets the schedule.

use super::lifecycle::ReconnectAdvice;
use super::peer::DiameterPeer;
use std::time::Duration;

/// How far below the nominal wait a delay may fall, as a fraction of it.
const JITTER: f64 = 0.3;

/// Exponential backoff with a ceiling and jitter.
#[derive(Debug, Clone)]
pub struct Backoff {
    base: Duration,
    max: Duration,
    attempt: u32,
}

impl Backoff {
    /// A schedule from `base` up to `max`. A `max` below `base` is `base`.
    pub fn new(base: Duration, max: Duration) -> Self {
        Self {
            base,
            max: max.max(base),
            attempt: 0,
        }
    }

    /// The nominal wait of the next attempt, before jitter: the base doubled
    /// once per earlier attempt, up to the ceiling.
    pub fn nominal(&self) -> Duration {
        let factor = 1u32.checked_shl(self.attempt.min(30)).unwrap_or(u32::MAX);
        self.base.saturating_mul(factor).min(self.max)
    }

    /// The wait before the next attempt, drawn with `unit` in `[0, 1)`: the
    /// nominal wait less up to 30 % of it. Counts the attempt.
    pub fn next_with(&mut self, unit: f64) -> Duration {
        let nominal = self.nominal();
        self.attempt = self.attempt.saturating_add(1);
        nominal.mul_f64(1.0 - JITTER * unit.clamp(0.0, 1.0))
    }

    /// [`next_with`](Self::next_with) with a random draw.
    pub fn next_delay(&mut self) -> Duration {
        self.next_with(unit_random())
    }

    /// Back to the first wait: the capabilities exchange succeeded.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

/// A uniform draw in `[0, 1)`. Jitter is not a secret, so a failed read of
/// the system source degrades to no jitter rather than failing a reconnect.
fn unit_random() -> f64 {
    let mut bytes = [0u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        return 0.0;
    }
    (u64::from_le_bytes(bytes) >> 11) as f64 / (1u64 << 53) as f64
}

/// What a dialling loop needs between its attempts: the backoff, and whether
/// the next connection is a reconnection after a failure (RFC 3539: it then
/// re-enters the watchdog through REOPEN).
#[derive(Debug, Clone)]
pub struct ReconnectSchedule {
    backoff: Backoff,
    ceiling: Duration,
    connected_before: bool,
    reopen_next: bool,
}

impl ReconnectSchedule {
    /// From a peer's configured `reconnect_delay` and `reconnect_delay_max`
    /// (seconds; a zero delay is one second).
    pub fn new(reconnect_delay: u64, reconnect_delay_max: u64) -> Self {
        let base = Duration::from_secs(reconnect_delay.max(1));
        let ceiling = Duration::from_secs(reconnect_delay_max.max(1)).max(base);
        Self {
            backoff: Backoff::new(base, ceiling),
            ceiling,
            connected_before: false,
            reopen_next: false,
        }
    }

    /// The capabilities exchange succeeded: the next failure starts the
    /// schedule over. Returns whether the connection is a reconnection after
    /// a failure, for which the watchdog starts in REOPEN.
    pub fn connected(&mut self) -> bool {
        self.backoff.reset();
        let reopen = self.reopen_next;
        self.connected_before = true;
        self.reopen_next = false;
        reopen
    }

    /// A connection attempt failed: how long to wait.
    pub fn failed(&mut self) -> Duration {
        if self.connected_before {
            self.reopen_next = true;
        }
        self.backoff.next_delay()
    }

    /// The connection `peer` ended: how long to wait before dialling again,
    /// or None when this node closed it on purpose. A peer that said BUSY or
    /// that it does not want to talk is not dialled before it allows.
    pub fn ended(&mut self, peer: &DiameterPeer) -> Option<Duration> {
        let delay = self.backoff.next_delay();
        match peer.reconnect_advice_with(self.ceiling) {
            ReconnectAdvice::Stop => None,
            ReconnectAdvice::Normal => {
                // A peer that went with a DPR announced it; one that just
                // dropped, or stopped answering the watchdog, failed.
                self.reopen_next = peer.remote_disconnect_cause().is_none();
                Some(delay)
            }
            ReconnectAdvice::Hold(hold) => {
                self.reopen_next = false;
                Some(delay.max(hold))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(value: u64) -> Duration {
        Duration::from_secs(value)
    }

    #[test]
    fn the_nominal_wait_doubles_up_to_the_ceiling() {
        let mut backoff = Backoff::new(secs(5), secs(60));
        let mut nominal = Vec::new();
        for _ in 0..6 {
            nominal.push(backoff.nominal().as_secs());
            backoff.next_with(0.0);
        }
        assert_eq!(nominal, [5, 10, 20, 40, 60, 60]);
    }

    #[test]
    fn a_wait_is_within_thirty_percent_below_its_nominal_value() {
        for unit in [0.0, 0.25, 0.5, 0.999] {
            let mut backoff = Backoff::new(secs(10), secs(60));
            let wait = backoff.next_with(unit);
            assert!(wait <= secs(10), "{wait:?} above nominal");
            assert!(wait >= secs(7), "{wait:?} more than 30 % below nominal");
        }
        let mut backoff = Backoff::new(secs(10), secs(60));
        assert_eq!(backoff.next_with(0.0), secs(10));
    }

    #[test]
    fn a_wait_never_exceeds_the_ceiling() {
        let mut backoff = Backoff::new(secs(5), secs(60));
        for _ in 0..80 {
            assert!(backoff.next_with(0.0) <= secs(60));
        }
    }

    #[test]
    fn random_waits_are_spread_and_stay_in_bounds() {
        let waits: Vec<Duration> = (0..200)
            .map(|_| Backoff::new(secs(5), secs(60)).next_delay())
            .collect();
        assert!(waits
            .iter()
            .all(|wait| *wait <= secs(5) && *wait >= Duration::from_millis(3500)));
        let distinct: std::collections::HashSet<_> = waits.iter().collect();
        assert!(
            distinct.len() > 100,
            "jitter spreads the waits: {}",
            distinct.len()
        );
    }

    #[test]
    fn a_reset_starts_over() {
        let mut backoff = Backoff::new(secs(5), secs(60));
        backoff.next_with(0.0);
        backoff.next_with(0.0);
        backoff.reset();
        assert_eq!(backoff.next_with(0.0), secs(5));
    }

    #[test]
    fn a_ceiling_below_the_base_is_the_base() {
        let mut backoff = Backoff::new(secs(5), secs(1));
        assert_eq!(backoff.next_with(0.0), secs(5));
        assert_eq!(backoff.next_with(0.0), secs(5));
    }

    #[test]
    fn a_long_run_of_attempts_does_not_overflow() {
        let mut backoff = Backoff::new(secs(5), secs(60));
        for _ in 0..200 {
            backoff.next_with(0.5);
        }
        assert_eq!(backoff.nominal(), secs(60));
    }

    #[test]
    fn the_schedule_resets_when_the_capabilities_exchange_succeeds() {
        let mut schedule = ReconnectSchedule::new(5, 60);
        for _ in 0..4 {
            schedule.failed();
        }
        assert!(!schedule.connected(), "a first connection is not a reopen");
        let wait = schedule.failed();
        assert!(
            wait <= secs(5),
            "back to the base after a success: {wait:?}"
        );
    }

    #[test]
    fn a_connection_after_a_failure_reopens_the_watchdog() {
        let mut schedule = ReconnectSchedule::new(5, 60);
        assert!(!schedule.connected());
        schedule.failed();
        assert!(schedule.connected());
        assert!(
            !schedule.connected(),
            "only the connection after the failure"
        );
    }
}
