//! How fast outbound registrations go out: when a binding is refreshed, and
//! how many new REGISTERs may leave per second.
//!
//! A handful of trunks never needed either. A process registering hundreds of
//! UEs does: started together they all refresh together at exactly half their
//! grant, for ever, and a restart puts every initial REGISTER (and its 401,
//! and with IMS-AKA a Milenage run and an SA install) into the same second.
//! [`RefreshWindow`] spreads the refreshes, [`RegisterRateLimiter`] caps the
//! starts.

use std::collections::VecDeque;
use std::time::Duration;

/// The fraction of a granted `Expires` after which a binding is refreshed,
/// drawn uniformly from `[low, high]` per refresh.
///
/// The default `[0.5, 0.5]` is the fixed half-interval siphon always used
/// (RFC 3261 §10.2.4 leaves the choice to the UA), to the second, so a config
/// that does not set one refreshes exactly as before.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RefreshWindow {
    low: f64,
    high: f64,
}

impl Default for RefreshWindow {
    fn default() -> Self {
        Self::HALF
    }
}

impl RefreshWindow {
    /// Refresh at exactly half the grant.
    pub const HALF: Self = Self {
        low: 0.5,
        high: 0.5,
    };

    /// A window of `[low, high]`, both fractions of the granted interval.
    ///
    /// Refused unless `0 < low <= high < 1`: a refresh at or past the grant
    /// lets the binding lapse first, and one at zero re-registers in a loop.
    pub fn new(low: f64, high: f64) -> Result<Self, String> {
        if !(low.is_finite() && high.is_finite()) || low <= 0.0 || high >= 1.0 || low > high {
            return Err(format!(
                "refresh_window [{low}, {high}] must satisfy 0 < low <= high < 1 \
                 (fractions of the granted Expires)"
            ));
        }
        Ok(Self { low, high })
    }

    /// From a `[low, high]` pair as YAML and scripts give it.
    pub fn from_pair(pair: [f64; 2]) -> Result<Self, String> {
        Self::new(pair[0], pair[1])
    }

    /// The lower bound.
    pub fn low(&self) -> f64 {
        self.low
    }

    /// The upper bound.
    pub fn high(&self) -> f64 {
        self.high
    }

    /// When to refresh a binding granted for `granted_secs`, with `unit` a
    /// uniform draw from `[0, 1)` choosing the point inside the window.
    ///
    /// Whole seconds, rounded down: for the default window that is
    /// `granted_secs / 2` exactly, the integer half siphon always used.
    pub fn delay(&self, granted_secs: u32, unit: f64) -> Duration {
        let unit = if unit.is_finite() {
            unit.clamp(0.0, 1.0)
        } else {
            0.0
        };
        let fraction = self.low + (self.high - self.low) * unit;
        let seconds = (f64::from(granted_secs) * fraction).floor();
        // Bounded by `granted_secs` (fraction < 1), so the cast cannot wrap.
        Duration::from_secs(seconds as u64)
    }
}

/// A uniform draw from `[0, 1)` for [`RefreshWindow::delay`].
pub(super) fn unit_draw() -> f64 {
    f64::from(super::rand_u32()) / (f64::from(u32::MAX) + 1.0)
}

/// At most `per_second` new REGISTERs in any one-second window.
///
/// A sliding window rather than a token bucket so the cap holds for every
/// second, not on average: a bucket that filled while idle releases its whole
/// burst on top of the steady rate. Only the registration loop's own starts
/// count (initial registrations, refreshes, retries after a failure); the
/// authenticated REGISTER answering a 401 is the second half of an attempt
/// already counted and is never held back.
#[derive(Debug)]
pub struct RegisterRateLimiter {
    per_second: usize,
    sent: VecDeque<tokio::time::Instant>,
}

impl RegisterRateLimiter {
    /// A limiter allowing `per_second` starts per second (at least one).
    pub fn new(per_second: u32) -> Self {
        let per_second = usize::try_from(per_second.max(1)).unwrap_or(usize::MAX);
        Self {
            per_second,
            sent: VecDeque::with_capacity(per_second.min(4096)),
        }
    }

    /// Take one start at `now`, or `false` when the last second already holds
    /// `per_second` of them.
    pub fn try_acquire(&mut self, now: tokio::time::Instant) -> bool {
        while let Some(oldest) = self.sent.front() {
            if now.saturating_duration_since(*oldest) >= Duration::from_secs(1) {
                self.sent.pop_front();
            } else {
                break;
            }
        }
        if self.sent.len() >= self.per_second {
            return false;
        }
        self.sent.push_back(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_window_is_the_integer_half_siphon_always_used() {
        let window = RefreshWindow::default();
        for granted in [0u32, 1, 2, 3, 59, 600, 3599, 3600, 3601, 600_000, u32::MAX] {
            for unit in [0.0, 0.25, 0.999_999] {
                assert_eq!(
                    window.delay(granted, unit),
                    Duration::from_secs(u64::from(granted) / 2),
                    "granted {granted}, draw {unit}"
                );
            }
        }
    }

    #[test]
    fn a_window_spreads_the_refresh_across_its_bounds() {
        let window = RefreshWindow::new(0.4, 0.8).expect("a valid window");
        assert_eq!(window.delay(1000, 0.0), Duration::from_secs(400));
        assert_eq!(window.delay(1000, 0.5), Duration::from_secs(600));
        assert_eq!(window.delay(1000, 0.999_999), Duration::from_secs(799));
        // An out-of-range draw is clamped rather than leaving the window.
        assert_eq!(window.delay(1000, 7.0), Duration::from_secs(800));
        assert_eq!(window.delay(1000, f64::NAN), Duration::from_secs(400));
    }

    #[test]
    fn draws_stay_inside_the_window() {
        let window = RefreshWindow::new(0.3, 0.6).expect("a valid window");
        for _ in 0..1000 {
            let delay = window.delay(3600, unit_draw());
            assert!(
                delay >= Duration::from_secs(1080) && delay <= Duration::from_secs(2160),
                "{delay:?} left the window"
            );
        }
    }

    #[test]
    fn windows_that_would_lapse_or_spin_are_refused() {
        for (low, high) in [
            (0.0, 0.5),
            (0.5, 1.0),
            (0.7, 0.6),
            (-0.1, 0.5),
            (f64::NAN, 0.5),
            (0.5, f64::INFINITY),
        ] {
            assert!(
                RefreshWindow::new(low, high).is_err(),
                "[{low}, {high}] must be refused"
            );
        }
        assert!(RefreshWindow::new(0.5, 0.5).is_ok());
        assert!(RefreshWindow::from_pair([0.1, 0.9]).is_ok());
    }

    #[test]
    fn the_limiter_never_admits_more_than_its_rate_in_any_second() {
        let start = tokio::time::Instant::now();
        let mut limiter = RegisterRateLimiter::new(5);
        let mut admitted = Vec::new();
        // Ask every 50 ms for 4 s, far more often than the rate allows.
        for step in 0..80u64 {
            let now = start + Duration::from_millis(step * 50);
            for _ in 0..3 {
                if limiter.try_acquire(now) {
                    admitted.push(now);
                }
            }
        }
        for (index, at) in admitted.iter().enumerate() {
            let in_window = admitted[index..]
                .iter()
                .take_while(|later| later.saturating_duration_since(*at) < Duration::from_secs(1))
                .count();
            assert!(in_window <= 5, "{in_window} starts inside one second");
        }
        // And it does admit the full rate: about 5 per second over 4 s.
        assert!(admitted.len() >= 19, "only {} admitted", admitted.len());
    }

    #[test]
    fn a_zero_rate_still_admits_one_per_second() {
        let start = tokio::time::Instant::now();
        let mut limiter = RegisterRateLimiter::new(0);
        assert!(limiter.try_acquire(start));
        assert!(!limiter.try_acquire(start + Duration::from_millis(500)));
        assert!(limiter.try_acquire(start + Duration::from_secs(1)));
    }
}
