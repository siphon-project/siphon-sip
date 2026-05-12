//! SIP transaction timers per RFC 3261 §17.1.1.2, §17.1.2.2, §17.2.1, §17.2.2.
//!
//! All timer values are configurable but have RFC-defined defaults.

use std::time::Duration;

/// Default T1 value: RTT estimate (500ms per RFC 3261).
pub const DEFAULT_T1: Duration = Duration::from_millis(500);

/// Default T2 value: maximum retransmit interval for non-INVITE (4s per RFC 3261).
pub const DEFAULT_T2: Duration = Duration::from_secs(4);

/// Default T4 value: maximum duration a message will remain in the network (5s).
pub const DEFAULT_T4: Duration = Duration::from_secs(5);

/// Default delay before a non-INVITE server transaction auto-emits 100 Trying.
/// Mirrors RFC 3261 §17.2.1's 200 ms timer for the INVITE server transaction.
pub const DEFAULT_AUTO_100_TRYING_DELAY: Duration = Duration::from_millis(200);

/// Timer configuration — all derived from T1, T2, T4.
#[derive(Debug, Clone, Copy)]
pub struct TimerConfig {
    pub t1: Duration,
    pub t2: Duration,
    pub t4: Duration,
    /// Whether the non-INVITE server transaction (NIST) auto-emits 100 Trying
    /// after `auto_100_delay` if the TU has not produced a response yet.
    /// Mirror of RFC 3261 §17.2.1 for INVITE applied to non-INVITE methods
    /// (MESSAGE, SUBSCRIBE, OPTIONS, etc.) so cross-hop relays do not trigger
    /// UAC retransmits (§17.1.2).
    pub auto_100_trying: bool,
    /// Delay before the NIST auto-100 timer fires.
    pub auto_100_delay: Duration,
}

impl TimerConfig {
    pub fn new(t1: Duration, t2: Duration, t4: Duration) -> Self {
        Self {
            t1,
            t2,
            t4,
            auto_100_trying: true,
            auto_100_delay: DEFAULT_AUTO_100_TRYING_DELAY,
        }
    }

    // -----------------------------------------------------------------------
    // INVITE Client Transaction (ICT) timers — RFC 3261 §17.1.1.2
    // -----------------------------------------------------------------------

    /// Timer A: INVITE retransmit interval (UDP only). Starts at T1, doubles each fire.
    pub fn timer_a_initial(&self) -> Duration {
        self.t1
    }

    /// Timer B: INVITE transaction timeout. 64 * T1 = 32s default.
    pub fn timer_b(&self) -> Duration {
        self.t1 * 64
    }

    /// Timer D: Wait time in Completed state for retransmits. > 32s for UDP, 0 for TCP.
    /// We use 32s for UDP (safe default).
    pub fn timer_d_udp(&self) -> Duration {
        Duration::from_secs(32)
    }

    pub fn timer_d_tcp(&self) -> Duration {
        Duration::ZERO
    }

    // -----------------------------------------------------------------------
    // Non-INVITE Client Transaction (NICT) timers — RFC 3261 §17.1.2.2
    // -----------------------------------------------------------------------

    /// Timer E: non-INVITE retransmit interval (UDP only). Starts at T1, doubles up to T2.
    pub fn timer_e_initial(&self) -> Duration {
        self.t1
    }

    /// Timer F: non-INVITE transaction timeout. 64 * T1.
    pub fn timer_f(&self) -> Duration {
        self.t1 * 64
    }

    /// Timer K: Wait time in Completed state for response retransmits. T4 for UDP, 0 for TCP.
    pub fn timer_k_udp(&self) -> Duration {
        self.t4
    }

    pub fn timer_k_tcp(&self) -> Duration {
        Duration::ZERO
    }

    // -----------------------------------------------------------------------
    // INVITE Server Transaction (IST) timers — RFC 3261 §17.2.1
    // -----------------------------------------------------------------------

    /// Timer G: INVITE response retransmit interval (UDP only). Starts at T1, doubles up to T2.
    pub fn timer_g_initial(&self) -> Duration {
        self.t1
    }

    /// Timer H: Wait time for ACK receipt. 64 * T1.
    pub fn timer_h(&self) -> Duration {
        self.t1 * 64
    }

    /// Timer I: Wait time in Confirmed state for retransmits. T4 for UDP, 0 for TCP.
    pub fn timer_i_udp(&self) -> Duration {
        self.t4
    }

    pub fn timer_i_tcp(&self) -> Duration {
        Duration::ZERO
    }

    // -----------------------------------------------------------------------
    // Non-INVITE Server Transaction (NIST) timers — RFC 3261 §17.2.2
    // -----------------------------------------------------------------------

    /// Timer J: Wait time in Completed state. 64 * T1 for UDP, 0 for TCP.
    pub fn timer_j_udp(&self) -> Duration {
        self.t1 * 64
    }

    pub fn timer_j_tcp(&self) -> Duration {
        Duration::ZERO
    }

    /// Compute the next retransmit interval given the current one, capped at T2.
    pub fn next_retransmit(&self, current: Duration) -> Duration {
        std::cmp::min(current * 2, self.t2)
    }
}

impl Default for TimerConfig {
    fn default() -> Self {
        Self {
            t1: DEFAULT_T1,
            t2: DEFAULT_T2,
            t4: DEFAULT_T4,
            auto_100_trying: true,
            auto_100_delay: DEFAULT_AUTO_100_TRYING_DELAY,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_t1() {
        let config = TimerConfig::default();
        assert_eq!(config.t1, Duration::from_millis(500));
    }

    #[test]
    fn default_t2() {
        let config = TimerConfig::default();
        assert_eq!(config.t2, Duration::from_secs(4));
    }

    #[test]
    fn timer_b_is_64_times_t1() {
        let config = TimerConfig::default();
        assert_eq!(config.timer_b(), Duration::from_secs(32));
    }

    #[test]
    fn timer_f_is_64_times_t1() {
        let config = TimerConfig::default();
        assert_eq!(config.timer_f(), Duration::from_secs(32));
    }

    #[test]
    fn timer_h_is_64_times_t1() {
        let config = TimerConfig::default();
        assert_eq!(config.timer_h(), Duration::from_secs(32));
    }

    #[test]
    fn timer_j_udp_is_64_times_t1() {
        let config = TimerConfig::default();
        assert_eq!(config.timer_j_udp(), Duration::from_secs(32));
    }

    #[test]
    fn timer_a_starts_at_t1() {
        let config = TimerConfig::default();
        assert_eq!(config.timer_a_initial(), Duration::from_millis(500));
    }

    #[test]
    fn next_retransmit_doubles() {
        let config = TimerConfig::default();
        let first = config.timer_a_initial();
        assert_eq!(first, Duration::from_millis(500));
        let second = config.next_retransmit(first);
        assert_eq!(second, Duration::from_millis(1000));
        let third = config.next_retransmit(second);
        assert_eq!(third, Duration::from_millis(2000));
        let fourth = config.next_retransmit(third);
        // Capped at T2 = 4000ms
        assert_eq!(fourth, Duration::from_millis(4000));
        let fifth = config.next_retransmit(fourth);
        assert_eq!(fifth, Duration::from_millis(4000)); // stays at T2
    }

    #[test]
    fn custom_t1() {
        let config = TimerConfig::new(
            Duration::from_millis(100),
            Duration::from_secs(2),
            Duration::from_secs(3),
        );
        assert_eq!(config.timer_b(), Duration::from_millis(6400));
        assert_eq!(config.timer_a_initial(), Duration::from_millis(100));
    }

    #[test]
    fn timer_d_udp_at_least_32s() {
        let config = TimerConfig::default();
        assert!(config.timer_d_udp() >= Duration::from_secs(32));
    }

    #[test]
    fn timer_k_udp_is_t4() {
        let config = TimerConfig::default();
        assert_eq!(config.timer_k_udp(), Duration::from_secs(5));
    }

    #[test]
    fn timer_i_udp_is_t4() {
        let config = TimerConfig::default();
        assert_eq!(config.timer_i_udp(), Duration::from_secs(5));
    }

    #[test]
    fn tcp_timers_are_zero() {
        let config = TimerConfig::default();
        assert_eq!(config.timer_d_tcp(), Duration::ZERO);
        assert_eq!(config.timer_k_tcp(), Duration::ZERO);
        assert_eq!(config.timer_i_tcp(), Duration::ZERO);
        assert_eq!(config.timer_j_tcp(), Duration::ZERO);
    }
}
