//! Whether the Redis backend of a named cache is reachable, and what follows
//! from it: the `siphon_cache_backend_up` gauge, the readiness probe, and
//! commands that fail at once instead of each waiting on a server that is
//! known to be gone.
//!
//! The state is fed from two sides. Every command a script issues reports its
//! outcome, and a monitor task per cache sends `PING` once per
//! [`PROBE_INTERVAL`], so that a cache nobody is using still notices its
//! server going away and coming back. While a backend is down, commands are
//! refused without touching the network, except one per interval that is let
//! through as a trial: that keeps a cache without a monitor (a
//! [`CacheManager`](super::CacheManager) built outside the server) recovering
//! too.

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{error, info};

use crate::lifecycle::LifecycleParticipant;

/// How often a backend is probed, and how often a command is let through to a
/// backend that is down.
pub(super) const PROBE_INTERVAL: Duration = Duration::from_secs(1);

const UNKNOWN: u8 = 0;
const UP: u8 = 1;
const DOWN: u8 = 2;

/// The reachability of one cache's Redis backend.
pub(super) struct BackendHealth {
    cache: String,
    required_for_readiness: bool,
    state: AtomicU8,
    /// Milliseconds after `started` before which a down backend takes no
    /// command.
    retry_at_millis: AtomicU64,
    started: Instant,
}

impl BackendHealth {
    pub(super) fn new(cache: &str, required_for_readiness: bool) -> Self {
        Self {
            cache: cache.to_string(),
            required_for_readiness,
            state: AtomicU8::new(UNKNOWN),
            retry_at_millis: AtomicU64::new(0),
            started: Instant::now(),
        }
    }

    pub(super) fn cache(&self) -> &str {
        &self.cache
    }

    fn now_millis(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn interval_millis() -> u64 {
        u64::try_from(PROBE_INTERVAL.as_millis()).unwrap_or(u64::MAX)
    }

    /// Whether a command may go to the backend now. Always while it is up or
    /// not yet known; once per [`PROBE_INTERVAL`] while it is down.
    pub(super) fn admit(&self) -> bool {
        if self.state.load(Ordering::Acquire) != DOWN {
            return true;
        }
        let now = self.now_millis();
        let retry_at = self.retry_at_millis.load(Ordering::Acquire);
        now >= retry_at
            && self
                .retry_at_millis
                .compare_exchange(
                    retry_at,
                    now.saturating_add(Self::interval_millis()),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
    }

    /// The backend answered.
    pub(super) fn mark_up(&self) {
        if self.state.load(Ordering::Acquire) == UP {
            return;
        }
        if self.state.swap(UP, Ordering::AcqRel) == DOWN {
            info!(cache = %self.cache, "cache: Redis backend reachable again");
        }
        self.publish();
    }

    /// Set the gauge from the state. Called on every change, and by the
    /// monitor after every probe: a change and its gauge write are two steps,
    /// so two changes racing can leave the gauge on the older one, and the
    /// next probe puts it right.
    pub(super) fn publish(&self) {
        crate::metrics::cache::set_backend_up(
            &self.cache,
            self.state.load(Ordering::Acquire) == UP,
        );
    }

    /// The link to the backend, or its primary, is gone. Logged once per
    /// outage, not once per command.
    pub(super) fn mark_down(&self, reason: &dyn std::fmt::Display) {
        self.retry_at_millis.store(
            self.now_millis().saturating_add(Self::interval_millis()),
            Ordering::Release,
        );
        if self.state.swap(DOWN, Ordering::AcqRel) != DOWN {
            error!(
                cache = %self.cache,
                "cache: Redis backend unreachable, operations fail until it answers again: {reason}"
            );
            self.publish();
        }
    }

    /// `Err` with the reason while this cache keeps the node out of rotation.
    fn ready(&self) -> Result<(), String> {
        if !self.required_for_readiness {
            return Ok(());
        }
        match self.state.load(Ordering::Acquire) {
            UP => Ok(()),
            DOWN => Err(format!("cache '{}': Redis backend unreachable", self.cache)),
            _ => Err(format!(
                "cache '{}': Redis backend not checked yet",
                self.cache
            )),
        }
    }
}

/// The caches as a readiness participant: not ready while the Redis backend of
/// any cache that counts towards readiness is unreachable or was never
/// reached. A cache holds no sessions, so it takes no part in drain.
pub(super) struct CacheReadiness {
    pub(super) backends: Vec<Arc<BackendHealth>>,
}

impl LifecycleParticipant for CacheReadiness {
    fn ready(&self) -> Result<(), String> {
        self.backends.iter().try_for_each(|backend| backend.ready())
    }
    fn set_draining(&self, _draining: bool) {}
    fn outstanding(&self) -> usize {
        0
    }
    fn force(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_backend_is_not_ready_until_it_answered_and_while_it_is_down() {
        let health = BackendHealth::new("health_flows", true);
        assert_eq!(
            health.ready().unwrap_err(),
            "cache 'health_flows': Redis backend not checked yet"
        );
        health.mark_up();
        assert_eq!(health.ready(), Ok(()));
        assert!(crate::metrics::cache::backend_up("health_flows"));
        health.mark_down(&"connection refused");
        assert_eq!(
            health.ready().unwrap_err(),
            "cache 'health_flows': Redis backend unreachable"
        );
        assert!(!crate::metrics::cache::backend_up("health_flows"));
        health.mark_up();
        assert_eq!(health.ready(), Ok(()));
        assert!(crate::metrics::cache::backend_up("health_flows"));
    }

    #[test]
    fn a_cache_that_does_not_count_towards_readiness_is_always_ready() {
        let health = BackendHealth::new("health_optional", false);
        assert_eq!(health.ready(), Ok(()));
        health.mark_down(&"connection refused");
        assert_eq!(health.ready(), Ok(()));
        assert!(!health.admit(), "down all the same: commands are refused");
    }

    #[test]
    fn a_down_backend_admits_one_command_per_interval() {
        let health = BackendHealth::new("health_gate", true);
        assert!(health.admit(), "not known yet: commands go through");
        health.mark_up();
        assert!(health.admit());
        assert!(health.admit());

        health.mark_down(&"connection reset");
        assert!(!health.admit(), "refused inside the interval");
        // Move the interval's end into the past instead of sleeping it out.
        health.retry_at_millis.store(0, Ordering::Release);
        assert!(health.admit(), "one trial once the interval has passed");
        assert!(!health.admit(), "and only one");

        health.mark_up();
        assert!(health.admit());
    }

    #[test]
    fn readiness_names_the_first_cache_that_is_down() {
        let up = Arc::new(BackendHealth::new("health_up", true));
        let optional = Arc::new(BackendHealth::new("health_skipped", false));
        let down = Arc::new(BackendHealth::new("health_down", true));
        up.mark_up();
        optional.mark_down(&"gone");
        down.mark_up();
        let readiness = CacheReadiness {
            backends: vec![up, optional, Arc::clone(&down)],
        };
        assert_eq!(readiness.ready(), Ok(()));
        down.mark_down(&"gone");
        assert_eq!(
            readiness.ready().unwrap_err(),
            "cache 'health_down': Redis backend unreachable"
        );
        assert_eq!(readiness.outstanding(), 0);
        readiness.set_draining(true);
        readiness.force();
    }

    #[test]
    fn concurrent_commands_share_one_trial() {
        let health = Arc::new(BackendHealth::new("health_race", true));
        health.mark_down(&"gone");
        health.retry_at_millis.store(0, Ordering::Release);
        let admitted: usize = (0..8)
            .map(|_| {
                let health = Arc::clone(&health);
                std::thread::spawn(move || usize::from(health.admit()))
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|thread| thread.join().expect("thread"))
            .sum();
        assert_eq!(admitted, 1);
    }
}
