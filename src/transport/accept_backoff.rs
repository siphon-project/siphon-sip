//! What a stream listener's accept loop does when `accept()` fails.
//!
//! Linux `accept4` fails with `EMFILE`/`ENFILE` (out of descriptors) or
//! `ENOBUFS`/`ENOMEM` (out of kernel memory) without taking the connection off
//! the backlog. The listener stays readable, so a loop that logs and accepts
//! again spins on the same error: every core it can get, and an error line per
//! turn. These errors back off instead, 5 ms doubling to 1 s, until an accept
//! succeeds (hyper's `AddrIncoming` and Go's `net/http` do the same).
//!
//! `ECONNABORTED`, `EPROTO`, `EPERM` and `EINTR` concern one connection (the
//! peer reset before we took it, a firewall rule refused it): the loop goes on
//! at once and logs at debug, since nothing on our side failed.
//!
//! Every error is counted in `siphon_accept_errors_total`. The `error!` line is
//! kept but limited to one per listener per 10 s, with the number of repeats it
//! stood for.

use std::io;
use std::time::Duration;

use tokio::time::Instant;
use tracing::{debug, error};

/// First sleep after a resource-exhaustion error.
pub const INITIAL_DELAY: Duration = Duration::from_millis(5);
/// Longest sleep; the delay doubles up to here and stays.
pub const MAX_DELAY: Duration = Duration::from_secs(1);
/// At most one `error!` line per listener in this window.
pub const LOG_INTERVAL: Duration = Duration::from_secs(10);

/// How an accept error is handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptErrorKind {
    /// Out of descriptors or kernel memory: back off. Carries the metric reason.
    Exhausted(&'static str),
    /// One connection failed; nothing of ours did. Accept again at once.
    PerConnection,
    /// Anything else: logged at error, no backoff.
    Other,
}

impl AcceptErrorKind {
    /// The `reason` label in `siphon_accept_errors_total`.
    pub fn reason(self) -> &'static str {
        match self {
            AcceptErrorKind::Exhausted(reason) => reason,
            AcceptErrorKind::PerConnection | AcceptErrorKind::Other => "other",
        }
    }
}

/// Sort an accept error by what the loop should do about it.
pub fn classify(error: &io::Error) -> AcceptErrorKind {
    match error.raw_os_error() {
        Some(libc::EMFILE) => AcceptErrorKind::Exhausted("emfile"),
        Some(libc::ENFILE) => AcceptErrorKind::Exhausted("enfile"),
        Some(libc::ENOBUFS) => AcceptErrorKind::Exhausted("enobufs"),
        Some(libc::ENOMEM) => AcceptErrorKind::Exhausted("enomem"),
        Some(libc::ECONNABORTED | libc::EPROTO | libc::EPERM | libc::EINTR) => {
            AcceptErrorKind::PerConnection
        }
        _ => match error.kind() {
            io::ErrorKind::ConnectionAborted | io::ErrorKind::Interrupted => {
                AcceptErrorKind::PerConnection
            }
            _ => AcceptErrorKind::Other,
        },
    }
}

/// One listener's accept-error state. Owned by its accept loop.
pub struct AcceptBackoff {
    transport: String,
    listener: String,
    next_delay: Duration,
    last_logged: Option<Instant>,
    suppressed: u64,
}

impl AcceptBackoff {
    /// State for the listener bound at `listener`. `transport` is the metric
    /// label (`tcp`, `tls`, `ws`, `wss`, `sctp`, `tcp+ws` for a mux port, or
    /// the protocol of a non-SIP listener: `diameter`, `x1`).
    pub fn new(transport: impl Into<String>, listener: impl std::fmt::Display) -> Self {
        let transport = transport.into();
        let listener = listener.to_string();
        crate::metrics::accept::register_listener(&transport, &listener);
        Self {
            transport,
            listener,
            next_delay: INITIAL_DELAY,
            last_logged: None,
            suppressed: 0,
        }
    }

    /// An accept succeeded: the next exhaustion starts from the short delay.
    pub fn on_success(&mut self) {
        self.next_delay = INITIAL_DELAY;
    }

    /// An accept failed: count it, log it (rate-limited) and, when the process
    /// is out of descriptors or memory, sleep before the loop accepts again.
    pub async fn on_error(&mut self, error: &io::Error) {
        if let Some(delay) = self.record(error, Instant::now()) {
            tokio::time::sleep(delay).await;
        }
    }

    /// Everything [`Self::on_error`] does except the sleep, which it returns.
    fn record(&mut self, error: &io::Error, now: Instant) -> Option<Duration> {
        let kind = classify(error);
        crate::metrics::accept::record(&self.transport, &self.listener, kind.reason());
        match kind {
            AcceptErrorKind::PerConnection => {
                debug!(
                    "{} accept on {}: connection dropped before it was taken: {error}",
                    self.transport, self.listener
                );
                None
            }
            AcceptErrorKind::Exhausted(_) => {
                let delay = self.next_delay;
                self.next_delay = (delay * 2).min(MAX_DELAY);
                self.log_error(error, now, Some(delay));
                Some(delay)
            }
            AcceptErrorKind::Other => {
                self.log_error(error, now, None);
                None
            }
        }
    }

    fn log_error(&mut self, error: &io::Error, now: Instant, delay: Option<Duration>) {
        let due = self
            .last_logged
            .is_none_or(|last| now.duration_since(last) >= LOG_INTERVAL);
        if !due {
            self.suppressed += 1;
            return;
        }
        let repeats = std::mem::take(&mut self.suppressed);
        self.last_logged = Some(now);
        let soft_limit = crate::fd_limit::current_soft_limit()
            .map_or_else(|| "unknown".to_string(), |limit| limit.to_string());
        match delay {
            Some(delay) => error!(
                "{} accept error on {}: {error} (RLIMIT_NOFILE soft {soft_limit}); \
                 retrying in {} ms; {repeats} more since the last report",
                self.transport,
                self.listener,
                delay.as_millis()
            ),
            None => error!(
                "{} accept error on {}: {error}; {repeats} more since the last report",
                self.transport, self.listener
            ),
        }
    }
}

#[cfg(test)]
#[path = "accept_backoff_listener_tests.rs"]
mod listener_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log_capture::LogBuffer;

    fn os_error(errno: i32) -> io::Error {
        io::Error::from_raw_os_error(errno)
    }

    fn capturing<T>(body: impl FnOnce() -> T) -> (T, String) {
        let log = LogBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(log.clone())
            .finish();
        let result = tracing::subscriber::with_default(subscriber, body);
        (result, log.rendered())
    }

    fn backoff(listener: &str) -> AcceptBackoff {
        AcceptBackoff::new("tcp", listener)
    }

    #[test]
    fn errors_are_sorted_by_what_the_loop_does() {
        assert_eq!(
            classify(&os_error(libc::EMFILE)),
            AcceptErrorKind::Exhausted("emfile")
        );
        assert_eq!(
            classify(&os_error(libc::ENFILE)),
            AcceptErrorKind::Exhausted("enfile")
        );
        assert_eq!(
            classify(&os_error(libc::ENOBUFS)),
            AcceptErrorKind::Exhausted("enobufs")
        );
        assert_eq!(
            classify(&os_error(libc::ENOMEM)),
            AcceptErrorKind::Exhausted("enomem")
        );
        for errno in [libc::ECONNABORTED, libc::EPROTO, libc::EPERM, libc::EINTR] {
            assert_eq!(
                classify(&os_error(errno)),
                AcceptErrorKind::PerConnection,
                "{errno}"
            );
        }
        assert_eq!(classify(&os_error(libc::EINVAL)), AcceptErrorKind::Other);
        assert_eq!(
            classify(&io::Error::other("not an os error")),
            AcceptErrorKind::Other
        );
    }

    #[test]
    fn reason_labels() {
        assert_eq!(AcceptErrorKind::Exhausted("enfile").reason(), "enfile");
        assert_eq!(AcceptErrorKind::PerConnection.reason(), "other");
        assert_eq!(AcceptErrorKind::Other.reason(), "other");
    }

    #[tokio::test(start_paused = true)]
    async fn exhaustion_backs_off_doubling_to_one_second() {
        let mut backoff = backoff("192.0.2.10:5060");
        let start = Instant::now();
        let delays: Vec<u64> = (0..10)
            .map(|step| {
                let now = start + Duration::from_secs(step);
                backoff
                    .record(&os_error(libc::EMFILE), now)
                    .expect("exhaustion sleeps")
                    .as_millis() as u64
            })
            .collect();
        assert_eq!(delays, [5, 10, 20, 40, 80, 160, 320, 640, 1000, 1000]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_successful_accept_resets_the_backoff() {
        let mut backoff = backoff("192.0.2.11:5060");
        let now = Instant::now();
        for _ in 0..4 {
            backoff.record(&os_error(libc::EMFILE), now);
        }
        backoff.on_success();
        assert_eq!(
            backoff.record(&os_error(libc::ENFILE), now),
            Some(INITIAL_DELAY)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn on_error_sleeps_for_the_backoff() {
        let mut backoff = backoff("192.0.2.12:5060");
        let start = Instant::now();
        backoff.on_error(&os_error(libc::EMFILE)).await;
        backoff.on_error(&os_error(libc::EMFILE)).await;
        assert_eq!(start.elapsed(), Duration::from_millis(15));
    }

    #[tokio::test(start_paused = true)]
    async fn a_per_connection_error_neither_sleeps_nor_logs_an_error() {
        let mut backoff = backoff("192.0.2.13:5060");
        let start = Instant::now();
        let (delay, log) = capturing(|| backoff.record(&os_error(libc::ECONNABORTED), start));
        assert_eq!(delay, None);
        assert!(!log.contains("ERROR"), "{log}");
        assert!(log.contains("DEBUG"), "{log}");
        backoff.on_error(&os_error(libc::ECONNABORTED)).await;
        assert_eq!(start.elapsed(), Duration::ZERO);
        // And it does not grow the delay a later exhaustion starts from.
        assert_eq!(
            backoff.record(&os_error(libc::EMFILE), start),
            Some(INITIAL_DELAY)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_unknown_error_logs_without_sleeping() {
        let mut backoff = backoff("192.0.2.14:5060");
        let (delay, log) = capturing(|| backoff.record(&os_error(libc::EINVAL), Instant::now()));
        assert_eq!(delay, None);
        assert!(log.contains("ERROR"), "{log}");
    }

    #[tokio::test(start_paused = true)]
    async fn the_error_line_is_limited_to_one_per_interval_with_a_repeat_count() {
        let mut backoff = backoff("192.0.2.15:5060");
        let start = Instant::now();
        let ((), log) = capturing(|| {
            // 500 errors inside the first window: one line.
            for step in 0..500 {
                backoff.record(&os_error(libc::EMFILE), start + Duration::from_millis(step));
            }
        });
        assert_eq!(log.matches("ERROR").count(), 1, "{log}");
        assert!(log.contains("tcp accept error on 192.0.2.15:5060"), "{log}");
        assert!(log.contains("RLIMIT_NOFILE soft"), "{log}");
        assert!(log.contains("0 more since the last report"), "{log}");

        let ((), log) = capturing(|| {
            backoff.record(&os_error(libc::EMFILE), start + LOG_INTERVAL);
        });
        assert_eq!(log.matches("ERROR").count(), 1, "{log}");
        assert!(log.contains("499 more since the last report"), "{log}");
    }

    #[tokio::test(start_paused = true)]
    async fn every_error_is_counted_logged_or_not() {
        crate::metrics::init().expect("metrics");
        let listener = "192.0.2.16:5060";
        let mut backoff = backoff(listener);
        let now = Instant::now();
        for _ in 0..3 {
            backoff.record(&os_error(libc::EMFILE), now);
        }
        backoff.record(&os_error(libc::ECONNABORTED), now);
        assert_eq!(
            crate::metrics::accept::errors("tcp", listener, "emfile"),
            Some(3)
        );
        assert_eq!(
            crate::metrics::accept::errors("tcp", listener, "other"),
            Some(1)
        );
    }
}
