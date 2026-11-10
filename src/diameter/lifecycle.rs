//! Peer connection lifecycle: Disconnect-Peer (RFC 6733 section 5.4) and what
//! a node does about reconnecting afterwards.
//!
//! A node about to take a connection down tells its peer why with a
//! Disconnect-Peer-Request, waits for the answer and only then closes. The
//! Disconnect-Cause is also what the receiver reads to decide when to dial
//! again: a peer that is rebooting is welcome back at once, one that is busy
//! or does not want to talk is not dialled in a tight loop.

use super::peer::DiameterPeer;
use std::sync::{Arc, LazyLock, Mutex, Weak};
use std::time::Duration;

/// Disconnect-Cause AVP values (RFC 6733 section 5.4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectCause {
    /// The sender is rebooting; reconnecting is welcome.
    Rebooting = 0,
    /// The sender cannot serve now; do not reconnect at once.
    Busy = 1,
    /// The sender does not want this connection; do not reconnect at once.
    DoNotWantToTalkToYou = 2,
}

impl DisconnectCause {
    /// The cause for a wire value, None for a value the RFC does not define.
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Rebooting),
            1 => Some(Self::Busy),
            2 => Some(Self::DoNotWantToTalkToYou),
            _ => None,
        }
    }

    /// The Disconnect-Cause AVP value.
    pub fn as_u32(self) -> u32 {
        self as u32
    }

    /// The name RFC 6733 gives the value, for logs and metric labels.
    pub fn name(self) -> &'static str {
        match self {
            Self::Rebooting => "REBOOTING",
            Self::Busy => "BUSY",
            Self::DoNotWantToTalkToYou => "DO_NOT_WANT_TO_TALK_TO_YOU",
        }
    }
}

/// Timers of a peer connection's lifecycle. Part of [`super::peer::PeerConfig`].
#[derive(Debug, Clone)]
pub struct PeerLifecycle {
    /// How long a Disconnect-Peer-Request waits for its answer before the
    /// connection is closed anyway, in milliseconds. Shutdown must not hang on
    /// a dead peer.
    pub disconnect_timeout_ms: u64,
    /// How long to leave a peer alone after it disconnected with
    /// DO_NOT_WANT_TO_TALK_TO_YOU, in seconds.
    pub refused_hold: u64,
    /// The ceiling of the reconnect backoff, in seconds. The wait between
    /// attempts starts at `reconnect_delay` and doubles up to this.
    pub reconnect_delay_max: u64,
    /// Watchdogs a peer must answer in REOPEN (RFC 3539) before it takes
    /// traffic again after a reconnection. 0 skips REOPEN.
    pub reopen_watchdog_answers: u32,
    /// The watchdog timer in milliseconds, when it is to be finer than
    /// `watchdog_interval` seconds.
    pub watchdog_interval_ms: Option<u64>,
}

impl Default for PeerLifecycle {
    fn default() -> Self {
        Self {
            disconnect_timeout_ms: 1000,
            refused_hold: 300,
            reconnect_delay_max: 60,
            reopen_watchdog_answers: 3,
            watchdog_interval_ms: None,
        }
    }
}

impl PeerLifecycle {
    /// The bound a Disconnect-Peer-Request waits for its answer.
    pub fn disconnect_timeout(&self) -> Duration {
        Duration::from_millis(self.disconnect_timeout_ms)
    }
}

/// What a reconnect loop does once its connection has ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconnectAdvice {
    /// This node disconnected the connection itself: do not dial again.
    Stop,
    /// Dial again after the ordinary delay.
    Normal,
    /// Wait at least this long before dialling.
    Hold(Duration),
}

/// Whether and when to dial a peer again, from how its connection ended.
/// `cause` is the Disconnect-Cause of a Disconnect-Peer-Request the peer sent.
/// BUSY holds for `busy_hold` (the reconnect ceiling): the peer said it cannot
/// serve now, and the ceiling is how long this node waits on a silent one.
pub fn reconnect_advice(
    cause: Option<u32>,
    disconnected_locally: bool,
    lifecycle: &PeerLifecycle,
    busy_hold: Duration,
) -> ReconnectAdvice {
    if disconnected_locally {
        return ReconnectAdvice::Stop;
    }
    match cause.and_then(DisconnectCause::from_u32) {
        Some(DisconnectCause::Busy) => ReconnectAdvice::Hold(busy_hold),
        Some(DisconnectCause::DoNotWantToTalkToYou) => {
            ReconnectAdvice::Hold(Duration::from_secs(lifecycle.refused_hold))
        }
        Some(DisconnectCause::Rebooting) | None => ReconnectAdvice::Normal,
    }
}

/// How a local disconnect ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisconnectOutcome {
    /// The peer answered the DPR; the connection was then closed.
    Answered,
    /// No answer within the bound (or the request could not be sent); the
    /// connection was closed anyway.
    Unanswered,
    /// The connection was not open, or another disconnect was already running.
    NotOpen,
}

static LIVE: LazyLock<Mutex<Vec<Weak<DiameterPeer>>>> = LazyLock::new(|| Mutex::new(Vec::new()));

/// Remember a connection so shutdown can disconnect it. Every connection of
/// every kind (`peers`, `servers`, `connect_to`, accepted clients) is
/// registered when its tasks start; entries of closed connections are
/// dropped as new ones come.
pub(crate) fn register(peer: &Arc<DiameterPeer>) {
    if let Ok(mut live) = LIVE.lock() {
        live.retain(|weak| weak.upgrade().is_some_and(|peer| peer.is_open()));
        live.push(Arc::downgrade(peer));
    }
}

/// The connections that are open now.
fn open_connections() -> Vec<Arc<DiameterPeer>> {
    LIVE.lock()
        .map(|live| {
            live.iter()
                .filter_map(Weak::upgrade)
                .filter(|peer| peer.is_open())
                .collect()
        })
        .unwrap_or_default()
}

/// Totals of [`disconnect_all`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DisconnectSummary {
    pub answered: usize,
    pub unanswered: usize,
}

/// Disconnect every open connection with `cause`: all the Disconnect-Peer-
/// Requests go out at once and each waits up to its own configured bound, so
/// the whole takes about one bound, not one per peer.
pub async fn disconnect_all(cause: DisconnectCause) -> DisconnectSummary {
    let mut tasks = Vec::new();
    for peer in open_connections() {
        tasks.push(tokio::spawn(async move {
            let wait = peer.config().lifecycle.disconnect_timeout();
            peer.disconnect(cause, wait).await
        }));
    }
    let mut summary = DisconnectSummary::default();
    for task in tasks {
        match task.await {
            Ok(DisconnectOutcome::Answered) => summary.answered += 1,
            Ok(DisconnectOutcome::Unanswered) => summary.unanswered += 1,
            Ok(DisconnectOutcome::NotOpen) | Err(_) => {}
        }
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_causes_carry_the_values_of_rfc_6733() {
        assert_eq!(DisconnectCause::Rebooting.as_u32(), 0);
        assert_eq!(DisconnectCause::Busy.as_u32(), 1);
        assert_eq!(DisconnectCause::DoNotWantToTalkToYou.as_u32(), 2);
        assert_eq!(
            DisconnectCause::from_u32(2),
            Some(DisconnectCause::DoNotWantToTalkToYou)
        );
        assert_eq!(DisconnectCause::from_u32(3), None);
    }

    #[test]
    fn a_connection_this_node_closed_is_not_dialled_again() {
        let lifecycle = PeerLifecycle::default();
        assert_eq!(
            reconnect_advice(None, true, &lifecycle, Duration::from_secs(60)),
            ReconnectAdvice::Stop
        );
    }

    #[test]
    fn a_rebooting_peer_is_dialled_on_the_ordinary_schedule() {
        let lifecycle = PeerLifecycle::default();
        assert_eq!(
            reconnect_advice(Some(0), false, &lifecycle, Duration::from_secs(60)),
            ReconnectAdvice::Normal
        );
        assert_eq!(
            reconnect_advice(None, false, &lifecycle, Duration::from_secs(60)),
            ReconnectAdvice::Normal
        );
    }

    #[test]
    fn a_busy_peer_is_left_alone_for_the_ceiling() {
        let lifecycle = PeerLifecycle::default();
        assert_eq!(
            reconnect_advice(Some(1), false, &lifecycle, Duration::from_secs(60)),
            ReconnectAdvice::Hold(Duration::from_secs(60))
        );
    }

    #[test]
    fn a_peer_that_does_not_want_to_talk_is_left_alone_for_the_refused_hold() {
        let lifecycle = PeerLifecycle {
            refused_hold: 900,
            ..PeerLifecycle::default()
        };
        assert_eq!(
            reconnect_advice(Some(2), false, &lifecycle, Duration::from_secs(60)),
            ReconnectAdvice::Hold(Duration::from_secs(900))
        );
    }
}
