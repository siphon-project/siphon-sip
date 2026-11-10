//! The peer state machine of RFC 3539 section 3.4.1: OKAY, SUSPECT, DOWN and
//! REOPEN, driven by the Device-Watchdog exchange.
//!
//! The machine decides; the connection acts. Every answer it gives is an
//! action for the caller: send a Device-Watchdog-Request, fail over the
//! requests waiting on this peer, close the connection. The peer takes new
//! traffic only in OKAY.
//!
//! * OKAY: any message from the peer proves it alive. The watchdog timer
//!   (Tw, `watchdog_interval`) sends a DWR when none is outstanding; when one
//!   still is, the peer is SUSPECT and its pending requests go elsewhere.
//! * SUSPECT: a DWA brings it back to OKAY; another expiry closes the
//!   connection (DOWN).
//! * REOPEN: a connection that follows a failure. The peer must answer
//!   `reopen_required` watchdogs before it takes traffic again; a missed one
//!   is DOWN.

/// The state of a peer's watchdog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogState {
    Okay,
    Suspect,
    Down,
    Reopen,
}

impl WatchdogState {
    pub(crate) fn as_u8(self) -> u8 {
        match self {
            Self::Okay => 0,
            Self::Suspect => 1,
            Self::Down => 2,
            Self::Reopen => 3,
        }
    }

    pub(crate) fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Suspect,
            2 => Self::Down,
            3 => Self::Reopen,
            _ => Self::Okay,
        }
    }

    /// The name used in logs.
    pub fn name(self) -> &'static str {
        match self {
            Self::Okay => "OKAY",
            Self::Suspect => "SUSPECT",
            Self::Down => "DOWN",
            Self::Reopen => "REOPEN",
        }
    }
}

/// What the connection does after an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogAction {
    None,
    /// Send a Device-Watchdog-Request.
    SendWatchdog,
    /// Fail the requests waiting for answers from this peer, so their senders
    /// can try another peer.
    FailOver,
    /// Close the connection.
    Close,
}

/// The state machine. No clock and no I/O: the timer calls
/// [`on_timer`](Self::on_timer), the reader reports what arrived.
#[derive(Debug, Clone)]
pub struct Watchdog {
    state: WatchdogState,
    pending: bool,
    answered: u32,
    reopen_required: u32,
}

impl Watchdog {
    /// A first connection: OKAY.
    pub fn new(reopen_required: u32) -> Self {
        Self {
            state: WatchdogState::Okay,
            pending: false,
            answered: 0,
            reopen_required,
        }
    }

    /// A connection after a failure: REOPEN, with the first DWR to be sent
    /// now (the returned action). With nothing required it is OKAY at once.
    pub fn reopening(reopen_required: u32) -> (Self, WatchdogAction) {
        if reopen_required == 0 {
            return (Self::new(0), WatchdogAction::None);
        }
        (
            Self {
                state: WatchdogState::Reopen,
                pending: true,
                answered: 0,
                reopen_required,
            },
            WatchdogAction::SendWatchdog,
        )
    }

    pub fn state(&self) -> WatchdogState {
        self.state
    }

    /// The watchdog timer expired.
    pub fn on_timer(&mut self) -> WatchdogAction {
        match self.state {
            WatchdogState::Okay if !self.pending => {
                self.pending = true;
                WatchdogAction::SendWatchdog
            }
            WatchdogState::Okay => {
                self.state = WatchdogState::Suspect;
                WatchdogAction::FailOver
            }
            WatchdogState::Suspect => {
                self.state = WatchdogState::Down;
                WatchdogAction::Close
            }
            WatchdogState::Reopen if !self.pending => {
                self.pending = true;
                WatchdogAction::SendWatchdog
            }
            WatchdogState::Reopen => {
                self.state = WatchdogState::Down;
                WatchdogAction::Close
            }
            WatchdogState::Down => WatchdogAction::None,
        }
    }

    /// A Device-Watchdog-Answer arrived.
    pub fn on_answer(&mut self) -> WatchdogAction {
        self.pending = false;
        match self.state {
            WatchdogState::Okay | WatchdogState::Down => WatchdogAction::None,
            WatchdogState::Suspect => {
                self.state = WatchdogState::Okay;
                WatchdogAction::None
            }
            WatchdogState::Reopen => {
                self.answered += 1;
                if self.answered >= self.reopen_required {
                    self.state = WatchdogState::Okay;
                    WatchdogAction::None
                } else {
                    self.pending = true;
                    WatchdogAction::SendWatchdog
                }
            }
        }
    }

    /// Any other message arrived: in OKAY it proves the peer alive, in the
    /// other states it changes nothing (only the watchdog brings a peer back).
    pub fn on_message(&mut self) {
        if self.state == WatchdogState::Okay {
            self.pending = false;
        }
    }

    /// The connection ended.
    pub fn on_closed(&mut self) {
        self.state = WatchdogState::Down;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use WatchdogAction::*;
    use WatchdogState::*;

    #[test]
    fn an_idle_okay_peer_is_sent_a_watchdog_then_goes_suspect_when_it_is_not_answered() {
        let mut machine = Watchdog::new(3);
        assert_eq!(machine.on_timer(), SendWatchdog);
        assert_eq!(machine.state(), Okay);
        assert_eq!(machine.on_timer(), FailOver);
        assert_eq!(machine.state(), Suspect);
    }

    #[test]
    fn any_message_proves_an_okay_peer_alive() {
        let mut machine = Watchdog::new(3);
        assert_eq!(machine.on_timer(), SendWatchdog);
        machine.on_message();
        assert_eq!(
            machine.on_timer(),
            SendWatchdog,
            "nothing is outstanding any more"
        );
        assert_eq!(machine.state(), Okay);
    }

    #[test]
    fn a_suspect_peer_that_answers_is_okay_again() {
        let mut machine = Watchdog::new(3);
        machine.on_timer();
        machine.on_timer();
        assert_eq!(machine.state(), Suspect);
        assert_eq!(machine.on_answer(), None);
        assert_eq!(machine.state(), Okay);
    }

    #[test]
    fn plain_traffic_does_not_bring_a_suspect_peer_back() {
        let mut machine = Watchdog::new(3);
        machine.on_timer();
        machine.on_timer();
        machine.on_message();
        assert_eq!(machine.state(), Suspect);
    }

    #[test]
    fn a_suspect_peer_that_stays_silent_is_closed() {
        let mut machine = Watchdog::new(3);
        machine.on_timer();
        machine.on_timer();
        assert_eq!(machine.on_timer(), Close);
        assert_eq!(machine.state(), Down);
        assert_eq!(machine.on_timer(), None);
    }

    #[test]
    fn a_reopened_peer_must_answer_the_required_watchdogs_before_it_is_okay() {
        let (mut machine, first) = Watchdog::reopening(3);
        assert_eq!(first, SendWatchdog);
        assert_eq!(machine.state(), Reopen);
        assert_eq!(machine.on_answer(), SendWatchdog);
        assert_eq!(machine.state(), Reopen);
        assert_eq!(machine.on_answer(), SendWatchdog);
        assert_eq!(machine.state(), Reopen);
        assert_eq!(machine.on_answer(), None);
        assert_eq!(machine.state(), Okay, "the third answer");
    }

    #[test]
    fn traffic_does_not_count_in_reopen() {
        let (mut machine, _) = Watchdog::reopening(2);
        machine.on_message();
        machine.on_message();
        assert_eq!(machine.state(), Reopen);
    }

    #[test]
    fn a_reopened_peer_that_misses_a_watchdog_is_down() {
        let (mut machine, _) = Watchdog::reopening(3);
        assert_eq!(machine.on_timer(), Close);
        assert_eq!(machine.state(), Down);
    }

    #[test]
    fn nothing_required_is_okay_at_once() {
        let (machine, action) = Watchdog::reopening(0);
        assert_eq!(action, None);
        assert_eq!(machine.state(), Okay);
    }

    #[test]
    fn a_closed_connection_is_down() {
        let mut machine = Watchdog::new(3);
        machine.on_closed();
        assert_eq!(machine.state(), Down);
    }
}
