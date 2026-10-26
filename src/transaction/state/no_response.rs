//! The no-response timer of a client transaction ([`TimerName::NoResponse`]):
//! a proxied request's bound on drawing any response at all, which a script
//! sets with `relay(no_response_ms=…)` / `fork(no_response_ms=…)`.
//!
//! The parts of [`Ict`] and [`Nict`] that only this timer needs, kept apart
//! from the RFC 3261 §17.1 machines they wrap.

use std::time::Duration;

use super::*;

/// Where a client transaction's no-response timer stands
/// ([`TimerName::NoResponse`]).
///
/// One byte in a transaction that already pads to a word, so a branch without
/// the timer costs nothing for it: the timer itself lives in the timer wheel,
/// and only for a branch the script armed it on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NoResponseProgress {
    /// Not armed: the script did not ask for it, the request drew a response,
    /// or the TU cancelled the request first.
    Off,
    /// Running: the request has been sent and nothing has come back.
    Armed,
    /// It ran out before any response (INVITE only; a non-INVITE transaction
    /// just ends). The branch has been answered locally with a `408`, the
    /// INVITE is no longer retransmitted, and its CANCEL waits for a
    /// provisional that may still come (RFC 3261 §9.1).
    GaveUp,
}

impl Nict {
    /// Give the request `after` to draw any response at all, provisional or
    /// final. Returns the timer to start, or nothing for a request that has
    /// already drawn one.
    ///
    /// When it runs out with nothing back, the transaction ends exactly as
    /// Timer F would end it: retransmission stops and the TU is told of a
    /// timeout, which a proxy answers as a `408` on the branch (RFC 3261
    /// §16.7 step 2). Any response, a `100 Trying` included, stops it: TS
    /// 24.229 §5.4.3.3 asks about failing "to receive any SIP response".
    pub fn arm_no_response(&mut self, after: Duration) -> Option<Action> {
        if self.state != NictState::Trying {
            return None;
        }
        self.no_response = NoResponseProgress::Armed;
        Some(Action::StartTimer(TimerName::NoResponse, after))
    }
}

impl Ict {
    /// Give the INVITE `after` to draw any response at all. Returns the timer
    /// to start, or nothing for an INVITE that has already drawn one.
    ///
    /// Only silence counts. TS 24.229 §5.4.3.3 (HSS based P-CSCF restoration)
    /// has the S-CSCF act when it "fails to receive any SIP response" within a
    /// configurable time, and its NOTE 24 bounds only that time ("needs to be
    /// less than timer B and timer F"), so a `100 Trying` is a response like
    /// any other and stops the timer. An INVITE that has drawn a provisional
    /// and then goes quiet is Timer C's (RFC 3261 §16.6 step 11).
    ///
    /// When it runs out, the branch is handled as RFC 3261 §16.8 handles a
    /// Timer C that fires on a transaction with no provisional: "the proxy
    /// MUST behave as if the transaction received a 408 (Request Timeout)
    /// response". See [`Self::give_up_unanswered`].
    pub fn arm_no_response(&mut self, after: Duration) -> Option<Action> {
        if self.state != IctState::Calling || self.no_response != NoResponseProgress::Off {
            return None;
        }
        self.no_response = NoResponseProgress::Armed;
        Some(Action::StartTimer(TimerName::NoResponse, after))
    }

    /// Stop the no-response timer because the TU is cancelling the INVITE
    /// anyway (the caller's CANCEL, another branch's 2xx or 6xx). Whether it was
    /// running, so the caller knows there is a timer entry to remove.
    pub fn disarm_no_response(&mut self) -> bool {
        if self.no_response != NoResponseProgress::Armed {
            return false;
        }
        self.no_response = NoResponseProgress::Off;
        true
    }

    /// Whether the no-response timer gave up on this INVITE: its branch has
    /// been answered locally, and what still arrives for it is not the
    /// branch's response any more.
    pub fn gave_up(&self) -> bool {
        self.no_response == NoResponseProgress::GaveUp
    }

    /// The no-response timer ran out with nothing back.
    ///
    /// RFC 3261 §9.1 forbids the CANCEL now ("If no provisional response has
    /// been received, the CANCEL request MUST NOT be sent"), so the INVITE is
    /// abandoned instead: Timer A stops (no more retransmissions), the TU is
    /// told of a timeout (answered as a `408` on the branch, §16.7 step 2 and
    /// §16.8), and the CANCEL is built and kept. Should the next hop wake up
    /// and send a provisional after all, that provisional releases the CANCEL;
    /// otherwise Timer B, still running, ends the transaction quietly.
    pub(super) fn give_up_unanswered(&mut self) -> Vec<Action> {
        if self.no_response != NoResponseProgress::Armed {
            return vec![];
        }
        self.no_response = NoResponseProgress::GaveUp;
        let mut actions = vec![Action::CancelTimer(TimerName::A)];
        if matches!(self.cancel, CancelProgress::NotRequested) {
            match self.build_cancel(&[]) {
                Ok(cancel) => self.cancel = CancelProgress::Waiting(Box::new(cancel)),
                Err(error) => actions.push(Action::ProtocolError(format!(
                    "no response before the no-response timer, and the INVITE's CANCEL could not be built for a late provisional: {error}"
                ))),
            }
        }
        actions.push(Action::Timeout);
        actions
    }

    /// An INVITE the no-response timer gave up on. Its branch already has
    /// its `408`, so nothing but a 2xx goes to the TU from here on:
    ///
    /// * a first provisional releases the CANCEL (RFC 3261 §9.1), and the
    ///   final response is given 64*T1 from then;
    /// * a 2xx is passed up: a proxy forwards every 2xx (§16.7 step 5), and
    ///   the TU already knows what to do with one for a branch it has done
    ///   with;
    /// * a 3xx-6xx (most likely the `487` of that CANCEL) is ACKed and
    ///   absorbed (§17.1.1.3);
    /// * Timer B ends the transaction without a second timeout.
    pub(super) fn process_given_up(&mut self, event: IctEvent) -> Vec<Action> {
        match (self.state, event) {
            (IctState::Calling | IctState::Proceeding, IctEvent::TimerB) => {
                self.state = IctState::Terminated;
                self.drop_waiting_cancel();
                vec![Action::Terminated]
            }
            (IctState::Calling, IctEvent::Provisional(_)) => {
                self.state = IctState::Proceeding;
                match self.release_waiting_cancel() {
                    Some(cancel) => vec![
                        Action::SendCancel(cancel),
                        Action::StartTimer(TimerName::B, self.timers.timer_b()),
                    ],
                    None => vec![],
                }
            }
            (
                _,
                IctEvent::TimerA
                | IctEvent::TimerC
                | IctEvent::NoResponse
                | IctEvent::Provisional(_),
            ) => vec![],
            (_, event @ IctEvent::ResponseNon2xx(_)) => {
                let mut actions = self.advance(event);
                actions.retain(|action| !matches!(action, Action::PassToTu(_)));
                actions
            }
            (_, event) => self.advance(event),
        }
    }
}
