//! RFC 3262 toward the caller: siphon is the UAS of the A-leg, so which
//! provisional reaches the caller reliably, with which `RSeq`, what waits for a
//! PRACK and what a PRACK releases are siphon's to decide, whatever the callee
//! did on the B-leg (which siphon PRACKs itself).
//!
//! Pure state, one per call: the dispatcher puts on the wire what this decides.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::sip::headers::refer::ReferTo;
use crate::sip::message::SipMessage;

/// How long a reliable provisional waits for its PRACK before the caller is
/// refused: 64*T1 (RFC 3262 §3).
pub const PRACK_WAIT: Duration = Duration::from_secs(32);

/// The highest `RSeq` siphon numbers a provisional with. RFC 3262 §7.1 allows up to
/// 2**32 - 1 and §3 has the numbering never wrap; siphon stays within 2**31 - 1,
/// the ceiling §3 puts on the first one.
const RSEQ_CEILING: u32 = 0x7FFF_FFFF;

/// Whether a provisional goes to the caller reliably (RFC 3262 §3).
///
/// Always when the caller required `100rel`: the UAS "MUST send any non-100
/// provisional response reliably". When it only supports `100rel`, siphon may,
/// and does when the callee sent this provisional reliably, so the caller keeps
/// the reliability the callee asked for, and when it carries a session
/// description, so the early media it announces is not lost on the way.
/// Otherwise never.
pub fn sends_reliably(
    caller_requires: bool,
    caller_supports: bool,
    callee_sent_reliably: bool,
    carries_session_description: bool,
) -> bool {
    caller_requires || (caller_supports && (callee_sent_reliably || carries_session_description))
}

/// A provisional for the caller that has to wait its turn.
#[derive(Debug)]
struct Queued {
    response: SipMessage,
    reliable: bool,
    link: Option<u64>,
}

/// A provisional to put on the wire now. `rseq` is `Some` for a reliable one,
/// together with the `stop` its retransmissions end on once a final response
/// has gone to the caller.
#[derive(Debug)]
pub struct ProvisionalSend {
    pub response: SipMessage,
    pub rseq: Option<u32>,
    pub stop: Option<Arc<tokio::sync::Notify>>,
}

/// What became of a provisional offered for the caller.
#[derive(Debug)]
pub enum Offered {
    /// Send it now.
    Send(ProvisionalSend),
    /// It waits for the PRACK of the reliable provisional before it (RFC 3262
    /// §3: no second reliable provisional until the first is acknowledged),
    /// and goes out when that PRACK arrives.
    Queued,
    /// A final response already went to the caller, so no provisional follows.
    AfterFinal,
}

/// The caller's 2xx, held until the PRACK of a reliable provisional that
/// carried a session description (RFC 3262 §3, §5).
#[derive(Debug)]
pub struct HeldAnswer {
    /// The 2xx as the caller receives it.
    pub response: SipMessage,
    /// Relayed from the callee, whose dialog is BYEd if this 2xx is never sent;
    /// `false` for siphon's own answer (`call.answer()`).
    pub relayed: bool,
    /// A `call.refer()` from `@b2bua.on_answer`, which follows the 2xx.
    pub deferred_refer: Option<ReferTo>,
}

/// What to do with the caller's 2xx.
#[derive(Debug)]
pub enum AnswerStep {
    /// Send it now.
    Send(Box<HeldAnswer>),
    /// It waits for a PRACK and goes out with the PRACK's 200.
    Held,
}

/// What a PRACK from the caller comes to (RFC 3262 §3).
#[derive(Debug)]
pub enum PrackOutcome {
    /// It acknowledges the reliable provisional awaiting it: 200, and what that
    /// releases, in order. `rseq` names the acknowledged provisional.
    Acknowledged {
        rseq: u32,
        release: Vec<ProvisionalSend>,
        answer: Option<Box<HeldAnswer>>,
        /// The link the acknowledged provisional carried to the callee's PRACK
        /// held for it ([`super::PrackBridge`]).
        link: Option<u64>,
    },
    /// A retransmission of a PRACK already answered: 200 again.
    AlreadyAcknowledged,
    /// It matches no reliable provisional on this dialog: 481.
    Unmatched,
}

/// The unacknowledged reliable provisional on the caller's dialog.
#[derive(Debug)]
struct Unacknowledged {
    rseq: u32,
    carries_sdp: bool,
    sent_at: Instant,
    stop: Arc<tokio::sync::Notify>,
    link: Option<u64>,
}

/// The A-leg's reliable provisionals (RFC 3262 §3), one per call: siphon's
/// `RSeq` numbering on the caller's dialog, the provisional awaiting its PRACK,
/// the provisionals and the 2xx waiting behind it.
#[derive(Debug, Default)]
pub struct ALegReliableProvisionals {
    /// The caller's INVITE CSeq number, which a PRACK's `RAck` names.
    invite_cseq: Option<u32>,
    first_rseq: Option<u32>,
    last_rseq: Option<u32>,
    unacknowledged: Option<Unacknowledged>,
    highest_acknowledged: Option<u32>,
    queued: VecDeque<Queued>,
    held_answer: Option<Box<HeldAnswer>>,
    /// A final response has gone to the caller.
    finished: bool,
    /// siphon's offer to a caller whose INVITE carried none, by the `RSeq` of the
    /// reliable provisional that carried it, until that provisional's PRACK.
    offer_to_caller: Option<(u32, Vec<u8>)>,
    /// siphon has sent that caller its offer.
    offered_to_caller: bool,
}

impl ALegReliableProvisionals {
    /// The session description in siphon's reliable provisional `rseq` is siphon's
    /// offer to a caller whose INVITE carried none (RFC 3262 §5), in force on the
    /// caller's dialog only once the PRACK of `rseq` answers it. Only the first
    /// counts: SDP in a later provisional offers nothing new.
    pub fn note_offer_to_caller(&mut self, rseq: u32, sdp: Vec<u8>) {
        if !self.offered_to_caller {
            self.offered_to_caller = true;
            self.offer_to_caller = Some((rseq, sdp));
        }
    }

    /// The offer the caller's PRACK of `rseq` answered, when that provisional
    /// carried siphon's offer.
    pub fn take_answered_offer(&mut self, rseq: u32) -> Option<Vec<u8>> {
        if self
            .offer_to_caller
            .as_ref()
            .is_some_and(|(noted, _)| *noted == rseq)
        {
            self.offer_to_caller.take().map(|(_, sdp)| sdp)
        } else {
            None
        }
    }
}

impl ALegReliableProvisionals {
    /// Offer a provisional for the caller, sent reliably when `reliable`.
    /// `link` ties it to the callee's PRACK held for it, which the caller's PRACK
    /// of this provisional releases.
    ///
    /// It goes out now unless something is already waiting, or it is reliable
    /// and a reliable one before it is unacknowledged; then it queues, so the
    /// caller sees the provisionals in the order the call produced them.
    pub fn offer(
        &mut self,
        response: SipMessage,
        reliable: bool,
        link: Option<u64>,
        now: Instant,
    ) -> Offered {
        if self.finished {
            return Offered::AfterFinal;
        }
        if !self.queued.is_empty() || (reliable && self.unacknowledged.is_some()) {
            self.queued.push_back(Queued {
                response,
                reliable,
                link,
            });
            return Offered::Queued;
        }
        Offered::Send(self.dispatch(response, reliable, link, now))
    }

    /// Number and record a provisional that goes out now.
    fn dispatch(
        &mut self,
        response: SipMessage,
        reliable: bool,
        link: Option<u64>,
        now: Instant,
    ) -> ProvisionalSend {
        if self.invite_cseq.is_none() {
            self.invite_cseq = cseq_number(&response);
        }
        let rseq = match self.last_rseq {
            // RFC 3262 §3: each later one on the dialog is exactly one more, and
            // the numbering never wraps. The start leaves 2**30 of room, so the
            // ceiling is not reached by a call; were it, the provisional goes
            // out unreliably rather than with a number the caller must reject.
            Some(last) => last.checked_add(1).filter(|next| *next <= RSEQ_CEILING),
            None => Some(initial_rseq()),
        };
        let Some(rseq) = rseq.filter(|_| reliable) else {
            return ProvisionalSend {
                response,
                rseq: None,
                stop: None,
            };
        };
        self.first_rseq.get_or_insert(rseq);
        self.last_rseq = Some(rseq);
        let stop = Arc::new(tokio::sync::Notify::new());
        self.unacknowledged = Some(Unacknowledged {
            rseq,
            carries_sdp: carries_session_description(&response),
            sent_at: now,
            stop: Arc::clone(&stop),
            link,
        });
        ProvisionalSend {
            response,
            rseq: Some(rseq),
            stop: Some(stop),
        }
    }

    /// The caller's 2xx is ready. It goes out now unless a reliable provisional
    /// that carried a session description is unacknowledged, or provisionals are
    /// still queued (one of them may carry the session description the 2xx
    /// relies on); then it is held for the PRACK that clears the way.
    pub fn answer(&mut self, answer: Box<HeldAnswer>) -> AnswerStep {
        if self.finished || self.answer_may_go() {
            self.finish();
            return AnswerStep::Send(answer);
        }
        self.held_answer = Some(answer);
        AnswerStep::Held
    }

    fn answer_may_go(&self) -> bool {
        self.queued.is_empty()
            && !self
                .unacknowledged
                .as_ref()
                .is_some_and(|pending| pending.carries_sdp)
    }

    /// A PRACK from the caller with `RAck: <rseq> <cseq_number> INVITE`.
    ///
    /// The one that acknowledges the provisional awaiting it releases what
    /// waited: the queued provisionals up to and including the next reliable
    /// one, and the held 2xx once nothing it has to follow is left.
    pub fn acknowledge(&mut self, rseq: u32, cseq_number: u32, now: Instant) -> PrackOutcome {
        if self.invite_cseq != Some(cseq_number) {
            return PrackOutcome::Unmatched;
        }
        if !self
            .unacknowledged
            .as_ref()
            .is_some_and(|pending| pending.rseq == rseq)
        {
            let acknowledged_before = self.first_rseq.is_some_and(|first| rseq >= first)
                && self
                    .highest_acknowledged
                    .is_some_and(|highest| rseq <= highest);
            return if acknowledged_before {
                PrackOutcome::AlreadyAcknowledged
            } else {
                PrackOutcome::Unmatched
            };
        }
        let link = self.unacknowledged.take().and_then(|pending| pending.link);
        self.highest_acknowledged = Some(rseq);
        let mut release = Vec::new();
        while let Some(next) = self.queued.pop_front() {
            let reliable = next.reliable;
            let send = self.dispatch(next.response, reliable, next.link, now);
            let sent_reliably = send.rseq.is_some();
            release.push(send);
            if sent_reliably {
                break;
            }
        }
        let answer = if self.held_answer.is_some() && self.answer_may_go() {
            let answer = self.held_answer.take();
            self.finish();
            answer
        } else {
            None
        };
        PrackOutcome::Acknowledged {
            rseq,
            release,
            answer,
            link,
        }
    }

    /// A final response goes to the caller: nothing is queued or sent reliably
    /// after it, and the unacknowledged provisional stops being retransmitted
    /// (RFC 3262 §3), though its PRACK is still answered. Returns a 2xx that was
    /// held, which will now never be sent.
    pub fn finish(&mut self) -> Option<Box<HeldAnswer>> {
        self.finished = true;
        self.queued.clear();
        if let Some(pending) = &self.unacknowledged {
            pending.stop.notify_one();
        }
        self.held_answer.take()
    }

    /// Whether the caller has let a reliable provisional go unacknowledged for
    /// 64*T1 while no final response has gone to it.
    pub fn overdue(&self, now: Instant) -> bool {
        !self.finished
            && self
                .unacknowledged
                .as_ref()
                .is_some_and(|pending| now.saturating_duration_since(pending.sent_at) >= PRACK_WAIT)
    }

    /// The `RSeq` of the provisional awaiting its PRACK.
    pub fn unacknowledged_rseq(&self) -> Option<u32> {
        self.unacknowledged.as_ref().map(|pending| pending.rseq)
    }

    /// Whether the caller's 2xx is ready but held for a PRACK, so the caller has
    /// had no final response yet.
    pub fn holds_answer(&self) -> bool {
        self.held_answer.is_some()
    }
}

impl Drop for ALegReliableProvisionals {
    /// A call removed with a reliable provisional unacknowledged, however it
    /// ended, stops its retransmissions.
    fn drop(&mut self) {
        if let Some(pending) = &self.unacknowledged {
            pending.stop.notify_one();
        }
    }
}

/// The first `RSeq` on a dialog: in 1..=2**30, leaving the numbering room to
/// grow by one per provisional without reaching the 2**31 - 1 ceiling.
fn initial_rseq() -> u32 {
    (crate::sip::headers::rseq::next_rseq() & 0x3FFF_FFFF).max(1)
}

fn cseq_number(response: &SipMessage) -> Option<u32> {
    response
        .headers
        .cseq()
        .and_then(|cseq| cseq.split_whitespace().next())
        .and_then(|number| number.parse().ok())
}

/// Whether a provisional carries a session description, which the 2xx must not
/// overtake. Any body counts: a provisional's body is SDP in practice, and
/// holding a 2xx for one that was not only delays the answer by a PRACK.
pub fn carries_session_description(response: &SipMessage) -> bool {
    !response.body.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provisional(status_code: u16, sdp: bool) -> SipMessage {
        let body = if sdp { "v=0\r\n" } else { "" };
        let raw = format!(
            concat!(
                "SIP/2.0 {status_code} Progress\r\n",
                "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-reliable\r\n",
                "From: <sip:15550100001@caller.example.com>;tag=caller-tag\r\n",
                "To: <sip:15550100042@siphon.example.com>;tag=siphon-tag\r\n",
                "Call-ID: reliable@192.0.2.10\r\n",
                "CSeq: 7 INVITE\r\n",
                "Content-Length: {length}\r\n",
                "\r\n",
                "{body}",
            ),
            status_code = status_code,
            length = body.len(),
            body = body,
        );
        crate::sip::parser::parse_sip_message_bytes(raw.as_bytes()).expect("the fixture parses")
    }

    fn answer() -> Box<HeldAnswer> {
        Box::new(HeldAnswer {
            response: provisional(200, true),
            relayed: false,
            deferred_refer: None,
        })
    }

    fn sent(offered: Offered) -> ProvisionalSend {
        match offered {
            Offered::Send(send) => send,
            other => panic!("expected a send, got {other:?}"),
        }
    }

    #[test]
    fn reliability_follows_the_callers_require_or_its_support_with_the_callees_choice_or_sdp() {
        assert!(sends_reliably(true, false, false, false));
        assert!(sends_reliably(true, true, false, false));
        assert!(sends_reliably(false, true, true, false));
        assert!(sends_reliably(false, true, false, true));
        assert!(!sends_reliably(false, true, false, false));
        assert!(!sends_reliably(false, false, true, true));
    }

    #[test]
    fn a_second_reliable_provisional_queues_and_takes_the_next_rseq_on_the_prack() {
        let now = Instant::now();
        let mut state = ALegReliableProvisionals::default();
        let first = sent(state.offer(provisional(180, false), true, None, now));
        let rseq = first.rseq.expect("reliable");
        assert!((1..=0x3FFF_FFFF).contains(&rseq));
        assert!(matches!(
            state.offer(provisional(183, true), true, None, now),
            Offered::Queued
        ));

        match state.acknowledge(rseq, 7, now) {
            PrackOutcome::Acknowledged {
                rseq: acknowledged,
                release,
                answer,
                ..
            } => {
                assert_eq!(acknowledged, rseq);
                assert_eq!(release.len(), 1);
                assert_eq!(release[0].rseq, Some(rseq + 1));
                assert!(answer.is_none());
            }
            other => panic!("expected the 180 acknowledged, got {other:?}"),
        }
        assert_eq!(state.unacknowledged_rseq(), Some(rseq + 1));
    }

    #[test]
    fn an_unreliable_provisional_goes_out_beside_an_unacknowledged_one_but_not_past_the_queue() {
        let now = Instant::now();
        let mut state = ALegReliableProvisionals::default();
        let first = sent(state.offer(provisional(183, true), true, None, now));
        let unreliable = sent(state.offer(provisional(180, false), false, None, now));
        assert!(unreliable.rseq.is_none());
        assert!(matches!(
            state.offer(provisional(183, true), true, None, now),
            Offered::Queued
        ));
        assert!(matches!(
            state.offer(provisional(180, false), false, None, now),
            Offered::Queued
        ));

        let rseq = first.rseq.expect("reliable");
        match state.acknowledge(rseq, 7, now) {
            PrackOutcome::Acknowledged { release, .. } => {
                assert_eq!(
                    release.len(),
                    1,
                    "up to and including the next reliable one"
                );
                assert_eq!(release[0].rseq, Some(rseq + 1));
            }
            other => panic!("expected an acknowledgement, got {other:?}"),
        }
        match state.acknowledge(rseq + 1, 7, now) {
            PrackOutcome::Acknowledged { release, .. } => {
                assert_eq!(release.len(), 1);
                assert!(release[0].rseq.is_none(), "the queued 180 stays unreliable");
            }
            other => panic!("expected an acknowledgement, got {other:?}"),
        }
    }

    #[test]
    fn a_prack_is_matched_on_its_rseq_and_the_invite_cseq() {
        let now = Instant::now();
        let mut state = ALegReliableProvisionals::default();
        let rseq = sent(state.offer(provisional(183, true), true, None, now))
            .rseq
            .expect("reliable");
        assert!(matches!(
            state.acknowledge(rseq + 1, 7, now),
            PrackOutcome::Unmatched
        ));
        assert!(matches!(
            state.acknowledge(rseq, 8, now),
            PrackOutcome::Unmatched
        ));
        assert!(matches!(
            state.acknowledge(rseq, 7, now),
            PrackOutcome::Acknowledged { .. }
        ));
        assert!(matches!(
            state.acknowledge(rseq, 7, now),
            PrackOutcome::AlreadyAcknowledged
        ));
        assert!(matches!(
            state.acknowledge(rseq.saturating_sub(1).max(1), 7, now),
            PrackOutcome::Unmatched | PrackOutcome::AlreadyAcknowledged
        ));
    }

    #[test]
    fn the_answer_waits_for_the_prack_of_a_provisional_with_sdp_only() {
        let now = Instant::now();
        let mut state = ALegReliableProvisionals::default();
        let rseq = sent(state.offer(provisional(183, true), true, None, now))
            .rseq
            .expect("reliable");
        assert!(matches!(state.answer(answer()), AnswerStep::Held));
        match state.acknowledge(rseq, 7, now) {
            PrackOutcome::Acknowledged { answer, .. } => assert!(answer.is_some()),
            other => panic!("expected the answer released, got {other:?}"),
        }

        let mut state = ALegReliableProvisionals::default();
        sent(state.offer(provisional(180, false), true, None, now));
        assert!(matches!(state.answer(answer()), AnswerStep::Send(_)));
    }

    #[test]
    fn the_answer_waits_behind_a_queued_provisional() {
        let now = Instant::now();
        let mut state = ALegReliableProvisionals::default();
        let rseq = sent(state.offer(provisional(180, false), true, None, now))
            .rseq
            .expect("reliable");
        state.offer(provisional(183, true), true, None, now);
        assert!(matches!(state.answer(answer()), AnswerStep::Held));
        match state.acknowledge(rseq, 7, now) {
            PrackOutcome::Acknowledged {
                answer, release, ..
            } => {
                assert_eq!(release.len(), 1);
                assert!(answer.is_none(), "the released 183 carries SDP");
            }
            other => panic!("expected an acknowledgement, got {other:?}"),
        }
        match state.acknowledge(rseq + 1, 7, now) {
            PrackOutcome::Acknowledged { answer, .. } => assert!(answer.is_some()),
            other => panic!("expected the answer released, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_final_response_stops_the_retransmits_and_drops_what_waited() {
        let now = Instant::now();
        let mut state = ALegReliableProvisionals::default();
        let first = sent(state.offer(provisional(183, true), true, None, now));
        state.offer(provisional(180, false), true, None, now);
        assert!(matches!(state.answer(answer()), AnswerStep::Held));

        assert!(state.finish().is_some(), "the held 2xx comes back");
        let stop = first.stop.expect("a reliable provisional has a stop");
        tokio::time::timeout(Duration::from_millis(50), stop.notified())
            .await
            .expect("the retransmits were told to stop");
        assert!(matches!(
            state.offer(provisional(180, false), false, None, now),
            Offered::AfterFinal
        ));
        let rseq = first.rseq.expect("reliable");
        assert!(matches!(
            state.acknowledge(rseq, 7, now),
            PrackOutcome::Acknowledged { ref release, answer: None, .. } if release.is_empty()
        ));
    }

    #[test]
    fn a_provisional_is_overdue_after_64_t1_without_its_prack() {
        let now = Instant::now();
        let mut state = ALegReliableProvisionals::default();
        assert!(!state.overdue(now + PRACK_WAIT));
        sent(state.offer(provisional(183, true), true, None, now));
        assert!(!state.overdue(now + PRACK_WAIT - Duration::from_millis(1)));
        assert!(state.overdue(now + PRACK_WAIT));
        state.finish();
        assert!(!state.overdue(now + PRACK_WAIT));
    }

    #[test]
    fn the_link_a_provisional_carries_comes_back_with_its_prack_even_after_queueing() {
        let now = Instant::now();
        let mut state = ALegReliableProvisionals::default();
        let first = sent(state.offer(provisional(180, false), true, Some(1), now));
        assert!(matches!(
            state.offer(provisional(183, true), true, Some(2), now),
            Offered::Queued
        ));
        let rseq = first.rseq.expect("reliable");
        match state.acknowledge(rseq, 7, now) {
            PrackOutcome::Acknowledged { link, .. } => assert_eq!(link, Some(1)),
            other => panic!("expected an acknowledgement, got {other:?}"),
        }
        match state.acknowledge(rseq + 1, 7, now) {
            PrackOutcome::Acknowledged { link, .. } => assert_eq!(link, Some(2)),
            other => panic!("expected an acknowledgement, got {other:?}"),
        }
    }

    #[test]
    fn an_offer_to_an_offerless_caller_comes_back_only_for_the_prack_of_its_provisional() {
        let mut state = ALegReliableProvisionals::default();
        state.note_offer_to_caller(7, b"offer".to_vec());
        state.note_offer_to_caller(8, b"later sdp".to_vec());
        assert_eq!(state.take_answered_offer(8), None, "only the first counts");
        assert_eq!(state.take_answered_offer(7), Some(b"offer".to_vec()));
        assert_eq!(state.take_answered_offer(7), None, "taken once");
        state.note_offer_to_caller(9, b"again".to_vec());
        assert_eq!(state.take_answered_offer(9), None, "one offer per call");
    }

    #[tokio::test]
    async fn dropping_the_state_stops_the_retransmits() {
        let mut state = ALegReliableProvisionals::default();
        let first = sent(state.offer(provisional(183, true), true, None, Instant::now()));
        drop(state);
        let stop = first.stop.expect("a reliable provisional has a stop");
        tokio::time::timeout(Duration::from_millis(50), stop.notified())
            .await
            .expect("the retransmits were told to stop");
    }
}
