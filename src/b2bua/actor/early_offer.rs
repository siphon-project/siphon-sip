//! An offer in an UPDATE on a call nobody has answered (RFC 3311 §5).
//!
//! Before the 2xx a call has two early dialogs that share one media session:
//! the caller's, where siphon is the UAS, and the callee's, where siphon is the
//! UAC. An UPDATE carrying an offer may cross from one to the other only when
//! both would let a single user agent send or take it:
//!
//! * the INVITE's own offer/answer exchange is complete on both dialogs. The
//!   answer has to have gone in a reliable provisional response that was
//!   acknowledged, or in the PRACK of one that carried the offer (RFC 3311 §5.1,
//!   RFC 3262 §5). SDP in an unreliable provisional completes nothing;
//! * no other offer is in flight in either direction (RFC 3264 §4: one exchange
//!   at a time).
//!
//! What the UPDATE gets otherwise is RFC 3311 §5.2's to say. An offer that
//! arrives while siphon still owes that party an answer, or before siphon has
//! finished answering an earlier UPDATE of that party's, "MUST" be refused "with
//! a 500 response" and "a Retry-After header field with a randomly chosen value
//! between 0 and 10 seconds". One that arrives while siphon has an offer of its
//! own unanswered on that dialog "MUST" be refused "with a 491 response". An
//! offer the other dialog cannot carry yet is none of siphon's own offers
//! crossing, and will be takeable once that dialog catches up, so it is asked
//! for again the same way: 500 with a Retry-After.
//!
//! Pure state: the dispatcher answers or relays what this decides.

use super::{CallActor, CallState, Leg};

/// The Via-less marker of a tracking leg for an UPDATE relayed from the caller
/// to the callee, and the other way.
const CALLER_UPDATE_IN_FLIGHT: &str = "update:a2b";
const CALLEE_UPDATE_IN_FLIGHT: &str = "update:b2a";

/// Where the INVITE's own offer/answer exchange stands on one early dialog, as
/// siphon sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitialExchange {
    /// The answer went in a reliable provisional that was acknowledged, or in
    /// the PRACK of one that carried the offer: a new offer may follow in an
    /// UPDATE (RFC 3311 §5.1).
    Complete,
    /// siphon holds an offer of the other party's on this dialog, or expects
    /// one, and has not answered it in a message that party acknowledged.
    SiphonOwesAnswer,
    /// siphon's own offer on this dialog has no answer yet.
    SiphonAwaitsAnswer,
}

/// The offers and answers of a call nobody has answered, as an UPDATE carrying
/// an offer finds them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EarlyOfferState {
    /// The dialog the UPDATE arrived on, where siphon is its UAS.
    pub offerer_dialog: InitialExchange,
    /// The dialog the offer would cross to. `None` when no single dialog of the
    /// other party's holds the session the offerer has: none answered yet, or
    /// several did.
    pub relay_dialog: Option<InitialExchange>,
    /// An earlier offer of the same party's, in an UPDATE or a PRACK, has no
    /// answer yet.
    pub offerer_offer_pending: bool,
    /// An offer of the other party's is with the offerer, relayed by siphon on
    /// the dialog the UPDATE arrived on, and has no answer yet.
    pub crossing_offer_pending: bool,
}

/// What an UPDATE carrying an offer on a call nobody has answered comes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EarlyOffer {
    /// It crosses to the other party.
    Relay,
    /// It is refused on the dialog it arrived on, and the session stays as it
    /// was (RFC 3311 §5.3).
    Refuse {
        status: u16,
        /// Whether the refusal carries a `Retry-After` of 0 to 10 seconds
        /// (RFC 3311 §5.2).
        retry_after: bool,
        why: &'static str,
    },
}

impl EarlyOfferState {
    /// Decide by RFC 3311 §5.2, in its order: the offerer's own unfinished
    /// offer, an offer of siphon's crossing it, the INVITE's exchange on the
    /// offerer's dialog, and last whether the other dialog can carry it (§5.1).
    pub fn decide(&self) -> EarlyOffer {
        if self.offerer_offer_pending {
            return EarlyOffer::Refuse {
                status: 500,
                retry_after: true,
                why: "an earlier offer of the same party's has no answer yet",
            };
        }
        if self.crossing_offer_pending {
            return EarlyOffer::Refuse {
                status: 491,
                retry_after: false,
                why: "an offer of the other party's is with the offerer and has no answer yet",
            };
        }
        match self.offerer_dialog {
            InitialExchange::Complete => {}
            InitialExchange::SiphonOwesAnswer => {
                return EarlyOffer::Refuse {
                    status: 500,
                    retry_after: true,
                    why: "the offerer has no acknowledged answer to the first offer on its dialog yet",
                };
            }
            InitialExchange::SiphonAwaitsAnswer => {
                return EarlyOffer::Refuse {
                    status: 491,
                    retry_after: false,
                    why: "the offer on the offerer's own dialog has no answer yet",
                };
            }
        }
        match self.relay_dialog {
            Some(InitialExchange::Complete) => EarlyOffer::Relay,
            _ => EarlyOffer::Refuse {
                status: 500,
                retry_after: true,
                why: "the other party's dialog cannot carry an offer yet",
            },
        }
    }
}

impl CallActor {
    /// Whether the call's INVITE is still pending between the caller and at
    /// least one callee siphon dialled: nobody has answered, and an in-dialog
    /// request from either is on an early dialog.
    pub fn is_early_between_parties(&self) -> bool {
        self.state != CallState::Answered
            && self.winner.is_none()
            && self.b_legs.iter().any(|leg| !leg.is_tracking_leg())
    }

    /// Whether the leg an in-dialog request arrived on moves to the flow the
    /// request arrived on (RFC 5626 §5.3): only once the INVITE that opened the
    /// leg's dialog has had its final response.
    ///
    /// Until then the leg's transport is that INVITE's own. The caller's is
    /// where every response to its INVITE goes, the source the INVITE came from
    /// (RFC 3261 §18.2.2), and a request on the early dialog is another
    /// transaction that may arrive from another hop. The caller has no final
    /// response while nobody has answered or its 2xx is held for a PRACK
    /// (RFC 3262 §3). A callee's is where siphon sent its INVITE, which the
    /// CANCEL of that INVITE follows (RFC 3261 §9.1), until the callee wins.
    pub fn in_dialog_request_moves_flow(&self, from_a_leg: bool) -> bool {
        if !from_a_leg {
            return self.winner.is_some();
        }
        if self.originated {
            return self.state == CallState::Answered;
        }
        self.a_leg_reliability.finished() && !self.prack_bridge.holds_answer()
    }

    /// The one callee leg whose early dialog shares the caller's session before
    /// anybody has answered: the only pending branch that completed the
    /// INVITE's offer/answer exchange and whose session description the caller
    /// was sent. `None` once a leg has won, when no branch got that far, and
    /// when several did, since the caller's one early dialog cannot then be
    /// paired with any of them.
    pub fn early_bridged_b_leg(&self) -> Option<usize> {
        if self.winner.is_some() {
            return None;
        }
        let mut complete = (0..self.b_legs.len()).filter(|&index| {
            self.is_pending_branch(index)
                && self.b_legs[index].early_exchange_complete
                && self.b_legs[index].early_answer_sent.is_some()
        });
        let first = complete.next()?;
        complete.next().is_none().then_some(first)
    }

    /// The callee leg an in-dialog request of the caller's crosses to: the
    /// winner, and before anybody has answered the leg
    /// [`early_bridged_b_leg`](Self::early_bridged_b_leg) names.
    pub fn bridged_b_leg_index(&self) -> Option<usize> {
        self.winner.or_else(|| self.early_bridged_b_leg())
    }

    /// The pending callee leg an in-dialog request arrived on before anybody
    /// has answered, by its dialog's Call-ID and, once the leg has learned it,
    /// the callee's tag in the request's From (RFC 3261 §12.2.2).
    pub fn early_request_leg(&self, sip_call_id: &str, from_tag: Option<&str>) -> Option<usize> {
        if self.winner.is_some() {
            return None;
        }
        (0..self.b_legs.len()).find(|&index| {
            let dialog = &self.b_legs[index].dialog;
            self.is_pending_branch(index)
                && dialog.call_id == sip_call_id
                && (dialog.remote_tag.is_none() || dialog.remote_tag.as_deref() == from_tag)
        })
    }

    /// The offers and answers of this call as an UPDATE carrying an offer finds
    /// them: from the callee leg at `origin`, or from the caller when `None`.
    pub fn early_offer_state(&self, origin: Option<usize>) -> EarlyOfferState {
        let bridged = self.early_bridged_b_leg();
        let caller_offer_pending =
            self.prack_bridge.offer_pending() || self.update_in_flight(CALLER_UPDATE_IN_FLIGHT);
        let callee_offer_pending = self.update_in_flight(CALLEE_UPDATE_IN_FLIGHT);
        match origin {
            None => EarlyOfferState {
                offerer_dialog: self.caller_exchange(),
                relay_dialog: bridged
                    .and_then(|index| self.b_legs.get(index))
                    .map(callee_exchange),
                offerer_offer_pending: caller_offer_pending,
                crossing_offer_pending: callee_offer_pending,
            },
            Some(origin) => EarlyOfferState {
                offerer_dialog: self
                    .b_legs
                    .get(origin)
                    .map_or(InitialExchange::SiphonAwaitsAnswer, callee_exchange),
                relay_dialog: (bridged == Some(origin)).then(|| self.caller_exchange()),
                offerer_offer_pending: callee_offer_pending,
                crossing_offer_pending: caller_offer_pending,
            },
        }
    }

    /// The INVITE's exchange on the caller's dialog. The caller offered in its
    /// INVITE and siphon owes the answer until the caller has PRACKed the
    /// reliable provisional that carried it; to an INVITE without SDP siphon
    /// offers in a reliable provisional and awaits the answer in its PRACK.
    fn caller_exchange(&self) -> InitialExchange {
        if self.a_leg_reliability.answer_acknowledged() {
            InitialExchange::Complete
        } else if self.a_leg_reliability.awaits_answer() {
            InitialExchange::SiphonAwaitsAnswer
        } else {
            InitialExchange::SiphonOwesAnswer
        }
    }

    /// Whether an UPDATE siphon relayed in the direction `marker` names has had
    /// no final response yet.
    fn update_in_flight(&self, marker: &str) -> bool {
        self.b_legs
            .iter()
            .any(|leg| leg.dialog.target_uri.as_deref() == Some(marker))
    }
}

/// The INVITE's exchange on a callee's dialog: complete once siphon has PRACKed
/// the reliable provisional that carried the callee's session description.
/// Until then siphon awaits the answer to the offer in its INVITE, or owes one
/// to the offer the callee is to make to an INVITE that carried none.
fn callee_exchange(leg: &Leg) -> InitialExchange {
    if leg.early_exchange_complete {
        return InitialExchange::Complete;
    }
    let invite_offered = leg
        .b_leg_invite
        .as_ref()
        .and_then(|invite| invite.lock().ok().map(|invite| !invite.body.is_empty()))
        .unwrap_or(true);
    if invite_offered {
        InitialExchange::SiphonAwaitsAnswer
    } else {
        InitialExchange::SiphonOwesAnswer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::b2bua::actor::{LegSide, TransportInfo};
    use crate::transport::{ConnectionId, Transport};

    fn transport(address: &str) -> TransportInfo {
        TransportInfo {
            remote_addr: address.parse().expect("a literal address"),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        }
    }

    /// A caller's call with `callees` pending callee legs, each on a dialog of
    /// its own.
    fn ringing(callees: usize) -> CallActor {
        let mut call = CallActor::new(Leg::new_a_leg(
            "caller-dialog@192.0.2.10".to_string(),
            "caller-tag".to_string(),
            "z9hG4bK-caller".to_string(),
            transport("192.0.2.10:5060"),
        ));
        for index in 0..callees {
            call.add_b_leg(Leg::new_b_leg(
                format!("callee-dialog-{index}@192.0.2.1"),
                format!("siphon-tag-{index}"),
                format!("sip:callee{index}@198.51.100.7"),
                format!("z9hG4bK-callee-{index}"),
                transport("198.51.100.7:5060"),
            ));
        }
        call
    }

    /// The callee at `index` answered reliably, siphon PRACKed it, and the
    /// caller was sent its session description.
    fn answer_reliably(call: &mut CallActor, index: usize) {
        let leg = &mut call.b_legs[index];
        leg.dialog.remote_tag = Some(format!("callee-tag-{index}"));
        leg.early_exchange_complete = true;
        leg.early_answer_sent = Some(b"v=0\r\n".to_vec());
    }

    fn update_in_flight(call: &mut CallActor, marker: &str) {
        let mut tracking = Leg::new_b_leg(
            "callee-dialog-0@192.0.2.1".to_string(),
            "siphon-tag-0".to_string(),
            marker.to_string(),
            format!("z9hG4bK-{marker}"),
            transport("198.51.100.7:5060"),
        );
        tracking.offered_sdp = Some(b"v=0\r\n".to_vec());
        call.add_b_leg(tracking);
    }

    #[test]
    fn the_callee_that_answered_reliably_is_the_callers_other_party() {
        let mut call = ringing(2);
        assert!(call.is_early_between_parties());
        assert_eq!(call.early_bridged_b_leg(), None, "nobody answered yet");
        assert_eq!(call.bridged_b_leg_index(), None);

        answer_reliably(&mut call, 1);
        assert_eq!(call.early_bridged_b_leg(), Some(1));
        assert_eq!(call.bridged_b_leg_index(), Some(1));

        // A second one makes the caller's single early dialog ambiguous.
        answer_reliably(&mut call, 0);
        assert_eq!(call.early_bridged_b_leg(), None);
    }

    #[test]
    fn a_callee_that_ended_or_a_call_that_is_answered_has_no_early_party() {
        let mut call = ringing(1);
        answer_reliably(&mut call, 0);
        call.mark_b_leg_failed(0, 480);
        assert_eq!(call.early_bridged_b_leg(), None, "its INVITE is over");

        let mut call = ringing(1);
        answer_reliably(&mut call, 0);
        call.set_winner(0);
        assert_eq!(call.early_bridged_b_leg(), None);
        assert_eq!(call.bridged_b_leg_index(), Some(0), "the winner");
        assert!(!call.is_early_between_parties());
    }

    #[test]
    fn a_call_without_a_callee_is_not_early_between_parties() {
        let mut call = ringing(0);
        assert!(!call.is_early_between_parties());
        update_in_flight(&mut call, CALLER_UPDATE_IN_FLIGHT);
        assert!(
            !call.is_early_between_parties(),
            "a tracking leg is no callee"
        );
    }

    #[test]
    fn a_request_names_the_callees_early_dialog_by_call_id_and_tag() {
        let mut call = ringing(2);
        assert_eq!(
            call.early_request_leg("callee-dialog-1@192.0.2.1", Some("any-tag")),
            Some(1),
            "a dialog whose tag siphon has not learned matches on its Call-ID"
        );
        answer_reliably(&mut call, 1);
        assert_eq!(
            call.early_request_leg("callee-dialog-1@192.0.2.1", Some("callee-tag-1")),
            Some(1)
        );
        assert_eq!(
            call.early_request_leg("callee-dialog-1@192.0.2.1", Some("another-tag")),
            None,
            "another early dialog on the same INVITE"
        );
        assert_eq!(call.early_request_leg("unknown@192.0.2.1", None), None);
        call.set_winner(1);
        assert_eq!(
            call.early_request_leg("callee-dialog-1@192.0.2.1", Some("callee-tag-1")),
            None,
            "the dialog is confirmed"
        );
    }

    /// A callee leg dialled with the caller's Call-ID is told from the caller's
    /// by its tag before anybody has answered.
    #[test]
    fn a_callees_early_request_on_the_callers_call_id_is_told_by_its_tag() {
        let mut call = ringing(1);
        call.b_legs[0].dialog.call_id = "caller-dialog@192.0.2.10".to_string();
        answer_reliably(&mut call, 0);
        assert_eq!(
            call.request_direction("caller-dialog@192.0.2.10", Some("callee-tag-0")),
            Some(LegSide::B)
        );
        assert_eq!(
            call.request_direction("caller-dialog@192.0.2.10", Some("caller-tag")),
            Some(LegSide::A)
        );
        assert_eq!(
            call.request_direction("caller-dialog@192.0.2.10", None),
            Some(LegSide::A)
        );
    }

    #[test]
    fn the_callers_offer_waits_for_its_own_answer_and_then_for_the_callees() {
        let mut call = ringing(1);
        let state = call.early_offer_state(None);
        assert_eq!(state.offerer_dialog, InitialExchange::SiphonOwesAnswer);
        assert_eq!(state.relay_dialog, None);
        assert_eq!(refusal(state.decide()), (500, true));

        answer_reliably(&mut call, 0);
        let state = call.early_offer_state(None);
        assert_eq!(state.relay_dialog, Some(InitialExchange::Complete));
        assert_eq!(
            refusal(state.decide()),
            (500, true),
            "the caller has not acknowledged its answer"
        );
    }

    #[test]
    fn a_callees_offer_crosses_the_one_in_siphons_invite_until_it_answered() {
        let mut call = ringing(2);
        let state = call.early_offer_state(Some(0));
        assert_eq!(state.offerer_dialog, InitialExchange::SiphonAwaitsAnswer);
        assert_eq!(refusal(state.decide()), (491, false));

        // The other callee answered: this one is not the caller's other party.
        answer_reliably(&mut call, 1);
        call.b_legs[0].early_exchange_complete = true;
        let state = call.early_offer_state(Some(0));
        assert_eq!(state.offerer_dialog, InitialExchange::Complete);
        assert_eq!(state.relay_dialog, None);
        assert_eq!(refusal(state.decide()), (500, true));
    }

    #[test]
    fn an_update_in_flight_is_the_same_partys_or_a_crossing_one() {
        let mut call = ringing(1);
        answer_reliably(&mut call, 0);
        update_in_flight(&mut call, CALLER_UPDATE_IN_FLIGHT);
        let from_caller = call.early_offer_state(None);
        assert!(from_caller.offerer_offer_pending);
        assert!(!from_caller.crossing_offer_pending);
        let from_callee = call.early_offer_state(Some(0));
        assert!(!from_callee.offerer_offer_pending);
        assert!(from_callee.crossing_offer_pending);
        assert_eq!(refusal(from_callee.decide()), (491, false));

        let mut call = ringing(1);
        answer_reliably(&mut call, 0);
        update_in_flight(&mut call, CALLEE_UPDATE_IN_FLIGHT);
        assert!(call.early_offer_state(None).crossing_offer_pending);
        assert!(call.early_offer_state(Some(0)).offerer_offer_pending);
        assert_eq!(
            call.early_bridged_b_leg(),
            Some(0),
            "a tracking leg is no callee"
        );
    }

    fn state(
        offerer_dialog: InitialExchange,
        relay_dialog: Option<InitialExchange>,
        offerer_offer_pending: bool,
        crossing_offer_pending: bool,
    ) -> EarlyOfferState {
        EarlyOfferState {
            offerer_dialog,
            relay_dialog,
            offerer_offer_pending,
            crossing_offer_pending,
        }
    }

    fn refusal(decision: EarlyOffer) -> (u16, bool) {
        match decision {
            EarlyOffer::Refuse {
                status,
                retry_after,
                ..
            } => (status, retry_after),
            EarlyOffer::Relay => panic!("relayed"),
        }
    }

    #[test]
    fn an_offer_crosses_once_both_exchanges_are_complete_and_none_is_in_flight() {
        let complete = InitialExchange::Complete;
        assert_eq!(
            state(complete, Some(complete), false, false).decide(),
            EarlyOffer::Relay
        );
    }

    #[test]
    fn an_offer_before_the_offerers_own_answer_is_refused_500_with_retry_after() {
        let decision = state(
            InitialExchange::SiphonOwesAnswer,
            Some(InitialExchange::Complete),
            false,
            false,
        )
        .decide();
        assert_eq!(refusal(decision), (500, true));
    }

    #[test]
    fn an_offer_crossing_siphons_own_on_the_dialog_is_refused_491() {
        let decision = state(
            InitialExchange::SiphonAwaitsAnswer,
            Some(InitialExchange::Complete),
            false,
            false,
        )
        .decide();
        assert_eq!(refusal(decision), (491, false));
    }

    #[test]
    fn a_second_offer_of_the_same_party_is_refused_500_with_retry_after() {
        let complete = InitialExchange::Complete;
        let decision = state(complete, Some(complete), true, false).decide();
        assert_eq!(refusal(decision), (500, true));
        // The earlier offer decides, whatever else is true.
        let decision = state(complete, Some(complete), true, true).decide();
        assert_eq!(refusal(decision), (500, true));
    }

    #[test]
    fn an_offer_crossing_the_other_partys_is_refused_491() {
        let complete = InitialExchange::Complete;
        let decision = state(complete, Some(complete), false, true).decide();
        assert_eq!(refusal(decision), (491, false));
    }

    #[test]
    fn an_offer_the_other_dialog_cannot_carry_is_refused_500_with_retry_after() {
        let complete = InitialExchange::Complete;
        for relay_dialog in [
            None,
            Some(InitialExchange::SiphonAwaitsAnswer),
            Some(InitialExchange::SiphonOwesAnswer),
        ] {
            let decision = state(complete, relay_dialog, false, false).decide();
            assert_eq!(refusal(decision), (500, true), "{relay_dialog:?}");
        }
    }

    #[test]
    fn the_offerers_own_dialog_is_judged_before_the_other_one() {
        let decision = state(InitialExchange::SiphonAwaitsAnswer, None, false, false).decide();
        assert_eq!(refusal(decision), (491, false));
    }
}
