//! RFC 3262 §5 across the B2BUA: offer and answer in PRACK.
//!
//! siphon PRACKs a callee's reliable provisional on the B-leg itself, but when
//! the provisional reaches the caller reliably that PRACK waits for the caller's
//! PRACK of siphon's copy. Whatever the caller's PRACK carries then crosses on
//! siphon's: the answer to an offer the callee made in the provisional, or a new
//! offer from the caller, whose answer comes back in the 200 to siphon's PRACK
//! and goes on in the 200 to the caller's.
//!
//! Pure state, one per call: the dispatcher sends what this decides.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::HeldAnswer;
use crate::sip::message::SipMessage;
use crate::transport::{ConnectionId, Transport};

/// How long siphon waits for the callee to answer an offer its PRACK carried
/// before the call fails: 64*T1, a non-INVITE transaction's Timer F.
pub const PRACK_OFFER_WAIT: Duration = Duration::from_secs(32);

/// siphon's PRACK for a callee's reliable provisional, waiting for the caller's
/// PRACK of siphon's copy.
#[derive(Debug, Clone)]
pub struct HeldCalleePrack {
    pub b_leg_index: usize,
    /// The callee's early dialog, by its To-tag.
    pub to_tag: String,
    /// The callee's `RSeq`, which the PRACK's `RAck` names.
    pub rseq: u32,
    /// The INVITE's CSeq number and method, which the `RAck` names too.
    pub cseq_number: u32,
    pub cseq_method: String,
    /// The early dialog's remote target and route set, off the provisional
    /// (RFC 3261 §12.1.2).
    pub remote_contact: Option<String>,
    pub to_header: Option<String>,
    pub route_set: Vec<String>,
    /// The callee's offer, when the INVITE siphon sent it carried none: the
    /// caller's PRACK has to answer it (RFC 3262 §5).
    pub offer: Option<Vec<u8>>,
}

/// Where a request from the caller came from, so its response goes back there.
#[derive(Debug, Clone, Copy)]
pub struct RequestSource {
    pub transport: Transport,
    pub remote_addr: SocketAddr,
    pub connection_id: ConnectionId,
    pub local_addr: SocketAddr,
}

/// An offer from the caller's PRACK, sent to the callee in siphon's PRACK and
/// waiting for its answer.
#[derive(Debug, Clone)]
pub struct PendingPrackOffer {
    /// The caller's PRACK, which the 200 carrying the answer responds to.
    pub caller_prack: SipMessage,
    pub source: RequestSource,
    /// siphon's `RSeq` that PRACK acknowledged: a retransmission of it names it.
    pub a_leg_rseq: u32,
    /// siphon's PRACK on the callee's dialog: that dialog's Call-ID and the
    /// PRACK's CSeq number, which the callee's response echoes.
    pub b_leg_call_id: String,
    pub b_leg_cseq: u32,
    /// The callee's leg, and the offer as siphon's PRACK carried it there: the
    /// session description in force on that dialog once the callee answers it.
    pub b_leg_index: usize,
    pub sent_offer: Option<Vec<u8>>,
    /// The caller's offer as it wrote it, for an answer rejecting every stream
    /// should the callee not answer.
    pub offer: Vec<u8>,
    pub sent_at: Instant,
}

/// One call's PRACKs across the legs.
#[derive(Debug, Default)]
pub struct PrackBridge {
    next_link: u64,
    held: Vec<(u64, HeldCalleePrack)>,
    callee_offered: bool,
    pending_offer: Option<PendingPrackOffer>,
    deferred_answer: Option<Box<HeldAnswer>>,
    answered: Option<(u32, SipMessage)>,
    /// The callee answered the caller's offer and the 200 carrying it to the
    /// caller is not on the wire yet.
    answering: bool,
}

impl PrackBridge {
    /// Hold `prack` for the caller's PRACK. `offer` is the provisional's SDP when
    /// the INVITE siphon sent the callee carried none. Returns the link siphon's
    /// copy of the provisional carries to it.
    pub fn hold(&mut self, mut prack: HeldCalleePrack, offer: Option<Vec<u8>>) -> u64 {
        prack.offer = self.offer_from(offer);
        self.next_link += 1;
        let link = self.next_link;
        self.held.push((link, prack));
        link
    }

    /// The callee's offer, from the SDP of a reliable provisional to an offerless
    /// INVITE: only the first such provisional carries it (RFC 3261 §13.2.1), and
    /// SDP in any later one answers nothing.
    pub fn offer_from(&mut self, offer: Option<Vec<u8>>) -> Option<Vec<u8>> {
        if self.callee_offered {
            return None;
        }
        if offer.is_some() {
            self.callee_offered = true;
        }
        offer
    }

    /// The link of the PRACK held for the callee's provisional `rseq` on its early
    /// dialog `to_tag` of B-leg `b_leg_index`.
    pub fn link_for(&self, b_leg_index: usize, to_tag: &str, rseq: u32) -> Option<u64> {
        self.held
            .iter()
            .find(|(_, prack)| {
                prack.b_leg_index == b_leg_index && prack.to_tag == to_tag && prack.rseq == rseq
            })
            .map(|(link, _)| *link)
    }

    /// Take the PRACK held under `link`, to send it.
    pub fn take(&mut self, link: u64) -> Option<HeldCalleePrack> {
        let position = self.held.iter().position(|(held, _)| *held == link)?;
        Some(self.held.remove(position).1)
    }

    /// Take every PRACK still held, to send them without the caller's: once the
    /// caller has its 2xx, siphon no longer retransmits the copies those PRACKs
    /// wait on, so the caller may never PRACK them.
    pub fn take_all(&mut self) -> Vec<HeldCalleePrack> {
        self.held.drain(..).map(|(_, prack)| prack).collect()
    }

    /// The caller's offer is on its way to the callee.
    pub fn begin_offer(&mut self, offer: PendingPrackOffer) {
        self.pending_offer = Some(offer);
    }

    /// Whether the caller's PRACK of siphon's `a_leg_rseq` carried an offer the
    /// callee has not answered yet.
    pub fn offer_waits_on(&self, a_leg_rseq: u32) -> bool {
        self.pending_offer
            .as_ref()
            .is_some_and(|pending| pending.a_leg_rseq == a_leg_rseq)
    }

    /// Whether the pending offer went to the callee in siphon's PRACK `b_leg_cseq`
    /// on the callee's dialog `b_leg_call_id`.
    fn offer_went_in(&self, b_leg_call_id: &str, b_leg_cseq: u32) -> bool {
        self.pending_offer.as_ref().is_some_and(|pending| {
            pending.b_leg_call_id == b_leg_call_id && pending.b_leg_cseq == b_leg_cseq
        })
    }

    /// Take the offer siphon's PRACK `b_leg_cseq` on the callee's dialog
    /// `b_leg_call_id` carried, for the callee's response to that PRACK.
    pub fn take_offer(
        &mut self,
        b_leg_call_id: &str,
        b_leg_cseq: u32,
    ) -> Option<PendingPrackOffer> {
        if self.offer_went_in(b_leg_call_id, b_leg_cseq) {
            self.answering = true;
            self.pending_offer.take()
        } else {
            None
        }
    }

    /// Withdraw the offer registered for siphon's PRACK `b_leg_cseq` on the callee's
    /// dialog `b_leg_call_id` when the transport refused that PRACK: nothing will
    /// answer the offer, and no answer to it is on its way to the caller.
    pub fn withdraw_offer(
        &mut self,
        b_leg_call_id: &str,
        b_leg_cseq: u32,
    ) -> Option<PendingPrackOffer> {
        if self.offer_went_in(b_leg_call_id, b_leg_cseq) {
            self.pending_offer.take()
        } else {
            None
        }
    }

    /// Whether the callee has let the offer go unanswered for 64*T1.
    pub fn offer_overdue(&self, now: Instant) -> bool {
        self.pending_offer.as_ref().is_some_and(|pending| {
            now.saturating_duration_since(pending.sent_at) >= PRACK_OFFER_WAIT
        })
    }

    /// Take the offer when it is overdue.
    pub fn take_overdue_offer(&mut self, now: Instant) -> Option<PendingPrackOffer> {
        if self.offer_overdue(now) {
            self.pending_offer.take()
        } else {
            None
        }
    }

    /// Whether an offer from the caller's PRACK is still with the callee.
    pub fn offer_pending(&self) -> bool {
        self.pending_offer.is_some() || self.answering
    }

    /// The 200 answering the caller's PRACK is on the wire, or will never be:
    /// a 2xx no longer waits, and one that came in meanwhile is handed back.
    pub fn finish_answering(&mut self) -> Option<Box<HeldAnswer>> {
        self.answering = false;
        self.deferred_answer.take()
    }

    /// Whether the caller's 2xx waits here for the 200 answering its PRACK.
    pub fn holds_answer(&self) -> bool {
        self.deferred_answer.is_some()
    }

    /// The caller's 2xx, released by the PRACK whose offer the callee still has:
    /// it follows the 200 that answers that PRACK.
    pub fn defer_answer(&mut self, answer: Box<HeldAnswer>) {
        self.deferred_answer = Some(answer);
    }

    pub fn take_deferred_answer(&mut self) -> Option<Box<HeldAnswer>> {
        self.deferred_answer.take()
    }

    /// The 200 that carried the callee's answer to the caller's PRACK of siphon's
    /// `a_leg_rseq`, kept so a retransmission of that PRACK gets it again (RFC
    /// 3261 §17.2.2).
    pub fn record_answered(&mut self, a_leg_rseq: u32, response: SipMessage) {
        self.answered = Some((a_leg_rseq, response));
    }

    pub fn answered_response(&self, a_leg_rseq: u32) -> Option<SipMessage> {
        self.answered
            .as_ref()
            .filter(|(rseq, _)| *rseq == a_leg_rseq)
            .map(|(_, response)| response.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held(b_leg_index: usize, to_tag: &str, rseq: u32) -> HeldCalleePrack {
        HeldCalleePrack {
            b_leg_index,
            to_tag: to_tag.to_string(),
            rseq,
            cseq_number: 1,
            cseq_method: "INVITE".to_string(),
            remote_contact: None,
            to_header: None,
            route_set: Vec::new(),
            offer: None,
        }
    }

    fn message() -> SipMessage {
        crate::sip::parser::parse_sip_message_bytes(
            concat!(
                "PRACK sip:192.0.2.1:5060 SIP/2.0\r\n",
                "Via: SIP/2.0/UDP 192.0.2.30:5060;branch=z9hG4bK-bridge\r\n",
                "From: <sip:15550100001@caller.example.com>;tag=caller-tag\r\n",
                "To: <sip:15550100042@siphon.example.com>;tag=siphon-tag\r\n",
                "Call-ID: bridge@192.0.2.30\r\n",
                "CSeq: 2 PRACK\r\n",
                "Content-Length: 0\r\n",
                "\r\n",
            )
            .as_bytes(),
        )
        .expect("the fixture parses")
    }

    fn pending(sent_at: Instant) -> PendingPrackOffer {
        PendingPrackOffer {
            caller_prack: message(),
            source: RequestSource {
                transport: Transport::Udp,
                remote_addr: "192.0.2.30:5060".parse().expect("a literal address"),
                connection_id: ConnectionId::default(),
                local_addr: "192.0.2.1:5060".parse().expect("a literal address"),
            },
            a_leg_rseq: 7,
            b_leg_call_id: "b-leg@198.51.100.70".to_string(),
            b_leg_cseq: 3,
            b_leg_index: 0,
            sent_offer: None,
            offer: b"v=0\r\n".to_vec(),
            sent_at,
        }
    }

    #[test]
    fn a_held_prack_is_found_by_its_early_dialog_and_rseq_and_taken_once() {
        let mut bridge = PrackBridge::default();
        let first = bridge.hold(held(0, "callee-a", 42), None);
        let second = bridge.hold(held(0, "callee-b", 42), None);
        assert_ne!(first, second);
        assert_eq!(bridge.link_for(0, "callee-a", 42), Some(first));
        assert_eq!(bridge.link_for(0, "callee-b", 42), Some(second));
        assert_eq!(bridge.link_for(1, "callee-a", 42), None);
        assert_eq!(
            bridge.take(first).map(|prack| prack.to_tag),
            Some("callee-a".to_string())
        );
        assert!(bridge.take(first).is_none());
        assert_eq!(bridge.link_for(0, "callee-a", 42), None);
    }

    #[test]
    fn only_the_first_sdp_on_an_offerless_invite_is_the_callees_offer() {
        let mut bridge = PrackBridge::default();
        let first = bridge.hold(held(0, "callee", 42), Some(b"v=0\r\n".to_vec()));
        let second = bridge.hold(held(0, "callee", 43), Some(b"v=0\r\n".to_vec()));
        assert!(bridge.take(first).and_then(|prack| prack.offer).is_some());
        assert!(bridge.take(second).and_then(|prack| prack.offer).is_none());
        assert!(bridge.offer_from(Some(b"v=0\r\n".to_vec())).is_none());
    }

    #[test]
    fn a_pending_offer_is_matched_on_the_prack_it_went_out_in_and_times_out_at_64_t1() {
        let now = Instant::now();
        let mut bridge = PrackBridge::default();
        assert!(!bridge.offer_pending());
        bridge.begin_offer(pending(now));
        assert!(bridge.offer_pending());
        assert!(bridge.offer_waits_on(7));
        assert!(!bridge.offer_waits_on(8));
        assert!(bridge.take_offer("b-leg@198.51.100.70", 4).is_none());
        assert!(bridge.take_offer("another@198.51.100.70", 3).is_none());
        assert!(!bridge.offer_overdue(now + PRACK_OFFER_WAIT - Duration::from_millis(1)));
        assert!(bridge.take_overdue_offer(now).is_none());
        assert!(bridge.offer_overdue(now + PRACK_OFFER_WAIT));
        assert!(bridge.take_offer("b-leg@198.51.100.70", 3).is_some());
        assert!(!bridge.offer_waits_on(7));
        assert!(
            bridge.offer_pending(),
            "a 2xx still waits for the 200 on its way"
        );
        assert!(bridge.finish_answering().is_none());
        assert!(!bridge.offer_pending());

        bridge.begin_offer(pending(now));
        assert!(bridge.take_overdue_offer(now + PRACK_OFFER_WAIT).is_some());
        assert!(!bridge.offer_overdue(now + PRACK_OFFER_WAIT));
    }

    #[test]
    fn an_offer_whose_prack_the_transport_refused_is_withdrawn_with_nothing_being_answered() {
        let mut bridge = PrackBridge::default();
        bridge.begin_offer(pending(Instant::now()));
        assert!(bridge.withdraw_offer("b-leg@198.51.100.70", 4).is_none());
        assert!(bridge.withdraw_offer("another@198.51.100.70", 3).is_none());
        assert!(bridge.offer_pending());
        assert!(bridge.withdraw_offer("b-leg@198.51.100.70", 3).is_some());
        assert!(
            !bridge.offer_pending(),
            "no 200 is on its way to the caller for a 2xx to wait behind"
        );
        assert!(bridge.take_offer("b-leg@198.51.100.70", 3).is_none());
    }

    #[test]
    fn the_200_that_carried_an_answer_is_kept_for_its_prack_retransmissions() {
        let mut bridge = PrackBridge::default();
        assert!(bridge.answered_response(7).is_none());
        bridge.record_answered(7, message());
        assert!(bridge.answered_response(7).is_some());
        assert!(bridge.answered_response(8).is_none());
    }

    #[test]
    fn take_all_empties_the_held_pracks_and_leaves_their_links_unmatched() {
        let mut bridge = PrackBridge::default();
        let first = bridge.hold(held(0, "callee-a", 42), None);
        bridge.hold(held(1, "callee-b", 7), None);
        let taken: Vec<(usize, u32)> = bridge
            .take_all()
            .into_iter()
            .map(|prack| (prack.b_leg_index, prack.rseq))
            .collect();
        assert_eq!(taken, [(0, 42), (1, 7)]);
        assert!(bridge.take_all().is_empty());
        assert!(bridge.take(first).is_none());
        assert_eq!(bridge.link_for(0, "callee-a", 42), None);
    }
}
