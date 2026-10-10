//! REFER as a server transaction: answered once, and always answered.
//!
//! The B2BUA answers a REFER itself, some time after it arrived: when a script
//! or a controlling application has decided, or when the far end it was
//! relayed to has. Two things follow from that gap.
//!
//! A retransmission can arrive after the decision. It is the same request (RFC
//! 3261 §17.2.3), so it is owed the same final response again (§17.2.2) and
//! must not be decided on a second time: that would report a second transfer
//! request, or dial the target twice. What was sent is remembered per call for
//! the transaction's lifetime, [`AnsweredReferStore`].
//!
//! And the call can end before the decision. A REFER held for an application
//! ([`PendingInboundReferStore`]) is still owed a final response then, and its
//! entry has to go with the call rather than wait for an accept that may never
//! come.

use crate::dispatcher::*;

/// How long a REFER's final response is kept for its retransmissions: 64*T1,
/// the time a non-INVITE server transaction stays in Completed (RFC 3261
/// §17.2.2, Timer J) and the longest its client goes on retransmitting (Timer
/// F).
pub const REFER_TRANSACTION_LIFETIME: std::time::Duration =
    std::time::Duration::from_millis(64 * 500);

/// The most REFER transactions remembered for one call. A party sends one
/// REFER at a time, so this is only ever reached by a peer sending a stream of
/// them; the oldest is then forgotten first.
pub const ANSWERED_REFERS_PER_CALL: usize = 8;

/// One REFER siphon has taken a decision on.
struct AnsweredRefer {
    /// What makes a later request this one again: the dialog's Call-ID, the
    /// CSeq and the top Via branch (RFC 3261 §17.2.3).
    identity: RequestIdentity,
    /// The final response it was answered with. `None` while what answers it
    /// is still on its way: a REFER relayed to the far end, whose response
    /// siphon relays back.
    response: Option<SipMessage>,
    /// When its transaction is over and it is forgotten.
    expires: std::time::Instant,
}

/// The identity a request shares with its retransmissions and its responses.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RequestIdentity {
    sip_call_id: String,
    cseq: String,
    branch: String,
}

impl RequestIdentity {
    /// Read off a request, or off a response to it: a response echoes all
    /// three (RFC 3261 §8.2.6.2). `None` for a message missing any of them.
    fn of(message: &SipMessage) -> Option<Self> {
        Some(Self {
            sip_call_id: message.headers.call_id()?.clone(),
            cseq: message
                .headers
                .cseq()?
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" "),
            branch: top_via_branch(message)?.to_string(),
        })
    }
}

/// What a REFER that arrives again is owed.
pub enum ReferReplay {
    /// Its final response, again.
    Final(Box<SipMessage>),
    /// Nothing yet: the response to the first copy is still on its way and
    /// answers this one too.
    Proceeding,
}

/// Per-call store of the REFERs siphon has decided on, keyed by the
/// `CallActor` id, so a retransmission is answered as the request was.
///
/// New per-call state: an entry is forgotten 64*T1 after it was recorded
/// ([`check_answered_refer_expiry`], on the maintenance tick) and with its
/// call ([`refers_end_with_call`]), and a call never holds more than
/// [`ANSWERED_REFERS_PER_CALL`], so the store drains back to baseline under a
/// completed workload (the classic never-evicted-per-call-entry leak). Covered
/// by the co-located steady-state leak test
/// `answered_refer_store_drains_to_baseline`.
#[derive(Default)]
pub struct AnsweredReferStore {
    entries: DashMap<String, Vec<AnsweredRefer>>,
}

impl AnsweredReferStore {
    /// `request` is being carried out by something that answers it later.
    pub fn proceeding(&self, call_id: &str, request: &SipMessage, now: std::time::Instant) {
        self.record(call_id, request, None, now);
    }

    /// `response` is the final response a REFER on `call_id` was just sent.
    pub fn answered(&self, call_id: &str, response: &SipMessage, now: std::time::Instant) {
        self.record(call_id, response, Some(response.clone()), now);
    }

    fn record(
        &self,
        call_id: &str,
        message: &SipMessage,
        response: Option<SipMessage>,
        now: std::time::Instant,
    ) {
        let Some(identity) = RequestIdentity::of(message) else {
            return;
        };
        let expires = now + REFER_TRANSACTION_LIFETIME;
        let mut answered = self.entries.entry(call_id.to_string()).or_default();
        if let Some(known) = answered.iter_mut().find(|known| known.identity == identity) {
            // A relayed REFER's response arriving, or the same response sent
            // again: the transaction's lifetime runs from its final response.
            if response.is_some() {
                known.response = response;
                known.expires = expires;
            }
            return;
        }
        if answered.len() >= ANSWERED_REFERS_PER_CALL {
            answered.remove(0);
        }
        answered.push(AnsweredRefer {
            identity,
            response,
            expires,
        });
    }

    /// What `request` is owed if it is a REFER on `call_id` already decided
    /// on. `None` for a request seen for the first time. Asked for every REFER
    /// on a tracked call, so it stays cheap when nothing is remembered — the
    /// steady state.
    pub fn replay(
        &self,
        call_id: &str,
        request: &SipMessage,
        now: std::time::Instant,
    ) -> Option<ReferReplay> {
        if self.entries.is_empty() {
            return None;
        }
        let identity = RequestIdentity::of(request)?;
        let answered = self.entries.get(call_id)?;
        let known = answered
            .iter()
            .find(|known| known.identity == identity && known.expires > now)?;
        Some(match &known.response {
            Some(response) => ReferReplay::Final(Box::new(response.clone())),
            None => ReferReplay::Proceeding,
        })
    }

    /// Whether a REFER other than `request` is still being carried out on
    /// `call_id`: handed to a script that has not decided yet, or relayed to
    /// the far end, whose response has not come back. Asked for every new
    /// REFER on a tracked call, so it stays cheap when nothing is remembered.
    pub fn another_proceeding(
        &self,
        call_id: &str,
        request: &SipMessage,
        now: std::time::Instant,
    ) -> bool {
        if self.entries.is_empty() {
            return false;
        }
        let identity = RequestIdentity::of(request);
        self.entries.get(call_id).is_some_and(|answered| {
            answered.iter().any(|known| {
                known.response.is_none()
                    && known.expires > now
                    && Some(&known.identity) != identity.as_ref()
            })
        })
    }

    /// Forget everything remembered for a call that is ending.
    pub fn forget_call(&self, call_id: &str) {
        if self.entries.is_empty() {
            return;
        }
        self.entries.remove(call_id);
    }

    /// Forget every REFER whose transaction is over.
    pub fn forget_expired(&self, now: std::time::Instant) {
        if self.entries.is_empty() {
            return;
        }
        self.entries.retain(|_, answered| {
            answered.retain(|known| known.expires > now);
            !answered.is_empty()
        });
    }

    /// The number of REFERs remembered, over every call (leak-test accessor).
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.iter().map(|answered| answered.len()).sum()
    }
}

/// Forget the REFERs whose transactions are over. Driven from the 500 ms
/// maintenance tick.
pub fn check_answered_refer_expiry(state: &DispatcherState) {
    state
        .answered_refers
        .forget_expired(std::time::Instant::now());
}

/// Answer a REFER that is a retransmission of one already decided on: its
/// final response again, on the flow this copy arrived on, or nothing while
/// that response is still on its way. Returns whether it was one.
pub fn answer_refer_retransmission(
    inbound: &InboundMessage,
    message: &SipMessage,
    call_id: &str,
    state: &DispatcherState,
) -> bool {
    match state
        .answered_refers
        .replay(call_id, message, std::time::Instant::now())
    {
        Some(ReferReplay::Final(response)) => {
            debug!(
                call_id = %call_id,
                status = response.status_code(),
                "B2BUA REFER: retransmission of a REFER already answered — the same response again"
            );
            send_message_from(
                *response,
                inbound.transport,
                inbound.remote_addr,
                inbound.connection_id,
                Some(inbound.local_addr),
                state,
            );
            true
        }
        Some(ReferReplay::Proceeding) => {
            debug!(call_id = %call_id, "B2BUA REFER: retransmission of a REFER whose response is on its way — absorbed");
            true
        }
        None => false,
    }
}

/// Refuse a new REFER that arrives while its call is still carrying out a
/// transfer. Returns whether it was refused.
///
/// A call is re-paired once at a time. While a leg replacement is in flight (a
/// REFER accepted for siphon to carry out, or a `replace_peer`, whose target
/// has neither answered nor failed nor run out of time), and while a REFER
/// relayed to the far end or handed to a script has not been answered, another
/// REFER on the call is refused `491 Request Pending` (RFC 3261 §21.4.27):
/// neither held for an application nor shown to `@b2bua.on_refer`, since
/// accepting it would start a second replacement on the same pair. RFC 3515
/// lets a referrer send several REFERs in a dialog; it does not oblige the
/// recipient to carry them out together, and a `491` asks for it again later.
/// Once the first transfer has concluded a REFER is taken as usual.
///
/// A retransmission of the REFER being carried out is not this: it was
/// answered from [`AnsweredReferStore`] before this is asked.
pub fn refuse_refer_during_transfer(
    inbound: &InboundMessage,
    message: &SipMessage,
    call_id: &str,
    state: &DispatcherState,
) -> bool {
    let replacing = state
        .call_actors
        .get_call(call_id)
        .is_some_and(|call| call.replacement_in_flight());
    let in_flight = replacing
        || state
            .answered_refers
            .another_proceeding(call_id, message, std::time::Instant::now());
    if !in_flight {
        return false;
    }
    warn!(
        call_id = %call_id,
        replacing,
        "B2BUA REFER: another transfer is still being carried out on this call — 491"
    );
    b2bua_refer_send_final(inbound, message, 491, "Request Pending", state);
    true
}

/// Remember the final response `response` to a REFER, for its
/// retransmissions. The call is found by the response's own Call-ID; one that
/// matches no call (a REFER answered `481`) has nothing to be remembered
/// under, and is answered the same way again from scratch.
pub fn remember_refer_response(response: &SipMessage, state: &DispatcherState) {
    let call_id = state.call_actors.find_by_message(response);
    if let Some(call_id) = call_id {
        state
            .answered_refers
            .answered(&call_id, response, std::time::Instant::now());
    }
}

/// The status a REFER held for a decision is answered with when its own
/// sender ends the dialog first: RFC 3261 §15.1.2 has a UAS that receives a
/// BYE still answer the requests pending in that dialog, and recommends 487.
const REFERRER_LEFT_STATUS: (u16, &str) = (487, "Request Terminated");

/// The status a REFER held for a decision is answered with when its call ends
/// under it while the referrer's own dialog is still up: there is no call left
/// to transfer, so it is declined, as it is when nobody decides in time.
const CALL_ENDED_STATUS: (u16, &str) = (603, "Decline");

/// A party's dialog on a call is ending, by its own BYE or because siphon is
/// releasing it (a `Replaces` takeover, a replacement): a REFER it sent in
/// that dialog, still held for its application's decision, is answered now,
/// and released.
///
/// `sip_call_id` and `peer_tag` name the dialog and the party (RFC 3261 §12),
/// which is how the REFER is recognised as that party's own wherever its leg
/// sits on the call. Before the BYE's own `200`, or before siphon's BYE, while
/// the flow the REFER arrived on is the one thing known about where to answer
/// it. Asked for every BYE, so it stays cheap when nothing is held.
pub fn pending_refer_referrer_left(
    state: &DispatcherState,
    call_id: &str,
    sip_call_id: &str,
    peer_tag: Option<&str>,
) {
    if state.pending_inbound_refer.is_empty() {
        return;
    }
    if let Some(pending) =
        state
            .pending_inbound_refer
            .take_from_dialog(call_id, sip_call_id, peer_tag)
    {
        let (code, reason) = REFERRER_LEFT_STATUS;
        info!(
            call_id = %call_id,
            %sip_call_id,
            "B2BUA REFER: the referrer's dialog ended before its transfer was decided — {code}"
        );
        b2bua_refer_send_final(&pending.inbound, &pending.message, code, reason, state);
    }
}

/// [`pending_refer_referrer_left`] for a leg siphon is about to release.
pub fn pending_refer_leg_released(state: &DispatcherState, call_id: &str, leg: &Leg) {
    pending_refer_referrer_left(
        state,
        call_id,
        &leg.dialog.call_id,
        leg.dialog.remote_tag.as_deref(),
    );
}

/// Take the REFER held for the call a control channel's Call-ID names: what
/// `accept_refer` and `reject_refer` decide on.
pub fn take_held_refer(state: &DispatcherState, sip_call_id: &str) -> Option<PendingInboundRefer> {
    if state.pending_inbound_refer.is_empty() {
        return None;
    }
    let call_id = state.call_actors.find_by_sip_call_id(sip_call_id);
    state
        .pending_inbound_refer
        .take_for_channel(sip_call_id, call_id.as_deref())
}

/// The leg of `call_id` the referrer of a held REFER is on now, for a decision
/// about to be carried out. `None` when the referrer's dialog is no longer on
/// the call: the REFER is answered `481` here (RFC 3515 §2.4.2 has it answered
/// whatever became of its dialog) and there is nothing left to carry out.
pub fn held_referrer_leg(
    pending: &PendingInboundRefer,
    call_id: &str,
    state: &DispatcherState,
) -> Option<bool> {
    let leg = state
        .call_actors
        .get_call(call_id)
        .and_then(|call| pending.referrer_on_a_leg(&call));
    if leg.is_none() {
        warn!(
            call_id = %call_id,
            "B2BUA REFER: the referrer's dialog left the call before its transfer was decided — 481"
        );
        b2bua_refer_send_final(
            &pending.inbound,
            &pending.message,
            481,
            "Call/Transaction Does Not Exist",
            state,
        );
    }
    leg
}

/// The call is being torn down: answer the REFER still held for its
/// application's decision, release it, and forget the REFERs already
/// answered on it.
///
/// Called before the BYEs go out, so the referrer has its final response ahead
/// of the BYE that ends its dialog.
pub fn refers_end_with_call(state: &DispatcherState, call_id: &str) {
    let held = (!state.pending_inbound_refer.is_empty())
        .then(|| state.pending_inbound_refer.take(call_id))
        .flatten();
    if let Some(pending) = held {
        let (code, reason) = CALL_ENDED_STATUS;
        info!(
            call_id = %call_id,
            "B2BUA REFER: the call ended before its transfer was decided — {code}"
        );
        b2bua_refer_send_final(&pending.inbound, &pending.message, code, reason, state);
    }
    state.answered_refers.forget_call(call_id);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refer(sip_call_id: &str, cseq: u32, branch: &str) -> SipMessage {
        let raw = format!(
            concat!(
                "REFER sip:192.0.2.1:5060 SIP/2.0\r\n",
                "Via: SIP/2.0/UDP 198.51.100.7:5060;branch={branch}\r\n",
                "Max-Forwards: 70\r\n",
                "From: <sip:15550100001@example.com>;tag=referrer\r\n",
                "To: <sip:15550100002@example.com>;tag=siphon\r\n",
                "Call-ID: {sip_call_id}\r\n",
                "CSeq: {cseq} REFER\r\n",
                "Refer-To: <sip:15550100003@example.com>\r\n",
                "Content-Length: 0\r\n",
                "\r\n",
            ),
            branch = branch,
            sip_call_id = sip_call_id,
            cseq = cseq,
        );
        parse_sip_message_bytes(raw.as_bytes()).expect("the REFER parses")
    }

    fn response(request: &SipMessage, code: u16, reason: &str) -> SipMessage {
        build_response(request, code, reason, None, &[])
    }

    fn status(replay: Option<ReferReplay>) -> Option<Option<u16>> {
        replay.map(|replay| match replay {
            ReferReplay::Final(response) => response.status_code(),
            ReferReplay::Proceeding => None,
        })
    }

    /// THE leak gate: N calls each have REFERs answered, and each entry leaves
    /// by one of its exits: the call ending, or the transaction's lifetime
    /// running out. The store must return to its baseline `len()`.
    #[test]
    fn answered_refer_store_drains_to_baseline() {
        let store = AnsweredReferStore::default();
        let baseline = store.len();
        assert_eq!(baseline, 0);
        let now = std::time::Instant::now();
        let later = now + REFER_TRANSACTION_LIFETIME;

        for cycle in 0..64 {
            let ended = format!("ended-{cycle}");
            let expired = format!("expired-{cycle}");
            for (call_id, sip_call_id) in [(&ended, "ended@192.0.2.10"), (&expired, "x@192.0.2.11")]
            {
                let accepted = refer(sip_call_id, 2, "z9hG4bK-two");
                let relayed = refer(sip_call_id, 3, "z9hG4bK-three");
                store.answered(call_id, &response(&accepted, 202, "Accepted"), now);
                store.proceeding(call_id, &relayed, now);
            }
            assert_eq!(store.len(), baseline + 4);

            store.forget_call(&ended);
            assert_eq!(store.len(), baseline + 2);
            store.forget_expired(now);
            assert_eq!(store.len(), baseline + 2, "not due yet");
            store.forget_expired(later);
            assert_eq!(
                store.len(),
                baseline,
                "store must drain to baseline after cycle {cycle}"
            );
            assert!(store.entries.is_empty(), "no empty per-call list is kept");
        }
    }

    /// A request is recognised by its Call-ID, CSeq and Via branch together:
    /// the same REFER again gets its response, a new one does not, and neither
    /// does the same REFER once its transaction is over.
    #[test]
    fn a_retransmission_is_the_same_call_id_cseq_and_branch() {
        let store = AnsweredReferStore::default();
        let now = std::time::Instant::now();
        let request = refer("call@192.0.2.10", 2, "z9hG4bK-two");
        assert!(store.replay("call", &request, now).is_none());

        store.answered("call", &response(&request, 603, "Decline"), now);
        assert_eq!(status(store.replay("call", &request, now)), Some(Some(603)));
        // A new CSeq, a new branch, another dialog, another call: new requests.
        for other in [
            refer("call@192.0.2.10", 3, "z9hG4bK-two"),
            refer("call@192.0.2.10", 2, "z9hG4bK-other"),
            refer("other@192.0.2.10", 2, "z9hG4bK-two"),
        ] {
            assert!(store.replay("call", &other, now).is_none());
        }
        assert!(store.replay("another-call", &request, now).is_none());
        // Its transaction over, the request is a new one again.
        assert!(store
            .replay("call", &request, now + REFER_TRANSACTION_LIFETIME)
            .is_none());
    }

    /// A REFER relayed to the far end has nothing to send again until the far
    /// end answers; from then on it has that response, and its lifetime runs
    /// from it.
    #[test]
    fn a_relayed_refer_is_proceeding_until_its_response_is_relayed() {
        let store = AnsweredReferStore::default();
        let now = std::time::Instant::now();
        let request = refer("call@192.0.2.10", 2, "z9hG4bK-two");
        store.proceeding("call", &request, now);
        assert_eq!(status(store.replay("call", &request, now)), Some(None));
        // The same request recorded as proceeding again changes nothing.
        store.proceeding("call", &request, now);
        assert_eq!(store.len(), 1);

        let answered_at = now + std::time::Duration::from_secs(10);
        store.answered("call", &response(&request, 202, "Accepted"), answered_at);
        assert_eq!(store.len(), 1, "the same transaction, now answered");
        assert_eq!(
            status(store.replay("call", &request, now + REFER_TRANSACTION_LIFETIME)),
            Some(Some(202)),
            "kept for 64*T1 from the response, not from the request"
        );
    }

    /// A REFER still being carried out is another request's reason to wait,
    /// never its own retransmission's, and only until it is answered or its
    /// transaction runs out.
    #[test]
    fn a_refer_being_carried_out_is_seen_by_another_request_until_it_is_answered() {
        let store = AnsweredReferStore::default();
        let now = std::time::Instant::now();
        let first = refer("call@192.0.2.10", 2, "z9hG4bK-two");
        let second = refer("call@192.0.2.10", 3, "z9hG4bK-three");
        assert!(!store.another_proceeding("call", &second, now), "nothing");

        store.proceeding("call", &first, now);
        assert!(store.another_proceeding("call", &second, now));
        assert!(
            !store.another_proceeding("call", &first, now),
            "its own retransmission is not another request"
        );
        assert!(!store.another_proceeding("another-call", &second, now));
        assert!(
            !store.another_proceeding("call", &second, now + REFER_TRANSACTION_LIFETIME),
            "a REFER nobody answered stops holding the call when its transaction ends"
        );

        store.answered("call", &response(&first, 202, "Accepted"), now);
        assert!(
            !store.another_proceeding("call", &second, now),
            "answered: nothing is being carried out"
        );
    }

    /// A call never holds more than its bound: the oldest goes first.
    #[test]
    fn a_call_remembers_a_bounded_number_of_refers() {
        let store = AnsweredReferStore::default();
        let now = std::time::Instant::now();
        let requests: Vec<SipMessage> = (0..ANSWERED_REFERS_PER_CALL as u32 + 3)
            .map(|number| refer("call@192.0.2.10", number + 2, &format!("z9hG4bK-{number}")))
            .collect();
        for request in &requests {
            store.answered("call", &response(request, 491, "Request Pending"), now);
        }
        assert_eq!(store.len(), ANSWERED_REFERS_PER_CALL);
        assert!(store.replay("call", &requests[0], now).is_none());
        assert!(store
            .replay("call", &requests[requests.len() - 1], now)
            .is_some());
    }
}
