//! A B2BUA BYE's final response, kept for the BYE's retransmissions (RFC 3261
//! §17.2.2).
//!
//! The B2BUA answers a BYE itself and ends the call in the same step. Over UDP
//! that 200 can be lost, and the peer then sends the BYE again on Timer E. By
//! then the call is gone, so a resend handled as a new request matched nothing
//! and was answered 481: a call that ended cleanly read as a failed hangup at
//! the peer. A non-INVITE server transaction in Completed answers every resend
//! with the response it sent, for Timer J: 64*T1 on UDP, zero on a reliable
//! transport, which does not retransmit.
//!
//! Kept here rather than in a server transaction because a resend needs only
//! the bytes that answered it, a few hundred, while a server transaction holds
//! the parsed request and response, several times that, for every call that
//! ends. Only a BYE that ended a call is remembered, never a 481 to a BYE that
//! matched nothing, so the store grows with real hangups and not with whatever
//! a peer chooses to send.

use super::refer_answered::RequestIdentity;
use crate::dispatcher::*;
use std::time::Instant;

/// The response one BYE was answered with, and when its transaction is over.
struct AnsweredBye {
    response: Bytes,
    expires: Instant,
}

/// BYEs the B2BUA answered over UDP within the last Timer J, keyed by what a
/// retransmission shares with the original (RFC 3261 §17.2.3).
///
/// Per-call state: an entry is forgotten once Timer J has passed
/// ([`expire_answered_byes`], on the maintenance tick), so the store drains
/// back to empty under a completed workload. Covered by
/// `the_store_drains_once_timer_j_has_passed` and the dispatcher-level
/// `answered_byes_drain_with_timer_j`.
#[derive(Default)]
pub struct AnsweredByeStore {
    entries: DashMap<RequestIdentity, AnsweredBye>,
}

impl AnsweredByeStore {
    /// `bye` was answered with `response`, owed again to every resend of it
    /// until `expires`. A BYE missing its Call-ID, CSeq or branch cannot be
    /// matched by a resend and is not kept.
    pub fn answered(&self, bye: &SipMessage, response: Bytes, expires: Instant) {
        let Some(identity) = RequestIdentity::of(bye) else {
            return;
        };
        self.entries
            .insert(identity, AnsweredBye { response, expires });
    }

    /// The response `bye` is owed if it is a resend of a BYE answered less than
    /// Timer J ago. Asked of every B2BUA BYE, so it is one lookup, and none
    /// while nothing is remembered.
    pub fn replay(&self, bye: &SipMessage, now: Instant) -> Option<Bytes> {
        if self.entries.is_empty() {
            return None;
        }
        let identity = RequestIdentity::of(bye)?;
        let answered = self.entries.get(&identity)?;
        (answered.expires > now).then(|| answered.response.clone())
    }

    /// Forget every BYE whose transaction is over at `now`.
    pub fn expire(&self, now: Instant) {
        if !self.entries.is_empty() {
            self.entries.retain(|_, answered| answered.expires > now);
        }
    }

    /// How many BYEs are remembered.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no BYE is remembered.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Answer `bye`, a BYE that matched a call, with `response` on the flow it
/// arrived on, and keep the response for the BYE's resends when that flow is
/// UDP (on a reliable transport Timer J is zero: nothing is resent).
pub fn answer_bye(
    response: SipMessage,
    bye: &SipMessage,
    inbound: &InboundMessage,
    state: &DispatcherState,
) {
    let data = Bytes::from(response.to_bytes());
    if inbound.transport == Transport::Udp {
        let timer_j = state.transaction_manager.timers().timer_j_udp();
        state
            .answered_byes
            .answered(bye, data.clone(), Instant::now() + timer_j);
    }
    send_outbound_from(
        data,
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
        Some(inbound.local_addr),
        state,
    );
}

/// Answer `bye` again if it is a resend of a BYE answered within Timer J, and
/// say whether it was. The resend is not handled any further: the call it
/// ended is torn down already, or being torn down by the original.
pub fn answer_bye_retransmission(
    inbound: &InboundMessage,
    bye: &SipMessage,
    state: &DispatcherState,
) -> bool {
    let Some(response) = state.answered_byes.replay(bye, Instant::now()) else {
        return false;
    };
    debug!(remote = %inbound.remote_addr, "B2BUA BYE: a resend, answered as the original was");
    send_outbound_from(
        response,
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
        Some(inbound.local_addr),
        state,
    );
    true
}

/// Maintenance tick: forget the BYEs whose transactions are over.
pub fn expire_answered_byes(state: &DispatcherState) {
    state.answered_byes.expire(Instant::now());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    fn bye(branch: &str) -> SipMessage {
        let raw = format!(
            concat!(
                "BYE sip:192.0.2.1:5060 SIP/2.0\r\n",
                "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-{branch}\r\n",
                "From: <sip:a@192.0.2.10>;tag=a\r\n",
                "To: <sip:b@192.0.2.1>;tag=b\r\n",
                "Call-ID: call-{branch}@192.0.2.10\r\n",
                "CSeq: 2 BYE\r\n",
                "Content-Length: 0\r\n",
                "\r\n",
            ),
            branch = branch,
        );
        parse_sip_message_bytes(raw.as_bytes()).expect("the BYE parses")
    }

    fn ok() -> Bytes {
        Bytes::from_static(b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n")
    }

    #[test]
    fn a_resend_is_answered_with_the_kept_response() {
        let store = AnsweredByeStore::default();
        let now = Instant::now();
        store.answered(&bye("one"), ok(), now + Duration::from_secs(32));
        assert_eq!(store.replay(&bye("one"), now), Some(ok()));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn a_different_bye_is_not_a_resend() {
        let store = AnsweredByeStore::default();
        let now = Instant::now();
        store.answered(&bye("one"), ok(), now + Duration::from_secs(32));
        assert_eq!(store.replay(&bye("two"), now), None);
    }

    #[test]
    fn a_resend_after_timer_j_is_not_answered_from_the_store() {
        let store = AnsweredByeStore::default();
        let now = Instant::now();
        store.answered(&bye("one"), ok(), now + Duration::from_secs(32));
        assert_eq!(
            store.replay(&bye("one"), now + Duration::from_secs(33)),
            None
        );
    }

    #[test]
    fn a_bye_without_a_branch_is_not_kept() {
        let raw = concat!(
            "BYE sip:192.0.2.1:5060 SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.10:5060\r\n",
            "Call-ID: no-branch@192.0.2.10\r\n",
            "CSeq: 2 BYE\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        let without = parse_sip_message_bytes(raw.as_bytes()).expect("the BYE parses");
        let store = AnsweredByeStore::default();
        let now = Instant::now();
        store.answered(&without, ok(), now + Duration::from_secs(32));
        assert!(store.is_empty());
        assert_eq!(store.replay(&without, now), None);
    }

    /// Leak gate: every entry goes once its Timer J has passed.
    #[test]
    fn the_store_drains_once_timer_j_has_passed() {
        let store = AnsweredByeStore::default();
        let now = Instant::now();
        for index in 0..1000 {
            store.answered(
                &bye(&format!("call-{index}")),
                ok(),
                now + Duration::from_secs(32),
            );
        }
        assert_eq!(store.len(), 1000);
        store.expire(now + Duration::from_secs(31));
        assert_eq!(store.len(), 1000, "nothing goes before Timer J");
        store.expire(now + Duration::from_secs(32));
        assert!(store.is_empty(), "everything goes at Timer J");
    }

    #[test]
    fn concurrent_answers_and_replays_all_land() {
        let store = Arc::new(AnsweredByeStore::default());
        let expires = Instant::now() + Duration::from_secs(32);
        let workers: Vec<_> = (0..8)
            .map(|worker| {
                let store = Arc::clone(&store);
                std::thread::spawn(move || {
                    for index in 0..250 {
                        let request = bye(&format!("w{worker}-{index}"));
                        store.answered(&request, ok(), expires);
                        assert_eq!(store.replay(&request, Instant::now()), Some(ok()));
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().expect("a worker panicked");
        }
        assert_eq!(store.len(), 2000);
    }
}
