//! The engine's own offer in the 2xx of an INVITE that carried no SDP, while
//! the caller's answer is awaited.

/// An anchored answer on an INVITE with no SDP (RFC 3261 §13.2.1): the media
/// engine made the offer (`offer_local`), siphon put it in its 2xx, and the
/// caller's answer comes in the ACK. Held on the call from the 2xx until that
/// ACK completes it with `answer`, or the call ends first; the engine call
/// stays pending, answering only `answer` and `delete`, until then.
#[derive(Debug, Clone)]
pub struct PendingLocalOffer {
    /// The engine's call-id the offer was made on.
    pub engine_call_id: String,
    /// The caller's tag: `from_tag` of the completing `answer`.
    pub caller_tag: String,
    /// The tag siphon's 2xx carries: `to_tag` of the completing `answer`.
    pub to_tag: String,
    /// The media profile the call is anchored with.
    pub profile: String,
    /// The offer the 2xx carried, held as the call's local description once
    /// the answer completes it.
    pub offer_sdp: String,
    /// The flags the offer was made with, for what the engine's observers are
    /// told of the call when it completes.
    pub flags: crate::rtpengine::NgFlags,
    /// Set by the ACK that takes the answer, so a retransmitted ACK completes
    /// nothing twice.
    pub claimed: bool,
    /// Dropped with the offer, which wakes everything waiting for the answer
    /// ([`CallActorStore::pending_local_offer_wait`]): a control verb that
    /// needs the engine call answered holds until then.
    pub completion: std::sync::Arc<tokio::sync::watch::Sender<()>>,
}

impl PendingLocalOffer {
    /// An offer awaiting its answer, nothing claiming it yet.
    pub fn new(
        engine_call_id: String,
        caller_tag: String,
        to_tag: String,
        profile: String,
        offer_sdp: String,
        flags: crate::rtpengine::NgFlags,
    ) -> Self {
        Self {
            engine_call_id,
            caller_tag,
            to_tag,
            profile,
            offer_sdp,
            flags,
            claimed: false,
            completion: std::sync::Arc::new(tokio::sync::watch::channel(()).0),
        }
    }
}

/// The offer an offerless re-INVITE's `200` repeated (the session in force),
/// from that `200` to the point the caller's ACK answer has been applied to
/// the engine (RFC 3261 §14.1, RFC 3264 §4). The dialog has an offer
/// outstanding for that long: the caller's leg is held on the pending
/// re-INVITE guard, and a request of the same transaction replays `response`.
#[derive(Debug, Clone)]
pub struct PendingRefreshAnswer {
    /// CSeq of the re-INVITE, which its ACK carries too.
    pub cseq: u32,
    /// Topmost Via branch of the re-INVITE: the transaction a retransmission
    /// repeats.
    pub branch: String,
    /// The `200`, as sent, for a retransmitted INVITE.
    pub response: crate::sip::message::SipMessage,
    /// Set by the ACK that takes the answer, so a copy of it completes nothing
    /// twice.
    pub claimed: bool,
}

impl PendingRefreshAnswer {
    /// An exchange awaiting its ACK.
    pub fn new(cseq: u32, branch: String, response: crate::sip::message::SipMessage) -> Self {
        Self {
            cseq,
            branch,
            response,
            claimed: false,
        }
    }
}
