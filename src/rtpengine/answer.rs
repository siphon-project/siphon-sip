//! What `rtpengine.answer` sends the media engine for a reply's SDP.
//!
//! Usually the reply answers the INVITE's offer. On a delayed offer (RFC 3264 §4)
//! the INVITE carried no SDP, so the reply's SDP is the offer itself, and the
//! caller answers it in its ACK: the engine is sent an `offer` from the replying
//! party's side, and siphon sends the matching `answer` when the ACK arrives
//! (`send_delayed_offer_ack`).

use tracing::debug;

use super::session::{MediaSession, MediaSessionStore};
use super::{MediaBackend, NgFlags, RtpEngineError};

/// One `rtpengine.answer`, as the engine is sent it.
pub(crate) struct AnswerExchange {
    pub(crate) call_id: String,
    /// The tag of the party that sent the INVITE.
    pub(crate) from_tag: String,
    /// The tag of the party whose reply carries the SDP.
    pub(crate) to_tag: String,
    pub(crate) sdp: Vec<u8>,
    pub(crate) flags: NgFlags,
    /// The INVITE carried no offer, so the reply's SDP is the offer.
    pub(crate) delayed_offer: bool,
    pub(crate) profile: String,
    pub(crate) ws_uri: Option<String>,
}

/// Send the engine what a reply's SDP is: the answer to the INVITE's offer, or,
/// for a delayed offer, the offer itself. Returns the SDP the engine rewrote.
pub(crate) async fn exchange_answer(
    client: &MediaBackend,
    sessions: &MediaSessionStore,
    exchange: AnswerExchange,
) -> Result<Vec<u8>, RtpEngineError> {
    if exchange.delayed_offer {
        let rewritten = client
            .offer(
                &exchange.call_id,
                &exchange.to_tag,
                &exchange.sdp,
                &exchange.flags,
            )
            .await?;
        debug!(
            call_id = %exchange.call_id,
            sdp_len = rewritten.len(),
            "RTPEngine: the reply carries a delayed offer, SDP rewritten as the offer"
        );
        // The replying party is the offerer. The answerer is recorded once the
        // caller's answer reaches the engine, in `send_delayed_offer_ack`.
        sessions.insert(MediaSession {
            rtpengine_call_id: exchange.call_id.clone(),
            ws_tee: exchange.flags.ws_tee.clone(),
            call_id: exchange.call_id,
            from_tag: exchange.to_tag,
            to_tag: None,
            profile: exchange.profile,
            ws_uri: exchange.ws_uri,
            ws_bridge_attached: false,
            created_at: std::time::Instant::now(),
        });
        return Ok(rewritten);
    }
    let rewritten = client
        .answer(
            &exchange.call_id,
            &exchange.from_tag,
            &exchange.to_tag,
            &exchange.sdp,
            &exchange.flags,
        )
        .await?;
    debug!(
        call_id = %exchange.call_id,
        sdp_len = rewritten.len(),
        "RTPEngine answer: SDP rewritten"
    );
    sessions.set_to_tag(&exchange.call_id, exchange.to_tag);
    Ok(rewritten)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtpengine::test_engine::{TestEngine, ENGINE_SDP};

    const ANCHORED_CALL_ID: &str = "anchored-call@192.0.2.20";

    /// The callee's SDP in its 2xx.
    const CALLEE_SDP: &str = concat!(
        "v=0\r\n",
        "o=- 7 7 IN IP4 198.51.100.91\r\n",
        "s=-\r\n",
        "c=IN IP4 198.51.100.91\r\n",
        "t=0 0\r\n",
        "m=audio 30000 RTP/AVP 0\r\n",
    );

    fn exchange(delayed_offer: bool) -> AnswerExchange {
        AnswerExchange {
            call_id: ANCHORED_CALL_ID.to_string(),
            from_tag: "caller-tag".to_string(),
            to_tag: "callee-tag".to_string(),
            sdp: CALLEE_SDP.as_bytes().to_vec(),
            flags: NgFlags::default(),
            delayed_offer,
            profile: "rtp_passthrough".to_string(),
            ws_uri: None,
        }
    }

    /// A delayed offer (RFC 3264 §4): the 2xx to an INVITE that carried no SDP
    /// carries the offer. The engine is sent an `offer` from the callee's side,
    /// and the session is recorded with the callee as offerer and no answerer
    /// yet: `send_delayed_offer_ack` completes it with the caller's answer.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_reply_carrying_the_offer_goes_to_the_engine_as_an_offer() {
        let engine = TestEngine::start(false).await;
        let backend = engine.backend().await;
        let sessions = MediaSessionStore::new();

        let rewritten = exchange_answer(&backend, &sessions, exchange(true))
            .await
            .expect("the engine takes the offer");

        assert_eq!(rewritten, ENGINE_SDP.as_bytes());
        assert!(
            engine.commands("answer").is_empty(),
            "nothing has answered the offer yet"
        );
        let offers = engine.commands("offer");
        assert_eq!(offers.len(), 1);
        assert_eq!(offers[0].call_id.as_deref(), Some(ANCHORED_CALL_ID));
        assert_eq!(
            offers[0].from_tag.as_deref(),
            Some("callee-tag"),
            "the callee is the offerer"
        );
        assert_eq!(offers[0].sdp.as_deref(), Some(CALLEE_SDP));
        let session = sessions
            .get(ANCHORED_CALL_ID)
            .expect("the session is recorded");
        assert_eq!(session.from_tag, "callee-tag");
        assert_eq!(session.to_tag, None, "the caller's answer is still to come");
        assert_eq!(session.profile, "rtp_passthrough");
    }

    /// A 2xx to an INVITE that carried the offer is the answer, as it always was.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_reply_to_an_offer_goes_to_the_engine_as_an_answer() {
        let engine = TestEngine::start(false).await;
        let backend = engine.backend().await;
        let sessions = MediaSessionStore::new();
        sessions.insert(MediaSession {
            call_id: ANCHORED_CALL_ID.to_string(),
            rtpengine_call_id: ANCHORED_CALL_ID.to_string(),
            from_tag: "caller-tag".to_string(),
            to_tag: None,
            profile: "rtp_passthrough".to_string(),
            ws_uri: None,
            ws_tee: None,
            ws_bridge_attached: false,
            created_at: std::time::Instant::now(),
        });

        exchange_answer(&backend, &sessions, exchange(false))
            .await
            .expect("the engine takes the answer");

        assert!(engine.commands("offer").is_empty());
        let answers = engine.commands("answer");
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].from_tag.as_deref(), Some("caller-tag"));
        assert_eq!(answers[0].to_tag.as_deref(), Some("callee-tag"));
        assert_eq!(
            sessions
                .get(ANCHORED_CALL_ID)
                .and_then(|session| session.to_tag),
            Some("callee-tag".to_string())
        );
    }
}
