//! What the test engine does with `offer_local`, as siphon-rtp 0.30.0 does it
//! ([`siphon_rtp_proto::Command::OfferLocal`]): on an engine that lists
//! `offer_local`, the verb makes the engine's own offer for a call whose
//! INVITE carried no SDP and leaves the call pending. While it is pending
//! only `answer`, `delete`, `query`, `attach_x3`, `detach_x3` and
//! `offer_local` are accepted, anything else is refused `offer-local-pending`.
//! The caller's `answer` completes it, or is refused with one of the engine's
//! tokens and leaves the call pending: a token a test asks for
//! ([`NATIVE_ENGINE_ANSWER_REFUSALS`]) is read off the answer's SDP as
//! `a=x-test-answer-<token>`, as [`super::NATIVE_ENGINE_REFUSED_OFFER`] is for
//! `answer_local`.

use std::collections::HashSet;
use std::sync::Mutex;

use siphon_rtp_proto::Command;

use super::Recorded;

/// What `node_info` lists when the engine serves `offer_local`.
pub(crate) const NATIVE_ENGINE_OFFER_LOCAL: &str = "offer_local";

/// The SDP the engine offers for every `offer_local`, on a port of its own.
pub(crate) const NATIVE_ENGINE_LOCAL_OFFER: &str = concat!(
    "v=0\r\n",
    "o=- 13 13 IN IP4 203.0.113.63\r\n",
    "s=-\r\n",
    "c=IN IP4 203.0.113.63\r\n",
    "t=0 0\r\n",
    "m=audio 54000 RTP/AVP 0 101\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
    "a=rtpmap:101 telephone-event/8000\r\n",
    "a=sendrecv\r\n",
);

/// The tokens an `answer` on a pending call is refused with, which a test asks
/// for by putting `a=x-test-answer-<token>` in the answer's SDP.
pub(crate) const NATIVE_ENGINE_ANSWER_REFUSALS: [&str; 12] = [
    "answer-sdp-invalid",
    "answer-rejected",
    "codec-not-offered",
    "security-mismatch",
    "sdes-no-acceptable-crypto",
    "dtls-fingerprint-missing",
    "dtls-setup-invalid",
    "ice-no-candidates",
    "rtcp-mux-not-accepted",
    "rtcp-mux-not-offered",
    "address-family-mismatch",
    "offer-local-superseded",
];

type CallKey = (Option<String>, String);

/// The calls `offer_local` made, keyed `(scope, call_id)`.
#[derive(Default)]
pub(super) struct OfferLocalModel {
    pending: Mutex<HashSet<CallKey>>,
    answered: Mutex<HashSet<CallKey>>,
}

impl OfferLocalModel {
    /// What the engine records of an `offer_local`.
    pub(super) fn record(command: &Command) -> Option<Recorded> {
        match command {
            Command::OfferLocal {
                call_id,
                from_tag,
                profile,
            } => Some(Recorded {
                profile: Some(profile.clone()),
                ..Recorded::new("offer_local", call_id, from_tag)
            }),
            _ => None,
        }
    }

    /// The engine's refusal of a command on a call `offer_local` made.
    pub(super) fn refusal(&self, command: &Command, scope: &Option<String>) -> Option<String> {
        let mut named = command.clone();
        let key = (scope.clone(), named.call_id_mut()?.clone());
        let pending = self.pending.lock().is_ok_and(|held| held.contains(&key));
        let answered = self.answered.lock().is_ok_and(|held| held.contains(&key));
        match command {
            Command::Answer { sdp, .. } if pending => {
                if sdp.trim().is_empty() {
                    return Some("answer: answer-sdp-invalid: the answer carries no SDP".into());
                }
                NATIVE_ENGINE_ANSWER_REFUSALS.iter().find_map(|token| {
                    sdp.contains(&format!("a=x-test-answer-{token}"))
                        .then(|| format!("answer: {token}: refused for the test"))
                })
            }
            Command::Answer { .. } if answered => Some(
                "answer: offer-local-already-answered: the call's offer was answered already"
                    .into(),
            ),
            Command::OfferLocal { .. } if answered => Some(
                "offer_local: offer-local-already-answered: the call is answered already".into(),
            ),
            Command::Answer { .. }
            | Command::Delete { .. }
            | Command::Query { .. }
            | Command::AttachX3 { .. }
            | Command::DetachX3 { .. }
            | Command::OfferLocal { .. } => None,
            _ if pending => {
                Some("offer-local-pending: the call waits for the answer to its offer_local".into())
            }
            _ => None,
        }
    }

    /// Keep what an accepted command changed.
    pub(super) fn accepted(&self, command: &Command, scope: &Option<String>) {
        let (Ok(mut pending), Ok(mut answered)) = (self.pending.lock(), self.answered.lock())
        else {
            return;
        };
        match command {
            Command::OfferLocal { call_id, .. } => {
                pending.insert((scope.clone(), call_id.clone()));
            }
            Command::Answer { call_id, .. } => {
                let key = (scope.clone(), call_id.clone());
                if pending.remove(&key) {
                    answered.insert(key);
                }
            }
            Command::Delete { call_id, .. } => {
                let key = (scope.clone(), call_id.clone());
                pending.remove(&key);
                answered.remove(&key);
            }
            _ => {}
        }
    }

    /// How many calls wait for their answer.
    pub(super) fn pending_calls(&self) -> usize {
        self.pending.lock().map_or(0, |held| held.len())
    }
}
