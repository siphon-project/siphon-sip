//! `conference_seat`: one leg of a live, answered call moved into a room in
//! place (`b2bua.adopt_replaced`).
//!
//! Unlike every other conference verb this one names a **call**: the engine
//! moves the leg the call's `from_tag` names into the room, keeps its endpoint,
//! its latched peer, its codec and its SRTP or DTLS context, and releases the
//! call's other leg once the seat is in. The call stays in the engine's call
//! registry as a one-legged call, so it is sent on the call's own instance and
//! under the call's frame scope, and a later `delete` on the call removes the
//! seat.
//!
//! An engine from before the verb closes the whole control connection on an
//! unknown command, dropping control of every call on it, so the verb is sent
//! only once `node_info` lists `conference_seat` (as an `ogg_opus` recording is
//! gated on `record_ogg_opus`).

use siphon_rtp_proto::{CmdResult, Command, ConferenceRole};

use super::super::{expect_ok, per_call, result_kind, SiphonRtpClient, SiphonRtpClientSet};
use super::room_affinity_key;
use crate::rtpengine::error::RtpEngineError;

/// What an engine that serves `conference_seat` lists in `node_info.features`.
pub(crate) const CONFERENCE_SEAT_FEATURE: &str = "conference_seat";

/// What an engine lists in `node_info.features` when a seat it answers or
/// offers honours the profile's received-from address (the participant behind
/// NAT whose `c=` names a private address): it admits that party's media from
/// there and sends the mix back there, as a two-party answer does.
pub(crate) const CONFERENCE_RECEIVED_FROM_FEATURE: &str = "conference_received_from";

/// Whether a `node_info` answer lists `conference_seat`.
pub(crate) fn require_conference_seat(result: CmdResult) -> Result<(), RtpEngineError> {
    require_feature(
        result,
        CONFERENCE_SEAT_FEATURE,
        "conference_seat",
        "siphon-rtp (an engine that does not list conference_seat)",
    )
}

/// Whether a `node_info` answer lists `conference_received_from`. An engine
/// without it would seat a NATed participant on its private `c=` address and
/// drop every packet it sends, so such a seat is refused rather than made.
pub(crate) fn require_seat_received_from(result: CmdResult) -> Result<(), RtpEngineError> {
    require_feature(
        result,
        CONFERENCE_RECEIVED_FROM_FEATURE,
        "a conference seat with received_from",
        "siphon-rtp (an engine that does not list conference_received_from)",
    )
}

/// Whether a `node_info` answer lists `feature`; refused as `operation` not
/// implemented by `backend` when it does not, so nothing is sent.
fn require_feature(
    result: CmdResult,
    feature: &str,
    operation: &'static str,
    backend: &'static str,
) -> Result<(), RtpEngineError> {
    match result {
        CmdResult::NodeInfo { node } if node.features.iter().any(|listed| listed == feature) => {
            Ok(())
        }
        CmdResult::NodeInfo { node } => {
            tracing::warn!(
                version = %node.version,
                "{operation} asked for, but the media engine does not list \
                 '{feature}' in node_info features"
            );
            Err(RtpEngineError::Unsupported { operation, backend })
        }
        CmdResult::Error { reason } => Err(RtpEngineError::EngineError(format!(
            "node_info refused while checking for {feature}: {reason}"
        ))),
        other => Err(RtpEngineError::Protocol(format!(
            "unexpected '{}' response for node_info",
            result_kind(&other)
        ))),
    }
}

impl SiphonRtpClient {
    /// Seat the leg `from_tag` of the live call `call_id` in `conference_id`,
    /// once the engine has said it serves the verb. A refusal is the engine's
    /// reason, prefixed `conference_seat: `, and leaves the call as it was.
    pub async fn conference_seat(
        &self,
        call_id: &str,
        from_tag: &str,
        conference_id: &str,
        role: ConferenceRole,
    ) -> Result<(), RtpEngineError> {
        require_conference_seat(self.request_in(None, Command::NodeInfo).await?)?;
        // A call verb: the frame carries the call's scope, as every verb
        // naming a call does.
        expect_ok(
            self.request(Command::ConferenceSeat {
                call_id: call_id.to_string(),
                from_tag: from_tag.to_string(),
                conference_id: conference_id.to_string(),
                role,
            })
            .await?,
        )
    }
}

impl SiphonRtpClientSet {
    /// Seat a call's leg on the instance that holds the call. The room has to
    /// be on that same instance: one already bound to another is refused
    /// before anything is sent, and one not bound yet is bound to the call's.
    pub async fn conference_seat(
        &self,
        call_id: &str,
        from_tag: &str,
        conference_id: &str,
        role: ConferenceRole,
    ) -> Result<(), RtpEngineError> {
        let room_key = room_affinity_key(conference_id);
        let call_index = if self.clients.len() == 1 {
            0
        } else {
            let call_key =
                per_call::scoped_key(call_id, per_call::frame_scope().as_ref()).into_owned();
            let Some(index) = self.affinity.get(&call_key).map(|index| *index) else {
                return Err(RtpEngineError::EngineError(format!(
                    "conference_seat: no engine instance is known to hold call {call_id}"
                )));
            };
            if let Some(room_index) = self.affinity.get(&room_key).map(|index| *index) {
                if room_index != index {
                    return Err(RtpEngineError::EngineError(format!(
                        "conference_seat: conference {conference_id} is on another engine \
                         instance than call {call_id}"
                    )));
                }
            }
            index
        };
        let Some(client) = self.clients.get(call_index) else {
            return Err(RtpEngineError::EngineError(format!(
                "conference_seat: no engine instance {call_index}"
            )));
        };
        client
            .conference_seat(call_id, from_tag, conference_id, role)
            .await?;
        if self.clients.len() > 1 {
            self.affinity.entry(room_key).or_insert(call_index);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node_info(features: &[&str]) -> CmdResult {
        serde_json::from_value(serde_json::json!({
            "result": "node_info",
            "node": {
                "node_id": "engine-1",
                "version": "0.15.3",
                "media_addresses": [],
                "codecs": [],
                "features": features,
                "max_sessions": 0,
                "draining": false,
            },
        }))
        .expect("a node_info result")
    }

    #[test]
    fn the_feature_is_read_off_node_info() {
        assert!(require_conference_seat(node_info(&["relay", "conference_seat"])).is_ok());
        let missing = require_conference_seat(node_info(&["relay", "scope"]))
            .expect_err("an engine without the feature is refused");
        assert!(
            matches!(
                missing,
                RtpEngineError::Unsupported {
                    operation: "conference_seat",
                    ..
                }
            ),
            "{missing}"
        );
    }

    #[test]
    fn a_refused_or_odd_node_info_is_an_error_not_a_pass() {
        let refused = require_conference_seat(CmdResult::Error {
            reason: "draining".into(),
        })
        .expect_err("a refusal is not a pass");
        assert!(
            matches!(refused, RtpEngineError::EngineError(_)),
            "{refused}"
        );
        let odd = require_conference_seat(CmdResult::Pong).expect_err("a pong is not a pass");
        assert!(matches!(odd, RtpEngineError::Protocol(_)), "{odd}");
    }
}
