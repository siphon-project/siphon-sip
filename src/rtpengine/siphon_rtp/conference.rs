//! The conference verbs: seating calls in the engine's mixing rooms.
//!
//! A room is not a call. The engine names it by an id the controller chose and
//! never enters it in its call registry, so a seat is addressed by
//! `(conference_id, from_tag)` and every verb here is one of the engine's
//! `conference_*` family rather than a call verb under another id
//! (`docs/control/json.md`, "Conferencing", in siphon-rtp).
//!
//! A room lives on one engine. On a set of engines its seats, its playbacks
//! and its bridges must all reach the instance that holds it, so the room is
//! bound by the same affinity a call is, under a key no `Call-ID` can take: the
//! engine refuses U+001F in a call-id (RFC 3261 §25.1 allows none), so a key
//! that starts with it never meets a call's.

use siphon_rtp_proto::{BridgeDirection, CmdResult, Command, ConferenceRole, PlayRepeat};

use super::{
    expect_ok, expect_sdp, profile_flags_from_ng, proto_play_source, unexpected_result,
    PlayMediaOutcome, SiphonRtpClient, SiphonRtpClientSet,
};
use crate::rtpengine::client::PlayMediaSource;
use crate::rtpengine::error::RtpEngineError;
use crate::rtpengine::profile::NgFlags;

/// The affinity key a room is bound under on a set of engines.
fn room_affinity_key(conference_id: &str) -> String {
    format!("\u{1f}conference\u{1f}{conference_id}")
}

impl SiphonRtpClient {
    /// The one place a conference frame is sent.
    ///
    /// siphon-rtp refuses a `scope` on a `conference_*` verb rather than
    /// dropping it (a room is named by its own id, so there is nothing to tell
    /// apart; `docs/control/json.md`, "Call scope"). When this node gains a
    /// scope for its call frames, this path must stay unscoped.
    async fn conference_request(&self, command: Command) -> Result<CmdResult, RtpEngineError> {
        self.request(command).await
    }

    /// Seat a participant: the engine answers its offer with its own endpoint
    /// and the participant's codec, and creates the room on its first seat.
    /// Returns the answer SDP.
    pub async fn conference_join(
        &self,
        conference_id: &str,
        from_tag: &str,
        offer_sdp: &str,
        role: ConferenceRole,
        flags: &NgFlags,
    ) -> Result<String, RtpEngineError> {
        if flags.received_from.is_some() {
            seat::require_seat_received_from(self.request_in(None, Command::NodeInfo).await?)?;
        }
        let result = self
            .conference_request(Command::ConferenceJoin {
                conference_id: conference_id.to_string(),
                from_tag: from_tag.to_string(),
                sdp: offer_sdp.to_string(),
                role,
                profile: profile_flags_from_ng(flags),
            })
            .await?;
        let answer_sdp = expect_sdp(result)?;
        Ok(String::from_utf8_lossy(&answer_sdp).into_owned())
    }

    /// Free a seat; the engine tears the room down with its last seat.
    pub async fn conference_leave(
        &self,
        conference_id: &str,
        from_tag: &str,
    ) -> Result<(), RtpEngineError> {
        expect_ok(
            self.conference_request(Command::ConferenceLeave {
                conference_id: conference_id.to_string(),
                from_tag: from_tag.to_string(),
            })
            .await?,
        )
    }

    /// Change who a seat hears and who hears it, live.
    pub async fn conference_route(
        &self,
        conference_id: &str,
        from_tag: &str,
        role: ConferenceRole,
    ) -> Result<(), RtpEngineError> {
        expect_ok(
            self.conference_request(Command::ConferenceRoute {
                conference_id: conference_id.to_string(),
                from_tag: from_tag.to_string(),
                role,
            })
            .await?,
        )
    }

    /// Link two live rooms so one hears the other, or each hears the other.
    pub async fn conference_bridge(
        &self,
        conference_id_a: &str,
        conference_id_b: &str,
        direction: BridgeDirection,
    ) -> Result<(), RtpEngineError> {
        expect_ok(
            self.conference_request(Command::ConferenceBridge {
                conference_id_a: conference_id_a.to_string(),
                conference_id_b: conference_id_b.to_string(),
                direction,
            })
            .await?,
        )
    }

    /// Undo a link between two rooms, whichever way it was made.
    pub async fn conference_unbridge(
        &self,
        conference_id_a: &str,
        conference_id_b: &str,
    ) -> Result<(), RtpEngineError> {
        expect_ok(
            self.conference_request(Command::ConferenceUnbridge {
                conference_id_a: conference_id_a.to_string(),
                conference_id_b: conference_id_b.to_string(),
            })
            .await?,
        )
    }

    /// Offer a new seat the focus calls out: the engine allocates the seat's
    /// endpoint and writes the offer (RFC 3264 §5). The seat joins the room
    /// on [`Self::conference_answer`]. Returns the offer SDP.
    pub async fn conference_offer(
        &self,
        conference_id: &str,
        from_tag: &str,
        role: ConferenceRole,
        flags: &NgFlags,
    ) -> Result<String, RtpEngineError> {
        let result = self
            .conference_request(Command::ConferenceOffer {
                conference_id: conference_id.to_string(),
                from_tag: from_tag.to_string(),
                role,
                profile: profile_flags_from_ng(flags),
            })
            .await?;
        let offer_sdp = expect_sdp(result)?;
        Ok(String::from_utf8_lossy(&offer_sdp).into_owned())
    }

    /// Seat an offered seat on the participant's answer. `received_from` is
    /// the address the participant's answer came from, for one behind NAT
    /// whose `c=` is private: the seat then takes its media from there and
    /// sends the mix there. Sent only to an engine that lists
    /// `conference_received_from`; any other refuses the seat.
    pub async fn conference_answer(
        &self,
        conference_id: &str,
        from_tag: &str,
        answer_sdp: &str,
        received_from: Option<std::net::IpAddr>,
    ) -> Result<(), RtpEngineError> {
        if received_from.is_some() {
            seat::require_seat_received_from(self.request_in(None, Command::NodeInfo).await?)?;
        }
        expect_ok(
            self.conference_request(Command::ConferenceAnswer {
                conference_id: conference_id.to_string(),
                from_tag: from_tag.to_string(),
                sdp: answer_sdp.to_string(),
                received_from,
            })
            .await?,
        )
    }

    /// Play audio into a room as a source nobody is mixed-minus-self against.
    ///
    /// Accept-on-start, like a leg playback: the end arrives later as a
    /// `play_finished` naming the room. An accept without a `play_id` is a
    /// protocol error, not an outcome: that id is the only handle a stop, a
    /// gain change and the completion have on the playback.
    pub async fn conference_play(
        &self,
        conference_id: &str,
        source: &PlayMediaSource,
        repeat_times: Option<PlayRepeat>,
        start_pos_ms: Option<u64>,
        duration_ms: Option<u64>,
        gain_decibels: Option<i32>,
    ) -> Result<PlayMediaOutcome, RtpEngineError> {
        let result = self
            .conference_request(Command::ConferencePlay {
                conference_id: conference_id.to_string(),
                source: proto_play_source(source),
                repeat_times,
                start_pos_ms,
                duration_ms,
                gain_decibels,
            })
            .await?;
        match result {
            CmdResult::Ok {
                play_id: Some(play_id),
                duration_ms,
                ..
            } => Ok(PlayMediaOutcome {
                play_id: Some(play_id),
                duration_ms,
            }),
            other => Err(unexpected_result("conference play", other)),
        }
    }

    /// Stop one room playback, or all of them when `play_id` is `None`.
    pub async fn conference_stop_play(
        &self,
        conference_id: &str,
        play_id: Option<u64>,
    ) -> Result<(), RtpEngineError> {
        expect_ok(
            self.conference_request(Command::ConferenceStopPlay {
                conference_id: conference_id.to_string(),
                play_id,
            })
            .await?,
        )
    }

    /// Retune a running room playback's gain.
    pub async fn conference_set_play_gain(
        &self,
        conference_id: &str,
        play_id: u64,
        gain_decibels: i32,
    ) -> Result<(), RtpEngineError> {
        expect_ok(
            self.conference_request(Command::ConferenceSetPlayGain {
                conference_id: conference_id.to_string(),
                play_id,
                gain_decibels,
            })
            .await?,
        )
    }

    /// Record the room's listener mix (every seat, any bridged room and any
    /// room playback) to a WAV, returning the engine's `recording_id`.
    /// Accept-on-start: the end arrives as a `recording_finished` naming the
    /// room, which `wait_recording` resolves by that id.
    pub async fn conference_start_recording(
        &self,
        conference_id: &str,
        path: Option<&str>,
        max_duration_ms: Option<u64>,
        silence_ms: Option<u64>,
    ) -> Result<String, RtpEngineError> {
        let result = self
            .conference_request(Command::ConferenceStartRecording {
                conference_id: conference_id.to_string(),
                path: path.map(str::to_string),
                recording_dir: None,
                max_duration_ms,
                silence_ms,
            })
            .await?;
        match result {
            CmdResult::Ok {
                recording_id: Some(id),
                ..
            } => Ok(id),
            // The id is the only handle a stop and the end have on the file.
            other => Err(unexpected_result("conference start recording", other)),
        }
    }

    /// Stop one room recording, or every recording of the room.
    pub async fn conference_stop_recording(
        &self,
        conference_id: &str,
        recording_id: Option<&str>,
    ) -> Result<(), RtpEngineError> {
        expect_ok(
            self.conference_request(Command::ConferenceStopRecording {
                conference_id: conference_id.to_string(),
                recording_id: recording_id.map(str::to_string),
            })
            .await?,
        )
    }
}

impl SiphonRtpClientSet {
    /// Seat a participant on the instance that holds the room, binding the
    /// room to an instance on its first seat.
    pub async fn conference_join(
        &self,
        conference_id: &str,
        from_tag: &str,
        offer_sdp: &str,
        role: ConferenceRole,
        flags: &NgFlags,
    ) -> Result<String, RtpEngineError> {
        let key = room_affinity_key(conference_id);
        let answer = self
            .select(&key)
            .conference_join(conference_id, from_tag, offer_sdp, role, flags)
            .await?;
        self.bind_affinity(&key);
        Ok(answer)
    }

    /// Free a seat on the instance that holds the room.
    pub async fn conference_leave(
        &self,
        conference_id: &str,
        from_tag: &str,
    ) -> Result<(), RtpEngineError> {
        self.select(&room_affinity_key(conference_id))
            .conference_leave(conference_id, from_tag)
            .await
    }

    /// The room has no seat left that this process knows of: forget which
    /// instance held it, so the affinity map cannot outgrow the live rooms.
    pub fn forget_room(&self, conference_id: &str) {
        self.affinity.remove(&room_affinity_key(conference_id));
    }

    /// Whether an instance holds an engine call under `call_id` (an offer or a
    /// local answer this process made), beside any seat the call holds.
    pub fn holds_call(&self, call_id: &str) -> bool {
        self.clients
            .iter()
            .any(|client| client.sessions.contains_key(call_id))
    }

    /// Change a seat's role on the instance that holds the room.
    pub async fn conference_route(
        &self,
        conference_id: &str,
        from_tag: &str,
        role: ConferenceRole,
    ) -> Result<(), RtpEngineError> {
        self.select(&room_affinity_key(conference_id))
            .conference_route(conference_id, from_tag, role)
            .await
    }

    /// Bridge two rooms on the instance that holds the first. Two rooms on
    /// different instances cannot be bridged; the engine says so.
    pub async fn conference_bridge(
        &self,
        conference_id_a: &str,
        conference_id_b: &str,
        direction: BridgeDirection,
    ) -> Result<(), RtpEngineError> {
        self.select(&room_affinity_key(conference_id_a))
            .conference_bridge(conference_id_a, conference_id_b, direction)
            .await
    }

    /// Unlink two rooms on the instance that holds the first.
    pub async fn conference_unbridge(
        &self,
        conference_id_a: &str,
        conference_id_b: &str,
    ) -> Result<(), RtpEngineError> {
        self.select(&room_affinity_key(conference_id_a))
            .conference_unbridge(conference_id_a, conference_id_b)
            .await
    }

    /// Offer a seat on the instance that holds the room, binding the room to
    /// an instance when this is its first seat.
    pub async fn conference_offer(
        &self,
        conference_id: &str,
        from_tag: &str,
        role: ConferenceRole,
        flags: &NgFlags,
    ) -> Result<String, RtpEngineError> {
        let key = room_affinity_key(conference_id);
        let offer = self
            .select(&key)
            .conference_offer(conference_id, from_tag, role, flags)
            .await?;
        self.bind_affinity(&key);
        Ok(offer)
    }

    /// Hand the participant's answer to the instance that made the offer.
    pub async fn conference_answer(
        &self,
        conference_id: &str,
        from_tag: &str,
        answer_sdp: &str,
        received_from: Option<std::net::IpAddr>,
    ) -> Result<(), RtpEngineError> {
        self.select(&room_affinity_key(conference_id))
            .conference_answer(conference_id, from_tag, answer_sdp, received_from)
            .await
    }

    /// Play into a room on the instance that holds it.
    pub async fn conference_play(
        &self,
        conference_id: &str,
        source: &PlayMediaSource,
        repeat_times: Option<PlayRepeat>,
        start_pos_ms: Option<u64>,
        duration_ms: Option<u64>,
        gain_decibels: Option<i32>,
    ) -> Result<PlayMediaOutcome, RtpEngineError> {
        self.select(&room_affinity_key(conference_id))
            .conference_play(
                conference_id,
                source,
                repeat_times,
                start_pos_ms,
                duration_ms,
                gain_decibels,
            )
            .await
    }

    /// Stop a room playback on the instance that holds the room.
    pub async fn conference_stop_play(
        &self,
        conference_id: &str,
        play_id: Option<u64>,
    ) -> Result<(), RtpEngineError> {
        self.select(&room_affinity_key(conference_id))
            .conference_stop_play(conference_id, play_id)
            .await
    }

    /// Retune a room playback on the instance that holds the room.
    pub async fn conference_set_play_gain(
        &self,
        conference_id: &str,
        play_id: u64,
        gain_decibels: i32,
    ) -> Result<(), RtpEngineError> {
        self.select(&room_affinity_key(conference_id))
            .conference_set_play_gain(conference_id, play_id, gain_decibels)
            .await
    }

    /// Record a room on the instance that holds it.
    pub async fn conference_start_recording(
        &self,
        conference_id: &str,
        path: Option<&str>,
        max_duration_ms: Option<u64>,
        silence_ms: Option<u64>,
    ) -> Result<String, RtpEngineError> {
        self.select(&room_affinity_key(conference_id))
            .conference_start_recording(conference_id, path, max_duration_ms, silence_ms)
            .await
    }

    /// Stop a room recording on the instance that holds the room.
    pub async fn conference_stop_recording(
        &self,
        conference_id: &str,
        recording_id: Option<&str>,
    ) -> Result<(), RtpEngineError> {
        self.select(&room_affinity_key(conference_id))
            .conference_stop_recording(conference_id, recording_id)
            .await
    }

    /// Wait for a room recording to end, on the instance that holds the room:
    /// its `recording_finished` arrives on that instance's connection.
    pub async fn conference_wait_recording(
        &self,
        conference_id: &str,
        recording_id: &str,
        deadline: std::time::Duration,
    ) -> Option<crate::rtpengine::events::RecordingFinished> {
        self.select(&room_affinity_key(conference_id))
            .wait_recording(recording_id, deadline)
            .await
    }
}

mod seat;

#[cfg(test)]
mod tests;
