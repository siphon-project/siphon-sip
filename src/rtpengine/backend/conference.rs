//! Conference rooms on the media backend, and the seats this process holds in
//! them.
//!
//! Only the native siphon-rtp engine mixes: rtpengine and rtpproxy have no
//! room to seat a call in, so every verb here answers
//! [`RtpEngineError::Unsupported`] on them rather than a hollow success.
//!
//! A seat is recorded under the SIP Call-ID of the call it seats, because that
//! is all a teardown has: `rtpengine.delete(call)` and the dispatcher's own
//! deletes name a call, and a room seat is no call the engine knows (its call
//! registry never holds one, so a `delete` answers `unknown call` and the seat
//! would stay in the mix until the idle reaper found it). [`MediaBackend::delete`]
//! looks here first and leaves the room instead.

use std::sync::LazyLock;

use dashmap::DashMap;
use tracing::debug;

use super::MediaBackend;
use crate::rtpengine::client::PlayMediaSource;
use crate::rtpengine::error::RtpEngineError;
use crate::rtpengine::profile::NgFlags;
use crate::rtpengine::siphon_rtp::PlayMediaOutcome;
// The routing matrix and the bridge direction are the engine contract's own
// types, for the reason `X3TargetLeg` is: a local twin would only add a
// conversion that could be wrong, and a wrong role seats a participant with the
// wrong audience.
pub use siphon_rtp_proto::{BridgeDirection, ConferenceRole, PlayRepeat};

/// A seat this process holds: which room, and the from-tag the engine knows
/// the participant by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConferenceSeat {
    pub conference_id: String,
    pub from_tag: String,
}

/// Seats by the SIP Call-ID of the call seated. Written by a join that the
/// engine accepted and cleared by every leave, so it cannot outgrow the seats.
static SEATS: LazyLock<DashMap<String, ConferenceSeat>> = LazyLock::new(DashMap::new);

/// Calls whose leg `conference_seat` moved into a room (`b2bua.adopt_replaced`),
/// by engine call-id, with the room. Unlike a [`ConferenceSeat`] such a seat is
/// still a call the engine holds, so its teardown is the call's own `delete`;
/// this is kept only so a room this process still has a seat in keeps its
/// instance. Written by an accepted seat and cleared by the call's delete.
static SEATED_CALLS: LazyLock<DashMap<String, String>> = LazyLock::new(DashMap::new);

/// What the engine says when the seat it is asked to free is not there.
const NO_SUCH_PARTICIPANT: &str = "no such conference participant";

impl MediaBackend {
    /// The seat the call `call_id` holds, if it holds one.
    pub fn conference_seat(call_id: &str) -> Option<ConferenceSeat> {
        SEATS.get(call_id).map(|seat| seat.clone())
    }

    /// The room the engine call `engine_call_id` has a leg seated in, when
    /// [`Self::conference_seat_call`] seated one.
    pub fn seated_call_room(engine_call_id: &str) -> Option<String> {
        SEATED_CALLS.get(engine_call_id).map(|room| room.clone())
    }

    /// Whether this process still knows of a seat in `conference_id`, a
    /// joined one or a seated call's.
    fn room_has_seats(conference_id: &str) -> bool {
        SEATS.iter().any(|held| held.conference_id == conference_id)
            || SEATED_CALLS
                .iter()
                .any(|room| room.value() == conference_id)
    }

    /// Move the leg `from_tag` of the live engine call `engine_call_id` into
    /// `conference_id` in place (siphon-rtp `conference_seat`). No SDP is
    /// exchanged; the call stays the engine's, one-legged, until its `delete`.
    /// A backend with no mixer, or an engine that does not list the verb, is
    /// [`RtpEngineError::Unsupported`]; the engine's own refusal is
    /// [`RtpEngineError::EngineError`] and leaves the call relaying as it was.
    pub async fn conference_seat_call(
        &self,
        engine_call_id: &str,
        from_tag: &str,
        conference_id: &str,
        role: ConferenceRole,
    ) -> Result<(), RtpEngineError> {
        let Self::SiphonRtp(set) = self else {
            return Err(self.no_mixer("conference_seat"));
        };
        set.conference_seat(engine_call_id, from_tag, conference_id, role)
            .await?;
        SEATED_CALLS.insert(engine_call_id.to_string(), conference_id.to_string());
        Ok(())
    }

    /// The engine call `engine_call_id` is being deleted: its seat goes with
    /// it, and a room this process then has no seat in forgets its instance.
    pub(super) fn seated_call_deleted(&self, engine_call_id: &str) {
        let Some((_, room)) = SEATED_CALLS.remove(engine_call_id) else {
            return;
        };
        if let Self::SiphonRtp(set) = self {
            if !Self::room_has_seats(&room) {
                set.forget_room(&room);
            }
        }
    }

    /// The refusal for a backend that has no conference mixer.
    fn no_mixer(&self, operation: &'static str) -> RtpEngineError {
        RtpEngineError::Unsupported {
            operation,
            backend: self.kind().as_str(),
        }
    }

    /// Seat the call `call_id` in a room under `from_tag`, answering its offer.
    pub async fn conference_join(
        &self,
        call_id: &str,
        seat: ConferenceSeat,
        offer_sdp: &str,
        role: ConferenceRole,
        flags: &NgFlags,
    ) -> Result<String, RtpEngineError> {
        let Self::SiphonRtp(set) = self else {
            return Err(self.no_mixer("conference_join"));
        };
        let answer = set
            .conference_join(&seat.conference_id, &seat.from_tag, offer_sdp, role, flags)
            .await?;
        SEATS.insert(call_id.to_string(), seat);
        Ok(answer)
    }

    /// Free a seat. A seat this process recorded that the engine no longer has
    /// (its idle reaper takes a silent seat and says nothing) has left all the
    /// same, so that is not an error; a seat nobody recorded is.
    pub async fn conference_leave(
        &self,
        call_id: &str,
        seat: &ConferenceSeat,
    ) -> Result<(), RtpEngineError> {
        let Self::SiphonRtp(set) = self else {
            return Err(self.no_mixer("conference_leave"));
        };
        let recorded = SEATS.get(call_id).is_some_and(|held| *held == *seat);
        let outcome = match set
            .conference_leave(&seat.conference_id, &seat.from_tag)
            .await
        {
            Err(RtpEngineError::EngineError(reason))
                if recorded && reason.contains(NO_SUCH_PARTICIPANT) =>
            {
                debug!(
                    %call_id,
                    conference_id = %seat.conference_id,
                    from_tag = %seat.from_tag,
                    "conference seat already released by the media engine"
                );
                Ok(())
            }
            other => other,
        };
        // Kept on any other failure: the engine may still hold the seat, and a
        // later leave or delete must still find it.
        if outcome.is_ok() {
            SEATS.remove_if(call_id, |_, held| held == seat);
            if !Self::room_has_seats(&seat.conference_id) {
                set.forget_room(&seat.conference_id);
            }
        }
        outcome
    }

    /// Leave the room the call `call_id` is seated in, for a teardown that
    /// names the call. `None` when it holds no seat; otherwise the leave's
    /// outcome, and whether the call also has an engine call of its own that
    /// still needs its `delete`.
    pub(super) async fn leave_seat_of(
        &self,
        call_id: &str,
    ) -> Option<(Result<(), RtpEngineError>, bool)> {
        let seat = Self::conference_seat(call_id)?;
        let left = self.conference_leave(call_id, &seat).await;
        let holds_call = match self {
            Self::SiphonRtp(set) => set.holds_call(call_id),
            Self::RtpEngine(_) | Self::RtpProxy(_) => false,
        };
        Some((left, holds_call))
    }

    /// Change a seat's role live.
    pub async fn conference_route(
        &self,
        seat: &ConferenceSeat,
        role: ConferenceRole,
    ) -> Result<(), RtpEngineError> {
        match self {
            Self::SiphonRtp(set) => {
                set.conference_route(&seat.conference_id, &seat.from_tag, role)
                    .await
            }
            Self::RtpEngine(_) | Self::RtpProxy(_) => Err(self.no_mixer("conference_route")),
        }
    }

    /// Link two rooms.
    pub async fn conference_bridge(
        &self,
        conference_id_a: &str,
        conference_id_b: &str,
        direction: BridgeDirection,
    ) -> Result<(), RtpEngineError> {
        match self {
            Self::SiphonRtp(set) => {
                set.conference_bridge(conference_id_a, conference_id_b, direction)
                    .await
            }
            Self::RtpEngine(_) | Self::RtpProxy(_) => Err(self.no_mixer("conference_bridge")),
        }
    }

    /// Unlink two rooms.
    pub async fn conference_unbridge(
        &self,
        conference_id_a: &str,
        conference_id_b: &str,
    ) -> Result<(), RtpEngineError> {
        match self {
            Self::SiphonRtp(set) => {
                set.conference_unbridge(conference_id_a, conference_id_b)
                    .await
            }
            Self::RtpEngine(_) | Self::RtpProxy(_) => Err(self.no_mixer("conference_unbridge")),
        }
    }

    /// Offer a seat for a participant the focus calls out, under `seat`'s
    /// from-tag. Nothing is recorded until the answer seats it: an offered
    /// seat no answer reaches is the engine's to expire.
    pub async fn conference_offer(
        &self,
        seat: &ConferenceSeat,
        role: ConferenceRole,
        flags: &NgFlags,
    ) -> Result<String, RtpEngineError> {
        let Self::SiphonRtp(set) = self else {
            return Err(self.no_mixer("conference_offer"));
        };
        set.conference_offer(&seat.conference_id, &seat.from_tag, role, flags)
            .await
    }

    /// Seat an offered seat on the participant's answer, recording it under
    /// the SIP Call-ID of the call that carried the offer, so that call's
    /// teardown leaves the room.
    pub async fn conference_answer(
        &self,
        call_id: &str,
        seat: ConferenceSeat,
        answer_sdp: &str,
    ) -> Result<(), RtpEngineError> {
        let Self::SiphonRtp(set) = self else {
            return Err(self.no_mixer("conference_answer"));
        };
        set.conference_answer(&seat.conference_id, &seat.from_tag, answer_sdp)
            .await?;
        SEATS.insert(call_id.to_string(), seat);
        Ok(())
    }

    /// Play audio into a room.
    pub async fn conference_play(
        &self,
        conference_id: &str,
        source: &PlayMediaSource,
        repeat_times: Option<PlayRepeat>,
        start_pos_ms: Option<u64>,
        duration_ms: Option<u64>,
        gain_decibels: Option<i32>,
    ) -> Result<PlayMediaOutcome, RtpEngineError> {
        match self {
            Self::SiphonRtp(set) => {
                set.conference_play(
                    conference_id,
                    source,
                    repeat_times,
                    start_pos_ms,
                    duration_ms,
                    gain_decibels,
                )
                .await
            }
            Self::RtpEngine(_) | Self::RtpProxy(_) => Err(self.no_mixer("conference_play")),
        }
    }

    /// Stop one room playback, or all of them.
    pub async fn conference_stop_play(
        &self,
        conference_id: &str,
        play_id: Option<u64>,
    ) -> Result<(), RtpEngineError> {
        match self {
            Self::SiphonRtp(set) => set.conference_stop_play(conference_id, play_id).await,
            Self::RtpEngine(_) | Self::RtpProxy(_) => Err(self.no_mixer("conference_stop_play")),
        }
    }

    /// Retune a running room playback.
    pub async fn conference_set_play_gain(
        &self,
        conference_id: &str,
        play_id: u64,
        gain_decibels: i32,
    ) -> Result<(), RtpEngineError> {
        match self {
            Self::SiphonRtp(set) => {
                set.conference_set_play_gain(conference_id, play_id, gain_decibels)
                    .await
            }
            Self::RtpEngine(_) | Self::RtpProxy(_) => {
                Err(self.no_mixer("conference_set_play_gain"))
            }
        }
    }

    /// Record a room's listener mix to a WAV; the engine's `recording_id`.
    pub async fn conference_start_recording(
        &self,
        conference_id: &str,
        path: Option<&str>,
        max_duration_ms: Option<u64>,
        silence_ms: Option<u64>,
    ) -> Result<String, RtpEngineError> {
        match self {
            Self::SiphonRtp(set) => {
                set.conference_start_recording(conference_id, path, max_duration_ms, silence_ms)
                    .await
            }
            Self::RtpEngine(_) | Self::RtpProxy(_) => {
                Err(self.no_mixer("conference_start_recording"))
            }
        }
    }

    /// Stop one room recording, or every recording of the room.
    pub async fn conference_stop_recording(
        &self,
        conference_id: &str,
        recording_id: Option<&str>,
    ) -> Result<(), RtpEngineError> {
        match self {
            Self::SiphonRtp(set) => {
                set.conference_stop_recording(conference_id, recording_id)
                    .await
            }
            Self::RtpEngine(_) | Self::RtpProxy(_) => {
                Err(self.no_mixer("conference_stop_recording"))
            }
        }
    }

    /// Wait until a room recording has ended and its file is closed, at most
    /// `deadline`. `Ok(None)` when it had not.
    pub async fn conference_wait_recording(
        &self,
        conference_id: &str,
        recording_id: &str,
        deadline: std::time::Duration,
    ) -> Result<Option<crate::rtpengine::events::RecordingFinished>, RtpEngineError> {
        match self {
            Self::SiphonRtp(set) => Ok(set
                .conference_wait_recording(conference_id, recording_id, deadline)
                .await),
            Self::RtpEngine(_) | Self::RtpProxy(_) => {
                Err(self.no_mixer("conference_wait_recording"))
            }
        }
    }
}

#[cfg(test)]
mod tests;
