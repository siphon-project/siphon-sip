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

/// What the engine says when the seat it is asked to free is not there.
const NO_SUCH_PARTICIPANT: &str = "no such conference participant";

impl MediaBackend {
    /// The seat the call `call_id` holds, if it holds one.
    pub fn conference_seat(call_id: &str) -> Option<ConferenceSeat> {
        SEATS.get(call_id).map(|seat| seat.clone())
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
            if !SEATS
                .iter()
                .any(|held| held.conference_id == seat.conference_id)
            {
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
}

#[cfg(test)]
mod tests;
