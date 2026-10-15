//! The conference verbs of the `rtpengine` namespace: seating a script's calls
//! in the media engine's mixing rooms.
//!
//! A script that is the far side of a call (a conference focus, RFC 4579)
//! answers the participant's INVITE itself, as with `answer_local`, except
//! that the engine seats the participant in a room instead of answering it
//! alone: the answer SDP comes from the engine, and the participant hears
//! everyone else in the room. siphon-rtp is the only backend that mixes; the
//! others answer "not supported by this media backend".
//!
//! A seat is addressed by the participant's From-tag, the name the engine
//! keys it by and the one `@rtpengine.on_active_speaker` and a room's
//! `@rtpengine.on_dtmf` hand back. The backend records it under the call's
//! SIP Call-ID, so `rtpengine.delete(call)` on a seated call leaves its room.

use std::sync::Arc;

use pyo3::prelude::*;
use tracing::debug;

use crate::rtpengine::backend::{BridgeDirection, ConferenceRole, ConferenceSeat};
use crate::rtpengine::profile::NgFlags;
use crate::rtpengine::{MediaBackend, RtpEngineError};

use super::{
    extract_message, extract_offer_params, extract_source_ip, finalise_flags, repeat,
    resolve_answer_profile, resolve_call_from_tag, resolve_play_media_source, MediaOverrides,
    PyRtpEngine,
};

/// The routing matrix a seat can take (siphon-rtp's `role`): who it hears and
/// who hears it.
const ROLES: &str = "talker, listener, muted, whisper, monitor";

/// Read `role=` (with its `target=` / `whisper_target=`) into the engine's
/// routing role. A role that needs a target and lacks one, or one given a
/// target it has no use for, is refused rather than guessed at: a seat with
/// the wrong audience is a privacy failure, not a degraded call.
pub(super) fn parse_role(
    role: &str,
    target: Option<String>,
    whisper_target: Option<String>,
) -> PyResult<ConferenceRole> {
    let refuse = |message: String| Err(pyo3::exceptions::PyValueError::new_err(message));
    let parsed = match (role, target) {
        ("whisper", Some(target)) if whisper_target.is_none() => ConferenceRole::Whisper { target },
        ("monitor", Some(target)) => ConferenceRole::Monitor {
            target,
            whisper_target,
        },
        ("whisper" | "monitor", None) => {
            return refuse(format!(
                "role {role:?} needs target= (the seat's from-tag it applies to)"
            ))
        }
        ("talker", None) if whisper_target.is_none() => ConferenceRole::Talker,
        ("listener", None) if whisper_target.is_none() => ConferenceRole::Listener,
        ("muted", None) if whisper_target.is_none() => ConferenceRole::Muted,
        ("talker" | "listener" | "muted" | "whisper", _) => {
            return refuse(format!(
                "role {role:?} takes no {}",
                if role == "whisper" {
                    "whisper_target="
                } else {
                    "target= or whisper_target="
                }
            ))
        }
        _ => return refuse(format!("role must be one of {ROLES}, got {role:?}")),
    };
    Ok(parsed)
}

/// Read `direction=` of a bridge.
pub(super) fn parse_direction(direction: &str) -> PyResult<BridgeDirection> {
    match direction {
        "both" => Ok(BridgeDirection::Both),
        "a_to_b" => Ok(BridgeDirection::AToB),
        "b_to_a" => Ok(BridgeDirection::BToA),
        other => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "direction must be one of both, a_to_b, b_to_a, got {other:?}"
        ))),
    }
}

/// Refuse an empty room id before it reaches the engine.
fn room_id(conference_id: String, argument: &str) -> PyResult<String> {
    if conference_id.is_empty() {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "rtpengine.{argument} is empty"
        )));
    }
    Ok(conference_id)
}

/// The seat a verb addresses: a `Request` / `Call` names it by its Call-ID and
/// From-tag, and a `(call_id, from_tag)` pair (what an event handler holds)
/// does the same. A bare string names no seat.
fn seat_of(conference_id: String, target: &Bound<'_, PyAny>) -> PyResult<(String, ConferenceSeat)> {
    let (call_id, from_tag) = resolve_call_from_tag(target)?;
    if from_tag.is_empty() {
        return Err(pyo3::exceptions::PyTypeError::new_err(
            "a conference seat is addressed by a Request/Call or a (call_id, from_tag) pair",
        ));
    }
    Ok((
        call_id,
        ConferenceSeat {
            conference_id,
            from_tag,
        },
    ))
}

/// What a seat does not get from a media profile on siphon-rtp 0.14.0, named
/// so a script is told rather than seated without it. The engine reads a
/// seat's interface (`direction`), ICE / DTLS posture, the `symmetric` flag
/// and the dialog's Call-ID from the profile, and picks the offer's first
/// audio codec itself: a codec policy is not applied to a seat.
fn seat_ignores(flags: &NgFlags) -> Vec<&'static str> {
    let codec_policy =
        !flags.codec.is_empty() || flags.flags.iter().any(|flag| flag.starts_with("codec-"));
    [
        ("a codec policy", codec_policy),
        ("ws_uri", flags.ws_uri.is_some()),
        ("ws_tee", flags.ws_tee.is_some()),
        ("record_call", flags.record_call),
        ("noise_suppression", flags.noise_suppression),
        ("echo_cancellation", flags.echo_cancellation),
        ("beep_detection", flags.beep_detection),
    ]
    .into_iter()
    .filter_map(|(name, set)| set.then_some(name))
    .collect()
}

/// What an offered seat does not get from a media profile: [`seat_ignores`]
/// less the codec policy, which the engine applies to the codecs it offers.
fn offered_seat_ignores(flags: &NgFlags) -> Vec<&'static str> {
    seat_ignores(flags)
        .into_iter()
        .filter(|name| *name != "a codec policy")
        .collect()
}

/// Refuse a seat tag that could not be a From-tag (RFC 3261 §25.1 `token`):
/// the engine keys the seat by it, and the script puts it on the INVITE.
fn seat_tag(tag: String) -> PyResult<String> {
    let token = !tag.is_empty()
        && tag.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~'
                )
        });
    if !token {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "rtpengine.conference_offer(seat_tag) must be a SIP token (a From-tag), got {tag:?}"
        )));
    }
    Ok(tag)
}

/// A join refused because the participant's codec cannot be mixed for it is a
/// `ValueError`, as `answer_local`'s no-encodable-codec is: the script owns the
/// SIP answer (488, RFC 3261 §13.3.1.2). Anything else is a `RuntimeError`.
fn join_failure(error: RtpEngineError) -> PyErr {
    match &error {
        RtpEngineError::EngineError(reason)
            if [
                "has no encoder",
                "offer has no audio codec",
                "conference_join: decoder",
            ]
            .iter()
            .any(|refusal| reason.contains(refusal)) =>
        {
            pyo3::exceptions::PyValueError::new_err(format!(
                "no encodable codec in offer: {reason}"
            ))
        }
        _ => failure("conference_join", error),
    }
}

fn failure(verb: &str, error: RtpEngineError) -> PyErr {
    pyo3::exceptions::PyRuntimeError::new_err(format!("rtpengine.{verb} failed: {error}"))
}

/// `rtpengine.conference_join`.
#[allow(clippy::too_many_arguments)]
pub(super) fn join<'py>(
    engine: &PyRtpEngine,
    python: Python<'py>,
    conference_id: String,
    call: &Bound<'py, PyAny>,
    role: &str,
    target: Option<String>,
    whisper_target: Option<String>,
    profile: Option<&str>,
) -> PyResult<Bound<'py, PyAny>> {
    let conference_id = room_id(conference_id, "conference_join(conference_id)")?;
    let role = parse_role(role, target, whisper_target)?;
    let message = extract_message(call)?;
    let (call_id, from_tag, offer_sdp) = extract_offer_params(&message)?;
    if offer_sdp.is_empty() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "rtpengine.conference_join needs the participant's offer: the message carries no SDP",
        ));
    }
    if let Some(seated) = MediaBackend::conference_seat(&call_id) {
        // The engine refuses a second seat under one from-tag without saying
        // so (it answers the join, then the room declines the seat), and it has
        // no verb that re-seats one in place.
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "call {call_id} is already seated in conference {:?}; conference_leave it first",
            seated.conference_id
        )));
    }

    // The engine is the participant's far side, as on `answer_local`: the
    // profile's answer half shapes what the participant is sent.
    let profile_name = resolve_answer_profile(profile, &engine.sessions, &call_id);
    let entry = engine.registry.get(&profile_name).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err(format!(
            "unknown RTP profile '{profile_name}'; valid profiles: {}",
            engine.registry.profile_names().join(", ")
        ))
    })?;
    let mut flags = finalise_flags(
        entry.answer.clone(),
        &engine.client,
        None,
        MediaOverrides::default(),
        extract_source_ip(call).as_deref(),
        &profile_name,
    )?;
    let ignored = seat_ignores(&flags);
    if !ignored.is_empty() {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "media profile '{profile_name}' sets {}, which siphon-rtp does not apply to a \
             conference seat; join with a profile that leaves {} unset",
            ignored.join(", "),
            if ignored.len() == 1 { "it" } else { "them" }
        )));
    }
    flags.stamp_sip_call_id(&call_id);
    let offer_sdp = String::from_utf8_lossy(&offer_sdp).into_owned();
    let client = Arc::clone(&engine.client);

    pyo3_async_runtimes::tokio::future_into_py(python, async move {
        let seat = ConferenceSeat {
            conference_id,
            from_tag,
        };
        let answer_sdp = client
            .conference_join(&call_id, seat.clone(), &offer_sdp, role, &flags)
            .await
            .map_err(join_failure)?;
        debug!(
            %call_id,
            conference_id = %seat.conference_id,
            from_tag = %seat.from_tag,
            "rtpengine.conference_join: seated"
        );
        Ok(answer_sdp)
    })
}

/// `rtpengine.conference_leave`.
pub(super) fn leave<'py>(
    engine: &PyRtpEngine,
    python: Python<'py>,
    conference_id: String,
    call: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyAny>> {
    let conference_id = room_id(conference_id, "conference_leave(conference_id)")?;
    let (call_id, seat) = seat_of(conference_id, call)?;
    let client = Arc::clone(&engine.client);
    pyo3_async_runtimes::tokio::future_into_py(python, async move {
        client
            .conference_leave(&call_id, &seat)
            .await
            .map_err(|error| failure("conference_leave", error))?;
        debug!(%call_id, conference_id = %seat.conference_id, "rtpengine.conference_leave");
        Ok(true)
    })
}

/// `rtpengine.conference_route`.
pub(super) fn route<'py>(
    engine: &PyRtpEngine,
    python: Python<'py>,
    conference_id: String,
    call: &Bound<'py, PyAny>,
    role: &str,
    target: Option<String>,
    whisper_target: Option<String>,
) -> PyResult<Bound<'py, PyAny>> {
    let conference_id = room_id(conference_id, "conference_route(conference_id)")?;
    let role = parse_role(role, target, whisper_target)?;
    let (_, seat) = seat_of(conference_id, call)?;
    let client = Arc::clone(&engine.client);
    pyo3_async_runtimes::tokio::future_into_py(python, async move {
        client
            .conference_route(&seat, role)
            .await
            .map_err(|error| failure("conference_route", error))?;
        Ok(true)
    })
}

/// `rtpengine.conference_bridge`.
pub(super) fn bridge<'py>(
    engine: &PyRtpEngine,
    python: Python<'py>,
    conference_a: String,
    conference_b: String,
    direction: &str,
) -> PyResult<Bound<'py, PyAny>> {
    let conference_a = room_id(conference_a, "conference_bridge(conference_a)")?;
    let conference_b = room_id(conference_b, "conference_bridge(conference_b)")?;
    if conference_a == conference_b {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "rtpengine.conference_bridge links two rooms; both ids name the same one",
        ));
    }
    let direction = parse_direction(direction)?;
    let client = Arc::clone(&engine.client);
    pyo3_async_runtimes::tokio::future_into_py(python, async move {
        client
            .conference_bridge(&conference_a, &conference_b, direction)
            .await
            .map_err(|error| failure("conference_bridge", error))?;
        Ok(true)
    })
}

/// `rtpengine.conference_unbridge`.
pub(super) fn unbridge<'py>(
    engine: &PyRtpEngine,
    python: Python<'py>,
    conference_a: String,
    conference_b: String,
) -> PyResult<Bound<'py, PyAny>> {
    let conference_a = room_id(conference_a, "conference_unbridge(conference_a)")?;
    let conference_b = room_id(conference_b, "conference_unbridge(conference_b)")?;
    if conference_a == conference_b {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "rtpengine.conference_unbridge unlinks two rooms; both ids name the same one",
        ));
    }
    let client = Arc::clone(&engine.client);
    pyo3_async_runtimes::tokio::future_into_py(python, async move {
        client
            .conference_unbridge(&conference_a, &conference_b)
            .await
            .map_err(|error| failure("conference_unbridge", error))?;
        Ok(true)
    })
}

/// `rtpengine.conference_offer`: resolves to the offer SDP for the INVITE the
/// focus sends a participant it calls out.
#[allow(clippy::too_many_arguments)]
pub(super) fn offer<'py>(
    engine: &PyRtpEngine,
    python: Python<'py>,
    conference_id: String,
    seat_tag_value: String,
    role: &str,
    target: Option<String>,
    whisper_target: Option<String>,
    profile: Option<&str>,
) -> PyResult<Bound<'py, PyAny>> {
    let conference_id = room_id(conference_id, "conference_offer(conference_id)")?;
    let from_tag = seat_tag(seat_tag_value)?;
    let role = parse_role(role, target, whisper_target)?;
    // The engine is the offerer toward the participant, the far side of the
    // call the focus places: the profile's offer half shapes what it is sent.
    let profile_name = profile.unwrap_or(super::DEFAULT_PROFILE).to_string();
    let entry = engine.registry.get(&profile_name).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err(format!(
            "unknown RTP profile '{profile_name}'; valid profiles: {}",
            engine.registry.profile_names().join(", ")
        ))
    })?;
    let flags = finalise_flags(
        entry.offer.clone(),
        &engine.client,
        None,
        MediaOverrides::default(),
        None,
        &profile_name,
    )?;
    let ignored = offered_seat_ignores(&flags);
    if !ignored.is_empty() {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "media profile '{profile_name}' sets {}, which siphon-rtp does not apply to a \
             conference seat; offer with a profile that leaves {} unset",
            ignored.join(", "),
            if ignored.len() == 1 { "it" } else { "them" }
        )));
    }
    let client = Arc::clone(&engine.client);
    pyo3_async_runtimes::tokio::future_into_py(python, async move {
        let seat = ConferenceSeat {
            conference_id,
            from_tag,
        };
        let offer_sdp = client
            .conference_offer(&seat, role, &flags)
            .await
            .map_err(|error| failure("conference_offer", error))?;
        debug!(
            conference_id = %seat.conference_id,
            from_tag = %seat.from_tag,
            "rtpengine.conference_offer: seat offered"
        );
        Ok(offer_sdp)
    })
}

/// `rtpengine.conference_answer`: seat the participant on its answer.
pub(super) fn answer<'py>(
    engine: &PyRtpEngine,
    python: Python<'py>,
    conference_id: String,
    call: &Bound<'py, PyAny>,
    answer_sdp: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyAny>> {
    let conference_id = room_id(conference_id, "conference_answer(conference_id)")?;
    let (call_id, seat) = seat_of(conference_id, call)?;
    let answer_sdp = super::super::request::extract_body_bytes(answer_sdp)?;
    if answer_sdp.is_empty() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "rtpengine.conference_answer needs the participant's answer SDP",
        ));
    }
    let answer_sdp = String::from_utf8_lossy(&answer_sdp).into_owned();
    let client = Arc::clone(&engine.client);
    pyo3_async_runtimes::tokio::future_into_py(python, async move {
        client
            .conference_answer(&call_id, seat.clone(), &answer_sdp)
            .await
            .map_err(|error| match &error {
                RtpEngineError::EngineError(_) => pyo3::exceptions::PyValueError::new_err(format!(
                    "rtpengine.conference_answer refused: {error}"
                )),
                _ => failure("conference_answer", error),
            })?;
        debug!(
            %call_id,
            conference_id = %seat.conference_id,
            from_tag = %seat.from_tag,
            "rtpengine.conference_answer: seated"
        );
        Ok(true)
    })
}

/// `rtpengine.conference_play`: resolves to the playback's `play_id`.
#[allow(clippy::too_many_arguments)]
pub(super) fn play<'py>(
    engine: &PyRtpEngine,
    python: Python<'py>,
    conference_id: String,
    file: Option<String>,
    blob: Option<Vec<u8>>,
    tone: Option<String>,
    repeat: Option<Bound<'py, PyAny>>,
    start_ms: Option<u64>,
    duration_ms: Option<u64>,
    gain_decibels: Option<i32>,
) -> PyResult<Bound<'py, PyAny>> {
    let conference_id = room_id(conference_id, "conference_play(conference_id)")?;
    // No `url=` and no `db_id=`: siphon-rtp plays a file, a blob or a tone into
    // a room and refuses any other source there.
    let source = resolve_play_media_source(file, blob, None, tone, None)?;
    let repeat = repeat::parse_repeat(repeat.as_ref())?;
    let client = Arc::clone(&engine.client);
    pyo3_async_runtimes::tokio::future_into_py(python, async move {
        let outcome = client
            .conference_play(
                &conference_id,
                &source,
                repeat,
                start_ms,
                duration_ms,
                gain_decibels,
            )
            .await
            .map_err(|error| failure("conference_play", error))?;
        debug!(%conference_id, play_id = ?outcome.play_id, "rtpengine.conference_play");
        Ok(outcome.play_id)
    })
}

/// `rtpengine.conference_stop_play`.
pub(super) fn stop_play<'py>(
    engine: &PyRtpEngine,
    python: Python<'py>,
    conference_id: String,
    play_id: Option<u64>,
) -> PyResult<Bound<'py, PyAny>> {
    let conference_id = room_id(conference_id, "conference_stop_play(conference_id)")?;
    let client = Arc::clone(&engine.client);
    pyo3_async_runtimes::tokio::future_into_py(python, async move {
        client
            .conference_stop_play(&conference_id, play_id)
            .await
            .map_err(|error| failure("conference_stop_play", error))?;
        Ok(true)
    })
}

/// `rtpengine.conference_set_play_gain`.
pub(super) fn set_play_gain<'py>(
    engine: &PyRtpEngine,
    python: Python<'py>,
    conference_id: String,
    play_id: u64,
    gain_decibels: i32,
) -> PyResult<Bound<'py, PyAny>> {
    let conference_id = room_id(conference_id, "conference_set_play_gain(conference_id)")?;
    let client = Arc::clone(&engine.client);
    pyo3_async_runtimes::tokio::future_into_py(python, async move {
        client
            .conference_set_play_gain(&conference_id, play_id, gain_decibels)
            .await
            .map_err(|error| failure("conference_set_play_gain", error))?;
        Ok(true)
    })
}

#[cfg(test)]
mod tests;
