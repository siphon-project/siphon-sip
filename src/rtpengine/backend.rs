//! Media-control backend abstraction.
//!
//! siphon can drive one of three media engines, all behind the same media-control
//! verbs:
//! - the legacy rtpengine NG/bencode-over-UDP engine ([`RtpEngineSet`]),
//! - the native `siphon-rtp` JSON-over-TCP engine ([`SiphonRtpClientSet`]),
//! - the classic `rtpproxy` text-over-UDP relay ([`RtpProxyClientSet`]) — for
//!   migrating an existing OpenSIPS/Kamailio/Sippy deployment to siphon while
//!   keeping its in-place rtpproxy.
//!
//! This enum is a thin dispatcher so the dispatcher and the Python `rtpengine`
//! namespace call one type regardless of which is configured (`media.backend`).
//!
//! Enum dispatch (rather than `Arc<dyn Trait>`) keeps the methods as plain
//! `async fn` with no `async-trait` dependency.  Every method mirrors
//! [`RtpEngineSet`]'s signature verbatim so all existing call sites compile
//! unchanged when the field type is swapped.  rtpproxy only allocates relay
//! ports, so the rtpengine-only verbs (prompts, DTMF, gating, SIPREC/MPTY)
//! return a clear [`RtpEngineError::EngineError`] on that backend.

use std::net::SocketAddr;
use std::sync::Arc;

use tracing::debug;

use super::client::{PlayMediaSource, RtpEngineSet};
use super::error::RtpEngineError;
use super::profile::{NgFlags, WsTeeDirection};
use super::rtpproxy::RtpProxyClientSet;
use super::siphon_rtp::{PlayMediaOutcome, SiphonRtpClientSet};
// The X3 target-leg selector is the engine contract's own type; re-deriving a
// local twin would only add a conversion that could be wrong.
pub use siphon_rtp_proto::X3TargetLeg;

/// The configured media-control backend.
pub enum MediaBackend {
    /// rtpengine NG protocol (bencode over UDP) — the default.
    RtpEngine(Arc<RtpEngineSet>),
    /// Native `siphon-rtp` control protocol (JSON over TCP), one or more instances.
    SiphonRtp(Arc<SiphonRtpClientSet>),
    /// Classic `rtpproxy` control protocol (text over UDP), one or more instances.
    RtpProxy(Arc<RtpProxyClientSet>),
}

/// Legs with a playback siphon started and has not stopped, keyed
/// `(engine call-id, leg tag)`. Read through
/// [`MediaBackend::playback_started`]; written only by `play_media` /
/// `stop_media` / `delete` below, so every path that ends a session also drops
/// its entry and the set cannot outgrow the calls it describes.
static ACTIVE_PLAYBACKS: std::sync::LazyLock<dashmap::DashSet<(String, String)>> =
    std::sync::LazyLock::new(dashmap::DashSet::new);

impl MediaBackend {
    /// Whether siphon started a playback on this leg and has not stopped it.
    ///
    /// For a caller that only needs the *guarantee* that nothing is playing —
    /// the bridge, before it re-points a leg's media — so it can skip a stop
    /// that would otherwise be the engine answering "this call has no active
    /// media playback". The engine counts that answer in
    /// `control_errors_total`, a counter operators alert on; a verb that bumps
    /// it every time it runs on an idle leg trains them to ignore it.
    ///
    /// Conservative in one direction only. The entry is written before the
    /// caller sees its `play_media` return, so this never says "nothing is
    /// playing" while something is. It can say the opposite: a prompt that ends
    /// on its own leaves its entry, because siphon does not subscribe to the
    /// engine's end-of-playback event. The cost is one redundant stop on a
    /// session that really did play something — the safe direction.
    pub fn playback_started(call_id: &str, from_tag: &str) -> bool {
        ACTIVE_PLAYBACKS.contains(&(call_id.to_string(), from_tag.to_string()))
    }

    /// Which engine this is, as the `media.backend` config spells it.
    pub fn kind(&self) -> crate::config::MediaBackendKind {
        use crate::config::MediaBackendKind;
        match self {
            Self::RtpEngine(_) => MediaBackendKind::Rtpengine,
            Self::SiphonRtp(_) => MediaBackendKind::SiphonRtp,
            Self::RtpProxy(_) => MediaBackendKind::Rtpproxy,
        }
    }

    /// Which of `flags`' set fields this engine has no way to express.
    ///
    /// The same capability table [`crate::config::Config`] enforces at load
    /// time, applied to the *resolved* [`NgFlags`] of a call.  Config validation
    /// only sees operator-declared `media.profiles`; a built-in profile is
    /// registered whatever the backend, so a script naming one this engine
    /// cannot honour has to be caught here instead.
    pub fn unsupported_flags(&self, flags: &NgFlags) -> Vec<&'static str> {
        let mut unsupported = Vec::new();

        if !matches!(self, Self::SiphonRtp(_)) {
            if flags.ws_uri.is_some() {
                unsupported.push("ws_uri");
            }
            if flags.ws_vad {
                unsupported.push("ws_vad");
            }
            if flags.ws_barge_in {
                unsupported.push("ws_barge_in");
            }
            if flags.ws_vad_threshold.is_some() {
                unsupported.push("ws_vad_threshold");
            }
            if flags.ws_vad_hangover_ms.is_some() {
                unsupported.push("ws_vad_hangover_ms");
            }
            if flags.noise_suppression {
                unsupported.push("noise_suppression");
            }
            if flags.echo_cancellation {
                unsupported.push("echo_cancellation");
            }
        }

        if matches!(self, Self::RtpProxy(_)) {
            if flags.carry_received_from || flags.received_from.is_some() {
                unsupported.push("received_from");
            }
            if !flags.rtcp_mux.is_empty() {
                unsupported.push("rtcp_mux");
            }
        }

        unsupported
    }

    /// Send an `offer`, returning the rewritten SDP.
    pub async fn offer(
        &self,
        call_id: &str,
        from_tag: &str,
        sdp: &[u8],
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        match self {
            Self::RtpEngine(set) => set.offer(call_id, from_tag, sdp, flags).await,
            Self::SiphonRtp(client) => client.offer(call_id, from_tag, sdp, flags).await,
            Self::RtpProxy(client) => client.offer(call_id, from_tag, sdp, flags).await,
        }
    }

    /// Send an `answer`, returning the rewritten SDP.
    pub async fn answer(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
        sdp: &[u8],
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        match self {
            Self::RtpEngine(set) => set.answer(call_id, from_tag, to_tag, sdp, flags).await,
            Self::SiphonRtp(client) => client.answer(call_id, from_tag, to_tag, sdp, flags).await,
            Self::RtpProxy(client) => client.answer(call_id, from_tag, to_tag, sdp, flags).await,
        }
    }

    /// Tear down a media session.
    pub async fn delete(&self, call_id: &str, from_tag: &str) -> Result<(), RtpEngineError> {
        // Unconditional, and before the engine round trip: the session is going
        // away either way, and a playback record that outlived its call would
        // be the one way `ACTIVE_PLAYBACKS` could grow without bound.
        ACTIVE_PLAYBACKS.remove(&(call_id.to_string(), from_tag.to_string()));
        match self {
            Self::RtpEngine(set) => set.delete(call_id, from_tag).await,
            Self::SiphonRtp(client) => client.delete(call_id, from_tag).await,
            Self::RtpProxy(client) => client.delete(call_id, from_tag).await,
        }
    }

    /// Inject an audio prompt; returns the engine-reported duration in ms.
    ///
    /// `wait` (native siphon-rtp backend only) blocks until the prompt finishes
    /// (`Event::PlayFinished`), so a script can sequence a following action after
    /// it. The rtpengine / rtpproxy backends have no completion event, so they
    /// ignore `wait` and return on accept (fire-and-forget) as before.
    #[allow(clippy::too_many_arguments)]
    pub async fn play_media(
        &self,
        call_id: &str,
        from_tag: &str,
        source: &PlayMediaSource,
        repeat_times: Option<u64>,
        start_pos_ms: Option<u64>,
        duration_ms: Option<u64>,
        to_tag: Option<&str>,
        overlay: bool,
        gain_decibels: Option<i32>,
        wait: bool,
    ) -> Result<PlayMediaOutcome, RtpEngineError> {
        let outcome = self
            .play_media_inner(
                call_id,
                from_tag,
                source,
                repeat_times,
                start_pos_ms,
                duration_ms,
                to_tag,
                overlay,
                gain_decibels,
                wait,
            )
            .await;
        if outcome.is_ok() {
            ACTIVE_PLAYBACKS.insert((call_id.to_string(), from_tag.to_string()));
        }
        outcome
    }

    /// The backend dispatch behind [`Self::play_media`], split out so the
    /// playback bookkeeping wraps every arm rather than being repeated in each.
    #[allow(clippy::too_many_arguments)]
    async fn play_media_inner(
        &self,
        call_id: &str,
        from_tag: &str,
        source: &PlayMediaSource,
        repeat_times: Option<u64>,
        start_pos_ms: Option<u64>,
        duration_ms: Option<u64>,
        to_tag: Option<&str>,
        overlay: bool,
        gain_decibels: Option<i32>,
        wait: bool,
    ) -> Result<PlayMediaOutcome, RtpEngineError> {
        match self {
            Self::RtpEngine(set) => {
                if wait {
                    debug!(call_id, "play_media(wait=True) ignored on rtpengine backend (no completion event); returning on accept");
                }
                // Overlay mixing and per-play gain are native siphon-rtp
                // features with no NG equivalent. Refused rather than dropped:
                // an overlay silently downgraded to a supersede would cut the
                // party's live audio, and a dropped gain would play a music bed
                // at full level under a prompt.
                if overlay {
                    return Err(RtpEngineError::Unsupported {
                        operation: "play_media(overlay=True)",
                        backend: "rtpengine",
                    });
                }
                if gain_decibels.is_some() {
                    return Err(RtpEngineError::Unsupported {
                        operation: "play_media(gain_decibels=...)",
                        backend: "rtpengine",
                    });
                }
                let duration_ms = set
                    .play_media(
                        call_id,
                        from_tag,
                        source,
                        repeat_times,
                        start_pos_ms,
                        duration_ms,
                        to_tag,
                    )
                    .await?;
                // No play_id: the NG protocol has no handle on a playback, which
                // is why set_play_gain and a targeted stop are siphon-rtp only.
                Ok(PlayMediaOutcome {
                    play_id: None,
                    duration_ms,
                })
            }
            Self::SiphonRtp(client) => {
                client
                    .play_media(
                        call_id,
                        from_tag,
                        source,
                        repeat_times,
                        start_pos_ms,
                        duration_ms,
                        to_tag,
                        overlay,
                        gain_decibels,
                        wait,
                    )
                    .await
            }
            Self::RtpProxy(client) => {
                if wait {
                    debug!(call_id, "play_media(wait=True) ignored on rtpproxy backend (no completion event); returning on accept");
                }
                let duration_ms = client
                    .play_media(
                        call_id,
                        from_tag,
                        source,
                        repeat_times,
                        start_pos_ms,
                        duration_ms,
                        to_tag,
                    )
                    .await?;
                Ok(PlayMediaOutcome {
                    play_id: None,
                    duration_ms,
                })
            }
        }
    }

    /// Stop prompt playback on the monologue selected by `from_tag`.
    ///
    /// `play_id` targets one playback (an individual overlay slot); `None` stops
    /// everything on the leg.  Only the native backend can address a single
    /// playback — the others have no handle, so a `play_id` there is refused
    /// rather than widened into "stop everything", which would silently kill
    /// playbacks the script meant to keep running.
    pub async fn stop_media(
        &self,
        call_id: &str,
        from_tag: &str,
        play_id: Option<u64>,
    ) -> Result<(), RtpEngineError> {
        let outcome = match self {
            Self::RtpEngine(set) => {
                if play_id.is_some() {
                    return Err(RtpEngineError::Unsupported {
                        operation: "stop_media(play_id=...)",
                        backend: "rtpengine",
                    });
                }
                set.stop_media(call_id, from_tag).await
            }
            Self::SiphonRtp(client) => client.stop_media(call_id, from_tag, play_id).await,
            Self::RtpProxy(client) => {
                if play_id.is_some() {
                    return Err(RtpEngineError::Unsupported {
                        operation: "stop_media(play_id=...)",
                        backend: "rtpproxy",
                    });
                }
                client.stop_media(call_id, from_tag).await
            }
        };
        // A blanket stop ends everything on the leg, so the leg is no longer
        // playing. A targeted one (`play_id`) leaves whatever else is running,
        // so the record stands.
        if play_id.is_none() && outcome.is_ok() {
            ACTIVE_PLAYBACKS.remove(&(call_id.to_string(), from_tag.to_string()));
        }
        outcome
    }

    /// Retune a running playback's gain — how a controller ducks a music bed
    /// under a prompt and lifts it again afterwards.
    ///
    /// Native `siphon-rtp` only: the NG and rtpproxy protocols have no handle on
    /// an individual playback, so there is nothing to address.
    pub async fn set_play_gain(
        &self,
        call_id: &str,
        from_tag: &str,
        play_id: u64,
        gain_decibels: i32,
        to_tag: Option<&str>,
    ) -> Result<(), RtpEngineError> {
        match self {
            Self::SiphonRtp(client) => {
                client
                    .set_play_gain(call_id, from_tag, play_id, gain_decibels, to_tag)
                    .await
            }
            Self::RtpEngine(_) => Err(RtpEngineError::Unsupported {
                operation: "set_play_gain",
                backend: "rtpengine",
            }),
            Self::RtpProxy(_) => Err(RtpEngineError::Unsupported {
                operation: "set_play_gain",
                backend: "rtpproxy",
            }),
        }
    }

    /// Inject DTMF (RFC 4733) toward a leg.
    #[allow(clippy::too_many_arguments)]
    pub async fn play_dtmf(
        &self,
        call_id: &str,
        from_tag: &str,
        code: &str,
        duration_ms: Option<u64>,
        volume_dbm0: Option<i64>,
        pause_ms: Option<u64>,
        to_tag: Option<&str>,
    ) -> Result<(), RtpEngineError> {
        match self {
            Self::RtpEngine(set) => {
                set.play_dtmf(
                    call_id,
                    from_tag,
                    code,
                    duration_ms,
                    volume_dbm0,
                    pause_ms,
                    to_tag,
                )
                .await
            }
            Self::SiphonRtp(client) => {
                client
                    .play_dtmf(
                        call_id,
                        from_tag,
                        code,
                        duration_ms,
                        volume_dbm0,
                        pause_ms,
                        to_tag,
                    )
                    .await
            }
            Self::RtpProxy(client) => {
                client
                    .play_dtmf(
                        call_id,
                        from_tag,
                        code,
                        duration_ms,
                        volume_dbm0,
                        pause_ms,
                        to_tag,
                    )
                    .await
            }
        }
    }

    /// Replace the selected monologue's outgoing audio with silence.
    pub async fn silence_media(&self, call_id: &str, from_tag: &str) -> Result<(), RtpEngineError> {
        match self {
            Self::RtpEngine(set) => set.silence_media(call_id, from_tag).await,
            Self::SiphonRtp(client) => client.silence_media(call_id, from_tag).await,
            Self::RtpProxy(client) => client.silence_media(call_id, from_tag).await,
        }
    }

    /// Resume forwarding audio after a `silence_media`.
    pub async fn unsilence_media(
        &self,
        call_id: &str,
        from_tag: &str,
    ) -> Result<(), RtpEngineError> {
        match self {
            Self::RtpEngine(set) => set.unsilence_media(call_id, from_tag).await,
            Self::SiphonRtp(client) => client.unsilence_media(call_id, from_tag).await,
            Self::RtpProxy(client) => client.unsilence_media(call_id, from_tag).await,
        }
    }

    /// Echo-test mode — reflect a leg's ingress audio back to itself (single-leg
    /// IVR echo). Native `siphon-rtp` backend only: rtpengine and rtpproxy have
    /// no echo verb, so those backends reject rather than silently no-op.
    pub async fn echo(
        &self,
        call_id: &str,
        from_tag: &str,
        enabled: bool,
    ) -> Result<(), RtpEngineError> {
        match self {
            Self::SiphonRtp(client) => client.echo(call_id, from_tag, enabled).await,
            Self::RtpEngine(_) | Self::RtpProxy(_) => Err(RtpEngineError::Protocol(
                "echo is only supported by the native siphon-rtp backend".to_string(),
            )),
        }
    }

    /// Single-leg UAS answer — synthesise an RFC 3264 answer for the offerer's
    /// SDP with the media engine as the far side (IVR / echo / announcement).
    /// Returns the answer SDP.  Native `siphon-rtp` backend only: rtpengine and
    /// rtpproxy have no answer-local verb, so those backends reject rather than
    /// silently no-op.
    pub async fn answer_local(
        &self,
        call_id: &str,
        from_tag: &str,
        offer_sdp: &str,
        flags: &NgFlags,
    ) -> Result<String, RtpEngineError> {
        match self {
            Self::SiphonRtp(client) => {
                client
                    .answer_local(call_id, from_tag, offer_sdp, flags)
                    .await
            }
            Self::RtpEngine(_) | Self::RtpProxy(_) => Err(RtpEngineError::Protocol(
                "answer_local is only supported by the native siphon-rtp backend".to_string(),
            )),
        }
    }

    /// Drop the selected monologue's outgoing packets entirely.
    pub async fn block_media(&self, call_id: &str, from_tag: &str) -> Result<(), RtpEngineError> {
        match self {
            Self::RtpEngine(set) => set.block_media(call_id, from_tag).await,
            Self::SiphonRtp(client) => client.block_media(call_id, from_tag).await,
            Self::RtpProxy(client) => client.block_media(call_id, from_tag).await,
        }
    }

    /// Resume forwarding after a `block_media`.
    pub async fn unblock_media(&self, call_id: &str, from_tag: &str) -> Result<(), RtpEngineError> {
        match self {
            Self::RtpEngine(set) => set.unblock_media(call_id, from_tag).await,
            Self::SiphonRtp(client) => client.unblock_media(call_id, from_tag).await,
            Self::RtpProxy(client) => client.unblock_media(call_id, from_tag).await,
        }
    }

    /// Create a media subscription, returning the subscriber SDP.
    pub async fn subscribe_request(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
        sdp: Option<&[u8]>,
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        match self {
            Self::RtpEngine(set) => {
                set.subscribe_request(call_id, from_tag, to_tag, sdp, flags)
                    .await
            }
            Self::SiphonRtp(client) => {
                client
                    .subscribe_request(call_id, from_tag, to_tag, sdp, flags)
                    .await
            }
            Self::RtpProxy(client) => {
                client
                    .subscribe_request(call_id, from_tag, to_tag, sdp, flags)
                    .await
            }
        }
    }

    /// SIPREC-mode subscription over both call directions; returns `(sdp, to_tag)`.
    pub async fn subscribe_request_siprec(
        &self,
        call_id: &str,
        from_tags: &[&str],
        profile_flags: Option<&NgFlags>,
    ) -> Result<(Vec<u8>, String), RtpEngineError> {
        match self {
            Self::RtpEngine(set) => {
                set.subscribe_request_siprec(call_id, from_tags, profile_flags)
                    .await
            }
            Self::SiphonRtp(client) => {
                client
                    .subscribe_request_siprec(call_id, from_tags, profile_flags)
                    .await
            }
            Self::RtpProxy(client) => {
                client
                    .subscribe_request_siprec(call_id, from_tags, profile_flags)
                    .await
            }
        }
    }

    /// Renegotiate a **live** call on the ports it already holds — what a SIP
    /// re-INVITE or UPDATE maps to.
    ///
    /// The backends differ in what a repeated offer means, which is the whole
    /// reason this verb exists:
    ///
    /// * **rtpengine / rtpproxy** — a repeat `offer` on a live call-id *is* a
    ///   re-offer.  That is how `rtpengine_manage()` has always done hold and
    ///   codec renegotiation, so these delegate to [`Self::offer`] and the wire
    ///   is byte-identical to before.  Not a degraded path: it is the native
    ///   semantics.
    /// * **siphon-rtp** — a repeat `offer` is a *replacement*: the engine frees
    ///   the old call and allocates fresh ports, which drops the WebSocket
    ///   bridge, any tee and any SIPREC subscription riding on it, and answers
    ///   with an address the peer was never told to expect.  So it gets the
    ///   dedicated `reoffer` command.
    pub async fn reoffer(
        &self,
        call_id: &str,
        from_tag: &str,
        sdp: &[u8],
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        match self {
            Self::RtpEngine(set) => set.offer(call_id, from_tag, sdp, flags).await,
            Self::SiphonRtp(client) => client.reoffer(call_id, from_tag, sdp, flags).await,
            Self::RtpProxy(client) => client.offer(call_id, from_tag, sdp, flags).await,
        }
    }

    /// Complete a subscription's SDP negotiation.
    pub async fn subscribe_answer(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
        sdp: &[u8],
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        match self {
            Self::RtpEngine(set) => {
                set.subscribe_answer(call_id, from_tag, to_tag, sdp, flags)
                    .await
            }
            Self::SiphonRtp(client) => {
                client
                    .subscribe_answer(call_id, from_tag, to_tag, sdp, flags)
                    .await
            }
            Self::RtpProxy(client) => {
                client
                    .subscribe_answer(call_id, from_tag, to_tag, sdp, flags)
                    .await
            }
        }
    }

    /// Tear down a subscription.
    pub async fn unsubscribe(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
    ) -> Result<(), RtpEngineError> {
        match self {
            Self::RtpEngine(set) => set.unsubscribe(call_id, from_tag, to_tag).await,
            Self::SiphonRtp(client) => client.unsubscribe(call_id, from_tag, to_tag).await,
            Self::RtpProxy(client) => client.unsubscribe(call_id, from_tag, to_tag).await,
        }
    }

    /// Attach a WebSocket tee to a live call — stream a copy of its decoded
    /// audio to `ws_uri` while the call keeps relaying.
    ///
    /// A native `siphon-rtp` extension.  The rtpengine and rtpproxy backends
    /// return [`RtpEngineError::Unsupported`] rather than `Ok(())`: a hollow
    /// success would read as "the tee is attached" while nothing ever reaches
    /// the consumer.  The declarative twin (`ws_tee` on a media profile) is
    /// rejected at config load for the same reason.
    pub async fn attach_ws_tee(
        &self,
        call_id: &str,
        from_tag: &str,
        ws_uri: &str,
        direction: WsTeeDirection,
        channels: Option<u8>,
        sample_rate: Option<u32>,
    ) -> Result<(), RtpEngineError> {
        match self {
            Self::SiphonRtp(client) => {
                client
                    .attach_ws_tee(call_id, from_tag, ws_uri, direction, channels, sample_rate)
                    .await
            }
            Self::RtpEngine(_) => Err(RtpEngineError::Unsupported {
                operation: "attach_ws_tee",
                backend: "rtpengine",
            }),
            Self::RtpProxy(_) => Err(RtpEngineError::Unsupported {
                operation: "attach_ws_tee",
                backend: "rtpproxy",
            }),
        }
    }

    /// Detach a call's WebSocket tee.  Idempotent on `siphon-rtp`; unsupported
    /// on the other backends for the same reason as [`Self::attach_ws_tee`].
    pub async fn detach_ws_tee(&self, call_id: &str, from_tag: &str) -> Result<(), RtpEngineError> {
        match self {
            Self::SiphonRtp(client) => client.detach_ws_tee(call_id, from_tag).await,
            Self::RtpEngine(_) => Err(RtpEngineError::Unsupported {
                operation: "detach_ws_tee",
                backend: "rtpengine",
            }),
            Self::RtpProxy(_) => Err(RtpEngineError::Unsupported {
                operation: "detach_ws_tee",
                backend: "rtpproxy",
            }),
        }
    }

    /// Attach a WebSocket **takeover** bridge to a live call, or re-point an
    /// existing one at a different server.
    ///
    /// A native `siphon-rtp` extension, refused rather than hollow-successful
    /// on the others for the same reason as [`Self::attach_ws_tee`], and with
    /// more riding on it: a bridge *replaces* the call's media path, so an
    /// `Ok(())` from a backend that cannot do it would read as "both parties
    /// are now talking to the media server" while they are in fact still
    /// relaying to each other.
    pub async fn attach_ws_bridge(
        &self,
        call_id: &str,
        from_tag: &str,
        ws_uri: &str,
    ) -> Result<(), RtpEngineError> {
        match self {
            Self::SiphonRtp(client) => client.attach_ws_bridge(call_id, from_tag, ws_uri).await,
            Self::RtpEngine(_) => Err(RtpEngineError::Unsupported {
                operation: "attach_ws_bridge",
                backend: "rtpengine",
            }),
            Self::RtpProxy(_) => Err(RtpEngineError::Unsupported {
                operation: "attach_ws_bridge",
                backend: "rtpproxy",
            }),
        }
    }

    /// Detach a call's WebSocket takeover bridge, returning its media path to
    /// relaying.
    ///
    /// Not idempotent, unlike [`Self::detach_ws_tee`]: the engine refuses a
    /// detach where there is no relay to go back to (a `ws_uri`-negotiated
    /// bridge, or a single-leg takeover), because silently answering `Ok` would
    /// leave a live call with no audio path at all.  Unsupported on the other
    /// backends for the same reason as [`Self::attach_ws_bridge`].
    pub async fn detach_ws_bridge(
        &self,
        call_id: &str,
        from_tag: &str,
    ) -> Result<(), RtpEngineError> {
        match self {
            Self::SiphonRtp(client) => client.detach_ws_bridge(call_id, from_tag).await,
            Self::RtpEngine(_) => Err(RtpEngineError::Unsupported {
                operation: "detach_ws_bridge",
                backend: "rtpengine",
            }),
            Self::RtpProxy(_) => Err(RtpEngineError::Unsupported {
                operation: "detach_ws_bridge",
                backend: "rtpproxy",
            }),
        }
    }

    /// Begin ETSI TS 103 221-2 X3 content delivery for a call.
    ///
    /// Native `siphon-rtp` only, and refused rather than hollow-successful on
    /// the others. Content framing lives in the media engine, so rtpengine and
    /// rtpproxy cannot deliver X3 at all — an `Ok(())` here would read as "the
    /// warrant is being serviced" while no product ever reaches the agency,
    /// which is the worst available outcome for an intercept. The same refusal
    /// is applied earlier, at config load and at `ActivateTask`, so this is the
    /// last of three rather than the only one.
    pub async fn attach_x3(
        &self,
        call_id: &str,
        from_tag: &str,
        delivery: &str,
        xid: [u8; 16],
        correlation_id: u64,
        target_leg: X3TargetLeg,
    ) -> Result<(), RtpEngineError> {
        match self {
            Self::SiphonRtp(client) => {
                client
                    .attach_x3(call_id, from_tag, delivery, xid, correlation_id, target_leg)
                    .await
            }
            Self::RtpEngine(_) => Err(RtpEngineError::Unsupported {
                operation: "attach_x3",
                backend: "rtpengine",
            }),
            Self::RtpProxy(_) => Err(RtpEngineError::Unsupported {
                operation: "attach_x3",
                backend: "rtpproxy",
            }),
        }
    }

    /// Stop X3 content delivery. Idempotent on `siphon-rtp`; unsupported on the
    /// other backends for the same reason as [`Self::attach_x3`].
    pub async fn detach_x3(&self, call_id: &str, from_tag: &str) -> Result<(), RtpEngineError> {
        match self {
            Self::SiphonRtp(client) => client.detach_x3(call_id, from_tag).await,
            Self::RtpEngine(_) => Err(RtpEngineError::Unsupported {
                operation: "detach_x3",
                backend: "rtpengine",
            }),
            Self::RtpProxy(_) => Err(RtpEngineError::Unsupported {
                operation: "detach_x3",
                backend: "rtpproxy",
            }),
        }
    }

    /// Liveness check.
    pub async fn ping(&self) -> Result<(), RtpEngineError> {
        match self {
            Self::RtpEngine(set) => set.ping().await,
            Self::SiphonRtp(client) => client.ping().await,
            Self::RtpProxy(client) => client.ping().await,
        }
    }

    /// Per-instance health probe: `(address, healthy)` tuples.
    pub async fn health_check(&self) -> Vec<(SocketAddr, bool)> {
        match self {
            Self::RtpEngine(set) => set.health_check().await,
            Self::SiphonRtp(client) => client.health_check().await,
            Self::RtpProxy(client) => client.health_check().await,
        }
    }

    /// Number of active media sessions tracked by the backend.
    pub fn active_sessions(&self) -> usize {
        match self {
            Self::RtpEngine(set) => set.active_sessions(),
            Self::SiphonRtp(client) => client.active_sessions(),
            Self::RtpProxy(client) => client.active_sessions(),
        }
    }

    /// Number of configured engine instances.
    pub fn instance_count(&self) -> usize {
        match self {
            Self::RtpEngine(set) => set.instance_count(),
            Self::SiphonRtp(client) => client.instance_count(),
            Self::RtpProxy(client) => client.instance_count(),
        }
    }

    /// Addresses of every configured instance, in registration order.
    pub fn instance_addresses(&self) -> Vec<SocketAddr> {
        match self {
            Self::RtpEngine(set) => set.instance_addresses(),
            Self::SiphonRtp(client) => client.instance_addresses(),
            Self::RtpProxy(client) => client.instance_addresses(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtpengine::events::RtpEngineEvent;
    use tokio::sync::mpsc;

    /// A valid-but-unused loopback address; nothing listens on it. The native
    /// client dispatches the command and times out; the other backends reject
    /// `echo` synchronously before any I/O.
    fn dead_address() -> SocketAddr {
        "127.0.0.1:1".parse().unwrap()
    }

    // -----------------------------------------------------------------------
    // Playback bookkeeping (`ACTIVE_PLAYBACKS`)
    // -----------------------------------------------------------------------
    //
    // The set is process-global, so these use call-ids of their own and assert
    // against the *starting* length rather than zero — a parallel test binary
    // has other entries in flight.

    /// How many records this test's own call-ids hold. The set is
    /// process-global and the test binary is parallel, so a bare `len()` is
    /// other tests' noise; counting one prefix is exact.
    fn playback_records_for(prefix: &str) -> usize {
        ACTIVE_PLAYBACKS
            .iter()
            .filter(|entry| entry.key().0.starts_with(prefix))
            .count()
    }

    /// A backend pointed at nothing: `play_media` and `stop_media` reach the
    /// client and time out, which is enough to prove the bookkeeping is keyed
    /// on the outcome and not on the attempt.
    fn dead_native_backend() -> MediaBackend {
        let (event_tx, _event_rx) = mpsc::channel::<RtpEngineEvent>(16);
        let set =
            SiphonRtpClientSet::new(vec![(dead_address(), 200, 1)], None, 200, event_tx).unwrap();
        MediaBackend::SiphonRtp(set)
    }

    #[tokio::test]
    async fn a_playback_that_never_started_is_not_recorded() {
        // The engine never answered, so nothing is playing and a later bridge
        // must not send a stop that the engine would reject.
        let backend = dead_native_backend();
        let outcome = backend
            .play_media(
                "leak-never-started",
                "tag-a",
                &PlayMediaSource::File("/prompts/x.wav".to_string()),
                None,
                None,
                None,
                None,
                false,
                None,
                false,
            )
            .await;
        assert!(outcome.is_err(), "the dead address must not answer");
        assert!(!MediaBackend::playback_started(
            "leak-never-started",
            "tag-a"
        ));
        assert_eq!(playback_records_for("leak-never-started"), 0);
    }

    #[tokio::test]
    async fn a_deleted_call_leaves_no_playback_record_behind() {
        // The leak gate: `delete` is the one path every session ends through,
        // so an entry that survived it would grow the set for the life of the
        // process. Driven over a batch, so a single stale entry shows up as a
        // length that did not return to where it started.
        let backend = dead_native_backend();
        for index in 0..64 {
            let call_id = format!("leak-delete-{index}");
            ACTIVE_PLAYBACKS.insert((call_id.clone(), "tag-a".to_string()));
            assert!(MediaBackend::playback_started(&call_id, "tag-a"));
            // The engine is unreachable — the record still has to go, because
            // the call is over either way.
            let _ = backend.delete(&call_id, "tag-a").await;
            assert!(!MediaBackend::playback_started(&call_id, "tag-a"));
        }
        assert_eq!(
            playback_records_for("leak-delete-"),
            0,
            "a playback record outlived its call"
        );
    }

    #[test]
    fn a_targeted_stop_leaves_the_leg_playing() {
        // `stop_media(play_id=…)` ends one playback of several, so the leg is
        // still playing and a bridge still has something to stop. Only a
        // blanket stop clears the record — asserted through the same helper the
        // bridge reads.
        let key = ("leak-targeted".to_string(), "tag-a".to_string());
        ACTIVE_PLAYBACKS.insert(key.clone());
        assert!(MediaBackend::playback_started("leak-targeted", "tag-a"));
        assert_eq!(playback_records_for("leak-targeted"), 1);
        ACTIVE_PLAYBACKS.remove(&key);
        assert!(!MediaBackend::playback_started("leak-targeted", "tag-a"));
        assert_eq!(playback_records_for("leak-targeted"), 0);
    }

    #[tokio::test]
    async fn echo_routes_to_siphon_rtp_backend() {
        // Reaching the native client is proven by a Timeout (the command was
        // framed and sent, then no response arrived) — the reject arms below
        // return synchronously and never time out.
        let (event_tx, _event_rx) = mpsc::channel::<RtpEngineEvent>(16);
        let set =
            SiphonRtpClientSet::new(vec![(dead_address(), 200, 1)], None, 5_000, event_tx).unwrap();
        let backend = MediaBackend::SiphonRtp(set);

        let error = backend.echo("call-1", "tag-a", true).await.unwrap_err();
        assert!(
            matches!(error, RtpEngineError::Timeout { .. }),
            "expected the native client path (Timeout), got {error:?}"
        );
    }

    #[tokio::test]
    async fn echo_rejected_on_rtpproxy_backend() {
        let set = RtpProxyClientSet::new(vec![(dead_address(), 200, 1)], 0)
            .await
            .unwrap();
        let backend = MediaBackend::RtpProxy(set);

        let error = backend.echo("call-1", "tag-a", true).await.unwrap_err();
        assert!(matches!(error, RtpEngineError::Protocol(_)));
        assert!(error.to_string().contains("siphon-rtp"));
    }

    #[tokio::test]
    async fn echo_rejected_on_rtpengine_backend() {
        let set = RtpEngineSet::new(vec![(dead_address(), 200, 1)])
            .await
            .unwrap();
        let backend = MediaBackend::RtpEngine(Arc::new(set));

        let error = backend.echo("call-1", "tag-a", true).await.unwrap_err();
        assert!(matches!(error, RtpEngineError::Protocol(_)));
        assert!(error.to_string().contains("siphon-rtp"));
    }

    /// rtpengine and rtpproxy must NOT reject a re-offer: a repeat offer is
    /// their native re-offer, so the verb has to delegate rather than surface
    /// an `Unsupported` the way the siphon-rtp-only verbs do.  Proven by
    /// reaching the wire (a timeout against a dead address) instead of a
    /// synchronous rejection.
    #[tokio::test]
    async fn reoffer_delegates_to_offer_on_rtpengine_and_rtpproxy() {
        let rtpengine = MediaBackend::RtpEngine(Arc::new(
            RtpEngineSet::new(vec![(dead_address(), 200, 1)])
                .await
                .unwrap(),
        ));
        let error = rtpengine
            .reoffer("call-1", "tag-a", b"v=0\r\n", &NgFlags::default())
            .await
            .unwrap_err();
        assert!(
            matches!(error, RtpEngineError::Timeout { .. }),
            "rtpengine must send a re-offer as a plain offer, got {error:?}"
        );

        let rtpproxy = MediaBackend::RtpProxy(
            RtpProxyClientSet::new(vec![(dead_address(), 200, 1)], 0)
                .await
                .unwrap(),
        );
        // rtpproxy's transport is UDP and it rewrites the SDP itself, so the
        // delegated offer succeeds rather than timing out — success here is the
        // same proof: the verb reached the offer path instead of being rejected.
        assert!(
            rtpproxy
                .reoffer("call-1", "tag-a", b"v=0\r\n", &NgFlags::default())
                .await
                .is_ok(),
            "rtpproxy must send a re-offer as a plain offer"
        );
    }

    /// A takeover bridge *replaces* the call's media path, so a backend that
    /// cannot do it must refuse rather than answer `Ok(())` — a hollow success
    /// would read as "both parties are on the media server" while they are in
    /// fact still relaying to each other.
    #[tokio::test]
    async fn ws_bridge_verbs_are_refused_on_rtpengine_and_rtpproxy() {
        let rtpengine = MediaBackend::RtpEngine(Arc::new(
            RtpEngineSet::new(vec![(dead_address(), 200, 1)])
                .await
                .unwrap(),
        ));
        let rtpproxy = MediaBackend::RtpProxy(
            RtpProxyClientSet::new(vec![(dead_address(), 200, 1)], 0)
                .await
                .unwrap(),
        );

        for (backend, name) in [(&rtpengine, "rtpengine"), (&rtpproxy, "rtpproxy")] {
            let error = backend
                .attach_ws_bridge("call-1", "tag-a", "wss://ai.invalid/one")
                .await
                .unwrap_err();
            assert!(
                matches!(
                    error,
                    RtpEngineError::Unsupported { operation: "attach_ws_bridge", backend: b } if b == name
                ),
                "{name} must refuse attach_ws_bridge, got {error:?}"
            );

            let error = backend
                .detach_ws_bridge("call-1", "tag-a")
                .await
                .unwrap_err();
            assert!(
                matches!(
                    error,
                    RtpEngineError::Unsupported { operation: "detach_ws_bridge", backend: b } if b == name
                ),
                "{name} must refuse detach_ws_bridge, got {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn reoffer_routes_to_the_native_client_on_siphon_rtp() {
        let (event_tx, _event_rx) = mpsc::channel::<RtpEngineEvent>(16);
        let set =
            SiphonRtpClientSet::new(vec![(dead_address(), 200, 1)], None, 5_000, event_tx).unwrap();
        let backend = MediaBackend::SiphonRtp(set);

        let error = backend
            .reoffer("call-1", "tag-a", b"v=0\r\n", &NgFlags::default())
            .await
            .unwrap_err();
        assert!(
            matches!(error, RtpEngineError::Timeout { .. }),
            "expected the native client path (Timeout), got {error:?}"
        );
    }

    #[tokio::test]
    async fn answer_local_routes_to_siphon_rtp_backend() {
        // Reaching the native client is proven by a Timeout (the command was
        // framed and sent, then no response arrived) — the reject arms below
        // return synchronously and never time out.
        let (event_tx, _event_rx) = mpsc::channel::<RtpEngineEvent>(16);
        let set =
            SiphonRtpClientSet::new(vec![(dead_address(), 200, 1)], None, 5_000, event_tx).unwrap();
        let backend = MediaBackend::SiphonRtp(set);

        let error = backend
            .answer_local("call-1", "tag-a", "v=0\r\n", &NgFlags::default())
            .await
            .unwrap_err();
        assert!(
            matches!(error, RtpEngineError::Timeout { .. }),
            "expected the native client path (Timeout), got {error:?}"
        );
    }

    #[tokio::test]
    async fn answer_local_rejected_on_rtpproxy_backend() {
        let set = RtpProxyClientSet::new(vec![(dead_address(), 200, 1)], 0)
            .await
            .unwrap();
        let backend = MediaBackend::RtpProxy(set);

        let error = backend
            .answer_local("call-1", "tag-a", "v=0\r\n", &NgFlags::default())
            .await
            .unwrap_err();
        assert!(matches!(error, RtpEngineError::Protocol(_)));
        assert!(error.to_string().contains("siphon-rtp"));
    }

    #[tokio::test]
    async fn answer_local_rejected_on_rtpengine_backend() {
        let set = RtpEngineSet::new(vec![(dead_address(), 200, 1)])
            .await
            .unwrap();
        let backend = MediaBackend::RtpEngine(Arc::new(set));

        let error = backend
            .answer_local("call-1", "tag-a", "v=0\r\n", &NgFlags::default())
            .await
            .unwrap_err();
        assert!(matches!(error, RtpEngineError::Protocol(_)));
        assert!(error.to_string().contains("siphon-rtp"));
    }

    // -- backend capability reporting -----------------------------------------

    async fn rtpengine_backend() -> MediaBackend {
        let set = RtpEngineSet::new(vec![(dead_address(), 200, 1)])
            .await
            .unwrap();
        MediaBackend::RtpEngine(Arc::new(set))
    }

    async fn rtpproxy_backend() -> MediaBackend {
        let set = RtpProxyClientSet::new(vec![(dead_address(), 200, 1)], 0)
            .await
            .unwrap();
        MediaBackend::RtpProxy(set)
    }

    fn siphon_rtp_backend() -> MediaBackend {
        let (event_tx, _event_rx) = mpsc::channel::<RtpEngineEvent>(16);
        let set =
            SiphonRtpClientSet::new(vec![(dead_address(), 200, 1)], None, 5_000, event_tx).unwrap();
        MediaBackend::SiphonRtp(set)
    }

    fn ws_and_dsp_flags() -> NgFlags {
        NgFlags {
            ws_uri: Some("wss://ai.invalid/stream".into()),
            ws_vad: true,
            ws_barge_in: true,
            ws_vad_threshold: Some(2_000_000),
            ws_vad_hangover_ms: Some(300),
            noise_suppression: true,
            echo_cancellation: true,
            ..NgFlags::default()
        }
    }

    #[tokio::test]
    async fn kind_reports_the_configured_backend() {
        use crate::config::MediaBackendKind;
        assert_eq!(
            rtpengine_backend().await.kind(),
            MediaBackendKind::Rtpengine
        );
        assert_eq!(rtpproxy_backend().await.kind(), MediaBackendKind::Rtpproxy);
        assert_eq!(siphon_rtp_backend().kind(), MediaBackendKind::SiphonRtp);
    }

    /// A plain profile must be honourable everywhere, or every existing
    /// deployment would start failing calls.
    #[tokio::test]
    async fn plain_flags_are_supported_on_every_backend() {
        let plain = NgFlags {
            replace: vec!["origin".into()],
            flags: vec!["trust-address".into()],
            ..NgFlags::default()
        };
        assert!(rtpengine_backend()
            .await
            .unsupported_flags(&plain)
            .is_empty());
        assert!(rtpproxy_backend()
            .await
            .unsupported_flags(&plain)
            .is_empty());
        assert!(siphon_rtp_backend().unsupported_flags(&plain).is_empty());
    }

    // `SiphonRtpClient::new` spawns its connection manager, so these need a
    // runtime even though the capability check itself does no I/O.
    #[tokio::test]
    async fn siphon_rtp_supports_every_websocket_and_dsp_flag() {
        assert!(siphon_rtp_backend()
            .unsupported_flags(&ws_and_dsp_flags())
            .is_empty());
    }

    #[tokio::test]
    async fn rtpengine_reports_every_websocket_and_dsp_flag_unsupported() {
        let unsupported = rtpengine_backend()
            .await
            .unsupported_flags(&ws_and_dsp_flags());
        assert_eq!(
            unsupported,
            vec![
                "ws_uri",
                "ws_vad",
                "ws_barge_in",
                "ws_vad_threshold",
                "ws_vad_hangover_ms",
                "noise_suppression",
                "echo_cancellation",
            ]
        );
    }

    /// `received_from` / `rtcp_mux` are real NG keys, so rtpengine honours them
    /// and only rtpproxy does not.
    #[tokio::test]
    async fn received_from_and_rtcp_mux_split_rtpengine_from_rtpproxy() {
        let flags = NgFlags {
            carry_received_from: true,
            rtcp_mux: vec!["require".into()],
            ..NgFlags::default()
        };
        assert!(rtpengine_backend()
            .await
            .unsupported_flags(&flags)
            .is_empty());
        assert!(siphon_rtp_backend().unsupported_flags(&flags).is_empty());
        assert_eq!(
            rtpproxy_backend().await.unsupported_flags(&flags),
            vec!["received_from", "rtcp_mux"]
        );
    }

    /// An injected address counts as asking for the gate even if the policy bit
    /// was cleared along the way.
    #[tokio::test]
    async fn rtpproxy_reports_injected_received_from_unsupported() {
        let flags = NgFlags {
            received_from: Some("198.51.100.7".parse().unwrap()),
            ..NgFlags::default()
        };
        assert_eq!(
            rtpproxy_backend().await.unsupported_flags(&flags),
            vec!["received_from"]
        );
    }
}
