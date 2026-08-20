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
use super::siphon_rtp::SiphonRtpClientSet;

/// The configured media-control backend.
pub enum MediaBackend {
    /// rtpengine NG protocol (bencode over UDP) — the default.
    RtpEngine(Arc<RtpEngineSet>),
    /// Native `siphon-rtp` control protocol (JSON over TCP), one or more instances.
    SiphonRtp(Arc<SiphonRtpClientSet>),
    /// Classic `rtpproxy` control protocol (text over UDP), one or more instances.
    RtpProxy(Arc<RtpProxyClientSet>),
}

impl MediaBackend {
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
        wait: bool,
    ) -> Result<Option<u64>, RtpEngineError> {
        match self {
            Self::RtpEngine(set) => {
                if wait {
                    debug!(call_id, "play_media(wait=True) ignored on rtpengine backend (no completion event); returning on accept");
                }
                set.play_media(
                    call_id,
                    from_tag,
                    source,
                    repeat_times,
                    start_pos_ms,
                    duration_ms,
                    to_tag,
                )
                .await
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
                        wait,
                    )
                    .await
            }
            Self::RtpProxy(client) => {
                if wait {
                    debug!(call_id, "play_media(wait=True) ignored on rtpproxy backend (no completion event); returning on accept");
                }
                client
                    .play_media(
                        call_id,
                        from_tag,
                        source,
                        repeat_times,
                        start_pos_ms,
                        duration_ms,
                        to_tag,
                    )
                    .await
            }
        }
    }

    /// Stop a prompt playing on the monologue selected by `from_tag`.
    pub async fn stop_media(&self, call_id: &str, from_tag: &str) -> Result<(), RtpEngineError> {
        match self {
            Self::RtpEngine(set) => set.stop_media(call_id, from_tag).await,
            Self::SiphonRtp(client) => client.stop_media(call_id, from_tag).await,
            Self::RtpProxy(client) => client.stop_media(call_id, from_tag).await,
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
                set.play_dtmf(call_id, from_tag, code, duration_ms, volume_dbm0, pause_ms, to_tag)
                    .await
            }
            Self::SiphonRtp(client) => {
                client
                    .play_dtmf(call_id, from_tag, code, duration_ms, volume_dbm0, pause_ms, to_tag)
                    .await
            }
            Self::RtpProxy(client) => {
                client
                    .play_dtmf(call_id, from_tag, code, duration_ms, volume_dbm0, pause_ms, to_tag)
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
    pub async fn echo(&self, call_id: &str, from_tag: &str, enabled: bool) -> Result<(), RtpEngineError> {
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
                client.answer_local(call_id, from_tag, offer_sdp, flags).await
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
                set.subscribe_request(call_id, from_tag, to_tag, sdp, flags).await
            }
            Self::SiphonRtp(client) => {
                client.subscribe_request(call_id, from_tag, to_tag, sdp, flags).await
            }
            Self::RtpProxy(client) => {
                client.subscribe_request(call_id, from_tag, to_tag, sdp, flags).await
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
                set.subscribe_request_siprec(call_id, from_tags, profile_flags).await
            }
            Self::SiphonRtp(client) => {
                client.subscribe_request_siprec(call_id, from_tags, profile_flags).await
            }
            Self::RtpProxy(client) => {
                client.subscribe_request_siprec(call_id, from_tags, profile_flags).await
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
                set.subscribe_answer(call_id, from_tag, to_tag, sdp, flags).await
            }
            Self::SiphonRtp(client) => {
                client.subscribe_answer(call_id, from_tag, to_tag, sdp, flags).await
            }
            Self::RtpProxy(client) => {
                client.subscribe_answer(call_id, from_tag, to_tag, sdp, flags).await
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
    ) -> Result<(), RtpEngineError> {
        match self {
            Self::SiphonRtp(client) => {
                client
                    .attach_ws_tee(call_id, from_tag, ws_uri, direction, channels)
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
    pub async fn detach_ws_tee(
        &self,
        call_id: &str,
        from_tag: &str,
    ) -> Result<(), RtpEngineError> {
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

    #[tokio::test]
    async fn echo_routes_to_siphon_rtp_backend() {
        // Reaching the native client is proven by a Timeout (the command was
        // framed and sent, then no response arrived) — the reject arms below
        // return synchronously and never time out.
        let (event_tx, _event_rx) = mpsc::channel::<RtpEngineEvent>(16);
        let set = SiphonRtpClientSet::new(vec![(dead_address(), 200, 1)], None, 5_000, event_tx).unwrap();
        let backend = MediaBackend::SiphonRtp(set);

        let error = backend.echo("call-1", "tag-a", true).await.unwrap_err();
        assert!(
            matches!(error, RtpEngineError::Timeout { .. }),
            "expected the native client path (Timeout), got {error:?}"
        );
    }

    #[tokio::test]
    async fn echo_rejected_on_rtpproxy_backend() {
        let set = RtpProxyClientSet::new(vec![(dead_address(), 200, 1)], 0).await.unwrap();
        let backend = MediaBackend::RtpProxy(set);

        let error = backend.echo("call-1", "tag-a", true).await.unwrap_err();
        assert!(matches!(error, RtpEngineError::Protocol(_)));
        assert!(error.to_string().contains("siphon-rtp"));
    }

    #[tokio::test]
    async fn echo_rejected_on_rtpengine_backend() {
        let set = RtpEngineSet::new(vec![(dead_address(), 200, 1)]).await.unwrap();
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
            RtpEngineSet::new(vec![(dead_address(), 200, 1)]).await.unwrap(),
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
            RtpProxyClientSet::new(vec![(dead_address(), 200, 1)], 0).await.unwrap(),
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
        let set = RtpProxyClientSet::new(vec![(dead_address(), 200, 1)], 0).await.unwrap();
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
        let set = RtpEngineSet::new(vec![(dead_address(), 200, 1)]).await.unwrap();
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
        let set = RtpEngineSet::new(vec![(dead_address(), 200, 1)]).await.unwrap();
        MediaBackend::RtpEngine(Arc::new(set))
    }

    async fn rtpproxy_backend() -> MediaBackend {
        let set = RtpProxyClientSet::new(vec![(dead_address(), 200, 1)], 0).await.unwrap();
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
        assert_eq!(rtpengine_backend().await.kind(), MediaBackendKind::Rtpengine);
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
        assert!(rtpengine_backend().await.unsupported_flags(&plain).is_empty());
        assert!(rtpproxy_backend().await.unsupported_flags(&plain).is_empty());
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
        let unsupported = rtpengine_backend().await.unsupported_flags(&ws_and_dsp_flags());
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
        assert!(rtpengine_backend().await.unsupported_flags(&flags).is_empty());
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
