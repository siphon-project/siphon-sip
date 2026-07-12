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
use super::profile::NgFlags;
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
}
