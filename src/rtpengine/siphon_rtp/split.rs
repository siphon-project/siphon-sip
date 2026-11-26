//! The split bridge (`attach_ws_split` / `detach_ws_split`): both legs of an
//! answered two-party call streamed to one duplex stereo WebSocket, the
//! parties isolated from each other while it is attached.
//!
//! Channel 0 of the stream is the offerer (the engine's `from_tag` party),
//! channel 1 the answerer, both ways. What the bot sends on a channel is played
//! to that party only; nothing crosses between the two directly until the
//! split is detached, which puts the direct path back without a re-INVITE.
//!
//! An engine from before the verb closes the whole control connection on an
//! unknown command, dropping control of every call on it, so the verbs are
//! sent only once `node_info` lists `ws_split`.

use siphon_rtp_proto::{resolve_ws_split_sample_rate, Command, WsSplitAttach, WsSplitDetach};

use super::node_features::require_feature;
use super::{expect_ok, profile_flags_from_ng, SiphonRtpClient, SiphonRtpClientSet};
use crate::rtpengine::error::RtpEngineError;
use crate::rtpengine::profile::NgFlags;

/// What an engine that serves the split bridge lists in `node_info.features`.
pub(crate) const WS_SPLIT_FEATURE: &str = "ws_split";

impl SiphonRtpClient {
    /// Stream both legs of the answered call `call_id` to `ws_uri` and isolate
    /// the parties from each other.
    ///
    /// `sample_rate` is the L16 wire rate in Hz, one of 8000, 16000, 24000 or
    /// 48000; `None` leaves the engine's default (16000). Anything else is
    /// refused here, before the call is touched. The two profiles are the
    /// per-party uplink options, read as `attach_ws_bridge` reads a profile,
    /// of which the engine applies only `noise_suppression` and refuses the
    /// rest.
    ///
    /// Resolves when the engine has accepted the attach. That is **before**
    /// `ws_split_started`, and it does not mean the bot connected: a bot that
    /// drops during the handshake gives `ok`, then `started`, then `ended` with
    /// `ws_error`, so a caller has to watch the end event. A refusal is the
    /// engine's reason, `attach_ws_split: <token>: <text>`, and leaves the call
    /// as it was. The engine ignores `from_tag` when it picks the parties:
    /// channel 0 is always the offerer and channel 1 the answerer.
    pub async fn attach_ws_split(
        &self,
        call_id: &str,
        from_tag: &str,
        ws_uri: &str,
        sample_rate: Option<u32>,
        offerer_profile: Option<&NgFlags>,
        answerer_profile: Option<&NgFlags>,
    ) -> Result<(), RtpEngineError> {
        resolve_ws_split_sample_rate(sample_rate)
            .map_err(|error| RtpEngineError::Protocol(error.to_string()))?;
        require_ws_split(self).await?;
        expect_ok(
            self.request(Command::AttachWsSplit(WsSplitAttach {
                call_id: call_id.to_string(),
                from_tag: from_tag.to_string(),
                ws_uri: ws_uri.to_string(),
                sample_rate,
                offerer_profile: offerer_profile
                    .map(|flags| Box::new(profile_flags_from_ng(flags))),
                answerer_profile: answerer_profile
                    .map(|flags| Box::new(profile_flags_from_ng(flags))),
            }))
            .await?,
        )
    }

    /// End the call's split and put the direct path back, without a re-INVITE.
    /// Idempotent: a call with no split is not an error.
    pub async fn detach_ws_split(
        &self,
        call_id: &str,
        from_tag: &str,
    ) -> Result<(), RtpEngineError> {
        require_ws_split(self).await?;
        expect_ok(
            self.request(Command::DetachWsSplit(WsSplitDetach {
                call_id: call_id.to_string(),
                from_tag: from_tag.to_string(),
            }))
            .await?,
        )
    }
}

/// Whether the engine behind `client` lists `ws_split`.
async fn require_ws_split(client: &SiphonRtpClient) -> Result<(), RtpEngineError> {
    require_feature(
        client.request_in(None, Command::NodeInfo).await?,
        WS_SPLIT_FEATURE,
        "ws_split",
        "siphon-rtp (needs an engine that lists ws_split)",
    )
}

impl SiphonRtpClientSet {
    /// [`SiphonRtpClient::attach_ws_split`] on the instance owning this call.
    pub async fn attach_ws_split(
        &self,
        call_id: &str,
        from_tag: &str,
        ws_uri: &str,
        sample_rate: Option<u32>,
        offerer_profile: Option<&NgFlags>,
        answerer_profile: Option<&NgFlags>,
    ) -> Result<(), RtpEngineError> {
        self.select(call_id)
            .attach_ws_split(
                call_id,
                from_tag,
                ws_uri,
                sample_rate,
                offerer_profile,
                answerer_profile,
            )
            .await
    }

    /// [`SiphonRtpClient::detach_ws_split`] on the instance owning this call.
    pub async fn detach_ws_split(
        &self,
        call_id: &str,
        from_tag: &str,
    ) -> Result<(), RtpEngineError> {
        self.select(call_id)
            .detach_ws_split(call_id, from_tag)
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::{json, Value};
    use tokio::sync::mpsc;

    use super::super::SiphonRtpClient;
    use crate::rtpengine::error::RtpEngineError;
    use crate::rtpengine::events::RtpEngineEvent;
    use crate::rtpengine::profile::NgFlags;
    use crate::rtpengine::test_conference_engine::{accept, FakeEngine};

    fn client(engine: &FakeEngine) -> (Arc<SiphonRtpClient>, mpsc::Receiver<RtpEngineEvent>) {
        let (event_tx, event_rx) = mpsc::channel(16);
        (
            SiphonRtpClient::new(engine.address(), None, 2000, 5_000, event_tx),
            event_rx,
        )
    }

    fn node_info(features: &[&str]) -> Value {
        json!({
            "result": "node_info",
            "node": {
                "node_id": "engine-1",
                "version": "0.29.0",
                "media_addresses": [],
                "codecs": [],
                "features": features,
                "max_sessions": 0,
                "draining": false,
            },
        })
    }

    fn lists_ws_split(request: &Value) -> Value {
        match request["command"].as_str() {
            Some("node_info") => node_info(&["relay", "ws_split"]),
            _ => accept(request),
        }
    }

    fn lacks_ws_split(request: &Value) -> Value {
        match request["command"].as_str() {
            Some("node_info") => node_info(&["relay", "conference_seat"]),
            _ => accept(request),
        }
    }

    fn refuses_a_split(request: &Value) -> Value {
        match request["command"].as_str() {
            Some("attach_ws_split") => json!({
                "result": "error",
                "reason": "attach_ws_split: ws-split-already-bridged: the call already has a \
                           WebSocket takeover or a split",
            }),
            _ => lists_ws_split(request),
        }
    }

    fn noise_suppressed() -> NgFlags {
        NgFlags {
            noise_suppression: true,
            ..NgFlags::default()
        }
    }

    /// The frame is the documented one, written out by hand: flat, with the
    /// wire rate and the per-party uplink options beside the call.
    #[tokio::test]
    async fn an_attach_is_the_documented_frame() {
        let engine = FakeEngine::start(lists_ws_split, Vec::new()).await;
        let (client, _events) = client(&engine);

        client
            .attach_ws_split(
                "call-1",
                "tag-a",
                "wss://bot.example.net/call",
                Some(24_000),
                Some(&noise_suppressed()),
                None,
            )
            .await
            .expect("attached");

        let frames = engine.frames("attach_ws_split");
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0]["call_id"], "call-1");
        assert_eq!(frames[0]["from_tag"], "tag-a");
        assert_eq!(frames[0]["ws_uri"], "wss://bot.example.net/call");
        assert_eq!(frames[0]["sample_rate"], 24_000);
        assert_eq!(frames[0]["offerer_profile"]["noise_suppression"], true);
        assert!(
            frames[0].get("answerer_profile").is_none(),
            "an absent profile stays off the wire: {}",
            frames[0]
        );
    }

    /// No rate and no profiles is the minimal frame, so the engine's own
    /// default (16 kHz) applies rather than a copy of it pinned here.
    #[tokio::test]
    async fn an_attach_without_options_leaves_them_off_the_wire() {
        let engine = FakeEngine::start(lists_ws_split, Vec::new()).await;
        let (client, _events) = client(&engine);

        client
            .attach_ws_split(
                "call-1",
                "tag-a",
                "ws://bot.example.net/s",
                None,
                None,
                None,
            )
            .await
            .expect("attached");

        assert_eq!(
            engine.frames("attach_ws_split"),
            vec![json!({
                "command": "attach_ws_split",
                "call_id": "call-1",
                "from_tag": "tag-a",
                "ws_uri": "ws://bot.example.net/s",
            })]
        );
    }

    /// An engine from before the verb closes the whole control connection on
    /// an unknown command, so nothing is sent unless `node_info` lists it.
    #[tokio::test]
    async fn an_engine_without_the_feature_is_refused_before_anything_is_sent() {
        let engine = FakeEngine::start(lacks_ws_split, Vec::new()).await;
        let (client, _events) = client(&engine);

        let attach = client
            .attach_ws_split(
                "call-1",
                "tag-a",
                "wss://bot.example.net/s",
                None,
                None,
                None,
            )
            .await
            .expect_err("refused");
        let detach = client
            .detach_ws_split("call-1", "tag-a")
            .await
            .expect_err("refused");

        for error in [attach, detach] {
            assert!(
                matches!(error, RtpEngineError::Unsupported { .. }),
                "{error}"
            );
            assert!(error.to_string().contains("ws_split"), "{error}");
        }
        assert!(engine.frames("attach_ws_split").is_empty());
        assert!(engine.frames("detach_ws_split").is_empty());
    }

    /// A rate the engine does not serve is refused here, before the call is
    /// touched and before a single frame is sent.
    #[tokio::test]
    async fn a_rate_the_engine_does_not_serve_is_refused_without_a_frame() {
        let engine = FakeEngine::start(lists_ws_split, Vec::new()).await;
        let (client, _events) = client(&engine);

        for rate in [0, 11_025, 32_000, 44_100] {
            let error = client
                .attach_ws_split(
                    "call-1",
                    "tag-a",
                    "wss://bot.example.net/s",
                    Some(rate),
                    None,
                    None,
                )
                .await
                .expect_err("refused");
            assert!(error.to_string().contains(&rate.to_string()), "{error}");
        }
        assert!(engine.commands().is_empty(), "{:?}", engine.commands());
    }

    #[tokio::test]
    async fn a_detach_is_the_documented_frame() {
        let engine = FakeEngine::start(lists_ws_split, Vec::new()).await;
        let (client, _events) = client(&engine);

        client
            .detach_ws_split("call-1", "tag-a")
            .await
            .expect("detached");

        assert_eq!(
            engine.frames("detach_ws_split"),
            vec![json!({
                "command": "detach_ws_split",
                "call_id": "call-1",
                "from_tag": "tag-a",
            })]
        );
    }

    /// The engine's refusal reaches the caller whole, token included.
    #[tokio::test]
    async fn an_engine_refusal_keeps_its_token() {
        let engine = FakeEngine::start(refuses_a_split, Vec::new()).await;
        let (client, _events) = client(&engine);

        let error = client
            .attach_ws_split(
                "call-1",
                "tag-a",
                "wss://bot.example.net/s",
                None,
                None,
                None,
            )
            .await
            .expect_err("refused");

        assert!(
            error
                .to_string()
                .contains("attach_ws_split: ws-split-already-bridged: "),
            "{error}"
        );
        assert_eq!(error.refusal_token(), Some("ws-split-already-bridged"));
    }
}
