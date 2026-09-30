//! The typed `stream_start` / `stream_stop` surface: a WebSocket audio stream
//! on the call's anchored media. siphon-rtp backend only.
//!
//! Split from [`sip`](crate::sip) for the reason [`recording`](crate::recording)
//! is: that file is at its size budget.

use serde_json::json;

use siphon_control_proto::sip::SipVerb;

use crate::error::ControlError;
use crate::sip::Call;

/// Which kind of WebSocket stream a `stream_start` / `stream_stop` addresses.
///
/// The two are opposites, not two shapes of one stream. A **tee** is additive:
/// a copy of the call's audio streams out and the call keeps relaying. A
/// **bridge** is a takeover: the WebSocket server becomes the leg's far side
/// and the call's own media path is unwired.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum StreamMode {
    /// Stream a copy; the call keeps relaying.
    #[default]
    Tee,
    /// Hand the leg's media to the server. On a leg that already has one, the
    /// server re-points it in place.
    Bridge,
}

impl StreamMode {
    /// The wire token the server parses.
    pub const fn as_str(self) -> &'static str {
        match self {
            StreamMode::Tee => "tee",
            StreamMode::Bridge => "bridge",
        }
    }

    /// The mode called `name`, in any case: `tee` or `bridge`.
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "tee" => Some(StreamMode::Tee),
            "bridge" => Some(StreamMode::Bridge),
            _ => None,
        }
    }
}

/// Which leg(s) a tee streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamDirection {
    /// Both legs — the server's default.
    Both,
    /// The offerer's audio only.
    Caller,
    /// The answerer's audio only.
    Callee,
}

impl StreamDirection {
    /// The wire token the server parses.
    pub const fn as_str(self) -> &'static str {
        match self {
            StreamDirection::Both => "both",
            StreamDirection::Caller => "caller",
            StreamDirection::Callee => "callee",
        }
    }

    /// The direction called `name`, in any case: `both`, `caller` or `callee`.
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "both" => Some(StreamDirection::Both),
            "caller" => Some(StreamDirection::Caller),
            "callee" => Some(StreamDirection::Callee),
            _ => None,
        }
    }
}

/// The channel layout of a tee's audio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamChannels {
    /// One mixed channel.
    Mono,
    /// Caller and callee on a channel each; only meaningful with
    /// [`StreamDirection::Both`].
    Stereo,
}

impl StreamChannels {
    /// The channel count the server parses (`1` or `2`).
    pub const fn count(self) -> u8 {
        match self {
            StreamChannels::Mono => 1,
            StreamChannels::Stereo => 2,
        }
    }

    /// The layout with `count` channels: `1` or `2`.
    pub const fn from_count(count: u8) -> Option<Self> {
        match count {
            1 => Some(StreamChannels::Mono),
            2 => Some(StreamChannels::Stereo),
            _ => None,
        }
    }
}

/// What [`Call::stream_start_with`] attaches.
///
/// `mode` always goes on the wire, the tee included. The shaping fields left
/// `None` take the server's own default rather than a copy of it pinned here.
///
/// `direction`, `channels` and `sample_rate` shape a **tee**. A bridge
/// negotiates its own wire shape with the server, which refuses any of them
/// alongside `mode: bridge` with `bad_request` rather than silently dropping
/// it. `profile` is the bridge's counterpart, refused on a tee the same way.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StreamOptions {
    /// Tee (the default) or bridge.
    pub mode: StreamMode,
    /// Which leg(s) a tee streams (`both` server-side when unset).
    pub direction: Option<StreamDirection>,
    /// A tee's channel layout (the engine's default when unset: stereo for
    /// both legs, mono for one).
    pub channels: Option<StreamChannels>,
    /// A tee's L16 sample rate in Hz: a multiple of 1000 within 8000–48000
    /// (the engine's default when unset). The server refuses anything else.
    pub sample_rate: Option<u32>,
    /// A bridge's media profile: the name of a profile on the server whose
    /// bridge settings (wire rate, noise suppression, echo cancellation, VAD,
    /// barge-in) the bridge runs with, as an `answer` with `ws_uri` would.
    /// Unset, the bridge runs at the leg's own rate with uplink processing
    /// off. An unknown name is `bad_request`.
    pub profile: Option<String>,
}

impl StreamOptions {
    /// An additive tee: a copy streams out, the call keeps relaying.
    pub fn tee() -> Self {
        Self::default()
    }

    /// A takeover bridge: the server becomes the leg's far side.
    pub fn bridge() -> Self {
        Self {
            mode: StreamMode::Bridge,
            ..Self::default()
        }
    }

    /// Tee this side of the call.
    pub fn direction(mut self, direction: StreamDirection) -> Self {
        self.direction = Some(direction);
        self
    }

    /// Stream the tee with this channel layout.
    pub fn channels(mut self, channels: StreamChannels) -> Self {
        self.channels = Some(channels);
        self
    }

    /// Stream the tee at this sample rate, in Hz.
    pub fn sample_rate(mut self, hertz: u32) -> Self {
        self.sample_rate = Some(hertz);
        self
    }

    /// Run the bridge with this media profile's bridge settings.
    pub fn profile(mut self, name: impl Into<String>) -> Self {
        self.profile = Some(name.into());
        self
    }
}

/// The `stream_start` args. The untyped [`Call::stream_start`] and the typed
/// [`Call::stream_start_with`] both build their frame here, so the two cannot
/// drift apart on what goes out.
fn stream_start_args(
    ws_uri: &str,
    mode: StreamMode,
    direction: Option<&str>,
    channels: Option<u8>,
    sample_rate: Option<u32>,
    profile: Option<&str>,
) -> serde_json::Value {
    let mut args = serde_json::Map::new();
    args.insert("ws_uri".to_string(), json!(ws_uri));
    args.insert("mode".to_string(), json!(mode.as_str()));
    if let Some(direction) = direction {
        args.insert("direction".to_string(), json!(direction));
    }
    if let Some(channels) = channels {
        args.insert("channels".to_string(), json!(channels));
    }
    if let Some(sample_rate) = sample_rate {
        args.insert("sample_rate".to_string(), json!(sample_rate));
    }
    if let Some(profile) = profile {
        args.insert("profile".to_string(), json!(profile));
    }
    serde_json::Value::Object(args)
}

impl Call {
    /// Attach a WebSocket audio **tee**: stream a copy of the call's decoded
    /// audio to `ws_uri` while the call keeps relaying.
    ///
    /// `direction` is one of `"both"` (default) / `"caller"` / `"callee"`;
    /// `channels` is `1` (mixed mono) or `2` (caller/callee stereo, only
    /// meaningful with `"both"`). For a bridge or a sample rate, use
    /// [`Call::stream_start_with`].
    ///
    /// This sends `mode: "tee"` explicitly. A tee and a bridge are opposites,
    /// and a caller of this method asked for a tee: relying on the server's
    /// default would turn every transcription into a takeover, with both
    /// parties hearing silence, the day that default moved.
    ///
    /// `ws_uri` may use `{call_id}` / `{from_tag}` / `{from_user}` /
    /// `{to_user}`, which siphon expands before the engine sees it: `{call_id}`
    /// expands to the call's SIP Call-ID ([`Call::sip_call_id`]), not the
    /// control-plane call id. siphon-rtp backend only: rtpengine / rtpproxy
    /// answer [`ControlError::is_unsupported_verb`].
    pub async fn stream_start(
        &self,
        ws_uri: &str,
        direction: Option<&str>,
        channels: Option<u8>,
    ) -> Result<(), ControlError> {
        let args = stream_start_args(ws_uri, StreamMode::Tee, direction, channels, None, None);
        self.sip(SipVerb::StreamStart, args).await.map(drop)
    }

    /// Attach a WebSocket audio stream to `ws_uri`: a tee or a takeover bridge,
    /// as [`StreamOptions::mode`] says.
    ///
    /// ```no_run
    /// # use siphon_control_client::sip::{Call, StreamDirection, StreamOptions};
    /// # async fn example(call: &Call) -> Result<(), siphon_control_client::ControlError> {
    /// // Transcribe the caller at 16 kHz; the call keeps relaying. siphon
    /// // expands `{call_id}` to the call's SIP Call-ID.
    /// call.stream_start_with(
    ///     "wss://ai.example/stream/{call_id}",
    ///     StreamOptions::tee()
    ///         .direction(StreamDirection::Caller)
    ///         .sample_rate(16_000),
    /// )
    /// .await?;
    /// // Hand the leg to a voice agent; the agent is now the far side, with
    /// // the server's `voice_ai` profile's rate, echo cancellation and barge-in.
    /// call.stream_start_with(
    ///     "wss://ai.example/agent",
    ///     StreamOptions::bridge().profile("voice_ai"),
    /// )
    /// .await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// A bridge on a leg that already has one re-points it in place. `ws_uri`
    /// is templated as for [`Call::stream_start`]: `{call_id}` expands to the
    /// call's SIP Call-ID. An unknown placeholder, or one the call has no
    /// value for, resolves to `bad_request`. A call with no anchored media session
    /// resolves to `not_found`; rtpengine / rtpproxy to
    /// [`ControlError::is_unsupported_verb`].
    pub async fn stream_start_with(
        &self,
        ws_uri: &str,
        options: StreamOptions,
    ) -> Result<(), ControlError> {
        let args = stream_start_args(
            ws_uri,
            options.mode,
            options.direction.map(StreamDirection::as_str),
            options.channels.map(StreamChannels::count),
            options.sample_rate,
            options.profile.as_deref(),
        );
        self.sip(SipVerb::StreamStart, args).await.map(drop)
    }

    /// Detach the WebSocket audio **tee** (idempotent on siphon-rtp). Sends
    /// `mode: "tee"` explicitly, for the reason [`Call::stream_start`] does.
    pub async fn stream_stop(&self) -> Result<(), ControlError> {
        self.stream_stop_with(StreamMode::Tee).await
    }

    /// Detach the WebSocket stream of `mode`.
    ///
    /// A tee detach is idempotent. A bridge detach is not: the engine refuses
    /// one where there is no relay to hand the call back to (a bridge
    /// negotiated through the profile's `ws_uri`, or a single-leg takeover),
    /// and that refusal surfaces as an error rather than an `Ok` that would
    /// leave a live call with no audio path.
    pub async fn stream_stop_with(&self, mode: StreamMode) -> Result<(), ControlError> {
        self.sip(SipVerb::StreamStop, json!({ "mode": mode.as_str() }))
            .await
            .map(drop)
    }
}
