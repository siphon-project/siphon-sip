//! The typed `record_start` / `record_stop` surface.
//!
//! Split from [`sip`](crate::sip) for the reason [`originate`](crate::originate)
//! is: that file is at its size budget.
//!
//! This records the call's **decoded** audio to a wav file. It is not
//! `li.record()` / SIPREC, which hands a recording *server* its own leg; it
//! works on a single-leg engine-terminated call, which is what a voicemail box
//! is. siphon-rtp backend only.

use serde_json::json;

use siphon_control_proto::sip::SipVerb;

use crate::error::ControlError;
use crate::sip::Call;

/// Which side of the call to record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordDirection {
    /// What the parties **sent** — the server's default, and what a recorded
    /// message is.
    Ingress,
    /// What was sent **to** them.
    Egress,
    /// Both directions.
    Both,
}

impl RecordDirection {
    /// The wire token the server parses.
    pub const fn as_str(self) -> &'static str {
        match self {
            RecordDirection::Ingress => "ingress",
            RecordDirection::Egress => "egress",
            RecordDirection::Both => "both",
        }
    }

    /// The direction called `name`, in any case: `ingress`, `egress` or `both`.
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "ingress" => Some(RecordDirection::Ingress),
            "egress" => Some(RecordDirection::Egress),
            "both" => Some(RecordDirection::Both),
            _ => None,
        }
    }
}

/// How many channels the recorded file carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordChannels {
    /// One mixed channel — the server's default.
    Mono,
    /// Two channels, one per side.
    Stereo,
}

impl RecordChannels {
    /// The wire token the server parses.
    pub const fn as_str(self) -> &'static str {
        match self {
            RecordChannels::Mono => "mono",
            RecordChannels::Stereo => "stereo",
        }
    }

    /// The layout called `name`, in any case: `mono` or `stereo`.
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "mono" => Some(RecordChannels::Mono),
            "stereo" => Some(RecordChannels::Stereo),
            _ => None,
        }
    }
}

/// Optional shaping for [`Call::record_start`]; every field left `None` takes
/// the server's own default rather than a copy of it pinned here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecordOptions {
    /// Which side to record (`ingress` server-side when unset).
    pub direction: Option<RecordDirection>,
    /// The file's channel layout (`mono` server-side when unset).
    pub channels: Option<RecordChannels>,
    /// Stop after this many milliseconds of recording.
    pub max_duration_ms: Option<u64>,
    /// Stop after this many milliseconds of silence.
    pub silence_ms: Option<u64>,
    /// Where the engine writes the file.
    pub path: Option<String>,
}

impl RecordOptions {
    /// Record this side of the call.
    pub fn direction(mut self, direction: RecordDirection) -> Self {
        self.direction = Some(direction);
        self
    }

    /// Write the file with this channel layout.
    pub fn channels(mut self, channels: RecordChannels) -> Self {
        self.channels = Some(channels);
        self
    }

    /// Stop after this many milliseconds — the "you have sixty seconds" bound.
    pub fn max_duration_ms(mut self, milliseconds: u64) -> Self {
        self.max_duration_ms = Some(milliseconds);
        self
    }

    /// Stop after this much silence — the "stop talking and we hang up" bound.
    pub fn silence_ms(mut self, milliseconds: u64) -> Self {
        self.silence_ms = Some(milliseconds);
        self
    }

    /// Write the file here.
    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    fn to_json(&self) -> serde_json::Value {
        let mut args = serde_json::Map::new();
        if let Some(direction) = self.direction {
            args.insert("direction".to_string(), json!(direction.as_str()));
        }
        if let Some(channels) = self.channels {
            args.insert("channels".to_string(), json!(channels.as_str()));
        }
        if let Some(max_duration_ms) = self.max_duration_ms {
            args.insert("max_duration_ms".to_string(), json!(max_duration_ms));
        }
        if let Some(silence_ms) = self.silence_ms {
            args.insert("silence_ms".to_string(), json!(silence_ms));
        }
        if let Some(path) = &self.path {
            args.insert("path".to_string(), json!(path));
        }
        serde_json::Value::Object(args)
    }
}

/// What the server answers an accepted [`Call::record_start`] with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recording {
    /// The channel being recorded.
    pub channel: String,
    /// The id a later [`Call::record_stop`] and the `RecordingFinished` event
    /// carry. `None` only from a server that did not name one.
    pub recording_id: Option<String>,
}

impl Call {
    /// Record this call's decoded audio to a wav file.
    ///
    /// The reply names the `recording_id` a later [`Call::record_stop`]
    /// addresses. It is **not** the file: `RecordingFinished` fires when the
    /// file is *closed* and names its path, which is what an app that mails the
    /// audio has to wait for — acting on this reply races a half-written file.
    ///
    /// [`RecordOptions::max_duration_ms`] and [`RecordOptions::silence_ms`] are
    /// the two stop conditions a voicemail greeting announces, and the engine
    /// evaluates both where the decoded audio already is.
    ///
    /// ```no_run
    /// # use siphon_control_client::sip::{Call, RecordDirection, RecordOptions};
    /// # async fn example(call: &Call) -> Result<(), siphon_control_client::ControlError> {
    /// let recording = call
    ///     .record_start(
    ///         RecordOptions::default()
    ///             .direction(RecordDirection::Ingress)
    ///             .max_duration_ms(60_000)
    ///             .silence_ms(4_000),
    ///     )
    ///     .await?;
    /// println!("recording {:?}", recording.recording_id);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// A call with no anchored media session resolves to `not_found`; a backend
    /// that is not siphon-rtp to [`ControlError::is_unsupported_verb`].
    pub async fn record_start(&self, options: RecordOptions) -> Result<Recording, ControlError> {
        let result = self.sip(SipVerb::RecordStart, options.to_json()).await?;
        Ok(Recording {
            channel: result
                .get("channel")
                .and_then(|value| value.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| self.channel_id().to_string()),
            recording_id: result
                .get("recording_id")
                .and_then(|value| value.as_str())
                .map(str::to_string),
        })
    }

    /// Stop the recording named by `recording_id`, or **every** recording on
    /// this call when it is `None`.
    ///
    /// Resolves once the engine has accepted the stop. The file is not closed
    /// yet: `RecordingFinished` says that, and carries the path and the reason
    /// (`stopped`, `max_duration`, `silence`, `call_ended`, `error`).
    pub async fn record_stop(&self, recording_id: Option<&str>) -> Result<(), ControlError> {
        let mut args = serde_json::Map::new();
        if let Some(recording_id) = recording_id {
            args.insert("recording_id".to_string(), json!(recording_id));
        }
        self.sip(SipVerb::RecordStop, serde_json::Value::Object(args))
            .await
            .map(drop)
    }
}
