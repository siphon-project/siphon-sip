//! RTP media profiles and their translation to RTPEngine NG protocol flags.
//!
//! Each profile describes a media transcoding/relay scenario (e.g. SRTP on the
//! UE side, plain RTP on the core side).  The profile determines which NG flags
//! are sent in `offer` and `answer` commands.
//!
//! Eight built-in profiles are always available:
//!   srtp_to_rtp, rtp_to_srtp, ws_to_rtp, wss_to_rtp, rtp_passthrough,
//!   srs_recording, siprec_src, voice_ai
//!
//! Operators can define additional profiles (or override built-ins) in the YAML
//! config under `media.profiles`.
//!
//! Not every flag is honourable by every media backend — the WebSocket bridge,
//! the WebSocket tee and the DSP knobs are native `siphon-rtp` extensions, and
//! `rtpproxy` has no equivalent for `address_family`, `received_from` or
//! `rtcp_mux`.  A profile
//! asking for something its configured backend cannot do is rejected at config
//! load; see `MediaBackendKind::unsupported_profile_fields`.

use std::collections::HashMap;

use crate::config::{MediaProfileConfig, NgFlagsConfig};

/// A single media profile: offer flags + answer flags.
#[derive(Debug, Clone)]
pub struct ProfileEntry {
    pub offer: NgFlags,
    pub answer: NgFlags,
}

/// Runtime form of [`CodecFlagsConfig`](crate::config::CodecFlagsConfig) — the
/// rtpengine `codec` sub-dict.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CodecFlags {
    pub strip: Vec<String>,
    pub offer: Vec<String>,
    pub transcode: Vec<String>,
    pub mask: Vec<String>,
    pub consume: Vec<String>,
    pub accept: Vec<String>,
    pub except: Vec<String>,
    pub ignore: Vec<String>,
    pub set: Vec<String>,
}

impl CodecFlags {
    /// True when nothing is set — the `codec` key is then omitted entirely
    /// rather than sent as an empty dict.
    pub fn is_empty(&self) -> bool {
        self.strip.is_empty()
            && self.offer.is_empty()
            && self.transcode.is_empty()
            && self.mask.is_empty()
            && self.consume.is_empty()
            && self.accept.is_empty()
            && self.except.is_empty()
            && self.ignore.is_empty()
            && self.set.is_empty()
    }

    fn from_config(config: &crate::config::CodecFlagsConfig) -> Self {
        Self {
            strip: config.strip.clone(),
            offer: config.offer.clone(),
            transcode: config.transcode.clone(),
            mask: config.mask.clone(),
            consume: config.consume.clone(),
            accept: config.accept.clone(),
            except: config.except.clone(),
            ignore: config.ignore.clone(),
            set: config.set.clone(),
        }
    }

    /// The ops the native `siphon-rtp` engine understands, flattened to the
    /// `codec-<op>-<NAME>` flag strings its `ProfileFlags.flags` carries.
    ///
    /// The engine implements the same rtpengine codec model but reads it off the
    /// flag list rather than a nested dict, so one profile drives both engines.
    /// `ignore` and `set` have no native equivalent and are deliberately not
    /// emitted here — the config gate refuses them on that backend rather than
    /// letting them look applied.
    pub fn to_native_flags(&self) -> Vec<String> {
        let mut out = Vec::new();
        for (op, list) in [
            ("strip", &self.strip),
            ("mask", &self.mask),
            ("consume", &self.consume),
            ("except", &self.except),
            ("accept", &self.accept),
            ("offer", &self.offer),
            ("transcode", &self.transcode),
        ] {
            for name in list {
                out.push(format!("codec-{op}-{name}"));
            }
        }
        out
    }

    /// The ops with no native equivalent, for the backend capability gate.
    pub fn native_unsupported_ops(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if !self.ignore.is_empty() {
            out.push("codec.ignore");
        }
        if !self.set.is_empty() {
            out.push("codec.set");
        }
        out
    }

    /// The `codec` sub-dict, or `None` when nothing is set. Keys are emitted in
    /// a fixed order so a command is byte-stable for a given profile.
    fn to_bencode(&self) -> Option<super::bencode::BencodeValue> {
        use super::bencode::BencodeValue;
        if self.is_empty() {
            return None;
        }
        let mut pairs: Vec<(&str, BencodeValue)> = Vec::new();
        for (key, list) in [
            ("strip", &self.strip),
            ("offer", &self.offer),
            ("transcode", &self.transcode),
            ("mask", &self.mask),
            ("consume", &self.consume),
            ("accept", &self.accept),
            ("except", &self.except),
            ("ignore", &self.ignore),
            ("set", &self.set),
        ] {
            if !list.is_empty() {
                let items: Vec<&str> = list.iter().map(|s| s.as_str()).collect();
                pairs.push((key, BencodeValue::string_list(&items)));
            }
        }
        Some(BencodeValue::dict(pairs))
    }
}

impl ProfileEntry {
    /// True when this profile's two halves are not interchangeable — the offer
    /// and answer flags describe *specific sides* of the call rather than a
    /// symmetric relay.
    ///
    /// A profile like `srtp_to_rtp` says "the offerer speaks SRTP, the answerer
    /// speaks plain RTP" and reverses `direction` between the two halves. That
    /// is exactly right for the pairing it was chosen for, and wrong for any
    /// other: apply its `answer` flags to a party that is on the *plain* side
    /// and you offer them SRTP, which they reject.
    ///
    /// This matters when a call is re-paired underneath the profile — a
    /// siphon-terminated transfer, or a `Replaces` takeover — because the party
    /// each half was written for may be the one that just left.
    pub fn is_direction_bound(&self) -> bool {
        self.offer.transport_protocol != self.answer.transport_protocol
            || !self.offer.direction.is_empty()
            || !self.answer.direction.is_empty()
            || self.offer.dtls != self.answer.dtls
            // Codec manipulation is chosen for the party on the far side of
            // this half — strip SILK because *that* carrier cannot take it —
            // so it is as side-specific as the transport is.
            || self.offer.codec != self.answer.codec
    }
}

/// Registry of named media profiles.
///
/// Populated at startup from built-in defaults + YAML config.  Shared via
/// `Arc<ProfileRegistry>` so that the Python API and dispatcher can look up
/// profiles by name.
#[derive(Debug, Clone)]
pub struct ProfileRegistry {
    profiles: HashMap<String, ProfileEntry>,
}

impl ProfileRegistry {
    /// Create a registry containing only the built-in profiles.
    pub fn new() -> Self {
        let mut profiles = HashMap::new();
        profiles.insert("srtp_to_rtp".into(), Self::builtin_srtp_to_rtp());
        profiles.insert("rtp_to_srtp".into(), Self::builtin_rtp_to_srtp());
        profiles.insert("ws_to_rtp".into(), Self::builtin_ws_to_rtp());
        profiles.insert("wss_to_rtp".into(), Self::builtin_wss_to_rtp());
        profiles.insert("rtp_passthrough".into(), Self::builtin_rtp_passthrough());
        profiles.insert("srs_recording".into(), Self::builtin_srs_recording());
        profiles.insert("siprec_src".into(), Self::builtin_siprec_src());
        profiles.insert("voice_ai".into(), Self::builtin_voice_ai());
        Self { profiles }
    }

    /// Create a registry from built-in defaults + custom YAML profiles.
    /// Custom profiles override built-ins with the same name.
    pub fn from_config(custom: &HashMap<String, MediaProfileConfig>) -> Self {
        let mut registry = Self::new();
        for (name, config) in custom {
            registry.profiles.insert(
                name.clone(),
                ProfileEntry {
                    offer: NgFlags::from_config(&config.offer),
                    answer: NgFlags::from_config(&config.answer),
                },
            );
        }
        registry
    }

    /// Look up a profile by name.
    pub fn get(&self, name: &str) -> Option<&ProfileEntry> {
        self.profiles.get(name)
    }

    /// List all available profile names (sorted for deterministic error messages).
    pub fn profile_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.profiles.keys().map(|s| s.as_str()).collect();
        names.sort_unstable();
        names
    }

    // --- Built-in profiles ---

    fn builtin_srtp_to_rtp() -> ProfileEntry {
        ProfileEntry {
            offer: NgFlags {
                transport_protocol: Some("RTP/SAVP".into()),
                ice: Some("remove".into()),
                replace: vec!["origin".into()],
                direction: vec!["external".into(), "internal".into()],
                ..NgFlags::default()
            },
            answer: NgFlags {
                transport_protocol: Some("RTP/AVP".into()),
                ice: Some("remove".into()),
                replace: vec!["origin".into()],
                direction: vec!["internal".into(), "external".into()],
                ..NgFlags::default()
            },
        }
    }

    fn builtin_rtp_to_srtp() -> ProfileEntry {
        ProfileEntry {
            offer: NgFlags {
                transport_protocol: Some("RTP/SAVP".into()),
                ice: Some("remove".into()),
                replace: vec!["origin".into()],
                direction: vec!["internal".into(), "external".into()],
                ..NgFlags::default()
            },
            answer: NgFlags {
                transport_protocol: Some("RTP/AVP".into()),
                ice: Some("remove".into()),
                replace: vec!["origin".into()],
                direction: vec!["external".into(), "internal".into()],
                ..NgFlags::default()
            },
        }
    }

    fn builtin_ws_to_rtp() -> ProfileEntry {
        ProfileEntry {
            offer: NgFlags {
                transport_protocol: Some("RTP/AVPF".into()),
                ice: Some("force".into()),
                replace: vec!["origin".into()],
                direction: vec!["external".into(), "internal".into()],
                ..NgFlags::default()
            },
            answer: NgFlags {
                transport_protocol: Some("RTP/AVP".into()),
                ice: Some("remove".into()),
                replace: vec!["origin".into()],
                direction: vec!["internal".into(), "external".into()],
                ..NgFlags::default()
            },
        }
    }

    fn builtin_wss_to_rtp() -> ProfileEntry {
        ProfileEntry {
            offer: NgFlags {
                transport_protocol: Some("RTP/SAVPF".into()),
                ice: Some("force".into()),
                dtls: Some("passive".into()),
                replace: vec!["origin".into()],
                direction: vec!["external".into(), "internal".into()],
                ..NgFlags::default()
            },
            answer: NgFlags {
                transport_protocol: Some("RTP/AVP".into()),
                ice: Some("remove".into()),
                dtls: Some("off".into()),
                replace: vec!["origin".into()],
                direction: vec!["internal".into(), "external".into()],
                ..NgFlags::default()
            },
        }
    }

    fn builtin_voice_ai() -> ProfileEntry {
        // Voice-AI bridge profile: plain RTP toward the caller, with the leg's
        // audio bridged to an external WebSocket media server by the engine.
        //
        // `ws_uri` is deliberately unset — there is no sensible default endpoint,
        // so the operator supplies it on a `media.profiles` override or the
        // script passes `ws_uri=` per call.  Everything this profile *does* set
        // is live on its own: noise suppression and echo cancellation clean the
        // uplink toward the inference server (the AI downlink is the echo
        // reference), and VAD + barge-in give the server turn boundaries and
        // let the bridge cut playout locally on the caller's speech edge without
        // a server round-trip.
        //
        // `siphon-rtp` backend only; the rtpengine and rtpproxy backends have no
        // equivalent for any of these and reject the profile at config load.
        ProfileEntry {
            offer: NgFlags {
                transport_protocol: Some("RTP/AVP".into()),
                ice: Some("remove".into()),
                dtls: Some("off".into()),
                replace: vec!["origin".into()],
                noise_suppression: true,
                echo_cancellation: true,
                ws_vad: true,
                ws_barge_in: true,
                ..NgFlags::default()
            },
            answer: NgFlags {
                transport_protocol: Some("RTP/AVP".into()),
                ice: Some("remove".into()),
                dtls: Some("off".into()),
                replace: vec!["origin".into()],
                noise_suppression: true,
                echo_cancellation: true,
                ws_vad: true,
                ws_barge_in: true,
                ..NgFlags::default()
            },
        }
    }

    fn builtin_srs_recording() -> ProfileEntry {
        // SIPREC SRS recording profile:
        // - replace origin so RTPEngine rewrites o= line
        // - media handover + port latching for NAT/SIPREC source port flexibility
        // - ICE remove, DTLS off (recording sink, no peer security needed)
        ProfileEntry {
            offer: NgFlags {
                transport_protocol: Some("RTP/AVP".into()),
                ice: Some("remove".into()),
                dtls: Some("off".into()),
                replace: vec!["origin".into()],
                flags: vec!["media handover".into(), "port latching".into()],
                record_call: true,
                ..NgFlags::default()
            },
            answer: NgFlags {
                transport_protocol: Some("RTP/AVP".into()),
                ice: Some("remove".into()),
                dtls: Some("off".into()),
                replace: vec!["origin".into()],
                flags: vec!["media handover".into(), "port latching".into()],
                record_call: true,
                ..NgFlags::default()
            },
        }
    }

    fn builtin_siprec_src() -> ProfileEntry {
        // SIPREC SRC subscribe profile:
        // - ICE remove, DTLS off (recording leg, no peer security)
        // - replace origin so RTPEngine rewrites o= line
        // - plain RTP to SRS
        // These flags are merged into the subscribe request alongside the
        // mandatory ["all", "siprec"] flags.
        ProfileEntry {
            offer: NgFlags {
                transport_protocol: Some("RTP/AVP".into()),
                ice: Some("remove".into()),
                dtls: Some("off".into()),
                replace: vec!["origin".into()],
                ..NgFlags::default()
            },
            answer: NgFlags::default(),
        }
    }

    fn builtin_rtp_passthrough() -> ProfileEntry {
        ProfileEntry {
            offer: NgFlags {
                replace: vec!["origin".into()],
                flags: vec!["trust-address".into()],
                ..NgFlags::default()
            },
            answer: NgFlags {
                replace: vec!["origin".into()],
                flags: vec!["trust-address".into()],
                ..NgFlags::default()
            },
        }
    }
}

impl Default for ProfileRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Which leg(s) of a call a WebSocket tee streams.
///
/// A siphon-side mirror of the native backend's `siphon_rtp_proto::WsTeeDirection`,
/// so the config and profile layers stay free of the proto type — the same posture
/// [`super::events::CallSummary`] takes for the call-summary event.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum WsTeeDirection {
    /// Both legs: stereo (channel 0 = caller, channel 1 = callee) unless
    /// [`NgFlags::ws_tee_channels`] is 1, which mixes them to mono.
    #[default]
    Both,
    /// Only the caller's (offerer's) audio, as a mono monologue.
    Caller,
    /// Only the callee's (answerer's) audio, as a mono monologue.
    Callee,
}

impl WsTeeDirection {
    /// The YAML / Python spelling, matching the proto's `snake_case` wire form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Both => "both",
            Self::Caller => "caller",
            Self::Callee => "callee",
        }
    }

    /// Parse the YAML / Python spelling, case-insensitively.
    ///
    /// Returns `None` for anything else so the caller can raise a named error
    /// rather than silently relaying a direction the engine would reject.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "both" => Some(Self::Both),
            "caller" => Some(Self::Caller),
            "callee" => Some(Self::Callee),
            _ => None,
        }
    }

    /// The accepted values, for error messages.
    pub const VALUES: [&'static str; 3] = ["both", "caller", "callee"];
}

/// Which voice-activity detector the WebSocket uplink VAD runs.
///
/// A siphon-side mirror of the native backend's `siphon_rtp_proto::WsVadEngine`,
/// keeping the config and profile layers free of the proto type (the same
/// posture [`WsTeeDirection`] takes).
///
/// Deliberately **not** `#[non_exhaustive]`, mirroring the proto: this selects
/// behaviour the script asked for *by name*.  A consumer that met an unknown
/// detector through a wildcard would have to fall back to the detector the
/// script was explicitly avoiding — a silent downgrade.  Exhaustiveness forces
/// that question to be answered in code.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum WsVadEngine {
    /// Mean-square energy against a threshold with a trailing hangover.  Cheap
    /// and exact, but it answers "is something loud here", so breathing, mains
    /// hum, fan noise and uncancelled echo all read as speech.  The engine's
    /// default, and the right choice when a false turn start is harmless.
    #[default]
    Energy,
    /// A neural speech classifier.  Answers "is what is here speech", so it does
    /// not turn-start on non-speech noise, at the cost of a 32 ms detection
    /// floor plus up to one media frame.  Pick it for turn taking and barge-in.
    Neural,
}

impl WsVadEngine {
    /// The YAML / Python spelling, matching the proto's `snake_case` wire form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Energy => "energy",
            Self::Neural => "neural",
        }
    }

    /// Parse the YAML / Python spelling, case-insensitively.
    ///
    /// Returns `None` for anything else so the caller can raise a named error
    /// rather than silently relaying a detector the engine would reject.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "energy" => Some(Self::Energy),
            "neural" => Some(Self::Neural),
            _ => None,
        }
    }

    /// The accepted values, for error messages.
    pub const VALUES: [&'static str; 2] = ["energy", "neural"];
}

/// Lowest L16 wire sample rate the engine accepts (`ws_sample_rate` /
/// `ws_tee_sample_rate`).
pub const WS_SAMPLE_RATE_MIN: u32 = 8_000;
/// Highest L16 wire sample rate the engine accepts.
pub const WS_SAMPLE_RATE_MAX: u32 = 48_000;
/// The engine requires a whole number of kHz.
pub const WS_SAMPLE_RATE_STEP: u32 = 1_000;

/// Validate an L16 wire sample rate the way the engine does.
///
/// The engine **fails the offer/answer** on a bad rate rather than clamping it,
/// so a profile carrying one is a call that never gets media.  Checking here
/// lets config load reject it at boot and the script API reject it at the call,
/// instead of the operator learning from a dead leg.
///
/// Returns a ready-to-print reason on rejection.
pub fn validate_ws_sample_rate(rate: u32) -> Result<(), String> {
    if !(WS_SAMPLE_RATE_MIN..=WS_SAMPLE_RATE_MAX).contains(&rate)
        || rate % WS_SAMPLE_RATE_STEP != 0
    {
        return Err(format!(
            "must be a multiple of {WS_SAMPLE_RATE_STEP} within \
             {WS_SAMPLE_RATE_MIN}–{WS_SAMPLE_RATE_MAX} Hz, got {rate}"
        ));
    }
    Ok(())
}

/// NG protocol flags sent with offer/answer commands.
#[derive(Debug, Clone, Default)]
pub struct NgFlags {
    /// Transport protocol override (e.g. "RTP/AVP", "RTP/SAVPF").
    pub transport_protocol: Option<String>,
    /// Codec manipulation — see [`CodecFlags`]. Honoured by rtpengine (as its NG
    /// `codec` dict) and by the native engine (flattened onto its flag list).
    pub codec: CodecFlags,
    /// ICE handling: "remove", "force", or "force-relay".
    pub ice: Option<String>,
    /// DTLS mode: "passive", "active", or "off".
    pub dtls: Option<String>,
    /// SDP fields to replace: "origin".
    pub replace: Vec<String>,
    /// Address family for the engine's relay endpoints on this side of the call:
    /// `"IP4"` or `"IP6"` (the SDP `addrtype` spelling).  `None` leaves the
    /// engine following the offered SDP's own family — a single-family relay.
    ///
    /// Carried on the wire as rtpengine's dedicated `"address family"` NG dict
    /// key (**not** a `flags` token — rtpengine would ignore it there) and as
    /// siphon-rtp's `address_family` JSON field.  The classic `rtpproxy` backend
    /// has no equivalent and cannot honour it.
    pub address_family: Option<String>,
    /// Additional flags: "trust-address", "symmetric", "asymmetric".
    pub flags: Vec<String>,
    /// Direction pair for NAT traversal: ["external", "internal"].
    pub direction: Vec<String>,
    /// Enable call recording in RTPEngine.
    pub record_call: bool,
    /// Directory path for RTPEngine to write recording files.
    pub record_path: Option<String>,
    /// Ask the engine to observe RFC 4103 real-time text on this call
    /// (`siphon-rtp` only).  When the call negotiates a plaintext `m=text`
    /// stream, the engine promotes *only* that low-rate stream to its userspace
    /// text processor, which RED-depacketizes and reassembles it and reports each
    /// recovered increment as an `@rtpengine.on_text` event plus per-leg counters
    /// in the end-of-call media summary.  The audio relay/transcode path is
    /// untouched — text observability never promotes audio — and the flag is
    /// inert on an audio-only call.
    pub text_events: bool,
    /// Single-channel noise suppression on this leg's decoded ingress audio,
    /// before it is relayed/transcoded toward the peer.  Engaged only on a
    /// userspace-transcoded leg whose ingress codec runs at 8 or 16 kHz, and
    /// setting it forces the call off the in-kernel fast path exactly as
    /// `record_call` does.
    ///
    /// A native `siphon-rtp` extension: the NG/bencode and rtpproxy backends
    /// have no equivalent and cannot honour it.
    pub noise_suppression: bool,
    /// Acoustic/line echo cancellation on this leg's **send** path, using the
    /// audio played toward that party as the far-end reference.  On a WebSocket
    /// voice-AI bridge it cancels the phone uplink toward the AI using the AI
    /// downlink as the reference.  Like [`NgFlags::noise_suppression`] it
    /// promotes a same-codec call onto the userspace media pipeline.
    ///
    /// A native `siphon-rtp` extension: the NG/bencode and rtpproxy backends
    /// have no equivalent and cannot honour it.
    pub echo_cancellation: bool,
    /// Bridge this call's offerer (leg A) audio to an external WebSocket media
    /// server — the voice-AI integration.  The engine dials this URI as a
    /// WebSocket client and bridges leg A's RTP to it (decode → L16 uplink, L16
    /// downlink → encode); the WS server *is* leg A's far side, so the A↔B
    /// relay path is not wired in this mode.  Both `ws://` and `wss://` are
    /// dialled.
    ///
    /// A native `siphon-rtp` extension: the NG/bencode and rtpproxy backends
    /// have no equivalent and cannot honour it.
    pub ws_uri: Option<String>,
    /// Run a local energy-VAD on the WS uplink so the bridge emits
    /// `speech_started` / `speech_stopped` control frames on the caller's speech
    /// edges — the inference server gets turn boundaries (and the turn
    /// endpoint) without running its own VAD.  Inert without
    /// [`NgFlags::ws_uri`].
    pub ws_vad: bool,
    /// Local barge-in on the WS leg: when the caller starts speaking the bridge
    /// flushes the queued downlink playout in the same tick (no server
    /// round-trip) and notifies the server via `speech_started`.  Implies
    /// [`NgFlags::ws_vad`].  Inert without [`NgFlags::ws_uri`].
    pub ws_barge_in: bool,
    /// Mean-square energy threshold for the WS uplink VAD.  `None` uses the
    /// engine's 8/16 kHz L16 default (~1_000_000); higher is less sensitive.
    /// Only meaningful with [`NgFlags::ws_vad`] / [`NgFlags::ws_barge_in`].
    pub ws_vad_threshold: Option<i64>,
    /// Trailing hangover for the WS uplink VAD in milliseconds — how long speech
    /// is held after energy drops before `speech_stopped` (the turn endpoint)
    /// fires.  `None` uses the engine's ~200 ms default.  Only meaningful with
    /// [`NgFlags::ws_vad`] / [`NgFlags::ws_barge_in`], and only with the
    /// [`WsVadEngine::Energy`] detector — [`WsVadEngine::Neural`] holds speech
    /// with its own probability hysteresis instead.
    pub ws_vad_hangover_ms: Option<u32>,
    /// L16 wire sample rate in Hz for the [`NgFlags::ws_uri`] takeover bridge,
    /// **independent of the leg's codec rate** and applied in *both* directions:
    /// the engine resamples the leg's decoded uplink into it and resamples the
    /// server's downlink back into the leg's codec rate before re-encoding.  So
    /// an 8 kHz G.711 call can speak 16 kHz L16 to the server, and a server
    /// rendering 24 kHz audio is played at the right speed and pitch.
    ///
    /// It is also the domain the uplink noise suppressor and echo canceller run
    /// in, and those engage only at 8 or 16 kHz — another rate leaves them off
    /// without changing the wire rate.
    ///
    /// Must satisfy [`validate_ws_sample_rate`]; the engine *fails* the
    /// offer/answer on a bad value rather than clamping.  `None` leaves the leg
    /// codec's own PCM rate with no conversion in either direction.  Inert
    /// without [`NgFlags::ws_uri`].
    pub ws_sample_rate: Option<u32>,
    /// Which detector the WS uplink VAD runs.  `None` leaves the engine's
    /// default ([`WsVadEngine::Energy`]).  Only meaningful with
    /// [`NgFlags::ws_vad`] / [`NgFlags::ws_barge_in`].
    pub ws_vad_engine: Option<WsVadEngine>,
    /// **Leading** minimum-speech run in milliseconds: how long the uplink must
    /// read as speech *continuously* before the `speech_started` edge (and
    /// barge-in) fires.  Distinct from the *trailing*
    /// [`NgFlags::ws_vad_hangover_ms`].
    ///
    /// `None` means no leading requirement — the edge fires on the first speech
    /// frame, which is what lets a cough, a door or one burst of echo interrupt
    /// a prompt.  Rounded up to whole ptime frames by the engine, and it adds
    /// directly to turn-start latency, so 60–120 ms is the useful range.  Works
    /// with either detector.  Only meaningful with [`NgFlags::ws_vad`] /
    /// [`NgFlags::ws_barge_in`].
    pub ws_vad_min_speech_ms: Option<u32>,
    /// Watch this leg's decoded ingress audio for the short single tone an
    /// answering machine plays before it starts recording (the "voicemail
    /// beep"), reporting it as `@rtpengine.on_beep` — the media half of
    /// answering-machine detection, so a script can abort a transfer instead of
    /// bridging the caller into a voicemail box.
    ///
    /// Set **per leg**: the flag arms the detector on the leg whose
    /// `offer`/`answer` carries it, so arming it on the outbound (callee) leg is
    /// what watches the party that might be a machine.  Like
    /// [`NgFlags::noise_suppression`] it needs decoded audio, so it promotes a
    /// same-codec plaintext call onto the userspace media pipeline, and it is
    /// inert on a codec whose native rate is neither 8 nor 16 kHz.
    ///
    /// Fires **once per leg per call** — there is no mid-call re-arm; a fresh
    /// `offer`/`answer` with the flag set re-arms it.
    ///
    /// A native `siphon-rtp` extension: the NG/bencode and rtpproxy backends
    /// have no equivalent and cannot honour it.
    pub beep_detection: bool,
    /// How long in milliseconds the beep detector waits after a candidate tone
    /// ends to confirm no repeat follows — the discriminator that keeps a
    /// cadenced ringback / busy / congestion tone from reading as a record tone.
    ///
    /// It is **also the detection latency**: the event arrives this long after
    /// the beep.  `None` uses the engine default (4500 ms, longer than the 4 s
    /// silent interval of the slowest widely deployed ringback cadence).  Lower
    /// it to trade cadence robustness for latency.  Inert without
    /// [`NgFlags::beep_detection`].
    pub beep_cadence_guard_ms: Option<u32>,
    /// Attach a **WebSocket tee** to this call at offer/answer time — the
    /// declarative twin of `rtpengine.attach_ws_tee(...)`, so a profile can turn
    /// the tee on without a second round-trip.
    ///
    /// The critical distinction from [`NgFlags::ws_uri`]: `ws_uri` is a
    /// **takeover** — the WS server *becomes* leg A's far side and the A↔B relay
    /// is not wired.  A tee is **send-only and additive** — the call relays (or
    /// transcodes) normally *and* streams a copy of its decoded audio to this
    /// URI, leaving any SIPREC subscription and recording untouched.  Setting
    /// both on one profile is legal but almost never what you want.
    ///
    /// Applied once the call's media path exists (on `answer` / `answer_local`)
    /// and torn down with the call.
    ///
    /// A native `siphon-rtp` extension: the NG/bencode and rtpproxy backends
    /// have no equivalent and cannot honour it.
    pub ws_tee: Option<String>,
    /// Which leg(s) [`NgFlags::ws_tee`] streams.  `None` leaves the engine's
    /// default (both).  Inert without [`NgFlags::ws_tee`].
    pub ws_tee_direction: Option<WsTeeDirection>,
    /// Wire channel count for [`NgFlags::ws_tee`]: `2` interleaves caller/callee
    /// as stereo, `1` mixes them to mono.  Only meaningful streaming both legs —
    /// a single-leg tee is always mono.  `None` leaves the engine's default (2
    /// for both legs, 1 for one).  Inert without [`NgFlags::ws_tee`].
    pub ws_tee_channels: Option<u8>,
    /// L16 wire sample rate in Hz for [`NgFlags::ws_tee`], independent of the
    /// legs' codec rates — the engine resamples the teed copy into it.  Unlike
    /// [`NgFlags::ws_sample_rate`] this is send-only, so it affects only what the
    /// tee consumer receives and never what the call itself hears.
    ///
    /// Must satisfy [`validate_ws_sample_rate`]; the engine *fails* the
    /// offer/answer on a bad value rather than clamping.  `None` leaves the
    /// engine's default.  Inert without [`NgFlags::ws_tee`].
    pub ws_tee_sample_rate: Option<u32>,
    /// Profile **policy**: carry the real post-NAT source IP the proxy saw this
    /// request arrive from (rtpengine's `received from`) on offer/answer.
    ///
    /// Separate from [`NgFlags::received_from`] because the policy comes from
    /// YAML at startup while the address is per-call data that only exists once
    /// a message is in hand.  Opt-in, so a profile that does not set it emits a
    /// byte-identical command to before this field existed.
    pub carry_received_from: bool,
    /// The per-call value behind [`NgFlags::carry_received_from`], injected by
    /// the script API from the message's source address just before the command
    /// is sent.  Never populated from YAML.
    ///
    /// When a NATed UA advertises a private `c=` address its media actually
    /// originates from its NAT's public IP; gating ingress to that is a
    /// *tighter* RTPBleed source gate than the unusable signalled address.  Only
    /// the IP is carried — the media port differs from the signalling port, so
    /// the port is never gated.
    pub received_from: Option<std::net::IpAddr>,
    /// `rtcp-mux` directive list (`offer` | `require` | `demux` | `accept` |
    /// `reject` | `remove`), overriding the mux decision the engine would derive
    /// from the offered SDP (RFC 5761).  Empty mirrors the offer (the default).
    ///
    /// Honoured by rtpengine and `siphon-rtp`; the classic `rtpproxy` backend
    /// has no equivalent.
    pub rtcp_mux: Vec<String>,
}

impl NgFlags {
    /// Build from the YAML config representation.
    ///
    /// [`NgFlags::received_from`] is deliberately left `None`: the config only
    /// carries the *policy* (`carry_received_from`); the address itself is
    /// per-call and is injected by the script API.
    pub fn from_config(config: &NgFlagsConfig) -> Self {
        Self {
            transport_protocol: config.transport_protocol.clone(),
            codec: CodecFlags::from_config(&config.codec),
            ice: config.ice.clone(),
            dtls: config.dtls.clone(),
            replace: config.replace.clone(),
            address_family: config.address_family.clone(),
            flags: config.flags.clone(),
            direction: config.direction.clone(),
            record_call: config.record_call,
            record_path: config.record_path.clone(),
            text_events: config.text_events,
            noise_suppression: config.noise_suppression,
            echo_cancellation: config.echo_cancellation,
            ws_uri: config.ws_uri.clone(),
            ws_vad: config.ws_vad,
            ws_barge_in: config.ws_barge_in,
            ws_vad_threshold: config.ws_vad_threshold,
            ws_vad_hangover_ms: config.ws_vad_hangover_ms,
            ws_sample_rate: config.ws_sample_rate,
            ws_vad_engine: config.ws_vad_engine,
            ws_vad_min_speech_ms: config.ws_vad_min_speech_ms,
            beep_detection: config.beep_detection,
            beep_cadence_guard_ms: config.beep_cadence_guard_ms,
            ws_tee: config.ws_tee.clone(),
            ws_tee_direction: config.ws_tee_direction,
            ws_tee_channels: config.ws_tee_channels,
            ws_tee_sample_rate: config.ws_tee_sample_rate,
            carry_received_from: config.received_from,
            received_from: None,
            rtcp_mux: config.rtcp_mux.clone(),
        }
    }

    /// Convert these flags to bencode dict entries to merge into the command dict.
    pub fn to_bencode_pairs(&self) -> Vec<(&str, super::bencode::BencodeValue)> {
        use super::bencode::BencodeValue;

        let mut pairs = Vec::new();

        if let Some(transport_protocol) = &self.transport_protocol {
            pairs.push((
                "transport-protocol",
                BencodeValue::string(transport_protocol),
            ));
        }
        // rtpengine takes codec manipulation as a nested dict under `codec`,
        // not as tokens in `flags`.
        if let Some(codec) = self.codec.to_bencode() {
            pairs.push(("codec", codec));
        }
        if let Some(ice) = &self.ice {
            pairs.push(("ICE", BencodeValue::string(ice)));
        }
        if let Some(dtls) = &self.dtls {
            pairs.push(("DTLS", BencodeValue::string(dtls)));
        }
        if !self.replace.is_empty() {
            let items: Vec<&str> = self.replace.iter().map(|s| s.as_str()).collect();
            pairs.push(("replace", BencodeValue::string_list(&items)));
        }
        // rtpengine reads the address family from a dedicated dict key
        // (`"address family": "IP4"`), NOT as a token in the `flags` list — a
        // family smuggled into `flags` is silently dropped by the engine.
        if let Some(address_family) = &self.address_family {
            pairs.push(("address family", BencodeValue::string(address_family)));
        }
        if !self.flags.is_empty() {
            let items: Vec<&str> = self.flags.iter().map(|s| s.as_str()).collect();
            pairs.push(("flags", BencodeValue::string_list(&items)));
        }
        if !self.direction.is_empty() {
            let items: Vec<&str> = self.direction.iter().map(|s| s.as_str()).collect();
            pairs.push(("direction", BencodeValue::string_list(&items)));
        }
        if self.record_call {
            pairs.push(("record call", BencodeValue::string("yes")));
        }
        if let Some(record_path) = &self.record_path {
            pairs.push(("recording-dir", BencodeValue::string(record_path)));
        }
        // rtpengine takes the source gate as a two-element `[family, address]`
        // list under `"received from"`, the same shape it uses for `"media
        // address"`.  Only emitted once the script API has injected the address
        // (`carry_received_from` alone changes nothing on the wire).
        if let Some(received_from) = &self.received_from {
            let family = if received_from.is_ipv6() { "IP6" } else { "IP4" };
            let address = received_from.to_string();
            pairs.push((
                "received from",
                BencodeValue::List(vec![
                    BencodeValue::string(family),
                    BencodeValue::string(&address),
                ]),
            ));
        }
        if !self.rtcp_mux.is_empty() {
            let items: Vec<&str> = self.rtcp_mux.iter().map(|s| s.as_str()).collect();
            pairs.push(("rtcp-mux", BencodeValue::string_list(&items)));
        }
        // The WS bridge, WS tee, VAD, beep-detection and DSP knobs (ws_uri,
        // ws_vad, ws_barge_in, ws_vad_threshold, ws_vad_hangover_ms,
        // ws_vad_engine, ws_vad_min_speech_ms, ws_sample_rate, ws_tee,
        // ws_tee_direction, ws_tee_channels, ws_tee_sample_rate,
        // beep_detection, beep_cadence_guard_ms, noise_suppression,
        // echo_cancellation) are native siphon-rtp extensions with no NG
        // equivalent, so they are deliberately not emitted here.  A profile that
        // sets them on this backend is rejected at config load rather than
        // silently degraded — see
        // `MediaBackendKind::unsupported_profile_fields`.

        pairs
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    /// The profiles that re-pair badly. A transfer or a `Replaces` takeover
    /// changes who is on each side of the call, so a profile whose two halves
    /// describe *specific* sides stops being correct the moment the pairing
    /// changes — its answer half was written for the party that just left.
    #[test]
    fn direction_bound_profiles_are_recognised() {
        let registry = ProfileRegistry::new();

        // Asymmetric transport (an SRTP edge) — the classic trap: after a
        // transfer the surviving carrier leg gets re-offered SRTP and answers
        // `m=audio 0`, leaving a connected call with no audio.
        for name in ["srtp_to_rtp", "rtp_to_srtp", "ws_to_rtp", "wss_to_rtp"] {
            let entry = registry.get(name).expect("built-in profile must exist");
            assert!(
                entry.is_direction_bound(),
                "{name} names specific sides and must be flagged"
            );
        }

        // A symmetric relay re-pairs safely — both halves say the same thing.
        let passthrough = registry
            .get("rtp_passthrough")
            .expect("built-in profile must exist");
        assert!(
            !passthrough.is_direction_bound(),
            "rtp_passthrough is symmetric and survives a re-pairing"
        );
    }

    /// The `codec` dict must reach rtpengine as a NESTED DICT under `codec`,
    /// not as tokens in `flags` — a codec list smuggled into `flags` is
    /// silently dropped by the engine, which is the failure mode this whole
    /// feature exists to remove.
    #[test]
    fn codec_flags_encode_as_a_nested_dict() {
        let flags = NgFlags {
            transport_protocol: Some("RTP/AVP".into()),
            codec: CodecFlags {
                strip: vec!["SILK".into(), "G722".into()],
                offer: vec!["PCMA".into(), "PCMU".into()],
                transcode: vec!["PCMA".into()],
                ..CodecFlags::default()
            },
            ..NgFlags::default()
        };

        let pairs = flags.to_bencode_pairs();
        let (_, codec) = pairs
            .iter()
            .find(|(key, _)| *key == "codec")
            .expect("codec must be its own dict key");

        let encoded =
            String::from_utf8_lossy(&crate::rtpengine::bencode::encode(codec)).to_string();
        // Bencode dict of three string lists, keys in the order emitted.
        assert!(encoded.contains("strip"), "strip missing: {encoded}");
        assert!(encoded.contains("SILK"), "SILK missing: {encoded}");
        assert!(encoded.contains("offer"), "offer missing: {encoded}");
        assert!(encoded.contains("PCMA"), "PCMA missing: {encoded}");
        assert!(encoded.contains("transcode"), "transcode missing: {encoded}");

        // Empty lists never reach the wire.
        assert!(!encoded.contains("mask"), "an unset key leaked: {encoded}");
        assert!(!encoded.contains("ignore"), "an unset key leaked: {encoded}");

        // And it is NOT folded into `flags`.
        let flags_pair = pairs.iter().find(|(key, _)| *key == "flags");
        assert!(
            flags_pair.is_none(),
            "codec manipulation must not be smuggled into the flags list"
        );
    }

    /// The native engine takes the same codec model off its flag list, so the
    /// block is flattened to `codec-<op>-<NAME>` for it. One profile, two
    /// engines — an operator does not write the policy twice.
    #[test]
    fn codec_flags_flatten_for_the_native_engine() {
        let codec = CodecFlags {
            strip: vec!["SILK".into()],
            offer: vec!["PCMA".into(), "PCMU".into()],
            transcode: vec!["PCMA".into()],
            except: vec!["telephone-event".into()],
            ..CodecFlags::default()
        };
        let flat = codec.to_native_flags();

        assert!(flat.contains(&"codec-strip-SILK".to_string()), "{flat:?}");
        assert!(flat.contains(&"codec-offer-PCMA".to_string()), "{flat:?}");
        assert!(flat.contains(&"codec-offer-PCMU".to_string()), "{flat:?}");
        assert!(flat.contains(&"codec-transcode-PCMA".to_string()), "{flat:?}");
        assert!(
            flat.contains(&"codec-except-telephone-event".to_string()),
            "{flat:?}"
        );
        // Order within `offer` is the operator's stated preference and must survive.
        let offer_positions: Vec<usize> = ["codec-offer-PCMA", "codec-offer-PCMU"]
            .iter()
            .map(|needle| flat.iter().position(|f| f == needle).expect("present"))
            .collect();
        assert!(
            offer_positions[0] < offer_positions[1],
            "codec-offer order is the preference order: {flat:?}"
        );

        // The two ops the engine has no equivalent for are never emitted...
        let unmappable = CodecFlags {
            ignore: vec!["G729".into()],
            set: vec!["opus/48000/2".into()],
            ..CodecFlags::default()
        };
        assert!(
            unmappable.to_native_flags().is_empty(),
            "unmappable ops must not be flattened into something meaningless"
        );
        // ...and are reported so the config gate can refuse them.
        assert_eq!(
            unmappable.native_unsupported_ops(),
            vec!["codec.ignore", "codec.set"]
        );
    }

    /// Nothing set means no `codec` key at all, rather than an empty dict the
    /// engine would have to interpret.
    #[test]
    fn absent_codec_flags_emit_no_key() {
        let flags = NgFlags {
            transport_protocol: Some("RTP/AVP".into()),
            ..NgFlags::default()
        };
        assert!(
            !flags
                .to_bencode_pairs()
                .iter()
                .any(|(key, _)| *key == "codec"),
            "an empty codec dict must not be sent"
        );
        assert!(CodecFlags::default().is_empty());
    }

    /// Codec policy is chosen for the party on the far side of that half, so a
    /// profile that strips one way and not the other is as side-specific as an
    /// SRTP edge — and equally wrong to inherit across a transfer.
    #[test]
    fn asymmetric_codec_policy_is_direction_bound() {
        let entry = ProfileEntry {
            offer: NgFlags {
                codec: CodecFlags {
                    offer: vec!["PCMA".into(), "PCMU".into()],
                    ..CodecFlags::default()
                },
                ..NgFlags::default()
            },
            answer: NgFlags::default(),
        };
        assert!(entry.is_direction_bound());

        // The same policy on both halves re-pairs safely.
        let symmetric = ProfileEntry {
            offer: NgFlags {
                codec: CodecFlags {
                    strip: vec!["SILK".into()],
                    ..CodecFlags::default()
                },
                ..NgFlags::default()
            },
            answer: NgFlags {
                codec: CodecFlags {
                    strip: vec!["SILK".into()],
                    ..CodecFlags::default()
                },
                ..NgFlags::default()
            },
        };
        assert!(!symmetric.is_direction_bound());
    }

    /// A `direction` pair is direction-bound by definition, even when both
    /// halves negotiate the same transport.
    #[test]
    fn a_direction_pair_alone_is_direction_bound() {
        let entry = ProfileEntry {
            offer: NgFlags {
                direction: vec!["external".into(), "internal".into()],
                ..NgFlags::default()
            },
            answer: NgFlags {
                direction: vec!["internal".into(), "external".into()],
                ..NgFlags::default()
            },
        };
        assert!(entry.is_direction_bound());
    }

    use super::*;

    #[test]
    fn ws_vad_engine_round_trips_its_wire_spelling() {
        for engine in [WsVadEngine::Energy, WsVadEngine::Neural] {
            assert_eq!(WsVadEngine::parse(engine.as_str()), Some(engine));
        }
        // Case-insensitive and whitespace-tolerant, matching WsTeeDirection.
        assert_eq!(WsVadEngine::parse("  NEURAL "), Some(WsVadEngine::Neural));
        // Anything else is None so the caller can raise a named error rather
        // than silently downgrading to the detector the operator avoided.
        assert_eq!(WsVadEngine::parse("telepathy"), None);
        assert_eq!(WsVadEngine::parse(""), None);
        assert_eq!(WsVadEngine::default(), WsVadEngine::Energy);
    }

    #[test]
    fn ws_sample_rate_validation_matches_the_engines_rule() {
        // Whole kHz within 8000-48000 inclusive.
        for rate in [8_000, 16_000, 24_000, 47_000, 48_000] {
            assert!(validate_ws_sample_rate(rate).is_ok(), "{rate} must be accepted");
        }
        // Out of range, or not a whole kHz. The engine fails the offer on these
        // rather than clamping, so they must never reach it.
        for rate in [0, 1_000, 7_999, 44_100, 48_001, 96_000] {
            let error = validate_ws_sample_rate(rate)
                .expect_err(&format!("{rate} must be rejected"));
            assert!(
                error.contains(&rate.to_string()),
                "reason should quote the offending rate: {error}"
            );
        }
    }

    #[test]
    fn default_registry_has_builtins() {
        let registry = ProfileRegistry::new();
        assert!(registry.get("srtp_to_rtp").is_some());
        assert!(registry.get("rtp_to_srtp").is_some());
        assert!(registry.get("ws_to_rtp").is_some());
        assert!(registry.get("wss_to_rtp").is_some());
        assert!(registry.get("rtp_passthrough").is_some());
        assert!(registry.get("srs_recording").is_some());
        assert!(registry.get("siprec_src").is_some());
        assert!(registry.get("voice_ai").is_some());
    }

    #[test]
    fn unknown_profile_returns_none() {
        let registry = ProfileRegistry::new();
        assert!(registry.get("invalid").is_none());
        assert!(registry.get("").is_none());
    }

    #[test]
    fn profile_names_sorted() {
        let registry = ProfileRegistry::new();
        let names = registry.profile_names();
        assert_eq!(
            names,
            vec![
                "rtp_passthrough",
                "rtp_to_srtp",
                "siprec_src",
                "srs_recording",
                "srtp_to_rtp",
                "voice_ai",
                "ws_to_rtp",
                "wss_to_rtp",
            ]
        );
    }

    #[test]
    fn custom_profile_from_config() {
        let mut custom = HashMap::new();
        custom.insert(
            "my_profile".to_string(),
            MediaProfileConfig {
                offer: NgFlagsConfig {
                    transport_protocol: Some("RTP/SAVPF".into()),
                    ice: Some("force".into()),
                    dtls: Some("passive".into()),
                    replace: vec!["origin".into()],
                    direction: vec!["external".into(), "internal".into()],
                    ..NgFlagsConfig::default()
                },
                answer: NgFlagsConfig {
                    transport_protocol: Some("RTP/AVP".into()),
                    ice: Some("remove".into()),
                    dtls: Some("off".into()),
                    replace: vec!["origin".into()],
                    direction: vec!["internal".into(), "external".into()],
                    ..NgFlagsConfig::default()
                },
            },
        );
        let registry = ProfileRegistry::from_config(&custom);
        // Custom profile exists
        let entry = registry.get("my_profile").unwrap();
        assert_eq!(entry.offer.transport_protocol.as_deref(), Some("RTP/SAVPF"));
        assert_eq!(entry.answer.dtls.as_deref(), Some("off"));
        // Built-ins still exist
        assert!(registry.get("srtp_to_rtp").is_some());
        assert_eq!(registry.profile_names().len(), 9);
    }

    #[test]
    fn custom_profile_overrides_builtin() {
        let mut custom = HashMap::new();
        custom.insert(
            "srtp_to_rtp".to_string(),
            MediaProfileConfig {
                offer: NgFlagsConfig {
                    transport_protocol: Some("CUSTOM/OFFER".into()),
                    ..NgFlagsConfig::default()
                },
                answer: NgFlagsConfig {
                    transport_protocol: Some("CUSTOM/ANSWER".into()),
                    ..NgFlagsConfig::default()
                },
            },
        );
        let registry = ProfileRegistry::from_config(&custom);
        let entry = registry.get("srtp_to_rtp").unwrap();
        assert_eq!(
            entry.offer.transport_protocol.as_deref(),
            Some("CUSTOM/OFFER")
        );
    }

    #[test]
    fn srtp_to_rtp_offer_flags() {
        let registry = ProfileRegistry::new();
        let entry = registry.get("srtp_to_rtp").unwrap();
        assert_eq!(entry.offer.transport_protocol.as_deref(), Some("RTP/SAVP"));
        assert_eq!(entry.offer.ice.as_deref(), Some("remove"));
        assert!(entry.offer.dtls.is_none());
        assert_eq!(entry.offer.replace, vec!["origin"]);
        assert!(entry.offer.flags.is_empty());
        assert_eq!(entry.offer.direction, vec!["external", "internal"]);
    }

    #[test]
    fn srtp_to_rtp_answer_flags() {
        let registry = ProfileRegistry::new();
        let entry = registry.get("srtp_to_rtp").unwrap();
        assert_eq!(entry.answer.transport_protocol.as_deref(), Some("RTP/AVP"));
        assert_eq!(entry.answer.ice.as_deref(), Some("remove"));
        assert_eq!(entry.answer.direction, vec!["internal", "external"]);
    }

    #[test]
    fn ws_to_rtp_offer_flags() {
        let registry = ProfileRegistry::new();
        let entry = registry.get("ws_to_rtp").unwrap();
        assert_eq!(entry.offer.transport_protocol.as_deref(), Some("RTP/AVPF"));
        assert_eq!(entry.offer.ice.as_deref(), Some("force"));
    }

    #[test]
    fn wss_to_rtp_offer_flags() {
        let registry = ProfileRegistry::new();
        let entry = registry.get("wss_to_rtp").unwrap();
        assert_eq!(
            entry.offer.transport_protocol.as_deref(),
            Some("RTP/SAVPF")
        );
        assert_eq!(entry.offer.ice.as_deref(), Some("force"));
        assert_eq!(entry.offer.dtls.as_deref(), Some("passive"));
    }

    #[test]
    fn wss_to_rtp_answer_flags() {
        let registry = ProfileRegistry::new();
        let entry = registry.get("wss_to_rtp").unwrap();
        assert_eq!(entry.answer.transport_protocol.as_deref(), Some("RTP/AVP"));
        assert_eq!(entry.answer.ice.as_deref(), Some("remove"));
        assert_eq!(entry.answer.dtls.as_deref(), Some("off"));
    }

    #[test]
    fn rtp_passthrough_flags() {
        let registry = ProfileRegistry::new();
        let entry = registry.get("rtp_passthrough").unwrap();
        assert!(entry.offer.transport_protocol.is_none());
        assert!(entry.offer.ice.is_none());
        assert_eq!(entry.offer.flags, vec!["trust-address"]);
        assert!(entry.offer.direction.is_empty());
        // Passthrough: offer and answer flags are symmetric.
        assert_eq!(entry.offer.flags, entry.answer.flags);
    }

    #[test]
    fn siprec_src_offer_flags() {
        let registry = ProfileRegistry::new();
        let entry = registry.get("siprec_src").unwrap();
        assert_eq!(entry.offer.transport_protocol.as_deref(), Some("RTP/AVP"));
        assert_eq!(entry.offer.ice.as_deref(), Some("remove"));
        assert_eq!(entry.offer.dtls.as_deref(), Some("off"));
        assert_eq!(entry.offer.replace, vec!["origin"]);
        assert!(!entry.offer.record_call);
    }

    #[test]
    fn ng_flags_to_bencode_pairs_full() {
        let registry = ProfileRegistry::new();
        let entry = registry.get("wss_to_rtp").unwrap();
        let pairs = entry.offer.to_bencode_pairs();
        let keys: Vec<&str> = pairs.iter().map(|(k, _)| *k).collect();
        assert!(keys.contains(&"transport-protocol"));
        assert!(keys.contains(&"ICE"));
        assert!(keys.contains(&"DTLS"));
        assert!(keys.contains(&"replace"));
        assert!(keys.contains(&"direction"));
        // No flags for WSS offer.
        assert!(!keys.contains(&"flags"));
    }

    #[test]
    fn ng_flags_to_bencode_pairs_minimal() {
        let flags = NgFlags::default();
        let pairs = flags.to_bencode_pairs();
        assert!(pairs.is_empty());
    }

    /// Regression check: `record_call` and `record_path` (set in user YAML
    /// or in the built-in `srs_recording` profile) MUST appear in the bencode
    /// emission as the keys RTPEngine actually understands. An audit once
    /// claimed these were dead config; if anyone inadvertently drops the
    /// emission again this test catches it.
    #[test]
    fn ng_flags_emits_record_call_and_recording_dir() {
        let flags = NgFlags {
            record_call: true,
            record_path: Some("/var/spool/rtpengine".into()),
            ..NgFlags::default()
        };
        let pairs = flags.to_bencode_pairs();
        let keys: Vec<&str> = pairs.iter().map(|(k, _)| *k).collect();
        assert!(keys.contains(&"record call"), "missing 'record call' key");
        assert!(keys.contains(&"recording-dir"), "missing 'recording-dir' key");
    }

    /// `address family` must ride its own NG dict key with the SDP `addrtype`
    /// spelling.  rtpengine reads the family from that key only — a family put in
    /// the free-form `flags` list is silently ignored by the engine, which is the
    /// exact bug this key exists to avoid.
    #[test]
    fn ng_flags_emits_address_family_as_its_own_key() {
        let flags = NgFlags {
            address_family: Some("IP4".into()),
            ..NgFlags::default()
        };
        let pairs = flags.to_bencode_pairs();
        let (key, value) = pairs
            .iter()
            .find(|(key, _)| *key == "address family")
            .expect("missing 'address family' key");
        assert_eq!(*key, "address family");
        assert_eq!(*value, super::super::bencode::BencodeValue::string("IP4"));
        // Never smuggled into the flags list.
        assert!(!pairs.iter().any(|(key, _)| *key == "flags"));
    }

    #[test]
    fn ng_flags_omits_address_family_when_unset() {
        let flags = NgFlags::default();
        assert!(!flags
            .to_bencode_pairs()
            .iter()
            .any(|(key, _)| *key == "address family"));
    }

    // -- received_from / rtcp_mux on the NG (bencode) wire --------------------

    /// rtpengine wants the source gate as a `[family, address]` pair, the same
    /// shape it uses for `"media address"`.
    #[test]
    fn ng_flags_emits_received_from_as_family_address_pair() {
        use super::super::bencode::BencodeValue;

        let flags = NgFlags {
            received_from: Some("198.51.100.7".parse().unwrap()),
            ..NgFlags::default()
        };
        let pairs = flags.to_bencode_pairs();
        let (_, value) = pairs
            .iter()
            .find(|(key, _)| *key == "received from")
            .expect("missing 'received from' key");
        assert_eq!(
            *value,
            BencodeValue::List(vec![
                BencodeValue::string("IP4"),
                BencodeValue::string("198.51.100.7"),
            ])
        );
    }

    #[test]
    fn ng_flags_emits_received_from_with_ip6_family() {
        use super::super::bencode::BencodeValue;

        let flags = NgFlags {
            received_from: Some("2001:db8::7".parse().unwrap()),
            ..NgFlags::default()
        };
        let pairs = flags.to_bencode_pairs();
        let (_, value) = pairs
            .iter()
            .find(|(key, _)| *key == "received from")
            .expect("missing 'received from' key");
        assert_eq!(
            *value,
            BencodeValue::List(vec![
                BencodeValue::string("IP6"),
                BencodeValue::string("2001:db8::7"),
            ])
        );
    }

    /// The policy bit alone must not reach the wire — only the injected address
    /// does, so an opted-in profile on a call with no usable source address
    /// emits exactly what it did before.
    #[test]
    fn ng_flags_omits_received_from_without_injected_address() {
        let flags = NgFlags {
            carry_received_from: true,
            ..NgFlags::default()
        };
        assert!(!flags
            .to_bencode_pairs()
            .iter()
            .any(|(key, _)| *key == "received from"));
    }

    #[test]
    fn ng_flags_emits_rtcp_mux_directives() {
        use super::super::bencode::BencodeValue;

        let flags = NgFlags {
            rtcp_mux: vec!["offer".into(), "require".into()],
            ..NgFlags::default()
        };
        let pairs = flags.to_bencode_pairs();
        let (_, value) = pairs
            .iter()
            .find(|(key, _)| *key == "rtcp-mux")
            .expect("missing 'rtcp-mux' key");
        assert_eq!(*value, BencodeValue::string_list(&["offer", "require"]));
    }

    /// The WS bridge and DSP knobs have no NG equivalent.  They must not leak
    /// onto the bencode wire under any spelling — an engine that does not know
    /// the key would ignore it, and the call would look configured and be silent.
    #[test]
    fn ng_flags_never_emits_websocket_or_dsp_fields() {
        let flags = NgFlags {
            ws_uri: Some("wss://ai.invalid/stream".into()),
            ws_vad: true,
            ws_barge_in: true,
            ws_vad_threshold: Some(2_000_000),
            ws_vad_hangover_ms: Some(300),
            noise_suppression: true,
            echo_cancellation: true,
            ..NgFlags::default()
        };
        let pairs = flags.to_bencode_pairs();
        assert!(
            pairs.is_empty(),
            "WS/DSP-only flags must produce no NG pairs, got: {:?}",
            pairs.iter().map(|(key, _)| *key).collect::<Vec<_>>()
        );
    }

    /// The no-wire-drift guard for the NG backend: default flags emit nothing.
    #[test]
    fn ng_flags_default_emits_no_pairs() {
        assert!(NgFlags::default().to_bencode_pairs().is_empty());
    }

    // -- config → flags for the new fields ------------------------------------

    #[test]
    fn websocket_and_dsp_fields_flow_from_config_to_flags() {
        let config = NgFlagsConfig {
            ws_uri: Some("wss://ai.example.com/stream".into()),
            ws_vad: true,
            ws_barge_in: true,
            ws_vad_threshold: Some(2_000_000),
            ws_vad_hangover_ms: Some(300),
            noise_suppression: true,
            echo_cancellation: true,
            received_from: true,
            rtcp_mux: vec!["require".into()],
            ..NgFlagsConfig::default()
        };
        let flags = NgFlags::from_config(&config);
        assert_eq!(flags.ws_uri.as_deref(), Some("wss://ai.example.com/stream"));
        assert!(flags.ws_vad);
        assert!(flags.ws_barge_in);
        assert_eq!(flags.ws_vad_threshold, Some(2_000_000));
        assert_eq!(flags.ws_vad_hangover_ms, Some(300));
        assert!(flags.noise_suppression);
        assert!(flags.echo_cancellation);
        assert_eq!(flags.rtcp_mux, vec!["require"]);
        // The YAML carries the policy; the address is per-call and stays unset
        // until the script API injects it.
        assert!(flags.carry_received_from);
        assert!(flags.received_from.is_none());
    }

    /// A profile's `address_family` must survive the YAML → `NgFlags` hop; it
    /// previously had no `NgFlagsConfig` source at all.
    #[test]
    fn address_family_flows_from_config_to_flags() {
        let mut custom = HashMap::new();
        custom.insert(
            "v6_access_to_v4_core".to_string(),
            MediaProfileConfig {
                offer: NgFlagsConfig {
                    replace: vec!["origin".into()],
                    address_family: Some("IP4".into()),
                    ..NgFlagsConfig::default()
                },
                answer: NgFlagsConfig {
                    replace: vec!["origin".into()],
                    address_family: Some("IP6".into()),
                    ..NgFlagsConfig::default()
                },
            },
        );
        let registry = ProfileRegistry::from_config(&custom);
        let entry = registry.get("v6_access_to_v4_core").unwrap();
        assert_eq!(entry.offer.address_family.as_deref(), Some("IP4"));
        assert_eq!(entry.answer.address_family.as_deref(), Some("IP6"));
        let keys: Vec<&str> = entry
            .offer
            .to_bencode_pairs()
            .iter()
            .map(|(key, _)| *key)
            .collect();
        assert!(keys.contains(&"address family"));
    }

    /// Built-ins must stay family-agnostic — anchoring a plain call must not
    /// suddenly pin a relay family (that would be a silent wire change).
    #[test]
    fn builtin_profiles_leave_address_family_unset() {
        let registry = ProfileRegistry::new();
        for name in registry.profile_names() {
            let entry = registry.get(name).unwrap();
            assert!(
                entry.offer.address_family.is_none(),
                "{name} offer pins an address family"
            );
            assert!(
                entry.answer.address_family.is_none(),
                "{name} answer pins an address family"
            );
        }
    }

    #[test]
    fn srs_recording_builtin_emits_record_call() {
        let registry = ProfileRegistry::new();
        let entry = registry.get("srs_recording").expect("srs_recording profile");
        assert!(entry.offer.record_call, "srs_recording offer must record_call");
        let pairs = entry.offer.to_bencode_pairs();
        let keys: Vec<&str> = pairs.iter().map(|(k, _)| *k).collect();
        assert!(keys.contains(&"record call"));
    }
}
