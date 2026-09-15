//! `media:` backend selection, engine instances and media profiles.

use crate::rtpengine::profile::{validate_ws_sample_rate, WsTeeDirection, WsVadEngine};
use serde::{Deserialize, Deserializer};

// ---------------------------------------------------------------------------
// Media (RTPEngine)
// ---------------------------------------------------------------------------

/// Which media-control backend siphon drives.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum MediaBackendKind {
    /// rtpengine NG protocol (bencode over UDP) — the default.
    #[default]
    Rtpengine,
    /// Native `siphon-rtp` control protocol (JSON over TCP).
    SiphonRtp,
    /// Classic `rtpproxy` control protocol (text over UDP).
    Rtpproxy,
}

impl MediaBackendKind {
    /// The engine's name as it appears in `media.backend`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rtpengine => "rtpengine",
            Self::SiphonRtp => "siphon-rtp",
            Self::Rtpproxy => "rtpproxy",
        }
    }

    /// Which of `flags`' set fields this backend has no way to express.
    ///
    /// The WebSocket bridge, the WebSocket tee and the DSP knobs are native
    /// `siphon-rtp` extensions; `received_from` and `rtcp_mux` are also real
    /// rtpengine NG keys but have no `rtpproxy` equivalent.
    ///
    /// A field the engine cannot honour is not a degraded call, it is a dead
    /// one — a `ws_uri` the engine never sees means the leg is answered and
    /// bridged nowhere, and the caller hears silence for its whole duration.
    /// So this drives a hard config error rather than the boot warning that
    /// covers `address_family` on `rtpproxy` (which merely loses IPv4/IPv6
    /// interworking on an otherwise working call).
    pub fn unsupported_profile_fields(self, flags: &NgFlagsConfig) -> Vec<&'static str> {
        let mut unsupported = Vec::new();

        if !matches!(self, Self::SiphonRtp) {
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
            if flags.ws_sample_rate.is_some() {
                unsupported.push("ws_sample_rate");
            }
            if flags.ws_vad_engine.is_some() {
                unsupported.push("ws_vad_engine");
            }
            if flags.ws_vad_min_speech_ms.is_some() {
                unsupported.push("ws_vad_min_speech_ms");
            }
            if flags.beep_detection {
                unsupported.push("beep_detection");
            }
            if flags.beep_cadence_guard_ms.is_some() {
                unsupported.push("beep_cadence_guard_ms");
            }
            if flags.noise_suppression {
                unsupported.push("noise_suppression");
            }
            if flags.echo_cancellation {
                unsupported.push("echo_cancellation");
            }
            if flags.echo_delay_search_ms.is_some() {
                unsupported.push("echo_delay_search_ms");
            }
            if flags.echo_long_tail {
                unsupported.push("echo_long_tail");
            }
            if flags.echo_residual_suppression {
                unsupported.push("echo_residual_suppression");
            }
            if flags.ws_tee.is_some() {
                unsupported.push("ws_tee");
            }
            if flags.ws_tee_direction.is_some() {
                unsupported.push("ws_tee_direction");
            }
            if flags.ws_tee_channels.is_some() {
                unsupported.push("ws_tee_channels");
            }
            if flags.ws_tee_sample_rate.is_some() {
                unsupported.push("ws_tee_sample_rate");
            }
            if flags.text_events {
                unsupported.push("text_events");
            }
        }

        if matches!(self, Self::Rtpproxy) {
            if flags.received_from {
                unsupported.push("received_from");
            }
            if !flags.rtcp_mux.is_empty() {
                unsupported.push("rtcp_mux");
            }
        }

        // Codec manipulation works on both real engines. rtpengine takes it as
        // its NG `codec` dict; the native engine implements the same model but
        // reads it off the flag list, so siphon flattens the block for it
        // (`CodecFlags::to_native_flags`). Only the two ops with no native
        // equivalent are refused there — the alternative is a config that reads
        // as "restricted to PCMA/PCMU" while every offered codec crosses
        // untouched, which is the failure this feature replaces.
        if matches!(self, Self::SiphonRtp) {
            for op in flags.codec.native_unsupported_ops() {
                unsupported.push(op);
            }
        }
        // rtpproxy is a plain relay with no transcoder and no codec control.
        if matches!(self, Self::Rtpproxy) && !flags.codec.is_empty() {
            unsupported.push("codec");
        }

        unsupported
    }
}

/// Media proxy configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct MediaConfig {
    /// Which media engine to drive. Defaults to `rtpengine` for backward
    /// compatibility; set to `siphon-rtp` to use the native JSON-over-TCP
    /// engine via the `siphon_rtp:` block below.
    ///
    /// Read it through [`MediaConfig::backend`]. `None` records that the key was
    /// left out, which [`MediaConfig::expects_engine`] needs to know.
    #[serde(default)]
    pub backend: Option<MediaBackendKind>,
    /// RTPEngine instance(s). A single instance or a list for load-balancing / HA.
    /// Required when `backend: rtpengine` (the default); ignored for `siphon-rtp`.
    #[serde(default)]
    pub rtpengine: Option<RtpEngineSetConfig>,
    /// Native `siphon-rtp` engine connection. Required when `backend: siphon-rtp`.
    #[serde(default)]
    pub siphon_rtp: Option<SiphonRtpConfig>,
    /// Classic `rtpproxy` relay connection. Required when `backend: rtpproxy`.
    #[serde(default)]
    pub rtpproxy: Option<RtpProxyConfig>,
    /// Custom media profiles (name → offer/answer NG flags).
    /// Built-in profiles (srtp_to_rtp, ws_to_rtp, wss_to_rtp, rtp_passthrough)
    /// are always available; custom entries here extend or override them.
    #[serde(default)]
    pub profiles: std::collections::HashMap<String, MediaProfileConfig>,
    /// Name used in SDP `o=` and `s=` lines when sanitizing relayed SDP.
    /// Hides the remote endpoint's identity (e.g. "FreeSWITCH") from the other leg.
    /// Defaults to "SIPhon" if not set.
    pub sdp_name: Option<String>,
    /// SDP attribute names siphon removes from the SDP it relays between the two
    /// legs of a B2BUA call, at session and media level, in both directions
    /// (e.g. `["msid"]`).
    ///
    /// The other half of what `sdp_name` does: `o=` and `s=` are rewritten, but
    /// every attribute otherwise crosses as the far side wrote it, including ones
    /// that carry its internal identifiers.  Matched case-insensitively and
    /// applied last on each relay path, after the media engine's rewrite, so an
    /// attribute the engine carries through is removed from what goes on the
    /// wire.  Empty by default, and then the relayed SDP is not looked at.
    #[serde(default, deserialize_with = "deserialize_sdp_strip_attributes")]
    pub sdp_strip_attributes: Vec<String>,
    /// Optional inbound event listener for rtpengine async notifications
    /// (DTMF, etc.).  Configure rtpengine with `dtmf-log-ng-tcp-uri=tcp://<this>`
    /// to make it deliver bencode-framed events here.
    pub events: Option<RtpEngineEventsConfig>,
    /// Interval in seconds between rtpengine NG `ping` health probes.
    /// The result is published as `siphon_rtpengine_instances_up` (count of
    /// healthy instances) and `siphon_rtpengine_instance_up{address}` (per
    /// instance 0/1).  Set to `0` to disable probing entirely.
    /// Default: 5.
    #[serde(default = "default_rtpengine_health_check_interval_secs")]
    pub health_check_interval_secs: u64,
}

impl MediaConfig {
    /// The media engine this block selects: `backend` as written, or rtpengine
    /// when the key is left out.
    pub fn backend(&self) -> MediaBackendKind {
        self.backend.unwrap_or_default()
    }

    /// Whether this block asks for a media engine at all.
    ///
    /// It does when it names a `backend`, gives an engine's connection block, or
    /// sets something only an engine uses: media `profiles` (engine flags) or the
    /// rtpengine `events` listener. A block with only `sdp_name` and
    /// `sdp_strip_attributes` shapes the SDP siphon relays and anchors nothing, so
    /// it has no engine to be missing. `health_check_interval_secs` has a default
    /// and cannot say either way, so on its own it does not count.
    pub fn expects_engine(&self) -> bool {
        self.backend.is_some()
            || self.rtpengine.is_some()
            || self.siphon_rtp.is_some()
            || self.rtpproxy.is_some()
            || !self.profiles.is_empty()
            || self.events.is_some()
    }
}

fn default_rtpengine_health_check_interval_secs() -> u64 {
    5
}

/// Configuration for siphon's inbound listener that accepts rtpengine's
/// async event notifications (DTMF, etc.) over NG-protocol TCP.
#[derive(Debug, Deserialize, Clone)]
pub struct RtpEngineEventsConfig {
    /// Socket address to listen on (e.g. ``"0.0.0.0:22226"``).
    pub listen_addr: String,
}

/// Connection to the native `siphon-rtp` media engine (JSON-over-TCP control).
///
/// Accepts a single engine (`address`) or several (`instances`) for HA /
/// load-balancing, mirroring `media.rtpengine`. Per-call-id affinity keeps all
/// of a call's commands on one connection (siphon-rtp keys call ownership to the
/// control connection). `control_secret` is shared across all instances.
///
/// Events (DTMF, media-timeout) arrive on the control connection itself, so the
/// rtpengine-specific `media.events` listener is not used with this backend.
#[derive(Debug, Deserialize, Clone)]
pub struct SiphonRtpConfig {
    /// Single control endpoint, e.g. ``"127.0.0.1:8080"``
    /// (`siphon-rtp --control <addr>`). Shorthand for one instance; ignored when
    /// `instances` is non-empty.
    #[serde(default)]
    pub address: Option<String>,
    /// Multiple control endpoints for HA / weighted load-balancing. Takes
    /// precedence over `address` when present.
    #[serde(default)]
    pub instances: Vec<SiphonRtpInstanceConfig>,
    /// Optional shared secret. When set, siphon authenticates each control
    /// connection before issuing commands (matches `siphon-rtp`'s
    /// `SIPHON_RTP_CONTROL_SECRET`). Supports `${VAR}` env expansion.
    #[serde(default)]
    pub control_secret: Option<String>,
    /// Default per-command response timeout in milliseconds (per-instance
    /// `timeout_ms` overrides it). Default: 2000.
    #[serde(default = "default_siphon_rtp_timeout_ms")]
    pub timeout_ms: u64,
    /// Fallback cap in milliseconds for a blocking `rtpengine.play_media()` — how
    /// long to wait for the prompt-finished event before giving up. A prompt can
    /// be far longer than a control request, so this is separate from
    /// `timeout_ms`. Default: 300000 (5 min).
    #[serde(default = "default_siphon_rtp_play_timeout_ms")]
    pub play_timeout_ms: u64,
}

impl SiphonRtpConfig {
    /// Normalized `(address, timeout_ms, weight)` tuples — from `instances` when
    /// present, else the single `address`. Empty when neither is configured.
    pub fn instances(&self) -> Vec<(String, u64, u32)> {
        if !self.instances.is_empty() {
            self.instances
                .iter()
                .map(|instance| {
                    (
                        instance.address.clone(),
                        instance.timeout_ms.unwrap_or(self.timeout_ms),
                        instance.weight,
                    )
                })
                .collect()
        } else if let Some(address) = &self.address {
            vec![(address.clone(), self.timeout_ms, 1)]
        } else {
            Vec::new()
        }
    }
}

/// One `siphon-rtp` control endpoint in a multi-instance set.
#[derive(Debug, Deserialize, Clone)]
pub struct SiphonRtpInstanceConfig {
    /// Control endpoint, e.g. ``"10.0.0.1:8080"``.
    pub address: String,
    /// Response timeout in ms; falls back to the parent `timeout_ms` when unset.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Weight for load-balancing (higher = more traffic). Default: 1.
    #[serde(default = "default_rtpengine_weight")]
    pub weight: u32,
}

/// Connection to a classic `rtpproxy` media relay (text-over-UDP control).
///
/// Accepts a single relay (`address`) or several (`instances`) for HA /
/// load-balancing, mirroring `media.rtpengine`. Per-call-id affinity keeps all
/// of a call's commands on one relay (the allocated ports live on one instance).
///
/// rtpproxy only allocates relay ports and returns them; siphon rewrites the SDP
/// itself. The rtpengine-only verbs (announcements, DTMF injection, gating,
/// SIPREC/MPTY) are not available on this backend. The rtpengine `media.events`
/// listener is also unused — rtpproxy pushes no async events.
#[derive(Debug, Deserialize, Clone)]
pub struct RtpProxyConfig {
    /// Single control endpoint, e.g. ``"127.0.0.1:22222"``
    /// (`rtpproxy -s udp:<addr>`). Shorthand for one instance; ignored when
    /// `instances` is non-empty.
    #[serde(default)]
    pub address: Option<String>,
    /// Multiple control endpoints for HA / weighted load-balancing. Takes
    /// precedence over `address` when present.
    #[serde(default)]
    pub instances: Vec<RtpProxyInstanceConfig>,
    /// Default per-command response budget in milliseconds, split across
    /// retransmits (per-instance `timeout_ms` overrides it). Default: 1000.
    #[serde(default = "default_rtpproxy_timeout_ms")]
    pub timeout_ms: u64,
    /// Retransmits after the first send before giving up. rtpproxy de-duplicates
    /// by cookie, so retransmitting the same command is safe and is the standard
    /// way to ride out UDP loss. Default: 2 (i.e. up to 3 sends).
    #[serde(default = "default_rtpproxy_retries")]
    pub retries: u32,
}

impl RtpProxyConfig {
    /// Normalized `(address, timeout_ms, weight)` tuples — from `instances` when
    /// present, else the single `address`. Empty when neither is configured.
    pub fn instances(&self) -> Vec<(String, u64, u32)> {
        if !self.instances.is_empty() {
            self.instances
                .iter()
                .map(|instance| {
                    (
                        instance.address.clone(),
                        instance.timeout_ms.unwrap_or(self.timeout_ms),
                        instance.weight,
                    )
                })
                .collect()
        } else if let Some(address) = &self.address {
            vec![(address.clone(), self.timeout_ms, 1)]
        } else {
            Vec::new()
        }
    }
}

/// One `rtpproxy` control endpoint in a multi-instance set.
#[derive(Debug, Deserialize, Clone)]
pub struct RtpProxyInstanceConfig {
    /// Control endpoint, e.g. ``"10.0.0.1:22222"``.
    pub address: String,
    /// Response timeout in ms; falls back to the parent `timeout_ms` when unset.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Weight for load-balancing (higher = more traffic). Default: 1.
    #[serde(default = "default_rtpengine_weight")]
    pub weight: u32,
}

fn default_rtpproxy_timeout_ms() -> u64 {
    1000
}

fn default_rtpproxy_retries() -> u32 {
    2
}

fn default_siphon_rtp_timeout_ms() -> u64 {
    2000
}

fn default_siphon_rtp_play_timeout_ms() -> u64 {
    300_000
}

/// Serde deserializer for a media profile's `address_family`, canonicalising to
/// the `IP4`/`IP6` spelling every media engine expects (it is the SDP `addrtype`
/// token — rtpengine's `"address family"` NG key, siphon-rtp's `address_family`
/// JSON field).
///
/// Case-insensitive, and `ipv4`/`ipv6` are accepted as aliases.  Any other value
/// is a config error: the engines ignore an unknown family silently, so a typo
/// would otherwise land as a relay quietly allocated in the wrong family.
fn deserialize_address_family<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de;

    let value: Option<String> = Option::deserialize(deserializer)?;
    let Some(value) = value else {
        return Ok(None);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "ip4" | "ipv4" => Ok(Some("IP4".to_string())),
        "ip6" | "ipv6" => Ok(Some("IP6".to_string())),
        other => Err(de::Error::custom(format!(
            "media profile address_family must be \"IP4\" or \"IP6\" (aliases \
             \"ipv4\"/\"ipv6\"), got {other:?}"
        ))),
    }
}

/// Serde deserializer for a media profile's `rtcp_mux` directive list.
///
/// The engines accept a fixed vocabulary (RFC 5761 mux handling); an unknown
/// token is silently ignored, which would land as a call quietly negotiating the
/// opposite mux decision from the one the operator wrote.  Same reasoning as
/// [`deserialize_address_family`].
fn deserialize_rtcp_mux<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de;

    const VALID: [&str; 6] = ["offer", "require", "demux", "accept", "reject", "remove"];

    let values: Vec<String> = Vec::deserialize(deserializer)?;
    values
        .into_iter()
        .map(|value| {
            let normalised = value.trim().to_ascii_lowercase();
            if VALID.contains(&normalised.as_str()) {
                Ok(normalised)
            } else {
                Err(de::Error::custom(format!(
                    "media profile rtcp_mux entries must be one of {}, got {value:?}",
                    VALID.join(", ")
                )))
            }
        })
        .collect()
}

/// Serde deserializer for `media.sdp_strip_attributes`.
///
/// Each entry has to be an SDP attribute name, an RFC 8866 §9 `token`.  One that
/// is not (an empty entry, `a=msid`, `msid:1`) can never match the name of an
/// `a=` line, so the relay would read as scrubbed while stripping nothing.
fn deserialize_sdp_strip_attributes<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de;

    let names: Vec<String> = Vec::deserialize(deserializer)?;
    if let Some(invalid) = names
        .iter()
        .find(|name| !crate::media::sdp::is_attribute_name(name))
    {
        return Err(de::Error::custom(format!(
            "media.sdp_strip_attributes entry {invalid:?} is not an SDP attribute name: give \
             the bare name (\"msid\", not \"a=msid\" or \"msid:1\"), one or more letters, \
             digits or !#$%&'*+-.^_`{{|}}~ (RFC 8866 §9 token)"
        )));
    }
    Ok(names)
}

/// Validate a WebSocket URI field, naming `field` in the error.
///
/// The engine dials these as a WebSocket client, so anything that is not
/// `ws://` / `wss://` can never connect.  Caught here rather than as a
/// connect failure per call.  `field` is threaded through so an operator with
/// a bad `ws_tee` is not told about `ws_uri`, a field they never set.
fn validate_ws_uri_field<E>(
    value: Option<String>,
    field: &str,
) -> std::result::Result<Option<String>, E>
where
    E: serde::de::Error,
{
    let Some(value) = value else {
        return Ok(None);
    };
    let trimmed = value.trim();
    let scheme = trimmed.split("://").next().unwrap_or_default();
    match scheme.to_ascii_lowercase().as_str() {
        "ws" | "wss" if trimmed.contains("://") => Ok(Some(trimmed.to_string())),
        _ => Err(E::custom(format!(
            "media profile {field} must be a ws:// or wss:// URI, got {value:?}"
        ))),
    }
}

/// Serde deserializer for a media profile's `ws_uri`.
fn deserialize_ws_uri<'de, D>(deserializer: D) -> std::result::Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    validate_ws_uri_field(Option::deserialize(deserializer)?, "ws_uri")
}

/// Serde deserializer for a media profile's `ws_tee`.
fn deserialize_ws_tee<'de, D>(deserializer: D) -> std::result::Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    validate_ws_uri_field(Option::deserialize(deserializer)?, "ws_tee")
}

/// Validate `ws_tee_direction` against the three values the engine accepts.
///
/// A direction the engine would reject is a config error rather than a value
/// relayed onto the wire, matching how `address_family` is validated at load.
fn deserialize_ws_tee_direction<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<WsTeeDirection>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de;

    let value: Option<String> = Option::deserialize(deserializer)?;
    let Some(value) = value else {
        return Ok(None);
    };
    WsTeeDirection::parse(&value).map(Some).ok_or_else(|| {
        de::Error::custom(format!(
            "media profile ws_tee_direction must be one of {}, got {value:?}",
            WsTeeDirection::VALUES.join(" / ")
        ))
    })
}

/// Accept `energy` / `neural` case-insensitively for `ws_vad_engine`.
///
/// A detector the engine would reject is a config error rather than a value
/// relayed onto the wire, matching `ws_tee_direction` above.  It is deliberately
/// *not* forgiving: falling back to a detector the operator was explicitly
/// avoiding is the silent downgrade the media engine already refuses.
fn deserialize_ws_vad_engine<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<WsVadEngine>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de;

    let value: Option<String> = Option::deserialize(deserializer)?;
    let Some(value) = value else {
        return Ok(None);
    };
    WsVadEngine::parse(&value).map(Some).ok_or_else(|| {
        de::Error::custom(format!(
            "media profile ws_vad_engine must be one of {}, got {value:?}",
            WsVadEngine::VALUES.join(" / ")
        ))
    })
}

/// Validate `ws_sample_rate` at config load.
///
/// The media engine *fails* an offer/answer carrying an out-of-range rate rather
/// than clamping it, so a profile with a bad value produces calls that answer
/// and never get media.  Rejecting at load means the operator learns at boot.
fn deserialize_ws_sample_rate<'de, D>(deserializer: D) -> std::result::Result<Option<u32>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_checked_sample_rate(deserializer, "ws_sample_rate")
}

/// Validate `ws_tee_sample_rate` at config load — same rule, same reason.
fn deserialize_ws_tee_sample_rate<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<u32>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_checked_sample_rate(deserializer, "ws_tee_sample_rate")
}

/// Shared body for the two L16 wire-rate fields, so the rule lives in one place.
fn deserialize_checked_sample_rate<'de, D>(
    deserializer: D,
    field: &str,
) -> std::result::Result<Option<u32>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de;

    let value: Option<u32> = Option::deserialize(deserializer)?;
    let Some(rate) = value else {
        return Ok(None);
    };
    validate_ws_sample_rate(rate)
        .map_err(|reason| de::Error::custom(format!("media profile {field} {reason}")))?;
    Ok(Some(rate))
}

/// A user-defined RTPEngine media profile with separate offer/answer NG flags.
#[derive(Debug, Deserialize, Clone)]
pub struct MediaProfileConfig {
    pub offer: NgFlagsConfig,
    pub answer: NgFlagsConfig,
}

/// rtpengine `codec` dictionary — which codecs cross, in what order, and what
/// gets transcoded. Modelled on the rtpengine NG `codec` sub-dict, which the
/// native engine implements too.
///
/// Every field is a list of RTP payload names (`PCMA`, `opus`, `AMR-WB`), and
/// an empty one is omitted from the wire entirely.
///
/// Works on both real engines from one block: rtpengine takes it as its NG
/// `codec` dictionary, and the native `siphon-rtp` engine implements the same
/// model but reads it off its flag list, so siphon flattens the block to
/// `codec-<op>-<NAME>` for it.
///
/// `ignore` and `set` have no native equivalent and are refused on that backend;
/// `rtpproxy` is a plain relay with no transcoder and refuses the block outright.
/// Refused at config load, never silently dropped — a codec policy that reads as
/// applied but is not is the failure this exists to remove.
///
/// **Honoured on `offer:`.** Both engines apply codec manipulation to the offer
/// and ignore most of it on an answer, so put it under the `offer:` half.
///
/// ```yaml
/// offer:
///   codec:
///     strip: ["SILK", "G722"]
///     offer: ["PCMA", "PCMU", "telephone-event"]
/// ```
#[derive(Debug, Deserialize, Clone, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CodecFlagsConfig {
    /// Remove these from the outgoing SDP. Accepts the wildcards `all` / `full`.
    #[serde(default)]
    pub strip: Vec<String>,
    /// The only codecs to offer, in this order (rtpengine `offer`) — like
    /// `except` but also fixes preference order.
    #[serde(default)]
    pub offer: Vec<String>,
    /// Add these to the offer even when the offerer did not list them, engaging
    /// the transcoder.
    #[serde(default)]
    pub transcode: Vec<String>,
    /// Hide these from the far side but keep accepting them from the offerer,
    /// transcoding on its behalf.
    #[serde(default)]
    pub mask: Vec<String>,
    /// Like `mask`, but engages the transcoder even with no other codec option set.
    #[serde(default)]
    pub consume: Vec<String>,
    /// Like `mask`/`consume` but leaves the codec in the offered list.
    #[serde(default)]
    pub accept: Vec<String>,
    /// Allow only these through, blocking every other offered codec.
    #[serde(default)]
    pub except: Vec<String>,
    /// Treat these as though the offer never contained them.
    #[serde(default)]
    pub ignore: Vec<String>,
    /// Options for implicitly accepted transcoding codecs — bitrate, clock rate,
    /// channels (e.g. `opus/48000/2/16000`).
    #[serde(default)]
    pub set: Vec<String>,
}

impl CodecFlagsConfig {
    /// The ops the native `siphon-rtp` engine has no equivalent for. It
    /// implements the rest of the rtpengine codec model, so only these are
    /// refused on that backend.
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

    /// True when nothing is set, so nothing is emitted on the wire.
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
}

/// NG protocol flags for one direction (offer or answer).
#[derive(Debug, Deserialize, Clone, Default)]
pub struct NgFlagsConfig {
    /// Transport protocol override (e.g. "RTP/AVP", "RTP/SAVPF").
    pub transport_protocol: Option<String>,
    /// Codec manipulation — see [`CodecFlagsConfig`]. Honoured by rtpengine and
    /// the native `siphon-rtp` engine; refused on `rtpproxy`.
    #[serde(default)]
    pub codec: CodecFlagsConfig,
    /// ICE handling: "remove", "force", or "force-relay".
    pub ice: Option<String>,
    /// DTLS mode: "passive", "active", or "off".
    pub dtls: Option<String>,
    /// SDP fields to replace: "origin".
    #[serde(default)]
    pub replace: Vec<String>,
    /// Address family the engine should allocate its relay endpoints in for this
    /// side of the call: `"IP4"` or `"IP6"`.  Unset (the default) leaves the
    /// engine following the offered SDP's own family — a single-family relay.
    ///
    /// Setting it is how an IPv4↔IPv6 interworking leg is expressed: a v6 VoLTE
    /// access side bridged to a v4 core sets `address_family: "IP4"` on the
    /// profile used toward the core.  Accepted case-insensitively, and `ipv4`/
    /// `ipv6` are taken as aliases; anything else is a hard config error rather
    /// than a value the media engine would silently ignore.
    #[serde(default, deserialize_with = "deserialize_address_family")]
    pub address_family: Option<String>,
    /// Additional flags: "trust-address", "symmetric", "asymmetric".
    #[serde(default)]
    pub flags: Vec<String>,
    /// Direction pair for NAT traversal: ["external", "internal"].
    #[serde(default)]
    pub direction: Vec<String>,
    /// Enable call recording in RTPEngine.
    #[serde(default)]
    pub record_call: bool,
    /// Directory path for RTPEngine to write recording files.
    pub record_path: Option<String>,
    /// Single-channel noise suppression on this leg's decoded ingress audio.
    /// `siphon-rtp` backend only.
    #[serde(default)]
    pub noise_suppression: bool,
    /// Acoustic/line echo cancellation on this leg's send path, referenced
    /// against the audio played toward that party.  `siphon-rtp` backend only.
    #[serde(default)]
    pub echo_cancellation: bool,
    /// How far from the reference the echo canceller searches for the returning
    /// echo, in milliseconds (16–1000, default 256).  With `echo_long_tail` set
    /// this is a **tail length** instead, checked against its own bound — both
    /// are read from `siphon-rtp-proto` rather than restated here.
    /// `siphon-rtp` backend only, and inert without `echo_cancellation`.
    ///
    /// The window has to span the whole media path twice, not an acoustic
    /// loudspeaker-to-microphone hop, so a carrier or mobile leg can sit past
    /// 200 ms on its own.  **An echo outside the window is not cancelled and
    /// nothing says so** — the estimator commits the tallest peak it can see and
    /// then adapts against a reference that is not the echo — so widen it for a
    /// leg reached through a carrier, and narrow it for a LAN softphone that
    /// should not pay for the larger estimator state.
    #[serde(default)]
    pub echo_delay_search_ms: Option<u32>,
    /// Span the echo path with the adaptive filter itself instead of estimating
    /// a bulk delay first, which makes `echo_delay_search_ms` a tail length
    /// rather than a search window (16–1000 ms in that reading).  `siphon-rtp`
    /// backend only, and inert without `echo_cancellation`.
    ///
    /// The two postures differ in **how they fail**.  Estimation is cheap and
    /// exact when it works, but commits the tallest correlation peak inside its
    /// window whatever that peak is, so an echo beyond the window leaves the
    /// filter adapting against a reference that is not the echo.  A long tail
    /// makes no alignment decision, so it has nothing to get wrong; it is
    /// slower to converge and materially more expensive per frame, so ask for
    /// the tail the path needs rather than the ceiling.
    #[serde(default)]
    pub echo_long_tail: bool,
    /// Chain the residual-echo suppressor after the linear canceller.
    /// `siphon-rtp` backend only, and inert without `echo_cancellation`.
    #[serde(default)]
    pub echo_residual_suppression: bool,
    /// Bridge this leg's audio to an external WebSocket media server: the engine
    /// dials this URI and relays the leg's RTP to it as L16.  `siphon-rtp`
    /// backend only.
    ///
    /// Supports `{call_id}`, `{from_tag}`, `{from_user}` and `{to_user}`
    /// placeholders, expanded per call.  A script can override the whole URI for
    /// one call with `rtpengine.offer(..., ws_uri=...)`.
    #[serde(default, deserialize_with = "deserialize_ws_uri")]
    pub ws_uri: Option<String>,
    /// Run a local energy-VAD on the WebSocket uplink and emit
    /// `speech_started`/`speech_stopped` on the caller's speech edges.  Inert
    /// without `ws_uri`.  `siphon-rtp` backend only.
    #[serde(default)]
    pub ws_vad: bool,
    /// Flush queued downlink playout locally when the caller starts speaking,
    /// without a server round-trip.  Implies `ws_vad`; inert without `ws_uri`.
    /// `siphon-rtp` backend only.
    #[serde(default)]
    pub ws_barge_in: bool,
    /// Mean-square energy threshold for the WebSocket uplink VAD.  Unset uses
    /// the engine default; higher is less sensitive.
    #[serde(default)]
    pub ws_vad_threshold: Option<i64>,
    /// Trailing hangover for the WebSocket uplink VAD in milliseconds — how long
    /// speech is held after energy drops before the turn endpoint fires.  Unset
    /// uses the engine default.  Only meaningful with the `energy` detector;
    /// `neural` holds speech with its own probability hysteresis.
    #[serde(default)]
    pub ws_vad_hangover_ms: Option<u32>,
    /// L16 wire sample rate in Hz for the `ws_uri` takeover bridge, independent
    /// of the leg's codec rate and applied in both directions (uplink resampled
    /// into it, downlink resampled back before re-encoding).  So an 8 kHz G.711
    /// call can speak 16 kHz to the server, and a server rendering 24 kHz audio
    /// plays at the right speed and pitch.
    ///
    /// Also the domain the noise suppressor and echo canceller run in, and those
    /// engage only at 8 or 16 kHz.  Must be a multiple of 1000 within
    /// 8000–48000 — the engine *fails* the offer rather than clamping, so a bad
    /// value is rejected here at boot.  Inert without `ws_uri`.  `siphon-rtp`
    /// backend only.
    #[serde(default, deserialize_with = "deserialize_ws_sample_rate")]
    pub ws_sample_rate: Option<u32>,
    /// Which detector the WebSocket uplink VAD runs: `energy` (default, cheap,
    /// but any loud sound reads as speech) or `neural` (answers "is this
    /// speech", so it does not turn-start on noise).  Inert without `ws_vad` /
    /// `ws_barge_in`.  `siphon-rtp` backend only.
    #[serde(default, deserialize_with = "deserialize_ws_vad_engine")]
    pub ws_vad_engine: Option<WsVadEngine>,
    /// **Leading** minimum-speech run in milliseconds: how long the uplink must
    /// read as speech *continuously* before the speech-start edge (and barge-in)
    /// fires.  Distinct from the trailing `ws_vad_hangover_ms`.
    ///
    /// Unset means no leading requirement — the edge fires on the first speech
    /// frame, which is what lets a cough or one burst of echo interrupt a
    /// prompt.  Rounded up to whole ptime frames and added directly to
    /// turn-start latency, so 60–120 ms is the useful range.  `siphon-rtp` only.
    #[serde(default)]
    pub ws_vad_min_speech_ms: Option<u32>,
    /// Watch this leg's decoded ingress audio for the short tone an answering
    /// machine plays before recording (the "voicemail beep") and deliver it to
    /// `@rtpengine.on_beep` — the media half of answering-machine detection.
    ///
    /// Set per leg, so arming it on the profile used toward the callee is what
    /// watches the party that might be a machine.  Needs decoded audio, so it
    /// promotes a same-codec plaintext call onto the userspace pipeline, and it
    /// is inert unless the codec's native rate is 8 or 16 kHz.  Fires once per
    /// leg per call — no mid-call re-arm.  `siphon-rtp` backend only.
    #[serde(default)]
    pub beep_detection: bool,
    /// How long in milliseconds the beep detector waits after a candidate tone
    /// to confirm no repeat follows — what keeps a cadenced ringback / busy tone
    /// from reading as a record tone.  **Also the detection latency**: the event
    /// arrives this long after the beep.  Unset uses the engine default
    /// (4500 ms).  Inert without `beep_detection`.  `siphon-rtp` backend only.
    #[serde(default)]
    pub beep_cadence_guard_ms: Option<u32>,
    /// Attach a **WebSocket tee** to this call: the engine dials this URI and
    /// streams a copy of the call's decoded audio to it as L16.  `siphon-rtp`
    /// backend only.
    ///
    /// Distinct from `ws_uri`, and the distinction matters: `ws_uri` is a
    /// *takeover* (the WS server becomes leg A's far side, the A↔B relay is not
    /// wired), a tee is *send-only and additive* (the call relays normally and
    /// the tee streams a copy, leaving SIPREC and recording untouched).
    ///
    /// Supports the same `{call_id}`, `{from_tag}`, `{from_user}` and
    /// `{to_user}` placeholders as `ws_uri`, expanded per call.  A script can
    /// attach or detach a tee on a live call with
    /// `rtpengine.attach_ws_tee(...)` / `rtpengine.detach_ws_tee(...)`.
    #[serde(default, deserialize_with = "deserialize_ws_tee")]
    pub ws_tee: Option<String>,
    /// Which leg(s) `ws_tee` streams: `both` (default), `caller` or `callee`.
    /// Inert without `ws_tee`.
    #[serde(default, deserialize_with = "deserialize_ws_tee_direction")]
    pub ws_tee_direction: Option<WsTeeDirection>,
    /// Wire channel count for `ws_tee`: `2` interleaves caller/callee as stereo,
    /// `1` mixes them to mono.  Only meaningful with `ws_tee_direction: both` —
    /// a single-leg tee is always mono.  Unset uses the engine default (2 for
    /// both legs, 1 for one).  Inert without `ws_tee`.
    #[serde(default)]
    pub ws_tee_channels: Option<u8>,
    /// L16 wire sample rate in Hz for `ws_tee`, independent of the legs' codec
    /// rates — the engine resamples the teed copy into it.  Send-only, unlike
    /// `ws_sample_rate`: it changes only what the tee consumer receives, never
    /// what the call itself hears.
    ///
    /// Must be a multiple of 1000 within 8000–48000 — the engine *fails* the
    /// offer rather than clamping, so a bad value is rejected here at boot.
    /// Inert without `ws_tee`.  `siphon-rtp` backend only.
    #[serde(default, deserialize_with = "deserialize_ws_tee_sample_rate")]
    pub ws_tee_sample_rate: Option<u32>,
    /// Carry the real post-NAT source IP the proxy saw the request arrive from
    /// (rtpengine's `received from`), gating the leg's media ingress to it.
    ///
    /// A tighter source gate than a NATed UA's unusable private `c=` address.
    /// Opt-in, and off by default: a profile that leaves it unset emits exactly
    /// the command it did before this knob existed.  Not honoured by `rtpproxy`.
    #[serde(default)]
    pub received_from: bool,
    /// `rtcp-mux` directives (`offer`, `require`, `demux`, `accept`, `reject`,
    /// `remove`), overriding the mux decision derived from the offered SDP
    /// (RFC 5761).  Empty mirrors the offer.  Not honoured by `rtpproxy`.
    #[serde(default, deserialize_with = "deserialize_rtcp_mux")]
    pub rtcp_mux: Vec<String>,
    /// Observe RFC 4103 real-time text on this call, delivering each recovered
    /// T.140 increment to `@rtpengine.on_text` and per-leg reception counters in
    /// the media CDR.  Promotes only the `m=text` stream, never audio, and is
    /// inert on a call that negotiated no text.  `siphon-rtp` only.
    #[serde(default)]
    pub text_events: bool,
}

/// One or more RTPEngine instances.
///
/// Accepts either a single instance or a list:
/// ```yaml
/// # Single instance:
/// media:
///   rtpengine:
///     address: "127.0.0.1:22222"
///
/// # Multiple instances (round-robin selection):
/// media:
///   rtpengine:
///     instances:
///       - address: "10.0.0.1:22222"
///         weight: 2
///       - address: "10.0.0.2:22222"
///         weight: 1
/// ```
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum RtpEngineSetConfig {
    /// A single RTPEngine instance (shorthand).
    Single(RtpEngineInstanceConfig),
    /// Multiple instances with optional weights for load-balancing.
    Set {
        instances: Vec<RtpEngineInstanceConfig>,
    },
}

impl RtpEngineSetConfig {
    /// Return all configured instances as a slice-compatible vec.
    pub fn instances(&self) -> Vec<&RtpEngineInstanceConfig> {
        match self {
            RtpEngineSetConfig::Single(instance) => vec![instance],
            RtpEngineSetConfig::Set { instances } => instances.iter().collect(),
        }
    }
}

/// Configuration for a single RTPEngine instance.
#[derive(Debug, Deserialize, Clone)]
pub struct RtpEngineInstanceConfig {
    /// NG control protocol address (e.g. "127.0.0.1:22222").
    pub address: String,
    /// Timeout in milliseconds for NG protocol responses.
    #[serde(default = "default_rtpengine_timeout_ms")]
    pub timeout_ms: u64,
    /// Weight for load-balancing (higher = more traffic). Default: 1.
    #[serde(default = "default_rtpengine_weight")]
    pub weight: u32,
}

fn default_rtpengine_timeout_ms() -> u64 {
    1000
}

fn default_rtpengine_weight() -> u32 {
    1
}
