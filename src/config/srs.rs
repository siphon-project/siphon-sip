//! `srs:` session recording server.

use serde::Deserialize;

// ---------------------------------------------------------------------------
// SRS — Session Recording Server
// ---------------------------------------------------------------------------

/// Session Recording Server (SIPREC SRS) — RFC 7866.
///
/// When enabled, SIPhon accepts inbound SIPREC INVITEs from external SRCs,
/// parses the recording metadata, captures audio via RTPEngine, and stores
/// recordings + metadata.
///
/// ```yaml
/// srs:
///   enabled: true
///   recording_dir: "/var/lib/siphon/recordings"
///   max_sessions: 1000
///   backend: file
///   file:
///     base_dir: "/var/lib/siphon/recordings"
///   http:
///     url: "https://api.example.com/recordings"
///     auth_header: "Bearer tok123"
///     upload_audio: false
///   rtpengine_profile: "srs_recording"
/// ```
#[derive(Debug, Deserialize, Clone)]
pub struct SrsConfig {
    /// Enable SRS functionality. Default: false.
    #[serde(default)]
    pub enabled: bool,
    /// Directory for recording files (RTPEngine writes here). Default: "/var/lib/siphon/recordings".
    #[serde(default = "default_srs_recording_dir")]
    pub recording_dir: String,
    /// Maximum concurrent recording sessions. Default: 1000.
    #[serde(default = "default_srs_max_sessions")]
    pub max_sessions: usize,
    /// Backend type: "file" or "http". Default: "file".
    #[serde(default = "default_srs_backend")]
    pub backend: String,
    /// File backend settings.
    pub file: Option<SrsFileConfig>,
    /// HTTP webhook backend settings.
    pub http: Option<SrsHttpConfig>,
    /// RTPEngine media profile to use for recording. Default: "srs_recording".
    #[serde(default = "default_srs_rtpengine_profile")]
    pub rtpengine_profile: String,
    /// The control application (a `control.apps` name) every recording session
    /// is offered to before it is answered (`StasisStart` with `kind:
    /// "siprec"`), which accepts or rejects it. Unset, the `@srs.*` script hooks
    /// decide, as before.
    #[serde(default)]
    pub app: Option<String>,
}

/// SRS file backend — writes JSON metadata alongside audio files.
#[derive(Debug, Deserialize, Clone)]
pub struct SrsFileConfig {
    /// Retained for compatibility; it no longer selects where metadata goes.
    /// The metadata is written into the session's own recording directory
    /// under `recording_dir`, beside the audio; a different value is reported
    /// at `warn` when a recording is stored.
    #[serde(default = "default_srs_recording_dir")]
    pub base_dir: String,
}

/// SRS HTTP webhook backend — POSTs recording metadata on session end.
#[derive(Debug, Deserialize, Clone)]
pub struct SrsHttpConfig {
    /// HTTP(S) endpoint URL for POST.
    pub url: String,
    /// Optional Authorization header value.
    pub auth_header: Option<String>,
    /// Upload audio files alongside metadata. Default: false.
    #[serde(default)]
    pub upload_audio: bool,
}

fn default_srs_recording_dir() -> String {
    "/var/lib/siphon/recordings".to_string()
}
fn default_srs_max_sessions() -> usize {
    1000
}
fn default_srs_backend() -> String {
    "file".to_string()
}
fn default_srs_rtpengine_profile() -> String {
    "srs_recording".to_string()
}

impl SrsConfig {
    /// Refuse an `srs:` block siphon could not serve.
    ///
    /// `enabled` needs the siphon-rtp media backend: the SRS answers each
    /// recorded stream receive-only on a single-leg engine call of its own (RFC
    /// 7866 §8.1; §8.1.8: an SRS does not normally send RTP), which only the
    /// siphon-rtp engine has a verb for (`answer_local`). rtpengine and rtpproxy
    /// can only relay, so on them every recording would be refused, and a node
    /// that boots like that is worse than one that does not.
    ///
    /// `app` must be one of the configured control apps (`apps`): every
    /// session would otherwise be offered to an application that cannot
    /// connect, and refused at its deadline.
    pub fn validate(&self, backend: super::MediaBackendKind, apps: &[&str]) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if backend != super::MediaBackendKind::SiphonRtp {
            return Err(format!(
                "srs.enabled is true, but media.backend is {:?}, which cannot terminate a \
                 recording: the SRS answers each stream receive-only on its own single-leg \
                 engine call, which only the siphon-rtp media engine supports. Set \
                 media.backend to \"siphon-rtp\", or turn srs off.",
                backend.as_str(),
            ));
        }
        match &self.app {
            Some(app) if !apps.contains(&app.as_str()) => Err(format!(
                "srs.app is {app:?}, which is not one of the configured control.apps ({}). \
                 Every recording session would be offered to an application that cannot \
                 connect, and refused at its deadline.",
                apps.join(", "),
            )),
            _ => Ok(()),
        }
    }
}
