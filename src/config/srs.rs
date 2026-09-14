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
}

/// SRS file backend — writes JSON metadata alongside audio files.
#[derive(Debug, Deserialize, Clone)]
pub struct SrsFileConfig {
    /// Base directory for metadata JSON files.
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
