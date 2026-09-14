//! `cdr:` call detail records.

use serde::Deserialize;

// ---------------------------------------------------------------------------
// CDR (Call Detail Records)
// ---------------------------------------------------------------------------

/// CDR configuration in `siphon.yaml`.
///
/// ```yaml
/// cdr:
///   enabled: true
///   include_register: false
///   channel_size: 10000
///   backend: file
///   file:
///     path: "/var/log/siphon/cdr.jsonl"
///     rotate_size_mb: 100
///   # -- or --
///   backend: syslog
///   syslog:
///     target: "10.0.0.5:514"
///   # -- or --
///   backend: http
///   http:
///     url: "https://collector.example.com/v1/cdr"
///     auth_header: "Bearer tok123"
/// ```
#[derive(Debug, Deserialize, Clone)]
pub struct CdrYamlConfig {
    /// Enable CDR generation. Default: false.
    #[serde(default)]
    pub enabled: bool,
    /// Automatically emit a CDR per call on lifecycle events (INVITE answer →
    /// BYE, plus failed/cancelled/timed-out calls) without the script calling
    /// `cdr.write()`. Default: false — existing manual-only deployments are
    /// unchanged; opt in to get call CDRs for free. Manual `cdr.write()` still
    /// works and is additive.
    #[serde(default)]
    pub auto_emit: bool,
    /// Include REGISTER events as CDRs. Only meaningful with `auto_emit: true`
    /// — when set, each registrar state change emits a REGISTER CDR. Default:
    /// false.
    #[serde(default)]
    pub include_register: bool,
    /// Async channel buffer size. Default: 10000.
    #[serde(default = "default_cdr_channel_size")]
    pub channel_size: usize,
    /// Single-sink form: "file", "syslog", or "http", configured by the
    /// matching block below. Mutually exclusive with [`Self::backends`];
    /// absent means "file" unless `backends` names the sinks instead.
    #[serde(default)]
    pub backend: Option<String>,
    /// File backend settings.
    pub file: Option<CdrFileConfig>,
    /// Syslog backend settings.
    pub syslog: Option<CdrSyslogConfig>,
    /// HTTP webhook backend settings.
    pub http: Option<CdrHttpConfig>,
    /// Every sink each record is written to.
    ///
    /// A deployment usually wants both a file on the node — the durable copy —
    /// and delivery to a collector, and with one sink a record the collector
    /// fails to take exists nowhere else. Each sink gets its own channel and
    /// writer task, so a slow or failing one cannot delay, block or drop
    /// another's records, and `channel_size` applies per sink.
    #[serde(default)]
    pub backends: Vec<CdrSinkConfig>,
}

/// One sink in [`CdrYamlConfig::backends`].
#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum CdrSinkConfig {
    /// JSON-lines file with optional rotation.
    File {
        #[serde(default = "default_cdr_file_path")]
        path: String,
        #[serde(default = "default_cdr_rotate_size")]
        rotate_size_mb: u64,
    },
    /// UDP syslog to a remote collector.
    Syslog { target: String },
    /// HTTP POST webhook.
    Http {
        url: String,
        #[serde(default)]
        auth_header: Option<String>,
    },
}

impl CdrSinkConfig {
    fn to_backend(&self) -> crate::cdr::CdrBackendType {
        match self {
            CdrSinkConfig::File {
                path,
                rotate_size_mb,
            } => crate::cdr::CdrBackendType::File {
                path: path.clone(),
                rotate_size_mb: *rotate_size_mb,
            },
            CdrSinkConfig::Syslog { target } => crate::cdr::CdrBackendType::Syslog {
                target: target.clone(),
            },
            CdrSinkConfig::Http { url, auth_header } => crate::cdr::CdrBackendType::Http {
                url: url.clone(),
                auth_header: auth_header.clone(),
            },
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct CdrFileConfig {
    /// Path to the JSON-lines CDR file.
    #[serde(default = "default_cdr_file_path")]
    pub path: String,
    /// Rename the file out of the way once it reaches this size, in MB, so
    /// the next record starts a fresh one. Rotated files are named
    /// `<path>.<UTC timestamp>` and are never deleted — retention belongs to
    /// logrotate or whatever ships them. `0` disables rotation entirely.
    /// Default: 100.
    #[serde(default = "default_cdr_rotate_size")]
    pub rotate_size_mb: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CdrSyslogConfig {
    /// UDP syslog target (host:port).
    pub target: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CdrHttpConfig {
    /// HTTP(S) endpoint URL for POST.
    pub url: String,
    /// Optional Authorization header value.
    pub auth_header: Option<String>,
}

impl CdrYamlConfig {
    /// Convert YAML config into runtime `CdrConfig`.
    pub fn to_cdr_config(&self) -> crate::cdr::CdrConfig {
        // The list form wins when present; `validate_cdr` has already refused a
        // config that sets both.
        if !self.backends.is_empty() {
            let backends: Vec<crate::cdr::CdrBackendType> =
                self.backends.iter().map(|sink| sink.to_backend()).collect();
            return crate::cdr::CdrConfig {
                enabled: self.enabled,
                // The first sink, so a consumer reading the single-sink field
                // still sees something true rather than a default.
                backend: backends[0].clone(),
                backends,
                auto_emit: self.auto_emit,
                include_register: self.include_register,
                channel_size: self.channel_size,
            };
        }

        let backend = match self.backend.as_deref().unwrap_or("file") {
            "syslog" => {
                let target = self
                    .syslog
                    .as_ref()
                    .map(|s| s.target.clone())
                    .unwrap_or_else(|| "127.0.0.1:514".to_string());
                crate::cdr::CdrBackendType::Syslog { target }
            }
            "http" => {
                let (url, auth_header) = self
                    .http
                    .as_ref()
                    .map(|h| (h.url.clone(), h.auth_header.clone()))
                    .unwrap_or_else(|| ("http://127.0.0.1:9080/cdr".to_string(), None));
                crate::cdr::CdrBackendType::Http { url, auth_header }
            }
            _ => {
                let (path, rotate_size_mb) = self
                    .file
                    .as_ref()
                    .map(|f| (f.path.clone(), f.rotate_size_mb))
                    .unwrap_or_else(|| (default_cdr_file_path(), default_cdr_rotate_size()));
                crate::cdr::CdrBackendType::File {
                    path,
                    rotate_size_mb,
                }
            }
        };

        crate::cdr::CdrConfig {
            enabled: self.enabled,
            backends: vec![backend.clone()],
            backend,
            auto_emit: self.auto_emit,
            include_register: self.include_register,
            channel_size: self.channel_size,
        }
    }
}

fn default_cdr_channel_size() -> usize {
    10_000
}

fn default_cdr_file_path() -> String {
    "/var/log/siphon/cdr.jsonl".to_string()
}

fn default_cdr_rotate_size() -> u64 {
    100
}
