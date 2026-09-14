//! `tracing:` (HEP), `metrics:` and `log:`.

use super::CorsConfig;
use serde::Deserialize;

// ---------------------------------------------------------------------------
// SIP tracing via HEP (Homer / captAgent)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
pub struct TracingConfig {
    pub hep: Option<HepConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HepConfig {
    /// Endpoint of the captAgent/Homer collector (e.g. "127.0.0.1:9060").
    pub endpoint: String,
    #[serde(default = "default_hep_version")]
    pub version: u8,
    #[serde(default = "default_hep_transport")]
    pub transport: HepTransport,
    /// Label shown in Homer for this agent — use different values per node type.
    pub agent_id: Option<String>,
    /// CA certificate file for TLS transport (PEM format).
    /// When omitted with TLS transport, the system root CAs are used.
    pub ca_cert: Option<String>,
    /// Server name for TLS SNI. Defaults to the hostname from `endpoint`.
    pub tls_server_name: Option<String>,
    /// Minimum interval (in seconds) between repeated error log messages.
    /// Prevents log flooding when the collector is unreachable. Default: 30.
    #[serde(default = "default_hep_error_log_interval")]
    pub error_log_interval: u64,
}

fn default_hep_error_log_interval() -> u64 {
    30
}

fn default_hep_version() -> u8 {
    3
}

fn default_hep_transport() -> HepTransport {
    HepTransport::Udp
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum HepTransport {
    Udp,
    Tcp,
    Tls,
}

// ---------------------------------------------------------------------------
// Prometheus metrics
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
pub struct MetricsConfig {
    pub prometheus: Option<PrometheusConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PrometheusConfig {
    /// Address to expose the /metrics endpoint on (e.g. "0.0.0.0:8888").
    pub listen: String,
    #[serde(default = "default_metrics_path")]
    pub path: String,
    /// Optional CORS policy so a browser dashboard served from another origin
    /// can `fetch()` this endpoint. Unset = no CORS headers (default).
    #[serde(default)]
    pub cors: Option<CorsConfig>,
}

fn default_metrics_path() -> String {
    "/metrics".to_owned()
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct LogConfig {
    pub level: LogLevel,
    pub format: LogFormat,
    /// Optional path to a log file (e.g. `/var/log/siphon/siphon.log`).
    /// When set, logs are written to both stderr and the file. A missing
    /// parent directory is created; the packaged logrotate config rotates
    /// anything named `*.log` under `/var/log/siphon`.
    pub file: Option<String>,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            format: LogFormat::Pretty,
            file: None,
        }
    }
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Pretty,
    Json,
}
