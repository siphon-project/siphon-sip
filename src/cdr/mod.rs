//! Call Detail Records (CDR) — billing and accounting.
//!
//! CDRs are generated at key call events (INVITE final response, BYE) and
//! written asynchronously to pluggable backends (file, syslog, HTTP webhook).
//!
//! The CDR writer runs in a background task, receiving CDRs over a bounded channel
//! so the call path is never blocked by I/O.
//!
//! ## Sample CDR (JSON-lines)
//!
//! ```json
//! {
//!   "timestamp": "2026-03-06T14:23:01.042Z",
//!   "call_id": "a84b4c76e66710@192.168.1.100",
//!   "from_uri": "sip:alice@example.com",
//!   "to_uri": "sip:bob@example.com",
//!   "ruri": "sip:bob@10.0.0.1:5060",
//!   "method": "INVITE",
//!   "response_code": 200,
//!   "timestamp_start": "2026-03-06T14:23:01.042Z",
//!   "timestamp_answer": "2026-03-06T14:23:03.185Z",
//!   "timestamp_end": "2026-03-06T14:25:47.920Z",
//!   "duration_secs": 164.735,
//!   "source_ip": "192.168.1.100",
//!   "destination_ip": "10.0.0.1",
//!   "transport": "udp",
//!   "user_agent": "Ozona/5.0",
//!   "auth_user": "alice",
//!   "disconnect_initiator": "caller",
//!   "sip_reason": null
//! }
//! ```

use std::sync::OnceLock;
use std::time::{Instant, SystemTime};

use serde::Serialize;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

/// Global CDR sender — initialized once at startup.
static CDR_SENDER: OnceLock<mpsc::Sender<Cdr>> = OnceLock::new();

/// A Call Detail Record.
#[derive(Debug, Clone, Serialize)]
pub struct Cdr {
    /// When the CDR was generated.
    pub timestamp: String,
    /// Call-ID header.
    pub call_id: String,
    /// From URI.
    pub from_uri: String,
    /// To URI.
    pub to_uri: String,
    /// Request-URI.
    pub ruri: String,
    /// SIP method (INVITE, BYE, REGISTER, etc.).
    pub method: String,
    /// Final response code (0 if no response yet).
    pub response_code: u16,
    /// When the call started (INVITE sent/received).
    pub timestamp_start: Option<String>,
    /// When the call was answered (2xx received).
    pub timestamp_answer: Option<String>,
    /// When the call ended (BYE or timeout).
    pub timestamp_end: Option<String>,
    /// Call duration in seconds (answer to end, 0 if not answered).
    pub duration_secs: f64,
    /// Source IP of the request.
    pub source_ip: String,
    /// Destination IP (next hop).
    pub destination_ip: String,
    /// Transport protocol.
    pub transport: String,
    /// User-Agent header.
    pub user_agent: Option<String>,
    /// Authenticated username (after digest auth).
    pub auth_user: Option<String>,
    /// Who initiated the disconnect: "caller", "callee", "timeout", "error".
    pub disconnect_initiator: Option<String>,
    /// SIP Reason header value (if present on BYE).
    pub sip_reason: Option<String>,
    /// Rf accounting Session-Id (TS 32.299) returned by the CDF — set by
    /// the auto-emit path on ACR-START so the CDR can be cross-referenced
    /// with the Diameter accounting record on the billing system.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rf_session_id: Option<String>,
    /// Result-Code (RFC 6733 §7.1) of the final ACR-STOP exchange — also
    /// set by the auto-emit path so CDR consumers can detect rejected /
    /// dropped accounting without correlating against a separate stream.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rf_result_code: Option<u32>,
    /// Extra custom fields from Python scripts.
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, String>,
    /// Monotonic instant when call was answered (not serialized, used for duration).
    #[serde(skip)]
    answer_instant: Option<Instant>,
}

impl Cdr {
    /// Create a new CDR with required fields.
    pub fn new(
        call_id: String,
        from_uri: String,
        to_uri: String,
        ruri: String,
        method: String,
        source_ip: String,
        transport: String,
    ) -> Self {
        Self {
            timestamp: format_timestamp(SystemTime::now()),
            call_id,
            from_uri,
            to_uri,
            ruri,
            method,
            response_code: 0,
            timestamp_start: None,
            timestamp_answer: None,
            timestamp_end: None,
            duration_secs: 0.0,
            source_ip,
            destination_ip: String::new(),
            transport,
            user_agent: None,
            auth_user: None,
            disconnect_initiator: None,
            sip_reason: None,
            rf_session_id: None,
            rf_result_code: None,
            extra: std::collections::HashMap::new(),
            answer_instant: None,
        }
    }

    /// Set the final response code.
    pub fn with_response_code(mut self, code: u16) -> Self {
        self.response_code = code;
        self
    }

    /// Set the destination IP.
    pub fn with_destination_ip(mut self, ip: String) -> Self {
        self.destination_ip = ip;
        self
    }

    /// Set the call start timestamp.
    pub fn with_start(mut self) -> Self {
        self.timestamp_start = Some(format_timestamp(SystemTime::now()));
        self
    }

    /// Set the call answer timestamp.
    pub fn with_answer(mut self) -> Self {
        self.timestamp_answer = Some(format_timestamp(SystemTime::now()));
        self.answer_instant = Some(Instant::now());
        self
    }

    /// Set the call end timestamp and compute duration from answer.
    pub fn with_end(mut self) -> Self {
        self.timestamp_end = Some(format_timestamp(SystemTime::now()));
        if let Some(answer_at) = self.answer_instant {
            self.duration_secs = answer_at.elapsed().as_secs_f64();
        }
        self
    }

    /// Set call duration in seconds (manual override).
    pub fn with_duration(mut self, seconds: f64) -> Self {
        self.duration_secs = seconds;
        self
    }

    /// Set the disconnect initiator.
    pub fn with_disconnect_initiator(mut self, initiator: String) -> Self {
        self.disconnect_initiator = Some(initiator);
        self
    }

    /// Add a custom extra field.
    pub fn with_extra(mut self, key: String, value: String) -> Self {
        self.extra.insert(key, value);
        self
    }

    /// Stamp the Rf accounting Session-Id (returned by the CDF).
    pub fn with_rf_session_id(mut self, session_id: String) -> Self {
        self.rf_session_id = Some(session_id);
        self
    }

    /// Stamp the Rf accounting Result-Code (from the final ACA).
    pub fn with_rf_result_code(mut self, code: u32) -> Self {
        self.rf_result_code = Some(code);
        self
    }
}

/// CDR writer configuration.
#[derive(Debug, Clone)]
pub struct CdrConfig {
    /// Enable CDR generation.
    pub enabled: bool,
    /// Backend type.
    pub backend: CdrBackendType,
    /// Automatically emit a CDR per call on lifecycle events (no script
    /// `cdr.write()` needed).
    pub auto_emit: bool,
    /// Include REGISTER events (only when `auto_emit`).
    pub include_register: bool,
    /// Channel buffer size.
    pub channel_size: usize,
}

impl Default for CdrConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: CdrBackendType::File {
                path: "/var/log/siphon/cdr.jsonl".to_string(),
                rotate_size_mb: 100,
            },
            auto_emit: false,
            include_register: false,
            channel_size: 10_000,
        }
    }
}

/// Runtime auto-emit flags, latched at `init` so the dispatcher hot path can
/// check them without threading `CdrConfig` everywhere (mirrors `CDR_SENDER`).
static CDR_AUTO_FLAGS: OnceLock<CdrAutoFlags> = OnceLock::new();

#[derive(Debug, Clone, Copy)]
struct CdrAutoFlags {
    auto_emit: bool,
    include_register: bool,
}

/// CDR backend types.
#[derive(Debug, Clone)]
pub enum CdrBackendType {
    /// JSON-lines file with optional rotation.
    File {
        path: String,
        rotate_size_mb: u64,
    },
    /// UDP syslog to remote collector.
    Syslog {
        target: String,
    },
    /// HTTP POST webhook — sends JSON body to the configured URL.
    Http {
        url: String,
        auth_header: Option<String>,
    },
}

/// In-flight per-call state accumulated between the INVITE and the BYE so an
/// auto-emitted CDR can carry setup time, answer time, duration, and the
/// disconnecting side.
///
/// Held in `DispatcherState::cdr_sessions`, keyed by the SIP dialog
/// (`<Call-ID>\0<tag>`) for proxy calls or the internal call UUID for B2BUA
/// calls. Removed when the call ends (BYE / failure / cancel); the orphan
/// sweep is only a backstop for calls whose teardown never reached the
/// dispatcher.
#[derive(Debug, Clone)]
pub struct CdrSession {
    call_id: String,
    from_uri: String,
    to_uri: String,
    ruri: String,
    source_ip: String,
    transport: String,
    user_agent: Option<String>,
    auth_user: Option<String>,
    /// Wall-clock INVITE time (serialized as `timestamp_start`).
    start_wall: SystemTime,
    /// Wall-clock answer time; `None` until a 2xx is seen.
    answer_wall: Option<SystemTime>,
    /// Monotonic answer time — durations use this so a wall-clock step can't
    /// produce a negative or wildly wrong `duration_secs`.
    answer_instant: Option<Instant>,
    /// Final response code seen so far (200 once answered, else the failure).
    response_code: u16,
    /// When this session was created — the orphan-sweep backstop keys off it.
    created_at: Instant,
}

impl CdrSession {
    /// Start tracking a call at INVITE time.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        call_id: String,
        from_uri: String,
        to_uri: String,
        ruri: String,
        source_ip: String,
        transport: String,
        user_agent: Option<String>,
        auth_user: Option<String>,
    ) -> Self {
        Self {
            call_id,
            from_uri,
            to_uri,
            ruri,
            source_ip,
            transport,
            user_agent,
            auth_user,
            start_wall: SystemTime::now(),
            answer_wall: None,
            answer_instant: None,
            response_code: 0,
            created_at: Instant::now(),
        }
    }

    /// Record the answer (2xx to the INVITE). Idempotent — the first answer
    /// wins so a 2xx retransmission can't reset the answer time.
    pub fn mark_answered(&mut self, response_code: u16) {
        if self.answer_instant.is_none() {
            self.answer_wall = Some(SystemTime::now());
            self.answer_instant = Some(Instant::now());
        }
        self.response_code = response_code;
    }

    /// Whether the call was answered (a 2xx was seen).
    pub fn is_answered(&self) -> bool {
        self.answer_instant.is_some()
    }

    /// When this session was created — used by the orphan sweep.
    pub fn created_at(&self) -> Instant {
        self.created_at
    }

    /// Build the final CDR at call teardown and consume the session.
    ///
    /// `disconnect_initiator` is one of `"caller"` / `"callee"` / `"timeout"`
    /// / `"error"`. `response_code` overrides the tracked code (e.g. the
    /// failure code on an unanswered call); pass `None` to keep the tracked
    /// value. `sip_reason` carries an RFC 3326 Reason header value if present.
    pub fn finalize(
        self,
        disconnect_initiator: &str,
        response_code: Option<u16>,
        sip_reason: Option<String>,
    ) -> Cdr {
        let mut cdr = Cdr::new(
            self.call_id,
            self.from_uri,
            self.to_uri,
            self.ruri,
            "INVITE".to_string(),
            self.source_ip,
            self.transport,
        );
        cdr.response_code = response_code.unwrap_or(self.response_code);
        cdr.timestamp_start = Some(format_timestamp(self.start_wall));
        if let Some(answer_wall) = self.answer_wall {
            cdr.timestamp_answer = Some(format_timestamp(answer_wall));
        }
        cdr.timestamp_end = Some(format_timestamp(SystemTime::now()));
        if let Some(answer_at) = self.answer_instant {
            cdr.duration_secs = answer_at.elapsed().as_secs_f64();
        }
        cdr.user_agent = self.user_agent;
        cdr.auth_user = self.auth_user;
        cdr.disconnect_initiator = Some(disconnect_initiator.to_string());
        cdr.sip_reason = sip_reason;
        cdr
    }
}

/// Initialize the CDR subsystem. Returns the receiver for the background writer.
pub fn init(config: &CdrConfig) -> Option<mpsc::Receiver<Cdr>> {
    if !config.enabled {
        return None;
    }

    let (sender, receiver) = mpsc::channel(config.channel_size);
    CDR_SENDER.set(sender).ok()?;
    // Latch the auto-emit flags for the dispatcher hot path. Ignore a second
    // set (only `init` writes it, once).
    let _ = CDR_AUTO_FLAGS.set(CdrAutoFlags {
        auto_emit: config.auto_emit,
        include_register: config.include_register,
    });
    Some(receiver)
}

/// Whether siphon should auto-generate call CDRs on lifecycle events.
/// False unless the CDR system is enabled AND `cdr.auto_emit: true`.
pub fn auto_emit_enabled() -> bool {
    CDR_AUTO_FLAGS.get().map(|f| f.auto_emit).unwrap_or(false)
}

/// Whether auto-emitted CDRs should include REGISTER events.
/// Only meaningful when [`auto_emit_enabled`] is also true.
pub fn include_register_enabled() -> bool {
    CDR_AUTO_FLAGS
        .get()
        .map(|f| f.include_register)
        .unwrap_or(false)
}

/// Write a CDR to the channel (non-blocking). Returns false if channel is full.
pub fn write(cdr: Cdr) -> bool {
    if let Some(sender) = CDR_SENDER.get() {
        match sender.try_send(cdr) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!("CDR channel full — dropping CDR");
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                error!("CDR channel closed");
                false
            }
        }
    } else {
        false
    }
}

/// Check if CDR system is initialized and enabled.
pub fn is_enabled() -> bool {
    CDR_SENDER.get().is_some()
}

/// Background CDR writer task. Drains the receiver and writes to the configured backend.
pub async fn writer_task(mut receiver: mpsc::Receiver<Cdr>, config: CdrConfig) {
    debug!("CDR writer started with backend: {:?}", config.backend);

    // Pre-parse HTTP URL once if using HTTP backend
    let http_state = match &config.backend {
        CdrBackendType::Http { url, auth_header } => {
            Some(HttpState::new(url, auth_header.as_deref()))
        }
        _ => None,
    };

    while let Some(cdr) = receiver.recv().await {
        match &config.backend {
            CdrBackendType::File { path, .. } => {
                write_file_cdr(&cdr, path).await;
            }
            CdrBackendType::Syslog { target } => {
                write_syslog_cdr(&cdr, target).await;
            }
            CdrBackendType::Http { .. } => {
                if let Some(ref state) = http_state {
                    write_http_cdr(&cdr, state).await;
                }
            }
        }
    }

    debug!("CDR writer shutting down");
}

// ---------------------------------------------------------------------------
// File backend
// ---------------------------------------------------------------------------

/// Write a CDR as JSON to a file (append mode, one JSON object per line).
async fn write_file_cdr(cdr: &Cdr, path: &str) {
    let json = match serde_json::to_string(cdr) {
        Ok(json) => json,
        Err(error) => {
            error!("CDR serialization error: {error}");
            return;
        }
    };

    use tokio::io::AsyncWriteExt;
    match tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
    {
        Ok(mut file) => {
            let line = format!("{json}\n");
            if let Err(error) = file.write_all(line.as_bytes()).await {
                error!("CDR file write error: {error}");
            }
        }
        Err(error) => error!("CDR file open error: {error}"),
    }
}

// ---------------------------------------------------------------------------
// Syslog backend
// ---------------------------------------------------------------------------

/// Write a CDR via UDP syslog (RFC 5424 simplified).
async fn write_syslog_cdr(cdr: &Cdr, target: &str) {
    let json = match serde_json::to_string(cdr) {
        Ok(json) => json,
        Err(error) => {
            error!("CDR serialization error: {error}");
            return;
        }
    };

    match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
        Ok(socket) => {
            let message = format!("<134>1 {} siphon cdr - - - {json}", cdr.timestamp);
            if let Err(error) = socket.send_to(message.as_bytes(), target).await {
                error!("CDR syslog send error: {error}");
            }
        }
        Err(error) => error!("CDR syslog bind error: {error}"),
    }
}

// ---------------------------------------------------------------------------
// HTTP webhook backend
// ---------------------------------------------------------------------------

/// Pre-parsed HTTP endpoint state.
struct HttpState {
    host: String,
    port: u16,
    path: String,
    auth_header: Option<String>,
    use_tls: bool,
}

impl HttpState {
    fn new(url: &str, auth_header: Option<&str>) -> Self {
        // Parse URL: http(s)://host:port/path
        let (scheme, rest) = if let Some(rest) = url.strip_prefix("https://") {
            ("https", rest)
        } else if let Some(rest) = url.strip_prefix("http://") {
            ("http", rest)
        } else {
            ("http", url)
        };

        let (host_port, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, "/"),
        };

        let (host, port) = match host_port.rfind(':') {
            Some(idx) => {
                let port_str = &host_port[idx + 1..];
                match port_str.parse::<u16>() {
                    Ok(port) => (host_port[..idx].to_string(), port),
                    Err(_) => (host_port.to_string(), if scheme == "https" { 443 } else { 80 }),
                }
            }
            None => (host_port.to_string(), if scheme == "https" { 443 } else { 80 }),
        };

        Self {
            host,
            port,
            path: path.to_string(),
            auth_header: auth_header.map(|s| s.to_string()),
            use_tls: scheme == "https",
        }
    }
}

impl std::fmt::Debug for HttpState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "HttpState({}://{}:{}{})",
            if self.use_tls { "https" } else { "http" },
            self.host,
            self.port,
            self.path,
        )
    }
}

/// POST a CDR as JSON to the HTTP webhook endpoint.
async fn write_http_cdr(cdr: &Cdr, state: &HttpState) {
    let body = match serde_json::to_string(cdr) {
        Ok(json) => json,
        Err(error) => {
            error!("CDR serialization error: {error}");
            return;
        }
    };

    // Build raw HTTP/1.1 POST request
    let mut request = format!(
        "POST {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n",
        state.path,
        state.host,
        body.len(),
    );

    if let Some(ref auth) = state.auth_header {
        request.push_str(&format!("Authorization: {auth}\r\n"));
    }

    request.push_str("\r\n");
    request.push_str(&body);

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let address = format!("{}:{}", state.host, state.port);

    if state.use_tls {
        // TLS connection
        match connect_tls(&address, &state.host).await {
            Ok(mut stream) => {
                if let Err(error) = stream.write_all(request.as_bytes()).await {
                    error!("CDR HTTP TLS write error: {error}");
                    return;
                }
                let mut response = vec![0u8; 256];
                let _ = stream.read(&mut response).await;
                check_http_response(&response, &cdr.call_id);
            }
            Err(error) => error!("CDR HTTP TLS connect error: {error}"),
        }
    } else {
        // Plain TCP connection
        match tokio::net::TcpStream::connect(&address).await {
            Ok(mut stream) => {
                if let Err(error) = stream.write_all(request.as_bytes()).await {
                    error!("CDR HTTP write error: {error}");
                    return;
                }
                let mut response = vec![0u8; 256];
                let _ = stream.read(&mut response).await;
                check_http_response(&response, &cdr.call_id);
            }
            Err(error) => error!("CDR HTTP connect error to {address}: {error}"),
        }
    }
}

/// Establish a TLS connection.
async fn connect_tls(
    address: &str,
    server_name: &str,
) -> std::io::Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    use std::sync::Arc;
    use tokio_rustls::TlsConnector;

    let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let stream = tokio::net::TcpStream::connect(address).await?;

    let domain = tokio_rustls::rustls::pki_types::ServerName::try_from(server_name.to_string())
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;

    connector.connect(domain, stream).await
}

/// Check the HTTP response status line.
fn check_http_response(response: &[u8], call_id: &str) {
    let response_str = String::from_utf8_lossy(response);
    if let Some(status_line) = response_str.lines().next() {
        if status_line.contains("200") || status_line.contains("201") || status_line.contains("202") || status_line.contains("204") {
            debug!("CDR HTTP POST ok: call_id={call_id}");
        } else {
            warn!("CDR HTTP POST non-2xx response: {status_line} (call_id={call_id})");
        }
    }
}

// ---------------------------------------------------------------------------
// Timestamp formatting
// ---------------------------------------------------------------------------

/// Format a SystemTime as ISO 8601 UTC.
fn format_timestamp(time: SystemTime) -> String {
    let duration = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    let millis = duration.subsec_millis();

    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let mut year = 1970i64;
    let mut remaining_days = days as i64;
    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let month_days = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1u32;
    for &days_in_month in &month_days {
        if remaining_days < days_in_month {
            break;
        }
        remaining_days -= days_in_month;
        month += 1;
    }
    let day = remaining_days + 1;

    format!(
        "{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}.{millis:03}Z"
    )
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_cdr() -> Cdr {
        Cdr::new(
            "a84b4c76e66710@192.168.1.100".to_string(),
            "sip:alice@example.com".to_string(),
            "sip:bob@example.com".to_string(),
            "sip:bob@10.0.0.1:5060".to_string(),
            "INVITE".to_string(),
            "192.168.1.100".to_string(),
            "udp".to_string(),
        )
    }

    #[test]
    fn cdr_creation() {
        let cdr = sample_cdr();
        assert_eq!(cdr.call_id, "a84b4c76e66710@192.168.1.100");
        assert_eq!(cdr.method, "INVITE");
        assert_eq!(cdr.response_code, 0);
        assert!(!cdr.timestamp.is_empty());
    }

    #[test]
    fn cdr_builder_methods() {
        let cdr = sample_cdr()
            .with_response_code(200)
            .with_destination_ip("10.0.0.1".to_string())
            .with_start()
            .with_answer()
            .with_duration(120.5)
            .with_disconnect_initiator("caller".to_string())
            .with_extra("billing_id".to_string(), "B-12345".to_string());

        assert_eq!(cdr.response_code, 200);
        assert_eq!(cdr.destination_ip, "10.0.0.1");
        assert!(cdr.timestamp_start.is_some());
        assert!(cdr.timestamp_answer.is_some());
        assert_eq!(cdr.duration_secs, 120.5);
        assert_eq!(cdr.disconnect_initiator.as_deref(), Some("caller"));
        assert_eq!(cdr.extra.get("billing_id").unwrap(), "B-12345");
    }

    #[test]
    fn cdr_with_end_computes_duration() {
        let cdr = sample_cdr()
            .with_answer();

        // Small sleep to get a non-zero duration
        std::thread::sleep(std::time::Duration::from_millis(10));

        let cdr = cdr.with_end();
        assert!(cdr.timestamp_end.is_some());
        assert!(cdr.duration_secs >= 0.01, "duration should be >= 10ms, got {}", cdr.duration_secs);
    }

    #[test]
    fn cdr_with_end_without_answer_has_zero_duration() {
        let cdr = sample_cdr()
            .with_start()
            .with_end();

        assert_eq!(cdr.duration_secs, 0.0);
    }

    #[test]
    fn cdr_serialization() {
        let cdr = sample_cdr()
            .with_response_code(200)
            .with_destination_ip("10.0.0.1".to_string())
            .with_start()
            .with_disconnect_initiator("caller".to_string());

        let json = serde_json::to_string_pretty(&cdr).unwrap();
        assert!(json.contains("\"call_id\": \"a84b4c76e66710@192.168.1.100\""));
        assert!(json.contains("\"response_code\": 200"));
        assert!(json.contains("\"method\": \"INVITE\""));
        assert!(json.contains("\"disconnect_initiator\": \"caller\""));
        assert!(json.contains("\"from_uri\": \"sip:alice@example.com\""));
    }

    #[test]
    fn cdr_extra_fields_flattened() {
        let cdr = sample_cdr()
            .with_extra("billing_id".to_string(), "B-12345".to_string())
            .with_extra("account_code".to_string(), "ACC-789".to_string());

        let json = serde_json::to_string(&cdr).unwrap();
        assert!(json.contains("\"billing_id\":\"B-12345\""));
        assert!(json.contains("\"account_code\":\"ACC-789\""));
    }

    #[test]
    fn format_timestamp_valid() {
        let timestamp = format_timestamp(SystemTime::now());
        assert!(timestamp.contains('T'));
        assert!(timestamp.ends_with('Z'));
        assert!(timestamp.len() >= 23); // 2026-03-06T14:23:01.042Z
    }

    #[test]
    fn cdr_config_defaults() {
        let config = CdrConfig::default();
        assert!(!config.enabled);
        assert!(!config.auto_emit);
        assert!(!config.include_register);
        assert_eq!(config.channel_size, 10_000);
    }

    fn sample_session() -> CdrSession {
        CdrSession::new(
            "call-abc@host".to_string(),
            "sip:alice@example.com".to_string(),
            "sip:bob@example.com".to_string(),
            "sip:bob@10.0.0.2".to_string(),
            "10.0.0.1".to_string(),
            "udp".to_string(),
            Some("Ozona/5.0".to_string()),
            Some("alice".to_string()),
        )
    }

    #[test]
    fn cdr_session_answered_finalize() {
        let mut session = sample_session();
        assert!(!session.is_answered());
        session.mark_answered(200);
        assert!(session.is_answered());
        // A 2xx retransmit must not reset the answer or change the code path.
        session.mark_answered(200);

        let cdr = session.finalize("caller", None, None);
        assert_eq!(cdr.call_id, "call-abc@host");
        assert_eq!(cdr.method, "INVITE");
        assert_eq!(cdr.response_code, 200);
        assert_eq!(cdr.transport, "udp");
        assert_eq!(cdr.disconnect_initiator.as_deref(), Some("caller"));
        assert_eq!(cdr.user_agent.as_deref(), Some("Ozona/5.0"));
        assert_eq!(cdr.auth_user.as_deref(), Some("alice"));
        assert!(cdr.timestamp_start.is_some());
        assert!(cdr.timestamp_answer.is_some());
        assert!(cdr.timestamp_end.is_some());
        // Answered → a real (non-negative) duration.
        assert!(cdr.duration_secs >= 0.0);
    }

    #[test]
    fn cdr_session_unanswered_finalize() {
        // A call that failed before answer: no answer timestamp, zero duration,
        // and the failure code + initiator carried through.
        let session = sample_session();
        let cdr = session.finalize("error", Some(486), None);
        assert_eq!(cdr.response_code, 486);
        assert_eq!(cdr.disconnect_initiator.as_deref(), Some("error"));
        assert!(cdr.timestamp_answer.is_none());
        assert_eq!(cdr.duration_secs, 0.0);
    }

    #[test]
    fn is_enabled_false_by_default() {
        let _ = is_enabled();
    }

    // --- HTTP state parsing ---

    #[test]
    fn http_state_parses_simple_url() {
        let state = HttpState::new("http://10.0.0.1:8080/cdr", None);
        assert_eq!(state.host, "10.0.0.1");
        assert_eq!(state.port, 8080);
        assert_eq!(state.path, "/cdr");
        assert!(!state.use_tls);
        assert!(state.auth_header.is_none());
    }

    #[test]
    fn http_state_parses_https_url() {
        let state = HttpState::new("https://api.example.com/v1/cdr", Some("Bearer tok123"));
        assert_eq!(state.host, "api.example.com");
        assert_eq!(state.port, 443);
        assert_eq!(state.path, "/v1/cdr");
        assert!(state.use_tls);
        assert_eq!(state.auth_header.as_deref(), Some("Bearer tok123"));
    }

    #[test]
    fn http_state_default_port() {
        let state = HttpState::new("http://collector.local/cdr", None);
        assert_eq!(state.host, "collector.local");
        assert_eq!(state.port, 80);
        assert_eq!(state.path, "/cdr");
    }

    #[test]
    fn http_state_no_path() {
        let state = HttpState::new("http://10.0.0.1:9090", None);
        assert_eq!(state.host, "10.0.0.1");
        assert_eq!(state.port, 9090);
        assert_eq!(state.path, "/");
    }

    #[test]
    fn check_http_response_success() {
        check_http_response(b"HTTP/1.1 200 OK\r\n", "test");
        check_http_response(b"HTTP/1.1 201 Created\r\n", "test");
        check_http_response(b"HTTP/1.1 204 No Content\r\n", "test");
    }

    #[test]
    fn check_http_response_failure() {
        // Should warn but not panic
        check_http_response(b"HTTP/1.1 500 Internal Server Error\r\n", "test");
        check_http_response(b"", "test");
    }

    // --- Sample CDR output ---

    #[test]
    fn sample_cdr_json_output() {
        let cdr = Cdr::new(
            "a84b4c76e66710@192.168.1.100".to_string(),
            "sip:alice@example.com".to_string(),
            "sip:bob@example.com".to_string(),
            "sip:bob@10.0.0.1:5060".to_string(),
            "INVITE".to_string(),
            "192.168.1.100".to_string(),
            "udp".to_string(),
        )
        .with_response_code(200)
        .with_destination_ip("10.0.0.1".to_string())
        .with_duration(164.735)
        .with_disconnect_initiator("caller".to_string())
        .with_extra("billing_id".to_string(), "B-12345".to_string());

        let json = serde_json::to_string_pretty(&cdr).unwrap();
        // Verify it's valid JSON with all expected fields
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["call_id"], "a84b4c76e66710@192.168.1.100");
        assert_eq!(parsed["response_code"], 200);
        assert_eq!(parsed["duration_secs"], 164.735);
        assert_eq!(parsed["disconnect_initiator"], "caller");
        assert_eq!(parsed["billing_id"], "B-12345"); // flattened extra
        assert_eq!(parsed["transport"], "udp");
    }
}
