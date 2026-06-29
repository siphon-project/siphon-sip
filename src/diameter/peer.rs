//! Diameter peer connection (TCP or SCTP).
//!
//! Handles CER/CEA capability exchange, DWR/DWA watchdog, and
//! request/answer correlation via Hop-by-Hop identifiers.
//!
//! Supports both client mode (connect outbound, send CER) and
//! server mode (accept inbound, respond to CER with CEA).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tracing::{error, info, warn};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot, Mutex, Notify};

use crate::diameter::transport::DiameterStream;

use crate::diameter::codec::{self, *};
use crate::diameter::dictionary::{self, avp};

/// Configuration for a Diameter peer connection.
#[derive(Debug, Clone)]
pub struct PeerConfig {
    pub host: String,
    pub port: u16,
    pub origin_host: String,
    pub origin_realm: String,
    pub destination_host: Option<String>,
    pub destination_realm: String,
    /// Local IP address for Host-IP-Address AVP in CER/CEA
    pub local_ip: std::net::Ipv4Addr,
    /// Application IDs to advertise in CER/CEA
    pub application_ids: Vec<(u32, u32)>, // (vendor_id, auth_app_id)
    /// Watchdog interval in seconds
    pub watchdog_interval: u64,
    /// Reconnect delay in seconds (client mode only)
    pub reconnect_delay: u64,
    /// Product name advertised in CER/CEA
    pub product_name: String,
    /// Firmware revision advertised in CER/CEA
    pub firmware_revision: u32,
}

/// Convert a semver version string (e.g. "1.2.3") to a Diameter Firmware-Revision u32.
/// Encoding: major * 10000 + minor * 100 + patch. Falls back to 1 on parse error.
pub fn version_to_firmware_revision(version: &str) -> u32 {
    let parts: Vec<u32> = version.split('.').filter_map(|s| s.parse().ok()).collect();
    match parts.as_slice() {
        [major, minor, patch, ..] => major * 10000 + minor * 100 + patch,
        [major, minor] => major * 10000 + minor * 100,
        [major] => major * 10000,
        _ => 1,
    }
}

/// A pending request awaiting its answer.
type PendingRequest = oneshot::Sender<DiameterMessage>;

/// Default request timeout (RFC 6733 Tx ≈ 30s, but siphon's app paths use a
/// tighter 10s). The Diameter server relay path overrides this per-call via
/// [`DiameterPeer::send_request_timeout`].
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Connection lifecycle state of a peer, used by the peer pool to skip dead
/// backends without a separate registry. Backed by an `AtomicU8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    /// Connection torn down (TCP reset, watchdog failure, DPR).
    Closed,
    /// Connecting / CER in flight (reserved for future async connect).
    Connecting,
    /// CER/CEA complete, reader/writer running — ready to carry requests.
    Open,
}

impl PeerState {
    fn from_u8(value: u8) -> PeerState {
        match value {
            2 => PeerState::Open,
            1 => PeerState::Connecting,
            _ => PeerState::Closed,
        }
    }

    fn as_u8(self) -> u8 {
        match self {
            PeerState::Closed => 0,
            PeerState::Connecting => 1,
            PeerState::Open => 2,
        }
    }
}

/// Incoming request from the peer (e.g. RTR from HSS, or ALR from S6c).
#[derive(Debug)]
pub struct IncomingRequest {
    pub command_code: u32,
    pub application_id: u32,
    pub hop_by_hop: u32,
    pub end_to_end: u32,
    pub avps: serde_json::Value,
    pub raw: Vec<u8>,
}

/// Handle to a connected Diameter peer.
pub struct DiameterPeer {
    config: PeerConfig,
    /// Channel to send outgoing messages to the writer task
    write_tx: mpsc::Sender<Vec<u8>>,
    /// Pending requests keyed by Hop-by-Hop ID
    pending: Arc<Mutex<HashMap<u32, PendingRequest>>>,
    /// Monotonic HbH and E2E ID generators
    hbh_counter: Arc<AtomicU32>,
    e2e_counter: Arc<AtomicU32>,
    /// Connection lifecycle state (see [`PeerState`]).
    state: Arc<AtomicU8>,
    /// Shutdown signal
    shutdown: Arc<Notify>,
}

impl DiameterPeer {
    /// Allocate the next Hop-by-Hop identifier.
    pub fn next_hbh(&self) -> u32 {
        self.hbh_counter.fetch_add(1, Ordering::Relaxed)
    }

    /// Allocate the next End-to-End identifier.
    pub fn next_e2e(&self) -> u32 {
        self.e2e_counter.fetch_add(1, Ordering::Relaxed)
    }

    /// Generate a session ID: "{origin_host};{high32};{low32}"
    pub fn new_session_id(&self) -> String {
        let hi = self.hbh_counter.load(Ordering::Relaxed);
        let lo = self.e2e_counter.load(Ordering::Relaxed);
        format!("{};{};{}", self.config.origin_host, hi, lo)
    }

    /// Get the peer config (for building messages with origin/dest fields).
    pub fn config(&self) -> &PeerConfig {
        &self.config
    }

    /// Current connection lifecycle state.
    pub fn state(&self) -> PeerState {
        PeerState::from_u8(self.state.load(Ordering::Acquire))
    }

    /// Whether the peer is `Open` and ready to carry requests.
    pub fn is_open(&self) -> bool {
        self.state() == PeerState::Open
    }

    /// Send a request and wait for the answer (default 10s timeout).
    pub async fn send_request(&self, msg: Vec<u8>) -> Result<DiameterMessage, String> {
        self.send_request_timeout(msg, DEFAULT_REQUEST_TIMEOUT).await
    }

    /// Send a request and wait up to `timeout` for the answer. Used by the Diameter server
    /// relay path, which honours the per-call `forward_to(timeout=…)`.
    pub async fn send_request_timeout(
        &self,
        msg: Vec<u8>,
        timeout: Duration,
    ) -> Result<DiameterMessage, String> {
        // Extract HbH and command code from the message
        if msg.len() < 20 {
            return Err("message too short".into());
        }
        let hbh = u32::from_be_bytes([msg[12], msg[13], msg[14], msg[15]]);
        let command_code = u32::from_be_bytes([0, msg[5], msg[6], msg[7]]);
        let command_label = codec::command_name(command_code, true);

        if let Some(metrics) = crate::metrics::try_metrics() {
            metrics.diameter_requests_total.with_label_values(&[command_label]).inc();
        }

        let start = std::time::Instant::now();

        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(hbh, tx);

        self.write_tx.send(msg).await.map_err(|e| format!("write channel closed: {}", e))?;

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(answer)) => {
                if let Some(metrics) = crate::metrics::try_metrics() {
                    metrics.diameter_request_duration_seconds
                        .with_label_values(&[command_label])
                        .observe(start.elapsed().as_secs_f64());
                }
                Ok(answer)
            }
            Ok(Err(_)) => {
                self.pending.lock().await.remove(&hbh);
                if let Some(metrics) = crate::metrics::try_metrics() {
                    metrics.diameter_request_errors_total
                        .with_label_values(&["channel_dropped"]).inc();
                }
                Err("answer channel dropped".into())
            }
            Err(_) => {
                self.pending.lock().await.remove(&hbh);
                if let Some(metrics) = crate::metrics::try_metrics() {
                    metrics.diameter_request_errors_total
                        .with_label_values(&["timeout"]).inc();
                }
                Err(format!("request timed out ({}s)", timeout.as_secs()))
            }
        }
    }

    /// Send a response (no answer expected).
    pub async fn send_response(&self, msg: Vec<u8>) -> Result<(), String> {
        self.write_tx.send(msg).await.map_err(|e| format!("write channel closed: {}", e))
    }

    /// Shutdown the peer connection.
    pub fn shutdown(&self) {
        self.shutdown.notify_waiters();
    }

    /// Create a peer handle for unit testing (no background tasks). Starts in
    /// the `Open` state so manager/pool tests treat it as live; flip with
    /// [`DiameterPeer::set_state_for_test`].
    #[cfg(test)]
    pub fn new_for_test(config: PeerConfig, write_tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            config,
            write_tx,
            pending: Arc::new(Mutex::new(HashMap::new())),
            hbh_counter: Arc::new(AtomicU32::new(1)),
            e2e_counter: Arc::new(AtomicU32::new(1)),
            state: Arc::new(AtomicU8::new(PeerState::Open.as_u8())),
            shutdown: Arc::new(Notify::new()),
        }
    }

    /// Override the connection state in tests.
    #[cfg(test)]
    pub fn set_state_for_test(&self, state: PeerState) {
        self.state.store(state.as_u8(), Ordering::Release);
    }
}

/// Build a CER (Capabilities-Exchange-Request) message.
pub fn build_cer(config: &PeerConfig, hbh: u32, e2e: u32) -> Vec<u8> {
    let mut avps = Vec::new();

    avps.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, &config.origin_host));
    avps.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, &config.origin_realm));
    avps.extend_from_slice(&encode_avp_address_ipv4(avp::HOST_IP_ADDRESS, config.local_ip));
    avps.extend_from_slice(&encode_avp_u32(avp::VENDOR_ID, 0)); // IETF
    avps.extend_from_slice(&encode_avp_utf8(avp::PRODUCT_NAME, &config.product_name));
    avps.extend_from_slice(&encode_avp_u32(avp::FIRMWARE_REVISION, config.firmware_revision));
    avps.extend_from_slice(&encode_avp_u32(avp::SUPPORTED_VENDOR_ID, dictionary::VENDOR_3GPP));

    for &(vendor_id, auth_app_id) in &config.application_ids {
        avps.extend_from_slice(&encode_vendor_specific_app_id(vendor_id, auth_app_id));
        avps.extend_from_slice(&encode_avp_u32(avp::AUTH_APPLICATION_ID, auth_app_id));
    }

    encode_diameter_message(
        FLAG_REQUEST,
        dictionary::CMD_CAPABILITIES_EXCHANGE,
        0, // Base protocol
        hbh,
        e2e,
        &avps,
    )
}

/// Build a CEA (Capabilities-Exchange-Answer) for an incoming CER.
pub fn build_cea(config: &PeerConfig, result_code: u32, hbh: u32, e2e: u32) -> Vec<u8> {
    let mut avps = Vec::new();

    avps.extend_from_slice(&encode_avp_u32(avp::RESULT_CODE, result_code));
    avps.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, &config.origin_host));
    avps.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, &config.origin_realm));
    avps.extend_from_slice(&encode_avp_address_ipv4(avp::HOST_IP_ADDRESS, config.local_ip));
    avps.extend_from_slice(&encode_avp_u32(avp::VENDOR_ID, 0));
    avps.extend_from_slice(&encode_avp_utf8(avp::PRODUCT_NAME, &config.product_name));
    avps.extend_from_slice(&encode_avp_u32(avp::FIRMWARE_REVISION, config.firmware_revision));
    avps.extend_from_slice(&encode_avp_u32(avp::SUPPORTED_VENDOR_ID, dictionary::VENDOR_3GPP));

    for &(vendor_id, auth_app_id) in &config.application_ids {
        avps.extend_from_slice(&encode_vendor_specific_app_id(vendor_id, auth_app_id));
        avps.extend_from_slice(&encode_avp_u32(avp::AUTH_APPLICATION_ID, auth_app_id));
    }

    encode_diameter_message(
        0, // Answer: no R flag
        dictionary::CMD_CAPABILITIES_EXCHANGE,
        0,
        hbh,
        e2e,
        &avps,
    )
}

/// Build a DWA (Device-Watchdog-Answer) for an incoming DWR.
pub fn build_dwa(origin_host: &str, origin_realm: &str, hbh: u32, e2e: u32) -> Vec<u8> {
    let mut avps = Vec::new();
    avps.extend_from_slice(&encode_avp_u32(avp::RESULT_CODE, dictionary::DIAMETER_SUCCESS));
    avps.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, origin_host));
    avps.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, origin_realm));

    encode_diameter_message(0, dictionary::CMD_DEVICE_WATCHDOG, 0, hbh, e2e, &avps)
}

/// Build a DPA (Disconnect-Peer-Answer) for an incoming DPR (RFC 6733 §5.4).
pub fn build_dpa(origin_host: &str, origin_realm: &str, hbh: u32, e2e: u32) -> Vec<u8> {
    let mut avps = Vec::new();
    avps.extend_from_slice(&encode_avp_u32(avp::RESULT_CODE, dictionary::DIAMETER_SUCCESS));
    avps.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, origin_host));
    avps.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, origin_realm));

    encode_diameter_message(0, dictionary::CMD_DISCONNECT_PEER, 0, hbh, e2e, &avps)
}

/// Build a DPR (Disconnect-Peer-Request) for graceful shutdown. `cause` is the
/// Disconnect-Cause AVP value (0 = REBOOTING, 1 = BUSY, 2 = DO_NOT_WANT_TO_TALK).
pub fn build_dpr(origin_host: &str, origin_realm: &str, cause: u32, hbh: u32, e2e: u32) -> Vec<u8> {
    let mut avps = Vec::new();
    avps.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, origin_host));
    avps.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, origin_realm));
    avps.extend_from_slice(&encode_avp_u32(avp::DISCONNECT_CAUSE, cause));

    encode_diameter_message(
        FLAG_REQUEST,
        dictionary::CMD_DISCONNECT_PEER,
        0,
        hbh,
        e2e,
        &avps,
    )
}

/// Build a DWR (Device-Watchdog-Request).
pub fn build_dwr(origin_host: &str, origin_realm: &str, hbh: u32, e2e: u32) -> Vec<u8> {
    let mut avps = Vec::new();
    avps.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, origin_host));
    avps.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, origin_realm));

    encode_diameter_message(
        FLAG_REQUEST,
        dictionary::CMD_DEVICE_WATCHDOG,
        0,
        hbh,
        e2e,
        &avps,
    )
}

/// Spawn reader, writer, and watchdog tasks for an established connection.
/// Returns the peer handle. Shared between client and server modes.
pub(crate) fn spawn_connection_tasks<S>(
    config: PeerConfig,
    stream: S,
    incoming_tx: mpsc::Sender<IncomingRequest>,
) -> Arc<DiameterPeer>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (reader, writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let mut writer = writer;

    let (write_tx, mut write_rx) = mpsc::channel::<Vec<u8>>(64);

    let pending: Arc<Mutex<HashMap<u32, PendingRequest>>> = Arc::new(Mutex::new(HashMap::new()));
    let hbh_counter = Arc::new(AtomicU32::new(1));
    let e2e_counter = Arc::new(AtomicU32::new(1));
    // The connection is established (CER/CEA done) by the time tasks spawn.
    let state = Arc::new(AtomicU8::new(PeerState::Open.as_u8()));
    let shutdown = Arc::new(Notify::new());

    let peer = Arc::new(DiameterPeer {
        config: config.clone(),
        write_tx,
        pending: pending.clone(),
        hbh_counter: hbh_counter.clone(),
        e2e_counter: e2e_counter.clone(),
        state: state.clone(),
        shutdown: shutdown.clone(),
    });

    if let Some(metrics) = crate::metrics::try_metrics() {
        metrics.diameter_peers_connected.inc();
    }

    // Writer task
    let shutdown_w = shutdown.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                msg = write_rx.recv() => {
                    match msg {
                        Some(data) => {
                            if let Err(e) = writer.write_all(&data).await {
                                error!("Diameter: write error: {}", e);
                                break;
                            }
                        }
                        None => break,
                    }
                }
                _ = shutdown_w.notified() => break,
            }
        }
    });

    // Reader task
    let pending_r = pending.clone();
    let origin_host = config.origin_host.clone();
    let origin_realm = config.origin_realm.clone();
    let write_tx_r = peer.write_tx.clone();
    let shutdown_r = shutdown.clone();
    let state_r = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                result = codec::read_diameter_message(&mut reader) => {
                    match result {
                        Ok(msg_bytes) => {
                            let decoded = match codec::decode_diameter(&msg_bytes) {
                                Some(d) => d,
                                None => {
                                    warn!("Diameter: failed to decode message ({} bytes)", msg_bytes.len());
                                    continue;
                                }
                            };

                            let cmd = codec::command_name(decoded.command_code, decoded.is_request);

                            if decoded.is_request {
                                if decoded.command_code == dictionary::CMD_DEVICE_WATCHDOG {
                                    let dwa = build_dwa(&origin_host, &origin_realm, decoded.hop_by_hop, decoded.end_to_end);
                                    let _ = write_tx_r.send(dwa).await;
                                } else if decoded.command_code == dictionary::CMD_DISCONNECT_PEER {
                                    // RFC 6733 §5.4: acknowledge the DPR with a
                                    // DPA before tearing the connection down.
                                    info!("Diameter: received DPR, sending DPA and closing");
                                    let dpa = build_dpa(&origin_host, &origin_realm, decoded.hop_by_hop, decoded.end_to_end);
                                    let _ = write_tx_r.send(dpa).await;
                                    break;
                                } else {
                                    info!("Diameter: received {} from peer", cmd);
                                    let _ = incoming_tx.send(IncomingRequest {
                                        command_code: decoded.command_code,
                                        application_id: decoded.application_id,
                                        hop_by_hop: decoded.hop_by_hop,
                                        end_to_end: decoded.end_to_end,
                                        avps: decoded.avps,
                                        raw: msg_bytes,
                                    }).await;
                                }
                            } else {
                                let mut map = pending_r.lock().await;
                                if let Some(tx) = map.remove(&decoded.hop_by_hop) {
                                    let _ = tx.send(decoded);
                                } else {
                                    warn!("Diameter: unexpected answer {} (hbh={})", cmd, decoded.hop_by_hop);
                                }
                            }
                        }
                        Err(e) => {
                            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                                info!("Diameter: peer disconnected");
                            } else {
                                error!("Diameter: read error: {}", e);
                            }
                            break;
                        }
                    }
                }
                _ = shutdown_r.notified() => break,
            }
        }
        // Reader loop exited → the connection is no longer usable. Mark Closed
        // so the peer pool stops handing it out (state-as-truth).
        state_r.store(PeerState::Closed.as_u8(), Ordering::Release);
        if let Some(metrics) = crate::metrics::try_metrics() {
            metrics.diameter_peers_connected.dec();
        }
    });

    // Watchdog task — sends DWR via send_request() so DWA is correlated
    // through the pending map. If DWA doesn't arrive within the request
    // timeout, the peer is considered dead and we trigger shutdown
    // (which causes reconnect in client mode per connect_with_retry).
    let peer_w = peer.clone();
    let shutdown_dw = shutdown.clone();
    let watchdog_interval = config.watchdog_interval;
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(watchdog_interval)) => {
                    let hbh = peer_w.next_hbh();
                    let e2e = peer_w.next_e2e();
                    let dwr = build_dwr(&peer_w.config.origin_host, &peer_w.config.origin_realm, hbh, e2e);
                    match peer_w.send_request(dwr).await {
                        Ok(_) => {} // DWA received — peer is alive
                        Err(error) => {
                            warn!("Diameter: watchdog failed ({}), closing connection", error);
                            if let Some(metrics) = crate::metrics::try_metrics() {
                                metrics.diameter_watchdog_failures_total.inc();
                            }
                            peer_w.shutdown();
                            break;
                        }
                    }
                }
                _ = shutdown_dw.notified() => break,
            }
        }
    });

    peer
}

// ── Client mode ────────────────────────────────────────────────────────────

/// Connect to a Diameter peer over TCP (client mode: sends CER, expects CEA).
/// Returns a handle and a receiver for incoming requests from the peer.
pub async fn connect(
    config: PeerConfig,
) -> Result<(Arc<DiameterPeer>, mpsc::Receiver<IncomingRequest>), String> {
    connect_with_transport(config, "tcp").await
}

/// Connect to a Diameter peer over the given transport ("tcp" | "sctp").
/// Drives the same CER/CEA handshake on either transport via the unified
/// [`DiameterStream`].
pub async fn connect_with_transport(
    config: PeerConfig,
    transport: &str,
) -> Result<(Arc<DiameterPeer>, mpsc::Receiver<IncomingRequest>), String> {
    let addr = format!("{}:{}", config.host, config.port);
    info!(
        "Diameter: connecting to {} via {} ({})",
        addr, transport, config.origin_host
    );

    let mut stream = crate::diameter::transport::connect(&addr, transport)
        .await
        .map_err(|e| format!("{} connect to {} failed: {}", transport, addr, e))?;

    info!("Diameter: connected to {} via {}", addr, transport);

    // Send CER
    let cer = build_cer(&config, 1, 1);
    stream.write_all(&cer).await.map_err(|e| format!("CER write failed: {}", e))?;
    info!("Diameter: sent CER to {}", addr);

    // Read CEA
    let cea_bytes = codec::read_diameter_message(&mut stream)
        .await
        .map_err(|e| format!("CEA read failed: {}", e))?;
    let cea = codec::decode_diameter(&cea_bytes).ok_or("failed to decode CEA")?;

    if cea.command_code != dictionary::CMD_CAPABILITIES_EXCHANGE || cea.is_request {
        return Err(format!(
            "expected CEA, got {} (request={})",
            codec::command_name(cea.command_code, cea.is_request),
            cea.is_request
        ));
    }

    let result_code = cea.avps.get("Result-Code").and_then(|v| v.as_u64()).unwrap_or(0);
    if result_code != dictionary::DIAMETER_SUCCESS as u64 {
        return Err(format!("CEA result code: {} (expected 2001)", result_code));
    }

    info!(
        "Diameter: CER/CEA complete with {} (result={})",
        addr, result_code
    );

    let (incoming_tx, incoming_rx) = mpsc::channel::<IncomingRequest>(32);
    let peer = spawn_connection_tasks(config, stream, incoming_tx);

    Ok((peer, incoming_rx))
}

/// Connect with auto-reconnect. Returns the same interface as `connect` but
/// retries until a connection is established.
pub async fn connect_with_retry(
    config: PeerConfig,
    incoming_tx: mpsc::Sender<IncomingRequest>,
) -> Arc<DiameterPeer> {
    let delay = config.reconnect_delay;

    loop {
        match connect(config.clone()).await {
            Ok((peer, mut incoming_rx)) => {
                // Forward incoming requests to the shared channel
                let tx = incoming_tx.clone();
                tokio::spawn(async move {
                    while let Some(req) = incoming_rx.recv().await {
                        if tx.send(req).await.is_err() {
                            break;
                        }
                    }
                });
                return peer;
            }
            Err(e) => {
                error!("Diameter: connection failed: {}. Retrying in {}s...", e, delay);
                tokio::time::sleep(Duration::from_secs(delay)).await;
            }
        }
    }
}

// ── Server mode ────────────────────────────────────────────────────────────

/// Accept a single inbound Diameter connection (server mode: waits for CER, sends CEA).
/// Returns a handle and a receiver for incoming requests.
pub async fn accept(
    mut stream: DiameterStream,
    config: PeerConfig,
) -> Result<(Arc<DiameterPeer>, mpsc::Receiver<IncomingRequest>), String> {
    let peer_addr = stream.peer_addr().map(|a| a.to_string()).unwrap_or_default();
    info!("Diameter: accepting connection from {}", peer_addr);

    // Read CER from the connecting peer
    let cer_bytes = codec::read_diameter_message(&mut stream)
        .await
        .map_err(|e| format!("CER read failed from {}: {}", peer_addr, e))?;
    let cer = codec::decode_diameter(&cer_bytes).ok_or("failed to decode CER")?;

    if cer.command_code != dictionary::CMD_CAPABILITIES_EXCHANGE || !cer.is_request {
        return Err(format!(
            "expected CER, got {} (request={}) from {}",
            codec::command_name(cer.command_code, cer.is_request),
            cer.is_request,
            peer_addr
        ));
    }

    let peer_origin = cer.avps.get("Origin-Host").and_then(|v| v.as_str()).unwrap_or("unknown");
    info!("Diameter: received CER from {} ({})", peer_origin, peer_addr);

    // Send CEA
    let cea = build_cea(&config, dictionary::DIAMETER_SUCCESS, cer.hop_by_hop, cer.end_to_end);
    stream.write_all(&cea).await.map_err(|e| format!("CEA write failed: {}", e))?;
    info!("Diameter: sent CEA to {} (result=2001)", peer_addr);

    let (incoming_tx, incoming_rx) = mpsc::channel::<IncomingRequest>(32);
    let peer = spawn_connection_tasks(config, stream, incoming_tx);

    Ok((peer, incoming_rx))
}

/// Listen for inbound Diameter connections on the given address.
///
/// For each accepted connection, performs the CER/CEA handshake and sends
/// the peer handle and incoming request receiver to the provided channel.
pub async fn listen(
    addr: &str,
    config: PeerConfig,
    peer_tx: mpsc::Sender<(Arc<DiameterPeer>, mpsc::Receiver<IncomingRequest>)>,
) -> Result<(), String> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| format!("Diameter listen on {} failed: {}", addr, e))?;

    info!("Diameter: listening on {}", addr);

    loop {
        let (stream, peer_addr) = listener
            .accept()
            .await
            .map_err(|e| format!("accept error: {}", e))?;

        info!("Diameter: accepted TCP connection from {}", peer_addr);

        let config = config.clone();
        let tx = peer_tx.clone();
        tokio::spawn(async move {
            match accept(DiameterStream::from(stream), config).await {
                Ok(pair) => {
                    if tx.send(pair).await.is_err() {
                        warn!("Diameter: peer channel closed, dropping connection from {}", peer_addr);
                    }
                }
                Err(e) => {
                    warn!("Diameter: handshake failed with {}: {}", peer_addr, e);
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_to_firmware() {
        assert_eq!(version_to_firmware_revision("1.2.3"), 10203);
        assert_eq!(version_to_firmware_revision("0.1.0"), 100);
        assert_eq!(version_to_firmware_revision("2.0"), 20000);
        assert_eq!(version_to_firmware_revision("bad"), 1);
    }

    #[test]
    fn build_cer_valid_binary() {
        let config = PeerConfig {
            host: "hss.example.com".to_string(),
            port: 3868,
            origin_host: "siphon.example.com".to_string(),
            origin_realm: "example.com".to_string(),
            destination_host: None,
            destination_realm: "example.com".to_string(),
            local_ip: "10.0.0.1".parse().unwrap(),
            application_ids: vec![(dictionary::VENDOR_3GPP, dictionary::CX_APP_ID)],
            watchdog_interval: 30,
            reconnect_delay: 5,
            product_name: "SIPhon".to_string(),
            firmware_revision: 100,
        };

        let cer = build_cer(&config, 1, 1);
        let decoded = codec::decode_diameter(&cer).unwrap();
        assert!(decoded.is_request);
        assert_eq!(decoded.command_code, dictionary::CMD_CAPABILITIES_EXCHANGE);
        assert_eq!(
            decoded.avps.get("Origin-Host").and_then(|v| v.as_str()),
            Some("siphon.example.com")
        );
        assert_eq!(
            decoded.avps.get("Product-Name").and_then(|v| v.as_str()),
            Some("SIPhon")
        );
    }

    /// Build a throwaway `PeerConfig` for the loopback leak tests. The watchdog
    /// interval is set far longer than any test runs so no DWR is injected into
    /// the `pending` map to perturb the assertions.
    fn leak_test_config() -> PeerConfig {
        PeerConfig {
            host: "127.0.0.1".to_string(),
            port: 0,
            origin_host: "siphon.test".to_string(),
            origin_realm: "test".to_string(),
            destination_host: None,
            destination_realm: "test".to_string(),
            local_ip: "127.0.0.1".parse().unwrap(),
            application_ids: vec![(dictionary::VENDOR_3GPP, dictionary::CX_APP_ID)],
            watchdog_interval: 3600,
            reconnect_delay: 5,
            product_name: "SIPhon".to_string(),
            firmware_revision: 1,
        }
    }

    /// Stand up a real [`DiameterPeer`] over a loopback TCP connection whose far
    /// end is a mock peer that turns every request it receives into an answer
    /// (clears the R-bit) and echoes it back with the same Hop-by-Hop id. This
    /// drives the **production** reader task from [`spawn_connection_tasks`], so
    /// the test exercises the real `pending`-map removal on the answer path, not
    /// a re-implementation. Returns the peer plus the incoming-request receiver,
    /// which the caller holds so the channel stays open.
    async fn loopback_peer_with_echo() -> (Arc<DiameterPeer>, mpsc::Receiver<IncomingRequest>) {
        use tokio::io::AsyncWriteExt;
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Mock far-end peer: flip every request into an answer and echo it back.
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let (read_half, mut write_half) = tokio::io::split(stream);
                let mut reader = BufReader::new(read_half);
                while let Ok(mut bytes) = codec::read_diameter_message(&mut reader).await {
                    if bytes.len() > 4 {
                        bytes[4] &= !codec::FLAG_REQUEST; // request -> answer
                    }
                    if write_half.write_all(&bytes).await.is_err() {
                        break;
                    }
                }
            }
        });

        let client_stream = TcpStream::connect(addr).await.unwrap();
        let (incoming_tx, incoming_rx) = mpsc::channel(16);
        let peer = spawn_connection_tasks(
            leak_test_config(),
            DiameterStream::Tcp(client_stream),
            incoming_tx,
        );
        (peer, incoming_rx)
    }

    /// Leak guard for the Diameter request/answer correlation map shared by every
    /// interface — Rx/Cx/Rf/Sh all funnel through `send_request`. After each
    /// answered request the reader task MUST remove the Hop-by-Hop entry from
    /// `pending`; a regression leaks one `oneshot::Sender` per transaction for the
    /// life of the connection (threads/FDs flat, only the heap grows).
    #[tokio::test]
    async fn pending_map_drains_across_answered_requests() {
        let (peer, _incoming_rx) = loopback_peer_with_echo().await;
        let config = peer.config().clone();

        for _ in 0..300 {
            let hbh = peer.next_hbh();
            // Any valid request works — the map is keyed by Hop-by-Hop, not command.
            let request = build_cer(&config, hbh, 1);
            // The echo peer answers, so the real reader resolves and removes `hbh`.
            let _ = peer.send_request(request).await;
        }

        assert_eq!(
            peer.pending.lock().await.len(),
            0,
            "pending request map must drain to empty after answered requests — \
             a non-zero count is one leaked oneshot::Sender per Diameter transaction"
        );
    }

    /// Same invariant under concurrent in-flight requests — the carrier-grade
    /// case where many transactions race through the shared map at once.
    #[tokio::test]
    async fn pending_map_drains_under_concurrent_inflight() {
        let (peer, _incoming_rx) = loopback_peer_with_echo().await;
        let config = peer.config().clone();

        let mut handles = Vec::new();
        for _ in 0..100 {
            let peer = Arc::clone(&peer);
            let config = config.clone();
            handles.push(tokio::spawn(async move {
                let hbh = peer.next_hbh();
                let request = build_cer(&config, hbh, 1);
                let _ = peer.send_request(request).await;
            }));
        }
        for handle in handles {
            let _ = handle.await;
        }

        assert_eq!(
            peer.pending.lock().await.len(),
            0,
            "pending request map must drain under concurrent in-flight load"
        );
    }

    #[test]
    fn build_cea_valid_binary() {
        let config = PeerConfig {
            host: "".to_string(),
            port: 3868,
            origin_host: "hss.example.com".to_string(),
            origin_realm: "example.com".to_string(),
            destination_host: None,
            destination_realm: "example.com".to_string(),
            local_ip: "10.0.0.2".parse().unwrap(),
            application_ids: vec![(dictionary::VENDOR_3GPP, dictionary::CX_APP_ID)],
            watchdog_interval: 30,
            reconnect_delay: 5,
            product_name: "HSS".to_string(),
            firmware_revision: 200,
        };

        let cea = build_cea(&config, dictionary::DIAMETER_SUCCESS, 1, 1);
        let decoded = codec::decode_diameter(&cea).unwrap();
        assert!(!decoded.is_request);
        assert_eq!(
            decoded.avps.get("Result-Code").and_then(|v| v.as_u64()),
            Some(dictionary::DIAMETER_SUCCESS as u64)
        );
    }

    #[test]
    fn build_dwr_dwa_roundtrip() {
        let dwr = build_dwr("siphon.example.com", "example.com", 10, 20);
        let decoded = codec::decode_diameter(&dwr).unwrap();
        assert!(decoded.is_request);
        assert_eq!(decoded.command_code, dictionary::CMD_DEVICE_WATCHDOG);

        let dwa = build_dwa("hss.example.com", "example.com", 10, 20);
        let decoded = codec::decode_diameter(&dwa).unwrap();
        assert!(!decoded.is_request);
        assert_eq!(
            decoded.avps.get("Result-Code").and_then(|v| v.as_u64()),
            Some(dictionary::DIAMETER_SUCCESS as u64)
        );
    }

    #[test]
    fn build_dpr_dpa_valid_binary() {
        let dpr = build_dpr("diam.example.org", "example.org", 0, 5, 6);
        // Verify via the lossless tree (Disconnect-Cause AVP 273 is read by
        // code, not by dictionary name).
        let tree = codec::DiameterMsg::from_wire(&dpr).unwrap();
        assert!(tree.is_request());
        assert_eq!(tree.command_code, dictionary::CMD_DISCONNECT_PEER);
        assert_eq!(
            tree.find(dictionary::avp::DISCONNECT_CAUSE, 0)
                .and_then(|a| a.as_u32()),
            Some(0)
        );

        let dpa = build_dpa("diam.example.org", "example.org", 5, 6);
        let decoded = codec::decode_diameter(&dpa).unwrap();
        assert!(!decoded.is_request);
        assert_eq!(decoded.command_code, dictionary::CMD_DISCONNECT_PEER);
        assert_eq!(
            decoded.avps.get("Result-Code").and_then(|v| v.as_u64()),
            Some(dictionary::DIAMETER_SUCCESS as u64)
        );
    }

    fn test_config() -> PeerConfig {
        PeerConfig {
            host: "peer.example.org".to_string(),
            port: 3868,
            origin_host: "diam.example.org".to_string(),
            origin_realm: "example.org".to_string(),
            destination_host: None,
            destination_realm: "example.org".to_string(),
            local_ip: "127.0.0.1".parse().unwrap(),
            application_ids: vec![],
            watchdog_interval: 30,
            reconnect_delay: 5,
            product_name: "SIPhon".to_string(),
            firmware_revision: 100,
        }
    }

    #[tokio::test]
    async fn send_request_timeout_returns_err_and_clears_pending() {
        // A test peer with no reader task: no answer ever arrives, so a short
        // timeout must elapse, return Err, and remove the pending entry.
        let (write_tx, mut write_rx) = mpsc::channel::<Vec<u8>>(4);
        let peer = DiameterPeer::new_for_test(test_config(), write_tx);

        // Drain the writer so send() doesn't block on a full channel.
        tokio::spawn(async move { while write_rx.recv().await.is_some() {} });

        let dwr = build_dwr("diam.example.org", "example.org", 42, 42);
        let start = std::time::Instant::now();
        let result = peer
            .send_request_timeout(dwr, Duration::from_millis(50))
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("timed out"));
        assert!(start.elapsed() < Duration::from_secs(1));
        // Pending entry for hbh=42 was removed on timeout.
        assert!(peer.pending.lock().await.is_empty());
    }

    #[cfg(feature = "sctp")]
    #[tokio::test]
    async fn sctp_client_server_cer_cea_roundtrip() {
        // Loopback SCTP CER/CEA over the real transport. Skips gracefully when
        // SCTP is unavailable in the test environment.
        let listener =
            match crate::diameter::transport::DiameterListener::bind_sctp("127.0.0.1:0".parse().unwrap()) {
                Ok(listener) => listener,
                Err(_) => return,
            };
        let addr = listener.local_addr().unwrap();

        let server_config = test_config();
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let _ = accept(stream, server_config).await;
            }
        });

        let mut client_config = test_config();
        client_config.host = addr.ip().to_string();
        client_config.port = addr.port();
        let result = connect_with_transport(client_config, "sctp").await;
        assert!(
            result.is_ok(),
            "SCTP CER/CEA should complete: {:?}",
            result.err()
        );
        let (peer, _incoming_rx) = result.unwrap();
        assert_eq!(peer.state(), PeerState::Open);
    }

    #[tokio::test]
    async fn outbound_connection_receives_inbound_request() {
        // The HSS-dials-Diameter server case: siphon initiates the connection (client CER),
        // but a request (AIR) arrives over it and must surface on incoming_rx
        // for @diameter.on_request dispatch — not be dropped.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // "Diameter server" side: accept, complete CER/CEA, then send an AIR request.
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            if let Ok((server_peer, _rx)) =
                accept(DiameterStream::Tcp(stream), test_config()).await
            {
                let air = encode_diameter_message(
                    FLAG_REQUEST | FLAG_PROXIABLE,
                    dictionary::CMD_AUTHENTICATION_INFORMATION,
                    dictionary::S6A_APP_ID,
                    0x4242,
                    0x4343,
                    &encode_avp_utf8(avp::SESSION_ID, "diam;1;1"),
                );
                // Fire the request without awaiting the answer.
                tokio::spawn(async move {
                    let _ = server_peer.send_request(air).await;
                });
            }
        });

        let mut client_config = test_config();
        client_config.host = addr.ip().to_string();
        client_config.port = addr.port();
        let (peer, mut incoming_rx) = connect_with_transport(client_config, "tcp")
            .await
            .expect("client connect should complete CER/CEA");
        assert_eq!(peer.state(), PeerState::Open);

        let request = tokio::time::timeout(Duration::from_secs(2), incoming_rx.recv())
            .await
            .expect("inbound request must arrive (not be dropped)")
            .expect("channel open");
        assert_eq!(request.command_code, dictionary::CMD_AUTHENTICATION_INFORMATION);
        assert_eq!(request.hop_by_hop, 0x4242);
    }

    #[tokio::test]
    async fn inbound_dpr_triggers_dpa_and_closed_state() {
        // Drive a full connection over an in-memory duplex stream: feed a DPR
        // and assert (a) the peer answers DPA, (b) it transitions to Closed.
        let (client_side, mut server_side) = tokio::io::duplex(8192);
        let (incoming_tx, _incoming_rx) = mpsc::channel(8);
        let peer = spawn_connection_tasks(test_config(), client_side, incoming_tx);
        assert_eq!(peer.state(), PeerState::Open);

        // Send a DPR into the connection (as the remote peer would).
        let dpr = build_dpr("remote.example.org", "example.org", 0, 77, 88);
        server_side.write_all(&dpr).await.unwrap();

        // Expect a DPA back.
        let dpa_bytes = codec::read_diameter_message(&mut server_side)
            .await
            .unwrap();
        let dpa = codec::decode_diameter(&dpa_bytes).unwrap();
        assert!(!dpa.is_request);
        assert_eq!(dpa.command_code, dictionary::CMD_DISCONNECT_PEER);
        assert_eq!(dpa.hop_by_hop, 77);

        // The peer should mark itself Closed after the DPR.
        for _ in 0..50 {
            if peer.state() == PeerState::Closed {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(peer.state(), PeerState::Closed);
    }
}
