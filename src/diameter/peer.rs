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

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot, Mutex, Notify};
use tracing::{error, info, warn};

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

/// Bound on a single write to a peer.
///
/// A peer that stops reading — alive, still ACKing, receive window closed —
/// makes `write_all` block for as long as it likes, and `SO_KEEPALIVE` cannot
/// see it (probes are suppressed with data unacked or the socket in persist).
/// Unbounded, the writer task never returns to its `recv`, the bounded channel
/// in front of it fills, and every producer parks — including the script
/// handlers that reach this through the Cx/Sh/Rx/Rf/S6a methods, each one
/// holding a script-executor worker until the watchdog aborts the process.
///
/// Breaking out on expiry drops the receiver, so the channel closes and
/// subsequent sends fail fast instead of queueing behind a corpse.
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Bound on handing a message to the writer task.
///
/// Short, because the callers are request paths that already own an answer
/// timeout and, on the scripting API, a script-executor worker. Long enough
/// that a scheduler hiccup on a healthy peer is absorbed rather than reported
/// as a failure.
const ENQUEUE_TIMEOUT: Duration = Duration::from_millis(250);

/// Bound on each leg of the CER/CEA capabilities exchange.
///
/// The handshake runs before the reader and writer tasks exist, so neither
/// [`WRITE_TIMEOUT`] nor the request timeout covers it. A peer that completes
/// the transport handshake and then never reads or never answers would
/// otherwise pin the connect attempt — and the reconnect loop driving it —
/// indefinitely.
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

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
/// Wall-clock-seeded high bits for Session-Id uniqueness across restarts.
fn session_high_seed() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

/// Bounded metric label for the Result-Code an answer carries.
///
/// Prefers the base `Result-Code`, falling back to the 3GPP
/// `Experimental-Result-Code` — which Cx/Sh/Rx answers carry *instead of*, not
/// alongside, the base code (TS 29.229 §6.2), nested inside the
/// `Experimental-Result` grouped AVP. An answer with neither is labelled `none`
/// rather than being dropped: a peer answering without a Result-Code at all is
/// itself worth seeing.
fn answer_result_label(answer: &DiameterMessage) -> &'static str {
    if let Some(code) = answer.avps.get("Result-Code").and_then(|v| v.as_u64()) {
        return dictionary::result_code_label(code as u32, false);
    }
    let experimental = answer
        .avps
        .get("Experimental-Result")
        .and_then(|group| group.get("Experimental-Result-Code"))
        // Tolerate a decoder that hoists the code to the top level.
        .or_else(|| answer.avps.get("Experimental-Result-Code"))
        .and_then(|v| v.as_u64());
    match experimental {
        Some(code) => dictionary::result_code_label(code as u32, true),
        None => "none",
    }
}

pub struct DiameterPeer {
    config: PeerConfig,
    /// Channel to send outgoing messages to the writer task
    write_tx: mpsc::Sender<Vec<u8>>,
    /// Pending requests keyed by Hop-by-Hop ID
    pending: Arc<Mutex<HashMap<u32, PendingRequest>>>,
    /// Monotonic HbH and E2E ID generators
    hbh_counter: Arc<AtomicU32>,
    e2e_counter: Arc<AtomicU32>,
    /// Dedicated monotonic Session-Id sequence (RFC 6733 §8.8 low bits). Atomic
    /// so two concurrent `new_session_id()` calls never mint the same id — a
    /// collision would collapse two credit-control sessions into one at the OCS.
    session_counter: Arc<AtomicU32>,
    /// Session-Id high bits, seeded once from wall-clock at construction so ids
    /// stay unique across process restarts.
    session_high: u32,
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

    /// Generate a globally-unique Session-Id "{origin_host};{high32};{low32}"
    /// (RFC 6733 §8.8). The low bits come from a dedicated atomic counter so
    /// concurrent callers cannot collide; the high bits are wall-clock-seeded
    /// so ids don't repeat across restarts.
    pub fn new_session_id(&self) -> String {
        let low = self.session_counter.fetch_add(1, Ordering::Relaxed);
        format!("{};{};{}", self.config.origin_host, self.session_high, low)
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
        self.send_request_timeout(msg, DEFAULT_REQUEST_TIMEOUT)
            .await
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
            metrics
                .diameter_requests_total
                .with_label_values(&[command_label])
                .inc();
        }

        let start = std::time::Instant::now();

        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(hbh, tx);

        // Bounded. The `timeout` below covers waiting for the *answer*; without
        // a bound here the wait for a slot in front of a stalled writer is
        // unbounded, which is where a handler thread is actually lost. The
        // pending entry was inserted above, so every early return has to take
        // it back out or a shed request leaks one entry per attempt.
        if let Err(error) = self.write_tx.send_timeout(msg, ENQUEUE_TIMEOUT).await {
            self.pending.lock().await.remove(&hbh);
            if let Some(metrics) = crate::metrics::try_metrics() {
                metrics
                    .diameter_request_errors_total
                    .with_label_values(&["write_blocked"])
                    .inc();
            }
            return Err(match error {
                mpsc::error::SendTimeoutError::Closed(_) => "write channel closed".to_string(),
                mpsc::error::SendTimeoutError::Timeout(_) => {
                    warn!(
                        peer = %self.config.host,
                        timeout = ?ENQUEUE_TIMEOUT,
                        "Diameter: peer is not draining its socket — outbound queue \
                         still full after the enqueue window; failing the request \
                         rather than stranding the caller"
                    );
                    "peer outbound queue full".to_string()
                }
            });
        }

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(answer)) => {
                if let Some(metrics) = crate::metrics::try_metrics() {
                    metrics
                        .diameter_request_duration_seconds
                        .with_label_values(&[command_label])
                        .observe(start.elapsed().as_secs_f64());
                    // An answer that arrives is a successful round trip as far
                    // as the error counter above is concerned, whatever it says.
                    // Counting the Result-Code here is what separates "the peer
                    // is unreachable" from "the peer is answering, and saying
                    // no" — an OCS refusing every CCR used to read as zero
                    // errors. One lookup per transaction, not per message.
                    //
                    // Labelled with the *answer* name (CCA, not CCR): the
                    // command code is shared and only the R-bit differs, and a
                    // counter of answers reading `CCR` would be a lie about
                    // which half of the exchange it counted.
                    metrics
                        .diameter_answers_total
                        .with_label_values(&[
                            codec::command_name(command_code, false),
                            answer_result_label(&answer),
                        ])
                        .inc();
                }
                Ok(answer)
            }
            Ok(Err(_)) => {
                self.pending.lock().await.remove(&hbh);
                if let Some(metrics) = crate::metrics::try_metrics() {
                    metrics
                        .diameter_request_errors_total
                        .with_label_values(&["channel_dropped"])
                        .inc();
                }
                Err("answer channel dropped".into())
            }
            Err(_) => {
                self.pending.lock().await.remove(&hbh);
                if let Some(metrics) = crate::metrics::try_metrics() {
                    metrics
                        .diameter_request_errors_total
                        .with_label_values(&["timeout"])
                        .inc();
                }
                Err(format!("request timed out ({}s)", timeout.as_secs()))
            }
        }
    }

    /// Send a response (no answer expected).
    pub async fn send_response(&self, msg: Vec<u8>) -> Result<(), String> {
        // Bounded for the same reason as the request path: answering an inbound
        // request must never be what parks the task that is answering it.
        self.write_tx
            .send_timeout(msg, ENQUEUE_TIMEOUT)
            .await
            .map_err(|error| match error {
                mpsc::error::SendTimeoutError::Closed(_) => "write channel closed".to_string(),
                mpsc::error::SendTimeoutError::Timeout(_) => "peer outbound queue full".to_string(),
            })
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
            session_counter: Arc::new(AtomicU32::new(1)),
            session_high: session_high_seed(),
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
/// Advertise supported applications in a CER/CEA (RFC 6733 §5.3).
///
/// Each entry is `(vendor_id, app_id)`. Correctness rules the prior code
/// violated:
///   * A `Vendor-Specific-Application-Id` is emitted only for a **non-zero**
///     Vendor-Id (§6.11) — wrapping a base app (Rf id 3, Ro id 4) in a
///     `VSAI{Vendor-Id: 0}` is malformed.
///   * An **accounting** application (Rf, id 3) is advertised via
///     `Acct-Application-Id (259)`, not `Auth-Application-Id (258)` — otherwise
///     a strict peer answers `DIAMETER_NO_COMMON_APPLICATION` (§2.4 / §6.9).
fn encode_application_ids(avps: &mut Vec<u8>, application_ids: &[(u32, u32)]) {
    for &(vendor_id, app_id) in application_ids {
        if vendor_id != 0 {
            avps.extend_from_slice(&encode_vendor_specific_app_id(vendor_id, app_id));
        }
        if dictionary::is_accounting_application(app_id) {
            avps.extend_from_slice(&encode_avp_u32(avp::ACCT_APPLICATION_ID, app_id));
        } else {
            avps.extend_from_slice(&encode_avp_u32(avp::AUTH_APPLICATION_ID, app_id));
        }
    }
}

pub fn build_cer(config: &PeerConfig, hbh: u32, e2e: u32) -> Vec<u8> {
    let mut avps = Vec::new();

    avps.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, &config.origin_host));
    avps.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, &config.origin_realm));
    avps.extend_from_slice(&encode_avp_address_ipv4(
        avp::HOST_IP_ADDRESS,
        config.local_ip,
    ));
    avps.extend_from_slice(&encode_avp_u32(avp::VENDOR_ID, 0)); // IETF
    avps.extend_from_slice(&encode_avp_utf8(avp::PRODUCT_NAME, &config.product_name));
    avps.extend_from_slice(&encode_avp_u32(
        avp::FIRMWARE_REVISION,
        config.firmware_revision,
    ));
    avps.extend_from_slice(&encode_avp_u32(
        avp::SUPPORTED_VENDOR_ID,
        dictionary::VENDOR_3GPP,
    ));

    encode_application_ids(&mut avps, &config.application_ids);

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
    avps.extend_from_slice(&encode_avp_address_ipv4(
        avp::HOST_IP_ADDRESS,
        config.local_ip,
    ));
    avps.extend_from_slice(&encode_avp_u32(avp::VENDOR_ID, 0));
    avps.extend_from_slice(&encode_avp_utf8(avp::PRODUCT_NAME, &config.product_name));
    avps.extend_from_slice(&encode_avp_u32(
        avp::FIRMWARE_REVISION,
        config.firmware_revision,
    ));
    avps.extend_from_slice(&encode_avp_u32(
        avp::SUPPORTED_VENDOR_ID,
        dictionary::VENDOR_3GPP,
    ));

    encode_application_ids(&mut avps, &config.application_ids);

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
    avps.extend_from_slice(&encode_avp_u32(
        avp::RESULT_CODE,
        dictionary::DIAMETER_SUCCESS,
    ));
    avps.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, origin_host));
    avps.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, origin_realm));

    encode_diameter_message(0, dictionary::CMD_DEVICE_WATCHDOG, 0, hbh, e2e, &avps)
}

/// Build a DPA (Disconnect-Peer-Answer) for an incoming DPR (RFC 6733 §5.4).
pub fn build_dpa(origin_host: &str, origin_realm: &str, hbh: u32, e2e: u32) -> Vec<u8> {
    let mut avps = Vec::new();
    avps.extend_from_slice(&encode_avp_u32(
        avp::RESULT_CODE,
        dictionary::DIAMETER_SUCCESS,
    ));
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
        session_counter: Arc::new(AtomicU32::new(1)),
        session_high: session_high_seed(),
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
                            match tokio::time::timeout(
                                WRITE_TIMEOUT,
                                writer.write_all(&data),
                            ).await {
                                Ok(Ok(())) => {}
                                Ok(Err(e)) => {
                                    error!("Diameter: write error: {}", e);
                                    break;
                                }
                                Err(_) => {
                                    error!(
                                        timeout = ?WRITE_TIMEOUT,
                                        "Diameter: write stalled — peer is not draining \
                                         its socket; dropping the connection so callers \
                                         fail fast instead of queueing behind it"
                                    );
                                    break;
                                }
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
                                // This task is the only thing that correlates
                                // answers to their pending requests, so it must
                                // never park: an awaiting send here against a
                                // stalled writer or a backed-up dispatcher stops
                                // every in-flight request on this peer, and the
                                // peer then looks dead to all of them at once.
                                // A dropped watchdog answer is recoverable (the
                                // peer re-DWRs, or its own watchdog closes us);
                                // a stalled reader is not.
                                if decoded.command_code == dictionary::CMD_DEVICE_WATCHDOG {
                                    let dwa = build_dwa(&origin_host, &origin_realm, decoded.hop_by_hop, decoded.end_to_end);
                                    if write_tx_r.try_send(dwa).is_err() {
                                        warn!("Diameter: dropped DWA — peer outbound queue full or closed");
                                    }
                                } else if decoded.command_code == dictionary::CMD_DISCONNECT_PEER {
                                    // RFC 6733 §5.4: acknowledge the DPR with a
                                    // DPA before tearing the connection down.
                                    info!("Diameter: received DPR, sending DPA and closing");
                                    let dpa = build_dpa(&origin_host, &origin_realm, decoded.hop_by_hop, decoded.end_to_end);
                                    if write_tx_r.try_send(dpa).is_err() {
                                        warn!("Diameter: dropped DPA — peer outbound queue full or closed");
                                    }
                                    break;
                                } else {
                                    info!("Diameter: received {} from peer", cmd);
                                    if incoming_tx.try_send(IncomingRequest {
                                        command_code: decoded.command_code,
                                        application_id: decoded.application_id,
                                        hop_by_hop: decoded.hop_by_hop,
                                        end_to_end: decoded.end_to_end,
                                        avps: decoded.avps,
                                        raw: msg_bytes,
                                    }).is_err() {
                                        warn!(
                                            command = cmd,
                                            "Diameter: dropped inbound request — dispatch queue \
                                             full or closed; the peer will time out and retry \
                                             rather than this connection stalling"
                                        );
                                    }
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

    // Send CER.  Bounded: a peer that completes the TCP handshake and then
    // never reads would otherwise hold this connect attempt — and whatever
    // drives it, including the reconnect loop — open indefinitely.
    let cer = build_cer(&config, 1, 1);
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.write_all(&cer)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(format!("CER write failed: {}", e)),
        Err(_) => return Err(format!("CER write timed out after {HANDSHAKE_TIMEOUT:?}")),
    }
    info!("Diameter: sent CER to {}", addr);

    // Read CEA.  Bounded for the mirror reason: a peer that accepts and then
    // says nothing must not pin the handshake forever.
    let cea_bytes =
        match tokio::time::timeout(HANDSHAKE_TIMEOUT, codec::read_diameter_message(&mut stream))
            .await
        {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(e)) => return Err(format!("CEA read failed: {}", e)),
            Err(_) => return Err(format!("CEA read timed out after {HANDSHAKE_TIMEOUT:?}")),
        };
    let cea = codec::decode_diameter(&cea_bytes).ok_or("failed to decode CEA")?;

    if cea.command_code != dictionary::CMD_CAPABILITIES_EXCHANGE || cea.is_request {
        return Err(format!(
            "expected CEA, got {} (request={})",
            codec::command_name(cea.command_code, cea.is_request),
            cea.is_request
        ));
    }

    let result_code = cea
        .avps
        .get("Result-Code")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
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
                error!(
                    "Diameter: connection failed: {}. Retrying in {}s...",
                    e, delay
                );
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
    let peer_addr = stream
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_default();
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

    let peer_origin = cer
        .avps
        .get("Origin-Host")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    info!(
        "Diameter: received CER from {} ({})",
        peer_origin, peer_addr
    );

    // Send CEA
    let cea = build_cea(
        &config,
        dictionary::DIAMETER_SUCCESS,
        cer.hop_by_hop,
        cer.end_to_end,
    );
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.write_all(&cea)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(format!("CEA write failed: {}", e)),
        Err(_) => return Err(format!("CEA write timed out after {HANDSHAKE_TIMEOUT:?}")),
    }
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
                        warn!(
                            "Diameter: peer channel closed, dropping connection from {}",
                            peer_addr
                        );
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

    #[test]
    fn cer_advertises_acct_app_for_rf_and_skips_vendor0_vsai() {
        // A peer speaking Rf (acct app 3, vendor 0), Ro (auth app 4, vendor 0)
        // and Cx (auth, vendor 10415). RFC 6733 §2.4/§6.9/§6.11 require: the
        // accounting app advertised via Acct-Application-Id (259), the base apps
        // advertised via the bare app-id AVP (never a VSAI with Vendor-Id 0),
        // and no Auth-Application-Id carrying the accounting app id.
        let config = PeerConfig {
            host: "cdf.example.com".to_string(),
            port: 3868,
            origin_host: "siphon.example.com".to_string(),
            origin_realm: "example.com".to_string(),
            destination_host: None,
            destination_realm: "example.com".to_string(),
            local_ip: "10.0.0.1".parse().unwrap(),
            application_ids: vec![
                (0, dictionary::RF_APP_ID),
                (0, dictionary::RO_APP_ID),
                (dictionary::VENDOR_3GPP, dictionary::CX_APP_ID),
            ],
            watchdog_interval: 3600,
            reconnect_delay: 5,
            product_name: "SIPhon".to_string(),
            firmware_revision: 1,
        };

        let cer = build_cer(&config, 1, 1);
        let tree = codec::DiameterMsg::from_wire(&cer).expect("decode CER");

        let acct: Vec<u32> = tree
            .find_all(avp::ACCT_APPLICATION_ID, 0)
            .filter_map(|a| a.as_u32())
            .collect();
        assert!(
            acct.contains(&dictionary::RF_APP_ID),
            "Rf must be advertised as Acct-Application-Id, got {acct:?}"
        );

        let auth: Vec<u32> = tree
            .find_all(avp::AUTH_APPLICATION_ID, 0)
            .filter_map(|a| a.as_u32())
            .collect();
        assert!(
            auth.contains(&dictionary::RO_APP_ID),
            "Ro must be advertised as Auth-Application-Id, got {auth:?}"
        );
        assert!(
            !auth.contains(&dictionary::RF_APP_ID),
            "the accounting app id must NOT appear as an Auth-Application-Id"
        );

        // Only the vendor-10415 app produces a Vendor-Specific-Application-Id;
        // the two base (vendor-0) apps must not be wrapped in one.
        let vsai_count = tree
            .find_all(avp::VENDOR_SPECIFIC_APPLICATION_ID, 0)
            .count();
        assert_eq!(vsai_count, 1, "exactly one VSAI (the vendor-10415 Cx app)");
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

    /// Stand up a real [`DiameterPeer`] whose far end answers every request with
    /// a CEA carrying `result_code`. Unlike [`loopback_peer_with_echo`] the
    /// answer has a real Result-Code AVP, which is what the answer counter reads.
    async fn loopback_peer_answering(
        result_code: u32,
    ) -> (Arc<DiameterPeer>, mpsc::Receiver<IncomingRequest>) {
        use tokio::io::AsyncWriteExt;
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let config = leak_test_config();
        let answer_config = config.clone();

        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let (read_half, mut write_half) = tokio::io::split(stream);
                let mut reader = BufReader::new(read_half);
                while let Ok(bytes) = codec::read_diameter_message(&mut reader).await {
                    let Some(request) = codec::decode_diameter(&bytes) else {
                        break;
                    };
                    // Correlate on the request's own Hop-by-Hop id, so the
                    // production reader task resolves the pending entry.
                    let answer = build_cea(
                        &answer_config,
                        result_code,
                        request.hop_by_hop,
                        request.end_to_end,
                    );
                    if write_half.write_all(&answer).await.is_err() {
                        break;
                    }
                }
            }
        });

        let client_stream = TcpStream::connect(addr).await.unwrap();
        let (incoming_tx, incoming_rx) = mpsc::channel(16);
        let peer = spawn_connection_tasks(config, DiameterStream::Tcp(client_stream), incoming_tx);
        (peer, incoming_rx)
    }

    fn answers_counter(command: &str, result_code: &str) -> u64 {
        crate::metrics::metrics()
            .map(|metrics| {
                metrics
                    .diameter_answers_total
                    .with_label_values(&[command, result_code])
                    .get()
            })
            .unwrap_or(0)
    }

    /// The blindness this counter exists to fix: a peer that answers, and says
    /// no. The round trip succeeds, so no transport error is recorded and the
    /// dashboard's "Errors total" stays at zero — an OCS refusing every single
    /// CCR looked identical to one granting them all.
    ///
    /// "Not a transport error" is asserted as `send_request` returning `Ok`,
    /// which is the observable form of it: every write to
    /// `diameter_request_errors_total` lives in an `Err` arm of the same match.
    /// The counter itself cannot carry an exact-delta assertion here — the
    /// registry is process-wide and the timeout tests below write to it in
    /// parallel.
    #[tokio::test]
    async fn a_failure_answer_counts_as_an_answer_not_a_transport_error() {
        crate::metrics::init().ok();
        let before = answers_counter("CEA", "4012");

        let (peer, _incoming_rx) = loopback_peer_answering(4012).await;
        let config = peer.config().clone();
        let request = build_cer(&config, peer.next_hbh(), 1);
        let result = peer.send_request(request).await;

        // The round trip itself succeeded — that is the whole point.
        let answer = result.expect(
            "a delivered answer is not a transport failure, however bad its \
             Result-Code; returning Err here would file a reachable peer that \
             is refusing everything under a metric that means something else",
        );
        assert_eq!(
            answer.avps.get("Result-Code").and_then(|v| v.as_u64()),
            Some(4012)
        );
        assert_eq!(
            answers_counter("CEA", "4012") - before,
            1,
            "a 4012 answer must be counted under its own Result-Code"
        );
    }

    /// A code siphon does not know must still be counted, and must not mint a
    /// series of its own — the value is chosen by the peer.
    #[tokio::test]
    async fn an_unknown_result_code_is_counted_in_its_class_bucket() {
        crate::metrics::init().ok();
        let before = answers_counter("CEA", "5xxx_other");

        let (peer, _incoming_rx) = loopback_peer_answering(5099).await;
        let config = peer.config().clone();
        let request = build_cer(&config, peer.next_hbh(), 1);
        peer.send_request(request).await.unwrap();

        assert_eq!(answers_counter("CEA", "5xxx_other") - before, 1);
        assert_eq!(
            answers_counter("CEA", "5099"),
            0,
            "an unlisted code must not get a series of its own"
        );
    }

    #[test]
    fn answer_result_label_prefers_base_then_experimental_then_none() {
        fn answer(avps: serde_json::Value) -> DiameterMessage {
            DiameterMessage {
                version: 1,
                length: 0,
                flags: 0,
                command_code: 272,
                application_id: 4,
                hop_by_hop: 1,
                end_to_end: 1,
                is_request: false,
                avps,
                raw: Vec::new(),
            }
        }

        assert_eq!(
            answer_result_label(&answer(serde_json::json!({"Result-Code": 2001}))),
            "2001"
        );

        // Cx/Sh/Rx answers carry Experimental-Result *instead of* Result-Code
        // (TS 29.229 §6.2), nested in the grouped AVP.
        assert_eq!(
            answer_result_label(&answer(serde_json::json!({
                "Experimental-Result": {"Experimental-Result-Code": 5001}
            }))),
            "exp:5001"
        );

        // The base code wins when a peer sends both, so one answer is never
        // counted twice or under the wrong namespace.
        assert_eq!(
            answer_result_label(&answer(serde_json::json!({
                "Result-Code": 2001,
                "Experimental-Result": {"Experimental-Result-Code": 5001}
            }))),
            "2001"
        );

        // A peer answering with no Result-Code at all is itself worth seeing.
        assert_eq!(answer_result_label(&answer(serde_json::json!({}))), "none");
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

    /// Stand up a real [`DiameterPeer`] whose far end completes the TCP
    /// handshake and then never reads a byte — alive, still ACKing, receive
    /// window closed. The small receive buffer is what makes the test fast: the
    /// window shuts after a few KB rather than after megabytes of autotuning.
    async fn loopback_peer_that_never_reads() -> (Arc<DiameterPeer>, mpsc::Receiver<IncomingRequest>)
    {
        use tokio::net::TcpStream;

        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket2::SockRef::from(&socket)
            .set_recv_buffer_size(2 * 1024)
            .unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let listener = socket.listen(8).unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
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

    /// The regression for the process abort.
    ///
    /// Every scripting Diameter method — `cx_*`, `sh_*`, `rx_*`, `rf_acr_*`,
    /// `s6a_*`, the generic `send_request` — reaches this enqueue from a script
    /// handler, holding a script-executor worker while it waits. The request
    /// timeout below it covers waiting for the *answer*, not for a slot in front
    /// of a writer that a non-draining peer has stalled, so before the bound
    /// this call never returned: worker after worker was consumed until the
    /// executor watchdog aborted the process.
    ///
    /// Against unbounded code this test does not fail, it hangs — which is
    /// exactly what it looked like in the field.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_peer_that_stops_reading_fails_the_request_instead_of_parking_the_caller() {
        let (peer, _incoming_rx) = loopback_peer_that_never_reads().await;
        let config = peer.config().clone();

        // Fill the socket and then the 64-slot channel behind it. `send_response`
        // is fire-and-forget, so this fills the pipe without waiting on answers
        // that a peer which never reads could never send.
        let filler = vec![0u8; 8 * 1024];
        let refusal = tokio::time::timeout(Duration::from_secs(20), async {
            for _ in 0..2000 {
                if let Err(error) = peer.send_response(filler.clone()).await {
                    return error;
                }
            }
            panic!("2000 sends to a peer that never reads all reported success");
        })
        .await
        .expect(
            "send_response parked on a peer that accepted the connection and \
             then stopped draining it — the write never returns, the channel \
             behind it fills, and every caller parks with it",
        );
        assert!(
            refusal.contains("queue full"),
            "expected the backlogged refusal, got: {refusal}"
        );

        // Now the path that matters: a request from a script handler.
        let before = peer.pending.lock().await.len();
        let request = build_cer(&config, peer.next_hbh(), 1);
        let outcome = tokio::time::timeout(
            Duration::from_secs(20),
            peer.send_request_timeout(request, Duration::from_secs(30)),
        )
        .await
        .expect(
            "send_request parked on the enqueue. This is the process-abort path: \
             the request timeout covers the answer, not the wait for a slot in \
             front of a stalled writer, so the handler thread is gone for good.",
        );

        let error = outcome.expect_err("a request to a peer that never reads cannot succeed");
        assert!(
            error.contains("queue full"),
            "expected the backlogged refusal, got: {error}"
        );

        // The pending entry is inserted before the enqueue, so the shed path has
        // to take it back out — otherwise every refused request leaks one
        // `oneshot::Sender` for the life of the connection.
        assert_eq!(
            peer.pending.lock().await.len(),
            before,
            "a request refused at the enqueue must not leave its Hop-by-Hop entry \
             behind in the correlation map"
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
        let listener = match crate::diameter::transport::DiameterListener::bind_sctp(
            "127.0.0.1:0".parse().unwrap(),
        ) {
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
            if let Ok((server_peer, _rx)) = accept(DiameterStream::Tcp(stream), test_config()).await
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
        assert_eq!(
            request.command_code,
            dictionary::CMD_AUTHENTICATION_INFORMATION
        );
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
