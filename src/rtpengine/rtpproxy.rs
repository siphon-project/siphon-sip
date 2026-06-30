//! Classic `rtpproxy` control-protocol client (text-over-UDP).
//!
//! `rtpproxy` (the Sippy/Kamailio/OpenSIPS media relay) speaks a small text
//! protocol over UDP: each request is `<cookie> <command>` in a single datagram,
//! and the reply is `<cookie> <result>`.  The cookie correlates reply to request
//! and lets the engine de-duplicate retransmits idempotently — so this client
//! resends the *same* cookie on timeout rather than failing immediately, which is
//! the standard way to get reliability over UDP.
//!
//! Unlike rtpengine NG and the native siphon-rtp engine — which rewrite the SDP
//! server-side and hand back the finished body — `rtpproxy` only **allocates a
//! relay port** and returns `<port> [<address>]`.  siphon therefore rewrites the
//! SDP itself: for each media stream it sends an `U`/`L` command carrying that
//! stream's advertised address/port, then writes the returned relay address/port
//! back into the `c=`/`m=` lines (via [`crate::media::sdp`]).
//!
//! This client mirrors the public method surface of
//! [`RtpEngineSet`](super::client::RtpEngineSet) so it is interchangeable behind
//! [`MediaBackend`](super::backend::MediaBackend).  Only the four media-anchoring
//! verbs are supported — `offer` (`U`), `answer` (`L`), `delete` (`D`) and `ping`
//! (`V`); the rtpengine-only extras (prompts, DTMF injection, gating,
//! SIPREC/MPTY subscriptions) surface a clear [`RtpEngineError::EngineError`].
//! The primary use case is migrating an existing OpenSIPS/Kamailio/Sippy
//! deployment to siphon while keeping its in-place rtpproxy as the media relay.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use dashmap::DashMap;
use futures_util::future::join_all;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tracing::{debug, error, trace, warn};

use crate::media::sdp::{MediaLine, SdpBody};

use super::client::PlayMediaSource;
use super::error::RtpEngineError;
use super::profile::NgFlags;

/// Maximum UDP datagram we will accept from rtpproxy (responses are tiny).
const RECV_BUFFER_SIZE: usize = 65535;
/// Floor for a single send attempt's wait when the per-call budget is split
/// across retransmits, so a tight `timeout_ms` still leaves time to hear back.
const MIN_PER_ATTEMPT_MS: u64 = 50;

/// Async client for one `rtpproxy` control endpoint.
pub struct RtpProxyClient {
    /// Local UDP socket bound to an ephemeral port.
    socket: Arc<UdpSocket>,
    /// rtpproxy control address (`rtpproxy -s udp:<host>:<port>`).
    address: SocketAddr,
    /// In-flight requests awaiting a response, keyed by cookie.
    pending: Arc<DashMap<String, oneshot::Sender<String>>>,
    /// Total per-command response budget in milliseconds (split across attempts).
    timeout_ms: u64,
    /// Number of retransmits after the first send (same cookie each time).
    retries: u32,
    /// Active call-ids (offer→insert, delete→remove) — mirrors `RtpEngineSet`'s
    /// affinity count for the `rtpengine.active_sessions` Python getter.
    sessions: DashMap<String, ()>,
}

impl RtpProxyClient {
    /// Create a client and spawn the background receiver task.
    pub async fn new(
        address: SocketAddr,
        timeout_ms: u64,
        retries: u32,
    ) -> Result<Arc<Self>, RtpEngineError> {
        // Bind a v4 or v6 ephemeral socket to match the control address family.
        let bind_addr = if address.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
        let pending: Arc<DashMap<String, oneshot::Sender<String>>> = Arc::new(DashMap::new());

        {
            let socket = Arc::clone(&socket);
            let pending = Arc::clone(&pending);
            tokio::spawn(async move { receiver_loop(socket, pending).await });
        }

        Ok(Arc::new(Self {
            socket,
            address,
            pending,
            timeout_ms,
            retries,
            sessions: DashMap::new(),
        }))
    }

    /// Send `U` (create/update) for an offer and return the rewritten SDP.
    pub async fn offer(
        &self,
        call_id: &str,
        from_tag: &str,
        sdp: &[u8],
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        let rewritten = self
            .negotiate('U', call_id, from_tag, None, sdp, flags)
            .await?;
        self.sessions.insert(call_id.to_string(), ());
        Ok(rewritten)
    }

    /// Send `L` (lookup) for an answer and return the rewritten SDP.
    pub async fn answer(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
        sdp: &[u8],
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        self.negotiate('L', call_id, from_tag, Some(to_tag), sdp, flags)
            .await
    }

    /// Send `D` (delete) to tear down a session and drop its active-session entry.
    pub async fn delete(&self, call_id: &str, from_tag: &str) -> Result<(), RtpEngineError> {
        let command = format!("D {call_id} {from_tag}");
        let response = self.request(&command).await;
        self.sessions.remove(call_id);
        let response = response?;
        let trimmed = response.trim();
        if let Some(code) = trimmed.strip_prefix('E') {
            return Err(RtpEngineError::EngineError(format!(
                "rtpproxy delete error {code}"
            )));
        }
        Ok(())
    }

    /// Liveness check: `V` returns the protocol version (e.g. `20040107`).
    pub async fn ping(&self) -> Result<(), RtpEngineError> {
        let response = self.request("V").await?;
        let trimmed = response.trim();
        if let Some(code) = trimmed.strip_prefix('E') {
            return Err(RtpEngineError::EngineError(format!(
                "rtpproxy version error {code}"
            )));
        }
        if !trimmed.is_empty() && trimmed.bytes().all(|byte| byte.is_ascii_digit()) {
            Ok(())
        } else {
            Err(RtpEngineError::Protocol(format!(
                "unexpected rtpproxy version response: {trimmed:?}"
            )))
        }
    }

    /// Probe health: a single-element `(address, healthy)` vec, shaped like
    /// [`RtpEngineSet::health_check`](super::client::RtpEngineSet::health_check).
    pub async fn health_check(&self) -> Vec<(SocketAddr, bool)> {
        vec![(self.address, self.ping().await.is_ok())]
    }

    /// Control endpoint this client talks to.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Number of active call-ids (offer without a matching delete).
    pub fn active_sessions(&self) -> usize {
        self.sessions.len()
    }

    /// Always 1 — a single client drives one rtpproxy endpoint.
    pub fn instance_count(&self) -> usize {
        1
    }

    /// The single control endpoint, shaped like `RtpEngineSet::instance_addresses`.
    pub fn instance_addresses(&self) -> Vec<SocketAddr> {
        vec![self.address]
    }

    /// Drive an `U`/`L` exchange across every media stream and return the SDP
    /// rewritten to point at the rtpproxy relay.
    ///
    /// One command is issued per media section whose port is non-zero (a `0` port
    /// is held/declined media — RFC 4566 — and is left untouched). With more than
    /// one media section, the media index (1-based) is appended to the from/to
    /// tag (`tag;1`, `tag;2`, …) so rtpproxy can distinguish the streams; this is
    /// applied identically on the matching `offer`/`answer` so the engine
    /// correlates them.
    async fn negotiate(
        &self,
        command_letter: char,
        call_id: &str,
        from_tag: &str,
        to_tag: Option<&str>,
        sdp: &[u8],
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        let sdp_text = std::str::from_utf8(sdp)
            .map_err(|_| RtpEngineError::Protocol("SDP body is not valid UTF-8".to_string()))?;
        let mut parsed = SdpBody::parse(sdp_text);

        // Clone the session-level c= up front so no borrow of `parsed` is held
        // across the awaits below (we mutate `parsed.media_sections` in the loop).
        let session_connection = parsed.connection().map(str::to_string);
        let multi_stream = parsed.media_sections.len() > 1;
        let mut relay_address_for_session: Option<String> = None;

        for index in 0..parsed.media_sections.len() {
            let advertised_port = parsed.media_sections[index].port;
            if advertised_port == 0 {
                // Held/declined media — nothing to anchor for this stream.
                continue;
            }

            let media_connection = parsed.media_sections[index].connection().map(str::to_string);
            let connection = media_connection
                .as_deref()
                .or(session_connection.as_deref())
                .ok_or_else(|| {
                    RtpEngineError::Protocol(
                        "SDP has no connection address (c=) for an active media stream"
                            .to_string(),
                    )
                })?;
            let (is_ipv6, advertised_address) = parse_connection(connection)?;

            let modifiers = command_modifiers(flags, is_ipv6);
            let tag_suffix = if multi_stream {
                format!(";{}", index + 1)
            } else {
                String::new()
            };
            let from = format!("{from_tag}{tag_suffix}");
            let to = to_tag.map(|tag| format!("{tag}{tag_suffix}"));

            let command = build_command(
                command_letter,
                &modifiers,
                call_id,
                &advertised_address,
                advertised_port,
                &from,
                to.as_deref(),
            );

            let response = self.request(&command).await?;
            let (relay_address, relay_port) =
                parse_session_response(&response, self.address.ip())?;

            parsed.media_sections[index].port = relay_port;
            if media_connection.is_some() {
                set_media_connection(&mut parsed.media_sections[index], &relay_address);
            }
            if relay_address_for_session.is_none() {
                relay_address_for_session = Some(relay_address);
            }
        }

        if let Some(relay_address) = relay_address_for_session {
            set_session_connection(&mut parsed, &relay_address);
        }

        Ok(parsed.to_string().into_bytes())
    }

    /// Send a command datagram and await the correlated reply, retransmitting the
    /// same cookie on a per-attempt timeout (rtpproxy de-duplicates by cookie).
    async fn request(&self, payload: &str) -> Result<String, RtpEngineError> {
        let cookie = generate_cookie();
        let datagram = format!("{cookie} {payload}");

        let (sender, mut receiver) = oneshot::channel();
        self.pending.insert(cookie.clone(), sender);

        let attempts = self.retries + 1;
        let per_attempt = Duration::from_millis((self.timeout_ms / attempts as u64).max(MIN_PER_ATTEMPT_MS));

        for attempt in 0..attempts {
            if let Err(error) = self.socket.send_to(datagram.as_bytes(), self.address).await {
                self.pending.remove(&cookie);
                return Err(RtpEngineError::Io(error));
            }
            trace!(cookie = %cookie, attempt, address = %self.address, "sent rtpproxy command");

            match tokio::time::timeout(per_attempt, &mut receiver).await {
                Ok(Ok(response)) => {
                    // The receiver loop already removed the pending entry.
                    debug!(cookie = %cookie, "received rtpproxy response");
                    return Ok(response);
                }
                Ok(Err(_)) => {
                    self.pending.remove(&cookie);
                    return Err(RtpEngineError::Protocol(
                        "response channel closed unexpectedly".to_string(),
                    ));
                }
                Err(_) => {
                    // Per-attempt timeout — resend the same cookie unless exhausted.
                    trace!(cookie = %cookie, attempt, "rtpproxy timeout, retransmitting");
                    continue;
                }
            }
        }

        self.pending.remove(&cookie);
        Err(RtpEngineError::Timeout {
            timeout_ms: self.timeout_ms,
        })
    }
}

// ---------------------------------------------------------------------------
// Multi-instance set (weighted round-robin + per-call-id affinity)
// ---------------------------------------------------------------------------

/// A set of `rtpproxy` endpoints for HA / load-balancing.
///
/// Mirrors [`RtpEngineSet`](super::client::RtpEngineSet): weighted round-robin
/// instance selection with per-call-id affinity, so every command for a call
/// goes to the same rtpproxy (splitting a call across relays would orphan the
/// allocated ports).
pub struct RtpProxyClientSet {
    clients: Vec<Arc<RtpProxyClient>>,
    /// Cumulative weights for weighted selection.
    cumulative_weights: Vec<u32>,
    total_weight: u32,
    /// Atomic counter for round-robin.
    counter: AtomicU64,
    /// Call-ID → client index affinity.
    affinity: DashMap<String, usize>,
}

impl RtpProxyClientSet {
    /// Build a set from `(address, timeout_ms, weight)` triples, binding one UDP
    /// socket per instance. Returns an error when `instances` is empty.
    pub async fn new(
        instances: Vec<(SocketAddr, u64, u32)>,
        retries: u32,
    ) -> Result<Arc<Self>, RtpEngineError> {
        if instances.is_empty() {
            return Err(RtpEngineError::Protocol(
                "at least one rtpproxy instance is required".to_string(),
            ));
        }

        let mut clients = Vec::with_capacity(instances.len());
        let mut cumulative_weights = Vec::with_capacity(instances.len());
        let mut running_total = 0u32;
        for (address, timeout_ms, weight) in &instances {
            clients.push(RtpProxyClient::new(*address, *timeout_ms, retries).await?);
            running_total += weight;
            cumulative_weights.push(running_total);
        }

        Ok(Arc::new(Self {
            clients,
            cumulative_weights,
            total_weight: running_total,
            counter: AtomicU64::new(0),
            affinity: DashMap::new(),
        }))
    }

    /// Select a client by call-id affinity or weighted round-robin.
    fn select(&self, call_id: &str) -> &Arc<RtpProxyClient> {
        if self.clients.len() == 1 {
            return &self.clients[0];
        }
        if let Some(index) = self.affinity.get(call_id) {
            return &self.clients[*index];
        }
        let tick = self.counter.fetch_add(1, Ordering::Relaxed);
        let position = (tick % self.total_weight as u64) as u32;
        let index = self
            .cumulative_weights
            .iter()
            .position(|&cumulative| position < cumulative)
            .unwrap_or(0);
        &self.clients[index]
    }

    /// Record call-id affinity after the first command (multi-instance only).
    fn bind_affinity(&self, call_id: &str) {
        if self.clients.len() <= 1 || self.affinity.contains_key(call_id) {
            return;
        }
        let tick = self.counter.load(Ordering::Relaxed).wrapping_sub(1);
        let position = (tick % self.total_weight as u64) as u32;
        let index = self
            .cumulative_weights
            .iter()
            .position(|&cumulative| position < cumulative)
            .unwrap_or(0);
        self.affinity.insert(call_id.to_string(), index);
    }

    /// Send an `offer`, binding call-id affinity to the selected instance.
    pub async fn offer(
        &self,
        call_id: &str,
        from_tag: &str,
        sdp: &[u8],
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        let result = self.select(call_id).offer(call_id, from_tag, sdp, flags).await?;
        self.bind_affinity(call_id);
        Ok(result)
    }

    /// Send an `answer` to the affinity-bound instance.
    pub async fn answer(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
        sdp: &[u8],
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        self.select(call_id)
            .answer(call_id, from_tag, to_tag, sdp, flags)
            .await
    }

    /// Send a `delete` and drop affinity.
    pub async fn delete(&self, call_id: &str, from_tag: &str) -> Result<(), RtpEngineError> {
        let result = self.select(call_id).delete(call_id, from_tag).await;
        self.affinity.remove(call_id);
        result
    }

    /// Inject an audio prompt — unsupported by rtpproxy.
    #[allow(clippy::too_many_arguments)]
    pub async fn play_media(
        &self,
        _call_id: &str,
        _from_tag: &str,
        _source: &PlayMediaSource,
        _repeat_times: Option<u64>,
        _start_pos_ms: Option<u64>,
        _duration_ms: Option<u64>,
        _to_tag: Option<&str>,
    ) -> Result<Option<u64>, RtpEngineError> {
        Err(unsupported("play_media"))
    }

    /// Stop a prompt — unsupported by rtpproxy.
    pub async fn stop_media(&self, _call_id: &str, _from_tag: &str) -> Result<(), RtpEngineError> {
        Err(unsupported("stop_media"))
    }

    /// Inject DTMF — unsupported by rtpproxy.
    #[allow(clippy::too_many_arguments)]
    pub async fn play_dtmf(
        &self,
        _call_id: &str,
        _from_tag: &str,
        _code: &str,
        _duration_ms: Option<u64>,
        _volume_dbm0: Option<i64>,
        _pause_ms: Option<u64>,
        _to_tag: Option<&str>,
    ) -> Result<(), RtpEngineError> {
        Err(unsupported("play_dtmf"))
    }

    /// Replace egress audio with silence — unsupported by rtpproxy.
    pub async fn silence_media(&self, _call_id: &str, _from_tag: &str) -> Result<(), RtpEngineError> {
        Err(unsupported("silence_media"))
    }

    /// Resume egress audio — unsupported by rtpproxy.
    pub async fn unsilence_media(
        &self,
        _call_id: &str,
        _from_tag: &str,
    ) -> Result<(), RtpEngineError> {
        Err(unsupported("unsilence_media"))
    }

    /// Drop egress packets — unsupported by rtpproxy.
    pub async fn block_media(&self, _call_id: &str, _from_tag: &str) -> Result<(), RtpEngineError> {
        Err(unsupported("block_media"))
    }

    /// Resume egress packets — unsupported by rtpproxy.
    pub async fn unblock_media(&self, _call_id: &str, _from_tag: &str) -> Result<(), RtpEngineError> {
        Err(unsupported("unblock_media"))
    }

    /// Create a media subscription — unsupported by rtpproxy.
    pub async fn subscribe_request(
        &self,
        _call_id: &str,
        _from_tag: &str,
        _to_tag: &str,
        _sdp: Option<&[u8]>,
        _flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        Err(unsupported("subscribe_request"))
    }

    /// SIPREC-mode subscription — unsupported by rtpproxy.
    pub async fn subscribe_request_siprec(
        &self,
        _call_id: &str,
        _from_tags: &[&str],
        _profile_flags: Option<&NgFlags>,
    ) -> Result<(Vec<u8>, String), RtpEngineError> {
        Err(unsupported("subscribe_request_siprec"))
    }

    /// Complete a subscription's SDP negotiation — unsupported by rtpproxy.
    pub async fn subscribe_answer(
        &self,
        _call_id: &str,
        _from_tag: &str,
        _to_tag: &str,
        _sdp: &[u8],
        _flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        Err(unsupported("subscribe_answer"))
    }

    /// Tear down a subscription — unsupported by rtpproxy.
    pub async fn unsubscribe(
        &self,
        _call_id: &str,
        _from_tag: &str,
        _to_tag: &str,
    ) -> Result<(), RtpEngineError> {
        Err(unsupported("unsubscribe"))
    }

    /// Ping any one instance (the first). For quick health checks.
    pub async fn ping(&self) -> Result<(), RtpEngineError> {
        match self.clients.first() {
            Some(client) => client.ping().await,
            None => Err(RtpEngineError::Protocol("no rtpproxy instances".to_string())),
        }
    }

    /// Ping every instance in parallel and return per-instance health status.
    pub async fn health_check(&self) -> Vec<(SocketAddr, bool)> {
        let probes = self
            .clients
            .iter()
            .map(|client| async move { (client.address(), client.ping().await.is_ok()) });
        join_all(probes).await
    }

    /// Total active call-ids across all instances.
    pub fn active_sessions(&self) -> usize {
        self.clients.iter().map(|client| client.active_sessions()).sum()
    }

    /// Number of configured instances.
    pub fn instance_count(&self) -> usize {
        self.clients.len()
    }

    /// Addresses of every configured instance, in registration order.
    pub fn instance_addresses(&self) -> Vec<SocketAddr> {
        self.clients.iter().map(|client| client.address()).collect()
    }
}

// ---------------------------------------------------------------------------
// Protocol helpers
// ---------------------------------------------------------------------------

/// Generate a random cookie for request/response correlation (and retransmit
/// de-duplication). Eight hex chars is ample collision resistance for in-flight
/// commands to one engine.
fn generate_cookie() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..8].to_string()
}

/// Error for the rtpengine-only verbs that rtpproxy cannot serve.
fn unsupported(operation: &str) -> RtpEngineError {
    RtpEngineError::EngineError(format!(
        "rtpproxy backend does not support '{operation}' \
         (use the rtpengine or siphon-rtp backend)"
    ))
}

/// Build the modifier suffix for a `U`/`L` command from the profile flags and
/// the stream's address family.
///
/// Mapping (the common rtpproxy flags; extend as deployments need them):
/// - `direction: ["internal", "external"]` → `ie` (bridge mode; the offer and
///   answer carry their own [`NgFlags`], so a profile sets `["internal",
///   "external"]` for the offer and `["external", "internal"]` for the answer to
///   get the `ie`/`ei` pairing rtpproxy bridging expects).
/// - a `flags` entry of `"asymmetric"` → `a` (rtpproxy defaults to symmetric).
/// - an IPv6 stream → `6`.
fn command_modifiers(flags: &NgFlags, is_ipv6: bool) -> String {
    let mut modifiers = String::new();
    for direction in &flags.direction {
        let lower = direction.to_ascii_lowercase();
        if lower.starts_with("int") || lower == "in" {
            modifiers.push('i');
        } else if lower.starts_with("ext") || lower.starts_with("pub") || lower == "out" {
            modifiers.push('e');
        }
    }
    if flags
        .flags
        .iter()
        .any(|flag| flag.eq_ignore_ascii_case("asymmetric"))
    {
        modifiers.push('a');
    }
    if is_ipv6 {
        modifiers.push('6');
    }
    modifiers
}

/// Build a `U`/`L` command line (without the leading cookie).
fn build_command(
    command_letter: char,
    modifiers: &str,
    call_id: &str,
    address: &str,
    port: u16,
    from_tag: &str,
    to_tag: Option<&str>,
) -> String {
    let mut command = format!("{command_letter}{modifiers} {call_id} {address} {port} {from_tag}");
    if let Some(to_tag) = to_tag {
        command.push(' ');
        command.push_str(to_tag);
    }
    command
}

/// Parse a `U`/`L` response: `<port> [<address> …]` or `E<code>` on error.
///
/// rtpproxy returns the allocated relay port and, on newer builds, one or more
/// advertised addresses. When no address is returned, the relay lives at the
/// control endpoint's IP, so we fall back to `default_address`.
fn parse_session_response(
    response: &str,
    default_address: IpAddr,
) -> Result<(String, u16), RtpEngineError> {
    let trimmed = response.trim();
    if let Some(code) = trimmed.strip_prefix('E') {
        return Err(RtpEngineError::EngineError(format!("rtpproxy error {code}")));
    }

    let mut tokens = trimmed.split_whitespace();
    let port_token = tokens
        .next()
        .ok_or_else(|| RtpEngineError::Protocol("empty rtpproxy response".to_string()))?;
    let port: u16 = port_token.parse().map_err(|_| {
        RtpEngineError::Protocol(format!("invalid rtpproxy port {port_token:?}"))
    })?;
    if port == 0 {
        return Err(RtpEngineError::EngineError(
            "rtpproxy returned port 0 (allocation declined)".to_string(),
        ));
    }

    let address = tokens
        .next()
        .map(str::to_string)
        .unwrap_or_else(|| default_address.to_string());
    Ok((address, port))
}

/// Parse an SDP `c=` value (`IN IP4 10.0.0.1`, `IN IP6 ::1`, with an optional
/// `/ttl` or `/ttl/count` multicast suffix) into `(is_ipv6, address)`.
fn parse_connection(connection: &str) -> Result<(bool, String), RtpEngineError> {
    let mut tokens = connection.split_whitespace();
    let _network_type = tokens.next(); // "IN"
    let address_type = tokens.next().unwrap_or("IP4");
    let address = tokens.next().ok_or_else(|| {
        RtpEngineError::Protocol(format!("malformed connection line: c={connection}"))
    })?;
    // Strip any multicast TTL/count suffix.
    let address = address.split('/').next().unwrap_or(address).to_string();
    Ok((address_type.eq_ignore_ascii_case("IP6"), address))
}

/// Format a `c=` line for a relay address, picking the family from the address.
fn connection_line(address: &str) -> String {
    let family = if address.contains(':') { "IP6" } else { "IP4" };
    format!("c=IN {family} {address}")
}

/// Replace (or insert) the session-level `c=` line with the relay address.
fn set_session_connection(sdp: &mut SdpBody, address: &str) {
    let new_line = connection_line(address);
    if let Some(position) = sdp.session_lines.iter().position(|line| line.starts_with("c=")) {
        sdp.session_lines[position] = new_line;
        return;
    }
    // RFC 4566 orders c= after s= (and after o=); insert there, else append.
    let insert_at = sdp
        .session_lines
        .iter()
        .position(|line| line.starts_with("s="))
        .map(|position| position + 1)
        .or_else(|| {
            sdp.session_lines
                .iter()
                .position(|line| line.starts_with("o="))
                .map(|position| position + 1)
        })
        .unwrap_or(sdp.session_lines.len());
    sdp.session_lines.insert(insert_at, new_line);
}

/// Replace (or insert) a media-level `c=` line with the relay address.
fn set_media_connection(media: &mut MediaLine, address: &str) {
    let new_line = connection_line(address);
    if let Some(position) = media.other_attrs.iter().position(|line| line.starts_with("c=")) {
        media.other_attrs[position] = new_line;
    } else {
        // A media-level c= must precede the a= lines.
        media.other_attrs.insert(0, new_line);
    }
}

/// Background receiver loop — reads UDP responses and dispatches to waiters.
async fn receiver_loop(
    socket: Arc<UdpSocket>,
    pending: Arc<DashMap<String, oneshot::Sender<String>>>,
) {
    let mut buffer = BytesMut::zeroed(RECV_BUFFER_SIZE);
    loop {
        match socket.recv_from(&mut buffer).await {
            Ok((size, source)) => {
                let data = &buffer[..size];
                trace!(size, source = %source, "received rtpproxy response packet");

                let space_position = match data.iter().position(|&byte| byte == b' ') {
                    Some(position) => position,
                    None => {
                        warn!("rtpproxy response missing space separator, ignoring");
                        continue;
                    }
                };
                let cookie = match std::str::from_utf8(&data[..space_position]) {
                    Ok(cookie) => cookie.to_string(),
                    Err(_) => {
                        warn!("rtpproxy response cookie is not valid UTF-8, ignoring");
                        continue;
                    }
                };
                let payload = match std::str::from_utf8(&data[space_position + 1..]) {
                    Ok(payload) => payload.trim_end().to_string(),
                    Err(_) => {
                        warn!(cookie = %cookie, "rtpproxy response payload is not valid UTF-8");
                        continue;
                    }
                };

                if let Some((_, sender)) = pending.remove(&cookie) {
                    let _ = sender.send(payload);
                } else {
                    debug!(cookie = %cookie, "no pending rtpproxy request for cookie (stale or duplicate)");
                }
            }
            Err(error) => {
                error!(error = %error, "rtpproxy receiver socket error");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- pure-function unit tests (no socket) --

    #[test]
    fn cookie_is_eight_hex_chars() {
        let cookie = generate_cookie();
        assert_eq!(cookie.len(), 8);
        assert!(cookie.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn modifiers_empty_for_default_flags() {
        let flags = NgFlags::default();
        assert_eq!(command_modifiers(&flags, false), "");
    }

    #[test]
    fn modifiers_bridge_internal_external() {
        let flags = NgFlags {
            direction: vec!["internal".to_string(), "external".to_string()],
            ..NgFlags::default()
        };
        assert_eq!(command_modifiers(&flags, false), "ie");
    }

    #[test]
    fn modifiers_bridge_reversed_for_answer() {
        let flags = NgFlags {
            direction: vec!["external".to_string(), "internal".to_string()],
            ..NgFlags::default()
        };
        assert_eq!(command_modifiers(&flags, false), "ei");
    }

    #[test]
    fn modifiers_asymmetric_and_ipv6() {
        let flags = NgFlags {
            flags: vec!["asymmetric".to_string()],
            ..NgFlags::default()
        };
        assert_eq!(command_modifiers(&flags, true), "a6");
    }

    #[test]
    fn build_offer_command_without_to_tag() {
        let command = build_command('U', "", "call-1", "10.0.0.1", 8000, "ftag", None);
        assert_eq!(command, "U call-1 10.0.0.1 8000 ftag");
    }

    #[test]
    fn build_answer_command_with_modifiers_and_to_tag() {
        let command = build_command('L', "ei", "call-1", "10.0.0.2", 9000, "ftag", Some("ttag"));
        assert_eq!(command, "Lei call-1 10.0.0.2 9000 ftag ttag");
    }

    #[test]
    fn parse_response_port_and_address() {
        let default_addr: IpAddr = "203.0.113.7".parse().unwrap();
        let (address, port) = parse_session_response("30000 203.0.113.1", default_addr).unwrap();
        assert_eq!(address, "203.0.113.1");
        assert_eq!(port, 30000);
    }

    #[test]
    fn parse_response_port_only_falls_back_to_control_ip() {
        let default_addr: IpAddr = "203.0.113.7".parse().unwrap();
        let (address, port) = parse_session_response("40002", default_addr).unwrap();
        assert_eq!(address, "203.0.113.7");
        assert_eq!(port, 40002);
    }

    #[test]
    fn parse_response_error_code() {
        let default_addr: IpAddr = "203.0.113.7".parse().unwrap();
        let result = parse_session_response("E7", default_addr);
        assert!(matches!(result, Err(RtpEngineError::EngineError(_))));
    }

    #[test]
    fn parse_response_port_zero_is_declined() {
        let default_addr: IpAddr = "203.0.113.7".parse().unwrap();
        let result = parse_session_response("0", default_addr);
        assert!(matches!(result, Err(RtpEngineError::EngineError(_))));
    }

    #[test]
    fn parse_connection_ipv4_and_ipv6() {
        assert_eq!(
            parse_connection("IN IP4 10.0.0.1").unwrap(),
            (false, "10.0.0.1".to_string())
        );
        assert_eq!(
            parse_connection("IN IP6 2001:db8::1").unwrap(),
            (true, "2001:db8::1".to_string())
        );
    }

    #[test]
    fn parse_connection_strips_multicast_ttl() {
        assert_eq!(
            parse_connection("IN IP4 224.2.1.1/127").unwrap(),
            (false, "224.2.1.1".to_string())
        );
    }

    #[test]
    fn connection_line_picks_family() {
        assert_eq!(connection_line("10.0.0.1"), "c=IN IP4 10.0.0.1");
        assert_eq!(connection_line("2001:db8::1"), "c=IN IP6 2001:db8::1");
    }

    #[test]
    fn set_session_connection_replaces_existing() {
        let mut sdp = SdpBody::parse("v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\n");
        set_session_connection(&mut sdp, "203.0.113.1");
        assert_eq!(sdp.connection(), Some("IN IP4 203.0.113.1"));
        // Exactly one c= line.
        assert_eq!(
            sdp.session_lines.iter().filter(|l| l.starts_with("c=")).count(),
            1
        );
    }

    #[test]
    fn set_session_connection_inserts_when_missing() {
        let mut sdp = SdpBody::parse("v=0\r\no=- 1 1 IN IP4 10.0.0.1\r\ns=-\r\nt=0 0\r\n");
        set_session_connection(&mut sdp, "203.0.113.1");
        assert_eq!(sdp.connection(), Some("IN IP4 203.0.113.1"));
        // c= lands after s=.
        let s_pos = sdp.session_lines.iter().position(|l| l.starts_with("s=")).unwrap();
        let c_pos = sdp.session_lines.iter().position(|l| l.starts_with("c=")).unwrap();
        assert_eq!(c_pos, s_pos + 1);
    }

    // -- socket-backed tests against an in-process mock rtpproxy --

    /// Spawn a mock rtpproxy that echoes the cookie and replies per command:
    /// `V` → version, `U`/`L` → `<port> <addr>`, `D` → `0`.
    async fn spawn_mock_rtpproxy(reply_address: &'static str, reply_port: u16) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buffer = BytesMut::zeroed(4096);
            while let Ok((size, source)) = socket.recv_from(&mut buffer).await {
                let data = &buffer[..size];
                let space = data.iter().position(|&b| b == b' ').unwrap();
                let cookie = std::str::from_utf8(&data[..space]).unwrap();
                let command = std::str::from_utf8(&data[space + 1..]).unwrap();
                let result = if command.starts_with('V') {
                    "20040107".to_string()
                } else if command.starts_with('U') || command.starts_with('L') {
                    format!("{reply_port} {reply_address}")
                } else {
                    // D and anything else
                    "0".to_string()
                };
                let reply = format!("{cookie} {result}");
                let _ = socket.send_to(reply.as_bytes(), source).await;
            }
        });
        address
    }

    fn sample_offer_sdp() -> &'static [u8] {
        concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "t=0 0\r\n",
            "m=audio 8000 RTP/AVP 0 8\r\n",
            "a=rtpmap:0 PCMU/8000\r\n",
            "a=rtpmap:8 PCMA/8000\r\n",
        )
        .as_bytes()
    }

    #[tokio::test]
    async fn ping_roundtrip() {
        let address = spawn_mock_rtpproxy("203.0.113.1", 30000).await;
        let client = RtpProxyClient::new(address, 1000, 1).await.unwrap();
        client.ping().await.unwrap();
    }

    #[tokio::test]
    async fn offer_rewrites_sdp_to_relay() {
        let address = spawn_mock_rtpproxy("203.0.113.1", 30000).await;
        let client = RtpProxyClient::new(address, 1000, 1).await.unwrap();
        let flags = NgFlags::default();

        let rewritten = client
            .offer("call-1", "ftag", sample_offer_sdp(), &flags)
            .await
            .unwrap();
        let text = String::from_utf8(rewritten).unwrap();

        // c= now points at the relay; m= carries the relay port; codecs intact.
        assert!(text.contains("c=IN IP4 203.0.113.1"), "sdp was: {text}");
        assert!(text.contains("m=audio 30000 RTP/AVP 0 8"), "sdp was: {text}");
        assert!(text.contains("a=rtpmap:0 PCMU/8000"));
        // The original endpoint must be gone from the connection line.
        assert!(!text.contains("c=IN IP4 10.0.0.1"));
        assert_eq!(client.active_sessions(), 1);
    }

    #[tokio::test]
    async fn answer_rewrites_sdp_to_relay() {
        let address = spawn_mock_rtpproxy("203.0.113.1", 31000).await;
        let client = RtpProxyClient::new(address, 1000, 1).await.unwrap();
        let flags = NgFlags::default();

        let answer_sdp = concat!(
            "v=0\r\n",
            "o=- 2 2 IN IP4 10.0.0.2\r\n",
            "s=-\r\n",
            "c=IN IP4 10.0.0.2\r\n",
            "t=0 0\r\n",
            "m=audio 9000 RTP/AVP 0\r\n",
        )
        .as_bytes();

        let rewritten = client
            .answer("call-1", "ftag", "ttag", answer_sdp, &flags)
            .await
            .unwrap();
        let text = String::from_utf8(rewritten).unwrap();
        assert!(text.contains("c=IN IP4 203.0.113.1"), "sdp was: {text}");
        assert!(text.contains("m=audio 31000 RTP/AVP 0"), "sdp was: {text}");
    }

    #[tokio::test]
    async fn offer_command_wire_format_is_exact() {
        // A mock that captures the exact command line it received.
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let (capture_tx, capture_rx) = oneshot::channel::<String>();
        tokio::spawn(async move {
            let mut buffer = BytesMut::zeroed(4096);
            if let Ok((size, source)) = socket.recv_from(&mut buffer).await {
                let data = &buffer[..size];
                let space = data.iter().position(|&b| b == b' ').unwrap();
                let cookie = std::str::from_utf8(&data[..space]).unwrap();
                let command = std::str::from_utf8(&data[space + 1..]).unwrap().to_string();
                let reply = format!("{cookie} 30000 203.0.113.1");
                let _ = socket.send_to(reply.as_bytes(), source).await;
                let _ = capture_tx.send(command);
            }
        });

        let client = RtpProxyClient::new(address, 1000, 1).await.unwrap();
        let flags = NgFlags::default();
        client
            .offer("abc123", "from-tag-1", sample_offer_sdp(), &flags)
            .await
            .unwrap();

        let command = capture_rx.await.unwrap();
        // Single media stream → no media-id suffix on the tag.
        assert_eq!(command, "U abc123 10.0.0.1 8000 from-tag-1");
    }

    #[tokio::test]
    async fn multi_stream_appends_media_id_suffix() {
        // Capture both command lines for a 2-stream offer.
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let (capture_tx, mut capture_rx) = tokio::sync::mpsc::channel::<String>(4);
        tokio::spawn(async move {
            let mut buffer = BytesMut::zeroed(4096);
            let mut port = 30000u16;
            while let Ok((size, source)) = socket.recv_from(&mut buffer).await {
                let data = &buffer[..size];
                let space = data.iter().position(|&b| b == b' ').unwrap();
                let cookie = std::str::from_utf8(&data[..space]).unwrap();
                let command = std::str::from_utf8(&data[space + 1..]).unwrap().to_string();
                let reply = format!("{cookie} {port} 203.0.113.1");
                port += 2;
                let _ = socket.send_to(reply.as_bytes(), source).await;
                let _ = capture_tx.send(command).await;
            }
        });

        let client = RtpProxyClient::new(address, 1000, 1).await.unwrap();
        let flags = NgFlags::default();
        let two_stream = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "t=0 0\r\n",
            "m=audio 8000 RTP/AVP 0\r\n",
            "m=video 8002 RTP/AVP 96\r\n",
        )
        .as_bytes();
        let rewritten = client.offer("c2", "ft", two_stream, &flags).await.unwrap();
        let text = String::from_utf8(rewritten).unwrap();
        assert!(text.contains("m=audio 30000 RTP/AVP 0"), "sdp: {text}");
        assert!(text.contains("m=video 30002 RTP/AVP 96"), "sdp: {text}");

        let first = capture_rx.recv().await.unwrap();
        let second = capture_rx.recv().await.unwrap();
        assert_eq!(first, "U c2 10.0.0.1 8000 ft;1");
        assert_eq!(second, "U c2 10.0.0.1 8002 ft;2");
    }

    #[tokio::test]
    async fn held_media_at_port_zero_is_not_anchored() {
        // The mock replies to any U/L; if a command is sent for the port-0
        // stream the test would still pass, so assert the port stays 0.
        let address = spawn_mock_rtpproxy("203.0.113.1", 30000).await;
        let client = RtpProxyClient::new(address, 1000, 1).await.unwrap();
        let flags = NgFlags::default();
        let held = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "c=IN IP4 0.0.0.0\r\n",
            "t=0 0\r\n",
            "m=audio 0 RTP/AVP 0\r\n",
        )
        .as_bytes();
        let rewritten = client.offer("held", "ft", held, &flags).await.unwrap();
        let text = String::from_utf8(rewritten).unwrap();
        assert!(text.contains("m=audio 0 RTP/AVP 0"), "sdp: {text}");
        // No stream anchored → session c= left as-is.
        assert!(text.contains("c=IN IP4 0.0.0.0"), "sdp: {text}");
    }

    #[tokio::test]
    async fn delete_clears_session() {
        let address = spawn_mock_rtpproxy("203.0.113.1", 30000).await;
        let client = RtpProxyClient::new(address, 1000, 1).await.unwrap();
        let flags = NgFlags::default();
        client.offer("call-1", "ft", sample_offer_sdp(), &flags).await.unwrap();
        assert_eq!(client.active_sessions(), 1);
        client.delete("call-1", "ft").await.unwrap();
        assert_eq!(client.active_sessions(), 0);
    }

    #[tokio::test]
    async fn timeout_when_engine_silent() {
        // Bind but never reply.
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let silent_addr = silent.local_addr().unwrap();
        let _keep_alive = silent;
        let client = RtpProxyClient::new(silent_addr, 120, 2).await.unwrap();
        let result = client.ping().await;
        assert!(matches!(result, Err(RtpEngineError::Timeout { .. })));
    }

    /// The pending-correlation map MUST drain to empty after every command
    /// settles, on both the success and timeout paths — a leaked entry is one
    /// `oneshot::Sender` retained per command for the life of the process.
    #[tokio::test]
    async fn pending_map_drains_on_success() {
        let address = spawn_mock_rtpproxy("203.0.113.1", 30000).await;
        let client = RtpProxyClient::new(address, 1000, 1).await.unwrap();
        let flags = NgFlags::default();
        for index in 0..300 {
            let call_id = format!("leak-{index}");
            client.offer(&call_id, "ft", sample_offer_sdp(), &flags).await.unwrap();
            client.answer(&call_id, "ft", "tt", sample_offer_sdp(), &flags).await.unwrap();
            client.delete(&call_id, "ft").await.unwrap();
        }
        assert_eq!(
            client.pending.len(),
            0,
            "pending map must drain after completed commands"
        );
    }

    #[tokio::test]
    async fn pending_map_drains_on_timeout() {
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let silent_addr = silent.local_addr().unwrap();
        let _keep_alive = silent;
        let client = RtpProxyClient::new(silent_addr, 90, 2).await.unwrap();
        for _ in 0..15 {
            let result = client.ping().await;
            assert!(result.is_err());
        }
        assert_eq!(
            client.pending.len(),
            0,
            "pending map must drain on the timeout path too"
        );
    }

    #[tokio::test]
    async fn retransmit_succeeds_when_first_attempt_dropped() {
        // Mock that ignores the first datagram and answers the second (same
        // cookie). Exercises the retransmit path.
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buffer = BytesMut::zeroed(4096);
            let mut seen = 0;
            while let Ok((size, source)) = socket.recv_from(&mut buffer).await {
                seen += 1;
                if seen == 1 {
                    continue; // drop the first attempt
                }
                let data = &buffer[..size];
                let space = data.iter().position(|&b| b == b' ').unwrap();
                let cookie = std::str::from_utf8(&data[..space]).unwrap();
                let reply = format!("{cookie} 20040107");
                let _ = socket.send_to(reply.as_bytes(), source).await;
            }
        });
        // 3 attempts within ~300ms; first dropped, second answers.
        let client = RtpProxyClient::new(address, 300, 2).await.unwrap();
        client.ping().await.unwrap();
    }

    // -- set tests --

    #[tokio::test]
    async fn set_single_instance_offer_answer_delete() {
        let address = spawn_mock_rtpproxy("203.0.113.1", 30000).await;
        let set = RtpProxyClientSet::new(vec![(address, 1000, 1)], 1).await.unwrap();
        assert_eq!(set.instance_count(), 1);
        let flags = NgFlags::default();
        set.offer("c1", "ft", sample_offer_sdp(), &flags).await.unwrap();
        assert_eq!(set.active_sessions(), 1);
        set.answer("c1", "ft", "tt", sample_offer_sdp(), &flags).await.unwrap();
        set.delete("c1", "ft").await.unwrap();
        assert_eq!(set.active_sessions(), 0);
    }

    #[tokio::test]
    async fn set_call_id_affinity() {
        let address1 = spawn_mock_rtpproxy("203.0.113.1", 30000).await;
        let address2 = spawn_mock_rtpproxy("203.0.113.2", 31000).await;
        let set = RtpProxyClientSet::new(vec![(address1, 1000, 1), (address2, 1000, 1)], 1)
            .await
            .unwrap();
        let flags = NgFlags::default();
        set.offer("call-affinity", "ft", sample_offer_sdp(), &flags).await.unwrap();
        // One affinity entry recorded; total active sessions == 1.
        assert_eq!(set.active_sessions(), 1);
        set.delete("call-affinity", "ft").await.unwrap();
        assert_eq!(set.active_sessions(), 0);
    }

    #[tokio::test]
    async fn set_empty_rejected() {
        let result = RtpProxyClientSet::new(vec![], 1).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn set_unsupported_ops_error_clearly() {
        let address = spawn_mock_rtpproxy("203.0.113.1", 30000).await;
        let set = RtpProxyClientSet::new(vec![(address, 1000, 1)], 1).await.unwrap();
        let error = set.silence_media("c1", "ft").await.unwrap_err();
        assert!(matches!(error, RtpEngineError::EngineError(_)));
        assert!(error.to_string().contains("does not support"));
    }
}
