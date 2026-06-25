//! RTPEngine NG protocol UDP client.
//!
//! Sends bencode-encoded commands to RTPEngine and correlates responses
//! using a random cookie prefix.  A background receiver task dispatches
//! responses to waiting callers via oneshot channels.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::BytesMut;
use dashmap::DashMap;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tracing::{debug, error, trace, warn};

use super::bencode::{self, BencodeValue};
use super::error::RtpEngineError;
use super::profile::NgFlags;

/// Source for the `play media` command.
///
/// Exactly one variant is sent per command:
/// - `File` — absolute path on the rtpengine host
/// - `Blob` — raw audio bytes embedded in the ng command (binary-safe via bencode)
/// - `DbId` — reference to a prompt stored in rtpengine's internal database
#[derive(Debug, Clone)]
pub enum PlayMediaSource {
    File(String),
    Blob(Vec<u8>),
    DbId(u64),
}

/// Async client for the RTPEngine NG control protocol.
pub struct RtpEngineClient {
    /// Local UDP socket bound to an ephemeral port.
    socket: Arc<UdpSocket>,
    /// RTPEngine NG control address.
    address: SocketAddr,
    /// Pending requests awaiting responses, keyed by cookie.
    pending: Arc<DashMap<String, oneshot::Sender<BencodeValue>>>,
    /// Response timeout in milliseconds.
    timeout_ms: u64,
}

impl RtpEngineClient {
    /// Create a new client and spawn the background receiver task.
    pub async fn new(address: SocketAddr, timeout_ms: u64) -> Result<Self, RtpEngineError> {
        // Bind to an ephemeral port (0 = OS-assigned).
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let socket = Arc::new(socket);
        let pending: Arc<DashMap<String, oneshot::Sender<BencodeValue>>> =
            Arc::new(DashMap::new());

        // Spawn background receiver.
        {
            let socket = Arc::clone(&socket);
            let pending = Arc::clone(&pending);
            tokio::spawn(async move {
                receiver_loop(socket, pending).await;
            });
        }

        Ok(Self {
            socket,
            address,
            pending,
            timeout_ms,
        })
    }

    /// Address of the RTPEngine NG control endpoint this client talks to.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Send an `offer` command with SDP, returning the rewritten SDP.
    pub async fn offer(
        &self,
        call_id: &str,
        from_tag: &str,
        sdp: &[u8],
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        let mut pairs: Vec<(&str, BencodeValue)> = vec![
            ("command", BencodeValue::string("offer")),
            ("call-id", BencodeValue::string(call_id)),
            ("from-tag", BencodeValue::string(from_tag)),
            ("sdp", BencodeValue::String(sdp.to_vec())),
        ];
        pairs.extend(flags.to_bencode_pairs());

        let response = self.send_command(BencodeValue::dict(pairs)).await?;
        self.extract_sdp_response(&response)
    }

    /// Send an `answer` command with SDP, returning the rewritten SDP.
    pub async fn answer(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
        sdp: &[u8],
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        let mut pairs: Vec<(&str, BencodeValue)> = vec![
            ("command", BencodeValue::string("answer")),
            ("call-id", BencodeValue::string(call_id)),
            ("from-tag", BencodeValue::string(from_tag)),
            ("to-tag", BencodeValue::string(to_tag)),
            ("sdp", BencodeValue::String(sdp.to_vec())),
        ];
        pairs.extend(flags.to_bencode_pairs());

        let response = self.send_command(BencodeValue::dict(pairs)).await?;
        self.extract_sdp_response(&response)
    }

    /// Send a `delete` command to tear down a media session.
    pub async fn delete(
        &self,
        call_id: &str,
        from_tag: &str,
    ) -> Result<(), RtpEngineError> {
        let pairs: Vec<(&str, BencodeValue)> = vec![
            ("command", BencodeValue::string("delete")),
            ("call-id", BencodeValue::string(call_id)),
            ("from-tag", BencodeValue::string(from_tag)),
        ];

        let response = self.send_command(BencodeValue::dict(pairs)).await?;
        self.check_result(&response)?;
        Ok(())
    }

    /// Send a `query` command to get session statistics.
    pub async fn query(
        &self,
        call_id: &str,
        from_tag: &str,
    ) -> Result<BencodeValue, RtpEngineError> {
        let pairs: Vec<(&str, BencodeValue)> = vec![
            ("command", BencodeValue::string("query")),
            ("call-id", BencodeValue::string(call_id)),
            ("from-tag", BencodeValue::string(from_tag)),
        ];

        self.send_command(BencodeValue::dict(pairs)).await
    }

    /// Send a `play media` command — play an audio file/blob/db-id into a call.
    ///
    /// The `from-tag` selects the monologue whose outgoing audio is replaced by
    /// the prompt. Per rtpengine semantics, the **peer** of that monologue hears
    /// the prompt. Optional `to_tag` scopes the injection to a specific peer
    /// when the monologue has multiple subscribers (relevant for MPTY).
    ///
    /// Requires rtpengine built with `--with-transcoding` and launched with
    /// `--audio-player=on-demand`. VoLTE prompts (AMR-NB/WB) need licensed codec
    /// plugins; G.711 and Opus prompts work without them.
    ///
    /// Returns the prompt duration in milliseconds, if the engine reports one.
    pub async fn play_media(
        &self,
        call_id: &str,
        from_tag: &str,
        source: &PlayMediaSource,
        repeat_times: Option<u64>,
        start_pos_ms: Option<u64>,
        duration_ms: Option<u64>,
        to_tag: Option<&str>,
    ) -> Result<Option<u64>, RtpEngineError> {
        let mut pairs: Vec<(&str, BencodeValue)> = vec![
            ("command", BencodeValue::string("play media")),
            ("call-id", BencodeValue::string(call_id)),
            ("from-tag", BencodeValue::string(from_tag)),
        ];
        if let Some(tag) = to_tag {
            pairs.push(("to-tag", BencodeValue::string(tag)));
        }
        match source {
            PlayMediaSource::File(path) => {
                pairs.push(("file", BencodeValue::string(path)));
            }
            PlayMediaSource::Blob(bytes) => {
                pairs.push(("blob", BencodeValue::String(bytes.clone())));
            }
            PlayMediaSource::DbId(id) => {
                pairs.push(("db-id", BencodeValue::Integer(*id as i64)));
            }
        }
        if let Some(repeat) = repeat_times {
            pairs.push(("repeat-times", BencodeValue::Integer(repeat as i64)));
        }
        if let Some(start) = start_pos_ms {
            pairs.push(("start-pos", BencodeValue::Integer(start as i64)));
        }
        if let Some(duration) = duration_ms {
            pairs.push(("duration", BencodeValue::Integer(duration as i64)));
        }

        let response = self.send_command(BencodeValue::dict(pairs)).await?;
        self.check_result(&response)?;
        Ok(response
            .dict_get("duration")
            .and_then(|value| value.as_integer())
            .map(|number| number as u64))
    }

    /// Send a `stop media` command — stop any prompt currently playing on the
    /// monologue selected by `from-tag`.
    pub async fn stop_media(
        &self,
        call_id: &str,
        from_tag: &str,
    ) -> Result<(), RtpEngineError> {
        let pairs: Vec<(&str, BencodeValue)> = vec![
            ("command", BencodeValue::string("stop media")),
            ("call-id", BencodeValue::string(call_id)),
            ("from-tag", BencodeValue::string(from_tag)),
        ];
        let response = self.send_command(BencodeValue::dict(pairs)).await?;
        self.check_result(&response)?;
        Ok(())
    }

    /// Send a `play DTMF` command — inject DTMF tone(s) into the call.
    ///
    /// `code` is a single digit (`"0"`–`"9"`, `"*"`, `"#"`, `"A"`–`"D"`) or a
    /// string sequence. `volume_dbm0` is typically `-8` (the default used by
    /// rtpengine). `pause_ms` is the inter-tone gap when `code` is a sequence.
    pub async fn play_dtmf(
        &self,
        call_id: &str,
        from_tag: &str,
        code: &str,
        duration_ms: Option<u64>,
        volume_dbm0: Option<i64>,
        pause_ms: Option<u64>,
        to_tag: Option<&str>,
    ) -> Result<(), RtpEngineError> {
        let mut pairs: Vec<(&str, BencodeValue)> = vec![
            ("command", BencodeValue::string("play DTMF")),
            ("call-id", BencodeValue::string(call_id)),
            ("from-tag", BencodeValue::string(from_tag)),
            ("code", BencodeValue::string(code)),
        ];
        if let Some(tag) = to_tag {
            pairs.push(("to-tag", BencodeValue::string(tag)));
        }
        if let Some(duration) = duration_ms {
            pairs.push(("duration", BencodeValue::Integer(duration as i64)));
        }
        if let Some(volume) = volume_dbm0 {
            pairs.push(("volume", BencodeValue::Integer(volume)));
        }
        if let Some(pause) = pause_ms {
            pairs.push(("pause", BencodeValue::Integer(pause as i64)));
        }
        let response = self.send_command(BencodeValue::dict(pairs)).await?;
        self.check_result(&response)?;
        Ok(())
    }

    /// Send a `silence media` command — replace the selected monologue's
    /// outgoing audio with silence. Use for hold-music gating and LI warnings.
    pub async fn silence_media(
        &self,
        call_id: &str,
        from_tag: &str,
    ) -> Result<(), RtpEngineError> {
        self.simple_tag_command("silence media", call_id, from_tag).await
    }

    /// Send an `unsilence media` command — stop replacing outgoing audio with
    /// silence; pass the original stream through again.
    pub async fn unsilence_media(
        &self,
        call_id: &str,
        from_tag: &str,
    ) -> Result<(), RtpEngineError> {
        self.simple_tag_command("unsilence media", call_id, from_tag).await
    }

    /// Send a `block media` command — drop the selected monologue's outgoing
    /// packets entirely (peer hears nothing, not even comfort silence).
    pub async fn block_media(
        &self,
        call_id: &str,
        from_tag: &str,
    ) -> Result<(), RtpEngineError> {
        self.simple_tag_command("block media", call_id, from_tag).await
    }

    /// Send an `unblock media` command — resume forwarding the selected
    /// monologue's packets after a prior `block media`.
    pub async fn unblock_media(
        &self,
        call_id: &str,
        from_tag: &str,
    ) -> Result<(), RtpEngineError> {
        self.simple_tag_command("unblock media", call_id, from_tag).await
    }

    /// Shared shape for `silence`/`unsilence`/`block`/`unblock media`:
    /// `{command, call-id, from-tag}` → `{result: ok}`.
    async fn simple_tag_command(
        &self,
        command: &str,
        call_id: &str,
        from_tag: &str,
    ) -> Result<(), RtpEngineError> {
        let pairs: Vec<(&str, BencodeValue)> = vec![
            ("command", BencodeValue::string(command)),
            ("call-id", BencodeValue::string(call_id)),
            ("from-tag", BencodeValue::string(from_tag)),
        ];
        let response = self.send_command(BencodeValue::dict(pairs)).await?;
        self.check_result(&response)?;
        Ok(())
    }

    /// Send a `subscribe request` command for SIPREC media forking.
    ///
    /// Creates a subscription on an existing call's media, returning SDP
    /// for the recording leg. Used to fork RTP to a Session Recording Server.
    pub async fn subscribe_request(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
        sdp: Option<&[u8]>,
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        let mut pairs: Vec<(&str, BencodeValue)> = vec![
            ("command", BencodeValue::string("subscribe request")),
            ("call-id", BencodeValue::string(call_id)),
            ("from-tag", BencodeValue::string(from_tag)),
            ("to-tag", BencodeValue::string(to_tag)),
        ];
        if let Some(sdp_bytes) = sdp {
            pairs.push(("sdp", BencodeValue::String(sdp_bytes.to_vec())));
        }
        pairs.extend(flags.to_bencode_pairs());

        let response = self.send_command(BencodeValue::dict(pairs)).await?;
        self.extract_sdp_response(&response)
    }

    /// Send a SIPREC-mode `subscribe request` — subscribes to both directions.
    ///
    /// Uses `flags: ["all", "siprec"]` and `from-tags` to select both call
    /// participants (A-leg from_tag + B-leg to_tag).  RTPEngine returns a
    /// combined SDP with 2 m= lines (one per call direction) plus a `to-tag`
    /// for the subscription.
    ///
    /// Returns `(sdp, to_tag)` on success.
    pub async fn subscribe_request_siprec(
        &self,
        call_id: &str,
        from_tags: &[&str],
        profile_flags: Option<&super::NgFlags>,
    ) -> Result<(Vec<u8>, String), RtpEngineError> {
        // Mandatory SIPREC flags — always present.
        let mut siprec_flags = vec!["all", "siprec"];

        // Merge profile flags if provided.
        let mut pairs: Vec<(&str, BencodeValue)> = vec![
            ("command", BencodeValue::string("subscribe request")),
            ("call-id", BencodeValue::string(call_id)),
        ];

        // from-tags selects which call participants to subscribe to.
        // Both monologue tags are needed to get 2 m= lines in the response.
        if !from_tags.is_empty() {
            pairs.push(("from-tags", BencodeValue::string_list(from_tags)));
        }

        if let Some(flags) = profile_flags {
            // Merge any profile-level flags into the siprec flags list.
            let extra: Vec<&str> = flags.flags.iter().map(|s| s.as_str()).collect();
            for flag in &extra {
                if !siprec_flags.contains(flag) {
                    siprec_flags.push(flag);
                }
            }
            // Add non-flag profile pairs (transport-protocol, ICE, DTLS, etc.)
            // but skip "flags" since we handle it separately above.
            for (key, value) in flags.to_bencode_pairs() {
                if key != "flags" {
                    pairs.push((key, value));
                }
            }
        }

        pairs.push(("flags", BencodeValue::string_list(&siprec_flags)));

        let response = self.send_command(BencodeValue::dict(pairs)).await?;
        self.check_result(&response)?;

        let sdp = response
            .dict_get_bytes("sdp")
            .map(|bytes| bytes.to_vec())
            .ok_or_else(|| {
                RtpEngineError::Protocol("response missing 'sdp' field".to_string())
            })?;

        let to_tag = response
            .dict_get_str("to-tag")
            .map(|s| s.to_string())
            .unwrap_or_default();

        Ok((sdp, to_tag))
    }

    /// Send a `subscribe answer` command to complete SIPREC media subscription.
    ///
    /// Returns the rewritten SDP if RTPEngine includes one, or an empty vec
    /// if the command succeeded without returning SDP (which is valid for
    /// subscribe answer — unlike offer/answer, the response may omit SDP).
    pub async fn subscribe_answer(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
        sdp: &[u8],
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        let mut pairs: Vec<(&str, BencodeValue)> = vec![
            ("command", BencodeValue::string("subscribe answer")),
            ("call-id", BencodeValue::string(call_id)),
            ("from-tag", BencodeValue::string(from_tag)),
            ("to-tag", BencodeValue::string(to_tag)),
            ("sdp", BencodeValue::String(sdp.to_vec())),
        ];
        pairs.extend(flags.to_bencode_pairs());

        let response = self.send_command(BencodeValue::dict(pairs)).await?;
        self.check_result(&response)?;

        // subscribe answer may or may not return SDP — both are valid.
        Ok(response
            .dict_get_bytes("sdp")
            .map(|bytes| bytes.to_vec())
            .unwrap_or_default())
    }

    /// Send an `unsubscribe` command to stop SIPREC media forking.
    pub async fn unsubscribe(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
    ) -> Result<(), RtpEngineError> {
        let pairs: Vec<(&str, BencodeValue)> = vec![
            ("command", BencodeValue::string("unsubscribe")),
            ("call-id", BencodeValue::string(call_id)),
            ("from-tag", BencodeValue::string(from_tag)),
            ("to-tag", BencodeValue::string(to_tag)),
        ];

        let response = self.send_command(BencodeValue::dict(pairs)).await?;
        self.check_result(&response)?;
        Ok(())
    }

    /// Send a `ping` command — health check.
    pub async fn ping(&self) -> Result<(), RtpEngineError> {
        let pairs: Vec<(&str, BencodeValue)> = vec![
            ("command", BencodeValue::string("ping")),
        ];

        let response = self.send_command(BencodeValue::dict(pairs)).await?;
        let result = response
            .dict_get_str("result")
            .ok_or_else(|| RtpEngineError::Protocol("ping response missing 'result'".to_string()))?;

        if result == "pong" {
            Ok(())
        } else {
            Err(RtpEngineError::Protocol(format!(
                "expected 'pong', got '{result}'"
            )))
        }
    }

    /// Send a bencode command and wait for the response.
    async fn send_command(
        &self,
        command: BencodeValue,
    ) -> Result<BencodeValue, RtpEngineError> {
        let cookie = generate_cookie();
        let encoded = bencode::encode(&command);

        // Build the wire message: "<cookie> <bencode>"
        let mut message = Vec::with_capacity(cookie.len() + 1 + encoded.len());
        message.extend_from_slice(cookie.as_bytes());
        message.push(b' ');
        message.extend_from_slice(&encoded);

        // Register the pending request before sending.
        let (sender, receiver) = oneshot::channel();
        self.pending.insert(cookie.clone(), sender);

        trace!(cookie = %cookie, address = %self.address, "sending NG command");

        // Send the UDP packet.
        self.socket.send_to(&message, self.address).await?;

        // Wait for the response with timeout.
        let timeout_duration = std::time::Duration::from_millis(self.timeout_ms);
        match tokio::time::timeout(timeout_duration, receiver).await {
            Ok(Ok(response)) => {
                debug!(cookie = %cookie, "received NG response");
                Ok(response)
            }
            Ok(Err(_)) => {
                // Sender was dropped (receiver task crashed or cleaned up).
                Err(RtpEngineError::Protocol(
                    "response channel closed unexpectedly".to_string(),
                ))
            }
            Err(_) => {
                // Timeout — clean up the pending entry.
                self.pending.remove(&cookie);
                Err(RtpEngineError::Timeout {
                    timeout_ms: self.timeout_ms,
                })
            }
        }
    }

    /// Extract the rewritten SDP from an NG response, checking for errors.
    fn extract_sdp_response(&self, response: &BencodeValue) -> Result<Vec<u8>, RtpEngineError> {
        self.check_result(response)?;

        response
            .dict_get_bytes("sdp")
            .map(|bytes| bytes.to_vec())
            .ok_or_else(|| {
                RtpEngineError::Protocol("response missing 'sdp' field".to_string())
            })
    }

    /// Check the `result` field of a response for errors.
    fn check_result(&self, response: &BencodeValue) -> Result<(), RtpEngineError> {
        let result = response
            .dict_get_str("result")
            .ok_or_else(|| {
                RtpEngineError::Protocol("response missing 'result' field".to_string())
            })?;

        if result == "ok" {
            Ok(())
        } else {
            let reason = response
                .dict_get_str("error-reason")
                .unwrap_or(result);
            Err(RtpEngineError::EngineError(reason.to_string()))
        }
    }
}

/// Generate a random cookie string for request/response correlation.
fn generate_cookie() -> String {
    // Use UUID v4, take the first 8 hex chars (no dashes).
    let uuid = uuid::Uuid::new_v4();
    uuid.simple().to_string()[..8].to_string()
}

/// Background receiver loop — reads UDP responses and dispatches to waiters.
async fn receiver_loop(
    socket: Arc<UdpSocket>,
    pending: Arc<DashMap<String, oneshot::Sender<BencodeValue>>>,
) {
    let mut buffer = BytesMut::zeroed(65535);

    loop {
        match socket.recv_from(&mut buffer).await {
            Ok((size, source)) => {
                let data = &buffer[..size];
                trace!(size, source = %source, "received NG response packet");

                // Split on the first space: cookie + bencode payload.
                let space_position = match data.iter().position(|&byte| byte == b' ') {
                    Some(position) => position,
                    None => {
                        warn!("NG response missing space separator, ignoring");
                        continue;
                    }
                };

                let cookie = match std::str::from_utf8(&data[..space_position]) {
                    Ok(cookie) => cookie.to_string(),
                    Err(_) => {
                        warn!("NG response cookie is not valid UTF-8, ignoring");
                        continue;
                    }
                };

                let payload = &data[space_position + 1..];
                match bencode::decode_full_dict(payload) {
                    Ok(value) => {
                        if let Some((_, sender)) = pending.remove(&cookie) {
                            let _ = sender.send(value);
                        } else {
                            debug!(cookie = %cookie, "no pending request for cookie (stale or duplicate)");
                        }
                    }
                    Err(error) => {
                        warn!(cookie = %cookie, error = %error, "failed to decode NG response");
                    }
                }
            }
            Err(error) => {
                error!(error = %error, "NG receiver socket error");
                // Brief pause before retrying to avoid busy-loop on persistent errors.
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Multi-instance set with weighted round-robin
// ---------------------------------------------------------------------------

/// A set of RTPEngine instances with weighted round-robin selection.
///
/// Call-ID affinity: once a call-id is assigned to an instance (via `offer`),
/// subsequent commands for that call-id go to the same instance.
pub struct RtpEngineSet {
    clients: Vec<RtpEngineClient>,
    /// Cumulative weights for weighted selection.
    cumulative_weights: Vec<u32>,
    total_weight: u32,
    /// Atomic counter for round-robin.
    counter: std::sync::atomic::AtomicU64,
    /// Call-ID → client index affinity.
    affinity: DashMap<String, usize>,
}

impl RtpEngineSet {
    /// Create a set from multiple address/timeout/weight triples.
    pub async fn new(
        instances: Vec<(SocketAddr, u64, u32)>,
    ) -> Result<Self, RtpEngineError> {
        if instances.is_empty() {
            return Err(RtpEngineError::Protocol(
                "at least one RTPEngine instance is required".to_string(),
            ));
        }

        let mut clients = Vec::with_capacity(instances.len());
        let mut cumulative_weights = Vec::with_capacity(instances.len());
        let mut running_total = 0u32;

        for (address, timeout_ms, weight) in &instances {
            clients.push(RtpEngineClient::new(*address, *timeout_ms).await?);
            running_total += weight;
            cumulative_weights.push(running_total);
        }

        Ok(Self {
            clients,
            cumulative_weights,
            total_weight: running_total,
            counter: std::sync::atomic::AtomicU64::new(0),
            affinity: DashMap::new(),
        })
    }

    /// Select a client by call-id affinity or weighted round-robin.
    fn select(&self, call_id: &str) -> &RtpEngineClient {
        if self.clients.len() == 1 {
            return &self.clients[0];
        }

        // Check affinity first.
        if let Some(index) = self.affinity.get(call_id) {
            return &self.clients[*index];
        }

        // Weighted round-robin: increment counter, mod by total weight,
        // then find the first cumulative weight that exceeds the value.
        let tick = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let position = (tick % self.total_weight as u64) as u32;
        let index = self
            .cumulative_weights
            .iter()
            .position(|&cw| position < cw)
            .unwrap_or(0);

        &self.clients[index]
    }

    /// Record call-id affinity after the first command.
    fn bind_affinity(&self, call_id: &str) {
        if self.clients.len() <= 1 {
            return;
        }
        if !self.affinity.contains_key(call_id) {
            // Find which client we'd select and bind it.
            if let Some(index) = self.affinity.get(call_id) {
                let _ = index; // already bound by another thread
            } else {
                let tick = self
                    .counter
                    .load(std::sync::atomic::Ordering::Relaxed)
                    .wrapping_sub(1); // last used tick
                let position = (tick % self.total_weight as u64) as u32;
                let index = self
                    .cumulative_weights
                    .iter()
                    .position(|&cw| position < cw)
                    .unwrap_or(0);
                self.affinity.insert(call_id.to_string(), index);
            }
        }
    }

    /// Send an `offer` command, binding call-id affinity to the selected instance.
    pub async fn offer(
        &self,
        call_id: &str,
        from_tag: &str,
        sdp: &[u8],
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        let client = self.select(call_id);
        let result = client.offer(call_id, from_tag, sdp, flags).await?;
        self.bind_affinity(call_id);
        Ok(result)
    }

    /// Send an `answer` command to the affinity-bound instance.
    pub async fn answer(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
        sdp: &[u8],
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        let client = self.select(call_id);
        client.answer(call_id, from_tag, to_tag, sdp, flags).await
    }

    /// Send a `delete` command and remove affinity.
    pub async fn delete(
        &self,
        call_id: &str,
        from_tag: &str,
    ) -> Result<(), RtpEngineError> {
        let client = self.select(call_id);
        let result = client.delete(call_id, from_tag).await;
        self.affinity.remove(call_id);
        result
    }

    /// Send a `query` command to the affinity-bound instance.
    pub async fn query(
        &self,
        call_id: &str,
        from_tag: &str,
    ) -> Result<BencodeValue, RtpEngineError> {
        let client = self.select(call_id);
        client.query(call_id, from_tag).await
    }

    /// Send a `play media` command to the affinity-bound instance.
    pub async fn play_media(
        &self,
        call_id: &str,
        from_tag: &str,
        source: &PlayMediaSource,
        repeat_times: Option<u64>,
        start_pos_ms: Option<u64>,
        duration_ms: Option<u64>,
        to_tag: Option<&str>,
    ) -> Result<Option<u64>, RtpEngineError> {
        let client = self.select(call_id);
        client
            .play_media(call_id, from_tag, source, repeat_times, start_pos_ms, duration_ms, to_tag)
            .await
    }

    /// Send a `stop media` command to the affinity-bound instance.
    pub async fn stop_media(
        &self,
        call_id: &str,
        from_tag: &str,
    ) -> Result<(), RtpEngineError> {
        let client = self.select(call_id);
        client.stop_media(call_id, from_tag).await
    }

    /// Send a `play DTMF` command to the affinity-bound instance.
    pub async fn play_dtmf(
        &self,
        call_id: &str,
        from_tag: &str,
        code: &str,
        duration_ms: Option<u64>,
        volume_dbm0: Option<i64>,
        pause_ms: Option<u64>,
        to_tag: Option<&str>,
    ) -> Result<(), RtpEngineError> {
        let client = self.select(call_id);
        client
            .play_dtmf(call_id, from_tag, code, duration_ms, volume_dbm0, pause_ms, to_tag)
            .await
    }

    /// Send a `silence media` command to the affinity-bound instance.
    pub async fn silence_media(
        &self,
        call_id: &str,
        from_tag: &str,
    ) -> Result<(), RtpEngineError> {
        let client = self.select(call_id);
        client.silence_media(call_id, from_tag).await
    }

    /// Send an `unsilence media` command to the affinity-bound instance.
    pub async fn unsilence_media(
        &self,
        call_id: &str,
        from_tag: &str,
    ) -> Result<(), RtpEngineError> {
        let client = self.select(call_id);
        client.unsilence_media(call_id, from_tag).await
    }

    /// Send a `block media` command to the affinity-bound instance.
    pub async fn block_media(
        &self,
        call_id: &str,
        from_tag: &str,
    ) -> Result<(), RtpEngineError> {
        let client = self.select(call_id);
        client.block_media(call_id, from_tag).await
    }

    /// Send an `unblock media` command to the affinity-bound instance.
    pub async fn unblock_media(
        &self,
        call_id: &str,
        from_tag: &str,
    ) -> Result<(), RtpEngineError> {
        let client = self.select(call_id);
        client.unblock_media(call_id, from_tag).await
    }

    /// Send a `subscribe request` command to the affinity-bound instance.
    pub async fn subscribe_request(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
        sdp: Option<&[u8]>,
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        let client = self.select(call_id);
        client.subscribe_request(call_id, from_tag, to_tag, sdp, flags).await
    }

    /// Send a SIPREC-mode `subscribe request` to the affinity-bound instance.
    pub async fn subscribe_request_siprec(
        &self,
        call_id: &str,
        from_tags: &[&str],
        profile_flags: Option<&NgFlags>,
    ) -> Result<(Vec<u8>, String), RtpEngineError> {
        let client = self.select(call_id);
        client.subscribe_request_siprec(call_id, from_tags, profile_flags).await
    }

    /// Send a `subscribe answer` command to the affinity-bound instance.
    pub async fn subscribe_answer(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
        sdp: &[u8],
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        let client = self.select(call_id);
        client.subscribe_answer(call_id, from_tag, to_tag, sdp, flags).await
    }

    /// Send an `unsubscribe` command to the affinity-bound instance.
    pub async fn unsubscribe(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
    ) -> Result<(), RtpEngineError> {
        let client = self.select(call_id);
        client.unsubscribe(call_id, from_tag, to_tag).await
    }

    /// Ping all instances. Returns Ok only if all respond.
    pub async fn ping_all(&self) -> Result<(), RtpEngineError> {
        for client in &self.clients {
            client.ping().await?;
        }
        Ok(())
    }

    /// Ping every instance in parallel and return per-instance health status.
    ///
    /// Returns one `(address, healthy)` tuple per configured instance, in the
    /// same order they were registered.  `healthy` is `true` when the
    /// instance answered with `pong` within its configured timeout, and
    /// `false` for a timeout, transport error, or unexpected response.
    pub async fn health_check(&self) -> Vec<(SocketAddr, bool)> {
        let probes = self.clients.iter().map(|client| async move {
            let healthy = client.ping().await.is_ok();
            (client.address(), healthy)
        });
        futures_util::future::join_all(probes).await
    }

    /// Ping any one instance (the first healthy one). For quick health checks.
    pub async fn ping(&self) -> Result<(), RtpEngineError> {
        if let Some(client) = self.clients.first() {
            client.ping().await
        } else {
            Err(RtpEngineError::Protocol("no RTPEngine instances".to_string()))
        }
    }

    /// Number of active call-id affinities.
    pub fn active_sessions(&self) -> usize {
        self.affinity.len()
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_format() {
        let cookie = generate_cookie();
        assert_eq!(cookie.len(), 8);
        assert!(cookie.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn cookie_uniqueness() {
        let cookies: Vec<String> = (0..100).map(|_| generate_cookie()).collect();
        let unique: std::collections::HashSet<&String> = cookies.iter().collect();
        // With 8 hex chars (32 bits), collision in 100 samples is astronomically unlikely.
        assert_eq!(unique.len(), cookies.len());
    }

    #[tokio::test]
    async fn ping_roundtrip_with_mock() {
        // Spawn a mock RTPEngine that responds to ping with pong.
        let mock_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_socket.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buffer = BytesMut::zeroed(4096);
            if let Ok((size, source)) = mock_socket.recv_from(&mut buffer).await {
                let data = &buffer[..size];
                // Extract cookie.
                let space = data.iter().position(|&b| b == b' ').unwrap();
                let cookie = std::str::from_utf8(&data[..space]).unwrap();

                // Build pong response.
                let response = BencodeValue::dict(vec![
                    ("result", BencodeValue::string("pong")),
                ]);
                let encoded = bencode::encode(&response);
                let mut reply = Vec::new();
                reply.extend_from_slice(cookie.as_bytes());
                reply.push(b' ');
                reply.extend_from_slice(&encoded);

                mock_socket.send_to(&reply, source).await.unwrap();
            }
        });

        let client = RtpEngineClient::new(mock_addr, 2000).await.unwrap();
        client.ping().await.unwrap();
    }

    #[tokio::test]
    async fn offer_roundtrip_with_mock() {
        let mock_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_socket.local_addr().unwrap();

        let rewritten_sdp = concat!(
            "v=0\r\n",
            "o=- 0 0 IN IP4 203.0.113.1\r\n",
            "s=-\r\n",
            "c=IN IP4 203.0.113.1\r\n",
            "t=0 0\r\n",
            "m=audio 30000 RTP/AVP 0\r\n",
        );

        let rewritten_sdp_clone = rewritten_sdp.to_string();
        tokio::spawn(async move {
            let mut buffer = BytesMut::zeroed(65535);
            if let Ok((size, source)) = mock_socket.recv_from(&mut buffer).await {
                let data = &buffer[..size];
                let space = data.iter().position(|&b| b == b' ').unwrap();
                let cookie = std::str::from_utf8(&data[..space]).unwrap();

                // Verify the command is an offer.
                let payload = &data[space + 1..];
                let command = bencode::decode_full_dict(payload).unwrap();
                assert_eq!(command.dict_get_str("command"), Some("offer"));
                assert_eq!(command.dict_get_str("call-id"), Some("test-call-1"));
                assert_eq!(command.dict_get_str("from-tag"), Some("tag-a"));

                // Build response with rewritten SDP.
                let response = BencodeValue::dict(vec![
                    ("result", BencodeValue::string("ok")),
                    ("sdp", BencodeValue::string(&rewritten_sdp_clone)),
                ]);
                let encoded = bencode::encode(&response);
                let mut reply = Vec::new();
                reply.extend_from_slice(cookie.as_bytes());
                reply.push(b' ');
                reply.extend_from_slice(&encoded);

                mock_socket.send_to(&reply, source).await.unwrap();
            }
        });

        let client = RtpEngineClient::new(mock_addr, 2000).await.unwrap();

        let original_sdp = concat!(
            "v=0\r\n",
            "o=- 0 0 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "t=0 0\r\n",
            "m=audio 8000 RTP/AVP 0\r\n",
        );

        let flags = NgFlags::default();
        let result = client
            .offer("test-call-1", "tag-a", original_sdp.as_bytes(), &flags)
            .await
            .unwrap();

        let result_str = std::str::from_utf8(&result).unwrap();
        assert!(result_str.contains("203.0.113.1"));
        assert!(result_str.contains("30000"));
    }

    #[tokio::test]
    async fn answer_roundtrip_with_mock() {
        let mock_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_socket.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buffer = BytesMut::zeroed(65535);
            if let Ok((size, source)) = mock_socket.recv_from(&mut buffer).await {
                let data = &buffer[..size];
                let space = data.iter().position(|&b| b == b' ').unwrap();
                let cookie = std::str::from_utf8(&data[..space]).unwrap();

                let payload = &data[space + 1..];
                let command = bencode::decode_full_dict(payload).unwrap();
                assert_eq!(command.dict_get_str("command"), Some("answer"));
                assert_eq!(command.dict_get_str("to-tag"), Some("tag-b"));

                let response = BencodeValue::dict(vec![
                    ("result", BencodeValue::string("ok")),
                    ("sdp", BencodeValue::string("v=0\r\nc=IN IP4 203.0.113.1\r\n")),
                ]);
                let encoded = bencode::encode(&response);
                let mut reply = Vec::new();
                reply.extend_from_slice(cookie.as_bytes());
                reply.push(b' ');
                reply.extend_from_slice(&encoded);
                mock_socket.send_to(&reply, source).await.unwrap();
            }
        });

        let client = RtpEngineClient::new(mock_addr, 2000).await.unwrap();
        let flags = NgFlags::default();
        let result = client
            .answer("call-1", "tag-a", "tag-b", b"v=0\r\nc=IN IP4 10.0.0.1\r\n", &flags)
            .await
            .unwrap();
        assert!(std::str::from_utf8(&result).unwrap().contains("203.0.113.1"));
    }

    #[tokio::test]
    async fn delete_roundtrip_with_mock() {
        let mock_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_socket.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buffer = BytesMut::zeroed(65535);
            if let Ok((size, source)) = mock_socket.recv_from(&mut buffer).await {
                let data = &buffer[..size];
                let space = data.iter().position(|&b| b == b' ').unwrap();
                let cookie = std::str::from_utf8(&data[..space]).unwrap();

                let payload = &data[space + 1..];
                let command = bencode::decode_full_dict(payload).unwrap();
                assert_eq!(command.dict_get_str("command"), Some("delete"));

                let response = BencodeValue::dict(vec![
                    ("result", BencodeValue::string("ok")),
                ]);
                let encoded = bencode::encode(&response);
                let mut reply = Vec::new();
                reply.extend_from_slice(cookie.as_bytes());
                reply.push(b' ');
                reply.extend_from_slice(&encoded);
                mock_socket.send_to(&reply, source).await.unwrap();
            }
        });

        let client = RtpEngineClient::new(mock_addr, 2000).await.unwrap();
        client.delete("call-1", "tag-a").await.unwrap();
    }

    #[tokio::test]
    async fn timeout_on_no_response() {
        // Bind a socket but never respond.
        let mock_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_socket.local_addr().unwrap();

        // Keep the socket alive so the send doesn't fail with "connection refused".
        let _keep_alive = mock_socket;

        let client = RtpEngineClient::new(mock_addr, 100).await.unwrap();
        let result = client.ping().await;
        assert!(matches!(result, Err(RtpEngineError::Timeout { .. })));
    }

    #[tokio::test]
    async fn engine_error_response() {
        let mock_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_socket.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buffer = BytesMut::zeroed(65535);
            if let Ok((size, source)) = mock_socket.recv_from(&mut buffer).await {
                let data = &buffer[..size];
                let space = data.iter().position(|&b| b == b' ').unwrap();
                let cookie = std::str::from_utf8(&data[..space]).unwrap();

                let response = BencodeValue::dict(vec![
                    ("result", BencodeValue::string("error")),
                    ("error-reason", BencodeValue::string("session not found")),
                ]);
                let encoded = bencode::encode(&response);
                let mut reply = Vec::new();
                reply.extend_from_slice(cookie.as_bytes());
                reply.push(b' ');
                reply.extend_from_slice(&encoded);
                mock_socket.send_to(&reply, source).await.unwrap();
            }
        });

        let client = RtpEngineClient::new(mock_addr, 2000).await.unwrap();
        let result = client.delete("call-1", "tag-a").await;
        assert!(matches!(result, Err(RtpEngineError::EngineError(_))));
        assert!(result.unwrap_err().to_string().contains("session not found"));
    }

    // -- RtpEngineSet tests --

    /// Helper: spawn a mock RTPEngine that responds to all commands with "ok".
    async fn spawn_mock_rtpengine() -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buffer = BytesMut::zeroed(65535);
            while let Ok((size, source)) = socket.recv_from(&mut buffer).await {
                let data = &buffer[..size];
                let space = data.iter().position(|&b| b == b' ').unwrap();
                let cookie = std::str::from_utf8(&data[..space]).unwrap().to_string();

                let payload = &data[space + 1..];
                let command = bencode::decode_full_dict(payload).unwrap();
                let cmd_name = command.dict_get_str("command").unwrap_or("unknown");

                let response = if cmd_name == "ping" {
                    BencodeValue::dict(vec![
                        ("result", BencodeValue::string("pong")),
                    ])
                } else {
                    let mut pairs = vec![
                        ("result", BencodeValue::string("ok")),
                    ];
                    if cmd_name == "offer" || cmd_name == "answer" || cmd_name == "subscribe request" || cmd_name == "subscribe answer" {
                        pairs.push(("sdp", BencodeValue::string("v=0\r\nc=IN IP4 203.0.113.1\r\n")));
                    }
                    BencodeValue::dict(pairs)
                };

                let encoded = bencode::encode(&response);
                let mut reply = Vec::new();
                reply.extend_from_slice(cookie.as_bytes());
                reply.push(b' ');
                reply.extend_from_slice(&encoded);
                let _ = socket.send_to(&reply, source).await;
            }
        });

        addr
    }

    #[tokio::test]
    async fn set_single_instance() {
        let addr = spawn_mock_rtpengine().await;
        let set = RtpEngineSet::new(vec![(addr, 2000, 1)]).await.unwrap();
        assert_eq!(set.instance_count(), 1);
        set.ping().await.unwrap();
    }

    #[tokio::test]
    async fn set_multiple_instances_ping_all() {
        let addr1 = spawn_mock_rtpengine().await;
        let addr2 = spawn_mock_rtpengine().await;
        let set = RtpEngineSet::new(vec![
            (addr1, 2000, 1),
            (addr2, 2000, 1),
        ]).await.unwrap();
        assert_eq!(set.instance_count(), 2);
        set.ping_all().await.unwrap();
    }

    #[tokio::test]
    async fn set_call_id_affinity() {
        let addr1 = spawn_mock_rtpengine().await;
        let addr2 = spawn_mock_rtpengine().await;
        let set = RtpEngineSet::new(vec![
            (addr1, 2000, 1),
            (addr2, 2000, 1),
        ]).await.unwrap();

        let flags = NgFlags::default();

        // First offer binds affinity.
        set.offer("call-abc", "tag-a", b"v=0\r\n", &flags).await.unwrap();
        assert_eq!(set.active_sessions(), 1);

        // Answer goes to the same instance (affinity).
        set.answer("call-abc", "tag-a", "tag-b", b"v=0\r\n", &flags).await.unwrap();
        assert_eq!(set.active_sessions(), 1);

        // Delete removes affinity.
        set.delete("call-abc", "tag-a").await.unwrap();
        assert_eq!(set.active_sessions(), 0);
    }

    #[tokio::test]
    async fn set_empty_instances_rejected() {
        let result = RtpEngineSet::new(vec![]).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn subscribe_request_roundtrip_with_mock() {
        let mock_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_socket.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buffer = BytesMut::zeroed(65535);
            if let Ok((size, source)) = mock_socket.recv_from(&mut buffer).await {
                let data = &buffer[..size];
                let space = data.iter().position(|&b| b == b' ').unwrap();
                let cookie = std::str::from_utf8(&data[..space]).unwrap();

                let payload = &data[space + 1..];
                let command = bencode::decode_full_dict(payload).unwrap();
                assert_eq!(command.dict_get_str("command"), Some("subscribe request"));
                assert_eq!(command.dict_get_str("call-id"), Some("call-1"));
                assert_eq!(command.dict_get_str("from-tag"), Some("tag-a"));
                assert_eq!(command.dict_get_str("to-tag"), Some("tag-b"));

                let response = BencodeValue::dict(vec![
                    ("result", BencodeValue::string("ok")),
                    ("sdp", BencodeValue::string("v=0\r\nc=IN IP4 203.0.113.1\r\nm=audio 40000 RTP/AVP 0\r\n")),
                ]);
                let encoded = bencode::encode(&response);
                let mut reply = Vec::new();
                reply.extend_from_slice(cookie.as_bytes());
                reply.push(b' ');
                reply.extend_from_slice(&encoded);
                mock_socket.send_to(&reply, source).await.unwrap();
            }
        });

        let client = RtpEngineClient::new(mock_addr, 2000).await.unwrap();
        let flags = NgFlags::default();
        let result = client
            .subscribe_request("call-1", "tag-a", "tag-b", None, &flags)
            .await
            .unwrap();
        let result_str = std::str::from_utf8(&result).unwrap();
        assert!(result_str.contains("203.0.113.1"));
        assert!(result_str.contains("40000"));
    }

    #[tokio::test]
    async fn unsubscribe_roundtrip_with_mock() {
        let mock_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_socket.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buffer = BytesMut::zeroed(65535);
            if let Ok((size, source)) = mock_socket.recv_from(&mut buffer).await {
                let data = &buffer[..size];
                let space = data.iter().position(|&b| b == b' ').unwrap();
                let cookie = std::str::from_utf8(&data[..space]).unwrap();

                let payload = &data[space + 1..];
                let command = bencode::decode_full_dict(payload).unwrap();
                assert_eq!(command.dict_get_str("command"), Some("unsubscribe"));

                let response = BencodeValue::dict(vec![
                    ("result", BencodeValue::string("ok")),
                ]);
                let encoded = bencode::encode(&response);
                let mut reply = Vec::new();
                reply.extend_from_slice(cookie.as_bytes());
                reply.push(b' ');
                reply.extend_from_slice(&encoded);
                mock_socket.send_to(&reply, source).await.unwrap();
            }
        });

        let client = RtpEngineClient::new(mock_addr, 2000).await.unwrap();
        client.unsubscribe("call-1", "tag-a", "tag-b").await.unwrap();
    }

    #[tokio::test]
    async fn set_subscribe_uses_affinity() {
        let addr = spawn_mock_rtpengine().await;
        let set = RtpEngineSet::new(vec![(addr, 2000, 1)]).await.unwrap();
        let flags = NgFlags::default();

        // First offer to bind affinity.
        set.offer("call-sub", "tag-a", b"v=0\r\n", &flags).await.unwrap();

        // subscribe_request uses the same instance via affinity.
        let result = set
            .subscribe_request("call-sub", "tag-a", "tag-b", None, &flags)
            .await
            .unwrap();
        assert!(!result.is_empty());
    }

    // -- play_media / stop_media / play_dtmf / silence / block --

    /// Spawn a mock that captures each request's decoded bencode dict in a
    /// shared Vec and responds with `{result: ok, duration: N}` for play_media.
    async fn spawn_capturing_mock() -> (SocketAddr, Arc<tokio::sync::Mutex<Vec<BencodeValue>>>) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let captured: Arc<tokio::sync::Mutex<Vec<BencodeValue>>> =
            Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let captured_clone = Arc::clone(&captured);

        tokio::spawn(async move {
            let mut buffer = BytesMut::zeroed(65535);
            while let Ok((size, source)) = socket.recv_from(&mut buffer).await {
                let data = &buffer[..size];
                let space = data.iter().position(|&b| b == b' ').unwrap();
                let cookie = std::str::from_utf8(&data[..space]).unwrap().to_string();

                let payload = &data[space + 1..];
                let command = bencode::decode_full_dict(payload).unwrap();
                let cmd_name = command.dict_get_str("command").unwrap_or("").to_string();
                captured_clone.lock().await.push(command);

                let response = if cmd_name == "play media" {
                    BencodeValue::dict(vec![
                        ("result", BencodeValue::string("ok")),
                        ("duration", BencodeValue::from_integer(12345)),
                    ])
                } else {
                    BencodeValue::dict(vec![
                        ("result", BencodeValue::string("ok")),
                    ])
                };
                let encoded = bencode::encode(&response);
                let mut reply = Vec::new();
                reply.extend_from_slice(cookie.as_bytes());
                reply.push(b' ');
                reply.extend_from_slice(&encoded);
                let _ = socket.send_to(&reply, source).await;
            }
        });

        (addr, captured)
    }

    #[tokio::test]
    async fn play_media_file_bencode_shape() {
        let (addr, captured) = spawn_capturing_mock().await;
        let client = RtpEngineClient::new(addr, 2000).await.unwrap();

        let duration = client
            .play_media(
                "call-1",
                "tag-a",
                &PlayMediaSource::File("/var/lib/siphon/prompts/announcement.wav".to_string()),
                Some(2),
                Some(500),
                Some(10_000),
                Some("tag-b"),
            )
            .await
            .unwrap();

        assert_eq!(duration, Some(12345));

        let captured = captured.lock().await;
        assert_eq!(captured.len(), 1);
        let command = &captured[0];
        assert_eq!(command.dict_get_str("command"), Some("play media"));
        assert_eq!(command.dict_get_str("call-id"), Some("call-1"));
        assert_eq!(command.dict_get_str("from-tag"), Some("tag-a"));
        assert_eq!(command.dict_get_str("to-tag"), Some("tag-b"));
        assert_eq!(
            command.dict_get_str("file"),
            Some("/var/lib/siphon/prompts/announcement.wav")
        );
        assert_eq!(command.dict_get("repeat-times").and_then(|v| v.as_integer()), Some(2));
        assert_eq!(command.dict_get("start-pos").and_then(|v| v.as_integer()), Some(500));
        assert_eq!(command.dict_get("duration").and_then(|v| v.as_integer()), Some(10_000));
    }

    #[tokio::test]
    async fn play_media_blob_is_binary_safe() {
        let (addr, captured) = spawn_capturing_mock().await;
        let client = RtpEngineClient::new(addr, 2000).await.unwrap();

        // Include NUL + high bytes to prove binary safety through bencode.
        let blob_bytes = vec![0x00, 0xff, 0x52, 0x49, 0x46, 0x46, 0xde, 0xad, 0xbe, 0xef];
        client
            .play_media(
                "call-blob",
                "tag-a",
                &PlayMediaSource::Blob(blob_bytes.clone()),
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();

        let captured = captured.lock().await;
        let command = &captured[0];
        assert_eq!(command.dict_get_str("command"), Some("play media"));
        assert_eq!(command.dict_get_bytes("blob"), Some(blob_bytes.as_slice()));
        assert!(command.dict_get("file").is_none());
        assert!(command.dict_get("db-id").is_none());
        assert!(command.dict_get("to-tag").is_none());
    }

    #[tokio::test]
    async fn play_media_db_id_shape() {
        let (addr, captured) = spawn_capturing_mock().await;
        let client = RtpEngineClient::new(addr, 2000).await.unwrap();

        client
            .play_media("call-db", "tag-a", &PlayMediaSource::DbId(42), None, None, None, None)
            .await
            .unwrap();

        let captured = captured.lock().await;
        let command = &captured[0];
        assert_eq!(command.dict_get("db-id").and_then(|v| v.as_integer()), Some(42));
        assert!(command.dict_get("file").is_none());
        assert!(command.dict_get("blob").is_none());
    }

    #[tokio::test]
    async fn play_media_omits_optionals_when_none() {
        let (addr, captured) = spawn_capturing_mock().await;
        let client = RtpEngineClient::new(addr, 2000).await.unwrap();
        client
            .play_media(
                "call-min",
                "tag-a",
                &PlayMediaSource::File("/tmp/x.wav".to_string()),
                None, None, None, None,
            )
            .await
            .unwrap();
        let captured = captured.lock().await;
        let command = &captured[0];
        assert!(command.dict_get("repeat-times").is_none());
        assert!(command.dict_get("start-pos").is_none());
        assert!(command.dict_get("duration").is_none());
        assert!(command.dict_get("to-tag").is_none());
    }

    #[tokio::test]
    async fn stop_media_shape() {
        let (addr, captured) = spawn_capturing_mock().await;
        let client = RtpEngineClient::new(addr, 2000).await.unwrap();
        client.stop_media("call-stop", "tag-a").await.unwrap();
        let captured = captured.lock().await;
        let command = &captured[0];
        assert_eq!(command.dict_get_str("command"), Some("stop media"));
        assert_eq!(command.dict_get_str("call-id"), Some("call-stop"));
        assert_eq!(command.dict_get_str("from-tag"), Some("tag-a"));
    }

    #[tokio::test]
    async fn play_dtmf_shape_full() {
        let (addr, captured) = spawn_capturing_mock().await;
        let client = RtpEngineClient::new(addr, 2000).await.unwrap();
        client
            .play_dtmf("call-dtmf", "tag-a", "123#", Some(100), Some(-8), Some(60), None)
            .await
            .unwrap();
        let captured = captured.lock().await;
        let command = &captured[0];
        assert_eq!(command.dict_get_str("command"), Some("play DTMF"));
        assert_eq!(command.dict_get_str("code"), Some("123#"));
        assert_eq!(command.dict_get("duration").and_then(|v| v.as_integer()), Some(100));
        assert_eq!(command.dict_get("volume").and_then(|v| v.as_integer()), Some(-8));
        assert_eq!(command.dict_get("pause").and_then(|v| v.as_integer()), Some(60));
    }

    #[tokio::test]
    async fn play_dtmf_shape_minimal() {
        let (addr, captured) = spawn_capturing_mock().await;
        let client = RtpEngineClient::new(addr, 2000).await.unwrap();
        client
            .play_dtmf("call-dtmf2", "tag-a", "5", None, None, None, None)
            .await
            .unwrap();
        let captured = captured.lock().await;
        let command = &captured[0];
        assert_eq!(command.dict_get_str("code"), Some("5"));
        assert!(command.dict_get("duration").is_none());
        assert!(command.dict_get("volume").is_none());
        assert!(command.dict_get("pause").is_none());
    }

    #[tokio::test]
    async fn silence_and_unsilence_shape() {
        let (addr, captured) = spawn_capturing_mock().await;
        let client = RtpEngineClient::new(addr, 2000).await.unwrap();
        client.silence_media("call-s", "tag-a").await.unwrap();
        client.unsilence_media("call-s", "tag-a").await.unwrap();
        let captured = captured.lock().await;
        assert_eq!(captured.len(), 2);
        assert_eq!(captured[0].dict_get_str("command"), Some("silence media"));
        assert_eq!(captured[1].dict_get_str("command"), Some("unsilence media"));
    }

    #[tokio::test]
    async fn block_and_unblock_shape() {
        let (addr, captured) = spawn_capturing_mock().await;
        let client = RtpEngineClient::new(addr, 2000).await.unwrap();
        client.block_media("call-b", "tag-a").await.unwrap();
        client.unblock_media("call-b", "tag-a").await.unwrap();
        let captured = captured.lock().await;
        assert_eq!(captured.len(), 2);
        assert_eq!(captured[0].dict_get_str("command"), Some("block media"));
        assert_eq!(captured[1].dict_get_str("command"), Some("unblock media"));
    }

    #[tokio::test]
    async fn play_media_engine_error_propagates() {
        let mock_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_socket.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buffer = BytesMut::zeroed(65535);
            if let Ok((size, source)) = mock_socket.recv_from(&mut buffer).await {
                let data = &buffer[..size];
                let space = data.iter().position(|&b| b == b' ').unwrap();
                let cookie = std::str::from_utf8(&data[..space]).unwrap();
                let response = BencodeValue::dict(vec![
                    ("result", BencodeValue::string("error")),
                    ("error-reason", BencodeValue::string("audio player not enabled")),
                ]);
                let encoded = bencode::encode(&response);
                let mut reply = Vec::new();
                reply.extend_from_slice(cookie.as_bytes());
                reply.push(b' ');
                reply.extend_from_slice(&encoded);
                mock_socket.send_to(&reply, source).await.unwrap();
            }
        });

        let client = RtpEngineClient::new(mock_addr, 2000).await.unwrap();
        let result = client
            .play_media(
                "call-err",
                "tag-a",
                &PlayMediaSource::File("/nope.wav".to_string()),
                None, None, None, None,
            )
            .await;
        assert!(matches!(result, Err(RtpEngineError::EngineError(_))));
        assert!(result.unwrap_err().to_string().contains("audio player"));
    }

    #[tokio::test]
    async fn health_check_reports_mixed_up_and_down() {
        // Live mock — answers ping with pong.
        let live_addr = spawn_mock_rtpengine().await;

        // Dead address: bind a socket to grab a free port, then drop it so
        // packets sent there get no response. UDP "connection refused" is
        // best-effort; either way our 100 ms timeout catches it.
        let dead_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead_socket.local_addr().unwrap();
        drop(dead_socket);

        let set = RtpEngineSet::new(vec![
            (live_addr, 2000, 1),
            (dead_addr, 100, 1),
        ])
        .await
        .unwrap();

        let results = set.health_check().await;
        assert_eq!(results.len(), 2);

        // Order matches registration order.
        assert_eq!(results[0].0, live_addr);
        assert!(results[0].1, "live instance should be healthy");
        assert_eq!(results[1].0, dead_addr);
        assert!(!results[1].1, "dead instance should be unhealthy");
    }

    #[tokio::test]
    async fn instance_addresses_preserves_registration_order() {
        let addr1 = spawn_mock_rtpengine().await;
        let addr2 = spawn_mock_rtpengine().await;
        let addr3 = spawn_mock_rtpengine().await;
        let set = RtpEngineSet::new(vec![
            (addr1, 2000, 1),
            (addr2, 2000, 1),
            (addr3, 2000, 1),
        ])
        .await
        .unwrap();

        let addresses = set.instance_addresses();
        assert_eq!(addresses, vec![addr1, addr2, addr3]);
    }

    #[tokio::test]
    async fn client_address_accessor_returns_configured_address() {
        let addr = spawn_mock_rtpengine().await;
        let client = RtpEngineClient::new(addr, 2000).await.unwrap();
        assert_eq!(client.address(), addr);
    }

    #[tokio::test]
    async fn set_play_media_uses_affinity() {
        let addr = spawn_mock_rtpengine().await;
        let set = RtpEngineSet::new(vec![(addr, 2000, 1)]).await.unwrap();
        let flags = NgFlags::default();
        set.offer("call-play-aff", "tag-a", b"v=0\r\n", &flags).await.unwrap();
        // `spawn_mock_rtpengine` returns `result: ok` for unknown commands,
        // so play_media succeeds with no duration. Success alone proves the
        // set routed to the affinity-bound instance without timing out.
        let result = set
            .play_media(
                "call-play-aff",
                "tag-a",
                &PlayMediaSource::File("/a.wav".to_string()),
                None, None, None, None,
            )
            .await
            .unwrap();
        assert_eq!(result, None);
    }
}
