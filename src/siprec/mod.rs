//! SIPREC — SIP-based Recording (RFC 7866).
//!
//! Manages recording sessions that fork media to a Session Recording Server (SRS).
//! When a B2BUA call is recorded, SIPhon sends an INVITE to the SRS with:
//! - Part 1: SDP (a=sendonly, SRC sends forked media to SRS)
//! - Part 2: RFC 7866 recording metadata XML

pub mod metadata;
pub mod multipart;

use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};

use dashmap::DashMap;
use tracing::{debug, info, warn};

use crate::sip::builder::SipMessageBuilder;
use crate::sip::message::{Method, SipMessage};
use crate::sip::uri::SipUri;
use crate::transport::Transport;

/// Fallback destination when SRS URI cannot be parsed to a socket address.
const FALLBACK_DESTINATION: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
    5060,
);

/// State of a recording session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordingState {
    /// INVITE sent to SRS, waiting for response.
    Pending,
    /// SRS answered (200 OK), recording active.
    Active,
    /// BYE sent to SRS, recording stopped.
    Stopped,
    /// Recording failed (SRS rejected or error).
    Failed,
}

impl fmt::Display for RecordingState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(formatter, "pending"),
            Self::Active => write!(formatter, "active"),
            Self::Stopped => write!(formatter, "stopped"),
            Self::Failed => write!(formatter, "failed"),
        }
    }
}

/// A single recording session.
#[derive(Debug)]
pub struct RecordingSession {
    /// Recording session ID (UUID).
    pub session_id: String,
    /// The B2BUA call ID this recording belongs to.
    pub call_id: String,
    /// SRS URI (e.g. "sip:srs@recorder.example.com").
    pub srs_uri: String,
    /// Current state.
    pub state: RecordingState,
    /// SIP Call-ID for the recording INVITE dialog.
    pub sip_call_id: String,
    /// Branch used for the recording INVITE.
    pub branch: String,
    /// CSeq number used in the original INVITE (needed for ACK).
    pub invite_cseq: u32,
    /// CSeq counter for this recording dialog.
    pub cseq: AtomicU32,
    /// From-tag for this recording dialog.
    pub from_tag: String,
    /// To-tag from the SRS 200 OK (set after answer).
    pub to_tag: Option<String>,
    /// Original call's SIP Call-ID (for RTPEngine subscribe correlation).
    pub original_sip_call_id: Option<String>,
    /// Original call's From-tag (for RTPEngine subscribe correlation).
    pub original_from_tag: Option<String>,
    /// Original call's To-tag (for RTPEngine subscribe correlation).
    pub original_to_tag: Option<String>,
    /// When this recording session was created.  Used by the orphan
    /// backstop sweep ([`RecordingManager::sweep_stale`]) to reap sessions
    /// whose call ended without `stop_recording` ever firing.  Normal
    /// recordings are cleaned on BYE; this only catches orphans.
    pub created_at: std::time::Instant,
}

/// Manages all active recording sessions.
#[derive(Debug)]
pub struct RecordingManager {
    /// session_id -> RecordingSession
    sessions: DashMap<String, RecordingSession>,
    /// call_id -> list of session_ids (a call can have multiple recordings)
    call_sessions: DashMap<String, Vec<String>>,
    /// branch -> session_id (for routing SRS responses)
    branch_to_session: DashMap<String, String>,
    /// CSeq counter for recording INVITEs.
    cseq_counter: AtomicU32,
    /// Default User-Agent value for recording INVITEs when the caller does
    /// not pass one. Sourced from `SiphonServer::product()`.
    default_user_agent: String,
}

impl RecordingManager {
    pub fn new(product_name: &str, product_version: &str) -> Self {
        Self {
            sessions: DashMap::new(),
            call_sessions: DashMap::new(),
            branch_to_session: DashMap::new(),
            cseq_counter: AtomicU32::new(1),
            default_user_agent: format!("{product_name}/{product_version}"),
        }
    }

    /// Start recording a call by sending INVITE to SRS.
    ///
    /// `caller_sdp` and `callee_sdp` are optional per-direction SDPs from
    /// RTPEngine subscribe_request (caller's audio = label 0, callee's = label 1).
    /// If both are provided, the INVITE carries 2 m= lines (RFC 7866 §4).
    /// If only one or neither is available, falls back to a single m= line
    /// built from the call's original SDP.
    ///
    /// Returns the recording session ID and the SIP message to send.
    pub fn start_recording(
        &self,
        call_id: &str,
        srs_uri: &str,
        caller_uri: &str,
        callee_uri: &str,
        sdp: &[u8],
        local_addr: SocketAddr,
        caller_sdp: Option<&[u8]>,
        callee_sdp: Option<&[u8]>,
        original_sip_call_id: Option<&str>,
        original_tags: Option<(&str, &str)>,
        user_agent: Option<&str>,
    ) -> Option<(String, SipMessage, SocketAddr, Transport)> {
        let session_id = uuid::Uuid::new_v4().to_string();
        let sip_call_id = format!("siprec-{}", uuid::Uuid::new_v4());
        let branch = format!("z9hG4bK-rec-{}", uuid::Uuid::new_v4());
        let from_tag = format!("rec-{}", &session_id[..8]);
        let cseq = self.cseq_counter.fetch_add(1, Ordering::Relaxed);

        // Parse SRS URI properly — extract host, port, transport, and URI params.
        // Example: "sip:srs@10.0.0.5:5080;transport=TCP"
        //   -> host="10.0.0.5", port=5080, transport=TCP
        let srs_host_part = srs_uri
            .strip_prefix("sip:")
            .or_else(|| srs_uri.strip_prefix("sips:"))
            .unwrap_or(srs_uri);
        // Strip user@ if present (e.g. "srs@10.0.0.5:5060" -> "10.0.0.5:5060")
        let srs_host_with_params = if let Some(at_pos) = srs_host_part.find('@') {
            &srs_host_part[at_pos + 1..]
        } else {
            srs_host_part
        };

        // Split host:port from URI parameters (;transport=TCP, etc.)
        let (srs_hostport, uri_params) = match srs_host_with_params.find(';') {
            Some(pos) => (&srs_host_with_params[..pos], &srs_host_with_params[pos..]),
            None => (srs_host_with_params, ""),
        };

        // Detect transport from URI parameters.
        let transport = if uri_params.to_ascii_lowercase().contains("transport=tcp") {
            Transport::Tcp
        } else if uri_params.to_ascii_lowercase().contains("transport=tls") {
            Transport::Tls
        } else {
            Transport::Udp
        };

        let transport_name = match transport {
            Transport::Tcp => "TCP",
            Transport::Tls => "TLS",
            _ => "UDP",
        };

        // Parse host and port separately for proper SipUri construction.
        let (srs_host, srs_port) = if let Some(colon_pos) = srs_hostport.rfind(':') {
            let potential_port = &srs_hostport[colon_pos + 1..];
            if let Ok(port) = potential_port.parse::<u16>() {
                (&srs_hostport[..colon_pos], Some(port))
            } else {
                (srs_hostport, None)
            }
        } else {
            (srs_hostport, None)
        };

        let destination_port = srs_port.unwrap_or(5060);
        let destination: SocketAddr = format!("{srs_host}:{destination_port}")
            .parse()
            .unwrap_or(FALLBACK_DESTINATION);

        // Build recording metadata XML
        let metadata_xml = metadata::build_recording_metadata(
            &session_id,
            caller_uri,
            callee_uri,
            original_sip_call_id,
        );

        // Build recording SDP with per-direction streams.
        // RTPEngine subscribe_request returns recvonly SDP (from its subscription
        // port perspective), which must be flipped to sendonly (SRC→SRS direction).
        let recording_sdp = match (caller_sdp, callee_sdp) {
            (Some(caller), Some(callee)) => {
                // Both directions available — combine into 2 m= lines with labels.
                combine_recording_sdps(caller, callee)
            }
            (Some(single), None) | (None, Some(single)) => {
                // Only one direction — single m= line fallback.
                fix_recording_sdp_direction(single)
            }
            (None, None) => {
                // No RTPEngine SDPs — build from original call SDP.
                build_recording_sdp(sdp, local_addr)
            }
        };

        // Build multipart/mixed body
        let boundary = format!("srec-{}", &session_id[..8]);
        let multipart_body = build_multipart_body(&boundary, &recording_sdp, &metadata_xml);

        // Build proper SipUri with separate host, port, and transport param.
        let mut request_uri = SipUri::new(srs_host.to_string());
        if let Some(port) = srs_port {
            request_uri = request_uri.with_port(port);
        }
        if transport != Transport::Udp {
            request_uri =
                request_uri.with_param("transport".to_string(), Some(transport_name.to_string()));
        }
        let via = format!(
            "SIP/2.0/{} {};branch={}",
            transport_name, local_addr, branch
        );

        let message = SipMessageBuilder::new()
            .request(Method::Invite, request_uri)
            .via(via)
            .from(format!(
                "<sip:recorder@{}>;tag={}",
                local_addr.ip(),
                from_tag
            ))
            .to(format!("<{srs_uri}>"))
            .call_id(sip_call_id.clone())
            .cseq(format!("{cseq} INVITE"))
            .header("Contact", format!("<sip:recorder@{local_addr}>"))
            .header(
                "Content-Type",
                format!("multipart/mixed;boundary={boundary}"),
            )
            .header("Require", "siprec".to_string())
            .header(
                "User-Agent",
                user_agent.unwrap_or(&self.default_user_agent).to_string(),
            )
            .max_forwards(70)
            .body(multipart_body)
            .build();

        let message = match message {
            Ok(message) => message,
            Err(error) => {
                warn!(call_id = %call_id, %error, "failed to build recording INVITE");
                return None;
            }
        };

        let session = RecordingSession {
            session_id: session_id.clone(),
            call_id: call_id.to_string(),
            srs_uri: srs_uri.to_string(),
            state: RecordingState::Pending,
            sip_call_id,
            branch: branch.clone(),
            invite_cseq: cseq,
            cseq: AtomicU32::new(cseq + 1),
            from_tag,
            to_tag: None,
            original_sip_call_id: original_sip_call_id.map(|s| s.to_string()),
            original_from_tag: original_tags.map(|(ft, _)| ft.to_string()),
            original_to_tag: original_tags.map(|(_, tt)| tt.to_string()),
            created_at: std::time::Instant::now(),
        };

        self.sessions.insert(session_id.clone(), session);
        self.call_sessions
            .entry(call_id.to_string())
            .or_default()
            .push(session_id.clone());
        self.branch_to_session.insert(branch, session_id.clone());

        info!(
            call_id = %call_id,
            session_id = %session_id,
            srs = %srs_uri,
            "SIPREC: starting recording"
        );

        Some((session_id, message, destination, transport))
    }

    /// Handle a 200 OK from the SRS — recording is now active.
    ///
    /// Returns the ACK message to send back to the SRS (RFC 3261 §13.2.2.4).
    pub fn handle_success(
        &self,
        session_id: &str,
        to_tag: Option<String>,
        local_addr: SocketAddr,
    ) -> Option<(SipMessage, SocketAddr, Transport)> {
        let mut session = self.sessions.get_mut(session_id)?;
        session.state = RecordingState::Active;
        session.to_tag = to_tag;
        info!(
            session_id = %session_id,
            call_id = %session.call_id,
            "SIPREC: recording active"
        );

        // Build ACK for the 200 OK (same SRS URI parsing as BYE).
        let srs_host_part = session
            .srs_uri
            .strip_prefix("sip:")
            .or_else(|| session.srs_uri.strip_prefix("sips:"))
            .unwrap_or(&session.srs_uri);
        let srs_host_with_params = if let Some(at_pos) = srs_host_part.find('@') {
            &srs_host_part[at_pos + 1..]
        } else {
            srs_host_part
        };

        let (srs_hostport, uri_params) = match srs_host_with_params.find(';') {
            Some(pos) => (&srs_host_with_params[..pos], &srs_host_with_params[pos..]),
            None => (srs_host_with_params, ""),
        };

        let ack_transport = if uri_params.to_ascii_lowercase().contains("transport=tcp") {
            Transport::Tcp
        } else if uri_params.to_ascii_lowercase().contains("transport=tls") {
            Transport::Tls
        } else {
            Transport::Udp
        };

        let transport_name = match ack_transport {
            Transport::Tcp => "TCP",
            Transport::Tls => "TLS",
            _ => "UDP",
        };

        let (host_str, port_opt) = if let Some(colon_pos) = srs_hostport.rfind(':') {
            let potential_port = &srs_hostport[colon_pos + 1..];
            if let Ok(port) = potential_port.parse::<u16>() {
                (&srs_hostport[..colon_pos], Some(port))
            } else {
                (srs_hostport, None)
            }
        } else {
            (srs_hostport, None)
        };

        let destination_port = port_opt.unwrap_or(5060);
        let destination: SocketAddr = format!("{host_str}:{destination_port}")
            .parse()
            .unwrap_or(FALLBACK_DESTINATION);

        let mut request_uri = SipUri::new(host_str.to_string());
        if let Some(port) = port_opt {
            request_uri = request_uri.with_port(port);
        }
        if ack_transport != Transport::Udp {
            request_uri =
                request_uri.with_param("transport".to_string(), Some(transport_name.to_string()));
        }

        // ACK for 2xx is a new transaction — new branch (RFC 3261 §13.2.2.4).
        let branch = format!("z9hG4bK-rec-ack-{}", uuid::Uuid::new_v4());
        let via = format!(
            "SIP/2.0/{} {};branch={}",
            transport_name, local_addr, branch
        );

        let mut to_value = format!("<{}>", session.srs_uri);
        if let Some(ref to_tag) = session.to_tag {
            to_value.push_str(&format!(";tag={to_tag}"));
        }

        // ACK CSeq must match the original INVITE CSeq number.
        let invite_cseq = session.invite_cseq;

        match SipMessageBuilder::new()
            .request(Method::Ack, request_uri)
            .via(via)
            .from(format!(
                "<sip:recorder@{}>;tag={}",
                local_addr.ip(),
                session.from_tag
            ))
            .to(to_value)
            .call_id(session.sip_call_id.clone())
            .cseq(format!("{invite_cseq} ACK"))
            .max_forwards(70)
            .content_length(0)
            .build()
        {
            Ok(ack) => {
                debug!(
                    session_id = %session_id,
                    "SIPREC: sending ACK to SRS"
                );
                Some((ack, destination, ack_transport))
            }
            Err(error) => {
                warn!(session_id = %session_id, %error, "SIPREC: failed to build ACK for SRS");
                None
            }
        }
    }

    /// Handle a failure from the SRS.
    pub fn handle_failure(&self, session_id: &str, status_code: u16) {
        if let Some(mut session) = self.sessions.get_mut(session_id) {
            session.state = RecordingState::Failed;
            warn!(
                session_id = %session_id,
                call_id = %session.call_id,
                status_code,
                "SIPREC: recording failed"
            );
        }
    }

    /// Get the original call tags for a recording session (for RTPEngine subscribe).
    pub fn original_call_tags(&self, session_id: &str) -> Option<(String, String)> {
        self.sessions.get(session_id).and_then(|session| {
            match (&session.original_from_tag, &session.original_to_tag) {
                (Some(from_tag), Some(to_tag)) => Some((from_tag.clone(), to_tag.clone())),
                _ => None,
            }
        })
    }

    /// Get the original call's SIP Call-ID and tags (for RTPEngine subscribe/unsubscribe).
    pub fn original_call_info(&self, session_id: &str) -> Option<(String, String, String)> {
        self.sessions.get(session_id).and_then(|session| {
            match (
                &session.original_sip_call_id,
                &session.original_from_tag,
                &session.original_to_tag,
            ) {
                (Some(call_id), Some(from_tag), Some(to_tag)) => {
                    Some((call_id.clone(), from_tag.clone(), to_tag.clone()))
                }
                _ => None,
            }
        })
    }

    /// Get original call info for all active sessions of a call (for RTPEngine unsubscribe on BYE).
    pub fn active_session_infos(&self, call_id: &str) -> Vec<(String, String, String)> {
        let session_ids = match self.call_sessions.get(call_id) {
            Some(ids) => ids.clone(),
            None => return Vec::new(),
        };
        session_ids
            .iter()
            .filter_map(|session_id| self.original_call_info(session_id))
            .collect()
    }

    /// Stop recording a call by sending BYE to SRS.
    ///
    /// Returns a list of BYE messages to send.
    pub fn stop_recording(
        &self,
        call_id: &str,
        local_addr: SocketAddr,
    ) -> Vec<(SipMessage, SocketAddr, Transport)> {
        let session_ids = match self.call_sessions.get(call_id) {
            Some(ids) => ids.clone(),
            None => return Vec::new(),
        };

        let mut bye_messages = Vec::new();

        for session_id in &session_ids {
            if let Some(mut session) = self.sessions.get_mut(session_id) {
                if session.state != RecordingState::Active {
                    continue;
                }

                session.state = RecordingState::Stopped;
                let cseq = session.cseq.fetch_add(1, Ordering::Relaxed);

                // Parse SRS URI — extract host, port, transport (same logic as start_recording).
                let srs_host_part = session
                    .srs_uri
                    .strip_prefix("sip:")
                    .or_else(|| session.srs_uri.strip_prefix("sips:"))
                    .unwrap_or(&session.srs_uri);
                let srs_host_with_params = if let Some(at_pos) = srs_host_part.find('@') {
                    &srs_host_part[at_pos + 1..]
                } else {
                    srs_host_part
                };

                let (srs_hostport, uri_params) = match srs_host_with_params.find(';') {
                    Some(pos) => (&srs_host_with_params[..pos], &srs_host_with_params[pos..]),
                    None => (srs_host_with_params, ""),
                };

                let bye_transport = if uri_params.to_ascii_lowercase().contains("transport=tcp") {
                    Transport::Tcp
                } else if uri_params.to_ascii_lowercase().contains("transport=tls") {
                    Transport::Tls
                } else {
                    Transport::Udp
                };

                let transport_name = match bye_transport {
                    Transport::Tcp => "TCP",
                    Transport::Tls => "TLS",
                    _ => "UDP",
                };

                let (host_str, port_opt) = if let Some(colon_pos) = srs_hostport.rfind(':') {
                    let potential_port = &srs_hostport[colon_pos + 1..];
                    if let Ok(port) = potential_port.parse::<u16>() {
                        (&srs_hostport[..colon_pos], Some(port))
                    } else {
                        (srs_hostport, None)
                    }
                } else {
                    (srs_hostport, None)
                };

                let destination_port = port_opt.unwrap_or(5060);
                let destination: SocketAddr = format!("{host_str}:{destination_port}")
                    .parse()
                    .unwrap_or(FALLBACK_DESTINATION);

                let mut request_uri = SipUri::new(host_str.to_string());
                if let Some(port) = port_opt {
                    request_uri = request_uri.with_port(port);
                }
                if bye_transport != Transport::Udp {
                    request_uri = request_uri
                        .with_param("transport".to_string(), Some(transport_name.to_string()));
                }
                let branch = format!("z9hG4bK-rec-bye-{}", uuid::Uuid::new_v4());
                let via = format!(
                    "SIP/2.0/{} {};branch={}",
                    transport_name, local_addr, branch
                );

                let mut to_value = format!("<{}>", session.srs_uri);
                if let Some(ref to_tag) = session.to_tag {
                    to_value.push_str(&format!(";tag={to_tag}"));
                }

                if let Ok(bye) = SipMessageBuilder::new()
                    .request(Method::Bye, request_uri)
                    .via(via)
                    .from(format!(
                        "<sip:recorder@{}>;tag={}",
                        local_addr.ip(),
                        session.from_tag
                    ))
                    .to(to_value)
                    .call_id(session.sip_call_id.clone())
                    .cseq(format!("{cseq} BYE"))
                    .max_forwards(70)
                    .content_length(0)
                    .build()
                {
                    bye_messages.push((bye, destination, bye_transport));
                    debug!(
                        session_id = %session_id,
                        "SIPREC: sending BYE to SRS"
                    );
                }
            }
        }

        // Clean up
        self.call_sessions.remove(call_id);
        for session_id in &session_ids {
            self.branch_to_session
                .retain(|_, value| value != session_id);
            self.sessions.remove(session_id);
        }

        bye_messages
    }

    /// Look up a recording session by branch (for routing SRS responses).
    pub fn session_for_branch(&self, branch: &str) -> Option<String> {
        self.branch_to_session
            .get(branch)
            .map(|value| value.clone())
    }

    /// Check if a call has any active recording sessions.
    pub fn is_recording(&self, call_id: &str) -> bool {
        self.call_sessions
            .get(call_id)
            .map(|ids| {
                ids.iter().any(|id| {
                    self.sessions
                        .get(id)
                        .map(|session| {
                            session.state == RecordingState::Active
                                || session.state == RecordingState::Pending
                        })
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false)
    }

    /// Number of active recording sessions.
    pub fn active_count(&self) -> usize {
        self.sessions
            .iter()
            .filter(|session| session.state == RecordingState::Active)
            .count()
    }

    /// Orphan backstop: remove recording sessions older than `max_age` along
    /// with their `call_sessions` / `branch_to_session` aliases.
    ///
    /// Normal recordings are torn down by [`Self::stop_recording`] on BYE;
    /// this only reaps sessions whose call ended without a stop ever firing
    /// (e.g. the B2BUA call was abandoned without a teardown path).  Ages
    /// strictly by creation time so an active recording is never dropped
    /// while its call is still alive.  Returns the number of sessions reaped.
    pub fn sweep_stale(&self, max_age: std::time::Duration) -> usize {
        let now = std::time::Instant::now();
        let stale_ids: Vec<String> = self
            .sessions
            .iter()
            .filter(|session| now.duration_since(session.created_at) > max_age)
            .map(|session| session.session_id.clone())
            .collect();

        for session_id in &stale_ids {
            // Drop the primary record.
            self.sessions.remove(session_id);
            // Drop the branch alias(es) pointing at this session.
            self.branch_to_session
                .retain(|_, value| value != session_id);
            // Drop the session id from its call's list; remove now-empty lists.
            self.call_sessions.retain(|_, ids| {
                ids.retain(|id| id != session_id);
                !ids.is_empty()
            });
        }

        let reaped = stale_ids.len();
        if reaped > 0 {
            info!(
                reaped,
                "SIPREC: orphan backstop swept stale recording sessions"
            );
        }
        reaped
    }
}

/// Rewrite SDP direction attributes to `a=sendonly` for SIPREC.
///
/// RTPEngine's subscribe_request returns SDP with `a=recvonly` (from its
/// subscription endpoint's perspective — it receives a copy of the media).
/// But in the SIPREC INVITE, the direction is from the SRC's perspective:
/// "I (SRC) will send forked media to you (SRS)" → `a=sendonly`.
/// Process a SIPREC-mode subscribe SDP (combined multi-m= from RTPEngine).
///
/// RTPEngine's `subscribe request` with `flags: ["all", "siprec"]` returns a
/// single SDP with one m= line per call direction.  This function:
/// 1. Flips `a=recvonly` → `a=sendonly` (SRC sends to SRS)
/// 2. Adds `a=label:N` to each m= section (0-based) if not already present
pub fn fix_siprec_subscribe_sdp(sdp: &[u8]) -> Vec<u8> {
    let sdp_str = String::from_utf8_lossy(sdp);
    let mut result = String::new();
    let mut media_index: i32 = -1; // -1 = session-level, 0+ = media section index
    let mut section_has_label = false;

    for line in sdp_str.lines() {
        if line.starts_with("m=") {
            // Before starting a new m= section, add label to previous section if missing.
            if media_index >= 0 && !section_has_label {
                result.push_str(&format!("a=label:{media_index}\r\n"));
            }
            media_index += 1;
            section_has_label = false;
            result.push_str(line);
            result.push_str("\r\n");
        } else if line.starts_with("a=recvonly") {
            result.push_str("a=sendonly\r\n");
        } else if line.starts_with("a=label:") {
            // Replace existing label with our index.
            section_has_label = true;
            result.push_str(&format!("a=label:{media_index}\r\n"));
        } else {
            result.push_str(line);
            result.push_str("\r\n");
        }
    }

    // Add label to the last m= section if missing.
    if media_index >= 0 && !section_has_label {
        result.push_str(&format!("a=label:{media_index}\r\n"));
    }

    result.into_bytes()
}

fn fix_recording_sdp_direction(sdp: &[u8]) -> Vec<u8> {
    let sdp_str = String::from_utf8_lossy(sdp);
    let mut result = String::new();
    for line in sdp_str.lines() {
        if line.starts_with("a=recvonly") {
            result.push_str("a=sendonly\r\n");
        } else {
            result.push_str(line);
            result.push_str("\r\n");
        }
    }
    result.into_bytes()
}

/// Combine two per-direction subscribe SDPs into a single SDP with 2 m= lines.
///
/// Takes the caller's subscribe SDP (label 0) and callee's subscribe SDP
/// (label 1), extracts the session-level headers from the first, then
/// appends both media sections with `a=label:N` and `a=sendonly`.
fn combine_recording_sdps(caller_sdp: &[u8], callee_sdp: &[u8]) -> Vec<u8> {
    let caller_str = String::from_utf8_lossy(caller_sdp);
    let callee_str = String::from_utf8_lossy(callee_sdp);

    let mut result = String::new();

    // Extract session-level lines from caller SDP (v=, o=, s=, t=, c=).
    // Stop at the first m= line.
    for line in caller_str.lines() {
        if line.starts_with("m=") {
            break;
        }
        result.push_str(line);
        result.push_str("\r\n");
    }

    // Append caller's media section (label 0) with direction fix.
    append_media_section(&mut result, &caller_str, "0");

    // Append callee's media section (label 1) with direction fix.
    append_media_section(&mut result, &callee_str, "1");

    result.into_bytes()
}

/// Extract the first m= section from an SDP and append it with a label.
fn append_media_section(result: &mut String, sdp: &str, label: &str) {
    let mut in_media = false;
    let mut has_label = false;

    for line in sdp.lines() {
        if line.starts_with("m=") {
            in_media = true;
            result.push_str(line);
            result.push_str("\r\n");
            continue;
        }
        if !in_media {
            continue;
        }
        // Direction fix: recvonly → sendonly (subscribe returns recvonly).
        if line.starts_with("a=recvonly") {
            result.push_str("a=sendonly\r\n");
        } else if line.starts_with("a=label:") {
            // Replace existing label.
            has_label = true;
            result.push_str(&format!("a=label:{label}\r\n"));
        } else {
            result.push_str(line);
            result.push_str("\r\n");
        }
    }

    // Add label if the subscribe SDP didn't have one.
    if in_media && !has_label {
        result.push_str(&format!("a=label:{label}\r\n"));
    }
}

/// Split a dual-m= SDP (from a SIPREC INVITE) into two single-m= SDPs.
///
/// Each returned SDP retains the session-level headers (v=, o=, s=, t=, c=)
/// and contains exactly one m= section. Used by the SRS to feed each stream
/// to RTPEngine as a separate offer/answer pair.
///
/// Also replaces `a=inactive` with `a=sendonly` so RTPEngine activates recording
/// (inactive media causes RTPEngine to skip recording for that stream).
pub fn split_dual_sdp(sdp: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let sdp_str = String::from_utf8_lossy(sdp);
    let mut session_header = String::new();
    let mut media_sections: Vec<String> = Vec::new();
    let mut current_media = String::new();

    for line in sdp_str.lines() {
        if line.starts_with("m=") {
            if !current_media.is_empty() {
                media_sections.push(current_media.clone());
                current_media.clear();
            }
            current_media.push_str(line);
            current_media.push_str("\r\n");
        } else if media_sections.is_empty() && current_media.is_empty() {
            // Session-level header (before any m= line).
            session_header.push_str(line);
            session_header.push_str("\r\n");
        } else {
            // Media-level attribute.
            if line.starts_with("a=inactive") {
                current_media.push_str("a=sendonly\r\n");
            } else {
                current_media.push_str(line);
                current_media.push_str("\r\n");
            }
        }
    }
    if !current_media.is_empty() {
        media_sections.push(current_media);
    }

    let sdp1 = if !media_sections.is_empty() {
        format!("{}{}", session_header, media_sections[0])
    } else {
        session_header.clone()
    };

    let sdp2 = if media_sections.len() > 1 {
        format!("{}{}", session_header, media_sections[1])
    } else {
        // Single m= line — duplicate it for both sides.
        sdp1.clone()
    };

    (sdp1.into_bytes(), sdp2.into_bytes())
}

/// Combine two RTPEngine response SDPs into a single SDP with 2 m= lines.
///
/// Takes the offer response (caller ports) and answer response (callee ports),
/// merges them into a single SDP body with `a=recvonly` direction (the SRS
/// receives media from the SRC) and `a=label:N` on each m= section.
pub fn combine_srs_answer_sdps(offer_sdp: &[u8], answer_sdp: &[u8]) -> Vec<u8> {
    let offer_str = String::from_utf8_lossy(offer_sdp);
    let answer_str = String::from_utf8_lossy(answer_sdp);

    let mut result = String::new();

    // Take session-level headers from the offer response.
    for line in offer_str.lines() {
        if line.starts_with("m=") {
            break;
        }
        result.push_str(line);
        result.push_str("\r\n");
    }

    // Append offer media section (label 0, recvonly).
    append_srs_media_section(&mut result, &offer_str, "0");

    // Append answer media section (label 1, recvonly).
    append_srs_media_section(&mut result, &answer_str, "1");

    result.into_bytes()
}

/// Extract the first m= section from an RTPEngine response SDP and append it
/// with `a=recvonly` direction and the given label.
fn append_srs_media_section(result: &mut String, sdp: &str, label: &str) {
    let mut in_media = false;
    let mut has_label = false;
    let mut has_direction = false;

    for line in sdp.lines() {
        if line.starts_with("m=") {
            if in_media {
                break; // Only take the first m= section.
            }
            in_media = true;
            result.push_str(line);
            result.push_str("\r\n");
            continue;
        }
        if !in_media {
            continue;
        }
        if line.starts_with("a=sendonly")
            || line.starts_with("a=recvonly")
            || line.starts_with("a=sendrecv")
            || line.starts_with("a=inactive")
        {
            if !has_direction {
                result.push_str("a=recvonly\r\n");
                has_direction = true;
            }
        } else if line.starts_with("a=label:") {
            has_label = true;
            result.push_str(&format!("a=label:{label}\r\n"));
        } else {
            result.push_str(line);
            result.push_str("\r\n");
        }
    }

    if in_media && !has_label {
        result.push_str(&format!("a=label:{label}\r\n"));
    }
    if in_media && !has_direction {
        result.push_str("a=recvonly\r\n");
    }
}

/// Build a sendonly SDP from the call's SDP for the SIPREC INVITE.
///
/// The SRC (us) sends forked media to the SRS, so the offer direction
/// must be `a=sendonly` — "I will send, you receive" (RFC 3264 §5).
fn build_recording_sdp(original_sdp: &[u8], local_addr: SocketAddr) -> Vec<u8> {
    let sdp_str = String::from_utf8_lossy(original_sdp);

    // Rewrite direction to sendonly: the SRC sends forked RTP to the SRS.
    let mut result = String::new();
    for line in sdp_str.lines() {
        if line.starts_with("a=sendrecv") || line.starts_with("a=recvonly") {
            result.push_str("a=sendonly\r\n");
        } else if line.starts_with("o=") {
            // Replace origin address with our address
            let parts: Vec<&str> = line.splitn(6, ' ').collect();
            if parts.len() >= 6 {
                result.push_str(&format!(
                    "{} {} {} IN IP4 {}\r\n",
                    parts[0],
                    parts[1],
                    parts[2],
                    local_addr.ip()
                ));
            } else {
                result.push_str(line);
                result.push_str("\r\n");
            }
        } else if line.starts_with("c=IN IP4 ") {
            // Replace connection address with our address
            result.push_str(&format!("c=IN IP4 {}\r\n", local_addr.ip()));
        } else {
            result.push_str(line);
            result.push_str("\r\n");
        }
    }

    result.into_bytes()
}

/// Build a multipart/mixed body with SDP and recording metadata XML.
fn build_multipart_body(boundary: &str, sdp: &[u8], metadata_xml: &str) -> Vec<u8> {
    let mut body = Vec::new();

    // SDP part
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Type: application/sdp\r\n\r\n");
    body.extend_from_slice(sdp);
    if !sdp.ends_with(b"\r\n") {
        body.extend_from_slice(b"\r\n");
    }

    // Metadata XML part
    body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
    body.extend_from_slice(b"Content-Type: application/rs-metadata+xml\r\n\r\n");
    body.extend_from_slice(metadata_xml.as_bytes());
    if !metadata_xml.ends_with("\r\n") {
        body.extend_from_slice(b"\r\n");
    }

    // Closing boundary
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

    body
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recording_state_display() {
        assert_eq!(RecordingState::Pending.to_string(), "pending");
        assert_eq!(RecordingState::Active.to_string(), "active");
        assert_eq!(RecordingState::Stopped.to_string(), "stopped");
        assert_eq!(RecordingState::Failed.to_string(), "failed");
    }

    #[test]
    fn recording_manager_new_is_empty() {
        let manager = RecordingManager::new("SIPhon", "0.1.0");
        assert_eq!(manager.active_count(), 0);
        assert!(!manager.is_recording("call-1"));
    }

    #[test]
    fn start_recording_creates_session() {
        let manager = RecordingManager::new("SIPhon", "0.1.0");
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "t=0 0\r\n",
            "m=audio 10000 RTP/AVP 0\r\n",
            "a=sendrecv\r\n",
        );

        let result = manager.start_recording(
            "call-1",
            "sip:srs@10.0.0.5:5060",
            "sip:alice@example.com",
            "sip:bob@example.com",
            sdp.as_bytes(),
            "10.0.0.1:5060".parse().unwrap(),
            None,
            None,
            None,
            None,
            None,
        );

        assert!(result.is_some());
        let (session_id, message, destination, transport) = result.unwrap();

        assert!(manager.is_recording("call-1"));
        assert_eq!(destination, "10.0.0.5:5060".parse::<SocketAddr>().unwrap());
        assert_eq!(transport, Transport::Udp);

        // Verify the INVITE message
        let bytes = message.to_bytes();
        let raw = String::from_utf8_lossy(&bytes);
        assert!(raw.contains("INVITE"));
        assert!(raw.contains("Require: siprec"));
        assert!(raw.contains("multipart/mixed"));
        assert!(raw.contains("application/sdp"));
        assert!(raw.contains("application/rs-metadata+xml"));
        assert!(raw.contains("a=sendonly"));

        // Verify session is in pending state
        let session = manager.sessions.get(&session_id).unwrap();
        assert_eq!(session.state, RecordingState::Pending);
    }

    #[test]
    fn handle_success_activates_session() {
        let manager = RecordingManager::new("SIPhon", "0.1.0");
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "t=0 0\r\n",
            "m=audio 10000 RTP/AVP 0\r\n",
            "a=sendrecv\r\n",
        );

        let (session_id, _, _, _) = manager
            .start_recording(
                "call-1",
                "sip:srs@10.0.0.5:5060",
                "sip:alice@example.com",
                "sip:bob@example.com",
                sdp.as_bytes(),
                "10.0.0.1:5060".parse().unwrap(),
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();

        let ack_result = manager.handle_success(
            &session_id,
            Some("srs-tag-1".to_string()),
            "10.0.0.1:5060".parse().unwrap(),
        );

        let session = manager.sessions.get(&session_id).unwrap();
        assert_eq!(session.state, RecordingState::Active);
        assert_eq!(session.to_tag.as_deref(), Some("srs-tag-1"));
        assert_eq!(manager.active_count(), 1);

        // handle_success must return an ACK message.
        let (ack, destination, transport) = ack_result.unwrap();
        assert_eq!(destination, "10.0.0.5:5060".parse::<SocketAddr>().unwrap());
        assert_eq!(transport, Transport::Udp);

        let bytes = ack.to_bytes();
        let raw = String::from_utf8_lossy(&bytes);
        assert!(raw.starts_with("ACK sip:10.0.0.5:5060 SIP/2.0\r\n"));
        assert!(
            raw.contains(";tag=srs-tag-1"),
            "ACK must include SRS To-tag"
        );
        assert!(raw.contains("CSeq: "), "ACK must have CSeq header");
        assert!(raw.contains(" ACK"), "CSeq method must be ACK");
        // ACK CSeq number must match the original INVITE CSeq.
        let invite_cseq = session.invite_cseq;
        assert!(raw.contains(&format!("CSeq: {invite_cseq} ACK")));
    }

    #[test]
    fn handle_success_ack_uses_tcp_when_srs_uri_requires_it() {
        let manager = RecordingManager::new("SIPhon", "0.1.0");
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "t=0 0\r\n",
            "m=audio 10000 RTP/AVP 0\r\n",
            "a=sendrecv\r\n",
        );

        let (session_id, _, _, _) = manager
            .start_recording(
                "call-1",
                "sip:srs@10.0.0.5:5080;transport=TCP",
                "sip:alice@example.com",
                "sip:bob@example.com",
                sdp.as_bytes(),
                "10.0.0.1:5060".parse().unwrap(),
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();

        let (ack, destination, transport) = manager
            .handle_success(
                &session_id,
                Some("srs-tag-tcp".to_string()),
                "10.0.0.1:5060".parse().unwrap(),
            )
            .unwrap();

        assert_eq!(transport, Transport::Tcp);
        assert_eq!(destination, "10.0.0.5:5080".parse::<SocketAddr>().unwrap());

        let ack_bytes = ack.to_bytes();
        let raw = String::from_utf8_lossy(&ack_bytes);
        assert!(raw.contains("SIP/2.0/TCP"), "ACK Via must use TCP");
        assert!(raw.contains(";tag=srs-tag-tcp"));
    }

    #[test]
    fn handle_failure_marks_failed() {
        let manager = RecordingManager::new("SIPhon", "0.1.0");
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "t=0 0\r\n",
            "m=audio 10000 RTP/AVP 0\r\n",
            "a=sendrecv\r\n",
        );

        let (session_id, _, _, _) = manager
            .start_recording(
                "call-1",
                "sip:srs@10.0.0.5:5060",
                "sip:alice@example.com",
                "sip:bob@example.com",
                sdp.as_bytes(),
                "10.0.0.1:5060".parse().unwrap(),
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();

        manager.handle_failure(&session_id, 503);

        let session = manager.sessions.get(&session_id).unwrap();
        assert_eq!(session.state, RecordingState::Failed);
    }

    #[test]
    fn stop_recording_sends_bye() {
        let manager = RecordingManager::new("SIPhon", "0.1.0");
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "t=0 0\r\n",
            "m=audio 10000 RTP/AVP 0\r\n",
            "a=sendrecv\r\n",
        );

        let (session_id, _, _, _) = manager
            .start_recording(
                "call-1",
                "sip:srs@10.0.0.5:5060",
                "sip:alice@example.com",
                "sip:bob@example.com",
                sdp.as_bytes(),
                "10.0.0.1:5060".parse().unwrap(),
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();

        manager.handle_success(
            &session_id,
            Some("srs-tag-1".to_string()),
            "10.0.0.1:5060".parse().unwrap(),
        );
        assert_eq!(manager.active_count(), 1);

        let bye_messages = manager.stop_recording("call-1", "10.0.0.1:5060".parse().unwrap());
        assert_eq!(bye_messages.len(), 1);

        let (bye, _destination, _transport) = &bye_messages[0];
        let bytes = bye.to_bytes();
        let raw = String::from_utf8_lossy(&bytes);
        assert!(raw.contains("BYE"));
        assert!(raw.contains("srs-tag-1"));

        // Session should be cleaned up
        assert!(!manager.is_recording("call-1"));
        assert_eq!(manager.active_count(), 0);
    }

    #[test]
    fn stop_recording_no_op_for_non_active() {
        let manager = RecordingManager::new("SIPhon", "0.1.0");
        let bye_messages = manager.stop_recording("no-such-call", "10.0.0.1:5060".parse().unwrap());
        assert!(bye_messages.is_empty());
    }

    #[test]
    fn session_for_branch_routing() {
        let manager = RecordingManager::new("SIPhon", "0.1.0");
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "t=0 0\r\n",
            "m=audio 10000 RTP/AVP 0\r\n",
            "a=sendrecv\r\n",
        );

        let (session_id, message, _, _) = manager
            .start_recording(
                "call-1",
                "sip:srs@10.0.0.5:5060",
                "sip:alice@example.com",
                "sip:bob@example.com",
                sdp.as_bytes(),
                "10.0.0.1:5060".parse().unwrap(),
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();

        // Extract branch from the message
        let bytes = message.to_bytes();
        let raw = String::from_utf8_lossy(&bytes);
        let branch = raw
            .lines()
            .find(|line| line.starts_with("Via:"))
            .and_then(|line| line.split("branch=").nth(1))
            .map(|branch_value| {
                branch_value
                    .split(';')
                    .next()
                    .unwrap_or(branch_value)
                    .trim()
            })
            .unwrap();

        assert_eq!(manager.session_for_branch(branch), Some(session_id));
        assert!(manager.session_for_branch("z9hG4bK-other").is_none());
    }

    #[test]
    fn build_recording_sdp_rewrites_sendrecv() {
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "t=0 0\r\n",
            "m=audio 10000 RTP/AVP 0\r\n",
            "a=sendrecv\r\n",
        );
        let result = build_recording_sdp(sdp.as_bytes(), "10.0.0.2:5060".parse().unwrap());
        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains("a=sendonly"));
        assert!(!result_str.contains("a=sendrecv"));
    }

    #[test]
    fn build_recording_sdp_rewrites_connection_address() {
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "t=0 0\r\n",
            "m=audio 10000 RTP/AVP 0\r\n",
            "a=sendrecv\r\n",
        );
        let result = build_recording_sdp(sdp.as_bytes(), "10.0.0.2:5060".parse().unwrap());
        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains("c=IN IP4 10.0.0.2"));
        assert!(!result_str.contains("c=IN IP4 10.0.0.1"));
    }

    #[test]
    fn fix_recording_sdp_direction_recvonly_to_sendonly() {
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "t=0 0\r\n",
            "m=audio 10000 RTP/AVP 0\r\n",
            "a=recvonly\r\n",
        );
        let result = fix_recording_sdp_direction(sdp.as_bytes());
        let result_str = String::from_utf8_lossy(&result);
        assert!(
            result_str.contains("a=sendonly"),
            "recvonly must be rewritten to sendonly"
        );
        assert!(!result_str.contains("a=recvonly"));
    }

    #[test]
    fn fix_recording_sdp_direction_preserves_sendonly() {
        let sdp = concat!("v=0\r\n", "m=audio 10000 RTP/AVP 0\r\n", "a=sendonly\r\n",);
        let result = fix_recording_sdp_direction(sdp.as_bytes());
        let result_str = String::from_utf8_lossy(&result);
        assert!(result_str.contains("a=sendonly"));
    }

    #[test]
    fn fix_siprec_subscribe_sdp_dual_stream() {
        // Simulates RTPEngine's SIPREC-mode subscribe response with 2 m= lines.
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "t=0 0\r\n",
            "m=audio 30000 RTP/AVP 8 101\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "a=rtpmap:8 PCMA/8000\r\n",
            "a=rtpmap:101 telephone-event/8000\r\n",
            "a=recvonly\r\n",
            "m=audio 30100 RTP/AVP 8 101\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "a=rtpmap:8 PCMA/8000\r\n",
            "a=rtpmap:101 telephone-event/8000\r\n",
            "a=recvonly\r\n",
        );
        let result = fix_siprec_subscribe_sdp(sdp.as_bytes());
        let result_str = String::from_utf8_lossy(&result);

        // Direction flipped.
        assert!(!result_str.contains("a=recvonly"));
        assert_eq!(result_str.matches("a=sendonly").count(), 2);

        // Labels added: 0 for first m=, 1 for second m=.
        assert!(result_str.contains("a=label:0"));
        assert!(result_str.contains("a=label:1"));

        // Two m= lines preserved.
        assert_eq!(result_str.matches("m=audio").count(), 2);
    }

    #[test]
    fn fix_siprec_subscribe_sdp_single_stream() {
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "t=0 0\r\n",
            "m=audio 30000 RTP/AVP 8\r\n",
            "a=recvonly\r\n",
        );
        let result = fix_siprec_subscribe_sdp(sdp.as_bytes());
        let result_str = String::from_utf8_lossy(&result);

        assert!(result_str.contains("a=sendonly"));
        assert!(result_str.contains("a=label:0"));
        assert!(!result_str.contains("a=label:1"));
    }

    #[test]
    fn fix_siprec_subscribe_sdp_replaces_existing_labels() {
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "t=0 0\r\n",
            "m=audio 30000 RTP/AVP 8\r\n",
            "a=label:foo\r\n",
            "a=recvonly\r\n",
            "m=audio 30100 RTP/AVP 8\r\n",
            "a=label:bar\r\n",
            "a=recvonly\r\n",
        );
        let result = fix_siprec_subscribe_sdp(sdp.as_bytes());
        let result_str = String::from_utf8_lossy(&result);

        assert!(result_str.contains("a=label:0"));
        assert!(result_str.contains("a=label:1"));
        assert!(!result_str.contains("a=label:foo"));
        assert!(!result_str.contains("a=label:bar"));
    }

    #[test]
    fn combine_two_subscribe_sdps_into_labeled_streams() {
        let caller_sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=session\r\n",
            "t=0 0\r\n",
            "m=audio 30000 RTP/AVP 8 101\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "a=rtpmap:8 PCMA/8000\r\n",
            "a=rtpmap:101 telephone-event/8000\r\n",
            "a=recvonly\r\n",
            "a=ptime:20\r\n",
        );
        let callee_sdp = concat!(
            "v=0\r\n",
            "o=- 2 2 IN IP4 10.0.0.2\r\n",
            "s=session\r\n",
            "t=0 0\r\n",
            "m=audio 30100 RTP/AVP 8 101\r\n",
            "c=IN IP4 10.0.0.2\r\n",
            "a=rtpmap:8 PCMA/8000\r\n",
            "a=rtpmap:101 telephone-event/8000\r\n",
            "a=recvonly\r\n",
            "a=ptime:20\r\n",
        );

        let combined = combine_recording_sdps(caller_sdp.as_bytes(), callee_sdp.as_bytes());
        let result = String::from_utf8_lossy(&combined);

        // Session-level headers from first SDP only.
        assert_eq!(result.matches("v=0").count(), 1);
        assert_eq!(result.matches("o=").count(), 1);

        // Two m= lines with different ports.
        assert_eq!(result.matches("m=audio").count(), 2);
        assert!(result.contains("m=audio 30000"));
        assert!(result.contains("m=audio 30100"));

        // Labels assigned: 0 for caller, 1 for callee.
        assert!(result.contains("a=label:0"));
        assert!(result.contains("a=label:1"));

        // Direction flipped from recvonly to sendonly.
        assert!(!result.contains("a=recvonly"));
        assert_eq!(result.matches("a=sendonly").count(), 2);
    }

    #[test]
    fn combine_sdps_preserves_existing_labels() {
        let caller_sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "t=0 0\r\n",
            "m=audio 30000 RTP/AVP 8\r\n",
            "a=label:existing\r\n",
            "a=recvonly\r\n",
        );
        let callee_sdp = concat!(
            "v=0\r\n",
            "o=- 2 2 IN IP4 10.0.0.2\r\n",
            "s=-\r\n",
            "t=0 0\r\n",
            "m=audio 30100 RTP/AVP 8\r\n",
            "a=recvonly\r\n",
        );

        let combined = combine_recording_sdps(caller_sdp.as_bytes(), callee_sdp.as_bytes());
        let result = String::from_utf8_lossy(&combined);

        // Existing label replaced with 0.
        assert!(result.contains("a=label:0"));
        assert!(result.contains("a=label:1"));
        assert!(!result.contains("a=label:existing"));
    }

    #[test]
    fn build_multipart_body_structure() {
        let sdp = b"v=0\r\nm=audio 10000 RTP/AVP 0\r\n";
        let xml = "<recording xmlns='urn:ietf:params:xml:ns:recording:1'/>";
        let body = build_multipart_body("test-boundary", sdp, xml);
        let body_str = String::from_utf8_lossy(&body);
        assert!(body_str.contains("--test-boundary\r\n"));
        assert!(body_str.contains("Content-Type: application/sdp"));
        assert!(body_str.contains("Content-Type: application/rs-metadata+xml"));
        assert!(body_str.contains("--test-boundary--\r\n"));
    }

    #[test]
    fn multiple_recordings_per_call() {
        let manager = RecordingManager::new("SIPhon", "0.1.0");
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "t=0 0\r\n",
            "m=audio 10000 RTP/AVP 0\r\n",
            "a=sendrecv\r\n",
        );

        let (session_id_1, _, _, _) = manager
            .start_recording(
                "call-1",
                "sip:srs1@10.0.0.5:5060",
                "sip:alice@example.com",
                "sip:bob@example.com",
                sdp.as_bytes(),
                "10.0.0.1:5060".parse().unwrap(),
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();

        let (session_id_2, _, _, _) = manager
            .start_recording(
                "call-1",
                "sip:srs2@10.0.0.6:5060",
                "sip:alice@example.com",
                "sip:bob@example.com",
                sdp.as_bytes(),
                "10.0.0.1:5060".parse().unwrap(),
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();

        assert_ne!(session_id_1, session_id_2);
        assert!(manager.is_recording("call-1"));

        // Activate both
        manager.handle_success(
            &session_id_1,
            Some("tag-1".to_string()),
            "10.0.0.1:5060".parse().unwrap(),
        );
        manager.handle_success(
            &session_id_2,
            Some("tag-2".to_string()),
            "10.0.0.1:5060".parse().unwrap(),
        );
        assert_eq!(manager.active_count(), 2);

        // Stop all recordings for the call
        let bye_messages = manager.stop_recording("call-1", "10.0.0.1:5060".parse().unwrap());
        assert_eq!(bye_messages.len(), 2);
        assert_eq!(manager.active_count(), 0);
    }

    #[test]
    fn start_recording_transport_tcp() {
        let manager = RecordingManager::new("SIPhon", "0.1.0");
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "t=0 0\r\n",
            "m=audio 10000 RTP/AVP 0\r\n",
            "a=sendrecv\r\n",
        );

        let (_, message, destination, transport) = manager
            .start_recording(
                "call-1",
                "sip:10.0.0.5:5080;transport=TCP",
                "sip:alice@example.com",
                "sip:bob@example.com",
                sdp.as_bytes(),
                "10.0.0.1:5060".parse().unwrap(),
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();

        // Transport should be TCP, not UDP.
        assert_eq!(transport, Transport::Tcp);
        // Destination should correctly parse host:port without ;transport=TCP.
        assert_eq!(destination, "10.0.0.5:5080".parse::<SocketAddr>().unwrap());

        // RURI should be properly formatted (no brackets around IPv4).
        let bytes = message.to_bytes();
        let raw = String::from_utf8_lossy(&bytes);
        assert!(raw.contains("INVITE sip:10.0.0.5:5080;transport=TCP SIP/2.0"));
        // Via should use TCP transport.
        assert!(raw.contains("SIP/2.0/TCP"));
        assert!(raw.contains("User-Agent: SIPhon"));
    }

    #[test]
    fn start_recording_uri_no_transport_param() {
        let manager = RecordingManager::new("SIPhon", "0.1.0");
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "t=0 0\r\n",
            "m=audio 10000 RTP/AVP 0\r\n",
            "a=sendrecv\r\n",
        );

        let (_, message, destination, transport) = manager
            .start_recording(
                "call-1",
                "sip:srs@10.0.0.5:5060",
                "sip:alice@example.com",
                "sip:bob@example.com",
                sdp.as_bytes(),
                "10.0.0.1:5060".parse().unwrap(),
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();

        // Default transport should be UDP.
        assert_eq!(transport, Transport::Udp);
        assert_eq!(destination, "10.0.0.5:5060".parse::<SocketAddr>().unwrap());

        let bytes = message.to_bytes();
        let raw = String::from_utf8_lossy(&bytes);
        // RURI should not have transport param when UDP.
        assert!(raw.contains("INVITE sip:10.0.0.5:5060 SIP/2.0"));
        assert!(raw.contains("SIP/2.0/UDP"));
    }

    #[test]
    fn start_recording_uri_default_port() {
        let manager = RecordingManager::new("SIPhon", "0.1.0");
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "t=0 0\r\n",
            "m=audio 10000 RTP/AVP 0\r\n",
            "a=sendrecv\r\n",
        );

        let (_, _, destination, _) = manager
            .start_recording(
                "call-1",
                "sip:10.0.0.5",
                "sip:alice@example.com",
                "sip:bob@example.com",
                sdp.as_bytes(),
                "10.0.0.1:5060".parse().unwrap(),
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();

        // Should default to port 5060.
        assert_eq!(destination, "10.0.0.5:5060".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn stop_recording_bye_uses_correct_transport() {
        let manager = RecordingManager::new("SIPhon", "0.1.0");
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "t=0 0\r\n",
            "m=audio 10000 RTP/AVP 0\r\n",
            "a=sendrecv\r\n",
        );

        let (session_id, _, _, _) = manager
            .start_recording(
                "call-1",
                "sip:10.0.0.5:5080;transport=TCP",
                "sip:alice@example.com",
                "sip:bob@example.com",
                sdp.as_bytes(),
                "10.0.0.1:5060".parse().unwrap(),
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();

        manager.handle_success(
            &session_id,
            Some("srs-tag-1".to_string()),
            "10.0.0.1:5060".parse().unwrap(),
        );

        let bye_messages = manager.stop_recording("call-1", "10.0.0.1:5060".parse().unwrap());
        assert_eq!(bye_messages.len(), 1);

        let (bye, destination, transport) = &bye_messages[0];
        assert_eq!(*transport, Transport::Tcp);
        assert_eq!(*destination, "10.0.0.5:5080".parse::<SocketAddr>().unwrap());

        let bytes = bye.to_bytes();
        let raw = String::from_utf8_lossy(&bytes);
        assert!(raw.contains("SIP/2.0/TCP"));
    }

    #[test]
    fn start_recording_uses_configured_user_agent() {
        let manager = RecordingManager::new("SIPhon", "0.1.0");
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "t=0 0\r\n",
            "m=audio 10000 RTP/AVP 0\r\n",
            "a=sendrecv\r\n",
        );

        let (_, message, _, _) = manager
            .start_recording(
                "call-1",
                "sip:srs@10.0.0.5:5060",
                "sip:alice@example.com",
                "sip:bob@example.com",
                sdp.as_bytes(),
                "10.0.0.1:5060".parse().unwrap(),
                None,
                None,
                None,
                None,
                Some("SIPhon/0.1.3"),
            )
            .unwrap();

        let bytes = message.to_bytes();
        let raw = String::from_utf8_lossy(&bytes);
        assert!(raw.contains("User-Agent: SIPhon/0.1.3"));
        assert!(!raw.contains("User-Agent: SIPhon\r\n"));
    }

    #[test]
    fn split_dual_sdp_produces_two_single_m_sdps() {
        let sdp = concat!(
            "v=0\r\n",
            "o=siphon 1 1 IN IP4 10.0.0.1\r\n",
            "s=siphon\r\n",
            "t=0 0\r\n",
            "m=audio 30000 RTP/AVP 8\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "a=label:0\r\n",
            "a=sendonly\r\n",
            "m=audio 30100 RTP/AVP 8\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "a=label:1\r\n",
            "a=sendonly\r\n",
        );

        let (sdp1, sdp2) = split_dual_sdp(sdp.as_bytes());
        let s1 = String::from_utf8_lossy(&sdp1);
        let s2 = String::from_utf8_lossy(&sdp2);

        // Each SDP has exactly one m= line.
        assert_eq!(s1.matches("m=audio").count(), 1);
        assert_eq!(s2.matches("m=audio").count(), 1);

        // Both have session headers.
        assert!(s1.contains("v=0"));
        assert!(s2.contains("v=0"));
        assert!(s1.contains("o=siphon"));
        assert!(s2.contains("o=siphon"));

        // First gets port 30000, second gets port 30100.
        assert!(s1.contains("m=audio 30000"));
        assert!(s2.contains("m=audio 30100"));
    }

    #[test]
    fn split_dual_sdp_replaces_inactive_with_sendonly() {
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "t=0 0\r\n",
            "m=audio 30000 RTP/AVP 8\r\n",
            "a=inactive\r\n",
            "m=audio 30100 RTP/AVP 8\r\n",
            "a=inactive\r\n",
        );

        let (sdp1, sdp2) = split_dual_sdp(sdp.as_bytes());
        let s1 = String::from_utf8_lossy(&sdp1);
        let s2 = String::from_utf8_lossy(&sdp2);

        assert!(s1.contains("a=sendonly"));
        assert!(s2.contains("a=sendonly"));
        assert!(!s1.contains("a=inactive"));
        assert!(!s2.contains("a=inactive"));
    }

    #[test]
    fn split_single_m_sdp_duplicates() {
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "t=0 0\r\n",
            "m=audio 30000 RTP/AVP 8\r\n",
            "a=sendonly\r\n",
        );

        let (sdp1, sdp2) = split_dual_sdp(sdp.as_bytes());
        assert_eq!(sdp1, sdp2, "single m= SDP should be duplicated");
    }

    #[test]
    fn combine_srs_answer_sdps_produces_recvonly_labeled() {
        let offer_sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "t=0 0\r\n",
            "m=audio 20000 RTP/AVP 8\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "a=sendrecv\r\n",
        );
        let answer_sdp = concat!(
            "v=0\r\n",
            "o=- 2 2 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "t=0 0\r\n",
            "m=audio 20100 RTP/AVP 8\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "a=sendrecv\r\n",
        );

        let combined = combine_srs_answer_sdps(offer_sdp.as_bytes(), answer_sdp.as_bytes());
        let result = String::from_utf8_lossy(&combined);

        // Two m= lines.
        assert_eq!(result.matches("m=audio").count(), 2);
        assert!(result.contains("m=audio 20000"));
        assert!(result.contains("m=audio 20100"));

        // Both recvonly (SRS receives from SRC).
        assert_eq!(result.matches("a=recvonly").count(), 2);
        assert!(!result.contains("a=sendrecv"));

        // Labeled 0 and 1.
        assert!(result.contains("a=label:0"));
        assert!(result.contains("a=label:1"));

        // Session headers from offer only (no duplicates).
        assert_eq!(result.matches("v=0").count(), 1);
    }

    #[test]
    fn start_recording_dual_sdp_produces_two_m_lines() {
        let manager = RecordingManager::new("SIPhon", "0.1.0");
        let fallback_sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "t=0 0\r\n",
            "m=audio 10000 RTP/AVP 0\r\n",
            "a=sendrecv\r\n",
        );

        // Simulate two per-direction SDPs from split_dual_sdp after
        // subscribe_request_siprec + fix_siprec_subscribe_sdp.
        let caller_sdp = concat!(
            "v=0\r\n",
            "o=siphon 1 1 IN IP4 10.0.0.1\r\n",
            "s=siphon\r\n",
            "t=0 0\r\n",
            "m=audio 30000 RTP/AVP 8 101\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "a=rtpmap:8 PCMA/8000\r\n",
            "a=rtpmap:101 telephone-event/8000\r\n",
            "a=sendonly\r\n",
            "a=label:0\r\n",
        );
        let callee_sdp = concat!(
            "v=0\r\n",
            "o=siphon 1 1 IN IP4 10.0.0.1\r\n",
            "s=siphon\r\n",
            "t=0 0\r\n",
            "m=audio 30100 RTP/AVP 8 101\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "a=rtpmap:8 PCMA/8000\r\n",
            "a=rtpmap:101 telephone-event/8000\r\n",
            "a=sendonly\r\n",
            "a=label:1\r\n",
        );

        let (_session_id, message, _destination, _transport) = manager
            .start_recording(
                "call-dual",
                "sip:srs@10.0.0.5:5060",
                "sip:alice@example.com",
                "sip:bob@example.com",
                fallback_sdp.as_bytes(),
                "10.0.0.1:5060".parse().unwrap(),
                Some(caller_sdp.as_bytes()),
                Some(callee_sdp.as_bytes()),
                Some("original-call-id"),
                Some(("", "subscriber-to-tag")),
                None,
            )
            .unwrap();

        let bytes = message.to_bytes();
        let raw = String::from_utf8_lossy(&bytes);

        // The INVITE body must contain 2 m= lines (both monologues).
        assert_eq!(
            raw.matches("m=audio").count(),
            2,
            "SIPREC INVITE must have 2 m=audio lines for both monologues"
        );
        // Both should be sendonly (SRC → SRS direction).
        assert_eq!(raw.matches("a=sendonly").count(), 2);
        // Labels must be present and distinct.
        assert!(raw.contains("a=label:0"));
        assert!(raw.contains("a=label:1"));
        // Both ports present.
        assert!(raw.contains("m=audio 30000"));
        assert!(raw.contains("m=audio 30100"));
        // Multipart body with SDP + metadata.
        assert!(raw.contains("Content-Type: multipart/mixed"));
        assert!(raw.contains("application/sdp"));
        assert!(raw.contains("application/rs-metadata+xml"));
    }

    #[test]
    fn start_recording_single_sdp_fallback() {
        let manager = RecordingManager::new("SIPhon", "0.1.0");
        let fallback_sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "t=0 0\r\n",
            "m=audio 10000 RTP/AVP 0\r\n",
            "a=sendrecv\r\n",
        );

        // Only caller SDP — callee is None (single-monologue fallback).
        let caller_sdp = concat!(
            "v=0\r\n",
            "o=siphon 1 1 IN IP4 10.0.0.1\r\n",
            "s=siphon\r\n",
            "t=0 0\r\n",
            "m=audio 30000 RTP/AVP 8\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "a=recvonly\r\n",
        );

        let (_session_id, message, _destination, _transport) = manager
            .start_recording(
                "call-single",
                "sip:srs@10.0.0.5:5060",
                "sip:alice@example.com",
                "sip:bob@example.com",
                fallback_sdp.as_bytes(),
                "10.0.0.1:5060".parse().unwrap(),
                Some(caller_sdp.as_bytes()),
                None,
                None,
                None,
                None,
            )
            .unwrap();

        let bytes = message.to_bytes();
        let raw = String::from_utf8_lossy(&bytes);

        // Single m= line fallback.
        assert_eq!(
            raw.matches("m=audio").count(),
            1,
            "single-direction fallback should have 1 m=audio line"
        );
        // Direction flipped to sendonly.
        assert!(raw.contains("a=sendonly"));
        assert!(!raw.contains("a=recvonly"));
    }

    #[test]
    fn sweep_stale_reaps_old_session_keeps_fresh() {
        let manager = RecordingManager::new("SIPhon", "0.1.0");
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "t=0 0\r\n",
            "m=audio 10000 RTP/AVP 0\r\n",
            "a=sendrecv\r\n",
        );

        // One session that we'll age into staleness.
        let (old_id, old_message, _, _) = manager
            .start_recording(
                "old-call",
                "sip:srs@10.0.0.5:5060",
                "sip:alice@example.com",
                "sip:bob@example.com",
                sdp.as_bytes(),
                "10.0.0.1:5060".parse().unwrap(),
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();

        // One fresh session that must survive the sweep.
        let (fresh_id, _, _, _) = manager
            .start_recording(
                "fresh-call",
                "sip:srs@10.0.0.5:5060",
                "sip:alice@example.com",
                "sip:bob@example.com",
                sdp.as_bytes(),
                "10.0.0.1:5060".parse().unwrap(),
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();

        // Capture the old session's branch so we can assert its alias is cleared.
        let old_raw = String::from_utf8_lossy(&old_message.to_bytes()).into_owned();
        let old_branch = old_raw
            .lines()
            .find(|line| line.starts_with("Via:"))
            .and_then(|line| line.split("branch=").nth(1))
            .map(|value| value.split(';').next().unwrap_or(value).trim().to_string())
            .unwrap();

        // Force the old session to look 48 h old.
        manager.sessions.get_mut(&old_id).unwrap().created_at -=
            std::time::Duration::from_secs(48 * 3600);

        let reaped = manager.sweep_stale(std::time::Duration::from_secs(24 * 3600));
        assert_eq!(reaped, 1, "exactly the aged session should be reaped");

        // Old session and all its aliases are gone.
        assert!(manager.sessions.get(&old_id).is_none());
        assert!(manager.call_sessions.get("old-call").is_none());
        assert!(manager.session_for_branch(&old_branch).is_none());

        // Fresh session and its aliases are untouched.
        assert!(manager.sessions.get(&fresh_id).is_some());
        assert!(manager.call_sessions.get("fresh-call").is_some());
    }
}
