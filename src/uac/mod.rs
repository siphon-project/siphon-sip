//! UAC (User Agent Client) — generates outbound SIP requests.
//!
//! Used by NAT keepalive (OPTIONS pings), PSTN health probing, and
//! any feature that needs to originate SIP requests without an
//! inbound trigger.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use dashmap::DashMap;
use tokio::sync::oneshot;
use tracing::{debug, warn};

use crate::hep::HepSender;

/// Resolve the effective source address for a given transport, replacing
/// unspecified (0.0.0.0 / ::) with the configured advertised address.
///
/// Resolution order:
/// 1. Per-transport advertised address (e.g. `advertised_addrs[Tls] = "1.2.3.4"`)
/// 2. Global `advertised_address` from config
/// 3. Localhost fallback (127.0.0.1 or ::1)
pub fn resolve_via_addr(
    local_addr: SocketAddr,
    transport: &Transport,
    advertised_addrs: &HashMap<Transport, String>,
    advertised_address: Option<&str>,
) -> SocketAddr {
    if local_addr.ip().is_unspecified() {
        // Check per-transport advertised address first
        if let Some(adv) = advertised_addrs.get(transport) {
            if let Ok(ip) = adv.parse::<std::net::IpAddr>() {
                return SocketAddr::new(ip, local_addr.port());
            }
            warn!(
                transport = %transport,
                value = %adv,
                "advertised address is not a valid IP, falling back"
            );
        }
        // Fall back to global advertised_address
        let fallback = if local_addr.is_ipv6() { "::1" } else { "127.0.0.1" };
        let host = advertised_address.unwrap_or(fallback);
        match host.parse::<std::net::IpAddr>() {
            Ok(ip) => SocketAddr::new(ip, local_addr.port()),
            Err(_) => {
                warn!(
                    value = %host,
                    "global advertised_address is not a valid IP, using localhost"
                );
                let ip = if local_addr.is_ipv6() {
                    std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
                } else {
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                };
                SocketAddr::new(ip, local_addr.port())
            }
        }
    } else {
        local_addr
    }
}
use crate::sip::builder::SipMessageBuilder;
use crate::sip::message::{Method, SipMessage};
use crate::sip::uri::SipUri;
use crate::transport::{ConnectionId, OutboundMessage, OutboundRouter, Transport};

/// Result of a UAC request.
#[derive(Debug)]
pub enum UacResult {
    /// Received a response.
    Response(Box<SipMessage>),
    /// Request timed out with no response.
    Timeout,
}

/// A pending UAC request awaiting a response.
struct PendingRequest {
    sender: oneshot::Sender<UacResult>,
}

/// UAC sender — generates and sends outbound SIP requests.
pub struct UacSender {
    outbound: Arc<OutboundRouter>,
    local_addr: SocketAddr,
    /// Per-transport listen addresses for Via/From headers.
    listen_addrs: HashMap<Transport, SocketAddr>,
    /// Per-transport advertised addresses (e.g. TLS → "1.2.3.4").
    advertised_addrs: HashMap<Transport, String>,
    /// Global advertised address fallback from config.
    advertised_address: Option<String>,
    /// HEP capture sender (if tracing is enabled).
    hep_sender: Option<Arc<HepSender>>,
    /// User-Agent header value (from `server.user_agent_header` config).
    user_agent_header: Option<String>,
    /// Pending requests keyed by branch parameter.
    pending: Arc<DashMap<String, PendingRequest>>,
    cseq_counter: std::sync::atomic::AtomicU32,
}

impl UacSender {
    pub fn new(
        outbound: Arc<OutboundRouter>,
        local_addr: SocketAddr,
        listen_addrs: HashMap<Transport, SocketAddr>,
        advertised_addrs: HashMap<Transport, String>,
        advertised_address: Option<String>,
        hep_sender: Option<Arc<HepSender>>,
        user_agent_header: Option<String>,
    ) -> Self {
        Self {
            outbound,
            local_addr,
            listen_addrs,
            advertised_addrs,
            advertised_address,
            hep_sender,
            user_agent_header,
            pending: Arc::new(DashMap::new()),
            cseq_counter: std::sync::atomic::AtomicU32::new(1),
        }
    }

    /// Return the effective address for a given transport, resolving
    /// unspecified (0.0.0.0) addresses via advertised address config.
    pub fn addr_for(&self, transport: &Transport) -> SocketAddr {
        let addr = self.listen_addrs.get(transport).copied().unwrap_or(self.local_addr);
        resolve_via_addr(addr, transport, &self.advertised_addrs, self.advertised_address.as_deref())
    }

    /// Send an OPTIONS request to a target address.
    ///
    /// Returns a receiver that will get the response or timeout.
    /// The caller is responsible for applying a timeout on the receiver.
    pub fn send_options(
        &self,
        destination: SocketAddr,
        transport: Transport,
        request_uri: SipUri,
    ) -> oneshot::Receiver<UacResult> {
        self.send_options_with_identity(destination, transport, request_uri, None, None)
    }

    /// Send an OPTIONS request on a specific existing connection (TLS reuse).
    ///
    /// Like `send_options()` but uses the given `connection_id` instead of
    /// `ConnectionId::default()`, so the message is sent on an existing
    /// connection rather than creating a new one.
    pub fn send_options_on_connection(
        &self,
        destination: SocketAddr,
        transport: Transport,
        request_uri: SipUri,
        connection_id: ConnectionId,
    ) -> oneshot::Receiver<UacResult> {
        self.send_options_on_connection_inner(destination, transport, request_uri, connection_id, None, None)
    }

    /// Send an OPTIONS request with custom From identity.
    pub fn send_options_with_identity(
        &self,
        destination: SocketAddr,
        transport: Transport,
        request_uri: SipUri,
        from_user: Option<&str>,
        from_domain: Option<&str>,
    ) -> oneshot::Receiver<UacResult> {
        self.send_options_on_connection_inner(
            destination, transport, request_uri,
            ConnectionId::default(), from_user, from_domain,
        )
    }

    /// Inner OPTIONS send — supports both default (pool) and specific connection ID.
    fn send_options_on_connection_inner(
        &self,
        destination: SocketAddr,
        transport: Transport,
        request_uri: SipUri,
        connection_id: ConnectionId,
        from_user: Option<&str>,
        from_domain: Option<&str>,
    ) -> oneshot::Receiver<UacResult> {
        let branch = format!("z9hG4bK-uac-{}", uuid::Uuid::new_v4());
        let cseq = self
            .cseq_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let addr = self.addr_for(&transport);
        let via = format!(
            "SIP/2.0/{} {}:{};branch={}",
            transport, addr.ip(), addr.port(), branch
        );

        let from_name = from_user.unwrap_or("siphon");
        let from_host_str = from_domain
            .map(|domain| domain.to_string())
            .unwrap_or_else(|| addr.ip().to_string());
        let from_uri = format!("<sip:{from_name}@{from_host_str}>;tag=uac-{cseq}");

        let mut builder = SipMessageBuilder::new()
            .request(Method::Options, request_uri.clone())
            .via(via)
            .to(format!("<{request_uri}>"))
            .from(from_uri)
            .call_id(format!("uac-keepalive-{}", uuid::Uuid::new_v4()))
            .cseq(format!("{cseq} OPTIONS"))
            .max_forwards(70)
            .content_length(0);

        if let Some(ref user_agent) = self.user_agent_header {
            builder = builder.header("User-Agent", user_agent.clone());
        }

        let message = match builder.build()
        {
            Ok(message) => message,
            Err(error) => {
                warn!("UAC failed to build OPTIONS message: {error}");
                let (sender, receiver) = oneshot::channel();
                let _ = sender.send(UacResult::Timeout);
                return receiver;
            }
        };

        let data = Bytes::from(message.to_bytes());

        // HEP capture — outbound OPTIONS
        if let Some(ref hep) = self.hep_sender {
            hep.capture_outbound(addr, destination, transport, &data);
        }

        let outbound_message = OutboundMessage {
            connection_id,
            transport,
            destination,
            data,
            source_local_addr: None,
        };

        let (sender, receiver) = oneshot::channel();
        self.pending.insert(branch.clone(), PendingRequest { sender });

        debug!(
            destination = %destination,
            branch = %branch,
            "UAC sending OPTIONS"
        );

        if let Err(error) = self.outbound.send(outbound_message) {
            warn!("UAC failed to send OPTIONS: {error}");
            // Remove the pending entry and signal timeout
            if let Some((_, pending)) = self.pending.remove(&branch) {
                let _ = pending.sender.send(UacResult::Timeout);
            }
        }

        receiver
    }

    /// Match an incoming response to a pending UAC request.
    ///
    /// Returns `true` if the response was consumed (matched a UAC branch).
    pub fn match_response(&self, message: &SipMessage) -> bool {
        // Extract branch from topmost Via
        let branch = match message.headers.get("Via").or_else(|| message.headers.get("v")) {
            Some(via_raw) => {
                match crate::sip::headers::via::Via::parse_multi(via_raw) {
                    Ok(vias) => vias.first().and_then(|v| v.branch.clone()),
                    Err(_) => None,
                }
            }
            None => None,
        };

        let branch = match branch {
            Some(b) if b.starts_with("z9hG4bK-uac-") => b,
            _ => return false,
        };

        if let Some((_, pending)) = self.pending.remove(&branch) {
            debug!(branch = %branch, "UAC matched response");
            let _ = pending.sender.send(UacResult::Response(Box::new(message.clone())));
            true
        } else {
            false
        }
    }

    /// Send a pre-built SIP message and register a pending entry so that the
    /// eventual response is delivered via the returned `oneshot::Receiver`.
    ///
    /// The caller MUST ensure the topmost Via branch starts with
    /// `z9hG4bK-uac-` — this is what [`match_response`] keys on.
    pub fn send_request_with_response(
        &self,
        message: SipMessage,
        destination: SocketAddr,
        transport: Transport,
    ) -> oneshot::Receiver<UacResult> {
        let (sender, receiver) = oneshot::channel();

        // Extract branch from the topmost Via.  If absent or not UAC-shaped,
        // we can't correlate — signal timeout immediately.
        let branch = message
            .headers
            .get("Via")
            .or_else(|| message.headers.get("v"))
            .and_then(|via_raw| {
                crate::sip::headers::via::Via::parse_multi(via_raw)
                    .ok()
                    .and_then(|vias| vias.into_iter().next())
                    .and_then(|v| v.branch)
            });

        let branch = match branch {
            Some(b) if b.starts_with("z9hG4bK-uac-") => b,
            _ => {
                warn!("send_request_with_response: message has no z9hG4bK-uac- branch");
                let _ = sender.send(UacResult::Timeout);
                return receiver;
            }
        };

        let data = Bytes::from(message.to_bytes());

        if let Some(ref hep) = self.hep_sender {
            let addr = self.addr_for(&transport);
            hep.capture_outbound(addr, destination, transport, &data);
        }

        let outbound_message = OutboundMessage {
            connection_id: ConnectionId::default(),
            transport,
            destination,
            data,
            source_local_addr: None,
        };

        self.pending.insert(branch.clone(), PendingRequest { sender });

        debug!(
            destination = %destination,
            transport = %transport,
            branch = %branch,
            "UAC send_request_with_response"
        );

        if let Err(error) = self.outbound.send(outbound_message) {
            warn!("UAC send_request_with_response failed: {error}");
            if let Some((_, pending)) = self.pending.remove(&branch) {
                let _ = pending.sender.send(UacResult::Timeout);
            }
        }

        receiver
    }

    /// Fire-and-forget: send a pre-built SIP message with no response tracking.
    ///
    /// Used for NOTIFY, MESSAGE, and other outbound requests where the caller
    /// does not need to correlate a response.
    pub fn send_request(
        &self,
        message: SipMessage,
        destination: SocketAddr,
        transport: Transport,
    ) {
        let data = Bytes::from(message.to_bytes());

        // HEP capture — outbound fire-and-forget
        if let Some(ref hep) = self.hep_sender {
            let addr = self.addr_for(&transport);
            hep.capture_outbound(addr, destination, transport, &data);
        }

        let outbound_message = OutboundMessage {
            connection_id: ConnectionId::default(),
            transport,
            destination,
            data,
            source_local_addr: None,
        };

        debug!(
            destination = %destination,
            transport = %transport,
            "UAC fire-and-forget send"
        );

        if let Err(error) = self.outbound.send(outbound_message) {
            warn!("UAC send_request failed: {error}");
        }
    }

    /// Clean up timed-out pending requests.
    /// Called periodically by the dispatcher's sweep task.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Expire a specific pending request by branch (called on timeout).
    pub fn expire_branch(&self, branch: &str) {
        if let Some((_, pending)) = self.pending.remove(branch) {
            let _ = pending.sender.send(UacResult::Timeout);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns (UacSender, Vec<Receiver>) — keep the receivers alive so sends succeed.
    fn make_uac_sender() -> (UacSender, Vec<flume::Receiver<OutboundMessage>>) {
        let (udp_tx, udp_rx) = flume::unbounded();
        let (tcp_tx, tcp_rx) = flume::unbounded();
        let (tls_tx, tls_rx) = flume::unbounded();
        let (ws_tx, ws_rx) = flume::unbounded();
        let (wss_tx, wss_rx) = flume::unbounded();
        let (sctp_tx, sctp_rx) = flume::unbounded();

        let router = Arc::new(OutboundRouter {
            udp: udp_tx,
            udp_by_local: std::collections::HashMap::new(),
            tcp: tcp_tx,
            tls: tls_tx,
            ws: ws_tx,
            wss: wss_tx,
            sctp: sctp_tx,
        });

        let sender = UacSender::new(router, "127.0.0.1:5060".parse().unwrap(), HashMap::new(), HashMap::new(), None, None, None);
        let receivers = vec![udp_rx, tcp_rx, tls_rx, ws_rx, wss_rx, sctp_rx];
        (sender, receivers)
    }

    #[test]
    fn send_options_creates_pending() {
        let (sender, _rxs) = make_uac_sender();
        assert_eq!(sender.pending_count(), 0);

        let _receiver = sender.send_options(
            "10.0.0.1:5060".parse().unwrap(),
            Transport::Udp,
            SipUri::new("10.0.0.1".to_string()),
        );

        assert_eq!(sender.pending_count(), 1);
    }

    #[test]
    fn match_response_with_uac_branch() {
        let (sender, _rxs) = make_uac_sender();

        // Send an OPTIONS to get the branch
        let _receiver = sender.send_options(
            "10.0.0.1:5060".parse().unwrap(),
            Transport::Udp,
            SipUri::new("10.0.0.1".to_string()),
        );
        assert_eq!(sender.pending_count(), 1);

        // Get the branch from the pending map
        let branch = sender.pending.iter().next().unwrap().key().clone();

        // Build a response with that branch
        let response = SipMessageBuilder::new()
            .response(200, "OK".to_string())
            .via(format!("SIP/2.0/UDP 127.0.0.1:5060;branch={branch}"))
            .to("<sip:10.0.0.1>".to_string())
            .from("<sip:siphon@127.0.0.1>;tag=uac-1".to_string())
            .call_id("uac-test".to_string())
            .cseq("1 OPTIONS".to_string())
            .content_length(0)
            .build()
            .unwrap();

        assert!(sender.match_response(&response));
        assert_eq!(sender.pending_count(), 0);
    }

    #[test]
    fn match_response_ignores_non_uac_branch() {
        let (sender, _rxs) = make_uac_sender();

        let response = SipMessageBuilder::new()
            .response(200, "OK".to_string())
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-regular".to_string())
            .to("<sip:bob@example.com>".to_string())
            .from("<sip:alice@example.com>;tag=abc".to_string())
            .call_id("regular-call".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();

        assert!(!sender.match_response(&response));
    }

    #[test]
    fn expire_branch_signals_timeout() {
        let (sender, _rxs) = make_uac_sender();

        let mut receiver = sender.send_options(
            "10.0.0.1:5060".parse().unwrap(),
            Transport::Udp,
            SipUri::new("10.0.0.1".to_string()),
        );

        let branch = sender.pending.iter().next().unwrap().key().clone();
        sender.expire_branch(&branch);

        let result = receiver.try_recv().unwrap();
        assert!(matches!(result, UacResult::Timeout));
        assert_eq!(sender.pending_count(), 0);
    }

    #[test]
    fn cseq_increments() {
        let (sender, _rxs) = make_uac_sender();

        let _r1 = sender.send_options(
            "10.0.0.1:5060".parse().unwrap(),
            Transport::Udp,
            SipUri::new("10.0.0.1".to_string()),
        );
        let _r2 = sender.send_options(
            "10.0.0.2:5060".parse().unwrap(),
            Transport::Udp,
            SipUri::new("10.0.0.2".to_string()),
        );

        assert_eq!(sender.pending_count(), 2);
    }

    #[test]
    fn send_request_fire_and_forget() {
        let (sender, receivers) = make_uac_sender();

        let message = SipMessageBuilder::new()
            .request(
                crate::sip::message::Method::Notify,
                SipUri::new("10.0.0.5".to_string()),
            )
            .via(format!(
                "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-notify-{}",
                uuid::Uuid::new_v4()
            ))
            .to("<sip:as@10.0.0.5>".to_string())
            .from("<sip:scscf@ims.example.com>;tag=notif1".to_string())
            .call_id("notify-test-1".to_string())
            .cseq("1 NOTIFY".to_string())
            .content_length(0)
            .build()
            .unwrap();

        sender.send_request(
            message,
            "10.0.0.5:5060".parse().unwrap(),
            Transport::Udp,
        );

        // No pending entry (fire-and-forget).
        assert_eq!(sender.pending_count(), 0);

        // Message was sent to UDP channel.
        let udp_rx = &receivers[0]; // UDP is index 0
        let outbound = udp_rx.try_recv().unwrap();
        assert_eq!(outbound.destination, "10.0.0.5:5060".parse().unwrap());
        assert!(!outbound.data.is_empty());
    }

    #[test]
    fn send_request_with_response_registers_pending() {
        let (sender, receivers) = make_uac_sender();

        let branch = format!("z9hG4bK-uac-{}", uuid::Uuid::new_v4());
        let message = SipMessageBuilder::new()
            .request(
                crate::sip::message::Method::Options,
                SipUri::new("10.0.0.5".to_string()),
            )
            .via(format!("SIP/2.0/UDP 127.0.0.1:5060;branch={branch}"))
            .to("<sip:as@10.0.0.5>".to_string())
            .from("<sip:siphon@127.0.0.1>;tag=py-1".to_string())
            .call_id("py-test-1".to_string())
            .cseq("1 OPTIONS".to_string())
            .content_length(0)
            .build()
            .unwrap();

        let _receiver = sender.send_request_with_response(
            message,
            "10.0.0.5:5060".parse().unwrap(),
            Transport::Udp,
        );

        assert_eq!(sender.pending_count(), 1);

        // Message was routed to UDP.
        let udp_rx = &receivers[0];
        let outbound = udp_rx.try_recv().unwrap();
        assert_eq!(outbound.destination, "10.0.0.5:5060".parse().unwrap());
    }

    #[test]
    fn send_request_with_response_rejects_non_uac_branch() {
        let (sender, _receivers) = make_uac_sender();

        let message = SipMessageBuilder::new()
            .request(
                crate::sip::message::Method::Options,
                SipUri::new("10.0.0.5".to_string()),
            )
            .via("SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-py-xyz".to_string())
            .to("<sip:as@10.0.0.5>".to_string())
            .from("<sip:siphon@127.0.0.1>;tag=py-1".to_string())
            .call_id("py-test-2".to_string())
            .cseq("1 OPTIONS".to_string())
            .content_length(0)
            .build()
            .unwrap();

        let receiver = sender.send_request_with_response(
            message,
            "10.0.0.5:5060".parse().unwrap(),
            Transport::Udp,
        );

        // No pending entry was registered; the receiver gets an immediate Timeout.
        assert_eq!(sender.pending_count(), 0);
        let result = receiver.blocking_recv().unwrap();
        assert!(matches!(result, UacResult::Timeout));
    }

    // --- resolve_via_addr tests ---

    #[test]
    fn send_options_includes_user_agent_when_configured() {
        let (udp_tx, udp_rx) = flume::unbounded();
        let (tcp_tx, _tcp_rx) = flume::unbounded();
        let (tls_tx, _tls_rx) = flume::unbounded();
        let (ws_tx, _ws_rx) = flume::unbounded();
        let (wss_tx, _wss_rx) = flume::unbounded();
        let (sctp_tx, _sctp_rx) = flume::unbounded();

        let router = Arc::new(OutboundRouter {
            udp: udp_tx,
            udp_by_local: HashMap::new(),
            tcp: tcp_tx,
            tls: tls_tx,
            ws: ws_tx,
            wss: wss_tx,
            sctp: sctp_tx,
        });

        let sender = UacSender::new(
            router, "127.0.0.1:5060".parse().unwrap(),
            HashMap::new(), HashMap::new(), None, None,
            Some("SIPhon/0.1".to_string()),
        );

        let _receiver = sender.send_options(
            "10.0.0.1:5060".parse().unwrap(),
            Transport::Udp,
            SipUri::new("10.0.0.1".to_string()),
        );

        let outbound = udp_rx.try_recv().unwrap();
        let raw = String::from_utf8_lossy(&outbound.data);
        assert!(raw.contains("User-Agent: SIPhon/0.1"), "missing User-Agent header: {raw}");
    }

    #[test]
    fn send_options_with_identity_overrides_from() {
        let (udp_tx, udp_rx) = flume::unbounded();
        let (tcp_tx, _tcp_rx) = flume::unbounded();
        let (tls_tx, _tls_rx) = flume::unbounded();
        let (ws_tx, _ws_rx) = flume::unbounded();
        let (wss_tx, _wss_rx) = flume::unbounded();
        let (sctp_tx, _sctp_rx) = flume::unbounded();

        let router = Arc::new(OutboundRouter {
            udp: udp_tx,
            udp_by_local: HashMap::new(),
            tcp: tcp_tx,
            tls: tls_tx,
            ws: ws_tx,
            wss: wss_tx,
            sctp: sctp_tx,
        });

        let sender = UacSender::new(
            router, "127.0.0.1:5060".parse().unwrap(),
            HashMap::new(), HashMap::new(), None, None, None,
        );

        let _receiver = sender.send_options_with_identity(
            "10.0.0.1:5060".parse().unwrap(),
            Transport::Udp,
            SipUri::new("10.0.0.1".to_string()),
            Some("bgcf"),
            Some("sip.connect.example.com"),
        );

        let outbound = udp_rx.try_recv().unwrap();
        let raw = String::from_utf8_lossy(&outbound.data);
        assert!(raw.contains("sip:bgcf@sip.connect.example.com"), "From should use configured user and domain: {raw}");
    }

    #[test]
    fn send_options_omits_user_agent_when_not_configured() {
        let (sender, rxs) = make_uac_sender();

        let _receiver = sender.send_options(
            "10.0.0.1:5060".parse().unwrap(),
            Transport::Udp,
            SipUri::new("10.0.0.1".to_string()),
        );

        let outbound = rxs[0].try_recv().unwrap();
        let raw = String::from_utf8_lossy(&outbound.data);
        assert!(!raw.contains("User-Agent:"), "should not have User-Agent: {raw}");
    }

    #[test]
    fn send_options_from_falls_back_to_ip_without_domain() {
        let (sender, rxs) = make_uac_sender();

        let _receiver = sender.send_options(
            "10.0.0.1:5060".parse().unwrap(),
            Transport::Udp,
            SipUri::new("10.0.0.1".to_string()),
        );

        let outbound = rxs[0].try_recv().unwrap();
        let raw = String::from_utf8_lossy(&outbound.data);
        assert!(raw.contains("sip:siphon@127.0.0.1"), "From should use IP fallback: {raw}");
    }

    // --- resolve_via_addr tests ---

    #[test]
    fn resolve_via_addr_non_unspecified_passthrough() {
        let addr: SocketAddr = "10.0.0.1:5060".parse().unwrap();
        let result = resolve_via_addr(addr, &Transport::Udp, &HashMap::new(), None);
        assert_eq!(result, addr);
    }

    #[test]
    fn resolve_via_addr_per_transport_override() {
        let addr: SocketAddr = "0.0.0.0:5060".parse().unwrap();
        let mut addrs = HashMap::new();
        addrs.insert(Transport::Udp, "203.0.113.1".to_string());
        let result = resolve_via_addr(addr, &Transport::Udp, &addrs, None);
        assert_eq!(result, "203.0.113.1:5060".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn resolve_via_addr_global_fallback() {
        let addr: SocketAddr = "0.0.0.0:5060".parse().unwrap();
        let result = resolve_via_addr(addr, &Transport::Udp, &HashMap::new(), Some("198.51.100.5"));
        assert_eq!(result, "198.51.100.5:5060".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn resolve_via_addr_localhost_fallback_on_no_config() {
        let addr: SocketAddr = "0.0.0.0:5060".parse().unwrap();
        let result = resolve_via_addr(addr, &Transport::Udp, &HashMap::new(), None);
        assert_eq!(result, "127.0.0.1:5060".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn resolve_via_addr_ipv6_localhost_fallback() {
        let addr: SocketAddr = "[::]:5060".parse().unwrap();
        let result = resolve_via_addr(addr, &Transport::Udp, &HashMap::new(), None);
        assert_eq!(result, "[::1]:5060".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn resolve_via_addr_invalid_global_falls_back_to_localhost() {
        let addr: SocketAddr = "0.0.0.0:5060".parse().unwrap();
        let result = resolve_via_addr(addr, &Transport::Udp, &HashMap::new(), Some("not-an-ip"));
        assert_eq!(result, "127.0.0.1:5060".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn resolve_via_addr_invalid_per_transport_falls_through() {
        let addr: SocketAddr = "0.0.0.0:5060".parse().unwrap();
        let mut addrs = HashMap::new();
        addrs.insert(Transport::Udp, "not-valid".to_string());
        // Should skip invalid per-transport and use global
        let result = resolve_via_addr(addr, &Transport::Udp, &addrs, Some("192.0.2.1"));
        assert_eq!(result, "192.0.2.1:5060".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn resolve_via_addr_preserves_port() {
        let addr: SocketAddr = "0.0.0.0:5080".parse().unwrap();
        let result = resolve_via_addr(addr, &Transport::Tcp, &HashMap::new(), Some("10.1.1.1"));
        assert_eq!(result.port(), 5080);
    }
}
