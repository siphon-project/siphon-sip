//! Which ports a message a P-CSCF sends to a UE over a security association
//! really leaves from and goes to.
//!
//! 3GPP TS 33.203 clause 7.1, UDP case, and TS 24.229 clause 5.2.2.2 1A a):
//! the flow from the P-CSCF's protected client port to the UE's protected
//! server port "is used by the P-CSCF to send requests and responses to the
//! UE". A response is addressed to the request's source, and a request sent
//! over the UE's captured flow (an MT request relayed with `flow=`, an
//! in-dialog request on that flow, the registrar-liveness OPTIONS) to the UE's
//! source: its protected client port, from the socket the UE's traffic landed
//! on, the P-CSCF's protected server port. That is the flow the UE sends on,
//! never the one it receives on, so both are moved here.
//!
//! TCP, TS 24.229 clause 5.2.2.2 1A b): the P-CSCF's requests go on the
//! connection it "established ... from the P-CSCF's protected client port and
//! the P-CSCF's IP address to the UE's protected server port and the UE's IP
//! address", which is also where the UE's responses to them come back. The
//! UE's own connection (port_uc -> port_ps) carries the UE's requests and the
//! responses to them, so a response is left on it ([`pcscf_tcp_request_egress`]).

use std::net::SocketAddr;

use tracing::{debug, error};

use super::{FlowToUe, IpsecManager};
use crate::transport::{ConnectionId, OutboundMessage, Transport};

/// `(destination, source_local_addr)` for a send of `transport` from `local`
/// to `destination` by a P-CSCF whose protected server port is
/// `pcscf_port_s`: a UDP send leaving that port (or no pinned socket) for a
/// UE's protected client port goes from the P-CSCF's protected client port to the UE's protected
/// server port instead ([`IpsecManager::udp_flow_to_ue`], one map lookup).
/// Anything else is returned unchanged. Nothing is dropped: a pair that
/// cannot carry UDP is logged and the message goes where it was going.
pub fn pcscf_udp_egress(
    manager: &IpsecManager,
    pcscf_port_s: u16,
    transport: Transport,
    destination: SocketAddr,
    local: Option<SocketAddr>,
) -> (SocketAddr, Option<SocketAddr>) {
    let unchanged = (destination, local);
    // Unpinned, the send would leave from a default socket outside every
    // security association, so it is moved too.
    if transport != Transport::Udp || local.is_some_and(|local| local.port() != pcscf_port_s) {
        return unchanged;
    }
    match manager.udp_flow_to_ue(destination) {
        FlowToUe::NotProtected => unchanged,
        FlowToUe::Protected {
            local: protected_local,
            destination: protected,
        } => {
            debug!(
                from = %destination,
                to = %protected,
                local = %protected_local,
                "IPsec: UDP send to the UE's protected server port (TS 33.203 clause 7.1)"
            );
            (protected, Some(protected_local))
        }
        FlowToUe::Unusable(protocol) => {
            error!(
                %destination,
                %protocol,
                "IPsec: the security association of this UE does not carry UDP, so the UDP \
                 message cannot reach its protected server port; sending it unchanged"
            );
            unchanged
        }
    }
}

/// `message` as it really goes out, for a P-CSCF whose protected server port
/// is `pcscf_port_s`: a TCP request to a UE's protected client port, leaving
/// from that port (or not pinned), is taken off the UE's connection and onto
/// the one the P-CSCF opens from its protected client port to the UE's
/// protected server port ([`IpsecManager::tcp_flow_to_ue`], one map lookup).
/// The connection id is cleared, so the stream distributor finds no live
/// connection and hands the message to the outbound pool, which opens that
/// connection bound to the protected client port once and reuses it; the
/// UE's responses on it are read into the inbound path like any pool
/// connection's.
///
/// Anything else is returned unchanged: a response (it belongs on the
/// connection its request came over), a CRLF keepalive, a send to an address
/// with no pair, a UE-role pair. Nothing is dropped: a pair that cannot carry
/// TCP is logged and the message goes where it was going.
pub fn pcscf_tcp_request_egress(
    manager: &IpsecManager,
    pcscf_port_s: u16,
    mut message: OutboundMessage,
) -> OutboundMessage {
    if message.transport != Transport::Tcp
        || message
            .source_local_addr
            .is_some_and(|local| local.port() != pcscf_port_s)
        || !is_request(&message.data)
    {
        return message;
    }
    match manager.tcp_flow_to_ue(message.destination) {
        FlowToUe::NotProtected => message,
        FlowToUe::Protected { local, destination } => {
            debug!(
                from = %message.destination,
                to = %destination,
                local = %local,
                "IPsec: TCP request on the P-CSCF's own connection to the UE's protected \
                 server port (TS 24.229 clause 5.2.2.2 1A b)"
            );
            message.destination = destination;
            message.source_local_addr = Some(local);
            message.connection_id = ConnectionId::default();
            message
        }
        FlowToUe::Unusable(protocol) => {
            error!(
                destination = %message.destination,
                %protocol,
                "IPsec: the security association of this UE does not carry TCP, so the TCP \
                 request cannot reach its protected server port; sending it unchanged"
            );
            message
        }
    }
}

/// Whether `frame` is a serialized SIP request: it starts with a method
/// token, which a response (`SIP/2.0 ...`) and a CRLF keepalive do not.
fn is_request(frame: &[u8]) -> bool {
    frame.first().is_some_and(u8::is_ascii_uppercase)
        && !crate::transport::response_route::is_response(frame)
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::time::Instant;

    use super::super::{
        EncryptionAlgorithm, IntegrityAlgorithm, SaProtocol, SaRole, SecurityAssociationPair,
    };
    use super::*;

    fn sock(text: &str) -> SocketAddr {
        text.parse().expect("a socket address literal")
    }

    /// A pair for the UE at `ue` (port_uc 6100, port_us 6101) through a
    /// P-CSCF at 192.0.2.1 (port_pc 5064, port_ps 5066).
    fn pair(role: SaRole, ue: &str) -> SecurityAssociationPair {
        SecurityAssociationPair {
            ue_addr: ue.parse::<IpAddr>().expect("an address"),
            pcscf_addr: "192.0.2.1".parse().expect("an address"),
            ue_port_c: 6100,
            ue_port_s: 6101,
            pcscf_port_c: 5064,
            pcscf_port_s: 5066,
            spi_uc: 1,
            spi_us: 2,
            spi_pc: 3,
            spi_ps: 4,
            ealg: EncryptionAlgorithm::Null,
            aalg: IntegrityAlgorithm::HmacSha1,
            encryption_key: String::new(),
            integrity_key: "00112233445566778899aabbccddeeff".to_string(),
            hard_lifetime_secs: Some(3600),
            protocol: SaProtocol::Any,
            expires_at: Instant::now(),
            created_at: Instant::now(),
            role,
            impi: None,
            security_server: None,
        }
    }

    fn manager_with(sa: SecurityAssociationPair) -> IpsecManager {
        let manager = IpsecManager::new();
        let key = IpsecManager::contact_key(&sa.ue_addr, sa.ue_port_c);
        manager.associations.insert(key, sa);
        manager
    }

    /// A request over the UE's flow (port_ps -> port_uc) goes
    /// port_pc -> port_us, as the responses do.
    #[test]
    fn a_send_over_the_ue_flow_goes_from_port_pc_to_port_us() {
        let manager = manager_with(pair(SaRole::PCscf, "198.51.100.30"));
        assert_eq!(
            pcscf_udp_egress(
                &manager,
                5066,
                Transport::Udp,
                sock("198.51.100.30:6100"),
                Some(sock("192.0.2.1:5066")),
            ),
            (sock("198.51.100.30:6101"), Some(sock("192.0.2.1:5064")))
        );
    }

    /// Already on the right flow, from another socket, to a peer with no
    /// pair, over TCP, or a UE-role pair: left alone.
    #[test]
    fn other_sends_are_left_alone() {
        let manager = manager_with(pair(SaRole::PCscf, "198.51.100.31"));
        for (transport, destination, local) in [
            (Transport::Udp, "198.51.100.31:6101", Some("192.0.2.1:5064")),
            (Transport::Udp, "198.51.100.31:6100", Some("192.0.2.1:5060")),
            (Transport::Udp, "198.51.100.32:6100", Some("192.0.2.1:5066")),
            (Transport::Tcp, "198.51.100.31:6100", Some("192.0.2.1:5066")),
        ] {
            let destination = sock(destination);
            let local = local.map(sock);
            assert_eq!(
                pcscf_udp_egress(&manager, 5066, transport, destination, local),
                (destination, local),
                "{transport} {destination} from {local:?}"
            );
        }
        assert_eq!(
            pcscf_udp_egress(
                &manager,
                5066,
                Transport::Udp,
                sock("198.51.100.31:6100"),
                None
            ),
            (sock("198.51.100.31:6101"), Some(sock("192.0.2.1:5064"))),
            "unpinned, it would leave outside every security association"
        );
        let ue_role = manager_with(pair(SaRole::Ue, "198.51.100.33"));
        let destination = sock("198.51.100.33:6100");
        let local = Some(sock("192.0.2.1:5066"));
        assert_eq!(
            pcscf_udp_egress(&ue_role, 5066, Transport::Udp, destination, local),
            (destination, local)
        );
    }

    /// A pair that cannot carry UDP keeps the send as it was.
    #[test]
    fn a_tcp_only_pair_keeps_the_send() {
        let mut sa = pair(SaRole::PCscf, "198.51.100.34");
        sa.protocol = SaProtocol::Tcp;
        let manager = manager_with(sa);
        let destination = sock("198.51.100.34:6100");
        let local = Some(sock("192.0.2.1:5066"));
        assert_eq!(
            pcscf_udp_egress(&manager, 5066, Transport::Udp, destination, local),
            (destination, local)
        );
    }

    fn tcp_message(data: &'static [u8], destination: &str, local: Option<&str>) -> OutboundMessage {
        OutboundMessage {
            connection_id: ConnectionId(7),
            transport: Transport::Tcp,
            destination: sock(destination),
            data: bytes::Bytes::from_static(data),
            source_local_addr: local.map(sock),
            server_name: None,
            verify_server: None,
            followups: None,
        }
    }

    const INVITE: &[u8] = b"INVITE sip:001010000000001@198.51.100.40:6101 SIP/2.0\r\n\r\n";
    const OK: &[u8] = b"SIP/2.0 200 OK\r\n\r\n";

    /// (where, from, on which connection) a message leaves.
    fn route(message: &OutboundMessage) -> (SocketAddr, Option<SocketAddr>, ConnectionId) {
        (
            message.destination,
            message.source_local_addr,
            message.connection_id,
        )
    }

    /// A request on the UE's own connection (port_uc -> port_ps) moves to the
    /// connection the P-CSCF opens, port_pc -> port_us (TS 24.229 clause
    /// 5.2.2.2 1A b), with no connection id so the pool opens or reuses it;
    /// unpinned the same.
    #[test]
    fn a_tcp_request_to_the_ue_client_port_goes_from_port_pc_to_port_us() {
        let manager = manager_with(pair(SaRole::PCscf, "198.51.100.40"));
        for local in [Some("192.0.2.1:5066"), None] {
            let moved = pcscf_tcp_request_egress(
                &manager,
                5066,
                tcp_message(INVITE, "198.51.100.40:6100", local),
            );
            assert_eq!(
                route(&moved),
                (
                    sock("198.51.100.40:6101"),
                    Some(sock("192.0.2.1:5064")),
                    ConnectionId::default()
                ),
                "from {local:?}"
            );
        }
    }

    /// A response stays on the connection its request came over, and so do a
    /// CRLF keepalive, a send from another socket, to a peer with no pair, to
    /// the UE's server port already, over UDP, and a UE-role pair.
    #[test]
    fn other_tcp_sends_are_left_alone() {
        let manager = manager_with(pair(SaRole::PCscf, "198.51.100.41"));
        for (data, destination, local) in [
            (OK, "198.51.100.41:6100", Some("192.0.2.1:5066")),
            (
                &b"\r\n\r\n"[..],
                "198.51.100.41:6100",
                Some("192.0.2.1:5066"),
            ),
            (INVITE, "198.51.100.41:6100", Some("192.0.2.1:5060")),
            (INVITE, "198.51.100.42:6100", Some("192.0.2.1:5066")),
            (INVITE, "198.51.100.41:6101", Some("192.0.2.1:5064")),
        ] {
            let message = tcp_message(data, destination, local);
            let before = route(&message);
            assert_eq!(
                route(&pcscf_tcp_request_egress(&manager, 5066, message)),
                before,
                "{destination} from {local:?}"
            );
        }
        let mut udp = tcp_message(INVITE, "198.51.100.41:6100", Some("192.0.2.1:5066"));
        udp.transport = Transport::Udp;
        let before = route(&udp);
        assert_eq!(
            route(&pcscf_tcp_request_egress(&manager, 5066, udp)),
            before
        );

        let ue_role = manager_with(pair(SaRole::Ue, "198.51.100.43"));
        let message = tcp_message(INVITE, "198.51.100.43:6100", Some("192.0.2.1:5066"));
        let before = route(&message);
        assert_eq!(
            route(&pcscf_tcp_request_egress(&ue_role, 5066, message)),
            before
        );
    }

    /// A pair that cannot carry TCP keeps the request where it was going.
    #[test]
    fn a_udp_only_pair_keeps_the_tcp_request() {
        let mut sa = pair(SaRole::PCscf, "198.51.100.44");
        sa.protocol = SaProtocol::Udp;
        let manager = manager_with(sa);
        let message = tcp_message(INVITE, "198.51.100.44:6100", Some("192.0.2.1:5066"));
        let before = route(&message);
        assert_eq!(
            route(&pcscf_tcp_request_egress(&manager, 5066, message)),
            before
        );
    }

    #[test]
    fn a_request_is_told_from_a_response_and_a_keepalive() {
        assert!(is_request(INVITE));
        assert!(!is_request(OK));
        assert!(!is_request(b"\r\n\r\n"));
        assert!(!is_request(b""));
    }
}
