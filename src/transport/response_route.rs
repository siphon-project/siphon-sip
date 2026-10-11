//! Where a response goes once the connection its request arrived on is gone.
//!
//! RFC 3261 §18.2.2: a response to a request that arrived over a reliable
//! transport is sent on the connection the request arrived on, and "if that
//! connection is no longer open, the server SHOULD open a connection to the IP
//! address in the `received` parameter, if present, using the port in the
//! `sent-by` value, or the default port for that transport, if no port is
//! specified".
//!
//! The port is the point. The address a response is handed to the transport
//! with is the one its request came from, and on a stream transport the port
//! of that address is the peer's ephemeral source port: nothing listens there
//! once the connection is closed, so a connect to it is refused. The peer
//! listens on the port it wrote in its Via.
//!
//! The address is left as it is. `received` is by definition the source
//! address of the request (§18.2.1), which is exactly what the response is
//! already addressed to, so the two agree whenever `received` is honest; and
//! taking it from where the request really came from, rather than from a
//! header the peer wrote, means a Via cannot point a response at a third
//! party.
//!
//! `rport` plays no part. It names the source port of a datagram (RFC 3581),
//! which on a connection is the ephemeral port again.

use std::net::SocketAddr;

use crate::sip::headers::via::Via;
use crate::sip::message::{SipMessage, StartLine};
use crate::transport::Transport;

/// Whether `frame` is a serialized SIP response. A request starts with its
/// method, so this is one comparison on the path every fallback send takes.
pub(crate) fn is_response(frame: &[u8]) -> bool {
    frame.starts_with(b"SIP/2.0 ")
}

/// The port a transport is reached on when a sent-by names none
/// (RFC 3261 §18.2.2, §19.1.2).
fn default_port(transport: Transport) -> u16 {
    match transport {
        Transport::Tls | Transport::WebSocketSecure => 5061,
        _ => 5060,
    }
}

/// The header block of `frame` and the first of its Via values, when `frame`
/// is a response that has one.
fn response_and_top_via(frame: &[u8]) -> Option<(SipMessage, Via)> {
    if !is_response(frame) {
        return None;
    }
    let response = crate::sip::parser::parse_sip_headers_only(frame).ok()?;
    let top = Via::parse_multi(response.headers.get("Via")?)
        .ok()?
        .into_iter()
        .next()?;
    Some((response, top))
}

/// Where to connect to deliver response `frame` over `transport`, given the
/// address its request was `received_from`: that address, at the port of the
/// sent-by of its top Via, or at the transport's default port when the sent-by
/// has none.
///
/// `None` when `frame` is not a response or carries no Via that parses. The
/// caller then has nothing better than the address it was given.
pub(crate) fn reconnect_target(
    frame: &[u8],
    transport: Transport,
    received_from: SocketAddr,
) -> Option<SocketAddr> {
    let (_, via) = response_and_top_via(frame)?;
    let port = via.port.unwrap_or_else(|| default_port(transport));
    Some(SocketAddr::new(received_from.ip(), port))
}

/// The transaction response `frame` belongs to, for a log line: its status,
/// the method it answers and the branch of its top Via. `None` when `frame`
/// is not a response.
pub(crate) fn describe_transaction(frame: &[u8]) -> Option<String> {
    let (response, via) = response_and_top_via(frame)?;
    let status_code = match &response.start_line {
        StartLine::Response(status_line) => status_line.status_code,
        StartLine::Request(_) => return None,
    };
    let cseq = response.headers.cseq().map(String::as_str).unwrap_or("?");
    let branch = via.branch.as_deref().unwrap_or("?");
    Some(format!("{status_code} to CSeq {cseq}, branch {branch}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response_with_via(via: &str) -> Vec<u8> {
        format!(
            "SIP/2.0 200 OK\r\n\
             Via: {via}\r\n\
             Via: SIP/2.0/UDP 203.0.113.9:5070;branch=z9hG4bK-caller\r\n\
             From: <sip:caller@example.org>;tag=caller-tag\r\n\
             To: <sip:callee@example.org>;tag=callee-tag\r\n\
             Call-ID: response-route@example.org\r\n\
             CSeq: 1 INVITE\r\n\
             Content-Length: 0\r\n\
             \r\n"
        )
        .into_bytes()
    }

    /// The address the request came from: the peer's address and the
    /// ephemeral port it connected from.
    fn received_from() -> SocketAddr {
        "192.0.2.10:33225".parse().unwrap()
    }

    #[test]
    fn a_response_goes_to_the_sent_by_port_not_the_source_port() {
        let frame = response_with_via("SIP/2.0/TCP 192.0.2.10:5080;branch=z9hG4bK-hop");
        assert_eq!(
            reconnect_target(&frame, Transport::Tcp, received_from()),
            Some("192.0.2.10:5080".parse().unwrap())
        );
    }

    #[test]
    fn a_sent_by_without_a_port_means_the_default_port_of_the_transport() {
        let frame = response_with_via("SIP/2.0/TCP 192.0.2.10;branch=z9hG4bK-hop");
        assert_eq!(
            reconnect_target(&frame, Transport::Tcp, received_from()),
            Some("192.0.2.10:5060".parse().unwrap())
        );
        let frame = response_with_via("SIP/2.0/TLS proxy.example.org;branch=z9hG4bK-hop");
        assert_eq!(
            reconnect_target(&frame, Transport::Tls, received_from()),
            Some("192.0.2.10:5061".parse().unwrap())
        );
    }

    /// `received` is the address the request came from (RFC 3261 §18.2.1), so
    /// with it present the response goes to that address at the sent-by port,
    /// whatever host the sent-by names.
    #[test]
    fn with_received_the_response_goes_to_that_address_at_the_sent_by_port() {
        let frame = response_with_via(
            "SIP/2.0/TCP proxy.example.org:5080;branch=z9hG4bK-hop;received=192.0.2.10",
        );
        assert_eq!(
            reconnect_target(&frame, Transport::Tcp, received_from()),
            Some("192.0.2.10:5080".parse().unwrap())
        );
    }

    /// The address is the one the request really came from. A `received` (or a
    /// sent-by host) that names somewhere else does not move the response
    /// there.
    #[test]
    fn a_via_cannot_point_the_response_at_another_address() {
        let frame = response_with_via(
            "SIP/2.0/TCP 198.51.100.77:5080;branch=z9hG4bK-hop;received=198.51.100.78",
        );
        assert_eq!(
            reconnect_target(&frame, Transport::Tcp, received_from()),
            Some("192.0.2.10:5080".parse().unwrap())
        );
    }

    /// RFC 3581 is about datagrams. On a connection, `rport` is the ephemeral
    /// source port: the one place that is known not to be listening.
    #[test]
    fn the_value_of_rport_is_never_the_port_to_connect_to() {
        let frame = response_with_via(
            "SIP/2.0/TCP 192.0.2.10:5080;branch=z9hG4bK-hop;received=192.0.2.10;rport=33225",
        );
        assert_eq!(
            reconnect_target(&frame, Transport::Tcp, received_from()),
            Some("192.0.2.10:5080".parse().unwrap())
        );
        let frame = response_with_via("SIP/2.0/TCP 192.0.2.10;branch=z9hG4bK-hop;rport=33225");
        assert_eq!(
            reconnect_target(&frame, Transport::Tcp, received_from()),
            Some("192.0.2.10:5060".parse().unwrap())
        );
    }

    #[test]
    fn an_ipv6_peer_keeps_its_address() {
        let frame = response_with_via("SIP/2.0/TCP [2001:db8::10]:5080;branch=z9hG4bK-hop");
        assert_eq!(
            reconnect_target(
                &frame,
                Transport::Tcp,
                "[2001:db8::10]:33225".parse().unwrap()
            ),
            Some("[2001:db8::10]:5080".parse().unwrap())
        );
    }

    #[test]
    fn a_compact_via_is_read_like_a_long_one() {
        let frame = b"SIP/2.0 408 Request Timeout\r\n\
                      v: SIP/2.0/TCP 192.0.2.10:5080;branch=z9hG4bK-hop\r\n\
                      CSeq: 1 INVITE\r\n\
                      l: 0\r\n\
                      \r\n";
        assert_eq!(
            reconnect_target(frame, Transport::Tcp, received_from()),
            Some("192.0.2.10:5080".parse().unwrap())
        );
    }

    /// A request is addressed by whoever sent it (its Request-URI or a Route),
    /// and its top Via is this node's own.
    #[test]
    fn a_request_is_left_alone() {
        let frame = b"OPTIONS sip:callee@192.0.2.10:5090;transport=tcp SIP/2.0\r\n\
                      Via: SIP/2.0/TCP 198.51.100.1:5060;branch=z9hG4bK-own\r\n\
                      CSeq: 1 OPTIONS\r\n\
                      Content-Length: 0\r\n\
                      \r\n";
        assert!(!is_response(frame));
        assert_eq!(
            reconnect_target(frame, Transport::Tcp, received_from()),
            None
        );
        assert_eq!(describe_transaction(frame), None);
    }

    #[test]
    fn a_response_without_a_usable_via_is_left_alone() {
        let frame = b"SIP/2.0 200 OK\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(
            reconnect_target(frame, Transport::Tcp, received_from()),
            None
        );
        assert_eq!(
            reconnect_target(b"SIP/2.0 200", Transport::Tcp, received_from()),
            None
        );
    }

    #[test]
    fn a_response_is_described_by_its_status_cseq_and_branch() {
        let frame = response_with_via("SIP/2.0/TCP 192.0.2.10:5080;branch=z9hG4bK-hop");
        assert_eq!(
            describe_transaction(&frame).as_deref(),
            Some("200 to CSeq 1 INVITE, branch z9hG4bK-hop")
        );
    }
}
