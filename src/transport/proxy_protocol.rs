//! HAProxy PROXY protocol, versions 1 and 2, on inbound stream listeners.
//!
//! A front that terminates the connection — HAProxy, stunnel, a layer4 proxy in
//! front of SIP-TLS — opens its *own* connection to siphon, so the peer address
//! is the front's. Every consumer that keys on the source inherits that: the
//! auto-ban store bans the front rather than the abuser, `from_gateway()` and
//! `source_ip_in()` stop discriminating, NAT return-routing advertises the
//! front, and `media.received_from` gates media ingress to it so no RTP is
//! accepted at all.
//!
//! The PROXY header carries the original endpoints ahead of the payload, in
//! cleartext, so it is read before the SIP sniff and before the TLS handshake.
//! [`parse`] is a pure function over bytes, in the shape of
//! [`sniff_first_line`](super::stream::sniff_first_line), and
//! [`read_proxy_header`] is the bounded read loop around it. The trust check and
//! the address substitution stay at the accept sites, which is where the ACL and
//! the per-source ceilings already live.
//!
//! Version 1 is the text line (`PROXY TCP4 <src> <dst> <sport> <dport>\r\n`),
//! version 2 the binary form behind a 12-byte signature. Both are defined by
//! <https://www.haproxy.org/download/2.8/doc/proxy-protocol.txt>.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use bytes::BytesMut;
use ipnet::IpNet;
use tokio::io::{AsyncRead, AsyncReadExt};
use tracing::{debug, warn};

use super::Transport;

/// v1 signature. The line form is ASCII and ends in CRLF.
pub(crate) const V1_PREFIX: &[u8] = b"PROXY ";

/// v2 signature: 12 bytes chosen to be invalid in every text protocol.
pub(crate) const V2_SIGNATURE: &[u8] = &[
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// Longest possible v1 line, per the spec: 107 bytes plus the CRLF it counts.
/// A line longer than this is not a PROXY header, it is a peer talking nonsense.
const V1_MAX_LEN: usize = 108;

/// Fixed part of a v2 header: signature, ver_cmd, fam, and the 16-bit length.
const V2_HEADER_LEN: usize = 16;

/// Largest v2 body accepted. The address block is at most 36 bytes (IPv6), and
/// the TLVs a front sends are small; this bounds a peer that declares 65535 and
/// then dribbles, which would otherwise pin a connection for the whole read
/// deadline.
const V2_MAX_BODY: usize = 1024;

/// `PROXY` (v2 `\x21`) versus `LOCAL` (`\x20`), the low nibble of ver_cmd.
const V2_CMD_PROXY: u8 = 0x01;
const V2_CMD_LOCAL: u8 = 0x00;

/// Address family / protocol byte: `TCP over IPv4` and `TCP over IPv6`.
const V2_TCP4: u8 = 0x11;
const V2_TCP6: u8 = 0x21;

/// TLV types this parser understands. `PP2_TYPE_SSL` carries the client's TLS
/// session *at the front*, which is the only way a re-encrypting front can tell
/// siphon the phone spoke TLS even though this hop is plaintext.
const PP2_TYPE_SSL: u8 = 0x20;
const PP2_SUBTYPE_SSL_VERSION: u8 = 0x21;
const PP2_CLIENT_SSL: u8 = 0x01;

/// What the client negotiated with the front, from a v2 `PP2_TYPE_SSL` TLV.
///
/// This is deliberately *not* a [`Transport`](super::Transport): the transport
/// siphon accepted and the transport the client used are different facts, and
/// conflating them would route a reply for a plaintext socket over a TLS map.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct EdgeTls {
    /// The client used TLS to reach the front (`PP2_CLIENT_SSL`).
    pub(crate) used_tls: bool,
    /// The front verified the client's certificate. Zero means verified, per
    /// the spec's `<verify>` field, so this is `true` only for a real success.
    pub(crate) client_cert_verified: bool,
    /// `PP2_SUBTYPE_SSL_VERSION`, e.g. `"TLSv1.3"`, when the front sends it.
    pub(crate) version: Option<String>,
}

/// The endpoints a PROXY header declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProxiedAddresses {
    /// The real client. This replaces the peer address at the accept site.
    pub(crate) source: SocketAddr,
    /// The address the client connected to — the front's VIP, not siphon's
    /// socket. Parsed and carried for diagnostics; nothing routes on it yet.
    pub(crate) destination: SocketAddr,
    /// The client's TLS session at the front, when the header carried one.
    pub(crate) edge_tls: Option<EdgeTls>,
}

/// Verdict of [`parse`] on the bytes seen so far.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProxyHeader {
    /// Header complete. `consumed` bytes belong to it; everything after is the
    /// payload and must be replayed to whatever reads the connection next.
    Decided {
        addresses: Box<ProxiedAddresses>,
        consumed: usize,
    },
    /// A header is starting but has not arrived in full — read more.
    NeedMore,
    /// `LOCAL` (v2) or `UNKNOWN` (v1): a health check or a connection the front
    /// opened itself. The header is consumed and the socket's own peer address
    /// stands, which is what HAProxy intends for its own probes.
    NoAddresses { consumed: usize },
    /// Not a PROXY header at all, or a malformed one.
    Invalid,
}

/// True when `buffer` begins with `signature`, or is itself a prefix of it.
///
/// Both directions matter: the sniffer may be holding one segment of a header
/// that is still arriving, and a front whose first segment is four bytes long
/// is still a front, not a scanner.
fn starts_with_or_is_prefix_of(buffer: &[u8], signature: &[u8]) -> bool {
    if buffer.len() >= signature.len() {
        buffer.starts_with(signature)
    } else {
        signature.starts_with(buffer)
    }
}

/// The senders permitted to assert a client address on one listener.
///
/// Built once per listener at startup from `proxy_protocol.from`. There is
/// deliberately no fallback to `security.trusted_cidrs`: that list means
/// "exempt from abuse controls" to all four of its consumers, and is where
/// monitoring boxes and trunks are listed, so inheriting it would hand
/// source-address forgery rights to hosts named there for an unrelated reason.
///
/// Empty means nobody. A PROXY header lets its sender claim to be any address
/// on the internet, so the failure direction has to be closed: a list that
/// degraded to "permit all" would turn the front door into a forgery primitive.
pub struct ProxyProtocolAcl {
    allowed: Vec<IpNet>,
}

impl ProxyProtocolAcl {
    /// `from` has already been through
    /// [`validate_listen`](crate::config::Config::validate_listen), which
    /// refuses an empty list and any entry that is not a CIDR, so a bad entry
    /// here is unreachable from a loaded config. Dropping one rather than
    /// failing is still the safe direction — it can only ever admit fewer
    /// senders, never more.
    pub fn new(from: &[String]) -> Self {
        Self {
            allowed: from
                .iter()
                .filter_map(|cidr| cidr.parse::<IpNet>().ok())
                .collect(),
        }
    }

    /// May this peer speak for someone else?
    pub fn allows(&self, source: IpAddr) -> bool {
        self.allowed.iter().any(|cidr| cidr.contains(&source))
    }
}

/// Classify the head of a connection.
pub(crate) fn parse(buffer: &[u8]) -> ProxyHeader {
    // Long enough to tell the two apart: v2's signature opens with CRLF, which
    // a v1 line never does, so the two can never both match.
    if buffer.starts_with(V2_SIGNATURE) {
        return parse_v2(buffer);
    }
    if buffer.starts_with(V1_PREFIX) {
        return parse_v1(buffer);
    }
    // Too short to decide yet, but still a viable prefix of either signature.
    if starts_with_or_is_prefix_of(buffer, V1_PREFIX)
        || starts_with_or_is_prefix_of(buffer, V2_SIGNATURE)
    {
        return ProxyHeader::NeedMore;
    }
    ProxyHeader::Invalid
}

fn parse_v1(buffer: &[u8]) -> ProxyHeader {
    let Some(end) = buffer.windows(2).position(|pair| pair == b"\r\n") else {
        // No terminator yet. Bound it so a peer that never sends one cannot
        // hold the connection past the read deadline.
        return if buffer.len() >= V1_MAX_LEN {
            ProxyHeader::Invalid
        } else {
            ProxyHeader::NeedMore
        };
    };
    let consumed = end + 2;
    if consumed > V1_MAX_LEN {
        return ProxyHeader::Invalid;
    }
    let Ok(line) = std::str::from_utf8(&buffer[..end]) else {
        return ProxyHeader::Invalid;
    };
    let mut fields = line.split(' ');
    if fields.next() != Some("PROXY") {
        return ProxyHeader::Invalid;
    }
    let family = match fields.next() {
        Some("TCP4") => V2_TCP4,
        Some("TCP6") => V2_TCP6,
        // `PROXY UNKNOWN` may carry the rest of the fields or nothing at all;
        // either way the socket's own addresses stand.
        Some("UNKNOWN") => return ProxyHeader::NoAddresses { consumed },
        _ => return ProxyHeader::Invalid,
    };
    let (Some(source_ip), Some(destination_ip), Some(source_port), Some(destination_port)) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return ProxyHeader::Invalid;
    };
    if fields.next().is_some() {
        return ProxyHeader::Invalid;
    }
    let Some(source) = socket_addr(source_ip, source_port, family) else {
        return ProxyHeader::Invalid;
    };
    let Some(destination) = socket_addr(destination_ip, destination_port, family) else {
        return ProxyHeader::Invalid;
    };
    ProxyHeader::Decided {
        addresses: Box::new(ProxiedAddresses {
            source,
            destination,
            edge_tls: None,
        }),
        consumed,
    }
}

/// Parse one `ip` / `port` pair, rejecting a family the header did not declare.
fn socket_addr(ip: &str, port: &str, family: u8) -> Option<SocketAddr> {
    let ip: IpAddr = ip.parse().ok()?;
    let matches_family = match family {
        V2_TCP4 => ip.is_ipv4(),
        V2_TCP6 => ip.is_ipv6(),
        _ => false,
    };
    if !matches_family {
        return None;
    }
    Some(SocketAddr::new(ip, port.parse().ok()?))
}

fn parse_v2(buffer: &[u8]) -> ProxyHeader {
    if buffer.len() < V2_HEADER_LEN {
        return ProxyHeader::NeedMore;
    }
    let ver_cmd = buffer[12];
    // High nibble is the version; only 2 is this format.
    if ver_cmd >> 4 != 0x02 {
        return ProxyHeader::Invalid;
    }
    let body_len = u16::from_be_bytes([buffer[14], buffer[15]]) as usize;
    if body_len > V2_MAX_BODY {
        return ProxyHeader::Invalid;
    }
    let consumed = V2_HEADER_LEN + body_len;
    if buffer.len() < consumed {
        return ProxyHeader::NeedMore;
    }
    let body = &buffer[V2_HEADER_LEN..consumed];
    match ver_cmd & 0x0F {
        // The front speaks for itself: a health check, not a proxied client.
        V2_CMD_LOCAL => return ProxyHeader::NoAddresses { consumed },
        V2_CMD_PROXY => {}
        _ => return ProxyHeader::Invalid,
    }
    let family = buffer[13];
    let (source, destination, rest) = match family {
        V2_TCP4 => {
            if body.len() < 12 {
                return ProxyHeader::Invalid;
            }
            let source_ip = Ipv4Addr::new(body[0], body[1], body[2], body[3]);
            let destination_ip = Ipv4Addr::new(body[4], body[5], body[6], body[7]);
            (
                SocketAddr::new(source_ip.into(), u16::from_be_bytes([body[8], body[9]])),
                SocketAddr::new(
                    destination_ip.into(),
                    u16::from_be_bytes([body[10], body[11]]),
                ),
                &body[12..],
            )
        }
        V2_TCP6 => {
            if body.len() < 36 {
                return ProxyHeader::Invalid;
            }
            let mut source_octets = [0u8; 16];
            let mut destination_octets = [0u8; 16];
            source_octets.copy_from_slice(&body[..16]);
            destination_octets.copy_from_slice(&body[16..32]);
            (
                SocketAddr::new(
                    Ipv6Addr::from(source_octets).into(),
                    u16::from_be_bytes([body[32], body[33]]),
                ),
                SocketAddr::new(
                    Ipv6Addr::from(destination_octets).into(),
                    u16::from_be_bytes([body[34], body[35]]),
                ),
                &body[36..],
            )
        }
        // AF_UNIX and UNSPEC carry no address siphon can use.
        _ => return ProxyHeader::NoAddresses { consumed },
    };
    ProxyHeader::Decided {
        addresses: Box::new(ProxiedAddresses {
            source,
            destination,
            edge_tls: parse_ssl_tlv(rest),
        }),
        consumed,
    }
}

/// Walk the TLVs after the address block, looking for `PP2_TYPE_SSL`.
///
/// A malformed TLV run is not fatal: the addresses are already parsed and are
/// what the feature exists for. The TLS detail is additive, so a front that
/// truncates it loses the detail, not the connection.
fn parse_ssl_tlv(mut rest: &[u8]) -> Option<EdgeTls> {
    while rest.len() >= 3 {
        let tlv_type = rest[0];
        let length = u16::from_be_bytes([rest[1], rest[2]]) as usize;
        let value_start = 3;
        if rest.len() < value_start + length {
            return None;
        }
        let value = &rest[value_start..value_start + length];
        if tlv_type == PP2_TYPE_SSL {
            return Some(parse_ssl_value(value));
        }
        rest = &rest[value_start + length..];
    }
    None
}

fn parse_ssl_value(value: &[u8]) -> EdgeTls {
    // `client` byte, then a 4-byte `verify` word, then nested TLVs.
    let client = value.first().copied().unwrap_or(0);
    let verify_verified = value.len() >= 5 && value[1..5] == [0, 0, 0, 0];
    let mut edge = EdgeTls {
        used_tls: client & PP2_CLIENT_SSL != 0,
        client_cert_verified: verify_verified,
        version: None,
    };
    let mut nested = if value.len() > 5 {
        &value[5..]
    } else {
        &[][..]
    };
    while nested.len() >= 3 {
        let sub_type = nested[0];
        let length = u16::from_be_bytes([nested[1], nested[2]]) as usize;
        if nested.len() < 3 + length {
            break;
        }
        if sub_type == PP2_SUBTYPE_SSL_VERSION {
            edge.version = std::str::from_utf8(&nested[3..3 + length])
                .ok()
                .map(str::to_owned);
        }
        nested = &nested[3 + length..];
    }
    edge
}

/// How long a front has to deliver its header. Same order as the SIP sniff and
/// the TLS handshake: long enough for a slow link, short enough that a peer
/// which connects and says nothing cannot pin a task and a socket.
pub(crate) const PROXY_READ_TIMEOUT: Duration = Duration::from_secs(2);

/// Read a PROXY header from a freshly accepted connection.
///
/// Returns the verdict and **every byte read**, so the caller can split at
/// `consumed` and replay the remainder to whatever reads the connection next —
/// the TLS acceptor, the WebSocket upgrade, or the SIP framer.
///
/// Unlike [`sniff_stream`](super::stream::sniff_stream), a silent peer is an
/// error rather than an assumption: this only runs on a listener configured to
/// sit behind a front, where a connection with no header is either a bypass or
/// a misconfiguration, and treating it as plain SIP would hand the front's own
/// address to every consumer.
pub(crate) async fn read_proxy_header<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> io::Result<(ProxyHeader, BytesMut)> {
    let mut buffer = BytesMut::with_capacity(256);
    let mut chunk = [0u8; 256];
    let deadline = tokio::time::Instant::now() + PROXY_READ_TIMEOUT;

    loop {
        match parse(&buffer) {
            ProxyHeader::NeedMore => {}
            verdict => return Ok((verdict, buffer)),
        }
        match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer closed before sending a PROXY header",
                ))
            }
            Ok(Ok(size)) => buffer.extend_from_slice(&chunk[..size]),
            Ok(Err(error)) => return Err(error),
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "no PROXY header within the read deadline",
                ))
            }
        }
    }
}

/// Read a PROXY header at an accept site and apply its verdict.
///
/// The caller has already established that `peer` may assert an address — the
/// allowlist is checked in the accept loop, before a task is spawned, so a
/// sender that may not speak for anyone costs one `accept()` and nothing more.
///
/// Returns the address every consumer should key on from here (the client's,
/// or the peer's own for a header that speaks for nobody), the client's TLS at
/// the front when the header carried it, and the bytes read past the header,
/// which the caller **must** replay — they are the TLS ClientHello, the
/// WebSocket upgrade, or the first SIP message.
///
/// `None` means the connection is over. Deliberately no fallback to `peer` on
/// a refusal: attributing a headerless connection to the front is the exact
/// bug this option exists to fix, and doing it quietly would be worse than not
/// having the option at all.
pub(crate) async fn accept_proxied<S: AsyncRead + Unpin>(
    stream: &mut S,
    peer: SocketAddr,
    transport: Transport,
    listener: &str,
) -> Option<(SocketAddr, Option<EdgeTls>, BytesMut)> {
    let (verdict, mut buffer) = match read_proxy_header(stream).await {
        Ok(read) => read,
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            // Connect, send nothing, close: an L4 health check is
            // indistinguishable from this, so it is not an abuse signal.
            debug!("{transport} connection from {peer} ended before its PROXY header");
            return None;
        }
        Err(error) => {
            warn!(
                "{transport} dropping {peer} on the proxy_protocol listener {listener}: \
                 no PROXY header ({error})"
            );
            return None;
        }
    };

    match verdict {
        ProxyHeader::Decided {
            addresses,
            consumed,
        } => {
            let addresses = *addresses;
            let replay = buffer.split_off(consumed);
            Some((addresses.source, addresses.edge_tls, replay))
        }
        // `LOCAL` / `UNKNOWN`: the front speaks for itself, not for a client,
        // which is what its own health checks send. The socket's address stands.
        ProxyHeader::NoAddresses { consumed } => {
            let replay = buffer.split_off(consumed);
            Some((peer, None, replay))
        }
        ProxyHeader::Invalid => {
            warn!(
                "{transport} dropping {peer} on the proxy_protocol listener {listener}: \
                 first bytes are not a PROXY header"
            );
            None
        }
        // `read_proxy_header` only returns once the verdict is settled, so this
        // is unreachable; refusing is the safe reading of an impossible state.
        ProxyHeader::NeedMore => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_listed_sender_may_assert_a_client_address() {
        let acl = ProxyProtocolAcl::new(&["198.51.100.7/32".to_string()]);
        assert!(acl.allows("198.51.100.7".parse().unwrap()));
        assert!(
            !acl.allows("198.51.100.8".parse().unwrap()),
            "a neighbour of the front is not the front"
        );
    }

    #[test]
    fn a_prefix_admits_every_address_inside_it() {
        let acl =
            ProxyProtocolAcl::new(&["198.51.100.0/24".to_string(), "2001:db8::/32".to_string()]);
        assert!(acl.allows("198.51.100.200".parse().unwrap()));
        assert!(acl.allows("2001:db8::1".parse().unwrap()));
        assert!(!acl.allows("203.0.113.1".parse().unwrap()));
    }

    #[test]
    fn an_allowlist_with_nothing_usable_in_it_admits_nobody() {
        // Fail closed. `validate_listen` refuses an empty or non-CIDR list at
        // config load, so this is unreachable from a loaded config — but the
        // direction of the failure is the whole security property, and a list
        // that silently degraded to "permit all" would be a forgery primitive.
        let acl = ProxyProtocolAcl::new(&[]);
        assert!(!acl.allows("198.51.100.7".parse().unwrap()));
        let acl = ProxyProtocolAcl::new(&["not-a-cidr".to_string()]);
        assert!(!acl.allows("198.51.100.7".parse().unwrap()));
    }

    fn decided(header: ProxyHeader) -> (ProxiedAddresses, usize) {
        match header {
            ProxyHeader::Decided {
                addresses,
                consumed,
            } => (*addresses, consumed),
            other => panic!("expected a decided header, got {other:?}"),
        }
    }

    #[test]
    fn v1_tcp4_line_yields_the_client_endpoints() {
        let line = b"PROXY TCP4 192.0.2.10 198.51.100.7 51234 5061\r\nINVITE sip:x SIP/2.0\r\n";
        let (addresses, consumed) = decided(parse(line));
        assert_eq!(
            addresses.source,
            "192.0.2.10:51234".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            addresses.destination,
            "198.51.100.7:5061".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(addresses.edge_tls, None);
        assert_eq!(
            consumed, 47,
            "only the header is consumed; the INVITE must be replayed"
        );
    }

    #[test]
    fn v1_tcp6_line_yields_the_client_endpoints() {
        let line = b"PROXY TCP6 2001:db8::1 2001:db8::2 51234 5061\r\n";
        let (addresses, consumed) = decided(parse(line));
        assert_eq!(
            addresses.source,
            "[2001:db8::1]:51234".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(consumed, line.len());
    }

    #[test]
    fn v1_unknown_consumes_the_line_and_keeps_the_socket_addresses() {
        let line = b"PROXY UNKNOWN\r\nINVITE sip:x SIP/2.0\r\n";
        assert_eq!(parse(line), ProxyHeader::NoAddresses { consumed: 15 });
    }

    #[test]
    fn a_v1_family_that_disagrees_with_the_address_is_refused() {
        // TCP4 declared, IPv6 given: a front that cannot be trusted to say
        // which family it is speaking cannot be trusted with the address.
        let line = b"PROXY TCP4 2001:db8::1 198.51.100.7 51234 5061\r\n";
        assert_eq!(parse(line), ProxyHeader::Invalid);
    }

    #[test]
    fn a_v1_line_without_its_terminator_asks_for_more_then_gives_up() {
        assert_eq!(parse(b"PROXY TCP4 192.0.2.10 198"), ProxyHeader::NeedMore);
        let overlong = [b"PROXY TCP4 ".as_slice(), &[b'9'; V1_MAX_LEN]].concat();
        assert_eq!(parse(&overlong), ProxyHeader::Invalid);
    }

    #[test]
    fn a_partial_signature_asks_for_more_rather_than_failing() {
        assert_eq!(parse(b"PRO"), ProxyHeader::NeedMore);
        assert_eq!(parse(&V2_SIGNATURE[..5]), ProxyHeader::NeedMore);
        assert_eq!(parse(b""), ProxyHeader::NeedMore);
    }

    #[test]
    fn plain_sip_is_not_a_proxy_header() {
        assert_eq!(parse(b"INVITE sip:x SIP/2.0\r\n"), ProxyHeader::Invalid);
        assert_eq!(parse(b"GET / HTTP/1.1\r\n"), ProxyHeader::Invalid);
    }

    /// Build a v2 header: `PROXY` command, TCP4, with an optional TLV run.
    fn v2_tcp4(tlvs: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&Ipv4Addr::new(192, 0, 2, 10).octets());
        body.extend_from_slice(&Ipv4Addr::new(198, 51, 100, 7).octets());
        body.extend_from_slice(&51234u16.to_be_bytes());
        body.extend_from_slice(&5061u16.to_be_bytes());
        body.extend_from_slice(tlvs);
        let mut header = Vec::from(V2_SIGNATURE);
        header.push(0x20 | V2_CMD_PROXY);
        header.push(V2_TCP4);
        header.extend_from_slice(&(body.len() as u16).to_be_bytes());
        header.extend_from_slice(&body);
        header
    }

    #[test]
    fn v2_tcp4_yields_the_client_endpoints() {
        let header = v2_tcp4(&[]);
        let (addresses, consumed) = decided(parse(&header));
        assert_eq!(
            addresses.source,
            "192.0.2.10:51234".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            addresses.destination,
            "198.51.100.7:5061".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(consumed, header.len());
        assert_eq!(addresses.edge_tls, None);
    }

    #[test]
    fn v2_tcp6_yields_the_client_endpoints() {
        let mut body = Vec::new();
        body.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        body.extend_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
        body.extend_from_slice(&51234u16.to_be_bytes());
        body.extend_from_slice(&5061u16.to_be_bytes());
        let mut header = Vec::from(V2_SIGNATURE);
        header.push(0x20 | V2_CMD_PROXY);
        header.push(V2_TCP6);
        header.extend_from_slice(&(body.len() as u16).to_be_bytes());
        header.extend_from_slice(&body);
        let (addresses, consumed) = decided(parse(&header));
        assert_eq!(
            addresses.source,
            "[2001:db8::1]:51234".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(consumed, header.len());
    }

    #[test]
    fn v2_local_consumes_the_header_and_keeps_the_socket_addresses() {
        let mut header = Vec::from(V2_SIGNATURE);
        header.push(0x20 | V2_CMD_LOCAL);
        header.push(0x00);
        header.extend_from_slice(&0u16.to_be_bytes());
        assert_eq!(
            parse(&header),
            ProxyHeader::NoAddresses {
                consumed: V2_HEADER_LEN
            }
        );
    }

    #[test]
    fn v2_ssl_tlv_reports_the_clients_tls_at_the_front() {
        // PP2_TYPE_SSL: client=PP2_CLIENT_SSL, verify=0 (verified), then a
        // nested PP2_SUBTYPE_SSL_VERSION.
        let version = b"TLSv1.3";
        let mut ssl_value = vec![PP2_CLIENT_SSL, 0, 0, 0, 0];
        ssl_value.push(PP2_SUBTYPE_SSL_VERSION);
        ssl_value.extend_from_slice(&(version.len() as u16).to_be_bytes());
        ssl_value.extend_from_slice(version);
        let mut tlvs = vec![PP2_TYPE_SSL];
        tlvs.extend_from_slice(&(ssl_value.len() as u16).to_be_bytes());
        tlvs.extend_from_slice(&ssl_value);

        let (addresses, _) = decided(parse(&v2_tcp4(&tlvs)));
        let edge = addresses.edge_tls.expect("the SSL TLV must be reported");
        assert!(edge.used_tls, "PP2_CLIENT_SSL was set");
        assert!(
            edge.client_cert_verified,
            "a zero verify word means verified"
        );
        assert_eq!(edge.version.as_deref(), Some("TLSv1.3"));
    }

    #[test]
    fn a_nonzero_verify_word_is_not_a_verified_certificate() {
        let ssl_value = vec![PP2_CLIENT_SSL, 0, 0, 0, 1];
        let mut tlvs = vec![PP2_TYPE_SSL];
        tlvs.extend_from_slice(&(ssl_value.len() as u16).to_be_bytes());
        tlvs.extend_from_slice(&ssl_value);
        let (addresses, _) = decided(parse(&v2_tcp4(&tlvs)));
        let edge = addresses.edge_tls.unwrap();
        assert!(edge.used_tls);
        assert!(!edge.client_cert_verified);
    }

    #[test]
    fn a_truncated_ssl_tlv_costs_the_detail_not_the_addresses() {
        // Declares 64 bytes of value and supplies two: the addresses parsed
        // before it are still good, so the connection must not be refused.
        let tlvs = vec![PP2_TYPE_SSL, 0x00, 0x40, PP2_CLIENT_SSL, 0];
        let (addresses, _) = decided(parse(&v2_tcp4(&tlvs)));
        assert_eq!(
            addresses.source,
            "192.0.2.10:51234".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(addresses.edge_tls, None);
    }

    #[test]
    fn a_v2_body_arriving_in_pieces_asks_for_more() {
        let header = v2_tcp4(&[]);
        assert_eq!(parse(&header[..V2_HEADER_LEN]), ProxyHeader::NeedMore);
        assert_eq!(parse(&header[..header.len() - 1]), ProxyHeader::NeedMore);
        assert!(matches!(parse(&header), ProxyHeader::Decided { .. }));
    }

    #[test]
    fn a_v2_version_other_than_two_is_refused() {
        let mut header = v2_tcp4(&[]);
        header[12] = 0x30 | V2_CMD_PROXY;
        assert_eq!(parse(&header), ProxyHeader::Invalid);
    }

    #[test]
    fn an_oversized_v2_body_is_refused_rather_than_awaited() {
        let mut header = Vec::from(V2_SIGNATURE);
        header.push(0x20 | V2_CMD_PROXY);
        header.push(V2_TCP4);
        header.extend_from_slice(&((V2_MAX_BODY + 1) as u16).to_be_bytes());
        assert_eq!(parse(&header), ProxyHeader::Invalid);
    }

    #[test]
    fn a_v2_address_block_shorter_than_its_family_is_refused() {
        let mut header = Vec::from(V2_SIGNATURE);
        header.push(0x20 | V2_CMD_PROXY);
        header.push(V2_TCP6);
        header.extend_from_slice(&4u16.to_be_bytes());
        header.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(parse(&header), ProxyHeader::Invalid);
    }

    // --- read_proxy_header: the bounded read around `parse` -----------------
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn the_reader_returns_the_header_and_leaves_the_payload_for_replay() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let header = b"PROXY TCP4 192.0.2.10 198.51.100.7 51234 5061\r\n";
        let payload = b"INVITE sip:bob@example.com SIP/2.0\r\n";
        client.write_all(header).await.unwrap();
        client.write_all(payload).await.unwrap();

        let (verdict, buffer) = read_proxy_header(&mut server).await.unwrap();
        let (addresses, consumed) = match verdict {
            ProxyHeader::Decided {
                addresses,
                consumed,
            } => (*addresses, consumed),
            other => panic!("expected a header, got {other:?}"),
        };
        assert_eq!(
            addresses.source,
            "192.0.2.10:51234".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            &buffer[consumed..],
            payload,
            "the bytes after the header must survive for the SIP framer"
        );
    }

    #[tokio::test]
    async fn the_reader_reassembles_a_header_split_across_writes() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let read = tokio::spawn(async move { read_proxy_header(&mut server).await });
        client
            .write_all(b"PROXY TCP4 192.0.2.10 198.5")
            .await
            .unwrap();
        client.write_all(b"1.100.7 51234 5061\r\n").await.unwrap();

        let (verdict, _) = read.await.unwrap().unwrap();
        assert!(
            matches!(verdict, ProxyHeader::Decided { .. }),
            "a header arriving in two segments is still a header, got {verdict:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_peer_that_sends_nothing_is_an_error_not_an_assumption() {
        // The SIP sniff assumes raw SIP when a peer stays silent (RFC 5923
        // connection reuse). Here the opposite is required: this listener sits
        // behind a front, so no header means a bypass, and falling through
        // would hand the front's own address to every consumer.
        let (_client, mut server) = tokio::io::duplex(4096);
        let error = read_proxy_header(&mut server).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn a_peer_that_closes_before_the_header_reports_eof() {
        // An L4 health check: connect, close, say nothing. The caller drops it
        // without counting abuse.
        let (client, mut server) = tokio::io::duplex(4096);
        drop(client);
        let error = read_proxy_header(&mut server).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn plain_sip_on_a_proxy_listener_is_invalid_rather_than_an_error() {
        // The distinction matters at the call site: `Invalid` is a rejected
        // connection with a diagnosable log line, not an I/O failure.
        let (mut client, mut server) = tokio::io::duplex(4096);
        client
            .write_all(b"INVITE sip:bob@example.com SIP/2.0\r\n")
            .await
            .unwrap();
        let (verdict, _) = read_proxy_header(&mut server).await.unwrap();
        assert_eq!(verdict, ProxyHeader::Invalid);
    }

    // --- accept_proxied: the verdict applied at an accept site ---------------

    #[tokio::test]
    async fn an_accepted_header_substitutes_the_client_and_replays_the_payload() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let payload = b"INVITE sip:bob@example.com SIP/2.0\r\n";
        client
            .write_all(b"PROXY TCP4 192.0.2.10 198.51.100.7 51234 5061\r\n")
            .await
            .unwrap();
        client.write_all(payload).await.unwrap();

        let front = "198.51.100.7:40000".parse::<SocketAddr>().unwrap();
        let (client_addr, edge_tls, replay) =
            accept_proxied(&mut server, front, Transport::Tcp, "tcp")
                .await
                .expect("an allowed front's header must be accepted");
        assert_eq!(
            client_addr,
            "192.0.2.10:51234".parse::<SocketAddr>().unwrap(),
            "every consumer keys on this address, so it must be the phone's"
        );
        assert_eq!(edge_tls, None);
        assert_eq!(
            &replay[..],
            payload,
            "the INVITE must survive for whatever reads the connection next"
        );
    }

    #[tokio::test]
    async fn a_local_header_keeps_the_fronts_own_address() {
        // HAProxy sends LOCAL for its own health checks. It speaks for nobody,
        // so the socket's peer address stands rather than being replaced.
        let (mut client, mut server) = tokio::io::duplex(4096);
        let mut header = Vec::from(V2_SIGNATURE);
        header.push(0x20 | V2_CMD_LOCAL);
        header.push(0x00);
        header.extend_from_slice(&0u16.to_be_bytes());
        client.write_all(&header).await.unwrap();

        let front = "198.51.100.7:40000".parse::<SocketAddr>().unwrap();
        let (client_addr, edge_tls, replay) =
            accept_proxied(&mut server, front, Transport::Tcp, "tcp")
                .await
                .expect("a health check is not a refusal");
        assert_eq!(client_addr, front);
        assert_eq!(edge_tls, None);
        assert!(replay.is_empty());
    }

    #[tokio::test]
    async fn a_connection_with_no_header_is_refused_not_attributed_to_the_front() {
        // The whole point of the option: falling back to the peer address here
        // would silently hand the front's address to auto-ban, the registrar
        // and capture, which is the bug this feature exists to fix.
        let (mut client, mut server) = tokio::io::duplex(4096);
        client
            .write_all(b"INVITE sip:bob@example.com SIP/2.0\r\n")
            .await
            .unwrap();
        let front = "198.51.100.7:40000".parse::<SocketAddr>().unwrap();
        assert!(
            accept_proxied(&mut server, front, Transport::Tcp, "tcp")
                .await
                .is_none(),
            "plain SIP on a proxy_protocol listener must drop the connection"
        );
    }

    #[tokio::test]
    async fn a_peer_that_closes_before_its_header_is_dropped() {
        let (client, mut server) = tokio::io::duplex(4096);
        drop(client);
        let front = "198.51.100.7:40000".parse::<SocketAddr>().unwrap();
        assert!(accept_proxied(&mut server, front, Transport::Tcp, "tcp")
            .await
            .is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_peer_is_dropped_rather_than_assumed_to_be_sip() {
        let (_client, mut server) = tokio::io::duplex(4096);
        let front = "198.51.100.7:40000".parse::<SocketAddr>().unwrap();
        assert!(accept_proxied(&mut server, front, Transport::Tcp, "tcp")
            .await
            .is_none());
    }

    #[tokio::test]
    async fn the_clients_edge_tls_survives_the_accept() {
        // A re-encrypting front terminates the phone's TLS and opens its own
        // connection, so this TLV is the only way siphon learns the client
        // spoke TLS. It is carried alongside the hop's transport, never over it.
        let version = b"TLSv1.3";
        let mut ssl_value = vec![PP2_CLIENT_SSL, 0, 0, 0, 0];
        ssl_value.push(PP2_SUBTYPE_SSL_VERSION);
        ssl_value.extend_from_slice(&(version.len() as u16).to_be_bytes());
        ssl_value.extend_from_slice(version);
        let mut tlvs = vec![PP2_TYPE_SSL];
        tlvs.extend_from_slice(&(ssl_value.len() as u16).to_be_bytes());
        tlvs.extend_from_slice(&ssl_value);

        let (mut client, mut server) = tokio::io::duplex(4096);
        client.write_all(&v2_tcp4(&tlvs)).await.unwrap();

        let front = "198.51.100.7:40000".parse::<SocketAddr>().unwrap();
        let (_, edge_tls, _) = accept_proxied(&mut server, front, Transport::Tcp, "tcp")
            .await
            .expect("accepted");
        let edge = edge_tls.expect("the SSL TLV must reach the accept site");
        assert!(edge.used_tls);
        assert_eq!(edge.version.as_deref(), Some("TLSv1.3"));
    }

    #[tokio::test(start_paused = true)]
    async fn a_v2_header_whose_declared_body_never_arrives_hits_the_deadline() {
        // The parser bounds the buffer on its own: a v1 line is capped by
        // `V1_MAX_LEN` and a v2 body by `V2_MAX_BODY`, so a peer cannot grow
        // the buffer without bound. What it *can* do is declare a body and
        // never finish it, and the read deadline is what ends that.
        let (mut client, mut server) = tokio::io::duplex(4096);
        let mut header = Vec::from(V2_SIGNATURE);
        header.push(0x20 | V2_CMD_PROXY);
        header.push(V2_TCP4);
        header.extend_from_slice(&(V2_MAX_BODY as u16).to_be_bytes());
        client.write_all(&header).await.unwrap();
        client.write_all(&[0u8; 8]).await.unwrap();

        let error = read_proxy_header(&mut server).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }
}
