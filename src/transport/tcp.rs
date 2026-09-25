//! TCP transport with per-connection response routing.
//!
//! Each accepted connection gets a unique `ConnectionId` and a
//! `mpsc::Sender<Bytes>` stored in a `DashMap`. When the core wants to
//! send a response, it looks up the connection ID and sends to that sender.
//!
//! This fixes the broken "broadcast to all TCP connections" bug in the
//! original prototype.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use dashmap::DashMap;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::transport::acl::TransportAcl;
use crate::transport::crlf_keepalive::CrlfPongTracker;
use crate::transport::pool::ConnectionPool;
use crate::transport::proxy_protocol::{accept_proxied, ProxyProtocolAcl};
use crate::transport::stream::{
    bind_tcp_listener, serve_sip_stream, sniff_sip_or_drop, spawn_outbound_distributor,
    PrefixedStream, StreamContext,
};
use crate::transport::{
    configure_tcp_socket, next_connection_id, ConnectionId, InboundMessage, OutboundMessage,
    StreamConnections, Transport,
};

/// Spawn a TCP listener. For each accepted connection a task is spawned that:
///   1. Reads inbound SIP messages and sends them to `inbound_tx`
///   2. Receives outbound messages from its per-connection channel and writes them
///
/// The `connection_map` maps ConnectionId → per-connection outbound sender.
/// The outbound dispatcher (in the core) looks up the connection ID and routes
/// responses to the right connection.
///
/// Returns the address the listener bound, which carries the port the kernel
/// picked when `local_addr` asks for port 0.
pub async fn listen(
    local_addr: SocketAddr,
    inbound_tx: flume::Sender<InboundMessage>,
    outbound_rx: flume::Receiver<OutboundMessage>,
    connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>>,
    acl: Arc<TransportAcl>,
    stream_connections: StreamConnections,
    tos: Option<u32>,
    pool: Option<Arc<ConnectionPool>>,
    crlf_pong_tracker: Option<Arc<CrlfPongTracker>>,
    close_tx: Option<flume::Sender<u64>>,
    // When set, this listener sits behind a connection-terminating front and
    // every connection must open with a PROXY header from one of these
    // senders. `None` is the default and leaves the accept path untouched.
    proxy_protocol: Option<Arc<ProxyProtocolAcl>>,
) -> std::io::Result<SocketAddr> {
    // Bind before spawning, so that awaiting `listen` means the socket is
    // already accepting. With the bind inside the task, the caller returned
    // first and the listener appeared whenever the runtime got round to it —
    // a peer (or a test) could connect in between and be refused. It also
    // means a bind failure is ordered before the caller continues instead of
    // surfacing as a listener that silently never exists, and before any task
    // is spawned that a failed listener would leave behind.
    let listener = bind_tcp_listener(local_addr, tos)?;
    let bound = listener.local_addr()?;
    info!("TCP listener on {}", bound);

    // Distribute outbound messages to per-connection senders. When no existing
    // connection matches (`ConnectionId::default()` from fire-and-forget UAC
    // sends, or a connection that has since closed), the distributor falls back
    // to the outbound `ConnectionPool` to open a new TCP connection. Without
    // that fallback the message would be silently dropped — the bug that left
    // in-dialog NOTIFY frames built but never written to the wire when the
    // Route header pointed at a destination with no live inbound connection.
    spawn_outbound_distributor(outbound_rx, connection_map.clone(), Transport::Tcp, pool);

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((socket, remote_addr)) => {
                    if !acl.is_allowed(remote_addr.ip()) {
                        debug!("TCP rejected {} by ACL", remote_addr);
                        continue;
                    }
                    // A listener behind a front talks to the front and nobody
                    // else. Refused here, before the spawn, so a sender that
                    // may not speak for anyone costs one accept() and nothing
                    // more. Not an auto-ban signal: the likeliest cause by far
                    // is a second front that was never added to the list, and
                    // banning it would turn a misconfiguration into an outage.
                    if let Some(allowlist) = &proxy_protocol {
                        if !allowlist.allows(remote_addr.ip()) {
                            warn!(
                                "TCP refusing {remote_addr} on the proxy_protocol listener \
                                 {bound}: not in proxy_protocol.from"
                            );
                            continue;
                        }
                    }
                    // See the TLS listener for why this is taken here, before
                    // the spawn, and dropped silently rather than banned.
                    let mut permit = match crate::security::try_accept_connection(remote_addr.ip())
                    {
                        Ok(permit) => permit,
                        Err(reason) => {
                            debug!("TCP refused {} by connection limit: {reason}", remote_addr);
                            crate::security::record_connection_refused(reason);
                            continue;
                        }
                    };
                    let inbound_tx = inbound_tx.clone();
                    let connection_map = connection_map.clone();
                    let stream_connections = stream_connections.clone();

                    configure_tcp_socket(&socket, tos);

                    let crlf_pong_tracker = crlf_pong_tracker.clone();
                    let close_tx = close_tx.clone();
                    let proxy_protocol = proxy_protocol.clone();
                    let acl = Arc::clone(&acl);
                    tokio::spawn(async move {
                        let local_addr = socket.local_addr().unwrap_or(bound);
                        // Split before the PROXY read so the bytes read past
                        // the header can be pushed back in front of the read
                        // half — `into_split` is not available once the socket
                        // is wrapped, and the framer needs them either way.
                        let (mut reader, writer) = socket.into_split();
                        // The PROXY header comes before anything else on the
                        // wire, so it is read before the SIP sniff, and the
                        // client address it carries replaces the front's for
                        // every consumer downstream: the ban store, the
                        // registrar's `received`, capture and the CDR.
                        let (remote_addr, edge_tls, replay) = if proxy_protocol.is_some() {
                            match accept_proxied(
                                &mut reader,
                                remote_addr,
                                Transport::Tcp,
                                &bound.to_string(),
                            )
                            .await
                            {
                                Some(accepted) => accepted,
                                None => return,
                            }
                        } else {
                            (remote_addr, None, bytes::BytesMut::new())
                        };
                        // The accept loop checked the ACL and the ceiling against
                        // the front, where neither means anything: every
                        // connection shares that address. Re-check the client the
                        // header named, and hold its permit instead — dropping
                        // the front's hands those slots back, so the connection
                        // is counted once, against whoever is responsible.
                        if proxy_protocol.is_some() {
                            match crate::transport::proxy_protocol::admit_proxied_client(
                                remote_addr,
                                &acl,
                                Transport::Tcp,
                            ) {
                                Some(client_permit) => permit = client_permit,
                                None => return,
                            }
                        }
                        // What the phone spoke to the front, when the front
                        // re-encrypted and said so. Carried beside the hop, not
                        // over it — this connection is still plain TCP.
                        let client_transport = crate::transport::proxy_protocol::client_transport(
                            edge_tls.as_ref(),
                            Transport::Tcp,
                        );
                        // Push the over-read back in front of the read half so
                        // the framer sees the first SIP message the front sent
                        // in the same segment as the header.
                        let mut reader = PrefixedStream::new(reader, replay);
                        // Decide from the first line that this really is SIP,
                        // before any byte reaches the framer — an HTTP probe
                        // frames as a complete "message" and would otherwise be
                        // caught only by the parser, too late to close the
                        // connection or count the source. Classifying ahead of
                        // the connection id also keeps a probe out of the
                        // connection map and out of the accept log.
                        let Some(seed) =
                            sniff_sip_or_drop(&mut reader, remote_addr, Transport::Tcp).await
                        else {
                            return;
                        };
                        // Confirmed SIP: the handshake slot goes back, the
                        // connection slot stays with `permit` below. Still
                        // after the PROXY read, so the header is covered by the
                        // handshake ceiling rather than by nothing.
                        permit.handshake_done();

                        let connection_id = next_connection_id();
                        debug!("TCP accepted {} as {:?}", remote_addr, connection_id);

                        serve_sip_stream(
                            reader,
                            writer,
                            StreamContext {
                                transport: Transport::Tcp,
                                client_transport,
                                connection_id,
                                local_addr,
                                remote_addr,
                            },
                            seed,
                            inbound_tx,
                            connection_map,
                            // Registered for the connection's lifetime, as TLS
                            // and WS are: a peer behind NAT or behind a front
                            // that terminates the connection is reachable only
                            // over the connection it opened (RFC 5923, RFC 5626
                            // §5.3). Registering is not routing: the plain URI
                            // relay still goes through the outbound pool, and
                            // the entry is used only where the signalling asked
                            // for the captured flow (`relay(flow=...)`,
                            // `Flow.is_alive`, the `subscribe_state`
                            // received-flow NOTIFY). Keyed as TCP, so a TLS send
                            // to the same address never picks it.
                            Some(stream_connections),
                            crlf_pong_tracker,
                            close_tx,
                        )
                        .await;
                    });
                }
                Err(error) => {
                    error!("TCP accept error: {}", error);
                }
            }
        }
    });

    Ok(bound)
}

/// Determine the total length of a complete SIP message in the buffer.
///
/// Scans for the end-of-headers marker (`\r\n\r\n`), then reads
/// `Content-Length` to compute the full message length (headers + body).
/// Returns `None` if the headers are not yet complete or if
/// Content-Length is missing (assumes 0-length body in that case once
/// the header block is complete).
pub fn extract_sip_message_length(buffer: &[u8]) -> Option<usize> {
    // Skip leading CRLF keepalives (RFC 3261 §7.5 / RFC 5626 §4.4.1) using the
    // same helper the parser does. The stream readers drain them before framing
    // so this rarely fires — but a framer and a parser that disagree about
    // where a message *starts* is the same class of bug as disagreeing about
    // where it ends, and sharing the helper makes them agree by construction
    // rather than by one layer happening to sanitise for the other.
    let prefix = crate::sip::parser::leading_crlf_len(buffer);
    let rest = &buffer[prefix..];

    // Find end of headers
    let header_end = rest.windows(4).position(|w| w == b"\r\n\r\n")?;
    let headers_len = prefix + header_end + 4; // include the \r\n\r\n

    // Parse Content-Length from header block
    let header_block = &rest[..header_end];
    let content_length = extract_content_length(header_block).unwrap_or(0);

    // Saturate rather than wrap. `Content-Length: 18446744073709551615` parses
    // as a valid `usize`, and `headers_len + content_length` then overflows —
    // which panics in debug but *wraps* in release (the release profile does
    // not enable overflow-checks), reporting a length one byte short of the
    // header block. The framer would hand the parser a truncated header block
    // and leave the tail of the `\r\n\r\n` in the accumulator, desynchronising
    // the stream from a value the peer chose. Saturating puts the result above
    // any ceiling instead, so the message is refused as oversized.
    Some(headers_len.saturating_add(content_length))
}

/// Maximum bytes of an incomplete (no `\r\n\r\n` yet) stream message before it
/// is treated as abusive. A legitimate SIP header block is far smaller; an
/// unbounded stream with no end-of-headers is either a slow-loris or a non-SIP
/// flood, and is dropped (and auto-banned) rather than accumulated unbounded.
const MAX_INCOMPLETE_HEADER_BYTES: usize = 64 * 1024;

/// Verdict for a stream buffer that does not yet contain a complete SIP message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamVerdict {
    /// Bytes are (or could still become) a SIP message — keep reading.
    MaybeSip,
    /// Bytes are definitely not SIP (a complete non-SIP first line, a binary
    /// probe, or an over-long header block). Drop the connection.
    Garbage,
}

/// Classify a stream buffer that [`extract_sip_message_length`] reported as
/// incomplete (no `\r\n\r\n` yet): is it a SIP message still arriving, or a
/// scanner's non-SIP probe (an HTTP request, a TLS record on the plaintext
/// port, random bytes)?
///
/// The caller must have already drained leading CRLF keepalives (RFC 5626
/// §4.4.1) and confirmed the buffer is non-empty, so an empty connection (an
/// AWS NLB / load-balancer L4 health check that connects and closes without
/// data) and CRLF pings never reach here and are never mistaken for garbage.
///
/// RFC 3261 permits extension methods, so unknown method tokens are NOT
/// rejected: a request-line is accepted while its first line ends with
/// ` SIP/2.0`, and a status-line while it starts with `SIP/2.0 `. Only a
/// *complete* first line that is neither, a C0 control byte that cannot appear
/// in a start-line (catches binary probes immediately), or an over-long header
/// block is declared garbage.
pub(crate) fn classify_incomplete_stream(buffer: &[u8]) -> StreamVerdict {
    // Over-long header block with no end-of-headers — slow-loris / flood.
    if buffer.len() > MAX_INCOMPLETE_HEADER_BYTES {
        return StreamVerdict::Garbage;
    }
    // A C0 control byte (other than CR/LF/HT) never appears in a SIP start-line
    // or header — catches binary probes (e.g. a TLS ClientHello: 0x16 0x03 …)
    // before a CRLF is even seen. Scan only the head; garbage shows at the start.
    let head = &buffer[..buffer.len().min(512)];
    if head
        .iter()
        .any(|&byte| byte < 0x20 && byte != b'\r' && byte != b'\n' && byte != b'\t')
    {
        return StreamVerdict::Garbage;
    }
    // Wait for the first line to complete before judging its request/status shape.
    match buffer.windows(2).position(|window| window == b"\r\n") {
        Some(line_end) => {
            if is_sip_start_line(&buffer[..line_end]) {
                StreamVerdict::MaybeSip
            } else {
                StreamVerdict::Garbage
            }
        }
        // First line still arriving and free of control bytes — keep reading
        // (bounded by the size cap above and the connection idle timeout).
        None => StreamVerdict::MaybeSip,
    }
}

/// Whether `line` is a SIP start-line — a request-line (RFC 3261 §7.1) or a
/// status-line (§7.2).
///
/// RFC 3261 permits extension methods, so the method token is deliberately not
/// checked against a list: a request-line qualifies while it ends with
/// ` SIP/2.0`, and a status-line while it starts with `SIP/2.0 `. Anything else
/// with a complete first line is not SIP.
pub(crate) fn is_sip_start_line(line: &[u8]) -> bool {
    line.starts_with(b"SIP/2.0 ") || line.ends_with(b" SIP/2.0")
}

/// Verdict for one framing attempt over a stream accumulator.
///
/// Replaces the old "`Option<usize>` plus a separate garbage classification"
/// pair so that every stream reader — inbound listeners and the outbound
/// connection pool alike — goes through one place that also enforces the
/// message-size ceiling. Without that ceiling a peer can declare a huge
/// `Content-Length`, send only the header block, and make the reader buffer
/// toward the declared size: the end-of-headers marker has already been seen,
/// so [`MAX_INCOMPLETE_HEADER_BYTES`] no longer applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameVerdict {
    /// A complete SIP message occupies the first `len` bytes of the buffer.
    Complete { len: usize },
    /// Not a complete message yet, and still plausibly SIP — keep reading.
    NeedMore,
    /// The header block is complete but the declared total exceeds the
    /// ceiling. `header_len` bounds the (already buffered) header block so the
    /// caller can parse it and answer 513 before closing the connection.
    Oversized { declared: usize, header_len: usize },
    /// Definitely not SIP, or an over-long header block — drop the connection.
    Garbage,
}

/// Frame one SIP message out of a stream accumulator, refusing anything whose
/// declared total exceeds `max_message_bytes`.
///
/// The caller must have already drained leading CRLF keepalives (RFC 5626
/// §4.4.1) and confirmed the buffer is non-empty.
pub fn frame_sip_message(buffer: &[u8], max_message_bytes: usize) -> FrameVerdict {
    let Some(len) = extract_sip_message_length(buffer) else {
        return match classify_incomplete_stream(buffer) {
            StreamVerdict::MaybeSip => FrameVerdict::NeedMore,
            StreamVerdict::Garbage => FrameVerdict::Garbage,
        };
    };
    // A complete header block is not the same thing as a SIP message. An HTTP
    // request block also ends `\r\n\r\n`, and `extract_sip_message_length`
    // defaults a missing `Content-Length` to zero, so a scanner's `GET /` frames
    // as a complete "message" and reaches the parser — which has no connection
    // to close and no source to count. The start line has to be judged here, on
    // every message, because the sniff at accept
    // ([`super::stream::sniff_stream`]) judges only the connection's *first*
    // line and assumes SIP for a peer that stays silent past its window, so a
    // probe that waits before speaking skips it entirely.
    //
    // Before the size check below: a non-SIP block that declares a huge
    // `Content-Length` is garbage, not an oversized SIP message owed a 513.
    let prefix = crate::sip::parser::leading_crlf_len(buffer);
    let first_line_end = buffer[prefix..]
        .windows(2)
        .position(|window| window == b"\r\n")
        .map(|end| prefix + end)
        // Unreachable: `extract_sip_message_length` returned `Some`, so a
        // `\r\n\r\n` exists past the prefix. Refuse rather than index blindly.
        .unwrap_or(buffer.len());
    if !is_sip_start_line(&buffer[prefix..first_line_end]) {
        return FrameVerdict::Garbage;
    }
    if len > max_message_bytes {
        // Safe: `extract_sip_message_length` returned `Some`, so `\r\n\r\n`
        // is present and the header block is fully buffered. Measured past any
        // leading CRLF keepalives, exactly as the length above was.
        let header_len = buffer[prefix..]
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|end| prefix + end + 4)
            .unwrap_or(buffer.len());
        return FrameVerdict::Oversized {
            declared: len,
            header_len,
        };
    }
    if len <= buffer.len() {
        FrameVerdict::Complete { len }
    } else {
        FrameVerdict::NeedMore
    }
}

/// Extract Content-Length value from raw header bytes.
/// Handles both full name and compact form (`l:`).
/// This scan runs *before* parsing, on bytes nobody has validated, and its
/// answer decides where the next message starts. So it has to model lines the
/// same way the parser does, or the two disagree about where this message ends
/// — and the bytes in between are attacker-controlled and belong, to one of
/// them, to the following message. Two shapes the fuzzer found:
///
/// ```text
/// Subject: hello\r\n Content-Length: 99\r\nContent-Length: 0\r\n\r\n
/// ```
///
/// The continuation line is part of `Subject` to the parser (RFC 3261 §7.3.1
/// folding) and a header of its own to a naive line scan: 133 bytes against
/// 232. And the reverse, a folded value the parser reads and a line scan does
/// not:
///
/// ```text
/// Content-Length:   \r\n\t   1\r\n\r\n
/// ```
///
/// So: skip the start line (never a header, and a Request-URI contains a colon
/// of its own), skip folded continuation lines, and fold their content into the
/// value of the header they continue.
fn extract_content_length(headers: &[u8]) -> Option<usize> {
    let mut lines = headers
        .split(|&b| b == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .filter(|line| !line.is_empty())
        .peekable();

    // The first non-empty line is the request/status line, not a header. (Any
    // empty lines before it are the RFC 5626 §4.4.1 keepalive prefix.)
    lines.next()?;

    while let Some(line) = lines.next() {
        // A continuation of a header we already rejected — skip it whole.
        if matches!(line.first(), Some(b' ' | b'\t')) {
            continue;
        }
        let Some(colon_pos) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let (name, value) = line.split_at(colon_pos);
        let name_lower: Vec<u8> = name.iter().map(|b| b.to_ascii_lowercase()).collect();
        if name_lower.trim_ascii() != b"content-length" && name_lower.trim_ascii() != b"l" {
            continue;
        }

        // Fold the continuation lines into the value, as the parser does.
        let mut value = value[1..].to_vec(); // skip the ':'
        while lines
            .peek()
            .is_some_and(|next| matches!(next.first(), Some(b' ' | b'\t')))
        {
            value.push(b' ');
            value.extend_from_slice(lines.next()?);
        }
        let value_str = std::str::from_utf8(&value).ok()?;
        return value_str.trim().parse().ok();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn connection_ids_are_unique() {
        let id1 = next_connection_id();
        let id2 = next_connection_id();
        let id3 = next_connection_id();
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_ne!(id1, id3);
    }

    #[tokio::test]
    async fn connection_map_routes_to_correct_connection() {
        let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> =
            Arc::new(DashMap::new());

        let conn_a = ConnectionId(100);
        let conn_b = ConnectionId(200);

        let (tx_a, mut rx_a) = mpsc::channel::<Bytes>(4);
        let (tx_b, mut rx_b) = mpsc::channel::<Bytes>(4);

        connection_map.insert(conn_a, tx_a);
        connection_map.insert(conn_b, tx_b);

        // Send to conn_a
        let data_a = Bytes::from_static(b"SIP/2.0 200 OK for A\r\n\r\n");
        connection_map
            .get(&conn_a)
            .unwrap()
            .send(data_a.clone())
            .await
            .unwrap();

        // Send to conn_b
        let data_b = Bytes::from_static(b"SIP/2.0 200 OK for B\r\n\r\n");
        connection_map
            .get(&conn_b)
            .unwrap()
            .send(data_b.clone())
            .await
            .unwrap();

        // Verify A gets A's message
        let received_a = rx_a.recv().await.unwrap();
        assert_eq!(received_a, data_a);

        // Verify B gets B's message
        let received_b = rx_b.recv().await.unwrap();
        assert_eq!(received_b, data_b);

        // Verify A does NOT have B's message
        assert!(rx_a.try_recv().is_err());
    }

    #[tokio::test]
    async fn removed_connection_returns_none() {
        let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> =
            Arc::new(DashMap::new());
        let conn = ConnectionId(999);
        let (tx, _rx) = mpsc::channel::<Bytes>(4);
        connection_map.insert(conn, tx);
        connection_map.remove(&conn);
        assert!(connection_map.get(&conn).is_none());
    }

    #[test]
    fn extract_length_with_body() {
        let message = b"INVITE sip:bob@example.com SIP/2.0\r\n\
                         Content-Length: 5\r\n\
                         \r\n\
                         hello";
        assert_eq!(extract_sip_message_length(message), Some(message.len()));
    }

    #[test]
    fn extract_length_no_body() {
        let message = b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(extract_sip_message_length(message), Some(message.len()));
    }

    #[test]
    fn extract_length_missing_content_length_defaults_to_zero() {
        let message = b"SIP/2.0 200 OK\r\nVia: SIP/2.0/TCP host\r\n\r\n";
        assert_eq!(extract_sip_message_length(message), Some(message.len()));
    }

    #[test]
    fn extract_length_incomplete_headers() {
        let partial = b"INVITE sip:bob@example.com SIP/2.0\r\nContent-Length: 5\r\n";
        assert_eq!(extract_sip_message_length(partial), None);
    }

    #[test]
    fn classify_accepts_partial_sip_request() {
        // A request-line whose message is still arriving (no \r\n\r\n yet).
        let partial = b"INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/TCP h";
        assert_eq!(classify_incomplete_stream(partial), StreamVerdict::MaybeSip);
    }

    #[test]
    fn classify_accepts_partial_status_line() {
        let partial = b"SIP/2.0 200 OK\r\nVia: SIP/2.0/TCP host";
        assert_eq!(classify_incomplete_stream(partial), StreamVerdict::MaybeSip);
    }

    #[test]
    fn classify_accepts_method_prefix_before_crlf() {
        // First line not yet terminated — too short to judge, keep reading.
        assert_eq!(classify_incomplete_stream(b"INV"), StreamVerdict::MaybeSip);
        assert_eq!(
            classify_incomplete_stream(b"REGISTER sip:exa"),
            StreamVerdict::MaybeSip
        );
    }

    #[test]
    fn classify_accepts_rfc3261_extension_method() {
        // RFC 3261 permits extension methods — an unknown token is NOT garbage
        // as long as the request-line ends with " SIP/2.0".
        let unknown = b"FROBNICATE sip:bob@example.com SIP/2.0\r\nVia: x";
        assert_eq!(classify_incomplete_stream(unknown), StreamVerdict::MaybeSip);
    }

    #[test]
    fn classify_rejects_http_probe() {
        let http = b"GET / HTTP/1.1\r\nHost: example.com\r\n";
        assert_eq!(classify_incomplete_stream(http), StreamVerdict::Garbage);
    }

    #[test]
    fn classify_rejects_binary_probe() {
        // A TLS ClientHello on the plaintext port: record type 0x16, version 0x0301.
        let tls_hello = b"\x16\x03\x01\x00\xa5\x01\x00\x00\xa1\x03\x03";
        assert_eq!(
            classify_incomplete_stream(tls_hello),
            StreamVerdict::Garbage
        );
    }

    #[test]
    fn classify_rejects_oversized_header_block() {
        // No end-of-headers within the cap — slow-loris / flood.
        let mut flood = Vec::from(&b"INVITE sip:x SIP/2.0\r\n"[..]);
        flood.resize(MAX_INCOMPLETE_HEADER_BYTES + 1, b'A');
        assert_eq!(classify_incomplete_stream(&flood), StreamVerdict::Garbage);
    }

    #[test]
    fn extract_content_length_with_leading_crlf() {
        // Simulates a buffer where a keepalive CRLF preceded the message
        // and was included in the header block. The ? operator must not
        // short-circuit on the empty first line.
        let headers = b"\r\nINVITE sip:bob@example.com SIP/2.0\r\n\
                         Content-Length: 440\r\n\
                         Via: SIP/2.0/TCP host;branch=z9hG4bK123";
        assert_eq!(extract_content_length(headers), Some(440));
    }

    #[test]
    fn extract_content_length_compact_form() {
        let headers = b"INVITE sip:bob@example.com SIP/2.0\r\nl: 200";
        assert_eq!(extract_content_length(headers), Some(200));
    }

    // --- message-size ceiling (frame_sip_message) ---------------------------

    const CEILING: usize = 256 * 1024;

    /// The shape this ceiling exists to stop: a peer sends a ~200 byte header
    /// block declaring a body far larger than anything SIP carries, then
    /// dribbles it. Before the ceiling the reader saw `\r\n\r\n` (so the
    /// over-long-header guard no longer applied) and buffered toward the
    /// declared size, so one connection could drive multi-GB growth.
    #[test]
    fn oversized_declared_content_length_is_refused_not_buffered() {
        let attack = b"INVITE sip:bob@example.com SIP/2.0\r\n\
                       Via: SIP/2.0/TCP host;branch=z9hG4bK1\r\n\
                       Content-Length: 4000000000\r\n\
                       \r\n";
        match frame_sip_message(attack, CEILING) {
            FrameVerdict::Oversized {
                declared,
                header_len,
            } => {
                assert_eq!(declared, 4_000_000_000 + attack.len());
                // The whole header block is buffered, so the caller can parse
                // it and answer 513 before closing.
                assert_eq!(header_len, attack.len());
            }
            other => panic!("expected Oversized, got {other:?}"),
        }
    }

    /// A `Content-Length` near `usize::MAX` must not wrap the headers+body sum.
    /// Found by the framing fuzz target: the sum overflowed, and because the
    /// release profile leaves overflow-checks off it wrapped silently to
    /// `headers_len - 1`, so the framer sliced a truncated header block and
    /// desynchronised the stream on a value the peer controls.
    #[test]
    fn absurd_content_length_saturates_instead_of_wrapping() {
        let attack = b"INVITE sip:bob@example.com SIP/2.0\r\n\
                       Content-Length: 18446744073709551615\r\n\
                       \r\n";
        assert_eq!(extract_sip_message_length(attack), Some(usize::MAX));
        assert!(
            matches!(
                frame_sip_message(attack, CEILING),
                FrameVerdict::Oversized { .. }
            ),
            "an unrepresentable declaration must be refused, never framed short"
        );
    }

    /// A message exactly at the ceiling is still accepted — the check is
    /// "greater than", so the documented limit is inclusive.
    #[test]
    fn message_exactly_at_the_ceiling_is_accepted() {
        let headers = b"INVITE sip:bob@example.com SIP/2.0\r\nContent-Length: 10\r\n\r\n";
        let mut message = headers.to_vec();
        message.extend_from_slice(b"0123456789");
        let limit = message.len();
        assert_eq!(
            frame_sip_message(&message, limit),
            FrameVerdict::Complete { len: message.len() }
        );
        assert!(matches!(
            frame_sip_message(&message, limit - 1),
            FrameVerdict::Oversized { .. }
        ));
    }

    /// An ordinary message still frames, and a partially-arrived body still
    /// asks for more rather than being mistaken for an attack.
    #[test]
    fn ordinary_message_frames_and_partial_body_waits() {
        let headers = b"INVITE sip:bob@example.com SIP/2.0\r\nContent-Length: 4\r\n\r\n";
        let mut complete = headers.to_vec();
        complete.extend_from_slice(b"AAAA");
        assert_eq!(
            frame_sip_message(&complete, CEILING),
            FrameVerdict::Complete {
                len: complete.len()
            }
        );

        let mut partial = headers.to_vec();
        partial.extend_from_slice(b"AA");
        assert_eq!(frame_sip_message(&partial, CEILING), FrameVerdict::NeedMore);
    }

    /// The pre-existing `classify_incomplete_stream` guards still fire through
    /// this entry point, unchanged, while the header block is incomplete. A
    /// buffer that already holds `\r\n\r\n` is judged by the start-line check
    /// instead — see [`http_request_block_is_garbage_not_a_message`].
    #[test]
    fn frame_sip_message_preserves_garbage_classification() {
        // A complete non-SIP first line, still mid-header-block.
        assert_eq!(
            frame_sip_message(b"GET /index.html HTTP/1.1\r\nHost: example", CEILING),
            FrameVerdict::Garbage
        );
        // A binary probe (TLS ClientHello on the plaintext port).
        assert_eq!(
            frame_sip_message(&[0x16, 0x03, 0x01, 0x00, 0x2f], CEILING),
            FrameVerdict::Garbage
        );
        // A genuine SIP message still arriving is not garbage.
        assert_eq!(
            frame_sip_message(b"INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP", CEILING),
            FrameVerdict::NeedMore
        );
        // Over-long header block with no end-of-headers is still refused.
        let mut flood = b"INVITE sip:bob@example.com SIP/2.0\r\n".to_vec();
        flood.resize(MAX_INCOMPLETE_HEADER_BYTES + 1, b'x');
        assert_eq!(frame_sip_message(&flood, CEILING), FrameVerdict::Garbage);
    }

    /// The probe this check exists to stop. A *complete* HTTP request block
    /// satisfies `extract_sip_message_length` — it ends `\r\n\r\n` and carries
    /// no `Content-Length`, which defaults to zero — so before the start-line
    /// check it framed as a complete "message", reached the dispatcher, and was
    /// rejected only by the parser, which has no connection to close and no
    /// source to record. A scanner could probe indefinitely over one connection.
    ///
    /// It is not caught by the accept-time sniff either: that judges only the
    /// connection's first line and assumes SIP for a peer that sends nothing
    /// inside its window, so a probe that connects, waits, then speaks skips it.
    #[test]
    fn http_request_block_is_garbage_not_a_message() {
        for probe in [
            &b"GET / HTTP/1.1\r\nHost: sip.example.com:443\r\n\r\n"[..],
            &b"GET / HTTP/1.0\r\n\r\n"[..],
            &b"POST /phpinfo.php HTTP/1.1\r\nContent-Length: 0\r\n\r\n"[..],
            // No recognisable protocol at all, but a well-formed header block.
            &b"hello world\r\n\r\n"[..],
        ] {
            assert_eq!(
                frame_sip_message(probe, CEILING),
                FrameVerdict::Garbage,
                "expected Garbage for {:?}",
                String::from_utf8_lossy(probe)
            );
        }
    }

    /// Leading CRLF keepalives (RFC 5626 §4.4.1) must not hide the start line
    /// from the check. The inbound readers drain them first, but the outbound
    /// pool frames straight off its accumulator, so the start line is measured
    /// past the same prefix the length is.
    #[test]
    fn http_request_block_behind_crlf_keepalives_is_garbage() {
        assert_eq!(
            frame_sip_message(b"\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n", CEILING),
            FrameVerdict::Garbage
        );
    }

    /// A non-SIP block declaring a huge body is garbage, not an oversized SIP
    /// message: the start-line check runs before the ceiling, so the peer is
    /// disconnected rather than answered 513 (which would need a Via it has not
    /// got, and would fingerprint the port to a scanner).
    #[test]
    fn non_sip_block_declaring_a_huge_body_is_garbage_not_oversized() {
        assert_eq!(
            frame_sip_message(
                b"GET / HTTP/1.1\r\nContent-Length: 4000000000\r\n\r\n",
                CEILING
            ),
            FrameVerdict::Garbage
        );
    }

    /// Every legitimate start-line shape still frames. RFC 3261 §7.1 permits
    /// extension methods, so the method token is never checked against a list —
    /// only the ` SIP/2.0` tail (request) or `SIP/2.0 ` head (status).
    #[test]
    fn every_sip_start_line_shape_still_frames() {
        let requests: [&[u8]; 4] = [
            b"INVITE sip:bob@example.com SIP/2.0\r\nContent-Length: 0\r\n\r\n",
            b"REGISTER sip:example.com SIP/2.0\r\n\r\n",
            // Extension method (RFC 6086 INFO is registered; an unregistered
            // token must frame just the same).
            b"FROBNICATE sip:bob@example.com SIP/2.0\r\n\r\n",
            b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n",
        ];
        for message in requests {
            assert_eq!(
                frame_sip_message(message, CEILING),
                FrameVerdict::Complete { len: message.len() },
                "expected Complete for {:?}",
                String::from_utf8_lossy(message)
            );
        }

        // With a body, and behind keepalive CRLFs.
        let with_body = b"\r\nSIP/2.0 200 OK\r\nContent-Length: 4\r\n\r\nAAAA";
        assert_eq!(
            frame_sip_message(with_body, CEILING),
            FrameVerdict::Complete {
                len: with_body.len()
            }
        );
    }

    #[test]
    fn is_sip_start_line_accepts_requests_and_status_lines_only() {
        assert!(is_sip_start_line(b"INVITE sip:bob@example.com SIP/2.0"));
        assert!(is_sip_start_line(b"SIP/2.0 486 Busy Here"));
        assert!(!is_sip_start_line(b"GET / HTTP/1.1"));
        assert!(!is_sip_start_line(b"SIP/2.0"));
        assert!(!is_sip_start_line(b""));
        // A URI that merely mentions the token is not a start line.
        assert!(!is_sip_start_line(b"Via: SIP/2.0/TCP host"));
    }

    /// The ceiling counts headers *and* body, so a message whose header block
    /// alone is under the incomplete-header cap can still be refused on its
    /// declared total.
    #[test]
    fn ceiling_covers_headers_plus_body() {
        let message = b"INVITE sip:bob@example.com SIP/2.0\r\nContent-Length: 5000\r\n\r\n";
        assert!(message.len() < MAX_INCOMPLETE_HEADER_BYTES);
        assert!(matches!(
            frame_sip_message(message, 4096),
            FrameVerdict::Oversized { .. }
        ));
    }

    // --- end to end: the listener only serves connections that speak SIP ----

    /// Start a TCP SIP listener on a port the kernel picks.
    async fn spawn_listener() -> (SocketAddr, flume::Receiver<InboundMessage>) {
        let (inbound_tx, inbound_rx) = flume::unbounded();
        let (_outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
        let addr = listen(
            "127.0.0.1:0".parse().unwrap(),
            inbound_tx,
            outbound_rx,
            Arc::new(DashMap::new()),
            Arc::new(TransportAcl::new(vec![], vec![])),
            StreamConnections::new(),
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("tcp listener must bind");
        assert_ne!(addr.port(), 0, "listen must return the port it bound");
        (addr, inbound_rx)
    }

    /// The accept loop checks the ACL against whoever opened the socket — the
    /// front — so a listener behind one applies every abuse control to an
    /// address every client shares. This proves the accept site re-applies it to
    /// the client the header named.
    ///
    /// Deliberately driven through the per-listener `TransportAcl` rather than
    /// the auto-ban store or the connection limiter: those are process-global
    /// `OnceLock`s owned by tests in `security.rs`, so a test depending on them
    /// here would be ordering-dependent. The ACL is passed in per listener, so
    /// this is deterministic. It exercises the same `admit_proxied_client` call
    /// either way — `is_allowed` is what consults the ban store in production.
    #[tokio::test]
    async fn a_denied_client_is_dropped_even_though_the_front_is_allowed() {
        use tokio::io::AsyncWriteExt;

        let (inbound_tx, inbound_rx) = flume::unbounded();
        let (_outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
        // Denies the client the header will claim; says nothing about loopback,
        // so the front itself passes the accept-loop check.
        let acl = Arc::new(TransportAcl::new(
            vec!["203.0.113.66/32".to_string()],
            vec![],
        ));
        let allowlist = Arc::new(crate::transport::proxy_protocol::ProxyProtocolAcl::new(&[
            "127.0.0.0/8".to_string(),
        ]));
        let addr = listen(
            "127.0.0.1:0".parse().unwrap(),
            inbound_tx,
            outbound_rx,
            Arc::new(DashMap::new()),
            acl,
            StreamConnections::new(),
            None,
            None,
            None,
            None,
            Some(allowlist),
        )
        .await
        .expect("tcp listener must bind");

        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"PROXY TCP4 203.0.113.66 198.51.100.7 51234 5060\r\n")
            .await
            .unwrap();
        client
            .write_all(
                concat!(
                    "OPTIONS sip:probe@example.com SIP/2.0\r\n",
                    "Via: SIP/2.0/TCP 203.0.113.66:51234;branch=z9hG4bKdenied\r\n",
                    "From: <sip:probe@example.com>;tag=denied\r\n",
                    "To: <sip:probe@example.com>\r\n",
                    "Call-ID: denied-client@example.com\r\n",
                    "CSeq: 1 OPTIONS\r\n",
                    "Content-Length: 0\r\n",
                    "\r\n",
                )
                .as_bytes(),
            )
            .await
            .unwrap();

        // Nothing must reach the dispatcher: delete the re-check at the accept
        // site and this OPTIONS arrives under a denied address.
        let delivered = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            inbound_rx.recv_async(),
        )
        .await;
        assert!(
            delivered.is_err(),
            "a client the ACL denies must be dropped even when the front carrying it is allowed"
        );
    }

    #[tokio::test]
    async fn listener_drops_an_http_probe_without_dispatching_it() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (addr, inbound_rx) = spawn_listener().await;
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        client
            .write_all(
                concat!(
                    "GET /phpinfo.php HTTP/1.1\r\n",
                    "Host: proxy.example.com\r\n",
                    "User-Agent: Mozilla/5.0\r\n",
                    "\r\n",
                )
                .as_bytes(),
            )
            .await
            .unwrap();

        // The listener closes the connection instead of framing the probe as a
        // message: read returns EOF, and nothing was answered.
        let mut response = Vec::new();
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.read_to_end(&mut response),
        )
        .await
        .expect("connection must be closed, not held open")
        .unwrap();
        assert_eq!(read, 0, "a SIP port must not answer a probe");
        assert!(
            inbound_rx.is_empty(),
            "the probe must never reach the dispatcher"
        );
    }

    /// End to end on a real listener: an oversized declaration is answered
    /// 513, never dispatched, and the connection is closed — so the body the
    /// peer promised is never buffered.
    #[tokio::test]
    async fn listener_answers_513_and_closes_on_an_oversized_declaration() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (addr, inbound_rx) = spawn_listener().await;
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let attack = concat!(
            "INVITE sip:bob@example.com SIP/2.0\r\n",
            "Via: SIP/2.0/TCP 10.0.0.1:5060;branch=z9hG4bK-oversize\r\n",
            "From: <sip:alice@example.com>;tag=abc123\r\n",
            "To: <sip:bob@example.com>\r\n",
            "Call-ID: oversize-test@example.com\r\n",
            "CSeq: 1 INVITE\r\n",
            "Content-Length: 4000000000\r\n",
            "\r\n",
        );
        client.write_all(attack.as_bytes()).await.unwrap();

        let mut response = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.read_to_end(&mut response),
        )
        .await
        .expect("the connection must be closed, not held open buffering")
        .unwrap();

        let response = String::from_utf8_lossy(&response);
        assert!(
            response.starts_with("SIP/2.0 513 "),
            "expected a 513, got: {response}"
        );
        assert!(
            response.contains("branch=z9hG4bK-oversize"),
            "the 513 must be routable back to the sender: {response}"
        );
        assert!(
            inbound_rx.try_recv().is_err(),
            "an oversized message must never reach the dispatcher"
        );
    }

    #[tokio::test]
    async fn listener_still_dispatches_sip_arriving_in_the_first_segment() {
        use tokio::io::AsyncWriteExt;

        // The bytes the classifier consumes to decide must be handed to the
        // framer, so a request that fits entirely in the first segment is not
        // swallowed by the decision.
        let (addr, inbound_rx) = spawn_listener().await;
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let register = concat!(
            "REGISTER sip:example.com SIP/2.0\r\n",
            "Via: SIP/2.0/TCP 10.0.0.1:5060;branch=z9hG4bK776\r\n",
            "From: <sip:alice@example.com>;tag=abc123\r\n",
            "To: <sip:alice@example.com>\r\n",
            "Call-ID: tcp-sniff-test@example.com\r\n",
            "CSeq: 1 REGISTER\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        client.write_all(register.as_bytes()).await.unwrap();

        let inbound =
            tokio::time::timeout(std::time::Duration::from_secs(2), inbound_rx.recv_async())
                .await
                .expect("SIP must still be dispatched")
                .unwrap();
        assert_eq!(&inbound.data[..], register.as_bytes());
        assert_eq!(inbound.transport, Transport::Tcp);
    }

    // --- end to end: inbound TCP connections in the flow registry -----------

    /// A TCP listener wired to a stream-connection registry, with the outbound
    /// channel and connection map handed back so a test can send over the
    /// flow the peer opened and watch the per-connection state drain.
    struct RegisteredListener {
        addr: SocketAddr,
        inbound_rx: flume::Receiver<InboundMessage>,
        outbound_tx: flume::Sender<OutboundMessage>,
        registry: StreamConnections,
        connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>>,
    }

    async fn spawn_registered_listener() -> RegisteredListener {
        let (inbound_tx, inbound_rx) = flume::unbounded();
        let (outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
        let registry = StreamConnections::new();
        let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> =
            Arc::new(DashMap::new());
        let addr = listen(
            "127.0.0.1:0".parse().unwrap(),
            inbound_tx,
            outbound_rx,
            Arc::clone(&connection_map),
            Arc::new(TransportAcl::new(vec![], vec![])),
            registry.clone(),
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("tcp listener must bind");
        RegisteredListener {
            addr,
            inbound_rx,
            outbound_tx,
            registry,
            connection_map,
        }
    }

    /// A REGISTER from a peer that asks for its connection to be reused
    /// (RFC 5626 outbound: `;ob` on the Contact, `reg-id`/`+sip.instance`).
    const FLOW_REGISTER: &str = concat!(
        "REGISTER sip:example.com SIP/2.0\r\n",
        "Via: SIP/2.0/TCP 192.0.2.30:5060;branch=z9hG4bK-flow;alias\r\n",
        "Max-Forwards: 70\r\n",
        "From: <sip:alice@example.com>;tag=flow1\r\n",
        "To: <sip:alice@example.com>\r\n",
        "Call-ID: tcp-flow-reuse@example.com\r\n",
        "CSeq: 1 REGISTER\r\n",
        "Contact: <sip:alice@192.0.2.30:5060;transport=tcp;ob>;reg-id=1;",
        "+sip.instance=\"<urn:uuid:00000000-0000-1000-8000-000000000001>\"\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    );

    const MT_OPTIONS: &str = concat!(
        "OPTIONS sip:alice@192.0.2.30:5060;transport=tcp SIP/2.0\r\n",
        "Via: SIP/2.0/TCP 198.51.100.1:5060;branch=z9hG4bK-mt\r\n",
        "Max-Forwards: 70\r\n",
        "From: <sip:proxy@example.com>;tag=mt1\r\n",
        "To: <sip:alice@example.com>\r\n",
        "Call-ID: tcp-flow-mt@example.com\r\n",
        "CSeq: 1 OPTIONS\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    );

    /// Connect, send the REGISTER, and hand back the client socket, its local
    /// address (the peer address siphon sees) and the connection id siphon
    /// gave it.
    async fn connect_and_register(
        listener: &RegisteredListener,
    ) -> (tokio::net::TcpStream, SocketAddr, ConnectionId) {
        use tokio::io::AsyncWriteExt;

        let mut client = tokio::net::TcpStream::connect(listener.addr).await.unwrap();
        let peer = client.local_addr().unwrap();
        client.write_all(FLOW_REGISTER.as_bytes()).await.unwrap();
        let inbound = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            listener.inbound_rx.recv_async(),
        )
        .await
        .expect("the REGISTER must be dispatched")
        .unwrap();
        assert_eq!(inbound.remote_addr, peer);
        assert_eq!(inbound.transport, Transport::Tcp);
        (client, peer, inbound.connection_id)
    }

    /// A peer that can only be reached over the connection it opened (behind
    /// NAT, or behind a front that terminates the connection) needs that
    /// connection registered, or every flow-routed send to it (`Flow.is_alive`,
    /// the `subscribe_state` received-flow NOTIFY, `relay(flow=...)` guarded by
    /// liveness) finds nothing and fails.  The registration is keyed as TCP,
    /// so it can never be picked for a TLS send to the same address.
    #[tokio::test]
    async fn an_inbound_tcp_connection_is_registered_for_flow_reuse() {
        use tokio::io::AsyncReadExt;

        let listener = spawn_registered_listener().await;
        let (mut client, peer, connection_id) = connect_and_register(&listener).await;

        assert_eq!(
            listener.registry.get(&peer, Transport::Tcp),
            Some(connection_id),
            "an inbound TCP connection must be in the stream-connection registry"
        );
        assert!(listener
            .registry
            .is_alive(peer, Transport::Tcp, connection_id));
        assert_eq!(
            listener.registry.reuse(peer, Transport::Tls),
            None,
            "a TCP registration must never be handed out for a TLS send"
        );

        // Send back over the flow the registry names, the way the received-flow
        // NOTIFY path does, and read it on the peer's own socket.
        let flow_connection = listener
            .registry
            .get(&peer, Transport::Tcp)
            .expect("registered above");
        listener
            .outbound_tx
            .send(OutboundMessage {
                followups: None,
                connection_id: flow_connection,
                transport: Transport::Tcp,
                destination: peer,
                data: Bytes::from_static(MT_OPTIONS.as_bytes()),
                source_local_addr: None,
                server_name: None,
            })
            .unwrap();
        let mut received = vec![0u8; MT_OPTIONS.len()];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.read_exact(&mut received),
        )
        .await
        .expect("the request must arrive over the peer's own connection")
        .unwrap();
        assert_eq!(received, MT_OPTIONS.as_bytes());
    }

    /// Wait until `condition` holds, failing the test after five seconds.
    async fn eventually(what: &str, condition: impl Fn() -> bool) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !condition() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
    }

    /// The registration lives exactly as long as the connection: once the peer
    /// closes, the entry goes, so a flow-routed send reports the flow dead
    /// instead of writing to a connection that no longer exists.
    #[tokio::test]
    async fn the_tcp_registration_goes_when_the_connection_closes() {
        let listener = spawn_registered_listener().await;
        let (client, peer, connection_id) = connect_and_register(&listener).await;
        assert!(listener
            .registry
            .is_alive(peer, Transport::Tcp, connection_id));

        drop(client);
        eventually("the registration to be evicted", || {
            listener.registry.get(&peer, Transport::Tcp).is_none()
        })
        .await;
        assert!(!listener
            .registry
            .is_alive(peer, Transport::Tcp, connection_id));
        eventually("the connection map entry to be removed", || {
            !listener.connection_map.contains_key(&connection_id)
        })
        .await;
    }

    /// Steady-state leak gate for the per-connection store: after a batch of
    /// complete connect → REGISTER → close cycles, the registry and the
    /// connection map are back at their starting size.  An inbound TCP entry
    /// that is inserted on accept and never evicted on close shows up here.
    #[tokio::test]
    async fn tcp_flow_registry_drains_to_baseline_after_connection_churn() {
        const CYCLES: usize = 200;
        const CONCURRENT: usize = 20;

        let listener = spawn_registered_listener().await;
        let registry_baseline = listener.registry.len();
        let map_baseline = listener.connection_map.len();

        for _ in 0..CYCLES / CONCURRENT {
            let mut open = Vec::with_capacity(CONCURRENT);
            for _ in 0..CONCURRENT {
                open.push(connect_and_register(&listener).await);
            }
            assert!(
                listener.registry.len() >= registry_baseline + CONCURRENT,
                "every open connection must be registered while it is up"
            );
            drop(open);
        }

        eventually("the registry to drain to its baseline", || {
            listener.registry.len() == registry_baseline
        })
        .await;
        eventually("the connection map to drain to its baseline", || {
            listener.connection_map.len() == map_baseline
        })
        .await;
    }

    // --- end to end: the client's transport at the front ---------------------

    /// Start a TCP SIP listener that sits behind a front and is given the
    /// PROXY header by it.
    async fn spawn_proxied_listener() -> (SocketAddr, flume::Receiver<InboundMessage>) {
        let (inbound_tx, inbound_rx) = flume::unbounded();
        let (_outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
        let addr = listen(
            "127.0.0.1:0".parse().unwrap(),
            inbound_tx,
            outbound_rx,
            Arc::new(DashMap::new()),
            Arc::new(TransportAcl::new(vec![], vec![])),
            StreamConnections::new(),
            None,
            None,
            None,
            None,
            Some(Arc::new(ProxyProtocolAcl::new(
                &["127.0.0.0/8".to_string()],
            ))),
        )
        .await
        .expect("tcp listener must bind");
        (addr, inbound_rx)
    }

    /// A v2 `PROXY` header for TCP4, optionally carrying the `PP2_TYPE_SSL` TLV
    /// that reports the client's TLS session with the front.
    fn proxy_v2_tcp4(client_used_tls: bool) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&std::net::Ipv4Addr::new(192, 0, 2, 10).octets());
        body.extend_from_slice(&std::net::Ipv4Addr::new(198, 51, 100, 7).octets());
        body.extend_from_slice(&51234u16.to_be_bytes());
        body.extend_from_slice(&5061u16.to_be_bytes());
        if client_used_tls {
            // client=PP2_CLIENT_SSL, verify=0, then PP2_SUBTYPE_SSL_VERSION.
            let mut ssl_value = vec![0x01u8, 0, 0, 0, 0];
            ssl_value.push(0x21);
            ssl_value.extend_from_slice(&7u16.to_be_bytes());
            ssl_value.extend_from_slice(b"TLSv1.3");
            body.push(0x20); // PP2_TYPE_SSL
            body.extend_from_slice(&(ssl_value.len() as u16).to_be_bytes());
            body.extend_from_slice(&ssl_value);
        }
        let mut header = Vec::from(
            [
                0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
            ]
            .as_slice(),
        );
        header.push(0x21); // version 2, command PROXY
        header.push(0x11); // TCP over IPv4
        header.extend_from_slice(&(body.len() as u16).to_be_bytes());
        header.extend_from_slice(&body);
        header
    }

    const PROXIED_REGISTER: &str = concat!(
        "REGISTER sip:example.com SIP/2.0\r\n",
        "Via: SIP/2.0/TCP 192.0.2.10:51234;branch=z9hG4bK-edge\r\n",
        "From: <sip:alice@example.com>;tag=abc123\r\n",
        "To: <sip:alice@example.com>\r\n",
        "Call-ID: edge-tls-test@example.com\r\n",
        "CSeq: 1 REGISTER\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    );

    /// A re-encrypting front terminates the phone's TLS and opens its own
    /// plaintext connection, so the hop is TCP while the client spoke TLS. The
    /// `PP2_TYPE_SSL` TLV is the only record of that, and it has to reach the
    /// dispatcher beside the hop rather than replacing it — the hop is what
    /// decides the connection map, the Via token and the advertised address.
    #[tokio::test]
    async fn a_proxied_clients_edge_tls_reaches_the_dispatcher_beside_the_hop() {
        use tokio::io::AsyncWriteExt;

        let (addr, inbound_rx) = spawn_proxied_listener().await;
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        client.write_all(&proxy_v2_tcp4(true)).await.unwrap();
        client.write_all(PROXIED_REGISTER.as_bytes()).await.unwrap();

        let inbound =
            tokio::time::timeout(std::time::Duration::from_secs(2), inbound_rx.recv_async())
                .await
                .expect("the proxied REGISTER must be dispatched")
                .unwrap();

        assert_eq!(
            inbound.transport,
            Transport::Tcp,
            "the hop siphon accepted is still plaintext TCP"
        );
        assert_eq!(
            inbound.client_transport,
            Some(Transport::Tls),
            "the SSL TLV says the phone reached the front over TLS"
        );
        assert_eq!(
            inbound.remote_addr.ip().to_string(),
            "192.0.2.10",
            "the client address still comes from the header, not the front"
        );
    }

    /// The same front without the TLV: nothing contradicts the hop, so no
    /// client transport is invented for a connection that may well be plaintext
    /// end to end.
    #[tokio::test]
    async fn a_proxied_client_without_the_tlv_reports_no_separate_transport() {
        use tokio::io::AsyncWriteExt;

        let (addr, inbound_rx) = spawn_proxied_listener().await;
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        client.write_all(&proxy_v2_tcp4(false)).await.unwrap();
        client.write_all(PROXIED_REGISTER.as_bytes()).await.unwrap();

        let inbound =
            tokio::time::timeout(std::time::Duration::from_secs(2), inbound_rx.recv_async())
                .await
                .expect("the proxied REGISTER must be dispatched")
                .unwrap();
        assert_eq!(inbound.transport, Transport::Tcp);
        assert_eq!(inbound.client_transport, None);
    }
}
