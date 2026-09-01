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
use tracing::{debug, error, info};

use crate::transport::{ConnectionId, InboundMessage, OutboundMessage, Transport, configure_tcp_socket, next_connection_id};
use crate::transport::acl::TransportAcl;
use crate::transport::crlf_keepalive::CrlfPongTracker;
use crate::transport::pool::ConnectionPool;
use crate::transport::stream::{bind_tcp_listener, serve_sip_stream, sniff_sip_or_drop, spawn_outbound_distributor, StreamContext};

/// Spawn a TCP listener. For each accepted connection a task is spawned that:
///   1. Reads inbound SIP messages and sends them to `inbound_tx`
///   2. Receives outbound messages from its per-connection channel and writes them
///
/// The `connection_map` maps ConnectionId → per-connection outbound sender.
/// The outbound dispatcher (in the core) looks up the connection ID and routes
/// responses to the right connection.
pub async fn listen(
    local_addr: SocketAddr,
    inbound_tx: flume::Sender<InboundMessage>,
    outbound_rx: flume::Receiver<OutboundMessage>,
    connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>>,
    acl: Arc<TransportAcl>,
    tos: Option<u32>,
    pool: Option<Arc<ConnectionPool>>,
    crlf_pong_tracker: Option<Arc<CrlfPongTracker>>,
    close_tx: Option<flume::Sender<u64>>,
) {
    // Distribute outbound messages to per-connection senders. When no existing
    // connection matches (`ConnectionId::default()` from fire-and-forget UAC
    // sends, or a connection that has since closed), the distributor falls back
    // to the outbound `ConnectionPool` to open a new TCP connection. Without
    // that fallback the message would be silently dropped — the bug that left
    // in-dialog NOTIFY frames built but never written to the wire when the
    // Route header pointed at a destination with no live inbound connection.
    spawn_outbound_distributor(outbound_rx, connection_map.clone(), Transport::Tcp, pool);

    tokio::spawn(async move {
        let listener = match bind_tcp_listener(local_addr, tos) {
            Ok(listener) => listener,
            Err(error) => {
                error!("failed to bind TCP listener to {local_addr}: {error}");
                return;
            }
        };
        info!("TCP listener on {}", local_addr);

        loop {
            match listener.accept().await {
                Ok((mut socket, remote_addr)) => {
                    if !acl.is_allowed(remote_addr.ip()) {
                        debug!("TCP rejected {} by ACL", remote_addr);
                        continue;
                    }
                    let inbound_tx = inbound_tx.clone();
                    let connection_map = connection_map.clone();

                    configure_tcp_socket(&socket, tos);

                    let crlf_pong_tracker = crlf_pong_tracker.clone();
                    let close_tx = close_tx.clone();
                    tokio::spawn(async move {
                        let local_addr = socket.local_addr().unwrap_or(local_addr);
                        // Decide from the first line that this really is SIP,
                        // before any byte reaches the framer — an HTTP probe
                        // frames as a complete "message" and would otherwise be
                        // caught only by the parser, too late to close the
                        // connection or count the source. Classifying ahead of
                        // the connection id also keeps a probe out of the
                        // connection map and out of the accept log.
                        let Some(seed) =
                            sniff_sip_or_drop(&mut socket, remote_addr, Transport::Tcp).await
                        else {
                            return;
                        };

                        let connection_id = next_connection_id();
                        debug!("TCP accepted {} as {:?}", remote_addr, connection_id);

                        let (reader, writer) = socket.into_split();
                        serve_sip_stream(
                            reader,
                            writer,
                            StreamContext {
                                transport: Transport::Tcp,
                                connection_id,
                                local_addr,
                                remote_addr,
                            },
                            seed,
                            inbound_tx,
                            connection_map,
                            // TCP reaches peers through the outbound pool, not
                            // by sending back over the inbound flow, so it does
                            // not register in the stream-connection registry.
                            None,
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
    let header_end = rest
        .windows(4)
        .position(|w| w == b"\r\n\r\n")?;
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
            let line = &buffer[..line_end];
            if line.starts_with(b"SIP/2.0 ") || line.ends_with(b" SIP/2.0") {
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
    if len > max_message_bytes {
        // Safe: `extract_sip_message_length` returned `Some`, so `\r\n\r\n`
        // is present and the header block is fully buffered. Measured past any
        // leading CRLF keepalives, exactly as the length above was.
        let prefix = crate::sip::parser::leading_crlf_len(buffer);
        let header_len = buffer[prefix..]
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|end| prefix + end + 4)
            .unwrap_or(buffer.len());
        return FrameVerdict::Oversized { declared: len, header_len };
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
        connection_map.get(&conn_a).unwrap().send(data_a.clone()).await.unwrap();

        // Send to conn_b
        let data_b = Bytes::from_static(b"SIP/2.0 200 OK for B\r\n\r\n");
        connection_map.get(&conn_b).unwrap().send(data_b.clone()).await.unwrap();

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
        assert_eq!(
            classify_incomplete_stream(&flood),
            StreamVerdict::Garbage
        );
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
            FrameVerdict::Oversized { declared, header_len } => {
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
            matches!(frame_sip_message(attack, CEILING), FrameVerdict::Oversized { .. }),
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
            FrameVerdict::Complete { len: complete.len() }
        );

        let mut partial = headers.to_vec();
        partial.extend_from_slice(b"AA");
        assert_eq!(frame_sip_message(&partial, CEILING), FrameVerdict::NeedMore);
    }

    /// The pre-existing `classify_incomplete_stream` guards still fire through
    /// the new entry point, unchanged: they apply only while the header block
    /// is incomplete (a buffer that already holds `\r\n\r\n` frames as a
    /// message and is judged further up the stack).
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

    /// Bind a port, release it, and start a TCP SIP listener on it.
    async fn spawn_listener() -> (SocketAddr, flume::Receiver<InboundMessage>) {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);

        let (inbound_tx, inbound_rx) = flume::unbounded();
        let (_outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
        listen(
            addr,
            inbound_tx,
            outbound_rx,
            Arc::new(DashMap::new()),
            Arc::new(TransportAcl::new(vec![], vec![])),
            None,
            None,
            None,
            None,
        )
        .await;
        // listen() binds inside a spawned task.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        (addr, inbound_rx)
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
        assert!(inbound_rx.is_empty(), "the probe must never reach the dispatcher");
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

        let inbound = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            inbound_rx.recv_async(),
        )
        .await
        .expect("SIP must still be dispatched")
        .unwrap();
        assert_eq!(&inbound.data[..], register.as_bytes());
        assert_eq!(inbound.transport, Transport::Tcp);
    }
}
