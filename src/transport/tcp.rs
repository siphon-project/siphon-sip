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

use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::transport::{ConnectionId, InboundMessage, OutboundMessage, Transport, CONNECTION_IDLE_TIMEOUT, configure_tcp_socket, next_connection_id};
use crate::transport::acl::TransportAcl;
use crate::transport::crlf_keepalive::{drain_leading_crlf_keepalives, CrlfPongTracker};
use crate::transport::pool::ConnectionPool;

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
    // Spawn a task that distributes outbound messages to per-connection senders.
    // When no existing connection matches (`ConnectionId::default()` from fire-
    // and-forget UAC sends, or a connection that has since closed), fall back
    // to the outbound `ConnectionPool` to open a new TCP connection.  Without
    // this fallback the message would be silently dropped — the bug that left
    // in-dialog NOTIFY frames built but never written to the wire when the
    // Route header pointed at a destination with no live inbound connection.
    let connection_map_clone = connection_map.clone();
    tokio::spawn(async move {
        while let Ok(outbound) = outbound_rx.recv_async().await {
            if let Some(sender) = connection_map_clone.get(&outbound.connection_id) {
                // Non-blocking: NEVER park in `send().await` here. This task is the
                // single outbound distributor and it holds the `connection_map`
                // shard read guard for the whole `if let`. A non-reading peer
                // fills its bounded channel; an awaiting send would then park
                // holding the guard — stalling outbound for every connection
                // (head-of-line) and blocking the accept loop's `insert` on the
                // same shard (accept stops, backlog fills, engine wedges).
                // `try_send` keeps the guard for only the synchronous send and
                // sheds for a backed-up (stuck) peer — it will retransmit or its
                // connection will close.
                match sender.try_send(outbound.data) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        warn!("TCP outbound dropped: connection {:?} send buffer full (slow/stuck peer)", outbound.connection_id);
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        warn!("TCP outbound dropped: connection {:?} closed", outbound.connection_id);
                    }
                }
            } else if let Some(ref pool) = pool {
                match pool.send_tcp(outbound.destination, outbound.data).await {
                    Ok(connection_id) => {
                        debug!(
                            destination = %outbound.destination,
                            connection_id = ?connection_id,
                            "TCP outbound: sent via pool"
                        );
                    }
                    Err(error) => {
                        warn!(
                            destination = %outbound.destination,
                            connection_id = ?outbound.connection_id,
                            "TCP outbound pool connect failed: {error}"
                        );
                    }
                }
            } else {
                warn!(
                    destination = %outbound.destination,
                    connection_id = ?outbound.connection_id,
                    "TCP outbound dropped: no live connection and no pool available"
                );
            }
        }
    });

    tokio::spawn(async move {
        // Use TcpSocket so we can set SO_REUSEADDR/SO_REUSEPORT before binding.
        // This allows the outbound connection pool to also bind to this address,
        // enabling outbound connections from the well-known SIP port.
        let socket = if local_addr.is_ipv6() {
            match tokio::net::TcpSocket::new_v6() {
                Ok(socket) => socket,
                Err(error) => { error!("failed to create TCP socket: {error}"); return; }
            }
        } else {
            match tokio::net::TcpSocket::new_v4() {
                Ok(socket) => socket,
                Err(error) => { error!("failed to create TCP socket: {error}"); return; }
            }
        };
        if let Err(error) = socket.set_reuseaddr(true) {
            error!("failed to set SO_REUSEADDR: {error}"); return;
        }
        #[cfg(unix)]
        if let Err(error) = socket.set_reuseport(true) {
            error!("failed to set SO_REUSEPORT: {error}"); return;
        }
        // DSCP / DiffServ marking (RFC 4594) — family-aware (IP_TOS on v4,
        // IPV6_TCLASS on v6), best-effort so it never fails the listener.
        if let Some(tos) = tos {
            super::apply_tos(&socket2::SockRef::from(&socket), tos);
        }
        if let Err(error) = socket.bind(local_addr) {
            error!("failed to bind TCP listener to {local_addr}: {error}"); return;
        }
        let listener = match socket.listen(1024) {
            Ok(listener) => listener,
            Err(error) => { error!("failed to listen on TCP socket: {error}"); return; }
        };
        info!("TCP listener on {}", local_addr);

        loop {
            match listener.accept().await {
                Ok((socket, remote_addr)) => {
                    if !acl.is_allowed(remote_addr.ip()) {
                        debug!("TCP rejected {} by ACL", remote_addr);
                        continue;
                    }
                    let connection_id = next_connection_id();
                    let inbound_tx = inbound_tx.clone();
                    let connection_map = connection_map.clone();

                    configure_tcp_socket(&socket, tos);
                    debug!("TCP accepted {} as {:?}", remote_addr, connection_id);

                    let crlf_pong_tracker = crlf_pong_tracker.clone();
                    let close_tx = close_tx.clone();
                    tokio::spawn(async move {
                        let local_addr = socket.local_addr().unwrap_or(local_addr);
                        let (mut reader, mut writer) = socket.into_split();

                        // Per-connection outbound channel.  Cloned for the read
                        // task so it can write RFC 5626 §4.4.1 pong (`\r\n`)
                        // responses back over the same connection.
                        let (outbound_tx, mut outbound_rx) = mpsc::channel::<Bytes>(64);
                        connection_map.insert(connection_id, outbound_tx.clone());
                        let keepalive_writer = outbound_tx;

                        // Read task with idle timeout and SIP stream framing (RFC 3261 §18.3)
                        let inbound_tx_clone = inbound_tx.clone();
                        let read_task = tokio::spawn(async move {
                            let mut accumulator = BytesMut::with_capacity(65536);
                            let mut read_buf = [0u8; 8192];
                            loop {
                                match tokio::time::timeout(CONNECTION_IDLE_TIMEOUT, reader.read(&mut read_buf)).await {
                                    Ok(Ok(0)) => {
                                        debug!("TCP connection {:?} closed by peer", connection_id);
                                        break;
                                    }
                                    Ok(Ok(size)) => {
                                        accumulator.extend_from_slice(&read_buf[..size]);

                                        // Extract all complete SIP messages from the buffer
                                        loop {
                                            // RFC 5626 §4.4.1 keepalive handling + RFC 3261 §7.5
                                            // stray-CRLF stripping in one pass.
                                            drain_leading_crlf_keepalives(
                                                &mut accumulator,
                                                connection_id,
                                                &keepalive_writer,
                                                crlf_pong_tracker.as_ref(),
                                            );
                                            if accumulator.is_empty() {
                                                break;
                                            }
                                            let message_len = match extract_sip_message_length(&accumulator) {
                                                Some(len) if len <= accumulator.len() => len,
                                                Some(_) => break, // header block complete, body still arriving — wait
                                                None => match classify_incomplete_stream(&accumulator) {
                                                    StreamVerdict::MaybeSip => break, // SIP still arriving — need more data
                                                    StreamVerdict::Garbage => {
                                                        warn!("non-SIP bytes from {} on TCP {:?}; dropping connection", remote_addr, connection_id);
                                                        crate::security::record_malformed_message(remote_addr.ip(), "TCP");
                                                        return; // close the connection
                                                    }
                                                },
                                            };
                                            let data = accumulator.split_to(message_len).freeze();
                                            let message = InboundMessage {
                                                connection_id,
                                                transport: Transport::Tcp,
                                                local_addr,
                                                remote_addr,
                                                data,
                                            };
                                            if let Err(e) = inbound_tx_clone.send_async(message).await {
                                                error!("TCP inbound enqueue failed: {}", e);
                                                return;
                                            }
                                        }
                                    }
                                    Ok(Err(e)) => {
                                        warn!("TCP read error on {:?}: {}", connection_id, e);
                                        break;
                                    }
                                    Err(_) => {
                                        debug!("TCP connection {:?} idle timeout ({}s)", connection_id, CONNECTION_IDLE_TIMEOUT.as_secs());
                                        break;
                                    }
                                }
                            }
                        });

                        // Write task
                        let write_task = tokio::spawn(async move {
                            while let Some(data) = outbound_rx.recv().await {
                                if let Err(e) = writer.write_all(&data).await {
                                    warn!("TCP write error on {:?}: {}", connection_id, e);
                                    break;
                                }
                            }
                        });

                        // Wait for either half to close, then clean up.
                        tokio::select! {
                            _ = read_task => {}
                            _ = write_task => {}
                        }

                        connection_map.remove(&connection_id);
                        // RFC 5626 §4.2.2 flow failure: tell the registrar the
                        // inbound flow is gone so it can deregister any binding
                        // that arrived on this connection.  Best-effort; the
                        // drain task no-ops for connections that never
                        // registered.
                        if let Some(close_tx) = &close_tx {
                            let _ = close_tx.send(connection_id.0);
                        }
                        debug!("TCP connection {:?} cleaned up", connection_id);
                    });
                }
                Err(e) => {
                    error!("TCP accept error: {}", e);
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
pub(crate) fn extract_sip_message_length(buffer: &[u8]) -> Option<usize> {
    // Find end of headers
    let header_end = buffer
        .windows(4)
        .position(|w| w == b"\r\n\r\n")?;
    let headers_len = header_end + 4; // include the \r\n\r\n

    // Parse Content-Length from header block
    let header_block = &buffer[..header_end];
    let content_length = extract_content_length(header_block).unwrap_or(0);

    Some(headers_len + content_length)
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

/// Extract Content-Length value from raw header bytes.
/// Handles both full name and compact form (`l:`).
fn extract_content_length(headers: &[u8]) -> Option<usize> {
    // Search line-by-line for Content-Length or compact form "l:"
    for line in headers.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        // Skip lines without a colon (request-line, empty lines from keepalive CRLFs)
        let colon_pos = match line.iter().position(|&b| b == b':') {
            Some(pos) => pos,
            None => continue,
        };
        let (name, value) = line.split_at(colon_pos);
        let value = &value[1..]; // skip the ':'
        let name_lower: Vec<u8> = name.iter().map(|b| b.to_ascii_lowercase()).collect();
        let name_trimmed = name_lower.trim_ascii();
        if name_trimmed == b"content-length" || name_trimmed == b"l" {
            let value_str = std::str::from_utf8(value).ok()?;
            return value_str.trim().parse().ok();
        }
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
}
