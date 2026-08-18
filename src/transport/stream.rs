//! Shared plumbing for the connection-oriented (stream) transports: TCP, TLS,
//! WS and WSS.
//!
//! Three pieces live here, all of them previously duplicated between
//! [`super::tcp`], [`super::tls`] and [`super::ws`]:
//!
//! * [`spawn_outbound_distributor`] — the single task per listener that fans
//!   outbound messages out to per-connection senders (with the optional
//!   [`ConnectionPool`] fallback when no inbound connection matches).
//! * [`serve_sip_stream`] — the per-connection read/write pair that frames
//!   inbound bytes into SIP messages (RFC 3261 §18.3), answers RFC 5626 §4.4.1
//!   CRLF keepalives, and cleans up both registries on close.
//! * [`sniff_stream`] / [`PrefixedStream`] — first-line protocol detection, so
//!   one listening socket can carry raw SIP *and* SIP-over-WebSocket
//!   (RFC 7118). See [`super::mux`] for the listener that uses them.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

use crate::transport::crlf_keepalive::{drain_leading_crlf_keepalives, CrlfPongTracker};
use crate::transport::pool::ConnectionPool;
use crate::transport::tcp::{classify_incomplete_stream, extract_sip_message_length, StreamVerdict};
use crate::transport::{
    ConnectionId, InboundMessage, OutboundMessage, StreamConnections, Transport,
    CONNECTION_IDLE_TIMEOUT,
};

/// Create a listening TCP socket with `SO_REUSEADDR`/`SO_REUSEPORT` and the
/// optional DSCP marking applied *before* bind.
///
/// `SO_REUSEPORT` lets the outbound connection pool bind the same address, so
/// siphon can originate connections from its well-known SIP port. Note that it
/// also means two listeners on one address both bind successfully and the
/// kernel load-balances accepts between them — which is why sharing a port
/// between protocols goes through [`super::mux`] rather than two listeners.
pub(crate) fn bind_tcp_listener(
    local_addr: SocketAddr,
    tos: Option<u32>,
) -> io::Result<tokio::net::TcpListener> {
    let socket = if local_addr.is_ipv6() {
        tokio::net::TcpSocket::new_v6()?
    } else {
        tokio::net::TcpSocket::new_v4()?
    };
    socket.set_reuseaddr(true)?;
    #[cfg(unix)]
    socket.set_reuseport(true)?;
    // DSCP / DiffServ marking (RFC 4594) — family-aware (IP_TOS on v4,
    // IPV6_TCLASS on v6), best-effort so it never fails the listener.
    if let Some(tos) = tos {
        super::apply_tos(&socket2::SockRef::from(&socket), tos);
    }
    socket.bind(local_addr)?;
    socket.listen(1024)
}

/// Per-connection coordinates carried through the stream helpers.
#[derive(Debug, Clone, Copy)]
pub(crate) struct StreamContext {
    /// Transport this connection speaks — stamped on every `InboundMessage`
    /// and used to key the [`StreamConnections`] registry.
    pub transport: Transport,
    pub connection_id: ConnectionId,
    /// Local (listener) address the connection arrived on.
    pub local_addr: SocketAddr,
    /// Peer address.
    pub remote_addr: SocketAddr,
}

/// Spawn the outbound distributor for one stream listener.
///
/// Routes each [`OutboundMessage`] to its connection's bounded sender; when no
/// live connection matches (a fire-and-forget send with
/// `ConnectionId::default()`, or a connection that has since closed) it falls
/// back to the outbound [`ConnectionPool`] where one is supplied.
pub(crate) fn spawn_outbound_distributor(
    outbound_rx: flume::Receiver<OutboundMessage>,
    connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>>,
    transport: Transport,
    pool: Option<Arc<ConnectionPool>>,
) {
    tokio::spawn(async move {
        while let Ok(outbound) = outbound_rx.recv_async().await {
            if let Some(sender) = connection_map.get(&outbound.connection_id) {
                // Non-blocking: NEVER park in `send().await` here. This task is
                // the single outbound distributor and it holds the
                // `connection_map` shard read guard for the whole `if let`. A
                // non-reading peer fills its bounded channel; an awaiting send
                // would then park holding the guard — stalling outbound for
                // every connection (head-of-line) and blocking the accept
                // loop's `insert` on the same shard (accept stops, backlog
                // fills, engine wedges). `try_send` keeps the guard for only
                // the synchronous send and sheds for a backed-up (stuck) peer —
                // it will retransmit or its connection will close.
                let connection_id = outbound.connection_id;
                // Frames of one message keep their relative order: they enter
                // the same per-connection channel back to back, and this is the
                // only distributor task feeding it.
                for frame in outbound.into_frames() {
                    match sender.try_send(frame) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            warn!("{transport} outbound dropped: connection {connection_id:?} send buffer full (slow/stuck peer)");
                            break;
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            warn!("{transport} outbound dropped: connection {connection_id:?} closed");
                            break;
                        }
                    }
                }
            } else if let Some(pool) = pool.as_ref() {
                let destination = outbound.destination;
                let server_name = outbound.server_name.clone();
                let requested_connection_id = outbound.connection_id;
                // Sequential await per frame — the pool coalesces to one
                // connection per destination, so frames stay in order on it.
                for frame in outbound.into_frames() {
                    let sent = match transport {
                        Transport::Tls => pool.send_tls(destination, server_name.as_deref(), frame).await,
                        Transport::Tcp => pool.send_tcp(destination, frame).await,
                        // WS/WSS are client-initiated (RFC 7118 §5): there is no
                        // outbound-connect path, so a miss here is a dead UE.
                        other => {
                            warn!(
                                destination = %destination,
                                connection_id = ?requested_connection_id,
                                "{other} outbound dropped: no live connection and no outbound-connect path for this transport"
                            );
                            break;
                        }
                    };
                    match sent {
                        Ok(connection_id) => {
                            debug!(
                                destination = %destination,
                                connection_id = ?connection_id,
                                "{transport} outbound: sent via pool"
                            );
                        }
                        Err(error) => {
                            warn!(
                                destination = %destination,
                                connection_id = ?requested_connection_id,
                                "{transport} outbound pool connect failed: {error}"
                            );
                            break;
                        }
                    }
                }
            } else {
                debug!(
                    "{transport} outbound: connection {:?} not found (may have closed)",
                    outbound.connection_id
                );
            }
        }
    });
}

/// Drive one accepted stream connection for its whole lifetime: frame inbound
/// SIP messages out of the byte stream, write outbound frames back, and clean
/// up both registries when either half ends.
///
/// `seed` carries bytes already consumed from the stream (the protocol sniff in
/// [`super::mux`]); it is framed before the first read, so a complete message
/// that arrived inside the sniff window is never lost. Callers with nothing
/// pre-read pass an empty buffer.
///
/// `stream_connections` is `Some` for the transports that support MT routing
/// back over the inbound flow (TLS, WS, WSS) and `None` for TCP, which reaches
/// peers through the outbound [`ConnectionPool`] instead.
pub(crate) async fn serve_sip_stream<R, W>(
    reader: R,
    mut writer: W,
    context: StreamContext,
    seed: BytesMut,
    inbound_tx: flume::Sender<InboundMessage>,
    connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>>,
    stream_connections: Option<StreamConnections>,
    crlf_pong_tracker: Option<Arc<CrlfPongTracker>>,
    close_tx: Option<flume::Sender<u64>>,
) where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let StreamContext { transport, connection_id, local_addr, remote_addr } = context;

    // Per-connection outbound channel. Cloned for the read task so it can write
    // RFC 5626 §4.4.1 pong (`\r\n`) responses back over the same connection.
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<Bytes>(64);
    connection_map.insert(connection_id, outbound_tx.clone());
    if let Some(registry) = stream_connections.as_ref() {
        registry.register(remote_addr, transport, connection_id);
    }
    let keepalive_writer = outbound_tx;

    // Read task: SIP stream framing (RFC 3261 §18.3) with an idle timeout.
    let read_task = tokio::spawn(async move {
        let mut reader = reader;
        let mut accumulator = seed;
        let mut read_buf = [0u8; 8192];
        loop {
            // Extract every complete message currently buffered. Runs before
            // the first read so a seeded buffer is framed immediately.
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
                    // Header block complete, body still arriving — wait.
                    Some(_) => break,
                    None => match classify_incomplete_stream(&accumulator) {
                        // SIP still arriving — need more data.
                        StreamVerdict::MaybeSip => break,
                        StreamVerdict::Garbage => {
                            warn!("non-SIP bytes from {remote_addr} on {transport} {connection_id:?}; dropping connection");
                            crate::security::record_malformed_message(
                                remote_addr.ip(),
                                &transport.to_string(),
                            );
                            return; // close the connection
                        }
                    },
                };
                let data = accumulator.split_to(message_len).freeze();
                let message = InboundMessage {
                    connection_id,
                    transport,
                    local_addr,
                    remote_addr,
                    data,
                };
                if let Err(error) = inbound_tx.send_async(message).await {
                    error!("{transport} inbound enqueue failed: {error}");
                    return;
                }
            }

            match tokio::time::timeout(CONNECTION_IDLE_TIMEOUT, reader.read(&mut read_buf)).await {
                Ok(Ok(0)) => {
                    debug!("{transport} connection {connection_id:?} closed by peer");
                    break;
                }
                Ok(Ok(size)) => accumulator.extend_from_slice(&read_buf[..size]),
                Ok(Err(error)) => {
                    warn!("{transport} read error on {connection_id:?} from {remote_addr}: {error}");
                    break;
                }
                Err(_) => {
                    debug!(
                        "{transport} connection {connection_id:?} idle timeout ({}s)",
                        CONNECTION_IDLE_TIMEOUT.as_secs()
                    );
                    break;
                }
            }
        }
    });

    // Write task.
    let write_task = tokio::spawn(async move {
        while let Some(data) = outbound_rx.recv().await {
            if let Err(error) = writer.write_all(&data).await {
                warn!("{transport} write error on {connection_id:?}: {error}");
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
    if let Some(registry) = stream_connections.as_ref() {
        registry.unregister(&remote_addr);
    }
    // RFC 5626 §4.2.2 flow failure: notify the registrar so it can deregister
    // any binding that arrived on this connection. Best-effort.
    if let Some(close_tx) = &close_tx {
        let _ = close_tx.send(connection_id.0);
    }
    debug!("{transport} connection {connection_id:?} cleaned up");
}

// ---------------------------------------------------------------------------
// Protocol sniffing — raw SIP vs SIP-over-WebSocket on one socket
// ---------------------------------------------------------------------------

/// How long a freshly accepted connection may stay silent before it is assumed
/// to be raw SIP.
///
/// A WebSocket client always sends its `GET` immediately (the upgrade is
/// client-driven, RFC 6455 §4.1), so only a raw-SIP peer holding a connection
/// open for reuse (RFC 5923) ever reaches this timeout. Until the sniff
/// resolves the connection is not yet in the connection map, so a short budget
/// keeps the window in which siphon would open a second connection to that
/// peer instead of reusing this one.
pub(crate) const SNIFF_TIMEOUT: Duration = Duration::from_secs(2);

/// Bytes of first line tolerated before the sniff gives up. A SIP request line
/// and a WebSocket `GET` line are both far shorter; anything longer is a probe.
const MAX_SNIFF_BYTES: usize = 4096;

/// What a listening socket found on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamProtocol {
    /// Raw SIP over the stream (RFC 3261 §18.3 framing).
    Sip,
    /// An HTTP request line — a SIP-over-WebSocket upgrade (RFC 7118 §5).
    WebSocket,
}

/// Verdict of [`sniff_first_line`] on the bytes seen so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sniff {
    /// First line not complete yet — read more.
    NeedMore,
    /// Protocol determined.
    Decided(StreamProtocol),
    /// Neither SIP nor HTTP — a scanner probe or binary garbage.
    Garbage,
}

/// Classify a connection from its first line.
///
/// SIP and the WebSocket upgrade are unambiguous at the first line: a SIP
/// request line ends with ` SIP/2.0` and a status line starts with `SIP/2.0 `
/// (RFC 3261 §7.1/§7.2), while the upgrade is an HTTP request line ending in
/// ` HTTP/1.1` (RFC 6455 §4.1). No SIP method is a valid HTTP method and vice
/// versa, so no message is ever ambiguous.
///
/// Leading CRLFs (RFC 5626 §4.4.1 keepalives, RFC 3261 §7.5 stray CRLF) are
/// skipped for the decision but left in the buffer — the SIP read loop still
/// sees them and answers the ping.
pub(crate) fn sniff_first_line(buffer: &[u8]) -> Sniff {
    // A C0 control byte (other than CR/LF/HT) never appears in a SIP start-line
    // or an HTTP request line — catches binary probes (a TLS ClientHello on the
    // plaintext port, random bytes) before a CRLF is even seen.
    let head = &buffer[..buffer.len().min(512)];
    if head
        .iter()
        .any(|&byte| byte < 0x20 && byte != b'\r' && byte != b'\n' && byte != b'\t')
    {
        return Sniff::Garbage;
    }
    // Skip leading CRLF keepalives to find the start of the first real line.
    let start = buffer
        .iter()
        .position(|&byte| byte != b'\r' && byte != b'\n')
        .unwrap_or(buffer.len());
    let rest = &buffer[start..];
    let Some(line_end) = rest.windows(2).position(|window| window == b"\r\n") else {
        // First line still arriving. Bound it so a peer that never sends a CRLF
        // cannot pin the connection (the sniff timeout also covers this).
        return if buffer.len() > MAX_SNIFF_BYTES {
            Sniff::Garbage
        } else {
            Sniff::NeedMore
        };
    };
    let line = &rest[..line_end];
    if line.starts_with(b"SIP/2.0 ") || line.ends_with(b" SIP/2.0") {
        Sniff::Decided(StreamProtocol::Sip)
    } else if line.ends_with(b" HTTP/1.1") || line.ends_with(b" HTTP/1.0") {
        // Any HTTP request line, not just GET: tungstenite answers a non-GET
        // or a non-upgrade request with a proper HTTP error, which is a better
        // diagnostic for an operator who points a browser at the port than a
        // silent connection reset.
        Sniff::Decided(StreamProtocol::WebSocket)
    } else {
        Sniff::Garbage
    }
}

/// Read from `stream` until its protocol is known.
///
/// Returns the verdict plus every byte consumed while deciding, which the
/// caller must replay: seed it into [`serve_sip_stream`] for SIP, or wrap the
/// stream in [`PrefixedStream`] for WebSocket.
///
/// A peer that sends nothing within [`SNIFF_TIMEOUT`] is taken to be raw SIP
/// (a WebSocket client always sends its upgrade immediately), so a silent
/// connection held open for reuse is never dropped.
pub(crate) async fn sniff_stream<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> io::Result<(StreamProtocol, BytesMut)> {
    let mut buffer = BytesMut::with_capacity(1024);
    let mut read_buf = [0u8; 1024];
    let deadline = tokio::time::Instant::now() + SNIFF_TIMEOUT;

    loop {
        match sniff_first_line(&buffer) {
            Sniff::Decided(protocol) => return Ok((protocol, buffer)),
            Sniff::Garbage => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "neither SIP nor an HTTP upgrade",
                ))
            }
            Sniff::NeedMore => {}
        }
        match tokio::time::timeout_at(deadline, stream.read(&mut read_buf)).await {
            Ok(Ok(0)) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer closed before sending a first line",
                ))
            }
            Ok(Ok(size)) => buffer.extend_from_slice(&read_buf[..size]),
            Ok(Err(error)) => return Err(error),
            // Silent (or still mid-line) peer: assume raw SIP and let the SIP
            // read loop apply its own framing, garbage and idle rules.
            Err(_) => return Ok((StreamProtocol::Sip, buffer)),
        }
    }
}

/// A stream with bytes already read from it pushed back in front.
///
/// Wraps the socket after [`sniff_stream`] so the WebSocket handshake sees the
/// `GET` line the sniff consumed. Reads drain the prefix first, then delegate;
/// writes always delegate.
pub(crate) struct PrefixedStream<S> {
    inner: S,
    prefix: BytesMut,
}

impl<S> PrefixedStream<S> {
    pub(crate) fn new(inner: S, prefix: BytesMut) -> Self {
        Self { inner, prefix }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.prefix.is_empty() {
            let take = this.prefix.len().min(buf.remaining());
            buf.put_slice(&this.prefix.split_to(take));
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INVITE: &[u8] = concat!(
        "INVITE sip:bob@biloxi.com SIP/2.0\r\n",
        "Via: SIP/2.0/TCP pc33.atlanta.com;branch=z9hG4bK776\r\n",
        "From: <sip:alice@atlanta.com>;tag=1928301774\r\n",
        "To: <sip:bob@biloxi.com>\r\n",
        "Call-ID: a84b4c76e66710\r\n",
        "CSeq: 314159 INVITE\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    )
    .as_bytes();

    const UPGRADE: &[u8] = concat!(
        "GET / HTTP/1.1\r\n",
        "Host: proxy.example.com\r\n",
        "Upgrade: websocket\r\n",
        "Connection: Upgrade\r\n",
        "Sec-WebSocket-Protocol: sip\r\n",
        "\r\n",
    )
    .as_bytes();

    fn context() -> StreamContext {
        StreamContext {
            transport: Transport::Tcp,
            connection_id: ConnectionId(42),
            local_addr: "127.0.0.1:5060".parse().unwrap(),
            remote_addr: "127.0.0.1:41234".parse().unwrap(),
        }
    }

    // --- sniff_first_line ---------------------------------------------------

    #[test]
    fn sniffs_sip_request_line() {
        assert_eq!(sniff_first_line(INVITE), Sniff::Decided(StreamProtocol::Sip));
    }

    #[test]
    fn sniffs_sip_status_line() {
        assert_eq!(
            sniff_first_line(b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"),
            Sniff::Decided(StreamProtocol::Sip)
        );
    }

    #[test]
    fn sniffs_extension_method_as_sip() {
        // RFC 3261 §7.1 permits extension methods — the sniff keys on the
        // ` SIP/2.0` tail, never on a known-method list.
        assert_eq!(
            sniff_first_line(b"FROBNICATE sip:bob@biloxi.com SIP/2.0\r\n\r\n"),
            Sniff::Decided(StreamProtocol::Sip)
        );
    }

    #[test]
    fn sniffs_websocket_upgrade() {
        assert_eq!(sniff_first_line(UPGRADE), Sniff::Decided(StreamProtocol::WebSocket));
    }

    #[test]
    fn sniffs_http_1_0_request_line() {
        assert_eq!(
            sniff_first_line(b"GET /health HTTP/1.0\r\n\r\n"),
            Sniff::Decided(StreamProtocol::WebSocket)
        );
    }

    #[test]
    fn sniffs_sip_behind_leading_crlf_keepalives() {
        // RFC 5626 §4.4.1 ping before the first request must not confuse the
        // decision, and must stay in the buffer for the pong.
        let mut buffer = Vec::from(&b"\r\n\r\n"[..]);
        buffer.extend_from_slice(INVITE);
        assert_eq!(sniff_first_line(&buffer), Sniff::Decided(StreamProtocol::Sip));
    }

    #[test]
    fn sniff_needs_more_on_partial_first_line() {
        assert_eq!(sniff_first_line(b""), Sniff::NeedMore);
        assert_eq!(sniff_first_line(b"\r\n"), Sniff::NeedMore);
        assert_eq!(sniff_first_line(b"INVITE sip:bob@bilo"), Sniff::NeedMore);
        assert_eq!(sniff_first_line(b"GET / HTT"), Sniff::NeedMore);
    }

    #[test]
    fn sniff_rejects_binary_probe() {
        // A TLS ClientHello arriving on a plaintext port.
        assert_eq!(sniff_first_line(&[0x16, 0x03, 0x01, 0x00, 0x9c]), Sniff::Garbage);
    }

    #[test]
    fn sniff_rejects_complete_non_sip_non_http_line() {
        assert_eq!(sniff_first_line(b"HELO example.com\r\n"), Sniff::Garbage);
    }

    #[test]
    fn sniff_rejects_overlong_first_line() {
        let flood = vec![b'A'; MAX_SNIFF_BYTES + 1];
        assert_eq!(sniff_first_line(&flood), Sniff::Garbage);
    }

    // --- sniff_stream -------------------------------------------------------

    #[tokio::test]
    async fn sniff_stream_returns_sip_and_consumed_prefix() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        client.write_all(INVITE).await.unwrap();
        let (protocol, prefix) = sniff_stream(&mut server).await.unwrap();
        assert_eq!(protocol, StreamProtocol::Sip);
        assert_eq!(&prefix[..], INVITE, "every consumed byte must be returned for replay");
    }

    #[tokio::test]
    async fn sniff_stream_returns_websocket_and_consumed_prefix() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        client.write_all(UPGRADE).await.unwrap();
        let (protocol, prefix) = sniff_stream(&mut server).await.unwrap();
        assert_eq!(protocol, StreamProtocol::WebSocket);
        assert_eq!(&prefix[..], UPGRADE);
    }

    #[tokio::test]
    async fn sniff_stream_reassembles_a_split_first_line() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let sniff = tokio::spawn(async move { sniff_stream(&mut server).await.map(|(p, _)| p) });
        client.write_all(b"GET / HT").await.unwrap();
        client.write_all(b"TP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
        assert_eq!(sniff.await.unwrap().unwrap(), StreamProtocol::WebSocket);
    }

    #[tokio::test(start_paused = true)]
    async fn sniff_stream_defaults_to_sip_when_peer_stays_silent() {
        // RFC 5923 connection reuse: a peer may open a connection and wait for
        // siphon to send the first request. It must not be dropped.
        let (_client, mut server) = tokio::io::duplex(4096);
        let (protocol, prefix) = sniff_stream(&mut server).await.unwrap();
        assert_eq!(protocol, StreamProtocol::Sip);
        assert!(prefix.is_empty());
    }

    #[tokio::test]
    async fn sniff_stream_rejects_garbage() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        client.write_all(b"\x16\x03\x01hello").await.unwrap();
        let error = sniff_stream(&mut server).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn sniff_stream_reports_eof() {
        let (client, mut server) = tokio::io::duplex(4096);
        drop(client);
        let error = sniff_stream(&mut server).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    // --- PrefixedStream -----------------------------------------------------

    #[tokio::test]
    async fn prefixed_stream_replays_prefix_then_inner() {
        let (mut client, server) = tokio::io::duplex(4096);
        client.write_all(b"world").await.unwrap();
        let mut stream = PrefixedStream::new(server, BytesMut::from(&b"hello "[..]));
        let mut out = [0u8; 11];
        stream.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"hello world");
    }

    #[tokio::test]
    async fn prefixed_stream_writes_pass_through() {
        let (mut client, server) = tokio::io::duplex(4096);
        let mut stream = PrefixedStream::new(server, BytesMut::from(&b"unread"[..]));
        stream.write_all(b"pong").await.unwrap();
        let mut out = [0u8; 4];
        client.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"pong");
    }

    #[tokio::test]
    async fn prefixed_stream_handles_short_reads_of_the_prefix() {
        let (_client, server) = tokio::io::duplex(4096);
        let mut stream = PrefixedStream::new(server, BytesMut::from(&b"abcdef"[..]));
        let mut out = [0u8; 2];
        stream.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"ab");
        stream.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"cd");
    }

    // --- serve_sip_stream ---------------------------------------------------

    #[tokio::test]
    async fn serve_frames_a_seeded_message_before_reading() {
        let (_client, server) = tokio::io::duplex(4096);
        let (reader, writer) = tokio::io::split(server);
        let (inbound_tx, inbound_rx) = flume::unbounded();
        let connection_map = Arc::new(DashMap::new());
        tokio::spawn(serve_sip_stream(
            reader,
            writer,
            context(),
            BytesMut::from(INVITE),
            inbound_tx,
            connection_map,
            None,
            None,
            None,
        ));
        let message = inbound_rx.recv_async().await.unwrap();
        assert_eq!(&message.data[..], INVITE);
        assert_eq!(message.transport, Transport::Tcp);
        assert_eq!(message.connection_id, ConnectionId(42));
    }

    #[tokio::test]
    async fn serve_frames_two_messages_coalesced_in_one_segment() {
        let (mut client, server) = tokio::io::duplex(8192);
        let (reader, writer) = tokio::io::split(server);
        let (inbound_tx, inbound_rx) = flume::unbounded();
        let connection_map = Arc::new(DashMap::new());
        tokio::spawn(serve_sip_stream(
            reader,
            writer,
            context(),
            BytesMut::new(),
            inbound_tx,
            connection_map,
            None,
            None,
            None,
        ));
        let mut both = Vec::from(INVITE);
        both.extend_from_slice(INVITE);
        client.write_all(&both).await.unwrap();
        assert_eq!(&inbound_rx.recv_async().await.unwrap().data[..], INVITE);
        assert_eq!(&inbound_rx.recv_async().await.unwrap().data[..], INVITE);
    }

    #[tokio::test]
    async fn serve_registers_and_deregisters_the_flow_registry() {
        let (client, server) = tokio::io::duplex(4096);
        let (reader, writer) = tokio::io::split(server);
        let (inbound_tx, _inbound_rx) = flume::unbounded();
        let connection_map = Arc::new(DashMap::new());
        let registry = StreamConnections::new();
        let context = StreamContext { transport: Transport::Tls, ..context() };
        let (close_tx, close_rx) = flume::unbounded();
        let served = tokio::spawn(serve_sip_stream(
            reader,
            writer,
            context,
            BytesMut::new(),
            inbound_tx,
            connection_map.clone(),
            Some(registry.clone()),
            None,
            Some(close_tx),
        ));
        // Wait for registration to land, then close the peer.
        while registry.get(&context.remote_addr).is_none() {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            registry.get(&context.remote_addr),
            Some((Transport::Tls, ConnectionId(42)))
        );
        assert!(connection_map.contains_key(&ConnectionId(42)));

        drop(client);
        served.await.unwrap();
        assert!(registry.get(&context.remote_addr).is_none(), "flow must be unregistered on close");
        assert!(!connection_map.contains_key(&ConnectionId(42)));
        // RFC 5626 §4.2.2 flow failure is reported to the registrar.
        assert_eq!(close_rx.recv_async().await.unwrap(), 42);
    }

    #[tokio::test]
    async fn serve_writes_outbound_frames_to_the_peer() {
        let (mut client, server) = tokio::io::duplex(4096);
        let (reader, writer) = tokio::io::split(server);
        let (inbound_tx, _inbound_rx) = flume::unbounded();
        let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> =
            Arc::new(DashMap::new());
        tokio::spawn(serve_sip_stream(
            reader,
            writer,
            context(),
            BytesMut::new(),
            inbound_tx,
            connection_map.clone(),
            None,
            None,
            None,
        ));
        let sender = loop {
            if let Some(entry) = connection_map.get(&ConnectionId(42)) {
                break entry.value().clone();
            }
            tokio::task::yield_now().await;
        };
        sender.send(Bytes::from_static(b"SIP/2.0 200 OK\r\n\r\n")).await.unwrap();
        let mut out = vec![0u8; 18];
        client.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"SIP/2.0 200 OK\r\n\r\n");
    }

    #[tokio::test]
    async fn serve_drops_the_connection_on_non_sip_bytes() {
        let (mut client, server) = tokio::io::duplex(4096);
        let (reader, writer) = tokio::io::split(server);
        let (inbound_tx, _inbound_rx) = flume::unbounded();
        let connection_map = Arc::new(DashMap::new());
        let served = tokio::spawn(serve_sip_stream(
            reader,
            writer,
            context(),
            BytesMut::new(),
            inbound_tx,
            connection_map.clone(),
            None,
            None,
            None,
        ));
        client.write_all(b"HELO example.com\r\n").await.unwrap();
        served.await.unwrap();
        assert!(!connection_map.contains_key(&ConnectionId(42)));
    }
}
