//! Transport abstraction for Diameter: TCP and SCTP.
//!
//! Provides `DiameterStream` (AsyncRead + AsyncWrite) and `DiameterListener`
//! that work with both TCP and one-to-one SCTP associations.
//!
//! SCTP uses `tokio-sctp` with a duplex bridge: background tasks do
//! recvmsg/sendmsg while the user-facing side implements AsyncRead/AsyncWrite.
//! It links the `libsctp` system library, so the whole SCTP half of this module
//! is gated behind the `sctp` Cargo feature (off by default). When the feature
//! is disabled, only the TCP transport is compiled in and
//! [`connect`] rejects `transport == "sctp"` with `ErrorKind::Unsupported`.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
#[cfg(feature = "sctp")]
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::{TcpListener, TcpStream};
#[cfg(feature = "sctp")]
use tokio_sctp::{SctpListener, SctpStream, SendOptions};

// ── SCTP AsyncRead/AsyncWrite bridge ────────────────────────────────────

/// Wrapper around `tokio_sctp::SctpStream` that implements `AsyncRead + AsyncWrite`
/// by bridging through background tasks that call recvmsg/sendmsg on SCTP stream 0.
#[cfg(feature = "sctp")]
pub struct SctpAsyncStream {
    reader: DuplexStream,
    writer: DuplexStream,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
}

#[cfg(feature = "sctp")]
impl SctpAsyncStream {
    pub fn new(stream: SctpStream) -> Self {
        let fallback_addr = SocketAddr::from(([0, 0, 0, 0], 0));
        let local_addr = stream.local_addr().unwrap_or(fallback_addr);
        let peer_addr = stream.peer_addr().unwrap_or(fallback_addr);

        let (read_tx, read_rx) = tokio::io::duplex(65536);
        let (write_tx, write_rx) = tokio::io::duplex(65536);

        let stream = std::sync::Arc::new(stream);
        let stream2 = std::sync::Arc::clone(&stream);

        // Reader task: SCTP recvmsg → duplex
        tokio::spawn(async move {
            let mut tx = read_tx;
            loop {
                let mut buf = vec![0u8; 65536];
                let mut read_buf = ReadBuf::new(&mut buf);
                match stream.recvmsg(&mut read_buf).await {
                    Ok((n, _info, _flags)) => {
                        if n == 0 {
                            break;
                        }
                        // Bounded: the duplex pipe is 64 KB, so a Diameter
                        // reader that stops draining backs this up and an
                        // unbounded write parks the task holding the SCTP
                        // association open with nothing draining either side.
                        match tokio::time::timeout(
                            crate::diameter::peer::HANDSHAKE_TIMEOUT,
                            tx.write_all(&buf[..n]),
                        )
                        .await
                        {
                            Ok(Ok(())) => {}
                            _ => break,
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // Writer task: duplex → SCTP sendmsg
        tokio::spawn(async move {
            let mut rx = write_rx;
            let opts = SendOptions::default();
            loop {
                let mut buf = vec![0u8; 65536];
                match rx.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        // Bounded for the mirror reason: a peer that stops
                        // draining the association must not pin this task.
                        match tokio::time::timeout(
                            crate::diameter::peer::HANDSHAKE_TIMEOUT,
                            stream2.sendmsg(&buf[..n], None, &opts),
                        )
                        .await
                        {
                            Ok(Ok(_)) => {}
                            _ => break,
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            reader: read_rx,
            writer: write_tx,
            local_addr,
            peer_addr,
        }
    }

    /// Connect to an SCTP peer.
    pub async fn connect(addr: SocketAddr) -> io::Result<Self> {
        Self::connect_from(addr, None).await
    }

    /// Connect to an SCTP peer from the local address `source` (any port),
    /// bound before the connect; `None` leaves the choice to the kernel.
    pub async fn connect_from(
        addr: SocketAddr,
        source: Option<std::net::IpAddr>,
    ) -> io::Result<Self> {
        let Some(source) = source else {
            return Ok(Self::new(SctpStream::connect(addr).await?));
        };
        if source.is_ipv4() != addr.is_ipv4() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source_address and peer address are of different families",
            ));
        }
        let family = if addr.is_ipv4() {
            libc::AF_INET
        } else {
            libc::AF_INET6
        };
        // tokio-sctp builds its sockets with a socket2 of another major
        // version than ours, so its `Domain` cannot be named here. The
        // descriptor is made directly and handed to its socket type, which
        // takes any `FromRawFd`; it is closed when that is dropped.
        //
        // SAFETY: `socket(2)` returns a new descriptor or -1; a descriptor
        // is owned by nothing else, so the wrapper may own it.
        let socket = unsafe {
            let descriptor = libc::socket(family, libc::SOCK_STREAM, libc::IPPROTO_SCTP);
            if descriptor < 0 {
                return Err(io::Error::last_os_error());
            }
            tokio_sctp::SctpSocket {
                inner: std::os::fd::FromRawFd::from_raw_fd(descriptor),
            }
        };
        socket.bind_sys(SocketAddr::new(source, 0))?;
        Ok(Self::new(SctpStream::connect_from(socket, addr).await?))
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.peer_addr)
    }
}

#[cfg(feature = "sctp")]
impl AsyncRead for SctpAsyncStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buf)
    }
}

#[cfg(feature = "sctp")]
impl AsyncWrite for SctpAsyncStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.writer).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

// ── Unified DiameterStream ───────────────────────────────────────────────

/// A Diameter transport stream, either TCP or SCTP.
pub enum DiameterStream {
    Tcp(TcpStream),
    #[cfg(feature = "sctp")]
    Sctp(SctpAsyncStream),
}

impl DiameterStream {
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        match self {
            DiameterStream::Tcp(s) => s.peer_addr(),
            #[cfg(feature = "sctp")]
            DiameterStream::Sctp(s) => s.peer_addr(),
        }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            DiameterStream::Tcp(s) => s.local_addr(),
            #[cfg(feature = "sctp")]
            DiameterStream::Sctp(s) => s.local_addr(),
        }
    }

    pub fn transport_name(&self) -> &'static str {
        match self {
            DiameterStream::Tcp(_) => "TCP",
            #[cfg(feature = "sctp")]
            DiameterStream::Sctp(_) => "SCTP",
        }
    }
}

impl From<TcpStream> for DiameterStream {
    fn from(s: TcpStream) -> Self {
        DiameterStream::Tcp(s)
    }
}

#[cfg(feature = "sctp")]
impl From<SctpAsyncStream> for DiameterStream {
    fn from(s: SctpAsyncStream) -> Self {
        DiameterStream::Sctp(s)
    }
}

impl AsyncRead for DiameterStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            DiameterStream::Tcp(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(feature = "sctp")]
            DiameterStream::Sctp(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for DiameterStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            DiameterStream::Tcp(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(feature = "sctp")]
            DiameterStream::Sctp(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            DiameterStream::Tcp(s) => Pin::new(s).poll_flush(cx),
            #[cfg(feature = "sctp")]
            DiameterStream::Sctp(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            DiameterStream::Tcp(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(feature = "sctp")]
            DiameterStream::Sctp(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

// ── Unified DiameterListener ─────────────────────────────────────────────

/// A Diameter listener, either TCP or SCTP.
pub enum DiameterListener {
    Tcp(TcpListener),
    #[cfg(feature = "sctp")]
    Sctp(SctpListener),
}

impl DiameterListener {
    /// Bind a TCP listener.
    pub async fn bind_tcp(addr: &str) -> io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(DiameterListener::Tcp(listener))
    }

    /// Bind an SCTP listener.
    #[cfg(feature = "sctp")]
    pub fn bind_sctp(addr: SocketAddr) -> io::Result<Self> {
        let listener = SctpListener::bind(addr)?;
        Ok(DiameterListener::Sctp(listener))
    }

    /// Accept a new connection.
    pub async fn accept(&self) -> io::Result<(DiameterStream, SocketAddr)> {
        match self {
            DiameterListener::Tcp(l) => {
                let (stream, addr) = l.accept().await?;
                Ok((DiameterStream::Tcp(stream), addr))
            }
            #[cfg(feature = "sctp")]
            DiameterListener::Sctp(l) => {
                let (stream, addr) = l.accept().await?;
                Ok((DiameterStream::Sctp(SctpAsyncStream::new(stream)), addr))
            }
        }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            DiameterListener::Tcp(l) => l.local_addr(),
            #[cfg(feature = "sctp")]
            DiameterListener::Sctp(l) => l.local_addr(),
        }
    }

    pub fn transport_name(&self) -> &'static str {
        match self {
            DiameterListener::Tcp(_) => "TCP",
            #[cfg(feature = "sctp")]
            DiameterListener::Sctp(_) => "SCTP",
        }
    }
}

/// Connect to a Diameter peer over TCP or SCTP.
pub async fn connect(addr: &str, transport: &str) -> io::Result<DiameterStream> {
    connect_from(addr, transport, None).await
}

/// Connect to a Diameter peer over TCP or SCTP from the local address
/// `source` (any port), bound before the connect. A node on a multi-homed
/// host originates from the address its peer expects, not from the default
/// route's. `None` leaves the choice to the kernel.
pub async fn connect_from(
    addr: &str,
    transport: &str,
    source: Option<std::net::IpAddr>,
) -> io::Result<DiameterStream> {
    match transport {
        #[cfg(feature = "sctp")]
        "sctp" => {
            let addr: SocketAddr = addr.parse().map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("bad address: {}", e))
            })?;
            let stream = SctpAsyncStream::connect_from(addr, source).await?;
            Ok(DiameterStream::Sctp(stream))
        }
        #[cfg(not(feature = "sctp"))]
        "sctp" => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Diameter-over-SCTP requested but this binary was built without the `sctp` feature; \
             rebuild with `--features sctp`",
        )),
        _ => {
            let stream = match source {
                None => TcpStream::connect(addr).await?,
                Some(source) => {
                    let remote = tokio::net::lookup_host(addr)
                        .await?
                        .find(|remote| remote.is_ipv4() == source.is_ipv4())
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                format!("{addr} has no address of the family of source_address"),
                            )
                        })?;
                    let socket = if source.is_ipv4() {
                        tokio::net::TcpSocket::new_v4()?
                    } else {
                        tokio::net::TcpSocket::new_v6()?
                    };
                    socket.bind(SocketAddr::new(source, 0))?;
                    socket.connect(remote).await?
                }
            };
            Ok(DiameterStream::Tcp(stream))
        }
    }
}

#[cfg(test)]
mod source_address_tests {
    use super::*;

    /// The address a listener sees a connection arrive from.
    async fn seen_from(source: Option<std::net::IpAddr>) -> std::net::IpAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = tokio::spawn(async move { listener.accept().await.unwrap().1.ip() });
        let _stream = connect_from(&address.to_string(), "tcp", source)
            .await
            .unwrap();
        accepted.await.unwrap()
    }

    #[tokio::test]
    async fn a_configured_source_address_is_where_the_connection_comes_from() {
        let source: std::net::IpAddr = "127.0.0.3".parse().unwrap();
        assert_eq!(seen_from(Some(source)).await, source);
    }

    #[tokio::test]
    async fn without_a_source_address_the_kernel_chooses() {
        let expected: std::net::IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(seen_from(None).await, expected);
    }

    #[tokio::test]
    async fn a_source_address_of_the_wrong_family_is_refused() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let result = connect_from(&address.to_string(), "tcp", Some("::1".parse().unwrap())).await;
        assert!(result.is_err());
    }

    #[test]
    fn the_entries_of_the_configuration_take_a_source_address() {
        let entry: crate::config::DiameterServerEntry =
            serde_saphyr::from_str("{name: a, host: example.net, source_address: 192.0.2.7}")
                .unwrap();
        assert_eq!(entry.source_address, Some("192.0.2.7".parse().unwrap()));
        let peer: crate::config::DiameterPeerEntry = serde_saphyr::from_str(
            "{name: a, host: example.net, destination_realm: example.net, source_address: 192.0.2.7}",
        )
        .unwrap();
        assert_eq!(peer.source_address, Some("192.0.2.7".parse().unwrap()));
        let absent: crate::config::DiameterServerEntry =
            serde_saphyr::from_str("{name: a, host: example.net}").unwrap();
        assert_eq!(absent.source_address, None);
    }
}
