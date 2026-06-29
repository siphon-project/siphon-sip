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
                        if tx.write_all(&buf[..n]).await.is_err() {
                            break;
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
                        if stream2.sendmsg(&buf[..n], None, &opts).await.is_err() {
                            break;
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
        let stream = SctpStream::connect(addr).await?;
        Ok(Self::new(stream))
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
    match transport {
        #[cfg(feature = "sctp")]
        "sctp" => {
            let addr: SocketAddr = addr.parse().map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("bad address: {}", e))
            })?;
            let stream = SctpAsyncStream::connect(addr).await?;
            Ok(DiameterStream::Sctp(stream))
        }
        #[cfg(not(feature = "sctp"))]
        "sctp" => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Diameter-over-SCTP requested but this binary was built without the `sctp` feature; \
             rebuild with `--features sctp`",
        )),
        _ => {
            let stream = TcpStream::connect(addr).await?;
            Ok(DiameterStream::Tcp(stream))
        }
    }
}
