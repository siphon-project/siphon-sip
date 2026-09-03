//! HEP v3 (Homer Encapsulation Protocol) capture and sender.
//!
//! Captures SIP messages flowing through the proxy and forwards them as HEP v3
//! packets to a Homer/heplify-server collector for call flow visualization.

pub mod encoder;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tracing::{debug, error, info, warn};

use crate::config::{HepConfig, HepTransport};
use crate::transport::Transport;
use encoder::{encode_hep3, extract_call_id, CaptureInfo};

/// Asynchronous HEP sender — captures SIP messages and ships them to a collector.
///
/// Capture calls are non-blocking: they encode HEP packets and enqueue them on a
/// channel. A background tokio task drains the channel and sends packets over
/// UDP, TCP, or TLS to the configured collector.
pub struct HepSender {
    sender: flume::Sender<Bytes>,
    agent_id: u32,
}

impl HepSender {
    /// Create a new `HepSender` and spawn the background sender task.
    ///
    /// Returns an error if the collector endpoint address cannot be resolved.
    pub async fn new(config: &HepConfig) -> io::Result<Self> {
        let endpoint: SocketAddr = config
            .endpoint
            .parse()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;

        let agent_id = parse_agent_id(config.agent_id.as_deref());

        let (sender, receiver) = flume::bounded(4096);

        match config.transport {
            HepTransport::Udp => {
                spawn_udp_sender(endpoint, receiver, config.error_log_interval);
            }
            HepTransport::Tcp => {
                spawn_tcp_sender(endpoint, receiver);
            }
            HepTransport::Tls => {
                let server_name = config.tls_server_name.clone().unwrap_or_else(|| {
                    config
                        .endpoint
                        .split(':')
                        .next()
                        .unwrap_or("localhost")
                        .to_string()
                });
                let ca_cert = config.ca_cert.clone();
                spawn_tls_sender(endpoint, receiver, server_name, ca_cert);
            }
        }

        info!(
            endpoint = %endpoint,
            transport = ?config.transport,
            agent_id = agent_id,
            "HEP capture started"
        );

        Ok(Self { sender, agent_id })
    }

    /// Capture an inbound SIP message (received from the network).
    pub fn capture_inbound(
        &self,
        source: SocketAddr,
        local_addr: SocketAddr,
        transport: Transport,
        raw: &[u8],
    ) {
        self.capture(source, local_addr, transport, raw);
    }

    /// Capture an outbound SIP message (sent to the network).
    pub fn capture_outbound(
        &self,
        local_addr: SocketAddr,
        destination: SocketAddr,
        transport: Transport,
        raw: &[u8],
    ) {
        self.capture(local_addr, destination, transport, raw);
    }

    fn capture(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
        transport: Transport,
        raw: &[u8],
    ) {
        let (timestamp_secs, timestamp_usecs) = now_timestamp();
        let call_id = extract_call_id(raw);

        let info = CaptureInfo {
            source,
            destination,
            transport,
            timestamp_secs,
            timestamp_usecs,
            agent_id: self.agent_id,
            payload: raw,
            call_id,
        };

        let packet = encode_hep3(&info);
        // Fire-and-forget: if the channel is full, drop the packet rather than blocking.
        if self.sender.try_send(packet.freeze()).is_err() {
            warn!("HEP capture channel full — dropping packet");
        }
    }
}

/// Parse the agent_id config string into a u32.
/// If numeric, use directly. Otherwise hash the string.
fn parse_agent_id(agent_id: Option<&str>) -> u32 {
    match agent_id {
        Some(id) => id.parse::<u32>().unwrap_or_else(|_| {
            // Simple FNV-1a hash for string agent IDs
            let mut hash: u32 = 2166136261;
            for byte in id.bytes() {
                hash ^= byte as u32;
                hash = hash.wrapping_mul(16777619);
            }
            hash
        }),
        None => 1,
    }
}

/// Get current wall-clock time as (seconds, microseconds) since UNIX epoch.
fn now_timestamp() -> (u32, u32) {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (duration.as_secs() as u32, duration.subsec_micros())
}

// ---------------------------------------------------------------------------
// Background sender tasks
// ---------------------------------------------------------------------------

fn spawn_udp_sender(
    endpoint: SocketAddr,
    receiver: flume::Receiver<Bytes>,
    error_log_interval: u64,
) {
    tokio::spawn(async move {
        // Bind to any available port
        let bind_addr = if endpoint.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = match UdpSocket::bind(bind_addr).await {
            Ok(socket) => socket,
            Err(error) => {
                error!(endpoint = %endpoint, "failed to bind HEP UDP socket: {error}");
                return;
            }
        };
        if let Err(error) = socket.connect(endpoint).await {
            error!(endpoint = %endpoint, "failed to connect HEP UDP socket: {error}");
            return;
        }

        debug!(endpoint = %endpoint, "HEP UDP sender connected");

        let interval = std::time::Duration::from_secs(error_log_interval);
        let mut last_error_log = Instant::now() - interval - std::time::Duration::from_secs(1);
        let mut suppressed: u64 = 0;

        while let Ok(packet) = receiver.recv_async().await {
            if let Err(error) = socket.send(&packet).await {
                if last_error_log.elapsed() >= interval {
                    if suppressed > 0 {
                        warn!(endpoint = %endpoint, suppressed, "HEP UDP send failed: {error}");
                    } else {
                        warn!(endpoint = %endpoint, "HEP UDP send failed: {error}");
                    }
                    suppressed = 0;
                    last_error_log = Instant::now();
                } else {
                    suppressed += 1;
                }
            }
        }
    });
}

fn spawn_tcp_sender(endpoint: SocketAddr, receiver: flume::Receiver<Bytes>) {
    tokio::spawn(async move {
        tcp_sender_loop(endpoint, &receiver).await;
    });
}

/// TCP sender loop with reconnection on failure.
async fn tcp_sender_loop(endpoint: SocketAddr, receiver: &flume::Receiver<Bytes>) {
    loop {
        let mut stream = match TcpStream::connect(endpoint).await {
            Ok(stream) => {
                debug!(endpoint = %endpoint, "HEP TCP sender connected");
                stream
            }
            Err(error) => {
                warn!(endpoint = %endpoint, "HEP TCP connect failed: {error}, retrying in 5s");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
        };

        // Drain the channel, writing each packet to the TCP stream.
        while let Ok(packet) = receiver.recv_async().await {
            if let Err(error) = stream.write_all(&packet).await {
                warn!(endpoint = %endpoint, "HEP TCP write failed: {error}, reconnecting");
                break;
            }
        }

        // If recv_async returns Err, the channel is closed — exit.
        if receiver.is_disconnected() {
            break;
        }
    }
}

fn spawn_tls_sender(
    endpoint: SocketAddr,
    receiver: flume::Receiver<Bytes>,
    server_name: String,
    ca_cert: Option<String>,
) {
    tokio::spawn(async move {
        tls_sender_loop(endpoint, &receiver, &server_name, ca_cert.as_deref()).await;
    });
}

/// TLS sender loop with reconnection on failure.
async fn tls_sender_loop(
    endpoint: SocketAddr,
    receiver: &flume::Receiver<Bytes>,
    server_name: &str,
    ca_cert: Option<&str>,
) {
    use tokio_rustls::rustls;
    use tokio_rustls::TlsConnector;

    let tls_config = match build_tls_client_config(ca_cert) {
        Ok(config) => config,
        Err(error) => {
            error!("failed to build HEP TLS config: {error}");
            return;
        }
    };
    let connector = TlsConnector::from(Arc::new(tls_config));

    let sni = match rustls::pki_types::ServerName::try_from(server_name.to_string()) {
        Ok(name) => name,
        Err(error) => {
            error!(server_name = %server_name, "invalid HEP TLS server name: {error}");
            return;
        }
    };

    loop {
        let tcp_stream = match TcpStream::connect(endpoint).await {
            Ok(stream) => stream,
            Err(error) => {
                warn!(endpoint = %endpoint, "HEP TLS connect failed: {error}, retrying in 5s");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
        };

        let mut tls_stream = match connector.connect(sni.clone(), tcp_stream).await {
            Ok(stream) => {
                debug!(endpoint = %endpoint, "HEP TLS sender connected");
                stream
            }
            Err(error) => {
                warn!(endpoint = %endpoint, "HEP TLS handshake failed: {error}, retrying in 5s");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
        };

        while let Ok(packet) = receiver.recv_async().await {
            if let Err(error) = tls_stream.write_all(&packet).await {
                warn!(endpoint = %endpoint, "HEP TLS write failed: {error}, reconnecting");
                break;
            }
        }

        if receiver.is_disconnected() {
            break;
        }
    }
}

/// Build a rustls `ClientConfig` for HEP TLS connections.
fn build_tls_client_config(
    ca_cert: Option<&str>,
) -> io::Result<tokio_rustls::rustls::ClientConfig> {
    use tokio_rustls::rustls;

    let mut root_store = rustls::RootCertStore::empty();

    if let Some(ca_path) = ca_cert {
        // Load custom CA certificate
        let ca_data = std::fs::read(ca_path)?;
        let mut cursor = io::Cursor::new(ca_data);
        use rustls_pki_types::pem::PemObject;
        let certs: Vec<_> = rustls_pki_types::CertificateDer::pem_reader_iter(&mut cursor)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        for cert in certs {
            root_store
                .add(cert)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        }
    } else {
        // Use Mozilla root CAs via webpki-roots
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn parse_agent_id_numeric() {
        assert_eq!(parse_agent_id(Some("42")), 42);
        assert_eq!(parse_agent_id(Some("0")), 0);
        assert_eq!(parse_agent_id(Some("100")), 100);
    }

    #[test]
    fn parse_agent_id_string_hash() {
        let id = parse_agent_id(Some("siphon-registrar"));
        assert_ne!(id, 0);
        // Same input produces same hash
        assert_eq!(id, parse_agent_id(Some("siphon-registrar")));
        // Different input produces different hash
        assert_ne!(id, parse_agent_id(Some("siphon-proxy")));
    }

    #[test]
    fn parse_agent_id_default() {
        assert_eq!(parse_agent_id(None), 1);
    }

    #[test]
    fn now_timestamp_reasonable() {
        let (secs, usecs) = now_timestamp();
        // Should be after 2020-01-01
        assert!(secs > 1577836800);
        // Microseconds should be less than 1 second
        assert!(usecs < 1_000_000);
    }

    #[tokio::test]
    async fn hep_sender_udp_roundtrip() {
        // Bind a mock collector socket
        let collector = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let collector_addr = collector.local_addr().unwrap();

        let config = HepConfig {
            endpoint: collector_addr.to_string(),
            version: 3,
            transport: HepTransport::Udp,
            agent_id: Some("99".to_string()),
            ca_cert: None,
            tls_server_name: None,
            error_log_interval: 60,
        };

        let sender = HepSender::new(&config).await.unwrap();

        let sip_payload = concat!(
            "INVITE sip:bob@biloxi.com SIP/2.0\r\n",
            "Call-ID: test-roundtrip@host\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );

        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 5060);
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5060);

        sender.capture_inbound(source, destination, Transport::Udp, sip_payload.as_bytes());

        // Give the background sender task time to pick up and send the packet
        tokio::task::yield_now().await;

        // Receive the HEP packet on the mock collector
        let mut buffer = vec![0u8; 4096];
        let timeout = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            collector.recv(&mut buffer),
        )
        .await
        .expect("timeout waiting for HEP packet");

        let length = timeout.unwrap();
        let packet = &buffer[..length];

        // Verify HEP v3 magic
        assert_eq!(&packet[0..4], b"HEP3");

        // Verify total length matches
        let total_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
        assert_eq!(total_len, length);

        // Verify the SIP payload is embedded in the packet (search for bytes, not string,
        // since the HEP envelope contains binary data)
        let needle = b"INVITE sip:bob@biloxi.com";
        assert!(
            packet.windows(needle.len()).any(|window| window == needle),
            "SIP payload not found in HEP packet"
        );
    }

    #[tokio::test]
    async fn hep_sender_tcp_roundtrip() {
        use tokio::net::TcpListener;

        // Bind a mock TCP collector
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let collector_addr = listener.local_addr().unwrap();

        let config = HepConfig {
            endpoint: collector_addr.to_string(),
            version: 3,
            transport: HepTransport::Tcp,
            agent_id: Some("77".to_string()),
            ca_cert: None,
            tls_server_name: None,
            error_log_interval: 60,
        };

        let sender = HepSender::new(&config).await.unwrap();

        let sip_payload = concat!(
            "REGISTER sip:atlanta.com SIP/2.0\r\n",
            "Call-ID: tcp-test@host\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );

        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5060);
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5060);

        sender.capture_outbound(source, destination, Transport::Tcp, sip_payload.as_bytes());

        // Accept connection and read data
        let timeout = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = vec![0u8; 4096];
            let mut total = 0;
            // Read until we get a complete HEP packet
            loop {
                use tokio::io::AsyncReadExt;
                let n = stream.read(&mut buffer[total..]).await.unwrap();
                if n == 0 {
                    break;
                }
                total += n;
                // Check if we have a complete packet (HEP3 magic + length)
                if total >= 6 {
                    let expected = u16::from_be_bytes([buffer[4], buffer[5]]) as usize;
                    if total >= expected {
                        break;
                    }
                }
            }
            buffer.truncate(total);
            buffer
        })
        .await
        .expect("timeout waiting for HEP TCP packet");

        let packet = timeout;
        assert_eq!(&packet[0..4], b"HEP3");

        let total_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
        assert_eq!(total_len, packet.len());
    }

    #[tokio::test]
    async fn hep_sender_channel_backpressure() {
        // Use a non-existent endpoint — we just test the channel behavior
        let config = HepConfig {
            endpoint: "127.0.0.1:1".to_string(),
            version: 3,
            transport: HepTransport::Udp,
            agent_id: None,
            ca_cert: None,
            tls_server_name: None,
            error_log_interval: 60,
        };

        let sender = HepSender::new(&config).await.unwrap();

        // Sending should not block even if the collector is unreachable
        let source = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5060);
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5060);

        for _ in 0..100 {
            sender.capture_inbound(
                source,
                destination,
                Transport::Udp,
                b"SIP/2.0 200 OK\r\nCall-ID: test\r\n\r\n",
            );
        }
        // If we get here without blocking, the test passes
    }
}
