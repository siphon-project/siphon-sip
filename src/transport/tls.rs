//! TLS transport — wraps TCP connections with rustls.
//!
//! Structurally identical to the TCP listener but performs a TLS handshake
//! on each accepted connection before splitting into read/write halves.
//! Failed handshakes are logged and the connection is dropped without
//! affecting other connections or the accept loop.

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::config::TlsServerConfig;
use crate::transport::{ConnectionId, InboundMessage, OutboundMessage, StreamConnections, Transport, CONNECTION_IDLE_TIMEOUT, configure_tcp_socket, next_connection_id};
use crate::transport::acl::TransportAcl;
use crate::transport::crlf_keepalive::{drain_leading_crlf_keepalives, CrlfPongTracker};
use crate::transport::pool::ConnectionPool;

/// Live-swappable TLS acceptor — read by every accept loop, replaced
/// atomically by the file watcher when the cert or key on disk changes.
pub type SharedTlsAcceptor = Arc<ArcSwap<TlsAcceptor>>;

/// Maximum time allowed for a TLS handshake to complete. tokio imposes no
/// default, so without this a peer that connects and then stalls mid-handshake
/// (slowloris) would pin a task + socket until the OS killed it. Generous
/// enough for slow mobile clients, short enough to bound half-open handshakes.
const TLS_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Build a `TlsAcceptor` from the certificate and key paths in config.
pub fn build_tls_acceptor(tls_config: &TlsServerConfig) -> io::Result<TlsAcceptor> {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};
    use std::fs::File;
    use std::io::BufReader;
    use tokio_rustls::rustls;

    // Load certificate chain
    let cert_file = File::open(&tls_config.certificate).map_err(|error| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("failed to open certificate file '{}': {}", tls_config.certificate, error),
        )
    })?;
    let certificates: Vec<_> =
        CertificateDer::pem_reader_iter(&mut BufReader::new(cert_file))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to parse certificate PEM: {}", error),
                )
            })?;

    if certificates.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "certificate file contains no certificates",
        ));
    }

    // Load private key
    let key_file = File::open(&tls_config.private_key).map_err(|error| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("failed to open private key file '{}': {}", tls_config.private_key, error),
        )
    })?;
    let key = PrivateKeyDer::from_pem_reader(&mut BufReader::new(key_file)).map_err(|error| {
        // `from_pem_reader` returns `Err(NoItemsFound)` when the file held no
        // private key — the case `rustls_pemfile::private_key` signalled with
        // `Ok(None)`. Preserve the original "contains no private key" message
        // for that case, and the "failed to parse" message for everything else.
        match error {
            rustls_pki_types::pem::Error::NoItemsFound => io::Error::new(
                io::ErrorKind::InvalidData,
                "private key file contains no private key",
            ),
            other => io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to parse private key PEM: {}", other),
            ),
        }
    })?;

    // Honor `verify_client` (mutual TLS). Previously this was hardcoded to
    // `with_no_client_auth()`, so the config option was silently ignored —
    // setting `verify_client: true` gave false assurance. When enabled we
    // require a client certificate that chains to `client_ca`; a missing CA is
    // a hard startup error (fail closed) rather than a silent downgrade.
    let builder = rustls::ServerConfig::builder();
    let server_config = if tls_config.verify_client {
        let ca_path = tls_config.client_ca.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "tls.verify_client is true but tls.client_ca (PEM CA bundle for \
                 client certificates) is not set",
            )
        })?;
        let ca_file = File::open(ca_path).map_err(|error| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("failed to open client CA file '{ca_path}': {error}"),
            )
        })?;
        let ca_certs: Vec<_> = CertificateDer::pem_reader_iter(&mut BufReader::new(ca_file))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to parse client CA PEM: {error}"),
                )
            })?;
        if ca_certs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "client CA file contains no certificates",
            ));
        }
        let mut roots = rustls::RootCertStore::empty();
        for ca in ca_certs {
            roots.add(ca).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to add client CA to root store: {error}"),
                )
            })?;
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to build client-certificate verifier: {error}"),
                )
            })?;
        info!(client_ca = %ca_path, "mutual TLS enabled — client certificate required");
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates, key)
    } else {
        builder
            .with_no_client_auth()
            .with_single_cert(certificates, key)
    }
    .map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to build TLS server config: {}", error),
        )
    })?;

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

/// Build a `SharedTlsAcceptor` and spawn a watcher that rebuilds it whenever
/// the certificate or private-key file on disk changes (atomic rename, in-place
/// rewrite, or directory swap — handled like the script hot-reload in
/// [`crate::script::engine::spawn_file_watcher`]).
///
/// Existing connections continue using whatever acceptor accepted them — only
/// new handshakes pick up the new cert. That matches the standard cert-renewal
/// model: ACME/cert-manager writes the new pair, siphon picks it up, sessions
/// transition naturally over the renewal window.
pub fn build_hot_reload_acceptor(
    tls_config: &TlsServerConfig,
) -> io::Result<SharedTlsAcceptor> {
    let initial = build_tls_acceptor(tls_config)?;
    let shared: SharedTlsAcceptor = Arc::new(ArcSwap::from(Arc::new(initial)));

    let cert_path = PathBuf::from(&tls_config.certificate);
    let key_path = PathBuf::from(&tls_config.private_key);
    let watch_config = tls_config.clone();
    // Weak ref so the watcher exits when the last strong reference (the
    // listener) is dropped. Without this, tests that build an acceptor
    // would leak the spawned task and block runtime shutdown.
    let weak = Arc::downgrade(&shared);

    tokio::task::spawn_blocking(move || {
        use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
        use std::sync::mpsc;

        let (sender, receiver) = mpsc::channel::<notify::Result<Event>>();
        let mut watcher = match RecommendedWatcher::new(sender, Config::default()) {
            Ok(watcher) => watcher,
            Err(error) => {
                error!(%error, "TLS watcher: failed to create file watcher");
                return;
            }
        };

        // Watch the parent directories so atomic rename (cert-manager, certbot)
        // is observed — they typically swap the file rather than rewrite it.
        for path in [&cert_path, &key_path] {
            let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
            if let Err(error) = watcher.watch(dir, RecursiveMode::NonRecursive) {
                warn!(%error, path = %dir.display(),
                    "TLS watcher: failed to watch directory; cert hot-reload disabled");
                return;
            }
        }
        info!(
            cert = %cert_path.display(),
            key = %key_path.display(),
            "TLS cert hot-reload watcher started"
        );

        let cert_name = cert_path.file_name().map(|n| n.to_owned());
        let key_name = key_path.file_name().map(|n| n.to_owned());

        loop {
            // Poll with a 1s timeout so we can check Weak::upgrade between
            // events — when the listener drops the SharedTlsAcceptor we exit.
            let event = match receiver.recv_timeout(std::time::Duration::from_secs(1)) {
                Ok(event) => event,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if weak.upgrade().is_none() { break; }
                    continue;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            };
            let target = match weak.upgrade() {
                Some(target) => target,
                None => break,
            };
            match event {
                Ok(Event { kind: EventKind::Modify(_) | EventKind::Create(_), paths, .. }) => {
                    let touched = paths.iter().any(|p| {
                        let name = p.file_name().map(|n| n.to_owned());
                        name == cert_name || name == key_name
                    });
                    if !touched {
                        continue;
                    }
                    // Debounce — typical cert renewal writes the key first,
                    // then the cert; wait for the pair to settle.
                    std::thread::sleep(std::time::Duration::from_millis(150));
                    match build_tls_acceptor(&watch_config) {
                        Ok(new_acceptor) => {
                            target.store(Arc::new(new_acceptor));
                            info!("TLS cert hot-reloaded — new handshakes use the updated cert");
                        }
                        Err(error) => {
                            warn!(%error,
                                "TLS hot-reload failed — keeping previous cert. Renewal half-written?");
                        }
                    }
                }
                Ok(_) => {}
                Err(error) => warn!(%error, "TLS watcher: file event error"),
            }
        }
        debug!("TLS watcher exiting (acceptor dropped)");
    });

    Ok(shared)
}

/// Spawn a TLS listener. Mirrors the TCP listener but wraps each accepted
/// connection in a TLS handshake before spawning read/write tasks.
pub async fn listen(
    local_addr: SocketAddr,
    tls_config: &TlsServerConfig,
    inbound_tx: flume::Sender<InboundMessage>,
    outbound_rx: flume::Receiver<OutboundMessage>,
    connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>>,
    acl: Arc<TransportAcl>,
    stream_connections: StreamConnections,
    tos: Option<u32>,
    pool: Option<Arc<ConnectionPool>>,
    crlf_pong_tracker: Option<Arc<CrlfPongTracker>>,
    close_tx: Option<flume::Sender<u64>>,
) {
    let acceptor = build_hot_reload_acceptor(tls_config).unwrap_or_else(|error| {
        eprintln!("Failed to build TLS acceptor: {error}");
        std::process::exit(1);
    });

    // Spawn a task that distributes outbound messages to per-connection senders.
    // When no existing connection matches, fall back to the connection pool to
    // create a new outbound TLS connection (needed for registrant, probes, etc.).
    let connection_map_clone = connection_map.clone();
    tokio::spawn(async move {
        while let Ok(outbound) = outbound_rx.recv_async().await {
            if let Some(sender) = connection_map_clone.get(&outbound.connection_id) {
                // Non-blocking: NEVER park in `send().await` here (see tcp.rs for
                // the full rationale). This single outbound distributor holds the
                // `connection_map` shard read guard across this `if let`; an
                // awaiting send to a non-reading peer's full bounded channel would
                // park here, stalling outbound for every connection and blocking
                // accept's `insert` on the same shard — the wedge. `try_send`
                // sheds for a backed-up (stuck) peer instead.
                match sender.try_send(outbound.data) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        warn!("TLS outbound dropped: connection {:?} send buffer full (slow/stuck peer)", outbound.connection_id);
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        warn!("TLS outbound dropped: connection {:?} closed", outbound.connection_id);
                    }
                }
            } else if let Some(ref pool) = pool {
                // No existing connection — create outbound TLS via pool
                match pool.send_tls(outbound.destination, outbound.server_name.as_deref(), outbound.data).await {
                    Ok(connection_id) => {
                        debug!(
                            destination = %outbound.destination,
                            connection_id = ?connection_id,
                            "TLS outbound: sent via pool"
                        );
                    }
                    Err(error) => {
                        warn!(
                            destination = %outbound.destination,
                            "TLS outbound pool connect failed: {error}"
                        );
                    }
                }
            } else {
                debug!("TLS outbound: connection {:?} not found (may have closed)", outbound.connection_id);
            }
        }
    });

    tokio::spawn(async move {
        // Use TcpSocket so we can set TOS/DSCP before binding.
        let socket = if local_addr.is_ipv6() {
            match tokio::net::TcpSocket::new_v6() {
                Ok(socket) => socket,
                Err(error) => { error!("failed to create TLS socket: {error}"); return; }
            }
        } else {
            match tokio::net::TcpSocket::new_v4() {
                Ok(socket) => socket,
                Err(error) => { error!("failed to create TLS socket: {error}"); return; }
            }
        };
        if let Err(error) = socket.set_reuseaddr(true) {
            error!("failed to set SO_REUSEADDR on TLS socket: {error}"); return;
        }
        #[cfg(unix)]
        if let Err(error) = socket.set_reuseport(true) {
            error!("failed to set SO_REUSEPORT on TLS socket: {error}"); return;
        }
        // DSCP / DiffServ marking (RFC 4594) — family-aware, best-effort.
        if let Some(tos) = tos {
            super::apply_tos(&socket2::SockRef::from(&socket), tos);
        }
        if let Err(error) = socket.bind(local_addr) {
            error!("failed to bind TLS listener on {local_addr}: {error}"); return;
        }
        let listener = match socket.listen(1024) {
            Ok(listener) => listener,
            Err(error) => { error!("failed to listen on TLS socket: {error}"); return; }
        };
        info!("TLS listener on {}", local_addr);

        loop {
            match listener.accept().await {
                Ok((tcp_stream, remote_addr)) => {
                    if !acl.is_allowed(remote_addr.ip()) {
                        debug!("TLS rejected {} by ACL", remote_addr);
                        continue;
                    }
                    // Read the *current* acceptor — it may have been swapped
                    // by the hot-reload watcher since the previous accept().
                    let acceptor = (**acceptor.load()).clone();
                    let inbound_tx = inbound_tx.clone();
                    let connection_map = connection_map.clone();
                    let stream_connections = stream_connections.clone();
                    let crlf_pong_tracker = crlf_pong_tracker.clone();
                    let close_tx = close_tx.clone();

                    configure_tcp_socket(&tcp_stream, tos);

                    tokio::spawn(async move {
                        // Perform TLS handshake under a bounded timeout so a peer
                        // that connects and stalls mid-handshake (slowloris) cannot
                        // pin a task + socket indefinitely.
                        let tls_stream = match tokio::time::timeout(
                            TLS_HANDSHAKE_TIMEOUT,
                            acceptor.accept(tcp_stream),
                        )
                        .await
                        {
                            Ok(Ok(stream)) => stream,
                            Ok(Err(error)) => {
                                warn!("TLS handshake failed from {}: {}", remote_addr, error);
                                crate::security::record_handshake_failure(remote_addr.ip(), "TLS");
                                return;
                            }
                            Err(_) => {
                                warn!("TLS handshake timed out from {}", remote_addr);
                                crate::security::record_handshake_failure(remote_addr.ip(), "TLS");
                                return;
                            }
                        };

                        let connection_id = next_connection_id();
                        debug!("TLS accepted {} as {:?}", remote_addr, connection_id);

                        let local_addr = tls_stream.get_ref().0.local_addr().unwrap_or(local_addr);
                        let (mut reader, mut writer) = tokio::io::split(tls_stream);

                        // Per-connection outbound channel.  Cloned for the read
                        // task so it can write RFC 5626 §4.4.1 pong (`\r\n`)
                        // responses back over the same connection.
                        let (outbound_tx, mut outbound_rx) = mpsc::channel::<Bytes>(64);
                        connection_map.insert(connection_id, outbound_tx.clone());
                        stream_connections.register(remote_addr, Transport::Tls, connection_id);
                        let keepalive_writer = outbound_tx;

                        // Read task with idle timeout and SIP stream framing (RFC 3261 §18.3)
                        let inbound_tx_clone = inbound_tx.clone();
                        let read_task = tokio::spawn(async move {
                            let mut accumulator = BytesMut::with_capacity(65536);
                            let mut read_buf = [0u8; 8192];
                            loop {
                                match tokio::time::timeout(CONNECTION_IDLE_TIMEOUT, reader.read(&mut read_buf)).await {
                                    Ok(Ok(0)) => {
                                        info!("TLS connection {:?} closed by peer", connection_id);
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
                                            let message_len = match crate::transport::tcp::extract_sip_message_length(&accumulator) {
                                                Some(len) if len <= accumulator.len() => len,
                                                Some(_) => break, // header block complete, body still arriving — wait
                                                None => match crate::transport::tcp::classify_incomplete_stream(&accumulator) {
                                                    crate::transport::tcp::StreamVerdict::MaybeSip => break, // SIP still arriving — need more data
                                                    crate::transport::tcp::StreamVerdict::Garbage => {
                                                        warn!("non-SIP bytes from {} on TLS {:?}; dropping connection", remote_addr, connection_id);
                                                        crate::security::record_malformed_message(remote_addr.ip(), "TLS");
                                                        return; // close the connection
                                                    }
                                                },
                                            };
                                            let data = accumulator.split_to(message_len).freeze();
                                            let message = InboundMessage {
                                                connection_id,
                                                transport: Transport::Tls,
                                                local_addr,
                                                remote_addr,
                                                data,
                                            };
                                            if let Err(error) = inbound_tx_clone.send_async(message).await {
                                                error!("TLS inbound enqueue failed: {}", error);
                                                return;
                                            }
                                        }
                                    }
                                    Ok(Err(error)) => {
                                        warn!("TLS read error on {:?} from {}: {}", connection_id, remote_addr, error);
                                        break;
                                    }
                                    Err(_) => {
                                        info!("TLS connection {:?} idle timeout ({}s)", connection_id, CONNECTION_IDLE_TIMEOUT.as_secs());
                                        break;
                                    }
                                }
                            }
                        });

                        // Write task
                        let write_task = tokio::spawn(async move {
                            while let Some(data) = outbound_rx.recv().await {
                                if let Err(error) = writer.write_all(&data).await {
                                    warn!("TLS write error on {:?}: {}", connection_id, error);
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
                        stream_connections.unregister(&remote_addr);
                        // RFC 5626 §4.2.2 flow failure: notify the registrar so
                        // it can deregister any binding that arrived on this
                        // connection.  Best-effort.
                        if let Some(close_tx) = &close_tx {
                            let _ = close_tx.send(connection_id.0);
                        }
                        debug!("TLS connection {:?} cleaned up", connection_id);
                    });
                }
                Err(error) => {
                    error!("TLS accept error: {}", error);
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn test_acl() -> Arc<TransportAcl> {
        Arc::new(TransportAcl::new(vec![], vec![]))
    }

    fn ensure_crypto_provider() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    }

    fn generate_test_cert() -> (String, String) {
        let key_pair = rcgen::KeyPair::generate().expect("keygen");
        let certificate_params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("failed to create cert params");
        let certificate = certificate_params.self_signed(&key_pair).expect("self-sign");
        let cert_pem = certificate.pem();
        let key_pem = key_pair.serialize_pem();
        (cert_pem, key_pem)
    }

    fn write_test_cert(directory: &tempfile::TempDir) -> TlsServerConfig {
        let (cert_pem, key_pem) = generate_test_cert();
        let cert_path = directory.path().join("cert.pem");
        let key_path = directory.path().join("key.pem");
        std::fs::write(&cert_path, &cert_pem).unwrap();
        std::fs::write(&key_path, &key_pem).unwrap();
        TlsServerConfig {
            certificate: cert_path.to_str().unwrap().to_string(),
            private_key: key_path.to_str().unwrap().to_string(),
            method: "TLSv1_3".to_string(),
            verify_client: false,
            client_ca: None,
            client_certificate: None,
            client_private_key: None,
        }
    }

    #[test]
    fn tls_acceptor_builds_from_valid_config() {
        ensure_crypto_provider();
        let directory = tempfile::tempdir().unwrap();
        let tls_config = write_test_cert(&directory);
        let result = build_tls_acceptor(&tls_config);
        assert!(result.is_ok(), "build_tls_acceptor failed: {:?}", result.err());
    }

    #[test]
    fn tls_acceptor_fails_on_missing_cert() {
        ensure_crypto_provider();
        let tls_config = TlsServerConfig {
            certificate: "/nonexistent/cert.pem".to_string(),
            private_key: "/nonexistent/key.pem".to_string(),
            method: "TLSv1_3".to_string(),
            verify_client: false,
            client_ca: None,
            client_certificate: None,
            client_private_key: None,
        };
        let result = build_tls_acceptor(&tls_config);
        assert!(result.is_err());
        let error = result.as_ref().err().unwrap().to_string();
        assert!(error.contains("cert"), "error should mention cert: {}", error);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shared_acceptor_is_atomically_swappable() {
        ensure_crypto_provider();
        let directory = tempfile::tempdir().unwrap();
        let tls_config = write_test_cert(&directory);

        // Build the SharedTlsAcceptor (this also spawns a watcher task — we don't
        // exercise the file-change path here because it depends on inotify timing
        // that's flaky in CI; just verify the swap mechanism itself works).
        let shared = build_hot_reload_acceptor(&tls_config).unwrap();
        let initial = Arc::clone(&shared.load());

        // Manually rebuild + store a new acceptor.
        let replacement = build_tls_acceptor(&tls_config).unwrap();
        shared.store(Arc::new(replacement));

        let after = Arc::clone(&shared.load());
        assert!(!Arc::ptr_eq(&initial, &after),
            "SharedTlsAcceptor did not swap the inner Arc after store()");
    }

    #[test]
    fn tls_acceptor_fails_on_bad_cert_content() {
        ensure_crypto_provider();
        let directory = tempfile::tempdir().unwrap();
        let cert_path = directory.path().join("cert.pem");
        let key_path = directory.path().join("key.pem");
        std::fs::write(&cert_path, b"not a certificate").unwrap();
        std::fs::write(&key_path, b"not a key").unwrap();

        let tls_config = TlsServerConfig {
            certificate: cert_path.to_str().unwrap().to_string(),
            private_key: key_path.to_str().unwrap().to_string(),
            method: "TLSv1_3".to_string(),
            verify_client: false,
            client_ca: None,
            client_certificate: None,
            client_private_key: None,
        };
        let result = build_tls_acceptor(&tls_config);
        assert!(result.is_err());
    }

    #[test]
    fn verify_client_without_ca_fails_closed() {
        // mTLS: verify_client must be honored. Enabling it without a client_ca
        // is a hard error (fail closed), never a silent no-client-auth downgrade.
        ensure_crypto_provider();
        let directory = tempfile::tempdir().unwrap();
        let mut tls_config = write_test_cert(&directory);
        tls_config.verify_client = true;
        tls_config.client_ca = None;
        let result = build_tls_acceptor(&tls_config);
        assert!(
            result.is_err(),
            "verify_client=true without client_ca must fail closed"
        );
    }

    #[tokio::test]
    async fn tls_connection_lifecycle() {
        ensure_crypto_provider();
        use tokio_rustls::rustls;
        use tokio_rustls::TlsConnector;

        let directory = tempfile::tempdir().unwrap();
        let tls_config = write_test_cert(&directory);

        let (inbound_tx, inbound_rx) = flume::unbounded();
        let (_outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
        let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> =
            Arc::new(DashMap::new());

        // Start TLS listener on a random port
        listen(
            "127.0.0.1:0".parse().unwrap(),
            &tls_config,
            inbound_tx,
            outbound_rx,
            Arc::clone(&connection_map),
            test_acl(),
            StreamConnections::new(),
            None,
            None,
            None,
            None,
        )
        .await;

        // We need the actual bound port. Since listen() binds inside a spawned task,
        // give it a moment to bind.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Read the cert back to build a client config that trusts it
        let cert_pem = std::fs::read(&tls_config.certificate).unwrap();
        let mut cursor = std::io::Cursor::new(cert_pem);
        use rustls_pki_types::pem::PemObject;
        let certs: Vec<_> =
            rustls_pki_types::CertificateDer::pem_reader_iter(&mut cursor)
                .collect::<Result<Vec<_>, _>>()
                .unwrap();

        let mut root_store = rustls::RootCertStore::empty();
        for cert in &certs {
            root_store.add(cert.clone()).unwrap();
        }

        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));

        // Unfortunately we can't easily get the bound port from inside the spawned task.
        // We'll use a different approach: bind to a known port.
        // Let's redo with a specific approach — start a raw TcpListener to find a free port first.
        drop(inbound_rx); // clean up the first attempt

        // --- Retry with a port we control ---
        let tcp_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let bound_addr = tcp_listener.local_addr().unwrap();
        drop(tcp_listener); // release so TLS listener can bind

        let (inbound_tx, inbound_rx) = flume::unbounded();
        let (_outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
        let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> =
            Arc::new(DashMap::new());

        listen(
            bound_addr,
            &tls_config,
            inbound_tx,
            outbound_rx,
            Arc::clone(&connection_map),
            test_acl(),
            StreamConnections::new(),
            None,
            None,
            None,
            None,
        )
        .await;

        // Give the listener time to bind
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Connect as a TLS client
        let tcp_stream = tokio::net::TcpStream::connect(bound_addr).await.unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut tls_stream = connector.connect(server_name, tcp_stream).await.unwrap();

        // Send a SIP REGISTER
        let sip_message = concat!(
            "REGISTER sip:example.com SIP/2.0\r\n",
            "Via: SIP/2.0/TLS 10.0.0.1:5061;branch=z9hG4bK776\r\n",
            "From: <sip:alice@example.com>;tag=abc123\r\n",
            "To: <sip:alice@example.com>\r\n",
            "Call-ID: test-tls-lifecycle@example.com\r\n",
            "CSeq: 1 REGISTER\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        tls_stream.write_all(sip_message.as_bytes()).await.unwrap();

        // Receive the inbound message
        let message = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            inbound_rx.recv_async(),
        )
        .await
        .expect("timed out waiting for inbound message")
        .expect("inbound channel closed");

        assert_eq!(message.transport, Transport::Tls);
        assert_eq!(message.local_addr, bound_addr);
        assert!(!message.data.is_empty());
        let data_str = String::from_utf8_lossy(&message.data);
        assert!(data_str.contains("REGISTER"), "expected REGISTER in data: {}", data_str);

        // Verify connection is tracked
        assert!(connection_map.contains_key(&message.connection_id));
    }

    #[tokio::test]
    async fn tls_connection_cleanup_on_client_drop() {
        ensure_crypto_provider();
        use tokio_rustls::rustls;
        use tokio_rustls::TlsConnector;

        let directory = tempfile::tempdir().unwrap();
        let tls_config = write_test_cert(&directory);

        // Find a free port
        let tcp_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let bound_addr = tcp_listener.local_addr().unwrap();
        drop(tcp_listener);

        let (inbound_tx, inbound_rx) = flume::unbounded();
        let (_outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
        let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> =
            Arc::new(DashMap::new());
        let stream_connections = StreamConnections::new();

        listen(
            bound_addr,
            &tls_config,
            inbound_tx,
            outbound_rx,
            Arc::clone(&connection_map),
            test_acl(),
            stream_connections.clone(),
            None,
            None,
            None,
            None,
        )
        .await;

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Build TLS client
        let cert_pem = std::fs::read(&tls_config.certificate).unwrap();
        let mut cursor = std::io::Cursor::new(cert_pem);
        use rustls_pki_types::pem::PemObject;
        let certs: Vec<_> =
            rustls_pki_types::CertificateDer::pem_reader_iter(&mut cursor)
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        let mut root_store = rustls::RootCertStore::empty();
        for cert in &certs {
            root_store.add(cert.clone()).unwrap();
        }
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));

        let tcp_stream = tokio::net::TcpStream::connect(bound_addr).await.unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut tls_stream = connector.connect(server_name, tcp_stream).await.unwrap();

        // Send data so the connection gets an ID
        tls_stream.write_all(b"REGISTER sip:test SIP/2.0\r\n\r\n").await.unwrap();
        let message = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            inbound_rx.recv_async(),
        )
        .await
        .unwrap()
        .unwrap();

        let connection_id = message.connection_id;
        let remote_addr = message.remote_addr;
        assert!(connection_map.contains_key(&connection_id));
        // Verify the registry is populated for connection reuse (tagged TLS).
        assert_eq!(
            stream_connections.reuse(remote_addr, Transport::Tls),
            Some(connection_id),
            "stream registry should track the TLS connection by remote address"
        );
        assert_eq!(
            stream_connections.get(&remote_addr),
            Some((Transport::Tls, connection_id)),
        );

        // Drop the client
        drop(tls_stream);

        // Wait for cleanup
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        assert!(
            !connection_map.contains_key(&connection_id),
            "connection should have been cleaned up after client drop"
        );
        assert_eq!(
            stream_connections.reuse(remote_addr, Transport::Tls),
            None,
            "stream registry should be cleaned up after client drop"
        );
    }
}
