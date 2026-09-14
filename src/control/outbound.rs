//! Outbound per-call-connect mode: siphon dials the controller's WebSocket at
//! handover and the accepting socket owns that call (the FreeSWITCH-outbound
//! model — the documented default for multi-pod controllers).
//!
//! Both rails dial **out from siphon** (this control WS + the media WS the
//! engine dials for `ws_uri`), so the "audio socket lands on a pod that doesn't
//! own the call" affinity bug is structurally impossible.
//!
//! Reuses the transport-agnostic frame logic in [`super::listener`]; only the
//! socket acquisition + write task differ (tungstenite client vs axum server).

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;
use tracing::{debug, info, warn};

use super::listener::process_text;
use super::protocol::{EventFrame, SUBPROTOCOL};
use super::registry::{ControlBus, OutboundQueue};
use super::CONTROL_WRITE_TIMEOUT;

/// How long to wait for the controller to accept the per-call dial before giving
/// up (the handoff deadline is the ultimate backstop, but a bounded connect
/// keeps a dead controller from holding the dial task).
const DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The transport under a control WebSocket: plain TCP for `ws://`, TLS for
/// `wss://`.
///
/// Hand-rolled rather than tokio-tungstenite's own `MaybeTlsStream`, which only
/// grows a TLS variant when one of that crate's TLS features is enabled — and
/// every one of those resolves a **second** copy of `webpki-roots` alongside the
/// one this process already uses, so the control plane would validate against a
/// different, older trust bundle than the CDR and HEP clients do. `client_async`
/// takes any stream, so the TLS half is built with the `tokio-rustls` already in
/// the tree and the whole process keeps one set of roots.
#[derive(Debug)]
pub enum ControlStream {
    /// `ws://` — no TLS.
    Plain(TcpStream),
    /// `wss://` — boxed because the rustls stream is far larger than a socket,
    /// and every frame read would otherwise carry that size.
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for ControlStream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            ControlStream::Plain(stream) => Pin::new(stream).poll_read(context, buffer),
            ControlStream::Tls(stream) => Pin::new(stream.as_mut()).poll_read(context, buffer),
        }
    }
}

impl AsyncWrite for ControlStream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            ControlStream::Plain(stream) => Pin::new(stream).poll_write(context, buffer),
            ControlStream::Tls(stream) => Pin::new(stream.as_mut()).poll_write(context, buffer),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            ControlStream::Plain(stream) => Pin::new(stream).poll_flush(context),
            ControlStream::Tls(stream) => Pin::new(stream.as_mut()).poll_flush(context),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            ControlStream::Plain(stream) => Pin::new(stream).poll_shutdown(context),
            ControlStream::Tls(stream) => Pin::new(stream.as_mut()).poll_shutdown(context),
        }
    }
}

/// The scheme, host and port to dial, parsed from a `connect_url`.
///
/// Parsed here rather than left to tungstenite because the host is what the
/// certificate is checked against, and the port has to be defaulted per scheme
/// (443 for `wss://`, 80 for `ws://`) exactly as a browser would.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DialTarget {
    pub(crate) tls: bool,
    pub(crate) host: String,
    pub(crate) port: u16,
}

impl DialTarget {
    /// `host:port`, for the TCP connect.
    fn address(&self) -> String {
        // An IPv6 literal has to stay bracketed or the port parse eats a group.
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// Split a `connect_url` into what to dial and whether to wrap it in TLS.
pub(crate) fn parse_connect_url(connect_url: &str) -> Result<DialTarget, String> {
    let (tls, rest) = match connect_url.split_once("://") {
        Some(("ws", rest)) => (false, rest),
        Some(("wss", rest)) => (true, rest),
        Some((scheme, _)) => {
            return Err(format!(
                "connect_url scheme {scheme:?} is not supported — it is ws:// or wss://"
            ))
        }
        None => return Err("connect_url has no scheme — it is ws:// or wss://".to_string()),
    };

    // Authority only: the path is tungstenite's problem, not the socket's.
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .rsplit('@')
        .next()
        .unwrap_or_default();
    if authority.is_empty() {
        return Err("connect_url has no host".to_string());
    }

    let default_port = if tls { 443 } else { 80 };
    let (host, port) = match authority.strip_prefix('[') {
        // IPv6 literal: [::1] or [::1]:9092
        Some(bracketed) => match bracketed.split_once(']') {
            Some((host, "")) => (host.to_string(), default_port),
            Some((host, rest)) => match rest.strip_prefix(':') {
                Some(port) => (host.to_string(), parse_port(port)?),
                None => return Err(format!("connect_url authority {authority:?} is malformed")),
            },
            None => return Err(format!("connect_url authority {authority:?} is malformed")),
        },
        None => match authority.rsplit_once(':') {
            Some((host, port)) => (host.to_string(), parse_port(port)?),
            None => (authority.to_string(), default_port),
        },
    };
    if host.is_empty() {
        return Err("connect_url has no host".to_string());
    }
    Ok(DialTarget { tls, host, port })
}

fn parse_port(port: &str) -> Result<u16, String> {
    port.parse::<u16>()
        .map_err(|_| format!("connect_url port {port:?} is not a port number"))
        .and_then(|port| {
            if port == 0 {
                Err("connect_url port 0 is not dialable".to_string())
            } else {
                Ok(port)
            }
        })
}

/// Everything needed to take ownership of a handed-over call once the dial
/// succeeds.
#[derive(Debug, Clone)]
pub struct PendingOwn {
    /// The leg-scoped channel id.
    pub channel_id: String,
    /// The internal `CallActor` id.
    pub call_actor_id: String,
    /// The per-leg SIP Call-ID.
    pub sip_call_id: String,
    /// Control-loss policy for the call.
    pub on_lost: String,
    /// Per-call variables set at handover.
    pub vars: std::collections::HashMap<String, String>,
    /// The `StasisStart` payload (full SIP context) to push on connect.
    pub stasis_payload: serde_json::Value,
}

/// Dial the controller and, on success, take ownership of the pending call.
/// Fire-and-forget: spawns a task and returns immediately (rule #4 — the
/// handover reply is not the dial result). A dial failure logs and lets the
/// handoff deadline apply the default action.
pub fn dial_and_own(
    bus: Arc<ControlBus>,
    app: String,
    token: String,
    connect_url: String,
    ca_file: Option<String>,
    pending: PendingOwn,
) {
    tokio::spawn(async move {
        let socket = match connect(&connect_url, &token, ca_file.as_deref()).await {
            Ok(socket) => socket,
            Err(error) => {
                warn!(%app, %connect_url, %error, "control plane: per-call-connect dial failed");
                return;
            }
        };
        info!(%app, %connect_url, channel = %pending.channel_id, "control plane: per-call-connect established");
        drive_outbound_socket(socket, app, bus, pending).await;
    });
}

/// Dial the controller with the app token + subprotocol, bounded by a connect
/// timeout.
async fn connect(
    connect_url: &str,
    token: &str,
    ca_file: Option<&str>,
) -> Result<WebSocketStream<ControlStream>, String> {
    let target = parse_connect_url(connect_url)?;
    let mut request = connect_url
        .into_client_request()
        .map_err(|error| format!("invalid connect_url: {error}"))?;
    let headers = request.headers_mut();
    headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|error| format!("invalid token header: {error}"))?,
    );
    headers.insert(
        "Sec-WebSocket-Protocol",
        HeaderValue::from_static(SUBPROTOCOL),
    );

    // One budget over the transport connect, the TLS handshake and the
    // WebSocket handshake together: a controller that accepts the socket and
    // then never finishes either handshake is as dead as one that never
    // accepted, and only a deadline that covers all three says so.
    let dial = async {
        let stream = if target.tls {
            let config = Arc::new(
                crate::transport::client_tls::client_config(ca_file)
                    .map_err(|error| format!("control TLS config: {error}"))?,
            );
            let tls =
                crate::transport::client_tls::connect(&target.address(), &target.host, config)
                    .await
                    .map_err(|error| format!("TLS connect to {}: {error}", target.address()))?;
            ControlStream::Tls(Box::new(tls))
        } else {
            let tcp = TcpStream::connect(target.address())
                .await
                .map_err(|error| format!("connect to {}: {error}", target.address()))?;
            ControlStream::Plain(tcp)
        };
        tokio_tungstenite::client_async(request, stream)
            .await
            .map_err(|error| format!("dial error: {error}"))
    };

    let (socket, _response) = tokio::time::timeout(DIAL_TIMEOUT, dial)
        .await
        .map_err(|_| "dial timed out".to_string())??;
    Ok(socket)
}

/// Register ownership, push `StasisStart`, then run the read/write driver for one
/// outbound control connection.
async fn drive_outbound_socket(
    socket: WebSocketStream<ControlStream>,
    app: String,
    bus: Arc<ControlBus>,
    pending: PendingOwn,
) {
    let conn = bus.register_connection(&app);
    crate::metrics::try_metrics()
        .inspect(|m| m.control_connections.with_label_values(&[&app]).inc());

    // The accepting socket owns the call. Register + push StasisStart before
    // reading commands so the very first thing the controller sees is its call.
    bus.register_channel(
        &pending.channel_id,
        &conn,
        &pending.call_actor_id,
        &pending.sip_call_id,
        &pending.on_lost,
        pending.vars,
    );
    conn.events.try_push_event(EventFrame::new(
        "StasisStart",
        &pending.channel_id,
        &app,
        &pending.call_actor_id,
        &pending.sip_call_id,
        pending.stasis_payload,
    ));

    let (ws_sink, mut ws_source) = socket.split();
    let writer_events = Arc::clone(&conn.events);
    let writer = tokio::spawn(outbound_write_task(ws_sink, writer_events));

    // In per-call-connect mode siphon presented the token in the dial headers, so
    // ownership is already established — no `hello` is expected from the
    // controller. Commands flow straight in.
    let mut said_hello = true;
    while let Some(message) = ws_source.next().await {
        let message = match message {
            Ok(message) => message,
            Err(error) => {
                debug!(conn_id = conn.id, %error, "control plane: outbound read error");
                break;
            }
        };
        match message {
            Message::Text(text) => {
                if !process_text(text.as_str(), &mut said_hello, &conn, &bus).await {
                    break;
                }
            }
            Message::Close(_) => break,
            Message::Ping(_) | Message::Pong(_) => {}
            other => {
                warn!(conn_id = conn.id, kind = ?std::mem::discriminant(&other), "control plane: ignoring non-text frame (outbound)");
            }
        }
    }

    conn.events.close();
    bus.unregister_connection(&conn);
    crate::metrics::try_metrics()
        .inspect(|m| m.control_connections.with_label_values(&[&app]).dec());
    let _ = writer.await;
    debug!(conn_id = conn.id, %app, "control plane: outbound connection closed");
}

/// The outbound connection's single write task: drains the ordered outbound
/// queue onto the tungstenite socket.
async fn outbound_write_task(
    mut ws_sink: SplitSink<WebSocketStream<ControlStream>, Message>,
    events: Arc<OutboundQueue>,
) {
    loop {
        let frames = events.recv_many().await;
        if frames.is_empty() {
            break;
        }
        for frame in frames {
            if let Some(text) = super::listener::frame_to_text(&frame) {
                // Bounded — see `CONTROL_WRITE_TIMEOUT`.
                match tokio::time::timeout(
                    CONTROL_WRITE_TIMEOUT,
                    ws_sink.send(Message::Text(text.into())),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => {
                        let _ = tokio::time::timeout(
                            CONTROL_WRITE_TIMEOUT,
                            ws_sink.send(Message::Close(None)),
                        )
                        .await;
                        return;
                    }
                    Err(_) => {
                        warn!(
                            timeout = ?CONTROL_WRITE_TIMEOUT,
                            "control plane: outbound write stalled — controller is \
                             not draining its socket; closing the connection"
                        );
                        return;
                    }
                }
            }
        }
        if events.disconnect_requested() {
            break;
        }
    }
    let _ = tokio::time::timeout(CONTROL_WRITE_TIMEOUT, ws_sink.send(Message::Close(None))).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ControlAppConfig;
    use crate::control::registry::SlowConsumerPolicy;
    use tokio_tungstenite::tungstenite::Message as ServerMessage;

    fn app_cfg(name: &str, token: &str, connect_url: &str) -> ControlAppConfig {
        ControlAppConfig {
            name: name.to_string(),
            token: token.to_string(),
            per_call_connect: true,
            connect_url: Some(connect_url.to_string()),
            on_lost: Some("hangup".to_string()),
            ca_file: None,
            events: Vec::new(),
        }
    }

    fn target(connect_url: &str) -> DialTarget {
        parse_connect_url(connect_url).expect(connect_url)
    }

    #[test]
    fn a_ws_url_dials_plain_tcp_on_port_80_by_default() {
        assert_eq!(
            target("ws://controller.example"),
            DialTarget {
                tls: false,
                host: "controller.example".to_string(),
                port: 80
            }
        );
        assert_eq!(target("ws://controller.example:9092/siphon").port, 9092);
    }

    #[test]
    fn a_wss_url_dials_tls_on_port_443_by_default() {
        // 443, not 80: a controller named without a port is reached the way a
        // browser would reach it, or every wss:// deployment needs a redundant
        // :443 to work at all.
        assert_eq!(
            target("wss://controller.example"),
            DialTarget {
                tls: true,
                host: "controller.example".to_string(),
                port: 443
            }
        );
        assert_eq!(target("wss://controller.example:8443/siphon").port, 8443);
    }

    #[test]
    fn the_path_query_and_userinfo_are_not_part_of_the_address() {
        // The socket takes the authority only; the path is the WebSocket
        // handshake's business. A ':' in the path must not be read as a port.
        assert_eq!(
            target("wss://controller.example/siphon:9092?x=1#f"),
            DialTarget {
                tls: true,
                host: "controller.example".to_string(),
                port: 443
            }
        );
        assert_eq!(
            target("ws://user@controller.example:9092/s").host,
            "controller.example"
        );
    }

    #[test]
    fn an_ipv6_literal_keeps_its_brackets_for_the_connect_but_not_for_sni() {
        let parsed = target("wss://[2001:db8::1]:8443/siphon");
        assert_eq!(parsed.host, "2001:db8::1");
        assert_eq!(parsed.port, 8443);
        // Re-bracketed for the socket, or the port parse eats the last group.
        assert_eq!(parsed.address(), "[2001:db8::1]:8443");
        assert_eq!(target("wss://[2001:db8::1]").port, 443);
    }

    #[test]
    fn an_unsupported_scheme_names_the_two_that_work() {
        for url in ["https://controller.example", "tcp://controller.example"] {
            let error = parse_connect_url(url).expect_err(url);
            assert!(error.contains("ws:// or wss://"), "{error}");
        }
        // A bare host is a common paste; it must not be guessed at.
        let error = parse_connect_url("controller.example:9092").expect_err("no scheme");
        assert!(error.contains("no scheme"), "{error}");
    }

    #[test]
    fn a_hostless_or_unusable_port_is_refused() {
        for url in ["wss://", "wss:///siphon", "ws://:9092"] {
            assert!(parse_connect_url(url).is_err(), "{url} must be refused");
        }
        // Port 0 parses as a u16 but cannot be dialed, so it would fail once
        // per call at handover instead of once at load.
        let error = parse_connect_url("wss://controller.example:0").expect_err("port 0");
        assert!(error.contains("not dialable"), "{error}");
        let error = parse_connect_url("wss://controller.example:https").expect_err("named port");
        assert!(error.contains("not a port number"), "{error}");
    }

    /// A stub controller: accepts one WS connection and returns the first frame
    /// it receives (or a signal that the socket owned the call via StasisStart).
    // The accept-callback's `ErrorResponse` type is fixed by tungstenite's API.
    #[allow(clippy::result_large_err)]
    #[tokio::test]
    async fn per_call_connect_dials_and_socket_owns_the_call() {
        // Stub controller listening on an ephemeral port.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connect_url = format!("ws://{addr}/siphon");

        let (got_stasis_tx, got_stasis_rx) = tokio::sync::oneshot::channel::<serde_json::Value>();
        tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.unwrap();
            // A real controller echoes the negotiated subprotocol on accept —
            // tungstenite's client rejects the handshake otherwise.
            use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
            let echo_subprotocol = |_request: &Request, mut response: Response| {
                response.headers_mut().insert(
                    "Sec-WebSocket-Protocol",
                    tokio_tungstenite::tungstenite::http::HeaderValue::from_static(
                        "siphon-control.v1",
                    ),
                );
                Ok(response)
            };
            let mut ws = tokio_tungstenite::accept_hdr_async(stream, echo_subprotocol)
                .await
                .unwrap();
            // The very first frame siphon pushes must be StasisStart (ownership).
            while let Some(Ok(message)) = ws.next().await {
                if let ServerMessage::Text(text) = message {
                    let value: serde_json::Value = serde_json::from_str(text.as_str()).unwrap();
                    if value["event"] == "StasisStart" {
                        let _ = got_stasis_tx.send(value);
                        break;
                    }
                }
            }
        });

        let (command_tx, _command_rx) = flume::unbounded();
        let bus = ControlBus::new(
            command_tx,
            vec![app_cfg("ivr-app", "tok", &connect_url)],
            64,
            SlowConsumerPolicy::DropOldest,
            10,
            3000,
        );

        // Offer a channel to the per-call-connect app → siphon dials the stub.
        let outcome = bus.offer_channel(
            "ivr-app",
            "ch1",
            "call-uuid",
            "sipcid@host",
            "hangup",
            Default::default(),
            serde_json::json!({ "source_ip": "203.0.113.7" }),
        );
        assert_eq!(outcome, crate::control::OfferOutcome::Dialing);

        let stasis = tokio::time::timeout(std::time::Duration::from_secs(5), got_stasis_rx)
            .await
            .expect("controller should receive StasisStart")
            .expect("stasis channel");
        assert_eq!(stasis["channel"], "ch1");
        assert_eq!(stasis["sip_call_id"], "sipcid@host");
        assert_eq!(stasis["payload"]["source_ip"], "203.0.113.7");

        // The dialed socket now owns the channel.
        for _ in 0..100 {
            if bus.channel_count() == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(bus.channel_count(), 1);
    }

    /// Generate a CA plus a leaf certificate for 127.0.0.1, returning
    /// `(ca_path, certificate_path, key_path)`.
    ///
    /// A CA and a separate leaf, not one self-signed certificate doing both
    /// jobs: webpki refuses an end-entity certificate carrying `CA:TRUE`, so
    /// the one-certificate shortcut fails the handshake with a bare
    /// `CertificateUnknown` alert that names nothing.
    fn write_test_chain(
        directory: &std::path::Path,
    ) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let ca_certificate = directory.join("ca.crt");
        let ca_key = directory.join("ca.key");
        let certificate = directory.join("controller.crt");
        let key = directory.join("controller.key");
        let csr = directory.join("controller.csr");
        let extensions = directory.join("leaf.ext");
        std::fs::write(
            &extensions,
            "subjectAltName=IP:127.0.0.1\n\
             extendedKeyUsage=serverAuth\n\
             basicConstraints=critical,CA:FALSE\n\
             keyUsage=critical,digitalSignature,keyEncipherment\n",
        )
        .expect("write extensions");

        let run = |arguments: Vec<std::ffi::OsString>| {
            let status = std::process::Command::new("openssl")
                .args(&arguments)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .expect("openssl must be available to generate test certificates");
            assert!(status.success(), "openssl failed: {arguments:?}");
        };
        let osstr = |value: &str| std::ffi::OsString::from(value);

        run(vec![
            osstr("req"),
            osstr("-x509"),
            osstr("-newkey"),
            osstr("rsa:2048"),
            osstr("-nodes"),
            osstr("-days"),
            osstr("1"),
            osstr("-subj"),
            osstr("/CN=siphon-test-ca"),
            osstr("-keyout"),
            ca_key.clone().into_os_string(),
            osstr("-out"),
            ca_certificate.clone().into_os_string(),
        ]);
        run(vec![
            osstr("req"),
            osstr("-newkey"),
            osstr("rsa:2048"),
            osstr("-nodes"),
            osstr("-subj"),
            osstr("/CN=siphon-control-test"),
            osstr("-keyout"),
            key.clone().into_os_string(),
            osstr("-out"),
            csr.clone().into_os_string(),
        ]);
        run(vec![
            osstr("x509"),
            osstr("-req"),
            osstr("-in"),
            csr.into_os_string(),
            osstr("-CA"),
            ca_certificate.clone().into_os_string(),
            osstr("-CAkey"),
            ca_key.into_os_string(),
            osstr("-CAcreateserial"),
            osstr("-days"),
            osstr("1"),
            osstr("-extfile"),
            extensions.into_os_string(),
            osstr("-out"),
            certificate.clone().into_os_string(),
        ]);
        (ca_certificate, certificate, key)
    }

    /// The same dial as above, over `wss://`.
    ///
    /// The whole point is that it goes over the wire: `parse_connect_url` says
    /// a URL *should* be dialed with TLS, but only a real handshake proves the
    /// stream is wrapped, the CA bundle is honoured and the WebSocket handshake
    /// still completes on top of it.
    // The accept-callback's `ErrorResponse` type is fixed by tungstenite's API.
    #[allow(clippy::result_large_err)]
    #[tokio::test]
    async fn a_wss_connect_url_dials_over_tls_and_owns_the_call() {
        let directory = std::env::temp_dir().join("siphon-control-wss-dial");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("temp dir");
        let (ca_path, certificate_path, key_path) = write_test_chain(&directory);

        use tokio_rustls::rustls::pki_types::pem::PemObject;
        let certificates: Vec<_> =
            tokio_rustls::rustls::pki_types::CertificateDer::pem_file_iter(&certificate_path)
                .expect("read cert")
                .collect::<std::result::Result<Vec<_>, _>>()
                .expect("parse cert");
        let key = tokio_rustls::rustls::pki_types::PrivateKeyDer::from_pem_file(&key_path)
            .expect("parse key");
        let server_config = tokio_rustls::rustls::ServerConfig::builder_with_provider(
            crate::transport::tls::crypto_provider(),
        )
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .expect("server config");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connect_url = format!("wss://{addr}/siphon");

        let (got_stasis_tx, got_stasis_rx) = tokio::sync::oneshot::channel::<serde_json::Value>();
        tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.unwrap();
            let stream = acceptor.accept(stream).await.expect("tls handshake");
            use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
            let echo_subprotocol = |_request: &Request, mut response: Response| {
                response.headers_mut().insert(
                    "Sec-WebSocket-Protocol",
                    tokio_tungstenite::tungstenite::http::HeaderValue::from_static(
                        "siphon-control.v1",
                    ),
                );
                Ok(response)
            };
            let mut ws = tokio_tungstenite::accept_hdr_async(stream, echo_subprotocol)
                .await
                .unwrap();
            while let Some(Ok(message)) = ws.next().await {
                if let ServerMessage::Text(text) = message {
                    let value: serde_json::Value = serde_json::from_str(text.as_str()).unwrap();
                    if value["event"] == "StasisStart" {
                        let _ = got_stasis_tx.send(value);
                        break;
                    }
                }
            }
        });

        let mut config = app_cfg("ivr-app", "tok", &connect_url);
        config.ca_file = Some(ca_path.to_string_lossy().into_owned());

        let (command_tx, _command_rx) = flume::unbounded();
        let bus = ControlBus::new(
            command_tx,
            vec![config],
            64,
            SlowConsumerPolicy::DropOldest,
            10,
            3000,
        );

        let outcome = bus.offer_channel(
            "ivr-app",
            "ch-tls",
            "call-uuid",
            "sipcid@host",
            "hangup",
            Default::default(),
            serde_json::json!({ "source_ip": "203.0.113.7" }),
        );
        assert_eq!(outcome, crate::control::OfferOutcome::Dialing);

        let stasis = tokio::time::timeout(std::time::Duration::from_secs(10), got_stasis_rx)
            .await
            .expect("controller should receive StasisStart over TLS")
            .expect("stasis channel");
        assert_eq!(stasis["channel"], "ch-tls");

        for _ in 0..200 {
            if bus.channel_count() == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(bus.channel_count(), 1);
        let _ = std::fs::remove_dir_all(&directory);
    }

    /// The negative twin: the same controller, but siphon is not told the CA.
    ///
    /// Without this, a `ca_file` that was silently ignored would leave the test
    /// above passing while every certificate on earth was acceptable.
    #[tokio::test]
    async fn a_wss_dial_without_the_ca_is_refused_rather_than_trusted() {
        let directory = std::env::temp_dir().join("siphon-control-wss-noca");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("temp dir");
        let (_ca_path, certificate_path, key_path) = write_test_chain(&directory);

        use tokio_rustls::rustls::pki_types::pem::PemObject;
        let certificates: Vec<_> =
            tokio_rustls::rustls::pki_types::CertificateDer::pem_file_iter(&certificate_path)
                .expect("read cert")
                .collect::<std::result::Result<Vec<_>, _>>()
                .expect("parse cert");
        let key = tokio_rustls::rustls::pki_types::PrivateKeyDer::from_pem_file(&key_path)
            .expect("parse key");
        let server_config = tokio_rustls::rustls::ServerConfig::builder_with_provider(
            crate::transport::tls::crypto_provider(),
        )
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .expect("server config");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // The controller really is there and really does hand over its
        // certificate — otherwise this would time out on connect and pass for
        // the wrong reason.
        tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.unwrap();
            let _ = acceptor.accept(stream).await;
        });

        // No ca_file: the self-signed controller is not in the public roots.
        let error = connect(&format!("wss://{addr}/siphon"), "tok", None)
            .await
            .expect_err("an untrusted certificate must not be accepted");
        assert!(
            error.contains("TLS connect"),
            "expected a TLS failure, got {error}"
        );
        let _ = std::fs::remove_dir_all(&directory);
    }
}
