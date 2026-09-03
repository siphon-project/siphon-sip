//! The inbound control-plane WebSocket listener (axum) + the shared,
//! transport-agnostic per-connection frame logic reused by the outbound
//! per-call-connect dialer.
//!
//! ## I/O discipline (the whole point)
//!
//! Per connection there are exactly two async tokio tasks and nothing else:
//!
//! - a **read task** that parses inbound frames, hands each command to the
//!   consumer over an **unbounded** `flume` channel (a send that never blocks)
//!   and then `.await`s a `oneshot` for the *local* reply, and
//! - a **write task** that drains the connection's **bounded** outbound queue
//!   (replies + events, one ordered stream) onto the socket.
//!
//! No control I/O ever runs on `py_executor` or the dispatcher; a slow/dead peer
//! stalls only its own two tasks.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use tracing::{debug, info, warn};

use super::protocol::{
    CommandFrame, ControlErrorCode, ControlResult, HelloArgs, PROTOCOL_VERSION, SUBPROTOCOL,
};
use super::registry::{ConnHandle, ControlBus, ControlCommand, OutboundFrame, OutboundQueue};

/// Start the inbound control-plane WebSocket server. Mirrors `admin::serve`:
/// logs and returns on bind error rather than panicking.
pub async fn serve(listen_addr: SocketAddr, bus: Arc<ControlBus>) {
    let app = router(bus);

    let listener = match tokio::net::TcpListener::bind(listen_addr).await {
        Ok(listener) => listener,
        Err(error) => {
            warn!(%listen_addr, %error, "failed to bind control plane listener");
            return;
        }
    };
    info!(%listen_addr, "control plane listening (inbound WebSocket)");

    let make_service = app.into_make_service_with_connect_info::<SocketAddr>();
    if let Err(error) = axum::serve(listener, make_service).await {
        warn!(%error, "control plane server error");
    }
}

/// Build the control router (also used by tests without binding a port).
pub fn router(bus: Arc<ControlBus>) -> Router {
    Router::new()
        .route("/control/ws", get(ws_handler))
        .with_state(bus)
}

/// Extract the `Authorization: Bearer <token>` header and match it against the
/// configured apps. Returns the matching app name, or `None`.
fn authenticate(headers: &HeaderMap, bus: &ControlBus) -> Option<String> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))?;
    bus.authenticate_token(token)
}

/// The WS upgrade handler. Rejects a bad/missing token with `401` **before** the
/// socket exists (no half-open state for unauthenticated peers) and feeds the
/// auto-ban store so brute-forcing tokens gets the source IP banned.
async fn ws_handler(
    ws: WebSocketUpgrade,
    State(bus): State<Arc<ControlBus>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let app = match authenticate(&headers, &bus) {
        Some(app) => app,
        None => {
            crate::security::record_handshake_failure(peer.ip(), "control");
            crate::metrics::try_metrics().inspect(|m| m.control_auth_failures_total.inc());
            warn!(remote = %peer, "control plane: rejected unauthenticated upgrade");
            return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
        }
    };

    ws.protocols([SUBPROTOCOL])
        .on_upgrade(move |socket| handle_inbound_socket(socket, app, bus, peer))
}

/// Drive one authenticated inbound control connection to completion.
async fn handle_inbound_socket(
    socket: WebSocket,
    app: String,
    bus: Arc<ControlBus>,
    peer: SocketAddr,
) {
    let conn = bus.register_connection(&app);
    info!(remote = %peer, %app, conn_id = conn.id, "control plane: connection open");
    crate::metrics::try_metrics()
        .inspect(|m| m.control_connections.with_label_values(&[&app]).inc());

    let (ws_sink, mut ws_source) = socket.split();
    let writer_events = Arc::clone(&conn.events);
    let writer = tokio::spawn(inbound_write_task(ws_sink, writer_events));

    let mut said_hello = false;
    while let Some(message) = ws_source.next().await {
        let message = match message {
            Ok(message) => message,
            Err(error) => {
                debug!(conn_id = conn.id, %error, "control plane: read error");
                break;
            }
        };
        match message {
            Message::Text(text) => {
                if !process_text(text.as_str(), &mut said_hello, &conn, &bus).await {
                    break;
                }
            }
            Message::Close(_) => {
                debug!(conn_id = conn.id, "control plane: client closed");
                break;
            }
            Message::Ping(_) | Message::Pong(_) => {}
            Message::Binary(_) => {
                warn!(conn_id = conn.id, "control plane: ignoring binary frame");
            }
        }
    }

    conn.events.close();
    bus.unregister_connection(&conn);
    crate::metrics::try_metrics()
        .inspect(|m| m.control_connections.with_label_values(&[&app]).dec());
    let _ = writer.await;
    info!(remote = %peer, %app, conn_id = conn.id, "control plane: connection closed");
}

/// The inbound connection's single write task: drains the ordered outbound queue
/// (replies + events) onto the axum socket.
async fn inbound_write_task(
    mut ws_sink: SplitSink<WebSocket, Message>,
    events: Arc<OutboundQueue>,
) {
    loop {
        let frames = events.recv_many().await;
        if frames.is_empty() {
            break; // queue closed on teardown
        }
        for frame in frames {
            match frame.to_json() {
                Ok(text) => {
                    if ws_sink.send(Message::Text(text.into())).await.is_err() {
                        let _ = ws_sink.send(Message::Close(None)).await;
                        return;
                    }
                }
                Err(error) => warn!(%error, "control plane: failed to serialize outbound frame"),
            }
        }
        if events.disconnect_requested() {
            break;
        }
    }
    let _ = ws_sink.send(Message::Close(None)).await;
}

// ---------------------------------------------------------------------------
// Shared, transport-agnostic frame processing (reused by outbound.rs).
// ---------------------------------------------------------------------------

/// Handle one inbound text frame on an authenticated connection. Returns `false`
/// when the connection should close (fatal protocol error / handshake failure).
pub(crate) async fn process_text(
    text: &str,
    said_hello: &mut bool,
    conn: &Arc<ConnHandle>,
    bus: &Arc<ControlBus>,
) -> bool {
    let frame: CommandFrame = match serde_json::from_str(text) {
        Ok(frame) => frame,
        Err(error) => {
            warn!(%error, "control plane: malformed frame");
            return true; // no id to correlate; drop the frame, keep the connection
        }
    };
    let id = frame.id.clone();

    if !*said_hello {
        return handle_hello(&frame, id, said_hello, &conn.app, conn);
    }

    handle_command(frame, id, conn, bus).await;
    true
}

/// Process the mandatory first `hello` frame. On success the reply carries the
/// negotiated protocol + subprotocol; a mismatch closes the connection.
fn handle_hello(
    frame: &CommandFrame,
    id: String,
    said_hello: &mut bool,
    app: &str,
    conn: &Arc<ConnHandle>,
) -> bool {
    if frame.verb != "hello" {
        conn.events.push_reply(
            ControlResult::error(
                ControlErrorCode::ProtocolError,
                "first frame must be a hello command",
            )
            .into_reply(id),
        );
        return false;
    }

    let hello: HelloArgs = match serde_json::from_value(frame.args.clone()) {
        Ok(hello) => hello,
        Err(error) => {
            conn.events.push_reply(
                ControlResult::error(
                    ControlErrorCode::BadRequest,
                    format!("invalid hello args: {error}"),
                )
                .into_reply(id),
            );
            return false;
        }
    };

    if hello.app != app {
        conn.events.push_reply(
            ControlResult::error(
                ControlErrorCode::Forbidden,
                "hello app does not match the authenticated token",
            )
            .into_reply(id),
        );
        return false;
    }

    if let Some(protocol) = hello.protocol {
        if protocol != PROTOCOL_VERSION {
            conn.events.push_reply(
                ControlResult::error(
                    ControlErrorCode::UnsupportedVersion,
                    format!("unsupported protocol version {protocol} (this build speaks {PROTOCOL_VERSION})"),
                )
                .into_reply(id),
            );
            return false;
        }
    }

    *said_hello = true;
    conn.events.push_reply(
        ControlResult::Ok(serde_json::json!({
            "app": app,
            "protocol": PROTOCOL_VERSION,
            "subprotocol": SUBPROTOCOL,
        }))
        .into_reply(id),
    );
    true
}

/// Route a command to the consumer and, when its *local* reply arrives, enqueue
/// it on the connection's ordered outbound queue (so replies + events for a call
/// are totally ordered on the owner socket).
async fn handle_command(
    frame: CommandFrame,
    id: String,
    conn: &Arc<ConnHandle>,
    bus: &Arc<ControlBus>,
) {
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    let verb = frame.verb.clone();
    let command = ControlCommand {
        id: frame.id,
        app: conn.app.clone(),
        conn_id: conn.id,
        module: frame.module,
        verb: frame.verb,
        target: frame.target,
        args: frame.args,
        response_tx,
    };

    if bus.command_sender().send(command).is_err() {
        conn.events.push_reply(
            ControlResult::error(
                ControlErrorCode::Unavailable,
                "control command consumer is not running",
            )
            .into_reply(id),
        );
        return;
    }
    crate::metrics::try_metrics().inspect(|m| {
        m.control_commands_total
            .with_label_values(&[&conn.app, &verb])
            .inc()
    });

    // Async wait for the *local* result — never a far-end wait, never a thread
    // block (rules 4/5). The far-end outcome arrives later as an event.
    let result = match response_rx.await {
        Ok(result) => result,
        Err(_) => {
            ControlResult::error(ControlErrorCode::Unavailable, "control command was dropped")
        }
    };
    conn.events.push_reply(result.into_reply(id));
}

/// Serialize a single outbound frame to a WS text payload (shared with the
/// outbound dialer's write task).
pub(crate) fn frame_to_text(frame: &OutboundFrame) -> Option<String> {
    match frame.to_json() {
        Ok(text) => Some(text),
        Err(error) => {
            warn!(%error, "control plane: failed to serialize outbound frame");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ControlAppConfig;
    use crate::control::registry::SlowConsumerPolicy;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::http::HeaderValue;
    use tokio_tungstenite::tungstenite::Message as ClientMessage;

    fn app_cfg(name: &str, token: &str) -> ControlAppConfig {
        ControlAppConfig {
            name: name.to_string(),
            token: token.to_string(),
            per_call_connect: false,
            connect_url: None,
            on_lost: Some("hangup".to_string()),
        }
    }

    fn test_bus() -> Arc<ControlBus> {
        let (command_tx, command_rx) = flume::unbounded();
        let bus = ControlBus::new(
            command_tx,
            vec![app_cfg("ivr-app", "s3cr3t")],
            64,
            SlowConsumerPolicy::DropOldest,
            10,
            3000,
        );
        // Stand-in consumer: echo every command Ok (no real adapter in this test).
        tokio::spawn(async move {
            while let Ok(command) = command_rx.recv_async().await {
                let _ = command.response_tx.send(ControlResult::Ok(
                    serde_json::json!({ "verb": command.verb }),
                ));
            }
        });
        bus
    }

    async fn start_server(bus: Arc<ControlBus>) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let make_service = router(bus).into_make_service_with_connect_info::<SocketAddr>();
        tokio::spawn(async move {
            let _ = axum::serve(listener, make_service).await;
        });
        addr
    }

    fn client_request(
        addr: SocketAddr,
        token: &str,
    ) -> tokio_tungstenite::tungstenite::handshake::client::Request {
        let mut request = format!("ws://{addr}/control/ws")
            .into_client_request()
            .unwrap();
        request.headers_mut().insert(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        request
    }

    #[tokio::test]
    async fn bad_token_rejected_with_401_before_upgrade() {
        let addr = start_server(test_bus()).await;
        let result = tokio_tungstenite::connect_async(client_request(addr, "wrong")).await;
        match result {
            Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
                assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            }
            other => panic!("expected HTTP 401, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn good_token_hello_then_event_then_command() {
        let bus = test_bus();
        let addr = start_server(Arc::clone(&bus)).await;

        let (mut ws, _response) = tokio_tungstenite::connect_async(client_request(addr, "s3cr3t"))
            .await
            .expect("handshake with good token must succeed");

        ws.send(ClientMessage::Text(
            serde_json::json!({"id":"1","type":"command","verb":"hello","args":{"app":"ivr-app","protocol":1}})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();

        let hello_reply = next_json(&mut ws).await;
        assert_eq!(hello_reply["type"], "reply");
        assert_eq!(hello_reply["id"], "1");
        assert_eq!(hello_reply["status"], "ok");
        assert_eq!(hello_reply["result"]["subprotocol"], "siphon-control.v1");

        // Register a channel server-side + push StasisStart.
        let conn = {
            let mut found = None;
            for _ in 0..100 {
                if let Some(conn) = bus.pick_connection("ivr-app") {
                    found = Some(conn);
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            found.expect("connection registered after hello")
        };
        bus.register_channel(
            "ch1",
            &conn,
            "call-uuid",
            "sipcid@h",
            "hangup",
            Default::default(),
        );
        assert!(bus.publish_to_channel(
            "ch1",
            crate::control::protocol::EventFrame::new(
                "StasisStart",
                "ch1",
                "ivr-app",
                "call-uuid",
                "sipcid@h",
                serde_json::json!({}),
            ),
        ));

        let event = next_json(&mut ws).await;
        assert_eq!(event["type"], "event");
        assert_eq!(event["event"], "StasisStart");
        assert_eq!(event["channel"], "ch1");
        assert_eq!(event["sip_call_id"], "sipcid@h");

        // A command → correlated reply (via the stand-in consumer).
        ws.send(ClientMessage::Text(
            serde_json::json!({"id":"42","type":"command","module":"sip","verb":"answer","target":{"channel":"ch1"},"args":{"code":200}})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
        let reply = next_json(&mut ws).await;
        assert_eq!(reply["id"], "42");
        assert_eq!(reply["status"], "ok");
    }

    #[tokio::test]
    async fn hello_with_wrong_app_is_forbidden() {
        let addr = start_server(test_bus()).await;
        let (mut ws, _response) = tokio_tungstenite::connect_async(client_request(addr, "s3cr3t"))
            .await
            .unwrap();
        ws.send(ClientMessage::Text(
            serde_json::json!({"id":"1","type":"command","verb":"hello","args":{"app":"someone-else"}})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
        let reply = next_json(&mut ws).await;
        assert_eq!(reply["status"], "error");
        assert_eq!(reply["error"]["code"], "forbidden");
    }

    /// A bus wired to the *real* command consumer + SIP adapter (so substrate
    /// verbs like `resync` are actually dispatched, not echoed).
    fn test_bus_real_consumer() -> Arc<ControlBus> {
        use std::collections::HashMap;
        let (command_tx, command_rx) = flume::unbounded();
        let bus = ControlBus::new(
            command_tx,
            vec![app_cfg("ivr-app", "s3cr3t")],
            64,
            SlowConsumerPolicy::DropOldest,
            10,
            3000,
        );
        let mut adapters: HashMap<String, Arc<dyn crate::control::ControlAdapter>> = HashMap::new();
        adapters.insert(
            "sip".to_string(),
            Arc::new(crate::control::sip_adapter::SipControlAdapter::new()),
        );
        tokio::spawn(crate::control::run_consumer(
            Arc::clone(&bus),
            Arc::new(adapters),
            command_rx,
        ));
        bus
    }

    #[tokio::test]
    async fn resync_reattaches_owned_channels_after_reconnect() {
        let bus = test_bus_real_consumer();
        let addr = start_server(Arc::clone(&bus)).await;

        // First connection: hello, then a channel is handed to it.
        let (mut ws1, _r) = tokio_tungstenite::connect_async(client_request(addr, "s3cr3t"))
            .await
            .unwrap();
        ws1.send(ClientMessage::Text(
            serde_json::json!({"id":"1","type":"command","verb":"hello","args":{"app":"ivr-app"}})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
        let _ = next_json(&mut ws1).await;

        let conn1 = {
            let mut found = None;
            for _ in 0..100 {
                if let Some(conn) = bus.pick_connection("ivr-app") {
                    found = Some(conn);
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            found.unwrap()
        };
        bus.register_channel(
            "ch-live",
            &conn1,
            "call-uuid",
            "sipcid@h",
            "hangup",
            Default::default(),
        );

        // Owner disconnects (drop the client socket) — the channel is orphaned
        // but kept for the reattach grace window.
        drop(ws1);
        for _ in 0..100 {
            if bus.app_connection_count("ivr-app") == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(bus.channel_count(), 1, "channel kept for reattach grace");

        // Reconnect + resync re-claims the orphaned channel.
        let (mut ws2, _r) = tokio_tungstenite::connect_async(client_request(addr, "s3cr3t"))
            .await
            .unwrap();
        ws2.send(ClientMessage::Text(
            serde_json::json!({"id":"1","type":"command","verb":"hello","args":{"app":"ivr-app"}})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
        let _ = next_json(&mut ws2).await;
        ws2.send(ClientMessage::Text(
            serde_json::json!({"id":"2","type":"command","verb":"resync"})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
        let reply = next_json(&mut ws2).await;
        assert_eq!(reply["id"], "2");
        assert_eq!(reply["status"], "ok");
        let channels = reply["result"]["channels"].as_array().unwrap();
        assert_eq!(channels.len(), 1);
        assert_eq!(channels[0]["channel"], "ch-live");
    }

    #[tokio::test]
    async fn unknown_protocol_version_is_rejected() {
        let addr = start_server(test_bus()).await;
        let (mut ws, _response) = tokio_tungstenite::connect_async(client_request(addr, "s3cr3t"))
            .await
            .unwrap();
        ws.send(ClientMessage::Text(
            serde_json::json!({"id":"1","type":"command","verb":"hello","args":{"app":"ivr-app","protocol":99}})
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
        let reply = next_json(&mut ws).await;
        assert_eq!(reply["error"]["code"], "unsupported_version");
    }

    async fn next_json(
        ws: &mut tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    ) -> serde_json::Value {
        loop {
            let message = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next())
                .await
                .expect("timed out waiting for a frame")
                .expect("stream closed")
                .expect("ws error");
            if let ClientMessage::Text(text) = message {
                return serde_json::from_str(text.as_str()).unwrap();
            }
        }
    }
}
