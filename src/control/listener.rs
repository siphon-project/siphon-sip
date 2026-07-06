//! The control-plane WebSocket listener (axum).
//!
//! ## I/O discipline (the whole point)
//!
//! Per connection there are exactly two async tokio tasks and nothing else:
//!
//! - a **read task** that parses inbound frames, hands each command to the
//!   dispatcher over an **unbounded** `flume` channel (a send that never blocks)
//!   and then `.await`s a `oneshot` for the *local* reply, and
//! - a **write task** that serialises replies and pushed events onto the socket,
//!   draining the connection's **bounded** event queue.
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
use serde::Serialize;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::config::ControlAppConfig;

use super::protocol::{
    CommandFrame, ControlErrorCode, ControlResult, HelloArgs, ReplyFrame,
};
use super::registry::{ControlBus, ControlCommand, EventQueue};

/// Shared state for the control listener router.
#[derive(Clone)]
pub struct ControlServerState {
    /// Configured applications (name + bearer token).
    pub apps: Arc<Vec<ControlAppConfig>>,
    /// The process-global control bus.
    pub bus: Arc<ControlBus>,
}

/// Start the control-plane WebSocket server. Mirrors `admin::serve`: logs and
/// returns on bind error rather than panicking.
pub async fn serve(listen_addr: SocketAddr, state: ControlServerState) {
    let app = router(state);

    info!(%listen_addr, "control plane (experimental) listening");

    let listener = match tokio::net::TcpListener::bind(listen_addr).await {
        Ok(listener) => listener,
        Err(error) => {
            warn!(%listen_addr, %error, "failed to bind control plane listener");
            return;
        }
    };

    let make_service = app.into_make_service_with_connect_info::<SocketAddr>();
    if let Err(error) = axum::serve(listener, make_service).await {
        warn!(%error, "control plane server error");
    }
}

/// Build the control router (also used by tests without binding a port).
pub fn router(state: ControlServerState) -> Router {
    Router::new()
        .route("/control/ws", get(ws_handler))
        .with_state(state)
}

/// Constant-time byte comparison for bearer tokens.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference: u8 = 0;
    for (a, b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
    }
    difference == 0
}

/// Validate the `Authorization: Bearer <token>` header against the configured
/// apps. Returns the matching app name, or `None` when unauthenticated.
fn authenticate(headers: &HeaderMap, apps: &[ControlAppConfig]) -> Option<String> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))?;
    for app in apps {
        if constant_time_eq(token.as_bytes(), app.token.as_bytes()) {
            return Some(app.name.clone());
        }
    }
    None
}

/// The WS upgrade handler. Rejects a bad/missing token with `401` **before** the
/// socket exists (no half-open state for unauthenticated peers).
async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<ControlServerState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let app = match authenticate(&headers, &state.apps) {
        Some(app) => app,
        None => {
            // Feed the existing auto-ban store so brute-forcing control tokens
            // gets the source IP banned just like a SIP scanner.
            crate::security::record_handshake_failure(peer.ip(), "control");
            warn!(remote = %peer, "control plane: rejected unauthenticated upgrade");
            return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
        }
    };

    let bus = Arc::clone(&state.bus);
    ws.on_upgrade(move |socket| handle_socket(socket, app, bus, peer))
}

/// Drive one authenticated control connection to completion.
async fn handle_socket(socket: WebSocket, app: String, bus: Arc<ControlBus>, peer: SocketAddr) {
    let conn = bus.register_connection(&app);
    info!(remote = %peer, %app, conn_id = conn.id, "control plane: connection open");

    let (ws_sink, mut ws_source) = socket.split();
    // Replies are 1:1 with in-flight commands and must never be dropped by
    // backpressure (a dropped reply would hang the client's rpc). Bounded so a
    // client that stops reading stalls only its own connection.
    let (reply_tx, reply_rx) = mpsc::channel::<ReplyFrame>(64);

    let writer_events = Arc::clone(&conn.events);
    let writer = tokio::spawn(write_task(ws_sink, writer_events, reply_rx));

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
                if !read_text_frame(text.as_str(), &mut said_hello, &app, &bus, &reply_tx).await {
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

    // Teardown: dropping reply_tx and closing the queue both wake the writer.
    conn.events.close();
    drop(reply_tx);
    bus.unregister_connection(&conn);
    let _ = writer.await;
    info!(remote = %peer, %app, conn_id = conn.id, "control plane: connection closed");
}

/// Handle one inbound text frame. Returns `false` when the connection should
/// close (fatal protocol error / handshake failure).
async fn read_text_frame(
    text: &str,
    said_hello: &mut bool,
    app: &str,
    bus: &Arc<ControlBus>,
    reply_tx: &mpsc::Sender<ReplyFrame>,
) -> bool {
    let frame: CommandFrame = match serde_json::from_str(text) {
        Ok(frame) => frame,
        Err(error) => {
            warn!(%error, "control plane: malformed frame");
            // No id to correlate; drop the frame but keep the connection.
            return true;
        }
    };

    let id = frame.id.clone();

    if !*said_hello {
        return handle_hello(&frame, id, said_hello, app, reply_tx).await;
    }

    handle_command(frame, id, bus, reply_tx).await;
    true
}

/// Process the mandatory first `hello` frame.
async fn handle_hello(
    frame: &CommandFrame,
    id: String,
    said_hello: &mut bool,
    app: &str,
    reply_tx: &mpsc::Sender<ReplyFrame>,
) -> bool {
    if frame.verb != "hello" {
        let reply = ControlResult::error(
            ControlErrorCode::ProtocolError,
            "first frame must be a hello command",
        )
        .into_reply(id);
        let _ = reply_tx.send(reply).await;
        return false;
    }

    let hello: HelloArgs = match serde_json::from_value(frame.args.clone()) {
        Ok(hello) => hello,
        Err(error) => {
            let reply = ControlResult::error(
                ControlErrorCode::BadRequest,
                format!("invalid hello args: {error}"),
            )
            .into_reply(id);
            let _ = reply_tx.send(reply).await;
            return false;
        }
    };

    // The token's configured app must equal the asserted app (closes cross-app
    // impersonation).
    if hello.app != app {
        let reply = ControlResult::error(
            ControlErrorCode::Forbidden,
            "hello app does not match the authenticated token",
        )
        .into_reply(id);
        let _ = reply_tx.send(reply).await;
        return false;
    }

    *said_hello = true;
    let reply = ControlResult::Ok(serde_json::json!({
        "app": app,
        "protocol": 1,
        "subprotocol": "siphon-control.v1",
    }))
    .into_reply(id);
    reply_tx.send(reply).await.is_ok()
}

/// Route a command to the dispatcher and await its *local* reply.
async fn handle_command(
    frame: CommandFrame,
    id: String,
    bus: &Arc<ControlBus>,
    reply_tx: &mpsc::Sender<ReplyFrame>,
) {
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    let command = ControlCommand {
        id: frame.id,
        verb: frame.verb,
        target: frame.target,
        args: frame.args,
        response_tx,
    };

    // Unbounded flume send — cannot block the read task (rule 3).
    if bus.command_sender().send(command).is_err() {
        let reply = ControlResult::error(
            ControlErrorCode::Unavailable,
            "control command consumer is not running",
        )
        .into_reply(id);
        let _ = reply_tx.send(reply).await;
        return;
    }

    // Async wait for the local result — never a far-end wait, never a thread
    // block (rule 4/5). The far-end outcome arrives later as an event.
    let result = match response_rx.await {
        Ok(result) => result,
        Err(_) => {
            ControlResult::error(ControlErrorCode::Unavailable, "control command was dropped")
        }
    };
    let _ = reply_tx.send(result.into_reply(id)).await;
}

/// The connection's single write task: multiplexes correlated replies and pushed
/// events onto the socket.
async fn write_task(
    mut ws_sink: SplitSink<WebSocket, Message>,
    events: Arc<EventQueue>,
    mut reply_rx: mpsc::Receiver<ReplyFrame>,
) {
    'outer: loop {
        tokio::select! {
            maybe_reply = reply_rx.recv() => {
                match maybe_reply {
                    Some(reply) => {
                        if !send_json(&mut ws_sink, &reply).await {
                            break 'outer;
                        }
                    }
                    // Reader gone (after all buffered replies drained) → done.
                    None => break 'outer,
                }
            }
            frames = events.recv_many() => {
                if frames.is_empty() {
                    // The event queue was closed on teardown. Drain any replies
                    // still buffered (e.g. a handshake rejection) before closing,
                    // so a queue-closed race can't swallow the correlated reply.
                    while let Some(reply) = reply_rx.recv().await {
                        if !send_json(&mut ws_sink, &reply).await {
                            break;
                        }
                    }
                    break 'outer;
                }
                for frame in frames {
                    if !send_json(&mut ws_sink, &frame).await {
                        break 'outer;
                    }
                }
                if events.disconnect_requested() {
                    break 'outer;
                }
            }
        }
    }
    let _ = ws_sink.send(Message::Close(None)).await;
}

/// Serialise a frame to a text WS message. Returns `false` on send failure.
async fn send_json<T: Serialize>(ws_sink: &mut SplitSink<WebSocket, Message>, frame: &T) -> bool {
    let text = match serde_json::to_string(frame) {
        Ok(text) => text,
        Err(error) => {
            warn!(%error, "control plane: failed to serialise outbound frame");
            return true; // don't tear down the connection over one bad frame
        }
    };
    ws_sink.send(Message::Text(text.into())).await.is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::protocol::EventFrame;
    use crate::control::registry::SlowConsumerPolicy;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::http::HeaderValue;
    use tokio_tungstenite::tungstenite::Message as ClientMessage;

    fn test_apps() -> Arc<Vec<ControlAppConfig>> {
        Arc::new(vec![ControlAppConfig {
            name: "ivr-app".to_string(),
            token: "s3cr3t".to_string(),
        }])
    }

    async fn start_server(
        bus: Arc<ControlBus>,
    ) -> SocketAddr {
        let state = ControlServerState {
            apps: test_apps(),
            bus,
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let make_service = router(state).into_make_service_with_connect_info::<SocketAddr>();
        tokio::spawn(async move {
            let _ = axum::serve(listener, make_service).await;
        });
        addr
    }

    fn client_request(addr: SocketAddr, token: &str) -> tokio_tungstenite::tungstenite::handshake::client::Request {
        let mut request = format!("ws://{addr}/control/ws")
            .into_client_request()
            .unwrap();
        request.headers_mut().insert(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        request
    }

    #[test]
    fn constant_time_eq_matches_and_rejects() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }

    #[test]
    fn authenticate_extracts_app() {
        let apps = test_apps();
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer s3cr3t"));
        assert_eq!(authenticate(&headers, &apps).as_deref(), Some("ivr-app"));

        let mut bad = HeaderMap::new();
        bad.insert("authorization", HeaderValue::from_static("Bearer nope"));
        assert!(authenticate(&bad, &apps).is_none());

        assert!(authenticate(&HeaderMap::new(), &apps).is_none());
    }

    #[tokio::test]
    async fn bad_token_rejected_with_401_before_upgrade() {
        let (command_tx, _command_rx) = flume::unbounded();
        let bus = ControlBus::new(command_tx, 64, SlowConsumerPolicy::DropOldest);
        let addr = start_server(bus).await;

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
        let (command_tx, command_rx) = flume::unbounded();
        let bus = ControlBus::new(command_tx, 64, SlowConsumerPolicy::DropOldest);
        let addr = start_server(Arc::clone(&bus)).await;

        // Stand in for the dispatcher's apply consumer: answer every command Ok.
        tokio::spawn(async move {
            while let Ok(command) = command_rx.recv_async().await {
                let _ = command
                    .response_tx
                    .send(ControlResult::Ok(serde_json::json!({ "verb": command.verb })));
            }
        });

        let (mut ws, _response) = tokio_tungstenite::connect_async(client_request(addr, "s3cr3t"))
            .await
            .expect("handshake with good token must succeed");

        // hello → ok reply
        ws.send(ClientMessage::Text(
            serde_json::json!({
                "id": "1",
                "type": "command",
                "verb": "hello",
                "args": { "app": "ivr-app", "protocol": 1 }
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();

        let hello_reply = next_json(&mut ws).await;
        assert_eq!(hello_reply["type"], "reply");
        assert_eq!(hello_reply["id"], "1");
        assert_eq!(hello_reply["status"], "ok");

        // A synthetic event pushed server-side must reach the client.
        let conn = {
            let mut found = None;
            for _ in 0..100 {
                if let Some(conn) = bus.pick_connection("ivr-app") {
                    found = Some(conn);
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            found.expect("connection should be registered after hello")
        };
        bus.register_channel("ch1", Arc::clone(&conn), "call-uuid");
        assert!(bus.publish_to_channel(
            "ch1",
            EventFrame::new("StasisStart", "ch1", "ivr-app", serde_json::json!({ "call_id": "x" })),
        ));

        let event = next_json(&mut ws).await;
        assert_eq!(event["type"], "event");
        assert_eq!(event["event"], "StasisStart");
        assert_eq!(event["channel"], "ch1");

        // A command → correlated reply.
        ws.send(ClientMessage::Text(
            serde_json::json!({
                "id": "42",
                "type": "command",
                "verb": "answer",
                "target": { "channel": "ch1" },
                "args": { "code": 200 }
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();

        let reply = next_json(&mut ws).await;
        assert_eq!(reply["type"], "reply");
        assert_eq!(reply["id"], "42");
        assert_eq!(reply["status"], "ok");
        assert_eq!(reply["result"]["verb"], "answer");
    }

    #[tokio::test]
    async fn hello_with_wrong_app_is_forbidden() {
        let (command_tx, _command_rx) = flume::unbounded();
        let bus = ControlBus::new(command_tx, 64, SlowConsumerPolicy::DropOldest);
        let addr = start_server(bus).await;

        let (mut ws, _response) = tokio_tungstenite::connect_async(client_request(addr, "s3cr3t"))
            .await
            .unwrap();
        ws.send(ClientMessage::Text(
            serde_json::json!({
                "id": "1",
                "type": "command",
                "verb": "hello",
                "args": { "app": "someone-else" }
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();

        let reply = next_json(&mut ws).await;
        assert_eq!(reply["status"], "error");
        assert_eq!(reply["error"]["code"], "forbidden");
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
