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

use std::sync::Arc;

use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tracing::{debug, info, warn};

use super::listener::process_text;
use super::protocol::{EventFrame, SUBPROTOCOL};
use super::registry::{ControlBus, OutboundQueue};

/// How long to wait for the controller to accept the per-call dial before giving
/// up (the handoff deadline is the ultimate backstop, but a bounded connect
/// keeps a dead controller from holding the dial task).
const DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

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
    pending: PendingOwn,
) {
    tokio::spawn(async move {
        let socket = match connect(&connect_url, &token).await {
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
) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>, String> {
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

    let (socket, _response) = tokio::time::timeout(DIAL_TIMEOUT, tokio_tungstenite::connect_async(request))
        .await
        .map_err(|_| "dial timed out".to_string())?
        .map_err(|error| format!("dial error: {error}"))?;
    Ok(socket)
}

/// Register ownership, push `StasisStart`, then run the read/write driver for one
/// outbound control connection.
async fn drive_outbound_socket(
    socket: WebSocketStream<MaybeTlsStream<TcpStream>>,
    app: String,
    bus: Arc<ControlBus>,
    pending: PendingOwn,
) {
    let conn = bus.register_connection(&app);
    crate::metrics::try_metrics().inspect(|m| m.control_connections.with_label_values(&[&app]).inc());

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
    crate::metrics::try_metrics().inspect(|m| m.control_connections.with_label_values(&[&app]).dec());
    let _ = writer.await;
    debug!(conn_id = conn.id, %app, "control plane: outbound connection closed");
}

/// The outbound connection's single write task: drains the ordered outbound
/// queue onto the tungstenite socket.
async fn outbound_write_task(
    mut ws_sink: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
    events: Arc<OutboundQueue>,
) {
    loop {
        let frames = events.recv_many().await;
        if frames.is_empty() {
            break;
        }
        for frame in frames {
            if let Some(text) = super::listener::frame_to_text(&frame) {
                if ws_sink.send(Message::Text(text.into())).await.is_err() {
                    let _ = ws_sink.send(Message::Close(None)).await;
                    return;
                }
            }
        }
        if events.disconnect_requested() {
            break;
        }
    }
    let _ = ws_sink.send(Message::Close(None)).await;
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
        }
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
}
