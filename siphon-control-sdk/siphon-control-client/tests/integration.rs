//! End-to-end tests against an in-process stub control server that speaks the
//! `siphon-control.v1` handshake, echoes correlated replies, and pushes events.
//! Covers BOTH connection modes: inbound-persistent ([`ControlClient`]) and
//! per-call-connect ([`ControlServer`]).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use futures_util::{SinkExt, StreamExt};

use siphon_control_client::{
    ClientConfig, ControlClient, ControlError, ControlErrorCode, ServerConfig, SipClient, SipServer,
};

const APP: &str = "ivr-app";
const TOKEN: &str = "s3cr3t";

// ---------------------------------------------------------------------------
// Inbound-persistent stub: an axum WS server the ControlClient connects to.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Stub {
    conn_count: AtomicU64,
    /// resync channels returned by the `resync` verb (2nd+ connection).
    resync_channels: Mutex<Vec<serde_json::Value>>,
    /// When true, connection index 0 closes right after replying `hello`.
    close_first_after_hello: bool,
}

async fn start_stub(stub: Arc<Stub>) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/control/ws", get(ws_handler))
        .with_state(stub);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });
    addr
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(stub): State<Arc<Stub>>,
    headers: HeaderMap,
) -> Response {
    let authorized = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(|token| token == TOKEN)
        .unwrap_or(false);
    if !authorized {
        return (StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    ws.protocols(["siphon-control.v1"])
        .on_upgrade(move |socket| drive_stub(socket, stub))
}

async fn drive_stub(mut socket: WebSocket, stub: Arc<Stub>) {
    let index = stub.conn_count.fetch_add(1, Ordering::SeqCst);
    let mut said_hello = false;
    while let Some(Ok(message)) = socket.next().await {
        let Message::Text(text) = message else {
            continue;
        };
        let frame: serde_json::Value = match serde_json::from_str(text.as_str()) {
            Ok(frame) => frame,
            Err(_) => continue,
        };
        let id = frame["id"].as_str().unwrap_or_default().to_string();
        let verb = frame["verb"].as_str().unwrap_or_default().to_string();

        if !said_hello {
            // First frame is the mandatory hello.
            assert_eq!(verb, "hello", "first frame must be hello");
            send_ok(
                &mut socket,
                &id,
                serde_json::json!({ "app": APP, "protocol": 1, "subprotocol": "siphon-control.v1" }),
            )
            .await;
            said_hello = true;
            if stub.close_first_after_hello && index == 0 {
                let _ = socket.send(Message::Close(None)).await;
                return;
            }
            continue;
        }

        match verb.as_str() {
            "resync" => {
                let channels = stub.resync_channels.lock().unwrap().clone();
                send_ok(&mut socket, &id, serde_json::json!({ "channels": channels })).await;
            }
            "describe" => {
                send_ok(
                    &mut socket,
                    &id,
                    serde_json::json!({ "adapters": [{ "module": "sip", "verbs": [], "events": [] }] }),
                )
                .await;
            }
            "answer" | "progress" | "reject" | "hangup" | "refer" | "set_header" | "set_var" => {
                send_ok(
                    &mut socket,
                    &id,
                    serde_json::json!({ "channel": frame["target"]["channel"], "state": "answered" }),
                )
                .await;
            }
            "get_header" | "get_var" => {
                send_ok(&mut socket, &id, serde_json::json!({ "value": "203.0.113.7" })).await;
            }
            // Test trigger: push a StasisStart, then ack.
            "test_push_stasis" => {
                let event = serde_json::json!({
                    "type": "event",
                    "event": "StasisStart",
                    "channel": "ch1",
                    "app": APP,
                    "call_id": "call-uuid",
                    "sip_call_id": "sipcid@host",
                    "payload": { "source_ip": "203.0.113.7" }
                });
                let _ = socket.send(Message::Text(event.to_string().into())).await;
                send_ok(&mut socket, &id, serde_json::json!({})).await;
            }
            // Media verbs the server does not implement yet.
            "play" | "dtmf" => {
                send_error(
                    &mut socket,
                    &id,
                    "unsupported_verb",
                    "sip adapter does not implement this verb in this build",
                )
                .await;
            }
            // Test trigger for the typed-error path.
            "boom" => {
                send_error(&mut socket, &id, "not_found", "no such channel").await;
            }
            _ => send_ok(&mut socket, &id, serde_json::json!({})).await,
        }
    }
}

async fn send_ok(socket: &mut WebSocket, id: &str, result: serde_json::Value) {
    let reply = serde_json::json!({ "id": id, "type": "reply", "status": "ok", "result": result });
    let _ = socket.send(Message::Text(reply.to_string().into())).await;
}

async fn send_error(socket: &mut WebSocket, id: &str, code: &str, message: &str) {
    let reply = serde_json::json!({
        "id": id, "type": "reply", "status": "error",
        "error": { "code": code, "message": message }
    });
    let _ = socket.send(Message::Text(reply.to_string().into())).await;
}

fn client_config(addr: SocketAddr) -> ClientConfig {
    let mut config = ClientConfig::new(format!("ws://{addr}/control/ws"), APP, TOKEN);
    config.reply_timeout = Duration::from_secs(3);
    config.reconnect_backoff = Duration::from_millis(50);
    config
}

// ---------------------------------------------------------------------------
// Inbound-mode tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bad_token_is_unauthorized_before_upgrade() {
    let addr = start_stub(Arc::new(Stub::default())).await;
    let mut config = client_config(addr);
    config.token = "wrong".to_string();
    match SipClient::connect(config).await {
        Err(ControlError::Unauthorized { status }) => assert_eq!(status, 401),
        other => panic!("expected Unauthorized, got {other:?}"),
    }
}

#[tokio::test]
async fn hello_then_command_correlates_a_typed_reply() {
    let addr = start_stub(Arc::new(Stub::default())).await;
    let client = SipClient::connect(client_config(addr))
        .await
        .expect("connect + hello");

    // A substrate command round-trips.
    let value = client.describe().await.expect("describe ok");
    assert_eq!(value["adapters"][0]["module"], "sip");
}

#[tokio::test]
async fn generic_core_command_routes_any_module() {
    // The protocol-agnostic core sends `{module, verb, target, args}` for ANY
    // module — no SIP knowledge required.
    let addr = start_stub(Arc::new(Stub::default())).await;
    let client = ControlClient::connect(client_config(addr)).await.unwrap();
    let value = client
        .command(Some("smpp"), "submit_sm", serde_json::Value::Null, serde_json::json!({ "short_message": "hi" }))
        .await
        .expect("generic command ok");
    assert!(value.is_object());
}

#[tokio::test]
async fn error_reply_maps_to_typed_control_error() {
    let addr = start_stub(Arc::new(Stub::default())).await;
    let client = SipClient::connect(client_config(addr)).await.unwrap();

    match client
        .command(Some("sip"), "boom", serde_json::json!({ "channel": "ch1" }), serde_json::json!({}))
        .await
    {
        Err(ControlError::Command { code, message }) => {
            assert_eq!(code, ControlErrorCode::NotFound);
            assert_eq!(message, "no such channel");
        }
        other => panic!("expected Command error, got {other:?}"),
    }
}

#[tokio::test]
async fn stasis_start_dispatches_a_call_and_verbs_round_trip() {
    let addr = start_stub(Arc::new(Stub::default())).await;
    let client = SipClient::connect(client_config(addr)).await.unwrap();
    let mut calls = client.calls();

    // Trigger the stub to push a StasisStart (deterministic, after the stream is
    // registered so there is no dispatch race).
    client
        .command(None, "test_push_stasis", serde_json::Value::Null, serde_json::Value::Null)
        .await
        .unwrap();

    let call = tokio::time::timeout(Duration::from_secs(3), calls.next())
        .await
        .expect("a call should arrive")
        .expect("call present");
    assert_eq!(call.channel_id(), "ch1");
    assert_eq!(call.sip_call_id(), Some("sipcid@host"));
    assert_eq!(call.payload()["source_ip"], "203.0.113.7");
    assert!(!call.is_reattached());

    // The high-level verbs each send + await a correlated reply.
    call.answer().await.expect("answer ok");
    assert_eq!(call.get_header("P-Asserted-Identity").await.unwrap().as_deref(), Some("203.0.113.7"));
    call.transfer("sip:agent@pbx").await.expect("refer ok");

    // A media verb surfaces the server's unsupported_verb as a typed error.
    match call.dtmf("123#").await {
        Err(error) => assert!(error.is_unsupported_verb(), "expected unsupported_verb, got {error:?}"),
        Ok(()) => panic!("dtmf should be unsupported today"),
    }
}

#[tokio::test]
async fn on_call_handler_fires_for_stasis_start() {
    let addr = start_stub(Arc::new(Stub::default())).await;
    let client = SipClient::connect(client_config(addr)).await.unwrap();

    let (fired_tx, fired_rx) = tokio::sync::oneshot::channel();
    let fired_tx = Arc::new(Mutex::new(Some(fired_tx)));
    client.set_call_handler(move |call| {
        let fired_tx = Arc::clone(&fired_tx);
        async move {
            call.answer().await?;
            if let Some(sender) = fired_tx.lock().unwrap().take() {
                let _ = sender.send(call.channel_id().to_string());
            }
            Ok(())
        }
    });

    client
        .command(None, "test_push_stasis", serde_json::Value::Null, serde_json::Value::Null)
        .await
        .unwrap();

    let channel = tokio::time::timeout(Duration::from_secs(3), fired_rx)
        .await
        .expect("handler should fire")
        .expect("channel id");
    assert_eq!(channel, "ch1");
}

#[tokio::test]
async fn reconnect_resyncs_and_reattaches_owned_calls() {
    let stub = Arc::new(Stub {
        close_first_after_hello: true,
        ..Default::default()
    });
    *stub.resync_channels.lock().unwrap() = vec![serde_json::json!({
        "channel": "ch-live",
        "call_id": "call-uuid",
        "sip_call_id": "sipcid@h",
        "state": "answered",
        "vars": { "queue": "support" }
    })];
    let addr = start_stub(Arc::clone(&stub)).await;

    let client = Arc::new(SipClient::connect(client_config(addr)).await.unwrap());
    let mut calls = client.calls();

    // Drive the supervised loop: it reconnects after the stub drops conn 0 and
    // re-attaches the owned channel via resync.
    let driver = Arc::clone(&client);
    tokio::spawn(async move {
        let _ = driver.run().await;
    });

    let call = tokio::time::timeout(Duration::from_secs(5), calls.next())
        .await
        .expect("a reattached call should arrive")
        .expect("call present");
    assert_eq!(call.channel_id(), "ch-live");
    assert!(call.is_reattached(), "resync-delivered calls are reattached");
    assert!(stub.conn_count.load(Ordering::SeqCst) >= 2, "the client reconnected");

    client.shutdown();
}

// ---------------------------------------------------------------------------
// Per-call-connect (ControlServer) tests — siphon dials the app.
// ---------------------------------------------------------------------------

/// Simulate siphon dialing the app: connect as a WS client presenting the token
/// and subprotocol, then push StasisStart and service the one command the
/// handler sends.
async fn dial_as_siphon(
    addr: SocketAddr,
    token: &str,
) -> Result<
    tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    tokio_tungstenite::tungstenite::Error,
> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::http::HeaderValue;
    let mut request = format!("ws://{addr}/siphon").into_client_request().unwrap();
    let headers = request.headers_mut();
    headers.insert(
        "Authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    );
    headers.insert(
        "Sec-WebSocket-Protocol",
        HeaderValue::from_static("siphon-control.v1"),
    );
    let (socket, _response) = tokio_tungstenite::connect_async(request).await?;
    Ok(socket)
}

#[tokio::test]
async fn per_call_connect_bad_token_is_rejected() {
    let config = ServerConfig::new("127.0.0.1:0".parse().unwrap(), APP, TOKEN);
    let server = Arc::new(SipServer::bind(config).await.unwrap());
    let addr = server.local_addr().unwrap();
    let driver = Arc::clone(&server);
    tokio::spawn(async move {
        let _ = driver.run().await;
    });

    match dial_as_siphon(addr, "wrong").await {
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
            assert_eq!(response.status(), 401);
        }
        other => panic!("expected HTTP 401, got {other:?}"),
    }
}

#[tokio::test]
async fn per_call_connect_owns_the_dialed_call_and_verbs_round_trip() {
    let config = ServerConfig::new("127.0.0.1:0".parse().unwrap(), APP, TOKEN);
    let server = SipServer::bind(config).await.unwrap();
    let addr = server.local_addr().unwrap();
    let mut calls = server.calls();
    let server = Arc::new(server);
    let driver = Arc::clone(&server);
    tokio::spawn(async move {
        let _ = driver.run().await;
    });

    // siphon dials in and pushes StasisStart (ownership) as its first frame.
    let mut siphon = dial_as_siphon(addr, TOKEN).await.expect("dial accepted");
    let stasis = serde_json::json!({
        "type": "event", "event": "StasisStart",
        "channel": "ch-out", "app": APP,
        "call_id": "call-uuid", "sip_call_id": "sipcid@out",
        "payload": { "from": "sip:alice@example.com" }
    });
    siphon
        .send(tokio_tungstenite::tungstenite::Message::Text(stasis.to_string().into()))
        .await
        .unwrap();

    // The accepting socket owns the call — it surfaces on the stream.
    let call = tokio::time::timeout(Duration::from_secs(3), calls.next())
        .await
        .expect("dialed call arrives")
        .expect("call present");
    assert_eq!(call.channel_id(), "ch-out");
    assert_eq!(call.sip_call_id(), Some("sipcid@out"));

    // Drive a verb; siphon (this stub) receives the command and replies ok.
    let answer_task = tokio::spawn(async move { call.answer().await });

    let command = next_text_frame(&mut siphon).await;
    assert_eq!(command["type"], "command");
    assert_eq!(command["verb"], "answer");
    assert_eq!(command["module"], "sip");
    assert_eq!(command["target"]["channel"], "ch-out");
    let id = command["id"].as_str().unwrap();
    let reply = serde_json::json!({ "id": id, "type": "reply", "status": "ok", "result": { "state": "answered" } });
    siphon
        .send(tokio_tungstenite::tungstenite::Message::Text(reply.to_string().into()))
        .await
        .unwrap();

    answer_task.await.unwrap().expect("answer ok");
}

async fn next_text_frame(
    socket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> serde_json::Value {
    loop {
        let message = tokio::time::timeout(Duration::from_secs(3), socket.next())
            .await
            .expect("frame within timeout")
            .expect("stream open")
            .expect("no ws error");
        if let tokio_tungstenite::tungstenite::Message::Text(text) = message {
            return serde_json::from_str(text.as_str()).unwrap();
        }
    }
}
