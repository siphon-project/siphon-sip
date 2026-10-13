//! The node's call **scope** on a siphon-rtp engine it shares with other nodes.
//!
//! A SIP proxy does not change the `Call-ID`, so every function that anchors
//! media on one call path names its engine call by the same id: a P-CSCF, a
//! BGCF on breakout, an MRF playing into the call, an application server acting
//! as a B2BUA. On one engine they would meet in one call. From 0.14.0 the engine
//! keys a call by `(scope, call_id)`, so each node names its own scope
//! (`media.siphon_rtp.scope`) and they stay separate calls.
//!
//! On the wire the scope is one more top-level key of a request, beside `id`
//! and `command`, on every verb that names a call, and of an event, beside
//! `event`. Left unset, no frame carries it and every frame is byte for byte
//! what it was before. The engine's own envelope type is not used here: it
//! arrived after the protocol release this crate builds against, and the key
//! is a single string beside the frame.
//!
//! A scope is a name, not a credential: any client of the engine may name any
//! scope. It separates functions that cooperate on one engine; it does not
//! protect one from another.

use std::fmt;

use serde::{Deserialize, Serialize};
use siphon_rtp_proto::{frame, CmdResult, Command, ProtoError, Request};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use super::connection::handshake;
use super::result_kind;
use crate::rtpengine::error::RtpEngineError;

/// The configuration key a scope is read from, named in every refusal.
const SCOPE_KEY: &str = "media.siphon_rtp.scope";

/// The longest scope the engine accepts, in bytes.
const MAX_SCOPE_LENGTH: usize = 64;

/// What an engine that keys calls by scope lists in `node_info.features`.
const SCOPE_FEATURE: &str = "scope";

/// A scope the engine accepts: 1 to 64 bytes of ASCII letters, digits, `-` and
/// `_`, the set the engine validates on every frame.
///
/// Checked when the configuration is read, so a node with a scope the engine
/// would refuse fails at start instead of having every call refused.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct CallScope(String);

impl CallScope {
    /// The scope as it goes on the wire.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for CallScope {
    type Error = String;

    fn try_from(scope: String) -> Result<Self, Self::Error> {
        // Empty is refused rather than read as unscoped, which is what the
        // engine makes of it: a key that is present but empty is almost always
        // an environment variable that was not set, and an unscoped node on a
        // shared engine is exactly what the key is there to prevent.
        if scope.is_empty() {
            return Err(format!(
                "{SCOPE_KEY} is empty; leave the key out for an unscoped node"
            ));
        }
        if scope.len() > MAX_SCOPE_LENGTH {
            return Err(format!(
                "{SCOPE_KEY} is {} bytes; the maximum is {MAX_SCOPE_LENGTH}",
                scope.len()
            ));
        }
        let allowed = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_';
        if !scope.bytes().all(allowed) {
            return Err(format!(
                "{SCOPE_KEY} may hold only ASCII letters, digits, '-' and '_', got {scope:?}"
            ));
        }
        Ok(Self(scope))
    }
}

impl fmt::Display for CallScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A request with the node's scope beside its `id` and `command`.
#[derive(Serialize)]
struct ScopedRequest<'a> {
    scope: &'a str,
    #[serde(flatten)]
    request: &'a Request,
}

/// Whether `command` addresses a call, and so carries the node's scope.
///
/// Spelled as the verbs that do **not**, so a verb added later is scoped by
/// default: a call verb sent without the scope would silently address the
/// unscoped call, while a scope on a verb that takes none is refused by the
/// engine, loudly. `list` is scoped: the engine answers with the calls of the
/// frame's scope, and a reap must see this node's. The conference verbs name a
/// room, not a call, and the engine refuses a scope on them.
fn carries_scope(command: &Command) -> bool {
    !matches!(
        command,
        Command::Ping
            | Command::Authenticate { .. }
            | Command::NodeInfo
            | Command::Statistics
            | Command::Load
            | Command::Drain
            | Command::Undrain
            | Command::Restore { .. }
            | Command::ConferenceJoin { .. }
            | Command::ConferenceLeave { .. }
            | Command::ConferenceRoute { .. }
            | Command::ConferenceBridge { .. }
            | Command::ConferencePlay { .. }
            | Command::ConferenceStopPlay { .. }
            | Command::ConferenceSetPlayGain { .. }
            | Command::ConferenceStartRecording { .. }
            | Command::ConferenceStopRecording { .. }
    )
}

/// Frame `request`, with `scope` on it when there is one and the verb names a
/// call. Without a scope this is the plain frame, the bytes every earlier
/// release wrote.
pub(super) fn encode_request(
    scope: Option<&CallScope>,
    request: &Request,
) -> Result<Vec<u8>, ProtoError> {
    match scope {
        Some(scope) if carries_scope(&request.command) => frame::encode(&ScopedRequest {
            scope: scope.as_str(),
            request,
        }),
        _ => frame::encode(request),
    }
}

/// Whether an event frame may belong to this node.
///
/// An event for a scoped call carries the scope it was anchored under, so one
/// that names another scope is never this node's, whatever its Call-ID. An
/// event with no scope passes on a scoped node too: conference verbs take no
/// scope, so a room this node seated raises unscoped events (its DTMF names the
/// room in `call_id`, its playback end carries an empty one), and the engine
/// sends those only to the client that created the room.
pub(super) fn event_is_for(scope: Option<&CallScope>, event: &serde_json::Value) -> bool {
    match event
        .get("scope")
        .and_then(serde_json::Value::as_str)
        .filter(|event_scope| !event_scope.is_empty())
    {
        None => true,
        Some(event_scope) => Some(event_scope) == scope.map(CallScope::as_str),
    }
}

/// Ask a fresh connection's engine whether it keys calls by scope, and refuse
/// the connection when it does not.
///
/// An engine before 0.14.0 reads a scoped frame as an unscoped one, silently,
/// so a scoped node on it would share calls with every other node using the
/// same Call-ID. The engine's documentation asks a controller to check
/// `node_info` once per connection before relying on scopes; this is that check.
pub(super) async fn require_scope_support(
    write_half: &mut OwnedWriteHalf,
    read_half: &mut OwnedReadHalf,
    buffer: &mut Vec<u8>,
    scope: &CallScope,
    timeout_ms: u64,
) -> Result<(), RtpEngineError> {
    let result = handshake(
        write_half,
        read_half,
        buffer,
        "node_info",
        Command::NodeInfo,
        timeout_ms,
    )
    .await?;
    match result {
        CmdResult::NodeInfo { node }
            if node.features.iter().any(|feature| feature == SCOPE_FEATURE) =>
        {
            Ok(())
        }
        CmdResult::NodeInfo { node } => Err(RtpEngineError::Protocol(format!(
            "{SCOPE_KEY} is {scope:?} but the engine (version {}) does not list \
             '{SCOPE_FEATURE}' in node_info features; scopes need siphon-rtp 0.14.0 \
             or later, and an older engine would anchor this node's calls unscoped",
            node.version
        ))),
        CmdResult::Error { reason } => Err(RtpEngineError::EngineError(format!(
            "node_info refused while checking {SCOPE_KEY}: {reason}"
        ))),
        other => Err(RtpEngineError::Protocol(format!(
            "unexpected '{}' response for node_info",
            result_kind(&other)
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use serde_json::{json, Value};
    use siphon_rtp_proto::{frame, X3TargetLeg};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;

    use super::super::SiphonRtpClient;
    use super::{carries_scope, encode_request, event_is_for, CallScope};
    use crate::rtpengine::client::PlayMediaSource;
    use crate::rtpengine::error::RtpEngineError;
    use crate::rtpengine::events::{
        RecordingChannels, RecordingDirection, RecordingRequest, RtpEngineEvent,
    };
    use crate::rtpengine::profile::{NgFlags, WsTeeDirection};
    use siphon_rtp_proto::{Command, ConferenceRole, Request};

    /// What the fake engine knows about one call: the connection that created it
    /// and the relay port it was given, so a test can tell two calls apart.
    struct FakeCall {
        owner: usize,
        port: u16,
    }

    /// State shared by every connection of one fake engine.
    #[derive(Default)]
    struct FakeEngineState {
        /// Calls keyed the way the engine keys them: `(scope, call_id)`.
        calls: HashMap<(Option<String>, String), FakeCall>,
        /// Outgoing event frames, per connection.
        connections: HashMap<usize, mpsc::UnboundedSender<Value>>,
        next_connection: usize,
        next_port: u16,
        /// What `node_info` lists in `features`.
        features: Vec<String>,
    }

    /// A siphon-rtp engine inside the test process that keys calls by
    /// `(scope, call_id)` the way the engine's control documentation describes
    /// it, and reads every request as raw JSON rather than through the proto
    /// types, so what it sees is what siphon wrote.
    struct FakeEngine {
        address: SocketAddr,
        state: Arc<Mutex<FakeEngineState>>,
        /// `(connection, raw request body)` for every frame received.
        captured: mpsc::UnboundedReceiver<(usize, String)>,
    }

    /// The `scope` a frame names: absent and empty both mean unscoped.
    fn frame_scope(frame: &Value) -> Option<String> {
        frame
            .get("scope")
            .and_then(Value::as_str)
            .filter(|scope| !scope.is_empty())
            .map(str::to_string)
    }

    fn ok(id: u64) -> Value {
        json!({"id": id, "result": "ok"})
    }

    /// Answer one request the way the engine would.
    fn answer(state: &Mutex<FakeEngineState>, connection: usize, request: &Value) -> Value {
        let id = request
            .get("id")
            .and_then(Value::as_u64)
            .unwrap_or(u64::MAX);
        let command = request.get("command").and_then(Value::as_str).unwrap_or("");
        let scope = frame_scope(request);
        let call_id = request
            .get("call_id")
            .and_then(Value::as_str)
            .map(str::to_string);
        let mut state = state.lock().expect("fake engine state");
        match (command, call_id) {
            ("ping", _) => json!({"id": id, "result": "pong"}),
            ("node_info", _) => json!({
                "id": id,
                "result": "node_info",
                "node": {
                    "node_id": "engine-1",
                    "version": "0.14.0",
                    "media_addresses": ["192.0.2.10"],
                    "codecs": ["PCMU"],
                    "features": state.features,
                    "max_sessions": 0,
                    "draining": false,
                },
            }),
            ("authenticate", _) => ok(id),
            // The engine refuses a scope on a room verb rather than drop it.
            (room, _) if room.starts_with("conference_") => match scope {
                Some(_) => {
                    json!({"id": id, "result": "error", "reason": "scope on a conference verb"})
                }
                None if room == "conference_join" => {
                    json!({"id": id, "result": "ok", "sdp": "m=audio 31000 RTP/AVP 0\r\n"})
                }
                None => ok(id),
            },
            ("list", _) => {
                let call_ids: Vec<&String> = state
                    .calls
                    .iter()
                    .filter(|((call_scope, _), call)| {
                        call.owner == connection && *call_scope == scope
                    })
                    .map(|((_, call_id), _)| call_id)
                    .collect();
                json!({"id": id, "result": "list", "call_ids": call_ids})
            }
            ("offer" | "answer_local", Some(call_id)) => {
                state.next_port += 2;
                let port = 30_000 + state.next_port;
                state.calls.insert(
                    (scope, call_id),
                    FakeCall {
                        owner: connection,
                        port,
                    },
                );
                json!({"id": id, "result": "ok", "sdp": format!("m=audio {port} RTP/AVP 0\r\n")})
            }
            (_, Some(call_id)) => {
                let key = (scope.clone(), call_id.clone());
                let Some(call) = state.calls.get(&key) else {
                    let named = match &scope {
                        Some(scope) => format!("{call_id} (scope {scope})"),
                        None => call_id,
                    };
                    return json!({"id": id, "result": "error", "reason": format!("unknown call: {named}")});
                };
                let port = call.port;
                match command {
                    "delete" => {
                        state.calls.remove(&key);
                        ok(id)
                    }
                    "reoffer" | "answer" | "subscribe_request" | "subscribe_answer" => {
                        json!({"id": id, "result": "ok", "sdp": format!("m=audio {port} RTP/AVP 0\r\n")})
                    }
                    "play_media" => json!({"id": id, "result": "ok", "play_id": port}),
                    "start_recording" => {
                        json!({"id": id, "result": "ok", "recording_id": format!("rec-{port}")})
                    }
                    _ => ok(id),
                }
            }
            _ => json!({"id": id, "result": "error", "reason": format!("unsupported: {command}")}),
        }
    }

    impl FakeEngine {
        /// An engine that keys calls by scope and says so in `node_info`.
        async fn start() -> Self {
            Self::with_features(&["relay", "transcode", "scope"]).await
        }

        async fn with_features(features: &[&str]) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let address = listener.local_addr().expect("address");
            let state = Arc::new(Mutex::new(FakeEngineState {
                features: features.iter().map(|feature| feature.to_string()).collect(),
                ..FakeEngineState::default()
            }));
            let (capture_tx, captured) = mpsc::unbounded_channel();
            let accept_state = Arc::clone(&state);
            tokio::spawn(async move {
                while let Ok((mut stream, _)) = listener.accept().await {
                    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<Value>();
                    let connection = {
                        let mut state = accept_state.lock().expect("fake engine state");
                        state.next_connection += 1;
                        let connection = state.next_connection;
                        state.connections.insert(connection, event_tx);
                        connection
                    };
                    let state = Arc::clone(&accept_state);
                    let capture_tx = capture_tx.clone();
                    tokio::spawn(async move {
                        let mut buffer = Vec::new();
                        let mut chunk = [0u8; 8192];
                        loop {
                            while let Ok(Some((request, consumed))) =
                                frame::decode::<Value>(&buffer)
                            {
                                let body =
                                    String::from_utf8_lossy(&buffer[frame::HEADER_LEN..consumed])
                                        .into_owned();
                                buffer.drain(..consumed);
                                let _ = capture_tx.send((connection, body));
                                let response = answer(&state, connection, &request);
                                let bytes = frame::encode(&response).expect("encode");
                                if stream.write_all(&bytes).await.is_err() {
                                    return;
                                }
                            }
                            tokio::select! {
                                read = stream.read(&mut chunk) => match read {
                                    Ok(0) | Err(_) => return,
                                    Ok(read) => buffer.extend_from_slice(&chunk[..read]),
                                },
                                Some(event) = event_rx.recv() => {
                                    let bytes = frame::encode(&event).expect("encode");
                                    if stream.write_all(&bytes).await.is_err() {
                                        return;
                                    }
                                }
                            }
                        }
                    });
                }
            });
            Self {
                address,
                state,
                captured,
            }
        }

        /// Every frame received so far, waiting briefly for stragglers.
        async fn frames(&mut self) -> Vec<String> {
            let mut frames = Vec::new();
            while let Ok(Some((_, body))) =
                tokio::time::timeout(Duration::from_millis(200), self.captured.recv()).await
            {
                frames.push(body);
            }
            frames
        }

        /// The relay port of a call the engine holds under `(scope, call_id)`.
        fn port_of(&self, scope: Option<&str>, call_id: &str) -> Option<u16> {
            let state = self.state.lock().expect("fake engine state");
            state
                .calls
                .get(&(scope.map(str::to_string), call_id.to_string()))
                .map(|call| call.port)
        }

        /// Emit `media_timeout` for a call the way the engine does: to the
        /// connection that created it, carrying its scope as a top-level key.
        fn time_out(&self, scope: Option<&str>, call_id: &str) {
            let state = self.state.lock().expect("fake engine state");
            let call = state
                .calls
                .get(&(scope.map(str::to_string), call_id.to_string()))
                .expect("the engine holds the call");
            let mut event = json!({
                "event": "media_timeout",
                "call_id": call_id,
                "from_tag": "tag-a",
                "reason": "no_media",
            });
            if let Some(scope) = scope {
                event["scope"] = json!(scope);
            }
            state.connections[&call.owner]
                .send(event)
                .expect("connection open");
        }

        /// Send a raw event frame to every connection, whoever created the call.
        fn broadcast(&self, event: Value) {
            let state = self.state.lock().expect("fake engine state");
            for sender in state.connections.values() {
                let _ = sender.send(event.clone());
            }
        }
    }

    /// Drive every command the client implements that names a call, in order,
    /// on `call-1`. Results are ignored: what is under test is the frame.
    async fn drive_every_call_command(client: &SiphonRtpClient) {
        let flags = NgFlags::default();
        let _ = client.offer("call-1", "tag-a", b"v=0\r\n", &flags).await;
        let _ = client.reoffer("call-1", "tag-a", b"v=0\r\n", &flags).await;
        let _ = client
            .answer("call-1", "tag-a", "tag-b", b"v=0\r\n", &flags)
            .await;
        let _ = client
            .play_media(
                "call-1",
                "tag-a",
                &PlayMediaSource::Tone("ringback".into()),
                None,
                None,
                None,
                None,
                false,
                None,
                false,
            )
            .await;
        let _ = client.stop_media("call-1", "tag-a", Some(7)).await;
        let _ = client.set_play_gain("call-1", "tag-a", 7, -6, None).await;
        let _ = client
            .play_dtmf("call-1", "tag-a", "5", None, None, None, None)
            .await;
        let _ = client.silence_media("call-1", "tag-a").await;
        let _ = client.unsilence_media("call-1", "tag-a").await;
        let _ = client.echo("call-1", "tag-a", true).await;
        let _ = client.block_media("call-1", "tag-a").await;
        let _ = client.unblock_media("call-1", "tag-a").await;
        let _ = client
            .start_recording(
                "call-1",
                "tag-a",
                &RecordingRequest {
                    direction: RecordingDirection::Both,
                    channels: RecordingChannels::Mono,
                    max_duration_ms: None,
                    silence_ms: None,
                    path: None,
                },
            )
            .await;
        let _ = client.stop_recording("call-1", "tag-a", None).await;
        let _ = client
            .subscribe_request("call-1", "tag-a", "tag-b", None, &flags)
            .await;
        let _ = client
            .subscribe_request_siprec("call-1", &["tag-a", "tag-b"], None)
            .await;
        let _ = client
            .subscribe_answer("call-1", "tag-s", "tag-t", b"v=0\r\n", &flags)
            .await;
        let _ = client.unsubscribe("call-1", "tag-s", "tag-t").await;
        let _ = client
            .attach_ws_tee(
                "call-1",
                "tag-a",
                "ws://tee.example.com/s",
                WsTeeDirection::Both,
                None,
                None,
            )
            .await;
        let _ = client.detach_ws_tee("call-1", "tag-a").await;
        let _ = client
            .attach_ws_bridge("call-1", "tag-a", "ws://bridge.example.com/s", None)
            .await;
        let _ = client.detach_ws_bridge("call-1", "tag-a").await;
        let _ = client
            .attach_x3(
                "call-1",
                "tag-a",
                "192.0.2.50:42069",
                [0x11; 16],
                9,
                X3TargetLeg::Caller,
            )
            .await;
        let _ = client.detach_x3("call-1", "tag-a").await;
        let _ = client.list().await;
        let _ = client.delete("call-1", "tag-a").await;
        let _ = client
            .answer_local("call-1", "tag-a", "v=0\r\n", &flags)
            .await;
        let _ = client.delete_call("call-1").await;
        let _ = client.ping().await;
    }

    /// The frames an unscoped node sends, recorded on the client as it was
    /// before scopes existed. A node without `media.siphon_rtp.scope` must keep
    /// sending exactly these bytes.
    const RECORDED_UNSCOPED_FRAMES: &[&str] = &[
        r#"{"id":1,"command":"offer","call_id":"call-1","from_tag":"tag-a","sdp":"v=0\r\n","profile":{}}"#,
        r#"{"id":2,"command":"reoffer","call_id":"call-1","from_tag":"tag-a","sdp":"v=0\r\n","profile":{}}"#,
        r#"{"id":3,"command":"answer","call_id":"call-1","from_tag":"tag-a","to_tag":"tag-b","sdp":"v=0\r\n","profile":{}}"#,
        r#"{"id":4,"command":"play_media","call_id":"call-1","from_tag":"tag-a","source":{"source":"tone","tone":"ringback"}}"#,
        r#"{"id":5,"command":"stop_media","call_id":"call-1","from_tag":"tag-a","play_id":7}"#,
        r#"{"id":6,"command":"set_play_gain","call_id":"call-1","from_tag":"tag-a","play_id":7,"gain_decibels":-6}"#,
        r#"{"id":7,"command":"play_dtmf","call_id":"call-1","from_tag":"tag-a","code":"5"}"#,
        r#"{"id":8,"command":"silence_media","call_id":"call-1","from_tag":"tag-a"}"#,
        r#"{"id":9,"command":"unsilence_media","call_id":"call-1","from_tag":"tag-a"}"#,
        r#"{"id":10,"command":"echo","call_id":"call-1","from_tag":"tag-a","enabled":true}"#,
        r#"{"id":11,"command":"block_media","call_id":"call-1","from_tag":"tag-a"}"#,
        r#"{"id":12,"command":"unblock_media","call_id":"call-1","from_tag":"tag-a"}"#,
        r#"{"id":13,"command":"start_recording","call_id":"call-1","from_tag":"tag-a","format":"wav","direction":"both","channels":"mono"}"#,
        r#"{"id":14,"command":"stop_recording","call_id":"call-1","from_tag":"tag-a"}"#,
        r#"{"id":15,"command":"subscribe_request","call_id":"call-1","from_tags":["tag-a"],"profile":{}}"#,
        r#"{"id":16,"command":"subscribe_request","call_id":"call-1","from_tags":["tag-a","tag-b"],"profile":{}}"#,
        r#"{"id":17,"command":"subscribe_answer","call_id":"call-1","from_tag":"tag-s","to_tag":"tag-t","sdp":"v=0\r\n","profile":{}}"#,
        r#"{"id":18,"command":"unsubscribe","call_id":"call-1","from_tag":"tag-s","to_tag":"tag-t"}"#,
        r#"{"id":19,"command":"attach_ws_tee","call_id":"call-1","from_tag":"tag-a","ws_uri":"ws://tee.example.com/s","direction":"both"}"#,
        r#"{"id":20,"command":"detach_ws_tee","call_id":"call-1","from_tag":"tag-a"}"#,
        r#"{"id":21,"command":"attach_ws_bridge","call_id":"call-1","from_tag":"tag-a","ws_uri":"ws://bridge.example.com/s"}"#,
        r#"{"id":22,"command":"detach_ws_bridge","call_id":"call-1","from_tag":"tag-a"}"#,
        r#"{"id":23,"command":"attach_x3","call_id":"call-1","from_tag":"tag-a","delivery":"192.0.2.50:42069","xid":"11111111-1111-1111-1111-111111111111","correlation_id":9,"target_leg":"caller"}"#,
        r#"{"id":24,"command":"detach_x3","call_id":"call-1","from_tag":"tag-a"}"#,
        r#"{"id":25,"command":"list"}"#,
        r#"{"id":26,"command":"delete","call_id":"call-1","from_tag":"tag-a"}"#,
        r#"{"id":27,"command":"answer_local","call_id":"call-1","from_tag":"tag-a","sdp":"v=0\r\n","profile":{}}"#,
        r#"{"id":28,"command":"delete","call_id":"call-1","from_tag":""}"#,
        r#"{"id":29,"command":"ping"}"#,
    ];

    #[tokio::test]
    async fn an_unscoped_node_sends_the_frames_it_always_sent() {
        let mut engine = FakeEngine::start().await;
        let (event_tx, _event_rx) = mpsc::channel::<RtpEngineEvent>(16);
        let client = SiphonRtpClient::new(engine.address, None, 2_000, 5_000, event_tx);
        drive_every_call_command(&client).await;
        assert_eq!(engine.frames().await, RECORDED_UNSCOPED_FRAMES);
    }

    /// `frame` as a scoped node writes it: the same frame with `scope` as one
    /// more top-level key, the shape the engine's control documentation gives.
    fn with_scope(frame: &str, scope: &str) -> String {
        format!(r#"{{"scope":"{scope}",{}"#, &frame[1..])
    }

    fn client(
        engine: &FakeEngine,
        scope: Option<&str>,
        timeout_ms: u64,
    ) -> (Arc<SiphonRtpClient>, mpsc::Receiver<RtpEngineEvent>) {
        let (event_tx, event_rx) = mpsc::channel::<RtpEngineEvent>(16);
        let scope = scope.map(|scope| CallScope::try_from(scope.to_string()).expect("valid"));
        let client =
            SiphonRtpClient::with_scope(engine.address, None, scope, timeout_ms, 5_000, event_tx);
        (client, event_rx)
    }

    /// The next event a node receives, or `None` when none arrives in 300 ms.
    async fn next_event(events: &mut mpsc::Receiver<RtpEngineEvent>) -> Option<RtpEngineEvent> {
        tokio::time::timeout(Duration::from_millis(300), events.recv())
            .await
            .ok()
            .flatten()
    }

    #[tokio::test]
    async fn a_scoped_node_puts_its_scope_on_every_frame_that_names_a_call() {
        let mut engine = FakeEngine::start().await;
        let (client, _events) = client(&engine, Some("bgcf"), 2_000);
        drive_every_call_command(&client).await;

        let mut expected = vec![r#"{"id":0,"command":"node_info"}"#.to_string()];
        expected.extend(RECORDED_UNSCOPED_FRAMES.iter().map(|frame| {
            if *frame == r#"{"id":29,"command":"ping"}"# {
                // Liveness names no call; the frame stays as it was.
                frame.to_string()
            } else {
                with_scope(frame, "bgcf")
            }
        }));
        assert_eq!(engine.frames().await, expected);
    }

    #[test]
    fn a_scope_is_what_the_engine_accepts() {
        for scope in [
            "pcscf-orig".to_string(),
            "pcscf_term".to_string(),
            "bgcf".to_string(),
            "MRF2".to_string(),
            "a".repeat(64),
        ] {
            let parsed = CallScope::try_from(scope.clone()).expect("accepted");
            assert_eq!(parsed.as_str(), scope);
        }
    }

    #[test]
    fn a_scope_the_engine_would_refuse_is_refused_naming_the_key() {
        let too_long = CallScope::try_from("a".repeat(65)).expect_err("65 bytes");
        assert_eq!(
            too_long,
            "media.siphon_rtp.scope is 65 bytes; the maximum is 64"
        );
        let empty = CallScope::try_from(String::new()).expect_err("empty");
        assert!(
            empty.starts_with("media.siphon_rtp.scope is empty"),
            "{empty}"
        );
        for scope in ["a b", "a/b", "a.b", "a\u{1f}b", "caf\u{e9}", "a\n", "a:b"] {
            let refused = CallScope::try_from(scope.to_string()).expect_err(scope);
            assert!(
                refused.starts_with("media.siphon_rtp.scope may hold only ASCII letters"),
                "{refused}"
            );
        }
    }

    /// A scoped node seats a room with the frame the engine accepts, without a
    /// scope, through the client's one room helper; the room's events reach it.
    #[tokio::test]
    async fn a_scoped_node_seats_a_room_without_a_scope_and_hears_the_room() {
        let mut engine = FakeEngine::start().await;
        let (client, mut events) = client(&engine, Some("mrf"), 2_000);
        client
            .conference_join(
                "room-1",
                "alice",
                "v=0\r\n",
                ConferenceRole::Talker,
                &NgFlags::default(),
            )
            .await
            .expect("seated");
        let frames = engine.frames().await;
        assert_eq!(frames[0], r#"{"id":0,"command":"node_info"}"#);
        let join: Value = serde_json::from_str(&frames[1]).expect("json");
        assert_eq!(join["command"], "conference_join");
        assert_eq!(join["conference_id"], "room-1");
        assert!(join.get("scope").is_none(), "{join}");

        engine.broadcast(json!({
            "event": "dtmf", "call_id": "room-1", "from_tag": "alice",
            "digit": "5", "duration_ms": 80, "volume": -10,
        }));
        match next_event(&mut events).await {
            Some(RtpEngineEvent::Dtmf(dtmf)) => assert_eq!(dtmf.call_id, "room-1"),
            other => panic!("expected the room's DTMF, got {other:?}"),
        }
    }

    /// On a scoped set a room still follows its first seat (its affinity key
    /// starts with U+001F, which no Call-ID holds), while calls carry the scope.
    #[tokio::test]
    async fn a_scoped_set_keeps_a_room_on_one_instance_and_scopes_its_calls() {
        let mut first = FakeEngine::start().await;
        let mut second = FakeEngine::start().await;
        let (event_tx, _events) = mpsc::channel::<RtpEngineEvent>(16);
        let set = super::super::SiphonRtpClientSet::with_scope(
            vec![(first.address, 2_000, 1), (second.address, 2_000, 1)],
            None,
            Some(CallScope::try_from("mrf".to_string()).expect("valid")),
            5_000,
            event_tx,
        )
        .expect("set");
        for tag in ["alice", "bob", "carol"] {
            set.conference_join(
                "room-1",
                tag,
                "v=0\r\n",
                ConferenceRole::Talker,
                &NgFlags::default(),
            )
            .await
            .expect("seated");
        }
        set.conference_leave("room-1", "bob").await.expect("left");
        set.offer("call-1", "tag-a", b"v=0\r\n", &NgFlags::default())
            .await
            .expect("offer");

        let mut room_frames = 0;
        let mut offers = Vec::new();
        for engine in [&mut first, &mut second] {
            let frames: Vec<Value> = engine
                .frames()
                .await
                .iter()
                .map(|frame| serde_json::from_str(frame).expect("json"))
                .collect();
            let room: Vec<&Value> = frames
                .iter()
                .filter(|frame| {
                    frame["command"]
                        .as_str()
                        .is_some_and(|command| command.starts_with("conference_"))
                })
                .collect();
            assert!(room.iter().all(|frame| frame.get("scope").is_none()));
            assert!(
                room.is_empty() || room.len() == 4,
                "one instance holds the room"
            );
            room_frames += room.len();
            offers.extend(
                frames
                    .into_iter()
                    .filter(|frame| frame["command"] == "offer"),
            );
        }
        assert_eq!(room_frames, 4);
        assert_eq!(offers.len(), 1);
        assert_eq!(offers[0]["scope"], "mrf");
    }

    /// The engine refuses a scope on a `conference_*` verb (a room is named by
    /// its own id, not a Call-ID) and on the verbs that name no call, so a
    /// scoped node sends those as before. Every conference verb is listed by
    /// name in `carries_scope`; this pins one on the wire and the rest by kind.
    #[test]
    fn a_scoped_node_sends_conference_and_node_verbs_without_a_scope() {
        let scope = CallScope::try_from("mrf".to_string()).expect("valid");
        let leave = Request {
            id: 4,
            command: Command::ConferenceLeave {
                conference_id: "room-1".into(),
                from_tag: "tag-a".into(),
            },
        };
        let bytes = encode_request(Some(&scope), &leave).expect("encode");
        assert_eq!(
            &bytes[frame::HEADER_LEN..],
            br#"{"id":4,"command":"conference_leave","conference_id":"room-1","from_tag":"tag-a"}"#
        );
        for command in [
            Command::Ping,
            Command::NodeInfo,
            Command::Statistics,
            Command::Load,
            Command::Drain,
            Command::Undrain,
        ] {
            assert!(!carries_scope(&command), "{command:?}");
        }
        assert!(carries_scope(&Command::List));
    }

    #[test]
    fn an_event_is_a_nodes_only_under_its_own_scope() {
        let bgcf = CallScope::try_from("bgcf".to_string()).expect("valid");
        let scoped = json!({"scope": "bgcf", "event": "dtmf", "call_id": "call-1"});
        let other = json!({"scope": "mrf", "event": "dtmf", "call_id": "call-1"});
        let unscoped = json!({"event": "dtmf", "call_id": "call-1"});
        let empty = json!({"scope": "", "event": "dtmf", "call_id": "call-1"});
        let room = json!({"event": "active_speaker", "conference_id": "room-1"});

        let room_dtmf = json!({"event": "dtmf", "call_id": "room-1", "from_tag": "alice"});
        let room_played =
            json!({"event": "play_finished", "call_id": "", "conference_id": "room-1"});

        assert!(event_is_for(Some(&bgcf), &scoped));
        assert!(!event_is_for(Some(&bgcf), &other));
        // A room this node seated raises unscoped events.
        assert!(event_is_for(Some(&bgcf), &unscoped));
        assert!(event_is_for(Some(&bgcf), &empty));
        assert!(event_is_for(Some(&bgcf), &room));
        assert!(event_is_for(Some(&bgcf), &room_dtmf));
        assert!(event_is_for(Some(&bgcf), &room_played));

        assert!(event_is_for(None, &unscoped));
        assert!(event_is_for(None, &empty));
        assert!(!event_is_for(None, &scoped));
        assert!(event_is_for(None, &room));
    }

    /// Two nodes (two clients, two control connections) on one engine, both
    /// anchoring media for one Call-ID: what an on-path P-CSCF and a BGCF see on
    /// one call. Each keeps a call of its own, and each acts only on its own
    /// call's events.
    #[tokio::test]
    async fn two_scoped_nodes_with_one_call_id_keep_separate_calls_and_events() {
        let engine = FakeEngine::start().await;
        let (pcscf, mut pcscf_events) = client(&engine, Some("pcscf"), 2_000);
        let (bgcf, mut bgcf_events) = client(&engine, Some("bgcf"), 2_000);
        let flags = NgFlags::default();

        let pcscf_offer = pcscf
            .offer("call-1", "tag-a", b"v=0\r\n", &flags)
            .await
            .expect("pcscf offer");
        let bgcf_offer = bgcf
            .offer("call-1", "tag-a", b"v=0\r\n", &flags)
            .await
            .expect("bgcf offer");
        assert_ne!(pcscf_offer, bgcf_offer, "two calls, two relay ports");
        let pcscf_port = engine.port_of(Some("pcscf"), "call-1").expect("pcscf call");
        let bgcf_port = engine.port_of(Some("bgcf"), "call-1").expect("bgcf call");
        assert_ne!(pcscf_port, bgcf_port);
        assert_eq!(engine.port_of(None, "call-1"), None, "nothing unscoped");

        // An event goes to the node whose call it is, and only there.
        engine.time_out(Some("pcscf"), "call-1");
        match next_event(&mut pcscf_events).await {
            Some(RtpEngineEvent::MediaTimeout { call_id, .. }) => assert_eq!(call_id, "call-1"),
            other => panic!("expected the pcscf call's media timeout, got {other:?}"),
        }
        assert!(next_event(&mut bgcf_events).await.is_none());

        // One node releasing its call leaves the other's relaying.
        bgcf.delete("call-1", "tag-a").await.expect("bgcf delete");
        assert_eq!(engine.port_of(Some("bgcf"), "call-1"), None);
        assert_eq!(engine.port_of(Some("pcscf"), "call-1"), Some(pcscf_port));
        pcscf
            .answer("call-1", "tag-a", "tag-b", b"v=0\r\n", &flags)
            .await
            .expect("the pcscf call is still there to answer");

        // Even an event that reaches the wrong connection is not acted on: a
        // node never takes another scope's, whatever the Call-ID.
        engine.broadcast(json!({
            "scope": "bgcf", "event": "media_timeout",
            "call_id": "call-1", "from_tag": "tag-a", "reason": "no_media",
        }));
        assert!(next_event(&mut pcscf_events).await.is_none());
        assert!(matches!(
            next_event(&mut bgcf_events).await,
            Some(RtpEngineEvent::MediaTimeout { .. })
        ));
        assert!(next_event(&mut bgcf_events).await.is_none());
    }

    /// An engine before 0.14.0 would read every scoped frame as unscoped, and
    /// the node would share calls without knowing. The connection is refused
    /// instead, so no call is ever anchored on it.
    #[tokio::test]
    async fn a_scoped_node_refuses_an_engine_without_the_scope_feature() {
        let mut engine = FakeEngine::with_features(&["relay", "transcode"]).await;
        let (scoped, _events) = client(&engine, Some("bgcf"), 300);
        let refused = scoped
            .offer("call-1", "tag-a", b"v=0\r\n", &NgFlags::default())
            .await;
        assert!(
            matches!(refused, Err(RtpEngineError::Timeout { .. })),
            "{refused:?}"
        );
        let frames = engine.frames().await;
        assert!(!frames.is_empty());
        assert!(
            frames
                .iter()
                .all(|frame| frame == r#"{"id":0,"command":"node_info"}"#),
            "only the feature check reached the engine: {frames:?}"
        );
        assert_eq!(engine.port_of(None, "call-1"), None);

        // An unscoped node asks nothing and is served as before.
        let (unscoped, _events) = client(&engine, None, 2_000);
        unscoped
            .offer("call-1", "tag-a", b"v=0\r\n", &NgFlags::default())
            .await
            .expect("unscoped offer");
        assert!(engine.port_of(None, "call-1").is_some());
    }

    /// The scope is the node's: every instance of a set carries the same one.
    #[tokio::test]
    async fn every_instance_of_a_scoped_set_carries_the_node_scope() {
        let mut first = FakeEngine::start().await;
        let mut second = FakeEngine::start().await;
        let (event_tx, _events) = mpsc::channel::<RtpEngineEvent>(16);
        let set = super::super::SiphonRtpClientSet::with_scope(
            vec![(first.address, 2_000, 1), (second.address, 2_000, 1)],
            None,
            Some(CallScope::try_from("mrf".to_string()).expect("valid")),
            5_000,
            event_tx,
        )
        .expect("set");
        for call_id in ["call-1", "call-2"] {
            set.offer(call_id, "tag-a", b"v=0\r\n", &NgFlags::default())
                .await
                .expect("offer");
        }
        for engine in [&mut first, &mut second] {
            let frames = engine.frames().await;
            assert_eq!(frames[0], r#"{"id":0,"command":"node_info"}"#);
            assert_eq!(frames.len(), 2, "{frames:?}");
            assert!(frames[1].starts_with(r#"{"scope":"mrf","id":1,"command":"offer""#));
        }
    }
}
