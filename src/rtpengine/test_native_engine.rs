//! A siphon-rtp media engine speaking the native protocol inside the test
//! process.
//!
//! [`super::test_engine::TestEngine`] speaks the rtpengine NG protocol, which
//! has no `answer_local`: an offerless originate is only served by the native
//! backend, so a test that drives one end to end points a [`MediaBackend`] at
//! this engine. It answers `answer_local` with [`NATIVE_ENGINE_ANSWER`], pings
//! with a pong and everything else with a bare `ok`, and records the call-id and
//! tag of every media command it is sent.
//!
//! It keeps the calls it holds the way the real engine does: `answer_local` and
//! `offer` create one, `delete` ends it, and an `answer`, `reoffer`,
//! `play_media`, `stop_media` or `delete` on a call it does not hold is refused
//! with the engine's own `unknown call: <call-id>`. A test that deletes a
//! session too early therefore sees the refusal a deployment would.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use siphon_rtp_proto::{frame, CmdResult, Command, Request, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::MediaBackend;

/// The SDP answer the engine returns for every `answer_local`: its own address,
/// so a test can tell the engine's answer from any SDP a peer sent.
pub(crate) const NATIVE_ENGINE_ANSWER: &str = concat!(
    "v=0\r\n",
    "o=- 7 7 IN IP4 203.0.113.60\r\n",
    "s=-\r\n",
    "c=IN IP4 203.0.113.60\r\n",
    "t=0 0\r\n",
    "m=audio 51000 RTP/AVP 0 101\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
    "a=rtpmap:101 telephone-event/8000\r\n",
    "a=sendrecv\r\n",
);

/// The SDP the engine returns for every `offer` and `reoffer`: the relay side
/// it presents to the leg the offer is for, on an address of its own.
pub(crate) const NATIVE_ENGINE_OFFER: &str = concat!(
    "v=0\r\n",
    "o=- 9 9 IN IP4 203.0.113.61\r\n",
    "s=-\r\n",
    "c=IN IP4 203.0.113.61\r\n",
    "t=0 0\r\n",
    "m=audio 52000 RTP/AVP 0 101\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
    "a=rtpmap:101 telephone-event/8000\r\n",
    "a=sendrecv\r\n",
);

/// `base` as the engine shapes it for a command: on the profile's `transport`
/// (with an RFC 4568 SDES key when it is a secure one), and carrying the
/// direction the SDP it was given (`input`) states, the way an engine relays a
/// party's `sendonly` hold to the other party and the other's `recvonly` back.
fn native_engine_sdp(base: &str, port: &str, transport: Option<&str>, input: &str) -> String {
    let mut sdp = base.to_string();
    if let Some(transport) = transport {
        sdp = sdp.replace(
            &format!("m=audio {port} RTP/AVP 0 101"),
            &format!("m=audio {port} {transport} 0 101"),
        );
    }
    if let Some(direction) = ["sendonly", "recvonly", "inactive"]
        .into_iter()
        .find(|direction| input.contains(&format!("a={direction}")))
    {
        sdp = sdp.replace("a=sendrecv", &format!("a={direction}"));
    }
    if transport.is_some_and(|transport| transport.contains("SAVP")) {
        sdp.push_str(
            "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz\r\n",
        );
    }
    sdp
}

/// One media command the engine was sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NativeCommand {
    /// `answer_local`, `answer`, `delete`, `offer`, `reoffer`, `play_media`
    /// or `stop_media`.
    pub(crate) name: &'static str,
    pub(crate) call_id: String,
    pub(crate) from_tag: String,
    /// What the command carried that a test asserts on: the tone a
    /// `play_media` plays (`None` for any other source), the `play_id` a
    /// `stop_media` targets (`None` for a stop of everything).
    pub(crate) detail: Option<String>,
    /// The profile's `transport_protocol` on an `answer_local`, `offer`,
    /// `answer` or `reoffer`.
    pub(crate) transport_protocol: Option<String>,
    /// The profile's per-call `received_from` on the same four.
    pub(crate) received_from: Option<IpAddr>,
    /// The profile's per-call `sip_call_id` on the same four: the Call-ID of
    /// the dialog whose SDP the command carried.
    pub(crate) sip_call_id: Option<String>,
    /// Whether the engine refused the command because it holds no such call.
    pub(crate) refused: bool,
}

/// What a recorded command carried, before the engine decides on it.
struct Recorded {
    name: &'static str,
    call_id: String,
    from_tag: String,
    detail: Option<String>,
    profile: Option<siphon_rtp_proto::ProfileFlags>,
}

impl Recorded {
    fn new(name: &'static str, call_id: &str, from_tag: &str) -> Self {
        Recorded {
            name,
            call_id: call_id.to_string(),
            from_tag: from_tag.to_string(),
            detail: None,
            profile: None,
        }
    }
}

/// The `play_id` the engine hands the first playback it accepts; each later one
/// gets the next.
pub(crate) const NATIVE_ENGINE_FIRST_PLAY_ID: u64 = 7001;

/// The engine: its address, and the media commands it has been sent.
pub(crate) struct NativeTestEngine {
    address: SocketAddr,
    commands: Arc<Mutex<Vec<NativeCommand>>>,
    live: Arc<Mutex<HashSet<String>>>,
}

impl NativeTestEngine {
    /// Start the engine on a loopback port. Serves every connection the client
    /// opens until the test's runtime ends.
    pub(crate) async fn start() -> NativeTestEngine {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback listener");
        let address = listener.local_addr().expect("the listener's address");
        let commands = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&commands);
        let live: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
        let held = Arc::clone(&live);
        let next_play_id = Arc::new(std::sync::atomic::AtomicU64::new(
            NATIVE_ENGINE_FIRST_PLAY_ID,
        ));
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let recorded = Arc::clone(&recorded);
                let held = Arc::clone(&held);
                let next_play_id = Arc::clone(&next_play_id);
                tokio::spawn(async move {
                    let mut buffer = Vec::new();
                    let mut chunk = [0u8; 4096];
                    loop {
                        let request = loop {
                            match frame::decode::<Request>(&buffer) {
                                Ok(Some((request, consumed))) => {
                                    buffer.drain(..consumed);
                                    break Some(request);
                                }
                                Ok(None) => {}
                                Err(_) => break None,
                            }
                            match stream.read(&mut chunk).await {
                                Ok(0) | Err(_) => break None,
                                Ok(read) => buffer.extend_from_slice(&chunk[..read]),
                            }
                        };
                        let Some(request) = request else {
                            return;
                        };
                        let mut play_id = None;
                        // What the command is, what SDP an accepted one answers
                        // with, and what it does to the calls the engine holds.
                        let (record, sdp, creates, needs_call) = match &request.command {
                            Command::AnswerLocal {
                                call_id,
                                from_tag,
                                profile,
                                ..
                            } => (
                                Some(Recorded {
                                    profile: Some(profile.clone()),
                                    ..Recorded::new("answer_local", call_id, from_tag)
                                }),
                                Some(NATIVE_ENGINE_ANSWER.to_string()),
                                true,
                                false,
                            ),
                            Command::Delete {
                                call_id, from_tag, ..
                            } => (
                                Some(Recorded::new("delete", call_id, from_tag)),
                                None,
                                false,
                                true,
                            ),
                            Command::Offer {
                                call_id,
                                from_tag,
                                profile,
                                sdp,
                            } => (
                                Some(Recorded {
                                    profile: Some(profile.clone()),
                                    ..Recorded::new("offer", call_id, from_tag)
                                }),
                                Some(native_engine_sdp(
                                    NATIVE_ENGINE_OFFER,
                                    "52000",
                                    profile.transport_protocol.as_deref(),
                                    sdp,
                                )),
                                true,
                                false,
                            ),
                            Command::Answer {
                                call_id,
                                from_tag,
                                profile,
                                sdp,
                                ..
                            } => (
                                Some(Recorded {
                                    profile: Some(profile.clone()),
                                    ..Recorded::new("answer", call_id, from_tag)
                                }),
                                Some(native_engine_sdp(
                                    NATIVE_ENGINE_ANSWER,
                                    "51000",
                                    profile.transport_protocol.as_deref(),
                                    sdp,
                                )),
                                false,
                                true,
                            ),
                            Command::Reoffer {
                                call_id,
                                from_tag,
                                profile,
                                sdp,
                            } => (
                                Some(Recorded {
                                    profile: Some(profile.clone()),
                                    ..Recorded::new("reoffer", call_id, from_tag)
                                }),
                                Some(native_engine_sdp(
                                    NATIVE_ENGINE_OFFER,
                                    "52000",
                                    profile.transport_protocol.as_deref(),
                                    sdp,
                                )),
                                false,
                                true,
                            ),
                            Command::PlayMedia {
                                call_id,
                                from_tag,
                                source,
                                ..
                            } => {
                                let tone = match source {
                                    siphon_rtp_proto::PlayMediaSource::Tone { tone } => {
                                        Some(tone.clone())
                                    }
                                    _ => None,
                                };
                                (
                                    Some(Recorded {
                                        detail: tone,
                                        ..Recorded::new("play_media", call_id, from_tag)
                                    }),
                                    None,
                                    false,
                                    true,
                                )
                            }
                            Command::StopMedia {
                                call_id,
                                from_tag,
                                play_id,
                            } => (
                                Some(Recorded {
                                    detail: play_id.map(|play_id| play_id.to_string()),
                                    ..Recorded::new("stop_media", call_id, from_tag)
                                }),
                                None,
                                false,
                                true,
                            ),
                            _ => (None, None, false, false),
                        };
                        let mut refused = false;
                        if let (Some(record), Ok(mut live)) = (record.as_ref(), held.lock()) {
                            if needs_call && !live.contains(&record.call_id) {
                                refused = true;
                            } else if creates {
                                live.insert(record.call_id.clone());
                            } else if record.name == "delete" {
                                live.remove(&record.call_id);
                            }
                        }
                        if !refused && matches!(request.command, Command::PlayMedia { .. }) {
                            play_id = Some(
                                next_play_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                            );
                        }
                        let unknown_call = record
                            .as_ref()
                            .map(|record| format!("unknown call: {}", record.call_id));
                        if let Some(record) = record {
                            if let Ok(mut log) = recorded.lock() {
                                log.push(NativeCommand {
                                    name: record.name,
                                    call_id: record.call_id,
                                    from_tag: record.from_tag,
                                    detail: record.detail,
                                    transport_protocol: record
                                        .profile
                                        .as_ref()
                                        .and_then(|profile| profile.transport_protocol.clone()),
                                    received_from: record
                                        .profile
                                        .as_ref()
                                        .and_then(|profile| profile.received_from),
                                    sip_call_id: record
                                        .profile
                                        .as_ref()
                                        .and_then(|profile| profile.sip_call_id.clone()),
                                    refused,
                                });
                            }
                        }
                        let result = match request.command {
                            Command::Ping => CmdResult::Pong,
                            _ if refused => CmdResult::Error {
                                reason: unknown_call.unwrap_or_default(),
                            },
                            _ => CmdResult::Ok {
                                sdp,
                                duration_ms: None,
                                play_id,
                                recording_id: None,
                                to_tag: None,
                                stats: None,
                            },
                        };
                        let Ok(bytes) = frame::encode(&Response {
                            id: request.id,
                            result,
                        }) else {
                            return;
                        };
                        if stream.write_all(&bytes).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        NativeTestEngine {
            address,
            commands,
            live,
        }
    }

    /// Whether the engine holds `call_id`: created and not deleted.
    pub(crate) fn holds(&self, call_id: &str) -> bool {
        self.live
            .lock()
            .map(|live| live.contains(call_id))
            .unwrap_or(false)
    }

    /// How many calls the engine holds.
    pub(crate) fn held_count(&self) -> usize {
        self.live.lock().map(|live| live.len()).unwrap_or(0)
    }

    /// A media backend that sends its commands to this engine.
    pub(crate) fn backend(&self) -> Arc<MediaBackend> {
        let (event_tx, _event_rx) = tokio::sync::mpsc::channel(16);
        let set =
            super::SiphonRtpClientSet::new(vec![(self.address, 2000, 1)], None, 5_000, event_tx)
                .expect("a native engine set");
        Arc::new(MediaBackend::SiphonRtp(set))
    }

    /// Every command of kind `name` the engine has been sent so far, in order.
    pub(crate) fn commands(&self, name: &str) -> Vec<NativeCommand> {
        self.commands
            .lock()
            .map(|log| {
                log.iter()
                    .filter(|command| command.name == name)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }
}
