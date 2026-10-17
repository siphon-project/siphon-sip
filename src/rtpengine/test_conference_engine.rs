//! A siphon-rtp control endpoint inside the test process that keeps every
//! frame it is sent as raw JSON, for tests of the conference verbs.
//!
//! Raw JSON on purpose: the tests compare what siphon sends with the frames
//! the engine documents, written out by hand, so a misreading shared by the
//! protocol crate's encoder and decoder cannot pass both sides.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use siphon_rtp_proto::frame;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use super::events::RtpEngineEvent;
use super::{MediaBackend, SiphonRtpClientSet};

/// The participant offer of the engine cookbook's join example.
pub(crate) const OFFER: &str = "v=0\r\no=- 1 1 IN IP4 198.51.100.10\r\ns=-\r\nc=IN IP4 198.51.100.10\r\nt=0 0\r\nm=audio 30000 RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\n";

/// What the engine answers a join with: its own address, the participant's
/// codec.
pub(crate) const ANSWER: &str = "v=0\r\no=- 2 2 IN IP4 203.0.113.7\r\ns=-\r\nc=IN IP4 203.0.113.7\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0 101\r\na=sendrecv\r\n";

/// What the engine offers a seat the focus calls out: its own address, the
/// codecs the room can mix.
pub(crate) const SEAT_OFFER: &str = "v=0\r\no=- 3 3 IN IP4 203.0.113.7\r\ns=-\r\nc=IN IP4 203.0.113.7\r\nt=0 0\r\nm=audio 40002 RTP/AVP 9 0 8 101\r\na=rtpmap:9 G722/8000\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\na=rtpmap:101 telephone-event/8000\r\na=sendrecv\r\na=rtcp-mux\r\n";

/// The engine's accept for every verb: `ok`, with an SDP for a join (and an
/// `answer_local`) and a play id for a play, as the documented responses carry.
pub(crate) fn accept(request: &Value) -> Value {
    match request["command"].as_str() {
        Some("conference_join") => {
            json!({"result": "ok", "sdp": ANSWER, "to_tag": request["from_tag"]})
        }
        Some("answer_local") => json!({"result": "ok", "sdp": ANSWER}),
        Some("conference_offer") => {
            json!({"result": "ok", "sdp": SEAT_OFFER, "to_tag": request["from_tag"]})
        }
        Some("conference_play") => json!({"result": "ok", "play_id": 12, "duration_ms": 800}),
        _ => json!({"result": "ok"}),
    }
}

/// The engine: its address, and the frames it has been sent.
pub(crate) struct FakeEngine {
    address: SocketAddr,
    frames: Arc<Mutex<Vec<Value>>>,
}

impl FakeEngine {
    /// Start an engine that answers each frame with `answer(frame)` (the `id`
    /// filled in), and pushes `events` after its first answer, so a test can
    /// watch them arrive on the event channel.
    pub(crate) async fn start(answer: fn(&Value) -> Value, events: Vec<Value>) -> FakeEngine {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let frames = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&frames);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let recorded = Arc::clone(&recorded);
                let mut events = events.clone();
                tokio::spawn(async move {
                    let mut buffer = Vec::new();
                    let mut chunk = [0u8; 8192];
                    loop {
                        while let Ok(Some((request, consumed))) = frame::decode::<Value>(&buffer) {
                            buffer.drain(..consumed);
                            let mut response = answer(&request);
                            response["id"] = request["id"].clone();
                            recorded.lock().expect("frames").push(request);
                            let bytes = frame::encode(&response).expect("encode");
                            if stream.write_all(&bytes).await.is_err() {
                                return;
                            }
                            for event in events.drain(..) {
                                let bytes = frame::encode(&event).expect("encode");
                                if stream.write_all(&bytes).await.is_err() {
                                    return;
                                }
                            }
                        }
                        match stream.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
                        }
                    }
                });
            }
        });
        FakeEngine { address, frames }
    }

    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }

    /// A siphon-rtp media backend that sends its commands here.
    pub(crate) fn backend(&self) -> Arc<MediaBackend> {
        let (event_tx, _events) = mpsc::channel::<RtpEngineEvent>(16);
        let set = SiphonRtpClientSet::new(vec![(self.address, 2000, 1)], None, 5_000, event_tx)
            .expect("a set");
        Arc::new(MediaBackend::SiphonRtp(set))
    }

    /// Every frame of `command` received so far, with its correlation `id`
    /// removed (it is the client's counter, not part of the verb).
    pub(crate) fn frames(&self, command: &str) -> Vec<Value> {
        self.frames
            .lock()
            .expect("frames")
            .iter()
            .filter(|frame| frame["command"] == command)
            .cloned()
            .map(|mut frame| {
                if let Some(fields) = frame.as_object_mut() {
                    fields.remove("id");
                }
                frame
            })
            .collect()
    }

    /// The command name of every frame received so far, in order.
    pub(crate) fn commands(&self) -> Vec<String> {
        self.frames
            .lock()
            .expect("frames")
            .iter()
            .filter_map(|frame| frame["command"].as_str().map(str::to_string))
            .collect()
    }
}
