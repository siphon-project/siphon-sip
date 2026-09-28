//! A siphon-rtp media engine speaking the native protocol inside the test
//! process.
//!
//! [`super::test_engine::TestEngine`] speaks the rtpengine NG protocol, which
//! has no `answer_local`: an offerless originate is only served by the native
//! backend, so a test that drives one end to end points a [`MediaBackend`] at
//! this engine. It answers `answer_local` with [`NATIVE_ENGINE_ANSWER`], pings
//! with a pong and everything else with a bare `ok`, and records the call-id and
//! tag of every `answer_local` and `delete` it is sent.

use std::net::SocketAddr;
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

/// One media command the engine was sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NativeCommand {
    /// `answer_local` or `delete`.
    pub(crate) name: &'static str,
    pub(crate) call_id: String,
    pub(crate) from_tag: String,
}

/// The engine: its address, and the media commands it has been sent.
pub(crate) struct NativeTestEngine {
    address: SocketAddr,
    commands: Arc<Mutex<Vec<NativeCommand>>>,
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
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let recorded = Arc::clone(&recorded);
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
                        let (sdp, record) = match &request.command {
                            Command::AnswerLocal {
                                call_id, from_tag, ..
                            } => (
                                Some(NATIVE_ENGINE_ANSWER.to_string()),
                                Some(("answer_local", call_id.clone(), from_tag.clone())),
                            ),
                            Command::Delete {
                                call_id, from_tag, ..
                            } => (None, Some(("delete", call_id.clone(), from_tag.clone()))),
                            _ => (None, None),
                        };
                        if let Some((name, call_id, from_tag)) = record {
                            if let Ok(mut log) = recorded.lock() {
                                log.push(NativeCommand {
                                    name,
                                    call_id,
                                    from_tag,
                                });
                            }
                        }
                        let result = match request.command {
                            Command::Ping => CmdResult::Pong,
                            _ => CmdResult::Ok {
                                sdp,
                                duration_ms: None,
                                play_id: None,
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
        NativeTestEngine { address, commands }
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
