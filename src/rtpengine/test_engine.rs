//! A media engine speaking the rtpengine NG protocol inside the test process.
//!
//! A test that drives siphon's media commands end to end points a
//! [`MediaBackend`] at it. It records every command it is sent, answers `offer`
//! and `answer` with [`ENGINE_SDP`], and refuses every `answer` when started with
//! `refuse_answers`.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bytes::BytesMut;
use tokio::net::UdpSocket;

use super::bencode::{self, BencodeValue};
use super::{MediaBackend, RtpEngineSet};

/// The SDP the engine returns for every `offer` and `answer`: its own address,
/// so a test can tell an SDP that went through the engine from one that did not.
pub(crate) const ENGINE_SDP: &str = concat!(
    "v=0\r\n",
    "o=- 1 1 IN IP4 203.0.113.50\r\n",
    "s=-\r\n",
    "c=IN IP4 203.0.113.50\r\n",
    "t=0 0\r\n",
    "m=audio 50000 RTP/AVP 0 101\r\n",
);

/// One command the engine was sent, with the fields a test checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EngineCommand {
    pub(crate) name: String,
    pub(crate) call_id: Option<String>,
    pub(crate) from_tag: Option<String>,
    pub(crate) to_tag: Option<String>,
    pub(crate) sdp: Option<String>,
}

/// The engine: its address, and the commands it has been sent.
pub(crate) struct TestEngine {
    address: SocketAddr,
    commands: Arc<Mutex<Vec<EngineCommand>>>,
}

impl TestEngine {
    /// Start the engine on a loopback port.
    pub(crate) async fn start(refuse_answers: bool) -> TestEngine {
        let socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("a loopback socket");
        let address = socket.local_addr().expect("the socket's address");
        let commands = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&commands);
        tokio::spawn(async move {
            let mut buffer = BytesMut::zeroed(65_535);
            while let Ok((size, source)) = socket.recv_from(&mut buffer).await {
                let data = &buffer[..size];
                let Some(space) = data.iter().position(|&byte| byte == b' ') else {
                    continue;
                };
                let Ok(command) = bencode::decode_full_dict(&data[space + 1..]) else {
                    continue;
                };
                let field = |key: &str| command.dict_get_str(key).map(str::to_string);
                let name = field("command").unwrap_or_default();
                recorded
                    .lock()
                    .expect("the command log")
                    .push(EngineCommand {
                        name: name.clone(),
                        call_id: field("call-id"),
                        from_tag: field("from-tag"),
                        to_tag: field("to-tag"),
                        sdp: field("sdp"),
                    });
                let response = match name.as_str() {
                    "ping" => BencodeValue::dict(vec![("result", BencodeValue::string("pong"))]),
                    "answer" if refuse_answers => BencodeValue::dict(vec![
                        ("result", BencodeValue::string("error")),
                        (
                            "error-reason",
                            BencodeValue::string("refused by the test engine"),
                        ),
                    ]),
                    "offer" | "answer" => BencodeValue::dict(vec![
                        ("result", BencodeValue::string("ok")),
                        ("sdp", BencodeValue::string(ENGINE_SDP)),
                    ]),
                    _ => BencodeValue::dict(vec![("result", BencodeValue::string("ok"))]),
                };
                let mut reply = data[..space].to_vec();
                reply.push(b' ');
                reply.extend_from_slice(&bencode::encode(&response));
                let _ = socket.send_to(&reply, source).await;
            }
        });
        TestEngine { address, commands }
    }

    /// A media backend that sends its commands to this engine.
    pub(crate) async fn backend(&self) -> Arc<MediaBackend> {
        let set = RtpEngineSet::new(vec![(self.address, 2000, 1)])
            .await
            .expect("an engine set");
        Arc::new(MediaBackend::RtpEngine(Arc::new(set)))
    }

    /// Every command of kind `name` the engine has been sent so far, in order.
    pub(crate) fn commands(&self, name: &str) -> Vec<EngineCommand> {
        self.all_commands()
            .into_iter()
            .filter(|command| command.name == name)
            .collect()
    }

    /// Every command the engine has been sent so far, of any kind, in order.
    pub(crate) fn all_commands(&self) -> Vec<EngineCommand> {
        self.commands.lock().expect("the command log").clone()
    }
}
