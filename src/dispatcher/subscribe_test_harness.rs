//! One dispatcher for every test that runs a `proxy.subscribe_state` script.
//!
//! The namespace a script reaches, the UAC it sends through and the store the
//! dispatcher completes a subscription in are each installed once per process
//! and the first writer wins. Tests in one binary share the process, so two of
//! them each building a dispatcher would leave one sending through the other's
//! egress. They share this one instead and take turns on it.

use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::*;
use crate::subscribe_state::SubscribeStore;

/// Both roles in one script: the notifier that accepts a SUBSCRIBE, and the
/// subscriber that a MESSAGE tells to send one and that looks a NOTIFY up.
const SCRIPT: &str = concat!(
    "from siphon import proxy\n",
    "\n",
    "@proxy.on_request(\"SUBSCRIBE\")\n",
    "async def subscribe(request):\n",
    "    handle = proxy.subscribe_state.accept(request, expires=60)\n",
    "    await handle.notify(\n",
    "        body=\"Messages-Waiting: no\\r\\n\",\n",
    "        content_type=\"application/simple-message-summary\",\n",
    "    )\n",
    "\n",
    "@proxy.on_request(\"MESSAGE\")\n",
    "async def watch(request):\n",
    "    try:\n",
    "        handle = await proxy.subscribe_state.send(\n",
    "            \"sip:001010123456789@192.0.2.30:5060\",\n",
    "            event=\"reg\",\n",
    "            expires=600,\n",
    "            timeout_ms=int(request.get_header(\"X-Timeout-Ms\")),\n",
    "        )\n",
    "    except RuntimeError as error:\n",
    "        request.set_reply_header(\"X-Failure\", str(error))\n",
    "        request.reply(500, \"Subscribe Failed\")\n",
    "        return\n",
    "    request.set_reply_header(\"X-Subscription\", handle.id)\n",
    "    request.reply(200, \"OK\")\n",
    "\n",
    "@proxy.on_request(\"NOTIFY\")\n",
    "def notify(request):\n",
    "    handle = proxy.subscribe_state.find(\n",
    "        request.call_id, request.to_tag, request.from_tag\n",
    "    )\n",
    "    if handle is None:\n",
    "        request.reply(481, \"Subscription Does Not Exist\")\n",
    "        return\n",
    "    request.set_reply_header(\"X-Subscription\", handle.id)\n",
    "    request.set_reply_header(\"X-Event\", handle.event)\n",
    "    request.reply(200, \"OK\")\n",
);

pub(super) struct SubscribeHarness {
    pub(super) state: Arc<DispatcherState>,
    pub(super) udp: flume::Receiver<OutboundMessage>,
    /// The store behind the script's `proxy.subscribe_state`, which is also the
    /// one the dispatcher reaches, as in a running server.
    pub(super) store: Arc<SubscribeStore>,
}

static HARNESS: OnceLock<SubscribeHarness> = OnceLock::new();
static TURN: Mutex<()> = Mutex::new(());

/// The shared dispatcher, and the turn on it: hold the guard for the test.
pub(super) fn subscribe_harness() -> (MutexGuard<'static, ()>, &'static SubscribeHarness) {
    // A test that failed while holding the turn must not fail the others.
    let turn = TURN.lock().unwrap_or_else(PoisonError::into_inner);
    let harness = HARNESS.get_or_init(|| {
        Python::initialize();
        // The singleton goes in before the script engine is built, so the
        // script's `proxy.subscribe_state` is the Rust namespace, not the stub.
        // Another test may have installed it already, so the store is read
        // back rather than assumed, and that one is made the dispatcher's.
        let store = Python::attach(|python| {
            let namespace = crate::script::api::subscribe_state::PySubscribeState::new(Arc::new(
                SubscribeStore::new(),
            ));
            let _ = crate::script::api::set_subscribe_state_singleton(python, namespace);
            crate::script::api::subscribe_state_singleton_store(python)
        })
        .expect("the namespace was just installed");
        crate::subscribe_state::set_global_store(Arc::clone(&store));
        let TestDispatcher { state, udp } = test_dispatcher_with_script(SCRIPT);
        crate::script::api::subscribe_state::set_uac_sender(Arc::clone(&state.uac_sender));
        crate::script::api::subscribe_state::set_resolver(Arc::clone(&state.dns_resolver));
        SubscribeHarness {
            state: Arc::new(state),
            udp,
            store,
        }
    });
    // Whatever an earlier test left unread is not this test's traffic.
    while harness.udp.try_recv().is_ok() {}
    (turn, harness)
}

impl SubscribeHarness {
    /// Deliver `raw` to the dispatcher as a request received from `source`.
    /// Returns once every handler for it has returned.
    pub(super) fn receive_request(&self, raw: &str, source: &str) {
        let message = parse_sip_message_bytes(raw.as_bytes()).expect("the request parses");
        let method = raw.split(' ').next().unwrap_or_default().to_string();
        handle_request(self.inbound(raw, source), message, method, &self.state);
    }

    /// Deliver `raw` to the dispatcher as a response received from `source`.
    pub(super) fn receive_response(&self, raw: &str, source: &str) {
        let message = parse_sip_message_bytes(raw.as_bytes()).expect("the response parses");
        let status = message.status_code().expect("a response has a status");
        handle_response(self.inbound(raw, source), message, status, &self.state);
    }

    fn inbound(&self, raw: &str, source: &str) -> InboundMessage {
        InboundMessage {
            client_transport: None,
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: "192.0.2.1:5060".parse().expect("a literal address"),
            remote_addr: source.parse().expect("a literal address"),
            data: Bytes::from(raw.to_string()),
        }
    }

    /// The frames sent so far, in egress order: each outbound message's own
    /// data, then the followups the transport writes behind it.
    pub(super) fn frames(&self) -> Vec<(SocketAddr, Bytes)> {
        let mut frames = Vec::new();
        while let Ok(message) = self.udp.try_recv() {
            let destination = message.destination;
            for frame in message.frames() {
                frames.push((destination, frame.clone()));
            }
        }
        frames
    }

    /// The next message sent whose start line begins with `start`, waiting for
    /// one a handler on another thread has yet to send.
    pub(super) fn next_sent(&self, start: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let message = self
                .udp
                .recv_timeout(remaining)
                .unwrap_or_else(|_| panic!("nothing starting with {start:?} was sent"));
            for frame in message.frames() {
                let text = String::from_utf8_lossy(frame).to_string();
                if text.starts_with(start) {
                    return text;
                }
            }
        }
    }
}

/// The value of header `name` in the SIP message `text`.
pub(super) fn header_value(text: &str, name: &str) -> Option<String> {
    text.lines()
        .take_while(|line| !line.is_empty())
        .find_map(|line| {
            let (found, value) = line.split_once(':')?;
            found
                .trim()
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_string())
        })
}
