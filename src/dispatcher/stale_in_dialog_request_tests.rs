//! An in-dialog request for a dialog siphon does not have, after the B2BUA's
//! own memory of the call has aged out.
//!
//! A torn-down B2BUA call is remembered for `TERMINATED_CALL_TTL` so a late
//! in-dialog request naming it is answered 481. Past that window the request
//! misses every B2BUA intercept and reaches the "no `@proxy.on_request`
//! handler" fallback, which answered 405 Method Not Allowed for everything but
//! OPTIONS. For a BYE that is false: siphon implements BYE, and says so in the
//! `Allow` of that very 405. What is true is that the dialog does not exist,
//! and RFC 3261 §12.2.2 gives that its own answer, 481. A peer that sends a
//! BYE 32 s after its own CANCEL, for a dialog that was never answered, lands
//! exactly here.
//!
//! A method siphon does not implement is still 405, in or out of a dialog:
//! method inspection (§8.2.1) comes before any dialog matching.
//!
//! Driven through `handle_request` on a test dispatcher and read back off the
//! UDP egress.

use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::*;

const CALLER: &str = "198.51.100.10:5060";

/// A B2BUA deployment: calls arrive at `@b2bua.on_invite`, and no proxy
/// handler claims any method.
const B2BUA_ONLY: &str = concat!(
    "from siphon import b2bua\n",
    "\n",
    "@b2bua.on_invite\n",
    "def on_invite(call):\n",
    "    call.reject(486, \"Busy Here\")\n",
);

/// A proxy whose script routes INVITE only.
const PROXY_INVITE_ONLY: &str = concat!(
    "from siphon import proxy\n",
    "\n",
    "@proxy.on_request(\"INVITE\")\n",
    "def on_invite(request):\n",
    "    request.reply(486, \"Busy Here\")\n",
);

/// An in-dialog request (it carries a To-tag) on a Call-ID siphon holds no
/// call or tombstone for.
fn in_dialog(method: &str) -> String {
    format!(
        concat!(
            "{method} sip:+15550100@siphon.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {caller};branch=z9hG4bK-stale-{method}\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:+15550111@peer.example.com>;tag=caller-tag\r\n",
            "To: <sip:+15550100@siphon.example.com>;tag=siphon-tag\r\n",
            "Call-ID: stale-{method}@peer.example.com\r\n",
            "CSeq: 2 {method}\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        method = method,
        caller = CALLER,
    )
}

fn out_of_dialog(method: &str) -> String {
    in_dialog(method).replace(";tag=siphon-tag", "")
}

/// A dispatcher running `script`, shared the way `handle_request` takes it.
fn dispatcher(script: &str) -> (Arc<DispatcherState>, flume::Receiver<OutboundMessage>) {
    let TestDispatcher { state, udp } = test_dispatcher_with_script(script);
    (Arc::new(state), udp)
}

/// Feed `raw` in from the caller and return the final response it got.
fn final_response_to(
    (state, udp): &(Arc<DispatcherState>, flume::Receiver<OutboundMessage>),
    raw: String,
) -> SipMessage {
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("the request parses");
    let method = match &message.start_line {
        StartLine::Request(request_line) => request_line.method.as_str().to_string(),
        StartLine::Response(_) => panic!("a request"),
    };
    handle_request(
        InboundMessage {
            client_transport: None,
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: state.local_addr,
            remote_addr: CALLER.parse().expect("a literal address"),
            data: Bytes::from(raw),
        },
        message,
        method,
        state,
    );
    udp.try_iter()
        .filter_map(|sent| parse_sip_message_bytes(&sent.data).ok())
        .find(|sent| sent.status_code().is_some_and(|code| code >= 200))
        .expect("the request got a final response")
}

/// The reported case and its siblings: every in-dialog method siphon
/// implements is answered 481 for a dialog it does not have.
#[tokio::test(flavor = "multi_thread")]
async fn an_in_dialog_request_for_an_unknown_dialog_is_481_not_405() {
    for script in [B2BUA_ONLY, PROXY_INVITE_ONLY] {
        for method in [
            "BYE", "INFO", "UPDATE", "PRACK", "NOTIFY", "REFER", "MESSAGE",
        ] {
            let dispatcher = dispatcher(script);
            let response = final_response_to(&dispatcher, in_dialog(method));
            assert_eq!(
                response.status_code(),
                Some(481),
                "{method}: a request for a dialog siphon does not have is 481 (RFC 3261 §12.2.2)"
            );
        }
    }
}

/// Method inspection comes first (RFC 3261 §8.2.1): a method siphon does not
/// implement is 405 with `Allow` whether or not it names a dialog.
#[tokio::test(flavor = "multi_thread")]
async fn an_unimplemented_method_is_405_in_or_out_of_a_dialog() {
    let dispatcher = dispatcher(B2BUA_ONLY);
    for raw in [in_dialog("FOO"), out_of_dialog("FOO")] {
        let response = final_response_to(&dispatcher, raw);
        assert_eq!(response.status_code(), Some(405));
        assert_eq!(
            response.headers.get("Allow").map(String::as_str),
            Some(crate::sip::SUPPORTED_METHODS)
        );
    }
}

/// Positive control: out of a dialog, a method no handler claims is still 405,
/// as before. Only the To-tag makes it a question about a dialog.
#[tokio::test(flavor = "multi_thread")]
async fn an_out_of_dialog_request_no_handler_claims_is_still_405() {
    let dispatcher = dispatcher(PROXY_INVITE_ONLY);
    let response = final_response_to(&dispatcher, out_of_dialog("MESSAGE"));
    assert_eq!(response.status_code(), Some(405));
}
