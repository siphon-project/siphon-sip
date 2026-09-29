//! Fixtures for the tests that ring phones for an answered caller with
//! `dial {on_answer: "bridge"}` and read what siphon put on the wire.
//!
//! A caller here is what an IVR ends with: an INVITE a controller answered with
//! `answer {anchor}`, so its media is on the engine, and its ACK is in. Each
//! test's caller has a Call-ID of its own: the media engine's playback record
//! and the event capture are process-wide, and two tests sharing one would
//! read each other's.

use std::sync::Arc;

use super::control_originate_tests::{controller_on, Controller};
use super::originate_test_harness::{drain, requests_to, socket, Sent};
use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::*;
use crate::control::protocol::EventFrame;
use crate::control::OutboundFrame;
use crate::rtpengine::test_native_engine::NativeTestEngine;

/// Where every caller calls from.
pub(super) const CALLER: &str = "192.0.2.10:5060";

/// A script with one `@b2bua.on_invite` handler that decides nothing, so the
/// dispatcher takes the B2BUA path for a caller's in-dialog BYE, as it does on
/// a deployment that hands calls to a controller.
const B2BUA_SCRIPT: &str = concat!(
    "from siphon import b2bua\n",
    "\n",
    "@b2bua.on_invite\n",
    "def on_invite(call):\n",
    "    pass\n",
);

/// A dispatcher on the B2BUA path whose media is anchored on `engine`.
pub(super) fn bridging_dispatcher(engine: &NativeTestEngine) -> TestDispatcher {
    let mut dispatcher = test_dispatcher_with_script(B2BUA_SCRIPT);
    dispatcher.state.rtpengine_set = Some(engine.backend());
    dispatcher.state.rtpengine_profiles = Some(Arc::new(crate::rtpengine::ProfileRegistry::new()));
    dispatcher.state.rtpengine_sessions =
        Some(Arc::new(crate::rtpengine::MediaSessionStore::new()));
    dispatcher
}

/// Register `contact` at `aor` over plain UDP, reached by its URI.
pub(super) fn register(aor: &str, contact: &str, q: f32) {
    crate::script::api::test_registrar()
        .save_with_source(
            aor,
            parse_uri_standalone(contact).expect("a contact URI"),
            3600,
            q,
            format!("register-{contact}"),
            1,
            None,
            None,
        )
        .expect("the binding saves");
}

/// An answered caller, as a controller left it after its prompts.
pub(super) struct Caller {
    /// Its SIP Call-ID.
    pub(super) call_id: String,
    /// Its `CallActor` id.
    pub(super) internal_call_id: String,
    /// The 200 siphon answered it with, whose dialog its requests are in.
    pub(super) answer: SipMessage,
    /// Where it calls from.
    pub(super) address: String,
}

/// The caller's INVITE from `address`, carrying an offer and a presented
/// identity.
fn caller_invite(call_id: &str, address: &str) -> SipMessage {
    let host = address.split(':').next().unwrap_or(address);
    let sdp = format!(
        concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 {host}\r\n",
            "s=-\r\n",
            "c=IN IP4 {host}\r\n",
            "t=0 0\r\n",
            "m=audio 40000 RTP/AVP 0 101\r\n",
            "a=rtpmap:0 PCMU/8000\r\n",
            "a=rtpmap:101 telephone-event/8000\r\n",
        ),
        host = host,
    );
    let raw = format!(
        concat!(
            "INVITE sip:4000@siphon.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {address};branch=z9hG4bK-{call_id}\r\n",
            "Max-Forwards: 70\r\n",
            "From: \"Caller One\" <sip:15550100001@siphon.example.com>;tag=caller-tag\r\n",
            "To: <sip:4000@siphon.example.com>\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:15550100001@{address}>\r\n",
            "Content-Type: application/sdp\r\n",
            "Content-Length: {length}\r\n",
            "\r\n",
            "{sdp}",
        ),
        address = address,
        call_id = call_id,
        length = sdp.len(),
        sdp = sdp,
    );
    parse_sip_message_bytes(raw.as_bytes()).expect("the caller's INVITE parses")
}

/// A caller on `call_id`, answered and anchored by siphon and ACKed, the way
/// `answer {anchor: true}` leaves it. What siphon sent it is drained.
pub(super) fn answered_caller(dispatcher: &TestDispatcher, call_id: &str) -> Caller {
    answered_caller_from(dispatcher, call_id, CALLER, "rtp_passthrough")
}

/// [`answered_caller`] calling from `address`, answered with media `profile`.
pub(super) fn answered_caller_from(
    dispatcher: &TestDispatcher,
    call_id: &str,
    address: &str,
    profile: &str,
) -> Caller {
    let state = &dispatcher.state;
    let invite = caller_invite(call_id, address);
    let mut leg = Leg::new_a_leg(
        call_id.to_string(),
        "caller-tag".to_string(),
        format!("z9hG4bK-{call_id}"),
        LegTransport {
            remote_addr: socket(address),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    );
    leg.dialog.local_contact = Some("<sip:192.0.2.1:5060;transport=udp>".to_string());
    leg.dialog.remote_contact = invite
        .headers
        .get("Contact")
        .map(|contact| crate::b2bua::actor::extract_contact_uri(contact));
    leg.dialog.local_from_uri = invite
        .headers
        .to()
        .map(|to| format!("{to};tag={}", leg.dialog.local_tag));
    leg.dialog.remote_to_uri = invite.headers.from().cloned();
    // What the INVITE path records of the caller's offer.
    leg.last_sdp = Some(invite.body.clone());
    let internal_call_id = state.call_actors.create_call(leg);
    state
        .call_actors
        .set_a_leg_invite(&internal_call_id, Arc::new(Mutex::new(invite.clone())));
    answer_first_anchor(
        &internal_call_id,
        &invite,
        socket(address).ip(),
        200,
        "OK",
        Some(profile),
        None,
        state,
    )
    .expect("the caller is answered and anchored");
    let answer = drain(&dispatcher.udp)
        .into_iter()
        .find(|sent| sent.message.status_code() == Some(200))
        .expect("siphon answered the caller")
        .message;
    let caller = Caller {
        call_id: call_id.to_string(),
        internal_call_id,
        answer,
        address: address.to_string(),
    };
    caller_sends(state, &caller, "ACK", "1 ACK");
    caller
}

/// A request from the caller in its dialog, through the request path.
pub(super) fn caller_sends(state: &DispatcherState, caller: &Caller, method: &str, cseq: &str) {
    let raw = format!(
        concat!(
            "{method} sip:192.0.2.1:5060;transport=udp SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {address};branch=z9hG4bK-{call_id}-{branch}\r\n",
            "Max-Forwards: 70\r\n",
            "From: {from}\r\n",
            "To: {to}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: {cseq}\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        method = method,
        address = caller.address,
        branch = method.to_ascii_lowercase(),
        cseq = cseq,
        from = caller.answer.headers.from().expect("a From"),
        to = caller.answer.headers.to().expect("a To"),
        call_id = caller.call_id,
    );
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("the caller's request parses");
    // Where the request path hands each over for a B2BUA call: an ACK for a
    // 2xx to the call's dialog, a BYE to the B2BUA's BYE handling.
    tokio::task::block_in_place(|| match method {
        "ACK" => assert!(absorb_b2bua_ack(&caller.call_id, &message, state)),
        "BYE" => handle_b2bua_bye(
            InboundMessage {
                client_transport: None,
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
                local_addr: socket("192.0.2.1:5060"),
                remote_addr: socket(&caller.address),
                data: Bytes::from(raw),
            },
            message,
            state,
        ),
        other => panic!("the caller sends no {other} in these tests"),
    });
}

/// A response to an in-dialog `request` — a re-INVITE siphon sent — from the
/// party it went to: the request's own Via, From, To, Call-ID and CSeq.
pub(super) fn in_dialog_response(
    request: &SipMessage,
    status_code: u16,
    reason: &str,
    contact: &str,
    body: Option<&str>,
) -> SipMessage {
    let header = |name: &str| {
        request
            .headers
            .get(name)
            .cloned()
            .unwrap_or_else(|| panic!("the request has a {name}"))
    };
    let (content, length) = match body {
        Some(sdp) => ("Content-Type: application/sdp\r\n".to_string(), sdp.len()),
        None => (String::new(), 0),
    };
    let raw = format!(
        concat!(
            "SIP/2.0 {status} {reason}\r\n",
            "Via: {via}\r\n",
            "From: {from}\r\n",
            "To: {to}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: {cseq}\r\n",
            "Contact: <{contact}>\r\n",
            "{content}",
            "Content-Length: {length}\r\n",
            "\r\n",
            "{body}",
        ),
        status = status_code,
        reason = reason,
        via = header("Via"),
        from = header("From"),
        to = header("To"),
        call_id = header("Call-ID"),
        cseq = header("CSeq"),
        contact = contact,
        content = content,
        length = length,
        body = body.unwrap_or_default(),
    );
    parse_sip_message_bytes(raw.as_bytes()).expect("the response parses")
}

/// A controller as `app`, on `dispatcher`, owning `caller` under
/// `channel_id` with the control-loss policy `on_lost`.
pub(super) fn controller_owning(
    app: &str,
    dispatcher: TestDispatcher,
    caller: &Caller,
    channel_id: &str,
    on_lost: &str,
) -> Controller {
    let controller = controller_on(app, dispatcher);
    controller.bus.register_channel(
        channel_id,
        &controller.connection,
        &caller.internal_call_id,
        &caller.call_id,
        on_lost,
        std::collections::HashMap::new(),
    );
    controller
}

/// Send the controller's `dial` for `channel_id` and return the reply and the
/// events queued ahead of it.
pub(super) async fn dial(
    controller: &Controller,
    channel_id: &str,
    args: serde_json::Value,
) -> (serde_json::Value, Vec<EventFrame>) {
    command(controller, "dial", channel_id, args).await
}

/// Send the controller's `verb` for `channel_id` and return the reply and the
/// events queued ahead of it.
pub(super) async fn command(
    controller: &Controller,
    verb: &str,
    channel_id: &str,
    args: serde_json::Value,
) -> (serde_json::Value, Vec<EventFrame>) {
    let frame = serde_json::json!({
        "id": format!("c-{verb}"),
        "type": "command",
        "module": "sip",
        "verb": verb,
        "target": { "channel": channel_id },
        "args": args,
    });
    let mut said_hello = true;
    assert!(
        crate::control::listener::process_text(
            &frame.to_string(),
            &mut said_hello,
            &controller.connection,
            &controller.bus,
        )
        .await
    );
    let mut events = Vec::new();
    loop {
        let frames = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            controller.connection.events.recv_many(),
        )
        .await
        .expect("a reply to the command");
        for frame in frames {
            match frame {
                OutboundFrame::Reply(reply) => {
                    return (
                        serde_json::to_value(reply).expect("the reply serialises"),
                        events,
                    )
                }
                OutboundFrame::Event(event) => events.push(event),
            }
        }
    }
}

/// The events queued for the controller since the last look, once the stream
/// has been quiet for a moment.
pub(super) async fn events(controller: &Controller) -> Vec<EventFrame> {
    let mut events = Vec::new();
    while let Ok(frames) = tokio::time::timeout(
        std::time::Duration::from_millis(150),
        controller.connection.events.recv_many(),
    )
    .await
    {
        events.extend(frames.into_iter().filter_map(|frame| match frame {
            OutboundFrame::Event(event) => Some(event),
            OutboundFrame::Reply(_) => None,
        }));
    }
    events
}

/// The events' names, in order.
pub(super) fn names(events: &[EventFrame]) -> Vec<&str> {
    events.iter().map(|event| event.event.as_str()).collect()
}

/// Every frame siphon sends until one satisfies `done`, or the deadline: the
/// coordinator's bridge runs on a task, so what it sends is waited for.
pub(super) async fn sent_until(
    udp: &flume::Receiver<OutboundMessage>,
    done: impl Fn(&[Sent]) -> bool,
) -> Vec<Sent> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut sent = Vec::new();
    loop {
        sent.extend(drain(udp));
        if done(&sent) || tokio::time::Instant::now() >= deadline {
            return sent;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// Wait until `check` holds, or the deadline; returns whether it did.
pub(super) async fn eventually(check: impl Fn() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        if check() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    check()
}

/// Whether a request is inside a dialog: its To carries the far end's tag
/// (RFC 3261 §12.2.1.1).
pub(super) fn in_dialog(message: &SipMessage) -> bool {
    message.headers.to().is_some_and(|to| to.contains(";tag="))
}

/// The one INVITE to `phone` among `sent` that opens a dialog.
pub(super) fn invite_to(sent: &[Sent], phone: &str) -> SipMessage {
    let mut invites: Vec<_> = requests_to(sent, socket(phone), Method::Invite)
        .into_iter()
        .filter(|sent| !in_dialog(&sent.message))
        .collect();
    assert_eq!(invites.len(), 1, "one dialog-opening INVITE to {phone}");
    invites.remove(0).message
}

/// The re-INVITEs among `sent` to `address`.
pub(super) fn reinvites_to(sent: &[Sent], address: &str) -> Vec<SipMessage> {
    requests_to(sent, socket(address), Method::Invite)
        .into_iter()
        .filter(|sent| in_dialog(&sent.message))
        .map(|sent| sent.message)
        .collect()
}

/// Nothing a bridge dial keeps is left behind.
pub(super) fn assert_drained(state: &DispatcherState) {
    assert_eq!(
        state.dial_bridges.ringing_count(),
        0,
        "a ringing dial leaked"
    );
    assert_eq!(
        state.dial_bridges.bridging_count(),
        0,
        "an awaited bridge leaked"
    );
    assert_eq!(state.originate_groups.group_count(), 0, "a group leaked");
    assert_eq!(state.originate_groups.leg_count(), 0, "a group leg leaked");
}
