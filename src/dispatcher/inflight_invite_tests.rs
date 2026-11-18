//! A caller's CANCEL that reaches another worker while its INVITE is still being
//! turned into a call (RFC 3261 §9.1, §9.2).
//!
//! The INVITE's worker is parked just before the call is created, which is
//! where the CANCEL overtook it on the wire, and the CANCEL is delivered
//! whole in that window.

use super::inflight_invite::pause;
use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::*;

const CALLER: &str = "198.51.100.10:5060";
const CALLEE: &str = "198.51.100.30:5060";

const DIALLING_B2BUA: &str = concat!(
    "from siphon import b2bua\n",
    "\n",
    "@b2bua.on_invite\n",
    "def on_invite(call):\n",
    "    call.dial(\"sip:bob@198.51.100.30:5060\")\n",
);

fn invite(call_id: &str) -> String {
    format!(
        concat!(
            "INVITE sip:bob@siphon.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {caller};branch=z9hG4bK-early-{call_id}\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:alice@peer.example.com>;tag=caller-tag\r\n",
            "To: <sip:bob@siphon.example.com>\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:alice@{caller}>\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        caller = CALLER,
        call_id = call_id,
    )
}

fn cancel(call_id: &str) -> String {
    invite(call_id)
        .replace("INVITE sip:", "CANCEL sip:")
        .replace("CSeq: 1 INVITE", "CSeq: 1 CANCEL")
}

fn arrives(state: &Arc<DispatcherState>, raw: String) {
    let inbound = InboundMessage {
        client_transport: None,
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: state.local_addr,
        remote_addr: CALLER.parse().expect("a literal address"),
        data: Bytes::from(raw),
    };
    super::inbound::handle_inbound(inbound, state);
}

/// What siphon sent, as (destination, status or method).
fn wire(udp: &flume::Receiver<OutboundMessage>) -> Vec<(SocketAddr, String)> {
    super::originate_test_harness::drain(udp)
        .into_iter()
        .map(|frame| {
            let label = match frame.message.status_code() {
                Some(code) => format!(
                    "{code} {}",
                    frame
                        .message
                        .headers
                        .cseq()
                        .and_then(|cseq| cseq.split_whitespace().nth(1).map(str::to_string))
                        .unwrap_or_default()
                ),
                None => frame
                    .message
                    .method()
                    .map(|method| method.as_str().to_string())
                    .unwrap_or_default(),
            };
            (frame.destination, label)
        })
        .collect()
}

fn dispatcher(script: &str) -> (Arc<DispatcherState>, flume::Receiver<OutboundMessage>) {
    let TestDispatcher { state, udp } = test_dispatcher_with_script(script);
    (Arc::new(state), udp)
}

/// The CANCEL lands after the INVITE was taken in and before its call exists:
/// it is answered `200` and the INVITE `487`, as for any early CANCEL, and the
/// callee, which was never dialled, is sent nothing. Before this the CANCEL was
/// answered `481` and the INVITE went on to ring the callee.
#[test]
fn a_cancel_that_overtakes_its_invite_cancels_the_call() {
    let (state, udp) = dispatcher(DIALLING_B2BUA);
    let call_id = "overtaken@peer.example.com";
    let (reached, release) = pause::arm(call_id);

    let invite_worker = {
        let state = Arc::clone(&state);
        std::thread::spawn(move || arrives(&state, invite(call_id)))
    };
    reached
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the INVITE's worker reached the call's creation");

    arrives(&state, cancel(call_id));
    assert_eq!(
        wire(&udp)
            .into_iter()
            .filter(|(destination, label)| {
                *destination == CALLER.parse::<SocketAddr>().unwrap() && label.starts_with("481")
            })
            .count(),
        0,
        "a CANCEL for an INVITE in flight is not answered 481 (RFC 3261 §9.2)"
    );

    release.send(()).expect("the INVITE's worker is parked");
    invite_worker.join().expect("the INVITE's worker finished");

    let sent = wire(&udp);
    let caller: SocketAddr = CALLER.parse().expect("a literal address");
    let to_caller: Vec<&str> = sent
        .iter()
        .filter(|(destination, _)| *destination == caller)
        .map(|(_, label)| label.as_str())
        .collect();
    assert!(
        to_caller.contains(&"200 CANCEL"),
        "the CANCEL is answered 200: {sent:?}"
    );
    assert!(
        to_caller.contains(&"487 INVITE"),
        "the INVITE is answered 487: {sent:?}"
    );
    assert!(
        !to_caller.iter().any(|label| label.starts_with("481")),
        "no 481 to the caller: {sent:?}"
    );
    let callee: SocketAddr = CALLEE.parse().expect("a literal address");
    assert!(
        !sent.iter().any(|(destination, _)| *destination == callee),
        "a call cancelled before it was dialled rings nobody: {sent:?}"
    );
    assert!(
        state.call_actors.find_by_sip_call_id(call_id).is_none(),
        "the cancelled call is gone"
    );
    assert_eq!(
        state.inflight_invites.len(),
        0,
        "the registration is released"
    );
}

/// An INVITE that ends without ever making a call (here: handed back before
/// the call step) still answers the CANCEL it held, once.
#[test]
fn a_held_cancel_is_answered_when_its_invite_ends_without_a_call() {
    let (state, udp) = dispatcher(DIALLING_B2BUA);
    let call_id = "never-a-call@peer.example.com";
    let message = parse_sip_message_bytes(invite(call_id).as_bytes()).expect("the INVITE parses");
    let guard = state
        .inflight_invites
        .begin(&message, &state)
        .expect("an initial INVITE registers");
    assert!(
        state.inflight_invites.begin(&message, &state).is_none(),
        "a copy of a registered INVITE does not register again"
    );

    arrives(&state, cancel(call_id));
    assert!(
        wire(&udp).is_empty(),
        "the CANCEL is held, not answered yet"
    );

    drop(guard);
    let sent = wire(&udp);
    assert_eq!(sent.len(), 1, "the held CANCEL is answered once: {sent:?}");
    assert!(sent[0].1.ends_with("CANCEL"), "{sent:?}");
    assert_eq!(state.inflight_invites.len(), 0);

    // With nothing registered a CANCEL is answered at once.
    arrives(&state, cancel(call_id));
    assert_eq!(wire(&udp).len(), 1);
}

/// Only so many CANCELs are held for one INVITE; the rest are answered.
#[test]
fn only_a_bounded_number_of_cancels_are_held_per_invite() {
    let (state, udp) = dispatcher("");
    let call_id = "flooded@peer.example.com";
    let message = parse_sip_message_bytes(invite(call_id).as_bytes()).expect("the INVITE parses");
    let guard = state
        .inflight_invites
        .begin(&message, &state)
        .expect("an initial INVITE registers");
    for _ in 0..20 {
        arrives(&state, cancel(call_id));
    }
    assert_eq!(wire(&udp).len(), 12, "twenty CANCELs, eight held");
    drop(guard);
    assert_eq!(
        wire(&udp).len(),
        8,
        "the eight held are answered on release"
    );
    assert_eq!(state.inflight_invites.len(), 0);
}
