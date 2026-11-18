//! A caller's CANCEL that reaches another worker while its INVITE is still being
//! turned into a call (RFC 3261 §9.1, §9.2).
//!
//! The INVITE is registered as the dispatch loop does it, its worker is parked
//! at a named stage, and the CANCEL is delivered whole to its own worker in
//! that window: before the INVITE's worker has done anything with it, just
//! before the call is created, and just after.

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

/// A message handled as a worker would after the dispatch loop's registration.
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

/// The INVITE of `call_id` on its own thread, registered first as the dispatch
/// loop does, parked at `stage`. Returns once its worker is there.
fn parked_invite(
    state: &Arc<DispatcherState>,
    stage: &str,
    call_id: &str,
    raw: String,
) -> (std::thread::JoinHandle<()>, std::sync::mpsc::Sender<()>) {
    let (reached, release) = pause::arm(stage, call_id);
    let inbound = InboundMessage {
        client_transport: None,
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: state.local_addr,
        remote_addr: CALLER.parse().expect("a literal address"),
        data: Bytes::from(raw),
    };
    let registration = super::inflight_invite::register_inbound(&inbound, state);
    assert!(registration.is_some(), "the loop registers an INVITE");
    let worker = {
        let state = Arc::clone(state);
        std::thread::spawn(move || {
            let _registration = registration;
            super::inbound::handle_inbound_after_queue(inbound, std::time::Duration::ZERO, &state);
        })
    };
    reached
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the INVITE's worker reached the stage");
    (worker, release)
}

fn caller() -> SocketAddr {
    CALLER.parse().expect("a literal address")
}

fn to_caller(sent: &[(SocketAddr, String)]) -> Vec<&str> {
    sent.iter()
        .filter(|(destination, _)| *destination == caller())
        .map(|(_, label)| label.as_str())
        .collect()
}

/// What a cancelled call looks like on the wire: the CANCEL answered 200, the
/// INVITE 487, no 481, and nothing for the callee, which was never dialled.
fn assert_cancelled_before_dialling(
    state: &Arc<DispatcherState>,
    sent: &[(SocketAddr, String)],
    call_id: &str,
) {
    let to_caller = to_caller(sent);
    assert!(to_caller.contains(&"200 CANCEL"), "CANCEL 200: {sent:?}");
    assert!(to_caller.contains(&"487 INVITE"), "INVITE 487: {sent:?}");
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

/// The CANCEL is delivered to its worker before the INVITE's worker has done
/// anything at all with the INVITE, not even parsed it. Registered by the loop,
/// the INVITE is found all the same: the CANCEL is held, then run once the call
/// exists.
#[test]
fn a_cancel_that_reaches_its_worker_before_the_invites_worker_has_started_is_held() {
    let (state, udp) = dispatcher(DIALLING_B2BUA);
    let call_id = "not-yet-parsed@peer.example.com";
    let (worker, release) = parked_invite(&state, "start", call_id, invite(call_id));

    arrives(&state, cancel(call_id));
    assert!(wire(&udp).is_empty(), "the CANCEL waits for its call");
    assert_eq!(state.inflight_invites.len(), 1);

    release.send(()).expect("the INVITE's worker is parked");
    worker.join().expect("the INVITE's worker finished");
    assert_cancelled_before_dialling(&state, &wire(&udp), call_id);
}

/// The CANCEL lands after the INVITE was taken in and before its call exists:
/// it is answered `200` and the INVITE `487`, as for any early CANCEL, and the
/// callee, which was never dialled, is sent nothing. Before this the CANCEL was
/// answered `481` and the INVITE went on to ring the callee.
#[test]
fn a_cancel_that_overtakes_its_invite_cancels_the_call() {
    let (state, udp) = dispatcher(DIALLING_B2BUA);
    let call_id = "overtaken@peer.example.com";
    let (worker, release) = parked_invite(&state, "create", call_id, invite(call_id));

    arrives(&state, cancel(call_id));
    assert!(
        !to_caller(&wire(&udp))
            .iter()
            .any(|label| label.starts_with("481")),
        "a CANCEL for an INVITE in flight is not answered 481 (RFC 3261 §9.2)"
    );

    release.send(()).expect("the INVITE's worker is parked");
    worker.join().expect("the INVITE's worker finished");
    assert_cancelled_before_dialling(&state, &wire(&udp), call_id);
}

/// The call exists but the handler window has not opened: the CANCEL finds the
/// call itself, answers both parties and removes it, and `@b2bua.on_invite`
/// then does not run for it (it used to, and set up for a call nobody would
/// release).
#[test]
fn a_cancel_between_the_calls_creation_and_its_handler_cancels_it_and_skips_the_handler() {
    let marker = std::env::temp_dir().join(format!("siphon-on-invite-ran-{}", std::process::id()));
    let _ = std::fs::remove_file(&marker);
    let script = format!(
        concat!(
            "from siphon import b2bua\n",
            "\n",
            "@b2bua.on_invite\n",
            "def on_invite(call):\n",
            "    open({marker:?}, 'a').write('ran')\n",
            "    call.dial(\"sip:bob@198.51.100.30:5060\")\n",
        ),
        marker = marker.to_string_lossy()
    );
    let (state, udp) = dispatcher(&script);
    let call_id = "just-created@peer.example.com";
    let (worker, release) = parked_invite(&state, "created", call_id, invite(call_id));
    assert!(
        state.call_actors.find_by_sip_call_id(call_id).is_some(),
        "the call exists at this stage"
    );

    arrives(&state, cancel(call_id));
    release.send(()).expect("the INVITE's worker is parked");
    worker.join().expect("the INVITE's worker finished");

    assert_cancelled_before_dialling(&state, &wire(&udp), call_id);
    assert!(
        !marker.exists(),
        "@b2bua.on_invite does not run for a call that was cancelled before it"
    );
    let _ = std::fs::remove_file(&marker);
}

/// How a test breaks an INVITE.
type Rewrite = fn(String) -> String;

/// An INVITE that ends without a call, however it ends, answers the CANCEL it
/// held, once, and releases its registration.
#[test]
fn a_held_cancel_is_answered_when_its_invite_is_refused_or_malformed() {
    let refusals: [(&str, Rewrite); 2] = [
        ("a Replaces naming no dialog (481)", |raw: String| {
            raw.replace(
                "Contact:",
                "Replaces: nosuch@peer.example.com;to-tag=a;from-tag=b\r\nContact:",
            )
        }),
        (
            "a CSeq that does not match the request line (400)",
            |raw: String| raw.replace("CSeq: 1 INVITE", "CSeq: 1 BYE"),
        ),
    ];
    for (index, (why, rewrite)) in refusals.iter().enumerate() {
        let (state, udp) = dispatcher(DIALLING_B2BUA);
        let call_id = format!("refused-{index}@peer.example.com");
        let (worker, release) = parked_invite(&state, "start", &call_id, rewrite(invite(&call_id)));
        arrives(&state, cancel(&call_id));
        assert!(wire(&udp).is_empty(), "{why}: the CANCEL is held");

        release.send(()).expect("the INVITE's worker is parked");
        worker.join().expect("the INVITE's worker finished");
        let sent = wire(&udp);
        let answers_to_cancel = to_caller(&sent)
            .into_iter()
            .filter(|label| label.ends_with("CANCEL"))
            .count();
        assert_eq!(
            answers_to_cancel, 1,
            "{why}: the CANCEL is answered once: {sent:?}"
        );
        assert_eq!(
            state.inflight_invites.len(),
            0,
            "{why}: nothing is left registered"
        );
    }
}

/// Without a registration (nothing in flight) a CANCEL is answered at once, and
/// only so many are held for one INVITE.
#[test]
fn only_a_bounded_number_of_cancels_are_held_per_invite() {
    let (state, udp) = dispatcher("");
    let call_id = "flooded@peer.example.com";
    let (worker, release) = parked_invite(&state, "start", call_id, invite(call_id));
    for _ in 0..20 {
        arrives(&state, cancel(call_id));
    }
    assert_eq!(wire(&udp).len(), 12, "twenty CANCELs, eight held");
    release.send(()).expect("the INVITE's worker is parked");
    worker.join().expect("the INVITE's worker finished");
    assert_eq!(state.inflight_invites.len(), 0);

    arrives(&state, cancel(call_id));
    assert!(
        !wire(&udp).is_empty(),
        "nothing in flight: answered at once"
    );
}
