//! A REFER a routing script carries out itself: `call.accept_refer(mode=
//! "script")`, then `b2bua.complete_refer()`.
//!
//! The REFER arrives in the dialog of a call siphon answered (a conference
//! focus, RFC 4579 §5.5): there is no far leg to transfer to, and what the
//! REFER asks is the script's to do. `@b2bua.on_refer` runs with the REFER held
//! un-answered, so `accept_refer(mode="script")` can send the 202 and the first
//! NOTIFY before the handler goes on with the work; the handler's other
//! decisions are taken back off the hold when it returns.
//!
//! The Python methods reach the dispatcher through its process-wide handle,
//! which a unit-test binary never installs, so the accept and the report are
//! driven here through their `_with_state` entry points while the REFER is
//! held exactly as the handler path holds it.

use std::sync::Arc;

use super::dial_bridge_test_harness::{answered_caller, Caller};
use super::dialog_state_events_tests::{header, inbound};
use super::originate_test_harness::{drain, socket, Sent};
use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::*;
use crate::rtpengine::test_native_engine::NativeTestEngine;

const TARGET: &str = "sip:15550100042@198.51.100.42:5060";

/// A dispatcher running `script`, with media anchored on `engine`.
fn focus(engine: &NativeTestEngine, script: &str) -> TestDispatcher {
    let mut dispatcher = test_dispatcher_with_script(script);
    dispatcher.state.rtpengine_set = Some(engine.backend());
    dispatcher.state.rtpengine_profiles = Some(Arc::new(crate::rtpengine::ProfileRegistry::new()));
    dispatcher.state.rtpengine_sessions =
        Some(Arc::new(crate::rtpengine::MediaSessionStore::new()));
    dispatcher
}

fn script_with(handler_body: &str) -> String {
    format!(
        concat!(
            "from siphon import b2bua\n",
            "\n",
            "@b2bua.on_invite\n",
            "def on_invite(call):\n",
            "    pass\n",
            "\n",
            "@b2bua.on_refer\n",
            "def on_refer(call):\n",
            "{}",
        ),
        handler_body
    )
}

fn refer(caller: &Caller, cseq: u32) -> (InboundMessage, SipMessage) {
    let raw = format!(
        concat!(
            "REFER sip:conf-7@conf.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {address};branch=z9hG4bK-{call_id}-refer-{cseq}\r\n",
            "Max-Forwards: 70\r\n",
            "From: {from}\r\n",
            "To: {to}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: {cseq} REFER\r\n",
            "Contact: <sip:15550100001@{address}>\r\n",
            "Refer-To: <{target}>\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        address = caller.address,
        call_id = caller.call_id,
        cseq = cseq,
        from = caller.answer.headers.from().expect("a From"),
        to = caller.answer.headers.to().expect("a To"),
        target = TARGET,
    );
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("the REFER parses");
    (inbound(&caller.address, &raw), message)
}

/// The caller's REFER through the B2BUA's REFER handling, no control plane.
fn caller_refers(state: &DispatcherState, caller: &Caller, cseq: u32) {
    let (inbound, message) = refer(caller, cseq);
    tokio::task::block_in_place(|| handle_b2bua_refer_on(None, inbound, message, state));
}

/// The REFER held for its handler's decision, as the handler path holds it.
fn held(state: &DispatcherState, caller: &Caller, cseq: u32) {
    let (inbound, message) = refer(caller, cseq);
    let refer_to = crate::sip::headers::refer::ReferTo {
        uri: TARGET.to_string(),
        replaces: None,
    };
    assert!(state.pending_inbound_refer.insert(
        &caller.internal_call_id,
        PendingInboundRefer {
            inbound,
            message,
            refer_to,
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(30),
            channel_sip_call_id: caller.call_id.clone(),
        },
    ));
}

fn statuses(sent: &[Sent]) -> Vec<Option<u16>> {
    sent.iter()
        .map(|frame| frame.message.status_code())
        .collect()
}

/// Accepted in mode `script`, the REFER is answered 202 then notified `100
/// Trying`, nothing is dialled, and the report ends the subscription.
#[tokio::test(flavor = "multi_thread")]
async fn a_refer_accepted_for_the_script_is_answered_then_reported() {
    let engine = NativeTestEngine::start().await;
    let dispatcher = focus(&engine, &script_with("    pass\n"));
    let state = &dispatcher.state;
    let caller = answered_caller(&dispatcher, "script-refer-ok@192.0.2.10");

    held(state, &caller, 2);
    let expires = b2bua_accept_refer_script_with_state(state, &caller.internal_call_id, None)
        .expect("the held REFER is accepted");
    assert_eq!(expires, 60);
    let sent = drain(&dispatcher.udp);
    assert_eq!(sent.len(), 2, "a 202 and a NOTIFY, and no INVITE to anyone");
    assert!(sent
        .iter()
        .all(|frame| frame.destination == socket(&caller.address)));
    assert_eq!(sent[0].message.status_code(), Some(202));
    assert!(sent[1].is(Method::Notify));
    assert_eq!(header(&sent[1].message, "Event"), "refer;id=2");
    assert_eq!(
        String::from_utf8_lossy(&sent[1].message.body),
        "SIP/2.0 100 Trying\r\n"
    );
    assert_eq!(state.pending_inbound_refer.len(), 0);
    assert_eq!(state.controller_refers.len(), 1);

    // A retransmission of the REFER gets its 202 again; another REFER 491.
    caller_refers(state, &caller, 2);
    assert_eq!(statuses(&drain(&dispatcher.udp)), vec![Some(202)]);
    caller_refers(state, &caller, 3);
    assert_eq!(statuses(&drain(&dispatcher.udp)), vec![Some(491)]);

    b2bua_complete_refer_with_state(state, &caller.call_id, 486, None).expect("the script reports");
    let sent = drain(&dispatcher.udp);
    assert_eq!(sent.len(), 1);
    assert!(sent[0].is(Method::Notify));
    assert!(header(&sent[0].message, "Subscription-State").starts_with("terminated"));
    assert_eq!(
        String::from_utf8_lossy(&sent[0].message.body),
        "SIP/2.0 486 Busy Here\r\n"
    );
    assert_eq!(state.controller_refers.len(), 0, "the record is gone");
    assert_eq!(
        b2bua_complete_refer_with_state(state, &caller.call_id, 200, None),
        Err(ControllerReferRefusal::NoTransferPending),
        "reported once"
    );
}

/// With no REFER held there is nothing to accept.
#[tokio::test(flavor = "multi_thread")]
async fn a_script_accept_without_a_held_refer_is_refused() {
    let engine = NativeTestEngine::start().await;
    let dispatcher = focus(&engine, &script_with("    pass\n"));
    let caller = answered_caller(&dispatcher, "script-refer-none@192.0.2.10");
    assert_eq!(
        b2bua_accept_refer_script_with_state(&dispatcher.state, &caller.internal_call_id, None),
        Err(ControllerReferRefusal::NoPendingRefer)
    );
    assert!(drain(&dispatcher.udp).is_empty());
}

/// A handler that decides nothing still leaves the REFER answered 603, and the
/// hold it ran under is released.
#[tokio::test(flavor = "multi_thread")]
async fn a_handler_that_decides_nothing_still_declines_and_releases_the_hold() {
    let engine = NativeTestEngine::start().await;
    let dispatcher = focus(&engine, &script_with("    pass\n"));
    let caller = answered_caller(&dispatcher, "script-refer-nothing@192.0.2.10");
    caller_refers(&dispatcher.state, &caller, 2);
    assert_eq!(statuses(&drain(&dispatcher.udp)), vec![Some(603)]);
    assert_eq!(dispatcher.state.pending_inbound_refer.len(), 0);
}

/// The script's own refusal is the answer, taken off the hold.
#[tokio::test(flavor = "multi_thread")]
async fn a_handler_refusal_is_answered_off_the_hold() {
    let engine = NativeTestEngine::start().await;
    let dispatcher = focus(
        &engine,
        &script_with("    call.reject_refer(488, \"Not Acceptable Here\")\n"),
    );
    let caller = answered_caller(&dispatcher, "script-refer-reject@192.0.2.10");
    caller_refers(&dispatcher.state, &caller, 2);
    assert_eq!(statuses(&drain(&dispatcher.udp)), vec![Some(488)]);
    assert_eq!(dispatcher.state.pending_inbound_refer.len(), 0);
}

/// A handler whose script-mode accept could not be carried out raises: the
/// REFER is answered 500, never left hanging, and nothing stays held.
#[tokio::test(flavor = "multi_thread")]
async fn a_script_accept_that_raises_is_answered_and_releases_the_hold() {
    let engine = NativeTestEngine::start().await;
    let dispatcher = focus(
        &engine,
        &script_with("    call.accept_refer(mode=\"script\")\n"),
    );
    let caller = answered_caller(&dispatcher, "script-refer-raise@192.0.2.10");
    caller_refers(&dispatcher.state, &caller, 2);
    assert_eq!(statuses(&drain(&dispatcher.udp)), vec![Some(500)]);
    assert_eq!(dispatcher.state.pending_inbound_refer.len(), 0);
    assert_eq!(dispatcher.state.controller_refers.len(), 0);
}
