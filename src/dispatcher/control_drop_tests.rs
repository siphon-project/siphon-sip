//! The control plane's `drop`: a controller abandons an un-answered call with
//! nothing on the wire, and siphon stops tracking it.
//!
//! `reject` and an un-answered `hangup` both answer the caller. On a SIP port
//! reachable from the internet that answer is the prize: a `404` to an INVITE
//! for a number nobody claims confirms the number to an enumeration sweep, where
//! silence leaves it unable to tell a missing extension from a filtered one. So
//! the two halves both have to hold — **nothing** goes to the peer, and nothing
//! is left behind that would either answer later or leak per probe.
//!
//! Driven against a real dispatcher, with what siphon sent read back off the UDP
//! egress channel.

use super::b2bua::b2bua_drop_call_in;
use super::b_leg_2xx_ack_tests::{callee, caller, caller_invite, caller_leg, drain, Call, Sent};
use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::*;

/// A script carrying one `@b2bua.on_invite` handler that decides nothing.
///
/// Two jobs: it turns `b2bua_mode_active` on, so an INVITE takes the B2BUA path
/// the way it does on a `control.inbound` deployment, and its verdict — decide
/// nothing, answer nothing — is the script spelling of the verdict this verb
/// gives a controller. Used by the retransmission test, which needs the INVITE
/// to reach that path a second time.
const UNDECIDED: &str = concat!(
    "from siphon import b2bua\n",
    "\n",
    "@b2bua.on_invite\n",
    "def on_invite(call):\n",
    "    pass\n",
);

/// A parked, un-answered call on a dispatcher whose INVITEs take the B2BUA path:
/// the caller's leg and its stored INVITE, nothing dialled. The shape of a call
/// handed to a controller over `control.inbound` and not yet acted on.
fn parked() -> (
    Arc<DispatcherState>,
    flume::Receiver<OutboundMessage>,
    String,
) {
    let TestDispatcher { state, udp } = test_dispatcher_with_script(UNDECIDED);
    let state = Arc::new(state);
    let call_id = state.call_actors.create_call(caller_leg());
    state
        .call_actors
        .set_a_leg_invite(&call_id, Arc::new(Mutex::new(caller_invite())));
    (state, udp, call_id)
}

/// The caller's INVITE arriving at the dispatcher's request path.
fn caller_invite_arrives(state: &Arc<DispatcherState>) {
    let message = caller_invite();
    let raw = message.to_bytes();
    tokio::task::block_in_place(|| {
        super::request::handle_request(
            InboundMessage {
                client_transport: None,
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
                local_addr: state.local_addr,
                remote_addr: caller(),
                data: Bytes::from(raw),
            },
            message,
            "INVITE".to_string(),
            state,
        )
    });
}

/// The final responses among `sent` — 200 and up, the only thing that tells a
/// prober anything. A `100 Trying` is not one: the open port already disclosed
/// that a server exists.
fn finals(sent: &[Sent]) -> Vec<u16> {
    sent.iter()
        .filter_map(|sent| sent.message.status_code())
        .filter(|code| *code >= 200)
        .collect()
}

/// The headline: the caller hears nothing at all, and the call is released.
#[tokio::test(flavor = "multi_thread")]
async fn dropping_an_unanswered_call_puts_nothing_on_the_wire() {
    let (state, udp, call_id) = parked();
    drain(&udp);

    let outcome = b2bua_drop_call_in(&state, &call_id, Some("no flow claims 10000"), None);

    assert_eq!(outcome, DropOutcome::Dropped);
    let sent = drain(&udp);
    assert!(
        sent.is_empty(),
        "a drop put {} message(s) on the wire: {:?}",
        sent.len(),
        sent.iter()
            .map(|sent| sent.message.status_code())
            .collect::<Vec<_>>()
    );
    // Released, not orphaned: a verb that leaked a call actor per probe would be
    // worse than the response it avoids, because a scanner sends many.
    assert!(
        state.call_actors.get_call(&call_id).is_none(),
        "the call actor survived the drop"
    );
    assert!(
        state.call_event_receivers.get(&call_id).is_none(),
        "the call's event receiver survived the drop"
    );
}

/// A controller that dialled before it changed its mind still owes the callee a
/// CANCEL (RFC 3261 §9.1). A phone ringing for a call nobody is on is worse than
/// the response the drop avoids, so this is the one thing a drop *does* send —
/// to the callee, never to the caller.
#[tokio::test(flavor = "multi_thread")]
async fn dropping_a_ringing_call_cancels_the_callee_and_still_tells_the_caller_nothing() {
    // `dial` rather than a pre-registered leg: this INVITE really went out, so it
    // is really armed for retransmission and the disarm below is not vacuous.
    let call = Call::dial();
    call.callee_sends(&call.callee_response("180 Ringing", "", ""));
    call.wire();
    let branch = call
        .state
        .call_actors
        .get_call(&call.call_id)
        .and_then(|actor| actor.b_legs.first().map(|leg| leg.branch.clone()))
        .expect("the dialled B-leg is registered");
    assert!(
        call.state.b2bua_retransmits.is_armed(),
        "the dialled INVITE is under retransmission before the drop"
    );

    let outcome = b2bua_drop_call_in(&call.state, &call.call_id, Some("abandoned"), None);

    assert_eq!(outcome, DropOutcome::Dropped);
    let sent = call.wire();
    assert_eq!(
        sent.iter()
            .filter(|sent| sent.destination == callee()
                && sent.message.method() == Some(&Method::Cancel))
            .count(),
        1,
        "the ringing callee was left ringing at a call that no longer exists"
    );
    let to_caller: Vec<&Sent> = sent
        .iter()
        .filter(|sent| sent.destination == caller())
        .collect();
    assert!(
        to_caller.is_empty(),
        "the caller was sent {} message(s) by a drop",
        to_caller.len()
    );
    // The cancelled branch's INVITE stops being retransmitted with it, or a copy
    // delivered behind its own CANCEL would start the callee ringing again with
    // nothing left to cancel it. (The CANCEL's own schedule stays armed — it is
    // a request of its own and is owed Timer E over UDP.)
    assert!(
        !call
            .state
            .b2bua_retransmits
            .disarm(&crate::b2bua::retransmit::RetransmitKey::new(
                branch,
                Method::Invite,
            )),
        "the cancelled branch's INVITE is still armed for retransmission"
    );
    assert!(call.state.call_actors.get_call(&call.call_id).is_none());
}

/// An answered dialog is owed a BYE (RFC 3261 §15), so `drop` refuses it rather
/// than orphaning the far end — and leaves the call exactly as it was, so the
/// controller can still hang up properly.
#[tokio::test(flavor = "multi_thread")]
async fn drop_is_refused_on_an_answered_call_and_changes_nothing() {
    let call = Call::bridged();
    call.callee_answers("");
    call.wire();
    assert!(matches!(
        call.state
            .call_actors
            .get_call(&call.call_id)
            .map(|call| call.state.clone()),
        Some(CallState::Answered)
    ));

    let outcome = b2bua_drop_call_in(&call.state, &call.call_id, Some("wrong verb"), None);

    assert_eq!(outcome, DropOutcome::Answered);
    assert!(
        call.wire().is_empty(),
        "a refused drop still put something on the wire"
    );
    assert!(
        call.state.call_actors.get_call(&call.call_id).is_some(),
        "a refused drop tore the call down anyway — the BYE it owes is now unsendable"
    );
}

/// A call that ended while the controller was deciding: reported, never a silent
/// success for a call nobody dropped.
#[tokio::test(flavor = "multi_thread")]
async fn drop_on_a_call_that_is_already_gone_is_reported() {
    let (state, udp, call_id) = parked();
    state.call_actors.remove_call(&call_id);
    drain(&udp);

    assert_eq!(
        b2bua_drop_call_in(&state, &call_id, None, None),
        DropOutcome::Gone
    );
    assert!(drain(&udp).is_empty());
}

/// The second half of "nothing on the wire": the transaction is really gone, not
/// merely untracked.
///
/// A peer that never saw the `100 Trying` retransmits its INVITE (RFC 3261
/// §17.2.1). Nothing siphon kept may answer it — no cached final response, no
/// absorbing server transaction — so the retransmission is a fresh request that
/// gets the same verdict and, again, no final response.
#[tokio::test(flavor = "multi_thread")]
async fn a_retransmitted_invite_after_a_drop_is_not_answered_either() {
    let (state, udp, call_id) = parked();
    drain(&udp);
    assert_eq!(
        b2bua_drop_call_in(&state, &call_id, Some("unsolicited"), None),
        DropOutcome::Dropped
    );
    drain(&udp);

    // The B2BUA takes the A-leg INVITE before an IST exists, so the call actor
    // is what absorbed its retransmissions and what held the dialog: both are
    // gone, and the transaction map never held anything to replay.
    assert!(state
        .call_actors
        .find_by_sip_call_id(super::b_leg_2xx_ack_tests::CALLER_CALL_ID)
        .is_none());
    assert_eq!(state.transaction_manager.count(), 0);

    caller_invite_arrives(&state);

    let sent = drain(&udp);
    // It really did reach the INVITE path — otherwise "no final response" would
    // only mean the request went nowhere and the test would prove nothing.
    assert!(
        sent.iter()
            .any(|sent| sent.message.status_code() == Some(100)),
        "the retransmitted INVITE never reached the B2BUA path"
    );
    assert!(
        finals(&sent).is_empty(),
        "the retransmitted INVITE was answered {:?} — something outlived the drop",
        finals(&sent)
    );
    // And it left nothing behind either, or a retransmitting scanner would cost
    // one actor per copy.
    assert!(state
        .call_actors
        .find_by_sip_call_id(super::b_leg_2xx_ack_tests::CALLER_CALL_ID)
        .is_none());
}

/// The record an operator reads afterwards. A dropped call must not look like a
/// crash or a leak: the reason the controller gave is on it, the disconnecting
/// side is the control plane, and there is no response code because no response
/// was sent.
#[tokio::test(flavor = "multi_thread")]
async fn the_reason_reaches_the_cdr_with_no_response_code() {
    let records = crate::cdr::capture_auto_emitted_cdrs();
    let (state, _udp, call_id) = parked();
    // What the INVITE path does when it creates the call actor.
    {
        let invite = state
            .call_actors
            .get_call(&call_id)
            .and_then(|call| call.a_leg_invite.clone())
            .expect("the parked call stores its INVITE");
        let guard = invite.lock().expect("the A-leg INVITE lock");
        cdr_track_b2bua_start(&state, &call_id, &guard, "192.0.2.10", "udp");
    }

    assert_eq!(
        b2bua_drop_call_in(&state, &call_id, Some("no flow claims 10000"), None),
        DropOutcome::Dropped
    );

    // The capture is process-wide and accumulates across the binary, so the
    // record is found by what identifies it, never by position.
    let written = records.lock().expect("the capture lock").clone();
    let record = written
        .iter()
        .find(|cdr| cdr.disconnect_initiator.as_deref() == Some("control"))
        .unwrap_or_else(|| panic!("a dropped call wrote no record, got {written:?}"));

    assert_eq!(
        record.sip_reason.as_deref(),
        Some("no flow claims 10000"),
        "the controller's reason is the only thing that says why"
    );
    assert_eq!(
        record.response_code, 0,
        "a response code would claim a status reached the caller"
    );
    assert!(
        record.timestamp_answer.is_none(),
        "a dropped call was never answered"
    );
    assert!(
        state.cdr_sessions.get(&call_id).is_none(),
        "the CDR session outlived the call it belongs to"
    );
}

/// A ban store that bans on the first weight-1 signal, so one drop is enough to
/// tell a scored caller from an unscored one.
fn ban_on_first_signal() -> crate::security::AutoBanStore {
    crate::security::AutoBanStore::new(1, 600, 3600, &[], 3, 0, 3600)
}

/// Silence alone costs a scanner nothing: it moves on to the next number at the
/// same rate. With `ban`, the caller's source is scored, and it still hears
/// nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_drop_with_ban_scores_the_caller_and_still_puts_nothing_on_the_wire() {
    let store = ban_on_first_signal();
    let (state, udp, call_id) = parked();
    drain(&udp);

    let outcome = b2bua_drop_call_in(&state, &call_id, Some("unsolicited"), Some(&store));

    assert_eq!(outcome, DropOutcome::Dropped);
    assert!(
        store.is_banned(caller().ip()),
        "the caller's source was not scored"
    );
    assert!(
        drain(&udp).is_empty(),
        "a banning drop put a message on the wire"
    );
    assert!(state.call_actors.get_call(&call_id).is_none());
}

/// Without `ban` the drop scores nothing: the ban is the controller's opt-in,
/// not a side effect of every drop. The positive control is the test above,
/// against the same store shape and the same caller.
#[tokio::test(flavor = "multi_thread")]
async fn a_drop_without_ban_scores_nothing() {
    let store = ban_on_first_signal();
    let (state, udp, call_id) = parked();
    drain(&udp);

    assert_eq!(
        b2bua_drop_call_in(&state, &call_id, Some("unsolicited"), None),
        DropOutcome::Dropped
    );
    assert!(!store.is_banned(caller().ip()));

    // Positive control on the same store: a banning drop of a second call from
    // the same caller does score it, so the assertion above is not vacuous.
    let second = state.call_actors.create_call(caller_leg());
    assert_eq!(
        b2bua_drop_call_in(&state, &second, Some("unsolicited"), Some(&store)),
        DropOutcome::Dropped
    );
    assert!(store.is_banned(caller().ip()));
}

/// A refused drop is refused whole: an answered call is not dropped, so its
/// caller is not scored either.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_drop_scores_nothing() {
    let store = ban_on_first_signal();
    let call = Call::bridged();
    call.callee_answers("");
    call.wire();

    assert_eq!(
        b2bua_drop_call_in(&call.state, &call.call_id, Some("wrong verb"), Some(&store)),
        DropOutcome::Answered
    );
    assert!(!store.is_banned(caller().ip()));
    assert_eq!(store.active_bans(), 0);
}
