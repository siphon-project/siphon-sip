//! RFC 4028 session timers on the dialogs siphon sets up without relaying the
//! other party's 2xx: a call siphon answers itself (`call.answer()`, a
//! handover's answer, the control plane's), a call siphon places
//! (`b2bua.originate()`), and a leg a bridge re-INVITEs.
//!
//! They run the rules every dialog runs. As the UAS of a caller's INVITE siphon
//! answers the caller's request for a session timer itself (§9 Table 2). As the
//! UAC of an INVITE or a re-INVITE it asks for the timer siphon runs and takes the
//! refresher from the 2xx (§7.1, §7.2, §7.4). siphon refreshes where it is the
//! refresher, and ends the call just before a session the other side refreshes
//! runs out (§10).
//!
//! Every test drives the real send, response and sweep paths and reads what the
//! peers would have been sent off the UDP egress channel.

use super::sdp_strip_tests::{
    address, body_text, caller_call, caller_invite, endpoint_sdp, request_to, response_to,
    A_LEG_CALL_ID, CALLEE, CALLEE_TAG, CALLEE_TARGET, CALLER,
};
use super::session_timer_tests::{
    age, branch_of, caller_acks, lists_option_tag, requests, sweep, timer_dispatcher, wire,
};
use super::test_dispatcher::TestDispatcher;
use super::*;
use crate::script::api::call::SessionTimerOverride;

/// The caller's Contact, the remote target of the caller's dialog.
const CALLER_TARGET: &str = "sip:caller@192.0.2.10:5060";

/// `peer` answers `request`, one siphon sent it on `call_id`, with `status_code`,
/// `headers` and `body`, through the dispatcher's response entry. Returns what
/// siphon put on the wire.
fn peer_answers(
    dispatcher: &TestDispatcher,
    call_id: &str,
    request: &SipMessage,
    peer: &str,
    status_code: u16,
    headers: &[(&str, &str)],
    body: &str,
) -> Vec<(SocketAddr, SipMessage)> {
    let mut response = build_response(request, status_code, "Answer", None, &[]);
    let target = if peer == CALLER {
        CALLER_TARGET
    } else {
        CALLEE_TARGET
    };
    response.headers.set("Contact", format!("<{target}>"));
    for (name, value) in headers {
        response.headers.set(name, value.to_string());
    }
    if !body.is_empty() {
        set_sdp_body(&mut response, body.as_bytes().to_vec(), "application/sdp");
    }
    let _ = wire(dispatcher);
    assert!(handle_b2bua_response(
        call_id,
        &branch_of(request),
        &mut response,
        status_code,
        address(peer),
        &dispatcher.state,
    ));
    wire(dispatcher)
}

/// The session timer of one leg's dialog.
fn timer_of(
    dispatcher: &TestDispatcher,
    call_id: &str,
    on_a_leg: bool,
) -> Option<crate::b2bua::actor::SessionTimerState> {
    dispatcher
        .state
        .call_actors
        .leg_session_timer(call_id, on_a_leg)
}

/// The session description siphon has in force on one leg's dialog.
fn in_force(dispatcher: &TestDispatcher, call_id: &str, on_a_leg: bool) -> Option<Vec<u8>> {
    dispatcher
        .state
        .call_actors
        .clone_leg(call_id, on_a_leg)
        .and_then(|leg| leg.dialog.last_sent_sdp)
}

/// Whether a BYE says a timer ended the call (Q.850 cause 102).
fn ended_by_a_timer(bye: &SipMessage) -> bool {
    bye.headers
        .get("Reason")
        .is_some_and(|reason| reason.contains("cause=102"))
}

// ---------------------------------------------------------------------------
// A call siphon answers itself: siphon is the UAS of the caller's INVITE
// ---------------------------------------------------------------------------

/// The caller's INVITE, carrying `headers` besides its offer.
fn invite_with(headers: &[(&str, &str)]) -> SipMessage {
    let mut invite = caller_invite(&endpoint_sdp("192.0.2.10"));
    for (name, value) in headers {
        invite.headers.set(name, value.to_string());
    }
    invite
}

/// siphon answers the caller's `invite` itself, the way `call.answer()` does.
/// Returns the 2xx the caller was sent.
fn siphon_answers(dispatcher: &TestDispatcher, call_id: &str, invite: &SipMessage) -> SipMessage {
    let _ = wire(dispatcher);
    assert!(send_uas_response(
        &dispatcher.state,
        call_id,
        invite,
        200,
        "OK",
        Some(endpoint_sdp("203.0.113.70").into_bytes()),
        Some("application/sdp"),
        true,
    ));
    response_to(&wire(dispatcher), CALLER, 200)
}

/// RFC 4028 §9: a call siphon answers itself negotiates the caller's session
/// timer from the caller's INVITE (Table 2), the way a relayed answer does. The
/// interval is never longer than the caller asked for, a refresher the caller
/// chose stands, and a caller without timer support is refreshed by siphon. With
/// no session timer configured or set on the call, the answer carries none.
#[tokio::test(flavor = "multi_thread")]
async fn a_call_siphon_answers_itself_negotiates_the_callers_session_timer() {
    struct Case {
        config: Option<&'static str>,
        caller: &'static [(&'static str, &'static str)],
        session_expires: Option<&'static str>,
        require_timer: bool,
        siphon_refreshes: Option<bool>,
    }
    let cases = [
        Case {
            config: Some("session_expires: 900\nrefresher: b2bua\n"),
            caller: &[("Supported", "timer"), ("Session-Expires", "1800")],
            session_expires: Some("900;refresher=uas"),
            require_timer: true,
            siphon_refreshes: Some(true),
        },
        Case {
            config: Some("session_expires: 900\n"),
            caller: &[
                ("Supported", "timer"),
                ("Session-Expires", "600;refresher=uac"),
            ],
            session_expires: Some("600;refresher=uac"),
            require_timer: true,
            siphon_refreshes: Some(false),
        },
        Case {
            config: Some("session_expires: 900\nrefresher: uac\n"),
            caller: &[("Session-Expires", "1800")],
            session_expires: Some("900;refresher=uas"),
            require_timer: false,
            siphon_refreshes: Some(true),
        },
        Case {
            config: Some("session_expires: 900\n"),
            caller: &[],
            session_expires: None,
            require_timer: false,
            siphon_refreshes: None,
        },
        Case {
            config: None,
            caller: &[("Supported", "timer"), ("Session-Expires", "1800")],
            session_expires: None,
            require_timer: false,
            siphon_refreshes: None,
        },
    ];
    for case in cases {
        let dispatcher = timer_dispatcher(case.config);
        let call_id = caller_call(&dispatcher);

        let answer = siphon_answers(&dispatcher, &call_id, &invite_with(case.caller));

        let context = format!("{:?} {:?}", case.config, case.caller);
        assert_eq!(
            answer.headers.get("Session-Expires").map(String::as_str),
            case.session_expires,
            "{context}"
        );
        assert_eq!(
            lists_option_tag(&answer, "Require", "timer"),
            case.require_timer,
            "{context}"
        );
        assert_eq!(
            timer_of(&dispatcher, &call_id, true).map(|timer| timer.siphon_refreshes),
            case.siphon_refreshes,
            "{context}"
        );
    }
}

/// `call.session_timer()` reaches an answer siphon gives the caller itself, with
/// no `session_timer:` block configured.
#[tokio::test(flavor = "multi_thread")]
async fn a_per_call_session_timer_reaches_an_answer_siphon_gives_itself() {
    let dispatcher = timer_dispatcher(None);
    let call_id = caller_call(&dispatcher);
    if let Some(mut call) = dispatcher.state.call_actors.get_call_mut(&call_id) {
        call.session_timer_override = Some(SessionTimerOverride {
            session_expires: 1800,
            min_se: 90,
            refresher: crate::config::SessionRefresher::B2bua,
        });
    }

    let answer = siphon_answers(
        &dispatcher,
        &call_id,
        &invite_with(&[("Supported", "timer")]),
    );

    assert_eq!(
        answer.headers.get("Session-Expires").map(String::as_str),
        Some("1800;refresher=uas")
    );
}

/// Where the answer siphon gave the caller names siphon the refresher, siphon
/// refreshes the caller on the caller's dialog, offering the answer it gave,
/// unchanged. The caller's 2xx is ACKed and restarts the session, on a call that
/// has no other leg.
#[tokio::test(flavor = "multi_thread")]
async fn siphon_refreshes_a_caller_it_answered_itself() {
    let dispatcher = timer_dispatcher(Some("session_expires: 90\nrefresher: b2bua\n"));
    let call_id = caller_call(&dispatcher);
    let answer = siphon_answers(
        &dispatcher,
        &call_id,
        &invite_with(&[("Supported", "timer")]),
    );
    caller_acks(&dispatcher, &answer);

    age(&dispatcher, &call_id, true, 46);
    let mut refreshes = requests(&sweep(&dispatcher), CALLER, Method::Invite);
    assert_eq!(
        refreshes.len(),
        1,
        "siphon did not refresh the caller it answered"
    );
    let refresh = refreshes.remove(0);
    assert_eq!(
        refresh.headers.call_id().map(String::as_str),
        Some(A_LEG_CALL_ID)
    );
    assert_eq!(
        refresh.headers.get("Session-Expires").map(String::as_str),
        Some("90;refresher=uac")
    );
    assert_eq!(body_text(&refresh), body_text(&answer));

    let sent = peer_answers(
        &dispatcher,
        &call_id,
        &refresh,
        CALLER,
        200,
        &[("Session-Expires", "90;refresher=uac")],
        &endpoint_sdp("192.0.2.10"),
    );
    assert_eq!(
        requests(&sent, CALLER, Method::Ack).len(),
        1,
        "the caller's 2xx to the refresh was not ACKed"
    );
    let timer = timer_of(&dispatcher, &call_id, true).expect("the caller's session timer");
    assert!(
        timer.refresh_in_flight.is_none(),
        "the 2xx did not complete the refresh"
    );
    assert!(timer.last_refresh.elapsed() < std::time::Duration::from_secs(5));
    let sent = sweep(&dispatcher);
    assert!(requests(&sent, CALLER, Method::Invite).is_empty());
    assert!(requests(&sent, CALLER, Method::Bye).is_empty());
}

/// RFC 4028 §10: a caller siphon answered that refreshes its own dialog and lets
/// the session run out is released just before the expiration.
#[tokio::test(flavor = "multi_thread")]
async fn a_caller_siphon_answered_that_stops_refreshing_is_released_before_its_session_expires() {
    let dispatcher = timer_dispatcher(Some("session_expires: 90\n"));
    let call_id = caller_call(&dispatcher);
    let answer = siphon_answers(
        &dispatcher,
        &call_id,
        &invite_with(&[
            ("Supported", "timer"),
            ("Session-Expires", "90;refresher=uac"),
        ]),
    );
    caller_acks(&dispatcher, &answer);

    age(&dispatcher, &call_id, true, 59);
    assert!(requests(&sweep(&dispatcher), CALLER, Method::Bye).is_empty());

    age(&dispatcher, &call_id, true, 61);
    let byes = requests(&sweep(&dispatcher), CALLER, Method::Bye);
    assert_eq!(
        byes.len(),
        1,
        "the caller siphon answered was not released before its session expired"
    );
    assert!(ended_by_a_timer(&byes[0]));
}

/// RFC 3261 §15: a session that runs out on a call siphon answered itself, before
/// the caller ACKs that 2xx, holds the caller's BYE until the ACK.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_that_runs_out_before_the_caller_acks_siphons_own_answer_holds_the_bye() {
    let dispatcher = timer_dispatcher(Some("session_expires: 90\n"));
    let call_id = caller_call(&dispatcher);
    let answer = siphon_answers(
        &dispatcher,
        &call_id,
        &invite_with(&[
            ("Supported", "timer"),
            ("Session-Expires", "90;refresher=uac"),
        ]),
    );

    age(&dispatcher, &call_id, true, 61);
    assert!(
        requests(&sweep(&dispatcher), CALLER, Method::Bye).is_empty(),
        "the caller was sent a BYE before it ACKed siphon's 2xx"
    );

    caller_acks(&dispatcher, &answer);
    let byes = requests(&wire(&dispatcher), CALLER, Method::Bye);
    assert_eq!(byes.len(), 1, "the caller's ACK did not release its BYE");
    assert!(ended_by_a_timer(&byes[0]));
}

/// RFC 4028 §9, §10: a caller siphon answered that refreshes its own dialog keeps
/// the call. There is no other party to relay the refresh to, so siphon answers
/// it itself: the 2xx answers the caller's request for a session timer, and the
/// session restarts. A re-INVITE and an UPDATE alike.
#[tokio::test(flavor = "multi_thread")]
async fn a_caller_siphon_answered_that_refreshes_keeps_the_call() {
    for method in ["INVITE", "UPDATE"] {
        let dispatcher = timer_dispatcher(Some("session_expires: 90\n"));
        let call_id = caller_call(&dispatcher);
        let answer = siphon_answers(
            &dispatcher,
            &call_id,
            &invite_with(&[
                ("Supported", "timer"),
                ("Session-Expires", "90;refresher=uac"),
            ]),
        );
        caller_acks(&dispatcher, &answer);
        age(&dispatcher, &call_id, true, 61);

        let mut refresh = super::sdp_strip_tests::in_dialog_request(method, true, "");
        refresh.headers.set("Supported", "timer".to_string());
        refresh
            .headers
            .set("Session-Expires", "90;refresher=uac".to_string());
        let inbound = super::sdp_strip_tests::inbound_from(CALLER);
        let _ = wire(&dispatcher);
        if method == "INVITE" {
            handle_b2bua_reinvite(inbound, refresh, &dispatcher.state);
        } else {
            handle_b2bua_update(inbound, refresh, &dispatcher.state);
        }

        let ok = response_to(&wire(&dispatcher), CALLER, 200);
        assert_eq!(
            ok.headers.get("Session-Expires").map(String::as_str),
            Some("90;refresher=uac"),
            "{method}: the 2xx did not answer the caller's session timer"
        );
        assert!(lists_option_tag(&ok, "Require", "timer"), "{method}");
        assert!(
            requests(&sweep(&dispatcher), CALLER, Method::Bye).is_empty(),
            "{method}: the caller's refresh did not restart the session"
        );
    }
}

// ---------------------------------------------------------------------------
// A call siphon places: siphon is the UAC of the INVITE
// ---------------------------------------------------------------------------

/// The offer the INVITE of a call siphon places carries.
fn originate_offer() -> String {
    endpoint_sdp("192.0.2.1")
}

/// Stage a call siphon places to the callee with its own offer, the way
/// `b2bua.originate(sdp=...)` does, with `session_timer` as the script's.
fn originate(
    dispatcher: &TestDispatcher,
    session_timer: Option<SessionTimerOverride>,
) -> PreparedOriginate {
    let params = OriginateParams {
        to: CALLEE_TARGET.to_string(),
        to_display: None,
        from: None,
        from_display: None,
        next_hop: None,
        p_asserted_identity: None,
        privacy: None,
        headers: Vec::new(),
        timeout_secs: 30,
        media: OriginateMedia::Offer {
            body: originate_offer().into_bytes(),
            content_type: "application/sdp".to_string(),
        },
        session_timer,
    };
    prepare_originate(&dispatcher.state, params).expect("the originate stages")
}

/// The callee answers the INVITE of a call siphon placed with a 200 carrying
/// `headers` and an answer. Returns what siphon put on the wire.
fn callee_answers_originate(
    dispatcher: &TestDispatcher,
    prepared: &PreparedOriginate,
    headers: &[(&str, &str)],
) -> Vec<(SocketAddr, SipMessage)> {
    let mut answer = build_response(&prepared.invite, 200, "OK", None, &[]);
    let to = prepared
        .invite
        .headers
        .to()
        .cloned()
        .expect("the INVITE has a To");
    answer.headers.set("To", format!("{to};tag={CALLEE_TAG}"));
    answer.headers.set("Contact", format!("<{CALLEE_TARGET}>"));
    for (name, value) in headers {
        answer.headers.set(name, value.to_string());
    }
    set_sdp_body(
        &mut answer,
        endpoint_sdp("198.51.100.20").into_bytes(),
        "application/sdp",
    );
    let _ = wire(dispatcher);
    handle_originated_call_response(&prepared.internal_call_id, &answer, 200, &dispatcher.state);
    wire(dispatcher)
}

/// RFC 4028 §7.1: a call siphon places asks for the session timer siphon runs,
/// the configured one or the one the script set on the originate, and asks for
/// none when siphon runs none.
#[tokio::test(flavor = "multi_thread")]
async fn a_call_siphon_places_asks_for_the_session_timer_siphon_runs() {
    let configured = timer_dispatcher(Some("session_expires: 1800\n"));
    let invite = originate(&configured, None).invite;
    assert_eq!(
        invite.headers.get("Session-Expires").map(String::as_str),
        Some("1800;refresher=uac")
    );
    assert_eq!(invite.headers.get("Min-SE").map(String::as_str), Some("90"));
    assert!(lists_option_tag(&invite, "Supported", "timer"));

    let per_call = timer_dispatcher(None);
    let invite = originate(
        &per_call,
        Some(SessionTimerOverride {
            session_expires: 900,
            min_se: 120,
            refresher: crate::config::SessionRefresher::Uas,
        }),
    )
    .invite;
    assert_eq!(
        invite.headers.get("Session-Expires").map(String::as_str),
        Some("900")
    );
    assert_eq!(
        invite.headers.get("Min-SE").map(String::as_str),
        Some("120")
    );

    let none = timer_dispatcher(None);
    let invite = originate(&none, None).invite;
    assert!(invite.headers.get("Session-Expires").is_none());
    assert!(invite.headers.get("Min-SE").is_none());
}

/// RFC 4028 §7.2: where the callee's 2xx names siphon the refresher of a call
/// siphon placed, siphon refreshes it on that dialog, offering the offer the
/// callee accepted, unchanged. The callee's 2xx is ACKed and restarts the session.
#[tokio::test(flavor = "multi_thread")]
async fn siphon_refreshes_a_call_it_placed_whose_answer_names_it() {
    let dispatcher = timer_dispatcher(Some("session_expires: 90\n"));
    let prepared = originate(&dispatcher, None);
    let call_id = prepared.internal_call_id.clone();
    let sent = callee_answers_originate(
        &dispatcher,
        &prepared,
        &[
            ("Supported", "timer"),
            ("Session-Expires", "90;refresher=uac"),
        ],
    );
    assert_eq!(requests(&sent, CALLEE, Method::Ack).len(), 1);

    age(&dispatcher, &call_id, true, 46);
    let mut refreshes = requests(&sweep(&dispatcher), CALLEE, Method::Invite);
    assert_eq!(
        refreshes.len(),
        1,
        "siphon did not refresh the call it placed"
    );
    let refresh = refreshes.remove(0);
    assert_eq!(
        refresh.headers.call_id(),
        Some(&prepared.sip_call_id),
        "the refresh is not on the dialog siphon placed"
    );
    assert_eq!(
        refresh.headers.get("Session-Expires").map(String::as_str),
        Some("90;refresher=uac")
    );
    assert_eq!(body_text(&refresh), originate_offer());

    let sent = peer_answers(
        &dispatcher,
        &call_id,
        &refresh,
        CALLEE,
        200,
        &[("Session-Expires", "90;refresher=uac")],
        &endpoint_sdp("198.51.100.20"),
    );
    assert_eq!(
        requests(&sent, CALLEE, Method::Ack).len(),
        1,
        "the callee's 2xx to the refresh was not ACKed"
    );
    let timer = timer_of(&dispatcher, &call_id, true).expect("the callee's session timer");
    assert!(
        timer.refresh_in_flight.is_none(),
        "the 2xx did not complete the refresh"
    );
    let sent = sweep(&dispatcher);
    assert!(requests(&sent, CALLEE, Method::Invite).is_empty());
    assert!(requests(&sent, CALLEE, Method::Bye).is_empty());
}

/// RFC 4028 §10: a callee of a call siphon placed that refreshes its own dialog
/// and lets the session run out is released just before the expiration.
#[tokio::test(flavor = "multi_thread")]
async fn a_call_siphon_placed_whose_callee_stops_refreshing_is_released_before_it_expires() {
    let dispatcher = timer_dispatcher(Some("session_expires: 90\n"));
    let prepared = originate(&dispatcher, None);
    let call_id = prepared.internal_call_id.clone();
    callee_answers_originate(
        &dispatcher,
        &prepared,
        &[
            ("Supported", "timer"),
            ("Session-Expires", "90;refresher=uas"),
        ],
    );

    age(&dispatcher, &call_id, true, 59);
    let sent = sweep(&dispatcher);
    assert!(
        requests(&sent, CALLEE, Method::Invite).is_empty(),
        "siphon refreshed a dialog the callee refreshes"
    );
    assert!(requests(&sent, CALLEE, Method::Bye).is_empty());

    age(&dispatcher, &call_id, true, 61);
    let byes = requests(&sweep(&dispatcher), CALLEE, Method::Bye);
    assert_eq!(
        byes.len(),
        1,
        "the call siphon placed was not released before its session expired"
    );
    assert!(ended_by_a_timer(&byes[0]));
}

// ---------------------------------------------------------------------------
// A bridge leg: siphon is the UAC of the bridge's re-INVITE
// ---------------------------------------------------------------------------

/// RFC 4028 §7.4: a bridge's re-INVITE on a leg's dialog asks for the session
/// timer siphon runs, even where the dialog runs none yet. Its 2xx sets the
/// dialog's timer, refresher included, and makes the offer the session in force
/// there. A peer that then lets the session run out is released before it
/// expires (§10).
#[tokio::test(flavor = "multi_thread")]
async fn a_bridge_reinvite_runs_the_session_timer_on_the_leg_it_joins() {
    let dispatcher = timer_dispatcher(Some("session_expires: 90\n"));
    let call_id = caller_call(&dispatcher);
    let answer = siphon_answers(&dispatcher, &call_id, &invite_with(&[]));
    caller_acks(&dispatcher, &answer);
    assert!(
        timer_of(&dispatcher, &call_id, true).is_none(),
        "the caller's dialog already ran a session timer"
    );

    let _ = wire(&dispatcher);
    assert!(b2bua_send_reinvite_on_leg(
        &call_id,
        true,
        endpoint_sdp("198.51.100.20").into_bytes(),
        BRIDGE_TRACKING_OFFER,
        &dispatcher.state,
    ));
    let offer = request_to(&wire(&dispatcher), CALLER, Method::Invite);
    assert_eq!(
        offer.headers.get("Session-Expires").map(String::as_str),
        Some("90;refresher=uac")
    );
    assert_eq!(offer.headers.get("Min-SE").map(String::as_str), Some("90"));
    assert!(lists_option_tag(&offer, "Supported", "timer"));

    let sent = peer_answers(
        &dispatcher,
        &call_id,
        &offer,
        CALLER,
        200,
        &[
            ("Supported", "timer"),
            ("Session-Expires", "90;refresher=uas"),
        ],
        &endpoint_sdp("192.0.2.10"),
    );
    assert_eq!(requests(&sent, CALLER, Method::Ack).len(), 1);
    let timer = timer_of(&dispatcher, &call_id, true).expect("the bridge leg's session timer");
    assert_eq!((timer.session_expires, timer.siphon_refreshes), (90, false));
    assert_eq!(
        in_force(&dispatcher, &call_id, true),
        Some(offer.body.clone())
    );

    age(&dispatcher, &call_id, true, 61);
    let byes = requests(&sweep(&dispatcher), CALLER, Method::Bye);
    assert_eq!(
        byes.len(),
        1,
        "the bridge leg was not released before its session expired"
    );
    assert!(ended_by_a_timer(&byes[0]));
}
