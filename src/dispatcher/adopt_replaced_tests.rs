//! `b2bua.adopt_replaced`: a call this node holds merged into a conference
//! room on this same node (RFC 4579 §5.5), driven through the dispatcher.
//!
//! The conference dialog is a call siphon answered and anchored itself, as a
//! focus does. The call merged into the room is a bridged pair: the subscriber
//! on one leg and a carrier on the other, either way round. A REFER carrying a
//! `Replaces` that names the subscriber's leg is held on the conference dialog
//! as the `@b2bua.on_refer` path holds it, accepted with
//! `accept_refer(mode="script")`, carried out by the Rust core of
//! `b2bua.adopt_replaced`, and reported with `complete_refer` — the status on
//! the NOTIFY is what each refusal test reads. The Python wrapper reaches the
//! core through the process-wide dispatcher handle, which a unit-test binary
//! never installs, so it is driven at its `_with_state` entry point here.
//!
//! The media engine is the in-process native engine, which records every
//! command it is sent: a seat that reaches it, a delete that takes it out.

use std::sync::Arc;

use super::dial_bridge_test_harness::{answered_caller_from, caller_sends, eventually, Caller};
use super::dialog_state_events_tests::{header, inbound};
use super::originate_test_harness::{drain, socket, Sent};
use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::*;
use crate::rtpengine::test_native_engine::NativeTestEngine;
use crate::sip::headers::refer::Replaces;

/// The subscriber's handset: where its conference dialog and its own calls come from.
const SUBSCRIBER: &str = "192.0.2.10:5060";
/// Another subscriber's handset.
const STRANGER: &str = "192.0.2.66:5060";
/// The carrier on the far side of a merged call.
const CARRIER: &str = "198.51.100.77:5060";
const ROOM: &str = "room-1";

const SCRIPT: &str = concat!(
    "from siphon import b2bua\n",
    "\n",
    "@b2bua.on_invite\n",
    "def on_invite(call):\n",
    "    pass\n",
    "\n",
    "@b2bua.on_refer\n",
    "def on_refer(call):\n",
    "    pass\n",
);

/// A focus whose media is on `engine`.
fn focus(engine: &NativeTestEngine) -> TestDispatcher {
    focus_running(engine, SCRIPT)
}

fn focus_running(engine: &NativeTestEngine, script: &str) -> TestDispatcher {
    let mut dispatcher = test_dispatcher_with_script(script);
    dispatcher.state.rtpengine_set = Some(engine.backend());
    dispatcher.state.rtpengine_profiles = Some(Arc::new(crate::rtpengine::ProfileRegistry::new()));
    dispatcher.state.rtpengine_sessions =
        Some(Arc::new(crate::rtpengine::MediaSessionStore::new()));
    dispatcher
}

/// The conference dialog: the subscriber's call to the conference factory,
/// answered and anchored by the focus.
fn conference_dialog(dispatcher: &TestDispatcher, call_id: &str, from: &str) -> Caller {
    answered_caller_from(dispatcher, call_id, from, "rtp_passthrough")
}

/// One end of a bridged call as a test builds it.
struct End {
    address: &'static str,
    uri: &'static str,
    tag: &'static str,
}

/// A bridged, answered, anchored call: what `merge` asks to take into a room.
struct Held {
    internal_call_id: String,
    /// The A-leg's SIP Call-ID, the engine call's id.
    a_call_id: String,
    b_call_id: String,
    /// siphon's tag on each dialog.
    a_local_tag: String,
    b_local_tag: String,
    caller: End,
    callee: End,
    /// What siphon sent the callee: the session in force on that dialog.
    sent_to_callee: Vec<u8>,
}

impl Held {
    /// The `Replaces` naming the caller's leg (the subscriber placed the call).
    fn replaces_caller(&self) -> Replaces {
        Replaces {
            call_id: self.a_call_id.clone(),
            to_tag: self.a_local_tag.clone(),
            from_tag: self.caller.tag.to_string(),
            early_only: false,
        }
    }

    /// The `Replaces` naming the callee's leg (the subscriber was called).
    fn replaces_callee(&self) -> Replaces {
        Replaces {
            call_id: self.b_call_id.clone(),
            to_tag: self.b_local_tag.clone(),
            from_tag: self.callee.tag.to_string(),
            early_only: false,
        }
    }
}

fn sdp(host: &str, version: u32) -> String {
    format!(
        concat!(
            "v=0\r\n",
            "o=- 7 {version} IN IP4 {host}\r\n",
            "s=-\r\n",
            "c=IN IP4 {host}\r\n",
            "t=0 0\r\n",
            "m=audio 41000 RTP/AVP 0\r\n",
            "a=rtpmap:0 PCMU/8000\r\n",
        ),
        host = host,
        version = version,
    )
}

fn host_of(address: &str) -> &str {
    address.split(':').next().unwrap_or(address)
}

/// Build a call from `caller` to `callee`, answered, ACKed and anchored on
/// `engine` as one engine call keyed by the caller's Call-ID.
fn held_call(
    dispatcher: &TestDispatcher,
    engine: &NativeTestEngine,
    name: &str,
    caller: End,
    callee: End,
) -> Held {
    let state = &dispatcher.state;
    let a_call_id = format!("{name}-a@192.0.2.1");
    let b_call_id = format!("{name}-b@192.0.2.1");
    let leg_transport = |address: &str| LegTransport {
        remote_addr: socket(address),
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: None,
    };
    let mut a_leg = Leg::new_a_leg(
        a_call_id.clone(),
        caller.tag.to_string(),
        format!("z9hG4bK-{name}-a"),
        leg_transport(caller.address),
    );
    a_leg.dialog.local_contact = Some("<sip:192.0.2.1:5060;transport=udp>".to_string());
    a_leg.dialog.remote_contact = Some(format!("sip:{}", caller.address));
    a_leg.dialog.local_from_uri = Some(format!("<{}>", callee.uri));
    a_leg.dialog.remote_to_uri = Some(format!("<{}>;tag={}", caller.uri, caller.tag));
    a_leg.last_sdp = Some(sdp(host_of(caller.address), 1).into_bytes());
    a_leg.dialog.last_sent_sdp = Some(sdp("192.0.2.1", 1).into_bytes());
    a_leg.initial_acked = true;
    let a_local_tag = a_leg.dialog.local_tag.clone();
    let internal_call_id = state.call_actors.create_call(a_leg);

    let b_local_tag = format!("sb-{name}");
    let mut b_leg = Leg::new_b_leg(
        b_call_id.clone(),
        b_local_tag.clone(),
        callee.uri.to_string(),
        format!("z9hG4bK-{name}-b"),
        leg_transport(callee.address),
    );
    b_leg.dialog.remote_tag = Some(callee.tag.to_string());
    b_leg.dialog.local_contact = Some("<sip:192.0.2.1:5060;transport=udp>".to_string());
    b_leg.dialog.remote_contact = Some(format!("sip:{}", callee.address));
    b_leg.dialog.local_from_uri = Some(format!("<{}>;tag={b_local_tag}", caller.uri));
    b_leg.dialog.remote_to_uri = Some(format!("<{}>", callee.uri));
    b_leg.last_sdp = Some(sdp(host_of(callee.address), 1).into_bytes());
    let sent_to_callee = sdp("192.0.2.1", 2).into_bytes();
    b_leg.dialog.last_sent_sdp = Some(sent_to_callee.clone());
    // The version the next SDP siphon sends the callee would carry.
    b_leg.dialog.sdp_version = 3;
    b_leg.dialog.sdp_session_id = 7;
    b_leg.initial_acked = true;
    assert!(state.call_actors.add_b_leg(&internal_call_id, b_leg));
    state.call_actors.set_winner(&internal_call_id, 0);

    let sessions = state.rtpengine_sessions.as_ref().expect("a session store");
    sessions.insert(crate::rtpengine::MediaSession {
        call_id: a_call_id.clone(),
        rtpengine_call_id: a_call_id.clone(),
        from_tag: caller.tag.to_string(),
        to_tag: Some(callee.tag.to_string()),
        profile: "rtp_passthrough".to_string(),
        ws_uri: None,
        ws_tee: None,
        ws_bridge_attached: false,
        bridge_sides: None,
        created_at: std::time::Instant::now(),
    });
    engine.admit(&a_call_id);
    Held {
        internal_call_id,
        a_call_id,
        b_call_id,
        a_local_tag,
        b_local_tag,
        caller,
        callee,
        sent_to_callee,
    }
}

/// The subscriber at `address` placed a call to a carrier.
fn subscriber_called_out(
    dispatcher: &TestDispatcher,
    engine: &NativeTestEngine,
    name: &str,
    address: &'static str,
) -> Held {
    held_call(
        dispatcher,
        engine,
        name,
        End {
            address,
            uri: "sip:15550100001@example.com",
            tag: "subscriber-tag",
        },
        End {
            address: CARRIER,
            uri: "sip:15550100042@carrier.example.com",
            tag: "carrier-tag",
        },
    )
}

/// A carrier called the subscriber at `address` (an inbound DID call).
fn subscriber_was_called(
    dispatcher: &TestDispatcher,
    engine: &NativeTestEngine,
    name: &str,
    address: &'static str,
) -> Held {
    held_call(
        dispatcher,
        engine,
        name,
        End {
            address: CARRIER,
            uri: "sip:15550100042@carrier.example.com",
            tag: "carrier-tag",
        },
        End {
            address,
            uri: "sip:15550100001@example.com",
            tag: "subscriber-tag",
        },
    )
}

/// The REFER in the conference dialog, held for its handler as the handler
/// path holds it, and accepted in mode `script`: a 202 and a `100 Trying`
/// NOTIFY, both to the subscriber.
fn refer_accepted(dispatcher: &TestDispatcher, conference: &Caller, replaces: &Replaces) {
    let state = &dispatcher.state;
    let raw = format!(
        concat!(
            "REFER sip:conf-7@conf.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {address};branch=z9hG4bK-{call_id}-refer\r\n",
            "Max-Forwards: 70\r\n",
            "From: {from}\r\n",
            "To: {to}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 2 REFER\r\n",
            "Contact: <sip:15550100001@{address}>\r\n",
            "Refer-To: <sip:15550100042@example.com?Replaces={replaces_call_id}%3Bto-tag%3D{to_tag}%3Bfrom-tag%3D{from_tag}>\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        address = conference.address,
        call_id = conference.call_id,
        from = conference.answer.headers.from().expect("a From"),
        to = conference.answer.headers.to().expect("a To"),
        replaces_call_id = replaces.call_id,
        to_tag = replaces.to_tag,
        from_tag = replaces.from_tag,
    );
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("the REFER parses");
    assert!(state.pending_inbound_refer.insert(
        &conference.internal_call_id,
        PendingInboundRefer {
            inbound: inbound(&conference.address, &raw),
            message,
            refer_to: crate::sip::headers::refer::ReferTo {
                uri: "sip:15550100042@example.com".to_string(),
                replaces: Some(replaces.clone()),
            },
            deadline: std::time::Instant::now() + std::time::Duration::from_secs(30),
            channel_sip_call_id: conference.call_id.clone(),
        },
    ));
    b2bua_accept_refer_script_with_state(state, &conference.internal_call_id, None)
        .expect("the held REFER is accepted");
    let sent = drain(&dispatcher.udp);
    assert_eq!(
        sent.iter()
            .map(|frame| frame.message.status_code())
            .collect::<Vec<_>>(),
        vec![Some(202), None],
        "a 202 and the first NOTIFY"
    );
}

fn request(conference: &Caller, replaces: Replaces, ends_with_owner: bool) -> AdoptRequest {
    AdoptRequest {
        owner_call_id: conference.internal_call_id.clone(),
        referrer_on_a_leg: true,
        replaces,
        conference_id: ROOM.to_string(),
        role: crate::rtpengine::backend::ConferenceRole::Talker,
        ends_with_owner,
    }
}

/// Merge with the REFER accepted, then report the outcome: returns the status
/// and what went on the wire from the merge on, the NOTIFY last.
async fn merge(
    dispatcher: &TestDispatcher,
    conference: &Caller,
    request: AdoptRequest,
) -> (u16, Vec<Sent>) {
    refer_accepted(dispatcher, conference, &request.replaces);
    let status = b2bua_adopt_replaced_with_state(&dispatcher.state, request).await;
    b2bua_complete_refer_with_state(&dispatcher.state, &conference.call_id, status, None)
        .expect("the report goes out");
    (status, drain(&dispatcher.udp))
}

/// The sipfrag status line of the NOTIFY that ended the REFER.
fn reported(sent: &[Sent]) -> String {
    let notify = sent
        .iter()
        .rfind(|frame| frame.is(Method::Notify))
        .expect("the final NOTIFY");
    assert!(header(&notify.message, "Subscription-State").starts_with("terminated"));
    String::from_utf8_lossy(&notify.message.body).into_owned()
}

/// Everything but the REFER's NOTIFY.
fn besides_the_report(sent: &[Sent]) -> Vec<&Sent> {
    sent.iter()
        .filter(|frame| !frame.is(Method::Notify))
        .collect()
}

/// The named call is exactly as it was: both legs, answered, no seat.
fn untouched(dispatcher: &TestDispatcher, engine: &NativeTestEngine, held: &Held) {
    let call = dispatcher
        .state
        .call_actors
        .get_call(&held.internal_call_id)
        .expect("the call is still here");
    assert_eq!(call.a_leg.dialog.call_id, held.a_call_id);
    assert_eq!(call.b_legs.len(), 1);
    assert_eq!(call.winner, Some(0));
    assert_eq!(call.state, CallState::Answered);
    assert!(call.adoption.is_none(), "the claim is released");
    drop(call);
    assert!(engine.holds(&held.a_call_id));
    assert_eq!(dispatcher.state.call_actors.adoptions_len(), (0, 0));
}

/// A request from the far party in its dialog with siphon.
fn far_request(
    method: &str,
    cseq: u32,
    far: &End,
    far_call_id: &str,
    siphon_tag: &str,
    body: Option<&str>,
) -> (InboundMessage, SipMessage) {
    let body = body.unwrap_or("");
    let content_type = if body.is_empty() {
        String::new()
    } else {
        "Content-Type: application/sdp\r\n".to_string()
    };
    let raw = format!(
        concat!(
            "{method} sip:192.0.2.1:5060;transport=udp SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {address};branch=z9hG4bK-far-{method}-{cseq}\r\n",
            "Max-Forwards: 70\r\n",
            "From: <{uri}>;tag={far_tag}\r\n",
            "To: <sip:siphon@192.0.2.1>;tag={siphon_tag}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: {cseq} {method}\r\n",
            "Contact: <sip:far@{address}>\r\n",
            "{content_type}",
            "Content-Length: {length}\r\n",
            "\r\n",
            "{body}",
        ),
        method = method,
        address = far.address,
        cseq = cseq,
        uri = far.uri,
        far_tag = far.tag,
        siphon_tag = siphon_tag,
        call_id = far_call_id,
        content_type = content_type,
        length = body.len(),
        body = body,
    );
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("the far party's request parses");
    (inbound(far.address, &raw), message)
}

/// The subscriber placed the call, so its A-leg is the named dialog: the
/// carrier's B-leg is seated in place, the subscriber's leg is BYE'd with the
/// merge's Reason, and the carrier hears nothing. The call keeps its name, its
/// media session and its engine call, with the carrier as its one leg.
#[tokio::test(flavor = "multi_thread")]
async fn the_callers_leg_is_ended_and_the_carrier_is_seated_in_place() {
    let engine = NativeTestEngine::start().await;
    let dispatcher = focus(&engine);
    let state = &dispatcher.state;
    let conference = conference_dialog(&dispatcher, "conf-out@192.0.2.10", SUBSCRIBER);
    let held = subscriber_called_out(&dispatcher, &engine, "merge-out", SUBSCRIBER);
    // Digest on both: the same identity.
    for id in [&conference.internal_call_id, &held.internal_call_id] {
        state
            .call_actors
            .get_call_mut(id)
            .expect("a call")
            .auth_user = Some("1001".into());
    }

    let (status, sent) = merge(
        &dispatcher,
        &conference,
        request(&conference, held.replaces_caller(), true),
    )
    .await;
    assert_eq!(status, 200);
    assert!(reported(&sent).starts_with("SIP/2.0 200 "));

    let seats = engine.commands("conference_seat");
    assert_eq!(seats.len(), 1);
    assert_eq!(
        seats[0].call_id, held.a_call_id,
        "the call's own engine call"
    );
    assert_eq!(seats[0].from_tag, "carrier-tag", "the far party's leg");
    assert_eq!(seats[0].detail.as_deref(), Some(ROOM));

    let others = besides_the_report(&sent);
    assert_eq!(
        others.len(),
        1,
        "one BYE, and nothing to the carrier: {others:?}"
    );
    let bye = &others[0];
    assert!(bye.is(Method::Bye));
    assert_eq!(bye.destination, socket(SUBSCRIBER));
    assert_eq!(header(&bye.message, "Call-ID"), held.a_call_id);
    assert_eq!(
        header(&bye.message, "Reason"),
        "SIP;cause=200;text=\"Merged into conference\""
    );

    let call = state
        .call_actors
        .get_call(&held.internal_call_id)
        .expect("the call goes on");
    assert_eq!(
        call.a_leg.dialog.call_id, held.b_call_id,
        "the carrier is its one leg"
    );
    assert!(call.b_legs.is_empty());
    assert_eq!(call.state, CallState::Answered);
    let adoption = call.adoption.clone().expect("adopted");
    drop(call);
    assert!(adoption.seated);
    assert_eq!(adoption.conference_id, ROOM);
    assert_eq!(
        adoption.alias_call_id.as_deref(),
        Some(held.a_call_id.as_str())
    );
    // Still the call to a script, an engine event and `b2bua.terminate`.
    assert_eq!(
        state
            .call_actors
            .find_by_sip_call_id(&held.a_call_id)
            .as_deref(),
        Some(held.internal_call_id.as_str())
    );
    assert_eq!(
        adopted_call_on_engine_call(state, &held.a_call_id).as_deref(),
        Some(held.internal_call_id.as_str())
    );
    // The media session follows the carrier, on the same engine call, and an
    // engine event for it reaches the call.
    let sessions = state.rtpengine_sessions.as_ref().expect("sessions");
    assert!(sessions.get(&held.a_call_id).is_none());
    let session = sessions.get(&held.b_call_id).expect("the session moved");
    assert_eq!(session.rtpengine_id(), held.a_call_id);
    assert_eq!(session.from_tag, "carrier-tag");
    assert_eq!(
        sessions
            .event_party(&held.a_call_id, "carrier-tag")
            .as_deref(),
        Some(held.b_call_id.as_str())
    );
    assert!(
        engine.holds(&held.a_call_id),
        "no delete: the seat is the call's media"
    );
    assert_eq!(state.call_actors.adoptions_len(), (1, 0));
}

/// The subscriber was called (an inbound DID call), so its B-leg is the named
/// dialog: the carrier's A-leg is seated in place, and nothing about the call's
/// name or its media session moves. Source-authorised: no `auth_user` on
/// either leg, so the source address and the user decide.
#[tokio::test(flavor = "multi_thread")]
async fn the_callees_leg_is_ended_and_the_carrier_is_seated_in_place() {
    let engine = NativeTestEngine::start().await;
    let dispatcher = focus(&engine);
    let state = &dispatcher.state;
    let conference = conference_dialog(&dispatcher, "conf-in@192.0.2.10", SUBSCRIBER);
    let held = subscriber_was_called(&dispatcher, &engine, "merge-in", SUBSCRIBER);

    let (status, sent) = merge(
        &dispatcher,
        &conference,
        request(&conference, held.replaces_callee(), true),
    )
    .await;
    assert_eq!(status, 200);
    assert!(reported(&sent).starts_with("SIP/2.0 200 "));

    let seats = engine.commands("conference_seat");
    assert_eq!(seats.len(), 1);
    assert_eq!(seats[0].call_id, held.a_call_id);
    assert_eq!(seats[0].from_tag, "carrier-tag");

    let others = besides_the_report(&sent);
    assert_eq!(
        others.len(),
        1,
        "one BYE, and nothing to the carrier: {others:?}"
    );
    assert!(others[0].is(Method::Bye));
    assert_eq!(others[0].destination, socket(SUBSCRIBER));
    assert_eq!(header(&others[0].message, "Call-ID"), held.b_call_id);
    assert_eq!(
        header(&others[0].message, "Reason"),
        "SIP;cause=200;text=\"Merged into conference\""
    );

    let call = state
        .call_actors
        .get_call(&held.internal_call_id)
        .expect("the call goes on");
    assert_eq!(call.a_leg.dialog.call_id, held.a_call_id);
    assert!(call.b_legs.is_empty());
    assert!(call.winner.is_none());
    assert!(call
        .adoption
        .as_ref()
        .is_some_and(|adoption| adoption.alias_call_id.is_none()));
    drop(call);
    // The ended dialog is retired: a late request on it is answered 481.
    assert!(state.call_actors.is_recently_terminated(&held.b_call_id));
    assert!(state
        .rtpengine_sessions
        .as_ref()
        .is_some_and(|sessions| sessions.get(&held.a_call_id).is_some()));
}

/// Digest-authenticated INVITEs: a `Replaces` naming another subscriber's
/// dialog is refused 403 on the NOTIFY, and that call is undisturbed.
#[tokio::test(flavor = "multi_thread")]
async fn another_subscribers_dialog_is_refused_403_by_digest_identity() {
    let engine = NativeTestEngine::start().await;
    let dispatcher = focus(&engine);
    let state = &dispatcher.state;
    let conference = conference_dialog(&dispatcher, "conf-403d@192.0.2.10", SUBSCRIBER);
    // Same source and user (a shared PBX trunk, say): the identities decide.
    let held = subscriber_called_out(&dispatcher, &engine, "victim-digest", SUBSCRIBER);
    state
        .call_actors
        .get_call_mut(&conference.internal_call_id)
        .expect("the conference dialog")
        .auth_user = Some("1001".into());
    state
        .call_actors
        .get_call_mut(&held.internal_call_id)
        .expect("the held call")
        .auth_user = Some("1002".into());

    let (status, sent) = merge(
        &dispatcher,
        &conference,
        request(&conference, held.replaces_caller(), true),
    )
    .await;
    assert_eq!(status, 403);
    assert!(reported(&sent).starts_with("SIP/2.0 403 "));
    assert!(
        besides_the_report(&sent).is_empty(),
        "nothing else on the wire"
    );
    assert!(engine.commands("conference_seat").is_empty());
    untouched(&dispatcher, &engine, &held);
}

/// Source-authorised INVITEs (no `auth_user` on either leg): another
/// subscriber's dialog, from another handset, is refused 403.
#[tokio::test(flavor = "multi_thread")]
async fn another_subscribers_dialog_is_refused_403_by_source() {
    let engine = NativeTestEngine::start().await;
    let dispatcher = focus(&engine);
    let conference = conference_dialog(&dispatcher, "conf-403s@192.0.2.10", SUBSCRIBER);
    let held = subscriber_was_called(&dispatcher, &engine, "victim-source", STRANGER);

    let (status, sent) = merge(
        &dispatcher,
        &conference,
        request(&conference, held.replaces_callee(), true),
    )
    .await;
    assert_eq!(status, 403);
    assert!(reported(&sent).starts_with("SIP/2.0 403 "));
    assert!(besides_the_report(&sent).is_empty());
    assert!(engine.commands("conference_seat").is_empty());
    untouched(&dispatcher, &engine, &held);
}

/// A `Replaces` naming no dialog here, and one naming a call nobody has
/// answered yet, are both 481 on the NOTIFY.
#[tokio::test(flavor = "multi_thread")]
async fn no_dialog_and_an_early_dialog_are_refused_481() {
    let engine = NativeTestEngine::start().await;
    let dispatcher = focus(&engine);
    let conference = conference_dialog(&dispatcher, "conf-481@192.0.2.10", SUBSCRIBER);
    let nowhere = Replaces {
        call_id: "nobody@192.0.2.99".into(),
        to_tag: "x".into(),
        from_tag: "y".into(),
        early_only: false,
    };
    let (status, sent) = merge(
        &dispatcher,
        &conference,
        request(&conference, nowhere, true),
    )
    .await;
    assert_eq!(status, 481);
    assert!(reported(&sent).starts_with("SIP/2.0 481 "));

    let held = subscriber_called_out(&dispatcher, &engine, "early", SUBSCRIBER);
    if let Some(mut call) = dispatcher
        .state
        .call_actors
        .get_call_mut(&held.internal_call_id)
    {
        call.winner = None;
        call.state = CallState::Ringing;
    }
    let (status, sent) = merge(
        &dispatcher,
        &conference,
        request(&conference, held.replaces_caller(), true),
    )
    .await;
    assert_eq!(status, 481);
    assert!(reported(&sent).starts_with("SIP/2.0 481 "));
    assert!(besides_the_report(&sent).is_empty());
    assert!(engine.commands("conference_seat").is_empty());
}

/// The engine refuses the seat (a full room): 488 on the NOTIFY, the call
/// relaying as it was, and the claim on it released.
#[tokio::test(flavor = "multi_thread")]
async fn a_seat_the_engine_refuses_is_488_and_leaves_the_call() {
    let engine = NativeTestEngine::start().await;
    let dispatcher = focus(&engine);
    let conference = conference_dialog(&dispatcher, "conf-488@192.0.2.10", SUBSCRIBER);
    let held = subscriber_called_out(&dispatcher, &engine, "full", SUBSCRIBER);
    let mut asked = request(&conference, held.replaces_caller(), true);
    asked.conference_id = "full-room".into();

    let (status, sent) = merge(&dispatcher, &conference, asked).await;
    assert_eq!(status, 488);
    assert!(reported(&sent).starts_with("SIP/2.0 488 "));
    assert!(besides_the_report(&sent).is_empty());
    assert_eq!(
        engine.commands("conference_seat").len(),
        1,
        "asked, and refused"
    );
    untouched(&dispatcher, &engine, &held);
    assert_eq!(
        crate::rtpengine::MediaBackend::seated_call_room(&held.a_call_id),
        None
    );
}

/// An engine that does not list `conference_seat` is never sent it: 501, and
/// no re-INVITE of the far party in its place.
#[tokio::test(flavor = "multi_thread")]
async fn an_engine_without_the_verb_is_501_and_nothing_is_sent() {
    let engine = NativeTestEngine::start_with_features(&["relay", "scope"]).await;
    let dispatcher = focus(&engine);
    let conference = conference_dialog(&dispatcher, "conf-501@192.0.2.10", SUBSCRIBER);
    let held = subscriber_called_out(&dispatcher, &engine, "old-engine", SUBSCRIBER);

    let (status, sent) = merge(
        &dispatcher,
        &conference,
        request(&conference, held.replaces_caller(), true),
    )
    .await;
    assert_eq!(status, 501);
    assert!(reported(&sent).starts_with("SIP/2.0 501 "));
    assert!(
        besides_the_report(&sent).is_empty(),
        "no re-INVITE of the far party"
    );
    assert!(engine.commands("conference_seat").is_empty());
    untouched(&dispatcher, &engine, &held);
}

/// The referrer hanging up its conference dialog ends the call it adopted:
/// the carrier gets a BYE with Q.850 cause 16, the engine call (and its seat)
/// is deleted, and the adoption bookkeeping drains.
#[tokio::test(flavor = "multi_thread")]
async fn the_conference_dialog_ending_ends_the_adopted_call() {
    let engine = NativeTestEngine::start().await;
    let dispatcher = focus(&engine);
    let state = &dispatcher.state;
    let conference = conference_dialog(&dispatcher, "conf-leave@192.0.2.10", SUBSCRIBER);
    let held = subscriber_called_out(&dispatcher, &engine, "owner-leaves", SUBSCRIBER);
    let (status, _) = merge(
        &dispatcher,
        &conference,
        request(&conference, held.replaces_caller(), true),
    )
    .await;
    assert_eq!(status, 200);

    caller_sends(state, &conference, "BYE", "3 BYE");
    let sent = drain(&dispatcher.udp);
    let to_carrier: Vec<&Sent> = sent
        .iter()
        .filter(|frame| frame.destination == socket(CARRIER))
        .collect();
    assert_eq!(to_carrier.len(), 1, "{sent:?}");
    assert!(to_carrier[0].is(Method::Bye));
    assert_eq!(header(&to_carrier[0].message, "Call-ID"), held.b_call_id);
    assert!(header(&to_carrier[0].message, "Reason").starts_with("Q.850;cause=16"));
    assert!(state.call_actors.get_call(&held.internal_call_id).is_none());
    assert!(
        eventually(|| !engine.holds(&held.a_call_id)).await,
        "the seat is deleted"
    );
    assert_eq!(state.call_actors.adoptions_len(), (0, 0));
    assert_eq!(
        crate::rtpengine::MediaBackend::seated_call_room(&held.a_call_id),
        None
    );
}

/// With `on_owner_leave="keep"` the adopted call stays in the room after the
/// conference dialog ends.
#[tokio::test(flavor = "multi_thread")]
async fn a_kept_call_outlives_the_conference_dialog() {
    let engine = NativeTestEngine::start().await;
    let dispatcher = focus(&engine);
    let state = &dispatcher.state;
    let conference = conference_dialog(&dispatcher, "conf-keep@192.0.2.10", SUBSCRIBER);
    let held = subscriber_called_out(&dispatcher, &engine, "kept", SUBSCRIBER);
    let (status, _) = merge(
        &dispatcher,
        &conference,
        request(&conference, held.replaces_caller(), false),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        state.call_actors.adoptions_len(),
        (0, 0),
        "nothing to end it by"
    );

    caller_sends(state, &conference, "BYE", "3 BYE");
    let sent = drain(&dispatcher.udp);
    assert!(
        sent.iter()
            .all(|frame| frame.destination != socket(CARRIER)),
        "{sent:?}"
    );
    assert!(state.call_actors.get_call(&held.internal_call_id).is_some());
    assert!(engine.holds(&held.a_call_id));
}

/// The carrier hanging up leaves the room carrying on: its BYE is answered,
/// nobody else is sent anything, the engine call (its seat) is deleted, and
/// the conference dialog stays.
#[tokio::test(flavor = "multi_thread")]
async fn the_far_party_hanging_up_leaves_the_room() {
    let engine = NativeTestEngine::start().await;
    let dispatcher = focus(&engine);
    let state = &dispatcher.state;
    let conference = conference_dialog(&dispatcher, "conf-farbye@192.0.2.10", SUBSCRIBER);
    let held = subscriber_called_out(&dispatcher, &engine, "far-bye", SUBSCRIBER);
    let (status, _) = merge(
        &dispatcher,
        &conference,
        request(&conference, held.replaces_caller(), true),
    )
    .await;
    assert_eq!(status, 200);

    let (inbound, message) = far_request(
        "BYE",
        2,
        &held.callee,
        &held.b_call_id,
        &held.b_local_tag,
        None,
    );
    tokio::task::block_in_place(|| handle_b2bua_bye(inbound, message, state));
    let sent = drain(&dispatcher.udp);
    assert_eq!(
        sent.len(),
        1,
        "the 200 to the carrier and nothing else: {sent:?}"
    );
    assert_eq!(sent[0].message.status_code(), Some(200));
    assert_eq!(sent[0].destination, socket(CARRIER));
    assert!(state.call_actors.get_call(&held.internal_call_id).is_none());
    assert!(
        eventually(|| !engine.holds(&held.a_call_id)).await,
        "the seat is deleted"
    );
    assert!(state
        .call_actors
        .get_call(&conference.internal_call_id)
        .is_some());
    assert_eq!(state.call_actors.adoptions_len(), (0, 0));
}

/// A session refresh from the carrier (its unchanged offer) is answered 200
/// with the session in force, here: no SIP to anyone else and nothing asked of
/// the engine, whose seat cannot be re-offered.
#[tokio::test(flavor = "multi_thread")]
async fn a_carrier_session_refresh_is_answered_with_the_unchanged_session() {
    let engine = NativeTestEngine::start().await;
    let dispatcher = focus(&engine);
    let state = &dispatcher.state;
    let conference = conference_dialog(&dispatcher, "conf-refresh@192.0.2.10", SUBSCRIBER);
    let held = subscriber_called_out(&dispatcher, &engine, "refresh", SUBSCRIBER);
    let (status, _) = merge(
        &dispatcher,
        &conference,
        request(&conference, held.replaces_caller(), true),
    )
    .await;
    assert_eq!(status, 200);
    let engine_commands_before = ["reoffer", "answer_local", "offer", "answer"]
        .iter()
        .map(|name| engine.commands(name).len())
        .sum::<usize>();

    let offer = sdp(host_of(CARRIER), 1);
    let (inbound, message) = far_request(
        "INVITE",
        3,
        &held.callee,
        &held.b_call_id,
        &held.b_local_tag,
        Some(&offer),
    );
    tokio::task::block_in_place(|| handle_b2bua_reinvite(inbound, message, state));
    let sent = drain(&dispatcher.udp);
    let finals: Vec<&Sent> = sent
        .iter()
        .filter(|frame| frame.message.status_code().is_some_and(|code| code >= 200))
        .collect();
    assert_eq!(finals.len(), 1, "{sent:?}");
    assert_eq!(finals[0].message.status_code(), Some(200));
    assert_eq!(finals[0].destination, socket(CARRIER));
    assert_eq!(
        finals[0].message.body, held.sent_to_callee,
        "the unchanged session"
    );
    assert!(sent
        .iter()
        .all(|frame| frame.destination == socket(CARRIER)));
    let engine_commands_after = ["reoffer", "answer_local", "offer", "answer"]
        .iter()
        .map(|name| engine.commands(name).len())
        .sum::<usize>();
    assert_eq!(engine_commands_before, engine_commands_after);
    assert!(state.call_actors.get_call(&held.internal_call_id).is_some());
}

/// The seat going silent ends the adopted call through its normal path: a BYE
/// to the carrier and the engine delete that frees the leg the engine kept.
#[tokio::test(flavor = "multi_thread")]
async fn a_silent_seat_ends_the_adopted_call() {
    let engine = NativeTestEngine::start().await;
    let dispatcher = focus(&engine);
    let state = &dispatcher.state;
    let conference = conference_dialog(&dispatcher, "conf-silent@192.0.2.10", SUBSCRIBER);
    let held = subscriber_was_called(&dispatcher, &engine, "silent", SUBSCRIBER);
    let (status, _) = merge(
        &dispatcher,
        &conference,
        request(&conference, held.replaces_callee(), true),
    )
    .await;
    assert_eq!(status, 200);

    assert!(!end_adopted_call_on_media_timeout(
        state,
        "not-a-call@192.0.2.99"
    ));
    assert!(end_adopted_call_on_media_timeout(state, &held.a_call_id));
    let sent = drain(&dispatcher.udp);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert!(sent[0].is(Method::Bye));
    assert_eq!(sent[0].destination, socket(CARRIER));
    assert!(header(&sent[0].message, "Reason").starts_with("Q.850;cause=102"));
    assert!(state.call_actors.get_call(&held.internal_call_id).is_none());
    assert!(eventually(|| !engine.holds(&held.a_call_id)).await);
    assert!(state
        .call_actors
        .get_call(&conference.internal_call_id)
        .is_some());
}

/// The script sees the facts siphon compares on `call.refer_replaces_call`.
#[tokio::test(flavor = "multi_thread")]
async fn the_script_reads_the_named_calls_facts() {
    let engine = NativeTestEngine::start().await;
    let dispatcher = focus_running(
        &engine,
        concat!(
            "from siphon import b2bua\n",
            "\n",
            "@b2bua.on_invite\n",
            "def on_invite(call):\n",
            "    pass\n",
            "\n",
            "@b2bua.on_refer\n",
            "def on_refer(call):\n",
            "    facts = call.refer_replaces_call\n",
            "    seen = (facts['leg'], facts['source'], facts['transport'], facts['auth_user'])\n",
            "    ok = seen == ('caller', '192.0.2.10:5060', 'udp', '1001') and 'sip:15550100001@' in facts['from_uri']\n",
            "    call.reject_refer(486 if ok else 500, 'Seen')\n",
        ),
    );
    let conference = conference_dialog(&dispatcher, "conf-facts@192.0.2.10", SUBSCRIBER);
    let held = subscriber_called_out(&dispatcher, &engine, "facts", SUBSCRIBER);
    dispatcher
        .state
        .call_actors
        .get_call_mut(&held.internal_call_id)
        .expect("the held call")
        .auth_user = Some("1001".into());
    let replaces = held.replaces_caller();
    let raw = format!(
        concat!(
            "REFER sip:conf-7@conf.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {address};branch=z9hG4bK-facts-refer\r\n",
            "Max-Forwards: 70\r\n",
            "From: {from}\r\n",
            "To: {to}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 2 REFER\r\n",
            "Contact: <sip:15550100001@{address}>\r\n",
            "Refer-To: <sip:15550100042@example.com?Replaces={replaces_call_id}%3Bto-tag%3D{to_tag}%3Bfrom-tag%3D{from_tag}>\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        address = conference.address,
        call_id = conference.call_id,
        from = conference.answer.headers.from().expect("a From"),
        to = conference.answer.headers.to().expect("a To"),
        replaces_call_id = replaces.call_id,
        to_tag = replaces.to_tag,
        from_tag = replaces.from_tag,
    );
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("the REFER parses");
    tokio::task::block_in_place(|| {
        handle_b2bua_refer_on(
            None,
            inbound(&conference.address, &raw),
            message,
            &dispatcher.state,
        )
    });
    let sent = drain(&dispatcher.udp);
    assert_eq!(
        sent.iter()
            .map(|frame| frame.message.status_code())
            .collect::<Vec<_>>(),
        vec![Some(486)],
        "the script read every fact"
    );
}

/// Leak gate: after merges that end every way an adopted call ends (the
/// conference dialog leaving, the far party hanging up, the seat going
/// silent), the adoption index, the seated-call map, the call store, the media
/// sessions and the engine all drain back to where they started.
#[tokio::test(flavor = "multi_thread")]
async fn adoption_bookkeeping_drains_to_baseline() {
    let engine = NativeTestEngine::start().await;
    let dispatcher = focus(&engine);
    let state = &dispatcher.state;
    let sessions = state.rtpengine_sessions.as_ref().expect("sessions");
    let calls_before = state.call_actors.count();
    let sessions_before = sessions.len();
    let held_before = engine.held_count();
    let mut engine_calls = Vec::new();

    for round in 0..12 {
        let conference = conference_dialog(
            &dispatcher,
            &format!("conf-leak-{round}@192.0.2.10"),
            SUBSCRIBER,
        );
        let held =
            subscriber_called_out(&dispatcher, &engine, &format!("leak-{round}"), SUBSCRIBER);
        let (status, _) = merge(
            &dispatcher,
            &conference,
            request(&conference, held.replaces_caller(), true),
        )
        .await;
        assert_eq!(status, 200);
        engine_calls.push(held.a_call_id.clone());
        match round % 3 {
            0 => {}
            1 => {
                let (inbound, message) = far_request(
                    "BYE",
                    2,
                    &held.callee,
                    &held.b_call_id,
                    &held.b_local_tag,
                    None,
                );
                tokio::task::block_in_place(|| handle_b2bua_bye(inbound, message, state));
            }
            _ => {
                assert!(end_adopted_call_on_media_timeout(state, &held.a_call_id));
            }
        }
        caller_sends(state, &conference, "BYE", "3 BYE");
        drain(&dispatcher.udp);
    }
    assert!(
        eventually(|| engine.held_count() == held_before).await,
        "every engine call deleted"
    );
    assert_eq!(state.call_actors.adoptions_len(), (0, 0));
    // The seated-call map is process-wide, so it is read by key: none of this
    // test's engine calls is left in it.
    assert!(engine_calls
        .iter()
        .all(|call| crate::rtpengine::MediaBackend::seated_call_room(call).is_none()));
    assert_eq!(state.call_actors.count(), calls_before);
    assert_eq!(sessions.len(), sessions_before);
}
