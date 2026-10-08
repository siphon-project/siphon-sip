//! What a `Replaces` takeover asks of the media engine, and what it answers
//! the newcomer with.
//!
//! The taking-over INVITE reaches `@b2bua.on_invite` like any other, so a
//! script that anchors its calls has already offered the newcomer's SDP to the
//! engine, under the profile it chose and the newcomer's own From-tag, before
//! the takeover runs. The INVITE then carries the engine's rewrite of that
//! offer, not the newcomer's own SDP. The takeover has to finish that session:
//! offering the rewritten SDP a second time presents the engine with an
//! offerer that has none of the newcomer's transport or keys, and the answer
//! it builds for the newcomer is one the newcomer cannot use.
//!
//! The answer also has to be to the offer in hand (RFC 3264 §6.1). The
//! survivor's last SDP is from the dialog that was replaced, and when that
//! call was on hold it says `inactive`.

use super::dialog_state_events_tests::{header, inbound, register, tag_of, wire};
use super::dialog_state_transfer_tests::{
    establish, host_of, invite, place, response_to_phone, sent_invite_to, Established,
};
use super::transfer_ingress_tests::{
    anchored, ip, profiles, sdp_naming, takeover, OPEN, PINS_ANSWERER,
};
use super::*;
use crate::rtpengine::test_native_engine::{NativeCommand, NativeTestEngine};

const NEWCOMER: &str = "192.0.2.245:5060";
const NEWCOMER_TAG: &str = "newcomer-tag";

/// Every command of kind `name` the engine was sent on `engine_call_id`.
fn sent_on(engine: &NativeTestEngine, name: &str, engine_call_id: &str) -> Vec<NativeCommand> {
    engine
        .commands(name)
        .into_iter()
        .filter(|command| command.call_id == engine_call_id)
        .collect()
}

fn sessions(call: &Established) -> Arc<crate::rtpengine::MediaSessionStore> {
    call.dispatcher
        .state
        .rtpengine_sessions
        .clone()
        .expect("a session store")
}

/// The newcomer is anchored under the tag it is known by everywhere else: its
/// own From-tag, which is what a script's `rtpengine.answer(call)` and
/// `rtpengine.delete(call)` address it by. siphon's own tag on that dialog
/// names nobody the engine has heard of.
#[tokio::test(flavor = "multi_thread")]
async fn a_takeover_anchors_the_newcomer_under_its_own_from_tag() {
    let engine = NativeTestEngine::start().await;
    let call = anchored(47000, &engine, OPEN).await;

    let fresh = takeover(&call, 47000, NEWCOMER);

    let offers = sent_on(&engine, "offer", &fresh);
    assert_eq!(offers.len(), 1, "one offer on the fresh call: {offers:?}");
    assert_eq!(offers[0].from_tag, NEWCOMER_TAG);
    let answers = sent_on(&engine, "answer", &fresh);
    assert_eq!(
        answers.len(),
        1,
        "one answer on the fresh call: {answers:?}"
    );
    assert_eq!(answers[0].from_tag, NEWCOMER_TAG);
    let session = sessions(&call).get(&fresh).expect("the pair's session");
    assert_eq!(session.from_tag, NEWCOMER_TAG);
    assert_eq!(session.to_tag.as_deref(), Some("a-tag"));
}

/// A newcomer the script already anchored, arriving as a call of its own with
/// the engine's rewrite of its offer in the INVITE. Returns its internal call
/// id, the INVITE, where it came from, and the rewritten offer.
async fn anchored_newcomer(
    call: &Established,
    engine: &NativeTestEngine,
    newcomer_call_id: &str,
    profile: &str,
) -> (String, SipMessage, InboundMessage, Vec<u8>) {
    let registry = profiles();
    let entry = registry.get(profile).expect("a known profile");
    let rewritten = engine
        .backend()
        .offer(
            newcomer_call_id,
            NEWCOMER_TAG,
            sdp_naming(host_of(NEWCOMER)).as_bytes(),
            &entry.offer,
        )
        .await
        .expect("the engine takes the newcomer's offer");
    sessions(call).insert(crate::rtpengine::session::MediaSession {
        call_id: newcomer_call_id.to_string(),
        rtpengine_call_id: newcomer_call_id.to_string(),
        from_tag: NEWCOMER_TAG.to_string(),
        to_tag: None,
        profile: profile.to_string(),
        ws_uri: None,
        ws_tee: None,
        ws_bridge_attached: false,
        bridge_sides: None,
        created_at: std::time::Instant::now(),
    });

    let leg = Leg::new_a_leg(
        newcomer_call_id.to_string(),
        NEWCOMER_TAG.to_string(),
        "z9hG4bK-newcomer".to_string(),
        LegTransport {
            remote_addr: NEWCOMER.parse().expect("a literal address"),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    );
    let new_call_id = call.dispatcher.state.call_actors.create_call(leg);
    let body = String::from_utf8(rewritten.clone()).expect("the engine answers in text");
    let raw = format!(
        concat!(
            "INVITE sip:takeover@siphon.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {newcomer};branch=z9hG4bK-newcomer\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:newcomer@example.com>;tag={tag}\r\n",
            "To: <sip:takeover@siphon.example.com>\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:newcomer@{newcomer}>\r\n",
            "Content-Type: application/sdp\r\n",
            "Content-Length: {length}\r\n",
            "\r\n",
            "{body}",
        ),
        newcomer = NEWCOMER,
        tag = NEWCOMER_TAG,
        call_id = newcomer_call_id,
        length = body.len(),
        body = body,
    );
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("the newcomer's INVITE parses");
    call.dispatcher.state.call_actors.set_a_leg_invite(
        &new_call_id,
        Arc::new(std::sync::Mutex::new(message.clone())),
    );
    (new_call_id, message, inbound(NEWCOMER, &raw), rewritten)
}

/// The script anchored the taking-over INVITE before the takeover ran. The
/// takeover completes that session: no second offer, the answer on the
/// script's session under the profile the script named for the new pair, and
/// the survivor re-INVITEd with the offer the script's anchoring produced.
#[tokio::test(flavor = "multi_thread")]
async fn a_takeover_of_a_newcomer_the_script_anchored_completes_that_session() {
    const NEWCOMER_CALL_ID: &str = "takeover-47010@192.0.2.245";
    let engine = NativeTestEngine::start().await;
    // The call being taken over was set up under a profile that pins nobody,
    // the newcomer under one that pins the answering party. Which of the two
    // shaped the takeover shows in the survivor's hint.
    let call = anchored(47010, &engine, OPEN).await;
    let state = &call.dispatcher.state;
    let (new_call_id, message, source, rewritten) =
        anchored_newcomer(&call, &engine, NEWCOMER_CALL_ID, PINS_ANSWERER).await;

    tokio::task::block_in_place(|| {
        b2bua_bridge_inbound_replaces(
            &source,
            &message,
            &new_call_id,
            &crate::b2bua::actor::PendingReplaces {
                replaced_call_id: call.call_id(),
                replaced_on_a_leg: false,
                early_only: false,
            },
            state,
        )
    });

    let offers = sent_on(&engine, "offer", NEWCOMER_CALL_ID);
    assert_eq!(
        offers.len(),
        1,
        "the script's offer and no second one: {offers:?}"
    );
    let answers = sent_on(&engine, "answer", NEWCOMER_CALL_ID);
    assert_eq!(answers.len(), 1, "one answer: {answers:?}");
    assert_eq!(answers[0].from_tag, NEWCOMER_TAG);
    assert_eq!(
        answers[0].received_from,
        Some(ip(call.a.1)),
        "the survivor answers under the profile named for the new pair"
    );

    let store = sessions(&call);
    let session = store.get(NEWCOMER_CALL_ID).expect("the pair's session");
    assert_eq!(session.profile, PINS_ANSWERER);
    assert_eq!(session.from_tag, NEWCOMER_TAG);
    assert_eq!(session.to_tag.as_deref(), Some("a-tag"));
    assert!(
        store.get(&call.a_call_id).is_none(),
        "the replaced pair's session is gone"
    );
    assert!(!engine.holds(&call.a_call_id), "and its engine call");
    assert!(
        engine.holds(NEWCOMER_CALL_ID),
        "positive control: the pair's is kept"
    );

    let sent = wire(&call.dispatcher);
    // siphon owns `o=` and `s=` toward each leg; what the engine wrote is
    // everything from the connection line on.
    let from_connection = |body: &[u8]| {
        let text = String::from_utf8_lossy(body).to_string();
        text.find("c=")
            .map(|at| text[at..].to_string())
            .expect("a connection line")
    };
    let reinvite = sent_invite_to(&sent, call.a.1);
    assert_eq!(
        from_connection(&reinvite.body),
        from_connection(&rewritten),
        "the survivor is offered what the script's anchoring produced"
    );
    let _ = response_to_phone(&sent, NEWCOMER, 200);
}

const HELD: &str = concat!(
    "v=0\r\n",
    "o=- 1 2 IN IP4 192.0.2.10\r\n",
    "s=-\r\n",
    "c=IN IP4 192.0.2.10\r\n",
    "t=0 0\r\n",
    "m=audio 40000 RTP/AVP 0\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
    "a=inactive\r\n",
);

/// The call being taken over was on hold, so the survivor's last SDP says
/// `inactive`. The newcomer offers a stream both ways and is answered one
/// (RFC 3264 §6.1): the hold belonged to the dialog that was replaced.
#[tokio::test(flavor = "multi_thread")]
async fn a_takeover_of_a_held_call_answers_the_newcomer_off_hold() {
    let call = establish(47020, "terminate");
    let state = &call.dispatcher.state;
    // The callee is replaced, the caller survives: its last SDP is the hold.
    state
        .call_actors
        .set_leg_last_sdp(&call.call_id(), true, HELD.as_bytes());
    let _ = wire(&call.dispatcher);

    let aor = "sip:47024@example.com";
    register(aor, NEWCOMER);
    let siphon_tag = tag_of(&header(&call.to_b, "From"));
    place(
        &call.dispatcher,
        NEWCOMER,
        &invite(
            NEWCOMER,
            "takeover-47020@192.0.2.245",
            &format!("<{aor}>;tag={NEWCOMER_TAG}"),
            "sip:takeover@siphon.example.com",
            &format!(
                "Replaces: {};to-tag={siphon_tag};from-tag=b-tag\r\n",
                header(&call.to_b, "Call-ID")
            ),
        ),
    );

    let accepted = response_to_phone(&wire(&call.dispatcher), NEWCOMER, 200);
    let body = String::from_utf8_lossy(&accepted.body).to_string();
    assert!(
        !body.contains("a=inactive"),
        "the answer is on hold: {body}"
    );
    assert!(body.contains("a=sendrecv"), "the answer: {body}");
}
