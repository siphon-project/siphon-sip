//! A teardown that lands while the media engine is still making or taking an
//! offer for a caller whose INVITE carried no SDP: the allocation it ends up
//! with must not outlive the call.

use super::delayed_offer_answer_tests::OfferlessCall;
use super::originate_test_harness::socket;
use super::*;
use crate::rtpengine::test_native_engine::NativeTestEngine;

/// A hang-up that lands while the engine is still making the offer finds no
/// session yet. The offer then completes: nothing may be left on the engine or
/// in the session store, and no 2xx goes to a call that is gone.
#[tokio::test(flavor = "multi_thread")]
async fn a_teardown_while_offer_local_is_in_flight_leaves_nothing_behind() {
    let call = Arc::new(OfferlessCall::park(
        NativeTestEngine::start_with_offer_local().await,
        "dly-race-1",
    ));
    call.engine.hold_answers();
    let answering = {
        let call = Arc::clone(&call);
        tokio::task::spawn_blocking(move || call.answer("rtp_passthrough", None))
    };
    // The engine has the command and the call; its answer is held.
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while call.engine.commands("offer_local").is_empty() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the engine was sent the offer_local");
    assert!(b2bua_terminate_call_inner(
        &call.call_id,
        None,
        "b2bua",
        &call.state
    ));
    call.engine.release_answers();
    let outcome = answering.await.expect("the answer ran");
    assert!(outcome.is_err(), "no answer for a call that is gone");
    assert!(call
        .wire()
        .iter()
        .all(|sent| sent.message.status_code() != Some(200)));
    call.deleted(1).await;
    let sessions = call.state.rtpengine_sessions.as_ref().expect("sessions");
    assert!(sessions.get("dly-race-1").is_none());
    assert_eq!(call.engine.held_count(), 0);
    assert_eq!(call.engine.offer_local_pending_count(), 0);
}

/// The same race on a connecting `dial` whose caller sent no SDP: the phone's
/// 2xx offer is anchored on the engine (`offer`) while the caller hangs up.
#[tokio::test(flavor = "multi_thread")]
async fn a_teardown_while_a_delayed_dial_anchors_leaves_nothing_behind() {
    let call = Arc::new(OfferlessCall::park(
        NativeTestEngine::start_with_offer_local().await,
        "dly-race-2",
    ));
    let phone = "198.51.100.7:5060";
    assert!(b2bua_dial_call_with_state(
        "dly-race-2",
        vec![DialTarget {
            uri: format!("sip:201@{phone}"),
            ..Default::default()
        }],
        true,
        30,
        &[],
        &DialShaping {
            profile: Some("rtp_to_srtp".to_string()),
            ..Default::default()
        },
        &call.state,
    )
    .expect("the dial is placed"));
    let invite = call
        .wire()
        .into_iter()
        .find(|sent| sent.message.method() == Some(&Method::Invite))
        .expect("the phone is rung")
        .message;
    let header = |name: &str| invite.headers.get(name).expect("a header").to_string();
    let offer = concat!(
        "v=0\r\n",
        "o=phone 7 7 IN IP4 198.51.100.7\r\n",
        "s=-\r\n",
        "c=IN IP4 198.51.100.7\r\n",
        "t=0 0\r\n",
        "m=audio 30000 RTP/AVP 0 101\r\n",
        "a=rtpmap:0 PCMU/8000\r\n",
        "a=rtpmap:101 telephone-event/8000\r\n",
    );
    let raw = format!(
        concat!(
            "SIP/2.0 200 OK\r\nVia: {via}\r\nFrom: {from}\r\nTo: {to};tag=phone-tag\r\n",
            "Call-ID: {call_id}\r\nCSeq: {cseq}\r\nContact: <sip:201@198.51.100.7:5060>\r\n",
            "Content-Type: application/sdp\r\nContent-Length: {length}\r\n\r\n{offer}"
        ),
        via = header("Via"),
        from = header("From"),
        to = header("To"),
        call_id = header("Call-ID"),
        cseq = header("CSeq"),
        length = offer.len(),
        offer = offer,
    );
    let mut response = parse_sip_message_bytes(raw.as_bytes()).expect("the 200 parses");
    let branch = super::lcr_ring_timeout_tests::top_via_branch(&invite);

    call.engine.hold_answers();
    let answering = {
        let call = Arc::clone(&call);
        tokio::task::spawn_blocking(move || {
            handle_b2bua_response(
                &call.call_id,
                &branch,
                &mut response,
                200,
                socket(phone),
                &call.state,
            )
        })
    };
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while call.engine.commands("offer").is_empty() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the engine was sent the offer");
    assert!(b2bua_terminate_call_inner(
        &call.call_id,
        None,
        "b2bua",
        &call.state
    ));
    call.engine.release_answers();
    let _ = answering.await.expect("the response ran");
    call.deleted(1).await;
    let sessions = call.state.rtpengine_sessions.as_ref().expect("sessions");
    assert!(sessions.get("dly-race-2").is_none());
    assert_eq!(call.engine.held_count(), 0, "the engine call was deleted");
}

/// A CANCEL that lands while the engine is still making the offer ends the
/// call with a 487. The offer then completes: the allocation is released, and
/// no 2xx follows the 487 on the same INVITE.
#[tokio::test(flavor = "multi_thread")]
async fn a_cancel_while_offer_local_is_in_flight_releases_the_allocation_and_sends_no_2xx() {
    let call = Arc::new(OfferlessCall::park(
        NativeTestEngine::start_with_offer_local().await,
        "dly-race-3",
    ));
    call.engine.hold_answers();
    let answering = {
        let call = Arc::clone(&call);
        tokio::task::spawn_blocking(move || call.answer("rtp_passthrough", None))
    };
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while call.engine.commands("offer_local").is_empty() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the engine was sent the offer_local");

    let raw = concat!(
        "CANCEL sip:4000@siphon.example.com SIP/2.0\r\n",
        "Via: SIP/2.0/UDP 192.0.2.40:5060;branch=z9hG4bK-dly-race-3\r\n",
        "Max-Forwards: 70\r\n",
        "From: \"Caller One\" <sip:15550100001@siphon.example.com>;tag=caller-tag\r\n",
        "To: <sip:4000@siphon.example.com>\r\n",
        "Call-ID: dly-race-3\r\n",
        "CSeq: 1 CANCEL\r\n",
        "Content-Length: 0\r\n\r\n",
    );
    let inbound = InboundMessage {
        client_transport: None,
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: socket("192.0.2.1:5060"),
        remote_addr: socket("192.0.2.40:5060"),
        data: Bytes::from(raw),
    };
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("the CANCEL parses");
    tokio::task::block_in_place(|| handle_b2bua_cancel(inbound, message, &call.state));

    call.engine.release_answers();
    let outcome = answering.await.expect("the answer ran");
    assert!(outcome.is_err(), "no answer for a cancelled call");
    let statuses: Vec<_> = call
        .wire()
        .iter()
        .filter_map(|sent| sent.message.status_code())
        .collect();
    assert!(
        statuses.contains(&487),
        "the INVITE is answered 487: {statuses:?}"
    );
    assert!(
        !statuses.contains(&200) || statuses.iter().filter(|c| **c == 200).count() == 1,
        "only the CANCEL's own 200: {statuses:?}"
    );
    assert!(
        call.wire().iter().all(|sent| sent.message.body.is_empty()),
        "no SDP-carrying 2xx"
    );
    call.deleted(1).await;
    let sessions = call.state.rtpengine_sessions.as_ref().expect("sessions");
    assert!(sessions.get("dly-race-3").is_none());
    assert_eq!(call.engine.held_count(), 0);
    assert_eq!(call.engine.offer_local_pending_count(), 0);
}

/// The window inside a CANCEL: it has claimed the call and answered the INVITE
/// 487, and the call is not yet removed. An offer completing then must not
/// become a 2xx after that 487, and its allocation is released.
#[tokio::test(flavor = "multi_thread")]
async fn an_offer_completing_inside_a_cancel_sends_no_2xx_after_the_487() {
    let call = Arc::new(OfferlessCall::park(
        NativeTestEngine::start_with_offer_local().await,
        "dly-race-5",
    ));
    call.engine.hold_answers();
    let answering = {
        let call = Arc::clone(&call);
        tokio::task::spawn_blocking(move || call.answer("rtp_passthrough", None))
    };
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while call.engine.commands("offer_local").is_empty() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the engine was sent the offer_local");
    call.state
        .call_actors
        .get_call_mut(&call.call_id)
        .expect("the call")
        .cancel_claimed = true;
    call.engine.release_answers();
    let outcome = answering.await.expect("the answer ran");
    assert!(outcome.is_err(), "no answer for a call being cancelled");
    assert!(
        call.wire().iter().all(|sent| sent.message.body.is_empty()),
        "no 2xx carrying the offer"
    );
    call.deleted(1).await;
    let sessions = call.state.rtpengine_sessions.as_ref().expect("sessions");
    assert!(sessions.get("dly-race-5").is_none());
    assert_eq!(call.engine.held_count(), 0);
    assert_eq!(call.state.call_actors.pending_local_offer_count(), 0);
}
