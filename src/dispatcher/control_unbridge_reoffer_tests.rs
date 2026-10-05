//! A re-INVITE or an UPDATE from a leg an `unbridge` parted from its pair.
//!
//! The two legs are held, and the pair's media session and its engine call
//! stay as the bridge left them: stored under the anchor, relaying between
//! the two, so a second `bridge` renegotiates it in place. Neither leg has a
//! session the engine could answer a re-offer from on its own. The anchor's
//! is the pair's, where a local answer would write a one-party call over the
//! relay; the other leg's was retired when the bridge formed.
//!
//! So a parted leg is answered from what its dialog already has:
//!
//! * a request that changes nothing (no SDP, or the SDP the leg last sent,
//!   told by its `o=` line, RFC 3264 §8) is a session refresh and is answered
//!   `200` with the session in force on the dialog;
//! * an offer that would change the session is refused `488` (RFC 3261
//!   §14.2), which leaves the session as it was (§14.1).
//!
//! Neither sends the engine anything, and neither reaches the other leg.

use super::control_bridge_ingress_tests::{OPEN_PLAIN, PINNED_SECURE};
use super::control_bridge_media_tests::host;
use super::control_rebridge_tests::{legs, Legs};
use super::dial_bridge_test_harness::{assert_drained, caller_sends, eventually, Caller};
use super::originate_test_harness::{drain, phone_offer, socket, Sent};
use super::*;

/// Every media command the engine has been sent, by kind.
fn engine_commands(legs: &Legs) -> Vec<usize> {
    ["answer_local", "offer", "reoffer", "answer", "delete"]
        .into_iter()
        .map(|name| legs.engine.commands(name).len())
        .collect()
}

/// `leg` sends `method` in its dialog, with `body` as its SDP. Returns what
/// siphon sent in reply, to anybody.
fn leg_sends(legs: &Legs, leg: &Caller, method: &str, cseq: u32, body: Option<&str>) -> Vec<Sent> {
    let content = match body {
        Some(body) => format!(
            "Content-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        ),
        None => "Content-Length: 0\r\n\r\n".to_string(),
    };
    let raw = format!(
        concat!(
            "{method} sip:192.0.2.1:5060;transport=udp SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {address};branch=z9hG4bK-parted-{method}-{cseq}\r\n",
            "Max-Forwards: 70\r\n",
            "From: {from}\r\n",
            "To: {to}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: {cseq} {method}\r\n",
            "Contact: <sip:15550100001@{address}>\r\n",
            "{content}",
        ),
        method = method,
        address = leg.address,
        cseq = cseq,
        from = leg.answer.headers.from().expect("a From"),
        to = leg.answer.headers.to().expect("a To"),
        call_id = leg.call_id,
        content = content,
    );
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("the request parses");
    let inbound = InboundMessage {
        client_transport: None,
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: socket("192.0.2.1:5060"),
        remote_addr: socket(&leg.address),
        data: Bytes::from(raw),
    };
    drain(legs.udp());
    tokio::task::block_in_place(|| match method {
        "INVITE" => handle_b2bua_reinvite(inbound, message, legs.state()),
        "UPDATE" => handle_b2bua_update(inbound, message, legs.state()),
        other => panic!("no {other} in these tests"),
    });
    drain(legs.udp())
}

/// The one final response among `sent`, which went to `leg`.
fn final_to<'a>(sent: &'a [Sent], leg: &Caller) -> &'a SipMessage {
    let finals: Vec<&Sent> = sent
        .iter()
        .filter(|frame| frame.message.status_code().is_some_and(|code| code >= 200))
        .collect();
    assert_eq!(finals.len(), 1, "one final response");
    assert_eq!(finals[0].destination, socket(&leg.address));
    &finals[0].message
}

/// The leg's own description of its media, as the leg last gave it.
fn last_sdp(legs: &Legs, leg: &Caller) -> Option<Vec<u8>> {
    legs.state()
        .call_actors
        .get_call(&leg.internal_call_id)
        .and_then(|call| call.a_leg.last_sdp.clone())
}

/// The session description in force on the leg's dialog: what siphon last
/// sent it and it accepted.
fn in_force(legs: &Legs, leg: &Caller) -> Vec<u8> {
    legs.state()
        .call_actors
        .get_call(&leg.internal_call_id)
        .and_then(|call| call.a_leg.dialog.last_sent_sdp.clone())
        .expect("a session in force")
}

/// A hold of the leg's own: the media it has, `sendonly`, as a new version of
/// its session.
fn hold_from(leg: &Caller) -> String {
    phone_offer(host(&leg.address))
        .replace("a=sendrecv", "a=sendonly")
        .replace("o=phone 4001 4001 ", "o=phone 4001 4002 ")
}

/// A pair bridged and parted, both legs held.
async fn parted(app: &str, peer_address: &str) -> Legs {
    let legs = legs(app, peer_address, OPEN_PLAIN, PINNED_SECURE).await;
    legs.bridge("anchor", "peer").await;
    legs.unbridge().await;
    legs
}

/// A hold from either parted leg, as a re-INVITE or an UPDATE, would change
/// its session. It is refused `488`: the engine is sent nothing (on the
/// anchor a local answer would land on the pair's own engine call), the other
/// leg hears nothing, and the refused offer is not taken for the leg's media.
/// The pair is then bridged again on the engine call it still holds.
#[tokio::test(flavor = "multi_thread")]
async fn a_changed_offer_from_a_parted_leg_is_refused_and_reaches_neither_the_engine_nor_the_peer()
{
    const PEER: &str = "198.51.100.221:5060";
    let legs = parted("parted-hold", PEER).await;
    let pair = legs
        .state()
        .rtpengine_sessions
        .as_ref()
        .and_then(|store| store.get(&legs.anchor.call_id))
        .expect("the pair's session")
        .rtpengine_id()
        .to_string();
    let mut cseq = 20;
    for (leg, other) in [(&legs.anchor, &legs.peer), (&legs.peer, &legs.anchor)] {
        for method in ["INVITE", "UPDATE"] {
            cseq += 1;
            let what = format!("{method} from {}", leg.address);
            let before = engine_commands(&legs);
            let media_before = last_sdp(&legs, leg);
            let session_before = in_force(&legs, leg);

            let sent = leg_sends(&legs, leg, method, cseq, Some(&hold_from(leg)));
            assert_eq!(final_to(&sent, leg).status_code(), Some(488), "{what}");
            assert_eq!(
                engine_commands(&legs),
                before,
                "{what}: the engine is sent nothing: {:?}",
                legs.engine.commands("answer_local")
            );
            assert!(
                sent.iter()
                    .all(|frame| frame.destination != socket(&other.address)),
                "{what}: nothing reaches the other leg"
            );
            assert_eq!(last_sdp(&legs, leg), media_before, "{what}");
            assert_eq!(in_force(&legs, leg), session_before, "{what}");
        }
    }

    // The pair's engine call is as the first bridge left it.
    assert!(legs.engine.holds(&pair));
    legs.bridge("anchor", "peer").await;
    let reoffers = legs.engine.commands("reoffer");
    assert_eq!(reoffers.len(), 1, "{reoffers:?}");
    assert_eq!(reoffers[0].call_id, pair);

    caller_sends(legs.state(), &legs.anchor, "BYE", "40 BYE");
    assert!(eventually(|| legs.state().call_actors.count() == 0).await);
    assert!(eventually(|| legs.engine.held_count() == 0).await);
    assert_drained(legs.state());
}

/// A request that changes nothing is a session refresh (RFC 4028 §10): no
/// SDP, or the SDP the leg last sent. Either parted leg is answered `200`
/// with the session in force on its dialog, which is the hold siphon put it
/// on: a re-INVITE's 2xx has to carry it (RFC 3261 §14.2), an UPDATE with no
/// offer needs no body. The engine is sent nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_from_a_parted_leg_is_answered_from_the_session_in_force() {
    const PEER: &str = "198.51.100.222:5060";
    let legs = parted("parted-refresh", PEER).await;
    let before = engine_commands(&legs);
    let mut cseq = 20;
    for leg in [&legs.anchor, &legs.peer] {
        let held = in_force(&legs, leg);
        assert!(
            String::from_utf8_lossy(&held).contains("a=sendonly"),
            "positive control: the leg is held"
        );
        let unchanged = String::from_utf8(last_sdp(&legs, leg).expect("the leg's media"))
            .expect("an SDP is text");
        for (method, body, answered_with_the_session) in [
            ("INVITE", None, true),
            ("UPDATE", None, false),
            ("INVITE", Some(unchanged.as_str()), true),
            ("UPDATE", Some(unchanged.as_str()), true),
        ] {
            cseq += 1;
            let what = format!(
                "{method} from {}, with SDP: {}",
                leg.address,
                body.is_some()
            );
            let sent = leg_sends(&legs, leg, method, cseq, body);
            let answer = final_to(&sent, leg);
            assert_eq!(answer.status_code(), Some(200), "{what}");
            if answered_with_the_session {
                assert_eq!(answer.body, held, "{what}: the session in force");
            } else {
                assert!(answer.body.is_empty(), "{what}");
            }
            assert_eq!(engine_commands(&legs), before, "{what}");
        }
    }

    // The legs are parted: each ends on its own, and the pair's engine call
    // goes with the anchor that holds it.
    caller_sends(legs.state(), &legs.peer, "BYE", "40 BYE");
    assert!(eventually(|| legs.state().call_actors.count() == 1).await);
    caller_sends(legs.state(), &legs.anchor, "BYE", "41 BYE");
    assert!(eventually(|| legs.state().call_actors.count() == 0).await);
    assert!(eventually(|| legs.engine.held_count() == 0).await);
    assert_drained(legs.state());
}
