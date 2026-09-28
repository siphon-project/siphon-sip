//! `dial {on_answer: "bridge"}` keeps an answer only once the phone is bridged.
//!
//! Until then every other phone rings on, a phone that answers meanwhile waits
//! as a standby, and a bridge that fails hangs its phone up and lets the dial
//! carry on: the phones still ringing, the standbys in answer order, the next
//! target of a sequential dial. Driven as the other bridge dial tests are, off
//! the egress channel and the controller's event stream.

use super::dial_bridge_test_harness::{
    answered_caller, assert_drained, bridging_dispatcher, controller_owning, dial, events,
    in_dialog_response, invite_to, names, register, reinvites_to, sent_until, CALLER,
};
use super::originate_test_harness::{
    drain, phone_offer, phone_response, phone_sends, requests_to, socket, Sent,
};
use super::*;
use crate::rtpengine::test_native_engine::NativeTestEngine;

/// `phone` answers `invite` with an offer of its own.
fn answers(state: &DispatcherState, phone: &str, invite: &SipMessage, contact: &str) {
    let host = phone.split(':').next().unwrap_or(phone);
    phone_sends(
        state,
        socket(phone),
        &phone_response(
            invite,
            200,
            "OK",
            &format!("tag-{host}"),
            contact,
            Some(&phone_offer(host)),
        ),
    );
}

/// The bridge's re-INVITE to `phone`, waited for.
async fn bridge_offer_to(
    udp: &flume::Receiver<OutboundMessage>,
    phone: &str,
) -> (SipMessage, Vec<Sent>) {
    let sent = sent_until(udp, |sent| !reinvites_to(sent, phone).is_empty()).await;
    let offer = reinvites_to(&sent, phone)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("a bridge re-INVITE to {phone}"));
    (offer, sent)
}

/// `phone` refuses the bridge's re-INVITE `offer`.
fn refuses(state: &DispatcherState, phone: &str, offer: &SipMessage, contact: &str) {
    phone_sends(
        state,
        socket(phone),
        &in_dialog_response(offer, 488, "Not Acceptable Here", contact, None),
    );
}

/// `phone` accepts the bridge's `offer`, and the caller the re-INVITE that
/// follows: the bridge forms. Returns what siphon sent meanwhile.
async fn bridge_forms(
    state: &DispatcherState,
    udp: &flume::Receiver<OutboundMessage>,
    phone: &str,
    offer: &SipMessage,
    contact: &str,
) -> Vec<Sent> {
    let host = phone.split(':').next().unwrap_or(phone);
    phone_sends(
        state,
        socket(phone),
        &in_dialog_response(offer, 200, "OK", contact, Some(&phone_offer(host))),
    );
    let mut sent = sent_until(udp, |sent| !reinvites_to(sent, CALLER).is_empty()).await;
    let to_caller = reinvites_to(&sent, CALLER)
        .into_iter()
        .next()
        .expect("the bridge re-INVITEs the caller");
    phone_sends(
        state,
        socket(CALLER),
        &in_dialog_response(
            &to_caller,
            200,
            "OK",
            "sip:15550100001@192.0.2.10:5060",
            Some(&phone_offer("192.0.2.10")),
        ),
    );
    sent.extend(drain(udp));
    sent
}

/// The phone the bridge failed on is hung up, and the one still ringing is
/// not CANCELled: it answers next and is the one bridged and reported.
#[tokio::test(flavor = "multi_thread")]
async fn a_phone_still_ringing_is_bridged_when_the_first_bridge_fails() {
    const DESK: &str = "198.51.100.211:5060";
    const MOBILE: &str = "198.51.100.212:5060";
    let aor = "sip:fb3401@siphon.example.com";
    let (desk_contact, mobile_contact) =
        (format!("sip:fb3401@{DESK}"), format!("sip:fb3401@{MOBILE}"));
    register(aor, &desk_contact, 1.0);
    register(aor, &mobile_contact, 0.5);
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "fallback-ringing@192.0.2.10");
    let controller =
        controller_owning("fallback-ringing", dispatcher, &caller, "ringing", "hangup");
    let state = &controller.dispatcher.state;
    let udp = &controller.dispatcher.udp;
    let (reply, _) = dial(
        &controller,
        "ringing",
        serde_json::json!({ "targets": [{ "aor": aor }], "on_answer": "bridge" }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let sent = drain(udp);
    let (desk, mobile) = (invite_to(&sent, DESK), invite_to(&sent, MOBILE));

    // The mobile answers; its bridge is refused.
    answers(state, MOBILE, &mobile, &mobile_contact);
    let (offer, sent) = bridge_offer_to(udp, MOBILE).await;
    assert!(requests_to(&sent, socket(DESK), Method::Cancel).is_empty());
    refuses(state, MOBILE, &offer, &mobile_contact);
    let sent = drain(udp);
    let bye = requests_to(&sent, socket(MOBILE), Method::Bye);
    assert_eq!(bye.len(), 1, "the mobile is hung up");
    assert!(bye[0]
        .message
        .headers
        .get("Reason")
        .is_some_and(|reason| reason.contains("cause=41")));
    assert!(
        requests_to(&sent, socket(DESK), Method::Cancel).is_empty(),
        "the desk is still ringing"
    );
    let heard = events(&controller).await;
    assert_eq!(names(&heard), ["DialBranchFailed"], "and the dial goes on");
    assert_eq!(heard[0].payload["target"], mobile_contact);
    assert_eq!(heard[0].payload["cause"], "bridge_failed");

    // The desk answers and is bridged.
    answers(state, DESK, &desk, &desk_contact);
    let (offer, _) = bridge_offer_to(udp, DESK).await;
    bridge_forms(state, udp, DESK, &offer, &desk_contact).await;
    let heard = events(&controller).await;
    assert_eq!(names(&heard), ["DialAnswered"]);
    assert_eq!(heard[0].payload["target"], desk_contact);
    assert!(heard[0].payload["channel"].is_string());
    assert_drained(state);
}

/// A phone that answers while another's bridge is in motion is ACKed and held:
/// not bridged, not reported. When that bridge fails it is bridged next.
#[tokio::test(flavor = "multi_thread")]
async fn a_standby_is_bridged_after_the_first_bridge_fails() {
    const DESK: &str = "198.51.100.213:5060";
    const MOBILE: &str = "198.51.100.214:5060";
    let aor = "sip:fb3402@siphon.example.com";
    let (desk_contact, mobile_contact) =
        (format!("sip:fb3402@{DESK}"), format!("sip:fb3402@{MOBILE}"));
    register(aor, &desk_contact, 1.0);
    register(aor, &mobile_contact, 0.5);
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "fallback-standby@192.0.2.10");
    let controller =
        controller_owning("fallback-standby", dispatcher, &caller, "standby", "hangup");
    let state = &controller.dispatcher.state;
    let udp = &controller.dispatcher.udp;
    let (reply, _) = dial(
        &controller,
        "standby",
        serde_json::json!({ "targets": [{ "aor": aor }], "on_answer": "bridge" }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let sent = drain(udp);
    let (desk, mobile) = (invite_to(&sent, DESK), invite_to(&sent, MOBILE));

    answers(state, MOBILE, &mobile, &mobile_contact);
    let (mobile_offer, _) = bridge_offer_to(udp, MOBILE).await;
    // The desk answers while the mobile's bridge is in motion: ACKed with the
    // engine's answer, like a winner, but not offered a bridge.
    answers(state, DESK, &desk, &desk_contact);
    let sent = sent_until(udp, |sent| {
        !requests_to(sent, socket(DESK), Method::Ack).is_empty()
    })
    .await;
    assert_eq!(requests_to(&sent, socket(DESK), Method::Ack).len(), 1);
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let sent = drain(udp);
    assert!(reinvites_to(&sent, DESK).is_empty(), "the standby waits");
    assert!(requests_to(&sent, socket(DESK), Method::Bye).is_empty());
    assert!(events(&controller).await.is_empty(), "nothing reported yet");

    // The mobile's bridge fails: the standby is bridged next.
    refuses(state, MOBILE, &mobile_offer, &mobile_contact);
    let (desk_offer, sent) = bridge_offer_to(udp, DESK).await;
    assert_eq!(requests_to(&sent, socket(MOBILE), Method::Bye).len(), 1);
    bridge_forms(state, udp, DESK, &desk_offer, &desk_contact).await;
    let heard = events(&controller).await;
    assert_eq!(names(&heard), ["DialBranchFailed", "DialAnswered"]);
    assert_eq!(heard[0].payload["target"], mobile_contact);
    assert_eq!(heard[0].payload["cause"], "bridge_failed");
    assert_eq!(heard[1].payload["target"], desk_contact);
    assert_drained(state);
}

/// A standby is hung up once the bridge it waited behind forms, and reported
/// as a branch that did not win; the phone still ringing is CANCELled.
#[tokio::test(flavor = "multi_thread")]
async fn a_standby_is_hung_up_when_the_first_bridge_forms() {
    const DESK: &str = "198.51.100.215:5060";
    const MOBILE: &str = "198.51.100.216:5060";
    const TABLET: &str = "198.51.100.217:5060";
    let aor = "sip:fb3403@siphon.example.com";
    let contact = |phone: &str| format!("sip:fb3403@{phone}");
    register(aor, &contact(DESK), 1.0);
    register(aor, &contact(MOBILE), 0.5);
    register(aor, &contact(TABLET), 0.2);
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "fallback-kept@192.0.2.10");
    let controller = controller_owning("fallback-kept", dispatcher, &caller, "kept", "hangup");
    let state = &controller.dispatcher.state;
    let udp = &controller.dispatcher.udp;
    let (reply, _) = dial(
        &controller,
        "kept",
        serde_json::json!({ "targets": [{ "aor": aor }], "on_answer": "bridge" }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let sent = drain(udp);
    let (desk, mobile) = (invite_to(&sent, DESK), invite_to(&sent, MOBILE));
    let _tablet = invite_to(&sent, TABLET);

    answers(state, MOBILE, &mobile, &contact(MOBILE));
    let (offer, _) = bridge_offer_to(udp, MOBILE).await;
    answers(state, DESK, &desk, &contact(DESK));
    let sent = sent_until(udp, |sent| {
        !requests_to(sent, socket(DESK), Method::Ack).is_empty()
    })
    .await;
    assert!(requests_to(&sent, socket(DESK), Method::Bye).is_empty());
    assert!(requests_to(&sent, socket(TABLET), Method::Cancel).is_empty());

    let sent = bridge_forms(state, udp, MOBILE, &offer, &contact(MOBILE)).await;
    let bye = requests_to(&sent, socket(DESK), Method::Bye);
    assert_eq!(bye.len(), 1, "the standby is hung up");
    assert!(bye[0]
        .message
        .headers
        .get("Reason")
        .is_some_and(|reason| reason.contains("cause=16")));
    assert_eq!(
        requests_to(&sent, socket(TABLET), Method::Cancel).len(),
        1,
        "the phone still ringing is CANCELled"
    );
    assert!(
        requests_to(&sent, socket(MOBILE), Method::Bye).is_empty(),
        "positive control: the bridged phone stays up"
    );
    let heard = events(&controller).await;
    assert_eq!(
        names(&heard),
        ["DialBranchFailed", "DialBranchFailed", "DialAnswered"]
    );
    let released: Vec<_> = heard[..2]
        .iter()
        .map(|event| {
            event.payload["target"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        })
        .collect();
    assert!(released.contains(&contact(DESK)) && released.contains(&contact(TABLET)));
    assert!(heard[..2]
        .iter()
        .all(|event| event.payload["cause"] == "cancelled"));
    assert_eq!(heard[2].payload["target"], contact(MOBILE));
    assert_drained(state);
}

/// Sequential: a phone whose bridge fails is hung up and the next target is
/// rung, as if the phone had not answered.
#[tokio::test(flavor = "multi_thread")]
async fn a_sequential_bridge_dial_moves_on_when_a_bridge_fails() {
    const FIRST: &str = "198.51.100.218:5060";
    const SECOND: &str = "198.51.100.219:5060";
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "fallback-hunt@192.0.2.10");
    let controller = controller_owning("fallback-hunt", dispatcher, &caller, "hunt", "hangup");
    let state = &controller.dispatcher.state;
    let udp = &controller.dispatcher.udp;
    let (first_uri, second_uri) = (format!("sip:3404@{FIRST}"), format!("sip:3404@{SECOND}"));
    let (reply, _) = dial(
        &controller,
        "hunt",
        serde_json::json!({
            "targets": [first_uri, second_uri],
            "on_answer": "bridge",
            "strategy": "sequential",
            "timeout": 10,
        }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let first = invite_to(&drain(udp), FIRST);
    answers(state, FIRST, &first, &first_uri);
    let (offer, sent) = bridge_offer_to(udp, FIRST).await;
    assert!(
        requests_to(&sent, socket(SECOND), Method::Invite).is_empty(),
        "one phone at a time, the answered one included"
    );
    refuses(state, FIRST, &offer, &first_uri);
    let sent = drain(udp);
    assert_eq!(requests_to(&sent, socket(FIRST), Method::Bye).len(), 1);
    let second = invite_to(&sent, SECOND);
    answers(state, SECOND, &second, &second_uri);
    let (offer, _) = bridge_offer_to(udp, SECOND).await;
    bridge_forms(state, udp, SECOND, &offer, &second_uri).await;
    let heard = events(&controller).await;
    let answered: Vec<_> = heard
        .iter()
        .filter(|event| event.event == "DialAnswered")
        .collect();
    assert_eq!(answered.len(), 1);
    assert_eq!(answered[0].payload["target"], second_uri);
    assert!(heard.iter().any(|event| event.event == "DialBranchFailed"
        && event.payload["cause"] == "bridge_failed"
        && event.payload["target"] == first_uri));
    assert_drained(state);
}
