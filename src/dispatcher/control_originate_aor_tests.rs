//! The control plane's `originate {aor}`, driven the way a controller's command
//! reaches it: the frame an SDK sends, the listener's frame processing, the
//! command consumer and the SIP adapter's handler, placing its legs on a
//! dispatcher of the test's own. The outcome is read off the wire, the
//! controller's event stream and the channel registry.

use super::control_originate_tests::{controller_on, Controller};
use super::originate_test_harness::{drain, phone_response, phone_sends, requests_to, socket};
use super::test_dispatcher::test_dispatcher;
use super::*;
use crate::control::protocol::EventFrame;
use crate::control::OutboundFrame;

/// An SDP offer the controller supplies, so the legs need no media engine.
const OFFER: &str = concat!(
    "v=0\r\n",
    "o=controller 1 1 IN IP4 192.0.2.1\r\n",
    "s=-\r\n",
    "c=IN IP4 192.0.2.1\r\n",
    "t=0 0\r\n",
    "m=audio 40000 RTP/AVP 0\r\n",
);

/// The answer a phone returns to [`OFFER`].
const ANSWER: &str = concat!(
    "v=0\r\n",
    "o=phone 2 2 IN IP4 198.51.100.1\r\n",
    "s=-\r\n",
    "c=IN IP4 198.51.100.1\r\n",
    "t=0 0\r\n",
    "m=audio 42000 RTP/AVP 0\r\n",
);

fn register(aor: &str, contact: &str, q: f32) {
    crate::script::api::test_registrar()
        .save_with_source(
            aor,
            parse_uri_standalone(contact).expect("a contact URI"),
            3600,
            q,
            format!("register-{contact}"),
            1,
            None,
            None,
        )
        .expect("the binding saves");
}

/// Send `args` as an `originate` frame. Returns the reply and the events that
/// were queued ahead of it.
async fn originate_frame(
    controller: &Controller,
    args: serde_json::Value,
) -> (serde_json::Value, Vec<EventFrame>) {
    let frame = serde_json::json!({
        "id": "c-aor",
        "type": "command",
        "module": "sip",
        "verb": "originate",
        "target": null,
        "args": args,
    });
    let mut said_hello = true;
    assert!(
        crate::control::listener::process_text(
            &frame.to_string(),
            &mut said_hello,
            &controller.connection,
            &controller.bus,
        )
        .await
    );
    let mut events = Vec::new();
    loop {
        let frames = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            controller.connection.events.recv_many(),
        )
        .await
        .expect("a reply to the originate");
        for frame in frames {
            match frame {
                OutboundFrame::Reply(reply) => {
                    return (
                        serde_json::to_value(reply).expect("the reply serialises"),
                        events,
                    )
                }
                OutboundFrame::Event(event) => events.push(event),
            }
        }
    }
}

/// The events queued for the controller since the last look.
async fn events(controller: &Controller) -> Vec<EventFrame> {
    let mut events = Vec::new();
    while let Ok(frames) = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        controller.connection.events.recv_many(),
    )
    .await
    {
        events.extend(frames.into_iter().filter_map(|frame| match frame {
            OutboundFrame::Event(event) => Some(event),
            OutboundFrame::Reply(_) => None,
        }));
    }
    events
}

fn names(events: &[EventFrame]) -> Vec<&str> {
    events.iter().map(|event| event.event.as_str()).collect()
}

fn invite_to(sent: &[super::originate_test_harness::Sent], phone: &str) -> SipMessage {
    let mut invites = requests_to(sent, socket(phone), Method::Invite);
    assert_eq!(invites.len(), 1, "one INVITE to {phone}");
    invites.remove(0).message
}

/// `to` and `aor` together, or neither, is a malformed request: refused with
/// nothing on the wire and the channel id left free.
#[tokio::test(flavor = "multi_thread")]
async fn originate_takes_exactly_one_of_to_and_aor() {
    let controller = controller_on("dialer-aor-exclusive", test_dispatcher());
    for args in [
        serde_json::json!({
            "channel": "ch-1",
            "to": "sip:3101@198.51.100.10",
            "aor": "sip:3101@siphon.example.com",
            "sdp": OFFER,
        }),
        serde_json::json!({ "channel": "ch-1", "sdp": OFFER }),
        serde_json::json!({
            "channel": "ch-1",
            "to": "sip:3101@198.51.100.10",
            "strategy": "sequential",
            "sdp": OFFER,
        }),
        serde_json::json!({
            "channel": "ch-1",
            "aor": "sip:3101@siphon.example.com",
            "strategy": "round-robin",
            "sdp": OFFER,
        }),
    ] {
        let (reply, _) = originate_frame(&controller, args.clone()).await;
        assert_eq!(reply["status"], "error", "{args}: {reply}");
        assert_eq!(reply["error"]["code"], "bad_request", "{args}: {reply}");
        assert!(drain(&controller.dispatcher.udp).is_empty(), "{args}");
        assert!(!controller.bus.channel_exists("ch-1"), "{args}");
    }
    // Positive control: `to` alone places the call.
    let (reply, _) = originate_frame(
        &controller,
        serde_json::json!({ "channel": "ch-1", "to": "sip:3101@198.51.100.10", "sdp": OFFER }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(
        requests_to(
            &drain(&controller.dispatcher.udp),
            socket("198.51.100.10:5060"),
            Method::Invite
        )
        .len(),
        1
    );
}

/// An AoR with nobody registered is a typed refusal, and nothing is placed.
#[tokio::test(flavor = "multi_thread")]
async fn an_aor_with_no_registered_phone_is_refused_with_nothing_on_the_wire() {
    let controller = controller_on("dialer-aor-unknown", test_dispatcher());
    let (reply, events) = originate_frame(
        &controller,
        serde_json::json!({
            "channel": "ch-2",
            "aor": "sip:nobody-3102@siphon.example.com",
            "sdp": OFFER,
        }),
    )
    .await;
    assert_eq!(reply["status"], "error", "{reply}");
    assert_eq!(reply["error"]["code"], "not_found", "{reply}");
    assert_eq!(
        reply["error"]["details"]["reason"], "no_contacts",
        "{reply}"
    );
    assert_eq!(reply["error"]["details"]["verb"], "originate", "{reply}");
    assert!(events.is_empty());
    assert!(drain(&controller.dispatcher.udp).is_empty());
    assert!(!controller.bus.channel_exists("ch-2"));
    assert_eq!(controller.dispatcher.state.call_actors.count(), 0);
}

/// Two phones ring under the controller's one channel; the one that answers
/// becomes the channel's call, and the other is CANCELled.
#[tokio::test(flavor = "multi_thread")]
async fn the_phone_that_answers_becomes_the_channels_call() {
    const DESK: &str = "198.51.100.111:5060";
    const MOBILE: &str = "198.51.100.112:5060";
    let aor = "sip:3103@siphon.example.com";
    register(aor, &format!("sip:3103@{DESK}"), 1.0);
    register(aor, &format!("sip:3103@{MOBILE}"), 0.5);
    let controller = controller_on("dialer-aor-ring", test_dispatcher());

    let (reply, queued) = originate_frame(
        &controller,
        serde_json::json!({ "channel": "ch-3", "aor": aor, "sdp": OFFER, "timeout": 20 }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let result = &reply["result"];
    assert_eq!(result["channel"], "ch-3");
    assert_eq!(result["aor"], aor);
    assert_eq!(result["strategy"], "parallel");
    assert_eq!(result["total_timeout"], 20);
    assert_eq!(result["branches"].as_array().map(Vec::len), Some(2));
    let group_id = result["group_id"]
        .as_str()
        .expect("the group id")
        .to_string();
    // Each leg was named on the channel before the reply.
    assert_eq!(names(&queued), ["DialBranch", "DialBranch"]);
    assert!(queued
        .iter()
        .all(|event| event.channel.as_deref() == Some("ch-3")
            && event.sip_call_id.as_deref() == Some(group_id.as_str())));
    assert_eq!(
        controller.bus.sip_call_id_for_channel("ch-3").as_deref(),
        Some(group_id.as_str()),
        "while the phones ring the channel is bound to the group"
    );

    let sent = drain(&controller.dispatcher.udp);
    let desk_invite = invite_to(&sent, DESK);
    let mobile_invite = invite_to(&sent, MOBILE);
    assert_eq!(
        desk_invite.body,
        OFFER.as_bytes(),
        "the controller's offer rides every leg"
    );

    // The desk rings: reported on the channel, naming the leg.
    phone_sends(
        &controller.dispatcher.state,
        socket(DESK),
        &phone_response(
            &desk_invite,
            180,
            "Ringing",
            "desk-tag",
            &format!("sip:3103@{DESK}"),
            None,
        ),
    );
    let ringing = events(&controller).await;
    assert_eq!(names(&ringing), ["ChannelStateChange"]);
    assert_eq!(ringing[0].payload["state"], "ringing");
    assert_eq!(ringing[0].payload["target"], format!("sip:3103@{DESK}"));

    // The mobile answers.
    let mobile_call_id = mobile_invite.headers.call_id().cloned().expect("a Call-ID");
    phone_sends(
        &controller.dispatcher.state,
        socket(MOBILE),
        &phone_response(
            &mobile_invite,
            200,
            "OK",
            "mobile-tag",
            &format!("sip:3103@{MOBILE}"),
            Some(ANSWER),
        ),
    );
    let answered = events(&controller).await;
    assert_eq!(names(&answered), ["DialBranchFailed", "DialAnswered"]);
    assert_eq!(answered[0].payload["target"], format!("sip:3103@{DESK}"));
    assert_eq!(answered[0].payload["cause"], "cancelled");
    assert_eq!(answered[1].payload["target"], format!("sip:3103@{MOBILE}"));
    assert_eq!(
        answered[1].sip_call_id.as_deref(),
        Some(mobile_call_id.as_str()),
        "the answer is reported under the winner's own Call-ID"
    );
    assert_eq!(
        controller.bus.sip_call_id_for_channel("ch-3").as_deref(),
        Some(mobile_call_id.as_str()),
        "the channel is now the mobile's call"
    );
    let winner = controller
        .dispatcher
        .state
        .call_actors
        .find_by_sip_call_id(&mobile_call_id)
        .expect("the winner's call");
    assert_eq!(
        controller
            .bus
            .owned_channels("dialer-aor-ring")
            .iter()
            .find(|channel| channel.channel_id == "ch-3")
            .map(|channel| channel.call_actor_id.clone()),
        Some(winner)
    );

    let sent = drain(&controller.dispatcher.udp);
    assert_eq!(requests_to(&sent, socket(MOBILE), Method::Ack).len(), 1);
    assert_eq!(requests_to(&sent, socket(DESK), Method::Cancel).len(), 1);
    assert!(requests_to(&sent, socket(MOBILE), Method::Cancel).is_empty());
    assert_eq!(
        controller.dispatcher.state.originate_groups.group_count(),
        0
    );
}

/// Nobody answers: the channel ends with the `StasisEnd` a plain originate's
/// failure carries, naming the best of the phones' statuses.
#[tokio::test(flavor = "multi_thread")]
async fn a_group_nobody_answers_ends_the_channel_with_the_cause() {
    const DESK: &str = "198.51.100.113:5060";
    let aor = "sip:3104@siphon.example.com";
    register(aor, &format!("sip:3104@{DESK}"), 1.0);
    let controller = controller_on("dialer-aor-busy", test_dispatcher());
    let (reply, _) = originate_frame(
        &controller,
        serde_json::json!({ "channel": "ch-4", "aor": aor, "sdp": OFFER }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let invite = invite_to(&drain(&controller.dispatcher.udp), DESK);
    phone_sends(
        &controller.dispatcher.state,
        socket(DESK),
        &phone_response(
            &invite,
            486,
            "Busy Here",
            "desk-tag",
            &format!("sip:3104@{DESK}"),
            None,
        ),
    );
    let ended = events(&controller).await;
    assert_eq!(names(&ended), ["DialBranchFailed", "StasisEnd"]);
    assert_eq!(ended[1].payload["reason"], "rejected");
    assert_eq!(ended[1].payload["code"], 486);
    assert_eq!(ended[1].payload["response"], "Busy Here");
    assert!(
        !controller.bus.channel_exists("ch-4"),
        "the channel is gone"
    );
    assert_eq!(
        controller.dispatcher.state.originate_groups.group_count(),
        0
    );
}
