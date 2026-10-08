//! The `From` host a phone is shown by `dial {on_answer: "bridge"}`.
//!
//! A connecting dial's B-leg hides the caller's `From` host behind siphon's own
//! advertised address. A bridge dial rings the same phone for the same caller,
//! only after the caller was answered (a greeting, a menu), and is placed as a
//! call of siphon's own rather than shaped from the caller's INVITE. It must
//! hide the host all the same: whatever the caller's side wrote there, a
//! carrier's address on a call in from a trunk, is not the phone's to see, and
//! a phone must not be shown one host on a direct ring and another behind a
//! prompt.

use super::dial_bridge_test_harness::{
    answered_caller, bridging_dispatcher, controller_owning, dial, CALLER,
};
use super::originate_test_harness::{drain, requests_to, socket};
use super::test_dispatcher::TestDispatcher;
use super::*;
use crate::rtpengine::test_native_engine::NativeTestEngine;

/// What siphon advertises, unlike any host a caller or a controller names.
const ADVERTISED: &str = "edge.example.net";

/// A bridging dispatcher that advertises [`ADVERTISED`] on UDP.
fn advertising_dispatcher(engine: &NativeTestEngine) -> TestDispatcher {
    let mut dispatcher = bridging_dispatcher(engine);
    dispatcher
        .state
        .advertised_addrs
        .insert(Transport::Udp, ADVERTISED.to_string());
    dispatcher
}

/// The `From` of the one INVITE siphon sent `phone`, up to its dialog tag.
fn from_shown_to(dispatcher: &TestDispatcher, phone: &str) -> String {
    let invite = requests_to(&drain(&dispatcher.udp), socket(phone), Method::Invite)
        .pop()
        .expect("siphon sent the phone an INVITE")
        .message;
    let from = invite.headers.from().expect("a From");
    let (identity, tag) = from.split_once(";tag=").expect("a From tag");
    assert!(!tag.is_empty() && tag != "caller-tag", "a tag of its own");
    identity.to_string()
}

/// The From a bridge dial with `identity` arguments shows `phone`.
async fn bridge_dial_shows(call_id: &str, phone: &str, identity: serde_json::Value) -> String {
    let engine = NativeTestEngine::start().await;
    let dispatcher = advertising_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, call_id);
    let controller = controller_owning(call_id, dispatcher, &caller, call_id, "hangup");
    let mut args = serde_json::json!({
        "on_answer": "bridge",
        "targets": [format!("sip:2101@{phone}")],
    });
    if let (Some(args), Some(identity)) = (args.as_object_mut(), identity.as_object()) {
        args.extend(identity.clone());
    }
    let (reply, _) = dial(&controller, call_id, args).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    from_shown_to(&controller.dispatcher, phone)
}

/// The caller's own From reaches the phone with siphon's advertised address as
/// its host: the caller's user and display name, never the caller's host.
#[tokio::test(flavor = "multi_thread")]
async fn a_bridge_dial_hides_the_callers_from_host() {
    let from = bridge_dial_shows(
        "from-host@192.0.2.10",
        "198.51.100.221:5060",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(
        from,
        format!("\"Caller One\" <sip:15550100001@{ADVERTISED}>")
    );
}

/// A display name alone names no host, so the caller's is still hidden.
#[tokio::test(flavor = "multi_thread")]
async fn a_bridge_dial_naming_only_a_display_name_hides_the_callers_from_host() {
    let from = bridge_dial_shows(
        "from-host-display@192.0.2.10",
        "198.51.100.222:5060",
        serde_json::json!({ "from_display": "Reception" }),
    )
    .await;
    assert_eq!(
        from,
        format!("\"Reception\" <sip:15550100001@{ADVERTISED}>")
    );
}

/// Positive control: a `from` the dial names keeps the host it names, as on a
/// connecting dial.
#[tokio::test(flavor = "multi_thread")]
async fn a_bridge_dial_naming_a_from_keeps_its_host() {
    let from = bridge_dial_shows(
        "from-host-named@192.0.2.10",
        "198.51.100.223:5060",
        serde_json::json!({ "from": "sip:5550100@tenant.example.org" }),
    )
    .await;
    assert_eq!(from, "<sip:5550100@tenant.example.org>");
}

/// The two paths agree: a phone rung for a caller sees the same From whether
/// the ring connects the caller or follows its answer.
#[tokio::test(flavor = "multi_thread")]
async fn a_bridge_dial_shows_the_from_a_connecting_dial_shows() {
    const PHONE: &str = "198.51.100.224:5060";
    let bridged =
        bridge_dial_shows("from-host-pair@192.0.2.10", PHONE, serde_json::json!({})).await;

    // The same caller, not yet answered, connected by the same dial.
    let call_id = "from-host-pair-connect@192.0.2.10";
    let engine = NativeTestEngine::start().await;
    let dispatcher = advertising_dispatcher(&engine);
    let invite = parse_sip_message_bytes(
        format!(
            concat!(
                "INVITE sip:4000@siphon.example.com SIP/2.0\r\n",
                "Via: SIP/2.0/UDP {caller};branch=z9hG4bK-{call_id}\r\n",
                "Max-Forwards: 70\r\n",
                "From: \"Caller One\" <sip:15550100001@siphon.example.com>;tag=caller-tag\r\n",
                "To: <sip:4000@siphon.example.com>\r\n",
                "Call-ID: {call_id}\r\n",
                "CSeq: 1 INVITE\r\n",
                "Content-Length: 0\r\n",
                "\r\n",
            ),
            caller = CALLER,
            call_id = call_id,
        )
        .as_bytes(),
    )
    .expect("the caller's INVITE parses");
    let internal_call_id = dispatcher.state.call_actors.create_call(Leg::new_a_leg(
        call_id.to_string(),
        "caller-tag".to_string(),
        format!("z9hG4bK-{call_id}"),
        LegTransport {
            remote_addr: socket(CALLER),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    ));
    dispatcher
        .state
        .call_actors
        .set_a_leg_invite(&internal_call_id, Arc::new(Mutex::new(invite)));
    let dialled = tokio::task::block_in_place(|| {
        b2bua_dial_call_with_state(
            call_id,
            vec![DialTarget {
                uri: format!("sip:2101@{PHONE}"),
                ..Default::default()
            }],
            true,
            30,
            &[],
            &DialShaping::default(),
            &dispatcher.state,
        )
    });
    assert!(matches!(dialled, Ok(true)), "{dialled:?}");
    let connected = from_shown_to(&dispatcher, PHONE);

    assert_eq!(
        connected,
        format!("\"Caller One\" <sip:15550100001@{ADVERTISED}>")
    );
    assert_eq!(bridged, connected);
}
