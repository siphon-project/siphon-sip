//! The 2xx siphon sends itself to a target refresh request carries siphon's
//! Contact on the dialog the request arrived on (RFC 3261 §12.2.2, §13.3.1.4;
//! RFC 3311 §5.2): a re-INVITE or UPDATE on a one-legged call, on a leg of a
//! controller bridge, and an UPDATE on an early dialog. That answer is the
//! peer's remote target from then on, so it is the dialog's own Contact,
//! `contact_host` included. It used to go out with no Contact at all.

use super::control_bridge_relay_tests::{
    deliver, finals_to, request, srtp_pair, srtp_pair_dialling, wait_for, Pair,
};
use super::dial_bridge_test_harness::CALLER;
use super::sdp_strip_tests::{
    caller_call, in_dialog_request, inbound_from, response_to, ringing_call,
};
use super::session_timer_tests::wire;
use super::test_dispatcher::test_dispatcher;
use super::*;

const TENANT_HOST: &str = "tenant-a.example.com";

fn contact(message: &SipMessage) -> Option<&str> {
    message.headers.get("Contact").map(String::as_str)
}

fn local_contact_of(state: &DispatcherState, internal_call_id: &str) -> String {
    state
        .call_actors
        .get_call(internal_call_id)
        .and_then(|call| call.a_leg.dialog.local_contact.clone())
        .expect("the dialog records siphon's Contact")
}

/// An answered call with nobody on the other side (siphon answered it, no
/// B-leg) and no media engine: a re-INVITE or UPDATE from the caller is
/// answered `200` by siphon, with the caller dialog's Contact, which carries a
/// caller `contact_host` when one was named.
#[tokio::test(flavor = "multi_thread")]
async fn a_one_legged_call_answers_a_refresh_with_its_dialogs_contact() {
    for (method, contact_host, expected) in [
        ("INVITE", None, "<sip:192.0.2.1:5060;transport=udp>"),
        ("UPDATE", None, "<sip:192.0.2.1:5060;transport=udp>"),
        (
            "INVITE",
            Some(TENANT_HOST),
            "<sip:tenant-a.example.com:5060;transport=udp>",
        ),
        (
            "UPDATE",
            Some(TENANT_HOST),
            "<sip:tenant-a.example.com:5060;transport=udp>",
        ),
    ] {
        let dispatcher = test_dispatcher();
        let call_id = caller_call(&dispatcher);
        if let Some(host) = contact_host {
            set_caller_contact_host(&dispatcher.state, &call_id, host).expect("set");
        }
        if let Some(mut call) = dispatcher.state.call_actors.get_call_mut(&call_id) {
            call.a_leg.initial_acked = true;
            call.a_leg.dialog.remote_tag = Some("caller-tag".to_string());
        }
        dispatcher
            .state
            .call_actors
            .set_state(&call_id, CallState::Answered);
        let message = in_dialog_request(method, true, "");
        let inbound = inbound_from(super::sdp_strip_tests::CALLER);
        tokio::task::block_in_place(|| match method {
            "INVITE" => handle_b2bua_reinvite(inbound, message, &dispatcher.state),
            _ => handle_b2bua_update(inbound, message, &dispatcher.state),
        });
        let answered = response_to(&wire(&dispatcher), super::sdp_strip_tests::CALLER, 200);
        assert_eq!(
            contact(&answered),
            Some(expected),
            "{method} ({contact_host:?})"
        );
    }
}

/// On a controller bridge each leg is the A-leg of its own call: a session
/// refresh from the carrier is answered with the carrier dialog's Contact, and
/// one from the phone with the phone dialog's, which carries the `contact_host`
/// its dial target named.
#[tokio::test(flavor = "multi_thread")]
async fn a_bridged_leg_answers_a_refresh_with_its_dialogs_contact() {
    const PHONE: &str = "198.51.100.178:5060";
    const TENANT_PHONE: &str = "198.51.100.179:5060";
    let pair = srtp_pair("refresh-contact", PHONE).await;
    deliver(&pair, CALLER, request(&pair, true, "INVITE", None));
    let sent = wait_for(&pair, |sent| !finals_to(sent, CALLER).is_empty()).await;
    let answered = &finals_to(&sent, CALLER)[0];
    assert_eq!(answered.status_code(), Some(200));
    assert_eq!(
        contact(answered),
        Some(local_contact_of(pair.state(), &pair.caller.internal_call_id).as_str()),
        "the carrier's refresh"
    );

    let pair = srtp_pair_dialling("refresh-contact-host", TENANT_PHONE, Some(TENANT_HOST)).await;
    for method in ["UPDATE", "INVITE"] {
        deliver(&pair, TENANT_PHONE, request(&pair, false, method, None));
        let sent = wait_for(&pair, |sent| !finals_to(sent, TENANT_PHONE).is_empty()).await;
        let answered = &finals_to(&sent, TENANT_PHONE)[0];
        assert_eq!(answered.status_code(), Some(200), "{method}");
        let uri = crate::sip::headers::nameaddr::NameAddr::parse(
            contact(answered).unwrap_or_else(|| panic!("the {method} 200 has no Contact")),
        )
        .expect("the Contact parses")
        .uri;
        assert_eq!(uri.host, TENANT_HOST, "the phone's {method} refresh");
        assert_eq!(contact(answered), Some(phone_local_contact(&pair).as_str()));
    }
}

fn phone_local_contact(pair: &Pair) -> String {
    let sip_call_id = pair
        .phone_dialog
        .headers
        .call_id()
        .cloned()
        .expect("a Call-ID");
    let internal = pair
        .state()
        .call_actors
        .find_by_sip_call_id(&sip_call_id)
        .expect("the phone's call");
    local_contact_of(pair.state(), &internal)
}

/// A bodyless UPDATE from the caller on a call still ringing is answered `200`
/// by siphon on the early dialog, with the caller dialog's Contact.
#[tokio::test(flavor = "multi_thread")]
async fn an_early_update_answered_locally_carries_the_dialogs_contact() {
    let dispatcher = test_dispatcher();
    let call_id = ringing_call(&dispatcher);
    set_caller_contact_host(&dispatcher.state, &call_id, TENANT_HOST).expect("set");
    tokio::task::block_in_place(|| {
        handle_b2bua_update(
            inbound_from(super::sdp_strip_tests::CALLER),
            in_dialog_request("UPDATE", true, ""),
            &dispatcher.state,
        )
    });
    let answered = response_to(&wire(&dispatcher), super::sdp_strip_tests::CALLER, 200);
    assert_eq!(
        contact(&answered),
        Some("<sip:tenant-a.example.com:5060;transport=udp>")
    );
}
