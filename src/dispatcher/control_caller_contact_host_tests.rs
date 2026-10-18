//! The caller side of `contact_host`: the host of siphon's own Contact toward a
//! call that came in, which a controller names on `answer` / `ring` /
//! `progress` (`contact_host`) or on `dial` / `route` (`caller_contact_host`).
//!
//! A peer that identifies the tenant or account by the host of the Contact
//! reads it on what siphon answers it with as much as on what siphon sends it,
//! so every Contact siphon presents the caller carries the host: siphon's own
//! 18x and 2xx, the 18x and 2xx a connecting dial relays, the answer to the
//! caller's re-INVITE, and the re-INVITE, UPDATE and session refresh siphon
//! sends the caller. Each is read back off the UDP egress against the same
//! exchange with no host named, so only the host may differ.

use super::control_dial_identity_tests::{dial_targets, park};
use super::originate_test_harness::{phone_response, phone_sends, socket};
use super::sdp_strip_tests::{
    address, answered_call, callee_response, endpoint_sdp, response_to, snapshot, strip_dispatcher,
    track_forwarded, CALLEE, CALLER,
};
use super::session_timer_tests::{
    age, callee_answers, requests, ringing_call_from, sweep, timer_dispatcher, wire,
};
use super::test_dispatcher::{test_dispatcher, TestDispatcher};
use super::*;

const TENANT_HOST: &str = "tenant-a.example.com";
/// The Contact the INVITE path records for the caller's dialog.
const DIALOG_CONTACT: &str = "<sip:192.0.2.1:5060;transport=udp>";
const TENANT_CONTACT: &str = "<sip:tenant-a.example.com:5060;transport=udp>";
const PHONE: &str = "198.51.100.7:5060";

fn contact(message: &SipMessage) -> Option<&str> {
    message.headers.get("Contact").map(String::as_str)
}

/// A parked caller whose dialog Contact is the one the INVITE path records.
fn parked(dispatcher: &TestDispatcher) -> String {
    let call_id = park(dispatcher);
    if let Some(mut call) = dispatcher.state.call_actors.get_call_mut(&call_id) {
        call.a_leg.dialog.local_contact = Some(DIALOG_CONTACT.to_string());
    }
    call_id
}

fn stored_invite(dispatcher: &TestDispatcher, call_id: &str) -> SipMessage {
    dispatcher
        .state
        .call_actors
        .get_call(call_id)
        .and_then(|call| call.a_leg_invite.clone())
        .and_then(|invite| invite.lock().ok().map(|invite| invite.clone()))
        .expect("the parked call stores its INVITE")
}

/// siphon's own 180, 183 and 200 to the caller each carry the host; the same
/// exchange without one carries the dialog's advertised Contact.
#[tokio::test(flavor = "multi_thread")]
async fn siphons_own_answers_to_the_caller_present_the_contact_host() {
    for (contact_host, expected) in [(None, DIALOG_CONTACT), (Some(TENANT_HOST), TENANT_CONTACT)] {
        let dispatcher = test_dispatcher();
        let call_id = parked(&dispatcher);
        if let Some(host) = contact_host {
            set_caller_contact_host(&dispatcher.state, &call_id, host).expect("set");
        }
        let invite = stored_invite(&dispatcher, &call_id);
        for (code, reason, body, final_response) in [
            (180, "Ringing", None, false),
            (
                183,
                "Session Progress",
                Some(endpoint_sdp("192.0.2.1")),
                false,
            ),
            (200, "OK", None, true),
        ] {
            let has_body = body.is_some();
            assert!(send_uas_response(
                &dispatcher.state,
                &call_id,
                &invite,
                code,
                reason,
                body.map(String::into_bytes),
                has_body.then_some("application/sdp"),
                final_response,
                &[],
            ));
            let sent = response_to(&wire(&dispatcher), CALLER, code);
            assert_eq!(contact(&sent), Some(expected), "{code} ({contact_host:?})");
        }
    }
}

/// A leg that recorded no dialog Contact gets one built for the response, and
/// that one carries the host too.
#[tokio::test(flavor = "multi_thread")]
async fn a_contact_built_for_the_response_carries_the_host() {
    let dispatcher = test_dispatcher();
    let call_id = park(&dispatcher);
    set_caller_contact_host(&dispatcher.state, &call_id, "2001:db8::5").expect("set");
    let invite = stored_invite(&dispatcher, &call_id);
    assert!(send_uas_response(
        &dispatcher.state,
        &call_id,
        &invite,
        180,
        "Ringing",
        None,
        None,
        false,
        &[],
    ));
    let sent = response_to(&wire(&dispatcher), CALLER, 180);
    let uri = crate::sip::headers::nameaddr::NameAddr::parse(contact(&sent).expect("a Contact"))
        .expect("the Contact parses")
        .uri;
    assert_eq!(uri.host, "[2001:db8::5]");
}

/// The host sticks once the caller holds it: before any response the last one
/// set wins, the same one again is a no-op, and a different one after an 18x
/// went out is refused naming the host the caller holds. A call that named
/// none is refused the same way once its advertised Contact went out.
#[tokio::test(flavor = "multi_thread")]
async fn the_caller_contact_host_is_fixed_once_the_caller_holds_it() {
    let dispatcher = test_dispatcher();
    let call_id = parked(&dispatcher);
    set_caller_contact_host(&dispatcher.state, &call_id, "tenant-z.example.com").expect("set");
    set_caller_contact_host(&dispatcher.state, &call_id, TENANT_HOST).expect("last one wins");
    let invite = stored_invite(&dispatcher, &call_id);
    assert!(send_uas_response(
        &dispatcher.state,
        &call_id,
        &invite,
        180,
        "Ringing",
        None,
        None,
        false,
        &[],
    ));
    assert_eq!(
        contact(&response_to(&wire(&dispatcher), CALLER, 180)),
        Some(TENANT_CONTACT)
    );
    assert_eq!(
        set_caller_contact_host(&dispatcher.state, &call_id, TENANT_HOST),
        Ok(())
    );
    assert_eq!(
        set_caller_contact_host(&dispatcher.state, &call_id, "tenant-b.example.com"),
        Err(CallerContactHostRefusal::AlreadyPresented {
            presented: TENANT_HOST.to_string()
        })
    );

    let dispatcher = test_dispatcher();
    let call_id = parked(&dispatcher);
    let invite = stored_invite(&dispatcher, &call_id);
    assert!(send_uas_response(
        &dispatcher.state,
        &call_id,
        &invite,
        180,
        "Ringing",
        None,
        None,
        false,
        &[],
    ));
    assert_eq!(
        set_caller_contact_host(&dispatcher.state, &call_id, TENANT_HOST),
        Err(CallerContactHostRefusal::AlreadyPresented {
            presented: "192.0.2.1".to_string()
        })
    );
    assert!(matches!(
        set_caller_contact_host(&dispatcher.state, &call_id, "tenant-a.example.com:5070"),
        Err(CallerContactHostRefusal::Invalid(_))
    ));
}

/// A connecting dial relays the phone's 180 and 200 to the caller with
/// siphon's Contact, and both carry the caller's host.
#[tokio::test(flavor = "multi_thread")]
async fn a_connecting_dial_relays_the_answer_with_the_caller_contact_host() {
    for (contact_host, expected_host) in [(None, None), (Some(TENANT_HOST), Some(TENANT_HOST))] {
        let dispatcher = test_dispatcher();
        let call_id = parked(&dispatcher);
        if let Some(host) = contact_host {
            set_caller_contact_host(&dispatcher.state, &call_id, host).expect("set");
        }
        assert!(dial_targets(
            &dispatcher,
            vec![DialTarget {
                uri: format!("sip:15550100077@{PHONE}"),
                ..Default::default()
            }],
            true,
            &DialShaping::default(),
        )
        .expect("the dial runs"));
        let invite = requests(&wire(&dispatcher), PHONE, Method::Invite)
            .pop()
            .expect("the B-leg INVITE");
        let phone_contact = format!("sip:callee@{PHONE}");
        phone_sends(
            &dispatcher.state,
            socket(PHONE),
            &phone_response(&invite, 180, "Ringing", "phone-tag", &phone_contact, None),
        );
        phone_sends(
            &dispatcher.state,
            socket(PHONE),
            &phone_response(
                &invite,
                200,
                "OK",
                "phone-tag",
                &phone_contact,
                Some(&endpoint_sdp("198.51.100.7")),
            ),
        );
        let sent = wire(&dispatcher);
        for code in [180, 200] {
            let relayed = response_to(&sent, "192.0.2.10:5060", code);
            let uri = crate::sip::headers::nameaddr::NameAddr::parse(
                contact(&relayed).expect("a Contact"),
            )
            .expect("the Contact parses")
            .uri;
            match expected_host {
                Some(host) => assert_eq!(uri.host, host, "the relayed {code}"),
                None => assert_ne!(uri.host, TENANT_HOST, "the control {code}"),
            }
        }
    }
}

/// The caller's dialog keeps the host for siphon's own requests on it: the
/// session refresh siphon is the refresher of, a re-INVITE and an UPDATE.
#[tokio::test(flavor = "multi_thread")]
async fn siphons_requests_to_the_caller_present_the_contact_host() {
    let dispatcher = timer_dispatcher(Some("session_expires: 90\nrefresher: b2bua\n"));
    let call_id = ringing_call_from(&dispatcher, &[("Supported", "timer")]);
    set_caller_contact_host(&dispatcher.state, &call_id, TENANT_HOST).expect("set");
    let answer = callee_answers(
        &dispatcher,
        &call_id,
        &[
            ("Supported", "timer"),
            ("Session-Expires", "90;refresher=uas"),
        ],
        &endpoint_sdp("198.51.100.20"),
    );
    assert_eq!(contact(&answer), Some(TENANT_CONTACT), "the relayed 200");

    age(&dispatcher, &call_id, true, 46);
    let refresh = requests(&sweep(&dispatcher), CALLER, Method::Invite)
        .pop()
        .expect("siphon refreshed the caller");
    assert_eq!(
        contact(&refresh),
        Some(TENANT_CONTACT),
        "the session refresh"
    );

    let _ = wire(&dispatcher);
    assert!(send_in_dialog_reinvite(
        &call_id,
        true,
        Some(endpoint_sdp("192.0.2.1").into_bytes()),
        &[],
        "reinvite:b2a",
        &dispatcher.state,
    ));
    assert!(send_in_dialog_request(
        &call_id,
        true,
        InDialogRequest {
            method: Method::Update,
            body: None,
            extra_headers: &[],
            tracking_target: "update:b2a",
            requested_session_expires: None,
        },
        |_| {},
        &dispatcher.state,
    ));
    let sent = wire(&dispatcher);
    for method in [Method::Invite, Method::Update] {
        let request = requests(&sent, CALLER, method.clone())
            .pop()
            .unwrap_or_else(|| panic!("no {method:?} reached the caller"));
        assert_eq!(contact(&request), Some(TENANT_CONTACT), "{method:?}");
    }
}

/// The answer to the caller's own re-INVITE or UPDATE, relayed from the
/// callee, carries the caller's host.
#[tokio::test(flavor = "multi_thread")]
async fn the_answer_to_the_callers_reoffer_presents_the_contact_host() {
    for (method, marker) in [("INVITE", "reinvite:a2b"), ("UPDATE", "update:a2b")] {
        let dispatcher = strip_dispatcher(&[]);
        let call_id = answered_call(&dispatcher);
        set_caller_contact_host(&dispatcher.state, &call_id, TENANT_HOST).expect("set");
        let branch = track_forwarded(&dispatcher, &call_id, method, marker, true);
        let mut answer = callee_response(
            200,
            "OK",
            &branch,
            &format!("2 {method}"),
            &endpoint_sdp("198.51.100.20"),
        );
        let taken = snapshot(&dispatcher, &call_id, &branch);
        let forwarded = if method == "INVITE" {
            forward_reinvite_response(
                &call_id,
                &branch,
                &mut answer,
                200,
                address(CALLEE),
                &dispatcher.state,
                &taken,
            )
        } else {
            forward_update_response(
                &call_id,
                &mut answer,
                200,
                address(CALLEE),
                &dispatcher.state,
                &taken,
            )
        };
        assert!(forwarded, "{method}");
        let relayed = response_to(&wire(&dispatcher), CALLER, 200);
        assert_eq!(contact(&relayed), Some(TENANT_CONTACT), "{method}");
    }
}

/// A bridge dial's caller is answered already, so `caller_contact_host` can
/// only repeat the host its answer carried: the same one rings the phones, a
/// different one is `invalid_state` with nothing sent.
#[tokio::test(flavor = "multi_thread")]
async fn a_bridge_dial_refuses_a_caller_contact_host_the_caller_does_not_hold() {
    use super::dial_bridge_test_harness::{
        answered_caller, bridging_dispatcher, controller_owning, dial,
    };
    use super::originate_test_harness::{drain, requests_to};
    use crate::rtpengine::test_native_engine::NativeTestEngine;

    const BRIDGED_PHONE: &str = "198.51.100.227:5060";
    for (call_id, caller_contact_host, accepted) in [
        ("caller-host-same@192.0.2.10", "192.0.2.1", true),
        ("caller-host-other@192.0.2.10", TENANT_HOST, false),
    ] {
        let engine = NativeTestEngine::start().await;
        let dispatcher = bridging_dispatcher(&engine);
        let caller = answered_caller(&dispatcher, call_id);
        let controller = controller_owning(call_id, dispatcher, &caller, call_id, "hangup");
        let (reply, _) = dial(
            &controller,
            call_id,
            serde_json::json!({
                "on_answer": "bridge",
                "caller_contact_host": caller_contact_host,
                "targets": [{ "uri": format!("sip:2101@{BRIDGED_PHONE}") }],
            }),
        )
        .await;
        let invites = requests_to(
            &drain(&controller.dispatcher.udp),
            socket(BRIDGED_PHONE),
            Method::Invite,
        );
        if accepted {
            assert_eq!(reply["status"], "ok", "{reply}");
            assert_eq!(invites.len(), 1);
        } else {
            assert_eq!(reply["error"]["code"], "invalid_state", "{reply}");
            assert_eq!(
                reply["error"]["details"]["presented"], "192.0.2.1",
                "{reply}"
            );
            assert!(invites.is_empty(), "a phone rang");
        }
    }
}

/// A call siphon placed has no caller side: its INVITE carried siphon's
/// Contact already (an originate's own `contact_host`), so only that host can
/// be repeated.
#[tokio::test(flavor = "multi_thread")]
async fn an_originated_call_takes_no_new_caller_contact_host() {
    let dispatcher = test_dispatcher();
    let mut params =
        super::originate_test_harness::anchored_params("sip:callee@198.51.100.20:5060");
    params.media = OriginateMedia::Offer {
        body: endpoint_sdp("192.0.2.1").into_bytes(),
        content_type: "application/sdp".to_string(),
    };
    let prepared = prepare_originate_with_contact_host(
        &dispatcher.state,
        params,
        Some(TENANT_HOST.to_string()),
    )
    .expect("the originate stages");
    let call_id = prepared.internal_call_id;
    assert_eq!(
        set_caller_contact_host(&dispatcher.state, &call_id, TENANT_HOST),
        Ok(())
    );
    assert_eq!(
        set_caller_contact_host(&dispatcher.state, &call_id, "tenant-b.example.com"),
        Err(CallerContactHostRefusal::AlreadyPresented {
            presented: TENANT_HOST.to_string()
        })
    );
}
