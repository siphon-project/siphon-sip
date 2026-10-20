//! The host siphon presents in its own `Contact` on a leg a controller places,
//! named per target by `contact_host`.
//!
//! siphon advertises one address per transport, so without it every leg of every
//! call presents the same Contact host, and a peer that identifies the tenant or
//! account by the host of the Contact can be served for one tenant per siphon.
//! `contact_host` replaces that host alone: the port, transport and user part
//! stay siphon's own, so the peer's in-dialog requests still reach the listener
//! the INVITE left from (RFC 3261 §12.1.2).
//!
//! Every placement path is read back off the UDP egress against a positive
//! control, the same placement without `contact_host`: the INVITE's Contact is
//! the control's with only the host changed. The leg keeps it as its dialog's
//! local Contact, so the re-INVITE, UPDATE and session refresh siphon sends on
//! the answered leg present it as well.

use super::control_dial_identity_tests::{
    advance_from_the_stored_invite, dial_targets, park, wire, SIP_CALL_ID,
};
use super::control_originate_tests::{callee_answers, controller_on, originate};
use super::lcr_ring_timeout_tests::summaries;
use super::originate_test_harness::{drain, phone_response, phone_sends, requests_to, socket};
use super::sdp_strip_tests::{endpoint_sdp, CALLEE};
use super::session_timer_tests::{age, requests, sweep, timer_dispatcher};
use super::test_dispatcher::test_dispatcher;
use super::*;

/// The host one tenant of the peer is known by.
const TENANT_HOST: &str = "tenant-a.example.com";
/// Another tenant's, on the same siphon.
const OTHER_TENANT_HOST: &str = "tenant-b.example.com";
const FIRST_PHONE: &str = "198.51.100.7:5060";
const SECOND_PHONE: &str = "198.51.100.8:5060";

fn target(address: &str, contact_host: Option<&str>) -> DialTarget {
    DialTarget {
        uri: format!("sip:15550100077@{address}"),
        contact_host: contact_host.map(str::to_string),
        ..Default::default()
    }
}

/// The URI of a message's `Contact`.
fn contact_uri(message: &SipMessage) -> SipUri {
    let contact = message.headers.get("Contact").expect("a Contact header");
    crate::sip::headers::nameaddr::NameAddr::parse(contact)
        .expect("the Contact parses")
        .uri
}

/// `presented` is `control` with its host, and only its host, replaced by
/// `host`: same scheme, user part, port and parameters.
fn assert_only_the_host_differs(presented: &SipUri, control: &SipUri, host: &str) {
    assert_eq!(presented.host, host, "the Contact host is not the target's");
    let mut expected = control.clone();
    expected.host = host.to_string();
    assert_eq!(
        presented.to_string(),
        expected.to_string(),
        "contact_host changed more than the Contact's host"
    );
}

/// The Contact of the B-leg INVITE a one-target connecting dial sends.
fn dialled_contact(contact_host: Option<&str>) -> SipUri {
    let dispatcher = test_dispatcher();
    park(&dispatcher);
    assert!(dial_targets(
        &dispatcher,
        vec![target(FIRST_PHONE, contact_host)],
        true,
        &DialShaping::default(),
    )
    .expect("the dial runs"));
    let sent = wire(&dispatcher);
    assert_eq!(summaries(&sent), [format!("INVITE to {FIRST_PHONE}")]);
    contact_uri(&sent[0].message)
}

/// A connecting dial presents the target's host in the B-leg's Contact and
/// keeps everything else of siphon's own: the control dial shows what that is.
#[tokio::test(flavor = "multi_thread")]
async fn a_dial_target_presents_its_contact_host() {
    let control = dialled_contact(None);
    assert_ne!(control.host, TENANT_HOST);
    assert_only_the_host_differs(&dialled_contact(Some(TENANT_HOST)), &control, TENANT_HOST);
}

/// An IPv6 address is carried bracketed in the Contact, however it was named.
#[tokio::test(flavor = "multi_thread")]
async fn an_ipv6_contact_host_is_bracketed_in_the_contact() {
    let control = dialled_contact(None);
    assert_only_the_host_differs(
        &dialled_contact(Some("2001:db8::5")),
        &control,
        "[2001:db8::5]",
    );
}

/// Each branch of a fork presents its own target's host, and a target naming
/// none presents siphon's advertised one.
#[tokio::test(flavor = "multi_thread")]
async fn each_branch_of_a_fork_presents_its_own_contact_host() {
    let control = dialled_contact(None);
    let dispatcher = test_dispatcher();
    park(&dispatcher);
    assert!(dial_targets(
        &dispatcher,
        vec![
            target(FIRST_PHONE, Some(TENANT_HOST)),
            target(SECOND_PHONE, None),
        ],
        true,
        &DialShaping::default(),
    )
    .expect("the dial runs"));
    let sent = wire(&dispatcher);
    let first = sent
        .iter()
        .find(|frame| frame.destination == socket(FIRST_PHONE))
        .expect("an INVITE to the first phone");
    let second = sent
        .iter()
        .find(|frame| frame.destination == socket(SECOND_PHONE))
        .expect("an INVITE to the second phone");
    assert_only_the_host_differs(&contact_uri(&first.message), &control, TENANT_HOST);
    assert_eq!(
        contact_uri(&second.message).to_string(),
        control.to_string(),
        "a target naming no contact_host presents the advertised Contact"
    );
}

/// Every attempt of a sequential hunt is rebuilt by the failover engine, so a
/// host that reached only the first would present the second to its peer as
/// the wrong tenant.
#[tokio::test(flavor = "multi_thread")]
async fn every_attempt_of_a_sequential_dial_presents_its_targets_contact_host() {
    let control = dialled_contact(None);
    let dispatcher = test_dispatcher();
    let call_id = park(&dispatcher);
    assert!(dial_targets(
        &dispatcher,
        vec![
            target(FIRST_PHONE, Some(TENANT_HOST)),
            target(SECOND_PHONE, Some(OTHER_TENANT_HOST)),
        ],
        false,
        &DialShaping::default(),
    )
    .expect("the dial runs"));
    let sent = wire(&dispatcher);
    assert_eq!(summaries(&sent), [format!("INVITE to {FIRST_PHONE}")]);
    assert_only_the_host_differs(&contact_uri(&sent[0].message), &control, TENANT_HOST);

    advance_from_the_stored_invite(&dispatcher, &call_id);
    let sent = wire(&dispatcher);
    assert_eq!(summaries(&sent), [format!("INVITE to {SECOND_PHONE}")]);
    assert_only_the_host_differs(&contact_uri(&sent[0].message), &control, OTHER_TENANT_HOST);
}

/// The `route` verb hands its carriers to the same engine, and a target's
/// `contact_host` reaches the wire the same way.
#[tokio::test(flavor = "multi_thread")]
async fn a_route_verb_target_presents_its_contact_host() {
    let control = dialled_contact(None);
    let dispatcher = test_dispatcher();
    park(&dispatcher);
    let routed = b2bua_route_call_with_state(
        SIP_CALL_ID,
        vec![RouteTarget {
            uri: format!("sip:15550100077@{FIRST_PHONE}"),
            next_hop: None,
            headers: Vec::new(),
            timeout_secs: None,
            reroute_after_progress: false,
            route: Vec::new(),
            contact_host: Some(TENANT_HOST.to_string()),
            contact_user: None,
            verify_server: None,
        }],
        &[],
        &dispatcher.state,
    );
    assert_eq!(routed, Ok(true));
    let sent = wire(&dispatcher);
    assert_eq!(summaries(&sent), [format!("INVITE to {FIRST_PHONE}")]);
    assert_only_the_host_differs(&contact_uri(&sent[0].message), &control, TENANT_HOST);
}

/// `call.set_contact_user()` composes with `contact_host`: the user part rides
/// on the target's host. `call.set_contact_uri()` names the whole URI and wins,
/// because a deployment that fronts siphon owns where in-dialog requests go.
#[tokio::test(flavor = "multi_thread")]
async fn a_script_contact_user_composes_and_a_script_contact_uri_wins() {
    let control = dialled_contact(None);

    let dispatcher = test_dispatcher();
    let call_id = park(&dispatcher);
    if let Some(mut call) = dispatcher.state.call_actors.get_call_mut(&call_id) {
        call.contact_user_override = Some("trunk-7".to_string());
    }
    assert!(dial_targets(
        &dispatcher,
        vec![target(FIRST_PHONE, Some(TENANT_HOST))],
        true,
        &DialShaping::default(),
    )
    .expect("the dial runs"));
    let presented = contact_uri(&wire(&dispatcher)[0].message);
    let mut expected = control.clone();
    expected.host = TENANT_HOST.to_string();
    expected.user = Some("trunk-7".to_string());
    assert_eq!(presented.to_string(), expected.to_string());

    let dispatcher = test_dispatcher();
    let call_id = park(&dispatcher);
    if let Some(mut call) = dispatcher.state.call_actors.get_call_mut(&call_id) {
        call.contact_override = Some("sip:edge@edge.example.net:5070".to_string());
    }
    assert!(dial_targets(
        &dispatcher,
        vec![target(FIRST_PHONE, Some(TENANT_HOST))],
        true,
        &DialShaping::default(),
    )
    .expect("the dial runs"));
    assert_eq!(
        wire(&dispatcher)[0].message.headers.get("Contact").cloned(),
        Some("<sip:edge@edge.example.net:5070>".to_string())
    );
}

/// A host siphon cannot put in a Contact refuses the whole dial before any
/// branch rings, as an unparseable `to` does.
#[tokio::test(flavor = "multi_thread")]
async fn an_unusable_contact_host_is_refused_before_anything_rings() {
    for refused in ["tenant-a.example.com:5070", "sip:tenant-a.example.com", ""] {
        let dispatcher = test_dispatcher();
        park(&dispatcher);
        let result = dial_targets(
            &dispatcher,
            vec![
                target(FIRST_PHONE, None),
                target(SECOND_PHONE, Some(refused)),
            ],
            true,
            &DialShaping::default(),
        );
        assert!(
            matches!(result, Err(DialError::InvalidIdentity(_))),
            "{refused:?}: {result:?}"
        );
        assert!(wire(&dispatcher).is_empty(), "{refused:?}: something rang");
    }
}

/// The answered B-leg keeps the target's host as its dialog's local Contact:
/// siphon's own re-INVITE, UPDATE and RFC 4028 session refresh on that leg all
/// present it, not the advertised one (RFC 3261 §12.2.1.1: a UA's Contact in a
/// target refresh request is its remote target for the peer).
#[tokio::test(flavor = "multi_thread")]
async fn in_dialog_requests_on_the_answered_leg_present_the_contact_host() {
    let control = dialled_contact(None);
    let dispatcher = timer_dispatcher(Some("session_expires: 90\n"));
    let call_id = park(&dispatcher);
    assert!(dial_targets(
        &dispatcher,
        vec![target(CALLEE, Some(TENANT_HOST))],
        true,
        &DialShaping::default(),
    )
    .expect("the dial runs"));
    let invite = requests(
        &super::session_timer_tests::wire(&dispatcher),
        CALLEE,
        Method::Invite,
    )
    .pop()
    .expect("the B-leg INVITE");
    assert_only_the_host_differs(&contact_uri(&invite), &control, TENANT_HOST);

    let mut answer = phone_response(
        &invite,
        200,
        "OK",
        "phone-tag",
        &format!("sip:callee@{CALLEE}"),
        Some(&endpoint_sdp("198.51.100.20")),
    );
    answer.headers.set("Supported", "timer".to_string());
    answer
        .headers
        .set("Session-Expires", "90;refresher=uac".to_string());
    phone_sends(&dispatcher.state, socket(CALLEE), &answer);
    let _ = super::session_timer_tests::wire(&dispatcher);

    assert!(send_in_dialog_reinvite(
        &call_id,
        false,
        Some(endpoint_sdp("192.0.2.1").into_bytes()),
        &[],
        "reinvite:a2b",
        |_| {},
        &dispatcher.state,
    ));
    assert!(send_in_dialog_request(
        &call_id,
        false,
        InDialogRequest {
            method: Method::Update,
            body: None,
            extra_headers: &[],
            tracking_target: "update:a2b",
            requested_session_expires: None,
        },
        |_| {},
        &dispatcher.state,
    ));
    let sent = super::session_timer_tests::wire(&dispatcher);
    for method in [Method::Invite, Method::Update] {
        let request = requests(&sent, CALLEE, method.clone())
            .pop()
            .unwrap_or_else(|| panic!("no {method:?} reached the callee"));
        assert_eq!(request.headers.call_id(), invite.headers.call_id());
        assert_only_the_host_differs(&contact_uri(&request), &control, TENANT_HOST);
    }

    age(&dispatcher, &call_id, false, 46);
    let refresh = requests(&sweep(&dispatcher), CALLEE, Method::Invite)
        .pop()
        .expect("siphon refreshed the session it is the refresher of");
    assert_eq!(refresh.headers.call_id(), invite.headers.call_id());
    assert_only_the_host_differs(&contact_uri(&refresh), &control, TENANT_HOST);
}

/// A bridging dial rings each phone as a call siphon places itself, from the
/// control plane's own parse of the target, so this drives the verb end to end
/// and compares against the same dial without `contact_host`.
#[tokio::test(flavor = "multi_thread")]
async fn a_bridging_dial_presents_the_contact_host_the_controller_named() {
    use super::dial_bridge_test_harness::{
        answered_caller, bridging_dispatcher, controller_owning, dial,
    };
    use crate::rtpengine::test_native_engine::NativeTestEngine;

    const PHONE: &str = "198.51.100.226:5060";
    let mut contacts = Vec::new();
    for (call_id, contact_host) in [
        ("contact-host-bridge-control@192.0.2.10", None),
        ("contact-host-bridge@192.0.2.10", Some("2001:db8::7")),
    ] {
        let engine = NativeTestEngine::start().await;
        let dispatcher = bridging_dispatcher(&engine);
        let caller = answered_caller(&dispatcher, call_id);
        let controller = controller_owning(call_id, dispatcher, &caller, call_id, "hangup");
        let mut dialled = serde_json::json!({ "uri": format!("sip:2101@{PHONE}") });
        if let Some(contact_host) = contact_host {
            dialled["contact_host"] = serde_json::json!(contact_host);
        }
        let (reply, _) = dial(
            &controller,
            call_id,
            serde_json::json!({ "on_answer": "bridge", "targets": [dialled] }),
        )
        .await;
        assert_eq!(reply["status"], "ok", "{reply}");
        let invite = requests_to(
            &drain(&controller.dispatcher.udp),
            socket(PHONE),
            Method::Invite,
        )
        .pop()
        .unwrap_or_else(|| panic!("no INVITE reached the phone for {call_id}"))
        .message;
        contacts.push(contact_uri(&invite));
    }
    assert_only_the_host_differs(&contacts[1], &contacts[0], "[2001:db8::7]");
}

/// The SDP an originate offers.
fn originate_args(channel: &str, contact_host: Option<&str>) -> serde_json::Value {
    let mut args = serde_json::json!({
        "channel": channel,
        "to": format!("sip:callee@{CALLEE}"),
        "sdp": endpoint_sdp("192.0.2.1"),
    });
    if let Some(contact_host) = contact_host {
        args["contact_host"] = serde_json::json!(contact_host);
    }
    args
}

/// The INVITE an `originate` with `contact_host` sends presents it, and so does
/// every in-dialog request siphon sends once the callee answered: the session
/// refresh siphon is the refresher of and an UPDATE.
#[tokio::test(flavor = "multi_thread")]
async fn an_originate_presents_its_contact_host_for_the_life_of_the_call() {
    let control_controller = controller_on("dialer-contact-host-control", test_dispatcher());
    let reply = originate(&control_controller, originate_args("ch-control", None)).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let control = contact_uri(
        &requests(
            &super::session_timer_tests::wire(&control_controller.dispatcher),
            CALLEE,
            Method::Invite,
        )
        .pop()
        .expect("the control INVITE"),
    );

    let controller = controller_on(
        "dialer-contact-host",
        timer_dispatcher(Some("session_expires: 90\n")),
    );
    let reply = originate(&controller, originate_args("ch-tenant", Some(TENANT_HOST))).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let call_id = reply["result"]["call_id"]
        .as_str()
        .expect("the call id")
        .to_string();
    let invite = requests(
        &super::session_timer_tests::wire(&controller.dispatcher),
        CALLEE,
        Method::Invite,
    )
    .pop()
    .expect("the originate INVITE");
    assert_only_the_host_differs(&contact_uri(&invite), &control, TENANT_HOST);

    callee_answers(
        &controller,
        &call_id,
        &invite,
        &[
            ("Supported", "timer"),
            ("Session-Expires", "90;refresher=uac"),
        ],
    );
    let _ = super::session_timer_tests::wire(&controller.dispatcher);
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
        &controller.dispatcher.state,
    ));
    let update = requests(
        &super::session_timer_tests::wire(&controller.dispatcher),
        CALLEE,
        Method::Update,
    )
    .pop()
    .expect("the UPDATE");
    assert_only_the_host_differs(&contact_uri(&update), &control, TENANT_HOST);

    age(&controller.dispatcher, &call_id, true, 46);
    let refresh = requests(&sweep(&controller.dispatcher), CALLEE, Method::Invite)
        .pop()
        .expect("siphon refreshed the call");
    assert_only_the_host_differs(&contact_uri(&refresh), &control, TENANT_HOST);
}

/// `originate {aor}` places one leg per registered phone, and every leg
/// presents the host the controller named.
#[tokio::test(flavor = "multi_thread")]
async fn every_leg_of_an_aor_originate_presents_the_contact_host() {
    const DESK: &str = "198.51.100.121:5060";
    const MOBILE: &str = "198.51.100.122:5060";
    let aor = "sip:3121@siphon.example.com";
    super::dial_bridge_test_harness::register(aor, &format!("sip:3121@{DESK}"), 1.0);
    super::dial_bridge_test_harness::register(aor, &format!("sip:3121@{MOBILE}"), 0.5);
    let control = {
        let controller = controller_on("dialer-contact-host-aor-control", test_dispatcher());
        let reply = originate(&controller, originate_args("ch-aor-control", None)).await;
        assert_eq!(reply["status"], "ok", "{reply}");
        contact_uri(
            &requests(
                &super::session_timer_tests::wire(&controller.dispatcher),
                CALLEE,
                Method::Invite,
            )
            .pop()
            .expect("the control INVITE"),
        )
    };

    let controller = controller_on("dialer-contact-host-aor", test_dispatcher());
    let reply = originate(
        &controller,
        serde_json::json!({
            "channel": "ch-aor",
            "aor": aor,
            "sdp": endpoint_sdp("192.0.2.1"),
            "contact_host": TENANT_HOST,
        }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let sent = drain(&controller.dispatcher.udp);
    for phone in [DESK, MOBILE] {
        let invite = requests_to(&sent, socket(phone), Method::Invite)
            .pop()
            .unwrap_or_else(|| panic!("no INVITE reached {phone}"))
            .message;
        assert_only_the_host_differs(&contact_uri(&invite), &control, TENANT_HOST);
    }
}

/// An `originate` naming a host siphon cannot put in its Contact is refused
/// `bad_request` with nothing on the wire.
#[tokio::test(flavor = "multi_thread")]
async fn an_originate_with_an_unusable_contact_host_is_bad_request() {
    let controller = controller_on("dialer-contact-host-refused", test_dispatcher());
    for (channel, contact_host) in [
        ("ch-port", serde_json::json!("tenant-a.example.com:5070")),
        ("ch-number", serde_json::json!(5070)),
    ] {
        let mut args = originate_args(channel, None);
        args["contact_host"] = contact_host;
        let reply = originate(&controller, args).await;
        assert_eq!(reply["status"], "error", "{reply}");
        assert_eq!(reply["error"]["code"], "bad_request", "{reply}");
        assert!(
            reply["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("contact_host")),
            "{reply}"
        );
    }
    assert!(drain(&controller.dispatcher.udp).is_empty());
}

/// The answer to a re-INVITE or UPDATE the callee sent is relayed back to it
/// with the Contact of the callee's own dialog, the one its INVITE carried.
/// It used to present the advertised address there, which moved the callee's
/// remote target off the `contact_host` the leg was dialled with (RFC 3261
/// §12.2.2: a 2xx to a target refresh request carries the answerer's Contact).
/// The positive control is the caller-facing relay, which keeps presenting the
/// caller's dialog Contact.
#[tokio::test(flavor = "multi_thread")]
async fn an_answer_relayed_to_the_callee_presents_its_dialogs_contact() {
    use super::sdp_strip_tests::{
        address, answered_call, caller_response, response_to, siphon_a_leg_tag, snapshot,
        strip_dispatcher, track_forwarded, CALLER,
    };
    const DIALOG_CONTACT: &str = "<sip:tenant-a.example.com:5060;transport=udp>";

    for method in ["INVITE", "UPDATE"] {
        let dispatcher = strip_dispatcher(&[]);
        let call_id = answered_call(&dispatcher);
        if let Some(mut call) = dispatcher.state.call_actors.get_call_mut(&call_id) {
            call.b_legs[0].dialog.local_contact = Some(DIALOG_CONTACT.to_string());
        }
        let marker = format!(
            "{}:b2a",
            method.to_lowercase().replace("invite", "reinvite")
        );
        let branch = track_forwarded(&dispatcher, &call_id, method, &marker, false);
        let siphon_tag = siphon_a_leg_tag(&dispatcher, &call_id);
        let mut answer = caller_response(
            &branch,
            &format!("2 {method}"),
            &siphon_tag,
            &endpoint_sdp("192.0.2.10"),
        );
        let taken = snapshot(&dispatcher, &call_id, &branch);
        let forwarded = if method == "INVITE" {
            forward_reinvite_response(
                &call_id,
                &branch,
                &mut answer,
                200,
                address(CALLER),
                &dispatcher.state,
                &taken,
            )
        } else {
            forward_update_response(
                &call_id,
                &mut answer,
                200,
                address(CALLER),
                &dispatcher.state,
                &taken,
            )
        };
        assert!(forwarded, "{method}");
        let relayed = response_to(&super::session_timer_tests::wire(&dispatcher), CALLEE, 200);
        assert_eq!(
            relayed.headers.get("Contact").map(String::as_str),
            Some(DIALOG_CONTACT),
            "the {method} 2xx relayed to the callee"
        );
    }
}
