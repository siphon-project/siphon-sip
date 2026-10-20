//! The user part siphon presents in its own `Contact`, named by a controller as
//! `contact_user` (and `caller_contact_user` for the caller's side of `dial` /
//! `route`), everywhere `contact_host` can be named.
//!
//! siphon's Contact is userless by default. A trunk peer that keys the account
//! on the Contact user (`<sip:user@host;transport=tls>`) needs one, and until
//! now only a script's `call.set_contact_user()` could add it. Each placement
//! path is read back off the UDP egress against a positive control, the same
//! placement with no user named: the Contact is the control's with only the
//! user part added (and the host too, where a `contact_host` rides beside it).

use super::control_dial_identity_tests::{
    advance_from_the_stored_invite, dial_targets, park, wire, SIP_CALL_ID,
};
use super::control_originate_tests::{callee_answers, controller_on, originate};
use super::lcr_ring_timeout_tests::summaries;
use super::originate_test_harness::{drain, phone_response, phone_sends, requests_to, socket};
use super::sdp_strip_tests::{endpoint_sdp, CALLEE};
use super::session_timer_tests::{age, requests, sweep, timer_dispatcher};
use super::test_dispatcher::{test_dispatcher, TestDispatcher};
use super::*;

const TRUNK_USER: &str = "trunk-7";
const OTHER_USER: &str = "trunk-8";
const TENANT_HOST: &str = "sbc.example.net";
const FIRST_PHONE: &str = "198.51.100.7:5060";
const SECOND_PHONE: &str = "198.51.100.8:5060";

fn target(address: &str, contact_host: Option<&str>, contact_user: Option<&str>) -> DialTarget {
    DialTarget {
        uri: format!("sip:15550100077@{address}"),
        contact_host: contact_host.map(str::to_string),
        contact_user: contact_user.map(str::to_string),
        ..Default::default()
    }
}

/// The URI of a message's `Contact`, parsed back as a peer would.
fn contact_uri(message: &SipMessage) -> SipUri {
    let contact = message.headers.get("Contact").expect("a Contact header");
    crate::sip::headers::nameaddr::NameAddr::parse(contact)
        .expect("the Contact parses")
        .uri
}

/// `presented` is `control` with the user part `user` (and the host `host`,
/// when one is named) and nothing else changed: same scheme, port and
/// parameters, no user parameters, and it serializes back to what was sent.
fn assert_contact_is(presented: &SipUri, control: &SipUri, host: Option<&str>, user: &str) {
    assert_eq!(control.user, None, "the control Contact is userless");
    assert_eq!(presented.user.as_deref(), Some(user), "the Contact user");
    assert!(presented.user_params().is_empty(), "no user parameters");
    let mut expected = control.clone();
    expected.user = Some(user.to_string());
    if let Some(host) = host {
        expected.host = host.to_string();
    }
    assert_eq!(presented.to_string(), expected.to_string());
}

/// The Contact of the B-leg INVITE a one-target connecting dial sends.
fn dialled_contact(contact_host: Option<&str>, contact_user: Option<&str>) -> SipUri {
    let dispatcher = test_dispatcher();
    park(&dispatcher);
    assert!(dial_targets(
        &dispatcher,
        vec![target(FIRST_PHONE, contact_host, contact_user)],
        true,
        &DialShaping::default(),
    )
    .expect("the dial runs"));
    let sent = wire(&dispatcher);
    assert_eq!(summaries(&sent), [format!("INVITE to {FIRST_PHONE}")]);
    contact_uri(&sent[0].message)
}

/// Alone, with a `contact_host`, and absent: the user part is added, composes
/// with the host, and without one the Contact stays siphon's userless one.
#[tokio::test(flavor = "multi_thread")]
async fn a_dial_target_presents_its_contact_user() {
    let control = dialled_contact(None, None);
    assert_eq!(control.user, None, "absent: the Contact stays userless");
    assert_contact_is(
        &dialled_contact(None, Some(TRUNK_USER)),
        &control,
        None,
        TRUNK_USER,
    );
    assert_contact_is(
        &dialled_contact(Some(TENANT_HOST), Some(TRUNK_USER)),
        &control,
        Some(TENANT_HOST),
        TRUNK_USER,
    );
}

/// Each branch of a fork presents its own target's user, and a target naming
/// none presents the userless Contact.
#[tokio::test(flavor = "multi_thread")]
async fn each_branch_of_a_fork_presents_its_own_contact_user() {
    let control = dialled_contact(None, None);
    let dispatcher = test_dispatcher();
    park(&dispatcher);
    assert!(dial_targets(
        &dispatcher,
        vec![
            target(FIRST_PHONE, None, Some(TRUNK_USER)),
            target(SECOND_PHONE, None, None),
        ],
        true,
        &DialShaping::default(),
    )
    .expect("the dial runs"));
    let sent = wire(&dispatcher);
    let to = |phone: &str| {
        sent.iter()
            .find(|frame| frame.destination == socket(phone))
            .map(|frame| contact_uri(&frame.message))
            .unwrap_or_else(|| panic!("no INVITE to {phone}"))
    };
    assert_contact_is(&to(FIRST_PHONE), &control, None, TRUNK_USER);
    assert_eq!(to(SECOND_PHONE).to_string(), control.to_string());
}

/// Every attempt of a sequential hunt is rebuilt by the failover engine and
/// presents its own target's user.
#[tokio::test(flavor = "multi_thread")]
async fn every_attempt_of_a_sequential_dial_presents_its_targets_contact_user() {
    let control = dialled_contact(None, None);
    let dispatcher = test_dispatcher();
    let call_id = park(&dispatcher);
    assert!(dial_targets(
        &dispatcher,
        vec![
            target(FIRST_PHONE, None, Some(TRUNK_USER)),
            target(SECOND_PHONE, Some(TENANT_HOST), Some(OTHER_USER)),
        ],
        false,
        &DialShaping::default(),
    )
    .expect("the dial runs"));
    let sent = wire(&dispatcher);
    assert_eq!(summaries(&sent), [format!("INVITE to {FIRST_PHONE}")]);
    assert_contact_is(&contact_uri(&sent[0].message), &control, None, TRUNK_USER);

    advance_from_the_stored_invite(&dispatcher, &call_id);
    let sent = wire(&dispatcher);
    assert_eq!(summaries(&sent), [format!("INVITE to {SECOND_PHONE}")]);
    assert_contact_is(
        &contact_uri(&sent[0].message),
        &control,
        Some(TENANT_HOST),
        OTHER_USER,
    );
}

/// The `route` verb hands its carriers to the same engine.
#[tokio::test(flavor = "multi_thread")]
async fn a_route_verb_target_presents_its_contact_user() {
    let control = dialled_contact(None, None);
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
            contact_host: None,
            contact_user: Some(TRUNK_USER.to_string()),
        }],
        &[],
        &dispatcher.state,
    );
    assert_eq!(routed, Ok(true));
    let sent = wire(&dispatcher);
    assert_eq!(summaries(&sent), [format!("INVITE to {FIRST_PHONE}")]);
    assert_contact_is(&contact_uri(&sent[0].message), &control, None, TRUNK_USER);
}

/// A target's `contact_user` outranks a script's `call.set_contact_user()`,
/// which still applies to a target naming none; a script's
/// `call.set_contact_uri()` (a GRUU, an edge fronting siphon) outranks both.
#[tokio::test(flavor = "multi_thread")]
async fn a_targets_contact_user_outranks_the_scripts_and_a_script_contact_uri_wins() {
    let control = dialled_contact(None, None);
    let script_user = |dispatcher: &TestDispatcher, call_id: &str| {
        if let Some(mut call) = dispatcher.state.call_actors.get_call_mut(call_id) {
            call.contact_user_override = Some("1001".to_string());
        }
    };

    let dispatcher = test_dispatcher();
    let call_id = park(&dispatcher);
    script_user(&dispatcher, &call_id);
    assert!(dial_targets(
        &dispatcher,
        vec![
            target(FIRST_PHONE, None, Some(TRUNK_USER)),
            target(SECOND_PHONE, None, None),
        ],
        true,
        &DialShaping::default(),
    )
    .expect("the dial runs"));
    let sent = wire(&dispatcher);
    let to = |phone: &str| {
        sent.iter()
            .find(|frame| frame.destination == socket(phone))
            .map(|frame| contact_uri(&frame.message))
            .unwrap_or_else(|| panic!("no INVITE to {phone}"))
    };
    assert_contact_is(&to(FIRST_PHONE), &control, None, TRUNK_USER);
    assert_contact_is(&to(SECOND_PHONE), &control, None, "1001");

    let dispatcher = test_dispatcher();
    let call_id = park(&dispatcher);
    if let Some(mut call) = dispatcher.state.call_actors.get_call_mut(&call_id) {
        call.contact_override = Some("sip:edge@edge.example.net:5070".to_string());
    }
    assert!(dial_targets(
        &dispatcher,
        vec![target(FIRST_PHONE, None, Some(TRUNK_USER))],
        true,
        &DialShaping::default(),
    )
    .expect("the dial runs"));
    assert_eq!(
        wire(&dispatcher)[0].message.headers.get("Contact").cloned(),
        Some("<sip:edge@edge.example.net:5070>".to_string())
    );
}

/// A user siphon cannot put in a Contact refuses the whole dial before any
/// branch rings.
#[tokio::test(flavor = "multi_thread")]
async fn an_unusable_contact_user_is_refused_before_anything_rings() {
    for refused in ["", "trunk@sbc.example.net", "trunk;npdi", "tr unk", "100%"] {
        let dispatcher = test_dispatcher();
        park(&dispatcher);
        let result = dial_targets(
            &dispatcher,
            vec![
                target(FIRST_PHONE, None, None),
                target(SECOND_PHONE, None, Some(refused)),
            ],
            true,
            &DialShaping::default(),
        );
        assert!(
            matches!(result, Err(DialError::InvalidIdentity(ref error)) if error.contains("contact_user")),
            "{refused:?}: {result:?}"
        );
        assert!(wire(&dispatcher).is_empty(), "{refused:?}: something rang");
    }
}

/// The answered B-leg keeps the user in its dialog's local Contact: siphon's
/// own re-INVITE, UPDATE and RFC 4028 session refresh on that leg present it.
#[tokio::test(flavor = "multi_thread")]
async fn in_dialog_requests_on_the_answered_leg_present_the_contact_user() {
    let control = dialled_contact(None, None);
    let dispatcher = timer_dispatcher(Some("session_expires: 90\n"));
    let call_id = park(&dispatcher);
    assert!(dial_targets(
        &dispatcher,
        vec![target(CALLEE, None, Some(TRUNK_USER))],
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
    assert_contact_is(&contact_uri(&invite), &control, None, TRUNK_USER);

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
        assert_contact_is(&contact_uri(&request), &control, None, TRUNK_USER);
    }

    age(&dispatcher, &call_id, false, 46);
    let refresh = requests(&sweep(&dispatcher), CALLEE, Method::Invite)
        .pop()
        .expect("siphon refreshed the session it is the refresher of");
    assert_contact_is(&contact_uri(&refresh), &control, None, TRUNK_USER);
}

/// A bridging dial, driven end to end over the control rail from the
/// controller's own frame: the phone's INVITE presents the target's user and
/// host, against the same dial with neither.
#[tokio::test(flavor = "multi_thread")]
async fn a_bridging_dial_presents_the_contact_user_the_controller_named() {
    use super::dial_bridge_test_harness::{
        answered_caller, bridging_dispatcher, controller_owning, dial,
    };
    use crate::rtpengine::test_native_engine::NativeTestEngine;

    const PHONE: &str = "198.51.100.228:5060";
    let mut contacts = Vec::new();
    for (call_id, named) in [
        ("contact-user-bridge-control@192.0.2.10", false),
        ("contact-user-bridge@192.0.2.10", true),
    ] {
        let engine = NativeTestEngine::start().await;
        let dispatcher = bridging_dispatcher(&engine);
        let caller = answered_caller(&dispatcher, call_id);
        let controller = controller_owning(call_id, dispatcher, &caller, call_id, "hangup");
        let mut dialled = serde_json::json!({ "uri": format!("sip:2101@{PHONE}") });
        if named {
            dialled["contact_user"] = serde_json::json!(TRUNK_USER);
            dialled["contact_host"] = serde_json::json!(TENANT_HOST);
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
    assert_contact_is(&contacts[1], &contacts[0], Some(TENANT_HOST), TRUNK_USER);
}

/// A bridging dial refuses an unusable `contact_user` as `bad_request` over
/// the rail, with nothing sent.
#[tokio::test(flavor = "multi_thread")]
async fn a_bridging_dial_refuses_an_unusable_contact_user() {
    use super::dial_bridge_test_harness::{
        answered_caller, bridging_dispatcher, controller_owning, dial,
    };
    use crate::rtpengine::test_native_engine::NativeTestEngine;

    const PHONE: &str = "198.51.100.229:5060";
    let call_id = "contact-user-bridge-refused@192.0.2.10";
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, call_id);
    let controller = controller_owning(call_id, dispatcher, &caller, call_id, "hangup");
    let (reply, _) = dial(
        &controller,
        call_id,
        serde_json::json!({
            "on_answer": "bridge",
            "targets": [{ "uri": format!("sip:2101@{PHONE}"), "contact_user": "trunk@x" }],
        }),
    )
    .await;
    assert_eq!(reply["error"]["code"], "bad_request", "{reply}");
    assert!(
        reply["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("contact_user")),
        "{reply}"
    );
    assert!(requests_to(
        &drain(&controller.dispatcher.udp),
        socket(PHONE),
        Method::Invite
    )
    .is_empty());
}

fn originate_args(
    channel: &str,
    contact_host: Option<&str>,
    contact_user: Option<&str>,
) -> serde_json::Value {
    let mut args = serde_json::json!({
        "channel": channel,
        "to": format!("sip:callee@{CALLEE}"),
        "sdp": endpoint_sdp("192.0.2.1"),
    });
    if let Some(contact_host) = contact_host {
        args["contact_host"] = serde_json::json!(contact_host);
    }
    if let Some(contact_user) = contact_user {
        args["contact_user"] = serde_json::json!(contact_user);
    }
    args
}

/// The INVITE an `originate` with `contact_user` sends presents it, alone and
/// beside a `contact_host`, and so does every in-dialog request siphon sends
/// once the callee answered: an UPDATE and the session refresh.
#[tokio::test(flavor = "multi_thread")]
async fn an_originate_presents_its_contact_user_for_the_life_of_the_call() {
    let control_controller = controller_on("dialer-contact-user-control", test_dispatcher());
    let reply = originate(
        &control_controller,
        originate_args("cu-control", None, None),
    )
    .await;
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
    assert_eq!(control.user, None);

    let alone = controller_on("dialer-contact-user-alone", test_dispatcher());
    let reply = originate(&alone, originate_args("cu-alone", None, Some(TRUNK_USER))).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let invite = requests(
        &super::session_timer_tests::wire(&alone.dispatcher),
        CALLEE,
        Method::Invite,
    )
    .pop()
    .expect("the originate INVITE");
    assert_contact_is(&contact_uri(&invite), &control, None, TRUNK_USER);

    let controller = controller_on(
        "dialer-contact-user",
        timer_dispatcher(Some("session_expires: 90\n")),
    );
    let reply = originate(
        &controller,
        originate_args("cu-both", Some(TENANT_HOST), Some(TRUNK_USER)),
    )
    .await;
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
    assert_contact_is(
        &contact_uri(&invite),
        &control,
        Some(TENANT_HOST),
        TRUNK_USER,
    );

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
    assert_contact_is(
        &contact_uri(&update),
        &control,
        Some(TENANT_HOST),
        TRUNK_USER,
    );

    age(&controller.dispatcher, &call_id, true, 46);
    let refresh = requests(&sweep(&controller.dispatcher), CALLEE, Method::Invite)
        .pop()
        .expect("siphon refreshed the call");
    assert_contact_is(
        &contact_uri(&refresh),
        &control,
        Some(TENANT_HOST),
        TRUNK_USER,
    );
}

/// `originate {aor}` places one leg per registered phone, and every leg
/// presents the user the controller named.
#[tokio::test(flavor = "multi_thread")]
async fn every_leg_of_an_aor_originate_presents_the_contact_user() {
    const DESK: &str = "198.51.100.123:5060";
    const MOBILE: &str = "198.51.100.124:5060";
    let aor = "sip:3122@siphon.example.com";
    super::dial_bridge_test_harness::register(aor, &format!("sip:3122@{DESK}"), 1.0);
    super::dial_bridge_test_harness::register(aor, &format!("sip:3122@{MOBILE}"), 0.5);

    let controller = controller_on("dialer-contact-user-aor", test_dispatcher());
    let reply = originate(
        &controller,
        serde_json::json!({
            "channel": "cu-aor",
            "aor": aor,
            "sdp": endpoint_sdp("192.0.2.1"),
            "contact_user": TRUNK_USER,
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
        let presented = contact_uri(&invite);
        assert_eq!(presented.user.as_deref(), Some(TRUNK_USER), "{phone}");
        assert!(presented.user_params().is_empty());
    }
}

/// An `originate` naming a user siphon cannot put in its Contact is refused
/// `bad_request` naming the argument, with nothing on the wire.
#[tokio::test(flavor = "multi_thread")]
async fn an_originate_with_an_unusable_contact_user_is_bad_request() {
    let controller = controller_on("dialer-contact-user-refused", test_dispatcher());
    for (channel, contact_user) in [
        ("cu-at", serde_json::json!("trunk@sbc.example.net")),
        ("cu-empty", serde_json::json!("")),
        ("cu-semicolon", serde_json::json!("trunk;npdi")),
        ("cu-number", serde_json::json!(7)),
    ] {
        let mut args = originate_args(channel, None, None);
        args["contact_user"] = contact_user;
        let reply = originate(&controller, args).await;
        assert_eq!(reply["status"], "error", "{reply}");
        assert_eq!(reply["error"]["code"], "bad_request", "{reply}");
        assert!(
            reply["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("contact_user")),
            "{reply}"
        );
    }
    assert!(drain(&controller.dispatcher.udp).is_empty());
}

/// A Contact siphon builds over TLS with a user and a `contact_host` is the
/// form a trunk peer documents, `<sip:user@host:port;transport=tls>`, and
/// reads back as exactly that.
#[test]
fn a_tls_contact_with_a_user_reads_back_as_the_documented_form() {
    let user = crate::dispatcher::checked_contact_user(TRUNK_USER).expect("a user");
    let contact = build_b_leg_contact(
        TENANT_HOST,
        5061,
        crate::transport::Transport::Tls,
        Some(&user),
        None,
    );
    assert_eq!(contact, "<sip:trunk-7@sbc.example.net:5061;transport=tls>");
    let uri = crate::sip::headers::nameaddr::NameAddr::parse(&contact)
        .expect("the Contact parses")
        .uri;
    assert_eq!(uri.user.as_deref(), Some(TRUNK_USER));
    assert_eq!(uri.host, TENANT_HOST);
    assert_eq!(uri.port, Some(5061));
    assert_eq!(format!("<{uri}>"), contact);
}
