//! A sequential `dial {on_answer: "bridge"}` and `reroute_after_progress` on
//! its targets, driven through the control plane's own `dial` verb.
//!
//! A target with `reroute_after_progress: false` that has rung ends the dial
//! on its own outcome; one that never rang moves the hunt on. A 6xx ends a
//! hunt whatever its target says, and CANCELs the phones a parallel dial still
//! has ringing (RFC 3261 §16.7 step 5).

use super::dial_bridge_test_harness::{
    answered_caller, assert_drained, bridging_dispatcher, controller_owning, dial, events,
    invite_to, sent_until,
};
use super::originate_test_harness::{
    drain, phone_response, phone_sends, phone_tries, requests_to, socket,
};
use super::*;
use crate::rtpengine::test_native_engine::NativeTestEngine;

/// `phone` answers `invite` with a final or provisional `code`.
fn phone_says(state: &DispatcherState, phone: &str, invite: &SipMessage, code: u16, reason: &str) {
    let tag = format!("tag-{}", phone.split(':').next().unwrap_or(phone));
    phone_sends(
        state,
        socket(phone),
        &phone_response(invite, code, reason, &tag, &format!("sip:hp@{phone}"), None),
    );
}

/// The three phones of a sequential bridge dial, each target an object with
/// `reroute_after_progress` set to `flag` (left out when `None`).
fn hunt_args(phones: &[&str], flag: Option<bool>) -> serde_json::Value {
    let targets: Vec<serde_json::Value> = phones
        .iter()
        .map(|phone| {
            let mut target = serde_json::json!({ "uri": format!("sip:hp@{phone}") });
            if let Some(flag) = flag {
                target["reroute_after_progress"] = serde_json::Value::Bool(flag);
            }
            target
        })
        .collect();
    serde_json::json!({
        "targets": targets,
        "on_answer": "bridge",
        "strategy": "sequential",
        "timeout": 5,
    })
}

/// The `DialFailed` among `heard`.
fn dial_failed(heard: &[crate::control::protocol::EventFrame]) -> &serde_json::Value {
    &heard
        .iter()
        .find(|event| event.event == "DialFailed")
        .unwrap_or_else(|| panic!("no DialFailed in {heard:?}"))
        .payload
}

/// With the flag off, a phone that rang and was busy ends the hunt with its
/// 486; the phones after it are never rung.
#[tokio::test(flavor = "multi_thread")]
async fn a_phone_that_rang_and_was_busy_ends_the_hunt() {
    const PHONES: [&str; 3] = [
        "198.51.100.71:5060",
        "198.51.100.72:5060",
        "198.51.100.73:5060",
    ];
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "hunt-progress-busy@192.0.2.10");
    let controller = controller_owning("hunt-progress-busy", dispatcher, &caller, "hp1", "hangup");
    let state = &controller.dispatcher.state;
    let udp = &controller.dispatcher.udp;
    let (reply, _) = dial(&controller, "hp1", hunt_args(&PHONES, Some(false))).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let first = invite_to(&drain(udp), PHONES[0]);
    phone_says(state, PHONES[0], &first, 180, "Ringing");
    phone_says(state, PHONES[0], &first, 486, "Busy Here");
    let heard = events(&controller).await;
    let failed = dial_failed(&heard);
    assert_eq!(failed["code"], 486);
    assert_eq!(failed["branches"].as_array().map(Vec::len), Some(1));
    let sent = drain(udp);
    for phone in &PHONES[1..] {
        assert!(
            requests_to(&sent, socket(phone), Method::Invite).is_empty(),
            "{phone} is never rung"
        );
    }
    assert_drained(state);
}

/// With the flag off, a phone that rang and rings out ends the hunt 408.
#[tokio::test(flavor = "multi_thread")]
async fn a_phone_that_rang_and_rings_out_ends_the_hunt() {
    const PHONES: [&str; 3] = [
        "198.51.100.74:5060",
        "198.51.100.75:5060",
        "198.51.100.76:5060",
    ];
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "hunt-progress-timeout@192.0.2.10");
    let controller = controller_owning(
        "hunt-progress-timeout",
        dispatcher,
        &caller,
        "hp2",
        "hangup",
    );
    let state = &controller.dispatcher.state;
    let udp = &controller.dispatcher.udp;
    let (reply, _) = dial(&controller, "hp2", hunt_args(&PHONES, Some(false))).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let first = invite_to(&drain(udp), PHONES[0]);
    phone_says(state, PHONES[0], &first, 180, "Ringing");
    check_b2bua_answer_timeouts_at(
        state,
        std::time::Instant::now() + std::time::Duration::from_secs(6),
    );
    let sent = sent_until(udp, |sent| {
        !requests_to(sent, socket(PHONES[0]), Method::Cancel).is_empty()
    })
    .await;
    // The phone answers its CANCEL with a 487, as RFC 3261 §9.2 has it.
    phone_says(state, PHONES[0], &first, 487, "Request Terminated");
    let heard = events(&controller).await;
    let failed = dial_failed(&heard);
    assert_eq!(failed["code"], 408);
    assert_eq!(failed["timed_out"], true);
    let mut sent = sent;
    sent.extend(drain(udp));
    for phone in &PHONES[1..] {
        assert!(
            requests_to(&sent, socket(phone), Method::Invite).is_empty(),
            "{phone} is never rung"
        );
    }
    assert_drained(state);
}

/// Without the flag, a phone that rang and was busy moves the hunt on, as it
/// always has; with the flag off, a phone that never rang does too.
#[tokio::test(flavor = "multi_thread")]
async fn a_hunt_moves_on_by_default_and_from_a_phone_that_never_rang() {
    for (index, (flag, provisional)) in [(None, Some(180)), (Some(false), None)]
        .into_iter()
        .enumerate()
    {
        let phones = [
            format!("198.51.100.{}:5060", 80 + index * 3),
            format!("198.51.100.{}:5060", 81 + index * 3),
            format!("198.51.100.{}:5060", 82 + index * 3),
        ];
        let phones: Vec<&str> = phones.iter().map(String::as_str).collect();
        let engine = NativeTestEngine::start().await;
        let dispatcher = bridging_dispatcher(&engine);
        let caller = answered_caller(&dispatcher, &format!("hunt-moves-{index}@192.0.2.10"));
        let channel = format!("hm{index}");
        let controller = controller_owning(
            &format!("hunt-moves-{index}"),
            dispatcher,
            &caller,
            &channel,
            "hangup",
        );
        let state = &controller.dispatcher.state;
        let udp = &controller.dispatcher.udp;
        let (reply, _) = dial(&controller, &channel, hunt_args(&phones, flag)).await;
        assert_eq!(reply["status"], "ok", "{reply}");
        let first = invite_to(&drain(udp), phones[0]);
        match provisional {
            Some(code) => phone_says(state, phones[0], &first, code, "Ringing"),
            None => phone_tries(state, phones[0], &first),
        }
        phone_says(state, phones[0], &first, 503, "Service Unavailable");
        let second = invite_to(&drain(udp), phones[1]);
        // The second phone ends the dial: it declines.
        phone_says(state, phones[1], &second, 603, "Decline");
        let heard = events(&controller).await;
        assert_eq!(dial_failed(&heard)["code"], 603);
        assert_drained(state);
    }
}

/// A 6xx ends a sequential bridge dial whatever its target says: the phones
/// after the one that declined are never rung.
#[tokio::test(flavor = "multi_thread")]
async fn a_decline_ends_the_hunt() {
    const PHONES: [&str; 3] = [
        "198.51.100.91:5060",
        "198.51.100.92:5060",
        "198.51.100.93:5060",
    ];
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "hunt-decline@192.0.2.10");
    let controller = controller_owning("hunt-decline", dispatcher, &caller, "hd", "hangup");
    let state = &controller.dispatcher.state;
    let udp = &controller.dispatcher.udp;
    let (reply, _) = dial(&controller, "hd", hunt_args(&PHONES, None)).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let first = invite_to(&drain(udp), PHONES[0]);
    phone_says(state, PHONES[0], &first, 603, "Decline");
    let heard = events(&controller).await;
    let failed = dial_failed(&heard);
    assert_eq!(failed["code"], 603);
    assert_eq!(failed["cause"], "rejected");
    let sent = drain(udp);
    for phone in &PHONES[1..] {
        assert!(
            requests_to(&sent, socket(phone), Method::Invite).is_empty(),
            "{phone} is never rung"
        );
    }
    assert_drained(state);
}

/// A 6xx from one phone of a parallel bridge dial CANCELs the phones still
/// ringing and ends the dial with it.
#[tokio::test(flavor = "multi_thread")]
async fn a_decline_cancels_the_rest_of_a_parallel_dial() {
    const DESK: &str = "198.51.100.94:5060";
    const MOBILE: &str = "198.51.100.95:5060";
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "parallel-decline@192.0.2.10");
    let controller = controller_owning("parallel-decline", dispatcher, &caller, "pd", "hangup");
    let state = &controller.dispatcher.state;
    let udp = &controller.dispatcher.udp;
    let (reply, _) = dial(
        &controller,
        "pd",
        serde_json::json!({
            "targets": [format!("sip:hp@{DESK}"), format!("sip:hp@{MOBILE}")],
            "on_answer": "bridge",
        }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let sent = drain(udp);
    let (desk, mobile) = (invite_to(&sent, DESK), invite_to(&sent, MOBILE));
    phone_says(state, DESK, &desk, 180, "Ringing");
    phone_says(state, MOBILE, &mobile, 603, "Decline");
    let sent = sent_until(udp, |sent| {
        !requests_to(sent, socket(DESK), Method::Cancel).is_empty()
    })
    .await;
    assert_eq!(
        requests_to(&sent, socket(DESK), Method::Cancel).len(),
        1,
        "the desk still ringing is CANCELled"
    );
    phone_says(state, DESK, &desk, 487, "Request Terminated");
    let heard = events(&controller).await;
    let failed = dial_failed(&heard);
    assert_eq!(failed["code"], 603);
    assert_eq!(failed["branches"].as_array().map(Vec::len), Some(2));
    assert_drained(state);
}

/// A `reroute_after_progress` that is not a boolean is `bad_request`, on
/// either form of the dial, and nothing is rung.
#[tokio::test(flavor = "multi_thread")]
async fn a_non_boolean_reroute_after_progress_is_a_bad_request() {
    const PHONE: &str = "198.51.100.96:5060";
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "hunt-bad-flag@192.0.2.10");
    let controller = controller_owning("hunt-bad-flag", dispatcher, &caller, "hb", "hangup");
    let udp = &controller.dispatcher.udp;
    for on_answer in ["bridge", "connect"] {
        let (reply, _) = dial(
            &controller,
            "hb",
            serde_json::json!({
                "targets": [{ "uri": format!("sip:hp@{PHONE}"), "reroute_after_progress": "false" }],
                "on_answer": on_answer,
                "strategy": "sequential",
            }),
        )
        .await;
        assert_eq!(reply["status"], "error", "{reply}");
        assert_eq!(reply["error"]["code"], "bad_request", "{reply}");
        assert!(
            reply["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("reroute_after_progress")),
            "{reply}"
        );
        assert!(
            requests_to(&drain(udp), socket(PHONE), Method::Invite).is_empty(),
            "nothing is rung"
        );
    }
}
