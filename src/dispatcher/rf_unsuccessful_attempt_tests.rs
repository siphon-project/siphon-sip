//! Rf: an INVITE that never became a session is one ACR EVENT per node.
//!
//! TS 32.260 V18.3.0 table 5.2.1.1-1 gives the Charging Data Request [Event]
//! to "SIP Final Response (4xx, 5xx or 6xx), indicating an unsuccessful SIP
//! session set-up" and to "SIP CANCEL, indicating abortion of a SIP session
//! set-up". TS 32.299 V18.0.0 clause 7.2.35 has the failure carried in
//! `Cause-Code` as the SIP status itself: values >= 1 are failures, and "in
//! case of errors where the session has been terminated as a result of a
//! specific known SIP error code, then the SIP error code is also used as the
//! cause code".
//!
//! A caller's CANCEL used to produce nothing at all: the proxy answers the
//! caller `487` itself and absorbs the `487` the branch draws back, and the
//! only EVENT emitter sat behind that absorption. Driven here through the
//! dispatcher's own entry points against a loopback CDF.

use std::time::Duration;

use super::proxy_cancel_awaits_provisional_tests::{
    answers, call, caller_cancels, cancels_to, fire, CALLER, FAILED, RINGING,
};
use super::proxy_dialog_state_tests::{find, Proxy, Sent};
use super::rf_reinvite_tests::{mock_cdf_with_wire, ReceivedAcrs, ReceivedWire};
use super::test_dispatcher::test_dispatcher_with_script;
use super::*;

const EVENT_RECORD: u64 = 1;
const START_RECORD: u64 = 2;
const ORIGINATING_ROLE: u64 = 0;
const P_CSCF: u64 = 1;

/// A charging P-CSCF whose script hands every INVITE to `routing` (one line of
/// Python, the body of the request handler).
async fn charging_proxy(routing: &str) -> (Proxy, ReceivedAcrs) {
    let (proxy, received, _) = charging_proxy_with_wire(routing).await;
    (proxy, received)
}

/// [`charging_proxy`], also handing back each ACR's octets.
async fn charging_proxy_with_wire(routing: &str) -> (Proxy, ReceivedAcrs, ReceivedWire) {
    let script = format!(
        concat!(
            "from siphon import proxy\n",
            "\n",
            "@proxy.on_request\n",
            "def route(request):\n",
            "    {routing}\n",
        ),
        routing = routing,
    );
    let mut dispatcher = test_dispatcher_with_script(&script);
    let (manager, received, wire) = mock_cdf_with_wire().await;
    dispatcher.state.local_domains = Arc::new(vec!["example.com".to_string()]);
    dispatcher.state.rf_charger = Some(crate::diameter::rf_service::RfChargingService::new(
        manager,
        crate::config::RfConfig {
            enabled: true,
            node_functionality: "pcscf".to_string(),
            ..Default::default()
        },
    ));
    let proxy = Proxy {
        state: Arc::new(dispatcher.state),
        udp: dispatcher.udp,
    };
    (proxy, received, wire)
}

/// The responses to the INVITE the caller was sent, the proxy's own `100`
/// aside: what a CANCEL is answered with is not the call's outcome.
fn invite_finals_to_caller(sent: &[Sent]) -> Vec<u16> {
    sent.iter()
        .filter(|sent| sent.destination == CALLER)
        .filter(|sent| {
            sent.message
                .headers
                .get("CSeq")
                .is_some_and(|cseq| cseq.ends_with("INVITE"))
        })
        .filter_map(|sent| sent.message.status_code())
        .filter(|status_code| *status_code != 100)
        .collect()
}

fn relaying(target: &str) -> String {
    format!("request.relay(\"sip:callee@{target}\")")
}

fn forking(targets: &[&str]) -> String {
    let uris: Vec<String> = targets
        .iter()
        .map(|target| format!("\"sip:callee@{target}\""))
        .collect();
    format!("request.fork([{}], strategy=\"parallel\")", uris.join(", "))
}

/// Every ACR the CDF was sent, once nothing more has arrived for a while: the
/// tests count records, so a late duplicate must have had its chance.
async fn settled(received: &ReceivedAcrs) -> Vec<serde_json::Value> {
    let mut seen = usize::MAX;
    loop {
        tokio::time::sleep(Duration::from_millis(300)).await;
        let now = received.lock().expect("the ACR log").len();
        if now == seen {
            return received.lock().expect("the ACR log").clone();
        }
        seen = now;
    }
}

/// The one ACR the CDF got, checked to be the EVENT of a failed INVITE from
/// an originating P-CSCF, and its Cause-Code.
fn the_one_event(acrs: &[serde_json::Value]) -> i64 {
    assert_eq!(acrs.len(), 1, "one record for the attempt: {acrs:#?}");
    let acr = &acrs[0];
    assert_eq!(acr["Accounting-Record-Type"], EVENT_RECORD, "EVENT_RECORD");
    let ims = &acr["Service-Information"]["IMS-Information"];
    assert_eq!(ims["Role-of-Node"], ORIGINATING_ROLE);
    assert_eq!(ims["Node-Functionality"], P_CSCF);
    assert_eq!(
        ims["Event-Type"]["SIP-Method"], "INVITE",
        "the record is about the INVITE that failed"
    );
    ims["Cause-Code"]
        .as_i64()
        .unwrap_or_else(|| panic!("no Cause-Code in {ims:#?}"))
}

/// The report: the callee rings, the caller hangs up. The proxy answers the
/// caller 487 and CANCELs the branch, which answers 487 in turn.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_call_is_one_event_with_cause_487() {
    let (proxy, received) = charging_proxy(&relaying(RINGING)).await;
    let (raw, invites) = call(&proxy, "rf-cancel@192.0.2.50");
    let branch = find(&invites, RINGING).clone();
    answers(&proxy, RINGING, &branch, 180, "Ringing");
    caller_cancels(&proxy, &raw);
    let sent = proxy.wire();
    assert_eq!(invite_finals_to_caller(&sent), [180, 487]);
    let cancel = cancels_to(&sent, RINGING).pop().expect("the branch CANCEL");
    answers(&proxy, RINGING, &cancel, 200, "OK");
    answers(&proxy, RINGING, &branch, 487, "Request Terminated");

    assert_eq!(the_one_event(&settled(&received).await), 487);
}

/// A cancelled call whose branch never answers its CANCEL: the timeout that
/// ends the branch later is not a second attempt, and not the cause either.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_branch_that_then_times_out_reports_no_408() {
    let (proxy, received) = charging_proxy(&relaying(RINGING)).await;
    let (raw, invites) = call(&proxy, "rf-cancel-timeout@192.0.2.50");
    let branch = find(&invites, RINGING).clone();
    answers(&proxy, RINGING, &branch, 180, "Ringing");
    caller_cancels(&proxy, &raw);
    let _ = proxy.wire();
    // The branch's INVITE client transaction gives up (Timer C, then the 64*T1
    // its CANCEL is given), which the proxy takes for a 408 on that branch
    // (RFC 3261 §16.7 step 2): the dispatcher's `Action::Timeout` arm.
    let client_key = TransactionManager::key_from_message(&branch).expect("a transaction key");
    tokio::task::block_in_place(|| {
        fail_branch_locally(
            &client_key,
            408,
            "Request Timeout",
            "client transaction timed out (RFC 3261 §16.7)",
            &proxy.state,
        )
    });
    assert!(
        invite_finals_to_caller(&proxy.wire()).is_empty(),
        "the caller already has its 487"
    );

    assert_eq!(the_one_event(&settled(&received).await), 487);
}

/// A fork CANCELled while both branches ring is one attempt from this node,
/// whatever its branches then answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_fork_is_one_event_not_one_per_branch() {
    let (proxy, received) = charging_proxy(&forking(&[RINGING, FAILED])).await;
    let (raw, invites) = call(&proxy, "rf-cancel-fork@192.0.2.50");
    for target in [RINGING, FAILED] {
        answers(&proxy, target, find(&invites, target), 180, "Ringing");
    }
    caller_cancels(&proxy, &raw);
    let _ = proxy.wire();
    for target in [RINGING, FAILED] {
        answers(
            &proxy,
            target,
            find(&invites, target),
            487,
            "Request Terminated",
        );
    }

    assert_eq!(the_one_event(&settled(&received).await), 487);
}

/// A callee that declines, and one that does not exist: the SIP status is the
/// cause, as a positive value.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rejected_call_is_one_event_with_the_status_as_its_cause() {
    for (status, reason) in [(486, "Busy Here"), (404, "Not Found")] {
        let (proxy, received) = charging_proxy(&relaying(RINGING)).await;
        let (_, invites) = call(&proxy, &format!("rf-reject-{status}@192.0.2.50"));
        let branch = find(&invites, RINGING).clone();
        answers(&proxy, RINGING, &branch, 180, "Ringing");
        answers(&proxy, RINGING, &branch, status, reason);
        assert_eq!(invite_finals_to_caller(&proxy.wire()), [180, status]);

        assert_eq!(
            the_one_event(&settled(&received).await),
            i64::from(status),
            "{status}"
        );
    }
}

/// A forked call whose branches all fail is one record with the status the
/// caller got (RFC 3261 §16.7 step 6), not one per branch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_fork_is_one_event_with_the_best_status() {
    let (proxy, received) = charging_proxy(&forking(&[RINGING, FAILED])).await;
    let (_, invites) = call(&proxy, "rf-fork-fail@192.0.2.50");
    answers(&proxy, RINGING, find(&invites, RINGING), 486, "Busy Here");
    answers(&proxy, FAILED, find(&invites, FAILED), 404, "Not Found");
    let to_caller = invite_finals_to_caller(&proxy.wire());
    assert_eq!(to_caller.len(), 1);

    assert_eq!(
        the_one_event(&settled(&received).await),
        i64::from(to_caller[0])
    );
}

/// A branch that never answers at all really did time out here, and 408 is
/// then the cause.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_call_that_times_out_is_one_event_with_cause_408() {
    let (proxy, received) = charging_proxy(&relaying(RINGING)).await;
    let (_, invites) = call(&proxy, "rf-timeout@192.0.2.50");
    let branch = find(&invites, RINGING).clone();
    fire(&proxy, &branch, TimerName::B);
    assert_eq!(invite_finals_to_caller(&proxy.wire()), [408]);

    assert_eq!(the_one_event(&settled(&received).await), 408);
}

/// A 2xx that crossed the caller's CANCEL answered the INVITE first: the
/// CANCEL has no effect (RFC 3261 §9.2), and the call is a session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_2xx_that_crosses_the_cancel_is_a_session_not_a_failure() {
    let (proxy, received) = charging_proxy(&relaying(RINGING)).await;
    let (raw, invites) = call(&proxy, "rf-cancel-glare@192.0.2.50");
    let branch = find(&invites, RINGING).clone();
    answers(&proxy, RINGING, &branch, 180, "Ringing");
    answers(&proxy, RINGING, &branch, 200, "OK");
    caller_cancels(&proxy, &raw);
    assert_eq!(invite_finals_to_caller(&proxy.wire()), [180, 200]);

    let acrs = settled(&received).await;
    let types: Vec<u64> = acrs
        .iter()
        .map(|acr| acr["Accounting-Record-Type"].as_u64().unwrap_or_default())
        .collect();
    assert_eq!(types, [START_RECORD], "a START and no EVENT: {acrs:#?}");
}

/// `reply.reject()` fails the set-up from the reply path: one EVENT with the
/// script's status, and nothing more for the 487 its CANCEL draws back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reply_time_reject_is_one_event_with_the_rejected_status() {
    let script_reject = concat!(
        "request.relay(\"sip:callee@198.51.100.11:5060\")\n",
        "\n",
        "@proxy.on_reply\n",
        "def answered(request, reply):\n",
        "    if reply.status_code == 183:\n",
        "        reply.reject(503, \"Service Unavailable\")\n",
        "        return\n",
        "    reply.relay()",
    );
    let (proxy, received) = charging_proxy(script_reject).await;
    let (_, invites) = call(&proxy, "rf-reject-on-reply@192.0.2.50");
    let branch = find(&invites, RINGING).clone();
    answers(&proxy, RINGING, &branch, 183, "Session Progress");
    let sent = proxy.wire();
    // A 503 a proxy produces itself still goes upstream as 503: RFC 3261
    // §16.7 step 6 rewrites a 503 a branch sent, not the proxy's own.
    let to_caller = invite_finals_to_caller(&sent);
    assert_eq!(to_caller.len(), 1, "{to_caller:?}");
    let cancel = cancels_to(&sent, RINGING).pop().expect("the branch CANCEL");
    answers(&proxy, RINGING, &cancel, 200, "OK");
    answers(&proxy, RINGING, &branch, 487, "Request Terminated");

    assert_eq!(the_one_event(&settled(&received).await), 503);
}

/// The EVENTs of a cancelled, a busy and a redirected call, as the dispatcher
/// put them on the wire, written as `text2pcap` hex dumps to the directory in
/// `SIPHON_RF_FAILED_SETUP_HEX_DIR` for `scripts/validate_rf_unsuccessful_acr.sh`.
/// The tests above read the records back with our own decoder; tshark reads
/// them with Wireshark's dictionary, which does not share our misreadings.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn emit_failed_setup_acrs_for_external_dissection() {
    let Ok(directory) = std::env::var("SIPHON_RF_FAILED_SETUP_HEX_DIR") else {
        // Nothing to do in an ordinary test run.
        return;
    };
    for (name, status, reason) in [
        ("cancel_487", 487, ""),
        ("busy_486", 486, "Busy Here"),
        ("redirect_302", 302, "Moved Temporarily"),
    ] {
        let (proxy, received, wire) = charging_proxy_with_wire(&relaying(RINGING)).await;
        let (raw, invites) = call(&proxy, &format!("rf-dissect-{name}@192.0.2.50"));
        let branch = find(&invites, RINGING).clone();
        answers(&proxy, RINGING, &branch, 180, "Ringing");
        if status == 487 {
            caller_cancels(&proxy, &raw);
            let cancel = cancels_to(&proxy.wire(), RINGING)
                .pop()
                .expect("the branch CANCEL");
            answers(&proxy, RINGING, &cancel, 200, "OK");
            answers(&proxy, RINGING, &branch, 487, "Request Terminated");
        } else {
            answers(&proxy, RINGING, &branch, status, reason);
        }
        assert_eq!(settled(&received).await.len(), 1, "{name}");
        let octets = wire.lock().expect("the ACR octets")[0].clone();
        let mut dump = String::new();
        for (offset, chunk) in octets.chunks(16).enumerate() {
            dump.push_str(&format!("{:06x}", offset * 16));
            for byte in chunk {
                dump.push_str(&format!(" {byte:02x}"));
            }
            dump.push('\n');
        }
        std::fs::write(format!("{directory}/{name}.hex"), dump).expect("a writable hex dump");
    }
}
