//! A sequential connecting `dial` and `reroute_after_progress` on its targets.
//!
//! By default a hunt moves on from a target that rang and then failed or rang
//! out. A target with `reroute_after_progress: false` ends the dial on its own
//! outcome once it has sent a 101-199, so a hunt across several routes to one
//! destination does not ring the same person again. A target that never rang,
//! and a 503 carrying Retry-After, still move it on; a 6xx ends it whatever the
//! target says.
//!
//! Driven through the dispatcher's own `dial` entry point on a test dispatcher,
//! as the branch-event tests are: responses through [`handle_b2bua_response`],
//! ring timeouts through [`check_b2bua_answer_timeouts_at`], the wire read back
//! off the UDP egress and `DialFailed` off the channel event capture.

use super::lcr_ring_timeout_tests::{carrier_response, top_via_branch};
use super::test_dispatcher::{test_dispatcher, TestDispatcher};
use super::*;
use crate::control::channel_event_capture;
use std::time::{Duration, Instant};

const CALLER: &str = "192.0.2.10:5060";
const TARGETS: [&str; 3] = [
    "198.51.100.41:5060",
    "198.51.100.42:5060",
    "198.51.100.43:5060",
];

fn caller_invite(sip_call_id: &str) -> SipMessage {
    let raw = format!(
        concat!(
            "INVITE sip:15550100077@siphon.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-hunt-progress\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:15550100042@example.com>;tag=caller-tag\r\n",
            "To: <sip:15550100077@siphon.example.com>\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:15550100042@192.0.2.10:5060>\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        call_id = sip_call_id,
    );
    parse_sip_message_bytes(raw.as_bytes()).expect("the caller INVITE parses")
}

/// A parked caller hunting the three [`TARGETS`] in order, each target's
/// `reroute_after_progress` set to `flag`.
struct Hunt {
    dispatcher: TestDispatcher,
    call_id: String,
    sip_call_id: String,
}

impl Hunt {
    fn start(sip_call_id: &str, flag: Option<bool>) -> Self {
        let dispatcher = test_dispatcher();
        let call_id = dispatcher.state.call_actors.create_call(Leg::new_a_leg(
            sip_call_id.to_string(),
            "caller-tag".to_string(),
            "z9hG4bK-hunt-progress".to_string(),
            LegTransport {
                remote_addr: CALLER.parse().expect("a literal address"),
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
                local_addr: None,
            },
        ));
        dispatcher
            .state
            .call_actors
            .set_a_leg_invite(&call_id, Arc::new(Mutex::new(caller_invite(sip_call_id))));
        channel_event_capture::watch(sip_call_id);
        let targets = TARGETS
            .iter()
            .map(|address| DialTarget {
                uri: format!("sip:15550100077@{address}"),
                reroute_after_progress: flag,
                ..Default::default()
            })
            .collect();
        let dialled = b2bua_dial_call_with_state(
            sip_call_id,
            targets,
            false,
            30,
            &[],
            &DialShaping::default(),
            &dispatcher.state,
        )
        .expect("the dial runs");
        assert!(dialled, "the dial found its call");
        Self {
            dispatcher,
            call_id,
            sip_call_id: sip_call_id.to_string(),
        }
    }

    /// The INVITEs siphon sent since the last look, by destination.
    fn invites(&self) -> Vec<(String, SipMessage)> {
        let mut invites = Vec::new();
        while let Ok(outbound) = self.dispatcher.udp.try_recv() {
            let message =
                parse_sip_message_bytes(&outbound.data).expect("siphon sent a message that parses");
            let is_invite = matches!(&message.start_line, StartLine::Request(_))
                && message
                    .headers
                    .cseq()
                    .is_some_and(|cseq| cseq.ends_with("INVITE"));
            if is_invite {
                invites.push((outbound.destination.to_string(), message));
            }
        }
        invites
    }

    /// The one INVITE sent since the last look, which went to `address`.
    fn rang(&self, address: &str) -> SipMessage {
        let invites = self.invites();
        assert_eq!(
            invites
                .iter()
                .map(|(destination, _)| destination.as_str())
                .collect::<Vec<_>>(),
            [address],
            "the hunt rang exactly {address}"
        );
        invites
            .into_iter()
            .next()
            .map(|(_, invite)| invite)
            .expect("one INVITE")
    }

    fn send(&self, address: &str, invite: &SipMessage, response: &mut SipMessage) {
        let status_code = match &response.start_line {
            StartLine::Response(status_line) => status_line.status_code,
            StartLine::Request(_) => panic!("a response"),
        };
        let handled = handle_b2bua_response(
            &self.call_id,
            &top_via_branch(invite),
            response,
            status_code,
            address.parse().expect("a literal address"),
            &self.dispatcher.state,
        );
        assert!(handled, "the call was gone when the {status_code} arrived");
    }

    fn responds(&self, address: &str, invite: &SipMessage, status_code: u16, reason: &str) {
        self.send(
            address,
            invite,
            &mut carrier_response(invite, status_code, reason),
        );
    }

    fn rings_out(&self) {
        check_b2bua_answer_timeouts_at(
            &self.dispatcher.state,
            Instant::now() + Duration::from_secs(31),
        );
    }

    /// The `DialFailed` published since the last look, if any.
    fn dial_failed(&self) -> Option<serde_json::Value> {
        let events = channel_event_capture::take(&self.sip_call_id);
        let failed: Vec<_> = events
            .into_iter()
            .filter(|(event, _)| event == "DialFailed")
            .map(|(_, payload)| payload)
            .collect();
        assert!(failed.len() <= 1, "one DialFailed at most: {failed:?}");
        failed.into_iter().next()
    }
}

/// With the flag off, a target that rang and then failed ends the dial on its
/// own code, whatever the code: the other two targets are never sent.
#[tokio::test(flavor = "multi_thread")]
async fn a_target_that_rang_ends_the_dial_on_its_failure() {
    for (index, (code, reason)) in [
        (486, "Busy Here"),
        (480, "Temporarily Unavailable"),
        (408, "Request Timeout"),
        (503, "Service Unavailable"),
    ]
    .into_iter()
    .enumerate()
    {
        let hunt = Hunt::start(&format!("hunt-stop-{index}@192.0.2.10"), Some(false));
        let first = hunt.rang(TARGETS[0]);
        hunt.responds(TARGETS[0], &first, 180, "Ringing");
        hunt.responds(TARGETS[0], &first, code, reason);
        assert!(
            hunt.invites().is_empty(),
            "{code}: no later target is tried"
        );
        let failed = hunt
            .dial_failed()
            .unwrap_or_else(|| panic!("{code}: the dial failed"));
        assert_eq!(failed["code"], code);
        assert_eq!(failed["timed_out"], false);
        assert_eq!(failed["branches"].as_array().map(Vec::len), Some(1));
    }
}

/// With the flag off, a target that rang and rings out ends the dial 408.
#[tokio::test(flavor = "multi_thread")]
async fn a_target_that_rang_and_rings_out_ends_the_dial() {
    let hunt = Hunt::start("hunt-stop-timeout@192.0.2.10", Some(false));
    let first = hunt.rang(TARGETS[0]);
    hunt.responds(TARGETS[0], &first, 183, "Session Progress");
    hunt.rings_out();
    assert!(hunt.invites().is_empty(), "no later target is tried");
    let failed = hunt.dial_failed().expect("the dial failed");
    assert_eq!(failed["code"], 408);
    assert_eq!(failed["timed_out"], true);
}

/// Without the flag a target that rang moves the hunt on, as it always has:
/// on a reroute cause and on its ring timeout.
#[tokio::test(flavor = "multi_thread")]
async fn by_default_a_target_that_rang_moves_the_hunt_on() {
    let hunt = Hunt::start("hunt-default@192.0.2.10", None);
    let first = hunt.rang(TARGETS[0]);
    hunt.responds(TARGETS[0], &first, 180, "Ringing");
    hunt.responds(TARGETS[0], &first, 408, "Request Timeout");
    let second = hunt.rang(TARGETS[1]);
    hunt.responds(TARGETS[1], &second, 180, "Ringing");
    hunt.rings_out();
    hunt.rang(TARGETS[2]);
    assert!(hunt.dial_failed().is_none(), "the dial is still ringing");
}

/// With the flag off, a target that never sent a 101-199 still moves the hunt
/// on: a 100 is hop by hop, a 503 or a silent ring-out reached nobody.
#[tokio::test(flavor = "multi_thread")]
async fn a_target_that_never_rang_moves_the_hunt_on_with_the_flag_off() {
    let hunt = Hunt::start("hunt-no-progress@192.0.2.10", Some(false));
    let first = hunt.rang(TARGETS[0]);
    hunt.responds(TARGETS[0], &first, 100, "Trying");
    hunt.responds(TARGETS[0], &first, 503, "Service Unavailable");
    let second = hunt.rang(TARGETS[1]);
    hunt.responds(TARGETS[1], &second, 100, "Trying");
    hunt.rings_out();
    hunt.rang(TARGETS[2]);
    assert!(hunt.dial_failed().is_none(), "the dial is still ringing");
}

/// With the flag off, a 503 carrying Retry-After moves the hunt on even after
/// progress: the element is unavailable, the callee did not answer.
#[tokio::test(flavor = "multi_thread")]
async fn a_503_with_retry_after_moves_the_hunt_on_after_progress() {
    let hunt = Hunt::start("hunt-retry-after@192.0.2.10", Some(false));
    let first = hunt.rang(TARGETS[0]);
    hunt.responds(TARGETS[0], &first, 180, "Ringing");
    let mut unavailable = carrier_response(&first, 503, "Service Unavailable");
    unavailable.headers.set("Retry-After", "30".to_string());
    hunt.send(TARGETS[0], &first, &mut unavailable);
    hunt.rang(TARGETS[1]);
    assert!(hunt.dial_failed().is_none(), "the dial is still ringing");
}

/// A 6xx ends a hunt whatever its target says, progress or not.
#[tokio::test(flavor = "multi_thread")]
async fn a_6xx_ends_the_hunt() {
    for (index, flag) in [None, Some(true), Some(false)].into_iter().enumerate() {
        let hunt = Hunt::start(&format!("hunt-decline-{index}@192.0.2.10"), flag);
        let first = hunt.rang(TARGETS[0]);
        hunt.responds(TARGETS[0], &first, 603, "Decline");
        assert!(hunt.invites().is_empty(), "{flag:?}: no later target");
        let failed = hunt.dial_failed().expect("the dial failed");
        assert_eq!(failed["code"], 603);
    }
}
