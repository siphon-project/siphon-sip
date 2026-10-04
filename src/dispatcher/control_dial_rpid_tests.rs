//! The caller's `Remote-Party-ID` on a B-leg whose calling identity siphon
//! reshaped.
//!
//! `Remote-Party-ID` (draft-ietf-sip-privacy) states the calling identity the
//! way `P-Asserted-Identity` does, and the default header policy copies it like
//! any header it has no rule for. siphon's identity steps (a dial's `from`, a
//! target's own `from`, `privacy: restricted`) reshaped `From` and PAI and left
//! it alone, so a B-leg presenting the controller's number still asserted the
//! caller's in RPID, and a withheld call still carried the number it withheld.
//!
//! Driven through the dispatcher's own `dial` entry point, with what siphon sent
//! read back off the UDP egress, including the second attempt of a sequential
//! hunt, which is rebuilt from the stored A-leg INVITE.

use super::lcr_ring_timeout_tests::{summaries, Sent};
use super::test_dispatcher::{test_dispatcher, TestDispatcher};
use super::*;

const CALLER: &str = "192.0.2.10:5060";
const FIRST_TARGET: &str = "198.51.100.7:5060";
const SECOND_TARGET: &str = "198.51.100.8:5060";
const SIP_CALL_ID: &str = "control-dial-rpid@192.0.2.10";
const PRESENTED_FROM: &str = "sip:15550100042@trunk.example.com";

/// A caller INVITE carrying the inbound side's identity in `Remote-Party-ID`.
fn caller_invite() -> SipMessage {
    let raw = format!(
        concat!(
            "INVITE sip:15550100077@siphon.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-dial-rpid\r\n",
            "Max-Forwards: 70\r\n",
            "From: \"Caller\" <sip:15550100011@inbound.example.com>;tag=caller-tag\r\n",
            "To: <sip:15550100077@siphon.example.com>\r\n",
            "Remote-Party-ID: \"Caller\" <sip:15550100011@inbound.example.com>;party=calling;screen=yes;privacy=off\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:15550100011@192.0.2.10:5060>\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        call_id = SIP_CALL_ID,
    );
    parse_sip_message_bytes(raw.as_bytes()).expect("the caller INVITE parses")
}

fn park(dispatcher: &TestDispatcher) -> String {
    let call_id = dispatcher.state.call_actors.create_call(Leg::new_a_leg(
        SIP_CALL_ID.to_string(),
        "caller-tag".to_string(),
        "z9hG4bK-dial-rpid".to_string(),
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
        .set_a_leg_invite(&call_id, Arc::new(Mutex::new(caller_invite())));
    call_id
}

fn wire(dispatcher: &TestDispatcher) -> Vec<Sent> {
    dispatcher
        .udp
        .try_iter()
        .map(|outbound| Sent {
            destination: outbound.destination,
            message: parse_sip_message_bytes(&outbound.data)
                .expect("siphon sent a message that parses"),
        })
        .collect()
}

fn target(address: &str) -> DialTarget {
    DialTarget {
        uri: format!("sip:15550100077@{address}"),
        ..Default::default()
    }
}

fn dial(
    dispatcher: &TestDispatcher,
    targets: Vec<DialTarget>,
    parallel: bool,
    shaping: &DialShaping,
) -> bool {
    b2bua_dial_call_with_state(
        SIP_CALL_ID,
        targets,
        parallel,
        30,
        &[],
        shaping,
        &dispatcher.state,
    )
    .expect("the dial runs")
}

fn rpid(sent: &Sent) -> Option<&str> {
    sent.message
        .headers
        .get("Remote-Party-ID")
        .map(String::as_str)
}

fn advance_from_the_stored_invite(dispatcher: &TestDispatcher, call_id: &str) {
    let invite_arc = dispatcher
        .state
        .call_actors
        .get_call(call_id)
        .and_then(|call| call.a_leg_invite.clone())
        .expect("the parked call stores its A-leg INVITE");
    let stored = invite_arc.lock().expect("the invite lock");
    let advanced = b2bua_advance_route(call_id, &stored, &dispatcher.state);
    assert!(advanced.dialed, "the sequence had another target to try");
}

/// Positive control: a dial that names no identity presents the caller's, and
/// the policy's copy of its RPID stands.
#[tokio::test(flavor = "multi_thread")]
async fn a_dial_naming_no_identity_keeps_the_callers_rpid() {
    let dispatcher = test_dispatcher();
    park(&dispatcher);
    assert!(dial(
        &dispatcher,
        vec![target(FIRST_TARGET)],
        true,
        &DialShaping::default()
    ));
    let sent = wire(&dispatcher);
    assert!(rpid(&sent[0]).is_some_and(|value| value.contains("15550100011")));
}

/// A dial's own identity replaces the caller's everywhere it is stated, on
/// every attempt of a hunt as well as the first.
#[tokio::test(flavor = "multi_thread")]
async fn a_dial_presenting_its_own_identity_drops_the_callers_rpid() {
    for parallel in [true, false] {
        let dispatcher = test_dispatcher();
        let call_id = park(&dispatcher);
        let shaping = DialShaping {
            from: Some(PRESENTED_FROM.to_string()),
            ..Default::default()
        };
        assert!(dial(
            &dispatcher,
            vec![target(FIRST_TARGET), target(SECOND_TARGET)],
            parallel,
            &shaping
        ));
        let mut sent = wire(&dispatcher);
        if !parallel {
            advance_from_the_stored_invite(&dispatcher, &call_id);
            sent.extend(wire(&dispatcher));
        }
        assert_eq!(
            summaries(&sent),
            [
                format!("INVITE to {FIRST_TARGET}"),
                format!("INVITE to {SECOND_TARGET}")
            ],
            "parallel={parallel}"
        );
        for invite in &sent {
            assert_eq!(
                rpid(invite),
                None,
                "parallel={parallel}: the caller's identity survived in RPID"
            );
        }
    }
}

/// A target naming its own `from` drops the caller's RPID on its branch alone,
/// on a fork and on a hunt.
#[tokio::test(flavor = "multi_thread")]
async fn a_targets_own_identity_drops_the_callers_rpid_on_its_branch() {
    for parallel in [true, false] {
        let dispatcher = test_dispatcher();
        let call_id = park(&dispatcher);
        let mut targets = vec![target(FIRST_TARGET), target(SECOND_TARGET)];
        targets[1].from = Some(PRESENTED_FROM.to_string());
        assert!(dial(
            &dispatcher,
            targets,
            parallel,
            &DialShaping::default()
        ));
        let mut sent = wire(&dispatcher);
        if !parallel {
            advance_from_the_stored_invite(&dispatcher, &call_id);
            sent.extend(wire(&dispatcher));
        }
        assert_eq!(sent.len(), 2, "parallel={parallel}");
        assert!(
            rpid(&sent[0]).is_some(),
            "parallel={parallel}: a branch naming nothing keeps the caller's"
        );
        assert_eq!(rpid(&sent[1]), None, "parallel={parallel}");
    }
}

/// A withheld call carries no RPID: a carrier rendering it would show the
/// number the call withholds. PAI keeps the identity for the trusted hop.
#[tokio::test(flavor = "multi_thread")]
async fn a_restricted_dial_carries_no_rpid() {
    for parallel in [true, false] {
        let dispatcher = test_dispatcher();
        park(&dispatcher);
        let shaping = DialShaping {
            privacy: Some(crate::sip::privacy::CallerIdPresentation::Restricted),
            ..Default::default()
        };
        assert!(dial(
            &dispatcher,
            vec![target(FIRST_TARGET)],
            parallel,
            &shaping
        ));
        let sent = wire(&dispatcher);
        assert_eq!(rpid(&sent[0]), None, "parallel={parallel}");
    }
}

/// An RPID the controller names for a branch is its explicit choice and goes
/// out as written.
#[tokio::test(flavor = "multi_thread")]
async fn an_rpid_the_controller_names_goes_out_as_written() {
    const NAMED: &str = "<sip:15550100042@trunk.example.com>;party=calling;screen=yes";
    let dispatcher = test_dispatcher();
    park(&dispatcher);
    let mut named = target(FIRST_TARGET);
    named
        .headers
        .insert("Remote-Party-ID".to_string(), NAMED.to_string());
    let shaping = DialShaping {
        from: Some(PRESENTED_FROM.to_string()),
        ..Default::default()
    };
    assert!(dial(&dispatcher, vec![named], true, &shaping));
    assert_eq!(rpid(&wire(&dispatcher)[0]), Some(NAMED));
}
