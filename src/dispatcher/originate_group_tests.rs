//! Originate groups: every phone registered at an AoR rung as a call siphon
//! places itself, the first to answer kept.
//!
//! Each test registers its own phones at an AoR of its own in the process-wide
//! test registrar, drives the group through the real originate send and
//! response paths, and reads what the phones were sent off the egress channels.

use std::sync::{Arc, Mutex};

use super::originate_test_harness::{
    anchored_dispatcher, anchored_params, drain, phone_offer, phone_response, phone_sends,
    requests_to, socket, with_stream_egress, Sent,
};
use super::test_dispatcher::TestDispatcher;
use super::*;
use crate::b2bua::actor::{DialBranch, DialBranchCause};
use crate::rtpengine::test_native_engine::{NativeTestEngine, NATIVE_ENGINE_ANSWER};

/// Everything a group reported, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Reported {
    Created(DialBranch),
    Progress(DialBranch, OriginateLegProgress),
    Ended(DialBranch),
    Answered(OriginateGroupWinner),
    Failed(OriginateGroupFailure),
}

/// A sink that records what the group reports.
#[derive(Default)]
struct Recorder {
    reported: Mutex<Vec<Reported>>,
}

impl Recorder {
    fn push(&self, reported: Reported) {
        self.reported.lock().expect("the report log").push(reported);
    }

    fn take(&self) -> Vec<Reported> {
        std::mem::take(&mut *self.reported.lock().expect("the report log"))
    }
}

impl OriginateGroupSink for Recorder {
    fn branch_created(&self, _group_id: &str, branch: &DialBranch) {
        self.push(Reported::Created(branch.clone()));
    }

    fn branch_progress(
        &self,
        _group_id: &str,
        branch: &DialBranch,
        progress: &OriginateLegProgress,
    ) {
        self.push(Reported::Progress(branch.clone(), progress.clone()));
    }

    fn branch_ended(&self, _group_id: &str, branch: &DialBranch) {
        self.push(Reported::Ended(branch.clone()));
    }

    fn answered(&self, winner: &OriginateGroupWinner) {
        self.push(Reported::Answered(winner.clone()));
    }

    fn failed(&self, failure: &OriginateGroupFailure) {
        self.push(Reported::Failed(failure.clone()));
    }
}

/// Register `contact` at `aor` over plain UDP, reached by its URI.
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

/// Register `contact` at `aor` over a flow: from `source`, on the listener
/// `local`, over connection `connection_id`, with `path` as its Path.
fn register_over_flow(
    aor: &str,
    contact: &str,
    transport: Transport,
    source: &str,
    local: &str,
    connection_id: u64,
    path: Vec<String>,
) {
    crate::script::api::test_registrar()
        .save_full(
            aor,
            parse_uri_standalone(contact).expect("a contact URI"),
            3600,
            1.0,
            format!("register-{contact}"),
            1,
            Some(socket(source)),
            Some(transport),
            None,
            None,
            path,
            crate::registrar::FlowCapture {
                flow_token: None,
                inbound_local_addr: Some(socket(local)),
                inbound_connection_id: Some(connection_id),
                client_transport: None,
            },
            Vec::new(),
        )
        .expect("the binding saves");
}

/// A group ringing `aor` with `strategy`, created and started on `state`.
fn ring(
    state: &DispatcherState,
    aor: &str,
    strategy: OriginateGroupStrategy,
    timeout_secs: u32,
    total_timeout_secs: u32,
) -> (String, Arc<Recorder>) {
    let targets = dial_targets_for_aor(aor).expect("the AoR has contacts");
    let mut params = anchored_params(aor);
    params.timeout_secs = timeout_secs;
    let recorder = Arc::new(Recorder::default());
    let group_id = create_originate_group(
        state,
        OriginateGroupSpec {
            params,
            targets,
            strategy,
            total_timeout_secs,
        },
        Arc::clone(&recorder) as Arc<dyn OriginateGroupSink>,
    )
    .expect("the group is created");
    start_originate_group(state, &group_id).expect("the group starts");
    (group_id, recorder)
}

/// The one INVITE sent to `phone` among `sent`.
fn invite_to(sent: &[Sent], phone: &str) -> SipMessage {
    let mut invites = requests_to(sent, socket(phone), Method::Invite);
    assert_eq!(invites.len(), 1, "exactly one INVITE to {phone}");
    invites.remove(0).message
}

fn request_uri(message: &SipMessage) -> String {
    match &message.start_line {
        StartLine::Request(line) => line.request_uri.to_string(),
        StartLine::Response(_) => panic!("a request"),
    }
}

fn via_branch(message: &SipMessage) -> String {
    message
        .headers
        .get("Via")
        .and_then(|via| via.split(";branch=").nth(1))
        .map(|rest| rest.split([';', ',', ' ']).next().unwrap_or("").to_string())
        .expect("a Via branch")
}

fn body_text(message: &SipMessage) -> &str {
    std::str::from_utf8(&message.body).expect("a text body")
}

fn assert_drained(dispatcher: &TestDispatcher) {
    assert_eq!(dispatcher.state.originate_groups.group_count(), 0);
    assert_eq!(dispatcher.state.originate_groups.leg_count(), 0);
}

/// Parallel: every contact is rung, the first 2xx wins and is ACKed with the
/// engine's answer, the other leg is CANCELled, and a late answer from it is
/// released with ACK and BYE.
#[tokio::test(flavor = "multi_thread")]
async fn the_first_phone_to_answer_wins_and_the_other_is_cancelled() {
    const DESK: &str = "198.51.100.31:5060";
    const MOBILE: &str = "198.51.100.32:5060";
    let aor = "sip:3001@siphon.example.com";
    register(aor, &format!("sip:3001@{DESK}"), 1.0);
    register(aor, &format!("sip:3001@{MOBILE}"), 0.5);
    let engine = NativeTestEngine::start().await;
    let dispatcher = anchored_dispatcher(&engine);

    let (group_id, recorder) = ring(
        &dispatcher.state,
        aor,
        OriginateGroupStrategy::Parallel,
        30,
        30,
    );
    let sent = drain(&dispatcher.udp);
    let desk_invite = invite_to(&sent, DESK);
    let mobile_invite = invite_to(&sent, MOBILE);
    // Each leg is addressed to its contact, and names the AoR as the callee.
    assert_eq!(request_uri(&desk_invite), format!("sip:3001@{DESK}"));
    assert_eq!(request_uri(&mobile_invite), format!("sip:3001@{MOBILE}"));
    for invite in [&desk_invite, &mobile_invite] {
        assert_eq!(
            invite.headers.to().map(String::as_str),
            Some(format!("<{aor}>").as_str())
        );
        assert!(invite.body.is_empty(), "an anchored leg goes out offerless");
    }
    assert_ne!(
        desk_invite.headers.call_id(),
        mobile_invite.headers.call_id(),
        "each leg is its own dialog"
    );
    let created: Vec<_> = recorder
        .take()
        .into_iter()
        .map(|reported| match reported {
            Reported::Created(branch) => branch,
            other => panic!("expected only DialBranch reports, got {other:?}"),
        })
        .collect();
    assert_eq!(created.len(), 2);
    assert!(created
        .iter()
        .all(|branch| branch.aor.as_deref() == Some(aor)));
    assert!(dispatcher.state.originate_groups.contains(&group_id));

    // The desk rings first: reported as that leg's progress, and nothing wins.
    let ringing = phone_response(
        &desk_invite,
        180,
        "Ringing",
        "desk-tag",
        &format!("sip:3001@{DESK}"),
        None,
    );
    phone_sends(&dispatcher.state, socket(DESK), &ringing);
    match recorder.take().as_slice() {
        [Reported::Progress(branch, progress)] => {
            assert_eq!(branch.target, format!("sip:3001@{DESK}"));
            assert_eq!(progress.code, 180);
            assert!(!progress.early_media);
        }
        other => panic!("expected the desk's progress, got {other:?}"),
    }

    // The mobile answers first.
    let mobile_answer = phone_response(
        &mobile_invite,
        200,
        "OK",
        "mobile-tag",
        &format!("sip:3001@{MOBILE}"),
        Some(&phone_offer("198.51.100.32")),
    );
    phone_sends(&dispatcher.state, socket(MOBILE), &mobile_answer);
    let sent = drain(&dispatcher.udp);
    let acks = requests_to(&sent, socket(MOBILE), Method::Ack);
    assert_eq!(acks.len(), 1, "the winner is ACKed");
    assert_eq!(body_text(&acks[0].message), NATIVE_ENGINE_ANSWER);
    let cancels = requests_to(&sent, socket(DESK), Method::Cancel);
    assert_eq!(cancels.len(), 1, "the desk is CANCELled");
    assert_eq!(via_branch(&cancels[0].message), via_branch(&desk_invite));
    // Positive control for the CANCEL: the winner is not cancelled.
    assert!(requests_to(&sent, socket(MOBILE), Method::Cancel).is_empty());
    let reported = recorder.take();
    match reported.as_slice() {
        [Reported::Ended(loser), Reported::Answered(winner)] => {
            assert_eq!(loser.target, format!("sip:3001@{DESK}"));
            let outcome = loser.outcome.clone().expect("the loser's outcome");
            assert_eq!(
                (outcome.code, outcome.cause),
                (487, DialBranchCause::Cancelled)
            );
            assert_eq!(winner.branch.target, format!("sip:3001@{MOBILE}"));
            assert_eq!(
                Some(winner.sip_call_id.as_str()),
                mobile_invite.headers.call_id().map(String::as_str)
            );
            assert_eq!(winner.group_id, group_id);
            let answered = dispatcher
                .state
                .call_actors
                .get_call(&winner.internal_call_id)
                .map(|call| matches!(call.state, CallState::Answered));
            assert_eq!(answered, Some(true), "the winner is an answered call");
        }
        other => panic!("expected the loser's end then the winner, got {other:?}"),
    }
    assert_drained(&dispatcher);
    assert!(
        engine.commands("answer_local").len() == 1,
        "only the winner is anchored"
    );

    // The desk answers anyway (RFC 3261 §9.1 glare): its dialog is released.
    let desk_answer = phone_response(
        &desk_invite,
        200,
        "OK",
        "desk-tag",
        &format!("sip:3001@{DESK}"),
        Some(&phone_offer("198.51.100.31")),
    );
    phone_sends(&dispatcher.state, socket(DESK), &desk_answer);
    let sent = drain(&dispatcher.udp);
    let desk_acks = requests_to(&sent, socket(DESK), Method::Ack);
    assert_eq!(desk_acks.len(), 1, "the late 2xx is ACKed");
    assert!(
        body_text(&desk_acks[0].message).contains("m=audio 0 "),
        "its offer is answered with every stream rejected: {}",
        body_text(&desk_acks[0].message)
    );
    assert_eq!(
        requests_to(&sent, socket(DESK), Method::Bye).len(),
        1,
        "and BYEd"
    );
    assert!(
        requests_to(&sent, socket(MOBILE), Method::Bye).is_empty(),
        "the winner is left alone"
    );
    assert!(recorder.take().is_empty(), "the group is over");
    assert_eq!(engine.commands("answer_local").len(), 1);
}

/// Sequential: one phone at a time, moving on when one declines and when one
/// rings out its own timeout.
#[tokio::test(flavor = "multi_thread")]
async fn a_sequential_group_moves_on_after_a_decline_and_a_ring_timeout() {
    const FIRST: &str = "198.51.100.41:5060";
    const SECOND: &str = "198.51.100.42:5060";
    const THIRD: &str = "198.51.100.43:5060";
    let aor = "sip:3002@siphon.example.com";
    register(aor, &format!("sip:3002@{FIRST}"), 1.0);
    register(aor, &format!("sip:3002@{SECOND}"), 0.8);
    register(aor, &format!("sip:3002@{THIRD}"), 0.5);
    let engine = NativeTestEngine::start().await;
    let dispatcher = anchored_dispatcher(&engine);

    let (_group_id, recorder) = ring(
        &dispatcher.state,
        aor,
        OriginateGroupStrategy::Sequential,
        5,
        60,
    );
    let sent = drain(&dispatcher.udp);
    let first_invite = invite_to(&sent, FIRST);
    // Positive control: only the first phone rings.
    assert!(requests_to(&sent, socket(SECOND), Method::Invite).is_empty());
    assert!(requests_to(&sent, socket(THIRD), Method::Invite).is_empty());
    assert!(matches!(recorder.take().as_slice(), [Reported::Created(_)]));

    // The first phone is busy: ACKed, reported, and the second rings.
    let busy = phone_response(
        &first_invite,
        486,
        "Busy Here",
        "first-tag",
        &format!("sip:3002@{FIRST}"),
        None,
    );
    phone_sends(&dispatcher.state, socket(FIRST), &busy);
    let sent = drain(&dispatcher.udp);
    assert_eq!(requests_to(&sent, socket(FIRST), Method::Ack).len(), 1);
    let second_invite = invite_to(&sent, SECOND);
    assert!(requests_to(&sent, socket(THIRD), Method::Invite).is_empty());
    match recorder.take().as_slice() {
        [Reported::Ended(first), Reported::Created(second)] => {
            let outcome = first.outcome.clone().expect("an outcome");
            assert_eq!(
                (outcome.code, outcome.cause),
                (486, DialBranchCause::Rejected)
            );
            assert_eq!(second.target, format!("sip:3002@{SECOND}"));
        }
        other => panic!("expected the first leg's end and the second's start, got {other:?}"),
    }

    // The second rings out its own 5 s: CANCELled, and the third rings.
    check_b2bua_answer_timeouts_at(
        &dispatcher.state,
        std::time::Instant::now() + std::time::Duration::from_secs(6),
    );
    let sent = drain(&dispatcher.udp);
    let cancels = requests_to(&sent, socket(SECOND), Method::Cancel);
    assert_eq!(cancels.len(), 1);
    assert_eq!(via_branch(&cancels[0].message), via_branch(&second_invite));
    let third_invite = invite_to(&sent, THIRD);
    match recorder.take().as_slice() {
        [Reported::Ended(second), Reported::Created(third)] => {
            let outcome = second.outcome.clone().expect("an outcome");
            assert_eq!(
                (outcome.code, outcome.cause),
                (408, DialBranchCause::Timeout)
            );
            assert_eq!(third.target, format!("sip:3002@{THIRD}"));
        }
        other => panic!("expected the second leg's timeout and the third's start, got {other:?}"),
    }

    // The third answers and wins.
    let answer = phone_response(
        &third_invite,
        200,
        "OK",
        "third-tag",
        &format!("sip:3002@{THIRD}"),
        Some(&phone_offer("198.51.100.43")),
    );
    phone_sends(&dispatcher.state, socket(THIRD), &answer);
    let acks = requests_to(&drain(&dispatcher.udp), socket(THIRD), Method::Ack);
    assert_eq!(acks.len(), 1);
    assert_eq!(body_text(&acks[0].message), NATIVE_ENGINE_ANSWER);
    assert!(matches!(
        recorder.take().as_slice(),
        [Reported::Answered(_)]
    ));
    assert_drained(&dispatcher);
}

/// Every phone declines: the group fails with the best of their statuses
/// (RFC 3261 §16.7 step 6), and every entry it held is gone.
#[tokio::test(flavor = "multi_thread")]
async fn a_group_whose_every_phone_declines_fails_with_the_best_status() {
    const DESK: &str = "198.51.100.51:5060";
    const MOBILE: &str = "198.51.100.52:5060";
    let aor = "sip:3003@siphon.example.com";
    register(aor, &format!("sip:3003@{DESK}"), 1.0);
    register(aor, &format!("sip:3003@{MOBILE}"), 0.5);
    let engine = NativeTestEngine::start().await;
    let dispatcher = anchored_dispatcher(&engine);
    let calls_before = dispatcher.state.call_actors.count();

    let (group_id, recorder) = ring(
        &dispatcher.state,
        aor,
        OriginateGroupStrategy::Parallel,
        30,
        30,
    );
    let sent = drain(&dispatcher.udp);
    let desk_invite = invite_to(&sent, DESK);
    let mobile_invite = invite_to(&sent, MOBILE);
    recorder.take();

    phone_sends(
        &dispatcher.state,
        socket(DESK),
        &phone_response(
            &desk_invite,
            486,
            "Busy Here",
            "desk-tag",
            &format!("sip:3003@{DESK}"),
            None,
        ),
    );
    // Positive control: one leg left ringing, the group has not failed.
    assert!(dispatcher.state.originate_groups.contains(&group_id));
    assert!(matches!(recorder.take().as_slice(), [Reported::Ended(_)]));

    phone_sends(
        &dispatcher.state,
        socket(MOBILE),
        &phone_response(
            &mobile_invite,
            603,
            "Decline",
            "mobile-tag",
            &format!("sip:3003@{MOBILE}"),
            None,
        ),
    );
    match recorder.take().as_slice() {
        [Reported::Ended(_), Reported::Failed(failure)] => {
            assert_eq!(failure.group_id, group_id);
            assert_eq!(failure.reason, "rejected");
            assert_eq!(failure.code, 603);
            assert_eq!(failure.response, "Decline");
            assert_eq!(failure.branches.len(), 2);
        }
        other => panic!("expected the last leg's end then the failure, got {other:?}"),
    }
    let sent = drain(&dispatcher.udp);
    assert_eq!(requests_to(&sent, socket(DESK), Method::Ack).len(), 1);
    assert_eq!(requests_to(&sent, socket(MOBILE), Method::Ack).len(), 1);
    assert!(
        sent.iter().all(|frame| !frame.is(Method::Invite)),
        "nothing else is dialled"
    );
    assert_drained(&dispatcher);
    assert_eq!(dispatcher.state.call_actors.count(), calls_before);
    assert!(engine.commands("answer_local").is_empty());
}

/// The controller hangs up while the phones ring: every leg is CANCELled and
/// the group reports the cancel as its end.
#[tokio::test(flavor = "multi_thread")]
async fn cancelling_a_ringing_group_cancels_every_leg() {
    const DESK: &str = "198.51.100.61:5060";
    const MOBILE: &str = "198.51.100.62:5060";
    let aor = "sip:3004@siphon.example.com";
    register(aor, &format!("sip:3004@{DESK}"), 1.0);
    register(aor, &format!("sip:3004@{MOBILE}"), 0.5);
    let engine = NativeTestEngine::start().await;
    let dispatcher = anchored_dispatcher(&engine);

    let (group_id, recorder) = ring(
        &dispatcher.state,
        aor,
        OriginateGroupStrategy::Parallel,
        30,
        30,
    );
    let sent = drain(&dispatcher.udp);
    let desk_invite = invite_to(&sent, DESK);
    let mobile_invite = invite_to(&sent, MOBILE);
    recorder.take();

    // `drop` is refused while the phones ring: there is no response to
    // withhold, and the INVITEs would be left standing. Nothing is sent.
    assert_eq!(
        b2bua_drop_call_in(&dispatcher.state, &group_id, None, None),
        DropOutcome::Ringing
    );
    assert!(drain(&dispatcher.udp).is_empty());
    assert!(dispatcher.state.originate_groups.contains(&group_id));

    // The path a controller's hangup of the channel takes.
    assert!(cancel_originated_call(
        &dispatcher.state,
        &group_id,
        Some("caller gave up")
    ));
    let sent = drain(&dispatcher.udp);
    for (phone, invite) in [(DESK, &desk_invite), (MOBILE, &mobile_invite)] {
        let cancels = requests_to(&sent, socket(phone), Method::Cancel);
        assert_eq!(cancels.len(), 1, "{phone} is CANCELled");
        assert_eq!(via_branch(&cancels[0].message), via_branch(invite));
    }
    let reported = recorder.take();
    assert_eq!(reported.len(), 3, "{reported:?}");
    assert!(reported[..2].iter().all(|reported| matches!(
        reported,
        Reported::Ended(branch) if branch.outcome.as_ref().map(|outcome| outcome.cause) == Some(DialBranchCause::Cancelled)
    )));
    match &reported[2] {
        Reported::Failed(failure) => {
            assert_eq!(failure.reason, "caller gave up");
            assert_eq!(
                (failure.code, failure.response.as_str()),
                (487, "Request Terminated")
            );
        }
        other => panic!("expected the failure, got {other:?}"),
    }
    assert_drained(&dispatcher);
    // Nothing is left to cancel a second time, or to drop.
    assert_eq!(
        b2bua_drop_call_in(&dispatcher.state, &group_id, None, None),
        DropOutcome::Gone
    );
    assert!(!cancel_originated_call(&dispatcher.state, &group_id, None));

    // The phones answer the CANCELs with 487, which are ACKed (RFC 3261
    // §17.1.1.3) and move nothing.
    phone_sends(
        &dispatcher.state,
        socket(DESK),
        &phone_response(
            &desk_invite,
            487,
            "Request Terminated",
            "desk-tag",
            &format!("sip:3004@{DESK}"),
            None,
        ),
    );
    assert_eq!(
        requests_to(&drain(&dispatcher.udp), socket(DESK), Method::Ack).len(),
        1
    );
    assert!(recorder.take().is_empty());
}

/// The group's own deadline bounds the hunt however long each leg may ring.
#[tokio::test(flavor = "multi_thread")]
async fn a_group_that_outlives_its_deadline_is_cancelled() {
    const DESK: &str = "198.51.100.71:5060";
    let aor = "sip:3005@siphon.example.com";
    register(aor, &format!("sip:3005@{DESK}"), 1.0);
    let engine = NativeTestEngine::start().await;
    let dispatcher = anchored_dispatcher(&engine);

    let (_group_id, recorder) = ring(
        &dispatcher.state,
        aor,
        OriginateGroupStrategy::Sequential,
        60,
        3,
    );
    let desk_invite = invite_to(&drain(&dispatcher.udp), DESK);
    recorder.take();

    // Positive control: before the deadline nothing moves.
    check_b2bua_answer_timeouts_at(
        &dispatcher.state,
        std::time::Instant::now() + std::time::Duration::from_secs(1),
    );
    assert!(drain(&dispatcher.udp).is_empty());
    assert!(recorder.take().is_empty());

    check_b2bua_answer_timeouts_at(
        &dispatcher.state,
        std::time::Instant::now() + std::time::Duration::from_secs(4),
    );
    let cancels = requests_to(&drain(&dispatcher.udp), socket(DESK), Method::Cancel);
    assert_eq!(cancels.len(), 1);
    assert_eq!(via_branch(&cancels[0].message), via_branch(&desk_invite));
    match recorder.take().as_slice() {
        [Reported::Ended(_), Reported::Failed(failure)] => {
            assert_eq!(failure.reason, "ring timeout");
            assert_eq!(failure.code, 408);
        }
        other => panic!("expected the leg's end then the failure, got {other:?}"),
    }
    assert_drained(&dispatcher);
}

/// A phone registered over TCP behind NAT is rung on the connection it
/// registered over, from the listener it registered on — never at its Contact.
#[tokio::test(flavor = "multi_thread")]
async fn a_phone_registered_over_a_flow_is_rung_on_that_flow() {
    let aor = "sip:3006@siphon.example.com";
    register_over_flow(
        aor,
        "sip:3006@phone.invalid;transport=tcp",
        Transport::Tcp,
        "203.0.113.80:41000",
        "192.0.2.1:5060",
        4242,
        Vec::new(),
    );
    let engine = NativeTestEngine::start().await;
    let (dispatcher, stream) = with_stream_egress(anchored_dispatcher(&engine));

    let (_group_id, recorder) = ring(
        &dispatcher.state,
        aor,
        OriginateGroupStrategy::Parallel,
        30,
        30,
    );
    let sent = drain(&stream);
    let invites: Vec<_> = sent
        .iter()
        .filter(|frame| frame.is(Method::Invite))
        .collect();
    assert_eq!(invites.len(), 1, "one INVITE, on the stream egress");
    let invite = invites[0];
    assert_eq!(invite.destination, socket("203.0.113.80:41000"));
    assert_eq!(invite.transport, Transport::Tcp);
    assert_eq!(
        invite.connection_id,
        ConnectionId(4242),
        "on the phone's own connection"
    );
    assert_eq!(invite.source, Some(socket("192.0.2.1:5060")));
    assert_eq!(
        request_uri(&invite.message),
        "sip:3006@phone.invalid;transport=tcp"
    );
    let via = invite.message.headers.get("Via").expect("a Via");
    assert!(via.starts_with("SIP/2.0/TCP "), "{via}");
    assert!(!via.contains("0.0.0.0"), "{via}");
    assert!(
        drain(&dispatcher.udp).is_empty(),
        "nothing goes out over UDP"
    );
    assert!(matches!(recorder.take().as_slice(), [Reported::Created(_)]));

    // The phone answers, and its ACK takes the same way: over the phone's live
    // connection, which the TCP listener registered when the phone connected.
    dispatcher.state.stream_connections.register(
        socket("203.0.113.80:41000"),
        Transport::Tcp,
        ConnectionId(4242),
    );
    let answer = phone_response(
        &invite.message,
        200,
        "OK",
        "phone-tag",
        "sip:3006@phone.invalid;transport=tcp",
        Some(&phone_offer("203.0.113.80")),
    );
    phone_sends(&dispatcher.state, socket("203.0.113.80:41000"), &answer);
    let acks: Vec<_> = drain(&stream)
        .into_iter()
        .filter(|frame| frame.is(Method::Ack))
        .collect();
    assert_eq!(acks.len(), 1, "the ACK goes over the phone's connection");
    assert_eq!(acks[0].destination, socket("203.0.113.80:41000"));
    assert_eq!(acks[0].connection_id, ConnectionId(4242));
    assert_eq!(body_text(&acks[0].message), NATIVE_ENGINE_ANSWER);
    assert!(
        drain(&dispatcher.udp).is_empty(),
        "nothing goes out over UDP"
    );
    assert!(matches!(
        recorder.take().as_slice(),
        [Reported::Answered(_)]
    ));
    assert_drained(&dispatcher);
}

/// A flow on a wildcard listener never advertises `0.0.0.0`: a Via that names
/// it turns the dialog's own requests into 482 Loop Detected.
#[tokio::test(flavor = "multi_thread")]
async fn a_flow_on_a_wildcard_listener_advertises_a_real_address() {
    let aor = "sip:3007@siphon.example.com";
    register_over_flow(
        aor,
        "sip:3007@phone.invalid",
        Transport::Udp,
        "203.0.113.81:41001",
        "0.0.0.0:5060",
        7,
        Vec::new(),
    );
    let engine = NativeTestEngine::start().await;
    let dispatcher = anchored_dispatcher(&engine);
    let _ = ring(
        &dispatcher.state,
        aor,
        OriginateGroupStrategy::Parallel,
        30,
        30,
    );
    let invite = invite_to(&drain(&dispatcher.udp), "203.0.113.81:41001");
    let via = invite.headers.get("Via").expect("a Via");
    let contact = invite.headers.get("Contact").expect("a Contact");
    assert!(!via.contains("0.0.0.0"), "{via}");
    assert!(!contact.contains("0.0.0.0"), "{contact}");
    // Positive control: it names the dispatcher's own address.
    assert!(via.contains("192.0.2.1:5060"), "{via}");
}

/// A binding registered through an edge proxy is rung through it: its Path is
/// the INVITE's route set and its next hop, and outranks the flow.
#[tokio::test(flavor = "multi_thread")]
async fn a_phone_registered_through_an_edge_proxy_is_rung_through_its_path() {
    const EDGE: &str = "198.51.100.90:5070";
    let aor = "sip:3008@siphon.example.com";
    let path = format!("<sip:edge-token@{EDGE};lr>");
    register_over_flow(
        aor,
        "sip:3008@phone.invalid",
        Transport::Udp,
        "203.0.113.82:41002",
        "192.0.2.1:5060",
        8,
        vec![path.clone()],
    );
    let engine = NativeTestEngine::start().await;
    let dispatcher = anchored_dispatcher(&engine);
    let (group_id, _recorder) = ring(
        &dispatcher.state,
        aor,
        OriginateGroupStrategy::Parallel,
        30,
        30,
    );
    let sent = drain(&dispatcher.udp);
    let invite = invite_to(&sent, EDGE);
    assert_eq!(
        invite.headers.get_all("Route").cloned().unwrap_or_default(),
        vec![path.clone()]
    );
    assert_eq!(request_uri(&invite), "sip:3008@phone.invalid");
    assert!(
        requests_to(&sent, socket("203.0.113.82:41002"), Method::Invite).is_empty(),
        "the Path outranks the flow"
    );

    // Its CANCEL carries the same route set to the same hop (RFC 3261 §9.1).
    assert!(cancel_originated_call(&dispatcher.state, &group_id, None));
    let cancels = requests_to(&drain(&dispatcher.udp), socket(EDGE), Method::Cancel);
    assert_eq!(cancels.len(), 1);
    assert_eq!(
        cancels[0]
            .message
            .headers
            .get_all("Route")
            .cloned()
            .unwrap_or_default(),
        vec![path]
    );
}

/// A decline through the edge is ACKed with the INVITE's route set (RFC 3261
/// §17.1.1.3).
#[tokio::test(flavor = "multi_thread")]
async fn a_decline_through_the_edge_is_acked_with_the_route_set() {
    const EDGE: &str = "198.51.100.91:5070";
    let aor = "sip:3009@siphon.example.com";
    let path = format!("<sip:edge-token@{EDGE};lr>");
    register_over_flow(
        aor,
        "sip:3009@phone.invalid",
        Transport::Udp,
        "203.0.113.83:41003",
        "192.0.2.1:5060",
        9,
        vec![path.clone()],
    );
    let engine = NativeTestEngine::start().await;
    let dispatcher = anchored_dispatcher(&engine);
    let _ = ring(
        &dispatcher.state,
        aor,
        OriginateGroupStrategy::Parallel,
        30,
        30,
    );
    let invite = invite_to(&drain(&dispatcher.udp), EDGE);
    phone_sends(
        &dispatcher.state,
        socket(EDGE),
        &phone_response(
            &invite,
            486,
            "Busy Here",
            "phone-tag",
            "sip:3009@phone.invalid",
            None,
        ),
    );
    let acks = requests_to(&drain(&dispatcher.udp), socket(EDGE), Method::Ack);
    assert_eq!(acks.len(), 1);
    assert_eq!(
        acks[0]
            .message
            .headers
            .get_all("Route")
            .cloned()
            .unwrap_or_default(),
        vec![path]
    );
    assert_drained(&dispatcher);
}

/// An AoR with a single phone is a group of one: it rings and wins alone.
#[tokio::test(flavor = "multi_thread")]
async fn a_single_phone_aor_rings_and_answers_as_a_group_of_one() {
    const DESK: &str = "198.51.100.33:5060";
    let aor = "sip:3010@siphon.example.com";
    register(aor, &format!("sip:3010@{DESK}"), 1.0);
    let engine = NativeTestEngine::start().await;
    let dispatcher = anchored_dispatcher(&engine);
    let (_group_id, recorder) = ring(
        &dispatcher.state,
        aor,
        OriginateGroupStrategy::Parallel,
        30,
        30,
    );
    let invite = invite_to(&drain(&dispatcher.udp), DESK);
    recorder.take();
    phone_sends(
        &dispatcher.state,
        socket(DESK),
        &phone_response(
            &invite,
            200,
            "OK",
            "desk-tag",
            &format!("sip:3010@{DESK}"),
            Some(&phone_offer("198.51.100.33")),
        ),
    );
    let acks = requests_to(&drain(&dispatcher.udp), socket(DESK), Method::Ack);
    assert_eq!(acks.len(), 1);
    assert_eq!(body_text(&acks[0].message), NATIVE_ENGINE_ANSWER);
    assert!(matches!(
        recorder.take().as_slice(),
        [Reported::Answered(_)]
    ));
    assert_drained(&dispatcher);
}

/// A group whose only target cannot be dialled places nothing, tells its sink
/// nothing, and hands the refusal back.
#[tokio::test(flavor = "multi_thread")]
async fn a_group_that_can_dial_nothing_is_refused_with_nothing_on_the_wire() {
    let engine = NativeTestEngine::start().await;
    let dispatcher = anchored_dispatcher(&engine);
    let recorder = Arc::new(Recorder::default());
    let group_id = create_originate_group(
        &dispatcher.state,
        OriginateGroupSpec {
            params: anchored_params("sip:3011@siphon.example.com"),
            targets: vec![DialTarget {
                uri: "sip:3011@nowhere.invalid".to_string(),
                ..Default::default()
            }],
            strategy: OriginateGroupStrategy::Sequential,
            total_timeout_secs: 30,
        },
        Arc::clone(&recorder) as Arc<dyn OriginateGroupSink>,
    )
    .expect("the group is created");
    assert!(matches!(
        start_originate_group(&dispatcher.state, &group_id),
        Err(OriginateError::Unroutable(_))
    ));
    assert!(drain(&dispatcher.udp).is_empty());
    assert!(recorder.take().is_empty());
    assert_drained(&dispatcher);
    assert_eq!(dispatcher.state.call_actors.count(), 0);
}

/// Per-module leak gate: after a batch of complete races — a win, every phone
/// declining, a cancel and a timeout — the group store holds nothing and no
/// call is left behind.
#[tokio::test(flavor = "multi_thread")]
async fn the_group_store_drains_after_complete_races() {
    const DESK: &str = "198.51.100.101:5060";
    const MOBILE: &str = "198.51.100.102:5060";
    let aor = "sip:3099@siphon.example.com";
    register(aor, &format!("sip:3099@{DESK}"), 1.0);
    register(aor, &format!("sip:3099@{MOBILE}"), 0.5);
    let engine = NativeTestEngine::start().await;
    let dispatcher = anchored_dispatcher(&engine);
    let baseline_groups = dispatcher.state.originate_groups.group_count();
    let baseline_legs = dispatcher.state.originate_groups.leg_count();

    for round in 0..25 {
        // A win: the mobile answers, the desk is CANCELled.
        let (_, _) = ring(
            &dispatcher.state,
            aor,
            OriginateGroupStrategy::Parallel,
            30,
            30,
        );
        let sent = drain(&dispatcher.udp);
        let mobile_invite = invite_to(&sent, MOBILE);
        phone_sends(
            &dispatcher.state,
            socket(MOBILE),
            &phone_response(
                &mobile_invite,
                200,
                "OK",
                &format!("m-{round}"),
                &format!("sip:3099@{MOBILE}"),
                Some(&phone_offer("198.51.100.102")),
            ),
        );
        let winner = dispatcher
            .state
            .call_actors
            .find_by_sip_call_id(mobile_invite.headers.call_id().expect("a Call-ID"))
            .expect("the winner's call");
        // The winner hangs up the ordinary way.
        assert!(b2bua_drop_or_bye(&dispatcher.state, &winner));

        // Every phone declines.
        let (_, _) = ring(
            &dispatcher.state,
            aor,
            OriginateGroupStrategy::Parallel,
            30,
            30,
        );
        let sent = drain(&dispatcher.udp);
        for phone in [DESK, MOBILE] {
            let invite = invite_to(&sent, phone);
            phone_sends(
                &dispatcher.state,
                socket(phone),
                &phone_response(
                    &invite,
                    486,
                    "Busy Here",
                    "busy",
                    &format!("sip:3099@{phone}"),
                    None,
                ),
            );
        }

        // A cancel.
        let (group_id, _) = ring(
            &dispatcher.state,
            aor,
            OriginateGroupStrategy::Parallel,
            30,
            30,
        );
        drain(&dispatcher.udp);
        assert!(cancel_originated_call(&dispatcher.state, &group_id, None));

        // A timeout.
        let (_, _) = ring(
            &dispatcher.state,
            aor,
            OriginateGroupStrategy::Sequential,
            30,
            2,
        );
        drain(&dispatcher.udp);
        check_b2bua_answer_timeouts_at(
            &dispatcher.state,
            std::time::Instant::now() + std::time::Duration::from_secs(3),
        );
        drain(&dispatcher.udp);
    }

    assert_eq!(
        dispatcher.state.originate_groups.group_count(),
        baseline_groups
    );
    assert_eq!(dispatcher.state.originate_groups.leg_count(), baseline_legs);
    assert_eq!(
        dispatcher.state.call_actors.count(),
        0,
        "every leg's call is gone"
    );
}

/// End an answered originated call with a BYE, through the teardown every
/// answered call takes.
fn b2bua_drop_or_bye(state: &DispatcherState, internal_call_id: &str) -> bool {
    b2bua_terminate_call_inner(internal_call_id, None, "b2bua", state)
}
