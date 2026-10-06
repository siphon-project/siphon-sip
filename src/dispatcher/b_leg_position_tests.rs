//! A response acts on the leg whose request it answers, wherever that leg sits
//! on the call by the time the response is acted on.
//!
//! A response handler reads the call once when the response arrives
//! ([`b_leg_response_snapshot`]) and acts after its hooks, retries and media
//! engine calls have run. A leg ahead of the one it answers can be taken off
//! the call in between: the leg tracking a relayed in-dialog request once that
//! request is refused, the targets of a replacement that failed. Every leg
//! behind it then sits one place lower, and a position read earlier names its
//! neighbour or no leg at all.
//!
//! Each test reads the snapshot, takes a leg ahead off the call, and only then
//! runs the handler with that snapshot: the interleaving another worker
//! produces. What the handler does has to land on the leg the response's Via
//! branch names (RFC 3261 §8.1.1.7).

use super::lcr_ring_timeout_tests::{
    carrier, carrier_response, invite_to, summaries, top_via_branch, Sequence, CALLER,
    FIRST_CARRIER, SECOND_CARRIER,
};
use super::*;

const AHEAD: &str = "z9hG4bK-tracked-ahead";
const TRACKED: &str = "z9hG4bK-tracked";
const BEHIND: &str = "z9hG4bK-tracked-behind";

const FAIL_THE_ANSWER: &str = r#"
from siphon import b2bua

@b2bua.on_answer
def answered(call, reply):
    raise RuntimeError("the answer is refused")
"#;

fn address(text: &str) -> SocketAddr {
    text.parse().expect("a literal address")
}

/// A leg tracking an in-dialog request siphon relayed from the caller to the
/// callee, as it sits on the call until the request's response is in.
fn tracking_leg(branch: &str, target: &str) -> Leg {
    let mut leg = Leg::new_b_leg(
        "callee-dialog@192.0.2.1".to_string(),
        "siphon-tag".to_string(),
        target.to_string(),
        branch.to_string(),
        LegTransport {
            remote_addr: address(FIRST_CARRIER),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    );
    leg.stored_vias = vec![format!("SIP/2.0/UDP {CALLER};branch={branch}-from-caller")];
    leg.stored_cseq = Some("7 UPDATE".to_string());
    leg
}

/// The callee's response to the request `leg` tracks.
fn tracked_response(leg: &Leg, status_code: u16, method: &str) -> SipMessage {
    let raw = format!(
        concat!(
            "SIP/2.0 {status_code} Response\r\n",
            "Via: SIP/2.0/UDP 192.0.2.1:5060;branch={branch}\r\n",
            "From: <sip:15550100001@192.0.2.1>;tag={tag}\r\n",
            "To: <sip:15550100042@198.51.100.7>;tag=carrier-tag\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 3 {method}\r\n",
            "Content-Length: 0\r\n\r\n",
        ),
        status_code = status_code,
        branch = leg.branch,
        tag = leg.dialog.local_tag,
        call_id = leg.dialog.call_id,
        method = method,
    );
    parse_sip_message_bytes(raw.as_bytes()).expect("the response parses")
}

/// A caller's call with a tracking leg already on it, and nothing dialled.
fn call_behind_a_tracking_leg(script: &str) -> Sequence {
    let sequence = Sequence::new_call(script);
    assert!(sequence
        .dispatcher
        .state
        .call_actors
        .add_b_leg(&sequence.call_id, tracking_leg(AHEAD, "info:a2b")));
    sequence
}

/// Dial `address` as one more branch of the call and hand back its INVITE.
fn dial(sequence: &Sequence, address: &str) -> SipMessage {
    let dialled = {
        let guard = sequence.invite.lock().expect("the A-leg INVITE lock");
        b2bua_send_b_leg_invite(
            &sequence.call_id,
            &format!("sip:15550100042@{address}"),
            Some(format!("sip:{address}").as_str()),
            None,
            &[],
            None,
            None,
            &guard,
            None,
            None,
            None,
            None,
            None,
            None,
            &[],
            &sequence.dispatcher.state,
        )
    };
    assert!(dialled, "the branch to {address} was not dialled");
    invite_to(sequence.wire(), address)
}

/// The snapshot a response on `branch` is handled with, read while the leg
/// ahead is still on the call; that leg is then taken off it.
fn snapshot_then_shift(sequence: &Sequence, branch: &str) -> BLegResponseSnapshot {
    let state = &sequence.dispatcher.state;
    let snapshot =
        b_leg_response_snapshot(&sequence.call_id, branch, state).expect("the call exists");
    assert!(snapshot.matched_b_leg);
    let read_at = state
        .call_actors
        .b_leg_index(&sequence.call_id, branch)
        .expect("the leg is on the call");
    state.call_actors.remove_b_leg_on(&sequence.call_id, AHEAD);
    assert_eq!(
        state.call_actors.b_leg_index(&sequence.call_id, branch),
        Some(read_at - 1),
        "the leg moved down one place"
    );
    snapshot
}

fn branches(sequence: &Sequence) -> Vec<String> {
    sequence
        .dispatcher
        .state
        .call_actors
        .get_call(&sequence.call_id)
        .map(|call| call.b_legs.iter().map(|leg| leg.branch.clone()).collect())
        .unwrap_or_default()
}

fn target_of(sequence: &Sequence, branch: &str) -> Option<String> {
    sequence
        .dispatcher
        .state
        .call_actors
        .read_b_leg_on(&sequence.call_id, branch, |leg| {
            leg.dialog.target_uri.clone()
        })
        .flatten()
}

/// The answer claims the call for the leg that answered: that leg is the
/// winner, its 2xx is ACKed and recorded as ACKed, and the caller is answered.
#[tokio::test(flavor = "multi_thread")]
async fn an_answer_wins_for_the_leg_that_sent_it_after_the_leg_list_shifts() {
    let sequence = call_behind_a_tracking_leg("");
    let state = &sequence.dispatcher.state;
    let invite = dial(&sequence, FIRST_CARRIER);
    let branch = top_via_branch(&invite);
    let snapshot = snapshot_then_shift(&sequence, &branch);

    let mut answer = carrier_response(&invite, 200, "OK");
    tokio::task::block_in_place(|| {
        b_leg_answered(
            &sequence.call_id,
            &mut answer,
            200,
            address(FIRST_CARRIER),
            state,
            &snapshot,
        )
    });

    let (winner, acked) = state
        .call_actors
        .get_call(&sequence.call_id)
        .map(|call| {
            let winner = call.winning_b_leg();
            (
                winner.map(|leg| leg.branch.clone()),
                winner.is_some_and(|leg| leg.initial_acked),
            )
        })
        .expect("the call is up");
    assert_eq!(winner, Some(branch), "the leg that answered is the winner");
    assert!(acked, "its 2xx is recorded as ACKed");
    let sent = summaries(&sequence.wire());
    assert!(sent.contains(&format!("200 to {CALLER}")), "{sent:?}");
    assert!(
        sent.contains(&format!("ACK to {FIRST_CARRIER}")),
        "{sent:?}"
    );
}

/// An answer `@b2bua.on_answer` refuses releases the leg that answered: its
/// 2xx is ACKed and its dialog ended with a BYE (RFC 3261 §13.2.2.4, §15), and
/// the caller gets the failure.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_answer_releases_the_leg_that_sent_it_after_the_leg_list_shifts() {
    let sequence = call_behind_a_tracking_leg(FAIL_THE_ANSWER);
    let state = &sequence.dispatcher.state;
    let invite = dial(&sequence, FIRST_CARRIER);
    let snapshot = snapshot_then_shift(&sequence, &top_via_branch(&invite));

    let mut answer = carrier_response(&invite, 200, "OK");
    tokio::task::block_in_place(|| {
        b_leg_answered(
            &sequence.call_id,
            &mut answer,
            200,
            address(FIRST_CARRIER),
            state,
            &snapshot,
        )
    });

    // The ACK and the BYE leave as one ordered unit, so each frame is read.
    let mut sent = Vec::new();
    while let Ok(outbound) = sequence.dispatcher.udp.try_recv() {
        for frame in outbound.frames() {
            let message = parse_sip_message_bytes(frame).expect("a message that parses");
            let what = match (message.method(), message.status_code()) {
                (Some(method), _) => method.as_str().to_string(),
                (None, status_code) => status_code.unwrap_or_default().to_string(),
            };
            sent.push(format!("{what} to {}", outbound.destination));
        }
    }
    assert_eq!(
        sent,
        [
            format!("ACK to {FIRST_CARRIER}"),
            format!("BYE to {FIRST_CARRIER}"),
            format!("500 to {CALLER}"),
        ]
    );
}

/// A carrier's failure settles that carrier's leg, so the route sequence moves
/// on to the next carrier instead of taking the response for a straggler.
#[tokio::test(flavor = "multi_thread")]
async fn a_carrier_failure_advances_the_sequence_after_the_leg_list_shifts() {
    let mut sequence = call_behind_a_tracking_leg("");
    let advance = sequence.start_routes(
        vec![
            carrier("first", FIRST_CARRIER, 30),
            carrier("second", SECOND_CARRIER, 30),
        ],
        30,
    );
    assert!(advance.dialed);
    let state = &sequence.dispatcher.state;
    let invite = invite_to(sequence.wire(), FIRST_CARRIER);
    let branch = top_via_branch(&invite);
    let snapshot = snapshot_then_shift(&sequence, &branch);

    let mut failure = carrier_response(&invite, 503, "Service Unavailable");
    tokio::task::block_in_place(|| {
        b_leg_failed(
            &sequence.call_id,
            &branch,
            &mut failure,
            503,
            state,
            &snapshot,
        )
    });

    let sent = summaries(&sequence.wire());
    assert_eq!(
        sent,
        [
            format!("ACK to {FIRST_CARRIER}"),
            format!("INVITE to {SECOND_CARRIER}")
        ]
    );
}

/// A challenge is answered once, by superseding the leg that was challenged:
/// the credentialed INVITE goes out and takes that leg's place on the call.
#[tokio::test(flavor = "multi_thread")]
async fn a_challenge_supersedes_the_leg_it_was_sent_on_after_the_leg_list_shifts() {
    let sequence = call_behind_a_tracking_leg("");
    let state = &sequence.dispatcher.state;
    if let Some(mut call) = state.call_actors.get_call_mut(&sequence.call_id) {
        call.outbound_credentials = Some(Arc::new(crate::auth::StoredCredentials {
            username: "trunk".to_string(),
            secret: crate::auth::StoredSecret::Password("secret".to_string()),
        }));
    }
    let invite = dial(&sequence, FIRST_CARRIER);
    let branch = top_via_branch(&invite);
    let snapshot = snapshot_then_shift(&sequence, &branch);

    let mut challenge = carrier_response(&invite, 401, "Unauthorized");
    challenge.headers.set(
        "WWW-Authenticate",
        r#"Digest realm="carrier.example", nonce="abc123", qop="auth", algorithm=MD5"#.to_string(),
    );
    tokio::task::block_in_place(|| {
        b_leg_failed(
            &sequence.call_id,
            &branch,
            &mut challenge,
            401,
            state,
            &snapshot,
        )
    });

    let sent = sequence.wire();
    assert_eq!(
        summaries(&sent),
        [
            format!("ACK to {FIRST_CARRIER}"),
            format!("INVITE to {FIRST_CARRIER}")
        ]
    );
    let retry = &sent[1].message;
    assert!(retry.headers.get("Authorization").is_some());
    assert_eq!(
        branches(&sequence),
        [top_via_branch(retry)],
        "the retry took the challenged leg's place"
    );

    // The challenge again, on the branch that was superseded: a retransmission,
    // ACKed and nothing else (RFC 3261 §17.1.1.3).
    tokio::task::block_in_place(|| {
        b_leg_failed(
            &sequence.call_id,
            &branch,
            &mut challenge,
            401,
            state,
            &snapshot,
        )
    });
    assert_eq!(
        summaries(&sequence.wire()),
        [format!("ACK to {FIRST_CARRIER}")]
    );
}

/// An answered call carrying three tracking legs, the one a response is about
/// to arrive for in the middle.
struct Tracked {
    sequence: Sequence,
    leg: Leg,
}

impl Tracked {
    fn on_an_answered_call(target: &str) -> Tracked {
        let sequence = Sequence::start_fork(&[FIRST_CARRIER]);
        let invite = invite_to(sequence.wire(), FIRST_CARRIER);
        sequence.carrier_answers(FIRST_CARRIER, &invite, 200, "OK");
        let _ = sequence.wire();
        let store = &sequence.dispatcher.state.call_actors;
        let mut leg = tracking_leg(TRACKED, target);
        leg.dialog.route_set = vec!["<sip:198.51.100.20:5060;lr>".to_string()];
        let mut behind = tracking_leg(BEHIND, "info:a2b");
        behind.dialog.route_set = vec!["<sip:198.51.100.30:5060;lr>".to_string()];
        for added in [tracking_leg(AHEAD, "info:a2b"), leg.clone(), behind] {
            assert!(store.add_b_leg(&sequence.call_id, added));
        }
        Tracked { sequence, leg }
    }

    /// The callee's `status_code` to the tracked request arrives, and the leg
    /// ahead is taken off the call before `handle` acts on it.
    fn respond(
        &self,
        status_code: u16,
        method: &str,
        handle: impl FnOnce(&str, &mut SipMessage, &DispatcherState, &BLegResponseSnapshot) -> bool,
    ) {
        let snapshot = snapshot_then_shift(&self.sequence, TRACKED);
        let mut response = tracked_response(&self.leg, status_code, method);
        let consumed = tokio::task::block_in_place(|| {
            handle(
                &self.sequence.call_id,
                &mut response,
                &self.sequence.dispatcher.state,
                &snapshot,
            )
        });
        assert!(consumed, "the response was for the tracked request");
    }

    /// The tracked leg is kept under `done`, for a retransmission of its 2xx
    /// to be recognised by, and the leg behind it still waits for its own
    /// response.
    fn assert_kept_as(&self, done: &str) {
        assert_eq!(
            target_of(&self.sequence, TRACKED).as_deref(),
            Some(done),
            "the answered request's own leg is the one marked done"
        );
        assert_eq!(
            target_of(&self.sequence, BEHIND).as_deref(),
            Some("info:a2b"),
            "the leg behind it still waits for its own response"
        );
    }

    /// The tracked leg is off the call and the leg behind it is not.
    fn assert_removed(&self) {
        let left = branches(&self.sequence);
        assert!(!left.iter().any(|branch| branch == TRACKED), "{left:?}");
        assert!(left.iter().any(|branch| branch == BEHIND), "{left:?}");
    }
}

fn update_response(
    call_id: &str,
    response: &mut SipMessage,
    state: &DispatcherState,
    snapshot: &BLegResponseSnapshot,
) -> bool {
    let status_code = response.status_code().expect("a response");
    forward_update_response(
        call_id,
        response,
        status_code,
        address(FIRST_CARRIER),
        state,
        snapshot,
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relayed_update_is_settled_on_its_own_leg_after_the_leg_list_shifts() {
    let accepted = Tracked::on_an_answered_call("update:a2b");
    accepted.respond(200, "UPDATE", update_response);
    accepted.assert_kept_as("update_done:a2b");
    let sent = summaries(&accepted.sequence.wire());
    assert_eq!(sent, [format!("200 to {CALLER}")]);

    let refused = Tracked::on_an_answered_call("update:a2b");
    refused.respond(488, "UPDATE", update_response);
    refused.assert_removed();
}

/// An UPDATE siphon sent itself (a session refresh) has no originator: its
/// tracking leg carries no Via to restore.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_siphon_sent_is_settled_on_its_own_leg_after_the_leg_list_shifts() {
    let own = |tracked: &mut Tracked| {
        tracked.leg.stored_vias.clear();
        let store = &tracked.sequence.dispatcher.state.call_actors;
        if let Some(mut call) = store.get_call_mut(&tracked.sequence.call_id) {
            if let Some((_, leg)) = call.find_b_leg_by_branch_mut(TRACKED) {
                leg.stored_vias.clear();
            }
        }
    };
    let mut accepted = Tracked::on_an_answered_call("update:a2b");
    own(&mut accepted);
    accepted.respond(200, "UPDATE", update_response);
    accepted.assert_kept_as("update_done:a2b");
    assert!(accepted.sequence.wire().is_empty(), "nothing is relayed");

    let mut refused = Tracked::on_an_answered_call("update:a2b");
    own(&mut refused);
    refused.respond(481, "UPDATE", update_response);
    refused.assert_removed();
}

fn reinvite_response(
    call_id: &str,
    response: &mut SipMessage,
    state: &DispatcherState,
    snapshot: &BLegResponseSnapshot,
) -> bool {
    let status_code = response.status_code().expect("a response");
    forward_reinvite_response(
        call_id,
        TRACKED,
        response,
        status_code,
        address(FIRST_CARRIER),
        state,
        snapshot,
    )
}

/// The ACK of a relayed re-INVITE's 2xx carries the route set the re-INVITE
/// went out with (RFC 3261 §12.2.1.1), read off the re-INVITE's own leg.
#[tokio::test(flavor = "multi_thread")]
async fn a_relayed_reinvite_is_settled_on_its_own_leg_after_the_leg_list_shifts() {
    let accepted = Tracked::on_an_answered_call("reinvite:a2b");
    accepted.respond(200, "INVITE", reinvite_response);
    accepted.assert_kept_as("reinvite_done:a2b");
    let sent = accepted.sequence.wire();
    let ack = sent
        .iter()
        .find(|sent| sent.message.method() == Some(&Method::Ack))
        .expect("the 2xx is ACKed");
    assert_eq!(
        ack.message.headers.get("Route").map(String::as_str),
        Some("<sip:198.51.100.20:5060;lr>"),
        "the route set of the re-INVITE this ACK completes"
    );
    assert_eq!(ack.destination, address("198.51.100.20:5060"));

    let refused = Tracked::on_an_answered_call("reinvite:a2b");
    refused.respond(488, "INVITE", reinvite_response);
    refused.assert_removed();
}

fn forwarded_response(
    call_id: &str,
    response: &mut SipMessage,
    state: &DispatcherState,
    snapshot: &BLegResponseSnapshot,
) -> bool {
    let status_code = response.status_code().expect("a response");
    forward_transfer_response(call_id, response, status_code, state, snapshot)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relayed_refer_is_settled_on_its_own_leg_after_the_leg_list_shifts() {
    let accepted = Tracked::on_an_answered_call("refer:a2b");
    accepted.respond(202, "REFER", forwarded_response);
    accepted.assert_kept_as("refer_done:a2b");
    let sent = summaries(&accepted.sequence.wire());
    assert_eq!(sent, [format!("202 to {CALLER}")]);

    let refused = Tracked::on_an_answered_call("refer:a2b");
    refused.respond(603, "REFER", forwarded_response);
    refused.assert_removed();
}

fn owned_response(
    call_id: &str,
    response: &mut SipMessage,
    state: &DispatcherState,
    snapshot: &BLegResponseSnapshot,
) -> bool {
    let status_code = response.status_code().expect("a response");
    settle_owned_leg_response(
        call_id,
        TRACKED,
        response,
        status_code,
        snapshot,
        OwnedLegRequest {
            done_target: "update_done:b2a".to_string(),
            is_invite: false,
        },
        state,
    );
    true
}

/// A request siphon sent on a leg's own dialog (a bridge's re-offer, a session
/// refresh) is settled on the leg that tracks it.
#[tokio::test(flavor = "multi_thread")]
async fn a_request_siphon_sent_on_a_leg_is_settled_on_its_own_leg_after_the_leg_list_shifts() {
    let accepted = Tracked::on_an_answered_call("update:b2a");
    accepted.respond(200, "UPDATE", owned_response);
    accepted.assert_kept_as("update_done:b2a");

    let refused = Tracked::on_an_answered_call("update:b2a");
    refused.respond(488, "UPDATE", owned_response);
    refused.assert_removed();
}
