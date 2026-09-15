//! A route's `timeout_secs` bounds the wait for a carrier to show progress, not
//! the wait for its answer.
//!
//! Driven through the dispatcher: carriers are dialled by
//! [`b2bua_advance_route`], answer through [`handle_b2bua_response`] and ring
//! out through [`check_b2bua_answer_timeouts_at`], with every INVITE, CANCEL and
//! response read back off the UDP egress channel.
//!
//! The answer deadlines are `std::time::Instant`s, which a paused tokio clock
//! does not move, so each test steps past a deadline by handing the sweep a
//! later instant rather than waiting it out.

use super::lcr_number_policy_tests::a_leg_invite;
use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::*;
use std::time::{Duration, Instant};

pub(super) const FIRST_CARRIER: &str = "198.51.100.7:5060";
pub(super) const SECOND_CARRIER: &str = "198.51.100.8:5060";
pub(super) const THIRD_CARRIER: &str = "198.51.100.9:5060";
pub(super) const CALLER: &str = "192.0.2.10:5060";

/// Leaves a mark on the A-leg INVITE each time `@b2bua.on_failure` runs, so a
/// test can tell how many times it ran, and with which code, without the
/// script keeping state of its own.
const MARK_FAILURES: &str = r#"
from siphon import b2bua

@b2bua.on_failure
def failed(call, code, reason):
    seen = call.get_header("X-Test-Failures") or ""
    call.set_header("X-Test-Failures", seen + str(code) + ";")
"#;

pub(super) fn carrier(carrier_id: &str, address: &str, timeout_secs: u32) -> crate::lcr::Route {
    crate::lcr::Route {
        carrier_id: carrier_id.to_string(),
        next_hop: Some(format!("sip:{address}")),
        timeout_secs: Some(timeout_secs),
        ..Default::default()
    }
}

/// One message siphon put on the wire.
pub(super) struct Sent {
    pub(super) destination: SocketAddr,
    pub(super) message: SipMessage,
}

impl Sent {
    /// `INVITE to 198.51.100.7:5060`, `408 to 192.0.2.10:5060`.
    fn summary(&self) -> String {
        match &self.message.start_line {
            StartLine::Request(_) => {
                let method = self
                    .message
                    .headers
                    .cseq()
                    .and_then(|cseq| cseq.split_whitespace().nth(1).map(str::to_string))
                    .unwrap_or_default();
                format!("{method} to {}", self.destination)
            }
            StartLine::Response(status) => {
                format!("{} to {}", status.status_code, self.destination)
            }
        }
    }
}

pub(super) fn summaries(sent: &[Sent]) -> Vec<String> {
    sent.iter().map(Sent::summary).collect()
}

/// The INVITE among `sent` that went to `address`.
pub(super) fn invite_to(sent: Vec<Sent>, address: &str) -> SipMessage {
    let listed = summaries(&sent);
    sent.into_iter()
        .find(|sent| sent.summary() == format!("INVITE to {address}"))
        .map(|sent| sent.message)
        .unwrap_or_else(|| panic!("no INVITE to {address}, sent: {listed:?}"))
}

pub(super) fn top_via_branch(message: &SipMessage) -> String {
    let via = message
        .headers
        .get("Via")
        .map(|value| value.to_string())
        .expect("a Via header");
    via.split(';')
        .find_map(|parameter| parameter.trim().strip_prefix("branch="))
        .map(str::to_string)
        .expect("a Via branch")
}

/// `status_code` for the carrier's INVITE, as its server transaction would send
/// it (RFC 3261 §8.2.6.2): the INVITE's Via, From, Call-ID and CSeq, and a To
/// the carrier has tagged on anything but a 100.
fn carrier_response(invite: &SipMessage, status_code: u16, reason: &str) -> SipMessage {
    let header = |name: &str| {
        invite
            .headers
            .get(name)
            .map(|value| value.to_string())
            .unwrap_or_else(|| panic!("the carrier INVITE has no {name}"))
    };
    let mut raw = format!("SIP/2.0 {status_code} {reason}\r\n");
    for via in invite.headers.get_all("Via").cloned().unwrap_or_default() {
        raw.push_str(&format!("Via: {via}\r\n"));
    }
    raw.push_str(&format!("From: {}\r\n", header("From")));
    if status_code == 100 {
        raw.push_str(&format!("To: {}\r\n", header("To")));
    } else {
        raw.push_str(&format!("To: {};tag=carrier-tag\r\n", header("To")));
    }
    raw.push_str(&format!("Call-ID: {}\r\n", header("Call-ID")));
    raw.push_str(&format!("CSeq: {}\r\n", header("CSeq")));
    raw.push_str("Content-Length: 0\r\n\r\n");
    parse_sip_message_bytes(raw.as_bytes()).expect("the carrier response parses")
}

/// A caller's call running an LCR sequence through a real dispatcher.
pub(super) struct Sequence {
    pub(super) dispatcher: TestDispatcher,
    pub(super) call_id: String,
    pub(super) invite: Arc<Mutex<SipMessage>>,
    /// Taken just after the most recent carrier was dialled, so no earlier than
    /// that attempt's own dial: a deadline counted from the dial has passed by
    /// `dialled` plus its length.
    dialled: Instant,
}

impl Sequence {
    /// Start `routes` with `ring_bound_secs` as the sequence's ring bound (what
    /// `call.route(timeout=…)` sets), and dial the first carrier.
    fn start(routes: Vec<crate::lcr::Route>, ring_bound_secs: u32) -> Sequence {
        Sequence::start_with_script(routes, ring_bound_secs, MARK_FAILURES)
    }

    /// [`Sequence::start`] with `script` as the dispatcher's script instead of
    /// one that only marks `@b2bua.on_failure`.
    pub(super) fn start_with_script(
        routes: Vec<crate::lcr::Route>,
        ring_bound_secs: u32,
        script: &str,
    ) -> Sequence {
        let mut sequence = Sequence::new_call(script);
        let state = &sequence.dispatcher.state;
        state.call_actors.start_route_sequence(
            &sequence.call_id,
            crate::b2bua::actor::RouteSequenceState {
                pending: routes.into(),
                default_timeout: ring_bound_secs,
                ..Default::default()
            },
        );
        let advance = {
            let guard = sequence.invite.lock().expect("the A-leg INVITE lock");
            b2bua_advance_route(&sequence.call_id, &guard, state)
        };
        // As the INVITE path does once its guard is released: a carrier burned
        // on the way to the first dial is reported like any other.
        b2bua_dispatch_burned_routes(&sequence.call_id, &advance.burned, state);
        assert!(advance.dialed, "the first carrier was not dialled");
        sequence.redialled();
        sequence
    }

    /// The caller's call forked in parallel to `addresses`, one branch each,
    /// with no script.
    pub(super) fn start_fork(addresses: &[&str]) -> Sequence {
        let mut sequence = Sequence::new_call("");
        {
            let guard = sequence.invite.lock().expect("the A-leg INVITE lock");
            for address in addresses {
                let target = format!("sip:15550100042@{address}");
                let next_hop = format!("sip:{address}");
                let dialled = b2bua_send_b_leg_invite(
                    &sequence.call_id,
                    &target,
                    Some(next_hop.as_str()),
                    None,
                    &[],
                    None,
                    None,
                    &guard,
                    None,
                    None,
                    None,
                    None,
                    &[],
                    &sequence.dispatcher.state,
                );
                assert!(dialled, "the branch to {address} was not dialled");
            }
        }
        sequence.redialled();
        sequence
    }

    /// A caller's call through a dispatcher running `script`, with nothing
    /// dialled yet.
    fn new_call(script: &str) -> Sequence {
        let dispatcher = test_dispatcher_with_script(script);
        let call_id = dispatcher.state.call_actors.create_call(Leg::new_a_leg(
            "lcr-policy@192.0.2.10".to_string(),
            "caller-tag".to_string(),
            "z9hG4bK-lcr-policy".to_string(),
            LegTransport {
                remote_addr: CALLER.parse().expect("a literal address"),
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
                local_addr: None,
            },
        ));
        let invite = Arc::new(Mutex::new(a_leg_invite("15550100042", "15550100001")));
        dispatcher
            .state
            .call_actors
            .set_a_leg_invite(&call_id, Arc::clone(&invite));
        Sequence {
            dispatcher,
            call_id,
            invite,
            dialled: Instant::now(),
        }
    }

    /// Everything siphon has put on the wire since the last look, in order.
    pub(super) fn wire(&self) -> Vec<Sent> {
        let mut sent = Vec::new();
        while let Ok(outbound) = self.dispatcher.udp.try_recv() {
            sent.push(Sent {
                destination: outbound.destination,
                message: parse_sip_message_bytes(&outbound.data)
                    .expect("siphon sent a message that parses"),
            });
        }
        sent
    }

    /// The carrier at `address` answers its INVITE with `status_code`.
    pub(super) fn carrier_answers(
        &self,
        address: &str,
        invite: &SipMessage,
        status_code: u16,
        reason: &str,
    ) {
        let mut response = carrier_response(invite, status_code, reason);
        let handled = handle_b2bua_response(
            &self.call_id,
            &top_via_branch(invite),
            &mut response,
            status_code,
            address.parse().expect("a literal address"),
            &self.dispatcher.state,
        );
        assert!(
            handled,
            "the call was gone when the carrier's {status_code} arrived"
        );
    }

    /// Run the answer-timeout sweep `after` the most recent dial.
    pub(super) fn ring_for(&self, after: Duration) {
        check_b2bua_answer_timeouts_at(&self.dispatcher.state, self.dialled + after);
    }

    /// A carrier was just dialled: later deadlines count from now.
    pub(super) fn redialled(&mut self) {
        self.dialled = Instant::now();
    }

    /// The codes `@b2bua.on_failure` ran with, in order, or `None` if it never
    /// ran.
    pub(super) fn failures_seen(&self) -> Option<String> {
        self.invite
            .lock()
            .expect("the A-leg INVITE lock")
            .headers
            .get("X-Test-Failures")
            .map(|value| value.to_string())
    }

    pub(super) fn call_is_gone(&self) -> bool {
        self.dispatcher
            .state
            .call_actors
            .get_call(&self.call_id)
            .is_none()
    }
}

/// The failure this exists for. The carrier sends 183 and is ringing the
/// callee when its 2 s `timeout_secs` passes. Failing it over there cut the
/// caller off mid-ring and handed the call to a carrier that had to start again.
/// Now it rings on to the sequence's 5 s bound, and then the call fails with 408
/// without the second carrier ever being tried.
#[tokio::test(flavor = "multi_thread")]
async fn a_carrier_that_showed_progress_keeps_the_call_past_its_ring_timeout() {
    let sequence = Sequence::start(
        vec![
            carrier("carrier-a", FIRST_CARRIER, 2),
            carrier("carrier-b", SECOND_CARRIER, 2),
        ],
        5,
    );
    let first = invite_to(sequence.wire(), FIRST_CARRIER);

    sequence.carrier_answers(FIRST_CARRIER, &first, 183, "Session Progress");
    assert_eq!(summaries(&sequence.wire()), [format!("183 to {CALLER}")]);

    sequence.ring_for(Duration::from_secs(2));
    assert_eq!(
        summaries(&sequence.wire()),
        Vec::<String>::new(),
        "a carrier that has shown progress is not failed over at its own timeout"
    );
    assert!(sequence.failures_seen().is_none());

    sequence.ring_for(Duration::from_secs(5));
    assert_eq!(
        summaries(&sequence.wire()),
        [
            format!("CANCEL to {FIRST_CARRIER}"),
            format!("408 to {CALLER}")
        ],
        "at the ring bound the carrier is CANCELled and the caller gets 408; the second carrier is never dialled"
    );
    assert_eq!(
        sequence.failures_seen().as_deref(),
        Some("408;"),
        "@b2bua.on_failure runs once, with 408"
    );
    assert!(sequence.call_is_gone());
}

/// Before progress nothing changes: a carrier that never answered is failed
/// over at its own `timeout_secs`.
#[tokio::test(flavor = "multi_thread")]
async fn a_carrier_that_never_responded_is_failed_over_at_its_ring_timeout() {
    let sequence = Sequence::start(
        vec![
            carrier("carrier-a", FIRST_CARRIER, 2),
            carrier("carrier-b", SECOND_CARRIER, 2),
        ],
        5,
    );
    invite_to(sequence.wire(), FIRST_CARRIER);

    sequence.ring_for(Duration::from_secs(2));
    assert_eq!(
        summaries(&sequence.wire()),
        [
            format!("CANCEL to {FIRST_CARRIER}"),
            format!("INVITE to {SECOND_CARRIER}")
        ]
    );
    assert!(sequence.failures_seen().is_none());
    assert!(!sequence.call_is_gone());
}

/// A 100 is hop-by-hop (RFC 3261 §16.7 step 2): it says the next hop has the
/// INVITE, not that anything past it is working on the call.
#[tokio::test(flavor = "multi_thread")]
async fn a_100_trying_is_not_progress() {
    let sequence = Sequence::start(
        vec![
            carrier("carrier-a", FIRST_CARRIER, 2),
            carrier("carrier-b", SECOND_CARRIER, 2),
        ],
        5,
    );
    let first = invite_to(sequence.wire(), FIRST_CARRIER);

    sequence.carrier_answers(FIRST_CARRIER, &first, 100, "Trying");
    assert_eq!(summaries(&sequence.wire()), Vec::<String>::new());

    sequence.ring_for(Duration::from_secs(2));
    assert_eq!(
        summaries(&sequence.wire()),
        [
            format!("CANCEL to {FIRST_CARRIER}"),
            format!("INVITE to {SECOND_CARRIER}")
        ]
    );
}

/// Progress belongs to one attempt. A carrier that rang and then failed with a
/// reroute cause hands the call to the next carrier, and that carrier, which
/// has shown nothing, is still failed over at its own timeout.
#[tokio::test(flavor = "multi_thread")]
async fn one_carriers_progress_does_not_keep_the_carrier_after_it() {
    let mut sequence = Sequence::start(
        vec![
            carrier("carrier-a", FIRST_CARRIER, 2),
            carrier("carrier-b", SECOND_CARRIER, 2),
            carrier("carrier-c", THIRD_CARRIER, 2),
        ],
        5,
    );
    let first = invite_to(sequence.wire(), FIRST_CARRIER);
    sequence.carrier_answers(FIRST_CARRIER, &first, 183, "Session Progress");
    assert_eq!(summaries(&sequence.wire()), [format!("183 to {CALLER}")]);

    sequence.carrier_answers(FIRST_CARRIER, &first, 503, "Service Unavailable");
    let sent = sequence.wire();
    assert_eq!(
        summaries(&sent),
        [
            format!("ACK to {FIRST_CARRIER}"),
            format!("INVITE to {SECOND_CARRIER}")
        ]
    );
    sequence.redialled();

    sequence.ring_for(Duration::from_secs(2));
    let sent = summaries(&sequence.wire());
    // Only the second carrier's fate is asserted: it showed nothing, so it is
    // CANCELled and the third carrier dialled.
    assert!(
        sent.contains(&format!("CANCEL to {SECOND_CARRIER}"))
            && sent.contains(&format!("INVITE to {THIRD_CARRIER}")),
        "the second carrier is failed over at its own timeout, sent: {sent:?}"
    );
    assert!(
        !sent.contains(&format!("408 to {CALLER}")),
        "sent: {sent:?}"
    );
    assert!(sequence.failures_seen().is_none());
}

/// A carrier CANCELled on its ring timeout can still get a 183 out before the
/// CANCEL lands. That late provisional must not count as progress for the
/// carrier dialled after it.
#[tokio::test(flavor = "multi_thread")]
async fn a_late_provisional_from_a_cancelled_carrier_does_not_mark_the_next_one() {
    let mut sequence = Sequence::start(
        vec![
            carrier("carrier-a", FIRST_CARRIER, 2),
            carrier("carrier-b", SECOND_CARRIER, 2),
            carrier("carrier-c", THIRD_CARRIER, 2),
        ],
        5,
    );
    let first = invite_to(sequence.wire(), FIRST_CARRIER);

    sequence.ring_for(Duration::from_secs(2));
    assert_eq!(
        summaries(&sequence.wire()),
        [
            format!("CANCEL to {FIRST_CARRIER}"),
            format!("INVITE to {SECOND_CARRIER}")
        ]
    );
    sequence.redialled();

    sequence.carrier_answers(FIRST_CARRIER, &first, 183, "Session Progress");
    assert_eq!(
        summaries(&sequence.wire()),
        Vec::<String>::new(),
        "a cancelled carrier's provisional is not relayed"
    );

    sequence.ring_for(Duration::from_secs(2));
    assert_eq!(
        summaries(&sequence.wire()),
        [
            format!("CANCEL to {SECOND_CARRIER}"),
            format!("INVITE to {THIRD_CARRIER}")
        ]
    );
}

/// The opt-out, for a carrier that answers 183 with its own ringback before it
/// has reached anyone: it is failed over at its timeout, as before.
#[tokio::test(flavor = "multi_thread")]
async fn a_route_that_reroutes_after_progress_is_failed_over_after_a_183() {
    let sequence = Sequence::start(
        vec![
            crate::lcr::Route {
                reroute_after_progress: true,
                ..carrier("carrier-a", FIRST_CARRIER, 2)
            },
            carrier("carrier-b", SECOND_CARRIER, 2),
        ],
        5,
    );
    let first = invite_to(sequence.wire(), FIRST_CARRIER);
    sequence.carrier_answers(FIRST_CARRIER, &first, 183, "Session Progress");
    assert_eq!(summaries(&sequence.wire()), [format!("183 to {CALLER}")]);

    sequence.ring_for(Duration::from_secs(2));
    assert_eq!(
        summaries(&sequence.wire()),
        [
            format!("CANCEL to {FIRST_CARRIER}"),
            format!("INVITE to {SECOND_CARRIER}")
        ]
    );
    assert!(sequence.failures_seen().is_none());
}

/// Progress never shortens a ring: a route whose own timeout is longer than
/// the sequence's bound rings for its own timeout.
#[tokio::test(flavor = "multi_thread")]
async fn a_route_longer_than_the_ring_bound_rings_for_its_own_timeout() {
    let sequence = Sequence::start(
        vec![
            carrier("carrier-a", FIRST_CARRIER, 8),
            carrier("carrier-b", SECOND_CARRIER, 2),
        ],
        5,
    );
    let first = invite_to(sequence.wire(), FIRST_CARRIER);
    sequence.carrier_answers(FIRST_CARRIER, &first, 183, "Session Progress");
    assert_eq!(summaries(&sequence.wire()), [format!("183 to {CALLER}")]);

    sequence.ring_for(Duration::from_secs(5));
    assert_eq!(summaries(&sequence.wire()), Vec::<String>::new());

    sequence.ring_for(Duration::from_secs(8));
    assert_eq!(
        summaries(&sequence.wire()),
        [
            format!("CANCEL to {FIRST_CARRIER}"),
            format!("408 to {CALLER}")
        ]
    );
    assert_eq!(sequence.failures_seen().as_deref(), Some("408;"));
}
