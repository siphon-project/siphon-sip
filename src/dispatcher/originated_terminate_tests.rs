//! Ending a call siphon placed, by its Call-ID, with `b2bua.terminate()` or a
//! control channel's loss policy: RFC 3261 §15 allows a BYE only on a dialog
//! the INVITE's final response has confirmed, and has a caller end one still
//! waiting for that response with a CANCEL (§9.1).
//!
//! An application that rings several of a user's clients at once places one
//! leg per client and, when one answers, ends the others while they ring. Each
//! of those is a CANCEL on its INVITE's own branch, sent once the INVITE has
//! drawn a provisional, its `487` ACKed (§17.1.1.3), and a `2xx` that crossed
//! it ACKed and released with a BYE.
//!
//! Driven through the dispatcher's response path, with what siphon sent read
//! back off the UDP egress.

use super::cancel_awaits_provisional_tests::{
    assert_branch_released, assert_no_cancel, branch_of, the_cancel, until_invite_retransmitted,
    wire_until,
};
use super::originate_test_harness::{
    drain, phone_response, phone_sends, requests_to, socket, Sent,
};
use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::*;
use crate::control::channel_event_capture;

const PHONE_TAG: &str = "callee-tag";

const OFFER: &str = concat!(
    "v=0\r\n",
    "o=- 1 1 IN IP4 192.0.2.1\r\n",
    "s=-\r\n",
    "c=IN IP4 192.0.2.1\r\n",
    "t=0 0\r\n",
    "m=audio 40000 RTP/AVP 0\r\n",
);

/// A script whose handlers note that they ran in `builtins.<slot>`.
fn recording_script(slot: &str) -> String {
    format!(
        concat!(
            "import builtins\n",
            "from siphon import b2bua\n",
            "\n",
            "builtins.{slot} = []\n",
            "\n",
            "@b2bua.on_answer\n",
            "def answer(call, reply):\n",
            "    builtins.{slot}.append(\"answer\")\n",
            "\n",
            "@b2bua.on_failure\n",
            "def failure(call, code, reason):\n",
            "    builtins.{slot}.append(f\"failure {{code}}\")\n",
            "\n",
            "@b2bua.on_bye\n",
            "def bye(call, initiator):\n",
            "    builtins.{slot}.append(\"bye\")\n",
        ),
        slot = slot
    )
}

/// What the handlers of [`recording_script`] noted, in order.
fn noted(slot: &str) -> Vec<String> {
    Python::attach(|python| {
        python
            .import("builtins")
            .and_then(|builtins| builtins.getattr(slot))
            .and_then(|notes| notes.extract())
            .expect("the script's notes")
    })
}

/// A leg siphon placed to one phone, and what the test reads of it.
struct PlacedLeg {
    dispatcher: TestDispatcher,
    phone: &'static str,
    prepared: PreparedOriginate,
}

impl PlacedLeg {
    /// Place a call to `phone`, as `b2bua.originate()` does when `by_script`
    /// and as a controller's `originate` does otherwise.
    fn place(slot: &str, phone: &'static str, by_script: bool) -> Self {
        let leg = Self::dial(slot, phone, by_script);
        assert_eq!(leg.sent(Method::Invite).len(), 1);
        leg
    }

    /// [`Self::place`] with the INVITE left on the egress for the test to read.
    fn dial(slot: &str, phone: &'static str, by_script: bool) -> Self {
        let dispatcher = test_dispatcher_with_script(&recording_script(slot));
        let params = OriginateParams {
            to: format!("sip:callee@{phone}"),
            to_display: None,
            from: Some("sip:server@siphon.example.com".to_string()),
            from_display: None,
            next_hop: None,
            p_asserted_identity: None,
            privacy: None,
            headers: Vec::new(),
            timeout_secs: 30,
            media: OriginateMedia::Offer {
                body: OFFER.as_bytes().to_vec(),
                content_type: "application/sdp".to_string(),
            },
            session_timer: None,
        };
        let prepared = prepare_originate_with_route(
            &dispatcher.state,
            params,
            // The phone's own outbound proxy role: the INVITE goes there.
            vec![format!("<sip:{phone};lr>")],
        )
        .expect("the originate stages");
        if by_script {
            dispatcher
                .state
                .call_actors
                .mark_script_originated(&prepared.internal_call_id);
        }
        channel_event_capture::watch(&prepared.sip_call_id);
        assert!(dial_originate(&dispatcher.state, &prepared));
        PlacedLeg {
            dispatcher,
            phone,
            prepared,
        }
    }

    /// The octets of every frame waiting on the egress, as they would leave.
    fn octets_sent(&self) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        while let Ok(outbound) = self.dispatcher.udp.try_recv() {
            frames.extend(outbound.frames().map(|frame| frame.to_vec()));
        }
        frames
    }

    fn state(&self) -> &DispatcherState {
        &self.dispatcher.state
    }

    fn invite(&self) -> &SipMessage {
        &self.prepared.invite
    }

    /// The phone's response to `request`: the INVITE, or a request sharing
    /// its dialog or branch.
    fn phone_says(&self, request: &SipMessage, status_code: u16, reason: &str, body: Option<&str>) {
        phone_sends(
            self.state(),
            socket(self.phone),
            &phone_response(
                request,
                status_code,
                reason,
                PHONE_TAG,
                &format!("sip:callee@{}", self.phone),
                body,
            ),
        );
    }

    /// The requests of `method` siphon has sent the phone since the last look.
    fn sent(&self, method: Method) -> Vec<Sent> {
        requests_to(&drain(&self.dispatcher.udp), socket(self.phone), method)
    }

    fn terminate(&self) -> bool {
        terminate_call(self.state(), &self.prepared.sip_call_id, Some("released"))
    }

    /// The `StasisEnd` events published for the leg since the last look.
    fn ends(&self) -> Vec<serde_json::Value> {
        channel_event_capture::take(&self.prepared.sip_call_id)
            .into_iter()
            .filter(|(event, _)| event == "StasisEnd")
            .map(|(_, payload)| payload)
            .collect()
    }

    /// The call is gone, and so is everything kept for it once the branch
    /// siphon gave up on has expired.
    fn assert_drained(&self) {
        let state = self.state();
        assert_eq!(state.call_actors.count(), 0, "the call is gone");
        assert!(state.call_event_receivers.is_empty());
        assert!(state.cdr_sessions.is_empty());
        assert_branch_released(state, &branch_of(self.invite()));
        assert_eq!(state.call_actors.cancelled_branch_count(), 0);
        assert!(state.b2bua_retransmits.is_empty());
    }
}

fn header(message: &SipMessage, name: &str) -> Option<String> {
    message.headers.get(name).cloned()
}

fn request_uri(message: &SipMessage) -> String {
    match &message.start_line {
        StartLine::Request(line) => line.request_uri.to_string(),
        StartLine::Response(_) => panic!("a request"),
    }
}

/// A leg that is ringing is ended with a CANCEL built from its INVITE (RFC
/// 3261 §9.1), not a BYE on its early dialog. The `487` the INVITE then draws
/// is ACKed on the INVITE's branch (§17.1.1.3), the end of the call is
/// reported once, and nothing is kept.
#[tokio::test(flavor = "multi_thread")]
async fn terminating_a_ringing_leg_cancels_its_invite() {
    let slot = "terminate_ringing_leg";
    let leg = PlacedLeg::place(slot, "198.51.100.61:5060", true);
    leg.phone_says(leg.invite(), 180, "Ringing", None);
    assert!(drain(&leg.dispatcher.udp).is_empty());

    assert!(leg.terminate());
    let sent = drain(&leg.dispatcher.udp);
    assert!(
        requests_to(&sent, socket(leg.phone), Method::Bye).is_empty(),
        "no BYE for an INVITE with no final response (RFC 3261 §15)"
    );
    assert_eq!(sent.len(), 1, "the CANCEL and nothing else: {sent:?}");
    let cancel = the_cancel(&sent, leg.phone, leg.invite());

    // §9.1: Request-URI, Call-ID, To, From and the numeric part of CSeq are
    // the INVITE's, the To still without the tag the 180 brought; one Via,
    // the INVITE's top one; and the INVITE's Route header field values.
    let invite = leg.invite();
    assert_eq!(request_uri(&cancel), request_uri(invite));
    for name in ["Call-ID", "From", "To", "Via", "Route"] {
        assert!(header(invite, name).is_some(), "the INVITE has a {name}");
        assert_eq!(header(&cancel, name), header(invite, name), "{name}");
    }
    assert_eq!(header(&cancel, "CSeq").as_deref(), Some("1 CANCEL"));
    assert_eq!(header(invite, "CSeq").as_deref(), Some("1 INVITE"));
    assert!(cancel.body.is_empty());

    let ends = leg.ends();
    assert_eq!(ends.len(), 1, "the end of the call is reported once");
    assert_eq!(ends[0]["reason"], "released");
    assert!(!leg.terminate(), "a second terminate finds the call gone");

    leg.phone_says(&cancel, 200, "OK", None);
    leg.phone_says(invite, 487, "Request Terminated", None);
    let sent = wire_until(&leg.dispatcher, |_| true).await;
    assert_eq!(sent.len(), 1, "the ACK and nothing else: {sent:?}");
    assert!(sent[0].is(Method::Ack));
    assert_eq!(branch_of(&sent[0].message), branch_of(invite));
    assert_eq!(header(&sent[0].message, "CSeq").as_deref(), Some("1 ACK"));
    assert_eq!(
        header(&sent[0].message, "Route"),
        header(invite, "Route"),
        "the ACK carries the INVITE's Route (RFC 3261 §17.1.1.3)"
    );

    // The phone's 487 retransmitted (its ACK was lost) is ACKed again.
    leg.phone_says(invite, 487, "Request Terminated", None);
    assert_eq!(leg.sent(Method::Ack).len(), 1);

    assert!(leg.ends().is_empty(), "and reported no second time");
    // The script ended the leg itself: none of its handlers is run for that,
    // as none is for a terminate() of an answered call.
    assert_eq!(noted(slot), Vec::<String>::new());
    leg.assert_drained();
}

/// RFC 3261 §9.1: "If no provisional response has been received, the CANCEL
/// request MUST NOT be sent; rather, the client MUST wait for the arrival of a
/// provisional response before sending the request." The INVITE retransmits
/// meanwhile, and its first provisional draws the CANCEL.
#[tokio::test(flavor = "multi_thread")]
async fn terminating_a_leg_that_has_drawn_nothing_cancels_it_on_its_first_provisional() {
    let leg = PlacedLeg::place("terminate_silent_leg", "198.51.100.62:5060", true);
    let branch = branch_of(leg.invite());

    assert!(leg.terminate());
    assert_eq!(leg.ends().len(), 1, "the call is over for the script now");
    let sent = until_invite_retransmitted(&leg.dispatcher, leg.phone, &branch).await;
    assert_no_cancel(&sent, leg.phone);
    assert!(requests_to(&sent, socket(leg.phone), Method::Bye).is_empty());
    assert_eq!(leg.state().call_actors.deferred_cancel_count(), 1);

    leg.phone_says(leg.invite(), 180, "Ringing", None);
    let sent = drain(&leg.dispatcher.udp);
    let cancel = the_cancel(&sent, leg.phone, leg.invite());
    assert!(requests_to(&sent, socket(leg.phone), Method::Bye).is_empty());
    assert_eq!(leg.state().call_actors.deferred_cancel_count(), 0);

    leg.phone_says(&cancel, 200, "OK", None);
    leg.phone_says(leg.invite(), 487, "Request Terminated", None);
    assert_eq!(leg.sent(Method::Ack).len(), 1);
    leg.assert_drained();
}

/// A phone that never says anything is never sent a CANCEL: the INVITE runs
/// out at Timer B (RFC 3261 §17.1.1.2) and that is the end of it.
#[tokio::test(flavor = "multi_thread")]
async fn terminating_a_leg_that_never_responds_lets_its_invite_time_out() {
    let leg = PlacedLeg::place("terminate_dead_leg", "198.51.100.63:5060", true);
    let state = leg.state();
    let branch = branch_of(leg.invite());

    assert!(leg.terminate());
    let sent = until_invite_retransmitted(&leg.dispatcher, leg.phone, &branch).await;
    assert_no_cancel(&sent, leg.phone);
    assert!(requests_to(&sent, socket(leg.phone), Method::Bye).is_empty());

    super::timers::sweep_b2bua_retransmits_at(
        state,
        std::time::Instant::now() + state.b2bua_retransmits.transaction_timeout(),
    );
    let sent = drain(&leg.dispatcher.udp);
    assert_no_cancel(&sent, leg.phone);
    assert!(requests_to(&sent, socket(leg.phone), Method::Bye).is_empty());
    assert_eq!(state.call_actors.deferred_cancel_count(), 0);

    // The transaction is over: a provisional after it draws no CANCEL.
    leg.phone_says(leg.invite(), 180, "Ringing", None);
    assert_no_cancel(&drain(&leg.dispatcher.udp), leg.phone);
    assert_eq!(leg.ends().len(), 1);
    leg.assert_drained();
}

/// The phone answers as the CANCEL reaches it: its 2xx is ACKed and the
/// dialog it confirmed released with a BYE (RFC 3261 §9.1, §13.2.2.4, §15).
#[tokio::test(flavor = "multi_thread")]
async fn a_2xx_that_crosses_the_cancel_is_acked_and_released_with_a_bye() {
    let slot = "terminate_crossing_answer";
    let leg = PlacedLeg::place(slot, "198.51.100.64:5060", true);
    leg.phone_says(leg.invite(), 180, "Ringing", None);
    assert!(leg.terminate());
    let cancel = the_cancel(&drain(&leg.dispatcher.udp), leg.phone, leg.invite());

    leg.phone_says(leg.invite(), 200, "OK", Some(OFFER));
    let sent = drain(&leg.dispatcher.udp);
    let position = |method: Method| {
        sent.iter()
            .position(|frame| frame.destination == socket(leg.phone) && frame.is(method.clone()))
    };
    let (ack, bye) = (position(Method::Ack), position(Method::Bye));
    assert!(ack.is_some() && bye.is_some(), "an ACK and a BYE: {sent:?}");
    assert!(ack < bye, "the ACK first");
    assert_eq!(sent.len(), 2, "and nothing else: {sent:?}");
    let bye = sent[bye.expect("a BYE")].message.clone();
    assert_eq!(header(&bye, "Call-ID"), header(leg.invite(), "Call-ID"));
    assert!(
        header(&bye, "To").is_some_and(|to| to.contains(PHONE_TAG)),
        "the BYE is in the dialog the 2xx confirmed"
    );

    // The 2xx retransmitted is ACKed again and not released a second time.
    leg.phone_says(leg.invite(), 200, "OK", Some(OFFER));
    let sent = drain(&leg.dispatcher.udp);
    assert_eq!(requests_to(&sent, socket(leg.phone), Method::Ack).len(), 1);
    assert!(requests_to(&sent, socket(leg.phone), Method::Bye).is_empty());

    leg.phone_says(&cancel, 200, "OK", None);
    leg.phone_says(&bye, 200, "OK", None);
    assert_eq!(leg.ends().len(), 1, "the call ended once, when given up on");
    assert_eq!(
        noted(slot),
        Vec::<String>::new(),
        "a call given up on is never answered for the script"
    );
    leg.assert_drained();
}

/// A leg whose INVITE has its 2xx is a confirmed dialog, and that is ended
/// with a BYE as it always was (RFC 3261 §15).
#[tokio::test(flavor = "multi_thread")]
async fn terminating_an_answered_leg_sends_a_bye() {
    let slot = "terminate_answered_leg";
    let leg = PlacedLeg::place(slot, "198.51.100.65:5060", true);
    leg.phone_says(leg.invite(), 180, "Ringing", None);
    leg.phone_says(leg.invite(), 200, "OK", Some(OFFER));
    assert_eq!(leg.sent(Method::Ack).len(), 1);
    assert_eq!(noted(slot), ["answer"]);

    assert!(leg.terminate());
    let sent = drain(&leg.dispatcher.udp);
    assert_no_cancel(&sent, leg.phone);
    let byes = requests_to(&sent, socket(leg.phone), Method::Bye);
    assert_eq!(byes.len(), 1);
    assert_eq!(sent.len(), 1, "the BYE and nothing else: {sent:?}");
    assert_eq!(
        header(&byes[0].message, "CSeq").as_deref(),
        Some("2 BYE"),
        "numbered past the INVITE (RFC 3261 §12.2.1.1)"
    );
    assert_eq!(leg.ends().len(), 1);
    assert_eq!(leg.state().call_actors.count(), 0);
}

/// The 2xx and the hangup arrive together, the 2xx first: a call answered by
/// the time it is given up on is not CANCELled, and not dropped with its
/// dialog left up either. The CANCEL path refuses it, and `terminate()` ends
/// the dialog with a BYE.
#[tokio::test(flavor = "multi_thread")]
async fn a_leg_answered_as_it_is_given_up_on_is_left_to_a_bye() {
    let leg = PlacedLeg::place("terminate_just_answered", "198.51.100.68:5060", true);
    leg.phone_says(leg.invite(), 200, "OK", Some(OFFER));
    assert_eq!(leg.sent(Method::Ack).len(), 1);

    // What a hangup that read the call as ringing a moment ago goes on to do.
    assert!(
        !cancel_originated_call(leg.state(), &leg.prepared.sip_call_id, Some("released")),
        "an answered call is not the CANCEL path's to end"
    );
    assert!(drain(&leg.dispatcher.udp).is_empty());
    assert!(leg.ends().is_empty());
    assert_eq!(leg.state().call_actors.count(), 1, "the call is still up");
    assert_eq!(leg.state().call_actors.cancelled_branch_count(), 0);

    assert!(leg.terminate());
    assert_eq!(leg.sent(Method::Bye).len(), 1);
    assert_eq!(leg.ends().len(), 1);
    assert_eq!(leg.state().call_actors.count(), 0);
}

/// The 2xx and the hangup arrive together, the hangup first: the 2xx finds
/// the call given up on, while it is still in the store, and answers it for
/// nobody. It is ACKed and its dialog released with a BYE (RFC 3261 §9.1,
/// §15), and `@b2bua.on_answer` does not run.
#[tokio::test(flavor = "multi_thread")]
async fn a_2xx_taken_while_the_leg_is_being_given_up_on_is_released() {
    let slot = "terminate_answer_in_flight";
    let leg = PlacedLeg::place(slot, "198.51.100.69:5060", true);
    leg.phone_says(leg.invite(), 180, "Ringing", None);
    // The hangup has claimed the call and not yet removed it.
    let kept = leg
        .state()
        .call_actors
        .give_up_on_pending(&leg.prepared.internal_call_id)
        .expect("the call is given up on");
    assert_eq!(kept.len(), 1);

    leg.phone_says(leg.invite(), 200, "OK", Some(OFFER));
    let sent = drain(&leg.dispatcher.udp);
    assert_eq!(requests_to(&sent, socket(leg.phone), Method::Ack).len(), 1);
    assert_eq!(requests_to(&sent, socket(leg.phone), Method::Bye).len(), 1);
    assert_eq!(noted(slot), Vec::<String>::new(), "answered for nobody");
    assert_ne!(
        leg.state()
            .call_actors
            .get_call(&leg.prepared.internal_call_id)
            .map(|call| call.state.clone()),
        Some(CallState::Answered)
    );

    // Its retransmission is ACKed again and released no second time.
    leg.phone_says(leg.invite(), 200, "OK", Some(OFFER));
    let sent = drain(&leg.dispatcher.udp);
    assert_eq!(requests_to(&sent, socket(leg.phone), Method::Ack).len(), 1);
    assert!(requests_to(&sent, socket(leg.phone), Method::Bye).is_empty());
}

/// A rejection and the hangup arrive together, the hangup first: the
/// rejection is ACKed (RFC 3261 §17.1.1.3) and concludes nothing, so the call
/// ends once and `@b2bua.on_failure` does not run for a leg the script ended.
#[tokio::test(flavor = "multi_thread")]
async fn a_rejection_taken_while_the_leg_is_being_given_up_on_is_only_acked() {
    let slot = "terminate_rejection_in_flight";
    let leg = PlacedLeg::place(slot, "198.51.100.70:5060", true);
    leg.phone_says(leg.invite(), 180, "Ringing", None);
    assert!(leg
        .state()
        .call_actors
        .give_up_on_pending(&leg.prepared.internal_call_id)
        .is_some());
    // A second hangup, or the ring timeout, finds the call spoken for.
    assert!(!leg.terminate());

    leg.phone_says(leg.invite(), 486, "Busy Here", None);
    let sent = drain(&leg.dispatcher.udp);
    assert_eq!(sent.len(), 1, "the ACK and nothing else: {sent:?}");
    assert!(sent[0].is(Method::Ack));
    assert_eq!(noted(slot), Vec::<String>::new());
    assert!(leg.ends().is_empty(), "the hangup reports the end, once");
    assert_eq!(leg.state().call_actors.count(), 1, "the hangup removes it");
}

/// A leg a controller placed is ended the same way when the controller is
/// lost while it rings: the loss policy ends the call by its Call-ID, and an
/// INVITE with no final response is CANCELled. The controller's channel is
/// told the `487` that ends a CANCELled INVITE.
#[tokio::test(flavor = "multi_thread")]
async fn a_ringing_leg_a_controller_placed_is_cancelled_when_ended_by_call_id() {
    let leg = PlacedLeg::place("terminate_controlled_leg", "198.51.100.66:5060", false);
    leg.phone_says(leg.invite(), 183, "Session Progress", None);
    let _ = drain(&leg.dispatcher.udp);
    let _ = leg.ends();

    assert!(terminate_call(
        leg.state(),
        &leg.prepared.sip_call_id,
        Some("control plane owner lost")
    ));
    let sent = drain(&leg.dispatcher.udp);
    assert!(requests_to(&sent, socket(leg.phone), Method::Bye).is_empty());
    let cancel = the_cancel(&sent, leg.phone, leg.invite());

    let ended = channel_event_capture::take(&leg.prepared.sip_call_id);
    assert_eq!(ended.len(), 1, "{ended:?}");
    assert_eq!(ended[0].0, "StasisEnd");
    assert_eq!(ended[0].1["reason"], "control plane owner lost");

    leg.phone_says(&cancel, 200, "OK", None);
    leg.phone_says(leg.invite(), 487, "Request Terminated", None);
    assert_eq!(leg.sent(Method::Ack).len(), 1);
    leg.assert_drained();
}

/// Emit the INVITE of a leg siphon placed, the CANCEL that ends it while it
/// rings and the ACK to the `487`, as hex for
/// `scripts/validate_originated_terminate_cancel.sh` to feed to tshark.
///
/// The tests above read the CANCEL back with siphon's own parser, which shares
/// whatever siphon's serializer gets wrong. Wireshark's SIP dissector does
/// not, so these are the octets as they leave, not a message parsed and
/// written again.
#[tokio::test(flavor = "multi_thread")]
async fn emit_terminate_cancel_for_external_dissection() {
    let Ok(path) = std::env::var("SIPHON_ORIGINATED_TERMINATE_CANCEL_HEX_OUT") else {
        // Nothing to do in an ordinary test run.
        return;
    };
    let leg = PlacedLeg::dial("terminate_dissected_leg", "198.51.100.67:5060", true);
    let mut frames = leg.octets_sent();
    leg.phone_says(leg.invite(), 180, "Ringing", None);
    assert!(leg.terminate());
    frames.extend(leg.octets_sent());
    leg.phone_says(leg.invite(), 487, "Request Terminated", None);
    frames.extend(leg.octets_sent());
    assert_eq!(frames.len(), 3, "an INVITE, its CANCEL and the ACK");

    // `text2pcap`'s form: an offset, then the octets; offset zero starts the
    // next packet.
    let mut dump = String::new();
    for frame in &frames {
        for (line, chunk) in frame.chunks(16).enumerate() {
            dump.push_str(&format!("{:06x}", line * 16));
            for octet in chunk {
                dump.push_str(&format!(" {octet:02x}"));
            }
            dump.push('\n');
        }
    }
    std::fs::write(&path, dump).expect("hex dump must be writable");
}
