//! `DialogStateChanged` through a transfer and a `Replaces` takeover.
//!
//! A B2BUA call between two registered phones, then: a siphon-terminated REFER
//! (siphon dials the target and re-bridges the survivor), a transparent REFER
//! and a siphon-originated REFER (the referred phone places the new call
//! itself, through siphon), and an INVITE with `Replaces` taking over one side.
//! Every phone's full state sequence is asserted, with the Call-ID and tags
//! checked against the messages read off the UDP egress.

use super::dialog_state_events_tests::{
    dialog_events, header, inbound, register, script, states, tag_of, text, wire, Sent,
};
use super::lcr_ring_timeout_tests::top_via_branch;
use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::*;

fn sdp(address: &str) -> String {
    format!(
        concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 {address}\r\n",
            "s=-\r\n",
            "c=IN IP4 {address}\r\n",
            "t=0 0\r\n",
            "m=audio 40000 RTP/AVP 0\r\n",
            "a=rtpmap:0 PCMU/8000\r\n",
        ),
        address = address,
    )
}

pub(super) fn host_of(address: &str) -> &str {
    address.split(':').next().unwrap_or(address)
}

/// A phone at `source` sends an INVITE for `to`, with an offer and `extra`
/// headers.
fn invite(source: &str, call_id: &str, from: &str, to: &str, extra: &str) -> String {
    let body = sdp(host_of(source));
    format!(
        concat!(
            "INVITE {to} SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {source};branch=z9hG4bK-{call_id}\r\n",
            "Max-Forwards: 70\r\n",
            "From: {from}\r\n",
            "To: <{to}>\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:phone@{source}>\r\n",
            "{extra}",
            "Content-Type: application/sdp\r\n",
            "Content-Length: {length}\r\n",
            "\r\n",
            "{body}",
        ),
        to = to,
        source = source,
        call_id = call_id,
        from = from,
        extra = extra,
        length = body.len(),
        body = body,
    )
}

/// The phone at `address` answers `invite` 200 with an answer, tagged `to_tag`.
pub(super) fn answer(invite: &SipMessage, address: &str, to_tag: &str) -> SipMessage {
    let body = sdp(host_of(address));
    let mut raw = String::from("SIP/2.0 200 OK\r\n");
    for via in invite.headers.get_all("Via").cloned().unwrap_or_default() {
        raw.push_str(&format!("Via: {via}\r\n"));
    }
    raw.push_str(&format!("From: {}\r\n", header(invite, "From")));
    raw.push_str(&format!("To: {};tag={to_tag}\r\n", header(invite, "To")));
    raw.push_str(&format!("Call-ID: {}\r\n", header(invite, "Call-ID")));
    raw.push_str(&format!("CSeq: {}\r\n", header(invite, "CSeq")));
    raw.push_str(&format!("Contact: <sip:phone@{address}>\r\n"));
    raw.push_str("Content-Type: application/sdp\r\n");
    raw.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
    parse_sip_message_bytes(raw.as_bytes()).expect("the answer parses")
}

pub(super) fn respond(
    dispatcher: &TestDispatcher,
    call_id: &str,
    address: &str,
    invite: &SipMessage,
    mut response: SipMessage,
) {
    let status_code = response.status_code().expect("a response");
    let handled = tokio::task::block_in_place(|| {
        handle_b2bua_response(
            call_id,
            &top_via_branch(invite),
            &mut response,
            status_code,
            address.parse().expect("a literal address"),
            &dispatcher.state,
        )
    });
    assert!(handled, "the call was gone when the {status_code} arrived");
}

fn place(dispatcher: &TestDispatcher, source: &str, raw: &str) {
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("the INVITE parses");
    tokio::task::block_in_place(|| {
        handle_b2bua_invite(inbound(source, raw), message, &dispatcher.state)
    });
}

fn internal(dispatcher: &TestDispatcher, sip_call_id: &str) -> String {
    dispatcher
        .state
        .call_actors
        .find_by_sip_call_id(sip_call_id)
        .expect("the call exists")
}

pub(super) fn sent_invite_to(sent: &[Sent], address: &str) -> SipMessage {
    sent.iter()
        .find(|sent| sent.destination == address && sent.message.method() == Some(&Method::Invite))
        .map(|sent| sent.message.clone())
        .unwrap_or_else(|| panic!("no INVITE to {address}"))
}

pub(super) fn sent_to(sent: &[Sent], address: &str, method: Method) -> Option<SipMessage> {
    sent.iter()
        .find(|sent| sent.destination == address && sent.message.method() == Some(&method))
        .map(|sent| sent.message.clone())
}

fn response_to_phone(sent: &[Sent], address: &str, status_code: u16) -> SipMessage {
    sent.iter()
        .find(|sent| sent.destination == address && sent.message.status_code() == Some(status_code))
        .map(|sent| sent.message.clone())
        .unwrap_or_else(|| panic!("no {status_code} to {address}"))
}

/// A request from `source` in a dialog, handed to [`handle_b2bua_bye`] or
/// [`handle_b2bua_refer`] the way the dispatcher's B2BUA gate hands it over.
pub(super) fn in_dialog(
    method: &str,
    source: &str,
    from: &str,
    to: &str,
    call_id: &str,
    cseq: u32,
    extra: &str,
) -> (String, SipMessage) {
    let raw = format!(
        concat!(
            "{method} sip:192.0.2.1:5060 SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {source};branch=z9hG4bK-{method}-{cseq}-{tag}\r\n",
            "Max-Forwards: 70\r\n",
            "From: {from}\r\n",
            "To: {to}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: {cseq} {method}\r\n",
            "Contact: <sip:phone@{source}>\r\n",
            "{extra}",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        method = method,
        source = source,
        from = from,
        to = to,
        call_id = call_id,
        cseq = cseq,
        tag = call_id.replace(['@', '.'], "-"),
        extra = extra,
    );
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("the request parses");
    (raw, message)
}

pub(super) fn hang_up(
    dispatcher: &TestDispatcher,
    source: &str,
    from: &str,
    to: &str,
    call_id: &str,
) {
    let (raw, message) = in_dialog("BYE", source, from, to, call_id, 9, "");
    tokio::task::block_in_place(|| {
        handle_b2bua_bye(inbound(source, &raw), message, &dispatcher.state)
    });
}

/// Registered phones A, B and C, and a call A → B through the B2BUA,
/// answered.
pub(super) struct Established {
    pub(super) dispatcher: TestDispatcher,
    pub(super) a: (&'static str, &'static str),
    pub(super) b: (&'static str, &'static str),
    pub(super) c: (&'static str, &'static str),
    /// The caller's Call-ID.
    pub(super) a_call_id: String,
    /// The INVITE siphon sent B.
    pub(super) to_b: SipMessage,
    /// The 200 siphon relayed to A.
    pub(super) answer_to_a: SipMessage,
}

pub(super) fn establish(prefix: u32, refer_mode: &str) -> Established {
    let aor =
        |n: u32| -> &'static str { Box::leak(format!("sip:{n}@example.com").into_boxed_str()) };
    let a = (
        aor(prefix + 1),
        Box::leak(format!("192.0.2.{}:5060", 120 + prefix % 50).into_boxed_str()) as &str,
    );
    let b = (
        aor(prefix + 2),
        Box::leak(format!("198.51.100.{}:5060", 120 + prefix % 50).into_boxed_str()) as &str,
    );
    let c = (
        aor(prefix + 3),
        Box::leak(format!("198.51.100.{}:5070", 120 + prefix % 50).into_boxed_str()) as &str,
    );
    for (aor, address) in [a, b, c] {
        register(aor, address);
    }
    let routing = format!(
        concat!(
            "call.dial(str(call.ruri))\n",
            "\n",
            "@b2bua.on_refer\n",
            "def on_refer(call):\n",
            "    call.accept_refer(mode=\"{mode}\")",
        ),
        mode = refer_mode,
    );
    let mut dispatcher = test_dispatcher_with_script(&script(&routing));
    dispatcher.state.accept_replaces = true;
    let user = |aor: &str| {
        aor.trim_start_matches("sip:")
            .split('@')
            .next()
            .unwrap_or_default()
            .to_string()
    };
    let a_call_id = format!("transfer-{prefix}@{}", host_of(a.1));
    place(
        &dispatcher,
        a.1,
        &invite(
            a.1,
            &a_call_id,
            &format!("<{}>;tag=a-tag", a.0),
            &format!("sip:{}@{}", user(b.0), b.1),
            "",
        ),
    );
    let Some(call_id) = dispatcher.state.call_actors.find_by_sip_call_id(&a_call_id) else {
        let sent = wire(&dispatcher);
        panic!(
            "no call: {:?}",
            sent.iter()
                .map(|sent| format!(
                    "{} {}",
                    sent.destination,
                    String::from_utf8_lossy(&sent.message.to_bytes())
                ))
                .collect::<Vec<_>>()
        );
    };
    let to_b = sent_invite_to(&wire(&dispatcher), b.1);
    respond(
        &dispatcher,
        &call_id,
        b.1,
        &to_b,
        answer(&to_b, b.1, "b-tag"),
    );
    let answer_to_a = response_to_phone(&wire(&dispatcher), a.1, 200);
    assert_eq!(states(&dialog_events(a.0)), ["proceeding", "confirmed"]);
    assert_eq!(states(&dialog_events(b.0)), ["trying", "confirmed"]);
    Established {
        dispatcher,
        a,
        b,
        c,
        a_call_id,
        to_b,
        answer_to_a,
    }
}

impl Established {
    pub(super) fn call_id(&self) -> String {
        internal(&self.dispatcher, &self.a_call_id)
    }

    fn user(aor: &str) -> String {
        aor.trim_start_matches("sip:")
            .split('@')
            .next()
            .unwrap_or_default()
            .to_string()
    }

    pub(super) fn c_uri(&self) -> String {
        format!("sip:{}@{}", Self::user(self.c.0), self.c.1)
    }

    /// B sends a REFER to C in its dialog with siphon.
    fn b_refers_to_c(&self) {
        let (raw, message) = in_dialog(
            "REFER",
            self.b.1,
            &format!("{};tag=b-tag", header(&self.to_b, "To")),
            &header(&self.to_b, "From"),
            &header(&self.to_b, "Call-ID"),
            2,
            &format!("Refer-To: <{}>\r\n", self.c_uri()),
        );
        tokio::task::block_in_place(|| {
            handle_b2bua_refer(inbound(self.b.1, &raw), message, &self.dispatcher.state)
        });
    }

    /// A places its own new call to C through siphon (what a transparent or a
    /// siphon-originated REFER asks it to do), C answers, and A hangs up on B.
    fn a_calls_c_then_leaves_b(&self) {
        let new_call_id = format!("{}-to-c", self.a_call_id);
        place(
            &self.dispatcher,
            self.a.1,
            &invite(
                self.a.1,
                &new_call_id,
                &format!("<{}>;tag=a-new-tag", self.a.0),
                &self.c_uri(),
                "",
            ),
        );
        let to_c = sent_invite_to(&wire(&self.dispatcher), self.c.1);
        let a_new = dialog_events(self.a.0);
        assert_eq!(states(&a_new), ["proceeding"]);
        assert_eq!(
            text(&a_new[0], "call_id"),
            new_call_id,
            "a second dialog of A's"
        );
        let c_trying = dialog_events(self.c.0);
        assert_eq!(states(&c_trying), ["trying"]);
        assert_eq!(text(&c_trying[0], "call_id"), header(&to_c, "Call-ID"));
        let new_call = internal(&self.dispatcher, &new_call_id);
        respond(
            &self.dispatcher,
            &new_call,
            self.c.1,
            &to_c,
            answer(&to_c, self.c.1, "c-tag"),
        );
        assert_eq!(states(&dialog_events(self.a.0)), ["confirmed"]);
        let c_confirmed = dialog_events(self.c.0);
        assert_eq!(states(&c_confirmed), ["confirmed"]);
        assert_eq!(text(&c_confirmed[0], "local_tag"), "c-tag");

        // A leaves the original call.
        hang_up(
            &self.dispatcher,
            self.a.1,
            "<sip:x@example.com>;tag=a-tag",
            &header(&self.answer_to_a, "To"),
            &self.a_call_id,
        );
        let a_ended = dialog_events(self.a.0);
        assert_eq!(states(&a_ended), ["terminated"]);
        assert_eq!(
            text(&a_ended[0], "call_id"),
            self.a_call_id,
            "the original dialog, not the new one"
        );
        assert_eq!(states(&dialog_events(self.b.0)), ["terminated"]);
        assert!(dialog_events(self.c.0).is_empty(), "the new call goes on");
    }
}

/// Siphon-terminated REFER: B transfers A to C. siphon dials C (a recipient
/// dialog of C's), and when C answers, B's dialog ends while A's stays
/// confirmed, now with C; the call's teardown ends A's and C's.
#[tokio::test(flavor = "multi_thread")]
async fn a_terminated_transfer_reports_the_target_and_ends_the_referrer() {
    let call = establish(5100, "terminate");
    call.b_refers_to_c();
    let sent = wire(&call.dispatcher);
    assert!(
        sent.iter()
            .any(|sent| sent.destination == call.b.1 && sent.message.status_code() == Some(202)),
        "the REFER was accepted"
    );
    let to_c = sent_invite_to(&sent, call.c.1);
    let c_trying = dialog_events(call.c.0);
    assert_eq!(states(&c_trying), ["trying"]);
    assert_eq!(text(&c_trying[0], "direction"), "recipient");
    assert_eq!(text(&c_trying[0], "call_id"), header(&to_c, "Call-ID"));
    assert_eq!(
        text(&c_trying[0], "remote_tag"),
        tag_of(&header(&to_c, "From"))
    );
    assert!(
        dialog_events(call.b.0).is_empty(),
        "B is still in the call while C rings"
    );

    respond(
        &call.dispatcher,
        &call.call_id(),
        call.c.1,
        &to_c,
        answer(&to_c, call.c.1, "c-tag"),
    );
    let c_confirmed = dialog_events(call.c.0);
    assert_eq!(states(&c_confirmed), ["confirmed"]);
    assert_eq!(text(&c_confirmed[0], "local_tag"), "c-tag");
    let b_ended = dialog_events(call.b.0);
    assert_eq!(states(&b_ended), ["terminated"]);
    assert_eq!(text(&b_ended[0], "call_id"), header(&call.to_b, "Call-ID"));
    assert!(
        dialog_events(call.a.0).is_empty(),
        "A stays in the call, now with C"
    );

    hang_up(
        &call.dispatcher,
        call.a.1,
        "<sip:x@example.com>;tag=a-tag",
        &header(&call.answer_to_a, "To"),
        &call.a_call_id,
    );
    assert_eq!(states(&dialog_events(call.a.0)), ["terminated"]);
    assert_eq!(states(&dialog_events(call.c.0)), ["terminated"]);
    assert_eq!(call.dispatcher.state.call_actors.count(), 0);
}

/// Transparent REFER: siphon relays B's REFER to A, and A calls C itself.
#[tokio::test(flavor = "multi_thread")]
async fn a_transparent_transfer_reports_the_new_call_and_ends_the_old() {
    let call = establish(5200, "transparent");
    call.b_refers_to_c();
    let refer = sent_to(&wire(&call.dispatcher), call.a.1, Method::Refer)
        .expect("the REFER was relayed to A");
    assert!(header(&refer, "Refer-To").contains(&call.c_uri()));
    assert!(dialog_events(call.b.0).is_empty());
    call.a_calls_c_then_leaves_b();
}

/// A siphon-originated REFER: siphon asks A to call C, and A does.
#[tokio::test(flavor = "multi_thread")]
async fn a_siphon_originated_transfer_reports_the_new_call_and_ends_the_old() {
    let call = establish(5300, "terminate");
    let refer_to = crate::sip::headers::refer::parse_refer_to(&format!("<{}>", call.c_uri()))
        .expect("a Refer-To");
    assert!(tokio::task::block_in_place(|| b2bua_send_outbound_refer(
        &call.dispatcher.state,
        &call.call_id(),
        true,
        &refer_to
    )));
    let refer =
        sent_to(&wire(&call.dispatcher), call.a.1, Method::Refer).expect("siphon sent A a REFER");
    assert!(header(&refer, "Refer-To").contains(&call.c_uri()));
    call.a_calls_c_then_leaves_b();
}

/// An INVITE with `Replaces` from registered phone D takes B's side of the
/// call: D's dialog is reported confirmed (it placed that INVITE), B's ends,
/// A's goes on, and the call's teardown ends A's and D's.
#[tokio::test(flavor = "multi_thread")]
async fn a_replaces_takeover_reports_the_new_party_and_ends_the_replaced() {
    let call = establish(5400, "terminate");
    let (d_aor, d) = ("sip:5404@example.com", "192.0.2.199:5060");
    register(d_aor, d);
    let siphon_tag = tag_of(&header(&call.to_b, "From"));
    let d_call_id = "takeover@192.0.2.199";
    place(
        &call.dispatcher,
        d,
        &invite(
            d,
            d_call_id,
            &format!("<{d_aor}>;tag=d-tag"),
            "sip:5400@siphon.example.com",
            &format!(
                "Replaces: {};to-tag={siphon_tag};from-tag=b-tag\r\n",
                header(&call.to_b, "Call-ID")
            ),
        ),
    );
    let sent = wire(&call.dispatcher);
    let to_d = response_to_phone(&sent, d, 200);
    assert!(
        sent_to(&sent, call.b.1, Method::Bye).is_some(),
        "the replaced party was BYEd"
    );
    let d_events = dialog_events(d_aor);
    assert_eq!(states(&d_events), ["confirmed"], "{d_events:?}");
    assert_eq!(text(&d_events[0], "direction"), "initiator");
    assert_eq!(text(&d_events[0], "call_id"), d_call_id);
    assert_eq!(text(&d_events[0], "local_tag"), "d-tag");
    assert_eq!(
        text(&d_events[0], "remote_tag"),
        tag_of(&header(&to_d, "To"))
    );
    assert_eq!(states(&dialog_events(call.b.0)), ["terminated"]);
    assert!(dialog_events(call.a.0).is_empty(), "A stays, now with D");

    hang_up(
        &call.dispatcher,
        d,
        &format!("<{d_aor}>;tag=d-tag"),
        &header(&to_d, "To"),
        d_call_id,
    );
    assert_eq!(states(&dialog_events(call.a.0)), ["terminated"]);
    assert_eq!(states(&dialog_events(d_aor)), ["terminated"]);
    assert!(dialog_events(call.c.0).is_empty());
    assert_eq!(call.dispatcher.state.call_actors.count(), 0);
}

/// A control plane of the test's own, with one connected application.
pub(super) fn control_plane(
    app: &str,
) -> (
    Arc<crate::control::ControlBus>,
    Arc<crate::control::ConnHandle>,
) {
    let (command_tx, _command_rx) = flume::unbounded();
    let bus = crate::control::ControlBus::new(
        command_tx,
        vec![crate::config::ControlAppConfig {
            name: app.to_string(),
            token: "token".to_string(),
            per_call_connect: false,
            connect_url: None,
            on_lost: None,
            ca_file: None,
            events: Vec::new(),
        }],
        64,
        crate::control::SlowConsumerPolicy::DropOldest,
        10,
        3000,
    );
    let connection = bus.register_connection(app);
    (bus, connection)
}

/// The events queued for a connection, once its stream has been quiet for a
/// moment.
async fn queued(connection: &crate::control::ConnHandle) -> Vec<crate::control::EventFrame> {
    let mut events = Vec::new();
    while let Ok(frames) = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        connection.events.recv_many(),
    )
    .await
    {
        events.extend(frames.into_iter().filter_map(|frame| match frame {
            crate::control::OutboundFrame::Event(event) => Some(event),
            crate::control::OutboundFrame::Reply(_) => None,
        }));
    }
    events
}

pub(super) fn parsed_refer_to(message: &SipMessage) -> crate::sip::headers::refer::ReferTo {
    crate::sip::headers::refer::parse_refer_to(&header(message, "Refer-To"))
        .expect("the Refer-To parses")
}

/// The callee of a controlled call — a party on a dialog of its own, with a
/// Call-ID siphon generated — sends a REFER. The channel is bound to the
/// caller's Call-ID, so the REFER is resolved through the call: it is held
/// under the channel's Call-ID, where `accept_refer` / `reject_refer` look, and
/// the application hears `TransferRequested` naming the B-leg as the referrer.
#[tokio::test(flavor = "multi_thread")]
async fn a_refer_from_the_callee_of_a_controlled_call_reaches_its_application() {
    let call = establish(8700, "terminate");
    let state = &call.dispatcher.state;
    let (bus, connection) = control_plane("transfer-8700");
    bus.register_channel(
        "channel-8700",
        &connection,
        &call.call_id(),
        &call.a_call_id,
        "hangup",
        std::collections::HashMap::new(),
    );
    let b_call_id = header(&call.to_b, "Call-ID");
    assert_ne!(
        b_call_id, call.a_call_id,
        "the callee has a dialog of its own"
    );
    let internal_call_id = call.call_id();
    let referrer = Referrer {
        call_id: &internal_call_id,
        from_a_leg: false,
        from_tag: Some("b-tag"),
    };
    let refer = || {
        in_dialog(
            "REFER",
            call.b.1,
            &format!("{};tag=b-tag", header(&call.to_b, "To")),
            &header(&call.to_b, "From"),
            &b_call_id,
            2,
            &format!("Refer-To: <{}>\r\n", call.c_uri()),
        )
    };
    let _ = wire(&call.dispatcher);

    let (raw, message) = refer();
    let refer_to = parsed_refer_to(&message);
    let taken = hold_controlled_refer(
        &bus,
        inbound(call.b.1, &raw),
        message,
        &refer_to,
        &referrer,
        state,
    );
    assert!(taken.is_none(), "a controlled call's REFER is held");
    assert!(
        wire(&call.dispatcher).is_empty(),
        "nothing is answered until the application decides"
    );

    let events = queued(&connection).await;
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].event, "TransferRequested");
    assert_eq!(events[0].channel.as_deref(), Some("channel-8700"));
    assert_eq!(events[0].payload["refer_to"], call.c_uri());
    assert_eq!(events[0].payload["referrer_leg"], "b");
    assert_eq!(events[0].payload["referrer_sip_call_id"], b_call_id);
    assert_eq!(events[0].payload["from_tag"], "b-tag");

    // A retransmission of that REFER is absorbed: no second event.
    let (raw, message) = refer();
    assert!(hold_controlled_refer(
        &bus,
        inbound(call.b.1, &raw),
        message,
        &refer_to,
        &referrer,
        state
    )
    .is_none());
    assert!(
        queued(&connection).await.is_empty(),
        "a retransmit is not reported"
    );
    assert!(wire(&call.dispatcher).is_empty());

    // The caller sends a REFER of its own while the first is undecided: it is
    // answered 491, never dropped, and the first is still the one held.
    let (raw, message) = in_dialog(
        "REFER",
        call.a.1,
        &format!("<{}>;tag=a-tag", call.a.0),
        &header(&call.answer_to_a, "To"),
        &call.a_call_id,
        2,
        &format!("Refer-To: <{}>\r\n", call.c_uri()),
    );
    let from_caller = Referrer {
        call_id: &internal_call_id,
        from_a_leg: true,
        from_tag: Some("a-tag"),
    };
    assert!(hold_controlled_refer(
        &bus,
        inbound(call.a.1, &raw),
        message,
        &refer_to,
        &from_caller,
        state
    )
    .is_none());
    let sent = wire(&call.dispatcher);
    assert_eq!(sent.len(), 1, "exactly the 491");
    assert_eq!(sent[0].destination, call.a.1);
    assert_eq!(sent[0].message.status_code(), Some(491));
    assert_eq!(header(&sent[0].message, "Call-ID"), call.a_call_id);
    assert!(queued(&connection).await.is_empty());

    // Held under the channel's Call-ID, which is the key the verbs present, and
    // it is the callee's REFER that is held.
    assert_eq!(state.pending_inbound_refer.len(), 1);
    let pending = state
        .pending_inbound_refer
        .take(&call.a_call_id)
        .expect("held under the channel's Call-ID");
    assert!(!pending.from_a_leg);
    assert_eq!(header(&pending.message, "Call-ID"), b_call_id);
    assert_eq!(state.pending_inbound_refer.len(), 0, "drained");
}

/// A call no application controls is not held: the REFER is handed back for the
/// script rail, untouched.
#[tokio::test(flavor = "multi_thread")]
async fn a_refer_on_an_uncontrolled_call_is_handed_back() {
    let call = establish(8750, "terminate");
    let (bus, connection) = control_plane("transfer-8750");
    let internal_call_id = call.call_id();
    let (raw, message) = in_dialog(
        "REFER",
        call.b.1,
        &format!("{};tag=b-tag", header(&call.to_b, "To")),
        &header(&call.to_b, "From"),
        &header(&call.to_b, "Call-ID"),
        2,
        &format!("Refer-To: <{}>\r\n", call.c_uri()),
    );
    let refer_to = parsed_refer_to(&message);
    let handed_back = hold_controlled_refer(
        &bus,
        inbound(call.b.1, &raw),
        message,
        &refer_to,
        &Referrer {
            call_id: &internal_call_id,
            from_a_leg: false,
            from_tag: Some("b-tag"),
        },
        &call.dispatcher.state,
    );
    assert!(handed_back.is_some());
    assert!(queued(&connection).await.is_empty());
    assert_eq!(call.dispatcher.state.pending_inbound_refer.len(), 0);
}

/// A `Replaces` takeover puts the new party in the call's A-leg slot, on a
/// Call-ID of its own, and retires the Call-ID that held it. A control channel
/// bound to the old one is moved to the new, so its verbs still find the call;
/// one already on the current A-leg, or naming a Call-ID no channel holds, is
/// left alone.
#[tokio::test(flavor = "multi_thread")]
async fn a_control_channel_follows_its_call_to_a_new_a_leg() {
    let call = establish(8800, "terminate");
    let state = &call.dispatcher.state;
    let internal_call_id = call.call_id();
    let (bus, connection) = control_plane("transfer-8800");
    bus.register_channel(
        "channel-8800",
        &connection,
        &internal_call_id,
        &call.a_call_id,
        "hangup",
        std::collections::HashMap::new(),
    );
    assert!(
        !channel_follows_a_leg(&bus, state, &internal_call_id, &call.a_call_id),
        "nothing to follow while the A-leg is the one the channel is bound to"
    );

    let (d_aor, d) = ("sip:8804@example.com", "192.0.2.198:5060");
    register(d_aor, d);
    let siphon_tag = tag_of(&header(&call.to_b, "From"));
    let d_call_id = "takeover-8800@192.0.2.198";
    place(
        &call.dispatcher,
        d,
        &invite(
            d,
            d_call_id,
            &format!("<{d_aor}>;tag=d-tag"),
            "sip:8800@siphon.example.com",
            &format!(
                "Replaces: {};to-tag={siphon_tag};from-tag=b-tag\r\n",
                header(&call.to_b, "Call-ID")
            ),
        ),
    );
    let _ = response_to_phone(&wire(&call.dispatcher), d, 200);
    let a_leg_now = state
        .call_actors
        .get_call(&internal_call_id)
        .map(|joined| joined.a_leg.dialog.call_id.clone());
    assert_eq!(
        a_leg_now.as_deref(),
        Some(d_call_id),
        "the newcomer holds the A-leg slot"
    );

    assert!(channel_follows_a_leg(
        &bus,
        state,
        &internal_call_id,
        &call.a_call_id
    ));
    assert_eq!(
        bus.sip_call_id_for_channel("channel-8800").as_deref(),
        Some(d_call_id)
    );
    assert_eq!(
        bus.channel_id_for_sip_call_id(d_call_id).as_deref(),
        Some("channel-8800")
    );
    assert_eq!(bus.channel_id_for_sip_call_id(&call.a_call_id), None);
    assert!(
        !channel_follows_a_leg(&bus, state, &internal_call_id, &call.a_call_id),
        "already moved"
    );
    assert!(
        !channel_follows_a_leg(&bus, state, "no-such-call", &call.a_call_id),
        "a call that is gone has no A-leg to follow"
    );
}

/// A replacement dialled at a registered contact with an identity of its own:
/// the new leg's Request-URI is the contact, it is called as the AoR, and it
/// presents the named `From` (with a dialog tag) and asserted identity instead
/// of the ones the call's own INVITE carried.
#[tokio::test(flavor = "multi_thread")]
async fn a_replacement_leg_is_called_as_its_aor_and_presents_the_named_identity() {
    let call = establish(8900, "terminate");
    let state = &call.dispatcher.state;
    let internal_call_id = call.call_id();
    let _ = wire(&call.dispatcher);
    let (target, dial) = ReplacementDial::to_contact(
        DialTarget {
            uri: call.c_uri(),
            aor: Some(call.c.0.to_string()),
            ..Default::default()
        },
        DialShaping {
            from: Some("sip:+15550100000@trunk.example.com".to_string()),
            from_display: Some("Main Line".to_string()),
            p_asserted_identity: Some("sip:+15550100000@trunk.example.com".to_string()),
            ..Default::default()
        },
        vec![("X-Account".to_string(), "main".to_string())],
    );
    let dialled = tokio::task::block_in_place(|| {
        b2bua_start_leg_replacement(
            &internal_call_id,
            false,
            &target,
            None,
            None,
            None,
            None,
            None,
            0,
            crate::b2bua::transfer::ReplacementOrigin::SiphonInitiated,
            30,
            &dial,
            state,
        )
    });
    assert!(dialled, "the INVITE reached the transport");
    let to_c = sent_invite_to(&wire(&call.dispatcher), call.c.1);
    assert_eq!(header(&to_c, "To"), format!("<{}>", call.c.0));
    match &to_c.start_line {
        StartLine::Request(request) => {
            assert_eq!(request.request_uri.to_string(), call.c_uri(), "the contact")
        }
        StartLine::Response(_) => panic!("an INVITE is a request"),
    }
    let from = header(&to_c, "From");
    assert!(
        from.starts_with("\"Main Line\" <sip:+15550100000@trunk.example.com>;tag="),
        "{from}"
    );
    assert!(!tag_of(&from).is_empty(), "the dialog tag is kept");
    assert_eq!(header(&to_c, "X-Account"), "main");
    let asserted = to_c
        .headers
        .get_all("P-Asserted-Identity")
        .cloned()
        .unwrap_or_default();
    assert_eq!(asserted.len(), 1, "one asserted identity: {asserted:?}");
    assert!(asserted[0].contains("+15550100000@trunk.example.com"));

    // Positive control: with nothing named, a replacement is called as its
    // target URI and presents the call's own caller.
    let other = establish(8950, "terminate");
    let _ = wire(&other.dispatcher);
    let other_call_id = other.call_id();
    assert!(tokio::task::block_in_place(|| {
        b2bua_start_leg_replacement(
            &other_call_id,
            false,
            &other.c_uri(),
            None,
            None,
            None,
            None,
            None,
            0,
            crate::b2bua::transfer::ReplacementOrigin::SiphonInitiated,
            30,
            &ReplacementDial::default(),
            &other.dispatcher.state,
        )
    }));
    let plain = sent_invite_to(&wire(&other.dispatcher), other.c.1);
    assert_eq!(header(&plain, "To"), format!("<{}>", other.c_uri()));
    let plain_from = header(&plain, "From");
    assert!(
        plain_from.contains(&format!("sip:{}@", Established::user(other.a.0))),
        "the caller: {plain_from}"
    );
    assert!(plain.headers.get("X-Account").is_none());
}

/// An attended transfer names the dialog to replace by Call-ID and tags, which
/// a controller never sees. When this node hosts that dialog the event says
/// which call and channel it is and which leg; a dialog hosted elsewhere is
/// reported as the referrer named it, with nothing local to say.
#[tokio::test(flavor = "multi_thread")]
async fn an_attended_refer_names_the_hosted_dialog_it_replaces() {
    let call = establish(9100, "terminate");
    let state = &call.dispatcher.state;
    let internal_call_id = call.call_id();
    let (bus, connection) = control_plane("transfer-9100");
    bus.register_channel(
        "channel-9100",
        &connection,
        &internal_call_id,
        &call.a_call_id,
        "hangup",
        std::collections::HashMap::new(),
    );
    let referrer = Referrer {
        call_id: &internal_call_id,
        from_a_leg: true,
        from_tag: Some("a-tag"),
    };
    let refer = |cseq: u32| {
        in_dialog(
            "REFER",
            call.a.1,
            &format!("<{}>;tag=a-tag", call.a.0),
            &header(&call.answer_to_a, "To"),
            &call.a_call_id,
            cseq,
            &format!("Refer-To: <{}>\r\n", call.c_uri()),
        )
    };

    // The callee's dialog, as the party on it sees it: siphon's tag is its
    // remote tag, its own the local one.
    let hosted = crate::sip::headers::refer::ReferTo {
        uri: call.c_uri(),
        replaces: Some(crate::sip::headers::refer::Replaces {
            call_id: header(&call.to_b, "Call-ID"),
            from_tag: "b-tag".to_string(),
            to_tag: tag_of(&header(&call.to_b, "From")),
            early_only: false,
        }),
    };
    let (raw, message) = refer(2);
    assert!(hold_controlled_refer(
        &bus,
        inbound(call.a.1, &raw),
        message,
        &hosted,
        &referrer,
        state
    )
    .is_none());
    let events = queued(&connection).await;
    assert_eq!(events.len(), 1, "{events:?}");
    let local = &events[0].payload["replaces"]["local"];
    assert_eq!(local["call_actor_id"], internal_call_id);
    assert_eq!(local["channel"], "channel-9100");
    assert_eq!(local["leg"], "b");
    assert!(local["bridged_with"].is_null(), "this call is not a bridge");
    assert!(state.pending_inbound_refer.take(&call.a_call_id).is_some());

    // A dialog this node does not host.
    let foreign = crate::sip::headers::refer::ReferTo {
        uri: call.c_uri(),
        replaces: Some(crate::sip::headers::refer::Replaces {
            call_id: "elsewhere@192.0.2.250".to_string(),
            from_tag: "x".to_string(),
            to_tag: "y".to_string(),
            early_only: true,
        }),
    };
    let (raw, message) = refer(3);
    assert!(hold_controlled_refer(
        &bus,
        inbound(call.a.1, &raw),
        message,
        &foreign,
        &referrer,
        state
    )
    .is_none());
    let events = queued(&connection).await;
    assert_eq!(events.len(), 1, "{events:?}");
    let replaces = &events[0].payload["replaces"];
    assert_eq!(replaces["call_id"], "elsewhere@192.0.2.250");
    assert_eq!(replaces["early_only"], true);
    assert!(replaces["local"].is_null());
    assert!(state.pending_inbound_refer.take(&call.a_call_id).is_some());
}

/// A call whose INVITE carried a `Replaces` naming a hosted dialog tells the
/// application which call, channel and leg it asked to join; a call with no
/// such header says nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_handed_over_call_names_the_hosted_dialog_its_invite_replaces() {
    let call = establish(9200, "terminate");
    let state = &call.dispatcher.state;
    let internal_call_id = call.call_id();
    let (bus, connection) = control_plane("transfer-9200");
    bus.register_channel(
        "channel-9200",
        &connection,
        &internal_call_id,
        &call.a_call_id,
        "hangup",
        std::collections::HashMap::new(),
    );
    assert_eq!(
        pending_replaces_payload(&bus, &internal_call_id, state),
        None
    );

    state.call_actors.set_pending_replaces(
        &internal_call_id,
        crate::b2bua::actor::PendingReplaces {
            replaced_call_id: internal_call_id.clone(),
            replaced_on_a_leg: true,
            early_only: true,
        },
    );
    let replaces =
        pending_replaces_payload(&bus, &internal_call_id, state).expect("a pending Replaces");
    assert_eq!(replaces["call_actor_id"], internal_call_id);
    assert_eq!(replaces["channel"], "channel-9200");
    assert_eq!(replaces["leg"], "a");
    assert_eq!(replaces["early_only"], true);
    assert_eq!(
        state
            .call_actors
            .take_pending_replaces(&internal_call_id)
            .map(|pending| pending.early_only),
        Some(true),
        "reporting it does not consume it"
    );
}
