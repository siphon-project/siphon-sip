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

fn host_of(address: &str) -> &str {
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
fn answer(invite: &SipMessage, address: &str, to_tag: &str) -> SipMessage {
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

fn respond(
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

fn sent_invite_to(sent: &[Sent], address: &str) -> SipMessage {
    sent.iter()
        .find(|sent| sent.destination == address && sent.message.method() == Some(&Method::Invite))
        .map(|sent| sent.message.clone())
        .unwrap_or_else(|| panic!("no INVITE to {address}"))
}

fn sent_to(sent: &[Sent], address: &str, method: Method) -> Option<SipMessage> {
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
fn in_dialog(
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

fn hang_up(dispatcher: &TestDispatcher, source: &str, from: &str, to: &str, call_id: &str) {
    let (raw, message) = in_dialog("BYE", source, from, to, call_id, 9, "");
    tokio::task::block_in_place(|| {
        handle_b2bua_bye(inbound(source, &raw), message, &dispatcher.state)
    });
}

/// Registered phones A, B and C, and a call A → B through the B2BUA,
/// answered.
struct Established {
    dispatcher: TestDispatcher,
    a: (&'static str, &'static str),
    b: (&'static str, &'static str),
    c: (&'static str, &'static str),
    /// The caller's Call-ID.
    a_call_id: String,
    /// The INVITE siphon sent B.
    to_b: SipMessage,
    /// The 200 siphon relayed to A.
    answer_to_a: SipMessage,
}

fn establish(prefix: u32, refer_mode: &str) -> Established {
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
    fn call_id(&self) -> String {
        internal(&self.dispatcher, &self.a_call_id)
    }

    fn user(aor: &str) -> String {
        aor.trim_start_matches("sip:")
            .split('@')
            .next()
            .unwrap_or_default()
            .to_string()
    }

    fn c_uri(&self) -> String {
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
