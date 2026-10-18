//! `call.take_over()`: a script hands a dialog this node hosts to the party
//! whose INVITE named it, the way an SCC AS takes the source access leg over
//! for the INVITE an SRVCC transfer sends with `Target-Dialog` (RFC 4538,
//! TS 24.237 §12.3.5).
//!
//! The script names the dialog by its Call-ID, siphon's own tag on it and the
//! far party's tag on it. These tests read the names from a `Target-Dialog`
//! header, whose tags are written as the recipient sees the dialog (RFC 4538
//! §3), so its `local-tag` is siphon's.
//!
//! Driven through [`handle_b2bua_invite`] and [`handle_b2bua_bye`], with what
//! siphon sent read back off the UDP egress. `b2bua.accept_replaces` is left at
//! its default (off) throughout: the takeover is the script's decision, not a
//! header's.

use super::dialog_state_events_tests::{header, tag_of, wire, Sent};
use super::dialog_state_transfer_tests::{
    establish_running, hang_up, host_of, invite, place, respond, response_to_phone, sent_invite_to,
    sent_to, Established,
};
use super::test_dispatcher::test_dispatcher_with_script;
use super::transfer_ingress_tests::{anchored_on, OPEN};
use super::*;
use crate::rtpengine::test_native_engine::NativeTestEngine;

/// Dials an ordinary INVITE; takes over the dialog an INVITE's `Target-Dialog`
/// names, re-INVITEing the survivor only when the INVITE says `X-Reinvite: yes`.
const TAKE_OVER: &str = concat!(
    "from siphon import b2bua\n",
    "\n",
    "@b2bua.on_invite\n",
    "def on_invite(call):\n",
    "    target = call.get_header(\"Target-Dialog\")\n",
    "    if target is None:\n",
    "        call.dial(str(call.ruri))\n",
    "        return\n",
    "    dialog_call_id, _, rest = target.partition(\";\")\n",
    "    params = dict(p.strip().split(\"=\", 1) for p in rest.split(\";\") if \"=\" in p)\n",
    "    headers = ANSWER_HEADERS.get(call.get_header(\"X-Answer-Headers\"))\n",
    "    call.take_over(\n",
    "        dialog_call_id.strip(),\n",
    "        params[\"local-tag\"],\n",
    "        params[\"remote-tag\"],\n",
    "        reinvite=call.get_header(\"X-Reinvite\") == \"yes\",\n",
    "        headers=headers,\n",
    "    )\n",
    "\n",
    "ANSWER_HEADERS = {\n",
    "    \"scc-as\": {\n",
    "        \"P-Asserted-Identity\": \"<sip:+15550100002@example.com>\",\n",
    "        \"Feature-Caps\": \"*;+g.3gpp.srvcc\",\n",
    "        \"Accept\": \"application/sdp, application/3gpp-ims+xml\",\n",
    "        \"Recv-Info\": \"g.3gpp.state-and-event\",\n",
    "    },\n",
    "    \"owned\": {\"Contact\": \"<sip:elsewhere@example.com>\"},\n",
    "}\n",
);

const NEWCOMER: &str = "192.0.2.240:5060";
const NEWCOMER_FROM: &str = "<sip:newcomer@example.com>;tag=newcomer-tag";

/// Which of the call's two dialogs the newcomer names.
#[derive(Clone, Copy)]
enum Named {
    /// siphon's dialog with the caller, A.
    ALeg,
    /// siphon's dialog with the callee, B.
    BLeg,
}

/// `Target-Dialog` naming one of `call`'s dialogs as siphon, its recipient,
/// sees it (RFC 4538 §3): `local-tag` siphon's tag, `remote-tag` the far
/// party's.
fn target_dialog(call: &Established, named: Named) -> String {
    match named {
        Named::ALeg => format!(
            "Target-Dialog: {};local-tag={};remote-tag=a-tag\r\n",
            call.a_call_id,
            tag_of(&header(&call.answer_to_a, "To"))
        ),
        Named::BLeg => format!(
            "Target-Dialog: {};local-tag={};remote-tag=b-tag\r\n",
            header(&call.to_b, "Call-ID"),
            tag_of(&header(&call.to_b, "From"))
        ),
    }
}

/// The newcomer's INVITE, carrying `extra` headers, as its own Call-ID.
fn newcomer_invite(newcomer_call_id: &str, extra: &str) -> String {
    invite(
        NEWCOMER,
        newcomer_call_id,
        NEWCOMER_FROM,
        "sip:scc-as@siphon.example.com",
        &format!("Require: tdialog\r\n{extra}"),
    )
}

/// The newcomer sends `raw`; everything siphon sent in return.
fn newcomer_sends(call: &Established, raw: &str) -> Vec<Sent> {
    place(&call.dispatcher, NEWCOMER, raw);
    wire(&call.dispatcher)
}

/// The SDP body of `message`, as text.
fn body_of(message: &SipMessage) -> String {
    String::from_utf8_lossy(&message.body).to_string()
}

/// The party that was sent `answer`, a 2xx siphon sent it, ACKs it (RFC 3261
/// §13.2.2.4), the way the dispatcher's ACK path hands a B2BUA ACK over.
fn acks(dispatcher: &super::test_dispatcher::TestDispatcher, answer: &SipMessage) {
    let raw = format!(
        concat!(
            "ACK sip:192.0.2.1:5060 SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.250:5060;branch=z9hG4bK-ack-{tag}\r\n",
            "Max-Forwards: 70\r\n",
            "From: {from}\r\n",
            "To: {to}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 ACK\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        tag = tag_of(&header(answer, "To")),
        from = header(answer, "From"),
        to = header(answer, "To"),
        call_id = header(answer, "Call-ID"),
    );
    let ack = parse_sip_message_bytes(raw.as_bytes()).expect("the ACK parses");
    assert!(
        absorb_b2bua_ack(&header(answer, "Call-ID"), &ack, &dispatcher.state),
        "the ACK matched its dialog"
    );
}

/// A call established under [`TAKE_OVER`], the caller's 200 ACKed, with
/// `accept_replaces` checked off.
fn established(prefix: u32) -> Established {
    let call = establish_running(prefix, TAKE_OVER);
    assert!(
        !call.dispatcher.state.accept_replaces,
        "the takeover must not lean on b2bua.accept_replaces"
    );
    acks(&call.dispatcher, &call.answer_to_a);
    let _ = wire(&call.dispatcher);
    call
}

/// The survivor of a takeover of `named`, as `(address, From, To, Call-ID)` of
/// a request it sends in its own dialog with siphon.
fn survivor_dialog(call: &Established, named: Named) -> (&'static str, String, String, String) {
    match named {
        Named::BLeg => (
            call.a.1,
            format!("<{}>;tag=a-tag", call.a.0),
            header(&call.answer_to_a, "To"),
            call.a_call_id.clone(),
        ),
        Named::ALeg => (
            call.b.1,
            format!("{};tag=b-tag", header(&call.to_b, "To")),
            header(&call.to_b, "From"),
            header(&call.to_b, "Call-ID"),
        ),
    }
}

/// The replaced party's and the survivor's addresses for a takeover of `named`.
fn parties(call: &Established, named: Named) -> (&'static str, &'static str) {
    match named {
        Named::BLeg => (call.b.1, call.a.1),
        Named::ALeg => (call.a.1, call.b.1),
    }
}

/// Take over `named` without re-INVITEing the survivor, and assert the
/// takeover itself: the newcomer is answered with the survivor's own last SDP,
/// the replaced party is BYE'd, and the survivor hears nothing. Returns the
/// 200 the newcomer got.
fn take_over_without_reinvite(
    call: &Established,
    named: Named,
    newcomer_call_id: &str,
) -> SipMessage {
    let (replaced, survivor) = parties(call, named);
    let sent = newcomer_sends(
        call,
        &newcomer_invite(newcomer_call_id, &target_dialog(call, named)),
    );
    let to_newcomer = response_to_phone(&sent, NEWCOMER, 200);
    let answer = body_of(&to_newcomer);
    assert!(
        answer.contains(&format!("c=IN IP4 {}", host_of(survivor))),
        "the newcomer is answered with the survivor's media: {answer}"
    );
    assert!(
        sent_to(&sent, replaced, Method::Bye).is_some(),
        "the replaced party was BYE'd"
    );
    assert!(
        sent_to(&sent, survivor, Method::Invite).is_none(),
        "the survivor is not re-INVITEd"
    );
    acks(&call.dispatcher, &to_newcomer);
    to_newcomer
}

/// TS 24.237 §12.3.5 C b: the remote party is kept on its dialog and not
/// re-INVITEd. Here the newcomer takes the callee's side: A is answered by
/// nobody new, and its later BYE reaches the newcomer.
#[tokio::test(flavor = "multi_thread")]
async fn a_take_over_of_the_callee_dialog_without_reinvite_keeps_the_caller_untouched() {
    let call = established(6100);
    take_over_without_reinvite(&call, Named::BLeg, "takeover-6100@192.0.2.240");

    let (survivor, from, to, sip_call_id) = survivor_dialog(&call, Named::BLeg);
    hang_up(&call.dispatcher, survivor, &from, &to, &sip_call_id);
    let sent = wire(&call.dispatcher);
    let bye =
        sent_to(&sent, NEWCOMER, Method::Bye).expect("the survivor's BYE reached the newcomer");
    assert_eq!(header(&bye, "Call-ID"), "takeover-6100@192.0.2.240");
    assert!(
        sent_to(&sent, call.b.1, Method::Bye).is_none(),
        "B is long gone"
    );
}

/// The same with the caller's dialog named: B survives as the callee of a call
/// whose caller is now the newcomer, and its BYE reaches the newcomer.
#[tokio::test(flavor = "multi_thread")]
async fn a_take_over_of_the_caller_dialog_without_reinvite_keeps_the_callee_untouched() {
    let call = established(6110);
    take_over_without_reinvite(&call, Named::ALeg, "takeover-6110@192.0.2.240");

    let (survivor, from, to, sip_call_id) = survivor_dialog(&call, Named::ALeg);
    hang_up(&call.dispatcher, survivor, &from, &to, &sip_call_id);
    let sent = wire(&call.dispatcher);
    let bye =
        sent_to(&sent, NEWCOMER, Method::Bye).expect("the survivor's BYE reached the newcomer");
    assert_eq!(header(&bye, "Call-ID"), "takeover-6110@192.0.2.240");
    assert!(
        sent_to(&sent, call.a.1, Method::Bye).is_none(),
        "A is long gone"
    );
}

/// The newcomer's own BYE reaches the survivor on the survivor's untouched
/// dialog, whichever leg was taken over, and ends the call.
#[tokio::test(flavor = "multi_thread")]
async fn the_newcomers_bye_reaches_the_survivor_on_its_own_dialog() {
    for (prefix, named) in [(6120, Named::BLeg), (6130, Named::ALeg)] {
        let call = established(prefix);
        let newcomer_call_id = format!("takeover-{prefix}@192.0.2.240");
        let to_newcomer = take_over_without_reinvite(&call, named, &newcomer_call_id);

        hang_up(
            &call.dispatcher,
            NEWCOMER,
            NEWCOMER_FROM,
            &header(&to_newcomer, "To"),
            &newcomer_call_id,
        );
        let (survivor, _, _, survivor_call_id) = survivor_dialog(&call, named);
        let sent = wire(&call.dispatcher);
        let bye =
            sent_to(&sent, survivor, Method::Bye).expect("the newcomer's BYE reached the survivor");
        assert_eq!(header(&bye, "Call-ID"), survivor_call_id);
        assert_eq!(call.dispatcher.state.call_actors.count(), 0);
    }
}

/// TS 24.237 §12.3.5 C a: with `reinvite=True` the survivor is re-INVITEd with
/// the newcomer's offer, exactly as a `Replaces` takeover does.
#[tokio::test(flavor = "multi_thread")]
async fn a_take_over_with_reinvite_re_invites_the_survivor_with_the_newcomers_offer() {
    for (prefix, named) in [(6140, Named::BLeg), (6150, Named::ALeg)] {
        let call = established(prefix);
        let (replaced, survivor) = parties(&call, named);
        let sent = newcomer_sends(
            &call,
            &newcomer_invite(
                &format!("takeover-{prefix}@192.0.2.240"),
                &format!("X-Reinvite: yes\r\n{}", target_dialog(&call, named)),
            ),
        );
        let _ = response_to_phone(&sent, NEWCOMER, 200);
        assert!(sent_to(&sent, replaced, Method::Bye).is_some());
        let reinvite =
            sent_to(&sent, survivor, Method::Invite).expect("the survivor is re-INVITEd");
        assert!(
            body_of(&reinvite).contains(&format!("c=IN IP4 {}", host_of(NEWCOMER))),
            "with the newcomer's offer: {}",
            body_of(&reinvite)
        );
    }
}

/// RFC 4538 §4: a request naming a dialog the UA does not have is refused 481.
/// The call it did not name goes on undisturbed.
#[tokio::test(flavor = "multi_thread")]
async fn a_take_over_of_an_unknown_dialog_is_refused_481() {
    let call = established(6160);
    let sent = newcomer_sends(
        &call,
        &newcomer_invite(
            "takeover-6160@192.0.2.240",
            &format!(
                "Target-Dialog: {};local-tag=not-siphons-tag;remote-tag=b-tag\r\n",
                header(&call.to_b, "Call-ID")
            ),
        ),
    );
    let _ = response_to_phone(&sent, NEWCOMER, 481);
    assert!(sent_to(&sent, call.a.1, Method::Bye).is_none());
    assert!(sent_to(&sent, call.b.1, Method::Bye).is_none());
    assert_eq!(
        call.dispatcher.state.call_actors.count(),
        1,
        "the refused INVITE left no call behind, and the named one is intact"
    );
}

/// Only a confirmed dialog is taken over in this release: a named dialog still
/// early is refused 480 (TS 24.237 §12.3.2.3), and the ringing call goes on.
#[tokio::test(flavor = "multi_thread")]
async fn a_take_over_of_an_early_dialog_is_refused_480() {
    let dispatcher = test_dispatcher_with_script(TAKE_OVER);
    let (a, b) = ("192.0.2.170:5060", "198.51.100.170:5060");
    let a_call_id = "early-6170@192.0.2.170";
    place(
        &dispatcher,
        a,
        &invite(
            a,
            a_call_id,
            "<sip:6171@example.com>;tag=a-tag",
            &format!("sip:6172@{b}"),
            "",
        ),
    );
    let call_id = dispatcher
        .state
        .call_actors
        .find_by_sip_call_id(a_call_id)
        .expect("the call exists");
    let to_b = sent_invite_to(&wire(&dispatcher), b);
    respond(&dispatcher, &call_id, b, &to_b, ringing(&to_b, "b-tag"));
    let _ = wire(&dispatcher);

    for target in [
        format!(
            "Target-Dialog: {};local-tag={};remote-tag=b-tag\r\n",
            header(&to_b, "Call-ID"),
            tag_of(&header(&to_b, "From"))
        ),
        format!(
            "Target-Dialog: {a_call_id};local-tag={};remote-tag=a-tag\r\n",
            dispatcher
                .state
                .call_actors
                .get_call(&call_id)
                .map(|call| call.a_leg.dialog.local_tag.clone())
                .expect("the call exists")
        ),
    ] {
        place(
            &dispatcher,
            NEWCOMER,
            &newcomer_invite("takeover-6170@192.0.2.240", &target),
        );
        let sent = wire(&dispatcher);
        let _ = response_to_phone(&sent, NEWCOMER, 480);
        assert!(sent_to(&sent, a, Method::Bye).is_none(), "{target}");
        assert!(sent_to(&sent, b, Method::Cancel).is_none(), "{target}");
    }
    assert_eq!(dispatcher.state.call_actors.count(), 1, "still ringing");
}

/// The phone answers `invite` 180 Ringing, tagged `to_tag`.
fn ringing(invite: &SipMessage, to_tag: &str) -> SipMessage {
    let mut raw = String::from("SIP/2.0 180 Ringing\r\n");
    for via in invite.headers.get_all("Via").cloned().unwrap_or_default() {
        raw.push_str(&format!("Via: {via}\r\n"));
    }
    raw.push_str(&format!("From: {}\r\n", header(invite, "From")));
    raw.push_str(&format!("To: {};tag={to_tag}\r\n", header(invite, "To")));
    raw.push_str(&format!("Call-ID: {}\r\n", header(invite, "Call-ID")));
    raw.push_str(&format!("CSeq: {}\r\n", header(invite, "CSeq")));
    raw.push_str("Content-Length: 0\r\n\r\n");
    parse_sip_message_bytes(raw.as_bytes()).expect("the 180 parses")
}

/// A call siphon anchors has to re-INVITE its survivor: the takeover moves it
/// onto a new engine call. `reinvite=False` refuses at call time when siphon
/// can see the anchor; when it cannot (the script anchored after asking), the
/// takeover is refused rather than run half-way, and the call goes on.
#[tokio::test(flavor = "multi_thread")]
async fn a_take_over_without_reinvite_of_an_anchored_call_is_refused() {
    let engine = NativeTestEngine::start().await;
    let call = anchored_on(established(6180), &engine, OPEN).await;
    let state = &call.dispatcher.state;
    let siphon_tag = tag_of(&header(&call.to_b, "From"));
    let to_b_call_id = header(&call.to_b, "Call-ID");
    assert!(
        take_over_is_anchored_on(state, "no-such-call", &to_b_call_id, &siphon_tag, "b-tag"),
        "the named call is anchored"
    );

    let sent = newcomer_sends(
        &call,
        &newcomer_invite(
            "takeover-6180@192.0.2.240",
            &target_dialog(&call, Named::BLeg),
        ),
    );
    let _ = response_to_phone(&sent, NEWCOMER, 500);
    assert!(sent_to(&sent, call.b.1, Method::Bye).is_none());
    assert!(sent_to(&sent, call.a.1, Method::Invite).is_none());
    assert_eq!(state.call_actors.count(), 1, "the anchored call is intact");
}

/// Neither call anchored: nothing for `reinvite=False` to trip over.
#[tokio::test(flavor = "multi_thread")]
async fn an_unanchored_call_is_not_reported_anchored() {
    let call = established(6190);
    assert!(!take_over_is_anchored_on(
        &call.dispatcher.state,
        &call.call_id(),
        &header(&call.to_b, "Call-ID"),
        &tag_of(&header(&call.to_b, "From")),
        "b-tag",
    ));
    assert!(!take_over_is_anchored_on(
        &call.dispatcher.state,
        &call.call_id(),
        "no-such-dialog",
        "x",
        "y",
    ));
}

/// The script's takeover is the INVITE's routing: it is not dialled anywhere.
#[tokio::test(flavor = "multi_thread")]
async fn a_take_over_never_dials_the_request_uri() {
    let call = established(6200);
    let sent = newcomer_sends(
        &call,
        &newcomer_invite(
            "takeover-6200@192.0.2.240",
            &target_dialog(&call, Named::BLeg),
        ),
    );
    let invites: Vec<&Sent> = sent
        .iter()
        .filter(|sent| sent.message.method() == Some(&Method::Invite))
        .collect();
    assert!(invites.is_empty(), "nothing dialled: {}", invites.len());
}

/// TS 24.237 §6A.4.3A: the SCC AS's 200 to the transfer INVITE carries the
/// remote party's identity and the SRVCC feature capabilities. The script's
/// headers reach the wire on that 200.
#[tokio::test(flavor = "multi_thread")]
async fn a_take_over_puts_the_scripts_headers_on_the_200() {
    let call = established(6210);
    let sent = newcomer_sends(
        &call,
        &newcomer_invite(
            "takeover-6210@192.0.2.240",
            &format!(
                "X-Answer-Headers: scc-as\r\n{}",
                target_dialog(&call, Named::BLeg)
            ),
        ),
    );
    let ok = response_to_phone(&sent, NEWCOMER, 200);
    assert_eq!(
        header(&ok, "P-Asserted-Identity"),
        "<sip:+15550100002@example.com>"
    );
    assert_eq!(header(&ok, "Feature-Caps"), "*;+g.3gpp.srvcc");
    assert_eq!(
        header(&ok, "Accept"),
        "application/sdp, application/3gpp-ims+xml"
    );
    assert_eq!(header(&ok, "Recv-Info"), "g.3gpp.state-and-event");
    assert!(sent_to(&sent, call.b.1, Method::Bye).is_some());
}

/// A header siphon owns on its own 200 is refused at call time, as
/// `answer(headers=…)` refuses it: the handler fails, the newcomer is refused
/// and the named call is left alone.
#[tokio::test(flavor = "multi_thread")]
async fn a_take_over_refuses_a_header_siphon_owns() {
    let call = established(6220);
    let sent = newcomer_sends(
        &call,
        &newcomer_invite(
            "takeover-6220@192.0.2.240",
            &format!(
                "X-Answer-Headers: owned\r\n{}",
                target_dialog(&call, Named::BLeg)
            ),
        ),
    );
    assert!(
        sent.iter()
            .all(|sent| sent.message.status_code() != Some(200)),
        "no 200 for a refused takeover"
    );
    assert!(sent
        .iter()
        .any(|sent| sent.destination == NEWCOMER && sent.message.status_code() >= Some(400)));
    assert!(sent_to(&sent, call.b.1, Method::Bye).is_none());
    assert_eq!(call.dispatcher.state.call_actors.count(), 1);
}
