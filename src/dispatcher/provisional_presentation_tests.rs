//! A script decides what the caller is shown of a callee's provisional.
//!
//! A callee may answer the INVITE's offer in a reliable provisional "without any
//! intention of sending early media (this is the case when preconditions are
//! used)", so "by only looking at the SIP signalling, a UAC cannot be sure
//! whether or not there will be early media" (RFC 3960 §3.2). A calling network
//! that takes a session description in a provisional for early media stops
//! generating ringback. `reply.relay(body=False)` in `@b2bua.on_provisional`
//! relays the response without its body and `reply.withhold()` relays nothing,
//! while the callee's dialog goes on as it would have: the provisional is
//! PRACKed, `@b2bua.on_early_media` still has the session description for the
//! media engine, and the answer reaches the caller in the 2xx (RFC 3261
//! §13.2.1).
//!
//! Driven with the harness of [`super::a_leg_reliable_provisional_tests`].

use super::a_leg_reliable_provisional_tests::{
    cseq_method, dial_script, is_reliable, only, statuses, Call, CALLEE, CALLEE_SDP, PLAIN,
    RELIABLY, SUPPORTS,
};
use super::lcr_ring_timeout_tests::summaries;
use super::*;

/// Relay without its body a provisional that carries a session description and
/// no `P-Early-Media` authorising media toward the caller (RFC 5009).
const RINGBACK: &str = concat!(
    "\n",
    "@b2bua.on_provisional\n",
    "def on_provisional(call, reply):\n",
    "    if not reply.has_body(\"application/sdp\"):\n",
    "        return\n",
    "    early_media = reply.get_header(\"P-Early-Media\") or \"\"\n",
    "    if \"sendrecv\" not in early_media and \"sendonly\" not in early_media:\n",
    "        reply.relay(body=False)\n",
);

/// Relay nothing for a 183.
const WITHHOLD_183: &str = concat!(
    "\n",
    "@b2bua.on_provisional\n",
    "def on_provisional(call, reply):\n",
    "    if reply.status_code == 183:\n",
    "        reply.withhold()\n",
);

fn script(handlers: &str) -> String {
    dial_script("transparent-b2bua@2026", handlers)
}

fn text(body: &[u8]) -> String {
    String::from_utf8_lossy(body).into_owned()
}

fn header(message: &SipMessage, name: &str) -> Option<String> {
    message.headers.get(name).cloned()
}

/// Whether siphon sent the callee a PRACK among `sent`.
fn pracked_the_callee(sent: &[lcr_ring_timeout_tests::Sent]) -> bool {
    summaries(sent).contains(&format!("PRACK to {CALLEE}"))
}

/// What the caller got among `sent`.
fn to_caller(sent: Vec<lcr_ring_timeout_tests::Sent>) -> Vec<SipMessage> {
    let caller: SocketAddr = "192.0.2.10:5060".parse().expect("a literal address");
    sent.into_iter()
        .filter(|sent| sent.destination == caller)
        .map(|sent| sent.message)
        .collect()
}

fn assert_no_body(message: &SipMessage) {
    assert!(message.body.is_empty(), "{}", text(&message.body));
    assert_eq!(header(message, "Content-Type"), None);
    assert_eq!(header(message, "Content-Length").as_deref(), Some("0"));
}

/// The answer the callee gave, as the caller's 2xx carries it.
fn assert_carries_the_callees_answer(answer: &SipMessage) {
    assert_eq!(cseq_method(answer), "INVITE");
    assert_eq!(
        header(answer, "Content-Type").as_deref(),
        Some("application/sdp")
    );
    assert!(
        text(&answer.body).contains("m=audio 50000 RTP/AVP 0\r\n"),
        "the 2xx carries the callee's answer: {}",
        text(&answer.body)
    );
}

/// `reply.relay(body=False)`: the 183 reaches the caller without its session
/// description, the callee is PRACKed as it would have been, and a `180`
/// without a body is relayed as it is.
#[tokio::test(flavor = "multi_thread")]
async fn a_provisional_is_relayed_without_its_body_when_the_script_says_so() {
    let call = Call::place(PLAIN, &script(RINGBACK));
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    let sent = call.wire();
    assert!(pracked_the_callee(&sent), "{:?}", summaries(&sent));
    let progress = only(to_caller(sent), 183);
    assert_no_body(&progress);
    assert!(!is_reliable(&progress));

    call.callee_sends(180, "Ringing", &[], None);
    assert_no_body(&only(call.to_caller(), 180));
}

/// The caller never had the answer, so the 2xx carries it even when the
/// callee's own 2xx does not (RFC 3261 §13.2.1): the session description the
/// provisional would have shown.
#[tokio::test(flavor = "multi_thread")]
async fn the_2xx_carries_the_answer_a_script_kept_out_of_the_provisional() {
    let call = Call::place(PLAIN, &script(RINGBACK));
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    assert_no_body(&only(call.to_caller(), 183));

    call.callee_sends(200, "OK", &[], None);
    let answer = only(call.to_caller(), 200);
    assert_carries_the_callees_answer(&answer);
    let leg = call
        .state
        .call_actors
        .clone_leg(&call.call_id, true)
        .expect("the caller's leg");
    assert_eq!(leg.dialog.last_sent_sdp, Some(answer.body.clone()));
    // It is the first description this caller is sent, so it goes out as any
    // answer no provisional showed does: under the caller's dialog's own `o=`
    // session id at its first version, and the next takes the one after.
    let own = leg.dialog.sdp_session_id;
    assert!(
        text(&answer.body).contains(&format!("o=siphon {own} 0 IN IP4 192.0.2.1\r\n")),
        "{}",
        text(&answer.body)
    );
    assert_eq!(leg.dialog.sdp_version, 1);
}

/// A callee's 2xx with SDP after a provisional the caller was not shown is the
/// first description too: no preview names a session for it to continue.
#[tokio::test(flavor = "multi_thread")]
async fn a_2xx_with_sdp_after_a_withheld_answer_is_a_first_description() {
    let call = Call::place(PLAIN, &script(WITHHOLD_183));
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    call.wire();

    call.callee_sends(200, "OK", &[], Some(CALLEE_SDP));
    let answer = only(call.to_caller(), 200);
    let leg = call
        .state
        .call_actors
        .clone_leg(&call.call_id, true)
        .expect("the caller's leg");
    let own = leg.dialog.sdp_session_id;
    assert!(
        text(&answer.body).contains(&format!("o=siphon {own} 0 IN IP4 192.0.2.1\r\n")),
        "{}",
        text(&answer.body)
    );
    assert_eq!(leg.dialog.sdp_version, 1);
}

/// A callee's 2xx that carries the answer is relayed with it, as always.
#[tokio::test(flavor = "multi_thread")]
async fn a_2xx_with_the_answer_follows_a_provisional_relayed_without_its_body() {
    let call = Call::place(PLAIN, &script(RINGBACK));
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    call.to_caller();

    call.callee_sends(200, "OK", &[], Some(CALLEE_SDP));
    assert_carries_the_callees_answer(&only(call.to_caller(), 200));
}

/// `reply.withhold()`: nothing reaches the caller for that provisional, the
/// callee is still PRACKed, later provisionals are relayed, and the 2xx carries
/// the answer.
#[tokio::test(flavor = "multi_thread")]
async fn a_withheld_provisional_reaches_nobody_and_its_answer_is_in_the_2xx() {
    let call = Call::place(PLAIN, &script(WITHHOLD_183));
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    let sent = call.wire();
    assert!(pracked_the_callee(&sent), "{:?}", summaries(&sent));
    assert_eq!(statuses(&to_caller(sent)), Vec::<u16>::new());

    call.callee_sends(180, "Ringing", &[], None);
    assert_eq!(statuses(&call.to_caller()), [180]);

    call.callee_sends(200, "OK", &[], None);
    assert_carries_the_callees_answer(&only(call.to_caller(), 200));
}

/// `@b2bua.on_early_media` still runs with the session description in hand,
/// which is where a script has the media engine anchor the callee's side.
#[tokio::test(flavor = "multi_thread")]
async fn on_early_media_still_has_the_session_description() {
    let handlers = concat!(
        "\n",
        "@b2bua.on_provisional\n",
        "def on_provisional(call, reply):\n",
        "    reply.relay(body=False)\n",
        "\n",
        "@b2bua.on_early_media\n",
        "def on_early_media(call, reply):\n",
        "    reply.set_header(\"X-Anchored\", str(reply.has_body(\"application/sdp\")))\n",
    );
    let call = Call::place(PLAIN, &script(handlers));
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    let progress = only(call.to_caller(), 183);
    assert_eq!(header(&progress, "X-Anchored").as_deref(), Some("True"));
    assert_no_body(&progress);
}

/// The last decision stands: `reply.relay()` after `reply.relay(body=False)`
/// or `reply.withhold()` relays the response as it is.
#[tokio::test(flavor = "multi_thread")]
async fn a_later_relay_restores_the_whole_provisional() {
    let handlers = concat!(
        "\n",
        "@b2bua.on_provisional\n",
        "def on_provisional(call, reply):\n",
        "    reply.withhold()\n",
        "    reply.relay(body=False)\n",
        "\n",
        "@b2bua.on_early_media\n",
        "def on_early_media(call, reply):\n",
        "    reply.relay()\n",
    );
    let call = Call::place(PLAIN, &script(handlers));
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    let progress = only(call.to_caller(), 183);
    assert!(text(&progress.body).contains("m=audio 50000 "));
}

/// A provisional the callee authorises early media on is relayed whole after
/// one that was not, and is then the session description the caller was shown:
/// the 2xx repeats it.
#[tokio::test(flavor = "multi_thread")]
async fn an_authorised_provisional_is_relayed_whole_after_one_that_was_not() {
    let call = Call::place(PLAIN, &script(RINGBACK));
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    assert_no_body(&only(call.to_caller(), 183));

    call.callee_sends(
        183,
        "Session Progress",
        &[("P-Early-Media", "sendrecv")],
        Some(CALLEE_SDP),
    );
    let authorised = only(call.to_caller(), 183);
    assert!(text(&authorised.body).contains("m=audio 50000 "));

    call.callee_sends(200, "OK", &[], None);
    let answer = only(call.to_caller(), 200);
    assert_eq!(text(&answer.body), text(&authorised.body));
}

/// Toward a caller that uses `100rel`, a provisional relayed without its body
/// is still reliable when the callee's was (RFC 3262 §3 does not ask for a
/// session description in one): siphon's own `RSeq`, the callee's PRACK
/// released by the caller's, the next one numbered one higher, and a 2xx that
/// carries the answer and waits for no PRACK.
#[tokio::test(flavor = "multi_thread")]
async fn a_reliable_provisional_without_its_body_keeps_rfc_3262_on_the_callers_dialog() {
    let call = Call::place(SUPPORTS, &script(RINGBACK));
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    let sent = call.wire();
    assert!(
        !pracked_the_callee(&sent),
        "the callee's PRACK waits for the caller's: {:?}",
        summaries(&sent)
    );
    let progress = only(to_caller(sent), 183);
    assert!(is_reliable(&progress));
    assert_no_body(&progress);

    call.caller_pracks(&progress, 2);
    let sent = call.wire();
    assert!(pracked_the_callee(&sent), "{:?}", summaries(&sent));
    assert_eq!(statuses(&to_caller(sent)), [200]);

    call.callee_sends(
        180,
        "Ringing",
        &[("Require", "100rel"), ("RSeq", "43")],
        None,
    );
    let ringing = only(call.to_caller(), 180);
    assert!(is_reliable(&ringing));
    let rseq = |message: &SipMessage| -> u32 {
        header(message, "RSeq")
            .and_then(|value| value.trim().parse().ok())
            .expect("a numeric RSeq")
    };
    assert_eq!(rseq(&ringing), rseq(&progress) + 1);

    call.callee_sends(200, "OK", &[], None);
    assert_carries_the_callees_answer(&only(call.to_caller(), 200));
}

/// A withheld reliable provisional is PRACKed toward the callee at once, since
/// no PRACK of the caller's will ever release it, and is nothing on the
/// caller's dialog: the next reliable provisional goes out without waiting for
/// a PRACK that cannot come (RFC 3262 §3), and is PRACKed like any other.
#[tokio::test(flavor = "multi_thread")]
async fn a_withheld_reliable_provisional_leaves_the_callers_dialog_untouched() {
    let call = Call::place(SUPPORTS, &script(WITHHOLD_183));
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    let sent = call.wire();
    assert!(pracked_the_callee(&sent), "{:?}", summaries(&sent));
    assert_eq!(statuses(&to_caller(sent)), Vec::<u16>::new());

    call.callee_sends(
        180,
        "Ringing",
        &[("Require", "100rel"), ("RSeq", "43")],
        None,
    );
    let ringing = only(call.to_caller(), 180);
    assert!(is_reliable(&ringing));
    call.caller_pracks(&ringing, 2);
    let sent = call.wire();
    assert!(pracked_the_callee(&sent), "{:?}", summaries(&sent));
    assert_eq!(statuses(&to_caller(sent)), [200]);

    call.callee_sends(200, "OK", &[], None);
    assert_carries_the_callees_answer(&only(call.to_caller(), 200));
}

/// A handler that decides nothing changes nothing: the provisional is relayed
/// with its session description.
#[tokio::test(flavor = "multi_thread")]
async fn a_handler_that_decides_nothing_relays_the_provisional_whole() {
    let handlers = concat!(
        "\n",
        "@b2bua.on_provisional\n",
        "def on_provisional(call, reply):\n",
        "    reply.set_header(\"X-Seen\", reply.get_header(\"P-Early-Media\") or \"none\")\n",
    );
    let call = Call::place(PLAIN, &script(handlers));
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    let progress = only(call.to_caller(), 183);
    assert_eq!(header(&progress, "X-Seen").as_deref(), Some("none"));
    assert!(text(&progress.body).contains("m=audio 50000 "));
}

/// Outside a provisional the B2BUA relays there is nothing for these to decide,
/// and they say so instead of doing nothing: in `@b2bua.on_answer` both raise,
/// which fails the call like any other raise there.
#[tokio::test(flavor = "multi_thread")]
async fn the_decision_is_refused_where_it_cannot_be_carried_out() {
    for decision in ["reply.relay(body=False)", "reply.withhold()"] {
        let handlers = format!("\n@b2bua.on_answer\ndef on_answer(call, reply):\n    {decision}\n");
        let call = Call::place(PLAIN, &script(&handlers));
        call.callee_sends(200, "OK", &[], Some(CALLEE_SDP));
        let sent = call.to_caller();
        assert!(
            !statuses(&sent).contains(&200),
            "{decision} in on_answer: {:?}",
            statuses(&sent)
        );
    }
}

/// Emit the 183 a script relayed without its body and the 2xx that carries the
/// answer instead, as hex for `scripts/validate_b2bua_previewed_answer.sh` to
/// feed to tshark: siphon's own parser shares whatever siphon gets wrong when
/// it takes a body off a response.
#[tokio::test(flavor = "multi_thread")]
async fn emit_provisional_without_body_for_external_dissection() {
    let Ok(path) = std::env::var("SIPHON_B2BUA_WITHHELD_ANSWER_HEX_OUT") else {
        // Nothing to do in an ordinary test run.
        return;
    };
    let call = Call::place(PLAIN, &script(RINGBACK));
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    let progress = only(call.to_caller(), 183);
    call.callee_sends(200, "OK", &[], None);
    let answer = only(call.to_caller(), 200);

    // `text2pcap`'s hex-dump form: an offset, then the octets. An offset of
    // zero starts the next packet.
    let mut dump = String::new();
    for message in [progress, answer] {
        for (offset, chunk) in message.to_bytes().chunks(16).enumerate() {
            dump.push_str(&format!("{:06x}", offset * 16));
            for byte in chunk {
                dump.push_str(&format!(" {byte:02x}"));
            }
            dump.push('\n');
        }
    }
    std::fs::write(&path, dump).expect("hex dump must be writable");
}
