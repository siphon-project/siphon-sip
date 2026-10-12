//! The caller's 2xx carries the answer unless the caller's own dialog already
//! had it reliably (RFC 3261 §13.2.1).
//!
//! "If the initial offer is in an INVITE, the answer MUST be in a reliable
//! non-failure message from UAS back to UAC which is correlated to that INVITE",
//! which is the 2xx unless a reliable provisional carried it (RFC 3262 §5). A
//! session description in an unreliable provisional is a preview: "the UAS MUST
//! send the same exact answer in the 2xx" (RFC 6337 §3.1.1). siphon is the UAS of
//! the caller's dialog, and each leg's reliability is its own: a callee that
//! answered in a reliable 183 may send its 2xx without a body, and the caller who
//! was shown that answer in an unreliable 183 is still owed it.
//!
//! Driven with the harness of [`super::a_leg_reliable_provisional_tests`].

use super::a_leg_reliable_provisional_tests::{
    cseq_method, default_dial, is_reliable, only, statuses, Call, CALLEE, CALLEE_SDP, PLAIN,
    RELIABLY, SUPPORTS,
};
use super::test_dispatcher::test_dispatcher_with_script;
use super::*;

/// The second callee of a fork, and its To tag.
const SECOND: (&str, &str) = ("198.51.100.8:5060", "second-callee-tag");

const SECOND_CALLEE_SDP: &str = concat!(
    "v=0\r\n",
    "o=- 5 9 IN IP4 198.51.100.8\r\n",
    "s=-\r\n",
    "c=IN IP4 198.51.100.8\r\n",
    "t=0 0\r\n",
    "m=audio 52000 RTP/AVP 0\r\n",
);

/// The callee's answer with an attribute `media.sdp_strip_attributes` names.
const CALLEE_SDP_WITH_HIDDEN: &str = concat!(
    "v=0\r\n",
    "o=- 2 2 IN IP4 198.51.100.7\r\n",
    "s=-\r\n",
    "c=IN IP4 198.51.100.7\r\n",
    "t=0 0\r\n",
    "m=audio 50000 RTP/AVP 0\r\n",
    "a=x-hidden:callee\r\n",
);

const FORK: &str = concat!(
    "from siphon import b2bua\n",
    "\n",
    "@b2bua.on_invite\n",
    "def on_invite(call):\n",
    "    call.fork([\"sip:15550100042@198.51.100.7:5060\", \"sip:15550100042@198.51.100.8:5060\"])\n",
);

fn content_type(message: &SipMessage) -> Option<&str> {
    message.headers.get("Content-Type").map(String::as_str)
}

fn content_length(message: &SipMessage) -> Option<usize> {
    message
        .headers
        .get("Content-Length")
        .and_then(|value| value.trim().parse().ok())
}

fn text(body: &[u8]) -> String {
    String::from_utf8_lossy(body).into_owned()
}

/// The session description in force on the caller's dialog, and the `o=`
/// session id and next version siphon holds for it.
fn caller_session(call: &Call) -> (Option<Vec<u8>>, u64, u64) {
    let leg = call
        .state
        .call_actors
        .clone_leg(&call.call_id, true)
        .expect("the caller's leg");
    (
        leg.dialog.last_sent_sdp,
        leg.dialog.sdp_session_id,
        leg.dialog.sdp_version,
    )
}

/// The defect: the callee answers in a reliable 183 and sends its 2xx without a
/// body. The caller does not use `100rel`, so its 183 was unreliable and only
/// previewed the answer. The 2xx carries that same answer, byte for byte.
#[tokio::test(flavor = "multi_thread")]
async fn the_2xx_carries_the_answer_an_unreliable_183_previewed() {
    let call = Call::place(PLAIN, &default_dial());
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    let progress = only(call.to_caller(), 183);
    assert!(!is_reliable(&progress));
    assert!(!progress.body.is_empty(), "the 183 previews the answer");

    call.callee_sends(200, "OK", &[], None);
    let answer = only(call.to_caller(), 200);
    assert_eq!(cseq_method(&answer), "INVITE");
    assert_eq!(
        text(&answer.body),
        text(&progress.body),
        "the 2xx carries the answer the 183 previewed, unchanged"
    );
    assert_eq!(content_type(&answer), Some("application/sdp"));
    assert_eq!(content_length(&answer), Some(answer.body.len()));

    // The answer keeps the `o=` it was previewed with, and the next session
    // description siphon sends the caller takes the version after it.
    let (in_force, session_id, next_version) = caller_session(&call);
    assert_eq!(in_force, Some(answer.body.clone()));
    assert_eq!((session_id, next_version), (2, 3));
}

/// A caller that got the answer in a reliable 183 has it: a 2xx without a body
/// goes to it without one, as before.
#[tokio::test(flavor = "multi_thread")]
async fn a_2xx_after_a_reliable_answer_carries_no_session_description() {
    let call = Call::place(SUPPORTS, &default_dial());
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    let progress = only(call.to_caller(), 183);
    assert!(is_reliable(&progress));
    assert!(!progress.body.is_empty());

    call.callee_sends(200, "OK", &[], None);
    call.caller_pracks(&progress, 2);
    let sent = call.to_caller();
    assert_eq!(statuses(&sent), [200, 200]);
    assert_eq!(cseq_method(&sent[1]), "INVITE");
    assert!(
        sent[1].body.is_empty(),
        "the answer went reliably in the 183: {}",
        text(&sent[1].body)
    );
    assert_eq!(caller_session(&call).0, Some(progress.body.clone()));
}

/// The callee's answer again with a new address and port: what a callee that
/// changed its mind, or a media engine that allocated again, puts in the 2xx.
const CALLEE_SDP_CHANGED: &str = concat!(
    "v=0\r\n",
    "o=- 2 2 IN IP4 198.51.100.7\r\n",
    "s=-\r\n",
    "c=IN IP4 198.51.100.9\r\n",
    "t=0 0\r\n",
    "m=audio 52000 RTP/AVP 0\r\n",
);

fn origin(message: &SipMessage) -> String {
    text(&message.body)
        .lines()
        .find(|line| line.starts_with("o="))
        .map(str::to_string)
        .expect("an o= line")
}

/// The `o=` session id and version the next session description siphon sends
/// the caller goes out under: what a re-INVITE or a session refresh toward the
/// caller reserves (`own_sdp_toward_leg`).
fn next_origin_toward_caller(call: &Call) -> (u64, u64) {
    call.state
        .call_actors
        .reserve_leg_sdp_version(&call.call_id, true)
        .expect("the caller's leg")
}

/// One INVITE describes one session to the caller: the `o=` session id is its
/// identity and the version its revision (RFC 4566 §5.2, RFC 3264 §5). A
/// callee's 2xx that repeats the answer the unreliable 183 previewed reaches the
/// caller as "the same exact answer" (RFC 6337 §3.1.1): the bytes of the 183,
/// the origin and its version included, and a later re-INVITE toward the caller
/// goes on from the version after it (RFC 3264 §8).
#[tokio::test(flavor = "multi_thread")]
async fn a_2xx_that_repeats_the_previewed_answer_is_byte_identical_to_it() {
    let call = Call::place(PLAIN, &default_dial());
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    let progress = only(call.to_caller(), 183);
    assert_eq!(origin(&progress), "o=siphon 2 2 IN IP4 192.0.2.1");

    call.callee_sends(200, "OK", &[], Some(CALLEE_SDP));
    let answer = only(call.to_caller(), 200);
    assert_eq!(text(&answer.body), text(&progress.body));
    assert_eq!(content_length(&answer), Some(answer.body.len()));
    assert_eq!(caller_session(&call).0, Some(answer.body.clone()));
    assert_eq!(next_origin_toward_caller(&call), (2, 3));
}

/// A 2xx whose description differs from the preview is a revision of the same
/// session: the preview's origin with the version one up, around the callee's
/// own description, because media follows the callee's 2xx. A caller may ignore
/// it (RFC 3261 §13.2.1), which siphon logs. The next description toward the
/// caller takes the version after that.
#[tokio::test(flavor = "multi_thread")]
async fn a_2xx_that_differs_from_the_preview_keeps_its_session_id_one_version_up() {
    let call = Call::place(PLAIN, &default_dial());
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    let progress = only(call.to_caller(), 183);
    assert_eq!(origin(&progress), "o=siphon 2 2 IN IP4 192.0.2.1");

    call.callee_sends(200, "OK", &[], Some(CALLEE_SDP_CHANGED));
    let answer = only(call.to_caller(), 200);
    assert_eq!(origin(&answer), "o=siphon 2 3 IN IP4 192.0.2.1");
    assert!(
        text(&answer.body).contains("c=IN IP4 198.51.100.9\r\n")
            && text(&answer.body).contains("m=audio 52000 "),
        "the callee's own 2xx description: {}",
        text(&answer.body)
    );
    assert_eq!(caller_session(&call).0, Some(answer.body.clone()));
    assert_eq!(next_origin_toward_caller(&call), (2, 4));
}

/// What `media.sdp_strip_attributes` removes on the way to the caller is no
/// difference: the 2xx is compared as the caller would get it.
#[tokio::test(flavor = "multi_thread")]
async fn a_repeated_answer_is_compared_as_the_caller_is_sent_it() {
    let mut dispatcher = test_dispatcher_with_script(&default_dial());
    dispatcher.state.sdp_strip_attributes = vec!["x-hidden".to_string()];
    let (call, _) = Call::place_on(dispatcher, PLAIN, true);
    call.callee_sends(
        183,
        "Session Progress",
        RELIABLY,
        Some(CALLEE_SDP_WITH_HIDDEN),
    );
    let progress = only(call.to_caller(), 183);

    call.callee_sends(200, "OK", &[], Some(CALLEE_SDP_WITH_HIDDEN));
    let answer = only(call.to_caller(), 200);
    assert_eq!(text(&answer.body), text(&progress.body));
}

/// Unchanged: a caller that had the answer in a reliable 183 gets the callee's
/// 2xx description under that session id at the next version, as before.
#[tokio::test(flavor = "multi_thread")]
async fn a_2xx_with_sdp_after_a_reliable_answer_is_stamped_as_before() {
    let call = Call::place(SUPPORTS, &default_dial());
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    let progress = only(call.to_caller(), 183);
    assert!(is_reliable(&progress));
    assert_eq!(origin(&progress), "o=siphon 2 2 IN IP4 192.0.2.1");

    call.callee_sends(200, "OK", &[], Some(CALLEE_SDP));
    call.caller_pracks(&progress, 2);
    let sent = call.to_caller();
    assert_eq!(statuses(&sent), [200, 200]);
    assert_eq!(origin(&sent[1]), "o=siphon 2 3 IN IP4 192.0.2.1");
    assert_eq!(next_origin_toward_caller(&call), (2, 4));
}

/// Unchanged: with no preview the 2xx is the first description the caller
/// gets, under the session id of the caller's own dialog at version 0.
#[tokio::test(flavor = "multi_thread")]
async fn a_2xx_with_sdp_and_no_preview_is_stamped_as_before() {
    let call = Call::place(PLAIN, &default_dial());
    call.callee_sends(180, "Ringing", &[], None);
    call.to_caller();
    let own = caller_session(&call).1;

    call.callee_sends(200, "OK", &[], Some(CALLEE_SDP));
    let answer = only(call.to_caller(), 200);
    assert_eq!(
        origin(&answer),
        format!("o=siphon {own} 0 IN IP4 192.0.2.1")
    );
    assert_eq!(next_origin_toward_caller(&call), (own, 1));
}

/// Unchanged: a 2xx on another early dialog of the callee than the previewed
/// one is that dialog's own first description.
#[tokio::test(flavor = "multi_thread")]
async fn a_2xx_with_sdp_on_another_early_dialog_is_stamped_as_before() {
    let call = Call::place(PLAIN, &default_dial());
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    call.to_caller();
    let own = caller_session(&call).1;

    let invite = call.callee_invite.clone();
    call.callee_at_sends(
        &invite,
        (CALLEE, "forked-tag"),
        200,
        "OK",
        &[],
        Some(CALLEE_SDP),
    );
    let answer = only(call.to_caller(), 200);
    assert_eq!(
        origin(&answer),
        format!("o=siphon {own} 0 IN IP4 192.0.2.1")
    );
}

/// What the 2xx carries is the session description the caller was shown, after
/// everything siphon does to one on its way to the caller, not the callee's as
/// it arrived.
#[tokio::test(flavor = "multi_thread")]
async fn the_2xx_carries_the_answer_as_the_caller_was_shown_it() {
    let mut dispatcher = test_dispatcher_with_script(&default_dial());
    dispatcher.state.sdp_strip_attributes = vec!["x-hidden".to_string()];
    let (call, _) = Call::place_on(dispatcher, PLAIN, true);
    call.callee_sends(
        183,
        "Session Progress",
        RELIABLY,
        Some(CALLEE_SDP_WITH_HIDDEN),
    );
    let progress = only(call.to_caller(), 183);
    assert!(!text(&progress.body).contains("x-hidden"));

    call.callee_sends(200, "OK", &[], None);
    let answer = only(call.to_caller(), 200);
    assert_eq!(text(&answer.body), text(&progress.body));
}

/// Each callee of a fork has its own early dialog, and RFC 3261 §13.2.1 lets
/// their answers differ. The 2xx carries the answer of the callee that sent it,
/// whatever another callee's provisional showed the caller last.
#[tokio::test(flavor = "multi_thread")]
async fn the_2xx_of_a_forked_call_carries_the_answering_callees_own_answer() {
    let (call, others) = Call::place_on(test_dispatcher_with_script(FORK), PLAIN, true);
    let second_invite = others.first().expect("the second callee was dialled");

    call.callee_at_sends(
        second_invite,
        SECOND,
        183,
        "Session Progress",
        RELIABLY,
        Some(SECOND_CALLEE_SDP),
    );
    let second_preview = only(call.to_caller(), 183);
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    let first_preview = only(call.to_caller(), 183);
    assert_ne!(text(&first_preview.body), text(&second_preview.body));

    call.callee_at_sends(second_invite, SECOND, 200, "OK", &[], None);
    let answer = only(call.to_caller(), 200);
    assert_eq!(text(&answer.body), text(&second_preview.body));
}

/// A callee that never sent a session description has given no answer to pass
/// on. Its 2xx is not given the answer of another callee's early dialog.
#[tokio::test(flavor = "multi_thread")]
async fn a_callee_that_gave_no_answer_is_not_lent_another_callees() {
    let (call, others) = Call::place_on(test_dispatcher_with_script(FORK), PLAIN, true);
    let second_invite = others.first().expect("the second callee was dialled");
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    call.to_caller();

    call.callee_at_sends(second_invite, SECOND, 200, "OK", &[], None);
    let answer = only(call.to_caller(), 200);
    assert!(answer.body.is_empty(), "{}", text(&answer.body));
}

/// A fork beyond the callee gives its leg several early dialogs. A 2xx on one
/// siphon relayed no session description of is not given another's.
#[tokio::test(flavor = "multi_thread")]
async fn a_2xx_on_another_early_dialog_of_the_callee_is_not_lent_the_previewed_answer() {
    let call = Call::place(PLAIN, &default_dial());
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    call.to_caller();

    let invite = call.callee_invite.clone();
    call.callee_at_sends(&invite, (CALLEE, "forked-tag"), 200, "OK", &[], None);
    let answer = only(call.to_caller(), 200);
    assert!(answer.body.is_empty(), "{}", text(&answer.body));
}

/// To an INVITE without an offer the session description of a provisional is
/// the callee's offer, and an unreliable provisional makes no offer (RFC 3261
/// §13.2.1). siphon has already turned that offer down on the callee's dialog
/// when it PRACKed, so it is not offered to the caller again in the 2xx.
#[tokio::test(flavor = "multi_thread")]
async fn a_2xx_to_an_invite_without_an_offer_is_left_as_the_callee_sent_it() {
    let (call, _) = Call::place_on(test_dispatcher_with_script(&default_dial()), PLAIN, false);
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    call.to_caller();

    call.callee_sends(200, "OK", &[], None);
    let answer = only(call.to_caller(), 200);
    assert!(answer.body.is_empty(), "{}", text(&answer.body));
}

/// `text2pcap`'s hex-dump form of `messages`: an offset, then the octets. An
/// offset of zero starts the next packet.
fn hex_dump(messages: &[SipMessage]) -> String {
    let mut dump = String::new();
    for message in messages {
        for (offset, chunk) in message.to_bytes().chunks(16).enumerate() {
            dump.push_str(&format!("{:06x}", offset * 16));
            for byte in chunk {
                dump.push_str(&format!(" {byte:02x}"));
            }
            dump.push('\n');
        }
    }
    dump
}

/// Emit the 183 and the 2xx a caller without `100rel` is sent, as hex for
/// `scripts/validate_b2bua_previewed_answer.sh` to feed to tshark: for a callee
/// whose 2xx carries no SDP, one whose 2xx repeats the answer, and one whose 2xx
/// changes it, in that order.
///
/// The tests above read siphon's messages back with siphon's own parser, which
/// shares whatever siphon gets wrong about a body and its `Content-Length`.
/// Wireshark's SIP and SDP dissectors do not.
#[tokio::test(flavor = "multi_thread")]
async fn emit_previewed_answer_for_external_dissection() {
    let Ok(path) = std::env::var("SIPHON_B2BUA_PREVIEWED_ANSWER_HEX_OUT") else {
        // Nothing to do in an ordinary test run.
        return;
    };
    let mut frames = Vec::new();
    for answer in [None, Some(CALLEE_SDP), Some(CALLEE_SDP_CHANGED)] {
        let call = Call::place(PLAIN, &default_dial());
        call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
        frames.push(only(call.to_caller(), 183));
        call.callee_sends(200, "OK", &[], answer);
        frames.push(only(call.to_caller(), 200));
    }
    std::fs::write(&path, hex_dump(&frames)).expect("hex dump must be writable");
}
