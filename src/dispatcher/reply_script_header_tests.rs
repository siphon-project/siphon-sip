//! A header a script sets or removes on a B-leg response in `@b2bua.on_answer`
//! or `@b2bua.on_early_media` goes to the caller as the script left it.
//!
//! The response-side twin of a script's `call.set_header()` on the B-leg
//! INVITE: above the response policy's strips and rewrites, and above siphon's
//! own `Supported`/`Allow` rewrite. The framework-managed headers stay
//! siphon's, and `replaces` is still merged into `Supported`. Driven through
//! the dispatcher with the harness of [`super::lcr_ring_timeout_tests`], the
//! callee answering through `handle_b2bua_response`, and what siphon relays
//! read back off the UDP egress.

use super::lcr_ring_timeout_tests::{
    carrier, invite_to, summaries, top_via_branch, Sent, Sequence, CALLER, FIRST_CARRIER,
};
use super::*;
use crate::b2bua::header_policy::ResolvedPolicy;

/// What the callee sends on its answer besides the dialog headers.
const CALLEE_HEADERS: &[(&str, &str)] = &[
    ("Supported", "100rel, timer, outbound"),
    ("Allow", "INVITE, ACK, BYE, CANCEL"),
    ("Organization", "callee organisation"),
    ("X-Callee-Tag", "from-the-callee"),
];

fn preset(name: &str) -> ResolvedPolicy {
    let preset = crate::b2bua::header_policy::builtin_presets()
        .get(name)
        .cloned()
        .unwrap_or_else(|| panic!("no built-in preset {name}"));
    ResolvedPolicy::from_preset(preset)
}

/// A call to one carrier running `script`, under `policy`, with its INVITE.
fn call_under(script: &str, policy: &str) -> (Sequence, SipMessage) {
    let sequence =
        Sequence::start_with_script(vec![carrier("callee", FIRST_CARRIER, 30)], 30, script);
    sequence
        .dispatcher
        .state
        .call_actors
        .get_call_mut(&sequence.call_id)
        .expect("the call exists")
        .resolved_header_policy = Some(Arc::new(preset(policy)));
    let invite = invite_to(sequence.wire(), FIRST_CARRIER);
    (sequence, invite)
}

/// The response siphon sent the caller with `status_code`.
fn to_caller(sent: Vec<Sent>, status_code: u16) -> SipMessage {
    let caller: SocketAddr = CALLER.parse().expect("a literal address");
    let listed = summaries(&sent);
    sent.into_iter()
        .find(|sent| sent.destination == caller && sent.message.status_code() == Some(status_code))
        .map(|sent| sent.message)
        .unwrap_or_else(|| panic!("no {status_code} to the caller, sent: {listed:?}"))
}

/// The callee answers 200 with [`CALLEE_HEADERS`]; the 200 the caller got.
fn answered(script: &str, policy: &str) -> SipMessage {
    let (sequence, invite) = call_under(script, policy);
    sequence.carrier_answers_with(FIRST_CARRIER, &invite, 200, "OK", CALLEE_HEADERS);
    to_caller(sequence.wire(), 200)
}

fn supported_tags(message: &SipMessage) -> Vec<String> {
    message
        .headers
        .get_all("Supported")
        .map(|values| {
            values
                .iter()
                .flat_map(|value| value.split(','))
                .map(|tag| tag.trim().to_ascii_lowercase())
                .filter(|tag| !tag.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn header(message: &SipMessage, name: &str) -> Option<String> {
    message.headers.get(name).cloned()
}

fn on_answer(lines: &[&str]) -> String {
    let mut script =
        String::from("from siphon import b2bua\n\n@b2bua.on_answer\ndef on_answer(call, reply):\n");
    for line in lines {
        script.push_str("    ");
        script.push_str(line);
        script.push('\n');
    }
    script
}

/// siphon's response-side rewrite of `Supported` and `Allow` does not replace
/// what `@b2bua.on_answer` wrote: the default preset strips both on responses
/// and siphon puts its own in, and the script's values used to be lost there.
#[tokio::test(flavor = "multi_thread")]
async fn a_reply_header_set_in_on_answer_outranks_siphons_capabilities() {
    let response = answered(
        &on_answer(&[
            "reply.set_header(\"Allow\", \"INVITE, ACK, BYE\")",
            "reply.set_header(\"Supported\", \"outbound, x-lab-tag\")",
        ]),
        "transparent-b2bua@2026",
    );
    assert_eq!(
        header(&response, "Allow").as_deref(),
        Some("INVITE, ACK, BYE")
    );
    assert_eq!(
        supported_tags(&response),
        ["outbound", "x-lab-tag", "replaces"]
    );
}

/// ...and a response policy's strips do not drop it: intra-trust strips `X-*`
/// on responses, the trust boundary strips everything outside its safe set.
#[tokio::test(flavor = "multi_thread")]
async fn a_reply_header_set_in_on_answer_outranks_a_response_policy_strip() {
    for policy in [
        "ims-intra-trust-domain@2026",
        "ims-trust-domain-boundary@2026",
    ] {
        let response = answered(
            &on_answer(&["reply.set_header(\"X-Lab-Tag\", \"set-by-the-script\")"]),
            policy,
        );
        assert_eq!(
            header(&response, "X-Lab-Tag").as_deref(),
            Some("set-by-the-script"),
            "under {policy}"
        );
        assert_eq!(
            header(&response, "X-Callee-Tag"),
            None,
            "under {policy}: the callee's own still gets the policy"
        );
    }
}

/// A removal is the script's value too: siphon does not put its own `Allow`
/// back, while `replaces` is still merged into `Supported` as it always is.
#[tokio::test(flavor = "multi_thread")]
async fn a_reply_header_removed_in_on_answer_stays_removed() {
    let response = answered(
        &on_answer(&[
            "reply.remove_header(\"Allow\")",
            "reply.remove_headers_matching(\"Supp\")",
            "reply.remove_header(\"Organization\")",
        ]),
        "transparent-b2bua@2026",
    );
    assert_eq!(header(&response, "Allow"), None);
    assert_eq!(header(&response, "Organization"), None);
    assert_eq!(supported_tags(&response), ["replaces"]);
}

/// The framework-managed headers stay siphon's: a script cannot point the
/// caller's dialog somewhere other than siphon.
#[tokio::test(flavor = "multi_thread")]
async fn framework_managed_headers_on_a_reply_stay_the_frameworks() {
    let response = answered(
        &on_answer(&["reply.set_header(\"Contact\", \"<sip:lab@203.0.113.9:5060>\")"]),
        "transparent-b2bua@2026",
    );
    let contact = header(&response, "Contact").expect("a Contact");
    assert!(
        !contact.contains("203.0.113.9"),
        "the Contact the caller sees is siphon's: {contact}"
    );
}

const EARLY_SDP: &str = concat!(
    "v=0\r\n",
    "o=- 2 2 IN IP4 198.51.100.7\r\n",
    "s=-\r\n",
    "c=IN IP4 198.51.100.7\r\n",
    "t=0 0\r\n",
    "m=audio 41000 RTP/AVP 0\r\n",
);

/// The callee's 183 with early-media SDP, which is what runs
/// `@b2bua.on_early_media`.
fn early_media_from_callee(invite: &SipMessage) -> SipMessage {
    let header = |name: &str| {
        invite
            .headers
            .get(name)
            .cloned()
            .unwrap_or_else(|| panic!("the carrier INVITE has no {name}"))
    };
    let raw = format!(
        concat!(
            "SIP/2.0 183 Session Progress\r\n",
            "Via: {via}\r\n",
            "From: {from}\r\n",
            "To: {to};tag=carrier-tag\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: {cseq}\r\n",
            "Contact: <sip:callee@198.51.100.7:5060>\r\n",
            "Supported: 100rel, outbound\r\n",
            "Allow: INVITE, ACK, BYE\r\n",
            "Content-Type: application/sdp\r\n",
            "Content-Length: {length}\r\n",
            "\r\n",
            "{sdp}",
        ),
        via = header("Via"),
        from = header("From"),
        to = header("To"),
        call_id = header("Call-ID"),
        cseq = header("CSeq"),
        length = EARLY_SDP.len(),
        sdp = EARLY_SDP,
    );
    parse_sip_message_bytes(raw.as_bytes()).expect("the 183 parses")
}

/// `@b2bua.on_early_media` shapes the 183 the caller gets the same way.
#[tokio::test(flavor = "multi_thread")]
async fn a_reply_header_set_in_on_early_media_reaches_the_caller() {
    let script = concat!(
        "from siphon import b2bua\n",
        "\n",
        "@b2bua.on_early_media\n",
        "def on_early_media(call, reply):\n",
        "    reply.set_header(\"Supported\", \"x-early-tag\")\n",
        "    reply.set_header(\"Allow\", \"INVITE, ACK\")\n",
    );
    let (sequence, invite) = call_under(script, "transparent-b2bua@2026");
    let mut progress = early_media_from_callee(&invite);
    let handled = handle_b2bua_response(
        &sequence.call_id,
        &top_via_branch(&invite),
        &mut progress,
        183,
        FIRST_CARRIER.parse().expect("a literal address"),
        &sequence.dispatcher.state,
    );
    assert!(handled, "the call was gone when the 183 arrived");
    let relayed = to_caller(sequence.wire(), 183);
    assert_eq!(supported_tags(&relayed), ["x-early-tag", "replaces"]);
    assert_eq!(header(&relayed, "Allow").as_deref(), Some("INVITE, ACK"));
}
