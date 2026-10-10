//! `@b2bua.on_provisional`: the hook for every provisional response the B2BUA
//! relays to the caller, with or without a session description.
//!
//! A 180 from a ringing phone carries no SDP, and it is the response a script
//! most often has something to say about: that the callee is being alerted at
//! all, and what the caller may be shown of it. The hook gets the call and the
//! response, and a header it sets or removes reaches the caller as it left it,
//! exactly as in `@b2bua.on_answer`. A provisional with SDP goes on to
//! `@b2bua.on_early_media` afterwards, with the same response.
//!
//! Driven through the dispatcher with the harness of
//! [`super::lcr_ring_timeout_tests`], the callee answering through
//! `handle_b2bua_response`, and what siphon relays read back off the UDP egress.

use super::lcr_ring_timeout_tests::{
    carrier, carrier_response, invite_to, summaries, top_via_branch, Sent, Sequence, CALLER,
    FIRST_CARRIER,
};
use super::*;

const EARLY_SDP: &str = concat!(
    "v=0\r\n",
    "o=- 2 2 IN IP4 198.51.100.7\r\n",
    "s=-\r\n",
    "c=IN IP4 198.51.100.7\r\n",
    "t=0 0\r\n",
    "m=audio 41000 RTP/AVP 0\r\n",
);

/// A call to one callee running `script`, with the INVITE the callee got.
fn call_running(script: &str) -> (Sequence, SipMessage) {
    let sequence =
        Sequence::start_with_script(vec![carrier("callee", FIRST_CARRIER, 30)], 30, script);
    let invite = invite_to(sequence.wire(), FIRST_CARRIER);
    (sequence, invite)
}

/// The callee answers `invite` with `status_code`, carrying `sdp` when given.
fn callee_responds(sequence: &Sequence, invite: &SipMessage, status_code: u16, sdp: Option<&str>) {
    let mut response = carrier_response(invite, status_code, "Reason");
    response
        .headers
        .set("Contact", "<sip:callee@198.51.100.7:5060>".to_string());
    if let Some(sdp) = sdp {
        response
            .headers
            .set("Content-Type", "application/sdp".to_string());
        response
            .headers
            .set("Content-Length", sdp.len().to_string());
        response.body = sdp.as_bytes().to_vec();
    }
    let handled = handle_b2bua_response(
        &sequence.call_id,
        &top_via_branch(invite),
        &mut response,
        status_code,
        FIRST_CARRIER.parse().expect("a literal address"),
        &sequence.dispatcher.state,
    );
    assert!(handled, "the call was gone when the {status_code} arrived");
}

/// The responses siphon sent the caller with `status_code`.
fn to_caller(sent: Vec<Sent>, status_code: u16) -> Vec<SipMessage> {
    let caller: SocketAddr = CALLER.parse().expect("a literal address");
    sent.into_iter()
        .filter(|sent| {
            sent.destination == caller && sent.message.status_code() == Some(status_code)
        })
        .map(|sent| sent.message)
        .collect()
}

fn the_one_to_caller(sequence: &Sequence, status_code: u16) -> SipMessage {
    let sent = sequence.wire();
    let listed = summaries(&sent);
    let mut relayed = to_caller(sent, status_code);
    assert_eq!(
        relayed.len(),
        1,
        "exactly one {status_code} to the caller, sent: {listed:?}"
    );
    relayed.remove(0)
}

fn header(message: &SipMessage, name: &str) -> Option<String> {
    message.headers.get(name).cloned()
}

/// What the hook is for: a 180 without SDP runs it, with the response in hand,
/// and a header it sets reaches the caller.
#[tokio::test(flavor = "multi_thread")]
async fn a_180_without_sdp_runs_on_provisional() {
    let script = concat!(
        "from siphon import b2bua\n",
        "\n",
        "@b2bua.on_provisional\n",
        "def on_provisional(call, reply):\n",
        "    reply.set_header(\"Privacy\", \"id\")\n",
        "    reply.set_header(\"X-Seen\", str(reply.status_code))\n",
    );
    let (sequence, invite) = call_running(script);
    callee_responds(&sequence, &invite, 180, None);

    let ringing = the_one_to_caller(&sequence, 180);
    assert_eq!(header(&ringing, "Privacy").as_deref(), Some("id"));
    assert_eq!(header(&ringing, "X-Seen").as_deref(), Some("180"));
    assert!(ringing.body.is_empty());
}

/// A header the hook removes stays removed, and the framework-managed ones
/// stay siphon's, as on any reply a script shapes.
#[tokio::test(flavor = "multi_thread")]
async fn on_provisional_shapes_the_relayed_response_like_on_answer() {
    let script = concat!(
        "from siphon import b2bua\n",
        "\n",
        "@b2bua.on_provisional\n",
        "def on_provisional(call, reply):\n",
        "    reply.remove_header(\"Allow\")\n",
        "    reply.set_header(\"Contact\", \"<sip:lab@203.0.113.9:5060>\")\n",
    );
    let (sequence, invite) = call_running(script);
    callee_responds(&sequence, &invite, 180, None);

    let ringing = the_one_to_caller(&sequence, 180);
    assert_eq!(header(&ringing, "Allow"), None);
    let contact = header(&ringing, "Contact").expect("a Contact");
    assert!(
        !contact.contains("203.0.113.9"),
        "the Contact the caller sees is siphon's: {contact}"
    );
}

/// A provisional with SDP runs both hooks on one response, `on_provisional`
/// first: `on_early_media` sees what it set, and both reach the caller.
#[tokio::test(flavor = "multi_thread")]
async fn a_183_with_sdp_runs_on_provisional_then_on_early_media() {
    let script = concat!(
        "from siphon import b2bua\n",
        "\n",
        "@b2bua.on_early_media\n",
        "def on_early_media(call, reply):\n",
        "    first = reply.get_header(\"X-Order\") or \"\"\n",
        "    reply.set_header(\"X-Order\", first + \" early_media\")\n",
        "\n",
        "@b2bua.on_provisional\n",
        "def on_provisional(call, reply):\n",
        "    reply.set_header(\"X-Order\", \"provisional\")\n",
    );
    let (sequence, invite) = call_running(script);
    callee_responds(&sequence, &invite, 183, Some(EARLY_SDP));

    let progress = the_one_to_caller(&sequence, 183);
    assert_eq!(
        header(&progress, "X-Order").as_deref(),
        Some("provisional early_media")
    );
    assert!(!progress.body.is_empty(), "the early media SDP is relayed");
}

/// `on_early_media` alone still sees only a provisional with SDP: a script
/// written before this hook existed runs as it did.
#[tokio::test(flavor = "multi_thread")]
async fn on_early_media_alone_still_skips_a_provisional_without_sdp() {
    let script = concat!(
        "from siphon import b2bua\n",
        "\n",
        "@b2bua.on_early_media\n",
        "def on_early_media(call, reply):\n",
        "    reply.set_header(\"X-Early\", \"yes\")\n",
    );
    let (sequence, invite) = call_running(script);
    callee_responds(&sequence, &invite, 180, None);
    assert_eq!(header(&the_one_to_caller(&sequence, 180), "X-Early"), None);

    callee_responds(&sequence, &invite, 183, Some(EARLY_SDP));
    assert_eq!(
        header(&the_one_to_caller(&sequence, 183), "X-Early").as_deref(),
        Some("yes")
    );
}

/// An awaiting handler is driven to completion before the response is relayed.
#[tokio::test(flavor = "multi_thread")]
async fn an_async_on_provisional_is_awaited() {
    let script = concat!(
        "import asyncio\n",
        "from siphon import b2bua\n",
        "\n",
        "@b2bua.on_provisional\n",
        "async def on_provisional(call, reply):\n",
        "    await asyncio.sleep(0)\n",
        "    reply.set_header(\"X-Awaited\", \"yes\")\n",
    );
    let (sequence, invite) = call_running(script);
    callee_responds(&sequence, &invite, 180, None);
    assert_eq!(
        header(&the_one_to_caller(&sequence, 180), "X-Awaited").as_deref(),
        Some("yes")
    );
}

/// A handler that raises decides nothing: the provisional is relayed as it
/// would have been without it.
#[tokio::test(flavor = "multi_thread")]
async fn an_on_provisional_that_raises_does_not_stop_the_relay() {
    let script = concat!(
        "from siphon import b2bua\n",
        "\n",
        "@b2bua.on_provisional\n",
        "def on_provisional(call, reply):\n",
        "    raise RuntimeError(\"no\")\n",
    );
    let (sequence, invite) = call_running(script);
    callee_responds(&sequence, &invite, 180, None);
    the_one_to_caller(&sequence, 180);
}

/// The hook runs for what is relayed, and a provisional that arrives after the
/// answer is not: it is dropped, as before, and the handler never sees it.
#[tokio::test(flavor = "multi_thread")]
async fn a_provisional_that_is_not_relayed_runs_no_hook() {
    let script = concat!(
        "from siphon import b2bua\n",
        "\n",
        "seen = []\n",
        "\n",
        "@b2bua.on_provisional\n",
        "def on_provisional(call, reply):\n",
        "    seen.append(reply.status_code)\n",
        "    reply.set_header(\"X-Count\", str(len(seen)))\n",
    );
    let (sequence, invite) = call_running(script);
    callee_responds(&sequence, &invite, 180, None);
    assert_eq!(
        header(&the_one_to_caller(&sequence, 180), "X-Count").as_deref(),
        Some("1")
    );

    callee_responds(&sequence, &invite, 200, Some(EARLY_SDP));
    sequence.wire();
    callee_responds(&sequence, &invite, 180, None);
    assert!(
        to_caller(sequence.wire(), 180).is_empty(),
        "a 180 after the answer was relayed"
    );
}
