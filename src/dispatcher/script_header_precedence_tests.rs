//! A header the script set or removed goes out on the B-leg INVITE as the script
//! left it, whatever the header policy says.
//!
//! Script headers are precedence 1: above the per-call `copy=` / `strip=` /
//! `translate=` deltas and above the preset, which may neither strip, rewrite
//! nor translate them. The framework-managed dialog and routing headers stay
//! the framework's. Driven through the INVITE handler, with the B-leg INVITE
//! read back off the UDP egress.

use super::lcr_ring_timeout_tests::{invite_to, summaries, Sent};
use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::*;

const CALLEE: &str = "198.51.100.7:5060";
const CALLER: &str = "192.0.2.10:5060";

/// A caller INVITE carrying a couple of headers a script might take off.
const CALLER_INVITE: &str = concat!(
    "INVITE sip:15550100042@siphon.example.com SIP/2.0\r\n",
    "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-script-headers\r\n",
    "Max-Forwards: 70\r\n",
    "From: <sip:15550100001@caller.example.com>;tag=caller-tag\r\n",
    "To: <sip:15550100042@siphon.example.com>\r\n",
    "Call-ID: script-headers@192.0.2.10\r\n",
    "CSeq: 1 INVITE\r\n",
    "Contact: <sip:caller@192.0.2.10:5060>\r\n",
    "Subject: the caller's subject\r\n",
    "X-Caller-Tag: from-the-caller\r\n",
    "Content-Length: 0\r\n",
    "\r\n",
);

fn wire(dispatcher: &TestDispatcher) -> Vec<Sent> {
    let mut sent = Vec::new();
    while let Ok(outbound) = dispatcher.udp.try_recv() {
        sent.push(Sent {
            destination: outbound.destination,
            message: parse_sip_message_bytes(&outbound.data)
                .expect("siphon sent a message that parses"),
        });
    }
    sent
}

/// Run an `@b2bua.on_invite` whose body is `lines` (one statement per entry) on
/// [`CALLER_INVITE`], and return everything siphon sent.
fn run_on_invite(lines: &[&str]) -> Vec<Sent> {
    let mut script =
        String::from("from siphon import b2bua\n\n@b2bua.on_invite\ndef on_invite(call):\n");
    for line in lines {
        script.push_str("    ");
        script.push_str(line);
        script.push('\n');
    }
    let dispatcher = test_dispatcher_with_script(&script);
    let inbound = InboundMessage {
        client_transport: None,
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: dispatcher.state.local_addr,
        remote_addr: CALLER.parse().expect("a literal address"),
        data: Bytes::from_static(CALLER_INVITE.as_bytes()),
    };
    let invite =
        parse_sip_message_bytes(CALLER_INVITE.as_bytes()).expect("the caller INVITE parses");
    handle_b2bua_invite(inbound, invite, &dispatcher.state);
    wire(&dispatcher)
}

/// [`run_on_invite`], returning the B-leg INVITE.
fn b_leg_invite(lines: &[&str]) -> SipMessage {
    invite_to(run_on_invite(lines), CALLEE)
}

fn header(message: &SipMessage, name: &str) -> Option<String> {
    message.headers.get(name).cloned()
}

/// `ims-trust-domain-boundary@2026` strips every request header outside its
/// safe set. Headers the script set are not the caller's to hide: they cross.
#[tokio::test(flavor = "multi_thread")]
async fn a_script_header_outranks_a_preset_strip() {
    let invite = b_leg_invite(&[
        "call.set_header(\"X-Lab-Tag\", \"set-by-the-script\")",
        "call.set_header(\"Alert-Info\", \"<urn:alert:service:normal>\")",
        "call.dial(\"sip:15550100042@198.51.100.7:5060\", header_policy=\"ims-trust-domain-boundary@2026\")",
    ]);
    assert_eq!(
        header(&invite, "X-Lab-Tag").as_deref(),
        Some("set-by-the-script")
    );
    assert_eq!(
        header(&invite, "Alert-Info").as_deref(),
        Some("<urn:alert:service:normal>")
    );
    // The caller's own headers still get the preset.
    assert_eq!(header(&invite, "X-Caller-Tag"), None);
}

/// A per-call `strip=` is precedence 2, below the script.
#[tokio::test(flavor = "multi_thread")]
async fn a_script_header_outranks_a_strip_delta() {
    let invite = b_leg_invite(&[
        "call.set_header(\"Subject\", \"the script's subject\")",
        "call.dial(\"sip:15550100042@198.51.100.7:5060\", strip=[\"Subject\", \"X-Caller-Tag\"])",
    ]);
    assert_eq!(
        header(&invite, "Subject").as_deref(),
        Some("the script's subject")
    );
    assert_eq!(header(&invite, "X-Caller-Tag"), None);
}

/// A preset rewrite does not touch a script header either:
/// `transparent-b2bua@2026` replaces `User-Agent` with siphon's (here, with
/// none configured, drops it) and moves the `P-Asserted-Identity` host to
/// siphon's address.
#[tokio::test(flavor = "multi_thread")]
async fn a_script_header_is_not_rewritten_by_the_preset() {
    let invite = b_leg_invite(&[
        "call.set_header(\"User-Agent\", \"lab-agent/1.0\")",
        "call.set_header(\"P-Asserted-Identity\", \"<sip:+15550100001@caller.example.com>\")",
        "call.dial(\"sip:15550100042@198.51.100.7:5060\")",
    ]);
    assert_eq!(
        header(&invite, "User-Agent").as_deref(),
        Some("lab-agent/1.0")
    );
    assert_eq!(
        header(&invite, "P-Asserted-Identity").as_deref(),
        Some("<sip:+15550100001@caller.example.com>")
    );
}

/// ...nor translate it: the trust boundary turns `Diversion` into
/// `History-Info`, but a `Diversion` the script wrote goes out as `Diversion`.
#[tokio::test(flavor = "multi_thread")]
async fn a_script_header_is_not_translated_by_the_preset() {
    let invite = b_leg_invite(&[
        "call.set_header(\"Diversion\", \"<sip:15550100099@caller.example.com>;reason=unconditional\")",
        "call.dial(\"sip:15550100042@198.51.100.7:5060\", header_policy=\"ims-trust-domain-boundary@2026\")",
    ]);
    assert_eq!(
        header(&invite, "Diversion").as_deref(),
        Some("<sip:15550100099@caller.example.com>;reason=unconditional")
    );
    assert_eq!(header(&invite, "History-Info"), None);
}

/// Removal is the script's value too, under a policy that would copy the
/// header, and `remove_headers_matching` counts as well.
#[tokio::test(flavor = "multi_thread")]
async fn a_script_removal_stays_removed() {
    let invite = b_leg_invite(&[
        "call.remove_header(\"Subject\")",
        "call.remove_headers_matching(\"X-\")",
        "call.dial(\"sip:15550100042@198.51.100.7:5060\")",
    ]);
    assert_eq!(header(&invite, "Subject"), None);
    assert_eq!(header(&invite, "X-Caller-Tag"), None);
}

/// A header set after a prefix removal is still the script's: under
/// `ims-intra-trust-domain@2026`, which strips `X-*`, the script's `X-` header
/// crosses and the caller's stays behind.
#[tokio::test(flavor = "multi_thread")]
async fn a_script_header_set_after_a_prefix_removal_crosses_a_prefix_strip() {
    let invite = b_leg_invite(&[
        "call.remove_headers_matching(\"X-\")",
        "call.set_header(\"X-Lab-Tag\", \"set-by-the-script\")",
        "call.dial(\"sip:15550100042@198.51.100.7:5060\", header_policy=\"ims-intra-trust-domain@2026\")",
    ]);
    assert_eq!(
        header(&invite, "X-Lab-Tag").as_deref(),
        Some("set-by-the-script")
    );
    assert_eq!(header(&invite, "X-Caller-Tag"), None);
}

/// Framework-managed headers stay the framework's: a script cannot move the
/// B-leg dialog's Contact or Call-ID.
#[tokio::test(flavor = "multi_thread")]
async fn framework_managed_headers_stay_the_frameworks() {
    let invite = b_leg_invite(&[
        "call.set_header(\"Contact\", \"<sip:lab@203.0.113.9:5060>\")",
        "call.set_header(\"Call-ID\", \"set-by-the-script@203.0.113.9\")",
        "call.dial(\"sip:15550100042@198.51.100.7:5060\")",
    ]);
    let contact = header(&invite, "Contact").expect("a Contact");
    assert!(
        !contact.contains("203.0.113.9"),
        "the B-leg Contact is siphon's: {contact}"
    );
    assert_ne!(
        header(&invite, "Call-ID").as_deref(),
        Some("set-by-the-script@203.0.113.9")
    );
}

/// A `Require` the script wrote reaches the callee whatever the policy, so it
/// counts as shown to the callee when siphon decides whether the call can
/// honour it (RFC 3261 §8.2.2.3): no 420 here, despite `strip=["Require"]`.
#[tokio::test(flavor = "multi_thread")]
async fn a_script_require_reaches_the_callee_and_is_not_refused() {
    let sent = run_on_invite(&[
        "call.set_header(\"Require\", \"histinfo\")",
        "call.dial(\"sip:15550100042@198.51.100.7:5060\", header_policy=\"ims-intra-trust-domain@2026\", strip=[\"Require\"])",
    ]);
    let listed = summaries(&sent);
    let invite = invite_to(sent, CALLEE);
    assert_eq!(
        header(&invite, "Require").as_deref(),
        Some("histinfo"),
        "sent: {listed:?}"
    );
}
