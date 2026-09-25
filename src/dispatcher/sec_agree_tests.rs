//! A B2BUA INVITE that requires `sec-agree` is verified against the security
//! agreement it arrived under (RFC 3329 §2.3.1), and that agreement stays on
//! the hop it was made on.
//!
//! Driven through the INVITE handler, with what siphon sent read back off the
//! UDP egress. A unit-test binary installs no IPsec runtime, so every request
//! here arrives unprotected; the protected half, a Security-Verify checked
//! against a real SA, is tested against a constructed SA in `ipsec::sec_agree`.

use super::lcr_ring_timeout_tests::{invite_to, summaries, Sent};
use super::test_dispatcher::{test_dispatcher, test_dispatcher_with_script, TestDispatcher};
use super::*;

const CALLEE: &str = "198.51.100.7:5060";
const CALLER: &str = "192.0.2.10:5060";

/// The Security-Verify a UE mirrors from the P-CSCF's Security-Server.
const SECURITY_VERIFY: &str =
    "ipsec-3gpp;prot=esp;mod=trans;spi-c=10000;spi-s=10001;port-c=5064;port-s=5066;alg=hmac-sha-1-96;ealg=null";

/// A caller INVITE with `extra` header lines.
fn caller_invite(extra: &str) -> String {
    format!(
        concat!(
            "INVITE sip:15550100042@siphon.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-sec-agree\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:15550100001@caller.example.com>;tag=caller-tag\r\n",
            "To: <sip:15550100042@siphon.example.com>\r\n",
            "Call-ID: sec-agree@192.0.2.10\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:caller@192.0.2.10:5060>\r\n",
            "{extra}",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        extra = extra,
    )
}

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

const DIAL: &str = concat!(
    "from siphon import b2bua\n",
    "\n",
    "@b2bua.on_invite\n",
    "def on_invite(call):\n",
    "    call.dial(\"sip:15550100042@198.51.100.7:5060\")\n",
);

/// Run `script` on a caller INVITE carrying `extra`; everything siphon sent.
fn place_call(script: &str, extra: &str) -> Vec<Sent> {
    let dispatcher = test_dispatcher_with_script(script);
    let raw = caller_invite(extra);
    let inbound = InboundMessage {
        client_transport: None,
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: dispatcher.state.local_addr,
        remote_addr: CALLER.parse().expect("a literal address"),
        data: Bytes::from(raw.clone().into_bytes()),
    };
    let invite = parse_sip_message_bytes(raw.as_bytes()).expect("the caller INVITE parses");
    handle_b2bua_invite(inbound, invite, &dispatcher.state);
    wire(&dispatcher)
}

fn reason(message: &SipMessage) -> String {
    match &message.start_line {
        StartLine::Response(status_line) => status_line.reason_phrase.clone(),
        StartLine::Request(_) => String::new(),
    }
}

/// RFC 3329 §2.3.1: "A server receiving an unprotected request that contains a
/// Require or Proxy-Require header field with the value "sec-agree" MUST respond
/// to the client with a 494 (Security Agreement Required) response." A request
/// that did not arrive over an SA cannot have been verified, whatever
/// Security-Verify it carries, so nothing else happens to it.
#[tokio::test(flavor = "multi_thread")]
async fn an_unprotected_invite_requiring_sec_agree_is_refused_494() {
    for extra in [
        format!(
            "Require: sec-agree\r\nProxy-Require: sec-agree\r\nSecurity-Verify: {SECURITY_VERIFY}\r\n"
        ),
        "Proxy-Require: sec-agree\r\n".to_string(),
        "Require: precondition, sec-agree\r\n".to_string(),
    ] {
        let sent = place_call(DIAL, &extra);
        assert_eq!(
            summaries(&sent),
            [format!("494 to {CALLER}")],
            "nothing but the 494 for {extra:?}"
        );
        assert_eq!(reason(&sent[0].message), "Security Agreement Required");
    }
}

/// The 494 to an unprotected request names what siphon supports: one
/// `ipsec-3gpp` line per transform, with its algorithms and no SPI or port,
/// since there is no association for those to name.
#[tokio::test(flavor = "multi_thread")]
async fn the_494_to_an_unprotected_invite_lists_the_mechanisms_siphon_supports() {
    let sent = place_call(DIAL, "Require: sec-agree\r\n");
    assert_eq!(summaries(&sent), [format!("494 to {CALLER}")]);
    let lines = sent[0]
        .message
        .headers
        .get_all("Security-Server")
        .cloned()
        .unwrap_or_default();
    assert_eq!(lines.len(), 6, "{lines:?}");
    for line in &lines {
        assert!(line.starts_with("ipsec-3gpp; alg="), "{line}");
        assert!(line.contains("; ealg="), "{line}");
        assert!(!line.contains("spi-") && !line.contains("port-"), "{line}");
    }
}

/// An INVITE that does not require `sec-agree` is not held to it: merely
/// supporting the extension is no reason to verify anything.
#[tokio::test(flavor = "multi_thread")]
async fn an_invite_that_only_supports_sec_agree_is_dialled() {
    let sent = place_call(DIAL, "Supported: sec-agree\r\n");
    assert_eq!(
        summaries(&sent),
        [format!("100 to {CALLER}"), format!("INVITE to {CALLEE}")]
    );
}

/// The agreement belongs to the caller's hop. Its Security-Verify and
/// Security-Client describe the caller's SA with siphon, which the callee has no
/// part in, so they do not cross to the B-leg.
#[tokio::test(flavor = "multi_thread")]
async fn the_callers_security_agreement_headers_stay_off_the_b_leg() {
    let sent = place_call(
        DIAL,
        &format!("Security-Verify: {SECURITY_VERIFY}\r\nSecurity-Client: {SECURITY_VERIFY}\r\n"),
    );
    let invite = invite_to(sent, CALLEE);
    assert_eq!(invite.headers.get("Security-Verify"), None);
    assert_eq!(invite.headers.get("Security-Client"), None);
}

/// A caller whose `sec-agree` siphon verified: siphon is the server that
/// agreement was made with, and RFC 3329 §2.3.1 has it "remove the "sec-agree"
/// value from both the Require and Proxy-Require header fields, and then remove
/// the header fields if no values remain" before the request goes on.
#[tokio::test(flavor = "multi_thread")]
async fn a_verified_callers_sec_agree_is_removed_from_the_b_leg() {
    let dispatcher = test_dispatcher();
    let raw = caller_invite(&format!(
        "Require: sec-agree, precondition\r\nProxy-Require: sec-agree\r\nSecurity-Verify: {SECURITY_VERIFY}\r\n"
    ));
    let caller = parse_sip_message_bytes(raw.as_bytes()).expect("the caller INVITE parses");
    let call_id = dispatcher.state.call_actors.create_call(Leg::new_a_leg(
        "sec-agree@192.0.2.10".to_string(),
        "caller-tag".to_string(),
        "z9hG4bK-sec-agree".to_string(),
        LegTransport {
            remote_addr: CALLER.parse().expect("a literal address"),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    ));
    let dialled = b2bua_send_b_leg_invite(
        &call_id,
        &format!("sip:15550100042@{CALLEE}"),
        None,
        None,
        &[],
        None,
        None,
        &caller,
        None,
        None,
        None,
        None,
        None,
        &[],
        &dispatcher.state,
    );
    assert!(dialled);
    let invite = invite_to(wire(&dispatcher), CALLEE);
    assert_eq!(
        invite.headers.get("Require").map(String::as_str),
        Some("precondition")
    );
    assert_eq!(invite.headers.get("Proxy-Require"), None);
    assert_eq!(invite.headers.get("Security-Verify"), None);
}

/// A script that sets up the B-leg's own agreement (siphon dialling out over its
/// own SA) keeps what it set: script headers are precedence 1.
#[tokio::test(flavor = "multi_thread")]
async fn a_security_agreement_the_script_sets_goes_out_on_the_b_leg() {
    let script = concat!(
        "from siphon import b2bua\n",
        "\n",
        "@b2bua.on_invite\n",
        "def on_invite(call):\n",
        "    call.set_header(\"Security-Verify\", \"ipsec-3gpp;spi-c=20000;spi-s=20001;port-c=6100;port-s=6101;alg=hmac-sha-1-96\")\n",
        "    call.set_header(\"Proxy-Require\", \"sec-agree\")\n",
        "    call.dial(\"sip:15550100042@198.51.100.7:5060\")\n",
    );
    let invite = invite_to(place_call(script, ""), CALLEE);
    assert!(invite.headers.has("Security-Verify"));
    assert_eq!(
        invite.headers.get("Proxy-Require").map(String::as_str),
        Some("sec-agree")
    );
}

/// `sec-agree` counts as honoured only on a call whose agreement was verified.
/// A script that makes an unverified caller require it has the call refused
/// with the response RFC 3329 names, not dialled as if it were agreed.
#[tokio::test(flavor = "multi_thread")]
async fn a_required_sec_agree_on_an_unverified_call_is_refused_494_at_routing() {
    let script = concat!(
        "from siphon import b2bua\n",
        "\n",
        "@b2bua.on_invite\n",
        "def on_invite(call):\n",
        "    call.set_header(\"Require\", \"sec-agree\")\n",
        "    call.dial(\"sip:15550100042@198.51.100.7:5060\")\n",
    );
    let sent = place_call(script, "");
    assert_eq!(
        summaries(&sent),
        [format!("100 to {CALLER}"), format!("494 to {CALLER}")]
    );
    // RFC 3329 §2.3.1 has every 494 list the server's mechanisms, and this
    // caller arrived over no association for them to name.
    let lines = sent[1]
        .message
        .headers
        .get_all("Security-Server")
        .cloned()
        .unwrap_or_default();
    assert_eq!(lines.len(), 6, "{lines:?}");
    assert!(lines.iter().all(|line| !line.contains("spi-")), "{lines:?}");
}
