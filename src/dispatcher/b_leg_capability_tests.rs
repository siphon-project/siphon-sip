//! What the B-leg INVITE says siphon supports.
//!
//! siphon is the UAC of the B-leg, so that INVITE's `Supported` (RFC 3261
//! §20.37) and `Allow` (§20.5) are siphon's own claims, not a relay of the
//! caller's. Driven through the dispatcher's own send path, with the B-leg
//! INVITE read back off the UDP egress.

use super::lcr_ring_timeout_tests::{invite_to, Sent};
use super::test_dispatcher::{test_dispatcher, test_dispatcher_with_script, TestDispatcher};
use super::*;
use crate::b2bua::header_policy::ResolvedPolicy;

const CALLEE: &str = "198.51.100.7:5060";
const CALLER: &str = "192.0.2.10:5060";

/// A caller listing extensions a B2BUA does not implement on the leg it
/// originates (`outbound`, `path`, `gruu`, `eventlist`, `answermode`,
/// `park-info`, `histinfo`) next to ones it does (`100rel`, `timer`) and one
/// the endpoints negotiate through it (`precondition`), and an `Allow` that is
/// not siphon's method set.
const CALLER_INVITE: &str = concat!(
    "INVITE sip:15550100042@siphon.example.com SIP/2.0\r\n",
    "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-caps\r\n",
    "Max-Forwards: 70\r\n",
    "From: <sip:15550100001@caller.example.com>;tag=caller-tag\r\n",
    "To: <sip:15550100042@siphon.example.com>\r\n",
    "Call-ID: b-leg-caps@192.0.2.10\r\n",
    "CSeq: 1 INVITE\r\n",
    "Contact: <sip:caller@192.0.2.10:5060>\r\n",
    "Supported: 100rel, timer, precondition, outbound, path, gruu\r\n",
    "Supported: eventlist, answermode, park-info, histinfo\r\n",
    "Allow: INVITE, ACK, BYE, CANCEL, PRACK, UPDATE, SUBSCRIBE, NOTIFY, PUBLISH\r\n",
    "Content-Length: 0\r\n",
    "\r\n",
);

/// A caller that lists no extensions and no methods at all.
const BARE_CALLER_INVITE: &str = concat!(
    "INVITE sip:15550100042@siphon.example.com SIP/2.0\r\n",
    "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-caps\r\n",
    "Max-Forwards: 70\r\n",
    "From: <sip:15550100001@caller.example.com>;tag=caller-tag\r\n",
    "To: <sip:15550100042@siphon.example.com>\r\n",
    "Call-ID: b-leg-caps@192.0.2.10\r\n",
    "CSeq: 1 INVITE\r\n",
    "Contact: <sip:caller@192.0.2.10:5060>\r\n",
    "Content-Length: 0\r\n",
    "\r\n",
);

/// The tags siphon never claims on a B-leg, whatever the caller lists.
const NOT_SIPHONS: &[&str] = &[
    "outbound",
    "path",
    "gruu",
    "eventlist",
    "answermode",
    "park-info",
    "histinfo",
];

fn parse(raw: &str) -> SipMessage {
    parse_sip_message_bytes(raw.as_bytes()).expect("the caller INVITE parses")
}

/// Everything siphon has put on the wire so far, in order.
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

/// The option tags of every `Supported` line, lowercased, in wire order.
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

fn allow(message: &SipMessage) -> Option<Vec<String>> {
    message.headers.get_all("Allow").cloned()
}

/// Dial `caller`'s call to [`CALLEE`] under `policy` and return the B-leg
/// INVITE siphon sent. A `policy` of `None` leaves the call on the configured
/// default (`transparent-b2bua@2026`).
fn b_leg_invite(caller: &str, policy: Option<ResolvedPolicy>) -> SipMessage {
    let dispatcher = test_dispatcher();
    let call_id = dispatcher.state.call_actors.create_call(Leg::new_a_leg(
        "b-leg-caps@192.0.2.10".to_string(),
        "caller-tag".to_string(),
        "z9hG4bK-caps".to_string(),
        LegTransport {
            remote_addr: CALLER.parse().expect("a literal address"),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    ));
    if let Some(policy) = policy {
        dispatcher
            .state
            .call_actors
            .get_call_mut(&call_id)
            .expect("the call exists")
            .resolved_header_policy = Some(Arc::new(policy));
    }
    let dialled = b2bua_send_b_leg_invite(
        &call_id,
        &format!("sip:15550100042@{CALLEE}"),
        None,
        None,
        &[],
        None,
        None,
        &parse(caller),
        None,
        None,
        None,
        None,
        &[],
        &dispatcher.state,
    );
    assert!(dialled, "the B-leg INVITE was not sent");
    invite_to(wire(&dispatcher), CALLEE)
}

/// A built-in preset by name, with no per-call deltas.
fn preset(name: &str) -> ResolvedPolicy {
    let preset = crate::b2bua::header_policy::builtin_presets()
        .get(name)
        .cloned()
        .unwrap_or_else(|| panic!("no built-in preset {name}"));
    ResolvedPolicy::from_preset(preset)
}

fn tags(expected: &[&str]) -> Vec<String> {
    expected.iter().map(|tag| tag.to_string()).collect()
}

/// The bug: every tag the caller listed went out on the B-leg as siphon's own
/// claim, so a callee could pick an extension (an `outbound` flow, a GRUU, an
/// event list) that nothing on this leg implements.
#[tokio::test(flavor = "multi_thread")]
async fn the_b_leg_advertises_siphons_extensions_not_the_callers() {
    let invite = b_leg_invite(CALLER_INVITE, None);
    let supported = supported_tags(&invite);
    for tag in NOT_SIPHONS {
        assert!(
            !supported.iter().any(|listed| listed == tag),
            "`{tag}` is the caller's extension, not siphon's: {supported:?}"
        );
    }
    assert_eq!(supported, tags(&["100rel", "timer", "replaces"]));
}

/// `precondition` is negotiated between the two endpoints, so it belongs on the
/// B-leg exactly when the call's policy relays `Supported` and `Require` both
/// ways; a policy that strips the callee's `Require` on the way back would
/// leave the caller unable to see the answer's preconditions.
#[tokio::test(flavor = "multi_thread")]
async fn precondition_crosses_only_under_a_policy_that_relays_capability_negotiation() {
    let relayed = tags(&["100rel", "timer", "precondition", "replaces"]);
    let withheld = tags(&["100rel", "timer", "replaces"]);
    for (name, expected) in [
        ("transparent-b2bua@2026", &withheld),
        ("ims-intra-trust-domain@2026", &relayed),
        ("ims-trust-domain-boundary@2026", &relayed),
        ("sip-trunk-edge@2026", &relayed),
    ] {
        let invite = b_leg_invite(CALLER_INVITE, Some(preset(name)));
        assert_eq!(&supported_tags(&invite), expected, "under {name}");
    }
}

/// `copy=["Supported"]` names a header the request direction of every built-in
/// preset already copies, so it cannot relay the caller's list verbatim
/// either. Copying `Require` as well does open capability negotiation on a
/// policy that strips both on responses, and `precondition` follows.
#[tokio::test(flavor = "multi_thread")]
async fn a_copy_delta_relays_capability_negotiation_not_the_callers_list() {
    let mut copy_supported = preset("transparent-b2bua@2026");
    copy_supported.deltas_copy = vec!["Supported".to_string()];
    let invite = b_leg_invite(CALLER_INVITE, Some(copy_supported));
    assert_eq!(
        supported_tags(&invite),
        tags(&["100rel", "timer", "replaces"])
    );

    let mut copy_both = preset("transparent-b2bua@2026");
    copy_both.deltas_copy = vec!["Supported".to_string(), "Require".to_string()];
    let invite = b_leg_invite(CALLER_INVITE, Some(copy_both));
    assert_eq!(
        supported_tags(&invite),
        tags(&["100rel", "timer", "precondition", "replaces"])
    );
}

/// A policy that strips `Supported` on requests keeps every caller tag off the
/// B-leg, `100rel` included, as it did before; siphon's own `replaces` stays.
#[tokio::test(flavor = "multi_thread")]
async fn a_strip_delta_keeps_every_caller_tag_off_the_b_leg() {
    let mut strip_supported = preset("ims-intra-trust-domain@2026");
    strip_supported.deltas_strip = vec!["Supported".to_string()];
    let invite = b_leg_invite(CALLER_INVITE, Some(strip_supported));
    assert_eq!(supported_tags(&invite), tags(&["replaces"]));
}

/// `100rel` and `timer` are only claimed when the caller offered them: a caller
/// with no `Supported` gets siphon's unconditional `replaces` and nothing else.
#[tokio::test(flavor = "multi_thread")]
async fn a_caller_offering_nothing_gets_only_siphons_unconditional_tags() {
    for name in [
        "transparent-b2bua@2026",
        "ims-intra-trust-domain@2026",
        "ims-trust-domain-boundary@2026",
        "sip-trunk-edge@2026",
    ] {
        let invite = b_leg_invite(BARE_CALLER_INVITE, Some(preset(name)));
        assert_eq!(supported_tags(&invite), tags(&["replaces"]), "under {name}");
    }
}

/// `Allow` is siphon's method set on every preset — including
/// `ims-trust-domain-boundary@2026`, which names `Allow` in its request copy
/// set — and whether or not the caller sent one.
#[tokio::test(flavor = "multi_thread")]
async fn the_b_leg_allow_is_siphons_method_set() {
    let siphons = Some(vec![crate::sip::SUPPORTED_METHODS.to_string()]);
    for name in [
        "transparent-b2bua@2026",
        "ims-intra-trust-domain@2026",
        "ims-trust-domain-boundary@2026",
        "sip-trunk-edge@2026",
    ] {
        for caller in [CALLER_INVITE, BARE_CALLER_INVITE] {
            let invite = b_leg_invite(caller, Some(preset(name)));
            assert_eq!(allow(&invite), siphons, "under {name}");
        }
    }
}

/// Run `script`'s `@b2bua.on_invite` on [`CALLER_INVITE`] through the INVITE
/// handler and return the B-leg INVITE it dialled.
fn b_leg_invite_from_script(script: &str) -> SipMessage {
    let dispatcher = test_dispatcher_with_script(script);
    let inbound = InboundMessage {
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: dispatcher.state.local_addr,
        remote_addr: CALLER.parse().expect("a literal address"),
        data: Bytes::from_static(CALLER_INVITE.as_bytes()),
    };
    handle_b2bua_invite(inbound, parse(CALLER_INVITE), &dispatcher.state);
    invite_to(wire(&dispatcher), CALLEE)
}

/// A script's `call.set_header()` is precedence 1: its `Supported` and `Allow`
/// reach the B-leg as written, extensions siphon does not implement included,
/// with only `replaces` merged in as it always was.
#[tokio::test(flavor = "multi_thread")]
async fn a_script_set_header_wins_over_siphons_capabilities() {
    let invite = b_leg_invite_from_script(concat!(
        "from siphon import b2bua\n",
        "\n",
        "@b2bua.on_invite\n",
        "def on_invite(call):\n",
        "    call.set_header(\"Supported\", \"100rel, outbound, x-lab-tag\")\n",
        "    call.set_header(\"Allow\", \"INVITE, ACK, BYE\")\n",
        "    call.dial(\"sip:15550100042@198.51.100.7:5060\")\n",
    ));
    assert_eq!(
        supported_tags(&invite),
        tags(&["100rel", "outbound", "x-lab-tag", "replaces"])
    );
    assert_eq!(allow(&invite), Some(vec!["INVITE, ACK, BYE".to_string()]));
}

/// Writing the caller's own list back is how a script relays it verbatim, so
/// it must count as the script's value even though nothing about it changed.
#[tokio::test(flavor = "multi_thread")]
async fn a_script_writing_back_the_callers_supported_relays_it() {
    let invite = b_leg_invite_from_script(concat!(
        "from siphon import b2bua\n",
        "\n",
        "@b2bua.on_invite\n",
        "def on_invite(call):\n",
        "    call.set_header(\"Supported\", call.get_header(\"Supported\"))\n",
        "    call.dial(\"sip:15550100042@198.51.100.7:5060\")\n",
    ));
    assert_eq!(
        supported_tags(&invite),
        tags(&[
            "100rel",
            "timer",
            "precondition",
            "outbound",
            "path",
            "gruu",
            "replaces"
        ])
    );
}

/// A script header outranks the policy's per-call deltas too: a `strip=` on
/// the header the script set does not drop the script's value.
#[tokio::test(flavor = "multi_thread")]
async fn a_script_set_header_outranks_a_strip_delta() {
    let invite = b_leg_invite_from_script(concat!(
        "from siphon import b2bua\n",
        "\n",
        "@b2bua.on_invite\n",
        "def on_invite(call):\n",
        "    call.set_header(\"Supported\", \"100rel, x-lab-tag\")\n",
        "    call.dial(\"sip:15550100042@198.51.100.7:5060\", strip=[\"Supported\"])\n",
    ));
    assert_eq!(
        supported_tags(&invite),
        tags(&["100rel", "x-lab-tag", "replaces"])
    );
}

/// `call.remove_header("Allow")` is the script's value too: no `Allow` at all.
#[tokio::test(flavor = "multi_thread")]
async fn a_script_remove_header_wins_over_siphons_allow() {
    let invite = b_leg_invite_from_script(concat!(
        "from siphon import b2bua\n",
        "\n",
        "@b2bua.on_invite\n",
        "def on_invite(call):\n",
        "    call.remove_header(\"Allow\")\n",
        "    call.dial(\"sip:15550100042@198.51.100.7:5060\")\n",
    ));
    assert_eq!(allow(&invite), None);
}
