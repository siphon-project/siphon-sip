//! What siphon says it supports on each leg of a B2BUA call.
//!
//! siphon is the UAC of the B-leg and the UAS of the A-leg, so the B-leg
//! INVITE's `Supported` (RFC 3261 §20.37) and `Allow` (§20.5), and those of
//! every response it relays to the caller, are siphon's own claims, not a relay
//! of the other party's. Driven through the dispatcher's own send and response
//! paths, with what siphon sent read back off the UDP egress.

use super::lcr_ring_timeout_tests::{invite_to, summaries, Sent, Sequence, FIRST_CARRIER};
use super::test_dispatcher::{test_dispatcher, test_dispatcher_with_script, TestDispatcher};
use super::*;
use crate::b2bua::header_policy::ResolvedPolicy;

const CALLEE: &str = "198.51.100.7:5060";
const CALLER: &str = "192.0.2.10:5060";

/// A caller listing extensions a B2BUA does not implement on the leg it
/// originates (`outbound`, `path`, `gruu`, `eventlist`, `answermode`,
/// `park-info`) next to ones it does (`100rel`, `timer`) and the ones the
/// endpoints negotiate through it (`precondition`, `histinfo`,
/// `resource-priority`), and an `Allow` that is not siphon's method set.
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
    "Supported: eventlist, answermode, park-info, histinfo, resource-priority\r\n",
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
/// INVITE siphon sent, parsed. A `policy` of `None` leaves the call on the
/// configured default (`transparent-b2bua@2026`).
fn b_leg_invite(caller: &str, policy: Option<ResolvedPolicy>) -> SipMessage {
    parse_sip_message_bytes(&b_leg_invite_bytes(caller, policy))
        .expect("siphon sent a B-leg INVITE that parses")
}

/// The same B-leg INVITE as [`b_leg_invite`], as the bytes that went out.
/// Parsing normalises a message into a header map, which is exactly where
/// header *order* is lost, so anything asserting on order has to read this.
fn b_leg_invite_bytes(caller: &str, policy: Option<ResolvedPolicy>) -> Vec<u8> {
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
        None,
        &[],
        &dispatcher.state,
    );
    assert!(dialled, "the B-leg INVITE was not sent");

    let mut invite = None;
    while let Ok(outbound) = dispatcher.udp.try_recv() {
        if outbound.destination.to_string() == CALLEE && outbound.data.starts_with(b"INVITE ") {
            invite = Some(outbound.data.to_vec());
        }
    }
    invite.unwrap_or_else(|| panic!("no INVITE to {CALLEE}"))
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
    assert_eq!(
        supported,
        tags(&[
            "100rel",
            "timer",
            "histinfo",
            "resource-priority",
            "replaces"
        ])
    );
}

/// An end-to-end tag belongs on the B-leg exactly when the call's policy relays
/// what that extension negotiates with, both ways: `Supported` and `Require`
/// for `precondition`, `History-Info` for `histinfo`, `Resource-Priority` out
/// and `Accept-Resource-Priority` back for `resource-priority`.
#[tokio::test(flavor = "multi_thread")]
async fn end_to_end_tags_cross_only_where_the_policy_relays_their_negotiation() {
    for (name, expected) in [
        (
            // Strips Supported/Require on responses; copies the rest.
            "transparent-b2bua@2026",
            tags(&[
                "100rel",
                "timer",
                "histinfo",
                "resource-priority",
                "replaces",
            ]),
        ),
        (
            "ims-intra-trust-domain@2026",
            tags(&[
                "100rel",
                "timer",
                "precondition",
                "histinfo",
                "resource-priority",
                "replaces",
            ]),
        ),
        (
            // Default-strip: History-Info, Resource-Priority and
            // Accept-Resource-Priority are not in its copy set.
            "ims-trust-domain-boundary@2026",
            tags(&["100rel", "timer", "precondition", "replaces"]),
        ),
        (
            // Strips History-Info on requests.
            "sip-trunk-edge@2026",
            tags(&[
                "100rel",
                "timer",
                "precondition",
                "resource-priority",
                "replaces",
            ]),
        ),
    ] {
        let invite = b_leg_invite(CALLER_INVITE, Some(preset(name)));
        assert_eq!(supported_tags(&invite), expected, "under {name}");
    }
}

/// Per-call deltas move the same test: each tag follows the headers its
/// extension rides on, in both directions, and nothing else.
#[tokio::test(flavor = "multi_thread")]
async fn deltas_on_the_negotiating_headers_move_the_end_to_end_tags() {
    let mut no_history = preset("ims-intra-trust-domain@2026");
    no_history.deltas_strip = vec!["History-Info".to_string()];
    let mut no_priority_answer = preset("ims-intra-trust-domain@2026");
    no_priority_answer.deltas_strip = vec!["Accept-Resource-Priority".to_string()];
    let mut boundary_history = preset("ims-trust-domain-boundary@2026");
    boundary_history.deltas_copy = vec!["History-Info".to_string()];
    let mut boundary_priority_out_only = preset("ims-trust-domain-boundary@2026");
    boundary_priority_out_only.deltas_copy = vec!["Resource-Priority".to_string()];
    let mut boundary_priority = preset("ims-trust-domain-boundary@2026");
    boundary_priority.deltas_copy = vec![
        "Resource-Priority".to_string(),
        "Accept-Resource-Priority".to_string(),
    ];

    for (label, policy, expected) in [
        (
            "intra-trust, strip=[History-Info]",
            no_history,
            tags(&[
                "100rel",
                "timer",
                "precondition",
                "resource-priority",
                "replaces",
            ]),
        ),
        (
            "intra-trust, strip=[Accept-Resource-Priority]",
            no_priority_answer,
            tags(&["100rel", "timer", "precondition", "histinfo", "replaces"]),
        ),
        (
            "boundary, copy=[History-Info]",
            boundary_history,
            tags(&["100rel", "timer", "precondition", "histinfo", "replaces"]),
        ),
        (
            "boundary, copy=[Resource-Priority]",
            boundary_priority_out_only,
            tags(&["100rel", "timer", "precondition", "replaces"]),
        ),
        (
            "boundary, copy=[Resource-Priority, Accept-Resource-Priority]",
            boundary_priority,
            tags(&[
                "100rel",
                "timer",
                "precondition",
                "resource-priority",
                "replaces",
            ]),
        ),
    ] {
        let invite = b_leg_invite(CALLER_INVITE, Some(policy));
        assert_eq!(supported_tags(&invite), expected, "{label}");
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
        tags(&[
            "100rel",
            "timer",
            "histinfo",
            "resource-priority",
            "replaces"
        ])
    );

    let mut copy_both = preset("transparent-b2bua@2026");
    copy_both.deltas_copy = vec!["Supported".to_string(), "Require".to_string()];
    let invite = b_leg_invite(CALLER_INVITE, Some(copy_both));
    assert_eq!(
        supported_tags(&invite),
        tags(&[
            "100rel",
            "timer",
            "precondition",
            "histinfo",
            "resource-priority",
            "replaces"
        ])
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
        client_transport: None,
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

// ----- Responses relayed to the caller -----

/// What the callee answers with: the tags siphon implements, the ones the
/// endpoints negotiate through siphon, ones nothing on the A-leg implements,
/// and the callee's own methods.
const CALLEE_CAPABILITIES: &[(&str, &str)] = &[
    (
        "Supported",
        "100rel, timer, precondition, histinfo, resource-priority, outbound, gruu",
    ),
    ("Allow", "INVITE, ACK, BYE"),
];

/// The callee answers the caller's call with `status_code`, advertising
/// [`CALLEE_CAPABILITIES`], under `policy`; returns the response siphon relayed
/// to the caller.
fn relayed_to_caller(policy: ResolvedPolicy, status_code: u16, reason: &str) -> SipMessage {
    let sequence = Sequence::start_fork(&[FIRST_CARRIER]);
    sequence
        .dispatcher
        .state
        .call_actors
        .get_call_mut(&sequence.call_id)
        .expect("the call exists")
        .resolved_header_policy = Some(Arc::new(policy));
    let invite = invite_to(sequence.wire(), FIRST_CARRIER);
    sequence.carrier_answers_with(
        FIRST_CARRIER,
        &invite,
        status_code,
        reason,
        CALLEE_CAPABILITIES,
    );
    let caller: SocketAddr = CALLER.parse().expect("a literal address");
    let sent = sequence.wire();
    let listed = summaries(&sent);
    sent.into_iter()
        .find(|sent| sent.destination == caller && sent.message.status_code() == Some(status_code))
        .map(|sent| sent.message)
        .unwrap_or_else(|| panic!("no {status_code} to the caller, sent: {listed:?}"))
}

/// The callee's `Allow` and extensions are no more siphon's to claim toward the
/// caller than the caller's are toward the callee. Every preset but the default
/// used to relay both verbatim, `outbound` and `gruu` included.
#[tokio::test(flavor = "multi_thread")]
async fn relayed_responses_advertise_siphons_capabilities_under_every_preset() {
    for (name, expected) in [
        (
            // Strips the callee's Supported on responses outright.
            "transparent-b2bua@2026",
            tags(&["replaces"]),
        ),
        (
            "ims-intra-trust-domain@2026",
            tags(&[
                "100rel",
                "timer",
                "precondition",
                "histinfo",
                "resource-priority",
                "replaces",
            ]),
        ),
        (
            "ims-trust-domain-boundary@2026",
            tags(&["100rel", "timer", "precondition", "replaces"]),
        ),
        (
            "sip-trunk-edge@2026",
            tags(&[
                "100rel",
                "timer",
                "precondition",
                "resource-priority",
                "replaces",
            ]),
        ),
    ] {
        for (status_code, reason) in [(183, "Session Progress"), (200, "OK"), (486, "Busy Here")] {
            let response = relayed_to_caller(preset(name), status_code, reason);
            assert_eq!(
                supported_tags(&response),
                expected,
                "{status_code} under {name}"
            );
            assert_eq!(
                allow(&response),
                Some(vec![crate::sip::SUPPORTED_METHODS.to_string()]),
                "{status_code} under {name}"
            );
        }
    }
}

/// The response direction reads the same per-call deltas: copying `Supported`
/// and `Require` onto the default preset relays the callee's `precondition`, and
/// its end-to-end tags with it, while `outbound` and `gruu` stay behind.
#[tokio::test(flavor = "multi_thread")]
async fn relayed_responses_follow_the_per_call_deltas() {
    let mut copy_both = preset("transparent-b2bua@2026");
    copy_both.deltas_copy = vec!["Supported".to_string(), "Require".to_string()];
    let response = relayed_to_caller(copy_both, 183, "Session Progress");
    assert_eq!(
        supported_tags(&response),
        tags(&[
            "100rel",
            "timer",
            "precondition",
            "histinfo",
            "resource-priority",
            "replaces"
        ])
    );

    let mut no_history = preset("ims-intra-trust-domain@2026");
    no_history.deltas_strip = vec!["History-Info".to_string()];
    let response = relayed_to_caller(no_history, 183, "Session Progress");
    assert_eq!(
        supported_tags(&response),
        tags(&[
            "100rel",
            "timer",
            "precondition",
            "resource-priority",
            "replaces"
        ])
    );
}

/// The reported regression, on the path that produced it.
///
/// `Supported` and `Allow` are settled by a `remove` + re-add — that is what
/// makes them siphon's claims rather than a relay of the caller's — and a
/// `remove` moves the header to the end of the map. Before the wire order was
/// owned by the serializer they went out *after* `Content-Length`, as did every
/// header injected once the body had been accounted for. None of the capability
/// logic changes here; the message just goes out in a fixed order.
#[tokio::test(flavor = "multi_thread")]
async fn the_b_leg_invite_goes_out_in_canonical_header_order() {
    let wire =
        String::from_utf8(b_leg_invite_bytes(CALLER_INVITE, None)).expect("siphon sent UTF-8");
    let names: Vec<&str> = wire
        .lines()
        .skip(1)
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.split_once(':').map(|(name, _)| name))
        .collect();

    assert_eq!(
        names.first(),
        Some(&"Via"),
        "Via leads the message (RFC 3261 §7.3.1), got {names:?}"
    );
    assert_eq!(
        names.last(),
        Some(&"Content-Length"),
        "Content-Length is the last header, got {names:?}"
    );

    let position = |name: &str| {
        names
            .iter()
            .position(|listed| listed.eq_ignore_ascii_case(name))
            .unwrap_or_else(|| panic!("no {name} on the B-leg INVITE, got {names:?}"))
    };
    let content_length = position("Content-Length");
    assert!(
        position("Supported") < content_length,
        "Supported must precede Content-Length, got {names:?}"
    );
    assert!(
        position("Allow") < content_length,
        "Allow must precede Content-Length, got {names:?}"
    );
    assert!(
        position("Contact") < position("Supported"),
        "the dialog headers lead the discretionary ones, got {names:?}"
    );
}
