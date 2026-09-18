//! A caller that `Require`s an extension the call cannot honour gets `420 Bad
//! Extension` (RFC 3261 §8.2.2.3), before any B-leg goes out.
//!
//! "Cannot honour" is decided per call, once the script has picked the header
//! policy: siphon does not implement the extension itself, and the policy does
//! not relay what the two endpoints would negotiate it with. Driven through the
//! INVITE handler, with what siphon sent read back off the UDP egress.

use super::lcr_ring_timeout_tests::{summaries, Sent};
use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::*;

const CALLEE: &str = "198.51.100.7:5060";
const CALLER: &str = "192.0.2.10:5060";

/// A caller's INVITE carrying `require` as its `Require`.
fn caller_invite(require: &str) -> String {
    format!(
        concat!(
            "INVITE sip:15550100042@siphon.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-require\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:15550100001@caller.example.com>;tag=caller-tag\r\n",
            "To: <sip:15550100042@siphon.example.com>\r\n",
            "Call-ID: require@192.0.2.10\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:caller@192.0.2.10:5060>\r\n",
            "Supported: 100rel, timer\r\n",
            "Require: {require}\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        require = require,
    )
}

/// A script whose `@b2bua.on_invite` runs `routing` on the call.
fn routing_script(routing: &str) -> String {
    format!(
        concat!(
            "from siphon import b2bua\n",
            "\n",
            "@b2bua.on_invite\n",
            "def on_invite(call):\n",
            "    {routing}\n",
        ),
        routing = routing,
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

/// Run `script` on a caller INVITE that `Require`s `require`, and return
/// everything siphon sent.
fn place_call(script: &str, require: &str) -> Vec<Sent> {
    let dispatcher = test_dispatcher_with_script(script);
    let raw = caller_invite(require);
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

/// The response to the caller with `status_code`.
fn response_to_caller(sent: &[Sent], status_code: u16) -> &SipMessage {
    let caller: SocketAddr = CALLER.parse().expect("a literal address");
    sent.iter()
        .find(|sent| sent.destination == caller && sent.message.status_code() == Some(status_code))
        .map(|sent| &sent.message)
        .unwrap_or_else(|| {
            panic!(
                "no {status_code} to the caller, sent: {:?}",
                summaries(sent)
            )
        })
}

const DIAL: &str = "call.dial(\"sip:15550100042@198.51.100.7:5060\")";

fn dial_under(policy: &str) -> String {
    format!("call.dial(\"sip:15550100042@198.51.100.7:5060\", header_policy=\"{policy}\")")
}

/// `Require: precondition` under the default preset, which strips the callee's
/// `Require` and `Supported` on responses: the callee could never tell the
/// caller the preconditions it answered with, so siphon refuses the INVITE
/// instead of connecting a call that ignores what the caller required.
#[tokio::test(flavor = "multi_thread")]
async fn a_required_extension_the_policy_cannot_relay_is_refused_with_420() {
    let sent = place_call(&routing_script(DIAL), "precondition");
    assert_eq!(
        summaries(&sent),
        [format!("100 to {CALLER}"), format!("420 to {CALLER}")],
        "no B-leg may go out"
    );
    let refusal = response_to_caller(&sent, 420);
    assert_eq!(
        refusal.headers.get("Unsupported").map(String::as_str),
        Some("precondition")
    );
}

/// Every tag the call cannot honour is listed, in the caller's order; the ones
/// siphon implements are not.
#[tokio::test(flavor = "multi_thread")]
async fn unsupported_lists_every_tag_the_call_cannot_honour() {
    let sent = place_call(
        &routing_script(DIAL),
        "100rel, precondition, x-lab-extension, timer",
    );
    let refusal = response_to_caller(&sent, 420);
    assert_eq!(
        refusal.headers.get("Unsupported").map(String::as_str),
        Some("precondition, x-lab-extension")
    );
}

/// Extensions siphon implements itself never draw a 420, under any preset:
/// `100rel` (it PRACKs the callee and answers the caller's PRACK), `timer` and
/// `replaces`. `sec-agree` counts only once verified (`sec_agree_tests`).
#[tokio::test(flavor = "multi_thread")]
async fn extensions_siphon_implements_never_draw_420() {
    for policy in [
        "transparent-b2bua@2026",
        "ims-intra-trust-domain@2026",
        "ims-trust-domain-boundary@2026",
        "sip-trunk-edge@2026",
    ] {
        let sent = place_call(
            &routing_script(&dial_under(policy)),
            "100rel, Timer, replaces",
        );
        assert_eq!(
            summaries(&sent),
            [format!("100 to {CALLER}"), format!("INVITE to {CALLEE}")],
            "under {policy}"
        );
    }
}

/// Under a policy that relays an extension's negotiation, the caller's
/// requirement goes to the callee, who is the one to honour or refuse it.
#[tokio::test(flavor = "multi_thread")]
async fn a_required_extension_the_policy_relays_is_dialled() {
    for (policy, require) in [
        ("ims-intra-trust-domain@2026", "precondition"),
        ("ims-intra-trust-domain@2026", "histinfo"),
        ("transparent-b2bua@2026", "resource-priority"),
    ] {
        let sent = place_call(&routing_script(&dial_under(policy)), require);
        let callee: SocketAddr = CALLEE.parse().expect("a literal address");
        let invite = sent
            .iter()
            .find(|sent| sent.destination == callee)
            .map(|sent| &sent.message)
            .unwrap_or_else(|| panic!("{require} under {policy}: {:?}", summaries(&sent)));
        assert_eq!(
            invite.headers.get("Require").map(String::as_str),
            Some(require),
            "{require} under {policy}"
        );
    }
}

/// The policy has to relay the extension's headers *and* `Require` itself: a
/// requirement the callee is never shown is not being honoured.
#[tokio::test(flavor = "multi_thread")]
async fn a_required_extension_is_refused_where_its_headers_or_require_do_not_cross() {
    for (routing, require) in [
        // History-Info stripped on requests.
        (dial_under("sip-trunk-edge@2026"), "histinfo"),
        // Resource-Priority is not in the trust boundary's copy set.
        (
            dial_under("ims-trust-domain-boundary@2026"),
            "resource-priority",
        ),
        // Everything relayed but the requirement itself.
        (
            "call.dial(\"sip:15550100042@198.51.100.7:5060\", \
             header_policy=\"ims-intra-trust-domain@2026\", strip=[\"Require\"])"
                .to_string(),
            "histinfo",
        ),
    ] {
        let sent = place_call(&routing_script(&routing), require);
        let refusal = response_to_caller(&sent, 420);
        assert_eq!(
            refusal.headers.get("Unsupported").map(String::as_str),
            Some(require),
            "{routing}"
        );
    }
}

/// A fork is refused the same way, before any branch goes out.
#[tokio::test(flavor = "multi_thread")]
async fn a_fork_is_refused_before_any_branch_goes_out() {
    let sent = place_call(
        &routing_script(
            "call.fork([\"sip:15550100042@198.51.100.7:5060\", \"sip:15550100042@198.51.100.8:5060\"])",
        ),
        "x-lab-extension",
    );
    assert_eq!(
        summaries(&sent),
        [format!("100 to {CALLER}"), format!("420 to {CALLER}")]
    );
}

/// The 420 concludes like any call that could not be connected: `@b2bua.on_failure`
/// hears it, and what it decides is carried out. Here it answers the caller
/// with its own refusal.
#[tokio::test(flavor = "multi_thread")]
async fn on_failure_hears_the_420_and_its_decision_is_carried_out() {
    let script = concat!(
        "from siphon import b2bua\n",
        "\n",
        "@b2bua.on_invite\n",
        "def on_invite(call):\n",
        "    call.dial(\"sip:15550100042@198.51.100.7:5060\")\n",
        "\n",
        "@b2bua.on_failure\n",
        "def on_failure(call, code, reason):\n",
        "    if code == 420 and reason == \"Bad Extension\":\n",
        "        call.reject(488, \"Not Acceptable Here\")\n",
    );
    let sent = place_call(script, "precondition");
    assert_eq!(
        summaries(&sent),
        [format!("100 to {CALLER}"), format!("488 to {CALLER}")]
    );
}

/// ...and it may route the call again under a policy that does relay the
/// extension, which the check lets through.
#[tokio::test(flavor = "multi_thread")]
async fn on_failure_can_route_again_under_a_policy_that_relays_the_extension() {
    let script = concat!(
        "from siphon import b2bua\n",
        "\n",
        "@b2bua.on_invite\n",
        "def on_invite(call):\n",
        "    call.dial(\"sip:15550100042@198.51.100.7:5060\")\n",
        "\n",
        "@b2bua.on_failure\n",
        "def on_failure(call, code, reason):\n",
        "    if code == 420:\n",
        "        call.dial(\"sip:15550100042@198.51.100.7:5060\",\n",
        "                  header_policy=\"ims-intra-trust-domain@2026\")\n",
    );
    let sent = place_call(script, "precondition");
    assert_eq!(
        summaries(&sent),
        [format!("100 to {CALLER}"), format!("INVITE to {CALLEE}")]
    );
}
