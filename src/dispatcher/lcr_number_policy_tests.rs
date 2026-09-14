//! An LCR route's `number_policy` shapes the dialled number in the carrier
//! Request-URI, the same way `call.dial(number_policy=…)` shapes its target.
//!
//! Driven through [`b2bua_advance_route_with_numbers`], the path that builds and
//! sends a carrier's INVITE, and read back off the UDP egress channel: a policy
//! resolved correctly and then not handed to the part that builds the INVITE
//! only shows up here.

use super::test_dispatcher::test_dispatcher;
use super::*;
use crate::numbers::policy::{NumberPolicyConfig, NumberRegistry, NumberingConfig};
use crate::script::api::numbers::NumberRuntime;
use std::collections::HashMap;

/// Where every carrier in these tests is reached. A literal address, so the
/// send resolves without DNS.
const CARRIER_NEXT_HOP: &str = "sip:198.51.100.7:5060";

/// One policy per shape a carrier may want the dialled number in, over a
/// numbering plan whose bare digits are already country-code-first (a trunk
/// that dials E.164 without the `+`), so `15550100042` is `+15550100042`.
///
/// Built locally rather than installed: the process-wide runtime is set once
/// per test binary and the first installer wins.
fn numbers(default: Option<&str>) -> NumberRuntime {
    let numbering = NumberingConfig {
        country_code: "1".to_string(),
        assume: crate::numbers::AssumeForm::International,
        ..Default::default()
    };
    let mut policies = HashMap::new();
    for (name, yaml) in [
        ("plain@test", "default: plain\n"),
        ("e164@test", "default: e164\n"),
        (
            "intl00@test",
            "default: international\ninternational_prefix: \"00\"\n",
        ),
    ] {
        policies.insert(
            name.to_string(),
            serde_yaml_ng::from_str::<NumberPolicyConfig>(yaml).expect("the policy parses"),
        );
    }
    let (registry, warnings) = NumberRegistry::build(&numbering, &policies);
    assert!(warnings.is_empty(), "policy warnings: {warnings:?}");
    let default_b2bua_policy = default.map(|name| {
        registry
            .get(name)
            .expect("the default is a configured policy")
    });
    NumberRuntime {
        registry,
        default_b2bua_policy,
    }
}

/// The two forms the same numbers reach siphon in.
#[derive(Debug, Clone, Copy)]
enum Arrives {
    Bare,
    Plus,
}

impl Arrives {
    const BOTH: [Arrives; 2] = [Arrives::Bare, Arrives::Plus];

    fn callee(self) -> &'static str {
        match self {
            Arrives::Bare => "15550100042",
            Arrives::Plus => "+15550100042",
        }
    }

    fn caller(self) -> &'static str {
        match self {
            Arrives::Bare => "15550100001",
            Arrives::Plus => "+15550100001",
        }
    }
}

/// The userparts a carrier INVITE went out with.
#[derive(Debug, PartialEq, Eq)]
struct CarrierInvite {
    request_uri: String,
    to: String,
    from: String,
}

fn shaped(request_uri: &str, to: &str, from: &str) -> CarrierInvite {
    CarrierInvite {
        request_uri: request_uri.to_string(),
        to: to.to_string(),
        from: from.to_string(),
    }
}

/// What the carrier sees when nothing reshapes the numbers: each as it arrived.
fn unshaped(arrives: Arrives) -> CarrierInvite {
    shaped(arrives.callee(), arrives.callee(), arrives.caller())
}

fn route(number_policy: Option<&str>) -> crate::lcr::Route {
    crate::lcr::Route {
        carrier_id: "carrier-a".to_string(),
        next_hop: Some(CARRIER_NEXT_HOP.to_string()),
        number_policy: number_policy.map(str::to_string),
        ..Default::default()
    }
}

pub(super) fn a_leg_invite(callee: &str, caller: &str) -> SipMessage {
    let raw = format!(
        concat!(
            "INVITE sip:{callee}@siphon.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-lcr-policy\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:{caller}@caller.example.com>;tag=caller-tag\r\n",
            "To: <sip:{callee}@siphon.example.com>\r\n",
            "Call-ID: lcr-policy@192.0.2.10\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:caller@192.0.2.10:5060>\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        callee = callee,
        caller = caller,
    );
    parse_sip_message_bytes(raw.as_bytes()).expect("the A-leg INVITE parses")
}

fn userpart(name_addr: &str) -> String {
    crate::sip::headers::nameaddr::NameAddr::parse(name_addr)
        .expect("a name-addr")
        .uri
        .user
        .unwrap_or_default()
}

/// Route a call to `callee` from `caller` over `route` and read back the
/// INVITE the carrier was sent.
fn dial_carrier(
    route: crate::lcr::Route,
    numbers: &NumberRuntime,
    callee: &str,
    caller: &str,
) -> CarrierInvite {
    let dispatcher = test_dispatcher();
    let a_leg_invite = a_leg_invite(callee, caller);
    let call_id = dispatcher.state.call_actors.create_call(Leg::new_a_leg(
        "lcr-policy@192.0.2.10".to_string(),
        "caller-tag".to_string(),
        "z9hG4bK-lcr-policy".to_string(),
        LegTransport {
            remote_addr: "192.0.2.10:5060".parse().expect("a literal address"),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    ));
    dispatcher.state.call_actors.start_route_sequence(
        &call_id,
        crate::b2bua::actor::RouteSequenceState {
            pending: std::collections::VecDeque::from([route]),
            default_timeout: 30,
            ..Default::default()
        },
    );

    let advance =
        b2bua_advance_route_with_numbers(&call_id, &a_leg_invite, &dispatcher.state, numbers);
    assert!(advance.dialed, "the carrier was not dialled");
    assert!(
        advance.burned.is_empty(),
        "{} carrier(s) burned without dialling",
        advance.burned.len()
    );

    let sent = dispatcher
        .udp
        .try_recv()
        .expect("the carrier INVITE reached the transport");
    assert_eq!(
        sent.destination,
        "198.51.100.7:5060"
            .parse::<SocketAddr>()
            .expect("a literal address")
    );
    let invite = parse_sip_message_bytes(&sent.data).expect("the carrier INVITE parses");
    let request_uri = match &invite.start_line {
        StartLine::Request(line) => line.request_uri.user.clone().unwrap_or_default(),
        StartLine::Response(_) => panic!("the carrier was sent a response"),
    };
    CarrierInvite {
        request_uri,
        to: userpart(invite.headers.to().expect("a To header")),
        from: userpart(invite.headers.from().expect("a From header")),
    }
}

/// The failure this exists for: a route naming a policy and no `tech_prefix`
/// sent the dialled number as bare digits in the Request-URI whatever shape the
/// policy gave From and To. A carrier screening the dialled number as `+E.164`
/// refuses that, and the refusal reads as the carrier declining the call, so
/// the call fails over.
#[tokio::test(flavor = "multi_thread")]
async fn an_e164_route_policy_shapes_the_carrier_request_uri() {
    for arrives in Arrives::BOTH {
        assert_eq!(
            dial_carrier(
                route(Some("e164@test")),
                &numbers(None),
                arrives.callee(),
                arrives.caller()
            ),
            shaped("+15550100042", "+15550100042", "+15550100001"),
            "arriving {arrives:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_plain_route_policy_shapes_the_carrier_request_uri() {
    for arrives in Arrives::BOTH {
        assert_eq!(
            dial_carrier(
                route(Some("plain@test")),
                &numbers(None),
                arrives.callee(),
                arrives.caller()
            ),
            shaped("15550100042", "15550100042", "15550100001"),
            "arriving {arrives:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_international_route_policy_shapes_the_carrier_request_uri() {
    for arrives in Arrives::BOTH {
        assert_eq!(
            dial_carrier(
                route(Some("intl00@test")),
                &numbers(None),
                arrives.callee(),
                arrives.caller()
            ),
            shaped("0015550100042", "0015550100042", "0015550100001"),
            "arriving {arrives:?}"
        );
    }
}

/// `tech_prefix` is a carrier routing code in front of the number, so it goes
/// on after the policy has shaped the number, and stays off the To.
#[tokio::test(flavor = "multi_thread")]
async fn tech_prefix_is_prepended_to_the_number_the_policy_shaped() {
    for arrives in Arrives::BOTH {
        let route = crate::lcr::Route {
            tech_prefix: Some("99900".to_string()),
            ..route(Some("plain@test"))
        };
        assert_eq!(
            dial_carrier(route, &numbers(None), arrives.callee(), arrives.caller()),
            shaped("9990015550100042", "15550100042", "15550100001"),
            "arriving {arrives:?}"
        );
    }
}

/// A retarget replaces the number before the policy runs, so the new number is
/// what gets shaped, in the Request-URI and in the To that follows it. The
/// `plain` case is the one that tells shaped from verbatim, since the
/// destination is already in `+E.164`.
#[tokio::test(flavor = "multi_thread")]
async fn a_retargeted_number_is_shaped_by_the_route_policy() {
    for arrives in Arrives::BOTH {
        let e164 = crate::lcr::Route {
            destination: Some("+15550100099".to_string()),
            ..route(Some("e164@test"))
        };
        assert_eq!(
            dial_carrier(e164, &numbers(None), arrives.callee(), arrives.caller()),
            shaped("+15550100099", "+15550100099", "+15550100001"),
            "arriving {arrives:?}"
        );

        let plain = crate::lcr::Route {
            destination: Some("+15550100099".to_string()),
            ..route(Some("plain@test"))
        };
        assert_eq!(
            dial_carrier(plain, &numbers(None), arrives.callee(), arrives.caller()),
            shaped("15550100099", "15550100099", "15550100001"),
            "arriving {arrives:?}"
        );
    }
}

/// A policy name the configuration does not define reshapes nothing, not even
/// with a default configured, and says so once, naming the carrier and the
/// policy so the routing backend's typo can be found.
#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_route_policy_shapes_nothing_and_warns_once() {
    for default in [None, Some("e164@test")] {
        for arrives in Arrives::BOTH {
            let log = LogBuffer::default();
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .with_max_level(tracing::Level::WARN)
                .with_writer(log.clone())
                .finish();
            let invite = tracing::subscriber::with_default(subscriber, || {
                dial_carrier(
                    route(Some("unknown@test")),
                    &numbers(default),
                    arrives.callee(),
                    arrives.caller(),
                )
            });

            assert_eq!(
                invite,
                unshaped(arrives),
                "arriving {arrives:?}, default {default:?}"
            );
            let rendered = log.rendered();
            let warnings: Vec<&str> = rendered
                .lines()
                .filter(|line| line.contains("unknown number_policy"))
                .collect();
            assert_eq!(
                warnings.len(),
                1,
                "expected one warning, logged:\n{rendered}"
            );
            assert!(
                warnings[0].contains("carrier=carrier-a")
                    && warnings[0].contains("policy=unknown@test"),
                "the warning names neither the carrier nor the policy: {}",
                warnings[0]
            );
        }
    }
}

/// A route that names no policy gets what `call.dial()` naming none gets.
#[tokio::test(flavor = "multi_thread")]
async fn a_route_without_a_policy_falls_back_to_the_b2bua_default() {
    for arrives in Arrives::BOTH {
        assert_eq!(
            dial_carrier(
                route(None),
                &numbers(Some("e164@test")),
                arrives.callee(),
                arrives.caller()
            ),
            shaped("+15550100042", "+15550100042", "+15550100001"),
            "arriving {arrives:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_route_without_a_policy_or_a_default_is_left_unshaped() {
    for arrives in Arrives::BOTH {
        assert_eq!(
            dial_carrier(
                route(None),
                &numbers(None),
                arrives.callee(),
                arrives.caller()
            ),
            unshaped(arrives),
            "arriving {arrives:?}"
        );
    }
}

/// A Request-URI user that is not a number (a SIP AoR) is not mangled into one.
#[tokio::test(flavor = "multi_thread")]
async fn a_request_uri_user_that_is_not_a_number_is_sent_verbatim() {
    let invite = dial_carrier(
        route(Some("e164@test")),
        &numbers(None),
        "alice",
        "+15550100001",
    );
    assert_eq!(invite, shaped("alice", "alice", "+15550100001"));
}

/// An explicit `ruri` is the base the number is shaped in, host and URI
/// parameters left as the routing backend wrote them.
#[test]
fn the_policy_shapes_the_number_in_an_explicit_ruri() {
    let numbers = numbers(None);
    let policy = numbers
        .registry
        .get("e164@test")
        .expect("a configured policy");
    let route = crate::lcr::Route {
        carrier_id: "carrier-a".to_string(),
        ruri: Some("sip:15550100042@carrier.example.com;user=phone".to_string()),
        ..Default::default()
    };

    let target = b2bua_carrier_ruri(
        &route,
        "sip:15550100000@siphon.example.com",
        None,
        Some(&policy),
    );

    assert!(
        target.starts_with("sip:+15550100042@carrier.example.com"),
        "{target}"
    );
    assert!(target.contains("user=phone"), "{target}");
}

/// Captured log output, for asserting on a warning.
#[derive(Clone, Default)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl LogBuffer {
    fn rendered(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("the log buffer lock")).into_owned()
    }
}

impl std::io::Write for LogBuffer {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("the log buffer lock")
            .extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for LogBuffer {
    type Writer = LogBuffer;

    fn make_writer(&'writer self) -> Self::Writer {
        self.clone()
    }
}
