//! A carrier INVITE carries an asserted identity, not just a rewritten `From`.
//!
//! The header policy strips `P-*` off an untrusted access leg, which is right:
//! what a UE sent is not an assertion siphon can make. Nothing then put one
//! back, and `set_calling_number` only *rewrites* a `P-Asserted-Identity` that
//! is already present — so a route naming `caller_id` reached the carrier with
//! the presented number in `From` and no asserted identity at all, which is the
//! one header most carriers ask for (RFC 3325 §5).
//!
//! CLIR had the same hole from the other side: `Privacy: id` asks the trusted
//! next hop to withhold the identity *it was given*, and over an absent PAI
//! there was nothing to withhold and nothing to identify the caller by.
//!
//! Every test drives the real carrier-dial path and reads the INVITE off the
//! UDP egress channel, because the ordering is the whole of this — assert after
//! the substitution, before the number policy, before the anonymisation — and
//! an assertion made in the wrong place only shows up on the wire.

use super::lcr_number_policy_tests::a_leg_invite;
use super::test_dispatcher::test_dispatcher;
use super::*;

/// Where every carrier in these tests is reached. A literal address, so the
/// send resolves without DNS.
const CARRIER_NEXT_HOP: &str = "sip:198.51.100.7:5060";
const CALLEE: &str = "+15550100042";
/// The caller's own number, as its INVITE arrives.
const CALLER: &str = "+15550100001";
/// What a route presents instead.
const PRESENTED: &str = "+15550100777";

/// The identity headers a carrier INVITE went out with.
#[derive(Debug)]
struct CarrierIdentity {
    from: String,
    asserted: Option<String>,
    privacy: Option<String>,
}

fn route(caller_id: Option<&str>, presentation: Option<&str>) -> crate::lcr::Route {
    crate::lcr::Route {
        carrier_id: "carrier-a".to_string(),
        next_hop: Some(CARRIER_NEXT_HOP.to_string()),
        caller_id: caller_id.map(str::to_string),
        caller_id_presentation: presentation.map(str::to_string),
        ..Default::default()
    }
}

/// Dial `route` and read back the identity headers the carrier was sent.
fn dial_carrier(route: crate::lcr::Route, assert_identity: bool) -> CarrierIdentity {
    let mut dispatcher = test_dispatcher();
    // The knob under test (`b2bua.assert_identity`).
    dispatcher.state.assert_identity = assert_identity;

    let a_leg_invite = a_leg_invite(CALLEE, CALLER);
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

    let advance = b2bua_advance_route(&call_id, &a_leg_invite, &dispatcher.state);
    assert!(advance.dialed, "the carrier was not dialled");

    let sent = dispatcher
        .udp
        .try_recv()
        .expect("the carrier INVITE reached the transport");
    let invite = parse_sip_message_bytes(&sent.data).expect("the carrier INVITE parses");
    CarrierIdentity {
        from: invite.headers.from().expect("a From header").clone(),
        asserted: invite.headers.get("P-Asserted-Identity").cloned(),
        privacy: invite.headers.get("Privacy").cloned(),
    }
}

/// The item's own acceptance line: a route naming `caller_id` reaches the
/// carrier with both a rewritten `From` and a matching PAI, and neither depends
/// on the LCR answer's free-form `headers` map.
#[tokio::test(flavor = "multi_thread")]
async fn a_route_caller_id_reaches_the_carrier_as_from_and_asserted_identity() {
    let identity = dial_carrier(route(Some(PRESENTED), None), true);

    assert!(
        identity.from.contains(PRESENTED),
        "From presents the route's CLI: {}",
        identity.from
    );
    let asserted = identity
        .asserted
        .expect("the carrier is told who the call is from");
    assert!(
        asserted.contains(PRESENTED),
        "the assertion agrees with the From: {asserted}"
    );
    assert!(
        !asserted.contains(CALLER),
        "and is not the caller's own number: {asserted}"
    );
    assert!(
        identity.privacy.is_none(),
        "nothing was restricted: {:?}",
        identity.privacy
    );
}

/// The CLIR half: `Privacy: id` together with a PAI carrying the real number.
/// Asserted before the anonymisation, which is the only point at which the
/// `From` still holds the real identity.
#[tokio::test(flavor = "multi_thread")]
async fn a_restricted_route_sends_privacy_id_with_the_real_number_asserted() {
    let identity = dial_carrier(route(None, Some("restricted")), true);

    assert_eq!(identity.privacy.as_deref(), Some("id"));
    assert!(
        identity.from.contains(crate::sip::privacy::ANONYMOUS_URI),
        "the untrusted From is anonymised: {}",
        identity.from
    );
    let asserted = identity
        .asserted
        .expect("Privacy: id must have an identity to withhold");
    assert!(
        asserted.contains(CALLER),
        "the real identity reaches the trusted next hop: {asserted}"
    );
}

/// Both together: the presented CLI is what gets asserted, not the caller's.
#[tokio::test(flavor = "multi_thread")]
async fn a_restricted_route_with_a_caller_id_asserts_the_presented_one() {
    let identity = dial_carrier(route(Some(PRESENTED), Some("restricted")), true);

    assert_eq!(identity.privacy.as_deref(), Some("id"));
    let asserted = identity.asserted.expect("an identity is asserted");
    assert!(
        asserted.contains(PRESENTED),
        "the route decided what this call presents: {asserted}"
    );
    assert!(
        !asserted.contains(CALLER),
        "the caller's own number is not what was asserted: {asserted}"
    );
}

/// `b2bua.assert_identity: false`, for a next hop genuinely outside the trust
/// domain. The rest of the leg is unchanged.
#[tokio::test(flavor = "multi_thread")]
async fn assertion_can_be_turned_off_for_an_untrusted_next_hop() {
    let identity = dial_carrier(route(Some(PRESENTED), None), false);

    assert!(
        identity.from.contains(PRESENTED),
        "the From is still rewritten: {}",
        identity.from
    );
    assert!(
        identity.asserted.is_none(),
        "nothing is asserted: {:?}",
        identity.asserted
    );
}

/// A plain carrier leg with no `caller_id` and no CLIR still gets an assertion:
/// "RFC 3325 toward every carrier" is the ask, not "only on routes that name a
/// CLI". The identity asserted is the caller's own.
#[tokio::test(flavor = "multi_thread")]
async fn a_plain_carrier_leg_still_carries_an_asserted_identity() {
    let identity = dial_carrier(route(None, None), true);

    let asserted = identity.asserted.expect("an identity is asserted");
    assert!(asserted.contains(CALLER), "{asserted}");
    assert!(identity.privacy.is_none());
}
