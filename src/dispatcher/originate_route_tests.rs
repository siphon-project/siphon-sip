//! A call siphon places with a pre-loaded route set (RFC 3261 §8.1.2).
//!
//! An application server that originates a request on behalf of a user or a
//! service identity hands it to its S-CSCF with the S-CSCF's URI as a Route
//! entry, so the S-CSCF knows which session case it is (TS 24.229 §5.7.3).
//! Steering the INVITE to the S-CSCF's address with `next_hop` is not the same
//! thing: the S-CSCF sees no Route of its own and takes the request for a
//! terminating one.

use super::originate_test_harness::{drain, phone_response, phone_sends, requests_to, socket};
use super::test_dispatcher::test_dispatcher;
use super::*;

const SCSCF: &str = "192.0.2.44:6060";
const ROUTE: &str = "<sip:orig@192.0.2.44:6060;lr>";
const CALLED: &str = "sip:+15551234@ims.example.com;user=phone";

fn originate_params() -> OriginateParams {
    OriginateParams {
        to: CALLED.to_string(),
        to_display: None,
        from: Some("sip:conf-1@focus.example.com".to_string()),
        from_display: None,
        next_hop: None,
        p_asserted_identity: Some("sip:conf-1@focus.example.com".to_string()),
        privacy: None,
        headers: Vec::new(),
        timeout_secs: 30,
        media: OriginateMedia::Offer {
            body: b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\n".to_vec(),
            content_type: "application/sdp".to_string(),
        },
        session_timer: None,
    }
}

fn routes_of(message: &SipMessage) -> Vec<String> {
    message
        .headers
        .get_all("Route")
        .cloned()
        .unwrap_or_default()
}

/// The INVITE carries the route set and goes to its topmost entry, with the
/// called party left in the Request-URI.
#[tokio::test(flavor = "multi_thread")]
async fn an_originate_with_a_route_set_carries_it_and_goes_to_its_top_entry() {
    let dispatcher = test_dispatcher();
    let prepared =
        prepare_originate_with_route(&dispatcher.state, originate_params(), vec![ROUTE.into()])
            .expect("the originate stages");
    assert!(dial_originate(&dispatcher.state, &prepared));

    let invite = requests_to(&drain(&dispatcher.udp), socket(SCSCF), Method::Invite)
        .pop()
        .expect("the INVITE went to the topmost Route")
        .message;
    assert_eq!(routes_of(&invite), vec![ROUTE.to_string()]);
    match &invite.start_line {
        StartLine::Request(line) => assert_eq!(line.request_uri.to_string(), CALLED),
        StartLine::Response(_) => panic!("a request"),
    }
}

/// An explicit next hop still decides where the INVITE goes; the route set is
/// carried all the same.
#[tokio::test(flavor = "multi_thread")]
async fn a_next_hop_outranks_the_route_set_for_the_destination() {
    let dispatcher = test_dispatcher();
    let mut params = originate_params();
    params.next_hop = Some("sip:192.0.2.45:6060".to_string());
    let prepared = prepare_originate_with_route(&dispatcher.state, params, vec![ROUTE.into()])
        .expect("the originate stages");
    assert!(dial_originate(&dispatcher.state, &prepared));

    let invite = requests_to(
        &drain(&dispatcher.udp),
        socket("192.0.2.45:6060"),
        Method::Invite,
    )
    .pop()
    .expect("the INVITE went to the next hop")
    .message;
    assert_eq!(routes_of(&invite), vec![ROUTE.to_string()]);
}

/// RFC 3261 §9.1: the CANCEL carries the INVITE's Route header field values.
#[tokio::test(flavor = "multi_thread")]
async fn the_cancel_of_a_routed_originate_carries_its_route_set() {
    let dispatcher = test_dispatcher();
    let prepared =
        prepare_originate_with_route(&dispatcher.state, originate_params(), vec![ROUTE.into()])
            .expect("the originate stages");
    assert!(dial_originate(&dispatcher.state, &prepared));
    let invite = requests_to(&drain(&dispatcher.udp), socket(SCSCF), Method::Invite)
        .pop()
        .expect("the INVITE went out")
        .message;
    phone_sends(
        &dispatcher.state,
        socket(SCSCF),
        &phone_response(&invite, 180, "Ringing", "callee", CALLED, None),
    );

    assert!(cancel_originated_call(
        &dispatcher.state,
        &prepared.sip_call_id,
        None
    ));
    let cancel = requests_to(&drain(&dispatcher.udp), socket(SCSCF), Method::Cancel)
        .pop()
        .expect("the CANCEL went the INVITE's way")
        .message;
    assert_eq!(routes_of(&cancel), vec![ROUTE.to_string()]);
}

/// RFC 3261 §17.1.1.3: the ACK to a non-2xx final carries the INVITE's Route.
#[tokio::test(flavor = "multi_thread")]
async fn the_ack_to_a_failure_of_a_routed_originate_carries_its_route_set() {
    let dispatcher = test_dispatcher();
    let prepared =
        prepare_originate_with_route(&dispatcher.state, originate_params(), vec![ROUTE.into()])
            .expect("the originate stages");
    assert!(dial_originate(&dispatcher.state, &prepared));
    let invite = requests_to(&drain(&dispatcher.udp), socket(SCSCF), Method::Invite)
        .pop()
        .expect("the INVITE went out")
        .message;
    phone_sends(
        &dispatcher.state,
        socket(SCSCF),
        &phone_response(
            &invite,
            480,
            "Temporarily Unavailable",
            "callee",
            CALLED,
            None,
        ),
    );

    let ack = requests_to(&drain(&dispatcher.udp), socket(SCSCF), Method::Ack)
        .pop()
        .expect("the failure was ACKed toward the S-CSCF")
        .message;
    assert_eq!(routes_of(&ack), vec![ROUTE.to_string()]);
}
