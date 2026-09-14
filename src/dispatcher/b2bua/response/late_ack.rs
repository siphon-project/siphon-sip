//! A 2xx for an INVITE siphon sent that arrives after its call is gone.
//!
//! RFC 3261 §13.2.2.4 has the UAC ACK every 2xx its INVITE draws, and RFC 5407
//! §3.1.3 keeps that true for a 2xx that crosses the UAC's own BYE. siphon is the
//! UAC of every INVITE it puts on a leg: the B-leg INVITE, the session refresh,
//! the media re-anchor after a transfer, a bridge offer. The call can end while
//! one of those is in flight (the other party hangs up, the call actor is removed
//! and its BYE sent), and the 2xx then names a branch nothing tracks. Left
//! unanswered, the far end retransmits it for 64*T1 (§13.3.1.4) and a strict UA
//! fails the transaction.
//!
//! Stateless on purpose. The 2xx carries everything its ACK needs: the Contact is
//! the Request-URI, the Record-Route reversed is the route set (§12.1.2), and
//! From, To, Call-ID and the CSeq number are echoed. A retransmitted 2xx is simply
//! ACKed again, which is what §13.2.2.4 asks for, so there is no store to absorb
//! retransmissions and nothing to evict.
//!
//! No BYE goes with it: the call that ended already sent its own.

use crate::dispatcher::*;

/// The ACK a 2xx that outlived its call is owed, and how it leaves.
#[derive(Debug)]
pub struct LateAck {
    pub message: SipMessage,
    pub transport: Transport,
    pub destination: SocketAddr,
    /// The connection the 2xx arrived on when the ACK goes back over it,
    /// `ConnectionId::default()` for a different next hop.
    pub connection_id: ConnectionId,
    /// The UDP socket the 2xx arrived on; `None` on a stream transport.
    pub source_local_addr: Option<SocketAddr>,
}

/// The single `Via` of a response to a request siphon sent as a UAC, or `None`
/// when that cannot be shown.
///
/// A request siphon originates carries exactly one Via, its own, and a response
/// copies the Vias of its request (RFC 3261 §8.2.6.2). A request siphon relayed as
/// a proxy carries the sender's Via under ours, so its response has at least two,
/// and that 2xx is the UAC's to ACK (§16.7), not ours. Requiring a single Via on a
/// sent-by siphon answers on, with an RFC 3261 branch, keeps a stray 2xx addressed
/// to anyone else from drawing an ACK.
pub fn own_request_via(response: &SipMessage, identity: &core::SelfIdentity) -> Option<Via> {
    let mut own = None;
    for line in response.headers.get_all("Via")? {
        for via in Via::parse_multi(line).ok()? {
            if own.is_some() {
                return None;
            }
            own = Some(via);
        }
    }
    let via = own?;
    // siphon always stamps a port, so a sent-by without one is not ours.
    let port = via.port?;
    let branch = via.branch.as_deref()?;
    (TransactionKey::is_rfc3261_branch(branch) && identity.matches(&via.host, Some(port)))
        .then_some(via)
}

/// The ACK for a 2xx to an INVITE siphon sent, built from the response alone,
/// and where it goes. `None` for anything else.
///
/// The destination is the first hop of the route set when there is one, else
/// the address the 2xx came from, over the same connection when that is the
/// same peer (RFC 5923). That is how siphon sends every other in-dialog request
/// on a B2BUA leg; the 2xx's source stands in for the leg address the removed
/// call held.
pub fn late_2xx_ack(
    response: &SipMessage,
    status_code: u16,
    arrived_on: &InboundMessage,
    identity: &core::SelfIdentity,
    resolver: &SipResolver,
) -> Option<LateAck> {
    // Only a 2xx is ACKed end to end. A non-2xx final is ACKed hop by hop by the
    // transaction that sent the INVITE (§17.1.1.3), never from here.
    if !(200..300).contains(&status_code) {
        return None;
    }
    let cseq = crate::sip::headers::cseq::CSeq::parse(response.headers.get("CSeq")?).ok()?;
    if cseq.method != Method::Invite {
        return None;
    }
    let via = own_request_via(response, identity)?;
    let sent_by_port = via.port?;

    // The ACK names the sent-by the INVITE carried: it is siphon's own, and
    // `own_request_via` has just checked that.
    let mut message =
        build_b2bua_ack_for_2xx(response, arrived_on.transport, &via.host, sent_by_port)?;
    // A 2xx to an INVITE must carry a Contact (§12.1.1). For one that does not,
    // address the ACK to where the 2xx came from rather than to a placeholder no
    // element can route.
    if response.headers.get("Contact").is_none() {
        if let StartLine::Request(ref mut request_line) = message.start_line {
            request_line.request_uri = SipUri::new(arrived_on.remote_addr.ip().to_string())
                .with_port(arrived_on.remote_addr.port());
        }
    }

    let next_hop = message
        .headers
        .get_all("Route")
        .map(Vec::as_slice)
        .and_then(first_route_uri);
    let (destination, transport, connection_id) = resolve_in_dialog_flow_uri(
        next_hop.as_deref(),
        resolver,
        arrived_on.remote_addr,
        arrived_on.transport,
        arrived_on.connection_id,
    );
    // Over UDP the ACK leaves from the socket the 2xx arrived on. For a leg
    // dialled over a captured flow that is the only socket its peer accepts
    // (3GPP TS 33.203 §7.4). A stream is reached over its connection, and a
    // source bind there would dial a new one.
    let source_local_addr = matches!(transport, Transport::Udp).then_some(arrived_on.local_addr);
    Some(LateAck {
        message,
        transport,
        destination,
        connection_id,
        source_local_addr,
    })
}

/// ACK a 2xx to an INVITE siphon sent when nothing tracks its call any more.
/// Returns whether the response was consumed.
pub fn ack_late_2xx_after_teardown(
    inbound: &InboundMessage,
    response: &SipMessage,
    status_code: u16,
    state: &DispatcherState,
) -> bool {
    let Some(late) = late_2xx_ack(
        response,
        status_code,
        inbound,
        &state.self_identity,
        &state.dns_resolver,
    ) else {
        return false;
    };
    info!(
        call_id = %response.headers.call_id().map(String::as_str).unwrap_or_default(),
        cseq = %response.headers.cseq().map(String::as_str).unwrap_or_default(),
        status = status_code,
        destination = %late.destination,
        "B2BUA: ACKed a late 2xx to our INVITE, its call had already ended \
         (RFC 3261 §13.2.2.4, RFC 5407 §3.1.3)"
    );
    send_message_from(
        late.message,
        late.transport,
        late.destination,
        late.connection_id,
        late.source_local_addr,
        state,
    );
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::parser::parse_sip_message;

    const SIPHON: &str = "192.0.2.60:5060";
    const BOB: &str = "198.51.100.52:5060";
    const REINVITE_BRANCH: &str = "z9hG4bK-reinvite-a2b-1";

    fn address(text: &str) -> SocketAddr {
        text.parse().expect("fixture address parses")
    }

    fn resolver() -> SipResolver {
        SipResolver::from_system().expect("system resolver")
    }

    /// siphon answers on 192.0.2.60:5060, the way `build_self_identity` records a
    /// listener.
    fn identity() -> core::SelfIdentity {
        let mut identity = core::SelfIdentity::new();
        identity.add_host("192.0.2.60", &[5060]);
        identity
    }

    fn udp_from(remote: &str, local: &str) -> InboundMessage {
        InboundMessage {
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: address(local),
            remote_addr: address(remote),
            data: Bytes::new(),
        }
    }

    fn parse(raw: &str) -> SipMessage {
        parse_sip_message(raw).expect("response fixture parses").1
    }

    /// Bob's 200 to the re-INVITE siphon sent him, carrying siphon's own Via.
    fn bob_reinvite_200() -> SipMessage {
        parse(concat!(
            "SIP/2.0 200 OK\r\n",
            "Via: SIP/2.0/UDP 192.0.2.60:5060;branch=z9hG4bK-reinvite-a2b-1\r\n",
            "From: <sip:alice@example.com>;tag=sb-bobside\r\n",
            "To: <sip:bob@example.com>;tag=bob-tag-1\r\n",
            "Call-ID: b2b-bob-dialog@192.0.2.60\r\n",
            "CSeq: 2 INVITE\r\n",
            "Contact: <sip:bob@198.51.100.52:5062>\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ))
    }

    fn wire(message: &SipMessage) -> String {
        String::from_utf8(message.to_bytes()).expect("serialized SIP is UTF-8")
    }

    fn via_branch(message: &SipMessage) -> String {
        message
            .headers
            .get("Via")
            .and_then(|via| Via::parse(via).ok())
            .and_then(|via| via.branch)
            .expect("the ACK carries a Via branch")
    }

    fn udp_leg(call_id: &str, local_tag: &str, target: &str, branch: &str) -> Leg {
        Leg::new_b_leg(
            call_id.to_string(),
            local_tag.to_string(),
            target.to_string(),
            branch.to_string(),
            LegTransport {
                remote_addr: address(BOB),
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
                local_addr: None,
            },
        )
    }

    /// The race this exists for: siphon re-INVITEs Bob (the surviving party of a
    /// transfer), the other party hangs up inside that round trip, the call is
    /// torn down, and only then does Bob's 200 arrive. Nothing tracks the branch
    /// any more, so the ACK has to come from the response itself.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_2xx_to_a_reinvite_after_teardown_draws_one_ack_built_from_the_response() {
        let store = CallActorStore::new();
        let alice = Leg::new_a_leg(
            "alice-call@198.51.100.53".to_string(),
            "alice-tag".to_string(),
            "z9hG4bK-alice-invite".to_string(),
            LegTransport {
                remote_addr: address("198.51.100.53:5060"),
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
                local_addr: None,
            },
        );
        let call_id = store.create_call(alice);
        store.add_b_leg(
            &call_id,
            udp_leg(
                "b2b-bob-dialog@192.0.2.60",
                "sb-bobside",
                "sip:bob@198.51.100.52:5060",
                "z9hG4bK-bob-invite",
            ),
        );
        store.set_winner(&call_id, 0);
        // What `b2bua_send_reinvite_on_leg` registers for the re-INVITE.
        store.add_b_leg(
            &call_id,
            udp_leg(
                "b2b-bob-dialog@192.0.2.60",
                "sb-bobside",
                "reinvite:a2b",
                REINVITE_BRANCH,
            ),
        );
        assert_eq!(
            store.call_id_for_branch(REINVITE_BRANCH).as_deref(),
            Some(call_id.as_str())
        );

        // The BYE path tears the call down while the re-INVITE is in flight.
        store.remove_call(&call_id);
        assert!(store.call_id_for_branch(REINVITE_BRANCH).is_none());
        assert!(store.zombie_cancelled_for_2xx(REINVITE_BRANCH).is_none());

        let response = bob_reinvite_200();
        let late = late_2xx_ack(
            &response,
            200,
            &udp_from(BOB, SIPHON),
            &identity(),
            &resolver(),
        )
        .expect("a 2xx to our own INVITE is ACKed after the call ended");

        let ack = &late.message;
        let text = wire(ack);
        // RFC 3261 §13.2.2.4: Request-URI is the 2xx's Contact, not where it came from.
        assert!(
            text.starts_with("ACK sip:bob@198.51.100.52:5062 SIP/2.0\r\n"),
            "request line:\n{text}"
        );
        assert_eq!(ack.headers.cseq().map(String::as_str), Some("2 ACK"));
        assert_eq!(
            ack.headers.call_id().map(String::as_str),
            Some("b2b-bob-dialog@192.0.2.60")
        );
        assert!(ack
            .headers
            .to()
            .is_some_and(|to| to.contains(";tag=bob-tag-1")));
        assert!(ack
            .headers
            .from()
            .is_some_and(|from| from.contains(";tag=sb-bobside")));
        // A 2xx ACK is its own transaction: a new branch on siphon's own sent-by.
        let branch = via_branch(ack);
        assert_ne!(branch, REINVITE_BRANCH);
        assert!(TransactionKey::is_rfc3261_branch(&branch));
        assert!(
            text.contains("Via: SIP/2.0/UDP 192.0.2.60:5060;branch="),
            "Via:\n{text}"
        );
        assert_eq!(
            ack.headers.get("Max-Forwards").map(String::as_str),
            Some("70")
        );
        assert_eq!(
            ack.headers.get("Content-Length").map(String::as_str),
            Some("0")
        );
        assert!(ack.headers.get("Route").is_none());

        // Exactly one message, and it is the ACK: no BYE, the call sent its own.
        assert_eq!(ack.method(), Some(&Method::Ack));
        assert_eq!(late.destination, address(BOB));
        assert_eq!(late.transport, Transport::Udp);
        assert_eq!(late.connection_id, ConnectionId::default());
        assert_eq!(late.source_local_addr, Some(address(SIPHON)));

        // Nothing was brought back to life to send it.
        assert_eq!(store.count(), 0);
        assert!(store
            .find_by_sip_call_id("b2b-bob-dialog@192.0.2.60")
            .is_none());
    }

    /// RFC 3261 §13.2.2.4: each retransmission of the 2xx is ACKed again. The
    /// design holds no state, so a retransmission is just another late 2xx.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_retransmitted_late_2xx_is_acked_again() {
        let response = bob_reinvite_200();
        let arrived_on = udp_from(BOB, SIPHON);
        let first = late_2xx_ack(&response, 200, &arrived_on, &identity(), &resolver())
            .expect("first copy is ACKed");
        let second = late_2xx_ack(&response, 200, &arrived_on, &identity(), &resolver())
            .expect("the retransmission is ACKed too");

        assert_eq!(first.message.method(), Some(&Method::Ack));
        assert_eq!(second.message.method(), Some(&Method::Ack));
        assert_eq!(
            second.message.headers.cseq().map(String::as_str),
            Some("2 ACK")
        );
        assert_eq!(second.destination, first.destination);
        assert_ne!(via_branch(&first.message), REINVITE_BRANCH);
        assert_ne!(via_branch(&second.message), REINVITE_BRANCH);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_2xx_whose_via_is_not_ours_is_not_acked() {
        for via in [
            // Some other host.
            "SIP/2.0/UDP 203.0.113.9:5060;branch=z9hG4bK-elsewhere",
            // Our host, but a port nothing here listens on.
            "SIP/2.0/UDP 192.0.2.60:5070;branch=z9hG4bK-other-proxy",
            // No sent-by port: siphon always stamps one.
            "SIP/2.0/UDP 192.0.2.60;branch=z9hG4bK-portless",
            // Not an RFC 3261 branch: siphon never generates one.
            "SIP/2.0/UDP 192.0.2.60:5060;branch=1234abcd",
        ] {
            let mut response = bob_reinvite_200();
            response.headers.set("Via", via.to_string());
            assert!(
                late_2xx_ack(
                    &response,
                    200,
                    &udp_from(BOB, SIPHON),
                    &identity(),
                    &resolver()
                )
                .is_none(),
                "{via} must not draw an ACK"
            );
        }
    }

    /// A 2xx to a request siphon relayed as a proxy carries the UAC's Via under
    /// ours. Its ACK is the UAC's to send (RFC 3261 §16.7), never ours.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_relayed_2xx_is_left_to_its_uac() {
        let separate_lines = parse(concat!(
            "SIP/2.0 200 OK\r\n",
            "Via: SIP/2.0/UDP 192.0.2.60:5060;branch=z9hG4bK-proxy-1\r\n",
            "Via: SIP/2.0/UDP 198.51.100.53:5060;branch=z9hG4bK-uac-1\r\n",
            "From: <sip:alice@example.com>;tag=alice-tag\r\n",
            "To: <sip:bob@example.com>;tag=bob-tag-1\r\n",
            "Call-ID: proxied@198.51.100.53\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:bob@198.51.100.52:5062>\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ));
        let mut one_line = separate_lines.clone();
        one_line.headers.set(
            "Via",
            "SIP/2.0/UDP 192.0.2.60:5060;branch=z9hG4bK-proxy-1, \
             SIP/2.0/UDP 198.51.100.53:5060;branch=z9hG4bK-uac-1"
                .to_string(),
        );
        for response in [separate_lines, one_line] {
            assert!(late_2xx_ack(
                &response,
                200,
                &udp_from(BOB, SIPHON),
                &identity(),
                &resolver()
            )
            .is_none());
        }
    }

    /// Only a 2xx is ACKed end to end. A non-2xx final is ACKed hop by hop by
    /// the transaction that sent the INVITE (RFC 3261 §17.1.1.3), and a
    /// provisional is never ACKed.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_non_2xx_response_for_an_unknown_call_is_not_acked() {
        for status_code in [100, 180, 183, 300, 481, 487, 500, 603] {
            assert!(
                late_2xx_ack(
                    &bob_reinvite_200(),
                    status_code,
                    &udp_from(BOB, SIPHON),
                    &identity(),
                    &resolver()
                )
                .is_none(),
                "{status_code} must not draw an ACK"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_2xx_to_a_request_other_than_invite_is_not_acked() {
        for cseq in ["3 BYE", "2 CANCEL", "4 UPDATE", "5 PRACK", "6 NOTIFY"] {
            let mut response = bob_reinvite_200();
            response.headers.set("CSeq", cseq.to_string());
            assert!(
                late_2xx_ack(
                    &response,
                    200,
                    &udp_from(BOB, SIPHON),
                    &identity(),
                    &resolver()
                )
                .is_none(),
                "a 2xx to {cseq} must not draw an ACK"
            );
        }
    }

    /// RFC 3261 §12.1.2: the route set is the 2xx's Record-Route reversed, and
    /// the ACK carries it and goes to its first hop (§12.2.1.1).
    #[tokio::test(flavor = "multi_thread")]
    async fn a_late_ack_carries_the_route_set_and_goes_to_its_first_hop() {
        let mut response = bob_reinvite_200();
        response.headers.add(
            "Record-Route",
            "<sip:198.51.100.10;lr;proxy-state=outer>".to_string(),
        );
        response.headers.add(
            "Record-Route",
            "<sip:198.51.100.20;lr;proxy-state=inner>".to_string(),
        );

        let late = late_2xx_ack(
            &response,
            200,
            &udp_from(BOB, SIPHON),
            &identity(),
            &resolver(),
        )
        .expect("ACKed");
        assert_eq!(
            late.message.headers.get_all("Route").cloned(),
            Some(vec![
                "<sip:198.51.100.20;lr;proxy-state=inner>".to_string(),
                "<sip:198.51.100.10;lr;proxy-state=outer>".to_string(),
            ])
        );
        assert_eq!(late.destination, address("198.51.100.20:5060"));
        assert_eq!(late.connection_id, ConnectionId::default());
    }

    /// When the first hop is the peer the 2xx came from, the ACK goes back over
    /// that same connection (RFC 5923), as every other in-dialog request does.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_route_back_to_the_answering_peer_reuses_the_arrival_connection() {
        let mut response = bob_reinvite_200();
        response.headers.set(
            "Via",
            "SIP/2.0/TCP 192.0.2.60:5060;branch=z9hG4bK-reinvite-tcp".to_string(),
        );
        response.headers.add(
            "Record-Route",
            "<sip:198.51.100.52;lr;transport=tcp>".to_string(),
        );
        let arrived_on = InboundMessage {
            connection_id: ConnectionId(7),
            transport: Transport::Tcp,
            local_addr: address(SIPHON),
            remote_addr: address("198.51.100.52:40123"),
            data: Bytes::new(),
        };

        let late =
            late_2xx_ack(&response, 200, &arrived_on, &identity(), &resolver()).expect("ACKed");
        assert_eq!(late.destination, address("198.51.100.52:40123"));
        assert_eq!(late.transport, Transport::Tcp);
        assert_eq!(late.connection_id, ConnectionId(7));
        // A stream is reached over its connection, never a source bind.
        assert_eq!(late.source_local_addr, None);
        assert!(wire(&late.message).contains("Via: SIP/2.0/TCP 192.0.2.60:5060;branch="));
    }

    /// A leg dialled over a captured flow is pinned to one socket; on an IPsec
    /// sec-agree leg it is the protected client port, and the kernel selector
    /// drops anything else (3GPP TS 33.203 §7.4). The late ACK leaves from the
    /// socket the 2xx arrived on and names it in its Via.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_late_ack_leaves_from_the_socket_the_2xx_arrived_on() {
        let mut identity = identity();
        identity.add_host("192.0.2.10", &[6100]);
        let mut response = bob_reinvite_200();
        response.headers.set(
            "Via",
            "SIP/2.0/UDP 192.0.2.10:6100;branch=z9hG4bK-flow-pinned".to_string(),
        );

        let late = late_2xx_ack(
            &response,
            200,
            &udp_from("192.0.2.20:5066", "192.0.2.10:6100"),
            &identity,
            &resolver(),
        )
        .expect("ACKed");
        assert_eq!(late.source_local_addr, Some(address("192.0.2.10:6100")));
        assert_eq!(late.destination, address("192.0.2.20:5066"));
        assert!(wire(&late.message).contains("Via: SIP/2.0/UDP 192.0.2.10:6100;branch="));
    }

    /// A 2xx to an INVITE must carry a Contact (RFC 3261 §12.1.1). For one that
    /// does not, the ACK is addressed to where the 2xx came from rather than to
    /// a placeholder no element can route.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_late_2xx_without_a_contact_is_acked_at_its_source() {
        let mut response = bob_reinvite_200();
        response.headers.remove("Contact");

        let late = late_2xx_ack(
            &response,
            200,
            &udp_from(BOB, SIPHON),
            &identity(),
            &resolver(),
        )
        .expect("ACKed");
        let text = wire(&late.message);
        assert!(
            text.starts_with("ACK sip:198.51.100.52:5060 SIP/2.0\r\n"),
            "request line:\n{text}"
        );
    }
}
