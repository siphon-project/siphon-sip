//! A request this node originates on a connection it already has.
//!
//! A node in server mode answers what its peers send, but some procedures
//! start at the server: an HSS cancels a location, inserts or deletes
//! subscriber data and announces a reset towards the MME (TS 29.272 clauses
//! 5.2.1.2, 5.2.2.1, 5.2.2.2 and 5.2.4.1), and alerts a service centre over
//! S6c (TS 29.338 clause 5.2.2). The connections those requests leave on are
//! the serving connections the peers (or the agent relaying for them) opened,
//! or opened by this node with `connect_to`; [`super::reauthorize`] records
//! each by the Origin-Host and Origin-Realm of the requests it carried. A
//! client-mode peer of `diameter.peers` can be named as well.
//!
//! The envelope (Session-Id first, RFC 6733 section 3; Origin-Host and
//! Origin-Realm of the connection; Destination-Host and Destination-Realm) is
//! built here. Everything else, Auth-Session-State and
//! Vendor-Specific-Application-Id included, is the caller's, in its order:
//! S6c forbids the latter (TS 29.338 clause 5.3.2.2) where S6a carries it.
use super::codec::{Avp, DiameterMsg, FLAG_PROXIABLE, FLAG_REQUEST};
use super::dictionary::avp;
use super::peer::DiameterPeer;
use super::{reauthorize, DiameterManager};
use std::sync::Arc;

/// The AVPs the envelope sets; a caller cannot supply them again.
pub(crate) const ENVELOPE_AVPS: [u32; 5] = [
    avp::SESSION_ID,
    avp::ORIGIN_HOST,
    avp::ORIGIN_REALM,
    avp::DESTINATION_HOST,
    avp::DESTINATION_REALM,
];

/// The tenant a script names when it names none. Client-mode peers of
/// `diameter.peers` belong to the node rather than to a tenant, so only this
/// tenant reaches them; any other tenant reaches its own connections alone.
pub(crate) const DEFAULT_TENANT: &str = "default";

/// Why no connection was found for a request.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Unreachable {
    /// A Destination-Host this node has no connection to and no agent of its
    /// realm to relay through: DIAMETER_UNABLE_TO_DELIVER (RFC 6733 section
    /// 6.1). Another peer of the realm is not the host and is not asked.
    Host,
    /// No open connection towards the realm, or none of the named peer.
    NoConnection,
}

/// The connection a request to `destination_host` / `destination_realm` of
/// `tenant` leaves on. With `peer`, the serving connection of that configured
/// peer that carried requests from the host, else the tenant's relay backend
/// of that name, else (for [`DEFAULT_TENANT`] only) the client-mode peer of
/// that name. Without, and with a host, the serving connection that carried
/// requests from the host, else one that carried requests relayed from the
/// realm: an agent routes the request on to the host (RFC 6733 section
/// 6.1.5). A direct peer of the realm is not the host and does not route
/// on, so a request for a host is never handed to it (RFC 6733 section 6.1):
/// that is [`Unreachable::Host`]. Without a host, any connection that carried
/// requests from the realm. Only an open connection is returned.
pub(crate) fn connection(
    manager: &DiameterManager,
    tenant: &str,
    peer: Option<&str>,
    destination_host: Option<&str>,
    destination_realm: &str,
) -> Result<Arc<DiameterPeer>, Unreachable> {
    match (peer, destination_host) {
        (Some(name), _) => destination_host
            .and_then(|host| reauthorize::connection(tenant, name, host))
            .or_else(|| {
                manager
                    .live_backend(tenant, name)
                    .or_else(|| {
                        (tenant == DEFAULT_TENANT)
                            .then(|| manager.live_client(name))
                            .flatten()
                    })
                    .map(|client| Arc::clone(client.peer()))
            })
            .ok_or(Unreachable::NoConnection),
        (None, Some(host)) => reauthorize::connection_to_host(tenant, host)
            .or_else(|| reauthorize::agent_for_realm(tenant, destination_realm))
            .ok_or(Unreachable::Host),
        (None, None) => reauthorize::connection_to_realm(tenant, destination_realm)
            .ok_or(Unreachable::NoConnection),
    }
}

/// What a caller asks to send.
pub(crate) struct Request<'a> {
    pub command_code: u32,
    pub application_id: u32,
    pub proxiable: bool,
    /// None: a new Session-Id of the connection's identity.
    pub session_id: Option<&'a str>,
    pub destination_host: Option<&'a str>,
    pub destination_realm: &'a str,
    /// The caller's AVPs, after the envelope, in this order.
    pub avps: Vec<Avp>,
}

/// Why a request was not built.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// An identity of the envelope is empty.
    EmptyIdentity,
    /// The caller's AVPs hold one the envelope sets (its code).
    EnvelopeAvp(u32),
}

/// The request on the wire, with the connection's next hop-by-hop and
/// end-to-end identifiers.
pub(crate) fn wire(peer: &DiameterPeer, request: Request<'_>) -> Result<Vec<u8>, Refusal> {
    if request.destination_realm.is_empty()
        || request.destination_host.is_some_and(str::is_empty)
        || request.session_id.is_some_and(str::is_empty)
    {
        return Err(Refusal::EmptyIdentity);
    }
    if let Some(taken) = request
        .avps
        .iter()
        .find(|item| item.vendor == 0 && ENVELOPE_AVPS.contains(&item.code))
    {
        return Err(Refusal::EnvelopeAvp(taken.code));
    }
    let config = peer.config();
    let session = request
        .session_id
        .map_or_else(|| peer.new_session_id(), str::to_owned);
    let text = |code, value: &str| Avp::raw(code, 0, value.as_bytes().to_vec());
    let mut avps = Vec::with_capacity(5 + request.avps.len());
    avps.push(text(avp::SESSION_ID, &session));
    avps.push(text(avp::ORIGIN_HOST, &config.origin_host));
    avps.push(text(avp::ORIGIN_REALM, &config.origin_realm));
    if let Some(host) = request.destination_host {
        avps.push(text(avp::DESTINATION_HOST, host));
    }
    avps.push(text(avp::DESTINATION_REALM, request.destination_realm));
    avps.extend(request.avps);
    let flags = if request.proxiable {
        FLAG_REQUEST | FLAG_PROXIABLE
    } else {
        FLAG_REQUEST
    };
    Ok(DiameterMsg {
        flags,
        command_code: request.command_code,
        application_id: request.application_id,
        hop_by_hop: peer.next_hbh(),
        end_to_end: peer.next_e2e(),
        avps,
    }
    .to_wire())
}

/// How a request that left without an answer coming back failed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Failure {
    /// No answer within the timeout.
    Timeout,
    /// The connection closed, or would not take the request.
    Connection,
}

/// The [`Failure`] of a `DiameterPeer::send_request_timeout` error.
pub(crate) fn failure(reason: &str) -> Failure {
    if reason.contains("timed out") {
        Failure::Timeout
    } else {
        Failure::Connection
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diameter::codec::{self, AvpData};
    use crate::diameter::dictionary::{self, VENDOR_3GPP};
    use crate::diameter::reauthorize::{tests::open_peer, ServingConnection};
    use serde_json::json;

    const CANCEL_LOCATION: u32 = 317;

    fn cancel_location(avps: Vec<Avp>) -> Request<'static> {
        Request {
            command_code: CANCEL_LOCATION,
            application_id: dictionary::S6A_APP_ID,
            proxiable: true,
            session_id: Some("chf.example;1;9"),
            destination_host: Some("mme1.epc.example"),
            destination_realm: "epc.example",
            avps,
        }
    }

    #[test]
    fn the_envelope_comes_first_and_the_callers_avps_follow_in_order() {
        let peer = open_peer();
        let user_name = Avp::raw(avp::USER_NAME, 0, b"001010000000001".to_vec());
        // CLR-Flags (TS 29.272 table 7.3.1/1): V set, M must not be.
        let mut clr_flags = Avp::raw(1638, VENDOR_3GPP, 2u32.to_be_bytes().to_vec());
        clr_flags.flags = codec::AVP_FLAG_VENDOR;
        let wire = wire(&peer, cancel_location(vec![user_name, clr_flags])).unwrap();
        let message = DiameterMsg::from_wire(&wire).unwrap();
        assert_eq!(message.command_code, CANCEL_LOCATION);
        assert_eq!(message.application_id, dictionary::S6A_APP_ID);
        assert_eq!(message.flags, FLAG_REQUEST | FLAG_PROXIABLE);
        let codes: Vec<(u32, u32)> = message
            .avps
            .iter()
            .map(|item| (item.code, item.vendor))
            .collect();
        assert_eq!(
            codes,
            vec![
                (avp::SESSION_ID, 0),
                (avp::ORIGIN_HOST, 0),
                (avp::ORIGIN_REALM, 0),
                (avp::DESTINATION_HOST, 0),
                (avp::DESTINATION_REALM, 0),
                (avp::USER_NAME, 0),
                (1638, VENDOR_3GPP),
            ]
        );
        assert_eq!(
            message.get_str(avp::SESSION_ID).as_deref(),
            Some("chf.example;1;9")
        );
        assert_eq!(
            message.get_str(avp::ORIGIN_HOST).as_deref(),
            Some("chf.example")
        );
        assert_eq!(
            message.get_str(avp::ORIGIN_REALM).as_deref(),
            Some("example")
        );
        assert_eq!(
            message.get_str(avp::DESTINATION_HOST).as_deref(),
            Some("mme1.epc.example")
        );
        let flags = message.avps.last().unwrap();
        assert_eq!(flags.flags, codec::AVP_FLAG_VENDOR);
        assert_eq!(flags.value, AvpData::Raw(vec![0, 0, 0, 2]));
    }

    #[test]
    fn without_a_session_id_or_host_the_connection_names_the_session() {
        let peer = open_peer();
        let mut request = cancel_location(Vec::new());
        request.session_id = None;
        request.destination_host = None;
        request.proxiable = false;
        let message = DiameterMsg::from_wire(&wire(&peer, request).unwrap()).unwrap();
        assert_eq!(message.flags, FLAG_REQUEST);
        assert!(message
            .get_str(avp::SESSION_ID)
            .is_some_and(|session| session.starts_with("chf.example;")));
        assert!(message.find(avp::DESTINATION_HOST, 0).is_none());
    }

    #[test]
    fn an_envelope_avp_or_an_empty_identity_is_refused() {
        let peer = open_peer();
        let origin = Avp::raw(avp::ORIGIN_HOST, 0, b"other.example".to_vec());
        assert_eq!(
            wire(&peer, cancel_location(vec![origin])),
            Err(Refusal::EnvelopeAvp(avp::ORIGIN_HOST))
        );
        let mut request = cancel_location(Vec::new());
        request.destination_realm = "";
        assert_eq!(wire(&peer, request), Err(Refusal::EmptyIdentity));
        let mut request = cancel_location(Vec::new());
        request.destination_host = Some("");
        assert_eq!(wire(&peer, request), Err(Refusal::EmptyIdentity));
    }

    #[test]
    fn a_host_is_preferred_and_an_agent_of_the_realm_is_the_fallback() {
        let manager = DiameterManager::new();
        let direct = open_peer();
        let agent = open_peer();
        let mut direct_serving = ServingConnection::new("t-originate", "mme", &direct);
        direct_serving
            .observe(&json!({"Origin-Host": "mme1.epc.example", "Origin-Realm": "epc.example"}));
        let mut agent_serving = ServingConnection::new("t-originate", "dra", &agent);
        agent_serving.observe(&json!({
            "Origin-Host": "mme2.epc.example",
            "Origin-Realm": "epc.example",
            "Route-Record": "mme2.epc.example",
        }));
        let found = |peer, host| connection(&manager, "t-originate", peer, host, "epc.example");
        assert!(Arc::ptr_eq(
            &found(None, Some("mme1.epc.example")).unwrap(),
            &direct
        ));
        assert!(Arc::ptr_eq(
            &found(None, Some("mme2.epc.example")).unwrap(),
            &agent
        ));
        // An unknown host of the realm goes through the agent relaying for
        // the realm, which routes it on (RFC 6733 section 6.1.5).
        assert!(Arc::ptr_eq(
            &found(None, Some("mme3.epc.example")).unwrap(),
            &agent
        ));
        assert!(Arc::ptr_eq(
            &found(Some("mme"), Some("mme1.epc.example")).unwrap(),
            &direct
        ));
        // A named peer that never carried the host, with no client of that name.
        assert_eq!(
            found(Some("mme"), Some("mme2.epc.example")).err(),
            Some(Unreachable::NoConnection)
        );
        assert_eq!(
            connection(&manager, "t-originate", None, None, "other.example").err(),
            Some(Unreachable::NoConnection)
        );
        assert_eq!(
            connection(
                &manager,
                "t-elsewhere",
                None,
                Some("mme1.epc.example"),
                "epc.example"
            )
            .err(),
            Some(Unreachable::Host)
        );
    }

    /// A request for a host this node has no connection to is not handed to
    /// another peer of the realm that is not an agent: that peer is not the
    /// host and does not route on (RFC 6733 section 6.1). A realm-only
    /// request still goes to any connection of the realm.
    #[test]
    fn a_host_without_a_connection_or_an_agent_is_unable_to_deliver() {
        let manager = DiameterManager::new();
        let direct = open_peer();
        let mut direct_serving = ServingConnection::new("t-strict", "mme", &direct);
        direct_serving
            .observe(&json!({"Origin-Host": "mme1.epc.example", "Origin-Realm": "epc.example"}));
        let found = |host| connection(&manager, "t-strict", None, host, "epc.example");
        assert!(Arc::ptr_eq(
            &found(Some("mme1.epc.example")).unwrap(),
            &direct
        ));
        assert_eq!(
            found(Some("mme2.epc.example")).err(),
            Some(Unreachable::Host)
        );
        assert!(Arc::ptr_eq(&found(None).unwrap(), &direct));
        drop(direct_serving);
    }

    fn connection_config() -> crate::diameter::peer::PeerConfig {
        crate::diameter::peer::PeerConfig {
            host: "192.0.2.10".into(),
            port: 3868,
            origin_host: "hss.epc.example".into(),
            origin_realm: "epc.example".into(),
            destination_host: None,
            destination_realm: "epc.example".into(),
            local_ip: "192.0.2.11".parse().unwrap(),
            application_ids: vec![(10415, dictionary::S6A_APP_ID)],
            watchdog_interval: 30,
            reconnect_delay: 5,
            product_name: "test".into(),
            firmware_revision: 1,
        }
    }

    /// The request goes out on a live connection and the answer, sent back
    /// with its hop-by-hop identifier, comes back to the caller.
    #[tokio::test]
    async fn the_answer_comes_back_on_the_connection_the_request_left_on() {
        let (local, mut remote) = tokio::io::duplex(65_536);
        let (incoming, _incoming) = tokio::sync::mpsc::channel(4);
        let peer =
            crate::diameter::peer::spawn_connection_tasks(connection_config(), local, incoming);
        let user_name = Avp::raw(avp::USER_NAME, 0, b"001010000000001".to_vec());
        let request = wire(&peer, cancel_location(vec![user_name])).unwrap();
        let answering = tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let bytes = codec::read_diameter_message(&mut remote).await.unwrap();
            let received = DiameterMsg::from_wire(&bytes).unwrap();
            let answer = DiameterMsg {
                flags: FLAG_PROXIABLE,
                command_code: received.command_code,
                application_id: received.application_id,
                hop_by_hop: received.hop_by_hop,
                end_to_end: received.end_to_end,
                avps: vec![
                    received.avps[0].clone(),
                    Avp::raw(avp::RESULT_CODE, 0, 2001u32.to_be_bytes().to_vec()),
                ],
            };
            remote.write_all(&answer.to_wire()).await.unwrap();
            (received, remote)
        });
        let answer = peer
            .send_request_timeout(request, std::time::Duration::from_secs(5))
            .await
            .unwrap();
        let (received, _remote) = answering.await.unwrap();
        assert!(received.is_request());
        assert_eq!(
            received.get_str(avp::USER_NAME).as_deref(),
            Some("001010000000001")
        );
        let answer = DiameterMsg::from_wire(&answer.raw).unwrap();
        assert_eq!(answer.command_code, CANCEL_LOCATION);
        assert_eq!(
            answer.find(avp::RESULT_CODE, 0).and_then(Avp::as_u32),
            Some(2001)
        );
    }

    /// A connection that closes while the request waits is a connection
    /// failure, not a timeout.
    #[tokio::test]
    async fn a_connection_closing_before_the_answer_is_a_connection_failure() {
        let (local, mut remote) = tokio::io::duplex(65_536);
        let (incoming, _incoming) = tokio::sync::mpsc::channel(4);
        let peer =
            crate::diameter::peer::spawn_connection_tasks(connection_config(), local, incoming);
        let request = wire(&peer, cancel_location(Vec::new())).unwrap();
        tokio::spawn(async move {
            let _ = codec::read_diameter_message(&mut remote).await;
            drop(remote);
        });
        let reason = peer
            .send_request_timeout(request, std::time::Duration::from_secs(5))
            .await
            .unwrap_err();
        assert_eq!(failure(&reason), Failure::Connection, "{reason}");
    }

    #[test]
    fn a_timeout_is_told_apart_from_a_lost_connection() {
        assert_eq!(failure("request timed out after 5s"), Failure::Timeout);
        assert_eq!(failure("write channel closed"), Failure::Connection);
        assert_eq!(failure("peer outbound queue full"), Failure::Connection);
    }

    /// The Session-Id AVPs of a request on the wire, in order.
    fn session_ids(wire: &[u8]) -> Vec<String> {
        DiameterMsg::from_wire(wire)
            .unwrap()
            .avps
            .iter()
            .filter(|item| item.code == avp::SESSION_ID && item.vendor == 0)
            .map(|item| match &item.value {
                AvpData::Raw(bytes) => String::from_utf8(bytes.clone()).unwrap(),
                AvpData::Grouped(_) => panic!("Session-Id is not grouped"),
            })
            .collect()
    }

    /// A PCRF's Re-Auth then Abort-Session on one Rx session, and a PCEF's
    /// CCR-I, -U and -T on one Gx session: each request carries the one
    /// Session-Id given, never a second one, and its own identifiers (RFC 6733
    /// sections 3 and 8.8; TS 29.214 clauses 4.4.6 and 4.4.4; TS 29.212
    /// clause 4.5.1).
    #[test]
    fn a_given_session_id_is_the_only_one_and_is_reused_across_requests() {
        const RE_AUTH: u32 = 258;
        const ABORT_SESSION: u32 = 274;
        const CREDIT_CONTROL: u32 = 272;
        let peer = open_peer();
        let rx_session = "pcrf.epc.mnc001.mcc001.3gppnetwork.org;7;1";
        let gx_session = "pgw.epc.mnc001.mcc001.3gppnetwork.org;9;2";
        let request = |command_code, application_id, session_id, avps| Request {
            command_code,
            application_id,
            proxiable: true,
            session_id: Some(session_id),
            destination_host: Some("peer.epc.mnc001.mcc001.3gppnetwork.org"),
            destination_realm: "epc.mnc001.mcc001.3gppnetwork.org",
            avps,
        };
        let u32_avp = |code, value: u32| Avp::raw(code, 0, value.to_be_bytes().to_vec());
        let mut identifiers = Vec::new();
        for command_code in [RE_AUTH, ABORT_SESSION] {
            let wire = wire(
                &peer,
                request(command_code, dictionary::RX_APP_ID, rx_session, Vec::new()),
            )
            .unwrap();
            assert_eq!(session_ids(&wire), vec![rx_session.to_string()]);
            let message = DiameterMsg::from_wire(&wire).unwrap();
            identifiers.push((message.hop_by_hop, message.end_to_end));
        }
        // CC-Request-Type 416 and CC-Request-Number 415 are the caller's.
        for (request_type, number) in [(1u32, 0u32), (2, 1), (3, 2)] {
            let avps = vec![u32_avp(416, request_type), u32_avp(415, number)];
            let wire = wire(
                &peer,
                request(CREDIT_CONTROL, dictionary::GX_APP_ID, gx_session, avps),
            )
            .unwrap();
            assert_eq!(session_ids(&wire), vec![gx_session.to_string()]);
            let message = DiameterMsg::from_wire(&wire).unwrap();
            assert_eq!(
                message.find(416, 0).and_then(Avp::as_u32),
                Some(request_type)
            );
            assert_eq!(message.find(415, 0).and_then(Avp::as_u32), Some(number));
            identifiers.push((message.hop_by_hop, message.end_to_end));
        }
        let mut distinct = identifiers.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), identifiers.len(), "{identifiers:?}");
        // A Session-Id in the caller's AVPs would be a second one: refused.
        let doubled = request(
            RE_AUTH,
            dictionary::GX_APP_ID,
            gx_session,
            vec![Avp::raw(avp::SESSION_ID, 0, gx_session.as_bytes().to_vec())],
        );
        assert_eq!(
            wire(&peer, doubled),
            Err(Refusal::EnvelopeAvp(avp::SESSION_ID))
        );
    }

    /// A named peer reaches the tenant's own connections; the node's
    /// client-mode peers only from the default tenant.
    #[test]
    fn a_named_peer_stays_inside_its_tenant() {
        let manager = DiameterManager::new();
        let client = open_peer();
        manager.register(
            "pcrf".into(),
            Arc::new(crate::diameter::DiameterClient::new(Arc::clone(&client))),
        );
        let backend = open_peer();
        manager.register_backend(
            "t-isolated",
            "pcrf",
            Arc::new(crate::diameter::DiameterClient::new(Arc::clone(&backend))),
        );
        let found = |tenant| connection(&manager, tenant, Some("pcrf"), None, "epc.example");
        assert!(Arc::ptr_eq(&found(DEFAULT_TENANT).unwrap(), &client));
        assert!(Arc::ptr_eq(&found("t-isolated").unwrap(), &backend));
        assert_eq!(found("t-other").err(), Some(Unreachable::NoConnection));
    }

    /// Answer `received` on `remote` with `result_code`, echoing its
    /// Session-Id and identifiers.
    async fn answer(
        remote: &mut tokio::io::DuplexStream,
        received: &DiameterMsg,
        result_code: u32,
    ) {
        use tokio::io::AsyncWriteExt;
        let answer = DiameterMsg {
            flags: FLAG_PROXIABLE,
            command_code: received.command_code,
            application_id: received.application_id,
            hop_by_hop: received.hop_by_hop,
            end_to_end: received.end_to_end,
            avps: vec![
                received.avps[0].clone(),
                Avp::raw(avp::RESULT_CODE, 0, result_code.to_be_bytes().to_vec()),
            ],
        };
        remote.write_all(&answer.to_wire()).await.unwrap();
    }

    /// Two requests in flight on one connection, answered in the reverse
    /// order: each caller gets the answer to its own request.
    #[tokio::test]
    async fn concurrent_requests_each_get_their_own_answer() {
        let (local, mut remote) = tokio::io::duplex(65_536);
        let (incoming, _incoming) = tokio::sync::mpsc::channel(4);
        let peer =
            crate::diameter::peer::spawn_connection_tasks(connection_config(), local, incoming);
        let answering = tokio::spawn(async move {
            let first = codec::read_diameter_message(&mut remote).await.unwrap();
            let second = codec::read_diameter_message(&mut remote).await.unwrap();
            let first = DiameterMsg::from_wire(&first).unwrap();
            let second = DiameterMsg::from_wire(&second).unwrap();
            // Result-Code tells the answers apart: 2001 for the first session,
            // 5002 (DIAMETER_UNKNOWN_SESSION_ID) for the second.
            let code = |message: &DiameterMsg| {
                if message.get_str(avp::SESSION_ID).as_deref() == Some("hss.epc.example;1;1") {
                    2001
                } else {
                    5002
                }
            };
            answer(&mut remote, &second, code(&second)).await;
            answer(&mut remote, &first, code(&first)).await;
            remote
        });
        let send = |session: &'static str| {
            let mut request = cancel_location(Vec::new());
            request.session_id = Some(session);
            let wire = wire(&peer, request).unwrap();
            let peer = Arc::clone(&peer);
            async move {
                peer.send_request_timeout(wire, std::time::Duration::from_secs(5))
                    .await
                    .unwrap()
            }
        };
        let (one, two) = tokio::join!(send("hss.epc.example;1;1"), send("hss.epc.example;1;2"));
        let _remote = answering.await.unwrap();
        let read = |raw: &[u8]| {
            let message = DiameterMsg::from_wire(raw).unwrap();
            (
                message.get_str(avp::SESSION_ID).unwrap(),
                message.find(avp::RESULT_CODE, 0).and_then(Avp::as_u32),
            )
        };
        assert_eq!(read(&one.raw), ("hss.epc.example;1;1".into(), Some(2001)));
        assert_eq!(read(&two.raw), ("hss.epc.example;1;2".into(), Some(5002)));
    }

    /// A peer that reads the request and never answers is a timeout, not a
    /// lost connection.
    #[tokio::test]
    async fn a_peer_that_does_not_answer_is_a_timeout() {
        let (local, mut remote) = tokio::io::duplex(65_536);
        let (incoming, _incoming) = tokio::sync::mpsc::channel(4);
        let peer =
            crate::diameter::peer::spawn_connection_tasks(connection_config(), local, incoming);
        let request = wire(&peer, cancel_location(Vec::new())).unwrap();
        let holding = tokio::spawn(async move {
            let _ = codec::read_diameter_message(&mut remote).await;
            remote
        });
        let reason = peer
            .send_request_timeout(request, std::time::Duration::from_millis(50))
            .await
            .unwrap_err();
        assert_eq!(failure(&reason), Failure::Timeout, "{reason}");
        let _remote = holding.await.unwrap();
    }

    /// A connection the server accepted, found by the host its requests came
    /// from, and one this node initiated as a client-mode peer: the request
    /// leaves on each and the answer comes back on it.
    #[tokio::test]
    async fn requests_leave_on_an_accepted_and_on_an_initiated_connection() {
        let manager = DiameterManager::new();
        let (accepted_local, mut accepted_remote) = tokio::io::duplex(65_536);
        let (initiated_local, mut initiated_remote) = tokio::io::duplex(65_536);
        let (incoming, _incoming) = tokio::sync::mpsc::channel(4);
        let accepted = crate::diameter::peer::spawn_connection_tasks(
            connection_config(),
            accepted_local,
            incoming.clone(),
        );
        let initiated = crate::diameter::peer::spawn_connection_tasks(
            connection_config(),
            initiated_local,
            incoming,
        );
        let mut serving = ServingConnection::new("t-both-ways", "pcscf", &accepted);
        serving.observe(&json!({
            "Origin-Host": "pcscf1.ims.example",
            "Origin-Realm": "ims.example",
        }));
        manager.register(
            "pcrf".into(),
            Arc::new(crate::diameter::DiameterClient::new(Arc::clone(&initiated))),
        );
        for (tenant, peer, host, remote) in [
            (
                "t-both-ways",
                None,
                Some("pcscf1.ims.example"),
                &mut accepted_remote,
            ),
            (DEFAULT_TENANT, Some("pcrf"), None, &mut initiated_remote),
        ] {
            let chosen = connection(&manager, tenant, peer, host, "ims.example").unwrap();
            let request = Request {
                command_code: 258,
                application_id: dictionary::RX_APP_ID,
                proxiable: true,
                session_id: Some("pcrf.ims.example;3;4"),
                destination_host: host,
                destination_realm: "ims.example",
                avps: Vec::new(),
            };
            let wire = wire(&chosen, request).unwrap();
            let pending = {
                let chosen = Arc::clone(&chosen);
                tokio::spawn(async move {
                    chosen
                        .send_request_timeout(wire, std::time::Duration::from_secs(5))
                        .await
                })
            };
            let bytes = codec::read_diameter_message(remote).await.unwrap();
            let received = DiameterMsg::from_wire(&bytes).unwrap();
            assert_eq!(received.command_code, 258);
            answer(remote, &received, 2001).await;
            let answered = pending.await.unwrap().unwrap();
            let answered = DiameterMsg::from_wire(&answered.raw).unwrap();
            assert_eq!(
                answered.find(avp::RESULT_CODE, 0).and_then(Avp::as_u32),
                Some(2001)
            );
        }
        drop(serving);
    }
}
