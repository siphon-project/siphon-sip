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

/// The connection a request to `destination_host` / `destination_realm` of
/// `tenant` leaves on. With `peer`, the serving connection of that configured
/// peer that carried requests from the host, else the client-mode peer of
/// that name. Without, the serving connection that carried requests from the
/// host, else one that carried requests from a node of the realm: an agent
/// routes the request on to the host (RFC 6733 section 6.1.5). Only an open
/// connection is returned.
pub(crate) fn connection(
    manager: &DiameterManager,
    tenant: &str,
    peer: Option<&str>,
    destination_host: Option<&str>,
    destination_realm: &str,
) -> Option<Arc<DiameterPeer>> {
    match peer {
        Some(name) => destination_host
            .and_then(|host| reauthorize::connection(tenant, name, host))
            .or_else(|| {
                manager
                    .live_client(name)
                    .map(|client| Arc::clone(client.peer()))
            }),
        None => destination_host
            .and_then(|host| reauthorize::connection_to_host(tenant, host))
            .or_else(|| reauthorize::connection_to_realm(tenant, destination_realm)),
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
    fn a_host_is_preferred_and_a_realm_is_the_fallback() {
        let manager = DiameterManager::new();
        let direct = open_peer();
        let agent = open_peer();
        let mut direct_serving = ServingConnection::new("t-originate", "mme", &direct);
        direct_serving
            .observe(&json!({"Origin-Host": "mme1.epc.example", "Origin-Realm": "epc.example"}));
        let mut agent_serving = ServingConnection::new("t-originate", "dra", &agent);
        agent_serving
            .observe(&json!({"Origin-Host": "mme2.epc.example", "Origin-Realm": "epc.example"}));
        let found = |peer, host| connection(&manager, "t-originate", peer, host, "epc.example");
        assert!(Arc::ptr_eq(
            &found(None, Some("mme1.epc.example")).unwrap(),
            &direct
        ));
        assert!(Arc::ptr_eq(
            &found(None, Some("mme2.epc.example")).unwrap(),
            &agent
        ));
        // An unknown host of the realm goes where the realm was last seen.
        assert!(Arc::ptr_eq(
            &found(None, Some("mme3.epc.example")).unwrap(),
            &agent
        ));
        assert!(Arc::ptr_eq(
            &found(Some("mme"), Some("mme1.epc.example")).unwrap(),
            &direct
        ));
        // A named peer that never carried the host, with no client of that name.
        assert!(found(Some("mme"), Some("mme2.epc.example")).is_none());
        assert!(connection(&manager, "t-originate", None, None, "other.example").is_none());
        assert!(connection(
            &manager,
            "t-elsewhere",
            None,
            Some("mme1.epc.example"),
            "epc.example"
        )
        .is_none());
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
}
