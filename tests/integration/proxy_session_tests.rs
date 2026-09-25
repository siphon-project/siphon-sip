//! Integration tests for ProxySession + server-side transaction wiring.
//!
//! Verifies that the ProxySession correctly links server transactions
//! (inbound requests) to client transactions (outbound relays), enabling
//! server-side response caching and retransmission on UDP.

use siphon::proxy::session::{ProxySession, ProxySessionStore};
use siphon::sip::builder::SipMessageBuilder;
use siphon::sip::message::Method;
use siphon::sip::uri::SipUri;
use siphon::transaction::key::TransactionKey;
use siphon::transaction::state::{Action, Transport as TxnTransport};
use siphon::transaction::{ServerEvent, TransactionManager};
use siphon::transaction::state::{IstEvent, NistEvent};
use siphon::transport::{ConnectionId, Transport};
use std::net::SocketAddr;

fn source_addr() -> SocketAddr {
    "10.0.0.1:5060".parse().unwrap()
}

fn options_request(branch: &str) -> siphon::sip::message::SipMessage {
    SipMessageBuilder::new()
        .request(Method::Options, SipUri::new("example.com".to_string()))
        .via(format!("SIP/2.0/UDP 10.0.0.1:5060;branch={branch}"))
        .to("<sip:example.com>".to_string())
        .from("<sip:user@example.com>;tag=abc".to_string())
        .call_id("session-integ-1".to_string())
        .cseq("1 OPTIONS".to_string())
        .content_length(0)
        .build()
        .unwrap()
}

fn invite_request(branch: &str) -> siphon::sip::message::SipMessage {
    SipMessageBuilder::new()
        .request(
            Method::Invite,
            SipUri::new("biloxi.com".to_string()).with_user("bob".to_string()),
        )
        .via(format!("SIP/2.0/UDP 10.0.0.1:5060;branch={branch}"))
        .to("<sip:bob@biloxi.com>".to_string())
        .from("<sip:alice@atlanta.com>;tag=xyz".to_string())
        .call_id("session-integ-2".to_string())
        .cseq("1 INVITE".to_string())
        .content_length(0)
        .build()
        .unwrap()
}

fn response_for(branch: &str, code: u16, reason: &str, method_str: &str) -> siphon::sip::message::SipMessage {
    SipMessageBuilder::new()
        .response(code, reason.to_string())
        .via(format!("SIP/2.0/UDP 10.0.0.1:5060;branch={branch}"))
        .to("<sip:example.com>".to_string())
        .from("<sip:user@example.com>;tag=abc".to_string())
        .call_id("session-integ-1".to_string())
        .cseq(format!("1 {method_str}"))
        .content_length(0)
        .build()
        .unwrap()
}

// ---------------------------------------------------------------------------
// ProxySession links server → client transaction
// ---------------------------------------------------------------------------

#[test]
fn session_links_server_to_client_transaction() {
    let store = ProxySessionStore::new();
    let server_key = TransactionKey::new("z9hG4bK-srv-1".to_string(), Method::Options, "10.0.0.1:5060".to_string());
    let client_key = TransactionKey::new("z9hG4bK-cli-1".to_string(), Method::Options, "10.0.0.1:5060".to_string());

    let mut session = ProxySession::new(
        server_key.clone(),
        source_addr(),
        ConnectionId::default(),
        Transport::Udp,
        options_request("z9hG4bK-srv-1"),
        false,
    );
    session.add_client_key(client_key.clone());
    store.insert(session);

    // Look up session by client key
    let found = store.get_by_client_key(&client_key).unwrap();
    let session = found.read().unwrap();
    assert_eq!(session.server_key, server_key);
    assert_eq!(session.source_addr, source_addr());
}

// ---------------------------------------------------------------------------
// Server transaction caches response for retransmission
// ---------------------------------------------------------------------------

#[test]
fn nist_caches_response_for_retransmit() {
    let manager = TransactionManager::default();
    let request = options_request("z9hG4bK-nist-cache");

    // Create server transaction
    let (key, _) = manager
        .new_server_transaction(&request, TxnTransport::Udp)
        .unwrap();

    // Feed a 200 OK response (simulating forwarded response from downstream)
    let response = response_for("z9hG4bK-nist-cache", 200, "OK", "OPTIONS");
    let actions = manager
        .process_server_event(&key, ServerEvent::Nist(NistEvent::TuFinal(response)))
        .unwrap();

    // State machine should produce SendMessage (to send the response)
    assert!(actions.iter().any(|a| matches!(a, Action::SendMessage(_))));

    // Now simulate a retransmit of the original request
    let retransmit_result = manager.handle_server_retransmit(&request).unwrap();
    assert!(retransmit_result.is_some());
    let (_, retransmit_actions) = retransmit_result.unwrap();

    // Should resend the cached 200 OK
    assert!(
        retransmit_actions
            .iter()
            .any(|a| matches!(a, Action::SendMessage(_))),
        "NIST in Completed should retransmit cached response"
    );
}

#[test]
fn ist_caches_provisional_for_retransmit() {
    let manager = TransactionManager::default();
    let request = invite_request("z9hG4bK-ist-prov");

    // Create server transaction for INVITE
    let (key, _) = manager
        .new_server_transaction(&request, TxnTransport::Udp)
        .unwrap();

    // Feed a 180 Ringing provisional
    let ringing = SipMessageBuilder::new()
        .response(180, "Ringing".to_string())
        .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-ist-prov".to_string())
        .to("<sip:bob@biloxi.com>;tag=resp-tag".to_string())
        .from("<sip:alice@atlanta.com>;tag=xyz".to_string())
        .call_id("session-integ-2".to_string())
        .cseq("1 INVITE".to_string())
        .content_length(0)
        .build()
        .unwrap();

    let actions = manager
        .process_server_event(&key, ServerEvent::Ist(IstEvent::TuProvisional(ringing)))
        .unwrap();
    assert!(actions.iter().any(|a| matches!(a, Action::SendMessage(_))));

    // Retransmit of INVITE should resend 180 Ringing
    let retransmit_result = manager.handle_server_retransmit(&request).unwrap();
    assert!(retransmit_result.is_some());
    let (_, retransmit_actions) = retransmit_result.unwrap();
    assert!(
        retransmit_actions
            .iter()
            .any(|a| matches!(a, Action::SendMessage(_))),
        "IST in Proceeding should retransmit cached provisional"
    );
}

// ---------------------------------------------------------------------------
// Server + client transaction full proxy round-trip
// ---------------------------------------------------------------------------

#[test]
fn full_proxy_round_trip_with_transactions() {
    let manager = TransactionManager::default();
    let store = ProxySessionStore::new();

    // 1. Incoming OPTIONS request creates server transaction
    let server_branch = "z9hG4bK-srv-round";
    let request = options_request(server_branch);
    let (server_key, server_actions) = manager
        .new_server_transaction(&request, TxnTransport::Udp)
        .unwrap();
    assert!(server_actions.iter().any(|a| matches!(a, Action::PassToTu(_))));

    // 2. Proxy relays downstream → creates client transaction
    let client_branch = "z9hG4bK-cli-round";
    let relayed = options_request(client_branch);
    let (client_key, _client_actions) = manager
        .new_client_transaction(
            &relayed,
            bytes::Bytes::from(relayed.to_bytes()),
            TxnTransport::Udp,
        )
        .unwrap();

    // 3. Create ProxySession linking them
    let mut session = ProxySession::new(
        server_key.clone(),
        source_addr(),
        ConnectionId::default(),
        Transport::Udp,
        request.clone(),
        false,
    );
    session.add_client_key(client_key.clone());
    store.insert(session);

    // 4. Response arrives from downstream → feed to client transaction
    let response = response_for(client_branch, 200, "OK", "OPTIONS");
    let client_response_actions = manager
        .process_client_event(
            &client_key,
            siphon::transaction::ClientEvent::Nict(
                siphon::transaction::state::NictEvent::FinalResponse(response.clone()),
            ),
        )
        .unwrap();
    assert!(client_response_actions.iter().any(|a| matches!(a, Action::PassToTu(_))));

    // 5. Forwarded response fed into server transaction for caching
    let server_response = response_for(server_branch, 200, "OK", "OPTIONS");
    let server_response_actions = manager
        .process_server_event(
            &server_key,
            ServerEvent::Nist(NistEvent::TuFinal(server_response)),
        )
        .unwrap();
    assert!(server_response_actions.iter().any(|a| matches!(a, Action::SendMessage(_))));

    // 6. UAC retransmits → server transaction resends cached response
    let retransmit = manager.handle_server_retransmit(&request).unwrap();
    assert!(retransmit.is_some());
    let (_, actions) = retransmit.unwrap();
    assert!(actions.iter().any(|a| matches!(a, Action::SendMessage(_))));

    // 7. Cleanup
    store.remove_client_key(&client_key);
    assert_eq!(store.session_count(), 0);
}

// ---------------------------------------------------------------------------
// Session store finds server key from client key for response routing
// ---------------------------------------------------------------------------

#[test]
fn session_store_routes_response_to_server_key() {
    let store = ProxySessionStore::new();
    let server_key = TransactionKey::new("z9hG4bK-srv-route".to_string(), Method::Invite, "10.0.0.1:5060".to_string());
    let client_key_1 = TransactionKey::new("z9hG4bK-cli-route-1".to_string(), Method::Invite, "10.0.0.1:5060".to_string());
    let client_key_2 = TransactionKey::new("z9hG4bK-cli-route-2".to_string(), Method::Invite, "10.0.0.1:5060".to_string());

    let mut session = ProxySession::new(
        server_key.clone(),
        source_addr(),
        ConnectionId::default(),
        Transport::Udp,
        invite_request("z9hG4bK-srv-route"),
        true, // record-routed
    );
    session.add_client_key(client_key_1.clone());
    session.add_client_key(client_key_2.clone());
    store.insert(session);

    // Both client keys should resolve to the same server key
    let session_1 = store.get_by_client_key(&client_key_1).unwrap();
    let session_2 = store.get_by_client_key(&client_key_2).unwrap();
    assert_eq!(session_1.read().unwrap().server_key, server_key);
    assert_eq!(session_2.read().unwrap().server_key, server_key);
    assert!(session_1.read().unwrap().record_routed);

    // Remove one client key — other should still work
    store.remove_client_key(&client_key_1);
    assert!(store.get_by_client_key(&client_key_1).is_none());
    assert!(store.get_by_client_key(&client_key_2).is_some());
    assert_eq!(store.session_count(), 1);
}

// ---------------------------------------------------------------------------
// IST server transaction: 2xx terminates, non-2xx enters Completed
// ---------------------------------------------------------------------------

#[test]
fn ist_2xx_terminates_immediately() {
    let manager = TransactionManager::default();
    let request = invite_request("z9hG4bK-ist-2xx");

    let (key, _) = manager
        .new_server_transaction(&request, TxnTransport::Reliable)
        .unwrap();
    assert_eq!(manager.count(), 1);

    let ok_response = SipMessageBuilder::new()
        .response(200, "OK".to_string())
        .via("SIP/2.0/TCP 10.0.0.1:5060;branch=z9hG4bK-ist-2xx".to_string())
        .to("<sip:bob@biloxi.com>;tag=resp".to_string())
        .from("<sip:alice@atlanta.com>;tag=xyz".to_string())
        .call_id("session-integ-2".to_string())
        .cseq("1 INVITE".to_string())
        .content_length(0)
        .build()
        .unwrap();

    let actions = manager
        .process_server_event(&key, ServerEvent::Ist(IstEvent::Tu2xx(ok_response)))
        .unwrap();

    // On reliable transport, 2xx should terminate immediately
    assert!(actions.iter().any(|a| matches!(a, Action::SendMessage(_))));
    assert!(actions.iter().any(|a| matches!(a, Action::Terminated)));
    assert_eq!(manager.count(), 0);
}

#[test]
fn ist_non_2xx_enters_completed_on_udp() {
    let manager = TransactionManager::default();
    let request = invite_request("z9hG4bK-ist-err");

    let (key, _) = manager
        .new_server_transaction(&request, TxnTransport::Udp)
        .unwrap();

    // Send 100 Trying first (moves to Proceeding)
    let trying = SipMessageBuilder::new()
        .response(100, "Trying".to_string())
        .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-ist-err".to_string())
        .to("<sip:bob@biloxi.com>".to_string())
        .from("<sip:alice@atlanta.com>;tag=xyz".to_string())
        .call_id("session-integ-2".to_string())
        .cseq("1 INVITE".to_string())
        .content_length(0)
        .build()
        .unwrap();
    manager
        .process_server_event(&key, ServerEvent::Ist(IstEvent::TuProvisional(trying)))
        .unwrap();

    // Send 486 Busy Here (non-2xx final)
    let busy = SipMessageBuilder::new()
        .response(486, "Busy Here".to_string())
        .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-ist-err".to_string())
        .to("<sip:bob@biloxi.com>;tag=resp".to_string())
        .from("<sip:alice@atlanta.com>;tag=xyz".to_string())
        .call_id("session-integ-2".to_string())
        .cseq("1 INVITE".to_string())
        .content_length(0)
        .build()
        .unwrap();

    let actions = manager
        .process_server_event(&key, ServerEvent::Ist(IstEvent::TuNon2xxFinal(busy)))
        .unwrap();

    // Should send the response and start Timer G (retransmit) and Timer H (timeout)
    assert!(actions.iter().any(|a| matches!(a, Action::SendMessage(_))));
    // On UDP, IST enters Completed (not terminated) — waits for ACK
    assert!(!actions.iter().any(|a| matches!(a, Action::Terminated)));
    assert_eq!(manager.count(), 1);
}
