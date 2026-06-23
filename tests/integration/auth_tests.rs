//! Integration tests for the auth module.
//!
//! Tests the full digest authentication challenge/response cycle using
//! the Rust-backed PyAuth struct directly (without Python).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use siphon::script::api::auth::PyAuth;
use siphon::script::api::request::{PyRequest, RequestAction};
use siphon::sip::builder::SipMessageBuilder;
use siphon::sip::message::Method;
use siphon::sip::uri::SipUri;

/// Compute MD5 hex digest of a string (mirrors auth.rs's md5_hex).
fn md5_hex(input: &str) -> String {
    format!("{:x}", md5::compute(input.as_bytes()))
}

/// Build a Digest Authorization header with a valid RFC 2617 response.
fn digest_header(username: &str, password: &str, realm: &str, nonce: &str, uri: &str, method: &str) -> String {
    let ha1 = md5_hex(&format!("{username}:{realm}:{password}"));
    let ha2 = md5_hex(&format!("{method}:{uri}"));
    let response = md5_hex(&format!("{ha1}:{nonce}:{ha2}"));
    format!(
        "Digest username=\"{username}\", realm=\"{realm}\", nonce=\"{nonce}\", uri=\"{uri}\", response=\"{response}\""
    )
}

/// A fresh timestamp-bound nonce accepted by the RFC 7616 §3.3 freshness check
/// (tests run with no nonce secret, so freshness is the only gate). Matches the
/// `{secs:016x}.tag` format minted by PyAuth::generate_nonce.
fn fresh_nonce() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    format!("{secs:016x}.test")
}

fn make_register(auth_header: Option<&str>) -> PyRequest {
    let mut builder = SipMessageBuilder::new()
        .request(
            Method::Register,
            SipUri::new("atlanta.com".to_string()),
        )
        .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-auth-test".to_string())
        .to("Alice <sip:alice@atlanta.com>".to_string())
        .from("Alice <sip:alice@atlanta.com>;tag=auth123".to_string())
        .call_id("auth-test-call@10.0.0.1".to_string())
        .cseq("1 REGISTER".to_string())
        .max_forwards(70)
        .content_length(0);

    if let Some(header) = auth_header {
        builder = builder.header("Authorization", header.to_string());
    }

    let message = builder.build().unwrap();
    PyRequest::new(
        Arc::new(Mutex::new(message)),
        "udp".to_string(),
        "10.0.0.1".to_string(),
        5060,
    )
}

fn make_auth(realm: &str, users: &[(&str, &str)]) -> PyAuth {
    let mut realm_users = HashMap::new();
    let user_map: HashMap<String, String> = users
        .iter()
        .map(|(user, pass)| (user.to_string(), pass.to_string()))
        .collect();
    realm_users.insert(realm.to_string(), user_map);
    PyAuth::new(realm_users, realm.to_string())
}

#[test]
fn www_digest_challenge_sets_401_reply() {
    let auth = make_auth("atlanta.com", &[("alice", "secret123")]);
    let mut request = make_register(None);

    let result = auth.challenge_www(&mut request, Some("atlanta.com")).unwrap();
    assert!(!result, "should return false when no credentials present");

    match request.action() {
        RequestAction::Reply { code, reason, .. } => {
            assert_eq!(*code, 401);
            assert_eq!(reason, "Unauthorized");
        }
        other => panic!("expected Reply action, got {:?}", other),
    }

    // Verify WWW-Authenticate header was set on the message
    let message = request.message();
    let message = message.lock().unwrap();
    let www_auth = message.headers.get("WWW-Authenticate");
    assert!(www_auth.is_some(), "WWW-Authenticate header should be set");
    let header_value = www_auth.unwrap();
    assert!(header_value.contains("Digest"), "should be Digest auth");
    assert!(header_value.contains("realm=\"atlanta.com\""));
    assert!(header_value.contains("nonce="));
}

#[test]
fn proxy_digest_challenge_sets_407_reply() {
    let auth = make_auth("atlanta.com", &[("alice", "secret123")]);

    let message = SipMessageBuilder::new()
        .request(
            Method::Invite,
            SipUri::new("atlanta.com".to_string()).with_user("bob".to_string()),
        )
        .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-proxy-auth".to_string())
        .to("Bob <sip:bob@atlanta.com>".to_string())
        .from("Alice <sip:alice@atlanta.com>;tag=inv123".to_string())
        .call_id("proxy-auth-test@10.0.0.1".to_string())
        .cseq("1 INVITE".to_string())
        .max_forwards(70)
        .content_length(0)
        .build()
        .unwrap();

    let mut request = PyRequest::new(
        Arc::new(Mutex::new(message)),
        "udp".to_string(),
        "10.0.0.1".to_string(),
        5060,
    );

    let result = auth.challenge_proxy(&mut request, Some("atlanta.com")).unwrap();
    assert!(!result);

    match request.action() {
        RequestAction::Reply { code, reason, .. } => {
            assert_eq!(*code, 407);
            assert_eq!(reason, "Proxy Authentication Required");
        }
        other => panic!("expected Reply action, got {:?}", other),
    }
}

#[test]
fn valid_credentials_return_true() {
    let auth = make_auth("atlanta.com", &[("alice", "secret123")]);
    let header = digest_header("alice", "secret123", "atlanta.com", &fresh_nonce(), "sip:atlanta.com", "REGISTER");
    let mut request = make_register(Some(&header));

    let result = auth.challenge_www(&mut request, Some("atlanta.com")).unwrap();
    assert!(result, "valid user should be authenticated");

    // Action should remain None (no reply needed)
    match request.action() {
        RequestAction::None => {}
        other => panic!("expected None action after auth success, got {:?}", other),
    }
}

#[test]
fn check_credentials_without_header_returns_false() {
    let auth = make_auth("atlanta.com", &[("alice", "secret123")]);
    let request = make_register(None);

    let result = auth.check_credentials(&request, Some("atlanta.com")).unwrap();
    assert!(!result);
}

#[test]
fn check_credentials_with_valid_user_returns_true() {
    let auth = make_auth("atlanta.com", &[("alice", "secret123")]);
    let header = digest_header("alice", "secret123", "atlanta.com", &fresh_nonce(), "sip:atlanta.com", "REGISTER");
    let request = make_register(Some(&header));

    let result = auth.check_credentials(&request, Some("atlanta.com")).unwrap();
    assert!(result, "should return true for known user");
}

#[test]
fn check_credentials_with_unknown_user_returns_false() {
    let auth = make_auth("atlanta.com", &[("alice", "secret123")]);
    let request = make_register(Some(
        "Digest username=\"eve\", realm=\"atlanta.com\", nonce=\"abc\", uri=\"sip:atlanta.com\", response=\"xyz\""
    ));

    let result = auth.check_credentials(&request, Some("atlanta.com")).unwrap();
    assert!(!result, "should return false for unknown user");
}

#[test]
fn multi_realm_users() {
    let mut realm_users = HashMap::new();
    realm_users.insert(
        "realm1.com".to_string(),
        HashMap::from([("bob".to_string(), "pass1".to_string())]),
    );
    realm_users.insert(
        "realm2.com".to_string(),
        HashMap::from([("carol".to_string(), "pass2".to_string())]),
    );
    let auth = PyAuth::new(realm_users, "realm1.com".to_string());

    // Bob is in realm1
    let header = digest_header("bob", "pass1", "realm1.com", &fresh_nonce(), "sip:realm1.com", "REGISTER");
    let request = make_register(Some(&header));
    assert!(auth.check_credentials(&request, Some("realm1.com")).unwrap());

    // Carol is in realm2 — static backend checks all realms regardless
    let header = digest_header("carol", "pass2", "realm2.com", &fresh_nonce(), "sip:realm2.com", "REGISTER");
    let request = make_register(Some(&header));
    assert!(auth.check_credentials(&request, Some("realm2.com")).unwrap());

    // Unknown user fails
    let request = make_register(Some(
        "Digest username=\"dave\", realm=\"realm1.com\", nonce=\"abc\", uri=\"sip:realm1.com\", response=\"xyz\""
    ));
    assert!(!auth.check_credentials(&request, Some("realm1.com")).unwrap());
}
