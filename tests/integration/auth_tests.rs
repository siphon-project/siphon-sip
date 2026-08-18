//! Integration tests for the auth module.
//!
//! Tests the full digest authentication challenge/response cycle using
//! the Rust-backed PyAuth struct directly (without Python).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use siphon::script::api::auth::PyAuth;
use siphon::script::api::call::{CallAction, PyCall};
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

// ---------------------------------------------------------------------------
// B2BUA A-leg challenge — the digest cycle against a `Call` instead of a
// `Request`.
//
// A script with any `@b2bua.*` handler never sees the INVITE through
// `@proxy.on_request` (the dispatcher routes it straight to the B2BUA path),
// so authenticating the caller has to work off the `Call` object.
// ---------------------------------------------------------------------------

/// Build an A-leg INVITE `Call`, optionally carrying a `Proxy-Authorization`.
fn make_invite_call(proxy_auth: Option<&str>) -> PyCall {
    let mut builder = SipMessageBuilder::new()
        .request(
            Method::Invite,
            SipUri::new("atlanta.com".to_string()).with_user("bob".to_string()),
        )
        .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-b2bua-auth".to_string())
        .to("Bob <sip:bob@atlanta.com>".to_string())
        .from("Alice <sip:alice@atlanta.com>;tag=a-leg-tag".to_string())
        .call_id("b2bua-auth-call@10.0.0.1".to_string())
        .cseq("1 INVITE".to_string())
        .max_forwards(70)
        .content_length(0);

    if let Some(header) = proxy_auth {
        builder = builder.header("Proxy-Authorization", header.to_string());
    }

    PyCall::new(
        "b2bua-auth-integration".to_string(),
        Arc::new(Mutex::new(builder.build().unwrap())),
        "10.0.0.1".to_string(),
        "udp".to_string(),
    )
}

/// All values of `name` on the call's A-leg INVITE.
fn call_headers(call: &PyCall, name: &str) -> Vec<String> {
    let message = call.message();
    let guard = message.lock().unwrap();
    guard.headers.get_all(name).cloned().unwrap_or_default()
}

/// Pull the `nonce="…"` out of a challenge header value.
fn nonce_of(challenge: &str) -> String {
    challenge
        .split_once("nonce=\"")
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(nonce, _)| nonce.to_string())
        .expect("challenge carries a nonce")
}

#[test]
fn b2bua_invite_challenge_arms_a_407_reject_on_the_call() {
    let auth = make_auth("atlanta.com", &[("alice", "secret123")]);
    let mut call = make_invite_call(None);

    let authenticated = auth
        .challenge_proxy_call(&mut call, Some("atlanta.com"))
        .unwrap();
    assert!(!authenticated, "no credentials — must not authenticate");

    // The deferred reject the dispatcher turns into the 407 on the wire. The
    // B-leg is never dialled, and the call actor is dropped with it.
    assert_eq!(
        *call.action(),
        CallAction::Reject {
            code: 407,
            reason: "Proxy Authentication Required".to_string(),
        }
    );

    // The challenge is parked on the A-leg INVITE, which is where the
    // dispatcher's response builder reads it from when it answers the caller.
    let challenges = call_headers(&call, "Proxy-Authenticate");
    assert_eq!(challenges.len(), 3, "one per algorithm: {challenges:?}");
    for challenge in &challenges {
        assert!(challenge.starts_with("Digest "), "{challenge}");
        assert!(challenge.contains("realm=\"atlanta.com\""), "{challenge}");
        assert!(challenge.contains("qop=\"auth\""), "{challenge}");
    }
}

#[test]
fn b2bua_invite_challenge_then_authenticated_reinvite() {
    // The full device-driven cycle a caller drives against a B2BUA:
    //   INVITE (no creds) -> 407 + nonce -> INVITE (creds) -> authenticated.
    let auth = make_auth("atlanta.com", &[("alice", "secret123")]);

    // 1. Challenge.
    let mut first = make_invite_call(None);
    assert!(!auth
        .challenge_proxy_call(&mut first, Some("atlanta.com"))
        .unwrap());
    let nonce = nonce_of(&call_headers(&first, "Proxy-Authenticate")[0]);

    // 2. The caller answers with credentials hashed over INVITE (not REGISTER)
    //    and the nonce we just minted.
    let credentials = digest_header(
        "alice",
        "secret123",
        "atlanta.com",
        &nonce,
        "sip:bob@atlanta.com",
        "INVITE",
    );
    let mut second = make_invite_call(Some(&credentials));

    let authenticated = auth
        .challenge_proxy_call(&mut second, Some("atlanta.com"))
        .unwrap();
    assert!(authenticated, "valid credentials must authenticate");
    assert_eq!(second.get_auth_user(), Some("alice"));

    // No action armed — the handler goes on to dial the B-leg normally.
    assert_eq!(*second.action(), CallAction::None);
    assert!(call_headers(&second, "Proxy-Authenticate").is_empty());

    // Proxy-Authorization is hop-by-hop (RFC 3261 §22.3). The B-leg INVITE is
    // built from this same message, so it must be gone by the time the handler
    // returns — otherwise the next hop challenges credentials minted for us.
    assert!(
        call_headers(&second, "Proxy-Authorization").is_empty(),
        "hop-by-hop credentials leaked toward the B-leg"
    );
}

#[test]
fn b2bua_invite_challenge_rejects_wrong_password() {
    let auth = make_auth("atlanta.com", &[("alice", "secret123")]);

    let mut first = make_invite_call(None);
    assert!(!auth
        .challenge_proxy_call(&mut first, Some("atlanta.com"))
        .unwrap());
    let nonce = nonce_of(&call_headers(&first, "Proxy-Authenticate")[0]);

    let credentials = digest_header(
        "alice",
        "wrong-password",
        "atlanta.com",
        &nonce,
        "sip:bob@atlanta.com",
        "INVITE",
    );
    let mut second = make_invite_call(Some(&credentials));

    assert!(!auth
        .challenge_proxy_call(&mut second, Some("atlanta.com"))
        .unwrap());
    assert_eq!(second.get_auth_user(), None);
    // Re-challenged rather than let through.
    assert_eq!(
        *second.action(),
        CallAction::Reject {
            code: 407,
            reason: "Proxy Authentication Required".to_string(),
        }
    );
}

#[test]
fn b2bua_invite_challenge_rejects_credentials_hashed_over_another_method() {
    // A captured REGISTER credential replayed onto an INVITE must not pass:
    // HA2 is hashed over the message's own method.
    let auth = make_auth("atlanta.com", &[("alice", "secret123")]);

    let mut first = make_invite_call(None);
    assert!(!auth
        .challenge_proxy_call(&mut first, Some("atlanta.com"))
        .unwrap());
    let nonce = nonce_of(&call_headers(&first, "Proxy-Authenticate")[0]);

    let register_credentials = digest_header(
        "alice",
        "secret123",
        "atlanta.com",
        &nonce,
        "sip:bob@atlanta.com",
        "REGISTER",
    );
    let mut second = make_invite_call(Some(&register_credentials));

    assert!(!auth
        .challenge_proxy_call(&mut second, Some("atlanta.com"))
        .unwrap());
    assert_eq!(second.get_auth_user(), None);
}

#[test]
fn b2bua_invite_www_challenge_arms_a_401_reject() {
    // A B2BUA is a UAS, so 401/WWW-Authenticate is available too (RFC 3261
    // §22.2) for deployments that authenticate as an endpoint rather than a
    // proxy.
    let auth = make_auth("atlanta.com", &[("alice", "secret123")]);
    let mut call = make_invite_call(None);

    assert!(!auth
        .challenge_www_call(&mut call, Some("atlanta.com"))
        .unwrap());
    assert_eq!(
        *call.action(),
        CallAction::Reject {
            code: 401,
            reason: "Unauthorized".to_string(),
        }
    );
    assert_eq!(call_headers(&call, "WWW-Authenticate").len(), 3);
    assert!(call_headers(&call, "Proxy-Authenticate").is_empty());
}
