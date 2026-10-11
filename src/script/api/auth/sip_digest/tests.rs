use super::super::test_support::{
    aka_first_authorization, register, sip_digest_item, text, Client, Hss, MockHss, Outcome,
    Registration, DIGEST_REALM, IMS_AKA, PRIVATE_IDENTITY, PUBLIC_IDENTITY, REALM, SCSCF,
    SIP_DIGEST, UNKNOWN,
};
use super::super::vectors::expire_digest_challenge;
use super::*;
use crate::diameter::codec::{
    self, encode_avp_grouped_3gpp, encode_avp_u32, encode_avp_u32_3gpp, encode_avp_utf8,
    encode_avp_utf8_3gpp,
};
use crate::diameter::cx_test_support::{answer_scaffold, finish_answer, hex_dump};
use crate::diameter::dictionary::avp;

/// A SIP-Auth-Data-Item holding these hashes, as the subscriber server
/// would send them.
fn item(realm: &str, md5: &str, sha256: Option<&str>) -> AuthItem {
    AuthItem {
        scheme: Some("SIP Digest".to_string()),
        has_digest: true,
        digest_realm: Some(realm.to_string()),
        digest_algorithm: Some("MD5".to_string()),
        digest_qop: Some("auth".to_string()),
        digest_ha1: Some(md5.to_string()),
        alternate_digest_algorithm: sha256.map(|_| "SHA-256".to_string()),
        alternate_digest_ha1: sha256.map(str::to_string),
        ..AuthItem::default()
    }
}

fn vector(realm: &str, md5: &str, sha256: Option<&str>) -> SipDigestVector {
    SipDigestVector::from_item(&item(realm, md5, sha256)).unwrap()
}

/// RFC 2617 clause 3.5: user "Mufasa", realm "testrealm@host.com", password
/// "Circle Of Life", a GET of /dir/index.html. H(A1) is the MD5 of
/// "Mufasa:testrealm@host.com:Circle Of Life", computed outside this crate,
/// which is all a subscriber server hands out. The response is the one the
/// RFC prints.
#[test]
fn rfc_2617_example_verifies_from_its_hash_a1() {
    let vector = vector(
        "testrealm@host.com",
        "939e7578ed9e3c518a452acee763bce9",
        None,
    );
    let answer = DigestAnswer::parse(
        "Digest username=\"Mufasa\", realm=\"testrealm@host.com\", \
         nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/dir/index.html\", \
         algorithm=MD5, qop=auth, nc=00000001, cnonce=\"0a4f113b\", \
         response=\"6629fae49393a05397450978507c4ef1\", \
         opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"",
    )
    .unwrap();

    let verified = vector.check(&answer, "GET").expect("the RFC's response");

    assert_eq!(verified.nonce_count, 1);
    // rspauth: the same computation with A2 = ":/dir/index.html" (RFC 2617
    // clause 3.2.3), computed outside this crate.
    assert_eq!(
        verified.authentication_info,
        "qop=auth, rspauth=\"376602cfd2f4e8e5e78b948a85263e85\", cnonce=\"0a4f113b\", \
         nc=00000001"
    );
    // One digit off is not the response.
    let mut wrong = answer;
    wrong.response = "6629fae49393a05397450978507c4ef0".to_string();
    assert!(vector.check(&wrong, "GET").is_err());
}

/// RFC 7616 clause 3.9.1: user "Mufasa", realm "http-auth@example.org",
/// password "Circle of Life", with the responses the RFC prints for SHA-256
/// and for MD5. Each H(A1) is the hash of
/// "Mufasa:http-auth@example.org:Circle of Life", computed outside this crate.
#[test]
fn rfc_7616_examples_verify_under_sha_256_and_md5() {
    let vector = vector(
        "http-auth@example.org",
        "3d78807defe7de2157e2b0b6573a855f",
        Some("7987c64c30e25f1b74be53f966b49b90f2808aa92faf9a00262392d7b4794232"),
    );
    for (algorithm, response, response_auth) in [
        (
            "SHA-256",
            "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1",
            "86d3b25618d41854ca5039a5d7e53ff6355d5134a9b1fb088a78ac3c462195a0",
        ),
        (
            "MD5",
            "8ca523f5e9506fed4657c9700eebdbec",
            "9b712497bc9f91499fbcca1dfc5f09a5",
        ),
    ] {
        let answer = DigestAnswer::parse(&format!(
            "Digest username=\"Mufasa\", realm=\"http-auth@example.org\", \
             uri=\"/dir/index.html\", algorithm={algorithm}, \
             nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", nc=00000001, \
             cnonce=\"f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ\", qop=auth, \
             response=\"{response}\", opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\""
        ))
        .unwrap();

        let verified = vector.check(&answer, "GET").expect(algorithm);

        assert!(
            verified
                .authentication_info
                .contains(&format!("rspauth=\"{response_auth}\"")),
            "{algorithm}: {}",
            verified.authentication_info
        );
        // The method is part of A2: the same header does not answer a
        // REGISTER.
        assert!(vector.check(&answer, "REGISTER").is_err(), "{algorithm}");
    }
}

/// TS 24.229 clause 5.4.1.2.2A step 3: realm, algorithm, cnonce and nc are
/// checked before the response is, and a response without qop=auth is not
/// one this challenge asked for.
#[test]
fn an_answer_missing_what_the_challenge_asked_for_does_not_verify() {
    let vector = vector(
        "http-auth@example.org",
        "3d78807defe7de2157e2b0b6573a855f",
        None,
    );
    let complete = "Digest username=\"Mufasa\", realm=\"http-auth@example.org\", \
         uri=\"/dir/index.html\", algorithm=MD5, \
         nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", nc=00000001, \
         cnonce=\"f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ\", qop=auth, \
         response=\"8ca523f5e9506fed4657c9700eebdbec\"";
    assert!(vector
        .check(&DigestAnswer::parse(complete).unwrap(), "GET")
        .is_ok());

    for (from, to, why) in [
        (
            "realm=\"http-auth@example.org\"",
            "realm=\"other.example.org\"",
            "realm",
        ),
        (" algorithm=MD5,", "", "no algorithm"),
        // Not offered: the vector holds no SHA-256 hash.
        ("algorithm=MD5", "algorithm=SHA-256", "algorithm"),
        (" nc=00000001,", "", "no nc"),
        ("nc=00000001", "nc=00000000", "nc of zero"),
        ("nc=00000001", "nc=first", "nc that is no count"),
        (
            " cnonce=\"f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ\",",
            "",
            "no cnonce",
        ),
        (" qop=auth,", "", "no qop"),
        ("qop=auth", "qop=auth-int", "another qop"),
    ] {
        let header = complete.replace(from, to);
        assert_ne!(header, complete, "{why}");
        let answer = DigestAnswer::parse(&header).unwrap();
        assert!(vector.check(&answer, "GET").is_err(), "{why}");
    }
}

/// TS 29.228 table 6.3.7: Digest-Realm, Digest-QoP and Digest-HA1 are
/// mandatory, Digest-Algorithm is "MD5" when present, and Digest-QoP "shall
/// be set to a value of "auth"".
#[test]
fn a_digest_item_is_read_as_the_table_defines_it() {
    let md5 = "3d78807defe7de2157e2b0b6573a855f";
    let complete = || item("example.org", md5, None);

    // Digest-Algorithm is optional and MD5 is assumed, and a challenge
    // without a Digest-QoP gets "auth" (TS 24.229 clause 5.4.1.2.1B).
    let assumed = SipDigestVector::from_item(&AuthItem {
        digest_algorithm: None,
        digest_qop: None,
        ..complete()
    })
    .unwrap();
    assert_eq!(
        assumed.challenges("n", false),
        vec!["Digest realm=\"example.org\", nonce=\"n\", algorithm=MD5, qop=\"auth\""]
    );

    let text = |value: &str| Some(value.to_string());
    for (broken, missing) in [
        (
            AuthItem {
                digest_realm: None,
                ..complete()
            },
            "Digest-Realm",
        ),
        (
            AuthItem {
                digest_ha1: None,
                ..complete()
            },
            "Digest-HA1",
        ),
        (
            AuthItem {
                digest_ha1: text("abc"),
                ..complete()
            },
            "Digest-HA1",
        ),
        (
            AuthItem {
                digest_qop: text("auth-int"),
                ..complete()
            },
            "Digest-QoP",
        ),
        (
            AuthItem {
                digest_algorithm: text("SHA-256"),
                ..complete()
            },
            "Digest-Algorithm",
        ),
        (
            AuthItem {
                has_digest: false,
                ..complete()
            },
            "SIP-Digest-Authenticate",
        ),
    ] {
        let error = SipDigestVector::from_item(&broken).unwrap_err();
        assert!(error.contains(missing), "{error}");
        // What is wrong is named, the hash is not repeated.
        assert!(!error.contains(md5), "{error}");
    }
}

/// H(A1) is enough to answer every challenge in its realm, so nothing that
/// formats a vector or a pending challenge prints it.
#[test]
fn hash_a1_is_not_part_of_any_debug_output() {
    let md5 = "3d78807defe7de2157e2b0b6573a855f";
    let sha256 = "7987c64c30e25f1b74be53f966b49b90f2808aa92faf9a00262392d7b4794232";
    let challenge = SipDigestChallenge {
        vector: vector("example.org", md5, Some(sha256)),
        public_identity: PUBLIC_IDENTITY.to_string(),
        private_identity: PRIVATE_IDENTITY.to_string(),
        call_id: "debug@192.0.2.10".to_string(),
    };

    let printed = format!("{challenge:?} {challenge:#?}");

    assert!(printed.contains("SHA-256") && printed.contains("example.org"));
    assert!(
        !printed.contains(md5) && !printed.contains(sha256),
        "{printed}"
    );
}

fn assert_digest_challenge(outcome: &Outcome, algorithms: &[&str], stale: bool) {
    assert!(
        !outcome.result.as_ref().unwrap(),
        "challenged, not verified"
    );
    assert_eq!(outcome.reply, Some(401));
    assert_eq!(
        outcome.challenges.len(),
        algorithms.len(),
        "{:?}",
        outcome.challenges
    );
    for (challenge, algorithm) in outcome.challenges.iter().zip(algorithms) {
        let parameter = |name: &str| auth_header_param(challenge, name);
        assert!(challenge.starts_with("Digest "), "{challenge}");
        // The realm H(A1) was computed with, not the one the script passes.
        assert_eq!(parameter("realm").as_deref(), Some(DIGEST_REALM));
        assert_eq!(parameter("algorithm").as_deref(), Some(*algorithm));
        assert_eq!(parameter("qop").as_deref(), Some("auth"));
        assert_eq!(
            parameter("stale").as_deref(),
            stale.then_some("true"),
            "{challenge}"
        );
        // Generated here: not the RAND and AUTN of an AKA vector, and no keys.
        assert!(parameter("nonce").is_some_and(|nonce| nonce.len() >= 32));
        assert_eq!(parameter("ck"), None);
        assert_eq!(parameter("ik"), None);
    }
    // One nonce for every algorithm of the 401.
    let nonces: std::collections::HashSet<_> = outcome
        .challenges
        .iter()
        .map(|challenge| auth_header_param(challenge, "nonce"))
        .collect();
    assert_eq!(nonces.len(), 1);
}

/// The Authorization header of a SIP Digest client's first REGISTER when it
/// sends one: no challenge response, and no "integrity-protected" (TS 24.229
/// clause 5.2.2.3 step 1 a).
fn first_authorization() -> String {
    format!(
        "Digest username=\"{PRIVATE_IDENTITY}\", realm=\"{DIGEST_REALM}\", nonce=\"\", \
         uri=\"sip:{REALM}\", response=\"\""
    )
}

/// A digest subscriber, challenged. Returns the WWW-Authenticate values.
async fn challenged(hss: &MockHss) -> Vec<String> {
    let outcome = register(hss, Some(first_authorization())).await;
    assert_eq!(outcome.reply, Some(401));
    outcome.challenges
}

/// TS 33.203 clause N.2.1.1, figure N.1: a REGISTER, a 401 with the nonce and
/// the algorithms "in order of preference, starting with SHA256, followed by
/// MD5", a REGISTER with the response, a 2xx with Authentication-Info. One
/// Multimedia-Auth-Request, asking for "Unknown" as TS 24.229 clause 5.4.1.1
/// item 9 has it for an Authorization header without "integrity-protected".
#[tokio::test]
async fn a_sip_digest_subscriber_registers() {
    let hss = MockHss::start(Hss::SipDigest { alternate: true }, 0).await;

    let first = register(&hss, Some(first_authorization())).await;

    assert_digest_challenge(&first, &["SHA-256", "MD5"], false);
    assert_eq!(hss.schemes(), vec![UNKNOWN]);
    let requests = hss.requests();
    assert_eq!(text(&requests[0], "User-Name"), Some(PRIVATE_IDENTITY));
    assert_eq!(text(&requests[0], "Public-Identity"), Some(PUBLIC_IDENTITY));
    assert_eq!(text(&requests[0], "Server-Name"), Some(SCSCF));

    // The client takes the first algorithm it supports.
    let client = Client::new();
    let challenge = &first.challenges[0];
    let second = register(&hss, Some(client.authorization(challenge, 1))).await;

    assert!(second.result.unwrap(), "the response verifies");
    assert_eq!(second.reply, None);
    assert_eq!(second.auth_user.as_deref(), Some(PRIVATE_IDENTITY));
    // TS 24.229 clause 5.4.1.2.2A step 11: qop, rspauth, cnonce and nc.
    assert_eq!(
        second.authentication_info,
        Some(format!(
            "qop=auth, rspauth=\"{}\", cnonce=\"{}\", nc=00000001",
            client.response_auth(challenge, 1),
            client.client_nonce
        ))
    );
    // H(A1) came with the first answer: no second request.
    assert_eq!(hss.requests().len(), 1);
}

/// A subscriber server that sends no alternate hash gets an MD5 challenge,
/// and a client may answer the second challenge of a 401 as well as the first.
#[tokio::test]
async fn md5_is_challenged_alone_and_is_answerable_next_to_sha_256() {
    let md5_only = MockHss::start(Hss::SipDigest { alternate: false }, 0).await;
    let first = register(&md5_only, Some(first_authorization())).await;
    assert_digest_challenge(&first, &["MD5"], false);
    let client = Client::new();
    let second = register(
        &md5_only,
        Some(client.authorization(&first.challenges[0], 1)),
    )
    .await;
    assert!(second.result.unwrap());

    let both = MockHss::start(Hss::SipDigest { alternate: true }, 0).await;
    let challenges = challenged(&both).await;
    let second = register(&both, Some(client.authorization(&challenges[1], 1))).await;
    assert!(second.result.unwrap(), "MD5, the second challenge");
}

/// TS 33.203 clause N.2.2.1: an incorrect response gets "a 4xx Auth_Failure"
/// in which "no security parameters shall be included", the 403 of TS 24.229
/// clause 5.4.1.2.3B. The nonce is spent: the right password under it is
/// "an invalid nonce with a valid challenge response" and is challenged again
/// with stale=true.
#[tokio::test]
async fn a_wrong_password_is_refused_without_a_challenge() {
    let hss = MockHss::start(Hss::SipDigest { alternate: true }, 0).await;
    let challenges = challenged(&hss).await;
    let mut intruder = Client::new();
    intruder.password = "not the password".to_string();

    let outcome = register(&hss, Some(intruder.authorization(&challenges[0], 1))).await;

    outcome.assert_forbidden();
    assert_eq!(hss.requests().len(), 1, "refused from the stored hash");

    let retry = register(&hss, Some(Client::new().authorization(&challenges[0], 1))).await;
    assert_digest_challenge(&retry, &["SHA-256", "MD5"], true);
    assert_eq!(hss.schemes(), vec![UNKNOWN, SIP_DIGEST]);
}

/// TS 24.229 clause 5.4.1.2.3B and TS 33.203 clause N.2.3: "when the
/// nonce-count value sent by the UE is not the expected value" the answer is
/// a 401 with a fresh nonce and stale=true. A REGISTER replayed as captured
/// carries a count that has been used.
#[tokio::test]
async fn a_replayed_nonce_count_is_challenged_again_as_stale() {
    let hss = MockHss::start(Hss::SipDigest { alternate: true }, 0).await;
    let challenges = challenged(&hss).await;
    let client = Client::new();
    let captured = client.authorization(&challenges[0], 1);
    assert!(register(&hss, Some(captured.clone())).await.result.unwrap());

    let replay = register(&hss, Some(captured)).await;

    assert_digest_challenge(&replay, &["SHA-256", "MD5"], true);
    assert_eq!(replay.auth_user, None);
    assert_eq!(replay.authentication_info, None);
    assert_ne!(
        auth_header_param(&replay.challenges[0], "nonce"),
        auth_header_param(&challenges[0], "nonce"),
        "a fresh nonce"
    );
    // The hash is the stored one: the subscriber server is not asked again.
    assert_eq!(hss.requests().len(), 1);

    // And the fresh nonce is answerable.
    let again = register(&hss, Some(client.authorization(&replay.challenges[0], 1))).await;
    assert!(again.result.unwrap());
}

/// A re-registration under the nonce of the last authentication verifies
/// with the next nonce count: the S-CSCF stores "the nonce-count value in the
/// received REGISTER request" (TS 24.229 clause 5.4.1.2.2A step 11) to
/// expect a higher one. The Call-ID is only held to the challenged REGISTER
/// for the answer to the 401.
#[tokio::test]
async fn a_re_registration_verifies_under_the_same_nonce_with_a_higher_count() {
    let hss = MockHss::start(Hss::SipDigest { alternate: true }, 0).await;
    let challenges = challenged(&hss).await;
    let mut client = Client::new();
    assert!(
        register(&hss, Some(client.authorization(&challenges[0], 1)))
            .await
            .result
            .unwrap()
    );

    client.extra = ", integrity-protected=\"ip-assoc-yes\"".to_string();
    let mut registration = Registration::new(Some(client.authorization(&challenges[0], 2)));
    registration.call_id = "another-call@192.0.2.10".to_string();
    let outcome = registration.run(&hss).await;

    assert!(outcome.result.unwrap());
    assert!(outcome
        .authentication_info
        .is_some_and(|value| value.ends_with("nc=00000002")));
    assert_eq!(hss.requests().len(), 1);

    // A lower count than the last is a replay too.
    let lower = register(&hss, Some(client.authorization(&challenges[0], 1))).await;
    assert_digest_challenge(&lower, &["SHA-256", "MD5"], true);
}

/// TS 24.229 clause 5.4.1.2.3B: "an invalid "nonce" Authorization header
/// field parameter with a valid challenge response for that nonce" gets a 401
/// "with a fresh nonce and the "stale" header field parameter set to "true"".
/// The hash is asked for again, in the scheme of the protected REGISTER.
#[tokio::test]
async fn an_expired_nonce_is_challenged_again_as_stale() {
    let hss = MockHss::start(Hss::SipDigest { alternate: true }, 0).await;
    let challenges = challenged(&hss).await;
    let client = Client::new();
    assert!(
        register(&hss, Some(client.authorization(&challenges[0], 1)))
            .await
            .result
            .unwrap()
    );
    expire_digest_challenge(&auth_header_param(&challenges[0], "nonce").unwrap());

    let outcome = register(&hss, Some(client.authorization(&challenges[0], 2))).await;

    assert_digest_challenge(&outcome, &["SHA-256", "MD5"], true);
    assert_eq!(hss.schemes(), vec![UNKNOWN, SIP_DIGEST]);

    // A wrong response under a nonce that is not valid is not stale, it is
    // wrong.
    let mut intruder = Client::new();
    intruder.password = "not the password".to_string();
    let refused = register(&hss, Some(intruder.authorization(&challenges[0], 3))).await;
    refused.assert_forbidden();
}

/// TS 24.229 clause 5.4.1.2.2A: "check if the Call-ID of the request matches
/// with the Call-ID of the 401 (Unauthorized) response which carried the last
/// challenge. The S-CSCF shall only proceed further if the Call-IDs match".
#[tokio::test]
async fn the_answer_to_a_challenge_has_to_repeat_its_call_id() {
    let hss = MockHss::start(Hss::SipDigest { alternate: true }, 0).await;
    let challenges = challenged(&hss).await;
    let mut registration = Registration::new(Some(Client::new().authorization(&challenges[0], 1)));
    registration.call_id = "another-call@192.0.2.10".to_string();

    registration.run(&hss).await.assert_forbidden();
}

/// The response does not cover the username, the stored hash does: a
/// subscriber who answers a challenge of his own under another private
/// identity is not that identity.
#[tokio::test]
async fn a_response_under_another_username_is_refused() {
    let hss = MockHss::start(Hss::SipDigest { alternate: true }, 0).await;
    let challenges = challenged(&hss).await;
    let header = Client::new().authorization(&challenges[0], 1).replace(
        &format!("username=\"{PRIVATE_IDENTITY}\""),
        &format!("username=\"001010000000009@{REALM}\""),
    );

    register(&hss, Some(header)).await.assert_forbidden();
}

/// A nonce is issued for one public identity. Under another one the
/// subscriber server is asked first, which is where the two identities are
/// checked against each other (TS 29.228 clause 6.3.1 step 3), and the valid
/// response under the other identity's nonce is stale.
#[tokio::test]
async fn a_nonce_does_not_authenticate_another_public_identity() {
    let hss = MockHss::start(Hss::SipDigest { alternate: true }, 0).await;
    let challenges = challenged(&hss).await;
    let mut registration = Registration::new(Some(Client::new().authorization(&challenges[0], 1)));
    registration.to = format!("<sip:001010000000007@{REALM}>");

    let outcome = registration.run(&hss).await;

    assert_digest_challenge(&outcome, &["SHA-256", "MD5"], true);
    let requests = hss.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        text(&requests[1], "Public-Identity"),
        Some(format!("sip:001010000000007@{REALM}").as_str())
    );
}

/// TS 29.228 clause 6.3.1 step 4 on both sides of a mismatch. An IMS-AKA
/// REGISTER for a subscriber provisioned for SIP Digest names
/// "Digest-AKAv1-MD5", which the server does not support for him. A SIP
/// Digest REGISTER for an IMS-AKA subscriber names "SIP Digest" or "Unknown",
/// and "Unknown" resolves to NASS-Bundled or SIP Digest only. Each is
/// answered DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED (5006) and refused.
#[tokio::test]
async fn a_register_in_the_mechanism_the_subscriber_does_not_have_is_refused() {
    let sip_digest_subscriber = MockHss::start(Hss::SipDigest { alternate: true }, 0).await;
    register(&sip_digest_subscriber, Some(aka_first_authorization()))
        .await
        .assert_forbidden();
    assert_eq!(sip_digest_subscriber.schemes(), vec![IMS_AKA]);

    let aka_subscriber = MockHss::start(Hss::Conformant, 0x70).await;
    register(&aka_subscriber, Some(first_authorization()))
        .await
        .assert_forbidden();
    let protected = format!(
        "{}, integrity-protected=\"tls-pending\"",
        first_authorization()
    );
    register(&aka_subscriber, Some(protected))
        .await
        .assert_forbidden();
    assert_eq!(aka_subscriber.schemes(), vec![UNKNOWN, SIP_DIGEST]);

    let refusing = MockHss::start(Hss::RefusesScheme, 0).await;
    register(&refusing, Some(first_authorization()))
        .await
        .assert_forbidden();
}

/// TS 24.229 clause 5.4.1.1 item 5: no Authorization header and an access
/// other than 3GPP that the network vouches for asks for "SIP Digest". The
/// private identity is the one derived from To.
#[tokio::test]
async fn a_register_without_authorization_over_a_non_3gpp_access_asks_for_sip_digest() {
    let hss = MockHss::start(Hss::SipDigest { alternate: false }, 0).await;
    let mut registration = Registration::new(None);
    registration.access_network_info = Some("IEEE-802.11;network-provided");

    let outcome = registration.run(&hss).await;

    assert_digest_challenge(&outcome, &["MD5"], false);
    assert_eq!(hss.schemes(), vec![SIP_DIGEST]);
    assert_eq!(
        text(&hss.requests()[0], "User-Name"),
        Some(PRIVATE_IDENTITY)
    );

    // Without the network's word the subscriber server decides.
    assert_digest_challenge(&register(&hss, None).await, &["MD5"], false);
    assert_eq!(hss.schemes(), vec![SIP_DIGEST, UNKNOWN]);
}

/// TS 24.229 clause 5.4.1.1 item 10 with clause 5.4.1.2.2A: a protected
/// REGISTER that has to be authenticated and carries no response is
/// challenged as an initial one, in the "SIP Digest" scheme.
#[tokio::test]
async fn a_protected_register_without_a_response_is_challenged() {
    for value in ["tls-pending", "tls-yes", "ip-assoc-pending", "ip-assoc-yes"] {
        let hss = MockHss::start(Hss::SipDigest { alternate: true }, 0).await;
        let header = format!("{}, integrity-protected=\"{value}\"", first_authorization());

        let outcome = register(&hss, Some(header)).await;

        assert_digest_challenge(&outcome, &["SHA-256", "MD5"], false);
        assert_eq!(hss.schemes(), vec![SIP_DIGEST], "{value}");
    }
}

/// TS 24.229 clause 5.4.1.1 items 2A and 11 name mechanisms that are not
/// implemented. The REGISTER is refused before the subscriber server is
/// asked anything, and never challenged in another mechanism.
#[tokio::test]
async fn a_mechanism_that_is_not_implemented_is_refused_without_a_request() {
    for value in ["tls-connected", "auth-done"] {
        let hss = MockHss::start(Hss::SipDigest { alternate: true }, 0).await;
        let header = format!("{}, integrity-protected=\"{value}\"", first_authorization());

        register(&hss, Some(header)).await.assert_forbidden();

        assert!(hss.requests().is_empty(), "{value}");
    }
}

/// "Unknown" has the subscriber server name the scheme it has stored
/// (TS 24.229 clause 5.4.1.1 item 9). NASS-Bundled is one this S-CSCF does
/// not implement: refused, not challenged as something else.
#[tokio::test]
async fn an_assigned_scheme_that_is_not_implemented_is_refused() {
    let hss = MockHss::start(Hss::NassBundled, 0).await;

    register(&hss, Some(first_authorization()))
        .await
        .assert_forbidden();

    assert_eq!(hss.schemes(), vec![UNKNOWN]);
}

/// A subscriber server that resolves "Unknown" to IMS-AKA goes beyond
/// TS 29.228 clause 6.3.1 step 4, and what it sends is a complete IMS-AKA
/// item: the challenge is the IMS-AKA one. For a request that named
/// "SIP Digest" the same answer is an error.
#[tokio::test]
async fn unknown_answered_with_an_ims_aka_vector_is_challenged_with_it() {
    let hss = MockHss::start(Hss::AnswersScheme(IMS_AKA), 0x78).await;

    let outcome = register(&hss, Some(first_authorization())).await;

    assert_eq!(hss.schemes(), vec![UNKNOWN]);
    assert_eq!(outcome.reply, Some(401));
    assert_eq!(outcome.challenges.len(), 1);
    assert!(outcome.challenges[0].contains("algorithm=AKAv1-MD5"));

    let protected = format!(
        "{}, integrity-protected=\"tls-pending\"",
        first_authorization()
    );
    let mismatch = register(&hss, Some(protected)).await;
    let error = mismatch.result.expect_err("a scheme mismatch must raise");
    assert!(error.to_string().contains(SIP_DIGEST), "{error}");
    assert_eq!(mismatch.reply, None);
}

/// DIAMETER_SUCCESS in the SIP Digest scheme without H(A1), without the realm
/// it was computed with, or without SIP-Digest-Authenticate is nothing to
/// challenge with.
#[tokio::test]
async fn a_success_without_hash_a1_is_an_error_and_not_a_challenge() {
    for omitted in ["Digest-HA1", "Digest-Realm", "SIP-Digest-Authenticate"] {
        let hss = MockHss::start(Hss::SipDigestOmits(omitted), 0).await;

        let outcome = register(&hss, Some(first_authorization())).await;

        let error = outcome.result.expect_err("no hash must raise");
        assert!(error.to_string().contains(omitted), "{error}");
        assert_eq!(outcome.reply, None, "{omitted}");
        assert!(outcome.challenges.is_empty(), "{omitted}");
    }
}

/// Emit a Multimedia-Auth-Answer carrying SIP-Digest-Authenticate, as the
/// subscriber server of these tests builds it, as hex for
/// `scripts/validate_diameter_cx_requests.sh` to feed to tshark.
#[tokio::test]
async fn emit_sip_digest_maa_for_external_dissection() {
    let Ok(directory) = std::env::var("SIPHON_CX_REQUESTS_HEX_DIR") else {
        // Nothing to do in an ordinary test run.
        return;
    };
    let hss = MockHss::start(Hss::SipDigest { alternate: true }, 0).await;
    register(&hss, Some(first_authorization())).await;

    let request = hss.server.first_request();
    let mut avps = answer_scaffold(&request);
    avps.extend_from_slice(&encode_avp_u32(avp::RESULT_CODE, 2001));
    avps.extend_from_slice(&encode_avp_utf8(avp::USER_NAME, PRIVATE_IDENTITY));
    avps.extend_from_slice(&encode_avp_utf8_3gpp(avp::PUBLIC_IDENTITY, PUBLIC_IDENTITY));
    avps.extend_from_slice(&encode_avp_u32_3gpp(avp::SIP_NUMBER_AUTH_ITEMS, 1));
    avps.extend_from_slice(&encode_avp_grouped_3gpp(
        avp::SIP_AUTH_DATA_ITEM,
        &sip_digest_item(true, None),
    ));
    let answer = finish_answer(&request, &avps);
    assert!(codec::decode_diameter(&answer).is_some());
    std::fs::write(
        format!("{directory}/maa_sip_digest_mock.hex"),
        hex_dump(&answer),
    )
    .expect("hex dump must be writable");
}
