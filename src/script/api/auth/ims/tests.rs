use super::super::base64_encode;
use super::super::test_support::{
    aka_first_authorization, register, requested_authorization, requested_scheme, text, Hss,
    MockHss, Outcome, Registration, AUTN, AUTS, IMS_AKA, PRIVATE_IDENTITY, PUBLIC_IDENTITY, REALM,
    SCSCF,
};
use super::*;

/// The nonce of the challenge built from a vector whose RAND is `fill`.
fn nonce(fill: u8) -> String {
    let mut bytes = vec![fill; 16];
    bytes.extend_from_slice(&AUTN);
    base64_encode(&bytes)
}

fn authorization(nonce: &str, extra: &str) -> String {
    format!(
        "Digest username=\"{PRIVATE_IDENTITY}\", realm=\"{REALM}\", nonce=\"{nonce}\", \
         uri=\"sip:{REALM}\", algorithm=AKAv1-MD5, response=\"{}\"{extra}",
        "0".repeat(32),
    )
}

/// The first REGISTER of an IMS UE, forwarded by a P-CSCF for IMS-AKA.
async fn first_register(hss: &MockHss) -> Outcome {
    register(hss, Some(aka_first_authorization())).await
}

fn assert_aka_challenge(outcome: &Outcome, rand_fill: u8) {
    assert!(
        !outcome.result.as_ref().unwrap(),
        "challenged, not verified"
    );
    assert_eq!(outcome.reply, Some(401));
    let challenge = outcome.challenge.as_deref().expect("WWW-Authenticate");
    assert!(challenge.contains("algorithm=AKAv1-MD5"), "{challenge}");
    assert!(
        challenge.contains(&format!("nonce=\"{}\"", nonce(rand_fill))),
        "{challenge}"
    );
}

/// TS 29.229 clause 6.3.9: "Digest-AKAv1-MD5" indicates the IMS-AKA
/// scheme and "SIP Digest" a different one, which a subscriber server
/// following TS 29.228 clause 6.3.1 refuses for an IMS-AKA subscriber.
#[tokio::test]
async fn the_first_register_asks_for_an_ims_aka_vector() {
    let hss = MockHss::start(Hss::Conformant, 0x10).await;

    let outcome = first_register(&hss).await;

    let requests = hss.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requested_scheme(&requests[0]), Some(IMS_AKA));
    // Table 6.3.2: present only for a synchronisation failure.
    assert_eq!(requested_authorization(&requests[0]), None);
    assert_aka_challenge(&outcome, 0x10);
}

/// A response that does not verify consumes the vector, and the fresh one
/// is asked for under the same scheme as the first.
#[tokio::test]
async fn a_failed_response_is_challenged_again_with_an_ims_aka_vector() {
    let hss = MockHss::start(Hss::Conformant, 0x18).await;
    assert_aka_challenge(&first_register(&hss).await, 0x18);

    let outcome = register(&hss, Some(authorization(&nonce(0x18), ""))).await;

    let requests = hss.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requested_scheme(&requests[1]), Some(IMS_AKA));
    assert_eq!(requested_authorization(&requests[1]), None);
    assert_aka_challenge(&outcome, 0x18);
}

/// TS 29.228 table 6.3.2: Authorization Information carries RAND and AUTS
/// after a synchronisation failure, and "only IMS-AKA authentication
/// schemes are allowed" with it.
#[tokio::test]
async fn a_resynchronisation_asks_for_an_ims_aka_vector_with_rand_and_auts() {
    let hss = MockHss::start(Hss::Conformant, 0x20).await;
    let auts = format!(", auts=\"{}\"", base64_encode(&AUTS));

    let outcome = register(&hss, Some(authorization(&nonce(0x20), &auts))).await;

    let requests = hss.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requested_scheme(&requests[0]), Some(IMS_AKA));
    let mut rand_and_auts = vec![0x20; 16];
    rand_and_auts.extend_from_slice(&AUTS);
    assert_eq!(requested_authorization(&requests[0]), Some(rand_and_auts));
    assert_aka_challenge(&outcome, 0x21);
}

/// An answer labelled with another scheme does not hold RAND, AUTN and
/// XRES, whatever octets sit in the item, so no challenge is built from it.
#[tokio::test]
async fn an_answer_in_another_scheme_is_an_error_and_not_a_challenge() {
    for (rand_fill, auts) in [
        (0x28, None),
        (0x30, Some(format!(", auts=\"{}\"", base64_encode(&AUTS)))),
    ] {
        let hss = MockHss::start(Hss::AnswersScheme("SIP Digest"), rand_fill).await;
        let header = match auts {
            Some(auts) => authorization(&nonce(rand_fill), &auts),
            None => aka_first_authorization(),
        };

        let outcome = register(&hss, Some(header)).await;

        let error = outcome.result.expect_err("a scheme mismatch must raise");
        let text = error.to_string();
        assert!(
            text.contains("SIP Digest") && text.contains(IMS_AKA),
            "{text}"
        );
        assert_eq!(outcome.reply, None);
        assert_eq!(outcome.challenge, None);
        for fill in [rand_fill, rand_fill + 1] {
            assert!(
                take_auth_vector(&nonce(fill)).is_none(),
                "no expected response may be stored for a refused answer"
            );
        }
    }
}

/// The scheme names are compared as the tokens they are, so a server that
/// writes the IMS-AKA name in another case is not refused.
#[tokio::test]
async fn the_answered_scheme_is_compared_without_regard_to_case() {
    let hss = MockHss::start(Hss::AnswersScheme("digest-akav1-md5"), 0x38).await;
    assert_aka_challenge(&first_register(&hss).await, 0x38);
}

/// DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED is the server refusing the
/// scheme for this subscriber: the REGISTER is refused and nothing is
/// challenged.
#[tokio::test]
async fn auth_scheme_not_supported_refuses_the_register() {
    let hss = MockHss::start(Hss::RefusesScheme, 0x40).await;

    let outcome = first_register(&hss).await;

    assert_eq!(requested_scheme(&hss.requests()[0]), Some(IMS_AKA));
    outcome.assert_forbidden();
}

/// TS 29.229 clause 6.1.7 lists `{ User-Name }`, `{ Public-Identity }`
/// and `{ Server-Name }` in the MAR. TS 24.229 clause 5.4.1.2.1 step 1
/// takes the public identity from the To header and the private one from
/// the `username` of the Authorization header.
#[tokio::test]
async fn the_mar_names_the_identities_of_to_and_authorization_and_the_scscf() {
    let hss = MockHss::start(Hss::Conformant, 0x50).await;
    // A username that is not what the derivation from To would give.
    let header = format!(
        "Digest username=\"private-user@{REALM}\", realm=\"{REALM}\", nonce=\"\", \
         uri=\"sip:{REALM}\", response=\"\", integrity-protected=\"no\""
    );
    let mut registration = Registration::new(Some(header));
    registration.to = format!("\"Display\" <{PUBLIC_IDENTITY}>;tag=to");

    let outcome = registration.run(&hss).await;

    let requests = hss.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(text(&requests[0], "Public-Identity"), Some(PUBLIC_IDENTITY));
    assert_eq!(
        text(&requests[0], "User-Name"),
        Some(format!("private-user@{REALM}").as_str())
    );
    assert_eq!(text(&requests[0], "Server-Name"), Some(SCSCF));
    assert_aka_challenge(&outcome, 0x50);
}

/// TS 24.229 clause 5.4.1.1 item 3: without an Authorization header the
/// private identity is the public one of the To header less the scheme,
/// the port number and the URI parameters.
#[tokio::test]
async fn without_authorization_the_private_identity_is_derived_from_to() {
    let hss = MockHss::start(Hss::Conformant, 0x58).await;
    let mut registration = Registration::new(None);
    registration.to = format!("<sip:001010000000001@{REALM}:5060;transport=tcp>;tag=to");

    let outcome = registration.run(&hss).await;

    let requests = hss.requests();
    assert_eq!(
        text(&requests[0], "Public-Identity"),
        Some(format!("sip:001010000000001@{REALM}:5060;transport=tcp").as_str())
    );
    assert_eq!(text(&requests[0], "User-Name"), Some(PRIVATE_IDENTITY));
    assert_aka_challenge(&outcome, 0x58);
}

/// A script that passes no `server_name=` sends the MAR without
/// Server-Name, and a server that checks the command answers
/// DIAMETER_MISSING_AVP: the REGISTER is refused, nothing is challenged.
#[tokio::test]
async fn without_server_name_a_strict_server_refuses_the_mar() {
    let hss = MockHss::start(Hss::Conformant, 0x60).await;
    let mut registration = Registration::new(Some(aka_first_authorization()));
    registration.server_name = None;

    let outcome = registration.run(&hss).await;

    let requests = hss.requests();
    assert_eq!(text(&requests[0], "Server-Name"), None);
    assert_eq!(text(&requests[0], "User-Name"), Some(PRIVATE_IDENTITY));
    outcome.assert_forbidden();
}

/// DIAMETER_SUCCESS without RAND and AUTN, without XRES, or without the
/// item at all is not something to challenge with: a nonce made up here
/// would carry no AUTN, and nothing could verify the answer to it.
#[tokio::test]
async fn a_success_without_a_vector_is_an_error_and_not_a_challenge() {
    for (rand_fill, omitted) in [
        (0x68, "SIP-Authenticate"),
        (0x6a, "SIP-Authorization"),
        (0x6c, "SIP-Auth-Data-Item"),
    ] {
        let hss = MockHss::start(Hss::Omits(omitted), rand_fill).await;

        let outcome = first_register(&hss).await;

        let error = outcome.result.expect_err("no vector must raise");
        assert!(error.to_string().contains(omitted), "{error}");
        assert_eq!(outcome.reply, None, "{omitted}");
        assert_eq!(outcome.challenge, None, "{omitted}");
        assert!(
            take_auth_vector(&nonce(rand_fill)).is_none(),
            "nothing may be stored for {omitted}"
        );
    }
}
