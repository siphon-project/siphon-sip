//! A call siphon places to a trunk that challenges it (RFC 3261 §22).
//!
//! The B-leg has answered `401`/`407` itself for a long time, but an originated
//! call has no B-leg — siphon is the UAC on its own A-leg — and its response
//! path never handled a challenge at all, so an `originate` to an
//! authenticating trunk died on the first `401`.

use super::session_timer_tests::wire;
use super::test_dispatcher::{test_dispatcher, TestDispatcher};
use super::*;

const TRUNK: &str = "sip:+15551234@192.0.2.50:5060";
const REALM: &str = "carrier.example";

fn credentials() -> Arc<crate::auth::StoredCredentials> {
    Arc::new(crate::auth::StoredCredentials {
        username: "trunk1".to_string(),
        secret: crate::auth::StoredSecret::Password("secret123".to_string()),
    })
}

fn originate_params() -> OriginateParams {
    OriginateParams {
        to: TRUNK.to_string(),
        to_display: None,
        from: None,
        from_display: None,
        next_hop: None,
        p_asserted_identity: None,
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

/// Stage an originate, optionally holding credentials for the trunk — what a
/// gateway destination's `auth:` block, or a script, supplies.
fn originate_to_trunk(dispatcher: &TestDispatcher, with_credentials: bool) -> PreparedOriginate {
    let prepared =
        prepare_originate(&dispatcher.state, originate_params()).expect("the originate stages");
    if with_credentials {
        if let Some(mut call) = dispatcher
            .state
            .call_actors
            .get_call_mut(&prepared.internal_call_id)
        {
            call.outbound_credentials = Some(credentials());
        }
    }
    let _ = wire(dispatcher);
    prepared
}

fn challenge(prepared: &PreparedOriginate, status_code: u16) -> SipMessage {
    let header = if status_code == 401 {
        "WWW-Authenticate"
    } else {
        "Proxy-Authenticate"
    };
    let mut response = build_response(&prepared.invite, status_code, "Unauthorized", None, &[]);
    response.headers.set(
        header,
        format!(r#"Digest realm="{REALM}", nonce="abc123", qop="auth", algorithm=MD5"#),
    );
    response
}

fn method_of(message: &SipMessage) -> Option<String> {
    match &message.start_line {
        StartLine::Request(request_line) => Some(request_line.method.as_str().to_string()),
        StartLine::Response(_) => None,
    }
}

fn sent_methods(sent: &[(SocketAddr, SipMessage)]) -> Vec<String> {
    sent.iter().filter_map(|(_, m)| method_of(m)).collect()
}

fn find_invite(sent: &[(SocketAddr, SipMessage)]) -> Option<&SipMessage> {
    sent.iter()
        .map(|(_, message)| message)
        .find(|message| method_of(message).as_deref() == Some("INVITE"))
}

#[tokio::test(flavor = "multi_thread")]
async fn an_originate_answers_a_401_with_a_credentialed_re_invite() {
    let dispatcher = test_dispatcher();
    let prepared = originate_to_trunk(&dispatcher, true);

    handle_originated_call_response(
        &prepared.internal_call_id,
        &challenge(&prepared, 401),
        401,
        &dispatcher.state,
    );

    let sent = wire(&dispatcher);
    let methods = sent_methods(&sent);
    // RFC 3261 §17.1.1.3: the challenge is ACKed on its own branch before the
    // retry, or the trunk retransmits it until Timer H.
    assert!(
        methods.contains(&"ACK".to_string()),
        "the challenge was not ACKed: {methods:?}"
    );
    let retry = find_invite(&sent).expect("a credentialed re-INVITE went out");
    let authorization = retry
        .headers
        .get("Authorization")
        .expect("the retry carries Authorization");
    assert!(
        authorization.contains(r#"username="trunk1""#),
        "{authorization}"
    );
    assert!(
        authorization.contains(r#"nonce="abc123""#),
        "{authorization}"
    );
    assert!(
        authorization.contains(r#"realm="carrier.example""#),
        "{authorization}"
    );

    // The call must survive: a retry is not a failure.
    assert!(dispatcher
        .state
        .call_actors
        .get_call(&prepared.internal_call_id)
        .is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_407_is_answered_with_proxy_authorization() {
    // RFC 3261 §22.3: a proxy's challenge is answered on the proxy header, not
    // the endpoint one.
    let dispatcher = test_dispatcher();
    let prepared = originate_to_trunk(&dispatcher, true);

    handle_originated_call_response(
        &prepared.internal_call_id,
        &challenge(&prepared, 407),
        407,
        &dispatcher.state,
    );

    let sent = wire(&dispatcher);
    let retry = find_invite(&sent).expect("a credentialed re-INVITE went out");
    assert!(retry.headers.get("Proxy-Authorization").is_some());
    assert!(retry.headers.get("Authorization").is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_retry_is_a_new_transaction() {
    // RFC 3261 §8.1.3.5: the credentialed request is a new transaction — new
    // Via branch, next CSeq — not a retransmission of the challenged one.
    let dispatcher = test_dispatcher();
    let prepared = originate_to_trunk(&dispatcher, true);
    let original_branch = prepared
        .invite
        .headers
        .get("Via")
        .expect("the INVITE has a Via")
        .clone();
    let original_cseq = prepared
        .invite
        .headers
        .cseq()
        .expect("the INVITE has a CSeq")
        .clone();

    handle_originated_call_response(
        &prepared.internal_call_id,
        &challenge(&prepared, 401),
        401,
        &dispatcher.state,
    );

    let sent = wire(&dispatcher);
    let retry = find_invite(&sent).expect("a credentialed re-INVITE went out");
    let retry_via = retry.headers.get("Via").expect("the retry has a Via");
    let retry_cseq = retry.headers.cseq().expect("the retry has a CSeq");
    assert_ne!(retry_via, &original_branch, "the retry reused the branch");
    assert_ne!(retry_cseq, &original_cseq, "the retry reused the CSeq");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_retry_branch_is_indexed_so_its_answer_comes_back() {
    // The response path finds an originated call by its INVITE's Via branch.
    // An unindexed retry branch would make the trunk's answer a response for an
    // unknown call — the retry would be sent and then silently orphaned.
    let dispatcher = test_dispatcher();
    let prepared = originate_to_trunk(&dispatcher, true);

    handle_originated_call_response(
        &prepared.internal_call_id,
        &challenge(&prepared, 401),
        401,
        &dispatcher.state,
    );

    let sent = wire(&dispatcher);
    let retry = find_invite(&sent).expect("a credentialed re-INVITE went out");
    let branch = crate::sip::headers::via::Via::parse_multi(
        retry.headers.get("Via").expect("the retry has a Via"),
    )
    .expect("the Via parses")
    .into_iter()
    .next()
    .and_then(|via| via.branch)
    .expect("the Via carries a branch");

    assert_eq!(
        dispatcher
            .state
            .call_actors
            .lookup_originated_call(&branch)
            .as_deref(),
        Some(prepared.internal_call_id.as_str())
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_challenge_without_credentials_still_fails_the_call() {
    // Unchanged behaviour for an originate that has no credentials: the
    // challenge is its final answer.
    let dispatcher = test_dispatcher();
    let prepared = originate_to_trunk(&dispatcher, false);

    handle_originated_call_response(
        &prepared.internal_call_id,
        &challenge(&prepared, 401),
        401,
        &dispatcher.state,
    );

    let sent = wire(&dispatcher);
    assert!(
        find_invite(&sent).is_none(),
        "retried without a credential to retry with"
    );
    assert!(
        sent_methods(&sent).contains(&"ACK".to_string()),
        "the challenge was not ACKed"
    );
    assert!(
        dispatcher
            .state
            .call_actors
            .get_call(&prepared.internal_call_id)
            .is_none(),
        "the call should have been failed and released"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_trunk_that_challenges_every_attempt_stops_at_the_retry_cap() {
    // A trunk with a wrong password issues a fresh nonce every time. Each retry
    // lands on a new branch, so nothing self-terminates the loop — the cap is
    // what does.
    let dispatcher = test_dispatcher();
    let prepared = originate_to_trunk(&dispatcher, true);

    let mut retries = 0;
    for _ in 0..(MAX_B2BUA_AUTH_RETRIES + 2) {
        handle_originated_call_response(
            &prepared.internal_call_id,
            &challenge(&prepared, 401),
            401,
            &dispatcher.state,
        );
        if find_invite(&wire(&dispatcher)).is_some() {
            retries += 1;
        }
    }

    assert_eq!(retries, MAX_B2BUA_AUTH_RETRIES as usize);
    assert!(
        dispatcher
            .state
            .call_actors
            .get_call(&prepared.internal_call_id)
            .is_none(),
        "the call should have been failed once the cap was reached"
    );
}
