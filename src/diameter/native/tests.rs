use super::*;
use crate::diameter::codec::{Avp, DiameterMsg, FLAG_PROXIABLE, FLAG_REQUEST};
use crate::diameter::dictionary::{self, avp};

fn script_handler() -> NativeHandlers {
    NativeHandlers::new()
        .handle(dictionary::S6A_APP_ID, 318, |_request| async {
            Ok(NativeOutcome::Script)
        })
        .expect("a first handler")
}

pub(crate) fn request(application_id: u32, command_code: u32) -> DiameterMsg {
    DiameterMsg {
        flags: FLAG_REQUEST | FLAG_PROXIABLE,
        command_code,
        application_id,
        hop_by_hop: 0x1111_2222,
        end_to_end: 0x3333_4444,
        avps: vec![
            Avp::utf8(avp::SESSION_ID, 0, "mme.epc.example.com;7;9"),
            Avp::grouped(
                avp::VENDOR_SPECIFIC_APPLICATION_ID,
                0,
                vec![
                    Avp::u32(avp::VENDOR_ID, 0, dictionary::VENDOR_3GPP),
                    Avp::u32(avp::AUTH_APPLICATION_ID, 0, application_id),
                ],
            ),
            Avp::u32(avp::AUTH_SESSION_STATE, 0, 1),
            Avp::utf8(avp::ORIGIN_HOST, 0, "mme.epc.example.com"),
            Avp::utf8(avp::ORIGIN_REALM, 0, "epc.example.com"),
            Avp::utf8(avp::DESTINATION_REALM, 0, "example.com"),
            Avp::utf8(avp::USER_NAME, 0, "001010000000001"),
        ],
    }
}

#[test]
fn a_registered_command_is_found_and_no_other() {
    let handlers = script_handler();
    assert_eq!(handlers.len(), 1);
    assert!(!handlers.is_empty());
    assert!(handlers.get(dictionary::S6A_APP_ID, 318).is_some());
    // The same command in another application, another command in this one.
    assert!(handlers.get(dictionary::CX_APP_ID, 318).is_none());
    assert!(handlers.get(dictionary::S6A_APP_ID, 316).is_none());
    assert_eq!(
        handlers.commands().collect::<Vec<_>>(),
        vec![(dictionary::S6A_APP_ID, 318)]
    );
}

#[test]
fn an_empty_set_has_no_handler() {
    let handlers = NativeHandlers::new();
    assert!(handlers.is_empty());
    assert!(handlers.get(0, 0).is_none());
}

#[test]
fn a_second_handler_for_a_command_is_refused() {
    let duplicate = script_handler().handle(dictionary::S6A_APP_ID, 318, |_request| async {
        Ok(NativeOutcome::Script)
    });
    let error = duplicate.expect_err("a duplicate is an error");
    assert_eq!(
        error,
        NativeHandlerError::Duplicate {
            application_id: dictionary::S6A_APP_ID,
            command_code: 318,
        }
    );
    assert!(error.to_string().contains("16777251"));
    assert!(error.to_string().contains("318"));
}

#[test]
fn merging_keeps_both_sets_and_refuses_a_shared_command() {
    let other = NativeHandlers::new()
        .handle(dictionary::CX_APP_ID, 303, |_request| async {
            Ok(NativeOutcome::Script)
        })
        .expect("a first handler");
    let merged = script_handler().merge(other).expect("distinct commands");
    assert_eq!(merged.len(), 2);
    assert!(merged.merge(script_handler()).is_err());
}

#[test]
fn the_debug_form_lists_the_commands() {
    let text = format!("{:?}", script_handler());
    assert!(text.contains("16777251"), "{text}");
}

fn harness_request() -> NativeRequest {
    let (write_tx, _written) = tokio::sync::mpsc::channel(1);
    let config = crate::diameter::peer::PeerConfig {
        host: "client.example.com".to_owned(),
        port: 3868,
        origin_host: "hss.example.com".to_owned(),
        origin_realm: "example.com".to_owned(),
        destination_host: None,
        destination_realm: "example.com".to_owned(),
        local_ip: std::net::Ipv4Addr::UNSPECIFIED,
        application_ids: Vec::new(),
        watchdog_interval: 30,
        reconnect_delay: 5,
        source_address: None,
        lifecycle: Default::default(),
        product_name: "SIPhon".to_owned(),
        firmware_revision: 0,
    };
    let peer = Arc::new(crate::diameter::peer::DiameterPeer::new_for_test(
        config, write_tx,
    ));
    NativeRequest::new(
        request(dictionary::S6A_APP_ID, 318),
        peer,
        "mme",
        "default",
        ("hss.example.com", "example.com"),
    )
}

#[test]
fn an_answer_takes_its_envelope_from_the_request() {
    let request = harness_request();
    let answer = request.answer(dictionary::DIAMETER_SUCCESS);
    let message = answer.message();
    assert!(!message.is_request());
    assert!(message.is_proxiable(), "the P bit is the request's");
    assert!(!message.is_error());
    assert_eq!(message.command_code, 318);
    assert_eq!(message.application_id, dictionary::S6A_APP_ID);
    assert_eq!(message.hop_by_hop, 0x1111_2222);
    assert_eq!(message.end_to_end, 0x3333_4444);
    let codes: Vec<u32> = message.avps.iter().map(|avp| avp.code).collect();
    assert_eq!(
        codes,
        [
            avp::SESSION_ID,
            avp::VENDOR_SPECIFIC_APPLICATION_ID,
            avp::RESULT_CODE,
            avp::AUTH_SESSION_STATE,
            avp::ORIGIN_HOST,
            avp::ORIGIN_REALM,
        ]
    );
    assert_eq!(
        message.get_str(avp::SESSION_ID).as_deref(),
        Some("mme.epc.example.com;7;9")
    );
    assert_eq!(
        message.get_str(avp::ORIGIN_HOST).as_deref(),
        Some("hss.example.com")
    );
    assert_eq!(
        message.get_str(avp::ORIGIN_REALM).as_deref(),
        Some("example.com")
    );
    assert_eq!(answer.result_code(), Some(2001));
    assert_eq!(answer.experimental_result_code(), None);
}

#[test]
fn an_answer_keeps_the_received_identifiers_after_the_header_is_rewritten() {
    let mut request = harness_request();
    request.message_mut().hop_by_hop = 1;
    request.message_mut().end_to_end = 2;
    let answer = request.answer(2001);
    assert_eq!(answer.message().hop_by_hop, 0x1111_2222);
    assert_eq!(answer.message().end_to_end, 0x3333_4444);
}

#[test]
fn a_protocol_error_sets_the_e_bit_and_copies_no_application_avp() {
    let answer = harness_request().answer_with_message(3004, "busy");
    assert!(answer.is_error());
    assert!(answer.avp(avp::AUTH_SESSION_STATE, 0).is_none());
    assert!(answer.avp(avp::VENDOR_SPECIFIC_APPLICATION_ID, 0).is_none());
    assert_eq!(
        answer.message().get_str(avp::ERROR_MESSAGE).as_deref(),
        Some("busy")
    );
    // A permanent failure a handler answers is an answer of the command.
    assert!(!harness_request().answer(5012).is_error());
}

#[test]
fn an_experimental_result_takes_the_place_of_the_result_code() {
    let answer = harness_request().answer_experimental(
        dictionary::VENDOR_3GPP,
        dictionary::DIAMETER_ERROR_USER_UNKNOWN,
    );
    assert_eq!(answer.result_code(), None);
    assert_eq!(answer.experimental_result_code(), Some(5001));
    assert!(!answer.is_error());
    let codes: Vec<u32> = answer.message().avps.iter().map(|avp| avp.code).collect();
    assert_eq!(
        codes,
        [
            avp::SESSION_ID,
            avp::VENDOR_SPECIFIC_APPLICATION_ID,
            avp::EXPERIMENTAL_RESULT,
            avp::AUTH_SESSION_STATE,
            avp::ORIGIN_HOST,
            avp::ORIGIN_REALM,
        ]
    );
    let group = answer.avp(avp::EXPERIMENTAL_RESULT, 0).expect("the group");
    let members = group.members().expect("grouped");
    assert_eq!(members[0].code, avp::VENDOR_ID);
    assert_eq!(members[0].as_u32(), Some(dictionary::VENDOR_3GPP));
    assert_eq!(members[1].code, avp::EXPERIMENTAL_RESULT_CODE);
    assert_eq!(members[1].as_u32(), Some(5001));
    // RFC 6733 section 7.6: Experimental-Result { Vendor-Id (266) = 10415,
    // Experimental-Result-Code (298) = 5001 }, every one with the M bit.
    let expected: [u8; 32] = [
        0x00, 0x00, 0x01, 0x29, 0x40, 0x00, 0x00, 0x20, // 297, M, length 32
        0x00, 0x00, 0x01, 0x0a, 0x40, 0x00, 0x00, 0x0c, // 266, M, length 12
        0x00, 0x00, 0x28, 0xaf, // 10415
        0x00, 0x00, 0x01, 0x2a, 0x40, 0x00, 0x00, 0x0c, // 298, M, length 12
        0x00, 0x00, 0x13, 0x89, // 5001
    ];
    let wire = answer.to_wire();
    assert!(
        wire.windows(expected.len())
            .any(|window| window == expected),
        "{wire:02x?}"
    );
}

#[test]
fn set_replaces_insert_appends_and_remove_counts() {
    let mut answer = harness_request().answer(2001);
    answer.set_avp(Avp::u32(avp::AUTH_SESSION_STATE, 0, 0));
    assert_eq!(
        answer
            .message()
            .find_all(avp::AUTH_SESSION_STATE, 0)
            .count(),
        1,
        "setting an AVP copied from the request replaces the copy"
    );
    assert_eq!(
        answer.avp(avp::AUTH_SESSION_STATE, 0).and_then(Avp::as_u32),
        Some(0)
    );

    // A vendor-specific AVP that an answer carries more than once.
    let item = |number: u32| {
        Avp::grouped(
            avp::SIP_AUTH_DATA_ITEM,
            dictionary::VENDOR_3GPP,
            vec![Avp::u32(613, dictionary::VENDOR_3GPP, number)],
        )
    };
    answer.insert_avp(item(1)).insert_avp(item(2));
    assert_eq!(
        answer
            .message()
            .find_all(avp::SIP_AUTH_DATA_ITEM, dictionary::VENDOR_3GPP)
            .count(),
        2
    );
    let first = answer
        .avp(avp::SIP_AUTH_DATA_ITEM, dictionary::VENDOR_3GPP)
        .expect("inserted");
    assert_ne!(
        first.flags & crate::diameter::codec::AVP_FLAG_VENDOR,
        0,
        "a vendor-specific AVP carries the V bit"
    );
    answer.set_avp(item(3));
    assert_eq!(
        answer
            .message()
            .find_all(avp::SIP_AUTH_DATA_ITEM, dictionary::VENDOR_3GPP)
            .count(),
        1
    );
    assert_eq!(
        answer.remove_avp(avp::SIP_AUTH_DATA_ITEM, dictionary::VENDOR_3GPP),
        1
    );
}

#[test]
fn the_first_insert_of_a_copied_avp_replaces_the_copy() {
    let mut answer = harness_request().answer(2001);
    answer.insert_avp(Avp::u32(avp::AUTH_SESSION_STATE, 0, 0));
    assert_eq!(
        answer
            .message()
            .find_all(avp::AUTH_SESSION_STATE, 0)
            .count(),
        1
    );
    answer.insert_avp(Avp::u32(avp::AUTH_SESSION_STATE, 0, 1));
    assert_eq!(
        answer
            .message()
            .find_all(avp::AUTH_SESSION_STATE, 0)
            .count(),
        2
    );
}

#[test]
fn supported_features_in_an_answer_carries_no_m_bit() {
    let answer = harness_request().answer(2001).with_avp(Avp::grouped(
        avp::SUPPORTED_FEATURES,
        dictionary::VENDOR_3GPP,
        Vec::new(),
    ));
    let features = answer
        .avp(avp::SUPPORTED_FEATURES, dictionary::VENDOR_3GPP)
        .expect("set");
    assert_eq!(
        features.flags & crate::diameter::codec::AVP_FLAG_MANDATORY,
        0
    );
}

#[test]
fn the_m_bit_of_an_avp_can_be_set_and_cleared() {
    let cleared = Avp::u32(4242, 10415, 1).mandatory(false);
    assert_eq!(
        cleared.flags & crate::diameter::codec::AVP_FLAG_MANDATORY,
        0
    );
    let set = cleared.mandatory(true);
    assert_ne!(set.flags & crate::diameter::codec::AVP_FLAG_MANDATORY, 0);
    assert_eq!(
        Avp::u64(4243, 0, 0x0102_0304_0506_0708).raw_bytes(),
        Some(&[1u8, 2, 3, 4, 5, 6, 7, 8][..])
    );
}

#[test]
fn the_applications_of_the_handlers_are_advertised_once_each() {
    let handlers = script_handler()
        .handle(dictionary::S6A_APP_ID, 316, |_request| async {
            Ok(NativeOutcome::Script)
        })
        .and_then(|handlers| {
            handlers.handle(dictionary::CX_APP_ID, 303, |_request| async {
                Ok(NativeOutcome::Script)
            })
        })
        // An application the dictionary does not know has no vendor.
        .and_then(|handlers| {
            handlers.handle(TEST_APPLICATION, 1, |_request| async {
                Ok(NativeOutcome::Script)
            })
        })
        .expect("distinct commands");
    assert_eq!(
        applications_of(&handlers),
        vec![
            (dictionary::VENDOR_3GPP, dictionary::CX_APP_ID),
            (dictionary::VENDOR_3GPP, dictionary::S6A_APP_ID),
        ]
    );
}

// ── The handlers the dispatch tests of this process share ───────────────────

/// An application no dictionary knows and no other test sends.
pub(crate) const TEST_APPLICATION: u32 = 0x00FF_F0A1;
/// Served by [`steered`], which does what the first field of the Session-Id
/// says.
pub(crate) const TEST_COMMAND: u32 = 8_399_001;
/// Served by [`steered`] too: a command with a name, for the metric labels.
pub(crate) const TEST_NAMED_COMMAND: u32 = dictionary::CMD_PURGE_UE;

/// How often [`steered`] was called, by Session-Id.
static CALLS: std::sync::LazyLock<dashmap::DashMap<String, usize>> =
    std::sync::LazyLock::new(dashmap::DashMap::new);

pub(crate) fn calls(session_id: &str) -> usize {
    CALLS.get(session_id).map_or(0, |count| *count)
}

async fn steered(request: NativeRequest) -> NativeResult {
    let session_id = request.session_id().unwrap_or_default();
    *CALLS.entry(session_id.clone()).or_insert(0) += 1;
    match session_id.split(';').next().unwrap_or_default() {
        "answer" => Ok(NativeOutcome::Answer(request.answer(2001))),
        "experimental" => Ok(NativeOutcome::Answer(
            request.answer_experimental(dictionary::VENDOR_3GPP, 5001),
        )),
        "script" => Ok(NativeOutcome::Script),
        "error" => Err("the subscriber store is unreachable".into()),
        "panic" => panic!("a handler bug"),
        "panic-late" => {
            tokio::task::yield_now().await;
            panic!("a handler bug after an await")
        }
        "relay" => {
            let host = request
                .message()
                .get_str(avp::DESTINATION_HOST)
                .unwrap_or_default();
            let Some(peer) = request.peer_for_host(&host) else {
                return Ok(NativeOutcome::Answer(request.answer(3002)));
            };
            // One subscriber's request is a retransmission of the handler's.
            let again =
                request.message().get_str(avp::USER_NAME).as_deref() == Some("001010000000003");
            let options = RelayOptions::default()
                .timeout(std::time::Duration::from_secs(1))
                .retransmitted(again);
            Ok(NativeOutcome::Answer(
                request.relay(RelayTarget::peer(peer), options).await,
            ))
        }
        other => Err(format!("no such test behaviour: {other}").into()),
    }
}

fn test_handlers() -> NativeHandlers {
    NativeHandlers::new()
        .handle(TEST_APPLICATION, TEST_COMMAND, steered)
        .and_then(|handlers| handlers.handle(TEST_APPLICATION, TEST_NAMED_COMMAND, steered))
        .expect("distinct commands")
}

/// Put the test handlers in force for this test process: what the dispatch
/// tests, which go through the installed set, are served by.
pub(crate) fn install_test_handlers() {
    INSTALLED.get_or_init(test_handlers);
}

#[test]
fn a_second_install_is_refused() {
    install_test_handlers();
    assert_eq!(
        install(NativeHandlers::new()),
        Err(NativeHandlerError::AlreadyInstalled)
    );
    assert!(
        installed().is_some_and(|handlers| handlers.get(TEST_APPLICATION, TEST_COMMAND).is_some())
    );
}

// ── The harness ─────────────────────────────────────────────────────────────

fn steered_request(session_id: &str) -> DiameterMsg {
    let mut message = request(TEST_APPLICATION, TEST_COMMAND);
    message.avps[0] = Avp::utf8(avp::SESSION_ID, 0, session_id);
    message
}

fn result_code(outcome: &HarnessOutcome) -> Option<u32> {
    outcome
        .answer()
        .and_then(|answer| answer.answer_result_codes().0)
}

#[tokio::test]
async fn the_harness_gives_the_answer_bytes_of_a_handler() {
    let harness = NativeHarness::new(test_handlers()).with_origin("hss.example.com", "example.com");
    let outcome = harness.call(&steered_request("answer;harness;1")).await;
    let HarnessOutcome::Answer(wire) = &outcome else {
        panic!("an answer, not {outcome:?}");
    };
    let answer = DiameterMsg::from_wire(wire).expect("the answer parses");
    assert_eq!(answer.answer_result_codes().0, Some(2001));
    assert_eq!(
        answer.get_str(avp::ORIGIN_HOST).as_deref(),
        Some("hss.example.com")
    );
    assert_eq!(answer.hop_by_hop, 0x1111_2222);
    // The same through the wire form of the request.
    let again = harness
        .call_wire(&steered_request("answer;harness;1").to_wire())
        .await;
    assert_eq!(again, outcome);
}

#[tokio::test]
async fn the_harness_tells_fall_through_from_no_handler() {
    let harness = NativeHarness::new(test_handlers());
    assert_eq!(
        harness.call(&steered_request("script;harness;2")).await,
        HarnessOutcome::Script
    );
    assert_eq!(
        harness.call(&request(dictionary::S6A_APP_ID, 318)).await,
        HarnessOutcome::Unregistered
    );
    assert_eq!(harness.call_wire(&[1, 2, 3]).await, HarnessOutcome::Script);
    assert!(HarnessOutcome::Script.answer().is_none());
}

#[tokio::test]
async fn a_handler_that_fails_or_panics_is_answered_unable_to_comply() {
    let harness = NativeHarness::new(test_handlers());
    for kind in ["error", "panic", "panic-late", "nonsense"] {
        let outcome = harness
            .call(&steered_request(&format!("{kind};harness;3")))
            .await;
        let answer = outcome.answer().expect("every request is answered");
        assert_eq!(answer.answer_result_codes().0, Some(5012), "{kind}");
        assert!(answer.is_error(), "{kind}: the generic answer-message");
        assert!(!answer.is_request());
        assert_eq!(answer.hop_by_hop, 0x1111_2222, "{kind}");
        assert_eq!(answer.end_to_end, 0x3333_4444, "{kind}");
        assert_eq!(
            answer.get_str(avp::SESSION_ID).as_deref(),
            Some(format!("{kind};harness;3").as_str())
        );
        assert!(answer.get_str(avp::ERROR_MESSAGE).is_some(), "{kind}");
    }
}

/// A handler that panics before it returns its future.
#[tokio::test]
async fn a_handler_that_panics_when_called_is_answered_too() {
    let eager: NativeHandler = Arc::new(|_request| panic!("before the future"));
    let mut handlers = NativeHandlers::new();
    handlers
        .insert((TEST_APPLICATION, TEST_COMMAND), eager)
        .expect("a first handler");
    let outcome = NativeHarness::new(handlers)
        .call(&steered_request("eager;harness;4"))
        .await;
    assert_eq!(result_code(&outcome), Some(5012));
}

fn relaying(target: RelayTarget, options: RelayOptions) -> NativeHandlers {
    NativeHandlers::new()
        .handle(TEST_APPLICATION, TEST_COMMAND, move |request| {
            let target = target.clone();
            let options = options.clone();
            async move { Ok(NativeOutcome::Answer(request.relay(target, options).await)) }
        })
        .expect("a first handler")
}

fn silent_peer(
    origin_host: &str,
) -> (
    Arc<crate::diameter::peer::DiameterPeer>,
    tokio::sync::mpsc::Receiver<Vec<u8>>,
) {
    let (write_tx, written) = tokio::sync::mpsc::channel(8);
    let config = crate::diameter::peer::PeerConfig {
        host: "192.0.2.20".to_owned(),
        port: 3868,
        origin_host: origin_host.to_owned(),
        origin_realm: "example.com".to_owned(),
        destination_host: None,
        destination_realm: "example.com".to_owned(),
        local_ip: std::net::Ipv4Addr::UNSPECIFIED,
        application_ids: Vec::new(),
        watchdog_interval: 30,
        reconnect_delay: 5,
        source_address: None,
        lifecycle: Default::default(),
        product_name: "SIPhon".to_owned(),
        firmware_revision: 0,
    };
    (
        Arc::new(crate::diameter::peer::DiameterPeer::new_for_test(
            config, write_tx,
        )),
        written,
    )
}

#[tokio::test]
async fn a_relay_records_the_previous_hop_and_answers_a_silent_backend_too_busy() {
    let (backend, mut written) = silent_peer("siphon.example.com");
    let options = RelayOptions::default()
        .timeout(std::time::Duration::from_millis(100))
        .identity("hidden.example.com", "example.com")
        .retransmitted(true);
    let harness = NativeHarness::new(relaying(RelayTarget::peer(backend), options))
        .with_peer_identity("mme-1.example.com", "example.com");
    let outcome = harness.call(&steered_request("relay;harness;5")).await;

    let relayed = DiameterMsg::from_wire(&written.recv().await.expect("the request was sent"))
        .expect("the relayed request parses");
    let records: Vec<String> = relayed
        .find_all(avp::ROUTE_RECORD, 0)
        .filter_map(Avp::as_str)
        .collect();
    assert_eq!(records, ["mme-1.example.com"], "RFC 6733 section 6.1.9");
    assert_ne!(relayed.hop_by_hop, 0x1111_2222, "a Hop-by-Hop of this node");
    assert_eq!(relayed.end_to_end, 0x3333_4444, "End-to-End preserved");
    assert_ne!(
        relayed.flags & crate::diameter::codec::FLAG_RETRANSMITTED,
        0
    );
    assert_eq!(
        relayed.get_str(avp::ORIGIN_HOST).as_deref(),
        Some("hidden.example.com")
    );

    // Nothing answered within the timeout.
    let answer = outcome.answer().expect("the relay answers in its place");
    assert_eq!(answer.answer_result_codes().0, Some(3004));
    assert!(answer.is_error());
    assert_eq!(answer.hop_by_hop, 0x1111_2222, "the received Hop-by-Hop");
    assert_eq!(answer.end_to_end, 0x3333_4444);
}

#[tokio::test]
async fn a_relay_that_would_loop_is_answered_loop_detected_and_not_sent() {
    let (backend, mut written) = silent_peer("siphon.example.com");
    let harness = NativeHarness::new(relaying(
        RelayTarget::peer(backend),
        RelayOptions::default(),
    ));
    let mut looping = steered_request("relay;harness;6");
    // A neighbour recorded this node: the request came back.
    looping
        .avps
        .push(Avp::utf8(avp::ROUTE_RECORD, 0, "siphon.example.com"));
    let outcome = harness.call(&looping).await;
    assert_eq!(result_code(&outcome), Some(3005));
    assert!(written.try_recv().is_err(), "nothing was sent");
}

/// The answer made for a loop goes back with the identifiers the request
/// was received with, whatever the handler wrote to the header since.
#[tokio::test]
async fn a_loop_is_answered_with_the_received_identifiers() {
    let (backend, _written) = silent_peer("siphon.example.com");
    let target = RelayTarget::peer(backend);
    let handlers = NativeHandlers::new()
        .handle(TEST_APPLICATION, TEST_COMMAND, move |mut request| {
            let target = target.clone();
            async move {
                request.message_mut().hop_by_hop = 1;
                request.message_mut().end_to_end = 2;
                let answer = request.relay(target, RelayOptions::default()).await;
                Ok(NativeOutcome::Answer(answer))
            }
        })
        .expect("a first handler");
    let mut looping = steered_request("relay;harness;10");
    looping
        .avps
        .push(Avp::utf8(avp::ROUTE_RECORD, 0, "siphon.example.com"));
    let answer = NativeHarness::new(handlers)
        .call(&looping)
        .await
        .answer()
        .expect("answered");
    assert_eq!(answer.answer_result_codes().0, Some(3005));
    assert_eq!(answer.hop_by_hop, 0x1111_2222);
    assert_eq!(answer.end_to_end, 0x3333_4444);
}

/// A handler that never finishes is answered once the handler timeout of
/// the script path has passed.
#[tokio::test]
async fn a_handler_that_never_finishes_is_answered_unable_to_comply() {
    let stuck: NativeHandler = Arc::new(|_request| Box::pin(std::future::pending()));
    let (peer, _written) = silent_peer("siphon.example.com");
    let inbound = dispatch::Inbound {
        peer: &peer,
        peer_name: "peer",
        tenant: "default",
        origin: ("siphon.example.com", "example.com"),
    };
    let wire = dispatch::answer_wire_within(
        &stuck,
        steered_request("stuck;harness;11"),
        &inbound,
        std::time::Duration::from_millis(50),
    )
    .await
    .expect("answered, not handed to the script");
    let answer = DiameterMsg::from_wire(&wire).expect("the answer parses");
    assert_eq!(answer.answer_result_codes().0, Some(5012));
    assert_eq!(answer.hop_by_hop, 0x1111_2222);
    assert_eq!(
        answer.get_str(avp::ERROR_MESSAGE).as_deref(),
        Some("native handler timed out")
    );
}

#[tokio::test]
async fn a_relay_with_no_open_peer_is_answered_unable_to_deliver() {
    let manager = Arc::new(crate::diameter::DiameterManager::new());
    let pool = crate::diameter::pool::PeerPool::new("default", manager, vec!["hss".to_owned()]);
    let target = RelayTarget::pool(&pool);
    assert!(!target.is_reachable());
    assert!(
        !RelayTarget::pool_sticky(&pool, "key", std::time::Duration::from_secs(1)).is_reachable()
    );
    let outcome = NativeHarness::new(relaying(target, RelayOptions::default()))
        .call(&steered_request("relay;harness;7"))
        .await;
    let answer = outcome.answer().expect("answered");
    assert_eq!(answer.answer_result_codes().0, Some(3002));
    assert_eq!(answer.hop_by_hop, 0x1111_2222);
}

#[tokio::test]
async fn a_relay_to_a_pool_takes_its_open_peer() {
    let manager = Arc::new(crate::diameter::DiameterManager::new());
    let (backend, mut written) = silent_peer("siphon.example.com");
    manager.register_backend(
        "default",
        "hss",
        Arc::new(crate::diameter::DiameterClient::new(backend)),
    );
    let pool = crate::diameter::pool::PeerPool::new("default", manager, vec!["hss".to_owned()]);
    let target = RelayTarget::pool(&pool);
    assert!(target.is_reachable());
    let options = RelayOptions::default().timeout(std::time::Duration::from_millis(100));
    let outcome = NativeHarness::new(relaying(target, options))
        .call(&steered_request("relay;harness;9"))
        .await;
    assert!(
        written.recv().await.is_some(),
        "the pool's peer got the request"
    );
    assert_eq!(result_code(&outcome), Some(3004));
}

/// Emit three answers to an S6a Authentication-Information-Request as hex
/// for [`scripts/validate_diameter_native_answers.sh`] to feed to tshark: a
/// handler's success with a vendor-specific grouped AVP two levels deep, a
/// handler's Experimental-Result, and the 5012 sent for a handler that
/// failed.
#[tokio::test]
async fn emit_answers_for_external_dissection() {
    let Ok(path) = std::env::var("SIPHON_DIAMETER_NATIVE_ANSWERS_HEX_OUT") else {
        // Nothing to do in an ordinary test run.
        return;
    };
    const AIR: u32 = dictionary::CMD_AUTHENTICATION_INFORMATION;
    let vendor = dictionary::VENDOR_3GPP;
    let handlers = NativeHandlers::new()
        .handle(dictionary::S6A_APP_ID, AIR, move |request| async move {
            match request.session_id().unwrap_or_default().as_str() {
                "mme.epc.example.com;1;1" => {
                    let vector = Avp::grouped(
                        avp::E_UTRAN_VECTOR,
                        vendor,
                        vec![
                            Avp::raw(avp::RAND, vendor, vec![0x11; 16]),
                            Avp::raw(avp::XRES, vendor, vec![0x22; 8]),
                            Avp::raw(avp::AUTN, vendor, vec![0x33; 16]),
                            Avp::raw(avp::KASME, vendor, vec![0x44; 32]),
                        ],
                    );
                    let answer = request.answer(2001).with_avp(Avp::grouped(
                        avp::AUTHENTICATION_INFO,
                        vendor,
                        vec![vector],
                    ));
                    Ok(NativeOutcome::Answer(answer))
                }
                "mme.epc.example.com;1;2" => Ok(NativeOutcome::Answer(
                    request.answer_experimental(vendor, 5001),
                )),
                _ => Err("no such subscriber store".into()),
            }
        })
        .expect("a first handler");
    let harness = NativeHarness::new(handlers).with_origin(
        "hss.epc.mnc001.mcc001.3gppnetwork.org",
        "epc.mnc001.mcc001.3gppnetwork.org",
    );

    // `text2pcap`'s hex-dump form: an offset, then the octets. An offset of
    // zero starts the next packet.
    let mut dump = String::new();
    for sequence in 1..=3 {
        let mut message = request(dictionary::S6A_APP_ID, AIR);
        message.avps[0] = Avp::utf8(
            avp::SESSION_ID,
            0,
            &format!("mme.epc.example.com;1;{sequence}"),
        );
        let HarnessOutcome::Answer(wire) = harness.call(&message).await else {
            panic!("every request is answered");
        };
        for (offset, chunk) in wire.chunks(16).enumerate() {
            dump.push_str(&format!("{:06x}", offset * 16));
            for byte in chunk {
                dump.push_str(&format!(" {byte:02x}"));
            }
            dump.push('\n');
        }
        dump.push('\n');
    }
    std::fs::write(&path, dump).expect("hex dump must be writable");
}

// ── Which peer a pool picked ────────────────────────────────────────────────

/// A pool of `names`, each an open peer whose written requests come out of
/// the receiver beside it.
fn pool_of(
    names: &[&str],
) -> (
    crate::diameter::pool::PeerPool,
    Vec<(
        Arc<crate::diameter::peer::DiameterPeer>,
        tokio::sync::mpsc::Receiver<Vec<u8>>,
    )>,
) {
    let manager = Arc::new(crate::diameter::DiameterManager::new());
    let peers: Vec<_> = names
        .iter()
        .map(|name| {
            let (peer, written) = silent_peer("siphon.example.com");
            manager.register_backend(
                "default",
                name,
                Arc::new(crate::diameter::DiameterClient::new(Arc::clone(&peer))),
            );
            (peer, written)
        })
        .collect();
    let pool = crate::diameter::pool::PeerPool::new(
        "default",
        manager,
        names.iter().map(|name| (*name).to_owned()).collect(),
    );
    (pool, peers)
}

#[tokio::test]
async fn a_named_pool_pick_reports_the_peer_it_relays_to() {
    let (pool, mut peers) = pool_of(&["hss-a", "hss-b"]);
    let first = RelayTarget::pool_named(&pool);
    assert_eq!(first.peer.as_deref(), Some("hss-a"));
    assert!(!first.affinity_hit, "round robin has no affinity");
    assert!(first.target.is_reachable());
    let second = RelayTarget::pool_named(&pool);
    assert_eq!(second.peer.as_deref(), Some("hss-b"), "the next in turn");

    // The request goes to the peer that was named.
    let options = RelayOptions::default().timeout(std::time::Duration::from_millis(100));
    let outcome = NativeHarness::new(relaying(second.target, options))
        .call(&steered_request("relay;pick;1"))
        .await;
    assert_eq!(result_code(&outcome), Some(3004));
    assert!(peers[1].1.try_recv().is_ok(), "hss-b got the request");
    assert!(peers[0].1.try_recv().is_err(), "hss-a did not");
}

#[tokio::test]
async fn a_named_sticky_pick_reports_the_peer_and_the_affinity() {
    let (pool, peers) = pool_of(&["hss-a", "hss-b"]);
    let ttl = std::time::Duration::from_secs(60);

    let miss = RelayTarget::pool_sticky_named(&pool, "001010000000001", ttl);
    assert_eq!(miss.peer.as_deref(), Some("hss-a"));
    assert!(!miss.affinity_hit, "the first pick binds the key");
    assert!(miss.target.is_reachable());

    let hit = RelayTarget::pool_sticky_named(&pool, "001010000000001", ttl);
    assert_eq!(hit.peer.as_deref(), Some("hss-a"));
    assert!(hit.affinity_hit);

    // The bound peer closes: the key moves, and that is not a hit.
    peers[0]
        .0
        .set_state_for_test(crate::diameter::peer::PeerState::Closed);
    let moved = RelayTarget::pool_sticky_named(&pool, "001010000000001", ttl);
    assert_eq!(moved.peer.as_deref(), Some("hss-b"));
    assert!(!moved.affinity_hit);
}

#[tokio::test]
async fn a_named_pick_from_a_pool_with_no_open_peer_names_none() {
    let manager = Arc::new(crate::diameter::DiameterManager::new());
    let pool = crate::diameter::pool::PeerPool::new("default", manager, vec!["hss".to_owned()]);
    let ttl = std::time::Duration::from_secs(60);
    for pick in [
        RelayTarget::pool_named(&pool),
        RelayTarget::pool_sticky_named(&pool, "key", ttl),
    ] {
        assert_eq!(pick.peer, None);
        assert!(!pick.affinity_hit);
        assert!(!pick.target.is_reachable());
        let outcome = NativeHarness::new(relaying(pick.target, RelayOptions::default()))
            .call(&steered_request("relay;pick;2"))
            .await;
        assert_eq!(result_code(&outcome), Some(3002));
    }
}

/// A named pick keeps the pool's other peers: when the picked peer cannot
/// take the request and `diameter.retry` allows it, the next peer gets it,
/// marked as a retransmission. A single connection has nowhere to go. In a
/// process of its own, since the retry policy is the process's.
#[test]
fn a_named_pick_falls_back_to_the_pools_other_peer() {
    crate::own_process::run(
        concat!(
            module_path!(),
            "::a_named_pick_falls_back_to_the_pools_other_peer"
        ),
        named_pick_falls_back,
    );
}

#[allow(clippy::disallowed_methods)] // a test's own runtime, nothing attached
fn named_pick_falls_back() {
    use crate::diameter::retry::{self, RetryPolicy, RetryRule};

    retry::install(RetryPolicy {
        rules: vec![RetryRule {
            application_id: TEST_APPLICATION,
            commands: vec![TEST_COMMAND],
            too_busy: true,
            unable_to_deliver: true,
            timeout: true,
        }],
        divert_abated: false,
    });
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(async {
        let options = RelayOptions::default().timeout(std::time::Duration::from_millis(100));
        type Pick = fn(&crate::diameter::pool::PeerPool) -> PoolPick;
        let picks: [(&str, Pick); 3] = [
            ("pool_named", RelayTarget::pool_named),
            ("pool_sticky_named", |pool| {
                RelayTarget::pool_sticky_named(pool, "key", std::time::Duration::from_secs(60))
            }),
            ("pool_peer", |pool| {
                let (name, client) = pool.pick_round_robin_named().expect("an open peer");
                PoolPick {
                    target: RelayTarget::pool_peer(pool, client),
                    peer: Some(name),
                    affinity_hit: false,
                }
            }),
        ];
        for (label, pick) in picks {
            let (pool, mut peers) = pool_of(&["hss-a", "hss-b"]);
            let picked = pick(&pool);
            assert_eq!(picked.peer.as_deref(), Some("hss-a"), "{label}");
            // The picked peer's connection is gone under the request.
            let (_, gone) = peers.remove(0);
            drop(gone);

            let outcome = NativeHarness::new(relaying(picked.target, options.clone()))
                .call(&steered_request("relay;fallback;1"))
                .await;
            let retried = peers[0]
                .1
                .try_recv()
                .unwrap_or_else(|_| panic!("{label}: the other peer got the request"));
            let retried = DiameterMsg::from_wire(&retried).expect("the request parses");
            assert_ne!(
                retried.flags & crate::diameter::codec::FLAG_RETRANSMITTED,
                0,
                "{label}: sent again, so with the T flag"
            );
            assert_eq!(retried.end_to_end, 0x3333_4444, "{label}");
            // The other peer is silent too: its timeout is the answer.
            assert_eq!(result_code(&outcome), Some(3004), "{label}");
        }

        // One connection alone: nothing else is tried.
        let (pool, mut peers) = pool_of(&["hss-a", "hss-b"]);
        let (_, client) = pool.pick_round_robin_named().expect("an open peer");
        let (_, gone) = peers.remove(0);
        drop(gone);
        let outcome = NativeHarness::new(relaying(RelayTarget::client(client), options))
            .call(&steered_request("relay;fallback;2"))
            .await;
        assert_eq!(result_code(&outcome), Some(3002));
        assert!(
            peers[0].1.try_recv().is_err(),
            "the other peer was not tried"
        );
    });
}
