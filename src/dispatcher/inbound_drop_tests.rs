//! What [`handle_inbound`] does with bytes that are not a SIP message.
//!
//! [`inbound_filter`](super::inbound_filter) unit-tests the classifier and the
//! rate limiter in isolation; these drive the dispatcher entry point itself, so
//! they prove the wiring — that a dropped payload is counted and never reaches
//! the parser, and that a malformed-but-plausible one still does.

use super::test_dispatcher::test_dispatcher;
use super::*;

fn udp_datagram(data: &[u8], remote: &str) -> InboundMessage {
    InboundMessage {
        connection_id: crate::transport::ConnectionId(1),
        transport: Transport::Udp,
        client_transport: None,
        local_addr: "192.0.2.1:5060".parse().expect("a literal address"),
        remote_addr: remote.parse().expect("a literal address"),
        data: Bytes::copy_from_slice(data),
    }
}

/// The `reason` series of `siphon_non_sip_datagrams_dropped_total`. Each test
/// below reads a different label so they cannot disturb each other when the
/// suite runs in parallel.
fn dropped(reason: &str) -> u64 {
    crate::metrics::metrics()
        .expect("metrics initialised")
        .non_sip_datagrams_dropped_total
        .with_label_values(&[reason])
        .get()
}

/// An INVITE with its header/body boundary chopped off: long enough and
/// SIP-shaped enough that the parser is the only thing that can judge it.
const TRUNCATED_INVITE: &str = concat!(
    "INVITE sip:bob@example.com SIP/2.0\r\n",
    "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK776asdhds\r\n",
    "From: <sip:alice@example.com>;tag=1928301774\r\n",
    "To: <sip:bob@example.com>\r\n",
);

#[tokio::test]
async fn an_all_nul_datagram_is_dropped_and_counted() {
    crate::metrics::init().ok();
    let dispatcher = test_dispatcher();
    let state = Arc::new(dispatcher.state);
    let before = dropped("all_nul");

    // The observed vendor NAT keepalive: four NUL bytes from the peer's SIP
    // port, every 15 s, for as long as the registration lives.
    handle_inbound(udp_datagram(&[0, 0, 0, 0], "192.0.2.20:5060"), &state);

    assert_eq!(dropped("all_nul"), before + 1);
    assert_eq!(
        state.parse_error_log.tracked_sources(),
        0,
        "the parser (and its warning) must never have been reached"
    );
    assert!(
        dispatcher.udp.try_recv().is_err(),
        "nothing is owed to the peer"
    );
}

#[tokio::test]
async fn a_datagram_too_short_for_a_start_line_is_dropped_and_counted() {
    crate::metrics::init().ok();
    let dispatcher = test_dispatcher();
    let state = Arc::new(dispatcher.state);
    let before = dropped("too_short");

    // One byte under the grammar floor, and neither whitespace nor NUL.
    handle_inbound(udp_datagram(b"SIP/2.0 200\r\n", "192.0.2.21:5060"), &state);

    assert_eq!(dropped("too_short"), before + 1);
    assert_eq!(state.parse_error_log.tracked_sources(), 0);
    assert!(dispatcher.udp.try_recv().is_err());
}

#[tokio::test]
async fn a_crlf_keepalive_is_still_dropped() {
    crate::metrics::init().ok();
    let dispatcher = test_dispatcher();
    let state = Arc::new(dispatcher.state);
    let before = dropped("whitespace");

    handle_inbound(udp_datagram(b"\r\n\r\n", "192.0.2.22:5060"), &state);

    assert_eq!(dropped("whitespace"), before + 1);
    assert_eq!(state.parse_error_log.tracked_sources(), 0);
    assert!(dispatcher.udp.try_recv().is_err());
}

#[tokio::test]
async fn a_malformed_but_plausible_datagram_still_reaches_the_parser() {
    let dispatcher = test_dispatcher();
    let state = Arc::new(dispatcher.state);

    // The premise: the parser is what rejects this, not the pre-parse filter.
    assert!(parse_sip_message_bytes(TRUNCATED_INVITE.as_bytes()).is_err());

    handle_inbound(
        udp_datagram(TRUNCATED_INVITE.as_bytes(), "192.0.2.23:5060"),
        &state,
    );

    // Tracking the source is what the warning path does on its way to logging,
    // so an entry here means the warning fired.
    assert_eq!(
        state.parse_error_log.tracked_sources(),
        1,
        "the parse error must still be logged"
    );
    assert!(dispatcher.udp.try_recv().is_err());
}

#[tokio::test]
async fn repeat_parse_errors_from_one_source_log_once_then_summarise() {
    let dispatcher = test_dispatcher();
    let state = Arc::new(dispatcher.state);
    let peer = "192.0.2.24:5060";

    for _ in 0..50 {
        handle_inbound(udp_datagram(TRUNCATED_INVITE.as_bytes(), peer), &state);
    }

    assert_eq!(
        state.parse_error_log.tracked_sources(),
        1,
        "one noisy source, one entry"
    );
    // The first of the fifty logged; the other forty-nine are carried, not
    // dropped, and the next line past the window reports them.
    let source = "192.0.2.24".parse().expect("a literal address");
    assert_eq!(
        state.parse_error_log.record(
            source,
            std::time::Instant::now() + super::inbound_filter::PARSE_ERROR_SUMMARY_WINDOW
        ),
        super::inbound_filter::ParseErrorAction::Log { suppressed: 49 }
    );
}

#[tokio::test]
async fn a_quiet_source_is_pruned_from_the_suppression_table() {
    let dispatcher = test_dispatcher();
    let state = Arc::new(dispatcher.state);
    let baseline = state.parse_error_log.tracked_sources();

    for host in 20..40u8 {
        let peer = format!("192.0.2.{host}:5060");
        handle_inbound(udp_datagram(TRUNCATED_INVITE.as_bytes(), &peer), &state);
    }
    assert_eq!(state.parse_error_log.tracked_sources(), baseline + 20);

    state
        .parse_error_log
        .prune(std::time::Instant::now() + super::inbound_filter::PARSE_ERROR_SUMMARY_WINDOW * 2);
    assert_eq!(state.parse_error_log.tracked_sources(), baseline);
}
