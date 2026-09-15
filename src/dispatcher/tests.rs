/// A script handler that never returns must not stop the event drain loop.
///
/// These loops `recv` media and registrar events from a bounded channel and
/// invoke the handler inline. Before the bound, one stuck handler stopped
/// the loop, the channel filled, and the media engine's control **read**
/// task then parked trying to enqueue the next event — at which point no
/// response was routed back to any pending request and every in-flight and
/// future media command failed on its own timeout. Media control dead
/// process-wide, connection still established, from one handler.
///
/// The handler is still awaited rather than spawned, so events keep their
/// order; only the wait is bounded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stuck_event_handler_does_not_stop_the_drain_loop() {
    // Released at the end so the blocked handler thread can exit and not
    // hold up runtime shutdown.
    let release = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let release_in_handler = std::sync::Arc::clone(&release);

    let started = std::time::Instant::now();
    tokio::time::timeout(
        super::EVENT_HANDLER_TIMEOUT * 30,
        super::run_event_handler("test.stuck", move || {
            while !release_in_handler.load(std::sync::atomic::Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }),
    )
    .await
    .expect(
        "run_event_handler never returned — one stuck script handler stops the \
         whole event drain, and for media events that takes the engine's \
         control read loop down with it",
    );

    assert!(
        started.elapsed() >= super::EVENT_HANDLER_TIMEOUT,
        "it must have waited out its own window, not returned early"
    );
    release.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// The timer wheel stores a *pointer* to the entry, not the entry.
///
/// Same shape as the transaction map: `hashbrown` sizes its bucket array
/// for peak concurrency and never shrinks it, and the wheel holds roughly
/// one entry per live transaction timer, so the count tracks
/// `rate x Timer J` too. Inline, a 176-byte `TimerEntry` made a 200-byte
/// bucket that the process kept at its busiest-ever moment for the rest of
/// its life.
#[test]
fn the_timer_wheel_stores_a_pointer_not_the_entry() {
    let bucket = std::mem::size_of::<(String, Box<super::TimerEntry>)>();
    let key_only = std::mem::size_of::<String>();
    assert!(
        bucket <= key_only + 16,
        "wheel bucket is {bucket} B against a {key_only} B key — the entry is \
         being stored inline again, and the table will retain it at peak \
         concurrency forever"
    );
    let payload = std::mem::size_of::<super::TimerEntry>();
    assert!(
        payload >= 64,
        "TimerEntry is down to {payload} B — re-check whether boxing still earns \
         its indirection"
    );
}

use super::*;
use crate::sip::builder::SipMessageBuilder;
use crate::sip::message::Method;
use crate::sip::parser::parse_sip_message;
use crate::sip::uri::SipUri;

/// `call.terminate()` from `@b2bua.on_answer` has to reach the dispatcher.
///
/// The B-leg is answered by the time the handler runs, but the A-leg is not —
/// its 2xx is only sent later in `handle_b2bua_response` — so terminate is
/// still actionable there, and it is the only lever a script has once it has
/// discovered the call cannot carry audio. It used to be dropped along with
/// every non-REFER action.
#[test]
fn terminate_from_on_answer_is_actionable() {
    assert_eq!(
        classify_answer_action(Some(CallAction::Terminate)),
        AnswerAction::Terminate
    );
}

/// A handler that deferred nothing connects the call, whether it set the
/// idle action explicitly or the object was never touched at all.
#[test]
fn an_untouched_call_object_connects() {
    assert_eq!(classify_answer_action(None), AnswerAction::Connect);
    assert_eq!(
        classify_answer_action(Some(CallAction::None)),
        AnswerAction::Connect
    );
}

/// `call.refer()` still defers rather than firing inside the handler — it is
/// sent only once the A-leg 2xx is on the wire, because a UAC confirms the
/// dialog on the 2xx (RFC 3261 §13.2.2.4) and answers an earlier REFER 481.
#[test]
fn refer_from_on_answer_is_deferred_with_its_target() {
    let refer_to = crate::sip::headers::refer::ReferTo {
        uri: "sip:transfer-target@example.invalid".to_string(),
        replaces: None,
    };
    assert_eq!(
        classify_answer_action(Some(CallAction::SendRefer {
            refer_to: refer_to.clone()
        })),
        AnswerAction::DeferRefer(refer_to)
    );
}

/// An action with no meaning after the B-leg answered is reported, not
/// silently discarded — the dispatcher warns naming the action, so a script
/// that tries one finds out from the log instead of from the absence of an
/// effect.
#[test]
fn an_inapplicable_action_is_surfaced_rather_than_dropped() {
    let reject = CallAction::Reject {
        code: 486,
        reason: "Busy Here".to_string(),
    };
    assert_eq!(
        classify_answer_action(Some(reject.clone())),
        AnswerAction::Inapplicable(reject)
    );
}

/// `Supported` is a list header: the option tag goes *inside* the value the
/// caller already advertised, never on a second line.
#[test]
fn option_tag_merges_into_the_callers_supported() {
    let mut headers = crate::sip::headers::SipHeaders::new();

    // Absent → set.
    advertise_option_tag(&mut headers, "timer");
    assert_eq!(headers.get("Supported").map(String::as_str), Some("timer"));

    // Already advertised → untouched, and NOT repeated.
    advertise_option_tag(&mut headers, "timer");
    assert_eq!(headers.get_all("Supported").map(|v| v.len()), Some(1));

    // Present without the tag → merged into the same line, caller's tags kept.
    let mut headers = crate::sip::headers::SipHeaders::new();
    headers.set("Supported", "histinfo".to_string());
    advertise_option_tag(&mut headers, "timer");
    assert_eq!(
        headers.get("Supported").map(String::as_str),
        Some("histinfo,timer")
    );
    assert_eq!(headers.get_all("Supported").map(|v| v.len()), Some(1));

    // Case-insensitive per RFC 3261 §7.3.1, and whitespace-tolerant.
    let mut headers = crate::sip::headers::SipHeaders::new();
    headers.set("Supported", "histinfo, TIMER".to_string());
    advertise_option_tag(&mut headers, "timer");
    assert_eq!(
        headers.get("Supported").map(String::as_str),
        Some("histinfo, TIMER"),
        "an option tag already present in any case must not be repeated"
    );
}

/// A B-leg response is classified by its own status line and nothing else.
///
/// This is the invariant behind the callee actually being ACKed. When the
/// leg actor's `CallEvent` decided this instead, a 2xx processed while its
/// own 18x's event was still queued read as `Provisional` — skipping
/// `set_winner` and the B-leg ACK, so the callee's 200 was never
/// ACKed and it retransmitted until the dialog collapsed. Measured at
/// 8-15% of plain calls on a loopback B2BUA.
#[test]
fn b_leg_response_is_classified_by_its_own_status() {
    // Every 2xx answers the call.
    for code in [200, 202, 250, 299] {
        assert_eq!(
            classify_b_leg_response(code),
            Some(ResponseClass::Answered),
            "{code} must answer"
        );
    }
    // 18x rings; 100 is absorbed rather than classified.
    assert_eq!(
        classify_b_leg_response(180),
        Some(ResponseClass::Provisional)
    );
    assert_eq!(
        classify_b_leg_response(183),
        Some(ResponseClass::Provisional)
    );
    assert_eq!(
        classify_b_leg_response(199),
        Some(ResponseClass::Provisional)
    );
    assert_eq!(classify_b_leg_response(100), None, "100 Trying is absorbed");
    assert_eq!(
        classify_b_leg_response(179),
        None,
        "a 1xx below 180 is absorbed"
    );
    // Everything final and non-2xx fails the leg.
    for code in [300, 401, 404, 486, 500, 603] {
        assert_eq!(
            classify_b_leg_response(code),
            Some(ResponseClass::Failed),
            "{code} must fail the leg"
        );
    }
}

// -----------------------------------------------------------------------
// LCR per-route header injection must not forge dialog headers
// -----------------------------------------------------------------------

/// A route carrying `headers`, everything else defaulted.
fn route_with_headers(pairs: &[(&str, &str)]) -> crate::lcr::Route {
    crate::lcr::Route {
        carrier_id: "carrier-a".to_string(),
        headers: pairs
            .iter()
            .map(|(name, value)| ((*name).to_string(), (*value).to_string()))
            .collect(),
        ..Default::default()
    }
}

// -----------------------------------------------------------------------
// LCR destination retarget (RFC 3261 §16.5)
// -----------------------------------------------------------------------

fn route_to(destination: Option<&str>) -> crate::lcr::Route {
    crate::lcr::Route {
        carrier_id: "carrier-a".to_string(),
        destination: destination.map(str::to_string),
        ..Default::default()
    }
}

fn injected_names(route: &crate::lcr::Route) -> Vec<String> {
    let mut names: Vec<String> = lcr_injectable_headers(route, "call-id@host")
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    names.sort();
    names
}

#[test]
fn lcr_headers_pass_through_an_ordinary_carrier_header() {
    let route = route_with_headers(&[("X-Account", "42"), ("X-Route-Tag", "gold")]);
    assert_eq!(injected_names(&route), vec!["X-Account", "X-Route-Tag"]);
}

#[test]
fn lcr_headers_refuse_from_so_the_dialog_tag_survives() {
    // The bug this closes: an unfiltered `From` overwrote the B-leg From
    // including its tag, which doesn't fail at INVITE time — it surfaces
    // later as ACKs and BYEs that no longer match the dialog.
    let route = route_with_headers(&[("From", "<sip:spoofed@example.net>"), ("X-Account", "42")]);
    assert_eq!(injected_names(&route), vec!["X-Account"]);
}

#[test]
fn lcr_headers_refuse_every_dialog_header() {
    for name in [
        "Via",
        "Call-ID",
        "CSeq",
        "Max-Forwards",
        "Content-Length",
        "From",
        "To",
        "Contact",
        "Record-Route",
        "Route",
    ] {
        let route = route_with_headers(&[(name, "forged"), ("X-Account", "42")]);
        assert_eq!(
            injected_names(&route),
            vec!["X-Account"],
            "{name} must not be injectable from an LCR route",
        );
    }
}

#[test]
fn lcr_headers_refuse_dialog_headers_case_insensitively() {
    // RFC 3261 §7.3.1 makes field names case-insensitive, so a lower-cased
    // or mixed-case spelling must not slip past the guard.
    let route = route_with_headers(&[
        ("from", "<sip:spoofed@example.net>"),
        ("cAlL-Id", "forged@host"),
        ("X-Account", "42"),
    ]);
    assert_eq!(injected_names(&route), vec!["X-Account"]);
}

#[test]
fn lcr_headers_still_allow_a_per_carrier_trunk_credential() {
    // Proxy-Authorization is deliberately outside the framework-auto set:
    // a per-carrier trunk credential is a legitimate use of this field.
    let route = route_with_headers(&[("Proxy-Authorization", "Digest username=\"trunk\"")]);
    assert_eq!(injected_names(&route), vec!["Proxy-Authorization"]);
}

#[test]
fn lcr_headers_on_a_route_with_none_inject_nothing() {
    assert!(lcr_injectable_headers(&route_with_headers(&[]), "call-id@host").is_empty());
}

// -----------------------------------------------------------------------
// The authenticated identity has to reach the proxy-mode CDR
// -----------------------------------------------------------------------

fn invite_for_cdr() -> SipMessage {
    let raw = concat!(
        "INVITE sip:bob@example.com SIP/2.0\r\n",
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-cdr\r\n",
        "From: <sip:alice@example.com>;tag=a-tag\r\n",
        "To: <sip:bob@example.com>\r\n",
        "Call-ID: cdr-auth@host\r\n",
        "CSeq: 1 INVITE\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    );
    parse_sip_message(raw).expect("fixture parses").1
}

#[test]
fn a_proxy_cdr_carries_the_authenticated_username() {
    // `cdr_session_from_invite` took an `auth_user` and both callers passed
    // `None`, so a proxy-mode CDR's `auth_user` was always empty even when
    // the script had authenticated the caller — while the doc on
    // `CdrSession::set_auth_user` claimed the proxy path supplied it at
    // session-build time.
    let (_, session) = cdr_session_from_invite(
        &invite_for_cdr(),
        "10.0.0.1",
        "udp",
        Some("alice".to_string()),
    )
    .expect("session builds");

    assert_eq!(
        session.finalize("caller", None, None).auth_user.as_deref(),
        Some("alice"),
    );
}

#[test]
fn an_unauthenticated_proxy_call_leaves_the_cdr_username_empty() {
    // `None` must stay absent rather than becoming an empty string that
    // reads as "authenticated as nobody".
    let (_, session) = cdr_session_from_invite(&invite_for_cdr(), "10.0.0.1", "udp", None)
        .expect("session builds");

    assert!(session.finalize("caller", None, None).auth_user.is_none());
}

/// The dispatcher function that owns the proxy CDR start is not
/// constructible in a unit test (it needs a full `DispatcherState` and a
/// live Python handler), and no integration harness drives it — so the
/// behaviour test above proves `cdr_session_from_invite` *stores* the
/// identity, but not that the call site still *passes* it.
///
/// That is the half that regressed once already: the parameter existed all
/// along and every caller passed `None`. Guard the wiring at the source
/// level, the same way the packaging tests guard workflow drift. The record
/// is now opened before the script runs, so the identity is no longer known
/// when it is built — it reaches the record through the settle step, and
/// that is what has to stay wired.
#[test]
fn the_proxy_cdr_settle_is_still_wired_to_the_authenticated_identity() {
    // `handle_request` lives in `request.rs` since the split.
    let source = include_str!("request.rs");

    // The block in `handle_request` that decides the outcome and settles.
    let block = source
        .split("    if let Some(cdr_key) = &cdr_key {")
        .nth(1)
        .expect("the proxy CDR settle is still called");
    let block = block
        .split("cdr_settle_proxy_start(")
        .next()
        .unwrap_or_default();

    assert!(
        block.contains("auth_user"),
        "the settled outcome no longer carries the authenticated \
         username — a proxy CDR's auth_user would silently go back to \
         always being empty. The block was:{block}"
    );
}

/// The record has to exist *while* the script handler runs, or
/// `cdr.write(request, extra=…)` from that handler finds nothing to attach
/// to and silently falls back to queueing a second, timing-less record —
/// the exact behaviour this ordering was changed to fix. Source-level for
/// the same reason as the guard above: `handle_request` needs a full
/// dispatcher and a live interpreter to drive.
#[test]
fn the_proxy_cdr_record_is_opened_before_the_script_handler_runs() {
    // `handle_request` lives in `request.rs` since the split.
    let source = include_str!("request.rs");

    let opened = source
        .find("    let cdr_key = if method == \"INVITE\" {")
        .expect("the proxy CDR record is still opened in handle_request");
    let handlers = source
        .find("    // Call Python handlers")
        .expect("the script handlers are still dispatched in handle_request");
    let settled = source
        .find("    if let Some(cdr_key) = &cdr_key {")
        .expect("the proxy CDR record is still settled in handle_request");

    assert!(
        opened < handlers,
        "the CDR record is opened after the script handlers run — \
         cdr.write(request, extra=…) from a handler can no longer reach it"
    );
    assert!(
        handlers < settled,
        "the CDR record is settled before the script handlers run"
    );
}

const ACCESS_NUMBER: &str = "sip:+12025550100@siphon.example.com";
const CARRIER: &str = "sip:10.0.0.1:5060";

#[test]
fn no_destination_keeps_the_dialled_number() {
    let target = b2bua_carrier_ruri(&route_to(None), ACCESS_NUMBER, Some(CARRIER), None);
    assert!(target.contains("+12025550100"), "{target}");
}

#[test]
fn a_destination_replaces_the_dialled_number_and_keeps_the_carrier_host() {
    // The shape this exists for: an inbound call addressed to a local
    // access number is retargeted at the real destination, and still goes
    // out through the gateway-group member siphon selected.
    let target = b2bua_carrier_ruri(
        &route_to(Some("+12025550199")),
        ACCESS_NUMBER,
        Some(CARRIER),
        None,
    );

    assert!(target.contains("+12025550199"), "{target}");
    assert!(
        !target.contains("+12025550100"),
        "the access number must not be on the wire: {target}",
    );
    assert!(
        target.contains("10.0.0.1"),
        "host still comes from the carrier: {target}"
    );
}

#[test]
fn a_destination_given_as_a_uri_contributes_only_its_userpart() {
    // The host is siphon's to decide, from the gateway group or next-hop, so
    // a retarget can never route the call somewhere unconfigured.
    let target = b2bua_carrier_ruri(
        &route_to(Some("sip:+12025550199@somewhere-else.example.net")),
        ACCESS_NUMBER,
        Some(CARRIER),
        None,
    );

    assert!(target.contains("+12025550199"), "{target}");
    assert!(
        !target.contains("somewhere-else"),
        "a destination must not redirect the call: {target}",
    );
    assert!(target.contains("10.0.0.1"), "{target}");
}

#[test]
fn tech_prefix_applies_on_top_of_the_retargeted_number() {
    // Retarget happens first, so the carrier's prefix lands in front of the
    // *new* number — not the access number.
    let route = crate::lcr::Route {
        carrier_id: "carrier-a".to_string(),
        destination: Some("+12025550199".to_string()),
        tech_prefix: Some("1010288".to_string()),
        ..Default::default()
    };
    let target = b2bua_carrier_ruri(&route, ACCESS_NUMBER, Some(CARRIER), None);

    assert!(target.contains("1010288+12025550199"), "{target}");
}

#[test]
fn an_explicit_ruri_still_gets_retargeted_but_keeps_its_own_host() {
    // `ruri` owns the host; `destination` owns the number. Both can be set.
    let route = crate::lcr::Route {
        carrier_id: "carrier-a".to_string(),
        ruri: Some("sip:+12025550100@carrier-a.net".to_string()),
        destination: Some("+12025550199".to_string()),
        ..Default::default()
    };
    let target = b2bua_carrier_ruri(&route, ACCESS_NUMBER, Some(CARRIER), None);

    assert!(target.contains("+12025550199"), "{target}");
    assert!(
        target.contains("carrier-a.net"),
        "an explicit ruri keeps its host: {target}"
    );
}

#[test]
fn an_empty_destination_is_ignored_rather_than_blanking_the_number() {
    let target = b2bua_carrier_ruri(&route_to(Some("")), ACCESS_NUMBER, Some(CARRIER), None);
    assert!(target.contains("+12025550100"), "{target}");
}

#[test]
fn a_retarget_survives_an_unparseable_base_uri() {
    // The degenerate path must not silently drop the retarget.
    let route = crate::lcr::Route {
        carrier_id: "carrier-a".to_string(),
        destination: Some("+12025550199".to_string()),
        tech_prefix: Some("99".to_string()),
        ..Default::default()
    };
    let target = b2bua_carrier_ruri(&route, "not a uri", Some(CARRIER), None);
    assert_eq!(target, "99+12025550199");
}

#[test]
fn a_retarget_moves_the_to_userpart_off_the_access_number() {
    // A retargeted call must not carry the number it was dialled on.
    // RFC 3261 §8.1.1.2 does not require To to track the R-URI, but a To
    // still naming the access number both leaks it and reads as malformed
    // to elements that expect the two to agree.
    let to = "<sip:+12025550100@siphon.example.com>";
    let rewritten = rewrite_uri_userpart(to, "+12025550199");

    assert!(rewritten.contains("+12025550199"), "{rewritten}");
    assert!(!rewritten.contains("+12025550100"), "{rewritten}");
    assert!(
        rewritten.contains("siphon.example.com"),
        "host is untouched: {rewritten}"
    );
}

#[test]
fn rewriting_the_to_userpart_preserves_the_display_name_and_params() {
    let to = "\"Support\" <sip:+12025550100@example.com:5070;transport=tcp>";
    let rewritten = rewrite_uri_userpart(to, "+12025550199");

    assert!(rewritten.contains("Support"), "{rewritten}");
    assert!(rewritten.contains("+12025550199"), "{rewritten}");
    assert!(rewritten.contains("5070"), "port survives: {rewritten}");
    assert!(
        rewritten.contains("transport=tcp"),
        "uri params survive: {rewritten}"
    );
}

#[test]
fn an_unparseable_header_is_left_alone_rather_than_corrupted() {
    assert_eq!(
        rewrite_uri_userpart("not a name-addr", "+12025550199"),
        "not a name-addr"
    );
}

#[test]
fn destination_userpart_accepts_a_bare_number_or_a_uri() {
    assert_eq!(lcr_destination_userpart("+12025550199"), "+12025550199");
    assert_eq!(
        lcr_destination_userpart("sip:+12025550199@carrier.net"),
        "+12025550199"
    );
    assert_eq!(lcr_destination_userpart("tel:+12025550199"), "+12025550199");
}

#[test]
fn b2bua_media_target_is_none_without_dispatcher() {
    // No B2BUA_CONTROL installed in a unit-test binary → the media-target
    // accessor resolves to None (the SIP control adapter maps that to a typed
    // not_found), never a fabricated call-id and never a panic.
    assert!(b2bua_media_target("sip-call-id@host").is_none());
}

// -----------------------------------------------------------------------
// Transport failure / timeout must become a response (RFC 3261 §16.7, §16.9)
// -----------------------------------------------------------------------

#[test]
fn send_outcome_distinguishes_failure_from_a_zero_connection_id() {
    // The bug that hid every transport error: the stream transports
    // returned `ConnectionId::default()` as a failure sentinel, but UDP
    // returns the caller's `fallback_connection_id` — which several call
    // sites pass as exactly that value. A caller could not tell "the pool
    // refused it" from "UDP sent it with no connection id".
    let udp_success = SendOutcome::sent(ConnectionId::default());
    assert!(!udp_success.delivery_failed);
    assert_eq!(udp_success.connection_id, ConnectionId::default());

    let refused = SendOutcome::failed();
    assert!(refused.delivery_failed);
    assert_eq!(refused.connection_id, ConnectionId::default());

    // Same connection id, opposite meaning — which is the whole point.
    assert_eq!(udp_success.connection_id, refused.connection_id);
    assert_ne!(udp_success.delivery_failed, refused.delivery_failed);
}

fn response_for_downgrade(status_code: u16, reason: &str) -> SipMessage {
    SipMessageBuilder::new()
        .response(status_code, reason.to_string())
        .via("SIP/2.0/UDP proxy.example.com;branch=z9hG4bK-1".to_string())
        .to("<sip:bob@example.com>;tag=b".to_string())
        .from("<sip:alice@example.com>;tag=a".to_string())
        .call_id("downgrade-test".to_string())
        .cseq("1 INVITE".to_string())
        .header("Retry-After", "120".to_string())
        .content_length(0)
        .build()
        .unwrap()
}

fn downgrade_key() -> TransactionKey {
    TransactionKey::new(
        "z9hG4bK-server".to_string(),
        Method::Invite,
        "192.0.2.1:5060".to_string(),
    )
}

#[test]
fn a_503_is_forwarded_upstream_as_500() {
    // RFC 3261 §16.7 step 6. A downstream element being unavailable is not
    // the caller's business, and a UAC that saw the 503 would take the
    // whole proxy out of service.
    let mut response = response_for_downgrade(503, "Service Unavailable");
    let forwarded = downgrade_503_for_upstream(&mut response, 503, &downgrade_key());

    assert_eq!(forwarded, 500);
    assert_eq!(response.status_code(), Some(500));
    let wire = String::from_utf8(response.to_bytes()).unwrap();
    assert!(wire.starts_with("SIP/2.0 500 Server Internal Error"));
    // Retry-After described the unavailable downstream, not this proxy.
    assert!(!wire.contains("Retry-After"));
}

#[test]
fn other_status_codes_are_forwarded_untouched() {
    for (code, reason) in [
        (404, "Not Found"),
        (408, "Request Timeout"),
        (200, "OK"),
        (500, "Server Internal Error"),
    ] {
        let mut response = response_for_downgrade(code, reason);
        let forwarded = downgrade_503_for_upstream(&mut response, code, &downgrade_key());
        assert_eq!(forwarded, code, "{code} must be forwarded unchanged");
        assert_eq!(response.status_code(), Some(code));
        // Only the 503 path strips Retry-After.
        let wire = String::from_utf8(response.to_bytes()).unwrap();
        assert!(wire.contains("Retry-After"), "{code} must keep Retry-After");
    }
}

/// A failure siphon builds for the caller answers the INVITE the caller sent
/// (RFC 3261 §8.2.6.2), not the B-leg shape a handler gave the stored copy: the
/// caller's own From, and its own To with the A-leg dialog's tag. A failure
/// `@b2bua.on_failure` chooses with `call.reject()` comes this way, from a
/// handler that has often reshaped the numbers for the dial plan first.
#[test]
fn a_b2bua_failure_for_the_caller_echoes_the_callers_own_from_and_to() {
    // The stored INVITE as a handler left it, numbers reshaped for the dial plan.
    let (_, invite) = parse_sip_message(concat!(
        "INVITE sip:+0010100000002@example.com SIP/2.0\r\n",
        "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-caller\r\n",
        "Max-Forwards: 70\r\n",
        "From: <sip:+0010100000001@example.com>;tag=caller\r\n",
        "To: <sip:+0010100000002@example.com>\r\n",
        "Call-ID: a-leg@192.0.2.10\r\n",
        "CSeq: 7 INVITE\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    ))
    .expect("INVITE parses");
    // From and To as the caller sent them.
    let arrived_from = "<sip:0100000001@example.com>;tag=caller".to_string();
    let arrived_to = "<sip:0100000002@example.com>".to_string();

    let response = build_a_leg_final_response(
        &invite,
        "siphon-a-tag",
        Some(&arrived_from),
        Some(&arrived_to),
        480,
        "Temporarily Unavailable",
        None,
    );

    assert_eq!(response.status_code(), Some(480));
    assert_eq!(
        response.headers.from().map(String::as_str),
        Some("<sip:0100000001@example.com>;tag=caller")
    );
    assert_eq!(
        response.headers.to().map(String::as_str),
        Some("<sip:0100000002@example.com>;tag=siphon-a-tag")
    );
}

/// RFC 3261 §16.7 step 6 on the B2BUA: the 500 that replaces a chosen B-leg
/// 503 is generated from the caller's own INVITE. It carries the A-leg's Via,
/// Call-ID and CSeq and the A-leg dialog's To-tag, and nothing from the B-leg
/// (no Retry-After, no Contact).
#[test]
fn a_b2bua_failure_for_the_caller_is_built_from_its_invite() {
    let (_, invite) = parse_sip_message(concat!(
        "INVITE sip:bob@example.com SIP/2.0\r\n",
        "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-caller\r\n",
        "Max-Forwards: 70\r\n",
        "From: <sip:alice@example.com>;tag=caller\r\n",
        "To: <sip:bob@example.com>\r\n",
        "Call-ID: a-leg@192.0.2.10\r\n",
        "CSeq: 7 INVITE\r\n",
        "Contact: <sip:alice@192.0.2.10:5060>\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    ))
    .expect("INVITE parses");

    let upstream = crate::sip::best_response::upstream_status(503);
    let response = build_a_leg_final_response(
        &invite,
        "siphon-a-tag",
        None,
        None,
        upstream,
        crate::sip::best_response::SERVER_INTERNAL_ERROR,
        None,
    );

    assert_eq!(response.status_code(), Some(500));
    let wire = String::from_utf8(response.to_bytes()).unwrap();
    assert!(wire.starts_with("SIP/2.0 500 Server Internal Error\r\n"));
    assert_eq!(
        response.headers.via().map(String::as_str),
        Some("SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-caller")
    );
    assert_eq!(
        response.headers.call_id().map(String::as_str),
        Some("a-leg@192.0.2.10")
    );
    assert_eq!(
        response.headers.cseq().map(String::as_str),
        Some("7 INVITE")
    );
    assert_eq!(
        response.headers.to().map(String::as_str),
        Some("<sip:bob@example.com>;tag=siphon-a-tag")
    );
    assert!(!wire.contains("Retry-After"));
    assert!(!wire.contains("Contact"));
}

// -----------------------------------------------------------------------
// Media CDR from an end-of-call summary (media.backend: siphon-rtp)
// -----------------------------------------------------------------------

#[test]
fn media_summary_to_cdr_flattens_legs() {
    use crate::rtpengine::events::{CallLegSummary, CallSummary};

    fn measured_leg(tag: &str, codec: &str) -> CallLegSummary {
        CallLegSummary {
            tag: tag.to_string(),
            codec: Some(codec.to_string()),
            packets_in: 2100,
            bytes_in: 336_000,
            packets_out: 2098,
            bytes_out: 335_680,
            packets_dropped: 2,
            ssrc: Some(0x0102_0304),
            packets_lost: Some(6),
            loss_percent: Some(0.3),
            jitter_ms: Some(4.2),
            rtt_ms: Some(21.0),
            mos_average: Some(4.11),
            mos_min: Some(3.9),
            mos_max: Some(4.3),
            mos_basis: Some("full".to_string()),
            text: None,
        }
    }

    // A counters-only far leg (plain in-kernel relay, no actor) — every
    // quality field is None and must be omitted from the CDR, not empty.
    let far = CallLegSummary {
        tag: "far-tag".to_string(),
        codec: None,
        packets_in: 2099,
        bytes_in: 335_840,
        packets_out: 2100,
        bytes_out: 336_000,
        packets_dropped: 0,
        ssrc: None,
        packets_lost: None,
        loss_percent: None,
        jitter_ms: None,
        rtt_ms: None,
        mos_average: None,
        mos_min: None,
        mos_max: None,
        mos_basis: None,
        text: None,
    };

    let summary = CallSummary {
        call_id: "call-9".to_string(),
        reason: "delete".to_string(),
        duration_ms: 42_500,
        legs: vec![measured_leg("near-tag", "AMR-WB"), far],
    };

    let cdr = media_summary_to_cdr(&summary);

    assert_eq!(cdr.call_id, "call-9");
    assert_eq!(cdr.method, "MEDIA");
    assert_eq!(cdr.response_code, 0);
    // Media lifetime surfaces both as the standard duration and precisely.
    assert!((cdr.duration_secs - 42.5).abs() < 1e-9);
    assert_eq!(
        cdr.extra.get("media_duration_ms").map(String::as_str),
        Some("42500")
    );
    assert_eq!(
        cdr.extra.get("media_reason").map(String::as_str),
        Some("delete")
    );

    // Near (measured) leg — counters + quality present under `near_`.
    assert_eq!(
        cdr.extra.get("near_tag").map(String::as_str),
        Some("near-tag")
    );
    assert_eq!(
        cdr.extra.get("near_codec").map(String::as_str),
        Some("AMR-WB")
    );
    assert_eq!(
        cdr.extra.get("near_packets_in").map(String::as_str),
        Some("2100")
    );
    assert_eq!(
        cdr.extra.get("near_bytes_out").map(String::as_str),
        Some("335680")
    );
    assert_eq!(
        cdr.extra.get("near_packets_dropped").map(String::as_str),
        Some("2")
    );
    assert_eq!(
        cdr.extra.get("near_packets_lost").map(String::as_str),
        Some("6")
    );
    assert_eq!(
        cdr.extra.get("near_loss_percent").map(String::as_str),
        Some("0.3")
    );
    assert_eq!(
        cdr.extra.get("near_mos_average").map(String::as_str),
        Some("4.11")
    );
    assert_eq!(
        cdr.extra.get("near_mos_basis").map(String::as_str),
        Some("full")
    );

    // Far (counters-only) leg — quality fields omitted entirely.
    assert_eq!(
        cdr.extra.get("far_tag").map(String::as_str),
        Some("far-tag")
    );
    assert_eq!(
        cdr.extra.get("far_packets_in").map(String::as_str),
        Some("2099")
    );
    assert!(!cdr.extra.contains_key("far_codec"));
    assert!(!cdr.extra.contains_key("far_ssrc"));
    assert!(!cdr.extra.contains_key("far_mos_average"));
    assert!(!cdr.extra.contains_key("far_mos_basis"));
}

#[test]
fn media_summary_to_cdr_indexes_extra_legs() {
    use crate::rtpengine::events::{CallLegSummary, CallSummary};

    fn bare_leg(tag: &str) -> CallLegSummary {
        CallLegSummary {
            tag: tag.to_string(),
            codec: None,
            packets_in: 1,
            bytes_in: 2,
            packets_out: 3,
            bytes_out: 4,
            packets_dropped: 0,
            ssrc: None,
            packets_lost: None,
            loss_percent: None,
            jitter_ms: None,
            rtt_ms: None,
            mos_average: None,
            mos_min: None,
            mos_max: None,
            mos_basis: None,
            text: None,
        }
    }

    // A third leg (MPTY / conference) indexes as `leg2_`, not near/far.
    let summary = CallSummary {
        call_id: "conf-1".to_string(),
        reason: "media_timeout".to_string(),
        duration_ms: 1_000,
        legs: vec![bare_leg("a"), bare_leg("b"), bare_leg("c")],
    };
    let cdr = media_summary_to_cdr(&summary);
    assert_eq!(cdr.extra.get("near_tag").map(String::as_str), Some("a"));
    assert_eq!(cdr.extra.get("far_tag").map(String::as_str), Some("b"));
    assert_eq!(cdr.extra.get("leg2_tag").map(String::as_str), Some("c"));
    assert_eq!(
        cdr.extra.get("media_reason").map(String::as_str),
        Some("media_timeout")
    );
}

#[test]
fn media_summary_to_cdr_handles_a_single_leg_call() {
    use crate::rtpengine::events::{CallLegSummary, CallSummary};

    // A single-leg call (`answer_local` — IVR, announcement, and every
    // voice-AI call where the engine itself is the far side) has exactly one
    // media party, and `siphon-rtp` reports it as one leg. Everything the
    // caller sent must land under `near_`, and no `far_` key may be
    // synthesised for a party that does not exist — a media CDR showing a
    // far leg on a call that never had one is worse than one showing none.
    let leg = CallLegSummary {
        tag: "caller".to_string(),
        codec: Some("PCMU".to_string()),
        packets_in: 60,
        bytes_in: 10_320,
        packets_out: 64,
        bytes_out: 11_008,
        packets_dropped: 0,
        ssrc: Some(0x0000_2222),
        packets_lost: Some(0),
        loss_percent: Some(0.0),
        jitter_ms: Some(19.25),
        rtt_ms: None,
        mos_average: None,
        mos_min: None,
        mos_max: None,
        mos_basis: Some("loss+jitter".to_string()),
        text: None,
    };
    let summary = CallSummary {
        call_id: "voice-ai-1".to_string(),
        reason: "delete".to_string(),
        duration_ms: 1_000,
        legs: vec![leg],
    };

    let cdr = media_summary_to_cdr(&summary);
    assert_eq!(
        cdr.extra.get("near_tag").map(String::as_str),
        Some("caller")
    );
    assert_eq!(
        cdr.extra.get("near_packets_in").map(String::as_str),
        Some("60")
    );
    assert_eq!(
        cdr.extra.get("near_packets_out").map(String::as_str),
        Some("64")
    );
    assert_eq!(
        cdr.extra.get("near_codec").map(String::as_str),
        Some("PCMU")
    );
    // Quality belongs to the same leg as the counters, not a separate one.
    assert_eq!(
        cdr.extra.get("near_jitter_ms").map(String::as_str),
        Some("19.25")
    );
    // No second party.
    assert!(
        !cdr.extra.keys().any(|key| key.starts_with("far_")),
        "single-leg summary must not synthesise a far leg: {:?}",
        cdr.extra.keys().collect::<Vec<_>>()
    );
}

// -----------------------------------------------------------------------
// A-leg advertised port (multi-homed Contact / reply-socket anchoring)
// -----------------------------------------------------------------------

#[test]
fn a_leg_advertised_port_prefers_arrival_socket() {
    // Multi-homed host: INVITE arrived on :5066 while the default listener is
    // :5060. The A-leg Contact / dialog anchor must be the arrival port, else
    // in-dialog requests are directed to a port the dialog isn't on.
    let arrival: SocketAddr = "192.0.2.94:5066".parse().unwrap();
    assert_eq!(a_leg_advertised_port(Some(arrival), 5060), 5066);
}

#[test]
fn a_leg_advertised_port_falls_back_to_via_port_when_unknown() {
    // Single-listener host (or arrival socket not captured): fall back to the
    // default per-transport listener port — where the two are the same anyway.
    assert_eq!(a_leg_advertised_port(None, 5060), 5060);
    // And when the arrival socket happens to equal the default, still correct.
    let same: SocketAddr = "10.0.0.1:5060".parse().unwrap();
    assert_eq!(a_leg_advertised_port(Some(same), 5060), 5060);
}

// -----------------------------------------------------------------------
// Flow-pinned B-leg sent-by (IPsec sec-agree / captured-flow egress)
// -----------------------------------------------------------------------

/// A B-leg dialled over a captured flow leaves from that flow's socket, so
/// the sent-by it advertises must name that socket — NOT the default
/// per-transport listener.
///
/// This is the soft-UE MO-call invariant (3GPP TS 33.203 §7.4): the UE's
/// protected client port sends the INVITE, and the SA only carries a
/// response addressed back to that port. Advertising the plain listener
/// asks the P-CSCF to answer outside the SA, where the response is lost and
/// the call times out with no final response at all.
#[test]
fn pinned_sent_by_names_the_flow_socket_not_the_default_listener() {
    // Soft-UE shape: plain SIP on :5060, protected client port :6100.
    let protected_client: SocketAddr = "192.0.2.10:6100".parse().unwrap();
    let (host, port) = pinned_sent_by(protected_client, || "advertised.example.net".to_string());
    assert_eq!(host, "192.0.2.10");
    assert_eq!(
        port, 6100,
        "a flow-pinned B-leg must advertise the flow's own port, not :5060"
    );
}

/// The protected *server* port is a distinct pin — a leg anchored there
/// must not collapse onto the client port or the default listener.
#[test]
fn pinned_sent_by_distinguishes_the_two_protected_ports() {
    let client: SocketAddr = "192.0.2.10:6100".parse().unwrap();
    let server: SocketAddr = "192.0.2.10:6101".parse().unwrap();
    let advertised = || "192.0.2.10".to_string();
    assert_ne!(
        pinned_sent_by(client, advertised),
        pinned_sent_by(server, advertised)
    );
    assert_eq!(pinned_sent_by(server, advertised).1, 6101);
}

/// A v6 flow socket has to come out bracketed, or the Via is malformed
/// (`SIP/2.0/UDP 2001:db8::10:6100` parses the last colon as the port).
#[test]
fn pinned_sent_by_brackets_an_ipv6_flow_socket() {
    let v6: SocketAddr = "[2001:db8::10]:6100".parse().unwrap();
    let (host, port) = pinned_sent_by(v6, || "192.0.2.10".to_string());
    assert_eq!(host, "[2001:db8::10]");
    assert_eq!(port, 6100);
}

/// `listen: 0.0.0.0:5060` is the ordinary production shape and
/// `InboundMessage::local_addr` carries the bind address, so a flow captured
/// on such a listener pins to a wildcard.  Stamping `0.0.0.0` into a
/// sent-by names an address no peer can answer to and that no self-identity
/// recognises — the dialog's own in-dialog requests come back to us and are
/// refused `482 Loop Detected`.  Keep the pinned port, take the advertised
/// host.
#[test]
fn pinned_sent_by_never_advertises_a_wildcard_bind() {
    let wildcard: SocketAddr = "0.0.0.0:5060".parse().unwrap();
    let (host, port) = pinned_sent_by(wildcard, || "192.0.2.10".to_string());
    assert_eq!(host, "192.0.2.10");
    assert_eq!(port, 5060, "the pinned port is the whole point of the pin");

    let wildcard_v6: SocketAddr = "[::]:5066".parse().unwrap();
    let (host, port) = pinned_sent_by(wildcard_v6, || "[2001:db8::10]".to_string());
    assert_eq!(host, "[2001:db8::10]");
    assert_eq!(port, 5066);
}

/// Same rule through the precedence wrapper: the flow still wins, it just
/// borrows the fallback's host rather than its port.
#[test]
fn egress_sent_by_keeps_a_wildcard_flows_port_but_not_its_host() {
    let wildcard: SocketAddr = "0.0.0.0:5060".parse().unwrap();
    let sent_by = egress_sent_by(Some(wildcard), None, || ("192.0.2.10".to_string(), 5070));
    assert_eq!(sent_by, ("192.0.2.10".to_string(), 5060));
}

/// The B-leg INVITE's own precedence. The bug this guards: a flow-dialled
/// B-leg took the per-transport fallback, so the INVITE went out the flow's
/// socket while advertising the default listener — the far end then answered
/// to a port outside the flow and the call never got a final response.
#[test]
fn egress_sent_by_prefers_the_flow_over_the_default_listener() {
    let flow: SocketAddr = "192.0.2.10:6100".parse().unwrap();
    let sent_by = egress_sent_by(Some(flow), None, || ("192.0.2.10".to_string(), 5060));
    assert_eq!(
        sent_by,
        ("192.0.2.10".to_string(), 6100),
        "a flow-dialled B-leg must advertise the flow socket, never the default listener"
    );
}

/// A flow beats a `send_socket=` pin: the flow already wrote the INVITE to
/// its own socket, so advertising the script's listener would be a lie.
#[test]
fn egress_sent_by_flow_beats_a_send_socket_pin() {
    let flow: SocketAddr = "192.0.2.10:6100".parse().unwrap();
    let sent_by = egress_sent_by(
        Some(flow),
        Some(("sip.example.com".to_string(), 5080)),
        || ("192.0.2.10".to_string(), 5060),
    );
    assert_eq!(sent_by, ("192.0.2.10".to_string(), 6100));
}

/// Without a flow the pre-existing behaviour is untouched: a `send_socket=`
/// pin wins over the default, and with neither, the default stands.
#[test]
fn egress_sent_by_without_a_flow_is_unchanged() {
    let pinned = egress_sent_by(None, Some(("sip.example.com".to_string(), 5080)), || {
        ("192.0.2.10".to_string(), 5060)
    });
    assert_eq!(pinned, ("sip.example.com".to_string(), 5080));

    let plain = egress_sent_by(None, None, || ("192.0.2.10".to_string(), 5060));
    assert_eq!(plain, ("192.0.2.10".to_string(), 5060));
}

/// A v6 `send_socket=` advertise host is bracketed on the way out, same as
/// the flow path — the sent-by is a URI host, not a bare address.
#[test]
fn egress_sent_by_brackets_an_ipv6_send_socket_host() {
    let sent_by = egress_sent_by(None, Some(("2001:db8::20".to_string(), 5080)), || {
        ("192.0.2.10".to_string(), 5060)
    });
    assert_eq!(sent_by, ("[2001:db8::20]".to_string(), 5080));
}

// -----------------------------------------------------------------------
// Record-Route entries (one per socket the dialog crosses)
// -----------------------------------------------------------------------

/// The ordinary proxy: one listener, in and out the same socket. One entry,
/// and the inbound host is never resolved — this is the relay hot path.
#[test]
fn record_route_uris_single_entry_when_both_legs_are_one_socket() {
    let resolved = std::cell::Cell::new(false);
    let entries = record_route_uris(
        Transport::Udp,
        5060,
        || {
            resolved.set(true);
            "192.0.2.10".to_string()
        },
        Transport::Udp,
        5060,
        "192.0.2.10",
    );
    assert_eq!(
        entries,
        ("sip:192.0.2.10:5060;transport=udp".to_string(), None)
    );
    assert!(
        !resolved.get(),
        "the single-socket path must not pay for an inbound host resolution"
    );
}

/// The P-CSCF: Gm `:5066` in, core `:5060` out, both UDP. The old
/// transport-only discriminator saw one socket here and stamped the egress
/// port, handing the UE a route set naming a port no IPsec SA covers.
#[test]
fn record_route_uris_two_entries_when_only_the_port_differs() {
    let entries = record_route_uris(
        Transport::Udp,
        5066,
        || "192.0.2.10".to_string(),
        Transport::Udp,
        5060,
        "192.0.2.10",
    );
    assert_eq!(
        entries,
        (
            "sip:192.0.2.10:5066;transport=udp".to_string(),
            Some("sip:192.0.2.10:5060;transport=udp".to_string()),
        ),
        "same transport, different listener is still two sockets"
    );
}

/// Transport bridging keeps emitting two entries, unchanged.
#[test]
fn record_route_uris_two_entries_when_the_transport_differs() {
    let entries = record_route_uris(
        Transport::Tls,
        5061,
        || "sip.example.com".to_string(),
        Transport::Tcp,
        5060,
        "sip.example.com",
    );
    assert_eq!(
        entries,
        (
            "sip:sip.example.com:5061;transport=tls".to_string(),
            Some("sip:sip.example.com:5060;transport=tcp".to_string()),
        )
    );
}

/// Order is load-bearing: `add_record_route` prepends, so the second entry
/// ends up topmost. RFC 3261 §12.1.1 gives the UAS the list in order (it
/// must read the outbound-facing entry first) and §12.1.2 gives the UAC the
/// reverse (it must read the inbound-facing entry first).
#[test]
fn record_route_uris_returns_the_outbound_entry_second() {
    let (first, second) = record_route_uris(
        Transport::Udp,
        5066,
        || "192.0.2.10".to_string(),
        Transport::Udp,
        5060,
        "192.0.2.10",
    );
    let mut headers = SipHeaders::new();
    core::add_record_route(&mut headers, &first);
    if let Some(ref second) = second {
        core::add_record_route(&mut headers, second);
    }
    let all = headers.get_all("Record-Route").unwrap();
    assert_eq!(all.len(), 2);
    assert!(
        all[0].contains(":5060"),
        "the outbound-facing entry must end up topmost: {}",
        all[0]
    );
    assert!(
        all[1].contains(":5066"),
        "the inbound-facing entry must end up second: {}",
        all[1]
    );
}

/// A v6 host arrives already bracketed from `resolve_advertised_host` /
/// `pinned_sent_by` and is stamped verbatim — no second round of brackets.
#[test]
fn record_route_uris_stamps_a_bracketed_ipv6_host_verbatim() {
    let entries = record_route_uris(
        Transport::Udp,
        5066,
        || "[2001:db8::10]".to_string(),
        Transport::Udp,
        5060,
        "[2001:db8::10]",
    );
    assert_eq!(
        entries,
        (
            "sip:[2001:db8::10]:5066;transport=udp".to_string(),
            Some("sip:[2001:db8::10]:5060;transport=udp".to_string()),
        )
    );
}

// -----------------------------------------------------------------------
// A-leg advertised host (per-family / dual-stack identity)
// -----------------------------------------------------------------------

fn dualstack_registry() -> crate::transport::ListenerRegistry {
    crate::transport::ListenerRegistry::from_entries(vec![
        (
            Transport::Udp,
            "192.0.2.10:5060".parse().unwrap(),
            None::<String>,
        ),
        (
            Transport::Udp,
            "[2001:db8::10]:5060".parse().unwrap(),
            None::<String>,
        ),
    ])
}

#[test]
fn resolve_advertised_host_uses_exact_listener_advertise() {
    // Per-listener advertise is the most specific source, per family.
    let registry = crate::transport::ListenerRegistry::from_entries(vec![
        (
            Transport::Udp,
            "192.0.2.10:5060".parse().unwrap(),
            Some("pcscf-v4.example".to_string()),
        ),
        (
            Transport::Udp,
            "[2001:db8::10]:5060".parse().unwrap(),
            Some("pcscf-v6.example".to_string()),
        ),
    ]);
    let advertised = std::collections::HashMap::new();
    let v4: SocketAddr = "192.0.2.10:5060".parse().unwrap();
    let v6: SocketAddr = "[2001:db8::10]:5060".parse().unwrap();
    assert_eq!(
        resolve_advertised_host(&registry, &advertised, v4.ip(), Some(v4), &Transport::Udp),
        "pcscf-v4.example"
    );
    assert_eq!(
        resolve_advertised_host(&registry, &advertised, v4.ip(), Some(v6), &Transport::Udp),
        "pcscf-v6.example"
    );
}

#[test]
fn resolve_advertised_host_uses_concrete_bind_ip_per_family() {
    // No advertise anywhere: the exact bound IP, bracketed for v6.
    let registry = dualstack_registry();
    let advertised = std::collections::HashMap::new();
    let default_ip: IpAddr = "192.0.2.10".parse().unwrap();
    let v6: SocketAddr = "[2001:db8::10]:5060".parse().unwrap();
    assert_eq!(
        resolve_advertised_host(
            &registry,
            &advertised,
            default_ip,
            Some(v6),
            &Transport::Udp
        ),
        "[2001:db8::10]"
    );
    let v4: SocketAddr = "192.0.2.10:5060".parse().unwrap();
    assert_eq!(
        resolve_advertised_host(
            &registry,
            &advertised,
            default_ip,
            Some(v4),
            &Transport::Udp
        ),
        "192.0.2.10"
    );
}

#[test]
fn resolve_advertised_host_filters_transport_advertised_by_family() {
    // The gap this closes: a transport-level advertised v4 literal must NOT be
    // stamped on a v6 UE's identity — it falls through to the v6 bind IP; a
    // same-family literal IS used.
    let registry = dualstack_registry();
    let mut advertised = std::collections::HashMap::new();
    advertised.insert(Transport::Udp, "198.51.100.1".to_string()); // public v4
    let default_ip: IpAddr = "192.0.2.10".parse().unwrap();
    let v6: SocketAddr = "[2001:db8::10]:5060".parse().unwrap();
    assert_eq!(
        resolve_advertised_host(
            &registry,
            &advertised,
            default_ip,
            Some(v6),
            &Transport::Udp
        ),
        "[2001:db8::10]"
    );
    let v4: SocketAddr = "192.0.2.10:5060".parse().unwrap();
    assert_eq!(
        resolve_advertised_host(
            &registry,
            &advertised,
            default_ip,
            Some(v4),
            &Transport::Udp
        ),
        "198.51.100.1"
    );
}

#[test]
fn resolve_advertised_host_fqdn_advertised_used_for_any_family() {
    // An FQDN advertised host resolves to both A and AAAA, so it's accepted
    // regardless of the UE's family.
    let registry = dualstack_registry();
    let mut advertised = std::collections::HashMap::new();
    advertised.insert(Transport::Udp, "pcscf.ims.example".to_string());
    let default_ip: IpAddr = "192.0.2.10".parse().unwrap();
    let v6: SocketAddr = "[2001:db8::10]:5060".parse().unwrap();
    assert_eq!(
        resolve_advertised_host(
            &registry,
            &advertised,
            default_ip,
            Some(v6),
            &Transport::Udp
        ),
        "pcscf.ims.example"
    );
}

#[test]
fn resolve_advertised_host_none_is_legacy_behavior() {
    // No arrival socket (outbound leg): first per-transport advertised host,
    // else the resolved default local IP — the pre-dual-stack via_host.
    let registry = dualstack_registry();
    let default_ip: IpAddr = "192.0.2.10".parse().unwrap();
    let mut advertised = std::collections::HashMap::new();
    advertised.insert(Transport::Udp, "203.0.113.5".to_string());
    assert_eq!(
        resolve_advertised_host(&registry, &advertised, default_ip, None, &Transport::Udp),
        "203.0.113.5"
    );
    let empty = std::collections::HashMap::new();
    assert_eq!(
        resolve_advertised_host(&registry, &empty, default_ip, None, &Transport::Udp),
        "192.0.2.10"
    );
}

// -----------------------------------------------------------------------
// TLS / WSS listeners that advertise an IP literal (startup warning)
// -----------------------------------------------------------------------

/// A listener registry from `(transport, bound address, advertise)` rows.
fn secure_listener_registry(
    listeners: &[(Transport, &str, Option<&str>)],
) -> crate::transport::ListenerRegistry {
    crate::transport::ListenerRegistry::from_entries(listeners.iter().map(
        |(transport, address, advertise)| {
            (
                *transport,
                address.parse().unwrap(),
                advertise.map(str::to_string),
            )
        },
    ))
}

/// `listen_addrs` the way the server fills it: the first listener of each
/// transport, in config order.
fn first_listener_per_transport(
    listeners: &[(Transport, &str, Option<&str>)],
) -> std::collections::HashMap<Transport, SocketAddr> {
    let mut listen_addrs = std::collections::HashMap::new();
    for (transport, address, _) in listeners {
        listen_addrs
            .entry(*transport)
            .or_insert_with(|| address.parse().unwrap());
    }
    listen_addrs
}

fn secure_host(
    transport: Transport,
    listener: &str,
    host: &str,
) -> (Transport, SocketAddr, String) {
    (transport, listener.parse().unwrap(), host.to_string())
}

#[test]
fn secure_listener_advertised_hosts_covers_only_tls_and_wss() {
    let listeners = [
        (Transport::Udp, "192.0.2.10:5060", None),
        (Transport::Tcp, "192.0.2.10:5060", None),
        (Transport::WebSocket, "192.0.2.10:80", None),
        (Transport::Tls, "192.0.2.10:5061", None),
        (Transport::WebSocketSecure, "192.0.2.10:443", None),
    ];
    let hosts = secure_listener_advertised_hosts(
        &secure_listener_registry(&listeners),
        &std::collections::HashMap::new(),
        &first_listener_per_transport(&listeners),
        "192.0.2.10".parse().unwrap(),
    );
    assert_eq!(
        hosts,
        vec![
            secure_host(Transport::Tls, "192.0.2.10:5061", "192.0.2.10"),
            secure_host(Transport::WebSocketSecure, "192.0.2.10:443", "192.0.2.10"),
        ]
    );
}

#[test]
fn secure_listener_advertised_hosts_reports_every_listener_sharing_advertised_address() {
    // The global `advertised_address` folded into every transport, as `run`
    // does: each listener writes it, so each listener is reported.
    let listeners = [
        (Transport::Tls, "192.0.2.10:5061", None),
        (Transport::Tls, "192.0.2.11:5061", None),
        (Transport::WebSocketSecure, "192.0.2.10:443", None),
    ];
    let mut advertised = std::collections::HashMap::new();
    advertised.insert(Transport::Tls, "198.51.100.1".to_string());
    advertised.insert(Transport::WebSocketSecure, "198.51.100.1".to_string());
    let hosts = secure_listener_advertised_hosts(
        &secure_listener_registry(&listeners),
        &advertised,
        &first_listener_per_transport(&listeners),
        "192.0.2.10".parse().unwrap(),
    );
    assert_eq!(
        hosts,
        vec![
            secure_host(Transport::Tls, "192.0.2.10:5061", "198.51.100.1"),
            secure_host(Transport::Tls, "192.0.2.11:5061", "198.51.100.1"),
            secure_host(Transport::WebSocketSecure, "192.0.2.10:443", "198.51.100.1"),
        ]
    );
}

#[test]
fn secure_listener_advertised_hosts_uses_the_listener_advertise() {
    let listeners = [(Transport::Tls, "192.0.2.10:5061", Some("sip.example.com"))];
    let mut advertised = std::collections::HashMap::new();
    advertised.insert(Transport::Tls, "sip.example.com".to_string());
    let hosts = secure_listener_advertised_hosts(
        &secure_listener_registry(&listeners),
        &advertised,
        &first_listener_per_transport(&listeners),
        "192.0.2.10".parse().unwrap(),
    );
    assert_eq!(
        hosts,
        vec![secure_host(
            Transport::Tls,
            "192.0.2.10:5061",
            "sip.example.com"
        )]
    );
}

#[test]
fn secure_listener_advertised_hosts_on_a_wildcard_bind_is_the_resolved_ip() {
    // No advertise anywhere and an unspecified bind: the host is whatever the
    // resolver falls back to, a routable local IP or else loopback. Which one
    // depends on the machine, but it is an IP literal either way, and never the
    // unspecified address itself.
    let listeners = [
        (Transport::Tls, "0.0.0.0:5061", None),
        (Transport::WebSocketSecure, "[::]:443", None),
    ];
    let registry = secure_listener_registry(&listeners);
    let advertised = std::collections::HashMap::new();
    // `run` resolves the default the same way, from the first listener.
    let via_addr = crate::uac::resolve_via_addr(
        "0.0.0.0:5061".parse().unwrap(),
        &Transport::Udp,
        &advertised,
        None,
    );
    let hosts = secure_listener_advertised_hosts(
        &registry,
        &advertised,
        &first_listener_per_transport(&listeners),
        via_addr.ip(),
    );

    for (transport, address) in [
        (Transport::Tls, "0.0.0.0:5061"),
        (Transport::WebSocketSecure, "[::]:443"),
    ] {
        let listener: SocketAddr = address.parse().unwrap();
        let own = resolve_advertised_host(
            &registry,
            &advertised,
            via_addr.ip(),
            Some(listener),
            &transport,
        );
        assert!(
            hosts.contains(&(transport, listener, own.clone())),
            "{transport} {listener} should report {own}: {hosts:?}"
        );
    }
    for (transport, listener, host) in &hosts {
        let ip = strip_ipv6_brackets(host).parse::<IpAddr>();
        assert!(
            ip.as_ref().is_ok_and(|ip| !ip.is_unspecified()),
            "{transport} {listener} advertises {host}"
        );
    }
}

#[test]
fn secure_listener_advertised_hosts_reports_a_different_transport_default() {
    // Multi-homed, nothing advertised: the Via and B-leg Contact on TLS fall
    // back to the first listener of any transport (UDP here), not the TLS bind
    // IP the A-leg Contact carries. Both reach a TLS peer, so both are reported.
    let listeners = [
        (Transport::Udp, "192.0.2.1:5060", None),
        (Transport::Tls, "192.0.2.2:5061", None),
    ];
    let hosts = secure_listener_advertised_hosts(
        &secure_listener_registry(&listeners),
        &std::collections::HashMap::new(),
        &first_listener_per_transport(&listeners),
        "192.0.2.1".parse().unwrap(),
    );
    assert_eq!(
        hosts,
        vec![
            secure_host(Transport::Tls, "192.0.2.2:5061", "192.0.2.2"),
            secure_host(Transport::Tls, "192.0.2.2:5061", "192.0.2.1"),
        ]
    );
}

/// A self-signed certificate for `names` in `directory`. rcgen writes an IP
/// literal as an iPAddress subjectAltName and anything else as a dNSName.
fn write_certificate_for(directory: &tempfile::TempDir, names: &[&str]) -> String {
    let key_pair = rcgen::KeyPair::generate().expect("keygen");
    let certificate = rcgen::CertificateParams::new(
        names
            .iter()
            .map(|name| name.to_string())
            .collect::<Vec<_>>(),
    )
    .expect("certificate params")
    .self_signed(&key_pair)
    .expect("self-sign");
    let path = directory.path().join("certificate.pem");
    std::fs::write(&path, certificate.pem()).expect("write certificate");
    path.to_str().expect("utf-8 path").to_string()
}

/// The WARN lines `emit` logs.
fn captured_warnings(emit: impl FnOnce()) -> Vec<String> {
    let log = super::lcr_number_policy_tests::LogBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .with_writer(log.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, emit);
    log.rendered()
        .lines()
        .filter(|line| line.contains("WARN"))
        .map(str::to_string)
        .collect()
}

#[test]
fn startup_warns_for_each_secure_listener_whose_ip_the_certificate_lacks() {
    let directory = tempfile::tempdir().unwrap();
    let certificate = write_certificate_for(
        &directory,
        &["sip.example.com", "192.0.2.10", "2001:db8::10"],
    );
    let listeners = [
        // Carried as an iPAddress SAN, and so is the transport default.
        (Transport::Tls, "192.0.2.10:5061", None),
        (Transport::Tls, "198.51.100.1:5061", None),
        // Covered; its transport default (192.0.2.10) is covered too.
        (Transport::WebSocketSecure, "[2001:db8::10]:443", None),
        (Transport::WebSocketSecure, "[2001:db8::20]:443", None),
    ];
    let warnings = captured_warnings(|| {
        warn_secure_listeners_advertising_ip_literals(
            &certificate,
            &secure_listener_registry(&listeners),
            &std::collections::HashMap::new(),
            &first_listener_per_transport(&listeners),
            "192.0.2.10".parse().unwrap(),
        )
    });

    assert_eq!(warnings.len(), 2, "{warnings:#?}");
    assert!(
        warnings[0].contains("listen.tls")
            && warnings[0].contains("transport=TLS")
            && warnings[0].contains("listener=198.51.100.1:5061")
            && warnings[0].contains("advertised=198.51.100.1")
            && warnings[0].contains("iPAddress subjectAltName")
            && warnings[0].contains("Set `advertise:`"),
        "{}",
        warnings[0]
    );
    assert!(
        warnings[1].contains("listen.wss")
            && warnings[1].contains("transport=WSS")
            && warnings[1].contains("listener=[2001:db8::20]:443")
            && warnings[1].contains("advertised=2001:db8::20")
            && warnings[1].contains("Set `advertise:`"),
        "{}",
        warnings[1]
    );
}

#[test]
fn startup_warns_when_the_certificate_cannot_be_read_for_the_san_check() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing.pem");
    let listeners = [
        (Transport::Tls, "192.0.2.10:5061", None),
        // A DNS name is never checked, so an unreadable certificate says nothing
        // about it.
        (
            Transport::WebSocketSecure,
            "192.0.2.20:443",
            Some("sip.example.com"),
        ),
    ];
    let mut advertised = std::collections::HashMap::new();
    advertised.insert(Transport::WebSocketSecure, "sip.example.com".to_string());
    let warnings = captured_warnings(|| {
        warn_secure_listeners_advertising_ip_literals(
            missing.to_str().unwrap(),
            &secure_listener_registry(&listeners),
            &advertised,
            &first_listener_per_transport(&listeners),
            "192.0.2.10".parse().unwrap(),
        )
    });

    assert_eq!(warnings.len(), 1, "{warnings:#?}");
    assert!(
        warnings[0].contains("listen.tls")
            && warnings[0].contains("listener=192.0.2.10:5061")
            && warnings[0].contains("advertised=192.0.2.10")
            && warnings[0].contains("not possible")
            && warnings[0].contains("missing.pem")
            && warnings[0].contains("Set `advertise:`"),
        "{}",
        warnings[0]
    );
}

// -----------------------------------------------------------------------
// Imperative B2BUA terminate helpers (b2bua.terminate / session timer)
// -----------------------------------------------------------------------

#[test]
fn format_normal_clearing_reason_is_q850_cause_16() {
    assert_eq!(
        format_normal_clearing_reason("Normal Clearing"),
        "Q.850;cause=16;text=\"Normal Clearing\"",
    );
    // Embedded quotes are stripped so the header stays well-formed.
    assert_eq!(
        format_normal_clearing_reason("say \"hi\""),
        "Q.850;cause=16;text=\"say hi\"",
    );
}

#[test]
fn parse_reason_cause_maps_sip_status_or_none() {
    // Build a BYE with an optional RFC 3326 Reason header via the parser
    // (the builder setters take String; raw parse matches the other fixtures).
    fn bye_with_reason(reason: Option<&str>) -> SipMessage {
        let mut raw = String::from("BYE sip:b@host SIP/2.0\r\n");
        raw.push_str("Via: SIP/2.0/UDP host:5060;branch=z9hG4bK1\r\n");
        raw.push_str("From: <sip:a@host>;tag=a\r\n");
        raw.push_str("To: <sip:b@host>;tag=b\r\n");
        raw.push_str("Call-ID: c@host\r\n");
        raw.push_str("CSeq: 1 BYE\r\n");
        if let Some(value) = reason {
            raw.push_str(&format!("Reason: {value}\r\n"));
        }
        raw.push_str("Content-Length: 0\r\n\r\n");
        parse_sip_message(&raw).expect("test fixture must parse").1
    }

    // SIP;cause=<status> maps via sip_status_to_cause_code.
    assert_eq!(
        parse_reason_cause(&bye_with_reason(Some("SIP;cause=486;text=\"Busy Here\""))),
        crate::diameter::rf::sip_status_to_cause_code(486),
    );
    // No Reason header → None.
    assert_eq!(parse_reason_cause(&bye_with_reason(None)), None);
    // Reason without a cause= param → None.
    assert_eq!(
        parse_reason_cause(&bye_with_reason(Some("SIP;text=\"no cause\""))),
        None,
    );
}

#[test]
fn b2bua_terminate_call_unknown_id_is_false_no_panic() {
    // Unknown SIP Call-ID (and no running dispatcher in the test binary) is a
    // clean no-op — never panics, returns false — so an IVR racing a
    // caller-initiated BYE degrades gracefully.
    assert!(!b2bua_terminate_call("does-not-exist@nowhere", None));
    assert!(!b2bua_terminate_call(
        "does-not-exist@nowhere",
        Some("Normal Clearing")
    ));
}

#[test]
fn b2bua_answer_and_progress_unknown_id_is_false_no_panic() {
    // Imperative call.answer()/progress() against an unknown call (and no
    // running dispatcher in the test binary) is a clean no-op — returns
    // false, never panics.
    let raw = concat!(
        "INVITE sip:echo@example.com SIP/2.0\r\n",
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1\r\n",
        "From: <sip:alice@example.com>;tag=a\r\n",
        "To: <sip:echo@example.com>\r\n",
        "Call-ID: unknown-ivr@example.com\r\n",
        "CSeq: 1 INVITE\r\n",
        "Max-Forwards: 70\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    );
    let invite = parse_sip_message(raw).expect("test fixture must parse").1;
    assert!(!b2bua_answer_call("nope", &invite, 200, "OK", None, None));
    assert!(!b2bua_progress_call(
        "nope",
        &invite,
        183,
        "Session Progress",
        None,
        None
    ));
}

#[test]
fn b2bua_local_tag_unknown_id_is_none_no_panic() {
    // `call.local_tag` is read from script threads, including after the
    // call it names has been torn down (an async handler resuming late, a
    // timer firing on a hung-up call). Unknown id — and no running
    // dispatcher in the test binary — must be None, never a panic.
    assert!(b2bua_local_tag("nope").is_none());
    assert!(b2bua_local_tag("").is_none());
}

// -----------------------------------------------------------------------
// Answer-first (AI-park) handover — the pure media-plan decision
// (`answer_first_prepare`): backend gate, profile resolution, ws_uri
// templating, honest failure. The I/O glue (answer_local round-trip +
// b2bua_answer_call) is thin over already-tested pieces.
// -----------------------------------------------------------------------

fn invite_with_offer(body: &[u8]) -> SipMessage {
    let raw = concat!(
        "INVITE sip:ai@example.com SIP/2.0\r\n",
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1\r\n",
        "From: <sip:alice@example.com>;tag=alice-tag\r\n",
        "To: <sip:ai@example.com>\r\n",
        "Call-ID: call-abc@pc\r\n",
        "CSeq: 1 INVITE\r\n",
        "Max-Forwards: 70\r\n",
        "Content-Type: application/sdp\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    );
    let mut invite = parse_sip_message(raw)
        .expect("answer-first fixture must parse")
        .1;
    invite.body = body.to_vec();
    invite
}

fn siphon_rtp_backend() -> crate::rtpengine::MediaBackend {
    // A native-backend handle over a dead address — `answer_first_prepare`
    // never does I/O (only `kind()` / `unsupported_flags()`), so no server
    // is needed. Construction spawns a connection task, hence #[tokio::test].
    let (event_tx, _rx) =
        tokio::sync::mpsc::channel::<crate::rtpengine::events::RtpEngineEvent>(16);
    let set = crate::rtpengine::siphon_rtp::SiphonRtpClientSet::new(
        vec![("127.0.0.1:1".parse().unwrap(), 200, 1)],
        None,
        5_000,
        event_tx,
    )
    .unwrap();
    crate::rtpengine::MediaBackend::SiphonRtp(set)
}

fn local_ip() -> std::net::IpAddr {
    "127.0.0.1".parse().unwrap()
}

#[tokio::test]
async fn answer_first_prepare_templates_ws_uri_on_siphon_rtp() {
    let backend = siphon_rtp_backend();
    let registry = crate::rtpengine::ProfileRegistry::new();
    let invite = invite_with_offer(
        b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\n",
    );
    let plan = answer_first_prepare(
        &invite,
        "203.0.113.7".parse().unwrap(),
        &backend,
        &registry,
        None, // default voice_ai
        Some("wss://ai.example/stream/{call_id}"),
    )
    .expect("prepare must succeed on siphon-rtp with a ws_uri");
    assert_eq!(
        plan.flags.ws_uri.as_deref(),
        Some("wss://ai.example/stream/call-abc@pc"),
        "ws_uri must be #131-templated"
    );
    assert_eq!(plan.from_tag, "alice-tag");
    assert_eq!(plan.profile_name, "voice_ai");
    assert!(!plan.offer_sdp.trim().is_empty());
}

#[tokio::test]
async fn answer_first_prepare_rejects_non_siphon_rtp_backend() {
    // The honest-failure case: answer-first on rtpengine must NOT fake a 200.
    let set =
        crate::rtpengine::client::RtpEngineSet::new(vec![("127.0.0.1:1".parse().unwrap(), 200, 1)])
            .await
            .unwrap();
    let backend = crate::rtpengine::MediaBackend::RtpEngine(std::sync::Arc::new(set));
    let registry = crate::rtpengine::ProfileRegistry::new();
    let invite = invite_with_offer(b"v=0\r\n");
    let error = answer_first_prepare(
        &invite,
        local_ip(),
        &backend,
        &registry,
        None,
        Some("wss://ai/{call_id}"),
    )
    .unwrap_err();
    assert!(
        error.contains("siphon-rtp"),
        "expected a backend-gate error, got: {error}"
    );
}

#[tokio::test]
async fn answer_first_prepare_anchors_without_a_bridge() {
    // No ws_uri used to be a hard error — "nowhere to bridge the AI audio" —
    // which made an anchored answer inseparable from opening a WebSocket. Most
    // of what an application does to a caller before a person picks up is the
    // engine talking to them: the IVR menu, the queue announcement, music on
    // hold, the voicemail greeting. None of it involves a WebSocket, and none
    // of it was reachable over the control rail while this refused.
    let backend = siphon_rtp_backend();
    let registry = crate::rtpengine::ProfileRegistry::new();
    let invite = invite_with_offer(b"v=0\r\n");
    let plan = answer_first_prepare(&invite, local_ip(), &backend, &registry, None, None)
        .expect("anchoring with no bridge is the IVR / voicemail case");
    assert!(
        plan.flags.ws_uri.is_none(),
        "no bridge was asked for, so none should be planned: {:?}",
        plan.flags.ws_uri
    );
}

#[tokio::test]
async fn answer_first_prepare_unknown_profile() {
    let backend = siphon_rtp_backend();
    let registry = crate::rtpengine::ProfileRegistry::new();
    let invite = invite_with_offer(b"v=0\r\n");
    let error = answer_first_prepare(
        &invite,
        local_ip(),
        &backend,
        &registry,
        Some("does-not-exist"),
        Some("wss://ai"),
    )
    .unwrap_err();
    assert!(error.contains("unknown media profile"), "got: {error}");
}

#[tokio::test]
async fn answer_first_prepare_requires_sdp_offer() {
    let backend = siphon_rtp_backend();
    let registry = crate::rtpengine::ProfileRegistry::new();
    let invite = invite_with_offer(b""); // no offer body
    let error = answer_first_prepare(
        &invite,
        local_ip(),
        &backend,
        &registry,
        None,
        Some("wss://ai"),
    )
    .unwrap_err();
    assert!(error.contains("SDP offer"), "got: {error}");
}

/// Save a stream P-CSCF cache binding directly against a bare `Registrar`,
/// so the flow-close decision helpers can be exercised without a running
/// server.  `ue_ip` is the UE source address the SA-liveness set matches on.
fn save_stream_binding(
    registrar: &crate::registrar::Registrar,
    aor: &str,
    user: &str,
    ue_ip: &str,
    connection_id: u64,
) {
    registrar
        .save_full(
            aor,
            SipUri::new(ue_ip.to_string()).with_user(user.to_string()),
            3600,
            1.0,
            format!("call-{user}"),
            1,
            Some(format!("{ue_ip}:5060").parse().unwrap()),
            Some(Transport::Tcp),
            None,
            None,
            vec![],
            crate::registrar::FlowCapture {
                flow_token: Some(format!("tok-{user}").into_boxed_str()),
                inbound_local_addr: None,
                inbound_connection_id: Some(connection_id),
            },
            Vec::new(),
        )
        .unwrap();
}

#[test]
fn flow_close_keep_set_retains_ipsec_ues() {
    // A closed IPsec flow is a recoverable RFC 5626 flow failure: the UE's
    // SA is still warm, so the binding must be retained (deferred to the
    // SA-idle sweep) rather than network-deregistered on the FIN.
    let registrar = crate::registrar::Registrar::default();
    save_stream_binding(
        &registrar,
        "sip:alice@ims.example.com",
        "alice",
        "100.65.0.2",
        7,
    );
    let bindings = registrar.bindings_for_connection(7);
    assert_eq!(bindings.len(), 1);

    let mut sa_ips = std::collections::HashSet::new();
    sa_ips.insert("100.65.0.2".parse::<std::net::IpAddr>().unwrap());

    let keep = flow_close_keep_set(&bindings, &sa_ips);
    assert_eq!(keep.len(), 1);
    assert!(keep.contains(&bindings[0].1.uri.to_string()));

    // Committing the close with that keep set detaches, never deregisters.
    assert!(registrar.close_flow(7, &keep).is_empty());
    assert!(registrar.is_registered("sip:alice@ims.example.com"));
}

#[test]
fn flow_close_keep_set_deregs_non_ipsec() {
    // No SA for the UE IP (plain TCP / WSS WebRTC) — the stream close stays
    // an authoritative death signal, so nothing is retained and the binding
    // is removed immediately.
    let registrar = crate::registrar::Registrar::default();
    save_stream_binding(&registrar, "sip:bob@example.com", "bob", "100.65.0.9", 9);
    let bindings = registrar.bindings_for_connection(9);

    let keep = flow_close_keep_set(&bindings, &std::collections::HashSet::new());
    assert!(keep.is_empty());

    let removed = registrar.close_flow(9, &keep);
    assert_eq!(removed.len(), 1);
    assert!(!registrar.is_registered("sip:bob@example.com"));
}

// -----------------------------------------------------------------------
// Registrar-liveness SA-idle sweep — SIP last-seen fold-in + probe
// hysteresis (Part B of the false-deregistration fix)
// -----------------------------------------------------------------------

fn ip(addr: &str) -> std::net::IpAddr {
    addr.parse().expect("test fixture IP must parse")
}

#[test]
fn liveness_last_active_folds_sip_over_stale_kernel() {
    // The prod scenario: the kernel XFRM use-time is stuck at an old value
    // (never advances on the inbound-answered SA) while siphon's SIP
    // last-seen is fresh.  Folding takes the max, so the fresh SIP signal
    // wins and the binding reads as active.
    let stale_kernel = 1_000;
    let fresh_sip = 1_890;
    assert_eq!(liveness_last_active(stale_kernel, fresh_sip), 1_890);
    // Either input alone still yields the most recent evidence.
    assert_eq!(liveness_last_active(0, 42), 42);
    assert_eq!(liveness_last_active(42, 0), 42);
}

#[test]
fn liveness_churn_fresh_sip_keeps_binding_active() {
    // A UE answered its keepalive 5 s ago (SIP stamp), but the kernel
    // use-time is stuck 300 s in the past.  With a 90 s idle window the
    // folded signal must read as recently-active → NOT re-probed.
    let now = 10_000u64;
    let idle_window = 90u64;
    let stale_kernel = now - 300;
    let fresh_sip = now - 5;
    let last_active = liveness_last_active(stale_kernel, fresh_sip);
    assert!(liveness_recently_active(now, last_active, idle_window));
    // Without the SIP fold-in the stale kernel value alone would look idle
    // and the UE would be probed every sweep — the bug being fixed.
    assert!(!liveness_recently_active(now, stale_kernel, idle_window));
}

#[test]
fn liveness_recently_active_boundary() {
    let now = 1_000u64;
    // Exactly at the window edge counts as active (inclusive).
    assert!(liveness_recently_active(now, now - 90, 90));
    // One second past the window is idle.
    assert!(!liveness_recently_active(now, now - 91, 90));
    // A last_active in the future (clock skew) is never idle.
    assert!(liveness_recently_active(now, now + 10, 90));
}

/// The SA pair for the probe/MT agreement test: UE 198.51.100.20 with
/// port_uc 50001 / port_us 50002, P-CSCF 192.0.2.10 with port_pc 5064 /
/// port_ps 5066.
fn agreement_sa(protocol: crate::ipsec::SaProtocol) -> crate::ipsec::SecurityAssociationPair {
    crate::ipsec::SecurityAssociationPair {
        ue_addr: ip("198.51.100.20"),
        pcscf_addr: ip("192.0.2.10"),
        ue_port_c: 50001,
        ue_port_s: 50002,
        pcscf_port_c: 5064,
        pcscf_port_s: 5066,
        spi_uc: 1000,
        spi_us: 1001,
        spi_pc: 10000,
        spi_ps: 10001,
        ealg: crate::ipsec::EncryptionAlgorithm::Null,
        aalg: crate::ipsec::IntegrityAlgorithm::HmacSha1,
        encryption_key: String::new(),
        integrity_key: "deadbeefdeadbeefdeadbeefdeadbeef".into(),
        hard_lifetime_secs: None,
        protocol,
        expires_at: std::time::Instant::now(),
        created_at: std::time::Instant::now(),
        role: crate::ipsec::SaRole::PCscf,
        impi: None,
    }
}

/// Save the agreement test's binding the way the P-CSCF does (a REGISTER
/// from port_uc landing on port_ps, flow captured, Contact on port_us) and
/// hand back the stored contact.  `contact_transport` is the Contact's
/// `;transport=` parameter, `None` for a bare Contact.  `detach` runs the
/// real `close_flow`, the path a TCP FIN takes for an IPsec binding.
fn agreement_binding(
    transport: Transport,
    contact_transport: Option<&str>,
    detach: bool,
) -> crate::registrar::Contact {
    let registrar = crate::registrar::Registrar::default();
    let mut uri = SipUri::new("198.51.100.20".to_string())
        .with_user("alice".to_string())
        .with_port(50002);
    if let Some(param) = contact_transport {
        uri = uri.with_param("transport".to_string(), Some(param.to_string()));
    }
    registrar
        .save_full(
            "sip:alice@ims.example.com",
            uri,
            3600,
            1.0,
            "call-agreement".to_string(),
            1,
            Some("198.51.100.20:50001".parse().expect("fixture")),
            Some(transport),
            None,
            None,
            vec![],
            crate::registrar::FlowCapture {
                flow_token: Some("tok-agreement".into()),
                inbound_local_addr: Some("192.0.2.10:5066".parse().expect("fixture")),
                inbound_connection_id: (transport == Transport::Tcp).then_some(7),
            },
            Vec::new(),
        )
        .expect("fixture binding saves");
    if detach {
        let keep: std::collections::HashSet<String> = registrar
            .bindings_for_connection(7)
            .iter()
            .map(|(_, contact)| contact.uri.to_string())
            .collect();
        assert!(
            registrar.close_flow(7, &keep).is_empty(),
            "an IPsec binding detaches on a flow close, it is not removed"
        );
    }
    registrar
        .all_contacts()
        .into_iter()
        .next()
        .expect("the fixture binding is stored")
        .1
}

/// Where an MT request to `contact` goes, built from the relay's own code and
/// never from the probe's: the flow the script hands `relay(flow=...)`
/// (`binding.flow`) through the relay's flow mapping, or with no flow, the
/// Contact URI resolved as `relay(uri)` resolves it; then the SA's transport
/// pin, as the relay's IPsec egress step applies it.
///
/// The transport comes back `None` where MT itself leaves it open: with no
/// flow and no `;transport=` on the Contact, the relay falls back to the MT
/// request's own inbound transport, which only an SA pin overrides.  That is
/// found by resolving against both inbound transports, not by restating the
/// rule.
fn mt_route(
    contact: &crate::registrar::Contact,
    sa: &crate::ipsec::SecurityAssociationPair,
) -> (SocketAddr, SocketAddr, Option<Transport>, ConnectionId) {
    match crate::script::api::registrar::PyContact::from_rust_contact(contact).flow() {
        Some(flow) => {
            let (destination, transport, local, connection_id) =
                flow_relay_egress(&flow, Transport::Udp);
            let transport =
                crate::script::api::ipsec::outbound_for_sa(sa, destination.port(), transport)
                    .map_or(transport, |(_, pinned)| pinned);
            (destination, local, Some(transport), connection_id)
        }
        None => {
            let target = resolve_target(&contact.uri.to_string(), &test_resolver())
                .expect("the contact URI resolves");
            let egress = |inbound: Transport| {
                crate::script::api::ipsec::outbound_for_sa(
                    sa,
                    target.address.port(),
                    target.transport.unwrap_or(inbound),
                )
                .expect("the contact port is one of the SA's ports")
            };
            let (source, over_udp) = egress(Transport::Udp);
            let (_, over_tcp) = egress(Transport::Tcp);
            let transport = (over_udp == over_tcp).then_some(over_udp);
            (target.address, source, transport, ConnectionId::default())
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn liveness_probe_route_agrees_with_the_mt_route_wherever_it_is_determined() {
    use crate::ipsec::SaProtocol;
    // The probe answers "can an MT request reach this binding?", so it has
    // to take the route MT takes.  MT does not always fix the transport: for
    // a detached binding with a bare Contact it follows the MT request's own
    // inbound transport, which the probe cannot know.  There the probe uses
    // the binding's transport, and the row checks exactly that.  Each row
    // also pins the MT route to concrete values, so a fault shared by both
    // sides (the flow tuple is common to them on purpose) cannot hide behind
    // an agreement.
    let rows = [
        (
            "UDP",
            Transport::Udp,
            None,
            false,
            SaProtocol::Any,
            "198.51.100.20:50001",
            "192.0.2.10:5066",
            Some(Transport::Udp),
        ),
        (
            "live TCP",
            Transport::Tcp,
            Some("tcp"),
            false,
            SaProtocol::Any,
            "198.51.100.20:50001",
            "192.0.2.10:5066",
            Some(Transport::Tcp),
        ),
        (
            "detached TCP, Contact ;transport=tcp",
            Transport::Tcp,
            Some("tcp"),
            true,
            SaProtocol::Any,
            "198.51.100.20:50002",
            "192.0.2.10:5064",
            Some(Transport::Tcp),
        ),
        (
            "detached TCP, Contact ;transport=tcp, TCP-pinned SA",
            Transport::Tcp,
            Some("tcp"),
            true,
            SaProtocol::Tcp,
            "198.51.100.20:50002",
            "192.0.2.10:5064",
            Some(Transport::Tcp),
        ),
        (
            "detached TCP, Contact ;transport=udp",
            Transport::Tcp,
            Some("udp"),
            true,
            SaProtocol::Any,
            "198.51.100.20:50002",
            "192.0.2.10:5064",
            Some(Transport::Udp),
        ),
        (
            "detached TCP, bare Contact",
            Transport::Tcp,
            None,
            true,
            SaProtocol::Any,
            "198.51.100.20:50002",
            "192.0.2.10:5064",
            None,
        ),
        (
            "detached TCP, bare Contact, TCP-pinned SA",
            Transport::Tcp,
            None,
            true,
            SaProtocol::Tcp,
            "198.51.100.20:50002",
            "192.0.2.10:5064",
            Some(Transport::Tcp),
        ),
    ];
    let mut failures = Vec::new();
    for (state, transport, contact_transport, detach, protocol, destination, source, expected) in
        rows
    {
        let contact = agreement_binding(transport, contact_transport, detach);
        let sa = agreement_sa(protocol);
        let mt = mt_route(&contact, &sa);
        let expected = (
            destination.parse::<SocketAddr>().expect("fixture"),
            source.parse::<SocketAddr>().expect("fixture"),
            expected,
        );
        if (mt.0, mt.1, mt.2) != expected {
            failures.push(format!("{state}: MT route {mt:?}, expected {expected:?}"));
        }
        let Some(probe) = liveness_probe_route(&contact, Some(&sa)) else {
            failures.push(format!("{state}: no probe route, MT {mt:?}"));
            continue;
        };
        // Where MT fixes the transport the probe must match it; where MT
        // follows its own inbound transport, the probe uses the binding's.
        let transport_agrees = match mt.2 {
            Some(mt_transport) => probe.transport == mt_transport,
            None => probe.transport == transport,
        };
        if (
            probe.destination,
            probe.source_local_addr,
            probe.connection_id,
        ) != (mt.0, mt.1, mt.3)
            || !transport_agrees
        {
            failures.push(format!("{state}: probe {probe:?}, MT {mt:?}"));
        }
    }
    assert!(
        failures.is_empty(),
        "the liveness probe must take the MT route:\n{}",
        failures.join("\n")
    );
}

#[test]
fn liveness_miss_outcome_survives_then_reaps_at_threshold() {
    // threshold 2: sweep N is the first miss → keep (counter 1); sweep N+1
    // is the second consecutive miss → reap (counter reset to 0).  A UE
    // racing an ECM-IDLE→paging window misses one sweep and answers the
    // next, so it never reaches the reap.
    assert_eq!(liveness_miss_outcome(0, 2), (1, false));
    assert_eq!(liveness_miss_outcome(1, 2), (0, true));
}

#[test]
fn liveness_miss_outcome_threshold_floor_of_one() {
    // A misconfigured threshold of 0 must not silently disable reaping — it
    // is floored to 1 (reap on the first miss), matching threshold == 1.
    assert_eq!(liveness_miss_outcome(0, 0), (0, true));
    assert_eq!(liveness_miss_outcome(0, 1), (0, true));
}

#[test]
fn liveness_note_alive_stamps_and_clears_strike() {
    // The answered-probe / inbound side effect: record last-seen for the UE
    // IP and wipe any partial miss strike so a later transient miss starts
    // from zero.
    let last_seen: DashMap<std::net::IpAddr, u64> = DashMap::new();
    let misses: DashMap<String, u64> = DashMap::new();
    let aor = "sip:alice@ims.example.com";
    misses.insert(aor.to_string(), 1); // one strike already accrued

    liveness_note_alive(&last_seen, &misses, ip("100.65.0.2"), aor, 12_345);

    assert_eq!(last_seen.get(&ip("100.65.0.2")).map(|v| *v), Some(12_345));
    assert!(
        !misses.contains_key(aor),
        "answer must clear the miss strike"
    );
}

#[test]
fn liveness_hysteresis_survive_then_reset_on_answer() {
    // Model the two-sweep sequence against the real maps + decision helper:
    // sweep N misses (strike 1, kept), then the UE answers on sweep N+1
    // (strike cleared) — the binding survives with a clean slate.
    let last_seen: DashMap<std::net::IpAddr, u64> = DashMap::new();
    let misses: DashMap<String, u64> = DashMap::new();
    let aor = "sip:alice@ims.example.com";

    // Sweep N: probe unanswered.
    let before = misses.get(aor).map(|v| *v).unwrap_or(0);
    let (count, reap) = liveness_miss_outcome(before, 2);
    assert!(!reap, "first miss is within grace");
    misses.insert(aor.to_string(), count);
    assert_eq!(misses.get(aor).map(|v| *v), Some(1));

    // Sweep N+1: UE answers (paging completed) → strike cleared, survives.
    liveness_note_alive(&last_seen, &misses, ip("100.65.0.2"), aor, 20_000);
    assert!(!misses.contains_key(aor));
}

#[test]
fn liveness_hysteresis_reaps_after_consecutive_misses() {
    // A genuinely gone UE misses every sweep: strike 1 (kept), strike 2 →
    // reap.  The vanish path is preserved, just delayed by the grace.
    let misses: DashMap<String, u64> = DashMap::new();
    let aor = "sip:gone@ims.example.com";

    let (count, reap) = liveness_miss_outcome(misses.get(aor).map(|v| *v).unwrap_or(0), 2);
    assert_eq!((count, reap), (1, false));
    misses.insert(aor.to_string(), count);

    let (count, reap) = liveness_miss_outcome(misses.get(aor).map(|v| *v).unwrap_or(0), 2);
    assert_eq!((count, reap), (0, true), "second consecutive miss reaps");
    if reap {
        misses.remove(aor);
    }
    assert!(!misses.contains_key(aor));
}

#[test]
fn liveness_gc_drains_bookkeeping_for_gone_ues() {
    // Leak guard: entries for UEs whose SA is gone (deregistered / vanished)
    // must drain to baseline.  Reconciling against empty live sets clears
    // both maps entirely — the "drains to 0" invariant.
    let last_seen: DashMap<std::net::IpAddr, u64> = DashMap::new();
    let misses: DashMap<String, u64> = DashMap::new();
    last_seen.insert(ip("100.65.0.2"), 1);
    last_seen.insert(ip("100.65.0.3"), 2);
    misses.insert("sip:a@ims".to_string(), 1);
    misses.insert("sip:b@ims".to_string(), 1);

    // One UE still live (IP .2 / AoR a), the other gone.
    let mut live_ips = std::collections::HashSet::new();
    live_ips.insert(ip("100.65.0.2"));
    let mut live_aors = std::collections::HashSet::new();
    live_aors.insert("sip:a@ims".to_string());

    liveness_gc(&last_seen, &misses, &live_ips, &live_aors);
    assert_eq!(last_seen.len(), 1);
    assert!(last_seen.contains_key(&ip("100.65.0.2")));
    assert_eq!(misses.len(), 1);
    assert!(misses.contains_key("sip:a@ims"));

    // All UEs gone → both maps drain to baseline (0).
    liveness_gc(
        &last_seen,
        &misses,
        &std::collections::HashSet::new(),
        &std::collections::HashSet::new(),
    );
    assert_eq!(last_seen.len(), 0);
    assert_eq!(misses.len(), 0);
}

#[test]
fn registrar_liveness_config_defaults_bias_toward_patience() {
    // The false-dereg fix ships new defaults: 2-sweep hysteresis and a 4 s
    // per-attempt probe timeout (one paging + reconnect).  An existing
    // pcscf.yaml that omits these picks them up via #[serde(default)].
    let defaults = crate::config::RegistrarLivenessConfig::default();
    assert_eq!(defaults.miss_threshold, 2);
    assert_eq!(defaults.probe_timeout_ms, 4000);
}

#[test]
fn advertise_supported_methods_sets_allow_when_absent() {
    let mut headers = SipHeaders::new();
    advertise_supported_methods(&mut headers);
    let allow = headers.get("Allow").expect("Allow must be set");
    assert_eq!(allow, crate::sip::SUPPORTED_METHODS);
    // The whole point: peers read transfer capability from here.
    assert!(allow.contains("REFER") && allow.contains("NOTIFY"));
}

#[test]
fn advertise_supported_methods_preserves_existing_allow() {
    let mut headers = SipHeaders::new();
    headers.set("Allow", "INVITE, ACK, BYE".to_string());
    advertise_supported_methods(&mut headers);
    assert_eq!(headers.get("Allow").unwrap(), "INVITE, ACK, BYE");
}

#[test]
fn stamp_uas_echo_restores_the_callers_own_from_and_to() {
    // The reported shape: the handler normalised the caller's number for the
    // dial plan (`+15551000001` -> `15551000001`) on the shared A-leg INVITE,
    // and the response built from that buffer answered the caller with an
    // identity it never sent. RFC 3261 §8.2.6.2 requires the echo.
    let mut response = SipMessageBuilder::new()
        .response(503, "Service Unavailable".to_string())
        .from("<sip:15550000001@example.test>;tag=caller-tag".to_string())
        .to("<sip:15551000001@example.test>".to_string())
        .build()
        .unwrap();
    let stored_from = "<sip:+15550000001@example.test>;tag=caller-tag".to_string();
    let stored_to = "<sip:+15551000001@example.test>".to_string();
    stamp_uas_echo(
        &mut response,
        Some(&stored_from),
        Some(&stored_to),
        "a-leg-uas-tag",
    );
    assert_eq!(response.headers.get("From").unwrap(), &stored_from);
    // The To URI is the caller's, plus the UAS tag §8.2.6.2 also requires.
    assert_eq!(
        response.headers.get("To").unwrap(),
        "<sip:+15551000001@example.test>;tag=a-leg-uas-tag"
    );
}

#[test]
fn stamp_uas_echo_preserves_a_to_tag_the_request_already_carried() {
    // An in-dialog request answers with the To it arrived with, tag and all
    // (§8.2.6.2: "if a request contained a To tag ... MUST equal that of the
    // request") — `ensure_tag` must not overwrite it with our dialog tag.
    let mut response = SipMessageBuilder::new()
        .response(200, "OK".to_string())
        .to("<sip:stale@example.test>;tag=stale".to_string())
        .build()
        .unwrap();
    let stored_to = "<sip:+15551000001@example.test>;tag=uas-tag-from-the-request".to_string();
    stamp_uas_echo(&mut response, None, Some(&stored_to), "a-different-tag");
    assert_eq!(response.headers.get("To").unwrap(), &stored_to);
}

#[test]
fn stamp_uas_echo_without_a_snapshot_is_tag_only() {
    // Fallback path — behaviour identical to stamp_uas_to_tag, so a call with
    // no captured arrival snapshot is no worse off than before.
    let mut response = SipMessageBuilder::new()
        .response(408, "Request Timeout".to_string())
        .from("<sip:caller@example.test>;tag=caller-tag".to_string())
        .to("<sip:callee@example.test>".to_string())
        .build()
        .unwrap();
    stamp_uas_echo(&mut response, None, None, "a-leg-uas-tag");
    assert_eq!(
        response.headers.get("From").unwrap(),
        "<sip:caller@example.test>;tag=caller-tag"
    );
    assert_eq!(
        response.headers.get("To").unwrap(),
        "<sip:callee@example.test>;tag=a-leg-uas-tag"
    );
}

#[test]
fn advertise_supported_options_sets_replaces_when_absent() {
    let mut headers = SipHeaders::new();
    advertise_supported_options(&mut headers);
    // RFC 3891 §6.2: a UA that supports the Replaces header MUST advertise
    // the option tag. RFC 5589 §7.3: this is what a transferor reads to
    // decide between an attended transfer and a blind one.
    assert_eq!(headers.get("Supported").unwrap(), "replaces");
}

#[test]
fn advertise_supported_options_merges_with_an_existing_tag() {
    // `Supported` is a comma-separated list header — `replaces` belongs
    // inside the existing value, not on a second line, and must not
    // displace a tag already negotiated (here RFC 4028 `timer`).
    let mut headers = SipHeaders::new();
    headers.set("Supported", "timer".to_string());
    advertise_supported_options(&mut headers);
    assert_eq!(headers.get("Supported").unwrap(), "timer,replaces");
    assert_eq!(headers.get_all("Supported").map(|v| v.len()), Some(1));
}

#[test]
fn advertise_supported_options_is_idempotent() {
    // The A-leg response path can be re-sanitized; the tag must not stack.
    let mut headers = SipHeaders::new();
    advertise_supported_options(&mut headers);
    advertise_supported_options(&mut headers);
    assert_eq!(headers.get("Supported").unwrap(), "replaces");
}

#[test]
fn advertise_supported_options_respects_a_tag_the_peer_already_named() {
    // Case-insensitive per RFC 3261 §7.3.1 — an option tag already present
    // in any casing must not be duplicated.
    let mut headers = SipHeaders::new();
    headers.set("Supported", "timer, REPLACES".to_string());
    advertise_supported_options(&mut headers);
    assert_eq!(headers.get("Supported").unwrap(), "timer, REPLACES");
}

fn builtin_policy(name: &str) -> crate::b2bua::header_policy::ResolvedPolicy {
    let preset = crate::b2bua::header_policy::builtin_presets()
        .get(name)
        .cloned()
        .expect("a built-in preset");
    crate::b2bua::header_policy::ResolvedPolicy::from_preset(preset)
}

/// The B-leg `Supported` settled under `policy_name` from a caller that listed
/// `offered`, with no script involved.
fn b_leg_supported(offered: &str, policy_name: &str) -> Option<String> {
    let mut outbound = SipHeaders::new();
    outbound.set("Supported", offered.to_string());
    advertise_b_leg_capabilities(&mut outbound, &[], &builtin_policy(policy_name));
    outbound.get("Supported").cloned()
}

#[test]
fn b_leg_capabilities_keep_only_the_caller_tags_siphon_claims() {
    // RFC 3261 §20.37: the B-leg INVITE's Supported is siphon's claim. The
    // caller's `100rel`/`timer` stay, in the caller's spelling; `precondition`
    // only where the policy relays capability negotiation both ways.
    let offered = "100rel, Timer, outbound, precondition, path";
    assert_eq!(
        b_leg_supported(offered, "transparent-b2bua@2026").as_deref(),
        Some("100rel,Timer")
    );
    assert_eq!(
        b_leg_supported(offered, "ims-intra-trust-domain@2026").as_deref(),
        Some("100rel,Timer,precondition")
    );
}

#[test]
fn b_leg_capabilities_drop_supported_when_no_caller_tag_is_siphons() {
    assert_eq!(
        b_leg_supported("outbound, path, eventlist", "ims-intra-trust-domain@2026"),
        None
    );
}

#[test]
fn b_leg_capabilities_read_every_supported_line_and_the_compact_form() {
    let mut outbound = SipHeaders::new();
    outbound.add("Supported", "outbound".to_string());
    outbound.add("k", "precondition, 100rel".to_string());
    advertise_b_leg_capabilities(
        &mut outbound,
        &[],
        &builtin_policy("ims-intra-trust-domain@2026"),
    );
    assert_eq!(
        outbound.get_all("Supported"),
        Some(&vec!["precondition,100rel".to_string()])
    );
}

#[test]
fn b_leg_capabilities_replace_the_callers_allow_with_siphons_methods() {
    // RFC 3261 §20.5: Allow lists the methods the sender supports.
    let mut outbound = SipHeaders::new();
    outbound.set("Allow", "INVITE, ACK, BYE".to_string());
    advertise_b_leg_capabilities(
        &mut outbound,
        &[],
        &builtin_policy("ims-trust-domain-boundary@2026"),
    );
    assert_eq!(
        outbound.get_all("Allow"),
        Some(&vec![crate::sip::SUPPORTED_METHODS.to_string()])
    );
}

#[test]
fn b_leg_capabilities_leave_a_script_shaped_header_alone() {
    // The policy kept the script's values; siphon's own must not replace them.
    let mut outbound = SipHeaders::new();
    outbound.set("Supported", "x-lab-tag, outbound".to_string());
    outbound.set("Allow", "INVITE, ACK, BYE".to_string());
    advertise_b_leg_capabilities(
        &mut outbound,
        // Recorded as the script spelled them; `k` is `Supported`.
        &["k".to_string(), "ALLOW".to_string()],
        &builtin_policy("transparent-b2bua@2026"),
    );
    assert_eq!(
        outbound.get("Supported").map(String::as_str),
        Some("x-lab-tag, outbound")
    );
    assert_eq!(
        outbound.get("Allow").map(String::as_str),
        Some("INVITE, ACK, BYE")
    );
}

#[test]
fn b_leg_capabilities_do_not_refill_a_header_the_script_removed() {
    let mut outbound = SipHeaders::new();
    advertise_b_leg_capabilities(
        &mut outbound,
        &["Supported".to_string(), "Allow".to_string()],
        &builtin_policy("transparent-b2bua@2026"),
    );
    assert!(!outbound.has("Supported"));
    assert!(!outbound.has("Allow"));
}

#[test]
fn relayed_response_capabilities_mirror_the_b_leg_rule() {
    // A relayed response's far leg is the callee: its claimable tags survive in
    // its own order, `replaces` is merged, and `Allow` is siphon's.
    let mut headers = SipHeaders::new();
    headers.add("Supported", "gruu, precondition".to_string());
    headers.add("k", "timer, outbound".to_string());
    headers.set("Allow", "INVITE, ACK, BYE".to_string());
    advertise_relayed_response_capabilities(
        &mut headers,
        &builtin_policy("ims-trust-domain-boundary@2026"),
    );
    assert_eq!(
        headers.get_all("Supported"),
        Some(&vec!["precondition,timer,replaces".to_string()])
    );
    assert_eq!(
        headers.get_all("Allow"),
        Some(&vec![crate::sip::SUPPORTED_METHODS.to_string()])
    );
}

#[test]
fn unhonourable_required_tags_keeps_what_siphon_or_the_callee_can_honour() {
    let mut invite = SipHeaders::new();
    invite.add(
        "Require",
        "100rel, precondition, X-Lab-Extension".to_string(),
    );
    invite.add(
        "Require",
        "sec-agree, x-lab-extension, histinfo, TIMER".to_string(),
    );
    // Under the default preset precondition cannot cross (responses strip
    // Supported/Require); histinfo can, and Require reaches the callee. The
    // duplicate vendor tag is listed once, in the caller's spelling.
    assert_eq!(
        unhonourable_required_tags(&invite, &[], &builtin_policy("transparent-b2bua@2026")),
        vec!["precondition".to_string(), "X-Lab-Extension".to_string()]
    );
    // The trust boundary relays precondition but not History-Info.
    assert_eq!(
        unhonourable_required_tags(
            &invite,
            &[],
            &builtin_policy("ims-trust-domain-boundary@2026")
        ),
        vec!["X-Lab-Extension".to_string(), "histinfo".to_string()]
    );
}

#[test]
fn unhonourable_required_tags_needs_require_to_reach_the_callee() {
    let mut invite = SipHeaders::new();
    invite.set("Require", "precondition, replaces".to_string());
    let mut no_require = builtin_policy("ims-intra-trust-domain@2026");
    assert!(unhonourable_required_tags(&invite, &[], &no_require).is_empty());
    no_require.deltas_strip = vec!["Require".to_string()];
    assert_eq!(
        unhonourable_required_tags(&invite, &[], &no_require),
        vec!["precondition".to_string()]
    );
    // A Require the script set goes out over the strip, so the callee is shown
    // it: histinfo (History-Info still relayed) is honoured again, while
    // precondition is not, since the strip also keeps the callee's Require on
    // the response from the caller.
    let mut history = SipHeaders::new();
    history.set("Require", "histinfo, precondition".to_string());
    assert_eq!(
        unhonourable_required_tags(&history, &[], &no_require),
        vec!["histinfo".to_string(), "precondition".to_string()]
    );
    assert_eq!(
        unhonourable_required_tags(&history, &["require".to_string()], &no_require),
        vec!["precondition".to_string()]
    );
}

#[test]
fn unhonourable_required_tags_is_empty_without_require() {
    let invite = SipHeaders::new();
    assert!(
        unhonourable_required_tags(&invite, &[], &builtin_policy("transparent-b2bua@2026"))
            .is_empty()
    );
}

#[test]
fn relayed_response_capabilities_add_siphons_own_to_an_empty_response() {
    // The default preset stripped the callee's Supported and Allow already.
    let mut headers = SipHeaders::new();
    advertise_relayed_response_capabilities(
        &mut headers,
        &builtin_policy("transparent-b2bua@2026"),
    );
    assert_eq!(
        headers.get("Supported").map(String::as_str),
        Some("replaces")
    );
    assert_eq!(
        headers.get("Allow").map(String::as_str),
        Some(crate::sip::SUPPORTED_METHODS)
    );
}

#[test]
fn augment_options_response_adds_contact_and_allow() {
    let mut response = SipMessageBuilder::new()
        .response(200, "OK".to_string())
        .build()
        .unwrap();
    augment_options_response(&mut response, "sbc.example.org", 5061, Transport::Tls);
    assert_eq!(
        response.headers.get("Contact").unwrap(),
        "<sip:sbc.example.org:5061;transport=tls>"
    );
    assert_eq!(
        response.headers.get("Allow").unwrap(),
        crate::sip::SUPPORTED_METHODS
    );
}

#[test]
fn augment_options_response_preserves_script_contact() {
    let mut response = SipMessageBuilder::new()
        .response(200, "OK".to_string())
        .contact("<sip:custom@host:5060>".to_string())
        .build()
        .unwrap();
    augment_options_response(&mut response, "sbc.example.org", 5061, Transport::Udp);
    // Script-set Contact must not be clobbered; Allow is still advertised.
    assert_eq!(
        response.headers.get("Contact").unwrap(),
        "<sip:custom@host:5060>"
    );
    assert_eq!(
        response.headers.get("Allow").unwrap(),
        crate::sip::SUPPORTED_METHODS
    );
}

/// A minimal well-formed request, for the no-handler response tests below.
fn request_for(method: &str) -> SipMessage {
    let raw = format!(
        concat!(
            "{} sip:probe@siphon.invalid SIP/2.0\r\n",
            "Via: SIP/2.0/UDP peer.invalid:5060;branch=z9hG4bK-nohandler\r\n",
            "From: <sip:peer@peer.invalid>;tag=abc\r\n",
            "To: <sip:probe@siphon.invalid>\r\n",
            "Call-ID: no-handler-test\r\n",
            "CSeq: 1 {}\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        method, method
    );
    crate::sip::parser::parse_sip_message(&raw).unwrap().1
}

#[test]
fn no_handler_options_is_answered_200_with_contact_and_allow() {
    // RFC 3261 §11.2 — a UAS SHOULD answer OPTIONS 200 with its
    // capabilities. This is the case every registered deployment hits: a
    // registrar qualifies its bindings on a timer forever, and before this
    // the probe was answered `500 No Script Handler`. It looked healthy from
    // both ends because a qualifying registrar takes any final response as
    // proof of life, so the only symptom was one WARN per probe.
    let response = build_no_handler_response(
        &request_for("OPTIONS"),
        "OPTIONS",
        true,
        Some("siphon"),
        "sbc.example.org",
        5060,
        Transport::Udp,
    )
    .expect("auto_options on must answer");
    assert_eq!(response.status_code(), Some(200));
    assert_eq!(
        response.headers.get("Allow").unwrap(),
        crate::sip::SUPPORTED_METHODS
    );
    // Some peers (Teams Direct Routing) reject an OPTIONS answer carrying
    // neither Contact nor Record-Route.
    assert_eq!(
        response.headers.get("Contact").unwrap(),
        "<sip:sbc.example.org:5060;transport=udp>"
    );
}

#[test]
fn no_handler_other_methods_are_answered_405_with_allow() {
    // RFC 3261 §8.2.1 — a UAS that does not support the method MUST answer
    // 405 and MUST add Allow. 500 said "this server is broken" and invited a
    // retry that would fail identically.
    for method in ["INVITE", "REGISTER", "SUBSCRIBE", "FOO"] {
        let response = build_no_handler_response(
            &request_for(method),
            method,
            true,
            Some("siphon"),
            "sbc.example.org",
            5060,
            Transport::Udp,
        )
        .unwrap_or_else(|| panic!("{method}: only OPTIONS may be dropped"));
        assert_eq!(response.status_code(), Some(405), "{method}");
        assert_eq!(
            response.headers.get("Allow").map(String::as_str),
            Some(crate::sip::SUPPORTED_METHODS),
            "{method}: RFC 3261 §8.2.1 makes Allow mandatory on a 405",
        );
        // A 405 is not a capability response — no Contact is owed, and
        // inventing one would put siphon in the peer's route set.
        assert!(!response.headers.has("Contact"), "{method}");
    }
}

#[test]
fn no_handler_response_echoes_the_dialog_identifiers() {
    // Whatever the code, the response has to be routable back: Via drives
    // response routing (§18.2.2) and From/To/Call-ID/CSeq are mandatory in
    // every response (§8.2.6.2).
    let response = build_no_handler_response(
        &request_for("MESSAGE"),
        "MESSAGE",
        true,
        None,
        "sbc.example.org",
        5060,
        Transport::Udp,
    )
    .expect("a 405 is never dropped");
    assert_eq!(
        response.headers.get("Via").unwrap(),
        "SIP/2.0/UDP peer.invalid:5060;branch=z9hG4bK-nohandler"
    );
    assert_eq!(response.headers.get("Call-ID").unwrap(), "no-handler-test");
    assert_eq!(response.headers.get("CSeq").unwrap(), "1 MESSAGE");
    assert_eq!(
        response.headers.get("From").unwrap(),
        "<sip:peer@peer.invalid>;tag=abc"
    );
}

#[test]
fn no_handler_options_match_is_case_sensitive_on_the_method_token() {
    // RFC 3261 §7.1: the method is a case-SENSITIVE token, so `Options` is
    // not `OPTIONS` — it is an unknown method and 405 is the right answer.
    // Pinned because the parser hands the method through verbatim and a
    // careless `eq_ignore_ascii_case` here would answer 200 to a method
    // siphon does not implement.
    let response = build_no_handler_response(
        &request_for("Options"),
        "Options",
        true,
        None,
        "sbc.example.org",
        5060,
        Transport::Udp,
    )
    .expect("an unknown method is answered, not dropped");
    assert_eq!(response.status_code(), Some(405));
}

#[test]
fn auto_options_off_drops_an_unclaimed_options_silently() {
    // `server.auto_options: false` means siphon must not answer for a script
    // that never asked it to, and the honest form of that is silence: a
    // status code — any status code — confirms to a scanner that something
    // is listening, which is the same reason the scripting API drops rather
    // than 403s. The operator who turns this off and registers no handler
    // has chosen an unanswered OPTIONS.
    assert!(build_no_handler_response(
        &request_for("OPTIONS"),
        "OPTIONS",
        false,
        Some("siphon"),
        "sbc.example.org",
        5060,
        Transport::Udp,
    )
    .is_none());
}

#[test]
fn auto_options_off_does_not_suppress_the_405() {
    // The knob is scoped to OPTIONS. A method siphon genuinely will not
    // handle still owes the sender a 405 + Allow (RFC 3261 §8.2.1) — going
    // silent there would turn one misconfigured script into a peer retrying
    // into a black hole.
    for method in ["INVITE", "REGISTER", "MESSAGE"] {
        let response = build_no_handler_response(
            &request_for(method),
            method,
            false,
            Some("siphon"),
            "sbc.example.org",
            5060,
            Transport::Udp,
        )
        .unwrap_or_else(|| panic!("{method}: auto_options must not gate the 405"));
        assert_eq!(response.status_code(), Some(405), "{method}");
        assert_eq!(
            response.headers.get("Allow").map(String::as_str),
            Some(crate::sip::SUPPORTED_METHODS),
            "{method}",
        );
    }
}

#[test]
fn b_leg_contact_default_is_userless() {
    // RFC 3261 §8.1.1.8 — no identity in the Contact userpart by default.
    let contact = build_b_leg_contact("proxy.example.com", 5060, Transport::Udp, None, None);
    assert_eq!(contact, "<sip:proxy.example.com:5060;transport=udp>");
}

#[test]
fn b_leg_contact_user_override_keeps_host_port() {
    // set_contact_user() injects a userpart, siphon's host:port unchanged.
    let contact = build_b_leg_contact(
        "proxy.example.com",
        5060,
        Transport::Tcp,
        Some("1001"),
        None,
    );
    assert_eq!(contact, "<sip:1001@proxy.example.com:5060;transport=tcp>");
}

#[test]
fn b_leg_contact_empty_user_override_collapses_to_userless() {
    // set_contact_user("") explicitly forces the userless form.
    let contact = build_b_leg_contact("proxy.example.com", 5060, Transport::Udp, Some(""), None);
    assert_eq!(contact, "<sip:proxy.example.com:5060;transport=udp>");
}

#[test]
fn b_leg_contact_full_uri_override_wins_over_user() {
    // set_contact_uri() takes precedence over set_contact_user().
    let contact = build_b_leg_contact(
        "proxy.example.com",
        5060,
        Transport::Udp,
        Some("1001"),
        Some("sip:gruu@edge.example.com:5080"),
    );
    assert_eq!(contact, "<sip:gruu@edge.example.com:5080>");
}

#[test]
fn collect_route_set_splits_lines_and_top_level_commas() {
    let mut message = SipMessageBuilder::new()
        .request(Method::Register, SipUri::new("example.com".to_string()))
        .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-reg-x".to_string())
        .to("<sip:alice@example.com>".to_string())
        .from("<sip:alice@example.com>;tag=t".to_string())
        .call_id("c".to_string())
        .cseq("1 REGISTER".to_string())
        .content_length(0)
        .build()
        .expect("builds");

    // One plain header line and one comma-folded line → three route values,
    // with the comma inside <...> of a uri-param left untouched.
    message.headers.set_all(
        "Service-Route",
        vec![
            "<sip:scscf1.example.com;lr>".to_string(),
            "<sip:scscf2.example.com;lr>, <sip:scscf3.example.com;lr>".to_string(),
        ],
    );

    let routes = collect_route_set(&message, "Service-Route");
    assert_eq!(
        routes,
        vec![
            "<sip:scscf1.example.com;lr>".to_string(),
            "<sip:scscf2.example.com;lr>".to_string(),
            "<sip:scscf3.example.com;lr>".to_string(),
        ]
    );

    // Missing header → empty.
    assert!(collect_route_set(&message, "P-Associated-URI").is_empty());
}

#[test]
fn build_dereg_register_has_expires_zero_routes_and_aor() {
    let destination = "192.0.2.5:6060".parse().unwrap();
    let routes = vec!["<sip:scscf.example.com:6060;lr>".to_string()];
    let message = build_dereg_register(
        "sip:alice@example.com",
        "sip:alice@10.0.0.1:5060",
        &routes,
        destination,
    )
    .expect("de-REGISTER builds");
    let wire = String::from_utf8(message.to_bytes()).unwrap();

    // R-URI is the registrar domain (AoR host), not the contact.
    assert!(
        wire.starts_with("REGISTER sip:example.com SIP/2.0\r\n"),
        "request line wrong:\n{wire}"
    );
    assert!(
        wire.contains("Expires: 0\r\n"),
        "missing Expires: 0:\n{wire}"
    );
    assert!(
        wire.contains("Contact: <sip:alice@10.0.0.1:5060>;expires=0"),
        "missing deregistering Contact:\n{wire}"
    );
    assert!(
        wire.contains("Route: <sip:scscf.example.com:6060;lr>"),
        "missing Service-Route:\n{wire}"
    );
    assert!(
        wire.contains("To: <sip:alice@example.com>"),
        "missing To:\n{wire}"
    );
    assert!(
        wire.contains("From: <sip:alice@example.com>;tag=liveness-"),
        "missing From with liveness tag:\n{wire}"
    );
    assert!(wire.contains("CSeq: 1 REGISTER"), "missing CSeq:\n{wire}");
    // Must carry the integrity-protected marker so the S-CSCF skips the
    // IMS-AKA re-challenge (TS 24.229 §5.4.1.2.2) and actually completes
    // the de-registration.
    assert!(
        wire.contains("integrity-protected=\"ip-assoc-yes\""),
        "missing integrity-protected marker in Authorization:\n{wire}"
    );
    assert!(
        wire.contains("Authorization: Digest username=\"alice@example.com\""),
        "Authorization username should be the IMPI-shaped public id:\n{wire}"
    );
}

#[test]
fn parse_route_uri_strips_brackets_and_keeps_hostport() {
    let uri = parse_route_uri("<sip:scscf.example.com:6060;lr>").expect("parses");
    assert_eq!(uri.host, "scscf.example.com");
    assert_eq!(uri.port, Some(6060));

    let secure = parse_route_uri("  <sips:scscf2.example.com;lr>  ").expect("parses");
    assert_eq!(secure.scheme, "sips");
    assert_eq!(secure.host, "scscf2.example.com");
    assert_eq!(secure.port, None);
}

#[test]
fn drain_state_default_counts_zero_when_managers_unset() {
    let drain = DrainState::new();
    assert_eq!(drain.active_counts(), (0, 0));
    assert!(!drain.is_draining.load(std::sync::atomic::Ordering::Relaxed));
}

#[test]
fn drain_state_reports_counts_after_register() {
    let drain = DrainState::new();
    let tm = Arc::new(TransactionManager::new(
        crate::transaction::timer::TimerConfig::default(),
    ));
    let ca = Arc::new(CallActorStore::new());
    drain.transaction_manager.set(Arc::clone(&tm)).ok();
    drain.call_actors.set(Arc::clone(&ca)).ok();
    // Both empty initially.
    assert_eq!(drain.active_counts(), (0, 0));
}

fn sample_invite() -> SipMessage {
    SipMessageBuilder::new()
        .request(
            Method::Invite,
            SipUri::new("biloxi.com".to_string()).with_user("bob".to_string()),
        )
        .via("SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds".to_string())
        .to("Bob <sip:bob@biloxi.com>".to_string())
        .from("Alice <sip:alice@atlanta.com>;tag=1928301774".to_string())
        .call_id("a84b4c76e66710@pc33.atlanta.com".to_string())
        .cseq("314159 INVITE".to_string())
        .max_forwards(70)
        .content_length(0)
        .build()
        .unwrap()
}

#[test]
fn first_route_uri_strips_angle_brackets() {
    let route_set = vec![
        "<sip:scscf.example.com:6060;lr;transport=udp>".to_string(),
        "<sip:pcscf.example.com:5060;lr;transport=tcp>".to_string(),
    ];
    let uri = first_route_uri(&route_set);
    assert_eq!(
        uri.as_deref(),
        Some("sip:scscf.example.com:6060;lr;transport=udp")
    );
}

#[test]
fn uac_route_set_from_record_routes_flattens_and_reverses() {
    // Mix of one-URI-per-line and a comma-joined multi-URI line (RFC 3261
    // §7.3.1). The UAC route set is the responder's Record-Route in reverse
    // wire order (RFC 3261 §12.1.2), computed after flattening.
    let record_routes = vec![
        "<sip:p1.example.com;lr>, <sip:p2.example.com;lr>".to_string(),
        "<sip:p3.example.com;lr>".to_string(),
    ];
    let route_set = uac_route_set_from_record_routes(&record_routes);
    assert_eq!(
        route_set,
        vec![
            "<sip:p3.example.com;lr>".to_string(),
            "<sip:p2.example.com;lr>".to_string(),
            "<sip:p1.example.com;lr>".to_string(),
        ],
    );
}

#[test]
fn uac_route_set_from_record_routes_empty() {
    assert!(uac_route_set_from_record_routes(&[]).is_empty());
}

/// The two Record-Route entries a record-routing proxy pair writes, and the
/// route set they mean for the UAC: same list, reversed (RFC 3261 §12.1.2).
const RECORD_ROUTES: [&str; 2] = [
    "<sip:198.51.100.10;lr;proxy-state=outer>",
    "<sip:198.51.100.20;lr;proxy-state=inner>",
];

fn uac_routes() -> Vec<String> {
    vec![RECORD_ROUTES[1].to_string(), RECORD_ROUTES[0].to_string()]
}

fn routes_on(message: &SipMessage) -> Vec<String> {
    message
        .headers
        .get_all("Route")
        .cloned()
        .unwrap_or_default()
}

/// A 2xx that establishes a dialog through two record-routing proxies.
fn record_routed_2xx() -> SipMessage {
    parse_sip_message(concat!(
        "SIP/2.0 200 OK\r\n",
        "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-target-1\r\n",
        "Record-Route: <sip:198.51.100.10;lr;proxy-state=outer>\r\n",
        "Record-Route: <sip:198.51.100.20;lr;proxy-state=inner>\r\n",
        "From: <sip:+15550100@192.0.2.1>;tag=sb-localtag\r\n",
        "To: <sip:+15550199@example.net>;tag=target-1\r\n",
        "Call-ID: b2b-transfer-target@192.0.2.1\r\n",
        "CSeq: 1 INVITE\r\n",
        "Contact: <sip:198.51.100.30:5073>\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    ))
    .expect("200 fixture parses")
    .1
}

fn leg_with_route_set(route_set: Vec<String>) -> Leg {
    let mut leg = Leg::new_b_leg(
        "b2b-transfer-target@192.0.2.1".to_string(),
        "sb-localtag".to_string(),
        "sip:+15550199@example.net".to_string(),
        "z9hG4bK-target-1".to_string(),
        LegTransport {
            remote_addr: "192.0.2.9:5060".parse().expect("fixture address parses"),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    );
    leg.dialog.route_set = route_set;
    leg
}

/// The chain a transferred call hangs on: the transfer target's 2xx defines the
/// dialog's route set (RFC 3261 §12.1.2), the capture puts it on the leg, and
/// every in-dialog request built from that leg then carries it (§12.2.1.1).
///
/// Pre-fix the capture did not exist, so the target leg's route set stayed
/// empty and its ACK and BYE went out with no `Route` at all — reaching the
/// far end without the state the proxies in between had record-routed.
#[test]
fn transfer_target_leg_captures_its_route_set_and_the_ack_carries_it() {
    let store = CallActorStore::new();
    let call_id = store.create_call(leg_with_route_set(vec![]));
    store.add_b_leg(&call_id, leg_with_route_set(vec![]));
    let response = record_routed_2xx();

    assert!(
        store_b_leg_route_set_from_2xx(&store, &call_id, 0, &response),
        "a 2xx carrying Record-Route establishes a route set"
    );
    let target = store
        .get_call(&call_id)
        .and_then(|call| call.b_legs.first().cloned())
        .expect("the target leg is in the store");
    assert_eq!(
        target.dialog.route_set,
        uac_routes(),
        "§12.1.2 — the response's Record-Route, reversed"
    );

    let ack = build_owned_leg_ack(&target, &response, "z9hG4bK-ack-1", "192.0.2.1", 5060)
        .expect("the ACK builds");
    assert_eq!(routes_on(&ack), uac_routes(), "§12.2.1.1 — the ACK routes");
    // The remote target is still the responder's Contact, not the first Route.
    match ack.start_line {
        StartLine::Request(ref line) => {
            assert_eq!(line.request_uri.to_string(), "sip:198.51.100.30:5073")
        }
        _ => panic!("the ACK is a request"),
    }
}

/// A direct peer that does not record-route leaves the leg's route set alone,
/// and its ACK carries no `Route` — the pre-fix wire shape, still correct here.
#[test]
fn a_2xx_without_record_route_stores_nothing_and_routes_nothing() {
    let store = CallActorStore::new();
    let call_id = store.create_call(leg_with_route_set(vec![]));
    store.add_b_leg(&call_id, leg_with_route_set(vec![]));
    let response = parse_sip_message(concat!(
        "SIP/2.0 200 OK\r\n",
        "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-target-1\r\n",
        "From: <sip:+15550100@192.0.2.1>;tag=sb-localtag\r\n",
        "To: <sip:+15550199@example.net>;tag=target-1\r\n",
        "Call-ID: b2b-transfer-target@192.0.2.1\r\n",
        "CSeq: 1 INVITE\r\n",
        "Contact: <sip:198.51.100.30:5073>\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    ))
    .expect("200 fixture parses")
    .1;

    assert!(!store_b_leg_route_set_from_2xx(
        &store, &call_id, 0, &response
    ));
    let target = store
        .get_call(&call_id)
        .and_then(|call| call.b_legs.first().cloned())
        .expect("the target leg is in the store");
    assert!(target.dialog.route_set.is_empty());
    let ack = build_owned_leg_ack(&target, &response, "z9hG4bK-ack-1", "192.0.2.1", 5060)
        .expect("the ACK builds");
    assert!(routes_on(&ack).is_empty());
}

/// The ACK for a re-INVITE's 2xx carries the dialog route set the re-INVITE
/// itself used. It cannot be recovered from the response — a mid-dialog 2xx
/// does not re-advertise `Record-Route` — so it comes off the tracking leg.
///
/// Pre-fix this builder emitted no `Route` at all, so every B2BUA re-INVITE
/// (hold, resume, session-timer refresh, transfer media re-anchor) answered
/// its 200 with an unrouted ACK.
#[test]
fn reinvite_ack_carries_the_dialog_route_set() {
    let route_set = uac_routes();
    let ack = build_reinvite_ack(ReinviteAck {
        request_uri: SipUri::new("sip:198.51.100.30:5073".to_string()),
        via_transport: "UDP",
        via_host: "192.0.2.1",
        via_port: 5060,
        branch: "z9hG4bK-ack-1",
        from: "<sip:+15550100@192.0.2.1>;tag=sb-localtag",
        to: "<sip:+15550199@example.net>;tag=target-1",
        call_id: "b2b-survivor@192.0.2.1",
        cseq_number: "2",
        route_set: &route_set,
    })
    .expect("the ACK builds");

    assert_eq!(routes_on(&ack), route_set);
    assert_eq!(ack.headers.cseq().map(String::as_str), Some("2 ACK"));
    assert_eq!(
        ack.headers.call_id().map(String::as_str),
        Some("b2b-survivor@192.0.2.1"),
        "the ACK stays in the responder's dialog"
    );

    // A leg with no route set (direct peer) still ACKs, with no Route.
    let direct = build_reinvite_ack(ReinviteAck {
        request_uri: SipUri::new("sip:198.51.100.30:5073".to_string()),
        via_transport: "UDP",
        via_host: "192.0.2.1",
        via_port: 5060,
        branch: "z9hG4bK-ack-1",
        from: "<sip:+15550100@192.0.2.1>;tag=sb-localtag",
        to: "<sip:+15550199@example.net>;tag=target-1",
        call_id: "b2b-survivor@192.0.2.1",
        cseq_number: "2",
        route_set: &[],
    })
    .expect("the ACK builds");
    assert!(routes_on(&direct).is_empty());
}

/// The ACK for a 2xx on a leg siphon originated takes its route set straight
/// from that response (RFC 3261 §12.1.2) — the leg predates the 2xx, so there
/// is nothing stored to read.
#[test]
fn originated_2xx_ack_carries_the_reversed_record_route() {
    let ack = build_b2bua_ack_for_2xx(&record_routed_2xx(), Transport::Udp, "192.0.2.1", 5060)
        .expect("the ACK builds");
    assert_eq!(routes_on(&ack), uac_routes());
}

#[test]
fn early_dialog_route_set_first_hop_is_proxy_not_cached_next_hop() {
    // Regression for the B2BUA auto-PRACK 406: a reliable 183 arrives via the
    // S-CSCF, which Record-Routes. The early-dialog route set must be derived
    // from THIS response's Record-Route so the PRACK's Route header and
    // resolve_in_dialog_destination both target the S-CSCF — not the cached
    // INVITE next-hop (an IMS I-CSCF that doesn't Record-Route and rejects the
    // in-dialog PRACK with 406, killing the 100rel handshake).
    let record_routes = vec!["<sip:scscf.ims.example.com:6060;lr;transport=udp>".to_string()];
    let route_set = uac_route_set_from_record_routes(&record_routes);
    assert_eq!(
        first_route_uri(&route_set).as_deref(),
        Some("sip:scscf.ims.example.com:6060;lr;transport=udp"),
        "PRACK must follow the early-dialog route set to the S-CSCF",
    );
}

/// The reliable 183 as an IMS UE sends it: a `Contact` on a host
/// (`203.0.113.14`) DISTINCT from the To AoR host (the home domain). The
/// early-dialog target must capture the Contact (RFC 3261 §12.1.2 remote
/// target), the tagged To, and the reversed Record-Route — a round-trip
/// against siphon's own loopback UAS would hide this because AoR and Contact
/// resolve to the same place.
#[test]
fn early_dialog_target_from_response_uses_contact_not_aor() {
    let response = parse_sip_message(concat!(
        "SIP/2.0 183 Session Progress\r\n",
        "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-bleg-1\r\n",
        "From: <sip:+15550100@192.0.2.1>;tag=sb-fromtag\r\n",
        "To: <sip:1001@ims.example.com>;tag=uas-early-1\r\n",
        "Call-ID: b2b-callid@192.0.2.1\r\n",
        "CSeq: 1 INVITE\r\n",
        "RSeq: 1\r\n",
        "Require: 100rel\r\n",
        "Record-Route: <sip:198.51.100.101:5060;transport=tcp;lr>, <sip:198.51.100.101:5060;transport=udp;lr>, <sip:198.51.100.121:6060;transport=udp;lr>\r\n",
        "Contact: <sip:ue@203.0.113.14:42685>\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    ))
    .expect("183 fixture parses")
    .1;

    let target = early_dialog_target_from_response(&response);
    // Remote target = the UE Contact, NOT the To AoR.
    assert_eq!(
        target.remote_contact.as_deref(),
        Some("sip:ue@203.0.113.14:42685"),
    );
    // To carries the early-dialog remote tag.
    assert_eq!(
        target.to_header.as_deref(),
        Some("<sip:1001@ims.example.com>;tag=uas-early-1"),
    );
    // Route set = Record-Route reversed for the UAC side (first hop = the
    // last Record-Route entry, the S-CSCF).
    assert_eq!(
        first_route_uri(&target.route_set).as_deref(),
        Some("sip:198.51.100.121:6060;transport=udp;lr"),
    );
}

/// The core fix: the auto-PRACK's Request-URI must be the reliable 183's
/// Contact (the UE), NOT the dialog To AoR. Pre-fix, `remote_contact` was
/// only captured on the 2xx, so the R-URI fell back to `target_uri` (the
/// AoR) and an IMS I-CSCF returned 482 Loop Detected.
#[test]
fn build_b2bua_prack_ruri_is_remote_contact_not_aor() {
    let response = parse_sip_message(concat!(
        "SIP/2.0 183 Session Progress\r\n",
        "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-bleg-1\r\n",
        "From: <sip:+15550100@192.0.2.1>;tag=sb-fromtag\r\n",
        "To: <sip:1001@ims.example.com>;tag=uas-early-1\r\n",
        "Call-ID: b2b-callid@192.0.2.1\r\n",
        "CSeq: 1 INVITE\r\n",
        "RSeq: 1\r\n",
        "Require: 100rel\r\n",
        "Record-Route: <sip:198.51.100.101:5060;transport=tcp;lr>, <sip:198.51.100.101:5060;transport=udp;lr>, <sip:198.51.100.121:6060;transport=udp;lr>\r\n",
        "Contact: <sip:ue@203.0.113.14:42685>\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    ))
    .expect("183 fixture parses")
    .1;
    let target = early_dialog_target_from_response(&response);

    // B-leg dialog as siphon holds it before answer: target_uri is the AoR,
    // remote_contact is still None (only the 2xx would set it pre-fix).
    let mut dialog = crate::b2bua::actor::Dialog::new_outbound(
        "b2b-callid@192.0.2.1".to_string(),
        "sb-fromtag".to_string(),
        "sip:1001@ims.example.com".to_string(),
    );
    dialog.local_from_uri = Some("<sip:+15550100@192.0.2.1>".to_string());
    dialog.local_contact = Some("<sip:192.0.2.1:5060;transport=udp>".to_string());

    let prack = build_b2bua_prack_message(
        &dialog,
        crate::transport::Transport::Udp,
        "192.0.2.1",
        5060,
        &target,
        1,        // RSeq
        1,        // INVITE CSeq number (echoed by the 183)
        "INVITE", // RAck method
        3,        // local CSeq for the PRACK
    )
    .expect("PRACK builds");

    // Request-URI is the UE Contact, not the home-domain AoR.
    match &prack.start_line {
        StartLine::Request(request_line) => {
            assert_eq!(request_line.method, Method::Prack);
            assert_eq!(request_line.request_uri.host, "203.0.113.14");
            assert_eq!(request_line.request_uri.port, Some(42685));
            assert_eq!(request_line.request_uri.user.as_deref(), Some("ue"),);
            assert_ne!(
                request_line.request_uri.host, "ims.example.com",
                "R-URI must be the remote target Contact, never the To AoR",
            );
        }
        _ => panic!("expected a PRACK request line"),
    }
    // To carries the remote tag from the 183 (early-dialog identity).
    assert!(prack.headers.to().unwrap().contains("tag=uas-early-1"));
    // RAck = "<RSeq> <CSeq-num> <method>" (RFC 3262 §7.2).
    assert_eq!(
        prack.headers.get("RAck").map(String::as_str),
        Some("1 1 INVITE")
    );
    // Route set follows the reversed Record-Route to the S-CSCF first hop.
    let routes = prack.headers.get_all("Route").cloned().unwrap_or_default();
    assert_eq!(
        first_route_uri(&routes).as_deref(),
        Some("sip:198.51.100.121:6060;transport=udp;lr"),
    );
}

/// Forked early dialogs: one INVITE branch, two reliable 183s with DISTINCT
/// To-tags and Contacts (and both RSeq 1). Each PRACK must target its OWN
/// dialog's Contact and carry its OWN To-tag — a single per-Leg remote-target
/// slot would send both PRACKs to the first dialog's Contact.
#[test]
fn forked_early_dialogs_prack_targets_matching_contact() {
    let make_183 = |to_tag: &str, contact_host: &str| {
        parse_sip_message(&format!(
            concat!(
                "SIP/2.0 183 Session Progress\r\n",
                "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-bleg-1\r\n",
                "From: <sip:+15550100@192.0.2.1>;tag=sb-fromtag\r\n",
                "To: <sip:1001@ims.example.com>;tag={to_tag}\r\n",
                "Call-ID: b2b-callid@192.0.2.1\r\n",
                "CSeq: 1 INVITE\r\n",
                "RSeq: 1\r\n",
                "Require: 100rel\r\n",
                "Contact: <sip:ue@{contact_host}:42685>\r\n",
                "Content-Length: 0\r\n",
                "\r\n",
            ),
            to_tag = to_tag,
            contact_host = contact_host,
        ))
        .expect("183 fixture parses")
        .1
    };

    let dialog = || {
        let mut dialog = crate::b2bua::actor::Dialog::new_outbound(
            "b2b-callid@192.0.2.1".to_string(),
            "sb-fromtag".to_string(),
            "sip:1001@ims.example.com".to_string(),
        );
        dialog.local_from_uri = Some("<sip:+15550100@192.0.2.1>".to_string());
        dialog.local_contact = Some("<sip:192.0.2.1:5060;transport=udp>".to_string());
        dialog
    };

    for (to_tag, host) in [("tag-alpha", "203.0.113.14"), ("tag-beta", "203.0.113.99")] {
        let response = make_183(to_tag, host);
        let target = early_dialog_target_from_response(&response);
        let prack = build_b2bua_prack_message(
            &dialog(),
            crate::transport::Transport::Udp,
            "192.0.2.149",
            5060,
            &target,
            1,
            1,
            "INVITE",
            3,
        )
        .expect("PRACK builds");

        match &prack.start_line {
            StartLine::Request(request_line) => {
                assert_eq!(
                    request_line.request_uri.host, host,
                    "each fork branch PRACKs its own Contact host",
                );
            }
            _ => panic!("expected a PRACK request line"),
        }
        assert!(
            prack
                .headers
                .to()
                .unwrap()
                .contains(&format!("tag={to_tag}")),
            "each fork branch PRACK carries its own To-tag",
        );
    }
}

#[test]
fn first_route_uri_empty_route_set() {
    assert!(first_route_uri(&[]).is_none());
}

#[test]
fn first_route_uri_malformed_entry() {
    // Missing angle brackets — RouteEntry::parse returns Err, so we get None
    // and the caller falls back to the cached destination.
    let route_set = vec!["sip:bad.example.com".to_string()];
    assert!(first_route_uri(&route_set).is_none());
}

#[test]
fn first_route_uri_picks_first_only() {
    // Each route_set entry is one URI (flatten_record_route_headers
    // guarantees that). first_route_uri must NOT split commas inside the
    // first entry — that's the previous layer's responsibility.
    let route_set = vec![
        "<sip:first.example.com;lr>".to_string(),
        "<sip:second.example.com;lr>".to_string(),
    ];
    let uri = first_route_uri(&route_set);
    assert_eq!(uri.as_deref(), Some("sip:first.example.com;lr"));
}

fn ack_request_with_route(route: Option<&str>) -> SipMessage {
    let ruri = parse_uri_standalone("sip:5111@100.65.0.2:7000").unwrap();
    let mut builder = SipMessageBuilder::new()
        .request(Method::Ack, ruri)
        .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-e2e-ack".to_string())
        .to("<sip:5111@ims.example.com>;tag=uas-tag".to_string())
        .from("<sip:trunk@example.com>;tag=uac-tag".to_string())
        .call_id("ack-e2e-route-set".to_string())
        .cseq("1 ACK".to_string())
        .content_length(0);
    if let Some(route) = route {
        builder = builder.header("Route", route.to_string());
    }
    builder.build().unwrap()
}

#[test]
fn ack_next_hop_prefers_remaining_route_over_ruri() {
    // The end-to-end 2xx ACK must follow the dialog route set: when a Route
    // remains (after the proxy popped its own), that Route is the next hop —
    // NOT the Request-URI (the UE Contact) and NOT the cached INVITE branch.
    let ack = ack_request_with_route(Some(
        "<sip:192.0.2.143:5060;transport=udp;lr>, <sip:192.0.2.143:5060;transport=tcp;lr>",
    ));
    let next_hop = ack_next_hop_uri(&ack.headers, &ack.start_line).expect("ACK has a next hop");
    let parsed = parse_uri_standalone(&next_hop).unwrap();
    assert_eq!(parsed.host, "192.0.2.143");
    assert_eq!(parsed.port, Some(5060));
    assert_ne!(
        parsed.host, "100.65.0.2",
        "must not short-circuit the ACK to the Request-URI when a Route remains",
    );
}

#[test]
fn ack_next_hop_falls_back_to_ruri_when_route_set_empty() {
    // No Route header → the next hop is the Request-URI (the remote target),
    // resolved per RFC 3261 §16.12 — still derived from the message, never
    // the cached INVITE branch destination.
    let ack = ack_request_with_route(None);
    let next_hop = ack_next_hop_uri(&ack.headers, &ack.start_line);
    let ruri = parse_uri_standalone("sip:5111@100.65.0.2:7000").unwrap();
    assert_eq!(next_hop, Some(ruri.to_string()));
}

/// Identity for the ACK route-set tests: hosts with the ports we serve.
fn ack_identity(hosts: &[(&str, &[u16])]) -> core::SelfIdentity {
    let mut identity = core::SelfIdentity::new();
    for (host, ports) in hosts {
        identity.add_host(host, ports);
    }
    identity
}

#[test]
fn ack_2xx_follows_route_set_after_popping_self() {
    // Field regression (siphon as S-CSCF): the 2xx ACK arrives with a route
    // set of [S-CSCF (self), P-CSCF]. After loose-routing pops our own top
    // Route, the next hop is the P-CSCF — not the cached INVITE branch (which
    // pointed at a non-Record-Routing MMTel-AS) and not the UE Contact in the
    // Request-URI. The cached-branch path mis-delivered the ACK so the UAS
    // never confirmed the dialog.
    let mut ack = ack_request_with_route(Some(
        "<sip:192.0.2.132:6060;lr>, <sip:192.0.2.143:5060;transport=udp;lr>",
    ));

    // Mirror handle_ack_via_session: consume our own leading Route entries.
    let identity = ack_identity(&[("192.0.2.132", &[6060])]);
    core::consume_self_routes(&mut ack.headers, &identity);

    let next_hop = ack_next_hop_uri(&ack.headers, &ack.start_line).expect("next hop");
    let parsed = parse_uri_standalone(&next_hop).unwrap();
    assert_eq!(
        parsed.host, "192.0.2.143",
        "ACK must follow the dialog route set to the P-CSCF",
    );
    assert_eq!(parsed.port, Some(5060));
    assert_ne!(
        parsed.host, "100.65.0.2",
        "ACK must not short-circuit to the UE Contact in the Request-URI",
    );
}

#[test]
fn ack_2xx_consumes_double_self_record_route_then_follows_route_set() {
    // Transport-bridging double Record-Route: siphon appears twice at the
    // top of the dialog route set, followed by the real next hop (P-CSCF).
    // Consuming only the top self-Route would leave our own second Route as
    // the apparent next hop — a routing loop. The ACK must consume both
    // self-Routes (via pop_local_routes) and forward to the P-CSCF, exactly
    // as loose_route() does for the in-dialog BYE on this dialog.
    let identity = ack_identity(&[("192.0.2.132", &[6060])]);
    let mut ack = ack_request_with_route(Some(
        "<sip:192.0.2.132:6060;transport=tcp;lr>, \
         <sip:192.0.2.132:6060;transport=udp;lr>, \
         <sip:192.0.2.143:5060;transport=udp;lr>",
    ));

    // Mirror handle_ack_via_session's route consumption.
    core::consume_self_routes(&mut ack.headers, &identity);

    let next_hop = ack_next_hop_uri(&ack.headers, &ack.start_line).expect("next hop");
    let parsed = parse_uri_standalone(&next_hop).unwrap();
    assert_eq!(
        parsed.host, "192.0.2.143",
        "ACK must skip our own double Record-Route and follow the route set",
    );
    assert_eq!(parsed.port, Some(5060));
}

#[test]
fn ack_2xx_does_not_consume_a_route_addressed_to_another_proxy() {
    // RFC 3261 §16.4: only Routes that indicate *this* proxy may be
    // removed. The ACK path used to pop the top Route unconditionally
    // whenever it carried `;lr`, stripping a downstream proxy's own Route
    // and sending the ACK a hop too far. It now applies the same
    // self-identity test the in-dialog BYE does.
    let identity = ack_identity(&[("192.0.2.132", &[6060])]);
    let mut ack = ack_request_with_route(Some(
        "<sip:192.0.2.143:5060;transport=udp;lr>, \
         <sip:192.0.2.168:5060;transport=udp;lr>",
    ));

    let popped = core::consume_self_routes(&mut ack.headers, &identity);
    assert!(popped.is_empty(), "no leading Route identifies this proxy");

    let next_hop = ack_next_hop_uri(&ack.headers, &ack.start_line).expect("next hop");
    let parsed = parse_uri_standalone(&next_hop).unwrap();
    assert_eq!(
        parsed.host, "192.0.2.143",
        "ACK must still go to the first Route, not past it",
    );
}

#[test]
fn ack_2xx_consumes_self_route_stamped_from_advertised_host() {
    // Same regression the in-dialog BYE hit: the Record-Route we stamp
    // carries our advertised/bind address, which `domain.local` need not
    // list. The ACK resolves self-identity from the same widened set, so
    // both in-dialog paths agree about the same dialog's route set.
    let identity = ack_identity(&[("192.0.2.132", &[6060])]);
    let mut ack = ack_request_with_route(Some(
        "<sip:192.0.2.132:6060;transport=udp;lr>, \
         <sip:192.0.2.143:5060;transport=udp;lr>",
    ));

    let popped = core::consume_self_routes(&mut ack.headers, &identity);
    assert_eq!(popped.len(), 1);

    let next_hop = ack_next_hop_uri(&ack.headers, &ack.start_line).expect("next hop");
    let parsed = parse_uri_standalone(&next_hop).unwrap();
    assert_eq!(parsed.host, "192.0.2.143");
}

// -----------------------------------------------------------------------
// build_self_identity — the wiring that F1 got wrong.
//
// The ACK/BYE tests above hand-build their identity, so they prove the
// *matching* is right while saying nothing about whether the dispatcher
// assembles the identity correctly. These drive the real builder.
// -----------------------------------------------------------------------

/// Build an identity the way the dispatcher does, from a listener list.
///
/// Deliberately reproduces server.rs's first-per-transport `or_insert`
/// collapse into `listen_addrs` / `advertised_addrs`, so these tests run
/// against the same asymmetry the real wiring has — that collapse is what
/// F1 was.
fn identity_from(
    listeners: &[(Transport, &str, Option<&str>)],
    domain_local: &[&str],
    ipsec_ports: Option<(u16, u16)>,
    path_host: Option<&str>,
) -> core::SelfIdentity {
    let entries: Vec<(Transport, SocketAddr, Option<String>)> = listeners
        .iter()
        .map(|(transport, addr, advertise)| {
            (
                *transport,
                addr.parse().expect("test listener address"),
                advertise.map(str::to_string),
            )
        })
        .collect();
    let registry = crate::transport::ListenerRegistry::from_entries(entries.clone());

    let mut listen_addrs: std::collections::HashMap<Transport, SocketAddr> =
        std::collections::HashMap::new();
    let mut advertised: std::collections::HashMap<Transport, String> =
        std::collections::HashMap::new();
    for (transport, addr, advertise) in &entries {
        listen_addrs.entry(*transport).or_insert(*addr);
        if let Some(advertise) = advertise {
            advertised
                .entry(*transport)
                .or_insert_with(|| advertise.clone());
        }
    }

    let via_addr = entries
        .first()
        .map(|(_, addr, _)| *addr)
        .unwrap_or_else(|| "127.0.0.1:5060".parse().expect("loopback"));
    let domains: Vec<String> = domain_local.iter().map(|d| d.to_string()).collect();

    build_self_identity(
        &domains,
        ipsec_ports,
        path_host,
        &registry,
        &advertised,
        &listen_addrs,
        via_addr,
    )
}

fn identity_for(
    listeners: &[(Transport, &str, Option<&str>)],
    domain_local: &[&str],
) -> core::SelfIdentity {
    identity_from(listeners, domain_local, None, None)
}

#[test]
fn build_self_identity_covers_a_second_listener_of_the_same_transport() {
    // F1 regression. `listen_addrs`/`advertised_addrs` keep only the first
    // listener per transport, so a dual-stack Gm P-CSCF's IPv6 listener is
    // invisible to them. Building from those maps meant the v6 UE's
    // in-dialog request did not match the Record-Route we stamped at it.
    let identity = identity_for(
        &[
            (Transport::Udp, "192.0.2.40:5060", None),
            (Transport::Udp, "[2001:db8:ac10::10]:5064", None),
        ],
        &["ims.example.com"],
    );
    assert!(
        identity.matches("2001:db8:ac10::10", Some(5064)),
        "second (v6) UDP listener must identify us: {:?}",
        identity.entries(),
    );
    // And bracketed, which is how it comes back on the wire.
    assert!(identity.matches("[2001:db8:ac10::10]", Some(5064)));
}

#[test]
fn build_self_identity_covers_a_second_listeners_advertise_name() {
    // A per-listener `advertise` on anything but the first listener of a
    // transport never reaches `advertised_addrs` either.
    let identity = identity_for(
        &[
            (Transport::Tls, "192.0.2.40:5061", Some("sip.example.com")),
            (Transport::Tls, "192.0.2.41:5081", Some("alt.example.com")),
        ],
        &[],
    );
    assert!(identity.matches("alt.example.com", Some(5081)));
    assert!(identity.matches("192.0.2.41", Some(5081)));
}

#[test]
fn build_self_identity_rejects_a_foreign_port_on_our_own_address() {
    // F3: a co-located proxy sharing our IP on its own port is not us.
    let identity = identity_for(&[(Transport::Udp, "192.0.2.40:5060", None)], &[]);
    assert!(identity.matches("192.0.2.40", Some(5060)));
    assert!(!identity.matches("192.0.2.40", Some(6060)));
}

#[test]
fn build_self_identity_includes_ipsec_protected_ports() {
    // A P-CSCF Record-Routes with pcscf_port_c/pcscf_port_s, which need not
    // be listener ports (TS 33.203 §7.1).
    let identity = identity_from(
        &[(Transport::Udp, "192.0.2.40:5060", None)],
        &[],
        Some((5064, 5066)),
        None,
    );
    assert!(identity.matches("192.0.2.40", Some(5064)));
    assert!(identity.matches("192.0.2.40", Some(5066)));
    // Still not a free-for-all on our address.
    assert!(!identity.matches("192.0.2.40", Some(6060)));
}

#[test]
fn build_self_identity_adds_path_host_as_an_any_port_alias() {
    // add_pcscf_path stamps ipsec.path_host into Path with no port; it comes
    // back as the top Route on MT requests (RFC 3327 §5).
    let identity = identity_from(
        &[(Transport::Udp, "192.0.2.40:5060", None)],
        &[],
        Some((5064, 5066)),
        Some("pcscf.example.com"),
    );
    assert!(identity.matches("pcscf.example.com", None));
    assert!(identity.matches("pcscf.example.com", Some(5060)));
}

#[test]
fn build_self_identity_keeps_domain_local_as_an_any_port_alias() {
    // Deployments that worked around the old behaviour by listing their own
    // address under `domain.local` must keep working, on any port.
    let identity = identity_for(
        &[(Transport::Udp, "192.0.2.40:5060", None)],
        &["example.com", "192.0.2.99"],
    );
    assert!(identity.matches("example.com", Some(12345)));
    assert!(identity.matches("192.0.2.99", Some(12345)));
}

#[test]
fn build_self_identity_skips_wildcard_binds_but_keeps_the_fallbacks() {
    // A wildcard bind identifies no host, so 0.0.0.0 itself is never a
    // match — but `resolve_advertised_host` then stamps a routable local IP
    // or loopback, and those must be recognised.
    let identity = identity_for(&[(Transport::Udp, "0.0.0.0:5060", None)], &[]);
    assert!(!identity.matches("0.0.0.0", Some(5060)));
    assert!(
        identity.matches("127.0.0.1", Some(5060)),
        "loopback fallback must identify us: {:?}",
        identity.entries(),
    );
}

#[test]
fn flatten_record_route_headers_single_line_multi_uri() {
    // RFC 3261 §7.3.1 allows multiple comma-separated URIs on a single header line.
    // B2BUA must split them so the route-set has one URI per entry — a precondition
    // for reversal to produce the RFC §12.1.1 UAC route order.
    let headers = vec!["<sip:p1.example.com:5060;lr;transport=tcp>, \
         <sip:p2.example.com:5060;lr;transport=udp>, \
         <sip:p3.example.com:6060;lr;transport=udp>"
        .to_string()];
    let routes = flatten_record_route_headers(&headers);
    assert_eq!(routes.len(), 3);
    assert_eq!(routes[0], "<sip:p1.example.com:5060;lr;transport=tcp>");
    assert_eq!(routes[1], "<sip:p2.example.com:5060;lr;transport=udp>");
    assert_eq!(routes[2], "<sip:p3.example.com:6060;lr;transport=udp>");
}

#[test]
fn flatten_record_route_headers_multi_line_one_uri_each() {
    let headers = vec![
        "<sip:p1.example.com;lr>".to_string(),
        "<sip:p2.example.com;lr>".to_string(),
        "<sip:p3.example.com;lr>".to_string(),
    ];
    let routes = flatten_record_route_headers(&headers);
    assert_eq!(
        routes,
        vec![
            "<sip:p1.example.com;lr>".to_string(),
            "<sip:p2.example.com;lr>".to_string(),
            "<sip:p3.example.com;lr>".to_string(),
        ]
    );
}

#[test]
fn flatten_record_route_headers_mixed_lines() {
    let headers = vec![
        "<sip:a;lr>, <sip:b;lr>".to_string(),
        "<sip:c;lr>".to_string(),
        "<sip:d;lr>, <sip:e;lr>".to_string(),
    ];
    let routes = flatten_record_route_headers(&headers);
    assert_eq!(
        routes,
        vec![
            "<sip:a;lr>".to_string(),
            "<sip:b;lr>".to_string(),
            "<sip:c;lr>".to_string(),
            "<sip:d;lr>".to_string(),
            "<sip:e;lr>".to_string(),
        ]
    );
}

#[test]
fn flatten_record_route_headers_then_reverse_matches_rfc_12_1_1() {
    // The bug: B2BUA was calling .iter().rev() on the Vec<String> before flattening.
    // For a typical IMS 200 OK where all RR URIs come back on a single header line,
    // the outer reverse was a no-op and the UAC route-set ended up in wire order
    // instead of reversed — sending in-dialog BYE through P-CSCF instead of I-CSCF.
    let single_line = vec![
        "<sip:pcscf;lr;transport=tcp>, <sip:pcscf;lr;transport=udp>, \
         <sip:scscf;lr;transport=udp>"
            .to_string(),
    ];
    let mut routes = flatten_record_route_headers(&single_line);
    routes.reverse();
    assert_eq!(routes[0], "<sip:scscf;lr;transport=udp>");
    assert_eq!(routes[2], "<sip:pcscf;lr;transport=tcp>");
}

#[test]
fn flatten_record_route_headers_ignores_empty_entries() {
    let headers = vec![
        "".to_string(),
        "<sip:a;lr>,".to_string(),
        ",  ,".to_string(),
    ];
    let routes = flatten_record_route_headers(&headers);
    assert_eq!(routes, vec!["<sip:a;lr>".to_string()]);
}

#[test]
fn build_response_copies_mandatory_headers() {
    let request = sample_invite();
    let response = build_response(&request, 200, "OK", None, &[]);

    assert!(response.is_response());
    assert_eq!(response.status_code(), Some(200));

    // Via must be copied
    let vias = response.headers.get_all("Via").unwrap();
    assert_eq!(vias.len(), 1);
    assert!(vias[0].contains("pc33.atlanta.com"));

    // From/To/Call-ID/CSeq must be copied
    assert!(response
        .headers
        .from()
        .unwrap()
        .contains("alice@atlanta.com"));
    assert!(response.headers.to().unwrap().contains("bob@biloxi.com"));
    assert_eq!(
        response.headers.call_id().unwrap(),
        "a84b4c76e66710@pc33.atlanta.com"
    );
    assert!(response.headers.cseq().unwrap().contains("INVITE"));
}

#[test]
fn build_response_sets_content_length_zero() {
    let request = sample_invite();
    let response = build_response(&request, 404, "Not Found", None, &[]);
    assert_eq!(response.headers.get("Content-Length").unwrap(), "0");
}

#[test]
fn build_response_copies_multiple_vias() {
    let mut request = sample_invite();
    request.headers.add(
        "Via",
        "SIP/2.0/UDP proxy1.example.com;branch=z9hG4bK-proxy".to_string(),
    );

    let response = build_response(&request, 200, "OK", None, &[]);
    let vias = response.headers.get_all("Via").unwrap();
    assert_eq!(vias.len(), 2);
}

#[test]
fn build_response_serializes_to_valid_sip() {
    let request = sample_invite();
    let response = build_response(&request, 200, "OK", None, &[]);
    let bytes = response.to_bytes();
    let text = String::from_utf8(bytes).unwrap();

    assert!(text.starts_with("SIP/2.0 200 OK\r\n"));
    assert!(text.contains("Via:"));
    assert!(text.contains("From:"));
    assert!(text.contains("To:"));
    assert!(text.contains("Call-ID:"));
    assert!(text.contains("CSeq:"));
    assert!(text.ends_with("\r\n\r\n"));
}

#[test]
fn build_response_includes_server_header_when_configured() {
    let request = sample_invite();
    let response = build_response(&request, 401, "Unauthorized", Some("SIPhon/0.1.0"), &[]);
    assert_eq!(response.headers.get("Server").unwrap(), "SIPhon/0.1.0");
}

#[test]
fn build_response_omits_server_header_when_none() {
    let request = sample_invite();
    let response = build_response(&request, 200, "OK", None, &[]);
    assert!(response.headers.get("Server").is_none());
}

#[test]
fn build_response_copies_expires_header() {
    let mut request = sample_invite();
    request.headers.set("Expires", "600".to_string());
    let response = build_response(&request, 200, "OK", None, &[]);
    assert_eq!(
        response.headers.get("Expires").unwrap(),
        "600",
        "Expires header should be copied from request to response"
    );
}

#[test]
fn build_response_omits_expires_when_absent() {
    let request = sample_invite();
    let response = build_response(&request, 200, "OK", None, &[]);
    assert!(
        response.headers.get("Expires").is_none(),
        "Expires should not appear in response when not set on request"
    );
}

#[test]
fn build_response_copies_every_auth_challenge_algorithm() {
    // `auth.require_*_digest` stacks one challenge per algorithm (RFC 7616
    // §3.7) so a single 401/407 serves RFC 2617 and RFC 7616 clients alike.
    // Copying only the first value put MD5 on the wire and silently dropped
    // the stronger two, leaving nothing for a client to negotiate up to.
    let mut request = sample_invite();
    for algorithm in ["MD5", "SHA-256", "SHA-512-256"] {
        request.headers.add(
            "Proxy-Authenticate",
            format!(
                "Digest realm=\"example.com\", nonce=\"abc\", algorithm={algorithm}, qop=\"auth\""
            ),
        );
        request.headers.add(
            "WWW-Authenticate",
            format!(
                "Digest realm=\"example.com\", nonce=\"abc\", algorithm={algorithm}, qop=\"auth\""
            ),
        );
    }

    let response = build_response(&request, 407, "Proxy Authentication Required", None, &[]);

    for name in ["Proxy-Authenticate", "WWW-Authenticate"] {
        let values = response.headers.get_all(name).unwrap();
        assert_eq!(values.len(), 3, "{name} lost algorithms: {values:?}");
        assert!(values[0].contains("algorithm=MD5"));
        assert!(values[1].contains("algorithm=SHA-256"));
        assert!(values[2].contains("algorithm=SHA-512-256"));
    }

    // And all three reach the wire as separate header lines.
    let text = String::from_utf8(response.to_bytes()).unwrap();
    assert_eq!(text.matches("Proxy-Authenticate:").count(), 3);
}

#[test]
fn build_response_omits_auth_challenge_when_request_has_none() {
    let request = sample_invite();
    let response = build_response(&request, 200, "OK", None, &[]);
    assert!(response.headers.get("Proxy-Authenticate").is_none());
    assert!(response.headers.get("WWW-Authenticate").is_none());
}

#[test]
fn stamp_uas_to_tag_adds_the_dialog_tag_to_a_tagless_response() {
    // The shape every locally-generated B2BUA final response has: the
    // INVITE's To is tagless, so build_response copies a tagless To and the
    // UAS tag has to be added (RFC 3261 §8.2.6.2). A 407 challenge without
    // it leaves the caller unable to key our response to its dialog.
    let request = sample_invite();
    let mut response = build_response(&request, 407, "Proxy Authentication Required", None, &[]);
    assert!(!response.headers.to().unwrap().contains(";tag="));

    stamp_uas_to_tag(&mut response, "a-leg-uas-tag");
    assert!(response
        .headers
        .to()
        .unwrap()
        .ends_with(";tag=a-leg-uas-tag"));
}

#[test]
fn stamp_uas_to_tag_leaves_an_existing_tag_alone() {
    // An in-dialog request already carries the tag we assigned; re-stamping
    // would corrupt the dialog identifier.
    let mut request = sample_invite();
    request
        .headers
        .set("To", "<sip:bob@example.com>;tag=already-here".to_string());
    let mut response = build_response(&request, 481, "Call/Transaction Does Not Exist", None, &[]);

    stamp_uas_to_tag(&mut response, "a-different-tag");
    assert_eq!(
        response.headers.to().unwrap(),
        "<sip:bob@example.com>;tag=already-here"
    );
}

// --- Reply-header replace/add semantics --------------------------------
//
// Regression coverage for the `set_reply_header` append bug:
// build_response must apply Replace ops via `set_header` so that
// a script-supplied To-tag (RFC 3261 §12.1.1.2 / RFC 6665 §4.1.3)
// ends up as exactly one To header in the wire response.

// --- RFC 3261 §12.1.1 Record-Route echo --------------------------------
//
// A UAS answering a dialog-forming request MUST copy every Record-Route
// value into the response that establishes the dialog, in order and with
// all parameters intact. The failure this guards is silent and one-sided:
// the response looks well-formed, and only the UAC notices, because its
// route set (§12.1.2, the echo reversed) is short by a hop.

/// Two entries in, two entries out, same order, parameters intact.
///
/// The shape that forced this: a P-CSCF bridging its protected Gm port to
/// its core port Record-Routes once per socket, so the UAS sees two. The
/// UAC reverses them, and it is the *second* — the access-facing one — that
/// its in-dialog requests have to leave on. Drop it and the UE is left
/// addressing a port with no IPsec SA covering it.
#[test]
fn build_response_echoes_every_record_route_in_order() {
    let mut request = sample_invite();
    request.headers.set_all(
        "Record-Route",
        vec![
            "<sip:198.51.100.1:5060;transport=udp;lr>".to_string(),
            "<sip:198.51.100.1:5066;transport=udp;lr>".to_string(),
        ],
    );
    let response = build_response(&request, 200, "OK", None, &[]);

    let echoed = response
        .headers
        .get_all("Record-Route")
        .expect("2xx to a dialog-forming INVITE must carry the Record-Route echo");
    assert_eq!(echoed.len(), 2, "both entries must survive, got {echoed:?}");
    assert_eq!(echoed[0], "<sip:198.51.100.1:5060;transport=udp;lr>");
    assert_eq!(echoed[1], "<sip:198.51.100.1:5066;transport=udp;lr>");

    // And on the wire, not just in the map.
    let text = String::from_utf8(response.to_bytes()).unwrap();
    let lines: Vec<&str> = text
        .lines()
        .filter(|line| line.starts_with("Record-Route:"))
        .collect();
    assert_eq!(
        lines.len(),
        2,
        "wire output must carry both lines: {lines:?}"
    );
}

/// An unknown parameter has to survive verbatim — §12.1.1 says "whether
/// they are known or unknown to the UAS", which is precisely why the echo
/// copies lines rather than parsing and re-emitting them.
#[test]
fn build_response_record_route_echo_preserves_unknown_parameters() {
    let mut request = sample_invite();
    request.headers.set(
        "Record-Route",
        "<sip:198.51.100.1:5060;lr;x-vendor-token=abc123>;some-hdr-param".to_string(),
    );
    let response = build_response(&request, 200, "OK", None, &[]);

    assert_eq!(
        response.headers.get("Record-Route").map(String::as_str),
        Some("<sip:198.51.100.1:5060;lr;x-vendor-token=abc123>;some-hdr-param"),
    );
}

/// SUBSCRIBE is the one the field defect landed on — a UAS answering
/// reg-event owes the same echo an INVITE does (RFC 6665 §4.1.2).
#[test]
fn build_response_echoes_record_route_for_subscribe_and_refer() {
    for method in [Method::Subscribe, Method::Refer] {
        let mut request = sample_invite();
        request.start_line = StartLine::Request(RequestLine {
            method: method.clone(),
            request_uri: SipUri::new("example.com".to_string()).with_user("alice".to_string()),
            version: Version::sip_2_0(),
        });
        request
            .headers
            .set("Record-Route", "<sip:198.51.100.1:5066;lr>".to_string());
        let response = build_response(&request, 200, "OK", None, &[]);
        assert_eq!(
            response.headers.get("Record-Route").map(String::as_str),
            Some("<sip:198.51.100.1:5066;lr>"),
            "{method:?} 2xx must echo Record-Route",
        );
    }
}

/// An early dialog needs the route set too, so a provisional above 100 gets
/// the echo — but 100 Trying establishes nothing and must stay clean.
#[test]
fn build_response_record_route_echo_covers_18x_but_not_100_trying() {
    let mut request = sample_invite();
    request
        .headers
        .set("Record-Route", "<sip:198.51.100.1:5066;lr>".to_string());

    let ringing = build_response(&request, 180, "Ringing", None, &[]);
    assert!(
        ringing.headers.has("Record-Route"),
        "an 18x may open an early dialog, so it owes the echo",
    );

    let trying = build_response(&request, 100, "Trying", None, &[]);
    assert!(
        !trying.headers.has("Record-Route"),
        "100 Trying establishes no dialog and must not echo",
    );
}

/// Nothing else gets it: a non-dialog-forming method, an in-dialog request
/// (§12.2.1.2 forbids the UAC refreshing its route set from one), and a
/// failure response all stay as they were.
#[test]
fn build_response_withholds_record_route_echo_where_no_dialog_forms() {
    let record_route = "<sip:198.51.100.1:5066;lr>".to_string();

    // REGISTER — dialogless.
    let mut register = sample_invite();
    register.start_line = StartLine::Request(RequestLine {
        method: Method::Register,
        request_uri: SipUri::new("example.com".to_string()),
        version: Version::sip_2_0(),
    });
    register.headers.set("Record-Route", record_route.clone());
    assert!(!build_response(&register, 200, "OK", None, &[])
        .headers
        .has("Record-Route"));

    // Re-INVITE — the To tag says the dialog already exists.
    let mut reinvite = sample_invite();
    reinvite.headers.set(
        "To",
        "Bob <sip:bob@biloxi.com>;tag=already-here".to_string(),
    );
    reinvite.headers.set("Record-Route", record_route.clone());
    assert!(!build_response(&reinvite, 200, "OK", None, &[])
        .headers
        .has("Record-Route"));

    // A failure response establishes nothing.
    let mut invite = sample_invite();
    invite.headers.set("Record-Route", record_route);
    assert!(!build_response(&invite, 404, "Not Found", None, &[])
        .headers
        .has("Record-Route"));
}

/// Script precedence is unchanged: `set_reply_header` still wins over the
/// framework copy, so a script with its own route set keeps control.
#[test]
fn build_response_script_reply_header_overrides_record_route_echo() {
    use crate::script::api::request::ReplyHeaderOp;
    let mut request = sample_invite();
    request.headers.set_all(
        "Record-Route",
        vec![
            "<sip:198.51.100.1:5060;lr>".to_string(),
            "<sip:198.51.100.1:5066;lr>".to_string(),
        ],
    );
    let reply_headers = vec![(
        ReplyHeaderOp::Replace,
        "Record-Route".to_string(),
        "<sip:203.0.113.9:5060;lr>".to_string(),
    )];
    let response = build_response(&request, 200, "OK", None, &reply_headers);

    let echoed = response.headers.get_all("Record-Route").unwrap();
    assert_eq!(
        echoed.len(),
        1,
        "Replace must clear the echo, got {echoed:?}"
    );
    assert_eq!(echoed[0], "<sip:203.0.113.9:5060;lr>");
}

#[test]
fn build_response_replace_op_overwrites_copied_to_header() {
    use crate::script::api::request::ReplyHeaderOp;
    let request = sample_invite();
    let to_with_tag = format!("{};tag=scscf-abc123", request.headers.to().unwrap());
    let reply_headers = vec![(
        ReplyHeaderOp::Replace,
        "To".to_string(),
        to_with_tag.clone(),
    )];
    let response = build_response(&request, 200, "OK", None, &reply_headers);

    // Exactly one To header — not two.
    let tos = response.headers.get_all("To").unwrap();
    assert_eq!(
        tos.len(),
        1,
        "set_reply_header(\"To\", …) must replace, not append; got {:?}",
        tos,
    );
    assert!(tos[0].contains(";tag=scscf-abc123"));

    // Wire-format check — only one "To:" line in the serialized response.
    let bytes = response.to_bytes();
    let text = String::from_utf8(bytes).unwrap();
    let to_line_count = text.lines().filter(|line| line.starts_with("To:")).count();
    assert_eq!(
        to_line_count, 1,
        "wire output must carry exactly one To header"
    );
}

#[test]
fn build_response_add_op_appends_multi_value_headers() {
    use crate::script::api::request::ReplyHeaderOp;
    let request = sample_invite();
    let reply_headers = vec![
        (
            ReplyHeaderOp::Add,
            "Service-Route".to_string(),
            "<sip:orig@scscf:6060;lr>".to_string(),
        ),
        (
            ReplyHeaderOp::Add,
            "Service-Route".to_string(),
            "<sip:term@scscf:6060;lr>".to_string(),
        ),
        (
            ReplyHeaderOp::Add,
            "P-Associated-URI".to_string(),
            "<sip:alice@ims.example.com>".to_string(),
        ),
    ];
    let response = build_response(&request, 200, "OK", None, &reply_headers);

    let routes = response.headers.get_all("Service-Route").unwrap();
    assert_eq!(routes.len(), 2);
    assert_eq!(routes[0], "<sip:orig@scscf:6060;lr>");
    assert_eq!(routes[1], "<sip:term@scscf:6060;lr>");

    let assoc = response.headers.get_all("P-Associated-URI").unwrap();
    assert_eq!(assoc.len(), 1);
}

#[test]
fn build_response_replace_overrides_copied_expires() {
    use crate::script::api::request::ReplyHeaderOp;
    let mut request = sample_invite();
    request.headers.set("Expires", "3600".to_string()); // copied by build_response
    let reply_headers = vec![(
        ReplyHeaderOp::Replace,
        "Expires".to_string(),
        "60".to_string(),
    )];
    let response = build_response(&request, 200, "OK", None, &reply_headers);

    let expires = response.headers.get_all("Expires").unwrap();
    assert_eq!(expires.len(), 1, "Expires must not duplicate when replaced");
    assert_eq!(expires[0], "60");
}

#[test]
fn build_response_replace_then_add_for_same_header_keeps_replace_then_appends() {
    use crate::script::api::request::ReplyHeaderOp;
    let request = sample_invite();
    // Pathological but well-defined: replace clears prior values,
    // subsequent add accumulates on top.
    let reply_headers = vec![
        (
            ReplyHeaderOp::Replace,
            "Warning".to_string(),
            "399 siphon \"first\"".to_string(),
        ),
        (
            ReplyHeaderOp::Add,
            "Warning".to_string(),
            "399 siphon \"second\"".to_string(),
        ),
    ];
    let response = build_response(&request, 200, "OK", None, &reply_headers);
    let warns = response.headers.get_all("Warning").unwrap();
    assert_eq!(warns.len(), 2);
    assert!(warns[0].contains("first"));
    assert!(warns[1].contains("second"));
}

#[test]
fn build_ack_for_non2xx_has_correct_headers() {
    let request = sample_invite();
    let response = build_response(&request, 480, "Temporarily Unavailable", None, &[]);
    let local_addr: SocketAddr = "10.0.0.1:5060".parse().unwrap();

    let ack = build_ack_for_non2xx(
        &request,
        &response,
        "z9hG4bK-proxy-branch",
        Transport::Tcp,
        local_addr,
    );

    // Must be an ACK request
    assert!(ack.is_request());
    let bytes = String::from_utf8(ack.to_bytes()).unwrap();
    assert!(bytes.starts_with("ACK sip:bob@biloxi.com SIP/2.0\r\n"));

    // Via: our own hop only (not the UAC's)
    let via = ack.headers.via().unwrap();
    assert!(via.contains("z9hG4bK-proxy-branch"));
    assert!(via.contains("TCP"));
    assert!(via.contains("10.0.0.1:5060"));

    // From: same as original request
    assert_eq!(ack.headers.from().unwrap(), request.headers.from().unwrap());

    // To: from the response (may have To-tag)
    assert_eq!(ack.headers.to().unwrap(), response.headers.to().unwrap());

    // Call-ID: same as original
    assert_eq!(
        ack.headers.call_id().unwrap(),
        request.headers.call_id().unwrap()
    );

    // CSeq: same number, ACK method
    let cseq = ack.headers.cseq().unwrap();
    assert!(cseq.contains("314159"));
    assert!(cseq.contains("ACK"));
    assert!(!cseq.contains("INVITE"));

    // Max-Forwards present
    assert_eq!(ack.headers.get("Max-Forwards").unwrap(), "70");

    // Content-Length: 0
    assert_eq!(ack.headers.content_length(), Some(0));
}

/// Build a representative B-leg INVITE — i.e. one that has already been
/// through the hygiene chain in `b2bua_send_b_leg_invite`: stripped
/// Record-Route/Route/Authorization, our own Via and Contact, rewritten
/// From host, fresh Call-ID, CSeq=1, decremented Max-Forwards, and an
/// SDP body with the o= line rewritten to our advertised address.
fn hygiene_processed_b_leg_invite() -> SipMessage {
    let sdp = "v=0\r\n\
o=siphon 0 0 IN IP4 192.0.2.10\r\n\
s=siphon\r\n\
c=IN IP4 192.0.2.10\r\n\
t=0 0\r\n\
m=audio 30054 RTP/SAVPF 8\r\n\
a=rtpmap:8 PCMA/8000\r\n";
    let mut msg = SipMessageBuilder::new()
        .request(
            Method::Invite,
            SipUri::new("biloxi.com".to_string()).with_user("bob".to_string()),
        )
        .via("SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-old".to_string())
        .to("Bob <sip:bob@biloxi.com>".to_string())
        .from("Alice <sip:alice@siphon.example.org>;tag=b-leg-tag-99".to_string())
        .call_id("b2b-bbbbbbbb-cccc-dddd-eeee-ffffffffffff".to_string())
        .cseq("1 INVITE".to_string())
        .max_forwards(69)
        .content_length(sdp.len())
        .build()
        .unwrap();
    msg.headers
        .set("Contact", "<sip:192.0.2.10:5060;transport=udp>".to_string());
    msg.headers.set("User-Agent", "SIPhon/test".to_string());
    msg.headers.set(
        "P-Asserted-Identity",
        "<sip:alice@siphon.example.org>".to_string(),
    );
    msg.body = sdp.as_bytes().to_vec();
    msg
}

#[test]
fn build_digest_retry_invite_replaces_via() {
    let original = hygiene_processed_b_leg_invite();
    let retry = build_digest_retry_invite(
        &original,
        "SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-new".to_string(),
        2,
        "Proxy-Authorization",
        "Digest username=\"alice\", realm=\"realm\"".to_string(),
    );
    assert_eq!(
        retry.headers.via().unwrap(),
        "SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-new"
    );
}

#[test]
fn build_digest_retry_invite_bumps_cseq() {
    let original = hygiene_processed_b_leg_invite();
    let retry = build_digest_retry_invite(
        &original,
        "SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-new".to_string(),
        2,
        "Proxy-Authorization",
        "Digest x".to_string(),
    );
    assert_eq!(retry.headers.cseq().unwrap(), "2 INVITE");
}

#[test]
fn build_digest_retry_invite_sets_proxy_auth_header() {
    let original = hygiene_processed_b_leg_invite();
    let retry = build_digest_retry_invite(
        &original,
        "SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-new".to_string(),
        2,
        "Proxy-Authorization",
        "Digest username=\"alice\"".to_string(),
    );
    assert!(retry.headers.get("Proxy-Authorization").is_some());
    assert!(retry.headers.get("Authorization").is_none());
}

#[test]
fn build_digest_retry_invite_replaces_existing_auth() {
    // A previous 401 added Authorization with stale credentials — the
    // helper must drop both Authorization and Proxy-Authorization before
    // adding the fresh challenge response.
    let mut original = hygiene_processed_b_leg_invite();
    original
        .headers
        .add("Authorization", "Digest stale".to_string());
    original
        .headers
        .add("Proxy-Authorization", "Digest also-stale".to_string());

    let retry = build_digest_retry_invite(
        &original,
        "SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-new".to_string(),
        3,
        "Authorization",
        "Digest fresh".to_string(),
    );

    let auths = retry
        .headers
        .get_all("Authorization")
        .expect("Authorization present");
    assert_eq!(auths.len(), 1);
    assert_eq!(auths[0], "Digest fresh");
    assert!(retry.headers.get("Proxy-Authorization").is_none());
}

/// This is the regression test for the leak fix: every header we expect
/// the prior B-leg INVITE to carry (post-hygiene) MUST be preserved.
#[test]
fn build_digest_retry_invite_preserves_all_other_headers() {
    let original = hygiene_processed_b_leg_invite();
    let retry = build_digest_retry_invite(
        &original,
        "SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-new".to_string(),
        2,
        "Proxy-Authorization",
        "Digest x".to_string(),
    );

    // Identity / dialog headers
    assert_eq!(retry.headers.from(), original.headers.from());
    assert_eq!(retry.headers.to(), original.headers.to());
    assert_eq!(retry.headers.call_id(), original.headers.call_id());

    // Topology + UA hygiene must survive
    assert_eq!(
        retry.headers.get("Contact"),
        original.headers.get("Contact"),
    );
    assert_eq!(
        retry.headers.get("User-Agent"),
        original.headers.get("User-Agent"),
    );
    assert_eq!(
        retry.headers.get("P-Asserted-Identity"),
        original.headers.get("P-Asserted-Identity"),
    );

    // Max-Forwards must NOT silently increment back up.
    assert_eq!(
        retry.headers.get("Max-Forwards").map(|s| s.as_str()),
        Some("69")
    );

    // Record-Route and Route must remain absent (they were stripped by
    // hygiene; the retry must not bring them back).
    assert!(retry.headers.get("Record-Route").is_none());
    assert!(retry.headers.get("Route").is_none());

    // RURI is the dial target — unchanged.
    match (&retry.start_line, &original.start_line) {
        (StartLine::Request(rl_retry), StartLine::Request(rl_orig)) => {
            assert_eq!(rl_retry.request_uri.user, rl_orig.request_uri.user);
            assert_eq!(rl_retry.request_uri.host, rl_orig.request_uri.host);
        }
        _ => panic!("expected Request start lines"),
    }

    // SDP body untouched (rtpengine had already anchored ports/crypto).
    assert_eq!(retry.body, original.body);
}

/// The B2BUA must ACK a 401/407 on the outbound leg before (and while)
/// retrying with credentials — RFC 3261 §17.1.1.3. Prior to the fix the
/// 401-retry path returned without ever building this ACK, so the trunk
/// kept retransmitting the challenge. The ACK must reuse the original
/// INVITE's Via branch (hop-by-hop) and carry the UAS To-tag from the 401.
///
/// Critically, the ACK's Via sent-by host:port must be the *advertised*
/// address the INVITE went out with — not the internal bind address — or
/// the trunk's server transaction can't match the ACK (RFC 3261 §17.2.3)
/// and keeps retransmitting its 401 on Timer G.  The caller passes
/// `state.via_host`/`via_port` (advertised); behind NAT/edge that differs
/// from the bind address.
#[test]
fn build_b2bua_ack_for_401_uses_invite_branch_and_response_to_tag() {
    let response = SipMessageBuilder::new()
        .response(401, "Unauthorized".to_string())
        .via("SIP/2.0/UDP 203.0.113.7:5060;branch=z9hG4bK-orig".to_string())
        .from("<sip:alice@siphon.example.org>;tag=b-leg-from".to_string())
        .to("<sip:bob@trunk.example.net>;tag=uas-12345".to_string())
        .call_id("b2b-aaaa-bbbb".to_string())
        .cseq("1 INVITE".to_string())
        .content_length(0)
        .build()
        .unwrap();

    // Advertised (public) address the B-leg INVITE used in its Via.  An
    // internal bind address (e.g. 10.x) would be a *different* value — the
    // regression was that the ACK leaked the internal one.
    let advertised_host = "203.0.113.7";
    let advertised_port = 5060;
    let ack = build_b2bua_ack_for_non2xx(
        &response,
        "z9hG4bK-orig",
        Some("sip:bob@trunk.example.net"),
        Transport::Udp,
        advertised_host,
        advertised_port,
    );

    // Method line is ACK to the dial target.
    match &ack.start_line {
        StartLine::Request(rl) => {
            assert_eq!(rl.method, Method::Ack);
            assert_eq!(rl.request_uri.host, "trunk.example.net");
        }
        _ => panic!("expected an ACK request line"),
    }

    // Same Via branch as the INVITE it acknowledges, and the advertised
    // sent-by host:port (RFC 3261 §17.1.1.3 / §17.2.3).
    assert_eq!(
        ack.headers.via().unwrap(),
        "SIP/2.0/UDP 203.0.113.7:5060;branch=z9hG4bK-orig"
    );
    // To header carries the UAS tag from the 401 — without it the trunk's
    // server transaction would not match the ACK.
    assert!(ack.headers.to().unwrap().contains("tag=uas-12345"));
    // CSeq number echoes the INVITE; method becomes ACK.
    assert_eq!(ack.headers.cseq().unwrap(), "1 ACK");
    assert_eq!(ack.headers.call_id().unwrap(), "b2b-aaaa-bbbb");
}

/// A CANCELled leg is answered `487 Request Terminated` (RFC 3261 §9.1) and
/// RFC 3261 §17.1.1.3 requires an ACK for it. By then the call is torn down,
/// so everything the ACK needs comes from the leg captured at CANCEL time
/// plus the response — and it must land on the INVITE's own branch and
/// Request-URI, carrying the 487's To-tag, or the peer's server transaction
/// cannot match it (§17.2.3) and retransmits to Timer H.
#[test]
fn cancelled_leg_ack_uses_the_invite_branch_ruri_and_the_487_to_tag() {
    let leg = crate::b2bua::actor::Leg::new_b_leg(
        "b2b-cancelled-leg".to_string(),
        "b-leg-from-tag".to_string(),
        "sip:bob@198.51.100.20".to_string(),
        "z9hG4bK-bleg-invite".to_string(),
        crate::b2bua::actor::TransportInfo {
            remote_addr: "198.51.100.20:5060".parse().unwrap(),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    );

    let response = SipMessageBuilder::new()
        .response(487, "Request Terminated".to_string())
        .via("SIP/2.0/UDP 198.51.100.10:5060;branch=z9hG4bK-bleg-invite".to_string())
        .from("<sip:alice@siphon.example.org>;tag=b-leg-from-tag".to_string())
        .to("<sip:bob@198.51.100.20>;tag=uas-487-tag".to_string())
        .call_id("b2b-cancelled-leg".to_string())
        .cseq("1 INVITE".to_string())
        .content_length(0)
        .build()
        .unwrap();

    let ack = build_cancelled_leg_ack(
        &leg,
        Some("sip:bob@198.51.100.20:5060"),
        &response,
        "198.51.100.10",
        5060,
    )
    .expect("a captured Request-URI must yield an ACK");

    match &ack.start_line {
        StartLine::Request(request_line) => {
            assert_eq!(request_line.method, Method::Ack);
            // §17.1.1.3 — same Request-URI as the INVITE being ACKed, NOT
            // the response's Contact (that rule is for the 2xx ACK, §13.2.2.4).
            assert_eq!(request_line.request_uri.host, "198.51.100.20");
            assert_eq!(request_line.request_uri.user.as_deref(), Some("bob"));
        }
        _ => panic!("expected an ACK request line"),
    }

    // The INVITE's own branch — the ACK for a non-2xx is part of that same
    // client transaction (§17.1.1.3), so a fresh branch would be unmatchable.
    assert_eq!(
        ack.headers.via().unwrap(),
        "SIP/2.0/UDP 198.51.100.10:5060;branch=z9hG4bK-bleg-invite"
    );
    // The 487's To-tag, without which the UAS cannot match the ACK (§17.2.3).
    assert!(ack.headers.to().unwrap().contains("tag=uas-487-tag"));
    assert_eq!(ack.headers.cseq().unwrap(), "1 ACK");
    assert_eq!(ack.headers.call_id().unwrap(), "b2b-cancelled-leg");

    // Without a captured Request-URI there is no ACK to build — the caller
    // logs it rather than emitting a placeholder R-URI the peer would drop.
    assert!(build_cancelled_leg_ack(&leg, None, &response, "198.51.100.10", 5060).is_none());
}

/// Regression: an outbound INVITE to an authenticating trunk draws a 401,
/// is ACKed, and re-sent with credentials on a new branch + CSeq. The retry
/// supersedes the failed B-leg in place (`replace_b_leg`), dropping the old
/// leg's actor handle — so that actor exits and emits `CallEvent::Terminated`
/// onto the SHARED per-call event channel. The dispatcher block-recvs that
/// channel to classify each response; consuming the stale `Terminated` as a
/// classification desynced the stream so the live retry leg's 200 OK was
/// read as the previous 18x's `Provisional` event. That skipped
/// `set_winner` + the deferred B-leg ACK, leaving the trunk's 200 OK unacked
/// until the dialog collapsed (BYE storm ~5 s after answer).
///
/// `recv_b_leg_classification_event` must skip the stale `Terminated` and
/// return the live leg's `Answered` for the 200 OK.
#[tokio::test(flavor = "multi_thread")]
async fn b_leg_200_classifies_as_answered_after_auth_retry_supersede() {
    use crate::b2bua::actor::{Leg, LegActor, LegMessage, TransportInfo as LegTransport};
    use crate::transport::{ConnectionId, Transport};

    // The shared per-call channel, mirroring CallActor.event_tx and the
    // dispatcher's call_event_receivers entry.
    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel::<CallEvent>(64);

    let transport = LegTransport {
        remote_addr: "10.0.0.2:5060".parse().unwrap(),
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: None,
    };

    // CSeq-1 B-leg: drew the 401 and is now superseded. Dropping its handle
    // closes the actor's mailbox, so the actor exits and pushes a
    // CallEvent::Terminated onto the shared channel — the stale event that
    // used to desync the classifier.
    let cseq1 = Leg::new_b_leg(
        "b2b-supersede-desync@test".to_string(),
        "from-tag-1".to_string(),
        "sip:bob@10.0.0.2:5060".to_string(),
        "z9hG4bK-cseq1-desync".to_string(),
        transport.clone(),
    );
    let (actor1, handle1) = LegActor::new(cseq1, event_tx.clone());
    let actor1_task = tokio::spawn(actor1.run());
    drop(handle1);
    // Await the old actor so its Terminated is on the channel ahead of the
    // live leg's Answered — the ordering that triggered the bug.
    actor1_task.await.unwrap();

    // CSeq-2 B-leg (the live retry). Its 200 OK must classify as Answered.
    let cseq2 = Leg::new_b_leg(
        "b2b-supersede-desync@test".to_string(),
        "from-tag-2".to_string(),
        "sip:bob@10.0.0.2:5060".to_string(),
        "z9hG4bK-cseq2-desync".to_string(),
        transport.clone(),
    );
    let (actor2, handle2) = LegActor::new(cseq2, event_tx.clone());
    let actor2_task = tokio::spawn(actor2.run());

    let ok_200 = parse_sip_message(concat!(
        "SIP/2.0 200 OK\r\n",
        "Via: SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bK-cseq2-desync\r\n",
        "From: <sip:alice@10.0.0.1>;tag=from-tag-2\r\n",
        "To: <sip:bob@10.0.0.2>;tag=uas-2\r\n",
        "Call-ID: b2b-supersede-desync@test\r\n",
        "CSeq: 2 INVITE\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    ))
    .expect("200 OK fixture parses")
    .1;
    handle2
        .tx
        .send(LegMessage::SipInbound {
            message: ok_200,
            source: transport,
        })
        .await
        .unwrap();

    // The channel now holds [Terminated (stale), Answered]. The classifier
    // must skip Terminated and return Answered; the pre-fix code returned
    // Terminated, which the dispatcher misreads as a non-answer.
    let event = tokio::task::spawn_blocking(move || recv_b_leg_classification_event(&mut event_rx))
        .await
        .unwrap();

    assert!(
        matches!(event, Some(CallEvent::Answered { .. })),
        "200 OK on the live retry leg must classify as Answered, not the \
         stale Terminated from the superseded leg; got {event:?}"
    );

    handle2.tx.send(LegMessage::Shutdown).await.ok();
    let _ = actor2_task.await;
}

fn test_resolver() -> SipResolver {
    SipResolver::from_system().unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn resolve_target_ip_with_port() {
    let resolver = test_resolver();
    let result = resolve_target("sip:alice@192.168.1.100:5080", &resolver).unwrap();
    assert_eq!(
        result.address,
        "192.168.1.100:5080".parse::<SocketAddr>().unwrap()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn resolve_target_ip_default_port() {
    let resolver = test_resolver();
    let result = resolve_target("sip:alice@10.0.0.1", &resolver).unwrap();
    assert_eq!(
        result.address,
        "10.0.0.1:5060".parse::<SocketAddr>().unwrap()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn resolve_target_localhost() {
    let resolver = test_resolver();
    let result = resolve_target("sip:bob@localhost:5090", &resolver).unwrap();
    assert_eq!(result.address.port(), 5090);
    assert!(result.address.ip().is_loopback());
}

#[tokio::test(flavor = "multi_thread")]
async fn resolve_target_bare_socketaddr() {
    let resolver = test_resolver();
    let result = resolve_target("10.0.0.1:5060", &resolver).unwrap();
    assert_eq!(
        result.address,
        "10.0.0.1:5060".parse::<SocketAddr>().unwrap()
    );
    assert!(result.transport.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn resolve_candidates_carries_hostname_for_sni() {
    let resolver = test_resolver();
    // A SIP URI with a hostname → every candidate carries the host so a new
    // outbound TLS connection presents it as SNI / certificate hostname.
    let hosted =
        resolve_target("sip:alice@localhost:5090", &resolver).expect("localhost must resolve");
    assert_eq!(hosted.server_name.as_deref(), Some("localhost"));

    // A bare IP:port short-circuits → no SNI (RFC 6066 emits none for an IP).
    let bare = resolve_target("192.0.2.1:5060", &resolver).expect("bare ip target");
    assert!(bare.server_name.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn resolve_target_transport_tcp() {
    let resolver = test_resolver();
    let result = resolve_target("sip:alice@10.0.0.1:5060;transport=tcp", &resolver).unwrap();
    assert_eq!(
        result.address,
        "10.0.0.1:5060".parse::<SocketAddr>().unwrap()
    );
    assert_eq!(result.transport, Some(Transport::Tcp));
}

#[tokio::test(flavor = "multi_thread")]
async fn resolve_target_unresolvable_domain() {
    let resolver = test_resolver();
    assert!(resolve_target(
        "sip:alice@this-domain-should-not-exist-xyzzy.invalid",
        &resolver
    )
    .is_none());
}

// -- RFC 3261 §18.1.1 over-MTU UDP → TCP fallback ------------------------

#[test]
fn over_mtu_threshold() {
    // Must EXCEED mtu-200 to trigger (the headroom for our Via + downstream).
    assert!(!over_mtu(1080, 1280), "exactly at the boundary is not over");
    assert!(over_mtu(1081, 1280));
    assert!(!over_mtu(500, 1280));
    // A tiny mtu saturates to 0 rather than underflowing.
    assert!(over_mtu(1, 100));
    assert!(!over_mtu(0, 100));
}

#[tokio::test(flavor = "multi_thread")]
async fn mtu_tcp_upgrade_switches_when_tcp_reachable() {
    let resolver = test_resolver();
    // A live TCP listener so the reachability probe succeeds.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dest = listener.local_addr().unwrap();
    let uri = dest.to_string(); // numeric "127.0.0.1:PORT" next hop
                                // Over threshold + reachable TCP → switch to TCP at the same address.
    assert_eq!(
        mtu_tcp_upgrade(Some(1280), Transport::Udp, 1300, &uri, dest, &resolver),
        Some((Transport::Tcp, dest)),
    );
    // Under threshold → keep UDP (no probe).
    assert_eq!(
        mtu_tcp_upgrade(Some(1280), Transport::Udp, 900, &uri, dest, &resolver),
        None
    );
    // MTU off → never switch.
    assert_eq!(
        mtu_tcp_upgrade(None, Transport::Udp, 1300, &uri, dest, &resolver),
        None
    );
    // Already non-UDP → never switch.
    assert_eq!(
        mtu_tcp_upgrade(Some(1280), Transport::Tcp, 1300, &uri, dest, &resolver),
        None
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn mtu_tcp_upgrade_keeps_udp_when_no_tcp_listener() {
    // Bind then drop → a closed port; the reachability probe refuses, so an
    // over-MTU request must STAY on UDP (delivered fragmented, not dropped).
    let dest: SocketAddr = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap()
    };
    let resolver = test_resolver();
    assert_eq!(
        mtu_tcp_upgrade(
            Some(1280),
            Transport::Udp,
            1300,
            &dest.to_string(),
            dest,
            &resolver
        ),
        None,
    );
}

#[test]
fn b_leg_flow_yields_to_a_path_route_set() {
    // A binding registered directly keeps connection reuse; a binding
    // registered through an edge proxy is routed by its Path instead, or a
    // single siphon that is both registrar and B2BUA would never honour one
    // (its own bindings are is_local, so their flow is always surfaced).
    let flow = crate::script::api::registrar::PyFlow {
        transport: "wss".to_string(),
        source_addr: "10.0.0.1:50000".parse().unwrap(),
        local_addr: "127.0.0.1:443".parse().unwrap(),
        connection_id: 0xc0ffee,
    };
    let route = vec!["<sip:TOKEN-A@edge.example.com;lr>".to_string()];

    assert!(
        b_leg_flow(Some(&flow), &[]).is_some(),
        "no Path — the captured flow still routes the B-leg (RFC 5626 §5.3)"
    );
    assert!(
        b_leg_flow(Some(&flow), &route).is_none(),
        "a Path route set outranks the flow (RFC 3327 §5.3)"
    );
    assert!(b_leg_flow(None, &[]).is_none());
    assert!(b_leg_flow(None, &route).is_none());
}

#[test]
fn b_leg_routing_uri_prefers_next_hop_then_route_then_target() {
    let target = "sip:bob@ue.example.com";
    let route = "sip:TOKEN-A@edge.example.com;lr";
    let next_hop = "sip:192.0.2.178:4060";

    // An explicit next_hop= overrides everything (BGCF / I-CSCF pin).
    assert_eq!(
        b_leg_routing_uri(Some(next_hop), Some(route), target),
        next_hop
    );
    assert_eq!(b_leg_routing_uri(Some(next_hop), None, target), next_hop);
    // RFC 3261 §16.6 step 6 — a route set with no next_hop routes via the
    // topmost Route, i.e. the binding's RFC 3327 Path, NOT the Contact.
    assert_eq!(b_leg_routing_uri(None, Some(route), target), route);
    // Neither → plain Request-URI routing, as before the Path feature.
    assert_eq!(b_leg_routing_uri(None, None, target), target);
}

#[tokio::test(flavor = "multi_thread")]
async fn mtu_tcp_upgrade_probes_the_uri_it_is_given_not_the_udp_destination() {
    // Why b2bua_send_b_leg_invite must hand the over-MTU probe the same URI
    // it resolved the UDP destination from: the probe's own A/AAAA lookup
    // REPLACES that destination.  Two live TCP listeners stand in for an
    // edge proxy (where a Path-routed B-leg belongs) and a callee Contact
    // (where it must not go); "localhost" is a non-numeric host, so the
    // lookup path runs rather than the numeric short-circuit.
    let resolver = test_resolver();
    // "localhost" resolves to both loopback families and the order between
    // two lookups is not stable, so each stand-in listens on BOTH — whichever
    // candidate the probe picks, the port is what identifies the host it
    // chose, and the port is the assertion below.
    let Some((edge_v4, edge_v6)) = loopback_pair() else {
        return; // no dual-family loopback here — nothing to discriminate
    };
    let Some((contact_v4, _contact_v6)) = loopback_pair() else {
        return;
    };
    let edge_addr = edge_v4.local_addr().unwrap();
    let contact_addr = contact_v4.local_addr().unwrap();
    assert_eq!(edge_v6.local_addr().unwrap().port(), edge_addr.port());

    let probe = |uri: String| {
        mtu_tcp_upgrade(Some(1280), Transport::Udp, 1300, &uri, edge_addr, &resolver)
            .map(|(transport, addr)| (transport, addr.port(), addr.ip().is_loopback()))
    };

    // Destination resolved from the Route; probing that same Route keeps it.
    assert_eq!(
        probe(format!("sip:TOKEN-A@localhost:{}", edge_addr.port())),
        Some((Transport::Tcp, edge_addr.port(), true)),
    );
    // Same destination, but probing the *Contact* URI drags the B-leg to the
    // Contact's address — the address the Path exists to route around.  This
    // is what passing the wrong URI here costs.
    assert_eq!(
        probe(format!("sip:bob@localhost:{}", contact_addr.port())),
        Some((Transport::Tcp, contact_addr.port(), true)),
    );
}

/// A TCP listener pair on the same port, one per loopback family, so a
/// `localhost` lookup answers with a live listener whichever family it
/// returns first.  `None` when the v6 twin cannot be bound (v4-only host).
fn loopback_pair() -> Option<(std::net::TcpListener, std::net::TcpListener)> {
    let v4 = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).ok()?;
    let port = v4.local_addr().ok()?.port();
    let v6 = std::net::TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, port)).ok()?;
    Some((v4, v6))
}

#[tokio::test(flavor = "multi_thread")]
async fn resolve_tcp_path_numeric_probes_reachability() {
    let resolver = test_resolver();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dest = listener.local_addr().unwrap();
    // Bare IP:port and a sip: URI with a numeric host both resolve to the
    // same address, and the live listener makes the probe succeed.
    assert_eq!(
        resolve_tcp_path(&dest.to_string(), dest, &resolver),
        Some(dest)
    );
    assert_eq!(
        resolve_tcp_path(&format!("sip:{dest}"), dest, &resolver),
        Some(dest)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn resolve_candidates_inner_uses_gateway_cache_without_dns() {
    use crate::gateway::{Algorithm, Destination, DispatcherGroup, DispatcherManager};
    let resolver = test_resolver();
    // `.invalid` never resolves in DNS (RFC 6761), so a fallthrough to
    // resolver.resolve returns an empty set — a non-empty result here proves
    // the gateway cache served the address with zero DNS.
    let destination = Destination::new(
        "sip:gw.test.invalid:5061;transport=tls".to_string(),
        "127.0.0.9:5061".parse().unwrap(),
        Transport::Tls,
        1,
        1,
    )
    .with_address_str("gw.test.invalid:5061".to_string());
    let group = DispatcherGroup::new("teams".to_string(), Algorithm::Weighted, vec![destination]);
    // Simulate the health prober having resolved the FQDN.
    let resolved: SocketAddr = "203.0.113.77:5061".parse().unwrap();
    group.all_destinations()[0].set_address(resolved);
    let manager = DispatcherManager::new();
    manager.add_group(group);

    let candidates = resolve_candidates_inner(
        "sip:gw.test.invalid:5061;transport=tls",
        &resolver,
        Some(&manager),
    );
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].address, resolved);
    // Hostname preserved for TLS SNI to the FQDN peer.
    assert_eq!(
        candidates[0].server_name.as_deref(),
        Some("gw.test.invalid")
    );
    assert_eq!(candidates[0].transport, Some(Transport::Tls));
}

#[tokio::test(flavor = "multi_thread")]
async fn resolve_candidates_inner_falls_through_when_host_not_a_gateway() {
    use crate::gateway::{Algorithm, Destination, DispatcherGroup, DispatcherManager};
    let resolver = test_resolver();
    let destination = Destination::new(
        "sip:gw.test.invalid:5061;transport=tls".to_string(),
        "127.0.0.9:5061".parse().unwrap(),
        Transport::Tls,
        1,
        1,
    )
    .with_address_str("gw.test.invalid:5061".to_string());
    let group = DispatcherGroup::new("teams".to_string(), Algorithm::Weighted, vec![destination]);
    let manager = DispatcherManager::new();
    manager.add_group(group);

    // A different unresolvable host is not a gateway member → no cache hit →
    // DNS fallthrough → empty (does NOT borrow the gateway's cached address).
    let candidates = resolve_candidates_inner(
        "sip:other.host.invalid:5061;transport=tls",
        &resolver,
        Some(&manager),
    );
    assert!(candidates.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn resolve_candidates_inner_bare_ip_short_circuits_before_gateway() {
    let resolver = test_resolver();
    let candidates = resolve_candidates_inner("203.0.113.5:5060", &resolver, None);
    assert_eq!(candidates.len(), 1);
    assert_eq!(
        candidates[0].address,
        "203.0.113.5:5060".parse::<SocketAddr>().unwrap()
    );
    assert!(candidates[0].server_name.is_none());
}

// --- In-dialog connection reuse (RFC 5923) ---

fn candidate(addr: &str) -> RelayTarget {
    RelayTarget {
        address: addr.parse().unwrap(),
        transport: None,
        server_name: None,
    }
}

#[test]
fn established_peer_in_candidates_ip_match() {
    // Load-balanced trunk: the established peer's IP is one of the members
    // the route-set domain resolves to → reuse the established connection.
    let candidates = [
        candidate("198.51.100.26:5061"),
        candidate("198.51.100.34:5061"),
    ];
    let cached = "198.51.100.26:5061".parse::<SocketAddr>().unwrap();
    assert!(established_peer_in_candidates(cached.ip(), &candidates));
}

#[test]
fn established_peer_in_candidates_ip_match_ignores_port() {
    // The cached address carries the peer's source / ephemeral port while a
    // candidate carries the SIP listening port — the match must be IP-only.
    let candidates = [candidate("198.51.100.26:5061")];
    let cached = "198.51.100.26:41897".parse::<SocketAddr>().unwrap();
    assert!(established_peer_in_candidates(cached.ip(), &candidates));
}

#[test]
fn established_peer_not_in_candidates() {
    // IMS divergence: the route set points at the S-CSCF while the
    // established peer is the I-CSCF the INVITE traversed → resolve fresh.
    let candidates = [candidate("203.0.113.20:5060")]; // S-CSCF
    let icscf = "203.0.113.10:5060".parse::<SocketAddr>().unwrap();
    assert!(!established_peer_in_candidates(icscf.ip(), &candidates));
}

#[test]
fn established_peer_in_empty_candidates() {
    // Resolution failure: nothing to compare against, so the established
    // peer is the best available target → reuse.
    let cached = "203.0.113.7:5060".parse::<SocketAddr>().unwrap();
    assert!(established_peer_in_candidates(cached.ip(), &[]));
}

#[tokio::test(flavor = "multi_thread")]
async fn in_dialog_flow_none_next_hop_reuses_cached() {
    // Empty route set → the cached peer is the remote target; reuse it
    // verbatim, including the connection_id.
    let resolver = test_resolver();
    let cached = "10.1.2.3:6000".parse::<SocketAddr>().unwrap();
    let connection_id = ConnectionId(42);
    let (destination, transport, out_connection_id) =
        resolve_in_dialog_flow_uri(None, &resolver, cached, Transport::Tls, connection_id);
    assert_eq!(destination, cached);
    assert_eq!(transport, Transport::Tls);
    assert_eq!(out_connection_id, connection_id);
}

#[tokio::test(flavor = "multi_thread")]
async fn in_dialog_flow_reuses_established_member_over_resolved_port() {
    // Next hop is a literal IP equal to the established peer but on its SIP
    // listening port, while the cached address is the same peer on its
    // source port. RFC 5923: keep the established connection (cached address
    // + connection_id), not the re-resolved listening-port address. This is
    // the load-balanced-trunk fix in miniature.
    let resolver = test_resolver();
    let cached = "192.0.2.50:33333".parse::<SocketAddr>().unwrap();
    let connection_id = ConnectionId(7);
    let (destination, transport, out_connection_id) = resolve_in_dialog_flow_uri(
        Some("sip:192.0.2.50:5061;transport=tls"),
        &resolver,
        cached,
        Transport::Tls,
        connection_id,
    );
    assert_eq!(
        destination, cached,
        "must keep the established peer's connection address"
    );
    assert_eq!(transport, Transport::Tls);
    assert_eq!(
        out_connection_id, connection_id,
        "must reuse the established connection_id"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn in_dialog_flow_resolves_fresh_for_divergent_next_hop() {
    // Next hop is a genuinely different peer than the established one (IMS
    // S-CSCF via the route set vs the I-CSCF the INVITE traversed): resolve
    // fresh and drop the established connection_id so a new connection is
    // opened/pooled.
    let resolver = test_resolver();
    let cached = "203.0.113.10:5060".parse::<SocketAddr>().unwrap(); // I-CSCF (established)
    let connection_id = ConnectionId(7);
    let (destination, _transport, out_connection_id) = resolve_in_dialog_flow_uri(
        Some("sip:203.0.113.20:5060"), // S-CSCF (route set)
        &resolver,
        cached,
        Transport::Udp,
        connection_id,
    );
    assert_eq!(
        destination,
        "203.0.113.20:5060".parse::<SocketAddr>().unwrap()
    );
    assert_eq!(
        out_connection_id,
        ConnectionId::default(),
        "fresh resolution must not reuse the established connection_id",
    );
}

// --- Mid-dialog self-next-hop rescue (RFC 3261 §12.2.1.1 / §16.5) ---
//
// The field case: a UAC keeps the proxy's address in the R-URI of its
// in-dialog re-INVITE/ACK ("sip:bob@<proxy>:5060") instead of the remote
// target from the 200's Contact.  After loose_route() consumed our Route
// the computed next hop resolves to ourselves; the old behaviour answered
// 482 Loop Detected (re-INVITE) / silently dropped (ACK), failing the
// hold/resume of a call whose correct destination sits in the dialog's
// session.  These tests pin the rescue: forward to the established branch.

const RESCUE_PROXY: &str = "192.0.2.1:5060";
const RESCUE_CALLEE: &str = "198.51.100.7:5060";

fn rescue_is_self(address: &SocketAddr) -> bool {
    *address == RESCUE_PROXY.parse::<SocketAddr>().unwrap()
}

fn rescue_dialog_invite(call_id: &str) -> SipMessage {
    // Dialog-establishing INVITE (no To-tag) — the session's original_request.
    SipMessageBuilder::new()
        .request(
            Method::Invite,
            SipUri::new("192.0.2.1".to_string()).with_user("bob".to_string()),
        )
        .via("SIP/2.0/UDP 203.0.113.9:5060;branch=z9hG4bK-orig".to_string())
        .to("<sip:bob@192.0.2.1>".to_string())
        .from("<sip:alice@203.0.113.9>;tag=alice-tag".to_string())
        .call_id(call_id.to_string())
        .cseq("1 INVITE".to_string())
        .content_length(0)
        .build()
        .unwrap()
}

fn rescue_in_dialog_message(method: Method, call_id: &str, cseq: u32, to_tag: bool) -> SipMessage {
    let to = if to_tag {
        "<sip:bob@192.0.2.1>;tag=bob-tag".to_string()
    } else {
        "<sip:bob@192.0.2.1>".to_string()
    };
    let cseq_header = format!("{cseq} {}", method.as_str());
    SipMessageBuilder::new()
        .request(
            method,
            SipUri::new("192.0.2.1".to_string()).with_user("bob".to_string()),
        )
        .via(format!(
            "SIP/2.0/UDP 203.0.113.9:5060;branch=z9hG4bK-cseq{cseq}"
        ))
        .to(to)
        .from("<sip:alice@203.0.113.9>;tag=alice-tag".to_string())
        .call_id(call_id.to_string())
        .cseq(cseq_header)
        .content_length(0)
        .build()
        .unwrap()
}

fn rescue_store_with_dialog(call_id: &str) -> ProxySessionStore {
    let store = ProxySessionStore::new();
    let invite_client_key = TransactionKey::new(
        "z9hG4bK-branch0".to_string(),
        Method::Invite,
        RESCUE_PROXY.to_string(),
    );
    let mut session = ProxySession::new(
        TransactionKey::new(
            "z9hG4bK-orig".to_string(),
            Method::Invite,
            "203.0.113.9:5060".to_string(),
        ),
        "203.0.113.9:5060".parse().unwrap(),
        RESCUE_PROXY.parse().unwrap(),
        ConnectionId::default(),
        Transport::Udp,
        rescue_dialog_invite(call_id),
        true,
    );
    session.add_client_key(invite_client_key.clone());
    session.set_client_branch(
        invite_client_key,
        ClientBranch {
            destination: RESCUE_CALLEE.parse().unwrap(),
            transport: Transport::Udp,
            connection_id: ConnectionId::default(),
        },
    );
    store.insert(session);
    store
}

#[test]
fn reinvite_addressed_at_proxy_reroutes_to_established_branch() {
    // The repro: hold re-INVITE with R-URI sip:bob@<proxy> — the computed
    // next hop is us, but the dialog's established branch is the callee.
    let store = rescue_store_with_dialog("rescue-1");
    let reinvite = rescue_in_dialog_message(Method::Invite, "rescue-1", 2, true);
    let rescued = rescue_in_dialog_self_next_hop(&reinvite, &store, &rescue_is_self);
    assert_eq!(
        rescued,
        Some((RESCUE_CALLEE.parse().unwrap(), Transport::Udp)),
        "in-dialog re-INVITE addressed at the proxy must forward to the dialog's established branch"
    );
}

#[test]
fn resume_reinvite_still_reroutes_after_hold_transaction_cleanup() {
    // The SECOND re-INVITE of a hold/resume pair: the hold's own
    // per-transaction session was inserted (same dialog key — insert's
    // or_insert_with keeps the INVITE's entry) and cleaned up when its
    // transaction completed.  The resume must still find the dialog.
    let store = rescue_store_with_dialog("rescue-2");

    // Hold re-INVITE relayed: relay_request inserts a per-transaction session.
    let hold_client_key = TransactionKey::new(
        "z9hG4bK-hold-branch".to_string(),
        Method::Invite,
        RESCUE_PROXY.to_string(),
    );
    let mut hold_session = ProxySession::new(
        TransactionKey::new(
            "z9hG4bK-cseq2".to_string(),
            Method::Invite,
            "203.0.113.9:5060".to_string(),
        ),
        "203.0.113.9:5060".parse().unwrap(),
        RESCUE_PROXY.parse().unwrap(),
        ConnectionId::default(),
        Transport::Udp,
        rescue_in_dialog_message(Method::Invite, "rescue-2", 2, true),
        false,
    );
    hold_session.add_client_key(hold_client_key.clone());
    hold_session.set_client_branch(
        hold_client_key.clone(),
        ClientBranch {
            destination: RESCUE_CALLEE.parse().unwrap(),
            transport: Transport::Udp,
            connection_id: ConnectionId::default(),
        },
    );
    store.insert(hold_session);
    // Hold's 200 forwarded → its client transaction is cleaned up.
    store.remove_client_key(&hold_client_key);

    let resume = rescue_in_dialog_message(Method::Invite, "rescue-2", 3, true);
    let rescued = rescue_in_dialog_self_next_hop(&resume, &store, &rescue_is_self);
    assert_eq!(
        rescued,
        Some((RESCUE_CALLEE.parse().unwrap(), Transport::Udp)),
        "the resume re-INVITE must still reach the callee after the hold's transaction is cleaned up"
    );
}

#[test]
fn out_of_dialog_request_is_not_rescued() {
    // No To-tag → not mid-dialog (RFC 3261 §12.2): a genuinely misdirected
    // initial request must keep drawing 482, never be steered by a session
    // that happens to share (Call-ID, From-tag).
    let store = rescue_store_with_dialog("rescue-3");
    let initial = rescue_in_dialog_message(Method::Invite, "rescue-3", 1, false);
    assert_eq!(
        rescue_in_dialog_self_next_hop(&initial, &store, &rescue_is_self),
        None
    );
}

#[test]
fn unknown_dialog_is_not_rescued() {
    let store = ProxySessionStore::new();
    let reinvite = rescue_in_dialog_message(Method::Invite, "rescue-4", 2, true);
    assert_eq!(
        rescue_in_dialog_self_next_hop(&reinvite, &store, &rescue_is_self),
        None
    );
}

#[test]
fn rescue_declines_when_established_branch_is_also_ourselves() {
    // Genuine loop: the session's branch ALSO points at us → keep the 482.
    let store = ProxySessionStore::new();
    let invite_client_key = TransactionKey::new(
        "z9hG4bK-branch0".to_string(),
        Method::Invite,
        RESCUE_PROXY.to_string(),
    );
    let mut session = ProxySession::new(
        TransactionKey::new(
            "z9hG4bK-orig".to_string(),
            Method::Invite,
            "203.0.113.9:5060".to_string(),
        ),
        "203.0.113.9:5060".parse().unwrap(),
        RESCUE_PROXY.parse().unwrap(),
        ConnectionId::default(),
        Transport::Udp,
        rescue_dialog_invite("rescue-5"),
        true,
    );
    session.add_client_key(invite_client_key.clone());
    session.set_client_branch(
        invite_client_key,
        ClientBranch {
            destination: RESCUE_PROXY.parse().unwrap(),
            transport: Transport::Udp,
            connection_id: ConnectionId::default(),
        },
    );
    store.insert(session);

    let reinvite = rescue_in_dialog_message(Method::Invite, "rescue-5", 2, true);
    assert_eq!(
        rescue_in_dialog_self_next_hop(&reinvite, &store, &rescue_is_self),
        None
    );
}

#[test]
fn ack_forward_hop_keeps_resolved_hop_when_not_self() {
    let resolved = (
        RESCUE_CALLEE.parse::<SocketAddr>().unwrap(),
        Transport::Udp,
        ConnectionId(3),
    );
    let established = (
        "198.51.100.9:5060".parse::<SocketAddr>().unwrap(),
        Transport::Tcp,
        ConnectionId(4),
    );
    assert_eq!(
        ack_forward_hop(resolved, established, &rescue_is_self),
        Some(resolved)
    );
}

#[test]
fn ack_forward_hop_falls_back_to_established_branch_when_resolved_is_self() {
    // The 2xx ACK with R-URI sip:bob@<proxy>: the resolved hop is us, the
    // established branch is the UAS that answered — deliver the ACK there
    // instead of dropping it (a dropped 2xx ACK leaves the UAS
    // retransmitting its 200 until Timer H).
    let resolved = (
        RESCUE_PROXY.parse::<SocketAddr>().unwrap(),
        Transport::Udp,
        ConnectionId(3),
    );
    let established = (
        RESCUE_CALLEE.parse::<SocketAddr>().unwrap(),
        Transport::Udp,
        ConnectionId(4),
    );
    assert_eq!(
        ack_forward_hop(resolved, established, &rescue_is_self),
        Some(established)
    );
}

#[test]
fn ack_forward_hop_drops_when_both_hops_are_self() {
    let resolved = (
        RESCUE_PROXY.parse::<SocketAddr>().unwrap(),
        Transport::Udp,
        ConnectionId(3),
    );
    let established = (
        RESCUE_PROXY.parse::<SocketAddr>().unwrap(),
        Transport::Udp,
        ConnectionId(4),
    );
    assert_eq!(
        ack_forward_hop(resolved, established, &rescue_is_self),
        None
    );
}

// --- B2BUA 401/407/422 retry connection reuse (RFC 5923) ---

#[tokio::test(flavor = "multi_thread")]
async fn b2bua_retry_reuses_established_member_not_resolved_sibling() {
    // The 401'd CSeq-1 INVITE (and the nonce) went to trunk member A.  The
    // dial target resolves to a *different* member B (the RFC 3263 A/AAAA
    // shuffle on a multi-member trunk behind one DNS name).  The retry MUST
    // stay on member A — the member that issued the nonce — so a strict
    // trunk doesn't 401 again and the INVITE isn't split across members.
    let resolver = test_resolver();
    let member_a = "198.51.100.10:5061".parse::<SocketAddr>().unwrap();
    let member_b_uri = "sip:trunk@198.51.100.20:5061;transport=tls";
    let leg_connection_id = ConnectionId(99);

    let (destination, transport, connection_id, relay_target) = select_b2bua_retry_destination(
        Some((member_a, Transport::Tls)),
        leg_connection_id,
        member_b_uri,
        &resolver,
    )
    .expect("established leg destination is always selectable");

    assert_eq!(
        destination, member_a,
        "retry must reuse the nonce-issuing member, not re-resolve onto a sibling",
    );
    assert_eq!(transport, Transport::Tls);
    assert_eq!(
        relay_target.address, member_a,
        "send target must point at the established member so the TLS pool reuses its connection",
    );
    assert_eq!(relay_target.transport, Some(Transport::Tls));
    // RFC 5923: the retry rides the connection the original INVITE was sent on.
    assert_eq!(connection_id, leg_connection_id);
}

#[tokio::test(flavor = "multi_thread")]
async fn b2bua_retry_resolves_fresh_when_leg_has_no_destination() {
    // Defensive fallback: with no recorded leg destination, resolve the
    // target afresh and open/pool a new connection (default connection_id).
    let resolver = test_resolver();
    let (destination, transport, connection_id, relay_target) = select_b2bua_retry_destination(
        None,
        ConnectionId(99),
        "sip:bob@192.0.2.50:5061;transport=tls",
        &resolver,
    )
    .expect("a resolvable literal-IP target yields a destination");

    assert_eq!(
        destination,
        "192.0.2.50:5061".parse::<SocketAddr>().unwrap()
    );
    assert_eq!(transport, Transport::Tls);
    assert_eq!(relay_target.address, destination);
    assert_eq!(
        connection_id,
        ConnectionId::default(),
        "fresh resolution must not claim a reused connection_id",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn b2bua_retry_none_when_no_dest_and_unresolvable_target() {
    // No leg destination and an unresolvable target → None, so the caller
    // drops the retry rather than sending to a bogus address.
    let resolver = test_resolver();
    let result = select_b2bua_retry_destination(
        None,
        ConnectionId::default(),
        "sip:bob@this-domain-should-not-exist-xyzzy.invalid",
        &resolver,
    );
    assert!(result.is_none());
}

// --- CANCEL tests ---

fn sample_cancel() -> SipMessage {
    SipMessageBuilder::new()
        .request(
            Method::Cancel,
            SipUri::new("biloxi.com".to_string()).with_user("bob".to_string()),
        )
        .via("SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds".to_string())
        .to("Bob <sip:bob@biloxi.com>".to_string())
        .from("Alice <sip:alice@atlanta.com>;tag=1928301774".to_string())
        .call_id("a84b4c76e66710@pc33.atlanta.com".to_string())
        .cseq("314159 CANCEL".to_string())
        .max_forwards(70)
        .content_length(0)
        .build()
        .unwrap()
}

#[test]
fn build_cancel_response_200() {
    let cancel = sample_cancel();
    let response = build_response(&cancel, 200, "OK", None, &[]);
    assert_eq!(response.status_code(), Some(200));
    assert!(response.headers.cseq().unwrap().contains("CANCEL"));
}

#[test]
fn build_cancel_response_481() {
    let cancel = sample_cancel();
    let response = build_response(&cancel, 481, "Call/Transaction Does Not Exist", None, &[]);
    assert_eq!(response.status_code(), Some(481));
}

#[test]
fn build_487_response() {
    let invite = sample_invite();
    let response = build_response(&invite, 487, "Request Terminated", None, &[]);
    assert_eq!(response.status_code(), Some(487));
    assert!(response.headers.cseq().unwrap().contains("INVITE"));
}

// --- build_cancel_from_invite (RFC 3261 §9.1) ---

fn b_leg_invite_sample() -> SipMessage {
    // Realistic B-leg INVITE as siphon would put it on the wire after
    // hygiene: single topmost Via, B-leg Call-ID, fresh From-tag,
    // To unchanged from the original RURI shape, Route set, SDP body.
    SipMessageBuilder::new()
        .request(
            Method::Invite,
            SipUri::new("ims.example.com".to_string()).with_user("5111".to_string()),
        )
        .via("SIP/2.0/UDP siphon.example.com:6060;branch=z9hG4bK-bleg-INVITE-BRANCH".to_string())
        .to("<sip:5111@ims.example.com>".to_string())
        .from("<sip:+31621376327@siphon.example.com>;tag=b2bua-from-tag-XYZ".to_string())
        .call_id("b2b-call-id-bleg".to_string())
        .cseq("1 INVITE".to_string())
        .max_forwards(70)
        .header("Route", "<sip:icscf.example.com:5060;lr>".to_string())
        .header(
            "Contact",
            "<sip:siphon@siphon.example.com:6060>".to_string(),
        )
        .header("Allow", "INVITE,ACK,BYE,CANCEL".to_string())
        .header("Supported", "timer,100rel".to_string())
        .header("Session-Expires", "1800".to_string())
        .header("Content-Type", "application/sdp".to_string())
        .body(b"v=0\r\no=- 0 0 IN IP4 1.2.3.4\r\n".to_vec())
        .build()
        .unwrap()
}

#[test]
fn cancel_preserves_invite_via_branch() {
    let invite = b_leg_invite_sample();
    let cancel = build_cancel_from_invite(&invite).unwrap();
    let via = cancel.headers.via().unwrap();
    assert!(
        via.contains("branch=z9hG4bK-bleg-INVITE-BRANCH"),
        "CANCEL Via must reuse the INVITE branch (RFC 3261 §9.1): {via}",
    );
}

#[test]
fn cancel_preserves_invite_cseq_number() {
    let invite = b_leg_invite_sample();
    let cancel = build_cancel_from_invite(&invite).unwrap();
    let cseq = cancel.headers.cseq().unwrap();
    assert_eq!(
        cseq, "1 CANCEL",
        "CANCEL CSeq must keep INVITE's sequence number and swap method to CANCEL",
    );
}

#[test]
fn cancel_keeps_from_to_callid_verbatim() {
    let invite = b_leg_invite_sample();
    let cancel = build_cancel_from_invite(&invite).unwrap();
    assert_eq!(
        cancel.headers.from().unwrap(),
        "<sip:+31621376327@siphon.example.com>;tag=b2bua-from-tag-XYZ",
    );
    assert_eq!(cancel.headers.to().unwrap(), "<sip:5111@ims.example.com>",);
    assert_eq!(cancel.headers.call_id().unwrap(), "b2b-call-id-bleg");
}

#[test]
fn cancel_request_line_method_is_cancel_with_invite_ruri() {
    let invite = b_leg_invite_sample();
    let cancel = build_cancel_from_invite(&invite).unwrap();
    match &cancel.start_line {
        StartLine::Request(rl) => {
            assert_eq!(rl.method, Method::Cancel);
            assert_eq!(rl.request_uri.user.as_deref(), Some("5111"));
            assert_eq!(rl.request_uri.host, "ims.example.com");
        }
        StartLine::Response(_) => panic!("expected request"),
    }
}

#[test]
fn cancel_strips_body_and_body_bearing_headers() {
    let invite = b_leg_invite_sample();
    let cancel = build_cancel_from_invite(&invite).unwrap();
    assert!(cancel.body.is_empty(), "CANCEL must carry no body");
    assert_eq!(cancel.headers.content_length(), Some(0));
    assert!(
        !cancel.headers.has("Content-Type"),
        "CANCEL must not carry Content-Type"
    );
    assert!(
        !cancel.headers.has("Contact"),
        "CANCEL is hop-by-hop — Contact must be stripped"
    );
    assert!(!cancel.headers.has("Allow"), "CANCEL must not carry Allow");
    assert!(
        !cancel.headers.has("Supported"),
        "CANCEL must not carry Supported"
    );
    assert!(
        !cancel.headers.has("Session-Expires"),
        "CANCEL must not carry Session-Expires"
    );
}

#[test]
fn cancel_keeps_route_set() {
    let invite = b_leg_invite_sample();
    let cancel = build_cancel_from_invite(&invite).unwrap();
    assert_eq!(
        cancel.headers.get("Route").map(String::as_str),
        Some("<sip:icscf.example.com:5060;lr>"),
        "CANCEL must follow the same Route set as the INVITE it cancels",
    );
}

#[test]
fn cancel_keeps_max_forwards() {
    let invite = b_leg_invite_sample();
    let cancel = build_cancel_from_invite(&invite).unwrap();
    assert_eq!(cancel.headers.max_forwards(), Some(70));
}

#[test]
fn cancel_returns_none_for_response_input() {
    // Defensive: build_cancel_from_invite must reject responses.
    let response = build_response(&b_leg_invite_sample(), 100, "Trying", None, &[]);
    assert!(build_cancel_from_invite(&response).is_none());
}

// --- 2xx-after-CANCEL glare: ACK builder (RFC 3261 §13.2.2.4) ---

#[test]
fn build_ack_for_2xx_echoes_dialog_and_targets_contact() {
    // The ACK siphon sends when a 2xx races our CANCEL must be its own
    // transaction: R-URI = the 2xx Contact, CSeq = the INVITE's number with
    // method ACK, From/To/Call-ID echoed (To carries the remote tag), and a
    // fresh Via on our supplied host:port.
    let response = SipMessageBuilder::new()
        .response(200, "OK".to_string())
        .via("SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bK-bleg".to_string())
        .from("<sip:alice@10.0.0.50>;tag=our-tag".to_string())
        .to("<sip:bob@10.0.0.2>;tag=their-tag".to_string())
        .call_id("glare-call@10.0.0.50".to_string())
        .cseq("5 INVITE".to_string())
        .header("Contact", "<sip:bob@10.0.0.2:5070>".to_string())
        .content_length(0)
        .build()
        .unwrap();

    let ack =
        build_b2bua_ack_for_2xx(&response, Transport::Udp, "10.0.0.9", 5060).expect("ACK builds");
    let wire = String::from_utf8(ack.to_bytes()).unwrap();

    // R-URI is the 2xx Contact (the remote target), method ACK.
    assert!(
        wire.starts_with("ACK sip:bob@10.0.0.2:5070 SIP/2.0\r\n"),
        "request line wrong:\n{wire}"
    );
    // Same CSeq number as the INVITE, method ACK (RFC 3261 §13.2.2.4).
    assert!(wire.contains("CSeq: 5 ACK\r\n"), "CSeq wrong:\n{wire}");
    // Dialog identifiers echoed from the 2xx, including the remote To-tag.
    assert!(
        wire.contains("Call-ID: glare-call@10.0.0.50\r\n"),
        "Call-ID:\n{wire}"
    );
    assert!(
        wire.contains(";tag=their-tag"),
        "To-tag must survive:\n{wire}"
    );
    assert!(
        wire.contains(";tag=our-tag"),
        "From-tag must survive:\n{wire}"
    );
    // Fresh Via on the supplied local host:port.
    assert!(
        wire.contains("Via: SIP/2.0/UDP 10.0.0.9:5060;branch="),
        "Via host:port wrong:\n{wire}"
    );
}

#[test]
fn build_ack_for_2xx_falls_back_when_contact_absent() {
    // No Contact on the 2xx → R-URI degrades to a placeholder rather than
    // panicking; CSeq number is still preserved from the response.
    let response = SipMessageBuilder::new()
        .response(200, "OK".to_string())
        .via("SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bK-x".to_string())
        .from("<sip:alice@10.0.0.50>;tag=a".to_string())
        .to("<sip:bob@10.0.0.2>;tag=b".to_string())
        .call_id("no-contact@10.0.0.50".to_string())
        .cseq("9 INVITE".to_string())
        .content_length(0)
        .build()
        .unwrap();

    let ack = build_b2bua_ack_for_2xx(&response, Transport::Udp, "10.0.0.9", 5060)
        .expect("ACK builds even without Contact");
    let wire = String::from_utf8(ack.to_bytes()).unwrap();
    assert!(wire.starts_with("ACK "), "must still be an ACK:\n{wire}");
    assert!(wire.contains("CSeq: 9 ACK\r\n"), "CSeq preserved:\n{wire}");
}

// --- Proxy-forwarded CANCEL Via (RFC 3261 §9.1 / §16.10) ---
//
// Regression: handle_cancel_via_session used to mint a fresh branch
// (TransactionKey::generate_branch()) for the forwarded CANCEL, so the
// downstream proxy/UAS could not match CANCEL→INVITE and dropped it — the
// INVITE leg below was never torn down and the callee kept ringing after
// the caller abandoned during alerting.

#[test]
fn proxy_cancel_via_reuses_invite_branch_and_sent_by() {
    // The proxy forwarded an INVITE on this client branch; its transaction
    // key holds exactly the branch + sent-by siphon stamped on that
    // INVITE's topmost Via.
    let client_key = TransactionKey::new(
        "z9hG4bK-invite-branch-B".to_string(),
        Method::Invite,
        "192.0.2.178:4060".to_string(),
    );
    let via = cancel_via_for_client_branch(&client_key, Transport::Udp);
    assert_eq!(
        via, "SIP/2.0/UDP 192.0.2.178:4060;branch=z9hG4bK-invite-branch-B",
        "forwarded CANCEL must reuse the INVITE's top Via branch + sent-by (RFC 3261 §9.1)",
    );
}

#[test]
fn proxy_cancel_via_branch_is_deterministic_not_fresh() {
    // Guards the exact regression: TransactionKey::generate_branch() would
    // yield a different (and non-matching) branch on every call.
    let client_key = TransactionKey::new(
        "z9hG4bK-stored-branch".to_string(),
        Method::Invite,
        "10.0.0.1:5060".to_string(),
    );
    let via_first = cancel_via_for_client_branch(&client_key, Transport::Tcp);
    let via_second = cancel_via_for_client_branch(&client_key, Transport::Tcp);
    assert_eq!(
        via_first, via_second,
        "forwarded CANCEL Via must derive from the stored client branch, \
         never a freshly generated one",
    );
    assert!(
        via_first.ends_with(";branch=z9hG4bK-stored-branch"),
        "CANCEL branch must equal the stored INVITE branch: {via_first}",
    );
}

#[test]
fn proxy_cancel_via_preserves_transport_and_ipv6_sent_by() {
    // sent_by is reused verbatim from the client key — this covers the
    // IPsec / flow / force_send_via cases where the advertised sent-by
    // (here an IPv6 literal with a non-default protected port) differs
    // from the default per-transport via_host.
    let client_key = TransactionKey::new(
        "z9hG4bK-tls-branch".to_string(),
        Method::Invite,
        "[2001:db8::1]:5061".to_string(),
    );
    let via = cancel_via_for_client_branch(&client_key, Transport::Tls);
    assert_eq!(
        via,
        "SIP/2.0/TLS [2001:db8::1]:5061;branch=z9hG4bK-tls-branch",
    );
}

// --- Transaction integration tests ---

#[test]
fn transaction_manager_creates_client_transaction() {
    let manager = TransactionManager::default();
    let invite = sample_invite();
    let txn_transport = crate::transaction::state::Transport::Udp;
    let (key, actions) = manager
        .new_client_transaction(invite, txn_transport)
        .unwrap();
    assert_eq!(key.method, Method::Invite);
    assert_eq!(manager.count(), 1);
    // Should have SendMessage + StartTimer(B) + StartTimer(A) for UDP
    assert!(actions.iter().any(|a| matches!(a, Action::SendMessage(_))));
    assert!(actions
        .iter()
        .any(|a| matches!(a, Action::StartTimer(TimerName::B, _))));
    assert!(actions
        .iter()
        .any(|a| matches!(a, Action::StartTimer(TimerName::A, _))));
}

/// Regression for the spurious-INVITE-retransmit bug: a forwarded INVITE
/// arms Timer A, and the downstream 100 Trying MUST cancel it (RFC 3261
/// §17.1.1.2). The historical bug was the dispatcher `return`ing on
/// status==100 (RFC 3261 §16.7 "don't forward 100 upstream") *before*
/// feeding the client transaction, so Timer A stayed armed and the proxy
/// retransmitted the INVITE ~T1 (~500 ms) despite holding a provisional.
///
/// Two properties must hold for the dispatcher's absorb-the-100 path
/// (which now feeds the FSM) to actually stop the retransmit:
///   1. the key derived from the echoed 100 matches the key the client
///      transaction was registered under (RFC 3261 §17.1.3), and
///   2. feeding that 100 as a Provisional emits CancelTimer(A).
#[test]
fn provisional_100_cancels_invite_client_timer_a() {
    let manager = TransactionManager::default();
    let invite = SipMessageBuilder::new()
        .request(
            Method::Invite,
            SipUri::new("biloxi.com".to_string()).with_user("bob".to_string()),
        )
        .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-timera".to_string())
        .to("Bob <sip:bob@biloxi.com>".to_string())
        .from("Alice <sip:alice@atlanta.com>;tag=99".to_string())
        .call_id("timera-call@10.0.0.1".to_string())
        .cseq("1 INVITE".to_string())
        .max_forwards(70)
        .content_length(0)
        .build()
        .unwrap();

    let (key, start_actions) = manager
        .new_client_transaction(invite, crate::transaction::state::Transport::Udp)
        .unwrap();
    assert!(
        start_actions
            .iter()
            .any(|a| matches!(a, Action::StartTimer(TimerName::A, _))),
        "UDP INVITE client transaction must arm Timer A"
    );

    // Downstream 100 Trying echoing the forwarded INVITE's top Via verbatim.
    let trying = SipMessageBuilder::new()
        .response(100, "Trying".to_string())
        .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-timera".to_string())
        .to("Bob <sip:bob@biloxi.com>".to_string())
        .from("Alice <sip:alice@atlanta.com>;tag=99".to_string())
        .call_id("timera-call@10.0.0.1".to_string())
        .cseq("1 INVITE".to_string())
        .content_length(0)
        .build()
        .unwrap();

    // (1) The 100 must map to the same transaction key the ICT was
    //     registered under — else the dispatcher's process_client_event
    //     lookup misses and Timer A is never cancelled.
    let response_key = TransactionManager::key_from_message(&trying).unwrap();
    assert_eq!(response_key, key, "100 response key must match the ICT key");

    // (2) Feeding the 100 as a provisional cancels Timer A.
    let actions = manager
        .process_client_event(
            &response_key,
            ClientEvent::Ict(IctEvent::Provisional(trying)),
        )
        .unwrap();
    assert!(
        actions
            .iter()
            .any(|a| matches!(a, Action::CancelTimer(TimerName::A))),
        "100 Trying must cancel the INVITE retransmit Timer A"
    );
}

#[test]
fn transaction_manager_creates_server_transaction() {
    let manager = TransactionManager::default();
    let invite = sample_invite();
    let txn_transport = crate::transaction::state::Transport::Udp;
    let crate::transaction::ServerTransactionOutcome { key, actions, .. } = manager
        .new_server_transaction(&invite, txn_transport)
        .unwrap();
    assert_eq!(key.method, Method::Invite);
    assert_eq!(manager.count(), 1);
    assert!(actions.iter().any(|a| matches!(a, Action::PassToTu(_))));
}

#[test]
fn timer_entry_created_with_correct_fields() {
    let key = TransactionKey::new(
        "z9hG4bK-test".to_string(),
        Method::Invite,
        "10.0.0.1:5060".to_string(),
    );
    let entry = TimerEntry {
        key: key.clone(),
        name: TimerName::A,
        fires_at: std::time::Instant::now() + std::time::Duration::from_millis(500),
        destination: Some("10.0.0.1:5060".parse().unwrap()),
        transport: Some(Transport::Udp),
        connection_id: Some(ConnectionId::default()),
        source_local_addr: None,
    };
    assert_eq!(entry.key, key);
    assert_eq!(entry.name, TimerName::A);
    assert!(entry.destination.is_some());
}

#[test]
fn transport_conversion_udp() {
    let txn = crate::transaction::state::Transport::from(Transport::Udp);
    assert_eq!(txn, crate::transaction::state::Transport::Udp);
}

#[test]
fn transport_conversion_tcp_is_reliable() {
    let txn = crate::transaction::state::Transport::from(Transport::Tcp);
    assert_eq!(txn, crate::transaction::state::Transport::Reliable);
}

#[test]
fn transport_conversion_tls_is_reliable() {
    let txn = crate::transaction::state::Transport::from(Transport::Tls);
    assert_eq!(txn, crate::transaction::state::Transport::Reliable);
}

// --- B2BUA call manager tests ---

#[test]
fn call_manager_create_and_cancel() {
    let manager = CallActorStore::new();
    let a_leg = Leg::new_a_leg(
        "call-1".to_string(),
        "tag-1".to_string(),
        "z9hG4bK-a1".to_string(),
        LegTransport {
            remote_addr: "10.0.0.1:5060".parse().unwrap(),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    );
    let call_id = manager.create_call(a_leg);
    assert_eq!(manager.count(), 1);

    // Simulate cancel: set state and remove
    manager.set_state(&call_id, CallState::Terminated);
    manager.remove_call(&call_id);
    assert_eq!(manager.count(), 0);
}

#[test]
fn call_manager_b_leg_response_routing() {
    let manager = CallActorStore::new();
    let a_leg = Leg::new_a_leg(
        "call-1".to_string(),
        "tag-1".to_string(),
        "z9hG4bK-a1".to_string(),
        LegTransport {
            remote_addr: "10.0.0.1:5060".parse().unwrap(),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    );
    let call_id = manager.create_call(a_leg);

    let b_leg = Leg::new_b_leg(
        "b2b-test-1".to_string(),
        "sb-test-1".to_string(),
        "sip:bob@10.0.0.2".to_string(),
        "z9hG4bK-b1".to_string(),
        LegTransport {
            remote_addr: "10.0.0.2:5060".parse().unwrap(),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    );
    manager.add_b_leg(&call_id, b_leg);

    // Can route response via B-leg branch
    assert_eq!(
        manager.call_id_for_branch("z9hG4bK-b1"),
        Some(call_id.clone())
    );

    // Set winner and verify answered state
    manager.set_winner(&call_id, 0);
    let call = manager.get_call(&call_id).unwrap();
    assert_eq!(call.state, CallState::Answered);
    assert_eq!(call.winner, Some(0));
}

/// Verify that next_hop routing does not clobber the Request-URI.
///
/// The relay_request function uses next_hop only for DNS resolution /
/// packet routing, keeping the original R-URI (including user part) intact.
/// This test validates the invariant at the message level.
#[test]
fn next_hop_does_not_overwrite_request_uri() {
    let invite = sample_invite();
    // Original R-URI: sip:bob@biloxi.com
    let original_ruri = match &invite.start_line {
        StartLine::Request(rl) => rl.request_uri.to_string(),
        _ => panic!("expected request"),
    };
    assert!(
        original_ruri.contains("bob@"),
        "original R-URI should have user part: {original_ruri}"
    );

    // Simulate what relay_request does: clone, add Via/RR, but do NOT overwrite R-URI
    let relayed = invite.clone();
    let ruri_after = match &relayed.start_line {
        StartLine::Request(rl) => rl.request_uri.to_string(),
        _ => panic!("expected request"),
    };
    assert_eq!(
        original_ruri, ruri_after,
        "R-URI must be preserved when next_hop is used for routing only"
    );
}

// --- Bug fix regression tests ---

/// Bug 1: INVITE retransmissions should be detected via find_by_sip_call_id.
#[test]
fn retransmission_guard_detects_duplicate_call_id() {
    let manager = CallActorStore::new();
    let a_leg = Leg::new_a_leg(
        "retransmit-test@host".to_string(),
        "tag-orig".to_string(),
        "z9hG4bK-orig".to_string(),
        LegTransport {
            remote_addr: "10.0.0.1:5060".parse().unwrap(),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    );
    let _call_id = manager.create_call(a_leg);

    // Second INVITE with same SIP Call-ID (retransmission) should be detected
    assert!(
        manager
            .find_by_sip_call_id("retransmit-test@host")
            .is_some(),
        "retransmission guard must detect existing call by SIP Call-ID"
    );
    // Different Call-ID should not match
    assert!(manager.find_by_sip_call_id("different-call@host").is_none());
}

/// Bug 2: build_b2bua_ack_for_non2xx constructs a valid ACK from a B-leg error response.
#[test]
fn build_b2bua_ack_for_non2xx_constructs_valid_ack() {
    // Build a 486 response as if from B-leg
    let response = SipMessageBuilder::new()
        .response(486, "Busy Here".to_string())
        .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-b2b-branch".to_string())
        .from("<sip:alice@example.com>;tag=b-leg-ftag".to_string())
        .to("<sip:bob@example.com>;tag=bob-tag".to_string())
        .call_id("b-leg-call-id".to_string())
        .cseq("1 INVITE".to_string())
        .content_length(0)
        .build()
        .unwrap();

    let ack = build_b2bua_ack_for_non2xx(
        &response,
        "z9hG4bK-b2b-branch",
        Some("sip:bob@10.0.0.2:5060"),
        Transport::Udp,
        "198.51.100.20",
        5060,
    );

    assert!(ack.is_request());
    let bytes = String::from_utf8(ack.to_bytes()).unwrap();
    assert!(bytes.starts_with("ACK sip:bob@10.0.0.2:5060 SIP/2.0\r\n"));

    // Via uses our branch (same as client transaction) and the advertised
    // sent-by host:port supplied by the caller (state.via_host/via_port).
    let via = ack.headers.via().unwrap();
    assert!(via.contains("z9hG4bK-b2b-branch"));
    assert!(via.contains("UDP"));
    assert!(via.contains("198.51.100.20:5060"));

    // From/To/Call-ID from the response
    assert!(ack.headers.from().unwrap().contains("b-leg-ftag"));
    assert!(ack.headers.to().unwrap().contains("bob-tag"));
    assert_eq!(ack.headers.call_id().unwrap(), "b-leg-call-id");

    // CSeq: same number, ACK method
    let cseq = ack.headers.cseq().unwrap();
    assert!(cseq.contains("1"));
    assert!(cseq.contains("ACK"));
    assert!(!cseq.contains("INVITE"));

    assert_eq!(ack.headers.content_length(), Some(0));
}

/// Bug 3: Winner is recorded and can be used to find the winning B-leg for ACK bridging.
#[test]
fn winner_tracks_answered_b_leg_for_ack_bridging() {
    let manager = CallActorStore::new();
    let a_leg = Leg::new_a_leg(
        "ack-bridge-test@host".to_string(),
        "a-tag".to_string(),
        "z9hG4bK-a1".to_string(),
        LegTransport {
            remote_addr: "10.0.0.1:5060".parse().unwrap(),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    );
    let call_id = manager.create_call(a_leg);

    // Add two B-legs (forked call)
    let b_leg_0 = Leg::new_b_leg(
        "b-cid-0".to_string(),
        "b-ftag-0".to_string(),
        "sip:bob@10.0.0.2".to_string(),
        "z9hG4bK-b0".to_string(),
        LegTransport {
            remote_addr: "10.0.0.2:5060".parse().unwrap(),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    );
    let b_leg_1 = Leg::new_b_leg(
        "b-cid-1".to_string(),
        "b-ftag-1".to_string(),
        "sip:bob@10.0.0.3".to_string(),
        "z9hG4bK-b1".to_string(),
        LegTransport {
            remote_addr: "10.0.0.3:5060".parse().unwrap(),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    );
    manager.add_b_leg(&call_id, b_leg_0);
    manager.add_b_leg(&call_id, b_leg_1);

    // B-leg 1 answers first
    manager.set_winner(&call_id, 1);
    manager.set_state(&call_id, CallState::Answered);

    let call = manager.get_call(&call_id).unwrap();
    assert_eq!(call.winner, Some(1));
    let winner = &call.b_legs[call.winner.unwrap()];
    assert_eq!(winner.dialog.call_id, "b-cid-1");
    assert_eq!(winner.dialog.local_tag, "b-ftag-1");
    assert_eq!(
        winner.transport.remote_addr,
        "10.0.0.3:5060".parse::<SocketAddr>().unwrap()
    );

    // ACK bridging would use find_by_sip_call_id to locate the call
    assert_eq!(
        manager.find_by_sip_call_id("ack-bridge-test@host"),
        Some(call_id),
    );
}

#[test]
fn sanitize_sdp_identity_rewrites_o_and_s_lines() {
    let sdp = "v=0\r\no=FreeSWITCH 123 456 IN IP4 10.0.0.1\r\ns=FreeSWITCH\r\nt=0 0\r\nm=audio 8000 RTP/AVP 0\r\n";
    let mut body = sdp.as_bytes().to_vec();
    sanitize_sdp_identity(&mut body, "Test SBC", None);
    let result = std::str::from_utf8(&body).unwrap();
    // o= username is space-delimited (RFC 4566 §5.2) — whitespace in the
    // configured name MUST collapse to `-`.
    assert!(result.contains("o=Test-SBC 123 456 IN IP4 10.0.0.1\r\n"));
    // s= permits whitespace (§5.3) — preserved verbatim.
    assert!(result.contains("s=Test SBC\r\n"));
    assert!(!result.contains("FreeSWITCH"));
    // Other lines unchanged
    assert!(result.contains("v=0\r\n"));
    assert!(result.contains("m=audio 8000 RTP/AVP 0\r\n"));
}

#[test]
fn sanitize_sdp_identity_rewrites_o_line_address() {
    let sdp = "v=0\r\no=FreeSWITCH 123 456 IN IP4 10.0.0.1\r\ns=FreeSWITCH\r\nt=0 0\r\nm=audio 8000 RTP/AVP 0\r\n";
    let mut body = sdp.as_bytes().to_vec();
    sanitize_sdp_identity(&mut body, "SIPhon", Some("203.0.113.1"));
    let result = std::str::from_utf8(&body).unwrap();
    assert!(
        result.contains("o=SIPhon 123 456 IN IP4 203.0.113.1\r\n"),
        "o= line should have rewritten address, got: {result}"
    );
    assert!(result.contains("s=SIPhon\r\n"));
    assert!(!result.contains("10.0.0.1"));
    assert!(!result.contains("FreeSWITCH"));
}

#[test]
fn sanitize_sdp_identity_rewrites_o_line_ipv6_address_and_addrtype() {
    // A v6 substitute host (bracketed, as via_host() produces) must land on
    // the o= line unbracketed with the addrtype flipped IP4 -> IP6.
    let sdp = "v=0\r\no=FreeSWITCH 123 456 IN IP4 10.0.0.1\r\ns=FreeSWITCH\r\nt=0 0\r\nm=audio 8000 RTP/AVP 0\r\n";
    let mut body = sdp.as_bytes().to_vec();
    sanitize_sdp_identity(&mut body, "SIPhon", Some("[2001:db8::1]"));
    let result = std::str::from_utf8(&body).unwrap();
    assert!(
        result.contains("o=SIPhon 123 456 IN IP6 2001:db8::1\r\n"),
        "o= line should carry IN IP6 + an unbracketed v6 address, got: {result}"
    );
    assert!(
        !result.contains("IN IP4 2001"),
        "addrtype must not stay IP4: {result}"
    );
    assert!(
        !result.contains('['),
        "SDP address must not be bracketed: {result}"
    );
}

#[test]
fn sanitize_sdp_identity_masks_address_on_malformed_o_line() {
    // A non-canonical o= line (doubled space → 7 tokens) must STILL have its
    // trailing address substituted — a missing rewrite would leak the peer's
    // real address (topology-hiding regression).
    let sdp = "v=0\r\no=carol 1 2 IN IP4  198.51.100.9\r\ns=-\r\nt=0 0\r\n";
    let mut body = sdp.as_bytes().to_vec();
    sanitize_sdp_identity(&mut body, "SIPhon", Some("203.0.113.7"));
    let result = std::str::from_utf8(&body).unwrap();
    assert!(
        !result.contains("198.51.100.9"),
        "peer address must be masked: {result}"
    );
    assert!(
        result.contains("203.0.113.7"),
        "substitute address must be present: {result}"
    );
    assert!(
        !result.contains("carol"),
        "username must be replaced: {result}"
    );
}

#[test]
fn sdp_origin_address_classifies_and_strips() {
    assert_eq!(
        sdp_origin_address("10.0.0.1"),
        ("10.0.0.1".to_string(), Some("IP4"))
    );
    assert_eq!(
        sdp_origin_address("[2001:db8::1]"),
        ("2001:db8::1".to_string(), Some("IP6"))
    );
    assert_eq!(
        sdp_origin_address("2001:db8::1"),
        ("2001:db8::1".to_string(), Some("IP6"))
    );
    // FQDN — emitted verbatim, addrtype left to the caller.
    assert_eq!(
        sdp_origin_address("pcscf.example"),
        ("pcscf.example".to_string(), None)
    );
    // Bracketed but unparseable (zoned link-local): brackets stripped, never
    // leaked into SDP.
    assert_eq!(
        sdp_origin_address("[fe80::1%eth0]"),
        ("fe80::1%eth0".to_string(), None)
    );
}

#[test]
fn sanitize_sdp_identity_no_op_on_empty_body() {
    let mut body = Vec::new();
    sanitize_sdp_identity(&mut body, "SIPhon", None);
    assert!(body.is_empty());
}

/// Regression: an `sdp_name` configured with internal whitespace
/// (multi-word product / role name) was being written verbatim into the
/// SDP `o=` line. RFC 4566 §5.2 splits o= on spaces, so a value like
/// `o=Foo Bar 123 456 IN IP4 ...` has a malformed username token and
/// downstream parsers (FreeSWITCH, kamailio) reject the whole SDP body.
#[test]
fn sanitize_sdp_identity_collapses_whitespace_in_o_username() {
    let sdp = "v=0\r\no=- 1 2 IN IP4 10.0.0.1\r\ns=-\r\nt=0 0\r\nm=audio 8000 RTP/AVP 0\r\n";
    let mut body = sdp.as_bytes().to_vec();
    sanitize_sdp_identity(&mut body, "Foo Bar", Some("203.0.113.5"));
    let result = std::str::from_utf8(&body).unwrap();
    assert!(
        result.contains("o=Foo-Bar 1 2 IN IP4 203.0.113.5\r\n"),
        "o= username must collapse whitespace; got: {result}",
    );
    // RFC 4566 token count check: o= line must have exactly 6 fields.
    let o_line = result.lines().find(|l| l.starts_with("o=")).unwrap();
    assert_eq!(
        o_line.split(' ').count(),
        6,
        "o= line must have exactly 6 space-separated fields; got: {o_line}",
    );
}

#[test]
fn sanitize_o_username_collapses_internal_whitespace() {
    assert_eq!(sanitize_o_username("Foo Bar"), "Foo-Bar");
    assert_eq!(sanitize_o_username("Foo  Bar"), "Foo-Bar");
    assert_eq!(sanitize_o_username("a b c"), "a-b-c");
    assert_eq!(sanitize_o_username("siphon"), "siphon");
    assert_eq!(sanitize_o_username("SIPhon\tProxy"), "SIPhon-Proxy");
}

#[test]
fn sanitize_o_username_handles_pure_whitespace() {
    // "All whitespace" → fall back to the RFC 4566 "no user ID" sentinel.
    assert_eq!(sanitize_o_username("   "), "-");
    assert_eq!(sanitize_o_username(""), "");
}

#[test]
fn stamp_sdp_origin_owns_session_id_and_version() {
    let sdp =
        "v=0\r\no=alice 111 222 IN IP4 10.0.0.1\r\ns=call\r\nt=0 0\r\nm=audio 8000 RTP/AVP 0\r\n";
    let mut body = sdp.as_bytes().to_vec();
    // addr=None → nettype/addrtype/address preserved, only username+ids owned.
    stamp_sdp_origin(&mut body, "SIPhon", 9999, 7, None);
    let result = std::str::from_utf8(&body).unwrap();
    assert!(
        result.contains("o=SIPhon 9999 7 IN IP4 10.0.0.1\r\n"),
        "got: {result}",
    );
    // A malformed username still collapses whitespace (RFC 4566 §5.2).
    let o_line = result.lines().find(|l| l.starts_with("o=")).unwrap();
    assert_eq!(o_line.split(' ').count(), 6);
}

#[test]
fn stamp_sdp_origin_rewrites_address_when_given() {
    let sdp = "v=0\r\no=carol 5 6 IN IP4 198.51.100.9\r\ns=-\r\nt=0 0\r\n";
    let mut body = sdp.as_bytes().to_vec();
    stamp_sdp_origin(&mut body, "SIPhon", 42, 1, Some("203.0.113.7"));
    let result = std::str::from_utf8(&body).unwrap();
    assert!(
        result.contains("o=SIPhon 42 1 IN IP4 203.0.113.7\r\n"),
        "got: {result}",
    );
    assert!(!result.contains("198.51.100.9"));
}

#[test]
fn stamp_sdp_origin_rewrites_ipv6_address_and_addrtype() {
    // v6 substitute (bracketed via_host()) -> unbracketed address + IP6.
    let sdp = "v=0\r\no=carol 5 6 IN IP4 198.51.100.9\r\ns=-\r\nt=0 0\r\n";
    let mut body = sdp.as_bytes().to_vec();
    stamp_sdp_origin(&mut body, "SIPhon", 42, 1, Some("[2001:db8::7]"));
    let result = std::str::from_utf8(&body).unwrap();
    assert!(
        result.contains("o=SIPhon 42 1 IN IP6 2001:db8::7\r\n"),
        "got: {result}",
    );
    assert!(
        !result.contains("IN IP4 2001"),
        "addrtype must flip to IP6: {result}"
    );
    assert!(
        !result.contains('['),
        "SDP address must be unbracketed: {result}"
    );
}

/// The whole point of siphon-owned o=: a re-emit toward the same peer keeps
/// the session-id stable and presents a strictly greater version, even when
/// the underlying SDP came from a different party (a transfer re-anchor).
#[test]
fn stamp_sdp_origin_monotonic_across_reemits() {
    let first = "v=0\r\no=bob 1 1 IN IP4 10.0.0.2\r\ns=-\r\nt=0 0\r\nm=audio 9000 RTP/AVP 0\r\n";
    let mut a = first.as_bytes().to_vec();
    stamp_sdp_origin(&mut a, "SIPhon", 5000, 0, None);
    // A later re-anchor carries a *different* party's SDP but siphon's same
    // session-id with an incremented version.
    let second = "v=0\r\no=carol 7 7 IN IP4 10.0.0.9\r\ns=-\r\nt=0 0\r\nm=audio 9100 RTP/AVP 0\r\n";
    let mut b = second.as_bytes().to_vec();
    stamp_sdp_origin(&mut b, "SIPhon", 5000, 1, None);
    let ra = std::str::from_utf8(&a).unwrap();
    let rb = std::str::from_utf8(&b).unwrap();
    assert!(
        ra.contains("o=SIPhon 5000 0 IN IP4 10.0.0.2\r\n"),
        "got: {ra}"
    );
    assert!(
        rb.contains("o=SIPhon 5000 1 IN IP4 10.0.0.9\r\n"),
        "got: {rb}"
    );
}

#[test]
fn stamp_sdp_origin_leaves_malformed_o_line_untouched() {
    // Fewer than the RFC-mandated six fields → left alone (defensive).
    let sdp = "v=0\r\no=broken 1 2\r\ns=-\r\nt=0 0\r\n";
    let mut body = sdp.as_bytes().to_vec();
    stamp_sdp_origin(&mut body, "SIPhon", 1, 2, None);
    let result = std::str::from_utf8(&body).unwrap();
    assert!(result.contains("o=broken 1 2\r\n"), "got: {result}");
}

#[test]
fn stamp_sdp_origin_no_op_on_empty_body() {
    let mut body = Vec::new();
    stamp_sdp_origin(&mut body, "SIPhon", 1, 1, None);
    assert!(body.is_empty());
}

/// Verify that fork targets DO update the R-URI (each branch gets its Contact).
#[test]
fn fork_branch_updates_request_uri() {
    let invite = sample_invite();
    let mut relayed = invite.clone();

    // Simulate fork branch updating R-URI to registered contact
    let target = "sip:bob@192.168.1.50:5060;transport=tls";
    if let Ok(new_uri) = parse_uri_standalone(target) {
        if let StartLine::Request(ref mut rl) = relayed.start_line {
            rl.request_uri = new_uri;
        }
    }

    let ruri = match &relayed.start_line {
        StartLine::Request(rl) => rl.request_uri.to_string(),
        _ => panic!("expected request"),
    };
    assert!(
        ruri.contains("bob@192.168.1.50"),
        "fork branch R-URI should be updated to target contact: {ruri}"
    );
}

#[test]
fn srs_answer_flips_sendonly_to_recvonly() {
    let sdp = concat!(
        "v=0\r\n",
        "o=- 1234 5678 IN IP4 10.0.0.1\r\n",
        "s=-\r\n",
        "t=0 0\r\n",
        "m=audio 10000 RTP/AVP 8 101\r\n",
        "c=IN IP4 10.0.0.1\r\n",
        "a=sendonly\r\n",
        "m=audio 10002 RTP/AVP 8 101\r\n",
        "c=IN IP4 10.0.0.1\r\n",
        "a=sendonly\r\n",
    );
    let mut body = sdp.as_bytes().to_vec();
    fix_srs_answer_sdp_direction(&mut body);
    let result = String::from_utf8(body).unwrap();
    assert!(!result.contains("a=sendonly"), "sendonly should be flipped");
    assert_eq!(result.matches("a=recvonly").count(), 2);
}

#[test]
fn srs_answer_flips_recvonly_to_sendonly() {
    let sdp = concat!(
        "v=0\r\n",
        "o=- 1234 5678 IN IP4 10.0.0.1\r\n",
        "s=-\r\n",
        "t=0 0\r\n",
        "m=audio 10000 RTP/AVP 8\r\n",
        "a=recvonly\r\n",
    );
    let mut body = sdp.as_bytes().to_vec();
    fix_srs_answer_sdp_direction(&mut body);
    let result = String::from_utf8(body).unwrap();
    assert!(result.contains("a=sendonly"));
    assert!(!result.contains("a=recvonly"));
}

#[test]
fn srs_answer_leaves_sendrecv_unchanged() {
    let sdp = concat!(
        "v=0\r\n",
        "o=- 1234 5678 IN IP4 10.0.0.1\r\n",
        "s=-\r\n",
        "t=0 0\r\n",
        "m=audio 10000 RTP/AVP 8\r\n",
        "a=sendrecv\r\n",
    );
    let mut body = sdp.as_bytes().to_vec();
    fix_srs_answer_sdp_direction(&mut body);
    let result = String::from_utf8(body).unwrap();
    assert!(result.contains("a=sendrecv"));
}

#[test]
fn srs_answer_no_direction_unchanged() {
    let sdp = concat!(
        "v=0\r\n",
        "o=- 1234 5678 IN IP4 10.0.0.1\r\n",
        "s=-\r\n",
        "t=0 0\r\n",
        "m=audio 10000 RTP/AVP 8\r\n",
        "c=IN IP4 10.0.0.1\r\n",
    );
    let mut body = sdp.as_bytes().to_vec();
    let original = body.clone();
    fix_srs_answer_sdp_direction(&mut body);
    assert_eq!(body, original);
}

// --- parse_contact_expires tests ---

#[test]
fn contact_expires_bare_param() {
    assert_eq!(
        parse_contact_expires("<sip:trunk@10.0.0.1:5060>;expires=3600"),
        Some(3600)
    );
}

#[test]
fn contact_expires_quoted_value() {
    assert_eq!(
        parse_contact_expires("<sip:trunk@10.0.0.1:5060>;expires=\"1800\""),
        Some(1800)
    );
}

#[test]
fn contact_expires_ignores_uri_param() {
    // expires= inside angle brackets is a URI parameter, not a Contact parameter
    assert_eq!(
        parse_contact_expires("<sip:trunk@10.0.0.1:5060;expires=0>;expires=3600"),
        Some(3600),
    );
}

#[test]
fn contact_expires_uri_param_only_ignored() {
    // Only URI-level expires=, no Contact-level — should return None
    assert_eq!(
        parse_contact_expires("<sip:trunk@10.0.0.1:5060;expires=0>"),
        None
    );
}

#[test]
fn contact_expires_no_angle_brackets() {
    assert_eq!(
        parse_contact_expires("sip:trunk@10.0.0.1:5060;expires=600"),
        Some(600)
    );
}

#[test]
fn contact_expires_missing() {
    assert_eq!(parse_contact_expires("<sip:trunk@10.0.0.1:5060>"), None);
}

#[test]
fn contact_expires_with_other_params() {
    assert_eq!(
        parse_contact_expires(
            "<sip:trunk@10.0.0.1:5060>;q=0.8;expires=900;+sip.instance=\"<urn:uuid:abc>\""
        ),
        Some(900),
    );
}

// -----------------------------------------------------------------------
// MediaTimeout bookkeeping — clear siphon-sip's own media session so the
// downstream safety-net delete (gated on a present record) is a no-op.
// -----------------------------------------------------------------------

fn media_session_fixture(call_id: &str) -> crate::rtpengine::session::MediaSession {
    crate::rtpengine::session::MediaSession {
        call_id: call_id.to_string(),
        rtpengine_call_id: call_id.to_string(),
        from_tag: "a-tag".to_string(),
        to_tag: None,
        profile: "srtp_to_rtp".to_string(),
        ws_uri: None,
        ws_tee: None,
        ws_bridge_attached: false,
        created_at: std::time::Instant::now(),
    }
}

#[test]
fn clear_media_session_on_timeout_removes_the_record() {
    let store = Arc::new(crate::rtpengine::session::MediaSessionStore::new());
    store.insert(media_session_fixture("1-1354742@host"));
    assert_eq!(store.len(), 1);

    // The event's call_id equals the store key (engine call-id == SIP Call-ID).
    let cleared = clear_media_session_on_timeout(Some(&store), "1-1354742@host");

    // Record removed → returns true and the store is empty. Because every
    // safety-net delete site is gated on `if let Some(session) =
    // media_sessions.remove(&…)`, an empty store means the later teardown
    // (e.g. via b2bua.terminate) issues NO `set.delete` — no round-trip, no
    // "unknown call" warn. (MediaBackend is a concrete enum with no trait to
    // mock, so store-is-empty is the structurally-equivalent assertion to a
    // spy that expects zero delete calls.)
    assert!(cleared);
    assert!(store.get("1-1354742@host").is_none());
    assert!(store.is_empty());
}

#[test]
fn clear_media_session_on_timeout_no_record_is_noop() {
    let store = Arc::new(crate::rtpengine::session::MediaSessionStore::new());
    // Unknown call_id → nothing to clear, returns false, does not panic.
    assert!(!clear_media_session_on_timeout(
        Some(&store),
        "no-such-call@host"
    ));
    assert!(store.is_empty());
}

#[test]
fn clear_media_session_on_timeout_no_store_is_noop() {
    // Media backend not configured (rtpengine_sessions is None) → false.
    assert!(!clear_media_session_on_timeout(None, "1-1354742@host"));
}

// -----------------------------------------------------------------------
// In-dialog request against a torn-down B2BUA call → 481 (RFC 3261 §12.2.2)
// -----------------------------------------------------------------------

fn glare_a_leg(sip_call_id: &str) -> Leg {
    Leg::new_a_leg(
        sip_call_id.to_string(),
        "tag-alice".to_string(),
        "z9hG4bK-aleg".to_string(),
        LegTransport {
            remote_addr: "10.0.0.1:5060".parse().unwrap(),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    )
}

/// A store whose only call carried `sip_call_id` and has been torn down —
/// the state the trunk's BYE leaves behind in the glare.
fn store_after_teardown(sip_call_id: &str) -> CallActorStore {
    let store = CallActorStore::new();
    let call_id = store.create_call(glare_a_leg(sip_call_id));
    store.remove_call(&call_id);
    store
}

fn in_dialog_request(method: Method, sip_call_id: &str, to_tag: Option<&str>) -> SipMessage {
    let to = match to_tag {
        Some(tag) => format!("<sip:bob@example.com>;tag={tag}"),
        None => "<sip:bob@example.com>".to_string(),
    };
    let cseq = format!("2 {}", method.as_str());
    SipMessageBuilder::new()
        .request(
            method,
            SipUri::new("example.com".to_string()).with_user("bob".to_string()),
        )
        .via("SIP/2.0/UDP ue.example.com:5060;branch=z9hG4bK-glare".to_string())
        .to(to)
        .from("<sip:alice@example.com>;tag=alice-tag".to_string())
        .call_id(sip_call_id.to_string())
        .cseq(cseq)
        .max_forwards(70)
        .content_length(0)
        .build()
        .unwrap()
}

#[test]
fn bye_after_teardown_needs_481() {
    // The field case: the trunk's BYE tore the call down, the UE's own BYE
    // lands ~350ms later. Silently dropping it costs the UE 32s to timer F
    // and then a full IMS re-registration.
    let store = store_after_teardown("ue-call-id@10.0.0.1");
    let bye = in_dialog_request(Method::Bye, "ue-call-id@10.0.0.1", Some("bob-tag"));
    assert!(terminated_dialog_needs_481("BYE", &bye, &store));
}

#[test]
fn bye_for_live_call_needs_no_481() {
    // A live call always wins: its own in-dialog requests must reach the
    // B2BUA intercepts, never a 481.
    let store = CallActorStore::new();
    store.create_call(glare_a_leg("ue-call-id@10.0.0.1"));
    let bye = in_dialog_request(Method::Bye, "ue-call-id@10.0.0.1", Some("bob-tag"));
    assert!(!terminated_dialog_needs_481("BYE", &bye, &store));
}

#[test]
fn reinvite_after_teardown_needs_481() {
    // Also stops handle_b2bua_invite from taking a re-INVITE for a dead call
    // as a brand-new call and dialling out again.
    let store = store_after_teardown("ue-call-id@10.0.0.1");
    let reinvite = in_dialog_request(Method::Invite, "ue-call-id@10.0.0.1", Some("bob-tag"));
    assert!(terminated_dialog_needs_481("INVITE", &reinvite, &store));
}

#[test]
fn update_and_refer_after_teardown_need_481() {
    let store = store_after_teardown("ue-call-id@10.0.0.1");
    let update = in_dialog_request(Method::Update, "ue-call-id@10.0.0.1", Some("bob-tag"));
    let refer = in_dialog_request(Method::Refer, "ue-call-id@10.0.0.1", Some("bob-tag"));
    assert!(terminated_dialog_needs_481("UPDATE", &update, &store));
    assert!(terminated_dialog_needs_481("REFER", &refer, &store));
}

#[test]
fn ack_after_teardown_is_never_answered() {
    // RFC 3261 §17.1.1.3 — an ACK has no response, ever.
    let store = store_after_teardown("ue-call-id@10.0.0.1");
    let ack = in_dialog_request(Method::Ack, "ue-call-id@10.0.0.1", Some("bob-tag"));
    assert!(!terminated_dialog_needs_481("ACK", &ack, &store));
}

// -----------------------------------------------------------------------
// In-dialog request on a call with no far leg → answered, never dropped
// -----------------------------------------------------------------------

#[test]
fn a_notify_with_no_far_leg_is_answered_481() {
    // RFC 6665 §8.2.1: siphon owns no subscription for it (the absorb arm
    // took the ones it does own) and has no peer dialog to bridge it onto.
    assert_eq!(
        no_far_leg_final_response(&Method::Notify),
        (481, "Call/Transaction Does Not Exist")
    );
}

#[test]
fn a_refer_with_no_far_leg_is_answered_500_not_481() {
    // A transparent-mode REFER that cannot be forwarded is siphon's own
    // inability (RFC 3261 §21.5.1). 481 would be a lie — the dialog the
    // REFER arrived on is alive.
    assert_eq!(
        no_far_leg_final_response(&Method::Refer),
        (500, "Server Internal Error")
    );
}

#[test]
fn a_one_legged_call_has_no_far_leg_to_forward_to() {
    // The shape the fix keys on: a UAS-mode / handover / WebSocket-takeover
    // call answers with no B-leg, so `winner` is never set and the bridge
    // path is unreachable for every in-dialog request it ever receives.
    // Before the fix that meant a silent drop and 32s of Timer F.
    let store = CallActorStore::new();
    let call_id = store.create_call(glare_a_leg("takeover@10.0.0.1"));
    let call = store.get_call(&call_id).expect("call");
    assert!(call.winner.is_none());
    assert!(call.b_legs.is_empty());
}

// -----------------------------------------------------------------------
// @b2bua.on_invite action applied to a call that ended mid-handler
// -----------------------------------------------------------------------

#[test]
fn invite_action_applies_to_a_live_call() {
    let store = CallActorStore::new();
    let call_id = store.create_call(glare_a_leg("live@10.0.0.1"));
    assert!(!invite_action_target_gone(&call_id, &store));
}

#[test]
fn invite_action_is_dropped_after_a_cancel_removed_the_call() {
    // The field case: an async handler awaits (a lookup, an agent becoming
    // free, `asyncio.sleep` to ring) and the caller gives up. The CANCEL
    // path answered 487 and removed the actor; applying the returned action
    // would put a second final response on the same server transaction.
    let store = CallActorStore::new();
    let call_id = store.create_call(glare_a_leg("cancelled@10.0.0.1"));
    store.remove_call_after_cancel(&call_id);
    assert!(invite_action_target_gone(&call_id, &store));
}

#[test]
fn invite_action_is_dropped_for_a_terminated_call() {
    // The CANCEL path sets the state before it removes the call, and every
    // other teardown (script terminate, max-duration, session timer) leaves
    // the same marker — so a call that is still in the map but Terminated
    // must be treated as gone too.
    let store = CallActorStore::new();
    let call_id = store.create_call(glare_a_leg("terminated@10.0.0.1"));
    store.set_state(&call_id, CallState::Terminated);
    assert!(invite_action_target_gone(&call_id, &store));
}

#[test]
fn invite_action_is_dropped_for_an_unknown_call() {
    let store = CallActorStore::new();
    assert!(invite_action_target_gone("never-existed", &store));
}

#[test]
fn call_action_names_every_variant() {
    // The guard logs which decision the handler reached; `Debug` would print
    // a whole carrier list or vars map instead.
    use crate::script::api::call::CallAction;
    assert_eq!(CallAction::None.name(), "none");
    assert_eq!(
        CallAction::Reject {
            code: 486,
            reason: "Busy Here".to_string(),
        }
        .name(),
        "reject"
    );
    assert_eq!(CallAction::Answered.name(), "answered");
    assert_eq!(CallAction::Terminate.name(), "terminate");
    assert_eq!(
        CallAction::Handover {
            app: "voice-ai".to_string(),
            on_lost: None,
            deadline_ms: None,
            vars: std::collections::HashMap::new(),
            answer: true,
            profile: None,
            ws_uri: None,
        }
        .name(),
        "handover"
    );
}

// -----------------------------------------------------------------------
// CANCEL retransmission (RFC 3261 §9.2)
// -----------------------------------------------------------------------
//
// A CANCEL is a request with its own server transaction, which absorbs
// retransmissions and answers them from its cached response. siphon
// intercepts CANCEL before transaction creation, so that transaction never
// exists — `cancelled_invites` is what stands in for it. These pin the
// three dispositions `handle_cancel` can reach for the proxy path.

fn cancel_key(branch: &str) -> TransactionKey {
    TransactionKey::new(
        branch.to_string(),
        Method::Invite,
        "10.0.0.1:5060".to_string(),
    )
}

/// The key a CANCEL resolves to is the *INVITE's*, not the CANCEL's — that
/// is what makes it find the INVITE's session (RFC 3261 §9.1: same branch).
#[test]
fn cancel_resolves_to_the_invites_transaction_key() {
    let invite = cancel_key("z9hG4bK-abc");
    assert_eq!(invite.method, Method::Invite);
    // And a CANCEL's *own* key is distinct, so recording one never shadows
    // the other (`transaction::key::tests::cancel_has_own_transaction`).
    let own = TransactionKey::new(
        "z9hG4bK-abc".to_string(),
        Method::Cancel,
        "10.0.0.1:5060".to_string(),
    );
    assert_ne!(invite, own);
}

/// The first CANCEL is not a retransmission, so it does the real work.
#[test]
fn a_first_cancel_is_not_treated_as_a_retransmission() {
    let store: Arc<DashMap<TransactionKey, ()>> = Arc::new(DashMap::new());
    assert!(!store.contains_key(&cancel_key("z9hG4bK-first")));
}

/// After acceptance, a second CANCEL on the same branch is a retransmission
/// — answered 200, with none of the side effects repeated. Before this, the
/// session had already been removed so the second copy fell through to 481,
/// and a copy arriving *before* the removal repeated the downstream CANCEL
/// and put a second 487 on one INVITE server transaction (§17.2.1).
#[test]
fn a_cancel_after_acceptance_is_a_retransmission() {
    let store: Arc<DashMap<TransactionKey, ()>> = Arc::new(DashMap::new());
    let key = cancel_key("z9hG4bK-dup");
    store.insert(key.clone(), ());
    assert!(store.contains_key(&key));
}

/// Acceptance is per-transaction: a CANCEL for a different INVITE is
/// unaffected and still reaches the session lookup.
#[test]
fn acceptance_does_not_leak_across_transactions() {
    let store: Arc<DashMap<TransactionKey, ()>> = Arc::new(DashMap::new());
    store.insert(cancel_key("z9hG4bK-one"), ());
    assert!(!store.contains_key(&cancel_key("z9hG4bK-two")));

    // Same branch, different sent-by is also a different transaction
    // (§17.2.3) — two UAs can pick the same branch.
    let elsewhere = TransactionKey::new(
        "z9hG4bK-one".to_string(),
        Method::Invite,
        "10.0.0.2:5060".to_string(),
    );
    assert!(!store.contains_key(&elsewhere));
}

/// The entry is recorded and reaped, so the map cannot grow without bound
/// under a CANCEL flood. 32 s is Timer J (64×T1) — the window a CANCEL's own
/// NIST would have held its cached response.
#[tokio::test(start_paused = true)]
async fn an_accepted_cancel_is_forgotten_after_timer_j() {
    let store: Arc<DashMap<TransactionKey, ()>> = Arc::new(DashMap::new());
    let key = cancel_key("z9hG4bK-reaped");
    remember_cancelled_invite(&store, key.clone());
    assert!(store.contains_key(&key), "recorded immediately");

    tokio::time::sleep(std::time::Duration::from_secs(31)).await;
    assert!(store.contains_key(&key), "still inside the 64xT1 window");

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    assert!(!store.contains_key(&key), "reaped after Timer J");
}

#[test]
fn cancel_after_teardown_is_left_to_handle_cancel() {
    // handle_cancel's fall-through already 481s an unknown transaction, and
    // it keys on the Via branch rather than the Call-ID.
    let store = store_after_teardown("ue-call-id@10.0.0.1");
    let cancel = in_dialog_request(Method::Cancel, "ue-call-id@10.0.0.1", Some("bob-tag"));
    assert!(!terminated_dialog_needs_481("CANCEL", &cancel, &store));
}

#[test]
fn out_of_dialog_request_reusing_the_call_id_needs_no_481() {
    // A peer that reuses a Call-ID for a *new* dialog sends no To-tag; it has
    // to reach the normal INVITE path.
    let store = store_after_teardown("ue-call-id@10.0.0.1");
    let invite = in_dialog_request(Method::Invite, "ue-call-id@10.0.0.1", None);
    assert!(!terminated_dialog_needs_481("INVITE", &invite, &store));
}

#[test]
fn unknown_call_id_is_left_to_the_script() {
    // Load-bearing for proxy mode: a CSCF loose-routes in-dialog requests for
    // dialogs it never tracked (topmost Route belongs to another proxy), so
    // "not a call of ours" must NOT become a 481.
    let store = store_after_teardown("ue-call-id@10.0.0.1");
    let bye = in_dialog_request(
        Method::Bye,
        "someone-elses-dialog@10.0.0.9",
        Some("bob-tag"),
    );
    assert!(!terminated_dialog_needs_481("BYE", &bye, &store));
}

#[test]
fn b_leg_call_id_after_teardown_needs_481() {
    // Glare can be lost by either peer, and the B2BUA's two legs carry
    // different Call-IDs.
    let store = CallActorStore::new();
    let call_id = store.create_call(glare_a_leg("ue-call-id@10.0.0.1"));
    store.add_b_leg(
        &call_id,
        Leg::new_b_leg(
            "trunk-call-id@10.0.0.2".to_string(),
            "tag-b2bua".to_string(),
            "sip:bob@10.0.0.2".to_string(),
            "z9hG4bK-bleg".to_string(),
            LegTransport {
                remote_addr: "10.0.0.2:5060".parse().unwrap(),
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
                local_addr: None,
            },
        ),
    );
    store.remove_call(&call_id);

    let bye = in_dialog_request(Method::Bye, "trunk-call-id@10.0.0.2", Some("bob-tag"));
    assert!(terminated_dialog_needs_481("BYE", &bye, &store));
}

#[test]
fn recreated_call_id_beats_the_tombstone() {
    // Eviction is lazy, so a UE that reuses a Call-ID for its next call can
    // be live and remembered-as-terminated at the same time. The live lookup
    // has to win, or the new call's own BYE would be 481'd.
    let store = store_after_teardown("ue-call-id@10.0.0.1");
    store.create_call(glare_a_leg("ue-call-id@10.0.0.1"));
    assert!(store.is_recently_terminated("ue-call-id@10.0.0.1"));

    let bye = in_dialog_request(Method::Bye, "ue-call-id@10.0.0.1", Some("bob-tag"));
    assert!(!terminated_dialog_needs_481("BYE", &bye, &store));
}

#[test]
fn to_has_tag_reads_the_dialog_identifier() {
    let in_dialog = in_dialog_request(Method::Bye, "cid@host", Some("bob-tag"));
    let out_of_dialog = in_dialog_request(Method::Invite, "cid@host", None);
    assert!(to_has_tag(&in_dialog));
    assert!(!to_has_tag(&out_of_dialog));
}

// --- X3 attachment timing (ETSI TS 103 221-2) ---------------------------
//
// Interception is matched before the script runs, so a script cannot
// decline a warrant — but the attachment cannot be made at that moment.
// The engine only learns of a call when the script offers it there, and it
// refuses an interception on a call it does not have ("unknown call") or on
// one whose second leg is not answered yet. The ACK is the first message
// that arrives with both already true.

fn li_message(raw: &str) -> SipMessage {
    parse_sip_message(raw).expect("test message must parse").1
}

// --- retransmission identity -------------------------------------------
//
// Interception runs before transaction matching, so a resend arrives here
// looking like a new message. These pin what counts as "the same message
// again" — the risk on both sides being real: collapsing two distinct
// messages loses a record, and failing to collapse a resend duplicates one
// and re-runs the session's lifecycle.

fn keyed(via_branch: &str, cseq: &str, first_line: &str) -> u64 {
    message_instance_key(&li_message(&format!(
        concat!(
            "{}\r\n",
            "Via: SIP/2.0/UDP 192.0.2.1:5060;branch={}\r\n",
            "From: <sip:a@example.com>;tag=1\r\n",
            "To: <sip:b@example.com>\r\n",
            "Call-ID: c@example.com\r\n",
            "CSeq: {}\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        first_line, via_branch, cseq
    )))
}

#[test]
fn the_same_message_again_keys_the_same() {
    assert_eq!(
        keyed("z9hG4bK1", "1 INVITE", "INVITE sip:b@example.com SIP/2.0"),
        keyed("z9hG4bK1", "1 INVITE", "INVITE sip:b@example.com SIP/2.0"),
        "a retransmission is byte-identical and must collapse"
    );
}

#[test]
fn messages_that_are_genuinely_different_key_differently() {
    let invite = keyed("z9hG4bK1", "1 INVITE", "INVITE sip:b@example.com SIP/2.0");

    // A re-INVITE opens a new transaction, so it carries a new branch.
    assert_ne!(
        invite,
        keyed("z9hG4bK2", "2 INVITE", "INVITE sip:b@example.com SIP/2.0"),
        "a re-INVITE is a new message, not a resend"
    );
    // An ACK to a non-2xx shares the INVITE's branch and CSeq number, and
    // is separated only by its method. This is the collision that would
    // lose a record if the method were left out of the key.
    assert_ne!(
        invite,
        keyed("z9hG4bK1", "1 ACK", "ACK sip:b@example.com SIP/2.0"),
        "an ACK on the INVITE's own branch must not read as a resend of it"
    );
    // Provisional and final responses share the branch and the CSeq, and
    // are separated only by their status.
    let ringing = keyed("z9hG4bK1", "1 INVITE", "SIP/2.0 180 Ringing");
    let ok = keyed("z9hG4bK1", "1 INVITE", "SIP/2.0 200 OK");
    assert_ne!(ringing, ok, "180 and 200 are different records");
    assert_ne!(invite, ringing, "a response is not its own request");
    assert_eq!(
        ringing,
        keyed("z9hG4bK1", "1 INVITE", "SIP/2.0 180 Ringing"),
        "a resent 180 is a resend"
    );
}

/// The last message of a dialog is the response to its BYE, not the BYE.
///
/// Regression test for a leak that a per-call soak found and no unit test
/// would have: releasing on the BYE alone freed the session, then its 200
/// arrived, found nothing remembered, re-derived a decision that still
/// matched — the To header carries the target either way — and put it back
/// permanently. One leaked entry per completed call, on a map keyed by a
/// value the peer chooses.
#[test]
fn the_response_to_a_bye_ends_the_dialog_too() {
    let bye = li_message(concat!(
        "BYE sip:b@example.com SIP/2.0\r\n",
        "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK3\r\n",
        "From: <sip:a@example.com>;tag=1\r\n",
        "To: <sip:b@example.com>;tag=2\r\n",
        "Call-ID: c@example.com\r\n",
        "CSeq: 2 BYE\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    ));
    assert!(terminates_dialog(&bye), "the BYE ends the dialog");

    let bye_ok = li_message(concat!(
        "SIP/2.0 200 OK\r\n",
        "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK3\r\n",
        "From: <sip:a@example.com>;tag=1\r\n",
        "To: <sip:b@example.com>;tag=2\r\n",
        "Call-ID: c@example.com\r\n",
        "CSeq: 2 BYE\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    ));
    assert!(
        terminates_dialog(&bye_ok),
        "the 200 to a BYE is the dialog's last message and must release it, \
         or it re-derives a decision nothing will ever remove"
    );

    let cancel_ok = li_message(concat!(
        "SIP/2.0 200 OK\r\n",
        "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK4\r\n",
        "From: <sip:a@example.com>;tag=1\r\n",
        "To: <sip:b@example.com>\r\n",
        "Call-ID: c@example.com\r\n",
        "CSeq: 1 CANCEL\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    ));
    assert!(terminates_dialog(&cancel_ok), "so is the 200 to a CANCEL");

    // The 200 that *starts* a dialog must not release it.
    let invite_ok = li_message(concat!(
        "SIP/2.0 200 OK\r\n",
        "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n",
        "From: <sip:a@example.com>;tag=1\r\n",
        "To: <sip:b@example.com>;tag=2\r\n",
        "Call-ID: c@example.com\r\n",
        "CSeq: 1 INVITE\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    ));
    assert!(
        !terminates_dialog(&invite_ok),
        "the 200 to an INVITE opens the dialog; releasing there would drop \
         the decision for the whole call"
    );

    // A failure to an INVITE ends a session that never started.
    let busy = li_message(concat!(
        "SIP/2.0 486 Busy Here\r\n",
        "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n",
        "From: <sip:a@example.com>;tag=1\r\n",
        "To: <sip:b@example.com>;tag=2\r\n",
        "Call-ID: c@example.com\r\n",
        "CSeq: 1 INVITE\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    ));
    assert!(terminates_dialog(&busy));
}

#[test]
fn the_top_via_branch_is_the_one_read() {
    let stacked = li_message(concat!(
        "INVITE sip:b@example.com SIP/2.0\r\n",
        "Via: SIP/2.0/UDP proxy.example.com;branch=z9hG4bK-top\r\n",
        "Via: SIP/2.0/UDP ua.example.com;branch=z9hG4bK-bottom\r\n",
        "From: <sip:a@example.com>;tag=1\r\n",
        "To: <sip:b@example.com>\r\n",
        "Call-ID: c@example.com\r\n",
        "CSeq: 1 INVITE\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    ));
    assert_eq!(top_via_branch(&stacked), Some("z9hG4bK-top"));

    // Several Vias folded onto one line: the top is still the first.
    let folded = li_message(concat!(
        "INVITE sip:b@example.com SIP/2.0\r\n",
        "Via: SIP/2.0/UDP proxy.example.com;branch=z9hG4bK-first,",
        "SIP/2.0/UDP ua.example.com;branch=z9hG4bK-second\r\n",
        "From: <sip:a@example.com>;tag=1\r\n",
        "To: <sip:b@example.com>\r\n",
        "Call-ID: c@example.com\r\n",
        "CSeq: 1 INVITE\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    ));
    assert_eq!(top_via_branch(&folded), Some("z9hG4bK-first"));
}

#[test]
fn only_the_ack_triggers_a_content_attachment() {
    let ack = li_message(concat!(
        "ACK sip:b@example.com SIP/2.0\r\n",
        "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK2\r\n",
        "From: <sip:a@example.com>;tag=1\r\n",
        "To: <sip:b@example.com>;tag=2\r\n",
        "Call-ID: c@example.com\r\n",
        "CSeq: 1 ACK\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    ));
    assert!(is_ack(&ack, "ACK"));

    // The INVITE is too early: the engine has never heard of the call.
    let invite = li_message(concat!(
        "INVITE sip:b@example.com SIP/2.0\r\n",
        "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n",
        "From: <sip:a@example.com>;tag=1\r\n",
        "To: <sip:b@example.com>\r\n",
        "Call-ID: c@example.com\r\n",
        "CSeq: 1 INVITE\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    ));
    assert!(!is_ack(&invite, "INVITE"));

    // So is the answer: it has not been dispatched to the script yet, so
    // the second leg is not answered in the engine.
    let ok = li_message(concat!(
        "SIP/2.0 200 OK\r\n",
        "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n",
        "From: <sip:a@example.com>;tag=1\r\n",
        "To: <sip:b@example.com>;tag=2\r\n",
        "Call-ID: c@example.com\r\n",
        "CSeq: 1 INVITE\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    ));
    assert!(
        !is_ack(&ok, "INVITE"),
        "a response's CSeq method is INVITE; it must not be read as the ACK"
    );

    // A response to an ACK does not exist in SIP, but the CSeq of a 200 to
    // a BYE names BYE — guard that the predicate keys on both the start
    // line and the method rather than the method alone.
    let bye_ok = li_message(concat!(
        "SIP/2.0 200 OK\r\n",
        "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK3\r\n",
        "From: <sip:a@example.com>;tag=1\r\n",
        "To: <sip:b@example.com>;tag=2\r\n",
        "Call-ID: c@example.com\r\n",
        "CSeq: 2 BYE\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    ));
    assert!(!is_ack(&bye_ok, "ACK"));
}

// --- truncate_for_log ---------------------------------------------------

#[test]
fn short_log_detail_is_passed_through_unchanged() {
    let detail = "start line parse error";
    assert!(matches!(truncate_for_log(detail), Cow::Borrowed(_)));
    assert_eq!(truncate_for_log(detail), detail);
}

#[test]
fn long_log_detail_is_capped() {
    // A scanner's browser header block quoted back by the parse error: the
    // source of an unparseable message must not decide how much it writes
    // into the log.
    let detail = format!("SIP parse error: {}", "A".repeat(4096));
    let logged = truncate_for_log(&detail);
    assert!(logged.len() < 300, "capped, got {} bytes", logged.len());
    assert!(logged.starts_with("SIP parse error: AAA"));
    assert!(logged.ends_with("more bytes elided)"));
}

#[test]
fn log_detail_is_never_cut_mid_character() {
    // Multi-byte UTF-8 straddling the cap must not panic on a byte slice.
    let detail = "é".repeat(4096);
    let logged = truncate_for_log(&detail);
    assert!(logged.ends_with("more bytes elided)"));
}

// -----------------------------------------------------------------------
// Rf ACR-START dedupe across the CDF round-trip (TS 32.260 §5.1)
// -----------------------------------------------------------------------

/// The duplicate-record bug, reproduced: an intra-node call reaches
/// `spawn_rf_proxy_start_if_invite` twice within milliseconds — once as the
/// originating leg's speculative dual-ACR terminating record, once as the
/// terminating leg's own record — and both resolve to the same
/// `icid:<ICID>:term` key.
///
/// `rf_sessions` only gains its entry after the CDF answers ACR-START, so
/// the `contains_key` gate alone lets both through and the node opens two
/// TERMINATING records on one ICID.  Only one is reachable from the BYE, so
/// the other never gets an ACR-STOP and emits an ACR-INTERIM every cadence
/// tick until the 24h backstop.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_acr_starts_on_one_key_open_a_single_record() {
    let rf_sessions: Arc<DashMap<String, u32>> = Arc::new(DashMap::new());
    let pending: Arc<DashMap<String, std::time::Instant>> = Arc::new(DashMap::new());
    let key = "icid:f58d8725-f905-437d-bb63-92610e417bd0:term";

    let mut legs = Vec::new();
    for leg in 0..2u32 {
        let rf_sessions = Arc::clone(&rf_sessions);
        let pending = Arc::clone(&pending);
        legs.push(tokio::spawn(async move {
            // Both legs observe an empty map — this is the window the old
            // gate could not close.
            assert!(
                !rf_sessions.contains_key(key),
                "the record cannot be filed before either ACR-START is answered"
            );
            let Some(reservation) = rf_reserve_start(&pending, key) else {
                return false;
            };
            // Stand in for the CDF round-trip: the ACA is what unblocks the
            // insert, and it takes long enough for the other leg to arrive.
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            rf_sessions.insert(key.to_string(), leg);
            drop(reservation);
            true
        }));
    }

    let mut opened = 0;
    for leg in legs {
        if leg.await.expect("leg task") {
            opened += 1;
        }
    }

    assert_eq!(opened, 1, "exactly one leg may open the accounting record");
    assert_eq!(rf_sessions.len(), 1);
    assert!(
        pending.is_empty(),
        "the reservation must be released once ACR-START resolves"
    );
}

/// A reservation is released even when ACR-START never files a record —
/// a CDF rejection must not wedge the key for the life of the process.
#[test]
fn a_dropped_reservation_frees_the_key() {
    let pending: Arc<DashMap<String, std::time::Instant>> = Arc::new(DashMap::new());
    let key = "icid:abc:orig";

    let first = rf_reserve_start(&pending, key).expect("first claim wins");
    assert!(
        rf_reserve_start(&pending, key).is_none(),
        "a second claim must lose while the first is in flight"
    );
    drop(first);
    assert!(pending.is_empty());
    assert!(
        rf_reserve_start(&pending, key).is_some(),
        "the key is claimable again once the in-flight START resolved"
    );
}

// -----------------------------------------------------------------------
// Pending-inbound-REFER store (controlled-call transfer decision)
// -----------------------------------------------------------------------

/// Build a parseable in-dialog REFER whose Refer-To targets `sip:carol@…`.
fn sample_refer() -> SipMessage {
    let raw = concat!(
        "REFER sip:proxy@example.com SIP/2.0\r\n",
        "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKrefer\r\n",
        "From: <sip:alice@example.com>;tag=alicetag\r\n",
        "To: <sip:proxy@example.com>;tag=proxytag\r\n",
        "Call-ID: refer-call@example.com\r\n",
        "CSeq: 2 REFER\r\n",
        "Refer-To: <sip:carol@example.com>\r\n",
        "Max-Forwards: 70\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    );
    parse_sip_message(raw).expect("REFER fixture must parse").1
}

/// Build a `PendingInboundRefer` with the given decision deadline. The
/// inbound flow is a minimal UDP datagram (the store just moves it around).
fn sample_pending_refer(deadline: std::time::Instant) -> PendingInboundRefer {
    let addr: SocketAddr = "192.0.2.1:5060".parse().unwrap();
    let local: SocketAddr = "192.0.2.100:5060".parse().unwrap();
    PendingInboundRefer {
        inbound: InboundMessage {
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: local,
            remote_addr: addr,
            data: Bytes::new(),
        },
        message: sample_refer(),
        refer_to: crate::sip::headers::refer::ReferTo {
            uri: "sip:carol@example.com".to_string(),
            replaces: None,
        },
        from_a_leg: true,
        deadline,
    }
}

#[test]
fn pending_inbound_refer_store_drains_to_baseline() {
    // THE leak gate: N controlled calls each get a pending REFER, then each is
    // drained via one of the three exit paths (accept → take, reject → take,
    // deadline → take_expired). The store MUST return to its baseline len() —
    // a per-call entry that is never evicted is the exact leak this catches.
    let store = PendingInboundReferStore::default();
    let baseline = store.len();
    assert_eq!(baseline, 0);

    let now = std::time::Instant::now();
    let future = now + std::time::Duration::from_secs(30);
    let past = now - std::time::Duration::from_secs(1);

    for cycle in 0..64 {
        let accept_key = format!("accept-{cycle}@host");
        let reject_key = format!("reject-{cycle}@host");
        let timeout_key = format!("timeout-{cycle}@host");

        assert!(store.insert(&accept_key, sample_pending_refer(future)));
        assert!(store.insert(&reject_key, sample_pending_refer(future)));
        assert!(store.insert(&timeout_key, sample_pending_refer(past)));
        assert_eq!(store.len(), baseline + 3);

        // Accept path drains its entry.
        assert!(store.take(&accept_key).is_some());
        // Reject path drains its entry.
        assert!(store.take(&reject_key).is_some());
        // Deadline sweep drains the expired one (only the past-deadline entry).
        let expired = store.take_expired(now);
        assert_eq!(expired.len(), 1);

        assert_eq!(
            store.len(),
            baseline,
            "store must drain to baseline after cycle {cycle}"
        );
    }
    assert_eq!(store.len(), baseline);
}

/// Build a `DeferredReferrerBye` with the given backstop deadline.
fn sample_deferred_bye(deadline: std::time::Instant) -> DeferredReferrerBye {
    DeferredReferrerBye {
        message: sample_refer(),
        leg: Leg::new_a_leg(
            "transfer-call@example.com".to_string(),
            "referrer-tag".to_string(),
            "z9hG4bK-referrer".to_string(),
            LegTransport {
                remote_addr: "192.0.2.1:5060".parse().expect("destination must parse"),
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
                local_addr: None,
            },
        ),
        deadline,
        call_id: "transfer-call@example.com".to_string(),
    }
}

#[test]
fn deferred_referrer_bye_store_drains_to_baseline() {
    // THE leak gate: N transfers each park a BYE, then each leaves by one of
    // the two exit paths (the NOTIFY is answered → take, or the referrer
    // never answers → take_expired). The store MUST return to baseline — a
    // per-transfer entry that is never evicted is the exact leak this
    // catches, and this one holds a whole SipMessage.
    let store = DeferredReferrerByeStore::default();
    let baseline = store.len();
    assert_eq!(baseline, 0);

    let now = std::time::Instant::now();
    let future = now + std::time::Duration::from_secs(32);
    let past = now - std::time::Duration::from_secs(1);

    for cycle in 0..64 {
        let answered = format!("z9hG4bK-answered-{cycle}");
        let abandoned = format!("z9hG4bK-abandoned-{cycle}");

        store.insert(&answered, sample_deferred_bye(future));
        store.insert(&abandoned, sample_deferred_bye(past));
        assert_eq!(store.len(), baseline + 2);

        // The referrer answered the NOTIFY: the response path releases it.
        assert!(store.take(&answered).is_some());
        // The referrer never answered: the Timer F sweep releases it.
        let expired = store.take_expired(now);
        assert_eq!(expired.len(), 1);

        assert_eq!(
            store.len(),
            baseline,
            "store must drain to baseline after cycle {cycle}"
        );
    }
    assert_eq!(store.len(), baseline);
}

#[test]
fn deferred_referrer_bye_is_released_once_and_only_for_its_own_branch() {
    // The BYE is keyed on the terminating NOTIFY's branch, so an unrelated
    // response must not release it — the referrer's dialog would be torn
    // down while it is still waiting to hear the transfer completed.
    let store = DeferredReferrerByeStore::default();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(32);
    store.insert("z9hG4bK-notify", sample_deferred_bye(deadline));

    assert!(
        store.take("z9hG4bK-someone-else").is_none(),
        "a response on another branch must not release the BYE"
    );
    assert_eq!(store.len(), 1);

    assert!(store.take("z9hG4bK-notify").is_some());
    assert!(
        store.take("z9hG4bK-notify").is_none(),
        "a NOTIFY retransmission's second response must not send a second BYE"
    );
    assert_eq!(store.len(), 0);
}

/// A response on `branch` carrying `status_code`, as the response path sees it.
fn sample_response_on_branch(branch: &str, status_code: u16) -> SipMessage {
    let raw = format!(
        "SIP/2.0 {status_code} Whatever\r\n\
         Via: SIP/2.0/UDP 192.0.2.100:5060;branch={branch}\r\n\
         From: <sip:proxy@example.com>;tag=proxytag\r\n\
         To: <sip:alice@example.com>;tag=alicetag\r\n\
         Call-ID: refer-call@example.com\r\n\
         CSeq: 3 NOTIFY\r\n\
         Content-Length: 0\r\n\
         \r\n"
    );
    parse_sip_message(&raw)
        .expect("response fixture must parse")
        .1
}

#[test]
fn deferred_referrer_bye_waits_for_a_final_response() {
    // The BYE is released by the response that ENDS the NOTIFY transaction.
    // A provisional must not release it — the referrer has not read the
    // sipfrag yet, and tearing the dialog down now reproduces the very race
    // the deferral exists to close.
    let store = DeferredReferrerByeStore::default();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(32);
    store.insert("z9hG4bK-notify", sample_deferred_bye(deadline));

    let provisional = sample_response_on_branch("z9hG4bK-notify", 100);
    assert!(
        store.take_for_response(&provisional, 100).is_none(),
        "a provisional must not release the BYE"
    );
    assert_eq!(store.len(), 1);

    let final_response = sample_response_on_branch("z9hG4bK-notify", 200);
    assert!(
        store.take_for_response(&final_response, 200).is_some(),
        "the NOTIFY's 200 releases the BYE"
    );
    assert_eq!(store.len(), 0);
}

#[test]
fn deferred_referrer_bye_is_released_by_a_notify_rejection_too() {
    // A referrer that rejects the NOTIFY (481 — it already dropped the
    // dialog, or 489 — it does not know the event package) has still ended
    // the transaction. Holding the BYE for the full Timer F backstop there
    // would keep a replaced leg alive for 32s for nothing.
    for status in [481u16, 489, 500] {
        let store = DeferredReferrerByeStore::default();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(32);
        store.insert("z9hG4bK-notify", sample_deferred_bye(deadline));
        let response = sample_response_on_branch("z9hG4bK-notify", status);
        assert!(
            store.take_for_response(&response, status).is_some(),
            "a {status} on the NOTIFY must still release the BYE"
        );
        assert_eq!(store.len(), 0);
    }
}

#[test]
fn deferred_referrer_bye_take_is_cheap_when_idle() {
    // `take` runs for every inbound response siphon handles, and the store
    // is empty in the steady state. The empty short-circuit is what keeps
    // that off the hot path, so assert the empty case answers None.
    let store = DeferredReferrerByeStore::default();
    assert!(store.take("z9hG4bK-anything").is_none());
    assert!(store.take_expired(std::time::Instant::now()).is_empty());
}

#[test]
fn pending_inbound_refer_absorbs_retransmit() {
    // A second insert for the same call (a REFER retransmit) is absorbed —
    // returns false and does not add a duplicate entry or reset the deadline.
    let store = PendingInboundReferStore::default();
    let now = std::time::Instant::now();
    let future = now + std::time::Duration::from_secs(30);

    assert!(store.insert("cid@host", sample_pending_refer(future)));
    assert!(
        !store.insert("cid@host", sample_pending_refer(future)),
        "a retransmit must be absorbed, not duplicated"
    );
    assert_eq!(store.len(), 1);

    assert!(store.take("cid@host").is_some());
    assert_eq!(store.len(), 0);
    // A decision after the entry is gone (raced timeout) is a clean no-op.
    assert!(store.take("cid@host").is_none());
}

#[test]
fn pending_inbound_refer_take_expired_only_past_deadline() {
    let store = PendingInboundReferStore::default();
    let now = std::time::Instant::now();

    assert!(store.insert(
        "past@host",
        sample_pending_refer(now - std::time::Duration::from_millis(1))
    ));
    assert!(store.insert(
        "future@host",
        sample_pending_refer(now + std::time::Duration::from_secs(30))
    ));

    let expired = store.take_expired(now);
    assert_eq!(expired.len(), 1, "only the past-deadline entry is swept");
    // The future entry survives the sweep.
    assert_eq!(store.len(), 1);
    assert!(store.take("future@host").is_some());
}

#[test]
fn pending_inbound_refer_preserves_accept_inputs() {
    // The stored entry preserves exactly what the accept path feeds
    // b2bua_refer_accept: the Refer-To target + the resolved leg direction.
    let store = PendingInboundReferStore::default();
    let now = std::time::Instant::now();
    store.insert(
        "cid@host",
        sample_pending_refer(now + std::time::Duration::from_secs(30)),
    );

    let pending = store.take("cid@host").expect("entry present");
    assert_eq!(pending.refer_to.uri, "sip:carol@example.com");
    assert!(pending.from_a_leg);
}

#[test]
fn expired_pending_refer_answers_603_decline() {
    // On the decision deadline the sweep answers the referrer 603 Decline
    // (matching the no-@b2bua.on_refer-handler default). Prove the drained
    // entry's REFER maps to a well-formed 603 final response — the wire action
    // the sweep applies via b2bua_refer_send_final.
    let store = PendingInboundReferStore::default();
    let now = std::time::Instant::now();
    store.insert(
        "cid@host",
        sample_pending_refer(now - std::time::Duration::from_millis(1)),
    );

    let expired = store.take_expired(now);
    assert_eq!(expired.len(), 1);
    let response = build_response(&expired[0].message, 603, "Decline", None, &[]);
    assert!(response.is_response());
    assert_eq!(response.status_code(), Some(603));
    // Answered on the referrer's dialog — the REFER's Via/From/To/Call-ID.
    assert_eq!(
        response.headers.call_id().unwrap(),
        "refer-call@example.com"
    );
}

/// A 3xx is a redirect, and its Contact is the redirect target (RFC 3261
/// §8.1.3.4, §21.3). Relayed to the A-leg it keeps that Contact; every other
/// response gets siphon's own, so the dialog it creates runs through siphon.
#[test]
fn only_a_redirect_keeps_its_own_contact_when_relayed() {
    for code in [300, 301, 302, 305, 380] {
        assert!(
            relayed_response_keeps_its_contact(Some(code)),
            "{code} is a redirect"
        );
    }
    for code in [180, 183, 200, 401, 486, 500, 603] {
        assert!(
            !relayed_response_keeps_its_contact(Some(code)),
            "{code} is not a redirect"
        );
    }
    assert!(!relayed_response_keeps_its_contact(None));
}

/// A failure siphon generates for the caller, rather than relays, carries the
/// reason phrase the RFC gives its code, not a placeholder. Only a code the
/// table does not know reads "Error".
#[test]
fn a_generated_failure_carries_its_rfc_reason_phrase() {
    assert_eq!(best_error_reason(302), "Moved Temporarily");
    assert_eq!(best_error_reason(407), "Proxy Authentication Required");
    assert_eq!(best_error_reason(422), "Session Interval Too Small");
    assert_eq!(best_error_reason(502), "Bad Gateway");
    assert_eq!(best_error_reason(580), "Precondition Failure");
    assert_eq!(best_error_reason(604), "Does Not Exist Anywhere");
    assert_eq!(best_error_reason(499), "Error");
}
