//! The entry point every inbound datagram and stream frame reaches.
//!
//! Frames, parses, validates and routes a message to the right handler. The
//! helpers here answer the questions that routing needs before it can decide:
//! is this an ACK, does it terminate a dialog, which branch is it on.

use super::*;

/// Handle a single inbound SIP message (request or response).
pub(super) fn handle_inbound(inbound: InboundMessage, state: &Arc<DispatcherState>) {
    // Defensive drop of all-whitespace UDP datagrams (RFC 3261 §7.5 — peers
    // may send stray CRLF as a NAT keepalive ping).  Stream transports
    // (TCP/TLS/WSS/pool) handle RFC 5626 §4.4.1 ping/pong in their own
    // read tasks before forwarding to the dispatcher, so this branch only
    // fires for UDP and shields the parser from logging a warn.
    //
    // Fast-path gate: real SIP messages start with an uppercase ASCII
    // letter, so the all-bytes scan only runs when the first byte already
    // looks like whitespace.
    if matches!(inbound.data.first(), Some(b'\r' | b'\n' | b' ')) {
        let all_whitespace = inbound
            .data
            .iter()
            .all(|b| matches!(b, b'\r' | b'\n' | b' '));
        if all_whitespace {
            return;
        }
    }

    // Parse SIP message — supports binary bodies (e.g. SMS TPDU)
    let message = match parse_sip_message_bytes(&inbound.data) {
        Ok(message) => message,
        Err(error) => {
            warn!(
                remote = %inbound.remote_addr,
                "SIP parse error: {}", truncate_for_log(&error.to_string())
            );
            return;
        }
    };

    // HEP capture — inbound (received from network)
    if let Some(ref hep) = state.hep_sender {
        hep.capture_inbound(
            inbound.remote_addr,
            state.hep_local_addr(inbound.local_addr, inbound.transport),
            inbound.transport,
            &inbound.data,
        );
    }

    // RFC 3261 validation of a message that parsed but is still invalid — an
    // unsupported version, a CSeq at odds with the Request-Line, a malformed
    // address header. The peer is owed the status the RFC names, so this runs
    // before any routing. A response that fails validation cannot be answered,
    // so it is discarded (RFC 4475 §3.1.2.5).
    if let Err(rejection) = crate::sip::validate::validate_message(&message) {
        match &message.start_line {
            StartLine::Request(_) => {
                warn!(
                    remote = %inbound.remote_addr,
                    status = rejection.status,
                    "rejecting malformed request: {}", rejection.detail
                );
                // Building a response needs the Via to route it back; without
                // one there is nowhere to send it (RFC 3261 §8.2.6.1).
                if message.headers.get("Via").is_some() {
                    let response = build_response(
                        &message,
                        rejection.status,
                        rejection.reason,
                        state.server_header.as_deref(),
                        &[],
                    );
                    send_message_from(
                        response,
                        inbound.transport,
                        inbound.remote_addr,
                        inbound.connection_id,
                        Some(inbound.local_addr),
                        state,
                    );
                }
            }
            StartLine::Response(_) => {
                warn!(
                    remote = %inbound.remote_addr,
                    "discarding malformed response: {}", rejection.detail
                );
            }
        }
        return;
    }

    // Registrar-liveness SIP-layer last-seen (Part B, fix A).  Any message
    // arriving on a P-CSCF protected port is inbound traffic from a UE with a
    // live IPsec SA — a direct liveness signal siphon observes even when the
    // kernel XFRM `use_time` counter fails to advance.  The SA-idle sweep folds
    // this into its idle test, so a UE that just answered anything (its
    // keepalive, an MO request, or the OPTIONS probe's 200) is not re-probed
    // for a full idle window.  Gated on `enabled` first so it is a single bool
    // read when liveness is off (the default); `is_protected_local_port` bounds
    // the keyspace to active IPsec UEs.
    if state.registrar_liveness.enabled
        && crate::script::api::ipsec::is_protected_local_port(inbound.local_addr.port())
    {
        if let Some(now) = now_unix() {
            state
                .liveness_last_seen
                .insert(inbound.remote_addr.ip(), now);
        }
    }

    // --- Lawful interception (ETSI TS 103 221) ---
    //
    // Every message, every leg, every path — before routing, and before any
    // Python handler runs. This is deliberately not something a script opts
    // into: a warrant a script forgot to act on is a missed intercept, and a
    // missed leg on a warranted intercept is a reportable failure.
    //
    // Placed after parse and validation so the identities are trustworthy, and
    // before dispatch so a script cannot drop the message first.
    //
    // That placement is also before transaction matching, so a UDP
    // retransmission produces a second record for a message the mediation
    // function has already seen. That is deliberate and not an oversight: the
    // element reports what arrived, and de-duplicating would mean keeping
    // another map keyed on peer-supplied values and accepting a way to *drop* a
    // record that only looked like a repeat. For a warrant, a duplicated record
    // is recoverable at the mediation function and a missing one is not.
    intercept_message(&message, &inbound, state);

    // Count the message on the way past. This is the one point every transport
    // funnels through where the start line is still typed, so it is where the
    // `direction="in"` half of `siphon_requests_total` / `siphon_responses_total`
    // is taken. It sits *above* transaction matching, so retransmissions count
    // each time — these are wire-event counters, not transaction counters (the
    // metric help text says so).
    let recorded_metrics = crate::metrics::try_metrics();

    // Debug capture rides the same chokepoint as the inbound counters, for the
    // same reason: it is the one place every transport funnels through. Off by
    // default, so the steady-state cost is one relaxed atomic load; when on,
    // the Call-ID is already parsed here and the wire bytes are already in
    // hand, so recording is a refcount bump rather than a re-serialization.
    if crate::capture::is_enabled() {
        crate::capture::capture().record(
            message
                .headers
                .call_id()
                .map(String::as_str)
                .unwrap_or_default(),
            crate::capture::Direction::In,
            inbound.remote_addr.to_string(),
            inbound.transport.label(),
            inbound.data.clone(),
        );
    }

    match &message.start_line {
        StartLine::Request(request_line) => {
            if let Some(metrics) = recorded_metrics {
                metrics.record_request(&request_line.method, crate::metrics::Direction::In);
            }
            let method = request_line.method.as_str().to_string();
            handle_request(inbound, message, method, state);
        }
        StartLine::Response(status_line) => {
            if let Some(metrics) = recorded_metrics {
                metrics.record_response(status_line.status_code, crate::metrics::Direction::In);
            }
            let status_code = status_line.status_code;
            handle_response(inbound, message, status_code, state);
        }
    }
}

/// A stable identity for one message *instance*, for retransmission detection.
///
/// Built from the top `Via` branch, the CSeq, the method and the status. RFC
/// 3261 §8.1.1.7 requires a new branch for every new transaction, so a resend
/// keeps its branch while anything genuinely new does not — and the remaining
/// fields separate the messages within one transaction, so an ACK, a second
/// provisional and a final response never collide with each other.
///
/// Hashed rather than assembled, because the only question asked of it is
/// whether it has been seen, and a per-message allocation on this path is
/// exactly what the rest of this function avoids.
pub(super) fn message_instance_key(message: &SipMessage) -> u64 {
    // FNV-1a, matching `correlation_from_call_id`: no allocation, and stable
    // within the process, which is all this needs.
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET_BASIS;
    let mut absorb = |bytes: &[u8]| {
        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(PRIME);
        }
        // A separator, so that ("ab", "c") and ("a", "bc") do not collide.
        hash ^= 0xff;
        hash = hash.wrapping_mul(PRIME);
    };

    absorb(top_via_branch(message).unwrap_or_default().as_bytes());
    absorb(
        message
            .headers
            .get("CSeq")
            .map(String::as_str)
            .unwrap_or_default()
            .as_bytes(),
    );
    match &message.start_line {
        StartLine::Request(request_line) => absorb(request_line.method.as_str().as_bytes()),
        StartLine::Response(status_line) => absorb(&status_line.status_code.to_be_bytes()),
    }
    hash
}

/// The branch parameter of the top `Via`.
///
/// Read straight out of the header rather than through the typed parser: this
/// runs per intercepted message and only needs the token, not a parsed Via.
pub(super) fn top_via_branch(message: &SipMessage) -> Option<&str> {
    // A single header line may carry several comma-separated Vias; the top one
    // is the first.
    let top = message.headers.get("Via")?.split(',').next()?;
    top.split(';')
        .map(str::trim)
        .find_map(|parameter| parameter.strip_prefix("branch="))
}

/// Whether this message ends the dialog it belongs to.
///
/// Used to release a session's remembered matching decision. Deliberately
/// generous about what counts: releasing early costs one re-derivation on the
/// next message of a session that turned out not to be over, while releasing
/// late costs memory on a busy node.
pub(super) fn terminates_dialog(message: &SipMessage) -> bool {
    match &message.start_line {
        StartLine::Request(request_line) => {
            matches!(request_line.method.as_str(), "BYE" | "CANCEL")
        }
        StartLine::Response(status_line) => {
            // A final failure to an INVITE ends a session that never started.
            // A 2xx to an INVITE does not — that is where the dialog begins.
            if status_line.status_code >= 300 {
                return true;
            }
            // The response to a BYE or CANCEL is the last message of the
            // dialog, and it has to count.
            //
            // Releasing on the BYE alone is not enough, and the way it fails is
            // quiet: the BYE frees the session, its 200 arrives, finds nothing
            // remembered, re-derives a decision that still matches — the To
            // header carries the target either way — and puts it straight back.
            // Nothing after that ever removes it, so a node leaked one entry
            // for every call it completed.
            let cseq_method = message
                .headers
                .get("CSeq")
                .and_then(|cseq| cseq.split_whitespace().nth(1));
            matches!(cseq_method, Some("BYE") | Some("CANCEL"))
        }
    }
}

/// Whether this message is an ACK request.
///
/// The point in a dialog where offer/answer is complete and the media session
/// is established on both legs (RFC 3261 §13.2.2.4), which is what an X3
/// attachment needs to be true.
pub(super) fn is_ack(message: &SipMessage, method: &str) -> bool {
    matches!(message.start_line, StartLine::Request(_)) && method == "ACK"
}
