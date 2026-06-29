//! Relay primitives for the Diameter server path.
//!
//! Pure functions over the lossless [`DiameterMsg`] tree: Route-Record append
//! and loop detection (RFC 6733 §6.1.9 / §6.3), Origin identity rewrite for
//! topology hiding, and protocol-error answer construction with the E-bit.
//!
//! The async relay driver that actually ships a request to a backend peer and
//! awaits the answer is wired in the dispatch layer (Phase 5); these are the
//! message-shaping building blocks it composes.

use crate::diameter::codec::{Avp, DiameterMsg, FLAG_ERROR, FLAG_PROXIABLE};
use crate::diameter::dictionary::avp;

/// Outcome of relaying a request to a backend peer. The dispatch layer maps
/// each variant to the Diameter Result-Code it answers upstream with.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ForwardError {
    /// No backend peer in the pool is connected/`Open`.
    #[error("no reachable backend peer")]
    PeerUnreachable,
    /// The backend accepted the request but did not answer in time.
    #[error("backend did not answer within the timeout")]
    Timeout,
    /// The backend connection dropped while the request was in flight.
    #[error("backend connection closed")]
    PeerClosed,
    /// The Diameter server is shedding load.
    #[error("overloaded")]
    Overload,
    /// Our own identity is already in a Route-Record — relaying would loop.
    #[error("forwarding loop detected")]
    LoopDetected,
}

impl ForwardError {
    /// The Diameter Result-Code to answer upstream with for this failure.
    pub fn result_code(&self) -> u32 {
        use crate::diameter::dictionary;
        match self {
            ForwardError::PeerUnreachable | ForwardError::PeerClosed => {
                dictionary::DIAMETER_UNABLE_TO_DELIVER
            }
            ForwardError::Timeout | ForwardError::Overload => dictionary::DIAMETER_TOO_BUSY,
            ForwardError::LoopDetected => dictionary::DIAMETER_LOOP_DETECTED,
        }
    }
}

/// Whether `identity` already appears in a Route-Record AVP (loop detection,
/// RFC 6733 §6.3).
pub fn has_route_record(msg: &DiameterMsg, identity: &str) -> bool {
    msg.find_all(avp::ROUTE_RECORD, 0)
        .any(|record| record.as_str().as_deref() == Some(identity))
}

/// Append a Route-Record AVP carrying our identity (RFC 6733 §6.1.9), so the
/// next hop can detect a loop through us.
pub fn append_route_record(msg: &mut DiameterMsg, identity: &str) {
    msg.avps.push(Avp::utf8(avp::ROUTE_RECORD, 0, identity));
}

/// Replace Origin-Host / Origin-Realm for topology hiding. Existing instances
/// are removed first.
pub fn rewrite_origin(msg: &mut DiameterMsg, origin_host: &str, origin_realm: &str) {
    msg.remove(avp::ORIGIN_HOST, 0);
    msg.remove(avp::ORIGIN_REALM, 0);
    msg.avps.push(Avp::utf8(avp::ORIGIN_HOST, 0, origin_host));
    msg.avps.push(Avp::utf8(avp::ORIGIN_REALM, 0, origin_realm));
}

/// Prepare an inbound request for forwarding: detect a loop through us, then
/// append our Route-Record. Returns [`ForwardError::LoopDetected`] when our
/// identity is already present.
pub fn prepare_forward(msg: &mut DiameterMsg, dra_identity: &str) -> Result<(), ForwardError> {
    if has_route_record(msg, dra_identity) {
        return Err(ForwardError::LoopDetected);
    }
    append_route_record(msg, dra_identity);
    Ok(())
}

/// Whether a Result-Code carries the protocol E-bit. Protocol errors (3xxx)
/// and permanent failures (5xxx) set it; informational (1xxx), success (2xxx),
/// and transient failures (4xxx) do not — matching freeDiameter's behaviour
/// (RFC 6733 §7.1).
fn result_code_sets_error_bit(result_code: u32) -> bool {
    (3000..4000).contains(&result_code) || (5000..6000).contains(&result_code)
}

/// Build a Diameter answer for `request` carrying `result_code` and our
/// identity. The R-bit is cleared; the P-bit mirrors the request; the E-bit is
/// set for protocol/permanent errors. Session-Id, hop-by-hop, and end-to-end
/// are echoed from the request (RFC 6733 §6.2 / §8.8).
pub fn build_answer(
    request: &DiameterMsg,
    origin_host: &str,
    origin_realm: &str,
    result_code: u32,
    error_message: Option<&str>,
) -> DiameterMsg {
    let mut flags = request.flags & FLAG_PROXIABLE; // preserve P, drop R
    if result_code_sets_error_bit(result_code) {
        flags |= FLAG_ERROR;
    }

    let mut avps = Vec::new();
    if let Some(session_id) = request.find(avp::SESSION_ID, 0) {
        avps.push(session_id.clone());
    }
    avps.push(Avp::u32(avp::RESULT_CODE, 0, result_code));
    avps.push(Avp::utf8(avp::ORIGIN_HOST, 0, origin_host));
    avps.push(Avp::utf8(avp::ORIGIN_REALM, 0, origin_realm));
    if let Some(message) = error_message {
        avps.push(Avp::utf8(avp::ERROR_MESSAGE, 0, message));
    }

    DiameterMsg {
        flags,
        command_code: request.command_code,
        application_id: request.application_id,
        hop_by_hop: request.hop_by_hop,
        end_to_end: request.end_to_end,
        avps,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diameter::codec::FLAG_REQUEST;
    use crate::diameter::dictionary;

    fn sample_request() -> DiameterMsg {
        DiameterMsg {
            flags: FLAG_REQUEST | FLAG_PROXIABLE,
            command_code: 257,
            application_id: dictionary::CX_APP_ID,
            hop_by_hop: 0xAAAA,
            end_to_end: 0xBBBB,
            avps: vec![
                Avp::utf8(avp::SESSION_ID, 0, "client;1;1"),
                Avp::utf8(avp::ORIGIN_HOST, 0, "mme.example.org"),
                Avp::utf8(avp::ORIGIN_REALM, 0, "example.org"),
            ],
        }
    }

    #[test]
    fn route_record_append_and_detect() {
        let mut msg = sample_request();
        assert!(!has_route_record(&msg, "diam.example.org"));
        append_route_record(&mut msg, "diam.example.org");
        assert!(has_route_record(&msg, "diam.example.org"));
        // Appended at the tail.
        let last = msg.avps.last().unwrap();
        assert_eq!(last.code, avp::ROUTE_RECORD);
        assert_eq!(last.as_str().as_deref(), Some("diam.example.org"));
    }

    #[test]
    fn prepare_forward_appends_then_detects_loop() {
        let mut msg = sample_request();
        // First pass: clean, appends our record.
        assert_eq!(prepare_forward(&mut msg, "diam.example.org"), Ok(()));
        assert_eq!(msg.find_all(avp::ROUTE_RECORD, 0).count(), 1);
        // Second pass through the same Diameter server: loop.
        assert_eq!(
            prepare_forward(&mut msg, "diam.example.org"),
            Err(ForwardError::LoopDetected)
        );
        // No duplicate Route-Record was added on the loop path.
        assert_eq!(msg.find_all(avp::ROUTE_RECORD, 0).count(), 1);
    }

    #[test]
    fn append_preserves_all_other_avps() {
        let mut msg = sample_request();
        let before = msg.avps.len();
        append_route_record(&mut msg, "diam.example.org");
        assert_eq!(msg.avps.len(), before + 1);
        // Every original AVP is still present and unchanged.
        for code in [avp::SESSION_ID, avp::ORIGIN_HOST, avp::ORIGIN_REALM] {
            assert!(msg.find(code, 0).is_some());
        }
    }

    #[test]
    fn rewrite_origin_replaces_in_place() {
        let mut msg = sample_request();
        rewrite_origin(&mut msg, "diam.example.org", "dra-realm.org");
        assert_eq!(msg.find_all(avp::ORIGIN_HOST, 0).count(), 1);
        assert_eq!(
            msg.get_str(avp::ORIGIN_HOST).as_deref(),
            Some("diam.example.org")
        );
        assert_eq!(
            msg.get_str(avp::ORIGIN_REALM).as_deref(),
            Some("dra-realm.org")
        );
    }

    #[test]
    fn error_answer_sets_e_bit_for_3xxx() {
        let request = sample_request();
        let answer = build_answer(
            &request,
            "diam.example.org",
            "dra-realm.org",
            dictionary::DIAMETER_LOOP_DETECTED,
            Some("loop via dra"),
        );
        assert!(!answer.is_request(), "answer must clear the R-bit");
        assert!(answer.is_proxiable(), "P-bit mirrors the request");
        assert!(answer.is_error(), "3005 must set the E-bit");
        assert_eq!(answer.command_code, request.command_code);
        assert_eq!(answer.application_id, request.application_id);
        assert_eq!(answer.hop_by_hop, request.hop_by_hop);
        assert_eq!(answer.end_to_end, request.end_to_end);
        assert_eq!(answer.get_str(avp::SESSION_ID).as_deref(), Some("client;1;1"));
        assert_eq!(
            answer.find(avp::RESULT_CODE, 0).and_then(|a| a.as_u32()),
            Some(dictionary::DIAMETER_LOOP_DETECTED)
        );
        assert_eq!(
            answer.get_str(avp::ORIGIN_HOST).as_deref(),
            Some("diam.example.org")
        );
        assert_eq!(answer.get_str(avp::ERROR_MESSAGE).as_deref(), Some("loop via dra"));
    }

    #[test]
    fn success_answer_clears_e_bit() {
        let request = sample_request();
        let answer = build_answer(
            &request,
            "diam.example.org",
            "dra-realm.org",
            dictionary::DIAMETER_SUCCESS,
            None,
        );
        assert!(!answer.is_error(), "2001 must not set the E-bit");
        assert!(answer.find(avp::ERROR_MESSAGE, 0).is_none());
    }

    #[test]
    fn transient_failure_clears_e_bit_permanent_sets_it() {
        let request = sample_request();
        // 4xxx transient → no E-bit.
        let transient = build_answer(&request, "h", "r", 4002, None);
        assert!(!transient.is_error());
        // 5xxx permanent → E-bit.
        let permanent = build_answer(
            &request,
            "h",
            "r",
            dictionary::DIAMETER_INVALID_AVP_LENGTH,
            None,
        );
        assert!(permanent.is_error());
    }

    #[test]
    fn forward_error_result_codes() {
        assert_eq!(
            ForwardError::PeerUnreachable.result_code(),
            dictionary::DIAMETER_UNABLE_TO_DELIVER
        );
        assert_eq!(
            ForwardError::Timeout.result_code(),
            dictionary::DIAMETER_TOO_BUSY
        );
        assert_eq!(
            ForwardError::LoopDetected.result_code(),
            dictionary::DIAMETER_LOOP_DETECTED
        );
    }

    #[test]
    fn answer_roundtrips_through_wire() {
        let request = sample_request();
        let answer = build_answer(
            &request,
            "diam.example.org",
            "dra-realm.org",
            dictionary::DIAMETER_UNABLE_TO_DELIVER,
            None,
        );
        let wire = answer.to_wire();
        let reparsed = DiameterMsg::from_wire(&wire).unwrap();
        assert_eq!(reparsed, answer);
    }
}
