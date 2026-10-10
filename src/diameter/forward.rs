//! Relay primitives for the Diameter server path.
//!
//! Pure functions over the lossless [`DiameterMsg`] tree: Route-Record append
//! and loop detection (RFC 6733 §6.1.9 / §6.3), Origin identity rewrite for
//! topology hiding, and answer construction with the E-bit where RFC 6733
//! puts it.
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
pub fn prepare_forward(msg: &mut DiameterMsg, local_identity: &str) -> Result<(), ForwardError> {
    if has_route_record(msg, local_identity) {
        return Err(ForwardError::LoopDetected);
    }
    append_route_record(msg, local_identity);
    Ok(())
}

/// Which grammar an answer is written in, which is what the E bit tells the
/// peer (RFC 6733 section 3: "If set, the message contains a protocol error,
/// and the message will not conform to the CCF described for this command").
#[derive(Clone, Copy)]
enum Grammar {
    /// The answer of the command, as a handler composes it. Protocol errors
    /// "MUST only be used in answer messages whose 'E' bit is set" (section
    /// 7.1.3), and the permanent failures "SHOULD be used in answer messages
    /// whose 'E' bit is not set" (section 7.1.5).
    Command,
    /// The `answer-message` of section 7.2, which siphon sends when it has to
    /// answer without a handler's answer to send. Section 7.1.5: "In error
    /// conditions where it is not possible or efficient to compose
    /// application-specific answer grammar, answer messages with the 'E' bit
    /// set and which comply to the grammar described in Section 7.2 MAY also
    /// be used for permanent errors."
    AnswerMessage,
}

impl Grammar {
    fn sets_error_bit(self, result_code: u32) -> bool {
        match self {
            Grammar::Command => (3000..4000).contains(&result_code),
            Grammar::AnswerMessage => {
                (3000..4000).contains(&result_code) || (5000..6000).contains(&result_code)
            }
        }
    }
}

fn answer_in(
    grammar: Grammar,
    request: &DiameterMsg,
    origin_host: &str,
    origin_realm: &str,
    result_code: u32,
    error_message: Option<&str>,
) -> DiameterMsg {
    let mut flags = request.flags & FLAG_PROXIABLE; // preserve P, drop R
    if grammar.sets_error_bit(result_code) {
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
        // Without the M bit, which RFC 6733 section 4.5 forbids on this AVP.
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

/// Build the answer of the command for `request`, carrying `result_code` and
/// our identity, for a handler to fill in. The R-bit is cleared; the P-bit
/// mirrors the request; the E-bit is set for a protocol error (3xxx) only.
/// Session-Id, hop-by-hop, and end-to-end are echoed from the request (RFC
/// 6733 §6.2 / §8.8).
pub fn build_answer(
    request: &DiameterMsg,
    origin_host: &str,
    origin_realm: &str,
    result_code: u32,
    error_message: Option<&str>,
) -> DiameterMsg {
    answer_in(
        Grammar::Command,
        request,
        origin_host,
        origin_realm,
        result_code,
        error_message,
    )
}

/// Build the generic error answer siphon sends when it answers in a
/// handler's place: nothing served the request, the handler failed, the
/// request did not parse, or relaying it failed. The E-bit is set for a
/// protocol error (3xxx) and for a permanent failure (5xxx).
pub fn build_error_answer(
    request: &DiameterMsg,
    origin_host: &str,
    origin_realm: &str,
    result_code: u32,
    error_message: &str,
) -> DiameterMsg {
    answer_in(
        Grammar::AnswerMessage,
        request,
        origin_host,
        origin_realm,
        result_code,
        Some(error_message),
    )
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
        rewrite_origin(&mut msg, "diam.example.org", "diam-realm.org");
        assert_eq!(msg.find_all(avp::ORIGIN_HOST, 0).count(), 1);
        assert_eq!(
            msg.get_str(avp::ORIGIN_HOST).as_deref(),
            Some("diam.example.org")
        );
        assert_eq!(
            msg.get_str(avp::ORIGIN_REALM).as_deref(),
            Some("diam-realm.org")
        );
    }

    #[test]
    fn error_answer_sets_e_bit_for_3xxx() {
        let request = sample_request();
        let answer = build_answer(
            &request,
            "diam.example.org",
            "diam-realm.org",
            dictionary::DIAMETER_LOOP_DETECTED,
            Some("loop detected"),
        );
        assert!(!answer.is_request(), "answer must clear the R-bit");
        assert!(answer.is_proxiable(), "P-bit mirrors the request");
        assert!(answer.is_error(), "3005 must set the E-bit");
        assert_eq!(answer.command_code, request.command_code);
        assert_eq!(answer.application_id, request.application_id);
        assert_eq!(answer.hop_by_hop, request.hop_by_hop);
        assert_eq!(answer.end_to_end, request.end_to_end);
        assert_eq!(
            answer.get_str(avp::SESSION_ID).as_deref(),
            Some("client;1;1")
        );
        assert_eq!(
            answer.find(avp::RESULT_CODE, 0).and_then(|a| a.as_u32()),
            Some(dictionary::DIAMETER_LOOP_DETECTED)
        );
        assert_eq!(
            answer.get_str(avp::ORIGIN_HOST).as_deref(),
            Some("diam.example.org")
        );
        assert_eq!(
            answer.get_str(avp::ERROR_MESSAGE).as_deref(),
            Some("loop detected")
        );
    }

    #[test]
    fn success_answer_clears_e_bit() {
        let request = sample_request();
        let answer = build_answer(
            &request,
            "diam.example.org",
            "diam-realm.org",
            dictionary::DIAMETER_SUCCESS,
            None,
        );
        assert!(!answer.is_error(), "2001 must not set the E-bit");
        assert!(answer.find(avp::ERROR_MESSAGE, 0).is_none());
    }

    /// An answer in the grammar of the command carries the E bit only for a
    /// protocol error (RFC 6733 section 7.1.3). Section 7.1.5 on the
    /// permanent failures: "these errors SHOULD be used in answer messages
    /// whose 'E' bit is not set".
    #[test]
    fn an_application_answer_sets_the_e_bit_for_protocol_errors_only() {
        let request = sample_request();
        for (result_code, error) in [
            (1001, false),
            (2001, false),
            (3002, true),
            (3999, true),
            (4002, false),
            (5001, false),
            (dictionary::DIAMETER_UNABLE_TO_COMPLY, false),
            (dictionary::DIAMETER_INVALID_AVP_LENGTH, false),
        ] {
            let answer = build_answer(&request, "h", "r", result_code, None);
            assert_eq!(answer.is_error(), error, "{result_code}");
        }
    }

    /// The generic `answer-message` of section 7.2, which siphon sends when
    /// it cannot compose the answer of the command, may also report a
    /// permanent failure (section 7.1.5).
    #[test]
    fn a_generic_error_answer_sets_the_e_bit_for_permanent_failures_too() {
        let request = sample_request();
        for (result_code, error) in [
            (3002, true),
            (dictionary::DIAMETER_UNABLE_TO_COMPLY, true),
            (dictionary::DIAMETER_INVALID_AVP_LENGTH, true),
        ] {
            let answer = build_error_answer(&request, "h", "r", result_code, "why");
            assert_eq!(answer.is_error(), error, "{result_code}");
            assert_eq!(answer.get_str(avp::ERROR_MESSAGE).as_deref(), Some("why"));
        }
    }

    /// RFC 6733 section 4.5: Error-Message MUST NOT carry the M bit.
    #[test]
    fn error_message_carries_no_m_bit() {
        let request = sample_request();
        for answer in [
            build_answer(&request, "h", "r", 3005, Some("loop detected")),
            build_error_answer(&request, "h", "r", 5012, "loop detected"),
        ] {
            let error_message = answer.find(avp::ERROR_MESSAGE, 0).unwrap();
            assert_eq!(error_message.flags, 0);
            // Code 281, no flag, length 8 + 13 = 21 (0x15), three of padding.
            let mut expected = vec![0x00, 0x00, 0x01, 0x19, 0x00, 0x00, 0x00, 0x15];
            expected.extend_from_slice(b"loop detected");
            expected.extend_from_slice(&[0, 0, 0]);
            let wire = answer.to_wire();
            assert!(wire
                .windows(expected.len())
                .any(|window| window == expected));
        }
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
            "diam-realm.org",
            dictionary::DIAMETER_UNABLE_TO_DELIVER,
            None,
        );
        let wire = answer.to_wire();
        let reparsed = DiameterMsg::from_wire(&wire).unwrap();
        assert_eq!(reparsed, answer);
    }

    /// Emit three answers as hex for
    /// [`scripts/validate_diameter_answer_flags.sh`] to feed to tshark: a
    /// handler's refusal with a permanent failure, a handler's protocol
    /// error, and the generic error siphon sends for a handler that raised.
    #[test]
    fn emit_answers_for_external_dissection() {
        let Ok(path) = std::env::var("SIPHON_DIAMETER_ANSWER_FLAGS_HEX_OUT") else {
            // Nothing to do in an ordinary test run.
            return;
        };
        let mut request = sample_request();
        // A Cx Registration-Termination-Request.
        request.command_code = dictionary::CMD_REGISTRATION_TERMINATION;
        let host = "scscf.ims.mnc001.mcc001.3gppnetwork.org";
        let realm = "ims.mnc001.mcc001.3gppnetwork.org";
        let answers = [
            build_answer(
                &request,
                host,
                realm,
                dictionary::DIAMETER_UNABLE_TO_COMPLY,
                None,
            ),
            build_answer(
                &request,
                host,
                realm,
                dictionary::DIAMETER_UNABLE_TO_DELIVER,
                Some("no route"),
            ),
            build_error_answer(
                &request,
                host,
                realm,
                dictionary::DIAMETER_UNABLE_TO_COMPLY,
                "on_request handler raised",
            ),
        ];

        // `text2pcap`'s hex-dump form: an offset, then the octets. An offset
        // of zero starts the next packet.
        let mut dump = String::new();
        for answer in answers {
            for (offset, chunk) in answer.to_wire().chunks(16).enumerate() {
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
}
