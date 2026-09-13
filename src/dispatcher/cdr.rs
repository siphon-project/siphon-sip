//! Call Detail Records: opening, stamping and finalising a record.
//!
//! The record is opened before the script handler runs, so a handler calling
//! `cdr.write(request, extra=…)` has something to attach to.

use super::*;

// ---------------------------------------------------------------------------
// Automatic CDR generation (cdr.auto_emit) — INVITE → answer → BYE.
//
// These mirror the Rf auto-emit hooks and fire from the same lifecycle points,
// but track only the fields a CDR needs (parties, timing, disconnect side) in
// `state.cdr_sessions`. Proxy calls key by the SIP dialog `<Call-ID>\0<tag>`;
// B2BUA calls key by the internal call UUID. All entry points no-op cheaply
// when `cdr.auto_emit` is off (the map stays empty).
// ---------------------------------------------------------------------------

/// Dialog CDR key for a proxy call: `<Call-ID>\0<tag>`.
pub(super) fn cdr_dialog_key(call_id: &str, tag: &str) -> String {
    format!("{call_id}\0{tag}")
}

/// Raw RFC 3326 `Reason:` header value, if present — carried into the CDR's
/// `sip_reason` field.
pub(super) fn cdr_extract_reason(message: &SipMessage) -> Option<String> {
    message.headers.get("Reason").map(|r| r.to_string())
}

/// disconnect_initiator for an unanswered/failed call, from the final code.
/// 408 → timeout, 487 (CANCEL) → caller, everything else → callee (the far
/// end returned the error).
pub(super) fn cdr_disconnect_for_failure(code: u16) -> &'static str {
    match code {
        408 => "timeout",
        487 => "caller",
        _ => "callee",
    }
}

/// Build a `CdrSession` from an INVITE. Returns `None` if the INVITE lacks the
/// Call-ID / From-tag needed to key it.
pub(super) fn cdr_session_from_invite(
    invite: &SipMessage,
    source_ip: &str,
    transport: &str,
    auth_user: Option<String>,
) -> Option<(String, crate::cdr::CdrSession)> {
    let call_id = invite.headers.get("Call-ID")?.to_string();
    let from_na = invite.typed_from().ok().flatten();
    let from_tag = from_na.as_ref().and_then(|na| na.tag.clone())?;
    let from_uri = from_na.map(|na| na.uri.to_string()).unwrap_or_default();
    let to_uri = invite
        .typed_to()
        .ok()
        .flatten()
        .map(|na| na.uri.to_string())
        .unwrap_or_default();
    let ruri = match &invite.start_line {
        StartLine::Request(request_line) => request_line.request_uri.to_string(),
        _ => String::new(),
    };
    let user_agent = invite.headers.get("User-Agent").map(|s| s.to_string());
    let mut session = crate::cdr::CdrSession::new(
        call_id.clone(),
        from_uri,
        to_uri,
        ruri,
        source_ip.to_string(),
        transport.to_string(),
        user_agent,
        auth_user,
    );
    // Rf correlation: remember where this dialog's accounting record can be
    // found so the finalized CDR can name it (TS 32.299). Resolved at teardown
    // rather than now — ACR-START is spawned, so the session usually does not
    // exist yet at INVITE time. Skipped entirely on a deployment with no Rf
    // configured, where the keys would be eight allocations per call to look
    // up a map that will never exist.
    if crate::diameter::rf_service::rf_lookup_installed() {
        session.set_rf_keys(crate::diameter::rf_service::rf_lookup_candidates(
            rf_extract_icid(invite).as_deref(),
            Some(call_id.as_str()),
            Some(from_tag.as_str()),
            None,
        ));
    }
    Some((cdr_dialog_key(&call_id, &from_tag), session))
}

/// Stamp the answer time on a tracked CDR session. No-op if untracked.
pub(super) fn cdr_mark_answer(state: &DispatcherState, key: &str, response_code: u16) {
    if let Some(mut session) = state.cdr_sessions.get_mut(key) {
        session.mark_answered(response_code);
    }
}

/// Finalize a tracked CDR session (write the record + drop it). No-op if the
/// call was never tracked (auto-emit off, or not an INVITE dialog).
///
/// Takes the session map rather than the whole dispatcher state so the BYE
/// drop guard — which outlives the borrow of the message it was built from —
/// can hold just the map.
pub(super) fn cdr_finalize(
    sessions: &DashMap<String, crate::cdr::CdrSession>,
    key: &str,
    disconnect_initiator: &str,
    response_code: Option<u16>,
    sip_reason: Option<String>,
) {
    if let Some((_, session)) = sessions.remove(key) {
        let cdr = session.finalize(disconnect_initiator, response_code, sip_reason);
        crate::cdr::write(cdr);
    }
}

/// Emit a REGISTER CDR for a registrar state change (`cdr.auto_emit` +
/// `cdr.include_register`). A point event — no lifecycle tracking. The registrar
/// event stream carries only the AoR and the change type, so the record keys on
/// those, with the change in the `reg_event` extra field.
pub(super) fn cdr_emit_register(aor: &str, event_type: &str) {
    let cdr = crate::cdr::Cdr::new(
        String::new(), // no Call-ID in the registrar event stream
        aor.to_string(),
        aor.to_string(),
        aor.to_string(),
        "REGISTER".to_string(),
        String::new(), // source IP not carried by the event
        String::new(), // transport not carried by the event
    )
    .with_response_code(200)
    .with_extra("reg_event".to_string(), event_type.to_string());
    crate::cdr::write(cdr);
}

/// Build a media CDR from a media-engine end-of-call summary.
///
/// A `method="MEDIA"` record keyed on the SIP Call-ID so a collector joins it to
/// the SIP-side CDR (which carries the URIs and disconnect side). The SIP URI /
/// source / transport fields are empty — the media summary carries none; the
/// join key is the Call-ID. `duration_secs` is the media call lifetime, with the
/// exact value also in `media_duration_ms`, and `media_reason` records why the
/// call ended (`"delete"` / `"media_timeout"`).
///
/// Each leg's figures are flattened into `extra`: index 0 → `near_`, index 1 →
/// `far_`, any further leg → `leg{n}_`. Unmeasured optional fields (a plain
/// in-kernel relay leg has no MOS/loss/jitter) are omitted, not emitted empty.
pub(super) fn media_summary_to_cdr(
    summary: &crate::rtpengine::events::CallSummary,
) -> crate::cdr::Cdr {
    let mut cdr = crate::cdr::Cdr::new(
        summary.call_id.clone(),
        String::new(), // from_uri — not carried by the media summary
        String::new(), // to_uri
        String::new(), // ruri
        "MEDIA".to_string(),
        String::new(), // source_ip
        String::new(), // transport
    )
    .with_duration(summary.duration_ms as f64 / 1000.0)
    .with_extra("media_reason".to_string(), summary.reason.clone())
    .with_extra(
        "media_duration_ms".to_string(),
        summary.duration_ms.to_string(),
    );

    for (index, leg) in summary.legs.iter().enumerate() {
        let prefix = match index {
            0 => "near".to_string(),
            1 => "far".to_string(),
            n => format!("leg{n}"),
        };
        let extra = &mut cdr.extra;
        let mut put = |suffix: &str, value: String| {
            extra.insert(format!("{prefix}_{suffix}"), value);
        };
        put("tag", leg.tag.clone());
        if let Some(codec) = &leg.codec {
            put("codec", codec.clone());
        }
        put("packets_in", leg.packets_in.to_string());
        put("bytes_in", leg.bytes_in.to_string());
        put("packets_out", leg.packets_out.to_string());
        put("bytes_out", leg.bytes_out.to_string());
        put("packets_dropped", leg.packets_dropped.to_string());
        if let Some(ssrc) = leg.ssrc {
            put("ssrc", ssrc.to_string());
        }
        if let Some(text) = &leg.text {
            put("text_packets", text.packets.to_string());
            put("text_characters", text.characters.to_string());
            put("text_missing_markers", text.missing_markers.to_string());
            put(
                "text_recovered_from_redundancy",
                text.recovered_from_redundancy.to_string(),
            );
        }
        if let Some(packets_lost) = leg.packets_lost {
            put("packets_lost", packets_lost.to_string());
        }
        if let Some(loss_percent) = leg.loss_percent {
            put("loss_percent", loss_percent.to_string());
        }
        if let Some(jitter_ms) = leg.jitter_ms {
            put("jitter_ms", jitter_ms.to_string());
        }
        if let Some(rtt_ms) = leg.rtt_ms {
            put("rtt_ms", rtt_ms.to_string());
        }
        if let Some(mos_average) = leg.mos_average {
            put("mos_average", mos_average.to_string());
        }
        if let Some(mos_min) = leg.mos_min {
            put("mos_min", mos_min.to_string());
        }
        if let Some(mos_max) = leg.mos_max {
            put("mos_max", mos_max.to_string());
        }
        if let Some(mos_basis) = &leg.mos_basis {
            put("mos_basis", mos_basis.clone());
        }
    }
    cdr
}

/// Proxy CDR START — open the record for an inbound INVITE, *before* the script
/// handler runs, so `cdr.write(request, extra=…)` from that handler has a
/// record to attach its fields to. What the script then decides is settled by
/// [`cdr_settle_proxy_start`]: an INVITE the proxy does not forward has no call
/// to account for and its record is dropped again (or emitted, when the script
/// attached fields to it — it asked for a record for this attempt).
///
/// Returns the key of the record this call opened, or `None` when it opened
/// none: auto-emit off, an INVITE without the Call-ID/From-tag to key on, or a
/// re-INVITE on a dialog that is already tracked — the established call's
/// record must survive whatever the script does with the re-INVITE, so it is
/// neither re-stamped nor settled.
pub(super) fn cdr_track_proxy_start(
    sessions: &DashMap<String, crate::cdr::CdrSession>,
    invite: &SipMessage,
    source_ip: &str,
    transport: &str,
) -> Option<String> {
    if !crate::cdr::auto_emit_enabled() {
        return None;
    }
    let (key, session) = cdr_session_from_invite(invite, source_ip, transport, None)?;
    match sessions.entry(key.clone()) {
        dashmap::mapref::entry::Entry::Occupied(_) => None,
        dashmap::mapref::entry::Entry::Vacant(slot) => {
            slot.insert(session);
            Some(key)
        }
    }
}

/// What the script did with an INVITE whose CDR record was opened by
/// [`cdr_track_proxy_start`].
pub(super) enum ProxyInviteOutcome<'a> {
    /// Relayed or forked — this is a call, keep the record.
    Forwarded {
        // Username the script authenticated the caller as, read after the
        // handler ran. `None` when the call was never challenged.
        auth_user: Option<&'a str>,
    },
    /// Answered locally (a 403, a 407 challenge the UA will retry, …).
    Rejected { code: u16 },
    /// Silently dropped.
    Dropped,
}

/// What happens to the record when the script's decision is in.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum CdrSettle {
    /// This is a call — keep accumulating; the BYE finalizes it.
    Keep,
    /// Not a call, but the script asked for a record of the attempt.
    Emit {
        disconnect: &'static str,
        code: Option<u16>,
    },
    /// Not a call and nothing was attached — the record never existed as far
    /// as the operator is concerned.
    Discard,
}

/// A forwarded INVITE keeps its record. An INVITE the proxy never forwarded is
/// not a call, so its record is discarded — *unless* the script attached fields
/// to it, because `cdr.write(request, extra=…)` on a call the script then
/// rejects is a deliberate ask for a record of that attempt, and it is emitted
/// carrying the code the script answered instead of a bare `0`.
pub(super) fn cdr_settle_decision(
    outcome: &ProxyInviteOutcome<'_>,
    script_attached_fields: bool,
) -> CdrSettle {
    match outcome {
        ProxyInviteOutcome::Forwarded { .. } => CdrSettle::Keep,
        ProxyInviteOutcome::Rejected { code } if script_attached_fields => CdrSettle::Emit {
            disconnect: cdr_disconnect_for_failure(*code),
            code: Some(*code),
        },
        ProxyInviteOutcome::Dropped if script_attached_fields => CdrSettle::Emit {
            disconnect: "error",
            code: None,
        },
        _ => CdrSettle::Discard,
    }
}

/// Keep, emit or discard the record [`cdr_track_proxy_start`] opened.
pub(super) fn cdr_settle_proxy_start(
    sessions: &DashMap<String, crate::cdr::CdrSession>,
    key: &str,
    outcome: ProxyInviteOutcome<'_>,
) {
    let script_attached_fields = sessions
        .get(key)
        .is_some_and(|session| session.has_extra_fields());

    match cdr_settle_decision(&outcome, script_attached_fields) {
        CdrSettle::Keep => {
            if let ProxyInviteOutcome::Forwarded {
                auth_user: Some(auth_user),
            } = outcome
            {
                if let Some(mut session) = sessions.get_mut(key) {
                    session.set_auth_user(auth_user.to_string());
                }
            }
        }
        CdrSettle::Emit { disconnect, code } => {
            cdr_finalize(sessions, key, disconnect, code, None);
        }
        CdrSettle::Discard => {
            sessions.remove(key);
        }
    }
}

/// Proxy CDR ANSWER — a 2xx for the INVITE was forwarded upstream.
pub(super) fn cdr_mark_proxy_answer(
    state: &DispatcherState,
    invite: &SipMessage,
    response_code: u16,
) {
    if !crate::cdr::auto_emit_enabled() {
        return;
    }
    let (Some(call_id), Some(from_tag)) = (
        invite.headers.get("Call-ID").map(|s| s.to_string()),
        invite.typed_from().ok().flatten().and_then(|na| na.tag),
    ) else {
        return;
    };
    cdr_mark_answer(state, &cdr_dialog_key(&call_id, &from_tag), response_code);
}

/// Proxy CDR STOP — an in-dialog BYE ended the call. Resolves the disconnecting
/// side by which tag the BYE arrived under: the BYE's From-tag matches the
/// INVITE's From-tag when the caller hangs up, else the callee did.
///
/// Owned rather than borrowed from the BYE because the record is finalized
/// after the script handler has run, by which point the relay path has taken
/// the message.
pub(super) struct CdrProxyStop {
    pub(super) call_id: String,
    pub(super) from_tag: Option<String>,
    pub(super) to_tag: Option<String>,
    pub(super) sip_reason: Option<String>,
}

impl CdrProxyStop {
    pub(super) fn from_bye(bye: &SipMessage) -> Option<Self> {
        Some(Self {
            call_id: bye.headers.get("Call-ID").map(|s| s.to_string())?,
            from_tag: bye.typed_from().ok().flatten().and_then(|na| na.tag),
            to_tag: bye.typed_to().ok().flatten().and_then(|na| na.tag),
            sip_reason: cdr_extract_reason(bye),
        })
    }

    pub(super) fn finalize(self, sessions: &DashMap<String, crate::cdr::CdrSession>) {
        // Caller hung up: BYE From-tag == INVITE From-tag (the stored key).
        if let Some(from_tag) = &self.from_tag {
            let key = cdr_dialog_key(&self.call_id, from_tag);
            if sessions.contains_key(&key) {
                cdr_finalize(sessions, &key, "caller", None, self.sip_reason);
                return;
            }
        }
        // Callee hung up: BYE To-tag == INVITE From-tag.
        if let Some(to_tag) = &self.to_tag {
            let key = cdr_dialog_key(&self.call_id, to_tag);
            if sessions.contains_key(&key) {
                cdr_finalize(sessions, &key, "callee", None, self.sip_reason);
            }
        }
    }
}

/// Finalizes the proxy CDR when the BYE's request handling ends, whichever way
/// it ends.
///
/// The record is written *after* the script's `@proxy.on_request("BYE")`
/// handler has run, so a `cdr.write(request, extra=…)` in that handler still
/// merges into it — attaching to the auto-emitted record is the whole contract
/// of `cdr.write` under `auto_emit`, and a record finalized before the handler
/// would leave that call with nothing to attach to. It is a drop guard rather
/// than a call at the end of the function because the record must be written
/// even when the script drops or rejects the BYE, or the handler panics — the
/// same "accounting closes regardless of what the script decides" rule the Rf
/// ACR-STOP above follows.
pub(super) struct CdrProxyStopGuard {
    pub(super) sessions: Arc<DashMap<String, crate::cdr::CdrSession>>,
    pub(super) parts: Option<CdrProxyStop>,
}

impl Drop for CdrProxyStopGuard {
    fn drop(&mut self) {
        if let Some(parts) = self.parts.take() {
            parts.finalize(&self.sessions);
        }
    }
}

/// Proxy CDR FAIL — a single-relay INVITE got a final non-2xx (the call
/// failed). Forked failures are finalized at `ForkAction::ForwardBestError`;
/// auth challenges (401/407) are excluded by the caller since the UA re-sends.
pub(super) fn cdr_finalize_proxy_fail(
    state: &DispatcherState,
    invite: &SipMessage,
    response_code: u16,
) {
    if !crate::cdr::auto_emit_enabled() {
        return;
    }
    let (Some(call_id), Some(from_tag)) = (
        invite.headers.get("Call-ID").map(|s| s.to_string()),
        invite.typed_from().ok().flatten().and_then(|na| na.tag),
    ) else {
        return;
    };
    cdr_finalize(
        &state.cdr_sessions,
        &cdr_dialog_key(&call_id, &from_tag),
        cdr_disconnect_for_failure(response_code),
        Some(response_code),
        None,
    );
}

/// B2BUA CDR START — a new call actor was created for an INVITE.
pub(super) fn cdr_track_b2bua_start(
    state: &DispatcherState,
    internal_call_id: &str,
    invite: &SipMessage,
    source_ip: &str,
    transport: &str,
) {
    if !crate::cdr::auto_emit_enabled() {
        return;
    }
    // Reuse the INVITE field extraction, but key by the internal call UUID so
    // both legs (A/B, different Call-IDs) resolve to one CDR.
    if let Some((_, mut session)) = cdr_session_from_invite(invite, source_ip, transport, None) {
        // A B2BUA Rf record is keyed on the internal call UUID, not on either
        // leg's dialog, so that candidate goes first; the dialog-derived ones
        // set above stay as the fallback for a record opened on the proxy path.
        if crate::diameter::rf_service::rf_lookup_installed() {
            let mut rf_keys = vec![crate::diameter::rf_service::rf_b2bua_key(internal_call_id)];
            rf_keys.extend(session.rf_keys().iter().cloned());
            session.set_rf_keys(rf_keys);
        }
        state
            .cdr_sessions
            .entry(internal_call_id.to_string())
            .or_insert(session);
    }
}

/// B2BUA CDR ANSWER — the call transitioned to Answered (2xx to the INVITE).
pub(super) fn cdr_mark_b2bua_answer(
    state: &DispatcherState,
    internal_call_id: &str,
    response_code: u16,
) {
    if !crate::cdr::auto_emit_enabled() {
        return;
    }
    cdr_mark_answer(state, internal_call_id, response_code);
}

/// Auto-stamp a winning LCR carrier's `cdr_fields` onto the call's CDR session,
/// so the external API can push billing/routing metadata straight into the
/// record without the script naming each field. No-op when CDR auto-emit is off.
pub(super) fn cdr_stamp_route_fields(
    state: &DispatcherState,
    internal_call_id: &str,
    fields: &std::collections::HashMap<String, String>,
) {
    if fields.is_empty() || !crate::cdr::auto_emit_enabled() {
        return;
    }
    if let Some(mut session) = state.cdr_sessions.get_mut(internal_call_id) {
        session.merge_extra(fields);
    }
}

/// Stamp the carriers a sequential-failover call BURNED onto its CDR, as
/// `lcr_attempts`.
///
/// The winner already reaches the record through `cdr_stamp_route_fields`; this
/// is the other half, and the half that was missing — a completed call that
/// burned a carrier on the way recorded that nowhere, so a failing carrier could
/// not be trended or taken to the carrier. Serialised as a compact JSON array
/// because `Cdr.extra` is a flat string map.
pub(super) fn cdr_stamp_route_attempts(state: &DispatcherState, internal_call_id: &str) {
    if !crate::cdr::auto_emit_enabled() {
        return;
    }
    let attempts = state.call_actors.route_attempts(internal_call_id);
    if attempts.is_empty() {
        return;
    }
    let rendered = attempts
        .iter()
        .map(|attempt| {
            format!(
                r#"{{"carrier_id":{},"status":{},"elapsed_ms":{},"dialed":{}}}"#,
                serde_json::Value::String(attempt.carrier_id.clone()),
                attempt.status,
                attempt.elapsed_ms,
                attempt.dialed
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    if let Some(mut session) = state.cdr_sessions.get_mut(internal_call_id) {
        session.merge_extra(&std::collections::HashMap::from([(
            "lcr_attempts".to_string(),
            format!("[{rendered}]"),
        )]));
    }
}

/// B2BUA CDR STOP — a BYE tore the call down. `from_a_leg` gives the side.
pub(super) fn cdr_finalize_b2bua_stop(
    state: &DispatcherState,
    internal_call_id: &str,
    from_a_leg: bool,
    bye: &SipMessage,
) {
    if !crate::cdr::auto_emit_enabled() {
        return;
    }
    let disconnect = if from_a_leg { "caller" } else { "callee" };
    cdr_finalize(
        &state.cdr_sessions,
        internal_call_id,
        disconnect,
        None,
        cdr_extract_reason(bye),
    );
}

/// B2BUA CDR FAIL — the call ended before/without a BYE (B-leg failure,
/// answer-timeout, or caller CANCEL). `response_code` is the final code and
/// selects the disconnect side (see [`cdr_disconnect_for_failure`]).
pub(super) fn cdr_finalize_b2bua_fail(
    state: &DispatcherState,
    internal_call_id: &str,
    response_code: u16,
) {
    if !crate::cdr::auto_emit_enabled() {
        return;
    }
    cdr_finalize(
        &state.cdr_sessions,
        internal_call_id,
        cdr_disconnect_for_failure(response_code),
        Some(response_code),
        None,
    );
}

#[cfg(test)]
mod cdr_proxy_tests {
    use super::*;
    use crate::sip::builder::SipMessageBuilder;
    use crate::sip::uri::SipUri;

    const CALL_ID: &str = "call-cdr-stop-1";
    const CALLER_TAG: &str = "tag-caller";
    const CALLEE_TAG: &str = "tag-callee";

    /// A BYE on the established dialog. `from_caller` picks the direction: the
    /// hanging-up side is always the one in the From header (RFC 3261 §15.1).
    fn bye(from_caller: bool) -> SipMessage {
        let (from_tag, to_tag) = if from_caller {
            (CALLER_TAG, CALLEE_TAG)
        } else {
            (CALLEE_TAG, CALLER_TAG)
        };
        SipMessageBuilder::new()
            .request(
                Method::Bye,
                SipUri::new("example.com".to_string()).with_user("bob".to_string()),
            )
            .via("SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-bye".to_string())
            .from(format!("<sip:alice@example.com>;tag={from_tag}"))
            .to(format!("<sip:bob@example.com>;tag={to_tag}"))
            .call_id(CALL_ID.to_string())
            .cseq("2 BYE".to_string())
            .content_length(0)
            .build()
            .expect("BYE builds")
    }

    /// The dispatcher keys a proxy call on the INVITE's From-tag, i.e. the
    /// caller's.
    fn tracked() -> DashMap<String, crate::cdr::CdrSession> {
        let sessions = DashMap::new();
        sessions.insert(
            cdr_dialog_key(CALL_ID, CALLER_TAG),
            crate::cdr::CdrSession::new(
                CALL_ID.to_string(),
                "sip:alice@example.com".to_string(),
                "sip:bob@example.com".to_string(),
                "sip:bob@192.0.2.1:5060".to_string(),
                "192.0.2.100".to_string(),
                "udp".to_string(),
                None,
                None,
            ),
        );
        sessions
    }

    #[test]
    fn a_bye_from_the_caller_finalizes_the_session() {
        let sessions = tracked();
        CdrProxyStop::from_bye(&bye(true))
            .expect("BYE carries a Call-ID")
            .finalize(&sessions);
        assert!(sessions.is_empty(), "the record should have been written");
    }

    /// The callee's BYE carries the INVITE's From-tag as its *To*-tag, so the
    /// session has to be resolved through the second candidate.
    #[test]
    fn a_bye_from_the_callee_resolves_through_the_to_tag() {
        let sessions = tracked();
        CdrProxyStop::from_bye(&bye(false))
            .expect("BYE carries a Call-ID")
            .finalize(&sessions);
        assert!(sessions.is_empty(), "the record should have been written");
    }

    /// The record is written when the BYE's handling ends — including when the
    /// script drops the BYE outright, which is the case the guard exists for:
    /// finalizing before the handler would have made the record unreachable to
    /// `cdr.write(request, extra=…)` from `@proxy.on_request("BYE")`, and
    /// finalizing at the end of the happy path only would have lost the record
    /// entirely for a dropped BYE.
    #[test]
    fn the_record_is_written_even_when_the_script_drops_the_bye() {
        let sessions = Arc::new(tracked());
        {
            let _guard = CdrProxyStopGuard {
                sessions: Arc::clone(&sessions),
                parts: CdrProxyStop::from_bye(&bye(true)),
            };
            // The script returned without relay()/reply() — the request path
            // takes an early exit and the guard is all that runs.
            assert_eq!(sessions.len(), 1, "not finalized before the handler ran");
        }
        assert!(sessions.is_empty(), "the record should have been written");
    }

    /// A forwarded INVITE is a call: its record stays open until the BYE, and
    /// takes the identity the script authenticated on the way through.
    #[test]
    fn a_forwarded_invite_keeps_its_record_and_takes_the_authenticated_identity() {
        let sessions = tracked();
        cdr_settle_proxy_start(
            &sessions,
            &cdr_dialog_key(CALL_ID, CALLER_TAG),
            ProxyInviteOutcome::Forwarded {
                auth_user: Some("alice"),
            },
        );
        let session = sessions
            .get(&cdr_dialog_key(CALL_ID, CALLER_TAG))
            .expect("the call's record is still open");
        assert_eq!(
            session.clone().finalize("caller", None, None).auth_user,
            Some("alice".to_string())
        );
    }

    /// An INVITE the proxy never forwarded is not a call, so the record opened
    /// for it before the handler ran is discarded rather than left to the
    /// orphan sweep — a 407 challenge on every REGISTER-less INVITE would
    /// otherwise pile up records for calls that never happened.
    #[test]
    fn a_rejected_invite_discards_its_record() {
        let sessions = tracked();
        cdr_settle_proxy_start(
            &sessions,
            &cdr_dialog_key(CALL_ID, CALLER_TAG),
            ProxyInviteOutcome::Rejected { code: 407 },
        );
        assert!(sessions.is_empty());
    }

    /// …unless the script attached fields to it, which is a deliberate ask for
    /// a record of the attempt. It carries the code the script answered rather
    /// than the bare `0` a script-built record used to have.
    #[test]
    fn a_rejected_invite_the_script_wrote_a_cdr_for_is_emitted() {
        assert_eq!(
            cdr_settle_decision(&ProxyInviteOutcome::Rejected { code: 403 }, true),
            CdrSettle::Emit {
                disconnect: "callee",
                code: Some(403),
            }
        );
        assert_eq!(
            cdr_settle_decision(&ProxyInviteOutcome::Rejected { code: 403 }, false),
            CdrSettle::Discard
        );
        // A silent drop (the rate-limit / scanner pattern) has no code to
        // report, but the script's record is still emitted when it asked.
        assert_eq!(
            cdr_settle_decision(&ProxyInviteOutcome::Dropped, true),
            CdrSettle::Emit {
                disconnect: "error",
                code: None,
            }
        );
        assert_eq!(
            cdr_settle_decision(&ProxyInviteOutcome::Dropped, false),
            CdrSettle::Discard
        );
        // A forwarded call is never emitted early, whatever is attached.
        assert_eq!(
            cdr_settle_decision(&ProxyInviteOutcome::Forwarded { auth_user: None }, true),
            CdrSettle::Keep
        );
    }

    /// A re-INVITE on an established dialog must not re-open (or re-settle)
    /// the record the call already has — the script rejecting a re-INVITE
    /// would otherwise throw away the answered call's CDR.
    #[test]
    fn a_reinvite_on_a_tracked_dialog_opens_no_second_record() {
        let sessions = tracked();
        let invite = SipMessageBuilder::new()
            .request(
                Method::Invite,
                SipUri::new("example.com".to_string()).with_user("bob".to_string()),
            )
            .via("SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-re".to_string())
            .from(format!("<sip:alice@example.com>;tag={CALLER_TAG}"))
            .to(format!("<sip:bob@example.com>;tag={CALLEE_TAG}"))
            .call_id(CALL_ID.to_string())
            .cseq("2 INVITE".to_string())
            .content_length(0)
            .build()
            .expect("re-INVITE builds");

        // Auto-emit is off in the test binary, so this returns None for that
        // reason too — what matters is that the tracked record is untouched.
        assert!(cdr_track_proxy_start(&sessions, &invite, "192.0.2.100", "udp").is_none());
        assert_eq!(sessions.len(), 1);
    }

    /// A BYE for a call this proxy never tracked (auto-emit off, or an INVITE
    /// that predates the process) must not disturb anything.
    #[test]
    fn an_untracked_bye_is_a_no_op() {
        let sessions: DashMap<String, crate::cdr::CdrSession> = DashMap::new();
        CdrProxyStop::from_bye(&bye(true))
            .expect("BYE carries a Call-ID")
            .finalize(&sessions);
        assert!(sessions.is_empty());
    }
}
