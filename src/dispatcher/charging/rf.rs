//! Rf offline charging (TS 32.260 / 32.299): ACR START, INTERIM, STOP, EVENT.
//!
//! Auto-emitted from the call lifecycle rather than from a script, so the
//! reservation guard matters: a START that is spawned but never answered must
//! not leave a session the STOP cannot find.

use crate::dispatcher::*;

// ---------------------------------------------------------------------------
// Rf offline-charging helpers (3GPP TS 32.299) — proxy auto-emit
// ---------------------------------------------------------------------------

/// Extract the IMS-Charging-Identifier from a SIP message's
/// `P-Charging-Vector` header (RFC 7315 §5.6 / TS 32.260 §5.5).
/// Returns `None` when the header is absent or carries no `icid-value`.
pub fn rf_extract_icid(message: &SipMessage) -> Option<String> {
    let header = message.headers.get("P-Charging-Vector")?;
    crate::sip::headers::charging::ChargingVector::parse(header).icid
}

/// Extract `(Call-ID, From-tag)` from a SIP message — the inputs to
/// the dialog-fallback storage key.  Returns `None` when either is
/// missing (an in-dialog request without a From-tag would be malformed).
pub fn rf_extract_dialog_parts(message: &SipMessage) -> Option<(String, String)> {
    let call_id = message.headers.get("Call-ID")?.to_string();
    let from_tag = message.typed_from().ok().flatten().and_then(|na| na.tag)?;
    Some((call_id, from_tag))
}

/// Predicate factory: returns `true` when a SIP URI / name-addr value
/// belongs to one of the locally-served domains.  Used by the
/// `ims_data_from_request` builder to decide ORIGINATING vs
/// TERMINATING role when no `P-Served-User` is present.
pub fn rf_local_uri_predicate(local_domains: &Arc<Vec<String>>) -> impl Fn(&str) -> bool {
    let domains: Vec<String> = local_domains
        .iter()
        .map(|d| d.to_ascii_lowercase())
        .collect();
    move |uri: &str| {
        let lower = uri.to_ascii_lowercase();
        domains.iter().any(|d| lower.contains(d))
    }
}

/// `Time-Stamps` for a record about to be emitted for `session`: the wall-clock
/// instant its INVITE arrived, plus now for the response.
///
/// The proxy session's `created_at` is the INVITE's arrival, so this is the
/// only place the pair can be recovered — by the time the 2xx lands, the
/// request instant is long past and sampling the clock inside the ACR builder
/// would stamp the answer time into `SIP-Request-Timestamp`, leaving the CDF
/// with no way to tell ring time from talk time.
pub fn rf_timestamps_for_session(
    session_arc: &Arc<std::sync::RwLock<crate::proxy::session::ProxySession>>,
) -> crate::diameter::rf_service::SipTimestamps {
    match session_arc.read() {
        Ok(session) => {
            crate::diameter::rf_service::SipTimestamps::from_request_instant(session.created_at)
        }
        // A poisoned lock means some other task panicked mid-call; the record
        // is still worth emitting, just without a trustworthy request instant.
        Err(_) => crate::diameter::rf_service::SipTimestamps::now(),
    }
}

/// Spawn ACR-EVENT for an INVITE that got a final non-2xx (TS 32.260
/// §5.2.2.1 — "unsuccessful session establishment").
///
/// This is the only Rf record a failed call ever produces: no accounting
/// session is opened, so there is no START/STOP pair, and it is the only place
/// a non-zero `Cause-Code` reaches the CDF. Without it, a collector cannot
/// distinguish "nobody answered" from "never attempted".
///
/// Auth challenges (401/407) are excluded — the UA re-sends against them and
/// the retry is the same call attempt, not a new failed one. 487 is *not*
/// excluded: a caller who hung up during alerting is a real, reportable
/// unsuccessful setup.
pub fn spawn_rf_proxy_event_on_failed_invite(
    state: &DispatcherState,
    server_key: &TransactionKey,
    original_request: &SipMessage,
    status_code: u16,
    session_arc: &Arc<std::sync::RwLock<crate::proxy::session::ProxySession>>,
) {
    let charger = match state.rf_charger.as_ref() {
        Some(c) if c.auto_emit_proxy() => Arc::clone(c),
        _ => return,
    };
    if server_key.method != crate::sip::message::Method::Invite {
        return;
    }
    if status_code == 401 || status_code == 407 {
        return;
    }
    // Only an *initial* INVITE can fail to establish a session. A re-INVITE
    // carries a To-tag and belongs to a dialog that is already up and already
    // has its own accounting session, so a failed one is a mid-call event, not
    // a failed setup.
    if original_request
        .typed_to()
        .ok()
        .flatten()
        .and_then(|to| to.tag)
        .is_some()
    {
        return;
    }
    let Some(cause_code) = crate::diameter::rf::sip_status_to_cause_code(status_code) else {
        return;
    };
    let timestamps = rf_timestamps_for_session(session_arc);

    let local_predicate = rf_local_uri_predicate(&state.local_domains);
    let mut ims_data = crate::diameter::rf_service::ims_data_from_request(
        original_request,
        charger.node_functionality(),
        &local_predicate,
        timestamps,
    );
    if let Some((call_id, from_tag)) = rf_extract_dialog_parts(original_request) {
        let drained = crate::diameter::rf_service::read_rf_charging_params(&format!(
            "{}\0{}",
            call_id, from_tag
        ));
        crate::diameter::rf_service::apply_charging_params(&mut ims_data, drained);
    }
    ims_data.cause_code = Some(cause_code);

    let user_name = crate::diameter::rf_service::served_party_identities(&ims_data)
        .into_iter()
        .next();
    debug!(
        status_code,
        cause_code, "rf: proxy ACR-EVENT for unsuccessful session establishment"
    );
    tokio::spawn(async move {
        charger.acr_event(ims_data, user_name).await;
    });
}

/// Holds an `rf_pending_starts` reservation for as long as the ACR-START it
/// guards is in flight, and releases it on drop — so a rejected START, a
/// dropped peer, or a panic can't wedge the key permanently.
pub struct RfStartReservation {
    pub pending: Arc<DashMap<String, std::time::Instant>>,
    pub key: String,
}

impl Drop for RfStartReservation {
    fn drop(&mut self) {
        self.pending.remove(&self.key);
    }
}

/// Claim `key` for an ACR-START that is about to be spawned.  `None` means
/// another task is already opening a record under it — the caller must not
/// spawn a second one.
pub fn rf_reserve_start(
    pending: &Arc<DashMap<String, std::time::Instant>>,
    key: &str,
) -> Option<RfStartReservation> {
    use dashmap::mapref::entry::Entry;
    match pending.entry(key.to_string()) {
        Entry::Occupied(_) => None,
        Entry::Vacant(slot) => {
            slot.insert(std::time::Instant::now());
            Some(RfStartReservation {
                pending: Arc::clone(pending),
                key: key.to_string(),
            })
        }
    }
}

/// Spawn ACR-START for the INVITE that just got a 2xx forwarded by the
/// proxy.  No-op when `rf_charger` is unset, auto-emit is disabled, or
/// the original method wasn't INVITE.
///
/// **Keying (TS 32.260 §5.5):** the resulting `RfChargingSession` is
/// co-stored under both an ICID-keyed primary (when the inbound INVITE
/// carries `P-Charging-Vector`) and a SIP-dialog fallback
/// `<Call-ID>\0<From-tag>`.  iFC re-dispatch through MMTel-AS — which
/// rewrites From-tag but preserves ICID — therefore deduplicates on
/// the ICID key, no longer producing the orphan ACR-STARTs that
/// plagued the From-tag-only keying scheme.
///
/// **Intra-S-CSCF dual-ACR (TS 32.260 §5.1):** when both the calling
/// and called parties are locally-served identities, the S-CSCF emits
/// two independent ACR sequences — one ORIGINATING, one TERMINATING.
/// Each sequence has its own Session-Id and Record-Number, and is
/// stored under its own `:orig` / `:term` keys so the BYE handler can
/// stop both in parallel.
pub fn spawn_rf_proxy_start_if_invite(
    state: &DispatcherState,
    server_key: &TransactionKey,
    original_request: &SipMessage,
    session_arc: &Arc<std::sync::RwLock<crate::proxy::session::ProxySession>>,
) {
    use crate::diameter::rf_service::{
        rf_dialog_key as build_rf_dialog_key, rf_icid_key, rf_session_storage_keys, RfRole,
    };

    let charger = match state.rf_charger.as_ref() {
        Some(c) if c.auto_emit_proxy() => Arc::clone(c),
        Some(_) => {
            debug!("rf: proxy ACR-START skipped — auto_emit_proxy disabled");
            return;
        }
        None => {
            debug!("rf: proxy ACR-START skipped — rf_charger not configured");
            return;
        }
    };
    if server_key.method != crate::sip::message::Method::Invite {
        debug!(
            method = server_key.method.as_str(),
            "rf: proxy ACR-START skipped — non-INVITE method"
        );
        return;
    }
    let (call_id, from_tag) = match rf_extract_dialog_parts(original_request) {
        Some(parts) => parts,
        None => {
            debug!("rf: proxy ACR-START skipped — INVITE has no Call-ID + From-tag");
            return;
        }
    };
    let icid = rf_extract_icid(original_request);
    // Resolved only once charging is known to be on — an operator running
    // without Rf must not pay a session read-lock per answered call.
    let timestamps = rf_timestamps_for_session(session_arc);

    // Build the IMS data first so we can key the dedupe by the
    // *actual* role (orig vs term) the request resolves to.  Hard-
    // coding `:orig` here used to silently drop the MT leg of an
    // intra-NF call (same ICID, different roles), because both legs
    // hit the same `:orig` key and the second arrival saw the first
    // already filed — even though the second was a TERMINATING
    // record on a distinct From-URI.
    let local_predicate = rf_local_uri_predicate(&state.local_domains);
    let mut ims_data = crate::diameter::rf_service::ims_data_from_request(
        original_request,
        charger.node_functionality(),
        &local_predicate,
        timestamps,
    );
    // Apply any script-supplied charging params (set via
    // `request.set_charging_param("outgoing-trunk-group-id", "...")`).
    // Drained from the side-map keyed by the inbound dialog key so a
    // BGCF script that picked a gateway via gateway.select(...) can
    // stamp the trunk-group-id without writing the whole ACR by hand.
    let drained_params =
        crate::diameter::rf_service::read_rf_charging_params(&format!("{}\0{}", call_id, from_tag));
    crate::diameter::rf_service::apply_charging_params(&mut ims_data, drained_params);

    // Resolve the RfRole from the request's role_of_node — defaults
    // to ORIGINATING when ims_data_from_request couldn't detect.
    let primary_role = match ims_data.role_of_node {
        Some(crate::diameter::ro::NodeRole::TerminatingRole) => RfRole::Terminating,
        _ => RfRole::Originating,
    };
    let primary_key = match icid.as_deref() {
        Some(icid) => rf_icid_key(icid, primary_role),
        None => build_rf_dialog_key(&call_id, &from_tag, primary_role),
    };
    if state.rf_sessions.contains_key(&primary_key) {
        debug!(
            primary_key = %primary_key,
            "rf: proxy ACR-START skipped — record already tracked"
        );
        return;
    }
    // Hold the key for the duration of the CDF round-trip, not just up to the
    // spawn — see `DispatcherState::rf_pending_starts`.
    let Some(primary_reservation) = rf_reserve_start(&state.rf_pending_starts, &primary_key) else {
        debug!(
            primary_key = %primary_key,
            "rf: proxy ACR-START skipped — record already opening"
        );
        return;
    };
    debug!(
        primary_key = %primary_key,
        role = primary_role.as_suffix(),
        icid = icid.as_deref().unwrap_or("(none)"),
        "rf: proxy ACR-START spawning"
    );

    // Intra-S-CSCF dual-ACR detection (TS 32.260 §5.1): when this
    // INVITE is itself the originating leg AND the called party is
    // *also* locally served by an S-CSCF, emit a parallel
    // terminating record.  Skipped when the primary role is already
    // TERMINATING (the MT-only leg of an intra-NF call) — that path
    // emits a single record under `:term` and the matching ORIG
    // record arrives separately on the MO leg.
    let term_user_name = if primary_role == RfRole::Originating {
        ims_data
            .called_party
            .as_deref()
            .filter(|uri| local_predicate(uri))
            .filter(|_| {
                charger.node_functionality() == Some(crate::diameter::ro::NodeFunctionality::SCscf)
            })
            .map(str::to_owned)
    } else {
        None
    };

    let rf_sessions = Arc::clone(&state.rf_sessions);

    if let Some(term_user) = term_user_name {
        // Dual-ACR (TS 32.260 §5.1): spawn the originating record
        // AND a parallel terminating record.  Each gets its own set
        // of storage keys (ICID + dialog fallback, both with `:term`).
        let term_keys =
            rf_session_storage_keys(icid.as_deref(), &call_id, &from_tag, RfRole::Terminating);
        // TERM-side dedupe: the terminating leg of an intra-node call reaches
        // this function on its own 2xx and resolves to the same `:term` key,
        // so without the in-flight reservation both it and this speculative
        // record open one — same ICID, same role, two Session-Ids, and only
        // one of them reachable from the BYE.
        if let Some(first_term_key) = term_keys.first() {
            if state.rf_sessions.contains_key(first_term_key) {
                debug!(
                    term_key = %first_term_key,
                    "rf: dual-ACR TERM skipped — record already tracked"
                );
                // Fall through to spawn the ORIG record.
                let _ = term_user;
            } else if let Some(term_reservation) =
                rf_reserve_start(&state.rf_pending_starts, first_term_key)
            {
                let mut ims_term = ims_data.clone();
                ims_term.role_of_node = Some(crate::diameter::ro::NodeRole::TerminatingRole);
                let charger_term = Arc::clone(&charger);
                let rf_sessions_term = Arc::clone(&rf_sessions);
                let term_user_for_record = term_user.clone();
                let term_keys_for_spawn = term_keys.clone();
                tokio::spawn(async move {
                    // Held until the task ends so the reservation outlives the
                    // ACR-START round-trip and is released on every exit path.
                    let _reservation = term_reservation;
                    let session = match charger_term
                        .acr_start(ims_term.clone(), Some(term_user_for_record.clone()))
                        .await
                    {
                        Some(s) => s,
                        None => return,
                    };
                    let entry = Arc::new(ProxyRfState {
                        session,
                        ims_data: ims_term,
                        user_name: Some(term_user_for_record),
                        storage_keys: term_keys_for_spawn.clone(),
                        created_at: std::time::Instant::now(),
                    });
                    for key in term_keys_for_spawn {
                        rf_sessions_term.insert(key, Arc::clone(&entry));
                    }
                });
            } else {
                debug!(
                    term_key = %first_term_key,
                    "rf: dual-ACR TERM skipped — record already opening"
                );
            }
        }
    }

    // Primary record — emitted under the role this request resolved
    // to (orig for MO legs / S-CSCF dual-ACR primary; term for the
    // standalone MT leg of an intra-NF call where the same NF sees
    // both legs separately).
    let primary_keys = rf_session_storage_keys(icid.as_deref(), &call_id, &from_tag, primary_role);
    let mut ims_primary = ims_data;
    // ims_data_from_request always sets a role, but defend against
    // future refactors that might leave it None.
    if ims_primary.role_of_node.is_none() {
        ims_primary.role_of_node = Some(match primary_role {
            RfRole::Originating => crate::diameter::ro::NodeRole::OriginatingRole,
            RfRole::Terminating => crate::diameter::ro::NodeRole::TerminatingRole,
        });
    }
    // User-Name names the *served* party (TS 32.260 §5.1), which on the
    // standalone terminating leg of an intra-node call is the callee — taking
    // the calling party unconditionally put the caller's IMPU on the callee's
    // record.
    let primary_user_name = crate::diameter::rf_service::served_party_identities(&ims_primary)
        .into_iter()
        .next();
    tokio::spawn(async move {
        let _reservation = primary_reservation;
        let session = match charger
            .acr_start(ims_primary.clone(), primary_user_name.clone())
            .await
        {
            Some(s) => s,
            None => return,
        };
        let entry = Arc::new(ProxyRfState {
            session,
            ims_data: ims_primary,
            user_name: primary_user_name,
            storage_keys: primary_keys.clone(),
            created_at: std::time::Instant::now(),
        });
        for key in primary_keys {
            rf_sessions.insert(key, Arc::clone(&entry));
        }
    });
}

/// Spawn ACR-STOP for the dialog this BYE belongs to.  No-op when no
/// matching Rf session is tracked.
///
/// **Lookup priority (TS 32.260 §5.5):** ICID key first (preserved
/// across iFC chain when P-CSCF is spec-compliant), falling back to
/// SIP-dialog key with both From-tag and To-tag candidates.
///
/// Also handles intra-S-CSCF dual-ACR (TS 32.260 §5.1): both the
/// ORIGINATING and TERMINATING records are stopped in parallel.
///
/// Entries are removed from `rf_sessions` **after** ACR-STOP completes
/// rather than at BYE arrival.  This keeps the entry visible to
/// `cdr.write()` calls from the script's `@proxy.on_request` handler
/// for the BYE so the CDR can be auto-stamped with `rf_session_id` /
/// `rf_result_code` (see `crate::diameter::rf_service::lookup_rf_for_dialog`).
/// Idempotency is enforced inside [`RfChargingService::acr_stop`] —
/// duplicate BYE retransmits short-circuit without re-emitting on the
/// wire.
pub fn spawn_rf_proxy_stop_if_tracked(state: &DispatcherState, bye: &SipMessage) {
    use crate::diameter::rf_service::{rf_lookup_candidates, RfRole};

    let charger = match state.rf_charger.as_ref() {
        Some(c) if c.auto_emit_proxy() => Arc::clone(c),
        _ => return,
    };

    let icid = rf_extract_icid(bye);
    let call_id = bye.headers.get("Call-ID").cloned();
    let from_tag = bye.typed_from().ok().flatten().and_then(|na| na.tag);
    let to_tag = bye.typed_to().ok().flatten().and_then(|na| na.tag);

    let candidates = rf_lookup_candidates(
        icid.as_deref(),
        call_id.as_deref(),
        from_tag.as_deref(),
        to_tag.as_deref(),
    );

    // Find the first storage entry the BYE resolves to, then collect
    // every Rf record reachable from there (orig + term in dual-ACR).
    // Using DashMap::get over the candidate list keeps the hot path
    // bounded — at most 8 hashmap probes for a complete BYE.
    let mut found_orig: Option<Arc<ProxyRfState>> = None;
    let mut found_term: Option<Arc<ProxyRfState>> = None;
    for key in &candidates {
        if let Some(entry) = state.rf_sessions.get(key) {
            let role_suffix = key.rsplit(':').next();
            match role_suffix {
                Some("orig") if found_orig.is_none() => {
                    found_orig = Some(Arc::clone(entry.value()));
                }
                Some("term") if found_term.is_none() => {
                    found_term = Some(Arc::clone(entry.value()));
                }
                _ => {}
            }
            if found_orig.is_some() && found_term.is_some() {
                break;
            }
        }
    }
    if found_orig.is_none() && found_term.is_none() {
        return;
    }

    // Pick up the Reason header if present (RFC 3326) — maps SIP cause
    // through to IMS-Information Cause-Code per TS 32.299 §5.2.5.
    let cause_code = bye
        .headers
        .get("Reason")
        .and_then(|r| {
            // Reason: SIP ;cause=200 ;text="..."
            r.split(';')
                .filter_map(|p| p.trim().strip_prefix("cause="))
                .next()
                .and_then(|v| v.split_whitespace().next())
                .and_then(|v| v.parse::<u16>().ok())
        })
        .and_then(crate::diameter::rf::sip_status_to_cause_code);
    let response_timestamp = std::time::SystemTime::now();

    let stop_one =
        |entry: Arc<ProxyRfState>, charger: Arc<crate::diameter::rf_service::RfChargingService>| {
            let rf_sessions = Arc::clone(&state.rf_sessions);
            tokio::spawn(async move {
                let session = entry.session.clone();
                let mut ims_data = entry.ims_data.clone();
                let user_name = entry.user_name.clone();
                ims_data.sip_method = Some("BYE".to_string());
                ims_data.cause_code = cause_code.or(Some(0));
                // Time-Stamps describes *this* record's trigger request
                // (TS 32.299 §7.2.183), and for a STOP that is the BYE — not
                // the INVITE the START already reported. Carrying the INVITE
                // instant forward left a record whose Event-Type said BYE and
                // whose request timestamp was minutes older.
                ims_data.request_timestamp = Some(response_timestamp);
                ims_data.response_timestamp = Some(response_timestamp);
                charger
                    .acr_stop(
                        &session,
                        ims_data,
                        user_name,
                        crate::diameter::rf::termination_cause::DIAMETER_LOGOUT,
                    )
                    .await;
                // ACR-STOP is committed; the CDR-correlation window is
                // now closed.  Drop every alias under which this
                // record was filed.
                for key in &entry.storage_keys {
                    rf_sessions.remove(key);
                }
            });
        };

    let _ = RfRole::Originating; // enum import kept for symmetry with start side
    if let Some(entry) = found_orig {
        stop_one(entry, Arc::clone(&charger));
    }
    if let Some(entry) = found_term {
        stop_one(entry, charger);
    }
}

/// Spawn ACR-START for a B2BUA call when the A-leg INVITE has been
/// answered.  No-op when `rf_charger` is unset or auto-emit disabled.
/// Stores the resulting [`ProxyRfState`] in `state.rf_sessions` keyed
/// by `b2bua:<internal_call_id>` so the BYE handler can find it.
pub fn spawn_rf_b2bua_start(
    state: &DispatcherState,
    internal_call_id: &str,
    a_leg_invite: &Arc<std::sync::Mutex<SipMessage>>,
) {
    let charger = match state.rf_charger.as_ref() {
        Some(c) if c.auto_emit_b2bua() => Arc::clone(c),
        Some(_) => {
            debug!(
                call_id = %internal_call_id,
                "rf: B2BUA ACR-START skipped — auto_emit_b2bua disabled"
            );
            return;
        }
        None => {
            debug!(
                call_id = %internal_call_id,
                "rf: B2BUA ACR-START skipped — rf_charger not configured"
            );
            return;
        }
    };
    let key = crate::diameter::rf_service::rf_b2bua_key(internal_call_id);
    if state.rf_sessions.contains_key(&key) {
        debug!(
            call_id = %internal_call_id,
            "rf: B2BUA ACR-START skipped — call already tracked"
        );
        return;
    }
    let Some(reservation) = rf_reserve_start(&state.rf_pending_starts, &key) else {
        debug!(
            call_id = %internal_call_id,
            "rf: B2BUA ACR-START skipped — record already opening"
        );
        return;
    };
    debug!(
        call_id = %internal_call_id,
        "rf: B2BUA ACR-START spawning"
    );
    // Snapshot the A-leg INVITE under the script-side mutex so we
    // build a stable IMS-Information block even if a script later
    // mutates the message.
    let invite_clone = match a_leg_invite.lock() {
        Ok(guard) => guard.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    };
    // The call actor's creation instant is the A-leg INVITE's arrival; this
    // record is built at the answer, so both ends of Time-Stamps come from
    // there rather than from a clock sample taken now.
    let timestamps = match state.call_actors.created_at(internal_call_id) {
        Some(invite_received) => {
            crate::diameter::rf_service::SipTimestamps::from_request_instant(invite_received)
        }
        None => crate::diameter::rf_service::SipTimestamps::now(),
    };
    let local_predicate = rf_local_uri_predicate(&state.local_domains);
    let mut ims_data = crate::diameter::rf_service::ims_data_from_request(
        &invite_clone,
        charger.node_functionality(),
        local_predicate,
        timestamps,
    );
    // Drain any script-supplied charging params keyed by the A-leg
    // dialog (BGCF / MGCF auto-emit stamping trunk-group-id, etc.).
    if let Some((call_id, from_tag)) = rf_extract_dialog_parts(&invite_clone) {
        let drained = crate::diameter::rf_service::read_rf_charging_params(&format!(
            "{}\0{}",
            call_id, from_tag
        ));
        crate::diameter::rf_service::apply_charging_params(&mut ims_data, drained);
    }
    // B2BUA mode → Role-of-Node = B2BUA_ROLE per TS 32.299 §7.2.149,
    // overriding the orig/term derived from local-domain matching.
    // Operators that need orig/term semantics (AS-as-B2BUA) can set
    // node_functionality=as in YAML and we still emit B2BUA_ROLE; if
    // they want the role override they can call
    // diameter.rf_acr_* manually with role_of_node=...
    ims_data.role_of_node = Some(crate::diameter::ro::NodeRole::B2buaRole);
    let user_name = crate::diameter::rf_service::served_party_identities(&ims_data)
        .into_iter()
        .next();
    let rf_sessions = Arc::clone(&state.rf_sessions);
    tokio::spawn(async move {
        let _reservation = reservation;
        let session = match charger.acr_start(ims_data.clone(), user_name.clone()).await {
            Some(s) => s,
            None => return,
        };
        rf_sessions.insert(
            key.clone(),
            Arc::new(ProxyRfState {
                session,
                ims_data,
                user_name,
                storage_keys: vec![key],
                created_at: std::time::Instant::now(),
            }),
        );
    });
}

/// Spawn ACR-STOP for a B2BUA call when its BYE arrives.  Picks up an
/// optional RFC 3326 `Reason:` header for IMS Cause-Code mapping.
/// Termination-Cause defaults to `DIAMETER_LOGOUT(1)`.
///
/// Removal from `rf_sessions` is deferred until after ACR-STOP
/// completes so script-driven `cdr.write()` calls still see the
/// rf_session for auto-stamping.  See [`spawn_rf_proxy_stop_if_tracked`]
/// for the full rationale.
/// Derive a Diameter Q.850 cause code from an RFC 3326 `Reason:` header, if
/// present. The `cause=` parameter is interpreted as a SIP status code and
/// mapped via [`crate::diameter::rf::sip_status_to_cause_code`] — the historical
/// B2BUA BYE behaviour, kept identical when [`spawn_rf_b2bua_stop`] moved from
/// taking the BYE message to taking the pre-derived cause.
pub fn parse_reason_cause(message: &SipMessage) -> Option<i32> {
    message
        .headers
        .get("Reason")
        .and_then(|r| {
            r.split(';')
                .filter_map(|p| p.trim().strip_prefix("cause="))
                .next()
                .and_then(|v| v.split_whitespace().next())
                .and_then(|v| v.parse::<u16>().ok())
        })
        .and_then(crate::diameter::rf::sip_status_to_cause_code)
}

pub fn spawn_rf_b2bua_stop(
    state: &DispatcherState,
    internal_call_id: &str,
    cause_code: Option<i32>,
) {
    let charger = match state.rf_charger.as_ref() {
        Some(c) if c.auto_emit_b2bua() => Arc::clone(c),
        _ => return,
    };
    let key = crate::diameter::rf_service::rf_b2bua_key(internal_call_id);
    if !state.rf_sessions.contains_key(&key) {
        return;
    }

    let response_timestamp = std::time::SystemTime::now();

    let rf_sessions = Arc::clone(&state.rf_sessions);
    tokio::spawn(async move {
        let snapshot = rf_sessions.get(&key).map(|entry| {
            let v = entry.value();
            (v.session.clone(), v.ims_data.clone(), v.user_name.clone())
        });
        let Some((session, mut ims_data, user_name)) = snapshot else {
            return;
        };
        ims_data.sip_method = Some("BYE".to_string());
        ims_data.cause_code = cause_code.or(Some(0));
        // See the proxy stop path: Time-Stamps on a STOP describes the BYE.
        ims_data.request_timestamp = Some(response_timestamp);
        ims_data.response_timestamp = Some(response_timestamp);
        charger
            .acr_stop(
                &session,
                ims_data,
                user_name,
                crate::diameter::rf::termination_cause::DIAMETER_LOGOUT,
            )
            .await;
        rf_sessions.remove(&key);
    });
}
