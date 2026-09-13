//! Ro online charging: reserve credit before the call connects.
//!
//! `ro_authorize_b2bua` is the gate — a prepaid call that cannot reserve is
//! rejected rather than connected and billed later.

use crate::dispatcher::*;

/// Key prefix for a B2BUA call's Ro session in `state.ro_sessions`.
///
/// Load-bearing in both directions: [`ro_b2bua_key`] writes it and
/// [`orphaned_ro_session_keys`] reads it back to recover the internal call UUID
/// and ask whether that call is still alive. Any future non-B2BUA Ro session
/// filed in the same map under a different prefix is left alone by the orphan
/// backstop rather than reaped against a call store that never knew it.
pub const RO_B2BUA_KEY_PREFIX: &str = "ro-b2bua:";

/// Format the B2BUA Ro-session key from the internal call UUID.
pub fn ro_b2bua_key(internal_call_id: &str) -> String {
    format!("{RO_B2BUA_KEY_PREFIX}{internal_call_id}")
}

/// The `ro_sessions` keys whose B2BUA call is gone — a credit reservation that
/// outlived the call it was made for.
///
/// The invariant: `call.ro_authorize()` reserves *before* the B-leg is
/// connected, so from the reservation until the call ends there is a live Ro
/// session whose only owner is the call actor. Every terminal path is supposed
/// to release it, and the ones that answer the A-leg do, carrying the status
/// they sent as the `Cause-Code`. This is the backstop for the ones that do
/// not: a reservation whose call actor has been removed can never be released
/// by anything else, and left alone its re-auth timer keeps sending CCR-UPDATE
/// for a call that no longer exists (and, in the undialled cases, never had a
/// leg at all) until the charging layer's own 24-hour max-lifetime fires.
///
/// Keyed on the call still existing rather than on an age — the same rule the
/// B-leg event-receiver backstop uses — so it catches an orphan from any cause,
/// including a terminal path that has not been written yet. That covers the
/// transferee's transient call in a `Replaces` takeover too, whose actor is
/// removed when its leg is adopted: the merged conversation keeps charging on
/// the *surviving* call's own session, so the reservation left on the id that
/// ceased to exist is a duplicate and releasing it is right.
///
/// Generic over the value so the decision logic is testable without standing up
/// a Diameter peer: what is worth testing here is the key mapping and the
/// liveness question, and both are wrong in a *dangerous* direction — a broken
/// prefix strip reaps live calls' reservations, cutting charging on calls that
/// are still up.
pub fn orphaned_ro_session_keys<V>(
    ro_sessions: &DashMap<String, V>,
    call_actors: &CallActorStore,
) -> Vec<String> {
    ro_sessions
        .iter()
        .filter(|entry| {
            entry
                .key()
                .strip_prefix(RO_B2BUA_KEY_PREFIX)
                .is_some_and(|internal_call_id| !call_actors.contains_call(internal_call_id))
        })
        .map(|entry| entry.key().clone())
        .collect()
}

/// Release Ro credit reservations whose B2BUA call is gone (see
/// [`orphaned_ro_session_keys`]).
///
/// Runs on the 500 ms call-lifetime tick rather than the 30 s stale sweep so an
/// orphan is released inside one `MIN_REAUTH_SECS` window — the point is that
/// **no** CCR-UPDATE goes out for a call that has already ended, and a 30 s
/// cadence would let several through.
///
/// The `warn!` is the diagnosis, not noise: reaching here at all means a
/// terminal path removed a call without releasing its reservation, and the call
/// UUID is what points at which one. `None` for the `Cause-Code` — the AVP is
/// omitted rather than reported as `0`, because siphon does not know what status
/// the A-leg was sent from here and "normal end" would be a claim, not a gap.
pub fn check_orphaned_ro_sessions(state: &DispatcherState) {
    // Ro off, or nothing reserved: the overwhelmingly common case, and the
    // reason this is cheap enough for a 500 ms tick.
    if state.ro_charger.is_none() || state.ro_sessions.is_empty() {
        return;
    }
    // Collect first, then remove: iterating a DashMap while removing from it on
    // the same thread can deadlock on a shard lock.
    let orphans = orphaned_ro_session_keys(&state.ro_sessions, &state.call_actors);
    if orphans.is_empty() {
        return;
    }
    let Some(charger) = state.ro_charger.as_ref().map(Arc::clone) else {
        return;
    };
    for key in orphans {
        let Some((key, session)) = state.ro_sessions.remove(&key) else {
            continue;
        };
        warn!(
            ro_session_key = %key,
            session_id = %session.session_id(),
            "ro: credit reservation outlived its call — a B2BUA teardown path \
             removed the call without releasing it; terminating (no Cause-Code: \
             the status the A-leg was sent is not knowable from here)"
        );
        let charger = Arc::clone(&charger);
        tokio::spawn(async move {
            charger.terminate_call(&session, None).await;
        });
    }
}

/// Outcome of a script `call.ro_authorize()` gate — returned to Python as a
/// dict `{authorized, result_code, granted_time, session_id}`.
pub struct RoAuthorizeOutcome {
    pub authorized: bool,
    pub result_code: Option<u32>,
    pub granted_time: Option<u32>,
    pub session_id: Option<String>,
}

/// Global handle the `call.ro_authorize()` scripting gate reaches to reserve
/// credit before dialing the B-leg. Bundles the charger + the dispatcher's
/// session store so the reserved `CcCreditSession` lands where BYE / teardown /
/// failure paths find it (`ro_b2bua_key(internal_call_id)`).
pub struct RoControlHandle {
    pub charger: Arc<crate::diameter::ro_service::RoChargingService>,
    pub ro_sessions: Arc<DashMap<String, crate::diameter::ro_service::CcCreditSession>>,
    pub local_domains: Arc<Vec<String>>,
}

pub static RO_CONTROL: std::sync::OnceLock<RoControlHandle> = std::sync::OnceLock::new();

/// Reserve credit (CCR-INITIAL) for a B2BUA call from a `@b2bua.on_invite`
/// script gate, BEFORE the B-leg is dialed. On grant the session is stored
/// keyed by the call so its re-auth loop runs and BYE/teardown sends
/// CCR-TERMINATION. Returns the grant/deny outcome for the script to branch on
/// (grant → `call.dial()`, deny → `call.reject()`).
///
/// `subscription_id` overrides the charged identity; when `None`, the party is
/// derived from `ro.charge` (orig = calling, term = called) off the INVITE.
pub async fn ro_authorize_b2bua(
    internal_call_id: String,
    invite: SipMessage,
    subscription_id: Option<String>,
    subscription_id_type: Option<String>,
) -> RoAuthorizeOutcome {
    use crate::diameter::ro_service::ChargeDecision;
    let deny = |code: Option<u32>| RoAuthorizeOutcome {
        authorized: false,
        result_code: code,
        granted_time: None,
        session_id: None,
    };
    let Some(control) = RO_CONTROL.get() else {
        // Ro not configured — the gate is a no-op that authorizes (uncharged).
        return RoAuthorizeOutcome {
            authorized: true,
            result_code: None,
            granted_time: None,
            session_id: None,
        };
    };
    let charger = Arc::clone(&control.charger);

    let local_predicate = rf_local_uri_predicate(&control.local_domains);
    let mut ims_data = crate::diameter::rf_service::ims_data_from_request(
        &invite,
        charger.node_functionality(),
        local_predicate,
        // Ro authorizes before the call is answered, so the INVITE is the
        // present event and there is no response instant yet.
        crate::diameter::rf_service::SipTimestamps::now(),
    );
    ims_data.role_of_node = Some(crate::diameter::ro::NodeRole::B2buaRole);

    let subscriber = match subscription_id {
        Some(id) => build_ro_subscriber(&id, subscription_id_type.as_deref()),
        None => {
            let party = match charger.config().charge.as_str() {
                "term" => ims_data.called_party.clone(),
                // The calling party may be asserted under several identities;
                // charge the first, which is the canonical IMPU.
                _ => ims_data.calling_party.first().cloned(),
            };
            let Some(party_uri) = party else {
                warn!(call_id = %internal_call_id,
                    "ro: ro_authorize skipped — no chargeable party on the INVITE");
                return deny(None);
            };
            crate::diameter::ro::SubscriberId::sip_uri(&party_uri)
        }
    };

    let sip_call_id = rf_extract_dialog_parts(&invite)
        .map(|(call_id, _)| call_id)
        .unwrap_or_else(|| internal_call_id.clone());

    let decision = charger
        .authorize_call(subscriber, ims_data, sip_call_id)
        .await;
    match decision {
        ChargeDecision::Granted(Some(session)) => {
            let outcome = RoAuthorizeOutcome {
                authorized: true,
                result_code: session.last_result_code(),
                granted_time: Some(session.granted_time()),
                session_id: Some(session.session_id().to_string()),
            };
            control
                .ro_sessions
                .insert(ro_b2bua_key(&internal_call_id), session);
            outcome
        }
        // 4011 CREDIT_CONTROL_NOT_APPLICABLE / Ro disabled / fail-open: the call
        // proceeds, unmonitored — no session to store.
        ChargeDecision::Granted(None) | ChargeDecision::AllowUncharged => RoAuthorizeOutcome {
            authorized: true,
            result_code: None,
            granted_time: None,
            session_id: None,
        },
        ChargeDecision::Denied(code) => deny(Some(code)),
    }
}

/// Build a `SubscriberId` from a script `(id, type)` pair, inferring a `sip:`/
/// `tel:` URI when the type is omitted (never mislabels a SIP URI as E.164).
pub fn build_ro_subscriber(id: &str, id_type: Option<&str>) -> crate::diameter::ro::SubscriberId {
    use crate::diameter::ro::SubscriberId;
    match id_type.map(|s| s.to_ascii_lowercase()).as_deref() {
        Some("e164") | Some("msisdn") => SubscriberId::msisdn(id),
        Some("imsi") => SubscriberId::imsi(id),
        Some("sip") | Some("sipuri") | Some("sip_uri") => SubscriberId::sip_uri(id),
        _ => {
            let lower = id.to_ascii_lowercase();
            if lower.starts_with("sip:") || lower.starts_with("sips:") || lower.starts_with("tel:")
            {
                SubscriberId::sip_uri(id)
            } else {
                SubscriberId::msisdn(id)
            }
        }
    }
}

/// Record the carrier that answered on the call's Ro session, so its
/// CCR-UPDATEs and CCR-TERMINATION carry `Outgoing-Trunk-Group-Id`
/// (TS 32.299 §7.2.71).
///
/// No-op when Ro is off or the call holds no reservation.
pub fn ro_stamp_winning_carrier(state: &DispatcherState, internal_call_id: &str, carrier_id: &str) {
    if carrier_id.is_empty() {
        return;
    }
    if let Some(session) = state.ro_sessions.get(&ro_b2bua_key(internal_call_id)) {
        session.set_outgoing_trunk_group(carrier_id);
    }
}

/// Report the answer on a B2BUA call's Ro session: start the chargeable clock
/// and send the answer-time CCR-UPDATE (`Time-Stamps`, TS 32.299 §7.2.97).
///
/// Fire-and-forget, like every other charging spawn — the SIP path must not
/// wait on the OCS. No-op when Ro is off or the call holds no reservation, and
/// idempotent on a retransmitted 200 OK.
pub fn spawn_ro_b2bua_answer(state: &DispatcherState, internal_call_id: &str) {
    if state.ro_charger.is_none() {
        return;
    }
    let Some(charger) = state.ro_charger.as_ref().map(Arc::clone) else {
        return;
    };
    let Some(session) = state
        .ro_sessions
        .get(&ro_b2bua_key(internal_call_id))
        .map(|entry| entry.clone())
    else {
        return;
    };
    tokio::spawn(async move {
        charger.report_answer(&session).await;
    });
}

/// Send CCR-TERMINATION for a B2BUA call's Ro session on BYE / teardown.
///
/// `cause_code` is the IMS-Information `Cause-Code` for the record
/// (TS 32.299 §7.2.35), in the same negative-SIP convention and from the same
/// source as the Rf ACR-STOP one — the two interfaces must never disagree about
/// why a call ended, so both take it from [`parse_reason_cause`] / the SIP
/// status via [`crate::diameter::rf::sip_status_to_cause_code`]. `None` means a
/// normal end and is reported as `0`.
pub fn spawn_ro_b2bua_stop(
    state: &DispatcherState,
    internal_call_id: &str,
    cause_code: Option<i32>,
) {
    if state.ro_charger.is_none() {
        return;
    }
    let charger = match state.ro_charger.as_ref() {
        Some(c) => Arc::clone(c),
        None => return,
    };
    let key = ro_b2bua_key(internal_call_id);
    let Some((_, session)) = state.ro_sessions.remove(&key) else {
        return;
    };
    tokio::spawn(async move {
        charger
            .terminate_call(&session, Some(cause_code.unwrap_or(0)))
            .await;
    });
}
