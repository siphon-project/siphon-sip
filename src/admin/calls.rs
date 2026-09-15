//! The admin API's view of the active B2BUA calls (`GET /admin/calls`): each
//! call with its parties, branches, session timers, carrier attempts and
//! rating, as JSON.

/// Clean a From/To header value into a bare display URI (`sip:user@host`) by
/// dropping the display name, angle brackets, and any `;tag=`/URI params — for
/// the calls listing's caller/callee columns.
fn display_party(header_value: &str) -> String {
    let uri = crate::b2bua::actor::extract_contact_uri(header_value);
    uri.split(';').next().unwrap_or(&uri).trim().to_string()
}

/// Serialize the active B2BUA calls. Split from the handler so it can be
/// unit-tested against a locally-built store without the process-global.
pub(super) fn calls_json(store: &crate::b2bua::actor::CallActorStore) -> serde_json::Value {
    use crate::b2bua::actor::{CallState, Leg};

    let mut calls: Vec<serde_json::Value> = Vec::new();
    for entry in store.iter_calls() {
        let call = entry.value();
        let state = match call.state {
            CallState::Calling => "calling",
            CallState::Ringing => "ringing",
            CallState::Answered => "answered",
            CallState::Terminated => "terminated",
        };
        // A-party = the caller. The inbound INVITE's From is stored as the
        // A-leg's `remote_to_uri` (as UAS, our in-dialog To is the caller). The
        // A-leg's `local_from_uri` is the INVITE *To* (the dialed identity), NOT
        // the caller — surfacing that as "from" was why a bridged call looked
        // like it only showed one leg.
        let a_party = call
            .a_leg
            .dialog
            .remote_to_uri
            .as_deref()
            .map(display_party);
        // B-party = the real dialed/forked callee. Exclude the re-INVITE/UPDATE
        // response-tracking pseudo-legs (their `target_uri` is a direction
        // marker) from both the displayed callee and the leg count, so a plain
        // call that did one re-INVITE no longer reports two B-legs.
        let real_b_legs: Vec<&Leg> = call
            .b_legs
            .iter()
            .filter(|leg| !leg.is_tracking_leg())
            .collect();
        let b_party = real_b_legs
            .first()
            .and_then(|leg| leg.dialog.target_uri.as_deref())
            .map(display_party);

        // Durations are derived from monotonic `Instant`s — the call actor keeps
        // no wall-clock stamp — so these are elapsed seconds and the client
        // renders "started N ago" rather than an absolute time it would have to
        // invent.
        let ringing_secs = call.created_at.elapsed().as_secs();
        let talk_secs = call.answered_at.map(|at| at.elapsed().as_secs());

        // Per-branch outcome. The failure code lives in `BLegStatus::Failed`, so
        // a fork that lost 3 of 4 branches can say *why* each lost instead of
        // collapsing to a single winner.
        let branches: Vec<serde_json::Value> = real_b_legs
            .iter()
            .enumerate()
            .map(|(index, leg)| {
                let (status, code) = call
                    .b_leg_status
                    .get(index)
                    .map(branch_status)
                    .unwrap_or(("unknown", None));
                serde_json::json!({
                    "target": leg.dialog.target_uri.as_deref().map(display_party),
                    "status": status,
                    "code": code,
                    "transport": leg.transport.transport.label(),
                    "remote_addr": leg.transport.remote_addr.to_string(),
                    "winner": call.winner == Some(index),
                })
            })
            .collect();

        calls.push(serde_json::json!({
            "id": call.id,
            "call_id": call.a_leg.dialog.call_id,
            "state": state,
            "a_party": a_party,
            "b_party": b_party,
            "b_legs": real_b_legs.len(),
            // Direction: siphon placed this call itself rather than bridging an
            // inbound INVITE.
            "originated": call.originated,
            "ringing_secs": ringing_secs,
            "talk_secs": talk_secs,
            "a_transport": call.a_leg.transport.transport.label(),
            "a_remote_addr": call.a_leg.transport.remote_addr.to_string(),
            "branches": branches,
            // `null` rather than `false` where the feature is not in play, so the
            // dashboard can tell "not configured" from "configured and off".
            "control_app": call.control_app,
            "recording": call.li_record,
            "transfer": call.transfer.as_ref().map(|transfer| {
                serde_json::json!({
                    "state": transfer.state.to_string(),
                    "refer_to": transfer.refer_to.uri,
                    // Present only on an attended transfer (RFC 3891) — its
                    // absence is what distinguishes blind from attended.
                    "replaces_call_id": transfer.refer_to.replaces
                        .as_ref()
                        .map(|replaces| replaces.call_id.clone()),
                })
            }),
            "session_timer": session_timer_json(call),
            // Carrier attempts on an LCR/route-sequence call — which carrier was
            // tried, what it answered, and whether siphon actually dialled it.
            "route_attempts": route_attempts_json(call),
            // What this call is costing, from the winning carrier's rate. `null`
            // on an unrated call — a call with no LCR route, or one whose route
            // carried no rate — because a zero there would read as "free".
            "rating": call.active_route().map(|route| serde_json::json!({
                "carrier": route.carrier_id,
                "rate_per_minute": route.rate,
                "currency": route.currency,
                "billing_increment": route.billing_increment,
                "min_duration": route.min_duration,
                "billed_secs": talk_secs.map(|seconds| route.billed_seconds(seconds)),
                "cost": talk_secs.and_then(|seconds| route.cost_for(seconds)),
            })),
        }));
    }
    // Stable order for the dashboard (DashMap iteration order is arbitrary).
    calls.sort_by(|a, b| a["call_id"].as_str().cmp(&b["call_id"].as_str()));
    serde_json::Value::Array(calls)
}

/// Render one B-leg's status as `(name, code)`. The code is `Some` only for a
/// branch that actually received a final failure response.
fn branch_status(status: &crate::b2bua::actor::BLegStatus) -> (&'static str, Option<u16>) {
    use crate::b2bua::actor::BLegStatus;
    match status {
        BLegStatus::Trying => ("trying", None),
        BLegStatus::Ringing => ("ringing", None),
        BLegStatus::Answered => ("answered", None),
        BLegStatus::Failed(code) => ("failed", Some(*code)),
        BLegStatus::Cancelled => ("cancelled", None),
    }
}

/// The RFC 4028 session timer of each dialog of a call, `null` when neither runs
/// one. The caller's and the callee's dialogs negotiate theirs separately, so
/// each is reported on its own, `null` where it has none; `refresher` is
/// `"siphon"` or `"peer"`.
fn session_timer_json(call: &crate::b2bua::actor::CallActor) -> serde_json::Value {
    let dialog = |leg: Option<&crate::b2bua::actor::Leg>| {
        leg.and_then(|leg| leg.dialog.session_timer.as_ref())
            .map(|timer| {
                serde_json::json!({
                    "expires": timer.session_expires,
                    "refresher": if timer.siphon_refreshes { "siphon" } else { "peer" },
                    "last_refresh_secs": timer.last_refresh.elapsed().as_secs(),
                })
            })
    };
    let caller = dialog(Some(&call.a_leg));
    let callee = dialog(call.winner.and_then(|index| call.b_legs.get(index)));
    if caller.is_none() && callee.is_none() {
        return serde_json::Value::Null;
    }
    serde_json::json!({ "caller": caller, "callee": callee })
}

/// Per-carrier attempts for an LCR / route-sequence call, or `null` when this
/// call is not routed by a sequence at all — an empty array would read as "the
/// sequence tried nothing", which is a different thing.
fn route_attempts_json(call: &crate::b2bua::actor::CallActor) -> serde_json::Value {
    if !call.is_route_sequence() {
        return serde_json::Value::Null;
    }
    serde_json::Value::Array(
        call.route_attempts()
            .iter()
            .map(|attempt| {
                serde_json::json!({
                    "carrier": attempt.carrier_id,
                    "status": attempt.status,
                    "elapsed_ms": attempt.elapsed_ms,
                    // False means siphon never got the INVITE onto the wire, so
                    // `status` is siphon's own verdict and not the carrier's —
                    // without this a local DNS or gateway fault reads as a
                    // carrier fault.
                    "dialed": attempt.dialed,
                })
            })
            .collect::<Vec<_>>(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calls_json_empty_store_is_empty_array() {
        let store = crate::b2bua::actor::CallActorStore::new();
        assert_eq!(calls_json(&store), serde_json::json!([]));
    }

    /// The session timer of each dialog is reported on its own, since the
    /// caller's and the callee's negotiate separately; a dialog with none is
    /// `null`, and a call with none on either reports `null`.
    #[test]
    fn calls_json_reports_the_session_timer_of_each_dialog() {
        use crate::b2bua::actor::{CallActorStore, Leg, SessionTimerState, TransportInfo};
        use crate::transport::{ConnectionId, Transport};

        let transport = || TransportInfo {
            remote_addr: "192.0.2.10:5060".parse().unwrap(),
            connection_id: ConnectionId(1),
            transport: Transport::Udp,
            local_addr: None,
        };
        let store = CallActorStore::new();
        let id = store.create_call(Leg::new_a_leg(
            "timer@example.com".to_string(),
            "fromtag".to_string(),
            "z9hG4bKa".to_string(),
            transport(),
        ));
        assert!(calls_json(&store)[0]["session_timer"].is_null());

        store.add_b_leg(
            &id,
            Leg::new_b_leg(
                "timer-b@example.com".to_string(),
                "btag".to_string(),
                "sip:callee@198.51.100.20".to_string(),
                "z9hG4bKb".to_string(),
                transport(),
            ),
        );
        store.set_winner(&id, 0);
        let now = std::time::Instant::now();
        store.set_leg_session_timer(
            &id,
            false,
            Some(SessionTimerState::new(1800, true, 90, now)),
        );

        let timer = &calls_json(&store)[0]["session_timer"];
        assert!(timer["caller"].is_null());
        assert_eq!(timer["callee"]["expires"], 1800);
        assert_eq!(timer["callee"]["refresher"], "siphon");

        store.set_leg_session_timer(&id, true, Some(SessionTimerState::new(600, false, 90, now)));
        let timer = &calls_json(&store)[0]["session_timer"];
        assert_eq!(timer["caller"]["expires"], 600);
        assert_eq!(timer["caller"]["refresher"], "peer");
    }

    #[test]
    fn calls_json_serializes_active_calls() {
        use crate::b2bua::actor::{CallActorStore, Leg, TransportInfo};
        use crate::transport::{ConnectionId, Transport};

        let transport = || TransportInfo {
            remote_addr: "10.0.0.1:5060".parse().unwrap(),
            connection_id: ConnectionId(1),
            transport: Transport::Udp,
            local_addr: None,
        };

        let store = CallActorStore::new();
        let mut a_leg = Leg::new_a_leg(
            "call-abc@example.com".to_string(),
            "fromtag".to_string(),
            "z9hG4bKbranch".to_string(),
            transport(),
        );
        // The caller (INVITE From) is stored on the A-leg as remote_to_uri.
        a_leg.dialog.remote_to_uri = Some("\"Alice\" <sip:alice@example.com>;tag=abc".to_string());
        let id = store.create_call(a_leg);

        // A freshly created call: caller surfaced, no B-party yet, zero B-legs.
        let json = calls_json(&store);
        let calls = json.as_array().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0]["call_id"], "call-abc@example.com");
        assert_eq!(calls[0]["state"], "calling");
        assert_eq!(calls[0]["a_party"], "sip:alice@example.com");
        assert!(calls[0]["b_party"].is_null());
        assert_eq!(calls[0]["b_legs"], 0);

        // Dial a real B-leg, plus a re-INVITE response-tracking pseudo-leg.
        store.add_b_leg(
            &id,
            Leg::new_b_leg(
                "bleg-1@example.com".to_string(),
                "btag".to_string(),
                "sip:bob@10.0.0.2:5060".to_string(),
                "z9hG4bKb1".to_string(),
                transport(),
            ),
        );
        store.add_b_leg(
            &id,
            Leg::new_b_leg(
                "call-abc@example.com".to_string(),
                "btag2".to_string(),
                "reinvite:0".to_string(),
                "z9hG4bKb2".to_string(),
                transport(),
            ),
        );

        let json = calls_json(&store);
        let calls = json.as_array().unwrap();
        // The tracking pseudo-leg is excluded from both the callee and the count.
        assert_eq!(calls[0]["b_party"], "sip:bob@10.0.0.2:5060");
        assert_eq!(calls[0]["b_legs"], 1);
    }
}
