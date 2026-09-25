//! Naming the B-legs of a controller-issued `dial` on the control rail.
//!
//! Each branch a `dial` rings is its own SIP dialog, with a Call-ID siphon
//! generated, and nothing on the wire ties it back to the call the controller
//! owns. So the controller is told about every branch: `DialBranch` the moment
//! its INVITE is built (the later attempts of a sequential hunt included, which
//! the failover engine places over time), `DialBranchFailed` when it ends
//! without answering, and `DialAnswered` for the one that wins. `DialFailed`
//! lists them all with their outcomes.
//!
//! ## Field names
//!
//! Every event's envelope already carries `sip_call_id`: the channel's own, the
//! caller's A-leg. A branch's Call-ID in the payload is therefore
//! `leg_sip_call_id`, never a bare `sip_call_id` that would read as the
//! channel's. It follows `ChannelBridged`, which names the far side of a bridge
//! `peer_call_id` (siphon's own identity for it) and `peer_sip_call_id` (the
//! Call-ID on its wire): here the thing named is a leg, so the pair is `leg_id`,
//! the B-leg's stable identity in the call's actor (it survives a 401/407 or 422
//! retry of the leg), and `leg_sip_call_id`. A leg id is needed next to the
//! Call-ID because the Call-ID alone does not always tell branches apart: with
//! `preserve_call_id` every branch goes out on the caller's own.

use crate::b2bua::actor::{DialBranch, DialBranchCause, SettledDialBranches};
use crate::dispatcher::*;

/// The identity fields every branch event carries.
fn identity(branch: &DialBranch) -> serde_json::Map<String, serde_json::Value> {
    let mut fields = serde_json::Map::new();
    fields.insert("leg_id".into(), branch.leg_id.clone().into());
    fields.insert(
        "leg_sip_call_id".into(),
        branch.leg_sip_call_id.clone().into(),
    );
    fields.insert("target".into(), branch.target.clone().into());
    // Only when the branch was dialled for a registered AoR: a raw URI names
    // nobody, and an absent field says so without inventing one.
    if let Some(aor) = &branch.aor {
        fields.insert("aor".into(), aor.clone().into());
    }
    fields
}

/// A branch as `DialFailed` lists it: its identity and how it ended.
pub fn dial_branch_summary(branch: &DialBranch) -> serde_json::Value {
    let mut fields = identity(branch);
    if let Some(outcome) = &branch.outcome {
        fields.insert("code".into(), outcome.code.into());
        fields.insert("reason".into(), outcome.reason.clone().into());
        fields.insert("cause".into(), outcome.cause.as_str().into());
    }
    serde_json::Value::Object(fields)
}

fn publish_settled(settled: Option<SettledDialBranches>) {
    let Some((sip_call_id, branches)) = settled else {
        return;
    };
    for branch in &branches {
        let Some(outcome) = &branch.outcome else {
            continue;
        };
        let event = match outcome.cause {
            DialBranchCause::Answered => {
                let mut fields = identity(branch);
                fields.insert("code".into(), outcome.code.into());
                ("DialAnswered", serde_json::Value::Object(fields))
            }
            _ => ("DialBranchFailed", dial_branch_summary(branch)),
        };
        control_notify_channel_event(&sip_call_id, event.0, event.1);
    }
}

/// A B-leg INVITE was built for `call_id`: name it as a branch when a
/// controller-issued `dial` is awaiting its outcome. Called from
/// [`b2bua_send_b_leg_invite`], which every branch goes through (each fork
/// target and each attempt of a sequential hunt), before the INVITE is sent so
/// the branch is named before anything it answers can be reported.
pub fn control_dial_branch_created(
    call_id: &str,
    leg: &Leg,
    target: &str,
    state: &DispatcherState,
) {
    if let Some((sip_call_id, branch)) = state.call_actors.record_dial_branch(call_id, leg, target)
    {
        control_notify_channel_event(
            &sip_call_id,
            "DialBranch",
            serde_json::Value::Object(identity(&branch)),
        );
    }
}

/// The B-leg whose INVITE rides Via `via_branch` ended on `code`.
pub fn control_dial_branch_ended(
    call_id: &str,
    via_branch: &str,
    code: u16,
    reason: &str,
    cause: DialBranchCause,
    state: &DispatcherState,
) {
    publish_settled(
        state
            .call_actors
            .settle_dial_branch_by_via(call_id, via_branch, code, reason, cause),
    );
}

/// siphon CANCELled `legs`. Each is reported once: a branch already settled (the
/// timeout that cancelled it, say) keeps the outcome it was reported with.
pub fn control_dial_legs_cancelled(call_id: &str, legs: &[Leg], state: &DispatcherState) {
    if legs.is_empty() {
        return;
    }
    publish_settled(state.call_actors.settle_dial_branch_legs(
        call_id,
        legs,
        487,
        "Request Terminated",
        DialBranchCause::Cancelled,
    ));
}

/// Every branch of the dial still ringing ended on `code`.
pub fn control_dial_open_branches_ended(
    call_id: &str,
    code: u16,
    reason: &str,
    cause: DialBranchCause,
    state: &DispatcherState,
) {
    publish_settled(
        state
            .call_actors
            .settle_open_dial_branches(call_id, code, reason, cause),
    );
}

/// The dial is over without an answer: every branch it rang, each with its
/// outcome, for `DialFailed`. Any branch still open is reported as cancelled
/// first, so a branch the controller was told of never goes without an outcome.
pub fn control_dial_branches_for_failure(
    call_id: &str,
    state: &DispatcherState,
) -> Vec<serde_json::Value> {
    control_dial_open_branches_ended(
        call_id,
        487,
        "Request Terminated",
        DialBranchCause::Cancelled,
        state,
    );
    state
        .call_actors
        .take_dial_branches(call_id)
        .iter()
        .map(dial_branch_summary)
        .collect()
}

/// Resolve an AoR to one dial target per registered contact, each carrying its
/// own flow and Path route set.
///
/// This is what makes a phone on TCP, TLS or WSS reachable: such a contact is
/// only reachable over the connection it registered on, so DNS-resolving its
/// Contact URI (what `originate` does with a bare URI) reaches nothing. Mirrors
/// what a script gets from `call.fork(registrar.lookup(aor))`.
pub fn dial_targets_for_aor(aor: &str) -> Result<Vec<DialTarget>, DialError> {
    let Some(registrar) = crate::script::api::registrar_arc() else {
        return Err(DialError::NoContacts(aor.to_string()));
    };
    let contacts = registrar.lookup(aor);
    if contacts.is_empty() {
        return Err(DialError::NoContacts(aor.to_string()));
    }
    // The key the bindings are stored under, which is what a watcher of the
    // AoR subscribed to, however the controller spelled it.
    let registered = registrar
        .registered_aor(aor)
        .unwrap_or_else(|| crate::registrar::normalize_aor(aor));
    Ok(contacts
        .into_iter()
        .map(|contact| {
            // Each branch carries the route set of its *own* binding (RFC 3327
            // §5.3); a shared one would put every branch through the first
            // binding's proxy chain.
            let path: Vec<String> = contact.path.iter().map(|value| value.to_string()).collect();
            let route = crate::proxy::core::route_set_from_path(&path)
                .map(|value| vec![value])
                .unwrap_or_default();
            // The captured inbound flow, same view the scripting API hands to
            // `call.fork` — `None` for a binding whose socket has gone, which
            // then falls back to resolving the Contact URI.
            let flow = contact
                .flow()
                .map(|flow| crate::script::api::registrar::PyFlow {
                    transport: flow.transport.as_scheme().to_string(),
                    source_addr: flow.source_addr,
                    local_addr: flow.local_addr,
                    connection_id: flow.connection_id,
                });
            DialTarget {
                uri: contact.uri.to_string(),
                next_hop: None,
                flow,
                route,
                headers: std::collections::HashMap::new(),
                aor: Some(registered.clone()),
                ..Default::default()
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::b2bua::actor::DialBranchOutcome;

    fn branch(outcome: Option<DialBranchOutcome>) -> DialBranch {
        DialBranch {
            leg_id: "leg-1".to_string(),
            leg_sip_call_id: "b-leg-1@siphon".to_string(),
            target: "sip:15550100077@198.51.100.7".to_string(),
            aor: None,
            outcome,
        }
    }

    #[test]
    fn a_settled_branch_summary_carries_identity_and_outcome() {
        let summary = dial_branch_summary(&branch(Some(DialBranchOutcome::new(
            486,
            "Busy Here",
            DialBranchCause::Rejected,
        ))));
        assert_eq!(
            summary,
            serde_json::json!({
                "leg_id": "leg-1",
                "leg_sip_call_id": "b-leg-1@siphon",
                "target": "sip:15550100077@198.51.100.7",
                "code": 486,
                "reason": "Busy Here",
                "cause": "rejected",
            })
        );
    }

    /// A branch dialled for a registered AoR names it in every event.
    #[test]
    fn a_branch_dialled_for_an_aor_names_it() {
        let mut named = branch(None);
        named.aor = Some("sip:201@example.com".to_string());
        assert_eq!(dial_branch_summary(&named)["aor"], "sip:201@example.com");
        assert!(
            dial_branch_summary(&branch(None)).get("aor").is_none(),
            "a raw URI names no AoR"
        );
    }

    #[test]
    fn an_open_branch_summary_carries_only_its_identity() {
        assert_eq!(
            dial_branch_summary(&branch(None)),
            serde_json::json!({
                "leg_id": "leg-1",
                "leg_sip_call_id": "b-leg-1@siphon",
                "target": "sip:15550100077@198.51.100.7",
            })
        );
    }
}
