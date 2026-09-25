//! The proxy's half of `DialogStateChanged`: hooks on the relay, response,
//! CANCEL and in-dialog paths that feed [`ProxyDialogStore`], the liveness
//! sweep and its in-dialog OPTIONS probes.
//!
//! Every hook asks [`dialog_state_wanted`] or the store's emptiness first, so a
//! deployment with no `dialog` subscriber pays one atomic load per INVITE and
//! nothing per other message.
//!
//! A tracked INVITE is Record-Routed by siphon itself (RFC 3261 §16.6 step 4:
//! a proxy that wishes to remain on the path of future requests in the dialog
//! adds a Record-Route), whether or not the script asked for it. §12.2 obliges
//! both UAs to send their in-dialog requests along the route set, which is what
//! brings the BYE — from either end — back through siphon. The entry siphon adds
//! on its own is marked ([`OWN_RECORD_ROUTE_PARAM`]) and the in-dialog requests
//! that follow it are routed by siphon without the script, which never asked to
//! see them.

use std::time::{Duration, Instant};

use crate::b2bua::actor::{publish_dialog_states, DialogDirection, DialogState, DialogWatch};
use crate::dispatcher::*;
use crate::proxy::dialog_state::{
    session_expires_secs, Answer, DialogKey, Hop, NewBranch, NewDialog, Probe, ProbeOutcome,
};
use crate::sip::headers::nameaddr::NameAddr;

/// The URI parameter siphon puts on a Record-Route it added on its own for a
/// tracked dialog — one the script did not ask for. An in-dialog request whose
/// topmost Route is siphon's and carries it is routed by siphon along the route
/// set without running the script: a script that never Record-Routes was never
/// written to route in-dialog requests, and still does not have to.
pub(super) const OWN_RECORD_ROUTE_PARAM: &str = "dlgw";

/// A Record-Route URI siphon adds on its own, marked as such.
pub(super) fn own_record_route(uri: String) -> String {
    format!("{uri};{OWN_RECORD_ROUTE_PARAM}")
}

/// Whether `message` is an in-dialog request whose topmost Route is one siphon
/// Record-Routed on its own ([`OWN_RECORD_ROUTE_PARAM`]).
pub(super) fn follows_own_record_route(message: &SipMessage, state: &DispatcherState) -> bool {
    if !to_has_tag(message) || !core::top_route_is_local(&message.headers, &state.self_identity) {
        return false;
    }
    message
        .headers
        .get("Route")
        .and_then(|raw| crate::sip::headers::route::RouteEntry::parse_multi(raw).ok())
        .and_then(|entries| entries.into_iter().next())
        .is_some_and(|entry| {
            entry
                .uri
                .params
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case(OWN_RECORD_ROUTE_PARAM))
        })
}

fn registrar() -> Option<&'static Arc<crate::registrar::Registrar>> {
    crate::script::api::registrar_arc()
}

fn tag_of(value: &str) -> Option<String> {
    value
        .split(';')
        .find_map(|parameter| parameter.trim().strip_prefix("tag="))
        .map(str::to_string)
}

fn untagged(value: &str) -> String {
    value
        .split(';')
        .filter(|parameter| !parameter.trim().starts_with("tag="))
        .collect::<Vec<_>>()
        .join(";")
}

fn identity_of(header: &str) -> (String, Option<String>) {
    match NameAddr::parse(header) {
        Ok(name_addr) => (name_addr.uri.to_string(), name_addr.display_name),
        Err(_) => (
            crate::b2bua::actor::extract_contact_uri(header)
                .split(';')
                .next()
                .unwrap_or_default()
                .to_string(),
            None,
        ),
    }
}

fn cseq_of(message: &SipMessage) -> Option<(u32, String)> {
    let cseq = message.headers.cseq()?;
    let mut parts = cseq.split_whitespace();
    let number = parts.next()?.parse().ok()?;
    Some((number, parts.next().unwrap_or_default().to_string()))
}

fn contact_of(message: &SipMessage) -> Option<String> {
    message
        .headers
        .get("Contact")
        .or_else(|| message.headers.get("m"))
        .map(|contact| crate::b2bua::actor::extract_contact_uri(contact))
}

/// `(Call-ID, From-tag)` of an out-of-dialog INVITE, else `None`.
fn invite_dialog_key(message: &SipMessage) -> Option<DialogKey> {
    if message.method() != Some(&Method::Invite) || to_has_tag(message) {
        return None;
    }
    let call_id = message.headers.call_id()?.to_string();
    let from_tag = tag_of(message.headers.from()?)?;
    Some((call_id, from_tag))
}

/// The caller's side of an INVITE, as [`NewDialog`] records it.
fn new_dialog(
    message: &SipMessage,
    key: &DialogKey,
    inbound: &InboundMessage,
    caller: Option<DialogWatch>,
) -> NewDialog {
    NewDialog {
        call_id: key.0.clone(),
        caller_tag: key.1.clone(),
        caller,
        caller_hop: Hop {
            destination: inbound.remote_addr,
            transport: inbound.transport,
            connection_id: inbound.connection_id,
            local_addr: Some(inbound.local_addr),
        },
        caller_contact: contact_of(message),
        from: message.headers.from().cloned().unwrap_or_default(),
        to: untagged(message.headers.to().map(String::as_str).unwrap_or_default()),
        invite_cseq: cseq_of(message).map(|(number, _)| number).unwrap_or(1),
        route_to_caller: message
            .headers
            .get_all("Record-Route")
            .map(|values| flatten_record_route_headers(values))
            .unwrap_or_default(),
    }
}

/// A registered phone placing an INVITE the script is about to relay: start
/// tracking its dialog. Called with the identity the script authenticated.
pub(super) fn proxy_dialog_begin(
    message: &SipMessage,
    auth_user: Option<&str>,
    inbound: &InboundMessage,
    state: &DispatcherState,
) {
    if !dialog_state_wanted() {
        return;
    }
    let (Some(key), Some(registrar)) = (invite_dialog_key(message), registrar()) else {
        return;
    };
    let Some(from) = message.headers.from() else {
        return;
    };
    let from_aor = crate::registrar::normalize_aor(&identity_of(from).0);
    let Some((aor, contact)) =
        registrar.binding_placing_request(&from_aor, auth_user, inbound.remote_addr)
    else {
        return;
    };
    let (remote_uri, remote_display_name) =
        identity_of(message.headers.to().map(String::as_str).unwrap_or_default());
    let caller = DialogWatch {
        // The caller's own Via branch: unique for the INVITE, and stable.
        leg_id: format!(
            "proxy-{}",
            message
                .headers
                .get("Via")
                .and_then(|raw| Via::parse_multi(raw).ok())
                .and_then(|vias| vias.into_iter().next())
                .and_then(|via| via.branch)
                .unwrap_or_else(|| key.1.clone())
        ),
        aor,
        direction: DialogDirection::Initiator,
        call_id: key.0.clone(),
        local_tag: Some(key.1.clone()),
        remote_tag: None,
        remote_uri,
        remote_display_name,
        // Every relayed INVITE was answered with a 100 on arrival (§16.2).
        state: DialogState::Proceeding,
        contact: Some(contact),
    };
    let dialog = new_dialog(message, &key, inbound, Some(caller));
    publish_dialog_states(state.proxy_dialogs.begin(dialog, Instant::now()));
}

/// Once the script's relay or fork has run: an INVITE that went out on no
/// branch at all (an unresolvable target, a loop) is over for the caller.
pub(super) fn proxy_dialog_after_relay(message: &SipMessage, state: &DispatcherState) {
    if state.proxy_dialogs.is_empty() {
        return;
    }
    if let Some(key) = invite_dialog_key(message) {
        if state.proxy_dialogs.has_no_branch(&key) {
            publish_dialog_states(state.proxy_dialogs.end_invite(&key));
        }
    }
}

/// A branch about to be tracked, decided before its Record-Route is added.
pub(super) struct PendingBranch {
    key: DialogKey,
    via_branch: String,
    watch: Option<DialogWatch>,
}

/// Decide whether the branch of `message` relayed to `target_uri` (over
/// `flow`, or to `next_hop`) is tracked: when its INVITE's dialog already is
/// (the caller is a registered phone, or an earlier branch rang one), or this
/// branch rings a registered phone. A tracked branch is Record-Routed.
pub(super) fn proxy_dialog_branch(
    message: &SipMessage,
    target_uri: &str,
    flow: Option<&crate::script::api::registrar::PyFlow>,
    next_hop: Option<&str>,
    via_branch: &str,
    state: &DispatcherState,
) -> Option<PendingBranch> {
    if !dialog_state_wanted() {
        return None;
    }
    let key = invite_dialog_key(message)?;
    let binding = registrar().and_then(|registrar| {
        match flow {
            // Over a captured flow the Request-URI need not be the Contact: the
            // flow names the binding.
            Some(flow) => registrar.binding_for_source(flow.source_addr),
            None => registrar.binding_for_contact(target_uri),
        }
        .or_else(|| next_hop.and_then(|hop| registrar.binding_for_contact(hop)))
    });
    if binding.is_none() && !state.proxy_dialogs.contains(&key) {
        return None;
    }
    let watch = binding.map(|(aor, contact)| {
        let (remote_uri, remote_display_name) = identity_of(
            message
                .headers
                .from()
                .map(String::as_str)
                .unwrap_or_default(),
        );
        DialogWatch {
            leg_id: format!("proxy-{via_branch}"),
            aor,
            direction: DialogDirection::Recipient,
            call_id: key.0.clone(),
            // The phone's tag arrives with its first tagged response; the far
            // end is the caller.
            local_tag: None,
            remote_tag: Some(key.1.clone()),
            remote_uri,
            remote_display_name,
            state: DialogState::Trying,
            contact: Some(contact),
        }
    });
    Some(PendingBranch {
        key,
        via_branch: via_branch.to_string(),
        watch,
    })
}

impl PendingBranch {
    /// Record the branch once its INVITE is built: `hop` is where it goes,
    /// `own_record_routes` how many Record-Route entries siphon put on it.
    pub(super) fn register(
        self,
        message: &SipMessage,
        inbound: &InboundMessage,
        hop: Hop,
        own_record_routes: usize,
        state: &DispatcherState,
    ) {
        if !state.proxy_dialogs.contains(&self.key) {
            // The caller is not a registered phone; this branch rings one.
            state.proxy_dialogs.begin(
                new_dialog(message, &self.key, inbound, None),
                Instant::now(),
            );
        }
        publish_dialog_states(state.proxy_dialogs.add_branch(
            &self.key,
            NewBranch {
                via_branch: self.via_branch,
                watch: self.watch,
                hop,
                own_record_routes,
            },
        ));
    }
}

/// Runs [`ProxyDialogStore::settle`] when the response handling that created it
/// returns, whichever way it returns: by then a failure retarget has added its
/// branches, and a suppressed or answered failure has not.
pub(super) struct SettleOnDrop<'a> {
    key: DialogKey,
    state: &'a DispatcherState,
}

impl Drop for SettleOnDrop<'_> {
    fn drop(&mut self) {
        publish_dialog_states(self.state.proxy_dialogs.settle(&self.key));
    }
}

/// A response arrived on the proxy path. A response to a tracked branch's
/// INVITE moves the callee's state; a 2xx to an in-dialog re-INVITE or UPDATE
/// refreshes the session interval. Returns the guard that settles the
/// caller's side once a final response has been handled.
pub(super) fn proxy_dialog_observe_response<'a>(
    message: &SipMessage,
    status_code: u16,
    state: &'a DispatcherState,
) -> Option<SettleOnDrop<'a>> {
    if state.proxy_dialogs.is_empty() {
        return None;
    }
    let (_, method) = cseq_of(message)?;
    let to_tag = message.headers.to().and_then(|to| tag_of(to));
    let via_branch = message
        .headers
        .get("Via")
        .and_then(|raw| Via::parse_multi(raw).ok())
        .and_then(|vias| vias.into_iter().next())
        .and_then(|via| via.branch)?;
    if method.eq_ignore_ascii_case("INVITE") {
        if let Some(key) = state.proxy_dialogs.key_of_branch(&via_branch) {
            let answer = (200..300).contains(&status_code).then(|| Answer {
                contact: contact_of(message),
                record_routes: message
                    .headers
                    .get_all("Record-Route")
                    .map(|values| flatten_record_route_headers(values))
                    .unwrap_or_default(),
                session_expires: message
                    .headers
                    .get("Session-Expires")
                    .or_else(|| message.headers.get("x"))
                    .and_then(|value| session_expires_secs(value)),
            });
            publish_dialog_states(state.proxy_dialogs.branch_response(
                &via_branch,
                status_code,
                to_tag.as_deref(),
                answer,
                Instant::now(),
                &state.dialog_state_config,
            ));
            return (status_code >= 200).then_some(SettleOnDrop { key, state });
        }
    }
    let refresh = method.eq_ignore_ascii_case("INVITE") || method.eq_ignore_ascii_case("UPDATE");
    if refresh && (200..300).contains(&status_code) {
        if let (Some(call_id), Some(from_tag), Some(to_tag)) = (
            message.headers.call_id(),
            message.headers.from().and_then(|from| tag_of(from)),
            to_tag,
        ) {
            state.proxy_dialogs.in_dialog_refreshed(
                call_id,
                &from_tag,
                &to_tag,
                message
                    .headers
                    .get("Session-Expires")
                    .or_else(|| message.headers.get("x"))
                    .and_then(|value| session_expires_secs(value)),
                Instant::now(),
            );
        }
    }
    None
}

/// siphon sent the caller `message`, a response to its INVITE.
pub(super) fn proxy_dialog_upstream(
    message: &SipMessage,
    status_code: u16,
    state: &DispatcherState,
) {
    if state.proxy_dialogs.is_empty() {
        return;
    }
    let Some((_, method)) = cseq_of(message) else {
        return;
    };
    if !method.eq_ignore_ascii_case("INVITE") {
        return;
    }
    let (Some(call_id), Some(from_tag)) = (
        message.headers.call_id(),
        message.headers.from().and_then(|from| tag_of(from)),
    ) else {
        return;
    };
    let to_tag = message.headers.to().and_then(|to| tag_of(to));
    publish_dialog_states(state.proxy_dialogs.upstream_response(
        &(call_id.to_string(), from_tag),
        status_code,
        to_tag.as_deref(),
    ));
}

/// The caller CANCELled `invite`, or a reply-time reject failed it: its dialog
/// is over for everyone before an answer.
pub(super) fn proxy_dialog_invite_abandoned(invite: &SipMessage, state: &DispatcherState) {
    if state.proxy_dialogs.is_empty() {
        return;
    }
    if let Some(key) = invite_dialog_key(invite) {
        publish_dialog_states(state.proxy_dialogs.end_invite(&key));
    }
}

/// siphon CANCELled the branches of `invite` other than `keep` (the branch that
/// answered or sent the 6xx), or all of them.
pub(super) fn proxy_dialog_branches_cancelled(
    invite: &SipMessage,
    keep: Option<&str>,
    state: &DispatcherState,
) {
    if state.proxy_dialogs.is_empty() {
        return;
    }
    if let Some(key) = invite_dialog_key(invite) {
        publish_dialog_states(state.proxy_dialogs.branches_cancelled(&key, keep));
    }
}

/// An in-dialog request reached the proxy. A BYE ends a tracked dialog for both
/// ends — here, before the script runs, so a BYE the script answers itself ends
/// it too.
pub(super) fn proxy_dialog_in_dialog_request(
    message: &SipMessage,
    method: &str,
    state: &DispatcherState,
) {
    if state.proxy_dialogs.is_empty() {
        return;
    }
    let (Some(call_id), Some(from_tag), Some(to_tag)) = (
        message.headers.call_id(),
        message.headers.from().and_then(|from| tag_of(from)),
        message.headers.to().and_then(|to| tag_of(to)),
    ) else {
        return;
    };
    publish_dialog_states(state.proxy_dialogs.in_dialog_request(
        call_id,
        &from_tag,
        &to_tag,
        method,
        cseq_of(message).map(|(number, _)| number),
        contact_of(message),
    ));
}

/// The liveness pass for every dialog state reported, at `now`: the proxied
/// dialogs' checks and probes, and the binding check for B2BUA legs.
pub(super) fn dialog_state_sweep_at(state: &DispatcherState, now: Instant) {
    if !dialog_state_wanted() && state.proxy_dialogs.is_empty() {
        return;
    }
    // `map_or(true, …)` not `is_none_or`: MSRV 1.80.
    #[allow(clippy::unnecessary_map_or)]
    let live = |aor: &str, contact: &str| {
        registrar().map_or(true, |registrar| registrar.has_live_contact(aor, contact))
    };
    let (reports, probes) = state
        .proxy_dialogs
        .sweep(now, &state.dialog_state_config, &live);
    publish_dialog_states(reports);
    state.call_actors.end_dialogs_without_binding(&live);
    for probe in probes {
        send_probe(probe, state);
    }
}

/// The in-dialog OPTIONS for `probe`, as the other end would send it.
fn probe_request(probe: &Probe, state: &DispatcherState) -> Option<(SipMessage, String)> {
    let transport = probe.hop.transport;
    let (host, port) = match probe.hop.local_addr {
        Some(local) => pinned_sent_by(local, || state.via_host(&transport)),
        None => (state.via_host(&transport), state.via_port(&transport)),
    };
    let branch = format!("z9hG4bK-uac-{}", uuid::Uuid::new_v4().simple());
    let mut raw = format!(
        concat!(
            "OPTIONS {ruri} SIP/2.0\r\n",
            "Via: SIP/2.0/{transport} {host}:{port};branch={branch}\r\n",
            "Max-Forwards: 70\r\n",
        ),
        ruri = probe.request_uri,
        transport = format!("{transport}").to_uppercase(),
        host = host,
        port = port,
        branch = branch,
    );
    for route in &probe.route {
        raw.push_str(&format!("Route: {route}\r\n"));
    }
    raw.push_str(&format!(
        concat!(
            "From: {from}\r\n",
            "To: {to}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: {cseq} OPTIONS\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        from = probe.from,
        to = probe.to,
        call_id = probe.call_id,
        cseq = probe.cseq,
    ));
    match parse_sip_message_bytes(raw.as_bytes()) {
        Ok(message) => Some((message, branch)),
        Err(error) => {
            warn!(call_id = %probe.call_id, %error, "dialog probe: could not build the OPTIONS");
            None
        }
    }
}

/// Send `probe` and settle it when its response (or the timeout) comes.
fn send_probe(probe: Probe, state: &DispatcherState) {
    let config = state.dialog_state_config.clone();
    let store = Arc::clone(&state.proxy_dialogs);
    let Some((request, branch)) = probe_request(&probe, state) else {
        publish_dialog_states(store.probe_result(
            &probe.key,
            probe.end,
            ProbeOutcome::Alive,
            &config,
        ));
        return;
    };
    let receiver = state.uac_sender.send_request_with_response_on(
        request,
        probe.hop.destination,
        probe.hop.transport,
        probe.hop.connection_id,
        probe.hop.local_addr,
    );
    let uac_sender = Arc::clone(&state.uac_sender);
    let timeout = Duration::from_secs(config.probe_timeout_secs.max(1));
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        warn!("dialog probe: no runtime to await the response on");
        return;
    };
    runtime.spawn(async move {
        let outcome = match tokio::time::timeout(timeout, receiver).await {
            Ok(Ok(crate::uac::UacResult::Response(response))) => {
                probe_outcome(response.status_code().unwrap_or(0))
            }
            _ => {
                uac_sender.expire_branch(&branch);
                ProbeOutcome::Unanswered
            }
        };
        debug!(
            call_id = %probe.call_id,
            end = ?probe.end,
            ?outcome,
            "dialog probe settled"
        );
        publish_dialog_states(store.probe_result(&probe.key, probe.end, outcome, &config));
    });
}

/// What a probe response says about the dialog at the end that sent it.
fn probe_outcome(status_code: u16) -> ProbeOutcome {
    match status_code {
        481 => ProbeOutcome::Gone,
        408 => ProbeOutcome::Unanswered,
        _ => ProbeOutcome::Alive,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_responses_map_to_outcomes() {
        assert_eq!(probe_outcome(200), ProbeOutcome::Alive);
        assert_eq!(probe_outcome(405), ProbeOutcome::Alive);
        assert_eq!(probe_outcome(500), ProbeOutcome::Alive);
        assert_eq!(probe_outcome(481), ProbeOutcome::Gone);
        assert_eq!(probe_outcome(408), ProbeOutcome::Unanswered);
    }

    #[test]
    fn tags_are_read_and_stripped() {
        assert_eq!(
            tag_of("<sip:a@example.com>;tag=abc").as_deref(),
            Some("abc")
        );
        assert_eq!(
            untagged("<sip:a@example.com>;tag=abc"),
            "<sip:a@example.com>"
        );
    }
}
