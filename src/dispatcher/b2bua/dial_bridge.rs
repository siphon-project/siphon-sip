//! Ringing phones for a caller siphon has already answered, and joining the
//! caller to the one that picks up — the dispatcher's half of the control
//! plane's `dial {on_answer: "bridge"}`.
//!
//! The flow an IVR ends in: the caller is answered and anchored on the media
//! engine, has heard its prompts, and is now to be put through to whichever
//! phone answers first. `dial`'s own B-leg machinery assumes a caller that is
//! still ringing, so it is not used at all. Each phone is instead rung as a call
//! siphon places itself, through an originate group
//! ([`create_originate_group`]); the phone that answers becomes an ordinary
//! answered call and is bridged to the caller with [`bridge_calls_with_state`],
//! exactly as the `bridge` verb would.
//!
//! This module holds the state that ties the two together and the hooks the
//! rest of the dispatcher calls into:
//!
//! * which caller has a group ringing, so a caller that hangs up has its phones
//!   CANCELled (RFC 3261 §9.1) and a second bridge dial is refused;
//! * which answered phone is waiting on its bridge, so a bridge that fails
//!   releases the phone rather than leaving it up with nobody on it;
//! * which playback on the caller is the ringback, so its `PlayFinished` is
//!   labelled and a ringback held back behind a prompt starts when it ends.
//!
//! Every entry goes on every way it can end: the dial concluding (a winner, a
//! failure), the bridge settling, the ringback's end event, and the caller's or
//! the phone's own teardown ([`dial_bridge_call_ended`]).
//!
//! The coordinator that runs one dial — the ringback, the bridge and the events
//! — lives with the control adapter, which owns the channel it reports on; it
//! is driven by the [`DialBridgeSignal`]s this module and the group's sink send
//! it.

use crate::dispatcher::*;

/// `origin` on the `PlayStarted` / `PlayFinished` of a bridge dial's ringback,
/// so a controller can tell it from a playback of its own.
pub const DIAL_RINGBACK_ORIGIN: &str = "ringback";

/// The reason a bridge dial's group is cancelled with when its caller goes
/// away: the one failure the coordinator does not act on, since there is no
/// caller left to stop the ringback on or to report to afterwards.
pub const DIAL_BRIDGE_CALLER_GONE: &str = "caller_hangup";

/// The `Reason` a phone that answered is released with when the bridge to its
/// caller failed (RFC 3326; Q.850 41, temporary failure).
const BRIDGE_FAILED_REASON: &str = q850_reason!(41, "bridge to the caller failed");

/// A dispatcher a spawned task can reach for as long as it runs: the process's
/// running B2BUA in production, a test's own dispatcher in a test.
pub trait DispatcherHandle: Send + Sync {
    /// The dispatcher's state, `None` once it is gone.
    fn state(&self) -> Option<&DispatcherState>;
    /// The runtime its tasks run on, `None` once it is gone.
    fn runtime(&self) -> Option<tokio::runtime::Handle>;
}

/// The running B2BUA, through its process-wide handle.
pub struct RunningDispatcher;

impl DispatcherHandle for RunningDispatcher {
    fn state(&self) -> Option<&DispatcherState> {
        B2BUA_CONTROL.get().map(|control| control.state.as_ref())
    }

    fn runtime(&self) -> Option<tokio::runtime::Handle> {
        B2BUA_CONTROL.get().map(|control| control.runtime.clone())
    }
}

/// What a bridge dial's coordinator is told, in the order it happened.
#[derive(Debug)]
pub enum DialBridgeSignal {
    /// A phone is alerting (a `180`-`183` from any leg): time for ringback.
    Alerting,
    /// A playback on the caller ended, so a ringback held back behind it may
    /// start.
    PromptFinished,
    /// A phone answered, provisionally: it is ACKed and anchored, and the
    /// other phones keep ringing until it is bridged.
    Answered(OriginateGroupWinner),
    /// The bridge to this phone failed after it was put in motion: the phone
    /// is already hung up and its answer refused, so the dial goes on.
    BridgeFailed(OriginateGroupWinner),
    /// The bridge formed: the dial is over.
    Bridged,
    /// Nobody answered, or no answer could be bridged.
    Failed(OriginateGroupFailure),
}

/// Where a bridge dial's signals go.
pub type DialBridgeSender = tokio::sync::mpsc::UnboundedSender<DialBridgeSignal>;

/// Told, synchronously, that a bridge dial's phone is bridged to its caller —
/// before the bridge's own `ChannelBridged` goes out, so a channel minted for
/// the phone here receives it.
pub trait DialBridgeListener: Send + Sync {
    fn bridged(&self, winner: &OriginateGroupWinner);
}

/// A phone whose bridge to its caller is in motion.
struct PendingBridge {
    /// The caller's SIP Call-ID.
    caller: String,
    winner: OriginateGroupWinner,
    signals: DialBridgeSender,
    listener: Arc<dyn DialBridgeListener>,
}

/// A caller with a group ringing for it.
struct RingingDial {
    /// The group, once it is created.
    group_id: Option<String>,
    signals: DialBridgeSender,
    /// The caller's media session, which a finished prompt is matched on.
    media_call_id: String,
    from_tag: String,
}

/// A ringback playing on a caller, until the engine reports its end.
struct RingbackPlay {
    media_call_id: String,
    from_tag: String,
    play_id: u64,
}

/// Every bridge dial in flight. Keyed by the caller's SIP Call-ID, except the
/// bridges, which are keyed by the answered phone's `CallActor` id.
#[derive(Default)]
pub struct DialBridgeStore {
    ringing: DashMap<String, RingingDial>,
    /// Answered phone → its bridge, from the moment the bridge is put in
    /// motion until it settles.
    bridging: DashMap<String, PendingBridge>,
    ringback: DashMap<String, RingbackPlay>,
}

impl std::fmt::Debug for DialBridgeStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DialBridgeStore")
            .field("ringing", &self.ringing.len())
            .field("bridging", &self.bridging.len())
            .field("ringback", &self.ringback.len())
            .finish()
    }
}

impl DialBridgeStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Callers with a group ringing. Drains with the dials — the leak gate.
    #[cfg(test)]
    pub fn ringing_count(&self) -> usize {
        self.ringing.len()
    }

    /// Answered phones waiting on their bridge.
    #[cfg(test)]
    pub fn bridging_count(&self) -> usize {
        self.bridging.len()
    }

    /// Ringbacks whose end has not been reported.
    #[cfg(test)]
    pub fn ringback_count(&self) -> usize {
        self.ringback.len()
    }

    /// Whether `caller` has a dial ringing for it.
    pub fn is_ringing(&self, caller: &str) -> bool {
        self.ringing.contains_key(caller)
    }

    /// The group ringing for `caller`, once created.
    pub fn group_of(&self, caller: &str) -> Option<String> {
        self.ringing.get(caller)?.group_id.clone()
    }

    /// Take `caller` for a new dial. `false` when it already has one.
    fn claim(&self, caller: &str, dial: RingingDial) -> bool {
        match self.ringing.entry(caller.to_string()) {
            dashmap::mapref::entry::Entry::Occupied(_) => false,
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                vacant.insert(dial);
                true
            }
        }
    }

    /// Record the group ringing for `caller`. `false` when the caller went
    /// away since it was claimed.
    fn set_group(&self, caller: &str, group_id: &str) -> bool {
        match self.ringing.get_mut(caller) {
            Some(mut dial) => {
                dial.group_id = Some(group_id.to_string());
                true
            }
            None => false,
        }
    }

    /// `caller`'s dial is over.
    pub fn release(&self, caller: &str) {
        self.ringing.remove(caller);
    }

    /// A ringback started on `caller`. Only an engine that names its playbacks
    /// reports their end, so only a ringback with a `play_id` is recorded — a
    /// record nothing would ever clear is a leak.
    pub fn record_ringback(&self, caller: &str, media_call_id: &str, from_tag: &str, play_id: u64) {
        self.ringback.insert(
            caller.to_string(),
            RingbackPlay {
                media_call_id: media_call_id.to_string(),
                from_tag: from_tag.to_string(),
                play_id,
            },
        );
    }

    /// Playback `play_id` on a leg ended: drop it when it was a ringback, and
    /// say whether it was.
    fn take_ringback(&self, media_call_id: &str, from_tag: &str, play_id: u64) -> bool {
        let mut matched = false;
        self.ringback.retain(|_, ringback| {
            let this = ringback.play_id == play_id
                && ringback.media_call_id == media_call_id
                && ringback.from_tag == from_tag;
            matched |= this;
            !this
        });
        matched
    }

    /// A phone's bridge is about to be put in motion.
    fn await_bridge(&self, pending: PendingBridge) {
        self.bridging
            .insert(pending.winner.internal_call_id.clone(), pending);
    }

    /// The bridge of the phone `winner` never got going; nothing waits on it.
    fn forget_bridge(&self, winner: &str) {
        self.bridging.remove(winner);
    }
}

/// An answered, anchored caller a bridge dial can ring phones for.
#[derive(Debug, Clone)]
pub struct DialBridgeCaller {
    pub sip_call_id: String,
    /// The caller's INVITE, whose `From` the phones are shown.
    pub template: SipMessage,
    /// The media profile the caller is anchored with.
    pub profile: String,
    /// The caller's media session.
    pub media_call_id: String,
    pub from_tag: String,
}

/// Why a caller cannot have phones rung for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DialBridgeRefusal {
    /// There is no such call.
    Gone,
    /// The caller is not answered: that is a connecting dial's job.
    NotAnswered { call_state: String },
    /// The caller is answered but has no media session on the engine, so there
    /// is nothing to play ringback on or to bridge the phone's media to.
    NotAnchored,
    /// The caller is already bridged to someone.
    AlreadyBridged,
    /// The caller already has phones ringing for it.
    AlreadyDialling,
}

impl DialBridgeRefusal {
    /// The machine-readable reason a refusal carries in its details.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Gone => "call_gone",
            Self::NotAnswered { .. } => "not_answered",
            Self::NotAnchored => "not_anchored",
            Self::AlreadyBridged => "already_bridged",
            Self::AlreadyDialling => "dial_in_progress",
        }
    }
}

impl std::fmt::Display for DialBridgeRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Gone => write!(formatter, "call is gone"),
            Self::NotAnswered { call_state } => write!(
                formatter,
                "dial on_answer \"bridge\" rings phones for an answered caller, and this call is {call_state} — on_answer \"connect\" rings for a caller still waiting"
            ),
            Self::NotAnchored => write!(
                formatter,
                "dial on_answer \"bridge\" needs the caller anchored on the media engine (answer it with anchor) to play ringback and bridge the phone that answers"
            ),
            Self::AlreadyBridged => write!(
                formatter,
                "the caller is already bridged — unbridge it before ringing phones for it"
            ),
            Self::AlreadyDialling => write!(
                formatter,
                "the caller already has phones ringing for it — hang those up or wait for DialAnswered / DialFailed"
            ),
        }
    }
}

/// Why a bridge dial did not start.
#[derive(Debug, Clone)]
pub enum DialBridgeStartError {
    /// The caller cannot have phones rung for it.
    Refused(DialBridgeRefusal),
    /// No phone could be rung; nothing went on the wire.
    Originate(OriginateError),
}

/// The caller behind `sip_call_id`, when phones can be rung for it: answered,
/// anchored, not bridged and with no dial ringing already.
pub fn dial_bridge_caller(
    state: &DispatcherState,
    sip_call_id: &str,
) -> Result<DialBridgeCaller, DialBridgeRefusal> {
    let internal_call_id = state
        .call_actors
        .find_by_sip_call_id(sip_call_id)
        .ok_or(DialBridgeRefusal::Gone)?;
    let (call_state, bridged, invite) = state
        .call_actors
        .get_call(&internal_call_id)
        .map(|call| {
            (
                call.state.clone(),
                call.bridge.is_some(),
                call.a_leg_invite.clone(),
            )
        })
        .ok_or(DialBridgeRefusal::Gone)?;
    if call_state != CallState::Answered {
        return Err(DialBridgeRefusal::NotAnswered {
            call_state: format!("{call_state:?}").to_lowercase(),
        });
    }
    if bridged {
        return Err(DialBridgeRefusal::AlreadyBridged);
    }
    if state.dial_bridges.is_ringing(sip_call_id) {
        return Err(DialBridgeRefusal::AlreadyDialling);
    }
    let session = state
        .rtpengine_sessions
        .as_ref()
        .and_then(|sessions| sessions.get(sip_call_id))
        .filter(|_| state.rtpengine_set.is_some())
        .ok_or(DialBridgeRefusal::NotAnchored)?;
    let template = invite
        .as_ref()
        .and_then(|invite| invite.lock().ok().map(|invite| invite.clone()))
        .ok_or(DialBridgeRefusal::Gone)?;
    Ok(DialBridgeCaller {
        sip_call_id: sip_call_id.to_string(),
        template,
        profile: session.profile.clone(),
        media_call_id: session.rtpengine_id().to_string(),
        from_tag: session.from_tag.clone(),
    })
}

/// What a bridge dial rings, as the `dial` verb parsed it.
#[derive(Debug, Clone)]
pub struct DialBridgePlan {
    /// The phones, `{aor}` targets already resolved to their contacts.
    pub targets: Vec<DialTarget>,
    /// The dial's identity arguments, and `profile`: the media profile each
    /// phone is anchored with (the caller's own when it names none).
    pub shaping: DialShaping,
    /// The dial's own headers, on every leg under each target's own.
    pub headers: Vec<(String, String)>,
    pub strategy: OriginateGroupStrategy,
    /// How long each phone rings.
    pub ring_timeout_secs: u32,
    /// How long the dial as a whole rings.
    pub total_timeout_secs: u32,
}

/// The originate group a bridge dial rings for `caller`.
///
/// Every phone is anchored on the media engine (its offerless INVITE answered
/// locally when it picks up), since the bridge that follows joins it to the
/// caller's media session. Each leg presents the calling identity
/// [`resolve_bridge_leg_identities`] settles for it.
pub fn dial_bridge_spec(
    caller: &DialBridgeCaller,
    mut plan: DialBridgePlan,
) -> Result<OriginateGroupSpec, DialError> {
    if plan.targets.is_empty() {
        return Err(DialError::NoTargets);
    }
    resolve_bridge_leg_identities(&caller.template, &plan.shaping, &mut plan.targets)?;
    // An identity named as an argument is carried as one: a copy in the
    // headers as well would put two on the wire.
    if plan.shaping.p_asserted_identity.is_some() {
        plan.headers
            .retain(|(name, _)| !name.eq_ignore_ascii_case("P-Asserted-Identity"));
    }
    Ok(OriginateGroupSpec {
        params: OriginateParams {
            // Each leg's own: its AoR, or its URI (see `leg_params`).
            to: String::new(),
            to_display: None,
            from: None,
            from_display: None,
            next_hop: None,
            p_asserted_identity: None,
            privacy: None,
            headers: plan.headers,
            timeout_secs: plan.ring_timeout_secs,
            media: OriginateMedia::Anchor {
                profile: plan
                    .shaping
                    .profile
                    .clone()
                    .unwrap_or_else(|| caller.profile.clone()),
                ws_uri: None,
            },
            session_timer: None,
        },
        targets: plan.targets,
        strategy: plan.strategy,
        total_timeout_secs: plan.total_timeout_secs,
        // An answer is only kept once the phone is bridged: until then the
        // other phones ring on, to fall back on when the bridge fails.
        answers: OriginateGroupAnswers::Confirmed,
    })
}

/// Settle on each target the calling identity its leg of a bridge dial
/// presents: its own over the dial's, over the caller's own `From`.
///
/// A bridge dial rings each phone as a call siphon places itself, so there is
/// no caller's INVITE for a leg to be shaped from. Presenting the caller is
/// still what a phone shows for an answered caller it is being connected to,
/// so a leg presents the caller's `From` unless the dial or the target names
/// another, shaped by the same rules a connecting dial follows (a named URI
/// drops the caller's display name unless one is named too, and an empty
/// display name presents none). Every field is written, the display name as
/// `""` when there is none, so the leg carries exactly this.
pub(crate) fn resolve_bridge_leg_identities(
    template: &SipMessage,
    shaping: &DialShaping,
    targets: &mut [DialTarget],
) -> Result<(), DialError> {
    for target in targets.iter_mut() {
        let leg = target.shaping_over(shaping);
        let shaped =
            super::control::shape_from(template, &leg).map_err(DialError::InvalidIdentity)?;
        let from = match shaped {
            Some(shaped) => shaped.header,
            None => template
                .headers
                .get("From")
                .or_else(|| template.headers.get("f"))
                .cloned()
                .ok_or_else(|| {
                    DialError::InvalidIdentity(
                        "the call has no From header to present to the phones".to_string(),
                    )
                })?,
        };
        let presented = crate::sip::headers::nameaddr::NameAddr::parse(&from).map_err(|error| {
            DialError::InvalidIdentity(format!("cannot parse the call's From header: {error}"))
        })?;
        target.from = Some(presented.uri.to_string());
        target.from_display = Some(presented.display_name.unwrap_or_default());
        target.p_asserted_identity = leg.p_asserted_identity;
        target.privacy = leg.privacy;
    }
    Ok(())
}

/// Bridge a phone that answered to its caller, the caller keeping its media
/// session (the anchor) — the `bridge` verb's own path. The phone waits on the
/// bridge from here until it settles ([`dial_bridge_settled`]), which tells
/// `listener` and sends [`DialBridgeSignal::Bridged`] or
/// [`DialBridgeSignal::BridgeFailed`] on `signals`; when the bridge cannot even
/// start, it waits on nothing and the error is returned instead.
pub async fn dial_bridge_join(
    state: &DispatcherState,
    caller_sip_call_id: &str,
    winner: &OriginateGroupWinner,
    signals: DialBridgeSender,
    listener: Arc<dyn DialBridgeListener>,
) -> Result<BridgeAccepted, crate::b2bua::bridge::BridgeError> {
    // Before the re-INVITE is on the wire: a phone that rejects it at once
    // must find itself awaited.
    state.dial_bridges.await_bridge(PendingBridge {
        caller: caller_sip_call_id.to_string(),
        winner: winner.clone(),
        signals,
        listener,
    });
    let joined = bridge_calls_with_state(
        state,
        BridgeParams {
            anchor_sip_call_id: caller_sip_call_id.to_string(),
            peer_sip_call_id: winner.sip_call_id.clone(),
            on_peer_hangup: crate::b2bua::bridge::PeerHangupPolicy::default(),
        },
    )
    .await;
    if joined.is_err() {
        state.dial_bridges.forget_bridge(&winner.internal_call_id);
    }
    joined
}

/// Ring `spec`'s phones for `caller` and return the group and the branches it
/// placed.
///
/// The caller is claimed before anything is created, so two dials racing for
/// it cannot both ring; the claim is released again on every error. On an
/// error nothing is on the wire and `sink` is never called.
pub fn dial_bridge_start(
    state: &DispatcherState,
    caller: &DialBridgeCaller,
    spec: OriginateGroupSpec,
    sink: Arc<dyn OriginateGroupSink>,
    signals: DialBridgeSender,
) -> Result<(String, Vec<crate::b2bua::actor::DialBranch>), DialBridgeStartError> {
    let claimed = state.dial_bridges.claim(
        &caller.sip_call_id,
        RingingDial {
            group_id: None,
            signals,
            media_call_id: caller.media_call_id.clone(),
            from_tag: caller.from_tag.clone(),
        },
    );
    if !claimed {
        return Err(DialBridgeStartError::Refused(
            DialBridgeRefusal::AlreadyDialling,
        ));
    }
    let group_id = match create_originate_group(state, spec, sink) {
        Ok(group_id) => group_id,
        Err(refusal) => {
            state.dial_bridges.release(&caller.sip_call_id);
            return Err(DialBridgeStartError::Originate(refusal));
        }
    };
    if !state.dial_bridges.set_group(&caller.sip_call_id, &group_id) {
        // The caller hung up while the group was created: ring nobody.
        cancel_originate_group(
            state,
            &group_id,
            OriginateGroupEnd::Cancelled {
                reason: DIAL_BRIDGE_CALLER_GONE.to_string(),
            },
        );
        return Err(DialBridgeStartError::Refused(DialBridgeRefusal::Gone));
    }
    match start_originate_group(state, &group_id) {
        Ok(branches) => {
            info!(
                caller = %caller.sip_call_id,
                %group_id,
                legs = branches.len(),
                "control plane: dial — ringing phones for an answered caller"
            );
            Ok((group_id, branches))
        }
        Err(refusal) => {
            state.dial_bridges.release(&caller.sip_call_id);
            Err(DialBridgeStartError::Originate(refusal))
        }
    }
}

/// A call is being torn down. When it is a caller with phones ringing, they are
/// CANCELled; when it is a phone that answered and waits on its bridge, or the
/// caller such a phone waits for, the bridge is no longer awaited; and a
/// ringback on it will never report its end.
///
/// Called from every teardown an answered call goes through, before its
/// `StasisEnd`, so the dial's own events precede it.
pub fn dial_bridge_call_ended(sip_call_id: &str, state: &DispatcherState) {
    let store = &state.dial_bridges;
    store.ringback.remove(sip_call_id);
    if let Some((_, dial)) = store.ringing.remove(sip_call_id) {
        if let Some(group_id) = dial.group_id {
            info!(
                caller = %sip_call_id,
                %group_id,
                "control plane: dial — the caller hung up, cancelling the phones"
            );
            cancel_originate_group(
                state,
                &group_id,
                OriginateGroupEnd::Cancelled {
                    reason: DIAL_BRIDGE_CALLER_GONE.to_string(),
                },
            );
        }
    }
    if let Some(internal_call_id) = state.call_actors.find_by_sip_call_id(sip_call_id) {
        store.bridging.remove(&internal_call_id);
    }
    store
        .bridging
        .retain(|_, pending| pending.caller != sip_call_id);
}

/// A bridge between `call_id` and `peer_call_id` settled — `failed` carries
/// the status that refused it. When one of them is a phone a bridge dial rang,
/// it no longer waits on it, and:
///
/// * bridged: its answer is kept. The group CANCELs every phone still ringing
///   and releases every other answered one, the listener is told (before the
///   bridge's `ChannelBridged`, which the caller of this sends after it), and
///   the dial is over;
/// * failed: the phone is released and its answer refused
///   ([`dial_bridge_refuse_phone`]), and the dial goes on with the rest.
pub fn dial_bridge_settled(
    state: &DispatcherState,
    call_id: &str,
    peer_call_id: &str,
    failed: Option<u16>,
) {
    for leg in [call_id, peer_call_id] {
        let Some((_, pending)) = state.dial_bridges.bridging.remove(leg) else {
            continue;
        };
        match failed {
            Some(code) => {
                warn!(
                    phone = %leg,
                    status = code,
                    "control plane: dial — the bridge to the caller failed, releasing the phone"
                );
                dial_bridge_refuse_phone(state, &pending.winner, code);
                let _ = pending
                    .signals
                    .send(DialBridgeSignal::BridgeFailed(pending.winner));
            }
            None => {
                confirm_originate_group_answer(
                    state,
                    &pending.winner.group_id,
                    &pending.winner.internal_call_id,
                );
                pending.listener.bridged(&pending.winner);
                let _ = pending.signals.send(DialBridgeSignal::Bridged);
            }
        }
    }
}

/// A phone that answered could not be bridged to its caller: hang it up, with
/// a `Reason` saying why, and refuse its answer so its group carries on — the
/// other phones ring on, a sequential dial moves to the next, and the dial
/// fails only once nothing is left. Reported as a `DialBranchFailed` with
/// cause `bridge_failed` and `code`.
pub fn dial_bridge_refuse_phone(state: &DispatcherState, winner: &OriginateGroupWinner, code: u16) {
    b2bua_terminate_call_inner(
        &winner.internal_call_id,
        Some(BRIDGE_FAILED_REASON),
        "b2bua",
        state,
    );
    reject_originate_group_answer(
        state,
        &winner.group_id,
        &winner.internal_call_id,
        crate::b2bua::actor::DialBranchOutcome::new(
            code,
            "Bridge Failed",
            crate::b2bua::actor::DialBranchCause::BridgeFailed,
        ),
    );
}

/// The engine reported playback `play_id` on a leg ended. `true` when it was a
/// bridge dial's ringback, whose record goes with it.
pub fn dial_bridge_ringback_finished(
    state: &DispatcherState,
    media_call_id: &str,
    from_tag: &str,
    play_id: u64,
) -> bool {
    state
        .dial_bridges
        .take_ringback(media_call_id, from_tag, play_id)
}

/// A playback on a leg ended: a dial ringing for that caller may now start the
/// ringback it held back.
pub fn dial_bridge_prompt_finished(state: &DispatcherState, media_call_id: &str, from_tag: &str) {
    for dial in state.dial_bridges.ringing.iter() {
        if dial.media_call_id == media_call_id && dial.from_tag == from_tag {
            let _ = dial.signals.send(DialBridgeSignal::PromptFinished);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CALLER: &str = "caller@192.0.2.10";

    fn ringing(signals: DialBridgeSender) -> RingingDial {
        RingingDial {
            group_id: None,
            signals,
            media_call_id: CALLER.to_string(),
            from_tag: "caller-tag".to_string(),
        }
    }

    #[test]
    fn a_caller_is_claimed_by_one_dial_at_a_time() {
        let store = DialBridgeStore::new();
        let (signals, _receiver) = tokio::sync::mpsc::unbounded_channel();
        assert!(store.claim(CALLER, ringing(signals.clone())));
        assert!(!store.claim(CALLER, ringing(signals.clone())));
        assert!(store.is_ringing(CALLER));
        assert!(store.set_group(CALLER, "group-1"));
        store.release(CALLER);
        assert!(!store.is_ringing(CALLER));
        // A caller gone since its claim has no group to record.
        assert!(!store.set_group(CALLER, "group-2"));
        // Positive control: released, it can be claimed again.
        assert!(store.claim(CALLER, ringing(signals)));
        store.release(CALLER);
        assert_eq!(store.ringing_count(), 0);
    }

    #[test]
    fn a_refusal_names_its_reason() {
        let not_answered = DialBridgeRefusal::NotAnswered {
            call_state: "ringing".to_string(),
        };
        assert_eq!(DialBridgeRefusal::Gone.reason(), "call_gone");
        assert_eq!(not_answered.reason(), "not_answered");
        assert_eq!(DialBridgeRefusal::NotAnchored.reason(), "not_anchored");
        assert_eq!(
            DialBridgeRefusal::AlreadyBridged.reason(),
            "already_bridged"
        );
        assert_eq!(
            DialBridgeRefusal::AlreadyDialling.reason(),
            "dial_in_progress"
        );
        let message = not_answered.to_string();
        assert!(message.contains("ringing"), "{message}");
        assert!(message.contains("connect"), "{message}");
    }

    #[test]
    fn a_ringback_is_matched_on_its_leg_and_its_play_id_alone() {
        let store = DialBridgeStore::new();
        store.record_ringback(CALLER, CALLER, "caller-tag", 7);
        assert!(
            !store.take_ringback(CALLER, "caller-tag", 8),
            "another play"
        );
        assert!(
            !store.take_ringback("other@192.0.2.11", "caller-tag", 7),
            "another leg"
        );
        assert_eq!(store.ringback_count(), 1);
        assert!(store.take_ringback(CALLER, "caller-tag", 7));
        assert_eq!(store.ringback_count(), 0);
    }

    #[test]
    fn an_awaited_bridge_is_forgotten() {
        struct Nobody;
        impl DialBridgeListener for Nobody {
            fn bridged(&self, _: &OriginateGroupWinner) {}
        }
        let store = DialBridgeStore::new();
        let (signals, _receiver) = tokio::sync::mpsc::unbounded_channel();
        store.await_bridge(PendingBridge {
            caller: CALLER.to_string(),
            winner: OriginateGroupWinner {
                group_id: "group".to_string(),
                internal_call_id: "phone-call".to_string(),
                sip_call_id: "phone@192.0.2.20".to_string(),
                branch: crate::b2bua::actor::DialBranch {
                    leg_id: "leg".to_string(),
                    leg_sip_call_id: "phone@192.0.2.20".to_string(),
                    target: "sip:201@192.0.2.20".to_string(),
                    aor: None,
                    outcome: None,
                },
            },
            signals,
            listener: Arc::new(Nobody),
        });
        assert_eq!(store.bridging_count(), 1);
        store.forget_bridge("phone-call");
        assert_eq!(store.bridging_count(), 0);
    }
}
