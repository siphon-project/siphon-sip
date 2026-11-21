//! What a warrant decision is about: the session, not the SIP dialog.
//!
//! A proxied call is one dialog and one Call-ID end to end, so for a proxy the
//! two are the same thing. A B2BUA call is not: each leg is its own dialog with
//! its own Call-ID, and keying on the Call-ID made one call two sessions at the
//! mediation function, with two Correlation IDs. TS 103 221-2 clause 6 requires
//! one correlation across all of a session's X2 and X3 records, so every leg of
//! a call is resolved here to one session id before anything is decided,
//! recorded or correlated.
//!
//! The session id of a warranted B2BUA call is the call's internal id, the key
//! its CDR and Rf records are written under. Interception decides before the
//! call exists, on the dialog-forming INVITE, so it mints that id there and the
//! call adopts it ([`LiManager::reserved_session_id`]). A proxied call's session
//! id is a minted one too, or the Call-ID for a session that started before the
//! warrant did.
//!
//! The legs are kept as aliases of the session, so a leg still resolves to it
//! after the call itself is gone: the 200 to a BYE siphon sent arrives after the
//! teardown, and it belongs to the same session as everything before it.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::warn;

use super::pdu::PayloadDirection;
use super::target::{MatchedField, MatchedParty};
use super::x1::store::TaskMatch;
use super::x1::types::{TargetIdentifier, XId};
use super::{IriEventType, LiManager};

/// What was decided about one session, and when.
#[derive(Debug, Clone)]
pub(super) struct SessionDecision {
    /// The provisioning generation this was decided under. A decision taken
    /// before a warrant was activated says nothing about the traffic after it.
    generation: u64,
    /// The warrants that matched, by XID and the party each names. Empty means
    /// the session matched nothing, which is worth remembering too: it is the
    /// common case and the one that costs the most to re-derive.
    ///
    /// Deliberately not the [`TaskMatch`] itself: that embeds a whole
    /// `StoredTask`, so caching it would both duplicate the store and go stale
    /// the moment a `ModifyTask` changed a delivery type or a DID. The task is
    /// re-read by XID at delivery, which is one lookup and always current.
    matched: Vec<SessionMatch>,
    /// Message instances already recorded for this session.
    ///
    /// Interception runs before transaction matching, so a UDP retransmission
    /// arrives here as an ordinary message and would produce a second record
    /// of something the mediation function already has, up to seven times for
    /// one INVITE under RFC 3261's timers. Worse, it would re-run the
    /// session's lifecycle: a retransmitted INVITE would restart content
    /// capture on a call already being captured.
    ///
    /// Held per session so it is evicted with the session and needs no
    /// lifetime rule of its own. Hashes rather than the keys themselves,
    /// because the only question asked of it is "seen this before".
    seen: HashSet<u64>,
    /// The Call-ID of the dialog the session is anchored on: the caller's leg
    /// of a B2BUA call, the only dialog of a proxied one. It is the call-id the
    /// media engine knows the call by, so it is what X3 attaches on.
    primary_call_id: Arc<str>,
    /// Every other Call-ID resolved to this session, so they can be released
    /// with it.
    legs: Vec<Arc<str>>,
    /// Whether the session id is a B2BUA call's internal id. Such a session is
    /// over when the call is, which is something no message reports on its own:
    /// a call that failed before it was answered ends with siphon's response to
    /// the caller, and nothing inbound follows it.
    bound_to_call: bool,
    /// Whether a dialog-forming INVITE opened the session.
    invite_session: bool,
    /// Whether that INVITE was answered. After the answer a failure response
    /// belongs to a re-INVITE or another in-dialog request and ends nothing.
    established: bool,
    /// The top `Via` branches of the INVITEs seen on the session, newest last:
    /// what the ACK of a failure response carries. See
    /// [`LiManager::acknowledges_unanswered_invite`].
    invite_branches: Vec<Box<str>>,
    /// When the session ended, if it has. It is kept for [`SESSION_GRACE`]
    /// after that, so the stragglers of a teardown still correlate.
    ended_at: Option<Instant>,
}

/// One warrant covering a session, and what is needed to say on every later
/// message whether the target sent it.
#[derive(Debug, Clone)]
struct SessionMatch {
    x_id: XId,
    party: MatchedParty,
    /// The provisioned identifier the deciding message matched on.
    identifier: TargetIdentifier,
    field: MatchedField,
    /// A dialog tag owned by one end of the session, taken from the deciding
    /// message. `None` when that message carried no usable tag, in which case
    /// the direction of the session's messages is not known.
    anchor_tag: Option<Box<str>>,
    /// Whether the end that owns `anchor_tag` is the target.
    target_owns_anchor: bool,
}

/// The dialog tags of one message, and whether it is a request.
///
/// Enough to say which end of a dialog sent a message: a request carries its
/// sender's tag in From, a response carries its sender's tag in To
/// (RFC 3261 §8.2.6.2, §12).
#[derive(Debug, Clone, Copy)]
struct Sender<'a> {
    request: bool,
    from_tag: Option<&'a str>,
    to_tag: Option<&'a str>,
}

impl<'a> Sender<'a> {
    fn of(facts: &MessageFacts<'_>, identities: &Identities<'a>) -> Self {
        Self {
            request: facts.request,
            from_tag: identities.from_uri.and_then(header_tag),
            to_tag: identities.to_uri.and_then(header_tag),
        }
    }

    /// The tag of whoever sent the message.
    fn tag(&self) -> Option<&'a str> {
        if self.request {
            self.from_tag
        } else {
            self.to_tag
        }
    }
}

/// The `tag` parameter of a From or To header value.
///
/// Looked for after the closing `>` of a name-addr, so a `tag` inside the URI
/// itself is not mistaken for the header's.
fn header_tag(header: &str) -> Option<&str> {
    let parameters = header.rfind('>').map_or(header, |end| &header[end + 1..]);
    parameters.split(';').skip(1).find_map(|parameter| {
        let (name, value) = parameter.split_once('=')?;
        let value = value.trim();
        (name.trim().eq_ignore_ascii_case("tag") && !value.is_empty()).then_some(value)
    })
}

impl SessionMatch {
    /// Remember a warrant matching `sender`'s message.
    ///
    /// `b2bua_leg` says the message is on a leg of a B2BUA call, where siphon
    /// is the other end of the dialog and one of the two tags is its own.
    fn decided_on(matched: &TaskMatch, sender: &Sender<'_>, b2bua_leg: bool) -> Self {
        // Whether the target sent the deciding message. The party in From sent
        // a request and received a response; the party in To or the
        // Request-URI the reverse; the party at the source address sent it,
        // whichever it was.
        let target_sent = match matched.field {
            MatchedField::From => sender.request,
            MatchedField::RequestUri | MatchedField::To => !sender.request,
            MatchedField::SourceAddress => true,
        };
        // The anchor has to be a tag an endpoint owns, never siphon's. A
        // request's From-tag always is. For a response the From-tag is the
        // request sender's: an endpoint through a proxy, and the better anchor
        // there because it is the one tag every fork of the dialog shares; but
        // siphon's own on a B2BUA leg, where the sender's To-tag is used.
        let anchor_on_sender = sender.request || (b2bua_leg && sender.to_tag.is_some());
        let (anchor_tag, target_owns_anchor) = if anchor_on_sender {
            (sender.tag(), target_sent)
        } else {
            (sender.from_tag, !target_sent)
        };
        Self {
            x_id: matched.task.details.x_id,
            party: matched.party,
            identifier: matched.identifier.clone(),
            field: matched.field,
            anchor_tag: anchor_tag.map(Box::from),
            target_owns_anchor,
        }
    }

    /// Whether `sender`'s message was sent by the target or towards it.
    ///
    /// TS 103 221-2 clause 5.2.6 asks this of each intercepted message, not of
    /// the call: on a call the target places, the far end's 180 and 200 travel
    /// *to* the target, and a BYE goes whichever way the side hanging up sends
    /// it. Every message siphon receives was sent by one end of the session, so
    /// the question is only whether that end is the target: it is the end that
    /// owns the anchor tag exactly when the message carries that tag as its
    /// sender's. That holds on every leg of a B2BUA call, whose other legs
    /// carry other tags, and whether or not the legs share a Call-ID.
    fn direction(&self, sender: &Sender<'_>) -> PayloadDirection {
        let Some(anchor_tag) = self.anchor_tag.as_deref() else {
            return PayloadDirection::Unknown;
        };
        let sent_by_anchor_owner = sender.tag() == Some(anchor_tag);
        if sent_by_anchor_owner == self.target_owns_anchor {
            PayloadDirection::SentFromTarget
        } else {
            PayloadDirection::SentToTarget
        }
    }

    /// The match as delivery sees it for `sender`'s message, re-reading the
    /// task so a `ModifyTask` is honoured on the very next message.
    fn task_match(&self, manager: &LiManager, sender: &Sender<'_>) -> Option<TaskMatch> {
        manager.tasks.get(self.x_id).map(|task| TaskMatch {
            task,
            party: self.party,
            identifier: self.identifier.clone(),
            field: self.field,
            direction: self.direction(sender),
        })
    }
}

/// How many message instances one session remembers having recorded.
///
/// A dialog is dozens of messages, not thousands; this is generous. Past it
/// de-duplication stops and every message is recorded, because for a warrant a
/// duplicated record is recoverable at the mediation function and a dropped one
/// is not. The degraded mode is therefore the old behaviour, never a gap.
pub(super) const MAX_SEEN_PER_SESSION: usize = 512;

/// How many sessions may have a remembered decision.
///
/// A bound rather than a hope: the key is the Call-ID, which is chosen by
/// whoever sent the message. Without a cap, a flood of requests bearing
/// distinct Call-IDs would grow this map until the process died, which is a
/// remote memory-exhaustion vector on an interface that faces the network.
///
/// On overflow the map is cleared rather than evicted one entry at a time.
/// Clearing costs a re-derivation for the sessions that were in it, which is
/// exactly the behaviour before this cache existed, so the degraded mode is
/// the old correct one, never a missed interception.
pub(super) const MAX_REMEMBERED_SESSIONS: usize = 100_000;

/// How long an ended warranted session stays resolvable.
///
/// RFC 3261 Timer F (64·T1): long enough for the last transaction of the
/// teardown, the 200 to a BYE included, to arrive and be correlated with the
/// session it ends.
pub const SESSION_GRACE: Duration = Duration::from_secs(32);

/// How many INVITE branches one session remembers.
///
/// One for the INVITE that opened it and room for re-INVITEs in flight on
/// either leg. Past it the oldest is dropped, and an ACK that no longer finds
/// its INVITE is treated as the ACK of an answer, which is what every ACK was
/// taken for before this was kept.
pub(super) const MAX_INVITE_BRANCHES_PER_SESSION: usize = 8;

/// The prefix RFC 3261 §8.1.1.7 puts on a branch that identifies its
/// transaction. A branch without it (RFC 2543) promises nothing, so nothing is
/// concluded from two of them being equal.
const BRANCH_MAGIC_COOKIE: &str = "z9hG4bK";

/// The identities a message is matched against a warrant on.
#[derive(Debug, Clone, Copy, Default)]
pub struct Identities<'a> {
    /// The Request-URI, for a request.
    pub request_uri: Option<&'a str>,
    /// The From header.
    pub from_uri: Option<&'a str>,
    /// The To header.
    pub to_uri: Option<&'a str>,
    /// Where the message came from.
    pub source_ip: Option<IpAddr>,
}

/// The shape of a message, as far as a session's lifecycle cares.
#[derive(Debug, Clone, Copy)]
pub struct MessageFacts<'a> {
    /// A request rather than a response.
    pub request: bool,
    /// The request's method, or for a response the method its CSeq names.
    pub method: &'a str,
    /// A response's status code.
    pub status_code: Option<u16>,
    /// Whether the To header carries a tag.
    pub to_tagged: bool,
    /// The branch of the top `Via`.
    pub branch: Option<&'a str>,
}

impl MessageFacts<'_> {
    /// A message whose shape is unknown, which opens nothing and ends nothing.
    pub const UNKNOWN: MessageFacts<'static> = MessageFacts {
        request: false,
        method: "",
        status_code: None,
        to_tagged: true,
        branch: None,
    };

    /// An INVITE outside any dialog: the message that opens a session.
    pub fn opens_dialog(&self) -> bool {
        self.request && self.method == "INVITE" && !self.to_tagged
    }
}

/// The B2BUA call a Call-ID is a leg of.
#[derive(Debug, Clone)]
pub struct CallOwner {
    /// The call's internal id.
    pub internal_id: String,
    /// The Call-ID of the call's caller leg.
    pub a_leg_call_id: String,
}

/// The session one message belongs to.
#[derive(Debug, Clone)]
pub struct SessionView {
    /// What the session is keyed and correlated on.
    pub session_id: Arc<str>,
    /// The Call-ID the media engine knows the call by. See
    /// `SessionDecision::primary_call_id`.
    pub engine_call_id: Arc<str>,
    /// Whether the message is on the session's anchoring dialog rather than on
    /// another leg of the call.
    pub on_primary_leg: bool,
    /// The warrants covering the session.
    pub matches: Vec<TaskMatch>,
}

impl SessionView {
    fn unwarranted(call_id: &str) -> Self {
        let call_id: Arc<str> = Arc::from(call_id);
        Self {
            session_id: Arc::clone(&call_id),
            engine_call_id: call_id,
            on_primary_leg: true,
            matches: Vec::new(),
        }
    }
}

impl LiManager {
    /// Whether anything can be intercepted at all: LI enabled and at least one
    /// warrant provisioned. Everything else on the message path waits behind
    /// this, so a node with nothing provisioned pays one branch.
    pub fn is_intercepting(&self) -> bool {
        self.config.enabled && !self.tasks.is_empty()
    }

    /// The session a message belongs to, and the warrants covering it.
    ///
    /// Decided once per session rather than once per message, for two reasons,
    /// and the second is the important one.
    ///
    /// **It is cheaper.** Matching normalises the URIs and walks the index for
    /// every warrant, and this runs on every message on every leg. A dialog is
    /// dozens of messages about one pair of identities, so deciding it once and
    /// remembering the answer turns all but the first into a map lookup.
    ///
    /// **It is more correct.** Matching each message on its own identities
    /// quietly assumes every message of a session carries the target in a
    /// matchable form, and they do not: a re-INVITE from the far end swaps From
    /// and To, an in-dialog REFER or NOTIFY carries the identities of whoever
    /// sent it, a BYE can come from either side, and a B2BUA rewrites the
    /// callee leg's To and Request-URI to whatever the dial plan chose. Deciding
    /// per message is how a warrant delivers the INVITE and then silently misses
    /// the BYE, or the whole of the other leg. Once a session is warranted,
    /// everything in it is intercepted.
    ///
    /// A remembered decision is only used while the provisioning generation has
    /// not moved: an `ActivateTask` must take effect on calls already in
    /// progress, so a session decided as unwarranted before it arrived is
    /// decided again after.
    ///
    /// `owner` names the B2BUA call the Call-ID is a leg of. It is asked only
    /// for a Call-ID this has not seen, which is a leg's first message.
    pub fn resolve_session(
        &self,
        call_id: &str,
        facts: &MessageFacts<'_>,
        identities: &Identities<'_>,
        owner: impl FnOnce() -> Option<CallOwner>,
    ) -> SessionView {
        if !self.is_intercepting() {
            return SessionView::unwarranted(call_id);
        }
        let generation = self.tasks.generation();
        let sender = Sender::of(facts, identities);

        let known = self
            .aliases
            .get(call_id)
            .map(|alias| Arc::clone(alias.value()))
            .or_else(|| {
                self.decisions
                    .get(call_id)
                    .map(|decision| Arc::clone(decision.key()))
            });
        if let Some(session_id) = known {
            if let Some(view) = self.refresh(&session_id, call_id, generation, identities, &sender)
            {
                return view;
            }
        }

        // A Call-ID not seen before: the first message of a session, or of
        // another leg of one.
        let owner = owner();
        if let Some(owner) = owner.as_ref() {
            if let Some(session_id) = self.warranted_session_of(owner) {
                self.alias(call_id, &session_id);
                if let Some(view) =
                    self.refresh(&session_id, call_id, generation, identities, &sender)
                {
                    return view;
                }
            }
        }

        let matches = self.tasks.match_message(
            identities.request_uri,
            identities.from_uri,
            identities.to_uri,
            identities.source_ip,
        );
        let decided: Vec<SessionMatch> = matches
            .iter()
            .map(|matched| SessionMatch::decided_on(matched, &sender, owner.is_some()))
            .collect();
        let matches = decided
            .iter()
            .zip(matches)
            .map(|(decided, matched)| TaskMatch {
                direction: decided.direction(&sender),
                ..matched
            })
            .collect::<Vec<_>>();
        let call_id: Arc<str> = Arc::from(call_id);
        let (session_id, primary_call_id, bound_to_call): (Arc<str>, Arc<str>, bool) =
            if matches.is_empty() {
                (Arc::clone(&call_id), Arc::clone(&call_id), false)
            } else if let Some(owner) = owner {
                // A warrant that began mid-call, on a call that already has its
                // internal id.
                (
                    Arc::from(owner.internal_id),
                    Arc::from(owner.a_leg_call_id),
                    true,
                )
            } else if facts.opens_dialog() {
                (
                    Arc::from(uuid::Uuid::new_v4().to_string()),
                    Arc::clone(&call_id),
                    false,
                )
            } else {
                (Arc::clone(&call_id), Arc::clone(&call_id), false)
            };

        self.insert_decision(
            &session_id,
            &primary_call_id,
            &call_id,
            generation,
            decided,
            bound_to_call,
        );
        SessionView {
            on_primary_leg: primary_call_id == call_id,
            session_id,
            engine_call_id: primary_call_id,
            matches,
        }
    }

    /// [`resolve_session`](Self::resolve_session) for a caller that only wants
    /// to know whether a message is covered, and has no call to name.
    pub fn check_session(
        &self,
        call_id: &str,
        request_uri: Option<&str>,
        from_uri: Option<&str>,
        to_uri: Option<&str>,
        source_ip: Option<IpAddr>,
    ) -> Vec<TaskMatch> {
        let identities = Identities {
            request_uri,
            from_uri,
            to_uri,
            source_ip,
        };
        self.resolve_session(call_id, &MessageFacts::UNKNOWN, &identities, || None)
            .matches
    }

    /// The id a B2BUA call should be created under, when interception has
    /// already decided its caller's INVITE.
    ///
    /// `None` for an unwarranted call, which keeps its own fresh id. Asking
    /// binds the session to the call, so it ends when the call does.
    pub fn reserved_session_id(&self, a_leg_call_id: &str) -> Option<String> {
        let session_id = self
            .aliases
            .get(a_leg_call_id)
            .map(|alias| Arc::clone(alias.value()))?;
        let mut decision = self.decisions.get_mut(&*session_id)?;
        if decision.matched.is_empty() || &*decision.primary_call_id != a_leg_call_id {
            return None;
        }
        decision.bound_to_call = true;
        Some(session_id.to_string())
    }

    /// Note a message on a warranted session, and say what kind of event it is
    /// in that session's life.
    ///
    /// The begin/continue/end shape decides where content capture stops; a
    /// mediation function reconstructs the rest from the SIP the record carries.
    /// A message that ends the session leaves it resolvable for
    /// [`SESSION_GRACE`]; [`sweep_sessions`](Self::sweep_sessions) releases it.
    pub fn note_message(&self, view: &SessionView, facts: &MessageFacts<'_>) -> IriEventType {
        let mut decision = self.decisions.get_mut(&*view.session_id);
        let (invite_session, established) =
            decision.as_deref().map_or((false, false), |decision| {
                (decision.invite_session, decision.established)
            });

        let event_type = if facts.request {
            match facts.method {
                "INVITE" if !facts.to_tagged => IriEventType::Begin,
                "BYE" | "CANCEL" => IriEventType::End,
                "REGISTER" | "MESSAGE" | "SUBSCRIBE" | "PUBLISH" | "OPTIONS" => {
                    IriEventType::Report
                }
                _ => IriEventType::Continue,
            }
        } else {
            match facts.status_code {
                // Another leg failing does not end the call. An LCR carrier
                // that refused, a forked branch that lost, a far end that sent
                // 491 to a re-INVITE: the call carries on, and so must content
                // capture.
                Some(code) if code >= 300 && !view.on_primary_leg => IriEventType::Continue,
                Some(code) if code >= 300 => {
                    let in_dialog_failure = invite_session
                        && !matches!(facts.method, "BYE" | "CANCEL")
                        && (established || facts.method != "INVITE");
                    if in_dialog_failure {
                        IriEventType::Continue
                    } else {
                        IriEventType::End
                    }
                }
                _ => IriEventType::Continue,
            }
        };

        let Some(decision) = decision.as_deref_mut() else {
            return event_type;
        };
        if event_type == IriEventType::Begin {
            decision.invite_session = true;
        }
        if facts.request && facts.method == "INVITE" {
            if let Some(branch) = facts.branch {
                if decision.invite_branches.len() >= MAX_INVITE_BRANCHES_PER_SESSION {
                    decision.invite_branches.remove(0);
                }
                decision.invite_branches.push(Box::from(branch));
            }
        }
        let answered = !facts.request
            && facts.method == "INVITE"
            && facts
                .status_code
                .is_some_and(|code| (200..300).contains(&code));
        if answered {
            decision.established = true;
        }

        let ends = matches!(facts.method, "BYE" | "CANCEL")
            || (!facts.request && event_type == IriEventType::End);
        if ends {
            decision.ended_at.get_or_insert_with(Instant::now);
        } else if !(facts.request && facts.method == "ACK") {
            // Something that is not part of a teardown: the session is live.
            // An ACK is neither, since the ACK of a failure follows the end.
            decision.ended_at = None;
        }
        event_type
    }

    /// Whether an ACK acknowledges a failure response to an INVITE on a
    /// session that was never answered, so there is no media to deliver.
    ///
    /// Interception sees every ACK, because it runs ahead of the transaction
    /// layer that would absorb this one. RFC 3261 tells the two kinds apart by
    /// transaction: the ACK of a non-2xx final belongs to the INVITE's and
    /// carries its branch (§17.1.1.3), the ACK of a 2xx is a transaction of its
    /// own with a new one (§13.2.2.4). That holds whoever sent the failure, a
    /// far end through a proxy or siphon itself as a B2BUA, where no failure
    /// response ever arrives on the caller's leg to be noticed.
    ///
    /// Both conditions are required, and every doubt resolves to `false`,
    /// which attaches: a sender that reuses the INVITE's branch on the ACK of
    /// a 2xx is wrong but its call was answered and its content is owed, and a
    /// branch without the magic cookie identifies nothing.
    pub fn acknowledges_unanswered_invite(
        &self,
        view: &SessionView,
        facts: &MessageFacts<'_>,
    ) -> bool {
        if !(facts.request && facts.method == "ACK") {
            return false;
        }
        let Some(branch) = facts
            .branch
            .filter(|branch| branch.starts_with(BRANCH_MAGIC_COOKIE))
        else {
            return false;
        };
        self.decisions
            .get(&*view.session_id)
            .is_some_and(|decision| {
                !decision.established
                    && decision
                        .invite_branches
                        .iter()
                        .any(|invite_branch| &**invite_branch == branch)
            })
    }

    /// Record that a message instance has been intercepted, once.
    ///
    /// Returns `false` when this exact instance has already been recorded for
    /// the session (a retransmission), and the caller should do nothing
    /// further with it.
    ///
    /// Interception is deliberately placed before transaction matching, so that
    /// a script cannot drop a message before it is intercepted. The cost of
    /// that placement is that retransmissions arrive here looking like new
    /// messages: RFC 3261's timers resend an unanswered INVITE up to seven
    /// times, and each would otherwise produce its own IRI record and re-run
    /// the session's lifecycle, restarting content capture on a call already
    /// being captured.
    ///
    /// The key is the message instance, not its content: the top `Via` branch
    /// identifies the transaction (§8.1.1.7 requires a new branch for a new
    /// one), and the CSeq, method and status separate the messages within it.
    /// A re-INVITE, an ACK and a second provisional all key differently; only
    /// a genuine resend of the same thing collides. Two legs of one call never
    /// share a branch, so keying on the session loses nothing.
    pub fn record_message_once(&self, session_id: &str, key: u64) -> bool {
        let Some(mut session) = self.decisions.get_mut(session_id) else {
            // No decision means nothing matched, so nothing is being recorded
            // and there is nothing to de-duplicate.
            return true;
        };
        if session.seen.len() >= MAX_SEEN_PER_SESSION {
            // Fail open. A duplicate record is recoverable at the mediation
            // function; a dropped one is not.
            return true;
        }
        session.seen.insert(key)
    }

    /// Forget a session's decision and every leg resolved to it.
    ///
    /// For an unwarranted session, as its dialog ends: the map would otherwise
    /// grow with every call the node ever handles and rely on the cap to save
    /// it. A warranted one ends through [`note_message`](Self::note_message) and
    /// is released by [`sweep_sessions`](Self::sweep_sessions) after its grace.
    pub fn forget_session(&self, session_id: &str) {
        if let Some((_, decision)) = self.decisions.remove(session_id) {
            for leg in &decision.legs {
                self.aliases.remove(&**leg);
            }
        }
    }

    /// Release warranted sessions that are over.
    ///
    /// A session bound to a B2BUA call ends when `call_is_live` stops naming
    /// it, whatever the last message was. Any ended session is released
    /// [`SESSION_GRACE`] after it ended. With nothing provisioned no message
    /// reaches this subsystem any more, so everything is released.
    pub fn sweep_sessions(&self, now: Instant, call_is_live: impl Fn(&str) -> bool) {
        if !self.is_intercepting() {
            self.decisions.clear();
            self.aliases.clear();
            return;
        }
        let mut released = Vec::new();
        for mut decision in self.decisions.iter_mut() {
            if decision.bound_to_call
                && decision.ended_at.is_none()
                && !call_is_live(decision.key())
            {
                decision.ended_at = Some(now);
            }
            if decision
                .ended_at
                .is_some_and(|ended| now.saturating_duration_since(ended) >= SESSION_GRACE)
            {
                released.push(Arc::clone(decision.key()));
            }
        }
        for session_id in released {
            self.forget_session(&session_id);
        }
    }

    /// How many sessions currently have a remembered decision.
    ///
    /// Exposed so the leak tests can assert this drains rather than grows.
    pub fn remembered_session_count(&self) -> usize {
        self.decisions.len()
    }

    /// How many leg Call-IDs currently resolve to a session other than their
    /// own. Drains with the sessions; exposed for the leak tests.
    pub fn session_alias_count(&self) -> usize {
        self.aliases.len()
    }

    /// The session an already-warranted call's other legs belong to.
    fn warranted_session_of(&self, owner: &CallOwner) -> Option<Arc<str>> {
        if let Some(decision) = self.decisions.get(owner.internal_id.as_str()) {
            if !decision.matched.is_empty() {
                return Some(Arc::clone(decision.key()));
            }
        }
        let session_id = self
            .aliases
            .get(owner.a_leg_call_id.as_str())
            .map(|alias| Arc::clone(alias.value()))?;
        self.decisions
            .get(&*session_id)
            .is_some_and(|decision| !decision.matched.is_empty())
            .then_some(session_id)
    }

    /// The current view of a known session, or `None` when it has to be decided
    /// afresh: its decision is gone, or it was unwarranted and a warrant
    /// provisioned since covers it now, which may make it part of a call.
    fn refresh(
        &self,
        session_id: &Arc<str>,
        call_id: &str,
        generation: u64,
        identities: &Identities<'_>,
        sender: &Sender<'_>,
    ) -> Option<SessionView> {
        let mut decision = self.decisions.get_mut(&**session_id)?;
        if decision.generation != generation {
            let fresh = self.tasks.match_message(
                identities.request_uri,
                identities.from_uri,
                identities.to_uri,
                identities.source_ip,
            );
            if decision.matched.is_empty() && !fresh.is_empty() {
                drop(decision);
                self.forget_session(session_id);
                return None;
            }
            // Warrants still provisioned keep covering the session, and any
            // new one this message matches is added. Re-deriving from this
            // message alone would drop a warrant whose target this particular
            // message does not carry.
            decision
                .matched
                .retain(|known| self.tasks.get(known.x_id).is_some());
            // A session bound to a call is a B2BUA call's, so this message is
            // on one of its legs.
            let b2bua_leg = decision.bound_to_call;
            for matched in fresh {
                let x_id = matched.task.details.x_id;
                if !decision.matched.iter().any(|known| known.x_id == x_id) {
                    decision
                        .matched
                        .push(SessionMatch::decided_on(&matched, sender, b2bua_leg));
                }
            }
            decision.generation = generation;
        }
        // Re-read each task rather than trusting a cached copy, so a
        // ModifyTask that changed a delivery type or a destination is
        // honoured on the very next message.
        let matches = decision
            .matched
            .iter()
            .filter_map(|known| known.task_match(self, sender))
            .collect();
        Some(SessionView {
            session_id: Arc::clone(session_id),
            on_primary_leg: &*decision.primary_call_id == call_id,
            engine_call_id: Arc::clone(&decision.primary_call_id),
            matches,
        })
    }

    /// Resolve `call_id` to `session_id` from now on.
    fn alias(&self, call_id: &str, session_id: &Arc<str>) {
        if &**session_id == call_id {
            return;
        }
        let call_id: Arc<str> = Arc::from(call_id);
        if let Some(mut decision) = self.decisions.get_mut(&**session_id) {
            if !decision.legs.contains(&call_id) {
                decision.legs.push(Arc::clone(&call_id));
            }
        }
        self.aliases.insert(call_id, Arc::clone(session_id));
    }

    fn insert_decision(
        &self,
        session_id: &Arc<str>,
        primary_call_id: &Arc<str>,
        call_id: &Arc<str>,
        generation: u64,
        matched: Vec<SessionMatch>,
        bound_to_call: bool,
    ) {
        // Bounded, because the key is attacker-supplied. Clearing on overflow
        // costs a re-derivation, never a missed interception.
        if self.decisions.len() >= MAX_REMEMBERED_SESSIONS {
            warn!(
                remembered = self.decisions.len(),
                "LI session decisions hit the cap and were cleared; matching \
                 falls back to per-message until they repopulate"
            );
            self.decisions.clear();
            self.aliases.clear();
        }
        // A leg that had a decision of its own (unwarranted, from before the
        // warrant) is now part of this session.
        for leg in [call_id, primary_call_id] {
            if leg != session_id {
                self.decisions.remove(&**leg);
            }
        }
        self.decisions.insert(
            Arc::clone(session_id),
            SessionDecision {
                generation,
                matched,
                seen: HashSet::new(),
                primary_call_id: Arc::clone(primary_call_id),
                legs: Vec::new(),
                bound_to_call,
                invite_session: false,
                established: false,
                invite_branches: Vec::new(),
                ended_at: None,
            },
        );
        self.alias(primary_call_id, session_id);
        self.alias(call_id, session_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::li::tests::{manager, provision, provision_targets};
    use crate::li::x1::types::DeliveryType;

    const CALLER_LEG: &str = "caller-leg@example.com";
    const CALLEE_LEG: &str = "callee-leg@example.com";

    fn invite() -> MessageFacts<'static> {
        MessageFacts {
            request: true,
            method: "INVITE",
            status_code: None,
            to_tagged: false,
            branch: Some("z9hG4bK-invite"),
        }
    }

    fn response(method: &'static str, code: u16) -> MessageFacts<'static> {
        MessageFacts {
            request: false,
            method,
            status_code: Some(code),
            to_tagged: true,
            branch: None,
        }
    }

    fn request(method: &'static str) -> MessageFacts<'static> {
        MessageFacts {
            request: true,
            method,
            status_code: None,
            to_tagged: true,
            branch: None,
        }
    }

    /// The caller's identities: the warrant names alice.
    fn caller() -> Identities<'static> {
        Identities {
            request_uri: Some("sip:bob@example.com"),
            from_uri: Some("<sip:alice@example.com>;tag=a"),
            to_uri: Some("<sip:bob@example.com>"),
            source_ip: None,
        }
    }

    /// The callee leg as a B2BUA builds it: nothing of the caller left.
    fn callee() -> Identities<'static> {
        Identities {
            request_uri: None,
            from_uri: Some("<sip:15550100001@192.0.2.1>;tag=s"),
            to_uri: Some("<sip:15550100042@198.51.100.77>;tag=c"),
            source_ip: None,
        }
    }

    fn owned_by(internal_id: &str) -> CallOwner {
        CallOwner {
            internal_id: internal_id.to_string(),
            a_leg_call_id: CALLER_LEG.to_string(),
        }
    }

    /// A warranted B2BUA call as the dispatcher sees it: the caller's INVITE,
    /// then the call created under the reserved id. Returns that id.
    fn warranted_call(manager: &LiManager) -> String {
        let opening = manager.resolve_session(CALLER_LEG, &invite(), &caller(), || None);
        assert_eq!(opening.matches.len(), 1);
        manager
            .reserved_session_id(CALLER_LEG)
            .expect("a warranted caller INVITE reserves the call's id")
    }

    #[test]
    fn a_warranted_dialog_forming_invite_reserves_a_fresh_id() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);

        let opening = manager.resolve_session(CALLER_LEG, &invite(), &caller(), || None);
        assert_ne!(
            &*opening.session_id, CALLER_LEG,
            "the session is not keyed on a leg"
        );
        assert!(opening.on_primary_leg);
        assert_eq!(&*opening.engine_call_id, CALLER_LEG);

        // A retransmission finds the same session.
        let again = manager.resolve_session(CALLER_LEG, &invite(), &caller(), || None);
        assert_eq!(again.session_id, opening.session_id);
        assert_eq!(
            manager.reserved_session_id(CALLER_LEG).as_deref(),
            Some(&*opening.session_id)
        );
    }

    #[test]
    fn an_unwarranted_call_reserves_nothing_and_aliases_nothing() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);
        let nobody = Identities {
            request_uri: Some("sip:carol@example.com"),
            from_uri: Some("<sip:dave@example.com>;tag=d"),
            to_uri: Some("<sip:carol@example.com>"),
            source_ip: None,
        };

        let view = manager.resolve_session(CALLER_LEG, &invite(), &nobody, || None);
        assert!(view.matches.is_empty());
        assert_eq!(manager.reserved_session_id(CALLER_LEG), None);
        manager.resolve_session(CALLEE_LEG, &response("INVITE", 180), &callee(), || {
            Some(owned_by("call-1"))
        });
        assert_eq!(
            manager.session_alias_count(),
            0,
            "an alias per unwarranted leg would grow with every call"
        );
    }

    #[test]
    fn the_callee_leg_resolves_to_the_callers_session() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);
        let internal_id = warranted_call(&manager);

        let ringing =
            manager.resolve_session(CALLEE_LEG, &response("INVITE", 180), &callee(), || {
                Some(owned_by(&internal_id))
            });
        assert_eq!(&*ringing.session_id, internal_id.as_str());
        assert_eq!(
            ringing.matches.len(),
            1,
            "the callee leg inherits the warrant"
        );
        assert!(!ringing.on_primary_leg);
        assert_eq!(&*ringing.engine_call_id, CALLER_LEG);

        // Later messages on the leg resolve by alias; the owner is not asked.
        let answered =
            manager.resolve_session(CALLEE_LEG, &response("INVITE", 200), &callee(), || {
                panic!("an aliased leg must not need its call")
            });
        assert_eq!(answered.session_id, ringing.session_id);
    }

    #[test]
    fn a_warrant_activated_mid_call_covers_both_legs_under_the_calls_id() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);
        let nobody = Identities {
            request_uri: Some("sip:carol@example.com"),
            from_uri: Some("<sip:dave@example.com>;tag=d"),
            to_uri: Some("<sip:carol@example.com>"),
            source_ip: None,
        };
        manager.resolve_session(CALLER_LEG, &invite(), &nobody, || None);

        // A warrant on dave arrives, and the caller re-INVITEs.
        let mut details = manager.tasks().list()[0].details.clone();
        details.x_id = XId::generate();
        details.target_identifiers = vec![crate::li::x1::types::TargetIdentifier::SipUri(
            "sip:dave@example.com".to_string(),
        )];
        manager
            .tasks()
            .activate(details)
            .expect("task must provision");

        let reinvite = manager.resolve_session(CALLER_LEG, &request("INVITE"), &nobody, || {
            Some(owned_by("call-7"))
        });
        assert_eq!(reinvite.matches.len(), 1);
        assert_eq!(&*reinvite.session_id, "call-7");
        let far = manager.resolve_session(CALLEE_LEG, &response("INVITE", 200), &callee(), || {
            Some(owned_by("call-7"))
        });
        assert_eq!(&*far.session_id, "call-7");
        assert_eq!(far.matches.len(), 1);
    }

    #[test]
    fn a_callee_leg_failure_is_not_the_end_of_the_call() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);
        let internal_id = warranted_call(&manager);
        let opening = manager.resolve_session(CALLER_LEG, &invite(), &caller(), || None);
        assert_eq!(
            manager.note_message(&opening, &invite()),
            IriEventType::Begin
        );

        let refused =
            manager.resolve_session(CALLEE_LEG, &response("INVITE", 503), &callee(), || {
                Some(owned_by(&internal_id))
            });
        assert_eq!(
            manager.note_message(&refused, &response("INVITE", 503)),
            IriEventType::Continue
        );
    }

    #[test]
    fn a_failed_re_invite_is_not_the_end_of_an_answered_call() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);
        let opening = manager.resolve_session(CALLER_LEG, &invite(), &caller(), || None);
        manager.note_message(&opening, &invite());
        manager.note_message(&opening, &response("INVITE", 200));

        assert_eq!(
            manager.note_message(&opening, &response("INVITE", 488)),
            IriEventType::Continue,
            "after the answer a failure belongs to a re-INVITE"
        );
        assert_eq!(
            manager.note_message(&opening, &response("INFO", 415)),
            IriEventType::Continue
        );
        assert_eq!(
            manager.note_message(&opening, &request("BYE")),
            IriEventType::End
        );
    }

    #[test]
    fn an_unanswered_invite_failure_ends_the_session() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);
        let opening = manager.resolve_session(CALLER_LEG, &invite(), &caller(), || None);
        manager.note_message(&opening, &invite());
        assert_eq!(
            manager.note_message(&opening, &response("INVITE", 486)),
            IriEventType::End
        );
    }

    #[test]
    fn an_ended_session_stays_resolvable_for_the_grace_then_drains() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);
        let internal_id = warranted_call(&manager);
        let ringing =
            manager.resolve_session(CALLEE_LEG, &response("INVITE", 200), &callee(), || {
                Some(owned_by(&internal_id))
            });
        manager.note_message(&ringing, &response("INVITE", 200));

        // The call is gone; the sweep notices.
        let ended = Instant::now();
        manager.sweep_sessions(ended, |_| false);
        assert_eq!(manager.remembered_session_count(), 1, "kept for the grace");
        let late = manager.resolve_session(CALLEE_LEG, &response("BYE", 200), &callee(), || None);
        assert_eq!(
            &*late.session_id,
            internal_id.as_str(),
            "the 200 to a BYE still correlates with its call"
        );
        manager.note_message(&late, &response("BYE", 200));

        manager.sweep_sessions(ended + SESSION_GRACE, |_| false);
        assert_eq!(manager.remembered_session_count(), 0);
        assert_eq!(manager.session_alias_count(), 0);
    }

    #[test]
    fn a_live_call_is_never_released() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);
        let internal_id = warranted_call(&manager);
        manager.sweep_sessions(Instant::now() + SESSION_GRACE * 10, |id| id == internal_id);
        assert_eq!(manager.remembered_session_count(), 1);
    }

    #[test]
    fn a_proxied_session_ends_on_its_bye_and_drains_after_the_grace() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);
        let opening = manager.resolve_session(CALLER_LEG, &invite(), &caller(), || None);
        manager.note_message(&opening, &invite());
        manager.note_message(&opening, &response("INVITE", 200));
        manager.note_message(&opening, &request("BYE"));

        let ended = Instant::now();
        manager.sweep_sessions(ended, |_| false);
        assert_eq!(
            manager.remembered_session_count(),
            1,
            "an unbound session is not ended by the call store"
        );
        manager.sweep_sessions(ended + SESSION_GRACE + Duration::from_secs(1), |_| false);
        assert_eq!(manager.remembered_session_count(), 0);
        assert_eq!(manager.session_alias_count(), 0);
    }

    /// The per-module leak gate: a steady stream of complete warranted calls
    /// leaves nothing behind once each has had its grace.
    #[test]
    fn complete_calls_drain_to_baseline() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);
        for index in 0..1_000 {
            let caller_leg = format!("caller-{index}@example.com");
            let callee_leg = format!("callee-{index}@example.com");
            manager.resolve_session(&caller_leg, &invite(), &caller(), || None);
            let internal_id = manager
                .reserved_session_id(&caller_leg)
                .expect("a reservation");
            let owner = CallOwner {
                internal_id,
                a_leg_call_id: caller_leg.clone(),
            };
            let answered =
                manager.resolve_session(&callee_leg, &response("INVITE", 200), &callee(), || {
                    Some(owner)
                });
            manager.note_message(&answered, &response("INVITE", 200));
            manager.note_message(&answered, &request("BYE"));
        }
        assert_eq!(manager.remembered_session_count(), 1_000);
        manager.sweep_sessions(Instant::now() + SESSION_GRACE, |_| false);
        assert_eq!(manager.remembered_session_count(), 0);
        assert_eq!(manager.session_alias_count(), 0);
    }

    #[test]
    fn nothing_provisioned_releases_everything() {
        let (manager, _iri, _audit) = manager();
        let x_id = provision(&manager, DeliveryType::X2Only, None);
        warranted_call(&manager);
        manager.tasks().deactivate(x_id).expect("must deactivate");
        manager.sweep_sessions(Instant::now(), |_| true);
        assert_eq!(manager.remembered_session_count(), 0);
        assert_eq!(manager.session_alias_count(), 0);
    }

    // --- per-message direction (TS 103 221-2 clause 5.2.6) -----------------

    const DIALOG: &str = "proxied-dialog@example.com";

    /// One message of the proxied dialog between alice (tag `a`) and bob (tag
    /// `b`), as seen by the session: who it names in From and To.
    fn proxied(from: &'static str, to: &'static str) -> Identities<'static> {
        Identities {
            request_uri: None,
            from_uri: Some(from),
            to_uri: Some(to),
            source_ip: None,
        }
    }

    const ALICE_TO_BOB: (&str, &str) = (
        "<sip:alice@example.com>;tag=a",
        "<sip:bob@example.com>;tag=b",
    );
    const BOB_TO_ALICE: (&str, &str) = (
        "<sip:bob@example.com>;tag=b",
        "<sip:alice@example.com>;tag=a",
    );

    /// The direction the session gives one message of the proxied dialog.
    fn direction_of(
        manager: &LiManager,
        facts: MessageFacts<'static>,
        (from, to): (&'static str, &'static str),
    ) -> PayloadDirection {
        let view = manager.resolve_session(DIALOG, &facts, &proxied(from, to), || None);
        assert_eq!(view.matches.len(), 1, "the session stays warranted");
        view.matches[0].direction
    }

    use PayloadDirection::{SentFromTarget, SentToTarget};

    /// A call the target places, through a proxy. Its own INVITE, ACK and BYE
    /// are from the target; everything the far end sends travels to it.
    #[test]
    fn on_a_call_the_target_places_only_its_own_messages_are_from_the_target() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);

        let opening = Identities {
            request_uri: Some("sip:bob@example.com"),
            from_uri: Some("<sip:alice@example.com>;tag=a"),
            to_uri: Some("<sip:bob@example.com>"),
            source_ip: None,
        };
        let view = manager.resolve_session(DIALOG, &invite(), &opening, || None);
        assert_eq!(view.matches[0].direction, SentFromTarget, "its INVITE");

        // A 100 Trying carries no To-tag, and is still not the target's.
        let untagged = ("<sip:alice@example.com>;tag=a", "<sip:bob@example.com>");
        assert_eq!(
            direction_of(&manager, response("INVITE", 100), untagged),
            SentToTarget
        );
        assert_eq!(
            direction_of(&manager, response("INVITE", 180), ALICE_TO_BOB),
            SentToTarget,
            "the far end's 180"
        );
        assert_eq!(
            direction_of(&manager, response("INVITE", 200), ALICE_TO_BOB),
            SentToTarget,
            "the far end's 200"
        );
        assert_eq!(
            direction_of(&manager, request("ACK"), ALICE_TO_BOB),
            SentFromTarget
        );
        // A re-INVITE from the far end swaps From and To.
        assert_eq!(
            direction_of(&manager, request("INVITE"), BOB_TO_ALICE),
            SentToTarget
        );
        assert_eq!(
            direction_of(&manager, response("INVITE", 200), BOB_TO_ALICE),
            SentFromTarget,
            "the target answering the far end's re-INVITE"
        );
        assert_eq!(
            direction_of(&manager, request("BYE"), ALICE_TO_BOB),
            SentFromTarget,
            "the target hanging up"
        );
        assert_eq!(
            direction_of(&manager, response("BYE", 200), ALICE_TO_BOB),
            SentToTarget
        );
    }

    /// A BYE goes whichever way the side hanging up sends it.
    #[test]
    fn a_bye_from_the_far_end_travels_to_the_target() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);
        manager.resolve_session(DIALOG, &invite(), &caller(), || None);

        assert_eq!(
            direction_of(&manager, request("BYE"), BOB_TO_ALICE),
            SentToTarget
        );
        assert_eq!(
            direction_of(&manager, response("BYE", 200), BOB_TO_ALICE),
            SentFromTarget,
            "the target's 200 to it"
        );
    }

    /// A call to the target: the caller's INVITE and ACK travel to it, and its
    /// own 180, 486, 200 and BYE are from it.
    #[test]
    fn on_a_call_to_the_target_its_own_responses_are_from_the_target() {
        let (manager, _iri, _audit) = manager();
        provision_targets(
            &manager,
            DeliveryType::X2Only,
            None,
            vec![TargetIdentifier::SipUri("sip:bob@example.com".to_string())],
        );

        let view = manager.resolve_session(DIALOG, &invite(), &caller(), || None);
        assert_eq!(view.matches[0].party, MatchedParty::Terminating);
        assert_eq!(
            view.matches[0].direction, SentToTarget,
            "the caller's INVITE"
        );

        assert_eq!(
            direction_of(&manager, response("INVITE", 180), ALICE_TO_BOB),
            SentFromTarget,
            "the target's own 180"
        );
        assert_eq!(
            direction_of(&manager, response("INVITE", 486), ALICE_TO_BOB),
            SentFromTarget,
            "the target's own 486"
        );
        assert_eq!(
            direction_of(&manager, request("ACK"), ALICE_TO_BOB),
            SentToTarget
        );
        assert_eq!(
            direction_of(&manager, request("BYE"), BOB_TO_ALICE),
            SentFromTarget,
            "the target hanging up"
        );
        assert_eq!(
            direction_of(&manager, request("BYE"), ALICE_TO_BOB),
            SentToTarget,
            "the caller hanging up"
        );
    }

    /// A warrant activated mid-call is decided on whatever message comes
    /// next. Here that is a response, where the party in From did not send it.
    #[test]
    fn a_session_decided_on_a_response_still_tells_the_directions_apart() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);

        // Decided on bob's 200 to alice's INVITE: alice is in From.
        assert_eq!(
            direction_of(&manager, response("INVITE", 200), ALICE_TO_BOB),
            SentToTarget
        );
        assert_eq!(
            direction_of(&manager, request("ACK"), ALICE_TO_BOB),
            SentFromTarget
        );
        assert_eq!(
            direction_of(&manager, request("BYE"), BOB_TO_ALICE),
            SentToTarget
        );
    }

    /// A warrant on an address: whoever is at it sent the message, request or
    /// response.
    #[test]
    fn a_source_address_match_is_from_the_target_whatever_the_message() {
        const ADDRESS: std::net::Ipv4Addr = std::net::Ipv4Addr::new(192, 0, 2, 10);
        /// A session decided on a message from the warranted address.
        fn from_target(
            facts: MessageFacts<'static>,
            (from, to): (&'static str, &'static str),
        ) -> LiManager {
            let (manager, _iri, _audit) = manager();
            provision_targets(
                &manager,
                DeliveryType::X2Only,
                None,
                vec![TargetIdentifier::Ipv4Address(ADDRESS)],
            );
            let identities = Identities {
                source_ip: Some(IpAddr::V4(ADDRESS)),
                ..proxied(from, to)
            };
            let decided = manager.resolve_session(DIALOG, &facts, &identities, || None);
            assert_eq!(decided.matches[0].direction, SentFromTarget);
            manager
        }

        // The other end then answers, from another address, on the same dialog.
        let manager = from_target(request("BYE"), ALICE_TO_BOB);
        assert_eq!(
            direction_of(&manager, response("BYE", 200), ALICE_TO_BOB),
            SentToTarget
        );
        let manager = from_target(response("INVITE", 200), ALICE_TO_BOB);
        assert_eq!(
            direction_of(&manager, request("ACK"), ALICE_TO_BOB),
            SentToTarget
        );
    }

    /// A session whose deciding message carried no tag cannot place later
    /// messages, and says so rather than guessing.
    #[test]
    fn a_session_without_dialog_tags_reports_the_direction_as_unknown() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);
        let untagged = ("<sip:alice@example.com>", "<sip:bob@example.com>");
        assert_eq!(
            direction_of(&manager, request("OPTIONS"), untagged),
            PayloadDirection::Unknown
        );
    }

    /// The B2BUA's callee leg: siphon's own tag in From, the callee's in To.
    fn callee_leg_response() -> Identities<'static> {
        callee()
    }

    fn callee_leg_request() -> Identities<'static> {
        Identities {
            request_uri: None,
            from_uri: Some("<sip:15550100042@198.51.100.77>;tag=c"),
            to_uri: Some("<sip:15550100001@192.0.2.1>;tag=s"),
            source_ip: None,
        }
    }

    /// The caller answering a request siphon sent it on the caller leg.
    fn caller_leg_response() -> Identities<'static> {
        Identities {
            request_uri: None,
            from_uri: Some("<sip:bob@example.com>;tag=siphon"),
            to_uri: Some("<sip:alice@example.com>;tag=a"),
            source_ip: None,
        }
    }

    /// The directions of a B2BUA call's messages, with the callee leg on
    /// `callee_leg`: its own Call-ID, or the caller leg's when the script
    /// preserves it.
    fn b2bua_directions(manager: &LiManager, callee_leg: &str) -> Vec<PayloadDirection> {
        let internal_id = warranted_call(manager);
        let owner = || Some(owned_by(&internal_id));
        let direction = |view: SessionView| view.matches[0].direction;
        vec![
            direction(manager.resolve_session(CALLER_LEG, &invite(), &caller(), owner)),
            direction(manager.resolve_session(
                callee_leg,
                &response("INVITE", 180),
                &callee_leg_response(),
                owner,
            )),
            direction(manager.resolve_session(
                callee_leg,
                &response("INVITE", 200),
                &callee_leg_response(),
                owner,
            )),
            direction(manager.resolve_session(
                callee_leg,
                &request("BYE"),
                &callee_leg_request(),
                owner,
            )),
            direction(manager.resolve_session(
                CALLER_LEG,
                &response("BYE", 200),
                &caller_leg_response(),
                owner,
            )),
        ]
    }

    /// Caller's INVITE, callee's 180 and 200, callee's BYE, caller's 200 to
    /// the BYE siphon relays: with the caller as target.
    const CALLER_IS_TARGET: [PayloadDirection; 5] = [
        SentFromTarget,
        SentToTarget,
        SentToTarget,
        SentToTarget,
        SentFromTarget,
    ];

    #[test]
    fn the_callee_leg_of_a_b2bua_call_travels_to_a_target_who_called() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);
        assert_eq!(b2bua_directions(&manager, CALLEE_LEG), CALLER_IS_TARGET);
    }

    #[test]
    fn the_callee_leg_of_a_b2bua_call_is_from_a_target_who_was_called() {
        let (manager, _iri, _audit) = manager();
        provision_targets(
            &manager,
            DeliveryType::X2Only,
            None,
            vec![TargetIdentifier::SipUri("sip:bob@example.com".to_string())],
        );
        assert_eq!(
            b2bua_directions(&manager, CALLEE_LEG),
            [
                SentToTarget,
                SentFromTarget,
                SentFromTarget,
                SentFromTarget,
                SentToTarget,
            ]
        );
    }

    /// A script may keep the caller's Call-ID on the callee leg. The legs are
    /// then one Call-ID and still two dialogs, with different tags.
    #[test]
    fn b2bua_legs_sharing_a_call_id_are_still_told_apart() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);
        assert_eq!(b2bua_directions(&manager, CALLER_LEG), CALLER_IS_TARGET);
    }

    /// A warrant activated mid-call and decided on a callee-leg response, whose
    /// From-tag is siphon's own and so anchors nothing.
    #[test]
    fn a_b2bua_session_decided_on_the_callee_leg_anchors_on_the_callees_tag() {
        let (manager, _iri, _audit) = manager();
        provision_targets(
            &manager,
            DeliveryType::X2Only,
            None,
            vec![TargetIdentifier::E164Number("15550100042".to_string())],
        );
        let owner = || Some(owned_by("call-1"));

        let answered = manager.resolve_session(
            CALLEE_LEG,
            &response("INVITE", 200),
            &callee_leg_response(),
            owner,
        );
        assert_eq!(answered.matches[0].direction, SentFromTarget);
        let acked = manager.resolve_session(CALLER_LEG, &request("ACK"), &caller(), owner);
        assert_eq!(acked.matches[0].direction, SentToTarget);
        let hung_up =
            manager.resolve_session(CALLEE_LEG, &request("BYE"), &callee_leg_request(), owner);
        assert_eq!(hung_up.matches[0].direction, SentFromTarget);
    }

    /// The identifier is the session's: a later message that no longer carries
    /// the target was still intercepted because of it.
    #[test]
    fn the_matched_identifier_stays_with_the_session() {
        let (manager, _iri, _audit) = manager();
        provision_targets(
            &manager,
            DeliveryType::X2Only,
            None,
            vec![
                TargetIdentifier::SipUri("sip:carol@example.com".to_string()),
                TargetIdentifier::E164Number("999000000001".to_string()),
            ],
        );
        let number = TargetIdentifier::E164Number("999000000001".to_string());
        let opening = Identities {
            request_uri: Some("sip:bob@example.com"),
            from_uri: Some("<sip:+999000000001@example.com>;tag=a"),
            to_uri: Some("<sip:bob@example.com>"),
            source_ip: None,
        };
        let internal_id = {
            let view = manager.resolve_session(CALLER_LEG, &invite(), &opening, || None);
            assert_eq!(view.matches[0].identifier, number);
            manager
                .reserved_session_id(CALLER_LEG)
                .expect("a reservation")
        };

        let ringing =
            manager.resolve_session(CALLEE_LEG, &response("INVITE", 180), &callee(), || {
                Some(owned_by(&internal_id))
            });
        assert_eq!(
            ringing.matches[0].identifier, number,
            "the callee leg names none of the target's identities"
        );
    }

    #[test]
    fn a_header_tag_is_read_from_the_header_parameters() {
        assert_eq!(header_tag("<sip:alice@example.com>;tag=a"), Some("a"));
        assert_eq!(
            header_tag("\"Alice\" <sip:alice@example.com;user=phone>;x=1; TAG = a9 "),
            Some("a9")
        );
        assert_eq!(header_tag("sip:alice@example.com;tag=a"), Some("a"));
        assert_eq!(header_tag("<sip:alice@example.com>"), None);
        assert_eq!(
            header_tag("<sip:alice@example.com;tag=in-the-uri>"),
            None,
            "a parameter of the URI is not the header's"
        );
        assert_eq!(header_tag("<sip:alice@example.com>;tag="), None);
    }

    fn ack(branch: Option<&'static str>) -> MessageFacts<'static> {
        MessageFacts {
            branch,
            ..request("ACK")
        }
    }

    #[test]
    fn the_ack_of_a_failure_is_told_from_the_ack_of_an_answer() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);
        let opening = manager.resolve_session(CALLER_LEG, &invite(), &caller(), || None);
        manager.note_message(&opening, &invite());

        // RFC 3261 §17.1.1.3: the ACK of a non-2xx carries the INVITE's branch.
        assert!(manager.acknowledges_unanswered_invite(&opening, &ack(Some("z9hG4bK-invite"))));
        // §13.2.2.4: the ACK of a 2xx is its own transaction.
        assert!(!manager.acknowledges_unanswered_invite(&opening, &ack(Some("z9hG4bK-ack"))));
        assert!(!manager.acknowledges_unanswered_invite(&opening, &ack(None)));
        assert!(
            !manager.acknowledges_unanswered_invite(&opening, &invite()),
            "only an ACK acknowledges anything"
        );

        // Once answered, an ACK is never taken for the ACK of a failure,
        // whatever branch a careless sender put on it.
        manager.note_message(&opening, &response("INVITE", 200));
        assert!(!manager.acknowledges_unanswered_invite(&opening, &ack(Some("z9hG4bK-invite"))));
    }

    #[test]
    fn a_branch_without_the_magic_cookie_decides_nothing() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);
        let legacy = MessageFacts {
            branch: Some("1"),
            ..invite()
        };
        let opening = manager.resolve_session(CALLER_LEG, &legacy, &caller(), || None);
        manager.note_message(&opening, &legacy);
        assert!(
            !manager.acknowledges_unanswered_invite(&opening, &ack(Some("1"))),
            "an RFC 2543 branch is not unique, so equality proves nothing"
        );
    }

    #[test]
    fn remembered_invite_branches_are_bounded() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);
        let opening = manager.resolve_session(CALLER_LEG, &invite(), &caller(), || None);
        manager.note_message(&opening, &invite());
        for index in 0..100 {
            let branch = format!("z9hG4bK-re-{index}");
            let re_invite = MessageFacts {
                branch: Some(&branch),
                ..request("INVITE")
            };
            manager.note_message(&opening, &re_invite);
        }
        let remembered = manager
            .decisions
            .get(&*opening.session_id)
            .map(|decision| decision.invite_branches.len());
        assert_eq!(remembered, Some(MAX_INVITE_BRANCHES_PER_SESSION));
        // The newest is the one kept.
        assert!(manager.acknowledges_unanswered_invite(&opening, &ack(Some("z9hG4bK-re-99"))));
    }
}
