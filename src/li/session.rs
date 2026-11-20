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

mod engine_calls;
use engine_calls::MintedEngineCall;
pub use engine_calls::{DialogMedia, EngineCallSide};

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
    /// The top `Via` branches of the INVITEs seen on the session, newest last,
    /// each with whether it was a re-INVITE: what the ACK of a failure
    /// response carries. See [`LiManager::acknowledges_unanswered_invite`].
    invite_branches: Vec<(Box<str>, bool)>,
    /// When the session ended, if it has. It is kept for [`SESSION_GRACE`]
    /// after that, so the stragglers of a teardown still correlate.
    ended_at: Option<Instant>,
    /// The conference seats the session's legs joined, each with whether it
    /// is still held. One that left stays listed so that its content record
    /// is released with the session, as an engine call's is.
    seats: Vec<(Seat, bool)>,
    /// The tag of the party that opened the session's anchoring dialog, when
    /// it is known: the `From` tag of the dialog-forming INVITE, or what the
    /// media path knows the offerer by. It tells which end of the call a later
    /// message's `From` is, on a dialog both ends send on.
    caller_tag: Option<Box<str>>,
    /// The legs a B2BUA call dialled for its called party.
    called_party_legs: Vec<Arc<str>>,
    /// The CANCELs of a re-INVITE whose final response has not come, each by
    /// the Call-ID and CSeq number of its transaction.
    re_invite_cancels: Vec<(Arc<str>, u32)>,
    /// A BYE has ended the session. No response that arrives later (the
    /// answer to a CANCEL that crossed the BYE) makes it live again.
    ended_by_bye: bool,
    /// The engine calls siphon allocated for the session under an id of its
    /// own minting, oldest first: a transfer re-anchors the call's media onto
    /// a fresh engine call and deletes the one the caller's Call-ID named.
    engine_calls: Vec<MintedEngineCall>,
}

/// A seat a party joined a conference room with (`conference_join`, or the
/// answer to a `conference_offer`). No engine call is behind it: the media
/// engine knows it by the room and the tag, and so does its content delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seat {
    /// The room.
    pub conference_id: Arc<str>,
    /// The tag the engine knows the participant by.
    pub tag: Arc<str>,
}

impl Seat {
    /// What the seat's content delivery is recorded under.
    pub fn record(&self) -> String {
        super::content::seat_record(&self.conference_id, &self.tag)
    }
}

impl SessionDecision {
    /// The engine call that holds the session's media now, and whether its
    /// offerer is the session's caller: the newest one siphon minted that the
    /// engine still holds, else the one the anchoring Call-ID names.
    pub(super) fn engine_call(&self) -> (Arc<str>, bool) {
        self.engine_calls
            .iter()
            .rev()
            .find(|minted| minted.live)
            .map_or_else(
                || (Arc::clone(&self.primary_call_id), true),
                |minted| {
                    (
                        Arc::clone(&minted.id),
                        minted.offerer_is_caller(&self.primary_call_id),
                    )
                },
            )
    }

    /// Whether a CANCEL, or a response to one, is of a re-INVITE.
    ///
    /// A CANCEL carries the branch of the request it cancels (RFC 3261 §9.1),
    /// so it is the INVITE with that branch that says. For a branch that
    /// identifies nothing (RFC 2543), or an INVITE no longer remembered, the
    /// request's own `To` does: only a request inside a dialog carries a tag
    /// there, and a CANCEL copies the `To` of the INVITE it cancels.
    fn cancels_a_re_invite(&self, facts: &MessageFacts<'_>) -> bool {
        let cancelled = facts
            .branch
            .filter(|branch| branch.starts_with(BRANCH_MAGIC_COOKIE))
            .and_then(|branch| {
                self.invite_branches
                    .iter()
                    .rev()
                    .find(|(invite_branch, _)| &**invite_branch == branch)
            });
        match cancelled {
            Some((_, re_invite)) => *re_invite,
            None => facts.request && facts.to_tagged,
        }
    }

    /// [`Self::cancels_a_re_invite`], following a CANCEL to its responses.
    ///
    /// A response to a CANCEL cannot be matched to an INVITE by its branch:
    /// through a proxy its top `Via` is the proxy's own, and on a B2BUA leg it
    /// answers a CANCEL siphon sent. It does carry the Call-ID and the CSeq
    /// number of the CANCEL it answers, as every response does (RFC 3261
    /// §8.2.6.2). So each CANCEL of a re-INVITE is remembered by those two
    /// until its final response has come, and a response to a CANCEL is of a
    /// re-INVITE when it answers one of them.
    fn cancel_is_of_a_re_invite(&mut self, facts: &MessageFacts<'_>) -> bool {
        let transaction = facts.cseq.map(|cseq| (facts.call_id, cseq));
        let known = |held: &(Arc<str>, u32)| Some((&*held.0, held.1)) == transaction;
        if facts.request {
            let of_a_re_invite = self.cancels_a_re_invite(facts);
            if let (true, Some((call_id, cseq))) = (of_a_re_invite, transaction) {
                if !self.re_invite_cancels.iter().any(known) {
                    if self.re_invite_cancels.len() >= MAX_INVITE_BRANCHES_PER_SESSION {
                        self.re_invite_cancels.remove(0);
                    }
                    self.re_invite_cancels.push((Arc::from(call_id), cseq));
                }
            }
            return of_a_re_invite;
        }
        let Some(index) = self.re_invite_cancels.iter().position(known) else {
            return self.cancels_a_re_invite(facts);
        };
        if facts.status_code.is_some_and(|code| code >= 200) {
            self.re_invite_cancels.remove(index);
        }
        true
    }

    /// The seats the session's legs hold now.
    fn held_seats(&self) -> Vec<Seat> {
        self.seats
            .iter()
            .filter(|(_, held)| *held)
            .map(|(seat, _)| seat.clone())
            .collect()
    }
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
    /// Further tags the target is known by: the `From` tag of each dialog it
    /// opened into the session after the deciding one.
    target_tags: Vec<Box<str>>,
    /// The Correlation ID the session's records for this warrant carry, from
    /// the first one delivered.
    correlation_id: Option<u64>,
}

/// How many further tags of a target one match remembers.
const MAX_TARGET_TAGS: usize = 8;

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

/// Where a message arrived, for what its tags do not say of its direction.
struct MessageOn<'a> {
    manager: &'a LiManager,
    identities: &'a Identities<'a>,
    /// Whether it is on a leg a B2BUA call dialled for its called party:
    /// only that party sends on it.
    called_party_leg: bool,
}

impl<'a> MessageOn<'a> {
    /// The header that names who sent the message: `From` on a request, `To`
    /// on a response.
    fn sender_identity(&self, sender: &Sender<'_>) -> Option<&'a str> {
        match sender.request {
            true => self.identities.from_uri,
            false => self.identities.to_uri,
        }
    }

    /// The header that names who the message was sent to.
    fn recipient_identity(&self, sender: &Sender<'_>) -> Option<&'a str> {
        match sender.request {
            true => self.identities.to_uri,
            false => self.identities.from_uri,
        }
    }

    /// Whether the warrant `x_id` names the party at `uri`.
    fn names(&self, x_id: XId, uri: Option<&str>) -> bool {
        uri.is_some_and(|uri| self.manager.tasks.index().match_uri(uri).contains(&x_id))
    }
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
            target_tags: Vec::new(),
            correlation_id: None,
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
    fn direction(&self, sender: &Sender<'_>, on: &MessageOn<'_>) -> PayloadDirection {
        // A tag the target is known by on another dialog of the session: its
        // own second dialog, which replaces the first (RFC 3891), carries a
        // tag the anchor never had.
        if sender
            .tag()
            .is_some_and(|tag| self.target_tags.iter().any(|known| &**known == tag))
        {
            return PayloadDirection::SentFromTarget;
        }
        let Some(anchor_tag) = self.anchor_tag.as_deref() else {
            return PayloadDirection::Unknown;
        };
        // On the dialog the anchor is a tag of, the two ends are the anchor's
        // owner and the other one, and the message is from whichever of them
        // its sender tag says.
        let on_the_anchors_dialog =
            sender.from_tag == Some(anchor_tag) || sender.to_tag == Some(anchor_tag);
        if on_the_anchors_dialog {
            let sent_by_anchor_owner = sender.tag() == Some(anchor_tag);
            return match sent_by_anchor_owner == self.target_owns_anchor {
                true => PayloadDirection::SentFromTarget,
                false => PayloadDirection::SentToTarget,
            };
        }
        // Another dialog of the session, with tags of its own. "Not the
        // anchor's owner" says nothing there when the anchor is the other
        // end's: a transfer's third party is not the anchor's owner either,
        // and is not the target. So only what is positively known decides:
        // who the message itself names as its sender, the target having sent
        // under the anchor and not under this tag, the leg being the one
        // dialled for the party the warrant names, who the message is
        // addressed to. With none of them the direction is not known, and is
        // reported so (1), never guessed.
        let x_id = self.x_id;
        if on.names(x_id, on.sender_identity(sender)) {
            return PayloadDirection::SentFromTarget;
        }
        if self.target_owns_anchor {
            return PayloadDirection::SentToTarget;
        }
        if on.called_party_leg && self.party == MatchedParty::Terminating {
            return PayloadDirection::SentFromTarget;
        }
        if on.names(x_id, on.recipient_identity(sender)) {
            return PayloadDirection::SentToTarget;
        }
        PayloadDirection::Unknown
    }

    /// The match as a caller that is not a message sees it (the media path):
    /// no message, so no direction.
    fn task_match_of_no_message(&self, manager: &LiManager) -> Option<TaskMatch> {
        manager.tasks.get(self.x_id).map(|task| TaskMatch {
            task,
            party: self.party,
            identifier: self.identifier.clone(),
            field: self.field,
            direction: PayloadDirection::Unknown,
        })
    }

    /// The match as delivery sees it for `sender`'s message, re-reading the
    /// task so a `ModifyTask` is honoured on the very next message.
    fn task_match(
        &self,
        manager: &LiManager,
        sender: &Sender<'_>,
        on: &MessageOn<'_>,
    ) -> Option<TaskMatch> {
        manager.tasks.get(self.x_id).map(|task| TaskMatch {
            task,
            party: self.party,
            identifier: self.identifier.clone(),
            field: self.field,
            direction: self.direction(sender, on),
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
    /// The message's Call-ID and the number of its CSeq, which with the
    /// method name a transaction end to end: a response carries both as its
    /// request did, through any number of proxies, where its top `Via` is
    /// only the last hop's.
    pub call_id: &'a str,
    pub cseq: Option<u32>,
}

impl MessageFacts<'_> {
    /// A message whose shape is unknown, which opens nothing and ends nothing.
    pub const UNKNOWN: MessageFacts<'static> = MessageFacts {
        request: false,
        method: "",
        status_code: None,
        to_tagged: true,
        branch: None,
        call_id: "",
        cseq: None,
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
    /// Whether the leg was dialled to replace a party of the call (a transfer
    /// target, a dialog taking a leg over with `Replaces`) rather than for
    /// the call's called party. Who sends on such a leg is somebody new.
    pub replacement_target: bool,
}

impl CallOwner {
    /// Whether `call_id` is a leg this call dialled for its called party.
    fn dialled_for_called_party(&self, call_id: &str) -> bool {
        !self.replacement_target && self.a_leg_call_id != call_id
    }
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
    /// Whether the offerer of that engine call, which the engine takes for
    /// the caller, is the session's caller. It is on the engine call the
    /// caller's own offer made; not on one a transfer offered with the
    /// called party's media.
    pub offerer_is_caller: bool,
    /// The warrants covering the session.
    pub matches: Vec<TaskMatch>,
    /// The conference seats the session's legs joined.
    pub seats: Vec<Seat>,
}

impl SessionView {
    fn unwarranted(call_id: &str) -> Self {
        let call_id: Arc<str> = Arc::from(call_id);
        Self {
            session_id: Arc::clone(&call_id),
            engine_call_id: call_id,
            offerer_is_caller: true,
            on_primary_leg: true,
            matches: Vec::new(),
            seats: Vec::new(),
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
        self.resolve_session_with(call_id, facts, identities, owner, || None)
    }

    /// [`resolve_session`](Self::resolve_session), with somewhere to ask the
    /// tag of the party that opened the dialog.
    ///
    /// Which end of a call a warrant names is which end the matched identity
    /// is on, and a message says that only relative to whoever sent it: a
    /// re-INVITE or a BYE from the far end carries the caller in `To`, and a
    /// response carries the headers of the request it answers. So the party is
    /// turned by which end the message's `From` is. On a B2BUA call the leg
    /// says it. On a dialog both ends send on it is the tag: the one the
    /// dialog-forming INVITE carried when this node saw it, else `caller_tag`,
    /// which is asked only for a match on a message that opens nothing, in a
    /// session nothing is remembered of. With none of them the `From` is
    /// taken for the caller, as it is on the INVITE.
    pub fn resolve_session_with(
        &self,
        call_id: &str,
        facts: &MessageFacts<'_>,
        identities: &Identities<'_>,
        owner: impl FnOnce() -> Option<CallOwner>,
        media: impl FnOnce() -> Option<DialogMedia>,
    ) -> SessionView {
        if !self.is_intercepting() {
            return SessionView::unwarranted(call_id);
        }
        let generation = self.tasks.generation();
        let sender = Sender::of(facts, identities);
        let mut caller_tag_known: Option<Box<str>> = None;
        // The engine calls siphon minted for the dialog, as an earlier
        // decision knew them: a decision replaced by one a warrant now covers
        // hands them on.
        let mut minted: Vec<MintedEngineCall> = Vec::new();

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
            if let Some(view) = self.refresh(
                &session_id,
                call_id,
                generation,
                facts,
                identities,
                &sender,
                &mut (&mut caller_tag_known, &mut minted),
            ) {
                return view;
            }
        }

        // A Call-ID not seen before: the first message of a session, or of
        // another leg of one.
        let owner = owner();
        if let Some(owner) = owner.as_ref() {
            if let Some(session_id) = self.warranted_session_of(owner) {
                self.alias(call_id, &session_id);
                if owner.dialled_for_called_party(call_id) {
                    self.note_called_party_leg(&session_id, call_id);
                }
                if facts.opens_dialog() {
                    self.learn_target_tag(&session_id, identities, &sender);
                }
                if let Some(view) = self.refresh(
                    &session_id,
                    call_id,
                    generation,
                    facts,
                    identities,
                    &sender,
                    &mut (&mut None, &mut Vec::new()),
                ) {
                    return view;
                }
            }
        }

        let mut matches = self.tasks.match_message(
            identities.request_uri,
            identities.from_uri,
            identities.to_uri,
            identities.source_ip,
        );
        // What an unwarranted decision of the dialog, or of the call's
        // anchoring dialog, knew: both are replaced by the one made here.
        let anchoring = owner.as_ref().map(|owner| owner.a_leg_call_id.as_str());
        for leg in [Some(call_id), anchoring].into_iter().flatten() {
            if let Some(decision) = self.decisions.get(leg) {
                if decision.matched.is_empty() {
                    minted.extend(decision.engine_calls.iter().cloned());
                }
            }
        }
        // A warrant that starts in the middle of a call nothing is remembered
        // of: the media path says where the call's media is, and who offered.
        let known_to_media = (!facts.opens_dialog() && !matches.is_empty())
            .then(media)
            .flatten()
            .unwrap_or_default();
        if minted.is_empty() {
            if let Some((engine_call_id, offerer_dialog)) = known_to_media.minted {
                minted.push(MintedEngineCall {
                    id: Arc::from(engine_call_id),
                    live: true,
                    dialog: Arc::from(offerer_dialog),
                    side: EngineCallSide::Offerer,
                });
            }
        }
        let caller_is_in_from = if facts.opens_dialog() {
            caller_tag_known = sender.from_tag.map(Box::from);
            Some(true)
        } else if let Some(owner) = owner.as_ref() {
            Some(leg_from_is_caller(facts, call_id == owner.a_leg_call_id))
        } else {
            if caller_tag_known.is_none() {
                caller_tag_known = known_to_media.offerer_tag.map(String::into_boxed_str);
            }
            sender
                .from_tag
                .zip(caller_tag_known.as_deref())
                .map(|(from, caller)| from == caller)
        };
        orient(&mut matches, facts, caller_is_in_from);
        let decided: Vec<SessionMatch> = matches
            .iter()
            .map(|matched| SessionMatch::decided_on(matched, &sender, owner.is_some()))
            .collect();
        let called_party_leg = owner
            .as_ref()
            .is_some_and(|owner| owner.dialled_for_called_party(call_id));
        let on = MessageOn {
            manager: self,
            identities,
            called_party_leg,
        };
        let matches = decided
            .iter()
            .zip(matches)
            .map(|(decided, matched)| TaskMatch {
                direction: decided.direction(&sender, &on),
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
            caller_tag_known,
        );
        if called_party_leg {
            self.note_called_party_leg(&session_id, &call_id);
        }
        let (engine_call_id, offerer_is_caller) = match matches.is_empty() {
            true => (Arc::clone(&primary_call_id), true),
            false => self.hand_on_engine_calls(&session_id, minted, &primary_call_id),
        };
        SessionView {
            on_primary_leg: primary_call_id == call_id,
            session_id,
            engine_call_id,
            offerer_is_caller,
            matches,
            seats: Vec::new(),
        }
    }

    /// The Correlation ID the session `session_id` uses for the warrant
    /// `x_id`: the one it already uses, else `fresh`, which it uses from now
    /// on. `fresh` for a session with no decision to keep it in.
    pub(super) fn session_correlation(&self, session_id: &str, x_id: XId, fresh: u64) -> u64 {
        let Some(mut decision) = self.decisions.get_mut(session_id) else {
            return fresh;
        };
        match decision.matched.iter_mut().find(|known| known.x_id == x_id) {
            Some(known) => *known.correlation_id.get_or_insert(fresh),
            None => fresh,
        }
    }

    /// `call_id` is a leg the session's call dialled for its called party.
    fn note_called_party_leg(&self, session_id: &Arc<str>, call_id: &str) {
        if let Some(mut decision) = self.decisions.get_mut(&**session_id) {
            if !decision
                .called_party_legs
                .iter()
                .any(|leg| &**leg == call_id)
            {
                decision.called_party_legs.push(Arc::from(call_id));
            }
        }
    }

    /// A dialog-forming request joined the session on a Call-ID of its own:
    /// where its `From` is the target of a warrant covering the session, its
    /// tag is one more the target sends under.
    fn learn_target_tag(
        &self,
        session_id: &Arc<str>,
        identities: &Identities<'_>,
        sender: &Sender<'_>,
    ) {
        let (Some(from), Some(tag)) = (identities.from_uri, sender.from_tag) else {
            return;
        };
        let named = self.tasks.index().match_uri(from);
        if named.is_empty() {
            return;
        }
        let Some(mut decision) = self.decisions.get_mut(&**session_id) else {
            return;
        };
        for known in &mut decision.matched {
            if named.contains(&known.x_id)
                && known.target_tags.len() < MAX_TARGET_TAGS
                && !known.target_tags.iter().any(|held| &**held == tag)
            {
                known.target_tags.push(Box::from(tag));
            }
        }
    }

    /// Record that the leg `sip_call_id` joined a conference room as `seat`,
    /// when a warrant covers its session. The session as it then is.
    pub fn note_seat(&self, sip_call_id: &str, seat: Seat) -> Option<SessionView> {
        let session_id = self.session_id_of(sip_call_id)?;
        {
            let mut decision = self.decisions.get_mut(&*session_id)?;
            if decision.matched.is_empty() {
                return None;
            }
            decision.seats.retain(|(held, _)| *held != seat);
            decision.seats.push((seat, true));
        }
        self.session_of_leg(sip_call_id)
    }

    /// The leg `sip_call_id` is leaving the room it joined as `seat`.
    pub fn seat_left(&self, sip_call_id: &str, seat: &Seat) {
        let Some(session_id) = self.session_id_of(sip_call_id) else {
            return;
        };
        if let Some(mut decision) = self.decisions.get_mut(&*session_id) {
            for (held, seated) in &mut decision.seats {
                if held == seat {
                    *seated = false;
                }
            }
        }
    }

    /// The session `call_id` resolves to, if any message resolved it.
    fn session_id_of(&self, call_id: &str) -> Option<Arc<str>> {
        self.aliases
            .get(call_id)
            .map(|alias| Arc::clone(alias.value()))
            .or_else(|| {
                self.decisions
                    .get(call_id)
                    .map(|decision| Arc::clone(decision.key()))
            })
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

        // A CANCEL ends the session only when it cancels the INVITE that
        // opened it. One that cancels a re-INVITE withdraws a change to a call
        // that goes on (RFC 3261 §9.1, §14.1), and so does every response to
        // it: its 200, and a 481 from a far end that had already answered the
        // re-INVITE.
        let cancels_a_re_invite = facts.method == "CANCEL"
            && decision
                .as_deref_mut()
                .is_some_and(|decision| decision.cancel_is_of_a_re_invite(facts));
        let event_type = if facts.request {
            match facts.method {
                "INVITE" if !facts.to_tagged => IriEventType::Begin,
                "CANCEL" if cancels_a_re_invite => IriEventType::Continue,
                "BYE" | "CANCEL" => IriEventType::End,
                "REGISTER" | "MESSAGE" | "SUBSCRIBE" | "PUBLISH" | "OPTIONS" => {
                    IriEventType::Report
                }
                _ => IriEventType::Continue,
            }
        } else {
            match facts.status_code {
                Some(code) if code >= 300 && cancels_a_re_invite => IriEventType::Continue,
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
                decision
                    .invite_branches
                    .push((Box::from(branch), facts.to_tagged));
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

        let ends = (matches!(facts.method, "BYE" | "CANCEL") && !cancels_a_re_invite)
            || (!facts.request && event_type == IriEventType::End);
        if facts.method == "BYE" {
            decision.ended_by_bye = true;
        }
        if ends {
            decision.ended_at.get_or_insert_with(Instant::now);
            // What was outstanding went with the session.
            decision.re_invite_cancels.clear();
        } else if !(facts.request && facts.method == "ACK")
            && !(decision.ended_by_bye && !facts.request)
        {
            // Something that is not part of a teardown: the session is live.
            // An ACK is neither, since the ACK of a failure follows the end.
            // Nor is a response once a BYE has ended the session: the answer
            // to a request that crossed the BYE says nothing of the call.
            decision.ended_at = None;
        }
        event_type
    }

    /// Whether an ACK acknowledges a failure response to an INVITE, so there
    /// is no media session of that INVITE's to deliver.
    ///
    /// Interception sees every ACK, because it runs ahead of the transaction
    /// layer that would absorb this one. RFC 3261 tells the two kinds apart by
    /// transaction: the ACK of a non-2xx final belongs to the INVITE's and
    /// carries its branch (§17.1.1.3), the ACK of a 2xx is a transaction of its
    /// own with a new one (§13.2.2.4). That holds whoever sent the failure, a
    /// far end through a proxy or siphon itself as a B2BUA, where no failure
    /// response ever arrives on the caller's leg to be noticed.
    ///
    /// Decided per INVITE, on the branch the ACK carries. For a re-INVITE that
    /// is the whole of it: its ACK on its own branch is the ACK of its
    /// rejection, whatever the session's state. For the INVITE that opened the
    /// session one doubt resolves to `false`, which attaches: a sender that
    /// reuses that INVITE's branch on the ACK of its 2xx is wrong, but its
    /// call was answered and its content is owed, so the branch decides only
    /// while no 2xx has been seen. A branch without the magic cookie
    /// identifies nothing.
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
                decision
                    .invite_branches
                    .iter()
                    .any(|(invite_branch, re_invite)| {
                        &**invite_branch == branch && (*re_invite || !decision.established)
                    })
            })
    }

    /// The warranted session `call_id` is a leg of, as interception last
    /// decided it. `None` for a Call-ID no message has been intercepted on.
    ///
    /// For a caller that is not a message: the media path, told that a leg was
    /// offered to the engine. Nothing is matched or decided here, so a warrant
    /// provisioned since the session's last message is picked up by its next
    /// message, as before.
    pub fn session_of_leg(&self, call_id: &str) -> Option<SessionView> {
        let session_id = self.session_id_of(call_id)?;
        let decision = self.decisions.get(&*session_id)?;
        let matches = decision
            .matched
            .iter()
            .filter_map(|known| known.task_match_of_no_message(self))
            .collect();
        Some(SessionView {
            on_primary_leg: &*decision.primary_call_id == call_id,
            engine_call_id: decision.engine_call().0,
            offerer_is_caller: decision.engine_call().1,
            session_id: Arc::clone(&session_id),
            matches,
            seats: decision.held_seats(),
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
            // The engine call's content record goes with its session. Asked
            // whatever the session matches now: a warrant deactivated since
            // may have left one.
            self.forget_x3_call(&decision.primary_call_id);
            for (seat, _) in &decision.seats {
                self.forget_x3_call(&seat.record());
            }
            self.release_engine_calls(session_id, &decision.engine_calls);
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
            self.minted_engine_calls.clear();
            self.forget_idle_x3_calls();
            return;
        }
        let mut released = Vec::new();
        for mut decision in self.decisions.iter_mut() {
            if decision.bound_to_call {
                let live = call_is_live(decision.key());
                if live {
                    // A dialog of the call ended and the call did not: a leg
                    // that was replaced, or merged away into a conference. The
                    // session is the call's, and goes on with it.
                    decision.ended_at = None;
                } else if decision.ended_at.is_none() {
                    decision.ended_at = Some(now);
                }
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
        facts: &MessageFacts<'_>,
        identities: &Identities<'_>,
        sender: &Sender<'_>,
        carried: &mut (&mut Option<Box<str>>, &mut Vec<MintedEngineCall>),
    ) -> Option<SessionView> {
        let mut decision = self.decisions.get_mut(&**session_id)?;
        if decision.generation != generation {
            let mut fresh = self.tasks.match_message(
                identities.request_uri,
                identities.from_uri,
                identities.to_uri,
                identities.source_ip,
            );
            if decision.matched.is_empty() && !fresh.is_empty() {
                // What the old decision knew of the caller carries over.
                *carried.0 = decision.caller_tag.take();
                carried.1.extend(decision.engine_calls.iter().cloned());
                drop(decision);
                self.forget_session(session_id);
                return None;
            }
            let caller_is_in_from = if decision.bound_to_call {
                Some(leg_from_is_caller(
                    facts,
                    &*decision.primary_call_id == call_id,
                ))
            } else {
                sender
                    .from_tag
                    .zip(decision.caller_tag.as_deref())
                    .map(|(from, caller)| from == caller)
            };
            orient(&mut fresh, facts, caller_is_in_from);
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
        let on = MessageOn {
            manager: self,
            identities,
            called_party_leg: decision
                .called_party_legs
                .iter()
                .any(|leg| &**leg == call_id),
        };
        // Re-read each task rather than trusting a cached copy, so a
        // ModifyTask that changed a delivery type or a destination is
        // honoured on the very next message.
        let matches = decision
            .matched
            .iter()
            .filter_map(|known| known.task_match(self, sender, &on))
            .collect();
        Some(SessionView {
            session_id: Arc::clone(session_id),
            on_primary_leg: &*decision.primary_call_id == call_id,
            engine_call_id: decision.engine_call().0,
            offerer_is_caller: decision.engine_call().1,
            matches,
            seats: decision.held_seats(),
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
        caller_tag: Option<Box<str>>,
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
            self.minted_engine_calls.clear();
            self.forget_idle_x3_calls();
        }
        // A leg that had a decision of its own (unwarranted, from before the
        // warrant) is now part of this session.
        for leg in [call_id, primary_call_id] {
            if leg != session_id {
                // What it knew of minted engine calls was handed on already;
                // the bindings under its own id go with it.
                if let Some((_, replaced)) = self.decisions.remove(&**leg) {
                    self.release_engine_calls(leg, &replaced.engine_calls);
                }
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
                seats: Vec::new(),
                caller_tag,
                called_party_legs: Vec::new(),
                re_invite_cancels: Vec::new(),
                ended_by_bye: false,
                engine_calls: Vec::new(),
            },
        );
        self.alias(primary_call_id, session_id);
        self.alias(call_id, session_id);
    }
}

/// Whether the `From` of a message that arrived on a leg of a B2BUA call is
/// the calling end. Only the party of a leg sends on it, so what arrives on
/// the caller's leg is the caller's: its requests carry it in `From`, and its
/// responses carry the headers of a request sent toward it.
fn leg_from_is_caller(facts: &MessageFacts<'_>, on_caller_leg: bool) -> bool {
    let response = !facts.request && facts.status_code.is_some();
    on_caller_leg != response
}

/// Turn each match from the end of the *message* it was found on into the end
/// of the *call* that end is.
///
/// A match reads `From` as the originating end, which holds for the request
/// that opens the dialog and for nothing sent the other way. A source address
/// names whoever sent the message: the `From` of a request, the `To` of a
/// response. `caller_is_in_from` unknown is taken as it is on the INVITE.
fn orient(matches: &mut [TaskMatch], facts: &MessageFacts<'_>, caller_is_in_from: Option<bool>) {
    let caller_is_in_from = caller_is_in_from.unwrap_or(true);
    let response = !facts.request && facts.status_code.is_some();
    if caller_is_in_from && !response {
        return;
    }
    for matched in matches {
        let on_from_side = match matched.field {
            MatchedField::From => true,
            MatchedField::RequestUri | MatchedField::To => false,
            MatchedField::SourceAddress => !response,
        };
        matched.party = if on_from_side == caller_is_in_from {
            MatchedParty::Originating
        } else {
            MatchedParty::Terminating
        };
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
            call_id: "",
            cseq: None,
        }
    }

    fn response(method: &'static str, code: u16) -> MessageFacts<'static> {
        MessageFacts {
            request: false,
            method,
            status_code: Some(code),
            to_tagged: true,
            branch: None,
            call_id: "",
            cseq: None,
        }
    }

    fn request(method: &'static str) -> MessageFacts<'static> {
        MessageFacts {
            request: true,
            method,
            status_code: None,
            to_tagged: true,
            branch: None,
            call_id: "",
            cseq: None,
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
            replacement_target: false,
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
                replacement_target: false,
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

        // Once answered, an ACK is never taken for the ACK of the opening
        // INVITE's failure, whatever branch a careless sender put on it.
        manager.note_message(&opening, &response("INVITE", 200));
        assert!(!manager.acknowledges_unanswered_invite(&opening, &ack(Some("z9hG4bK-invite"))));
    }

    #[test]
    fn the_ack_of_a_rejected_re_invite_is_the_ack_of_a_failure() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);
        let opening = manager.resolve_session(CALLER_LEG, &invite(), &caller(), || None);
        manager.note_message(&opening, &invite());
        manager.note_message(&opening, &response("INVITE", 200));

        let re_invite = MessageFacts {
            branch: Some("z9hG4bK-re-invite"),
            ..request("INVITE")
        };
        manager.note_message(&opening, &re_invite);
        manager.note_message(&opening, &response("INVITE", 488));
        assert!(
            manager.acknowledges_unanswered_invite(&opening, &ack(Some("z9hG4bK-re-invite"))),
            "RFC 3261 §17.1.1.3: an ACK on the re-INVITE's branch acknowledges its rejection"
        );
        // An accepted re-INVITE is ACKed on a branch of its own (§13.2.2.4).
        assert!(!manager.acknowledges_unanswered_invite(&opening, &ack(Some("z9hG4bK-re-ack"))));
    }

    #[test]
    fn a_leg_resolves_to_its_session_without_a_message() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);
        assert!(manager.session_of_leg(CALLER_LEG).is_none(), "never seen");

        let internal_id = warranted_call(&manager);
        let caller_leg = manager.session_of_leg(CALLER_LEG).expect("a session");
        assert_eq!(&*caller_leg.session_id, internal_id.as_str());
        assert!(caller_leg.on_primary_leg);
        assert_eq!(caller_leg.matches.len(), 1);

        manager.resolve_session(CALLEE_LEG, &response("INVITE", 180), &callee(), || {
            Some(owned_by(&internal_id))
        });
        let callee_leg = manager.session_of_leg(CALLEE_LEG).expect("a session");
        assert_eq!(callee_leg.session_id, caller_leg.session_id);
        assert!(!callee_leg.on_primary_leg);
        assert_eq!(&*callee_leg.engine_call_id, CALLER_LEG);
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

    // ── A dialog of a call ending while the call goes on ────────────────────

    /// A leg merged into a conference is sent a BYE and answers it, and the
    /// call lives on with the far party seated. The session is the call's.
    #[test]
    fn a_dialog_of_a_live_call_ending_does_not_end_the_calls_session() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);
        let internal_id = warranted_call(&manager);
        let view = manager.resolve_session(CALLER_LEG, &response("BYE", 200), &caller(), || None);
        manager.note_message(&view, &response("BYE", 200));

        let later = Instant::now() + SESSION_GRACE * 4;
        manager.sweep_sessions(later, |id| id == internal_id);
        manager.sweep_sessions(later + SESSION_GRACE * 4, |id| id == internal_id);
        assert_eq!(manager.remembered_session_count(), 1, "the call is live");

        // The call ends: the session goes after its grace, as any does.
        manager.sweep_sessions(later, |_| false);
        manager.sweep_sessions(later + SESSION_GRACE, |_| false);
        assert_eq!(manager.remembered_session_count(), 0);
        assert_eq!(manager.session_alias_count(), 0);
    }

    // ── Conference seats ────────────────────────────────────────────────────

    fn seat(room: &str) -> Seat {
        Seat {
            conference_id: Arc::from(room),
            tag: Arc::from("a"),
        }
    }

    #[test]
    fn a_session_learns_the_seat_its_leg_joined_and_forgets_it_when_it_leaves() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2AndX3, None);
        assert!(
            manager.note_seat(CALLER_LEG, seat("room-1")).is_none(),
            "a leg no message was intercepted on has no session"
        );
        manager.resolve_session(CALLER_LEG, &invite(), &caller(), || None);

        let seated = manager
            .note_seat(CALLER_LEG, seat("room-1"))
            .expect("the session");
        assert_eq!(seated.seats, vec![seat("room-1")]);
        let again = manager.resolve_session(CALLER_LEG, &request("ACK"), &caller(), || None);
        assert_eq!(
            again.seats,
            vec![seat("room-1")],
            "every later message sees it"
        );

        manager.seat_left(CALLER_LEG, &seat("room-1"));
        let left = manager.resolve_session(CALLER_LEG, &request("INFO"), &caller(), || None);
        assert!(left.seats.is_empty());
        // Seated again elsewhere.
        manager.note_seat(CALLER_LEG, seat("room-2"));
        let moved = manager.session_of_leg(CALLER_LEG).expect("the session");
        assert_eq!(moved.seats, vec![seat("room-2")]);
    }

    #[test]
    fn an_unwarranted_session_keeps_no_seat() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2AndX3, None);
        manager.resolve_session(CALLEE_LEG, &invite(), &callee(), || None);
        assert!(manager.note_seat(CALLEE_LEG, seat("room-1")).is_none());
    }

    /// The per-module leak gate for seats: every seat's content record is
    /// released with its session, the ones that left included.
    #[test]
    fn seat_records_are_released_with_their_sessions() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2AndX3, None);
        for index in 0..200 {
            let leg = format!("seated-{index}@example.com");
            let view = manager.resolve_session(&leg, &invite(), &caller(), || None);
            for room in ["first", "second"] {
                let seat = seat(&format!("{room}-{index}"));
                manager.note_seat(&leg, seat.clone());
                let record = seat.record();
                let attempt = manager.x3_attempt(&record, None);
                manager.register_x3_attachment(
                    &record,
                    crate::li::ActiveIntercept {
                        x_id: view.matches[0].task.details.x_id,
                        d_id: view.matches[0].task.details.list_of_dids[0],
                        from_tag: "a".to_string(),
                        correlation_id: 7,
                        session_id: Arc::clone(&view.session_id),
                        scope: None,
                    },
                    attempt,
                );
                manager.x3_media_ended_by_siphon(&record, None);
                manager.seat_left(&leg, &seat);
                assert!(manager.x3_delivery_ended(&record, None).by_siphon);
            }
            manager.note_message(&view, &request("BYE"));
        }
        assert_eq!(manager.x3_attachment_count(), 0);
        assert_eq!(manager.x3_call_count(), 400, "kept while the sessions are");
        manager.sweep_sessions(Instant::now() + SESSION_GRACE, |_| false);
        assert_eq!(manager.remembered_session_count(), 0);
        assert_eq!(manager.x3_call_count(), 0, "seat records drain");
    }

    // ── Which end of the call a warrant names ───────────────────────────────

    /// A request from the far end of alice's call: alice is in `To`.
    fn from_the_far_end() -> Identities<'static> {
        Identities {
            request_uri: Some("sip:alice@192.0.2.10"),
            from_uri: Some("<sip:bob@example.com>;tag=b"),
            to_uri: Some("<sip:alice@example.com>;tag=a"),
            source_ip: None,
        }
    }

    fn party(view: &SessionView) -> MatchedParty {
        assert_eq!(view.matches.len(), 1, "the warrant covers the session");
        view.matches[0].party
    }

    /// Nothing was provisioned when the call was set up, so nothing is
    /// remembered of it. The warrant arrives, and the first message after it
    /// is the far end's: the target is in `To`, and is still the caller.
    #[test]
    fn a_mid_call_warrant_decided_on_a_far_end_request_names_the_caller() {
        let (manager, _iri, _audit) = manager();
        manager.resolve_session(CALLER_LEG, &invite(), &caller(), || None);
        provision(&manager, DeliveryType::X2AndX3, None);

        let view = manager.resolve_session_with(
            CALLER_LEG,
            &request("BYE"),
            &from_the_far_end(),
            || None,
            || {
                Some(DialogMedia {
                    offerer_tag: Some("a".to_string()),
                    minted: None,
                })
            },
        );
        assert_eq!(party(&view), MatchedParty::Originating);
    }

    /// With another warrant already provisioned the call's opening was seen,
    /// and the caller's tag is remembered from it: nothing has to be asked.
    #[test]
    fn the_callers_tag_is_remembered_from_the_invite() {
        let (manager, _iri, _audit) = manager();
        let other = provision(&manager, DeliveryType::X2Only, None);
        let mut carol = manager.tasks().get(other).expect("a task").details.clone();
        manager.tasks().deactivate(other).expect("must deactivate");
        carol.target_identifiers = vec![crate::li::x1::types::TargetIdentifier::SipUri(
            "sip:carol@example.com".to_string(),
        )];
        manager.tasks().activate(carol).expect("must provision");
        let opening = manager.resolve_session(CALLER_LEG, &invite(), &caller(), || None);
        assert!(opening.matches.is_empty(), "nobody names alice yet");

        provision(&manager, DeliveryType::X2AndX3, None);
        let view =
            manager.resolve_session(CALLER_LEG, &request("BYE"), &from_the_far_end(), || None);
        assert_eq!(party(&view), MatchedParty::Originating);
    }

    /// A response carries the headers of the request it answers: the caller's
    /// 200 to the far end's re-INVITE has the caller in `To` as well.
    #[test]
    fn a_mid_call_warrant_decided_on_a_response_names_the_caller() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2AndX3, None);
        let view = manager.resolve_session_with(
            CALLER_LEG,
            &response("INVITE", 200),
            &from_the_far_end(),
            || None,
            || {
                Some(DialogMedia {
                    offerer_tag: Some("a".to_string()),
                    minted: None,
                })
            },
        );
        assert_eq!(party(&view), MatchedParty::Originating);
    }

    /// With nothing to tell the ends apart the `From` is taken for the caller,
    /// as it is on the INVITE.
    #[test]
    fn a_dialog_nothing_is_known_of_is_read_as_its_headers_say() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2AndX3, None);
        let view =
            manager.resolve_session(CALLER_LEG, &request("BYE"), &from_the_far_end(), || None);
        assert_eq!(party(&view), MatchedParty::Terminating);
    }

    /// On a B2BUA call the leg says which end sent a message. A warrant on the
    /// caller that is decided on the callee's leg, where a transparent B2BUA
    /// left the caller's identity in place, names the caller whether the
    /// deciding message is the callee's request or its response.
    #[test]
    fn a_mid_call_warrant_decided_on_the_callee_leg_names_the_caller() {
        for facts in [request("INFO"), response("INVITE", 200)] {
            let (manager, _iri, _audit) = manager();
            provision(&manager, DeliveryType::X2AndX3, None);
            // The callee's request carries the caller in `To`; its response
            // carries the request siphon sent it, with the caller in `From`.
            let identities = match facts.request {
                true => from_the_far_end(),
                false => caller(),
            };
            let view = manager
                .resolve_session(CALLEE_LEG, &facts, &identities, || Some(owned_by("call-1")));
            assert_eq!(
                party(&view),
                MatchedParty::Originating,
                "request={}",
                facts.request
            );
        }
    }

    /// The target's own second dialog into the call (an INVITE that replaces
    /// its first, RFC 3891) carries a tag the session never saw. What it
    /// sends there is from the target, and a third party doing the same is
    /// not.
    #[test]
    fn a_dialog_the_target_opens_into_its_call_is_sent_from_the_target() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);
        let internal_id = warranted_call(&manager);
        let joining = |leg: &str, from: &'static str| {
            let identities = Identities {
                request_uri: Some("sip:bob@example.com"),
                from_uri: Some(from),
                to_uri: Some("<sip:bob@example.com>"),
                source_ip: None,
            };
            let view = manager
                .resolve_session(leg, &invite(), &identities, || Some(owned_by(&internal_id)));
            assert_eq!(&*view.session_id, internal_id.as_str());
            view.matches[0].direction
        };
        assert_eq!(
            joining(
                "second-device@example.com",
                "<sip:alice@example.com>;tag=a2"
            ),
            SentFromTarget
        );
        assert_eq!(
            joining("third-party@example.com", "<sip:carol@example.com>;tag=c"),
            SentToTarget
        );
        // And its later requests on that dialog.
        let later = manager.resolve_session(
            "second-device@example.com",
            &request("BYE"),
            &proxied(
                "<sip:alice@example.com>;tag=a2",
                "<sip:bob@example.com>;tag=s",
            ),
            || None,
        );
        assert_eq!(later.matches[0].direction, SentFromTarget);
    }

    /// The facts of a message of the transaction `cseq` on the caller's
    /// dialog.
    fn transaction(facts: MessageFacts<'static>, cseq: u32) -> MessageFacts<'static> {
        MessageFacts {
            call_id: CALLER_LEG,
            cseq: Some(cseq),
            ..facts
        }
    }

    /// An established session with a re-INVITE in progress, CSeq 2.
    fn established_with_a_re_invite(manager: &LiManager) -> SessionView {
        let view = manager.resolve_session(CALLER_LEG, &invite(), &caller(), || None);
        manager.note_message(&view, &invite());
        manager.note_message(&view, &response("INVITE", 200));
        let re_invite = MessageFacts {
            branch: Some("z9hG4bK-re-invite"),
            ..transaction(request("INVITE"), 2)
        };
        manager.note_message(&view, &re_invite);
        view
    }

    /// The CANCEL of the re-INVITE with CSeq `cseq`.
    fn cancel_of_re_invite(cseq: u32) -> MessageFacts<'static> {
        MessageFacts {
            branch: Some("z9hG4bK-re-invite"),
            ..transaction(request("CANCEL"), cseq)
        }
    }

    /// A response to a CANCEL as a proxy receives it: the transaction's
    /// Call-ID and CSeq, and a top Via that is the proxy's own.
    fn cancel_response(code: u16, cseq: u32) -> MessageFacts<'static> {
        MessageFacts {
            branch: Some("z9hG4bK-the-proxys-own"),
            ..transaction(response("CANCEL", code), cseq)
        }
    }

    /// A CANCEL of a re-INVITE withdraws a change to a call that goes on. It
    /// is not the end of the session, and neither is any response to it; the
    /// CANCEL of the INVITE that opened the session is.
    #[test]
    fn a_cancel_ends_the_session_only_when_it_cancels_the_opening_invite() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);
        let view = established_with_a_re_invite(&manager);

        assert_eq!(
            manager.note_message(&view, &cancel_of_re_invite(2)),
            IriEventType::Continue
        );
        assert_eq!(
            manager.note_message(&view, &cancel_response(481, 2)),
            IriEventType::Continue,
            "a 481 to it, from a far end that had answered the re-INVITE"
        );
        manager.sweep_sessions(Instant::now() + SESSION_GRACE * 2, |_| false);
        assert_eq!(
            manager.remembered_session_count(),
            1,
            "the session did not end"
        );

        // The CANCEL of the opening INVITE: its branch, and no To-tag.
        let opening = MessageFacts {
            to_tagged: false,
            branch: Some("z9hG4bK-invite"),
            ..transaction(request("CANCEL"), 1)
        };
        assert_eq!(manager.note_message(&view, &opening), IriEventType::End);
    }

    /// A CANCEL whose INVITE is not on record is read off its own `To`.
    #[test]
    fn a_cancel_of_an_invite_not_on_record_is_read_off_its_own_to() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);
        let view = established_with_a_re_invite(&manager);
        let unknown = MessageFacts {
            branch: Some("z9hG4bK-not-seen"),
            ..transaction(request("CANCEL"), 7)
        };
        assert_eq!(
            manager.note_message(&view, &unknown),
            IriEventType::Continue
        );
        let untagged = MessageFacts {
            to_tagged: false,
            ..unknown
        };
        assert_eq!(manager.note_message(&view, &untagged), IriEventType::End);
    }

    /// Each response to a CANCEL is matched to the CANCEL it answers by the
    /// transaction it carries. Two re-INVITE CANCELs outstanding are told
    /// apart, each is done with at its final response, and a response to a
    /// CANCEL that is none of them is not excused by them.
    #[test]
    fn responses_are_matched_to_the_cancel_they_answer() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);
        let view = established_with_a_re_invite(&manager);
        manager.note_message(&view, &cancel_of_re_invite(2));
        let second = MessageFacts {
            branch: Some("z9hG4bK-re-invite-3"),
            ..transaction(request("INVITE"), 3)
        };
        manager.note_message(&view, &second);
        let second_cancel = MessageFacts {
            branch: Some("z9hG4bK-re-invite-3"),
            ..transaction(request("CANCEL"), 3)
        };
        manager.note_message(&view, &second_cancel);

        // The second is answered first.
        assert_eq!(
            manager.note_message(&view, &cancel_response(481, 3)),
            IriEventType::Continue
        );
        assert_eq!(
            manager.note_message(&view, &cancel_response(481, 2)),
            IriEventType::Continue,
            "the first, by its own transaction"
        );
        assert_eq!(
            manager.note_message(&view, &cancel_response(481, 2)),
            IriEventType::End,
            "and done with at its final response"
        );

        // A response to a CANCEL that is none of those outstanding is not
        // excused by one that is.
        let (manager, _iri, _audit) = crate::li::tests::manager();
        provision(&manager, DeliveryType::X2Only, None);
        let view = established_with_a_re_invite(&manager);
        manager.note_message(&view, &cancel_of_re_invite(2));
        assert_eq!(
            manager.note_message(&view, &cancel_response(481, 9)),
            IriEventType::End
        );
    }

    /// A BYE ends the session. The answer to a CANCEL that crossed it arrives
    /// afterwards and says nothing of the call: the session stays ended, and
    /// is released after its grace.
    #[test]
    fn a_late_response_does_not_bring_back_a_session_a_bye_ended() {
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2Only, None);
        let view = established_with_a_re_invite(&manager);
        manager.note_message(&view, &cancel_of_re_invite(2));
        assert_eq!(
            manager.note_message(&view, &transaction(request("BYE"), 3)),
            IriEventType::End
        );
        let ended = Instant::now();

        manager.note_message(&view, &cancel_response(200, 2));
        manager.note_message(&view, &transaction(response("INVITE", 487), 2));
        manager.sweep_sessions(ended + SESSION_GRACE + Duration::from_secs(1), |_| false);
        assert_eq!(
            manager.remembered_session_count(),
            0,
            "ended at the BYE, and released a grace after it"
        );
    }

    /// The warrant names the called party, and the caller's INVITE decided
    /// it, so the anchor is the caller's tag. The called party's own leg is
    /// from the target. A transfer then dials a third party on a leg of its
    /// own: that party is not the caller either, and is not the target. What
    /// it sends is never reported as from the target; with nothing to say
    /// which way it went, the direction is not known.
    #[test]
    fn a_transfers_third_party_is_never_taken_for_a_called_target() {
        let (manager, _iri, _audit) = manager();
        provision_targets(
            &manager,
            DeliveryType::X2Only,
            None,
            vec![TargetIdentifier::SipUri("sip:bob@example.com".to_string())],
        );
        let internal_id = warranted_call(&manager);
        let direction = |leg: &str, facts: MessageFacts<'static>, identities, replacement| {
            let owner = CallOwner {
                replacement_target: replacement,
                ..owned_by(&internal_id)
            };
            manager
                .resolve_session(leg, &facts, &identities, || Some(owner))
                .matches[0]
                .direction
        };
        assert_eq!(
            direction(
                CALLEE_LEG,
                response("INVITE", 200),
                callee_leg_response(),
                false
            ),
            SentFromTarget,
            "the called party's own leg"
        );
        const THIRD: &str = "transfer-target@example.com";
        for (facts, identities) in [
            (response("INVITE", 180), callee_leg_response()),
            (response("INVITE", 200), callee_leg_response()),
            (request("BYE"), callee_leg_request()),
        ] {
            assert_eq!(
                direction(THIRD, facts, identities, true),
                PayloadDirection::Unknown,
                "the third party's leg"
            );
        }
        // Where the message says who it is for, the direction is known: the
        // third party's request to the target.
        let to_the_target = Identities {
            request_uri: None,
            from_uri: Some("<sip:carol@example.com>;tag=t"),
            to_uri: Some("<sip:bob@example.com>;tag=s2"),
            source_ip: None,
        };
        assert_eq!(
            direction(THIRD, request("INFO"), to_the_target, true),
            SentToTarget
        );
        // And the called party is still told from it afterwards.
        assert_eq!(
            direction(CALLEE_LEG, request("BYE"), callee_leg_request(), false),
            SentFromTarget
        );
    }

    /// An engine call siphon mints for a session is the session's media from
    /// its offer to its end, and its record is released with the session.
    #[test]
    fn a_session_follows_its_media_onto_an_engine_call_siphon_minted() {
        const MINTED: &str = "minted-engine-call";
        use EngineCallSide::{Answerer, Offerer};
        let (manager, _iri, _audit) = manager();
        provision(&manager, DeliveryType::X2AndX3, None);
        manager.adopt_engine_call(CALLER_LEG, MINTED, Offerer);
        assert_eq!(
            manager.minted_engine_call_count(),
            0,
            "a dialog nothing was intercepted on has no session to give it to"
        );
        let internal_id = warranted_call(&manager);
        manager.adopt_engine_call(CALLER_LEG, CALLER_LEG, Offerer);
        assert_eq!(
            manager.minted_engine_call_count(),
            0,
            "its own Call-ID is no minted id"
        );

        // Offered with the called party's media: the engine's caller is not
        // the session's.
        let on_callee_leg =
            manager.resolve_session(CALLEE_LEG, &response("INVITE", 200), &callee(), || {
                Some(owned_by(&internal_id))
            });
        assert_eq!(&*on_callee_leg.engine_call_id, CALLER_LEG);
        manager.adopt_engine_call(CALLEE_LEG, MINTED, Offerer);
        let view = manager.session_of_leg(CALLER_LEG).expect("the session");
        assert_eq!(&*view.engine_call_id, MINTED);
        assert!(!view.offerer_is_caller);
        assert_eq!(
            manager.sessions_on_engine_call(MINTED),
            vec![Arc::<str>::from(internal_id.as_str())]
        );
        let message = manager.resolve_session(CALLER_LEG, &request("ACK"), &caller(), || None);
        assert_eq!(
            &*message.engine_call_id, MINTED,
            "every later message sees it"
        );
        // The caller's answer on it changes nothing it knew.
        manager.adopt_engine_call(CALLER_LEG, MINTED, Answerer);
        assert!(
            !manager
                .session_of_leg(CALLER_LEG)
                .expect("the session")
                .offerer_is_caller
        );

        // siphon ends it: the media is where the anchoring Call-ID says again.
        manager.engine_call_is_live(MINTED, false);
        let back = manager.session_of_leg(CALLER_LEG).expect("the session");
        assert_eq!(&*back.engine_call_id, CALLER_LEG);
        assert!(back.offerer_is_caller);

        // Answered by the called party, another one's offerer is the caller.
        manager.adopt_engine_call(CALLEE_LEG, "minted-2", Answerer);
        let second = manager.session_of_leg(CALLER_LEG).expect("the session");
        assert_eq!(&*second.engine_call_id, "minted-2");
        assert!(second.offerer_is_caller);

        let attempt = manager.x3_attempt(MINTED, None);
        assert!(manager.x3_attempt_in_progress(MINTED, None, attempt));
        manager.sweep_sessions(Instant::now(), |_| false);
        manager.sweep_sessions(Instant::now() + SESSION_GRACE * 2, |_| false);
        assert_eq!(manager.remembered_session_count(), 0);
        assert_eq!(
            manager.minted_engine_call_count(),
            0,
            "the minted ids are released"
        );
        assert_eq!(manager.x3_call_count(), 0, "and so is their content record");
    }

    /// A warrant that arrives after the call's media was moved onto an engine
    /// call siphon minted finds that engine call: from what the unwarranted
    /// decision of the dialog knew, and with nothing remembered at all from
    /// what the media path holds.
    #[test]
    fn a_mid_call_warrant_finds_the_engine_call_the_media_moved_to() {
        const MINTED: &str = "minted-engine-call";
        // Another warrant was provisioned, so the dialog's decision was kept.
        let (manager, _iri, _audit) = manager();
        provision_targets(
            &manager,
            DeliveryType::X2Only,
            None,
            vec![TargetIdentifier::SipUri(
                "sip:carol@example.com".to_string(),
            )],
        );
        let opening = manager.resolve_session(CALLER_LEG, &invite(), &caller(), || None);
        assert!(opening.matches.is_empty());
        manager.adopt_engine_call(CALLER_LEG, MINTED, EngineCallSide::Offerer);
        provision(&manager, DeliveryType::X2AndX3, None);
        let view = manager.resolve_session(CALLER_LEG, &request("ACK"), &caller(), || None);
        assert_eq!(view.matches.len(), 1);
        assert_eq!(&*view.engine_call_id, MINTED);
        assert!(view.offerer_is_caller);
        assert_eq!(manager.sessions_on_engine_call(MINTED).len(), 1);

        // Nothing was provisioned at all while the call was set up and moved.
        let (manager, _iri, _audit) = crate::li::tests::manager();
        provision(&manager, DeliveryType::X2AndX3, None);
        let view = manager.resolve_session_with(
            CALLER_LEG,
            &request("ACK"),
            &caller(),
            || None,
            || {
                Some(DialogMedia {
                    offerer_tag: Some("a".to_string()),
                    minted: Some((MINTED.to_string(), CALLEE_LEG.to_string())),
                })
            },
        );
        assert_eq!(&*view.engine_call_id, MINTED);
        assert!(
            !view.offerer_is_caller,
            "offered with the other party's media"
        );
    }

    /// The leak gate for minted engine calls across a promotion: the caller's
    /// dialog is decided unwarranted and its media moves onto an engine call
    /// siphon minted; then a message on another leg of the call matches a
    /// warrant, and the call's session replaces the caller dialog's decision.
    /// What that decision bound goes with it, and every map is back at
    /// baseline when the calls are over.
    #[test]
    fn a_decision_replaced_through_another_leg_leaves_no_engine_binding() {
        let (manager, _iri, _audit) = manager();
        // The warrant names the called number, which only the callee leg
        // carries.
        provision_targets(
            &manager,
            DeliveryType::X2AndX3,
            None,
            vec![TargetIdentifier::E164Number("15550100042".to_string())],
        );
        const CALLS: usize = 200;
        for index in 0..CALLS {
            let caller_leg = format!("promoted-caller-{index}@example.com");
            let callee_leg = format!("promoted-callee-{index}@example.com");
            let minted = format!("promoted-minted-{index}");
            let opening = manager.resolve_session(&caller_leg, &invite(), &caller(), || None);
            assert!(opening.matches.is_empty());
            manager.adopt_engine_call(&caller_leg, &minted, EngineCallSide::Offerer);
            assert_eq!(manager.sessions_on_engine_call(&minted).len(), 1);

            let owner = CallOwner {
                internal_id: format!("call-{index}"),
                a_leg_call_id: caller_leg.clone(),
                replacement_target: false,
            };
            let promoted =
                manager.resolve_session(&callee_leg, &response("INVITE", 200), &callee(), || {
                    Some(owner)
                });
            assert_eq!(promoted.matches.len(), 1);
            assert_eq!(&*promoted.engine_call_id, minted.as_str(), "handed on");
            assert_eq!(
                manager.sessions_on_engine_call(&minted),
                vec![Arc::<str>::from(format!("call-{index}"))],
                "bound to the call's session, and to nothing that is gone"
            );
            manager.note_message(&promoted, &request("BYE"));
        }
        manager.sweep_sessions(Instant::now(), |_| false);
        manager.sweep_sessions(Instant::now() + SESSION_GRACE * 2, |_| false);
        assert_eq!(manager.remembered_session_count(), 0);
        assert_eq!(manager.session_alias_count(), 0);
        assert_eq!(manager.minted_engine_call_count(), 0, "bindings drain");
        assert_eq!(manager.x3_call_count(), 0);
    }
}
