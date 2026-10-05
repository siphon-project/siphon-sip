//! Media session tracking — maps SIP Call-IDs to active RTPEngine sessions.

use std::time::Instant;

use dashmap::DashMap;

/// An active RTPEngine media session associated with a SIP dialog.
#[derive(Debug, Clone)]
pub struct MediaSession {
    /// SIP Call-ID header value. This is the **store key** — the dispatcher
    /// looks sessions up by the A-leg's SIP Call-ID.
    pub call_id: String,
    /// The opaque call-id used in rtpengine NG commands (`offer`/`answer`/
    /// `delete`). Normally equal to [`MediaSession::call_id`], but decoupled so
    /// a siphon-terminated transfer can re-anchor the surviving pair on a
    /// **fresh** rtpengine call-id while the store key stays the (post-promotion)
    /// SIP Call-ID that later re-INVITEs/teardown look up. Use
    /// [`MediaSession::rtpengine_id`] rather than reading this directly.
    pub rtpengine_call_id: String,
    /// SIP From-tag (A leg).
    pub from_tag: String,
    /// SIP To-tag (B leg) — set after the answer.
    pub to_tag: Option<String>,
    /// The media profile name used for this session.
    pub profile: String,
    /// The fully-expanded WebSocket bridge URI this session's media is attached
    /// to, when one was requested (`siphon-rtp` voice-AI bridge).
    ///
    /// Recorded at `offer` so a later `answer` on the same Call-ID reuses the
    /// same bridge without the script re-passing `ws_uri=` — the same reason
    /// [`MediaSession::profile`] is recorded.
    pub ws_uri: Option<String>,
    /// The WebSocket **tee** URI streaming a copy of this session's audio, when
    /// one is attached.
    ///
    /// Deliberately separate from [`MediaSession::ws_uri`]: a tee is additive
    /// (the call relays on and a copy goes out) while `ws_uri` is a takeover
    /// (the server *is* the far side). Conflating them makes a leg with a
    /// takeover look like a leg with a tee, which sends the wrong detach at
    /// bridge time — the wrong verb succeeds harmlessly and the media path the
    /// bridge was about to renegotiate is still owned by the WebSocket server.
    pub ws_tee: Option<String>,
    /// Whether a WebSocket **takeover bridge** was attached to this session
    /// *mid-call* (`attach_ws_bridge`) rather than negotiated through the
    /// profile's `ws_uri`.
    ///
    /// Only a mid-call attach can be detached — it took over a live relay, so
    /// there is a relay to give back. A `ws_uri`-negotiated bridge is the
    /// call's whole media path and the engine refuses to detach it, which is
    /// why the two are tracked apart rather than as one "has a bridge" flag.
    pub ws_bridge_attached: bool,
    /// For a session whose two parties were paired by something other than
    /// one dial (a formed controller bridge, a leg replacement, a `Replaces`
    /// takeover), which flags shape the SDP the engine sends each party and
    /// whose policy pins each one's media ingress. `None` for every other
    /// session, which has one [`MediaSession::profile`] describing the pair
    /// the way a dial's profile does.
    pub bridge_sides: Option<BridgeSides>,
    /// When this session was created.
    pub created_at: Instant,
}

/// Which half of a media profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileHalf {
    /// The profile's `offer` flags.
    Offer,
    /// The profile's `answer` flags.
    Answer,
}

/// The flags that shape the SDP the engine sends one party: a profile and the
/// half of it the party was given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SideFlags {
    /// The media profile's name.
    pub profile: String,
    /// Which half of it.
    pub half: ProfileHalf,
}

impl SideFlags {
    /// The flags themselves, from `registry`; `None` for a profile it does
    /// not carry.
    pub fn resolve(
        &self,
        registry: &super::profile::ProfileRegistry,
    ) -> Option<super::profile::NgFlags> {
        registry.get(&self.profile).map(|entry| match self.half {
            ProfileHalf::Offer => entry.offer.clone(),
            ProfileHalf::Answer => entry.answer.clone(),
        })
    }

    /// Whether this half asks for a party's media ingress to be pinned to its
    /// signalling source (`received_from`). `false` for a profile `registry`
    /// does not carry: a policy that cannot be read pins nothing.
    pub fn pins_ingress(&self, registry: &super::profile::ProfileRegistry) -> bool {
        registry
            .get(&self.profile)
            .is_some_and(|entry| match self.half {
                ProfileHalf::Offer => entry.offer.carry_received_from,
                ProfileHalf::Answer => entry.answer.carry_received_from,
            })
    }
}

/// The two parties of a bridged pair's session and what shapes each.
///
/// A bridge offers its peer with one profile's `offer` half and re-INVITEs its
/// anchor with one profile's `answer` half — the pair profile's two halves, or
/// each party's own profile. Every SDP the engine later sends one of them, on
/// a relayed re-offer in either direction, is shaped by the same flags that
/// party was bridged with, so an SRTP phone keeps getting SRTP and a plain-RTP
/// caller plain RTP whichever of them re-offers.
///
/// Shaping and ingress are two questions with two answers. The flags that
/// shape the SDP sent to one party ride on the command that carries the
/// **other** party's SDP, and the `received_from` hint on that command names
/// where the other party's media comes from. So each party's ingress policy is
/// kept beside its shaping, and a command takes its shape from the party it is
/// for and its hint from the party whose SDP it carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeSides {
    /// The anchor: the party on [`MediaSession::from_tag`].
    pub anchor: SideFlags,
    /// The peer: the party on [`MediaSession::to_tag`].
    pub peer: SideFlags,
    /// Whose `received_from` policy pins the anchor's media ingress.
    pub anchor_ingress: SideFlags,
    /// Whose `received_from` policy pins the peer's.
    pub peer_ingress: SideFlags,
}

impl MediaSession {
    /// The call-id to address rtpengine with. Falls back to the SIP `call_id`
    /// when `rtpengine_call_id` was left empty (back-compat for sessions created
    /// before the decoupling), so all existing anchored calls talk to rtpengine
    /// on their SIP Call-ID exactly as before.
    pub fn rtpengine_id(&self) -> &str {
        if self.rtpengine_call_id.is_empty() {
            &self.call_id
        } else {
            &self.rtpengine_call_id
        }
    }

    /// Whose `received_from` policy pins the media ingress of one party of
    /// this session: the one on [`MediaSession::from_tag`] when `on_from_tag`,
    /// the one on [`MediaSession::to_tag`] otherwise.
    ///
    /// What was recorded for the party when the pair was put together
    /// ([`MediaSession::bridge_sides`]), and without that the half of the
    /// session's profile the party's SDP reached the engine under: `offer`
    /// for the offerer of a relay and `answer` for its answerer, as on a
    /// dial, and `answer` for the one party of a session the engine answered
    /// itself.
    #[must_use]
    pub fn party_ingress(&self, on_from_tag: bool) -> SideFlags {
        match (&self.bridge_sides, on_from_tag) {
            (Some(sides), true) => sides.anchor_ingress.clone(),
            (Some(sides), false) => sides.peer_ingress.clone(),
            (None, _) => SideFlags {
                profile: self.profile.clone(),
                half: if on_from_tag && self.to_tag.is_some() {
                    ProfileHalf::Offer
                } else {
                    ProfileHalf::Answer
                },
            },
        }
    }

    /// The tag naming the party that is **sending** an in-dialog offer, for the media engine's
    /// re-offer: the A-leg's `from_tag` when the offer came from A, the B-leg's `to_tag` when it came
    /// from B.
    ///
    /// `None` when B is offering on a session whose `to_tag` was never recorded. The engine resolves
    /// the re-offering party *by tag*, so substituting A's tag there does not name B — it claims to be
    /// A, and the engine then answers with the leg facing the wrong party and re-points that party's
    /// media. There is no safe guess, so the caller refuses the request instead.
    #[must_use]
    pub fn offer_tag(&self, from_a_leg: bool) -> Option<&str> {
        if from_a_leg {
            Some(self.from_tag.as_str())
        } else {
            self.to_tag.as_deref()
        }
    }

    /// The `(offerer, answerer)` tag pair naming both parties of an in-dialog **answer**; `is_a2b`
    /// says the A-leg made the offer.
    ///
    /// The B→A direction returns `None` on a session with no recorded `to_tag`, for the reason
    /// [`MediaSession::offer_tag`] gives — naming B is exactly what the pair is for. The A→B direction
    /// keeps an empty answerer tag rather than refusing: on a session whose `to_tag` was never
    /// recorded, that answer is the *first* one the engine sees for the original offer, and dropping
    /// it would leave the call unanchored.
    #[must_use]
    pub fn answer_tags(&self, is_a2b: bool) -> Option<(&str, &str)> {
        if is_a2b {
            Some((self.from_tag.as_str(), self.to_tag.as_deref().unwrap_or("")))
        } else {
            Some((self.to_tag.as_deref()?, self.from_tag.as_str()))
        }
    }
}

#[cfg(test)]
mod media_session_tests {
    use super::*;

    fn session(to_tag: Option<&str>) -> MediaSession {
        MediaSession {
            call_id: "call-1".to_string(),
            rtpengine_call_id: String::new(),
            from_tag: "tag-a".to_string(),
            to_tag: to_tag.map(str::to_string),
            profile: "default".to_string(),
            ws_uri: None,
            ws_tee: None,
            ws_bridge_attached: false,
            bridge_sides: None,
            created_at: Instant::now(),
        }
    }

    #[test]
    fn a_partys_ingress_policy_is_the_half_its_sdp_reached_the_engine_under() {
        let half = |half| SideFlags {
            profile: "default".to_string(),
            half,
        };
        // A relay set up by one dial: the offerer's `offer` half, the
        // answerer's `answer` half.
        let relay = session(Some("tag-b"));
        assert_eq!(relay.party_ingress(true), half(ProfileHalf::Offer));
        assert_eq!(relay.party_ingress(false), half(ProfileHalf::Answer));
        // A session the engine answered itself has one party, anchored under
        // the `answer` half.
        assert_eq!(session(None).party_ingress(true), half(ProfileHalf::Answer));
    }

    #[test]
    fn a_partys_ingress_policy_is_what_was_recorded_when_the_pair_was_put_together() {
        let side = |profile: &str, half| SideFlags {
            profile: profile.to_string(),
            half,
        };
        let paired = MediaSession {
            bridge_sides: Some(BridgeSides {
                anchor: side("shapes_the_anchor", ProfileHalf::Answer),
                peer: side("shapes_the_peer", ProfileHalf::Offer),
                anchor_ingress: side("pins_the_anchor", ProfileHalf::Answer),
                peer_ingress: side("pins_the_peer", ProfileHalf::Offer),
            }),
            ..session(Some("tag-b"))
        };
        // Never the profile half its tag would name, nor the shaping.
        assert_eq!(
            paired.party_ingress(true),
            side("pins_the_anchor", ProfileHalf::Answer)
        );
        assert_eq!(
            paired.party_ingress(false),
            side("pins_the_peer", ProfileHalf::Offer)
        );
    }

    #[test]
    fn offer_tag_names_the_offering_party() {
        let answered = session(Some("tag-b"));
        assert_eq!(answered.offer_tag(true), Some("tag-a"));
        assert_eq!(answered.offer_tag(false), Some("tag-b"));
    }

    #[test]
    fn an_offer_from_b_without_a_recorded_answerer_tag_has_no_tag_to_use() {
        // The caller must refuse: A's tag would name the wrong party to the engine.
        let unanswered = session(None);
        assert_eq!(unanswered.offer_tag(true), Some("tag-a"));
        assert_eq!(unanswered.offer_tag(false), None);
    }

    #[test]
    fn answer_tags_put_the_offerer_first() {
        let answered = session(Some("tag-b"));
        assert_eq!(answered.answer_tags(true), Some(("tag-a", "tag-b")));
        assert_eq!(answered.answer_tags(false), Some(("tag-b", "tag-a")));
    }

    #[test]
    fn an_answer_to_b_without_a_recorded_answerer_tag_is_refused_only_in_the_b_to_a_direction() {
        let unanswered = session(None);
        // A→B keeps the empty answerer tag: this is the first answer the engine sees.
        assert_eq!(unanswered.answer_tags(true), Some(("tag-a", "")));
        // B→A cannot name the offerer at all.
        assert_eq!(unanswered.answer_tags(false), None);
    }
}

/// Thread-safe store of active media sessions, keyed by SIP Call-ID.
pub struct MediaSessionStore {
    sessions: DashMap<String, MediaSession>,
    /// Who an engine call's end-of-call summary belongs to, for each engine
    /// call not simply named by its own SIP Call-ID. See
    /// [`MediaSessionStore::summary_parties`].
    parties: std::sync::Arc<DashMap<String, EngineParties>>,
}

/// The SIP Call-IDs an engine call carries media for, and until when they are
/// kept once no stored session is on it.
#[derive(Debug)]
struct EngineParties {
    parties: Vec<EngineParty>,
    /// `None` while a stored session is on the engine call; set when it
    /// leaves the store, since the engine's summary follows that delete.
    expires_at: Option<tokio::time::Instant>,
}

/// One party of an engine call: its SIP Call-ID, and the engine tag its
/// media is on, which is how the engine names the party in a per-party event
/// (a digit, a playback, a stream).
#[derive(Debug)]
struct EngineParty {
    sip_call_id: String,
    tag: Option<String>,
}

impl MediaSessionStore {
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
            parties: Default::default(),
        }
    }

    /// Insert or update a media session.
    ///
    /// A session on an engine call of its own (a bridged pair, a re-anchor) is
    /// recorded as that call's party, so the call's summary still finds the SIP
    /// Call-ID. A session it replaces on another engine call has its parties
    /// released, as [`MediaSessionStore::remove`] releases them.
    pub fn insert(&self, session: MediaSession) {
        let engine_call_id = session.rtpengine_id().to_string();
        let call_id = session.call_id.clone();
        if engine_call_id != call_id {
            match self.parties.get_mut(&engine_call_id) {
                Some(mut parties) => parties.expires_at = None,
                None => {
                    self.parties.insert(
                        engine_call_id.clone(),
                        EngineParties {
                            parties: vec![EngineParty {
                                sip_call_id: call_id.clone(),
                                tag: Some(session.from_tag.clone()),
                            }],
                            expires_at: None,
                        },
                    );
                }
            }
        }
        if let Some(replaced) = self.sessions.insert(call_id, session) {
            if replaced.rtpengine_id() != engine_call_id {
                self.release_parties(replaced.rtpengine_id());
            }
        }
    }

    /// Record that the engine call `engine_call_id`, which the session stored
    /// under `call_id` is on, carries the media of each `(SIP Call-ID, engine
    /// tag)` in `parties`: a bridged pair's anchor and peer. Replaces what was
    /// recorded, and keeps a Call-ID listed twice once. Nothing is recorded
    /// unless the stored session is on that engine call, so nothing is recorded
    /// that no removal would ever release.
    pub fn record_parties(
        &self,
        call_id: &str,
        engine_call_id: &str,
        parties: &[(&str, Option<&str>)],
    ) {
        let stored = self
            .sessions
            .get(call_id)
            .is_some_and(|session| session.rtpengine_id() == engine_call_id);
        if !stored {
            return;
        }
        let mut unique: Vec<EngineParty> = Vec::with_capacity(parties.len());
        for (sip_call_id, tag) in parties {
            if !unique.iter().any(|kept| kept.sip_call_id == *sip_call_id) {
                unique.push(EngineParty {
                    sip_call_id: (*sip_call_id).to_string(),
                    tag: tag.map(str::to_string),
                });
            }
        }
        self.parties.insert(
            engine_call_id.to_string(),
            EngineParties {
                parties: unique,
                expires_at: None,
            },
        );
    }

    /// The SIP Call-ID a per-party engine event on `engine_call_id` belongs
    /// to — a digit, a playback, a recording, a stream — given the engine tag
    /// `tag` the event names.
    ///
    /// On an engine call with one party, that party. On a bridged pair, the
    /// party whose tag it is: a digit the peer pressed is the peer's alone.
    /// `None` when no party, or more than one, carries the tag, since
    /// guessing would hand one party's event to the other. On an engine call
    /// with nothing recorded, `engine_call_id` itself, which is then the SIP
    /// Call-ID. Unlike [`MediaSessionStore::summary_parties`] this spends
    /// nothing: a call reports many such events.
    pub fn event_party(&self, engine_call_id: &str, tag: &str) -> Option<String> {
        let Some(recorded) = self.parties.get(engine_call_id) else {
            return Some(engine_call_id.to_string());
        };
        if let [only] = recorded.parties.as_slice() {
            return Some(only.sip_call_id.clone());
        }
        let mut named = recorded
            .parties
            .iter()
            .filter(|party| party.tag.as_deref() == Some(tag));
        match (named.next(), named.next()) {
            (Some(party), None) => Some(party.sip_call_id.clone()),
            _ => None,
        }
    }

    /// Whether the dialog `sip_call_id` is recorded as a party of engine call
    /// `engine_call_id`: a bridged pair's anchor or peer. A pair parted by an
    /// `unbridge` stays recorded, since its session stays on the engine call,
    /// which is how a second bridge of the same two legs recognises the party
    /// that session already relays to. Spends nothing.
    pub fn is_party(&self, engine_call_id: &str, sip_call_id: &str) -> bool {
        self.parties.get(engine_call_id).is_some_and(|recorded| {
            recorded
                .parties
                .iter()
                .any(|party| party.sip_call_id == sip_call_id)
        })
    }

    /// The store key of the session on engine call `engine_call_id`: the SIP
    /// Call-ID it is stored under, which for a bridged pair or a re-anchor is
    /// not the engine id. `None` when no stored session is on that call.
    pub fn session_key_for_engine_call(&self, engine_call_id: &str) -> Option<String> {
        let on_call = |key: &str| {
            self.sessions
                .get(key)
                .is_some_and(|session| session.rtpengine_id() == engine_call_id)
        };
        if on_call(engine_call_id) {
            return Some(engine_call_id.to_string());
        }
        let recorded = self.parties.get(engine_call_id)?;
        recorded
            .parties
            .iter()
            .map(|party| party.sip_call_id.as_str())
            .find(|key| on_call(key))
            .map(str::to_string)
    }

    /// The SIP Call-IDs the engine's end-of-call summary for `engine_call_id`
    /// belongs to, each once: both parties of a bridged pair, the call a
    /// re-anchored session serves, and otherwise `engine_call_id` itself, which
    /// is then the SIP Call-ID.
    ///
    /// An engine call reports one summary, so what was recorded for it is spent
    /// here. It is found while a stored session is on the call and for
    /// [`crate::control::CHANNEL_TOMBSTONE_GRACE`] after it left the store: the
    /// summary follows the engine delete a teardown issues, and the owners it
    /// goes to stay reachable for that same window.
    pub fn summary_parties(&self, engine_call_id: &str) -> Vec<String> {
        match self.parties.remove(engine_call_id) {
            Some((_, parties))
                if parties
                    .expires_at
                    .map_or(true, |expires_at| expires_at > tokio::time::Instant::now()) =>
            {
                parties
                    .parties
                    .into_iter()
                    .map(|party| party.sip_call_id)
                    .collect()
            }
            _ => vec![engine_call_id.to_string()],
        }
    }

    /// Number of engine calls with recorded parties (drains to baseline — leak
    /// gate).
    pub fn engine_parties_count(&self) -> usize {
        self.parties.len()
    }

    /// No stored session is on `engine_call_id` any more: keep its parties for
    /// the summary that follows the delete, then let them go. Expiry is a timer
    /// on the current runtime; with none (never the case in the running
    /// server) expired entries are swept here instead, so none is left behind.
    fn release_parties(&self, engine_call_id: &str) {
        let expires_at = tokio::time::Instant::now() + crate::control::CHANNEL_TOMBSTONE_GRACE;
        match self.parties.get_mut(engine_call_id) {
            Some(mut parties) if parties.expires_at.is_none() => {
                parties.expires_at = Some(expires_at);
            }
            _ => return,
        }
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                let parties = std::sync::Arc::clone(&self.parties);
                let engine_call_id = engine_call_id.to_string();
                runtime.spawn(async move {
                    tokio::time::sleep_until(expires_at).await;
                    // Only this release: an engine call stored again since
                    // keeps its entry.
                    parties.remove_if(&engine_call_id, |_, parties| {
                        parties
                            .expires_at
                            .is_some_and(|expiry| expiry <= expires_at)
                    });
                });
            }
            Err(_) => {
                let now = tokio::time::Instant::now();
                self.parties
                    .retain(|_, parties| parties.expires_at.map_or(true, |expiry| expiry > now));
            }
        }
    }

    /// Look up a session by Call-ID.
    pub fn get(&self, call_id: &str) -> Option<MediaSession> {
        self.sessions.get(call_id).map(|entry| entry.clone())
    }

    /// Remove a session by Call-ID. Returns the removed session, if any.
    pub fn remove(&self, call_id: &str) -> Option<MediaSession> {
        let (_, session) = self.sessions.remove(call_id)?;
        self.release_parties(session.rtpengine_id());
        Some(session)
    }

    /// Update the to_tag for an existing session.
    pub fn set_to_tag(&self, call_id: &str, to_tag: String) {
        if let Some(mut entry) = self.sessions.get_mut(call_id) {
            entry.to_tag = Some(to_tag);
        }
    }

    /// Record the WebSocket **tee** attached to a session, or clear it on
    /// detach.
    ///
    /// Kept apart from the takeover bridge below: a bridge plan has to send
    /// `detach_ws_tee` for one and `detach_ws_bridge` for the other, and the
    /// wrong verb succeeds harmlessly rather than failing loudly — so a
    /// conflated flag leaves the media path still owned by the WebSocket
    /// server while the plan believes it was handed back.
    pub fn set_ws_tee(&self, call_id: &str, ws_tee: Option<String>) {
        if let Some(mut entry) = self.sessions.get_mut(call_id) {
            entry.ws_tee = ws_tee;
        }
    }

    /// Record that a WebSocket **takeover bridge** was attached to a session
    /// mid-call, or that it was detached.
    ///
    /// Only mid-call attaches are tracked here. A bridge negotiated through the
    /// profile's `ws_uri` is not detachable, so flagging it would make a bridge
    /// plan emit a detach the engine refuses.
    pub fn set_ws_bridge_attached(&self, call_id: &str, attached: bool) {
        if let Some(mut entry) = self.sessions.get_mut(call_id) {
            entry.ws_bridge_attached = attached;
        }
    }

    /// Remove sessions older than `max_age`.
    pub fn sweep_stale(&self, max_age: std::time::Duration) {
        let cutoff = Instant::now() - max_age;
        let mut swept = Vec::new();
        self.sessions.retain(|_, session| {
            let keep = session.created_at > cutoff;
            if !keep {
                swept.push(session.rtpengine_id().to_string());
            }
            keep
        });
        for engine_call_id in swept {
            self.release_parties(&engine_call_id);
        }
    }

    /// The engine-side call-ids of every session siphon currently holds.
    ///
    /// Engine-side, not SIP: the store is keyed by SIP Call-ID, but a media
    /// engine enumerates by the id siphon offered it, and a media re-anchor
    /// gives a call an engine id of its own. Comparing the wrong one would
    /// read every live call as an orphan.
    pub fn live_engine_call_ids(&self) -> std::collections::HashSet<String> {
        self.sessions
            .iter()
            .map(|entry| entry.value().rtpengine_id().to_string())
            .collect()
    }

    /// Number of active sessions.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

#[cfg(test)]
#[path = "session_parties_tests.rs"]
mod session_parties_tests;

impl Default for MediaSessionStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    fn make_session(call_id: &str) -> MediaSession {
        MediaSession {
            call_id: call_id.to_string(),
            rtpengine_call_id: call_id.to_string(),
            from_tag: "tag-a".to_string(),
            to_tag: None,
            profile: "srtp_to_rtp".to_string(),
            ws_uri: None,
            ws_tee: None,
            ws_bridge_attached: false,
            bridge_sides: None,
            created_at: Instant::now(),
        }
    }

    #[test]
    fn a_side_pins_ingress_only_where_its_own_half_asks_for_it() {
        let half = |received_from: bool| crate::config::NgFlagsConfig {
            received_from,
            ..Default::default()
        };
        let mut custom = std::collections::HashMap::new();
        custom.insert(
            "pins_the_offerer".to_string(),
            crate::config::MediaProfileConfig {
                offer: half(true),
                answer: half(false),
            },
        );
        let registry = crate::rtpengine::ProfileRegistry::from_config(&custom);
        let side = |profile: &str, half| SideFlags {
            profile: profile.to_string(),
            half,
        };
        assert!(side("pins_the_offerer", ProfileHalf::Offer).pins_ingress(&registry));
        assert!(!side("pins_the_offerer", ProfileHalf::Answer).pins_ingress(&registry));
        // A profile the registry does not carry pins nothing.
        assert!(!side("no_such_profile", ProfileHalf::Offer).pins_ingress(&registry));
    }

    #[test]
    fn insert_and_get() {
        let store = MediaSessionStore::new();
        store.insert(make_session("call-1"));
        let session = store.get("call-1").unwrap();
        assert_eq!(session.call_id, "call-1");
        assert_eq!(session.from_tag, "tag-a");
        assert!(session.to_tag.is_none());
    }

    #[test]
    fn get_missing_returns_none() {
        let store = MediaSessionStore::new();
        assert!(store.get("nonexistent").is_none());
    }

    #[test]
    fn remove_session() {
        let store = MediaSessionStore::new();
        store.insert(make_session("call-1"));
        assert_eq!(store.len(), 1);
        let removed = store.remove("call-1").unwrap();
        assert_eq!(removed.call_id, "call-1");
        assert!(store.is_empty());
    }

    #[test]
    fn remove_missing_returns_none() {
        let store = MediaSessionStore::new();
        assert!(store.remove("nonexistent").is_none());
    }

    #[test]
    fn set_to_tag() {
        let store = MediaSessionStore::new();
        store.insert(make_session("call-1"));
        store.set_to_tag("call-1", "tag-b".to_string());
        let session = store.get("call-1").unwrap();
        assert_eq!(session.to_tag.as_deref(), Some("tag-b"));
    }

    #[test]
    fn set_to_tag_missing_is_noop() {
        let store = MediaSessionStore::new();
        store.set_to_tag("nonexistent", "tag-b".to_string());
        assert!(store.is_empty());
    }

    #[test]
    fn sweep_stale_removes_old() {
        let store = MediaSessionStore::new();

        // Insert a session with a past created_at.
        let mut old_session = make_session("old-call");
        old_session.created_at = Instant::now() - std::time::Duration::from_secs(120);
        store.insert(old_session);

        // Insert a fresh session.
        store.insert(make_session("new-call"));

        assert_eq!(store.len(), 2);
        store.sweep_stale(std::time::Duration::from_secs(60));
        assert_eq!(store.len(), 1);
        assert!(store.get("old-call").is_none());
        assert!(store.get("new-call").is_some());
    }

    #[test]
    fn concurrent_access() {
        let store = Arc::new(MediaSessionStore::new());
        let mut handles = vec![];

        for index in 0..10 {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                let call_id = format!("call-{index}");
                store.insert(make_session(&call_id));
                assert!(store.get(&call_id).is_some());
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(store.len(), 10);
    }

    #[test]
    fn insert_overwrites_existing() {
        let store = MediaSessionStore::new();
        store.insert(make_session("call-1"));
        let mut updated = make_session("call-1");
        updated.from_tag = "tag-updated".to_string();
        store.insert(updated);
        assert_eq!(store.len(), 1);
        assert_eq!(store.get("call-1").unwrap().from_tag, "tag-updated");
    }

    #[test]
    fn default_trait() {
        let store = MediaSessionStore::default();
        assert!(store.is_empty());
    }

    #[test]
    fn rtpengine_id_uses_field_then_falls_back_to_call_id() {
        // Normal session: rtpengine_call_id == call_id → both agree.
        let mut session = make_session("sip-cid");
        assert_eq!(session.rtpengine_id(), "sip-cid");

        // Decoupled (transfer re-anchor): store key stays the SIP Call-ID, but
        // rtpengine is addressed on the fresh id.
        session.rtpengine_call_id = "b2b-fresh-anchor".to_string();
        assert_eq!(session.call_id, "sip-cid");
        assert_eq!(session.rtpengine_id(), "b2b-fresh-anchor");

        // Back-compat: an empty rtpengine_call_id falls back to the SIP Call-ID.
        session.rtpengine_call_id = String::new();
        assert_eq!(session.rtpengine_id(), "sip-cid");
    }

    /// The takeover URI and the tee URI are independent state. Conflating them
    /// is what made a leg holding a `ws_uri` takeover look like a leg holding a
    /// tee, so the bridge plan sent the tee detach — which succeeds, being
    /// idempotent — and then renegotiated a path the WebSocket server owned.
    #[test]
    fn a_takeover_uri_and_a_tee_uri_are_tracked_apart() {
        let store = MediaSessionStore::new();
        store.insert(MediaSession {
            ws_uri: Some("wss://ai.invalid/takeover".to_string()),
            ..make_session("call-1")
        });

        // A leg with only a takeover has no tee.
        let session = store.get("call-1").expect("session");
        assert!(session.ws_uri.is_some());
        assert!(session.ws_tee.is_none(), "a takeover is not a tee");
        assert!(
            !session.ws_bridge_attached,
            "a profile takeover is not a mid-call attach"
        );

        // Attaching a tee leaves the takeover alone, and vice versa.
        store.set_ws_tee("call-1", Some("wss://asr.invalid/tee".to_string()));
        let session = store.get("call-1").expect("session");
        assert_eq!(session.ws_tee.as_deref(), Some("wss://asr.invalid/tee"));
        assert_eq!(session.ws_uri.as_deref(), Some("wss://ai.invalid/takeover"));

        store.set_ws_tee("call-1", None);
        assert!(store.get("call-1").expect("session").ws_tee.is_none());
        assert!(
            store.get("call-1").expect("session").ws_uri.is_some(),
            "detaching a tee must not disturb the takeover"
        );
    }

    /// Only a mid-call attach is detachable, so it is tracked separately from
    /// the profile-negotiated `ws_uri`.
    #[test]
    fn a_mid_call_takeover_is_flagged_detachable_and_clears_on_detach() {
        let store = MediaSessionStore::new();
        store.insert(make_session("call-1"));
        assert!(!store.get("call-1").expect("session").ws_bridge_attached);

        store.set_ws_bridge_attached("call-1", true);
        assert!(store.get("call-1").expect("session").ws_bridge_attached);

        // A re-point stays attached; only a detach clears it.
        store.set_ws_bridge_attached("call-1", true);
        assert!(store.get("call-1").expect("session").ws_bridge_attached);

        store.set_ws_bridge_attached("call-1", false);
        assert!(!store.get("call-1").expect("session").ws_bridge_attached);
    }
}
