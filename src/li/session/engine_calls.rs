//! The engine calls siphon makes for a session under an id of its own.
//!
//! A call's media is on the engine call its anchoring Call-ID names until
//! siphon moves it: a control-plane `dial`, `bridge`, `replace_peer` or
//! `accept_refer`, an originate's early offer, a transfer and a take-over each
//! offer the media under a fresh id that is no dialog's Call-ID. Content
//! delivery has to follow, so the session keeps those engine calls, which one
//! holds its media now, and which party of it the engine takes for the
//! caller there.
//!
//! Nothing here is told by the path that minted the id. Every allocation
//! siphon makes names the dialog whose SDP it carries, and the one place every
//! offer and answer is sent from tells [`LiManager::adopt_engine_call`].

use std::sync::Arc;

use super::super::LiManager;

/// An engine call siphon made for a session under an id that is no dialog's
/// Call-ID.
#[derive(Debug, Clone)]
pub(super) struct MintedEngineCall {
    pub(super) id: Arc<str>,
    /// Whether the engine holds it: offered, and not ended by siphon since.
    pub(super) live: bool,
    /// The dialog of the party of this session whose SDP a command on it
    /// carried, and which side of the engine call that party is.
    pub(super) dialog: Arc<str>,
    pub(super) side: EngineCallSide,
}

impl MintedEngineCall {
    /// Whether the offerer of the engine call, which the engine takes for
    /// the caller, is the caller of a session anchored on `primary_call_id`.
    pub(super) fn offerer_is_caller(&self, primary_call_id: &str) -> bool {
        (&*self.dialog == primary_call_id) == (self.side == EngineCallSide::Offerer)
    }
}

/// Which side of an engine call a party's SDP was given to the engine as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineCallSide {
    /// Its offer: the engine's "caller".
    Offerer,
    /// Its answer.
    Answerer,
}

/// What the media path holds for a dialog, for a session decided in the
/// middle of a call it kept no record of.
#[derive(Debug, Clone, Default)]
pub struct DialogMedia {
    /// The tag of the party whose offer anchored the dialog's media.
    pub offerer_tag: Option<String>,
    /// The engine call the media is on and the dialog of its offerer, when
    /// the engine call is under an id siphon minted.
    pub minted: Option<(String, String)>,
}

impl LiManager {
    /// Take `session_id` off the minted engine calls a decision of it was
    /// on: the decision is released, or replaced by another session's. An
    /// engine call no session is left on has its content record released with
    /// it. Two calls bridged onto one engine call each have a session there,
    /// and its record goes with the last of them.
    pub(super) fn release_engine_calls(&self, session_id: &str, engine_calls: &[MintedEngineCall]) {
        for minted in engine_calls {
            let last = self
                .minted_engine_calls
                .get_mut(&*minted.id)
                .is_none_or(|mut sessions| {
                    sessions.retain(|held| **held != *session_id);
                    sessions.is_empty()
                });
            if last {
                self.minted_engine_calls.remove(&*minted.id);
                self.forget_x3_call_of(&minted.id, session_id);
            }
        }
    }

    /// The session `session_id` as it stands on the minted engine call
    /// `engine_call_id`: with that engine call for its media and that engine
    /// call's own offerer. `None` when the session is not on it, or siphon
    /// has ended it.
    ///
    /// For what is asked of one engine call in particular. Which of a
    /// session's engine calls holds its media in the end is not known while
    /// several are offered (a transfer forked to two targets): the one that
    /// is answered is asked for as itself, whatever was offered after it.
    pub fn session_on_engine_call(
        &self,
        session_id: &str,
        engine_call_id: &str,
    ) -> Option<super::SessionView> {
        let mut view = self.session_of_leg(session_id)?;
        let decision = self.decisions.get(session_id)?;
        let minted = decision
            .engine_calls
            .iter()
            .find(|minted| &*minted.id == engine_call_id && minted.live)?;
        view.offerer_is_caller = minted.offerer_is_caller(&decision.primary_call_id);
        view.engine_call_id = Arc::clone(&minted.id);
        Some(view)
    }

    /// Give a decision just made the engine calls siphon minted for its
    /// dialogs before it. The engine call that holds the session's media now.
    pub(super) fn hand_on_engine_calls(
        &self,
        session_id: &Arc<str>,
        minted: Vec<MintedEngineCall>,
        primary_call_id: &Arc<str>,
    ) -> (Arc<str>, bool) {
        let Some(mut decision) = self.decisions.get_mut(&**session_id) else {
            return (Arc::clone(primary_call_id), true);
        };
        for engine_call in minted {
            if *engine_call.id == **primary_call_id
                || decision
                    .engine_calls
                    .iter()
                    .any(|held| held.id == engine_call.id)
            {
                continue;
            }
            self.session_is_on_engine_call(session_id, &engine_call.id);
            decision.engine_calls.push(engine_call);
        }
        decision.engine_call()
    }

    /// Note that `session_id` has media on the minted `engine_call_id`.
    fn session_is_on_engine_call(&self, session_id: &Arc<str>, engine_call_id: &str) {
        let mut sessions = self
            .minted_engine_calls
            .entry(engine_call_id.to_string())
            .or_default();
        if !sessions.contains(session_id) {
            sessions.push(Arc::clone(session_id));
        }
    }

    /// The engine has taken, under `engine_call_id`, the SDP of the party on
    /// the dialog `sip_call_id`, as the offer or the answer of that engine
    /// call (`side`). When the id is one siphon minted (it is no dialog's
    /// Call-ID) the engine call is, from here on, the media of the session
    /// that dialog belongs to: content delivery is asked for and judged
    /// there, and an end siphon brings about under the id is the session's.
    ///
    /// Every media allocation siphon makes names the dialog it is for, so
    /// this is told from the one place every offer and answer is sent, and no
    /// path that mints an id has to remember to.
    ///
    /// Nothing for a dialog no message was intercepted on, and nothing when
    /// the id is the session's anchoring Call-ID, which is its engine call
    /// already. A session already on the engine call keeps what it knew.
    pub fn adopt_engine_call(&self, sip_call_id: &str, engine_call_id: &str, side: EngineCallSide) {
        if sip_call_id == engine_call_id {
            return;
        }
        let Some(session_id) = self.session_id_of(sip_call_id) else {
            return;
        };
        let Some(mut decision) = self.decisions.get_mut(&*session_id) else {
            return;
        };
        if &*decision.primary_call_id == engine_call_id {
            return;
        }
        match decision
            .engine_calls
            .iter_mut()
            .find(|minted| &*minted.id == engine_call_id)
        {
            Some(minted) => minted.live = true,
            None => {
                decision.engine_calls.push(MintedEngineCall {
                    id: Arc::from(engine_call_id),
                    live: true,
                    dialog: Arc::from(sip_call_id),
                    side,
                });
                self.session_is_on_engine_call(&session_id, engine_call_id);
            }
        }
    }

    /// The engine holds the minted engine call `engine_call_id` (`live`), or
    /// siphon has ended it. Nothing for an id that is no session's minted
    /// engine call, which is nearly every one.
    pub fn engine_call_is_live(&self, engine_call_id: &str, live: bool) {
        for session_id in self.sessions_on_engine_call(engine_call_id) {
            if let Some(mut decision) = self.decisions.get_mut(&*session_id) {
                for minted in &mut decision.engine_calls {
                    if &*minted.id == engine_call_id {
                        minted.live = live;
                    }
                }
            }
        }
    }

    /// The sessions with media on the minted `engine_call_id`: one, or the
    /// two of a pair of calls bridged onto it.
    pub fn sessions_on_engine_call(&self, engine_call_id: &str) -> Vec<Arc<str>> {
        self.minted_engine_calls
            .get(engine_call_id)
            .map(|sessions| sessions.clone())
            .unwrap_or_default()
    }

    /// How many minted engine calls have a session on them. Drains with the
    /// sessions; exposed for the leak tests.
    pub fn minted_engine_call_count(&self) -> usize {
        self.minted_engine_calls.len()
    }
}
