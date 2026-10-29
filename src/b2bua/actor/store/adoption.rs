//! The store side of `b2bua.adopt_replaced`: reading the two dialogs the
//! ownership check compares, taking a call apart around the leg merged into a
//! room, and remembering which calls end with which conference dialog.
//!
//! The calls that end with their conference dialog are indexed here rather
//! than in the script: module state is emptied on every reload, and a
//! conference outlives a deploy. [`CallActorStore::remove_call`] is the one
//! funnel every ended call passes through, so the index is kept there: an
//! adopted call that ends leaves it, and a conference dialog that ends hands its
//! adopted calls to [`CallActorStore::take_orphaned_adoptions`] for the
//! dispatcher to tear down.

use super::*;

/// Which adopted calls end with which conference dialog.
#[derive(Debug, Default)]
pub struct AdoptionIndex {
    /// Conference dialog (internal call id) → the calls it adopted with
    /// `on_owner_leave="end"`.
    by_owner: DashMap<String, Vec<String>>,
    /// Adopted calls whose conference dialog ended, waiting for their
    /// teardown.
    orphaned: DashMap<String, ()>,
}

/// What a merge took out of a call: the leg that ends, and the Call-IDs the
/// media session and the control channel follow.
#[derive(Debug, Clone)]
pub struct AdoptedSwap {
    /// The named leg, off the call now, to be sent its BYE.
    pub replaced: Leg,
    /// The A-leg's SIP Call-ID before the merge: the media session's key.
    pub previous_a_call_id: String,
    /// The A-leg's SIP Call-ID after it: the far party's dialog.
    pub a_call_id: String,
}

impl CallActorStore {
    /// The party on the leg the `Replaces` triple names (RFC 3891 §3: its
    /// `to-tag` is siphon's tag on the dialog, its `from-tag` the party's),
    /// and whether that call is answered.
    pub fn replaced_dialog_party(
        &self,
        sip_call_id: &str,
        from_tag: &str,
        to_tag: &str,
    ) -> Option<(DialogParty, bool)> {
        let matched = self.find_call_by_replaces_dialog(sip_call_id, from_tag, to_tag)?;
        let call = self.calls.get(&matched.call_id)?;
        let leg = if matched.on_a_leg {
            &call.a_leg
        } else {
            call.b_legs
                .iter()
                .find(|leg| leg.dialog.call_id == sip_call_id && leg.dialog.local_tag == to_tag)?
        };
        let answered = call.state == CallState::Answered
            && call.winner.is_some_and(|winner| {
                matched.on_a_leg || call.b_legs.get(winner).is_some_and(|won| won.id == leg.id)
            });
        Some((DialogParty::on_leg(&call, leg, matched.on_a_leg), answered))
    }

    /// The party on the A-leg (or the winning B-leg) of `call_id`: the dialog a
    /// REFER arrived in.
    pub fn dialog_party(&self, call_id: &str, on_a_leg: bool) -> Option<DialogParty> {
        let call = self.calls.get(call_id)?;
        let leg = if on_a_leg {
            &call.a_leg
        } else {
            call.b_legs.get(call.winner?)?
        };
        Some(DialogParty::on_leg(&call, leg, on_a_leg))
    }

    /// Mark `call_id` as being merged into `conference_id` for the conference
    /// dialog `owner_call_id`, if it can be: answered, the named leg confirmed,
    /// and nothing else in progress that a merge would cut across. Returns the
    /// A-leg's SIP Call-ID, which keys the call's media session.
    pub fn begin_adoption(
        &self,
        call_id: &str,
        conference_id: &str,
        owner_call_id: &str,
        ends_with_owner: bool,
    ) -> Result<String, AdoptRefusal> {
        let mut call = self.calls.get_mut(call_id).ok_or(AdoptRefusal::NoDialog)?;
        if call.state != CallState::Answered || call.winner.is_none() || call.teardown_claimed {
            return Err(AdoptRefusal::NoDialog);
        }
        if call.adoption.is_some()
            || call.transfer.is_some()
            || call.bridge.is_some()
            || call.deferred_takeover.is_some()
            || call.pending_replaces.is_some()
        {
            return Err(AdoptRefusal::Busy);
        }
        call.adoption = Some(Adoption {
            conference_id: conference_id.to_string(),
            owner_call_id: owner_call_id.to_string(),
            ends_with_owner,
            alias_call_id: None,
            seated: false,
        });
        Ok(call.a_leg.dialog.call_id.clone())
    }

    /// Clear a merge [`Self::begin_adoption`] marked and that did not happen.
    pub fn abandon_adoption(&self, call_id: &str) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            if call
                .adoption
                .as_ref()
                .is_some_and(|adoption| !adoption.seated)
            {
                call.adoption = None;
            }
        }
    }

    /// The seat is in: take the named leg off the call and leave the far party
    /// as its one SIP leg, in the A-leg slot, as on a call siphon answered
    /// itself. The far party's in-dialog requests are then answered here
    /// (a re-offer against the session in force), and every teardown path ends
    /// the call through that one leg.
    ///
    /// When the named leg was the A-leg, its Call-ID stays the call's name in
    /// the registry (a script, an engine event and `b2bua.terminate` know the
    /// call by it), though no leg carries it, so an in-dialog request on the
    /// ended dialog finds no leg and is answered 481. The named B-leg's
    /// Call-ID is retired as a teardown retires it.
    pub fn complete_adoption(&self, call_id: &str, replaced_on_a_leg: bool) -> Option<AdoptedSwap> {
        let swap = {
            let mut call = self.calls.get_mut(call_id)?;
            let winner = call.winner?;
            if winner >= call.b_legs.len() || call.adoption.is_none() {
                return None;
            }
            let previous_a_call_id = call.a_leg.dialog.call_id.clone();
            call.shutdown_actors();
            let far = call.b_legs.swap_remove(winner);
            let replaced = if replaced_on_a_leg {
                call.a_leg_local_addr = far.transport.local_addr;
                std::mem::replace(&mut call.a_leg, far)
            } else {
                far
            };
            call.b_legs.clear();
            call.b_leg_status.clear();
            call.b_leg_handles.clear();
            call.winner = None;
            let a_call_id = call.a_leg.dialog.call_id.clone();
            let ends_with_owner = match call.adoption.as_mut() {
                Some(adoption) => {
                    adoption.seated = true;
                    if replaced_on_a_leg && previous_a_call_id != a_call_id {
                        adoption.alias_call_id = Some(previous_a_call_id.clone());
                    }
                    adoption
                        .ends_with_owner
                        .then(|| adoption.owner_call_id.clone())
                }
                None => None,
            };
            publish_dialog_states(call.end_orphaned_dialogs());
            if let Some(owner) = ends_with_owner {
                self.adoptions
                    .by_owner
                    .entry(owner)
                    .or_default()
                    .push(call_id.to_string());
            }
            AdoptedSwap {
                replaced,
                previous_a_call_id,
                a_call_id,
            }
        };
        // The far party's dialog is the caller dialog of the call now.
        self.registry
            .register_call_id(&swap.a_call_id, call_id, LegSide::A);
        self.registry.remove_branch(&swap.replaced.branch);
        let replaced_call_id = &swap.replaced.dialog.call_id;
        if !replaced_on_a_leg && *replaced_call_id != swap.a_call_id {
            self.registry.remove_call_id(replaced_call_id, call_id);
            self.remember_terminated(replaced_call_id);
        }
        Some(swap)
    }

    /// The calls whose conference dialog ended, each once, to be torn down.
    pub fn take_orphaned_adoptions(&self) -> Vec<String> {
        let orphaned: Vec<String> = self
            .adoptions
            .orphaned
            .iter()
            .map(|entry| entry.key().clone())
            .collect();
        orphaned
            .into_iter()
            .filter(|call_id| self.adoptions.orphaned.remove(call_id).is_some())
            .collect()
    }

    /// Hand the adopted calls of every conference dialog no longer in the store
    /// to [`Self::take_orphaned_adoptions`]: the safety net behind the
    /// [`Self::remove_call`] hook, for a call taken out some other way.
    pub fn orphan_adoptions_of_ended_owners(&self) {
        let ended: Vec<String> = self
            .adoptions
            .by_owner
            .iter()
            .filter(|entry| !self.calls.contains_key(entry.key()))
            .map(|entry| entry.key().clone())
            .collect();
        for owner in ended {
            self.orphan_adoptions_of(&owner);
        }
    }

    /// How many conference dialogs have adopted calls that end with them, and
    /// how many adopted calls wait for their teardown (both drain to baseline:
    /// the per-module leak gate).
    pub fn adoptions_len(&self) -> (usize, usize) {
        (self.adoptions.by_owner.len(), self.adoptions.orphaned.len())
    }

    fn orphan_adoptions_of(&self, owner_call_id: &str) {
        if let Some((_, adopted)) = self.adoptions.by_owner.remove(owner_call_id) {
            for call_id in adopted {
                if self.calls.contains_key(&call_id) {
                    self.adoptions.orphaned.insert(call_id, ());
                }
            }
        }
    }

    /// `call` (`call_id`) has left the store: it leaves the index, the name it
    /// was adopted under goes with it, and the calls it adopted are orphaned.
    pub(super) fn adoption_ended(&self, call_id: &str, call: &CallActor) {
        self.adoptions.orphaned.remove(call_id);
        if let Some(adoption) = &call.adoption {
            if let Some(alias) = &adoption.alias_call_id {
                self.registry.remove_call_id(alias, call_id);
                self.remember_terminated(alias);
            }
            if adoption.ends_with_owner {
                if let Some(mut adopted) = self.adoptions.by_owner.get_mut(&adoption.owner_call_id)
                {
                    adopted.retain(|adopted_id| adopted_id != call_id);
                }
                self.adoptions
                    .by_owner
                    .remove_if(&adoption.owner_call_id, |_, adopted| adopted.is_empty());
            }
        }
        self.orphan_adoptions_of(call_id);
    }
}
