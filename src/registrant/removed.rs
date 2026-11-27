//! The de-REGISTER of an entry that is gone from the manager.
//!
//! A removed entry clears its binding with an `Expires: 0` REGISTER (RFC 3261
//! §10.2.2), but only after a fetch (§10.2.3, no Contact and no Expires) on the
//! same Call-ID shows the registrar still lists this node's own Contact: a
//! registrar that keeps one binding per AoR dropped it when another node
//! registered, and an `Expires: 0` then clears the other node's. Any other
//! outcome of the fetch (another Contact only, none, a non-2xx, Timer F) sends no
//! `Expires: 0` and leaves the binding to expire. The same exchange precedes the
//! de-REGISTER of a live removal, of a source update that moves the binding, of
//! shutdown (the entry stays, see [`super::lifecycle`]) and of a restart's
//! clean-up (see [`super::startup`]). Most registrars challenge every REGISTER, a de-registration
//! included (§22), so sending it and forgetting it leaves the binding in place
//! against them. The challenge has to be answered, once, with the entry's
//! credentials, and the whole exchange bounded: a final answer, a second
//! challenge, Timer F or [`DRAINING_LIFETIME`] ends it, and nothing stays.
//!
//! What it needs (credentials, registrar, Call-ID, the CSeq to continue from)
//! is kept here, apart from the live entries, so a removed trunk is in no
//! `list`, status or due-check while it drains.
//!
//! An IMS AKA entry is not tracked and not fetched: its challenge needs the USIM's sequence
//! number and the SA set, which go with the entry, and its protected
//! de-REGISTER and teardown have their own path (see `protected`).

use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

use super::{
    AuthMode, BuiltRegister, EgressDefaults, RegistrantCredentials, RegistrantEntry,
    RegistrantManager, RegistrantState,
};
use crate::auth::DigestChallenge;
use crate::sip::message::SipMessage;

/// How long a removed entry's de-REGISTER may stay tracked: Timer F (64·T1)
/// with room for one challenge answered. The transaction's own Timer F
/// normally ends it first; this bounds the case where no transaction was
/// opened.
pub(super) const DRAINING_LIFETIME: Duration = Duration::from_secs(70);

/// A removed entry's de-REGISTER in flight.
pub(super) struct DrainingDeregistration {
    /// A copy of what answering a challenge needs.
    pub(super) entry: RegistrantEntry,
    /// Via branch of the request in flight (its Timer F names it).
    branch: String,
    /// CSeq of the request in flight: an answer carrying another one belongs
    /// to an earlier REGISTER of the entry and is not this de-registration's.
    cseq: u32,
    /// Whether the challenge was answered already.
    challenged: bool,
    /// The entry holds no credentials (a binding the last process left, found
    /// at start-up): a challenge is answered from the source's lookup.
    needs_lookup: bool,
    /// The request in flight is the fetch of RFC 3261 §10.2.3 a restart sends
    /// before it clears a binding (see [`super::startup`]); the de-REGISTER
    /// follows only when the registrar lists this node's Contact.
    fetching: bool,
    /// The entry is still in the manager, shutting down: its own
    /// [`Deregistration`](super::Deregistration) ends with this exchange.
    shutdown_of_live_entry: bool,
    /// A shutdown exchange's answer bound ([`super::SHUTDOWN_ANSWER_WAIT`] from the
    /// signal): a fetch answered after it sends no `Expires: 0`.
    answer_by: Option<tokio::time::Instant>,
    deadline: Instant,
}

/// What the lookup of the credentials for a challenged de-REGISTER needs.
#[derive(Debug, Clone)]
pub struct CredentialRequest {
    /// Call-ID of the de-REGISTER the challenge answered.
    pub call_id: String,
    pub aor: String,
    pub registrar_uri: String,
    /// The challenge to answer once the credentials are in.
    pub challenge: DigestChallenge,
    /// `true` for a 407.
    pub is_proxy_auth: bool,
}

/// What an answer to a removed entry's REGISTER came to.
#[derive(Debug)]
pub enum RemovedAnswer {
    /// No removed entry's de-REGISTER has this Call-ID.
    NotTracked,
    /// An answer to an earlier REGISTER of the removed entry; the
    /// de-REGISTER is still in flight.
    Stale,
    /// The de-registration is over (answered, refused, or given up on).
    Finished,
    /// The challenge, answered: send this.
    Retry(Box<BuiltRegister>),
    /// The fetch of a restart's clean-up listed this node's Contact: its
    /// de-REGISTER is staged for the checks made just before it goes.
    Continued,
    /// The challenge needs credentials the manager does not hold: look them up
    /// and hand them to [`RegistrantManager::answer_after_lookup`].
    Lookup(Box<CredentialRequest>),
}

static DEPRECATED_ANSWER_NOTICE: std::sync::Once = std::sync::Once::new();
static DEPRECATED_ANSWER_NOTICED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Whether the deprecated-answer warning was logged by this process.
#[cfg(test)]
pub(crate) fn deprecated_answer_noticed() -> bool {
    DEPRECATED_ANSWER_NOTICED.load(std::sync::atomic::Ordering::SeqCst)
}

/// The CSeq number of `message`.
pub fn cseq_number(message: &SipMessage) -> Option<u32> {
    message
        .headers
        .get("CSeq")?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

impl RegistrantEntry {
    /// Whether the registrar may hold a binding from this entry, so removing
    /// it has to clear one: a grant that has not run out (a refresh, forced or
    /// after a source update, moves the state on while the binding stays, and
    /// a refresh that failed leaves the earlier grant in place), or a REGISTER
    /// that may have reached the registrar without an answer (in flight, or
    /// timed out: RFC 3261 §10.3 answers 200 to removing a contact it does not
    /// hold, so clearing it is harmless).
    pub fn holds_binding(&self) -> bool {
        self.binding_until.is_some_and(|at| at > Instant::now())
            || self.register_in_flight()
            || self.register_unanswered
    }

    fn register_in_flight(&self) -> bool {
        matches!(
            self.state,
            RegistrantState::Registering | RegistrantState::Challenging
        )
    }

    /// Whether a REGISTER of `other` would bind the same contact on the same
    /// registrar as this entry's does, so replacing this entry with it is a
    /// refresh of the binding rather than a second one.
    fn same_binding_target(&self, other: &RegistrantEntry) -> bool {
        self.registrar_uri == other.registrar_uri
            && self.destination == other.destination
            && self.transport == other.transport
            && self.contact_uri == other.contact_uri
            && self.local_addr == other.local_addr
            && self.credentials.username == other.credentials.username
    }

    /// Take over the binding `existing` holds when this entry, replacing it,
    /// targets the same one: a refresh of it, so the Call-ID carries over, the
    /// CSeq continues (RFC 3261 §10.2.4 / §8.1.1.5) and a removal before the
    /// refresh is answered still clears it. Returns `false` when the binding is
    /// elsewhere and has to be cleared there.
    pub(super) fn carry_binding_from(&mut self, existing: &RegistrantEntry) -> bool {
        if !existing.same_binding_target(self) {
            return false;
        }
        self.call_id = existing.call_id.clone();
        self.cseq = std::sync::atomic::AtomicU32::new(
            existing.cseq.load(std::sync::atomic::Ordering::Relaxed),
        );
        self.expires_at = existing.expires_at;
        self.binding_until = existing.binding_until;
        self.register_unanswered = existing.register_unanswered || existing.register_in_flight();
        true
    }

    /// Whether a de-REGISTER of this entry is preceded by the fetch of RFC 3261
    /// §10.2.3, so it clears the binding only when the registrar still lists
    /// this node's Contact: a digest entry. An IMS entry (AKA, or any with an
    /// IPsec UE) is not: its S-CSCF keeps every contact of the IMPU instead of
    /// replacing them, its de-REGISTER rides the SA set it registered over, and
    /// an unprotected fetch would not reach the protected port (see the module).
    pub(super) fn fetches_before_deregistering(&self) -> bool {
        self.auth_mode == AuthMode::Digest && self.ue_ipsec.is_none()
    }

    /// What a challenge to this entry's de-REGISTER is answered from.
    fn copy_for_draining(&self) -> RegistrantEntry {
        let mut copy = RegistrantEntry::new(
            self.aor.clone(),
            self.registrar_uri.clone(),
            self.destination,
            self.transport,
            self.credentials.clone(),
            self.interval_secs,
            self.contact_uri.clone(),
        );
        copy.call_id = self.call_id.clone();
        copy.cseq =
            std::sync::atomic::AtomicU32::new(self.cseq.load(std::sync::atomic::Ordering::Relaxed));
        // The Contact the registrar was given, which the fetch's answer is read
        // against and the de-REGISTER names.
        copy.contact_uri = self
            .contact_uri
            .clone()
            .or_else(|| self.sent_contact.clone());
        copy.sent_contact = self.sent_contact.clone();
        copy.local_addr = self.local_addr;
        copy.ims_contact = self.ims_contact.clone();
        copy.register_extras = self.register_extras.clone();
        copy
    }
}

impl RegistrantManager {
    /// Queue the de-REGISTER `built` of the removed (or replaced) `entry` for
    /// the loop to send, and track it so the challenge to it is answered.
    pub(super) fn queue_removed_deregistration(
        &self,
        entry: &RegistrantEntry,
        built: BuiltRegister,
    ) {
        self.track_removed_deregistration(entry, &built);
        self.push_pending_deregistration(built);
    }

    /// Queue the fetch `built` (RFC 3261 §10.2.3) that precedes the de-REGISTER
    /// of a binding the last process left, from `copy`, an entry without
    /// credentials (see [`super::startup`]).
    pub(super) fn queue_startup_deregistration(&self, copy: RegistrantEntry, built: BuiltRegister) {
        if let Some(cseq) = cseq_number(&built.message) {
            self.draining_deregistrations.insert(
                copy.call_id.clone(),
                DrainingDeregistration {
                    entry: copy,
                    branch: built.branch.clone(),
                    cseq,
                    challenged: false,
                    needs_lookup: true,
                    fetching: true,
                    shutdown_of_live_entry: false,
                    answer_by: None,
                    deadline: Instant::now() + DRAINING_LIFETIME,
                },
            );
        }
        // Held for the checks made just before it goes.
        self.stage_startup_deregistration(built);
    }

    pub(super) fn push_pending_deregistration(&self, built: BuiltRegister) {
        match self.pending_deregistrations.lock() {
            Ok(mut pending) => pending.push(built),
            Err(poisoned) => poisoned.into_inner().push(built),
        }
    }

    /// Track the de-REGISTER `built` of the removed (or replaced) `entry`, so
    /// the challenge to it is answered. `built` is the fetch that goes before
    /// it when the entry takes one ([`RegistrantEntry::fetches_before_deregistering`]).
    /// Not for an AKA entry (see the module).
    fn track_removed_deregistration(&self, entry: &RegistrantEntry, built: &BuiltRegister) {
        self.track_digest_deregistration(entry, built, false);
    }

    /// Track the fetch or de-REGISTER `built` of a live `entry` that is shutting
    /// down, whose [`Deregistration`](super::Deregistration) the exchange ends.
    pub(super) fn track_shutdown_deregistration(
        &self,
        entry: &RegistrantEntry,
        built: &BuiltRegister,
    ) {
        self.track_digest_deregistration(entry, built, true);
    }

    fn track_digest_deregistration(
        &self,
        entry: &RegistrantEntry,
        built: &BuiltRegister,
        shutdown_of_live_entry: bool,
    ) {
        if !entry.fetches_before_deregistering() {
            return;
        }
        let Some(cseq) = cseq_number(&built.message) else {
            return;
        };
        self.draining_deregistrations.insert(
            entry.call_id.clone(),
            DrainingDeregistration {
                entry: entry.copy_for_draining(),
                branch: built.branch.clone(),
                cseq,
                challenged: false,
                needs_lookup: false,
                fetching: true,
                shutdown_of_live_entry,
                answer_by: shutdown_of_live_entry
                    .then(|| self.shutdown_answer_by.get().copied())
                    .flatten(),
                deadline: Instant::now() + DRAINING_LIFETIME,
            },
        );
    }

    /// Take the de-registrations queued by [`Self::remove`] and the restart
    /// clean-up, leaving none. A restart's is checked again here, just before it
    /// would leave: see [`Self::startup_deregistration_superseded`].
    pub(super) fn take_pending_deregistrations(&self) -> Vec<BuiltRegister> {
        let taken = match self.pending_deregistrations.lock() {
            Ok(mut pending) => std::mem::take(&mut *pending),
            Err(poisoned) => std::mem::take(&mut *poisoned.into_inner()),
        };
        taken
            .into_iter()
            .filter(|built| {
                !built
                    .message
                    .headers
                    .get("Call-ID")
                    .is_some_and(|call_id| self.startup_deregistration_superseded(call_id))
            })
            .collect()
    }

    /// Whether the restart de-REGISTER on `call_id` must not go: a live entry
    /// now holds the AoR on the same Contact, so an `Expires: 0` on that Contact
    /// would delete its binding (RFC 3261 §10.3). It is forgotten, record
    /// included.
    pub(super) fn startup_deregistration_superseded(&self, call_id: &str) -> bool {
        let superseded =
            self.draining_deregistrations
                .get(call_id)
                .filter(|draining| draining.needs_lookup)
                .is_some_and(|draining| {
                    let Some(contact) = draining.entry.contact_uri.as_deref() else {
                        return false;
                    };
                    self.entries.get(&draining.entry.aor).is_some_and(|live| {
                        // The same registrar: one moved to another is a binding the
                        // old registrar still holds.
                        live.registrar_uri == draining.entry.registrar_uri
                            && live.transport == draining.entry.transport
                            && (live.sent_contact.as_deref().is_some_and(|sent| {
                                super::contact::contacts_equivalent(sent, contact)
                            }) || self.egress.get().is_some_and(|egress| {
                                super::contact::contacts_equivalent(
                                    &self.predicted_contact(&live, egress.defaults()),
                                    contact,
                                )
                            }))
                    })
                });
        if superseded {
            if let Some((_, draining)) = self.draining_deregistrations.remove(call_id) {
                info!(
                    aor = %draining.entry.aor,
                    registrar = %draining.entry.registrar_uri,
                    "restart clean-up: a live entry holds the binding now, its de-REGISTER is not sent"
                );
                self.forget_binding_record(&draining.entry.aor, call_id);
            }
        }
        superseded
    }

    /// Whether a de-REGISTER (or the fetch before it) on `call_id` is tracked,
    /// so its answers are the removal path's, not a live entry's.
    pub fn is_deregistering(&self, call_id: &str) -> bool {
        self.draining_deregistrations.contains_key(call_id)
    }

    /// How many removed entries' de-REGISTERs are still tracked.
    pub fn removed_deregistrations_pending(&self) -> usize {
        self.draining_deregistrations.len()
    }

    /// A final answer (`status_code`, carrying `response_cseq`) to a REGISTER
    /// with Call-ID `call_id` that no live entry owns. A 401 or 407 is
    /// answered once, with `challenge` (`true`: proxy authentication), as
    /// `Expires: 0` on the same Call-ID with the next CSeq; a second one, any
    /// other failure or a 2xx ends the de-registration.
    ///
    /// **Deprecated.** It is given no `Contact` headers, so it cannot read the
    /// answer to the fetch that now precedes a digest de-REGISTER (RFC 3261
    /// §10.2.3). On such a fetch's 2xx it ends the exchange without sending
    /// `Expires: 0` (the safe side: the binding expires on its own) and logs a
    /// warning once per process. Use [`answer_removed_registration`](Self::answer_removed_registration).
    /// On a de-REGISTER that is not preceded by a fetch it behaves as before.
    #[deprecated(
        note = "cannot read a fetch's answer, so it never sends Expires: 0 after one; use answer_removed_registration with the response's Contact headers"
    )]
    pub fn answer_removed_deregistration(
        &self,
        call_id: &str,
        response_cseq: Option<u32>,
        status_code: u16,
        challenge: Option<(&DigestChallenge, bool)>,
        defaults: EgressDefaults<'_>,
    ) -> RemovedAnswer {
        let undecidable = (200..300).contains(&status_code)
            && self
                .draining_deregistrations
                .get(call_id)
                .is_some_and(|draining| draining.fetching && response_cseq == Some(draining.cseq));
        if undecidable {
            DEPRECATED_ANSWER_NOTICE.call_once(|| {
                DEPRECATED_ANSWER_NOTICED.store(true, std::sync::atomic::Ordering::SeqCst);
                warn!(
                    "answer_removed_deregistration cannot read the answer to the fetch before a \
                     de-REGISTER, so it sends no Expires: 0; use answer_removed_registration \
                     with the response's Contact headers"
                );
            });
            self.conclude_draining(call_id, Some(0));
            return RemovedAnswer::Finished;
        }
        self.answer_removed_registration(
            call_id,
            response_cseq,
            status_code,
            challenge,
            &[],
            None,
            defaults,
        )
    }

    /// [`answer_removed_deregistration`](Self::answer_removed_deregistration)
    /// also given the `Contact` header lines of the answer and its `Expires`
    /// header (a Contact whose effective expiry is zero is not bound, RFC 3261
    /// §10.3 step 8), which the fetch a
    /// restart sends first needs (RFC 3261 §10.2.3): its 2xx lists the bindings
    /// the registrar holds. The de-REGISTER follows only when one is this
    /// node's Contact ([`RemovedAnswer::Continued`]); otherwise the binding is
    /// not ours to clear (a registrar that keeps one binding per AoR has
    /// already replaced it) or is gone, and it is left, record dropped.
    ///
    /// Known limit: a registrar that replaces the AoR's binding on every
    /// REGISTER can still be overwritten by another node between this fetch
    /// and the de-REGISTER that follows; nothing closes that window, and the
    /// binding then returns at the other node's next refresh.
    pub fn answer_removed_registration(
        &self,
        call_id: &str,
        response_cseq: Option<u32>,
        status_code: u16,
        challenge: Option<(&DigestChallenge, bool)>,
        contacts: &[String],
        response_expires: Option<u32>,
        defaults: EgressDefaults<'_>,
    ) -> RemovedAnswer {
        let Some(mut draining) = self.draining_deregistrations.get_mut(call_id) else {
            return RemovedAnswer::NotTracked;
        };
        if response_cseq != Some(draining.cseq) {
            debug!(
                call_id,
                ?response_cseq,
                "removed registrant: answer to an earlier REGISTER, de-REGISTER still in flight"
            );
            return RemovedAnswer::Stale;
        }
        let mut skipped = false;
        let mut status_code_override: Option<u16> = None;
        if (200..300).contains(&status_code) && draining.fetching {
            let ours = draining.entry.contact_uri.clone().unwrap_or_default();
            let listed = super::contact::bound_contact_uris(contacts, response_expires)
                .iter()
                .any(|listed| super::contact::contacts_equivalent(listed, &ours));
            if listed
                && draining
                    .answer_by
                    .is_some_and(|bound| tokio::time::Instant::now() >= bound)
            {
                warn!(
                    aor = %draining.entry.aor,
                    registrar = %draining.entry.registrar_uri,
                    "shutdown: the fetch was answered after the shutdown bound, \
                     no de-REGISTER is sent and the binding is left to expire"
                );
                // Over, with no answer to the de-REGISTER to come.
                status_code_override = Some(0);
            } else if listed && self.superseded_by_live_entry(&draining) {
                info!(
                    aor = %draining.entry.aor,
                    registrar = %draining.entry.registrar_uri,
                    "de-REGISTER not sent: a live entry holds the binding on this Contact now"
                );
                skipped = true;
            } else if listed {
                let built = self.build_unprotected_register(&mut draining.entry, defaults, 0, None);
                if let Some(built) = built {
                    if let Some(cseq) = cseq_number(&built.message) {
                        draining.cseq = cseq;
                        draining.branch = built.branch.clone();
                        draining.challenged = false;
                        draining.fetching = false;
                        draining.deadline = Instant::now() + DRAINING_LIFETIME;
                        // A restart's goes through the checks made just before
                        // it leaves; a live entry's is sent by the caller, now.
                        let staged = draining.needs_lookup;
                        drop(draining);
                        if staged {
                            self.stage_startup_deregistration(built);
                            return RemovedAnswer::Continued;
                        }
                        return RemovedAnswer::Retry(Box::new(built));
                    }
                }
                warn!(
                    aor = %draining.entry.aor,
                    registrar = %draining.entry.registrar_uri,
                    "de-REGISTER cannot be built after the fetch, binding left to expire"
                );
            } else {
                info!(
                    aor = %draining.entry.aor,
                    registrar = %draining.entry.registrar_uri,
                    listed = contacts.len(),
                    "the registrar does not list this node's Contact, \
                     the binding is not this node's to clear and is left"
                );
                skipped = true;
            }
        } else if (200..300).contains(&status_code) {
            info!(aor = %draining.entry.aor, "removed registrant de-registered");
        } else if matches!(status_code, 401 | 407) && !draining.challenged {
            if let (true, Some((challenge, is_proxy_auth))) = (draining.needs_lookup, challenge) {
                let configured = self
                    .restart
                    .credential_lookup
                    .get()
                    .is_some_and(|lookup| lookup.is_configured());
                if configured {
                    draining.challenged = true;
                    draining.deadline = Instant::now() + DRAINING_LIFETIME;
                    return RemovedAnswer::Lookup(Box::new(CredentialRequest {
                        call_id: call_id.to_string(),
                        aor: draining.entry.aor.clone(),
                        registrar_uri: draining.entry.registrar_uri.clone(),
                        challenge: challenge.clone(),
                        is_proxy_auth,
                    }));
                }
                warn!(
                    aor = %draining.entry.aor,
                    registrar = %draining.entry.registrar_uri,
                    fetch = draining.fetching,
                    "removed registrant: the registrar challenged the de-REGISTER (or the fetch before it) and no credential lookup is configured, binding left to expire"
                );
            } else if let (false, Some((challenge, is_proxy_auth))) =
                (draining.needs_lookup, challenge)
            {
                let fetch = draining.fetching;
                let built = self.build_register_with_auth_as(
                    &mut draining.entry,
                    defaults,
                    challenge,
                    is_proxy_auth,
                    0,
                    fetch,
                );
                if let Some(built) = built {
                    if let Some(cseq) = cseq_number(&built.message) {
                        draining.cseq = cseq;
                        draining.branch = built.branch.clone();
                        draining.challenged = true;
                        draining.deadline = Instant::now() + DRAINING_LIFETIME;
                        return RemovedAnswer::Retry(Box::new(built));
                    }
                }
            }
            warn!(
                aor = %draining.entry.aor,
                registrar = %draining.entry.registrar_uri,
                "removed registrant: cannot answer the challenge to its de-REGISTER, binding left to expire"
            );
        } else {
            warn!(
                aor = %draining.entry.aor,
                registrar = %draining.entry.registrar_uri,
                status_code,
                fetch = draining.fetching,
                "removed registrant: de-REGISTER (or the fetch before it) not accepted, binding left to expire"
            );
        }
        drop(draining);
        let outcome = status_code_override.or((!skipped).then_some(status_code));
        self.conclude_draining(call_id, outcome);
        RemovedAnswer::Finished
    }

    /// End the tracked de-registration on `call_id`: forget it and its record,
    /// and, when it is a shutting-down live entry's, end that entry's
    /// [`Deregistration`](super::Deregistration) too. `status_code` is the final
    /// answer (`Some(0)`: none), `None` when no de-REGISTER was needed.
    fn conclude_draining(&self, call_id: &str, status_code: Option<u16>) {
        let Some((_, draining)) = self.draining_deregistrations.remove(call_id) else {
            return;
        };
        if draining.shutdown_of_live_entry {
            self.finish_shutdown_deregistration(&draining.entry.aor, status_code);
        } else {
            self.forget_binding_record(&draining.entry.aor, call_id);
        }
    }

    /// Whether a live entry now holds `draining`'s AoR on the Contact its
    /// de-REGISTER would clear, on the same registrar and destination, so an
    /// `Expires: 0` on it would clear that entry's binding (RFC 3261 §10.3). A
    /// removal followed by the same trunk added again meets it. Not for a
    /// shutting-down entry (it is the live one) or a restart's (see
    /// [`Self::startup_deregistration_superseded`]).
    fn superseded_by_live_entry(&self, draining: &DrainingDeregistration) -> bool {
        if draining.needs_lookup || draining.shutdown_of_live_entry {
            return false;
        }
        let Some(contact) = draining.entry.contact_uri.as_deref() else {
            return false;
        };
        self.entries.get(&draining.entry.aor).is_some_and(|live| {
            live.registrar_uri == draining.entry.registrar_uri
                && live.destination == draining.entry.destination
                && live.transport == draining.entry.transport
                && live
                    .sent_contact
                    .as_deref()
                    .is_some_and(|sent| super::contact::contacts_equivalent(sent, contact))
        })
    }

    /// The credentials for `request`'s challenge, looked up: `Ok(Some(..))` a
    /// row, `Ok(None)` the source does not know the AoR, `Err` it could not be
    /// asked. Answers the challenge with them, once; without them the binding
    /// is left to expire (logged with the AoR and registrar) and the
    /// de-registration ends.
    pub fn answer_after_lookup(
        &self,
        request: &CredentialRequest,
        credentials: Result<Option<RegistrantCredentials>, String>,
        defaults: EgressDefaults<'_>,
    ) -> RemovedAnswer {
        // The lookup may have taken a while: the trunk may be live on that
        // Contact by now.
        if self.startup_deregistration_superseded(&request.call_id) {
            return RemovedAnswer::Finished;
        }
        let Some(mut draining) = self.draining_deregistrations.get_mut(&request.call_id) else {
            // Ended meanwhile (Timer F, the sweep): nothing to answer.
            return RemovedAnswer::NotTracked;
        };
        let credentials = match credentials {
            Ok(Some(credentials)) => Some(credentials),
            Ok(None) => {
                warn!(
                    aor = %request.aor,
                    registrar = %request.registrar_uri,
                    "removed registrant: the source does not know the AoR, the challenge to its de-REGISTER is not answered, binding left to expire"
                );
                None
            }
            Err(error) => {
                warn!(
                    aor = %request.aor,
                    registrar = %request.registrar_uri,
                    %error,
                    "removed registrant: the credential lookup failed, the challenge to its de-REGISTER is not answered, binding left to expire"
                );
                None
            }
        };
        if let Some(credentials) = credentials {
            draining.entry.credentials = credentials;
            let fetch = draining.fetching;
            let built = self.build_register_with_auth_as(
                &mut draining.entry,
                defaults,
                &request.challenge,
                request.is_proxy_auth,
                0,
                fetch,
            );
            if let Some(built) = built {
                if let Some(cseq) = cseq_number(&built.message) {
                    draining.cseq = cseq;
                    draining.branch = built.branch.clone();
                    draining.deadline = Instant::now() + DRAINING_LIFETIME;
                    return RemovedAnswer::Retry(Box::new(built));
                }
            }
            warn!(
                aor = %request.aor,
                registrar = %request.registrar_uri,
                "removed registrant: cannot answer the challenge with the looked-up credentials, binding left to expire"
            );
        }
        drop(draining);
        self.draining_deregistrations.remove(&request.call_id);
        self.forget_binding_record(&request.aor, &request.call_id);
        RemovedAnswer::Finished
    }

    /// Timer F of the de-REGISTER with Via branch `branch` fired, or it could
    /// not be sent: give up on it. `true` when it was a removed entry's.
    pub fn removed_deregistration_ended(&self, branch: &str, why: &str) -> bool {
        let Some(call_id) = self
            .draining_deregistrations
            .iter()
            .find(|draining| draining.branch == branch)
            .map(|draining| draining.key().clone())
        else {
            return false;
        };
        if let Some(draining) = self.draining_deregistrations.get(&call_id) {
            warn!(
                aor = %draining.entry.aor,
                registrar = %draining.entry.registrar_uri,
                fetch = draining.fetching,
                "removed registrant: de-REGISTER (or the fetch before it) {why}, binding left to expire"
            );
        }
        self.conclude_draining(&call_id, Some(0));
        true
    }

    /// Drop the tracked de-REGISTERs past [`DRAINING_LIFETIME`].
    pub fn expire_removed_deregistrations(&self, now: Instant) {
        let expired: Vec<String> = self
            .draining_deregistrations
            .iter()
            .filter(|draining| draining.deadline <= now)
            .map(|draining| draining.key().clone())
            .collect();
        for call_id in expired {
            self.conclude_draining(&call_id, Some(0));
        }
    }
}
