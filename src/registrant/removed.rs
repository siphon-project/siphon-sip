//! The de-REGISTER of an entry that is gone from the manager.
//!
//! A removed entry clears its binding with an `Expires: 0` REGISTER (RFC 3261
//! §10.2.2). Most registrars challenge every REGISTER, a de-registration
//! included (§22), so sending it and forgetting it leaves the binding in place
//! against them. The challenge has to be answered, once, with the entry's
//! credentials, and the whole exchange bounded: a final answer, a second
//! challenge, Timer F or [`DRAINING_LIFETIME`] ends it, and nothing stays.
//!
//! What it needs (credentials, registrar, Call-ID, the CSeq to continue from)
//! is kept here, apart from the live entries, so a removed trunk is in no
//! `list`, status or due-check while it drains.
//!
//! An IMS AKA entry is not tracked: its challenge needs the USIM's sequence
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
    entry: RegistrantEntry,
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
    /// The challenge needs credentials the manager does not hold: look them up
    /// and hand them to [`RegistrantManager::answer_after_lookup`].
    Lookup(Box<CredentialRequest>),
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

    /// Queue the de-REGISTER `built` of a binding the last process left, from
    /// `copy`, an entry without credentials (see [`super::startup`]).
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
                    deadline: Instant::now() + DRAINING_LIFETIME,
                },
            );
        }
        self.push_pending_deregistration(built);
    }

    pub(super) fn push_pending_deregistration(&self, built: BuiltRegister) {
        match self.pending_deregistrations.lock() {
            Ok(mut pending) => pending.push(built),
            Err(poisoned) => poisoned.into_inner().push(built),
        }
    }

    /// Track the de-REGISTER `built` of the removed (or replaced) `entry`, so
    /// the challenge to it is answered. Not for an AKA entry (see the module).
    fn track_removed_deregistration(&self, entry: &RegistrantEntry, built: &BuiltRegister) {
        if entry.auth_mode != AuthMode::Digest || entry.ue_ipsec.is_some() {
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
                deadline: Instant::now() + DRAINING_LIFETIME,
            },
        );
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
    pub fn answer_removed_deregistration(
        &self,
        call_id: &str,
        response_cseq: Option<u32>,
        status_code: u16,
        challenge: Option<(&DigestChallenge, bool)>,
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
        if (200..300).contains(&status_code) {
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
                    "removed registrant: the registrar challenged the de-REGISTER and no credential lookup is configured, binding left to expire"
                );
            } else if let (false, Some((challenge, is_proxy_auth))) =
                (draining.needs_lookup, challenge)
            {
                let built = self.build_register_with_auth_for(
                    &mut draining.entry,
                    defaults,
                    challenge,
                    is_proxy_auth,
                    0,
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
                "removed registrant: de-REGISTER not accepted, binding left to expire"
            );
        }
        let aor = draining.entry.aor.clone();
        drop(draining);
        self.draining_deregistrations.remove(call_id);
        self.forget_binding_record(&aor, call_id);
        RemovedAnswer::Finished
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
            let built = self.build_register_with_auth_for(
                &mut draining.entry,
                defaults,
                &request.challenge,
                request.is_proxy_auth,
                0,
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
        if let Some((_, draining)) = self.draining_deregistrations.remove(&call_id) {
            warn!(
                aor = %draining.entry.aor,
                registrar = %draining.entry.registrar_uri,
                "removed registrant: de-REGISTER {why}, binding left to expire"
            );
            self.forget_binding_record(&draining.entry.aor, &call_id);
        }
        true
    }

    /// Drop the tracked de-REGISTERs past [`DRAINING_LIFETIME`].
    pub fn expire_removed_deregistrations(&self, now: Instant) {
        let expired: Vec<(String, String)> = self
            .draining_deregistrations
            .iter()
            .filter(|draining| draining.deadline <= now)
            .map(|draining| (draining.key().clone(), draining.entry.aor.clone()))
            .collect();
        for (call_id, aor) in expired {
            if self.draining_deregistrations.remove(&call_id).is_some() {
                self.forget_binding_record(&aor, &call_id);
            }
        }
    }
}
