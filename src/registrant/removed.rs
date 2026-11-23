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

use super::{AuthMode, BuiltRegister, EgressDefaults, RegistrantEntry, RegistrantManager};
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
    deadline: Instant,
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
    /// Track the de-REGISTER `built` of the removed (or replaced) `entry`, so
    /// the challenge to it is answered. Not for an AKA entry (see the module).
    pub(super) fn track_removed_deregistration(
        &self,
        entry: &RegistrantEntry,
        built: &BuiltRegister,
    ) {
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
            if let Some((challenge, is_proxy_auth)) = challenge {
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
        drop(draining);
        self.draining_deregistrations.remove(call_id);
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
        }
        true
    }

    /// Drop the tracked de-REGISTERs past [`DRAINING_LIFETIME`].
    pub fn expire_removed_deregistrations(&self, now: Instant) {
        self.draining_deregistrations
            .retain(|_, draining| draining.deadline > now);
    }
}
