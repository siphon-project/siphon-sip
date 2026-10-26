//! When a REGISTER may start, and the client transaction it is sent under.
//!
//! **Shutdown.** Once [`RegistrantManager::begin_shutdown`] has run, which
//! [`super::deregister_all`] does before a single de-REGISTER leaves, nothing
//! starts a registration again: no entry is added, updated or moved, none is
//! due, a forced refresh is refused, and no REGISTER with `Expires > 0` is
//! built. A process that is going away and registers again leaves the
//! registrar holding a binding (and, for an IMS UE, the P-CSCF holding a
//! security association) for a UE whose next process registers it afresh.
//!
//! What it does instead is de-register (TS 24.229 5.1.1.6, RFC 3261 §10.2.2):
//! every registered entry sends `Expires: 0` on its registration's Call-ID,
//! over its SA set and from its own address, and an entry whose REGISTER is
//! in flight sends it once that is answered (§10.2: one REGISTER at a time),
//! never acting on the binding meanwhile. A challenged de-REGISTER answers its
//! challenge, still with `Expires: 0`. The entries stay, so their answers find
//! them, and so do their sockets; a de-registration ends with its final
//! response or its Timer F ([`Deregistration`]), which deletes the entry's SA
//! sets, and shutdown waits, bounded, for all of them
//! ([`super::retire_ue_security_associations`]).
//!
//! **Transactions.** Every REGISTER, de-REGISTER included, is sent under a
//! non-INVITE client transaction of the dispatcher's transaction layer (RFC 3261
//! §17.1.2), opened through [`RegisterTransactions`] just before it goes on the
//! wire. Over UDP the transaction retransmits it on Timer E, from T1 doubling to
//! T2, the same octets from the same socket (a UE's own address, or its
//! protected client port and so its SA), until a response arrives; over TCP it
//! never does. Timer F ends an unanswered one as a timeout
//! ([`RegistrantManager::transaction_timed_out`]). The registrant keeps no
//! timer of its own for either.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, info, warn};

use super::{RegistrantManager, RegistrantState};
use crate::sip::message::SipMessage;
use crate::transport::OutboundMessage;

/// Opens the client transaction a registrant REGISTER is sent under.
///
/// Implemented by the dispatcher, whose timer sweep drives the transaction's
/// timers and whose response path feeds it the answers.
pub trait RegisterTransactions: Send + Sync {
    /// Open a non-INVITE client transaction for `request`, whose wire form is
    /// `message`, before `message` is sent. Its retransmissions go where
    /// `message` goes, from the same local address.
    fn open(&self, request: &SipMessage, message: &OutboundMessage) -> Result<(), String>;
}

/// Where an entry is in the shutdown de-registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deregistration {
    /// Not shutting down, or nothing to de-register.
    NotStarted,
    /// A REGISTER was in flight at shutdown: the de-REGISTER goes once it is
    /// answered with a binding.
    Owed,
    /// The de-REGISTER (or the answer to its challenge) is in flight.
    InFlight,
    /// Answered, timed out, or nothing was registered after all.
    Done,
}

impl RegistrantManager {
    /// Stop starting registrations, for good. Idempotent.
    pub fn begin_shutdown(&self) {
        if !self.shutting_down.swap(true, Ordering::SeqCst) {
            info!("registrant shutting down: no new registration or refresh is started");
        }
    }

    /// Whether [`begin_shutdown`](Self::begin_shutdown) has run.
    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down.load(Ordering::SeqCst)
    }

    /// Whether a REGISTER of `aor` with `expires` must not be built: one that
    /// would register (`expires > 0`) once shutdown has begun.
    pub(super) fn refuses_registration(&self, aor: &str, expires: u32) -> bool {
        let refused = expires > 0 && self.is_shutting_down();
        if refused {
            debug!(aor = %aor, "registrant shutting down: REGISTER not started");
        }
        refused
    }

    /// Whether the registration of `aor` whose dialog is `call_id` may still
    /// go on: the entry is still the one that started it, not removed (or
    /// removed and added again), and either shutdown has not begun or this is
    /// its de-registration.
    pub fn registration_live(&self, aor: &str, call_id: &str) -> bool {
        self.entries.get(aor).is_some_and(|entry| {
            entry.call_id == call_id
                && (!self.is_shutting_down() || entry.deregistration == Deregistration::InFlight)
        })
    }

    /// Build the `Expires: 0` REGISTER that clears one entry's binding.
    ///
    /// `None` when the entry is unknown, was never registered (nothing to
    /// clear), or the loop has not started yet, so there is no egress to build
    /// a Via and Contact from.
    pub(super) fn build_deregistration(&self, aor: &str) -> Option<super::BuiltRegister> {
        let egress = self.egress.get()?;
        let entry = self.entries.get(aor)?;
        // A shutdown de-registration already covers (or covered) it.
        if entry.state != RegistrantState::Registered
            || entry.deregistration != Deregistration::NotStarted
        {
            return None;
        }
        drop(entry);
        self.build_register(aor, egress.defaults(), 0)
    }

    /// The `Expires` a REGISTER answering a challenge to `aor` carries: 0 for
    /// a de-registration, the entry's interval otherwise.
    pub fn challenge_expires(&self, aor: &str) -> u32 {
        if self.deregistration(aor) == Deregistration::InFlight {
            0
        } else {
            self.interval_for(aor)
        }
    }

    /// Where `aor` is in the shutdown de-registration.
    pub fn deregistration(&self, aor: &str) -> Deregistration {
        self.entries
            .get(aor)
            .map_or(Deregistration::NotStarted, |entry| entry.deregistration)
    }

    pub(super) fn deregistration_owed_or_in_flight(&self, aor: &str) -> bool {
        matches!(
            self.deregistration(aor),
            Deregistration::Owed | Deregistration::InFlight
        )
    }

    /// Whether any entry's shutdown de-registration has not ended yet.
    pub fn deregistrations_pending(&self) -> bool {
        self.entries.iter().any(|entry| {
            matches!(
                entry.deregistration,
                Deregistration::Owed | Deregistration::InFlight
            )
        })
    }

    /// Begin shutdown and build the de-REGISTER of every registered entry;
    /// mark the entries with a REGISTER in flight as owing one. Each built
    /// de-REGISTER is the entry's in-flight request from here on.
    pub(super) fn begin_deregistration(
        &self,
        defaults: super::EgressDefaults<'_>,
    ) -> Vec<super::BuiltRegister> {
        self.begin_shutdown();
        // Collected first: building takes each entry's write lock.
        let aors: Vec<(String, RegistrantState)> = self
            .entries
            .iter()
            .filter(|entry| entry.deregistration == Deregistration::NotStarted)
            .map(|entry| (entry.aor.clone(), entry.state))
            .collect();
        let mut built = Vec::new();
        for (aor, state) in aors {
            match state {
                RegistrantState::Registered => {
                    if let Some(deregistration) = self.start_deregistration(&aor, defaults) {
                        built.push(deregistration);
                    }
                }
                RegistrantState::Registering | RegistrantState::Challenging => {
                    self.set_deregistration(&aor, Deregistration::Owed);
                }
                _ => self.set_deregistration(&aor, Deregistration::Done),
            }
        }
        built
    }

    /// The de-REGISTER `aor` owed, now that the REGISTER in flight at shutdown
    /// was answered with a binding. `None` when it owes none.
    pub fn take_owed_deregistration(
        &self,
        aor: &str,
        defaults: super::EgressDefaults<'_>,
    ) -> Option<super::BuiltRegister> {
        if self.deregistration(aor) != Deregistration::Owed {
            return None;
        }
        self.start_deregistration(aor, defaults)
    }

    fn start_deregistration(
        &self,
        aor: &str,
        defaults: super::EgressDefaults<'_>,
    ) -> Option<super::BuiltRegister> {
        let built = self.build_register(aor, defaults, 0);
        match built.as_ref() {
            Some(built) => {
                if let Some(mut entry) = self.entries.get_mut(aor) {
                    entry.deregistration = Deregistration::InFlight;
                    entry.in_flight_branch = Some(built.branch.clone());
                }
            }
            None => self.set_deregistration(aor, Deregistration::Done),
        }
        built
    }

    fn set_deregistration(&self, aor: &str, deregistration: Deregistration) {
        if let Some(mut entry) = self.entries.get_mut(aor) {
            entry.deregistration = deregistration;
        }
    }

    /// The de-registration of `aor` ended with `status_code` (0: no answer):
    /// nothing is registered from here on, and its SA sets are deleted (TS
    /// 24.229 5.1.1.6.1, TS 33.203 7.4.1a).
    pub fn finish_deregistration(&self, aor: &str, status_code: u16) {
        let Some(mut entry) = self.entries.get_mut(aor) else {
            return;
        };
        if entry.deregistration == Deregistration::Done {
            return;
        }
        entry.deregistration = Deregistration::Done;
        entry.state = RegistrantState::Unregistered;
        entry.expires_at = None;
        entry.in_flight_branch = None;
        let address = entry.local_addr;
        let deletions: Vec<super::SaDeletion> = entry
            .ue_ipsec
            .as_mut()
            .map(|ipsec| {
                std::mem::take(&mut ipsec.sa_sets)
                    .keys()
                    .into_iter()
                    .map(|key| super::SaDeletion { address, key })
                    .collect()
            })
            .unwrap_or_default();
        drop(entry);
        self.queue_sa_deletions(deletions);
        if status_code == 200 {
            info!(aor = %aor, "de-registered for shutdown");
        } else {
            warn!(aor = %aor, status_code, "shutdown de-registration ended without a 200");
        }
        self.emit_event(super::RegistrantEvent::Deregistered {
            aor: aor.to_string(),
        });
    }

    /// Attach the transaction layer REGISTERs are sent under. Only the first
    /// attach counts.
    pub fn attach_transactions(&self, transactions: Arc<dyn RegisterTransactions>) {
        if self.transactions.set(transactions).is_err() {
            warn!("registrant: a transaction layer is already attached");
        }
    }

    /// Wait until the dispatcher has attached its transaction layer, so the
    /// first REGISTER is not sent before there is a transaction to send it
    /// under.
    pub(super) async fn transactions_attached(&self) {
        while self.transactions.get().is_none() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Open the client transaction `request` is sent under (see
    /// [`RegisterTransactions::open`]). Call it right before `message` goes on
    /// the wire; an `Err` means it must not go.
    pub fn open_transaction(
        &self,
        request: &SipMessage,
        message: &OutboundMessage,
    ) -> Result<(), String> {
        match self.transactions.get() {
            Some(transactions) => transactions.open(request, message),
            None => no_transaction_layer(),
        }
    }

    /// Timer F of the REGISTER with Via branch `branch` fired with no final
    /// response (RFC 3261 §17.1.2.2): fail the entry still waiting on it, as
    /// any failure does (backoff, and an IMS UE's temporary SA set dropped).
    /// Returns the AoR it failed; `None` when no entry waits on that branch any
    /// more (a removed entry's de-REGISTER, or one that has moved on).
    pub fn transaction_timed_out(&self, branch: &str) -> Option<String> {
        let aor = self
            .entries
            .iter()
            .find(|entry| {
                entry.in_flight_branch.as_deref() == Some(branch)
                    && (matches!(
                        entry.state,
                        RegistrantState::Registering | RegistrantState::Challenging
                    ) || entry.deregistration == Deregistration::InFlight)
            })
            .map(|entry| entry.aor.clone())?;
        warn!(aor = %aor, branch, "REGISTER transaction timed out: no response received");
        self.handle_failure(&aor, 0, None);
        Some(aor)
    }
}

/// No transaction layer attached. In the process that is never the case once
/// [`super::registration_loop`] runs (it waits for one); the registrant's unit
/// tests drive it without a dispatcher and send untracked.
#[cfg(not(test))]
fn no_transaction_layer() -> Result<(), String> {
    Err("no client transaction layer attached; REGISTER not sent".to_string())
}

#[cfg(test)]
fn no_transaction_layer() -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registrant::test_support::{self, trunk};
    use crate::registrant::EgressDefaults;
    use std::collections::HashMap;

    const AOR: &str = "sip:trunk@carrier.example";

    fn defaults(
        listen: &HashMap<crate::transport::Transport, std::net::SocketAddr>,
    ) -> EgressDefaults<'_> {
        EgressDefaults::new("192.0.2.1:5060".parse().expect("an address"), listen)
    }

    fn registered() -> RegistrantManager {
        let manager = test_support::manager();
        test_support::install_egress(&manager);
        manager.add(trunk(AOR));
        manager.handle_success(AOR, 3600);
        manager
    }

    #[test]
    fn shutdown_is_off_until_begun_and_stays_on() {
        let manager = test_support::manager();
        assert!(!manager.is_shutting_down());
        manager.begin_shutdown();
        manager.begin_shutdown();
        assert!(manager.is_shutting_down());
    }

    #[test]
    fn after_shutdown_no_register_is_built_but_a_de_register_is() {
        let manager = registered();
        let listen = HashMap::new();
        manager.begin_shutdown();

        assert!(manager
            .build_register(AOR, defaults(&listen), 3600)
            .is_none());
        let challenge = crate::auth::DigestChallenge {
            realm: "carrier.example".to_string(),
            nonce: "abc".to_string(),
            opaque: None,
            qop: Some("auth".to_string()),
            algorithm: crate::auth::DigestAlgorithm::Md5,
            stale: false,
        };
        assert!(manager
            .build_register_with_auth(AOR, defaults(&listen), &challenge, false, 3600)
            .is_none());
        assert!(manager
            .build_register_aka(AOR, defaults(&listen), &challenge, 3600, None)
            .is_none());

        let deregistration = manager
            .build_register(AOR, defaults(&listen), 0)
            .expect("a de-REGISTER still goes");
        assert_eq!(
            deregistration
                .message
                .headers
                .get("Expires")
                .map(String::as_str),
            Some("0")
        );
    }

    #[test]
    fn after_shutdown_nothing_is_due_refreshed_added_or_updated() {
        const SOURCED: &str = "sip:sourced@carrier.example";
        let manager = registered();
        manager.add(trunk(SOURCED).from_source(1));
        manager.handle_success(SOURCED, 3600);
        test_support::make_due(&manager, AOR);
        assert_eq!(manager.entries_due(), vec![AOR.to_string()]);

        manager.begin_shutdown();

        assert!(manager.entries_due().is_empty());
        assert!(!manager.refresh(AOR));
        assert!(manager.try_add(trunk("sip:other@carrier.example")).is_err());
        assert!(!manager.update_from_source(trunk(SOURCED).from_source(2)));
        assert_eq!(manager.len(), 2);
    }

    #[test]
    fn a_registration_is_live_only_for_its_own_entry_before_shutdown() {
        let manager = registered();
        let call_id = manager
            .entries
            .get(AOR)
            .map(|entry| entry.call_id.clone())
            .expect("an entry");

        assert!(manager.registration_live(AOR, &call_id));
        assert!(!manager.registration_live(AOR, "another-dialog"));
        manager.remove(AOR);
        assert!(!manager.registration_live(AOR, &call_id));

        let manager = registered();
        let call_id = manager
            .entries
            .get(AOR)
            .map(|entry| entry.call_id.clone())
            .expect("an entry");
        manager.begin_shutdown();
        assert!(!manager.registration_live(AOR, &call_id));
    }
}
