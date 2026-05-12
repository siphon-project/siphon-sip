//! SIP transaction layer — RFC 3261 §17.
//!
//! This module implements the four transaction state machines:
//! - **ICT**: INVITE Client Transaction (§17.1.1)
//! - **NICT**: Non-INVITE Client Transaction (§17.1.2)
//! - **IST**: INVITE Server Transaction (§17.2.1)
//! - **NIST**: Non-INVITE Server Transaction (§17.2.2)
//!
//! The [`TransactionManager`] owns all active transactions in a [`DashMap`]
//! keyed by [`TransactionKey`].

pub mod key;
pub mod state;
pub mod timer;

use dashmap::DashMap;

use crate::sip::headers::via::Via;
use crate::sip::message::{Method, SipMessage, StartLine};
use crate::transaction::key::TransactionKey;
use crate::transaction::state::*;
use crate::transaction::timer::TimerConfig;

/// A transaction — one of the four types.
#[derive(Debug)]
pub enum Transaction {
    Ict(Ict),
    Nict(Nict),
    Ist(Ist),
    Nist(Nist),
}

/// The transaction manager — holds all active transactions.
#[derive(Debug)]
pub struct TransactionManager {
    transactions: DashMap<TransactionKey, Transaction>,
    timers: TimerConfig,
}

impl TransactionManager {
    pub fn new(timers: TimerConfig) -> Self {
        Self {
            transactions: DashMap::new(),
            timers,
        }
    }

    /// Number of active transactions.
    pub fn count(&self) -> usize {
        self.transactions.len()
    }

    /// Check if a transaction exists for the given key.
    pub fn contains(&self, key: &TransactionKey) -> bool {
        self.transactions.contains_key(key)
    }

    /// Extract the transaction key from a SIP message.
    ///
    /// Uses the branch from the topmost Via header + the method.
    /// For responses, the method comes from the CSeq header.
    pub fn key_from_message(message: &SipMessage) -> Result<TransactionKey, String> {
        // Get branch from topmost Via
        let via_raw = message
            .headers
            .get("Via")
            .or_else(|| message.headers.get("v"))
            .ok_or("message has no Via header")?;

        let vias = Via::parse_multi(via_raw)?;
        let top_via = vias.first().ok_or("Via header is empty")?;
        let branch = top_via
            .branch
            .as_ref()
            .ok_or("topmost Via has no branch parameter")?;

        // Get method
        let method = match &message.start_line {
            StartLine::Request(request_line) => request_line.method.clone(),
            StartLine::Response(_) => {
                // For responses, method comes from CSeq
                let cseq_raw = message
                    .headers
                    .get("CSeq")
                    .ok_or("response has no CSeq header")?;
                let cseq = crate::sip::headers::cseq::CSeq::parse(cseq_raw)?;
                cseq.method
            }
        };

        let sent_by = TransactionKey::format_sent_by(&top_via.host, top_via.port);
        Ok(TransactionKey::new(branch.clone(), method, sent_by))
    }

    /// Create a new server transaction for an incoming request.
    ///
    /// Returns the initial actions (e.g. pass to TU) and the transaction key.
    pub fn new_server_transaction(
        &self,
        request: &SipMessage,
        transport: Transport,
    ) -> Result<(TransactionKey, Vec<Action>), String> {
        let key = Self::key_from_message(request)?;

        let method = match &request.start_line {
            StartLine::Request(request_line) => &request_line.method,
            _ => return Err("expected a request".to_string()),
        };

        let (transaction, actions) = match method {
            Method::Invite => {
                let ist = Ist::new(transport, self.timers);
                (Transaction::Ist(ist), vec![Action::PassToTu(request.clone())])
            }
            Method::Ack => {
                // ACK doesn't create its own transaction — it's matched to
                // the existing INVITE transaction. Return empty actions.
                return Ok((key, vec![]));
            }
            _ => {
                let (nist, mut actions) = Nist::new(request.clone(), transport, self.timers);
                actions.push(Action::PassToTu(request.clone()));
                (Transaction::Nist(nist), actions)
            }
        };

        self.transactions.insert(key.clone(), transaction);
        Ok((key, actions))
    }

    /// Handle an incoming ACK by matching it to an existing INVITE server
    /// transaction (IST).
    ///
    /// ACK for non-2xx responses is hop-by-hop and must be absorbed by the
    /// transaction layer (RFC 3261 §17.2.1). The IST transitions from
    /// Completed → Confirmed and the ACK never reaches the TU/script.
    ///
    /// Returns `Ok(Some(actions))` if an IST was found and processed (ACK
    /// absorbed), or `Ok(None)` if no IST exists — meaning this is either
    /// an ACK for a 2xx (end-to-end, handled by TU) or a stale ACK.
    pub fn handle_ack(
        &self,
        request: &SipMessage,
    ) -> Result<Option<(TransactionKey, Vec<Action>)>, String> {
        let key = Self::key_from_message(request)?;

        let mut entry = match self.transactions.get_mut(&key) {
            Some(entry) => entry,
            None => return Ok(None),
        };

        let actions = match &mut *entry {
            Transaction::Ist(ist) => {
                ist.process(IstEvent::AckReceived(request.clone()))
            }
            _ => {
                // Not an IST — nothing to absorb
                return Ok(None);
            }
        };

        let terminated = actions.iter().any(|a| matches!(a, Action::Terminated));
        let key_clone = key.clone();
        drop(entry);

        if terminated {
            self.transactions.remove(&key);
        }

        Ok(Some((key_clone, actions)))
    }

    /// Try to handle an incoming request as a retransmission.
    ///
    /// If a server transaction already exists for this request's key, feeds the
    /// retransmit event into the state machine and returns `Ok(Some(actions))`.
    /// If no transaction exists, returns `Ok(None)` — the caller should create
    /// a new server transaction.
    ///
    /// This is an atomic check-and-process to avoid race conditions.
    pub fn handle_server_retransmit(
        &self,
        request: &SipMessage,
    ) -> Result<Option<(TransactionKey, Vec<Action>)>, String> {
        let key = Self::key_from_message(request)?;

        let mut entry = match self.transactions.get_mut(&key) {
            Some(entry) => entry,
            None => return Ok(None),
        };

        let actions = match &mut *entry {
            Transaction::Ist(ist) => {
                ist.process(IstEvent::InviteRetransmit(request.clone()))
            }
            Transaction::Nist(nist) => {
                nist.process(NistEvent::RequestRetransmit(request.clone()))
            }
            _ => {
                // Client transactions shouldn't be here for a server retransmit
                return Ok(None);
            }
        };

        let terminated = actions.iter().any(|a| matches!(a, Action::Terminated));
        let key_clone = key.clone();
        drop(entry);

        if terminated {
            self.transactions.remove(&key);
        }

        Ok(Some((key_clone, actions)))
    }

    /// Create a new client transaction for an outgoing request.
    ///
    /// Returns the initial actions (send request, start timers).
    pub fn new_client_transaction(
        &self,
        request: SipMessage,
        transport: Transport,
    ) -> Result<(TransactionKey, Vec<Action>), String> {
        let key = Self::key_from_message(&request)?;

        let (transaction, actions) = match request.method() {
            Some(Method::Invite) => {
                let (ict, actions) = Ict::new(request, transport, self.timers);
                (Transaction::Ict(ict), actions)
            }
            Some(Method::Ack) => {
                // ACK doesn't create a client transaction
                return Err("ACK does not create a client transaction".to_string());
            }
            _ => {
                let (nict, actions) = Nict::new(request, transport, self.timers);
                (Transaction::Nict(nict), actions)
            }
        };

        self.transactions.insert(key.clone(), transaction);
        Ok((key, actions))
    }

    /// Pass an event to an existing server transaction.
    ///
    /// Returns the actions and whether the transaction was terminated.
    pub fn process_server_event(
        &self,
        key: &TransactionKey,
        event: ServerEvent,
    ) -> Result<Vec<Action>, String> {
        let mut entry = self
            .transactions
            .get_mut(key)
            .ok_or_else(|| format!("no transaction for key {key}"))?;

        let actions = match (&mut *entry, event) {
            (Transaction::Ist(ist), ServerEvent::Ist(event)) => ist.process(event),
            (Transaction::Nist(nist), ServerEvent::Nist(event)) => nist.process(event),
            _ => return Err("event type mismatch for transaction".to_string()),
        };

        // Check if terminated
        let terminated = actions.iter().any(|a| matches!(a, Action::Terminated));
        drop(entry);

        if terminated {
            self.transactions.remove(key);
        }

        Ok(actions)
    }

    /// Pass an event to an existing client transaction.
    pub fn process_client_event(
        &self,
        key: &TransactionKey,
        event: ClientEvent,
    ) -> Result<Vec<Action>, String> {
        let mut entry = self
            .transactions
            .get_mut(key)
            .ok_or_else(|| format!("no transaction for key {key}"))?;

        let actions = match (&mut *entry, event) {
            (Transaction::Ict(ict), ClientEvent::Ict(event)) => ict.process(event),
            (Transaction::Nict(nict), ClientEvent::Nict(event)) => nict.process(event),
            _ => return Err("event type mismatch for transaction".to_string()),
        };

        let terminated = actions.iter().any(|a| matches!(a, Action::Terminated));
        drop(entry);

        if terminated {
            self.transactions.remove(key);
        }

        Ok(actions)
    }

    /// Remove a transaction (e.g. on cleanup).
    pub fn remove(&self, key: &TransactionKey) -> Option<Transaction> {
        self.transactions.remove(key).map(|(_, transaction)| transaction)
    }
}

impl Default for TransactionManager {
    fn default() -> Self {
        Self::new(TimerConfig::default())
    }
}

/// Wrapper for server-side events.
#[derive(Debug)]
pub enum ServerEvent {
    Ist(IstEvent),
    Nist(NistEvent),
}

/// Wrapper for client-side events.
#[derive(Debug)]
pub enum ClientEvent {
    Ict(IctEvent),
    Nict(NictEvent),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::builder::SipMessageBuilder;
    use crate::sip::message::Method;
    use crate::sip::uri::SipUri;

    fn options_request() -> SipMessage {
        SipMessageBuilder::new()
            .request(Method::Options, SipUri::new("example.com".to_string()))
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-opts".to_string())
            .to("<sip:example.com>".to_string())
            .from("<sip:user@example.com>;tag=abc".to_string())
            .call_id("mgr-test-1".to_string())
            .cseq("1 OPTIONS".to_string())
            .content_length(0)
            .build()
            .unwrap()
    }

    fn invite_request() -> SipMessage {
        SipMessageBuilder::new()
            .request(
                Method::Invite,
                SipUri::new("biloxi.com".to_string()).with_user("bob".to_string()),
            )
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-inv1".to_string())
            .to("<sip:bob@biloxi.com>".to_string())
            .from("<sip:alice@atlanta.com>;tag=xyz".to_string())
            .call_id("mgr-test-2".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap()
    }

    fn response_200() -> SipMessage {
        SipMessageBuilder::new()
            .response(200, "OK".to_string())
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-opts".to_string())
            .to("<sip:example.com>".to_string())
            .from("<sip:user@example.com>;tag=abc".to_string())
            .call_id("mgr-test-1".to_string())
            .cseq("1 OPTIONS".to_string())
            .content_length(0)
            .build()
            .unwrap()
    }

    #[test]
    fn key_from_request() {
        let key = TransactionManager::key_from_message(&options_request()).unwrap();
        assert_eq!(key.branch, "z9hG4bK-opts");
        assert_eq!(key.method, Method::Options);
    }

    #[test]
    fn key_from_response() {
        let key = TransactionManager::key_from_message(&response_200()).unwrap();
        assert_eq!(key.branch, "z9hG4bK-opts");
        assert_eq!(key.method, Method::Options);
    }

    #[test]
    fn new_nist_server_transaction() {
        let manager = TransactionManager::default();
        let (key, actions) = manager
            .new_server_transaction(&options_request(), Transport::Udp)
            .unwrap();
        assert_eq!(key.method, Method::Options);
        assert_eq!(manager.count(), 1);
        assert!(actions.iter().any(|a| matches!(a, Action::PassToTu(_))));
    }

    #[test]
    fn new_ist_server_transaction() {
        let manager = TransactionManager::default();
        let (key, actions) = manager
            .new_server_transaction(&invite_request(), Transport::Udp)
            .unwrap();
        assert_eq!(key.method, Method::Invite);
        assert_eq!(manager.count(), 1);
        assert!(actions.iter().any(|a| matches!(a, Action::PassToTu(_))));
    }

    #[test]
    fn nist_full_lifecycle_via_manager() {
        let manager = TransactionManager::default();
        let (key, _) = manager
            .new_server_transaction(&options_request(), Transport::Reliable)
            .unwrap();
        assert_eq!(manager.count(), 1);

        // TU sends 200 OK — TCP: immediate termination
        let actions = manager
            .process_server_event(
                &key,
                ServerEvent::Nist(NistEvent::TuFinal(response_200())),
            )
            .unwrap();

        assert!(actions.iter().any(|a| matches!(a, Action::SendMessage(_))));
        assert!(actions.iter().any(|a| matches!(a, Action::Terminated)));
        assert_eq!(manager.count(), 0); // auto-removed
    }

    #[test]
    fn new_nict_client_transaction() {
        let manager = TransactionManager::default();
        let (key, actions) = manager
            .new_client_transaction(options_request(), Transport::Udp)
            .unwrap();
        assert_eq!(key.method, Method::Options);
        assert_eq!(manager.count(), 1);
        assert!(actions.iter().any(|a| matches!(a, Action::SendMessage(_))));
    }

    #[test]
    fn client_transaction_removed_on_terminate() {
        let manager = TransactionManager::default();
        let (key, _) = manager
            .new_client_transaction(options_request(), Transport::Reliable)
            .unwrap();
        assert_eq!(manager.count(), 1);

        // 200 OK on TCP → immediate terminate
        let actions = manager
            .process_client_event(
                &key,
                ClientEvent::Nict(NictEvent::FinalResponse(response_200())),
            )
            .unwrap();
        assert!(actions.iter().any(|a| matches!(a, Action::Terminated)));
        assert_eq!(manager.count(), 0);
    }

    #[test]
    fn duplicate_transaction_replaced() {
        let manager = TransactionManager::default();
        manager
            .new_server_transaction(&options_request(), Transport::Udp)
            .unwrap();
        assert_eq!(manager.count(), 1);
        // Same message → same key → replaces
        manager
            .new_server_transaction(&options_request(), Transport::Udp)
            .unwrap();
        assert_eq!(manager.count(), 1);
    }

    #[test]
    fn unknown_key_returns_error() {
        let manager = TransactionManager::default();
        let key = TransactionKey::new("z9hG4bK-nonexistent".to_string(), Method::Options, "10.0.0.1:5060".to_string());
        let result = manager.process_server_event(
            &key,
            ServerEvent::Nist(NistEvent::TimerJ),
        );
        assert!(result.is_err());
    }

    fn ack_for_invite() -> SipMessage {
        SipMessageBuilder::new()
            .request(
                Method::Ack,
                SipUri::new("biloxi.com".to_string()).with_user("bob".to_string()),
            )
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-inv1".to_string())
            .to("<sip:bob@biloxi.com>".to_string())
            .from("<sip:alice@atlanta.com>;tag=xyz".to_string())
            .call_id("mgr-test-2".to_string())
            .cseq("1 ACK".to_string())
            .content_length(0)
            .build()
            .unwrap()
    }

    fn response_401() -> SipMessage {
        SipMessageBuilder::new()
            .response(401, "Unauthorized".to_string())
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-inv1".to_string())
            .to("<sip:bob@biloxi.com>".to_string())
            .from("<sip:alice@atlanta.com>;tag=xyz".to_string())
            .call_id("mgr-test-2".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap()
    }

    #[test]
    fn handle_ack_absorbs_non_2xx_ack() {
        let manager = TransactionManager::default();

        // Create IST for INVITE
        let (key, _) = manager
            .new_server_transaction(&invite_request(), Transport::Udp)
            .unwrap();
        assert_eq!(manager.count(), 1);

        // TU sends 401 → IST moves to Completed
        manager
            .process_server_event(
                &key,
                ServerEvent::Ist(IstEvent::TuNon2xxFinal(response_401())),
            )
            .unwrap();

        // ACK arrives — should be absorbed by IST (Completed → Confirmed)
        let result = manager.handle_ack(&ack_for_invite()).unwrap();
        assert!(result.is_some(), "ACK should match the IST");
        let (matched_key, actions) = result.unwrap();
        assert_eq!(matched_key, key);
        // Should cancel timers G and H, no PassToTu
        assert!(!actions.iter().any(|a| matches!(a, Action::PassToTu(_))));
        assert!(actions.iter().any(|a| matches!(a, Action::CancelTimer(_))));
    }

    #[test]
    fn handle_ack_absorbs_non_2xx_ack_tcp() {
        // On reliable transport, Timer I is 0 → immediate termination
        let manager = TransactionManager::default();

        let (key, _) = manager
            .new_server_transaction(&invite_request(), Transport::Reliable)
            .unwrap();

        // TU sends 401
        manager
            .process_server_event(
                &key,
                ServerEvent::Ist(IstEvent::TuNon2xxFinal(response_401())),
            )
            .unwrap();
        assert_eq!(manager.count(), 1);

        // ACK arrives — IST should terminate immediately (Timer I = 0 for TCP)
        let result = manager.handle_ack(&ack_for_invite()).unwrap();
        assert!(result.is_some());
        let (_, actions) = result.unwrap();
        assert!(actions.iter().any(|a| matches!(a, Action::Terminated)));
        assert_eq!(manager.count(), 0);
    }

    #[test]
    fn handle_ack_no_ist_returns_none() {
        // No transaction at all — ACK for 2xx (IST already terminated) or stale
        let manager = TransactionManager::default();
        let result = manager.handle_ack(&ack_for_invite()).unwrap();
        assert!(result.is_none(), "no IST → None (ACK for 2xx or stale)");
    }

    #[test]
    fn handle_ack_retransmit_in_confirmed() {
        let manager = TransactionManager::default();

        let (key, _) = manager
            .new_server_transaction(&invite_request(), Transport::Udp)
            .unwrap();

        // TU sends 401 → Completed
        manager
            .process_server_event(
                &key,
                ServerEvent::Ist(IstEvent::TuNon2xxFinal(response_401())),
            )
            .unwrap();

        // First ACK → Confirmed
        manager.handle_ack(&ack_for_invite()).unwrap();

        // Second ACK (retransmit) → absorbed silently
        let result = manager.handle_ack(&ack_for_invite()).unwrap();
        assert!(result.is_some());
        let (_, actions) = result.unwrap();
        assert!(actions.is_empty(), "ACK retransmit in Confirmed should be silently absorbed");
    }

    #[test]
    fn handle_server_retransmit_no_existing_transaction() {
        let manager = TransactionManager::default();
        let result = manager.handle_server_retransmit(&options_request()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn handle_server_retransmit_nist_in_trying() {
        let manager = TransactionManager::default();
        manager
            .new_server_transaction(&options_request(), Transport::Udp)
            .unwrap();
        // Retransmit while in Trying: absorbed silently (no response cached yet)
        let result = manager.handle_server_retransmit(&options_request()).unwrap();
        assert!(result.is_some());
        let (_key, actions) = result.unwrap();
        assert!(actions.is_empty()); // NIST in Trying absorbs retransmit
    }

    #[test]
    fn handle_server_retransmit_nist_in_completed() {
        let manager = TransactionManager::default();
        let (key, _) = manager
            .new_server_transaction(&options_request(), Transport::Udp)
            .unwrap();
        // Send a final response to move to Completed
        manager
            .process_server_event(
                &key,
                ServerEvent::Nist(NistEvent::TuFinal(response_200())),
            )
            .unwrap();
        // Now retransmit should resend the cached response
        let result = manager.handle_server_retransmit(&options_request()).unwrap();
        assert!(result.is_some());
        let (_key, actions) = result.unwrap();
        assert!(actions.iter().any(|a| matches!(a, Action::SendMessage(_))));
    }

    #[test]
    fn handle_server_retransmit_ist_in_proceeding() {
        let manager = TransactionManager::default();
        let (key, _) = manager
            .new_server_transaction(&invite_request(), Transport::Udp)
            .unwrap();
        // Send 100 Trying
        let trying = SipMessageBuilder::new()
            .response(100, "Trying".to_string())
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-inv1".to_string())
            .to("<sip:bob@biloxi.com>".to_string())
            .from("<sip:alice@atlanta.com>;tag=xyz".to_string())
            .call_id("mgr-test-2".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();
        manager
            .process_server_event(
                &key,
                ServerEvent::Ist(IstEvent::TuProvisional(trying)),
            )
            .unwrap();
        // Retransmit of INVITE should resend the cached provisional
        let result = manager.handle_server_retransmit(&invite_request()).unwrap();
        assert!(result.is_some());
        let (_key, actions) = result.unwrap();
        assert!(actions.iter().any(|a| matches!(a, Action::SendMessage(_))));
    }
}
