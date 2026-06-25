//! SIP dialog state machine — RFC 3261 §12.
//!
//! A dialog is identified by Call-ID + local-tag + remote-tag. It is created
//! by a 2xx or 101-199 response to an INVITE and lives until a BYE terminates it.
//!
//! The dialog layer tracks:
//! - Local/remote sequence numbers (for CSeq ordering)
//! - Route set (Record-Route from the dialog-creating exchange)
//! - Remote target (Contact from the dialog peer)

use std::time::Instant;

use dashmap::DashMap;

use crate::sip::headers::route::RouteEntry;
use crate::sip::uri::SipUri;

/// Uniquely identifies a dialog.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DialogId {
    pub call_id: String,
    pub local_tag: String,
    pub remote_tag: String,
}

impl DialogId {
    pub fn new(call_id: String, local_tag: String, remote_tag: String) -> Self {
        Self {
            call_id,
            local_tag,
            remote_tag,
        }
    }

    /// Create the "reverse" dialog ID (swap local/remote tags).
    /// Useful when matching a response from the peer's perspective.
    pub fn reversed(&self) -> Self {
        Self {
            call_id: self.call_id.clone(),
            local_tag: self.remote_tag.clone(),
            remote_tag: self.local_tag.clone(),
        }
    }
}

impl std::fmt::Display for DialogId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.call_id, self.local_tag, self.remote_tag
        )
    }
}

/// Dialog states per RFC 3261 §12.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialogState {
    /// 1xx received — dialog exists but not confirmed.
    Early,
    /// 2xx received — dialog fully established.
    Confirmed,
    /// BYE sent or received — dialog is being torn down.
    Terminated,
}

/// A SIP dialog.
#[derive(Debug, Clone)]
pub struct Dialog {
    pub id: DialogId,
    pub state: DialogState,
    /// Local CSeq sequence number (we increment for outgoing requests).
    pub local_cseq: u32,
    /// Remote CSeq (last seen from peer — for ordering).
    pub remote_cseq: Option<u32>,
    /// Route set (from Record-Route in the dialog-creating exchange).
    /// Stored in order for the UAC; reversed for UAS.
    pub route_set: Vec<RouteEntry>,
    /// Remote target (Contact URI of the peer).
    pub remote_target: Option<SipUri>,
    /// Local URI.
    pub local_uri: Option<SipUri>,
    /// Remote URI.
    pub remote_uri: Option<SipUri>,
    /// When the dialog was created.
    pub created_at: Instant,
    /// Whether we are the UAC (initiated the INVITE).
    pub is_uac: bool,
    /// Whether an INVITE transaction is currently in progress within this dialog.
    /// Used for glare detection (RFC 3261 §14.1) — if both sides send
    /// re-INVITE simultaneously, the UAS returns 491 "Request Pending".
    pub pending_reinvite: bool,
}

impl Dialog {
    /// Create a new dialog from a UAC perspective (we sent the INVITE).
    pub fn new_uac(
        call_id: String,
        local_tag: String,
        remote_tag: String,
        local_cseq: u32,
        route_set: Vec<RouteEntry>,
        remote_target: Option<SipUri>,
        local_uri: Option<SipUri>,
        remote_uri: Option<SipUri>,
    ) -> Self {
        Self {
            id: DialogId::new(call_id, local_tag, remote_tag),
            state: DialogState::Early,
            local_cseq,
            remote_cseq: None,
            route_set,
            remote_target,
            local_uri,
            remote_uri,
            created_at: Instant::now(),
            is_uac: true,
            pending_reinvite: false,
        }
    }

    /// Create a new dialog from a UAS perspective (we received the INVITE).
    pub fn new_uas(
        call_id: String,
        local_tag: String,
        remote_tag: String,
        remote_cseq: u32,
        route_set: Vec<RouteEntry>,
        remote_target: Option<SipUri>,
        local_uri: Option<SipUri>,
        remote_uri: Option<SipUri>,
    ) -> Self {
        Self {
            id: DialogId::new(call_id, local_tag, remote_tag),
            state: DialogState::Early,
            local_cseq: 0,
            remote_cseq: Some(remote_cseq),
            route_set,
            remote_target,
            local_uri,
            remote_uri,
            created_at: Instant::now(),
            is_uac: false,
            pending_reinvite: false,
        }
    }

    /// Confirm the dialog (2xx received/sent).
    pub fn confirm(&mut self) {
        self.state = DialogState::Confirmed;
    }

    /// Terminate the dialog (BYE sent/received).
    pub fn terminate(&mut self) {
        self.state = DialogState::Terminated;
    }

    /// Get the next local CSeq (incremented).
    pub fn next_cseq(&mut self) -> u32 {
        self.local_cseq += 1;
        self.local_cseq
    }

    /// Check if an incoming CSeq is in order (greater than last seen remote CSeq).
    pub fn check_remote_cseq(&mut self, cseq: u32) -> bool {
        match self.remote_cseq {
            Some(last) if cseq <= last => false,
            _ => {
                self.remote_cseq = Some(cseq);
                true
            }
        }
    }

    /// Update the remote target (Contact URI from a target refresh request).
    pub fn update_remote_target(&mut self, target: SipUri) {
        self.remote_target = Some(target);
    }

    /// Attempt to begin a re-INVITE transaction within this dialog.
    /// Returns `true` if no re-INVITE is already pending (success).
    /// Returns `false` if a re-INVITE is already in progress (glare — RFC 3261 §14.1).
    pub fn begin_reinvite(&mut self) -> bool {
        if self.pending_reinvite {
            return false;
        }
        self.pending_reinvite = true;
        true
    }

    /// Mark the pending re-INVITE as completed (2xx or error received).
    pub fn end_reinvite(&mut self) {
        self.pending_reinvite = false;
    }
}

/// Dialog store — manages all active dialogs.
#[derive(Debug)]
pub struct DialogStore {
    dialogs: DashMap<DialogId, Dialog>,
}

impl DialogStore {
    pub fn new() -> Self {
        Self {
            dialogs: DashMap::new(),
        }
    }

    /// Insert or replace a dialog.
    pub fn insert(&self, dialog: Dialog) {
        self.dialogs.insert(dialog.id.clone(), dialog);
    }

    /// Look up a dialog by ID.
    pub fn get(&self, id: &DialogId) -> Option<Dialog> {
        self.dialogs.get(id).map(|entry| entry.value().clone())
    }

    /// Check if a dialog exists.
    pub fn contains(&self, id: &DialogId) -> bool {
        self.dialogs.contains_key(id)
    }

    /// Remove a dialog.
    pub fn remove(&self, id: &DialogId) -> Option<Dialog> {
        self.dialogs.remove(id).map(|(_, dialog)| dialog)
    }

    /// Confirm a dialog (transition Early → Confirmed).
    pub fn confirm(&self, id: &DialogId) -> bool {
        if let Some(mut entry) = self.dialogs.get_mut(id) {
            entry.value_mut().confirm();
            true
        } else {
            false
        }
    }

    /// Terminate a dialog (transition → Terminated) and remove it.
    pub fn terminate(&self, id: &DialogId) -> Option<Dialog> {
        if let Some(mut entry) = self.dialogs.get_mut(id) {
            entry.value_mut().terminate();
        }
        self.dialogs.remove(id).map(|(_, dialog)| dialog)
    }

    /// Number of active dialogs.
    pub fn count(&self) -> usize {
        self.dialogs.len()
    }

    /// Number of confirmed dialogs.
    pub fn confirmed_count(&self) -> usize {
        self.dialogs
            .iter()
            .filter(|entry| entry.value().state == DialogState::Confirmed)
            .count()
    }

    /// Remove all terminated dialogs.
    pub fn cleanup_terminated(&self) {
        self.dialogs
            .retain(|_, dialog| dialog.state != DialogState::Terminated);
    }
}

impl Default for DialogStore {
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
    use crate::sip::uri::SipUri;

    fn alice_bob_dialog_id() -> DialogId {
        DialogId::new(
            "call-123@atlanta.com".to_string(),
            "alice-tag".to_string(),
            "bob-tag".to_string(),
        )
    }

    fn alice_bob_uac_dialog() -> Dialog {
        Dialog::new_uac(
            "call-123@atlanta.com".to_string(),
            "alice-tag".to_string(),
            "bob-tag".to_string(),
            1,
            vec![],
            Some(SipUri::new("192.0.2.4".to_string()).with_user("bob".to_string())),
            Some(SipUri::new("atlanta.com".to_string()).with_user("alice".to_string())),
            Some(SipUri::new("biloxi.com".to_string()).with_user("bob".to_string())),
        )
    }

    #[test]
    fn dialog_id_display() {
        let id = alice_bob_dialog_id();
        assert_eq!(id.to_string(), "call-123@atlanta.com:alice-tag:bob-tag");
    }

    #[test]
    fn dialog_id_reversed() {
        let id = alice_bob_dialog_id();
        let reversed = id.reversed();
        assert_eq!(reversed.local_tag, "bob-tag");
        assert_eq!(reversed.remote_tag, "alice-tag");
        assert_eq!(reversed.call_id, id.call_id);
    }

    #[test]
    fn new_uac_dialog_starts_early() {
        let dialog = alice_bob_uac_dialog();
        assert_eq!(dialog.state, DialogState::Early);
        assert!(dialog.is_uac);
        assert_eq!(dialog.local_cseq, 1);
    }

    #[test]
    fn new_uas_dialog_starts_early() {
        let dialog = Dialog::new_uas(
            "call-123@atlanta.com".to_string(),
            "bob-tag".to_string(),
            "alice-tag".to_string(),
            1,
            vec![],
            Some(SipUri::new("pc33.atlanta.com".to_string()).with_user("alice".to_string())),
            Some(SipUri::new("biloxi.com".to_string()).with_user("bob".to_string())),
            Some(SipUri::new("atlanta.com".to_string()).with_user("alice".to_string())),
        );
        assert_eq!(dialog.state, DialogState::Early);
        assert!(!dialog.is_uac);
        assert_eq!(dialog.remote_cseq, Some(1));
    }

    #[test]
    fn confirm_dialog() {
        let mut dialog = alice_bob_uac_dialog();
        dialog.confirm();
        assert_eq!(dialog.state, DialogState::Confirmed);
    }

    #[test]
    fn terminate_dialog() {
        let mut dialog = alice_bob_uac_dialog();
        dialog.confirm();
        dialog.terminate();
        assert_eq!(dialog.state, DialogState::Terminated);
    }

    #[test]
    fn next_cseq_increments() {
        let mut dialog = alice_bob_uac_dialog();
        assert_eq!(dialog.next_cseq(), 2);
        assert_eq!(dialog.next_cseq(), 3);
        assert_eq!(dialog.next_cseq(), 4);
    }

    #[test]
    fn check_remote_cseq_accepts_higher() {
        let mut dialog = alice_bob_uac_dialog();
        assert!(dialog.check_remote_cseq(1));
        assert!(dialog.check_remote_cseq(2));
        assert!(dialog.check_remote_cseq(100));
    }

    #[test]
    fn check_remote_cseq_rejects_lower() {
        let mut dialog = alice_bob_uac_dialog();
        dialog.check_remote_cseq(10);
        assert!(!dialog.check_remote_cseq(5));
        assert!(!dialog.check_remote_cseq(10)); // equal also rejected
    }

    #[test]
    fn update_remote_target() {
        let mut dialog = alice_bob_uac_dialog();
        let new_target = SipUri::new("192.0.2.99".to_string()).with_user("bob".to_string());
        dialog.update_remote_target(new_target.clone());
        assert_eq!(dialog.remote_target.unwrap().host, "192.0.2.99");
    }

    // =======================================================================
    // DialogStore tests
    // =======================================================================

    #[test]
    fn store_insert_and_get() {
        let store = DialogStore::new();
        let dialog = alice_bob_uac_dialog();
        let id = dialog.id.clone();
        store.insert(dialog);

        let retrieved = store.get(&id).unwrap();
        assert_eq!(retrieved.id, id);
        assert_eq!(retrieved.state, DialogState::Early);
    }

    #[test]
    fn store_contains() {
        let store = DialogStore::new();
        let dialog = alice_bob_uac_dialog();
        let id = dialog.id.clone();
        assert!(!store.contains(&id));
        store.insert(dialog);
        assert!(store.contains(&id));
    }

    #[test]
    fn store_confirm() {
        let store = DialogStore::new();
        let dialog = alice_bob_uac_dialog();
        let id = dialog.id.clone();
        store.insert(dialog);

        assert!(store.confirm(&id));
        let retrieved = store.get(&id).unwrap();
        assert_eq!(retrieved.state, DialogState::Confirmed);
    }

    #[test]
    fn store_terminate_removes() {
        let store = DialogStore::new();
        let dialog = alice_bob_uac_dialog();
        let id = dialog.id.clone();
        store.insert(dialog);

        let terminated = store.terminate(&id).unwrap();
        assert_eq!(terminated.state, DialogState::Terminated);
        assert!(!store.contains(&id));
    }

    #[test]
    fn store_count() {
        let store = DialogStore::new();
        assert_eq!(store.count(), 0);

        store.insert(alice_bob_uac_dialog());
        assert_eq!(store.count(), 1);

        store.insert(Dialog::new_uac(
            "call-456@host.com".to_string(),
            "tag-a".to_string(),
            "tag-b".to_string(),
            1,
            vec![],
            None, None, None,
        ));
        assert_eq!(store.count(), 2);
    }

    #[test]
    fn store_confirmed_count() {
        let store = DialogStore::new();
        let dialog1 = alice_bob_uac_dialog();
        let id1 = dialog1.id.clone();
        store.insert(dialog1);

        store.insert(Dialog::new_uac(
            "call-456@host.com".to_string(),
            "tag-a".to_string(),
            "tag-b".to_string(),
            1,
            vec![],
            None, None, None,
        ));

        assert_eq!(store.confirmed_count(), 0);
        store.confirm(&id1);
        assert_eq!(store.confirmed_count(), 1);
    }

    #[test]
    fn store_cleanup_terminated() {
        let store = DialogStore::new();
        let dialog1 = alice_bob_uac_dialog();
        let id1 = dialog1.id.clone();
        store.insert(dialog1);

        let _dialog2_id = DialogId::new("call-456".into(), "a".into(), "b".into());
        store.insert(Dialog::new_uac(
            "call-456".to_string(),
            "a".to_string(),
            "b".to_string(),
            1,
            vec![],
            None, None, None,
        ));

        // Terminate dialog1 but don't remove it through terminate()
        // Instead, manually set state via get_mut to test cleanup
        store.terminate(&id1);
        // terminate() already removes, so re-insert a terminated one for cleanup test
        let mut terminated_dialog = Dialog::new_uac(
            "call-789".to_string(),
            "x".to_string(),
            "y".to_string(),
            1,
            vec![],
            None, None, None,
        );
        terminated_dialog.state = DialogState::Terminated;
        store.insert(terminated_dialog);

        assert_eq!(store.count(), 2); // dialog2 + terminated
        store.cleanup_terminated();
        assert_eq!(store.count(), 1); // only dialog2 remains
    }

    #[test]
    fn store_remove() {
        let store = DialogStore::new();
        let dialog = alice_bob_uac_dialog();
        let id = dialog.id.clone();
        store.insert(dialog);

        let removed = store.remove(&id).unwrap();
        assert_eq!(removed.id, id);
        assert!(!store.contains(&id));
    }

    #[test]
    fn begin_reinvite_succeeds_when_none_pending() {
        let mut dialog = alice_bob_uac_dialog();
        assert!(dialog.begin_reinvite());
        assert!(dialog.pending_reinvite);
    }

    #[test]
    fn begin_reinvite_fails_when_already_pending() {
        let mut dialog = alice_bob_uac_dialog();
        assert!(dialog.begin_reinvite());
        assert!(!dialog.begin_reinvite()); // glare
    }

    #[test]
    fn end_reinvite_clears_pending() {
        let mut dialog = alice_bob_uac_dialog();
        dialog.begin_reinvite();
        dialog.end_reinvite();
        assert!(!dialog.pending_reinvite);
        assert!(dialog.begin_reinvite()); // can start again
    }

    #[test]
    fn store_get_nonexistent_returns_none() {
        let store = DialogStore::new();
        let id = alice_bob_dialog_id();
        assert!(store.get(&id).is_none());
    }
}
