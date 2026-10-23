//! Creating a call under an id chosen before the call existed.
//!
//! Lawful interception decides a warranted session on its dialog-forming
//! INVITE, before routing, which is before there is a call to name it by. So it
//! mints the session's id there and the call adopts it. The call's internal id,
//! the key its CDR and Rf records are written under, is then the value every
//! leg's X2/X3 Correlation ID is derived from.

use super::*;

impl CallActorStore {
    /// Create a new call from an A-leg and return the internal call ID.
    ///
    /// `id` is adopted when given and not already a live call's; otherwise the
    /// call gets a fresh one. The collision is not hypothetical: in a spiral the
    /// inbound Call-ID already belongs to another call's B-leg, so the session
    /// it resolves to is that call's, and two calls cannot share one key.
    ///
    /// Registers the A-leg's SIP Call-ID in the registry.
    pub fn create_call_with_id(&self, a_leg: Leg, id: Option<String>) -> String {
        let sip_call_id = a_leg.dialog.call_id.clone();
        let a_branch = a_leg.branch.clone();
        let mut call = CallActor::new(a_leg);
        if let Some(id) = id.filter(|id| !self.calls.contains_key(id.as_str())) {
            call.id = id;
        }
        let id = call.id.clone();
        // In the store before it is registered: a mapping to a call that is
        // not in the store is taken for one a finished call left behind.
        self.calls.insert(id.clone(), Box::new(call));
        self.forget_ended_owners(&sip_call_id);
        self.registry
            .register_call_id(&sip_call_id, &id, LegSide::A);
        self.registry.register_branch(&a_branch, &id);
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{ConnectionId, Transport};

    fn a_leg(sip_call_id: &str) -> Leg {
        Leg::new_a_leg(
            sip_call_id.into(),
            "caller-tag".into(),
            "z9hG4bK-reserved".into(),
            TransportInfo {
                remote_addr: "192.0.2.10:5060".parse().expect("an address"),
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
                local_addr: None,
            },
        )
    }

    #[test]
    fn a_reserved_id_is_adopted() {
        let store = CallActorStore::new();
        let id = store.create_call_with_id(a_leg("a@example.com"), Some("session-1".into()));
        assert_eq!(id, "session-1");
        assert!(store.contains_call("session-1"));
        assert_eq!(
            store.find_by_sip_call_id("a@example.com").as_deref(),
            Some("session-1"),
            "the A-leg's Call-ID must resolve to the adopted id"
        );
    }

    #[test]
    fn no_reserved_id_gets_a_fresh_one() {
        let store = CallActorStore::new();
        let first = store.create_call_with_id(a_leg("a@example.com"), None);
        let second = store.create_call(a_leg("b@example.com"));
        assert_ne!(first, second);
        assert!(store.contains_call(&first));
        assert!(store.contains_call(&second));
    }

    #[test]
    fn a_reserved_id_already_in_use_is_not_shared() {
        let store = CallActorStore::new();
        let first = store.create_call_with_id(a_leg("a@example.com"), Some("session-1".into()));
        let second = store.create_call_with_id(a_leg("b@example.com"), Some("session-1".into()));
        assert_eq!(first, "session-1");
        assert_ne!(second, "session-1", "two calls cannot share one key");
        assert_eq!(store.count(), 2);
        assert_eq!(
            store.find_by_sip_call_id("a@example.com").as_deref(),
            Some("session-1"),
            "the first call must keep its id"
        );
    }
}
