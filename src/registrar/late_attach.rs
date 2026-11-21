//! Attaching a persistence backend to a registrar that is already running.
//!
//! A backend that answers after start-up (it was down when siphon started and
//! is retried in the background) meets a registrar that has been taking
//! REGISTERs on memory alone. Its stored bindings are merged beside the live
//! ones rather than replacing them, and what was accepted meanwhile is written
//! through once the writer is in place.

use super::{backend, Contact, Registrar};

impl Registrar {
    /// Add the bindings a backend restore found for `aor` beside the ones this
    /// process holds. A stored binding of a contact that is held already is
    /// dropped: the live one is the newer, it was accepted after the process
    /// started and the stored one was written before it.
    pub(crate) fn merge_restored_bindings(&self, aor: &str, restored: Vec<Contact>) {
        let mut entry = self.bindings.entry(aor.to_string()).or_default();
        let before = self.contact_index.keys_of(entry.value());
        let held: std::collections::HashSet<u64> = entry
            .value()
            .iter()
            .map(|contact| self.contact_index.key_of(&contact.uri))
            .collect();
        for contact in restored {
            if !held.contains(&self.contact_index.key_of(&contact.uri)) {
                entry.value_mut().push(contact);
            }
        }
        entry
            .value_mut()
            .sort_by(|a, b| b.q.partial_cmp(&a.q).unwrap_or(std::cmp::Ordering::Equal));
        self.contact_index
            .replace(aor, before, self.contact_index.keys_of(entry.value()));
    }

    /// [`apply_aor_state`](Self::apply_aor_state), except for what this
    /// process already set for `aor`.
    pub(crate) fn apply_aor_state_unless_held(
        &self,
        aor: &str,
        mut state: backend::StoredAorState,
    ) {
        if self.service_routes.contains_key(aor) {
            state.service_routes.clear();
        }
        if self.asserted_identities.contains_key(aor) {
            state.asserted_identity = None;
        }
        if self.associated_uris.contains_key(aor) {
            state.associated_uris.clear();
        }
        self.apply_aor_state(aor, state);
    }

    /// Write every AoR this registrar holds through to the backend writer, with
    /// its auxiliary state. Returns how many AoRs were written.
    ///
    /// For the moment a writer is set on a registrar that has been running
    /// without one: nothing accepted before that was written. Each snapshot is
    /// taken under the AoR's entry with its sequence, as a save does, so a
    /// registration racing this keeps the newest state however the writes
    /// arrive.
    pub fn write_through_all(&self) -> usize {
        let aors: Vec<String> = self
            .bindings
            .iter()
            .map(|entry| entry.key().clone())
            .collect();
        let mut written = 0usize;
        for aor in aors {
            let Some(entry) = self.bindings.get(&aor) else {
                continue;
            };
            if entry.value().is_empty() {
                continue;
            }
            let stored: Vec<backend::StoredContact> = entry
                .value()
                .iter()
                .map(backend::StoredContact::from_contact)
                .collect();
            let sequence = self.write_sequence();
            drop(entry);
            self.persist_aor(&aor, stored, sequence);
            written += 1;
        }
        let state_aors: std::collections::HashSet<String> = self
            .service_routes
            .iter()
            .map(|entry| entry.key().clone())
            .chain(
                self.asserted_identities
                    .iter()
                    .map(|entry| entry.key().clone()),
            )
            .chain(self.associated_uris.iter().map(|entry| entry.key().clone()))
            .collect();
        for aor in state_aors {
            self.persist_aor_state(&aor);
        }
        written
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registrar::{FlowCapture, InstanceIdentity};
    use crate::sip::uri::SipUri;
    use crate::transport::Transport;

    const AOR: &str = "sip:alice@example.com";

    fn registrar(epoch: &str) -> Registrar {
        let registrar = Registrar::default();
        registrar.set_instance_identity(InstanceIdentity {
            id: "node-a".into(),
            epoch: epoch.into(),
        });
        registrar
    }

    fn save(registrar: &Registrar, aor: &str, host: &str) {
        registrar
            .save_full(
                aor,
                SipUri::new(host.to_string()).with_user("alice".to_string()),
                3600,
                1.0,
                format!("call-{host}"),
                1,
                None,
                Some(Transport::Udp),
                None,
                None,
                vec![],
                FlowCapture::default(),
                Vec::new(),
            )
            .unwrap();
    }

    #[test]
    fn a_merge_adds_the_stored_bindings_beside_the_live_ones() {
        let earlier = registrar("earlier");
        save(&earlier, AOR, "192.0.2.1");
        save(&earlier, AOR, "192.0.2.2");
        let live = registrar("live");
        save(&live, AOR, "192.0.2.2");
        save(&live, "sip:bob@example.com", "192.0.2.3");

        live.merge_restored_bindings(AOR, earlier.lookup_all(AOR));

        let hosts: Vec<String> = live
            .lookup_all(AOR)
            .iter()
            .map(|contact| contact.uri.host.clone())
            .collect();
        assert_eq!(hosts.len(), 2, "the held contact is not doubled: {hosts:?}");
        assert!(hosts.contains(&"192.0.2.1".to_string()));
        let held = live
            .lookup_all(AOR)
            .into_iter()
            .find(|contact| contact.uri.host == "192.0.2.2")
            .unwrap();
        assert_eq!(held.instance_epoch(), Some("live"), "the live one wins");
        assert!(live.contact_index_is_consistent());
        assert!(live.is_registered("sip:bob@example.com"));
    }

    #[test]
    fn auxiliary_state_set_by_this_process_is_kept() {
        let live = registrar("live");
        live.set_service_routes(AOR, vec!["<sip:live@scscf.example.com;lr>".into()]);
        let state = backend::StoredAorState {
            service_routes: vec!["<sip:stored@scscf.example.com;lr>".into()],
            asserted_identity: Some("sip:stored@example.com".into()),
            associated_uris: Vec::new(),
        };

        live.apply_aor_state_unless_held(AOR, state);

        assert_eq!(
            live.service_routes(AOR),
            vec!["<sip:live@scscf.example.com;lr>".to_string()]
        );
        assert_eq!(
            live.asserted_identity(AOR),
            Some("sip:stored@example.com".to_string()),
            "what was not set is taken from the backend"
        );
    }

    #[test]
    fn write_through_all_writes_what_was_accepted_before_the_writer() {
        let live = registrar("live");
        save(&live, AOR, "192.0.2.1");
        save(&live, "sip:bob@example.com", "192.0.2.3");
        live.set_service_routes(AOR, vec!["<sip:live@scscf.example.com;lr>".into()]);
        let (writer, mut writes) = backend::recording_writer();
        live.set_backend_writer(writer);

        assert_eq!(live.write_through_all(), 2);

        let mut lines = writes.drain();
        lines.sort();
        assert_eq!(
            lines,
            vec![
                format!("save {AOR} [\"sip:alice@192.0.2.1\"]"),
                "save sip:bob@example.com [\"sip:alice@192.0.2.3\"]".to_string(),
                format!("save_state {AOR}"),
            ]
        );
    }
}
