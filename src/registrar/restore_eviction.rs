//! Taking restored bindings out of service when this node cannot serve them.
//!
//! A binding restored from a persistence backend is only as good as the
//! transport state behind it. Where that state died with the previous process
//! (the IPsec security associations of a P-CSCF, TS 33.203), the binding must
//! not be treated as live: the caller decides which bindings that is, and
//! [`Registrar::evict_restored`] removes them through the same bookkeeping a
//! de-registration uses, so no index, backend row or gauge is left behind.

use dashmap::mapref::entry::Entry;

use super::update::retire;
use super::{backend, Contact, ContactKind, Registrar, RegistrationEvent};

/// A binding [`Registrar::evict_restored`] took out of service.
#[derive(Debug, Clone)]
pub struct EvictedBinding {
    /// The AoR the binding was stored under.
    pub aor: String,
    /// The binding as it was restored.
    pub contact: Contact,
    /// Another instance (a different `instance_id`) accepted the REGISTER, so
    /// its row in a shared backend is that instance's and stays there; only
    /// this node's copy is dropped.
    pub owned_elsewhere: bool,
}

impl Registrar {
    /// Remove every binding `select` picks, and return what was removed.
    ///
    /// Each AoR that loses a binding is carried through the de-registration
    /// bookkeeping of [`remove_contact`](Self::remove_contact): the flow token,
    /// connection and contact indexes forget the binding, the backend is
    /// written through, `Deregistered` fires, and an AoR left without a UE
    /// binding is removed with its auxiliary state, aliases and its share of the
    /// registrations gauge.
    ///
    /// A binding another instance accepted (its `instance_id` is not this
    /// node's) is dropped from memory only: on a shared backend its row belongs
    /// to the instance that holds it, and deleting it would de-register a UE
    /// that instance still serves. A binding with no recorded instance, or one
    /// recorded by an earlier boot of this instance, is this node's and goes
    /// from the backend too, so the next restore does not bring it back.
    pub fn evict_restored(&self, select: impl Fn(&Contact) -> bool) -> Vec<EvictedBinding> {
        let own_id = self.instance_identity().map(|identity| identity.id.clone());
        let owned_elsewhere = |contact: &Contact| {
            matches!(
                (own_id.as_deref(), contact.instance_id()),
                (Some(own), Some(writer)) if own != writer
            )
        };
        let aors: Vec<String> = self
            .bindings
            .iter()
            .filter(|entry| entry.value().iter().any(&select))
            .map(|entry| entry.key().clone())
            .collect();

        let mut evicted = Vec::new();
        for aor in aors {
            let Entry::Occupied(mut entry) = self.bindings.entry(aor.clone()) else {
                continue;
            };
            let indexed = self.contact_index.keys_of(entry.get());
            let (taken, mut kept): (Vec<Contact>, Vec<Contact>) = entry
                .get_mut()
                .drain(..)
                .partition(|contact| select(contact));
            let mut stale_tokens = Vec::new();
            let mut stale_connections = Vec::new();
            for contact in &taken {
                retire(contact, &mut stale_tokens, &mut stale_connections);
            }
            // As `remove_contact`: AS capability records do not outlive the last
            // live UE binding (TS 24.229 clause 5.4.2.1.2).
            if !kept
                .iter()
                .any(|contact| contact.kind == ContactKind::Ue && !contact.is_expired())
            {
                for contact in &kept {
                    retire(contact, &mut stale_tokens, &mut stale_connections);
                }
                kept.clear();
            }
            *entry.get_mut() = kept;
            if taken.is_empty() {
                // Raced with a writer that already replaced them.
                self.contact_index
                    .replace(&aor, indexed, self.contact_index.keys_of(entry.get()));
                continue;
            }
            self.contact_index
                .replace(&aor, indexed, self.contact_index.keys_of(entry.get()));
            let own_rows_removed = taken.iter().any(|contact| !owned_elsewhere(contact));
            let backend_rows: Vec<backend::StoredContact> = entry
                .get()
                .iter()
                .chain(taken.iter().filter(|contact| owned_elsewhere(contact)))
                .map(backend::StoredContact::from_contact)
                .collect();
            let emptied = entry.get().is_empty();
            if emptied {
                entry.remove();
            } else {
                drop(entry);
            }

            for token in &stale_tokens {
                self.tokens.remove(token);
            }
            for id in &stale_connections {
                self.deindex_connection(*id, &aor);
            }
            let backend_emptied = backend_rows.is_empty();
            if own_rows_removed {
                self.persist_aor(&aor, backend_rows);
            }
            if emptied {
                if own_rows_removed && backend_emptied {
                    // The registration is over everywhere: state, aliases and
                    // their backend rows go, as `remove_all` takes them.
                    self.drop_aor_state(&aor);
                } else {
                    // Over on this node only; the owner's state row stays.
                    self.prune_aliases_to(&aor);
                    self.remove_aor_state_entries(&aor);
                }
                if let Some(metrics) = crate::metrics::try_metrics() {
                    metrics.registrations_active.dec();
                }
            }
            self.emit_event(RegistrationEvent::Deregistered { aor: aor.clone() });
            evicted.extend(taken.into_iter().map(|contact| EvictedBinding {
                aor: aor.clone(),
                owned_elsewhere: owned_elsewhere(&contact),
                contact,
            }));
        }
        evicted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registrar::{FlowCapture, InstanceIdentity};
    use crate::sip::uri::SipUri;
    use crate::transport::Transport;

    const IMPU: &str = "sip:001010000000001@ims.example.com";

    fn save(registrar: &Registrar, aor: &str, host: &str, token: &str, local_port: u16) {
        registrar
            .save_full(
                aor,
                SipUri::new(host.to_string())
                    .with_user("001010000000001".to_string())
                    .with_port(6101),
                3600,
                1.0,
                format!("call-{token}"),
                1,
                Some(format!("{host}:6100").parse().unwrap()),
                Some(Transport::Udp),
                None,
                None,
                vec![],
                FlowCapture {
                    client_transport: None,
                    flow_token: Some(token.into()),
                    inbound_local_addr: Some(format!("192.0.2.1:{local_port}").parse().unwrap()),
                    inbound_connection_id: None,
                },
                Vec::new(),
            )
            .unwrap();
    }

    fn on_port(port: u16) -> impl Fn(&Contact) -> bool {
        move |contact| contact.inbound_local_addr.map(|local| local.port()) == Some(port)
    }

    fn identity(id: &str) -> InstanceIdentity {
        InstanceIdentity {
            id: id.to_string(),
            epoch: format!("{id}-epoch"),
        }
    }

    #[test]
    fn the_last_binding_goes_like_a_deregistration() {
        let registrar = Registrar::default();
        let (writer, mut writes) = backend::recording_writer();
        registrar.set_backend_writer(writer);
        save(&registrar, IMPU, "198.51.100.10", "tok-a", 5066);
        registrar.set_service_routes(IMPU, vec!["<sip:orig@scscf.example.com;lr>".into()]);
        writes.drain();
        let mut events = registrar.subscribe_events();

        let evicted = registrar.evict_restored(on_port(5066));

        assert_eq!(evicted.len(), 1);
        assert_eq!(evicted[0].aor, IMPU);
        assert!(!evicted[0].owned_elsewhere);
        assert!(registrar.lookup(IMPU).is_empty());
        assert!(registrar.lookup_by_token("tok-a").is_none());
        assert!(registrar.service_routes(IMPU).is_empty());
        assert_eq!(
            writes.drain(),
            vec![format!("remove {IMPU}"), format!("remove_state {IMPU}")]
        );
        assert!(matches!(
            events.try_recv(),
            Ok(RegistrationEvent::Deregistered { ref aor }) if aor == IMPU
        ));
        assert!(registrar.contact_index_is_consistent());
    }

    #[test]
    fn unselected_bindings_stay_and_are_written_back() {
        let registrar = Registrar::default();
        let (writer, mut writes) = backend::recording_writer();
        registrar.set_backend_writer(writer);
        save(&registrar, IMPU, "198.51.100.10", "tok-a", 5066);
        save(&registrar, IMPU, "198.51.100.11", "tok-b", 5060);
        writes.drain();

        let evicted = registrar.evict_restored(on_port(5066));

        assert_eq!(evicted.len(), 1);
        assert_eq!(registrar.lookup(IMPU).len(), 1);
        assert!(registrar.lookup_by_token("tok-b").is_some());
        assert_eq!(
            writes.drain(),
            vec![format!(
                "save {IMPU} [\"sip:001010000000001@198.51.100.11:6101\"]"
            )]
        );
        assert!(registrar.contact_index_is_consistent());
    }

    #[test]
    fn nothing_selected_changes_nothing() {
        let registrar = Registrar::default();
        let (writer, mut writes) = backend::recording_writer();
        registrar.set_backend_writer(writer);
        save(&registrar, IMPU, "198.51.100.10", "tok-a", 5060);
        writes.drain();

        assert!(registrar.evict_restored(on_port(5066)).is_empty());
        assert_eq!(registrar.lookup(IMPU).len(), 1);
        assert!(writes.drain().is_empty());
    }

    /// On a shared backend another instance's row is that instance's: this
    /// node forgets its copy and leaves the row alone.
    #[test]
    fn a_binding_another_instance_accepted_stays_in_the_backend() {
        let registrar = Registrar::default();
        registrar.set_instance_identity(identity("node-b"));
        let peer = Registrar::default();
        peer.set_instance_identity(identity("node-a"));
        save(&peer, IMPU, "198.51.100.10", "tok-a", 5066);
        registrar.install_bindings(IMPU, peer.lookup_all(IMPU));
        registrar.rebuild_token_index();
        let (writer, mut writes) = backend::recording_writer();
        registrar.set_backend_writer(writer);

        let evicted = registrar.evict_restored(on_port(5066));

        assert_eq!(evicted.len(), 1);
        assert!(evicted[0].owned_elsewhere);
        assert!(registrar.lookup(IMPU).is_empty());
        assert!(registrar.lookup_by_token("tok-a").is_none());
        assert!(writes.drain().is_empty(), "the owner's row is untouched");
    }

    /// A binding an earlier boot of this instance accepted is this node's.
    #[test]
    fn a_binding_from_an_earlier_boot_of_this_instance_leaves_the_backend() {
        let earlier = Registrar::default();
        earlier.set_instance_identity(identity("node-a"));
        save(&earlier, IMPU, "198.51.100.10", "tok-a", 5066);
        let registrar = Registrar::default();
        registrar.set_instance_identity(InstanceIdentity {
            id: "node-a".to_string(),
            epoch: "a-later-boot".to_string(),
        });
        registrar.install_bindings(IMPU, earlier.lookup_all(IMPU));
        let (writer, mut writes) = backend::recording_writer();
        registrar.set_backend_writer(writer);

        let evicted = registrar.evict_restored(on_port(5066));

        assert!(!evicted[0].owned_elsewhere);
        assert_eq!(writes.drain(), vec![format!("remove {IMPU}")]);
    }
}
