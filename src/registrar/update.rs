//! Applying one REGISTER's contacts to an AoR as a single change.
//!
//! A REGISTER can carry several Contacts, and the registrar can refuse any of
//! them. Stored one at a time straight onto the AoR's list, a refusal halfway
//! through left the Contacts before it stored, and a forced save had already
//! cleared the AoR before anything was validated. Here every Contact is applied
//! to a copy of the list under the AoR's shard lock, and the copy is committed
//! only when all of them were accepted.
//!
//! What a stored change owes beyond the list itself (the reverse indexes, the
//! backend write-through, the registrations gauge, the change event) is
//! recorded per Contact while staging and carried out after the commit, in
//! Contact order. An accepted REGISTER issues exactly the writes and events it
//! did when each Contact was saved on its own; a refused one issues none.

use std::net::SocketAddr;
use std::time::Instant;

use dashmap::mapref::entry::Entry;

use super::{
    backend, is_aor_key_safe, is_stream_transport, normalize_aor_cow, push_binding, Contact,
    ContactKind, FlowCapture, Registrar, RegistrarError, RegistrationEvent,
};
use crate::sip::uri::SipUri;
use crate::transport::Transport;

/// One Contact of a REGISTER, as the registrar stores it.
#[derive(Debug)]
pub(crate) struct ContactUpdate {
    pub uri: SipUri,
    /// Lifetime in seconds, already capped by the caller where the local
    /// `max_expires` applies. `0` removes the binding.
    pub expires_secs: u32,
    pub q: f32,
    pub call_id: String,
    pub cseq: u32,
    pub source_addr: Option<SocketAddr>,
    pub source_transport: Option<Transport>,
    /// RFC 5627 `+sip.instance`.
    pub sip_instance: Option<String>,
    /// RFC 5626 `reg-id`.
    pub reg_id: Option<u32>,
    /// RFC 3327 Path headers.
    pub path: Vec<String>,
    pub flow: FlowCapture,
    /// The remaining Contact parameters (RFC 3840 feature tags and the like).
    pub params: Vec<(String, Option<String>)>,
    /// Who this REGISTER authenticated as (`request.auth_user`). Recorded on
    /// the binding from this REGISTER only, never carried over from the one it
    /// replaces.
    pub auth_user: Option<String>,
}

/// What one staged Contact owes once the new binding list is committed.
enum Effect {
    /// `expires=0` removed the Contact's binding.
    Removed {
        stale_tokens: Vec<String>,
        stale_connections: Vec<u64>,
        remaining: Vec<backend::StoredContact>,
        emptied: bool,
    },
    /// The Contact added a binding, or replaced the one it refreshes.
    Stored {
        stale_tokens: Vec<String>,
        stale_connections: Vec<u64>,
        stored: Vec<backend::StoredContact>,
        flow_token: Option<Box<str>>,
        connection_id: Option<u64>,
        is_stream: bool,
        refreshed: bool,
    },
}

impl RegistrarError {
    /// The `reason` label a refusal is counted under in
    /// `siphon_registrar_refusals_total`.
    pub(crate) fn reason_label(&self) -> &'static str {
        match self {
            RegistrarError::IntervalTooBrief { .. } => "interval_too_brief",
            RegistrarError::TooManyContacts { .. } => "too_many_contacts",
            RegistrarError::InvalidAor => "invalid_aor",
        }
    }
}

/// A binding's remaining lifetime as a `Retry-After` value, between one second
/// and `max_expires`. With no binding held, nothing will expire to free a slot,
/// so the answer is the longest interval this registrar grants.
pub(crate) fn clamp_retry_after(soonest_expiry_secs: Option<u64>, max_expires: u32) -> u32 {
    let ceiling = max_expires.max(1);
    match soonest_expiry_secs {
        Some(seconds) => u32::try_from(seconds).unwrap_or(u32::MAX).clamp(1, ceiling),
        None => ceiling,
    }
}

/// Collect what the reverse indexes hold for a binding being dropped.
fn retire(contact: &Contact, tokens: &mut Vec<String>, connections: &mut Vec<u64>) {
    if let Some(token) = &contact.flow_token {
        tokens.push(token.to_string());
    }
    if is_stream_transport(contact.source_transport) {
        if let Some(id) = contact.inbound_connection_id {
            connections.push(id);
        }
    }
}

impl Registrar {
    /// Apply the Contacts of one REGISTER to `aor` as a single change.
    ///
    /// Each Contact goes, in order, onto a copy of the AoR's bindings under the
    /// AoR's shard lock, by the rules a lone Contact always had: expired
    /// bindings are pruned, a Contact replaces the binding with its
    /// `+sip.instance` (RFC 5627 §4.2) or else its URI, `expires=0` removes it,
    /// an interval below `min_expires` is refused (RFC 3261 §10.3 step 7), and
    /// so is a new binding past `max_contacts`. The copy replaces the stored
    /// list only if every Contact was accepted, so a refusal stores nothing,
    /// writes nothing to the backend and emits no change event.
    ///
    /// `force` empties the AoR, but only once every Contact has been accepted: a
    /// refused forced REGISTER keeps the bindings it would have replaced.
    pub(crate) fn apply_register(
        &self,
        aor: &str,
        updates: Vec<ContactUpdate>,
        force: bool,
    ) -> Result<(), RegistrarError> {
        if updates.is_empty() {
            if force {
                self.clear_bindings(aor);
            }
            return Ok(());
        }

        // Resolve alias → primary so a REGISTER arriving with a non-primary
        // IMPU still attaches to the implicit set's primary AoR. A forced save
        // clears that set first, which retires the alias the REGISTER may have
        // come in on, so its bindings land under the AoR as addressed instead.
        let primary = self.resolve_alias(aor);
        let key = if force && self.alias_retired_by_clearing(aor, &primary) {
            normalize_aor_cow(aor).into_owned()
        } else {
            primary.clone()
        };

        // Keyspace-safety invariant: never let a crafted AoR collide a contact
        // binding into the reserved `state:` namespace or inject control chars
        // into a storage key. See `is_aor_key_safe`.
        if !is_aor_key_safe(&key) {
            return Err(RegistrarError::InvalidAor);
        }

        // The entry holds the AoR's shard lock until the commit, so no other
        // save on this AoR can land between the decision and the write.
        let entry = self.bindings.entry(key.clone());
        let clears_this_list = force && key == primary;
        let mut contacts = match &entry {
            Entry::Occupied(occupied) if !clears_this_list => occupied.get().clone(),
            _ => Vec::new(),
        };
        let mut effects = Vec::with_capacity(updates.len());
        for update in updates {
            effects.push(self.stage(&mut contacts, update)?);
        }

        let replaced = match entry {
            Entry::Occupied(occupied) if contacts.is_empty() => Some(occupied.remove()),
            Entry::Occupied(mut occupied) => Some(occupied.insert(contacts)),
            Entry::Vacant(vacant) => {
                if !contacts.is_empty() {
                    vacant.insert(contacts);
                }
                None
            }
        };

        if force {
            let cleared = if clears_this_list {
                replaced
            } else {
                self.bindings
                    .remove(primary.as_str())
                    .map(|(_, contacts)| contacts)
            };
            self.release_cleared(&primary, cleared);
        }
        for effect in effects {
            self.carry_out(&key, effect);
        }
        Ok(())
    }

    /// Whether clearing `primary` retires `aor` as an alias of it: the clear
    /// drops the implicit set `primary` owns, so every URI on its
    /// P-Associated-URI list stops resolving to it.
    fn alias_retired_by_clearing(&self, aor: &str, primary: &str) -> bool {
        let addressed = normalize_aor_cow(aor);
        addressed != primary
            && self.associated_uris.get(primary).is_some_and(|uris| {
                uris.value()
                    .iter()
                    .any(|uri| normalize_aor_cow(uri) == addressed)
            })
    }

    /// Apply one Contact to `contacts`, returning what the change owes once
    /// committed. On a refusal `contacts` is left part-way; the caller throws
    /// the copy away.
    ///
    /// Runs under the AoR's shard lock, so it must not touch `bindings`.
    fn stage(
        &self,
        contacts: &mut Vec<Contact>,
        update: ContactUpdate,
    ) -> Result<Effect, RegistrarError> {
        let ContactUpdate {
            uri,
            expires_secs,
            q,
            call_id,
            cseq,
            source_addr,
            source_transport,
            sip_instance,
            reg_id,
            path,
            flow,
            params,
            auth_user,
        } = update;

        if expires_secs > 0 && expires_secs < self.config.min_expires {
            return Err(RegistrarError::IntervalTooBrief {
                min_expires: self.config.min_expires,
            });
        }

        let uri_string = uri.to_string();
        let mut stale_tokens = Vec::new();
        let mut stale_connections = Vec::new();
        contacts.retain(|contact| {
            let expired = contact.is_expired();
            if expired {
                retire(contact, &mut stale_tokens, &mut stale_connections);
            }
            !expired
        });

        if expires_secs == 0 {
            // Expires=0 deregisters this UE contact only; an AS capability
            // record sharing the URI by coincidence is left to the cascade.
            contacts.retain(|contact| {
                let removed =
                    contact.kind == ContactKind::Ue && contact.uri.to_string() == uri_string;
                if removed {
                    retire(contact, &mut stale_tokens, &mut stale_connections);
                }
                !removed
            });
            // AS contacts only make sense while the user is registered
            // (TS 24.229 §5.4.2.1.2): the last UE binding takes them with it, so
            // the next reg-event NOTIFY carries no stale contacts.
            if !contacts
                .iter()
                .any(|contact| contact.kind == ContactKind::Ue && !contact.is_expired())
            {
                contacts.clear();
            }
            return Ok(Effect::Removed {
                stale_tokens,
                stale_connections,
                remaining: contacts
                    .iter()
                    .map(backend::StoredContact::from_contact)
                    .collect(),
                emptied: contacts.is_empty(),
            });
        }

        let FlowCapture {
            flow_token,
            inbound_local_addr,
            inbound_connection_id,
        } = flow;
        let is_stream = is_stream_transport(source_transport);
        let contact = Contact {
            uri,
            q,
            registered_at: Instant::now(),
            expires_secs,
            call_id: call_id.into_boxed_str(),
            cseq,
            source_addr,
            source_transport,
            sip_instance: sip_instance.map(String::into_boxed_str),
            reg_id,
            path: path.into_iter().map(String::into_boxed_str).collect(),
            pending: false,
            instance: self.current_instance(),
            flow_token: flow_token.clone(),
            inbound_local_addr,
            inbound_connection_id,
            params,
            kind: ContactKind::Ue,
            auth_user: auth_user.map(String::into_boxed_str),
        };

        // Replace the binding with the same +sip.instance first (RFC 5627 §4.2:
        // a UE re-registering from a rotated port keeps its instance), then the
        // one with the same URI.
        let replace_index = contact
            .sip_instance
            .as_ref()
            .and_then(|instance| {
                contacts.iter().position(|held| {
                    held.sip_instance
                        .as_ref()
                        .is_some_and(|held_instance| held_instance == instance)
                })
            })
            .or_else(|| {
                contacts
                    .iter()
                    .position(|held| held.uri.to_string() == uri_string)
            });

        let refreshed = replace_index.is_some();
        match replace_index {
            Some(index) => {
                retire(&contacts[index], &mut stale_tokens, &mut stale_connections);
                contacts[index] = contact;
            }
            None if contacts.len() >= self.config.max_contacts => {
                return Err(RegistrarError::TooManyContacts {
                    max: self.config.max_contacts,
                });
            }
            None => push_binding(contacts, contact),
        }
        contacts.sort_by(|a, b| b.q.partial_cmp(&a.q).unwrap_or(std::cmp::Ordering::Equal));

        Ok(Effect::Stored {
            stale_tokens,
            stale_connections,
            stored: contacts
                .iter()
                .map(backend::StoredContact::from_contact)
                .collect(),
            flow_token,
            connection_id: inbound_connection_id,
            is_stream,
            refreshed,
        })
    }

    /// Carry out what one committed Contact owes, in the order a lone save
    /// always did.
    fn carry_out(&self, aor: &str, effect: Effect) {
        match effect {
            Effect::Removed {
                stale_tokens,
                stale_connections,
                remaining,
                emptied,
            } => {
                for token in &stale_tokens {
                    self.tokens.remove(token);
                }
                for id in &stale_connections {
                    self.deindex_connection(*id, aor);
                }
                self.persist_aor(aor, remaining);
                if emptied {
                    // The last binding is gone, so the registration is over and
                    // its auxiliary state goes with it: service route, asserted
                    // identity, P-Associated-URI list and the implicit-set
                    // aliases, the same teardown `remove_all` performs.
                    self.drop_aor_state(aor);
                    if let Some(metrics) = crate::metrics::try_metrics() {
                        metrics.registrations_active.dec();
                    }
                }
                self.emit_event(RegistrationEvent::Deregistered {
                    aor: aor.to_string(),
                });
            }
            Effect::Stored {
                stale_tokens,
                stale_connections,
                stored,
                flow_token,
                connection_id,
                is_stream,
                refreshed,
            } => {
                // A refresh that reuses its token keeps the mapping it
                // re-inserts below.
                for token in &stale_tokens {
                    if Some(token.as_str()) != flow_token.as_deref() {
                        self.tokens.remove(token);
                    }
                }
                if let Some(token) = &flow_token {
                    self.tokens.insert(token.to_string(), aor.to_string());
                }
                // Retire first and index second, so a refresh on the same
                // connection stays indexed.
                for id in &stale_connections {
                    self.deindex_connection(*id, aor);
                }
                self.index_connection(connection_id, is_stream, aor);
                self.persist_aor(aor, stored);
                if refreshed {
                    self.emit_event(RegistrationEvent::Refreshed {
                        aor: aor.to_string(),
                    });
                } else {
                    if let Some(metrics) = crate::metrics::try_metrics() {
                        metrics.registrations_active.inc();
                    }
                    self.emit_event(RegistrationEvent::Registered {
                        aor: aor.to_string(),
                    });
                }
            }
        }
    }

    /// The index, backend and auxiliary-state half of clearing an AoR, for
    /// bindings already taken out of the map. Emits no change event.
    pub(super) fn release_cleared(&self, aor: &str, contacts: Option<Vec<Contact>>) {
        for contact in contacts.into_iter().flatten() {
            if let Some(token) = contact.flow_token {
                self.tokens.remove(token.as_ref());
            }
            if is_stream_transport(contact.source_transport) {
                if let Some(id) = contact.inbound_connection_id {
                    self.deindex_connection(id, aor);
                }
            }
        }
        if let Some(writer) = self.backend_writer.get() {
            writer.remove(aor);
        }
        self.drop_aor_state(aor);
    }

    /// `Retry-After` for a REGISTER refused for too many contacts: the seconds
    /// until the soonest live binding on `aor` expires and frees a slot,
    /// clamped by [`clamp_retry_after`].
    pub(crate) fn retry_after_secs(&self, aor: &str) -> u32 {
        let primary = self.resolve_alias(aor);
        let soonest = self.bindings.get(primary.as_str()).and_then(|entry| {
            entry
                .value()
                .iter()
                .filter(|contact| !contact.is_expired())
                .map(Contact::remaining_seconds)
                .min()
        });
        clamp_retry_after(soonest, self.config.max_expires)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{clamp_retry_after, ContactUpdate};
    use crate::registrar::{FlowCapture, Registrar, RegistrarConfig, RegistrarError};
    use crate::sip::uri::SipUri;
    use crate::transport::Transport;

    fn save_tagged(
        registrar: &Registrar,
        aor: &str,
        host: &str,
        expires_secs: u32,
        token: &str,
        connection_id: u64,
    ) -> Result<(), RegistrarError> {
        registrar.save_full(
            aor,
            SipUri::new(host.to_string()).with_user("001010000000001".to_string()),
            expires_secs,
            1.0,
            format!("call-{token}"),
            1,
            None,
            Some(Transport::Tcp),
            None,
            None,
            vec![],
            FlowCapture {
                flow_token: Some(token.into()),
                inbound_local_addr: None,
                inbound_connection_id: Some(connection_id),
            },
            Vec::new(),
        )
    }

    fn update(host: &str, expires_secs: u32) -> ContactUpdate {
        ContactUpdate {
            uri: SipUri::new(host.to_string()).with_user("001010000000001".to_string()),
            expires_secs,
            q: 1.0,
            call_id: format!("call@{host}"),
            cseq: 1,
            source_addr: None,
            source_transport: None,
            sip_instance: None,
            reg_id: None,
            path: vec![],
            flow: FlowCapture::default(),
            params: Vec::new(),
            auth_user: None,
        }
    }

    /// A binding remembers the identity that authenticated the REGISTER which
    /// stored it, and `is_registered_by` vouches only for that identity,
    /// through the implicit set, and only while the binding is live.
    #[test]
    fn a_binding_answers_only_for_the_identity_that_stored_it() {
        let registrar = Registrar::default();
        let aor = "sip:001010000000001@ims.example.com";
        let alias = "sip:+15550100001@ims.example.com";
        let impi = "001010000000001@ims.example.com";
        let mut authenticated = update("192.0.2.10", 3600);
        authenticated.auth_user = Some(impi.to_string());
        registrar
            .apply_register(aor, vec![authenticated], false)
            .unwrap();
        registrar.set_associated_uris(aor, vec![aor.to_string(), alias.to_string()]);

        assert_eq!(registrar.lookup(aor)[0].auth_user.as_deref(), Some(impi));
        assert!(registrar.is_registered_by(aor, impi));
        assert!(registrar.is_registered_by(alias, impi));
        assert!(!registrar.is_registered_by(aor, "001010000000002@ims.example.com"));
        assert!(!registrar.is_registered_by("sip:001010000000003@ims.example.com", impi));

        if let Some(mut entry) = registrar.bindings.get_mut(aor) {
            for contact in entry.value_mut().iter_mut() {
                contact.registered_at = Instant::now() - Duration::from_secs(7200);
            }
        }
        assert!(
            !registrar.is_registered_by(aor, impi),
            "an expired binding vouches for nobody"
        );
    }

    #[test]
    fn a_refresh_without_an_authenticated_user_forgets_the_previous_one() {
        let registrar = Registrar::default();
        let aor = "sip:001010000000001@ims.example.com";
        let impi = "001010000000001@ims.example.com";
        let mut authenticated = update("192.0.2.10", 3600);
        authenticated.auth_user = Some(impi.to_string());
        registrar
            .apply_register(aor, vec![authenticated], false)
            .unwrap();
        registrar
            .apply_register(aor, vec![update("192.0.2.10", 3600)], false)
            .unwrap();

        assert_eq!(registrar.lookup(aor)[0].auth_user, None);
        assert!(!registrar.is_registered_by(aor, impi));
    }

    /// A refused save must leave the AoR exactly as it found it. Pruning the
    /// expired bindings is part of applying a save, so a refusal does not get to
    /// keep that half: dropping a binding without retiring its flow token or
    /// connection index entry is how those indexes drift from `bindings`.
    #[test]
    fn a_refused_save_changes_nothing_not_even_the_expired_prune() {
        let mut registrar = Registrar::new(RegistrarConfig {
            max_contacts: 2,
            ..Default::default()
        });
        let aor = "sip:001010000000001@ims.example.com";
        save_tagged(&registrar, aor, "192.0.2.10", 3600, "live", 1).unwrap();
        save_tagged(&registrar, aor, "192.0.2.11", 3600, "stale", 2).unwrap();
        if let Some(mut entry) = registrar.bindings.get_mut(aor) {
            for contact in entry.value_mut().iter_mut() {
                if contact.uri.host == "192.0.2.11" {
                    contact.registered_at = Instant::now() - Duration::from_secs(7200);
                }
            }
        }
        registrar.config.max_contacts = 1;

        let refused = save_tagged(&registrar, aor, "192.0.2.12", 3600, "new", 3);

        assert_eq!(refused, Err(RegistrarError::TooManyContacts { max: 1 }));
        let held = registrar.bindings.get(aor).map(|entry| entry.value().len());
        assert_eq!(held, Some(2), "a refused save must not prune the AoR");
        assert_eq!(registrar.tokens.len(), 2);
        assert_eq!(registrar.connection_index.len(), 2);
    }

    /// The per-AoR leak rule for the refusal path: a batch of refused saves on
    /// AoRs the registrar has never seen, one of each refusal, leaves every
    /// per-AoR store at its starting length. A refusal that inserts an empty
    /// binding list before deciding is a per-REGISTER entry nothing evicts.
    #[test]
    fn refused_saves_leave_every_per_aor_store_at_baseline() {
        const BATCH: u64 = 100;

        let registrar = Registrar::new(RegistrarConfig {
            max_contacts: 0,
            min_expires: 60,
            ..Default::default()
        });
        // An implicit set whose primary is not a safe storage key.
        registrar.set_associated_uris(
            "sip:unsafe\u{1}key@ims.example.com",
            vec!["sip:001010000000999@ims.example.com".to_string()],
        );
        let lengths = |registrar: &Registrar| {
            [
                ("bindings", registrar.bindings.len()),
                ("service_routes", registrar.service_routes.len()),
                ("asserted_identities", registrar.asserted_identities.len()),
                ("associated_uris", registrar.associated_uris.len()),
                ("aliases", registrar.aliases.len()),
                ("tokens", registrar.tokens.len()),
                ("connection_index", registrar.connection_index.len()),
            ]
        };
        let baseline = lengths(&registrar);

        for index in 0..BATCH {
            let aor = format!("sip:0010100000{index:05}@ims.example.com");
            assert_eq!(
                save_tagged(&registrar, &aor, "192.0.2.10", 3600, "many", index),
                Err(RegistrarError::TooManyContacts { max: 0 })
            );
            assert_eq!(
                save_tagged(&registrar, &aor, "192.0.2.10", 30, "brief", index),
                Err(RegistrarError::IntervalTooBrief { min_expires: 60 })
            );
            assert_eq!(
                save_tagged(
                    &registrar,
                    "sip:001010000000999@ims.example.com",
                    "192.0.2.10",
                    3600,
                    "unsafe",
                    index,
                ),
                Err(RegistrarError::InvalidAor)
            );
        }

        for ((name, after), (_, before)) in lengths(&registrar).iter().zip(baseline.iter()) {
            assert_eq!(
                after, before,
                "{name} grew on refused saves: {after} entries, started at {before}"
            );
        }
    }

    /// A refusal on the second Contact must not store the first.
    #[test]
    fn a_refused_contact_takes_the_contacts_before_it_down_too() {
        let registrar = Registrar::new(RegistrarConfig {
            max_contacts: 1,
            ..Default::default()
        });
        let aor = "sip:001010000000001@ims.example.com";

        let refused = registrar.apply_register(
            aor,
            vec![update("192.0.2.10", 3600), update("192.0.2.11", 3600)],
            false,
        );

        assert_eq!(refused, Err(RegistrarError::TooManyContacts { max: 1 }));
        assert!(registrar.bindings.is_empty());
    }

    /// A forced save through an alias clears the implicit set, which retires
    /// the alias, so the new bindings land under the AoR as addressed. That is
    /// where clearing first and saving second always put them; deciding before
    /// clearing must not move them to the old primary.
    #[test]
    fn a_forced_save_through_an_alias_lands_where_it_always_did() {
        let registrar = Registrar::default();
        let primary = "sip:001010000000001@ims.example.com";
        let alias = "sip:001010000000002@ims.example.com";
        registrar.set_associated_uris(primary, vec![primary.to_string(), alias.to_string()]);
        save_tagged(&registrar, primary, "192.0.2.10", 3600, "old", 1).unwrap();

        registrar
            .apply_register(alias, vec![update("192.0.2.11", 3600)], true)
            .unwrap();

        assert!(registrar.bindings.get(primary).is_none());
        let under_alias = registrar
            .bindings
            .get(alias)
            .map(|entry| entry.value().len());
        assert_eq!(under_alias, Some(1));
        assert!(registrar.aliases.is_empty(), "the clear retired the set");
        assert!(
            registrar.tokens.is_empty(),
            "the cleared binding's token went too"
        );
    }

    #[test]
    fn retry_after_is_clamped_between_one_second_and_max_expires() {
        assert_eq!(clamp_retry_after(Some(0), 7200), 1);
        assert_eq!(clamp_retry_after(Some(1), 7200), 1);
        assert_eq!(clamp_retry_after(Some(1800), 7200), 1800);
        assert_eq!(clamp_retry_after(Some(7200), 7200), 7200);
        assert_eq!(clamp_retry_after(Some(9000), 7200), 7200);
        assert_eq!(clamp_retry_after(Some(u64::MAX), 7200), 7200);
        assert_eq!(clamp_retry_after(None, 7200), 7200);
        // A registrar configured to grant nothing still answers a usable delay.
        assert_eq!(clamp_retry_after(Some(30), 0), 1);
        assert_eq!(clamp_retry_after(None, 0), 1);
    }

    #[test]
    fn every_refusal_is_counted_under_its_own_reason() {
        assert_eq!(
            RegistrarError::IntervalTooBrief { min_expires: 60 }.reason_label(),
            "interval_too_brief"
        );
        assert_eq!(
            RegistrarError::TooManyContacts { max: 1 }.reason_label(),
            "too_many_contacts"
        );
        assert_eq!(RegistrarError::InvalidAor.reason_label(), "invalid_aor");
    }
}
