//! Contact → AoR reverse index.
//!
//! `lookup_contact`, `is_registered_contact` and `binding_for_contact` find a
//! binding by its **Contact** rather than its AoR: the terminating edge behind
//! a PBX that retargets an INVITE at the cached Contact, and the dialog-state
//! publisher naming the AoR a branch rings. Each scanned every binding of every
//! AoR, which is a per-call cost proportional to the registration count
//! (hundreds of milliseconds at half a million AoRs).
//!
//! The index maps a Contact's identity to the AoRs holding a binding with it,
//! one entry per binding, so a lookup reads the few AoRs it names and checks
//! their bindings as before. The identity is what [`same_contact`] compares,
//! scheme, user, host (case-insensitively) and port with the default port
//! counted, so parameters and the spelling of a default port do not split a
//! device in two. It is stored as a keyed hash rather than as a string: a
//! lookup always re-checks the bindings it is led to, so a collision costs a
//! wasted read and never a wrong answer, and a binding pays eight bytes of key
//! instead of a copy of its URI. The hash is keyed per registrar (std's
//! `RandomState`), so a peer cannot choose Contacts that collide.
//!
//! Only UE bindings are indexed: AS capability records are never what a
//! Contact lookup returns.
//!
//! Every path that changes a binding list keeps the index in step under the
//! same rule: an entry for a new binding is added before the binding is
//! visible, under the AoR's shard lock, and an entry for a removed binding
//! may be dropped after it is gone. A lookup therefore never misses a live
//! binding, and a removal always finds the entry it drops.
//!
//! [`same_contact`]: super::same_contact

use std::hash::{BuildHasher, BuildHasherDefault, Hasher};

use dashmap::DashMap;

use super::{contact_target, same_contact, sort_by_preference, Aor, Contact, ContactKind};
use crate::sip::uri::{Scheme, SipUri};

/// A `Hasher` for keys that are already keyed hashes: hashing them again buys
/// nothing.
#[derive(Default)]
pub(crate) struct PassThrough(u64);

impl Hasher for PassThrough {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        // Only `u64` keys are hashed with this; anything else folds in.
        for byte in bytes {
            self.0 = self.0.rotate_left(8) ^ u64::from(*byte);
        }
    }

    fn write_u64(&mut self, value: u64) {
        self.0 = value;
    }
}

/// The AoRs holding a binding with one Contact identity, once per binding.
/// Nearly always one.
#[derive(Debug)]
enum Holders {
    One(Box<str>),
    Many(Box<[Box<str>]>),
}

impl Holders {
    fn as_slice(&self) -> &[Box<str>] {
        match self {
            Holders::One(aor) => std::slice::from_ref(aor),
            Holders::Many(aors) => aors,
        }
    }

    /// `self` with one more `aor`.
    fn with(&self, aor: &str) -> Holders {
        let mut aors: Vec<Box<str>> = self.as_slice().to_vec();
        aors.push(aor.into());
        Holders::Many(aors.into_boxed_slice())
    }
}

/// Contact identity → the AoRs with a UE binding that has it.
pub(crate) struct ContactIndex {
    holders: DashMap<u64, Holders, BuildHasherDefault<PassThrough>>,
    keys: std::collections::hash_map::RandomState,
}

impl std::fmt::Debug for ContactIndex {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ContactIndex")
            .field("identities", &self.holders.len())
            .finish()
    }
}

impl Default for ContactIndex {
    fn default() -> Self {
        Self {
            holders: DashMap::default(),
            keys: std::collections::hash_map::RandomState::new(),
        }
    }
}

impl ContactIndex {
    /// The identity of `uri`: what [`super::same_contact`] compares.
    pub(crate) fn key_of(&self, uri: &SipUri) -> u64 {
        let mut hasher = self.keys.build_hasher();
        match &uri.scheme {
            Scheme::Sip => hasher.write_u8(0),
            Scheme::Sips => hasher.write_u8(1),
            Scheme::Tel => hasher.write_u8(2),
            other => {
                hasher.write_u8(3);
                hasher.write(other.to_string().as_bytes());
            }
        }
        match &uri.user {
            Some(user) => {
                hasher.write_u8(1);
                hasher.write_usize(user.len());
                hasher.write(user.as_bytes());
            }
            None => hasher.write_u8(0),
        }
        hasher.write_usize(uri.host.len());
        for byte in uri.host.bytes() {
            hasher.write_u8(byte.to_ascii_lowercase());
        }
        let default_port = if matches!(uri.scheme, Scheme::Sips) {
            5061
        } else {
            5060
        };
        hasher.write_u16(uri.port.unwrap_or(default_port));
        hasher.finish()
    }

    /// The identities of the UE bindings among `contacts`, one per binding.
    pub(crate) fn keys_of(&self, contacts: &[Contact]) -> Vec<u64> {
        contacts
            .iter()
            .filter(|contact| contact.kind == ContactKind::Ue)
            .map(|contact| self.key_of(&contact.uri))
            .collect()
    }

    /// Record a binding of `aor` with identity `key`.
    pub(crate) fn add(&self, key: u64, aor: &str) {
        match self.holders.entry(key) {
            dashmap::mapref::entry::Entry::Occupied(mut occupied) => {
                let grown = occupied.get().with(aor);
                *occupied.get_mut() = grown;
            }
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                vacant.insert(Holders::One(aor.into()));
            }
        }
    }

    /// Forget one binding of `aor` with identity `key`.
    pub(crate) fn remove(&self, key: u64, aor: &str) {
        let dashmap::mapref::entry::Entry::Occupied(mut occupied) = self.holders.entry(key) else {
            return;
        };
        let held = occupied.get().as_slice();
        let Some(position) = held.iter().position(|holder| holder.as_ref() == aor) else {
            return;
        };
        let mut rest: Vec<Box<str>> = held.to_vec();
        rest.remove(position);
        match rest.pop() {
            None => {
                occupied.remove();
            }
            Some(last) if rest.is_empty() => *occupied.get_mut() = Holders::One(last),
            Some(last) => {
                rest.push(last);
                *occupied.get_mut() = Holders::Many(rest.into_boxed_slice());
            }
        }
    }

    /// Record every UE binding of `contacts` under `aor`.
    #[cfg(test)]
    pub(crate) fn add_all(&self, aor: &str, contacts: &[Contact]) {
        for key in self.keys_of(contacts) {
            self.add(key, aor);
        }
    }

    /// Forget every UE binding of `contacts` under `aor`.
    pub(crate) fn remove_all(&self, aor: &str, contacts: &[Contact]) {
        for key in self.keys_of(contacts) {
            self.remove(key, aor);
        }
    }

    /// `aor`'s bindings went from identities `before` to `after`: record what
    /// was added and forget what was removed. A refresh of the same Contact
    /// changes nothing and costs no write.
    pub(crate) fn replace(&self, aor: &str, mut before: Vec<u64>, mut after: Vec<u64>) {
        if before == after {
            return;
        }
        before.sort_unstable();
        after.sort_unstable();
        let (mut old, mut new) = (0, 0);
        while old < before.len() || new < after.len() {
            match (before.get(old), after.get(new)) {
                (Some(gone), Some(kept)) if gone == kept => {
                    old += 1;
                    new += 1;
                }
                (Some(gone), Some(added)) if gone > added => {
                    self.add(*added, aor);
                    new += 1;
                }
                (Some(gone), _) => {
                    self.remove(*gone, aor);
                    old += 1;
                }
                (None, Some(added)) => {
                    self.add(*added, aor);
                    new += 1;
                }
                (None, None) => break,
            }
        }
    }

    /// The AoRs holding a binding with identity `key`, each once.
    pub(crate) fn aors(&self, key: u64) -> Vec<String> {
        let Some(holders) = self.holders.get(&key) else {
            return Vec::new();
        };
        let mut aors: Vec<String> = Vec::with_capacity(holders.as_slice().len());
        for aor in holders.as_slice() {
            if !aors.iter().any(|seen| seen.as_str() == aor.as_ref()) {
                aors.push(aor.to_string());
            }
        }
        aors
    }

    /// Every identity with the AoRs holding it, sorted: what a consistency
    /// check compares against an index rebuilt from the bindings.
    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> std::collections::BTreeMap<u64, Vec<String>> {
        self.holders
            .iter()
            .map(|entry| {
                let mut aors: Vec<String> = entry
                    .value()
                    .as_slice()
                    .iter()
                    .map(|aor| aor.to_string())
                    .collect();
                aors.sort();
                (*entry.key(), aors)
            })
            .collect()
    }

    /// An empty index keyed as this one is, so the two can be compared.
    #[cfg(test)]
    pub(crate) fn empty_like(&self) -> Self {
        Self {
            holders: DashMap::default(),
            keys: self.keys.clone(),
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.holders.len()
    }
}

/// The lookups the index serves, and the install a restore goes through.
impl super::Registrar {
    /// Reverse lookup: non-expired UE-side contacts whose stored **Contact**
    /// URI names the same device as `contact_uri`: scheme, user, host
    /// (case-insensitively, RFC 3261 §19.1.4) and port, a default port equal
    /// to none, parameters ignored.
    ///
    /// [`lookup`](Self::lookup) resolves a *logical* address (`user@domain`);
    /// this resolves a *physical* one.  It exists for the terminating edge
    /// where an upstream registrar-of-record (a PBX sitting in front of
    /// siphon) retargets the INVITE straight at the cached Contact and
    /// loose-routes it back through siphon: the Request-URI / To then carry
    /// the contact (`sip:1001@203.0.113.7:17514`), not the registration
    /// domain (`sip:1001@pbx.example`), so an AoR-keyed `lookup` misses even
    /// though the binding is present.  Matching on the Contact recovers it.
    ///
    /// Reads only the AoRs the [`contact_index`] names for that Contact, so it
    /// costs the same at any registration count. AS-side contacts are excluded
    /// and the result is sorted by q descending, both matching `lookup`.
    pub fn lookup_contact(&self, contact_uri: &str) -> Vec<Contact> {
        let mut out: Vec<Contact> = Vec::new();
        self.for_each_contact_match(contact_uri, |_, contact| {
            out.push(contact.clone());
            true
        });
        sort_by_preference(&mut out);
        out
    }

    /// Whether any non-expired UE-side binding has a **Contact** URI matching
    /// `contact_uri`.  Contact-keyed twin of [`is_registered`](Self::is_registered);
    /// see [`lookup_contact`](Self::lookup_contact) for why the terminating
    /// edge needs to match on the Contact rather than the AoR.
    pub fn is_registered_contact(&self, contact_uri: &str) -> bool {
        let mut found = false;
        self.for_each_contact_match(contact_uri, |_, _| {
            found = true;
            false
        });
        found
    }

    /// Call `visit` with each live UE binding whose Contact names the device
    /// `contact_uri` does, and its AoR, until it returns `false`. Nothing
    /// matches a `contact_uri` that is not a URI.
    fn for_each_contact_match(
        &self,
        contact_uri: &str,
        mut visit: impl FnMut(&str, &Contact) -> bool,
    ) {
        let Some(target) = contact_target(contact_uri) else {
            return;
        };
        for aor in self.contact_index.aors(self.contact_index.key_of(&target)) {
            let Some(entry) = self.bindings.get(&aor) else {
                continue;
            };
            for contact in entry.value().iter() {
                if contact.kind == ContactKind::Ue
                    && !contact.is_expired()
                    && same_contact(&contact.uri, &target)
                    && !visit(&aor, contact)
                {
                    return;
                }
            }
        }
    }

    /// [`aor_for_contact`](Self::aor_for_contact) with the matched binding's
    /// Contact URI, which is what [`has_live_contact`](Self::has_live_contact)
    /// later asks about.
    pub fn binding_for_contact(&self, contact_uri: &str) -> Option<(Aor, String)> {
        let mut found: Option<(Aor, String)> = None;
        let mut shared = false;
        self.for_each_contact_match(contact_uri, |aor, contact| {
            match &found {
                Some((first, _)) if first != aor => {
                    shared = true;
                    return false;
                }
                Some(_) => {}
                None => found = Some((aor.to_string(), contact.uri.to_string())),
            }
            true
        });
        if shared {
            None
        } else {
            found
        }
    }

    /// Install `contacts` as the bindings of `aor`, replacing any it has, with
    /// the contact index following under the same shard lock. What a restore
    /// from a persistent backend stores each AoR with.
    pub(crate) fn install_bindings(&self, aor: &str, contacts: Vec<Contact>) {
        let mut entry = self.bindings.entry(aor.to_string()).or_default();
        self.contact_index.replace(
            aor,
            self.contact_index.keys_of(entry.value()),
            self.contact_index.keys_of(&contacts),
        );
        *entry.value_mut() = contacts;
    }

    /// Whether the contact index holds exactly one entry per UE binding, live
    /// or not yet reaped, as one rebuilt from the bindings would.
    #[cfg(test)]
    pub(crate) fn contact_index_is_consistent(&self) -> bool {
        let rebuilt = self.contact_index.empty_like();
        for entry in self.bindings.iter() {
            rebuilt.add_all(entry.key(), entry.value());
        }
        rebuilt.snapshot() == self.contact_index.snapshot()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uri(text: &str) -> SipUri {
        crate::sip::parser::parse_uri_standalone(text).expect("a URI")
    }

    #[test]
    fn the_identity_ignores_parameters_host_case_and_the_default_port() {
        let index = ContactIndex::default();
        let key = index.key_of(&uri("sip:1001@203.0.113.7"));
        assert_eq!(key, index.key_of(&uri("sip:1001@203.0.113.7:5060")));
        assert_eq!(
            key,
            index.key_of(&uri("sip:1001@203.0.113.7;transport=udp"))
        );
        assert_eq!(
            index.key_of(&uri("sip:1001@Pbx.Example.Invalid")),
            index.key_of(&uri("sip:1001@pbx.example.invalid"))
        );
        assert_eq!(
            index.key_of(&uri("sips:1001@203.0.113.7")),
            index.key_of(&uri("sips:1001@203.0.113.7:5061"))
        );
    }

    #[test]
    fn the_identity_tells_apart_what_names_another_device() {
        let index = ContactIndex::default();
        let key = index.key_of(&uri("sip:1001@203.0.113.7:5060"));
        for other in [
            "sip:1002@203.0.113.7",
            "sip:1001@203.0.113.8",
            "sip:1001@203.0.113.7:5070",
            "sips:1001@203.0.113.7:5060",
            "sip:203.0.113.7",
            "sip:1001@203.0.113.7:5061",
        ] {
            assert_ne!(key, index.key_of(&uri(other)), "{other}");
        }
        // A user is case-sensitive (RFC 3261 §19.1.4).
        assert_ne!(
            index.key_of(&uri("sip:Alice@203.0.113.7")),
            index.key_of(&uri("sip:alice@203.0.113.7"))
        );
    }

    #[test]
    fn holders_count_one_entry_per_binding() {
        let index = ContactIndex::default();
        index.add(7, "sip:a@example.invalid");
        index.add(7, "sip:a@example.invalid");
        index.add(7, "sip:b@example.invalid");
        assert_eq!(
            index.aors(7),
            ["sip:a@example.invalid", "sip:b@example.invalid"]
        );
        index.remove(7, "sip:a@example.invalid");
        assert_eq!(
            index.aors(7),
            ["sip:a@example.invalid", "sip:b@example.invalid"]
        );
        index.remove(7, "sip:a@example.invalid");
        assert_eq!(index.aors(7), ["sip:b@example.invalid"]);
        // Forgetting what is not held changes nothing.
        index.remove(7, "sip:c@example.invalid");
        index.remove(8, "sip:b@example.invalid");
        assert_eq!(index.aors(7), ["sip:b@example.invalid"]);
        index.remove(7, "sip:b@example.invalid");
        assert!(index.aors(7).is_empty());
        assert_eq!(index.len(), 0, "an emptied identity takes no room");
    }

    #[test]
    fn replace_writes_only_the_difference() {
        let index = ContactIndex::default();
        index.replace("sip:a@example.invalid", vec![], vec![3, 1, 2, 2]);
        index.replace("sip:a@example.invalid", vec![1, 2, 2, 3], vec![2, 4, 3]);
        let snapshot = index.snapshot();
        assert_eq!(
            snapshot.keys().copied().collect::<Vec<_>>(),
            [2, 3, 4],
            "{snapshot:?}"
        );
        assert_eq!(snapshot[&2], ["sip:a@example.invalid"]);
        index.replace("sip:a@example.invalid", vec![2, 4, 3], vec![]);
        assert_eq!(index.len(), 0);
    }

    #[test]
    fn the_pass_through_hasher_hands_back_the_key() {
        let mut hasher = PassThrough::default();
        hasher.write_u64(0xfeed_beef);
        assert_eq!(hasher.finish(), 0xfeed_beef);
    }
}
