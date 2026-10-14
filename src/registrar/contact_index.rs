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
//! Each binding is also keyed by the address its REGISTER came from, for
//! `binding_for_source`, the dialog-state match over a captured flow. Both
//! keys are fixed for the life of a binding, so the same maintenance carries
//! both.
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
use std::net::SocketAddr;

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

/// The AoRs holding a binding with one identity, with how many bindings each.
/// Nearly always one AoR with one binding. Many AoRs share a source address
/// behind a PBX or an SBC, so the shared case is a counted map: adding and
/// forgetting a binding stay O(1) however many AoRs it holds, and the map is
/// boxed so the common case pays no more than a pointer for it.
#[derive(Debug)]
enum Holders {
    One(Box<str>),
    // Boxed on purpose: an unboxed map would widen every slot of the index
    // from 16 to 56 bytes to serve the rare shared identity.
    #[allow(clippy::box_collection)]
    Many(Box<std::collections::HashMap<Box<str>, u32>>),
}

impl Holders {
    /// Each AoR once.
    fn aors(&self) -> Vec<String> {
        match self {
            Holders::One(aor) => vec![aor.to_string()],
            Holders::Many(counts) => counts.keys().map(|aor| aor.to_string()).collect(),
        }
    }

    /// Each AoR once per binding, sorted.
    #[cfg(test)]
    fn bindings(&self) -> Vec<String> {
        let mut aors: Vec<String> = match self {
            Holders::One(aor) => vec![aor.to_string()],
            Holders::Many(counts) => counts
                .iter()
                .flat_map(|(aor, count)| std::iter::repeat_n(aor.to_string(), *count as usize))
                .collect(),
        };
        aors.sort();
        aors
    }

    /// Count one more binding of `aor`.
    fn add(&mut self, aor: &str) {
        if let Holders::One(held) = self {
            let mut counts = std::collections::HashMap::with_capacity(2);
            counts.insert(std::mem::take(held), 1);
            *self = Holders::Many(Box::new(counts));
        }
        if let Holders::Many(counts) = self {
            *counts.entry(aor.into()).or_insert(0) += 1;
        }
    }

    /// Count one binding of `aor` fewer. `false` when nothing is left.
    fn remove(&mut self, aor: &str) -> bool {
        match self {
            Holders::One(held) => held.as_ref() != aor,
            Holders::Many(counts) => {
                if let Some(count) = counts.get_mut(aor) {
                    *count -= 1;
                    if *count == 0 {
                        counts.remove(aor);
                    }
                }
                // Back to the compact form once one binding is left.
                if counts.len() == 1 && counts.values().all(|count| *count == 1) {
                    if let Some(last) = counts.keys().next().cloned() {
                        *self = Holders::One(last);
                    }
                }
                !matches!(self, Holders::Many(counts) if counts.is_empty())
            }
        }
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

    /// The identity of the address a binding's REGISTER came from: what
    /// `binding_for_source` matches. Tagged apart from every Contact identity,
    /// whose first byte is a scheme tag of 0 to 3.
    pub(crate) fn source_key_of(&self, source: SocketAddr) -> u64 {
        let mut hasher = self.keys.build_hasher();
        hasher.write_u8(0xff);
        match source.ip() {
            std::net::IpAddr::V4(address) => hasher.write(&address.octets()),
            std::net::IpAddr::V6(address) => hasher.write(&address.octets()),
        }
        hasher.write_u16(source.port());
        hasher.finish()
    }

    /// The identities one UE binding is indexed under: its Contact, and the
    /// address its REGISTER came from when that is known. Neither changes for
    /// as long as the binding is stored; a refresh replaces the binding.
    pub(crate) fn keys_of_binding(&self, contact: &Contact) -> impl Iterator<Item = u64> {
        let indexed = contact.kind == ContactKind::Ue;
        let by_contact = indexed.then(|| self.key_of(&contact.uri));
        let by_source = contact
            .source_addr
            .filter(|_| indexed)
            .map(|source| self.source_key_of(source));
        by_contact.into_iter().chain(by_source)
    }

    /// The identities of the UE bindings among `contacts`, every one of each.
    pub(crate) fn keys_of(&self, contacts: &[Contact]) -> Vec<u64> {
        contacts
            .iter()
            .flat_map(|contact| self.keys_of_binding(contact))
            .collect()
    }

    /// Record a binding of `aor` with identity `key`.
    pub(crate) fn add(&self, key: u64, aor: &str) {
        match self.holders.entry(key) {
            dashmap::mapref::entry::Entry::Occupied(mut occupied) => occupied.get_mut().add(aor),
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
        if !occupied.get_mut().remove(aor) {
            occupied.remove();
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
        holders.aors()
    }

    /// Every identity with the AoRs holding it, sorted: what a consistency
    /// check compares against an index rebuilt from the bindings.
    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> std::collections::BTreeMap<u64, Vec<String>> {
        self.holders
            .iter()
            .map(|entry| (*entry.key(), entry.value().bindings()))
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
    /// The one AoR whose live UE binding's REGISTER came from `source`, with
    /// that binding's Contact URI. `None` when none did, or bindings of two
    /// AoRs did (a shared device or a front), as for
    /// [`binding_for_contact`](Self::binding_for_contact). For a request
    /// relayed over a captured flow, whose Request-URI need not be the
    /// Contact. Reads the AoRs the index names for that address.
    pub fn binding_for_source(&self, source: SocketAddr) -> Option<(Aor, String)> {
        let mut found: Option<(Aor, String)> = None;
        for aor in self
            .contact_index
            .aors(self.contact_index.source_key_of(source))
        {
            let Some(entry) = self.bindings.get(&aor) else {
                continue;
            };
            let Some(contact) = entry.value().iter().find(|contact| {
                contact.kind == ContactKind::Ue
                    && !contact.is_expired()
                    && contact.source_addr == Some(source)
            }) else {
                continue;
            };
            if found.is_some() {
                return None;
            }
            found = Some((aor.clone(), contact.uri.to_string()));
        }
        found
    }

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
    fn a_slot_stays_two_words() {
        assert_eq!(std::mem::size_of::<Holders>(), 16);
    }

    #[test]
    fn a_source_identity_is_its_address_and_port() {
        let index = ContactIndex::default();
        let source: SocketAddr = "203.0.113.7:5060".parse().expect("an address");
        assert_eq!(index.source_key_of(source), index.source_key_of(source));
        assert_ne!(
            index.source_key_of(source),
            index.source_key_of("203.0.113.7:5061".parse().expect("an address"))
        );
        assert_ne!(
            index.source_key_of(source),
            index.source_key_of("[2001:db8::7]:5060".parse().expect("an address"))
        );
    }

    #[test]
    fn the_pass_through_hasher_hands_back_the_key() {
        let mut hasher = PassThrough::default();
        hasher.write_u64(0xfeed_beef);
        assert_eq!(hasher.finish(), 0xfeed_beef);
    }
}
