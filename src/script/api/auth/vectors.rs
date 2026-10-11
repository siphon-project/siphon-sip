//! Pending IMS challenges: what is cached between a 401 and the REGISTER that
//! answers it, keyed by the nonce of the challenge.
//!
//! One store holds both kinds. An IMS-AKA entry is the expected response and
//! is used once. A SIP Digest entry is the H(A1) the subscriber server handed
//! out and lives on after the first answer, with the last nonce count, so a
//! later REGISTER under the same nonce is checked without another challenge.

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use dashmap::DashMap;

use super::sip_digest::SipDigestChallenge;

/// Expected response, cached between the 401 challenge and the verification
/// REGISTER so the second REGISTER can be checked without deriving a fresh
/// vector (which would carry a different RAND, hence a different XRES, and so
/// could never match).
///
/// Serves both AKA paths: HSS-backed (XRES from the MAA) and local Milenage
/// (XRES from `generate_vector`).
#[derive(Debug, Clone)]
pub(super) struct ImsAuthVector {
    /// Expected response (SIP-Authorization / XRES).
    ///
    /// CK/IK (AVP 625/626) are not cached here — they are consumed at
    /// challenge time via the `hss_ck`/`hss_ik` locals when building the
    /// WWW-Authenticate, and the P-CSCF IPsec path re-extracts them from the
    /// relayed 401 header via `reply.take_av()`. The verification REGISTER
    /// only needs the expected response.
    pub(super) expected_response: Vec<u8>,
    /// When the challenge was issued, so one that is never answered expires
    /// instead of sitting in the store for the life of the process.
    pub(super) stored_at: Instant,
}

/// A SIP Digest challenge and how far its nonce has been used.
#[derive(Debug, Clone)]
struct SipDigestEntry {
    challenge: SipDigestChallenge,
    /// The nonce count of the last REGISTER that verified, 0 before the first.
    last_nonce_count: u32,
    /// When the nonce stops being accepted.
    valid_until: Instant,
}

/// What is pending under a nonce.
#[derive(Debug, Clone)]
enum Pending {
    Aka(ImsAuthVector),
    SipDigest(SipDigestEntry),
}

impl Pending {
    fn is_live(&self) -> bool {
        match self {
            Pending::Aka(vector) => vector.stored_at.elapsed() < AUTH_VECTOR_TTL,
            Pending::SipDigest(entry) => Instant::now() < entry.valid_until,
        }
    }
}

/// The scheme of the challenge a nonce belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PendingScheme {
    Aka,
    SipDigest,
}

/// What recording a verified nonce count found.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum NonceCount {
    /// Higher than the last one: recorded, and the nonce stays valid.
    Accepted,
    /// Not higher than the last one: a replay, nothing recorded.
    Replayed,
    /// The nonce is gone or has expired.
    Unknown,
}

/// How long a pending auth vector stays usable after its 401 went out.
///
/// A UE answers a challenge inside one SIP transaction, so RFC 3261 Timer F
/// (64*T1 = 32 s) is the natural ceiling; 120 s leaves room for a slow radio
/// link and a retransmitted REGISTER. The bound matters because the store only
/// ever shrank on a *successful* verification, so a peer that collects 401s and
/// never answers grew it for the life of the process.
pub(super) const AUTH_VECTOR_TTL: Duration = Duration::from_secs(120);

/// Prune every Nth insert rather than on each one, so a burst of challenges
/// does not turn every insert into a full scan of the store. A trickle keeps
/// the store small on its own, and a burst reaches the threshold quickly.
const AUTH_VECTOR_PRUNE_EVERY: u64 = 64;

/// Pending IMS challenges, keyed by nonce: stored with the 401 challenge,
/// read by the REGISTER that answers it.
///
/// Prunes expired entries on every `AUTH_VECTOR_PRUNE_EVERY`th insert. The
/// insert counter is atomic, so under concurrent inserts each threshold goes to
/// exactly one insert, and that insert prunes before it stores its own entry. A
/// prune can run on another thread than the insert that happens to push the
/// store past a threshold, but none is skipped, which is what bounds the store.
pub(super) struct AuthVectorStore {
    vectors: DashMap<String, Pending>,
    inserts: std::sync::atomic::AtomicU64,
}

impl AuthVectorStore {
    fn new() -> Self {
        Self {
            vectors: DashMap::new(),
            inserts: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Store `pending` under `nonce`, dropping every entry that has expired.
    fn insert_pending(&self, nonce: String, pending: Pending) {
        let count = self
            .inserts
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if count.is_multiple_of(AUTH_VECTOR_PRUNE_EVERY) {
            self.vectors.retain(|_, pending| pending.is_live());
        }
        self.vectors.insert(nonce, pending);
    }

    /// Cache the expected response for `nonce`, dropping any vector whose
    /// challenge has since expired.
    fn insert(&self, nonce: String, expected_response: Vec<u8>) {
        self.insert_pending(
            nonce,
            Pending::Aka(ImsAuthVector {
                expected_response,
                stored_at: Instant::now(),
            }),
        );
    }

    /// Cache a SIP Digest challenge under its nonce. It waits for its first
    /// answer as long as an AKA vector does.
    fn insert_digest(&self, nonce: String, challenge: SipDigestChallenge) {
        self.insert_pending(
            nonce,
            Pending::SipDigest(SipDigestEntry {
                challenge,
                last_nonce_count: 0,
                valid_until: Instant::now() + AUTH_VECTOR_TTL,
            }),
        );
    }

    /// Consume the AKA vector for `nonce`, if one is cached and still within
    /// its TTL.
    ///
    /// Removal is unconditional, so a nonce is single-use whether or not the
    /// response verifies: replaying a captured `Authorization` finds nothing.
    /// A SIP Digest challenge under the nonce is left alone.
    fn take(&self, nonce: &str) -> Option<ImsAuthVector> {
        let (_, pending) = self
            .vectors
            .remove_if(nonce, |_, pending| matches!(pending, Pending::Aka(_)))?;
        match pending {
            Pending::Aka(vector) if vector.stored_at.elapsed() < AUTH_VECTOR_TTL => Some(vector),
            _ => None,
        }
    }

    /// The scheme of the live challenge under `nonce`.
    fn scheme(&self, nonce: &str) -> Option<PendingScheme> {
        let pending = self.vectors.get(nonce)?;
        pending.is_live().then(|| match pending.value() {
            Pending::Aka(_) => PendingScheme::Aka,
            Pending::SipDigest(_) => PendingScheme::SipDigest,
        })
    }

    /// The live SIP Digest challenge under `nonce` and whether it has been
    /// answered before.
    fn digest(&self, nonce: &str) -> Option<(SipDigestChallenge, bool)> {
        let pending = self.vectors.get(nonce)?;
        match pending.value() {
            Pending::SipDigest(entry) if pending.is_live() => {
                Some((entry.challenge.clone(), entry.last_nonce_count > 0))
            }
            _ => None,
        }
    }

    /// Record the nonce count of a response that verified. The check and the
    /// write happen under the entry's lock, so of two REGISTERs with the same
    /// count only one is accepted. An accepted count keeps the nonce valid for
    /// `lifetime` from now.
    fn record_nonce_count(&self, nonce: &str, count: u32, lifetime: Duration) -> NonceCount {
        let Some(mut pending) = self.vectors.get_mut(nonce) else {
            return NonceCount::Unknown;
        };
        if !pending.is_live() {
            return NonceCount::Unknown;
        }
        match pending.value_mut() {
            Pending::SipDigest(entry) if count > entry.last_nonce_count => {
                entry.last_nonce_count = count;
                entry.valid_until = Instant::now() + lifetime;
                NonceCount::Accepted
            }
            Pending::SipDigest(_) => NonceCount::Replayed,
            Pending::Aka(_) => NonceCount::Unknown,
        }
    }

    fn forget(&self, nonce: &str) {
        self.vectors.remove(nonce);
    }

    pub(super) fn contains(&self, nonce: &str) -> bool {
        self.vectors.contains_key(nonce)
    }

    pub(super) fn len(&self) -> usize {
        self.vectors.len()
    }
}

/// The process-wide [`AuthVectorStore`]: populated on the first REGISTER (401
/// challenge), read on the second (credential verification).
static AUTH_VECTORS: OnceLock<AuthVectorStore> = OnceLock::new();

pub(super) fn auth_vectors() -> &'static AuthVectorStore {
    AUTH_VECTORS.get_or_init(AuthVectorStore::new)
}

/// Drop whatever is pending under `nonce` in the process-wide store.
pub(super) fn forget_challenge(nonce: &str) {
    auth_vectors().forget(nonce);
}

/// Cache the expected response for `nonce` in the process-wide store.
pub(super) fn store_auth_vector(nonce: String, expected_response: Vec<u8>) {
    auth_vectors().insert(nonce, expected_response);
}

/// Consume the vector for `nonce` from the process-wide store.
pub(super) fn take_auth_vector(nonce: &str) -> Option<ImsAuthVector> {
    auth_vectors().take(nonce)
}

/// The scheme of the live challenge under `nonce` in the process-wide store.
pub(super) fn pending_scheme(nonce: &str) -> Option<PendingScheme> {
    auth_vectors().scheme(nonce)
}

/// Cache a SIP Digest challenge in the process-wide store.
pub(super) fn store_digest_challenge(nonce: String, challenge: SipDigestChallenge) {
    auth_vectors().insert_digest(nonce, challenge);
}

/// The live SIP Digest challenge under `nonce` and whether it has been
/// answered before.
pub(super) fn digest_challenge(nonce: &str) -> Option<(SipDigestChallenge, bool)> {
    auth_vectors().digest(nonce)
}

/// Record a verified nonce count in the process-wide store.
pub(super) fn record_nonce_count(nonce: &str, count: u32, lifetime: Duration) -> NonceCount {
    auth_vectors().record_nonce_count(nonce, count, lifetime)
}

/// Store an AKA vector whose challenge went out longer ago than the TTL.
#[cfg(test)]
pub(super) fn store_expired_auth_vector(nonce: String, expected_response: Vec<u8>) {
    auth_vectors().vectors.insert(
        nonce,
        Pending::Aka(ImsAuthVector {
            expected_response,
            stored_at: Instant::now() - (AUTH_VECTOR_TTL + Duration::from_secs(1)),
        }),
    );
}

/// Make the SIP Digest nonce expire now, as the passing of its lifetime does.
#[cfg(test)]
pub(super) fn expire_digest_challenge(nonce: &str) {
    if let Some(mut pending) = auth_vectors().vectors.get_mut(nonce) {
        if let Pending::SipDigest(entry) = pending.value_mut() {
            entry.valid_until = Instant::now() - Duration::from_secs(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// A vector whose challenge went out longer ago than the TTL.
    fn expired_vector() -> Pending {
        Pending::Aka(ImsAuthVector {
            expected_response: vec![0xBB; 8],
            stored_at: std::time::Instant::now()
                - (AUTH_VECTOR_TTL + std::time::Duration::from_secs(1)),
        })
    }

    /// The insert that reaches the prune threshold drops every expired vector
    /// before it stores its own.
    ///
    /// On a store of the test's own. The process-wide store and its insert
    /// counter are shared with every other test that issues a challenge, so the
    /// threshold could be drawn by one of those on its own thread, which then
    /// pruned after this test had already asserted.
    #[test]
    fn auth_vector_store_prunes_expired_entries_on_insert() {
        let store = AuthVectorStore::new();
        let stale = "aka-nonce-stale-prune";
        store.vectors.insert(stale.to_string(), expired_vector());

        // A fresh store's first insert is at the threshold.
        store.insert("aka-nonce-prune-0".to_string(), vec![0xCC; 8]);

        assert!(!store.contains(stale), "prune drops expired vectors");
        assert!(store.contains("aka-nonce-prune-0"));
    }

    /// Between thresholds no insert scans the store, and the insert at the next
    /// threshold prunes again: every `AUTH_VECTOR_PRUNE_EVERY` inserts, not once.
    #[test]
    fn auth_vector_store_prunes_again_at_every_threshold() {
        let store = AuthVectorStore::new();
        store.insert("aka-nonce-cadence-0".to_string(), vec![0xCC; 8]);
        let stale = "aka-nonce-stale-cadence";
        store.vectors.insert(stale.to_string(), expired_vector());

        for index in 1..AUTH_VECTOR_PRUNE_EVERY {
            store.insert(format!("aka-nonce-cadence-{index}"), vec![0xCC; 8]);
        }
        assert!(
            store.contains(stale),
            "an insert between thresholds pruned the store"
        );

        store.insert(
            format!("aka-nonce-cadence-{AUTH_VECTOR_PRUNE_EVERY}"),
            vec![0xCC; 8],
        );
        assert!(
            !store.contains(stale),
            "the insert at the next threshold did not prune"
        );
        assert_eq!(store.len(), AUTH_VECTOR_PRUNE_EVERY as usize + 1);
    }

    /// Concurrent inserts do not skip a prune. The counter is atomic, so each
    /// threshold goes to exactly one insert, and that insert prunes before it
    /// returns: once every inserting thread has returned, no vector that had
    /// expired before they started is left, and every fresh vector is.
    #[test]
    fn auth_vector_store_prunes_under_concurrent_inserts() {
        const THREADS: usize = 8;
        const STALE: usize = 32;
        let per_thread = 3 * AUTH_VECTOR_PRUNE_EVERY;

        let store = Arc::new(AuthVectorStore::new());
        for index in 0..STALE {
            store
                .vectors
                .insert(format!("aka-nonce-stale-{index}"), expired_vector());
        }
        let start = Arc::new(std::sync::Barrier::new(THREADS));
        let inserters: Vec<_> = (0..THREADS)
            .map(|thread| {
                let store = Arc::clone(&store);
                let start = Arc::clone(&start);
                std::thread::spawn(move || {
                    start.wait();
                    for index in 0..per_thread {
                        store.insert(format!("aka-nonce-{thread}-{index}"), vec![0xCC; 8]);
                    }
                })
            })
            .collect();
        for inserter in inserters {
            inserter.join().expect("an inserting thread");
        }

        for index in 0..STALE {
            assert!(
                !store.contains(&format!("aka-nonce-stale-{index}")),
                "expired vector {index} survived concurrent inserts"
            );
        }
        assert_eq!(store.len(), THREADS * per_thread as usize);

        // No insert was lost from the count either: the concurrent inserts
        // ended exactly on a threshold, so the next insert prunes.
        let stale = "aka-nonce-stale-after";
        store.vectors.insert(stale.to_string(), expired_vector());
        store.insert("aka-nonce-after".to_string(), vec![0xCC; 8]);
        assert!(
            !store.contains(stale),
            "the insert after the concurrent ones was not on a threshold"
        );
        assert_eq!(store.len(), THREADS * per_thread as usize + 1);
    }
}
