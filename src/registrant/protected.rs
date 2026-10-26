//! Re-registering an IMS UE over the security association it already holds.
//!
//! A registered UE with a set of SAs re-registers and de-registers over it
//! (3GPP TS 24.229 5.1.1.4.1, 5.1.1.6.1): from its protected client port to the
//! P-CSCF's protected server port, repeating the Authorization of the last
//! successful authentication and echoing its Security-Server in
//! Security-Verify, and offering new SA parameters in Security-Client
//! (5.1.1.4.2, 5.1.1.6.2). The S-CSCF may accept that on the strength of the
//! P-CSCF's integrity-protected stamp, or challenge it again.
//!
//! A challenge sets up a new SA set alongside the old one (TS 33.203 7.4.1a,
//! TS 24.229 5.1.1.5.1). The new set uses a new protected client port, the
//! server port stays (TS 33.203 7.4.0); the authenticated REGISTER rides the
//! new set; at its 200 the new set takes over sending and the old one is kept
//! for the P-CSCF, which goes on using it until it hears from the UE over the
//! new one. The old set goes once a further message arrives over the new one,
//! which for a registrant is the answer to its next REGISTER.
//!
//! A challenge to an *unprotected* REGISTER (the initial one, or a fall-back
//! after a failure) concludes an initial authentication: every older set goes
//! at its 200 (TS 24.229 table 5.2.2-1). A failed re-registration falls back
//! to an unprotected one (TS 24.229 5.1.1.4.1), its temporary set deleted.
//!
//! The UE therefore holds at most two sets at rest and offers a third client
//! port, which is why it rotates through three (see
//! [`protected_client_ports`]): a P-CSCF refuses an offered client port that
//! one of its sets still uses (TS 33.203 7.1, rule 3).

use super::*;
use std::collections::HashSet;
use std::sync::atomic::AtomicUsize;

/// The protected client ports a UE rotates through: `ue_port_c`, then the two
/// ports above the higher of the client and server ports (below the lower one
/// when there is no room above). The configured pair `6100`/`6101` rotates
/// through `6100`, `6102`, `6103`.
pub fn protected_client_ports(ue_port_c: u16, ue_port_s: u16) -> [u16; 3] {
    let high = ue_port_c.max(ue_port_s);
    match (high.checked_add(1), high.checked_add(2)) {
        (Some(first), Some(second)) => [ue_port_c, first, second],
        _ => {
            let low = ue_port_c.min(ue_port_s);
            [ue_port_c, low.saturating_sub(1), low.saturating_sub(2)]
        }
    }
}

/// Why a UE's protected ports cannot be used, if they cannot: every protected
/// port must differ from the standard SIP ports and from each other (TS 33.203
/// 7.1), and none may be zero.
pub fn protected_ports_problem(ue_port_c: u16, ue_port_s: u16) -> Option<String> {
    let client_ports = protected_client_ports(ue_port_c, ue_port_s);
    let mut all: Vec<u16> = client_ports.to_vec();
    all.push(ue_port_s);
    if let Some(port) = all.iter().find(|port| matches!(**port, 0 | 5060 | 5061)) {
        return Some(format!(
            "protected ports {all:?} (ue_port_c {ue_port_c}, ue_port_s {ue_port_s}) include \
             {port}: a protected port is never 0, 5060 or 5061 (3GPP TS 33.203 7.1)"
        ));
    }
    let mut sorted = all.clone();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.len() != all.len() {
        return Some(format!(
            "protected ports {all:?} (ue_port_c {ue_port_c}, ue_port_s {ue_port_s}) repeat a port"
        ));
    }
    None
}

/// One set of four SAs the UE installed: its protected client port, and the
/// SPIs it allocated, which tell this installation from a later one on the
/// same port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UeSaKey {
    pub ue_port_c: u16,
    pub spi_uc: u32,
    pub spi_us: u32,
}

/// The SA set of the last successful authentication, the one protected
/// REGISTERs ride.
#[derive(Debug, Clone)]
pub struct EstablishedSaSet {
    pub key: UeSaKey,
    /// The P-CSCF protected server port: where protected requests go.
    pub pcscf_port_s: u16,
    /// The Security-Server of the 401 that set it up, mirrored in the
    /// Security-Verify of every protected REGISTER (TS 24.229 5.1.1.4.2 e).
    pub security_server: String,
    /// The Authorization of the REGISTER that authenticated it: the last nonce
    /// and the last calculated response, repeated on protected re- and
    /// de-REGISTERs (TS 24.229 5.1.1.4.2 a, 5.1.1.6.2 a).
    pub authorization: String,
    /// `false` once a re-registration over it failed: the next REGISTER goes
    /// unprotected (TS 24.229 5.1.1.4.1), and the set stays only for what the
    /// P-CSCF may still send over it, until that registration concludes.
    pub usable: bool,
}

/// The REGISTER exchange an IPsec entry has in flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UeExchange {
    /// None.
    #[default]
    Idle,
    /// An unprotected REGISTER: the initial one, or a fall-back.
    Unprotected,
    /// A REGISTER over the established set.
    Protected,
    /// The authenticated REGISTER over a temporary set, after a 401 to a
    /// REGISTER that was protected (`started_protected`) or not.
    Authenticating { started_protected: bool },
}

/// Every SA set an IPsec entry holds, and the exchange in flight. At most
/// three sets: established, retiring and temporary.
#[derive(Debug, Clone, Default)]
pub struct UeSaSets {
    /// The set of the last successful authentication.
    pub established: Option<EstablishedSaSet>,
    /// The set an authenticated re-registration replaced, kept until a
    /// message arrives over its successor (TS 33.203 7.4.1a).
    pub retiring: Option<UeSaKey>,
    /// The set installed at a 401, awaiting the 200 to the authenticated
    /// REGISTER (TS 24.229 5.1.1.5.1).
    pub temporary: Option<UeSaKey>,
    pub exchange: UeExchange,
    /// The Authorization of the authenticated REGISTER in flight, which
    /// becomes the established set's at its 200.
    pub pending_authorization: Option<String>,
}

impl UeSaSets {
    /// Every set held, oldest first.
    pub fn keys(&self) -> Vec<UeSaKey> {
        self.retiring
            .into_iter()
            .chain(self.established.as_ref().map(|set| set.key))
            .chain(self.temporary)
            .collect()
    }

    /// The set protected REGISTERs ride, while it may.
    pub fn usable(&self) -> Option<&EstablishedSaSet> {
        self.established.as_ref().filter(|set| set.usable)
    }
}

/// A UE SA pair to delete: the entry's own address, or `None` for the
/// process's UE address, which the drainer resolves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SaDeletion {
    pub address: Option<IpAddr>,
    pub key: UeSaKey,
}

/// The SA sets of a removed entry, deleted when its protected de-REGISTER is
/// answered or `deadline` passes.
#[derive(Debug)]
pub(super) struct Teardown {
    call_id: String,
    deletions: Vec<SaDeletion>,
    deadline: Instant,
}

/// How long a removed entry's SA sets wait for the answer to its de-REGISTER:
/// RFC 3261 Timer F, plus the loop tick that sends it.
const TEARDOWN_WAIT: Duration = Duration::from_secs(32 + 5);

/// The SIP level lifetime of a temporary set: the reg-await-auth timer, 4
/// minutes (TS 24.229 clause 5.1.1.5.1 step 2, "The UE shall set a temporary
/// SIP level lifetime for the temporary set of security associations to the
/// value of reg-await-auth timer"; table 7.8.1 gives the timer 4 minutes, 2
/// times the IM CN subsystem Timer F of 128 seconds). The 200 replaces it.
pub const REG_AWAIT_AUTH_SECS: u64 = 4 * 60;

/// What an established set lives beyond the registration it carries: "the
/// lifetime of the just completed registration plus 30 seconds" (TS 24.229
/// clauses 5.1.1.2.2, 5.1.1.4.2 and 5.1.1.5.1), unless what it had left was
/// longer.
pub const SA_LIFETIME_MARGIN_SECS: u64 = 30;

/// A consecutive invalid challenge past this many goes unanswered: "A UE shall
/// only respond to two consecutive invalid challenges" (TS 24.229 clause
/// 5.1.1.5.12).
const MAX_INVALID_CHALLENGES: u32 = 2;

/// How many times one entry may move a protected client port it cannot bind
/// to another port before it gives up on that port.
const MAX_PORT_REPLACEMENTS: u32 = 8;

/// Delete `deletions` from `ipsec`, in order. A pair is deleted only while the
/// kernel still holds the installation the deletion names (the same SPIs): a
/// later set re-installed on the same port is left alone. Returns how many
/// pairs it deleted.
pub async fn delete_sa_sets(
    ipsec: &IpsecManager,
    deletions: Vec<SaDeletion>,
    process_ue_ip: IpAddr,
) -> usize {
    let mut deleted = 0;
    for deletion in deletions {
        let ue_addr = deletion.address.unwrap_or(process_ue_ip);
        let key = deletion.key;
        let installed = ipsec
            .get_sa(&ue_addr, key.ue_port_c)
            .filter(|sa| sa.spi_uc == key.spi_uc && sa.spi_us == key.spi_us);
        let Some(installed) = installed else {
            continue;
        };
        if ipsec.delete_installation(&installed).await {
            deleted += 1;
        }
    }
    deleted
}

/// Counts a deletion task in flight for as long as it lives, so shutdown can
/// wait for the ones the dispatcher started.
struct DeletionInFlight(Arc<AtomicUsize>);

impl DeletionInFlight {
    fn start(counter: &Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::AcqRel);
        Self(Arc::clone(counter))
    }
}

impl Drop for DeletionInFlight {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// What [`RegistrantManager::degrade_unbindable_ports`] made of the sockets an
/// entry could not bind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PortDegradation {
    /// A protected client port moved, so the socket plan changed.
    pub moved: bool,
    /// The entry cannot register this tick: its plain or protected server
    /// port, or every client port it could offer, is unbound.
    pub blocked: bool,
}

/// The key of the SA set the current handshake installs.
fn offered_key(ipsec: &UeIpsec) -> UeSaKey {
    UeSaKey {
        ue_port_c: ipsec.ue_port_c,
        spi_uc: ipsec.spi_uc,
        spi_us: ipsec.spi_us,
    }
}

/// The SA sets a REGISTER exchange produced, from the 200 that concluded it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConcludedSaSets {
    /// The established set, whose lifetime the 200 extends.
    pub established: UeSaKey,
    /// The set it took over from, whose remaining lifetime the new one must
    /// not fall short of (TS 24.229 5.1.1.5.1).
    pub previous: Option<UeSaKey>,
    /// Whether the established set had a lifetime of its own already (a
    /// refresh over it), which the 200 never shortens (TS 33.203 7.4.1a). A
    /// new set's lifetime is the temporary one set at the 401, replaced.
    pub keeps_own_lifetime: bool,
}

impl RegistrantManager {
    /// Give the manager the kernel the UE SAs live in. Called once by
    /// [`registration_loop`].
    pub fn install_ipsec(&self, ipsec: Arc<IpsecManager>) {
        let _ = self.ipsec.set(ipsec);
    }

    /// Delete the queued SA pairs from `ipsec` on a task of their own,
    /// counted in flight until it ends (see [`Self::sa_deletions_settled`]).
    pub fn spawn_sa_deletions(&self, ipsec: &Arc<IpsecManager>, process_ue_ip: IpAddr) {
        let deletions = self.take_pending_sa_deletions();
        if deletions.is_empty() {
            return;
        }
        let ipsec = Arc::clone(ipsec);
        let in_flight = DeletionInFlight::start(&self.sa_deletions_in_flight);
        tokio::spawn(async move {
            delete_sa_sets(&ipsec, deletions, process_ue_ip).await;
            drop(in_flight);
        });
    }

    /// Whether no SA set waits on a de-REGISTER's answer, none is queued for
    /// deletion and no deletion task is still running.
    pub fn sa_deletions_settled(&self) -> bool {
        self.sa_deletions_in_flight.load(Ordering::Acquire) == 0
            && self
                .teardowns
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .is_empty()
            && self
                .pending_sa_deletions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .is_empty()
    }

    /// Hand every SA set still tracked to the deletion queue, for shutdown:
    /// those of removed entries whose de-REGISTER went unanswered, and those
    /// of any entry still live.
    pub(super) fn surrender_all_sa_sets(&self) {
        self.expire_teardowns(Instant::now() + TEARDOWN_WAIT * 2);
        let mut deletions = Vec::new();
        for mut entry in self.entries.iter_mut() {
            let address = entry.local_addr;
            if let Some(ipsec) = entry.ue_ipsec.as_mut() {
                let sets = std::mem::take(&mut ipsec.sa_sets);
                deletions.extend(
                    sets.keys()
                        .into_iter()
                        .map(|key| SaDeletion { address, key }),
                );
            }
        }
        self.queue_sa_deletions(deletions);
    }

    /// Wait for deletion tasks still running, until `deadline`. `false` when
    /// some were still running at it.
    pub(super) async fn await_sa_deletions_in_flight(
        &self,
        deadline: tokio::time::Instant,
    ) -> bool {
        while self.sa_deletions_in_flight.load(Ordering::Acquire) > 0 {
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        true
    }

    /// Record the SPIs of the XFRM states the kernel held when the loop
    /// started, states a previous process left among them: no offer uses one
    /// (TS 33.203 clause 7.1, "The UE shall select the SPIs uniquely, and
    /// different from any SPIs that might be used in any existing SAs").
    pub fn note_kernel_spis(&self, spis: impl IntoIterator<Item = u32>) {
        let _ = self.kernel_spis_at_start.set(spis.into_iter().collect());
    }

    /// A fresh SPI pair for an offer, different from every SPI in `avoid`,
    /// from the kernel's states at start, and from those a live pair of the
    /// IPsec manager owns (TS 33.203 clause 7.1).
    fn allocate_unique_ue_spi_pair(&self, avoid: &HashSet<u32>) -> (u32, u32) {
        let at_start = self.kernel_spis_at_start.get();
        let taken = |spi: u32| {
            avoid.contains(&spi)
                || at_start.is_some_and(|spis| spis.contains(&spi))
                || self.ipsec.get().is_some_and(|ipsec| ipsec.owns_spi(spi))
        };
        let mut pair = self.allocate_ue_spi_pair();
        for _ in 0..1024 {
            if !taken(pair.0) && !taken(pair.1) {
                return pair;
            }
            pair = self.allocate_ue_spi_pair();
        }
        warn!(
            spi_uc = pair.0,
            "IPsec UE: no SPI pair clear of the existing SAs found; offering one anyway"
        );
        pair
    }

    /// Every SPI of the SA sets `ipsec` holds on `ue_addr`, both ends'.
    fn held_spis(&self, ue_addr: IpAddr, ipsec: &UeIpsec) -> HashSet<u32> {
        let mut spis = HashSet::new();
        for key in ipsec.sa_sets.keys() {
            spis.extend([key.spi_uc, key.spi_us]);
            if let Some(pair) = self
                .ipsec
                .get()
                .and_then(|manager| manager.get_sa(&ue_addr, key.ue_port_c))
            {
                spis.extend([pair.spi_pc, pair.spi_ps]);
            }
        }
        spis
    }

    /// Queue SA pairs for deletion.
    pub(super) fn queue_sa_deletions(&self, deletions: impl IntoIterator<Item = SaDeletion>) {
        let mut pending = self
            .pending_sa_deletions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        pending.extend(deletions);
    }

    /// Take the queued SA deletions, leaving none.
    pub fn take_pending_sa_deletions(&self) -> Vec<SaDeletion> {
        let mut pending = self
            .pending_sa_deletions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::mem::take(&mut *pending)
    }

    /// Whether the kernel still holds the SA set `key` on `ue_addr`. Assumed so
    /// before the loop installed the kernel.
    fn sa_installed(&self, ue_addr: IpAddr, key: UeSaKey) -> bool {
        self.ipsec.get().is_none_or(|ipsec| {
            ipsec
                .get_sa(&ue_addr, key.ue_port_c)
                .is_some_and(|sa| sa.spi_uc == key.spi_uc && sa.spi_us == key.spi_us)
        })
    }

    /// Point the offer at a client port no held set uses (TS 33.203 7.1, rule
    /// 6; 7.4.0) and give it fresh SPIs, different from those of every set
    /// held (rule: SPIs unique among the existing SAs, inbound and outbound).
    ///
    /// `replacing_offer`: the offer answers a challenge to the previous one,
    /// whose port the P-CSCF set up SAs for at that 401 and deletes only once
    /// this REGISTER arrives (TS 33.203 7.3.1.2, 7.3.1.3), so it takes another
    /// port when one is free ("new values for ... port_uc", TS 24.229
    /// 5.1.1.5.3).
    fn renew_offer(&self, ue_addr: IpAddr, ipsec: &mut UeIpsec, replacing_offer: bool) {
        let held: Vec<u16> = ipsec
            .sa_sets
            .established
            .as_ref()
            .map(|set| set.key.ue_port_c)
            .into_iter()
            .chain(ipsec.sa_sets.retiring.map(|key| key.ue_port_c))
            .collect();
        let previous = replacing_offer.then_some(ipsec.ue_port_c);
        let free = |port: &u16| !held.contains(port);
        if let Some(port) = ipsec
            .client_ports
            .iter()
            .copied()
            .find(|port| free(port) && Some(*port) != previous)
            .or_else(|| ipsec.client_ports.iter().copied().find(free))
        {
            ipsec.ue_port_c = port;
        }
        let held_spis = self.held_spis(ue_addr, ipsec);
        let (spi_uc, spi_us) = self.allocate_unique_ue_spi_pair(&held_spis);
        ipsec.spi_uc = spi_uc;
        ipsec.spi_us = spi_us;
    }

    /// Start an unprotected REGISTER for `entry`: the sets of an earlier
    /// re-registration and of an incomplete authentication go (TS 33.203
    /// 7.4.1a), and the offer gets a free client port and fresh SPIs.
    pub(super) fn begin_unprotected_offer(
        &self,
        entry: &mut RegistrantEntry,
        defaults: EgressDefaults<'_>,
        replacing_offer: bool,
    ) {
        let address = entry.local_addr;
        let ue_addr = address.unwrap_or(defaults.ue_ip);
        let Some(ipsec) = entry.ue_ipsec.as_mut() else {
            return;
        };
        let stale: Vec<UeSaKey> = ipsec
            .sa_sets
            .retiring
            .take()
            .into_iter()
            .chain(ipsec.sa_sets.temporary.take())
            .collect();
        self.queue_sa_deletions(stale.into_iter().map(|key| SaDeletion { address, key }));
        ipsec.sa_sets.exchange = UeExchange::Unprotected;
        ipsec.sa_sets.pending_authorization = None;
        self.renew_offer(ue_addr, ipsec, replacing_offer);
    }

    /// The established set `entry` can send a protected REGISTER over: usable,
    /// and still in the kernel. A set the kernel lost (it expired) is
    /// forgotten, so the REGISTER goes unprotected.
    fn protected_set(
        &self,
        entry: &mut RegistrantEntry,
        defaults: EgressDefaults<'_>,
    ) -> Option<EstablishedSaSet> {
        let ue_addr = entry.local_addr.unwrap_or(defaults.ue_ip);
        let ipsec = entry.ue_ipsec.as_mut()?;
        let set = ipsec.sa_sets.usable()?.clone();
        if self.sa_installed(ue_addr, set.key) {
            return Some(set);
        }
        warn!(
            aor = %entry.aor,
            ue_port_c = set.key.ue_port_c,
            "IPsec UE: the established SA set is gone, re-registering unprotected"
        );
        ipsec.sa_sets.established = None;
        None
    }

    /// Build a REGISTER over the established SA set, when the entry has one it
    /// can use; `None` leaves the caller to build an unprotected one.
    ///
    /// From the set's protected client port to the P-CSCF's protected server
    /// port, the Via and Contact naming the protected server port (TS 24.229
    /// 5.1.1.4.2 b, c), the Authorization of the last authentication repeated
    /// (a), new SA parameters in Security-Client (d), the set's Security-Server
    /// mirrored in Security-Verify (e). Same Call-ID, next CSeq. A
    /// de-REGISTER (`expires` 0) takes the same form (5.1.1.6.2).
    pub(super) fn build_protected_register(
        &self,
        entry: &mut RegistrantEntry,
        defaults: EgressDefaults<'_>,
        expires: u32,
    ) -> Option<Option<BuiltRegister>> {
        let set = self.protected_set(entry, defaults)?;
        let authorization = set.authorization.clone();
        Some(self.register_over_set(entry, defaults, &set, expires, authorization, false))
    }

    /// Build the REGISTER that tells the network its challenge was invalid
    /// (TS 24.229 clause 5.1.1.5.3: an "auts" for an SQN out of range, an empty
    /// response for a bad MAC), carrying `authorization`. It goes "using an
    /// existing set of security associations, if available", with a new
    /// Security-Client ("new values for spi_uc, spi_us and port_uc"), and the
    /// UE does "not create a temporary set of security associations" (TS
    /// 33.203 clauses 7.3.1.2, 7.3.1.3: it "may pass through an already
    /// established SA"). Without a usable set it goes unprotected, like the
    /// initial REGISTER.
    pub(super) fn build_challenge_rejection(
        &self,
        entry: &mut RegistrantEntry,
        defaults: EgressDefaults<'_>,
        expires: u32,
        authorization: String,
    ) -> Option<BuiltRegister> {
        match self.protected_set(entry, defaults) {
            Some(set) => {
                self.register_over_set(entry, defaults, &set, expires, authorization, true)
            }
            None => self.build_unprotected_register(entry, defaults, expires, Some(authorization)),
        }
    }

    /// A REGISTER over `set` carrying `authorization`; see
    /// [`build_protected_register`](Self::build_protected_register).
    fn register_over_set(
        &self,
        entry: &mut RegistrantEntry,
        defaults: EgressDefaults<'_>,
        set: &EstablishedSaSet,
        expires: u32,
        authorization: String,
        challenge_rejected: bool,
    ) -> Option<BuiltRegister> {
        let ue_addr = entry.local_addr.unwrap_or(defaults.ue_ip);
        let address = entry.local_addr;
        let ipsec = entry.ue_ipsec.as_mut()?;
        let ue_port_s = ipsec.ue_port_s;
        // An authentication that never concluded leaves its temporary set.
        if let Some(key) = ipsec.sa_sets.temporary.take() {
            self.queue_sa_deletions([SaDeletion { address, key }]);
        }
        ipsec.sa_sets.pending_authorization = None;
        self.renew_offer(ue_addr, ipsec, challenge_rejected);
        let security_client = build_security_client(&ipsec.offer());
        if expires > 0 {
            ipsec.sa_sets.exchange = UeExchange::Protected;
        }

        let sent_by = SocketAddr::new(ue_addr, ue_port_s);
        let egress = messages::EntryEgress::of(entry, defaults);
        let cseq = entry.next_cseq();
        let branch = format!("z9hG4bK-reg-{}", uuid::Uuid::new_v4());
        // The binding is the protected server port, where the P-CSCF sends
        // the requests for this UE over the set (TS 24.229 5.1.1.4.2 b,
        // 5.1.1.6.2 b; TS 33.203 7.1).
        let contact = entry.contact_uri.clone().unwrap_or_else(|| {
            default_contact_uri(&entry.credentials.username, sent_by, entry.transport)
        });
        let mut builder = SipMessageBuilder::new()
            .request(
                Method::Register,
                registrar_request_uri(&entry.registrar_uri),
            )
            .via(format!(
                "SIP/2.0/{} {sent_by};branch={branch};rport",
                entry.transport
            ))
            .to(format!("<{}>", entry.aor))
            .from(format!("<{}>;tag=reg-{}", entry.aor, cseq))
            .call_id(entry.call_id.clone())
            .cseq(format!("{cseq} REGISTER"))
            .header(
                "Contact",
                build_contact_header(&contact, entry.ims_contact.as_ref()),
            )
            .header("Expires", expires.to_string())
            .header("Authorization", authorization)
            .header("Security-Client", security_client)
            .header("Security-Verify", set.security_server.clone())
            .header("Require", "sec-agree".to_string())
            .header("Proxy-Require", "sec-agree".to_string())
            .header("Supported", "path, sec-agree".to_string())
            .header("Allow", IMS_ALLOW_METHODS.to_string())
            .max_forwards(70)
            .content_length(0);
        if let Some(ref user_agent) = self.identity.load().user_agent {
            builder = builder.header("User-Agent", user_agent.clone());
        }
        if expires > 0 {
            entry.state = RegistrantState::Registering;
            entry.in_flight_branch = Some(branch.clone());
        }
        match builder.build() {
            Ok(message) => Some(BuiltRegister {
                message,
                branch,
                destination: SocketAddr::new(entry.destination.ip(), set.pcscf_port_s),
                transport: entry.transport,
                source_local_addr: Some(SocketAddr::new(ue_addr, set.key.ue_port_c)),
                sent_by,
                own_address: egress.own_address,
                protected: true,
                challenge_rejected,
            }),
            Err(error) => {
                warn!(aor = %entry.aor, %error, "failed to build protected REGISTER");
                None
            }
        }
    }

    /// Count an invalid challenge (TS 24.229 clause 5.1.1.5.3) against
    /// `entry`; `false` once it is past the two consecutive ones a UE answers
    /// (clause 5.1.1.5.12), which ends the attempt.
    pub(super) fn answer_invalid_challenge(entry: &mut RegistrantEntry) -> bool {
        entry.invalid_challenges += 1;
        if entry.invalid_challenges > MAX_INVALID_CHALLENGES {
            warn!(
                aor = %entry.aor,
                consecutive = entry.invalid_challenges,
                "AKA: a third consecutive invalid challenge goes unanswered (TS 24.229 5.1.1.5.12)"
            );
            entry.invalid_challenges = 0;
            return false;
        }
        true
    }

    /// The exchange `aor` has in flight; `None` for an entry without IPsec.
    pub fn ipsec_exchange(&self, aor: &str) -> Option<UeExchange> {
        self.entries
            .get(aor)
            .and_then(|entry| entry.ue_ipsec.as_ref().map(|ipsec| ipsec.sa_sets.exchange))
    }

    /// Record that the authenticated REGISTER answering a 401 is about to go
    /// over the temporary set the handshake installs, carrying
    /// `authorization`.
    ///
    /// A 401 to a protected REGISTER arrived over the established set, a
    /// message over the newer set, so a retiring one goes now (TS 33.203
    /// 7.4.1a). A temporary set on another port, from an authentication that
    /// never concluded, goes too; one on the same port is replaced by the
    /// install. Returns the temporary set's key.
    pub fn begin_authentication(&self, aor: &str, authorization: &str) -> Option<UeSaKey> {
        let mut entry = self.entries.get_mut(aor)?;
        let address = entry.local_addr;
        let ipsec = entry.ue_ipsec.as_mut()?;
        let key = offered_key(ipsec);
        let sets = &mut ipsec.sa_sets;
        let started_protected = match sets.exchange {
            UeExchange::Protected => true,
            UeExchange::Authenticating { started_protected } => started_protected,
            UeExchange::Unprotected | UeExchange::Idle => false,
        };
        let mut stale = Vec::new();
        if started_protected {
            stale.extend(sets.retiring.take());
        }
        if let Some(previous) = sets.temporary.take() {
            if previous.ue_port_c != key.ue_port_c {
                stale.push(previous);
            }
        }
        sets.temporary = Some(key);
        sets.exchange = UeExchange::Authenticating { started_protected };
        sets.pending_authorization = Some(authorization.to_string());
        drop(entry);
        self.queue_sa_deletions(stale.into_iter().map(|key| SaDeletion { address, key }));
        Some(key)
    }

    /// Apply a 200 to the exchange in flight, returning the established set
    /// to extend, if any.
    ///
    /// - To the authenticated REGISTER: the temporary set becomes the
    ///   established one. When the authentication started protected, the old
    ///   set retires, kept for the P-CSCF (TS 33.203 7.4.1a); otherwise this
    ///   was an initial authentication and every older set goes (TS 24.229
    ///   table 5.2.2-1).
    /// - To a protected REGISTER: it arrived over the established set, so a
    ///   retiring one goes (TS 33.203 7.4.1a).
    pub fn conclude_ipsec_exchange(&self, aor: &str) -> Option<ConcludedSaSets> {
        let mut entry = self.entries.get_mut(aor)?;
        let address = entry.local_addr;
        let ipsec = entry.ue_ipsec.as_mut()?;
        let pcscf_port_s = ipsec.pcscf_port_s;
        let security_server = ipsec.security_server.clone();
        let sets = &mut ipsec.sa_sets;
        let exchange = std::mem::take(&mut sets.exchange);
        let mut stale = Vec::new();
        let concluded = match exchange {
            UeExchange::Authenticating { started_protected } => {
                let (Some(key), Some(authorization), Some(security_server)) = (
                    sets.temporary,
                    sets.pending_authorization.take(),
                    security_server,
                ) else {
                    // Nothing to conclude: the temporary set, if any, goes.
                    stale.extend(sets.temporary.take());
                    drop(entry);
                    self.queue_sa_deletions(
                        stale.into_iter().map(|key| SaDeletion { address, key }),
                    );
                    return None;
                };
                sets.temporary = None;
                let previous = sets.established.take().map(|set| set.key);
                if started_protected {
                    stale.extend(std::mem::replace(&mut sets.retiring, previous));
                } else {
                    stale.extend(previous);
                    stale.extend(sets.retiring.take());
                }
                sets.established = Some(EstablishedSaSet {
                    key,
                    pcscf_port_s,
                    security_server,
                    authorization,
                    usable: true,
                });
                Some(ConcludedSaSets {
                    established: key,
                    previous: if started_protected { previous } else { None },
                    keeps_own_lifetime: false,
                })
            }
            UeExchange::Protected => {
                stale.extend(sets.retiring.take());
                sets.established.as_ref().map(|set| ConcludedSaSets {
                    established: set.key,
                    previous: None,
                    keeps_own_lifetime: true,
                })
            }
            UeExchange::Unprotected | UeExchange::Idle => None,
        };
        drop(entry);
        self.queue_sa_deletions(stale.into_iter().map(|key| SaDeletion { address, key }));
        concluded
    }

    /// Give up the exchange in flight after a failure or a timeout: its
    /// temporary set goes, and after a failed re-registration the established
    /// set may no longer be used, so the next REGISTER goes unprotected (TS
    /// 24.229 5.1.1.4.1, 5.1.1.5.1). The established set itself stays until
    /// that registration concludes or it expires.
    pub(super) fn abandon_ipsec_exchange(&self, entry: &mut RegistrantEntry) {
        let address = entry.local_addr;
        let Some(ipsec) = entry.ue_ipsec.as_mut() else {
            return;
        };
        let sets = &mut ipsec.sa_sets;
        let exchange = std::mem::take(&mut sets.exchange);
        if matches!(
            exchange,
            UeExchange::Protected
                | UeExchange::Authenticating {
                    started_protected: true
                }
        ) {
            if let Some(set) = sets.established.as_mut() {
                set.usable = false;
            }
        }
        sets.pending_authorization = None;
        if let Some(key) = sets.temporary.take() {
            self.queue_sa_deletions([SaDeletion { address, key }]);
        }
    }

    /// Delete the SA sets of `entry`, which is going: once its protected
    /// de-REGISTER (`deregistration`) is answered or times out, else now (TS
    /// 24.229 5.1.1.6.1; TS 33.203 7.4.1a: all of them once every IMPU is
    /// de-registered).
    pub(super) fn retire_sa_sets(
        &self,
        entry: &RegistrantEntry,
        deregistration: Option<&BuiltRegister>,
    ) {
        let Some(ipsec) = entry.ue_ipsec.as_ref() else {
            return;
        };
        let address = entry.local_addr;
        let deletions: Vec<SaDeletion> = ipsec
            .sa_sets
            .keys()
            .into_iter()
            .map(|key| SaDeletion { address, key })
            .collect();
        if deletions.is_empty() {
            return;
        }
        if deregistration.is_some_and(|built| built.protected) {
            let mut teardowns = self
                .teardowns
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            teardowns.push(Teardown {
                call_id: entry.call_id.clone(),
                deletions,
                deadline: Instant::now() + TEARDOWN_WAIT,
            });
        } else {
            self.queue_sa_deletions(deletions);
        }
    }

    /// The de-REGISTER with Call-ID `call_id` of a removed entry was answered:
    /// queue its SA sets for deletion. `false` when no removed entry waited on
    /// that Call-ID.
    pub fn finish_teardown(&self, call_id: &str) -> bool {
        let finished: Vec<Teardown> = {
            let mut teardowns = self
                .teardowns
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let (finished, waiting) = std::mem::take(&mut *teardowns)
                .into_iter()
                .partition(|teardown| teardown.call_id == call_id);
            *teardowns = waiting;
            finished
        };
        let found = !finished.is_empty();
        self.queue_sa_deletions(finished.into_iter().flat_map(|teardown| teardown.deletions));
        found
    }

    /// Queue the SA sets of removed entries whose de-REGISTER went unanswered
    /// past its deadline.
    pub fn expire_teardowns(&self, now: Instant) {
        let expired: Vec<Teardown> = {
            let mut teardowns = self
                .teardowns
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let (expired, waiting) = std::mem::take(&mut *teardowns)
                .into_iter()
                .partition(|teardown| teardown.deadline <= now);
            *teardowns = waiting;
            expired
        };
        self.queue_sa_deletions(expired.into_iter().flat_map(|teardown| teardown.deletions));
    }

    /// The protected client sources, on an address of their own, of the sets
    /// of removed entries still waiting for their de-REGISTER's answer: a TCP
    /// UE's connection from there is where that answer comes back.
    pub(super) fn teardown_client_sources(&self) -> Vec<std::net::SocketAddr> {
        self.teardowns
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .flat_map(|teardown| teardown.deletions.iter())
            .filter_map(|deletion| {
                deletion
                    .address
                    .map(|ip| std::net::SocketAddr::new(ip, deletion.key.ue_port_c))
            })
            .collect()
    }

    /// How many UE SA sets the manager tracks: every live entry's, those of
    /// removed entries awaiting their de-REGISTER's answer, and those queued
    /// for deletion. The per-entity store the leak gate watches.
    pub fn tracked_sa_sets(&self) -> usize {
        let live: usize = self
            .entries
            .iter()
            .filter_map(|entry| {
                entry
                    .ue_ipsec
                    .as_ref()
                    .map(|ipsec| ipsec.sa_sets.keys().len())
            })
            .sum();
        let waiting: usize = self
            .teardowns
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .map(|teardown| teardown.deletions.len())
            .sum();
        let queued = self
            .pending_sa_deletions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len();
        live + waiting + queued
    }

    /// Make what can be made of the protected ports of `aor` that would not
    /// bind (`failed`, on its address), instead of leaving the entry stalled:
    ///
    /// - a rotation port no set holds moves to another free port (bounded,
    ///   [`MAX_PORT_REPLACEMENTS`]), which the next socket pass binds;
    /// - the established set's client port takes that set out of use, so the
    ///   next REGISTER goes unprotected and sets up a new one on a port that
    ///   binds (TS 33.203 7.4.0: "the UE may send unprotected REGISTER
    ///   messages at any time");
    /// - a retiring or temporary set's port changes nothing: neither sends.
    ///
    /// It is blocked (sits the tick out) only when its plain or protected
    /// server port is unbound, which nothing replaces, or no client port is
    /// left to offer. Each move and each set taken out of use is logged and
    /// counted (`siphon_ipsec_ue_port_bind_failures_total`).
    pub fn degrade_unbindable_ports(
        &self,
        aor: &str,
        failed: &[u16],
        plain_port: u16,
    ) -> PortDegradation {
        let taken = self.ports_taken_beside(aor);
        let Some(mut entry) = self.entries.get_mut(aor) else {
            return PortDegradation::default();
        };
        let own_address = entry.local_addr.is_some();
        let aor = entry.aor.clone();
        let Some(ipsec) = entry.ue_ipsec.as_mut() else {
            return PortDegradation {
                moved: false,
                blocked: !failed.is_empty(),
            };
        };
        let mut outcome = PortDegradation {
            moved: false,
            blocked: failed.contains(&ipsec.ue_port_s)
                || (own_address && failed.contains(&plain_port)),
        };
        let held: Vec<u16> = ipsec
            .sa_sets
            .keys()
            .iter()
            .map(|key| key.ue_port_c)
            .collect();
        for &port in failed {
            if !ipsec.client_ports.contains(&port) {
                continue;
            }
            if let Some(set) = ipsec
                .sa_sets
                .established
                .as_mut()
                .filter(|set| set.key.ue_port_c == port)
            {
                if set.usable {
                    set.usable = false;
                    crate::metrics::ipsec::record_ue_port_bind_failure();
                    warn!(
                        aor = %aor,
                        port,
                        "IPsec UE: the established set's client port will not bind; re-registering unprotected"
                    );
                }
                continue;
            }
            if held.contains(&port) || ipsec.port_replacements >= MAX_PORT_REPLACEMENTS {
                continue;
            }
            let Some(replacement) = replacement_port(ipsec, &taken, plain_port) else {
                continue;
            };
            if let Some(slot) = ipsec.client_ports.iter_mut().find(|slot| **slot == port) {
                *slot = replacement;
            }
            if ipsec.ue_port_c == port {
                ipsec.ue_port_c = replacement;
            }
            ipsec.port_replacements += 1;
            outcome.moved = true;
            crate::metrics::ipsec::record_ue_port_bind_failure();
            warn!(
                aor = %aor,
                port,
                replacement,
                "IPsec UE: a protected client port will not bind; rotating through another"
            );
        }
        let offerable = ipsec
            .client_ports
            .iter()
            .any(|port| !failed.contains(port) && !held.contains(port));
        if !offerable && !outcome.moved {
            outcome.blocked = true;
            if !ipsec.ports_exhausted {
                ipsec.ports_exhausted = true;
                error!(
                    aor = %aor,
                    client_ports = ?ipsec.client_ports,
                    "IPsec UE: no protected client port left that binds; the registration waits until one does"
                );
            }
        } else {
            ipsec.ports_exhausted = false;
        }
        outcome
    }

    /// The protected ports every other entry on `aor`'s address holds or may
    /// offer, which a moved port must avoid.
    fn ports_taken_beside(&self, aor: &str) -> HashSet<u16> {
        let Some(address) = self.entries.get(aor).map(|entry| entry.local_addr) else {
            return HashSet::new();
        };
        self.entries
            .iter()
            .filter(|other| other.aor != aor && other.local_addr == address)
            .flat_map(|other| Self::protected_ports(&other))
            .collect()
    }

    /// The established SA set's client and P-CSCF server ports, for the MO
    /// flow over it; `None` without one.
    pub(super) fn established_ports(entry: &RegistrantEntry) -> Option<(u16, u16)> {
        entry
            .ue_ipsec
            .as_ref()
            .and_then(|ipsec| ipsec.sa_sets.established.as_ref())
            .map(|set| (set.key.ue_port_c, set.pcscf_port_s))
    }

    /// Every protected port `entry` holds or may offer: its three client ports
    /// and its server port.
    pub(super) fn protected_ports(entry: &RegistrantEntry) -> Vec<u16> {
        entry
            .ue_ipsec
            .as_ref()
            .map(|ipsec| {
                let mut ports = ipsec.client_ports.to_vec();
                ports.push(ipsec.ue_port_s);
                ports
            })
            .unwrap_or_default()
    }
}

/// A free port for a client port that would not bind: above every port of
/// the entry's, else below, never a standard SIP port (TS 33.203 7.1), the
/// plain port, one of the entry's own, or one of `taken`.
fn replacement_port(ipsec: &UeIpsec, taken: &HashSet<u16>, plain_port: u16) -> Option<u16> {
    let own: HashSet<u16> = ipsec
        .client_ports
        .iter()
        .copied()
        .chain([ipsec.ue_port_s])
        .collect();
    let free = |port: &u16| {
        !matches!(*port, 0 | 5060 | 5061)
            && *port != plain_port
            && !own.contains(port)
            && !taken.contains(port)
    };
    let highest = own.iter().copied().max().unwrap_or(ipsec.ue_port_s);
    let lowest = own.iter().copied().min().unwrap_or(ipsec.ue_port_s);
    (highest..=u16::MAX)
        .find(free)
        .or_else(|| (1..lowest).rev().find(free))
}

#[cfg(test)]
#[path = "protected_tests.rs"]
mod tests;
