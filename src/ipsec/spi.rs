//! SPI bookkeeping for the P-CSCF's own security associations.
//!
//! 3GPP TS 33.203 §7.1 has the P-CSCF choose `spi_pc` and `spi_ps` so that
//! they are unique among the SAs it holds: the kernel keys an inbound XFRM
//! state on `(destination, SPI, ESP)`, and every inbound state of a P-CSCF
//! has the P-CSCF's own address as its destination. Handing out an SPI that a
//! live SA still uses makes the next install overwrite that SA's inbound
//! state, which silently cuts the other UE off.
//!
//! [`SpiAllocator`] holds three things under one lock, so they never drift:
//!
//! * a bitmap of the configured partition, one bit per SPI, set while the SPI
//!   is reserved, owned by a live pair, or used by a kernel SA that survived a
//!   restart. Allocation is a next-fit scan from a rotating cursor that skips
//!   full 64-bit words, so it stays cheap with millions of SAs live, and a
//!   held-count makes "the partition is full" an O(1) answer;
//! * the owner of every local inbound SPI of a live pair (any SPI, in the
//!   partition or not), so an install can be refused rather than replace an SA
//!   another UE still holds;
//! * the partition SPIs adopted from surviving kernel SAs at startup, released
//!   once the kernel no longer has them.
//!
//! SPIs 0 to 255 are never handed out: RFC 4303 §2.1 reserves 1 to 255 and
//! RFC 4301 gives 0 a local meaning.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Mutex, MutexGuard, PoisonError};

use super::{IpsecError, IpsecManager, SaRole, SecurityAssociationPair};

/// Lowest SPI a partition may start at. RFC 4303 §2.1 reserves 1 to 255.
pub const MIN_SPI: u32 = 256;

/// Largest partition a single manager tracks: 2^28 SPIs, a 32 MiB bitmap.
/// Two SPIs per UE make that ~134 million concurrent UEs, well past what one
/// P-CSCF holds.
pub const MAX_SPI_RANGE_COUNT: u32 = 1 << 28;

/// Who owns an SPI: the UE address and protected client port of the pair,
/// the same identity as the manager's contact key.
pub(crate) type SpiOwner = (IpAddr, u16);

/// Partition bitmap, live owners and restart orphans, behind one lock.
pub(crate) struct SpiAllocator {
    table: Mutex<SpiTable>,
}

struct SpiTable {
    start: u32,
    count: u32,
    /// Offset into the partition the next scan starts from.
    cursor: u32,
    /// One bit per partition SPI. The padding bits past `count` in the last
    /// word are set, so the scan never returns them.
    words: Vec<u64>,
    /// Partition SPIs whose bit is set (padding excluded).
    held: u32,
    owners: HashMap<u32, SpiOwner>,
    orphans: HashSet<u32>,
}

impl SpiAllocator {
    /// A partition of `count` SPIs from `start`. The start is raised to
    /// [`MIN_SPI`], and the count kept between 2 and both
    /// [`MAX_SPI_RANGE_COUNT`] and what fits below `u32::MAX`. Configuration
    /// refuses values that need either, so this only guards library callers.
    pub(crate) fn new(start: u32, count: u32) -> Self {
        let start = start.max(MIN_SPI);
        let room = u64::from(u32::MAX) - u64::from(start) + 1;
        let count = u64::from(count)
            .clamp(2, u64::from(MAX_SPI_RANGE_COUNT))
            .min(room) as u32;
        let word_count = count.div_ceil(64) as usize;
        let mut words = vec![0u64; word_count];
        let used_in_last = count % 64;
        if used_in_last != 0 {
            if let Some(last) = words.last_mut() {
                *last = !((1u64 << used_in_last) - 1);
            }
        }
        Self {
            table: Mutex::new(SpiTable {
                start,
                count,
                cursor: 0,
                words,
                held: 0,
                owners: HashMap::new(),
                orphans: HashSet::new(),
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, SpiTable> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// First SPI of the partition.
    #[cfg(test)]
    pub(crate) fn start(&self) -> u32 {
        self.lock().start
    }

    /// Number of SPIs in the partition.
    pub(crate) fn capacity(&self) -> u32 {
        self.lock().count
    }

    /// Partition SPIs currently reserved, owned or adopted.
    pub(crate) fn in_use(&self) -> u32 {
        self.lock().held
    }

    /// Reserve two distinct free SPIs of the partition. Refuses with
    /// [`IpsecError::SpiExhausted`] when fewer than two are free, rather than
    /// reuse one a live SA holds.
    pub(crate) fn allocate_pair(&self) -> Result<(u32, u32), IpsecError> {
        let mut table = self.lock();
        if table.count - table.held < 2 {
            return Err(IpsecError::SpiExhausted {
                start: table.start,
                count: table.count,
            });
        }
        let cursor = table.cursor;
        let first = table.take_free_from(cursor);
        let after_first = (first + 1) % table.count;
        let second = table.take_free_from(after_first);
        table.cursor = (second + 1) % table.count;
        Ok((table.start + first, table.start + second))
    }

    /// Record `owner` as the owner of each of `spis`, holding the partition
    /// ones. Refuses with [`IpsecError::SpiInUse`], changing nothing, when one
    /// already belongs to another pair. Returns which of `spis` this call
    /// newly took, which is what a failed install gives back.
    pub(crate) fn claim(&self, owner: SpiOwner, spis: [u32; 2]) -> Result<[bool; 2], IpsecError> {
        let mut table = self.lock();
        if spis[0] == spis[1] {
            return Err(IpsecError::SpiInUse(spis[0]));
        }
        for spi in spis {
            if table.owners.get(&spi).is_some_and(|held| *held != owner) {
                return Err(IpsecError::SpiInUse(spi));
            }
        }
        let mut newly = [false; 2];
        for (index, spi) in spis.into_iter().enumerate() {
            if table.owners.insert(spi, owner).is_none() {
                newly[index] = true;
            }
            table.orphans.remove(&spi);
            table.hold(spi);
        }
        Ok(newly)
    }

    /// Give back each of `spis` that `owner` still owns. An SPI another pair
    /// owns is left alone, so a late or repeated release never frees it.
    pub(crate) fn release(&self, owner: SpiOwner, spis: impl IntoIterator<Item = u32>) {
        let mut table = self.lock();
        for spi in spis {
            if table.owners.get(&spi) == Some(&owner) {
                table.owners.remove(&spi);
                table.unhold(spi);
            }
        }
    }

    /// Give back a reservation no pair took ownership of: each of `spis` with
    /// no owner and not adopted from the kernel.
    pub(crate) fn release_unowned(&self, spis: impl IntoIterator<Item = u32>) {
        let mut table = self.lock();
        for spi in spis {
            if !table.owners.contains_key(&spi) && !table.orphans.contains(&spi) {
                table.unhold(spi);
            }
        }
    }

    /// Hold every partition SPI of `kernel_spis` that nothing holds yet, as an
    /// SA that outlived the previous process. Returns how many were adopted.
    pub(crate) fn adopt_orphans(&self, kernel_spis: impl IntoIterator<Item = u32>) -> usize {
        let mut table = self.lock();
        let mut adopted = 0;
        for spi in kernel_spis {
            if table.owners.contains_key(&spi) || !table.hold(spi) {
                continue;
            }
            table.orphans.insert(spi);
            adopted += 1;
        }
        adopted
    }

    /// Whether a live pair owns `spi`.
    pub(crate) fn is_owned(&self, spi: u32) -> bool {
        self.lock().owners.contains_key(&spi)
    }

    /// How many SPIs live pairs own.
    #[cfg(test)]
    pub(crate) fn owner_count(&self) -> usize {
        self.lock().owners.len()
    }

    /// Whether any adopted SPI is still waiting for the kernel to drop it.
    pub(crate) fn has_orphans(&self) -> bool {
        !self.lock().orphans.is_empty()
    }

    /// Release each adopted SPI that `still_in_kernel` no longer reports.
    /// Returns how many were released.
    pub(crate) fn release_departed_orphans(&self, still_in_kernel: impl Fn(u32) -> bool) -> usize {
        let mut table = self.lock();
        let departed: Vec<u32> = table
            .orphans
            .iter()
            .copied()
            .filter(|spi| !still_in_kernel(*spi))
            .collect();
        for spi in &departed {
            table.orphans.remove(spi);
            if !table.owners.contains_key(spi) {
                table.unhold(*spi);
            }
        }
        departed.len()
    }
}

impl SpiTable {
    fn offset(&self, spi: u32) -> Option<u32> {
        spi.checked_sub(self.start)
            .filter(|offset| *offset < self.count)
    }

    /// Set the bit of a partition SPI. False when it is outside the partition
    /// or already set.
    fn hold(&mut self, spi: u32) -> bool {
        let Some(offset) = self.offset(spi) else {
            return false;
        };
        let (word, bit) = ((offset / 64) as usize, offset % 64);
        if self.words[word] & (1 << bit) != 0 {
            return false;
        }
        self.words[word] |= 1 << bit;
        self.held += 1;
        true
    }

    fn unhold(&mut self, spi: u32) {
        let Some(offset) = self.offset(spi) else {
            return;
        };
        let (word, bit) = ((offset / 64) as usize, offset % 64);
        if self.words[word] & (1 << bit) != 0 {
            self.words[word] &= !(1 << bit);
            self.held -= 1;
        }
    }

    /// Set and return the first clear bit at or after `from`, wrapping. The
    /// caller has checked one is free.
    fn take_free_from(&mut self, from: u32) -> u32 {
        let word_count = self.words.len();
        let first_word = (from / 64) as usize;
        let below_from = (1u64 << (from % 64)) - 1;
        // One pass over every word, then the low bits of the first word that
        // the opening step skipped.
        for step in 0..=word_count {
            let word = (first_word + step) % word_count;
            let taken = match step {
                0 => self.words[word] | below_from,
                last if last == word_count => self.words[word] | !below_from,
                _ => self.words[word],
            };
            if taken != u64::MAX {
                let offset = word as u32 * 64 + (!taken).trailing_zeros();
                self.words[word] |= 1 << (offset % 64);
                self.held += 1;
                return offset;
            }
        }
        unreachable!("take_free_from runs only with a free SPI in the partition")
    }
}

impl SecurityAssociationPair {
    /// The SPIs of the two states whose destination is this end, which this
    /// end chose and the kernel keys on `(own address, SPI)`: `spi_ps` and
    /// `spi_pc` at the P-CSCF, `spi_uc` and `spi_us` at the UE.
    pub fn local_inbound_spis(&self) -> [u32; 2] {
        match self.role {
            SaRole::PCscf => [self.spi_ps, self.spi_pc],
            SaRole::Ue => [self.spi_uc, self.spi_us],
        }
    }

    /// The four states as the kernel keys them, `(destination, SPI)`.
    pub(crate) fn state_keys(&self) -> [(IpAddr, u32); 4] {
        [
            (self.pcscf_addr, self.spi_ps),
            (self.ue_addr, self.spi_uc),
            (self.ue_addr, self.spi_us),
            (self.pcscf_addr, self.spi_pc),
        ]
    }

    fn spi_owner(&self) -> SpiOwner {
        (self.ue_addr, self.ue_port_c)
    }
}

/// The SPI side of [`IpsecManager`]: allocation, the ownership an install
/// takes and a teardown gives back, and the SAs a restart left behind.
impl IpsecManager {
    /// Reserve the P-CSCF's two SPIs (`spi_pc`, `spi_ps`) for a new pair.
    ///
    /// Never returns an SPI a pair this manager holds still uses, one a
    /// reservation not yet installed holds, or one a kernel SA that outlived
    /// the previous process uses ([`adopt_surviving_kernel_sas`]), including
    /// after the scan wraps round the partition. `create_sa_pair` takes
    /// ownership of the reservation, and deleting the pair frees it. When the
    /// partition has fewer than two free SPIs this is
    /// [`IpsecError::SpiExhausted`], never a reused SPI.
    ///
    /// [`adopt_surviving_kernel_sas`]: Self::adopt_surviving_kernel_sas
    pub fn allocate_spi_pair(&self) -> Result<(u32, u32), IpsecError> {
        let allocated = self.spis.allocate_pair();
        if let Err(error) = &allocated {
            crate::metrics::ipsec::record_spi_allocation_failure();
            tracing::error!(%error, active = self.active_count(), "IPsec: no SPI pair to allocate");
        }
        allocated
    }

    /// SPIs of the partition in use (reserved, owned, or adopted from the
    /// kernel) and the partition size.
    pub fn spi_usage(&self) -> (u32, u32) {
        (self.spis.in_use(), self.spis.capacity())
    }

    /// Take ownership of the SPIs `sa` chose for this end, before any kernel
    /// op. Refused when another live pair owns one, and then the reservation
    /// the caller made for `sa` is handed back.
    pub(super) fn claim_local_spis(
        &self,
        sa: &SecurityAssociationPair,
    ) -> Result<[bool; 2], IpsecError> {
        let spis = sa.local_inbound_spis();
        self.spis.claim(sa.spi_owner(), spis).inspect_err(|error| {
            self.spis.release_unowned(spis);
            tracing::error!(ue = %sa.ue_addr, ue_port_c = sa.ue_port_c, %error, "IPsec: SA pair refused");
        })
    }

    /// Give back the SPIs a failed install newly claimed (`claimed` as
    /// [`claim_local_spis`](Self::claim_local_spis) returned it).
    pub(super) fn release_claimed_spis(&self, sa: &SecurityAssociationPair, claimed: [bool; 2]) {
        let spis = sa.local_inbound_spis();
        let newly = (0..2)
            .filter(|index| claimed[*index])
            .map(|index| spis[index]);
        self.spis.release(sa.spi_owner(), newly);
    }

    /// Give back the SPIs of a pair whose kernel states are gone.
    pub(super) fn release_pair_spis(&self, sa: &SecurityAssociationPair) {
        self.spis.release(sa.spi_owner(), sa.local_inbound_spis());
    }

    /// A pair re-created under the same UE address and port with other SPIs
    /// (a retransmitted REGISTER challenged again) leaves its old states, and
    /// the policies on a P-CSCF client port of its own, behind. Delete them
    /// now, by its own SPIs and selectors, then give back the SPIs the new
    /// pair no longer uses; in that order, so a later owner's state is never
    /// hit.
    pub(super) async fn retire_replaced_pair(
        &self,
        replaced: SecurityAssociationPair,
        new_states: [(IpAddr, u32); 4],
        new_spis: [u32; 2],
    ) {
        for (destination, spi) in replaced.state_keys() {
            if new_states.contains(&(destination, spi)) {
                continue;
            }
            let source = if destination == replaced.ue_addr {
                &replaced.pcscf_addr
            } else {
                &replaced.ue_addr
            };
            self.del_sa(source, &destination, spi).await.ok();
        }
        self.delete_policies_left_by(&replaced).await;
        let stale = replaced
            .local_inbound_spis()
            .into_iter()
            .filter(|spi| !new_spis.contains(spi));
        self.spis.release(replaced.spi_owner(), stale);
    }

    /// Hold every SPI of the partition that a kernel SA still uses at startup.
    ///
    /// Kernel SAs outlive a restart, and a UE whose registration survived it
    /// keeps using them. The previous process's pairs are unknown to this one,
    /// so without this an allocation could hand out one of their SPIs, and the
    /// install's collision clearing (see `create_sa_pair`) would delete the
    /// surviving state. They are held instead, not flushed, and released as the
    /// kernel reaps them on their own hard lifetime (checked each sweep).
    /// Returns how many were adopted; a failed kernel read is logged and adopts
    /// none.
    pub async fn adopt_surviving_kernel_sas(&self) -> usize {
        match self.kernel_spis().await {
            Ok(kernel_spis) => self.spis.adopt_orphans(kernel_spis),
            Err(error) => {
                tracing::warn!(
                    %error,
                    "IPsec: cannot read the kernel SAs a restart left behind; an SPI one of them uses may be reallocated"
                );
                0
            }
        }
    }

    /// The SPI of every XFRM state in the kernel now, for a caller choosing
    /// its own SPIs: the UE registrant, which must pick SPIs "different from
    /// any SPIs that might be used in any existing SAs" (3GPP TS 33.203 clause
    /// 7.1), states a previous process left behind included. Empty, and
    /// logged, when the kernel cannot be read.
    pub async fn kernel_spi_snapshot(&self) -> Vec<u32> {
        self.kernel_spis().await.unwrap_or_else(|error| {
            tracing::warn!(%error, "IPsec: cannot read the kernel SAs; an SPI one of them uses may be offered again");
            Vec::new()
        })
    }

    /// Whether a live pair of this manager owns `spi` as one of its local
    /// inbound SPIs.
    pub fn owns_spi(&self, spi: u32) -> bool {
        self.spis.is_owned(spi)
    }

    /// How many SPIs live pairs own: the SPI ownership map the leak gates
    /// watch.
    #[cfg(test)]
    pub(crate) fn test_spi_owner_count(&self) -> usize {
        self.spis.owner_count()
    }

    /// Release the SPIs adopted at startup whose kernel SA has since gone.
    /// One kernel dump per sweep, and only while any adopted SPI is left.
    pub(super) async fn release_departed_kernel_orphans(&self) {
        if !self.spis.has_orphans() {
            return;
        }
        match self.kernel_spis().await {
            Ok(kernel_spis) => {
                let present: HashSet<u32> = kernel_spis.into_iter().collect();
                let released = self
                    .spis
                    .release_departed_orphans(|spi| present.contains(&spi));
                if released > 0 {
                    tracing::debug!(
                        released,
                        "IPsec: SPIs of SAs left by a restart are free again"
                    );
                }
            }
            Err(error) => {
                tracing::warn!(%error, "IPsec: kernel SA dump failed; SPIs left by a restart stay held");
            }
        }
    }

    /// The SPI of every XFRM state in the kernel (netlink dump).
    async fn kernel_spis(&self) -> Result<Vec<u32>, IpsecError> {
        #[cfg(test)]
        if let Some(mock) = self.kernel_mock.as_ref() {
            let state = mock.lock().expect("mock kernel lock poisoned");
            return Ok(state
                .live
                .iter()
                .filter_map(|key| key.strip_prefix("sa:")?.rsplit_once(':'))
                .filter_map(|(_, spi)| spi.parse().ok())
                .collect());
        }
        #[cfg(target_os = "linux")]
        {
            self.xfrm()
                .dump_sa_use_times()
                .await
                .map(|use_times| use_times.into_keys().collect())
        }
        #[cfg(not(target_os = "linux"))]
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    fn owner(port: u16) -> SpiOwner {
        (IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)), port)
    }

    /// Fill a small partition, then keep allocating as the old counter would
    /// have wrapped: nothing a live owner holds comes back, the one SPI freed
    /// is what the next allocation reuses, and a full partition is an error.
    #[test]
    fn a_wrapped_allocation_never_returns_a_live_spi() {
        let allocator = SpiAllocator::new(10_000, 8);
        let mut live = Vec::new();
        for port in 0..4 {
            let (spi_pc, spi_ps) = allocator.allocate_pair().expect("room for four pairs");
            allocator
                .claim(owner(port), [spi_pc, spi_ps])
                .expect("fresh SPIs are free");
            live.push((port, spi_pc, spi_ps));
        }
        assert_eq!(allocator.in_use(), 8);
        assert!(matches!(
            allocator.allocate_pair(),
            Err(IpsecError::SpiExhausted {
                start: 10_000,
                count: 8
            })
        ));

        // The first UE leaves; its two SPIs are the only free ones.
        let (port, spi_pc, spi_ps) = live.remove(0);
        allocator.release(owner(port), [spi_pc, spi_ps]);
        let (next_pc, next_ps) = allocator.allocate_pair().expect("two SPIs are free again");
        let mut reused = [next_pc, next_ps];
        reused.sort_unstable();
        let mut freed = [spi_pc, spi_ps];
        freed.sort_unstable();
        assert_eq!(reused, freed, "the freed SPIs are what comes back");
        for (_, held_pc, held_ps) in &live {
            assert!(![next_pc, next_ps].contains(held_pc));
            assert!(![next_pc, next_ps].contains(held_ps));
        }
    }

    #[test]
    fn one_free_spi_is_not_a_pair() {
        let allocator = SpiAllocator::new(10_000, 3);
        allocator.allocate_pair().expect("the first pair fits");
        assert_eq!(allocator.in_use(), 2);
        assert!(allocator.allocate_pair().is_err());
        assert_eq!(allocator.in_use(), 2, "a refused allocation holds nothing");
    }

    #[test]
    fn allocation_skips_a_held_spi_past_the_cursor() {
        let allocator = SpiAllocator::new(10_000, 130);
        // Something else already owns the SPIs the cursor would reach next.
        allocator
            .claim(owner(1), [10_000, 10_001])
            .expect("unowned SPIs are claimable");
        let (first, second) = allocator.allocate_pair().expect("room");
        assert_eq!((first, second), (10_002, 10_003));
    }

    #[test]
    fn allocation_crosses_word_boundaries_and_wraps() {
        let allocator = SpiAllocator::new(10_000, 130);
        let mut seen = HashSet::new();
        for _ in 0..65 {
            let (first, second) = allocator.allocate_pair().expect("130 SPIs hold 65 pairs");
            assert!((10_000..10_130).contains(&first));
            assert!((10_000..10_130).contains(&second));
            assert!(
                seen.insert(first) && seen.insert(second),
                "never handed out twice"
            );
        }
        assert_eq!(seen.len(), 130);
        assert!(allocator.allocate_pair().is_err());
        allocator.release_unowned([10_064, 10_003]);
        let (first, second) = allocator.allocate_pair().expect("two were given back");
        let mut pair = [first, second];
        pair.sort_unstable();
        assert_eq!(pair, [10_003, 10_064]);
    }

    #[test]
    fn concurrent_allocations_are_all_distinct() {
        let allocator = Arc::new(SpiAllocator::new(10_000, 1 << 16));
        let workers: Vec<_> = (0..16)
            .map(|_| {
                let allocator = Arc::clone(&allocator);
                std::thread::spawn(move || {
                    (0..1_000)
                        .map(|_| allocator.allocate_pair().expect("room for every worker"))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let mut seen = HashSet::new();
        for worker in workers {
            for (first, second) in worker.join().expect("the worker ran") {
                assert!(seen.insert(first), "SPI {first} handed out twice");
                assert!(seen.insert(second), "SPI {second} handed out twice");
            }
        }
        assert_eq!(seen.len(), 32_000);
        assert_eq!(allocator.in_use(), 32_000);
    }

    #[test]
    fn a_claim_on_an_spi_another_pair_owns_changes_nothing() {
        let allocator = SpiAllocator::new(10_000, 16);
        allocator.claim(owner(1), [10_000, 10_001]).expect("free");
        assert!(matches!(
            allocator.claim(owner(2), [10_002, 10_001]),
            Err(IpsecError::SpiInUse(10_001))
        ));
        assert_eq!(allocator.in_use(), 2, "the refused claim held nothing");
        // The owner may claim its own SPIs again (a re-key keeps them).
        assert_eq!(
            allocator
                .claim(owner(1), [10_000, 10_001])
                .expect("own SPIs"),
            [false, false]
        );
    }

    #[test]
    fn a_release_by_anyone_but_the_owner_frees_nothing() {
        let allocator = SpiAllocator::new(10_000, 16);
        allocator.claim(owner(1), [10_000, 10_001]).expect("free");
        allocator.release(owner(2), [10_000, 10_001]);
        allocator.release_unowned([10_000, 10_001]);
        assert_eq!(allocator.in_use(), 2);
        allocator.release(owner(1), [10_000, 10_001]);
        assert_eq!(allocator.in_use(), 0);
    }

    #[test]
    fn spis_outside_the_partition_are_owned_but_not_counted() {
        let allocator = SpiAllocator::new(10_000, 16);
        allocator.claim(owner(1), [50_000, 50_001]).expect("free");
        assert_eq!(allocator.in_use(), 0);
        assert!(allocator.claim(owner(2), [50_001, 50_002]).is_err());
    }

    #[test]
    fn surviving_kernel_spis_are_never_handed_out_until_they_leave() {
        let allocator = SpiAllocator::new(10_000, 4);
        // Two inbound SAs of the previous process are still in the kernel,
        // plus SPIs outside this partition (another instance's).
        let adopted = allocator.adopt_orphans([10_000, 10_002, 20_000]);
        assert_eq!(adopted, 2);
        assert!(allocator.has_orphans());
        let (first, second) = allocator.allocate_pair().expect("two are free");
        let mut pair = [first, second];
        pair.sort_unstable();
        assert_eq!(pair, [10_001, 10_003]);
        assert!(allocator.allocate_pair().is_err());

        // A sweep finds 10_000 still installed and 10_002 gone.
        assert_eq!(allocator.release_departed_orphans(|spi| spi == 10_000), 1);
        assert!(allocator.has_orphans());
        let (first, second) = (allocator.allocate_pair(), allocator.in_use());
        assert!(first.is_err(), "only one SPI is free, not a pair");
        assert_eq!(second, 3);
        assert_eq!(allocator.release_departed_orphans(|_| false), 1);
        assert!(!allocator.has_orphans());
        assert_eq!(allocator.in_use(), 2);
    }

    #[test]
    fn a_claimed_orphan_stays_held_when_the_kernel_copy_leaves() {
        let allocator = SpiAllocator::new(10_000, 4);
        allocator.adopt_orphans([10_000]);
        allocator
            .claim(owner(1), [10_000, 10_001])
            .expect("an orphan has no owner");
        assert!(!allocator.has_orphans(), "a claimed SPI is no orphan");
        allocator.release_unowned([10_000]);
        assert_eq!(allocator.in_use(), 2);
    }

    #[test]
    fn construction_keeps_the_partition_valid() {
        let low = SpiAllocator::new(0, 8);
        assert_eq!(low.start(), MIN_SPI, "SPIs below 256 are reserved");
        let (first, _) = low.allocate_pair().expect("room");
        assert!(first >= MIN_SPI);

        let tiny = SpiAllocator::new(10_000, 0);
        assert_eq!(tiny.capacity(), 2);

        let top = SpiAllocator::new(u32::MAX - 3, 100);
        assert_eq!(top.capacity(), 4, "the partition stops at u32::MAX");
        let mut seen = HashSet::new();
        while let Ok((first, second)) = top.allocate_pair() {
            seen.insert(first);
            seen.insert(second);
        }
        assert_eq!(
            seen,
            HashSet::from([u32::MAX - 3, u32::MAX - 2, u32::MAX - 1, u32::MAX])
        );

        let huge = SpiAllocator::new(MIN_SPI, u32::MAX);
        assert_eq!(huge.capacity(), MAX_SPI_RANGE_COUNT);
    }
}
