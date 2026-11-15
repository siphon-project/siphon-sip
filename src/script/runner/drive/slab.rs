//! The slab a driver thread keeps its coroutines in.

/// A slab index and the generation of the slot when the coroutine took it,
/// packed so that it fits an atomic and is never 0.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(in crate::script::runner) struct DriveKey(pub(in crate::script::runner) u64);

impl DriveKey {
    fn new(index: usize, generation: u32) -> Self {
        Self((u64::from(generation) << 32) | index as u64)
    }

    fn index(self) -> usize {
        (self.0 & u64::from(u32::MAX)) as usize
    }

    fn generation(self) -> u32 {
        (self.0 >> 32) as u32
    }
}

struct Slot<T> {
    generation: u32,
    entry: Option<T>,
}

/// Slots reused under a fresh generation, so that a key held past its
/// coroutine's end never reaches the coroutine that took the slot next.
pub(super) struct Slab<T> {
    slots: Vec<Slot<T>>,
    free: Vec<usize>,
}

impl<T> Default for Slab<T> {
    fn default() -> Self {
        Self {
            slots: Vec::new(),
            free: Vec::new(),
        }
    }
}

impl<T> Slab<T> {
    pub(super) fn insert(&mut self, entry: T) -> DriveKey {
        match self.free.pop() {
            Some(index) => {
                let slot = &mut self.slots[index];
                slot.entry = Some(entry);
                DriveKey::new(index, slot.generation)
            }
            None => {
                self.slots.push(Slot {
                    generation: 1,
                    entry: Some(entry),
                });
                DriveKey::new(self.slots.len() - 1, 1)
            }
        }
    }

    pub(super) fn get_mut(&mut self, key: DriveKey) -> Option<&mut T> {
        let slot = self.slots.get_mut(key.index())?;
        if slot.generation != key.generation() {
            return None;
        }
        slot.entry.as_mut()
    }

    pub(super) fn remove(&mut self, key: DriveKey) -> Option<T> {
        let slot = self.slots.get_mut(key.index())?;
        if slot.generation != key.generation() {
            return None;
        }
        let entry = slot.entry.take()?;
        // Never 0, so a key is never 0 either.
        slot.generation = slot.generation.checked_add(1).unwrap_or(1);
        self.free.push(key.index());
        Some(entry)
    }

    pub(super) fn drain(&mut self) -> Vec<T> {
        self.free.clear();
        std::mem::take(&mut self.slots)
            .into_iter()
            .filter_map(|slot| slot.entry)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_packs_its_index_and_generation_and_is_never_zero() {
        let key = DriveKey::new(7, 3);
        assert_eq!((key.index(), key.generation()), (7, 3));
        assert_ne!(DriveKey::new(0, 1).0, 0);
        let wide = DriveKey::new(u32::MAX as usize, u32::MAX);
        assert_eq!(
            (wide.index(), wide.generation()),
            (u32::MAX as usize, u32::MAX)
        );
    }

    #[test]
    fn a_slab_hands_out_and_takes_back_entries() {
        let mut slab = Slab::default();
        let first = slab.insert("first");
        let second = slab.insert("second");
        assert_ne!(first, second);
        assert_eq!(slab.get_mut(first).copied(), Some("first"));
        assert_eq!(slab.remove(first), Some("first"));
        assert_eq!(slab.remove(first), None, "removed once");
        assert_eq!(slab.get_mut(first), None);
        assert_eq!(slab.get_mut(second).copied(), Some("second"));
    }

    /// The key of a coroutine that has finished must not reach whichever
    /// coroutine takes its slot next: a late wake or cancel would otherwise
    /// step or cancel a stranger.
    #[test]
    fn a_stale_key_does_not_reach_the_slot_s_next_entry() {
        let mut slab = Slab::default();
        let old = slab.insert(1);
        assert_eq!(slab.remove(old), Some(1));
        let new = slab.insert(2);
        assert_eq!(new.index(), old.index(), "the slot is reused");
        assert_ne!(new, old);
        assert_eq!(slab.get_mut(old), None);
        assert_eq!(slab.remove(old), None);
        assert_eq!(slab.get_mut(new).copied(), Some(2));
    }

    #[test]
    fn a_generation_wraps_past_zero() {
        let mut slab = Slab::default();
        let key = slab.insert(0u8);
        slab.slots[key.index()].generation = u32::MAX;
        let last = DriveKey::new(key.index(), u32::MAX);
        assert_eq!(slab.remove(last), Some(0));
        let next = slab.insert(1);
        assert_eq!(next.generation(), 1);
        assert_ne!(next.0, 0);
    }

    #[test]
    fn draining_a_slab_returns_every_live_entry() {
        let mut slab = Slab::default();
        let gone = slab.insert(1);
        slab.insert(2);
        slab.insert(3);
        slab.remove(gone);
        let mut left = slab.drain();
        left.sort_unstable();
        assert_eq!(left, vec![2, 3]);
        assert!(slab.drain().is_empty());
    }
}
