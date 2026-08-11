//! Allocation-free reverse mapping from random WireGuard receiver indices to
//! session slots.
//!
//! The assigned receiver index lives with the slot state itself. This map only
//! provides the reverse wire-index-to-slot lookup needed for incoming packets.

#[cfg(not(feature = "alloc"))]
use core::hash::{BuildHasherDefault, Hasher};

#[cfg(not(feature = "alloc"))]
use heapless::index_map::{Entry, IndexMap};

use crate::{error::Error, session::SlotIdx};

/// Hasher for uniformly random WireGuard receiver indices.
///
/// Session indices are already sampled from a CSPRNG, so they do not need an
/// additional mixing step. `IndexMap` only requires a `u64` hash value; the
/// `u32` index can be widened directly without losing information.
#[cfg(not(feature = "alloc"))]
#[derive(Debug, Default)]
struct SessionIndexHasher(u64);

#[cfg(not(feature = "alloc"))]
impl Hasher for SessionIndexHasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        // `Hash for u32` calls `write_u32`, but keep the required byte-oriented
        // method deterministic as well.
        let mut value = 0u64;
        for (offset, byte) in bytes.iter().copied().take(8).enumerate() {
            value |= u64::from(byte) << (offset * 8);
        }
        self.0 = value;
    }

    #[inline]
    fn write_u32(&mut self, index: u32) {
        self.0 = u64::from(index);
    }
}

/// The reverse index table.
///
/// Inline and allocation-free by default; an ordered map on the heap under
/// `alloc`, which also lifts the power-of-two constraint `IndexMap` imposes
/// on `MAX_SESSIONS` (see [`crate::Core::new`]). Either way the table can
/// never hold more than `MAX_SESSIONS` entries:
/// [`SessionIndexMap::insert`] rejects out-of-range
/// slots and each slot owns at most one live receiver index.
#[cfg(not(feature = "alloc"))]
type SessionIndexTable<const MAX_SESSIONS: usize> =
    IndexMap<u32, SlotIdx, BuildHasherDefault<SessionIndexHasher>, MAX_SESSIONS>;

/// Fixed-capacity reverse session-index map.
#[derive(Debug)]
pub(crate) struct SessionIndexMap<const MAX_SESSIONS: usize> {
    #[cfg(not(feature = "alloc"))]
    by_index: SessionIndexTable<MAX_SESSIONS>,
    #[cfg(feature = "alloc")]
    by_index: hashbrown::HashMap<u32, SlotIdx>,
    #[cfg(feature = "alloc")]
    _capacity: core::marker::PhantomData<[(); MAX_SESSIONS]>,
}

impl<const MAX_SESSIONS: usize> SessionIndexMap<MAX_SESSIONS> {
    /// Receiver-index collisions are vanishingly unlikely with a healthy
    /// CSPRNG. Keep the random path bounded anyway so a broken implementation
    /// cannot wedge the device forever.
    const MAX_RANDOM_ATTEMPTS: usize = 32;

    pub(crate) fn new() -> Self {
        Self {
            #[cfg(not(feature = "alloc"))]
            by_index: SessionIndexTable::default(),
            #[cfg(feature = "alloc")]
            by_index: hashbrown::HashMap::new(),
            #[cfg(feature = "alloc")]
            _capacity: core::marker::PhantomData,
        }
    }

    /// Sample an index that is not currently active, without assigning it.
    ///
    /// Callers can complete all fallible cryptographic work first, then insert
    /// the candidate together with the slot state that stores it.
    pub(crate) fn random_unused<R>(&self, rng: &mut R) -> Result<u32, Error>
    where
        R: rand_core::RngCore + rand_core::CryptoRng,
    {
        for _ in 0..Self::MAX_RANDOM_ATTEMPTS {
            let index = rng.next_u32();
            if !self.by_index.contains_key(&index) {
                return Ok(index);
            }
        }

        Err(Error::SessionIndexGenerationFailed)
    }

    /// Assign a previously checked unique receiver index to `slot`.
    pub(crate) fn insert(&mut self, index: u32, slot: SlotIdx) -> Result<(), Error> {
        if slot as usize >= MAX_SESSIONS {
            return Err(Error::SessionIndexGenerationFailed);
        }
        #[cfg(feature = "alloc")]
        {
            match self.by_index.entry(index) {
                hashbrown::hash_map::Entry::Occupied(_) => Err(Error::SessionIndexGenerationFailed),
                hashbrown::hash_map::Entry::Vacant(entry) => {
                    entry.insert(slot);
                    Ok(())
                }
            }
        }
        #[cfg(not(feature = "alloc"))]
        {
            match self.by_index.entry(index) {
                Entry::Occupied(_) => Err(Error::SessionIndexGenerationFailed),
                Entry::Vacant(entry) => entry
                    .insert(slot)
                    .map(|_| ())
                    .map_err(|_| Error::SessionIndexGenerationFailed),
            }
        }
    }

    /// Replace `old` with a previously checked unused receiver index.
    ///
    /// The old mapping is restored if insertion unexpectedly fails, keeping
    /// the operation transactional even if an internal invariant is broken.
    pub(crate) fn replace(&mut self, old: u32, new: u32, slot: SlotIdx) -> Result<(), Error> {
        if slot as usize >= MAX_SESSIONS {
            return Err(Error::SessionIndexGenerationFailed);
        }
        if self.by_index.get(&old).copied() != Some(slot) {
            return Err(Error::InternalInvariant);
        }
        if old == new {
            return Ok(());
        }
        if self.by_index.contains_key(&new) {
            return Err(Error::SessionIndexGenerationFailed);
        }

        let removed = self.by_index.remove(&old);
        if removed != Some(slot) {
            return Err(Error::InternalInvariant);
        }
        if self.insert(new, slot).is_ok() {
            return Ok(());
        }

        if self.insert(old, slot).is_err() {
            return Err(Error::InternalInvariant);
        }
        Err(Error::SessionIndexGenerationFailed)
    }

    /// Resolve a wire receiver index to its owning slot.
    #[inline]
    pub(crate) fn slot_for(&self, index: u32) -> Option<SlotIdx> {
        self.by_index.get(&index).copied()
    }

    /// Remove `index`, which is expected to belong to `slot`.
    pub(crate) fn remove(&mut self, index: u32, slot: SlotIdx) -> Result<(), Error> {
        if self.by_index.get(&index).copied() != Some(slot) {
            return Err(Error::InternalInvariant);
        }
        match self.by_index.remove(&index) {
            Some(owner) if owner == slot => Ok(()),
            _ => Err(Error::InternalInvariant),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Capacity must be a power of two greater than one under the
    /// allocation-free backend, which `Core::new` enforces for `MAX_SESSIONS`.
    const MAX_SESSIONS: usize = 4;

    /// An RNG that always returns the same word. Sampling a receiver index is
    /// the one place the engine trusts the embedding's randomness, so the
    /// bounded-retry guard has to hold even when that trust is misplaced.
    struct StuckRng(u32);

    impl rand_core::RngCore for StuckRng {
        fn next_u32(&mut self) -> u32 {
            self.0
        }
        fn next_u64(&mut self) -> u64 {
            u64::from(self.0)
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            dest.fill(0);
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl rand_core::CryptoRng for StuckRng {}

    #[test]
    fn insertion_refuses_duplicates_and_out_of_range_slots() {
        let mut map = SessionIndexMap::<MAX_SESSIONS>::new();
        map.insert(7, 0).expect("insert");

        // Two slots claiming one wire index would make inbound packets
        // ambiguous, so the second loses rather than overwriting.
        assert_eq!(map.insert(7, 1), Err(Error::SessionIndexGenerationFailed));
        assert_eq!(map.slot_for(7), Some(0));

        // A slot handle outside the pool would index out of bounds later.
        assert_eq!(
            map.insert(8, MAX_SESSIONS as SlotIdx),
            Err(Error::SessionIndexGenerationFailed)
        );
        assert_eq!(map.slot_for(8), None);

        // The table holds exactly `MAX_SESSIONS` entries, one per slot.
        for slot in 1..MAX_SESSIONS as SlotIdx {
            map.insert(100 + slot, slot).expect("insert");
        }
        for slot in 0..MAX_SESSIONS as SlotIdx {
            let index = if slot == 0 { 7 } else { 100 + slot };
            assert_eq!(map.slot_for(index), Some(slot));
        }
    }

    #[test]
    fn replacement_is_transactional() {
        let mut map = SessionIndexMap::<MAX_SESSIONS>::new();
        map.insert(10, 0).expect("insert");
        map.insert(20, 1).expect("insert");

        // The happy path: a responder re-answering an initiation swaps its
        // slot onto a freshly sampled index.
        map.replace(10, 11, 0).expect("replace");
        assert_eq!(map.slot_for(10), None);
        assert_eq!(map.slot_for(11), Some(0));

        // Replacing an index that belongs to someone else, or to nobody, must
        // not disturb either mapping.
        assert_eq!(map.replace(20, 21, 0), Err(Error::InternalInvariant));
        assert_eq!(map.replace(99, 30, 0), Err(Error::InternalInvariant));
        assert_eq!(map.slot_for(20), Some(1));
        assert_eq!(map.slot_for(11), Some(0));

        // Colliding with a live index leaves the original mapping intact —
        // this is the rollback path, and losing it would strand a session
        // that is still addressable on the wire.
        assert_eq!(
            map.replace(11, 20, 0),
            Err(Error::SessionIndexGenerationFailed)
        );
        assert_eq!(map.slot_for(11), Some(0));
        assert_eq!(map.slot_for(20), Some(1));

        // A no-op replacement is allowed and changes nothing.
        map.replace(11, 11, 0).expect("self-replace");
        assert_eq!(map.slot_for(11), Some(0));

        assert_eq!(
            map.replace(11, 12, MAX_SESSIONS as SlotIdx),
            Err(Error::SessionIndexGenerationFailed)
        );
    }

    #[test]
    fn sampling_avoids_live_indices_and_gives_up_rather_than_becoming_predictable() {
        let mut map = SessionIndexMap::<MAX_SESSIONS>::new();
        let mut rng = <rand_chacha::ChaCha20Rng as rand_core::SeedableRng>::from_seed([3; 32]);

        // Sampling does not assign, so callers can finish their fallible
        // cryptographic work before committing the index.
        let candidate = map.random_unused(&mut rng).expect("sampled");
        assert_eq!(map.slot_for(candidate), None);
        map.insert(candidate, 0).expect("insert");

        // With a healthy CSPRNG, further draws avoid what is already live.
        for slot in 1..MAX_SESSIONS as SlotIdx {
            let next = map.random_unused(&mut rng).expect("sampled");
            assert_eq!(map.slot_for(next), None);
            map.insert(next, slot).expect("insert");
        }

        // A broken RNG that keeps returning a live index must be reported as
        // such after a bounded number of retries. Falling back to a
        // predictable index instead would hand an attacker the receiver index
        // of every new session.
        let mut fresh = SessionIndexMap::<MAX_SESSIONS>::new();
        fresh.insert(42, 0).expect("insert");
        assert_eq!(
            fresh.random_unused(&mut StuckRng(42)),
            Err(Error::SessionIndexGenerationFailed)
        );
        // The same broken RNG is fine as long as its one value is free.
        assert_eq!(fresh.random_unused(&mut StuckRng(43)), Ok(43));
    }
}
