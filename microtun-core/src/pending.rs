//! Pending outbound packets.
//!
//! When an inner packet cannot be sent yet — its destination is being
//! resolved, or a handshake to its peer is still in flight — it parks here.
//! The pool is tiny and global (not per-peer): dropping packets under
//! pressure is fine, IP is lossy and the transport above will retransmit
//! (§6.4 leans on exactly this property). What matters is keeping *one*
//! packet alive per new flow so TCP SYNs and DNS queries survive the
//! handshake RTT.

use zeroize::Zeroize;

use crate::{MAX_INNER_SIZE, ResolveId, routing::PeerIdx, time::Instant};

/// What a parked packet is waiting for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wait {
    /// A `by-address` resolver query with this request identifier.
    Resolve(ResolveId),
    /// A handshake with this peer.
    Handshake(PeerIdx),
}

pub struct PendingPacket {
    /// The parked packet. An inline worst-case buffer by default; under
    /// `alloc` a heap buffer holding exactly the bytes parked, so an idle
    /// pool costs nothing and a short SYN does not reserve `MAX_INNER_SIZE`.
    #[cfg(not(feature = "alloc"))]
    buf: [u8; MAX_INNER_SIZE],
    #[cfg(feature = "alloc")]
    buf: alloc::vec::Vec<u8>,
    len: u16,
    pub wait: Wait,
    pub deadline: Instant,
}

impl core::fmt::Debug for PendingPacket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PendingPacket")
            .field("len", &self.len)
            .field("wait", &self.wait)
            .finish()
    }
}

impl PendingPacket {
    pub fn packet(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }

    fn wipe(&mut self) {
        self.buf.zeroize();
        self.len.zeroize();
    }
}

impl Drop for PendingPacket {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// Fixed pool of `N` parked packets.
#[derive(Debug)]
pub struct PendingPool<const N: usize> {
    #[cfg(not(feature = "alloc"))]
    slots: [Option<PendingPacket>; N],
    #[cfg(feature = "alloc")]
    slots: alloc::vec::Vec<Option<PendingPacket>>,
    #[cfg(feature = "alloc")]
    _capacity: core::marker::PhantomData<[(); N]>,
}

impl<const N: usize> Default for PendingPool<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> PendingPool<N> {
    pub fn new() -> Self {
        Self {
            #[cfg(not(feature = "alloc"))]
            slots: core::array::from_fn(|_| None),
            #[cfg(feature = "alloc")]
            slots: (0..N).map(|_| None).collect(),
            #[cfg(feature = "alloc")]
            _capacity: core::marker::PhantomData,
        }
    }

    /// Park a packet. On a full pool the entry closest to its deadline is
    /// replaced (newest flow wins — it is the one the user is waiting on).
    pub fn park(&mut self, packet: &[u8], wait: Wait, deadline: Instant) -> bool {
        if packet.len() > MAX_INNER_SIZE {
            return false;
        }
        #[cfg(not(feature = "alloc"))]
        let buf = {
            let mut buf = [0u8; MAX_INNER_SIZE];
            buf[..packet.len()].copy_from_slice(packet);
            buf
        };
        #[cfg(feature = "alloc")]
        let buf = packet.to_vec();
        let entry = PendingPacket {
            buf,
            len: packet.len() as u16,
            wait,
            deadline,
        };

        if let Some(slot) = self.slots.iter_mut().find(|s| s.is_none()) {
            *slot = Some(entry);
            return true;
        }
        if let Some(slot) = self
            .slots
            .iter_mut()
            .min_by_key(|s| s.as_ref().map(|p| p.deadline).unwrap_or(Instant(0)))
        {
            *slot = Some(entry);
            return true;
        }
        false
    }

    /// Take (remove and return) the next packet matching `pred`.
    pub fn take_if<F: Fn(&PendingPacket) -> bool>(&mut self, pred: F) -> Option<PendingPacket> {
        for slot in self.slots.iter_mut() {
            if slot.as_ref().is_some_and(&pred) {
                return slot.take();
            }
        }
        None
    }

    /// Drop all packets matching `pred`.
    pub fn drop_if<F: Fn(&PendingPacket) -> bool>(&mut self, pred: F) {
        for slot in self.slots.iter_mut() {
            if slot.as_ref().is_some_and(&pred) {
                *slot = None;
            }
        }
    }

    /// Earliest deadline among parked packets (for `poll_at`).
    pub fn next_deadline(&self) -> Option<Instant> {
        self.slots.iter().flatten().map(|p| p.deadline).min()
    }

    /// Drop one packet whose deadline has passed.
    ///
    /// Returning after one removal lets the core make timeout processing
    /// incremental: embeddings can finish packet delivery between
    /// successive due timer actions.
    pub fn expire_one(&mut self, now: Instant) -> bool {
        for slot in self.slots.iter_mut() {
            if slot.as_ref().is_some_and(|packet| packet.deadline <= now) {
                *slot = None;
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::Duration;

    /// A fixed instant well away from zero, so a saturated-to-zero deadline
    /// can never be mistaken for a correct one.
    const T0: Instant = Instant::from_millis(1_000_000);

    fn at(secs: u64) -> Instant {
        T0 + Duration::from_secs(secs)
    }

    #[test]
    fn dropping_by_predicate_clears_every_match_and_nothing_else() {
        let mut pool = PendingPool::<4>::new();
        pool.park(b"x", Wait::Handshake(1), at(10));
        pool.park(b"y", Wait::Handshake(1), at(11));
        pool.park(b"z", Wait::Handshake(2), at(12));

        pool.drop_if(|p| p.wait == Wait::Handshake(1));
        assert!(pool.take_if(|p| p.wait == Wait::Handshake(1)).is_none());
        assert_eq!(
            pool.take_if(|p| p.wait == Wait::Handshake(2))
                .expect("survivor")
                .packet(),
            b"z"
        );
    }

    #[test]
    fn expiry_removes_one_packet_per_call() {
        // Timeout processing is incremental so an embedding can deliver each
        // call's output before the next; a sweep that drained the whole pool
        // at once would break that contract.
        let mut pool = PendingPool::<4>::new();
        pool.park(b"a", Wait::Handshake(1), at(10));
        pool.park(b"b", Wait::Handshake(1), at(10));
        pool.park(b"c", Wait::Handshake(1), at(30));

        assert!(!pool.expire_one(at(9)), "nothing is due yet");
        assert!(pool.expire_one(at(10)), "the deadline is inclusive");
        assert!(pool.expire_one(at(10)));
        assert!(!pool.expire_one(at(10)));
        assert_eq!(pool.next_deadline(), Some(at(30)));

        assert!(pool.expire_one(at(31)));
        assert_eq!(pool.next_deadline(), None);
        assert!(!pool.expire_one(at(1_000)));
    }

    #[test]
    fn a_full_pool_sacrifices_the_packet_closest_to_giving_up() {
        // Dropping under pressure is fine — IP is lossy and the transport
        // above retransmits — but the newest flow is the one a user is
        // actually waiting on, so it wins.
        let mut pool = PendingPool::<2>::new();
        assert!(pool.park(b"oldest", Wait::Handshake(1), at(10)));
        assert!(pool.park(b"middle", Wait::Handshake(2), at(20)));

        assert!(pool.park(b"newest", Wait::Handshake(3), at(30)));
        assert!(
            pool.take_if(|p| p.wait == Wait::Handshake(1)).is_none(),
            "the entry closest to its deadline should have been replaced"
        );
        assert!(pool.take_if(|p| p.wait == Wait::Handshake(2)).is_some());
        assert!(pool.take_if(|p| p.wait == Wait::Handshake(3)).is_some());
    }

    #[test]
    fn an_oversized_packet_is_refused_rather_than_truncated() {
        let mut pool = PendingPool::<1>::new();
        assert!(!pool.park(&vec![0u8; MAX_INNER_SIZE + 1], Wait::Handshake(1), at(10)));
        assert_eq!(pool.next_deadline(), None, "nothing was stored");

        // The boundary itself fits, and survives the round trip intact.
        let biggest = vec![0x5au8; MAX_INNER_SIZE];
        assert!(pool.park(&biggest, Wait::Handshake(1), at(10)));
        let taken = pool.take_if(|_| true).expect("parked");
        assert_eq!(taken.packet(), &biggest[..]);
    }
}
