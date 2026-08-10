//! The cryptokey routing cache (§2, adapted for dynamic peers).
//!
//! A classic WireGuard device has a static cryptokey-routing table; microtun has a
//! resolver-filled cache, pre-seeded with the pinned peers' CIDRs. Dynamic
//! records stay usable while watched invalidations reconcile them; integrations
//! without a watch transport retain periodic by-key refresh as a fallback.
//! Records are replaced or removed only by an authoritative resolver answer.
//!
//! Routes live in stable fixed-capacity slots. A path-compressed prefix trie
//! maps each distinct CIDR to the slot of its incumbent owner, making the packet
//! hot path a bounded longest-prefix trie walk followed by one slot access.
//! Multiple peers may temporarily claim the same prefix; those extra owners stay
//! in the slot array, and the earliest insertion remains in the trie until it is
//! removed. Its next-oldest owner is then promoted without changing tie-break
//! semantics.
//!
//! This cache holds only positive routes. Suppression of repeated resolver
//! queries for authoritatively-unknown destinations and static keys lives in
//! the engine's in-flight resolve table (see `device.rs`), not here.

use core::net::IpAddr;

use crate::{Error, IpNet, prefix_trie::PrefixTrie, time::Instant};

/// Handle into the peer table.
///
/// Wide enough that no plausible `P` can overflow it. The engine indexes its
/// fixed pools with these handles and casts them to `usize`, so a narrow
/// handle would silently alias two peers onto one entry once `P` exceeded its
/// range; [`crate::Core::new`] additionally rejects any `P` this type cannot
/// address, returning [`Error::InvalidCapacity`] rather than allowing aliasing.
pub type PeerIdx = u32;

#[derive(Debug, Clone, Copy)]
struct Entry {
    cidr: IpNet,
    peer: PeerIdx,
    pinned: bool,
    last_used: Instant,
    insertion_order: u64,
}

/// Route cache with `RT` positive slots.
///
/// Its path-compressed prefix trie is sized from the same route capacity. On
/// allocation-free builds the trie reserves its two roots plus two nodes per
/// route, the Patricia-trie worst case; allocator-backed builds grow on demand.
#[derive(Debug)]
pub struct RouteCache<const RT: usize> {
    /// Stable slots. Trie values are indices into this array.
    ///
    /// Under `alloc` this is a heap `Vec` filled with `RT` empty slots up
    /// front rather than an inline array, so slot indices stay stable and
    /// every access below is unchanged; only the storage moves.
    #[cfg(not(feature = "alloc"))]
    entries: [Option<Entry>; RT],
    #[cfg(feature = "alloc")]
    entries: alloc::vec::Vec<Option<Entry>>,
    len: usize,
    trie: PrefixTrie<usize, RT>,
    next_insertion_order: u64,
    /// `RT` is a slot count rather than an array length under `alloc`, but a
    /// struct must still use every const parameter it declares.
    #[cfg(feature = "alloc")]
    _capacity: core::marker::PhantomData<[(); RT]>,
}

impl<const RT: usize> RouteCache<RT> {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            #[cfg(not(feature = "alloc"))]
            entries: [None; RT],
            #[cfg(feature = "alloc")]
            entries: alloc::vec![None; RT],
            len: 0,
            trie: PrefixTrie::new().map_err(|_| Error::InvalidCapacity)?,
            next_insertion_order: 0,
            #[cfg(feature = "alloc")]
            _capacity: core::marker::PhantomData,
        })
    }

    /// Longest-prefix match: stable slot of the winning entry, if any.
    fn best_match(&self, ip: &IpAddr) -> Option<usize> {
        self.trie.lookup(*ip).copied()
    }

    /// Longest-prefix-match lookup. Marks the winning entry as used.
    pub fn lookup(&mut self, ip: &IpAddr, now: Instant) -> Option<PeerIdx> {
        let index = self.best_match(ip)?;
        let entry = self.entries.get_mut(index)?.as_mut()?;
        entry.last_used = now;
        Some(entry.peer)
    }

    /// Return the peer selected for a source address without updating LRU state.
    pub fn lookup_readonly(&self, ip: &IpAddr) -> Option<PeerIdx> {
        let index = self.best_match(ip)?;
        self.entries.get(index)?.as_ref().map(|entry| entry.peer)
    }

    /// Insert or refresh a route without evicting another entry.
    ///
    /// The caller makes room before installing a dynamic peer's complete
    /// address set. Keeping eviction out of this method prevents partial peer
    /// updates and keeps the cache responsible only for routes.
    ///
    /// # Overlap
    ///
    /// Overlapping prefixes are permitted, including between a dynamic route
    /// and a pinned one: the resolver is the routing authority for dynamic
    /// peers and may assign address space freely (see
    /// `Core::check_resolved_answer`). [`Self::lookup`] resolves overlap by
    /// longest-prefix match.
    ///
    /// **Caveat — equal prefixes do not displace.** Only an identical
    /// `(cidr, peer)` pair is refreshed in place; the same prefix claimed by a
    /// *different* peer is added alongside the incumbent, and
    /// [`Self::lookup`] breaks a length tie in favour of the entry inserted
    /// first. A reassignment of an address from one peer to another therefore
    /// does not take effect until the previous owner's route is removed
    /// (peer eviction, or an authoritative `404` in a watched update). Until then
    /// the new owner is unroutable in both directions — outbound traffic goes
    /// to the incumbent, and the new owner's inner packets fail the source
    /// check in the transport receive path.
    pub fn insert(
        &mut self,
        cidr: IpNet,
        peer: PeerIdx,
        pinned: bool,
        now: Instant,
    ) -> Result<(), Error> {
        // Keys are network prefixes, and `IpNet` cannot represent anything
        // else — a sloppy input such as `10.1.2.3/8` was already folded to
        // `10.0.0.0/8` at the parse boundary. So there is nothing to
        // canonicalize here, and equal prefixes are guaranteed to share one
        // trie key and one tie-break run.

        // Refresh an identical route in place. Stable slots keep any trie
        // reference valid and consume no extra route or node capacity.
        if let Some(entry) = self
            .entries
            .iter_mut()
            .flatten()
            .find(|entry| entry.cidr == cidr && entry.peer == peer)
        {
            entry.pinned = pinned;
            entry.last_used = now;
            return Ok(());
        }

        let index = self
            .entries
            .iter()
            .position(Option::is_none)
            .ok_or(Error::RouteCacheFull)?;
        let next_len = self.len + 1;

        // Only the first owner of an exact prefix is installed in the trie.
        // Later owners remain dormant until the incumbent is removed.
        if self.trie.get(cidr).is_none() {
            let previous = self
                .trie
                .insert(cidr, index)
                .map_err(|_| Error::RouteCacheFull)?;
            if previous.is_some() {
                return Err(Error::InternalInvariant);
            }
        }

        self.entries[index] = Some(Entry {
            cidr,
            peer,
            pinned,
            last_used: now,
            insertion_order: self.next_insertion_order,
        });
        self.len = next_len;
        self.next_insertion_order = self.next_insertion_order.wrapping_add(1);
        Ok(())
    }

    /// Number of unused positive-route slots.
    pub fn available_slots(&self) -> usize {
        RT.saturating_sub(self.len)
    }

    /// Number of positive-route slots currently owned by `peer`.
    pub(crate) fn peer_route_count(&self, peer: PeerIdx) -> usize {
        self.entries
            .iter()
            .flatten()
            .filter(|entry| entry.peer == peer)
            .count()
    }

    /// Least-recently-used dynamic peer that can be evicted to make room.
    #[cfg(test)]
    pub fn lru_dynamic_peer(&self) -> Option<PeerIdx> {
        self.entries
            .iter()
            .flatten()
            .filter(|entry| !entry.pinned)
            .min_by_key(|entry| (entry.last_used, entry.insertion_order))
            .map(|entry| entry.peer)
    }

    /// Drop every route belonging to `peer` (peer eviction cascade).
    pub fn remove_peer(&mut self, peer: PeerIdx) -> Result<(), Error> {
        for index in 0..RT {
            let Some(entry) = self.entries[index] else {
                continue;
            };
            if entry.peer != peer {
                continue;
            }

            let next_len = self.len - 1;
            let was_incumbent = self.trie.get(entry.cidr).copied() == Some(index);
            let replacement = if was_incumbent {
                self.entries
                    .iter()
                    .enumerate()
                    .filter_map(|(candidate_index, candidate)| {
                        if candidate_index == index {
                            return None;
                        }
                        let candidate = candidate.as_ref()?;
                        (candidate.cidr == entry.cidr)
                            .then_some((candidate.insertion_order, candidate_index))
                    })
                    .min_by_key(|(order, _)| *order)
                    .map(|(_, candidate_index)| candidate_index)
            } else {
                None
            };

            if was_incumbent {
                let removed = self.trie.remove(entry.cidr);
                match removed {
                    Some(removed_index) if removed_index == index => {}
                    Some(removed_index) => {
                        let _ = self.trie.insert(entry.cidr, removed_index);
                        return Err(Error::InternalInvariant);
                    }
                    None => return Err(Error::InternalInvariant),
                }

                if let Some(replacement) = replacement {
                    match self.trie.insert(entry.cidr, replacement) {
                        Ok(None) => {}
                        _ => {
                            let _ = self.trie.insert(entry.cidr, index);
                            return Err(Error::InternalInvariant);
                        }
                    }
                }
            }

            let slot = &mut self.entries[index];
            if slot
                .as_ref()
                .is_none_or(|current| current.peer != entry.peer || current.cidr != entry.cidr)
            {
                if was_incumbent {
                    let _ = self.trie.remove(entry.cidr);
                    let _ = self.trie.insert(entry.cidr, index);
                }
                return Err(Error::InternalInvariant);
            }
            *slot = None;
            self.len = next_len;
        }
        Ok(())
    }
}

/// Do two CIDR prefixes intersect?
///
/// Two prefixes of the same family are either disjoint or nested, so it is
/// enough to test whether either one contains the other's network address.
/// Prefixes of different families never intersect (`IpNet::contains` is
/// false across families). `first_address` *is* the network address: `IpNet`
/// stores prefixes canonically.
pub(crate) fn ipnets_overlap(a: &IpNet, b: &IpNet) -> bool {
    a.contains(&b.first_address()) || b.contains(&a.first_address())
}

#[cfg(test)]
mod tests {
    use core::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::time::Duration;

    /// A fixed instant well away from zero, so a saturated-to-zero deadline
    /// can never be mistaken for a correct one.
    const T0: Instant = Instant::from_millis(1_000_000);

    fn net4(a: u8, b: u8, c: u8, d: u8, len: u8) -> IpNet {
        // `IpNet` is canonical by construction, so build through `IpInet`
        // (which tolerates host bits) and take its network. That keeps the
        // host-bit cases these tests deliberately exercise expressible.
        crate::IpInet::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), len)
            .expect("valid prefix")
            .network()
    }

    fn net6(addr: Ipv6Addr, len: u8) -> IpNet {
        crate::IpInet::new(IpAddr::V6(addr), len)
            .expect("valid prefix")
            .network()
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn v6(segments: [u16; 8]) -> IpAddr {
        let [a, b, c, d, e, f, g, h] = segments;
        IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h))
    }

    type Cache = RouteCache<4>;

    fn at(secs: u64) -> Instant {
        T0 + Duration::from_secs(secs)
    }

    #[test]
    fn lookup_is_longest_prefix_and_records_use() {
        let mut cache = Cache::new().expect("capacity");
        cache
            .insert(net4(10, 0, 0, 0, 8), 1, true, T0)
            .expect("pinned route");
        cache
            .insert(net4(10, 1, 0, 0, 16), 2, false, T0)
            .expect("dynamic route");

        // A more specific dynamic route wins over a pinned one: the resolver
        // is the routing authority for dynamic peers and may reassign space.
        assert_eq!(cache.lookup(&v4(10, 1, 2, 3), T0), Some(2));
        assert_eq!(cache.lookup(&v4(10, 9, 9, 9), T0), Some(1));
        assert_eq!(cache.lookup(&v4(11, 0, 0, 1), T0), None);
        assert_eq!(cache.lookup_readonly(&v4(10, 1, 2, 3)), Some(2));
        assert_eq!(
            cache.lookup_readonly(&v6([0xfd00, 0, 0, 0, 0, 0, 0, 1])),
            None
        );

        // The receive path must not disturb LRU state, or inbound traffic
        // would decide which peer survives eviction.
        cache.lookup(&v4(10, 9, 9, 9), at(100));
        cache.lookup_readonly(&v4(10, 1, 2, 3));
        assert_eq!(
            cache.lru_dynamic_peer(),
            Some(2),
            "only `lookup` refreshes a route's last use"
        );
        cache.lookup(&v4(10, 1, 2, 3), at(200));
        assert_eq!(
            cache.lru_dynamic_peer(),
            Some(2),
            "peer 1 is pinned, so never a victim"
        );
    }

    #[test]
    fn routes_are_stored_canonically_and_refreshed_in_place() {
        let mut cache = Cache::new().expect("capacity");
        // Equivalent spellings share one trie key and one slot, so a resolver
        // that returns un-truncated prefixes cannot exhaust the cache.
        cache
            .insert(net4(10, 1, 2, 3, 8), 1, false, T0)
            .expect("insert");
        assert_eq!(cache.available_slots(), 3);
        cache
            .insert(net4(10, 0, 0, 0, 8), 1, false, at(5))
            .expect("refresh");
        assert_eq!(
            cache.available_slots(),
            3,
            "the same route was refreshed, not added"
        );
        assert_eq!(cache.lookup(&v4(10, 5, 5, 5), T0), Some(1));

        // A refresh may also flip the pinned flag, which is how a route stops
        // being an eviction candidate.
        assert_eq!(cache.lru_dynamic_peer(), Some(1));
        cache
            .insert(net4(10, 0, 0, 0, 8), 1, true, at(6))
            .expect("refresh");
        assert_eq!(cache.lru_dynamic_peer(), None);
    }

    #[test]
    fn an_equal_prefix_claimed_by_a_second_peer_waits_behind_the_incumbent() {
        // Documented caveat: equal prefixes do not displace. The first owner
        // keeps the trie entry, and reassignment only takes effect once that
        // owner's route is removed — at which point the next-oldest claim is
        // promoted without changing tie-break semantics.
        let mut cache = Cache::new().expect("capacity");
        cache
            .insert(net4(10, 1, 0, 0, 24), 1, false, T0)
            .expect("first owner");
        cache
            .insert(net4(10, 1, 0, 0, 24), 2, false, at(1))
            .expect("second claim");
        cache
            .insert(net4(10, 1, 0, 0, 24), 3, false, at(2))
            .expect("third claim");
        assert_eq!(cache.available_slots(), 1, "each claim occupies a slot");
        assert_eq!(cache.lookup(&v4(10, 1, 0, 5), T0), Some(1));

        cache.remove_peer(1).expect("evict incumbent");
        assert_eq!(
            cache.lookup(&v4(10, 1, 0, 5), T0),
            Some(2),
            "the next-oldest owner is promoted"
        );
        cache.remove_peer(2).expect("evict");
        assert_eq!(cache.lookup(&v4(10, 1, 0, 5), T0), Some(3));
        cache.remove_peer(3).expect("evict");
        assert_eq!(cache.lookup(&v4(10, 1, 0, 5), T0), None);
        assert_eq!(cache.available_slots(), 4, "every slot came back");

        // Removing a peer that owns nothing is a no-op, not an error.
        cache.remove_peer(9).expect("no-op");
    }

    #[test]
    fn eviction_removes_every_route_a_peer_owns_and_nothing_else() {
        let mut cache = Cache::new().expect("capacity");
        cache
            .insert(net4(10, 1, 0, 0, 24), 1, false, T0)
            .expect("insert");
        cache
            .insert(net4(10, 2, 0, 0, 24), 1, false, T0)
            .expect("insert");
        cache
            .insert(
                net6(core::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0), 16),
                1,
                false,
                T0,
            )
            .expect("insert");
        cache
            .insert(net4(10, 3, 0, 0, 24), 2, true, T0)
            .expect("insert");
        assert_eq!(cache.available_slots(), 0);

        cache.remove_peer(1).expect("evict");
        assert_eq!(cache.available_slots(), 3);
        assert_eq!(cache.lookup(&v4(10, 1, 0, 1), T0), None);
        assert_eq!(cache.lookup(&v4(10, 2, 0, 1), T0), None);
        assert_eq!(cache.lookup(&v6([0xfd00, 0, 0, 0, 0, 0, 0, 1]), T0), None);
        assert_eq!(cache.lookup(&v4(10, 3, 0, 1), T0), Some(2));
    }

    #[test]
    fn a_full_cache_reports_rather_than_evicting_on_its_own() {
        // Eviction is the caller's job: keeping it out of `insert` is what
        // stops a partially applied peer update from leaving a peer routable
        // for some of its prefixes and not others.
        let mut cache = Cache::new().expect("capacity");
        for index in 0..4u8 {
            cache
                .insert(net4(10, index, 0, 0, 24), u32::from(index), false, T0)
                .expect("insert");
        }
        assert_eq!(cache.available_slots(), 0);
        assert_eq!(
            cache.insert(net4(10, 9, 0, 0, 24), 9, false, T0),
            Err(Error::RouteCacheFull)
        );
        // The refusal changes nothing.
        assert_eq!(cache.lookup(&v4(10, 0, 0, 1), T0), Some(0));
        assert_eq!(cache.lookup(&v4(10, 9, 0, 1), T0), None);
    }

    #[test]
    fn the_eviction_victim_is_the_least_recently_used_dynamic_route() {
        let mut cache = Cache::new().expect("capacity");
        cache
            .insert(net4(10, 0, 0, 0, 24), 10, true, T0)
            .expect("pinned");
        cache
            .insert(net4(10, 1, 0, 0, 24), 11, false, at(1))
            .expect("insert");
        cache
            .insert(net4(10, 2, 0, 0, 24), 12, false, at(2))
            .expect("insert");

        assert_eq!(cache.lru_dynamic_peer(), Some(11));
        cache.lookup(&v4(10, 1, 0, 1), at(50));
        assert_eq!(
            cache.lru_dynamic_peer(),
            Some(12),
            "using a route moves it to the back of the queue"
        );

        // Insertion order breaks ties, so the victim is deterministic even
        // when several routes were last used at the same instant.
        let mut cache = Cache::new().expect("capacity");
        cache
            .insert(net4(10, 1, 0, 0, 24), 11, false, T0)
            .expect("insert");
        cache
            .insert(net4(10, 2, 0, 0, 24), 12, false, T0)
            .expect("insert");
        assert_eq!(cache.lru_dynamic_peer(), Some(11));

        // With nothing but pinned routes there is no victim at all, which is
        // what turns into `RouteCacheFull` upstream.
        let mut pinned_only = Cache::new().expect("capacity");
        pinned_only
            .insert(net4(10, 0, 0, 0, 24), 1, true, T0)
            .expect("insert");
        assert_eq!(pinned_only.lru_dynamic_peer(), None);
    }
}
