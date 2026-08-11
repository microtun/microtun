//! A path-compressed (radix / Patricia-style) prefix trie mapping
//! [`IpCidr`] prefixes to values, with longest-prefix-match lookups —
//! the shape needed for WireGuard cryptokey routing
//! (`allowed_ips -> peer`).
//!
//! By default nodes live in fixed-capacity inline storage sized directly from
//! the route/prefix capacity; with the `alloc` feature the pool is a heap `Vec`
//! that grows on demand. Instead of one node per bit, each node stores a whole
//! run of bits (its "edge"), so a prefix costs at most **two**
//! nodes instead of up to 128. Lookups walk edge-by-edge, comparing a
//! run of bits at a time with one XOR; insert and remove do the edge
//! splitting/merging and are allowed to be slower.

use core::net::IpAddr;
#[cfg(not(feature = "alloc"))]
use core::ops::{Index, IndexMut};

use crate::IpCidr;

/// Index of a node in the pool. Both fixed-capacity and allocator-backed
/// builds use the platform index width, keeping the trie implementation and
/// capacity semantics identical across feature configurations.
type NodeId = usize;

/// Returned by [`PrefixTrie::insert`] when the node pool is exhausted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapacityError;

#[derive(Debug)]
struct Node<V> {
    /// The edge leading into this node: a run of address bits,
    /// MSB-aligned, with everything past `len` zeroed. Its first bit
    /// equals this node's index in its parent's `children`.
    bits: u128,
    /// Number of significant bits in `bits`. 0 only for the two roots.
    len: u8,
    /// Child taken when the next address bit is 0 or 1.
    children: [Option<NodeId>; 2],
    /// Value if some inserted prefix ends exactly at this node.
    value: Option<V>,
}

impl<V> Node<V> {
    fn new(bits: u128, len: u8) -> Self {
        Self {
            bits: mask(bits, len),
            len,
            children: [None, None],
            value: None,
        }
    }
}

/// Inline storage for the allocation-free trie.
///
/// The two address-family roots are always present. Every route/prefix can
/// require at most two additional Patricia nodes, so `MAX_PREFIXES` two-node
/// buckets are enough for any set of `MAX_PREFIXES` routes without needing
/// unstable const-generic
/// arithmetic such as `[Node<V>; 2 + 2 * MAX_PREFIXES]`.
#[cfg(not(feature = "alloc"))]
#[derive(Debug)]
struct NodePair<V> {
    nodes: [Node<V>; 2],
    /// Bit 0/1 says whether the corresponding node slot is live.
    occupied: u8,
}

#[cfg(not(feature = "alloc"))]
impl<V> NodePair<V> {
    fn empty() -> Self {
        Self {
            nodes: [Node::new(0, 0), Node::new(0, 0)],
            occupied: 0,
        }
    }

    fn get(&self, slot: usize) -> Option<&Node<V>> {
        let bit = 1u8 << slot;
        if self.occupied & bit == 0 {
            None
        } else {
            self.nodes.get(slot)
        }
    }

    fn get_mut(&mut self, slot: usize) -> Option<&mut Node<V>> {
        let bit = 1u8 << slot;
        if self.occupied & bit == 0 {
            None
        } else {
            self.nodes.get_mut(slot)
        }
    }

    fn first_free(&self) -> Option<usize> {
        (0usize..2).find(|&slot| self.occupied & (1u8 << slot) == 0)
    }

    fn occupy(&mut self, slot: usize, node: Node<V>) {
        let bit = 1u8 << slot;
        debug_assert_eq!(self.occupied & bit, 0);
        self.nodes[slot] = node;
        self.occupied |= bit;
    }

    fn release(&mut self, slot: usize) {
        let bit = 1u8 << slot;
        assert_ne!(self.occupied & bit, 0, "released trie node must be live");
        self.nodes[slot] = Node::new(0, 0);
        self.occupied &= !bit;
    }
}

#[cfg(not(feature = "alloc"))]
#[derive(Debug)]
struct NodePool<V, const MAX_PREFIXES: usize> {
    roots: [Node<V>; 2],
    pairs: [NodePair<V>; MAX_PREFIXES],
    used: usize,
}

#[cfg(not(feature = "alloc"))]
impl<V, const MAX_PREFIXES: usize> NodePool<V, MAX_PREFIXES> {
    fn new() -> Self {
        Self {
            roots: [Node::new(0, 0), Node::new(0, 0)],
            pairs: core::array::from_fn(|_| NodePair::empty()),
            used: 0,
        }
    }

    fn get(&self, id: NodeId) -> Option<&Node<V>> {
        match id {
            V4_ROOT | V6_ROOT => self.roots.get(id),
            _ => {
                let offset = id.checked_sub(2)?;
                self.pairs.get(offset / 2)?.get(offset % 2)
            }
        }
    }

    fn get_mut(&mut self, id: NodeId) -> Option<&mut Node<V>> {
        match id {
            V4_ROOT | V6_ROOT => self.roots.get_mut(id),
            _ => {
                let offset = id.checked_sub(2)?;
                self.pairs.get_mut(offset / 2)?.get_mut(offset % 2)
            }
        }
    }

    fn available(&self) -> usize {
        MAX_PREFIXES.saturating_mul(2).saturating_sub(self.used)
    }

    fn alloc(&mut self, node: Node<V>) -> Option<NodeId> {
        let (pair_index, slot) = self
            .pairs
            .iter()
            .enumerate()
            .find_map(|(pair_index, pair)| pair.first_free().map(|slot| (pair_index, slot)))?;
        self.pairs[pair_index].occupy(slot, node);
        self.used += 1;
        Some(2 + pair_index * 2 + slot)
    }

    fn release(&mut self, id: NodeId) {
        assert!(id >= 2, "trie roots are never released");
        let offset = id - 2;
        self.pairs
            .get_mut(offset / 2)
            .expect("valid trie node id")
            .release(offset % 2);
        self.used -= 1;
    }
}

#[cfg(not(feature = "alloc"))]
impl<V, const MAX_PREFIXES: usize> Index<NodeId> for NodePool<V, MAX_PREFIXES> {
    type Output = Node<V>;

    fn index(&self, index: NodeId) -> &Self::Output {
        self.get(index).expect("valid live trie node id")
    }
}

#[cfg(not(feature = "alloc"))]
impl<V, const MAX_PREFIXES: usize> IndexMut<NodeId> for NodePool<V, MAX_PREFIXES> {
    fn index_mut(&mut self, index: NodeId) -> &mut Self::Output {
        self.get_mut(index).expect("valid live trie node id")
    }
}

/// A path-compressed binary trie mapping IPv4 and IPv6 prefixes to `V`.
///
/// On allocation-free builds, `MAX_PREFIXES` is the maximum number of
/// prefixes the trie
/// must be able to represent. The backing pool reserves two roots plus two
/// nodes per prefix, which is the Patricia-trie worst case. With `alloc`, the
/// pool grows on demand and `MAX_PREFIXES` is only retained so callers can
/// use the same
/// type spelling in either storage mode.
///
/// Invariant kept by all operations: every non-root node either holds a value
/// or has two children — chains of single-child nodes are always merged into
/// one edge.
#[derive(Debug)]
pub struct PrefixTrie<V, const MAX_PREFIXES: usize> {
    #[cfg(not(feature = "alloc"))]
    nodes: NodePool<V, MAX_PREFIXES>,
    #[cfg(feature = "alloc")]
    nodes: alloc::vec::Vec<Node<V>>,
    /// Nodes freed by [`remove`](Self::remove), available for reuse.
    #[cfg(feature = "alloc")]
    free: alloc::vec::Vec<NodeId>,
    #[cfg(feature = "alloc")]
    _capacity: core::marker::PhantomData<[(); MAX_PREFIXES]>,
}

// The two roots are ordinary pool nodes at fixed indices with empty edges. A
// value on a root is a default route (`0.0.0.0/0` or `::/0`).
const V4_ROOT: NodeId = 0;
const V6_ROOT: NodeId = 1;

impl<V, const MAX_PREFIXES: usize> PrefixTrie<V, MAX_PREFIXES> {
    /// Creates an empty trie.
    pub fn new() -> Result<Self, CapacityError> {
        #[cfg(not(feature = "alloc"))]
        let nodes = NodePool::new();
        #[allow(clippy::vec_init_then_push)]
        #[cfg(feature = "alloc")]
        let nodes = {
            let mut nodes = alloc::vec::Vec::with_capacity(2);
            nodes.push(Node::new(0, 0)); // V4_ROOT
            nodes.push(Node::new(0, 0)); // V6_ROOT
            nodes
        };

        Ok(Self {
            nodes,
            #[cfg(feature = "alloc")]
            free: alloc::vec::Vec::new(),
            #[cfg(feature = "alloc")]
            _capacity: core::marker::PhantomData,
        })
    }

    /// Inserts `value` for `net`, returning the value previously stored
    /// for exactly this prefix, if any. [`IpCidr`] cannot carry host bits, so
    /// `10.1.2.3/8` is not a distinct key that has to be folded onto
    /// `10.0.0.0/8` — it is not representable in the first place.
    ///
    /// On `Err(CapacityError)` the trie is left unchanged.
    pub fn insert(&mut self, net: IpCidr, value: V) -> Result<Option<V>, CapacityError> {
        let (key, _, root) = key(net.first_address());
        let klen = net.network_length();

        let mut node = root;
        let mut pos = 0;
        loop {
            if pos == klen {
                return Ok(self.nodes[node].value.replace(value));
            }

            let branch = bit(key, pos);
            let Some(child) = self.nodes[node].children[branch] else {
                self.check_capacity(1)?;
                let leaf = self.alloc(shl(key, pos), klen - pos);
                self.nodes[leaf].value = Some(value);
                self.nodes[node].children[branch] = Some(leaf);
                return Ok(None);
            };

            let (cbits, clen) = {
                let child = &self.nodes[child];
                (child.bits, child.len)
            };
            let remaining = klen - pos;
            let rest = shl(key, pos);
            let shared = common_len(rest, cbits, clen.min(remaining));
            if shared == clen {
                node = child;
                pos += clen;
                continue;
            }

            let ends_here = shared == remaining;
            self.check_capacity(if ends_here { 1 } else { 2 })?;
            let mid = self.alloc(cbits, shared);
            self.nodes[child].bits = shl(cbits, shared);
            self.nodes[child].len = clen - shared;
            let child_branch = bit(self.nodes[child].bits, 0);
            self.nodes[mid].children[child_branch] = Some(child);
            self.nodes[node].children[branch] = Some(mid);

            if ends_here {
                self.nodes[mid].value = Some(value);
            } else {
                let leaf = self.alloc(shl(rest, shared), remaining - shared);
                self.nodes[leaf].value = Some(value);
                let leaf_branch = bit(self.nodes[leaf].bits, 0);
                self.nodes[mid].children[leaf_branch] = Some(leaf);
            }
            return Ok(None);
        }
    }

    /// Longest-prefix-match lookup: the value of the most specific
    /// inserted prefix containing `addr`. This is the hot path.
    pub fn lookup(&self, addr: IpAddr) -> Option<&V> {
        let (key, klen, root) = key(addr);
        let mut node = root;
        let mut pos = 0;
        let mut best = self.nodes.get(root)?.value.as_ref();
        while pos < klen {
            let branch = bit(key, pos);
            let Some(child) = self.nodes.get(node)?.children[branch] else {
                break;
            };
            let Some(step) = self.edge_match(child, shl(key, pos), klen - pos) else {
                break;
            };
            node = child;
            pos += step;
            if pos > klen {
                return None;
            }
            if let Some(v) = &self.nodes.get(node)?.value {
                best = Some(v);
            }
        }
        best
    }

    /// The value stored for exactly `net`, if any (no LPM).
    pub fn get(&self, net: IpCidr) -> Option<&V> {
        let (key, _, mut node) = key(net.first_address());
        let klen = net.network_length();
        let mut pos = 0;
        while pos < klen {
            let branch = bit(key, pos);
            let child = self.nodes.get(node)?.children[branch]?;
            let step = self.edge_match(child, shl(key, pos), klen - pos)?;
            node = child;
            pos += step;
            if pos > klen {
                return None;
            }
        }
        self.nodes.get(node)?.value.as_ref()
    }

    /// Removes and returns the value stored for exactly `net`, merging
    /// edges back together so freed nodes can be reused.
    pub fn remove(&mut self, net: IpCidr) -> Option<V> {
        let (key, _, root) = key(net.first_address());
        let klen = net.network_length();

        #[cfg(not(feature = "alloc"))]
        let mut path: heapless::Vec<(NodeId, usize), 128> = heapless::Vec::new();
        #[cfg(feature = "alloc")]
        let mut path: alloc::vec::Vec<(NodeId, usize)> = alloc::vec::Vec::new();
        let mut node = root;
        let mut pos = 0;
        while pos < klen {
            let branch = bit(key, pos);
            let child = self.nodes[node].children[branch]?;
            let step = self.edge_match(child, shl(key, pos), klen - pos)?;
            #[cfg(not(feature = "alloc"))]
            path.push((node, branch))
                .expect("an IP prefix has at most 128 edges");
            #[cfg(feature = "alloc")]
            path.push((node, branch));
            node = child;
            pos += step;
        }

        let value = self.nodes[node].value.take()?;
        let Some(&(parent, branch)) = path.last() else {
            return Some(value);
        };

        match self.nodes[node].children {
            [Some(_), Some(_)] => {}
            [Some(only), None] | [None, Some(only)] => {
                self.merge_into_child(parent, branch, node, only);
            }
            [None, None] => {
                self.nodes[parent].children[branch] = None;
                self.release(node);

                if path.len() >= 2 {
                    let (grand, grand_branch) = path[path.len() - 2];
                    let parent_node = &self.nodes[parent];
                    if parent_node.value.is_none() {
                        match parent_node.children {
                            [Some(only), None] | [None, Some(only)] => {
                                self.merge_into_child(grand, grand_branch, parent, only);
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        Some(value)
    }

    fn edge_match(&self, child: NodeId, key: u128, rem: u8) -> Option<u8> {
        let c = self.nodes.get(child)?;
        if c.len <= rem && common_len(key, c.bits, c.len) == c.len {
            Some(c.len)
        } else {
            None
        }
    }

    fn merge_into_child(&mut self, parent: NodeId, branch: usize, node: NodeId, child: NodeId) {
        let (bits, len) = {
            let node = &self.nodes[node];
            (node.bits, node.len)
        };
        let child_node = &mut self.nodes[child];
        child_node.bits = bits | shr(child_node.bits, len);
        child_node.len += len;
        self.nodes[parent].children[branch] = Some(child);
        self.release(node);
    }

    fn release(&mut self, node: NodeId) {
        #[cfg(not(feature = "alloc"))]
        self.nodes.release(node);
        #[cfg(feature = "alloc")]
        self.free.push(node);
    }

    fn check_capacity(&self, needed: usize) -> Result<(), CapacityError> {
        #[cfg(not(feature = "alloc"))]
        {
            return if self.nodes.available() >= needed {
                Ok(())
            } else {
                Err(CapacityError)
            };
        }
        #[cfg(feature = "alloc")]
        {
            let _ = needed;
            Ok(())
        }
    }

    /// Takes a free node or grows the pool. Callers reserve enough space with
    /// `check_capacity` before mutating the trie.
    fn alloc(&mut self, bits: u128, len: u8) -> NodeId {
        #[cfg(not(feature = "alloc"))]
        {
            return self
                .nodes
                .alloc(Node::new(bits, len))
                .expect("capacity was checked before allocation");
        }
        #[cfg(feature = "alloc")]
        {
            if let Some(id) = self.free.pop() {
                self.nodes[id] = Node::new(bits, len);
                return id;
            }
            let id = self.nodes.len();
            self.nodes.push(Node::new(bits, len));
            id
        }
    }
}

/// Address bits MSB-aligned in a `u128`, the address bit length, and the
/// pool index of the root for this address family. Keeping IPv4 and IPv6
/// under separate roots keeps the families fully disjoint.
fn key(addr: IpAddr) -> (u128, u8, NodeId) {
    match addr {
        IpAddr::V4(a) => ((u32::from_be_bytes(a.octets()) as u128) << 96, 32, V4_ROOT),
        IpAddr::V6(a) => (u128::from_be_bytes(a.octets()), 128, V6_ROOT),
    }
}

/// Bit `i` of MSB-aligned `bits`, as an index into `children`.
fn bit(bits: u128, i: u8) -> usize {
    ((bits >> (127 - i)) & 1) as usize
}

/// Length of the common MSB-aligned prefix of `a` and `b`, capped at `max`.
fn common_len(a: u128, b: u128, max: u8) -> u8 {
    ((a ^ b).leading_zeros() as u8).min(max)
}

/// Shifts that tolerate a count of 128 (edges can span a full address).
fn shl(bits: u128, n: u8) -> u128 {
    if n >= 128 { 0 } else { bits << n }
}

fn shr(bits: u128, n: u8) -> u128 {
    if n >= 128 { 0 } else { bits >> n }
}

/// Zeroes every bit of `bits` past the first `len`.
fn mask(bits: u128, len: u8) -> u128 {
    match len {
        0 => 0,
        128.. => bits,
        _ => bits & (!0u128 << (128 - u32::from(len))),
    }
}

#[cfg(test)]
mod tests {
    use core::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::IpCidr;

    fn net4(a: u8, b: u8, c: u8, d: u8, len: u8) -> IpCidr {
        // `IpCidr` is canonical by construction, so build through `IpInet`
        // (which tolerates host bits) and take its network. That keeps the
        // host-bit cases these tests deliberately exercise expressible.
        crate::IpInet::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), len)
            .expect("valid prefix")
            .network()
    }

    fn net6(addr: Ipv6Addr, len: u8) -> IpCidr {
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

    /// Capacity is expressed in prefixes; the no-alloc backing pool derives
    /// its two-roots-plus-two-nodes-per-prefix storage internally.
    type Trie = PrefixTrie<u32, 64>;

    #[test]
    fn host_bits_are_ignored_and_re_insertion_replaces_in_place() {
        let mut trie = Trie::new().expect("capacity");
        // `10.1.2.3/8` and `10.0.0.0/8` are the same key, so a caller that
        // forgets to canonicalise cannot create a shadow entry.
        assert_eq!(trie.insert(net4(10, 1, 2, 3, 8), 1), Ok(None));
        assert_eq!(
            trie.insert(net4(10, 0, 0, 0, 8), 2),
            Ok(Some(1)),
            "the previous value for the same prefix is returned"
        );
        assert_eq!(trie.lookup(v4(10, 255, 255, 255)), Some(&2));
        assert_eq!(trie.get(net4(10, 200, 0, 0, 8)), Some(&2));
    }

    #[test]
    fn the_families_are_disjoint_and_default_routes_live_on_the_roots() {
        let mut trie = Trie::new().expect("capacity");
        let v6_net = |a: u16, len: u8| net6(Ipv6Addr::new(a, 0, 0, 0, 0, 0, 0, 0), len);

        trie.insert(net4(0, 0, 0, 0, 0), 40).expect("v4 default");
        trie.insert(net6(Ipv6Addr::UNSPECIFIED, 0), 60)
            .expect("v6 default");
        trie.insert(v6_net(0xfd00, 16), 61).expect("insert");

        // A default route matches everything in its own family and nothing in
        // the other; sharing one root would make them alias.
        assert_eq!(trie.lookup(v4(203, 0, 113, 1)), Some(&40));
        assert_eq!(trie.lookup(v6([0xfd00, 0, 0, 0, 0, 0, 0, 1])), Some(&61));
        assert_eq!(trie.lookup(v6([0x2001, 0, 0, 0, 0, 0, 0, 1])), Some(&60));

        // A full-length IPv6 prefix exercises the 128-bit edge case in the
        // shift helpers.
        let host = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x1234);
        trie.insert(net6(host, 128), 62).expect("insert");
        assert_eq!(trie.lookup(IpAddr::V6(host)), Some(&62));
        assert_eq!(trie.get(net6(host, 128)), Some(&62));
        assert_eq!(
            trie.lookup(v6([0xfd00, 0, 0, 0, 0, 0, 0, 0x1235])),
            Some(&61)
        );
    }

    #[test]
    fn removal_uncovers_the_next_less_specific_prefix_and_frees_its_nodes() {
        let mut trie = Trie::new().expect("capacity");
        trie.insert(net4(10, 0, 0, 0, 8), 1).expect("insert");
        trie.insert(net4(10, 1, 2, 0, 24), 3).expect("insert");
        trie.insert(net4(10, 1, 3, 0, 24), 4).expect("insert");

        assert_eq!(trie.remove(net4(10, 1, 2, 0, 24)), Some(3));
        assert_eq!(
            trie.remove(net4(10, 1, 2, 0, 24)),
            None,
            "removal is idempotent"
        );
        assert_eq!(
            trie.lookup(v4(10, 1, 2, 9)),
            Some(&1),
            "the covering prefix takes over"
        );
        assert_eq!(
            trie.lookup(v4(10, 1, 3, 9)),
            Some(&4),
            "siblings are untouched"
        );

        // Removing a prefix that was never inserted must not disturb the
        // structure, even when an interior node exists on its path.
        assert_eq!(trie.remove(net4(10, 1, 0, 0, 16)), None);
        assert_eq!(trie.lookup(v4(10, 1, 3, 9)), Some(&4));

        assert_eq!(trie.remove(net4(10, 0, 0, 0, 8)), Some(1));
        assert_eq!(trie.lookup(v4(10, 9, 9, 9)), None);
        assert_eq!(trie.lookup(v4(10, 1, 3, 9)), Some(&4));

        // Freed nodes return to the pool: churning far more prefixes than the
        // trie could hold at once must keep working.
        let mut small: PrefixTrie<u32, 1> = PrefixTrie::new().expect("capacity");
        for round in 0..50u8 {
            small
                .insert(net4(172, 16, round, 0, 24), u32::from(round))
                .expect("insert");
            assert_eq!(small.lookup(v4(172, 16, round, 5)), Some(&u32::from(round)));
            assert_eq!(
                small.remove(net4(172, 16, round, 0, 24)),
                Some(u32::from(round))
            );
            assert_eq!(small.lookup(v4(172, 16, round, 5)), None);
        }
    }

    /// Only the allocation-free backend has a node ceiling; with `alloc` the
    /// pool grows with the table and `check_capacity` is a no-op.
    #[cfg(not(feature = "alloc"))]
    #[test]
    fn a_full_node_pool_is_reported_and_leaves_the_trie_unchanged() {
        // Capacity one derives two non-root node slots internally: enough for
        // one prefix, but not enough for a sibling that needs both a new
        // interior node and a new leaf.
        let mut trie: PrefixTrie<u32, 1> = PrefixTrie::new().expect("capacity");
        trie.insert(net4(10, 1, 0, 0, 24), 1).expect("first prefix");

        // A sibling prefix needs a new interior node plus a leaf.
        assert_eq!(trie.insert(net4(10, 2, 0, 0, 24), 2), Err(CapacityError));
        assert_eq!(
            trie.lookup(v4(10, 1, 0, 1)),
            Some(&1),
            "a failed insert must not damage what is already there"
        );
        assert_eq!(trie.lookup(v4(10, 2, 0, 1)), None);

        // Replacing an existing prefix costs no nodes, so it still succeeds.
        assert_eq!(trie.insert(net4(10, 1, 0, 0, 24), 9), Ok(Some(1)));
        assert_eq!(trie.lookup(v4(10, 1, 0, 1)), Some(&9));

        // Freeing a node makes room again.
        assert_eq!(trie.remove(net4(10, 1, 0, 0, 24)), Some(9));
        trie.insert(net4(10, 2, 0, 0, 24), 2)
            .expect("room was reclaimed");
        assert_eq!(trie.lookup(v4(10, 2, 0, 1)), Some(&2));

        // Roots are separate from the prefix budget: a zero-capacity trie can
        // still represent default routes, but cannot allocate a non-root node.
        let mut roots_only: PrefixTrie<u32, 0> = PrefixTrie::new().expect("roots");
        assert_eq!(roots_only.insert(net4(0, 0, 0, 0, 0), 7), Ok(None));
        assert_eq!(
            roots_only.insert(net4(10, 0, 0, 0, 8), 8),
            Err(CapacityError)
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn an_allocator_backed_trie_grows_instead_of_reporting_capacity() {
        // The same const parameter is still declared, but with `alloc` it
        // bounds nothing: the trie grows with the route table.
        let mut trie: PrefixTrie<u32, 4> = PrefixTrie::new().expect("capacity");
        for byte in 0..32u8 {
            trie.insert(net4(10, byte, 0, 0, 24), u32::from(byte))
                .expect("an allocator-backed pool never fills");
        }
        for byte in 0..32u8 {
            assert_eq!(trie.lookup(v4(10, byte, 0, 1)), Some(&u32::from(byte)));
        }
    }

    #[test]
    fn many_prefixes_resolve_the_same_way_a_linear_scan_would() {
        // Path compression, edge splitting and edge merging are the parts most
        // likely to go subtly wrong, so this cross-checks the trie against the
        // definition of longest-prefix match over a set that forces splits at
        // many different depths.
        let mut prefixes = Vec::new();
        for byte in [0u8, 1, 2, 3, 127, 128, 129, 200, 254, 255] {
            for len in [8u8, 12, 16, 20, 24] {
                prefixes.push((
                    net4(10, byte, byte, byte, len),
                    u32::from(byte) * 32 + u32::from(len),
                ));
            }
        }

        let mut trie = Trie::new().expect("capacity");
        for (net, value) in &prefixes {
            trie.insert(*net, *value).expect("insert");
        }

        // A free function rather than a closure: the second half of this test
        // shrinks `prefixes`, which a closure capturing it would forbid.
        fn expected(prefixes: &[(IpCidr, u32)], address: Ipv4Addr) -> Option<u32> {
            prefixes
                .iter()
                .filter(|(net, _)| net.contains(&IpAddr::V4(address)))
                .max_by_key(|(net, _)| net.network_length())
                .map(|(_, value)| *value)
        }

        for a in [10u8, 11] {
            for b in [0u8, 1, 2, 3, 15, 127, 128, 129, 200, 254, 255] {
                for c in [0u8, 1, 128, 255] {
                    let address = Ipv4Addr::new(a, b, c, 7);
                    assert_eq!(
                        trie.lookup(IpAddr::V4(address)).copied(),
                        expected(&prefixes, address),
                        "lookup disagreed for {address}"
                    );
                }
            }
        }

        // Removing half the set must leave the other half exactly as it was.
        let doomed: Vec<IpCidr> = prefixes
            .iter()
            .filter(|(net, _)| net.network_length() % 8 != 0)
            .map(|(net, _)| *net)
            .collect();
        for net in doomed {
            trie.remove(net);
        }
        prefixes.retain(|(net, _)| net.network_length() % 8 == 0);
        for b in [0u8, 1, 127, 255] {
            let address = Ipv4Addr::new(10, b, b, 7);
            assert_eq!(
                trie.lookup(IpAddr::V4(address)).copied(),
                expected(&prefixes, address)
            );
        }
    }
}
