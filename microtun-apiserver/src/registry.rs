//! Peer records and the two indexes the API is defined over.
//!
//! Records contain only validated peer data. RPC results are serialized from
//! that data for each request, straight into the peer's transmit buffer; no
//! result is pre-rendered or cached in the registry.

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::{Arc, RwLock},
};

use microtun_api::PeerInfo;
use microtun_core::{
    InboundPolicy, IpNet, PeerAddresses, ResolvedPeer, encode_key, push_peer_address,
};

/// Characters of a key's base64 form used to name a peer in a log line: wide
/// enough to pick one record out of a file, narrow enough to sit in a line
/// with other fields.
pub const KEY_PREFIX_LEN: usize = 12;

/// One configured peer.
///
/// Peer names are configuration-local aliases used while resolving `Relay`.
/// Records and resolver responses remain keyed by public key, so names do not
/// become part of the wire contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRecord {
    pub public_key: [u8; 32],
    /// The key in WireGuard's base64, which is the form it is served and
    /// logged in. Held rather than re-encoded per request.
    pub public_key_text: String,
    pub endpoint: Option<SocketAddr>,
    pub relay: Option<[u8; 32]>,
    pub persistent_keepalive: Option<u16>,
    /// Canonical (host-bits-cleared) tunnel prefixes, at least one, at most
    /// `microtun_core::MAX_PEER_ADDRESSES`.
    pub addresses: Vec<IpNet>,
}

impl PeerRecord {
    /// Build a record from validated configuration data.
    pub fn new(
        public_key: [u8; 32],
        endpoint: Option<SocketAddr>,
        relay: Option<[u8; 32]>,
        addresses: Vec<IpNet>,
        persistent_keepalive: Option<u16>,
    ) -> Self {
        let public_key_text = encode_key(&public_key).as_str().to_string();

        Self {
            public_key,
            public_key_text,
            endpoint,
            relay,
            persistent_keepalive,
            addresses,
        }
    }

    /// Copy this record into the Peers API's single owned wire shape.
    pub fn info(&self) -> PeerInfo {
        PeerInfo::from_fields(
            &self.public_key,
            self.endpoint,
            self.relay.as_ref(),
            self.addresses.iter().copied(),
            self.persistent_keepalive,
        )
        .expect("validated Peers API server records fit the bounded API type")
    }

    /// Clone this configured record into the tunnel core's resolver shape.
    pub fn resolved(&self) -> ResolvedPeer {
        let mut addresses = PeerAddresses::new();
        for address in self.addresses.iter().copied() {
            // Configuration validation already applies the same per-peer
            // address limit and canonicalization rules as the core.
            push_peer_address(&mut addresses, address)
                .expect("validated Peers API server addresses fit resolver records");
        }

        ResolvedPeer {
            public_key: self.public_key,
            endpoint: self.endpoint,
            relay: self.relay,
            addresses,
            inbound_policy: InboundPolicy::AllowAll,
            persistent_keepalive: self
                .persistent_keepalive
                .map(|seconds| microtun_core::Duration::from_secs(u64::from(seconds))),
        }
    }

    /// The leading characters of the public key's base64 form, for log lines.
    pub fn key_prefix(&self) -> &str {
        &self.public_key_text[..KEY_PREFIX_LEN]
    }
}

/// Peers indexed by public key and by tunnel prefix.
///
/// Both indexes hold positions into `peers`, which owns the records. A
/// registry value is immutable after construction; reload publishes a newly
/// built value through [`SharedRegistry`].
#[derive(Debug, Default)]
pub struct Registry {
    peers: Vec<PeerRecord>,
    by_key: HashMap<[u8; 32], usize>,
    /// Prefixes sorted longest-first, so the first containing entry wins.
    routes: Vec<(IpNet, usize)>,
}

/// Atomically replaceable registry shared by the Peers API and tunnel resolver.
///
/// Readers take an `Arc` snapshot and then release the lock immediately, so a
/// reload never waits for response serialization or resolver work to finish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryChange {
    /// The key whose record was added, modified, or removed. Subscribers read
    /// the new state out of the published snapshot rather than carrying it
    /// here, so a change is just a name.
    pub public_key: [u8; 32],
}

/// The published registry.
///
/// There is no revision counter, cursor, or replay log. A notification carries
/// no state, so it cannot be reordered into a stale install; the only ordering
/// this type owes the Peers API is the explicit watch-creation atomicity in
/// [`Self::read`].
#[derive(Debug, Clone)]
pub struct SharedRegistry {
    current: Arc<RwLock<Arc<Registry>>>,
    changes: tokio::sync::broadcast::Sender<RegistryChange>,
}

impl SharedRegistry {
    pub fn new(registry: Registry) -> Self {
        let (changes, _) = tokio::sync::broadcast::channel(256);
        Self {
            current: Arc::new(RwLock::new(Arc::new(registry))),
            changes,
        }
    }

    /// Obtain one internally consistent view of all peer and route indexes.
    pub fn snapshot(&self) -> Arc<Registry> {
        self.current
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Read the current registry with change dispatch held off.
    ///
    /// This is the critical section the Peers API requires of `v1.peer.watch`:
    /// insert the requested key into the connection's watch set and read its
    /// current record inside `read`, and no change to that key can land after
    /// the snapshot yet escape the new watch. [`Self::replace`] publishes and
    /// dispatches under the matching write lock, so the two orderings are
    /// mutually exclusive — either the watch ran first and precedes the
    /// notification, or the reload ran first and the watch already answers
    /// from the new registry.
    ///
    /// Nothing else is owed. The response may be serialized and written
    /// afterwards, from any task, in any order relative to notifications.
    ///
    /// `read` must not block or acquire the registry lock again; keep it to the
    /// watch-set insertion and one by-key lookup.
    pub fn read<T>(&self, with: impl FnOnce(&Registry) -> T) -> T {
        let current = self
            .current
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        with(&current)
    }

    /// Subscribe to peer-level registry changes.
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<RegistryChange> {
        self.changes.subscribe()
    }

    /// Publish a completely validated replacement registry and notify only
    /// keys whose record was added, removed, or modified.
    ///
    /// Both the swap and the dispatch happen under the write lock, which is
    /// what makes [`Self::read`] a usable critical section for watch creation.
    pub fn replace(&self, registry: Registry) {
        let mut current = self
            .current
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let keys: HashSet<_> = current
            .by_key
            .keys()
            .chain(registry.by_key.keys())
            .copied()
            .collect();
        let mut changed = Vec::new();
        for public_key in keys {
            let differs = match (
                current.lookup_key(&public_key),
                registry.lookup_key(&public_key),
            ) {
                (None, Some(_)) | (Some(_), None) => true,
                (Some(before), Some(after)) => before != after,
                (None, None) => false,
            };
            if differs {
                changed.push(public_key);
            }
        }
        if changed.is_empty() {
            return;
        }
        *current = Arc::new(registry);
        for public_key in changed {
            let _ = self.changes.send(RegistryChange { public_key });
        }
    }
}

impl Registry {
    /// Index a set of records, rejecting collisions.
    pub fn build(records: Vec<PeerRecord>) -> Result<Self, String> {
        let mut peers: Vec<PeerRecord> = Vec::with_capacity(records.len());
        let mut by_key: HashMap<[u8; 32], usize> = HashMap::new();
        let mut routes: Vec<(IpNet, usize)> = Vec::new();

        for record in records {
            let index = peers.len();
            if by_key.contains_key(&record.public_key) {
                return Err(format!(
                    "two peers share the public key {}",
                    record.public_key_text
                ));
            }
            for cidr in &record.addresses {
                // Overlap is fine and is resolved by longest-prefix match, but
                // an identical prefix on two peers has no tie-break: the
                // by-address answer would depend on load order.
                if let Some(&(_, owner)) = routes.iter().find(|(existing, _)| existing == cidr) {
                    return Err(format!(
                        "peers {} and {} both claim {cidr}",
                        peers[owner].key_prefix(),
                        record.key_prefix()
                    ));
                }
                routes.push((*cidr, index));
            }
            by_key.insert(record.public_key, index);
            peers.push(record);
        }

        routes.sort_by_key(|(cidr, _)| std::cmp::Reverse(cidr.network_length()));

        Ok(Self {
            peers,
            by_key,
            routes,
        })
    }

    /// Look a peer up by its public key.
    pub fn lookup_key(&self, public_key: &[u8; 32]) -> Option<&PeerRecord> {
        self.by_key.get(public_key).map(|&index| &self.peers[index])
    }

    /// Look a peer up by an address inside one of its tunnel prefixes.
    ///
    /// Longest prefix wins, matching the route cache on the client side.
    pub fn lookup_address(&self, address: IpAddr) -> Option<&PeerRecord> {
        self.routes
            .iter()
            .find(|(cidr, _)| cidr.contains(&address))
            .map(|&(_, index)| &self.peers[index])
    }

    /// Number of configured peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Number of indexed tunnel prefixes.
    pub fn route_count(&self) -> usize {
        self.routes.len()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A record with `key`-filled key bytes and the given prefixes.
    pub(crate) fn record(key: u8, addresses: &[&str]) -> PeerRecord {
        PeerRecord::new(
            [key; 32],
            None,
            None,
            addresses
                .iter()
                .map(|cidr| cidr.parse().expect("test prefix parses"))
                .collect(),
            None,
        )
    }

    fn body_of(record: &PeerRecord) -> String {
        serde_json::to_string(&record.info()).expect("response serializes")
    }

    #[test]
    fn serializes_the_wire_body() {
        let peer = PeerRecord::new(
            [0xAA; 32],
            Some("203.0.113.5:51820".parse().unwrap()),
            Some([0xCC; 32]),
            vec!["10.0.0.3/32".parse().unwrap()],
            Some(25),
        );
        assert_eq!(
            body_of(&peer),
            concat!(
                r#"{"public_key":"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=","#,
                r#""endpoint":"203.0.113.5:51820","#,
                r#""relay":"zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMw=","#,
                r#""addresses":["10.0.0.3/32"],"persistent_keepalive":25}"#,
            )
        );
    }

    #[test]
    fn omits_absent_optional_fields() {
        let body = body_of(&record(0x01, &["10.0.0.1/32"]));
        assert!(!body.contains("endpoint"));
        assert!(!body.contains("relay"));
        assert!(!body.contains("persistent_keepalive"));
        assert!(!body.contains("inbound_policy"));
    }

    #[test]
    fn ipv6_endpoints_are_bracketed() {
        let peer = PeerRecord::new(
            [0x02; 32],
            Some("[2001:db8::5]:51820".parse().unwrap()),
            None,
            vec!["fd00::1/128".parse().unwrap()],
            None,
        );
        assert!(body_of(&peer).contains(r#""endpoint":"[2001:db8::5]:51820""#));
    }

    #[test]
    fn several_addresses_are_comma_separated() {
        let peer = record(0x04, &["10.0.0.1/32", "10.5.0.0/24"]);
        assert!(body_of(&peer).ends_with(r#""addresses":["10.0.0.1/32","10.5.0.0/24"]}"#));
    }

    #[test]
    fn longest_prefix_wins() {
        // 0x01 is the widest prefix, 0x03 the narrowest.
        let registry = Registry::build(vec![
            record(0x01, &["10.0.0.0/8"]),
            record(0x02, &["10.1.2.0/24"]),
            record(0x03, &["10.1.2.7/32"]),
        ])
        .expect("builds");

        let lookup = |address: &str| {
            registry
                .lookup_address(address.parse().unwrap())
                .map(|record| record.public_key[0])
        };
        assert_eq!(lookup("10.1.2.7"), Some(0x03));
        assert_eq!(lookup("10.1.2.9"), Some(0x02));
        assert_eq!(lookup("10.9.9.9"), Some(0x01));
        assert_eq!(lookup("192.0.2.1"), None);
        // A v6 query never matches a v4 prefix.
        assert_eq!(lookup("fd00::1"), None);
    }

    #[test]
    fn indexes_by_key() {
        let registry = Registry::build(vec![record(0x01, &["10.0.0.1/32"])]).expect("builds");
        assert!(registry.lookup_key(&[0x01; 32]).is_some());
        assert!(registry.lookup_key(&[0x02; 32]).is_none());
        assert_eq!(registry.peer_count(), 1);
        assert_eq!(registry.route_count(), 1);
    }

    #[test]
    fn replacement_broadcasts_only_changed_peer_keys() {
        let shared = SharedRegistry::new(
            Registry::build(vec![
                record(0x01, &["10.0.0.1/32"]),
                record(0x02, &["10.0.0.2/32"]),
                record(0x03, &["10.0.0.3/32"]),
            ])
            .expect("initial registry builds"),
        );
        let mut changes = shared.subscribe();

        shared.replace(
            Registry::build(vec![
                record(0x01, &["10.0.0.1/32"]),
                record(0x02, &["10.2.0.0/24"]),
                record(0x04, &["10.0.0.4/32"]),
            ])
            .expect("replacement registry builds"),
        );

        let mut observed = Vec::new();
        while let Ok(change) = changes.try_recv() {
            observed.push(change.public_key[0]);
        }
        observed.sort_unstable();
        assert_eq!(observed, vec![0x02, 0x03, 0x04]);

        shared.replace(
            Registry::build(vec![
                record(0x01, &["10.0.0.1/32"]),
                record(0x02, &["10.2.0.0/24"]),
                record(0x04, &["10.0.0.4/32"]),
            ])
            .expect("identical registry builds"),
        );
        assert!(matches!(
            changes.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn rejects_collisions() {
        let error = Registry::build(vec![
            record(0x01, &["10.0.0.1/32"]),
            record(0x01, &["10.0.0.2/32"]),
        ])
        .expect_err("duplicate key");
        assert!(error.contains("share the public key"), "{error}");

        let error = Registry::build(vec![
            record(0x01, &["10.0.0.0/24"]),
            record(0x02, &["10.0.0.0/24"]),
        ])
        .expect_err("duplicate prefix");
        assert!(error.contains("both claim 10.0.0.0/24"), "{error}");
    }
}
