//! Peer records and the two indexes the API is defined over.
//!
//! Configured records contain only validated peer data. The published registry
//! also carries a small runtime overlay of direct endpoints learned from
//! authenticated tunnel traffic. RPC and local-resolver projections combine the
//! two on read, with learned endpoints taking precedence over configured
//! `Endpoint` values. No result is pre-rendered or cached.

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::{Arc, RwLock},
};

use microtun_api::PeerInfo;
use microtun_core::{
    IpCidr, PeerAddresses, ResolvedPeer, firewall::InboundPolicy, key::encode_key,
    prefix_trie::PrefixTrie, push_peer_address,
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
    pub addresses: Vec<IpCidr>,
}

impl PeerRecord {
    /// Build a record from validated configuration data.
    pub fn new(
        public_key: [u8; 32],
        endpoint: Option<SocketAddr>,
        relay: Option<[u8; 32]>,
        addresses: Vec<IpCidr>,
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
    #[cfg(test)]
    pub fn info(&self) -> PeerInfo {
        self.info_with_endpoint(self.endpoint)
    }

    /// Copy this record into the Peers API wire shape using an effective runtime
    /// endpoint. The remaining fields always come from validated configuration.
    pub fn info_with_endpoint(&self, endpoint: Option<SocketAddr>) -> PeerInfo {
        PeerInfo::from_fields(
            &self.public_key,
            endpoint,
            self.relay.as_ref(),
            self.addresses.iter().copied(),
            self.persistent_keepalive,
        )
        .expect("validated Peers API server records fit the bounded API type")
    }

    /// Clone this configured record into the tunnel core's resolver shape.
    #[cfg(test)]
    pub fn resolved(&self) -> ResolvedPeer {
        self.resolved_with_endpoint(self.endpoint)
    }

    /// Clone this record into the tunnel resolver shape using an effective
    /// runtime endpoint.
    pub fn resolved_with_endpoint(&self, endpoint: Option<SocketAddr>) -> ResolvedPeer {
        let mut addresses = PeerAddresses::new();
        for address in self.addresses.iter().copied() {
            // Configuration validation already applies the same per-peer
            // address limit and canonicalization rules as the core.
            push_peer_address(&mut addresses, address)
                .expect("validated Peers API server addresses fit resolver records");
        }

        ResolvedPeer {
            public_key: self.public_key,
            endpoint,
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
#[derive(Debug)]
pub struct Registry {
    peers: Vec<PeerRecord>,
    by_key: HashMap<[u8; 32], usize>,
    /// Longest-prefix-match index from tunnel prefix to owning peer.
    routes: PrefixTrie<usize, 0>,
    route_count: usize,
}

impl Default for Registry {
    fn default() -> Self {
        Self::build(Vec::new()).expect("empty registry is always valid")
    }
}

/// One peer whose effective published state changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryChange {
    /// Subscribers re-read the published state rather than carrying it here,
    /// so a change is just a name.
    pub public_key: [u8; 32],
}

/// The published registry.
///
/// There is no revision counter, cursor, or replay log. A notification carries
/// no state, so it cannot be reordered into a stale install; the only ordering
/// this type owes the Peers API is the explicit watch-creation atomicity in
/// [`Self::read`].
#[derive(Debug, Clone)]
struct PublishedRegistry {
    registry: Arc<Registry>,
    /// Authenticated direct endpoints learned by the running tunnel. These are
    /// runtime observations, not configuration: while present they override the
    /// configured endpoint in Peers API and local-resolver projections.
    observed_endpoints: HashMap<[u8; 32], SocketAddr>,
}

/// Borrowed view of one atomically published config/runtime state pair.
///
/// Callers intentionally cannot access the overlay representation. Endpoint
/// precedence lives here so every projection observes the same rule.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PublishedView<'a> {
    registry: &'a Registry,
    observed_endpoints: &'a HashMap<[u8; 32], SocketAddr>,
}

impl<'a> PublishedView<'a> {
    pub(crate) fn config(self) -> &'a Registry {
        self.registry
    }

    pub(crate) fn lookup_key(self, public_key: &[u8; 32]) -> Option<&'a PeerRecord> {
        self.registry.lookup_key(public_key)
    }

    pub(crate) fn lookup_address(self, address: IpAddr) -> Option<&'a PeerRecord> {
        self.registry.lookup_address(address)
    }

    pub(crate) fn effective_endpoint(self, record: &PeerRecord) -> Option<SocketAddr> {
        self.observed_endpoints
            .get(&record.public_key)
            .copied()
            .or(record.endpoint)
    }

    pub(crate) fn info(self, record: &PeerRecord) -> PeerInfo {
        record.info_with_endpoint(self.effective_endpoint(record))
    }
}

#[derive(Debug, Clone)]
pub struct SharedRegistry {
    current: Arc<RwLock<PublishedRegistry>>,
    changes: tokio::sync::broadcast::Sender<RegistryChange>,
}

impl SharedRegistry {
    pub fn new(registry: Registry) -> Self {
        let (changes, _) = tokio::sync::broadcast::channel(256);
        Self {
            current: Arc::new(RwLock::new(PublishedRegistry {
                registry: Arc::new(registry),
                observed_endpoints: HashMap::new(),
            })),
            changes,
        }
    }

    /// Obtain only the current validated configuration. Runtime endpoint
    /// observations are intentionally projected only through [`Self::read`].
    pub fn config_snapshot(&self) -> Arc<Registry> {
        self.current
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .registry
            .clone()
    }

    /// Read the current registry with change dispatch held off.
    ///
    /// This is the critical section the Peers API requires of `v1.peer.watch`:
    /// insert the requested key into the connection's watch set and read its
    /// current record inside `read`, and no change to that key can land after
    /// the snapshot yet escape the new watch. Both [`Self::replace`] and
    /// [`Self::observe_endpoint`] publish and dispatch under the matching write
    /// lock, so the two orderings are mutually exclusive — either the watch ran
    /// first and precedes the notification, or the state change ran first and
    /// the watch already answers from the new published state.
    ///
    /// Nothing else is owed. The response may be serialized and written
    /// afterwards, from any task, in any order relative to notifications.
    ///
    /// `read` must not block or acquire the registry lock again; keep it to the
    /// watch-set insertion and one by-key lookup.
    pub(crate) fn read<T>(&self, with: impl FnOnce(PublishedView<'_>) -> T) -> T {
        let current = self
            .current
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        with(PublishedView {
            registry: current.registry.as_ref(),
            observed_endpoints: &current.observed_endpoints,
        })
    }

    /// Record a direct endpoint learned from authenticated tunnel traffic.
    ///
    /// The first observation is retained even when it equals configuration, so
    /// a later config reload cannot displace an endpoint that was actually
    /// authenticated. A notification is sent only when the *effective* served
    /// endpoint changes. Unknown keys are ignored and cannot grow runtime state.
    pub fn observe_endpoint(&self, public_key: [u8; 32], endpoint: SocketAddr) {
        let mut current = self
            .current
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(record) = current.registry.lookup_key(&public_key) else {
            return;
        };
        let before = current
            .observed_endpoints
            .get(&public_key)
            .copied()
            .or(record.endpoint);
        if current.observed_endpoints.get(&public_key) == Some(&endpoint) {
            return;
        }
        current.observed_endpoints.insert(public_key, endpoint);
        if before != Some(endpoint) {
            let _ = self.changes.send(RegistryChange { public_key });
        }
    }

    /// Subscribe to peer-level registry changes.
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<RegistryChange> {
        self.changes.subscribe()
    }

    /// Publish a completely validated replacement registry and notify keys
    /// whose *effective* served record changed.
    ///
    /// Learned endpoints survive configuration changes and continue to override
    /// `Endpoint` for the same cryptographic identity. They are discarded only
    /// when that public key disappears from the registry. A `Relay` change does
    /// not erase the observation: relay remains the routing authority while set,
    /// and the last authenticated direct endpoint is still the best fallback if
    /// direct routing is enabled again later.
    ///
    /// Both config publication and endpoint-observation dispatch use this same
    /// write lock, preserving the watch-creation ordering guaranteed by
    /// [`Self::read`].
    pub fn replace(&self, registry: Registry) {
        let mut current = self
            .current
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let old_registry = Arc::clone(&current.registry);
        let old_observed = current.observed_endpoints.clone();

        current
            .observed_endpoints
            .retain(|public_key, _| registry.lookup_key(public_key).is_some());

        let keys: HashSet<_> = old_registry
            .by_key
            .keys()
            .chain(registry.by_key.keys())
            .copied()
            .collect();
        let mut changed = Vec::new();
        for public_key in keys {
            let before = old_registry.lookup_key(&public_key);
            let after = registry.lookup_key(&public_key);
            let differs = match (before, after) {
                (None, Some(_)) | (Some(_), None) => true,
                (Some(before), Some(after)) => {
                    let before_endpoint =
                        old_observed.get(&public_key).copied().or(before.endpoint);
                    let after_endpoint = current
                        .observed_endpoints
                        .get(&public_key)
                        .copied()
                        .or(after.endpoint);
                    before.public_key != after.public_key
                        || before_endpoint != after_endpoint
                        || before.relay != after.relay
                        || before.persistent_keepalive != after.persistent_keepalive
                        || before.addresses != after.addresses
                }
                (None, None) => false,
            };
            if differs {
                changed.push(public_key);
            }
        }

        // Publish even when learned state masks every externally visible config
        // change. If the observation is later invalidated, fallback must use the
        // newest configuration rather than the snapshot from when it was learned.
        current.registry = Arc::new(registry);
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
        // The API server is allocator-backed through `microtun-std`, so the
        // const capacity is unused and the Patricia pool grows on demand.
        let mut routes: PrefixTrie<usize, 0> =
            PrefixTrie::new().expect("allocator-backed prefix trie initializes");
        let mut route_count = 0;

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
                if let Some(&owner) = routes.get(*cidr) {
                    return Err(format!(
                        "peers {} and {} both claim {cidr}",
                        peers[owner].key_prefix(),
                        record.key_prefix()
                    ));
                }
                routes
                    .insert(*cidr, index)
                    .expect("allocator-backed prefix trie grows on demand");
                route_count += 1;
            }
            by_key.insert(record.public_key, index);
            peers.push(record);
        }

        Ok(Self {
            peers,
            by_key,
            routes,
            route_count,
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
        self.routes.lookup(address).map(|&index| &self.peers[index])
    }

    /// Number of configured peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Number of indexed tunnel prefixes.
    pub fn route_count(&self) -> usize {
        self.route_count
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
    fn learned_endpoint_overrides_config_and_survives_endpoint_reload() {
        let key = [0x05; 32];
        let configured: SocketAddr = "198.51.100.5:51820".parse().unwrap();
        let reconfigured: SocketAddr = "198.51.100.50:51820".parse().unwrap();
        let roamed: SocketAddr = "203.0.113.5:42424".parse().unwrap();
        let make = |endpoint| {
            PeerRecord::new(
                key,
                Some(endpoint),
                None,
                vec!["10.0.0.5/32".parse().unwrap()],
                None,
            )
        };
        let shared = SharedRegistry::new(Registry::build(vec![make(configured)]).unwrap());
        let mut changes = shared.subscribe();

        // The first authenticated observation matters even when its value is
        // identical to configuration: it establishes provenance without
        // changing the served record, so no watch notification is needed.
        shared.observe_endpoint(key, configured);
        assert!(matches!(
            changes.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));

        // A config-only endpoint change cannot displace authenticated runtime
        // knowledge, but the new config is still published as the fallback.
        shared.replace(Registry::build(vec![make(reconfigured)]).unwrap());
        let effective = shared.read(|published| {
            let record = published.lookup_key(&key).unwrap();
            published.effective_endpoint(record)
        });
        assert_eq!(effective, Some(configured));
        assert_eq!(
            shared.config_snapshot().lookup_key(&key).unwrap().endpoint,
            Some(reconfigured)
        );
        assert!(matches!(
            changes.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));

        // A genuinely new authenticated source replaces the learned value and
        // does change the served record, so watched clients are invalidated.
        shared.observe_endpoint(key, roamed);
        let effective = shared.read(|published| {
            let record = published.lookup_key(&key).unwrap();
            published.effective_endpoint(record)
        });
        assert_eq!(effective, Some(roamed));
        assert_eq!(changes.try_recv().unwrap().public_key, key);
    }

    #[test]
    fn removing_peer_discards_learned_endpoint() {
        let key = [0x06; 32];
        let learned: SocketAddr = "203.0.113.6:60000".parse().unwrap();
        let configured: SocketAddr = "198.51.100.6:51820".parse().unwrap();
        let make = || {
            PeerRecord::new(
                key,
                Some(configured),
                None,
                vec!["10.0.0.6/32".parse().unwrap()],
                None,
            )
        };
        let shared = SharedRegistry::new(Registry::build(vec![make()]).unwrap());
        shared.observe_endpoint(key, learned);

        shared.replace(Registry::default());
        shared.replace(Registry::build(vec![make()]).unwrap());
        let effective = shared.read(|published| {
            let record = published.lookup_key(&key).unwrap();
            published.effective_endpoint(record)
        });
        assert_eq!(effective, Some(configured));
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
