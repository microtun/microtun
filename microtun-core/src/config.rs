//! Engine configuration: interface identity, bootstrap peers, and runtime tunables.
//!
//! Pinned peers are the bootstrap peers of a microtun deployment. They are
//! loaded at init, can never be evicted, and their tunnel address prefixes
//! live in the route cache without a resolver watch or polling deadline.

use core::net::SocketAddr;

use zeroize::Zeroizing;

use crate::{
    IpCidr,
    constants::*,
    firewall::{DEFAULT_FIREWALL_FLOWS, DEFAULT_FIREWALL_FLOWS_PER_PEER, InboundPolicy},
    time::Duration,
};

/// A configured, non-evictable bootstrap peer.
#[derive(Debug, Clone, Copy)]
pub struct PinnedPeer<'a> {
    /// The peer's static Curve25519 public key.
    pub public_key: [u8; 32],
    /// Initial outer endpoint. Required for directly reachable peers
    /// (without it the bootstrap handshake has nowhere to go); may be
    /// `None` when `relay` is set. Roaming may update it later. An
    /// IPv4-mapped IPv6 endpoint is stored as native IPv4 by the core.
    pub endpoint: Option<SocketAddr>,
    /// Optional relay: the static public key of another peer through which
    /// this peer is reached (relay protocol §4, `relay(B) = R`). The relay
    /// itself must be a configured peer with a direct endpoint. Exactly one
    /// of a direct `endpoint` or a `relay` must be usable for outbound
    /// traffic; when `relay` is set it is the routing authority (relay spec §9).
    pub relay: Option<[u8; 32]>,
    /// Tunnel address prefixes assigned to this peer, pre-seeded into the
    /// route cache without expiry.
    pub addresses: &'a [IpCidr],
    /// Ingress policy applied to authenticated inner packets from this peer.
    pub inbound_policy: InboundPolicy,
    /// WireGuard-style persistent keepalive interval. When set, the core
    /// periodically sends an authenticated empty transport packet while the
    /// peer is otherwise idle. `None` disables persistent keepalives.
    pub persistent_keepalive: Option<Duration>,
}

/// Per-engine operational tunables.
///
/// Values are copied into [`crate::Core`] during construction, so different
/// engines in one process may use different settings without recompiling.
/// [`Default`] applies the recommended bounded-resource and peer-churn policy.
/// Defaults are backend-aware: allocation-free builds retain embedded table
/// sizes, while `alloc` builds use host-sized rate-limit and firewall tables.
/// WireGuard protocol constants and capacities represented by [`crate::Core`]'s
/// const generic parameters deliberately do not appear here. Storage-backed
/// implementation limits must not exceed their documented compile-time
/// ceilings; [`crate::Core::new`] rejects configurations that do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreConfig {
    /// Deadline for a by-key lookup request.
    pub resolve_timeout: Duration,
    /// Maximum time an outbound packet waits for by-address resolution.
    pub resolve_outbound_timeout: Duration,
    /// Lifetime of an authoritative negative resolver result.
    pub negative_ttl: Duration,
    /// Minimum idle time before a sessionless dynamic peer may be evicted for capacity.
    pub dynamic_peer_min_idle: Duration,
    /// Refill interval for the global destructive peer-eviction budget.
    pub peer_eviction_interval: Duration,
    /// Number of destructive peer evictions initially available and bankable.
    pub peer_eviction_burst: u32,
    /// How long a capacity-evicted identity is denied immediate re-admission.
    pub peer_eviction_ghost_ttl: Duration,
    /// Number of recently evicted identities retained. Must be no greater than
    /// [`crate::MAX_CORE_PEER_EVICTION_GHOSTS`]. Zero disables ghost tracking.
    pub peer_eviction_ghost_entries: usize,
    /// Per-authenticated-submitter interval for relay-driven unknown-destination lookups.
    /// Zero disables the per-submitter gate; the global remote-resolve budget remains.
    pub relay_resolve_min_interval: Duration,
    /// Peer-table slots reserved from all unauthenticated lazy-cache installs.
    /// Authenticated unknown initiators may consume the reserve.
    pub lazy_peer_reserve: usize,
    /// Legacy endpoint-confirmation interval retained for configuration/API
    /// compatibility. Accepted resolver records are complete replacements, so
    /// this value no longer lets a previously roamed endpoint override them.
    pub endpoint_confirmation_ttl: Duration,
    /// Stateful firewall lifetime for UDP flows.
    pub firewall_udp_timeout: Duration,
    /// Stateful firewall lifetime for ICMP echo flows.
    pub firewall_icmp_timeout: Duration,
    /// Stateful firewall lifetime for established TCP flows.
    pub firewall_tcp_timeout: Duration,
    /// Stateful firewall lifetime for closing TCP flows.
    pub firewall_tcp_closing_timeout: Duration,
    /// Active firewall flow-table limit. Must be no greater than
    /// [`crate::firewall::MAX_FIREWALL_FLOWS`].
    pub firewall_flow_entries: usize,
    /// Maximum live firewall flows owned by one peer. A peer at this limit
    /// can only recycle its own entries, preventing cross-peer state eviction.
    pub firewall_flows_per_peer: usize,
    /// Handshakes in the current or previous one-second window that engage cookies.
    pub under_load_handshakes_per_sec: u32,
    /// Remaining session slots at or below which the core considers itself under load.
    pub under_load_free_slots: usize,
    /// Sustained per-source handshake allowance after cookie validation.
    pub rate_limit_per_sec: u32,
    /// Per-source handshake burst after cookie validation.
    pub rate_limit_burst: u32,
    /// Active per-source rate-limiter table limit. Must be no greater than
    /// [`crate::MAX_CORE_RATE_LIMIT_ENTRIES`].
    pub rate_limit_entries: usize,
    /// Sustained allowance for resolver work provoked by remote input.
    pub remote_resolve_per_sec: u32,
    /// Burst allowance for resolver work provoked by remote input.
    pub remote_resolve_burst: u32,
    /// Sustained allowance for authenticating unknown initiators.
    pub unknown_auth_per_sec: u32,
    /// Burst allowance for authenticating unknown initiators.
    pub unknown_auth_burst: u32,
    /// Active resolver bookkeeping limit. Must be no greater than
    /// [`crate::MAX_CORE_INFLIGHT_RESOLVES`].
    pub max_inflight_resolves: usize,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            resolve_timeout: RESOLVE_TIMEOUT,
            resolve_outbound_timeout: RESOLVE_OUTBOUND_TIMEOUT,
            negative_ttl: NEGATIVE_TTL,
            dynamic_peer_min_idle: DYNAMIC_PEER_MIN_IDLE,
            peer_eviction_interval: PEER_EVICTION_INTERVAL,
            peer_eviction_burst: PEER_EVICTION_BURST,
            peer_eviction_ghost_ttl: PEER_EVICTION_GHOST_TTL,
            peer_eviction_ghost_entries: DEFAULT_PEER_EVICTION_GHOSTS,
            relay_resolve_min_interval: RELAY_RESOLVE_MIN_INTERVAL,
            lazy_peer_reserve: LAZY_PEER_RESERVE,
            endpoint_confirmation_ttl: ENDPOINT_CONFIRMATION_TTL,
            firewall_udp_timeout: FIREWALL_UDP_TIMEOUT,
            firewall_icmp_timeout: FIREWALL_ICMP_TIMEOUT,
            firewall_tcp_timeout: FIREWALL_TCP_TIMEOUT,
            firewall_tcp_closing_timeout: FIREWALL_TCP_CLOSING_TIMEOUT,
            firewall_flow_entries: DEFAULT_FIREWALL_FLOWS,
            firewall_flows_per_peer: DEFAULT_FIREWALL_FLOWS_PER_PEER,
            under_load_handshakes_per_sec: UNDER_LOAD_HANDSHAKES_PER_SEC,
            under_load_free_slots: UNDER_LOAD_FREE_SLOTS,
            rate_limit_per_sec: RATE_LIMIT_PER_SEC,
            rate_limit_burst: RATE_LIMIT_BURST,
            rate_limit_entries: DEFAULT_RATE_LIMIT_ENTRIES,
            remote_resolve_per_sec: REMOTE_RESOLVE_PER_SEC,
            remote_resolve_burst: REMOTE_RESOLVE_BURST,
            unknown_auth_per_sec: UNKNOWN_AUTH_PER_SEC,
            unknown_auth_burst: UNKNOWN_AUTH_BURST,
            max_inflight_resolves: MAX_INFLIGHT_RESOLVES,
        }
    }
}

/// Engine configuration.
pub struct Config<'a> {
    /// The interface's static private key (burnt into flash on real
    /// devices). The public key is derived at init. The key is deliberately
    /// non-`Copy` and is wiped when its owner is dropped.
    pub private_key: Zeroizing<[u8; 32]>,
    /// Configured bootstrap peers, borrowed only for construction.
    pub pinned: &'a [PinnedPeer<'a>],
    /// Runtime operational settings.
    pub core_config: CoreConfig,
}

impl<'a> Config<'a> {
    /// Build a configuration while taking ownership of the static private
    /// key. The key will be zeroized when this configuration, or the core
    /// that consumes it, is dropped. Runtime tunables use
    /// [`CoreConfig::default`], including backend-appropriate host or embedded
    /// state-table capacities.
    pub fn new(private_key: [u8; 32], pinned: &'a [PinnedPeer<'a>]) -> Self {
        Self {
            private_key: Zeroizing::new(private_key),
            pinned,
            core_config: CoreConfig::default(),
        }
    }

    /// Replace the default runtime tunables.
    pub fn with_core_config(mut self, core: CoreConfig) -> Self {
        self.core_config = core;
        self
    }
}

impl core::fmt::Debug for Config<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Config")
            .field("private_key", &"[REDACTED]")
            .field("pinned", &self.pinned)
            .field("core_config", &self.core_config)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_config_defaults_are_complete_and_stable() {
        assert_eq!(
            CoreConfig::default(),
            CoreConfig {
                resolve_timeout: RESOLVE_TIMEOUT,
                resolve_outbound_timeout: RESOLVE_OUTBOUND_TIMEOUT,
                negative_ttl: NEGATIVE_TTL,
                dynamic_peer_min_idle: DYNAMIC_PEER_MIN_IDLE,
                peer_eviction_interval: PEER_EVICTION_INTERVAL,
                peer_eviction_burst: PEER_EVICTION_BURST,
                peer_eviction_ghost_ttl: PEER_EVICTION_GHOST_TTL,
                peer_eviction_ghost_entries: DEFAULT_PEER_EVICTION_GHOSTS,
                relay_resolve_min_interval: RELAY_RESOLVE_MIN_INTERVAL,
                lazy_peer_reserve: LAZY_PEER_RESERVE,
                endpoint_confirmation_ttl: ENDPOINT_CONFIRMATION_TTL,
                firewall_udp_timeout: FIREWALL_UDP_TIMEOUT,
                firewall_icmp_timeout: FIREWALL_ICMP_TIMEOUT,
                firewall_tcp_timeout: FIREWALL_TCP_TIMEOUT,
                firewall_tcp_closing_timeout: FIREWALL_TCP_CLOSING_TIMEOUT,
                firewall_flow_entries: DEFAULT_FIREWALL_FLOWS,
                firewall_flows_per_peer: DEFAULT_FIREWALL_FLOWS_PER_PEER,
                under_load_handshakes_per_sec: UNDER_LOAD_HANDSHAKES_PER_SEC,
                under_load_free_slots: UNDER_LOAD_FREE_SLOTS,
                rate_limit_per_sec: RATE_LIMIT_PER_SEC,
                rate_limit_burst: RATE_LIMIT_BURST,
                rate_limit_entries: DEFAULT_RATE_LIMIT_ENTRIES,
                remote_resolve_per_sec: REMOTE_RESOLVE_PER_SEC,
                remote_resolve_burst: REMOTE_RESOLVE_BURST,
                unknown_auth_per_sec: UNKNOWN_AUTH_PER_SEC,
                unknown_auth_burst: UNKNOWN_AUTH_BURST,
                max_inflight_resolves: MAX_INFLIGHT_RESOLVES,
            }
        );
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn alloc_defaults_are_host_sized() {
        let config = CoreConfig::default();
        assert_eq!(config.rate_limit_entries, 1_024);
        assert_eq!(config.firewall_flow_entries, 4_096);
        assert_eq!(config.firewall_flows_per_peer, 128);
        assert!(config.rate_limit_entries <= MAX_RATE_LIMIT_ENTRIES);
        assert!(config.firewall_flow_entries <= crate::firewall::MAX_FIREWALL_FLOWS);
    }

    #[test]
    #[cfg(not(feature = "alloc"))]
    fn allocation_free_defaults_remain_embedded_sized() {
        let config = CoreConfig::default();
        assert_eq!(config.rate_limit_entries, 64);
        assert_eq!(config.firewall_flow_entries, 16);
        assert_eq!(config.firewall_flows_per_peer, 8);
    }
}
