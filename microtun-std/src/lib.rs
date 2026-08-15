//! # microtun-std
//!
//! Tokio/`std` integration for [`microtun_core`].
//!
//! This crate is the host-runtime counterpart to `microtun-embassy`: it turns
//! the sans-IO [`Core`](microtun_core::Core) into an async tunnel runner and
//! provides a stateful JSON-RPC Peers API resolver. It deliberately does not create or
//! configure an operating-system tunnel interface. Applications supply a
//! [`TunnelDevice`] implementation and retain control of platform-specific
//! setup, permissions, routing, and configuration parsing.
//!
//! The runner owns the protocol core and drives it from four event sources:
//!
//! * encrypted datagrams from a Tokio UDP socket,
//! * plaintext packets received from the supplied tunnel device,
//! * Peers API resolver lookup completions and peer-change updates, and
//! * the core's next timer deadline.
//!
//! This crate enables `microtun-core/async`, and packet outputs are awaited
//! directly on the UDP socket and tunnel device without an intermediate output
//! queue. Resolver requests arrive through [`microtun_core::Sink::resolve`] and
//! are forwarded to the resolver task with a non-blocking bounded-channel send.
//! Dynamic peer releases arrive as [`microtun_core::Event::PeerEvicted`] sink
//! events; the runner forwards local forget commands to the resolver, retaining
//! them locally if the resolver channel is temporarily full. The tunnel loop therefore never awaits resolver-channel capacity on
//! the packet path.
//!
//! Lookups and pushed `v1.peer.changed` / `v1.peer.removed` keyed invalidations share
//! one continuously serviced JSON-RPC stream to the Peers API server's inner
//! address. After
//! reconnect the resolver re-watches every peer the core still holds. Opening the
//! stream is the caller's job — see [`PeersApiTransport`] and the security notes on
//! [`PeersApiResolver`].

#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(async_fn_in_trait)]

// Host peer/session/replay/route capacities.
//
// This crate enables `microtun-core/alloc`, so these are upper bounds on
// heap-backed pools rather than the lengths of inline arrays: a `TunnelCore`
// is small enough to move around freely and does not have to be boxed or
// placed in a `static`. They are still real limits — a full peer table evicts
// the least-recently-active dynamic peer, and a full route cache is an error —
// so they are sized for a host rather than made unbounded.
//
// The index-addressed pools are allocated at their full length when the core
// is built, so raising these trades a one-off heap allocation (roughly
// `MAX_PEERS` × 400 B plus `MAX_SESSIONS` × roughly 1.2 KiB with
// `REPLAY_WORDS = 128`, so a little over 600 KiB at the sizes below)
// for headroom, and costs nothing on the stack.

/// Maximum number of peers, including pinned and dynamically resolved peers.
pub const MAX_PEERS: usize = 128;

/// Maximum number of session slots, shared by handshakes and live sessions.
///
/// Four per peer, which is the worst case a peer can actually reach:
/// `current`, `previous`, `next` and `handshake` at once. Two of those are
/// ordinary steady state rather than a transient, because a rotation parks
/// the outgoing session in `previous` until it reaches `REJECT_AFTER_TIME` —
/// a third of every rekey cycle with the whitepaper's 120-against-180-second
/// timers.
///
/// The two-times sizing this used to carry was exactly enough for 128 peers
/// holding `current` and `previous` and nothing left for the handshakes, and
/// a correlated fleet reaches that state together: sessions established
/// inside one second all rotate inside one second. The core now spreads the
/// rekey trigger (see `REKEY_AFTER_TIME_JITTER_MAX`), which makes the
/// correlated case rare rather than periodic, but the pool should not be
/// sized on the assumption that jitter always wins.
pub const MAX_SESSIONS: usize = 512;

/// Replay bitmap words per established session. 128 matches the reference
/// implementations' 8,128-counter trailing window.
///
/// Unlike the embedded shells, a host has no reason to trade this down: it is
/// genuinely servicing senders that reorder, and roughly 1.2 KiB per slot is
/// not a constraint here.
pub const REPLAY_WORDS: usize = 128;
/// Default route-cache sizing for the host runner. Each peer owns one route.
pub const MAX_ROUTES: usize = MAX_PEERS;
/// Bounded request and response queue depth used by [`TunnelRunner::run`].
///
/// The core tracks up to `CoreConfig::max_inflight_resolves` lookups at once
/// and every one of them crosses this channel, so a shallower queue quietly
/// becomes the real concurrency bound rather than the configured limit. Sized
/// from [`INFLIGHT_RESOLVES`] with headroom for pushed change notifications
/// sharing the response channel.
pub const RESOLVER_QUEUE_DEPTH: usize = 128;

/// Peer-table slots reserved for peers that authenticate, keeping
/// unauthenticated lazy-cache installs from filling the table.
///
/// The core's default is a flat 1, which is a meaningful fraction of an
/// eight-entry embedded table and essentially nothing against a host-sized
/// one. Derived from [`MAX_PEERS`] so it stays a fraction rather than a
/// constant as the table grows.
pub const LAZY_PEER_RESERVE: usize = MAX_PEERS / 16;

/// Live resolver queries plus negative markers tracked at once.
///
/// This budget is shared between in-flight lookups and the spent negative
/// markers that suppress repeat queries for authoritatively-unknown targets,
/// and a live query always wins a slot over a marker. Under-sizing it
/// therefore does not merely evict markers early, it silently turns the
/// negative cache off — every repeat lookup for an unknown target becomes a
/// fresh Peers API query. A host fronting a fleet meets far more distinct
/// unknown targets inside one negative-cache TTL than a sensor does.
pub const INFLIGHT_RESOLVES: usize = 64;

/// Handshakes per second above which the responder engages cookies.
///
/// The core's cross-backend default is tuned for a device with a handful of
/// peers. On a hub the busiest *legitimate* moment is the whole fleet
/// arriving at once after a restart, which trivially exceeds a small
/// threshold and would otherwise make the two-round-trip handshake the normal
/// case rather than the exception it is meant to be.
pub const UNDER_LOAD_HANDSHAKES_PER_SEC: u32 = 64;

/// Refill interval for destructive capacity evictions.
///
/// This is a churn brake, and the right cadence depends on how many peers
/// there are to churn through. Ten seconds per eviction is a sensible
/// anti-thrash floor for an eight-peer device; against a 128-entry table it
/// means over twenty minutes to cycle, so any deployment whose genuine churn
/// exceeds six peers per minute never converges and simply refuses new peers
/// indefinitely.
pub const PEER_EVICTION_INTERVAL: microtun_core::Duration = microtun_core::Duration::from_secs(1);

/// Recently capacity-evicted identities retained to break A/B/A/B thrash
/// cycles. Sixteen entries cover sixteen seconds of a sixty-second ghost TTL
/// at the eviction cadence above, which breaks nothing.
pub const PEER_EVICTION_GHOSTS: usize = 64;

pub mod resolver;
pub mod runner;

pub use microtun_api as peers_api;
/// Convenience re-exports so host applications can depend on this crate alone.
pub use microtun_core as core;
pub use resolver::{PeersApiResolver, PeersApiTransport, resolver_task};
pub use runner::{
    Error, MAX_IP_PACKET_SIZE, OUTER_SIZE, TunnelCore, TunnelDevice, TunnelObserver, TunnelRunner,
    host_core_config,
};

#[cfg(test)]
mod tests {
    use microtun_core::CoreConfig;

    /// The core sizes *storage* against its backend, and this crate always
    /// builds it with `alloc`.
    #[test]
    fn standard_runtime_receives_heap_backed_core_storage_defaults() {
        let config = CoreConfig::default();
        assert_eq!(config.rate_limit_entries, 1_024);
        assert_eq!(config.firewall_flow_entries, 4_096);
        assert_eq!(config.firewall_flows_per_peer, 128);
    }

    /// *Policy* is this crate's to choose, not the core's, and the profile
    /// has to be one the core will actually accept — otherwise
    /// `TunnelRunner::new` is a constructor that always fails.
    #[test]
    fn the_host_profile_is_constructible_and_scaled_to_the_peer_table() {
        let config = crate::host_core_config();
        config
            .validate_against_limits()
            .expect("the injected host profile must be constructible");

        assert_eq!(config.lazy_peer_reserve, crate::MAX_PEERS / 16);
        assert!(
            config.lazy_peer_reserve > CoreConfig::default().lazy_peer_reserve,
            "a host-sized peer table needs more than the core's flat reserve"
        );
        assert!(
            config.under_load_handshakes_per_sec
                > CoreConfig::default().under_load_handshakes_per_sec,
            "a fleet arriving at once must not be mistaken for an attack"
        );
        assert!(
            config.peer_eviction_interval < CoreConfig::default().peer_eviction_interval,
            "a host-sized peer table must be able to cycle in reasonable time"
        );
    }
}
