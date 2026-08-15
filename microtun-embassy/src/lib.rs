//! # microtun-embassy
//!
//! [embassy](https://embassy.dev) async integration for [`microtun_core`].
//!
//! This crate turns the sans-IO [`Core`](microtun_core::Core) into a running
//! tunnel on `no_std` embassy targets. The design is the one settled in the
//! project notes:
//!
//! * A single [`TunnelRunner`] task owns the
//!   `Core` and drives it from four
//!   event sources — the *outer* UDP socket (encrypted WireGuard traffic to
//!   the internet-facing peer/Peers API server endpoints), the tunnel device's
//!   outbound queue (plaintext IP packets the inner stack wants to send), the
//!   resolver-event channel, and the `Core`'s own timer via
//!   [`Core::poll_at`](microtun_core::Core::poll_at). This crate enables the
//!   core's async feature, so sink output is awaited directly on the UDP socket
//!   or tunnel device without a local packet queue. Timeout handling remains
//!   incremental: one due timer action is run, and an immediately-due
//!   `poll_at` re-enters for the next action.
//! * The tunnel is exposed to the rest of the firmware as an
//!   [`embassy_net_driver_channel::Device`], so the application runs an
//!   ordinary inner `embassy-net` stack *over the tunnel* and gets sockets,
//!   DNS, static addressing, etc. for free.
//! * Peer resolution runs in a second task, [`resolver_task`], joined with
//!   the tunnel loop via [`embassy_futures::join`]. One persistent JSON-RPC
//!   connection over the **inner** stack carries lookups and pushed
//!   `v1.peer.changed` / `v1.peer.removed` keyed invalidations, so the only bootstrap
//!   dependency is the pinned Peers API server peer. Reconnect re-watches every
//!   peer the core still holds.
//!
//! ## Allocator-backed core state
//!
//! By default this crate keeps `microtun-core` allocator-free, preserving the
//! fixed-storage behavior expected by bare-metal Embassy targets. Enabling this
//! crate's `alloc` feature forwards to `microtun-core/alloc`, moving the core's
//! large bounded tables and packet scratch storage behind the application's
//! global allocator. This is useful on heap-capable MCUs such as ESP32-C3 where
//! async task stacks are comparatively small. The protocol capacities remain
//! bounded by the same const generics, and the runner applies
//! [`runner::embedded_core_config`] so active rate, firewall and under-load
//! policy stays embedded-sized rather than silently inheriting the core's
//! host-sized defaults; only the core storage backend changes. A caller that
//! supplies its own tuned `CoreConfig` keeps it — the profile is applied only
//! when the caller left the defaults alone.
//!
//! That profile lives here rather than in `microtun-core` on purpose. The
//! core is sans-IO and has no business knowing whether it is running on a
//! microcontroller or a hub — and cannot know, since the peer-table capacity
//! most policy scales against is a const generic chosen here. It publishes
//! storage ceilings and a
//! [`CoreConfig::validate_against_limits`](microtun_core::CoreConfig::validate_against_limits)
//! check; the embedding chooses the policy to inject. `microtun-std` does the
//! same with its own host profile.
//!
//! ## The resolver deadlock, and why `try_send`
//!
//! Resolver responses arrive as ordinary inner packets, so they flow
//! *through the tunnel loop* before reaching the resolver task. If the tunnel
//! loop ever `await`ed on a full channel toward the resolver, it could block
//! the very path the resolver's response needs — a deadlock. Resolver output
//! therefore arrives through [`microtun_core::Sink`] callbacks that only
//! `try_send` into the command channel. A full channel makes the callback reject
//! the operation, leaving it in the core for a later iteration without blocking
//! the packet path.

#![no_std]
#![deny(unsafe_code)]

/// Tunnel (inner) MTU. 1280 is the IPv6 minimum link MTU and leaves ample
/// headroom for the outer transport and optional relay envelope.
pub const MTU: usize = 1280;

/// Embedded peer/session/replay/route capacities.
pub const MAX_PEERS: usize = 4;

/// Session-slot capacity: four per peer.
///
/// A peer can hold `current`, `previous`, `next` and `handshake` at once, and
/// holding two of them is ordinary steady state rather than a transient — a
/// rotation parks the outgoing session in `previous` until it reaches
/// `REJECT_AFTER_TIME`, which with a 120-second rekey against a 180-second
/// lifetime is a third of every cycle. Sizing this at `MAX_PEERS` meant a
/// fully-populated device could not seat its own peers: it evicted live
/// sessions to make room for handshakes, and it sat permanently below
/// `UNDER_LOAD_FREE_SLOTS`, so every handshake ate a cookie round trip
/// forever.
///
/// The allocation-free peer and session index structures require powers of
/// two greater than one, so the practical steps here are 16 and 32.
pub const MAX_SESSIONS: usize = 16;

/// Replay bitmap words per established session.
///
/// One word is reserved for recycling, so this accepts packets up to
/// `(32 - 1) * 64 = 1,984` counters behind the high-water mark. The reference
/// implementations use 128 words (8,128 counters) because they are servicing
/// multi-core senders that genuinely reorder that far; a constrained device on
/// a single link does not, and the difference is roughly 0.8 KiB *per session
/// slot*. Trading it back is what pays for the pool above: four times the
/// sessions for about 2 KiB more than the old eight-slot, 128-word pool cost.
pub const REPLAY_WORDS: usize = 32;

/// Each peer owns exactly one route, so route capacity matches peer capacity.
pub const MAX_ROUTES: usize = MAX_PEERS;

/// Post-cookie per-source handshake allowance. Tighter than the core's
/// wireguard-go-matching default: a device with a handful of peers has no
/// legitimate need for twenty per second from one source.
pub const RATE_LIMIT_PER_SEC: u32 = 2;
pub const RATE_LIMIT_BURST: u32 = 4;
pub const RATE_LIMIT_ENTRIES: usize = 64;
/// Handshakes per second above which this device engages the cookie
/// machinery.
pub const UNDER_LOAD_HANDSHAKES_PER_SEC: u32 = 8;
/// Ingress firewall table, and the share of it any one peer may hold. The
/// quota only isolates peers when it is a small fraction of the table.
pub const FIREWALL_FLOW_ENTRIES: usize = 64;
pub const FIREWALL_FLOWS_PER_PEER: usize = 8;
/// Churn brake on destructive capacity evictions. Ten seconds per eviction is
/// an anti-thrash floor that suits a peer table this small.
pub const PEER_EVICTION_INTERVAL: microtun_core::Duration = microtun_core::Duration::from_secs(10);
pub const PEER_EVICTION_GHOSTS: usize = 8;
/// Live resolver queries plus negative markers tracked at once.
///
/// [`crate::resolver::CHANNEL_DEPTH`] must be at least this, or the channel
/// silently becomes the real concurrency bound instead of this value.
pub const INFLIGHT_RESOLVES: usize = 12;

pub mod device;
pub mod resolver;
pub mod runner;

pub use device::{TunnelDevice, TunnelState, new_tunnel, new_tunnel_with_mtu};
pub use microtun_api as peers_api;
/// Convenience re-exports so downstream firmware needs only this crate.
pub use microtun_core as core;
pub use resolver::{
    CHANNEL_DEPTH as RESOLVER_CHANNEL_DEPTH, ResolverBuffers, ResolverChannels, ResolverConfig,
    resolver_task,
};
pub use runner::{OUTER_SIZE, TunnelRunner};
