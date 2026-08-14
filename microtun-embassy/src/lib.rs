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
//! bounded by the same const generics, and the runner retains embedded-sized
//! active rate/firewall limits; only the core storage backend changes.
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

pub mod device;
pub mod resolver;
pub mod runner;

pub use device::{TunnelState, new_tunnel};
pub use microtun_api as peers_api;
/// Convenience re-exports so downstream firmware needs only this crate.
pub use microtun_core as core;
pub use resolver::{ResolverBuffers, ResolverChannels, ResolverConfig, resolver_task};
pub use runner::{MTU, OUTER_SIZE, TunnelRunner};
