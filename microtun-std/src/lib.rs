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
//! * Peers API resolver lookup completions and watched-peer updates, and
//! * the core's next timer deadline.
//!
//! This crate enables `microtun-core/async`, and packet outputs are awaited
//! directly on the UDP socket and tunnel device without an intermediate output
//! queue. Resolver commands are transferred to a separate task only after the
//! runner reserves bounded-channel capacity without waiting. A full queue
//! leaves the command in the core, so the tunnel loop cannot deadlock the
//! resolver's response path or lose watch-set mutations.
//!
//! Lookups, watch mutations, and pushed peer updates share one continuously
//! serviced JSON-RPC stream to the Peers API server's inner address. After reconnect
//! the resolver replays the complete watch set on that same stream. Opening the
//! stream is the caller's job — see [`PeersApiTransport`] and the security notes on
//! [`PeersApiResolver`].

#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]
#![allow(async_fn_in_trait)]

pub mod resolver;
pub mod runner;

pub use microtun_api as peers_api;
/// Convenience re-exports so host applications can depend on this crate alone.
pub use microtun_core as core;
pub use resolver::{PeersApiResolver, PeersApiTransport, resolver_task};
pub use runner::{
    Error, MAX_IP_PACKET_SIZE, OUTER_SIZE, PEERS, RESOLVER_QUEUE_DEPTH, ROUTES, SESSIONS,
    TunnelCore, TunnelDevice, TunnelRunner,
};

#[cfg(test)]
mod tests {
    use microtun_core::CoreConfig;

    #[test]
    fn standard_runtime_receives_host_sized_core_defaults() {
        let config = CoreConfig::default();
        assert_eq!(config.rate_limit_entries, 1_024);
        assert_eq!(config.firewall_flow_entries, 4_096);
        assert_eq!(config.firewall_flows_per_peer, 128);
    }
}
