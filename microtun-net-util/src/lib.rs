//! Shared networking utilities for microtun host tools and embedded targets.
//!
//! The crate keeps networking helpers that are useful outside any one product
//! concern in a top-level home:
//!
//! - provisioning-mode mDNS/DNS-SD discovery and responders for `std` and
//!   Embassy-net,
//! - an Embassy-net ICMP ping command runner using `embedded_io_async::Write`.

#![no_std]
#![deny(unsafe_code)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(any(feature = "std", feature = "embassy-net"))]
pub mod mdns;
#[cfg(feature = "ping")]
pub mod ping;
