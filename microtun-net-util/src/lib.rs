//! Shared networking utilities for microtun host tools and embedded targets.
//!
//! The crate owns reusable network-domain behavior:
//!
//! - fallback-link addressing and stable device network names,
//! - mDNS/DNS-SD discovery and responders for `std` and Embassy-net,
//! - a small Embassy-net DHCP server for the fallback link,
//! - an Embassy-net ICMP ping command runner using `embedded_io_async::Write`.

#![no_std]
#![deny(unsafe_code)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "embassy-net")]
pub mod dhcp;
mod link;
#[cfg(any(feature = "std", feature = "embassy-net"))]
pub mod mdns;
#[cfg(feature = "ping")]
pub mod ping;

pub use link::{
    DEVICE_AP_SSID_PREFIX, DEVICE_HOSTNAME_PREFIX, FALLBACK_DEVICE_IPV4, FALLBACK_DHCP_RANGE_END,
    FALLBACK_DHCP_RANGE_START, FALLBACK_HOST_IPV4, FALLBACK_IPV4_PREFIX_LEN,
    MAX_DEVICE_HOSTNAME_LEN, MAX_SSID_LEN, MDNS_MULTICAST_IPV4, MDNS_PORT, MICROTUN_MDNS_SERVICE,
    device_ap_ssid, device_hostname,
};
