//! Well-known fallback-link addressing and device network names.
//!
//! Embedded targets can use these values when they need to bring up an isolated
//! local link without an upstream DHCP server. The device uses a fixed address,
//! serves a small DHCP pool, and advertises its stable `microtun-<device_id>.local`
//! hostname through mDNS and, on wireless targets, the matching bare label as the
//! access-point SSID.
//!
//! The fallback subnet is deliberately local-only: no gateway or DNS server is
//! advertised. Because the device address is fixed, only one device should use a
//! given wired fallback segment at a time. Wireless targets naturally isolate the
//! same address behind their per-device access point.

use heapless::String;

/// IPv4 address used by a device on the fallback link, in network order.
pub const FALLBACK_DEVICE_IPV4: [u8; 4] = [192, 168, 7, 1];

/// First address conventionally used by a host on the fallback link.
pub const FALLBACK_HOST_IPV4: [u8; 4] = [192, 168, 7, 2];

/// First address in the fallback-link DHCP pool.
pub const FALLBACK_DHCP_RANGE_START: [u8; 4] = FALLBACK_HOST_IPV4;

/// Last address in the fallback-link DHCP pool.
pub const FALLBACK_DHCP_RANGE_END: [u8; 4] = [192, 168, 7, 20];

/// Prefix length shared by the fallback device address and DHCP leases.
pub const FALLBACK_IPV4_PREFIX_LEN: u8 = 24;

/// IPv4 multicast group used by mDNS.
pub const MDNS_MULTICAST_IPV4: [u8; 4] = [224, 0, 0, 251];

/// UDP port used by mDNS.
pub const MDNS_PORT: u16 = 5353;

/// DNS-SD service advertised by microtun devices.
pub const MICROTUN_MDNS_SERVICE: &str = "_microtun._tcp.local";

/// Prefix shared by the device DHCP/mDNS hostname and access-point SSID.
pub const DEVICE_HOSTNAME_PREFIX: &str = "microtun-";

/// Maximum hostname length accepted by Embassy-net's DHCPv4 hostname support.
pub const MAX_DEVICE_HOSTNAME_LEN: usize = 32;

/// Prefix used for a device-hosted wireless access point.
pub const DEVICE_AP_SSID_PREFIX: &str = DEVICE_HOSTNAME_PREFIX;

/// Maximum length of an IEEE 802.11 SSID.
pub const MAX_SSID_LEN: usize = 32;

/// Build the stable bare network hostname for a device ID.
///
/// DHCP can send this label as Option 12 while mDNS appends `.local` to it.
/// Returns `None` when the supplied ID would exceed the fixed-capacity hostname.
pub fn device_hostname(device_id: &str) -> Option<String<MAX_DEVICE_HOSTNAME_LEN>> {
    let mut hostname = String::new();
    hostname.push_str(DEVICE_HOSTNAME_PREFIX).ok()?;
    hostname.push_str(device_id).ok()?;
    Some(hostname)
}

/// Build the SSID used by a device-hosted wireless access point.
///
/// The SSID intentionally matches the bare device hostname so operators see the
/// same stable label in DHCP, mDNS, and Wi-Fi discovery.
pub fn device_ap_ssid(device_id: &str) -> Option<String<MAX_SSID_LEN>> {
    let mut ssid = String::new();
    ssid.push_str(DEVICE_AP_SSID_PREFIX).ok()?;
    ssid.push_str(device_id).ok()?;
    Some(ssid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_is_the_prefixed_device_id() {
        assert_eq!(
            device_hostname("0svmx1udh1").unwrap().as_str(),
            "microtun-0svmx1udh1"
        );
    }

    #[test]
    fn ssid_is_the_prefixed_device_id() {
        assert_eq!(
            device_ap_ssid("0svmx1udh1").unwrap().as_str(),
            "microtun-0svmx1udh1"
        );
    }

    #[test]
    fn oversized_device_id_is_rejected() {
        assert!(device_hostname("abcdefghijklmnopqrstuvwxyz").is_none());
        assert!(device_ap_ssid("abcdefghijklmnopqrstuvwxyz").is_none());
    }
}
