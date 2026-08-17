//! Well-known static link an unprovisioned device brings up.
//!
//! This module covers both halves of "how is a device that has never been
//! configured reachable at all": the fixed IPv4 addressing, and — for wireless
//! targets that have to create the network themselves — the SSID they
//! advertise.
//!
//! On an isolated provisioning link the device assigns itself a fixed address
//! and may serve DHCP so the provisioning host configures itself automatically.
//! Wired targets can first probe as a DHCP client: if an existing server answers,
//! they remain a client on that network; if not, they fall back to the dedicated
//! provisioning subnet and its tiny DHCP pool. Wireless targets that create their
//! own provisioning-mode access point can serve the fallback DHCP pool immediately.
//! In either case provisioning firmware can advertise [`PROVISION_MDNS_SERVICE`]
//! over mDNS/DNS-SD so a host can discover the current address without knowing
//! whether it came from the fallback subnet or an upstream DHCP server.
//!
//! The fallback subnet is deliberately narrow and is not routed: no gateway and
//! no DNS servers are advertised in provisioning mode. Nothing except the
//! provisioning host should normally be on this link.
//!
//! When the fallback subnet is active, the address is fixed rather than
//! per-device, so **only one unprovisioned device may be on a given isolated
//! provisioning link at a time**. Attaching several to that fallback segment
//! produces an ordinary IPv4 address conflict; the intended setup is a direct
//! cable, or a small switch used with one board powered at a time. A wireless
//! device instead hosts its own
//! network, so the address is scoped to that one access point and several
//! devices can be powered at once — [`provision_ap_ssid`] gives each of them a
//! distinct SSID.

use heapless::String;

use crate::DeviceIdentity;

/// IPv4 address an unprovisioned device assigns to itself, in network order.
pub const PROVISION_DEVICE_IPV4: [u8; 4] = [192, 168, 7, 1];

/// First address handed to a provisioning host by the fallback DHCP server.
///
/// Kept as the historical host-address constant as well, so a manually configured
/// host using `192.168.7.2/24` continues to work.
pub const PROVISION_HOST_IPV4: [u8; 4] = [192, 168, 7, 2];

/// First address in the fallback provisioning-mode DHCP pool.
pub const PROVISION_DHCP_RANGE_START: [u8; 4] = PROVISION_HOST_IPV4;

/// Last address in the fallback provisioning-mode DHCP pool.
pub const PROVISION_DHCP_RANGE_END: [u8; 4] = [192, 168, 7, 20];

/// Prefix length shared by the fallback device address and DHCP leases.
pub const PROVISION_IPV4_PREFIX_LEN: u8 = 24;

/// IPv4 multicast group used by mDNS.
pub const PROVISION_MDNS_IPV4: [u8; 4] = [224, 0, 0, 251];

/// UDP port used by mDNS.
pub const PROVISION_MDNS_PORT: u16 = 5353;

/// DNS-SD service advertised by devices while awaiting provisioning.
pub const PROVISION_MDNS_SERVICE: &str = "_microtun._tcp.local";

/// Prefix shared by the device DHCP/mDNS hostname and provisioning AP SSID.
pub const DEVICE_HOSTNAME_PREFIX: &str = "microtun-";

/// Maximum hostname length accepted by Embassy-net's DHCPv4 hostname support.
pub const MAX_DEVICE_HOSTNAME_LEN: usize = 32;

/// Prefix of the SSID a wireless device advertises while unprovisioned.
pub const PROVISION_AP_SSID_PREFIX: &str = DEVICE_HOSTNAME_PREFIX;

/// Maximum length of an IEEE 802.11 SSID.
pub const MAX_SSID_LEN: usize = 32;

/// Stable bare hostname advertised by the device.
///
/// DHCP sends this label as Option 12. mDNS appends `.local` to the same label,
/// so a device with ID `0svmx1udh1` requests `microtun-0svmx1udh1` from DHCP and
/// advertises `microtun-0svmx1udh1.local` via mDNS.
pub fn device_hostname(identity: &DeviceIdentity) -> String<MAX_DEVICE_HOSTNAME_LEN> {
    let device_id = identity.device_id();
    let mut hostname = String::new();
    hostname
        .push_str(DEVICE_HOSTNAME_PREFIX)
        .expect("device hostname prefix fits");
    hostname
        .push_str(device_id.as_str())
        .expect("fixed-width device ID fits device hostname");
    hostname
}

/// SSID an unprovisioned wireless device should advertise.
///
/// The SSID has to be unique per device so an operator can tell two boards on a
/// bench apart, and it has to be derivable with no stored configuration at all.
/// It is therefore the device ID behind a fixed prefix.
///
/// Device IDs use a fixed 10-character representation, so the complete ID fits
/// comfortably within the 32-byte IEEE 802.11 SSID limit behind this prefix.
pub fn provision_ap_ssid(identity: &DeviceIdentity) -> String<MAX_SSID_LEN> {
    device_hostname(identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_is_the_prefixed_device_id() {
        let identity = DeviceIdentity::from_unique_bytes(&[0x12, 0xab, 0xcd]).unwrap();
        assert_eq!(device_hostname(&identity).as_str(), "microtun-0svmx1udh1");
    }

    #[test]
    fn ssid_is_the_prefixed_device_id() {
        let identity = DeviceIdentity::from_unique_bytes(&[0x12, 0xab, 0xcd]).unwrap();
        assert_eq!(provision_ap_ssid(&identity).as_str(), "microtun-0svmx1udh1");
    }

    #[test]
    fn complete_standardized_device_id_always_fits_in_ssid() {
        let identity = DeviceIdentity::from_unique_bytes(&[0xa5; 27]).unwrap();
        let ssid = provision_ap_ssid(&identity);

        assert_eq!(ssid.as_str(), "microtun-043s9lu7na");
        assert!(ssid.len() <= MAX_SSID_LEN);
        assert!(ssid.as_str().ends_with(identity.device_id().as_str()));
    }

    #[test]
    fn distinct_devices_get_distinct_ssids() {
        let first = DeviceIdentity::from_unique_bytes(&[1, 2, 3, 4, 5, 6]).unwrap();
        let second = DeviceIdentity::from_unique_bytes(&[1, 2, 3, 4, 5, 7]).unwrap();

        assert_ne!(provision_ap_ssid(&first), provision_ap_ssid(&second));
    }
}
