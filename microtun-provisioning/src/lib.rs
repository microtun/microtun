//! Portable provisioning support for microtun devices.
//!
//! This crate deliberately contains no MCU, flash-driver, GPIO, or network-stack
//! ownership. Boards provide a stable hardware identifier and implement
//! [`ConfigStore`]; the crate supplies:
//!
//! - the portable flash provisioning record format,
//! - stable device IDs and locally-administered Ethernet MAC derivation,
//! - the provisioning command's Telnet/YMODEM wire constants,
//! - the well-known static link an unprovisioned device brings up: its fixed
//!   IPv4 addressing and, for wireless targets, its per-device SSID,
//! - optional Embassy-net DHCP support.
//!
//! The default `std` feature is retained for compatibility; embedded users can
//! disable default features. The board firmware owns the concrete Telnet session
//! while this crate keeps addressing, identity, and persistent record handling
//! shared across targets and host-side tooling. mDNS discovery/responder support
//! lives in `microtun-net-util`.

#![no_std]
#![deny(unsafe_code)]

#[cfg(feature = "std")]
extern crate std;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ConfigStoreError {
    InvalidConfig,
    Storage,
    Verify,
}

/// Board-specific persistent configuration storage adapter.
///
/// `store` receives the decoded config bytes. Implementations should validate
/// them before destructive writes and verify the persisted record after writing.
/// Board implementations can use this crate's portable provisioning record
/// format with their own flash driver and partition address.
pub trait ConfigStore {
    /// Erase the persisted provisioning state.
    ///
    /// After a successful erase, the next boot must observe the device as
    /// unprovisioned. Implementations should erase the complete board-specific
    /// storage region used for the provisioning record.
    fn erase(&mut self) -> Result<(), ConfigStoreError>;

    fn store(&mut self, config: &[u8]) -> Result<(), ConfigStoreError>;
}

mod identity;
mod link;
mod protocol;
pub mod storage;

#[cfg(feature = "embassy-net")]
pub mod dhcp;

pub use identity::{
    DEVICE_ID_LEN, DEVICE_ID_RADIX, DeviceId, DeviceIdentity, IdentityError, MAX_DEVICE_ID_LEN,
};
pub use link::{
    DEVICE_HOSTNAME_PREFIX, MAX_DEVICE_HOSTNAME_LEN, MAX_SSID_LEN, PROVISION_AP_SSID_PREFIX,
    PROVISION_DEVICE_IPV4, PROVISION_DHCP_RANGE_END, PROVISION_DHCP_RANGE_START,
    PROVISION_HOST_IPV4, PROVISION_IPV4_PREFIX_LEN, PROVISION_MDNS_IPV4, PROVISION_MDNS_PORT,
    PROVISION_MDNS_SERVICE, device_hostname, provision_ap_ssid,
};
pub use protocol::{
    IDENTIFY_SECONDS, PROVISION_PORT, PROVISION_PROMPT, PROVISION_STORED, PROVISION_YMODEM_READY,
    TELNET_PROMPT,
};
pub use storage::{
    HEADER_LEN, MAX_INI_BASE64_LEN, MAX_INI_LEN, ProvisionRecord, RECORD_FORMAT_VERSION,
    RECORD_MAGIC, RECORD_SIZE, RecordError, RecordHeader, crc32, decode_record, encode_record,
    encode_record_base64,
};
