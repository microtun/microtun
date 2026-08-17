use heapless::String;

/// Maximum stable hardware identifier accepted by [`DeviceIdentity::from_unique_bytes`].
///
/// This constructor exists for platforms such as STM32 that do not have a
/// factory-assigned MAC available to the firmware. It derives a stable locally
/// administered MAC first; the public device ID is always encoded from that MAC.
pub const MAX_UNIQUE_ID_BYTES: usize = 27;
/// Radix used by the canonical textual device ID representation.
pub const DEVICE_ID_RADIX: u64 = 36;
/// A 48-bit MAC address needs at most 10 base36 digits.
pub const DEVICE_ID_LEN: usize = 10;
/// Fixed-capacity string bound for canonical device IDs.
pub const MAX_DEVICE_ID_LEN: usize = DEVICE_ID_LEN;

const DEVICE_ID_ALPHABET: &[u8; DEVICE_ID_RADIX as usize] = b"0123456789abcdefghijklmnopqrstuvwxyz";
const MAX_MAC_VALUE: u64 = 0x0000_ffff_ffff_ffff;
const FNV1A_64_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV1A_64_PRIME: u64 = 0x0000_0100_0000_01b3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityError {
    Empty,
    TooLong,
}

/// Platform-independent device identifier: a MAC address encoded as base36.
///
/// The underlying value is exactly the 48 bits of the canonical device MAC in
/// network byte order. Its text form is always exactly 10 lowercase base36
/// characters. Base36 is deliberately used instead of base62 because device IDs
/// also appear in DNS/mDNS names, whose labels are case-insensitive.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DeviceId(u64);

impl DeviceId {
    pub const fn from_mac(mac: [u8; 6]) -> Self {
        Self(u64::from_be_bytes([
            0, 0, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
        ]))
    }

    pub const fn as_u64(self) -> u64 {
        self.0
    }

    pub const fn to_mac(self) -> [u8; 6] {
        let bytes = self.0.to_be_bytes();
        [bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]]
    }

    pub fn encode(self) -> String<DEVICE_ID_LEN> {
        debug_assert!(
            self.0 <= MAX_MAC_VALUE,
            "DeviceId must contain a 48-bit MAC"
        );

        let mut value = self.0;
        let mut encoded = [b'0'; DEVICE_ID_LEN];

        for byte in encoded.iter_mut().rev() {
            *byte = DEVICE_ID_ALPHABET[(value % DEVICE_ID_RADIX) as usize];
            value /= DEVICE_ID_RADIX;
        }

        debug_assert_eq!(value, 0, "10 base36 digits cover every 48-bit MAC");
        let encoded = core::str::from_utf8(&encoded).expect("base36 alphabet is UTF-8");
        let mut out = String::new();
        out.push_str(encoded)
            .expect("device ID fits fixed-capacity string");
        out
    }

    /// Parse the canonical fixed-width base36 representation.
    ///
    /// Uppercase ASCII letters are accepted for operator convenience, but
    /// [`DeviceId::encode`] always emits lowercase. Values outside the 48-bit
    /// MAC address range are rejected even if they fit in 10 base36 digits.
    pub fn parse(candidate: &str) -> Option<Self> {
        if candidate.len() != DEVICE_ID_LEN {
            return None;
        }

        let mut value = 0u64;
        for byte in candidate.bytes() {
            let digit = match byte {
                b'0'..=b'9' => u64::from(byte - b'0'),
                b'a'..=b'z' => u64::from(byte - b'a') + 10,
                b'A'..=b'Z' => u64::from(byte - b'A') + 10,
                _ => return None,
            };
            value = value.checked_mul(DEVICE_ID_RADIX)?.checked_add(digit)?;
        }

        if value > MAX_MAC_VALUE {
            return None;
        }
        Some(Self(value))
    }
}

/// Board-independent identity used while a device is awaiting provisioning.
///
/// The public device ID is a reversible base36 encoding of `mac`; there is no
/// separate device-ID hash. Platforms with a stable factory MAC should use
/// [`DeviceIdentity::from_mac`] directly. Platforms without one may use
/// [`DeviceIdentity::from_unique_bytes`] to derive a stable locally administered
/// MAC from immutable chip data first.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceIdentity {
    device_id: DeviceId,
    mac: [u8; 6],
}

impl DeviceIdentity {
    /// Build an identity directly from the canonical 48-bit device MAC.
    pub const fn from_mac(mac: [u8; 6]) -> Self {
        Self {
            device_id: DeviceId::from_mac(mac),
            mac,
        }
    }

    /// Derive a stable locally administered MAC from immutable hardware bytes.
    ///
    /// This is a compatibility helper for targets without a factory-assigned
    /// MAC. FNV-1a is used only to derive the MAC; the public device ID is then
    /// the direct base36 encoding of those six MAC bytes.
    pub fn from_unique_bytes(unique: &[u8]) -> Result<Self, IdentityError> {
        if unique.is_empty() {
            return Err(IdentityError::Empty);
        }
        if unique.len() > MAX_UNIQUE_ID_BYTES {
            return Err(IdentityError::TooLong);
        }

        let mut hash = FNV1A_64_OFFSET_BASIS;
        for byte in unique {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(FNV1A_64_PRIME);
        }

        let hash_bytes = hash.to_be_bytes();
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&hash_bytes[2..]);
        mac[0] = (mac[0] | 0x02) & !0x01; // locally administered + unicast

        Ok(Self::from_mac(mac))
    }

    pub const fn id(&self) -> DeviceId {
        self.device_id
    }

    pub const fn mac(&self) -> [u8; 6] {
        self.mac
    }

    pub fn device_id(&self) -> String<DEVICE_ID_LEN> {
        self.device_id.encode()
    }

    pub fn mac_string(&self) -> String<17> {
        let mut encoded = [0u8; 12];
        hex::encode_to_slice(self.mac, &mut encoded)
            .expect("MAC output buffer is sized for hex encoding");

        let mut out = String::new();
        for (index, pair) in encoded.chunks_exact(2).enumerate() {
            if index != 0 {
                out.push(':').expect("MAC string capacity is exact");
            }
            out.push_str(core::str::from_utf8(pair).expect("hex encoding always produces UTF-8"))
                .expect("MAC string capacity is exact");
        }
        out
    }

    pub fn matches_device_id(&self, candidate: &str) -> bool {
        DeviceId::parse(candidate) == Some(self.device_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_id_covers_full_mac_range_with_fixed_width_base36() {
        assert_eq!(DeviceId::from_mac([0; 6]).encode().as_str(), "0000000000");
        assert_eq!(
            DeviceId::from_mac([0xff; 6]).encode().as_str(),
            "2rrvthnxtr"
        );
    }

    #[test]
    fn device_id_is_reversible_and_accepts_uppercase() {
        let mac = [0x4a, 0x18, 0xc5, 0x8f, 0x84, 0xb5];
        let id = DeviceId::from_mac(mac);
        assert_eq!(id.as_u64(), 0x4a18_c58f_84b5);
        assert_eq!(id.encode().as_str(), "0svmx1udh1");
        assert_eq!(id.to_mac(), mac);
        assert_eq!(DeviceId::parse("0svmx1udh1"), Some(id));
        assert_eq!(DeviceId::parse("0SVMX1UDH1"), Some(id));
        assert_eq!(DeviceId::parse("0svmx1udh"), None);
        assert_eq!(DeviceId::parse("0svmx1udh!"), None);
        assert_eq!(DeviceId::parse("zzzzzzzzzz"), None);
    }

    #[test]
    fn identity_from_mac_is_the_direct_base36_encoding() {
        let identity = DeviceIdentity::from_mac([0x4a, 0x18, 0xc5, 0x8f, 0x84, 0xb5]);
        assert_eq!(identity.device_id().as_str(), "0svmx1udh1");
        assert_eq!(identity.id().to_mac(), identity.mac());
        assert!(identity.matches_device_id("0SVMX1UDH1"));
        assert!(!identity.matches_device_id("0svmx1udh0"));
        assert_eq!(identity.mac_string().as_str(), "4a:18:c5:8f:84:b5");
    }

    #[test]
    fn unique_bytes_derive_mac_then_encode_that_mac() {
        let identity = DeviceIdentity::from_unique_bytes(&[0x12, 0xab, 0xcd]).unwrap();
        assert_eq!(identity.mac(), [0x4a, 0x18, 0xc5, 0x8f, 0x84, 0xb5]);
        assert_eq!(identity.device_id().as_str(), "0svmx1udh1");
        assert_eq!(identity.id().to_mac(), identity.mac());
    }
}
