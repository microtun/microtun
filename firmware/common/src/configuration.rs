//! Device-configuration storage and setup helpers shared only by the embedded firmware targets.
//!
//! This module intentionally stays firmware-local. Generic network behavior
//! lives in `microtun-net-util`.

use crc::{CRC_32_ISO_HDLC, Crc, NoTable};
use heapless::String;
pub use microtun_core::device_config::DeviceConfig;
use microtun_core::device_config::decode_toml;

const CRC32: Crc<u32, NoTable> = Crc::<u32, NoTable>::new(&CRC_32_ISO_HDLC);
const RECORD_MAGIC: [u8; 4] = *b"MTUN";
const RECORD_FORMAT_VERSION: u16 = 2;
const HEADER_LEN: usize = 16;
const DEVICE_ID_LEN: usize = 10;
const DEVICE_ID_RADIX: u64 = 36;
const DEVICE_ID_ALPHABET: &[u8; DEVICE_ID_RADIX as usize] = b"0123456789abcdefghijklmnopqrstuvwxyz";
const MAX_UNIQUE_ID_BYTES: usize = 27;
const FNV1A_64_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV1A_64_PRIME: u64 = 0x0000_0100_0000_01b3;

pub const RECORD_SIZE: usize = 4096;
pub const MAX_TOML_LEN: usize = RECORD_SIZE - HEADER_LEN;
pub const CONFIG_INSTALLED: &str = "configuration installed; rebooting";

/// Stable board identity used for network naming and setup discovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceIdentity {
    mac: [u8; 6],
}

impl DeviceIdentity {
    pub const fn from_mac(mac: [u8; 6]) -> Self {
        Self { mac }
    }

    /// Derive a stable locally administered MAC from immutable hardware bytes.
    pub fn from_unique_bytes(unique: &[u8]) -> Option<Self> {
        if unique.is_empty() || unique.len() > MAX_UNIQUE_ID_BYTES {
            return None;
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
        Some(Self { mac })
    }

    pub const fn mac(self) -> [u8; 6] {
        self.mac
    }

    /// Return the canonical fixed-width base36 encoding of the 48-bit MAC.
    pub fn device_id(self) -> String<DEVICE_ID_LEN> {
        let mut value = u64::from_be_bytes([
            0,
            0,
            self.mac[0],
            self.mac[1],
            self.mac[2],
            self.mac[3],
            self.mac[4],
            self.mac[5],
        ]);
        let mut encoded = [b'0'; DEVICE_ID_LEN];

        for byte in encoded.iter_mut().rev() {
            *byte = DEVICE_ID_ALPHABET[(value % DEVICE_ID_RADIX) as usize];
            value /= DEVICE_ID_RADIX;
        }

        let encoded = core::str::from_utf8(&encoded).expect("base36 alphabet is UTF-8");
        let mut out = String::new();
        out.push_str(encoded).expect("device ID capacity is exact");
        out
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodeRecordError {
    RecordTooSmall,
    TomlTooLarge,
    InvalidConfig,
}

/// Validate `toml` and encode one complete configuration record.
pub fn encode_record(toml: &[u8], record: &mut [u8]) -> Result<(), EncodeRecordError> {
    if record.len() < RECORD_SIZE {
        return Err(EncodeRecordError::RecordTooSmall);
    }

    if toml.len() > MAX_TOML_LEN {
        return Err(EncodeRecordError::TomlTooLarge);
    }

    decode_toml(toml).map_err(|_| EncodeRecordError::InvalidConfig)?;

    record[..RECORD_SIZE].fill(0xff);
    let payload_len = toml.len() as u32;
    let crc = record_crc32(payload_len, toml);

    record[..4].copy_from_slice(&RECORD_MAGIC);
    record[4..6].copy_from_slice(&RECORD_FORMAT_VERSION.to_le_bytes());
    record[6..8].copy_from_slice(&(HEADER_LEN as u16).to_le_bytes());
    record[8..12].copy_from_slice(&payload_len.to_le_bytes());
    record[12..16].copy_from_slice(&crc.to_le_bytes());
    record[HEADER_LEN..HEADER_LEN + toml.len()].copy_from_slice(toml);
    Ok(())
}

/// Return the payload area of a configuration record for receiving a raw TOML file.
///
/// The Telnet/YMODEM path receives directly into the bytes that will become the
/// persisted record payload. This lets boot reads, setup transfers, flash
/// writes, and read-back verification all share one `RECORD_SIZE` scratch buffer.
pub fn record_payload_buffer(record: &mut [u8; RECORD_SIZE]) -> &mut [u8] {
    &mut record[HEADER_LEN..]
}

/// Validate a TOML payload already stored in [`record_payload_buffer`] and finish
/// the record in place.
///
/// Unlike [`encode_record`], this does not need a second buffer for the TOML. The
/// payload is already at its final flash offset, so only the header and unused
/// tail need to be written.
pub fn encode_record_in_place(
    record: &mut [u8; RECORD_SIZE],
    payload_len: usize,
) -> Result<(), EncodeRecordError> {
    if payload_len > MAX_TOML_LEN {
        return Err(EncodeRecordError::TomlTooLarge);
    }

    let payload_len_u32 = payload_len as u32;
    let crc = {
        let payload = &record[HEADER_LEN..HEADER_LEN + payload_len];
        decode_toml(payload).map_err(|_| EncodeRecordError::InvalidConfig)?;
        record_crc32(payload_len_u32, payload)
    };

    record[HEADER_LEN + payload_len..].fill(0xff);
    record[..4].copy_from_slice(&RECORD_MAGIC);
    record[4..6].copy_from_slice(&RECORD_FORMAT_VERSION.to_le_bytes());
    record[6..8].copy_from_slice(&(HEADER_LEN as u16).to_le_bytes());
    record[8..12].copy_from_slice(&payload_len_u32.to_le_bytes());
    record[12..16].copy_from_slice(&crc.to_le_bytes());
    Ok(())
}

/// Decode and validate one configuration record.
pub fn decode_record(record: &[u8]) -> Option<DeviceConfig> {
    if record.len() < RECORD_SIZE
        || record[..4] != RECORD_MAGIC
        || u16::from_le_bytes([record[4], record[5]]) != RECORD_FORMAT_VERSION
        || usize::from(u16::from_le_bytes([record[6], record[7]])) != HEADER_LEN
    {
        return None;
    }

    let payload_len = u32::from_le_bytes(record[8..12].try_into().ok()?) as usize;
    if payload_len > MAX_TOML_LEN {
        return None;
    }

    let payload = &record[HEADER_LEN..HEADER_LEN + payload_len];
    let stored_crc = u32::from_le_bytes(record[12..16].try_into().ok()?);
    if record_crc32(payload_len as u32, payload) != stored_crc {
        return None;
    }

    decode_toml(payload).ok()
}

fn record_crc32(payload_len: u32, payload: &[u8]) -> u32 {
    let mut prefix = [0u8; 12];
    prefix[..4].copy_from_slice(&RECORD_MAGIC);
    prefix[4..6].copy_from_slice(&RECORD_FORMAT_VERSION.to_le_bytes());
    prefix[6..8].copy_from_slice(&(HEADER_LEN as u16).to_le_bytes());
    prefix[8..12].copy_from_slice(&payload_len.to_le_bytes());

    let mut digest = CRC32.digest();
    digest.update(&prefix);
    digest.update(payload);
    digest.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOML: &[u8] = br#"[Microtun]
ApiVersion = "microtun.dev/v1alpha1"
Kind = "DeviceConfig"

[Tunnel]
PrivateKey = "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM="
Address = "100.64.0.3/10"
MTU = 1280
ListenPort = 51999
EnableForwarding = true

[WiFi]
SSID = "test"
Password = "password"

[Tracker]
Host = "console.microtun.dev"
Port = 51820
PublicKey = "e06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxM="
TunnelAddress = "100.64.0.1/32"

[NTP]
Host = "time.google.com"
Port = 123
"#;

    #[test]
    fn device_identity_is_stable() {
        let identity = DeviceIdentity::from_unique_bytes(&[0x12, 0xab, 0xcd]).unwrap();
        assert_eq!(identity.mac(), [0x4a, 0x18, 0xc5, 0x8f, 0x84, 0xb5]);
        assert_eq!(identity.device_id().as_str(), "0svmx1udh1");
    }

    #[test]
    fn record_round_trip() {
        let mut record = [0u8; RECORD_SIZE];
        encode_record(TOML, &mut record).expect("encode");
        let config = decode_record(&record).expect("decode");
        assert_eq!(config.wifi.as_ref().unwrap().ssid.as_str(), "test");
        assert_eq!(config.tunnel.mtu, Some(1280));
        assert_eq!(config.tunnel.listen_port, Some(51999));
        assert!(config.tunnel.enable_forwarding);
    }

    #[test]
    fn in_place_record_round_trip() {
        let mut expected = [0u8; RECORD_SIZE];
        encode_record(TOML, &mut expected).expect("encode");

        let mut record = [0u8; RECORD_SIZE];
        record_payload_buffer(&mut record)[..TOML.len()].copy_from_slice(TOML);
        encode_record_in_place(&mut record, TOML.len()).expect("encode in place");
        assert_eq!(record, expected);

        let config = decode_record(&record).expect("decode");
        assert_eq!(config.wifi.as_ref().unwrap().ssid.as_str(), "test");
        assert_eq!(config.tunnel.mtu, Some(1280));
    }

    #[test]
    fn crc_detects_corruption() {
        let mut record = [0u8; RECORD_SIZE];
        encode_record(TOML, &mut record).expect("encode");
        record[HEADER_LEN + 5] ^= 1;
        assert!(decode_record(&record).is_none());
    }
}
