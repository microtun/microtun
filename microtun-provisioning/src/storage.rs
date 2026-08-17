//! Portable flash provisioning record format.
//!
//! A record is a small binary header followed by the original UTF-8 INI payload
//! and erased-flash padding. The format is independent of a target's flash erase
//! geometry so the same 4 KiB image can be used across supported boards.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use crc::{CRC_32_ISO_HDLC, Crc, NoTable};
use microtun_core::device_config::{DeviceConfig, DeviceConfigError, decode_ini};
use thiserror::Error;

const CRC32: Crc<u32, NoTable> = Crc::<u32, NoTable>::new(&CRC_32_ISO_HDLC);

pub const RECORD_MAGIC: [u8; 4] = *b"MTUN";
pub const RECORD_FORMAT_VERSION: u16 = 1;
pub const HEADER_LEN: usize = 16;
pub const RECORD_SIZE: usize = 4096;
pub const MAX_INI_LEN: usize = RECORD_SIZE - HEADER_LEN;
/// Maximum standard padded-base64 length of a provisioning INI payload.
pub const MAX_INI_BASE64_LEN: usize = MAX_INI_LEN.div_ceil(3);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordHeader {
    pub format_version: u16,
    pub header_len: u16,
    pub payload_len: u32,
    pub record_crc32: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionRecord {
    pub header: RecordHeader,
    pub config: DeviceConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RecordError {
    #[error("provisioning record is too small")]
    RecordTooSmall,
    #[error("INI payload is too large")]
    PayloadTooLarge,
    #[error("invalid provisioning record magic")]
    BadMagic,
    #[error("unsupported provisioning record format version {0}")]
    UnsupportedFormatVersion(u16),
    #[error("invalid provisioning header length {0}")]
    BadHeaderLength(u16),
    #[error("invalid provisioning payload length {0}")]
    BadPayloadLength(u32),
    #[error("provisioning record CRC32 mismatch")]
    BadCrc,
    #[error("invalid provisioning INI base64")]
    BadBase64,
    #[error("invalid provisioning INI")]
    BadIni,
    #[error("invalid provisioning config")]
    InvalidConfig,
}

impl From<DeviceConfigError> for RecordError {
    fn from(error: DeviceConfigError) -> Self {
        match error {
            DeviceConfigError::BadIni => Self::BadIni,
            DeviceConfigError::InvalidConfig => Self::InvalidConfig,
        }
    }
}

/// Encode a complete 4 KiB provisioning image containing `ini` and its header.
pub fn encode_record(ini: &[u8], record: &mut [u8]) -> Result<RecordHeader, RecordError> {
    if record.len() < RECORD_SIZE {
        return Err(RecordError::RecordTooSmall);
    }
    if ini.len() > MAX_INI_LEN {
        return Err(RecordError::PayloadTooLarge);
    }
    decode_ini(ini)?;

    record[..RECORD_SIZE].fill(0xff);
    let header = RecordHeader {
        format_version: RECORD_FORMAT_VERSION,
        header_len: HEADER_LEN as u16,
        payload_len: ini.len() as u32,
        record_crc32: 0,
    };
    let header = RecordHeader {
        record_crc32: record_crc32(header, ini),
        ..header
    };
    write_header(header, &mut record[..HEADER_LEN]);
    record[HEADER_LEN..HEADER_LEN + ini.len()].copy_from_slice(ini);
    Ok(header)
}

/// Decode a standard-base64 INI payload directly into a provisioning record.
///
/// The payload is decoded into the record's payload area before validation, so
/// embedded provisioning paths do not need a second 4 KiB scratch buffer. No
/// valid record header is written until the decoded INI has passed validation.
pub fn encode_record_base64(
    config_base64: &str,
    record: &mut [u8],
) -> Result<RecordHeader, RecordError> {
    if record.len() < RECORD_SIZE {
        return Err(RecordError::RecordTooSmall);
    }
    if config_base64.len() > MAX_INI_BASE64_LEN {
        return Err(RecordError::PayloadTooLarge);
    }

    record[..RECORD_SIZE].fill(0xff);
    let payload_len = STANDARD
        .decode_slice(
            config_base64.as_bytes(),
            &mut record[HEADER_LEN..RECORD_SIZE],
        )
        .map_err(|_| RecordError::BadBase64)?;
    let payload = &record[HEADER_LEN..HEADER_LEN + payload_len];
    decode_ini(payload)?;

    let header = RecordHeader {
        format_version: RECORD_FORMAT_VERSION,
        header_len: HEADER_LEN as u16,
        payload_len: payload_len as u32,
        record_crc32: 0,
    };
    let header = RecordHeader {
        record_crc32: record_crc32(header, payload),
        ..header
    };
    write_header(header, &mut record[..HEADER_LEN]);
    Ok(header)
}

/// Decode and validate one 4 KiB provisioning image.
pub fn decode_record(record: &[u8]) -> Result<ProvisionRecord, RecordError> {
    if record.len() < RECORD_SIZE {
        return Err(RecordError::RecordTooSmall);
    }
    let header = read_header(&record[..HEADER_LEN])?;
    let payload_len = header.payload_len as usize;
    if payload_len > MAX_INI_LEN || HEADER_LEN + payload_len > RECORD_SIZE {
        return Err(RecordError::BadPayloadLength(header.payload_len));
    }
    let payload = &record[HEADER_LEN..HEADER_LEN + payload_len];
    if record_crc32(header, payload) != header.record_crc32 {
        return Err(RecordError::BadCrc);
    }
    let config = decode_ini(payload)?;
    Ok(ProvisionRecord { header, config })
}

fn record_crc32(header: RecordHeader, payload: &[u8]) -> u32 {
    let mut prefix = [0u8; 12];
    prefix[..4].copy_from_slice(&RECORD_MAGIC);
    prefix[4..6].copy_from_slice(&header.format_version.to_le_bytes());
    prefix[6..8].copy_from_slice(&header.header_len.to_le_bytes());
    prefix[8..12].copy_from_slice(&header.payload_len.to_le_bytes());

    let mut digest = CRC32.digest();
    digest.update(&prefix);
    digest.update(payload);
    digest.finalize()
}

pub fn crc32(bytes: &[u8]) -> u32 {
    CRC32.checksum(bytes)
}

fn read_header(bytes: &[u8]) -> Result<RecordHeader, RecordError> {
    if bytes[..4] != RECORD_MAGIC {
        return Err(RecordError::BadMagic);
    }
    let format_version = u16::from_le_bytes([bytes[4], bytes[5]]);
    if format_version != RECORD_FORMAT_VERSION {
        return Err(RecordError::UnsupportedFormatVersion(format_version));
    }
    let header_len = u16::from_le_bytes([bytes[6], bytes[7]]);
    if usize::from(header_len) != HEADER_LEN {
        return Err(RecordError::BadHeaderLength(header_len));
    }
    Ok(RecordHeader {
        format_version,
        header_len,
        payload_len: u32::from_le_bytes(bytes[8..12].try_into().expect("fixed header slice")),
        record_crc32: u32::from_le_bytes(bytes[12..16].try_into().expect("fixed header slice")),
    })
}

fn write_header(header: RecordHeader, bytes: &mut [u8]) {
    bytes[..4].copy_from_slice(&RECORD_MAGIC);
    bytes[4..6].copy_from_slice(&header.format_version.to_le_bytes());
    bytes[6..8].copy_from_slice(&header.header_len.to_le_bytes());
    bytes[8..12].copy_from_slice(&header.payload_len.to_le_bytes());
    bytes[12..16].copy_from_slice(&header.record_crc32.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    const INI: &[u8] = br#"[Microtun]
ApiVersion = microtun.dev/v1alpha1
Kind = DeviceConfig

[Tunnel]
PrivateKey = MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=
Address = 100.64.0.3/10
MTU = 1280
ListenPort = 51999
EnableForwarding = true

[WiFi]
SSID = test
Password = password

[Tracker]
Host = console.microtun.dev
Port = 51820
PublicKey = e06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxM=
TunnelAddress = 100.64.0.1/32

[NTP]
Host = time.google.com
Port = 123
"#;

    #[test]
    fn record_round_trip() {
        let mut record = [0u8; RECORD_SIZE];
        let header = encode_record(INI, &mut record).expect("encode");
        let decoded = decode_record(&record).expect("decode");
        assert_eq!(decoded.header, header);
        assert_eq!(decoded.config.wifi.as_ref().unwrap().ssid.as_str(), "test");
        assert_eq!(decoded.config.tunnel.mtu, Some(1280));
        assert_eq!(decoded.config.tunnel.listen_port, Some(51999));
        assert!(decoded.config.tunnel.enable_forwarding);
    }

    #[test]
    fn base64_record_round_trip() {
        let mut encoded = [0u8; MAX_INI_BASE64_LEN];
        let encoded_len = STANDARD
            .encode_slice(INI, &mut encoded)
            .expect("base64 encode");
        let encoded = core::str::from_utf8(&encoded[..encoded_len]).expect("base64 is ascii");

        let mut record = [0u8; RECORD_SIZE];
        let header = encode_record_base64(encoded, &mut record).expect("encode base64 record");
        let decoded = decode_record(&record).expect("decode record");
        assert_eq!(decoded.header, header);
        assert_eq!(decoded.config.wifi.as_ref().unwrap().ssid.as_str(), "test");
    }

    #[test]
    fn base64_record_rejects_invalid_transport_encoding() {
        let mut record = [0u8; RECORD_SIZE];
        assert_eq!(
            encode_record_base64("not base64!", &mut record),
            Err(RecordError::BadBase64)
        );
        assert_ne!(&record[..4], &RECORD_MAGIC);
    }

    #[test]
    fn crc_detects_corruption() {
        let mut record = [0u8; RECORD_SIZE];
        encode_record(INI, &mut record).expect("encode");
        record[HEADER_LEN + 5] ^= 1;
        assert_eq!(decode_record(&record), Err(RecordError::BadCrc));
    }

    #[test]
    fn crc32_standard_vector() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }
}
