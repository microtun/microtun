#![no_std]
#![deny(unsafe_code)]

//! Portable provisioning record format shared by embedded firmware and the host CLI.
//!
//! A record is a small binary header followed by the original UTF-8 JSON payload
//! and erased-flash padding. The record format is intentionally independent of
//! the target's flash erase geometry so the same 4 KiB image can be used on both
//! ESP32-C3 and STM32H753 devices.

use core::{fmt, net::Ipv4Addr, str::FromStr};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use crc::{CRC_32_ISO_HDLC, Crc, NoTable};
use heapless::String;
use serde::Deserialize;

const CRC32: Crc<u32, NoTable> = Crc::<u32, NoTable>::new(&CRC_32_ISO_HDLC);

pub const RECORD_MAGIC: [u8; 4] = *b"MTUN";
pub const RECORD_FORMAT_VERSION: u16 = 2;
pub const CONFIG_VERSION: u16 = 1;
pub const HEADER_LEN: usize = 16;
pub const RECORD_SIZE: usize = 4096;
pub const MAX_JSON_LEN: usize = RECORD_SIZE - HEADER_LEN;
const STRING_UNESCAPE_BUFFER_SIZE: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvisionConfig {
    pub version: u16,
    /// Wi-Fi is required by the ESP32-C3 example and omitted by the wired STM32 example.
    #[serde(default)]
    pub wifi: Option<WifiConfig>,
    pub private_key: String<44>,
    pub tunnel_address: String<20>,
    pub api_server: ApiServerConfig,
    pub ntp: NtpConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WifiConfig {
    pub ssid: String<32>,
    pub password: String<63>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiServerConfig {
    pub host: String<64>,
    pub port: u16,
    pub public_key: String<44>,
    pub tunnel_address: String<20>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NtpConfig {
    pub host: String<64>,
    pub port: u16,
}

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
    pub config: ProvisionConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    UnsupportedVersion(u16),
    EmptyWifiSsid,
    InvalidPrivateKey,
    InvalidApiServerPublicKey,
    InvalidTunnelAddress,
    InvalidApiServerTunnelAddress,
    InvalidApiServerHost,
    InvalidApiServerPort,
    InvalidNtpHost,
    InvalidNtpPort,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported provisioning config version {version}")
            }
            Self::EmptyWifiSsid => f.write_str("Wi-Fi SSID must not be empty when wifi is present"),
            Self::InvalidPrivateKey => {
                f.write_str("private_key must be a 32-byte WireGuard key in standard base64")
            }
            Self::InvalidApiServerPublicKey => f.write_str(
                "api_server.public_key must be a 32-byte WireGuard key in standard base64",
            ),
            Self::InvalidTunnelAddress => f.write_str("tunnel_address must be an IPv4 CIDR"),
            Self::InvalidApiServerTunnelAddress => {
                f.write_str("api_server.tunnel_address must be an IPv4 /32 CIDR")
            }
            Self::InvalidApiServerHost => f.write_str(
                "api_server.host must be a non-empty hostname or IPv4 address without whitespace",
            ),
            Self::InvalidApiServerPort => f.write_str("api_server.port must be non-zero"),
            Self::InvalidNtpHost => {
                f.write_str("ntp.host must be non-empty and contain no whitespace")
            }
            Self::InvalidNtpPort => f.write_str("ntp.port must be non-zero"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordError {
    RecordTooSmall,
    PayloadTooLarge,
    BadMagic,
    UnsupportedFormatVersion(u16),
    BadHeaderLength(u16),
    BadPayloadLength(u32),
    BadCrc,
    BadJson,
    TrailingJsonData,
    InvalidConfig(ConfigError),
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RecordTooSmall => {
                write!(f, "provisioning record is smaller than {RECORD_SIZE} bytes")
            }
            Self::PayloadTooLarge => write!(f, "JSON payload exceeds {MAX_JSON_LEN} bytes"),
            Self::BadMagic => f.write_str("invalid provisioning record magic"),
            Self::UnsupportedFormatVersion(version) => {
                write!(
                    f,
                    "unsupported provisioning record format version {version}"
                )
            }
            Self::BadHeaderLength(length) => {
                write!(f, "invalid provisioning header length {length}")
            }
            Self::BadPayloadLength(length) => {
                write!(f, "invalid provisioning payload length {length}")
            }
            Self::BadCrc => f.write_str("provisioning record CRC32 mismatch"),
            Self::BadJson => f.write_str("invalid provisioning JSON"),
            Self::TrailingJsonData => {
                f.write_str("unexpected non-whitespace data after provisioning JSON")
            }
            Self::InvalidConfig(error) => write!(f, "invalid provisioning config: {error}"),
        }
    }
}

impl ProvisionConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.version != CONFIG_VERSION {
            return Err(ConfigError::UnsupportedVersion(self.version));
        }
        if self.wifi.as_ref().is_some_and(|wifi| wifi.ssid.is_empty()) {
            return Err(ConfigError::EmptyWifiSsid);
        }
        if !valid_wireguard_key(self.private_key.as_str()) {
            return Err(ConfigError::InvalidPrivateKey);
        }
        if !valid_wireguard_key(self.api_server.public_key.as_str()) {
            return Err(ConfigError::InvalidApiServerPublicKey);
        }
        parse_ipv4_cidr(self.tunnel_address.as_str())
            .map_err(|_| ConfigError::InvalidTunnelAddress)?;
        let (_, api_prefix) = parse_ipv4_cidr(self.api_server.tunnel_address.as_str())
            .map_err(|_| ConfigError::InvalidApiServerTunnelAddress)?;
        if api_prefix != 32 {
            return Err(ConfigError::InvalidApiServerTunnelAddress);
        }
        if !valid_host(self.api_server.host.as_str()) {
            return Err(ConfigError::InvalidApiServerHost);
        }
        if self.api_server.port == 0 {
            return Err(ConfigError::InvalidApiServerPort);
        }
        if !valid_host(self.ntp.host.as_str()) {
            return Err(ConfigError::InvalidNtpHost);
        }
        if self.ntp.port == 0 {
            return Err(ConfigError::InvalidNtpPort);
        }
        Ok(())
    }
}

/// Parse and validate a JSON payload without requiring allocation.
pub fn decode_json(json: &[u8]) -> Result<ProvisionConfig, RecordError> {
    let mut string_unescape_buffer = [0u8; STRING_UNESCAPE_BUFFER_SIZE];
    let (config, consumed) =
        serde_json_core::from_slice_escaped::<ProvisionConfig>(json, &mut string_unescape_buffer)
            .map_err(|_| RecordError::BadJson)?;
    if !json[consumed..].iter().all(u8::is_ascii_whitespace) {
        return Err(RecordError::TrailingJsonData);
    }
    config.validate().map_err(RecordError::InvalidConfig)?;
    Ok(config)
}

/// Encode a complete 4 KiB provisioning image containing `json` and its header.
pub fn encode_record(json: &[u8], record: &mut [u8]) -> Result<RecordHeader, RecordError> {
    if record.len() < RECORD_SIZE {
        return Err(RecordError::RecordTooSmall);
    }
    if json.len() > MAX_JSON_LEN {
        return Err(RecordError::PayloadTooLarge);
    }
    decode_json(json)?;

    record[..RECORD_SIZE].fill(0xff);
    let header = RecordHeader {
        format_version: RECORD_FORMAT_VERSION,
        header_len: HEADER_LEN as u16,
        payload_len: json.len() as u32,
        record_crc32: 0,
    };
    let header = RecordHeader {
        record_crc32: record_crc32(header, json),
        ..header
    };
    write_header(header, &mut record[..HEADER_LEN]);
    record[HEADER_LEN..HEADER_LEN + json.len()].copy_from_slice(json);
    Ok(header)
}

/// Decode and validate one 4 KiB provisioning image.
pub fn decode_record(record: &[u8]) -> Result<ProvisionRecord, RecordError> {
    if record.len() < RECORD_SIZE {
        return Err(RecordError::RecordTooSmall);
    }
    let header = read_header(&record[..HEADER_LEN])?;
    let payload_len = header.payload_len as usize;
    if payload_len > MAX_JSON_LEN || HEADER_LEN + payload_len > RECORD_SIZE {
        return Err(RecordError::BadPayloadLength(header.payload_len));
    }
    let payload = &record[HEADER_LEN..HEADER_LEN + payload_len];
    if record_crc32(header, payload) != header.record_crc32 {
        return Err(RecordError::BadCrc);
    }
    let config = decode_json(payload)?;
    Ok(ProvisionRecord { header, config })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CidrError;

impl fmt::Display for CidrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid IPv4 CIDR")
    }
}

pub fn parse_ipv4_cidr(value: &str) -> Result<(Ipv4Addr, u8), CidrError> {
    let (address, prefix) = value.split_once('/').ok_or(CidrError)?;
    let address = Ipv4Addr::from_str(address).map_err(|_| CidrError)?;
    let prefix = prefix.parse::<u8>().map_err(|_| CidrError)?;
    if prefix > 32 {
        return Err(CidrError);
    }
    Ok((address, prefix))
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

fn valid_wireguard_key(value: &str) -> bool {
    let mut decoded = [0u8; 33];
    matches!(
        STANDARD.decode_slice(value.as_bytes(), &mut decoded),
        Ok(32)
    )
}

fn valid_host(value: &str) -> bool {
    !value.is_empty()
        && !value.chars().any(char::is_whitespace)
        && !value.contains('/')
        && !value.contains(':')
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

    const JSON: &[u8] = br#"{
      "version": 1,
      "wifi": {"ssid": "test", "password": "password"},
      "private_key": "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=",
      "tunnel_address": "100.64.0.3/10",
      "api_server": {
        "host": "console.microtun.dev",
        "port": 51820,
        "public_key": "e06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxM=",
        "tunnel_address": "100.64.0.1/32"
      },
      "ntp": {"host": "time.google.com", "port": 123}
    }"#;

    const WIRED_JSON: &[u8] = br#"{
      "version": 1,
      "private_key": "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=",
      "tunnel_address": "100.64.0.3/10",
      "api_server": {
        "host": "console.microtun.dev",
        "port": 51820,
        "public_key": "e06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxM=",
        "tunnel_address": "100.64.0.1/32"
      },
      "ntp": {"host": "time.google.com", "port": 123}
    }"#;

    #[test]
    fn record_round_trip() {
        let mut record = [0u8; RECORD_SIZE];
        let header = encode_record(JSON, &mut record).expect("encode");
        let decoded = decode_record(&record).expect("decode");
        assert_eq!(decoded.header, header);
        assert_eq!(decoded.config.wifi.as_ref().unwrap().ssid.as_str(), "test");
    }

    #[test]
    fn wired_config_does_not_require_wifi() {
        let config = decode_json(WIRED_JSON).expect("decode wired config");
        assert!(config.wifi.is_none());
    }

    #[test]
    fn crc_detects_corruption() {
        let mut record = [0u8; RECORD_SIZE];
        encode_record(JSON, &mut record).expect("encode");
        record[HEADER_LEN + 5] ^= 1;
        assert_eq!(decode_record(&record), Err(RecordError::BadCrc));
    }

    #[test]
    fn json_strings_are_unescaped() {
        let escaped = br#"{
          "version": 1,
          "wifi": {"ssid": "test\\ssid", "password": "pa\"ssword"},
          "private_key": "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=",
          "tunnel_address": "100.64.0.3/10",
          "api_server": {
            "host": "console.microtun.dev",
            "port": 51820,
            "public_key": "e06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxM=",
            "tunnel_address": "100.64.0.1/32"
          },
          "ntp": {"host": "time.google.com", "port": 123}
        }"#;

        let config = decode_json(escaped).expect("decode escaped strings");
        let wifi = config.wifi.expect("wifi");
        assert_eq!(wifi.ssid.as_str(), "test\\ssid");
        assert_eq!(wifi.password.as_str(), "pa\"ssword");
    }

    #[test]
    fn crc32_standard_vector() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }
}
