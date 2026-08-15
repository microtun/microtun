#![no_std]
#![deny(unsafe_code)]

//! Portable device configuration and provisioning record format shared by firmware
//! and host tools.
//!
//! A record is a small binary header followed by the original UTF-8 INI payload
//! and erased-flash padding. The record format is intentionally independent of
//! the target's flash erase geometry so the same 4 KiB image can be used on both
//! ESP32-C3 and STM32H753 devices.

use core::net::{IpAddr, Ipv4Addr};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use cidr::IpInet;
use crc::{CRC_32_ISO_HDLC, Crc, NoTable};
use heapless::String;
use serde::Deserialize;
use thiserror::Error;
use wary::{Error as ValidationError, Report, Validate, Wary};

const CRC32: Crc<u32, NoTable> = Crc::<u32, NoTable>::new(&CRC_32_ISO_HDLC);

pub const RECORD_MAGIC: [u8; 4] = *b"MTUN";
pub const RECORD_FORMAT_VERSION: u16 = 3;
/// Kubernetes-style API identity used by human-facing configuration.
pub const CONFIG_API_GROUP: &str = "microtun.dev";
pub const CONFIG_API_VERSION: &str = "v1alpha1";
pub const CONFIG_API_VERSION_ID: &str = "microtun.dev/v1alpha1";
pub const CONFIG_KIND: &str = "Device";
pub const HEADER_LEN: usize = 16;
pub const RECORD_SIZE: usize = 4096;
pub const MAX_INI_LEN: usize = RECORD_SIZE - HEADER_LEN;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Wary)]
#[serde(deny_unknown_fields)]
pub struct DeviceConfig {
    #[serde(rename = "Microtun")]
    #[validate(dive)]
    pub microtun: MicrotunConfig,
    #[serde(rename = "Tunnel")]
    #[validate(dive)]
    pub tunnel: TunnelConfig,
    #[serde(rename = "WiFi", default)]
    #[validate(dive)]
    pub wifi: Option<WifiConfig>,
    #[serde(rename = "ApiServer")]
    #[validate(dive)]
    pub api_server: ApiServerConfig,
    // Embedded devices synchronize wall clock time over NTP.
    #[serde(rename = "NTP", default)]
    #[validate(dive)]
    pub ntp: Option<NtpConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Wary)]
#[serde(deny_unknown_fields)]
pub struct WifiConfig {
    #[serde(rename = "SSID")]
    #[validate(func = validate_non_empty)]
    pub ssid: String<32>,
    #[serde(rename = "Password")]
    pub password: String<63>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Wary)]
#[serde(deny_unknown_fields)]
pub struct ApiServerConfig {
    #[serde(rename = "Host")]
    #[validate(func = validate_host)]
    pub host: String<64>,
    #[serde(rename = "Port")]
    #[validate(range(1..))]
    pub port: u16,
    #[serde(rename = "PublicKey")]
    #[validate(func = validate_wireguard_key)]
    pub public_key: String<44>,
    #[serde(rename = "TunnelAddress")]
    #[validate(func = validate_tunnel_address)]
    pub tunnel_address: String<43>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Wary)]
#[serde(deny_unknown_fields)]
pub struct NtpConfig {
    #[serde(rename = "Host")]
    #[validate(func = validate_host)]
    pub host: String<64>,
    #[serde(rename = "Port")]
    #[validate(range(1..))]
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Wary)]
#[serde(deny_unknown_fields)]
pub struct MicrotunConfig {
    #[serde(rename = "ApiVersion")]
    #[validate(func = validate_api_version)]
    pub api_version: String<32>,
    #[serde(rename = "Kind")]
    #[validate(func = validate_kind)]
    pub kind: String<16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Wary)]
#[serde(deny_unknown_fields)]
pub struct TunnelConfig {
    #[serde(rename = "PrivateKey")]
    #[validate(func = validate_wireguard_key)]
    pub private_key: String<44>,
    #[serde(rename = "Address")]
    #[validate(func = validate_tunnel_address)]
    pub tunnel_address: String<43>,
    #[serde(rename = "MTU", default)]
    pub mtu: Option<u16>,
    #[serde(rename = "ListenPort", default)]
    pub listen_port: Option<u16>,
    /// EnableForwarding whether to enable forwarding of packets for other devices.
    #[serde(rename = "EnableForwarding", default)]
    pub enable_forwarding: bool,
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
    #[error("invalid provisioning INI")]
    BadIni,
    #[error("invalid provisioning config")]
    InvalidConfig,
}

fn supported_api_version(value: &str) -> bool {
    matches!(
        value.split_once('/'),
        Some((group, version)) if group == CONFIG_API_GROUP && version == CONFIG_API_VERSION
    )
}

impl DeviceConfig {
    /// Validate all configuration fields and return Wary's structured report on failure.
    pub fn validate(&self) -> Result<(), Report> {
        Validate::validate(self, &())
    }
}

/// Parse and validate an INI payload without requiring allocation.
pub fn decode_ini(ini: &[u8]) -> Result<DeviceConfig, RecordError> {
    let ini = core::str::from_utf8(ini).map_err(|_| RecordError::BadIni)?;
    let config: DeviceConfig = microtun_ini::from_str(ini).map_err(|_| RecordError::BadIni)?;
    config.validate().map_err(|_| RecordError::InvalidConfig)?;
    Ok(config)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("invalid IP address or CIDR")]
pub struct CidrError;

/// Parse an IPv4 or IPv6 interface-style address, preserving the literal host
/// address and accepting an omitted prefix as the address-family host prefix.
pub fn parse_ip_cidr(value: &str) -> Result<(IpAddr, u8), CidrError> {
    let inet = if value.contains('/') {
        value.parse::<IpInet>().map_err(|_| CidrError)?
    } else {
        let address = value.parse::<IpAddr>().map_err(|_| CidrError)?;
        IpInet::new_host(address)
    };

    Ok((inet.address(), inet.network_length()))
}

/// Backwards-compatible IPv4-only parser for callers that still specifically
/// require IPv4. New tunnel-address code should use [`parse_ip_cidr`].
pub fn parse_ipv4_cidr(value: &str) -> Result<(Ipv4Addr, u8), CidrError> {
    let (address, prefix) = parse_ip_cidr(value)?;
    match address {
        IpAddr::V4(address) => Ok((address, prefix)),
        IpAddr::V6(_) => Err(CidrError),
    }
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

fn validation_result(valid: bool, code: &'static str) -> Result<(), ValidationError> {
    if valid {
        Ok(())
    } else {
        Err(ValidationError::new(code))
    }
}

fn validate_api_version(_: &(), value: &String<32>) -> Result<(), ValidationError> {
    validation_result(supported_api_version(value.as_str()), "api_version")
}

fn validate_kind(_: &(), value: &String<16>) -> Result<(), ValidationError> {
    validation_result(value.as_str() == CONFIG_KIND, "kind")
}

fn validate_non_empty<const N: usize>(_: &(), value: &String<N>) -> Result<(), ValidationError> {
    validation_result(!value.is_empty(), "required")
}

fn validate_wireguard_key<const N: usize>(
    _: &(),
    value: &String<N>,
) -> Result<(), ValidationError> {
    let mut decoded = [0u8; 33];
    validation_result(
        matches!(
            STANDARD.decode_slice(value.as_bytes(), &mut decoded),
            Ok(32)
        ),
        "wireguard_key",
    )
}

fn validate_tunnel_address<const N: usize>(
    _: &(),
    value: &String<N>,
) -> Result<(), ValidationError> {
    validation_result(parse_ip_cidr(value.as_str()).is_ok(), "tunnel_address")
}

fn validate_host<const N: usize>(_: &(), value: &String<N>) -> Result<(), ValidationError> {
    let value = value.as_str();
    validation_result(
        !value.is_empty()
            && !value.chars().any(char::is_whitespace)
            && !value.contains('/')
            && !value.contains(':'),
        "host",
    )
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
Kind = Device

[Tunnel]
PrivateKey = MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=
Address = 100.64.0.3/10
MTU = 1280
ListenPort = 51999
EnableForwarding = true

[WiFi]
SSID = test
Password = password

[ApiServer]
Host = console.microtun.dev
Port = 51820
PublicKey = e06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxM=
TunnelAddress = 100.64.0.1/32

[NTP]
Host = time.google.com
Port = 123
"#;

    const WIRED_INI: &[u8] = br#"[Microtun]
ApiVersion = microtun.dev/v1alpha1
Kind = Device

[Tunnel]
PrivateKey = MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=
Address = 100.64.0.3/10

[ApiServer]
Host = console.microtun.dev
Port = 51820
PublicKey = e06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxM=
TunnelAddress = 100.64.0.1/32
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
    fn wired_config_does_not_require_optional_sections() {
        let config = decode_ini(WIRED_INI).expect("decode wired config");
        assert!(config.wifi.is_none());
        assert!(config.ntp.is_none());
        assert_eq!(config.tunnel.mtu, None);
        assert_eq!(config.tunnel.listen_port, None);
        assert!(!config.tunnel.enable_forwarding);
    }

    #[test]
    fn wary_validation_rejects_invalid_fields() {
        let mut config = decode_ini(WIRED_INI).expect("decode wired config");
        config.api_server.port = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn provisioning_ini_names_are_case_insensitive() {
        let ini = br#"[microtun]
apiversion = microtun.dev/v1alpha1
kind = Device

[tunnel]
PRIVATEKEY = MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=
address = 100.64.0.3/10
mtu = 1400
LISTENPORT = 51821
enableforwarding = false

[apiserver]
host = console.microtun.dev
PORT = 51820
publickey = e06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxM=
TUNNELADDRESS = 100.64.0.1/32

[ntp]
HOST = time.google.com
port = 123
"#;

        let config = decode_ini(ini).expect("decode mixed-case provisioning INI");
        assert_eq!(config.microtun.api_version.as_str(), CONFIG_API_VERSION_ID);
        assert_eq!(config.microtun.kind.as_str(), CONFIG_KIND);
        assert_eq!(config.tunnel.mtu, Some(1400));
        assert_eq!(config.tunnel.listen_port, Some(51821));
        assert!(!config.tunnel.enable_forwarding);
        assert_eq!(config.api_server.port, 51820);
        assert_eq!(config.ntp.as_ref().unwrap().port, 123);
    }

    #[test]
    fn crc_detects_corruption() {
        let mut record = [0u8; RECORD_SIZE];
        encode_record(INI, &mut record).expect("encode");
        record[HEADER_LEN + 5] ^= 1;
        assert_eq!(decode_record(&record), Err(RecordError::BadCrc));
    }

    #[test]
    fn ini_values_are_literal() {
        let ini = br#"[Microtun]
ApiVersion = microtun.dev/v1alpha1
Kind = Device

[Tunnel]
PrivateKey = MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=
Address = 100.64.0.3/10

[WiFi]
SSID = test\ssid
Password = pa"ss=word#still-a-value

[ApiServer]
Host = console.microtun.dev
Port = 51820
PublicKey = e06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxM=
TunnelAddress = 100.64.0.1/32

[NTP]
Host = time.google.com
Port = 123
"#;

        let config = decode_ini(ini).expect("decode INI literals");
        let wifi = config.wifi.expect("wifi");
        assert_eq!(wifi.ssid.as_str(), "test\\ssid");
        assert_eq!(wifi.password.as_str(), "pa\"ss=word#still-a-value");
    }

    #[test]
    fn tunnel_addresses_accept_bare_hosts_prefixes_and_ipv6() {
        assert_eq!(
            parse_ip_cidr("100.64.0.3").unwrap(),
            (IpAddr::V4(Ipv4Addr::new(100, 64, 0, 3)), 32)
        );
        assert_eq!(
            parse_ip_cidr("100.64.0.3/10").unwrap(),
            (IpAddr::V4(Ipv4Addr::new(100, 64, 0, 3)), 10)
        );
        assert_eq!(
            parse_ip_cidr("fd00::3").unwrap(),
            (IpAddr::V6("fd00::3".parse().unwrap()), 128)
        );
        assert_eq!(
            parse_ip_cidr("fd00::3/64").unwrap(),
            (IpAddr::V6("fd00::3".parse().unwrap()), 64)
        );
        assert!(parse_ip_cidr("10.0.0.1/33").is_err());
        assert!(parse_ip_cidr("fd00::1/129").is_err());
    }

    #[test]
    fn provisioning_accepts_ipv6_and_api_server_without_host_prefix() {
        let ini = br#"[Microtun]
ApiVersion = microtun.dev/v1alpha1
Kind = Device

[Tunnel]
PrivateKey = MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=
Address = fd00:1234:5678::3/64

[ApiServer]
Host = console.microtun.dev
Port = 51820
PublicKey = e06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxM=
TunnelAddress = fd00:1234:5678::1/48
"#;

        let config = decode_ini(ini).expect("IPv6 tunnel configuration");
        assert_eq!(
            config.tunnel.tunnel_address.as_str(),
            "fd00:1234:5678::3/64"
        );
        assert_eq!(
            config.api_server.tunnel_address.as_str(),
            "fd00:1234:5678::1/48"
        );
    }

    #[test]
    fn crc32_standard_vector() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }
}
