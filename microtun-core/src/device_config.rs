use heapless::String;
use serde::Deserialize;
use thiserror::Error;
use wary::{Error as ValidationError, Report, Validate, Wary};
use zeroize::Zeroizing;

use crate::key::{KEY_TEXT_LEN, decode_key_into};

/// Kubernetes-style API identity used by human-facing configuration.
pub const CONFIG_API_VERSION_ID: &str = "microtun.dev/v1alpha1";
pub const CONFIG_KIND: &str = "DeviceConfig";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Wary)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct DeviceConfig {
    #[validate(dive)]
    pub microtun: MicrotunConfig,
    #[validate(dive)]
    pub tunnel: TunnelConfig,
    #[serde(rename = "WiFi", default)]
    #[validate(dive)]
    pub wifi: Option<WifiConfig>,
    #[validate(dive)]
    pub tracker: TrackerConfig,
    // Embedded devices synchronize wall clock time over NTP.
    #[serde(rename = "NTP", default)]
    #[validate(dive)]
    pub ntp: Option<NtpConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Wary)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct WifiConfig {
    #[serde(rename = "SSID")]
    #[validate(func = validate_non_empty)]
    pub ssid: String<32>,
    pub password: String<63>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Wary)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct TrackerConfig {
    #[validate(func = validate_host)]
    pub host: String<64>,
    #[validate(range(1..))]
    pub port: u16,
    #[validate(func = validate_tunnel_key)]
    pub public_key: String<KEY_TEXT_LEN>,
    #[validate(func = validate_tunnel_address)]
    pub tunnel_address: String<43>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Wary)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct NtpConfig {
    #[validate(func = validate_host)]
    pub host: String<64>,
    #[validate(range(1..))]
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Wary)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct MicrotunConfig {
    #[validate(func = validate_api_version)]
    pub api_version: String<32>,
    #[validate(func = validate_kind)]
    pub kind: String<16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Wary)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
pub struct TunnelConfig {
    #[validate(func = validate_tunnel_key)]
    pub private_key: String<KEY_TEXT_LEN>,
    #[serde(rename = "Address")]
    #[validate(func = validate_tunnel_address)]
    pub tunnel_address: String<43>,
    #[serde(rename = "MTU", default)]
    pub mtu: Option<u16>,
    #[serde(default)]
    pub listen_port: Option<u16>,
    /// Whether to enable forwarding of packets for other devices.
    #[serde(default)]
    pub enable_forwarding: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DeviceConfigError {
    #[error("invalid device configuration INI")]
    BadIni,
    #[error("invalid device configuration")]
    InvalidConfig,
}

impl DeviceConfig {
    /// Validate all configuration fields and return Wary's structured report on failure.
    pub fn validate(&self) -> Result<(), Report> {
        Validate::validate(self, &())
    }
}

/// Parse and validate a device configuration INI payload without allocation.
pub fn decode_ini(ini: &[u8]) -> Result<DeviceConfig, DeviceConfigError> {
    let ini = core::str::from_utf8(ini).map_err(|_| DeviceConfigError::BadIni)?;
    let config: DeviceConfig =
        microtun_ini::from_str(ini).map_err(|_| DeviceConfigError::BadIni)?;
    config
        .validate()
        .map_err(|_| DeviceConfigError::InvalidConfig)?;
    Ok(config)
}

fn validation_result(valid: bool, code: &'static str) -> Result<(), ValidationError> {
    if valid {
        Ok(())
    } else {
        Err(ValidationError::new(code))
    }
}

fn validate_api_version(_: &(), value: &String<32>) -> Result<(), ValidationError> {
    validation_result(value.as_str() == CONFIG_API_VERSION_ID, "api_version")
}

fn validate_kind(_: &(), value: &String<16>) -> Result<(), ValidationError> {
    validation_result(value.as_str() == CONFIG_KIND, "kind")
}

fn validate_non_empty<const N: usize>(_: &(), value: &String<N>) -> Result<(), ValidationError> {
    validation_result(!value.is_empty(), "required")
}

fn validate_tunnel_key<const N: usize>(_: &(), value: &String<N>) -> Result<(), ValidationError> {
    let mut key = Zeroizing::new([0u8; 32]);
    validation_result(
        decode_key_into(value.as_str(), &mut key).is_ok(),
        "tunnel_key",
    )
}

fn validate_tunnel_address<const N: usize>(
    _: &(),
    value: &String<N>,
) -> Result<(), ValidationError> {
    validation_result(
        crate::ip::parse_ip_inet(value.as_str()).is_ok(),
        "tunnel_address",
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    const WIRED_INI: &[u8] = br#"[Microtun]
ApiVersion = microtun.dev/v1alpha1
Kind = DeviceConfig

[Tunnel]
PrivateKey = MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=
Address = 100.64.0.3/10

[Tracker]
Host = console.microtun.dev
Port = 51820
PublicKey = e06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxM=
TunnelAddress = 100.64.0.1/32
"#;

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
        config.tracker.port = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn ini_names_are_case_insensitive() {
        let ini = br#"[microtun]
apiversion = microtun.dev/v1alpha1
kind = DeviceConfig

[tunnel]
PRIVATEKEY = MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=
address = 100.64.0.3/10
mtu = 1400
LISTENPORT = 51821
enableforwarding = false

[tracker]
host = console.microtun.dev
PORT = 51820
publickey = e06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxM=
TUNNELADDRESS = 100.64.0.1/32

[ntp]
HOST = time.google.com
port = 123
"#;

        let config = decode_ini(ini).expect("decode mixed-case INI");
        assert_eq!(config.microtun.api_version.as_str(), CONFIG_API_VERSION_ID);
        assert_eq!(config.microtun.kind.as_str(), CONFIG_KIND);
        assert_eq!(config.tunnel.mtu, Some(1400));
        assert_eq!(config.tunnel.listen_port, Some(51821));
        assert!(!config.tunnel.enable_forwarding);
        assert_eq!(config.tracker.port, 51820);
        assert_eq!(config.ntp.as_ref().unwrap().port, 123);
    }

    #[test]
    fn ini_values_are_literal() {
        let ini = br#"[Microtun]
ApiVersion = microtun.dev/v1alpha1
Kind = DeviceConfig

[Tunnel]
PrivateKey = MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=
Address = 100.64.0.3/10

[WiFi]
SSID = test\ssid
Password = pa"ss=word#still-a-value

[Tracker]
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
    fn config_accepts_ipv6_tunnel_addresses() {
        let ini = br#"[Microtun]
ApiVersion = microtun.dev/v1alpha1
Kind = DeviceConfig

[Tunnel]
PrivateKey = MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=
Address = fd00:1234:5678::3/64

[Tracker]
Host = console.microtun.dev
Port = 51820
PublicKey = e06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxM=
TunnelAddress = fd00:1234:5678::1
"#;

        let config = decode_ini(ini).expect("IPv6 tunnel configuration");
        assert_eq!(
            config.tunnel.tunnel_address.as_str(),
            "fd00:1234:5678::3/64"
        );
        assert_eq!(config.tracker.tunnel_address.as_str(), "fd00:1234:5678::1");
    }
}
