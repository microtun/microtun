use heapless::{String, Vec};
use thiserror::Error;
use toml_parser::{
    ErrorSink, Raw, Source, Span,
    decoder::{Encoding, IntegerRadix, ScalarKind, StringBuilder},
    lexer::Token,
    parser::{EventReceiver, parse_document},
};
use wary::{Error as ValidationError, Report, Validate, Wary};
use zeroize::Zeroizing;

use crate::key::{KEY_TEXT_LEN, decode_key_into};

/// Kubernetes-style API identity used by human-facing configuration.
pub const CONFIG_API_VERSION_ID: &str = "microtun.dev/v1alpha1";
pub const CONFIG_KIND: &str = "DeviceConfig";

#[derive(Debug, Clone, PartialEq, Eq, Wary)]
pub struct DeviceConfig {
    #[validate(dive)]
    pub microtun: MicrotunConfig,
    #[validate(dive)]
    pub tunnel: TunnelConfig,
    #[validate(dive)]
    pub wifi: Option<WifiConfig>,
    #[validate(dive)]
    pub tracker: TrackerConfig,
    // Embedded devices synchronize wall clock time over NTP.
    #[validate(dive)]
    pub ntp: Option<NtpConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Wary)]
pub struct WifiConfig {
    #[validate(func = validate_non_empty)]
    pub ssid: String<32>,
    pub password: String<63>,
}

#[derive(Debug, Clone, PartialEq, Eq, Wary)]
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

#[derive(Debug, Clone, PartialEq, Eq, Wary)]
pub struct NtpConfig {
    #[validate(func = validate_host)]
    pub host: String<64>,
    #[validate(range(1..))]
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Wary)]
pub struct MicrotunConfig {
    #[validate(func = validate_api_version)]
    pub api_version: String<32>,
    #[validate(func = validate_kind)]
    pub kind: String<16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Wary)]
pub struct TunnelConfig {
    #[validate(func = validate_tunnel_key)]
    pub private_key: String<KEY_TEXT_LEN>,
    #[validate(func = validate_tunnel_address)]
    pub tunnel_address: String<43>,
    pub mtu: Option<u16>,
    pub listen_port: Option<u16>,
    /// Whether to enable forwarding of packets for other devices.
    pub enable_forwarding: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DeviceConfigError {
    #[error("invalid device configuration TOML")]
    BadToml,
    #[error("invalid device configuration")]
    InvalidConfig,
}

impl DeviceConfig {
    /// Validate all configuration fields and return Wary's structured report on failure.
    pub fn validate(&self) -> Result<(), Report> {
        Validate::validate(self, &())
    }
}

const TOML_TOKEN_CAPACITY: usize = 256;
const TOML_KEY_CAPACITY: usize = 32;
const TOML_VALUE_CAPACITY: usize = 128;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    Root,
    Microtun,
    Tunnel,
    Wifi,
    Tracker,
    Ntp,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HeaderKind {
    None,
    Standard,
    Array,
}

#[derive(Default)]
struct DeviceTomlBuilder {
    section_bits: u8,
    api_version: Option<String<32>>,
    kind: Option<String<16>>,
    private_key: Option<String<KEY_TEXT_LEN>>,
    tunnel_address: Option<String<43>>,
    mtu: Option<u16>,
    listen_port: Option<u16>,
    enable_forwarding: Option<bool>,
    wifi_ssid: Option<String<32>>,
    wifi_password: Option<String<63>>,
    tracker_host: Option<String<64>>,
    tracker_port: Option<u16>,
    tracker_public_key: Option<String<KEY_TEXT_LEN>>,
    tracker_tunnel_address: Option<String<43>>,
    ntp_host: Option<String<64>>,
    ntp_port: Option<u16>,
}

impl DeviceTomlBuilder {
    const MICROTUN: u8 = 1 << 0;
    const TUNNEL: u8 = 1 << 1;
    const WIFI: u8 = 1 << 2;
    const TRACKER: u8 = 1 << 3;
    const NTP: u8 = 1 << 4;

    fn enter_section(&mut self, section: Section) -> bool {
        let bit = match section {
            Section::Microtun => Self::MICROTUN,
            Section::Tunnel => Self::TUNNEL,
            Section::Wifi => Self::WIFI,
            Section::Tracker => Self::TRACKER,
            Section::Ntp => Self::NTP,
            Section::Root => return false,
        };
        if self.section_bits & bit != 0 {
            return false;
        }
        self.section_bits |= bit;
        true
    }

    fn has_section(&self, bit: u8) -> bool {
        self.section_bits & bit != 0
    }

    fn finish(self) -> Result<DeviceConfig, DeviceConfigError> {
        if !self.has_section(Self::MICROTUN)
            || !self.has_section(Self::TUNNEL)
            || !self.has_section(Self::TRACKER)
        {
            return Err(DeviceConfigError::BadToml);
        }

        let has_wifi = self.has_section(Self::WIFI);
        let has_ntp = self.has_section(Self::NTP);

        let microtun = MicrotunConfig {
            api_version: self.api_version.ok_or(DeviceConfigError::BadToml)?,
            kind: self.kind.ok_or(DeviceConfigError::BadToml)?,
        };
        let tunnel = TunnelConfig {
            private_key: self.private_key.ok_or(DeviceConfigError::BadToml)?,
            tunnel_address: self.tunnel_address.ok_or(DeviceConfigError::BadToml)?,
            mtu: self.mtu,
            listen_port: self.listen_port,
            enable_forwarding: self.enable_forwarding.unwrap_or(false),
        };
        let wifi = if has_wifi {
            Some(WifiConfig {
                ssid: self.wifi_ssid.ok_or(DeviceConfigError::BadToml)?,
                password: self.wifi_password.ok_or(DeviceConfigError::BadToml)?,
            })
        } else {
            None
        };
        let tracker = TrackerConfig {
            host: self.tracker_host.ok_or(DeviceConfigError::BadToml)?,
            port: self.tracker_port.ok_or(DeviceConfigError::BadToml)?,
            public_key: self.tracker_public_key.ok_or(DeviceConfigError::BadToml)?,
            tunnel_address: self
                .tracker_tunnel_address
                .ok_or(DeviceConfigError::BadToml)?,
        };
        let ntp = if has_ntp {
            Some(NtpConfig {
                host: self.ntp_host.ok_or(DeviceConfigError::BadToml)?,
                port: self.ntp_port.ok_or(DeviceConfigError::BadToml)?,
            })
        } else {
            None
        };

        Ok(DeviceConfig {
            microtun,
            tunnel,
            wifi,
            tracker,
            ntp,
        })
    }
}

struct HeaplessStringBuilder<'a, const N: usize>(&'a mut String<N>);

impl<'s, const N: usize> StringBuilder<'s> for HeaplessStringBuilder<'_, N> {
    fn clear(&mut self) {
        self.0.clear();
    }

    fn push_str(&mut self, append: &'s str) -> bool {
        self.0.push_str(append).is_ok()
    }

    fn push_char(&mut self, append: char) -> bool {
        self.0.push(append).is_ok()
    }
}

struct DeviceTomlReceiver<'i> {
    source: Source<'i>,
    section: Section,
    header_kind: HeaderKind,
    header_name: String<TOML_KEY_CAPACITY>,
    pending_key: String<TOML_KEY_CAPACITY>,
    builder: DeviceTomlBuilder,
    failed: bool,
}

impl<'i> DeviceTomlReceiver<'i> {
    fn new(source: Source<'i>) -> Self {
        Self {
            source,
            section: Section::Root,
            header_kind: HeaderKind::None,
            header_name: String::new(),
            pending_key: String::new(),
            builder: DeviceTomlBuilder::default(),
            failed: false,
        }
    }

    fn fail(&mut self) {
        self.failed = true;
    }

    fn decode_key(
        &mut self,
        span: Span,
        encoding: Option<Encoding>,
    ) -> Option<String<TOML_KEY_CAPACITY>> {
        let raw_text = self.source.input().get(span.start()..span.end())?;
        let raw = Raw::new_unchecked(raw_text, encoding, span);
        let mut key = String::new();
        let mut output = HeaplessStringBuilder(&mut key);
        let mut error = None;
        raw.decode_key(&mut output, &mut error);
        if error.is_some() {
            self.fail();
            None
        } else {
            Some(key)
        }
    }

    fn set_section(&mut self) {
        let section = match self.header_name.as_str() {
            "Microtun" => Section::Microtun,
            "Tunnel" => Section::Tunnel,
            "WiFi" => Section::Wifi,
            "Tracker" => Section::Tracker,
            "NTP" => Section::Ntp,
            _ => {
                self.fail();
                Section::Root
            }
        };
        if section != Section::Root && !self.builder.enter_section(section) {
            self.fail();
        }
        self.section = section;
        self.header_name.clear();
        self.header_kind = HeaderKind::None;
    }

    fn assign_scalar(&mut self, span: Span, encoding: Option<Encoding>) {
        if self.pending_key.is_empty() || self.section == Section::Root {
            self.fail();
            return;
        }
        let Some(raw_text) = self.source.input().get(span.start()..span.end()) else {
            self.fail();
            return;
        };
        let raw = Raw::new_unchecked(raw_text, encoding, span);
        let mut value = String::<TOML_VALUE_CAPACITY>::new();
        let mut output = HeaplessStringBuilder(&mut value);
        let mut decode_error = None;
        let kind = raw.decode_scalar(&mut output, &mut decode_error);
        if decode_error.is_some() {
            self.fail();
            return;
        }

        let key = self.pending_key.as_str();
        let ok = match (self.section, key) {
            (Section::Microtun, "ApiVersion") => {
                set_string(&mut self.builder.api_version, &value, kind)
            }
            (Section::Microtun, "Kind") => set_string(&mut self.builder.kind, &value, kind),
            (Section::Tunnel, "PrivateKey") => {
                set_string(&mut self.builder.private_key, &value, kind)
            }
            (Section::Tunnel, "Address") => {
                set_string(&mut self.builder.tunnel_address, &value, kind)
            }
            (Section::Tunnel, "MTU") => set_u16(&mut self.builder.mtu, &value, kind),
            (Section::Tunnel, "ListenPort") => set_u16(&mut self.builder.listen_port, &value, kind),
            (Section::Tunnel, "EnableForwarding") => {
                set_bool(&mut self.builder.enable_forwarding, kind)
            }
            (Section::Wifi, "SSID") => set_string(&mut self.builder.wifi_ssid, &value, kind),
            (Section::Wifi, "Password") => {
                set_string(&mut self.builder.wifi_password, &value, kind)
            }
            (Section::Tracker, "Host") => set_string(&mut self.builder.tracker_host, &value, kind),
            (Section::Tracker, "Port") => set_u16(&mut self.builder.tracker_port, &value, kind),
            (Section::Tracker, "PublicKey") => {
                set_string(&mut self.builder.tracker_public_key, &value, kind)
            }
            (Section::Tracker, "TunnelAddress") => {
                set_string(&mut self.builder.tracker_tunnel_address, &value, kind)
            }
            (Section::Ntp, "Host") => set_string(&mut self.builder.ntp_host, &value, kind),
            (Section::Ntp, "Port") => set_u16(&mut self.builder.ntp_port, &value, kind),
            _ => false,
        };
        if !ok {
            self.fail();
        }
        self.pending_key.clear();
    }
}

impl EventReceiver for DeviceTomlReceiver<'_> {
    fn std_table_open(&mut self, _span: Span, _error: &mut dyn ErrorSink) {
        self.header_kind = HeaderKind::Standard;
        self.header_name.clear();
    }

    fn std_table_close(&mut self, _span: Span, _error: &mut dyn ErrorSink) {
        if self.header_kind != HeaderKind::Standard || self.header_name.is_empty() {
            self.fail();
            return;
        }
        self.set_section();
    }

    fn array_table_open(&mut self, _span: Span, _error: &mut dyn ErrorSink) {
        self.header_kind = HeaderKind::Array;
        self.header_name.clear();
        self.fail();
    }

    fn array_table_close(&mut self, _span: Span, _error: &mut dyn ErrorSink) {
        self.header_kind = HeaderKind::None;
        self.header_name.clear();
    }

    fn inline_table_open(&mut self, _span: Span, _error: &mut dyn ErrorSink) -> bool {
        self.fail();
        false
    }

    fn array_open(&mut self, _span: Span, _error: &mut dyn ErrorSink) -> bool {
        self.fail();
        false
    }

    fn simple_key(&mut self, span: Span, encoding: Option<Encoding>, _error: &mut dyn ErrorSink) {
        let Some(key) = self.decode_key(span, encoding) else {
            self.fail();
            return;
        };
        if self.header_kind != HeaderKind::None {
            if !self.header_name.is_empty() {
                self.fail();
            } else {
                self.header_name = key;
            }
        } else if !self.pending_key.is_empty() {
            self.fail();
        } else {
            self.pending_key = key;
        }
    }

    fn key_sep(&mut self, _span: Span, _error: &mut dyn ErrorSink) {
        // The configuration schema deliberately stays flat within each table.
        self.fail();
    }

    fn scalar(&mut self, span: Span, encoding: Option<Encoding>, _error: &mut dyn ErrorSink) {
        self.assign_scalar(span, encoding);
    }

    fn error(&mut self, _span: Span, _error: &mut dyn ErrorSink) {
        self.fail();
    }
}

fn set_string<const N: usize>(
    slot: &mut Option<String<N>>,
    value: &String<TOML_VALUE_CAPACITY>,
    kind: ScalarKind,
) -> bool {
    if slot.is_some() || kind != ScalarKind::String {
        return false;
    }
    let mut parsed = String::<N>::new();
    if parsed.push_str(value.as_str()).is_err() {
        return false;
    }
    *slot = Some(parsed);
    true
}

fn set_u16(slot: &mut Option<u16>, value: &String<TOML_VALUE_CAPACITY>, kind: ScalarKind) -> bool {
    if slot.is_some() {
        return false;
    }
    let ScalarKind::Integer(radix) = kind else {
        return false;
    };
    let Some(parsed) = parse_u16(value.as_str(), radix) else {
        return false;
    };
    *slot = Some(parsed);
    true
}

fn parse_u16(value: &str, radix: IntegerRadix) -> Option<u16> {
    let value = value.strip_prefix('+').unwrap_or(value);
    if value.starts_with('-') {
        return None;
    }
    u16::from_str_radix(value, radix.value()).ok()
}

fn set_bool(slot: &mut Option<bool>, kind: ScalarKind) -> bool {
    if slot.is_some() {
        return false;
    }
    let ScalarKind::Boolean(value) = kind else {
        return false;
    };
    *slot = Some(value);
    true
}

/// Parse and validate a device configuration TOML payload without allocation.
pub fn decode_toml(toml: &[u8]) -> Result<DeviceConfig, DeviceConfigError> {
    let text = core::str::from_utf8(toml).map_err(|_| DeviceConfigError::BadToml)?;
    let source = Source::new(text);
    let mut tokens = Vec::<Token, TOML_TOKEN_CAPACITY>::new();
    for token in source.lex() {
        tokens.push(token).map_err(|_| DeviceConfigError::BadToml)?;
    }

    let mut receiver = DeviceTomlReceiver::new(source);
    let mut parse_error = None;
    parse_document(tokens.as_slice(), &mut receiver, &mut parse_error);
    if parse_error.is_some() || receiver.failed {
        return Err(DeviceConfigError::BadToml);
    }

    let config = receiver.builder.finish()?;
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

    const WIRED_TOML: &[u8] = br#"[Microtun]
ApiVersion = "microtun.dev/v1alpha1"
Kind = "DeviceConfig"

[Tunnel]
PrivateKey = "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM="
Address = "100.64.0.3/10"

[Tracker]
Host = "console.microtun.dev"
Port = 51820
PublicKey = "e06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxM="
TunnelAddress = "100.64.0.1/32"
"#;

    #[test]
    fn wired_config_does_not_require_optional_sections() {
        let config = decode_toml(WIRED_TOML).expect("decode wired config");
        assert!(config.wifi.is_none());
        assert!(config.ntp.is_none());
        assert_eq!(config.tunnel.mtu, None);
        assert_eq!(config.tunnel.listen_port, None);
        assert!(!config.tunnel.enable_forwarding);
    }

    #[test]
    fn wary_validation_rejects_invalid_fields() {
        let mut config = decode_toml(WIRED_TOML).expect("decode wired config");
        config.tracker.port = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn toml_names_are_case_sensitive() {
        let toml = core::str::from_utf8(WIRED_TOML)
            .unwrap()
            .replace("[Microtun]", "[microtun]");
        assert_eq!(
            decode_toml(toml.as_bytes()),
            Err(DeviceConfigError::BadToml)
        );
    }

    #[test]
    fn toml_string_decoding_supports_literal_and_escaped_strings() {
        let toml = br#"[Microtun]
ApiVersion = "microtun.dev/v1alpha1"
Kind = "DeviceConfig"

[Tunnel]
PrivateKey = "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM="
Address = "100.64.0.3/10"

[WiFi]
SSID = 'test\ssid'
Password = "pa\"ss=word#still-a-value"

[Tracker]
Host = "console.microtun.dev"
Port = 51820
PublicKey = "e06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxM="
TunnelAddress = "100.64.0.1/32"

[NTP]
Host = "time.google.com"
Port = 123
"#;

        let config = decode_toml(toml).expect("decode TOML strings");
        let wifi = config.wifi.expect("wifi");
        assert_eq!(wifi.ssid.as_str(), "test\\ssid");
        assert_eq!(wifi.password.as_str(), "pa\"ss=word#still-a-value");
    }

    #[test]
    fn duplicate_keys_are_rejected() {
        let toml = core::str::from_utf8(WIRED_TOML)
            .unwrap()
            .replace("Port = 51820", "Port = 51820\nPort = 51821");
        assert_eq!(
            decode_toml(toml.as_bytes()),
            Err(DeviceConfigError::BadToml)
        );
    }

    #[test]
    fn config_accepts_ipv6_tunnel_addresses() {
        let toml = br#"[Microtun]
ApiVersion = "microtun.dev/v1alpha1"
Kind = "DeviceConfig"

[Tunnel]
PrivateKey = "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM="
Address = "fd00:1234:5678::3/64"

[Tracker]
Host = "console.microtun.dev"
Port = 51820
PublicKey = "e06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxM="
TunnelAddress = "fd00:1234:5678::1"
"#;

        let config = decode_toml(toml).expect("IPv6 tunnel configuration");
        assert_eq!(
            config.tunnel.tunnel_address.as_str(),
            "fd00:1234:5678::3/64"
        );
        assert_eq!(config.tracker.tunnel_address.as_str(), "fd00:1234:5678::1");
    }
}
