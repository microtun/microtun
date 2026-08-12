//! WireGuard-style configuration handling for the Linux host.
//!
//! The daemon has one local `[Interface]` and one statically pinned Peers API
//! server `[ApiServer]`. Other peers are learned dynamically from that server.
//! Configuration is intentionally close to `wg.conf` and to the Peers API
//! server's own configuration format, while keeping Linux-only TUN settings in
//! the interface section.

use std::{fmt, fs::File, io::Read, net::SocketAddr, os::unix::fs::PermissionsExt, path::Path};

use microtun_std::core::{
    IpCidr, IpInet,
    ip::{parse_ip_inet, unmap_socket_addr},
    key::{KEY_TEXT_LEN, decode_key, decode_key_into},
};
use zeroize::{Zeroize, Zeroizing};

const INTERFACE_SECTION: &str = "Interface";
const API_SERVER_SECTION: &str = "ApiServer";
const INTERFACE_KEYS: &[&str] = &[
    "PrivateKey",
    "ListenPort",
    "Name",
    "Address",
    "MTU",
    "RelayForwarding",
];
const API_SERVER_KEYS: &[&str] = &["PublicKey", "Endpoint", "Addresses"];
const DEFAULT_LISTEN_PORT: u16 = 51820;
const DEFAULT_TUN_NAME: &str = "microtun0";
const DEFAULT_MTU: u16 = 1280;

/// Validated, owned runtime configuration.
pub struct Runtime {
    pub private_key: Zeroizing<[u8; 32]>,
    pub api_server_public_key: [u8; 32],
    pub api_server_endpoint: ApiServerEndpoint,
    pub api_server_addresses: Vec<IpCidr>,
    pub listen: SocketAddr,
    pub tun_name: String,
    pub tun_address: IpInet,
    pub tun_mtu: u16,
    pub peers_api: SocketAddr,
    pub enable_forwarding: bool,
}

/// Outer bootstrap endpoint for the pinned Peers API server.
///
/// Numeric IP endpoints stay fully resolved during configuration parsing.
/// DNS names are retained until the async runtime starts so hostname lookup
/// does not block configuration-file parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiServerEndpoint {
    Socket(SocketAddr),
    Dns { host: String, port: u16 },
}

impl fmt::Display for ApiServerEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Socket(address) => write!(f, "{address}"),
            Self::Dns { host, port } => write!(f, "{host}:{port}"),
        }
    }
}

impl ApiServerEndpoint {
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Socket(address) => Some(*address),
            Self::Dns { .. } => None,
        }
    }

    pub fn dns_target(&self) -> Option<(&str, u16)> {
        match self {
            Self::Socket(_) => None,
            Self::Dns { host, port } => Some((host.as_str(), *port)),
        }
    }
}

/// A configuration problem, located in the file where possible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    path: String,
    line: Option<usize>,
    message: String,
}

impl ConfigError {
    fn at(path: &Path, line: usize, message: impl Into<String>) -> Self {
        Self {
            path: path.display().to_string(),
            line: Some(line),
            message: message.into(),
        }
    }

    fn file(path: &Path, message: impl Into<String>) -> Self {
        Self {
            path: path.display().to_string(),
            line: None,
            message: message.into(),
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(line) => write!(f, "{}:{}: {}", self.path, line, self.message),
            None => write!(f, "{}: {}", self.path, self.message),
        }
    }
}

impl std::error::Error for ConfigError {}

// ---------------------------------------------------------------------------
// INI
// ---------------------------------------------------------------------------
//
// Keep this parser deliberately small and line-aware, like the apiserver
// parser. Entries borrow from the input buffer so the private key is not copied
// into an ordinary String; `load` wipes the complete file buffer after parsing.
// A `#` or `;` is a comment only at the start of a line.

#[derive(Debug, Clone, Copy)]
struct Entry<'a> {
    key: &'a str,
    value: &'a str,
    line: usize,
}

impl Entry<'_> {
    fn is(&self, key: &str) -> bool {
        self.key.eq_ignore_ascii_case(key)
    }
}

#[derive(Debug)]
struct Section<'a> {
    name: &'a str,
    line: usize,
    entries: Vec<Entry<'a>>,
}

impl<'a> Section<'a> {
    fn is(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name)
    }

    fn get(&self, key: &str) -> Result<Option<&Entry<'a>>, (usize, String)> {
        let mut found: Option<&Entry<'a>> = None;
        for entry in self.entries.iter().filter(|entry| entry.is(key)) {
            if let Some(first) = found {
                return Err((
                    entry.line,
                    format!(
                        "duplicate key `{key}` in section [{}] (first set on line {})",
                        self.name, first.line
                    ),
                ));
            }
            found = Some(entry);
        }
        Ok(found)
    }

    fn all<'s>(&'s self, key: &'s str) -> impl Iterator<Item = &'s Entry<'a>> + 's {
        self.entries.iter().filter(move |entry| entry.is(key))
    }

    fn unknown_key(&self, allowed: &[&str]) -> Option<&Entry<'a>> {
        self.entries
            .iter()
            .find(|entry| !allowed.iter().copied().any(|key| entry.is(key)))
    }
}

fn parse_ini(text: &str) -> Result<Vec<Section<'_>>, (usize, String)> {
    let mut sections: Vec<Section<'_>> = Vec::new();

    for (index, raw) in text.lines().enumerate() {
        let line = index + 1;
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix('[') {
            let name = rest
                .strip_suffix(']')
                .ok_or_else(|| (line, format!("unterminated section header `{trimmed}`")))?
                .trim();
            if name.is_empty() {
                return Err((line, "empty section name".into()));
            }
            sections.push(Section {
                name,
                line,
                entries: Vec::new(),
            });
            continue;
        }

        let (key, value) = trimmed
            .split_once('=')
            .ok_or_else(|| (line, format!("expected `Key = value`, found `{trimmed}`")))?;
        let key = key.trim();
        if key.is_empty() {
            return Err((line, "empty key".into()));
        }
        let section = sections
            .last_mut()
            .ok_or_else(|| (line, format!("key `{key}` appears before any [Section]")))?;
        section.entries.push(Entry {
            key,
            value: value.trim().trim_matches(['"', '\'']),
            line,
        });
    }

    Ok(sections)
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/// Parse and validate a config file into a [`Runtime`].
pub fn load(path: &str) -> Result<Runtime, ConfigError> {
    let path = Path::new(path);
    let mut file = File::open(path)
        .map_err(|error| ConfigError::file(path, format!("cannot open: {error}")))?;
    let metadata = file
        .metadata()
        .map_err(|error| ConfigError::file(path, format!("cannot stat: {error}")))?;
    let mode = metadata.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(ConfigError::file(
            path,
            format!(
                "configuration is accessible by group or others (mode {:03o}); use mode 600",
                mode & 0o777
            ),
        ));
    }

    let file_len = usize::try_from(metadata.len())
        .map_err(|_| ConfigError::file(path, "configuration is too large to read"))?;
    let mut bytes = Zeroizing::new(vec![0u8; file_len]);
    file.read_exact(&mut bytes[..])
        .map_err(|error| ConfigError::file(path, format!("cannot read: {error}")))?;

    let result = match std::str::from_utf8(&bytes) {
        Ok(text) => parse(text, path),
        Err(error) => Err(ConfigError::file(
            path,
            format!("configuration is not UTF-8: {error}"),
        )),
    };

    // Parsing entries borrow from this buffer. Wipe it as soon as the owned
    // runtime values (including the decoded private key) have been produced.
    bytes.zeroize();
    result
}

/// Parse configuration text. Split out from [`load`] for testing.
fn parse(text: &str, path: &Path) -> Result<Runtime, ConfigError> {
    let sections =
        parse_ini(text).map_err(|(line, message)| ConfigError::at(path, line, message))?;

    let mut interface: Option<&Section<'_>> = None;
    let mut api_server: Option<&Section<'_>> = None;

    for section in &sections {
        if section.is(INTERFACE_SECTION) {
            if interface.is_some() {
                return Err(ConfigError::at(
                    path,
                    section.line,
                    "duplicate [Interface] section; this daemon has one local tunnel interface",
                ));
            }
            interface = Some(section);
        } else if section.is(API_SERVER_SECTION) {
            if api_server.is_some() {
                return Err(ConfigError::at(
                    path,
                    section.line,
                    "duplicate [ApiServer] section; microtun-linux has exactly one Peers API server",
                ));
            }
            api_server = Some(section);
        } else {
            return Err(ConfigError::at(
                path,
                section.line,
                format!(
                    "unknown section [{}]; expected exactly [Interface] and [ApiServer]",
                    section.name
                ),
            ));
        }
    }

    let interface = interface.ok_or_else(|| {
        ConfigError::file(
            path,
            "missing [Interface] section; define the local `PrivateKey` and `Address` there",
        )
    })?;
    let api_server = api_server.ok_or_else(|| {
        ConfigError::file(
            path,
            "missing [ApiServer] section for the pinned Peers API server",
        )
    })?;

    reject_unknown(interface, INTERFACE_KEYS, path)?;
    reject_unknown(api_server, API_SERVER_KEYS, path)?;

    let private_entry = field(interface, "PrivateKey", path)?.ok_or_else(|| {
        ConfigError::at(
            path,
            interface.line,
            "[Interface] has no `PrivateKey`; the tunnel needs a static identity",
        )
    })?;
    let mut private_key = Zeroizing::new([0u8; 32]);
    decode_key_into(private_entry.value, &mut private_key).map_err(|_| {
        ConfigError::at(
            path,
            private_entry.line,
            format!(
                "`PrivateKey` must be a base64 key as `wg` writes one ({KEY_TEXT_LEN} characters ending in `=`)"
            ),
        )
    })?;

    let listen = match field(interface, "ListenPort", path)? {
        Some(entry) => listen_socket(entry, path)?,
        None => SocketAddr::from(([0, 0, 0, 0], DEFAULT_LISTEN_PORT)),
    };
    let tun_name = field(interface, "Name", path)?
        .map(|entry| entry.value.to_string())
        .unwrap_or_else(|| DEFAULT_TUN_NAME.to_string());
    if tun_name.is_empty() {
        let line = field(interface, "Name", path)?.map_or(interface.line, |entry| entry.line);
        return Err(ConfigError::at(path, line, "`Name` must not be empty"));
    }

    let tun_address_entry = field(interface, "Address", path)?.ok_or_else(|| {
        ConfigError::at(
            path,
            interface.line,
            "[Interface] has no `Address`; configure the TUN address such as `10.0.0.2/24`",
        )
    })?;
    let tun_address = parse_ip_inet(tun_address_entry.value).map_err(|_| {
        ConfigError::at(
            path,
            tun_address_entry.line,
            format!(
                "`Address` must be an interface address such as `10.0.0.2/24` or `fd00::2/64`, found `{}`",
                tun_address_entry.value
            ),
        )
    })?;

    let tun_mtu = match field(interface, "MTU", path)? {
        Some(entry) => {
            let mtu = parse_u16(entry, "MTU", path)?;
            if mtu == 0 {
                return Err(ConfigError::at(
                    path,
                    entry.line,
                    "`MTU` must be greater than zero",
                ));
            }
            mtu
        }
        None => DEFAULT_MTU,
    };
    let enable_forwarding = match field(interface, "RelayForwarding", path)? {
        Some(entry) if entry.value.eq_ignore_ascii_case("true") => true,
        Some(entry) if entry.value.eq_ignore_ascii_case("false") => false,
        Some(entry) => {
            return Err(ConfigError::at(
                path,
                entry.line,
                format!(
                    "`RelayForwarding` must be `true` or `false`, found `{}`",
                    entry.value
                ),
            ));
        }
        None => false,
    };

    let public_key_entry = field(api_server, "PublicKey", path)?.ok_or_else(|| {
        ConfigError::at(
            path,
            api_server.line,
            format!("[{}] has no `PublicKey`", api_server.name),
        )
    })?;
    let api_server_public_key = decode_key(public_key_entry.value).map_err(|_| {
        ConfigError::at(
            path,
            public_key_entry.line,
            format!(
                "`PublicKey` must be a base64 key as `wg` writes one ({KEY_TEXT_LEN} characters ending in `=`)"
            ),
        )
    })?;

    let endpoint_entry = field(api_server, "Endpoint", path)?.ok_or_else(|| {
        ConfigError::at(
            path,
            api_server.line,
            format!(
                "[{}] has no `Endpoint`; the Peers API server needs an outer bootstrap endpoint",
                api_server.name
            ),
        )
    })?;
    let api_server_endpoint = api_server_endpoint(endpoint_entry, path)?;

    let api_server_addresses = api_server_addresses(api_server, path)?;
    let api_server_ip = api_server_addresses[0].first_address();
    let peers_api = SocketAddr::new(api_server_ip, 80);

    Ok(Runtime {
        private_key,
        api_server_public_key,
        api_server_endpoint,
        api_server_addresses,
        listen,
        tun_name,
        tun_address,
        tun_mtu,
        peers_api,
        enable_forwarding,
    })
}

/// Parse an outer Peers API endpoint without performing DNS I/O.
///
/// Numeric IPv4/IPv6 addresses are canonicalized immediately. A hostname is
/// retained with its port and resolved asynchronously at daemon startup.
fn api_server_endpoint(entry: &Entry<'_>, path: &Path) -> Result<ApiServerEndpoint, ConfigError> {
    if let Ok(address) = entry.value.parse::<SocketAddr>() {
        return Ok(ApiServerEndpoint::Socket(unmap_socket_addr(address)));
    }

    let invalid = || {
        ConfigError::at(
            path,
            entry.line,
            format!(
                "`Endpoint` must be a hostname or IP address with a port, such as `api.example.com:51820`, `203.0.113.10:51820`, or `[2001:db8::10]:51820`; found `{}`",
                entry.value
            ),
        )
    };

    let (host, port) = entry.value.rsplit_once(':').ok_or_else(invalid)?;
    if host.is_empty()
        || host.contains(':')
        || host.starts_with('[')
        || host.ends_with(']')
        || host.chars().any(char::is_whitespace)
    {
        return Err(invalid());
    }
    let port = port.parse::<u16>().map_err(|_| invalid())?;

    Ok(ApiServerEndpoint::Dns {
        host: host.to_string(),
        port,
    })
}

/// `ListenPort = 51820` binds the port on every IPv4 local address, as the
/// daemon did before INI configuration. An explicit socket address can be used
/// to select one bind address or IPv6, matching the apiserver configuration.
fn listen_socket(entry: &Entry<'_>, path: &Path) -> Result<SocketAddr, ConfigError> {
    if let Ok(port) = entry.value.parse::<u16>() {
        return Ok(SocketAddr::from(([0, 0, 0, 0], port)));
    }
    entry.value.parse().map_err(|_| {
        ConfigError::at(
            path,
            entry.line,
            format!(
                "`ListenPort` must be a UDP port such as `51820`, or an address and port such as `0.0.0.0:51820`, found `{}`",
                entry.value
            ),
        )
    })
}

/// Collect and canonicalize the Peers API server's tunnel prefixes.
///
/// `Addresses` may repeat and each entry may contain comma- or whitespace-
/// separated prefixes. As in the apiserver configuration, omitting a prefix
/// length means a host prefix.
fn api_server_addresses(section: &Section<'_>, path: &Path) -> Result<Vec<IpCidr>, ConfigError> {
    let mut addresses = Vec::new();

    for entry in section.all("Addresses") {
        for token in entry
            .value
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|token| !token.is_empty())
        {
            let written = parse_ip_inet(token).map_err(|_| {
                ConfigError::at(
                    path,
                    entry.line,
                    format!("`{token}` is not a CIDR prefix such as `10.0.0.1/32`"),
                )
            })?;
            let canonical = written.network();
            if written.address() != canonical.first_address() {
                tracing::warn!(
                    "line {}: clearing host bits in {written:#}; using {canonical:#}",
                    entry.line
                );
            }
            if !addresses.contains(&canonical) {
                addresses.push(canonical);
            }
        }
    }

    if addresses.is_empty() {
        return Err(ConfigError::at(
            path,
            section.line,
            format!("[{}] has no `Addresses`", section.name),
        ));
    }

    Ok(addresses)
}

fn field<'s, 'a>(
    section: &'s Section<'a>,
    key: &str,
    path: &Path,
) -> Result<Option<&'s Entry<'a>>, ConfigError> {
    section
        .get(key)
        .map_err(|(line, message)| ConfigError::at(path, line, message))
}

fn reject_unknown(section: &Section<'_>, allowed: &[&str], path: &Path) -> Result<(), ConfigError> {
    match section.unknown_key(allowed) {
        Some(entry) => Err(ConfigError::at(
            path,
            entry.line,
            format!(
                "unknown key `{}` in section [{}]; expected one of {}",
                entry.key,
                section.name,
                allowed.join(", ")
            ),
        )),
        None => Ok(()),
    }
}

fn parse_u16(entry: &Entry<'_>, key: &str, path: &Path) -> Result<u16, ConfigError> {
    entry.value.parse::<u16>().map_err(|_| {
        ConfigError::at(
            path,
            entry.line,
            format!(
                "`{key}` must be a number from 0 to 65535, found `{}`",
                entry.value
            ),
        )
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    const PRIVATE: &str = "oLHC0+T1BhcoOUpbbH2OnwobLD1OX2BxgpOktcbX6Pk=";
    const PUBLIC: &str = "scLT5PUGFyg5SltsfY6fChssPU5fYHGCk6S1xtfo+aA=";

    fn path() -> PathBuf {
        PathBuf::from("client.conf")
    }

    fn base() -> String {
        format!(
            "[Interface]\nPrivateKey = {PRIVATE}\nAddress = 10.0.0.2/24\n\n\
             [ApiServer]\nPublicKey = {PUBLIC}\nEndpoint = 203.0.113.10:51820\nAddresses = 10.0.0.1/32\n"
        )
    }

    fn error_of(text: &str) -> String {
        match parse(text, &path()) {
            Ok(_) => panic!("configuration unexpectedly parsed successfully"),
            Err(error) => error.to_string(),
        }
    }

    #[test]
    fn parses_wireguard_style_config_with_defaults() {
        let runtime = parse(&base(), &path()).unwrap();
        assert_eq!(runtime.listen, "0.0.0.0:51820".parse().unwrap());
        assert_eq!(runtime.tun_name, "microtun0");
        assert_eq!(format!("{:#}", runtime.tun_address), "10.0.0.2/24");
        assert_eq!(runtime.tun_mtu, 1280);
        assert!(!runtime.enable_forwarding);
        assert_eq!(
            runtime.api_server_endpoint.socket_addr(),
            Some("203.0.113.10:51820".parse().unwrap())
        );
        assert_eq!(runtime.peers_api, "10.0.0.1:80".parse().unwrap());
    }

    #[test]
    fn accepts_dns_api_server_endpoint() {
        let text = base().replace(
            "Endpoint = 203.0.113.10:51820",
            "Endpoint = api.example.com:51820",
        );
        let runtime = parse(&text, &path()).unwrap();
        assert_eq!(runtime.api_server_endpoint.socket_addr(), None);
        assert_eq!(
            runtime.api_server_endpoint.dns_target(),
            Some(("api.example.com", 51820))
        );
        assert_eq!(
            runtime.api_server_endpoint.to_string(),
            "api.example.com:51820"
        );
    }

    #[test]
    fn rejects_dns_endpoint_without_port_and_unbracketed_ipv6() {
        let no_port = base().replace("203.0.113.10:51820", "api.example.com");
        assert!(error_of(&no_port).contains("hostname or IP address with a port"));

        let unbracketed_v6 = base().replace("203.0.113.10:51820", "2001:db8::10:51820");
        assert!(error_of(&unbracketed_v6).contains("hostname or IP address with a port"));
    }

    #[test]
    fn accepts_api_server_and_custom_interface_settings() {
        let text = format!(
            "[Interface]\nPrivateKey = {PRIVATE}\nListenPort = 51999\nName = mtun7\n\
             Address = fd00::2/64\nMTU = 1400\nRelayForwarding = true\n\n\
             [ApiServer]\nPublicKey = {PUBLIC}\nEndpoint = [2001:db8::10]:51820\n\
             Addresses = fd00::1, 10.0.0.1/32\nAddresses = 10.1.2.3/24 fd00::1/128\n"
        );
        let runtime = parse(&text, &path()).unwrap();
        assert_eq!(runtime.listen, "0.0.0.0:51999".parse().unwrap());
        assert_eq!(runtime.tun_name, "mtun7");
        assert_eq!(format!("{:#}", runtime.tun_address), "fd00::2/64");
        assert_eq!(runtime.tun_mtu, 1400);
        assert!(runtime.enable_forwarding);
        assert_eq!(runtime.api_server_addresses.len(), 3);
        assert_eq!(
            format!("{:#}", runtime.api_server_addresses[2]),
            "10.1.2.0/24"
        );
    }

    #[test]
    fn accepts_explicit_listen_socket_and_zero_keepalive() {
        let text = base().replace(
            "Address = 10.0.0.2/24",
            "ListenPort = [::1]:51999\nAddress = 10.0.0.2/24",
        );
        let runtime = parse(&text, &path()).unwrap();
        assert_eq!(runtime.listen, "[::1]:51999".parse().unwrap());
    }

    #[test]
    fn rejects_peer_sections_as_ambiguous() {
        let text = base().replace("[ApiServer]", "[Peer]");
        let error = error_of(&text);
        assert!(error.contains("unknown section [Peer]"));
        assert!(error.contains("expected exactly [Interface] and [ApiServer]"));

        let named = base().replace("[ApiServer]", "[Peer.api-server]");
        assert!(error_of(&named).contains("unknown section [Peer.api-server]"));
    }

    #[test]
    fn rejects_duplicate_api_server_section() {
        let text = format!(
            "{}\n[ApiServer]\nPublicKey = {PUBLIC}\nEndpoint = 203.0.113.11:51820\nAddresses = 10.0.0.9\n",
            base()
        );
        assert!(error_of(&text).contains("duplicate [ApiServer] section"));
    }

    #[test]
    fn reports_duplicate_keys_with_lines() {
        let text = format!(
            "[Interface]\nPrivateKey = {PRIVATE}\nAddress = 10.0.0.2/24\nAddress = 10.0.0.3/24\n\
             [ApiServer]\nPublicKey = {PUBLIC}\nEndpoint = 203.0.113.10:51820\nAddresses = 10.0.0.1\n"
        );
        let error = error_of(&text);
        assert!(error.contains("client.conf:4:"));
        assert!(error.contains("duplicate key `Address`"));
    }

    #[test]
    fn rejects_unknown_keys() {
        let text = base().replace(
            "Address = 10.0.0.2/24",
            "Address = 10.0.0.2/24\nAllowedIPs = 0.0.0.0/0",
        );
        let error = error_of(&text);
        assert!(error.contains("unknown key `AllowedIPs`"));
    }

    #[test]
    fn requires_api_server_endpoint_and_addresses() {
        let no_endpoint = base().replace("Endpoint = 203.0.113.10:51820\n", "");
        assert!(error_of(&no_endpoint).contains("no `Endpoint`"));

        let no_addresses = base().replace("Addresses = 10.0.0.1/32\n", "");
        assert!(error_of(&no_addresses).contains("no `Addresses`"));
    }

    #[test]
    fn comments_are_only_whole_lines() {
        let text = format!(
            "# comment\n; another\n[Interface]\nPrivateKey = {PRIVATE}\nAddress = 10.0.0.2/24\n\
             [ApiServer]\nPublicKey = {PUBLIC}\nEndpoint = 203.0.113.10:51820\nAddresses = 10.0.0.1\n"
        );
        assert!(parse(&text, &path()).is_ok());
    }
}
