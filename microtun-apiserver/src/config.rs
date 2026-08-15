//! Loading `apiserver.conf` into a served [`Registry`].
//!
//! The API server configuration has `[Microtun]` and `[Tunnel]` base sections,
//! followed by repeated `[Peer]` registry sections.
//! The server's own identity and tunnel address come directly from `[Tunnel]`;
//! there is no separate `[ApiServer]` section.
//!
//! Parsing is delegated to `microtun-ini`, so section and property names are
//! ASCII case-insensitive, repeated sections deserialize into sequences, and
//! repeated list-valued properties are flattened by the shared INI dialect.

use std::{collections::HashSet, fmt, net::SocketAddr, path::Path};

use microtun_core::{
    IpCidr, IpInet, RECOMMENDED_MAX_MTU, RECOMMENDED_MAX_RELAYED_MTU,
    ip::{host_cidr, parse_ip_inet, unmap_socket_addr},
    key::{KEY_TEXT_LEN, decode_key, encode_key},
    public_key as derive_public_key,
};
use serde::Deserialize;

use crate::registry::{KEY_PREFIX_LEN, PeerRecord, Registry};

const DEFAULT_LISTEN_PORT: u16 = 51820;
const DEFAULT_MTU: u16 = 1280;
const CONFIG_API_GROUP: &str = "microtun.dev";
const CONFIG_API_VERSION: &str = "v1alpha1";
const CONFIG_API_VERSION_ID: &str = "microtun.dev/v1alpha1";
const CONFIG_KIND: &str = "ApiServer";
const TUNNEL_ADDRESS_MAX_LEN: usize = 43;
const SELF_ALIAS: &str = "@self";

/// Settings required to run the local tunnel.
#[derive(Clone)]
pub struct ServerOptions {
    /// Outer UDP socket used by the tunnel protocol.
    pub listen: SocketAddr,
    /// Inner interface address and prefix for the virtual TCP stack.
    pub tunnel_address: IpInet,
    /// Inner IP MTU advertised by the virtual tunnel interface.
    pub mtu: u16,
    /// Whether this server forwards authenticated type-5 relay packets between peers.
    pub enable_forwarding: bool,
    /// Static tunnel private key.
    pub private_key: [u8; 32],
    /// Derived from `Tunnel.PrivateKey`; never configured independently.
    pub public_key: [u8; 32],
}

/// Written by hand so a stray `{:?}` on the configuration cannot put the
/// tunnel's private key in a log line.
impl fmt::Debug for ServerOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerOptions")
            .field("listen", &self.listen)
            .field("tunnel_address", &self.tunnel_address)
            .field("mtu", &self.mtu)
            .field("enable_forwarding", &self.enable_forwarding)
            .field("private_key", &"[REDACTED]")
            .field("public_key", &encode_key(&self.public_key))
            .finish()
    }
}

/// One successfully loaded configuration.
#[derive(Debug)]
pub struct Loaded {
    pub options: ServerOptions,
    pub registry: Registry,
}

/// A configuration problem, located in the file where possible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    pub path: String,
    pub line: Option<usize>,
    pub message: String,
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

/// API-server configuration.
///
/// The server owns and validates its config types here; there is no
/// device-config crate dependency. `[Tunnel]` is also the server's own peer
/// record source, while peer registry data lives in the repeated extension
/// sections below.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApiServerConfig {
    #[serde(rename = "Microtun")]
    microtun: MicrotunConfig,
    #[serde(rename = "Tunnel")]
    tunnel: TunnelConfig,
    #[serde(rename = "Peer", default)]
    peers: Vec<PeerConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MicrotunConfig {
    #[serde(rename = "ApiVersion")]
    api_version: String,
    #[serde(rename = "Kind")]
    kind: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TunnelConfig {
    #[serde(rename = "PrivateKey")]
    private_key: String,
    #[serde(rename = "Address")]
    tunnel_address: String,
    #[serde(rename = "MTU", default)]
    mtu: Option<u16>,
    #[serde(rename = "ListenPort", default)]
    listen_port: Option<u16>,
    #[serde(rename = "EnableForwarding", default)]
    enable_forwarding: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerConfig {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "PublicKey")]
    public_key: String,
    #[serde(rename = "Endpoint", default)]
    endpoint: Option<String>,
    #[serde(rename = "Address")]
    address: String,
    #[serde(rename = "Relay", default)]
    relay: Option<String>,
    #[serde(rename = "PersistentKeepalive", default)]
    persistent_keepalive: Option<u16>,
}

/// A peer parsed but not yet relay-resolved.
struct Draft {
    /// Local alias from `Peer.Name`; the API server record is unnamed.
    name: Option<String>,
    public_key: [u8; 32],
    endpoint: Option<SocketAddr>,
    /// Literal `Relay` value, still to be resolved against the file.
    relay: Option<String>,
    persistent_keepalive: Option<u16>,
    address: IpCidr,
}

/// Read and validate a configuration file.
pub fn load(path: &Path) -> Result<Loaded, ConfigError> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| ConfigError::file(path, format!("cannot read: {error}")))?;
    parse(&text, path)
}

/// Parse configuration text. Split out from [`load`] for testing and reloads.
pub fn parse(text: &str, path: &Path) -> Result<Loaded, ConfigError> {
    let config: ApiServerConfig =
        microtun_ini::from_str(text).map_err(|error| match error.line() {
            Some(line) => ConfigError::at(path, line, error.to_string()),
            None => ConfigError::file(path, error.to_string()),
        })?;

    validate_base_config(&config, path)?;
    validate_names(&config, path)?;

    let private_key = key(
        config.tunnel.private_key.as_str(),
        "Tunnel.PrivateKey",
        path,
    )?;
    let public_key = derive_public_key(&private_key);

    let tunnel_address = parse_ip_inet(config.tunnel.tunnel_address.as_str()).map_err(|_| {
        ConfigError::file(
            path,
            "Tunnel.Address is invalid after base config validation",
        )
    })?;
    // The configured prefix belongs to the server's virtual interface, but the
    // server peer itself owns only its host address. Keeping those concepts
    // separate prevents e.g. 10.0.0.1/24 from publishing 10.0.0.0/24 as an
    // address owned by the API server. IPv6 gets the equivalent /128 host route.
    let server_address = host_cidr(tunnel_address.address());

    let options = ServerOptions {
        listen: SocketAddr::from((
            [0, 0, 0, 0],
            config.tunnel.listen_port.unwrap_or(DEFAULT_LISTEN_PORT),
        )),
        tunnel_address,
        mtu: config.tunnel.mtu.unwrap_or(DEFAULT_MTU),
        enable_forwarding: config.tunnel.enable_forwarding,
        private_key,
        public_key,
    };

    let mut drafts = Vec::with_capacity(config.peers.len() + 1);
    drafts.push(Draft {
        name: None,
        public_key,
        endpoint: None,
        relay: None,
        persistent_keepalive: None,
        address: server_address,
    });
    for peer in &config.peers {
        drafts.push(peer_draft(peer, path)?);
    }

    let records = resolve(&drafts, path)?;
    let registry = Registry::build(records).map_err(|message| ConfigError::file(path, message))?;

    Ok(Loaded { options, registry })
}

fn supported_api_version(value: &str) -> bool {
    matches!(
        value.split_once('/'),
        Some((group, version)) if group == CONFIG_API_GROUP && version == CONFIG_API_VERSION
    )
}

fn validate_base_config(config: &ApiServerConfig, path: &Path) -> Result<(), ConfigError> {
    if !supported_api_version(&config.microtun.api_version) {
        return Err(ConfigError::file(
            path,
            format!(
                "unsupported config ApiVersion {} (expected {CONFIG_API_VERSION_ID})",
                config.microtun.api_version
            ),
        ));
    }
    if config.microtun.kind != CONFIG_KIND {
        return Err(ConfigError::file(
            path,
            format!(
                "unsupported config Kind {} (expected {CONFIG_KIND})",
                config.microtun.kind
            ),
        ));
    }

    validate_max_len(
        &config.tunnel.private_key,
        KEY_TEXT_LEN,
        "Tunnel.PrivateKey",
        path,
    )?;
    validate_max_len(
        &config.tunnel.tunnel_address,
        TUNNEL_ADDRESS_MAX_LEN,
        "Tunnel.Address",
        path,
    )?;
    if decode_key(&config.tunnel.private_key).is_err() {
        return Err(ConfigError::file(
            path,
            "Tunnel.PrivateKey must be a 32-byte WireGuard key in standard base64",
        ));
    }
    parse_ip_inet(&config.tunnel.tunnel_address).map_err(|_| {
        ConfigError::file(path, "Tunnel.Address must be an IPv4 or IPv6 address/CIDR")
    })?;

    if let Some(mtu) = config.tunnel.mtu {
        if mtu == 0 {
            return Err(ConfigError::file(path, "Tunnel.MTU must be non-zero"));
        }
        // Deliberately *not* MAX_INNER_SIZE. That constant is the engine's
        // buffer ceiling and does not subtract the outer IP and UDP headers,
        // so accepting a value up to it let an operator configure an MTU that
        // fragments on every ordinary 1500-byte path — and, for any peer
        // reached through a relay, one that silently exceeds the relay
        // envelope budget and is dropped with no ICMP notification at all.
        // That is a path-MTU black hole: small packets work, large ones
        // vanish, and nothing in the logs says why.
        //
        // RECOMMENDED_MAX_RELAYED_MTU is the stricter of the two ceilings and
        // is the one enforced here, because whether a given peer is relayed
        // is a property of the peer registry rather than of this file, and a
        // configuration that only works until someone adds a relay is not a
        // configuration worth accepting.
        if usize::from(mtu) > RECOMMENDED_MAX_RELAYED_MTU {
            return Err(ConfigError::file(
                path,
                format!(
                    "Tunnel.MTU must not exceed {RECOMMENDED_MAX_RELAYED_MTU} \
                     (the largest inner packet that fits a 1500-byte path, including \
                     the relay envelope; direct-only deployments could carry up to \
                     {RECOMMENDED_MAX_MTU})"
                ),
            ));
        }
    }

    Ok(())
}

fn validate_max_len(
    value: &str,
    max_len: usize,
    field: &str,
    path: &Path,
) -> Result<(), ConfigError> {
    if value.len() > max_len {
        return Err(ConfigError::file(
            path,
            format!("{field} exceeds the device-config-compatible limit of {max_len} bytes"),
        ));
    }
    Ok(())
}

fn validate_names(config: &ApiServerConfig, path: &Path) -> Result<(), ConfigError> {
    let mut peer_names = HashSet::new();
    for peer in &config.peers {
        validate_name("Peer", &peer.name, &mut peer_names, path)?;
    }

    Ok(())
}

fn validate_name(
    section: &str,
    name: &str,
    seen: &mut HashSet<String>,
    path: &Path,
) -> Result<(), ConfigError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(ConfigError::file(
            path,
            format!("[{section}] has an empty `Name`"),
        ));
    }
    if !seen.insert(name.to_ascii_lowercase()) {
        return Err(ConfigError::file(
            path,
            format!("duplicate {section} name `{name}`"),
        ));
    }
    Ok(())
}

fn peer_draft(peer: &PeerConfig, path: &Path) -> Result<Draft, ConfigError> {
    let public_key = key(&peer.public_key, "Peer.PublicKey", path)?;
    let endpoint = peer
        .endpoint
        .as_deref()
        .map(|value| {
            value
                .parse::<SocketAddr>()
                .map(unmap_socket_addr)
                .map_err(|_| {
                    ConfigError::file(
                        path,
                        format!(
                            "Peer `{}` Endpoint must be an address and port such as 198.51.100.20:51820, found `{value}`",
                            peer.name
                        ),
                    )
                })
        })
        .transpose()?;

    let persistent_keepalive = peer.persistent_keepalive.filter(|seconds| *seconds != 0);
    let address = peer_address(&peer.name, &peer.address, path)?;

    Ok(Draft {
        name: Some(peer.name.trim().to_string()),
        public_key,
        endpoint,
        relay: peer.relay.as_ref().map(|value| value.trim().to_string()),
        persistent_keepalive,
        address,
    })
}

/// Parse, canonicalize and check a peer's single tunnel prefix.
fn peer_address(name: &str, value: &str, path: &Path) -> Result<IpCidr, ConfigError> {
    let token = value.trim();
    let written = parse_ip_inet(token).map_err(|_| {
        ConfigError::file(
            path,
            format!("Peer `{name}` Address `{token}` is not a CIDR prefix such as 10.0.0.3/32"),
        )
    })?;
    if written.network_length() == 0 {
        return Err(ConfigError::file(
            path,
            format!(
                "Peer `{name}` Address `{written:#}` is the default route; resolver answers may not carry one"
            ),
        ));
    }
    let canonical = written.network();
    if written.address() != canonical.first_address() {
        tracing::warn!("clearing host bits in {written:#} for peer {name}; serving {canonical:#}");
    }
    Ok(canonical)
}

/// Turn drafts into records, resolving `Relay` references.
fn resolve(drafts: &[Draft], path: &Path) -> Result<Vec<PeerRecord>, ConfigError> {
    let mut records = Vec::with_capacity(drafts.len());

    for draft in drafts {
        let relay = match &draft.relay {
            None => None,
            Some(value) => {
                let relay = if value.eq_ignore_ascii_case(SELF_ALIAS) {
                    self_public_key(drafts)
                } else {
                    drafts
                        .iter()
                        .find(|candidate| {
                            candidate
                                .name
                                .as_deref()
                                .map(|name| name.eq_ignore_ascii_case(value))
                                .unwrap_or(false)
                        })
                        .map(|candidate| candidate.public_key)
                        .or_else(|| decode_key(value).ok())
                        .ok_or_else(|| {
                            ConfigError::file(
                                path,
                                format!(
                                    "Relay names `{value}`, but no Peer with that Name exists; use `{SELF_ALIAS}`, a configured peer name, or a public key in base64"
                                ),
                            )
                        })?
                };
                if relay == draft.public_key {
                    return Err(ConfigError::file(path, "a peer cannot be its own relay"));
                }
                let relay_draft = drafts
                    .iter()
                    .find(|candidate| candidate.public_key == relay)
                    .ok_or_else(|| {
                        ConfigError::file(
                            path,
                            format!(
                                "this peer relays through {}, which has no registry record",
                                encode_key(&relay)
                            ),
                        )
                    })?;
                if relay_draft.relay.is_some() {
                    return Err(ConfigError::file(
                        path,
                        format!(
                            "this peer relays through {}, which is itself relayed; relay chaining is not supported",
                            encode_key(&relay)
                        ),
                    ));
                }
                if draft.endpoint.is_some() {
                    tracing::warn!(
                        "peer {} has both an `Endpoint` and a `Relay`; clients route through the relay",
                        draft_label(draft)
                    );
                }
                Some(relay)
            }
        };

        records.push(PeerRecord::new(
            draft.public_key,
            draft.endpoint,
            relay,
            draft.address,
            draft.persistent_keepalive,
        ));
    }

    for draft in drafts {
        if draft.name.is_some() && draft.endpoint.is_none() && draft.relay.is_none() {
            tracing::debug!(
                "peer {} has neither `Endpoint` nor `Relay`; only peers that initiate can reach it",
                draft_label(draft)
            );
        }
    }

    Ok(records)
}

fn self_public_key(drafts: &[Draft]) -> [u8; 32] {
    drafts
        .iter()
        .find(|candidate| candidate.name.is_none())
        .expect("a parsed configuration has exactly one API server draft")
        .public_key
}

fn draft_label(draft: &Draft) -> String {
    draft
        .name
        .clone()
        .unwrap_or_else(|| short(&draft.public_key))
}

fn key(value: &str, what: &str, path: &Path) -> Result<[u8; 32], ConfigError> {
    decode_key(value).map_err(|_| {
        ConfigError::file(
            path,
            format!(
                "`{what}` must be a key in base64 ({KEY_TEXT_LEN} characters ending in `=`), found `{value}`"
            ),
        )
    })
}

/// The leading characters of a key's base64 form, used for the unnamed API
/// server record in log lines.
fn short(public_key: &[u8; 32]) -> String {
    encode_key(public_key).as_str()[..KEY_PREFIX_LEN].to_string()
}

#[cfg(test)]
pub(crate) mod tests {
    use std::path::PathBuf;

    use super::*;

    pub(crate) const SERVER_PRIVATE: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const KEY_A: &str = "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=";
    const KEY_B: &str = "u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7s=";

    pub(crate) fn server_public() -> [u8; 32] {
        derive_public_key(&decode_key(SERVER_PRIVATE).expect("the test private key decodes"))
    }

    pub(crate) fn server_config(address: &str) -> String {
        format!(
            "[Microtun]\nApiVersion = microtun.dev/v1alpha1\nKind = ApiServer\n\n\
             [Tunnel]\nPrivateKey = {SERVER_PRIVATE}\nAddress = {address}\n\
             ListenPort = 51820\n\n"
        )
    }

    fn base() -> String {
        server_config("10.0.0.1/32")
    }

    fn load_text(text: &str) -> Result<Loaded, ConfigError> {
        parse(text, &PathBuf::from("apiserver.conf"))
    }

    #[test]
    fn loads_extended_server_config() {
        let text = format!(
            "{}[Peer]\nName = gateway\nPublicKey = {KEY_B}\nEndpoint = 198.51.100.20:51820\n\
             Address = 10.0.0.3/32\n\n\
             [Peer]\nName = laptop\nPublicKey = {KEY_A}\nAddress = 10.0.0.7/32\nRelay = gateway\n",
            base()
        );
        let loaded = load_text(&text).expect("loads");
        assert_eq!(loaded.options.public_key, server_public());
        assert_eq!(loaded.registry.peer_count(), 3);
        assert_eq!(loaded.registry.route_count(), 3);
        assert_eq!(
            loaded.registry.lookup_key(&[0xAA; 32]).unwrap().relay,
            Some([0xBB; 32])
        );
    }

    #[test]
    fn tunnel_mtu_defaults_to_1280_and_can_be_configured() {
        let loaded = load_text(&base()).expect("default config loads");
        assert_eq!(loaded.options.mtu, 1280);

        let configured = base().replace("ListenPort = 51820", "MTU = 1320\nListenPort = 51820");
        let loaded = load_text(&configured).expect("configured MTU loads");
        assert_eq!(loaded.options.mtu, 1320);
    }

    /// The accepted range must be what survives the wire, not what the
    /// engine's buffers happen to hold. An MTU above
    /// [`RECOMMENDED_MAX_RELAYED_MTU`] fragments on an ordinary path and is
    /// dropped outright for relayed peers, with no ICMP notification — a
    /// path-MTU black hole reachable straight from the config file.
    #[test]
    fn tunnel_mtu_must_fit_the_wire_not_just_the_engine_buffers() {
        let zero = base().replace("ListenPort = 51820", "MTU = 0\nListenPort = 51820");
        assert!(
            load_text(&zero)
                .unwrap_err()
                .to_string()
                .contains("Tunnel.MTU must be non-zero")
        );

        let at_ceiling = base().replace(
            "ListenPort = 51820",
            &format!("MTU = {RECOMMENDED_MAX_RELAYED_MTU}\nListenPort = 51820"),
        );
        assert_eq!(
            load_text(&at_ceiling)
                .expect("the ceiling itself is valid")
                .options
                .mtu,
            RECOMMENDED_MAX_RELAYED_MTU as u16
        );

        let oversized = base().replace(
            "ListenPort = 51820",
            &format!(
                "MTU = {}\nListenPort = 51820",
                RECOMMENDED_MAX_RELAYED_MTU + 1
            ),
        );
        assert!(
            load_text(&oversized)
                .unwrap_err()
                .to_string()
                .contains("Tunnel.MTU must not exceed")
        );

        // The specific regression: this used to load, because the old bound
        // was the engine's inner-packet buffer ceiling.
        let fragmenting = base().replace("ListenPort = 51820", "MTU = 1400\nListenPort = 51820");
        assert!(
            load_text(&fragmenting).is_err(),
            "an MTU that fragments on a 1500-byte path must be rejected at load"
        );

        // The default has to be inside the ceiling it is validated against,
        // or the shipped configuration is one nobody can reproduce.
        assert!(usize::from(DEFAULT_MTU) <= RECOMMENDED_MAX_RELAYED_MTU);
        assert!(RECOMMENDED_MAX_RELAYED_MTU <= RECOMMENDED_MAX_MTU);
    }

    #[test]
    fn api_version_is_enforced() {
        let text = base().replace(
            "ApiVersion = microtun.dev/v1alpha1",
            "ApiVersion = microtun.dev/v99",
        );
        assert!(
            load_text(&text)
                .unwrap_err()
                .to_string()
                .contains("unsupported config ApiVersion")
        );
    }

    #[test]
    fn kind_is_enforced() {
        let text = base().replace("Kind = ApiServer", "Kind = Device");
        assert!(
            load_text(&text)
                .unwrap_err()
                .to_string()
                .contains("unsupported config Kind")
        );
    }

    #[test]
    fn tunnel_address_accepts_interface_cidr_and_publishes_only_the_host() {
        let loaded = load_text(&server_config("10.0.0.9/24")).expect("loads interface CIDR");
        assert_eq!(
            format!("{:#}", loaded.options.tunnel_address),
            "10.0.0.9/24"
        );

        let record = loaded
            .registry
            .lookup_key(&server_public())
            .expect("server record");
        assert_eq!(record.address.network_length(), 32);
        assert_eq!(record.address.first_address().to_string(), "10.0.0.9");
    }

    #[test]
    fn tunnel_address_accepts_a_bare_host() {
        let loaded = load_text(&server_config("10.0.0.9")).expect("loads bare host");
        assert_eq!(
            format!("{:#}", loaded.options.tunnel_address),
            "10.0.0.9/32"
        );

        let record = loaded
            .registry
            .lookup_key(&server_public())
            .expect("server record");
        assert_eq!(record.address.network_length(), 32);
        assert_eq!(record.address.first_address().to_string(), "10.0.0.9");
    }

    #[test]
    fn ipv6_tunnel_address_publishes_only_the_host() {
        let loaded = load_text(&server_config("fd00:1234::9/64")).expect("loads IPv6 CIDR");
        assert_eq!(
            format!("{:#}", loaded.options.tunnel_address),
            "fd00:1234::9/64"
        );

        let record = loaded
            .registry
            .lookup_key(&server_public())
            .expect("server record");
        assert_eq!(record.address.network_length(), 128);
        assert_eq!(record.address.first_address().to_string(), "fd00:1234::9");
    }

    #[test]
    fn server_record_comes_from_tunnel_and_has_no_endpoint() {
        let loaded = load_text(&base()).expect("loads");
        let record = loaded
            .registry
            .lookup_key(&server_public())
            .expect("server record");
        assert_eq!(record.public_key, server_public());
        assert_eq!(record.endpoint, None);
        assert_eq!(record.address.network_length(), 32);
        assert_eq!(record.address.last_address().to_string(), "10.0.0.1");
    }

    #[test]
    fn base_sections_remain_ascii_case_insensitive() {
        let text = base()
            .replace("[Microtun]", "[microtun]")
            .replace("[Tunnel]", "[tUnNeL]");
        assert!(load_text(&text).is_ok());
    }

    #[test]
    fn repeated_peer_sections_are_parsed_by_microtun_ini() {
        let text = format!(
            "{}[Peer]\nName = a\nPublicKey = {KEY_A}\nAddress = 10.0.0.2/32\n\n\
             [Peer]\nName = b\nPublicKey = {KEY_B}\nAddress = 10.0.0.3/32\n",
            base()
        );
        assert_eq!(load_text(&text).unwrap().registry.peer_count(), 3);
    }

    #[test]
    fn duplicate_scalar_keys_report_source_line() {
        let text = base().replace(
            "ListenPort = 51820",
            "ListenPort = 51820\nListenPort = 51821",
        );
        let error = load_text(&text).unwrap_err();
        assert!(error.line.is_some());
        assert!(
            error
                .to_string()
                .contains("repeated property requires a sequence")
        );
    }
}
