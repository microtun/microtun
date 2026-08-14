//! Loading `apiserver.conf` into a served [`Registry`].
//!
//! The file is a WireGuard `wg.conf` in shape: one `[Server]` section for
//! the Peers API server's own identity, then named `[Peer.name]` sections and
//! optional `[Group.name]` membership sections and `[Link.name]` relationship sections.
//! Sections and keys are matched without regard to case, as `wg` matches
//! them. Peer names are case-insensitive local configuration aliases: a
//! `Relay` may name a peer, or use the special `@self` alias for the API server
//! itself; aliases are resolved to public keys before records are served to clients.
//! Groups list member peers; links connect
//! one group internally or two groups mutually.
//!
//! The one deliberate departure from `wg.conf` is `Addresses`, which stands in
//! for both `Address` and `AllowedIPs`: in either kind of section it is the
//! set of tunnel prefixes that peer owns, and it is what a by-address lookup
//! is answered from.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    net::SocketAddr,
    path::Path,
};

use microtun_core::{
    IpCidr, MAX_PEER_ADDRESSES,
    ip::{parse_ip_inet, unmap_socket_addr},
    key::{KEY_TEXT_LEN, decode_key, encode_key},
    public_key as derive_public_key,
};

use crate::registry::{KEY_PREFIX_LEN, LinkPolicy, PeerRecord, Registry};

/// Settings from the `[Server]` section.
#[derive(Clone)]
pub struct ServerOptions {
    /// Outer UDP socket used by the tunnel protocol.
    pub listen: SocketAddr,
    /// Whether this server forwards authenticated type-5 relay packets between peers.
    pub relay_forwarding: bool,
    /// Static tunnel private key.
    pub private_key: [u8; 32],
    /// Derived from `PrivateKey`; never configured.
    pub public_key: [u8; 32],
}

/// Written by hand so a stray `{:?}` on the configuration cannot put the
/// tunnel's private key in a log line.
impl fmt::Debug for ServerOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerOptions")
            .field("listen", &self.listen)
            .field("relay_forwarding", &self.relay_forwarding)
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

const INTERFACE_SECTION: &str = "Server";
const PEER_SECTION: &str = "Peer";
const GROUP_SECTION: &str = "Group";
const LINK_SECTION: &str = "Link";
const INTERFACE_KEYS: &[&str] = &[
    "PrivateKey",
    "ListenPort",
    "Endpoint",
    "Addresses",
    "Relay",
    "RelayForwarding",
];
const PEER_KEYS: &[&str] = &[
    "PublicKey",
    "Endpoint",
    "Addresses",
    "Relay",
    "PersistentKeepalive",
];
const GROUP_KEYS: &[&str] = &["Peers"];
const LINK_KEYS: &[&str] = &["Groups"];
const DEFAULT_LISTEN_PORT: u16 = 51820;
const SELF_RELAY_ALIAS: &str = "@self";

// ---------------------------------------------------------------------------
// INI
// ---------------------------------------------------------------------------
//
// A configuration file is a few dozen `Key = value` lines under `[Section]`
// headers, and validation needs a line number for every one of them. That is
// the whole requirement, so it is met here directly rather than through a
// tokenizer whose single comment character has to be worked around.
//
// A `#` or `;` introduces a comment only at the start of a line: values are
// keys, addresses and endpoints, and none of them should lose a suffix to a
// character that happens to appear in them.

#[derive(Debug, Clone)]
struct Entry {
    /// As written, so an error can quote the operator's own spelling.
    key: String,
    value: String,
    line: usize,
}

impl Entry {
    fn is(&self, key: &str) -> bool {
        self.key.eq_ignore_ascii_case(key)
    }
}

#[derive(Debug, Clone)]
struct Section {
    name: String,
    line: usize,
    entries: Vec<Entry>,
}

impl Section {
    fn is(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name)
    }

    /// Look up a key that may appear at most once.
    fn get(&self, key: &str) -> Result<Option<&Entry>, (usize, String)> {
        let mut found: Option<&Entry> = None;
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

    fn all(&self, key: &str) -> impl Iterator<Item = &Entry> {
        self.entries.iter().filter(move |entry| entry.is(key))
    }

    fn unknown_key(&self, allowed: &[&str]) -> Option<&Entry> {
        self.entries
            .iter()
            .find(|entry| !allowed.iter().copied().any(|key| entry.is(key)))
    }
}

fn parse_ini(text: &str) -> Result<Vec<Section>, (usize, String)> {
    let mut sections: Vec<Section> = Vec::new();

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
            // Repeated section kinds are meaningful for `[Peer.name]`, so a
            // repeated header is not an error here. Whether *this* section may
            // appear twice is a question about its meaning, answered in
            // `parse`.
            sections.push(Section {
                name: name.to_string(),
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
            key: key.to_string(),
            value: value.trim().trim_matches(['"', '\'']).to_string(),
            line,
        });
    }

    Ok(sections)
}

/// Return the alias from a `[Peer.alias]` section header.
fn peer_section_name(section: &Section) -> Option<&str> {
    let (kind, name) = section.name.split_once('.')?;
    kind.trim()
        .eq_ignore_ascii_case(PEER_SECTION)
        .then_some(name.trim())
}

/// Return the alias from a `[Group.alias]` section header.
fn group_section_name(section: &Section) -> Option<&str> {
    let (kind, name) = section.name.split_once('.')?;
    kind.trim()
        .eq_ignore_ascii_case(GROUP_SECTION)
        .then_some(name.trim())
}

/// Return the alias from a `[Link.alias]` section header.
fn link_section_name(section: &Section) -> Option<&str> {
    let (kind, name) = section.name.split_once('.')?;
    kind.trim()
        .eq_ignore_ascii_case(LINK_SECTION)
        .then_some(name.trim())
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/// Read and validate a configuration file.
pub fn load(path: &Path) -> Result<Loaded, ConfigError> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| ConfigError::file(path, format!("cannot read: {error}")))?;
    parse(&text, path)
}

/// Parse configuration text. Split out from [`load`] for testing.
pub fn parse(text: &str, path: &Path) -> Result<Loaded, ConfigError> {
    let sections =
        parse_ini(text).map_err(|(line, message)| ConfigError::at(path, line, message))?;

    let mut server: Option<ServerOptions> = None;
    let mut drafts: Vec<Draft> = Vec::new();
    let mut groups: Vec<GroupDraft> = Vec::new();
    let mut link_drafts: Vec<LinkDraft> = Vec::new();

    for section in &sections {
        if section.is(INTERFACE_SECTION) {
            if server.is_some() {
                return Err(ConfigError::at(
                    path,
                    section.line,
                    "duplicate [Server] section; the Peers API server has one identity",
                ));
            }
            let (options, draft) = interface_section(section, path)?;
            server = Some(options);
            drafts.push(draft);
        } else if section.is(PEER_SECTION) {
            return Err(ConfigError::at(
                path,
                section.line,
                "peer sections must be named, for example [Peer.my-relay]",
            ));
        } else if let Some(name) = peer_section_name(section) {
            if name.is_empty() {
                return Err(ConfigError::at(
                    path,
                    section.line,
                    "peer section name is empty; use a header such as [Peer.my-relay]",
                ));
            }
            if drafts.iter().any(|draft| {
                draft
                    .name
                    .as_deref()
                    .map(|existing| existing.eq_ignore_ascii_case(name))
                    .unwrap_or(false)
            }) {
                return Err(ConfigError::at(
                    path,
                    section.line,
                    format!("duplicate peer name `{name}`"),
                ));
            }
            drafts.push(peer_draft(section, name, path)?);
        } else if section.is(GROUP_SECTION) {
            return Err(ConfigError::at(
                path,
                section.line,
                "group sections must be named, for example [Group.users]",
            ));
        } else if let Some(name) = group_section_name(section) {
            if name.is_empty() {
                return Err(ConfigError::at(
                    path,
                    section.line,
                    "group section name is empty; use a header such as [Group.users]",
                ));
            }
            if groups
                .iter()
                .any(|group| group.name.eq_ignore_ascii_case(name))
            {
                return Err(ConfigError::at(
                    path,
                    section.line,
                    format!("duplicate group name `{name}`"),
                ));
            }
            groups.push(group_draft(section, name, path)?);
        } else if section.is(LINK_SECTION) {
            return Err(ConfigError::at(
                path,
                section.line,
                "link sections must be named, for example [Link.clients-devices]",
            ));
        } else if let Some(name) = link_section_name(section) {
            if name.is_empty() {
                return Err(ConfigError::at(
                    path,
                    section.line,
                    "link section name is empty; use a header such as [Link.clients-devices]",
                ));
            }
            if link_drafts
                .iter()
                .any(|link| link.name.eq_ignore_ascii_case(name))
            {
                return Err(ConfigError::at(
                    path,
                    section.line,
                    format!("duplicate link name `{name}`"),
                ));
            }
            link_drafts.push(link_draft(section, name, path)?);
        } else {
            return Err(ConfigError::at(
                path,
                section.line,
                format!(
                    "unknown section [{}]; expected [Server], [Peer.name], [Group.name], or [Link.name]",
                    section.name
                ),
            ));
        }
    }

    let options = server.ok_or_else(|| {
        ConfigError::file(
            path,
            "missing [Server] section; define the Peers API server's `PrivateKey` \
             and `Addresses` there",
        )
    })?;

    let records = resolve(&drafts, path)?;
    let links = compile_links(&drafts, &groups, &link_drafts, path)?;
    validate_relay_links(&drafts, &records, &links, path)?;
    let registry = Registry::build_with_links(records, links)
        .map_err(|message| ConfigError::file(path, message))?;

    Ok(Loaded { options, registry })
}

/// A peer parsed but not yet relay-resolved.
struct Draft {
    /// The local alias from `[Peer.name]`; the Server record is unnamed.
    name: Option<String>,
    /// The line its section header is on.
    line: usize,
    public_key: [u8; 32],
    endpoint: Option<SocketAddr>,
    /// The literal `Relay` value, still to be checked against the file.
    relay: Option<Entry>,
    persistent_keepalive: Option<u16>,
    addresses: Vec<IpCidr>,
}

#[derive(Debug, Clone)]
struct GroupDraft {
    name: String,
    peers: Vec<Entry>,
}

#[derive(Debug, Clone)]
struct LinkDraft {
    name: String,
    groups: Entry,
}

fn group_draft(section: &Section, name: &str, path: &Path) -> Result<GroupDraft, ConfigError> {
    reject_unknown(section, GROUP_KEYS, path)?;
    let peers: Vec<Entry> = section.all("Peers").cloned().collect();
    if peers.is_empty() {
        return Err(ConfigError::at(
            path,
            section.line,
            format!("[Group.{name}] has no `Peers`"),
        ));
    }
    Ok(GroupDraft {
        name: name.to_string(),
        peers,
    })
}

fn link_draft(section: &Section, name: &str, path: &Path) -> Result<LinkDraft, ConfigError> {
    reject_unknown(section, LINK_KEYS, path)?;
    let groups = field(section, "Groups", path)?.ok_or_else(|| {
        ConfigError::at(path, section.line, format!("[Link.{name}] has no `Groups`"))
    })?;
    Ok(LinkDraft {
        name: name.to_string(),
        groups: groups.clone(),
    })
}

fn interface_section(
    section: &Section,
    path: &Path,
) -> Result<(ServerOptions, Draft), ConfigError> {
    if let Some(entry) = section.entries.iter().find(|entry| entry.is("PublicKey")) {
        return Err(ConfigError::at(
            path,
            entry.line,
            "the Peers API server's public key is derived from `PrivateKey`; remove `PublicKey`",
        ));
    }
    reject_unknown(section, INTERFACE_KEYS, path)?;

    let private_entry = field(section, "PrivateKey", path)?.ok_or_else(|| {
        ConfigError::at(
            path,
            section.line,
            "[Server] has no `PrivateKey`; the Peers API server needs a tunnel identity",
        )
    })?;
    let private_key = key(&private_entry.value, private_entry.line, "PrivateKey", path)?;
    let public_key = derive_public_key(&private_key);

    let listen = match field(section, "ListenPort", path)? {
        Some(entry) => listen_socket(entry, path)?,
        None => SocketAddr::from(([0, 0, 0, 0], DEFAULT_LISTEN_PORT)),
    };
    let relay_forwarding = match field(section, "RelayForwarding", path)? {
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

    let addresses = peer_addresses(section, path)?;

    let options = ServerOptions {
        listen,
        relay_forwarding,
        private_key,
        public_key,
    };
    let draft = draft_fields(section, None, public_key, addresses, path)?;
    Ok((options, draft))
}

/// `ListenPort = 51820` binds the port on every local address, as `wg` does.
/// An address and port binds just that one, which is the only reason the map
/// server ever needs to say more than a number here.
fn listen_socket(entry: &Entry, path: &Path) -> Result<SocketAddr, ConfigError> {
    if let Ok(port) = entry.value.parse::<u16>() {
        return Ok(SocketAddr::from(([0, 0, 0, 0], port)));
    }
    entry.value.parse().map_err(|_| {
        ConfigError::at(
            path,
            entry.line,
            format!(
                "`ListenPort` must be a UDP port such as `51820`, or an address and port \
                 such as `0.0.0.0:51820` to bind one address, found `{}`",
                entry.value
            ),
        )
    })
}

fn peer_draft(section: &Section, name: &str, path: &Path) -> Result<Draft, ConfigError> {
    reject_unknown(section, PEER_KEYS, path)?;

    let public_key_entry = field(section, "PublicKey", path)?.ok_or_else(|| {
        ConfigError::at(
            path,
            section.line,
            format!("[Peer.{name}] has no `PublicKey`"),
        )
    })?;
    let public_key = key(
        &public_key_entry.value,
        public_key_entry.line,
        "PublicKey",
        path,
    )?;
    let addresses = peer_addresses(section, path)?;
    draft_fields(section, Some(name.to_string()), public_key, addresses, path)
}

/// The fields `[Server]` and `[Peer.name]` share, once the key and prefixes
/// are in hand (they are sourced differently).
fn draft_fields(
    section: &Section,
    name: Option<String>,
    public_key: [u8; 32],
    addresses: Vec<IpCidr>,
    path: &Path,
) -> Result<Draft, ConfigError> {
    let endpoint = match field(section, "Endpoint", path)? {
        Some(entry) => {
            let endpoint: SocketAddr = entry.value.parse().map_err(|_| {
                ConfigError::at(
                    path,
                    entry.line,
                    format!(
                        "`Endpoint` must be an address and port such as `198.51.100.20:51820` \
                         (IPv6 in brackets), found `{}`",
                        entry.value
                    ),
                )
            })?;
            // Normalized as the client's decoder normalizes it, so a record
            // compares equal on both sides.
            Some(unmap_socket_addr(endpoint))
        }
        None => None,
    };
    let persistent_keepalive = match field(section, "PersistentKeepalive", path)? {
        Some(entry) => {
            let seconds = entry.value.parse::<u16>().map_err(|_| {
                ConfigError::at(
                    path,
                    entry.line,
                    format!(
                        concat!(
                            "`PersistentKeepalive` must be a number of seconds from 0 to 65535, ",
                            "found `{}`",
                        ),
                        entry.value
                    ),
                )
            })?;
            (seconds != 0).then_some(seconds)
        }
        None => None,
    };

    Ok(Draft {
        name,
        line: section.line,
        public_key,
        endpoint,
        relay: field(section, "Relay", path)?.cloned(),
        persistent_keepalive,
        addresses,
    })
}

/// Collect, canonicalize and check a peer's tunnel prefixes.
///
/// `Addresses` may repeat and each entry may list several prefixes separated
/// by commas or whitespace. A prefix length may be omitted, in which case the
/// entry is a host prefix: `10.0.0.3` is `10.0.0.3/32`.
fn peer_addresses(section: &Section, path: &Path) -> Result<Vec<IpCidr>, ConfigError> {
    let mut addresses: Vec<IpCidr> = Vec::new();

    for entry in section.all("Addresses") {
        for token in entry
            .value
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|token| !token.is_empty())
        {
            // Parsed as an `IpInet` (address *plus* prefix) rather than an
            // `IpCidr`, which cannot represent host bits at all. Keeping the
            // sloppy form for one moment longer is what lets the operator be
            // told their line was rewritten, instead of having it silently
            // corrected inside the parser.
            let written = parse_ip_inet(token).map_err(|_| {
                ConfigError::at(
                    path,
                    entry.line,
                    format!("`{token}` is not a CIDR prefix such as `10.0.0.3/32`"),
                )
            })?;
            // A default route matches every by-address query, so a peer
            // claiming one would suppress every later lookup on the client.
            // The core refuses such an answer; refuse to serve it.
            if written.network_length() == 0 {
                return Err(ConfigError::at(
                    path,
                    entry.line,
                    format!(
                        "`{written:#}` is the default route; resolver answers may not carry one"
                    ),
                ));
            }
            let canonical = written.network();
            if written.address() != canonical.first_address() {
                tracing::warn!(
                    "line {}: clearing host bits in {written:#}; serving {canonical:#}",
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
    if addresses.len() > MAX_PEER_ADDRESSES {
        return Err(ConfigError::at(
            path,
            section.line,
            format!(
                "[{}] has {} tunnel prefixes; clients accept at most {MAX_PEER_ADDRESSES}",
                section.name,
                addresses.len()
            ),
        ));
    }

    Ok(addresses)
}

// ---------------------------------------------------------------------------
// Group links
// ---------------------------------------------------------------------------

fn compile_links(
    drafts: &[Draft],
    groups: &[GroupDraft],
    links: &[LinkDraft],
    path: &Path,
) -> Result<LinkPolicy, ConfigError> {
    // Visibility is default-deny: without groups and links, each configured
    // peer can resolve only itself. Groups plus explicit links grant visibility
    // between distinct peers.
    if groups.is_empty() && links.is_empty() {
        return Ok(LinkPolicy::deny_all());
    }
    if groups.is_empty() {
        let first = &links[0];
        return Err(ConfigError::at(
            path,
            first.groups.line,
            format!(
                "[Link.{}] cannot be used without any [Group.name] sections",
                first.name
            ),
        ));
    }

    let peer_names: HashMap<String, [u8; 32]> = drafts
        .iter()
        .filter_map(|draft| {
            draft
                .name
                .as_ref()
                .map(|name| (name.to_ascii_lowercase(), draft.public_key))
        })
        .collect();
    let configured_keys: HashSet<[u8; 32]> = drafts.iter().map(|draft| draft.public_key).collect();
    let group_names: HashMap<String, usize> = groups
        .iter()
        .enumerate()
        .map(|(index, group)| (group.name.to_ascii_lowercase(), index))
        .collect();

    let mut members = Vec::with_capacity(groups.len());
    for group in groups {
        let mut group_members = HashSet::new();
        for entry in &group.peers {
            for token in list_tokens(entry, "Peers", path)? {
                if let Some(key) = peer_names.get(&token.to_ascii_lowercase()) {
                    group_members.insert(*key);
                    continue;
                }
                if let Ok(key) = decode_key(token) {
                    if configured_keys.contains(&key) {
                        group_members.insert(key);
                        continue;
                    }
                    return Err(ConfigError::at(
                        path,
                        entry.line,
                        format!("group peer `{token}` is a public key with no configured peer"),
                    ));
                }
                if group_names.contains_key(&token.to_ascii_lowercase()) {
                    return Err(ConfigError::at(
                        path,
                        entry.line,
                        format!(
                            "`Peers` in [Group.{}] may only name peers; `{token}` is another group",
                            group.name
                        ),
                    ));
                }
                return Err(ConfigError::at(
                    path,
                    entry.line,
                    format!(
                        "unknown peer `{token}` in [Group.{}]; expected a [Peer.name] alias or configured public key",
                        group.name
                    ),
                ));
            }
        }
        members.push(group_members);
    }

    let mut compiled_links = Vec::with_capacity(links.len());
    let mut seen_links: HashMap<(usize, usize), (&str, usize)> = HashMap::new();
    for link in links {
        let names: Vec<&str> = list_tokens(&link.groups, "Groups", path)?.collect();
        if names.len() > 2 {
            return Err(ConfigError::at(
                path,
                link.groups.line,
                format!(
                    "[Link.{}] `Groups` must name one group (an internal mesh) or two groups (a mutual link)",
                    link.name
                ),
            ));
        }

        let mut indexes = Vec::with_capacity(names.len());
        for token in names {
            let Some(&index) = group_names.get(&token.to_ascii_lowercase()) else {
                return Err(ConfigError::at(
                    path,
                    link.groups.line,
                    format!("unknown group `{token}` in [Link.{}] `Groups`", link.name),
                ));
            };
            indexes.push(index);
        }

        let (a, b) = match indexes.as_slice() {
            [a] => (*a, *a),
            [a, b] if a != b => ((*a).min(*b), (*a).max(*b)),
            [a, _] => {
                return Err(ConfigError::at(
                    path,
                    link.groups.line,
                    format!(
                        "[Link.{}] names the same group twice; use `Groups = {}` for an internal mesh",
                        link.name, groups[*a].name
                    ),
                ));
            }
            [] => unreachable!("list_tokens rejects an empty value"),
            _ => unreachable!("links are limited to at most two groups"),
        };

        if let Some((first_name, first_line)) =
            seen_links.insert((a, b), (link.name.as_str(), link.groups.line))
        {
            return Err(ConfigError::at(
                path,
                link.groups.line,
                format!(
                    "[Link.{}] duplicates the relationship already declared by [Link.{first_name}] on line {first_line}",
                    link.name
                ),
            ));
        }
        compiled_links.push((a, b));
    }

    Ok(LinkPolicy::from_groups_and_links(members, compiled_links))
}

fn list_tokens<'a>(
    entry: &'a Entry,
    field_name: &str,
    path: &Path,
) -> Result<impl Iterator<Item = &'a str>, ConfigError> {
    if entry.value.split(',').all(|token| token.trim().is_empty()) {
        return Err(ConfigError::at(
            path,
            entry.line,
            format!("`{field_name}` may not be empty"),
        ));
    }
    Ok(entry
        .value
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty()))
}

/// A relayed peer that is accessible to another peer must not point at a relay
/// inaccessible to that same peer, because the client needs to resolve the
/// relay key in the record it has just received.
fn validate_relay_links(
    drafts: &[Draft],
    records: &[PeerRecord],
    links: &LinkPolicy,
    path: &Path,
) -> Result<(), ConfigError> {
    for caller in drafts {
        for target in records {
            let Some(relay) = target.relay else {
                continue;
            };
            if caller.public_key != target.public_key
                && links.are_linked(&caller.public_key, &target.public_key)
                && !links.are_linked(&caller.public_key, &relay)
            {
                let target_draft = drafts
                    .iter()
                    .find(|draft| draft.public_key == target.public_key)
                    .expect("records are built from drafts");
                let line = target_draft
                    .relay
                    .as_ref()
                    .map(|entry| entry.line)
                    .unwrap_or(target_draft.line);
                return Err(ConfigError::at(
                    path,
                    line,
                    format!(
                        "link policy lets {} access relayed peer {} but not its relay {}; add a [Link.name] relationship that includes the relay",
                        draft_label(caller),
                        target.key_prefix(),
                        &encode_key(&relay).as_str()[..KEY_PREFIX_LEN],
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// Turn drafts into records, resolving `Relay` references.
fn resolve(drafts: &[Draft], path: &Path) -> Result<Vec<PeerRecord>, ConfigError> {
    let mut records = Vec::with_capacity(drafts.len());

    for draft in drafts {
        let relay = match &draft.relay {
            None => None,
            Some(entry) => {
                // `@self` is the short spelling for the unnamed `[Server]`
                // record. Otherwise prefer a local `[Peer.name]` alias; a
                // public key can also name any configured record, including
                // `[Server]` when it acts as a relay.
                let relay = if entry.value.eq_ignore_ascii_case(SELF_RELAY_ALIAS) {
                    drafts
                        .iter()
                        .find(|candidate| candidate.name.is_none())
                        .expect("a parsed configuration has exactly one [Server] draft")
                        .public_key
                } else {
                    drafts
                        .iter()
                        .find(|candidate| {
                            candidate
                                .name
                                .as_deref()
                                .map(|name| name.eq_ignore_ascii_case(&entry.value))
                                .unwrap_or(false)
                        })
                        .map(|candidate| candidate.public_key)
                        .or_else(|| decode_key(&entry.value).ok())
                        .ok_or_else(|| {
                            ConfigError::at(
                                path,
                                entry.line,
                                format!(
                                    "`Relay` names `{}`, but no [Peer.{}] section exists; use \
                                     `{SELF_RELAY_ALIAS}`, a configured peer name, or a public key in base64",
                                    entry.value, entry.value
                                ),
                            )
                        })?
                };
                if relay == draft.public_key {
                    return Err(ConfigError::at(
                        path,
                        entry.line,
                        "a peer cannot be its own relay",
                    ));
                }
                // The relaying peer has to be resolvable too: a client that
                // learns `Relay = R` must be able to look R up to find its
                // endpoint. Serving a key no `by-key` query can answer would
                // leave the peer permanently unreachable.
                let relay_draft = drafts
                    .iter()
                    .find(|candidate| candidate.public_key == relay)
                    .ok_or_else(|| {
                        ConfigError::at(
                            path,
                            entry.line,
                            format!(
                                "this peer relays through {}, which has no [Server] or [Peer.name] \
                                 record; clients could not resolve the relay",
                                encode_key(&relay)
                            ),
                        )
                    })?;
                if relay_draft.relay.is_some() {
                    return Err(ConfigError::at(
                        path,
                        entry.line,
                        format!(
                            "this peer relays through {}, which is itself relayed; relay chaining \
                             is not supported",
                            encode_key(&relay)
                        ),
                    ));
                }
                if draft.endpoint.is_some() {
                    tracing::warn!(
                        "peer {} has both an `Endpoint` and a `Relay`; \
                         clients route through the relay",
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
            draft.addresses.clone(),
            draft.persistent_keepalive,
        ));
    }

    // Not fatal: a peer with neither an endpoint nor a relay is exactly how a
    // roaming client behind NAT is configured. It is worth saying once, since
    // it is also what a forgotten `Endpoint` looks like.
    for draft in drafts {
        if draft.endpoint.is_none() && draft.relay.is_none() {
            tracing::debug!(
                "peer {} (line {}) has neither `Endpoint` nor `Relay`; \
                 only peers that initiate can reach it",
                draft_label(draft),
                draft.line
            );
        }
    }

    Ok(records)
}

fn draft_label(draft: &Draft) -> String {
    draft
        .name
        .clone()
        .unwrap_or_else(|| short(&draft.public_key))
}

/// Look up a single-valued key, translating a duplicate into a config error.
fn field<'a>(
    section: &'a Section,
    key: &str,
    path: &Path,
) -> Result<Option<&'a Entry>, ConfigError> {
    section
        .get(key)
        .map_err(|(line, message)| ConfigError::at(path, line, message))
}

fn reject_unknown(section: &Section, allowed: &[&str], path: &Path) -> Result<(), ConfigError> {
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

fn key(value: &str, line: usize, what: &str, path: &Path) -> Result<[u8; 32], ConfigError> {
    decode_key(value).map_err(|_| {
        ConfigError::at(
            path,
            line,
            format!(
                "`{what}` must be a key in base64, as `wg` writes one \
                 ({KEY_TEXT_LEN} characters ending in `=`), found `{value}`"
            ),
        )
    })
}

/// The leading characters of a key's base64 form, used for the unnamed
/// Server record in log lines. Long enough to pick a peer out of a file,
/// short enough not to wrap it.
fn short(public_key: &[u8; 32]) -> String {
    encode_key(public_key).as_str()[..KEY_PREFIX_LEN].to_string()
}

#[cfg(test)]
pub(crate) mod tests {
    use std::path::PathBuf;

    use super::*;

    /// The private key every test configuration uses, and the public key it
    /// derives to. Pinning the pair here is what proves the derivation is wired
    /// up: no test can assert the server's identity without it.
    pub(crate) const SERVER_PRIVATE: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

    /// `[0xAA; 32]`, `[0xBB; 32]` and `[0xCC; 32]`.
    const KEY_A: &str = "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=";
    const KEY_B: &str = "u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7s=";
    const KEY_C: &str = "zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMw=";

    /// The public key `SERVER_PRIVATE` derives to.
    pub(crate) fn server_public() -> [u8; 32] {
        derive_public_key(&decode_key(SERVER_PRIVATE).expect("the test private key decodes"))
    }

    fn load_text(text: &str) -> Result<Loaded, ConfigError> {
        parse(text, &PathBuf::from("apiserver.conf"))
    }

    fn valid_interface() -> String {
        format!("[Server]\nPrivateKey = {SERVER_PRIVATE}\nAddresses = 10.255.255.1/32\n\n")
    }

    fn error_of(text: &str) -> String {
        load_text(text).expect_err("rejected").to_string()
    }

    fn peer_error_of(peer: &str) -> String {
        error_of(&format!("{}{peer}", valid_interface()))
    }

    #[test]
    fn loads_a_full_configuration() {
        let text = format!(
            "\
[Server]
PrivateKey = {SERVER_PRIVATE}
ListenPort = 127.0.0.1:51999
Endpoint = 203.0.113.10:51820
Addresses = 10.0.0.1/32
RelayForwarding = true

[Peer.gateway]
PublicKey = {KEY_B}
Endpoint = 198.51.100.20:51820
Addresses = 10.0.0.3/32, 10.5.0.0/24

[Peer.laptop]
PublicKey = {KEY_C}
Addresses = 10.0.0.7/32
Relay = GATEWAY
"
        );
        let loaded = load_text(&text).expect("loads");

        assert_eq!(loaded.options.listen, "127.0.0.1:51999".parse().unwrap());
        assert!(loaded.options.relay_forwarding);
        assert_eq!(loaded.options.public_key, server_public());

        assert_eq!(loaded.registry.peer_count(), 3);
        assert_eq!(loaded.registry.route_count(), 4);

        let server = loaded
            .registry
            .lookup_key(&server_public())
            .expect("the [Server] record is keyed by the derived public key");
        assert_eq!(
            server.addresses.as_slice(),
            &["10.0.0.1/32".parse::<IpCidr>().unwrap()]
        );
        let gateway = loaded.registry.lookup_key(&[0xBB; 32]).expect("gateway");
        assert_eq!(gateway.addresses.len(), 2);

        let laptop = loaded.registry.lookup_key(&[0xCC; 32]).expect("laptop");
        assert_eq!(laptop.relay, Some([0xBB; 32]));
    }

    #[test]
    fn links_are_symmetric_without_device_mesh() {
        let text = format!(
            "\
[Server]
PrivateKey = {SERVER_PRIVATE}
Addresses = 10.0.0.1/32

[Peer.alice]
PublicKey = {KEY_A}
Addresses = 10.0.0.2/32

[Peer.device-001]
PublicKey = {KEY_B}
Addresses = 10.0.0.3/32

[Peer.device-002]
PublicKey = {KEY_C}
Addresses = 10.0.0.4/32

[Group.clients]
Peers = alice

[Group.devices]
Peers = device-001, device-002

[Link.clients]
Groups = clients

[Link.clients-devices]
Groups = clients, devices
"
        );
        let loaded = load_text(&text).expect("loads");

        // Self-access is implicit.
        assert!(loaded.registry.are_linked(&[0xAA; 32], &[0xAA; 32]));
        assert!(loaded.registry.are_linked(&[0xBB; 32], &[0xBB; 32]));

        // A two-group link creates mutual visibility.
        assert!(loaded.registry.are_linked(&[0xAA; 32], &[0xBB; 32]));
        assert!(loaded.registry.are_linked(&[0xBB; 32], &[0xAA; 32]));
        assert!(loaded.registry.are_linked(&[0xAA; 32], &[0xCC; 32]));
        assert!(loaded.registry.are_linked(&[0xCC; 32], &[0xAA; 32]));

        // Devices do not see one another because there is no one-group devices link.
        assert!(!loaded.registry.are_linked(&[0xBB; 32], &[0xCC; 32]));
        assert!(!loaded.registry.are_linked(&[0xCC; 32], &[0xBB; 32]));

        // The unnamed server record is outside the groups and therefore hidden.
        assert!(!loaded.registry.are_linked(&[0xAA; 32], &server_public()));
    }

    #[test]
    fn one_group_link_creates_an_internal_mesh() {
        let text = format!(
            "{}[Peer.a]\nPublicKey = {KEY_A}\nAddresses = 10.0.0.2/32\n\n\
             [Peer.b]\nPublicKey = {KEY_B}\nAddresses = 10.0.0.3/32\n\n\
             [Group.clients]\nPeers = a, b\n\n\
             [Link.client-mesh]\nGroups = clients\n",
            valid_interface()
        );
        let loaded = load_text(&text).expect("loads");
        assert!(loaded.registry.are_linked(&[0xAA; 32], &[0xBB; 32]));
        assert!(loaded.registry.are_linked(&[0xBB; 32], &[0xAA; 32]));
    }

    #[test]
    fn peer_and_group_names_use_separate_namespaces() {
        let text = format!(
            "{}[Peer.clients]\nPublicKey = {KEY_A}\nAddresses = 10.0.0.2/32\n\n\
             [Peer.other]\nPublicKey = {KEY_B}\nAddresses = 10.0.0.3/32\n\n\
             [Group.clients]\nPeers = clients, other\n\n\
             [Link.clients]\nGroups = clients\n",
            valid_interface()
        );
        let loaded = load_text(&text).expect("loads");
        assert!(loaded.registry.are_linked(&[0xAA; 32], &[0xBB; 32]));
    }

    #[test]
    fn groups_without_links_are_isolated() {
        let text = format!(
            "{}[Peer.a]\nPublicKey = {KEY_A}\nAddresses = 10.0.0.2/32\n\n\
             [Peer.b]\nPublicKey = {KEY_B}\nAddresses = 10.0.0.3/32\n\n\
             [Group.a]\nPeers = a\n\n\
             [Group.b]\nPeers = b\n",
            valid_interface()
        );
        let loaded = load_text(&text).expect("loads");
        assert!(loaded.registry.are_linked(&[0xAA; 32], &[0xAA; 32]));
        assert!(!loaded.registry.are_linked(&[0xAA; 32], &[0xBB; 32]));
    }

    #[test]
    fn no_groups_denies_cross_peer_visibility() {
        let text = format!(
            "{}[Peer.a]\nPublicKey = {KEY_A}\nAddresses = 10.0.0.2/32\n\n\
             [Peer.b]\nPublicKey = {KEY_B}\nAddresses = 10.0.0.3/32\n",
            valid_interface()
        );
        let loaded = load_text(&text).expect("loads");
        assert!(loaded.registry.are_linked(&[0xAA; 32], &[0xAA; 32]));
        assert!(loaded.registry.are_linked(&[0xBB; 32], &[0xBB; 32]));
        assert!(!loaded.registry.are_linked(&[0xAA; 32], &[0xBB; 32]));
        assert!(!loaded.registry.are_linked(&[0xBB; 32], &[0xAA; 32]));
    }

    #[test]
    fn group_peers_must_name_peers_not_groups() {
        let text = format!(
            "{}[Peer.a]\nPublicKey = {KEY_A}\nAddresses = 10.0.0.2/32\n\n\
             [Group.first]\nPeers = a\n\n\
             [Group.second]\nPeers = first\n",
            valid_interface()
        );
        assert!(error_of(&text).contains("may only name peers"));
    }

    #[test]
    fn link_must_name_existing_groups() {
        let text = format!(
            "{}[Peer.a]\nPublicKey = {KEY_A}\nAddresses = 10.0.0.2/32\n\n\
             [Group.clients]\nPeers = a\n\n\
             [Link.clients-devices]\nGroups = clients, devices\n",
            valid_interface()
        );
        assert!(error_of(&text).contains("unknown group `devices`"));
    }

    #[test]
    fn link_must_name_one_or_two_groups() {
        let text = format!(
            "{}[Peer.a]\nPublicKey = {KEY_A}\nAddresses = 10.0.0.2/32\n\n\
             [Group.a]\nPeers = a\n\n\
             [Group.b]\nPeers = a\n\n\
             [Group.c]\nPeers = a\n\n\
             [Link.too-many]\nGroups = a, b, c\n",
            valid_interface()
        );
        assert!(error_of(&text).contains("must name one group"));
    }

    #[test]
    fn duplicate_or_reversed_links_are_rejected() {
        let text = format!(
            "{}[Peer.a]\nPublicKey = {KEY_A}\nAddresses = 10.0.0.2/32\n\n\
             [Peer.b]\nPublicKey = {KEY_B}\nAddresses = 10.0.0.3/32\n\n\
             [Group.a]\nPeers = a\n\n\
             [Group.b]\nPeers = b\n\n\
             [Link.first]\nGroups = a, b\n\n\
             [Link.second]\nGroups = b, a\n",
            valid_interface()
        );
        assert!(error_of(&text).contains("duplicates the relationship"));
    }

    #[test]
    fn same_group_twice_is_rejected_in_favor_of_one_group_link() {
        let text = format!(
            "{}[Peer.a]\nPublicKey = {KEY_A}\nAddresses = 10.0.0.2/32\n\n\
             [Group.clients]\nPeers = a\n\n\
             [Link.clients]\nGroups = clients, clients\n",
            valid_interface()
        );
        assert!(error_of(&text).contains("names the same group twice"));
    }

    #[test]
    fn link_policy_requires_an_accessible_relay_for_every_accessible_relayed_peer() {
        let text = format!(
            "{}\
[Peer.gateway]\nPublicKey = {KEY_A}\nEndpoint = 198.51.100.10:51820\nAddresses = 10.0.0.2/32\n\n\
[Peer.client]\nPublicKey = {KEY_B}\nAddresses = 10.0.0.3/32\nRelay = gateway\n\n\
[Peer.viewer]\nPublicKey = {KEY_C}\nAddresses = 10.0.0.4/32\n\n\
[Group.viewers]\nPeers = viewer\n\n\
[Group.clients]\nPeers = client\n\n\
[Group.relays]\nPeers = gateway\n\n\
[Link.viewer-client]\nGroups = viewers, clients\n",
            valid_interface()
        );
        assert!(error_of(&text).contains("but not its relay"));
    }

    #[test]
    fn relay_forwarding_defaults_off_and_parses_booleans() {
        let disabled = load_text(&valid_interface()).expect("loads");
        assert!(!disabled.options.relay_forwarding);

        for value in ["true", "TRUE", "True"] {
            let text = format!(
                "[Server]\nPrivateKey = {SERVER_PRIVATE}\nAddresses = 10.0.0.1/32\nRelayForwarding = {value}\n"
            );
            assert!(load_text(&text).expect("loads").options.relay_forwarding);
        }

        let explicit_false = format!(
            "[Server]\nPrivateKey = {SERVER_PRIVATE}\nAddresses = 10.0.0.1/32\nRelayForwarding = false\n"
        );
        assert!(
            !load_text(&explicit_false)
                .expect("loads")
                .options
                .relay_forwarding
        );

        let invalid = format!(
            "[Server]\nPrivateKey = {SERVER_PRIVATE}\nAddresses = 10.0.0.1/32\nRelayForwarding = yes\n"
        );
        assert!(error_of(&invalid).contains("`RelayForwarding` must be `true` or `false`"));
    }

    #[test]
    fn the_public_key_is_derived_not_configured() {
        // Supplying it — even correctly — is an error, because a second source
        // of truth is a second thing that can disagree with the tunnel.
        let correct = encode_key(&server_public());
        let text = format!(
            "[Server]\nPrivateKey = {SERVER_PRIVATE}\nPublicKey = {correct}\nAddresses = 10.0.0.1/32\n"
        );
        assert!(error_of(&text).contains("derived from `PrivateKey`"));

        assert!(
            error_of("[Server]\nAddresses = 10.0.0.1/32\n").contains("no `PrivateKey`"),
            "a Peers API server without a private key has no identity to derive"
        );
    }

    #[test]
    fn a_peer_can_relay_through_the_api_server_public_key() {
        let server = encode_key(&server_public());
        let text = format!(
            "\
[Server]
PrivateKey = {SERVER_PRIVATE}
Addresses = 10.0.0.1/32

[Peer.client]
PublicKey = {KEY_B}
Addresses = 10.0.0.2/32
Relay = {server}
"
        );
        let loaded = load_text(&text).expect("loads");
        let peer = loaded.registry.lookup_key(&[0xBB; 32]).unwrap();
        assert_eq!(peer.relay, Some(server_public()));
    }

    #[test]
    fn self_relay_alias_resolves_to_the_api_server_public_key() {
        for alias in ["@self", "@SELF"] {
            let text = format!(
                "\
[Server]
PrivateKey = {SERVER_PRIVATE}
Addresses = 10.0.0.1/32

[Peer.client]
PublicKey = {KEY_B}
Addresses = 10.0.0.2/32
Relay = {alias}
"
            );
            let loaded = load_text(&text).expect("loads");
            let peer = loaded.registry.lookup_key(&[0xBB; 32]).unwrap();
            assert_eq!(peer.relay, Some(server_public()));
        }
    }

    #[test]
    fn peer_sections_repeat_but_the_interface_does_not() {
        let text = format!(
            "{}[Peer.alpha]\nPublicKey = {KEY_A}\nAddresses = 10.0.0.1/32\n\n\
             [Peer.beta]\nPublicKey = {KEY_B}\nAddresses = 10.0.0.2/32\n",
            valid_interface()
        );
        let loaded = load_text(&text).expect("loads");
        assert_eq!(loaded.registry.peer_count(), 3);

        assert!(
            error_of(&format!(
                "{}[Peer]\nPublicKey = {KEY_A}\nAddresses = 10.0.0.1/32\n",
                valid_interface()
            ))
            .contains("must be named")
        );
        assert!(
            error_of(&format!(
                "{}[Peer.]\nPublicKey = {KEY_A}\nAddresses = 10.0.0.1/32\n",
                valid_interface()
            ))
            .contains("name is empty")
        );

        let duplicate_name = format!(
            "{}[Peer.gateway]\nPublicKey = {KEY_A}\nAddresses = 10.0.0.1/32\n\n\
             [peer.GATEWAY]\nPublicKey = {KEY_B}\nAddresses = 10.0.0.2/32\n",
            valid_interface()
        );
        assert!(error_of(&duplicate_name).contains("duplicate peer name"));

        let twice = format!("{}{}", valid_interface(), valid_interface());
        assert!(error_of(&twice).contains("duplicate [Server]"));
    }

    #[test]
    fn sections_and_keys_are_case_insensitive() {
        let text = format!(
            "\
[Server]
privatekey = {SERVER_PRIVATE}
listenport = 51999
addresses = 10.0.0.1/32

[PEER.gateway]
publickey = {KEY_B}
ADDRESSES = 10.0.0.2/32
"
        );
        let loaded = load_text(&text).expect("loads");
        assert_eq!(loaded.options.listen, "0.0.0.0:51999".parse().unwrap());
        assert!(loaded.registry.lookup_key(&[0xBB; 32]).is_some());
    }

    #[test]
    fn listen_port_defaults_and_accepts_an_address() {
        let text = format!("[Server]\nPrivateKey = {SERVER_PRIVATE}\nAddresses = 10.0.0.1/32\n");
        let loaded = load_text(&text).expect("loads");
        assert_eq!(loaded.options.listen, "0.0.0.0:51820".parse().unwrap());
        assert_eq!(loaded.registry.peer_count(), 1);

        // A bare port binds every address, as `wg` reads it.
        let text = format!(
            "[Server]\nPrivateKey = {SERVER_PRIVATE}\nListenPort = 51999\nAddresses = 10.0.0.1/32\n"
        );
        assert_eq!(
            load_text(&text).expect("loads").options.listen,
            "0.0.0.0:51999".parse::<SocketAddr>().unwrap()
        );

        // An address and port binds just that one.
        let text = format!(
            "[Server]\nPrivateKey = {SERVER_PRIVATE}\nListenPort = [::1]:51999\nAddresses = 10.0.0.1/32\n"
        );
        assert_eq!(
            load_text(&text).expect("loads").options.listen,
            "[::1]:51999".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn addresses_accept_repeats_and_separators() {
        let text = format!(
            "[Server]\nPrivateKey = {SERVER_PRIVATE}\nAddresses = 10.0.0.1/32 10.0.0.2/32\nAddresses = 10.0.0.3/32,10.0.0.1/32\n"
        );
        let loaded = load_text(&text).expect("loads");
        let peer = loaded.registry.lookup_key(&server_public()).unwrap();
        // Three unique prefixes; the repeat is collapsed.
        assert_eq!(peer.addresses.len(), 3);
    }

    #[test]
    fn host_bits_are_cleared() {
        let text = format!("[Server]\nPrivateKey = {SERVER_PRIVATE}\nAddresses = 10.1.2.3/24\n");
        let loaded = load_text(&text).expect("loads");
        let peer = loaded.registry.lookup_key(&server_public()).unwrap();
        assert_eq!(peer.addresses[0], "10.1.2.0/24".parse::<IpCidr>().unwrap());
    }

    /// A missing prefix length means a host prefix, which is what almost every
    /// `Addresses` entry is in practice.
    #[test]
    fn abbreviated_host_prefixes() {
        let text =
            format!("[Server]\nPrivateKey = {SERVER_PRIVATE}\nAddresses = 10.0.0.1, fd00::1\n");
        let loaded = load_text(&text).expect("loads");
        let peer = loaded.registry.lookup_key(&server_public()).unwrap();
        assert_eq!(peer.addresses[0], "10.0.0.1/32".parse::<IpCidr>().unwrap());
        assert_eq!(peer.addresses[1], "fd00::1/128".parse::<IpCidr>().unwrap());
    }

    /// The abbreviation is an input convenience only: what the server serves
    /// still carries the length, so no peer sees the short form.
    #[test]
    fn abbreviated_prefixes_are_served_in_full() {
        let text = format!("[Server]\nPrivateKey = {SERVER_PRIVATE}\nAddresses = 10.0.0.1\n");
        let loaded = load_text(&text).expect("loads");
        let peer = loaded.registry.lookup_key(&server_public()).unwrap();
        assert_eq!(format!("{:#}", peer.addresses[0]), "10.0.0.1/32");
    }

    #[test]
    fn ipv4_mapped_endpoints_are_normalized() {
        let text = format!(
            "[Server]\nPrivateKey = {SERVER_PRIVATE}\nAddresses = 10.0.0.1/32\nEndpoint = [::ffff:203.0.113.5]:51820\n"
        );
        let loaded = load_text(&text).expect("loads");
        let peer = loaded.registry.lookup_key(&server_public()).unwrap();
        assert_eq!(peer.endpoint, Some("203.0.113.5:51820".parse().unwrap()));
    }

    #[test]
    fn persistent_keepalive_is_wireguard_style_seconds() {
        let text = format!(
            concat!(
                "{}[Peer.client]\nPublicKey = {}\n",
                "Addresses = 10.0.0.2/32\nPersistentKeepalive = 25\n",
            ),
            valid_interface(),
            KEY_A,
        );
        let loaded = load_text(&text).expect("loads");
        let peer = loaded.registry.lookup_key(&[0xAA; 32]).expect("peer");
        assert_eq!(peer.persistent_keepalive, Some(25));
        assert_eq!(
            peer.resolved().persistent_keepalive,
            Some(microtun_core::Duration::from_secs(25))
        );

        let disabled = format!(
            concat!(
                "{}[Peer.client]\nPublicKey = {}\n",
                "Addresses = 10.0.0.2/32\nPersistentKeepalive = 0\n",
            ),
            valid_interface(),
            KEY_A,
        );
        let loaded = load_text(&disabled).expect("zero disables keepalive");
        assert_eq!(
            loaded
                .registry
                .lookup_key(&[0xAA; 32])
                .expect("peer")
                .persistent_keepalive,
            None
        );

        for invalid in ["-1", "65536", "not-a-number"] {
            let peer = format!(
                concat!(
                    "[Peer.client]\nPublicKey = {}\n",
                    "Addresses = 10.0.0.2/32\nPersistentKeepalive = {}\n",
                ),
                KEY_A, invalid,
            );
            assert!(
                peer_error_of(&peer).contains("number of seconds from 0 to 65535"),
                "invalid value {invalid} was not rejected"
            );
        }
    }

    #[test]
    fn rejects_bad_peers() {
        let base = format!("[Peer.test-peer]\nPublicKey = {KEY_A}\n");

        assert!(peer_error_of(&base).contains("no `Addresses`"));
        assert!(
            peer_error_of("[Peer.test-peer]\nAddresses = 10.0.0.1/32\n").contains("no `PublicKey`")
        );
        assert!(
            peer_error_of("[Peer.test-peer]\nPublicKey = nope\nAddresses = 10.0.0.1/32\n")
                .contains("must be a key in base64")
        );
        // Hexadecimal, which is what a key used to be written in here.
        let hexadecimal = "ab".repeat(32);
        assert!(
            peer_error_of(&format!(
                "[Peer.test-peer]\nPublicKey = {hexadecimal}\nAddresses = 10.0.0.1/32\n"
            ))
            .contains("must be a key in base64")
        );
        assert!(peer_error_of(&format!("{base}Addresses = 0.0.0.0/0\n")).contains("default route"));
        assert!(
            peer_error_of(&format!(
                "{base}Addresses = 10.0.0.0/32 10.0.0.1/32 10.0.0.2/32 10.0.0.3/32 10.0.0.4/32\n"
            ))
            .contains("at most 4")
        );
        // Malformed, as opposed to merely abbreviated: a bare address is
        // legal and means a host prefix (see `abbreviated_host_prefixes`).
        assert!(peer_error_of(&format!("{base}Addresses = 10.0.0.1/33\n")).contains("not a CIDR"));
        assert!(peer_error_of(&format!("{base}Addresses = 10.0.0.256\n")).contains("not a CIDR"));
        assert!(peer_error_of(&format!("{base}Addresses = /24\n")).contains("not a CIDR"));
        assert!(
            peer_error_of(&format!(
                "{base}Addresses = 10.0.0.1/32\nEndpoint = 198.51.100.20\n"
            ))
            .contains("`Endpoint` must be")
        );
        assert!(
            peer_error_of(&format!(
                "{base}Addresses = 10.0.0.1/32\nInboundPolicy = established_only\n"
            ))
            .contains("unknown key `InboundPolicy`")
        );
        assert!(
            peer_error_of(&format!("{base}Addresses = 10.0.0.1/32\nEndpont = x\n"))
                .contains("unknown key `Endpont`")
        );
        // Repeated `Addresses` is legal and must not become a duplicate-key
        // error the way a repeated `Endpoint` would.
        let repeated = format!(
            "{}{base}Addresses = 10.0.0.1/32\nAddresses = 10.0.0.2/32\n",
            valid_interface()
        );
        assert!(load_text(&repeated).is_ok());
        assert!(
            peer_error_of(&format!(
                "{base}Addresses = 10.0.0.1/32\nEndpoint = 1.2.3.4:1\nEndpoint = 1.2.3.5:1\n"
            ))
            .contains("duplicate key `Endpoint`")
        );
    }

    #[test]
    fn rejects_bad_relays() {
        let base = format!("[Peer.client]\nPublicKey = {KEY_A}\nAddresses = 10.0.0.1/32\n");

        assert!(peer_error_of(&format!("{base}Relay = {KEY_A}\n")).contains("its own relay"));
        assert!(
            peer_error_of(&format!("{base}Relay = gateway\n"))
                .contains("no [Peer.gateway] section exists")
        );
        assert!(
            peer_error_of(&format!("{base}Relay = {KEY_B}\n"))
                .contains("no [Server] or [Peer.name]")
        );

        let named_self = format!(
            "{}[Peer.client]\nPublicKey = {KEY_A}\nAddresses = 10.0.0.1/32\nRelay = CLIENT\n",
            valid_interface()
        );
        assert!(error_of(&named_self).contains("its own relay"));

        let chained = format!(
            "{}[Peer.first]\nPublicKey = {KEY_A}\nAddresses = 10.0.0.1/32\nRelay = second\n\n\
             [Peer.second]\nPublicKey = {KEY_B}\nAddresses = 10.0.0.2/32\nRelay = third\n\n\
             [Peer.third]\nPublicKey = {KEY_C}\nEndpoint = 192.0.2.3:51820\nAddresses = 10.0.0.3/32\n",
            valid_interface()
        );
        assert!(error_of(&chained).contains("relay chaining"));
    }

    #[test]
    fn rejects_bad_interface_section() {
        let base = format!("[Server]\nPrivateKey = {SERVER_PRIVATE}\n");

        assert!(
            error_of(&format!("{base}ListenPort = nowhere\n")).contains("`ListenPort` must be")
        );
        assert!(error_of(&format!("{base}Lissen = 51820\n")).contains("unknown key `Lissen`"));
        // `wg` spells it `ListenPort`, and so does this.
        assert!(
            error_of(&format!("{base}Listen = 0.0.0.0:51820\n")).contains("unknown key `Listen`")
        );
        assert!(error_of("[Interfaces]\n").contains("unknown section"));
        assert!(error_of(&format!("{base}ListenPort = 51820\n")).contains("no `Addresses`"));
        assert!(
            error_of(&format!(
                "[Peer.test-peer]\nPublicKey = {KEY_A}\nAddresses = 10.0.0.1/32\n"
            ))
            .contains("missing [Server] section")
        );
    }

    #[test]
    fn ini_syntax_errors_carry_a_line() {
        assert!(error_of("[Server\n").contains("unterminated section header"));
        assert!(error_of("PrivateKey = x\n").contains("before any [Section]"));
        assert!(error_of("[Server]\njust-a-word\n").contains("expected `Key = value`"));
        assert!(error_of("[Server]\n = value\n").contains("empty key"));
        assert!(error_of("[]\n").contains("empty section name"));
        assert!(
            error_of(&format!(
                "[Server]\nPrivateKey = {SERVER_PRIVATE}\nPrivateKey = {SERVER_PRIVATE}\n"
            ))
            .contains("duplicate key `PrivateKey`")
        );
    }

    #[test]
    fn comments_are_recognized_with_either_marker() {
        let text = format!(
            "\
# a hash comment
; a semicolon comment
[Server]
PrivateKey = {SERVER_PRIVATE}   ; trailing text is part of no value
Addresses = 10.0.0.1/32
"
        );
        // The trailing `;` is *not* a comment — it is inside the value, which is
        // why the key no longer parses. Comments start lines; values keep their
        // characters.
        assert!(load_text(&text).is_err());

        let clean = format!(
            "# lead\n; lead\n[Server]\nPrivateKey = {SERVER_PRIVATE}\nAddresses = 10.0.0.1/32\n"
        );
        assert!(load_text(&clean).is_ok());
    }

    #[test]
    fn errors_carry_the_file_and_line() {
        let error = load_text("[Server]\nPrivateKey = short\nAddresses = 10.0.0.1/32\n")
            .expect_err("rejected");
        assert_eq!(error.line, Some(2));
        assert!(error.to_string().starts_with("apiserver.conf:2: "));
    }
}
