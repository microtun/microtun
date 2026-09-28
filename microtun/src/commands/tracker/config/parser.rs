use std::path::Path;

use toml_parser::{
    ErrorSink, Raw, Source, Span,
    decoder::{Encoding, IntegerRadix, ScalarKind, StringBuilder},
    parser::{EventReceiver, parse_document},
};

use super::{ConfigError, MicrotunConfig, PeerConfig, TrackerConfig, TunnelConfig};

#[derive(Default)]
struct MicrotunBuilder {
    api_version: Option<String>,
    kind: Option<String>,
}

#[derive(Default)]
struct TunnelBuilder {
    private_key: Option<String>,
    tunnel_address: Option<String>,
    mtu: Option<u16>,
    listen_port: Option<u16>,
    enable_forwarding: Option<bool>,
}

#[derive(Default)]
struct PeerBuilder {
    name: Option<String>,
    public_key: Option<String>,
    endpoint: Option<String>,
    address: Option<String>,
    relay: Option<String>,
    persistent_keepalive: Option<u16>,
}

#[derive(Default)]
struct TrackerTomlBuilder {
    seen_microtun: bool,
    seen_tunnel: bool,
    microtun: MicrotunBuilder,
    tunnel: TunnelBuilder,
    peers: Vec<PeerBuilder>,
}

impl TrackerTomlBuilder {
    fn finish(self, path: &Path) -> Result<TrackerConfig, ConfigError> {
        if !self.seen_microtun {
            return Err(ConfigError::file(path, "missing [Microtun] table"));
        }
        if !self.seen_tunnel {
            return Err(ConfigError::file(path, "missing [Tunnel] table"));
        }

        let microtun = MicrotunConfig {
            api_version: self
                .microtun
                .api_version
                .ok_or_else(|| ConfigError::file(path, "missing Microtun.ApiVersion"))?,
            kind: self
                .microtun
                .kind
                .ok_or_else(|| ConfigError::file(path, "missing Microtun.Kind"))?,
        };
        let tunnel = TunnelConfig {
            private_key: self
                .tunnel
                .private_key
                .ok_or_else(|| ConfigError::file(path, "missing Tunnel.PrivateKey"))?,
            tunnel_address: self
                .tunnel
                .tunnel_address
                .ok_or_else(|| ConfigError::file(path, "missing Tunnel.Address"))?,
            mtu: self.tunnel.mtu,
            listen_port: self.tunnel.listen_port,
            enable_forwarding: self.tunnel.enable_forwarding.unwrap_or(false),
        };

        let mut peers = Vec::with_capacity(self.peers.len());
        for (index, peer) in self.peers.into_iter().enumerate() {
            let label = index + 1;
            peers.push(PeerConfig {
                name: peer.name.ok_or_else(|| {
                    ConfigError::file(path, format!("missing Peer[{label}].Name"))
                })?,
                public_key: peer.public_key.ok_or_else(|| {
                    ConfigError::file(path, format!("missing Peer[{label}].PublicKey"))
                })?,
                endpoint: peer.endpoint,
                address: peer.address.ok_or_else(|| {
                    ConfigError::file(path, format!("missing Peer[{label}].Address"))
                })?,
                relay: peer.relay,
                persistent_keepalive: peer.persistent_keepalive,
            });
        }

        Ok(TrackerConfig {
            microtun,
            tunnel,
            peers,
        })
    }
}

struct StdStringBuilder<'a>(&'a mut String);

impl<'s> StringBuilder<'s> for StdStringBuilder<'_> {
    fn clear(&mut self) {
        self.0.clear();
    }

    fn push_str(&mut self, append: &'s str) -> bool {
        self.0.push_str(append);
        true
    }

    fn push_char(&mut self, append: char) -> bool {
        self.0.push(append);
        true
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TomlSection {
    Root,
    Microtun,
    Tunnel,
    Peer(usize),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HeaderKind {
    None,
    Standard,
    Array,
}

struct TrackerTomlReceiver<'i> {
    source: Source<'i>,
    section: TomlSection,
    header_kind: HeaderKind,
    header_name: String,
    pending_key: Option<(Span, String)>,
    builder: TrackerTomlBuilder,
    semantic_error: Option<(Span, String)>,
}

impl<'i> TrackerTomlReceiver<'i> {
    fn new(source: Source<'i>) -> Self {
        Self {
            source,
            section: TomlSection::Root,
            header_kind: HeaderKind::None,
            header_name: String::new(),
            pending_key: None,
            builder: TrackerTomlBuilder::default(),
            semantic_error: None,
        }
    }

    fn fail(&mut self, span: Span, message: impl Into<String>) {
        if self.semantic_error.is_none() {
            self.semantic_error = Some((span, message.into()));
        }
    }

    fn decode_key(&mut self, span: Span, encoding: Option<Encoding>) -> Option<String> {
        let Some(raw_text) = self.source.input().get(span.start()..span.end()) else {
            self.fail(span, "invalid TOML source span");
            return None;
        };
        let raw = Raw::new_unchecked(raw_text, encoding, span);
        let mut value = String::new();
        let mut output = StdStringBuilder(&mut value);
        let mut error = None;
        raw.decode_key(&mut output, &mut error);
        if let Some(error) = error {
            self.fail(
                error.unexpected().or(error.context()).unwrap_or(span),
                error.description(),
            );
            None
        } else {
            Some(value)
        }
    }

    fn finish_header(&mut self, span: Span) {
        let name = std::mem::take(&mut self.header_name);
        let section = match self.header_kind {
            HeaderKind::Standard => match name.as_str() {
                "Microtun" if !self.builder.seen_microtun => {
                    self.builder.seen_microtun = true;
                    TomlSection::Microtun
                }
                "Tunnel" if !self.builder.seen_tunnel => {
                    self.builder.seen_tunnel = true;
                    TomlSection::Tunnel
                }
                "Microtun" | "Tunnel" => {
                    self.fail(span, format!("duplicate [{name}] table"));
                    TomlSection::Root
                }
                "Peer" => {
                    self.fail(span, "Peer entries must use [[Peer]] array tables");
                    TomlSection::Root
                }
                _ => {
                    self.fail(span, format!("unknown TOML table [{name}]"));
                    TomlSection::Root
                }
            },
            HeaderKind::Array => match name.as_str() {
                "Peer" => {
                    self.builder.peers.push(PeerBuilder::default());
                    TomlSection::Peer(self.builder.peers.len() - 1)
                }
                _ => {
                    self.fail(span, format!("unknown TOML array table [[{name}]]"));
                    TomlSection::Root
                }
            },
            HeaderKind::None => {
                self.fail(span, "invalid TOML table header");
                TomlSection::Root
            }
        };
        self.section = section;
        self.header_kind = HeaderKind::None;
    }

    fn assign_scalar(&mut self, span: Span, encoding: Option<Encoding>) {
        let Some((key_span, key)) = self.pending_key.take() else {
            self.fail(span, "TOML value has no key");
            return;
        };
        if self.section == TomlSection::Root {
            self.fail(key_span, "top-level configuration keys are not supported");
            return;
        }

        let Some(raw_text) = self.source.input().get(span.start()..span.end()) else {
            self.fail(span, "invalid TOML source span");
            return;
        };
        let raw = Raw::new_unchecked(raw_text, encoding, span);
        let mut value = String::new();
        let mut output = StdStringBuilder(&mut value);
        let mut decode_error = None;
        let kind = raw.decode_scalar(&mut output, &mut decode_error);
        if let Some(error) = decode_error {
            self.fail(
                error.unexpected().or(error.context()).unwrap_or(span),
                error.description(),
            );
            return;
        }

        let ok = match self.section {
            TomlSection::Microtun => match key.as_str() {
                "ApiVersion" => set_string(&mut self.builder.microtun.api_version, value, kind),
                "Kind" => set_string(&mut self.builder.microtun.kind, value, kind),
                _ => false,
            },
            TomlSection::Tunnel => match key.as_str() {
                "PrivateKey" => set_string(&mut self.builder.tunnel.private_key, value, kind),
                "Address" => set_string(&mut self.builder.tunnel.tunnel_address, value, kind),
                "MTU" => set_u16(&mut self.builder.tunnel.mtu, &value, kind),
                "ListenPort" => set_u16(&mut self.builder.tunnel.listen_port, &value, kind),
                "EnableForwarding" => set_bool(&mut self.builder.tunnel.enable_forwarding, kind),
                _ => false,
            },
            TomlSection::Peer(index) => {
                let peer = &mut self.builder.peers[index];
                match key.as_str() {
                    "Name" => set_string(&mut peer.name, value, kind),
                    "PublicKey" => set_string(&mut peer.public_key, value, kind),
                    "Endpoint" => set_string(&mut peer.endpoint, value, kind),
                    "Address" => set_string(&mut peer.address, value, kind),
                    "Relay" => set_string(&mut peer.relay, value, kind),
                    "PersistentKeepalive" => set_u16(&mut peer.persistent_keepalive, &value, kind),
                    _ => false,
                }
            }
            TomlSection::Root => false,
        };
        if !ok {
            self.fail(
                key_span,
                format!(
                    "unknown, duplicate, or type-mismatched key {}.{}",
                    self.section_name(),
                    key
                ),
            );
        }
    }

    fn section_name(&self) -> &'static str {
        match self.section {
            TomlSection::Root => "<root>",
            TomlSection::Microtun => "Microtun",
            TomlSection::Tunnel => "Tunnel",
            TomlSection::Peer(_) => "Peer",
        }
    }
}

impl EventReceiver for TrackerTomlReceiver<'_> {
    fn std_table_open(&mut self, span: Span, _error: &mut dyn ErrorSink) {
        if self.pending_key.is_some() {
            self.fail(span, "unfinished TOML key before table header");
        }
        self.header_kind = HeaderKind::Standard;
        self.header_name.clear();
    }

    fn std_table_close(&mut self, span: Span, _error: &mut dyn ErrorSink) {
        if self.header_kind != HeaderKind::Standard || self.header_name.is_empty() {
            self.fail(span, "invalid TOML table header");
        } else {
            self.finish_header(span);
        }
    }

    fn array_table_open(&mut self, span: Span, _error: &mut dyn ErrorSink) {
        if self.pending_key.is_some() {
            self.fail(span, "unfinished TOML key before array table header");
        }
        self.header_kind = HeaderKind::Array;
        self.header_name.clear();
    }

    fn array_table_close(&mut self, span: Span, _error: &mut dyn ErrorSink) {
        if self.header_kind != HeaderKind::Array || self.header_name.is_empty() {
            self.fail(span, "invalid TOML array table header");
        } else {
            self.finish_header(span);
        }
    }

    fn inline_table_open(&mut self, span: Span, _error: &mut dyn ErrorSink) -> bool {
        self.fail(
            span,
            "inline tables are not supported in tracker configuration",
        );
        false
    }

    fn array_open(&mut self, span: Span, _error: &mut dyn ErrorSink) -> bool {
        self.fail(
            span,
            "array values are not supported in tracker configuration",
        );
        false
    }

    fn simple_key(&mut self, span: Span, encoding: Option<Encoding>, _error: &mut dyn ErrorSink) {
        let Some(key) = self.decode_key(span, encoding) else {
            return;
        };
        if self.header_kind != HeaderKind::None {
            if self.header_name.is_empty() {
                self.header_name = key;
            } else {
                self.fail(span, "dotted table names are not supported");
            }
        } else if self.pending_key.is_some() {
            self.fail(span, "dotted keys are not supported");
        } else {
            self.pending_key = Some((span, key));
        }
    }

    fn key_sep(&mut self, span: Span, _error: &mut dyn ErrorSink) {
        self.fail(span, "dotted keys and table names are not supported");
    }

    fn scalar(&mut self, span: Span, encoding: Option<Encoding>, _error: &mut dyn ErrorSink) {
        self.assign_scalar(span, encoding);
    }

    fn error(&mut self, span: Span, _error: &mut dyn ErrorSink) {
        self.fail(span, "invalid TOML syntax");
    }
}

fn set_string(slot: &mut Option<String>, value: String, kind: ScalarKind) -> bool {
    if slot.is_some() || kind != ScalarKind::String {
        return false;
    }
    *slot = Some(value);
    true
}

fn set_u16(slot: &mut Option<u16>, value: &str, kind: ScalarKind) -> bool {
    if slot.is_some() {
        return false;
    }
    let ScalarKind::Integer(radix) = kind else {
        return false;
    };
    let Some(parsed) = parse_u16(value, radix) else {
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

fn source_line(text: &str, span: Span) -> usize {
    text[..span.start().min(text.len())]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
}

pub(super) fn parse_tracker_toml(text: &str, path: &Path) -> Result<TrackerConfig, ConfigError> {
    let source = Source::new(text);
    let tokens: Vec<_> = source.lex().collect();
    let mut receiver = TrackerTomlReceiver::new(source);
    let mut parse_error = None;
    parse_document(&tokens, &mut receiver, &mut parse_error);

    if let Some(error) = parse_error {
        let line = error
            .unexpected()
            .or(error.context())
            .map(|span| source_line(text, span));
        let message = format!("invalid TOML: {}", error.description());
        return Err(match line {
            Some(line) => ConfigError::at(path, line, message),
            None => ConfigError::file(path, message),
        });
    }
    if let Some((span, message)) = receiver.semantic_error {
        return Err(ConfigError::at(path, source_line(text, span), message));
    }
    receiver.builder.finish(path)
}
