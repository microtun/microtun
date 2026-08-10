//! JSON-RPC 2.0 codec for the microtun Peers API.
//!
//! This crate owns the wire contract and an optional typed async client for
//! either `embedded-io-async` or native Tokio transports.
//! Runtime-specific timeout, scheduling, logging, and reconnect policy remains
//! outside this crate.
//!
//! # The calls
//!
//! ```text
//! --> {"jsonrpc":"2.0","id":1,"method":"v1.peer.by_key","params":{"public_key":"<base64>"}}
//! --> {"jsonrpc":"2.0","id":2,"method":"v1.peer.by_address","params":{"address":"10.0.0.5"}}
//! --> {"jsonrpc":"2.0","id":3,"method":"v1.peer.watch","params":{"public_key":"<base64>"}}
//! --> {"jsonrpc":"2.0","method":"v1.peer.unwatch","params":{"public_key":"<base64>"}}
//! <-- {"jsonrpc":"2.0","id":1,"result":{"found":{ ...record... }}}
//! <-- {"jsonrpc":"2.0","id":2,"result":{"not_found":{}}}     // authoritatively unknown
//! <-- {"jsonrpc":"2.0","id":2,"error":{...}}                  // transient failure
//! <-- {"jsonrpc":"2.0","id":3,"result":{"found":{ ...record... }}}
//! <-- {"jsonrpc":"2.0","method":"v1.peer.changed","params":{"public_key":"<base64>"}}
//! ```
//!
//! Both lookups answer questions about *another* peer; the caller's own
//! identity is fixed by the connection and is never a parameter.
//!
//! Lookups are side-effect free. A client that wants to keep a returned record
//! current explicitly calls `v1.peer.watch` for its public key. `v1.peer.watch`
//! atomically installs the subscription and returns the current by-key
//! [`LookupResult`], closing the race between learning a record and subscribing
//! to changes.
//!
//! When a watched record
//! changes or disappears the server sends `v1.peer.changed`, which names a key and
//! carries nothing else: it means *whatever you hold for this key may no
//! longer be current*. The client answers it with an ordinary `v1.peer.by_key`,
//! whose result is the new record or the `{"not_found":{}}` variant
//! that authoritatively removes the peer. A reconnecting client replays
//! `v1.peer.watch` for every record it still holds, which both reconciles its
//! state and re-establishes every subscription.
//!
//! # `not_found` answers a question about the registry, and nothing else
//!
//! The authoritative miss is reserved for one meaning: *the registry has no
//! record for the thing you asked about*. Two other failures that once shared
//! that answer no longer do, because neither is a statement about the target:
//!
//! * a caller with no registry record of its own is refused at accept, and any
//!   request that still reaches a handler answers
//!   [`ERROR_NOT_ADMITTED`] — a de-admitted client must not read its own
//!   removal as every peer it holds having been deleted;
//! * a syntactically undecodable key or address answers `-32602`, because a
//!   caller that cannot spell a key has learned nothing about who exists.
//!
//! Both are transient in the client's classification, so an installed record
//! survives them. See `docs/peers-api.md` §3.2 and §11.2.
//!
//! A notification with no payload cannot be stale, so it cannot be reordered
//! into a stale install. That is the whole reason it carries no record: a
//! record on the wire twice, from two snapshots, would oblige the server to
//! order responses against notifications — a guarantee that is invisible when
//! violated and undetectable by the client. Omitting it also merges
//! authoritative removal into the ordinary `not_found` lookup result. The price is
//! one round trip per changed key.
//!
//! `v1.peer.watch` and `v1.peer.unwatch` are the explicit watch-set operations.
//! `v1.peer.unwatch` is still safe to treat as best-effort: a stale notification
//! can race an eviction, so clients must ignore notifications for records they
//! no longer hold.
//!
//! # One shape per outcome
//!
//! A lookup result uses an externally tagged shape: `{"found":{...}}` or
//! `{"not_found":{}}`. Only the second is the old `404` — authoritative and
//! negative-cached by the core. An `error` object, malformed frame, and dead
//! connection are all the old `5xx`: transient, and an installed record
//! survives them.
//!
//! The explicit variant exists because absence is ambiguous and authority must
//! not be. A bare `null`, omitted `result`, decode default, or serialization
//! failure must never be inferred as removal. [`classify_result`] draws that
//! distinction once for every embedding.
//!
//! [`LookupResult`] is a normal Serde externally tagged enum. Its `Found`
//! newtype variant and empty `NotFound {}` struct variant serialize directly to
//! the two protocol result shapes.
//!
//! # One spelling for a key
//!
//! The HTTP protocol this replaces carried keys in two alphabets, because a
//! `by-key` *path segment* cannot contain the `/` of standard base64. JSON-RPC
//! parameters have no such restriction, so a key now has exactly one spelling
//! everywhere — the 44-character standard base64 WireGuard itself writes, in
//! configuration files, in parameters, in results, and in logs.
//! [`microtun_core::encode_key_url`] is no longer part of this protocol.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]

#[cfg(feature = "alloc")]
extern crate alloc;

// Client-side helpers stay out of the wire-only default build. The transport
// features are additive because Cargo may unify them when std and Embassy
// integrations are built in the same workspace graph.
#[cfg(any(feature = "embedded-client", feature = "tokio-client"))]
pub mod client;
#[cfg(any(feature = "embedded-client", feature = "tokio-client"))]
pub mod jitter;

use core::{
    fmt::Write as _,
    net::{IpAddr, SocketAddr},
};

use heapless::{String, Vec};
#[cfg(any(feature = "embedded-client", feature = "tokio-client"))]
pub use jitter::{Jitter, REFRESH_BURST_WINDOW_MS};
use microtun_core::{
    Duration, IpNet, KEY_TEXT_LEN, MAX_PEER_ADDRESSES, PeerAddresses, ResolveOutcome, ResolveQuery,
    ResolvedPeer, decode_key, encode_key, parse_ip_net, push_peer_address, unmap_socket_addr,
};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};

// ---------------------------------------------------------------------------
// Method names
// ---------------------------------------------------------------------------

/// Resolve a peer by its static public key.
pub const METHOD_BY_KEY: &str = "v1.peer.by_key";
/// Resolve the peer that owns a tunnel address (longest prefix wins).
pub const METHOD_BY_ADDRESS: &str = "v1.peer.by_address";
/// Start watching one peer record by static public key.
///
/// This is a request, not a notification. The server adds the key to the
/// connection watch set and reads the current record in one registry critical
/// section, then returns a [`LookupResult`]. A `found` response therefore
/// establishes both the initial state and the subscription without a race.
pub const METHOD_WATCH: &str = "v1.peer.watch";
/// Stop watching one peer record by static public key. This is a notification.
pub const METHOD_UNWATCH: &str = "v1.peer.unwatch";
/// Server-to-client notice that a watched key's state may have changed. This
/// is a notification, and it carries the key and nothing else: the client
/// answers it with an ordinary [`METHOD_BY_KEY`] lookup.
///
/// The name states what the server observed, not what the client should
/// conclude. The server knows only that the record is no longer the one the
/// client was last told about; whether that is a modification or a removal is
/// settled by the re-lookup, not by this notification.
pub const METHOD_CHANGED: &str = "v1.peer.changed";

// ---------------------------------------------------------------------------
// Application error codes
// ---------------------------------------------------------------------------

/// The caller's own key has no registry record, so it may not resolve peers.
///
/// This lives in JSON-RPC's implementation-defined server-error range. It is a
/// *transient* failure in the client's classification, which is the entire
/// reason it exists: answering `{"not_found":{}}` here would tell a client
/// whose own admission had lapsed that every peer it holds had been deleted,
/// and it would tear down its whole peer table on the strength of one bad
/// config push.
pub const ERROR_NOT_ADMITTED: i32 = -32001;

/// The caller exceeded its request budget. Transient; retry later.
///
/// Distinct from [`ERROR_NOT_ADMITTED`] so an operator reading a client log
/// can tell overload apart from a configuration fault. Both classify the same
/// way, so telling them apart costs the client nothing.
pub const ERROR_RATE_LIMITED: i32 = -32002;

// ---------------------------------------------------------------------------
// Wire-size budget
// ---------------------------------------------------------------------------

/// Longest textual IP address: an IPv4-mapped IPv6 address written in full.
pub const MAX_ADDRESS_TEXT_LEN: usize = 45;
/// Longest `ip:port` / `[ip]:port` endpoint: an address, brackets, and a port.
pub const MAX_ENDPOINT_TEXT_LEN: usize = MAX_ADDRESS_TEXT_LEN + 8;
/// Longest CIDR: an address, a slash, and up to three prefix-length digits.
pub const MAX_CIDR_TEXT_LEN: usize = MAX_ADDRESS_TEXT_LEN + 4;

/// Frame buffer size for the direction that carries a peer record.
///
/// A worst-case record — a 44-character key, a bracketed IPv6 endpoint, a
/// relay key, and [`MAX_PEER_ADDRESSES`] IPv6 CIDRs — plus the surrounding
/// lookup response fits below this bound. This is the client's `RX` and the
/// server's `TX`, and with the `alloc` feature of
/// `microtun-jsonrpc` left off (it must be) it is also the hard ceiling on a
/// Peers API response: a longer frame fails the read rather than growing a
/// buffer a hostile server controls.
pub const RECORD_FRAME_LEN: usize = 1024;

/// Frame buffer size for small control traffic.
///
/// Lookup, watch, and unwatch messages carry a method name and one short string. This
/// also has to fit the small error responses each side emits for malformed
/// traffic. Watch updates travel in the record direction, not this one.
pub const QUERY_FRAME_LEN: usize = 256;

/// Scratch capacity for a rendered query argument: a base64 key (44) or a
/// textual address (45), whichever is longer.
pub const QUERY_TEXT_LEN: usize = MAX_ADDRESS_TEXT_LEN;

const _: () = assert!(QUERY_TEXT_LEN >= KEY_TEXT_LEN);

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors while building or decoding the Peers API wire protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A bounded wire field or caller-provided buffer was too small.
    BufferTooSmall,
    /// The payload was not valid JSON for the Peers API schema.
    BadJson,
    /// A wire value had invalid syntax, such as a malformed key, endpoint, or
    /// CIDR.
    InvalidSyntax,
}

// ---------------------------------------------------------------------------
// Request parameters
// ---------------------------------------------------------------------------

/// Parameters of every message that names one peer key.
///
/// [`METHOD_BY_KEY`], [`METHOD_WATCH`], [`METHOD_UNWATCH`], and
/// [`METHOD_CHANGED`] all carry the same single-member object, so they share one
/// identical type. The key borrows from the frame it was read out of.
#[derive(Debug, Deserialize, Serialize)]
pub struct KeyParams<'a> {
    /// The peer's public key, as WireGuard's base64: 44 characters.
    #[serde(borrow)]
    pub public_key: &'a str,
}

/// Parameters of a [`METHOD_BY_ADDRESS`] call, as the server borrows them.
#[derive(Debug, Deserialize, Serialize)]
pub struct ByAddressParams<'a> {
    /// A tunnel address, in the usual textual form for its family.
    #[serde(borrow)]
    pub address: &'a str,
}

/// Scratch storage for the rendered argument of an outgoing query.
///
/// The parameters of a call borrow from here, so this must outlive the
/// [`Query`] built from it.
#[derive(Debug, Default)]
pub struct QueryText(String<QUERY_TEXT_LEN>);

impl QueryText {
    /// An empty buffer.
    pub const fn new() -> Self {
        Self(String::new())
    }
}

/// The parameters of an outgoing query, in either shape.
///
/// Serializes as the single-member object the corresponding `*Params` type
/// deserializes, so both ends of the call are defined by one type each way.
#[derive(Debug, Clone, Copy)]
pub enum QueryParams<'a> {
    /// Parameters for [`METHOD_BY_KEY`].
    ByKey {
        /// The queried key, in standard base64.
        public_key: &'a str,
    },
    /// Parameters for [`METHOD_BY_ADDRESS`].
    ByAddress {
        /// The queried tunnel address.
        address: &'a str,
    },
}

impl Serialize for QueryParams<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut object = serializer.serialize_struct("params", 1)?;
        match self {
            Self::ByKey { public_key } => object.serialize_field("public_key", public_key)?,
            Self::ByAddress { address } => object.serialize_field("address", address)?,
        }
        object.end()
    }
}

/// A core resolver query rendered as a JSON-RPC method and parameters.
#[derive(Debug, Clone, Copy)]
pub struct Query<'a> {
    /// The method to call.
    pub method: &'static str,
    /// Its parameters.
    pub params: QueryParams<'a>,
}

/// Render a core resolver query as the call that answers it.
///
/// `text` holds the rendered argument the returned parameters borrow.
///
/// ```ignore
/// let mut text = QueryText::new();
/// let call = microtun_api::encode_query(&request.query(), &mut text)?;
/// let record: Option<PeerInfo> = peer.call(call.method, Some(&call.params)).await?;
/// ```
pub fn encode_query<'a>(query: &ResolveQuery, text: &'a mut QueryText) -> Result<Query<'a>, Error> {
    text.0.clear();
    match *query {
        ResolveQuery::ByPublicKey(key) => {
            text.0
                .push_str(encode_key(&key).as_str())
                .map_err(|_| Error::BufferTooSmall)?;
            Ok(Query {
                method: METHOD_BY_KEY,
                params: QueryParams::ByKey {
                    public_key: text.0.as_str(),
                },
            })
        }
        ResolveQuery::ByDstAddress(address) => {
            write!(&mut text.0, "{address}").map_err(|_| Error::BufferTooSmall)?;
            Ok(Query {
                method: METHOD_BY_ADDRESS,
                params: QueryParams::ByAddress {
                    address: text.0.as_str(),
                },
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Result: the peer record
// ---------------------------------------------------------------------------

/// A bounded, owned peer record used for both serialization and decoding.
///
/// Using one owned shape costs a small copy when a server builds a response,
/// but keeps the wire contract represented by a single type everywhere.
///
/// Every field is bounded by the same limit the syntax it carries implies, so
/// an over-long value is a parse failure — a transient outcome — rather than
/// something the decoder has to reject later.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct PeerInfo {
    /// The peer's public key, as WireGuard's base64: 44 characters.
    pub public_key: String<KEY_TEXT_LEN>,
    /// Optional current outer endpoint, formatted as `"ip:port"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String<MAX_ENDPOINT_TEXT_LEN>>,
    /// Optional relay static public key, in the same base64 form.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<String<KEY_TEXT_LEN>>,
    /// Tunnel address prefixes assigned to the peer.
    pub addresses: Vec<String<MAX_CIDR_TEXT_LEN>, MAX_PEER_ADDRESSES>,
    /// WireGuard-style persistent keepalive interval in seconds.
    /// Absent means disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persistent_keepalive: Option<u16>,
}

impl PeerInfo {
    /// Build a wire record from validated peer fields.
    pub fn from_fields(
        public_key: &[u8; 32],
        endpoint: Option<SocketAddr>,
        relay: Option<&[u8; 32]>,
        addresses: impl IntoIterator<Item = IpNet>,
        persistent_keepalive: Option<u16>,
    ) -> Result<Self, Error> {
        let mut encoded_addresses = Vec::new();
        for address in addresses {
            let mut text = String::new();
            // `{:#}` is load-bearing, not cosmetic. `IpNet`'s plain `Display`
            // abbreviates a host prefix to a bare address, so `10.0.0.3/32`
            // would go on the wire as `10.0.0.3` — and §4.4 of the Peers API
            // spec defines this field as a CIDR string. The alternate form
            // always writes `address/length`.
            write!(&mut text, "{address:#}").map_err(|_| Error::BufferTooSmall)?;
            encoded_addresses
                .push(text)
                .map_err(|_| Error::BufferTooSmall)?;
        }

        Ok(Self {
            public_key: render_key(public_key)?,
            endpoint: endpoint.map(render_endpoint).transpose()?,
            relay: relay.map(render_key).transpose()?,
            addresses: encoded_addresses,
            persistent_keepalive,
        })
    }
}

// ---------------------------------------------------------------------------
// Result: the externally-tagged lookup outcome
// ---------------------------------------------------------------------------

/// The result member of a successful lookup response.
///
/// This is a normal Serde externally tagged enum. The wire forms are
/// `{"found": { ...PeerInfo... }}` and `{"not_found": {}}`.
///
/// `NotFound` is deliberately an empty struct variant rather than a unit
/// variant: Serde encodes an externally tagged unit variant as a string, while
/// an empty struct variant retains the object payload required by the protocol.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
#[allow(clippy::large_enum_variant)]
pub enum LookupResult {
    /// Positive result carrying one complete peer record.
    Found(PeerInfo),
    /// Authoritative negative result.
    NotFound {},
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// Map a lookup result to the core's resolver outcome.
///
/// This is the single place the authoritative/transient distinction is drawn:
/// **only** the exact `{"not_found":{}}` variant is
/// [`ResolveOutcome::NotFound`]. Malformed externally tagged shapes are rejected
/// during deserialization and therefore never reach this function; a `found`
/// payload whose peer fields are syntactically invalid becomes
/// [`ResolveOutcome::Failed`].
///
/// A syntactically valid record becomes [`ResolveOutcome::Found`] even when it
/// is semantically unacceptable; the core applies the authoritative resolver
/// policy when the response is completed.
///
/// Transport and remote-error cases never reach here: map them directly onto
/// [`ResolveOutcome::Failed`]. So does an absent or `null` `result` member,
/// which cannot produce a [`LookupResult`] at all.
pub fn classify_result(result: &LookupResult) -> ResolveOutcome {
    match result {
        LookupResult::Found(info) => match decode_peer(info) {
            Ok(peer) => ResolveOutcome::Found(peer),
            Err(_) => ResolveOutcome::Failed,
        },
        LookupResult::NotFound {} => ResolveOutcome::NotFound,
    }
}

/// Decode one peer record.
///
/// This validates wire syntax only. Semantic resolver policy is intentionally
/// left to [`microtun_core::Core`].
pub fn decode_peer(info: &PeerInfo) -> Result<ResolvedPeer, Error> {
    decode_fields(
        info.public_key.as_str(),
        info.endpoint.as_ref().map(String::as_str),
        info.relay.as_ref().map(String::as_str),
        info.addresses.iter().map(String::as_str),
        info.persistent_keepalive,
    )
}

/// Parse and decode a serialized peer record.
pub fn decode_record(body: &[u8]) -> Result<ResolvedPeer, Error> {
    decode_peer(&parse_record(body)?)
}

/// Parse a serialized peer record without decoding its string fields.
pub fn parse_record(body: &[u8]) -> Result<PeerInfo, Error> {
    let (info, _used) =
        serde_json_core::from_slice::<PeerInfo>(body).map_err(|_| Error::BadJson)?;
    Ok(info)
}

fn render_key(key: &[u8; 32]) -> Result<String<KEY_TEXT_LEN>, Error> {
    let mut text = String::new();
    text.push_str(encode_key(key).as_str())
        .map_err(|_| Error::BufferTooSmall)?;
    Ok(text)
}

fn render_endpoint(endpoint: SocketAddr) -> Result<String<MAX_ENDPOINT_TEXT_LEN>, Error> {
    let mut text = String::new();
    write!(&mut text, "{endpoint}").map_err(|_| Error::BufferTooSmall)?;
    Ok(text)
}

fn decode_fields<'a>(
    public_key: &str,
    endpoint: Option<&str>,
    relay: Option<&str>,
    addresses: impl Iterator<Item = &'a str>,
    persistent_keepalive: Option<u16>,
) -> Result<ResolvedPeer, Error> {
    let public_key = key_from_wire(public_key)?;
    let endpoint = endpoint
        .map(|value| value.parse::<SocketAddr>().map(unmap_socket_addr))
        .transpose()
        .map_err(|_| Error::InvalidSyntax)?;
    let relay = relay.map(key_from_wire).transpose()?;

    // `PeerAddresses` is a `heapless::Vec` or a heap `Vec` depending on
    // `microtun-core`'s `alloc` feature; `push_peer_address` enforces
    // `MAX_PEER_ADDRESSES` either way.
    let mut peer_addresses = PeerAddresses::new();
    for value in addresses {
        // `parse_ip_net`, not `IpNet::from_str`: §4.4 asks a receiver to accept
        // both abbreviations a sender must not produce — a bare address for a
        // host prefix, and a prefix carrying host bits — and to normalize them
        // here. `IpNet::from_str` rejects the second outright.
        let cidr = parse_ip_net(value).map_err(|_| Error::InvalidSyntax)?;
        push_peer_address(&mut peer_addresses, cidr).map_err(|_| Error::InvalidSyntax)?;
    }

    Ok(ResolvedPeer {
        public_key,
        endpoint,
        relay,
        addresses: peer_addresses,
        // Ingress filtering is an embedding detail, not part of the Peers API
        // protocol. Dynamic records therefore use the core's default policy.
        inbound_policy: Default::default(),
        persistent_keepalive: persistent_keepalive
            .filter(|seconds| *seconds != 0)
            .map(|seconds| Duration::from_secs(u64::from(seconds))),
    })
}

/// Normalize an IPv4-mapped IPv6 address to native IPv4, so a client may query
/// in either form and land in the same v4 prefix.
///
/// Lives here rather than in the server so that both ends normalize a queried
/// address identically.
pub fn unmap_address(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => address,
        },
        IpAddr::V4(_) => address,
    }
}

/// A key as the protocol writes one: WireGuard's base64, 44 characters.
fn key_from_wire(value: &str) -> Result<[u8; 32], Error> {
    decode_key(value).map_err(|_| Error::InvalidSyntax)
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use std::{format, string::String as StdString};

    use super::*;

    /// `[0xAA; 32]`, and `[0xCC; 32]`, as the protocol spells them.
    const KEY_B64: &str = "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=";
    const RELAY_B64: &str = "zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMw=";

    fn params_json(query: &ResolveQuery) -> (&'static str, StdString) {
        let mut text = QueryText::new();
        let call = encode_query(query, &mut text).expect("query renders");
        let mut buffer = [0u8; QUERY_FRAME_LEN];
        let len = serde_json_core::to_slice(&call.params, &mut buffer).expect("params serialize");
        (
            call.method,
            StdString::from_utf8(buffer[..len].to_vec()).expect("utf-8"),
        )
    }

    #[test]
    fn renders_calls() {
        let (method, params) = params_json(&ResolveQuery::ByPublicKey([0xAA; 32]));
        assert_eq!(method, METHOD_BY_KEY);
        assert_eq!(params, format!(r#"{{"public_key":"{KEY_B64}"}}"#));

        let (method, params) =
            params_json(&ResolveQuery::ByDstAddress("2001:db8::1".parse().unwrap()));
        assert_eq!(method, METHOD_BY_ADDRESS);
        assert_eq!(params, r#"{"address":"2001:db8::1"}"#);

        let (_, params) = params_json(&ResolveQuery::ByDstAddress("10.0.0.5".parse().unwrap()));
        assert_eq!(params, r#"{"address":"10.0.0.5"}"#);
    }

    /// The parameters one side serializes are the ones the other side parses.
    #[test]
    fn parameters_round_trip() {
        let (_, params) = params_json(&ResolveQuery::ByPublicKey([0xAA; 32]));
        let (parsed, _) =
            serde_json_core::from_slice::<KeyParams<'_>>(params.as_bytes()).expect("parses");
        assert_eq!(parsed.public_key, KEY_B64);

        let (_, params) = params_json(&ResolveQuery::ByDstAddress("10.0.0.5".parse().unwrap()));
        let (parsed, _) =
            serde_json_core::from_slice::<ByAddressParams<'_>>(params.as_bytes()).expect("parses");
        assert_eq!(parsed.address, "10.0.0.5");
    }

    /// `v1.peer.by_key`, `v1.peer.watch`, `v1.peer.unwatch`, and `v1.peer.changed` all carry the same
    /// single-member object, which is why they share one type.
    #[test]
    fn key_params_round_trip() {
        let params = KeyParams {
            public_key: KEY_B64,
        };
        let mut buffer = [0u8; QUERY_FRAME_LEN];
        let len = serde_json_core::to_slice(&params, &mut buffer).expect("key params serialize");
        assert_eq!(
            core::str::from_utf8(&buffer[..len]).expect("params are UTF-8"),
            format!(r#"{{"public_key":"{KEY_B64}"}}"#)
        );
        let (parsed, _) =
            serde_json_core::from_slice::<KeyParams<'_>>(&buffer[..len]).expect("key params parse");
        assert_eq!(parsed.public_key, KEY_B64);
        assert_eq!(
            decode_key(parsed.public_key).expect("key decodes"),
            [0xAA; 32]
        );
    }

    /// A `v1.peer.changed` notification names a key and carries nothing else, so it
    /// sits far below the frame it shares with lookup responses.
    #[test]
    fn changed_notification_fits_the_frame_budget() {
        let body = format!(
            r#"{{"jsonrpc":"2.0","method":"v1.peer.changed","params":{{"public_key":"{KEY_B64}"}}}}"#
        );
        assert!(
            body.len() < QUERY_FRAME_LEN,
            "changed notification frame is {} bytes",
            body.len()
        );
    }

    fn peer_info(body: &str) -> PeerInfo {
        serde_json_core::from_slice::<PeerInfo>(body.as_bytes())
            .expect("record parses")
            .0
    }

    #[test]
    fn decodes_wire_values() {
        let body = format!(
            r#"{{"public_key":"{KEY_B64}","endpoint":"203.0.113.5:51820","relay":"{RELAY_B64}","addresses":["10.1.2.3/32","10.1.4.0/24"],"persistent_keepalive":25}}"#
        );
        let resolved = decode_record(body.as_bytes()).unwrap();
        assert_eq!(resolved.public_key, [0xAA; 32]);
        assert_eq!(resolved.relay, Some([0xCC; 32]));
        assert_eq!(resolved.addresses.len(), 2);
        assert!(resolved.endpoint.is_some());
        assert_eq!(resolved.persistent_keepalive, Some(Duration::from_secs(25)));
        assert_eq!(
            resolved.inbound_policy,
            microtun_core::InboundPolicy::AllowAll
        );

        // Parsing the peer wire type and decoding it agree with the direct
        // record decoder, field for field.
        assert_eq!(decode_peer(&peer_info(&body)).unwrap(), resolved);
    }

    #[test]
    fn decoded_endpoint_unmaps_ipv4_mapped_ipv6() {
        let body = format!(
            r#"{{"public_key":"{KEY_B64}","endpoint":"[::ffff:203.0.113.5]:51820","addresses":["10.1.2.3/32"]}}"#
        );
        let resolved = decode_record(body.as_bytes()).unwrap();
        assert_eq!(
            resolved.endpoint,
            Some("203.0.113.5:51820".parse().unwrap())
        );
    }

    #[test]
    fn defaults_optional_fields() {
        let body = format!(r#"{{"public_key":"{KEY_B64}","addresses":["10.1.2.3/32"]}}"#);
        let resolved = decode_peer(&peer_info(&body)).unwrap();
        assert!(resolved.endpoint.is_none());
        assert!(resolved.relay.is_none());
        assert!(resolved.persistent_keepalive.is_none());
        assert_eq!(
            resolved.inbound_policy,
            microtun_core::InboundPolicy::AllowAll
        );

        let zero = format!(
            r#"{{"public_key":"{KEY_B64}","addresses":["10.1.2.3/32"],"persistent_keepalive":0}}"#
        );
        assert!(
            decode_record(zero.as_bytes())
                .unwrap()
                .persistent_keepalive
                .is_none()
        );
    }

    #[test]
    fn malformed_wire_values_are_rejected() {
        let invalid_key = br#"{"public_key":"not-a-key","addresses":["10.1.2.3/32"]}"#;
        assert_eq!(
            decode_record(invalid_key).unwrap_err(),
            Error::InvalidSyntax
        );

        // The URL-safe, unpadded spelling was only ever needed for a path
        // segment. There are no paths now, and it is not a key.
        let url_form = format!(
            r#"{{"public_key":"{}","addresses":["10.1.2.3/32"]}}"#,
            &KEY_B64[..43]
        );
        assert_eq!(
            decode_record(url_form.as_bytes()).unwrap_err(),
            Error::InvalidSyntax
        );

        let bad_endpoint = format!(
            r#"{{"public_key":"{KEY_B64}","endpoint":"not-an-endpoint","addresses":["10.1.2.3/32"]}}"#
        );
        assert_eq!(
            decode_record(bad_endpoint.as_bytes()).unwrap_err(),
            Error::InvalidSyntax
        );

        let bad_cidr = format!(r#"{{"public_key":"{KEY_B64}","addresses":["not-a-cidr"]}}"#);
        assert_eq!(
            decode_record(bad_cidr.as_bytes()).unwrap_err(),
            Error::InvalidSyntax
        );
    }

    #[test]
    fn too_many_addresses_are_rejected_by_parser() {
        let body = format!(
            r#"{{"public_key":"{KEY_B64}","addresses":["10.1.2.0/32","10.1.2.1/32","10.1.2.2/32","10.1.2.3/32","10.1.2.4/32"]}}"#
        );
        assert!(parse_record(body.as_bytes()).is_err());
        assert!(serde_json_core::from_slice::<PeerInfo>(body.as_bytes()).is_err());
    }

    /// An over-long field is a parse failure, which the caller reports as a
    /// transient outcome rather than an authoritative miss.
    #[test]
    fn over_long_fields_do_not_parse() {
        let long_endpoint = format!(
            r#"{{"public_key":"{KEY_B64}","endpoint":"{}","addresses":["10.1.2.3/32"]}}"#,
            "9".repeat(MAX_ENDPOINT_TEXT_LEN + 1)
        );
        assert!(serde_json_core::from_slice::<PeerInfo>(long_endpoint.as_bytes()).is_err());
    }

    fn lookup_result(body: &str) -> LookupResult {
        serde_json_core::from_slice::<LookupResult>(body.as_bytes())
            .expect("result parses")
            .0
    }

    #[test]
    fn results_are_classified() {
        let body = format!(r#"{{"public_key":"{KEY_B64}","addresses":["10.1.2.3/32"]}}"#);
        assert!(matches!(
            classify_result(&LookupResult::Found(peer_info(&body))),
            ResolveOutcome::Found(_)
        ));
        assert!(matches!(
            classify_result(&LookupResult::NotFound {}),
            ResolveOutcome::NotFound
        ));

        // Valid JSON, valid field lengths, invalid syntax: transient, so an
        // installed record survives it.
        let bad = format!(r#"{{"public_key":"{KEY_B64}","addresses":["not-a-cidr"]}}"#);
        assert!(matches!(
            classify_result(&LookupResult::Found(peer_info(&bad))),
            ResolveOutcome::Failed
        ));
    }

    /// The enum serializes to the exact externally tagged shapes defined by the
    /// protocol.
    #[test]
    fn lookup_results_round_trip() {
        let body = format!(r#"{{"public_key":"{KEY_B64}","addresses":["10.1.2.3/32"]}}"#);
        let found = LookupResult::Found(peer_info(&body));
        let mut buffer = [0u8; RECORD_FRAME_LEN];
        let len = serde_json_core::to_slice(&found, &mut buffer).expect("found serializes");
        let text = core::str::from_utf8(&buffer[..len]).expect("utf-8");
        assert_eq!(
            text,
            format!(r#"{{"found":{{"public_key":"{KEY_B64}","addresses":["10.1.2.3/32"]}}}}"#)
        );
        assert_eq!(lookup_result(text), found);

        let missing = LookupResult::NotFound {};
        let len = serde_json_core::to_slice(&missing, &mut buffer).expect("miss serializes");
        let text = core::str::from_utf8(&buffer[..len]).expect("utf-8");
        assert_eq!(text, r#"{"not_found":{}}"#);
        assert_eq!(lookup_result(text), missing);
    }

    /// Nothing except the exact `not_found` variant may authoritatively remove
    /// a peer. Every other top-level shape is rejected during deserialization.
    #[test]
    fn only_the_not_found_variant_is_authoritative() {
        for body in [
            r#"{}"#,
            r#"{"missing":{}}"#,
            r#"{"notfound":{}}"#,
            r#"{"NOT_FOUND":{}}"#,
            r#"{"found":null}"#,
            r#"{"not_found":null}"#,
            r#"{"not_found":{"extra":1}}"#,
            r#"{"not_found":{},"extra":1}"#,
            r#"{"found":{"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","addresses":[]},"not_found":{}}"#,
        ] {
            assert!(
                serde_json_core::from_slice::<LookupResult>(body.as_bytes()).is_err(),
                "{body} must be rejected as malformed"
            );
        }

        assert!(matches!(
            classify_result(&lookup_result(r#"{"not_found":{}}"#)),
            ResolveOutcome::NotFound
        ));
    }

    /// A `result` member that is absent or `null` cannot become the explicit
    /// negative variant.
    #[test]
    fn null_result_is_not_a_lookup_result() {
        assert!(serde_json_core::from_slice::<LookupResult>(b"null").is_err());
    }

    #[test]
    fn addresses_are_unmapped() {
        assert_eq!(
            unmap_address("::ffff:10.0.0.1".parse().unwrap()),
            "10.0.0.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            unmap_address("2001:db8::1".parse().unwrap()),
            "2001:db8::1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn builds_wire_values() {
        let record = PeerInfo::from_fields(
            &[0xAA; 32],
            Some("203.0.113.5:51820".parse().unwrap()),
            Some(&[0xCC; 32]),
            ["10.1.2.3/32".parse().unwrap()],
            Some(25),
        )
        .unwrap();
        assert_eq!(record.public_key.as_str(), KEY_B64);
        assert_eq!(record.endpoint.as_deref(), Some("203.0.113.5:51820"));
        assert_eq!(record.relay.as_deref(), Some(RELAY_B64));
        assert_eq!(record.addresses[0].as_str(), "10.1.2.3/32");
        assert_eq!(record.persistent_keepalive, Some(25));
    }

    /// §4.4 defines `Cidr` as a CIDR string, so the prefix length is always
    /// written — including on host prefixes, where `IpNet`'s plain `Display`
    /// would abbreviate `10.1.2.3/32` to `10.1.2.3` and quietly change the
    /// wire format.
    #[test]
    fn host_prefixes_keep_their_length_on_the_wire() {
        let record = PeerInfo::from_fields(
            &[0xAA; 32],
            None,
            None,
            [
                "10.1.2.3/32".parse().unwrap(),
                "2001:db8::1/128".parse().unwrap(),
            ],
            None,
        )
        .unwrap();
        assert_eq!(record.addresses[0].as_str(), "10.1.2.3/32");
        assert_eq!(record.addresses[1].as_str(), "2001:db8::1/128");
    }

    /// §4.4: a receiver accepts the two forms a conforming sender never emits,
    /// and normalizes them rather than rejecting the record.
    #[test]
    fn abbreviated_and_sloppy_prefixes_are_normalized_not_rejected() {
        let body = format!(
            r#"{{"public_key":"{KEY_B64}","addresses":["10.1.2.3/24","10.0.0.9","fd00::9"]}}"#
        );
        let resolved = decode_record(body.as_bytes()).expect("both abbreviations are tolerated");
        assert_eq!(resolved.addresses.len(), 3);
        // Host bits cleared.
        assert_eq!(
            resolved.addresses[0],
            "10.1.2.0/24".parse::<IpNet>().unwrap()
        );
        // Missing length read as a host prefix, per family.
        assert_eq!(
            resolved.addresses[1],
            "10.0.0.9/32".parse::<IpNet>().unwrap()
        );
        assert_eq!(
            resolved.addresses[2],
            "fd00::9/128".parse::<IpNet>().unwrap()
        );
    }

    /// The buffer budget has to hold a worst-case record *inside the tagged
    /// result*, or a legitimate answer would be unreadable in the field.
    #[test]
    fn worst_case_record_fits_the_frame_budget() {
        let v6 = "2001:0db8:0000:0000:0000:ffff:255.255.255.255";
        let record = format!(
            r#"{{"public_key":"{KEY_B64}","endpoint":"[{v6}]:65535","relay":"{RELAY_B64}","addresses":["{v6}/128","{v6}/128","{v6}/128","{v6}/128"],"persistent_keepalive":65535}}"#
        );
        let body =
            format!(r#"{{"jsonrpc":"2.0","id":9007199254740991,"result":{{"found":{record}}}}}"#);
        assert!(
            body.len() < RECORD_FRAME_LEN,
            "worst-case record frame is {} bytes",
            body.len()
        );
    }
}
