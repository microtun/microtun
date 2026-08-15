//! A tiny stateful ingress firewall for authenticated peers.
//!
//! The policy is intentionally small and predictable for `no_std` /
//! `no_alloc` targets. It implements the useful subset of an nftables rule
//! such as:
//!
//! ```text
//! ct state established,related accept
//! ct state new drop
//! ```
//!
//! Outbound TCP SYNs, UDP datagrams and ICMP echo requests create
//! fixed-capacity flow entries. Return traffic from the same peer is accepted
//! while the entry is alive.
//!
//! ICMP and ICMPv6 *error* messages are the `related` half of the rule: one
//! is accepted when the packet quoted inside it belongs to a live flow. That
//! is what keeps Path MTU Discovery working — without it, ICMPv4
//! fragmentation-needed and ICMPv6 packet-too-big are dropped and large
//! transfers black-hole. An error message neither creates nor refreshes
//! state, so a peer cannot use one to hold a pinhole open.
//!
//! Unsolicited TCP and UDP, inbound echo requests, ICMP redirects, IPv6
//! neighbor/router discovery, IPv4 fragments, IPv6 extension headers and all
//! other IP protocols are rejected for peers configured with
//! [`InboundPolicy::EstablishedOnly`].

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[cfg(test)]
use crate::constants::{
    DEFAULT_FIREWALL_ICMP_TIMEOUT, DEFAULT_FIREWALL_TCP_CLOSING_TIMEOUT,
    DEFAULT_FIREWALL_TCP_TIMEOUT, DEFAULT_FIREWALL_UDP_TIMEOUT,
};
use crate::{
    ip,
    routing::PeerIdx,
    time::{Duration, Instant},
};

/// Compile-time ceiling for TCP/UDP flows remembered by the ingress firewall.
///
/// Allocation-free builds keep an inline table; host builds keep entries on
/// the heap and permit a substantially larger bounded one. An [`Entry`] is
/// roughly 64 bytes, so the embedded table below costs about 4 KiB — an
/// affordable trade on any target that can run this stack at all, and the
/// price of making [`DEFAULT_FIREWALL_FLOWS_PER_PEER`] mean something.
#[cfg(feature = "alloc")]
pub const MAX_FIREWALL_FLOWS: usize = 16_384;
#[cfg(not(feature = "alloc"))]
pub const MAX_FIREWALL_FLOWS: usize = 64;

/// Backend-appropriate active firewall table default.
#[cfg(feature = "alloc")]
pub const DEFAULT_FIREWALL_FLOWS: usize = 4_096;
#[cfg(not(feature = "alloc"))]
pub const DEFAULT_FIREWALL_FLOWS: usize = MAX_FIREWALL_FLOWS;

/// Backend-appropriate maximum number of live tracked flows owned by one peer.
/// This quota prevents one authenticated peer from evicting every other
/// protected peer's return-flow state.
///
/// The quota only isolates peers if it is a small fraction of the table: the
/// host ratio is 1/32, and the embedded ratio is 1/8 against the widened
/// table above. At the previous embedded sizing (8 of 16) two peers could
/// consume the whole table between them, which is the exact outcome the
/// quota exists to prevent.
#[cfg(feature = "alloc")]
pub const DEFAULT_FIREWALL_FLOWS_PER_PEER: usize = 128;
#[cfg(not(feature = "alloc"))]
pub const DEFAULT_FIREWALL_FLOWS_PER_PEER: usize = 8;

const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMPV6: u8 = 58;

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

// ICMPv4 message types (RFC 792).
const ICMP4_ECHO_REPLY: u8 = 0;
const ICMP4_DEST_UNREACHABLE: u8 = 3;
const ICMP4_ECHO_REQUEST: u8 = 8;
const ICMP4_TIME_EXCEEDED: u8 = 11;
const ICMP4_PARAMETER_PROBLEM: u8 = 12;

// ICMPv6 message types (RFC 4443).
const ICMP6_DEST_UNREACHABLE: u8 = 1;
const ICMP6_PACKET_TOO_BIG: u8 = 2;
const ICMP6_TIME_EXCEEDED: u8 = 3;
const ICMP6_PARAMETER_PROBLEM: u8 = 4;
const ICMP6_ECHO_REQUEST: u8 = 128;
const ICMP6_ECHO_REPLY: u8 = 129;

/// An ICMP header is eight bytes; an error message carries the packet that
/// provoked it starting immediately after.
const ICMP_HEADER_LEN: usize = 8;

/// Inbound filtering applied to an authenticated peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InboundPolicy {
    /// Preserve the normal WireGuard behavior: any valid packet whose source
    /// address passes cryptokey routing may be delivered.
    #[default]
    AllowAll,
    /// Permit only return traffic for a flow initiated locally, plus the
    /// ICMP errors related to such a flow. Unsolicited TCP connections,
    /// unsolicited UDP datagrams, inbound pings, fragmented packets, and
    /// other IP protocols are dropped.
    EstablishedOnly,
}

/// The identity of a flow.
///
/// For TCP and UDP the port fields are the real ports. For ICMP and ICMPv6
/// echo traffic they both hold the echo identifier: a request and its reply
/// share that identifier, so storing it in both fields lets
/// [`FlowKey::is_reverse_of`] work unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FlowKey {
    src: IpAddr,
    dst: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
}

impl FlowKey {
    fn is_reverse_of(&self, other: &Self) -> bool {
        self.protocol == other.protocol
            && self.src == other.dst
            && self.dst == other.src
            && self.src_port == other.dst_port
            && self.dst_port == other.src_port
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Tcp {
        flags: u8,
    },
    Udp,
    /// ICMP/ICMPv6 echo request — may open a flow.
    EchoRequest,
    /// ICMP/ICMPv6 echo reply — may only match one.
    EchoReply,
    /// An ICMP/ICMPv6 error message. The accompanying [`FlowKey`] is that of
    /// the packet quoted inside it, in its original outbound direction —
    /// *not* the direction of the error message itself.
    Error,
}

#[derive(Debug, Clone, Copy)]
struct Parsed {
    key: FlowKey,
    kind: Kind,
}

impl Parsed {
    fn opens_new_flow(&self) -> bool {
        match self.kind {
            Kind::Udp | Kind::EchoRequest => true,
            Kind::Tcp { flags } => flags & TCP_SYN != 0 && flags & TCP_ACK == 0,
            Kind::EchoReply | Kind::Error => false,
        }
    }

    fn is_closing(&self) -> bool {
        matches!(self.kind, Kind::Tcp { flags } if flags & (TCP_FIN | TCP_RST) != 0)
    }
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    peer: PeerIdx,
    flow: FlowKey,
    expires: Instant,
    last_seen: Instant,
    /// Sticky: set once a FIN or RST has been seen in either direction. A
    /// closing flow is never promoted back to the full established timeout,
    /// so a peer cannot keep a half-closed connection's pinhole alive by
    /// trickling acknowledgements at it.
    closing: bool,
}

impl Entry {
    /// The lifetime this entry gets from its next refresh, derived from the
    /// entry's own state rather than from the packet doing the refreshing.
    fn effective_timeout(
        &self,
        udp_timeout: Duration,
        icmp_timeout: Duration,
        tcp_timeout: Duration,
        tcp_closing_timeout: Duration,
    ) -> Duration {
        match self.flow.protocol {
            IPPROTO_UDP => udp_timeout,
            IPPROTO_ICMP | IPPROTO_ICMPV6 => icmp_timeout,
            _ if self.closing => tcp_closing_timeout,
            _ => tcp_timeout,
        }
    }
}

/// Fixed-capacity flow tracker used by [`crate::Core`].
///
/// `MAX_FLOWS` is the compile-time storage ceiling and `MAX_PEERS` is
/// the peer-table capacity.
/// The active global and per-peer limits are runtime settings bounded by those
/// ceilings. The per-peer accounting is load-bearing: a peer at its quota may
/// replace only its own entries, so it cannot flush every other peer's return
/// traffic state by opening a burst of flows.
#[derive(Debug)]
pub(crate) struct Firewall<const MAX_FLOWS: usize, const MAX_PEERS: usize> {
    udp_timeout: Duration,
    icmp_timeout: Duration,
    tcp_timeout: Duration,
    tcp_closing_timeout: Duration,
    max_entries: usize,
    max_entries_per_peer: usize,
    #[cfg(not(feature = "alloc"))]
    entries: heapless::Vec<Entry, MAX_FLOWS>,
    #[cfg(feature = "alloc")]
    entries: alloc::vec::Vec<Entry>,
    #[cfg(not(feature = "alloc"))]
    peer_counts: [u16; MAX_PEERS],
    #[cfg(feature = "alloc")]
    peer_counts: alloc::vec::Vec<u16>,
    #[cfg(feature = "alloc")]
    _capacity: core::marker::PhantomData<[(); MAX_FLOWS]>,
}

impl<const MAX_FLOWS: usize, const MAX_PEERS: usize> Firewall<MAX_FLOWS, MAX_PEERS> {
    #[cfg(test)]
    pub(crate) fn new() -> Self {
        Self::with_limits_and_timeouts(
            MAX_FLOWS,
            MAX_FLOWS,
            DEFAULT_FIREWALL_UDP_TIMEOUT,
            DEFAULT_FIREWALL_ICMP_TIMEOUT,
            DEFAULT_FIREWALL_TCP_TIMEOUT,
            DEFAULT_FIREWALL_TCP_CLOSING_TIMEOUT,
        )
    }

    #[cfg(test)]
    pub(crate) fn with_timeouts(
        udp_timeout: Duration,
        icmp_timeout: Duration,
        tcp_timeout: Duration,
        tcp_closing_timeout: Duration,
    ) -> Self {
        Self::with_limits_and_timeouts(
            MAX_FLOWS,
            MAX_FLOWS,
            udp_timeout,
            icmp_timeout,
            tcp_timeout,
            tcp_closing_timeout,
        )
    }

    pub(crate) fn with_limits_and_timeouts(
        max_entries: usize,
        max_entries_per_peer: usize,
        udp_timeout: Duration,
        icmp_timeout: Duration,
        tcp_timeout: Duration,
        tcp_closing_timeout: Duration,
    ) -> Self {
        Self {
            udp_timeout,
            icmp_timeout,
            tcp_timeout,
            tcp_closing_timeout,
            max_entries: max_entries.min(MAX_FLOWS),
            max_entries_per_peer: max_entries_per_peer.min(max_entries).min(MAX_FLOWS),
            #[cfg(not(feature = "alloc"))]
            entries: heapless::Vec::new(),
            #[cfg(feature = "alloc")]
            entries: alloc::vec::Vec::new(),
            #[cfg(not(feature = "alloc"))]
            peer_counts: [0; MAX_PEERS],
            #[cfg(feature = "alloc")]
            peer_counts: alloc::vec![0; MAX_PEERS],
            #[cfg(feature = "alloc")]
            _capacity: core::marker::PhantomData,
        }
    }

    fn peer_position(peer: PeerIdx) -> Option<usize> {
        usize::try_from(peer)
            .ok()
            .filter(|position| *position < MAX_PEERS)
    }

    fn peer_count(&self, peer: PeerIdx) -> usize {
        Self::peer_position(peer)
            .and_then(|position| self.peer_counts.get(position))
            .copied()
            .map(usize::from)
            .unwrap_or(0)
    }

    fn increment_peer(&mut self, peer: PeerIdx) {
        let Some(position) = Self::peer_position(peer) else {
            return;
        };
        if let Some(count) = self.peer_counts.get_mut(position) {
            *count = count.saturating_add(1);
        }
    }

    fn decrement_peer(&mut self, peer: PeerIdx) {
        let Some(position) = Self::peer_position(peer) else {
            return;
        };
        if let Some(count) = self.peer_counts.get_mut(position) {
            *count = count.saturating_sub(1);
        }
    }

    fn rebuild_peer_counts(&mut self) {
        self.peer_counts.fill(0);
        for entry in &self.entries {
            let Some(position) = Self::peer_position(entry.peer) else {
                continue;
            };
            if let Some(count) = self.peer_counts.get_mut(position) {
                *count = count.saturating_add(1);
            }
        }
    }

    fn collect_expired(&mut self, now: Instant) {
        let previous_len = self.entries.len();
        self.entries.retain(|entry| entry.expires > now);
        if self.entries.len() != previous_len {
            self.rebuild_peer_counts();
        }
    }

    fn victim_owned_by(&self, peer: PeerIdx) -> Option<usize> {
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.peer == peer)
            .min_by_key(|(_, entry)| (if entry.closing { 0u8 } else { 1u8 }, entry.last_seen))
            .map(|(position, _)| position)
    }

    /// Select a victim without allowing the requester to grow beyond the
    /// current fair share. A peer already at its hard quota recycles only its
    /// own entries. Otherwise, a full table yields one entry from the most
    /// represented peer only when that owner has more state than the
    /// requester; ties make the requester recycle its own state.
    fn fair_victim(&self, requester: PeerIdx) -> Option<usize> {
        let requester_count = self.peer_count(requester);
        if requester_count >= self.max_entries_per_peer {
            return self.victim_owned_by(requester);
        }

        let mut largest_owner = None;
        let mut largest_count = requester_count;
        for (position, count) in self.peer_counts.iter().copied().enumerate() {
            let count = usize::from(count);
            if count > largest_count {
                largest_count = count;
                largest_owner = PeerIdx::try_from(position).ok();
            }
        }

        largest_owner
            .and_then(|owner| self.victim_owned_by(owner))
            .or_else(|| self.victim_owned_by(requester))
    }

    fn replace(&mut self, position: usize, entry: Entry) {
        let Some(previous) = self.entries.get(position).copied() else {
            return;
        };
        if previous.peer != entry.peer {
            self.decrement_peer(previous.peer);
            self.increment_peer(entry.peer);
        }
        if let Some(slot) = self.entries.get_mut(position) {
            *slot = entry;
        }
    }

    fn push(&mut self, entry: Entry) -> bool {
        if self.entries.len() >= self.max_entries {
            return false;
        }
        #[cfg(feature = "alloc")]
        {
            self.entries.push(entry);
            self.increment_peer(entry.peer);
            true
        }
        #[cfg(not(feature = "alloc"))]
        {
            if self.entries.push(entry).is_ok() {
                self.increment_peer(entry.peer);
                true
            } else {
                false
            }
        }
    }

    /// Record an outbound packet after it has been successfully encapsulated.
    /// Live flows are refreshed; only an initial TCP SYN, a UDP packet or an
    /// ICMP echo request may create a new entry.
    pub(crate) fn observe_outbound(&mut self, peer: PeerIdx, packet: &[u8], now: Instant) {
        if Self::peer_position(peer).is_none() {
            return;
        }
        let Some(parsed) = parse_flow(packet) else {
            return;
        };
        // An error message we emit says nothing about a flow we originated.
        if parsed.kind == Kind::Error {
            return;
        }

        // The expiry test matters: without it a packet that is not allowed to
        // open a flow could still resurrect an entry that had already timed
        // out, silently reopening the pinhole.
        let udp_timeout = self.udp_timeout;
        let icmp_timeout = self.icmp_timeout;
        let tcp_timeout = self.tcp_timeout;
        let tcp_closing_timeout = self.tcp_closing_timeout;

        if let Some(pos) = self
            .entries
            .iter()
            .position(|e| e.peer == peer && e.expires > now && e.flow == parsed.key)
        {
            let Some(entry) = self.entries.get_mut(pos) else {
                return;
            };
            entry.last_seen = now;
            entry.closing |= parsed.is_closing();
            entry.expires = now
                + entry.effective_timeout(
                    udp_timeout,
                    icmp_timeout,
                    tcp_timeout,
                    tcp_closing_timeout,
                );
            return;
        }

        if !parsed.opens_new_flow() {
            return;
        }

        // Expired entries constrain neither admission nor fairness. Reclaim
        // them before applying the per-peer and global limits.
        self.collect_expired(now);

        let mut entry = Entry {
            peer,
            flow: parsed.key,
            expires: now,
            last_seen: now,
            closing: false,
        };
        entry.expires = now
            + entry.effective_timeout(udp_timeout, icmp_timeout, tcp_timeout, tcp_closing_timeout);

        if self.peer_count(peer) < self.max_entries_per_peer && self.push(entry) {
            return;
        }

        if let Some(victim) = self.fair_victim(peer) {
            self.replace(victim, entry);
        }
    }

    /// Decide whether an inbound packet belongs to a live flow, or is an ICMP
    /// error related to one.
    pub(crate) fn allows_inbound(&mut self, peer: PeerIdx, packet: &[u8], now: Instant) -> bool {
        let udp_timeout = self.udp_timeout;
        let icmp_timeout = self.icmp_timeout;
        let tcp_timeout = self.tcp_timeout;
        let tcp_closing_timeout = self.tcp_closing_timeout;
        let Some(parsed) = parse_flow(packet) else {
            return false;
        };

        match parsed.kind {
            // `related`: admitted when the quoted packet is one we sent on a
            // live flow. Deliberately neither creates, refreshes nor removes
            // state — a peer must not be able to hold a pinhole open, or tear
            // one down, with unauthenticated error messages.
            Kind::Error => {
                return self
                    .entries
                    .iter()
                    .any(|e| e.peer == peer && e.expires > now && e.flow == parsed.key);
            }
            // A bare inbound SYN is always a new connection attempt, even if
            // a stale five-tuple happens to remain in the table.
            // Simultaneous-open TCP is intentionally outside this policy.
            Kind::Tcp { flags } if flags & TCP_SYN != 0 && flags & TCP_ACK == 0 => {
                return false;
            }
            // An inbound ping is an unsolicited new flow, exactly like a SYN.
            Kind::EchoRequest => return false,
            _ => {}
        }

        let Some(pos) = self
            .entries
            .iter()
            .position(|e| e.peer == peer && e.expires > now && parsed.key.is_reverse_of(&e.flow))
        else {
            return false;
        };

        let Some(entry) = self.entries.get_mut(pos) else {
            return false;
        };
        entry.last_seen = now;
        entry.closing |= parsed.is_closing();
        entry.expires = now
            + entry.effective_timeout(udp_timeout, icmp_timeout, tcp_timeout, tcp_closing_timeout);
        true
    }

    pub(crate) fn remove_peer(&mut self, peer: PeerIdx) {
        self.entries.retain(|entry| entry.peer != peer);
        if let Some(position) = Self::peer_position(peer) {
            if let Some(count) = self.peer_counts.get_mut(position) {
                *count = 0;
            }
        }
    }
}

/// Parse an inner IP packet down to the flow it belongs to.
///
/// Only a direct TCP/UDP/ICMP next-header is supported; IPv6 extension and
/// fragment headers are dropped under `EstablishedOnly`, and each family
/// admits only its own ICMP.
fn parse_flow(packet: &[u8]) -> Option<Parsed> {
    let header = ip::parse_header(packet)?;
    // Reject all fragments: later fragments do not carry ports, and allowing
    // only the first fragment would create inconsistent filtering. This is a
    // filtering decision, so it lives here rather than in `ip::parse_header`
    // — the plain data path still forwards fragments.
    if ip::is_v4_fragment(packet) {
        return None;
    }
    let (src, dst) = (header.src, header.dst);
    match header.protocol {
        IPPROTO_TCP | IPPROTO_UDP => parse_transport(
            packet,
            header.total_len,
            header.header_len,
            src,
            dst,
            header.protocol,
        ),
        IPPROTO_ICMP if src.is_ipv4() => {
            parse_icmp(packet, header.total_len, header.header_len, src, dst, 4)
        }
        IPPROTO_ICMPV6 if src.is_ipv6() => {
            parse_icmp(packet, header.total_len, header.header_len, src, dst, 6)
        }
        _ => None,
    }
}

fn parse_transport(
    packet: &[u8],
    total_len: usize,
    offset: usize,
    src: IpAddr,
    dst: IpAddr,
    protocol: u8,
) -> Option<Parsed> {
    let minimum = match protocol {
        IPPROTO_TCP => 20,
        IPPROTO_UDP => 8,
        _ => return None,
    };
    if offset + minimum > total_len {
        return None;
    }
    let transport_end = offset + minimum;
    let transport = packet.get(offset..transport_end)?;
    let src_port = u16::from_be_bytes([*transport.first()?, *transport.get(1)?]);
    let dst_port = u16::from_be_bytes([*transport.get(2)?, *transport.get(3)?]);
    let kind = if protocol == IPPROTO_TCP {
        let flags = *transport.get(13)?;
        if !plausible_tcp_flags(flags) {
            return None;
        }
        Kind::Tcp { flags }
    } else {
        Kind::Udp
    };
    Some(Parsed {
        key: FlowKey {
            src,
            dst,
            protocol,
            src_port,
            dst_port,
        },
        kind,
    })
}

/// SYN+FIN, SYN+RST, FIN+RST and null-flag segments are never produced by a
/// conforming stack; they are scan signatures. Refuse to track or admit them.
fn plausible_tcp_flags(f: u8) -> bool {
    f & (TCP_SYN | TCP_FIN) != (TCP_SYN | TCP_FIN)
        && f & (TCP_SYN | TCP_RST) != (TCP_SYN | TCP_RST)
        && f & (TCP_FIN | TCP_RST) != (TCP_FIN | TCP_RST)
        && f & (TCP_SYN | TCP_FIN | TCP_RST | TCP_ACK) != 0
}

/// Parse an ICMPv4 (`version == 4`) or ICMPv6 (`version == 6`) message.
fn parse_icmp(
    packet: &[u8],
    total_len: usize,
    offset: usize,
    src: IpAddr,
    dst: IpAddr,
    version: u8,
) -> Option<Parsed> {
    if offset + ICMP_HEADER_LEN > total_len {
        return None;
    }
    let protocol = if version == 4 {
        IPPROTO_ICMP
    } else {
        IPPROTO_ICMPV6
    };
    let icmp_end = offset + ICMP_HEADER_LEN;
    let icmp = packet.get(offset..icmp_end)?;
    let icmp_type = *icmp.first()?;

    let (echo_request, echo_reply) = if version == 4 {
        (ICMP4_ECHO_REQUEST, ICMP4_ECHO_REPLY)
    } else {
        (ICMP6_ECHO_REQUEST, ICMP6_ECHO_REPLY)
    };
    if icmp_type == echo_request || icmp_type == echo_reply {
        let id = u16::from_be_bytes([*icmp.get(4)?, *icmp.get(5)?]);
        return Some(Parsed {
            key: FlowKey {
                src,
                dst,
                protocol,
                src_port: id,
                dst_port: id,
            },
            kind: if icmp_type == echo_request {
                Kind::EchoRequest
            } else {
                Kind::EchoReply
            },
        });
    }

    // Error messages quote the packet that provoked them.
    //
    // ICMPv4 Redirect (5) and ICMPv6 Redirect (137) are deliberately absent:
    // they ask us to change routing, which a tunnel peer has no business
    // doing. So are ICMPv6 neighbor and router discovery (133-136) — the
    // tunnel is a point-to-point IP link with no L2 addressing, so NDP has no
    // role on it. Source Quench (4) is deprecated by RFC 6633.
    let is_error = if version == 4 {
        matches!(
            icmp_type,
            ICMP4_DEST_UNREACHABLE | ICMP4_TIME_EXCEEDED | ICMP4_PARAMETER_PROBLEM
        )
    } else {
        matches!(
            icmp_type,
            ICMP6_DEST_UNREACHABLE
                | ICMP6_PACKET_TOO_BIG
                | ICMP6_TIME_EXCEEDED
                | ICMP6_PARAMETER_PROBLEM
        )
    };
    if !is_error {
        return None;
    }

    let quoted = packet.get(offset + ICMP_HEADER_LEN..total_len)?;
    let key = parse_quoted(quoted, version)?;
    // The quoted packet must be one *we* sent: its source is the address the
    // error was returned to. Without this check a peer could hand us an error
    // quoting a conversation between two other hosts.
    if key.src != dst {
        return None;
    }
    Some(Parsed {
        key,
        kind: Kind::Error,
    })
}

/// Recover the flow key of the packet quoted inside an ICMP error.
///
/// Unlike the top-level parsers this one must **not** trust the quoted
/// header's length field. The quote is truncated — to eight bytes of
/// transport header for ICMPv4, and to whatever fits in 1280 bytes for
/// ICMPv6 — so `total_len` / `payload_len` describe the original packet, not
/// the bytes actually present. Only the addresses, protocol and ports are
/// needed, and those live in the first four bytes of the transport header.
fn parse_quoted(quoted: &[u8], version: u8) -> Option<FlowKey> {
    if *quoted.first()? >> 4 != version {
        return None;
    }
    let (src, dst, protocol, offset) = if version == 4 {
        let header = quoted.get(..20)?;
        let ihl = ((*header.first()? & 0x0f) as usize) * 4;
        if ihl < 20 {
            return None;
        }
        // A quoted fragment with a nonzero offset carries no ports and could
        // not have matched a tracked flow in the first place.
        if u16::from_be_bytes([*header.get(6)?, *header.get(7)?]) & 0x1fff != 0 {
            return None;
        }
        (
            IpAddr::V4(Ipv4Addr::new(
                *header.get(12)?,
                *header.get(13)?,
                *header.get(14)?,
                *header.get(15)?,
            )),
            IpAddr::V4(Ipv4Addr::new(
                *header.get(16)?,
                *header.get(17)?,
                *header.get(18)?,
                *header.get(19)?,
            )),
            *header.get(9)?,
            ihl,
        )
    } else {
        let header = quoted.get(..40)?;
        let mut s = [0u8; 16];
        s.copy_from_slice(header.get(8..24)?);
        let mut d = [0u8; 16];
        d.copy_from_slice(header.get(24..40)?);
        (
            IpAddr::V6(Ipv6Addr::from(s)),
            IpAddr::V6(Ipv6Addr::from(d)),
            *header.get(6)?,
            40,
        )
    };

    let (src_port, dst_port) = match protocol {
        IPPROTO_TCP | IPPROTO_UDP => {
            let a = quoted.get(offset..offset + 4)?;
            (
                u16::from_be_bytes([*a.first()?, *a.get(1)?]),
                u16::from_be_bytes([*a.get(2)?, *a.get(3)?]),
            )
        }
        IPPROTO_ICMP | IPPROTO_ICMPV6 => {
            // Only a quoted echo *request* has an identifier we track. An
            // error quoting another error is not followed any further.
            let a = quoted.get(offset..offset + 6)?;
            let message_type = *a.first()?;
            let is_echo = (protocol == IPPROTO_ICMP && message_type == ICMP4_ECHO_REQUEST)
                || (protocol == IPPROTO_ICMPV6 && message_type == ICMP6_ECHO_REQUEST);
            if !is_echo {
                return None;
            }
            let id = u16::from_be_bytes([*a.get(4)?, *a.get(5)?]);
            (id, id)
        }
        _ => return None,
    };

    Some(FlowKey {
        src,
        dst,
        protocol,
        src_port,
        dst_port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::Duration;

    /// A protocol this module has no parser for.
    const IPPROTO_GRE: u8 = 47;

    /// A fixed instant well away from zero, so a saturated-to-zero deadline
    /// can never be mistaken for a correct one.
    const T0: Instant = Instant::from_millis(1_000_000);

    /// An inner (tunnel) address.
    fn tun(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(10, 0, 0, last)
    }

    /// A well-formed IPv4 packet whose `total_length` matches its real length.
    fn ipv4(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, payload: &[u8]) -> Vec<u8> {
        let total = 20 + payload.len();
        let mut packet = vec![0u8; total];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&src.octets());
        packet[16..20].copy_from_slice(&dst.octets());
        packet[20..].copy_from_slice(payload);
        packet
    }

    /// A well-formed IPv6 packet with a single, direct next header.
    fn ipv6(src: Ipv6Addr, dst: Ipv6Addr, next_header: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 40 + payload.len()];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        packet[6] = next_header;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&src.octets());
        packet[24..40].copy_from_slice(&dst.octets());
        packet[40..].copy_from_slice(payload);
        packet
    }

    fn udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut segment = vec![0u8; 8 + payload.len()];
        segment[0..2].copy_from_slice(&src_port.to_be_bytes());
        segment[2..4].copy_from_slice(&dst_port.to_be_bytes());
        segment[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        segment[8..].copy_from_slice(payload);
        segment
    }

    /// A 20-byte TCP header with no options.
    fn tcp(src_port: u16, dst_port: u16, flags: u8) -> Vec<u8> {
        let mut segment = vec![0u8; 20];
        segment[0..2].copy_from_slice(&src_port.to_be_bytes());
        segment[2..4].copy_from_slice(&dst_port.to_be_bytes());
        segment[12] = 0x50;
        segment[13] = flags;
        segment
    }

    /// An ICMP echo header. The type numbers differ between ICMPv4 (8 / 0) and
    /// ICMPv6 (128 / 129), so the caller names the one it means.
    fn icmp_echo(message_type: u8, identifier: u16) -> Vec<u8> {
        let mut body = vec![0u8; 8];
        body[0] = message_type;
        body[4..6].copy_from_slice(&identifier.to_be_bytes());
        body
    }

    /// An ICMP error body of `message_type` quoting `provoking`.
    fn icmp_error_body(message_type: u8, provoking: &[u8]) -> Vec<u8> {
        let mut body = vec![0u8; 8];
        body[0] = message_type;
        body.extend_from_slice(provoking);
        body
    }

    const PEER: PeerIdx = 1;
    /// This device's tunnel address.
    const LOCAL: u8 = 2;
    /// The peer's tunnel address.
    const REMOTE: u8 = 1;

    fn at(secs: u64) -> Instant {
        T0 + Duration::from_secs(secs)
    }

    /// A packet this device sends to the peer.
    fn out(protocol: u8, body: &[u8]) -> Vec<u8> {
        ipv4(tun(LOCAL), tun(REMOTE), protocol, body)
    }

    /// A packet the peer sends to this device.
    fn inbound(protocol: u8, body: &[u8]) -> Vec<u8> {
        ipv4(tun(REMOTE), tun(LOCAL), protocol, body)
    }

    fn v6_local() -> core::net::Ipv6Addr {
        core::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)
    }

    fn v6_remote() -> core::net::Ipv6Addr {
        core::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)
    }

    #[test]
    fn a_locally_opened_tcp_connection_admits_its_own_return_traffic() {
        let mut firewall = Firewall::<8, 8>::new();

        // Nothing is admitted before anything has been sent.
        assert!(!firewall.allows_inbound(
            PEER,
            &inbound(IPPROTO_TCP, &tcp(80, 40000, TCP_SYN | TCP_ACK)),
            T0
        ));

        firewall.observe_outbound(PEER, &out(IPPROTO_TCP, &tcp(40000, 80, TCP_SYN)), T0);
        assert!(firewall.allows_inbound(
            PEER,
            &inbound(IPPROTO_TCP, &tcp(80, 40000, TCP_SYN | TCP_ACK)),
            at(1)
        ));
        assert!(firewall.allows_inbound(
            PEER,
            &inbound(IPPROTO_TCP, &tcp(80, 40000, TCP_ACK)),
            at(2)
        ));

        // The five-tuple has to match: a different port is a different flow.
        assert!(!firewall.allows_inbound(
            PEER,
            &inbound(IPPROTO_TCP, &tcp(80, 40001, TCP_ACK)),
            at(2)
        ));
        assert!(!firewall.allows_inbound(
            PEER,
            &inbound(IPPROTO_TCP, &tcp(81, 40000, TCP_ACK)),
            at(2)
        ));
        // ...and so is the same tuple over a different protocol.
        assert!(!firewall.allows_inbound(PEER, &inbound(IPPROTO_UDP, &udp(80, 40000, b"")), at(2)));

        // A bare inbound SYN is always a new connection attempt, even on a
        // five-tuple that happens to be tracked. Simultaneous-open TCP is
        // deliberately outside this policy.
        assert!(!firewall.allows_inbound(
            PEER,
            &inbound(IPPROTO_TCP, &tcp(80, 40000, TCP_SYN)),
            at(3)
        ));

        // Flows are per-peer: another authenticated peer cannot ride this one.
        assert!(!firewall.allows_inbound(
            2,
            &inbound(IPPROTO_TCP, &tcp(80, 40000, TCP_ACK)),
            at(3)
        ));
    }

    #[test]
    fn a_closing_connection_gets_the_short_timeout_and_cannot_be_promoted_back() {
        let mut firewall = Firewall::<8, 8>::new();
        firewall.observe_outbound(PEER, &out(IPPROTO_TCP, &tcp(40000, 80, TCP_SYN)), T0);

        // A FIN in either direction makes the entry closing, and the flag is
        // sticky: a peer must not be able to hold a half-closed connection's
        // pinhole open by trickling acknowledgements at it.
        firewall.observe_outbound(
            PEER,
            &out(IPPROTO_TCP, &tcp(40000, 80, TCP_FIN | TCP_ACK)),
            at(10),
        );
        let ack = inbound(IPPROTO_TCP, &tcp(80, 40000, TCP_ACK));
        assert!(firewall.allows_inbound(PEER, &ack, at(20)));

        // The refresh at t=20 used the closing timeout, so the entry dies at
        // t=20+30 rather than surviving for the full established lifetime.
        assert!(firewall.allows_inbound(PEER, &ack, at(49)));
        assert!(!firewall.allows_inbound(PEER, &ack, at(80)));

        // A reset does the same on the inbound side.
        let mut firewall = Firewall::<8, 8>::new();
        firewall.observe_outbound(PEER, &out(IPPROTO_TCP, &tcp(40001, 80, TCP_SYN)), T0);
        assert!(firewall.allows_inbound(
            PEER,
            &inbound(IPPROTO_TCP, &tcp(80, 40001, TCP_RST | TCP_ACK)),
            at(1)
        ));
        assert!(!firewall.allows_inbound(
            PEER,
            &inbound(IPPROTO_TCP, &tcp(80, 40001, TCP_ACK)),
            at(40)
        ));
    }

    #[test]
    fn udp_and_icmp_flows_use_their_own_shorter_lifetimes() {
        let mut firewall = Firewall::<8, 8>::new();

        // UDP: a datagram opens a pinhole for a minute.
        firewall.observe_outbound(PEER, &out(IPPROTO_UDP, &udp(5353, 53, b"query")), T0);
        let answer = inbound(IPPROTO_UDP, &udp(53, 5353, b"answer"));
        assert!(firewall.allows_inbound(PEER, &answer, at(59)));
        // That reply refreshed it, so it now dies a minute after t=59.
        assert!(firewall.allows_inbound(PEER, &answer, at(118)));
        assert!(!firewall.allows_inbound(PEER, &answer, at(180)));

        // ICMP echo is keyed on the identifier a request and its reply share.
        let mut firewall = Firewall::<8, 8>::new();
        firewall.observe_outbound(PEER, &out(IPPROTO_ICMP, &icmp_echo(8, 0x1234)), T0);
        assert!(firewall.allows_inbound(
            PEER,
            &inbound(IPPROTO_ICMP, &icmp_echo(0, 0x1234)),
            at(1)
        ));
        assert!(
            !firewall.allows_inbound(PEER, &inbound(IPPROTO_ICMP, &icmp_echo(0, 0x9999)), at(1)),
            "a reply to a ping we never sent"
        );
        // An inbound echo *request* is unsolicited, exactly like a bare SYN.
        assert!(!firewall.allows_inbound(
            PEER,
            &inbound(IPPROTO_ICMP, &icmp_echo(8, 0x1234)),
            at(1)
        ));
        // Thirty seconds, not sixty.
        assert!(!firewall.allows_inbound(
            PEER,
            &inbound(IPPROTO_ICMP, &icmp_echo(0, 0x1234)),
            at(40)
        ));
    }

    #[test]
    fn configured_flow_lifetimes_replace_the_defaults() {
        let mut firewall = Firewall::<8, 8>::with_timeouts(
            Duration::from_secs(5),
            Duration::from_secs(7),
            Duration::from_secs(11),
            Duration::from_secs(3),
        );

        firewall.observe_outbound(PEER, &out(IPPROTO_UDP, &udp(5353, 53, b"query")), T0);
        let answer = inbound(IPPROTO_UDP, &udp(53, 5353, b"answer"));
        assert!(firewall.allows_inbound(PEER, &answer, at(4)));
        // The accepted reply refreshed the flow using the configured five
        // seconds, so the entry expires exactly at t=9.
        assert!(!firewall.allows_inbound(PEER, &answer, at(9)));
    }

    #[test]
    fn icmp_errors_are_admitted_for_live_flows_without_becoming_state() {
        // This is what keeps Path MTU Discovery working: without it, ICMPv4
        // fragmentation-needed and ICMPv6 packet-too-big are dropped and large
        // transfers black-hole.
        let mut firewall = Firewall::<8, 8>::new();
        let provoking = out(IPPROTO_UDP, &udp(5353, 53, b"query"));
        firewall.observe_outbound(PEER, &provoking, T0);

        let related = inbound(IPPROTO_ICMP, &icmp_error_body(3, &provoking));
        assert!(firewall.allows_inbound(PEER, &related, at(10)));

        // An error neither creates nor refreshes state, so a peer cannot hold
        // a pinhole open — or tear one down — with unauthenticated errors.
        assert!(firewall.allows_inbound(PEER, &related, at(59)));
        assert!(
            !firewall.allows_inbound(PEER, &related, at(61)),
            "the underlying flow expired on its own schedule"
        );

        // An error quoting a conversation we never had is refused...
        let mut firewall = Firewall::<8, 8>::new();
        firewall.observe_outbound(PEER, &provoking, T0);
        let stranger = out(IPPROTO_UDP, &udp(9999, 9999, b""));
        assert!(!firewall.allows_inbound(
            PEER,
            &inbound(IPPROTO_ICMP, &icmp_error_body(3, &stranger)),
            at(1)
        ));

        // ...and so is one quoting traffic between two other hosts, which the
        // quoted source check is there to catch.
        let elsewhere = ipv4(tun(9), tun(REMOTE), IPPROTO_UDP, &udp(5353, 53, b""));
        assert!(!firewall.allows_inbound(
            PEER,
            &inbound(IPPROTO_ICMP, &icmp_error_body(3, &elsewhere)),
            at(1)
        ));

        // Types that ask us to change routing or resolve neighbours have no
        // business on a point-to-point tunnel and are not "related" at all.
        for message_type in [5u8, 4, 0xff] {
            assert!(
                !firewall.allows_inbound(
                    PEER,
                    &inbound(IPPROTO_ICMP, &icmp_error_body(message_type, &provoking)),
                    at(1)
                ),
                "ICMP type {message_type} must not be treated as related"
            );
        }

        // An error *we* send says nothing about a flow we originated: it is a
        // complaint about something the peer sent us, so it must not open a
        // pinhole for that conversation.
        let mut firewall = Firewall::<8, 8>::new();
        let peer_sent = inbound(IPPROTO_UDP, &udp(53, 5353, b"unsolicited"));
        firewall.observe_outbound(
            PEER,
            &out(IPPROTO_ICMP, &icmp_error_body(3, &peer_sent)),
            T0,
        );
        assert!(!firewall.allows_inbound(PEER, &peer_sent, at(1)));
    }

    #[test]
    fn ipv6_flows_and_packet_too_big_are_handled_the_same_way() {
        let mut firewall = Firewall::<8, 8>::new();
        let provoking = ipv6(
            v6_local(),
            v6_remote(),
            IPPROTO_TCP,
            &tcp(40000, 443, TCP_SYN),
        );
        firewall.observe_outbound(PEER, &provoking, T0);

        assert!(firewall.allows_inbound(
            PEER,
            &ipv6(
                v6_remote(),
                v6_local(),
                IPPROTO_TCP,
                &tcp(443, 40000, TCP_SYN | TCP_ACK)
            ),
            at(1)
        ));

        // ICMPv6 type 2 quoting our SYN: the error PMTUD depends on.
        let too_big = ipv6(
            v6_remote(),
            v6_local(),
            IPPROTO_ICMPV6,
            &icmp_error_body(2, &provoking),
        );
        assert!(firewall.allows_inbound(PEER, &too_big, at(2)));

        // ICMPv6 echo keeps the identifier keying, with its own type numbers.
        let mut firewall = Firewall::<8, 8>::new();
        firewall.observe_outbound(
            PEER,
            &ipv6(v6_local(), v6_remote(), IPPROTO_ICMPV6, &icmp_echo(128, 7)),
            T0,
        );
        assert!(firewall.allows_inbound(
            PEER,
            &ipv6(v6_remote(), v6_local(), IPPROTO_ICMPV6, &icmp_echo(129, 7)),
            at(1)
        ));
        // Neighbour and router discovery have no role on a tunnel with no L2.
        for message_type in [133u8, 134, 135, 136, 137] {
            assert!(!firewall.allows_inbound(
                PEER,
                &ipv6(
                    v6_remote(),
                    v6_local(),
                    IPPROTO_ICMPV6,
                    &icmp_error_body(message_type, &provoking)
                ),
                at(1)
            ));
        }
    }

    #[test]
    fn unparseable_and_implausible_packets_are_never_tracked_or_admitted() {
        let mut firewall = Firewall::<8, 8>::new();

        // Flag combinations no conforming stack emits are scan signatures.
        for flags in [
            TCP_SYN | TCP_FIN,
            TCP_SYN | TCP_RST,
            TCP_FIN | TCP_RST,
            0x00,
        ] {
            firewall.observe_outbound(PEER, &out(IPPROTO_TCP, &tcp(40000, 80, flags)), T0);
            assert!(
                !firewall.allows_inbound(
                    PEER,
                    &inbound(IPPROTO_TCP, &tcp(80, 40000, TCP_ACK)),
                    at(1)
                ),
                "flags {flags:#04x} must not open a flow"
            );
            assert!(!firewall.allows_inbound(
                PEER,
                &inbound(IPPROTO_TCP, &tcp(80, 40000, flags)),
                at(1)
            ));
        }

        // Fragments carry no ports after the first, so admitting only the
        // first would filter inconsistently. All of them are refused.
        firewall.observe_outbound(PEER, &out(IPPROTO_UDP, &udp(5353, 53, b"q")), T0);
        let mut fragment = inbound(IPPROTO_UDP, &udp(53, 5353, b"a"));
        fragment[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        assert!(!firewall.allows_inbound(PEER, &fragment, at(1)));
        let mut later_fragment = inbound(IPPROTO_UDP, &udp(53, 5353, b"a"));
        later_fragment[6..8].copy_from_slice(&0x0001u16.to_be_bytes());
        assert!(!firewall.allows_inbound(PEER, &later_fragment, at(1)));

        // Protocols with no parser here are refused rather than passed.
        firewall.observe_outbound(PEER, &out(IPPROTO_GRE, &[0u8; 8]), T0);
        assert!(!firewall.allows_inbound(PEER, &inbound(IPPROTO_GRE, &[0u8; 8]), at(1)));

        // Truncated transport headers, and packets that are not IP at all.
        assert!(!firewall.allows_inbound(PEER, &inbound(IPPROTO_TCP, &[0u8; 19]), at(1)));
        assert!(!firewall.allows_inbound(PEER, &inbound(IPPROTO_UDP, &[0u8; 7]), at(1)));
        assert!(!firewall.allows_inbound(PEER, &inbound(IPPROTO_ICMP, &[0u8; 7]), at(1)));
        assert!(!firewall.allows_inbound(PEER, &[], at(1)));
        assert!(!firewall.allows_inbound(PEER, &[0xf0; 40], at(1)));
    }

    #[test]
    fn an_expired_entry_cannot_be_resurrected_by_a_packet_that_may_not_open_a_flow() {
        // Without the expiry check on the refresh path, a bare outbound ACK
        // would silently reopen a pinhole that had already timed out.
        let mut firewall = Firewall::<8, 8>::new();
        firewall.observe_outbound(PEER, &out(IPPROTO_TCP, &tcp(40000, 80, TCP_SYN)), T0);

        let long_after = at(31 * 60);
        firewall.observe_outbound(
            PEER,
            &out(IPPROTO_TCP, &tcp(40000, 80, TCP_ACK)),
            long_after,
        );
        assert!(!firewall.allows_inbound(
            PEER,
            &inbound(IPPROTO_TCP, &tcp(80, 40000, TCP_ACK)),
            long_after
        ));

        // A packet that *may* open one starts a fresh flow, as it should.
        firewall.observe_outbound(
            PEER,
            &out(IPPROTO_TCP, &tcp(40000, 80, TCP_SYN)),
            long_after,
        );
        assert!(firewall.allows_inbound(
            PEER,
            &inbound(IPPROTO_TCP, &tcp(80, 40000, TCP_ACK)),
            long_after
        ));
    }

    #[test]
    fn a_peer_at_its_quota_recycles_only_its_own_flows() {
        let flow = |port: u16| out(IPPROTO_UDP, &udp(port, 53, b"q"));
        let peer_a = 0;
        let peer_b = 1;
        let mut firewall = Firewall::<6, 4>::with_limits_and_timeouts(
            6,
            2,
            DEFAULT_FIREWALL_UDP_TIMEOUT,
            DEFAULT_FIREWALL_ICMP_TIMEOUT,
            DEFAULT_FIREWALL_TCP_TIMEOUT,
            DEFAULT_FIREWALL_TCP_CLOSING_TIMEOUT,
        );

        firewall.observe_outbound(peer_a, &flow(1000), T0);
        firewall.observe_outbound(peer_a, &flow(1001), at(1));
        firewall.observe_outbound(peer_b, &flow(2000), at(2));
        firewall.observe_outbound(peer_b, &flow(2001), at(3));
        firewall.observe_outbound(peer_a, &flow(1002), at(4));

        assert_eq!(firewall.peer_count(peer_a), 2);
        assert_eq!(firewall.peer_count(peer_b), 2);
        assert!(
            firewall.allows_inbound(peer_b, &inbound(IPPROTO_UDP, &udp(53, 2000, b"r")), at(5),),
            "peer A reaching its quota must not evict peer B's state"
        );
        assert!(
            firewall.allows_inbound(peer_a, &inbound(IPPROTO_UDP, &udp(53, 1002, b"r")), at(5),),
            "the new flow replaces one of the requester's own entries"
        );
    }

    #[test]
    fn a_full_table_yields_state_from_the_most_represented_peer() {
        let flow = |port: u16| out(IPPROTO_UDP, &udp(port, 53, b"q"));
        let peer_a = 0;
        let peer_b = 1;
        let peer_c = 2;
        let mut firewall = Firewall::<4, 4>::with_limits_and_timeouts(
            4,
            4,
            DEFAULT_FIREWALL_UDP_TIMEOUT,
            DEFAULT_FIREWALL_ICMP_TIMEOUT,
            DEFAULT_FIREWALL_TCP_TIMEOUT,
            DEFAULT_FIREWALL_TCP_CLOSING_TIMEOUT,
        );

        firewall.observe_outbound(peer_a, &flow(1000), T0);
        firewall.observe_outbound(peer_a, &flow(1001), at(1));
        firewall.observe_outbound(peer_a, &flow(1002), at(2));
        firewall.observe_outbound(peer_b, &flow(2000), at(3));
        firewall.observe_outbound(peer_c, &flow(3000), at(4));

        assert_eq!(firewall.peer_count(peer_a), 2);
        assert_eq!(firewall.peer_count(peer_b), 1);
        assert_eq!(firewall.peer_count(peer_c), 1);
    }

    #[test]
    fn a_full_table_prefers_expired_then_closing_then_least_recently_seen() {
        // The table is bounded because a peer that can open flows must not be
        // able to exhaust memory; the ordering keeps a burst of short-lived
        // flows from evicting a live connection.
        let flow = |port: u16| out(IPPROTO_UDP, &udp(port, 53, b"q"));
        let reply = |port: u16| inbound(IPPROTO_UDP, &udp(53, port, b"a"));

        // Least recently seen loses when nothing is expired or closing.
        let mut firewall = Firewall::<2, 2>::new();
        firewall.observe_outbound(PEER, &flow(1), T0);
        firewall.observe_outbound(PEER, &flow(2), at(1));
        firewall.observe_outbound(PEER, &flow(3), at(2));
        assert!(
            !firewall.allows_inbound(PEER, &reply(1), at(3)),
            "the stalest flow went"
        );
        assert!(firewall.allows_inbound(PEER, &reply(2), at(3)));
        assert!(firewall.allows_inbound(PEER, &reply(3), at(3)));

        // An expired entry is preferred over a live but older one.
        let mut firewall = Firewall::<2, 2>::new();
        firewall.observe_outbound(PEER, &flow(1), T0);
        firewall.observe_outbound(PEER, &flow(2), at(30));
        firewall.observe_outbound(PEER, &flow(3), at(61));
        assert!(
            firewall.allows_inbound(PEER, &reply(2), at(61)),
            "the live flow survived"
        );
        assert!(firewall.allows_inbound(PEER, &reply(3), at(61)));

        // A closing TCP flow is given up before a live one, even if the live
        // one has been idle longer.
        let mut firewall = Firewall::<2, 2>::new();
        firewall.observe_outbound(PEER, &out(IPPROTO_TCP, &tcp(1, 80, TCP_SYN)), T0);
        firewall.observe_outbound(PEER, &out(IPPROTO_TCP, &tcp(2, 80, TCP_SYN)), at(1));
        firewall.observe_outbound(
            PEER,
            &out(IPPROTO_TCP, &tcp(2, 80, TCP_FIN | TCP_ACK)),
            at(2),
        );
        firewall.observe_outbound(PEER, &out(IPPROTO_TCP, &tcp(3, 80, TCP_SYN)), at(3));
        assert!(
            firewall.allows_inbound(PEER, &inbound(IPPROTO_TCP, &tcp(80, 1, TCP_ACK)), at(4)),
            "the older but healthy connection survived"
        );
        assert!(!firewall.allows_inbound(PEER, &inbound(IPPROTO_TCP, &tcp(80, 2, TCP_ACK)), at(4)));
        assert!(firewall.allows_inbound(PEER, &inbound(IPPROTO_TCP, &tcp(80, 3, TCP_ACK)), at(4)));
    }
}
