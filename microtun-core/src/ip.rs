//! Shared IP parsing and address canonicalization.
//!
//! Both the transport receive path ([`crate::Core::receive_outer`], which
//! must trim the §5.4.6 zero padding before delivery) and the optional ingress
//! firewall ([`crate::firewall`]) have to agree, byte for byte, on how far an
//! inner packet extends and where its addresses live. Two parsers of differing
//! strictness over the same bytes is how filter bypasses happen, so there is
//! exactly one implementation here.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};

/// A validated inner IPv4/IPv6 header.
///
/// Every constructor upholds `header_len <= total_len <= packet.len()`, with
/// `header_len` never below the fixed header size for the family. Callers may
/// therefore slice `packet[..total_len]` unconditionally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IpHeader {
    pub(crate) src: IpAddr,
    pub(crate) dst: IpAddr,
    /// IPv4 `protocol` / IPv6 `next header`.
    pub(crate) protocol: u8,
    pub(crate) header_len: usize,
    pub(crate) total_len: usize,
}

/// Parse and validate the fixed header of an inner IP packet.
///
/// Returns `None` for anything whose own length fields disagree with the
/// bytes actually present — including the case this module exists for: an
/// IPv4 `total_length` *below* the header length, which a bare
/// `min(packet.len())` clamp silently turns into a truncated delivery.
pub(crate) fn parse_header(packet: &[u8]) -> Option<IpHeader> {
    match packet.first()? >> 4 {
        4 => parse_v4_header(packet),
        6 => parse_v6_header(packet),
        _ => None,
    }
}

fn parse_v4_header(packet: &[u8]) -> Option<IpHeader> {
    let first = *packet.first()?;
    if packet.len() < 20 || first >> 4 != 4 {
        return None;
    }
    let header_len = ((first & 0x0f) as usize) * 4;
    if header_len < 20 || packet.len() < header_len {
        return None;
    }
    let total_len = u16::from_be_bytes([*packet.get(2)?, *packet.get(3)?]) as usize;
    if total_len < header_len || total_len > packet.len() {
        return None;
    }
    let mut src = [0u8; 4];
    src.copy_from_slice(packet.get(12..16)?);
    let mut dst = [0u8; 4];
    dst.copy_from_slice(packet.get(16..20)?);
    Some(IpHeader {
        src: IpAddr::V4(Ipv4Addr::from(src)),
        dst: IpAddr::V4(Ipv4Addr::from(dst)),
        protocol: *packet.get(9)?,
        header_len,
        total_len,
    })
}

fn parse_v6_header(packet: &[u8]) -> Option<IpHeader> {
    let first = *packet.first()?;
    if packet.len() < 40 || first >> 4 != 6 {
        return None;
    }
    let payload_len = u16::from_be_bytes([*packet.get(4)?, *packet.get(5)?]) as usize;
    let total_len = 40 + payload_len;
    if total_len > packet.len() {
        return None;
    }
    let mut src = [0u8; 16];
    src.copy_from_slice(packet.get(8..24)?);
    let mut dst = [0u8; 16];
    dst.copy_from_slice(packet.get(24..40)?);
    Some(IpHeader {
        src: IpAddr::V6(Ipv6Addr::from(src)),
        dst: IpAddr::V6(Ipv6Addr::from(dst)),
        protocol: *packet.get(6)?,
        header_len: 40,
        total_len,
    })
}

/// Is this IPv4 packet a fragment (nonzero offset, or MF set)?
///
/// Deliberately *not* folded into [`parse_header`]: dropping fragments is an
/// ingress **filtering** decision — later fragments carry no ports, so
/// admitting only the first would filter inconsistently — and not a
/// well-formedness one. The tunnel data path must keep carrying them.
pub(crate) fn is_v4_fragment(packet: &[u8]) -> bool {
    let Some(first) = packet.first().copied() else {
        return false;
    };
    let Some(flags_hi) = packet.get(6).copied() else {
        return false;
    };
    let Some(flags_lo) = packet.get(7).copied() else {
        return false;
    };
    packet.len() >= 20 && first >> 4 == 4 && u16::from_be_bytes([flags_hi, flags_lo]) & 0x3fff != 0
}

/// Convert an IPv4-mapped IPv6 address to native IPv4.
///
/// Non-mapped IPv6 addresses and native IPv4 addresses are returned unchanged.
pub(crate) fn unmap_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

/// Convert an IPv4-mapped IPv6 socket address to native IPv4.
///
/// A genuine IPv6 socket address is returned byte-for-byte, including its
/// flow-info and scope ID. Only a mapped address loses those IPv6-only fields
/// when it becomes the equivalent [`SocketAddr::V4`].
pub fn unmap_socket_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::V4(SocketAddrV4::new(v4, v6.port())),
            None => SocketAddr::V6(v6),
        },
        SocketAddr::V4(_) => addr,
    }
}

/// Returned by [`parse_ip_cidr`] when the text is not a CIDR prefix.
///
/// Deliberately opaque: the underlying parser distinguishes several failure
/// modes, none of which any caller here acts on differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidIpCidr;

impl core::fmt::Display for InvalidIpCidr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("not a valid IP network prefix")
    }
}

impl core::error::Error for InvalidIpCidr {}

/// Parse a CIDR prefix such as `10.1.2.0/24` or `2001:db8:1::/64`, truncating
/// any host bits rather than rejecting them.
///
/// [`crate::IpCidr`] is canonical by construction, so its own `FromStr` refuses
/// `10.1.2.3/8`. Every parse boundary in this project — the Peers API wire
/// codec, server config files, host config files — reaches for *this* function
/// so lenient input handling lives in exactly one place rather than being
/// reinvented per call site.
///
/// A bare address with no `/` is read as a host prefix — `10.0.0.1` means
/// `10.0.0.1/32`, `2001:db8::1` means `2001:db8::1/128`. Nothing is ambiguous
/// about a bare address, and every prefix this project *writes* still carries
/// its length (see the `{:#}` formatting in
/// `microtun-api`), so the short form is an input convenience that never
/// reaches another implementation.
pub fn parse_ip_cidr(text: &str) -> Result<crate::IpCidr, InvalidIpCidr> {
    cidr::parsers::parse_cidr_ignore_hostbits::<crate::IpCidr, _>(text, |value| {
        value.parse::<IpAddr>()
    })
    .map_err(|_| InvalidIpCidr)
}

/// Parse an address *with* its prefix, keeping host bits: `10.0.0.2/24` stays
/// `10.0.0.2/24` rather than collapsing to the `10.0.0.0/24` network.
///
/// The counterpart to [`parse_ip_cidr`], for the two things that are genuinely
/// interface addresses rather than routes: a TUN device's own address, and the
/// one moment a config parser still holds an operator's literal text and can
/// tell them it is about to be rewritten. Bare addresses are accepted here too,
/// so `10.0.0.2` configures a `/32` interface.
pub fn parse_ip_inet(text: &str) -> Result<crate::IpInet, InvalidIpCidr> {
    cidr::parsers::parse_inet::<crate::IpInet, _>(text, |value| value.parse::<IpAddr>())
        .map_err(|_| InvalidIpCidr)
}

#[cfg(test)]
mod tests {
    use super::*;
    const IPPROTO_UDP: u8 = 17;

    fn v6_addr(last: u16) -> Ipv6Addr {
        Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, last)
    }

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

    #[test]
    fn a_v4_packet_whose_length_fields_disagree_with_reality_is_refused() {
        let good = ipv4(tun(1), tun(2), IPPROTO_UDP, &udp(1, 1, b"x"));

        // The case this module exists for: `total_length` *below* the header
        // length. A bare `min(packet.len())` clamp turns this into a truncated
        // — possibly header-less — delivery to the host stack.
        let mut short_total = good.clone();
        short_total[2..4].copy_from_slice(&19u16.to_be_bytes());
        assert_eq!(parse_header(&short_total), None);

        // `total_length` claiming more than is present.
        let mut long_total = good.clone();
        long_total[2..4].copy_from_slice(&(good.len() as u16 + 1).to_be_bytes());
        assert_eq!(parse_header(&long_total), None);

        // An IHL below the fixed header size, and one beyond the buffer.
        let mut small_ihl = good.clone();
        small_ihl[0] = 0x44;
        assert_eq!(parse_header(&small_ihl), None);
        let mut huge_ihl = good.clone();
        huge_ihl[0] = 0x4f;
        assert_eq!(parse_header(&huge_ihl), None);

        // Too short to hold a header at all, and a version nobody speaks.
        assert_eq!(parse_header(&good[..19]), None);
        assert_eq!(parse_header(&[]), None);
        assert_eq!(parse_header(&[0x00; 40]), None);
        assert_eq!(parse_header(&[0xf0; 40]), None);
    }

    #[test]
    fn fragment_detection_ignores_dont_fragment() {
        let base = ipv4(tun(1), tun(2), IPPROTO_UDP, &udp(1, 1, b"x"));
        assert!(!is_v4_fragment(&base));

        // Don't-Fragment is bit 0x4000 and says nothing about fragmentation
        // having happened; treating it as a fragment would drop most normal
        // traffic under the ingress policy.
        let mut dont_fragment = base.clone();
        dont_fragment[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        assert!(!is_v4_fragment(&dont_fragment));

        // More-Fragments set, or any non-zero offset, is a fragment.
        let mut more = base.clone();
        more[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        assert!(is_v4_fragment(&more));
        let mut offset = base.clone();
        offset[6..8].copy_from_slice(&0x0001u16.to_be_bytes());
        assert!(is_v4_fragment(&offset));
        let mut both = base.clone();
        both[6..8].copy_from_slice(&0x6185u16.to_be_bytes());
        assert!(is_v4_fragment(&both));

        // Fragmentation is an IPv4 concept, and short or non-v4 buffers must
        // not be mistaken for one.
        let v6 = ipv6(v6_addr(1), v6_addr(2), IPPROTO_UDP, &[]);
        assert!(!is_v4_fragment(&v6));
        assert!(!is_v4_fragment(&base[..19]));
        assert!(!is_v4_fragment(&[]));
    }

    #[test]
    fn ipv4_mapped_addresses_are_reduced_to_native_ipv4() {
        // One canonical form matters because the cookie MAC, the rate-limiter
        // key and the roaming endpoint all derive from the source address: two
        // spellings would be two identities.
        let native = Ipv4Addr::new(203, 0, 113, 7);
        let mapped = IpAddr::V6(native.to_ipv6_mapped());
        assert_eq!(unmap_ip(mapped), IpAddr::V4(native));
        assert_eq!(unmap_ip(IpAddr::V4(native)), IpAddr::V4(native));

        assert_eq!(
            unmap_socket_addr(SocketAddr::new(mapped, 51820)),
            SocketAddr::new(IpAddr::V4(native), 51820)
        );
        assert_eq!(
            unmap_socket_addr(SocketAddr::new(IpAddr::V4(native), 51820)),
            SocketAddr::new(IpAddr::V4(native), 51820)
        );

        // A genuine IPv6 address is returned byte for byte, including the
        // IPv6-only flow-info and scope-id fields a naive rebuild would lose.
        let genuine = core::net::SocketAddrV6::new(v6_addr(9), 51820, 7, 3);
        let unmapped = unmap_socket_addr(SocketAddr::V6(genuine));
        assert_eq!(unmapped, SocketAddr::V6(genuine));
        match unmapped {
            SocketAddr::V6(v6) => {
                assert_eq!(v6.flowinfo(), 7);
                assert_eq!(v6.scope_id(), 3);
            }
            SocketAddr::V4(_) => panic!("a genuine IPv6 address must stay IPv6"),
        }

        // IPv4-compatible (`::a.b.c.d`) is a different, deprecated encoding
        // and is deliberately not folded.
        let compatible = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0xcb00, 0x7107));
        assert_eq!(unmap_ip(compatible), compatible);
    }

    #[test]
    fn parse_ip_cidr_accepts_canonical_prefixes() {
        let v4 = parse_ip_cidr("10.1.2.0/24").expect("valid IPv4 prefix");
        assert_eq!(v4.first_address(), IpAddr::V4(Ipv4Addr::new(10, 1, 2, 0)));
        assert_eq!(v4.network_length(), 24);

        let v6 = parse_ip_cidr("2001:db8:1::/64").expect("valid IPv6 prefix");
        assert_eq!(v6.network_length(), 64);
    }

    #[test]
    fn parse_ip_cidr_truncates_host_bits() {
        // Sloppy input is accepted and canonicalized at this parse boundary.
        assert_eq!(
            parse_ip_cidr("10.1.2.3/8").expect("host bits are truncated"),
            parse_ip_cidr("10.0.0.0/8").expect("valid IPv4 prefix")
        );
    }

    /// A bare address is a host prefix.
    #[test]
    fn parse_ip_cidr_reads_a_bare_address_as_a_host_prefix() {
        let v4 = parse_ip_cidr("10.0.0.1").expect("bare IPv4 address");
        assert_eq!(v4, parse_ip_cidr("10.0.0.1/32").expect("valid host prefix"));
        assert_eq!(v4.network_length(), 32);

        let v6 = parse_ip_cidr("2001:db8::1").expect("bare IPv6 address");
        assert_eq!(
            v6,
            parse_ip_cidr("2001:db8::1/128").expect("valid host prefix")
        );
        assert_eq!(v6.network_length(), 128);
    }

    #[test]
    fn parse_ip_inet_keeps_host_bits() {
        let inet = parse_ip_inet("10.0.0.2/24").expect("valid interface address");
        assert_eq!(inet.address(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(inet.network_length(), 24);
        // ...and its network is what `parse_ip_cidr` would have returned.
        assert_eq!(
            inet.network(),
            parse_ip_cidr("10.0.0.2/24").expect("valid prefix")
        );
        assert_eq!(
            parse_ip_inet("10.0.0.2").expect("bare address is a /32 interface"),
            parse_ip_inet("10.0.0.2/32").expect("valid interface address")
        );
    }

    #[test]
    fn parse_ip_cidr_rejects_nonsense() {
        assert_eq!(parse_ip_cidr(""), Err(InvalidIpCidr));
        assert_eq!(parse_ip_cidr("10.0.0.0/33"), Err(InvalidIpCidr));
        assert_eq!(parse_ip_cidr("not-an-address/24"), Err(InvalidIpCidr));
    }
}
