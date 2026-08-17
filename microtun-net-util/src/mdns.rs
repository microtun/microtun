//! mDNS/DNS-SD support for provisioning mode.
//!
//! The DNS wire format is shared by the host (`std`) and Embassy integrations.
//! There are deliberately no separate discovery/responder submodules: only the
//! UDP socket/runtime glue is feature-gated. The public API is always named
//! [`run`] / [`discover`]; `std` selects the host signatures and otherwise
//! `embassy-net` selects the async Embassy signatures.

use heapless::{String as HString, Vec as HVec};
use microtun_provisioning::{
    DEVICE_HOSTNAME_PREFIX, DeviceIdentity, PROVISION_MDNS_IPV4, PROVISION_MDNS_PORT,
    PROVISION_MDNS_SERVICE, PROVISION_PORT, device_hostname,
};

const DNS_PACKET_BUFFER: usize = 768;
const DNS_HEADER_LEN: usize = 12;
const DNS_CLASS_IN: u16 = 1;
const DNS_CLASS_QU: u16 = 0x8000;
const DNS_CLASS_CACHE_FLUSH: u16 = 0x8000;
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_PTR: u16 = 12;
const DNS_TYPE_TXT: u16 = 16;
const DNS_TYPE_SRV: u16 = 33;
const DNS_TYPE_ANY: u16 = 255;
const DNS_RESPONSE_AUTHORITATIVE: u16 = 0x8400;
const DNS_TTL_SECONDS: u32 = 120;
const DNS_SD_ENUMERATION: &str = "_services._dns-sd._udp.local";
const MAX_DNS_NAME_LEN: usize = 192;

/// Maximum device ID carried by the provisioning mDNS TXT record.
pub const MAX_MDNS_DEVICE_ID_LEN: usize = microtun_provisioning::DEVICE_ID_LEN;
/// Maximum model string retained from a provisioning mDNS TXT record.
pub const MAX_MDNS_MODEL_LEN: usize = 192;

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedDevice {
    device_id: HString<MAX_MDNS_DEVICE_ID_LEN>,
    model: Option<HString<MAX_MDNS_MODEL_LEN>>,
    address: [u8; 4],
    port: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MatchingQuery {
    id: u16,
    prefer_unicast: bool,
    enumeration: bool,
}

fn build_discovery_query(packet: &mut [u8]) -> Option<usize> {
    packet.fill(0);
    write_u16(packet, 4, 1)?;

    let mut offset = DNS_HEADER_LEN;
    offset = write_name(packet, offset, PROVISION_MDNS_SERVICE)?;
    offset = write_u16_at(packet, offset, DNS_TYPE_PTR)?;
    offset = write_u16_at(packet, offset, DNS_CLASS_IN | DNS_CLASS_QU)?;
    Some(offset)
}

fn matching_query(
    packet: &[u8],
    service: &str,
    instance: &str,
    hostname: &str,
) -> Option<MatchingQuery> {
    if packet.len() < DNS_HEADER_LEN || read_u16(packet, 2)? & 0x8000 != 0 {
        return None;
    }

    let qdcount = read_u16(packet, 4)? as usize;
    if qdcount == 0 {
        return None;
    }

    let mut offset = DNS_HEADER_LEN;
    let mut matched = false;
    let mut enumeration = false;
    let mut prefer_unicast = false;
    let mut name: HString<MAX_DNS_NAME_LEN> = HString::new();

    for _ in 0..qdcount {
        name.clear();
        offset = read_name(packet, offset, &mut name)?;
        let qtype = read_u16(packet, offset)?;
        let qclass = read_u16(packet, offset + 2)?;
        offset += 4;

        if qclass & 0x7fff != DNS_CLASS_IN {
            continue;
        }

        let type_matches = |expected| qtype == expected || qtype == DNS_TYPE_ANY;
        if eq_dns_name(name.as_str(), DNS_SD_ENUMERATION) && type_matches(DNS_TYPE_PTR) {
            matched = true;
            enumeration = true;
            prefer_unicast |= qclass & DNS_CLASS_QU != 0;
        } else if (eq_dns_name(name.as_str(), service) && type_matches(DNS_TYPE_PTR))
            || (eq_dns_name(name.as_str(), instance)
                && (type_matches(DNS_TYPE_SRV) || type_matches(DNS_TYPE_TXT)))
            || (eq_dns_name(name.as_str(), hostname) && type_matches(DNS_TYPE_A))
        {
            matched = true;
            prefer_unicast |= qclass & DNS_CLASS_QU != 0;
        }
    }

    matched.then_some(MatchingQuery {
        id: read_u16(packet, 0)?,
        prefer_unicast,
        enumeration,
    })
}

fn parse_discovery_response(packet: &[u8]) -> Option<ParsedDevice> {
    if packet.len() < DNS_HEADER_LEN || read_u16(packet, 2)? & 0x8000 == 0 {
        return None;
    }

    let qdcount = read_u16(packet, 4)? as usize;
    let record_count = read_u16(packet, 6)? as usize
        + read_u16(packet, 8)? as usize
        + read_u16(packet, 10)? as usize;
    let mut offset = DNS_HEADER_LEN;
    let mut name: HString<MAX_DNS_NAME_LEN> = HString::new();

    for _ in 0..qdcount {
        name.clear();
        offset = read_name(packet, offset, &mut name)?;
        offset = offset.checked_add(4)?;
        if offset > packet.len() {
            return None;
        }
    }

    let mut service_instance: Option<HString<MAX_DNS_NAME_LEN>> = None;
    let mut srv_owner: Option<HString<MAX_DNS_NAME_LEN>> = None;
    let mut srv_target: Option<HString<MAX_DNS_NAME_LEN>> = None;
    let mut srv_port = None;
    let mut txt_owner: Option<HString<MAX_DNS_NAME_LEN>> = None;
    let mut device_id: Option<HString<MAX_MDNS_DEVICE_ID_LEN>> = None;
    let mut model: Option<HString<MAX_MDNS_MODEL_LEN>> = None;
    let mut addresses: HVec<(HString<MAX_DNS_NAME_LEN>, [u8; 4]), 8> = HVec::new();

    for _ in 0..record_count {
        name.clear();
        let next = read_name(packet, offset, &mut name)?;
        let record_type = read_u16(packet, next)?;
        let rdlength = read_u16(packet, next + 8)? as usize;
        let rdata = next.checked_add(10)?;
        let end = rdata.checked_add(rdlength)?;
        if end > packet.len() {
            return None;
        }

        match record_type {
            DNS_TYPE_PTR if eq_dns_name(name.as_str(), PROVISION_MDNS_SERVICE) => {
                let mut target: HString<MAX_DNS_NAME_LEN> = HString::new();
                read_name(packet, rdata, &mut target)?;
                service_instance = Some(target);
            }
            DNS_TYPE_SRV if rdlength >= 6 => {
                srv_owner = Some(name.clone());
                srv_port = Some(read_u16(packet, rdata + 4)?);
                let mut target: HString<MAX_DNS_NAME_LEN> = HString::new();
                read_name(packet, rdata + 6, &mut target)?;
                srv_target = Some(target);
            }
            DNS_TYPE_TXT => {
                txt_owner = Some(name.clone());
                let mut at = rdata;
                while at < end {
                    let len = *packet.get(at)? as usize;
                    at += 1;
                    let text_end = at.checked_add(len)?;
                    if text_end > end {
                        return None;
                    }
                    let text = core::str::from_utf8(packet.get(at..text_end)?).ok()?;
                    if let Some(value) = text.strip_prefix("device_id=") {
                        let mut parsed = HString::new();
                        parsed.push_str(value).ok()?;
                        device_id = Some(parsed);
                    } else if let Some(value) = text.strip_prefix("model=") {
                        let mut parsed = HString::new();
                        parsed.push_str(value).ok()?;
                        model = Some(parsed);
                    }
                    at = text_end;
                }
            }
            DNS_TYPE_A if rdlength == 4 => {
                let _ = addresses.push((
                    name.clone(),
                    [
                        packet[rdata],
                        packet[rdata + 1],
                        packet[rdata + 2],
                        packet[rdata + 3],
                    ],
                ));
            }
            _ => {}
        }
        offset = end;
    }

    let instance = service_instance?;
    if srv_owner
        .as_ref()
        .is_some_and(|owner| !eq_dns_name(owner.as_str(), instance.as_str()))
        || txt_owner
            .as_ref()
            .is_some_and(|owner| !eq_dns_name(owner.as_str(), instance.as_str()))
    {
        return None;
    }

    let target = srv_target?;
    let address = addresses.into_iter().find_map(|(owner, address)| {
        eq_dns_name(owner.as_str(), target.as_str()).then_some(address)
    })?;
    let device_id = device_id.or_else(|| device_id_from_instance(instance.as_str()))?;

    Some(ParsedDevice {
        device_id,
        model,
        address,
        port: srv_port?,
    })
}

fn device_id_from_instance(instance: &str) -> Option<HString<MAX_MDNS_DEVICE_ID_LEN>> {
    let label = instance.split('.').next()?;
    let value = label.strip_prefix(DEVICE_HOSTNAME_PREFIX)?;
    let mut out = HString::new();
    out.push_str(value).ok()?;
    Some(out)
}

fn build_enumeration_response(packet: &mut [u8], id: u16, service: &str) -> Option<usize> {
    packet.fill(0);
    write_u16(packet, 0, id)?;
    write_u16(packet, 2, DNS_RESPONSE_AUTHORITATIVE)?;
    write_u16(packet, 6, 1)?;
    write_ptr_record(packet, DNS_HEADER_LEN, DNS_SD_ENUMERATION, service, false)
}

#[allow(clippy::too_many_arguments)]
fn build_service_response(
    packet: &mut [u8],
    id: u16,
    service: &str,
    instance: &str,
    hostname: &str,
    device_id: &str,
    model: &str,
    ip: [u8; 4],
) -> Option<usize> {
    packet.fill(0);
    write_u16(packet, 0, id)?;
    write_u16(packet, 2, DNS_RESPONSE_AUTHORITATIVE)?;
    write_u16(packet, 6, 4)?;

    let mut offset = DNS_HEADER_LEN;
    offset = write_ptr_record(packet, offset, service, instance, false)?;
    offset = write_srv_record(packet, offset, instance, hostname, PROVISION_PORT)?;
    offset = write_txt_record(packet, offset, instance, device_id, model)?;
    write_a_record(packet, offset, hostname, ip)
}

fn service_names(
    identity: DeviceIdentity,
) -> Option<(HString<72>, HString<128>, HString<MAX_MDNS_DEVICE_ID_LEN>)> {
    let identity_id = identity.device_id();
    let mut device_id: HString<MAX_MDNS_DEVICE_ID_LEN> = HString::new();
    device_id.push_str(identity_id.as_str()).ok()?;

    let host_label = device_hostname(&identity);

    let mut hostname: HString<72> = HString::new();
    hostname.push_str(host_label.as_str()).ok()?;
    hostname.push_str(".local").ok()?;

    let mut instance: HString<128> = HString::new();
    instance.push_str(host_label.as_str()).ok()?;
    instance.push('.').ok()?;
    instance.push_str(PROVISION_MDNS_SERVICE).ok()?;

    Some((hostname, instance, device_id))
}

fn write_ptr_record(
    packet: &mut [u8],
    mut offset: usize,
    owner: &str,
    target: &str,
    cache_flush: bool,
) -> Option<usize> {
    offset = write_name(packet, offset, owner)?;
    offset = write_u16_at(packet, offset, DNS_TYPE_PTR)?;
    let class = DNS_CLASS_IN
        | if cache_flush {
            DNS_CLASS_CACHE_FLUSH
        } else {
            0
        };
    offset = write_u16_at(packet, offset, class)?;
    offset = write_u32_at(packet, offset, DNS_TTL_SECONDS)?;
    let rdlength_at = offset;
    offset = write_u16_at(packet, offset, 0)?;
    let rdata_start = offset;
    offset = write_name(packet, offset, target)?;
    write_u16(
        packet,
        rdlength_at,
        u16::try_from(offset - rdata_start).ok()?,
    )?;
    Some(offset)
}

fn write_srv_record(
    packet: &mut [u8],
    mut offset: usize,
    owner: &str,
    target: &str,
    port: u16,
) -> Option<usize> {
    offset = write_name(packet, offset, owner)?;
    offset = write_u16_at(packet, offset, DNS_TYPE_SRV)?;
    offset = write_u16_at(packet, offset, DNS_CLASS_IN | DNS_CLASS_CACHE_FLUSH)?;
    offset = write_u32_at(packet, offset, DNS_TTL_SECONDS)?;
    let rdlength_at = offset;
    offset = write_u16_at(packet, offset, 0)?;
    let rdata_start = offset;
    offset = write_u16_at(packet, offset, 0)?;
    offset = write_u16_at(packet, offset, 0)?;
    offset = write_u16_at(packet, offset, port)?;
    offset = write_name(packet, offset, target)?;
    write_u16(
        packet,
        rdlength_at,
        u16::try_from(offset - rdata_start).ok()?,
    )?;
    Some(offset)
}

fn write_txt_record(
    packet: &mut [u8],
    mut offset: usize,
    owner: &str,
    device_id: &str,
    model: &str,
) -> Option<usize> {
    if device_id.len() > MAX_MDNS_DEVICE_ID_LEN || model.len() > MAX_MDNS_MODEL_LEN {
        return None;
    }

    offset = write_name(packet, offset, owner)?;
    offset = write_u16_at(packet, offset, DNS_TYPE_TXT)?;
    offset = write_u16_at(packet, offset, DNS_CLASS_IN | DNS_CLASS_CACHE_FLUSH)?;
    offset = write_u32_at(packet, offset, DNS_TTL_SECONDS)?;
    let rdlength_at = offset;
    offset = write_u16_at(packet, offset, 0)?;
    let rdata_start = offset;

    let mut device_txt: HString<64> = HString::new();
    device_txt.push_str("device_id=").ok()?;
    device_txt.push_str(device_id).ok()?;
    offset = write_txt_string(packet, offset, device_txt.as_str())?;

    let mut model_txt: HString<200> = HString::new();
    model_txt.push_str("model=").ok()?;
    model_txt.push_str(model).ok()?;
    offset = write_txt_string(packet, offset, model_txt.as_str())?;

    write_u16(
        packet,
        rdlength_at,
        u16::try_from(offset - rdata_start).ok()?,
    )?;
    Some(offset)
}

fn write_a_record(packet: &mut [u8], mut offset: usize, owner: &str, ip: [u8; 4]) -> Option<usize> {
    offset = write_name(packet, offset, owner)?;
    offset = write_u16_at(packet, offset, DNS_TYPE_A)?;
    offset = write_u16_at(packet, offset, DNS_CLASS_IN | DNS_CLASS_CACHE_FLUSH)?;
    offset = write_u32_at(packet, offset, DNS_TTL_SECONDS)?;
    offset = write_u16_at(packet, offset, 4)?;
    write_bytes(packet, offset, &ip)
}

fn write_txt_string(packet: &mut [u8], offset: usize, value: &str) -> Option<usize> {
    let len = u8::try_from(value.len()).ok()?;
    let next = offset.checked_add(1 + value.len())?;
    if next > packet.len() {
        return None;
    }
    packet[offset] = len;
    packet[offset + 1..next].copy_from_slice(value.as_bytes());
    Some(next)
}

fn write_name(packet: &mut [u8], mut offset: usize, name: &str) -> Option<usize> {
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        let len = u8::try_from(label.len()).ok()?;
        let next = offset.checked_add(1 + label.len())?;
        if next > packet.len() {
            return None;
        }
        packet[offset] = len;
        packet[offset + 1..next].copy_from_slice(label.as_bytes());
        offset = next;
    }
    if offset >= packet.len() {
        return None;
    }
    packet[offset] = 0;
    Some(offset + 1)
}

fn read_name<const N: usize>(packet: &[u8], start: usize, out: &mut HString<N>) -> Option<usize> {
    let mut offset = start;
    let mut next = None;
    let mut jumps = 0usize;

    loop {
        let len = *packet.get(offset)?;
        if len & 0xc0 == 0xc0 {
            let second = *packet.get(offset + 1)?;
            let pointer = (((len & 0x3f) as usize) << 8) | second as usize;
            next.get_or_insert(offset + 2);
            offset = pointer;
            jumps += 1;
            if jumps > 16 {
                return None;
            }
            continue;
        }
        if len & 0xc0 != 0 {
            return None;
        }
        offset += 1;
        if len == 0 {
            return Some(next.unwrap_or(offset));
        }

        let end = offset.checked_add(len as usize)?;
        let label = packet.get(offset..end)?;
        if !out.is_empty() {
            out.push('.').ok()?;
        }
        for byte in label {
            if !byte.is_ascii() {
                return None;
            }
            out.push((*byte as char).to_ascii_lowercase()).ok()?;
        }
        offset = end;
    }
}

fn eq_dns_name(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}

fn read_u16(packet: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *packet.get(offset)?,
        *packet.get(offset + 1)?,
    ]))
}

fn write_u16(packet: &mut [u8], offset: usize, value: u16) -> Option<()> {
    packet
        .get_mut(offset..offset + 2)?
        .copy_from_slice(&value.to_be_bytes());
    Some(())
}

fn write_u16_at(packet: &mut [u8], offset: usize, value: u16) -> Option<usize> {
    write_u16(packet, offset, value)?;
    Some(offset + 2)
}

fn write_u32_at(packet: &mut [u8], offset: usize, value: u32) -> Option<usize> {
    packet
        .get_mut(offset..offset + 4)?
        .copy_from_slice(&value.to_be_bytes());
    Some(offset + 4)
}

fn write_bytes(packet: &mut [u8], offset: usize, value: &[u8]) -> Option<usize> {
    let end = offset.checked_add(value.len())?;
    packet.get_mut(offset..end)?.copy_from_slice(value);
    Some(end)
}

// ---- std socket integration -------------------------------------------------

#[cfg(feature = "std")]
use std::{
    borrow::ToOwned,
    collections::HashSet,
    format,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
    string::String,
    thread,
    time::{Duration, Instant},
    vec::Vec,
};

/// A provisioning-mode device discovered by the host-side `std` implementation.
#[cfg(feature = "std")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredDevice {
    pub device_id: String,
    pub model: Option<String>,
    pub address: Ipv4Addr,
    pub port: u16,
}

/// Discover provisioning-mode devices using standard-library UDP sockets.
///
/// When `std` is enabled, this is the host-side form of the unified `discover` API.
#[cfg(feature = "std")]
pub fn discover(timeout: Duration) -> Result<Vec<DiscoveredDevice>, String> {
    const QUERY_RETRY: Duration = Duration::from_millis(350);

    let sockets = std_discovery_sockets()?;
    let destination = SocketAddrV4::new(Ipv4Addr::from(PROVISION_MDNS_IPV4), PROVISION_MDNS_PORT);
    let mut query = [0u8; DNS_PACKET_BUFFER];
    let query_len =
        build_discovery_query(&mut query).ok_or_else(|| "build mDNS discovery query".to_owned())?;
    let deadline = Instant::now() + timeout;
    let mut next_query = Instant::now();
    let mut devices = Vec::new();
    let mut seen = HashSet::new();
    let mut packet = [0u8; 1500];

    while Instant::now() < deadline {
        if Instant::now() >= next_query {
            for socket in &sockets {
                let _ = socket.send_to(&query[..query_len], destination);
            }
            next_query = Instant::now() + QUERY_RETRY;
        }

        let mut received_any = false;
        for socket in &sockets {
            loop {
                match socket.recv_from(&mut packet) {
                    Ok((len, _)) => {
                        received_any = true;
                        if let Some(parsed) = parse_discovery_response(&packet[..len]) {
                            let device = DiscoveredDevice {
                                device_id: parsed.device_id.as_str().to_owned(),
                                model: parsed.model.map(|value| value.as_str().to_owned()),
                                address: Ipv4Addr::from(parsed.address),
                                port: parsed.port,
                            };
                            let key = (device.device_id.clone(), device.address, device.port);
                            if seen.insert(key) {
                                devices.push(device);
                            }
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(format!("receive mDNS discovery response: {error}")),
                }
            }
        }

        if !received_any {
            thread::sleep(Duration::from_millis(20));
        }
    }

    devices.sort_by(|left, right| left.device_id.cmp(&right.device_id));
    Ok(devices)
}

/// Run an mDNS responder using standard-library UDP sockets.
///
/// `address` selects the IPv4 interface to advertise and the interface on which
/// the mDNS multicast group is joined. This keeps the response's A record
/// deterministic on multi-homed hosts.
#[cfg(feature = "std")]
pub fn run(identity: DeviceIdentity, model: &str, address: Ipv4Addr) -> Result<(), String> {
    let socket = std_responder_socket(address)?;
    let multicast = SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::from(PROVISION_MDNS_IPV4),
        PROVISION_MDNS_PORT,
    ));
    let (hostname, instance, device_id) =
        service_names(identity).ok_or_else(|| "build mDNS service names".to_owned())?;
    let mut packet = [0u8; DNS_PACKET_BUFFER];

    loop {
        let (len, source) = socket
            .recv_from(&mut packet)
            .map_err(|error| format!("receive mDNS query: {error}"))?;
        let Some(query) = matching_query(
            &packet[..len],
            PROVISION_MDNS_SERVICE,
            instance.as_str(),
            hostname.as_str(),
        ) else {
            continue;
        };

        let response_id = if source.port() == PROVISION_MDNS_PORT {
            0
        } else {
            query.id
        };
        let response_len = if query.enumeration {
            build_enumeration_response(&mut packet, response_id, PROVISION_MDNS_SERVICE)
        } else {
            build_service_response(
                &mut packet,
                response_id,
                PROVISION_MDNS_SERVICE,
                instance.as_str(),
                hostname.as_str(),
                device_id.as_str(),
                model,
                address.octets(),
            )
        };
        let Some(response_len) = response_len else {
            continue;
        };

        let destination = if source.port() != PROVISION_MDNS_PORT || query.prefer_unicast {
            source
        } else {
            multicast
        };
        socket
            .send_to(&packet[..response_len], destination)
            .map_err(|error| format!("send mDNS response: {error}"))?;
    }
}

#[cfg(feature = "std")]
fn std_discovery_sockets() -> Result<Vec<UdpSocket>, String> {
    use getifaddrs::getifaddrs;

    let mut local_ipv4 = HashSet::new();
    let interfaces =
        getifaddrs().map_err(|error| format!("enumerate network interfaces: {error}"))?;
    for interface in interfaces {
        let Some(IpAddr::V4(address)) = interface.address.ip_addr() else {
            continue;
        };
        if !address.is_loopback() && !address.is_unspecified() {
            local_ipv4.insert(address);
        }
    }

    let mut local_ipv4 = local_ipv4.into_iter().collect::<Vec<_>>();
    local_ipv4.sort_unstable();

    let mut sockets = Vec::new();
    for address in local_ipv4 {
        if let Ok(socket) = std_discovery_socket(address) {
            sockets.push(socket);
        }
    }

    if sockets.is_empty() {
        sockets.push(std_discovery_socket(Ipv4Addr::UNSPECIFIED)?);
    }
    Ok(sockets)
}

#[cfg(feature = "std")]
fn std_discovery_socket(address: Ipv4Addr) -> Result<UdpSocket, String> {
    let socket = UdpSocket::bind((address, 0))
        .map_err(|error| format!("bind mDNS discovery socket on {address}: {error}"))?;
    let socket = socket2::Socket::from(socket);
    socket
        .set_multicast_if_v4(&address)
        .map_err(|error| format!("select mDNS multicast interface {address}: {error}"))?;
    socket
        .set_multicast_ttl_v4(255)
        .map_err(|error| format!("set mDNS multicast TTL on {address}: {error}"))?;
    socket
        .set_nonblocking(true)
        .map_err(|error| format!("set mDNS discovery socket nonblocking on {address}: {error}"))?;
    Ok(socket.into())
}

#[cfg(feature = "std")]
fn std_responder_socket(address: Ipv4Addr) -> Result<UdpSocket, String> {
    use socket2::{Domain, Protocol, Socket, Type};

    let multicast = Ipv4Addr::from(PROVISION_MDNS_IPV4);
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|error| format!("create mDNS responder socket: {error}"))?;
    socket
        .set_reuse_address(true)
        .map_err(|error| format!("set mDNS responder SO_REUSEADDR: {error}"))?;
    socket
        .bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, PROVISION_MDNS_PORT).into())
        .map_err(|error| format!("bind mDNS responder socket: {error}"))?;
    socket
        .join_multicast_v4(&multicast, &address)
        .map_err(|error| format!("join mDNS multicast group on {address}: {error}"))?;
    socket
        .set_multicast_if_v4(&address)
        .map_err(|error| format!("select mDNS multicast interface {address}: {error}"))?;
    socket
        .set_multicast_ttl_v4(255)
        .map_err(|error| format!("set mDNS multicast TTL on {address}: {error}"))?;
    Ok(socket.into())
}

// ---- Embassy socket integration -------------------------------------------

#[cfg(all(feature = "embassy-net", not(feature = "std")))]
use embassy_net::{
    IpEndpoint, Ipv4Address, Stack,
    udp::{PacketMetadata, UdpSocket},
};
#[cfg(all(feature = "embassy-net", not(feature = "std")))]
use embassy_time::{Duration, Instant, with_timeout};
#[cfg(all(feature = "embassy-net", not(feature = "std")))]
use static_cell::StaticCell;

// Local UDP port used by Embassy discovery. It is intentionally not 5353 so
// the QU query receives unicast answers without sharing the responder socket.
#[cfg(all(feature = "embassy-net", not(feature = "std")))]
const DISCOVERY_PORT: u16 = 53530;

/// A provisioning-mode device discovered by the Embassy implementation.
#[cfg(all(feature = "embassy-net", not(feature = "std")))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredDevice {
    pub device_id: HString<MAX_MDNS_DEVICE_ID_LEN>,
    pub model: Option<HString<MAX_MDNS_MODEL_LEN>>,
    pub address: [u8; 4],
    pub port: u16,
}

#[cfg(all(feature = "embassy-net", not(feature = "std")))]
static RESPONDER_RX_META: StaticCell<[PacketMetadata; 2]> = StaticCell::new();
#[cfg(all(feature = "embassy-net", not(feature = "std")))]
static RESPONDER_TX_META: StaticCell<[PacketMetadata; 2]> = StaticCell::new();
#[cfg(all(feature = "embassy-net", not(feature = "std")))]
static RESPONDER_RX_BUFFER: StaticCell<[u8; DNS_PACKET_BUFFER]> = StaticCell::new();
#[cfg(all(feature = "embassy-net", not(feature = "std")))]
static RESPONDER_TX_BUFFER: StaticCell<[u8; DNS_PACKET_BUFFER]> = StaticCell::new();

/// Run the provisioning-mode mDNS responder on an Embassy network stack.
///
/// This signature is selected when `embassy-net` is enabled without `std`.
#[cfg(all(feature = "embassy-net", not(feature = "std")))]
pub async fn run(
    stack: Stack<'static>,
    identity: DeviceIdentity,
    model: &'static str,
) -> Result<(), ()> {
    let rx_meta = RESPONDER_RX_META.init([PacketMetadata::EMPTY; 2]);
    let tx_meta = RESPONDER_TX_META.init([PacketMetadata::EMPTY; 2]);
    let rx_buffer = RESPONDER_RX_BUFFER.init([0; DNS_PACKET_BUFFER]);
    let tx_buffer = RESPONDER_TX_BUFFER.init([0; DNS_PACKET_BUFFER]);

    let multicast = Ipv4Address::new(
        PROVISION_MDNS_IPV4[0],
        PROVISION_MDNS_IPV4[1],
        PROVISION_MDNS_IPV4[2],
        PROVISION_MDNS_IPV4[3],
    );
    stack.join_multicast_group(multicast).map_err(|_| ())?;

    let mut socket = UdpSocket::new(stack, rx_meta, rx_buffer, tx_meta, tx_buffer);
    socket.set_hop_limit(Some(255));
    socket.bind(PROVISION_MDNS_PORT).map_err(|_| ())?;

    let (hostname, instance, device_id) = service_names(identity).ok_or(())?;
    let mut packet = [0u8; DNS_PACKET_BUFFER];

    loop {
        let (len, source) = socket.recv_from(&mut packet).await.map_err(|_| ())?;
        let Some(query) = matching_query(
            &packet[..len],
            PROVISION_MDNS_SERVICE,
            instance.as_str(),
            hostname.as_str(),
        ) else {
            continue;
        };

        let Some(config) = stack.config_v4() else {
            continue;
        };
        let ip = config.address.address().octets();
        let response_id = if source.endpoint.port == PROVISION_MDNS_PORT {
            0
        } else {
            query.id
        };

        let response_len = if query.enumeration {
            build_enumeration_response(&mut packet, response_id, PROVISION_MDNS_SERVICE)
        } else {
            build_service_response(
                &mut packet,
                response_id,
                PROVISION_MDNS_SERVICE,
                instance.as_str(),
                hostname.as_str(),
                device_id.as_str(),
                model,
                ip,
            )
        };
        let Some(response_len) = response_len else {
            continue;
        };

        let destination = if source.endpoint.port != PROVISION_MDNS_PORT || query.prefer_unicast {
            source.endpoint
        } else {
            IpEndpoint::new(multicast.into(), PROVISION_MDNS_PORT)
        };
        socket
            .send_to(&packet[..response_len], destination)
            .await
            .map_err(|_| ())?;
    }
}

/// Discover provisioning-mode devices using an Embassy network stack.
///
/// Results use fixed-capacity strings and a caller-selected maximum `N`, so the
/// operation stays allocation-free. A unicast-response query is retried every
/// 350 ms until `timeout` expires. This signature is selected when `embassy-net`
/// is enabled without `std`.
#[cfg(all(feature = "embassy-net", not(feature = "std")))]
pub async fn discover<const N: usize>(
    stack: Stack<'static>,
    timeout: Duration,
) -> Result<HVec<DiscoveredDevice, N>, ()> {
    discover_on_port(stack, timeout, DISCOVERY_PORT).await
}

#[cfg(all(feature = "embassy-net", not(feature = "std")))]
async fn discover_on_port<const N: usize>(
    stack: Stack<'static>,
    timeout: Duration,
    local_port: u16,
) -> Result<HVec<DiscoveredDevice, N>, ()> {
    let retry = Duration::from_millis(350);

    if local_port == 0 || local_port == PROVISION_MDNS_PORT {
        return Err(());
    }

    let mut devices = HVec::new();
    if N == 0 {
        return Ok(devices);
    }

    let mut rx_meta = [PacketMetadata::EMPTY; 4];
    let mut tx_meta = [PacketMetadata::EMPTY; 2];
    let mut rx_buffer = [0u8; DNS_PACKET_BUFFER];
    let mut tx_buffer = [0u8; DNS_PACKET_BUFFER];
    let mut socket = UdpSocket::new(
        stack,
        &mut rx_meta,
        &mut rx_buffer,
        &mut tx_meta,
        &mut tx_buffer,
    );
    socket.set_hop_limit(Some(255));
    socket.bind(local_port).map_err(|_| ())?;

    let multicast = Ipv4Address::new(
        PROVISION_MDNS_IPV4[0],
        PROVISION_MDNS_IPV4[1],
        PROVISION_MDNS_IPV4[2],
        PROVISION_MDNS_IPV4[3],
    );
    let destination = IpEndpoint::new(multicast.into(), PROVISION_MDNS_PORT);
    let mut query = [0u8; DNS_PACKET_BUFFER];
    let query_len = build_discovery_query(&mut query).ok_or(())?;
    let mut packet = [0u8; DNS_PACKET_BUFFER];
    let deadline = Instant::now() + timeout;

    socket
        .send_to(&query[..query_len], destination)
        .await
        .map_err(|_| ())?;

    loop {
        let now = Instant::now();
        if now >= deadline || devices.len() == N {
            break;
        }
        let remaining = deadline - now;
        let wait = if remaining < retry { remaining } else { retry };

        match with_timeout(wait, socket.recv_from(&mut packet)).await {
            Ok(Ok((len, _))) => {
                let Some(parsed) = parse_discovery_response(&packet[..len]) else {
                    continue;
                };
                let duplicate = devices.iter().any(|device: &DiscoveredDevice| {
                    device.device_id == parsed.device_id
                        && device.address == parsed.address
                        && device.port == parsed.port
                });
                if !duplicate {
                    let _ = devices.push(DiscoveredDevice {
                        device_id: parsed.device_id,
                        model: parsed.model,
                        address: parsed.address,
                        port: parsed.port,
                    });
                }
            }
            Ok(Err(_)) => return Err(()),
            Err(_) => {
                if Instant::now() < deadline {
                    socket
                        .send_to(&query[..query_len], destination)
                        .await
                        .map_err(|_| ())?;
                }
            }
        }
    }

    Ok(devices)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_query_targets_the_provisioning_service() {
        let mut query = [0u8; DNS_PACKET_BUFFER];
        let len = build_discovery_query(&mut query).unwrap();
        assert_eq!(&query[4..6], &1u16.to_be_bytes());

        let mut name: HString<MAX_DNS_NAME_LEN> = HString::new();
        let next = read_name(&query[..len], DNS_HEADER_LEN, &mut name).unwrap();
        assert_eq!(name.as_str(), PROVISION_MDNS_SERVICE);
        assert_eq!(read_u16(&query, next), Some(DNS_TYPE_PTR));
        assert_eq!(
            read_u16(&query, next + 2),
            Some(DNS_CLASS_IN | DNS_CLASS_QU)
        );
    }

    #[test]
    fn shared_response_builder_round_trips_through_shared_parser() {
        let mut packet = [0u8; DNS_PACKET_BUFFER];
        let instance = "microtun-0svmx1udh1._microtun._tcp.local";
        let host = "microtun-0svmx1udh1.local";
        let len = build_service_response(
            &mut packet,
            0,
            PROVISION_MDNS_SERVICE,
            instance,
            host,
            "0svmx1udh1",
            "test-board",
            [10, 42, 0, 17],
        )
        .unwrap();

        let device = parse_discovery_response(&packet[..len]).unwrap();
        assert_eq!(device.device_id.as_str(), "0svmx1udh1");
        assert_eq!(
            device.model.as_ref().map(|value| value.as_str()),
            Some("test-board")
        );
        assert_eq!(device.address, [10, 42, 0, 17]);
        assert_eq!(device.port, PROVISION_PORT);
    }

    #[test]
    fn device_id_falls_back_to_canonical_hostname_prefix() {
        let device_id =
            device_id_from_instance("microtun-0svmx1udh1._microtun._tcp.local").unwrap();
        assert_eq!(device_id.as_str(), "0svmx1udh1");
    }

    #[test]
    fn service_names_embed_the_canonical_device_id() {
        let identity = DeviceIdentity::from_unique_bytes(&[0x12, 0xab, 0xcd]).unwrap();
        let (hostname, instance, device_id) = service_names(identity).unwrap();

        assert_eq!(device_id.as_str(), "0svmx1udh1");
        assert_eq!(hostname.as_str(), "microtun-0svmx1udh1.local");
        assert_eq!(
            instance.as_str(),
            "microtun-0svmx1udh1._microtun._tcp.local"
        );
    }

    #[test]
    fn responder_matches_the_shared_discovery_query() {
        let mut packet = [0u8; DNS_PACKET_BUFFER];
        let len = build_discovery_query(&mut packet).unwrap();
        let query = matching_query(
            &packet[..len],
            PROVISION_MDNS_SERVICE,
            "microtun-0svmx1udh1._microtun._tcp.local",
            "microtun-0svmx1udh1.local",
        )
        .unwrap();

        assert!(query.prefer_unicast);
        assert!(!query.enumeration);
    }
}
