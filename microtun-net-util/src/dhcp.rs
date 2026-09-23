//! Tiny DHCP server for the isolated fallback link.
//!
//! This intentionally implements only the DHCP messages needed to put a host
//! interface on the local link: DISCOVER/OFFER and REQUEST/ACK (plus RELEASE
//! cleanup). It advertises no router because the fallback network is local-only,
//! and does not override the host's DNS configuration; device discovery uses mDNS.

use embassy_net::{
    IpEndpoint, Ipv4Address, Stack,
    udp::{PacketMetadata, UdpSocket},
};
use static_cell::StaticCell;

use crate::{
    FALLBACK_DEVICE_IPV4, FALLBACK_DHCP_RANGE_END, FALLBACK_DHCP_RANGE_START,
    FALLBACK_IPV4_PREFIX_LEN,
};

const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;
const DHCP_PACKET_BUFFER: usize = 600;
const DHCP_FIXED_HEADER_LEN: usize = 240;
const DHCP_MIN_REPLY_LEN: usize = 300;
const DHCP_LEASE_SECONDS: u32 = 60 * 60;
const DHCP_LEASE_CAPACITY: usize =
    (FALLBACK_DHCP_RANGE_END[3] - FALLBACK_DHCP_RANGE_START[3] + 1) as usize;

const BOOTREQUEST: u8 = 1;
const BOOTREPLY: u8 = 2;
const ETHERNET_HTYPE: u8 = 1;
const DHCP_MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

const OPTION_PAD: u8 = 0;
const OPTION_SUBNET_MASK: u8 = 1;
const OPTION_BROADCAST_ADDRESS: u8 = 28;
const OPTION_REQUESTED_IP: u8 = 50;
const OPTION_LEASE_TIME: u8 = 51;
const OPTION_MESSAGE_TYPE: u8 = 53;
const OPTION_SERVER_IDENTIFIER: u8 = 54;
const OPTION_CLIENT_IDENTIFIER: u8 = 61;
const OPTION_END: u8 = 255;

const DHCP_DISCOVER: u8 = 1;
const DHCP_OFFER: u8 = 2;
const DHCP_REQUEST: u8 = 3;
const DHCP_DECLINE: u8 = 4;
const DHCP_ACK: u8 = 5;
const DHCP_NAK: u8 = 6;
const DHCP_RELEASE: u8 = 7;

#[derive(Clone, Copy)]
struct ClientKey {
    bytes: [u8; 16],
    len: u8,
}

impl ClientKey {
    const EMPTY: Self = Self {
        bytes: [0; 16],
        len: 0,
    };

    fn from_slice(value: &[u8]) -> Self {
        let mut key = Self::EMPTY;
        let len = value.len().min(key.bytes.len());
        key.bytes[..len].copy_from_slice(&value[..len]);
        key.len = len as u8;
        key
    }

    fn matches(&self, other: &Self) -> bool {
        self.len == other.len
            && self.bytes[..self.len as usize] == other.bytes[..other.len as usize]
    }
}

#[derive(Clone, Copy)]
struct Lease {
    in_use: bool,
    client: ClientKey,
}

impl Lease {
    const EMPTY: Self = Self {
        in_use: false,
        client: ClientKey::EMPTY,
    };
}

struct Request {
    message_type: u8,
    client: ClientKey,
    requested_ip: Option<[u8; 4]>,
    server_identifier: Option<[u8; 4]>,
    ciaddr: [u8; 4],
    htype: u8,
    hlen: u8,
    xid: [u8; 4],
    flags: [u8; 2],
    giaddr: [u8; 4],
    chaddr: [u8; 16],
}

/// Run the fallback-link DHCP server until the task is cancelled or the
/// UDP socket fails.
///
/// The pool is deliberately tiny and bounded. A lease table is kept only for
/// the lifetime of the DHCP server; rebooting the device forgets it, which is
/// fine because DHCP clients will simply request a lease again.
pub async fn run(stack: Stack<'static>) -> Result<(), ()> {
    static RX_META: StaticCell<[PacketMetadata; 1]> = StaticCell::new();
    static TX_META: StaticCell<[PacketMetadata; 1]> = StaticCell::new();
    static RX_BUFFER: StaticCell<[u8; DHCP_PACKET_BUFFER]> = StaticCell::new();
    static TX_BUFFER: StaticCell<[u8; DHCP_PACKET_BUFFER]> = StaticCell::new();
    static LEASES: StaticCell<[Lease; DHCP_LEASE_CAPACITY]> = StaticCell::new();

    let rx_meta = RX_META.init([PacketMetadata::EMPTY; 1]);
    let tx_meta = TX_META.init([PacketMetadata::EMPTY; 1]);
    let rx_buffer = RX_BUFFER.init([0; DHCP_PACKET_BUFFER]);
    let tx_buffer = TX_BUFFER.init([0; DHCP_PACKET_BUFFER]);
    let leases = LEASES.init([Lease::EMPTY; DHCP_LEASE_CAPACITY]);

    let mut socket = UdpSocket::new(stack, rx_meta, rx_buffer, tx_meta, tx_buffer);
    socket.bind(DHCP_SERVER_PORT).map_err(|_| ())?;

    let mut packet = [0u8; DHCP_PACKET_BUFFER];

    loop {
        let (len, _) = socket.recv_from(&mut packet).await.map_err(|_| ())?;
        let Some(request) = parse_request(&packet[..len]) else {
            continue;
        };

        // The fallback network is intentionally link-local. Do not service DHCP
        // relays from another subnet.
        if request.giaddr != [0; 4] {
            continue;
        }

        if let Some(server_identifier) = request.server_identifier {
            if server_identifier != FALLBACK_DEVICE_IPV4 {
                // A client chose a different DHCP server after receiving
                // multiple offers. Do not compete with the selected server.
                continue;
            }
        }

        match request.message_type {
            DHCP_DISCOVER => {
                let Some(slot) = existing_or_allocate_lease(leases, request.client) else {
                    continue;
                };
                let offered_ip = lease_ip(slot);
                let reply_len = build_reply(&request, &mut packet, DHCP_OFFER, offered_ip);
                socket
                    .send_to(
                        &packet[..reply_len],
                        reply_destination(&request, DHCP_OFFER),
                    )
                    .await
                    .map_err(|_| ())?;
            }
            DHCP_REQUEST => {
                let requested_ip = request
                    .requested_ip
                    .or_else(|| nonzero_ipv4(request.ciaddr))
                    .or_else(|| find_client_lease(leases, request.client).map(lease_ip));

                let Some(requested_ip) = requested_ip else {
                    continue;
                };

                let reply_type = match lease_slot(requested_ip) {
                    Some(slot)
                        if !leases[slot].in_use || leases[slot].client.matches(&request.client) =>
                    {
                        assign_lease(leases, slot, request.client);
                        DHCP_ACK
                    }
                    _ => DHCP_NAK,
                };

                let yiaddr = if reply_type == DHCP_ACK {
                    requested_ip
                } else {
                    [0; 4]
                };
                let reply_len = build_reply(&request, &mut packet, reply_type, yiaddr);
                socket
                    .send_to(
                        &packet[..reply_len],
                        reply_destination(&request, reply_type),
                    )
                    .await
                    .map_err(|_| ())?;
            }
            DHCP_RELEASE => {
                release_lease(leases, request.client);
            }
            DHCP_DECLINE => {
                decline_lease(leases, request.client);
            }
            _ => {}
        }
    }
}

fn parse_request(packet: &[u8]) -> Option<Request> {
    if packet.len() < DHCP_FIXED_HEADER_LEN
        || packet[0] != BOOTREQUEST
        || packet[1] != ETHERNET_HTYPE
        || packet[2] == 0
        || packet[2] > 16
        || packet[236..240] != DHCP_MAGIC_COOKIE
    {
        return None;
    }

    let ciaddr = [packet[12], packet[13], packet[14], packet[15]];
    let hlen = packet[2] as usize;
    let mut client = ClientKey::from_slice(&packet[28..28 + hlen]);
    let mut message_type = None;
    let mut requested_ip = None;
    let mut server_identifier = None;

    let mut offset = DHCP_FIXED_HEADER_LEN;
    while offset < packet.len() {
        let code = packet[offset];
        offset += 1;

        match code {
            OPTION_PAD => continue,
            OPTION_END => break,
            _ => {}
        }

        let Some(&option_len) = packet.get(offset) else {
            break;
        };
        offset += 1;
        let option_len = option_len as usize;
        let Some(value) = packet.get(offset..offset + option_len) else {
            break;
        };
        offset += option_len;

        match code {
            OPTION_MESSAGE_TYPE if value.len() == 1 => message_type = Some(value[0]),
            OPTION_REQUESTED_IP if value.len() == 4 => {
                requested_ip = Some([value[0], value[1], value[2], value[3]]);
            }
            OPTION_SERVER_IDENTIFIER if value.len() == 4 => {
                server_identifier = Some([value[0], value[1], value[2], value[3]]);
            }
            OPTION_CLIENT_IDENTIFIER if !value.is_empty() => {
                client = ClientKey::from_slice(value);
            }
            _ => {}
        }
    }

    let mut chaddr = [0; 16];
    chaddr.copy_from_slice(&packet[28..44]);

    Some(Request {
        message_type: message_type?,
        client,
        requested_ip,
        server_identifier,
        ciaddr,
        htype: packet[1],
        hlen: packet[2],
        xid: [packet[4], packet[5], packet[6], packet[7]],
        flags: [packet[10], packet[11]],
        giaddr: [packet[24], packet[25], packet[26], packet[27]],
        chaddr,
    })
}

fn build_reply(request: &Request, reply: &mut [u8], message_type: u8, yiaddr: [u8; 4]) -> usize {
    reply.fill(0);

    reply[0] = BOOTREPLY;
    reply[1] = request.htype;
    reply[2] = request.hlen;
    reply[4..8].copy_from_slice(&request.xid);
    reply[10..12].copy_from_slice(&request.flags);
    if message_type == DHCP_ACK {
        // RFC 2131: ACK copies ciaddr when the client is renewing/rebinding.
        reply[12..16].copy_from_slice(&request.ciaddr);
    }
    reply[16..20].copy_from_slice(&yiaddr);
    reply[24..28].copy_from_slice(&request.giaddr);
    reply[28..44].copy_from_slice(&request.chaddr);
    reply[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);

    let mut offset = DHCP_FIXED_HEADER_LEN;
    push_option(reply, &mut offset, OPTION_MESSAGE_TYPE, &[message_type]);
    push_option(
        reply,
        &mut offset,
        OPTION_SERVER_IDENTIFIER,
        &FALLBACK_DEVICE_IPV4,
    );

    if message_type == DHCP_OFFER || message_type == DHCP_ACK {
        push_option(
            reply,
            &mut offset,
            OPTION_LEASE_TIME,
            &DHCP_LEASE_SECONDS.to_be_bytes(),
        );
        push_option(
            reply,
            &mut offset,
            OPTION_SUBNET_MASK,
            &prefix_mask(FALLBACK_IPV4_PREFIX_LEN),
        );
        push_option(
            reply,
            &mut offset,
            OPTION_BROADCAST_ADDRESS,
            &[
                FALLBACK_DEVICE_IPV4[0],
                FALLBACK_DEVICE_IPV4[1],
                FALLBACK_DEVICE_IPV4[2],
                255,
            ],
        );
    }

    reply[offset] = OPTION_END;
    offset += 1;

    offset.max(DHCP_MIN_REPLY_LEN)
}

fn push_option(packet: &mut [u8], offset: &mut usize, code: u8, value: &[u8]) {
    packet[*offset] = code;
    packet[*offset + 1] = value.len() as u8;
    packet[*offset + 2..*offset + 2 + value.len()].copy_from_slice(value);
    *offset += value.len() + 2;
}

fn existing_or_allocate_lease(leases: &mut [Lease], client: ClientKey) -> Option<usize> {
    if let Some(slot) = find_client_lease(leases, client) {
        return Some(slot);
    }

    let slot = leases.iter().position(|lease| !lease.in_use)?;
    leases[slot] = Lease {
        in_use: true,
        client,
    };
    Some(slot)
}

fn find_client_lease(leases: &[Lease], client: ClientKey) -> Option<usize> {
    leases
        .iter()
        .position(|lease| lease.in_use && lease.client.matches(&client))
}

fn assign_lease(leases: &mut [Lease], slot: usize, client: ClientKey) {
    for lease in leases.iter_mut() {
        if lease.in_use && lease.client.matches(&client) {
            *lease = Lease::EMPTY;
        }
    }
    leases[slot] = Lease {
        in_use: true,
        client,
    };
}

fn release_lease(leases: &mut [Lease], client: ClientKey) {
    if let Some(slot) = find_client_lease(leases, client) {
        leases[slot] = Lease::EMPTY;
    }
}

fn decline_lease(leases: &mut [Lease], client: ClientKey) {
    if let Some(slot) = find_client_lease(leases, client) {
        // Keep the declined address out of the pool for this DHCP server
        // session, but detach it from the client that reported the conflict.
        leases[slot] = Lease {
            in_use: true,
            client: ClientKey::EMPTY,
        };
    }
}

fn reply_destination(request: &Request, message_type: u8) -> IpEndpoint {
    let ip = if message_type != DHCP_NAK {
        nonzero_ipv4(request.ciaddr).unwrap_or([255, 255, 255, 255])
    } else {
        [255, 255, 255, 255]
    };

    IpEndpoint::new(
        Ipv4Address::new(ip[0], ip[1], ip[2], ip[3]).into(),
        DHCP_CLIENT_PORT,
    )
}

fn lease_ip(slot: usize) -> [u8; 4] {
    [
        FALLBACK_DHCP_RANGE_START[0],
        FALLBACK_DHCP_RANGE_START[1],
        FALLBACK_DHCP_RANGE_START[2],
        FALLBACK_DHCP_RANGE_START[3] + slot as u8,
    ]
}

fn lease_slot(ip: [u8; 4]) -> Option<usize> {
    if ip[0..3] != FALLBACK_DHCP_RANGE_START[0..3]
        || ip[3] < FALLBACK_DHCP_RANGE_START[3]
        || ip[3] > FALLBACK_DHCP_RANGE_END[3]
    {
        return None;
    }
    Some((ip[3] - FALLBACK_DHCP_RANGE_START[3]) as usize)
}

fn nonzero_ipv4(ip: [u8; 4]) -> Option<[u8; 4]> {
    (ip != [0; 4]).then_some(ip)
}

fn prefix_mask(prefix_len: u8) -> [u8; 4] {
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len as u32)
    };
    mask.to_be_bytes()
}
