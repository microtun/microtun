//! Microtun relay envelope carried by transport message type 0xF0.
//!
//! Relay type 0xF0 uses the normal WireGuard transport header, session keys, counters,
//! replay window, padding, and timers. Its authenticated plaintext is:
//!
//! ```text
//! destination_public_key[32] || inner_len_le[4] || inner_wireguard_packet
//! ```
//!
//! The inner packet is a complete standard WireGuard datagram (types 1-4) and
//! is forwarded unchanged to one directly reachable destination. There is no
//! relay version field, hop limit, route list, or relay-side re-wrapping.

use core::mem::size_of;

use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned,
    byteorder::{LittleEndian, U32},
};

use crate::messages::{self, Message};

/// Fixed relay header preceding the inner WireGuard datagram.
#[repr(C)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub struct EnvelopeHeader {
    /// Destination peer static X25519 public key.
    pub destination: [u8; 32],
    /// Exact length of the inner WireGuard datagram, excluding relay-message padding.
    pub inner_len: U32<LittleEndian>,
}

/// Fixed relay-envelope header size: 36 bytes. The inner datagram begins on a 4-byte boundary.
pub const ENVELOPE_HEADER_LEN: usize = size_of::<EnvelopeHeader>();

/// Largest complete inner WireGuard datagram that can fit in one relay
/// packet under Microtun's 1500-byte outer UDP budget.
pub const MAX_RELAY_INNER_SIZE: usize =
    (((crate::MAX_UDP_SIZE - messages::DATA_OVERHEAD) & !15) - ENVELOPE_HEADER_LEN) & !15;

/// Largest IP plaintext that fits in a relayed type-4 WireGuard datagram.
/// Inner type-4 datagrams are 16-byte aligned, so round the remaining budget
/// down before subtracting their 32-byte transport overhead.
pub const MAX_RELAY_INNER_IP_SIZE: usize = (MAX_RELAY_INNER_SIZE - messages::DATA_OVERHEAD) & !15;

/// Write the fixed relay header into `buf`.
///
/// This is crate-internal because callers must already have enforced the outer
/// packet size limit; under that invariant `inner_len` trivially fits in `u32`.
pub(crate) fn write_header(buf: &mut [u8], destination: &[u8; 32], inner_len: usize) -> Option<()> {
    let inner_len = u32::try_from(inner_len).ok()?;
    let header = EnvelopeHeader {
        destination: *destination,
        inner_len: U32::new(inner_len),
    };
    buf.get_mut(..ENVELOPE_HEADER_LEN)?
        .copy_from_slice(header.as_bytes());
    Some(())
}

/// A successfully parsed relay envelope.
#[derive(Debug, Clone, Copy)]
pub struct Envelope<'a> {
    /// Destination peer static X25519 public key.
    pub destination: [u8; 32],
    /// Complete standard WireGuard datagram, excluding relay outer padding.
    pub inner: &'a [u8],
}

/// Parse and validate a decrypted relay plaintext.
///
/// The explicit inner length keeps parsing independent of the inner message's
/// own padding rules. Any bytes after the inner datagram must be exactly the
/// zero padding implied by the normal 16-byte transport padding rule.
pub fn parse(plaintext: &[u8]) -> Option<Envelope<'_>> {
    let (header, rest) = EnvelopeHeader::ref_from_prefix(plaintext).ok()?;
    let inner_len = usize::try_from(header.inner_len.get()).ok()?;
    let unpadded_len = ENVELOPE_HEADER_LEN.checked_add(inner_len)?;
    let expected_plaintext_len = unpadded_len.checked_add(15)? & !15;
    if plaintext.len() != expected_plaintext_len {
        return None;
    }

    let inner = rest.get(..inner_len)?;
    if rest.get(inner_len..)?.iter().any(|&byte| byte != 0) || !inner_plausible(inner) {
        return None;
    }

    Some(Envelope {
        destination: header.destination,
        inner,
    })
}

/// Is `inner` wire-format-plausible as a standard WireGuard datagram?
///
/// Relay type 0xF0 is deliberately excluded: this relay protocol is single-hop and a
/// relay never forwards another relay envelope as its inner datagram.
fn inner_plausible(inner: &[u8]) -> bool {
    match messages::classify(inner) {
        Some(Message::Initiation | Message::Response | Message::CookieReply) => true,
        Some(Message::Data) => inner.len() % 16 == 0,
        Some(Message::RelayData) | None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DESTINATION: [u8; 32] = [0x5a; 32];

    fn inner(message_type: u8, len: usize) -> Vec<u8> {
        let mut packet = vec![0u8; len];
        packet[0] = message_type;
        packet
    }

    fn envelope(inner: &[u8]) -> Vec<u8> {
        let payload_len = ENVELOPE_HEADER_LEN + inner.len();
        let padded_len = (payload_len + 15) & !15;
        let mut plaintext = vec![0u8; padded_len];
        write_header(&mut plaintext, &DESTINATION, inner.len()).expect("relay header");
        plaintext[ENVELOPE_HEADER_LEN..ENVELOPE_HEADER_LEN + inner.len()].copy_from_slice(inner);
        plaintext
    }

    #[test]
    fn layout_and_size_budget_are_stable() {
        assert_eq!(ENVELOPE_HEADER_LEN, 36);
        assert_eq!(MAX_RELAY_INNER_SIZE, 1408);
        assert_eq!(MAX_RELAY_INNER_IP_SIZE, 1376);

        let plaintext = envelope(&inner(messages::MSG_DATA, 0x120));
        assert_eq!(&plaintext[..32], &DESTINATION);
        assert_eq!(&plaintext[32..36], &[0x20, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn parses_all_standard_wireguard_message_types() {
        for packet in [
            inner(messages::MSG_INITIATION, messages::INITIATION_LEN),
            inner(messages::MSG_RESPONSE, messages::RESPONSE_LEN),
            inner(messages::MSG_COOKIE_REPLY, messages::COOKIE_REPLY_LEN),
            inner(messages::MSG_DATA, messages::DATA_MIN_LEN),
            inner(messages::MSG_DATA, 1408),
        ] {
            let plaintext = envelope(&packet);
            let parsed = parse(&plaintext).expect("valid relay envelope");
            assert_eq!(parsed.destination, DESTINATION);
            assert_eq!(parsed.inner, packet);
        }
    }

    #[test]
    fn rejects_nested_type_five_and_malformed_inner_packets() {
        assert!(
            parse(&envelope(&inner(
                messages::MSG_RELAY,
                messages::DATA_MIN_LEN
            )))
            .is_none()
        );
        assert!(parse(&envelope(&inner(0x42, 64))).is_none());
        assert!(
            parse(&envelope(&inner(
                messages::MSG_DATA,
                messages::DATA_MIN_LEN - 1
            )))
            .is_none()
        );
        assert!(
            parse(&envelope(&inner(
                messages::MSG_DATA,
                messages::DATA_MIN_LEN + 1
            )))
            .is_none()
        );

        let mut reserved = inner(messages::MSG_DATA, messages::DATA_MIN_LEN);
        reserved[2] = 1;
        assert!(parse(&envelope(&reserved)).is_none());
    }

    #[test]
    fn rejects_bad_lengths_noncanonical_padding_and_extra_blocks() {
        let packet = inner(messages::MSG_INITIATION, messages::INITIATION_LEN);
        let good = envelope(&packet);
        assert!(parse(&good).is_some());

        let mut overrun = good.clone();
        overrun[32..36].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse(&overrun).is_none());

        let mut wrong_length = good.clone();
        wrong_length[32..36].copy_from_slice(&((packet.len() - 1) as u32).to_le_bytes());
        assert!(parse(&wrong_length).is_none());

        let mut nonzero_padding = good.clone();
        *nonzero_padding.last_mut().expect("padding") = 1;
        assert!(parse(&nonzero_padding).is_none());

        let mut extra_block = good;
        extra_block.extend_from_slice(&[0u8; 16]);
        assert!(parse(&extra_block).is_none());
    }
}
