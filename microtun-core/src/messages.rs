//! Wire message layouts (§5.4).
//!
//! The fixed portions are represented as `zerocopy` wire structs. This keeps
//! layout, byte order, and the protocol constants tied together at compile
//! time while still allowing the Noise and cookie code to work with byte
//! ranges for authenticated/encrypted transcript slices.
//!
//! All multi-byte integers are little-endian per the whitepaper. The three
//! reserved zero bytes make the first four bytes readable together as the
//! little-endian message type without adding alignment padding.

use core::{
    mem::{offset_of, size_of},
    ops::Range,
};

use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned,
    byteorder::{LittleEndian, U32, U64},
};

use crate::{
    crypto::{TAG_LEN, TIMESTAMP_LEN, XNONCE_LEN},
    error::Error,
};

/// Message type identifiers.
pub const MSG_INITIATION: u8 = 1;
pub const MSG_RESPONSE: u8 = 2;
pub const MSG_COOKIE_REPLY: u8 = 3;
pub const MSG_DATA: u8 = 4;
/// Microtun extension: authenticated relay transport data. It reuses the
/// standard transport header/session/counter machinery, but its plaintext is a
/// relay envelope rather than an IP packet.
pub const MSG_RELAY: u8 = 0xF0;

/// Relay type 0xF0 authenticates its four-byte message prefix as AEAD associated data.
/// Type 4 remains standard WireGuard and therefore continues to use empty AD.
pub const RELAY_AEAD_AD: &[u8] = &[MSG_RELAY, 0, 0, 0];
/// Common `type ‖ reserved` prefix shared by every WireGuard packet.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub struct MessagePrefix {
    pub message_type: u8,
    pub reserved: [u8; 3],
}

/// Fixed handshake-initiation packet.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub struct HandshakeInitiation {
    pub prefix: MessagePrefix,
    pub sender: U32<LittleEndian>,
    pub ephemeral: [u8; 32],
    pub encrypted_static: [u8; 32 + TAG_LEN],
    pub encrypted_timestamp: [u8; TIMESTAMP_LEN + TAG_LEN],
    pub mac1: [u8; 16],
    pub mac2: [u8; 16],
}

/// Fixed handshake-response packet.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub struct HandshakeResponse {
    pub prefix: MessagePrefix,
    pub sender: U32<LittleEndian>,
    pub receiver: U32<LittleEndian>,
    pub ephemeral: [u8; 32],
    pub encrypted_empty: [u8; TAG_LEN],
    pub mac1: [u8; 16],
    pub mac2: [u8; 16],
}

/// Fixed cookie-reply packet.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub struct CookieReply {
    pub prefix: MessagePrefix,
    pub receiver: U32<LittleEndian>,
    pub nonce: [u8; XNONCE_LEN],
    pub encrypted_cookie: [u8; 16 + TAG_LEN],
}

/// Fixed header preceding every variable-length transport ciphertext.
#[repr(C)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub struct DataHeader {
    pub prefix: MessagePrefix,
    pub receiver: U32<LittleEndian>,
    pub counter: U64<LittleEndian>,
}

/// Total lengths, derived directly from the wire structs.
pub const INITIATION_LEN: usize = size_of::<HandshakeInitiation>();
pub const RESPONSE_LEN: usize = size_of::<HandshakeResponse>();
pub const COOKIE_REPLY_LEN: usize = size_of::<CookieReply>();
/// Transport data fixed header (type+rsv+receiver+counter).
pub const DATA_HEADER_LEN: usize = size_of::<DataHeader>();
/// Total per-packet transport overhead: header + Poly1305 tag.
pub const DATA_OVERHEAD: usize = DATA_HEADER_LEN + TAG_LEN;
/// Minimum transport message: header + tag over a zero-length keepalive.
pub const DATA_MIN_LEN: usize = DATA_OVERHEAD;

const fn field_range(start: usize, len: usize) -> Range<usize> {
    start..start + len
}

// Byte ranges remain useful for transcript hashing and in-place AEAD. Their
// offsets come from the typed layouts instead of duplicated handwritten math.
pub mod init {
    use super::*;
    pub const SENDER: Range<usize> = field_range(offset_of!(HandshakeInitiation, sender), 4);
    pub const EPHEMERAL: Range<usize> = field_range(offset_of!(HandshakeInitiation, ephemeral), 32);
    pub const STATIC: Range<usize> = field_range(
        offset_of!(HandshakeInitiation, encrypted_static),
        32 + TAG_LEN,
    );
    pub const TIMESTAMP: Range<usize> = field_range(
        offset_of!(HandshakeInitiation, encrypted_timestamp),
        TIMESTAMP_LEN + TAG_LEN,
    );
    pub const MAC1: Range<usize> = field_range(offset_of!(HandshakeInitiation, mac1), 16);
    pub const MAC2: Range<usize> = field_range(offset_of!(HandshakeInitiation, mac2), 16);
    /// Bytes covered by mac1 (`msgα`).
    pub const ALPHA: Range<usize> = 0..offset_of!(HandshakeInitiation, mac1);
    /// Bytes covered by mac2 (`msgβ`).
    pub const BETA: Range<usize> = 0..offset_of!(HandshakeInitiation, mac2);
}

pub mod resp {
    use super::*;
    pub const SENDER: Range<usize> = field_range(offset_of!(HandshakeResponse, sender), 4);
    pub const RECEIVER: Range<usize> = field_range(offset_of!(HandshakeResponse, receiver), 4);
    pub const EPHEMERAL: Range<usize> = field_range(offset_of!(HandshakeResponse, ephemeral), 32);
    pub const EMPTY: Range<usize> =
        field_range(offset_of!(HandshakeResponse, encrypted_empty), TAG_LEN);
    pub const MAC1: Range<usize> = field_range(offset_of!(HandshakeResponse, mac1), 16);
    pub const MAC2: Range<usize> = field_range(offset_of!(HandshakeResponse, mac2), 16);
    pub const ALPHA: Range<usize> = 0..offset_of!(HandshakeResponse, mac1);
    pub const BETA: Range<usize> = 0..offset_of!(HandshakeResponse, mac2);
}

pub mod cookie {
    use super::*;
    pub const RECEIVER: Range<usize> = field_range(offset_of!(CookieReply, receiver), 4);
    pub const NONCE: Range<usize> = field_range(offset_of!(CookieReply, nonce), XNONCE_LEN);
    pub const COOKIE: Range<usize> =
        field_range(offset_of!(CookieReply, encrypted_cookie), 16 + TAG_LEN);
}

pub mod data {
    use super::*;
    pub const RECEIVER: Range<usize> = field_range(offset_of!(DataHeader, receiver), 4);
    pub const COUNTER: Range<usize> = field_range(offset_of!(DataHeader, counter), 8);
    pub const PACKET_START: usize = DATA_HEADER_LEN;
}

/// Write the common `type ‖ reserved` prefix.
#[inline]
pub fn write_type(buf: &mut [u8], message_type: u8) -> Result<(), Error> {
    let prefix = MessagePrefix {
        message_type,
        reserved: [0; 3],
    };
    buf.get_mut(..size_of::<MessagePrefix>())
        .ok_or(Error::BufferTooSmall)?
        .copy_from_slice(prefix.as_bytes());
    Ok(())
}

#[inline]
pub fn read_u32_le(bytes: &[u8]) -> Option<u32> {
    Some(U32::<LittleEndian>::read_from_prefix(bytes).ok()?.0.get())
}

#[inline]
pub fn read_u64_le(bytes: &[u8]) -> Option<u64> {
    Some(U64::<LittleEndian>::read_from_prefix(bytes).ok()?.0.get())
}

/// Classify a datagram by type byte + exact/minimum length. Returns `None`
/// for anything malformed — which per §5.1 is silently dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Message {
    Initiation,
    Response,
    CookieReply,
    Data,
    /// Microtun relay transport data (private type 0xF0).
    RelayData,
}

pub fn classify(buf: &[u8]) -> Option<Message> {
    let prefix = MessagePrefix::ref_from_prefix(buf).ok()?.0;
    if prefix.reserved != [0; 3] {
        return None;
    }
    match prefix.message_type {
        MSG_INITIATION if buf.len() == INITIATION_LEN => Some(Message::Initiation),
        MSG_RESPONSE if buf.len() == RESPONSE_LEN => Some(Message::Response),
        MSG_COOKIE_REPLY if buf.len() == COOKIE_REPLY_LEN => Some(Message::CookieReply),
        MSG_DATA if buf.len() >= DATA_MIN_LEN => Some(Message::Data),
        MSG_RELAY if buf.len() >= DATA_MIN_LEN => Some(Message::RelayData),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every fixed length and field offset, pinned against the whitepaper's
    /// §5.4 layouts. These come from `zerocopy` struct definitions rather than
    /// handwritten arithmetic, so this test is what notices if a field is
    /// reordered, resized, or accidentally padded.
    #[test]
    fn wire_layouts_match_the_specification() {
        assert_eq!(INITIATION_LEN, 148);
        assert_eq!(RESPONSE_LEN, 92);
        assert_eq!(COOKIE_REPLY_LEN, 64);
        assert_eq!(DATA_HEADER_LEN, 16);
        assert_eq!(DATA_OVERHEAD, 32);
        assert_eq!(DATA_MIN_LEN, DATA_OVERHEAD);
        assert_eq!(size_of::<MessagePrefix>(), 4);
        assert_eq!(MSG_RELAY, 0xF0);
        assert_eq!(RELAY_AEAD_AD, &[0xF0, 0, 0, 0]);

        assert_eq!(init::SENDER, 4..8);
        assert_eq!(init::EPHEMERAL, 8..40);
        assert_eq!(init::STATIC, 40..88);
        assert_eq!(init::TIMESTAMP, 88..116);
        assert_eq!(init::MAC1, 116..132);
        assert_eq!(init::MAC2, 132..148);
        // mac1 covers everything before it, mac2 everything before *it*.
        assert_eq!(init::ALPHA, 0..init::MAC1.start);
        assert_eq!(init::BETA, 0..init::MAC2.start);

        assert_eq!(resp::SENDER, 4..8);
        assert_eq!(resp::RECEIVER, 8..12);
        assert_eq!(resp::EPHEMERAL, 12..44);
        assert_eq!(resp::EMPTY, 44..60);
        assert_eq!(resp::MAC1, 60..76);
        assert_eq!(resp::MAC2, 76..92);
        assert_eq!(resp::ALPHA, 0..resp::MAC1.start);
        assert_eq!(resp::BETA, 0..resp::MAC2.start);

        assert_eq!(cookie::RECEIVER, 4..8);
        assert_eq!(cookie::NONCE, 8..32);
        assert_eq!(cookie::COOKIE, 32..64);

        assert_eq!(data::RECEIVER, 4..8);
        assert_eq!(data::COUNTER, 8..16);
        assert_eq!(data::PACKET_START, DATA_HEADER_LEN);
    }

    #[test]
    fn classification_demands_the_exact_shape_of_each_message() {
        let of = |message_type: u8, len: usize| {
            let mut buf = vec![0u8; len];
            if !buf.is_empty() {
                buf[0] = message_type;
            }
            classify(&buf)
        };

        assert_eq!(
            of(MSG_INITIATION, INITIATION_LEN),
            Some(Message::Initiation)
        );
        assert_eq!(of(MSG_RESPONSE, RESPONSE_LEN), Some(Message::Response));
        assert_eq!(
            of(MSG_COOKIE_REPLY, COOKIE_REPLY_LEN),
            Some(Message::CookieReply)
        );

        // The handshake messages are fixed-size; one byte either way is not a
        // handshake message.
        for message_type in [MSG_INITIATION, MSG_RESPONSE, MSG_COOKIE_REPLY] {
            let exact = match message_type {
                MSG_INITIATION => INITIATION_LEN,
                MSG_RESPONSE => RESPONSE_LEN,
                _ => COOKIE_REPLY_LEN,
            };
            assert_eq!(of(message_type, exact - 1), None);
            assert_eq!(of(message_type, exact + 1), None);
        }

        // Transport messages are variable-length above a floor.
        assert_eq!(of(MSG_DATA, DATA_MIN_LEN), Some(Message::Data));
        assert_eq!(of(MSG_DATA, DATA_MIN_LEN + 1_000), Some(Message::Data));
        assert_eq!(of(MSG_DATA, DATA_MIN_LEN - 1), None);
        assert_eq!(of(MSG_RELAY, DATA_MIN_LEN), Some(Message::RelayData));
        assert_eq!(
            of(MSG_RELAY, DATA_MIN_LEN + 1_000),
            Some(Message::RelayData)
        );
        assert_eq!(of(MSG_RELAY, DATA_MIN_LEN - 1), None);

        // Unknown types and anything too short to hold the common prefix.
        assert_eq!(of(0, INITIATION_LEN), None);
        assert_eq!(of(0xff, DATA_MIN_LEN), None);
        assert_eq!(classify(&[]), None);
        assert_eq!(classify(&[MSG_DATA, 0, 0]), None);

        // The three reserved bytes must be zero, so a peer cannot smuggle
        // anything through them or produce two readings of one datagram.
        for byte in 1..4 {
            let mut buf = vec![0u8; INITIATION_LEN];
            buf[0] = MSG_INITIATION;
            buf[byte] = 1;
            assert_eq!(classify(&buf), None, "reserved byte {byte}");
        }
    }

    #[test]
    fn integers_are_little_endian_and_short_reads_fail_rather_than_pad() {
        let mut buf = vec![0u8; DATA_HEADER_LEN];
        write_type(&mut buf, MSG_DATA).expect("prefix written");
        assert_eq!(buf[0], MSG_DATA);
        assert_eq!(&buf[1..4], &[0, 0, 0], "reserved bytes are zeroed");
        let mut relay_prefix = [0u8; 4];
        write_type(&mut relay_prefix, MSG_RELAY).expect("relay prefix written");
        assert_eq!(&relay_prefix, RELAY_AEAD_AD);

        buf[data::RECEIVER].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        buf[data::COUNTER].copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(read_u32_le(&buf[data::RECEIVER]), Some(0x1234_5678));
        assert_eq!(
            read_u64_le(&buf[data::COUNTER]),
            Some(0x0102_0304_0506_0708)
        );
        assert_eq!(buf[data::RECEIVER.start], 0x78, "little-endian on the wire");

        // Reads take a prefix, so trailing bytes are ignored but missing ones
        // are an error rather than an implicit zero pad.
        assert_eq!(read_u32_le(&[1, 0, 0, 0, 9, 9]), Some(1));
        assert_eq!(read_u32_le(&[1, 0, 0]), None);
        assert_eq!(read_u64_le(&[1, 0, 0, 0, 0, 0, 0]), None);
        assert_eq!(read_u32_le(&[]), None);

        // Writing into a buffer that cannot hold the prefix is reported.
        let mut tiny = [0u8; 3];
        assert_eq!(write_type(&mut tiny, MSG_DATA), Err(Error::BufferTooSmall));
    }
}
