//! RFC 6455 frame headers.
//!
//! Only the header is handled here, and only as bytes: the payload never
//! passes through this module, so nothing in it needs a buffer. That keeps the
//! one piece of bit-twiddling in the crate separate from the I/O it drives,
//! and testable without a transport.
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-------+-+-------------+-------------------------------+
//! |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
//! |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
//! |N|V|V|V|       |S|             |   (if payload len==126/127)   |
//! | |1|2|3|       |K|             |                               |
//! +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
//! |     Extended payload length continued, if payload len == 127  |
//! + - - - - - - - - - - - - - - - +-------------------------------+
//! |                               |Masking-key, if MASK set to 1  |
//! +-------------------------------+-------------------------------+
//! ```

use crate::error::Error;

/// The largest payload a control frame may carry (RFC 6455 §5.5).
///
/// Control frames must also never be fragmented, so this is a hard ceiling on
/// one control payload rather than on a control *message*, and a fixed
/// 125-byte array is enough to receive any of them.
pub const MAX_CONTROL_PAYLOAD_LEN: usize = 125;

/// The longest header this crate writes: two fixed bytes, an eight-byte
/// extended length, and a four-byte masking key.
pub(crate) const MAX_HEADER_LEN: usize = 14;

/// Frame opcodes.
pub(crate) mod opcode {
    pub(crate) const CONTINUATION: u8 = 0x0;
    pub(crate) const TEXT: u8 = 0x1;
    pub(crate) const BINARY: u8 = 0x2;
    pub(crate) const CLOSE: u8 = 0x8;
    pub(crate) const PING: u8 = 0x9;
    pub(crate) const PONG: u8 = 0xA;
}

/// Whether an opcode names a control frame.
pub(crate) const fn is_control(opcode: u8) -> bool {
    opcode & 0x8 != 0
}

/// The two fixed leading bytes of a frame, decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Prefix {
    pub fin: bool,
    pub opcode: u8,
    pub masked: bool,
    /// The 7-bit length field, which may be an escape for a longer one.
    pub len7: u8,
}

/// Decode the first two bytes of a frame.
///
/// The reserved bits are rejected here rather than ignored. They are only ever
/// set by an extension, this crate negotiates none, and a peer that believes
/// an extension is active is framing the rest of the stream by rules this
/// decoder does not implement — so continuing would misread every following
/// frame rather than just this one.
pub(crate) fn decode_prefix(bytes: [u8; 2]) -> Result<Prefix, Error> {
    if bytes[0] & 0x70 != 0 {
        return Err(Error::Protocol);
    }
    let opcode = bytes[0] & 0x0F;
    // 0x3..0x7 and 0xB..0xF are reserved for future data and control frames.
    let known = matches!(
        opcode,
        opcode::CONTINUATION
            | opcode::TEXT
            | opcode::BINARY
            | opcode::CLOSE
            | opcode::PING
            | opcode::PONG
    );
    if !known {
        return Err(Error::Protocol);
    }
    Ok(Prefix {
        fin: bytes[0] & 0x80 != 0,
        opcode,
        masked: bytes[1] & 0x80 != 0,
        len7: bytes[1] & 0x7F,
    })
}

/// How many further length bytes follow the prefix.
pub(crate) const fn extended_len_bytes(len7: u8) -> usize {
    match len7 {
        126 => 2,
        127 => 8,
        _ => 0,
    }
}

/// Combine the 7-bit length with its extension, if any.
///
/// A length that does not fit `usize` is [`Error::TooLarge`] rather than a
/// truncating cast: this receiver could not hold such a message anyway, and
/// wrapping the value would make an enormous frame look like a small one and
/// desynchronize the stream.
pub(crate) fn decode_len(len7: u8, extended: &[u8]) -> Result<usize, Error> {
    let len = match len7 {
        126 => {
            let bytes: [u8; 2] = extended.try_into().map_err(|_| Error::Protocol)?;
            u64::from(u16::from_be_bytes(bytes))
        }
        127 => {
            let bytes: [u8; 8] = extended.try_into().map_err(|_| Error::Protocol)?;
            let len = u64::from_be_bytes(bytes);
            // The high bit must be clear (RFC 6455 §5.2).
            if len & 0x8000_0000_0000_0000 != 0 {
                return Err(Error::Protocol);
            }
            len
        }
        short => u64::from(short),
    };
    usize::try_from(len).map_err(|_| Error::TooLarge)
}

/// Write a frame header into `out`, returning its length.
pub(crate) fn encode_header(
    out: &mut [u8; MAX_HEADER_LEN],
    fin: bool,
    opcode: u8,
    len: usize,
    mask: Option<[u8; 4]>,
) -> usize {
    out[0] = if fin { 0x80 | opcode } else { opcode };
    let mask_bit = if mask.is_some() { 0x80 } else { 0x00 };

    let mut cursor = 2;
    if len < 126 {
        out[1] = mask_bit | len as u8;
    } else if len <= u16::MAX as usize {
        out[1] = mask_bit | 126;
        out[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        cursor = 4;
    } else {
        out[1] = mask_bit | 127;
        out[2..10].copy_from_slice(&(len as u64).to_be_bytes());
        cursor = 10;
    }

    if let Some(key) = mask {
        out[cursor..cursor + 4].copy_from_slice(&key);
        cursor += 4;
    }
    cursor
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(fin: bool, opcode: u8, len: usize, mask: Option<[u8; 4]>) -> ([u8; 14], usize) {
        let mut out = [0u8; MAX_HEADER_LEN];
        let written = encode_header(&mut out, fin, opcode, len, mask);
        (out, written)
    }

    #[test]
    fn short_headers_are_two_bytes() {
        let (bytes, len) = header(true, opcode::TEXT, 5, None);
        assert_eq!(len, 2);
        assert_eq!(&bytes[..2], &[0x81, 0x05]);
    }

    #[test]
    fn masked_headers_carry_the_key() {
        let (bytes, len) = header(true, opcode::TEXT, 5, Some([1, 2, 3, 4]));
        assert_eq!(len, 6);
        assert_eq!(&bytes[..6], &[0x81, 0x85, 1, 2, 3, 4]);
    }

    /// Every length escape has to round-trip, because picking the wrong one
    /// shifts the payload by two or eight bytes and desynchronizes the stream
    /// rather than failing visibly.
    #[test]
    fn length_escapes_round_trip() {
        for len in [0usize, 1, 125, 126, 127, 65_535, 65_536, 1 << 20] {
            let (bytes, written) = header(true, opcode::BINARY, len, None);
            let prefix = decode_prefix([bytes[0], bytes[1]]).expect("prefix decodes");
            let extended = extended_len_bytes(prefix.len7);
            assert_eq!(written, 2 + extended);
            assert_eq!(
                decode_len(prefix.len7, &bytes[2..2 + extended]).expect("length decodes"),
                len
            );
        }
    }

    #[test]
    fn reserved_bits_and_opcodes_are_protocol_errors() {
        // RSV1 set, as `permessage-deflate` would.
        assert_eq!(decode_prefix([0xC1, 0x00]), Err(Error::Protocol));
        // A reserved data opcode.
        assert_eq!(decode_prefix([0x83, 0x00]), Err(Error::Protocol));
        // A reserved control opcode.
        assert_eq!(decode_prefix([0x8B, 0x00]), Err(Error::Protocol));
    }

    #[test]
    fn a_64_bit_length_with_the_high_bit_set_is_rejected() {
        let extended = [0xFF; 8];
        assert_eq!(decode_len(127, &extended), Err(Error::Protocol));
    }

    #[test]
    fn control_opcodes_are_recognized() {
        assert!(is_control(opcode::CLOSE));
        assert!(is_control(opcode::PING));
        assert!(is_control(opcode::PONG));
        assert!(!is_control(opcode::TEXT));
        assert!(!is_control(opcode::CONTINUATION));
    }
}
