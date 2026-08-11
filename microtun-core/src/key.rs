//! The textual form of a 32-byte static key.
//!
//! WireGuard writes a key as standard base64 — 44 characters ending in `=` —
//! and every tool an operator already has speaks that form: `wg genkey`,
//! `wg show`, a `wg.conf`. microtun uses exactly the same spelling, so a key
//! can be moved between the two without conversion.
//!
//! # One spelling
//!
//! There used to be a second one. Standard base64 uses `+` and `/`, and `/` is
//! a path separator, so while the Peers API was REST the `by-key`
//! lookup put a key in a URL path segment and needed the URL-safe alphabet of
//! RFC 4648 §5 for that one place. The protocol is JSON-RPC now and has no
//! paths, so the second alphabet went with them: a key has exactly one form
//! everywhere — configuration files, parameters, results, and logs.
//!
//! Decoding is strict. A key is 32 bytes, which is not a multiple of three, so
//! the last character carries four data bits and two that are unused. Those
//! two must be zero: otherwise a single key would have four different
//! spellings, and two records naming the same peer could fail to compare
//! equal. The `base64` crate's general-purpose engines already refuse non-zero
//! trailing bits and require canonical padding, so this module adds only the
//! fixed 32-byte length to that.
//!
//! Everything here is slice-based: `no_std` targets encode and decode a key
//! without allocating.

use core::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use zeroize::Zeroizing;

/// Characters in a key's standard base64 form, as `wg` prints one.
pub const KEY_TEXT_LEN: usize = 44;

/// Bytes `decode_slice` must be handed, which is not the 32 it writes.
///
/// The engine checks the output against a length *estimate* computed from the
/// input alone, before it knows how much padding the input carries — for our
/// input lengths that estimate rounds up to the next whole 3-byte group. The
/// scratch buffer exists to satisfy that check; only the 32 bytes actually
/// decoded are ever copied out.
const DECODE_SCRATCH_LEN: usize = 33;

/// A key rendered as text.
///
/// Owns its characters, so it can be built and returned on a `no_std` target
/// with nothing to allocate. `TEXT_LEN` is the length of the encoding: see
/// [`KeyBase64`], which is currently the only one.
///
/// This is only an encoding of bytes the caller already holds. It applies no
/// secrecy of its own, and a value built from a *private* key will print it —
/// which is why nothing in this workspace encodes one.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KeyText<const TEXT_LEN: usize>([u8; TEXT_LEN]);

/// A key in WireGuard's standard base64: 44 characters ending in `=`.
pub type KeyBase64 = KeyText<KEY_TEXT_LEN>;

impl<const TEXT_LEN: usize> KeyText<TEXT_LEN> {
    /// The encoded characters.
    pub fn as_str(&self) -> &str {
        // Only alphabet characters and `=` are ever written, so this cannot
        // fail. Answering with the fallback rather than unwrapping keeps a
        // panicking path out of the binary.
        core::str::from_utf8(&self.0).unwrap_or("")
    }
}

impl<const TEXT_LEN: usize> AsRef<str> for KeyText<TEXT_LEN> {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl<const TEXT_LEN: usize> fmt::Display for KeyText<TEXT_LEN> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<const TEXT_LEN: usize> fmt::Debug for KeyText<TEXT_LEN> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.as_str())
    }
}

/// A string that is not the base64 form of a 32-byte key.
///
/// Deliberately carries no detail about *why*. The reasons — wrong length,
/// a character outside the alphabet, a non-canonical tail — are all the same
/// answer to the caller, and a decoder that reports which character it
/// disliked is a decoder that describes the key it was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct InvalidKey;

impl fmt::Display for InvalidKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not a base64-encoded 32-byte key")
    }
}

impl core::error::Error for InvalidKey {}

/// Encode a key the way WireGuard writes one.
pub fn encode_key(key: &[u8; 32]) -> KeyBase64 {
    let mut text = [0u8; KEY_TEXT_LEN];
    let written = STANDARD
        .encode_slice(key, &mut text)
        .expect("KEY_TEXT_LEN is the padded base64 length of 32 bytes");
    debug_assert_eq!(written, KEY_TEXT_LEN);
    KeyText(text)
}

/// Decode a key from WireGuard's standard base64.
pub fn decode_key(text: &str) -> Result<[u8; 32], InvalidKey> {
    let mut key = [0u8; 32];
    decode_key_into(text, &mut key)?;
    Ok(key)
}

/// Decode a key from WireGuard's standard base64 directly into `key`.
///
/// The `_into` form exists for private keys: it writes through to a buffer the
/// caller can wipe, rather than returning a copy of the secret by value and
/// leaving that copy on the stack. `key` is written only on success.
pub fn decode_key_into(text: &str, key: &mut [u8; 32]) -> Result<(), InvalidKey> {
    if text.len() != KEY_TEXT_LEN {
        return Err(InvalidKey);
    }
    decode_into(text, &STANDARD, key)
}

/// Decode `text` with `engine`, accepting only a result that is exactly a key.
///
/// The caller has already checked the character count, so a length other than
/// 32 here means the input was well-formed base64 of something that is not a
/// key.
fn decode_into(
    text: &str,
    engine: &impl base64::Engine,
    key: &mut [u8; 32],
) -> Result<(), InvalidKey> {
    // Wiped on the way out: `decode_key_into` exists so that a private key can
    // be decoded without leaving a copy behind, and this buffer would be one.
    let mut scratch = Zeroizing::new([0u8; DECODE_SCRATCH_LEN]);
    let written = engine
        .decode_slice(text.as_bytes(), &mut *scratch)
        .map_err(|_| InvalidKey)?;
    if written != key.len() {
        return Err(InvalidKey);
    }
    key.copy_from_slice(&scratch[..written]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key whose byte pattern reaches the characters at the top of the
    /// alphabet: its standard form contains `+`, which is the one the
    /// now-retired URL-safe spelling existed to avoid.
    const MIXED: [u8; 32] = [
        0xC2, 0xD3, 0xE4, 0xF5, 0x06, 0x17, 0x28, 0x39, 0x4A, 0x5B, 0x6C, 0x7D, 0x8E, 0x9F, 0x0A,
        0x1B, 0x2C, 0x3D, 0x4E, 0x5F, 0x60, 0x71, 0x82, 0x93, 0xA4, 0xB5, 0xC6, 0xD7, 0xE8, 0xF9,
        0xA0, 0xB1,
    ];
    const MIXED_TEXT: &str = "wtPk9QYXKDlKW2x9jp8KGyw9Tl9gcYKTpLXG1+j5oLE=";
    /// The same key in the URL-safe, unpadded alphabet the protocol no longer
    /// uses. Kept as a negative fixture: it must not decode as a key.
    const MIXED_URL: &str = "wtPk9QYXKDlKW2x9jp8KGyw9Tl9gcYKTpLXG1-j5oLE";

    #[test]
    fn encodes_the_same_text_wireguard_does() {
        assert_eq!(encode_key(&MIXED).as_str(), MIXED_TEXT);
        assert_eq!(
            encode_key(&[0u8; 32]).as_str(),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        );
        assert_eq!(
            encode_key(&[0xAA; 32]).as_str(),
            "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo="
        );
        assert_eq!(encode_key(&MIXED).as_str().len(), KEY_TEXT_LEN);
    }

    #[test]
    fn round_trips_every_byte_pattern() {
        for seed in 0u8..=255 {
            let mut key = [0u8; 32];
            for (index, byte) in key.iter_mut().enumerate() {
                *byte = seed.wrapping_mul(index as u8).wrapping_add(seed);
            }
            assert_eq!(decode_key(encode_key(&key).as_str()).unwrap(), key);
        }
    }

    #[test]
    fn decodes_the_canonical_form() {
        assert_eq!(decode_key(MIXED_TEXT).unwrap(), MIXED);
    }

    #[test]
    fn decode_into_writes_through() {
        let mut key = [0xFFu8; 32];
        decode_key_into(MIXED_TEXT, &mut key).unwrap();
        assert_eq!(key, MIXED);
    }

    /// A key has one spelling. The URL-safe form the REST protocol used in a
    /// path segment is not a second one, and a client still sending it gets a
    /// clean rejection rather than a silent match.
    #[test]
    fn the_retired_url_form_is_not_a_key() {
        // Wrong length, and `-` is outside the standard alphabet.
        assert_eq!(decode_key(MIXED_URL), Err(InvalidKey));
        // Right length, wrong alphabet.
        let swapped = MIXED_TEXT.replace('+', "-");
        assert_eq!(decode_key(&swapped), Err(InvalidKey));
    }

    #[test]
    fn rejects_malformed_text() {
        assert_eq!(decode_key(""), Err(InvalidKey));
        assert_eq!(decode_key("AAAA"), Err(InvalidKey));
        // Right length, no padding character.
        assert_eq!(decode_key(&MIXED_TEXT.replace('=', "A")), Err(InvalidKey));
        // Right length, a character outside the alphabet.
        assert_eq!(decode_key(&MIXED_TEXT.replace('w', " ")), Err(InvalidKey));
        // Hexadecimal, which is what this used to be.
        assert_eq!(decode_key(&"ab".repeat(32)), Err(InvalidKey));
    }

    #[test]
    fn rejects_a_non_canonical_tail() {
        // The all-zero key ends in `A`, which is zero. `B` is one: it sets the
        // lowest bit of the final character, which is not a data bit.
        let canonical = encode_key(&[0u8; 32]);
        let mut altered = canonical.as_str().to_string();
        altered.replace_range(42..43, "B");
        assert_eq!(decode_key(canonical.as_str()).unwrap(), [0u8; 32]);
        assert_eq!(decode_key(&altered), Err(InvalidKey));
    }

    #[test]
    fn text_displays_as_its_characters() {
        assert_eq!(encode_key(&MIXED).to_string(), MIXED_TEXT);
        assert_eq!(encode_key(&MIXED).as_ref(), MIXED_TEXT);
    }
}
