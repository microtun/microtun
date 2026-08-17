//! Client-side WebSocket masking.
//!
//! RFC 6455 requires every client-to-server frame to use a fresh,
//! unpredictable 32-bit masking key. The opening handshake likewise requires
//! a fresh 16-byte `Sec-WebSocket-Key` nonce.
//!
//! `microtun-ws` deliberately does not invent entropy. A client constructor
//! takes a caller-owned [`rand_core::CryptoRng`], draws one 256-bit seed, and
//! retains a ChaCha20 CSPRNG for the lifetime of the connection. That keeps the
//! public connection type independent of the caller's RNG implementation while
//! ensuring all subsequent masking keys come from cryptographically strong
//! state. Servers do not allocate or initialize a masking generator at all.

use core::fmt;

use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};

/// Per-client cryptographic state for handshake nonces and frame masking keys.
///
/// This type stays private to the crate. Callers provide entropy through the
/// client constructors rather than selecting or seeding a WebSocket-specific
/// PRNG themselves.
pub(crate) struct Masker(ChaCha20Rng);

impl Masker {
    /// Seed one connection from a caller-provided cryptographic RNG.
    pub(crate) fn from_rng<R: RngCore + CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut seed = <ChaCha20Rng as SeedableRng>::Seed::default();
        rng.fill_bytes(&mut seed);
        let masker = Self(ChaCha20Rng::from_seed(seed));
        // The initialized CSPRNG retains the seed material it needs; do not
        // leave the temporary copy sitting on the stack longer than necessary.
        seed.fill(0);
        masker
    }

    /// Produce the four-byte masking key for one outgoing frame.
    pub(crate) fn key(&mut self) -> [u8; 4] {
        let mut key = [0u8; 4];
        self.0.fill_bytes(&mut key);
        key
    }

    /// Produce the 16 random bytes encoded into `Sec-WebSocket-Key`.
    pub(crate) fn nonce(&mut self) -> [u8; 16] {
        let mut nonce = [0u8; 16];
        self.0.fill_bytes(&mut nonce);
        nonce
    }
}

impl fmt::Debug for Masker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Masker").finish_non_exhaustive()
    }
}

/// XOR `data` with `key`, starting `offset` bytes into the four-byte cycle.
///
/// Returns the offset to resume from, so a payload can be masked or unmasked
/// incrementally without materializing the whole frame. Applying the function
/// twice with the same key and offsets restores the original bytes.
pub(crate) fn apply(key: [u8; 4], offset: usize, data: &mut [u8]) -> usize {
    let offset = offset & 3;
    for (index, byte) in data.iter_mut().enumerate() {
        *byte ^= key[(offset + index) & 3];
    }
    (offset + data.len()) & 3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_6455_masking_example_matches() {
        // RFC 6455 §5.7: "Hello" masked by 37 fa 21 3d.
        let key = [0x37, 0xFA, 0x21, 0x3D];
        let mut payload = *b"Hello";
        assert_eq!(apply(key, 0, &mut payload), 1);
        assert_eq!(payload, [0x7F, 0x9F, 0x4D, 0x51, 0x58]);
    }

    #[test]
    fn masking_is_its_own_inverse_across_chunk_boundaries() {
        let key = [0x37, 0xFA, 0x21, 0x3D];
        let original: [u8; 11] = *b"hello world";

        let mut whole = original;
        apply(key, 0, &mut whole);
        assert_ne!(whole, original);

        let mut chunked = original;
        let mut offset = 0;
        for range in [0..3, 3..4, 4..11] {
            offset = apply(key, offset, &mut chunked[range]);
        }
        assert_eq!(chunked, whole);

        apply(key, 0, &mut chunked);
        assert_eq!(chunked, original);
    }

    #[test]
    fn chunk_offsets_are_normalized() {
        let key = [1, 2, 3, 4];
        let mut a = *b"abcdef";
        let mut b = a;
        assert_eq!(apply(key, 1, &mut a), apply(key, 5, &mut b));
        assert_eq!(a, b);
    }

    #[test]
    fn masker_is_seeded_from_the_supplied_crypto_rng() {
        let mut entropy_a = ChaCha20Rng::from_seed([1; 32]);
        let mut entropy_b = ChaCha20Rng::from_seed([2; 32]);
        let mut a = Masker::from_rng(&mut entropy_a);
        let mut b = Masker::from_rng(&mut entropy_b);

        assert_ne!(a.nonce(), b.nonce());
        assert_ne!(a.key(), b.key());
    }
}
