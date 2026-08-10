//! Cryptographic primitives exactly as specified in whitepaper §5.4:
//!
//! * `Hash(input)`    = BLAKE2s-256
//! * `Mac(key, in)`   = keyed BLAKE2s, 16-byte output
//! * `Hmac(key, in)`  = HMAC-BLAKE2s, 32-byte output
//! * `Kdf_n(key, in)` = HKDF chain built from `Hmac`
//! * `Aead`           = ChaCha20Poly1305 (RFC 7539) with a 32-bit-zero ‖
//!   64-bit-LE-counter nonce
//! * `Xaead`          = XChaCha20Poly1305 with a random 24-byte nonce
//! * `DH`             = Curve25519 (X25519)
//! * `Timestamp()`    = TAI64N
//!
//! Everything is pure-Rust and `no_std`; on RV32IMC / thumbv8m these all run
//! in software (there is no hardware ChaCha/BLAKE2s/X25519 on the target
//! chips), which keeps both supported MCUs on identical code paths.

use blake2::{
    Blake2s256, Blake2sMac, Digest,
    digest::{FixedOutput, KeyInit, Update, consts::U16},
};
use chacha20poly1305::{ChaCha20Poly1305, Key, Tag, XChaCha20Poly1305, XNonce, aead::AeadInPlace};
use hmac::SimpleHmac;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::error::Error;

/// AEAD authentication tag length (Poly1305).
pub const TAG_LEN: usize = 16;
/// TAI64N timestamp length.
pub const TIMESTAMP_LEN: usize = 12;
/// XChaCha20Poly1305 nonce length used by cookie replies.
pub const XNONCE_LEN: usize = 24;

/// Two secret outputs produced by [`kdf2`].
pub type Kdf2Output = (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>);

/// Three secret outputs produced by [`kdf3`].
pub type Kdf3Output = (
    Zeroizing<[u8; 32]>,
    Zeroizing<[u8; 32]>,
    Zeroizing<[u8; 32]>,
);

/// `Hash(a ‖ b ‖ ...)` — BLAKE2s-256 over the concatenation of the parts.
pub fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Blake2s256::new();
    for p in parts {
        Digest::update(&mut h, p);
    }
    h.finalize().into()
}

/// `Mac(key, a ‖ b ‖ ...)` — keyed BLAKE2s with 16-byte output (§5.4).
pub fn mac16(key: &[u8], parts: &[&[u8]]) -> Result<[u8; 16], Error> {
    let mut m = <Blake2sMac<U16> as KeyInit>::new_from_slice(key).map_err(|_| Error::Crypto)?;
    for p in parts {
        Update::update(&mut m, p);
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&m.finalize_fixed());
    Ok(out)
}

/// Constant-time comparison of two 16-byte MACs.
#[inline]
pub fn mac_eq(a: &[u8; 16], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    b.len() == 16 && bool::from(a.ct_eq(b))
}

/// `Hmac(key, a ‖ b ‖ ...)` — HMAC-BLAKE2s with 32-byte output.
fn hmac(key: &[u8; 32], parts: &[&[u8]]) -> Result<[u8; 32], Error> {
    let mut m =
        <SimpleHmac<Blake2s256> as KeyInit>::new_from_slice(key).map_err(|_| Error::Crypto)?;
    for p in parts {
        Update::update(&mut m, p);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&m.finalize_fixed());
    Ok(out)
}

/// `Kdf₁(key, input)` (§5.4): first derived key of the HKDF chain.
///
/// Every `Kdf` output is a chaining key or a transport/handshake key, so all
/// of them come back wrapped in [`Zeroizing`]: the caller's binding is wiped
/// when it goes out of scope, including on the `?` early-returns that are
/// dense in the handshake code.
pub fn kdf1(key: &[u8; 32], input: &[u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut t0 = hmac(key, &[input])?;
    let t1 = hmac(&t0, &[&[0x01]])?;
    t0.zeroize();
    Ok(Zeroizing::new(t1))
}

/// `Kdf₂(key, input)`.
pub fn kdf2(key: &[u8; 32], input: &[u8]) -> Result<Kdf2Output, Error> {
    let mut t0 = hmac(key, &[input])?;
    let t1 = hmac(&t0, &[&[0x01]])?;
    let t2 = hmac(&t0, &[&t1[..], &[0x02]])?;
    t0.zeroize();
    Ok((Zeroizing::new(t1), Zeroizing::new(t2)))
}

/// `Kdf₃(key, input)`.
pub fn kdf3(key: &[u8; 32], input: &[u8]) -> Result<Kdf3Output, Error> {
    let mut t0 = hmac(key, &[input])?;
    let t1 = hmac(&t0, &[&[0x01]])?;
    let t2 = hmac(&t0, &[&t1[..], &[0x02]])?;
    let t3 = hmac(&t0, &[&t2[..], &[0x03]])?;
    t0.zeroize();
    Ok((Zeroizing::new(t1), Zeroizing::new(t2), Zeroizing::new(t3)))
}

/// Build the 12-byte ChaCha20Poly1305 nonce: 32 bits of zeros followed by the
/// 64-bit little-endian counter (§5.4).
#[inline]
fn counter_nonce(counter: u64) -> chacha20poly1305::Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&counter.to_le_bytes());
    n.into()
}

/// `Aead(key, counter, plaintext, authtext)`: encrypt `buf[..pt_len]` in
/// place and append the 16-byte tag. `buf` must have room for
/// `pt_len + TAG_LEN`. Returns the total ciphertext length.
pub fn aead_seal(
    key: &[u8; 32],
    counter: u64,
    buf: &mut [u8],
    pt_len: usize,
    ad: &[u8],
) -> Result<usize, Error> {
    let total = pt_len + TAG_LEN;
    if buf.len() < total {
        return Err(Error::BufferTooSmall);
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = counter_nonce(counter);
    let (plaintext, tag_out) = buf[..total].split_at_mut(pt_len);
    let tag = cipher
        .encrypt_in_place_detached(&nonce, ad, plaintext)
        .map_err(|_| Error::Crypto)?;
    tag_out.copy_from_slice(&tag);
    Ok(total)
}

/// Open an `Aead` ciphertext in place. `buf` is `ciphertext ‖ tag`; on
/// success returns the plaintext length (`buf.len() - TAG_LEN`) and the
/// plaintext occupies `buf[..len]`.
pub fn aead_open(key: &[u8; 32], counter: u64, buf: &mut [u8], ad: &[u8]) -> Result<usize, Error> {
    if buf.len() < TAG_LEN {
        return Err(Error::Crypto);
    }
    let pt_len = buf.len() - TAG_LEN;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = counter_nonce(counter);
    let (data, tag_bytes) = buf.split_at_mut(pt_len);
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(tag_bytes);
    cipher
        .decrypt_in_place_detached(&nonce, ad, data, Tag::from_slice(&tag))
        .map_err(|_| Error::Crypto)?;
    Ok(pt_len)
}

/// `Xaead(key, nonce, plaintext, authtext)` used for cookie replies (§5.4.7).
/// Encrypts `buf[..pt_len]` in place and appends the tag.
pub fn xaead_seal(
    key: &[u8; 32],
    nonce: &[u8; XNONCE_LEN],
    buf: &mut [u8],
    pt_len: usize,
    ad: &[u8],
) -> Result<usize, Error> {
    let total = pt_len + TAG_LEN;
    if buf.len() < total {
        return Err(Error::BufferTooSmall);
    }
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let (plaintext, tag_out) = buf[..total].split_at_mut(pt_len);
    let tag = cipher
        .encrypt_in_place_detached(XNonce::from_slice(nonce), ad, plaintext)
        .map_err(|_| Error::Crypto)?;
    tag_out.copy_from_slice(&tag);
    Ok(total)
}

/// Open an `Xaead` ciphertext in place; returns plaintext length.
pub fn xaead_open(
    key: &[u8; 32],
    nonce: &[u8; XNONCE_LEN],
    buf: &mut [u8],
    ad: &[u8],
) -> Result<usize, Error> {
    if buf.len() < TAG_LEN {
        return Err(Error::Crypto);
    }
    let pt_len = buf.len() - TAG_LEN;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let (data, tag_bytes) = buf.split_at_mut(pt_len);
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(tag_bytes);
    cipher
        .decrypt_in_place_detached(XNonce::from_slice(nonce), ad, data, Tag::from_slice(&tag))
        .map_err(|_| Error::Crypto)?;
    Ok(pt_len)
}

/// `DH(private, public)` — X25519 scalar multiplication.
///
/// Returns `Err(Error::Crypto)` if the shared secret is all-zero (the peer
/// supplied a low-order point), which the Noise spec requires rejecting.
pub fn dh(private: &[u8; 32], public: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, Error> {
    let secret = StaticSecret::from(*private);
    let shared = secret.diffie_hellman(&PublicKey::from(*public));
    let bytes = Zeroizing::new(*shared.as_bytes());
    if bytes.iter().all(|&b| b == 0) {
        return Err(Error::Crypto);
    }
    Ok(bytes)
}

/// Derive the public key for a private key.
pub fn public_key(private: &[u8; 32]) -> [u8; 32] {
    *PublicKey::from(&StaticSecret::from(*private)).as_bytes()
}

/// Generate a fresh Curve25519 keypair (`DH-Generate()`), returning
/// `(private, public)`.
pub fn dh_generate<R: rand_core::RngCore + rand_core::CryptoRng>(
    rng: &mut R,
) -> (Zeroizing<[u8; 32]>, [u8; 32]) {
    let secret = StaticSecret::random_from_rng(&mut *rng);
    let public = PublicKey::from(&secret);
    (Zeroizing::new(secret.to_bytes()), *public.as_bytes())
}

/// Build a TAI64N timestamp (§5.1) from a Unix wall-clock reading: 8 bytes
/// big-endian seconds since the TAI epoch label, then 4 bytes big-endian
/// nanoseconds.
///
/// WireGuard uses the conventional TAI64N label offset of
/// `0x4000_0000_0000_000a` for Unix timestamps. Peers only compare our
/// timestamps against our own previous ones, but matching that encoding
/// avoids a needless interoperability window when an identity moves between
/// implementations. As in wireguard-go, the low 24 bits of the nanoseconds
/// field are cleared to reduce wall-clock precision leakage.
pub fn tai64n(unix_secs: u64, nanos: u32) -> Result<[u8; TIMESTAMP_LEN], Error> {
    let seconds = 0x4000_0000_0000_000au64
        .checked_add(unix_secs)
        .ok_or(Error::TimeOverflow)?;
    let mut out = [0u8; TIMESTAMP_LEN];
    out[..8].copy_from_slice(&seconds.to_be_bytes());
    out[8..].copy_from_slice(&(nanos & !0x00ff_ffff).to_be_bytes());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::*;

    fn rng(seed: u8) -> ChaCha20Rng {
        ChaCha20Rng::from_seed([seed; 32])
    }

    fn keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
        let (private, public) = dh_generate(&mut rng(seed));
        (*private, public)
    }

    #[test]
    fn hash_mac_and_kdf_match_independent_known_answers() {
        assert_eq!(
            hash(&[b"abc", b"def"]),
            [
                0x26, 0x7e, 0x44, 0x43, 0xfc, 0x1a, 0x38, 0x87, 0x9f, 0xeb, 0x10, 0x90, 0xaf, 0x1e,
                0x78, 0x89, 0x56, 0xdf, 0xd9, 0x32, 0x04, 0xcd, 0xdc, 0xba, 0x81, 0x8d, 0x6e, 0x32,
                0xee, 0x57, 0xf3, 0x35,
            ]
        );

        let mac = mac16(&[7u8; 32], &[b"m", b"sg"]).expect("mac");
        assert_eq!(
            mac,
            [
                0x36, 0x59, 0x05, 0xb5, 0x8c, 0x28, 0x8b, 0x65, 0xbe, 0xfd, 0xcf, 0xf4, 0x1a, 0x7f,
                0x34, 0xa3,
            ]
        );
        assert!(mac_eq(&mac, &mac));
        assert!(!mac_eq(&mac, &mac[..15]));

        let (t1, t2, t3) = kdf3(&[3u8; 32], b"chaining input").expect("kdf3");
        assert_eq!(
            *t1,
            [
                0x33, 0xac, 0x91, 0x55, 0x5f, 0x97, 0x8a, 0x44, 0x05, 0xa1, 0x7e, 0x9f, 0x44, 0x1a,
                0xab, 0x98, 0x6b, 0xb7, 0x89, 0x42, 0x1f, 0xbe, 0x6e, 0xf1, 0xb2, 0x5f, 0x7a, 0xc0,
                0xb6, 0x9b, 0x30, 0xbd,
            ]
        );
        assert_eq!(
            *t2,
            [
                0x37, 0x6b, 0xc9, 0x9c, 0xc7, 0x57, 0x07, 0x47, 0x51, 0x1f, 0x61, 0xc5, 0x89, 0xe7,
                0xd9, 0x51, 0x14, 0x4a, 0xc5, 0x78, 0x60, 0x07, 0xd1, 0x51, 0x14, 0xaa, 0xc1, 0xab,
                0x1d, 0x7b, 0xa9, 0xec,
            ]
        );
        assert_eq!(
            *t3,
            [
                0xc5, 0x92, 0x4a, 0x02, 0x8f, 0xcc, 0xdc, 0x13, 0x5d, 0x54, 0x09, 0x59, 0xbf, 0x2a,
                0x90, 0x3e, 0xb3, 0x73, 0xe9, 0x74, 0x23, 0x2d, 0xea, 0xe5, 0x89, 0x3b, 0xae, 0x07,
                0x93, 0x67, 0x49, 0x18,
            ]
        );
    }

    #[test]
    fn aead_binds_its_key_counter_and_associated_data() {
        let key = [1u8; 32];
        let plaintext = b"transport payload";
        let mut buf = vec![0u8; plaintext.len() + TAG_LEN];
        buf[..plaintext.len()].copy_from_slice(plaintext);

        let total = aead_seal(&key, 7, &mut buf, plaintext.len(), b"ad").expect("seal");
        assert_eq!(total, plaintext.len() + TAG_LEN);
        assert_ne!(
            &buf[..plaintext.len()],
            &plaintext[..],
            "ciphertext is not plaintext"
        );

        let sealed = buf.clone();
        let opened = aead_open(&key, 7, &mut buf, b"ad").expect("open");
        assert_eq!(opened, plaintext.len());
        assert_eq!(&buf[..opened], &plaintext[..]);

        // Each of the four bindings must be load-bearing on its own.
        let mut wrong_counter = sealed.clone();
        assert_eq!(
            aead_open(&key, 8, &mut wrong_counter, b"ad"),
            Err(Error::Crypto)
        );
        let mut wrong_key = sealed.clone();
        assert_eq!(
            aead_open(&[2u8; 32], 7, &mut wrong_key, b"ad"),
            Err(Error::Crypto)
        );
        let mut wrong_ad = sealed.clone();
        assert_eq!(
            aead_open(&key, 7, &mut wrong_ad, b"other"),
            Err(Error::Crypto)
        );
        let mut tampered = sealed.clone();
        tampered[0] ^= 1;
        assert_eq!(aead_open(&key, 7, &mut tampered, b"ad"), Err(Error::Crypto));
        let mut clipped = sealed[..sealed.len() - 1].to_vec();
        assert_eq!(aead_open(&key, 7, &mut clipped, b"ad"), Err(Error::Crypto));

        // The counter is the nonce, so reusing a key across counters must
        // produce unrelated keystreams.
        let seal_at = |counter: u64| {
            let mut buf = vec![0u8; plaintext.len() + TAG_LEN];
            buf[..plaintext.len()].copy_from_slice(plaintext);
            aead_seal(&key, counter, &mut buf, plaintext.len(), b"").expect("seal");
            buf
        };
        assert_ne!(seal_at(0), seal_at(1));
        assert_eq!(seal_at(9), seal_at(9), "sealing is deterministic");

        // A zero-length plaintext is the keepalive and the handshake `empty`
        // field: a bare tag.
        let mut empty = [0u8; TAG_LEN];
        assert_eq!(
            aead_seal(&key, 0, &mut empty, 0, b"h").expect("seal"),
            TAG_LEN
        );
        assert_eq!(aead_open(&key, 0, &mut empty, b"h").expect("open"), 0);

        // Buffers that cannot hold the tag are refused rather than truncated.
        let mut tiny = [0u8; 4];
        assert_eq!(
            aead_seal(&key, 0, &mut tiny, 4, b""),
            Err(Error::BufferTooSmall)
        );
        assert_eq!(aead_open(&key, 0, &mut tiny, b""), Err(Error::Crypto));
    }

    #[test]
    fn xaead_round_trips_and_binds_its_nonce_and_associated_data() {
        // The cookie reply's binding to the provoking mac1 lives in the AD
        // here; without it a third party could feed us fraudulent cookies.
        let key = [5u8; 32];
        let nonce = [6u8; XNONCE_LEN];
        let cookie = [0xabu8; 16];

        let mut buf = [0u8; 16 + TAG_LEN];
        buf[..16].copy_from_slice(&cookie);
        assert_eq!(
            xaead_seal(&key, &nonce, &mut buf, 16, b"mac1").expect("seal"),
            16 + TAG_LEN
        );
        let sealed = buf;

        assert_eq!(
            xaead_open(&key, &nonce, &mut buf, b"mac1").expect("open"),
            16
        );
        assert_eq!(&buf[..16], &cookie);

        let mut wrong_ad = sealed;
        assert_eq!(
            xaead_open(&key, &nonce, &mut wrong_ad, b"other"),
            Err(Error::Crypto)
        );
        let mut wrong_nonce = sealed;
        assert_eq!(
            xaead_open(&key, &[7u8; XNONCE_LEN], &mut wrong_nonce, b"mac1"),
            Err(Error::Crypto)
        );

        let mut tiny = [0u8; 4];
        assert_eq!(
            xaead_seal(&key, &nonce, &mut tiny, 4, b""),
            Err(Error::BufferTooSmall)
        );
        assert_eq!(xaead_open(&key, &nonce, &mut tiny, b""), Err(Error::Crypto));
    }

    #[test]
    fn diffie_hellman_agrees_and_refuses_low_order_points() {
        let (a_priv, a_pub) = keypair(1);
        let (b_priv, b_pub) = keypair(2);
        assert_ne!(a_pub, b_pub);

        let ab = dh(&a_priv, &b_pub).expect("agreement");
        let ba = dh(&b_priv, &a_pub).expect("agreement");
        assert_eq!(*ab, *ba, "X25519 must be commutative");

        let (_, c_pub) = keypair(3);
        assert_ne!(*ab, *dh(&a_priv, &c_pub).expect("agreement"));

        // The Noise spec requires rejecting an all-zero shared secret, which
        // is what a low-order public key produces. Accepting it would let a
        // peer force a known key.
        assert_eq!(dh(&a_priv, &[0u8; 32]).err(), Some(Error::Crypto));

        // Public keys are a pure function of the private key, and generation
        // agrees with derivation.
        assert_eq!(public_key(&a_priv), a_pub);
        let (generated_priv, generated_pub) = dh_generate(&mut rng(9));
        assert_eq!(public_key(&generated_priv), generated_pub);
        assert_ne!(generated_pub, dh_generate(&mut rng(10)).1);
    }

    #[test]
    fn tai64n_encodes_the_conventional_label_and_orders_bytewise() {
        // WireGuard uses the TAI64N label offset 0x4000_0000_0000_000a for
        // Unix timestamps: eight big-endian seconds then four big-endian
        // nanoseconds.
        assert_eq!(
            tai64n(0, 0).expect("epoch"),
            [0x40, 0, 0, 0, 0, 0, 0, 0x0a, 0, 0, 0, 0]
        );
        assert_eq!(
            tai64n(1, 2).expect("one second"),
            [0x40, 0, 0, 0, 0, 0, 0, 0x0b, 0, 0, 0, 0]
        );
        assert_eq!(tai64n(0, 0).expect("epoch").len(), TIMESTAMP_LEN);

        // Peers compare timestamps as opaque byte strings, so the big-endian
        // encoding has to make byte order match time order — including across
        // a nanosecond rollover into the next second.
        let earlier = tai64n(1_700_000_000, 999_999_999).expect("timestamp");
        let later = tai64n(1_700_000_001, 0).expect("timestamp");
        assert!(earlier < later);
        assert_eq!(tai64n(5, 1).expect("t"), tai64n(5, 2).expect("t"));
        assert!(tai64n(5, 0x0100_0000).expect("t") > tai64n(5, 0x00ff_ffff).expect("t"));

        assert_eq!(tai64n(u64::MAX, 0), Err(Error::TimeOverflow));
    }
}
