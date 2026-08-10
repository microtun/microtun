//! The Noise `IKpsk2` handshake (§5.4.2, §5.4.3, §5.4.5).
//!
//! The PSK `Q` is fixed to `0³²`: microtun deliberately has no PSK
//! configuration surface, but the psk2 KDF step **must** still be executed —
//! the construction string names `IKpsk2` and omitting the `Kdf₃(C, Q)` step
//! would produce a wire-incompatible protocol. With `Q = 0³²` we are
//! compatible with any standard WireGuard peer that has no PSK set.
//!
//! These functions are pure: they take key material in and produce message
//! bodies (without `mac1`/`mac2`, which are the cookie layer's job — see
//! [`crate::cookie`]) plus the state needed for the next step.

use core::ops::Range;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    crypto::{TIMESTAMP_LEN, aead_open, aead_seal, dh, dh_generate, hash, kdf1, kdf2, kdf3},
    error::Error,
    messages::{self, INITIATION_LEN, RESPONSE_LEN},
};

const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
/// `Q` — the (unused) pre-shared key, fixed all-zero. See module docs.
const PSK_Q: [u8; 32] = [0u8; 32];

#[inline]
fn field(msg: &[u8], range: Range<usize>) -> &[u8] {
    &msg[range]
}

#[inline]
fn field_mut(msg: &mut [u8], range: Range<usize>) -> &mut [u8] {
    &mut msg[range]
}

/// `Ci := Hash(Construction)`, `Hi := Hash(Ci ‖ Identifier)` — the common
/// prologue. Cheap (two BLAKE2s invocations), so recomputed per handshake
/// rather than cached.
///
/// The chaining key `C` is held in [`Zeroizing`] from here on: every
/// reassignment below drops (and therefore wipes) the previous generation,
/// and the final value is wiped when the binding leaves scope — including
/// via the `?` early-returns. `H` is left bare on purpose: up to the psk2
/// step it is a hash over material an on-path observer already has, and
/// afterwards it is a one-way hash of τ used only as AEAD associated data.
fn prologue() -> (Zeroizing<[u8; 32]>, [u8; 32]) {
    let c = hash(&[CONSTRUCTION]);
    let h = hash(&[&c, IDENTIFIER]);
    (Zeroizing::new(c), h)
}

/// Initiator-side state kept between sending an initiation and consuming the
/// response. Zeroed on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct InitiatorState {
    pub chain: [u8; 32],
    pub hash: [u8; 32],
    pub e_priv: [u8; 32],
}

impl core::fmt::Debug for InitiatorState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("InitiatorState{..}")
    }
}

/// Result of consuming a valid initiation on the responder side. Contains
/// everything needed either to answer immediately (known peer) or to decide
/// the initiation must be parked for resolution (unknown static key).
pub struct ConsumedInitiation {
    pub chain: [u8; 32],
    pub hash: [u8; 32],
    /// The initiator's ephemeral public key.
    pub e_pub_i: [u8; 32],
    /// The initiator's **static** public key, recovered from the message.
    pub s_pub_i: [u8; 32],
    /// The TAI64N anti-replay timestamp (§5.1).
    pub timestamp: [u8; TIMESTAMP_LEN],
    /// The initiator's chosen sender index `Iᵢ`.
    pub sender: u32,
}

impl Drop for ConsumedInitiation {
    fn drop(&mut self) {
        self.chain.zeroize();
        self.hash.zeroize();
    }
}

impl core::fmt::Debug for ConsumedInitiation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ConsumedInitiation{..}")
    }
}

/// Transport key pair produced by a completed handshake (§5.4.5).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TransportKeys {
    pub send: [u8; 32],
    pub recv: [u8; 32],
}

impl core::fmt::Debug for TransportKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TransportKeys{..}")
    }
}

/// Build a handshake initiation (§5.4.2) into `msg` (which must be
/// `INITIATION_LEN` bytes). `sender` is the local index `Iᵢ`; `timestamp` the
/// monotonic TAI64N value. `mac1`/`mac2` are left zeroed for the cookie
/// layer. Returns the state to keep for [`consume_response`].
pub fn create_initiation<R: rand_core::RngCore + rand_core::CryptoRng>(
    rng: &mut R,
    s_priv_i: &[u8; 32],
    s_pub_i: &[u8; 32],
    s_pub_r: &[u8; 32],
    sender: u32,
    timestamp: &[u8; TIMESTAMP_LEN],
    msg: &mut [u8],
) -> Result<InitiatorState, Error> {
    if msg.len() != INITIATION_LEN {
        return Err(Error::BufferTooSmall);
    }
    let (mut c, mut h) = prologue();
    h = hash(&[&h, s_pub_r]);

    let (e_priv, e_pub) = dh_generate(rng);
    c = kdf1(&c, &e_pub)?;

    messages::write_type(msg, messages::MSG_INITIATION)?;
    field_mut(msg, messages::init::SENDER).copy_from_slice(&sender.to_le_bytes());
    field_mut(msg, messages::init::EPHEMERAL).copy_from_slice(&e_pub);
    h = hash(&[&h, &e_pub]);

    // msg.static := Aead(κ, 0, Sᵖᵘᵇᵢ, Hᵢ)
    let (c2, k) = kdf2(&c, &dh(&e_priv, s_pub_r)?[..])?;
    c = c2;
    {
        let out = field_mut(msg, messages::init::STATIC);
        out[..32].copy_from_slice(s_pub_i);
        aead_seal(&k, 0, out, 32, &h)?;
    }
    h = hash(&[&h, field(msg, messages::init::STATIC)]);

    // msg.timestamp := Aead(κ, 0, Timestamp(), Hᵢ)
    let (c3, k) = kdf2(&c, &dh(s_priv_i, s_pub_r)?[..])?;
    c = c3;
    {
        let out = field_mut(msg, messages::init::TIMESTAMP);
        out[..TIMESTAMP_LEN].copy_from_slice(timestamp);
        aead_seal(&k, 0, out, TIMESTAMP_LEN, &h)?;
    }
    h = hash(&[&h, field(msg, messages::init::TIMESTAMP)]);

    // mac1/mac2 zeroed; filled in by the cookie layer.
    field_mut(msg, messages::init::MAC1).fill(0);
    field_mut(msg, messages::init::MAC2).fill(0);

    Ok(InitiatorState {
        chain: *c,
        hash: h,
        e_priv: *e_priv,
    })
}

/// State recovered after the first responder DH and static-key AEAD.
///
/// At this point the initiator has named a static identity, but has not yet
/// proved possession of that identity's private key. Callers may use the key
/// for a read-only peer lookup, but must not mutate peer state or allocate
/// resolver state until [`authenticate_identified_initiation`] succeeds.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct IdentifiedInitiation {
    chain: [u8; 32],
    hash: [u8; 32],
    e_pub_i: [u8; 32],
    s_pub_i: [u8; 32],
    encrypted_timestamp: [u8; TIMESTAMP_LEN + crate::crypto::TAG_LEN],
    sender: u32,
}

impl IdentifiedInitiation {
    pub fn static_key(&self) -> &[u8; 32] {
        &self.s_pub_i
    }
}

impl core::fmt::Debug for IdentifiedInitiation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("IdentifiedInitiation{..}")
    }
}

/// Recover the initiator's claimed static identity, stopping before the
/// static-static DH. This mirrors wireguard-go's lookup point and allows the
/// caller to reject or budget unknown identities before doing the second DH.
pub fn identify_initiation(
    s_priv_r: &[u8; 32],
    s_pub_r: &[u8; 32],
    msg: &[u8],
) -> Result<IdentifiedInitiation, Error> {
    if msg.len() != INITIATION_LEN {
        return Err(Error::Crypto);
    }
    let (mut c, mut h) = prologue();
    h = hash(&[&h, s_pub_r]);

    let mut e_pub_i = [0u8; 32];
    e_pub_i.copy_from_slice(field(msg, messages::init::EPHEMERAL));
    c = kdf1(&c, &e_pub_i)?;
    h = hash(&[&h, &e_pub_i]);

    let (c2, k) = kdf2(&c, &dh(s_priv_r, &e_pub_i)?[..])?;
    c = c2;
    let mut static_buf = [0u8; 32 + crate::crypto::TAG_LEN];
    static_buf.copy_from_slice(field(msg, messages::init::STATIC));
    aead_open(&k, 0, &mut static_buf, &h)?;
    let mut s_pub_i = [0u8; 32];
    s_pub_i.copy_from_slice(&static_buf[..32]);
    h = hash(&[&h, field(msg, messages::init::STATIC)]);

    let mut encrypted_timestamp = [0u8; TIMESTAMP_LEN + crate::crypto::TAG_LEN];
    encrypted_timestamp.copy_from_slice(field(msg, messages::init::TIMESTAMP));
    let sender = field(msg, messages::init::SENDER);
    let sender = u32::from_le_bytes([sender[0], sender[1], sender[2], sender[3]]);

    Ok(IdentifiedInitiation {
        chain: *c,
        hash: h,
        e_pub_i,
        s_pub_i,
        encrypted_timestamp,
        sender,
    })
}

/// Complete authentication of an identified initiation. Successful timestamp
/// decryption proves possession of the claimed static private key.
pub fn authenticate_identified_initiation(
    s_priv_r: &[u8; 32],
    identified: IdentifiedInitiation,
) -> Result<ConsumedInitiation, Error> {
    let shared = dh(s_priv_r, identified.static_key())?;
    authenticate_identified_with_shared_secret(identified, &shared)
}

/// Complete authentication using a peer's precomputed static-static secret.
/// Known peers use this path to avoid an attacker repeatedly triggering X25519.
pub fn authenticate_identified_with_shared_secret(
    identified: IdentifiedInitiation,
    shared: &[u8; 32],
) -> Result<ConsumedInitiation, Error> {
    let chain = identified.chain;
    let hash_before_timestamp = identified.hash;
    let e_pub_i = identified.e_pub_i;
    let s_pub_i = identified.s_pub_i;
    let sender = identified.sender;
    let ciphertext = identified.encrypted_timestamp;

    let (c, k) = kdf2(&chain, shared)?;
    let mut ts_buf = ciphertext;
    aead_open(&k, 0, &mut ts_buf, &hash_before_timestamp)?;
    let mut timestamp = [0u8; TIMESTAMP_LEN];
    timestamp.copy_from_slice(&ts_buf[..TIMESTAMP_LEN]);
    let hash = hash(&[&hash_before_timestamp, &ciphertext]);

    Ok(ConsumedInitiation {
        chain: *c,
        hash,
        e_pub_i,
        s_pub_i,
        timestamp,
        sender,
    })
}

/// Consume a handshake initiation on the responder side (§5.4.2, mirrored).
/// The engine always uses the staged pair — [`identify_initiation`] then
/// [`authenticate_identified_initiation`] — so this one-shot convenience
/// exists only for tests that don't care about staged admission.
#[cfg(test)]
pub fn consume_initiation(
    s_priv_r: &[u8; 32],
    s_pub_r: &[u8; 32],
    msg: &[u8],
) -> Result<ConsumedInitiation, Error> {
    let identified = identify_initiation(s_priv_r, s_pub_r, msg)?;
    authenticate_identified_initiation(s_priv_r, identified)
}

/// Build the handshake response (§5.4.3) into `msg` (`RESPONSE_LEN` bytes)
/// and derive transport keys (§5.4.5) for the **responder** side
/// (`send = τ₂`, `recv = τ₁`). `mac1`/`mac2` are left zeroed.
pub fn create_response<R: rand_core::RngCore + rand_core::CryptoRng>(
    rng: &mut R,
    consumed: &ConsumedInitiation,
    sender: u32,
    msg: &mut [u8],
) -> Result<TransportKeys, Error> {
    if msg.len() != RESPONSE_LEN {
        return Err(Error::BufferTooSmall);
    }
    let mut c = Zeroizing::new(consumed.chain);
    let mut h = consumed.hash;

    let (e_priv_r, e_pub_r) = dh_generate(rng);
    c = kdf1(&c, &e_pub_r)?;

    messages::write_type(msg, messages::MSG_RESPONSE)?;
    field_mut(msg, messages::resp::SENDER).copy_from_slice(&sender.to_le_bytes());
    field_mut(msg, messages::resp::RECEIVER).copy_from_slice(&consumed.sender.to_le_bytes());
    field_mut(msg, messages::resp::EPHEMERAL).copy_from_slice(&e_pub_r);
    h = hash(&[&h, &e_pub_r]);

    c = kdf1(&c, &dh(&e_priv_r, &consumed.e_pub_i)?[..])?;
    c = kdf1(&c, &dh(&e_priv_r, &consumed.s_pub_i)?[..])?;

    let (c2, tau, k) = kdf3(&c, &PSK_Q)?;
    c = c2;
    h = hash(&[&h, &tau[..]]);

    // msg.empty := Aead(κ, 0, ε, Hᵣ) — a bare 16-byte tag.
    {
        let out = field_mut(msg, messages::resp::EMPTY);
        aead_seal(&k, 0, out, 0, &h)?;
    }
    h = hash(&[&h, field(msg, messages::resp::EMPTY)]);
    let _ = h; // Hᵢ=Hᵣ is retained by the spec for future Noise revisions; we drop it.

    field_mut(msg, messages::resp::MAC1).fill(0);
    field_mut(msg, messages::resp::MAC2).fill(0);

    // (T_send_i = T_recv_r, T_recv_i = T_send_r) := Kdf₂(C, ε)
    let (t1, t2) = kdf2(&c, b"")?;
    Ok(TransportKeys {
        send: *t2,
        recv: *t1,
    })
}

/// Consume a handshake response on the initiator side (§5.4.3 mirrored) and
/// derive transport keys for the **initiator** (`send = τ₁`, `recv = τ₂`).
pub fn consume_response(
    state: &InitiatorState,
    s_priv_i: &[u8; 32],
    msg: &[u8],
) -> Result<(TransportKeys, u32), Error> {
    if msg.len() != RESPONSE_LEN {
        return Err(Error::Crypto);
    }
    let mut c = Zeroizing::new(state.chain);
    let mut h = state.hash;

    let mut e_pub_r = [0u8; 32];
    e_pub_r.copy_from_slice(field(msg, messages::resp::EPHEMERAL));
    c = kdf1(&c, &e_pub_r)?;
    h = hash(&[&h, &e_pub_r]);

    c = kdf1(&c, &dh(&state.e_priv, &e_pub_r)?[..])?;
    c = kdf1(&c, &dh(s_priv_i, &e_pub_r)?[..])?;

    let (c2, tau, k) = kdf3(&c, &PSK_Q)?;
    c = c2;
    h = hash(&[&h, &tau[..]]);

    let mut empty = [0u8; crate::crypto::TAG_LEN];
    empty.copy_from_slice(field(msg, messages::resp::EMPTY));
    aead_open(&k, 0, &mut empty, &h)?;
    h = hash(&[&h, field(msg, messages::resp::EMPTY)]);
    let _ = h; // Complete the Noise transcript; transport keys are derived from C.

    let (t1, t2) = kdf2(&c, b"")?;
    let responder_index = field(msg, messages::resp::SENDER);
    let responder_index = u32::from_le_bytes([
        responder_index[0],
        responder_index[1],
        responder_index[2],
        responder_index[3],
    ]);
    Ok((
        TransportKeys {
            send: *t1,
            recv: *t2,
        },
        responder_index,
    ))
}

#[cfg(test)]
mod tests {
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::*;
    use crate::crypto::{dh as crypto_dh, tai64n};

    fn rng(seed: u8) -> ChaCha20Rng {
        ChaCha20Rng::from_seed([seed; 32])
    }

    fn keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
        let (private, public) = crate::crypto::dh_generate(&mut rng(seed));
        (*private, public)
    }

    const INITIATOR_INDEX: u32 = 0x1111_2222;
    const RESPONDER_INDEX: u32 = 0x3333_4444;

    fn timestamp() -> [u8; TIMESTAMP_LEN] {
        tai64n(1_700_000_000, 12_345).expect("representable")
    }

    fn initiation(
        s_priv_i: &[u8; 32],
        s_pub_i: &[u8; 32],
        s_pub_r: &[u8; 32],
    ) -> (InitiatorState, [u8; INITIATION_LEN]) {
        let mut msg = [0u8; INITIATION_LEN];
        let state = create_initiation(
            &mut rng(77),
            s_priv_i,
            s_pub_i,
            s_pub_r,
            INITIATOR_INDEX,
            &timestamp(),
            &mut msg,
        )
        .expect("initiation");
        (state, msg)
    }

    #[test]
    fn a_full_handshake_derives_mirrored_transport_keys() {
        let (s_priv_i, s_pub_i) = keypair(1);
        let (s_priv_r, s_pub_r) = keypair(2);

        let (state, msg) = initiation(&s_priv_i, &s_pub_i, &s_pub_r);
        assert_eq!(msg[0], messages::MSG_INITIATION);
        // The cookie layer owns the trailing MACs, so the Noise code leaves
        // them zeroed rather than half-filled.
        assert_eq!(&msg[messages::init::MAC1], &[0u8; 16]);
        assert_eq!(&msg[messages::init::MAC2], &[0u8; 16]);
        // The initiator's static key is encrypted, never sent in the clear.
        assert!(
            !msg.windows(32).any(|window| window == s_pub_i),
            "the static identity must not appear on the wire"
        );

        let consumed = consume_initiation(&s_priv_r, &s_pub_r, &msg).expect("consume");
        assert_eq!(
            consumed.s_pub_i, s_pub_i,
            "the responder recovers the identity"
        );
        assert_eq!(consumed.timestamp, timestamp());
        assert_eq!(consumed.sender, INITIATOR_INDEX);

        let mut response = [0u8; RESPONSE_LEN];
        let responder_keys =
            create_response(&mut rng(78), &consumed, RESPONDER_INDEX, &mut response)
                .expect("response");
        assert_eq!(response[0], messages::MSG_RESPONSE);
        assert_eq!(&response[messages::resp::MAC1], &[0u8; 16]);
        assert_eq!(&response[messages::resp::MAC2], &[0u8; 16]);

        let (initiator_keys, remote_index) =
            consume_response(&state, &s_priv_i, &response).expect("consume response");

        // §5.4.5: each side's send key is the other's receive key, and the
        // pair is not symmetric — swapping them would decrypt nothing.
        assert_eq!(initiator_keys.send, responder_keys.recv);
        assert_eq!(initiator_keys.recv, responder_keys.send);
        assert_ne!(initiator_keys.send, initiator_keys.recv);
        assert_eq!(remote_index, RESPONDER_INDEX);
    }

    #[test]
    fn identification_stops_before_the_second_scalar_multiplication() {
        // The engine looks a peer up on the identity recovered here, then
        // decides whether to spend the static-static DH on it. Both
        // completion paths must therefore agree exactly.
        let (s_priv_i, s_pub_i) = keypair(1);
        let (s_priv_r, s_pub_r) = keypair(2);
        let (_, msg) = initiation(&s_priv_i, &s_pub_i, &s_pub_r);

        let identified = identify_initiation(&s_priv_r, &s_pub_r, &msg).expect("identify");
        assert_eq!(identified.static_key(), &s_pub_i);
        assert!(
            !format!("{identified:?}").contains("s_pub_i"),
            "staged handshake state must not render its contents"
        );

        let precomputed = crypto_dh(&s_priv_r, &s_pub_i).expect("static-static");
        let via_shared =
            authenticate_identified_with_shared_secret(identified, &precomputed).expect("auth");

        let identified = identify_initiation(&s_priv_r, &s_pub_r, &msg).expect("identify");
        let via_dh = authenticate_identified_initiation(&s_priv_r, identified).expect("auth");

        assert_eq!(via_shared.timestamp, via_dh.timestamp);
        assert_eq!(via_shared.s_pub_i, via_dh.s_pub_i);
        assert_eq!(via_shared.chain, via_dh.chain);
        assert_eq!(via_shared.hash, via_dh.hash);

        // A wrong precomputed secret fails at the timestamp AEAD, which is
        // exactly the proof-of-possession step.
        let identified = identify_initiation(&s_priv_r, &s_pub_r, &msg).expect("identify");
        assert!(
            authenticate_identified_with_shared_secret(identified, &[0x5a; 32]).is_err(),
            "a wrong static-static secret must not authenticate"
        );
    }

    #[test]
    fn an_initiation_is_rejected_by_the_wrong_responder_or_after_any_tampering() {
        let (s_priv_i, s_pub_i) = keypair(1);
        let (s_priv_r, s_pub_r) = keypair(2);
        let (wrong_priv, wrong_pub) = keypair(3);
        let (_, msg) = initiation(&s_priv_i, &s_pub_i, &s_pub_r);

        // The message is addressed to one responder: nobody else can even
        // recover the claimed identity from it.
        assert!(identify_initiation(&wrong_priv, &wrong_pub, &msg).is_err());
        // Mixing a right key with a wrong transcript fails too, because the
        // responder's public key is hashed into the transcript.
        assert!(identify_initiation(&s_priv_r, &wrong_pub, &msg).is_err());

        // Every authenticated field is covered: flipping a bit anywhere in the
        // transcript breaks either the static or the timestamp AEAD.
        for field in [
            messages::init::EPHEMERAL,
            messages::init::STATIC,
            messages::init::TIMESTAMP,
        ] {
            let mut tampered = msg;
            tampered[field.start] ^= 0x01;
            assert!(
                consume_initiation(&s_priv_r, &s_pub_r, &tampered).is_err(),
                "tampering at {} was not detected",
                field.start
            );
        }

        // Wrong lengths are refused before any cryptography runs.
        assert_eq!(
            identify_initiation(&s_priv_r, &s_pub_r, &msg[..INITIATION_LEN - 1]).err(),
            Some(Error::Crypto)
        );
        let mut long = msg.to_vec();
        long.push(0);
        assert_eq!(
            identify_initiation(&s_priv_r, &s_pub_r, &long).err(),
            Some(Error::Crypto)
        );
    }

    #[test]
    fn a_response_only_authenticates_against_the_ephemeral_generation_it_answers() {
        // §6.4 retransmission uses a fresh ephemeral in the same slot, so a
        // response to a stale generation must fail the AEAD and drop rather
        // than install keys nobody else holds.
        let (s_priv_i, s_pub_i) = keypair(1);
        let (s_priv_r, s_pub_r) = keypair(2);

        let (first_state, first_msg) = initiation(&s_priv_i, &s_pub_i, &s_pub_r);
        let mut second_msg = [0u8; INITIATION_LEN];
        let second_state = create_initiation(
            &mut rng(99),
            &s_priv_i,
            &s_pub_i,
            &s_pub_r,
            INITIATOR_INDEX,
            &timestamp(),
            &mut second_msg,
        )
        .expect("second initiation");

        let consumed = consume_initiation(&s_priv_r, &s_pub_r, &first_msg).expect("consume");
        let mut response = [0u8; RESPONSE_LEN];
        create_response(&mut rng(100), &consumed, RESPONDER_INDEX, &mut response)
            .expect("response");

        assert!(consume_response(&first_state, &s_priv_i, &response).is_ok());
        assert!(
            consume_response(&second_state, &s_priv_i, &response).is_err(),
            "a response to the previous generation must not authenticate"
        );

        // Tampering, wrong static key, and wrong length are all rejected.
        let mut tampered = response;
        tampered[messages::resp::EPHEMERAL.start] ^= 0x01;
        assert!(consume_response(&first_state, &s_priv_i, &tampered).is_err());
        let mut tampered = response;
        tampered[messages::resp::EMPTY.start] ^= 0x01;
        assert!(consume_response(&first_state, &s_priv_i, &tampered).is_err());
        let (other_priv, _) = keypair(4);
        assert!(consume_response(&first_state, &other_priv, &response).is_err());
        assert_eq!(
            consume_response(&first_state, &s_priv_i, &response[..RESPONSE_LEN - 1]).err(),
            Some(Error::Crypto)
        );
    }

    #[test]
    fn undersized_output_buffers_are_refused() {
        let (s_priv_i, s_pub_i) = keypair(1);
        let (_, s_pub_r) = keypair(2);
        let mut short = [0u8; INITIATION_LEN - 1];
        assert_eq!(
            create_initiation(
                &mut rng(1),
                &s_priv_i,
                &s_pub_i,
                &s_pub_r,
                0,
                &timestamp(),
                &mut short,
            )
            .err(),
            Some(Error::BufferTooSmall)
        );
    }
}
