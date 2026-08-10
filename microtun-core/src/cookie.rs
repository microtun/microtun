//! The cookie / DoS-mitigation layer (§5.3, §5.4.4, §5.4.7).
//!
//! * Every handshake message carries `mac1 = Mac(Hash(Label-Mac1 ‖ S_pub_receiver), msgα)`,
//!   always required, providing "stealth": you must know the responder's
//!   public key to elicit any reaction at all.
//! * Under load, the responder demands `mac2 = Mac(cookie, msgβ)` where the
//!   cookie is a MAC of the sender's IP:port under a secret `R` rotated every
//!   two minutes, transmitted encrypted inside a cookie reply message bound
//!   (via the AEAD AD field) to the `mac1` of the message that provoked it.

use core::net::SocketAddr;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    constants::COOKIE_REFRESH_TIME,
    crypto::{self, XNONCE_LEN, mac16, xaead_open, xaead_seal},
    error::Error,
    ip::unmap_socket_addr,
    messages::{self, COOKIE_REPLY_LEN},
    time::Instant,
};

const LABEL_MAC1: &[u8] = b"mac1----";
const LABEL_COOKIE: &[u8] = b"cookie--";

/// `Hash(Label-Mac1 ‖ S_pub)` — precomputable mac1 key for a given receiver.
pub fn mac1_key(s_pub_receiver: &[u8; 32]) -> [u8; 32] {
    crypto::hash(&[LABEL_MAC1, s_pub_receiver])
}

/// `Hash(Label-Cookie ‖ S_pub)` — precomputable cookie-reply AEAD key.
pub fn cookie_key(s_pub: &[u8; 32]) -> [u8; 32] {
    crypto::hash(&[LABEL_COOKIE, s_pub])
}

/// Serialize `Aₘ` = external IP source address ‖ UDP source port for the
/// cookie MAC. IPv4-mapped IPv6 is first reduced to native IPv4, then address
/// bytes are written in network order and the port big-endian.
fn addr_bytes(addr: &SocketAddr, out: &mut [u8; 18]) -> usize {
    match unmap_socket_addr(*addr) {
        SocketAddr::V4(v4) => {
            out[..4].copy_from_slice(&v4.ip().octets());
            out[4..6].copy_from_slice(&v4.port().to_be_bytes());
            6
        }
        SocketAddr::V6(v6) => {
            out[..16].copy_from_slice(&v6.ip().octets());
            out[16..18].copy_from_slice(&v6.port().to_be_bytes());
            18
        }
    }
}

/// Fill `mac1` (and `mac2` if a fresh cookie is available) on an outgoing
/// handshake message. `msg` must be a full initiation or response;
/// `peer_pub` is the *receiver's* static public key; `cookie` the most
/// recently received cookie for this peer with its receipt time (§5.4.4).
pub fn apply_macs(
    msg: &mut [u8],
    peer_pub: &[u8; 32],
    cookie: Option<&([u8; 16], Instant)>,
    now: Instant,
) -> Result<[u8; 16], Error> {
    let (alpha, mac1_r, beta, mac2_r) = match msg.first().copied() {
        Some(messages::MSG_INITIATION) if msg.len() == messages::INITIATION_LEN => (
            messages::init::ALPHA,
            messages::init::MAC1,
            messages::init::BETA,
            messages::init::MAC2,
        ),
        Some(messages::MSG_RESPONSE) if msg.len() == messages::RESPONSE_LEN => (
            messages::resp::ALPHA,
            messages::resp::MAC1,
            messages::resp::BETA,
            messages::resp::MAC2,
        ),
        _ => return Err(Error::Crypto),
    };
    let key = mac1_key(peer_pub);
    let m1 = mac16(&key, &[&msg[alpha]])?;
    msg[mac1_r].copy_from_slice(&m1);

    // mac2: latest cookie if younger than 120 s, else zeros (§5.4.4).
    match cookie {
        Some((c, received)) if now.saturating_since(*received) < COOKIE_REFRESH_TIME => {
            let m2 = mac16(c, &[&msg[beta]])?;
            msg[mac2_r].copy_from_slice(&m2);
        }
        _ => msg[mac2_r].fill(0),
    }
    Ok(m1)
}

/// Verify `mac1` on an inbound handshake message against our precomputed
/// `mac1_key`. Constant-time. Returns the message's mac1 bytes on success
/// (needed as AD if we answer with a cookie reply).
pub fn verify_mac1(msg: &[u8], our_mac1_key: &[u8; 32]) -> Option<[u8; 16]> {
    let (alpha, mac1_r) = match *msg.first()? {
        messages::MSG_INITIATION if msg.len() == messages::INITIATION_LEN => {
            (messages::init::ALPHA, messages::init::MAC1)
        }
        messages::MSG_RESPONSE if msg.len() == messages::RESPONSE_LEN => {
            (messages::resp::ALPHA, messages::resp::MAC1)
        }
        _ => return None,
    };
    let expect = mac16(our_mac1_key, &[msg.get(alpha)?]).ok()?;
    let received = msg.get(mac1_r)?;
    if crypto::mac_eq(&expect, received) {
        let mut out = [0u8; 16];
        out.copy_from_slice(received);
        Some(out)
    } else {
        None
    }
}

/// The responder's rotating cookie secret `R` (§5.4.7).
///
/// WireGuard's reference implementations keep exactly one active secret. Once
/// it reaches [`COOKIE_REFRESH_TIME`], it is replaced before deriving or
/// validating a cookie. The secret is explicitly zeroized both on rotation and
/// when this value is dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CookieSecret {
    current: [u8; 32],
    #[zeroize(skip)]
    rotated_at: Instant,
}

impl core::fmt::Debug for CookieSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CookieSecret{..}")
    }
}

impl CookieSecret {
    pub fn new<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R, now: Instant) -> Self {
        let mut current = [0u8; 32];
        rng.fill_bytes(&mut current);
        Self {
            current,
            rotated_at: now,
        }
    }

    /// Lazily rotate if the secret is older than two minutes.
    pub fn refresh<R: rand_core::RngCore + rand_core::CryptoRng>(
        &mut self,
        rng: &mut R,
        now: Instant,
    ) {
        if now.saturating_since(self.rotated_at) >= COOKIE_REFRESH_TIME {
            let mut next = [0u8; 32];
            rng.fill_bytes(&mut next);
            self.current.zeroize();
            core::mem::swap(&mut self.current, &mut next);
            next.zeroize();
            self.rotated_at = now;
        }
    }

    /// τ := Mac(R, Aₘ) — the cookie value for a source address, under the
    /// current secret.
    pub fn cookie_for(&self, src: &SocketAddr) -> Result<[u8; 16], Error> {
        let mut buf = [0u8; 18];
        let n = addr_bytes(src, &mut buf);
        mac16(&self.current, &[&buf[..n]])
    }

    /// Verify an inbound `mac2` against a cookie minted under the current
    /// secret.
    pub fn verify_mac2(&self, msg: &[u8], src: &SocketAddr) -> bool {
        let (beta, mac2_r) = match msg.first() {
            Some(&messages::MSG_INITIATION) if msg.len() == messages::INITIATION_LEN => {
                (messages::init::BETA, messages::init::MAC2)
            }
            Some(&messages::MSG_RESPONSE) if msg.len() == messages::RESPONSE_LEN => {
                (messages::resp::BETA, messages::resp::MAC2)
            }
            _ => return false,
        };
        let mut buf = [0u8; 18];
        let n = addr_bytes(src, &mut buf);
        let Some(addr) = buf.get(..n) else {
            return false;
        };
        let Ok(cookie) = mac16(&self.current, &[addr]) else {
            return false;
        };
        let Some(beta_bytes) = msg.get(beta) else {
            return false;
        };
        let Ok(expect) = mac16(&cookie, &[beta_bytes]) else {
            return false;
        };
        msg.get(mac2_r)
            .is_some_and(|received| crypto::mac_eq(&expect, received))
    }
}

/// Build a cookie reply (§5.4.7) for a message that carried a valid `mac1`
/// (`provoking_mac1`) from `src`, addressed to that message's sender index.
pub fn create_cookie_reply<R: rand_core::RngCore + rand_core::CryptoRng>(
    rng: &mut R,
    secret: &CookieSecret,
    our_cookie_key: &[u8; 32],
    receiver: u32,
    src: &SocketAddr,
    provoking_mac1: &[u8; 16],
    msg: &mut [u8],
) -> Result<(), Error> {
    if msg.len() != COOKIE_REPLY_LEN {
        return Err(Error::BufferTooSmall);
    }
    messages::write_type(msg, messages::MSG_COOKIE_REPLY)?;
    msg[messages::cookie::RECEIVER].copy_from_slice(&receiver.to_le_bytes());

    let mut nonce = [0u8; XNONCE_LEN];
    rng.fill_bytes(&mut nonce);
    msg[messages::cookie::NONCE].copy_from_slice(&nonce);

    let tau = secret.cookie_for(src)?;
    let out = &mut msg[messages::cookie::COOKIE];
    out[..16].copy_from_slice(&tau);
    xaead_seal(our_cookie_key, &nonce, out, 16, provoking_mac1)?;
    Ok(())
}

/// Consume a cookie reply we received: decrypt with
/// `Hash(Label-Cookie ‖ S_pub_peer)` using the `mac1` of the handshake
/// message we last sent as AD (this binding is what stops third parties from
/// feeding us fraudulent cookies — §5.3, problem three). Returns the cookie.
pub fn consume_cookie_reply(
    peer_pub: &[u8; 32],
    last_sent_mac1: &[u8; 16],
    msg: &[u8],
) -> Result<[u8; 16], Error> {
    if msg.len() != COOKIE_REPLY_LEN {
        return Err(Error::Crypto);
    }
    let mut nonce = [0u8; XNONCE_LEN];
    nonce.copy_from_slice(&msg[messages::cookie::NONCE]);
    let mut buf = [0u8; 16 + crypto::TAG_LEN];
    buf.copy_from_slice(&msg[messages::cookie::COOKIE]);
    let key = cookie_key(peer_pub);
    xaead_open(&key, &nonce, &mut buf, last_sent_mac1)?;
    let mut cookie = [0u8; 16];
    cookie.copy_from_slice(&buf[..16]);
    Ok(cookie)
}

#[cfg(test)]
mod tests {
    use core::net::{IpAddr, Ipv4Addr, SocketAddr};

    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::*;
    use crate::{
        messages::{INITIATION_LEN, RESPONSE_LEN},
        time::Duration,
    };

    /// A fixed instant well away from zero, so a saturated-to-zero deadline
    /// can never be mistaken for a correct one.
    const T0: Instant = Instant::from_millis(1_000_000);

    fn rng(seed: u8) -> ChaCha20Rng {
        ChaCha20Rng::from_seed([seed; 32])
    }

    fn keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
        let (private, public) = crate::crypto::dh_generate(&mut rng(seed));
        (*private, public)
    }

    /// An outer (physical network) address.
    fn outer(last: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, last)), 51820)
    }

    const SENDER: u32 = 0xdead_beef;

    /// A syntactically valid handshake message. The cookie layer works over
    /// the message bytes and never inspects the Noise fields, so real
    /// handshake content would only make these tests slower.
    fn handshake(message_type: u8) -> Vec<u8> {
        let len = if message_type == messages::MSG_INITIATION {
            INITIATION_LEN
        } else {
            RESPONSE_LEN
        };
        let mut msg = vec![0xa5u8; len];
        msg[0] = message_type;
        msg[1..4].fill(0);
        msg[messages::init::SENDER.start..messages::init::SENDER.end]
            .copy_from_slice(&SENDER.to_le_bytes());
        msg
    }

    #[test]
    fn mac1_proves_the_sender_knows_who_it_is_talking_to() {
        // §5.3 "stealth": without the receiver's public key you cannot elicit
        // any reaction at all, so the key is per-receiver and mac1 is checked
        // before anything expensive happens.
        let (_, responder) = keypair(1);
        let (_, other) = keypair(2);
        assert_ne!(mac1_key(&responder), mac1_key(&other));
        assert_eq!(mac1_key(&responder), mac1_key(&responder));
        assert_ne!(mac1_key(&responder), cookie_key(&responder));

        for message_type in [messages::MSG_INITIATION, messages::MSG_RESPONSE] {
            let mut msg = handshake(message_type);
            let mac1 = apply_macs(&mut msg, &responder, None, T0).expect("macs");

            let (alpha, mac1_range, mac2_range) = if message_type == messages::MSG_INITIATION {
                (
                    messages::init::ALPHA,
                    messages::init::MAC1,
                    messages::init::MAC2,
                )
            } else {
                (
                    messages::resp::ALPHA,
                    messages::resp::MAC1,
                    messages::resp::MAC2,
                )
            };
            assert_eq!(&msg[mac1_range.clone()], &mac1[..]);
            assert_eq!(
                &msg[mac2_range],
                &[0u8; 16][..],
                "mac2 stays zero until a cookie is known"
            );

            assert_eq!(verify_mac1(&msg, &mac1_key(&responder)), Some(mac1));
            assert_eq!(
                verify_mac1(&msg, &mac1_key(&other)),
                None,
                "another device must not accept this message"
            );

            // mac1 covers every byte before it, so tampering anywhere in the
            // handshake body is caught here rather than later.
            let mut tampered = msg.clone();
            tampered[alpha.end - 1] ^= 0x01;
            assert_eq!(verify_mac1(&tampered, &mac1_key(&responder)), None);
            let mut forged = msg.clone();
            forged[mac1_range.start] ^= 0x01;
            assert_eq!(verify_mac1(&forged, &mac1_key(&responder)), None);
        }

        // Anything that is not a well-formed handshake message is refused by
        // both sides of the layer.
        let mut wrong_length = handshake(messages::MSG_INITIATION);
        wrong_length.pop();
        assert_eq!(
            apply_macs(&mut wrong_length, &responder, None, T0),
            Err(Error::Crypto)
        );
        assert_eq!(verify_mac1(&wrong_length, &mac1_key(&responder)), None);
        let mut wrong_type = handshake(messages::MSG_INITIATION);
        wrong_type[0] = messages::MSG_DATA;
        assert_eq!(
            apply_macs(&mut wrong_type, &responder, None, T0),
            Err(Error::Crypto)
        );
        assert_eq!(verify_mac1(&wrong_type, &mac1_key(&responder)), None);
        assert_eq!(verify_mac1(&[], &mac1_key(&responder)), None);
    }

    #[test]
    fn a_cookie_challenge_binds_the_sender_to_its_own_source_address() {
        let (_, responder) = keypair(3);
        let secret = CookieSecret::new(&mut rng(4), T0);
        let src = outer(7);

        let mut msg = handshake(messages::MSG_INITIATION);
        let mac1 = apply_macs(&mut msg, &responder, None, T0).expect("macs");
        assert!(
            !secret.verify_mac2(&msg, &src),
            "an unchallenged message carries no mac2"
        );

        // The reply is addressed to the message's sender index and encrypted
        // under the responder's cookie key.
        let mut reply = [0u8; COOKIE_REPLY_LEN];
        create_cookie_reply(
            &mut rng(5),
            &secret,
            &cookie_key(&responder),
            SENDER,
            &src,
            &mac1,
            &mut reply,
        )
        .expect("reply");
        assert_eq!(reply[0], messages::MSG_COOKIE_REPLY);
        assert_eq!(
            crate::messages::read_u32_le(&reply[messages::cookie::RECEIVER]),
            Some(SENDER)
        );

        let cookie = consume_cookie_reply(&responder, &mac1, &reply).expect("cookie");
        assert_eq!(
            cookie,
            secret.cookie_for(&src).expect("cookie"),
            "the recovered cookie is the one minted for this source"
        );

        // Armed with the cookie, the retransmission satisfies the challenge —
        // but only from the address the cookie was minted for, which is the
        // whole point: it proves the sender owns its source address.
        let mut retransmission = handshake(messages::MSG_INITIATION);
        apply_macs(&mut retransmission, &responder, Some(&(cookie, T0)), T0).expect("macs");
        assert_ne!(&retransmission[messages::init::MAC2], &[0u8; 16][..]);
        assert!(secret.verify_mac2(&retransmission, &src));
        assert!(!secret.verify_mac2(&retransmission, &outer(8)));
        assert!(
            !secret.verify_mac2(&retransmission, &SocketAddr::new(src.ip(), 9999)),
            "the cookie covers the port as well as the address"
        );

        // mac2 covers mac1, so a message cannot be re-macced with a stolen
        // mac2 from another handshake.
        let mut spliced = handshake(messages::MSG_INITIATION);
        spliced[100] ^= 0x01;
        apply_macs(&mut spliced, &responder, None, T0).expect("macs");
        spliced[messages::init::MAC2].copy_from_slice(&retransmission[messages::init::MAC2]);
        assert!(!secret.verify_mac2(&spliced, &src));
    }

    #[test]
    fn a_cookie_reply_is_bound_to_the_message_that_provoked_it() {
        // §5.3 problem three: without this binding a third party could feed us
        // fraudulent cookies and stop us ever satisfying a challenge.
        let (_, responder) = keypair(6);
        let (_, impostor) = keypair(7);
        let secret = CookieSecret::new(&mut rng(8), T0);
        let src = outer(7);

        let mut msg = handshake(messages::MSG_INITIATION);
        let mac1 = apply_macs(&mut msg, &responder, None, T0).expect("macs");
        let mut reply = [0u8; COOKIE_REPLY_LEN];
        create_cookie_reply(
            &mut rng(9),
            &secret,
            &cookie_key(&responder),
            SENDER,
            &src,
            &mac1,
            &mut reply,
        )
        .expect("reply");

        assert!(consume_cookie_reply(&responder, &mac1, &reply).is_ok());
        // A different mac1 means this reply answers a message we did not send.
        let mut other_mac1 = mac1;
        other_mac1[0] ^= 0x01;
        assert_eq!(
            consume_cookie_reply(&responder, &other_mac1, &reply).err(),
            Some(Error::Crypto)
        );
        // A reply that did not come from the peer we challenged.
        assert_eq!(
            consume_cookie_reply(&impostor, &mac1, &reply).err(),
            Some(Error::Crypto)
        );
        // Tampering with the nonce or the ciphertext.
        for index in [
            messages::cookie::NONCE.start,
            messages::cookie::COOKIE.start,
        ] {
            let mut tampered = reply;
            tampered[index] ^= 0x01;
            assert_eq!(
                consume_cookie_reply(&responder, &mac1, &tampered).err(),
                Some(Error::Crypto)
            );
        }
        assert_eq!(
            consume_cookie_reply(&responder, &mac1, &reply[..COOKIE_REPLY_LEN - 1]).err(),
            Some(Error::Crypto)
        );

        // Each reply uses a fresh random nonce, so two challenges for the same
        // source do not produce identical bytes.
        let mut again = [0u8; COOKIE_REPLY_LEN];
        create_cookie_reply(
            &mut rng(10),
            &secret,
            &cookie_key(&responder),
            SENDER,
            &src,
            &mac1,
            &mut again,
        )
        .expect("reply");
        assert_ne!(reply, again);
        assert_eq!(
            consume_cookie_reply(&responder, &mac1, &again).expect("cookie"),
            consume_cookie_reply(&responder, &mac1, &reply).expect("cookie"),
            "but both carry the same cookie"
        );

        let mut short = [0u8; COOKIE_REPLY_LEN - 1];
        assert_eq!(
            create_cookie_reply(
                &mut rng(11),
                &secret,
                &cookie_key(&responder),
                SENDER,
                &src,
                &mac1,
                &mut short,
            ),
            Err(Error::BufferTooSmall)
        );
    }

    #[test]
    fn cookies_expire_on_both_sides_after_two_minutes() {
        let (_, responder) = keypair(12);
        let mut secret = CookieSecret::new(&mut rng(13), T0);
        let src = outer(7);
        let cookie = secret.cookie_for(&src).expect("cookie");

        // Sender side (§5.4.4): a cookie older than Cookie-Refresh-Time is not
        // used, and mac2 goes back to zeros rather than carrying a stale value
        // the responder would reject anyway.
        let mut fresh = handshake(messages::MSG_INITIATION);
        let received = T0;
        apply_macs(
            &mut fresh,
            &responder,
            Some(&(cookie, received)),
            received + (COOKIE_REFRESH_TIME - Duration::from_millis(1)),
        )
        .expect("macs");
        assert_ne!(&fresh[messages::init::MAC2], &[0u8; 16][..]);

        let mut stale = handshake(messages::MSG_INITIATION);
        apply_macs(
            &mut stale,
            &responder,
            Some(&(cookie, received)),
            received + COOKIE_REFRESH_TIME,
        )
        .expect("macs");
        assert_eq!(&stale[messages::init::MAC2], &[0u8; 16][..]);

        // Receiver side (§5.4.7): the secret R rotates on the same schedule,
        // and rotating invalidates every cookie minted under the old one.
        secret.refresh(
            &mut rng(14),
            T0 + (COOKIE_REFRESH_TIME - Duration::from_millis(1)),
        );
        assert_eq!(secret.cookie_for(&src).expect("cookie"), cookie);
        secret.refresh(&mut rng(14), T0 + COOKIE_REFRESH_TIME);
        assert_ne!(secret.cookie_for(&src).expect("cookie"), cookie);
        assert!(!secret.verify_mac2(&fresh, &src));

        // The secret never renders itself.
        assert_eq!(format!("{secret:?}"), "CookieSecret{..}");
    }

    #[test]
    fn a_source_address_has_exactly_one_cookie_whatever_its_spelling() {
        // The cookie is a MAC over the serialised source address, so two
        // spellings of one address would be two identities and an initiator
        // could be challenged forever.
        let secret = CookieSecret::new(&mut rng(15), T0);
        let native = Ipv4Addr::new(203, 0, 113, 2);
        let mapped = SocketAddr::new(IpAddr::V6(native.to_ipv6_mapped()), 51820);
        assert_eq!(
            secret.cookie_for(&mapped).expect("cookie"),
            secret.cookie_for(&outer(2)).expect("cookie")
        );

        // Distinct addresses, ports and families all get distinct cookies.
        assert_ne!(
            secret.cookie_for(&outer(2)).expect("cookie"),
            secret.cookie_for(&outer(3)).expect("cookie")
        );
        assert_ne!(
            secret.cookie_for(&outer(2)).expect("cookie"),
            secret
                .cookie_for(&SocketAddr::new(IpAddr::V4(native), 9999))
                .expect("cookie")
        );
        let v6 = SocketAddr::new(
            IpAddr::V6(core::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            51820,
        );
        assert_ne!(
            secret.cookie_for(&v6).expect("cookie"),
            secret.cookie_for(&outer(2)).expect("cookie")
        );
    }
}
