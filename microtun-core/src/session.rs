//! Established secure sessions (§5.4.5, §5.4.6, §6.2).

use zeroize::Zeroize;

use crate::{
    constants::{REJECT_AFTER_MESSAGES, REJECT_AFTER_TIME, REKEY_AFTER_TIME},
    noise::TransportKeys,
    replay::ReplayWindow,
    time::{Duration, Instant},
};

/// Handle into the session slot pool.
///
/// The companion of [`crate::routing::PeerIdx`], and wide for the same
/// reason: slot handles are stored in the peer table, in the session-index
/// map, and in resolver bookkeeping, and every one of those uses is cast to
/// `usize` on the way to an array. [`crate::Core::new`] rejects any
/// `MAX_SESSIONS` this type cannot address.
pub type SlotIdx = u32;

/// Which side of the handshake created this session — the initiator carries
/// the time-based rekey duties (§6.2, thundering-herd avoidance).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

/// A live secure session: one symmetric key pair plus counters.
pub struct Session<const REPLAY_WORDS: usize> {
    /// Index of the owning peer in the peer table (backlink for O(1)
    /// slot→peer resolution on the receive path).
    pub peer: crate::routing::PeerIdx,
    pub t_send: [u8; 32],
    pub t_recv: [u8; 32],
    /// `N_send` — next transport counter to use.
    pub n_send: u64,
    /// Receive-side anti-replay window (tracks `N_recv`).
    pub replay: ReplayWindow<REPLAY_WORDS>,
    /// Our receiver index, carried on the wire so incoming packets can find
    /// this session.
    pub local_index: u32,
    /// The peer's receiver index we must address them by.
    pub remote_index: u32,
    pub role: Role,
    /// Session age is measured from transport-key derivation (§6.1).
    pub created: Instant,
    /// Session age at which the initiator begins a rekey.
    ///
    /// Per-session rather than the bare [`REKEY_AFTER_TIME`] constant so a
    /// fleet that established every one of its sessions inside the same
    /// second does not then rekey inside the same second forever. Sampled in
    /// `REKEY_AFTER_TIME - REKEY_AFTER_TIME_JITTER_MAX ..= REKEY_AFTER_TIME`
    /// by the core, which owns the CSPRNG; see
    /// [`crate::constants::REKEY_AFTER_TIME_JITTER_MAX`]. Defaults to the
    /// unjittered constant so a session built without an explicit value is
    /// never *less* conservative than the whitepaper requires.
    pub rekey_after: Duration,
    /// A responder session is unconfirmed ("next" slot, §6.3) until the
    /// first valid transport message arrives from the initiator.
    pub confirmed: bool,
    /// Set once we have triggered a rekey because of this session's age or
    /// message count, so we only do it once per session.
    pub rekey_triggered: bool,
}

impl<const REPLAY_WORDS: usize> core::fmt::Debug for Session<REPLAY_WORDS> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Session")
            .field("role", &self.role)
            .field("confirmed", &self.confirmed)
            .field("n_send", &self.n_send)
            .finish_non_exhaustive()
    }
}

impl<const REPLAY_WORDS: usize> Session<REPLAY_WORDS> {
    pub fn new(
        keys: TransportKeys,
        role: Role,
        local_index: u32,
        remote_index: u32,
        now: Instant,
    ) -> Self {
        Self {
            peer: 0,
            t_send: keys.send,
            t_recv: keys.recv,
            n_send: 0,
            replay: ReplayWindow::new(),
            local_index,
            remote_index,
            role,
            created: now,
            rekey_after: REKEY_AFTER_TIME,
            confirmed: role == Role::Initiator,
            rekey_triggered: false,
        }
    }

    /// Session age at which this session's initiator should rekey, clamped so
    /// a nonsensical override can never push the rekey past the point where
    /// the session is refused outright (§6.2).
    pub fn rekey_deadline(&self) -> Instant {
        let after = if self.rekey_after < REJECT_AFTER_TIME {
            self.rekey_after
        } else {
            REKEY_AFTER_TIME
        };
        self.created + after
    }

    /// §6.2: refuse to send or receive past `Reject-After-Time` or
    /// `Reject-After-Messages`.
    pub fn expired(&self, now: Instant) -> bool {
        now.saturating_since(self.created) >= REJECT_AFTER_TIME
            || self.n_send >= REJECT_AFTER_MESSAGES
    }

    /// May this session encrypt one more outgoing message right now?
    pub fn can_send(&self, now: Instant) -> bool {
        if self.expired(now) {
            return false;
        }
        // A responder must not send transport data until the initiator's
        // first transport message confirmed the session (§5.4.5).
        self.confirmed
    }

    /// Zero key material.
    pub fn wipe(&mut self) {
        self.t_send.zeroize();
        self.t_recv.zeroize();
    }
}

impl<const REPLAY_WORDS: usize> Drop for Session<REPLAY_WORDS> {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::Duration;

    /// A fixed instant well away from zero, so a saturated-to-zero deadline
    /// can never be mistaken for a correct one.
    const T0: Instant = Instant::from_millis(1_000_000);

    fn keys() -> TransportKeys {
        TransportKeys {
            send: [0x11; 32],
            recv: [0x22; 32],
        }
    }

    const REPLAY_WORDS: usize = 128;

    fn session(role: Role) -> Session<REPLAY_WORDS> {
        Session::new(keys(), role, 0xaaaa_bbbb, 0xcccc_dddd, T0)
    }

    #[test]
    fn only_the_initiator_may_send_before_the_session_is_confirmed() {
        // §5.4.5: a responder must not send transport data until the
        // initiator's first transport message confirms the session, because
        // until then it has no evidence the initiator ever received the
        // response.
        let responder = session(Role::Responder);
        assert!(!responder.confirmed);
        assert!(!responder.can_send(T0));

        let mut responder = responder;
        responder.confirmed = true;
        assert!(responder.can_send(T0));

        // The initiator, having derived the keys from a message it sent, is
        // confirmed from the start.
        let initiator = session(Role::Initiator);
        assert!(initiator.confirmed);
        assert!(initiator.can_send(T0));
    }

    #[test]
    fn sessions_expire_on_age_and_on_message_count_at_the_exact_boundary() {
        // §6.2. Both limits are inclusive: the constants name the first value
        // that is *rejected*, not the last one accepted.
        let mut s = session(Role::Initiator);

        let last_good = T0 + (REJECT_AFTER_TIME - Duration::from_millis(1));
        assert!(!s.expired(last_good));
        assert!(s.can_send(last_good));

        assert!(s.expired(T0 + REJECT_AFTER_TIME));
        assert!(!s.can_send(T0 + REJECT_AFTER_TIME));
        assert!(s.expired(T0 + REJECT_AFTER_TIME + Duration::from_secs(1)));

        s.n_send = REJECT_AFTER_MESSAGES - 1;
        assert!(!s.expired(T0));
        s.n_send = REJECT_AFTER_MESSAGES;
        assert!(s.expired(T0), "the message ceiling must bind on its own");
        assert!(!s.can_send(T0));
    }

    #[test]
    fn key_material_is_wiped_and_never_shown() {
        let mut s = session(Role::Initiator);
        // Debug output can end up in logs, so it must carry no key bytes.
        let rendered = format!("{s:?}");
        assert!(rendered.contains("Initiator"));
        assert!(!rendered.contains("17"), "rendered: {rendered}");
        assert!(!rendered.contains("t_send"), "rendered: {rendered}");

        s.wipe();
        assert_eq!(s.t_send, [0u8; 32]);
        assert_eq!(s.t_recv, [0u8; 32]);
    }
}
