//! Peer-owned WireGuard state.

use core::net::SocketAddr;

use zeroize::Zeroize;

use crate::{
    PeerAddresses,
    crypto::TIMESTAMP_LEN,
    error::Error,
    firewall::InboundPolicy,
    ip::unmap_socket_addr,
    session::SlotIdx,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeerKind {
    Pinned,
    Dynamic,
}

/// WireGuard session generations and their protocol timers for one peer.
///
/// Generation rotation, handshake installation, and slot cleanup are kept
/// here so callers cannot update only part of those transitions.
#[derive(Debug, Clone, Default)]
pub(crate) struct PeerSessions {
    pub(crate) current: Option<SlotIdx>,
    pub(crate) previous: Option<SlotIdx>,
    pub(crate) next: Option<SlotIdx>,
    pub(crate) handshake: Option<SlotIdx>,
    pub(crate) keepalive_due: Option<Instant>,
    pub(crate) persistent_keepalive_due: Option<Instant>,
    pub(crate) reply_due: Option<Instant>,
    pub(crate) attempt_deadline: Option<Instant>,
}

impl PeerSessions {
    pub(crate) fn slots(&self) -> [Option<SlotIdx>; 4] {
        [self.current, self.previous, self.next, self.handshake]
    }

    pub(crate) fn validate_responder_install(&self, sidx: SlotIdx) -> Result<(), Error> {
        if self.next.is_some() && self.next != Some(sidx) {
            return Err(Error::InternalInvariant);
        }
        Ok(())
    }

    pub(crate) fn commit_responder_install(&mut self, sidx: SlotIdx) {
        self.next = Some(sidx);
    }

    pub(crate) fn install_initiator(&mut self, sidx: SlotIdx) -> Result<Option<SlotIdx>, Error> {
        if self.handshake != Some(sidx) {
            return Err(Error::InternalInvariant);
        }
        self.handshake = None;
        self.attempt_deadline = None;
        Ok(self.rotate_current(sidx))
    }

    pub(crate) fn confirm_responder(&mut self, sidx: SlotIdx) -> Result<Option<SlotIdx>, Error> {
        if self.next != Some(sidx) {
            return Err(Error::InternalInvariant);
        }
        self.next = None;
        Ok(self.rotate_current(sidx))
    }

    pub(crate) fn begin_handshake(
        &mut self,
        sidx: SlotIdx,
        deadline: Instant,
    ) -> Result<(), Error> {
        if self.handshake.is_some() {
            return Err(Error::InternalInvariant);
        }
        self.handshake = Some(sidx);
        if self.attempt_deadline.is_none() {
            self.attempt_deadline = Some(deadline);
        }
        Ok(())
    }

    pub(crate) fn abort_handshake(&mut self) {
        self.handshake = None;
        self.attempt_deadline = None;
    }

    pub(crate) fn unlink(&mut self, sidx: SlotIdx) {
        if self.current == Some(sidx) {
            self.current = None;
        }
        if self.previous == Some(sidx) {
            self.previous = None;
        }
        if self.next == Some(sidx) {
            self.next = None;
        }
        if self.handshake == Some(sidx) {
            self.abort_handshake();
        }
    }

    fn rotate_current(&mut self, sidx: SlotIdx) -> Option<SlotIdx> {
        let old_previous = self.previous.take();
        self.previous = self.current.replace(sidx);
        old_previous
    }
}

#[derive(Clone)]
pub(crate) struct PeerEntry {
    pub(crate) public_key: [u8; 32],
    /// Precomputed X25519(local static, remote static), matching wireguard-go.
    pub(crate) precomputed_static_static: [u8; 32],
    pub(crate) kind: PeerKind,
    pub(crate) endpoint: Option<SocketAddr>,
    /// When `endpoint` was last set from *authenticated inbound traffic*
    /// (§2.1 roaming), as opposed to configuration or a resolver answer.
    ///
    /// Only a packet that passed the transport AEAD or the handshake proves
    /// the peer is reachable at the address it came from, so only those
    /// stamp this. It stays `None` for an endpoint that a resolver supplied
    /// and nothing has yet been heard from, which is what lets
    /// [`crate::Core`] tell a demonstrably live endpoint from a guess when
    /// the two disagree.
    pub(crate) endpoint_confirmed: Option<Instant>,
    /// Relay protocol: if set, packets for this peer are not sent to its
    /// endpoint but wrapped in a relay envelope and submitted to the peer
    /// (identified by static key) named here. The configured relay relation
    /// is the routing authority for outbound traffic (relay spec §9), so a
    /// learned `endpoint` is ignored while this is set.
    pub(crate) relay: Option<[u8; 32]>,
    /// Optional stateful ingress filtering supplied by either the pinned
    /// configuration or the trusted resolver record.
    pub(crate) inbound_policy: InboundPolicy,
    /// Configured WireGuard-style idle keepalive interval.
    pub(crate) persistent_keepalive: Option<Duration>,
    /// Last authoritative tunnel address set, used to make refreshes no-ops.
    pub(crate) addresses: PeerAddresses,
    pub(crate) greatest_ts: [u8; TIMESTAMP_LEN],
    /// Monotonic time at which the last authenticated initiation was accepted.
    /// Kept independently of cookie/rate limiting, as in wireguard-go.
    pub(crate) last_initiation_consumption: Option<Instant>,
    pub(crate) cookie: Option<([u8; 16], Instant)>,
    /// `mac1` of the most recent handshake message we sent to this peer —
    /// initiation *or* response.
    ///
    /// A cookie reply is bound, via its AEAD associated data, to the `mac1`
    /// of the message that provoked it (§5.4.7), so consuming one requires
    /// remembering that value. It lives on the peer rather than on the
    /// handshake slot because a responder's reply-provoking message leaves
    /// no `Initiating` slot behind: the slot goes straight to `Established`.
    /// Keying this off slot state would silently discard every challenge
    /// aimed at a response we sent, and the peer could then never learn a
    /// cookie to put in `mac2`.
    pub(crate) last_mac1: Option<[u8; 16]>,
    pub(crate) sessions: PeerSessions,
    /// Last unknown-destination resolver lookup accepted from this peer while
    /// it acted as an authenticated relay submitter.
    pub(crate) last_relay_resolve: Option<Instant>,
    pub(crate) last_activity: Instant,
}

impl PeerEntry {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        public_key: [u8; 32],
        kind: PeerKind,
        precomputed_static_static: [u8; 32],
        endpoint: Option<SocketAddr>,
        relay: Option<[u8; 32]>,
        inbound_policy: InboundPolicy,
        persistent_keepalive: Option<Duration>,
        addresses: PeerAddresses,
        now: Instant,
    ) -> Self {
        let persistent_keepalive =
            persistent_keepalive.filter(|interval| interval.as_millis() != 0);
        let persistent_keepalive_due = persistent_keepalive.map(|interval| now + interval);
        Self {
            public_key,
            precomputed_static_static,
            kind,
            endpoint: endpoint.map(unmap_socket_addr),
            // A configured or resolved endpoint is a claim, not evidence:
            // nothing has been heard from it yet.
            endpoint_confirmed: None,
            relay,
            inbound_policy,
            persistent_keepalive,
            addresses,
            greatest_ts: [0; TIMESTAMP_LEN],
            last_initiation_consumption: None,
            cookie: None,
            last_mac1: None,
            sessions: PeerSessions {
                persistent_keepalive_due,
                ..PeerSessions::default()
            },
            last_relay_resolve: None,
            last_activity: now,
        }
    }

    /// Apply an endpoint learned from authenticated inbound traffic.
    ///
    /// Returns `true` exactly when this observation is externally meaningful:
    /// the endpoint became authenticated for the first time, or it changed. A
    /// configured/resolved endpoint starts unconfirmed, so observing that exact
    /// same address still returns `true` once. Repeated authenticated traffic
    /// from an already-confirmed address is coalesced.
    pub(crate) fn observe_direct_endpoint(&mut self, endpoint: SocketAddr, now: Instant) -> bool {
        if self.relay.is_some() {
            return false;
        }

        let newly_observed = self.endpoint_confirmed.is_none() || self.endpoint != Some(endpoint);
        self.endpoint = Some(endpoint);
        self.endpoint_confirmed = Some(now);
        newly_observed
    }

    pub(crate) const fn is_pinned(&self) -> bool {
        matches!(self.kind, PeerKind::Pinned)
    }
}

impl core::fmt::Debug for PeerEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PeerEntry")
            .field("public_key", &self.public_key)
            .field("kind", &self.kind)
            .field("endpoint", &self.endpoint)
            .field("relay", &self.relay)
            .field("persistent_keepalive", &self.persistent_keepalive)
            .field("addresses", &self.addresses)
            .field("sessions", &self.sessions)
            .finish_non_exhaustive()
    }
}

impl Drop for PeerEntry {
    fn drop(&mut self) {
        self.precomputed_static_static.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PeerAddresses, time::Duration};

    /// A fixed instant well away from zero, so a saturated-to-zero deadline
    /// can never be mistaken for a correct one.
    const T0: Instant = Instant::from_millis(1_000_000);

    fn deadline() -> Instant {
        T0 + Duration::from_secs(90)
    }

    #[test]
    fn only_one_handshake_may_be_in_flight_per_peer() {
        let mut sessions = PeerSessions::default();
        assert!(sessions.handshake.is_none());

        sessions
            .begin_handshake(1, deadline())
            .expect("first attempt");
        assert_eq!(sessions.handshake, Some(1));
        assert_eq!(sessions.attempt_deadline, Some(deadline()));

        // A second concurrent attempt is a state-machine violation, not a
        // silently-replaced slot: the retransmission timer already owns the
        // one in flight.
        assert_eq!(
            sessions.begin_handshake(2, deadline()),
            Err(Error::InternalInvariant)
        );
        assert_eq!(sessions.handshake, Some(1), "the attempt must be untouched");

        // Retrying after an abort starts a fresh overall deadline; retrying
        // while one is already set must not extend it, or Rekey-Attempt-Time
        // would never be reached.
        sessions.abort_handshake();
        assert_eq!(sessions.handshake, None);
        assert_eq!(sessions.attempt_deadline, None);
        let later = deadline() + Duration::from_secs(30);
        sessions.begin_handshake(2, later).expect("retry");
        assert_eq!(sessions.attempt_deadline, Some(later));
        sessions.abort_handshake();
        sessions.attempt_deadline = Some(deadline());
        sessions.begin_handshake(3, later).expect("retry");
        assert_eq!(
            sessions.attempt_deadline,
            Some(deadline()),
            "an existing attempt deadline must not be pushed out"
        );
    }

    #[test]
    fn installing_an_initiator_session_rotates_current_into_previous() {
        let mut sessions = PeerSessions::default();

        // The transition validates its precondition before mutating anything.
        assert_eq!(
            sessions.install_initiator(7),
            Err(Error::InternalInvariant),
            "installing without a matching handshake must fail"
        );

        sessions.begin_handshake(1, deadline()).expect("handshake");
        assert_eq!(
            sessions.install_initiator(2),
            Err(Error::InternalInvariant),
            "installing the wrong slot must fail"
        );
        assert_eq!(sessions.handshake, Some(1));

        // First generation: nothing to displace.
        assert_eq!(sessions.install_initiator(1), Ok(None));
        assert_eq!(sessions.current, Some(1));
        assert_eq!(sessions.previous, None);
        assert_eq!(sessions.handshake, None);
        assert_eq!(
            sessions.attempt_deadline, None,
            "a completed handshake clears its overall deadline"
        );

        // Second: the old current becomes previous, and nothing is freed yet.
        sessions.begin_handshake(2, deadline()).expect("handshake");
        assert_eq!(sessions.install_initiator(2), Ok(None));
        assert_eq!((sessions.current, sessions.previous), (Some(2), Some(1)));

        // Third: only now does a slot fall out the back, and the caller is
        // handed it so it can be freed.
        sessions.begin_handshake(3, deadline()).expect("handshake");
        assert_eq!(sessions.install_initiator(3), Ok(Some(1)));
        assert_eq!((sessions.current, sessions.previous), (Some(3), Some(2)));
    }

    #[test]
    fn a_responder_session_is_staged_in_next_until_the_initiator_speaks() {
        // §6.3: a peer may retransmit or replace an initiation while its
        // previous responder session is still unconfirmed, so `next` may be
        // reused in place — but never silently overwritten by a different one.
        let mut sessions = PeerSessions::default();
        assert_eq!(sessions.validate_responder_install(1), Ok(()));
        sessions.commit_responder_install(1);
        assert_eq!(sessions.next, Some(1));

        assert_eq!(
            sessions.validate_responder_install(1),
            Ok(()),
            "replacing the same unconfirmed slot is the retransmission case"
        );
        assert_eq!(
            sessions.validate_responder_install(2),
            Err(Error::InternalInvariant)
        );

        // Confirmation is what promotes it, and it too checks its precondition.
        assert_eq!(sessions.confirm_responder(2), Err(Error::InternalInvariant));
        assert_eq!(sessions.confirm_responder(1), Ok(None));
        assert_eq!(sessions.next, None);
        assert_eq!(sessions.current, Some(1));

        sessions.commit_responder_install(2);
        assert_eq!(sessions.confirm_responder(2), Ok(None));
        assert_eq!((sessions.current, sessions.previous), (Some(2), Some(1)));
    }

    #[test]
    fn unlinking_a_slot_clears_every_reference_to_it() {
        let mut sessions = PeerSessions {
            current: Some(1),
            previous: Some(2),
            next: Some(3),
            handshake: Some(4),
            attempt_deadline: Some(deadline()),
            ..PeerSessions::default()
        };
        assert_eq!(
            sessions.slots(),
            [Some(1), Some(2), Some(3), Some(4)],
            "every generation must be reported so eviction can cascade"
        );

        sessions.unlink(2);
        assert_eq!(sessions.slots(), [Some(1), None, Some(3), Some(4)]);

        // Unlinking the handshake slot also tears down its deadline; leaving
        // it armed would spin the timer against a slot nobody owns.
        sessions.unlink(4);
        assert_eq!(sessions.handshake, None);
        assert_eq!(sessions.attempt_deadline, None);

        sessions.unlink(1);
        sessions.unlink(3);
        assert_eq!(sessions.slots(), [None; 4]);

        // Unlinking a slot this peer never held is a no-op, not a corruption.
        sessions.current = Some(9);
        sessions.unlink(8);
        assert_eq!(sessions.current, Some(9));
    }

    #[test]
    fn peer_debug_output_does_not_expose_precomputed_key_material() {
        let peer = PeerEntry::new(
            [8u8; 32],
            PeerKind::Dynamic,
            [9u8; 32],
            None,
            Some([1u8; 32]),
            InboundPolicy::AllowAll,
            None,
            PeerAddresses::new(),
            T0,
        );

        let rendered = format!("{peer:?}");
        assert!(!rendered.contains("precomputed"), "rendered: {rendered}");
        assert!(!rendered.contains("9, 9, 9, 9"), "rendered: {rendered}");
    }
}
