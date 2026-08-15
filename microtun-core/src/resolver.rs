//! Peer resolution and dynamic-peer lifecycle.
//!
//! This module owns resolver request/event types, in-flight query bookkeeping,
//! answer validation, dynamic-peer installation, and held-peer updates. Resolver
//! output itself is delivered through [`crate::Sink`].
//!
//! A resolver that can receive peer changes keeps local interest in keys whose
//! positive answers the core has installed. The core does not expose subscribe
//! or unsubscribe wire operations: when a dynamic record leaves the peer table
//! it emits an eviction observation so the resolver can forget that key locally.

use core::net::{IpAddr, SocketAddr};

use defmt_or_log::{debug, info, warn};

use crate::{
    Core, Error, EvictedPeerGhost, IpCidr, RelayPolicy, Sink, Slot,
    firewall::InboundPolicy,
    ip::unmap_socket_addr,
    peer::{PeerEntry, PeerKind},
    pending::Wait,
    routing::PeerIdx,
    time::{Duration, Instant},
};

// ---------------------------------------------------------------------------
// Peer resolution interface
// ---------------------------------------------------------------------------

/// Opaque identifier for an in-flight peer-resolution operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolveId(pub(crate) u64);

/// What the resolver is being asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveQuery {
    /// An unknown static public key sent us a (cryptographically valid)
    /// handshake initiation: who is this?
    ByPublicKey([u8; 32]),
    /// An inner packet wants to reach this destination address: whose is it?
    ByDstAddress(IpAddr),
}

/// The result of a resolver query.
#[derive(Debug)]
pub enum ResolveOutcome {
    /// A peer record returned by the embedding's trusted resolver.
    Found(ResolvedPeer),
    /// `404`: authoritatively unknown. Suppresses repeat lookups for the same
    /// target until the configured negative TTL elapses (see [`ResolveKind::Negative`]).
    NotFound,
    /// Transient failure (timeout, `429`, `5xx`). Initial lookups are left
    /// uncached so traffic can retry; held peers retain their last known-good
    /// record, while polling integrations schedule another check.
    Failed,
}

/// A peer record from the embedding's trusted resolver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPeer {
    pub public_key: [u8; 32],
    /// Current outer endpoint. IPv4-mapped IPv6 is normalized to native IPv4
    /// by the core when the answer is canonicalized.
    pub endpoint: Option<SocketAddr>,
    /// Relay protocol: static public key of the peer through which this
    /// peer is reached, if it is not directly addressable.
    pub relay: Option<[u8; 32]>,
    /// The peer's single authoritative tunnel prefix.
    pub address: IpCidr,
    /// Ingress policy applied to authenticated inner packets from this peer.
    pub inbound_policy: InboundPolicy,
    /// WireGuard-style persistent keepalive interval. `None` disables it.
    pub persistent_keepalive: Option<Duration>,
}

/// A typed resolution operation emitted through [`crate::Sink::resolve`].
///
/// The request owns its correlation identifier. Resolver implementations
/// should retain the whole value and turn it into a [`ResolveResponse`] with
/// [`ResolveRequest::complete`] when the asynchronous lookup finishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolveRequest {
    id: ResolveId,
    query: ResolveQuery,
}

impl ResolveRequest {
    /// The query to execute.
    pub const fn query(&self) -> ResolveQuery {
        self.query
    }

    /// The opaque operation identifier, useful for diagnostics only.
    pub const fn id(&self) -> ResolveId {
        self.id
    }

    /// Build a request that no core issued, for testing resolver plumbing.
    ///
    /// Its identifier belongs to no in-flight operation, so a completion built
    /// from it is discarded as stale by any real core. That is the point: it
    /// lets an integration crate drive a resolver end to end without standing
    /// up an engine to mint requests for it.
    #[cfg(feature = "test-util")]
    pub const fn for_test(query: ResolveQuery) -> Self {
        Self {
            id: ResolveId(u64::MAX),
            query,
        }
    }

    /// Pair an outcome with this request for delivery through
    /// [`crate::Core::resolver_event_completed`].
    pub fn complete(self, outcome: ResolveOutcome) -> ResolveResponse {
        ResolveResponse {
            id: self.id,
            outcome,
        }
    }
}

/// Completion of a previously emitted [`ResolveRequest`].
#[derive(Debug)]
pub struct ResolveResponse {
    id: ResolveId,
    outcome: ResolveOutcome,
}

/// Convenience envelope for integrations that multiplex resolver work onto one
/// channel.
///
/// [`ResolverCommand::Resolve`] originates at [`crate::Sink::resolve`].
/// [`ResolverCommand::Forget`] is runtime-derived from [`crate::Event::PeerEvicted`];
/// the core itself does not expose a separate forget sink callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolverCommand {
    /// Perform this lookup. A positive answer may become a locally held key.
    Resolve(ResolveRequest),
    /// Forget local resolver interest in this key after peer eviction.
    Forget([u8; 32]),
}

/// Authoritative state for a peer the core already holds.
///
/// A resolver integration produces one of these when it reconciles a held
/// record — because the Peers API server named the key in a peer invalidation
/// notification, or because a reconnect replayed the whole held set. Either
/// way the state here came from a `v1.peer.by_key` reconciliation, so it is
/// subject to the same validation as a first answer.
#[derive(Debug)]
pub struct PeerUpdate {
    pub public_key: [u8; 32],
    pub outcome: ResolveOutcome,
}

impl PeerUpdate {
    /// Build an update for a peer the core already holds.
    pub fn new(public_key: [u8; 32], outcome: ResolveOutcome) -> Self {
        Self {
            public_key,
            outcome,
        }
    }
}

/// Event stream from a resolver integration back into the core.
#[derive(Debug)]
pub enum ResolverEvent {
    Resolved(ResolveResponse),
    PeerUpdated(PeerUpdate),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstallSource {
    AuthenticatedInitiator,
    Relay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerAdmission {
    /// The remote has proved possession of the claimed WireGuard static key.
    /// This is the only new-peer admission allowed to consume protected slots.
    AuthenticatedInitiator,
    /// A local outbound packet caused a by-address lazy lookup.
    LazyOutbound,
    /// An authenticated peer named a relay destination. Relay admissions are
    /// intentionally non-evicting as well as subject to the protected reserve.
    LazyRelay,
    /// Apply a held-peer update to an already-installed dynamic peer; never
    /// create a replacement.
    HeldUpdate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResolveKind {
    /// Answer unblocks pending outbound packets carrying this id.
    Outbound,
    /// Answer populates the peer table and route cache. Authenticated unknown
    /// initiators may additionally retain one bounded responder-side Noise
    /// state entry until this lookup completes; relay envelopes are still
    /// dropped and rely on the submitter's own retry behavior.
    Install(InstallSource),
    /// A spent entry: the resolver authoritatively answered "no such peer" for
    /// `query`. It emits no request and parks nothing; its only job is to make
    /// `Core` short-circuit repeated lookups for the same
    /// target until `deadline` (`now + negative_ttl`), at which point the timer
    /// sweep reclaims its slot. This replaces the former negative caches that
    /// lived inside the route cache.
    Negative,
    /// A re-lookup of a record this device already holds, issued because an
    /// earlier reconciliation of that record could not be completed. Its
    /// answer goes down the local interested-update path, so it can refresh or
    /// authoritatively remove the peer but never create one.
    Reconcile,
}

/// A reconciliation this device owes itself.
///
/// Created when a held-peer update cannot be applied and discharged when one
/// finally is. The obligation is deliberately not the same thing as a queued
/// lookup: it survives the failure of any number of lookups, and it holds a
/// `due` time so a peer whose record simply does not fit cannot spin the
/// resolver at round-trip speed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PendingReconcile {
    pub(super) public_key: [u8; 32],
    /// Earliest time the next `by-key` lookup for this key may be issued.
    pub(super) due: Instant,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct InflightResolve {
    id: ResolveId,
    query: ResolveQuery,
    kind: ResolveKind,
    pub(super) deadline: Instant,
    emitted: bool,
}

#[cfg_attr(not(feature = "async"), maybe_async::must_be_sync)]
impl<
    RNG: rand_core::RngCore + rand_core::CryptoRng,
    RP: RelayPolicy,
    const MAX_PEERS: usize,
    const MAX_SESSIONS: usize,
    const REPLAY_WORDS: usize,
    const MAX_ROUTES: usize,
> Core<RNG, RP, MAX_PEERS, MAX_SESSIONS, REPLAY_WORDS, MAX_ROUTES>
{
    /// Deliver either a lookup completion or an unsolicited held-peer update.
    pub async fn resolver_event_completed<E: Sink>(
        &mut self,
        now: Instant,
        event: ResolverEvent,
        sink: &mut E,
    ) -> Result<(), Error> {
        let result = match event {
            ResolverEvent::Resolved(response) => {
                debug!("resolver completion received: id={}", response.id.0);
                self.resolved(now, response, sink).await
            }
            ResolverEvent::PeerUpdated(update) => self.peer_updated(now, update),
        };
        self.flush_sink_output(sink);
        result
    }

    /// Deliver pending control-plane output through the sink.
    ///
    /// Peer releases are observations, so they are emitted first through
    /// [`crate::Sink::event`]. Resolver requests use the non-blocking acceptance
    /// callback: a rejected request remains queued and stops this pass.
    pub(super) fn flush_sink_output<E: Sink>(&mut self, sink: &mut E) {
        while let Some(public_key) = self.pending_peer_evictions.pop() {
            sink.event(crate::Event::PeerEvicted { public_key });
            debug!("emitted peer eviction event");
        }

        loop {
            let Some(pos) = self.resolves.iter().position(|resolve| !resolve.emitted) else {
                return;
            };
            let pending = self.resolves[pos];
            let request = ResolveRequest {
                id: pending.id,
                query: pending.query,
            };
            if !sink.resolve(request) {
                return;
            }
            if let Some(resolve) = self.resolves.get_mut(pos) {
                // The entry can only disappear while the core itself is running,
                // and sink resolver callbacks are synchronous/non-reentrant.
                resolve.emitted = true;
            }
            debug!("emitted resolver request: id={}", request.id().0);
        }
    }

    /// Park an unrouted outbound packet behind a deduplicated address lookup.
    pub(super) fn queue_outbound_resolution(
        &mut self,
        dst: IpAddr,
        packet: &[u8],
        now: Instant,
    ) -> Result<(), Error> {
        // A single scan of the resolve table decides between three cases,
        // because there is at most one entry per query:
        //   * an unexpired negative marker -> recently authoritative "no such
        //     peer": drop without re-querying;
        //   * an in-flight outbound resolve -> park behind it (dedup);
        //   * nothing (or an expired marker) -> start a fresh lookup.
        let query = ResolveQuery::ByDstAddress(dst);
        let deadline = now + self.core_config.resolve_outbound_timeout;
        let id = match self.resolves.iter().position(|r| r.query == query) {
            Some(pos) => {
                let existing = self.resolves[pos]; // InflightResolve: Copy
                match existing.kind {
                    ResolveKind::Negative if existing.deadline > now => {
                        debug!("negative resolve marker hit; dropping inner packet");
                        return Ok(());
                    }
                    ResolveKind::Negative => {
                        // Expired but not yet swept: reuse its slot in place.
                        let id = self.alloc_resolve_id();
                        self.resolves[pos] = InflightResolve {
                            id,
                            query,
                            kind: ResolveKind::Outbound,
                            deadline,
                            emitted: false,
                        };
                        info!("queued outbound peer resolution: id={}", id.0);
                        id
                    }
                    _ => existing.id,
                }
            }
            None => {
                let id = self.alloc_resolve_id();
                let entry = InflightResolve {
                    id,
                    query,
                    kind: ResolveKind::Outbound,
                    deadline,
                    emitted: false,
                };
                if self.push_resolve(entry).is_err() {
                    warn!("resolver inflight queue full");
                    return Err(Error::ResolverBusy);
                }
                info!("queued outbound peer resolution: id={}", id.0);
                id
            }
        };
        debug!(
            "parking outbound packet: resolve_id={} len={}",
            id.0,
            packet.len()
        );
        self.pending.park(packet, Wait::Resolve(id), deadline);
        self.timers.arm(deadline);
        Ok(())
    }

    /// Expire one resolver entry, unwinding any state parked behind it.
    pub(super) fn expire_one_resolve(&mut self, now: Instant) -> bool {
        let Some(pos) = self
            .resolves
            .iter()
            .position(|resolve| resolve.deadline <= now)
        else {
            return false;
        };

        let entry = self.resolves.swap_remove(pos);
        match entry.kind {
            ResolveKind::Outbound => {
                self.pending
                    .drop_if(|packet| packet.wait == Wait::Resolve(entry.id));
            }
            ResolveKind::Install(source) => {
                // Authenticated initiator installs may own one parked Noise
                // generation. Expiry drops it atomically with the lookup; the
                // initiator's normal retransmission remains the fallback.
                if matches!(source, InstallSource::AuthenticatedInitiator) {
                    self.drop_pending_initiation(entry.id);
                }
            }
            // A reconciliation lookup parks nothing either, but it carries an
            // obligation that must not lapse with it: the record it was going
            // to reconcile is still held and still unreconciled.
            ResolveKind::Reconcile => {
                if let ResolveQuery::ByPublicKey(public_key) = entry.query
                    && self.find_peer(&public_key).is_some()
                {
                    self.queue_reconcile(public_key, now);
                }
            }
            // A spent negative marker: its deadline reaching `now` is the end
            // of the suppression window. It was already removed above; nothing
            // else references it, so there is nothing to unwind.
            ResolveKind::Negative => {}
        }
        true
    }

    /// Ask the resolver to install an authenticated unknown initiator.
    ///
    /// Returns the resolver id only when a live lookup was successfully queued;
    /// the caller may use it to bind bounded pending handshake state to the
    /// completion. Failure to queue is intentionally lossy because WireGuard
    /// retransmission preserves the previous recovery behavior.
    pub(super) fn request_peer_install(
        &mut self,
        key: [u8; 32],
        now: Instant,
    ) -> Option<ResolveId> {
        if self.peer_is_ghosted(&key, now) {
            debug!("unknown initiator suppressed by recently-evicted ghost");
            return None;
        }
        self.queue_peer_install(key, InstallSource::AuthenticatedInitiator, now)
    }

    /// Return the id of the live install resolve created by an authenticated
    /// initiation for `key`. This deliberately excludes relay installs,
    /// negative markers, and expired entries so only proof-bearing retries may
    /// refresh responder-side pending handshake state.
    pub(super) fn authenticated_initiator_resolve_id(
        &self,
        key: [u8; 32],
        now: Instant,
    ) -> Option<ResolveId> {
        let query = ResolveQuery::ByPublicKey(key);
        self.resolves
            .iter()
            .find(|entry| {
                entry.query == query
                    && entry.deadline > now
                    && matches!(
                        entry.kind,
                        ResolveKind::Install(InstallSource::AuthenticatedInitiator)
                    )
            })
            .map(|entry| entry.id)
    }

    /// Ask the resolver to install a relay destination, with a quota attached
    /// to the authenticated submitter in addition to the global remote budget.
    pub(super) fn request_relay_peer_install(
        &mut self,
        submitter: PeerIdx,
        key: [u8; 32],
        now: Instant,
    ) {
        if self.resolve_suppressed(ResolveQuery::ByPublicKey(key), now) {
            return;
        }
        if self.peer_is_ghosted(&key, now) {
            debug!("relay destination suppressed by recently-evicted ghost");
            return;
        }
        let free = self.peers.iter().filter(|peer| peer.is_none()).count();
        if free <= self.core_config.lazy_peer_reserve {
            debug!("relay peer lookup denied by protected reserve");
            return;
        }
        let interval = self.core_config.relay_resolve_min_interval;
        if interval.as_millis() != 0 {
            let Some(peer) = self
                .peers
                .get_mut(submitter as usize)
                .and_then(Option::as_mut)
            else {
                return;
            };
            if peer
                .last_relay_resolve
                .is_some_and(|last| now.saturating_since(last) < interval)
            {
                debug!("relay submitter resolve quota exhausted; dropping lookup");
                return;
            }
            peer.last_relay_resolve = Some(now);
        }
        let _ = self.queue_peer_install(key, InstallSource::Relay, now);
    }

    fn queue_peer_install(
        &mut self,
        key: [u8; 32],
        source: InstallSource,
        now: Instant,
    ) -> Option<ResolveId> {
        if self.resolve_suppressed(ResolveQuery::ByPublicKey(key), now) {
            return None;
        }
        if !self.remote_resolves.try_take(now) {
            debug!("remote resolve budget exhausted; dropping by-key lookup");
            return None;
        }
        let id = self.alloc_resolve_id();
        let query = ResolveQuery::ByPublicKey(key);
        let entry = InflightResolve {
            id,
            query,
            kind: ResolveKind::Install(source),
            deadline: now + self.core_config.resolve_timeout,
            emitted: false,
        };
        // Best effort. Authenticated initiators may park state only after this
        // succeeds; relay callers still rely entirely on their own retry path.
        if self.push_resolve(entry).is_err() {
            return None;
        }
        Some(id)
    }

    // -----------------------------------------------------------------------
    // Resolver answers
    // -----------------------------------------------------------------------

    /// Apply one asynchronous resolver completion. Unknown or stale request
    /// identifiers are ignored.
    async fn resolved<E: Sink>(
        &mut self,
        now: Instant,
        response: ResolveResponse,
        sink: &mut E,
    ) -> Result<(), Error> {
        let ResolveResponse { id, outcome } = response;
        debug!("applying resolver result: id={}", id.0);
        let Some(pos) = self.resolves.iter().position(|r| r.id == id) else {
            warn!("ignoring stale resolver completion: id={}", id.0);
            return Ok(());
        };
        let entry = self.resolves.swap_remove(pos);
        match entry.kind {
            ResolveKind::Outbound => self.resolved_outbound(now, entry, outcome, sink).await,
            ResolveKind::Install(source) => {
                self.resolved_install(now, entry, source, outcome, sink)
                    .await
            }
            // A reconciliation answer is an ordinary held-peer update: it may
            // refresh or authoritatively remove the record, never create one.
            ResolveKind::Reconcile => match entry.query {
                ResolveQuery::ByPublicKey(public_key) => {
                    self.apply_held_answer(now, public_key, outcome)
                }
                ResolveQuery::ByDstAddress(_) => Ok(()),
            },
            // Negative markers are never emitted as requests, so no external
            // completion can carry their id. Reaching here would mean an id
            // collision or a spoofed completion; ignore it.
            ResolveKind::Negative => {
                warn!("ignoring resolver completion for a negative marker");
                Ok(())
            }
        }
    }

    /// Apply an authoritative update to a currently installed dynamic peer.
    /// Late updates for peers already removed are ignored.
    fn peer_updated(&mut self, now: Instant, update: PeerUpdate) -> Result<(), Error> {
        let PeerUpdate {
            public_key,
            outcome,
        } = update;
        self.apply_held_answer(now, public_key, outcome)
    }

    /// The single reconciliation routine for a record this device already
    /// holds, whatever prompted it: a peer invalidation relayed by the embedding, a
    /// reconnect replay, or one of this core's own retries.
    ///
    /// Three properties matter here, and each is a rule the protocol states
    /// explicitly:
    ///
    /// * a lookup result is a *complete replacement*, so the peer must end up
    ///   describing the answer entirely or not at all — never new metadata
    ///   stapled to the old address;
    /// * only a well-formed `not_found` removes anything, so a rejected or
    ///   failed answer leaves the held record exactly as it was;
    /// * a reconciliation that could not be completed is still owed, so it is
    ///   recorded rather than dropped on the floor.
    fn apply_held_answer(
        &mut self,
        now: Instant,
        public_key: [u8; 32],
        outcome: ResolveOutcome,
    ) -> Result<(), Error> {
        let Some(pidx) = self.find_peer(&public_key) else {
            // The record is gone, so there is nothing left to reconcile and a
            // late answer must not resurrect it.
            self.forget_reconcile(&public_key);
            return Ok(());
        };
        let is_dynamic = self
            .peers
            .get(pidx as usize)
            .and_then(Option::as_ref)
            .is_some_and(|peer| !peer.is_pinned() && peer.public_key == public_key);
        if !is_dynamic {
            self.forget_reconcile(&public_key);
            return Ok(());
        }

        let query = ResolveQuery::ByPublicKey(public_key);
        match outcome {
            ResolveOutcome::Found(info) => {
                let info = match self.canonicalize_resolved_answer(query, info) {
                    Ok(info) => info,
                    Err(_) => {
                        // A positive answer this device refuses is not an
                        // authoritative miss: the peer keeps its record. But
                        // the record is still unreconciled, so the obligation
                        // has to survive the rejection.
                        warn!("rejected an invalid held-peer update: peer={}", pidx);
                        self.queue_reconcile(public_key, now);
                        return Ok(());
                    }
                };
                if let Err(error) = self.commit_held_update(pidx, &info, now) {
                    warn!(
                        "keeping the last complete record for a peer whose held-peer update could not be installed: peer={} error={:?}",
                        pidx, error
                    );
                    self.queue_reconcile(public_key, now);
                    return Ok(());
                }
                self.forget_reconcile(&public_key);
                self.clear_negative(query);
            }
            ResolveOutcome::NotFound => {
                // The one outcome with the authority to remove state.
                self.forget_reconcile(&public_key);
                self.evict_peer(pidx)?;
                self.mark_negative(query, now);
            }
            ResolveOutcome::Failed => {
                // Transient: keep the record, keep the obligation. The
                // embedding will usually reconnect and replay the whole held
                // set, which discharges this; the entry is what covers the
                // case where it does not.
                self.queue_reconcile(public_key, now);
            }
        }
        Ok(())
    }

    /// Install local interested answer as one complete record, or change nothing.
    ///
    /// Route replacement is the only step that can fail, and it is fully
    /// preflighted — it plans every eviction and draws the whole eviction
    /// budget before it mutates anything — so running it *first* is what makes
    /// the update atomic. Peer metadata is applied only once the address
    /// is committed, and applying it cannot fail for a peer that is already
    /// installed.
    ///
    /// Doing it the other way round is what produced records carrying a new
    /// endpoint, relay, policy and keepalive alongside the address from the
    /// previous answer, with nothing scheduled to ever reconcile them.
    fn commit_held_update(
        &mut self,
        pidx: PeerIdx,
        info: &ResolvedPeer,
        now: Instant,
    ) -> Result<(), Error> {
        self.commit_existing_resolved_peer(pidx, info, now, PeerAdmission::HeldUpdate, true)
    }

    /// Record that `public_key` still needs reconciling, without issuing the
    /// lookup yet.
    ///
    /// The delay is deliberate. A record that does not fit this device's route
    /// cache will not fit on the next round trip either, so retrying
    /// immediately would burn the resolve budget in a tight loop for as long
    /// as the condition lasted. Waiting `negative_ttl` gives capacity a chance
    /// to appear — which is the same interval this core already uses to decide
    /// that an answer is worth asking for again.
    fn queue_reconcile(&mut self, public_key: [u8; 32], now: Instant) {
        let due = now + self.core_config.negative_ttl;
        let armed = match self
            .pending_reconciles
            .iter_mut()
            .find(|pending| pending.public_key == public_key)
        {
            Some(pending) => {
                // An obligation already recorded must not be pushed further
                // out by a later failure, or a peer failing repeatedly would
                // be reconciled progressively less often.
                if due < pending.due {
                    pending.due = due;
                }
                pending.due
            }
            None => {
                if self
                    .push_reconcile(PendingReconcile { public_key, due })
                    .is_err()
                {
                    warn!("reconciliation backlog full; dropping local interested-update retry");
                    return;
                }
                due
            }
        };
        self.timers.arm(armed);
    }

    fn push_reconcile(&mut self, pending: PendingReconcile) -> Result<(), Error> {
        #[cfg(feature = "alloc")]
        {
            if self.pending_reconciles.len() >= MAX_PEERS {
                return Err(Error::ResolverBusy);
            }
            self.pending_reconciles.push(pending);
            Ok(())
        }
        #[cfg(not(feature = "alloc"))]
        {
            self.pending_reconciles
                .push(pending)
                .map_err(|_| Error::ResolverBusy)
        }
    }

    /// Discharge the obligation for `public_key`, if there was one.
    fn forget_reconcile(&mut self, public_key: &[u8; 32]) {
        self.pending_reconciles
            .retain(|pending| &pending.public_key != public_key);
    }

    /// Turn at most one due obligation into a real `by-key` lookup.
    ///
    /// The obligation is always held by exactly one of two places: this list,
    /// or a live [`ResolveKind::Reconcile`] entry. It moves from here to there
    /// when it comes due, and back again if that lookup lapses or its answer
    /// cannot be installed.
    ///
    /// Returns whether any work was done, matching the rest of the incremental
    /// timer step.
    pub(super) fn promote_due_reconcile(&mut self, now: Instant) -> bool {
        let Some(index) = self
            .pending_reconciles
            .iter()
            .position(|pending| pending.due <= now)
        else {
            return false;
        };
        let pending = self.pending_reconciles[index];

        // The peer may have been evicted while the obligation waited.
        if self.find_peer(&pending.public_key).is_none() {
            self.pending_reconciles.swap_remove(index);
            return true;
        }

        let query = ResolveQuery::ByPublicKey(pending.public_key);
        // Something is already asking this question; its answer discharges the
        // obligation, so leave the entry for that answer to clear and re-arm
        // rather than issuing a duplicate.
        if self.resolve_suppressed(query, now) {
            self.defer_reconcile(index, now);
            return true;
        }

        let id = self.alloc_resolve_id();
        let entry = InflightResolve {
            id,
            query,
            kind: ResolveKind::Reconcile,
            deadline: now + self.core_config.resolve_timeout,
            emitted: false,
        };
        if self.push_resolve(entry).is_err() {
            // No slot right now. The obligation stays here and tries again.
            self.defer_reconcile(index, now);
            return true;
        }
        debug!("issuing a held-record reconciliation: id={}", id.0);
        self.pending_reconciles.swap_remove(index);
        true
    }

    fn defer_reconcile(&mut self, index: usize, now: Instant) {
        let due = now + self.core_config.negative_ttl;
        if let Some(pending) = self.pending_reconciles.get_mut(index) {
            pending.due = due;
        }
        self.timers.arm(due);
    }

    /// A `by-key` answer for an unknown initiator or a relay-forwarding
    /// destination. Authenticated initiators retain their newest bounded Noise
    /// generation while the lookup is in flight, so a successful install can
    /// answer immediately rather than waiting for Rekey-Timeout. Relay
    /// destinations continue to rely on the submitter's retry behavior.
    async fn resolved_install<E: Sink>(
        &mut self,
        now: Instant,
        entry: InflightResolve,
        source: InstallSource,
        outcome: ResolveOutcome,
        sink: &mut E,
    ) -> Result<(), Error> {
        let ResolveQuery::ByPublicKey(expected_key) = entry.query else {
            return Ok(());
        };

        // Take before applying the answer so every completion path — found,
        // not-found, failed, malformed, or capacity-rejected — releases the
        // parked cryptographic state exactly once. A successful install below
        // is the only path that consumes it into a handshake response.
        let pending = matches!(source, InstallSource::AuthenticatedInitiator)
            .then(|| self.take_pending_initiation(entry.id))
            .flatten();

        match outcome {
            ResolveOutcome::Found(info) => {
                // The resolver established local interest for this key before
                // returning the answer. Every path below that does not leave
                // the record installed must say so.
                let info_key = info.public_key;
                // The core is the sole resolver-policy boundary. A rejected
                // answer installs nothing and is treated like a transient
                // resolver failure so malformed policy cannot poison caches.
                let info = match self.canonicalize_resolved_answer(entry.query, info) {
                    Ok(info) => info,
                    Err(_) => {
                        self.discard_answer(&info_key);
                        return Ok(());
                    }
                };
                let admission = match source {
                    InstallSource::AuthenticatedInitiator => PeerAdmission::AuthenticatedInitiator,
                    InstallSource::Relay => PeerAdmission::LazyRelay,
                };
                let pidx = if let Some(pidx) = self.find_peer(&info.public_key) {
                    // Another resolve can install the peer while this lookup
                    // is in flight. In that race this answer is a replacement,
                    // not a new admission: commit routes first so a capacity
                    // failure cannot leave new metadata attached to the old
                    // address.
                    match self.commit_existing_resolved_peer(
                        pidx,
                        &info,
                        now,
                        admission,
                        !matches!(source, InstallSource::Relay),
                    ) {
                        Ok(()) => pidx,
                        Err(Error::RouteCacheFull) | Err(Error::PeerAdmissionLimited) => {
                            return Ok(());
                        }
                        Err(error) => return Err(error),
                    }
                } else {
                    let (pidx, routes_changed, installed_new) =
                        match self.upsert_peer_unchecked(&info, now, admission) {
                            Ok(installed) => installed,
                            Err(Error::PeerTableFull) | Err(Error::PeerAdmissionLimited) => {
                                self.discard_answer(&info_key);
                                return Ok(());
                            }
                            Err(error) => return Err(error),
                        };
                    if routes_changed
                        && self
                            .replace_dynamic_route(
                                pidx,
                                info.address,
                                now,
                                !matches!(source, InstallSource::Relay),
                            )
                            .is_err()
                    {
                        // A freshly admitted peer has no usable old route.
                        // Remove it entirely rather than retaining a partial
                        // record; eviction reports that the resolver interest must
                        // be released.
                        if installed_new {
                            self.evict_peer(pidx)?;
                        }
                        return Ok(());
                    }
                    pidx
                };
                self.clear_negative(entry.query);

                if let Some(pending) = pending {
                    // Both the resolver answer and the parked proof are bound to
                    // this exact by-key query. Keep the check explicit so future
                    // resolver refactors cannot accidentally cross-wire state.
                    if pending.consumed.s_pub_i != expected_key || info.public_key != expected_key {
                        warn!("dropping mismatched pending initiation after peer install");
                        return Ok(());
                    }
                    self.accept_authenticated_initiation(
                        pidx,
                        &pending.consumed,
                        pending.src,
                        now,
                        sink,
                    )
                    .await?;
                }
                Ok(())
            }
            ResolveOutcome::NotFound => {
                self.mark_negative(entry.query, now);
                Ok(())
            }
            ResolveOutcome::Failed => Ok(()),
        }
    }

    async fn resolved_outbound<E: Sink>(
        &mut self,
        now: Instant,
        entry: InflightResolve,
        outcome: ResolveOutcome,
        sink: &mut E,
    ) -> Result<(), Error> {
        let ResolveQuery::ByDstAddress(address) = entry.query else {
            return Ok(());
        };
        match outcome {
            ResolveOutcome::Found(info) => {
                // A by-address answer must actually cover the address that
                // was queried. This check belongs in the core rather than
                // only in the optional Peers API client: other embeddings can
                // feed resolver answers directly.
                //
                // A rejected positive answer is *not* an authoritative miss.
                // The server said "found"; we declined the record. Only a
                // well-formed `not_found` result carries the authority to
                // negative-cache, so no marker is left here — otherwise one
                // malformed or hostile answer would suppress every lookup for
                // this address for the whole negative TTL, including the
                // correct answer that might arrive immediately after.
                //
                // The parked packets are still dropped. Re-dispatching them
                // would allocate a fresh resolve after this entry was removed,
                // letting one packet drive an unbounded query loop; dropping
                // them leaves the retry to the next packet, exactly as the
                // transient-failure arm below does.
                let info_key = info.public_key;
                if !info.address.contains(&address) {
                    warn!("discarding a by-address answer that does not cover the query");
                    // The resolver locally retained the key returned by the
                    // address lookup before completing this answer. Every path
                    // that does not leave it installed has to release the local interest.
                    self.discard_answer(&info_key);
                    self.pending.drop_if(|p| p.wait == Wait::Resolve(entry.id));
                    return Ok(());
                }

                let info = match self.canonicalize_resolved_answer(entry.query, info) {
                    Ok(info) => info,
                    Err(_) => {
                        self.discard_answer(&info_key);
                        self.pending.drop_if(|p| p.wait == Wait::Resolve(entry.id));
                        return Ok(());
                    }
                };
                let (pidx, installed_new) = if let Some(pidx) = self.find_peer(&info.public_key) {
                    match self.commit_existing_resolved_peer(
                        pidx,
                        &info,
                        now,
                        PeerAdmission::LazyOutbound,
                        true,
                    ) {
                        Ok(()) => (pidx, false),
                        Err(Error::RouteCacheFull) | Err(Error::PeerAdmissionLimited) => {
                            self.mark_negative(entry.query, now);
                            self.pending.drop_if(|p| p.wait == Wait::Resolve(entry.id));
                            return Ok(());
                        }
                        Err(error) => return Err(error),
                    }
                } else {
                    let (pidx, routes_changed, installed_new) =
                        match self.upsert_peer_unchecked(&info, now, PeerAdmission::LazyOutbound) {
                            Ok(installed) => installed,
                            Err(Error::PeerTableFull) | Err(Error::PeerAdmissionLimited) => {
                                self.discard_answer(&info_key);
                                self.pending.drop_if(|p| p.wait == Wait::Resolve(entry.id));
                                return Ok(());
                            }
                            Err(error) => return Err(error),
                        };
                    if routes_changed
                        && self
                            .replace_dynamic_route(pidx, info.address, now, true)
                            .is_err()
                    {
                        if installed_new {
                            self.evict_peer(pidx)?;
                        }
                        self.mark_negative(entry.query, now);
                        self.pending.drop_if(|p| p.wait == Wait::Resolve(entry.id));
                        return Ok(());
                    }
                    (pidx, installed_new)
                };

                // Route installation can still fail (for example when the
                // route cache is entirely pinned). Verify the postcondition
                // before replaying packets so a valid-looking answer cannot
                // recreate the same resolve forever.
                if self.routes.lookup_readonly(&address).is_none() {
                    if installed_new {
                        self.evict_peer(pidx)?;
                    }
                    self.mark_negative(entry.query, now);
                    self.pending.drop_if(|p| p.wait == Wait::Resolve(entry.id));
                    return Ok(());
                }

                self.clear_negative(entry.query);
                // Unblock parked packets: they re-enter the outbound path
                // and now find a route (and park again on the handshake).
                while let Some(p) = self.pending.take_if(|p| p.wait == Wait::Resolve(entry.id)) {
                    let packet = p.packet();
                    let _ = self.outbound(now, packet, sink).await;
                }
                Ok(())
            }
            ResolveOutcome::NotFound => {
                self.mark_negative(entry.query, now);
                self.pending.drop_if(|p| p.wait == Wait::Resolve(entry.id));
                Ok(())
            }
            ResolveOutcome::Failed => {
                // Transient: drop the parked packets but leave no cache
                // entry, so the very next packet retries.
                self.pending.drop_if(|p| p.wait == Wait::Resolve(entry.id));
                Ok(())
            }
        }
    }

    /// Reinstall `pidx`'s single dynamic route.
    ///
    /// Capacity is reserved before insertion by preflighting whole-peer
    /// evictions. Only idle, sessionless dynamic peers are candidates; pinned
    /// and active peers are never selected. Returns [`Error::RouteCacheFull`]
    /// when no safe plan can fit the route.
    fn replace_dynamic_route(
        &mut self,
        pidx: PeerIdx,
        address: IpCidr,
        now: Instant,
        allow_peer_eviction: bool,
    ) -> Result<(), Error> {
        let current_slots = self.routes.peer_route_count(pidx);
        let available_after_replace = self.routes.available_slots().saturating_add(current_slots);
        if available_after_replace == 0 {
            if !allow_peer_eviction {
                return Err(Error::RouteCacheFull);
            }

            let selected = [None; MAX_PEERS];
            let Some(victim) = self.capacity_victim_excluding(now, Some(pidx), &selected, 0, 1)
            else {
                return Err(Error::RouteCacheFull);
            };
            if !self.peer_evictions.try_take_many(1, now) {
                debug!("route-capacity eviction denied by global cooldown");
                return Err(Error::PeerAdmissionLimited);
            }
            warn!(
                "evicting idle sessionless peer to make room in the route cache: peer={}",
                victim
            );
            self.evict_peer_and_remember(victim, now)?;
        }

        self.routes.remove_peer(pidx)?;
        self.routes.insert(address, pidx, false, now)?;
        let Some(peer) = self.peers.get_mut(pidx as usize).and_then(Option::as_mut) else {
            return Err(Error::InternalInvariant);
        };
        peer.address = address;
        Ok(())
    }

    /// Replace an already-installed dynamic peer as one atomic resolver
    /// record.
    ///
    /// Route replacement is the only capacity-sensitive operation and is
    /// fully preflighted, so it runs before metadata mutation. If it cannot
    /// commit, the peer remains byte-for-byte on its prior accepted record.
    /// Once routes succeed, refreshing metadata for an existing peer cannot
    /// require peer-table or route capacity.
    fn commit_existing_resolved_peer(
        &mut self,
        pidx: PeerIdx,
        info: &ResolvedPeer,
        now: Instant,
        admission: PeerAdmission,
        allow_peer_eviction: bool,
    ) -> Result<(), Error> {
        let routes_changed = {
            let Some(peer) = self.peers.get(pidx as usize).and_then(Option::as_ref) else {
                return Err(Error::InternalInvariant);
            };
            peer.address != info.address
        };
        if routes_changed {
            self.replace_dynamic_route(pidx, info.address, now, allow_peer_eviction)?;
        }

        let (updated, _, installed_new) = self.upsert_peer_unchecked(info, now, admission)?;
        if updated != pidx || installed_new {
            return Err(Error::InternalInvariant);
        }
        Ok(())
    }

    /// Enforce every semantic invariant for a resolver answer.
    ///
    /// This is the single policy boundary for all resolver implementations.
    /// HTTP/JSON codecs decode wire syntax only; they must not duplicate these
    /// checks because a second policy can drift from the core's behavior.
    ///
    /// A by-key answer must name the key that was queried. Every answer must
    /// also avoid this interface's own identity and pinned identities, avoid a
    /// self-relay, and carry one non-default tunnel address.
    ///
    /// # The resolver is the routing trust root
    ///
    /// These checks are about *self-consistency*, not about defending against
    /// the resolver. Cryptokey routing for dynamic peers is delegated to the
    /// resolver in full: it decides which static key owns which tunnel
    /// prefixes, and this device implements that decision. In particular, a
    /// resolver answer **may** claim address space that overlaps a pinned
    /// peer's, and **may** claim address space already assigned to another
    /// dynamic peer. Resolution between overlapping claims is left to the
    /// route cache's longest-prefix match, where a pinned route wins a tie
    /// (it is installed first) but loses to a more specific dynamic one.
    ///
    /// The consequence is worth stating plainly: an answer can redirect
    /// traffic for any tunnel address on this device, including the resolver's
    /// own. A resolver that is compromised, or that is reached over a path
    /// this device cannot authenticate, can therefore reroute everything and —
    /// by claiming a prefix covering the Peers API server itself — make the
    /// misdirection self-sustaining across held-peer updates. That is accepted
    /// deliberately: the resolver is already the authority that names peers,
    /// and layering partial address-space restrictions on top bought
    /// consistency, not safety. What still protects the deployment is the
    /// binding between the resolver and a pinned identity — see the transport
    /// security notes on the embedding's resolver (for the Tokio host,
    /// `microtun_std::PeersApiResolver`).
    fn canonicalize_resolved_answer(
        &self,
        query: ResolveQuery,
        mut info: ResolvedPeer,
    ) -> Result<ResolvedPeer, Error> {
        // The single normalization point for a resolver answer. Every path
        // that installs or updates a peer passes through here, so mapped
        // IPv4-in-IPv6 endpoints are folded to native IPv4 exactly once
        // rather than at each boundary type's constructor.
        info.endpoint = info.endpoint.map(unmap_socket_addr);
        self.check_resolved_answer(query, &info)?;
        Ok(info)
    }

    fn check_resolved_answer(&self, query: ResolveQuery, info: &ResolvedPeer) -> Result<(), Error> {
        if let ResolveQuery::ByPublicKey(expected) = query {
            if info.public_key != expected {
                return Err(Error::InvalidResolverAnswer);
            }
        }
        // Our own static key. `Core::new` refuses this for pinned peers; a
        // dynamic answer must not be able to install what configuration
        // cannot. Accepting it would let us handshake with ourselves and
        // spend session slots on a peer that is this very interface.
        if info.public_key == self.s_pub {
            return Err(Error::InvalidResolverAnswer);
        }
        if self
            .find_peer(&info.public_key)
            .and_then(|pidx| self.peers.get(pidx as usize))
            .and_then(Option::as_ref)
            .is_some_and(PeerEntry::is_pinned)
        {
            return Err(Error::InvalidResolverAnswer);
        }
        // A peer cannot be its own relay. `relay_path` would reject the
        // resulting configuration anyway, but only after the peer had been
        // installed — leaving an entry that is permanently unreachable
        // rather than one that was never accepted.
        if info.relay == Some(info.public_key) {
            return Err(Error::InvalidResolverAnswer);
        }
        // A default route is still refused. Not to protect pinned space —
        // overlap is allowed now — but because `/0` cannot be expressed as a
        // resolvable assignment: it matches every `by-address` query, so it
        // would suppress every future lookup and pin all routing to whichever
        // peer happened to claim it first.
        if info.address.network_length() == 0 {
            return Err(Error::InvalidResolverAnswer);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn upsert_peer(
        &mut self,
        info: &ResolvedPeer,
        now: Instant,
    ) -> Result<(PeerIdx, bool), Error> {
        let info = self.canonicalize_resolved_answer(
            ResolveQuery::ByPublicKey(info.public_key),
            info.clone(),
        )?;
        let (pidx, routes_changed, _) =
            self.upsert_peer_unchecked(&info, now, PeerAdmission::AuthenticatedInitiator)?;
        Ok((pidx, routes_changed))
    }

    #[cfg(test)]
    pub(super) fn upsert_outbound_lazy_peer(
        &mut self,
        info: &ResolvedPeer,
        now: Instant,
    ) -> Result<(PeerIdx, bool), Error> {
        let info = self.canonicalize_resolved_answer(
            ResolveQuery::ByPublicKey(info.public_key),
            info.clone(),
        )?;
        let (pidx, routes_changed, _) =
            self.upsert_peer_unchecked(&info, now, PeerAdmission::LazyOutbound)?;
        Ok((pidx, routes_changed))
    }

    /// Insert or refresh a dynamic peer after resolver policy was checked.
    /// Returns `(peer, routes_changed, installed_new)`.
    fn upsert_peer_unchecked(
        &mut self,
        info: &ResolvedPeer,
        now: Instant,
        admission: PeerAdmission,
    ) -> Result<(PeerIdx, bool, bool), Error> {
        if let Some(pidx) = self.find_peer(&info.public_key) {
            let mut persistent_deadline = None;
            let (policy_changed, routes_changed) = {
                let Some(peer) = self.peers.get_mut(pidx as usize).and_then(Option::as_mut) else {
                    return Err(Error::InvalidResolverAnswer);
                };
                // Resolver records are complete replacements. In particular,
                // an omitted endpoint clears a previously held endpoint, and
                // a newly accepted endpoint is not overridden by a locally
                // roamed/confirmed value from the previous record. Liveness
                // confirmation is local metadata, so it can survive only when
                // it still refers to the exact endpoint the new record names.
                if peer.endpoint != info.endpoint {
                    peer.endpoint = info.endpoint;
                    peer.endpoint_confirmed = None;
                }
                let policy_changed = peer.inbound_policy != info.inbound_policy;
                let routes_changed = peer.address != info.address;
                peer.relay = info.relay;
                peer.inbound_policy = info.inbound_policy;
                let persistent_keepalive = info
                    .persistent_keepalive
                    .filter(|interval| interval.as_millis() != 0);
                if peer.persistent_keepalive != persistent_keepalive {
                    peer.persistent_keepalive = persistent_keepalive;
                    peer.sessions.persistent_keepalive_due =
                        persistent_keepalive.map(|interval| now + interval);
                    persistent_deadline = peer.sessions.persistent_keepalive_due;
                }
                // Address ownership is committed only after the route-cache
                // replacement has been fully preflighted and installed.
                (policy_changed, routes_changed)
            };
            if let Some(deadline) = persistent_deadline {
                self.timers.arm(deadline);
            }
            if policy_changed {
                // Policy changes invalidate conntrack, but cryptographic sessions remain valid.
                self.firewall.remove_peer(pidx);
            }
            return Ok((pidx, routes_changed, false));
        }
        if self.peer_is_ghosted(&info.public_key, now) {
            debug!("peer admission suppressed by recently-evicted ghost");
            return Err(Error::PeerAdmissionLimited);
        }

        let free_index = self.peers.iter().position(|peer| peer.is_none());
        let free = self.peers.iter().filter(|peer| peer.is_none()).count();
        let authenticated = matches!(admission, PeerAdmission::AuthenticatedInitiator);
        let lazy = matches!(
            admission,
            PeerAdmission::LazyOutbound | PeerAdmission::LazyRelay
        );

        // Lazy records are a cache, not an entitlement to all peer slots. They
        // may use only capacity above the protected reserve. A cryptographically
        // authenticated unknown initiator can consume a reserved free slot.
        if authenticated || free > self.core_config.lazy_peer_reserve {
            if let Some(i) = free_index {
                let peer = PeerEntry::new(
                    info.public_key,
                    PeerKind::Dynamic,
                    *crate::crypto::dh(&self.s_priv, &info.public_key)?,
                    info.endpoint,
                    info.relay,
                    info.inbound_policy,
                    info.persistent_keepalive,
                    info.address,
                    now,
                );
                self.install_peer(i as PeerIdx, peer)?;
                return Ok((i as PeerIdx, true, true));
            }
        }

        // A held-peer update is existing-only. A stale invalidation must never
        // turn into a fresh admission after the original peer was removed.
        if matches!(admission, PeerAdmission::HeldUpdate) {
            return Err(Error::InvalidResolverAnswer);
        }

        // Relay-triggered admissions are deliberately non-evicting. If there
        // is no unreserved free slot, the submitter must retry after capacity
        // becomes naturally available.
        if matches!(admission, PeerAdmission::LazyRelay) {
            debug!("relay peer admission denied by protected reserve or capacity");
            return Err(Error::PeerAdmissionLimited);
        }

        // Authenticated initiators and local outbound lazy lookups may displace
        // only an idle dynamic peer carrying no handshake or established-session
        // generation. A lazy outbound lookup can swap one cache entry for
        // another while leaving protected free slots untouched.
        //
        // Documented caveat: eviction forgets `greatest_ts`, leaving the same
        // bounded replay window as a responder restart (§5.1); the TAI64N
        // monotonicity of initiators bounds the damage.
        let route_shortage = 1usize.saturating_sub(self.routes.available_slots());
        let selected = [None; MAX_PEERS];
        let Some(i) = self
            .capacity_victim_excluding(now, None, &selected, 0, route_shortage)
            .map(|pidx| pidx as usize)
        else {
            // A table victim is accepted only when removing that same peer also
            // makes the newcomer's route fit. This keeps peer-table
            // and route-cache admission one destructive transaction.
            return Err(if lazy {
                Error::PeerAdmissionLimited
            } else {
                Error::PeerTableFull
            });
        };
        let peer = PeerEntry::new(
            info.public_key,
            PeerKind::Dynamic,
            *crate::crypto::dh(&self.s_priv, &info.public_key)?,
            info.endpoint,
            info.relay,
            info.inbound_policy,
            info.persistent_keepalive,
            info.address,
            now,
        );
        self.evict_peer_for_capacity(i as PeerIdx, now)?;
        self.install_peer(i as PeerIdx, peer)?;
        Ok((i as PeerIdx, true, true))
    }

    fn capacity_victim_excluding(
        &self,
        now: Instant,
        exclude: Option<PeerIdx>,
        selected: &[Option<PeerIdx>; MAX_PEERS],
        selected_len: usize,
        minimum_routes_to_free: usize,
    ) -> Option<PeerIdx> {
        let min_idle = self.core_config.dynamic_peer_min_idle;
        self.peers
            .iter()
            .enumerate()
            .filter_map(|(index, peer)| peer.as_ref().map(|peer| (index as PeerIdx, peer)))
            .filter(|(pidx, peer)| {
                Some(*pidx) != exclude
                    && !selected[..selected_len].contains(&Some(*pidx))
                    && !peer.is_pinned()
                    && peer.sessions.slots().into_iter().all(|slot| slot.is_none())
                    && now.saturating_since(peer.last_activity) >= min_idle
                    && self.routes.peer_route_count(*pidx) >= minimum_routes_to_free
            })
            .min_by_key(|(_, peer)| peer.last_activity)
            .map(|(pidx, _)| pidx)
    }

    fn evict_peer_for_capacity(&mut self, pidx: PeerIdx, now: Instant) -> Result<(), Error> {
        if !self.peer_evictions.try_take(now) {
            debug!("peer capacity eviction denied by global cooldown");
            return Err(Error::PeerAdmissionLimited);
        }
        self.evict_peer_and_remember(pidx, now)
    }

    fn evict_peer_and_remember(&mut self, pidx: PeerIdx, now: Instant) -> Result<(), Error> {
        let Some(public_key) = self
            .peers
            .get(pidx as usize)
            .and_then(Option::as_ref)
            .map(|peer| peer.public_key)
        else {
            return Ok(());
        };
        self.evict_peer(pidx)?;
        self.remember_evicted_peer(public_key, now);
        Ok(())
    }

    fn peer_is_ghosted(&mut self, public_key: &[u8; 32], now: Instant) -> bool {
        let limit = self
            .core_config
            .peer_eviction_ghost_entries
            .min(self.evicted_peer_ghosts.len());
        for index in 0..limit {
            if matches!(
                self.evicted_peer_ghosts[index],
                Some(entry) if entry.expires <= now
            ) {
                self.evicted_peer_ghosts[index] = None;
            }
        }
        self.evicted_peer_ghosts[..limit]
            .iter()
            .flatten()
            .any(|entry| &entry.public_key == public_key)
    }

    fn remember_evicted_peer(&mut self, public_key: [u8; 32], now: Instant) {
        let limit = self
            .core_config
            .peer_eviction_ghost_entries
            .min(self.evicted_peer_ghosts.len());
        let ttl = self.core_config.peer_eviction_ghost_ttl;
        if limit == 0 || ttl.as_millis() == 0 {
            return;
        }
        let expires = now + ttl;
        for index in 0..limit {
            if self.evicted_peer_ghosts[index].is_some_and(|entry| entry.public_key == public_key) {
                self.evicted_peer_ghosts[index] = Some(EvictedPeerGhost {
                    public_key,
                    expires,
                });
                return;
            }
        }
        for index in 0..limit {
            if self.evicted_peer_ghosts[index].is_none_or(|entry| entry.expires <= now) {
                self.evicted_peer_ghosts[index] = Some(EvictedPeerGhost {
                    public_key,
                    expires,
                });
                return;
            }
        }
        let mut victim = 0usize;
        for index in 1..limit {
            let candidate = self.evicted_peer_ghosts[index]
                .map(|entry| entry.expires)
                .unwrap_or(now);
            let current = self.evicted_peer_ghosts[victim]
                .map(|entry| entry.expires)
                .unwrap_or(now);
            if candidate < current {
                victim = index;
            }
        }
        self.evicted_peer_ghosts[victim] = Some(EvictedPeerGhost {
            public_key,
            expires,
        });
    }

    /// Remove a peer and cascade: free its slots, routes, and parked packets.
    fn evict_peer(&mut self, pidx: PeerIdx) -> Result<(), Error> {
        let slots = match self.peers.get(pidx as usize).and_then(Option::as_ref) {
            Some(peer) => peer.sessions.slots(),
            None => return Ok(()),
        };

        // Validate every reverse index before removing the peer so reverse-index
        // divergence is detected before any peer or slot state is changed.
        for sidx in slots.into_iter().flatten() {
            let slot = self
                .slots
                .get(sidx as usize)
                .ok_or(Error::InternalInvariant)?;
            if self.slot_owner(sidx) != Some(pidx) {
                return Err(Error::InternalInvariant);
            }
            if let Some(index) = slot.local_index()
                && self.session_indices.slot_for(index) != Some(sidx)
            {
                return Err(Error::InternalInvariant);
            }
        }

        let Some(peer) = self.take_peer(pidx)? else {
            return Ok(());
        };
        for sidx in peer.sessions.slots().into_iter().flatten() {
            let local_index = self
                .slots
                .get(sidx as usize)
                .ok_or(Error::InternalInvariant)?
                .local_index();
            if let Some(index) = local_index {
                self.session_indices.remove(index, sidx)?;
            }
            *self
                .slots
                .get_mut(sidx as usize)
                .ok_or(Error::InternalInvariant)? = Slot::Free;
        }
        self.routes.remove_peer(pidx)?;
        self.firewall.remove_peer(pidx);
        self.pending.drop_if(|p| p.wait == Wait::Handshake(pidx));
        if !peer.is_pinned() {
            self.queue_peer_evicted(peer.public_key);
        }
        Ok(())
    }

    /// Report release of resolver interest created by an answer the core did
    /// not keep.
    ///
    /// Resolver integrations establish local interest before returning a positive
    /// answer to the core. When admission, policy, or capacity says no, that
    /// interest would otherwise outlive every local trace of the peer.
    fn discard_answer(&mut self, public_key: &[u8; 32]) {
        // A positive resolver completion has already established local interest
        // for this key. If this particular answer is rejected, release that interest
        // even when an older local record for the same key is still retained.
        // Reconciliation can establish fresh local interest later; keeping the
        // rejected answer's interest would leave resolver-side state that the core explicitly
        // declined to accept.
        self.queue_peer_evicted(*public_key);
    }

    fn queue_peer_evicted(&mut self, public_key: [u8; 32]) {
        if self.pending_peer_evictions.contains(&public_key) {
            return;
        }
        #[cfg(feature = "alloc")]
        self.pending_peer_evictions.push(public_key);
        #[cfg(not(feature = "alloc"))]
        {
            let _ = self.pending_peer_evictions.push(public_key);
        }
    }

    fn alloc_resolve_id(&mut self) -> ResolveId {
        loop {
            let id = ResolveId(self.next_resolve_id);
            self.next_resolve_id = self.next_resolve_id.wrapping_add(1);
            if !self.resolves.iter().any(|entry| entry.id == id) {
                return id;
            }
        }
    }

    /// Whether a fresh resolver lookup for `query` should be suppressed:
    /// either a request is already in flight, or an authoritative "no such
    /// peer" answer is still being honoured (an unexpired [`ResolveKind::Negative`]
    /// entry). Expired negatives do not suppress; the timer sweep reclaims them.
    ///
    /// This is the single check that replaces both the former in-flight dedup
    /// scan and the `RouteCache::is_negative_*` lookups.
    pub(super) fn resolve_suppressed(&self, query: ResolveQuery, now: Instant) -> bool {
        self.resolves.iter().any(|r| {
            r.query == query
                && match r.kind {
                    ResolveKind::Negative => r.deadline > now,
                    _ => true,
                }
        })
    }

    /// Record an authoritative "no such peer" for `query`, suppressing repeat
    /// lookups until `now + negative_ttl`. Best effort: the marker is skipped
    /// only when every slot holds a live (non-negative) resolve, which is
    /// self-correcting since those complete or lapse quickly.
    ///
    /// At most one entry ever exists per query, and the live entry that
    /// produced this answer was already removed when its completion was applied, so the
    /// retain is a defensive no-op in the common path (and clears a stale
    /// negative in the pathological one).
    fn mark_negative(&mut self, query: ResolveQuery, now: Instant) {
        self.resolves.retain(|r| r.query != query);
        let id = self.alloc_resolve_id();
        let _ = self.try_push_resolve(InflightResolve {
            id,
            query,
            kind: ResolveKind::Negative,
            deadline: now + self.core_config.negative_ttl,
            emitted: true, // spent: never emitted as a request
        });
    }

    /// Drop any negative marker for `query` (a target we previously could not
    /// resolve just resolved positively). Live resolves are left untouched.
    fn clear_negative(&mut self, query: ResolveQuery) {
        self.resolves
            .retain(|r| !(matches!(r.kind, ResolveKind::Negative) && r.query == query));
    }

    /// Push a *live* resolve, evicting the soonest-to-expire negative marker if
    /// the table is otherwise full. Negatives are low value — a suppressed
    /// junk lookup — and must never deny a real query a slot, which preserves
    /// the isolation the separate negative caches used to provide.
    fn push_resolve(&mut self, entry: InflightResolve) -> Result<(), Error> {
        if self.try_push_resolve(entry).is_ok() {
            return Ok(());
        }
        let victim = self
            .resolves
            .iter()
            .enumerate()
            .filter(|(_, r)| matches!(r.kind, ResolveKind::Negative))
            .min_by_key(|(_, r)| r.deadline)
            .map(|(index, _)| index);
        let Some(index) = victim else {
            return Err(Error::ResolverBusy);
        };
        self.resolves.swap_remove(index);
        self.try_push_resolve(entry)
    }

    /// Append to the resolve table, enforcing `MAX_INFLIGHT_RESOLVES` under
    /// either storage backend.
    fn try_push_resolve(&mut self, entry: InflightResolve) -> Result<(), Error> {
        // The single funnel for every resolver entry — in-flight queries and
        // negative markers alike — so one arm here covers them all.
        let deadline = entry.deadline;
        #[cfg(feature = "alloc")]
        {
            if self.resolves.len() >= self.core_config.max_inflight_resolves {
                return Err(Error::ResolverBusy);
            }
            self.resolves.push(entry);
            self.timers.arm(deadline);
            Ok(())
        }
        #[cfg(not(feature = "alloc"))]
        {
            if self.resolves.len() >= self.core_config.max_inflight_resolves {
                return Err(Error::ResolverBusy);
            }
            self.resolves.push(entry).map_err(|_| Error::ResolverBusy)?;
            self.timers.arm(deadline);
            Ok(())
        }
    }
}
