//! # microtun-core
//!
//! A sans-IO WireGuard® protocol engine designed for constrained `no_std` /
//! `no_alloc` targets (and equally usable on hosts).
//!
//! The engine implements the protocol described in the WireGuard whitepaper
//! ("WireGuard: Next Generation Kernel Network Tunnel", Jason A. Donenfeld):
//!
//! ## Dynamic peers
//!
//! Unlike a classic WireGuard device, `microtun` does not require all peers to
//! be configured up front. Unknown peers — both inbound (unknown static key in
//! a handshake initiation) and outbound (destination address not in the route
//! cache) — cause the engine to emit a [`ResolveRequest`] through [`Sink::resolve`].
//! The embedding answers later through [`Core::resolver_event_completed`]. Resolver
//! integrations retain local interest in accepted dynamic peer keys and may feed
//! unsolicited authoritative updates back through [`Core::resolver_event_completed`].
//! When the core releases a resolver-backed dynamic peer record it reports
//! [`Event::PeerEvicted`] through [`Sink::event`]; resolver integrations use that
//! observation to forget the key locally. No Peers API unsubscribe RPC is needed.
//! Authoritative misses use a short local negative TTL. The Peers API server wire integration — JSON-RPC methods, parameters, and
//! record decoding — lives in the separate `microtun-api` crate; nothing in
//! this one knows how an answer arrived.
//!
//! ## Runtime configuration
//!
//! [`CoreConfig`] carries per-engine resolver/cache lifetimes, firewall flow
//! lifetimes and active capacities, overload thresholds, and rate-limit budgets.
//! [`CoreConfig::default`] applies the hardened operational policy, while
//! [`Config::with_core_config`] selects different operational policy for one
//! engine. WireGuard protocol constants and const-generic peer/session/route
//! capacities remain compile-time fixed; rate and firewall active limits are
//! runtime settings below backend-specific compile-time ceilings.
//!
//! ## Sans-IO contract
//!
//! [`Core`] never performs IO. Its default synchronous API never blocks; with
//! the `async` feature it may suspend only while awaiting the embedding's
//! [`Sink`]. It owns a [`RelayPolicy`] (what may be forwarded), while the
//! embedding passes a sink (where
//! outputs go) to one named method per stimulus:
//!
//! ```text
//!   plaintext IP packet out ─► Core::send_inner              ─┐   ┌─► Sink::outer_datagram
//!   encrypted datagram in   ─► Core::receive_outer           ─┤   ├─► Sink::inner_packet
//!   resolver event in       ─► Core::resolver_event_completed ─┤   ├─► Sink::event
//!   deadline fired          ─► Core::handle_timeout           ─┘   └─► Sink::resolve
//!                                      Core::poll_at ─────► next deadline
//! ```
//!
//! Borrowed packet output is delivered through the sink before the stimulus
//! call completes, with no packet-output queue or allocation. Resolver requests
//! are also offered through the sink; when the non-blocking resolver callback
//! returns `false`, the core retains that request and retries it on a later
//! sink-bearing call. Dynamic peer removals are reported as non-blocking events;
//! the embedding owns any retry/backpressure policy needed to turn those events
//! into resolver-side local forget operations. By default the sink packet methods and
//! core stimulus methods are synchronous. Enabling the `async` feature changes
//! the packet sink methods and core stimulus methods in place to native async
//! trait methods and async functions; [`Sink::resolve`] and [`Sink::event`]
//! remain synchronous, non-blocking hooks. It does not create a
//! parallel API.
//! [`Core::handle_timeout`] processes at most one due
//! timer action; whenever it processed one, [`Core::poll_at`] stays at or
//! before the current instant, so an embedding dispatches that call's output
//! and comes straight back. A call that returns `false` is the signal that the
//! due work is drained. Time is passed in explicitly as a monotonic
//! [`Instant`]; wall-clock time (needed for TAI64N handshake timestamps) is
//! injected via [`Core::set_unix_time`] and extrapolated monotonically.
//!
//! The embedding also drives the clock: consult [`Core::poll_at`] after every
//! call and invoke [`Core::handle_timeout`] at the returned instant. Because
//! that means once per packet, `poll_at` is `O(1)` — it reads a cached bound
//! rather than walking the timer state. The bound is deliberately
//! conservative: it may sit earlier than the true deadline, so an embedding
//! must treat a wake as "something *may* be due" rather than a guarantee.
//!
//! ## Const parameters
//!
//! * `MAX_PEERS` — maximum peers (pinned + dynamic)
//! * `MAX_SESSIONS` — maximum session slots (shared by in-flight
//!   handshakes and live sessions)
//! * `REPLAY_WORDS` — 64-bit replay bitmap words retained per live session
//! * `MAX_ROUTES` — maximum cached routes; on no-alloc builds the prefix trie
//!   derives its fixed storage directly from this value
//!
//! A sensible ESP32-C3 starting point is `MAX_PEERS = 8`,
//! `MAX_SESSIONS = 8`, `REPLAY_WORDS = 128`, and `MAX_ROUTES = 16`.
//!
//! ## Session indices
//!
//! Every local receiver index is a freshly sampled random `u32`. A
//! fixed-capacity map takes those wire values back to the session slot that
//! owns them — an allocation-free [`heapless::index_map::IndexMap`] by
//! default, a `BTreeMap` under the `alloc` feature. Indices are removed as
//! soon as their slot is freed, so stale receiver indices stop resolving.
//!
//! ## Storage backends
//!
//! By default every pool, table and buffer is a fixed-capacity inline array
//! sized by the const parameters — nothing is allocated and a [`Core`] can
//! live in a `static`. Enabling the `alloc` feature keeps the peer/session/route
//! parameters and every bound they enforce, moves their storage behind the
//! global allocator, and selects larger bounded defaults for the source-rate
//! and firewall tables. A [`Core`] value itself becomes pointer-sized
//! bookkeeping rather than hundreds of kilobytes of inline arrays. Both
//! backends index static
//! public keys to stable peer slots: no-allocator builds use a fixed-capacity
//! [`heapless::index_map::IndexMap`], while allocator-backed builds use a
//! `hashbrown::HashMap`. Hosts (`microtun-std`) use the latter.
//! `microtun-embassy` stays on the allocator-free backend by default, but its
//! optional `alloc` feature forwards
//! to this one for heap-capable MCUs where keeping the large protocol state off
//! task stacks matters. The switch is per-site `#[cfg]`, not
//! an abstraction layer: the protocol logic is identical.
//!
//! WireGuard is a registered trademark of Jason A. Donenfeld. This project is
//! not sponsored or endorsed by him.

#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]

#[cfg(feature = "alloc")]
extern crate alloc;

// ---------------------------------------------------------------------------
// Modules
// ---------------------------------------------------------------------------

pub mod config;
mod constants;
mod cookie;
mod crypto;
mod error;
pub mod firewall;
pub mod ip;
pub mod key;
mod messages;
mod noise;
mod peer;
mod pending;
pub mod prefix_trie;
mod rate;
pub mod relay;
mod replay;
pub mod resolver;
mod routing;
mod session;
mod session_index;
pub mod time;

use core::net::SocketAddr;

pub use cidr::{IpCidr, IpInet};
pub use config::{Config, CoreConfig, PinnedPeer};
/// Derive the static public key for a private key.
///
/// Re-exported so host applications can present, check, or configure the
/// device's identity without duplicating the Curve25519 base-point
/// multiplication (or taking their own `x25519-dalek` dependency).
pub use crypto::public_key;
// Logging. These compile to no-ops unless `defmt-or-log` has one of its
// backends selected, which the crate's own `defmt` / `log` features do.
use defmt_or_log::{debug, error, info, trace, warn};
pub use error::Error;
pub use resolver::{
    PeerUpdate, ResolveId, ResolveOutcome, ResolveQuery, ResolveRequest, ResolveResponse,
    ResolvedPeer, ResolverCommand, ResolverEvent,
};
pub use time::{Duration, Instant};
use zeroize::Zeroizing;

use crate::{
    constants::*,
    cookie::CookieSecret,
    crypto::{TIMESTAMP_LEN, aead_open, aead_seal, dh, tai64n},
    firewall::{Firewall, InboundPolicy, MAX_FIREWALL_FLOWS},
    ip::unmap_socket_addr,
    messages::{COOKIE_REPLY_LEN, INITIATION_LEN, Message, RESPONSE_LEN},
    noise::InitiatorState,
    peer::{PeerEntry, PeerKind},
    pending::{PendingPool, Wait},
    rate::{IntervalBudget, RateLimiter, TokenBucket},
    resolver::{InflightResolve, PendingReconcile},
    routing::{PeerIdx, RouteCache},
    session::{Role, Session, SlotIdx},
    session_index::SessionIndexMap,
    time::{TimerCache, min_deadline},
};

// ---------------------------------------------------------------------------
// Public limits and shared storage
// ---------------------------------------------------------------------------

/// Maximum active resolver entries accepted by [`CoreConfig`].
pub const MAX_CORE_INFLIGHT_RESOLVES: usize = constants::MAX_INFLIGHT_RESOLVES;

/// Maximum active per-source rate-limit buckets accepted by [`CoreConfig`].
pub const MAX_CORE_RATE_LIMIT_ENTRIES: usize = constants::MAX_RATE_LIMIT_ENTRIES;

/// Maximum recently capacity-evicted peer identities retained by [`CoreConfig`].
pub const MAX_CORE_PEER_EVICTION_GHOSTS: usize = constants::MAX_PEER_EVICTION_GHOSTS;

/// Maximum outer UDP payload the engine will produce or accept.
///
/// Sized for a 1500-byte physical MTU with outer IPv4/UDP headroom — the
/// classic WireGuard wire budget. This is independent of the *inner* tunnel
/// MTU (which defaults to 1280 in the shells); the whole outer datagram is
/// kept ≤ `MAX_UDP_SIZE`.
pub const MAX_UDP_SIZE: usize = 1500;

/// Maximum *inner* IP packet (plaintext) length the engine will encapsulate:
/// `MAX_UDP_SIZE` minus the 32-byte transport overhead (16 header + 16 tag),
/// rounded down to the 16-byte padding granularity of §5.4.6.
pub const MAX_INNER_SIZE: usize = (MAX_UDP_SIZE - messages::DATA_OVERHEAD) & !15;

/// Maximum tunnel address prefixes carried by one peer without `alloc`.
///
/// Allocator-backed peers have no separate per-peer cap. Resolver answers are
/// canonicalized and deduplicated at the core boundary, and their unique
/// prefixes must fit the route-cache ceiling.
pub const MAX_PEER_ADDRESSES: usize = 4;

/// The tunnel address list carried by a peer record.
///
/// A `heapless::Vec` inline in the peer entry by default; a heap `Vec` under
/// `alloc`. Build one with [`push_peer_address`] to stay backend-agnostic.
#[cfg(feature = "alloc")]
pub type PeerAddresses = alloc::vec::Vec<IpCidr>;

/// The tunnel address list carried by a peer record.
///
/// A `heapless::Vec` inline in the peer entry by default; a heap `Vec` under
/// `alloc`. Build one with [`push_peer_address`] to stay backend-agnostic.
#[cfg(not(feature = "alloc"))]
pub type PeerAddresses = heapless::Vec<IpCidr, MAX_PEER_ADDRESSES>;

/// Append one canonical prefix to a [`PeerAddresses`]. Duplicate prefixes are
/// ignored. Without `alloc`, the unique set is bounded by
/// [`MAX_PEER_ADDRESSES`].
pub fn push_peer_address(addresses: &mut PeerAddresses, cidr: IpCidr) -> Result<(), Error> {
    // No canonicalization step here any more: `IpCidr` cannot represent a
    // prefix with host bits set, so the value arrived canonical and equal
    // prefixes compare equal. Text that may carry host bits is normalized once,
    // at the parse boundary, by `ip::parse_ip_cidr`.
    if addresses.contains(&cidr) {
        return Ok(());
    }
    #[cfg(feature = "alloc")]
    {
        addresses.push(cidr);
        Ok(())
    }
    #[cfg(not(feature = "alloc"))]
    {
        addresses.push(cidr).map_err(|_| Error::TooManyAddresses)
    }
}

// ---------------------------------------------------------------------------
// Embedding interface
// ---------------------------------------------------------------------------

/// Runtime observations emitted by the protocol engine.
///
/// Events describe authenticated protocol state and lifecycle transitions
/// observed while processing a stimulus. They are observations only: delivering
/// an event does not mutate resolver or configuration state. The enum is
/// non-exhaustive so the core can add new observations without growing [`Sink`]
/// with one callback per event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// Authenticated direct traffic established or changed a peer's endpoint.
    ///
    /// The first authenticated endpoint is reported even when it equals the
    /// configured value. Repeated traffic from an already-confirmed endpoint is
    /// coalesced. Relayed peers do not produce this event because their outer
    /// source belongs to the relay.
    PeerEndpointUpdate {
        /// Static public key identifying the peer.
        public_key: [u8; 32],
        /// Authenticated outer UDP source for the peer.
        endpoint: SocketAddr,
    },
    /// The core released a resolver-backed dynamic peer record.
    ///
    /// Resolver integrations that retain local interest in positive answers
    /// should translate this event into their local forget operation. It is also
    /// emitted when such an answer is rejected before admission, so resolver-side
    /// interest cannot outlive the core record.
    PeerEvicted {
        /// Static public key identifying the released peer record.
        public_key: [u8; 32],
    },
}

/// Where the engine sends its immediate output.
///
/// The slices borrow the engine's internal buffers and are valid only for the
/// duration of the callback. In the default build packet callbacks are
/// synchronous and must not block. With the `async` feature, the packet methods
/// are native async trait methods and the core awaits each callback before
/// reusing its buffers. Resolver and observation callbacks remain synchronous
/// in both modes so they can be implemented as non-blocking queue operations.
///
/// The two packet methods are named for the layer they carry rather than for
/// a direction: an *outer datagram* is encrypted WireGuard traffic on the
/// physical network, an *inner packet* is plaintext IP inside the tunnel.
#[allow(async_fn_in_trait)]
#[cfg_attr(not(feature = "async"), maybe_async::must_be_sync)]
pub trait Sink {
    /// Send an encrypted WireGuard datagram to the outer network.
    async fn outer_datagram(&mut self, destination: SocketAddr, datagram: &[u8]);

    /// Deliver a decrypted, cryptokey-routed inner IP packet to the local
    /// stack.
    ///
    /// `src_peer_key` is the authenticated static public key of the
    /// peer whose WireGuard session carried the packet. `src_endpoint` is the
    /// authenticated outer UDP source for a directly connected peer, and is
    /// `None` for relayed peers. Like `packet`, the references are valid only
    /// for the duration of this call.
    async fn inner_packet(
        &mut self,
        src_peer_key: &[u8; 32],
        src_endpoint: Option<SocketAddr>,
        packet: &[u8],
    );

    /// Submit one peer-resolution lookup requested by the core.
    ///
    /// This callback is synchronous deliberately. Resolver traffic may itself
    /// traverse the tunnel, so awaiting resolver-channel capacity here can
    /// deadlock the packet path. Return `true` only after the embedding has
    /// accepted the request for eventual execution. Returning `false` keeps it
    /// pending in the core and retries it through a later sink call.
    fn resolve(&mut self, request: ResolveRequest) -> bool;

    /// Observe protocol state or lifecycle changes produced by a stimulus.
    ///
    /// Event delivery is synchronous deliberately: observing protocol state must
    /// not add backpressure to packet processing. Embeddings that need async
    /// delivery should record the latest value or enqueue it without waiting.
    fn event(&mut self, _event: Event) {}
}

/// Decides which relay envelopes this device is willing to forward.
///
/// The engine consults the policy only after the hop-local relay packet has
/// been authenticated under a configured peer's session and the relay envelope
/// has passed its syntactic checks. The source identity is authenticated
/// and the requested destination key is integrity-protected. The policy never
/// sees UDP addresses — only static public keys.
///
/// Forwarding is opt-in: use [`StaticRelayPolicy::DenyAll`] (its [`Default`])
/// unless this device is meant to act as a relay.
pub trait RelayPolicy {
    /// May an envelope submitted by `source` be forwarded toward
    /// `destination`?
    fn authorize_relay(&mut self, source: &[u8; 32], destination: &[u8; 32]) -> bool;
}

/// The all-or-nothing [`RelayPolicy`] (relay spec §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StaticRelayPolicy {
    /// Never forward: this device is not a relay. The default.
    #[default]
    DenyAll,
    /// Forward every authenticated source-to-destination pair.
    AllowAll,
}

impl StaticRelayPolicy {
    /// [`Self::AllowAll`] when `enabled`, [`Self::DenyAll`] otherwise.
    pub const fn forwarding(enabled: bool) -> Self {
        if enabled {
            Self::AllowAll
        } else {
            Self::DenyAll
        }
    }
}

impl RelayPolicy for StaticRelayPolicy {
    fn authorize_relay(&mut self, _source: &[u8; 32], _destination: &[u8; 32]) -> bool {
        matches!(self, Self::AllowAll)
    }
}

// ---------------------------------------------------------------------------
// Internal state
// ---------------------------------------------------------------------------

struct Initiating {
    peer: PeerIdx,
    /// Our receiver index for this handshake attempt. It stays stable across
    /// retransmissions and is copied into the established session.
    local_index: u32,
    noise: InitiatorState,
    /// Stable, per-attempt retransmission deadline. The random jitter is
    /// sampled when the initiation is built rather than from `poll_at()`, so
    /// repeated polls cannot move the timer.
    retry_at: Instant,
}

#[allow(clippy::large_enum_variant)]
enum Slot<const REPLAY_WORDS: usize> {
    Free,
    /// We are the initiator; awaiting a handshake response.
    Initiating(Initiating),
    Established(Session<REPLAY_WORDS>),
}

impl<const REPLAY_WORDS: usize> Slot<REPLAY_WORDS> {
    fn is_free(&self) -> bool {
        matches!(self, Slot::Free)
    }

    fn local_index(&self) -> Option<u32> {
        match self {
            Slot::Initiating(handshake) => Some(handshake.local_index),
            Slot::Established(session) => Some(session.local_index),
            Slot::Free => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct WallClock {
    base_unix_nanos: u64,
    base_instant: Instant,
}

#[derive(Debug, Clone, Copy)]
struct EvictedPeerGhost {
    public_key: [u8; 32],
    expires: Instant,
}

/// The sans-IO WireGuard engine. See the crate-level documentation.
///
/// `REPLAY_WORDS` is the number of 64-bit bitmap words retained per established
/// session; one word is reserved for recycling, so 128 words accepts packets up
/// to 8,128 counters behind the high-water mark. `MAX_ROUTES` sizes both
/// the route slots and, on allocation-free builds, the prefix-trie storage
/// needed to index them.
pub struct Core<
    RNG,
    RP,
    const MAX_PEERS: usize,
    const MAX_SESSIONS: usize,
    const REPLAY_WORDS: usize,
    const MAX_ROUTES: usize,
> where
    RP: RelayPolicy,
{
    rng: RNG,
    relay_policy: RP,
    core_config: CoreConfig,
    s_priv: Zeroizing<[u8; 32]>,
    s_pub: [u8; 32],
    /// `Hash(Label-Mac1 ‖ our_pub)` — verifies mac1 on messages sent *to* us.
    our_mac1_key: [u8; 32],
    /// `Hash(Label-Cookie ‖ our_pub)` — encrypts cookie replies we send.
    our_cookie_key: [u8; 32],

    /// Peer table and slot pool. Under `alloc` these are heap `Vec`s
    /// pre-filled with `MAX_PEERS` / `MAX_SESSIONS` empty entries rather
    /// than inline arrays, so stable [`PeerIdx`] / [`SlotIdx`] handles and
    /// `0..MAX_PEERS` loops are unchanged.
    /// Public keys are indexed back to stable peer slots, avoiding a full
    /// table scan on every identity lookup. Embedded builds use an inline,
    /// fixed-capacity `heapless::IndexMap`; host builds use `hashbrown`.
    #[cfg(not(feature = "alloc"))]
    peers: [Option<PeerEntry>; MAX_PEERS],
    #[cfg(feature = "alloc")]
    peers: alloc::vec::Vec<Option<PeerEntry>>,
    #[cfg(not(feature = "alloc"))]
    peers_by_public_key: heapless::index_map::FnvIndexMap<[u8; 32], PeerIdx, MAX_PEERS>,
    #[cfg(feature = "alloc")]
    peers_by_public_key: hashbrown::HashMap<[u8; 32], PeerIdx>,
    #[cfg(not(feature = "alloc"))]
    slots: [Slot<REPLAY_WORDS>; MAX_SESSIONS],
    #[cfg(feature = "alloc")]
    slots: alloc::vec::Vec<Slot<REPLAY_WORDS>>,
    session_indices: SessionIndexMap<MAX_SESSIONS>,

    routes: RouteCache<MAX_ROUTES>,
    /// Cached lower bound on the next timer deadline, so that `poll_at` — which
    /// embeddings call after every single packet — does not have to walk the
    /// peer table, the slot pool, the parked packets and the resolver table.
    timers: TimerCache,
    pending: PendingPool<2>,
    #[cfg(not(feature = "alloc"))]
    resolves: heapless::Vec<InflightResolve, MAX_INFLIGHT_RESOLVES>,
    #[cfg(feature = "alloc")]
    resolves: alloc::vec::Vec<InflightResolve>,
    /// Released resolver-backed records waiting to be reported as events.
    #[cfg(not(feature = "alloc"))]
    pending_peer_evictions: heapless::Vec<[u8; 32], MAX_PEERS>,
    #[cfg(feature = "alloc")]
    pending_peer_evictions: alloc::vec::Vec<[u8; 32]>,
    /// Records whose reconciliation is owed but not yet in flight.
    ///
    /// A held-peer update that cannot be installed — because it did not fit,
    /// because it failed policy, or because the lookup itself failed — leaves
    /// the peer holding its previous record. That record is now known to be
    /// possibly stale, so the obligation to ask again has to outlive the
    /// answer that failed; dropping it would leave the peer stale until
    /// something unrelated happened to disturb it. Each entry becomes a fresh
    /// `by-key` resolve once its `due` time passes.
    #[cfg(not(feature = "alloc"))]
    pending_reconciles: heapless::Vec<PendingReconcile, MAX_PEERS>,
    #[cfg(feature = "alloc")]
    pending_reconciles: alloc::vec::Vec<PendingReconcile>,
    next_resolve_id: u64,

    cookie_secret: CookieSecret,
    rate: RateLimiter,
    /// Budget for peer resolutions that remote input can provoke: inbound
    /// initiations from unknown static keys, and relay envelopes naming
    /// unknown destination keys. Neither caller is authorized, and neither
    /// can be attributed to a source address that is worth limiting, so the
    /// limit is on this device's total outbound query rate. Locally driven
    /// lookups — an outbound packet to an unrouted address, plus change tracking
    /// maintenance for records we already hold — are not charged.
    remote_resolves: TokenBucket,
    /// Bounds the second DH and timestamp authentication for identities that
    /// are not installed yet. Separate from resolver-query accounting.
    unknown_authentications: TokenBucket,
    /// Global sub-Hz budget for destructive capacity evictions.
    peer_evictions: IntervalBudget,
    /// Recently capacity-evicted identities, used to reject immediate
    /// re-admission and break cache-thrashing cycles.
    evicted_peer_ghosts: [Option<EvictedPeerGhost>; MAX_PEER_EVICTION_GHOSTS],
    firewall: Firewall<MAX_FIREWALL_FLOWS, MAX_PEERS>,

    wall: Option<WallClock>,
    last_ts: [u8; TIMESTAMP_LEN],

    hs_window_start: Instant,
    hs_window_count: u32,
    hs_prev_count: u32,

    /// Staging buffer for outgoing datagrams.
    ///
    /// Between the plaintext being copied in and `aead_seal` running over it,
    /// this holds an inner IP packet in the clear, and it keeps holding the
    /// tail of the last one until a longer packet overwrites it. Wrapped in
    /// [`Zeroizing`] so the residue does not outlive the engine — matching the
    /// treatment of every other buffer here that has held plaintext or key
    /// material.
    ///
    /// Heap-backed under `alloc` — it is `MAX_UDP_SIZE` bytes either way, but
    /// keeping it out of the `Core` value is most of what makes the engine
    /// movable and cheap to place on a host.
    #[cfg(not(feature = "alloc"))]
    scratch: Zeroizing<[u8; MAX_UDP_SIZE]>,
    #[cfg(feature = "alloc")]
    scratch: Zeroizing<alloc::vec::Vec<u8>>,
    /// Staging buffer for relay envelopes: the sealed inner packet lives in
    /// `scratch` while the envelope around it is built and sealed here.
    /// Zeroized on drop for the same reason as `scratch`.
    #[cfg(not(feature = "alloc"))]
    relay_scratch: Zeroizing<[u8; MAX_UDP_SIZE]>,
    #[cfg(feature = "alloc")]
    relay_scratch: Zeroizing<alloc::vec::Vec<u8>>,
    #[cfg(feature = "alloc")]
    _capacity: core::marker::PhantomData<[(); MAX_PEERS]>,
}

impl<
    RNG,
    RP,
    const MAX_PEERS: usize,
    const MAX_SESSIONS: usize,
    const REPLAY_WORDS: usize,
    const MAX_ROUTES: usize,
> core::fmt::Debug for Core<RNG, RP, MAX_PEERS, MAX_SESSIONS, REPLAY_WORDS, MAX_ROUTES>
where
    RP: RelayPolicy,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Core")
            .field("peers", &self.peers.iter().filter(|p| p.is_some()).count())
            .field(
                "sessions",
                &self
                    .slots
                    .iter()
                    .filter(|s| matches!(s, Slot::Established(_)))
                    .count(),
            )
            .finish_non_exhaustive()
    }
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
    /// Validate fixed-capacity pool parameters before constructing any table.
    fn validate_pool_parameters() -> Result<(), Error> {
        if MAX_PEERS == 0
            || MAX_SESSIONS == 0
            || REPLAY_WORDS == 0
            || MAX_PEERS > PeerIdx::MAX as usize
            || MAX_SESSIONS > SlotIdx::MAX as usize
        {
            return Err(Error::InvalidCapacity);
        }
        #[cfg(not(feature = "alloc"))]
        if MAX_PEERS <= 1
            || !MAX_PEERS.is_power_of_two()
            || MAX_SESSIONS <= 1
            || !MAX_SESSIONS.is_power_of_two()
        {
            return Err(Error::InvalidCapacity);
        }
        Ok(())
    }

    /// Build an engine from `config`. Fails if the pinned peers do not fit
    /// the peer table, per-peer address capacity, or route cache, or if a
    /// runtime implementation limit exceeds its fixed storage ceiling.
    pub fn new(
        config: Config<'_>,
        mut rng: RNG,
        relay_policy: RP,
        now: Instant,
    ) -> Result<Self, Error> {
        Self::validate_pool_parameters()?;
        let Config {
            private_key: s_priv,
            pinned,
            core_config,
        } = config;
        if core_config.rate_limit_entries > MAX_RATE_LIMIT_ENTRIES
            || core_config.firewall_flow_entries > MAX_FIREWALL_FLOWS
            || core_config.firewall_flow_entries == 0
            || core_config.firewall_flows_per_peer == 0
            || core_config.firewall_flows_per_peer > core_config.firewall_flow_entries
            || core_config.max_inflight_resolves > MAX_INFLIGHT_RESOLVES
            || core_config.peer_eviction_ghost_entries > MAX_PEER_EVICTION_GHOSTS
            || core_config.lazy_peer_reserve > MAX_PEERS
        {
            return Err(Error::InvalidCapacity);
        }
        if core_config.resolve_timeout.as_millis() == 0
            || core_config.resolve_outbound_timeout.as_millis() == 0
            || core_config.peer_eviction_interval.as_millis() == 0
            || core_config.peer_eviction_burst == 0
        {
            return Err(Error::InvalidCoreConfig);
        }
        info!(
            "core init: peers={} sessions={} routes={} pinned={}",
            MAX_PEERS,
            MAX_SESSIONS,
            MAX_ROUTES,
            pinned.len()
        );
        if s_priv.iter().all(|byte| *byte == 0) {
            error!("core init failed: static private key is all zeroes");
            return Err(Error::InvalidPrivateKey);
        }
        let s_pub = crate::crypto::public_key(&s_priv);
        if pinned.len() > MAX_PEERS {
            error!("core init failed: pinned peer table overflow");
            return Err(Error::PeerTableFull);
        }
        #[cfg(not(feature = "alloc"))]
        if pinned
            .iter()
            .any(|peer| peer.addresses.len() > MAX_PEER_ADDRESSES)
        {
            return Err(Error::TooManyAddresses);
        }
        for (i, peer) in pinned.iter().enumerate() {
            let previous_peers = &pinned[..i];
            if peer.public_key == s_pub {
                error!(
                    "core init failed: pinned peer {} uses our static public key",
                    i
                );
                return Err(Error::InvalidPinnedConfiguration);
            }
            if previous_peers
                .iter()
                .any(|other| other.public_key == peer.public_key)
            {
                error!(
                    "core init failed: duplicate pinned public key at peer {}",
                    i
                );
                return Err(Error::InvalidPinnedConfiguration);
            }
            if let Some(relay_key) = peer.relay {
                if relay_key == peer.public_key {
                    error!("core init failed: pinned peer {} relays through itself", i);
                    return Err(Error::InvalidPinnedConfiguration);
                }
                let Some(relay) = pinned
                    .iter()
                    .find(|candidate| candidate.public_key == relay_key)
                else {
                    error!("core init failed: pinned peer {} names an unknown relay", i);
                    return Err(Error::InvalidPinnedConfiguration);
                };
                if relay.endpoint.is_none() || relay.relay.is_some() {
                    error!(
                        "core init failed: pinned peer {} relay is not directly reachable",
                        i
                    );
                    return Err(Error::InvalidPinnedConfiguration);
                }
            }
            for cidr in peer.addresses {
                if cidr.network_length() == 0 {
                    error!("core init failed: pinned peer {} owns a default route", i);
                    return Err(Error::InvalidPinnedConfiguration);
                }
                for previous in previous_peers {
                    if previous
                        .addresses
                        .iter()
                        .any(|other| crate::routing::cidrs_overlap(other, cidr))
                    {
                        error!(
                            "core init failed: pinned peer {} overlaps another pinned CIDR",
                            i
                        );
                        return Err(Error::InvalidPinnedConfiguration);
                    }
                }
            }
        }

        let cookie_secret = CookieSecret::new(&mut rng, now);

        let mut core = Self {
            our_mac1_key: cookie::mac1_key(&s_pub),
            our_cookie_key: cookie::cookie_key(&s_pub),
            rng,
            relay_policy,
            core_config,
            s_priv,
            s_pub,
            #[cfg(not(feature = "alloc"))]
            peers: [const { None }; MAX_PEERS],
            #[cfg(feature = "alloc")]
            peers: (0..MAX_PEERS).map(|_| None).collect(),
            #[cfg(not(feature = "alloc"))]
            peers_by_public_key: heapless::index_map::FnvIndexMap::new(),
            #[cfg(feature = "alloc")]
            peers_by_public_key: hashbrown::HashMap::with_capacity(MAX_PEERS),
            #[cfg(not(feature = "alloc"))]
            slots: core::array::from_fn(|_| Slot::Free),
            #[cfg(feature = "alloc")]
            slots: (0..MAX_SESSIONS).map(|_| Slot::Free).collect(),
            session_indices: SessionIndexMap::new(),
            routes: RouteCache::new()?,
            timers: TimerCache::new(),
            pending: PendingPool::new(),
            #[cfg(not(feature = "alloc"))]
            resolves: heapless::Vec::new(),
            #[cfg(feature = "alloc")]
            resolves: alloc::vec::Vec::new(),
            #[cfg(not(feature = "alloc"))]
            pending_peer_evictions: heapless::Vec::new(),
            #[cfg(feature = "alloc")]
            pending_peer_evictions: alloc::vec::Vec::new(),
            #[cfg(not(feature = "alloc"))]
            pending_reconciles: heapless::Vec::new(),
            #[cfg(feature = "alloc")]
            pending_reconciles: alloc::vec::Vec::new(),
            next_resolve_id: 1,
            cookie_secret,
            rate: RateLimiter::new(
                core_config.rate_limit_per_sec,
                core_config.rate_limit_burst,
                core_config.rate_limit_entries,
            ),
            remote_resolves: TokenBucket::new(
                core_config.remote_resolve_per_sec,
                core_config.remote_resolve_burst,
                now,
            ),
            unknown_authentications: TokenBucket::new(
                core_config.unknown_auth_per_sec,
                core_config.unknown_auth_burst,
                now,
            ),
            peer_evictions: IntervalBudget::new(
                core_config.peer_eviction_interval,
                core_config.peer_eviction_burst,
                now,
            ),
            evicted_peer_ghosts: [None; MAX_PEER_EVICTION_GHOSTS],
            firewall: Firewall::with_limits_and_timeouts(
                core_config.firewall_flow_entries,
                core_config.firewall_flows_per_peer,
                core_config.firewall_udp_timeout,
                core_config.firewall_icmp_timeout,
                core_config.firewall_tcp_timeout,
                core_config.firewall_tcp_closing_timeout,
            ),
            wall: None,
            last_ts: [0; TIMESTAMP_LEN],
            hs_window_start: now,
            hs_window_count: 0,
            hs_prev_count: 0,
            #[cfg(not(feature = "alloc"))]
            scratch: Zeroizing::new([0; MAX_UDP_SIZE]),
            #[cfg(feature = "alloc")]
            scratch: Zeroizing::new(alloc::vec![0u8; MAX_UDP_SIZE]),
            #[cfg(not(feature = "alloc"))]
            relay_scratch: Zeroizing::new([0; MAX_UDP_SIZE]),
            #[cfg(feature = "alloc")]
            relay_scratch: Zeroizing::new(alloc::vec![0u8; MAX_UDP_SIZE]),
            #[cfg(feature = "alloc")]
            _capacity: core::marker::PhantomData,
        };

        for (i, p) in pinned.iter().enumerate() {
            let mut addresses = PeerAddresses::new();
            for address in p.addresses.iter().copied() {
                crate::push_peer_address(&mut addresses, address)?;
            }
            core.install_peer(
                i as PeerIdx,
                PeerEntry::new(
                    p.public_key,
                    PeerKind::Pinned,
                    *crate::crypto::dh(&core.s_priv, &p.public_key)?,
                    p.endpoint,
                    p.relay,
                    p.inbound_policy,
                    p.persistent_keepalive,
                    addresses,
                    now,
                ),
            )?;
            for cidr in p.addresses {
                core.routes.insert(*cidr, i as PeerIdx, true, now)?;
            }
        }
        info!("core initialized with {} pinned peers", pinned.len());
        Ok(core)
    }

    /// Our static public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.s_pub
    }

    /// Runtime operational settings used by this engine instance.
    pub fn core_config(&self) -> &CoreConfig {
        &self.core_config
    }

    /// Inject the wall clock (Unix time). Must be called before the first
    /// handshake can be initiated (TAI64N timestamps, §5.4.2); re-call
    /// whenever the RTC is disciplined. The engine extrapolates between
    /// calls using the monotonic clock and enforces that emitted timestamps
    /// never decrease (per-peer replay protection survives our reboots only
    /// if the RTC is roughly sane — see the deployment notes in the README).
    pub fn set_unix_time(&mut self, unix_secs: u64, nanos: u32, now: Instant) {
        debug!(
            "wall clock updated: unix_secs={} nanos={}",
            unix_secs, nanos
        );
        self.wall = Some(WallClock {
            base_unix_nanos: unix_secs
                .saturating_mul(1_000_000_000)
                .saturating_add(nanos as u64),
            base_instant: now,
        });
    }

    /// Has a wall clock been provided?
    pub fn has_wall_clock(&self) -> bool {
        self.wall.is_some()
    }

    /// Send a plaintext inner IP packet through the tunnel.
    pub async fn send_inner<E: Sink>(
        &mut self,
        now: Instant,
        packet: &[u8],
        sink: &mut E,
    ) -> Result<(), Error> {
        trace!(
            "inner packet received from local stack: len={}",
            packet.len()
        );
        let result = self.outbound(now, packet, sink).await;
        self.flush_sink_output(sink);
        result
    }

    /// Feed one encrypted UDP datagram from the outer network to the engine.
    /// IPv4-mapped IPv6 sources are normalized to native IPv4 before any
    /// cookie, rate-limit, roaming, or reply handling. Decryption happens in
    /// place, so `datagram` is left clobbered.
    pub async fn receive_outer<E: Sink>(
        &mut self,
        now: Instant,
        source: SocketAddr,
        datagram: &mut [u8],
        sink: &mut E,
    ) -> Result<(), Error> {
        let source = unmap_socket_addr(source);
        let result = if datagram.len() > MAX_UDP_SIZE {
            debug!(
                "dropping oversized outer datagram: len={} max={}",
                datagram.len(),
                MAX_UDP_SIZE
            );
            Err(Error::PacketTooLarge)
        } else {
            trace!(
                "outer datagram received: len={} port={}",
                datagram.len(),
                source.port()
            );
            self.datagram(now, source, datagram, sink).await
        };
        self.flush_sink_output(sink);
        result
    }

    /// Process at most one protocol timer action due at `now`.
    ///
    /// While this returns `true`, [`Core::poll_at`] remains at or before `now`;
    /// call this method again after the previous call's sink output has been
    /// delivered. Limiting each call to one action keeps timeout fan-out bounded
    /// in both synchronous and asynchronous embeddings.
    ///
    /// The `false` return is therefore load-bearing rather than merely
    /// informational: it marks the end of a wave of due work, and is the one
    /// point at which the engine recomputes an exact next deadline.
    ///
    /// Returns `true` when one due action was processed, or `false` when the
    /// call was spurious and no deadline was due.
    pub async fn handle_timeout<E: Sink>(&mut self, now: Instant, sink: &mut E) -> bool {
        trace!("processing one protocol timer action");
        let handled = if self.timeout(now, sink).await {
            // More work may still be due at `now`. Hold the bound at or before
            // `now` so the embedding comes straight back after delivering this
            // call's sink output. Doing it here rather than relying on the
            // individual arming sites makes the "call again until it returns
            // false" contract hold structurally.
            self.timers.arm(now);
            true
        } else {
            // The bound was reached with nothing due, so it was a stale
            // artefact of a *cleared* timer. This is the one moment precision
            // is needed and the only place the full walk runs.
            let exact = self.scan_deadlines();
            if exact.is_some_and(|deadline| deadline <= now) {
                error!("timer scan found a due deadline after a no-work timeout pass");
            }
            self.timers.set_exact(exact);
            false
        };
        self.flush_sink_output(sink);
        handled
    }

    /// Access the relay policy owned by this core.
    pub fn relay_policy(&self) -> &RP {
        &self.relay_policy
    }

    /// Mutably access the relay policy owned by this core.
    pub fn relay_policy_mut(&mut self) -> &mut RP {
        &mut self.relay_policy
    }

    // -----------------------------------------------------------------------
    // Outbound path
    // -----------------------------------------------------------------------

    async fn outbound<E: Sink>(
        &mut self,
        now: Instant,
        packet: &[u8],
        sink: &mut E,
    ) -> Result<(), Error> {
        if packet.len() > MAX_INNER_SIZE {
            warn!("dropping oversized inner packet: len={}", packet.len());
            return Err(Error::PacketTooLarge);
        }
        let dst = ip::parse_header(packet)
            .ok_or(Error::MalformedIpPacket)?
            .dst;

        if let Some(pidx) = self.routes.lookup(&dst, now) {
            trace!("route cache hit: peer={}", pidx);
            return self.send_to_peer(pidx, packet, now, sink).await;
        }
        self.queue_outbound_resolution(dst, packet, now)
    }

    /// Send an inner packet to a known peer: encrypt if a session is usable,
    /// otherwise park it and make sure a handshake is running.
    async fn send_to_peer<E: Sink>(
        &mut self,
        pidx: PeerIdx,
        packet: &[u8],
        now: Instant,
        sink: &mut E,
    ) -> Result<(), Error> {
        let usable = self.usable_session(pidx, now);
        match usable {
            Some(sidx) => {
                trace!("using established session: peer={} slot={}", pidx, sidx);
                self.encrypt_and_send(pidx, sidx, packet, now, sink).await
            }
            None => {
                debug!(
                    "no usable session; parking packet and starting handshake: peer={}",
                    pidx
                );
                self.pending
                    .park(packet, Wait::Handshake(pidx), now + REKEY_ATTEMPT_TIME);
                self.timers.arm(now + REKEY_ATTEMPT_TIME);
                self.ensure_handshake(pidx, now, sink).await
            }
        }
    }

    /// The peer's current session if it may encrypt right now.
    fn usable_session(&self, pidx: PeerIdx, now: Instant) -> Option<SlotIdx> {
        let peer = self.peers.get(pidx as usize)?.as_ref()?;
        let sidx = peer.sessions.current?;
        match self.slots.get(sidx as usize)? {
            Slot::Established(session) if session.can_send(now) => Some(sidx),
            _ => None,
        }
    }

    /// Encrypt `packet` (may be empty = keepalive) under session `sidx` and
    /// deliver it: directly to the peer's endpoint, or — when the peer has a
    /// configured relay (relay spec §5) — wrapped in a relay transport
    /// message on the hop-local session with the relay.
    async fn encrypt_and_send<E: Sink>(
        &mut self,
        pidx: PeerIdx,
        sidx: SlotIdx,
        packet: &[u8],
        now: Instant,
        sink: &mut E,
    ) -> Result<(), Error> {
        if packet.len() > MAX_INNER_SIZE {
            return Err(Error::PacketTooLarge);
        }
        if let Some(relay_key) = self
            .peers
            .get(pidx as usize)
            .and_then(Option::as_ref)
            .and_then(|peer| peer.relay)
        {
            return self
                .encrypt_via_relay(pidx, sidx, relay_key, packet, now, sink)
                .await;
        }
        let endpoint = self
            .peers
            .get(pidx as usize)
            .and_then(Option::as_ref)
            .and_then(|peer| peer.endpoint)
            .ok_or(Error::NoEndpoint)?;
        let packet_end = messages::data::PACKET_START + packet.len();
        self.scratch[messages::data::PACKET_START..packet_end].copy_from_slice(packet);
        let (total, rekey) =
            self.seal_transport(pidx, sidx, messages::MSG_DATA, packet.len(), false, now)?;
        trace!(
            "sending direct transport datagram: peer={} slot={} len={}",
            pidx, sidx, total
        );
        let datagram = &self.scratch[..total];
        sink.outer_datagram(endpoint, datagram).await;
        self.note_outbound_flow(pidx, packet, now);
        if rekey {
            let _ = self.ensure_handshake(pidx, now, sink).await;
        }
        Ok(())
    }

    /// Relayed send: seal the ordinary end-to-end packet `I = WG_{A→B}(P)`
    /// exactly as for direct delivery, then carry it in authenticated relay
    /// data on the hop-local session with the configured relay.
    async fn encrypt_via_relay<E: Sink>(
        &mut self,
        pidx: PeerIdx,
        sidx: SlotIdx,
        relay_key: [u8; 32],
        packet: &[u8],
        now: Instant,
        sink: &mut E,
    ) -> Result<(), Error> {
        // Everything the relay hop needs must be usable *before* the inner
        // session's counter is advanced.
        let (rpidx, rsidx, relay_endpoint) = self.relay_path(&relay_key, now, sink).await?;
        let padded_len = (packet.len() + 15) & !15;
        let inner_total = messages::DATA_HEADER_LEN + padded_len + crate::crypto::TAG_LEN;
        if inner_total > relay::MAX_RELAY_INNER_SIZE {
            return Err(Error::PacketTooLarge);
        }
        let destination = self
            .peers
            .get(pidx as usize)
            .and_then(Option::as_ref)
            .ok_or(Error::InternalInvariant)?
            .public_key;

        // 1. The unchanged end-to-end encapsulation, staged in `scratch`.
        let packet_end = messages::data::PACKET_START + packet.len();
        self.scratch[messages::data::PACKET_START..packet_end].copy_from_slice(packet);
        let (inner_total, rekey_dest) =
            self.seal_transport(pidx, sidx, messages::MSG_DATA, packet.len(), false, now)?;

        // 2. Destination key + inner datagram, sealed as hop-local relay type
        //    0xF0 in `relay_scratch`.
        let (total, rekey_relay) =
            self.wrap_and_seal(rpidx, rsidx, &destination, inner_total, now)?;
        trace!(
            "sending relayed transport datagram: peer={} relay_peer={} len={}",
            pidx, rpidx, total
        );
        let datagram = &self.relay_scratch[..total];
        sink.outer_datagram(relay_endpoint, datagram).await;
        self.note_outbound_flow(pidx, packet, now);

        if rekey_dest {
            let _ = self.ensure_handshake(pidx, now, sink).await;
        }
        if rekey_relay {
            let _ = self.ensure_direct_handshake(rpidx, now, sink).await;
        }
        Ok(())
    }

    /// Copy the sealed inner packet (`scratch[..inner_total]`) into
    /// `relay_scratch`, prepend the destination key and inner length, and seal
    /// the whole payload as relay transport message type 0xF0 under session
    /// `rsidx` of relay peer `rpidx`.
    fn wrap_and_seal(
        &mut self,
        rpidx: PeerIdx,
        rsidx: SlotIdx,
        destination: &[u8; 32],
        inner_total: usize,
        now: Instant,
    ) -> Result<(usize, bool), Error> {
        let payload_len = relay::ENVELOPE_HEADER_LEN + inner_total;
        {
            let this = &mut *self;
            let inner_start = messages::data::PACKET_START + relay::ENVELOPE_HEADER_LEN;
            let inner_end = inner_start + inner_total;
            this.relay_scratch[inner_start..inner_end]
                .copy_from_slice(&this.scratch[..inner_total]);
            relay::write_header(
                &mut this.relay_scratch[messages::data::PACKET_START..],
                destination,
                inner_total,
            )
            .ok_or(Error::InternalInvariant)?;
        }
        self.seal_transport(rpidx, rsidx, messages::MSG_RELAY, payload_len, true, now)
    }

    /// Record a locally initiated TCP/UDP/ICMP flow for a protected peer.
    fn note_outbound_flow(&mut self, pidx: PeerIdx, packet: &[u8], now: Instant) {
        if self
            .peers
            .get(pidx as usize)
            .and_then(Option::as_ref)
            .is_some_and(|peer| peer.inbound_policy == InboundPolicy::EstablishedOnly)
        {
            self.firewall.observe_outbound(pidx, packet, now);
        }
    }

    /// Resolve a configured relay key to a usable `(peer, session,
    /// endpoint)` triple. If the relay peer is known but no session is
    /// established yet, a handshake with it is started and
    /// [`Error::RelayUnavailable`] is returned. Handshake-path messages have
    /// their normal handshake retry timers; callers sending IP data may retry
    /// after the relay session becomes usable.
    async fn relay_path<E: Sink>(
        &mut self,
        relay_key: &[u8; 32],
        now: Instant,
        sink: &mut E,
    ) -> Result<(PeerIdx, SlotIdx, SocketAddr), Error> {
        let rpidx = self.find_peer(relay_key).ok_or(Error::RelayUnavailable)?;
        let rpeer = self
            .peers
            .get(rpidx as usize)
            .and_then(Option::as_ref)
            .ok_or(Error::RelayUnavailable)?;
        // Relay submission is only to a directly reachable relay.
        // The sender never tries to reach its relay through another relay.
        if rpeer.relay.is_some() {
            return Err(Error::RelayUnavailable);
        }
        let endpoint = rpeer.endpoint.ok_or(Error::RelayUnavailable)?;
        match self.usable_session(rpidx, now) {
            Some(rsidx) => Ok((rpidx, rsidx, endpoint)),
            None => {
                let _ = self.ensure_direct_handshake(rpidx, now, sink).await;
                Err(Error::RelayUnavailable)
            }
        }
    }

    /// Seal the payload already staged at `PACKET_START` of the chosen
    /// buffer as type-4 transport data or Microtun relay type 0xF0 under
    /// session
    /// `sidx` of peer `pidx`: padding, counters, rekey triggers, and the
    /// peer's send-side timers. Transmission is left to the caller (buffer
    /// and destination differ between the direct and relayed paths).
    /// Returns the total datagram length and whether a rekey handshake is
    /// due.
    fn seal_transport(
        &mut self,
        pidx: PeerIdx,
        sidx: SlotIdx,
        message_type: u8,
        payload_len: usize,
        use_relay_scratch: bool,
        now: Instant,
    ) -> Result<(usize, bool), Error> {
        let padded_len = (payload_len + 15) & !15;
        let total = messages::DATA_HEADER_LEN + padded_len + crate::crypto::TAG_LEN;
        if total > MAX_UDP_SIZE {
            return Err(Error::PacketTooLarge);
        }
        let padding_start = messages::data::PACKET_START + payload_len;
        let padding_end = messages::data::PACKET_START + padded_len;

        if self
            .peers
            .get(pidx as usize)
            .and_then(Option::as_ref)
            .is_none()
        {
            return Err(Error::InternalInvariant);
        }

        // Split borrows through one deref so slots/buffers/peers don't alias.
        let this = &mut *self;
        let sess = match this.slots.get_mut(sidx as usize) {
            Some(Slot::Established(session)) => session,
            _ => return Err(Error::InternalInvariant),
        };
        if !sess.can_send(now) {
            return Err(Error::Crypto);
        }
        let next_send = sess.n_send + 1;
        let peer = this
            .peers
            .get_mut(pidx as usize)
            .and_then(Option::as_mut)
            .ok_or(Error::InternalInvariant)?;

        let storage: &mut [u8] = if use_relay_scratch {
            &mut this.relay_scratch[..]
        } else {
            &mut this.scratch[..]
        };
        let buf = &mut storage[..total];
        messages::write_type(buf, message_type)?;
        buf[messages::data::RECEIVER].copy_from_slice(&sess.remote_index.to_le_bytes());
        buf[messages::data::COUNTER].copy_from_slice(&sess.n_send.to_le_bytes());
        buf[padding_start..padding_end].fill(0);
        let ad = match message_type {
            messages::MSG_DATA => b"" as &[u8],
            messages::MSG_RELAY => messages::RELAY_AEAD_AD,
            _ => return Err(Error::InternalInvariant),
        };
        let ciphertext = &mut buf[messages::data::PACKET_START..];
        aead_seal(&sess.t_send, sess.n_send, ciphertext, padded_len, ad)?;
        sess.n_send = next_send;

        let hit_msg_rekey = sess.n_send >= REKEY_AFTER_MESSAGES && !sess.rekey_triggered;
        let hit_time_rekey = sess.role == Role::Initiator
            && now.saturating_since(sess.created) >= REKEY_AFTER_TIME
            && !sess.rekey_triggered;
        if hit_msg_rekey || hit_time_rekey {
            sess.rekey_triggered = true;
        }

        peer.last_activity = now;
        // We just sent — no keepalive needed until the next receive (§6.5).
        peer.sessions.keepalive_due = None;
        let persistent_deadline = peer.persistent_keepalive.map(|interval| now + interval);
        peer.sessions.persistent_keepalive_due = persistent_deadline;
        // Real data demands evidence of life from the other side; keepalives
        // don't (that way two idle peers don't ping-pong forever). A relay
        // payload always counts as real data for its hop-local session;
        // the relay's own passive keepalives answer it.
        let armed = if payload_len > 0 && peer.sessions.reply_due.is_none() {
            let deadline =
                now + KEEPALIVE_TIMEOUT + REKEY_TIMEOUT + rekey_timeout_jitter(&mut this.rng);
            peer.sessions.reply_due = Some(deadline);
            Some(deadline)
        } else {
            None
        };
        // After the peer borrow ends: clearing `keepalive_due` above needs no
        // cache maintenance, only the newly armed deadline does.
        if let Some(deadline) = armed {
            self.timers.arm(deadline);
        }
        if let Some(deadline) = persistent_deadline {
            self.timers.arm(deadline);
        }

        Ok((total, hit_msg_rekey || hit_time_rekey))
    }

    /// Deliver a locally built handshake-path message (`initiation` or
    /// `response`) to `pidx`: to `direct_dst` (the live source being
    /// answered) or the stored endpoint when the peer is directly
    /// reachable, or wrapped in a relay envelope when a relay is configured
    /// — the relay relation is the routing authority (relay spec §9).
    async fn transmit_wire<E: Sink>(
        &mut self,
        pidx: PeerIdx,
        direct_dst: Option<SocketAddr>,
        msg: &[u8],
        now: Instant,
        sink: &mut E,
    ) -> Result<(), Error> {
        let (relay_cfg, endpoint, destination) = {
            let peer = self
                .peers
                .get(pidx as usize)
                .and_then(Option::as_ref)
                .ok_or(Error::InternalInvariant)?;
            (peer.relay, peer.endpoint, peer.public_key)
        };
        let Some(relay_key) = relay_cfg else {
            let dst = direct_dst.or(endpoint).ok_or(Error::NoEndpoint)?;
            sink.outer_datagram(dst, msg).await;
            return Ok(());
        };
        let (rpidx, rsidx, relay_endpoint) = self.relay_path(&relay_key, now, sink).await?;
        if msg.len() > relay::MAX_RELAY_INNER_SIZE {
            return Err(Error::PacketTooLarge);
        }
        let payload_len = relay::ENVELOPE_HEADER_LEN + msg.len();
        {
            let inner_start = messages::data::PACKET_START + relay::ENVELOPE_HEADER_LEN;
            let inner_end = inner_start + msg.len();
            self.relay_scratch[inner_start..inner_end].copy_from_slice(msg);
            relay::write_header(
                &mut self.relay_scratch[messages::data::PACKET_START..],
                &destination,
                msg.len(),
            )
            .ok_or(Error::InternalInvariant)?;
        }
        let (total, rekey_relay) =
            self.seal_transport(rpidx, rsidx, messages::MSG_RELAY, payload_len, true, now)?;
        let datagram = &self.relay_scratch[..total];
        sink.outer_datagram(relay_endpoint, datagram).await;
        if rekey_relay {
            let _ = self.ensure_direct_handshake(rpidx, now, sink).await;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Inbound datagram path
    // -----------------------------------------------------------------------

    /// Process one encrypted datagram command. Decryption happens in place.
    async fn datagram<E: Sink>(
        &mut self,
        now: Instant,
        src: SocketAddr,
        data: &mut [u8],
        sink: &mut E,
    ) -> Result<(), Error> {
        trace!("classifying outer datagram: len={}", data.len());
        match messages::classify(data) {
            Some(Message::Initiation) => self.rx_initiation(now, src, data, sink).await?,
            Some(Message::Response) => self.rx_response(now, src, data, sink).await,
            Some(Message::CookieReply) => self.rx_cookie_reply(now, data),
            Some(Message::Data) => self.rx_data(now, src, data, sink, false).await,
            Some(Message::RelayData) => self.rx_data(now, src, data, sink, true).await,
            None => debug!("ignoring unrecognized outer datagram: len={}", data.len()),
        }
        Ok(())
    }

    async fn rx_initiation<E: Sink>(
        &mut self,
        now: Instant,
        src: SocketAddr,
        data: &[u8],
        sink: &mut E,
    ) -> Result<(), Error> {
        let Some(mac1) = cookie::verify_mac1(data, &self.our_mac1_key) else {
            debug!("handshake initiation rejected: invalid mac1");
            return Ok(());
        };
        // Only mac1-valid messages count toward the load estimate. Anyone can
        // emit a well-formed 148-byte datagram, and counting those would let
        // unauthenticated traffic pin the device under load — forcing a cookie
        // round-trip onto every legitimate handshake. `mac1` requires the
        // sender to know our static public key, which is the same bar the rest
        // of the cookie layer is built on (§5.3, "stealth").
        self.note_handshake_msg(now);
        if self.under_load(now) && !self.check_mac2_or_reply(now, src, data, &mac1, sink).await {
            return Ok(());
        }
        let Ok(identified) = noise::identify_initiation(&self.s_priv, &self.s_pub, data) else {
            debug!("handshake initiation rejected: identity decrypt failed");
            return Ok(());
        };
        let claimed_key = *identified.static_key();

        if let Some(pidx) = self.find_peer(&claimed_key) {
            let Some(shared) = self
                .peers
                .get(pidx as usize)
                .and_then(Option::as_ref)
                .map(|peer| Zeroizing::new(peer.precomputed_static_static))
            else {
                return Ok(());
            };
            let Ok(consumed) =
                noise::authenticate_identified_with_shared_secret(identified, &shared)
            else {
                debug!("handshake initiation rejected: timestamp authentication failed");
                self.equalize_unknown_identity_cost(&claimed_key, now);
                return Ok(());
            };
            return self
                .accept_authenticated_initiation(pidx, &consumed, src, now, sink)
                .await;
        }

        // This check is read-only: stage one reveals a claimed identity but
        // does not yet prove possession of its private key. A lookup already in
        // flight or a still-honoured negative answer suppresses a duplicate
        // resolver request, but must not make the unknown-key rejection cheaper
        // than the matching known-key authentication failure. Charge the same
        // gated scalar multiplication before returning so suppression state
        // cannot reopen the peer-membership cost oracle.
        if self.resolve_suppressed(ResolveQuery::ByPublicKey(claimed_key), now) {
            self.equalize_unknown_identity_cost(&claimed_key, now);
            return Ok(());
        }
        if !self.unknown_authentications.try_take(now) {
            debug!("unknown-initiation authentication budget exhausted");
            return Ok(());
        }
        let Ok(consumed) = noise::authenticate_identified_initiation(&self.s_priv, identified)
        else {
            debug!("unknown initiation failed static-key proof");
            return Ok(());
        };
        // The sender demonstrably holds the private key for the claimed
        // identity. Ask the resolver who it is and drop this initiation:
        // nothing is parked, and the initiator's retransmission (§6.4, every
        // Rekey-Timeout) finds a configured peer once the answer has been
        // installed — the same self-healing a slow resolver relies on anyway.
        info!("valid initiation from unknown peer; requesting resolution");
        self.request_peer_install(consumed.s_pub_i, now);
        Ok(())
    }

    /// Apply the authenticated timestamp replay check and wireguard-go's
    /// independent per-peer 20 ms initiation-consumption gate. Both values are
    /// committed together before response allocation, so resource pressure
    /// cannot turn one accepted initiation into repeated expensive attempts.
    async fn accept_authenticated_initiation<E: Sink>(
        &mut self,
        pidx: PeerIdx,
        consumed: &noise::ConsumedInitiation,
        src: SocketAddr,
        now: Instant,
        sink: &mut E,
    ) -> Result<(), Error> {
        {
            let Some(peer) = self.peers.get_mut(pidx as usize).and_then(Option::as_mut) else {
                return Ok(());
            };
            if consumed.timestamp <= peer.greatest_ts {
                warn!(
                    "handshake initiation rejected: replayed timestamp peer={}",
                    pidx
                );
                return Ok(());
            }
            if let Some(last) = peer.last_initiation_consumption {
                if now.saturating_since(last) <= HANDSHAKE_INITIATION_MIN_INTERVAL {
                    warn!(
                        "handshake initiation rejected: per-peer flood peer={}",
                        pidx
                    );
                    return Ok(());
                }
            }
            peer.greatest_ts = consumed.timestamp;
            peer.last_initiation_consumption = Some(now);
        }
        info!("accepted handshake initiation: peer={}", pidx);
        self.respond_to_initiation(pidx, consumed, src, now, sink)
            .await
    }

    /// Under load: demand a valid mac2, or answer with a cookie reply.
    /// Returns `true` if processing may continue.
    async fn check_mac2_or_reply<E: Sink>(
        &mut self,
        now: Instant,
        src: SocketAddr,
        data: &[u8],
        mac1: &[u8; 16],
        sink: &mut E,
    ) -> bool {
        self.cookie_secret.refresh(&mut self.rng, now);
        if self.cookie_secret.verify_mac2(data, &src) {
            // IP ownership proven — now the per-IP rate limiter decides.
            let allowed = self.rate.allow(src.ip(), now);
            if !allowed {
                warn!("handshake rate limited after cookie validation");
            }
            return allowed;
        }
        // Valid mac1, no valid mac2 → cookie reply (§5.3).
        let sender = match data.first() {
            Some(&messages::MSG_INITIATION) => data
                .get(messages::init::SENDER)
                .and_then(messages::read_u32_le),
            _ => data
                .get(messages::resp::SENDER)
                .and_then(messages::read_u32_le),
        };
        let Some(sender) = sender else {
            return false;
        };
        let mut reply = [0u8; COOKIE_REPLY_LEN];
        if cookie::create_cookie_reply(
            &mut self.rng,
            &self.cookie_secret,
            &self.our_cookie_key,
            sender,
            &src,
            mac1,
            &mut reply,
        )
        .is_ok()
        {
            debug!("sending cookie reply");
            sink.outer_datagram(src, &reply).await;
        }
        false
    }

    /// Answer a valid initiation from a known peer: derive the session, send
    /// the response, install as the unconfirmed "next" session (§6.3).
    async fn respond_to_initiation<E: Sink>(
        &mut self,
        pidx: PeerIdx,
        consumed: &noise::ConsumedInitiation,
        src: SocketAddr,
        now: Instant,
        sink: &mut E,
    ) -> Result<(), Error> {
        // A peer may retransmit or replace an initiation while its previous
        // responder session is still unconfirmed in `next`. Reuse that slot
        // transactionally instead of asking the global allocator first: under
        // pressure the latter could evict an unrelated live session and only
        // then free this peer's superseded slot.
        let replacement = self
            .peers
            .get(pidx as usize)
            .and_then(Option::as_ref)
            .ok_or(Error::InternalInvariant)?
            .sessions
            .next;
        let (sidx, local_index) = if let Some(sidx) = replacement {
            let index = self.session_indices.random_unused(&mut self.rng)?;
            (sidx, index)
        } else {
            let Some(sidx) = self.alloc_slot(now)? else {
                return Ok(());
            };
            let index = match self.session_indices.random_unused(&mut self.rng) {
                Ok(index) => index,
                Err(error) => {
                    self.free_slot(sidx)?;
                    return Err(error);
                }
            };
            (sidx, index)
        };
        let mut msg = [0u8; RESPONSE_LEN];
        let keys = match noise::create_response(&mut self.rng, consumed, local_index, &mut msg) {
            Ok(keys) => keys,
            Err(error) => {
                if replacement.is_none() {
                    self.free_slot(sidx)?;
                }
                return Err(error);
            }
        };
        let cookie = match self
            .peers
            .get(pidx as usize)
            .and_then(Option::as_ref)
            .map(|peer| peer.cookie)
        {
            Some(cookie) => cookie,
            None => {
                if replacement.is_none() {
                    self.free_slot(sidx)?;
                }
                return Err(Error::InternalInvariant);
            }
        };
        let response_mac1 =
            match cookie::apply_macs(&mut msg, &consumed.s_pub_i, cookie.as_ref(), now) {
                Ok(mac1) => mac1,
                Err(error) => {
                    // Keep the previous responder session and cookie-reply binding
                    // intact rather than committing partial state.
                    if replacement.is_none() {
                        self.free_slot(sidx)?;
                    }
                    return Err(error);
                }
            };
        let mut sess = Session::new(keys, Role::Responder, local_index, consumed.sender, now);
        sess.peer = pidx;

        // Validate the peer-owned transition before changing the global wire
        // index or slot. Once those tables are committed, the remaining peer
        // updates are infallible and cannot leave a half-installed session.
        self.peers
            .get(pidx as usize)
            .and_then(Option::as_ref)
            .ok_or(Error::InternalInvariant)?
            .sessions
            .validate_responder_install(sidx)?;

        // Commit the fresh wire index only after every fallible cryptographic
        // step has succeeded. Until this point, an existing `next` session is
        // still fully usable and addressable by its old receiver index.
        let slot = self
            .slots
            .get(sidx as usize)
            .ok_or(Error::InternalInvariant)?;
        if let Some(old_index) = slot.local_index() {
            self.session_indices.replace(old_index, local_index, sidx)?;
        } else {
            self.session_indices.insert(local_index, sidx)?;
        }
        *self
            .slots
            .get_mut(sidx as usize)
            .ok_or(Error::InternalInvariant)? = Slot::Established(sess);
        // A live session carries its own expiry deadline (§6.4).
        self.timers.arm(now + REJECT_AFTER_TIME);

        let endpoint_observed = {
            let peer = self
                .peers
                .get_mut(pidx as usize)
                .and_then(Option::as_mut)
                .ok_or(Error::InternalInvariant)?;
            // Remember this response's mac1: if the initiator is under load
            // it will challenge the response, and the reply is bound to
            // exactly this value.
            peer.last_mac1 = Some(response_mac1);
            peer.sessions.commit_responder_install(sidx);
            // Relay spec §9: for a relayed peer, the observed UDP source is
            // the relay, not the peer — the configured relay relation stays
            // the routing authority and the source is not adopted.
            let observed = peer
                .observe_direct_endpoint(src, now)
                .then_some(peer.public_key);
            peer.last_activity = now;
            observed
        };
        if let Some(public_key) = endpoint_observed {
            sink.event(Event::PeerEndpointUpdate {
                public_key,
                endpoint: src,
            });
        }
        let _ = self.transmit_wire(pidx, Some(src), &msg, now, sink).await;
        Ok(())
    }

    async fn rx_response<E: Sink>(
        &mut self,
        now: Instant,
        src: SocketAddr,
        data: &[u8],
        sink: &mut E,
    ) {
        debug!("processing handshake response: len={}", data.len());
        let Some(mac1) = cookie::verify_mac1(data, &self.our_mac1_key) else {
            return;
        };
        // As in `rx_initiation`: the load estimate is fed only by messages
        // that carried a valid mac1.
        self.note_handshake_msg(now);
        if self.under_load(now) && !self.check_mac2_or_reply(now, src, data, &mac1, sink).await {
            return;
        }
        let Some(receiver) = data
            .get(messages::resp::RECEIVER)
            .and_then(messages::read_u32_le)
        else {
            return;
        };
        let Some(sidx) = self.slot_for_session_index(receiver) else {
            return;
        };
        let Some(Slot::Initiating(hs)) = self.slots.get(sidx as usize) else {
            return;
        };
        let pidx = hs.peer;
        let local_index = hs.local_index;
        let Ok((keys, remote_index)) = noise::consume_response(&hs.noise, &self.s_priv, data)
        else {
            return; // wrong ephemeral generation or tamper: drop, retransmit heals
        };

        let mut sess = Session::new(keys, Role::Initiator, local_index, remote_index, now);
        sess.peer = pidx;

        // Rotate: current → previous (freeing any old previous), new → current.
        // The transition validates its precondition before mutating peer state.
        let (old_previous, endpoint_observed) = {
            let Some(peer) = self.peers.get_mut(pidx as usize).and_then(Option::as_mut) else {
                if let Err(error) = self.free_slot(sidx) {
                    error!("failed to free orphaned handshake slot: {:?}", error);
                }
                return;
            };
            let old_prev = match peer.sessions.install_initiator(sidx) {
                Ok(old) => old,
                Err(error) => {
                    error!("invalid initiator session transition: {:?}", error);
                    return;
                }
            };
            let endpoint_observed = peer
                .observe_direct_endpoint(src, now)
                .then_some(peer.public_key);
            peer.last_activity = now;
            (old_prev, endpoint_observed)
        };
        if let Some(public_key) = endpoint_observed {
            sink.event(Event::PeerEndpointUpdate {
                public_key,
                endpoint: src,
            });
        }

        let Some(slot) = self.slots.get_mut(sidx as usize) else {
            error!("resolved session index points outside the slot pool");
            return;
        };
        *slot = Slot::Established(sess);
        // A live session carries its own expiry deadline (§6.4).
        self.timers.arm(now + REJECT_AFTER_TIME);

        if let Some(old) = old_previous {
            if let Err(error) = self.free_slot(old) {
                error!("failed to free superseded session slot: {:?}", error);
            }
        }

        // The initiator must speak first to confirm the session (§5.4.5):
        // flush anything parked for this peer, else send a keepalive.
        let mut sent_any = false;
        while let Some(p) = self.pending.take_if(|p| p.wait == Wait::Handshake(pidx)) {
            let packet = p.packet();
            if self
                .encrypt_and_send(pidx, sidx, packet, now, sink)
                .await
                .is_ok()
            {
                sent_any = true;
            }
        }
        if !sent_any {
            let _ = self.encrypt_and_send(pidx, sidx, &[], now, sink).await;
        }
    }

    fn rx_cookie_reply(&mut self, now: Instant, data: &[u8]) {
        debug!("processing cookie reply: len={}", data.len());
        let Some(receiver) = data
            .get(messages::cookie::RECEIVER)
            .and_then(messages::read_u32_le)
        else {
            return;
        };
        let Some(sidx) = self.slot_for_session_index(receiver) else {
            return;
        };
        // A cookie reply may answer *either* handshake message we sent
        // (§5.3: mac2 is demanded on initiations and responses alike). An
        // initiation leaves an `Initiating` slot behind, but a response we
        // sent leaves an `Established` one — so the owning peer is resolved
        // from whatever state the slot is in. Matching on `Initiating` here
        // would discard every challenge aimed at our responses, and a loaded
        // peer would then reject those responses forever.
        let Some(pidx) = self.slot_owner(sidx) else {
            return;
        };
        let Some((peer_pub, last_mac1)) = self
            .peers
            .get(pidx as usize)
            .and_then(Option::as_ref)
            .map(|peer| (peer.public_key, peer.last_mac1))
        else {
            return;
        };
        // No handshake message on record for this peer: nothing to bind the
        // reply's associated data to, so it cannot be authenticated.
        let Some(last_mac1) = last_mac1 else {
            return;
        };
        if let Ok(c) = cookie::consume_cookie_reply(&peer_pub, &last_mac1, data) {
            if let Some(peer) = self.peers.get_mut(pidx as usize).and_then(Option::as_mut) {
                debug!("stored cookie for peer={}", pidx);
                peer.cookie = Some((c, now));
                // The ≤5 s retransmission (§6.4) will carry mac2; no
                // immediate resend, exactly like the reference behavior.
            }
        }
    }

    async fn rx_data<E: Sink>(
        &mut self,
        now: Instant,
        src: SocketAddr,
        data: &mut [u8],
        sink: &mut E,
        is_relay: bool,
    ) {
        let Some(receiver) = data
            .get(messages::data::RECEIVER)
            .and_then(messages::read_u32_le)
        else {
            return;
        };
        let Some(sidx) = self.slot_for_session_index(receiver) else {
            return;
        };
        let Some(counter) = data
            .get(messages::data::COUNTER)
            .and_then(messages::read_u64_le)
        else {
            return;
        };
        if counter >= REJECT_AFTER_MESSAGES {
            return;
        }

        let this = &mut *self;
        let Some(Slot::Established(sess)) = this.slots.get_mut(sidx as usize) else {
            return;
        };
        if now.saturating_since(sess.created) >= REJECT_AFTER_TIME {
            return;
        }
        let ad = if is_relay {
            messages::RELAY_AEAD_AD
        } else {
            b""
        };
        let Ok(pt_len) = aead_open(
            &sess.t_recv,
            counter,
            match data.get_mut(messages::data::PACKET_START..) {
                Some(ciphertext) => ciphertext,
                None => return,
            },
            ad,
        ) else {
            return;
        };
        // Replay window strictly after authentication (§5.4.6).
        if !sess.replay.check_and_update(counter) {
            return;
        }
        let pidx = sess.peer;
        let role = sess.role;
        let session_age = now.saturating_since(sess.created);
        let already_triggered = sess.rekey_triggered;

        // Session confirmation & rotation for responder "next" sessions.
        let peer = match this.peers.get_mut(pidx as usize).and_then(Option::as_mut) {
            Some(peer) => peer,
            None => return,
        };
        let mut freed: Option<SlotIdx> = None;
        if peer.sessions.next == Some(sidx) {
            freed = match peer.sessions.confirm_responder(sidx) {
                Ok(old) => old,
                Err(error) => {
                    error!("invalid responder session transition: {:?}", error);
                    return;
                }
            };
            if let Some(Slot::Established(session)) = this.slots.get_mut(sidx as usize) {
                session.confirmed = true;
            } else {
                error!("confirmed session slot disappeared during receive");
                return;
            }
        }
        // Roaming (§2.1): the outer source of an authenticated message is
        // the peer's new endpoint — unless the peer is routed via a
        // configured relay, which stays the outbound authority (relay spec
        // §9).
        let endpoint_observed = peer
            .observe_direct_endpoint(src, now)
            .then_some(peer.public_key);
        peer.last_activity = now;
        peer.sessions.reply_due = None;
        let persistent_deadline = peer.persistent_keepalive.map(|interval| now + interval);
        peer.sessions.persistent_keepalive_due = persistent_deadline;

        let is_keepalive = pt_len == 0;
        if !is_keepalive {
            // §6.5: every received data packet wants an eventual reply;
            // a queued passive keepalive satisfies it if nothing else does.
            peer.sessions.keepalive_due = Some(now + KEEPALIVE_TIMEOUT);
            // Ends the `peer` borrow: clearing `reply_due` above needed no
            // cache maintenance, but this newly armed deadline does.
            self.timers.arm(now + KEEPALIVE_TIMEOUT);
        }
        if let Some(deadline) = persistent_deadline {
            self.timers.arm(deadline);
        }
        if let Some(public_key) = endpoint_observed {
            sink.event(Event::PeerEndpointUpdate {
                public_key,
                endpoint: src,
            });
        }

        if let Some(old) = freed {
            if let Err(error) = self.free_slot(old) {
                error!("failed to free superseded responder session: {:?}", error);
            }
        }

        // Receive-path rekey (§6.2), initiator role only.
        if role == Role::Initiator
            && !already_triggered
            && session_age >= REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT
        {
            if let Some(Slot::Established(session)) = self.slots.get_mut(sidx as usize) {
                session.rekey_triggered = true;
            }
            let _ = self.ensure_handshake(pidx, now, sink).await;
        }

        if is_keepalive {
            return;
        }
        let inner_end = messages::data::PACKET_START + pt_len;
        let Some(inner) = data.get(messages::data::PACKET_START..inner_end) else {
            return;
        };
        if is_relay {
            // Relay plaintext is always a relay envelope, never an IP packet.
            self.rx_relay(pidx, inner, now, sink).await;
            return;
        }
        // Validate the inner header before anything is allowed to trust its
        // length fields. `total_length` is peer-controlled and, unchecked,
        // may claim to be shorter than the header it sits in — clamping it
        // with `min(inner.len())` alone would hand the host stack a
        // truncated (possibly empty) "IP packet".
        let Some(header) = ip::parse_header(inner) else {
            return;
        };
        // Cryptokey routing, inbound direction (§2's "global question"): the
        // inner source must map back to exactly this peer.
        if self.routes.lookup_readonly(&header.src) != Some(pidx) {
            return;
        }
        // Trim the §5.4.6 zero padding. `parse_header` guarantees
        // `header_len <= total_len <= inner.len()`, so this cannot truncate
        // below a complete header.
        let ip_len = header.total_len;
        let policy = self
            .peers
            .get(pidx as usize)
            .and_then(Option::as_ref)
            .map(|peer| peer.inbound_policy)
            .unwrap_or(InboundPolicy::AllowAll);
        let Some(ip_packet) = inner.get(..ip_len) else {
            return;
        };
        if policy == InboundPolicy::EstablishedOnly
            && !self.firewall.allows_inbound(pidx, ip_packet, now)
        {
            return;
        }
        let Some((src_peer_key, src_endpoint)) = self
            .peers
            .get(pidx as usize)
            .and_then(Option::as_ref)
            .map(|peer| (peer.public_key, peer.relay.is_none().then_some(src)))
        else {
            return;
        };
        sink.inner_packet(&src_peer_key, src_endpoint, ip_packet)
            .await;
    }

    // -----------------------------------------------------------------------
    // Relay forwarding
    // -----------------------------------------------------------------------

    /// Process a decrypted relay envelope submitted over the authenticated
    /// session with peer `pidx`. Authentication precedes parsing; parsing
    /// precedes policy; policy precedes destination lookup and forwarding.
    async fn rx_relay<E: Sink>(
        &mut self,
        pidx: PeerIdx,
        plaintext: &[u8],
        now: Instant,
        sink: &mut E,
    ) {
        let submitter = match self.peers.get(pidx as usize).and_then(Option::as_ref) {
            Some(p) => p.public_key,
            None => return,
        };
        // Header/length checks and inner wire-format plausibility all live in
        // `relay::parse`.
        let Some(envelope) = relay::parse(plaintext) else {
            return;
        };
        // §8: policy sees two authenticated *identities*, never UDP
        // addresses. Deny is the default.
        if !self
            .relay_policy
            .authorize_relay(&submitter, &envelope.destination)
        {
            return;
        }
        // §4.4: the destination is resolved through the local peer
        // configuration by static key.
        let Some(dpidx) = self.find_peer(&envelope.destination) else {
            self.request_relay_peer_install(pidx, envelope.destination, now);
            return;
        };
        let (dest_relay, dest_endpoint) =
            match self.peers.get(dpidx as usize).and_then(Option::as_ref) {
                Some(p) => (p.relay, p.endpoint),
                None => return,
            };
        // Relay forwarding is intentionally single-hop. A peer whose local
        // route is itself relayed is not a valid final destination here.
        if dest_relay.is_some() {
            return;
        }
        if let Some(endpoint) = dest_endpoint {
            // Final hop: send the end-to-end WireGuard packet unchanged.
            sink.outer_datagram(endpoint, envelope.inner).await;
        }
        // No direct endpoint: drop silently. The destination becomes reachable
        // once it resolves or initiates traffic of its own.
    }

    // -----------------------------------------------------------------------
    // Timers
    // -----------------------------------------------------------------------

    /// The next instant at which [`Core::handle_timeout`] should be
    /// called, or `None` if fully idle.
    ///
    /// `O(1)`: embeddings consult this after *every* call, including once per
    /// packet, so it reads a cached bound rather than walking the timer state.
    /// The value may be earlier than the true next deadline — see
    /// [`TimerCache`] — which costs at most an occasional spurious wake that
    /// [`Core::handle_timeout`] absorbs.
    pub fn poll_at(&self) -> Option<Instant> {
        // A stale early bound is harmless. A late bound would delay protocol
        // work, so report it in instrumented builds without making diagnostics
        // capable of terminating production.
        #[cfg(any(test, debug_assertions))]
        {
            let valid = match (self.timers.get(), self.scan_deadlines()) {
                (Some(cached), Some(exact)) => cached <= exact,
                (None, exact) => exact.is_none(),
                (Some(_), None) => true,
            };
            if !valid {
                error!("timer cache is later than the earliest live deadline");
            }
        }
        self.timers.get()
    }

    /// Walk all timer state for the true earliest deadline.
    ///
    /// `O(MAX_PEERS + MAX_SESSIONS)`. This is the work `poll_at` used to
    /// do on every call; it now
    /// runs only when a wake turns out to be spurious, so its cost is tied to
    /// the protocol's timer rate rather than to the packet rate.
    fn scan_deadlines(&self) -> Option<Instant> {
        let mut at: Option<Instant> = None;
        for p in self.peers.iter().flatten() {
            at = min_deadline(at, p.sessions.keepalive_due);
            at = min_deadline(at, p.sessions.persistent_keepalive_due);
            at = min_deadline(at, p.sessions.reply_due);
        }
        for slot in self.slots.iter() {
            match slot {
                Slot::Initiating(hs) => {
                    at = min_deadline(at, Some(hs.retry_at));
                    if let Some(peer) = self.peers.get(hs.peer as usize).and_then(Option::as_ref) {
                        at = min_deadline(at, peer.sessions.attempt_deadline);
                    }
                }
                Slot::Established(s) => {
                    // Free expired sessions promptly so the pool breathes.
                    at = min_deadline(at, Some(s.created + REJECT_AFTER_TIME));
                }
                Slot::Free => {}
            }
        }
        at = min_deadline(at, self.pending.next_deadline());
        for r in self.resolves.iter() {
            at = min_deadline(at, Some(r.deadline));
        }
        for pending in self.pending_reconciles.iter() {
            at = min_deadline(at, Some(pending.due));
        }
        at
    }

    /// Process one timer action that is due at `now`.
    async fn timeout<E: Sink>(&mut self, now: Instant, sink: &mut E) -> bool {
        trace!(
            "incremental timer step: inflight_resolves={}",
            self.resolves.len()
        );

        // 1. Expired parked packets.
        if self.pending.expire_one(now) {
            return true;
        }

        // 2. One expired resolver entry.
        if self.expire_one_resolve(now) {
            return true;
        }

        // 3. One reconciliation that has waited long enough to be re-asked.
        //    Placed after expiry so a lapsed reconcile is re-queued before
        //    this step reconsiders it.
        if self.promote_due_reconcile(now) {
            return true;
        }

        // 4. One slot timer: handshake retransmission or session expiry.
        for sidx in 0..MAX_SESSIONS as SlotIdx {
            let Some(slot) = self.slots.get(sidx as usize) else {
                error!("timer iteration exceeded the slot pool");
                return false;
            };
            match slot {
                Slot::Initiating(handshake) => {
                    let pidx = handshake.peer;
                    let attempt_deadline = self
                        .peers
                        .get(pidx as usize)
                        .and_then(Option::as_ref)
                        .and_then(|peer| peer.sessions.attempt_deadline);
                    if attempt_deadline.is_some_and(|deadline| deadline <= now) {
                        // §6.4: give up after Rekey-Attempt-Time.
                        if let Err(error) = self.free_slot(sidx) {
                            error!("failed to expire handshake slot: {:?}", error);
                        }
                        self.pending
                            .drop_if(|packet| packet.wait == Wait::Handshake(pidx));
                        return true;
                    }
                    if handshake.retry_at <= now {
                        self.retransmit_initiation(pidx, sidx, now, sink).await;
                        return true;
                    }
                }
                Slot::Established(session)
                    if now.saturating_since(session.created) >= REJECT_AFTER_TIME =>
                {
                    if let Err(error) = self.free_slot(sidx) {
                        error!("failed to expire session slot: {:?}", error);
                    }
                    return true;
                }
                Slot::Established(_) | Slot::Free => {}
            }
        }

        // 5. One peer timer: passive/persistent keepalive or missing-reply re-handshake.
        for pidx in 0..MAX_PEERS as PeerIdx {
            let (keepalive_due, persistent_keepalive_due, reply_due) =
                match self.peers.get(pidx as usize).and_then(Option::as_ref) {
                    Some(peer) => (
                        peer.sessions.keepalive_due,
                        peer.sessions.persistent_keepalive_due,
                        peer.sessions.reply_due,
                    ),
                    None => continue,
                };
            if keepalive_due.is_some_and(|deadline| deadline <= now) {
                if let Some(peer) = self.peers.get_mut(pidx as usize).and_then(Option::as_mut) {
                    peer.sessions.keepalive_due = None;
                }
                if let Some(sidx) = self.usable_session(pidx, now) {
                    let _ = self.encrypt_and_send(pidx, sidx, &[], now, sink).await;
                }
                return true;
            }
            if persistent_keepalive_due.is_some_and(|deadline| deadline <= now) {
                let interval = self
                    .peers
                    .get_mut(pidx as usize)
                    .and_then(Option::as_mut)
                    .and_then(|peer| {
                        peer.sessions.persistent_keepalive_due = None;
                        peer.persistent_keepalive
                    });
                if let Some(sidx) = self.usable_session(pidx, now) {
                    let _ = self.encrypt_and_send(pidx, sidx, &[], now, sink).await;
                } else {
                    let _ = self.ensure_handshake(pidx, now, sink).await;
                    if let Some(interval) = interval {
                        let deadline = now + interval;
                        if let Some(peer) =
                            self.peers.get_mut(pidx as usize).and_then(Option::as_mut)
                        {
                            peer.sessions.persistent_keepalive_due = Some(deadline);
                        }
                        self.timers.arm(deadline);
                    }
                }
                return true;
            }
            if reply_due.is_some_and(|deadline| deadline <= now) {
                if let Some(peer) = self.peers.get_mut(pidx as usize).and_then(Option::as_mut) {
                    peer.sessions.reply_due = None;
                }
                // Data went unanswered for Keepalive-Timeout + Rekey-Timeout:
                // assume the session died with the peer's reboot (§6.4).
                let _ = self.ensure_handshake(pidx, now, sink).await;
                return true;
            }
        }

        false
    }

    // -----------------------------------------------------------------------
    // Handshake initiation machinery
    // -----------------------------------------------------------------------

    /// Reserve a slot for a new handshake, or return `None` when one is
    /// already in flight.
    fn allocate_handshake_slot(
        &mut self,
        pidx: PeerIdx,
        now: Instant,
    ) -> Result<Option<SlotIdx>, Error> {
        {
            let Some(peer) = self.peers.get(pidx as usize).and_then(Option::as_ref) else {
                return Ok(None);
            };
            if peer.sessions.handshake.is_some() {
                trace!("handshake already in progress: peer={}", pidx);
                return Ok(None); // already running; retransmission timer owns it
            }
            if peer.endpoint.is_none() && peer.relay.is_none() {
                return Err(Error::NoEndpoint);
            }
        }
        let Some(sidx) = self.alloc_slot(now)? else {
            warn!("cannot start handshake: session pool full peer={}", pidx);
            return Err(Error::SessionPoolFull);
        };
        info!("starting handshake: peer={} slot={}", pidx, sidx);
        Ok(Some(sidx))
    }

    fn commit_handshake_start(
        &mut self,
        pidx: PeerIdx,
        sidx: SlotIdx,
        now: Instant,
    ) -> Result<(), Error> {
        debug!("handshake initiation sent: peer={} slot={}", pidx, sidx);
        let started = self
            .peers
            .get_mut(pidx as usize)
            .and_then(Option::as_mut)
            .ok_or(Error::InternalInvariant)
            .and_then(|peer| {
                peer.sessions
                    .begin_handshake(sidx, now + REKEY_ATTEMPT_TIME)
            });
        if let Err(error) = started {
            self.free_slot(sidx)?;
            return Err(error);
        }
        self.timers.arm(now + REKEY_ATTEMPT_TIME);
        Ok(())
    }

    /// Allocate a slot, build an initiation for it and commit the handshake
    /// state. Everything the two handshake entry points share, and all of it
    /// synchronous — which is what keeps their async bodies distinct (see
    /// [`Self::ensure_direct_handshake`]).
    ///
    /// `Ok(None)` means no slot was available and nothing was started.
    fn stage_initiation(
        &mut self,
        pidx: PeerIdx,
        now: Instant,
    ) -> Result<Option<[u8; INITIATION_LEN]>, Error> {
        let Some(sidx) = self.allocate_handshake_slot(pidx, now)? else {
            return Ok(None);
        };
        let msg = match self.build_initiation(pidx, sidx, now) {
            Ok(msg) => msg,
            Err(error) => {
                warn!("handshake initiation failed: peer={} slot={}", pidx, sidx);
                self.free_slot(sidx)?;
                return Err(error);
            }
        };

        // Link the initiating slot and arm its attempt deadline before the
        // sink is awaited. Native async callers may cancel at any suspension
        // point; committing first ensures cancellation can never leave an
        // unowned Initiating slot with no overall expiry.
        self.commit_handshake_start(pidx, sidx, now)?;
        Ok(Some(msg))
    }

    /// Make sure a handshake to `pidx` is in flight, starting one if needed.
    async fn ensure_handshake<E: Sink>(
        &mut self,
        pidx: PeerIdx,
        now: Instant,
        sink: &mut E,
    ) -> Result<(), Error> {
        if let Some(msg) = self.stage_initiation(pidx, now)? {
            let _ = self.transmit_wire(pidx, None, &msg, now, sink).await;
        }
        Ok(())
    }

    /// Start a handshake to a peer already proven to be directly reachable.
    ///
    /// Relay path discovery uses this specialized edge to keep the async call
    /// graph acyclic: a relay's own handshake is never wrapped in another relay
    /// envelope. That is a *type-level* requirement, not merely a runtime one —
    /// an async fn's future contains every future it awaits anywhere in its
    /// body, so folding this into [`Self::ensure_handshake`] would put a
    /// `transmit_wire` future on the path `transmit_wire` → `relay_path` →
    /// here, and the layout of that future becomes infinitely recursive
    /// (`error[E0391]`). Only the shared *synchronous* setup is factored out.
    async fn ensure_direct_handshake<E: Sink>(
        &mut self,
        pidx: PeerIdx,
        now: Instant,
        sink: &mut E,
    ) -> Result<(), Error> {
        // Resolved before a slot is taken, so an unreachable peer cannot
        // consume one.
        let endpoint = {
            let Some(peer) = self.peers.get(pidx as usize).and_then(Option::as_ref) else {
                return Ok(());
            };
            if peer.relay.is_some() {
                return Err(Error::RelayUnavailable);
            }
            peer.endpoint.ok_or(Error::NoEndpoint)?
        };

        if let Some(msg) = self.stage_initiation(pidx, now)? {
            sink.outer_datagram(endpoint, &msg).await;
        }
        Ok(())
    }

    /// Build a fresh-ephemeral initiation and update its retry state.
    fn build_initiation(
        &mut self,
        pidx: PeerIdx,
        sidx: SlotIdx,
        now: Instant,
    ) -> Result<[u8; INITIATION_LEN], Error> {
        let (peer_pub, cookie) = {
            let peer = self
                .peers
                .get(pidx as usize)
                .and_then(Option::as_ref)
                .ok_or(Error::InternalInvariant)?;
            if peer.endpoint.is_none() && peer.relay.is_none() {
                return Err(Error::NoEndpoint);
            }
            (peer.public_key, peer.cookie)
        };
        let ts = self.timestamp(now)?;
        let existing_index = match self
            .slots
            .get(sidx as usize)
            .ok_or(Error::InternalInvariant)?
        {
            Slot::Initiating(handshake) => Some(handshake.local_index),
            Slot::Free => None,
            Slot::Established(_) => return Err(Error::Crypto),
        };
        let local_index = match existing_index {
            Some(index) => index,
            None => self.session_indices.random_unused(&mut self.rng)?,
        };
        let mut msg = [0u8; INITIATION_LEN];
        let state = noise::create_initiation(
            &mut self.rng,
            &self.s_priv,
            &self.s_pub,
            &peer_pub,
            local_index,
            &ts,
            &mut msg,
        )?;
        let mac1 = cookie::apply_macs(&mut msg, &peer_pub, cookie.as_ref(), now)?;
        let retry_at = handshake_retry_deadline(&mut self.rng, now);
        if existing_index.is_none() {
            self.session_indices.insert(local_index, sidx)?;
        }
        *self
            .slots
            .get_mut(sidx as usize)
            .ok_or(Error::InternalInvariant)? = Slot::Initiating(Initiating {
            peer: pidx,
            local_index,
            noise: state,
            retry_at,
        });
        self.peers
            .get_mut(pidx as usize)
            .and_then(Option::as_mut)
            .ok_or(Error::InternalInvariant)?
            .last_mac1 = Some(mac1);
        self.timers.arm(retry_at);
        Ok(msg)
    }

    /// Build and transmit a (fresh-ephemeral) initiation for slot `sidx`.
    async fn send_initiation<E: Sink>(
        &mut self,
        pidx: PeerIdx,
        sidx: SlotIdx,
        now: Instant,
        sink: &mut E,
    ) -> Result<(), Error> {
        let msg = self.build_initiation(pidx, sidx, now)?;
        // A relayed transmit may fail (e.g. the relay session is still
        // handshaking); the Initiating slot stays put so the §6.4
        // retransmission carries the initiation once the relay path is up.
        let _ = self.transmit_wire(pidx, None, &msg, now, sink).await;
        Ok(())
    }

    /// §6.4 retransmission: same slot and local index, fresh ephemeral (a
    /// response to *either* generation authenticates only against the
    /// matching ephemeral, so stale responses just fail AEAD and drop).
    async fn retransmit_initiation<E: Sink>(
        &mut self,
        pidx: PeerIdx,
        sidx: SlotIdx,
        now: Instant,
        sink: &mut E,
    ) {
        if self.send_initiation(pidx, sidx, now, sink).await.is_err() {
            // Could not rebuild (endpoint vanished / no wall clock): abort
            // this attempt entirely.
            if let Err(error) = self.free_slot(sidx) {
                error!("failed to free aborted handshake slot: {:?}", error);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Peer & slot pool management
    // -----------------------------------------------------------------------

    #[inline]
    fn find_peer(&self, public_key: &[u8; 32]) -> Option<PeerIdx> {
        self.peers_by_public_key.get(public_key).copied()
    }

    /// Install a peer into an empty stable slot and update the public-key
    /// index atomically with the slot table.
    fn install_peer(&mut self, pidx: PeerIdx, peer: PeerEntry) -> Result<(), Error> {
        if self
            .peers
            .get(pidx as usize)
            .ok_or(Error::InternalInvariant)?
            .is_some()
            || self.peers_by_public_key.contains_key(&peer.public_key)
        {
            return Err(Error::InternalInvariant);
        }

        let public_key = peer.public_key;
        let persistent_keepalive_due = peer.sessions.persistent_keepalive_due;
        #[cfg(feature = "alloc")]
        let previous = self.peers_by_public_key.insert(public_key, pidx);
        #[cfg(not(feature = "alloc"))]
        let previous = self
            .peers_by_public_key
            .insert(public_key, pidx)
            .map_err(|_| Error::InternalInvariant)?;
        if let Some(previous_pidx) = previous {
            // Preserve the old mapping even if an impossible duplicate slips
            // past the preflight check.
            let _ = self.peers_by_public_key.insert(public_key, previous_pidx);
            return Err(Error::InternalInvariant);
        }

        let Some(slot) = self.peers.get_mut(pidx as usize) else {
            self.peers_by_public_key.remove(&public_key);
            return Err(Error::InternalInvariant);
        };
        if slot.is_some() {
            self.peers_by_public_key.remove(&public_key);
            return Err(Error::InternalInvariant);
        }
        *slot = Some(peer);
        if let Some(deadline) = persistent_keepalive_due {
            self.timers.arm(deadline);
        }
        Ok(())
    }

    #[cfg(test)]
    fn assert_peer_index_consistent(&self) {
        assert_eq!(
            self.peers_by_public_key.len(),
            self.peers.iter().filter(|peer| peer.is_some()).count()
        );
        for (index, peer) in self.peers.iter().enumerate() {
            if let Some(peer) = peer {
                assert_eq!(
                    self.peers_by_public_key.get(&peer.public_key),
                    Some(&(index as PeerIdx))
                );
            }
        }
        for (public_key, pidx) in &self.peers_by_public_key {
            assert_eq!(
                self.peers[*pidx as usize]
                    .as_ref()
                    .map(|peer| &peer.public_key),
                Some(public_key)
            );
        }
    }

    /// Remove a peer from its stable slot and the public-key index.
    fn take_peer(&mut self, pidx: PeerIdx) -> Result<Option<PeerEntry>, Error> {
        let Some(public_key) = self
            .peers
            .get(pidx as usize)
            .ok_or(Error::InternalInvariant)?
            .as_ref()
            .map(|peer| peer.public_key)
        else {
            return Ok(None);
        };
        if self.peers_by_public_key.get(&public_key).copied() != Some(pidx) {
            return Err(Error::InternalInvariant);
        }
        if self.peers_by_public_key.remove(&public_key) != Some(pidx) {
            return Err(Error::InternalInvariant);
        }
        let Some(slot) = self.peers.get_mut(pidx as usize) else {
            let _ = self.peers_by_public_key.insert(public_key, pidx);
            return Err(Error::InternalInvariant);
        };
        match slot.take() {
            Some(peer) => Ok(Some(peer)),
            None => {
                let _ = self.peers_by_public_key.insert(public_key, pidx);
                Err(Error::InternalInvariant)
            }
        }
    }

    /// Allocate a session slot for authenticated use (handshakes with known
    /// peers, established sessions). Eviction order: free → expired session
    /// → any peer's `previous` → LRU established (never a pinned peer's
    /// current session).
    fn alloc_slot(&mut self, now: Instant) -> Result<Option<SlotIdx>, Error> {
        // 1. Free.
        if let Some(i) = self.slots.iter().position(Slot::is_free) {
            return Ok(Some(i as SlotIdx));
        }
        // 2. Expired established.
        if let Some(i) = self.slots.iter().position(|s| {
            matches!(s, Slot::Established(sess) if now.saturating_since(sess.created) >= REJECT_AFTER_TIME)
        }) {
            self.free_slot(i as SlotIdx)?;
            return Ok(Some(i as SlotIdx));
        }
        // 3. Any previous session (superseded; safe to drop).
        if let Some(prev) = self
            .peers
            .iter()
            .flatten()
            .filter_map(|p| p.sessions.previous)
            .next()
        {
            self.free_slot(prev)?;
            return Ok(Some(prev));
        }
        // 4. LRU established, excluding pinned peers' current sessions.
        let victim = self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| match s {
                Slot::Established(sess) => Some((i, sess.peer)),
                _ => None,
            })
            .filter(|(i, pidx)| {
                self.peers
                    .get(*pidx as usize)
                    .and_then(Option::as_ref)
                    .is_none_or(|peer| {
                        !(peer.is_pinned() && peer.sessions.current == Some(*i as SlotIdx))
                    })
            })
            .min_by_key(|(_, pidx)| {
                self.peers
                    .get(*pidx as usize)
                    .and_then(Option::as_ref)
                    .map(|peer| peer.last_activity)
                    .unwrap_or(Instant(0))
            })
            .map(|(i, _)| i as SlotIdx);
        if let Some(v) = victim {
            self.free_slot(v)?;
            return Ok(Some(v));
        }
        Ok(None)
    }

    /// The peer that owns `sidx`, for the slot states that have one.
    fn slot_owner(&self, sidx: SlotIdx) -> Option<PeerIdx> {
        match self.slots.get(sidx as usize)? {
            Slot::Established(session) => Some(session.peer),
            Slot::Initiating(handshake) => Some(handshake.peer),
            Slot::Free => None,
        }
    }

    /// Free a slot: unlink it from its owning peer, remove its random wire
    /// index so stale packets stop resolving, and drop (zeroizing) its contents.
    fn free_slot(&mut self, sidx: SlotIdx) -> Result<(), Error> {
        debug!("freeing session slot={}", sidx);
        let slot = self
            .slots
            .get(sidx as usize)
            .ok_or(Error::InternalInvariant)?;
        let owner = match slot {
            Slot::Established(session) => Some(session.peer),
            Slot::Initiating(handshake) => Some(handshake.peer),
            Slot::Free => None,
        };
        let local_index = slot.local_index();

        if let Some(pidx) = owner {
            if self
                .peers
                .get(pidx as usize)
                .and_then(Option::as_ref)
                .is_none()
            {
                return Err(Error::InternalInvariant);
            }
        }
        if let Some(index) = local_index {
            self.session_indices.remove(index, sidx)?;
        }
        if let Some(pidx) = owner {
            self.peers
                .get_mut(pidx as usize)
                .and_then(Option::as_mut)
                .ok_or(Error::InternalInvariant)?
                .sessions
                .unlink(sidx);
        }
        *self
            .slots
            .get_mut(sidx as usize)
            .ok_or(Error::InternalInvariant)? = Slot::Free;
        Ok(())
    }

    #[inline]
    fn slot_for_session_index(&self, index: u32) -> Option<SlotIdx> {
        self.session_indices.slot_for(index)
    }

    // -----------------------------------------------------------------------
    // Load tracking & wall clock
    // -----------------------------------------------------------------------

    /// Spend the same work on a *rejected* initiation from an installed
    /// identity as an initiation from an unknown one would have cost.
    ///
    /// `identify_initiation` succeeds for an arbitrary claimed static key:
    /// producing one needs only this device's public key, not the claimed
    /// identity's private key. An attacker can therefore probe any key `X` and
    /// distinguish the two rejection paths by cost:
    ///
    /// * `X` installed → `Kdf₂` + one AEAD open against the *precomputed*
    ///   static-static secret. No asymmetric operation at all.
    /// * `X` unknown → a token from [`Self::unknown_authentications`], a full
    ///   X25519, then the same `Kdf₂` and AEAD open.
    ///
    /// On the MCUs this engine targets X25519 is software and costs
    /// milliseconds, so the gap is a membership oracle for the peer set,
    /// readable through any channel that exposes the engine's occupancy (it is
    /// single-threaded, so the latency of a *separate* handshake the attacker
    /// does control is enough) or through power analysis.
    ///
    /// wireguard-go has the opposite asymmetry — `ConsumeMessageInitiation`
    /// returns at `LookupPeer` and never performs a second scalar
    /// multiplication for an unknown key — so it cannot be inherited from the
    /// reference; it is a cost of the dynamic-peer extension.
    ///
    /// The two obvious fixes are both worse. Dropping
    /// `precomputed_static_static` would hand an attacker one X25519 per
    /// forged packet, which is the DoS the precomputation exists to prevent.
    /// Parking unknown initiations before proving possession would let anyone
    /// holding our public key spend resolver queries.
    ///
    /// So instead: charge both the failed known-key path and any suppressed
    /// unknown-key path the same budget and the same scalar multiplication as
    /// a fresh unknown identity. In the legitimate case this never runs — a
    /// real peer's initiation authenticates. Under a forgery flood the budget
    /// empties after `CoreConfig::unknown_auth_burst` attempts and every
    /// rejection path becomes cheap together, which preserves the equality and keeps the DoS
    /// ceiling exactly where it was.
    ///
    /// This equalises the dominant term, not every cycle; it is not a
    /// constant-time guarantee.
    fn equalize_unknown_identity_cost(&mut self, claimed_key: &[u8; 32], now: Instant) {
        if self.unknown_authentications.try_take(now) {
            let _ = dh(&self.s_priv, claimed_key);
        }
    }

    fn note_handshake_msg(&mut self, now: Instant) {
        let elapsed = now.saturating_since(self.hs_window_start);
        if elapsed >= Duration::from_secs(1) {
            // The window only advances when a message arrives, so a gap
            // longer than two windows means the previous count describes
            // traffic that stopped arbitrarily long ago. Carrying it forward
            // would leave `under_load` true after a burst and force a cookie
            // round-trip onto the first legitimate handshake that follows an
            // idle period. Only a genuinely adjacent window is history.
            self.hs_prev_count = if elapsed < Duration::from_secs(2) {
                self.hs_window_count
            } else {
                0
            };
            self.hs_window_count = 0;
            self.hs_window_start = now;
        }
        self.hs_window_count = self.hs_window_count.saturating_add(1);
    }

    fn under_load(&self, now: Instant) -> bool {
        let free = self
            .slots
            .iter()
            .filter(|s| match s {
                Slot::Free => true,
                Slot::Established(sess) => now.saturating_since(sess.created) >= REJECT_AFTER_TIME,
                _ => false,
            })
            .count();
        free <= self.core_config.under_load_free_slots
            || self.hs_window_count > self.core_config.under_load_handshakes_per_sec
            || self.hs_prev_count > self.core_config.under_load_handshakes_per_sec
    }

    /// Current TAI64N, extrapolated monotonically and forced strictly
    /// increasing across calls (initiation timestamps must never repeat or
    /// regress, §5.1 — a stalled RTC otherwise deadlocks us out of every
    /// peer that remembers our last handshake).
    fn timestamp(&mut self, now: Instant) -> Result<[u8; TIMESTAMP_LEN], Error> {
        let wall = self.wall.ok_or(Error::NoWallClock)?;
        let elapsed_ms = now.saturating_since(wall.base_instant).as_millis();
        let nanos_total = wall
            .base_unix_nanos
            .saturating_add(elapsed_ms.saturating_mul(1_000_000));
        let mut ts = tai64n(
            nanos_total / 1_000_000_000,
            (nanos_total % 1_000_000_000) as u32,
        )?;
        if ts <= self.last_ts {
            ts = next_whitened_timestamp(self.last_ts)?;
        }
        self.last_ts = ts;
        Ok(ts)
    }
}

/// Return the next representable timestamp while preserving WireGuard's
/// 24-bit nanosecond whitening.
fn next_whitened_timestamp(last: [u8; TIMESTAMP_LEN]) -> Result<[u8; TIMESTAMP_LEN], Error> {
    const QUANTUM: u32 = 1 << 24;

    let mut seconds_bytes = [0u8; 8];
    seconds_bytes.copy_from_slice(&last[..8]);
    let mut seconds = u64::from_be_bytes(seconds_bytes);

    let mut nanos_bytes = [0u8; 4];
    nanos_bytes.copy_from_slice(&last[8..]);
    let nanos = u32::from_be_bytes(nanos_bytes) & !0x00ff_ffff;
    let next_nanos = nanos.saturating_add(QUANTUM);

    let nanos = if next_nanos >= 1_000_000_000 {
        seconds = seconds.checked_add(1).ok_or(Error::TimeOverflow)?;
        0
    } else {
        next_nanos
    };

    let mut out = [0u8; TIMESTAMP_LEN];
    out[..8].copy_from_slice(&seconds.to_be_bytes());
    out[8..].copy_from_slice(&nanos.to_be_bytes());
    Ok(out)
}

/// Draw WireGuard's bounded rekey-timeout jitter.
///
/// The modulo bias over 334 millisecond values is negligible for a timer
/// whose purpose is desynchronization rather than secrecy. Keeping this a
/// single bounded RNG draw also preserves the core's strict progress bounds
/// if an embedding supplies a faulty RNG implementation.
fn rekey_timeout_jitter<R: rand_core::RngCore>(rng: &mut R) -> Duration {
    let jitter_range = REKEY_TIMEOUT_JITTER_MAX.as_millis().saturating_add(1);
    let jitter_ms = u64::from(rng.next_u32()) % jitter_range;
    Duration::from_millis(jitter_ms)
}

/// Return a stable WireGuard retransmission deadline for one initiation.
fn handshake_retry_deadline<R: rand_core::RngCore>(rng: &mut R, now: Instant) -> Instant {
    now + REKEY_TIMEOUT + rekey_timeout_jitter(rng)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Scenario tests for the engine.
///
/// These are deliberately few and wide: each one drives real `Core` instances
/// against each other through the public sans-IO API, so a single test walks
/// the Noise handshake, the AEAD transport path, cryptokey routing, the timer
/// wheel and the peer/session pools in one go. Behaviour that belongs to one
/// module is tested next to that module instead.
///
/// The `async` feature flips [`Sink`] and the event methods to native async in
/// place, so each scenario is written once as an `async fn` and desugared for
/// the default build by the same `maybe_async` the engine itself uses. Note
/// that `.await` may not appear inside a macro invocation anywhere below: a
/// macro's arguments are an opaque token stream to `must_be_sync`, so it would
/// survive into the synchronous build. Hoist it into a binding first.
///
/// The const parameters below are legal under both storage backends. The
/// allocation-free peer/session index structures require powers of two greater
/// than one; replay and route storage derive directly from their own capacities.
#[cfg(test)]
mod tests {
    #![allow(unused_imports)]

    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::collections::VecDeque;

    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    use super::*;

    // -----------------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------------

    /// A fixed instant well away from zero, so a saturated-to-zero deadline
    /// can never be mistaken for a correct one.
    const T0: Instant = Instant::from_millis(1_000_000);

    const IPPROTO_ICMP: u8 = 1;
    const IPPROTO_TCP: u8 = 6;
    const IPPROTO_UDP: u8 = 17;
    const TCP_SYN: u8 = 0x02;
    const TCP_ACK: u8 = 0x10;

    fn rng(seed: u8) -> ChaCha20Rng {
        ChaCha20Rng::from_seed([seed; 32])
    }

    fn keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
        let (private, public) = crypto::dh_generate(&mut rng(seed));
        (*private, public)
    }

    fn net4(a: u8, b: u8, c: u8, d: u8, len: u8) -> IpCidr {
        // `IpCidr` is canonical by construction, so build through `IpInet`
        // (which tolerates host bits) and take its network. That keeps the
        // host-bit cases these tests deliberately exercise expressible.
        crate::IpInet::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), len)
            .expect("valid prefix")
            .network()
    }

    fn net6(addr: Ipv6Addr, len: u8) -> IpCidr {
        crate::IpInet::new(IpAddr::V6(addr), len)
            .expect("valid prefix")
            .network()
    }

    /// An outer (physical network) address.
    fn outer(last: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, last)), 51820)
    }

    /// An inner (tunnel) address.
    fn tun(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(10, 0, 0, last)
    }

    /// A well-formed IPv4 packet whose `total_length` matches its real length.
    fn ipv4(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, payload: &[u8]) -> Vec<u8> {
        let total = 20 + payload.len();
        let mut packet = vec![0u8; total];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&src.octets());
        packet[16..20].copy_from_slice(&dst.octets());
        packet[20..].copy_from_slice(payload);
        packet
    }

    /// A well-formed IPv6 packet with a single, direct next header.
    fn ipv6(src: Ipv6Addr, dst: Ipv6Addr, next_header: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 40 + payload.len()];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        packet[6] = next_header;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&src.octets());
        packet[24..40].copy_from_slice(&dst.octets());
        packet[40..].copy_from_slice(payload);
        packet
    }

    fn udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut segment = vec![0u8; 8 + payload.len()];
        segment[0..2].copy_from_slice(&src_port.to_be_bytes());
        segment[2..4].copy_from_slice(&dst_port.to_be_bytes());
        segment[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        segment[8..].copy_from_slice(payload);
        segment
    }

    /// A 20-byte TCP header with no options.
    fn tcp(src_port: u16, dst_port: u16, flags: u8) -> Vec<u8> {
        let mut segment = vec![0u8; 20];
        segment[0..2].copy_from_slice(&src_port.to_be_bytes());
        segment[2..4].copy_from_slice(&dst_port.to_be_bytes());
        segment[12] = 0x50;
        segment[13] = flags;
        segment
    }

    fn icmp_echo(message_type: u8, identifier: u16) -> Vec<u8> {
        let mut body = vec![0u8; 8];
        body[0] = message_type;
        body[4..6].copy_from_slice(&identifier.to_be_bytes());
        body
    }

    /// An ICMPv4 destination-unreachable (fragmentation-needed) message
    /// quoting `provoking` — the error Path MTU Discovery depends on.
    fn icmp_error(src: Ipv4Addr, dst: Ipv4Addr, provoking: &[u8]) -> Vec<u8> {
        let mut body = vec![0u8; 8];
        body[0] = 3;
        body[1] = 4;
        body.extend_from_slice(provoking);
        ipv4(src, dst, IPPROTO_ICMP, &body)
    }

    // ---------------------------------------------------------------------------
    // Harness
    // ---------------------------------------------------------------------------

    /// Peer-table capacity: small enough that eviction is reachable, large enough
    /// for the three-node relay topology.
    const PEERS: usize = 4;
    /// Session-slot capacity. Kept well clear of `UNDER_LOAD_FREE_SLOTS` so that
    /// `under_load` is driven purely by the handshake rate in the cookie test and
    /// never trips accidentally elsewhere.
    const SESSIONS: usize = 8;
    /// Replay bitmap words per established session.
    const REPLAY_WORDS: usize = 128;
    /// Route-cache capacity.
    const ROUTES: usize = 8;

    type TestCore = Core<ChaCha20Rng, StaticRelayPolicy, PEERS, SESSIONS, REPLAY_WORDS, ROUTES>;

    /// Inspect stored resolver/configuration metadata in tests that exercise
    /// atomic peer-record updates. Runtime embeddings observe learned endpoints
    /// exclusively through `Sink::event`.
    fn stored_direct_endpoint(core: &TestCore, public_key: &[u8; 32]) -> Option<SocketAddr> {
        let pidx = core.find_peer(public_key)?;
        let peer = core.peers.get(pidx as usize)?.as_ref()?;
        peer.relay.is_none().then_some(peer.endpoint).flatten()
    }

    /// Collects everything the engine hands to its embedding. The slices the core
    /// passes borrow its internal buffers and are valid only for the duration of
    /// the call, so both methods copy.
    #[derive(Debug, Default)]
    struct Capture {
        outer: VecDeque<(SocketAddr, Vec<u8>)>,
        inner: Vec<([u8; 32], Vec<u8>)>,
        inner_endpoints: Vec<Option<SocketAddr>>,
        resolves: VecDeque<ResolveRequest>,
        events: Vec<Event>,
    }

    impl Capture {
        fn clear(&mut self) {
            self.outer.clear();
            self.inner.clear();
            self.inner_endpoints.clear();
            self.events.clear();
        }

        /// Message-type byte of every queued outer datagram, in order.
        fn outer_types(&self) -> Vec<u8> {
            self.outer.iter().map(|(_, datagram)| datagram[0]).collect()
        }

        fn take_outer(&mut self) -> Option<(SocketAddr, Vec<u8>)> {
            self.outer.pop_front()
        }

        fn expect_one_outer(&mut self) -> (SocketAddr, Vec<u8>) {
            assert_eq!(
                self.outer.len(),
                1,
                "expected exactly one outer datagram, saw types {:?}",
                self.outer_types()
            );
            self.outer.pop_front().expect("one datagram")
        }
    }

    #[cfg_attr(not(feature = "async"), maybe_async::must_be_sync)]
    impl Sink for Capture {
        async fn outer_datagram(&mut self, destination: SocketAddr, datagram: &[u8]) {
            assert!(
                !datagram.is_empty() && datagram.len() <= crate::MAX_UDP_SIZE,
                "engine emitted a datagram of {} bytes",
                datagram.len()
            );
            self.outer.push_back((destination, datagram.to_vec()));
        }

        fn resolve(&mut self, request: ResolveRequest) -> bool {
            self.resolves.push_back(request);
            true
        }

        fn event(&mut self, event: Event) {
            self.events.push(event);
        }

        async fn inner_packet(
            &mut self,
            src_peer_key: &[u8; 32],
            src_endpoint: Option<SocketAddr>,
            packet: &[u8],
        ) {
            self.inner.push((*src_peer_key, packet.to_vec()));
            self.inner_endpoints.push(src_endpoint);
        }
    }

    /// One engine plus the identity and outer address it is reachable at.
    struct Node {
        core: TestCore,
        addr: SocketAddr,
        public: [u8; 32],
        sink: Capture,
    }

    // Every core call is wrapped so the sink borrow is taken from `&mut self`
    // alongside the core borrow. Reaching through a `Vec` index twice in one
    // expression would ask for two overlapping `IndexMut` borrows instead.
    #[cfg_attr(not(feature = "async"), maybe_async::must_be_sync)]
    impl Node {
        async fn send_inner(&mut self, now: Instant, packet: &[u8]) -> Result<(), Error> {
            self.core.send_inner(now, packet, &mut self.sink).await
        }

        /// Decryption happens in place, so hand the engine a scratch copy and let
        /// callers keep the pristine bytes for replay and tamper checks.
        async fn receive_outer(
            &mut self,
            now: Instant,
            source: SocketAddr,
            datagram: &[u8],
        ) -> Result<(), Error> {
            let mut buf = datagram.to_vec();
            self.core
                .receive_outer(now, source, &mut buf, &mut self.sink)
                .await
        }

        async fn handle_timeout(&mut self, now: Instant) -> bool {
            self.core.handle_timeout(now, &mut self.sink).await
        }

        async fn resolve_completed(
            &mut self,
            now: Instant,
            response: ResolveResponse,
        ) -> Result<(), Error> {
            self.core
                .resolver_event_completed(now, ResolverEvent::Resolved(response), &mut self.sink)
                .await
        }

        async fn resolver_event_completed(
            &mut self,
            now: Instant,
            event: ResolverEvent,
        ) -> Result<(), Error> {
            self.core
                .resolver_event_completed(now, event, &mut self.sink)
                .await
        }

        fn next_resolve_request(&mut self) -> Option<ResolveRequest> {
            // Some tests exercise the internal request_* helpers directly rather
            // than entering through a public Core method. Public entry points
            // flush queued control-plane output before returning; mirror that
            // boundary here so direct queueing is observable through Capture too.
            self.core.flush_sink_output(&mut self.sink);
            self.sink.resolves.pop_front()
        }

        fn next_peer_evicted(&mut self) -> Option<[u8; 32]> {
            let index = self
                .sink
                .events
                .iter()
                .position(|event| matches!(event, Event::PeerEvicted { .. }))?;
            match self.sink.events.remove(index) {
                Event::PeerEvicted { public_key } => Some(public_key),
                _ => unreachable!("matched peer eviction event"),
            }
        }

        /// Run due timer work to completion, checking the documented contract:
        /// at most one action per call, and a `false` return marks the end of the
        /// due wave.
        async fn drain_timers(&mut self, now: Instant) -> usize {
            let mut steps = 0usize;
            while self.handle_timeout(now).await {
                steps += 1;
                assert!(steps < 512, "handle_timeout failed to converge");
            }
            let still_due = self.handle_timeout(now).await;
            assert!(!still_due, "a drained engine reported work as due");
            steps
        }
    }

    /// A set of nodes wired together by outer UDP address.
    struct Net {
        nodes: Vec<Node>,
    }

    #[cfg_attr(not(feature = "async"), maybe_async::must_be_sync)]
    impl Net {
        fn index_of(&self, addr: SocketAddr) -> Option<usize> {
            self.nodes.iter().position(|node| node.addr == addr)
        }

        /// Deliver queued datagrams until the network is quiescent. This is what
        /// makes these scenario tests: one call walks a whole handshake, including
        /// relayed paths, without the test spelling out each leg.
        async fn pump(&mut self, now: Instant) -> usize {
            let mut delivered = 0usize;
            loop {
                let mut next = None;
                for index in 0..self.nodes.len() {
                    if let Some(datagram) = self.nodes[index].sink.take_outer() {
                        next = Some((index, datagram));
                        break;
                    }
                }
                let Some((from, (destination, datagram))) = next else {
                    return delivered;
                };
                let to = self
                    .index_of(destination)
                    .unwrap_or_else(|| panic!("datagram addressed to unknown node {destination}"));
                let via = self.nodes[from].addr;
                self.nodes[to]
                    .receive_outer(now, via, &datagram)
                    .await
                    .expect("receive_outer must not fail on engine-produced input");
                delivered += 1;
                assert!(
                    delivered < 512,
                    "pump failed to converge (forwarding loop?)"
                );
            }
        }

        /// Send one probe packet and let the resulting handshake settle.
        async fn connect(&mut self, from: usize, src: Ipv4Addr, dst: Ipv4Addr, now: Instant) {
            let probe = ipv4(src, dst, IPPROTO_UDP, &udp(1024, 1024, b"probe"));
            self.nodes[from]
                .send_inner(now, &probe)
                .await
                .expect("probe packet accepted");
            self.pump(now).await;
        }

        /// Encapsulate one inner packet at `from`, hand the resulting datagram to
        /// `to`, and report whether it was delivered to `to`'s local stack.
        async fn send_and_deliver(
            &mut self,
            from: usize,
            to: usize,
            packet: &[u8],
            at: Instant,
        ) -> bool {
            self.nodes[from].sink.clear();
            self.nodes[from]
                .send_inner(at, packet)
                .await
                .expect("packet encapsulated");
            let (_, datagram) = self.nodes[from].sink.expect_one_outer();
            let via = self.nodes[from].addr;
            self.nodes[to].sink.clear();
            self.nodes[to]
                .receive_outer(at, via, &datagram)
                .await
                .expect("datagram processed");
            !self.nodes[to].sink.inner.is_empty()
        }
    }

    // ---------------------------------------------------------------------------
    // Fixtures
    // ---------------------------------------------------------------------------

    /// Build a node. The wall clock is injected immediately: handshake timestamps
    /// (§5.4.2) cannot be produced without one.
    fn node(
        seed: u8,
        addr: SocketAddr,
        peers: &[PinnedPeer<'_>],
        policy: StaticRelayPolicy,
        now: Instant,
    ) -> Node {
        node_with_core_config(seed, addr, peers, policy, now, CoreConfig::default())
    }

    fn node_with_core_config(
        seed: u8,
        addr: SocketAddr,
        peers: &[PinnedPeer<'_>],
        policy: StaticRelayPolicy,
        now: Instant,
        core_config: CoreConfig,
    ) -> Node {
        let (private, public) = keypair(seed);
        let core = TestCore::new(
            Config::new(private, peers).with_core_config(core_config),
            rng(seed.wrapping_add(0x40)),
            policy,
            now,
        )
        .expect("core construction");
        assert_eq!(core.public_key(), public);
        assert_eq!(*core.core_config(), core_config);
        let mut node = Node {
            core,
            addr,
            public,
            sink: Capture::default(),
        };
        node.core.set_unix_time(1_700_000_000, 0, now);
        assert!(node.core.has_wall_clock());
        node
    }

    fn pinned<'a>(
        public_key: [u8; 32],
        endpoint: Option<SocketAddr>,
        relay: Option<[u8; 32]>,
        addresses: &'a [IpCidr],
        inbound_policy: InboundPolicy,
    ) -> PinnedPeer<'a> {
        PinnedPeer {
            public_key,
            endpoint,
            relay,
            addresses,
            inbound_policy,
            persistent_keepalive: None,
        }
    }

    fn pinned_with_keepalive<'a>(
        public_key: [u8; 32],
        endpoint: Option<SocketAddr>,
        relay: Option<[u8; 32]>,
        addresses: &'a [IpCidr],
        inbound_policy: InboundPolicy,
        interval: Duration,
    ) -> PinnedPeer<'a> {
        let mut peer = pinned(public_key, endpoint, relay, addresses, inbound_policy);
        peer.persistent_keepalive = Some(interval);
        peer
    }

    fn addresses(nets: &[IpCidr]) -> PeerAddresses {
        let mut out = PeerAddresses::new();
        for net in nets {
            push_peer_address(&mut out, *net).expect("address fits");
        }
        out
    }

    fn resolved(
        public_key: [u8; 32],
        endpoint: Option<SocketAddr>,
        relay: Option<[u8; 32]>,
        nets: &[IpCidr],
    ) -> ResolvedPeer {
        ResolvedPeer {
            public_key,
            endpoint,
            relay,
            addresses: addresses(nets),
            inbound_policy: InboundPolicy::AllowAll,
            persistent_keepalive: None,
        }
    }

    // ---------------------------------------------------------------------------
    // Forged wire input
    // ---------------------------------------------------------------------------

    /// A well-formed initiation for `responder_pub` from a freshly minted
    /// identity: valid `mac1`, valid static-key proof, installed nowhere.
    fn forged_initiation(
        seed: u8,
        responder_pub: &[u8; 32],
        unix_secs: u64,
        now: Instant,
    ) -> Vec<u8> {
        let (private, public) = keypair(seed);
        let timestamp = crypto::tai64n(unix_secs, 0).expect("representable timestamp");
        let mut msg = [0u8; INITIATION_LEN];
        noise::create_initiation(
            &mut rng(seed.wrapping_add(0x80)),
            &private,
            &public,
            responder_pub,
            u32::from(seed) | 0x0100_0000,
            &timestamp,
            &mut msg,
        )
        .expect("initiation built");
        cookie::apply_macs(&mut msg, responder_pub, None, now).expect("macs applied");
        msg.to_vec()
    }

    // ---------------------------------------------------------------------------
    // 1. The data path
    // ---------------------------------------------------------------------------

    #[maybe_async::test(not(feature = "async"), async(feature = "async", tokio::test))]
    async fn handshake_completes_and_data_flows_in_both_directions() {
        let (_, a_pub) = keypair(1);
        let (_, b_pub) = keypair(2);
        let a_v6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        let b_v6 = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
        let a_nets = [net4(10, 0, 0, 1, 32), net6(a_v6, 128)];
        let b_nets = [net4(10, 0, 0, 2, 32), net6(b_v6, 128)];

        let a = node(
            1,
            outer(1),
            &[pinned(
                b_pub,
                Some(outer(2)),
                None,
                &b_nets,
                InboundPolicy::AllowAll,
            )],
            StaticRelayPolicy::DenyAll,
            T0,
        );
        let b = node(
            2,
            outer(2),
            &[pinned(
                a_pub,
                Some(outer(1)),
                None,
                &a_nets,
                InboundPolicy::AllowAll,
            )],
            StaticRelayPolicy::DenyAll,
            T0,
        );
        let mut net = Net { nodes: vec![a, b] };

        // --- One outbound packet drives the whole handshake -------------------
        let payload = ipv4(tun(1), tun(2), IPPROTO_UDP, &udp(4242, 53, b"hello tunnel"));
        net.nodes[0]
            .send_inner(T0, &payload)
            .await
            .expect("packet routed to the pinned peer");

        // The packet is parked; only the initiation goes out.
        let (destination, initiation) = net.nodes[0].sink.expect_one_outer();
        assert_eq!(destination, outer(2));
        assert_eq!(initiation[0], messages::MSG_INITIATION);
        assert_eq!(initiation.len(), INITIATION_LEN);

        net.nodes[1]
            .receive_outer(T0, outer(1), &initiation)
            .await
            .expect("initiation accepted");
        let (_, response) = net.nodes[1].sink.expect_one_outer();
        assert_eq!(response[0], messages::MSG_RESPONSE);
        assert_eq!(response.len(), RESPONSE_LEN);
        // §2.1: the responder reports the endpoint learned from the authenticated source.
        assert_eq!(
            net.nodes[1].sink.events,
            vec![Event::PeerEndpointUpdate {
                public_key: a_pub,
                endpoint: outer(1),
            }],
            "the first authenticated observation is reported even when it matches config"
        );

        // §5.4.5: the initiator must speak first to confirm the session, and the
        // parked packet is what does it — no separate keepalive is emitted.
        net.nodes[0]
            .receive_outer(T0, outer(2), &response)
            .await
            .expect("response accepted");
        let (_, data) = net.nodes[0].sink.expect_one_outer();
        assert_eq!(
            net.nodes[0].sink.events,
            vec![Event::PeerEndpointUpdate {
                public_key: b_pub,
                endpoint: outer(2),
            }],
        );
        assert_eq!(data[0], messages::MSG_DATA);
        // §5.4.6: the plaintext is padded to a 16-byte boundary before sealing.
        assert_eq!((data.len() - messages::DATA_OVERHEAD) % 16, 0);
        assert!(data.len() >= messages::DATA_HEADER_LEN + payload.len());

        net.nodes[1]
            .receive_outer(T0, outer(1), &data)
            .await
            .expect("transport data accepted");
        assert_eq!(
            net.nodes[1].sink.inner,
            vec![(a_pub, payload.clone())],
            "padding must be trimmed back to the exact IP packet"
        );
        assert_eq!(
            net.nodes[1].sink.inner_endpoints,
            vec![Some(outer(1))],
            "direct plaintext delivery must retain the authenticated UDP source"
        );
        assert!(net.nodes[1].sink.outer.is_empty());

        // --- Reverse direction, now that the responder session is confirmed ---
        net.nodes[0].sink.clear();
        net.nodes[1].sink.clear();
        let reply = ipv4(tun(2), tun(1), IPPROTO_UDP, &udp(53, 4242, b"hello back"));
        net.nodes[1]
            .send_inner(T0, &reply)
            .await
            .expect("reply sent");
        let (_, reply_datagram) = net.nodes[1].sink.expect_one_outer();
        net.nodes[0]
            .receive_outer(T0, outer(2), &reply_datagram)
            .await
            .expect("reply accepted");
        assert_eq!(net.nodes[0].sink.inner, vec![(b_pub, reply.clone())]);
        assert!(
            net.nodes[0].sink.events.is_empty(),
            "repeated traffic from an already-confirmed endpoint is coalesced"
        );

        // --- Replay: same bytes, same counter, already seen (§5.4.6) ----------
        net.nodes[0].sink.clear();
        net.nodes[0]
            .receive_outer(T0, outer(2), &reply_datagram)
            .await
            .expect("replays are dropped silently, not reported as errors");
        assert!(net.nodes[0].sink.inner.is_empty(), "a replay was delivered");

        // --- Tamper: one flipped ciphertext byte fails the AEAD ---------------
        let mut tampered = reply_datagram.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        net.nodes[0]
            .receive_outer(T0, outer(2), &tampered)
            .await
            .expect("forgeries are dropped silently");
        assert!(net.nodes[0].sink.inner.is_empty());

        // --- Cryptokey routing, inbound direction ----------------------------
        // A source the sending peer does not own is refused even though the
        // packet authenticates perfectly.
        net.nodes[0].sink.clear();
        net.nodes[1].sink.clear();
        let spoofed = ipv4(
            Ipv4Addr::new(192, 0, 2, 7),
            tun(2),
            IPPROTO_UDP,
            &udp(1, 1, b"spoof"),
        );
        net.nodes[0].send_inner(T0, &spoofed).await.expect("sent");
        let (_, spoofed_datagram) = net.nodes[0].sink.expect_one_outer();
        net.nodes[1]
            .receive_outer(T0, outer(1), &spoofed_datagram)
            .await
            .expect("dropped silently");
        assert!(
            net.nodes[1].sink.inner.is_empty(),
            "an inner source outside the peer's prefixes was delivered"
        );

        // --- IPv6 rides the same session and the same trie -------------------
        net.nodes[0].sink.clear();
        net.nodes[1].sink.clear();
        let v6_packet = ipv6(a_v6, b_v6, IPPROTO_UDP, &udp(9, 9, b"v6"));
        net.nodes[0]
            .send_inner(T0, &v6_packet)
            .await
            .expect("v6 routed");
        let (_, v6_datagram) = net.nodes[0].sink.expect_one_outer();
        net.nodes[1]
            .receive_outer(T0, outer(1), &v6_datagram)
            .await
            .expect("v6 accepted");
        assert_eq!(net.nodes[1].sink.inner, vec![(a_pub, v6_packet)]);

        // --- The largest packet the engine will encapsulate -------------------
        assert_eq!(crate::MAX_UDP_SIZE, 1500);
        assert_eq!(crate::MAX_INNER_SIZE, 1456);
        net.nodes[0].sink.clear();
        net.nodes[1].sink.clear();
        let bulk = ipv4(
            tun(1),
            tun(2),
            IPPROTO_UDP,
            &udp(1, 2, &vec![0xa5u8; crate::MAX_INNER_SIZE - 28]),
        );
        assert_eq!(bulk.len(), crate::MAX_INNER_SIZE);
        net.nodes[0]
            .send_inner(T0, &bulk)
            .await
            .expect("max-size packet sent");
        let (_, bulk_datagram) = net.nodes[0].sink.expect_one_outer();
        assert_eq!(
            bulk_datagram.len(),
            messages::DATA_OVERHEAD + crate::MAX_INNER_SIZE
        );
        net.nodes[1]
            .receive_outer(T0, outer(1), &bulk_datagram)
            .await
            .expect("max-size packet accepted");
        assert_eq!(net.nodes[1].sink.inner, vec![(a_pub, bulk)]);

        // Endpoint observations are event-only, and unchanged authenticated
        // traffic is coalesced rather than reported again.
        assert!(net.nodes[1].sink.events.is_empty());
    }

    // ---------------------------------------------------------------------------
    // 2. Protocol timers
    // ---------------------------------------------------------------------------

    #[maybe_async::test(not(feature = "async"), async(feature = "async", tokio::test))]
    async fn timers_emit_keepalives_and_reclaim_expired_sessions() {
        let (_, a_pub) = keypair(3);
        let (_, b_pub) = keypair(4);
        let a_nets = [net4(10, 0, 0, 1, 32)];
        let b_nets = [net4(10, 0, 0, 2, 32)];

        let a = node(
            3,
            outer(1),
            &[pinned(
                b_pub,
                Some(outer(2)),
                None,
                &b_nets,
                InboundPolicy::AllowAll,
            )],
            StaticRelayPolicy::DenyAll,
            T0,
        );
        let b = node(
            4,
            outer(2),
            &[pinned(
                a_pub,
                Some(outer(1)),
                None,
                &a_nets,
                InboundPolicy::AllowAll,
            )],
            StaticRelayPolicy::DenyAll,
            T0,
        );
        let mut net = Net { nodes: vec![a, b] };
        net.connect(0, tun(1), tun(2), T0).await;
        assert_eq!(
            net.nodes[1].sink.inner.len(),
            1,
            "handshake did not complete"
        );
        net.nodes[0].sink.clear();
        net.nodes[1].sink.clear();

        // Having received data, the responder owes a reply; a passive keepalive
        // discharges that obligation after Keepalive-Timeout (§6.5). `poll_at` is
        // a lower bound, so it must be at or before the true deadline.
        let poll = net.nodes[1].core.poll_at().expect("a deadline is pending");
        assert!(
            poll <= T0 + KEEPALIVE_TIMEOUT,
            "keepalive deadline not armed"
        );

        let keepalive_at = T0 + KEEPALIVE_TIMEOUT;
        let steps = net.nodes[1].drain_timers(keepalive_at).await;
        assert_eq!(steps, 1, "exactly one timer action was due");
        let (destination, keepalive) = net.nodes[1].sink.expect_one_outer();
        assert_eq!(destination, outer(1));
        assert_eq!(keepalive[0], messages::MSG_DATA);
        assert_eq!(
            keepalive.len(),
            messages::DATA_OVERHEAD,
            "a keepalive is a zero-length transport message"
        );

        // A keepalive authenticates but carries nothing to deliver, and does not
        // itself demand a reply — two idle peers must not ping-pong forever.
        net.nodes[0]
            .receive_outer(keepalive_at, outer(2), &keepalive)
            .await
            .expect("keepalive accepted");
        assert!(net.nodes[0].sink.inner.is_empty());
        assert!(net.nodes[0].sink.outer.is_empty());

        // --- Reject-After-Time: sessions are reclaimed, not merely unused -----
        let expiry = T0 + REJECT_AFTER_TIME;
        net.nodes[0].sink.clear();
        net.nodes[1].sink.clear();
        let initiator_steps = net.nodes[0].drain_timers(expiry).await;
        let responder_steps = net.nodes[1].drain_timers(expiry).await;
        assert_eq!((initiator_steps, responder_steps), (1, 1));
        assert!(
            net.nodes[0].sink.outer.is_empty() && net.nodes[1].sink.outer.is_empty(),
            "an expired session must not transmit"
        );
        assert_eq!(
            net.nodes[0].core.poll_at(),
            None,
            "a fully idle engine reports no deadline"
        );
        assert_eq!(net.nodes[1].core.poll_at(), None);

        // With the pool drained, the next packet starts a fresh handshake rather
        // than encrypting under the dead session.
        let packet = ipv4(tun(1), tun(2), IPPROTO_UDP, &udp(1, 1, b"after expiry"));
        net.nodes[0]
            .send_inner(expiry, &packet)
            .await
            .expect("sent");
        assert_eq!(
            net.nodes[0].sink.outer_types(),
            vec![messages::MSG_INITIATION]
        );
    }

    #[maybe_async::test(not(feature = "async"), async(feature = "async", tokio::test))]
    async fn data_sent_arms_missing_reply_timer_with_jitter() {
        let (_, a_pub) = keypair(82);
        let (_, b_pub) = keypair(83);
        let a_nets = [net4(10, 0, 0, 1, 32)];
        let b_nets = [net4(10, 0, 0, 2, 32)];

        let a = node(
            82,
            outer(1),
            &[pinned(
                b_pub,
                Some(outer(2)),
                None,
                &b_nets,
                InboundPolicy::AllowAll,
            )],
            StaticRelayPolicy::DenyAll,
            T0,
        );
        let b = node(
            83,
            outer(2),
            &[pinned(
                a_pub,
                Some(outer(1)),
                None,
                &a_nets,
                InboundPolicy::AllowAll,
            )],
            StaticRelayPolicy::DenyAll,
            T0,
        );
        let mut net = Net { nodes: vec![a, b] };
        net.connect(0, tun(1), tun(2), T0).await;
        net.nodes[0].sink.clear();
        net.nodes[1].sink.clear();

        // Let B's passive keepalive acknowledge the probe so A has no old
        // missing-reply timer when the packet under test is sent.
        let keepalive_at = T0 + KEEPALIVE_TIMEOUT;
        assert_eq!(net.nodes[1].drain_timers(keepalive_at).await, 1);
        let (_, keepalive) = net.nodes[1].sink.expect_one_outer();
        net.nodes[0]
            .receive_outer(keepalive_at, outer(2), &keepalive)
            .await
            .expect("passive keepalive accepted");
        net.nodes[0].sink.clear();

        // Make the next jitter draw non-zero so this test catches a regression
        // back to the old fixed KEEPALIVE_TIMEOUT + REKEY_TIMEOUT deadline.
        loop {
            let mut probe_rng = net.nodes[0].core.rng.clone();
            if rekey_timeout_jitter(&mut probe_rng).as_millis() != 0 {
                break;
            }
            let _ = rekey_timeout_jitter(&mut net.nodes[0].core.rng);
        }
        let mut expected_rng = net.nodes[0].core.rng.clone();
        let expected_jitter = rekey_timeout_jitter(&mut expected_rng);
        let sent_at = keepalive_at + Duration::from_secs(1);
        let packet = ipv4(tun(1), tun(2), IPPROTO_UDP, &udp(1, 1, b"needs reply"));
        net.nodes[0]
            .send_inner(sent_at, &packet)
            .await
            .expect("packet encrypted");

        let pidx = net.nodes[0]
            .core
            .find_peer(&b_pub)
            .expect("configured peer");
        let reply_due = net.nodes[0].core.peers[pidx as usize]
            .as_ref()
            .and_then(|peer| peer.sessions.reply_due)
            .expect("missing-reply timer armed");
        let base = sent_at + KEEPALIVE_TIMEOUT + REKEY_TIMEOUT;
        assert_eq!(reply_due, base + expected_jitter);
        assert!(reply_due > base);
        assert!(reply_due <= base + REKEY_TIMEOUT_JITTER_MAX);

        // The fixed, unjittered deadline must not fire the new-handshake timer.
        net.nodes[0].sink.clear();
        assert_eq!(net.nodes[0].drain_timers(base).await, 0);
        assert!(net.nodes[0].sink.outer.is_empty());

        // The sampled deadline does.
        assert_eq!(net.nodes[0].drain_timers(reply_due).await, 1);
        assert_eq!(
            net.nodes[0].sink.outer_types(),
            vec![messages::MSG_INITIATION]
        );
    }

    #[maybe_async::test(not(feature = "async"), async(feature = "async", tokio::test))]
    async fn persistent_keepalive_sends_an_empty_transport_after_idle() {
        let (_, a_pub) = keypair(80);
        let (_, b_pub) = keypair(81);
        let a_nets = [net4(10, 0, 0, 1, 32)];
        let b_nets = [net4(10, 0, 0, 2, 32)];
        let interval = Duration::from_secs(25);

        let a = node(
            80,
            outer(1),
            &[pinned_with_keepalive(
                b_pub,
                Some(outer(2)),
                None,
                &b_nets,
                InboundPolicy::AllowAll,
                interval,
            )],
            StaticRelayPolicy::DenyAll,
            T0,
        );
        let b = node(
            81,
            outer(2),
            &[pinned(
                a_pub,
                Some(outer(1)),
                None,
                &a_nets,
                InboundPolicy::AllowAll,
            )],
            StaticRelayPolicy::DenyAll,
            T0,
        );
        let mut net = Net { nodes: vec![a, b] };
        net.connect(0, tun(1), tun(2), T0).await;
        net.nodes[0].sink.clear();
        net.nodes[1].sink.clear();

        // B's passive keepalive acknowledges A's initial data and resets A's
        // persistent-idle timer from an authenticated receive.
        let passive_at = T0 + KEEPALIVE_TIMEOUT;
        assert_eq!(net.nodes[1].drain_timers(passive_at).await, 1);
        let (_, passive) = net.nodes[1].sink.expect_one_outer();
        net.nodes[0]
            .receive_outer(passive_at, outer(2), &passive)
            .await
            .expect("passive keepalive accepted");
        net.nodes[0].sink.clear();

        let persistent_at = passive_at + interval;
        let poll = net.nodes[0]
            .core
            .poll_at()
            .expect("persistent keepalive deadline is armed");
        assert!(poll <= persistent_at);
        assert_eq!(net.nodes[0].drain_timers(persistent_at).await, 1);

        let (destination, keepalive) = net.nodes[0].sink.expect_one_outer();
        assert_eq!(destination, outer(2));
        assert_eq!(keepalive[0], messages::MSG_DATA);
        assert_eq!(
            keepalive.len(),
            messages::DATA_OVERHEAD,
            "persistent keepalive is an empty authenticated transport packet"
        );
    }

    #[maybe_async::test(not(feature = "async"), async(feature = "async", tokio::test))]
    async fn only_the_initiator_rekeys_on_the_send_path() {
        let (_, a_pub) = keypair(5);
        let (_, b_pub) = keypair(6);
        let a_nets = [net4(10, 0, 0, 1, 32)];
        let b_nets = [net4(10, 0, 0, 2, 32)];

        let a = node(
            5,
            outer(1),
            &[pinned(
                b_pub,
                Some(outer(2)),
                None,
                &b_nets,
                InboundPolicy::AllowAll,
            )],
            StaticRelayPolicy::DenyAll,
            T0,
        );
        let b = node(
            6,
            outer(2),
            &[pinned(
                a_pub,
                Some(outer(1)),
                None,
                &a_nets,
                InboundPolicy::AllowAll,
            )],
            StaticRelayPolicy::DenyAll,
            T0,
        );
        let mut net = Net { nodes: vec![a, b] };
        net.connect(0, tun(1), tun(2), T0).await;

        let rekey_at = T0 + REKEY_AFTER_TIME;

        // §6.2: the time-based rekey duty belongs to the initiator alone, so the
        // responder sending at the same session age starts nothing.
        net.nodes[1].sink.clear();
        let from_responder = ipv4(tun(2), tun(1), IPPROTO_UDP, &udp(1, 1, b"responder"));
        net.nodes[1]
            .send_inner(rekey_at, &from_responder)
            .await
            .expect("sent");
        assert_eq!(net.nodes[1].sink.outer_types(), vec![messages::MSG_DATA]);

        net.nodes[0].sink.clear();
        let from_initiator = ipv4(tun(1), tun(2), IPPROTO_UDP, &udp(1, 1, b"initiator"));
        net.nodes[0]
            .send_inner(rekey_at, &from_initiator)
            .await
            .expect("sent");
        assert_eq!(
            net.nodes[0].sink.outer_types(),
            vec![messages::MSG_DATA, messages::MSG_INITIATION],
            "the packet still goes out under the old session, then a rekey starts"
        );

        // The trigger fires once per session, not once per packet.
        net.nodes[0].sink.clear();
        net.nodes[0]
            .send_inner(rekey_at, &from_initiator)
            .await
            .expect("sent");
        assert_eq!(net.nodes[0].sink.outer_types(), vec![messages::MSG_DATA]);
    }

    // ---------------------------------------------------------------------------
    // 3. Dynamic peers: resolution by destination address
    // ---------------------------------------------------------------------------

    #[maybe_async::test(not(feature = "async"), async(feature = "async", tokio::test))]
    async fn outbound_packet_resolves_an_unknown_destination_and_is_replayed() {
        let (_, a_pub) = keypair(7);
        let (_, b_pub) = keypair(8);
        let a_nets = [net4(10, 0, 0, 1, 32)];
        let b_nets = [net4(10, 0, 0, 2, 32)];

        // A starts with no peers at all: everything it knows comes from the
        // resolver.
        let a = node(7, outer(1), &[], StaticRelayPolicy::DenyAll, T0);
        let b = node(
            8,
            outer(2),
            &[pinned(
                a_pub,
                Some(outer(1)),
                None,
                &a_nets,
                InboundPolicy::AllowAll,
            )],
            StaticRelayPolicy::DenyAll,
            T0,
        );
        let mut net = Net { nodes: vec![a, b] };

        let payload = ipv4(tun(1), tun(2), IPPROTO_UDP, &udp(7, 7, b"resolve me"));
        net.nodes[0]
            .send_inner(T0, &payload)
            .await
            .expect("unrouted packets are parked, not rejected");
        assert!(
            net.nodes[0].sink.outer.is_empty(),
            "nothing can be sent before the destination is known"
        );

        let request = net.nodes[0]
            .next_resolve_request()
            .expect("a by-address lookup was queued");
        assert_eq!(
            request.query(),
            ResolveQuery::ByDstAddress(IpAddr::V4(tun(2)))
        );
        assert!(
            net.nodes[0].next_resolve_request().is_none(),
            "a request is emitted exactly once"
        );

        // A second packet for the same destination rides the in-flight lookup
        // rather than starting another one.
        net.nodes[0]
            .send_inner(T0, &payload)
            .await
            .expect("parked behind the existing query");
        assert!(net.nodes[0].next_resolve_request().is_none());

        net.nodes[0]
            .resolve_completed(
                T0,
                request.complete(ResolveOutcome::Found(resolved(
                    b_pub,
                    Some(outer(2)),
                    None,
                    &b_nets,
                ))),
            )
            .await
            .expect("answer applied");

        // Both parked packets re-enter the outbound path, find the new route, and
        // share the single handshake they trigger between them.
        assert_eq!(
            net.nodes[0].sink.outer_types(),
            vec![messages::MSG_INITIATION]
        );
        assert_eq!(
            stored_direct_endpoint(&net.nodes[0].core, &b_pub),
            Some(outer(2))
        );
        net.nodes[0].core.assert_peer_index_consistent();

        net.pump(T0).await;
        assert_eq!(
            net.nodes[1].sink.inner.len(),
            2,
            "both parked packets survived the handshake"
        );
        assert_eq!(net.nodes[1].sink.inner[0], (a_pub, payload.clone()));

        // --- A held-peer update refreshes the dynamic record --------------------
        //
        // Freshness is delivered by the change-broadcast transport, so no timer arms a
        // lookup of its own: nothing is due but the protocol's own deadlines.
        assert!(
            net.nodes[0].next_resolve_request().is_none(),
            "an installed dynamic peer must not schedule lookups of its own",
        );
        let updated_at = T0 + Duration::from_secs(1);
        net.nodes[0].sink.clear();

        // The prior endpoint was just confirmed by authenticated traffic, but
        // an accepted resolver record is still a complete replacement. Local
        // roaming evidence from the previous record must not override it.
        net.nodes[0]
            .resolver_event_completed(
                updated_at,
                ResolverEvent::PeerUpdated(PeerUpdate::new(
                    b_pub,
                    ResolveOutcome::Found(resolved(b_pub, Some(outer(4)), None, &b_nets)),
                )),
            )
            .await
            .expect("held-peer update applied");
        assert_eq!(
            stored_direct_endpoint(&net.nodes[0].core, &b_pub),
            Some(outer(4))
        );
        net.nodes[0].core.assert_peer_index_consistent();
    }

    #[maybe_async::test(not(feature = "async"), async(feature = "async", tokio::test))]
    async fn dynamic_peer_watch_updates_and_authoritative_deletion_converge() {
        let (_, b_pub) = keypair(18);
        let b_nets = [net4(10, 0, 0, 18, 32)];
        let mut a = node(17, outer(1), &[], StaticRelayPolicy::DenyAll, T0);

        let packet = ipv4(tun(1), tun(18), IPPROTO_UDP, &udp(7, 7, b"watch me"));
        a.send_inner(T0, &packet).await.expect("lookup queued");
        let request = a.next_resolve_request().expect("by-address lookup queued");
        a.resolve_completed(
            T0,
            request.complete(ResolveOutcome::Found(resolved(
                b_pub,
                Some(outer(2)),
                None,
                &b_nets,
            ))),
        )
        .await
        .expect("dynamic peer installed");

        // Installing a resolved peer asks for no subscription of its own: the
        // answer that installed it already carried one.
        assert!(a.next_peer_evicted().is_none());

        a.resolver_event_completed(
            T0 + Duration::from_secs(1),
            ResolverEvent::PeerUpdated(PeerUpdate::new(
                b_pub,
                ResolveOutcome::Found(resolved(b_pub, Some(outer(4)), None, &b_nets)),
            )),
        )
        .await
        .expect("held-peer update applied");
        assert_eq!(stored_direct_endpoint(&a.core, &b_pub), Some(outer(4)));

        // Omission is replacement too: it clears the old endpoint rather than
        // inheriting it from the previous accepted record.
        a.resolver_event_completed(
            T0 + Duration::from_secs(2),
            ResolverEvent::PeerUpdated(PeerUpdate::new(
                b_pub,
                ResolveOutcome::Found(resolved(b_pub, None, None, &b_nets)),
            )),
        )
        .await
        .expect("endpoint-clearing held-peer update applied");
        assert_eq!(stored_direct_endpoint(&a.core, &b_pub), None);

        a.resolver_event_completed(
            T0 + Duration::from_secs(3),
            ResolverEvent::PeerUpdated(PeerUpdate::new(b_pub, ResolveOutcome::NotFound)),
        )
        .await
        .expect("authoritative deletion applied");
        assert!(a.core.find_peer(&b_pub).is_none());
        assert_eq!(a.next_peer_evicted(), Some(b_pub));
        assert!(a.next_peer_evicted().is_none());
        a.core.assert_peer_index_consistent();
    }

    /// A held-peer update that cannot be installed must change *nothing*.
    ///
    /// The failure mode this pins down is a peer left describing one answer's
    /// endpoint and a previous answer's addresses: a record that never existed
    /// on the Peers API server, and which nothing would later correct.
    #[maybe_async::test(not(feature = "async"), async(feature = "async", tokio::test))]
    async fn a_watched_update_that_does_not_fit_changes_nothing() {
        let (_, b_pub) = keypair(21);
        let (_, filler_pub) = keypair(22);

        // Pin seven of the eight route slots. Pinned peers are never eviction
        // victims, so the eighth is the only one that can ever be reclaimed.
        let filler_nets = [
            net4(10, 9, 1, 0, 24),
            net4(10, 9, 2, 0, 24),
            net4(10, 9, 3, 0, 24),
            net4(10, 9, 4, 0, 24),
        ];
        let more_nets = [
            net4(10, 9, 5, 0, 24),
            net4(10, 9, 6, 0, 24),
            net4(10, 9, 7, 0, 24),
        ];
        let (_, other_pub) = keypair(23);
        let mut a = node(
            20,
            outer(1),
            &[
                pinned(
                    filler_pub,
                    Some(outer(9)),
                    None,
                    &filler_nets,
                    InboundPolicy::AllowAll,
                ),
                pinned(
                    other_pub,
                    Some(outer(10)),
                    None,
                    &more_nets,
                    InboundPolicy::AllowAll,
                ),
            ],
            StaticRelayPolicy::DenyAll,
            T0,
        );

        // Install a dynamic peer in the one remaining slot.
        let b_nets = [net4(10, 0, 0, 21, 32)];
        let packet = ipv4(tun(1), tun(21), IPPROTO_UDP, &udp(7, 7, b"install"));
        a.send_inner(T0, &packet).await.expect("lookup queued");
        let request = a.next_resolve_request().expect("by-address lookup queued");
        a.resolve_completed(
            T0,
            request.complete(ResolveOutcome::Found(resolved(
                b_pub,
                Some(outer(2)),
                None,
                &b_nets,
            ))),
        )
        .await
        .expect("dynamic peer installed");
        assert_eq!(stored_direct_endpoint(&a.core, &b_pub), Some(outer(2)));

        // A held-peer update that both moves the endpoint and grows the address
        // set past the remaining capacity. There is no eligible victim: every
        // other peer is pinned.
        let grown = [
            net4(10, 0, 1, 0, 24),
            net4(10, 0, 2, 0, 24),
            net4(10, 0, 3, 0, 24),
            net4(10, 0, 4, 0, 24),
        ];
        let at = T0 + Duration::from_secs(1);
        a.resolver_event_completed(
            at,
            ResolverEvent::PeerUpdated(PeerUpdate::new(
                b_pub,
                ResolveOutcome::Found(resolved(b_pub, Some(outer(4)), None, &grown)),
            )),
        )
        .await
        .expect("the rejected update is not an error");

        // Neither half of the answer was applied. Previously the endpoint moved
        // while the addresses stayed behind.
        assert_eq!(
            stored_direct_endpoint(&a.core, &b_pub),
            Some(outer(2)),
            "metadata must not be applied when the address set could not be"
        );
        assert!(
            a.core.find_peer(&b_pub).is_some(),
            "a rejected update is not an authoritative removal"
        );
        a.core.assert_peer_index_consistent();
    }

    /// A by-key lookup can finish after another lookup has already installed
    /// the same peer. If the late answer does not fit, it must not partially
    /// replace metadata on the now-existing peer.
    #[maybe_async::test(not(feature = "async"), async(feature = "async", tokio::test))]
    async fn by_key_install_race_that_does_not_fit_keeps_the_previous_complete_record() {
        let (_, b_pub) = keypair(120);
        let filler_pub = keypair(121).1;
        let other_pub = keypair(122).1;
        let filler_nets = [
            net4(10, 101, 1, 0, 24),
            net4(10, 101, 2, 0, 24),
            net4(10, 101, 3, 0, 24),
            net4(10, 101, 4, 0, 24),
        ];
        let other_nets = [
            net4(10, 102, 1, 0, 24),
            net4(10, 102, 2, 0, 24),
            net4(10, 102, 3, 0, 24),
        ];
        let mut a = node(
            123,
            outer(1),
            &[
                pinned(
                    filler_pub,
                    Some(outer(9)),
                    None,
                    &filler_nets,
                    InboundPolicy::AllowAll,
                ),
                pinned(
                    other_pub,
                    Some(outer(10)),
                    None,
                    &other_nets,
                    InboundPolicy::AllowAll,
                ),
            ],
            StaticRelayPolicy::DenyAll,
            T0,
        );

        // Start a by-key install first, but leave it in flight.
        a.core.request_peer_install(b_pub, T0);
        let by_key = a.next_resolve_request().expect("by-key lookup queued");
        assert_eq!(by_key.query(), ResolveQuery::ByPublicKey(b_pub));

        // A by-address lookup for the same identity completes first and fills
        // the one route slot left after the pinned peers.
        let old_nets = [net4(10, 103, 0, 21, 32)];
        let packet = ipv4(
            tun(1),
            Ipv4Addr::new(10, 103, 0, 21),
            IPPROTO_UDP,
            &udp(7, 7, b"race"),
        );
        a.send_inner(T0, &packet)
            .await
            .expect("by-address lookup queued");
        let by_address = a
            .next_resolve_request()
            .expect("by-address lookup emitted independently");
        a.resolve_completed(
            T0,
            by_address.complete(ResolveOutcome::Found(resolved(
                b_pub,
                Some(outer(2)),
                None,
                &old_nets,
            ))),
        )
        .await
        .expect("first answer installs the peer");
        assert_eq!(stored_direct_endpoint(&a.core, &b_pub), Some(outer(2)));
        assert_eq!(a.core.routes.available_slots(), 0);

        // The older by-key lookup now returns a different complete record that
        // needs more route slots. Every possible victim is pinned, so this
        // replacement must fail before touching endpoint or addresses.
        let grown = [
            net4(10, 104, 1, 0, 24),
            net4(10, 104, 2, 0, 24),
            net4(10, 104, 3, 0, 24),
            net4(10, 104, 4, 0, 24),
        ];
        a.resolve_completed(
            T0 + Duration::from_secs(1),
            by_key.complete(ResolveOutcome::Found(resolved(
                b_pub,
                Some(outer(4)),
                None,
                &grown,
            ))),
        )
        .await
        .expect("capacity rejection is not surfaced as a core error");

        let pidx = a.core.find_peer(&b_pub).expect("existing peer retained");
        assert_eq!(stored_direct_endpoint(&a.core, &b_pub), Some(outer(2)));
        assert_eq!(
            a.core
                .routes
                .lookup_readonly(&IpAddr::V4(Ipv4Addr::new(10, 103, 0, 21))),
            Some(pidx),
            "the previous route remains installed"
        );
        assert!(
            a.core
                .routes
                .lookup_readonly(&IpAddr::V4(Ipv4Addr::new(10, 104, 1, 1)))
                .is_none(),
            "none of the rejected route set was committed"
        );
    }

    /// The inverse race is possible too: a by-address lookup can finish after
    /// a by-key install has populated the peer. Its replacement must use the
    /// same atomic commit path.
    #[maybe_async::test(not(feature = "async"), async(feature = "async", tokio::test))]
    async fn outbound_lookup_race_that_does_not_fit_keeps_the_previous_complete_record() {
        let b_pub = keypair(124).1;
        let filler_pub = keypair(125).1;
        let other_pub = keypair(126).1;
        let filler_nets = [
            net4(10, 105, 1, 0, 24),
            net4(10, 105, 2, 0, 24),
            net4(10, 105, 3, 0, 24),
            net4(10, 105, 4, 0, 24),
        ];
        let other_nets = [
            net4(10, 106, 1, 0, 24),
            net4(10, 106, 2, 0, 24),
            net4(10, 106, 3, 0, 24),
        ];
        let mut a = node(
            127,
            outer(1),
            &[
                pinned(
                    filler_pub,
                    Some(outer(9)),
                    None,
                    &filler_nets,
                    InboundPolicy::AllowAll,
                ),
                pinned(
                    other_pub,
                    Some(outer(10)),
                    None,
                    &other_nets,
                    InboundPolicy::AllowAll,
                ),
            ],
            StaticRelayPolicy::DenyAll,
            T0,
        );

        // Leave the by-address lookup outstanding.
        let target = Ipv4Addr::new(10, 108, 0, 99);
        let packet = ipv4(tun(1), target, IPPROTO_UDP, &udp(7, 7, b"race"));
        a.send_inner(T0, &packet)
            .await
            .expect("by-address lookup queued");
        let by_address = a.next_resolve_request().expect("by-address lookup emitted");
        assert_eq!(
            by_address.query(),
            ResolveQuery::ByDstAddress(IpAddr::V4(target))
        );

        // While it is in flight, a by-key install for that identity wins the
        // race and occupies the final route slot.
        a.core.request_peer_install(b_pub, T0);
        let by_key = a.next_resolve_request().expect("by-key lookup emitted");
        let old_nets = [net4(10, 107, 0, 1, 32)];
        a.resolve_completed(
            T0,
            by_key.complete(ResolveOutcome::Found(resolved(
                b_pub,
                Some(outer(2)),
                None,
                &old_nets,
            ))),
        )
        .await
        .expect("by-key answer installs the peer");
        assert_eq!(a.core.routes.available_slots(), 0);

        // The by-address answer covers its query, but its complete route set
        // cannot fit. Endpoint and old routes must therefore remain together.
        let grown = [
            net4(10, 108, 0, 99, 32),
            net4(10, 108, 1, 0, 24),
            net4(10, 108, 2, 0, 24),
            net4(10, 108, 3, 0, 24),
        ];
        a.resolve_completed(
            T0 + Duration::from_secs(1),
            by_address.complete(ResolveOutcome::Found(resolved(
                b_pub,
                Some(outer(4)),
                None,
                &grown,
            ))),
        )
        .await
        .expect("capacity rejection is handled locally");

        let pidx = a.core.find_peer(&b_pub).expect("existing peer retained");
        assert_eq!(stored_direct_endpoint(&a.core, &b_pub), Some(outer(2)));
        assert_eq!(
            a.core
                .routes
                .lookup_readonly(&IpAddr::V4(Ipv4Addr::new(10, 107, 0, 1))),
            Some(pidx)
        );
        assert!(a.core.routes.lookup_readonly(&IpAddr::V4(target)).is_none());
    }

    /// ...and the reconciliation it could not complete is still owed.
    ///
    /// The record is now known to be possibly stale, so forgetting the
    /// obligation would leave it that way until something unrelated disturbed
    /// it. The retry is deliberately delayed rather than immediate.
    #[maybe_async::test(not(feature = "async"), async(feature = "async", tokio::test))]
    async fn an_uninstallable_watched_update_is_retried_later() {
        let (_, b_pub) = keypair(25);
        let b_nets = [net4(10, 0, 0, 25, 32)];
        let mut a = node(24, outer(1), &[], StaticRelayPolicy::DenyAll, T0);

        let packet = ipv4(tun(1), tun(25), IPPROTO_UDP, &udp(7, 7, b"install"));
        a.send_inner(T0, &packet).await.expect("lookup queued");
        let request = a.next_resolve_request().expect("by-address lookup queued");
        a.resolve_completed(
            T0,
            request.complete(ResolveOutcome::Found(resolved(
                b_pub,
                Some(outer(2)),
                None,
                &b_nets,
            ))),
        )
        .await
        .expect("dynamic peer installed");
        assert!(a.next_resolve_request().is_none());

        // An answer this device refuses: a peer that relays through itself.
        let at = T0 + Duration::from_secs(1);
        a.resolver_event_completed(
            at,
            ResolverEvent::PeerUpdated(PeerUpdate::new(
                b_pub,
                ResolveOutcome::Found(resolved(b_pub, Some(outer(4)), Some(b_pub), &b_nets)),
            )),
        )
        .await
        .expect("the rejected update is not an error");
        assert_eq!(stored_direct_endpoint(&a.core, &b_pub), Some(outer(2)));

        // Not retried immediately: a record that failed once will usually fail
        // again on the next round trip, and the resolve budget is finite.
        assert!(
            a.next_resolve_request().is_none(),
            "the retry must not be issued before its delay elapses"
        );

        // Once the delay passes, the obligation becomes an ordinary by-key
        // lookup — the same path a peer invalidation and a reconnect replay use.
        let due = at + a.core.core_config().negative_ttl;
        while a.handle_timeout(due).await {}
        let retry = a
            .next_resolve_request()
            .expect("the reconciliation is retried");
        assert_eq!(retry.query(), ResolveQuery::ByPublicKey(b_pub));

        // A good answer discharges it: no further retry is scheduled.
        a.resolve_completed(
            due,
            retry.complete(ResolveOutcome::Found(resolved(
                b_pub,
                Some(outer(5)),
                None,
                &b_nets,
            ))),
        )
        .await
        .expect("the reconciliation applies");
        assert_eq!(stored_direct_endpoint(&a.core, &b_pub), Some(outer(5)));

        let later = due + a.core.core_config().negative_ttl + Duration::from_secs(1);
        while a.handle_timeout(later).await {}
        assert!(
            a.next_resolve_request().is_none(),
            "a discharged obligation must not keep re-asking"
        );
        a.core.assert_peer_index_consistent();
    }

    // ---------------------------------------------------------------------------
    // 4. Resolver policy and negative caching
    // ---------------------------------------------------------------------------

    #[maybe_async::test(not(feature = "async"), async(feature = "async", tokio::test))]
    async fn resolver_answers_are_validated_and_authoritative_misses_are_cached() {
        let (_, pinned_pub) = keypair(9);
        let (_, other_pub) = keypair(10);
        let pinned_nets = [net4(10, 0, 0, 9, 32)];

        let mut a = node(
            11,
            outer(1),
            &[pinned(
                pinned_pub,
                Some(outer(9)),
                None,
                &pinned_nets,
                InboundPolicy::AllowAll,
            )],
            StaticRelayPolicy::DenyAll,
            T0,
        );
        let own_pub = a.public;

        // A well-formed answer installs.
        assert!(
            a.core
                .upsert_peer(
                    &resolved(other_pub, Some(outer(2)), None, &[net4(10, 0, 0, 2, 32)]),
                    T0
                )
                .is_ok()
        );

        // Every rejection below yields the same error deliberately: the core is
        // the single resolver-policy boundary, and a malformed answer must install
        // nothing no matter which invariant it breaks.
        let refused: Vec<(&str, ResolvedPeer)> = vec![
            (
                "this interface's own identity",
                resolved(own_pub, Some(outer(2)), None, &[net4(10, 0, 1, 0, 24)]),
            ),
            (
                "a pinned identity",
                resolved(pinned_pub, Some(outer(9)), None, &[net4(10, 0, 2, 0, 24)]),
            ),
            (
                "a peer relaying through itself",
                resolved(other_pub, None, Some(other_pub), &[net4(10, 0, 3, 0, 24)]),
            ),
            (
                "no address space at all",
                resolved(other_pub, Some(outer(2)), None, &[]),
            ),
            (
                "a default route",
                resolved(other_pub, Some(outer(2)), None, &[net4(0, 0, 0, 0, 0)]),
            ),
        ];
        for (why, answer) in refused {
            assert_eq!(
                a.core.upsert_peer(&answer, T0),
                Err(Error::InvalidResolverAnswer),
                "an answer naming {why} must be refused"
            );
        }
        a.core.assert_peer_index_consistent();

        // --- An authoritative miss suppresses lookups until Negative-TTL ------
        let unknown = Ipv4Addr::new(10, 9, 9, 9);
        let packet = ipv4(tun(1), unknown, IPPROTO_UDP, &udp(1, 1, b"nowhere"));
        a.send_inner(T0, &packet).await.expect("parked");
        let request = a.next_resolve_request().expect("lookup queued");
        a.resolve_completed(T0, request.complete(ResolveOutcome::NotFound))
            .await
            .expect("miss recorded");
        assert!(a.sink.outer.is_empty());

        a.send_inner(T0, &packet).await.expect("dropped silently");
        assert!(
            a.next_resolve_request().is_none(),
            "a cached miss must not be re-queried"
        );

        // `ResolveRequest` is `Copy`, so the same completion can be delivered
        // twice. The second one names an identifier the core no longer holds and
        // must be ignored rather than acted on.
        a.resolve_completed(T0, request.complete(ResolveOutcome::NotFound))
            .await
            .expect("stale completions are ignored");
        assert!(a.next_resolve_request().is_none());

        let after_ttl = T0 + NEGATIVE_TTL + Duration::from_millis(1);
        a.send_inner(after_ttl, &packet)
            .await
            .expect("parked again");
        let request = a
            .next_resolve_request()
            .expect("the suppression window lapsed");
        assert_eq!(
            request.query(),
            ResolveQuery::ByDstAddress(IpAddr::V4(unknown))
        );

        // --- A positive answer that does not cover the queried address --------
        // The server said "found" and this device declined the record. That is
        // a rejected positive, not an authoritative miss: only a well-formed
        // `not_found` carries the authority to negative-cache, so nothing is
        // suppressed here. Otherwise one malformed or hostile answer would
        // silence every lookup for this address for a whole Negative-TTL,
        // including the correct answer that might arrive right behind it.
        a.resolve_completed(
            after_ttl,
            request.complete(ResolveOutcome::Found(resolved(
                other_pub,
                Some(outer(2)),
                None,
                &[net4(10, 8, 0, 0, 24)],
            ))),
        )
        .await
        .expect("mismatch handled");
        assert_eq!(
            a.next_peer_evicted(),
            Some(other_pub),
            "a rejected resolver answer must release its local resolver interest"
        );

        // The parked packets are still dropped rather than re-dispatched:
        // replaying them here would allocate a fresh resolve from inside the
        // completion and let one packet drive an unbounded query loop.
        assert!(a.sink.outer.is_empty());

        // The retry comes from the next packet instead, exactly as it does
        // after a transient failure.
        a.send_inner(after_ttl, &packet)
            .await
            .expect("parked again");
        let retry = a
            .next_resolve_request()
            .expect("a rejected positive answer must not suppress the next lookup");
        assert_eq!(
            retry.query(),
            ResolveQuery::ByDstAddress(IpAddr::V4(unknown))
        );
        a.resolve_completed(after_ttl, retry.complete(ResolveOutcome::Failed))
            .await
            .expect("failure handled");

        // --- A transient failure leaves no cache entry ------------------------
        let flaky = Ipv4Addr::new(10, 9, 9, 10);
        let packet = ipv4(tun(1), flaky, IPPROTO_UDP, &udp(1, 1, b"transient"));
        a.send_inner(after_ttl, &packet).await.expect("parked");
        let request = a.next_resolve_request().expect("lookup queued");
        a.resolve_completed(after_ttl, request.complete(ResolveOutcome::Failed))
            .await
            .expect("failure handled");
        a.send_inner(after_ttl, &packet).await.expect("parked");
        assert!(
            a.next_resolve_request().is_some(),
            "a transient failure must be retried by the very next packet"
        );
    }

    // ---------------------------------------------------------------------------
    // 5. Dynamic peers: resolution by static key
    // ---------------------------------------------------------------------------

    #[maybe_async::test(not(feature = "async"), async(feature = "async", tokio::test))]
    async fn initiation_from_an_unknown_key_resolves_the_peer_and_then_succeeds() {
        let (_, b_pub) = keypair(12);
        let (_, c_pub) = keypair(13);
        let b_nets = [net4(10, 0, 0, 2, 32)];
        let c_nets = [net4(10, 0, 0, 3, 32)];

        // C knows B; B knows nobody.
        let b = node(12, outer(2), &[], StaticRelayPolicy::DenyAll, T0);
        let c = node(
            13,
            outer(3),
            &[pinned(
                b_pub,
                Some(outer(2)),
                None,
                &b_nets,
                InboundPolicy::AllowAll,
            )],
            StaticRelayPolicy::DenyAll,
            T0,
        );
        let mut net = Net { nodes: vec![b, c] };

        let payload = ipv4(tun(3), tun(2), IPPROTO_UDP, &udp(5, 5, b"who am i"));
        net.nodes[1].send_inner(T0, &payload).await.expect("parked");
        let (_, initiation) = net.nodes[1].sink.expect_one_outer();

        // The initiation is cryptographically valid but names an identity B has
        // never heard of. B proves possession, asks the resolver, and drops the
        // message: nothing is parked on the responder side (§5.1).
        net.nodes[0]
            .receive_outer(T0, outer(3), &initiation)
            .await
            .expect("initiation consumed");
        assert!(
            net.nodes[0].sink.outer.is_empty(),
            "an unknown initiator gets no response and no cookie"
        );
        let request = net.nodes[0]
            .next_resolve_request()
            .expect("by-key lookup queued");
        assert_eq!(request.query(), ResolveQuery::ByPublicKey(c_pub));

        net.nodes[0]
            .resolve_completed(
                T0,
                request.complete(ResolveOutcome::Found(resolved(
                    c_pub,
                    Some(outer(3)),
                    None,
                    &c_nets,
                ))),
            )
            .await
            .expect("peer installed");
        assert_eq!(
            stored_direct_endpoint(&net.nodes[0].core, &c_pub),
            Some(outer(3))
        );
        net.nodes[0].core.assert_peer_index_consistent();

        // The initiator's own §6.4 retransmission is what heals the exchange.
        let retry_at = T0 + REKEY_TIMEOUT + REKEY_TIMEOUT_JITTER_MAX;
        let steps = net.nodes[1].drain_timers(retry_at).await;
        assert_eq!(steps, 1, "only the handshake retransmission was due");
        assert_eq!(
            net.nodes[1].sink.outer_types(),
            vec![messages::MSG_INITIATION]
        );

        net.pump(retry_at).await;
        assert_eq!(net.nodes[0].sink.inner, vec![(c_pub, payload)]);

        // --- The budget for remotely provoked work is finite ------------------
        // A fresh responder, five initiations from five freshly minted identities
        // at one instant. Minting a Curve25519 pair costs an attacker nothing and
        // needs only our public key, so every such key is new to the suppression
        // check by construction; the unattributed budget is what bounds it. Both
        // the unknown-authentication and remote-resolve buckets burst at four, so
        // the fifth is dropped before any scalar multiplication is spent on it.
        let mut fresh = node(14, outer(2), &[], StaticRelayPolicy::DenyAll, T0);
        for seed in 20u8..25 {
            let forged =
                forged_initiation(seed, &fresh.public, 1_700_000_000 + u64::from(seed), T0);
            fresh
                .receive_outer(T0, outer(3), &forged)
                .await
                .expect("dropped or queued, never an error");
        }
        let mut queued = 0;
        while fresh.next_resolve_request().is_some() {
            queued += 1;
        }
        assert_eq!(
            queued, 4,
            "the remote-provoked lookup budget was not enforced"
        );
        assert!(fresh.sink.outer.is_empty());
    }

    // ---------------------------------------------------------------------------
    // 6. Cookies and load
    // ---------------------------------------------------------------------------

    #[maybe_async::test(not(feature = "async"), async(feature = "async", tokio::test))]
    async fn cookie_challenge_is_issued_under_load_and_satisfied_by_mac2() {
        let (_, a_pub) = keypair(15);
        let (_, b_pub) = keypair(16);
        let a_nets = [net4(10, 0, 0, 1, 32)];
        let b_nets = [net4(10, 0, 0, 2, 32)];

        let a = node(
            15,
            outer(1),
            &[pinned(
                b_pub,
                Some(outer(2)),
                None,
                &b_nets,
                InboundPolicy::AllowAll,
            )],
            StaticRelayPolicy::DenyAll,
            T0,
        );
        let b = node(
            16,
            outer(2),
            &[pinned(
                a_pub,
                Some(outer(1)),
                None,
                &a_nets,
                InboundPolicy::AllowAll,
            )],
            StaticRelayPolicy::DenyAll,
            T0,
        );
        let mut net = Net { nodes: vec![a, b] };

        let payload = ipv4(tun(1), tun(2), IPPROTO_UDP, &udp(1, 1, b"under load"));
        net.nodes[0].send_inner(T0, &payload).await.expect("parked");
        let (_, initiation) = net.nodes[0].sink.expect_one_outer();

        // B answers, but the response is lost in transit, so A stays in the
        // Initiating state and will retransmit.
        net.nodes[1]
            .receive_outer(T0, outer(1), &initiation)
            .await
            .expect("initiation accepted");
        assert_eq!(
            net.nodes[1].sink.outer_types(),
            vec![messages::MSG_RESPONSE]
        );
        net.nodes[1].sink.clear();

        // Push B past Under-Load-Handshakes-Per-Sec with replays of that same
        // initiation. They carry a valid mac1 — which is the bar for counting
        // toward the load estimate at all — but replayed timestamps, so none is
        // answered until the threshold engages the cookie machinery.
        let flood_at = T0 + REKEY_TIMEOUT + REKEY_TIMEOUT_JITTER_MAX;
        for _ in 0..9 {
            net.nodes[1]
                .receive_outer(flood_at, outer(1), &initiation)
                .await
                .expect("replays are dropped silently");
        }
        assert_eq!(
            net.nodes[1].sink.outer_types(),
            vec![messages::MSG_COOKIE_REPLY],
            "crossing the load threshold should produce exactly one challenge"
        );
        let (destination, cookie_reply) = net.nodes[1].sink.expect_one_outer();
        assert_eq!(destination, outer(1));
        assert_eq!(cookie_reply.len(), COOKIE_REPLY_LEN);

        // §5.4.7: the reply is bound to the mac1 of the message that provoked it,
        // which is what stops third parties feeding us fraudulent cookies.
        assert!(
            net.nodes[0].core.peers[0]
                .as_ref()
                .expect("pinned peer")
                .cookie
                .is_none()
        );
        net.nodes[0]
            .receive_outer(flood_at, outer(2), &cookie_reply)
            .await
            .expect("cookie reply consumed");
        assert!(
            net.nodes[0].core.peers[0]
                .as_ref()
                .expect("pinned peer")
                .cookie
                .is_some(),
            "the cookie was not stored"
        );
        assert!(
            net.nodes[0].sink.outer.is_empty(),
            "§5.3: a cookie reply provokes no immediate resend"
        );

        // The scheduled retransmission is what carries mac2.
        let steps = net.nodes[0].drain_timers(flood_at).await;
        assert_eq!(steps, 1);
        let (_, retransmission) = net.nodes[0].sink.expect_one_outer();
        assert_eq!(retransmission[0], messages::MSG_INITIATION);
        assert_ne!(
            &retransmission[messages::init::MAC2],
            &[0u8; 16][..],
            "the retransmission should carry a mac2"
        );

        // B is still under load, so mac2 is mandatory — and this time it verifies,
        // the per-source rate limiter admits the message, and the handshake
        // proceeds instead of bouncing another challenge.
        net.nodes[1]
            .receive_outer(flood_at, outer(1), &retransmission)
            .await
            .expect("challenged initiation accepted");
        assert_eq!(
            net.nodes[1].sink.outer_types(),
            vec![messages::MSG_RESPONSE],
            "a valid mac2 under load must yield a response, not another cookie"
        );

        net.pump(flood_at).await;
        assert_eq!(net.nodes[1].sink.inner, vec![(a_pub, payload)]);
    }

    // ---------------------------------------------------------------------------
    // 7. Relay forwarding
    // ---------------------------------------------------------------------------

    #[maybe_async::test(not(feature = "async"), async(feature = "async", tokio::test))]
    async fn relayed_peer_handshakes_and_carries_data_through_the_relay() {
        let (_, a_pub) = keypair(30);
        let (_, r_pub) = keypair(31);
        let (_, b_pub) = keypair(32);
        let a_nets = [net4(10, 0, 0, 1, 32)];
        let r_nets = [net4(10, 0, 0, 9, 32)];
        let b_nets = [net4(10, 0, 0, 2, 32)];

        // A and B are only reachable through R; R is directly reachable by both.
        let a = node(
            30,
            outer(1),
            &[
                pinned(
                    r_pub,
                    Some(outer(9)),
                    None,
                    &r_nets,
                    InboundPolicy::AllowAll,
                ),
                pinned(b_pub, None, Some(r_pub), &b_nets, InboundPolicy::AllowAll),
            ],
            StaticRelayPolicy::DenyAll,
            T0,
        );
        let r = node(
            31,
            outer(9),
            &[
                pinned(
                    a_pub,
                    Some(outer(1)),
                    None,
                    &a_nets,
                    InboundPolicy::AllowAll,
                ),
                pinned(
                    b_pub,
                    Some(outer(2)),
                    None,
                    &b_nets,
                    InboundPolicy::AllowAll,
                ),
            ],
            StaticRelayPolicy::AllowAll,
            T0,
        );
        let b = node(
            32,
            outer(2),
            &[
                pinned(
                    r_pub,
                    Some(outer(9)),
                    None,
                    &r_nets,
                    InboundPolicy::AllowAll,
                ),
                pinned(a_pub, None, Some(r_pub), &a_nets, InboundPolicy::AllowAll),
            ],
            StaticRelayPolicy::DenyAll,
            T0,
        );
        let mut net = Net {
            nodes: vec![a, r, b],
        };

        // Both hop-local sessions with the relay come first: an envelope can only
        // be submitted over an established session with the relay itself.
        net.connect(0, tun(1), tun(9), T0).await;
        net.connect(2, tun(2), tun(9), T0).await;
        for index in 0..3 {
            net.nodes[index].sink.clear();
        }

        // Now the end-to-end exchange. Every relayed leg is carried as an
        // authenticated Microtun relay packet on the A-R/B-R session.
        let payload = ipv4(
            tun(1),
            tun(2),
            IPPROTO_UDP,
            &udp(11, 22, b"through the relay"),
        );
        net.nodes[0]
            .send_inner(T0, &payload)
            .await
            .expect("a relayed destination is routable");
        let (destination, envelope) = net.nodes[0].sink.expect_one_outer();
        assert_eq!(
            destination,
            outer(9),
            "envelopes go to the relay, not the peer"
        );
        assert_eq!(envelope[0], messages::MSG_RELAY);

        // The type selector is authenticated. Reclassifying this ciphertext as
        // ordinary type 4 must fail authentication without consuming the
        // counter, so the untouched relay packet remains acceptable.
        let mut confused = envelope.clone();
        confused[0] = messages::MSG_DATA;
        net.nodes[1]
            .receive_outer(T0, outer(1), &confused)
            .await
            .expect("type confusion is dropped silently");
        assert!(net.nodes[1].sink.outer.is_empty());

        net.nodes[0].sink.outer.push_back((destination, envelope));
        net.pump(T0).await;
        assert_eq!(
            net.nodes[2].sink.inner,
            vec![(a_pub, payload.clone())],
            "the relayed packet did not reach the destination"
        );
        assert_eq!(
            net.nodes[2].sink.inner_endpoints,
            vec![None],
            "a relay's UDP socket must not be exposed as the end peer's endpoint"
        );
        assert!(
            net.nodes[1].sink.inner.is_empty(),
            "the relay must never see tunnelled plaintext"
        );

        // Relay spec §9: the configured relay relation is the routing authority,
        // so the relay's UDP source is never reported as an end-peer endpoint.
        // The hop-local relay endpoints were already confirmed before the sinks
        // were cleared, so there are no endpoint updates anywhere in this exchange.
        assert!(net.nodes.iter().all(|node| node.sink.events.is_empty()));

        // --- Forwarding is opt-in (§8) ----------------------------------------
        for index in 0..3 {
            net.nodes[index].sink.clear();
        }
        *net.nodes[1].core.relay_policy_mut() = StaticRelayPolicy::DenyAll;
        assert_eq!(
            net.nodes[1].core.relay_policy(),
            &StaticRelayPolicy::DenyAll
        );

        let blocked = ipv4(tun(1), tun(2), IPPROTO_UDP, &udp(11, 22, b"denied"));
        net.nodes[0].send_inner(T0, &blocked).await.expect("sent");
        let (_, envelope) = net.nodes[0].sink.expect_one_outer();
        net.nodes[1]
            .receive_outer(T0, outer(1), &envelope)
            .await
            .expect("dropped silently");
        assert!(
            net.nodes[1].sink.outer.is_empty(),
            "a denied envelope must not be forwarded"
        );
        assert!(net.nodes[2].sink.inner.is_empty());

        // Envelope syntax itself is pinned next to the implementation, in
        // `relay::tests`; this scenario covers only the forwarding behaviour that
        // needs three live engines.
    }

    // ---------------------------------------------------------------------------
    // 8. Stateful ingress filtering
    // ---------------------------------------------------------------------------

    #[maybe_async::test(not(feature = "async"), async(feature = "async", tokio::test))]
    async fn established_only_admits_return_traffic_and_related_icmp_errors() {
        let (_, a_pub) = keypair(40);
        let (_, b_pub) = keypair(41);
        let a_nets = [net4(10, 0, 0, 1, 32)];
        let b_nets = [net4(10, 0, 0, 2, 32)];

        let a = node(
            40,
            outer(1),
            &[pinned(
                b_pub,
                Some(outer(2)),
                None,
                &b_nets,
                InboundPolicy::AllowAll,
            )],
            StaticRelayPolicy::DenyAll,
            T0,
        );
        // B admits only return traffic from A.
        let b = node(
            41,
            outer(2),
            &[pinned(
                a_pub,
                Some(outer(1)),
                None,
                &a_nets,
                InboundPolicy::EstablishedOnly,
            )],
            StaticRelayPolicy::DenyAll,
            T0,
        );
        let mut net = Net { nodes: vec![a, b] };

        // The handshake still completes: the confirming data packet is admitted by
        // the session and then dropped by policy, which is exactly the point.
        net.connect(0, tun(1), tun(2), T0).await;
        assert!(
            net.nodes[1].sink.inner.is_empty(),
            "unsolicited traffic must not be delivered"
        );

        // An unsolicited inbound SYN is always a new connection attempt.
        let syn = ipv4(tun(1), tun(2), IPPROTO_TCP, &tcp(40000, 22, TCP_SYN));
        let unsolicited_syn = net.send_and_deliver(0, 1, &syn, T0).await;
        assert!(!unsolicited_syn);

        // An inbound ping is unsolicited in the same way.
        let ping = ipv4(tun(1), tun(2), IPPROTO_ICMP, &icmp_echo(8, 7));
        let unsolicited_ping = net.send_and_deliver(0, 1, &ping, T0).await;
        assert!(!unsolicited_ping);

        // Scan signatures no conforming stack emits are refused outright.
        let christmas = ipv4(tun(1), tun(2), IPPROTO_TCP, &tcp(40000, 22, 0x00));
        let null_flags = net.send_and_deliver(0, 1, &christmas, T0).await;
        assert!(!null_flags);

        // B opens a TCP flow of its own.
        let outbound = ipv4(tun(2), tun(1), IPPROTO_TCP, &tcp(40001, 80, TCP_SYN));
        net.nodes[1].sink.clear();
        net.nodes[1].send_inner(T0, &outbound).await.expect("sent");
        let _ = net.nodes[1].sink.expect_one_outer();

        // Return traffic for that flow is admitted.
        let syn_ack = ipv4(
            tun(1),
            tun(2),
            IPPROTO_TCP,
            &tcp(80, 40001, TCP_SYN | TCP_ACK),
        );
        let return_traffic = net.send_and_deliver(0, 1, &syn_ack, T0).await;
        assert!(return_traffic);

        // `related`: an ICMP error quoting the packet B sent keeps Path MTU
        // Discovery working instead of black-holing large transfers.
        let related = icmp_error(tun(1), tun(2), &outbound);
        let related_error = net.send_and_deliver(0, 1, &related, T0).await;
        assert!(related_error);

        // The same shape quoting a conversation B never had is refused, so a peer
        // cannot hand us an error about two other hosts.
        let stranger = ipv4(tun(2), tun(1), IPPROTO_TCP, &tcp(9999, 9999, TCP_SYN));
        let unrelated = icmp_error(tun(1), tun(2), &stranger);
        let unrelated_error = net.send_and_deliver(0, 1, &unrelated, T0).await;
        assert!(!unrelated_error);

        // --- Flows age out on their own, protocol-specific timeouts -----------
        // A UDP pinhole lives 60 s. Both instants below stay inside
        // Reject-After-Time and Rekey-After-Time so the session, and the number of
        // datagrams each send produces, are unchanged.
        let query = ipv4(tun(2), tun(1), IPPROTO_UDP, &udp(5353, 5353, b"q"));
        net.nodes[1].sink.clear();
        net.nodes[1].send_inner(T0, &query).await.expect("sent");
        let _ = net.nodes[1].sink.expect_one_outer();

        let answer = ipv4(tun(1), tun(2), IPPROTO_UDP, &udp(5353, 5353, b"a"));
        let inside = T0 + Duration::from_secs(30);
        let inside_window = net.send_and_deliver(0, 1, &answer, inside).await;
        assert!(inside_window);

        // That reply refreshed the entry to `inside + 60 s`; one second past it
        // the pinhole is closed again.
        let outside = inside + Duration::from_secs(61);
        let outside_window = net.send_and_deliver(0, 1, &answer, outside).await;
        assert!(!outside_window);
    }

    #[test]
    fn runtime_under_load_threshold_is_used() {
        let default = node(70, outer(70), &[], StaticRelayPolicy::DenyAll, T0);
        assert!(!default.core.under_load(T0));

        let configured = node_with_core_config(
            71,
            outer(71),
            &[],
            StaticRelayPolicy::DenyAll,
            T0,
            CoreConfig {
                under_load_free_slots: SESSIONS,
                ..CoreConfig::default()
            },
        );
        assert!(configured.core.under_load(T0));
    }

    // ---------------------------------------------------------------------------
    // 9. Construction
    // ---------------------------------------------------------------------------

    #[maybe_async::test(not(feature = "async"), async(feature = "async", tokio::test))]
    async fn construction_rejects_unsafe_configuration() {
        fn build(private: [u8; 32], peers: &[PinnedPeer<'_>]) -> Option<Error> {
            TestCore::new(
                Config::new(private, peers),
                rng(0x99),
                StaticRelayPolicy::DenyAll,
                T0,
            )
            .err()
        }

        let (_, peer_pub) = keypair(50);
        let (_, relay_pub) = keypair(51);
        let (private, own_pub) = keypair(52);
        let (_, chained_pub) = keypair(56);
        let nets = [net4(10, 0, 0, 2, 32)];
        let relay_nets = [net4(10, 0, 0, 9, 32)];
        let chained_nets = [net4(10, 0, 0, 10, 32)];
        let overlapping = [net4(10, 0, 0, 0, 24)];

        assert_eq!(build([0u8; 32], &[]), Some(Error::InvalidPrivateKey));

        // The baseline this test varies from.
        assert_eq!(
            build(
                private,
                &[pinned(
                    peer_pub,
                    Some(outer(2)),
                    None,
                    &nets,
                    InboundPolicy::AllowAll
                )]
            ),
            None
        );

        // Runtime limits may be lowered below their backing storage ceilings,
        // but cannot exceed those ceilings.
        for core_config in [
            CoreConfig {
                rate_limit_entries: MAX_CORE_RATE_LIMIT_ENTRIES + 1,
                ..CoreConfig::default()
            },
            CoreConfig {
                firewall_flow_entries: MAX_FIREWALL_FLOWS + 1,
                ..CoreConfig::default()
            },
            CoreConfig {
                firewall_flow_entries: 0,
                ..CoreConfig::default()
            },
            CoreConfig {
                firewall_flows_per_peer: 0,
                ..CoreConfig::default()
            },
            CoreConfig {
                firewall_flow_entries: 8,
                firewall_flows_per_peer: 9,
                ..CoreConfig::default()
            },
            CoreConfig {
                max_inflight_resolves: MAX_CORE_INFLIGHT_RESOLVES + 1,
                ..CoreConfig::default()
            },
            CoreConfig {
                peer_eviction_ghost_entries: MAX_CORE_PEER_EVICTION_GHOSTS + 1,
                ..CoreConfig::default()
            },
            CoreConfig {
                lazy_peer_reserve: PEERS + 1,
                ..CoreConfig::default()
            },
        ] {
            assert_eq!(
                TestCore::new(
                    Config::new(private, &[]).with_core_config(core_config),
                    rng(0x98),
                    StaticRelayPolicy::DenyAll,
                    T0,
                )
                .err(),
                Some(Error::InvalidCapacity),
            );
        }

        for core_config in [
            CoreConfig {
                resolve_timeout: Duration::from_millis(0),
                ..CoreConfig::default()
            },
            CoreConfig {
                resolve_outbound_timeout: Duration::from_millis(0),
                ..CoreConfig::default()
            },
            CoreConfig {
                peer_eviction_interval: Duration::from_millis(0),
                ..CoreConfig::default()
            },
            CoreConfig {
                peer_eviction_burst: 0,
                ..CoreConfig::default()
            },
        ] {
            assert_eq!(
                TestCore::new(
                    Config::new(private, &[]).with_core_config(core_config),
                    rng(0x97),
                    StaticRelayPolicy::DenyAll,
                    T0,
                )
                .err(),
                Some(Error::InvalidCoreConfig),
            );
        }

        // A pinned peer using this interface's own identity: accepting it would
        // let the device handshake with itself.
        assert_eq!(
            build(
                private,
                &[pinned(
                    own_pub,
                    Some(outer(2)),
                    None,
                    &nets,
                    InboundPolicy::AllowAll
                )]
            ),
            Some(Error::InvalidPinnedConfiguration)
        );

        // The same static key twice.
        assert_eq!(
            build(
                private,
                &[
                    pinned(
                        peer_pub,
                        Some(outer(2)),
                        None,
                        &nets,
                        InboundPolicy::AllowAll
                    ),
                    pinned(
                        peer_pub,
                        Some(outer(3)),
                        None,
                        &relay_nets,
                        InboundPolicy::AllowAll
                    ),
                ]
            ),
            Some(Error::InvalidPinnedConfiguration)
        );

        // A peer relaying through itself.
        assert_eq!(
            build(
                private,
                &[pinned(
                    peer_pub,
                    None,
                    Some(peer_pub),
                    &nets,
                    InboundPolicy::AllowAll
                )]
            ),
            Some(Error::InvalidPinnedConfiguration)
        );

        // A relay that is not itself a configured peer.
        assert_eq!(
            build(
                private,
                &[pinned(
                    peer_pub,
                    None,
                    Some(relay_pub),
                    &nets,
                    InboundPolicy::AllowAll
                )]
            ),
            Some(Error::InvalidPinnedConfiguration)
        );

        // A relay with no endpoint of its own is not directly reachable, so it
        // cannot carry anyone else's traffic.
        assert_eq!(
            build(
                private,
                &[
                    pinned(relay_pub, None, None, &relay_nets, InboundPolicy::AllowAll),
                    pinned(
                        peer_pub,
                        None,
                        Some(relay_pub),
                        &nets,
                        InboundPolicy::AllowAll
                    ),
                ]
            ),
            Some(Error::InvalidPinnedConfiguration)
        );

        // Relay chaining is not part of the relay protocol. The selected
        // relay must itself be directly reachable.
        assert_eq!(
            build(
                private,
                &[
                    pinned(
                        peer_pub,
                        None,
                        Some(relay_pub),
                        &nets,
                        InboundPolicy::AllowAll,
                    ),
                    pinned(
                        relay_pub,
                        None,
                        Some(chained_pub),
                        &relay_nets,
                        InboundPolicy::AllowAll,
                    ),
                    pinned(
                        chained_pub,
                        Some(outer(10)),
                        None,
                        &chained_nets,
                        InboundPolicy::AllowAll,
                    ),
                ],
            ),
            Some(Error::InvalidPinnedConfiguration)
        );

        // A pinned default route.
        assert_eq!(
            build(
                private,
                &[pinned(
                    peer_pub,
                    Some(outer(2)),
                    None,
                    &[net4(0, 0, 0, 0, 0)],
                    InboundPolicy::AllowAll
                )]
            ),
            Some(Error::InvalidPinnedConfiguration)
        );

        // Overlapping pinned address space is ambiguous and refused at init, even
        // though the resolver may later hand out overlapping *dynamic* prefixes.
        assert_eq!(
            build(
                private,
                &[
                    pinned(
                        peer_pub,
                        Some(outer(2)),
                        None,
                        &nets,
                        InboundPolicy::AllowAll
                    ),
                    pinned(
                        relay_pub,
                        Some(outer(9)),
                        None,
                        &overlapping,
                        InboundPolicy::AllowAll
                    ),
                ]
            ),
            Some(Error::InvalidPinnedConfiguration)
        );

        // More pinned peers than the table can hold.
        let (_, extra1) = keypair(53);
        let (_, extra2) = keypair(54);
        let (_, extra3) = keypair(55);
        let n1 = [net4(10, 1, 0, 0, 24)];
        let n2 = [net4(10, 2, 0, 0, 24)];
        let n3 = [net4(10, 3, 0, 0, 24)];
        let n4 = [net4(10, 4, 0, 0, 24)];
        let n5 = [net4(10, 5, 0, 0, 24)];
        assert_eq!(
            build(
                private,
                &[
                    pinned(peer_pub, Some(outer(2)), None, &n1, InboundPolicy::AllowAll),
                    pinned(
                        relay_pub,
                        Some(outer(3)),
                        None,
                        &n2,
                        InboundPolicy::AllowAll
                    ),
                    pinned(extra1, Some(outer(4)), None, &n3, InboundPolicy::AllowAll),
                    pinned(extra2, Some(outer(5)), None, &n4, InboundPolicy::AllowAll),
                    pinned(extra3, Some(outer(6)), None, &n5, InboundPolicy::AllowAll),
                ]
            ),
            Some(Error::PeerTableFull)
        );

        // Const-parameter validation. Without `alloc` the fixed-capacity index map
        // rejects an out-of-range capacity at monomorphisation, so an illegal
        // `MAX_PEERS` cannot even be *named* there; the runtime guard is only
        // observable on
        // the allocator-backed backend.
        #[cfg(feature = "alloc")]
        {
            type ZeroPeers =
                Core<ChaCha20Rng, StaticRelayPolicy, 0, SESSIONS, REPLAY_WORDS, ROUTES>;
            assert_eq!(
                ZeroPeers::new(
                    Config::new(private, &[]),
                    rng(0x99),
                    StaticRelayPolicy::DenyAll,
                    T0
                )
                .err(),
                Some(Error::InvalidCapacity)
            );
        }

        type ZeroReplayWords = Core<ChaCha20Rng, StaticRelayPolicy, PEERS, SESSIONS, 0, ROUTES>;
        assert_eq!(
            ZeroReplayWords::new(
                Config::new(private, &[]),
                rng(0x9a),
                StaticRelayPolicy::DenyAll,
                T0
            )
            .err(),
            Some(Error::InvalidCapacity)
        );

        // Route capacity is now the only route/trie sizing knob. A large route
        // cache must not fail because of an unrelated hidden trie-node limit.
        #[cfg(not(feature = "alloc"))]
        {
            type LargeRoutes =
                Core<ChaCha20Rng, StaticRelayPolicy, PEERS, SESSIONS, REPLAY_WORDS, 100>;
            assert!(
                LargeRoutes::new(
                    Config::new(private, &[]),
                    rng(0x99),
                    StaticRelayPolicy::DenyAll,
                    T0
                )
                .is_ok()
            );
        }
    }

    // ---------------------------------------------------------------------------
    // 10. Peer-table pressure
    // ---------------------------------------------------------------------------

    #[maybe_async::test(not(feature = "async"), async(feature = "async", tokio::test))]
    async fn peer_eviction_cascades_into_routes_and_keeps_the_key_index_consistent() {
        let (_, anchor_pub) = keypair(60);
        let (_, first_pub) = keypair(61);
        let (_, second_pub) = keypair(62);
        let (_, third_pub) = keypair(63);
        let (_, newcomer_pub) = keypair(64);
        let anchor_nets = [net4(10, 0, 0, 9, 32)];

        let mut a = node(
            65,
            outer(1),
            &[pinned(
                anchor_pub,
                Some(outer(9)),
                None,
                &anchor_nets,
                InboundPolicy::AllowAll,
            )],
            StaticRelayPolicy::DenyAll,
            T0,
        );

        // The first dynamic peer arrives through the real resolver path, so its
        // routes are actually installed. It is deliberately endpoint-less: without
        // an endpoint or a relay no handshake can start, which keeps it eligible
        // for eviction later (a peer with a handshake in flight never is).
        let first_net = net4(10, 1, 0, 0, 24);
        let target = Ipv4Addr::new(10, 1, 0, 5);
        let probe = ipv4(tun(1), target, IPPROTO_UDP, &udp(1, 1, b"probe"));
        a.send_inner(T0, &probe).await.expect("parked");
        let request = a.next_resolve_request().expect("lookup queued");
        a.resolve_completed(
            T0,
            request.complete(ResolveOutcome::Found(resolved(
                first_pub,
                None,
                None,
                &[first_net],
            ))),
        )
        .await
        .expect("peer installed");
        a.core.assert_peer_index_consistent();

        // The route is live: the packet now gets past resolution and fails only
        // for want of somewhere to send it.
        let routed = a.send_inner(T0, &probe).await;
        assert_eq!(
            routed,
            Err(Error::NoEndpoint),
            "the resolved prefix should be routable"
        );

        // Fill the remaining slots, each at a distinct instant so the
        // least-recently-active victim is unambiguous.
        for (offset, public) in [second_pub, third_pub].into_iter().enumerate() {
            let at = T0 + Duration::from_secs(offset as u64 + 1);
            a.core
                .upsert_peer(
                    &resolved(public, None, None, &[net4(10, 2, offset as u8, 0, 24)]),
                    at,
                )
                .expect("dynamic peer installed");
        }
        a.core.assert_peer_index_consistent();
        for public in [first_pub, second_pub, third_pub, anchor_pub] {
            assert!(a.core.find_peer(&public).is_some());
        }

        // One more: the table is full, so the least recently active *dynamic* peer
        // is evicted. A pinned peer is never a candidate.
        let evicted_at = T0 + DYNAMIC_PEER_MIN_IDLE + Duration::from_secs(1);
        a.core
            .upsert_peer(
                &resolved(newcomer_pub, None, None, &[net4(10, 3, 0, 0, 24)]),
                evicted_at,
            )
            .expect("newcomer installed");
        a.core.assert_peer_index_consistent();

        assert_eq!(
            a.core.find_peer(&first_pub),
            None,
            "the least recently active dynamic peer was not evicted"
        );
        for public in [second_pub, third_pub, newcomer_pub, anchor_pub] {
            assert!(a.core.find_peer(&public).is_some());
        }

        // The eviction cascades: the evicted peer's routes went with it, so the
        // same destination is unrouted again and provokes a fresh lookup.
        a.send_inner(evicted_at, &probe)
            .await
            .expect("unrouted packets are parked");
        assert_eq!(
            a.next_resolve_request()
                .expect("the route was removed with the peer")
                .query(),
            ResolveQuery::ByDstAddress(IpAddr::V4(target))
        );

        // Refreshing an installed peer updates it in place rather than consuming
        // another slot, and an unchanged address set is reported as a no-op so the
        // route cache is not needlessly rebuilt.
        let (_, routes_changed) = a
            .core
            .upsert_peer(
                &resolved(second_pub, Some(outer(7)), None, &[net4(10, 2, 0, 0, 24)]),
                evicted_at,
            )
            .expect("refresh accepted");
        assert!(!routes_changed);
        assert_eq!(stored_direct_endpoint(&a.core, &second_pub), Some(outer(7)));
        a.core.assert_peer_index_consistent();
    }

    #[maybe_async::test(not(feature = "async"), async(feature = "async", tokio::test))]
    async fn active_dynamic_sessions_are_not_capacity_victims() {
        let (_, a_pub) = keypair(80);
        let (_, b_pub) = keypair(81);
        let (_, c_pub) = keypair(82);
        let (_, d_pub) = keypair(83);
        let (_, e_pub) = keypair(84);
        let (_, newcomer_pub) = keypair(85);
        let a_nets = [net4(10, 0, 0, 1, 32)];
        let b_nets = [net4(10, 0, 0, 2, 32)];

        let a = node(80, outer(20), &[], StaticRelayPolicy::DenyAll, T0);
        let b = node(
            81,
            outer(21),
            &[pinned(
                a_pub,
                Some(outer(20)),
                None,
                &a_nets,
                InboundPolicy::AllowAll,
            )],
            StaticRelayPolicy::DenyAll,
            T0,
        );
        let mut net = Net { nodes: vec![a, b] };

        let probe = ipv4(tun(1), tun(2), IPPROTO_UDP, &udp(1, 1, b"connect"));
        net.nodes[0].send_inner(T0, &probe).await.expect("parked");
        let request = net.nodes[0].next_resolve_request().expect("lookup queued");
        net.nodes[0]
            .resolve_completed(
                T0,
                request.complete(ResolveOutcome::Found(resolved(
                    b_pub,
                    Some(outer(21)),
                    None,
                    &b_nets,
                ))),
            )
            .await
            .expect("dynamic peer installed");
        net.pump(T0).await;

        let bpidx = net.nodes[0].core.find_peer(&b_pub).expect("dynamic peer");
        assert!(
            net.nodes[0].core.peers[bpidx as usize]
                .as_ref()
                .is_some_and(|peer| peer.sessions.slots().into_iter().any(|slot| slot.is_some())),
            "the resolved peer should own an established session generation"
        );

        for (offset, public) in [c_pub, d_pub, e_pub].into_iter().enumerate() {
            net.nodes[0]
                .core
                .upsert_peer(
                    &resolved(public, None, None, &[net4(10, 21, offset as u8, 0, 24)]),
                    T0 + Duration::from_secs(offset as u64 + 1),
                )
                .expect("idle dynamic peer installed");
        }

        let evict_at = T0 + DYNAMIC_PEER_MIN_IDLE + Duration::from_secs(10);
        net.nodes[0]
            .core
            .upsert_peer(
                &resolved(newcomer_pub, None, None, &[net4(10, 22, 0, 0, 24)]),
                evict_at,
            )
            .expect("an idle peer can be displaced");

        assert!(
            net.nodes[0].core.find_peer(&b_pub).is_some(),
            "a peer with session state must never be selected as a capacity victim"
        );
        assert_eq!(
            net.nodes[0].core.find_peer(&c_pub),
            None,
            "the oldest idle sessionless peer should be selected instead"
        );
    }

    #[maybe_async::test(not(feature = "async"), async(feature = "async", tokio::test))]
    async fn route_refresh_failure_retains_active_peer_and_last_known_good_routes() {
        let (_, a_pub) = keypair(102);
        let (_, b_pub) = keypair(103);
        let c_pub = keypair(104).1;
        let d_pub = keypair(105).1;
        let e_pub = keypair(106).1;
        let a_nets = [net4(10, 0, 0, 1, 32)];
        let b_nets = [net4(10, 0, 0, 2, 32)];
        let c_routes = [net4(10, 61, 0, 0, 24), net4(10, 61, 1, 0, 24)];
        let d_routes = [net4(10, 62, 0, 0, 24), net4(10, 62, 1, 0, 24)];
        let e_routes = [
            net4(10, 63, 0, 0, 24),
            net4(10, 63, 1, 0, 24),
            net4(10, 63, 2, 0, 24),
        ];

        let a = node_with_core_config(
            102,
            outer(60),
            &[],
            StaticRelayPolicy::DenyAll,
            T0,
            CoreConfig {
                dynamic_peer_min_idle: Duration::from_millis(0),
                ..CoreConfig::default()
            },
        );
        let b = node(
            103,
            outer(61),
            &[pinned(
                a_pub,
                Some(outer(60)),
                None,
                &a_nets,
                InboundPolicy::AllowAll,
            )],
            StaticRelayPolicy::DenyAll,
            T0,
        );
        let mut net = Net { nodes: vec![a, b] };

        let probe = ipv4(tun(1), tun(2), IPPROTO_UDP, &udp(1, 1, b"connect"));
        net.nodes[0].send_inner(T0, &probe).await.expect("parked");
        let request = net.nodes[0].next_resolve_request().expect("lookup queued");
        net.nodes[0]
            .resolve_completed(
                T0,
                request.complete(ResolveOutcome::Found(resolved(
                    b_pub,
                    Some(outer(61)),
                    None,
                    &b_nets,
                ))),
            )
            .await
            .expect("dynamic peer installed");
        net.pump(T0).await;

        for (offset, (public, routes)) in [
            (c_pub, c_routes.as_slice()),
            (d_pub, d_routes.as_slice()),
            (e_pub, e_routes.as_slice()),
        ]
        .into_iter()
        .enumerate()
        {
            let at = T0 + Duration::from_secs(offset as u64 + 1);
            net.nodes[0].core.request_peer_install(public, at);
            let request = net.nodes[0]
                .next_resolve_request()
                .expect("idle peer lookup queued");
            net.nodes[0]
                .resolve_completed(
                    at,
                    request.complete(ResolveOutcome::Found(resolved(public, None, None, routes))),
                )
                .await
                .expect("idle peer installed");
        }
        assert_eq!(net.nodes[0].core.routes.available_slots(), 0);

        let refreshed_at = T0 + Duration::from_secs(5);
        let expanded = [
            b_nets[0],
            net4(10, 64, 0, 0, 24),
            net4(10, 64, 1, 0, 24),
            net4(10, 64, 2, 0, 24),
        ];
        net.nodes[0]
            .resolver_event_completed(
                refreshed_at,
                ResolverEvent::PeerUpdated(PeerUpdate::new(
                    b_pub,
                    ResolveOutcome::Found(resolved(b_pub, Some(outer(61)), None, &expanded)),
                )),
            )
            .await
            .expect("oversized refresh is retained as last-known-good");

        let bpidx = net.nodes[0]
            .core
            .find_peer(&b_pub)
            .expect("active peer retained");
        assert!(
            net.nodes[0].core.peers[bpidx as usize]
                .as_ref()
                .is_some_and(|peer| peer.sessions.slots().into_iter().any(|slot| slot.is_some()))
        );
        assert_eq!(
            net.nodes[0]
                .core
                .routes
                .lookup_readonly(&IpAddr::V4(tun(2))),
            Some(bpidx),
            "the old route remains installed"
        );
        assert!(
            net.nodes[0]
                .core
                .routes
                .lookup_readonly(&IpAddr::V4(Ipv4Addr::new(10, 64, 0, 1)))
                .is_none(),
            "the failed expanded route set was not partially committed"
        );
        for public in [c_pub, d_pub, e_pub] {
            assert!(net.nodes[0].core.find_peer(&public).is_some());
        }
    }

    #[test]
    fn eviction_cooldown_and_ghost_cache_break_peer_thrashing_cycles() {
        let publics = [keypair(86).1, keypair(87).1, keypair(88).1, keypair(89).1];
        let newcomer = keypair(90).1;
        let other = keypair(91).1;
        let mut a = node(92, outer(22), &[], StaticRelayPolicy::DenyAll, T0);

        for (offset, public) in publics.into_iter().enumerate() {
            a.core
                .upsert_peer(
                    &resolved(public, None, None, &[net4(10, 30, offset as u8, 0, 24)]),
                    T0 + Duration::from_secs(offset as u64),
                )
                .expect("table fill");
        }

        let first_evict = T0 + DYNAMIC_PEER_MIN_IDLE + Duration::from_secs(10);
        a.core
            .upsert_peer(
                &resolved(newcomer, None, None, &[net4(10, 31, 0, 0, 24)]),
                first_evict,
            )
            .expect("first budgeted eviction");
        assert_eq!(a.core.find_peer(&publics[0]), None);

        assert_eq!(
            a.core.upsert_peer(
                &resolved(publics[0], None, None, &[net4(10, 30, 0, 0, 24)]),
                first_evict,
            ),
            Err(Error::PeerAdmissionLimited),
            "the evicted identity cannot immediately force its way back"
        );
        a.core.request_peer_install(publics[0], first_evict);
        assert!(
            a.next_resolve_request().is_none(),
            "ghost suppression should happen before another resolver query"
        );
        assert_eq!(
            a.core.upsert_peer(
                &resolved(other, None, None, &[net4(10, 32, 0, 0, 24)]),
                first_evict,
            ),
            Err(Error::PeerAdmissionLimited),
            "a second identity cannot consume another destructive eviction immediately"
        );

        let one_interval_later = first_evict + PEER_EVICTION_INTERVAL;
        assert_eq!(
            a.core.upsert_peer(
                &resolved(publics[0], None, None, &[net4(10, 30, 0, 0, 24)]),
                one_interval_later,
            ),
            Err(Error::PeerAdmissionLimited),
            "refilling the eviction budget does not bypass the ghost TTL"
        );

        let after_ghost = first_evict + PEER_EVICTION_GHOST_TTL + Duration::from_millis(1);
        a.core
            .upsert_peer(
                &resolved(publics[0], None, None, &[net4(10, 30, 0, 0, 24)]),
                after_ghost,
            )
            .expect("the identity may return after the suppression window");
        assert!(a.core.find_peer(&publics[0]).is_some());
    }

    #[maybe_async::test(not(feature = "async"), async(feature = "async", tokio::test))]
    async fn route_capacity_preflight_never_partially_evicts_on_budget_failure() {
        let first_pub = keypair(97).1;
        let second_pub = keypair(98).1;
        let third_pub = keypair(99).1;
        let newcomer_pub = keypair(100).1;
        let first_routes = [net4(10, 50, 0, 0, 24), net4(10, 50, 1, 0, 24)];
        let second_routes = [
            net4(10, 51, 0, 0, 24),
            net4(10, 51, 1, 0, 24),
            net4(10, 51, 2, 0, 24),
        ];
        let third_routes = [
            net4(10, 52, 0, 0, 24),
            net4(10, 52, 1, 0, 24),
            net4(10, 52, 2, 0, 24),
        ];
        let newcomer_routes = [
            net4(10, 53, 0, 0, 24),
            net4(10, 53, 1, 0, 24),
            net4(10, 53, 2, 0, 24),
            net4(10, 53, 3, 0, 24),
        ];
        let mut a = node(101, outer(50), &[], StaticRelayPolicy::DenyAll, T0);

        for (offset, (public, routes)) in [
            (first_pub, first_routes.as_slice()),
            (second_pub, second_routes.as_slice()),
            (third_pub, third_routes.as_slice()),
        ]
        .into_iter()
        .enumerate()
        {
            let at = T0 + Duration::from_secs(offset as u64);
            a.core.request_peer_install(public, at);
            let request = a.next_resolve_request().expect("install lookup queued");
            a.resolve_completed(
                at,
                request.complete(ResolveOutcome::Found(resolved(public, None, None, routes))),
            )
            .await
            .expect("existing peer installed");
        }
        assert_eq!(a.core.routes.available_slots(), 0, "route cache is full");

        let at = T0 + DYNAMIC_PEER_MIN_IDLE + Duration::from_secs(10);
        a.core.request_peer_install(newcomer_pub, at);
        let request = a.next_resolve_request().expect("newcomer lookup queued");
        a.resolve_completed(
            at,
            request.complete(ResolveOutcome::Found(resolved(
                newcomer_pub,
                None,
                None,
                &newcomer_routes,
            ))),
        )
        .await
        .expect("budget failure is an admission drop, not a core error");

        assert_eq!(a.core.find_peer(&newcomer_pub), None);
        for public in [first_pub, second_pub, third_pub] {
            assert!(
                a.core.find_peer(&public).is_some(),
                "route admission must not partially evict its preflighted victims"
            );
        }
        assert_eq!(a.core.routes.available_slots(), 0);
    }

    #[maybe_async::test(not(feature = "async"), async(feature = "async", tokio::test))]
    async fn combined_peer_and_route_admission_is_preflighted_before_eviction() {
        let existing = [
            keypair(107).1,
            keypair(108).1,
            keypair(109).1,
            keypair(110).1,
        ];
        let oversized = keypair(111).1;
        let fitting = keypair(112).1;
        let mut a = node(113, outer(70), &[], StaticRelayPolicy::DenyAll, T0);

        for (offset, public) in existing.into_iter().enumerate() {
            let routes = [
                net4(10, 70 + offset as u8, 0, 0, 24),
                net4(10, 70 + offset as u8, 1, 0, 24),
            ];
            let at = T0 + Duration::from_secs(offset as u64);
            a.core.request_peer_install(public, at);
            let request = a.next_resolve_request().expect("table-fill lookup queued");
            a.resolve_completed(
                at,
                request.complete(ResolveOutcome::Found(resolved(public, None, None, &routes))),
            )
            .await
            .expect("table-fill peer installed");
        }
        assert_eq!(a.core.routes.available_slots(), 0);

        let at = T0 + DYNAMIC_PEER_MIN_IDLE + Duration::from_secs(10);
        let oversized_routes = [
            net4(10, 80, 0, 0, 24),
            net4(10, 80, 1, 0, 24),
            net4(10, 80, 2, 0, 24),
            net4(10, 80, 3, 0, 24),
        ];
        a.core.request_peer_install(oversized, at);
        let request = a.next_resolve_request().expect("oversized lookup queued");
        a.resolve_completed(
            at,
            request.complete(ResolveOutcome::Found(resolved(
                oversized,
                None,
                None,
                &oversized_routes,
            ))),
        )
        .await
        .expect("unsafe admission is dropped without surfacing a core error");
        assert_eq!(a.core.find_peer(&oversized), None);
        for public in existing {
            assert!(a.core.find_peer(&public).is_some());
        }

        let fitting_routes = [net4(10, 81, 0, 0, 24), net4(10, 81, 1, 0, 24)];
        a.core.request_peer_install(fitting, at);
        let request = a.next_resolve_request().expect("fitting lookup queued");
        a.resolve_completed(
            at,
            request.complete(ResolveOutcome::Found(resolved(
                fitting,
                None,
                None,
                &fitting_routes,
            ))),
        )
        .await
        .expect("fitting admission uses the still-available eviction budget");
        assert!(a.core.find_peer(&fitting).is_some());
        assert_eq!(
            a.core.find_peer(&existing[0]),
            None,
            "the oldest eligible peer is evicted only by the fitting admission"
        );
        for public in &existing[1..] {
            assert!(a.core.find_peer(public).is_some());
        }
    }

    #[test]
    fn outbound_lazy_installs_preserve_capacity_for_authenticated_initiators() {
        let publics = [
            keypair(114).1,
            keypair(115).1,
            keypair(116).1,
            keypair(117).1,
            keypair(118).1,
        ];
        let mut a = node_with_core_config(
            119,
            outer(80),
            &[],
            StaticRelayPolicy::DenyAll,
            T0,
            CoreConfig {
                lazy_peer_reserve: 1,
                ..CoreConfig::default()
            },
        );

        for (offset, public) in publics[..3].iter().copied().enumerate() {
            a.core
                .upsert_outbound_lazy_peer(
                    &resolved(public, None, None, &[net4(10, 90 + offset as u8, 0, 0, 24)]),
                    T0,
                )
                .expect("an unreserved lazy-cache slot is available");
        }

        assert_eq!(
            a.core.upsert_outbound_lazy_peer(
                &resolved(publics[3], None, None, &[net4(10, 93, 0, 0, 24)]),
                T0,
            ),
            Err(Error::PeerAdmissionLimited),
            "a lazy lookup must not consume the final protected slot"
        );
        assert_eq!(a.core.peers.iter().filter(|peer| peer.is_none()).count(), 1);

        let swap_at = T0 + DYNAMIC_PEER_MIN_IDLE + Duration::from_millis(1);
        a.core
            .upsert_outbound_lazy_peer(
                &resolved(publics[3], None, None, &[net4(10, 93, 0, 0, 24)]),
                swap_at,
            )
            .expect("an idle lazy-cache entry may be swapped without using the reserve");
        assert_eq!(a.core.find_peer(&publics[0]), None);
        assert!(a.core.find_peer(&publics[3]).is_some());
        assert_eq!(
            a.core.peers.iter().filter(|peer| peer.is_none()).count(),
            1,
            "a cache swap must preserve the protected free slot"
        );

        a.core
            .upsert_peer(
                &resolved(publics[4], None, None, &[net4(10, 94, 0, 0, 24)]),
                swap_at,
            )
            .expect("a key-authenticated initiator may consume the reserve");
        assert!(a.core.find_peer(&publics[4]).is_some());
        assert!(a.core.peers.iter().all(|peer| peer.is_some()));
    }

    #[maybe_async::test(not(feature = "async"), async(feature = "async", tokio::test))]
    async fn relay_lazy_installs_are_per_submitter_throttled_and_respect_the_reserve() {
        let submitter_pub = keypair(93).1;
        let first_pub = keypair(94).1;
        let second_pub = keypair(95).1;
        let submitter_nets = [net4(10, 40, 0, 1, 32)];
        let mut a = node_with_core_config(
            96,
            outer(40),
            &[pinned(
                submitter_pub,
                Some(outer(41)),
                None,
                &submitter_nets,
                InboundPolicy::AllowAll,
            )],
            StaticRelayPolicy::AllowAll,
            T0,
            CoreConfig {
                lazy_peer_reserve: 2,
                relay_resolve_min_interval: Duration::from_secs(5),
                ..CoreConfig::default()
            },
        );
        let submitter = a.core.find_peer(&submitter_pub).expect("pinned submitter");

        a.core.request_relay_peer_install(submitter, first_pub, T0);
        let request = a
            .next_resolve_request()
            .expect("first relay lookup admitted");
        a.core.request_relay_peer_install(submitter, second_pub, T0);
        assert!(
            a.next_resolve_request().is_none(),
            "one submitter cannot fan out resolver work inside its interval"
        );

        a.resolve_completed(
            T0,
            request.complete(ResolveOutcome::Found(resolved(
                first_pub,
                None,
                None,
                &[net4(10, 41, 0, 0, 24)],
            ))),
        )
        .await
        .expect("first relay destination installed");
        assert!(a.core.find_peer(&first_pub).is_some());

        let later = T0 + Duration::from_secs(5);
        a.core
            .request_relay_peer_install(submitter, second_pub, later);
        assert!(
            a.next_resolve_request().is_none(),
            "relay installs cannot consume the protected peer-table reserve"
        );

        a.core.request_peer_install(second_pub, later);
        let direct = a
            .next_resolve_request()
            .expect("the reserved slot remains available to a direct initiator");
        a.resolve_completed(
            later,
            direct.complete(ResolveOutcome::Found(resolved(
                second_pub,
                None,
                None,
                &[net4(10, 42, 0, 0, 24)],
            ))),
        )
        .await
        .expect("direct install uses the reserve");
        assert!(a.core.find_peer(&second_pub).is_some());
    }

    // ---------------------------------------------------------------------------
    // 11. Malformed input
    // ---------------------------------------------------------------------------

    #[maybe_async::test(not(feature = "async"), async(feature = "async", tokio::test))]
    async fn malformed_input_is_reported_locally_and_dropped_in_silence_remotely() {
        let (_, b_pub) = keypair(70);
        let b_nets = [net4(10, 0, 0, 2, 32)];
        let mut a = node(
            71,
            outer(1),
            &[pinned(
                b_pub,
                Some(outer(2)),
                None,
                &b_nets,
                InboundPolicy::AllowAll,
            )],
            StaticRelayPolicy::DenyAll,
            T0,
        );

        // --- Local input: the embedding gets a real error ---------------------
        let truncated = a.send_inner(T0, &[0x45, 0x00]).await;
        assert_eq!(truncated, Err(Error::MalformedIpPacket));
        let unknown_version = a.send_inner(T0, &[0xf0; 40]).await;
        assert_eq!(
            unknown_version,
            Err(Error::MalformedIpPacket),
            "an unknown IP version has no parseable destination"
        );

        // An IPv4 total_length below the header length — the case a bare
        // `min(packet.len())` clamp would silently turn into a truncated delivery.
        let mut liar = ipv4(tun(1), tun(2), IPPROTO_UDP, &udp(1, 1, b"x"));
        liar[2..4].copy_from_slice(&8u16.to_be_bytes());
        let sent = a.send_inner(T0, &liar).await;
        assert_eq!(sent, Err(Error::MalformedIpPacket));

        // An IHL claiming more header than is present.
        let mut wide = ipv4(tun(1), tun(2), IPPROTO_UDP, &udp(1, 1, b"x"));
        wide[0] = 0x4f;
        let sent = a.send_inner(T0, &wide).await;
        assert_eq!(sent, Err(Error::MalformedIpPacket));

        let oversized = ipv4(
            tun(1),
            tun(2),
            IPPROTO_UDP,
            &vec![0u8; crate::MAX_INNER_SIZE],
        );
        let sent = a.send_inner(T0, &oversized).await;
        assert_eq!(sent, Err(Error::PacketTooLarge));

        // --- Remote input: §5.1, silence is a virtue --------------------------
        let oversized_datagram = a
            .receive_outer(T0, outer(2), &vec![0u8; crate::MAX_UDP_SIZE + 1])
            .await;
        assert_eq!(
            oversized_datagram,
            Err(Error::PacketTooLarge),
            "the size ceiling is the one datagram-path condition worth reporting"
        );

        let dropped: Vec<(&str, Vec<u8>)> = vec![
            ("empty", vec![]),
            (
                "shorter than the common prefix",
                vec![messages::MSG_INITIATION, 0, 0],
            ),
            ("initiation one byte short", {
                let mut v = vec![0u8; INITIATION_LEN - 1];
                v[0] = messages::MSG_INITIATION;
                v
            }),
            ("response one byte long", {
                let mut v = vec![0u8; RESPONSE_LEN + 1];
                v[0] = messages::MSG_RESPONSE;
                v
            }),
            ("transport below the minimum", {
                let mut v = vec![0u8; messages::DATA_MIN_LEN - 1];
                v[0] = messages::MSG_DATA;
                v
            }),
            ("unknown message type", vec![0x7f, 0, 0, 0, 0, 0, 0, 0]),
            ("non-zero reserved bytes", {
                let mut v = vec![0u8; INITIATION_LEN];
                v[0] = messages::MSG_INITIATION;
                v[1] = 1;
                v
            }),
            ("well-formed shape with an invalid mac1", {
                let mut v = vec![0xabu8; INITIATION_LEN];
                v[0] = messages::MSG_INITIATION;
                v[1..4].fill(0);
                v
            }),
            ("transport naming an unowned receiver index", {
                let mut v = vec![0u8; messages::DATA_MIN_LEN + 16];
                v[0] = messages::MSG_DATA;
                v
            }),
        ];
        for (why, datagram) in dropped {
            a.receive_outer(T0, outer(2), &datagram)
                .await
                .unwrap_or_else(|error| panic!("{why} should drop silently, got {error:?}"));
            assert!(
                a.sink.outer.is_empty() && a.sink.inner.is_empty(),
                "{why} produced output"
            );
        }

        // IPv4-mapped IPv6 sources are normalised before anything else looks at
        // them, so the cookie layer, the rate limiter and roaming all agree on one
        // canonical form.
        let mapped = SocketAddr::new(
            IpAddr::V6(Ipv4Addr::new(203, 0, 113, 2).to_ipv6_mapped()),
            51820,
        );
        assert_eq!(crate::ip::unmap_socket_addr(mapped), outer(2));
        assert_eq!(crate::ip::unmap_socket_addr(outer(2)), outer(2));
    }
}
