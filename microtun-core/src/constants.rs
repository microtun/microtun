//! Protocol constants (§6.1 of the whitepaper) and microtun tunables.

use crate::time::Duration;

// ---------------------------------------------------------------------------
// Whitepaper §6.1 timer constants
// ---------------------------------------------------------------------------

/// After this many transport messages the sender starts a new handshake.
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
/// Hard limit on transport messages per session: `2^64 - 2^13 - 1`.
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13);
/// The initiator of a session rekeys once the session is this old (send path).
pub const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
/// Sessions are never used past this age.
pub const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
/// Give up re-initiating a handshake after this long.
pub const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
/// Handshake initiation retransmission interval; also the minimum interval
/// between any two initiations to the same peer.
pub const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
/// Minimum interval between accepted initiation messages from one authenticated peer.
pub const HANDSHAKE_INITIATION_MIN_INTERVAL: Duration = Duration::from_millis(20);
/// Maximum random delay added to each handshake retransmission deadline.
/// WireGuard specifies a random jitter in `0..=333 ms` to keep
/// peers recovering from a shared outage from retransmitting in lockstep.
pub const REKEY_TIMEOUT_JITTER_MAX: Duration = Duration::from_millis(333);
/// Passive keepalive interval (§6.5).
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// Cookies (and the responder's cookie secret `R`) are valid for two minutes
/// (§5.3, §5.4.4).
pub const COOKIE_REFRESH_TIME: Duration = Duration::from_secs(120);

// ---------------------------------------------------------------------------
// microtun tunables (not from the whitepaper)
// ---------------------------------------------------------------------------

/// How long an emitted `by-key` resolver query may remain unanswered before
/// it is treated as failed and its table entry reclaimed. Chosen as
/// 2 × `REKEY_TIMEOUT`: nothing is parked behind these queries — the
/// provoking initiation or envelope was dropped — so a lapsed one simply
/// means the sender's next retransmission starts a fresh lookup.
pub const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a queued outbound packet may wait on a `by-address` resolve.
pub const RESOLVE_OUTBOUND_TIMEOUT: Duration = Duration::from_secs(10);

/// TTL used for negative cache entries (unknown public_key / unknown dst IP).
pub const NEGATIVE_TTL: Duration = Duration::from_secs(60);

/// Minimum activity-idle time before a dynamic peer with no session
/// state may be selected as a capacity victim. This prevents a newly loaded
/// peer from being displaced immediately by a resolver-driven scan.
pub const DYNAMIC_PEER_MIN_IDLE: Duration = Duration::from_secs(30);

/// Refill interval and burst for destructive capacity evictions. The default
/// permits one peer eviction every ten seconds, globally across peer-table and
/// route-cache pressure.
pub const PEER_EVICTION_INTERVAL: Duration = Duration::from_secs(10);
pub const PEER_EVICTION_BURST: u32 = 1;

/// Recently capacity-evicted identities are denied re-admission for this long,
/// breaking A/B/A/B cache-thrashing loops.
pub const PEER_EVICTION_GHOST_TTL: Duration = Duration::from_secs(60);
pub const MAX_PEER_EVICTION_GHOSTS: usize = 16;
pub const DEFAULT_PEER_EVICTION_GHOSTS: usize = 8;

/// Minimum interval between resolver lookups caused by one authenticated relay
/// submitter naming unknown destinations. The global remote-resolve budget still
/// applies in addition to this per-submitter gate.
pub const RELAY_RESOLVE_MIN_INTERVAL: Duration = Duration::from_secs(5);

/// Peer-table slots unavailable to unauthenticated lazy-cache installs,
/// including local by-address resolution and relay destinations. They remain
/// available to initiators that prove possession of their WireGuard static key.
pub const LAZY_PEER_RESERVE: usize = 1;

/// Legacy default for [`crate::CoreConfig::endpoint_confirmation_ttl`].
///
/// The field is retained for configuration/API compatibility, but accepted
/// resolver records now replace the endpoint unconditionally as required by
/// the Peers API's complete-record semantics.
pub const ENDPOINT_CONFIRMATION_TTL: Duration = REJECT_AFTER_TIME;

/// Stateful ingress-firewall flow lifetimes.
pub const FIREWALL_UDP_TIMEOUT: Duration = Duration::from_secs(60);
pub const FIREWALL_ICMP_TIMEOUT: Duration = Duration::from_secs(30);
pub const FIREWALL_TCP_TIMEOUT: Duration = Duration::from_secs(30 * 60);
pub const FIREWALL_TCP_CLOSING_TIMEOUT: Duration = Duration::from_secs(30);

/// Handshake messages per second above which the responder considers itself
/// under load and engages the cookie machinery.
pub const UNDER_LOAD_HANDSHAKES_PER_SEC: u32 = 8;
/// The responder also considers itself under load when this few session
/// slots remain free.
pub const UNDER_LOAD_FREE_SLOTS: usize = 1;

/// Post-cookie-attribution rate limit (per source): sustained rate and burst,
/// in handshake messages. These match the wireguard-go reference
/// implementation. Resource-constrained backends may select tighter values
/// through [`crate::CoreConfig`].
pub const RATE_LIMIT_PER_SEC: u32 = 20;
pub const RATE_LIMIT_BURST: u32 = 5;

/// Sustained rate and burst, in queries, for peer resolutions that *remote*
/// input can provoke.
///
/// Two paths qualify: an initiation from an unrecognized static key, and a
/// relay envelope naming an unknown destination key. Neither is a proof of
/// authorization. A handshake initiation only has to decrypt under *our*
/// private key and carry *some* static key the sender holds — minting a fresh
/// Curve25519 keypair costs an attacker nothing and produces a key that is by
/// construction absent from both the in-flight dedup check and the negative
/// cache, so every attempt would otherwise become a fresh Peers API server query.
/// Across a fleet that aims a great many devices at one Peers API server.
///
/// The cookie machinery does bound this, but only once
/// [`UNDER_LOAD_HANDSHAKES_PER_SEC`] is exceeded; below that threshold
/// nothing constrains an attacker who merely knows our public key, and the
/// source address it arrives from can be forged. This budget closes that gap
/// and is deliberately unattributed — a per-source limit would be useless
/// against exactly the spoofing it needs to stop.
///
/// One query per second sustained, four back to back: enough for a device
/// meeting several genuinely new peers at once (a fleet restart, a roam into
/// a new segment), and a throttled lookup is not a lost one — the initiator
/// retransmits every [`REKEY_TIMEOUT`], and a relay submitter's own retries
/// carry its envelope again, so the query happens a few seconds later.
pub const REMOTE_RESOLVE_PER_SEC: u32 = 1;
pub const REMOTE_RESOLVE_BURST: u32 = 4;

/// Budget for completing the expensive static-static DH and timestamp AEAD
/// for an initiation whose recovered static identity is not installed yet.
/// This is intentionally separate from the resolver-query budget.
pub const UNKNOWN_AUTH_PER_SEC: u32 = 2;
pub const UNKNOWN_AUTH_BURST: u32 = 4;

/// Compile-time ceiling for tracked handshake sources.
///
/// A "source" is a full IPv4 address or an IPv6 /64 prefix, matching the
/// reference implementation's keying (see [`crate::rate`]). A full table
/// denies rather than recycling, so the host backend needs substantially more
/// headroom than the embedded backend. `alloc` builds keep the buckets on the
/// heap and may admit up to 4096 active sources; allocation-free builds retain
/// the original 64-entry ceiling.
/// This symbol exists in every feature configuration. `cfg!` is evaluated at
/// compile time, so allocation-free builds get a 64-entry heapless table while
/// `alloc` builds retain the larger host ceiling.
pub const MAX_RATE_LIMIT_ENTRIES: usize = if cfg!(feature = "alloc") { 4096 } else { 64 };

/// Backend-appropriate active source-table default.
///
/// The host default is deliberately below its storage ceiling so deployments
/// can raise it further without recompiling. The embedded default consumes the
/// complete fixed table.
pub const DEFAULT_RATE_LIMIT_ENTRIES: usize = if cfg!(feature = "alloc") {
    1024
} else {
    MAX_RATE_LIMIT_ENTRIES
};

/// Maximum number of entries in the core's resolver-tracking table (the
/// embedding will usually apply a lower bound via channel depth).
///
/// This table holds two kinds of entry that share the budget: live queries
/// (awaiting an answer) and spent *negative markers* that suppress repeat
/// lookups for authoritatively-unknown targets until `NEGATIVE_TTL` elapses.
/// A live query is never denied a slot while a marker occupies one —
/// `Core::push_resolve` evicts the soonest-to-expire marker first — so this
/// is sized to seat the handful of concurrent live queries (install,
/// outbound, and relay installs) with headroom left for a working set of
/// markers.
pub const MAX_INFLIGHT_RESOLVES: usize = 12;
