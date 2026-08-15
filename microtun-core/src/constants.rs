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

/// Maximum amount *subtracted* from [`REKEY_AFTER_TIME`] when a session is
/// established, to desynchronise a fleet's rekey traffic.
///
/// [`REKEY_TIMEOUT_JITTER_MAX`] spreads *retransmissions*, which is not the
/// same problem. A fleet that bootstraps together — a hub restart, a power
/// event, a link flap — creates every one of its sessions inside the same
/// second, and an unjittered `REKEY_AFTER_TIME` then makes every one of them
/// rekey inside the same second, forever, every two minutes. That spike is
/// what [`DEFAULT_UNDER_LOAD_HANDSHAKES_PER_SEC`] sees, and it is what forces the
/// session pool to hold `current`, `previous` and `handshake` for every peer
/// at once instead of for a few peers at a time.
///
/// The offset is subtracted rather than added so that a jittered session
/// still leaves the full [`REKEY_ATTEMPT_TIME`] budget before
/// [`REJECT_AFTER_TIME`]; adding to it would eat into the margin the
/// whitepaper's timer relationships depend on.
///
/// This mirrors the pacing doctrine `microtun-api`'s `jitter` module already
/// applies to Peers API reconnects and change-driven refreshes: correlated
/// populations must be spread deliberately, because nothing else will spread
/// them.
pub const REKEY_AFTER_TIME_JITTER_MAX: Duration = Duration::from_secs(10);
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
/// 2 × `REKEY_TIMEOUT`: an authenticated unknown initiator may retain one
/// bounded Noise generation behind the lookup, with a retransmission refreshing
/// it to the newest generation; relay envelopes remain unparked. When the
/// deadline lapses, any parked initiation is dropped and the sender's next
/// retransmission starts a fresh lookup.
pub const DEFAULT_RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a queued outbound packet may wait on a `by-address` resolve.
pub const DEFAULT_RESOLVE_OUTBOUND_TIMEOUT: Duration = Duration::from_secs(10);

/// TTL used for negative cache entries (unknown public_key / unknown dst IP).
pub const DEFAULT_NEGATIVE_TTL: Duration = Duration::from_secs(60);

/// Minimum activity-idle time before a dynamic peer with no session
/// state may be selected as a capacity victim. This prevents a newly loaded
/// peer from being displaced immediately by a resolver-driven scan.
pub const DEFAULT_DYNAMIC_PEER_MIN_IDLE: Duration = Duration::from_secs(30);

/// Refill interval and burst for destructive capacity evictions, globally
/// across peer-table and route-cache pressure.
///
/// This is a churn brake, and the right cadence depends on how many peers
/// there are to churn *through* — which is a const generic on the engine, not
/// anything visible here. The default is therefore the conservative one: ten
/// seconds per eviction is a sensible anti-thrash floor for a small table,
/// and against a large one it is far too slow (a 128-entry table would take
/// over twenty minutes to cycle, so a deployment with real churn would never
/// converge). Embeddings driving a large peer table are expected to inject a
/// faster cadence; see the shells' policy profiles.
pub const DEFAULT_PEER_EVICTION_INTERVAL: Duration = Duration::from_secs(10);
pub const DEFAULT_PEER_EVICTION_BURST: u32 = 1;

/// Recently capacity-evicted identities are denied re-admission for this long,
/// breaking A/B/A/B cache-thrashing loops.
pub const DEFAULT_PEER_EVICTION_GHOST_TTL: Duration = Duration::from_secs(60);

/// Compile-time ceiling for retained evicted identities.
///
/// Storage follows the same rule as every other bounded table here: heap
/// under `alloc`, inline otherwise. Keeping this inline at the larger ceiling
/// would put kilobytes back into the `Core` value that `alloc` exists to keep
/// out of it.
pub const MAX_PEER_EVICTION_GHOSTS: usize = if cfg!(feature = "alloc") { 256 } else { 16 };

/// Default retained evicted identities.
///
/// Conservative rather than scaled: the ghost list only breaks thrash cycles
/// for the identities it remembers, so the useful size depends on the peer
/// table and the eviction cadence, neither of which is knowable from here.
pub const DEFAULT_PEER_EVICTION_GHOSTS: usize = 8;

/// Minimum interval between resolver lookups caused by one authenticated relay
/// submitter naming unknown destinations. The global remote-resolve budget still
/// applies in addition to this per-submitter gate.
pub const DEFAULT_RELAY_RESOLVE_MIN_INTERVAL: Duration = Duration::from_secs(5);

/// Peer-table slots unavailable to unauthenticated lazy-cache installs,
/// including local by-address resolution and relay destinations. They remain
/// available to initiators that prove possession of their WireGuard static key.
pub const DEFAULT_LAZY_PEER_RESERVE: usize = 1;

/// Stateful ingress-firewall flow lifetimes.
pub const DEFAULT_FIREWALL_UDP_TIMEOUT: Duration = Duration::from_secs(60);
pub const DEFAULT_FIREWALL_ICMP_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEFAULT_FIREWALL_TCP_TIMEOUT: Duration = Duration::from_secs(30 * 60);
pub const DEFAULT_FIREWALL_TCP_CLOSING_TIMEOUT: Duration = Duration::from_secs(30);

/// Handshake messages per second above which the responder considers itself
/// under load and engages the cookie machinery.
///
/// Cookies cost the responder almost nothing and the initiator one extra
/// round trip, so the threshold wants to sit above the busiest *legitimate*
/// moment a deployment has — which is a property of how many peers there are,
/// and so is not knowable from here. The default is the conservative one,
/// suited to a small peer table. An embedding fronting a large fleet should
/// inject a higher threshold, or the whole fleet arriving at once after a
/// restart will make the two-round-trip handshake its normal case rather than
/// the exception it is meant to be.
pub const DEFAULT_UNDER_LOAD_HANDSHAKES_PER_SEC: u32 = 8;

/// The responder also considers itself under load when this few session
/// slots remain free.
///
/// This is an absolute count, so it is only meaningful against a session
/// pool with real headroom. Sizing `MAX_SESSIONS` at or near `MAX_PEERS`
/// leaves the pool permanently at or below this mark, which pins the engine
/// into permanent under-load and engages cookies on every handshake forever;
/// see [`crate::Core`] for the ratio the pool actually needs.
pub const DEFAULT_UNDER_LOAD_FREE_SLOTS: usize = 1;

/// Post-cookie-attribution rate limit (per source): sustained rate and burst,
/// in handshake messages. These match the wireguard-go reference
/// implementation. Resource-constrained backends may select tighter values
/// through [`crate::CoreConfig`].
pub const DEFAULT_RATE_LIMIT_PER_SEC: u32 = 20;
pub const DEFAULT_RATE_LIMIT_BURST: u32 = 5;

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
/// [`DEFAULT_UNDER_LOAD_HANDSHAKES_PER_SEC`] is exceeded; below that threshold
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
pub const DEFAULT_REMOTE_RESOLVE_PER_SEC: u32 = 1;
pub const DEFAULT_REMOTE_RESOLVE_BURST: u32 = 4;

/// Budget for completing the expensive static-static DH and timestamp AEAD
/// for an initiation whose recovered static identity is not installed yet.
/// This is intentionally separate from the resolver-query budget.
pub const DEFAULT_UNKNOWN_AUTH_PER_SEC: u32 = 2;
pub const DEFAULT_UNKNOWN_AUTH_BURST: u32 = 4;

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
/// `alloc` builds retain the larger heap-backed ceiling.
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
/// lookups for authoritatively-unknown targets until `DEFAULT_NEGATIVE_TTL` elapses.
/// A live query is never denied a slot while a marker occupies one —
/// `Core::push_resolve` evicts the soonest-to-expire marker first — so this
/// is sized to seat the handful of concurrent live queries (install,
/// outbound, and relay installs) with headroom left for a working set of
/// markers.
///
/// This is the storage ceiling, not the policy: [`crate::Core::new`] rejects
/// a [`crate::CoreConfig`] asking for more, so it bounds what any embedding
/// can inject. The inline backend keeps it small because the table lives in
/// the `Core` value; `alloc` keeps entries on the heap and can afford a
/// working set large enough for a deployment meeting many distinct unknown
/// targets inside one [`DEFAULT_NEGATIVE_TTL`].
pub const MAX_INFLIGHT_RESOLVES: usize = if cfg!(feature = "alloc") { 256 } else { 12 };

/// Default active resolver-table size.
///
/// Conservative rather than scaled: the useful size is a function of how many
/// distinct unknown targets are seen inside one [`DEFAULT_NEGATIVE_TTL`], which
/// depends on the peer table and the deployment, neither of which is knowable
/// from here. Embeddings fronting a fleet should inject a larger value —
/// under-sizing it does not merely evict markers early, it silently turns the
/// negative cache off, because every marker is reclaimed before its TTL
/// expires and every repeat lookup for an authoritatively-unknown target
/// becomes a fresh Peers API query. That is the load [`DEFAULT_REMOTE_RESOLVE_PER_SEC`]
/// exists to prevent, arriving by a different route.
pub const DEFAULT_INFLIGHT_RESOLVES: usize = 12;

/// Maximum number of authenticated unknown-peer initiations retained while
/// their `by-key` resolver lookups are in flight.
///
/// Overflow is intentionally lossy: the resolver lookup still proceeds, and
/// normal WireGuard retransmission remains the fallback, so exceeding this
/// costs an extra [`REKEY_TIMEOUT`] rather than a failure. Sized against the
/// storage backend, since the array is inline in the `Core` value without
/// `alloc`.
pub const MAX_PENDING_INITIATIONS: usize = if cfg!(feature = "alloc") { 32 } else { 4 };

/// Parked outbound packets awaiting a resolve or a handshake, globally.
///
/// The pool is deliberately lossy — IP is lossy and the transport above
/// retransmits — but its stated job is to keep *one* packet alive per new
/// flow so a TCP SYN or a DNS query survives the handshake round trip, so
/// the pool size is the number of simultaneously-cold flows that get that
/// benefit. Every flow past it eats a full initial RTO instead.
///
/// Sized against the storage backend rather than the deployment: without
/// `alloc` each slot costs a fixed [`crate::MAX_INNER_SIZE`] buffer inline in
/// the `Core` value, whereas under `alloc` a parked packet owns a heap buffer
/// sized to the packet and an idle pool costs nothing.
pub const MAX_PENDING_PACKETS: usize = if cfg!(feature = "alloc") { 64 } else { 2 };
