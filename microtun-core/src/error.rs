//! Error type shared across the crate.

/// Errors surfaced by the protocol engine and its helpers.
///
/// Note that in keeping with §5.1 ("Silence is a Virtue") most *protocol*
/// failures on the datagram path are not errors at all — invalid packets are
/// silently dropped and the corresponding `Core` call returns `Ok(())`.
/// `Error` is for
/// conditions the embedding may want to act on (misconfiguration, resource
/// exhaustion, malformed local input, or a failed local cryptographic
/// invariant).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Error {
    /// A buffer supplied by or produced for the caller was too small.
    BufferTooSmall,
    /// A const-generic capacity combination is invalid, or a runtime active
    /// limit exceeds its fixed backing-storage ceiling.
    InvalidCapacity,
    /// Runtime operational settings contain a value that cannot make forward
    /// progress, such as a zero resolver timeout.
    InvalidCoreConfig,
    /// A wall-clock or timestamp conversion exceeded its representable range.
    TimeOverflow,
    /// Internal tables or state machines were found to be inconsistent.
    ///
    /// This is recoverable at the API boundary, but generally indicates a bug
    /// or memory corruption and should be logged and investigated.
    InternalInvariant,
    /// The supplied packet is not a well-formed IPv4/IPv6 packet.
    MalformedIpPacket,
    /// An inner packet exceeds `MAX_INNER_SIZE`, or an outer datagram
    /// exceeds `MAX_UDP_SIZE`.
    PacketTooLarge,
    /// The peer table is full and nothing was evictable.
    PeerTableFull,
    /// A peer admission was suppressed by the eviction cooldown, idle
    /// protection, lazy-cache reserve, or recently-evicted ghost cache.
    PeerAdmissionLimited,
    /// The static private key is all zeroes.
    InvalidPrivateKey,
    /// The pinned peer set is internally inconsistent or unsafe to route.
    InvalidPinnedConfiguration,
    /// A no-alloc peer was configured with more than `MAX_PEER_ADDRESSES` unique prefixes.
    TooManyAddresses,
    /// The session pool is full and nothing was evictable.
    SessionPoolFull,
    /// The RNG failed to produce a unique random receiver index within the
    /// bounded retry limit. Treat this as a broken or compromised RNG rather
    /// than falling back to a predictable index.
    SessionIndexGenerationFailed,
    /// The route cache could not fit the requested complete route set.
    RouteCacheFull,
    /// Too many resolver queries in flight.
    ResolverBusy,
    /// Cryptographic failure (AEAD tag mismatch, bad public key encoding).
    Crypto,
    /// Wall-clock time has not been provided via `set_unix_time` yet, so
    /// handshake timestamps cannot be generated.
    NoWallClock,
    /// The peer has no known endpoint, so nothing can be transmitted to it.
    NoEndpoint,
    /// The peer is configured to be reached via a relay, but the relay is
    /// not currently usable (unknown relay peer, no relay endpoint, or no
    /// established relay session yet — a handshake with the relay has been
    /// started where possible).
    RelayUnavailable,
    /// A resolver answer violated an invariant the core enforces on every
    /// dynamically learned peer: it named a pinned identity or this
    /// interface's own, relayed through itself, carried no address space, or
    /// carried a default route.
    ///
    /// Overlapping address space is *not* one of these: the resolver is the
    /// routing authority and may reassign any prefix, pinned or dynamic.
    InvalidResolverAnswer,
}
