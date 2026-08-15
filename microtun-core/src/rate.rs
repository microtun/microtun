//! Per-source token-bucket rate limiter (§5.3).
//!
//! Applied to handshake messages only, only under load, and only **after**
//! `mac2` proved the sender owns its claimed source address — the cookie
//! mechanism exists precisely so this table can be keyed by address without
//! being poisonable by spoofed traffic.
//!
//! Keying follows the reference implementation: an IPv4 source is keyed on
//! its full address, an IPv6 source on its /64 prefix only. A single host is
//! routinely allocated an entire /64, so keying v6 on the full address hands
//! one attacker 2^64 distinct buckets and makes the limiter decorative.
//!
//! Two further behaviours are inherited from the reference limiter, and both
//! matter more than the table size:
//!
//! * A full table **denies** rather than evicting. Recycling the stalest
//!   bucket would grant every newly seen source a fresh full burst, so an
//!   attacker cycling addresses would never be limited no matter how large
//!   the table was.
//! * Before a new source is admitted, buckets that have refilled to capacity
//!   are reclaimed. A full bucket is indistinguishable from one that does not
//!   exist, so dropping it forgets nothing and keeps slots available for
//!   genuinely active sources. This stands in for the periodic garbage
//!   collection the reference implementation runs on a timer; doing it at
//!   admission time keeps the engine free of another deadline.

use core::net::IpAddr;

use defmt_or_log::warn;

#[cfg(not(feature = "alloc"))]
use crate::constants::MAX_RATE_LIMIT_ENTRIES;
use crate::{ip::unmap_ip, time::Instant};

/// What one handshake message costs, in millitokens (thousandths of one
/// message). Millitokens keep the refill arithmetic integral at millisecond
/// resolution.
const COST_MT: u32 = 1000;

/// What the limiter treats as "one source".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Key {
    /// A complete IPv4 address.
    V4([u8; 4]),
    /// The upper 64 bits of an IPv6 address. The interface identifier is
    /// discarded because the host, not its network, chooses it.
    V6Prefix([u8; 8]),
}

impl Key {
    fn from_ip(ip: IpAddr) -> Self {
        match unmap_ip(ip) {
            IpAddr::V4(v4) => Self::V4(v4.octets()),
            IpAddr::V6(v6) => {
                let mut prefix = [0u8; 8];
                prefix.copy_from_slice(&v6.octets()[..8]);
                Self::V6Prefix(prefix)
            }
        }
    }
}

/// One source's bucket. The refill arithmetic is [`TokenBucket`]'s; this type
/// only attaches the source it belongs to.
///
/// Only the allocation-free backend needs this pairing: the `alloc` backend
/// keys a map on [`Key`] directly.
#[cfg(not(feature = "alloc"))]
#[derive(Debug, Clone, Copy)]
struct Bucket {
    key: Key,
    tokens: TokenBucket,
}

/// Bounded token bucket table.
///
/// `MAX_RATE_LIMIT_ENTRIES` is the backend-specific storage ceiling. That
/// bound is load-bearing rather than a storage detail: a full table *denies*
/// instead of evicting, which is what stops a source-cycling attacker from
/// resetting its own limit. `alloc` moves the buckets to the heap and uses a
/// larger host ceiling; allocation-free builds retain the embedded ceiling.
///
/// The two backends differ in lookup structure, and the reason is the same
/// reason the ceilings differ. This table is consulted once per handshake
/// message *while under load* — that is, during exactly the flood it exists
/// to bound — so its per-message cost is on the attack path. A linear scan is
/// the right shape at 64 entries and the wrong shape at 4,096, where it hands
/// an attacker a multiplier on every packet they send. `alloc` builds
/// therefore use a hash map, matching the reference implementation.
#[derive(Debug)]
pub struct RateLimiter {
    per_sec: u32,
    burst: u32,
    max_entries: usize,
    #[cfg(not(feature = "alloc"))]
    buckets: heapless::Vec<Bucket, MAX_RATE_LIMIT_ENTRIES>,
    #[cfg(feature = "alloc")]
    buckets: hashbrown::HashMap<Key, TokenBucket>,
}

impl RateLimiter {
    #[cfg(not(feature = "alloc"))]
    pub const fn new(per_sec: u32, burst: u32, max_entries: usize) -> Self {
        Self {
            per_sec,
            burst,
            max_entries,
            buckets: heapless::Vec::new(),
        }
    }

    #[cfg(feature = "alloc")]
    pub fn new(per_sec: u32, burst: u32, max_entries: usize) -> Self {
        Self {
            per_sec,
            burst,
            max_entries,
            buckets: hashbrown::HashMap::new(),
        }
    }

    /// Charge one handshake message to `ip`. Returns `true` if allowed.
    pub fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        let key = Key::from_ip(ip);

        if let Some(tokens) = self.lookup_mut(&key) {
            return tokens.try_take(now);
        }

        // An unseen source needs a slot. Reclaiming refilled buckets is only
        // worth doing when there is no room, so the common admission stays
        // O(1) on the `alloc` backend instead of paying a full sweep per new
        // source — which under a source-cycling flood is the whole table,
        // per packet.
        if self.len() >= self.max_entries {
            self.collect(now);
            if self.len() >= self.max_entries {
                warn!("handshake denied: rate limiter table full");
                return false;
            }
        }

        // A partially drained bucket is never evicted to make room, which is
        // precisely what stops a source-cycling attacker from resetting its
        // own limit.
        let mut tokens = TokenBucket::new(self.per_sec, self.burst, now);
        let allowed = tokens.try_take(now);
        if !self.admit(key, tokens) {
            warn!("handshake denied: rate limiter table full");
            return false;
        }
        allowed
    }

    #[cfg(not(feature = "alloc"))]
    fn lookup_mut(&mut self, key: &Key) -> Option<&mut TokenBucket> {
        self.buckets
            .iter_mut()
            .find(|bucket| bucket.key == *key)
            .map(|bucket| &mut bucket.tokens)
    }

    #[cfg(feature = "alloc")]
    fn lookup_mut(&mut self, key: &Key) -> Option<&mut TokenBucket> {
        self.buckets.get_mut(key)
    }

    fn len(&self) -> usize {
        self.buckets.len()
    }

    #[cfg(not(feature = "alloc"))]
    fn admit(&mut self, key: Key, tokens: TokenBucket) -> bool {
        self.buckets.push(Bucket { key, tokens }).is_ok()
    }

    #[cfg(feature = "alloc")]
    fn admit(&mut self, key: Key, tokens: TokenBucket) -> bool {
        self.buckets.insert(key, tokens);
        true
    }

    /// Drop every bucket that has refilled to capacity: it constrains
    /// nothing, and its slot is worth more than its history.
    #[cfg(not(feature = "alloc"))]
    fn collect(&mut self, now: Instant) {
        self.buckets.retain(|bucket| !bucket.tokens.is_full(now));
    }

    #[cfg(feature = "alloc")]
    fn collect(&mut self, now: Instant) {
        self.buckets.retain(|_, tokens| !tokens.is_full(now));
    }
}

/// A single token bucket with a caller-chosen rate and burst.
///
/// [`RateLimiter`] answers "is *this source* asking too often", which needs
/// the cookie mechanism first so the source cannot be forged. This type
/// answers the different question "is *this device* being asked to do too
/// much in total", which needs no attribution at all — and is therefore the
/// right shape for limiting work that unauthenticated or merely
/// key-possessing remote parties can provoke. It is used for peer-resolution
/// queries; see [`crate::Core`].
///
/// Accounting is in millitokens for the same reason as above: it keeps the
/// refill arithmetic integral at millisecond clock resolution.
#[derive(Debug, Clone, Copy)]
pub struct TokenBucket {
    millitokens: u32,
    capacity_mt: u32,
    per_sec: u32,
    last: Instant,
}

impl TokenBucket {
    /// A bucket that refills at `per_sec` operations per second and starts
    /// full at `burst` operations.
    pub const fn new(per_sec: u32, burst: u32, now: Instant) -> Self {
        let capacity_mt = burst.saturating_mul(1000);
        Self {
            millitokens: capacity_mt,
            capacity_mt,
            per_sec,
            last: now,
        }
    }

    /// Tokens this bucket would hold at `now`, capped at capacity.
    fn tokens_at(&self, now: Instant) -> u32 {
        let elapsed_ms = now.saturating_since(self.last).as_millis();
        let gained = elapsed_ms.saturating_mul(self.per_sec as u64);
        u64::from(self.millitokens)
            .saturating_add(gained)
            .min(u64::from(self.capacity_mt)) as u32
    }

    /// Has this bucket refilled all the way back to capacity? Such a bucket
    /// constrains nothing, so [`RateLimiter`] reclaims its table slot.
    fn is_full(&self, now: Instant) -> bool {
        self.tokens_at(now) >= self.capacity_mt
    }

    /// Refill to `now`, then charge one operation if the budget allows it.
    /// Returns `true` when the caller may proceed.
    pub fn try_take(&mut self, now: Instant) -> bool {
        self.millitokens = self.tokens_at(now);
        self.last = now;
        if self.millitokens >= COST_MT {
            self.millitokens -= COST_MT;
            true
        } else {
            false
        }
    }
}

/// A global operation budget that refills one token per fixed interval.
///
/// Unlike [`TokenBucket`], this supports sub-Hz policies such as one destructive
/// eviction every ten seconds while retaining bounded burst behavior.
#[derive(Debug, Clone, Copy)]
pub(crate) struct IntervalBudget {
    available: u32,
    burst: u32,
    interval_ms: u64,
    last_refill: Instant,
}

impl IntervalBudget {
    pub(crate) const fn new(interval: crate::time::Duration, burst: u32, now: Instant) -> Self {
        Self {
            available: burst,
            burst,
            interval_ms: interval.as_millis(),
            last_refill: now,
        }
    }

    pub(crate) fn try_take(&mut self, now: Instant) -> bool {
        self.try_take_many(1, now)
    }

    /// Atomically charge `count` destructive operations.
    ///
    /// The all-or-nothing behavior lets route admission preflight every peer
    /// eviction it would need before mutating the peer or route tables.
    pub(crate) fn try_take_many(&mut self, count: u32, now: Instant) -> bool {
        if count == 0 {
            return true;
        }
        if self.interval_ms == 0 || self.burst == 0 || count > self.burst {
            return false;
        }
        let elapsed = now.saturating_since(self.last_refill).as_millis();
        let refills = elapsed / self.interval_ms;
        if refills != 0 {
            let gained = u32::try_from(refills).unwrap_or(u32::MAX);
            self.available = self.available.saturating_add(gained).min(self.burst);
            self.last_refill = Instant::from_millis(
                self.last_refill
                    .as_millis()
                    .saturating_add(refills.saturating_mul(self.interval_ms)),
            );
        }
        if self.available < count {
            false
        } else {
            self.available -= count;
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use core::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::time::Duration;

    /// A fixed instant well away from zero, so a saturated-to-zero deadline
    /// can never be mistaken for a correct one.
    const T0: Instant = Instant::from_millis(1_000_000);

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn v6(segments: [u16; 8]) -> IpAddr {
        let [a, b, c, d, e, f, g, h] = segments;
        IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h))
    }

    fn at(ms: u64) -> Instant {
        T0 + Duration::from_millis(ms)
    }

    #[test]
    fn a_source_gets_a_burst_and_then_refills_at_the_configured_rate() {
        let mut limiter = RateLimiter::new(
            crate::constants::DEFAULT_RATE_LIMIT_PER_SEC,
            crate::constants::DEFAULT_RATE_LIMIT_BURST,
            crate::constants::MAX_RATE_LIMIT_ENTRIES,
        );
        let source = v4(198, 51, 100, 1);

        // A fresh bucket starts full, so a peer recovering from an outage is
        // not punished for its first handshakes.
        for attempt in 0..crate::constants::DEFAULT_RATE_LIMIT_BURST {
            assert!(limiter.allow(source, T0), "burst attempt {attempt}");
        }
        assert!(!limiter.allow(source, T0), "the burst must be finite");

        // Refill is linear in elapsed time: one message costs a full token.
        let one_token_ms = 1000 / u64::from(crate::constants::DEFAULT_RATE_LIMIT_PER_SEC);
        assert!(!limiter.allow(source, at(one_token_ms - 1)));
        assert!(limiter.allow(source, at(one_token_ms)));
        assert!(!limiter.allow(source, at(one_token_ms)));

        // Waiting far longer than the burst period does not bank extra credit.
        let much_later = at(60_000);
        for _ in 0..crate::constants::DEFAULT_RATE_LIMIT_BURST {
            assert!(limiter.allow(source, much_later));
        }
        assert!(!limiter.allow(source, much_later));
    }

    #[test]
    fn sources_are_keyed_the_way_addresses_are_actually_allocated() {
        let mut limiter = RateLimiter::new(
            crate::constants::DEFAULT_RATE_LIMIT_PER_SEC,
            crate::constants::DEFAULT_RATE_LIMIT_BURST,
            crate::constants::MAX_RATE_LIMIT_ENTRIES,
        );

        // Distinct IPv4 addresses are distinct sources.
        assert!(limiter.allow(v4(198, 51, 100, 1), T0));
        assert!(limiter.allow(v4(198, 51, 100, 2), T0));

        // A single host is routinely handed an entire IPv6 /64, so keying on
        // the full address would give one attacker 2^64 buckets and make the
        // limiter decorative. Everything inside a /64 shares one bucket.
        let same_prefix_a = v6([0x2001, 0xdb8, 0, 1, 0, 0, 0, 1]);
        let same_prefix_b = v6([0x2001, 0xdb8, 0, 1, 0xffff, 0xffff, 0xffff, 0xffff]);
        let other_prefix = v6([0x2001, 0xdb8, 0, 2, 0, 0, 0, 1]);

        for _ in 0..crate::constants::DEFAULT_RATE_LIMIT_BURST {
            assert!(limiter.allow(same_prefix_a, T0));
        }
        assert!(
            !limiter.allow(same_prefix_b, T0),
            "a different interface identifier is the same source"
        );
        assert!(limiter.allow(other_prefix, T0), "a different /64 is not");

        // An IPv4-mapped source is the IPv4 source, not a second identity.
        let native = v4(203, 0, 113, 9);
        let mapped = core::net::IpAddr::V6(Ipv4Addr::new(203, 0, 113, 9).to_ipv6_mapped());
        for _ in 0..crate::constants::DEFAULT_RATE_LIMIT_BURST {
            assert!(limiter.allow(native, T0));
        }
        assert!(
            !limiter.allow(mapped, T0),
            "a mapped address must share the bucket"
        );
    }

    #[test]
    fn a_full_table_denies_rather_than_recycling_a_partly_drained_bucket() {
        // Recycling the stalest bucket would grant every newly seen source a
        // fresh full burst, so an attacker cycling addresses would never be
        // limited no matter how large the table was.
        let mut limiter = RateLimiter::new(
            crate::constants::DEFAULT_RATE_LIMIT_PER_SEC,
            crate::constants::DEFAULT_RATE_LIMIT_BURST,
            crate::constants::MAX_RATE_LIMIT_ENTRIES,
        );
        for index in 0..crate::constants::MAX_RATE_LIMIT_ENTRIES {
            let source = core::net::IpAddr::V6(Ipv6Addr::new(
                0x2001,
                0xdb8,
                (index >> 16) as u16,
                index as u16,
                0,
                0,
                0,
                1,
            ));
            assert!(
                limiter.allow(source, T0),
                "source {index} should be admitted"
            );
        }
        assert!(
            !limiter.allow(v4(198, 51, 100, 254), T0),
            "the table is full and every bucket is still constraining someone"
        );

        // A bucket that has refilled to capacity constrains nothing, so it is
        // indistinguishable from one that does not exist and its slot is
        // reclaimed at admission time — no separate garbage-collection timer.
        let recovered = at(60_000);
        assert!(limiter.allow(v4(198, 51, 100, 254), recovered));
    }

    #[test]
    fn interval_budget_enforces_sub_hz_eviction_cadence_and_burst() {
        let mut budget = IntervalBudget::new(Duration::from_secs(10), 2, T0);
        assert!(budget.try_take(T0));
        assert!(budget.try_take(T0));
        assert!(!budget.try_take(T0));
        assert!(!budget.try_take(at(9_999)));
        assert!(budget.try_take(at(10_000)));
        assert!(!budget.try_take(at(10_000)));
        assert!(budget.try_take_many(2, at(30_000)));
        assert!(!budget.try_take(at(30_000)));
        assert!(!budget.try_take_many(3, at(40_000)));

        let mut atomic = IntervalBudget::new(Duration::from_secs(10), 2, T0);
        assert!(atomic.try_take(T0));
        assert!(!atomic.try_take_many(2, T0));
        assert!(
            atomic.try_take(T0),
            "a failed multi-charge must consume nothing"
        );
    }

    #[test]
    fn the_runtime_entry_limit_can_be_lower_than_the_storage_ceiling() {
        let mut limiter = RateLimiter::new(1, 1, 2);

        assert!(limiter.allow(v4(198, 51, 100, 1), T0));
        assert!(limiter.allow(v4(198, 51, 100, 2), T0));
        assert!(
            !limiter.allow(v4(198, 51, 100, 3), T0),
            "the configured two-entry limit must bind before the backing table is full"
        );

        // Once both one-token buckets refill, admission-time collection may
        // reclaim them and a different source can take a configured slot.
        assert!(limiter.allow(v4(198, 51, 100, 3), at(1_000)));
    }
}
