//! Pacing jitter for reconnect and reconciliation bursts.
//!
//! Registry churn is a *synchronised* event: one reload invalidates a key for
//! every interested client at the same instant, and one Peers API server restart
//! drops every client's connection at the same instant. Without jitter each
//! population answers in lockstep, so the server sees the whole fleet's
//! refresh traffic inside one round-trip window rather than spread across the
//! recovery interval. The Peers API therefore requires clients to spread both
//! reconnect attempts and change-driven refresh bursts (see `docs/microtun-peers-api.md`
//! §10.3).
//!
//! This is pacing, not cryptography, so the generator is [`rand`]'s
//! [`SmallRng`] — fast, `no_std`, and 16 bytes of state on the 32-bit targets
//! the Embassy client runs on. Nothing here depends on its output being
//! reproducible across `rand` releases; it is seeded explicitly only so that
//! two nodes differ and so that client tests are deterministic within a build.
//!
//! # Seeding
//!
//! The seed must differ between nodes, and that is the one part this module
//! cannot supply. Identical firmware images booting together observe the same
//! uptime, so a clock-derived seed can leave a fleet just as correlated as no
//! seed at all. [`Jitter::from_key`] derives one from a node's static public
//! key, which is unique by construction and available before the first
//! connection attempt.

use rand::{Rng, RngCore, SeedableRng, rngs::SmallRng};

/// Width of the window a change-driven reconciliation burst is spread over.
///
/// A client that has queued refreshes because of peer invalidations waits a
/// uniformly random part of this window before issuing the first one. One
/// reload therefore arrives at the server spread over a second rather than as
/// a single spike. Reconnect replay is *not* delayed by this window: it is
/// already paced by the jittered reconnect delay that preceded it.
pub const REFRESH_BURST_WINDOW_MS: u32 = 1_000;

/// Numerator of the upper bound [`Jitter::spread_ms`] varies to.
pub const SPREAD_NUMERATOR: u32 = 3;
/// Denominator of [`SPREAD_NUMERATOR`]. The delay is uniform over
/// `[base/2, base*3/2)`, so a fleet sharing one base delay spreads across a
/// full base-delay-wide window.
pub const SPREAD_DENOMINATOR: u32 = 2;

/// Pacing source for reconnect delays and reconciliation bursts.
#[derive(Debug, Clone)]
pub struct Jitter {
    rng: SmallRng,
}

impl Jitter {
    /// Seed the generator from a 64-bit value.
    ///
    /// Any distinct value works: [`SeedableRng::seed_from_u64`] expands it
    /// through a PCG-based mixer, so neighbouring seeds do not produce
    /// correlated streams and the caller owes no mixing of its own.
    pub fn new(seed: u64) -> Self {
        Self {
            rng: SmallRng::seed_from_u64(seed),
        }
    }

    /// Seed from a node's static public key.
    ///
    /// This is the recommended seed: it is unique per node, stable across
    /// restarts, and known before the first connection attempt, so two devices
    /// flashed from one image and powered on together still reconnect at
    /// different moments.
    pub fn from_key(public_key: &[u8; 32]) -> Self {
        Self::new(Self::seed_from_key(public_key))
    }

    /// The seed [`Jitter::from_key`] would use.
    ///
    /// Exposed separately so a caller can carry a plain `u64` in its own
    /// configuration rather than a generator.
    ///
    /// Each 64-bit word of the key is mixed in turn rather than combined
    /// arithmetically. XOR-folding looks like the obvious reduction and is
    /// wrong: it cancels, so every key whose 32 bytes repeat with a 16-byte
    /// period — including every uniform-byte key — collapses onto the same
    /// seed, and a fleet of such nodes would share one schedule. Chaining
    /// through [`SeedableRng::seed_from_u64`] is order-dependent and has no
    /// such fixed point.
    pub fn seed_from_key(public_key: &[u8; 32]) -> u64 {
        public_key.chunks_exact(8).fold(0u64, |mixed, chunk| {
            let mut word = [0u8; 8];
            word.copy_from_slice(chunk);
            SmallRng::seed_from_u64(mixed ^ u64::from_le_bytes(word)).next_u64()
        })
    }

    /// A delay uniform over `[base_ms / 2, base_ms * 3 / 2)`.
    ///
    /// Used for the reconnect delay. The lower bound keeps a client from
    /// hot-looping against a server that is refusing connections; the upper
    /// bound keeps worst-case recovery within a small multiple of the base.
    ///
    /// Returns `0` for a zero base, and saturates rather than overflowing.
    pub fn spread_ms(&mut self, base_ms: u32) -> u32 {
        if base_ms == 0 {
            return 0;
        }
        let base = u64::from(base_ms);
        let low = base / 2;
        let high = base
            .saturating_mul(u64::from(SPREAD_NUMERATOR))
            .saturating_div(u64::from(SPREAD_DENOMINATOR))
            .max(low + 1);
        u32::try_from(self.rng.gen_range(low..high)).unwrap_or(u32::MAX)
    }

    /// A delay uniform over `[0, window_ms)`.
    ///
    /// Used to offset the start of a reconciliation burst. Returns `0` for a
    /// zero window.
    pub fn window_ms(&mut self, window_ms: u32) -> u32 {
        if window_ms == 0 {
            return 0;
        }
        self.rng.gen_range(0..window_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spread_stays_within_the_documented_bounds() {
        let mut jitter = Jitter::new(1);
        for _ in 0..10_000 {
            let delay = jitter.spread_ms(1_000);
            assert!((500..1_500).contains(&delay), "out of bounds: {delay}");
        }
    }

    #[test]
    fn window_stays_below_its_bound() {
        let mut jitter = Jitter::new(7);
        for _ in 0..10_000 {
            assert!(jitter.window_ms(REFRESH_BURST_WINDOW_MS) < REFRESH_BURST_WINDOW_MS);
        }
    }

    #[test]
    fn zero_inputs_do_not_panic() {
        let mut jitter = Jitter::new(0);
        assert_eq!(jitter.spread_ms(0), 0);
        assert_eq!(jitter.window_ms(0), 0);
    }

    /// `gen_range` panics on an empty range, so the degenerate bases that make
    /// `[base/2, base*3/2)` collapse have to stay non-empty.
    #[test]
    fn tiny_and_huge_bases_produce_a_usable_range() {
        let mut jitter = Jitter::new(3);
        for base in [1, 2, 3, u32::MAX - 1, u32::MAX] {
            let delay = jitter.spread_ms(base);
            assert!(
                delay >= base / 2,
                "base {base} produced {delay}, below its floor"
            );
        }
    }

    /// The whole point: two nodes must not reconnect in lockstep.
    ///
    /// These two keys are the ones a broken reduction collapses — both are
    /// uniform-byte, so both folded to seed 0 under the XOR version. Keep the
    /// assertion on the *schedule* rather than the seed: a shared seed is only
    /// a problem because it produces a shared schedule.
    #[test]
    fn distinct_keys_produce_distinct_schedules() {
        let mut left = Jitter::from_key(&[0xAA; 32]);
        let mut right = Jitter::from_key(&[0xBB; 32]);
        let left: Vec<_> = (0..8).map(|_| left.spread_ms(1_000)).collect();
        let right: Vec<_> = (0..8).map(|_| right.spread_ms(1_000)).collect();
        assert_ne!(left, right);
    }

    #[test]
    fn one_key_always_seeds_the_same_schedule() {
        let mut first = Jitter::from_key(&[0x11; 32]);
        let mut second = Jitter::from_key(&[0x11; 32]);
        assert_eq!(first.spread_ms(1_000), second.spread_ms(1_000));
    }

    /// The reduction must have no fixed point that swallows whole families of
    /// keys.
    #[test]
    fn no_key_family_collapses_onto_one_seed() {
        let mut seeds = std::collections::HashSet::new();

        // Every uniform-byte key. The broken fold mapped all 256 to zero.
        for byte in 0u8..=255 {
            assert!(
                seeds.insert(Jitter::seed_from_key(&[byte; 32])),
                "uniform key {byte:#04x} collided with an earlier seed"
            );
        }

        // Keys built from a repeating 16-byte and 8-byte period.
        for byte in 0u8..=255 {
            let mut period16 = [0u8; 32];
            for (index, slot) in period16.iter_mut().enumerate() {
                *slot = byte.wrapping_add((index % 16) as u8);
            }
            assert!(
                seeds.insert(Jitter::seed_from_key(&period16)),
                "16-byte-period key from {byte:#04x} collided"
            );
        }

        // Keys differing in exactly one byte, at either end.
        let mut early = [0u8; 32];
        early[0] = 1;
        let mut late = [0u8; 32];
        late[31] = 1;
        assert!(seeds.insert(Jitter::seed_from_key(&early)));
        assert!(seeds.insert(Jitter::seed_from_key(&late)));
    }

    /// A fleet must actually fill the window, not cluster in part of it.
    #[test]
    fn delays_cover_the_window() {
        let mut buckets = [0usize; 4];
        for seed in 0..1_000u64 {
            let mut jitter = Jitter::new(seed);
            let delay = jitter.spread_ms(1_000);
            buckets[((delay - 500) / 250) as usize] += 1;
        }
        for count in buckets {
            assert!(count > 150, "uneven spread: {buckets:?}");
        }
    }
}
