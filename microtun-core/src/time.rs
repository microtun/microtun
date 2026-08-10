//! Monotonic time primitives.
//!
//! The core is time-agnostic: the embedding supplies a monotonic [`Instant`]
//! with every call. Milliseconds since an arbitrary epoch is plenty of
//! resolution for every timer in §6 of the whitepaper (the shortest interval
//! is the 5 s `Rekey-Timeout`).

/// A point in monotonic time, in milliseconds since an arbitrary epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Instant(pub u64);

/// A span of time in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Duration(pub u64);

impl Instant {
    /// Construct from raw milliseconds.
    #[inline]
    pub const fn from_millis(ms: u64) -> Self {
        Self(ms)
    }

    /// Raw milliseconds.
    #[inline]
    pub const fn as_millis(self) -> u64 {
        self.0
    }

    /// Saturating time elapsed since `earlier`.
    #[inline]
    pub const fn saturating_since(self, earlier: Instant) -> Duration {
        Duration(self.0.saturating_sub(earlier.0))
    }

    /// `self + d`, saturating.
    #[inline]
    pub const fn saturating_add(self, d: Duration) -> Instant {
        Instant(self.0.saturating_add(d.0))
    }
}

impl Duration {
    /// Construct from seconds, saturating at [`u64::MAX`] milliseconds.
    #[inline]
    pub const fn from_secs(s: u64) -> Self {
        Self(s.saturating_mul(1000))
    }

    /// Construct from milliseconds.
    #[inline]
    pub const fn from_millis(ms: u64) -> Self {
        Self(ms)
    }

    /// Raw milliseconds.
    #[inline]
    pub const fn as_millis(self) -> u64 {
        self.0
    }
}

impl core::ops::Add<Duration> for Instant {
    type Output = Instant;
    #[inline]
    fn add(self, rhs: Duration) -> Instant {
        self.saturating_add(rhs)
    }
}

impl core::ops::Sub<Instant> for Instant {
    type Output = Duration;
    #[inline]
    fn sub(self, rhs: Instant) -> Duration {
        self.saturating_since(rhs)
    }
}

impl core::ops::Add<Duration> for Duration {
    type Output = Duration;
    #[inline]
    fn add(self, rhs: Duration) -> Duration {
        Duration(self.0.saturating_add(rhs.0))
    }
}

impl core::ops::Sub<Duration> for Duration {
    type Output = Duration;
    #[inline]
    fn sub(self, rhs: Duration) -> Duration {
        Duration(self.0.saturating_sub(rhs.0))
    }
}

/// Return the earlier of two optional deadlines.
#[inline]
pub fn min_deadline(a: Option<Instant>, b: Option<Instant>) -> Option<Instant> {
    [a, b].into_iter().flatten().min()
}

/// A cached *lower bound* on the engine's next timer deadline.
///
/// The engine's timers live spread across the peer table, the slot pool, the
/// parked-packet pool and the resolver table. Computing their true minimum
/// means walking all four, which is far too expensive to repeat on every
/// packet. This type replaces that walk with an `O(1)` bound maintained
/// incrementally, under one invariant:
///
/// > the cached value is never *later* than the true earliest deadline.
///
/// That asymmetry is what makes the bookkeeping cheap. Arming a new timer
/// must lower the bound ([`TimerCache::arm`]), or the engine would sleep
/// through it — but *clearing* a timer needs no bookkeeping at all, because
/// leaving the bound where it is only risks waking early. An early wake is
/// harmless: the engine finds nothing due, and pays for one exact
/// recomputation ([`TimerCache::set_exact`]) to restore precision.
///
/// So every timer-clearing site in the engine — and there are many, on the
/// hottest paths — needs no cache maintenance whatsoever, and forgetting one
/// costs at most a spurious wake rather than a stalled protocol.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct TimerCache {
    /// `None` means "no deadline known", i.e. an infinitely distant bound.
    at: Option<Instant>,
}

impl TimerCache {
    /// A cache holding no deadline.
    #[inline]
    pub(crate) const fn new() -> Self {
        Self { at: None }
    }

    /// The current bound: at or before the true next deadline.
    #[inline]
    pub(crate) const fn get(self) -> Option<Instant> {
        self.at
    }

    /// Lower the bound to `at` unless it is already at or before it.
    ///
    /// Every site that installs or advances a deadline calls this. It is
    /// monotonically decreasing and therefore cannot break the invariant, no
    /// matter how often or how redundantly it is called.
    #[inline]
    pub(crate) fn arm(&mut self, at: Instant) {
        if self.at.is_none_or(|current| at < current) {
            self.at = Some(at);
        }
    }

    /// Replace the bound with an exactly computed value.
    ///
    /// Called only after a wake that found no work due, which is the one
    /// moment the bound is known to be stale and worth recomputing.
    #[inline]
    pub(crate) fn set_exact(&mut self, at: Option<Instant>) {
        self.at = at;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arithmetic_saturates_instead_of_wrapping_or_panicking() {
        // Every operator on these types is saturating, because a monotonic
        // clock supplied by an embedding is not something the engine gets to
        // assume anything about.
        let late = Instant::from_millis(u64::MAX);
        assert_eq!(late + Duration::from_secs(1), late);
        assert_eq!(late.saturating_add(Duration(u64::MAX)), late);

        // Time running backwards yields zero elapsed, never a huge duration —
        // the difference between a no-op and every timer firing at once.
        let early = Instant::from_millis(10);
        assert_eq!(early.saturating_since(late), Duration(0));
        assert_eq!(early - late, Duration(0));
        assert_eq!(late - early, Duration(u64::MAX - 10));

        assert_eq!(
            Duration::from_millis(3) - Duration::from_millis(10),
            Duration(0)
        );
        assert_eq!(Duration(u64::MAX) + Duration(1), Duration(u64::MAX));
        assert_eq!(Duration::from_secs(u64::MAX), Duration(u64::MAX));
    }

    #[test]
    fn timer_cache_only_ever_moves_its_bound_earlier() {
        // The cache's single invariant is that it is never *later* than the
        // true earliest deadline. That is what lets every timer-clearing site
        // in the engine skip cache maintenance entirely: forgetting one costs
        // a spurious wake, never a stalled protocol.
        let mut cache = TimerCache::new();
        assert_eq!(cache.get(), None);

        // The first arm always takes: `None` means "infinitely distant".
        cache.arm(Instant::from_millis(100));
        assert_eq!(cache.get(), Some(Instant::from_millis(100)));

        // A later deadline cannot raise the bound, however often it is armed.
        for _ in 0..3 {
            cache.arm(Instant::from_millis(500));
        }
        assert_eq!(cache.get(), Some(Instant::from_millis(100)));

        // An earlier one always lowers it, so arming is order-insensitive.
        cache.arm(Instant::from_millis(40));
        assert_eq!(cache.get(), Some(Instant::from_millis(40)));
        cache.arm(Instant::from_millis(40));
        assert_eq!(cache.get(), Some(Instant::from_millis(40)));

        // Whatever order deadlines arrive in, the bound is their minimum.
        let deadlines = [700u64, 3, 900, 250, 61, 1];
        let mut shuffled = TimerCache::new();
        for ms in deadlines {
            shuffled.arm(Instant::from_millis(ms));
        }
        let expected = deadlines.iter().copied().min().expect("non-empty");
        assert_eq!(shuffled.get(), Some(Instant::from_millis(expected)));

        // `set_exact` is the one operation allowed to move the bound later,
        // and is called only after a wake that found nothing due.
        shuffled.set_exact(Some(Instant::from_millis(10_000)));
        assert_eq!(shuffled.get(), Some(Instant::from_millis(10_000)));
        shuffled.set_exact(None);
        assert_eq!(shuffled.get(), None);
        // ...and after clearing, arming works from scratch again.
        shuffled.arm(Instant::from_millis(7));
        assert_eq!(shuffled.get(), Some(Instant::from_millis(7)));
    }
}
