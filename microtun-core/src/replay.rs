//! Anti-replay sliding window for transport message counters (§5.4.6).
//!
//! Implements the bitmap scheme of RFC 6479 (as the whitepaper recommends):
//! a ring of word-sized blocks, avoiding bit shifts across the whole window
//! and tolerating the extreme reordering multi-core senders can produce.
//! The ring size is selected by the core's replay-word capacity. One word is
//! reserved for recycling, so `REPLAY_WORDS = 128` provides the reference-compatible
//! `(128 - 1) * 64 = 8128` packet trailing window.

const WORD_BITS: u64 = 64;

/// Sliding-window replay filter. `check_and_update` must only be called
/// **after** the message authenticated (the whitepaper is explicit that the
/// window is consulted post-authentication so attackers cannot poison it).
#[derive(Debug, Clone)]
pub struct ReplayWindow<const REPLAY_WORDS: usize> {
    bitmap: [u64; REPLAY_WORDS],
    /// Highest counter accepted so far, or `None` before the first packet.
    top: Option<u64>,
}

impl<const REPLAY_WORDS: usize> Default for ReplayWindow<REPLAY_WORDS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const REPLAY_WORDS: usize> ReplayWindow<REPLAY_WORDS> {
    const WINDOW: u64 = WORD_BITS * REPLAY_WORDS.saturating_sub(1) as u64;

    pub const fn new() -> Self {
        assert!(REPLAY_WORDS > 0, "replay window requires at least one word");
        Self {
            bitmap: [0; REPLAY_WORDS],
            top: None,
        }
    }

    /// Returns `true` (and records the counter) if `counter` is new and
    /// within the window; `false` if replayed or too old.
    pub fn check_and_update(&mut self, counter: u64) -> bool {
        let index = counter / WORD_BITS;
        match self.top {
            None => {
                // First packet: initialize around it.
                self.bitmap = [0; REPLAY_WORDS];
                if !self.set_bit(counter) {
                    return false;
                }
                self.top = Some(counter);
                true
            }
            Some(top) => {
                if counter > top {
                    // Advance: clear every block between the old top block and
                    // the new one (bounded by the ring size).
                    let top_index = top / WORD_BITS;
                    let diff = (index - top_index).min(REPLAY_WORDS as u64);
                    for i in 1..=diff {
                        let blk = ((top_index + i) % REPLAY_WORDS as u64) as usize;
                        let Some(word) = self.bitmap.get_mut(blk) else {
                            return false;
                        };
                        *word = 0;
                    }
                    if !self.set_bit(counter) {
                        return false;
                    }
                    self.top = Some(counter);
                    true
                } else {
                    // Behind the top: inside the window and unseen?
                    if top - counter > Self::WINDOW {
                        return false; // too old
                    }
                    if self.get_bit(counter) {
                        return false; // replay
                    }
                    self.set_bit(counter)
                }
            }
        }
    }

    #[inline]
    fn get_bit(&self, counter: u64) -> bool {
        let blk = ((counter / WORD_BITS) % REPLAY_WORDS as u64) as usize;
        let bit = counter % WORD_BITS;
        self.bitmap
            .get(blk)
            .is_some_and(|word| (word >> bit) & 1 == 1)
    }

    #[inline]
    fn set_bit(&mut self, counter: u64) -> bool {
        let blk = ((counter / WORD_BITS) % REPLAY_WORDS as u64) as usize;
        let bit = counter % WORD_BITS;
        let Some(word) = self.bitmap.get_mut(blk) else {
            return false;
        };
        *word |= 1 << bit;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The usable window: one block of the ring is always in the process of
    /// being recycled, so the guarantee is `(REPLAY_WORDS - 1) * WORD_BITS`.
    const REPLAY_WORDS: usize = 128;
    const WINDOW: u64 = WORD_BITS * (REPLAY_WORDS as u64 - 1);

    #[test]
    fn reordering_inside_the_window_is_accepted_exactly_once() {
        // Tolerating extreme reordering is the whole point of the bitmap: a
        // multi-core sender routinely delivers counters out of order, and a
        // simple "greater than the last" check would drop most of a burst.
        let mut window = ReplayWindow::<REPLAY_WORDS>::new();
        for counter in [5u64, 3, 4, 1, 2, 0] {
            assert!(window.check_and_update(counter), "{counter} is new");
        }
        for counter in [0u64, 1, 2, 3, 4, 5] {
            assert!(!window.check_and_update(counter), "{counter} is a replay");
        }

        // Crossing a word boundary backwards is still inside the window.
        let mut window = ReplayWindow::<REPLAY_WORDS>::new();
        assert!(window.check_and_update(70));
        assert!(window.check_and_update(63));
        assert!(window.check_and_update(64));
        assert!(!window.check_and_update(63));
    }

    #[test]
    fn the_trailing_edge_is_exact() {
        let mut window = ReplayWindow::<REPLAY_WORDS>::new();
        let top = 20_000u64;
        assert!(window.check_and_update(top));

        // wireguard-go rejects only when the distance is greater than the
        // usable window, so the exact trailing edge remains valid.
        assert!(
            window.check_and_update(top - WINDOW),
            "exactly `WINDOW` behind the top must still be accepted"
        );
        assert!(!window.check_and_update(top - WINDOW), "and only once");
        assert!(
            !window.check_and_update(top - WINDOW - 1),
            "one counter beyond the trailing edge must be rejected"
        );

        assert!(window.check_and_update(top - 1));
        assert!(!window.check_and_update(top - 1));
    }

    #[test]
    fn word_count_controls_the_usable_window() {
        const SMALL_WORDS: usize = 3;
        const SMALL_WINDOW: u64 = WORD_BITS * (SMALL_WORDS as u64 - 1);
        let mut window = ReplayWindow::<SMALL_WORDS>::new();
        let top = 1_000u64;

        assert!(window.check_and_update(top));
        assert!(window.check_and_update(top - SMALL_WINDOW));
        assert!(!window.check_and_update(top - SMALL_WINDOW - 1));
    }

    #[test]
    fn a_forward_jump_clears_the_ring_rather_than_wrapping_onto_stale_bits() {
        // The ring is only `REPLAY_WORDS` blocks long, so a jump larger than the ring
        // must clear every block. If it wrapped instead, bits set long ago
        // would masquerade as recent history and reject fresh counters.
        let mut window = ReplayWindow::<REPLAY_WORDS>::new();
        for counter in 0..200u64 {
            assert!(window.check_and_update(counter));
        }

        let top = 1_000_000u64;
        assert!(window.check_and_update(top));

        // Everything the jump left behind is unreachably old...
        for stale in [0u64, 199, top - WINDOW - 1] {
            assert!(!window.check_and_update(stale), "{stale} should be too old");
        }
        // ...and every counter inside the new window is genuinely unseen,
        // including ones whose bit position collides with an old entry.
        for offset in 1..WINDOW {
            assert!(
                window.check_and_update(top - offset),
                "counter {} inside the window was wrongly rejected",
                top - offset
            );
        }
        assert!(!window.check_and_update(top - 1), "now it is a replay");

        // Advancing again invalidates the tail we just filled.
        let next = top + 2 * WINDOW;
        assert!(window.check_and_update(next));
        assert!(!window.check_and_update(top));
        assert!(window.check_and_update(next - 1));
    }

    #[test]
    fn a_single_step_advance_only_clears_the_blocks_it_crosses() {
        // The common case: counters arriving in order. Advancing must not
        // clear the block the top currently lives in, or every packet would
        // erase its own predecessors and replays would be admitted.
        let mut window = ReplayWindow::<REPLAY_WORDS>::new();
        for counter in 0..(WORD_BITS * 3) {
            assert!(window.check_and_update(counter));
        }
        for counter in 0..(WORD_BITS * 3) {
            assert!(
                !window.check_and_update(counter),
                "in-order counter {counter} was forgotten"
            );
        }
    }
}
