//! Injectable time source (SPEC §10.4).
//!
//! Every gating decision that depends on time — warden poll cadence,
//! time-to-auto-stop, circuit-breaker timing, trust transitions — reads time
//! through the [`Clock`] trait, never `std::time::Instant::now()` or
//! `SystemTime::now()` directly. That makes those decisions deterministic and
//! replayable: tests drive an advanceable [`MockClock`] and assert exact
//! event order, with **no wall-clock reads anywhere in gating logic**.
//!
//! The production [`SystemClock`] is the only place a real clock is read, and
//! it lives behind the same trait so it can be swapped at the seam.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// A logical instant, expressed as whole milliseconds.
///
/// We deliberately use a plain integer rather than `std::time::Instant` so the
/// type is `Copy`, serializable, and trivially comparable across the
/// dry-run/apply boundary. Two flavours are exposed by [`Clock`]:
///
/// - [`Clock::now_unix_millis`] — a wall-clock-style timestamp for stamping
///   records (audit, blast-radius). Not for gating.
/// - [`Clock::monotonic_millis`] — a never-decreasing counter for measuring
///   elapsed time in gating logic (timeouts, breaker windows).
pub type Millis = u64;

/// Injectable source of time.
///
/// Implementors must guarantee that [`monotonic_millis`](Clock::monotonic_millis)
/// is non-decreasing across calls. Gating logic depends on the monotonic value;
/// the unix value is for human-facing stamps only.
pub trait Clock: Send + Sync {
    /// Wall-clock-style timestamp in milliseconds since the Unix epoch.
    ///
    /// Use this only to *stamp* records, never to make a gating decision —
    /// wall clocks can jump backwards (NTP, leap seconds).
    fn now_unix_millis(&self) -> Millis;

    /// A monotonic, non-decreasing millisecond counter.
    ///
    /// This is the value all timeout / breaker / auto-stop logic reads. With
    /// the [`MockClock`] it only advances when the test advances it, so timing
    /// is fully deterministic.
    fn monotonic_millis(&self) -> Millis;
}

/// Production clock backed by the operating system.
///
/// This is the **only** type that reads a real clock; it exists so the rest of
/// the system can depend on the [`Clock`] trait and inject [`MockClock`] in
/// tests.
#[derive(Debug, Clone, Default)]
pub struct SystemClock {
    /// Process-start anchor for the monotonic reading, captured lazily.
    _private: (),
}

impl SystemClock {
    /// Construct a system clock.
    pub fn new() -> Self {
        SystemClock { _private: () }
    }
}

impl Clock for SystemClock {
    fn now_unix_millis(&self) -> Millis {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as Millis)
            // A clock before the epoch is nonsensical; clamp to 0 rather than
            // panic. Gating logic never reads the unix clock anyway.
            .unwrap_or(0)
    }

    fn monotonic_millis(&self) -> Millis {
        // `Instant` has no public epoch, so we derive a monotonic-ish reading
        // from a process-lifetime anchor. This is production-only; tests use
        // `MockClock`, so determinism is unaffected.
        use std::sync::OnceLock;
        use std::time::Instant;
        static ANCHOR: OnceLock<Instant> = OnceLock::new();
        let anchor = ANCHOR.get_or_init(Instant::now);
        anchor.elapsed().as_millis() as Millis
    }
}

/// Advanceable test clock (SPEC §10.4).
///
/// Both the unix and monotonic readings start at a caller-chosen value and only
/// move when the test calls [`advance`](MockClock::advance) (or one of the
/// `set_*` helpers). Cloning shares the same underlying counters via [`Arc`], so
/// a clock handed to the code under test and a handle kept by the test observe
/// the same time — the test can advance it mid-flight.
#[derive(Debug, Clone, Default)]
pub struct MockClock {
    unix: Arc<AtomicU64>,
    monotonic: Arc<AtomicU64>,
}

impl MockClock {
    /// A mock clock with both readings starting at `0`.
    pub fn new() -> Self {
        MockClock::starting_at(0)
    }

    /// A mock clock with both the unix and monotonic readings starting at
    /// `start_millis`.
    pub fn starting_at(start_millis: Millis) -> Self {
        MockClock {
            unix: Arc::new(AtomicU64::new(start_millis)),
            monotonic: Arc::new(AtomicU64::new(start_millis)),
        }
    }

    /// Advance **both** readings by `delta_millis`.
    ///
    /// Returns the new monotonic reading.
    pub fn advance(&self, delta_millis: Millis) -> Millis {
        self.unix.fetch_add(delta_millis, Ordering::SeqCst);
        self.monotonic.fetch_add(delta_millis, Ordering::SeqCst) + delta_millis
    }

    /// Overwrite the unix reading (used to simulate a wall-clock jump that must
    /// *not* affect gating).
    pub fn set_unix_millis(&self, value: Millis) {
        self.unix.store(value, Ordering::SeqCst);
    }
}

impl Clock for MockClock {
    fn now_unix_millis(&self) -> Millis {
        self.unix.load(Ordering::SeqCst)
    }

    fn monotonic_millis(&self) -> Millis {
        self.monotonic.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_clock_starts_frozen() {
        let clock = MockClock::new();
        // Frozen: reading twice without advancing returns the same value.
        assert_eq!(clock.monotonic_millis(), 0);
        assert_eq!(clock.monotonic_millis(), 0);
        assert_eq!(clock.now_unix_millis(), 0);
    }

    #[test]
    fn mock_clock_advances_deterministically() {
        let clock = MockClock::starting_at(1_000);
        assert_eq!(clock.monotonic_millis(), 1_000);
        let new = clock.advance(250);
        assert_eq!(new, 1_250);
        assert_eq!(clock.monotonic_millis(), 1_250);
        assert_eq!(clock.now_unix_millis(), 1_250);
    }

    #[test]
    fn mock_clock_clones_share_the_same_time() {
        // A clock handed to the code under test must share its counter with the
        // handle the test keeps, so the test can advance it mid-flight.
        let clock = MockClock::new();
        let injected = clock.clone();
        clock.advance(42);
        assert_eq!(injected.monotonic_millis(), 42);
    }

    #[test]
    fn unix_jump_does_not_move_the_monotonic_reading() {
        // A wall-clock jump (NTP / leap second) must never rewind or warp the
        // monotonic reading that gating logic relies on.
        let clock = MockClock::starting_at(10_000);
        clock.advance(5);
        clock.set_unix_millis(0); // wall clock jumps backwards
        assert_eq!(clock.now_unix_millis(), 0);
        assert_eq!(clock.monotonic_millis(), 10_005);
    }

    #[test]
    fn monotonic_is_non_decreasing() {
        let clock = MockClock::new();
        let mut prev = clock.monotonic_millis();
        for step in [3, 0, 7, 1] {
            clock.advance(step);
            let now = clock.monotonic_millis();
            assert!(now >= prev, "monotonic clock went backwards");
            prev = now;
        }
    }

    #[test]
    fn system_clock_is_usable_through_the_trait() {
        // Smoke-test the production impl behind the trait object boundary.
        let clock: &dyn Clock = &SystemClock::new();
        let a = clock.monotonic_millis();
        let b = clock.monotonic_millis();
        assert!(b >= a);
        // Unix reading should be a plausible post-2020 timestamp.
        assert!(clock.now_unix_millis() > 1_577_836_800_000);
    }
}
