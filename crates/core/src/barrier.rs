//! The apply-barrier seam (SPEC §10.4).
//!
//! Guarded apply runs in two phases: a **dry-run** on a clone that produces a
//! [`BlastRadius`](crate::blast_radius::BlastRadius) (with a
//! [`PkChecksum`](crate::pk_checksum::PkChecksum)), then an **apply** inside a
//! single txn that recomputes the checksum and aborts on any mismatch. The
//! [`ApplyBarrier::pause_point`] hook sits *between* those two phases.
//!
//! - In **production** the barrier is a no-op ([`NoopBarrier`]): the apply
//!   proceeds straight from dry-run to apply with nothing injected.
//! - In **tests** the barrier runs an injected closure ([`ClosureBarrier`]).
//!   The drift / TOCTOU tests (#8 and the S3 spike) use it to *mutate the clone
//!   or prod state mid-flight* — inserting or deleting rows between the dry-run
//!   checksum and the apply-time checksum — and then assert the guard ABORTs.
//!
//! The seam is deliberately tiny and synchronous so the ordering is
//! deterministic: when `pause_point()` returns, every side effect the injected
//! closure performed has happened-before the apply phase.

/// A label naming which barrier was crossed, surfaced for audit / tracing.
///
/// Callers pass it so logs can show *where* in the apply lifecycle an injected
/// action ran (there is exactly one barrier today, but the field keeps the API
/// forward-compatible).
pub type BarrierLabel = &'static str;

/// The deterministic hook between the dry-run and apply phases of a guarded
/// write (SPEC §10.4).
///
/// Implementors run any pending injected behaviour when [`pause_point`] is
/// called. The production implementation does nothing; test implementations run
/// a closure that can mutate world state to simulate drift.
///
/// The method takes `&self` (not `&mut self`) so a single barrier can be shared
/// across the apply pipeline; implementations that need mutability use interior
/// mutability (see [`ClosureBarrier`]).
pub trait ApplyBarrier: Send + Sync {
    /// Called exactly once, after the dry-run checksum is captured and before
    /// the apply txn recomputes it.
    ///
    /// `label` names the crossing for audit/tracing. Production impls ignore it.
    fn pause_point(&self, label: BarrierLabel);
}

/// Production barrier: a no-op (SPEC §10.4).
///
/// Crossing the barrier does nothing, so apply proceeds straight from dry-run to
/// apply. This is the only barrier wired into the real apply path.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopBarrier;

impl NoopBarrier {
    /// Construct the production no-op barrier.
    pub fn new() -> Self {
        NoopBarrier
    }
}

impl ApplyBarrier for NoopBarrier {
    fn pause_point(&self, _label: BarrierLabel) {
        // Intentionally empty: production crosses the barrier with no detour.
    }
}

/// Test barrier that runs an injected closure when the barrier is crossed
/// (SPEC §10.4).
///
/// Used by the drift / TOCTOU tests to mutate clone or prod state *between* the
/// dry-run checksum and the apply-time checksum. The closure is `FnMut` so it
/// can carry and update its own counters (e.g. "only inject on the first
/// crossing"). It also records how many times the barrier was crossed, which
/// lets a test assert the apply pipeline reached the barrier exactly once.
pub struct ClosureBarrier {
    inner: std::sync::Mutex<ClosureBarrierInner>,
}

struct ClosureBarrierInner {
    on_pause: Box<dyn FnMut(BarrierLabel) + Send>,
    crossings: u64,
}

impl ClosureBarrier {
    /// Build a test barrier that runs `on_pause` every time the barrier is
    /// crossed.
    pub fn new(on_pause: impl FnMut(BarrierLabel) + Send + 'static) -> Self {
        ClosureBarrier {
            inner: std::sync::Mutex::new(ClosureBarrierInner {
                on_pause: Box::new(on_pause),
                crossings: 0,
            }),
        }
    }

    /// How many times the barrier has been crossed so far.
    pub fn crossings(&self) -> u64 {
        self.inner.lock().expect("barrier mutex poisoned").crossings
    }
}

impl ApplyBarrier for ClosureBarrier {
    fn pause_point(&self, label: BarrierLabel) {
        let mut guard = self.inner.lock().expect("barrier mutex poisoned");
        guard.crossings += 1;
        // Take the closure out so we don't hold a `&mut` borrow of `guard`
        // across the call (which would also let a re-entrant cross deadlock —
        // it instead panics on the mutex, surfacing the bug loudly).
        (guard.on_pause)(label);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    #[test]
    fn noop_barrier_does_nothing_and_is_a_zst() {
        let barrier = NoopBarrier::new();
        // Crossing it has no observable effect; just assert it does not panic.
        barrier.pause_point("between dry_run and apply");
        assert_eq!(std::mem::size_of::<NoopBarrier>(), 0);
    }

    #[test]
    fn closure_barrier_runs_injected_closure_on_crossing() {
        // Simulate the drift test: the injected closure mutates shared state
        // (here a counter standing in for "rows on the clone") mid-flight.
        let injected_rows = Arc::new(AtomicU64::new(0));
        let rows = Arc::clone(&injected_rows);
        let barrier = ClosureBarrier::new(move |_label| {
            rows.fetch_add(7, Ordering::SeqCst);
        });

        assert_eq!(injected_rows.load(Ordering::SeqCst), 0);
        barrier.pause_point("between dry_run and apply");
        // The mutation happened-before pause_point returned.
        assert_eq!(injected_rows.load(Ordering::SeqCst), 7);
        assert_eq!(barrier.crossings(), 1);
    }

    #[test]
    fn closure_barrier_can_inject_only_on_the_first_crossing() {
        // FnMut lets the closure carry state — inject drift once, then behave.
        let drift_applied = Arc::new(AtomicU64::new(0));
        let counter = Arc::clone(&drift_applied);
        let mut first = true;
        let barrier = ClosureBarrier::new(move |_label| {
            if first {
                counter.fetch_add(1, Ordering::SeqCst);
                first = false;
            }
        });

        barrier.pause_point("apply");
        barrier.pause_point("apply");
        assert_eq!(drift_applied.load(Ordering::SeqCst), 1);
        assert_eq!(barrier.crossings(), 2);
    }

    #[test]
    fn barrier_is_usable_as_a_trait_object() {
        // The apply pipeline holds `&dyn ApplyBarrier`; both impls must fit.
        let prod: &dyn ApplyBarrier = &NoopBarrier::new();
        prod.pause_point("prod");

        let hit = Arc::new(AtomicU64::new(0));
        let h = Arc::clone(&hit);
        let test_barrier = ClosureBarrier::new(move |_| {
            h.fetch_add(1, Ordering::SeqCst);
        });
        let test_dyn: &dyn ApplyBarrier = &test_barrier;
        test_dyn.pause_point("test");
        assert_eq!(hit.load(Ordering::SeqCst), 1);
    }
}
