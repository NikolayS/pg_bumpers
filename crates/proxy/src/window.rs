//! The **cumulative per-window volume budget** — the anti slow-drip read gate
//! (SPEC §3 layer 2, §11.6, §13.4 R4a; deferred from S1 → S4).
//!
//! The single-shot byte/row cutoff ([`crate::budget`]) bounds *one* statement,
//! but it can't stop exfiltration split across **many small reads** (R4a): each
//! read is individually under the single-shot cap, yet their sum drains the DB.
//! This meter closes that gap. It accumulates the bytes/rows streamed by a
//! session's reads **across statements** within a rolling window and, when the
//! cumulative total would breach the per-window budget `B`, **kills** the
//! statement (and the session) — the bounded-disclosure guarantee: ≤ B leaked,
//! then stopped.
//!
//! ## Deterministic by construction
//!
//! Time is read through the injected [`Clock`] (the **monotonic** reading, never
//! a wall clock), so the window boundary and reset are fully deterministic and
//! CI-gated: tests advance a [`pgb_core::MockClock`] and assert the budget trips
//! at the exact boundary and resets exactly when the window rolls over. There is
//! no wall-clock read anywhere in this gate.
//!
//! ## Window semantics (fixed, tumbling)
//!
//! The window is a **fixed (tumbling)** window of `window_secs`: the first charge
//! anchors the window at the current monotonic instant; subsequent charges that
//! land within `[anchor, anchor + window)` accumulate against the same budget;
//! the first charge at or after `anchor + window` **resets** the counters and
//! re-anchors. A fixed window keeps the boundary a single deterministic instant
//! (a sliding window would need per-event history); the single-shot cutoff plus
//! `statement_timeout` cover the within-window burst, so a tumbling window is the
//! right granularity for the slow-drip gate.

use pgb_core::Clock;
use pgb_policy::WindowBudget;

/// Which cumulative dimension tripped the per-window budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowCap {
    /// The cumulative byte budget for the window (`WindowBudget::max_bytes`).
    Bytes,
    /// The cumulative row budget for the window (`WindowBudget::max_rows`).
    Rows,
}

impl WindowCap {
    /// A short machine-readable code for audit/error reasons.
    pub fn code(self) -> &'static str {
        match self {
            WindowCap::Bytes => "window_byte_budget_exceeded",
            WindowCap::Rows => "window_row_budget_exceeded",
        }
    }
}

/// What charging volume against the per-window budget yields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowOutcome {
    /// The volume fits inside the window's budget; the charge is committed.
    /// Carries the running cumulative totals (after this charge).
    Within {
        /// Cumulative bytes charged in the current window (incl. this charge).
        bytes: u64,
        /// Cumulative rows charged in the current window (incl. this charge).
        rows: u64,
    },
    /// Charging this volume would breach the cumulative budget — **kill**. The
    /// charge is **not** committed; the carried totals are the pre-charge values.
    Exceeded {
        /// Which cumulative dimension tripped.
        cap: WindowCap,
        /// Cumulative bytes *before* this (refused) charge.
        bytes: u64,
        /// Cumulative rows *before* this (refused) charge.
        rows: u64,
    },
}

/// A live cumulative meter over a rolling (fixed/tumbling) window for one
/// session, driven by an injected [`Clock`] for deterministic boundaries.
///
/// The meter holds the window budget, the window length in **milliseconds**
/// (derived once from `window_secs`), the monotonic anchor of the current
/// window (`None` until the first charge), and the running cumulative totals.
#[derive(Debug)]
pub struct WindowMeter {
    max_bytes: u64,
    max_rows: u64,
    window_ms: u64,
    anchor_ms: Option<u64>,
    used_bytes: u64,
    used_rows: u64,
}

impl WindowMeter {
    /// A fresh per-window meter for a role's cumulative budget.
    pub fn for_window(budget: &WindowBudget) -> Self {
        WindowMeter {
            max_bytes: budget.max_bytes,
            max_rows: budget.max_rows,
            // `window_secs` is validated > 0 by the policy loader; saturate the
            // ms conversion so an absurd window can't overflow.
            window_ms: budget.window_secs.saturating_mul(1_000),
            anchor_ms: None,
            used_bytes: 0,
            used_rows: 0,
        }
    }

    /// Cumulative bytes charged in the current window.
    pub fn used_bytes(&self) -> u64 {
        self.used_bytes
    }

    /// Cumulative rows charged in the current window.
    pub fn used_rows(&self) -> u64 {
        self.used_rows
    }

    /// The monotonic anchor of the current window, if one is open.
    pub fn anchor_ms(&self) -> Option<u64> {
        self.anchor_ms
    }

    /// Roll the window forward if `now` has passed the current window's end.
    ///
    /// Resets the cumulative counters and re-anchors at `now` when the window
    /// has expired (or has never been opened). Idempotent within a window. This
    /// is split out from [`charge`](Self::charge) so the session can also expire
    /// an idle window before a new statement without charging anything.
    pub fn roll(&mut self, now_ms: u64) {
        match self.anchor_ms {
            // First ever charge / fresh window: anchor here.
            None => {
                self.anchor_ms = Some(now_ms);
                self.used_bytes = 0;
                self.used_rows = 0;
            }
            Some(anchor) => {
                // Window is [anchor, anchor + window_ms). At/after the end → roll.
                if now_ms.saturating_sub(anchor) >= self.window_ms {
                    self.anchor_ms = Some(now_ms);
                    self.used_bytes = 0;
                    self.used_rows = 0;
                }
            }
        }
    }

    /// Charge `bytes`/`rows` of streamed read volume against the window budget at
    /// time `now`.
    ///
    /// Rolls the window first (so an expired window resets before charging), then
    /// commits the charge iff the cumulative totals still hold. On a breach the
    /// charge is **not** committed and [`WindowOutcome::Exceeded`] is returned
    /// (the kill signal) — fail-closed, like the single-shot cutoff. Both caps
    /// are inclusive (cumulative exactly at the cap is within); the row cap is
    /// checked first so a zero-byte row still counts against the row budget.
    pub fn charge(&mut self, bytes: u64, rows: u64, clock: &dyn Clock) -> WindowOutcome {
        let now = clock.monotonic_millis();
        self.roll(now);

        let next_rows = self.used_rows.saturating_add(rows);
        if next_rows > self.max_rows {
            return WindowOutcome::Exceeded {
                cap: WindowCap::Rows,
                bytes: self.used_bytes,
                rows: self.used_rows,
            };
        }
        let next_bytes = self.used_bytes.saturating_add(bytes);
        if next_bytes > self.max_bytes {
            return WindowOutcome::Exceeded {
                cap: WindowCap::Bytes,
                bytes: self.used_bytes,
                rows: self.used_rows,
            };
        }
        self.used_rows = next_rows;
        self.used_bytes = next_bytes;
        WindowOutcome::Within {
            bytes: self.used_bytes,
            rows: self.used_rows,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgb_core::MockClock;

    fn window(window_secs: u64, max_bytes: u64, max_rows: u64) -> WindowBudget {
        WindowBudget {
            window_secs,
            max_bytes,
            max_rows,
        }
    }

    #[test]
    fn small_reads_accumulate_across_statements() {
        // Budget: 1000 bytes / 100 rows per 60s window. Each read is small.
        let clock = MockClock::starting_at(1_000);
        let mut m = WindowMeter::for_window(&window(60, 1_000, 100));
        // Three small reads, each 100 bytes / 10 rows, all within the same window.
        for i in 1..=3u64 {
            match m.charge(100, 10, &clock) {
                WindowOutcome::Within { bytes, rows } => {
                    assert_eq!(bytes, 100 * i);
                    assert_eq!(rows, 10 * i);
                }
                other => panic!("expected Within, got {other:?}"),
            }
        }
        assert_eq!(m.used_bytes(), 300);
        assert_eq!(m.used_rows(), 30);
    }

    /// R4a (deterministic via injected Clock): N small reads whose cumulative
    /// bytes exceed B → the per-window budget trips at the deterministic
    /// boundary (kill), and the refused charge is NOT committed.
    #[test]
    fn slow_drip_trips_the_cumulative_byte_budget_at_the_boundary() {
        let clock = MockClock::starting_at(0);
        // B = 1000 cumulative bytes. Rows are generous so BYTES is the gate.
        let mut m = WindowMeter::for_window(&window(60, 1_000, 1_000_000));
        // 9 reads of 100 bytes = 900 cumulative (each within).
        for i in 1..=9u64 {
            assert!(matches!(
                m.charge(100, 1, &clock),
                WindowOutcome::Within { bytes, .. } if bytes == 100 * i
            ));
            // Drip slowly in time, but stay inside the 60s window.
            clock.advance(1_000);
        }
        assert_eq!(m.used_bytes(), 900);
        // The 10th 100-byte read would make 1000 (exactly at cap) → still within.
        assert!(matches!(
            m.charge(100, 1, &clock),
            WindowOutcome::Within { bytes: 1_000, .. }
        ));
        clock.advance(1_000);
        // The 11th read would push to 1100 > 1000 → KILL at the boundary.
        match m.charge(100, 1, &clock) {
            WindowOutcome::Exceeded { cap, bytes, .. } => {
                assert_eq!(cap, WindowCap::Bytes);
                assert_eq!(bytes, 1_000, "refused charge must not be committed");
            }
            other => panic!("expected Exceeded(Bytes), got {other:?}"),
        }
        // The refused charge left the meter unchanged.
        assert_eq!(m.used_bytes(), 1_000);
    }

    #[test]
    fn slow_drip_trips_the_cumulative_row_budget() {
        let clock = MockClock::starting_at(0);
        // B = 100 rows. Bytes generous so ROWS is the gate.
        let mut m = WindowMeter::for_window(&window(60, 1_000_000_000, 100));
        // 10 reads of 10 rows = 100 (exactly at cap) → all within.
        for _ in 0..10 {
            assert!(matches!(
                m.charge(10, 10, &clock),
                WindowOutcome::Within { .. }
            ));
        }
        assert_eq!(m.used_rows(), 100);
        // One more row breaches.
        match m.charge(1, 1, &clock) {
            WindowOutcome::Exceeded { cap, rows, .. } => {
                assert_eq!(cap, WindowCap::Rows);
                assert_eq!(rows, 100);
            }
            other => panic!("expected Exceeded(Rows), got {other:?}"),
        }
    }

    /// The window RESETS correctly: a sub-budget sequence in window 1 is allowed,
    /// then after the window rolls over the cumulative counters reset and a fresh
    /// sub-budget sequence is allowed again.
    #[test]
    fn window_resets_after_window_secs_elapses() {
        let clock = MockClock::starting_at(0);
        let mut m = WindowMeter::for_window(&window(60, 1_000, 1_000_000));
        // Window 1: charge 900 bytes (within).
        for _ in 0..9 {
            assert!(matches!(
                m.charge(100, 1, &clock),
                WindowOutcome::Within { .. }
            ));
        }
        assert_eq!(m.used_bytes(), 900);
        let anchor1 = m.anchor_ms().unwrap();

        // Advance exactly to the window boundary (60s = 60_000ms): the NEXT
        // charge rolls the window and resets the counters.
        clock.advance(60_000);
        match m.charge(100, 1, &clock) {
            WindowOutcome::Within { bytes, .. } => {
                // Reset: this is the first charge of a brand-new window.
                assert_eq!(bytes, 100, "counters must reset on window roll");
            }
            other => panic!("expected Within after reset, got {other:?}"),
        }
        let anchor2 = m.anchor_ms().unwrap();
        assert!(anchor2 > anchor1, "window must re-anchor on roll");
        // And a fresh 900 more bytes fit in the new window without tripping.
        for _ in 0..8 {
            assert!(matches!(
                m.charge(100, 1, &clock),
                WindowOutcome::Within { .. }
            ));
        }
        assert_eq!(m.used_bytes(), 900);
    }

    #[test]
    fn just_before_the_boundary_does_not_reset() {
        let clock = MockClock::starting_at(0);
        let mut m = WindowMeter::for_window(&window(60, 1_000, 1_000_000));
        assert!(matches!(
            m.charge(900, 1, &clock),
            WindowOutcome::Within { bytes: 900, .. }
        ));
        // 1ms before the window end: still the same window — does NOT reset.
        clock.advance(59_999);
        match m.charge(100, 1, &clock) {
            WindowOutcome::Within { bytes, .. } => assert_eq!(bytes, 1_000),
            other => panic!("expected accumulation within the same window, got {other:?}"),
        }
        // And the very next byte (still pre-boundary in the same window) trips.
        assert!(matches!(
            m.charge(1, 1, &clock),
            WindowOutcome::Exceeded {
                cap: WindowCap::Bytes,
                ..
            }
        ));
    }

    #[test]
    fn a_single_oversized_read_trips_immediately() {
        // Even the first read trips if it alone exceeds the cumulative budget
        // (the per-window gate is independent of the single-shot cutoff).
        let clock = MockClock::starting_at(5_000);
        let mut m = WindowMeter::for_window(&window(60, 1_000, 1_000_000));
        match m.charge(2_000, 1, &clock) {
            WindowOutcome::Exceeded {
                cap: WindowCap::Bytes,
                bytes,
                ..
            } => assert_eq!(bytes, 0, "nothing was committed before the first read"),
            other => panic!("expected immediate Exceeded, got {other:?}"),
        }
    }
}
