//! Proposal state — `propose(statement, expected_rows?)` (SPEC §4 MCP
//! `propose_write` → proposal/ticket state in core, with a TTL).
//!
//! A [`Proposal`] is the in-crate handle a caller gets back from
//! [`propose`](crate::propose): a stable id, the exact candidate statement, the
//! caller's optional `expected_rows` (so the blast-radius preview can be checked
//! against an expectation), and a **TTL** measured against the injected
//! [`Clock`] (SPEC §10.4 — no wall-clock reads in gating logic). The proposal is
//! created at dry-run-proposal time and consumed by [`dry_run`](crate::dry_run);
//! state lives in-crate/core, never on the stateless MCP server (§4).
//!
//! The id is derived deterministically from `(statement, expected_rows,
//! created_unix_millis, seq)` so it is reproducible in tests and unique in
//! practice, without pulling in a uuid dependency.

use std::sync::atomic::{AtomicU64, Ordering};

use pgb_core::Clock;

/// Default proposal time-to-live: 15 minutes, in milliseconds. A dry-run
/// preview that the operator does not act on within the TTL is stale (the
/// clone's LSN has moved); the apply path re-checks anyway via the PK-set guard,
/// but an expired proposal should not be silently rehearsed.
pub const DEFAULT_TTL_MILLIS: u64 = 15 * 60 * 1_000;

/// Monotonic per-process sequence so two proposals created in the same
/// millisecond still get distinct ids.
static SEQ: AtomicU64 = AtomicU64::new(0);

/// A candidate write awaiting a dry-run rehearsal (SPEC §4 proposal/ticket
/// state, TTL'd).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    /// Stable, unique id (`p-<hex>`); echoed into the blast-radius record's
    /// `proposal_id`.
    pub id: String,
    /// The exact candidate statement to rehearse. Stored verbatim so the apply
    /// path can bind it to a signed grant (§14) and so the dry-run runs the
    /// *same* SQL it will later apply.
    pub statement: String,
    /// The caller's row-count expectation, if any (the MCP `confirm_rows`
    /// forcing function, §4). `None` ⇒ no expectation supplied.
    pub expected_rows: Option<u64>,
    /// Creation timestamp (unix millis, from the injected clock) — for the id
    /// and human-facing display only, never for gating.
    pub created_unix_millis: u64,
    /// Monotonic reading at creation (from the injected clock) — TTL is measured
    /// against this so a wall-clock jump cannot expire or un-expire a proposal.
    pub created_monotonic_millis: u64,
    /// Time-to-live in milliseconds (see [`DEFAULT_TTL_MILLIS`]).
    pub ttl_millis: u64,
}

impl Proposal {
    /// Whether this proposal has outlived its TTL, measured against the
    /// monotonic clock (SPEC §10.4 — gating reads the monotonic clock only).
    pub fn is_expired(&self, clock: &dyn Clock) -> bool {
        let now = clock.monotonic_millis();
        now.saturating_sub(self.created_monotonic_millis) >= self.ttl_millis
    }

    /// Remaining time-to-live in milliseconds (0 once expired).
    pub fn remaining_millis(&self, clock: &dyn Clock) -> u64 {
        let elapsed = clock
            .monotonic_millis()
            .saturating_sub(self.created_monotonic_millis);
        self.ttl_millis.saturating_sub(elapsed)
    }
}

/// Create a [`Proposal`] for `statement` with an optional `expected_rows`,
/// stamping it against the injected [`Clock`] and the default TTL.
///
/// The statement is **not** parsed or validated here — that happens in
/// [`dry_run`](crate::dry_run), which refuses volatile predicates and PK-less
/// tables. `propose` only mints the handle + TTL.
pub fn propose(
    statement: impl Into<String>,
    expected_rows: Option<u64>,
    clock: &dyn Clock,
) -> Proposal {
    propose_with_ttl(statement, expected_rows, DEFAULT_TTL_MILLIS, clock)
}

/// As [`propose`], but with an explicit TTL (used by tests to drive expiry
/// deterministically against a [`pgb_core::MockClock`]).
pub fn propose_with_ttl(
    statement: impl Into<String>,
    expected_rows: Option<u64>,
    ttl_millis: u64,
    clock: &dyn Clock,
) -> Proposal {
    let statement = statement.into();
    let created_unix_millis = clock.now_unix_millis();
    let created_monotonic_millis = clock.monotonic_millis();
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let id = make_id(&statement, expected_rows, created_unix_millis, seq);
    Proposal {
        id,
        statement,
        expected_rows,
        created_unix_millis,
        created_monotonic_millis,
        ttl_millis,
    }
}

/// Deterministic id derived from the proposal's defining fields. Not a security
/// token (the §14 grant is) — just a stable, collision-resistant handle.
fn make_id(statement: &str, expected_rows: Option<u64>, created_millis: u64, seq: u64) -> String {
    // A tiny FNV-1a hash keeps this dependency-free; uniqueness comes from the
    // per-process `seq` even when two ids share inputs.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut mix = |bytes: &[u8]| {
        for &b in bytes {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    };
    mix(statement.as_bytes());
    mix(&expected_rows.unwrap_or(u64::MAX).to_le_bytes());
    mix(&created_millis.to_le_bytes());
    mix(&seq.to_le_bytes());
    format!("p-{h:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgb_core::MockClock;

    #[test]
    fn propose_stamps_statement_and_default_ttl() {
        let clock = MockClock::starting_at(1_000);
        let p = propose("UPDATE public.orders SET balance = 0", Some(48), &clock);
        assert_eq!(p.statement, "UPDATE public.orders SET balance = 0");
        assert_eq!(p.expected_rows, Some(48));
        assert_eq!(p.ttl_millis, DEFAULT_TTL_MILLIS);
        assert_eq!(p.created_unix_millis, 1_000);
        assert!(p.id.starts_with("p-"));
    }

    #[test]
    fn expected_rows_is_optional() {
        let clock = MockClock::new();
        let p = propose("DELETE FROM public.orders WHERE id = 1", None, &clock);
        assert_eq!(p.expected_rows, None);
    }

    #[test]
    fn ids_are_unique_even_for_identical_statements() {
        let clock = MockClock::new();
        let a = propose("UPDATE t SET x = 1", None, &clock);
        let b = propose("UPDATE t SET x = 1", None, &clock);
        assert_ne!(a.id, b.id, "the per-process seq must make ids distinct");
    }

    #[test]
    fn ttl_expiry_is_measured_against_the_monotonic_clock() {
        let clock = MockClock::starting_at(0);
        let p = propose_with_ttl("UPDATE t SET x = 1", None, 1_000, &clock);
        assert!(!p.is_expired(&clock), "fresh proposal is not expired");
        assert_eq!(p.remaining_millis(&clock), 1_000);

        clock.advance(999);
        assert!(!p.is_expired(&clock), "still within TTL at 999ms");
        assert_eq!(p.remaining_millis(&clock), 1);

        clock.advance(1);
        assert!(p.is_expired(&clock), "expired exactly at the TTL boundary");
        assert_eq!(p.remaining_millis(&clock), 0);
    }

    #[test]
    fn wall_clock_jump_does_not_change_expiry() {
        // A backwards wall-clock jump must not un-expire a proposal: TTL reads
        // the monotonic clock only (SPEC §10.4).
        let clock = MockClock::starting_at(10_000);
        let p = propose_with_ttl("UPDATE t SET x = 1", None, 500, &clock);
        clock.advance(600); // monotonic advances → expired
        clock.set_unix_millis(0); // wall clock jumps backwards
        assert!(p.is_expired(&clock));
    }
}
