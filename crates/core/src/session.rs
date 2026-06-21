//! Session state, trust level, and the **pure, tighten-only** trust transition
//! (SPEC §10.4, §11.1).
//!
//! Two distinct concerns live here, and the boundary between them is the whole
//! point of the design:
//!
//! 1. [`SessionState`] — an injectable, *cumulative* byte/row counter plus the
//!    current trust level, so read-path slow-drip and trust tests are
//!    deterministic. It mutates as a session runs.
//!
//! 2. [`trust_transition`] — a **pure function** of `(events, clock)`. Given the
//!    same event slice and the same clock readings it always returns the same
//!    [`TrustLevel`]; it touches no global state and reads no wall clock. This is
//!    the round-4 fix: trust is reproducible and auditable.
//!
//! # The trust lattice
//!
//! [`TrustLevel`] orders sessions by *how trusted* they are:
//! `Untrusted < Agent < Operator`. A *more* trusted level unlocks a *larger*
//! budget ([`TrustLevel::budget_multiplier_bp`] is non-decreasing in trust), and
//! [`TrustLevel::default_floor`] is `Untrusted` — the fail-closed least-privilege
//! default for any session we have no signal about.
//!
//! # Tighten-only invariant (the safety property)
//!
//! Trust is **tighten-only** (SPEC §11.1, "Anti-DoS / trust-poisoning"). A
//! transition may only *lower* trust (raise friction); it may **never raise a
//! floor bound / unlock a bigger budget**. Concretely:
//!
//! - [`trust_transition`] folds events with [`TrustLevel::tighten`], which is
//!   `min` over the lattice — it can only move *toward* `Untrusted`. It starts at
//!   the most-trusting level and erodes; it can never climb.
//! - Every *benign* event ([`TrustEvent::BenignRead`]/[`BenignWrite`]) maps to
//!   the most-trusting ceiling, so it contributes **nothing** — a long run of
//!   benign reads can never raise trust ("no ramp-and-strike").
//! - Because the budget multiplier is non-decreasing in trust, lowering trust
//!   can only shrink the budget, never grow it.
//! - [`SessionState`] additionally caps the effective level by the session's
//!   *granted identity* and never re-raises a level it has already lowered, so
//!   replaying a shorter/benign history cannot wash out earned friction.
//!
//! These properties are asserted directly in the tests, including a brute-force
//! sweep over event sequences.

use crate::clock::{Clock, Millis};

/// How trusted a session is (SPEC §3 intent tiers / §11.6 trust level).
///
/// Ordering is **trust-ascending**: `Untrusted < Agent < Operator`. A *greater*
/// value is *more* trusted and unlocks a *larger* budget.
/// [`default_floor`](TrustLevel::default_floor) is `Untrusted` — the fail-closed
/// least-privilege default.
///
/// Trust is **tighten-only**: a session may only ever move *down* this lattice
/// (toward `Untrusted`), never up, in response to runtime events. See the module
/// docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TrustLevel {
    /// Untrusted by default — fail closed, smallest budget. The **floor**: a
    /// session can never be tightened below this, and an unknown session starts
    /// here.
    Untrusted,
    /// Identified agent role, no stronger signal yet. Medium budget.
    Agent,
    /// Operator / human-in-the-loop session. Largest budget.
    Operator,
}

impl TrustLevel {
    /// The safe default for any newly observed session: fail closed.
    ///
    /// The engineering posture is deterministic-floor + fail-closed: with no
    /// signal we assume least privilege, so this is `Untrusted` — the *bottom*
    /// of the trust lattice and the floor that tightening can never breach.
    pub const fn default_floor() -> Self {
        TrustLevel::Untrusted
    }

    /// The budget multiplier this level unlocks, in **basis points** (1.0× =
    /// `10_000` bp). Integer math keeps [`trust_transition`] deterministic
    /// across platforms (no float rounding).
    ///
    /// This is **non-decreasing in trust**: a less-trusted level never unlocks a
    /// bigger budget than a more-trusted one, so tightening (lowering trust) can
    /// only shrink the budget. The value at
    /// [`default_floor`](TrustLevel::default_floor) is the smallest.
    pub const fn budget_multiplier_bp(self) -> u32 {
        match self {
            // Floor / smallest budget. Still non-zero: the deterministic write/
            // byte floor independently bounds an untrusted session.
            TrustLevel::Untrusted => 1_000,
            TrustLevel::Agent => 5_000,
            // Most trusted / largest budget.
            TrustLevel::Operator => 10_000,
        }
    }

    /// Combine two levels in the **tightening** direction: the result is the
    /// *less*-trusted (lower) of the two. Trust can only fall.
    ///
    /// This is `min` over the lattice. It is the only operation
    /// [`trust_transition`] uses to fold events, which is what makes the
    /// transition tighten-only.
    pub fn tighten(self, other: TrustLevel) -> TrustLevel {
        self.min(other)
    }
}

impl Default for TrustLevel {
    fn default() -> Self {
        TrustLevel::default_floor()
    }
}

/// A signal observed during a session that may *tighten* trust (SPEC §11.6).
///
/// Every variant maps, via [`TrustEvent::trust_ceiling`], to the **maximum**
/// trust level it is consistent with. Benign events map to
/// [`TrustLevel::Operator`] (the top), so they impose no ceiling and can never
/// *raise* trust, because [`trust_transition`] only ever takes the minimum. This
/// is what makes "ramp-and-strike" impossible: a long run of benign reads
/// contributes only the top ceiling and so changes nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustEvent {
    /// A normal, in-budget read. Benign — imposes no ceiling.
    BenignRead {
        /// Rows returned by the read (for the cumulative counter; does not by
        /// itself tighten trust).
        rows: u64,
        /// Bytes returned by the read.
        bytes: u64,
    },
    /// A normal, in-budget write. Benign — imposes no ceiling.
    BenignWrite {
        /// Rows affected.
        rows: u64,
    },
    /// A heuristic flagged an unusual access pattern (PII columns, recon shape).
    /// Caps trust at `Agent` (mild tightening).
    SuspiciousPattern,
    /// The deterministic floor flagged something (e.g. a row/byte budget was
    /// exceeded, or an EXPLAIN cost-gate tripped). A *trusted, independent*
    /// signal, so it may tighten autonomously — caps trust at `Untrusted`.
    FloorTripped,
    /// Slow-drip exfiltration suspected across many small reads. Caps trust at
    /// `Untrusted` (heavy tightening).
    SlowDripSuspected,
    /// An operator or the risk engine explicitly quarantined the session. Caps
    /// trust at `Untrusted` (maximum tightening; combine with budget gates).
    OperatorQuarantine,
}

impl TrustEvent {
    /// The maximum trust level (ceiling) this event is consistent with.
    ///
    /// Benign events return [`TrustLevel::Operator`] (no ceiling) so they can
    /// never raise trust — they only feed the cumulative counter.
    pub const fn trust_ceiling(&self) -> TrustLevel {
        match self {
            TrustEvent::BenignRead { .. } | TrustEvent::BenignWrite { .. } => TrustLevel::Operator,
            TrustEvent::SuspiciousPattern => TrustLevel::Agent,
            TrustEvent::FloorTripped
            | TrustEvent::SlowDripSuspected
            | TrustEvent::OperatorQuarantine => TrustLevel::Untrusted,
        }
    }

    /// Rows this event adds to the cumulative counter.
    const fn rows(&self) -> u64 {
        match self {
            TrustEvent::BenignRead { rows, .. } | TrustEvent::BenignWrite { rows } => *rows,
            _ => 0,
        }
    }

    /// Bytes this event adds to the cumulative counter.
    const fn bytes(&self) -> u64 {
        match self {
            TrustEvent::BenignRead { bytes, .. } => *bytes,
            _ => 0,
        }
    }
}

/// Compute the trust level implied by a sequence of events — a **pure function**
/// of `(events, clock)` (SPEC §10.4 round-4 fix).
///
/// Determinism: the result depends only on the `events` slice and the `clock`
/// readings; it reads no global state and no wall clock. Calling it twice with
/// the same inputs always yields the same [`TrustLevel`].
///
/// Tighten-only: the running level starts at the most-trusting ceiling
/// ([`TrustLevel::Operator`]) and is folded with [`TrustLevel::tighten`] (`min`),
/// so it can only *fall*. Because every benign event's
/// [`trust_ceiling`](TrustEvent::trust_ceiling) is the top, **no sequence of
/// benign events can ever raise the level** — and since
/// [`TrustLevel::budget_multiplier_bp`] is non-decreasing in trust, no sequence
/// can unlock a bigger budget. The pure result is an *upper bound* on trust given
/// the events; [`SessionState`] caps it further by the granted identity (so the
/// empty-history fail-closed default lives at the session boundary, not here).
///
/// The `clock` is threaded through (rather than ignored) because real trust
/// policy is time-aware — e.g. "quarantine decays only after N ms of clean
/// activity". The MVP transition does not decay friction (tighten-only forbids
/// *raising* trust), but the parameter pins the seam so the signature is stable
/// and any future time-dependence stays injectable and testable.
pub fn trust_transition(events: &[TrustEvent], clock: &dyn Clock) -> TrustLevel {
    // Reading the monotonic clock keeps the seam honest (no wall-clock) and the
    // function injectable; the value is intentionally unused by the MVP rule.
    let _now: Millis = clock.monotonic_millis();

    events.iter().fold(TrustLevel::Operator, |level, event| {
        // Tighten-only: never above `level`, never above the event's ceiling —
        // i.e. take the less-trusted (lower) of the two.
        level.tighten(event.trust_ceiling())
    })
}

/// Injectable cumulative session counter + trust store (SPEC §10.4).
///
/// Holds the running byte/row totals (so slow-drip exfiltration tests are
/// deterministic — they advance the counter explicitly), the session's *granted*
/// identity (the ceiling its trust can never exceed), and the current effective
/// trust level. The trust level is only ever updated through [`apply_event`] /
/// [`recompute_trust`], both of which can only *lower* it (route through the
/// tighten-only [`trust_transition`]), so the stored level can never *rise*.
#[derive(Debug, Clone)]
pub struct SessionState {
    cumulative_rows: u64,
    cumulative_bytes: u64,
    /// The identity-granted ceiling. The effective level can never exceed it,
    /// which is how the fail-closed default is enforced (a session granted only
    /// `Untrusted` stays `Untrusted` no matter how benign its events).
    granted: TrustLevel,
    trust: TrustLevel,
}

impl Default for SessionState {
    fn default() -> Self {
        SessionState::new()
    }
}

impl SessionState {
    /// A fresh session at the fail-closed floor: zero counters, granted +
    /// effective trust both `Untrusted`.
    pub fn new() -> Self {
        SessionState::with_granted(TrustLevel::default_floor())
    }

    /// A fresh session whose *granted identity* is `granted` (e.g. an
    /// authenticated operator). The effective trust starts at the grant and can
    /// only be tightened down from there.
    pub fn with_granted(granted: TrustLevel) -> Self {
        SessionState {
            cumulative_rows: 0,
            cumulative_bytes: 0,
            granted,
            trust: granted,
        }
    }

    /// Cumulative rows returned/affected so far this session.
    pub fn cumulative_rows(&self) -> u64 {
        self.cumulative_rows
    }

    /// Cumulative bytes returned so far this session.
    pub fn cumulative_bytes(&self) -> u64 {
        self.cumulative_bytes
    }

    /// The identity-granted ceiling for this session.
    pub fn granted(&self) -> TrustLevel {
        self.granted
    }

    /// The session's current effective trust level (never above
    /// [`granted`](Self::granted)).
    pub fn trust(&self) -> TrustLevel {
        self.trust
    }

    /// The budget multiplier (basis points) this session is currently allowed,
    /// given its effective trust level. Never exceeds the granted ceiling's
    /// multiplier.
    pub fn budget_multiplier_bp(&self) -> u32 {
        self.trust.budget_multiplier_bp()
    }

    /// Fold one event into the session: bump the cumulative counters and tighten
    /// the trust level (never raise it).
    ///
    /// Using `saturating_add` means a counter at `u64::MAX` stays pinned rather
    /// than wrapping — a wrapped counter could silently *reset* a slow-drip
    /// total, defeating the guard.
    pub fn apply_event(&mut self, event: TrustEvent, clock: &dyn Clock) {
        self.cumulative_rows = self.cumulative_rows.saturating_add(event.rows());
        self.cumulative_bytes = self.cumulative_bytes.saturating_add(event.bytes());
        // Tighten-only: combine the stored level with this single event's
        // ceiling. `tighten` is `min`, so this can only lower `trust`.
        let from_event = trust_transition(std::slice::from_ref(&event), clock);
        self.trust = self.trust.tighten(from_event);
    }

    /// Recompute the trust level from a full event history and store it, but
    /// **never raise** above the current stored level (nor above the granted
    /// ceiling).
    ///
    /// This guards against a caller replaying a *shorter* or reordered history
    /// to wash out earned friction: the stored level is an upper bound on trust
    /// that only ever falls.
    pub fn recompute_trust(&mut self, events: &[TrustEvent], clock: &dyn Clock) {
        let recomputed = trust_transition(events, clock);
        self.trust = self.trust.tighten(recomputed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::MockClock;

    #[test]
    fn floor_is_untrusted_fail_closed() {
        // Fail-closed posture: absence of signal must never imply trust.
        assert_eq!(TrustLevel::default_floor(), TrustLevel::Untrusted);
        assert_eq!(TrustLevel::default(), TrustLevel::Untrusted);
    }

    #[test]
    fn trust_levels_are_ordered_least_privilege_first() {
        assert!(TrustLevel::Untrusted < TrustLevel::Agent);
        assert!(TrustLevel::Agent < TrustLevel::Operator);
    }

    #[test]
    fn empty_history_is_the_most_trusting_upper_bound() {
        // The pure fn returns an *upper bound* given the events; with no events
        // there is no tightening signal, so the bound is the top. Fail-closed is
        // enforced by `SessionState` capping by the granted identity.
        let clock = MockClock::new();
        assert_eq!(trust_transition(&[], &clock), TrustLevel::Operator);
    }

    #[test]
    fn trust_transition_is_a_pure_function() {
        // Same (events, clock readings) => same output, every time.
        let clock = MockClock::starting_at(123);
        let events = [
            TrustEvent::BenignRead {
                rows: 10,
                bytes: 100,
            },
            TrustEvent::SuspiciousPattern,
            TrustEvent::BenignRead { rows: 5, bytes: 50 },
        ];
        let a = trust_transition(&events, &clock);
        let b = trust_transition(&events, &clock);
        assert_eq!(a, b);
        // And it does not depend on hidden state — a fresh clock at the same
        // reading gives the same answer.
        let fresh = MockClock::starting_at(123);
        assert_eq!(trust_transition(&events, &fresh), a);
        assert_eq!(a, TrustLevel::Agent);
    }

    #[test]
    fn transition_only_tightens_never_loosens() {
        let clock = MockClock::new();
        // A tightening event followed by benign reads stays tightened.
        let events = [
            TrustEvent::SlowDripSuspected, // -> Untrusted
            TrustEvent::BenignRead { rows: 1, bytes: 1 },
            TrustEvent::BenignRead { rows: 1, bytes: 1 },
        ];
        assert_eq!(trust_transition(&events, &clock), TrustLevel::Untrusted);
    }

    /// The headline invariant: **no event sequence can raise a floor bound /
    /// unlock a bigger budget.** Brute-force every sequence (with repetition) of
    /// length up to 4 over the full event alphabet and assert the resulting
    /// budget never exceeds the most-trusting budget, friction never drops below
    /// the floor, and appending a benign event never *raises* trust.
    #[test]
    fn tighten_only_invariant_no_sequence_unlocks_a_bigger_budget() {
        let clock = MockClock::new();
        let max_budget = TrustLevel::Operator.budget_multiplier_bp();
        let alphabet = [
            TrustEvent::BenignRead { rows: 9, bytes: 90 },
            TrustEvent::BenignWrite { rows: 3 },
            TrustEvent::SuspiciousPattern,
            TrustEvent::FloorTripped,
            TrustEvent::SlowDripSuspected,
            TrustEvent::OperatorQuarantine,
        ];
        let n = alphabet.len();

        // length 0..=4
        for len in 0..=4usize {
            let total = n.pow(len as u32);
            for mut code in 0..total {
                let mut seq = Vec::with_capacity(len);
                for _ in 0..len {
                    seq.push(alphabet[code % n]);
                    code /= n;
                }
                let level = trust_transition(&seq, &clock);
                let budget = level.budget_multiplier_bp();

                // 1. Budget never exceeds the most-trusting budget.
                assert!(
                    budget <= max_budget,
                    "sequence {seq:?} unlocked budget {budget} > max {max_budget}",
                );
                // 2. Level never falls below the absolute floor.
                assert!(
                    level >= TrustLevel::default_floor(),
                    "sequence {seq:?} produced a level below the floor",
                );
                // 3. Appending a benign event never *raises* trust (no
                //    ramp-and-strike), and in fact never changes it.
                let mut extended = seq.clone();
                extended.push(TrustEvent::BenignRead { rows: 1, bytes: 1 });
                let extended_level = trust_transition(&extended, &clock);
                assert!(
                    extended_level <= level,
                    "benign extension raised trust for {seq:?}",
                );
                assert_eq!(
                    extended_level, level,
                    "a benign read changed the level for {seq:?}",
                );
            }
        }
    }

    #[test]
    fn budget_multiplier_is_non_decreasing_in_trust() {
        // Stepping *up* in trust must not decrease (and here strictly increases)
        // the budget; equivalently, tightening can only shrink it.
        let ordered = [
            TrustLevel::Untrusted,
            TrustLevel::Agent,
            TrustLevel::Operator,
        ];
        for pair in ordered.windows(2) {
            assert!(
                pair[1].budget_multiplier_bp() >= pair[0].budget_multiplier_bp(),
                "more-trusted {:?} unlocked a smaller budget than {:?}",
                pair[1],
                pair[0],
            );
        }
        // Floor is the minimum budget.
        let min_budget = ordered
            .iter()
            .map(|l| l.budget_multiplier_bp())
            .min()
            .unwrap();
        assert_eq!(
            min_budget,
            TrustLevel::default_floor().budget_multiplier_bp()
        );
    }

    #[test]
    fn session_state_accumulates_bytes_and_rows() {
        let clock = MockClock::new();
        let mut session = SessionState::with_granted(TrustLevel::Operator);
        session.apply_event(
            TrustEvent::BenignRead {
                rows: 100,
                bytes: 4_096,
            },
            &clock,
        );
        session.apply_event(
            TrustEvent::BenignRead {
                rows: 50,
                bytes: 2_048,
            },
            &clock,
        );
        assert_eq!(session.cumulative_rows(), 150);
        assert_eq!(session.cumulative_bytes(), 6_144);
        // Benign reads never tighten — trust stays at the grant.
        assert_eq!(session.trust(), TrustLevel::Operator);
    }

    #[test]
    fn new_session_is_capped_at_the_floor_regardless_of_benign_events() {
        // Fail-closed: a session we have no identity signal about starts at the
        // floor and benign events cannot lift it.
        let clock = MockClock::new();
        let mut session = SessionState::new();
        assert_eq!(session.granted(), TrustLevel::Untrusted);
        for _ in 0..100 {
            session.apply_event(
                TrustEvent::BenignRead {
                    rows: 1_000,
                    bytes: 1_000_000,
                },
                &clock,
            );
        }
        assert_eq!(session.trust(), TrustLevel::Untrusted);
        assert_eq!(
            session.budget_multiplier_bp(),
            TrustLevel::Untrusted.budget_multiplier_bp()
        );
    }

    #[test]
    fn session_state_tightens_and_never_loosens_on_replay() {
        let clock = MockClock::new();
        let mut session = SessionState::with_granted(TrustLevel::Operator);
        session.apply_event(TrustEvent::SuspiciousPattern, &clock);
        assert_eq!(session.trust(), TrustLevel::Agent);

        // Replaying only-benign history must not wash out the earned friction.
        session.recompute_trust(&[TrustEvent::BenignRead { rows: 1, bytes: 1 }], &clock);
        assert_eq!(session.trust(), TrustLevel::Agent);

        // A stronger signal still tightens further.
        session.apply_event(TrustEvent::OperatorQuarantine, &clock);
        assert_eq!(session.trust(), TrustLevel::Untrusted);
        assert_eq!(
            session.budget_multiplier_bp(),
            TrustLevel::Untrusted.budget_multiplier_bp()
        );
    }

    #[test]
    fn cumulative_counters_saturate_instead_of_wrapping() {
        // A wrapped slow-drip total could silently reset and defeat the guard.
        let clock = MockClock::new();
        let mut session = SessionState::new();
        session.apply_event(
            TrustEvent::BenignRead {
                rows: u64::MAX,
                bytes: u64::MAX,
            },
            &clock,
        );
        session.apply_event(TrustEvent::BenignRead { rows: 5, bytes: 5 }, &clock);
        assert_eq!(session.cumulative_rows(), u64::MAX);
        assert_eq!(session.cumulative_bytes(), u64::MAX);
    }
}
