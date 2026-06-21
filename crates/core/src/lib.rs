//! Core domain types and one-way-door seams shared across pg_bumpers.
//!
//! This crate is intentionally dependency-light: it holds the contracts every
//! other crate builds on (see SPEC.md §3 and the S0 core-seams work item #6).
//! The real seams — `ApplyBarrier`, `Clock`, `SessionState`/`TrustLevel`,
//! `BlastRadius`, the PK-set checksum and typed-inverse — land in #6. For S0
//! this crate only needs to compile cleanly and carry a real test.

/// Coarse trust level inferred for a session at the wire (SPEC §3 intent tiers).
///
/// In the MVP tiers T0–T2 are captured/logged only; this enum gives the rest of
/// the workspace a stable type to reference before the full seam lands in #6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustLevel {
    /// Untrusted by default — fail closed.
    Untrusted,
    /// Identified agent role, no stronger signal yet.
    Agent,
    /// Operator / human-in-the-loop session.
    Operator,
}

impl TrustLevel {
    /// The safe default for any newly observed session: fail closed.
    ///
    /// The engineering posture is deterministic-floor + fail-closed: when we
    /// have no signal we assume the least privilege.
    pub fn default_floor() -> Self {
        TrustLevel::Untrusted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_floor_is_untrusted_fail_closed() {
        // Fail-closed posture: the absence of signal must never imply trust.
        assert_eq!(TrustLevel::default_floor(), TrustLevel::Untrusted);
    }

    #[test]
    fn trust_levels_are_ordered_least_privilege_first() {
        assert!(TrustLevel::Untrusted < TrustLevel::Agent);
        assert!(TrustLevel::Agent < TrustLevel::Operator);
    }
}
