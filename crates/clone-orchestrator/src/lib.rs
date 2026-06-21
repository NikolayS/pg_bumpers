//! Clone-orchestrator for pg_bumpers.
//!
//! Rehearses a proposed write (on a DBLab clone if present, else in a rolled-back
//! txn), measures the blast radius, and guards apply with a PK-set checksum so
//! row-identity drift is caught even when the row *count* is unchanged (SPEC §4).
//! Guarded apply re-checks the affected-PK set at apply time and aborts on any
//! drift (0-tolerance for destructive ops). This S0 crate provides the drift-
//! decision seam and a test; the live rehearsal lands in S2/S3.

/// The outcome of comparing the dry-run affected-PK set against the apply-time set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriftDecision {
    /// PK sets match — safe to proceed to commit.
    Proceed,
    /// PK sets diverged — abort before commit (fail-closed).
    Abort,
}

/// Decide whether a guarded apply may proceed given the dry-run and apply-time
/// affected-PK-set checksums.
///
/// Guard is the PK-set checksum, *not* cardinality: identical counts with
/// different rows still drift and must abort.
pub fn guard_decision(dry_run_checksum: u64, apply_checksum: u64) -> DriftDecision {
    if dry_run_checksum == apply_checksum {
        DriftDecision::Proceed
    } else {
        DriftDecision::Abort
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_pk_set_proceeds() {
        assert_eq!(guard_decision(0xABCD, 0xABCD), DriftDecision::Proceed);
    }

    #[test]
    fn predicate_flip_same_count_different_rows_aborts() {
        // The count-only blind spot: different checksum => abort even if the
        // cardinality were equal upstream.
        assert_eq!(guard_decision(0xABCD, 0x1234), DriftDecision::Abort);
    }
}
