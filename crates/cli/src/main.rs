//! pg_bumpers CLI binary (stub).
//!
//! The CLI is the MVP approval surface (SPEC §14): an authorized human approves,
//! denies, or break-glasses a blocked proposal. A grant is **signed, single-use,
//! and bound to the exact proposal** — the agent cannot swap the SQL after
//! approval, and can never authorize itself. This S0 stub carries the
//! single-use grant-consumption seam + a test; the live flow lands in S4.

/// A single-use grant bound to one proposal (SPEC §14).
///
/// Once consumed it cannot be reused — replay is refused (fail-closed).
#[derive(Debug)]
struct Grant {
    proposal_id: u64,
    consumed: bool,
}

impl Grant {
    fn new(proposal_id: u64) -> Self {
        Grant {
            proposal_id,
            consumed: false,
        }
    }

    /// Consume the grant for `proposal_id`. Returns `true` only if the grant is
    /// fresh **and** bound to exactly this proposal; any reuse or mismatch fails.
    fn consume_for(&mut self, proposal_id: u64) -> bool {
        if self.consumed || self.proposal_id != proposal_id {
            return false;
        }
        self.consumed = true;
        true
    }
}

fn main() {
    // Exercise the grant seam plus the workspace deps so the stub is wired.
    let mut grant = Grant::new(0);
    let consumed = grant.consume_for(0);
    let trust = pgb_core::TrustLevel::Operator;
    let verdict = pgb_policy::StubRiskEngine.evaluate();
    println!(
        "pgb-cli: stub — operator approval flow lands in S4 (see SPEC.md §14). \
         grant seam ready (sample consume={consumed}, approver_trust={trust:?}, \
         engine_verdict={verdict:?})."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_is_single_use_and_proposal_bound() {
        let mut grant = Grant::new(42);
        // Wrong proposal id is refused (proposal-bound).
        assert!(!grant.consume_for(7));
        // Correct proposal id succeeds once.
        assert!(grant.consume_for(42));
        // Replay of a consumed grant is refused (single-use).
        assert!(!grant.consume_for(42));
    }
}
