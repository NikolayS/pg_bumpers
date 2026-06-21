//! Policy model and the `RiskEngine` seam for pg_bumpers.
//!
//! Compiled into the proxy and core (SPEC §4). One `policy.yaml` drives the
//! certified-action-set and autonomy levels. In the MVP the `RiskEngine` is a
//! stub that returns `Allow` (SPEC §15.1); the gating engine is fast-follow.
//! This S0 stub only establishes the verdict vocabulary and the floor default.

/// The verdict a risk evaluation can return.
///
/// Critically, the risk engine can only *tighten* (block/hold/escalate) — it
/// can never loosen below the deterministic floor (SPEC §3, brief "tighten-only").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Permitted by the risk plane (still subject to the deterministic floor).
    Allow,
    /// Blocked outright.
    Block,
    /// Held pending human approval / escalation.
    Hold,
}

/// MVP risk engine: a stub that returns `Allow` (SPEC §15.1).
///
/// The deterministic floor — not this engine — is the safety guarantee in v1.
#[derive(Debug, Default)]
pub struct StubRiskEngine;

impl StubRiskEngine {
    /// Evaluate an action. The MVP stub always allows; the floor enforces safety.
    pub fn evaluate(&self) -> Verdict {
        Verdict::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_engine_allows_in_mvp() {
        // Per SPEC §15.1 the MVP RiskEngine is a stub returning Allow.
        assert_eq!(StubRiskEngine.evaluate(), Verdict::Allow);
    }

    #[test]
    fn verdicts_are_distinct() {
        assert_ne!(Verdict::Allow, Verdict::Block);
        assert_ne!(Verdict::Block, Verdict::Hold);
    }
}
